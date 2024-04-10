use std::io::{Error as IoError, ErrorKind};
use hyper::{body::Incoming, Request, Response, Version, client::conn::{http1, http2}};
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::{net::TcpStream, sync::RwLock};
use crate::body::IncomingBody;
use super::ProxySocket;


impl super::Proxy {
    pub async fn setup(&mut self) -> Result<(), String> {
        self.client = Some(Client::new());

        //check the connection
        let addr = match &self.forward.addr {
            ProxySocket::Ip(addr) => *addr,
            ProxySocket::Dns((host, port)) => {
                let host = host.clone();
                let port = *port;
                tokio::task::spawn_blocking(move || {
                    std::net::ToSocketAddrs::to_socket_addrs(&(host, port))
                })
                .await.map_err(|e|e.to_string())?.map_err(|e|e.to_string())?
                .next()
                .ok_or("No DNS Address could be obtained".to_string())?
            }
        };
        let io = TcpStream::connect(addr).await.map_err(|e|e.to_string())?;

        //check available HTTP version
        self.client.as_mut().unwrap().v = match self.forward.scheme.as_str() {
            "http" => {
                Version::HTTP_11
            }
            super::HTTP2_PLAINTEXT_KNOWN => {
                Version::HTTP_2
            }
            #[cfg(any(feature = "tlsrust", feature = "tlsnative"))]
            "https" => {
                //version depends on ALPN
                let (_io, is_h2) = Client::wrap_tls(io, &self.forward.addr).await.map_err(|e|e.to_string())?;
                if is_h2 {
                    Version::HTTP_2
                }else{
                    Version::HTTP_11
                }
            },
            _ => unreachable!("config should not allow other values"),
        };

        Ok(())
    }
    pub async fn request(&self, mut req: Request<IncomingBody>) -> Result<Response<Incoming>, IoError> {
        let client = self.client.as_ref().unwrap();
        loop {
            if let Some(h1) = client.h1.write().await.as_mut() {
                match h1.ready().await {
                    Err(e) => {
                        if !e.is_closed() {
                            return Err(IoError::other(e));
                        }
                    }
                    Ok(()) => {
                        //persist connection, if its not an upgrade
                        let h = req.headers_mut();
                        if !h.contains_key(hyper::header::CONNECTION) {
                            h.insert(hyper::header::CONNECTION, "keep-alive".try_into().unwrap());
                        }
                        return h1.send_request(req).await.map_err(IoError::other)
                    },
                }
            }
            if let Some(h2) = client.h2.write().await.as_mut() {
                match h2.ready().await {
                    Err(e) => {
                        if !e.is_closed() {
                            return Err(IoError::other(e));
                        }
                    }
                    Ok(()) => return h2.send_request(req).await.map_err(IoError::other),
                }
            }
            client
                .connect(&self.forward.addr, &self.forward.scheme)
                .await?;
        }
    }
}

/// simple HTTPClient to send requests
/// 
/// does not support connection pooling, but will reuse connections on h2 and h1.1 (via keep-alive)
#[derive(Debug)]
pub struct Client {
    h1: RwLock<Option<http1::SendRequest<IncomingBody>>>,
    h2: RwLock<Option<http2::SendRequest<IncomingBody>>>,
    v: Version
}
impl Client {
    pub fn new() -> Client {
        Client {
            h1: RwLock::new(None),
            h2: RwLock::new(None),
            v: Version::HTTP_11,
        }
    }
    async fn connect(&self, proxy_addr: &ProxySocket, scheme: &hyper::http::uri::Scheme) -> Result<(), IoError> {
        let addr = match proxy_addr {
            ProxySocket::Ip(addr) => *addr,
            ProxySocket::Dns((host, port)) => {
                let host = host.clone();
                let port = *port;
                tokio::task::spawn_blocking(move || {
                    std::net::ToSocketAddrs::to_socket_addrs(&(host, port))
                })
                .await??
                .next()
                .ok_or(ErrorKind::NotFound)?
            }
        };
        let io = TcpStream::connect(addr).await?;

        match scheme.as_str() {
            "http" => {
                let (s, r) = http1::handshake(TokioIo::new(io))
                    .await
                    .map_err(IoError::other)?;
                tokio::spawn(r.with_upgrades());
                *self.h1.write().await = Some(s);
            }
            super::HTTP2_PLAINTEXT_KNOWN => {
                let (s, r) = http2::handshake(TokioExecutor::new(), TokioIo::new(io))
                    .await
                    .map_err(IoError::other)?;
                tokio::spawn(r);
                *self.h2.write().await = Some(s);
            }
            #[cfg(any(feature = "tlsrust", feature = "tlsnative"))]
            "https" => {
                //version depends on ALPN
                let (io, is_h2) = Self::wrap_tls(io, proxy_addr).await?;
                if is_h2 {
                    let (s , r) = http2::handshake(TokioExecutor::new(), TokioIo::new(io)).await.map_err(IoError::other)?;
                    tokio::spawn(r);
                    *self.h2.write().await = Some(s);
                }else{
                    let (s , r) = http1::handshake(TokioIo::new(io)).await.map_err(IoError::other)?;
                    tokio::spawn(r);
                    *self.h1.write().await = Some(s);
                }
            },
            _ => unreachable!("config should not allow other values"),
        }
        Ok(())
    }
    pub async fn get_supported_version(&self) -> Version {
        self.v
    }
    #[cfg(feature = "tlsrust")]
    async fn wrap_tls(io: TcpStream, proxy_addr: &ProxySocket) -> Result<(tokio_rustls::client::TlsStream<TcpStream>, bool), IoError> {
        use tokio_rustls::rustls::client::ClientConfig;
        use tokio_rustls::rustls::pki_types::{DnsName, ServerName};
        //use tokio_rustls::rustls::RootCertStore;

        //let mut root_store = RootCertStore::empty();
        //crate::transport::tls::rustls::load_certs(a);
        //root_store.add(der);

        let mut cc = ClientConfig::builder()
        //.with_root_certificates(root_store).with_no_client_auth();
        .dangerous().with_custom_certificate_verifier(std::sync::Arc::new(rustls::AnyCert::new())).with_no_client_auth();
        cc.alpn_protocols.push(b"h2".to_vec());
        cc.alpn_protocols.push(b"http/1.1".to_vec());
        let c: tokio_rustls::TlsConnector = std::sync::Arc::new(cc).into();

        let domain = match proxy_addr {
            ProxySocket::Ip(sa) => ServerName::IpAddress(sa.ip().into()),
            ProxySocket::Dns((n,_)) => ServerName::DnsName(DnsName::try_from(n.clone()).expect("name already worked in DNS")),
        };

        let s = c.connect(domain, io).await?;
        let is_h2 = s.get_ref().1.alpn_protocol().is_some_and(|v|v == b"h2");
        Ok((s, is_h2))
    }
}

#[cfg(feature = "tlsrust")]
mod rustls {
    use tokio_rustls::rustls::{client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier}, crypto::{verify_tls12_signature, verify_tls13_signature, WebPkiSupportedAlgorithms}, pki_types::{CertificateDer, ServerName}, DigitallySignedStruct};
    #[derive(Debug)]
    pub struct AnyCert(WebPkiSupportedAlgorithms);
    impl AnyCert {
        pub fn new() -> AnyCert {
            AnyCert(tokio_rustls::rustls::crypto::ring::default_provider().signature_verification_algorithms)
        }
    }
    impl ServerCertVerifier for AnyCert {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: tokio_rustls::rustls::pki_types::UnixTime,
        ) -> Result<ServerCertVerified, tokio_rustls::rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
            verify_tls12_signature(message, cert, dss, &self.0)
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
            verify_tls13_signature(message, cert, dss, &self.0)
        }
        fn supported_verify_schemes(&self) -> Vec<tokio_rustls::rustls::SignatureScheme> {
            self.0.supported_schemes()
        }
    }
}

/*
     GET / HTTP/1.1
     Host: server.example.com
     Connection: Upgrade, HTTP2-Settings
     Upgrade: h2c
     HTTP2-Settings: <base64url encoding of HTTP/2 SETTINGS payload>

*/