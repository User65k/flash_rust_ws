use std::io::{Error as IoError, ErrorKind};

use hyper::{body::Incoming, Request, Response, Version, client::conn::{http1, http2}};
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::{net::TcpStream, sync::RwLock};
#[cfg(feature = "tlsrust")]
use tokio_rustls::rustls::pki_types::{DnsName, ServerName};

use crate::body::IncomingBody;

use super::ProxySocket;


impl super::Proxy {
    pub async fn setup(&mut self) -> Result<(), String> {
        self.client = Some(Client::new());
        Ok(())
    }
    pub async fn request(&self, req: Request<IncomingBody>) -> Result<Response<Incoming>, IoError> {
        let client = self.client.as_ref().unwrap();
        loop {
            if let Some(h1) = client.h1.write().await.as_mut() {
                match h1.ready().await {
                    Err(e) => {
                        if !e.is_closed() {
                            return Err(IoError::other(e));
                        }
                    }
                    Ok(()) => return h1.send_request(req).await.map_err(IoError::other),
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

#[derive(Debug)]
pub struct Client {
    h1: RwLock<Option<http1::SendRequest<IncomingBody>>>,
    h2: RwLock<Option<http2::SendRequest<IncomingBody>>>,
}
impl Client {
    pub fn new() -> Client {
        Client {
            h1: RwLock::new(None),
            h2: RwLock::new(None),
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
                #[cfg(feature = "tlsrust")]
                let io = {
                    let mut cc = tokio_rustls::rustls::client::ClientConfig::builder().dangerous().with_custom_certificate_verifier(std::sync::Arc::new(rustls::AnyCert::new())).with_no_client_auth();
                    cc.alpn_protocols.push(b"h2".to_vec());
                    cc.alpn_protocols.push(b"http/1.1".to_vec());
                    let c: tokio_rustls::TlsConnector = std::sync::Arc::new(cc).into();

                    let domain = match proxy_addr {
                        ProxySocket::Ip(sa) => ServerName::IpAddress(sa.ip().into()),
                        ProxySocket::Dns((n,_)) => ServerName::DnsName(DnsName::try_from(n.clone()).expect("name already worked in DNS")),
                    };

                    c.connect(domain, io).await?
                };
                if io.get_ref().1.alpn_protocol().is_some_and(|v|v == b"h2") {
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
        if self.h2.read().await.is_some() {
            Version::HTTP_2
        } else {
            Version::HTTP_11
        }
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