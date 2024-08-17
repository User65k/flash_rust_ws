use super::cfg::ProxySocket;
use crate::body::IncomingBody;
use deadpool::unmanaged::{Object, Pool, PoolError};
use hyper::{
    body::Incoming,
    client::conn::{http1, http2},
    Request, Response, Version,
};
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::io::Error as IoError;
use tokio::{net::TcpStream, sync::RwLock};

impl super::Proxy {
    pub async fn setup(&mut self) -> Result<(), String> {
        let client = Client::new();

        // check DNS and connection by just connecting
        client.connect(self).await.map_err(|e| e.to_string())?;

        self.client = Some(client);
        Ok(())
    }
    pub async fn request(
        &self,
        mut req: Request<IncomingBody>,
    ) -> Result<Response<Incoming>, IoError> {
        let client = self.client.as_ref().unwrap();
        loop {
            if let Some(pool) = client.h1.write().await.as_mut() {
                let stat = pool.status();
                match if stat.size == stat.max_size {
                    pool.get().await
                } else {
                    pool.try_get()
                } {
                    Ok(mut h1) => {
                        match h1.ready().await {
                            Err(_e) => {
                                //only error here is is_closed
                                let _ = Object::take(h1);
                            }
                            Ok(()) => {
                                //persist connection, if its not an upgrade
                                let h = req.headers_mut();
                                if !h.contains_key(hyper::header::CONNECTION) {
                                    h.insert(
                                        hyper::header::CONNECTION,
                                        "keep-alive".try_into().unwrap(),
                                    );
                                }
                                let res = h1.send_request(req).await;
                                //is_ready / is_closed
                                tokio::spawn(delay_drop(h1));
                                return res.map_err(IoError::other);
                            }
                        }
                    }
                    Err(PoolError::Timeout) => {} //connect a new IO
                    Err(PoolError::Closed) => unreachable!("pool should not close"),
                    Err(PoolError::NoRuntimeSpecified) => unreachable!("pool not using timeout"),
                }
            }
            if let Some(h2) = client.h2.write().await.as_mut() {
                match h2.ready().await {
                    Err(_e) => {
                        //only error here is is_closed
                        //connect a new IO
                    }
                    Ok(()) => return h2.send_request(req).await.map_err(IoError::other),
                }
            }
            client.connect(self).await?;
        }
    }
}

/// dont insert back into the pool until its ready again
async fn delay_drop(mut h1: Object<http1::SendRequest<IncomingBody>>) {
    if let Err(_e) = h1.ready().await {
        //only error here is is_closed
        let _ = Object::take(h1);
    }
}

/// simple HTTPClient to send requests
///
/// does support connection pooling for h1 and will reuse connections on h2 and h1.1 (via keep-alive)
#[derive(Debug)]
pub struct Client {
    h1: RwLock<Option<Pool<http1::SendRequest<IncomingBody>>>>,
    h2: RwLock<Option<http2::SendRequest<IncomingBody>>>,
}
impl Client {
    pub fn new() -> Client {
        Client {
            h1: RwLock::new(None),
            h2: RwLock::new(None),
        }
    }
    async fn add_to_h1_pool(&self, s: http1::SendRequest<IncomingBody>, max_size: usize) {
        let mut lock = self.h1.write().await;
        let pool = lock.get_or_insert(Pool::new(max_size));
        pool.try_add(s).expect("pool should never close");
    }
    async fn connect(&self, cfg: &super::Proxy) -> Result<(), IoError> {
        let addr = match &cfg.forward.addr {
            ProxySocket::Ip(addr) => *addr,
            ProxySocket::Dns((host, port)) => {
                let host = host.clone();
                let port = *port;
                tokio::task::spawn_blocking(move || {
                    std::net::ToSocketAddrs::to_socket_addrs(&(host, port))
                })
                .await??
                .next()
                .ok_or(IoError::other("No DNS Address could be obtained"))?
            }
        };
        log::trace!("connecting to {addr}");
        let io = TcpStream::connect(addr).await?;

        match cfg.forward.scheme.as_str() {
            "http" => {
                let (s, r) = http1::handshake(TokioIo::new(io))
                    .await
                    .map_err(IoError::other)?;
                tokio::spawn(r.with_upgrades());
                self.add_to_h1_pool(s, cfg.h1_pool_size).await;
            }
            super::cfg::HTTP2_PLAINTEXT_KNOWN => {
                let (s, r) = http2::handshake(TokioExecutor::new(), TokioIo::new(io))
                    .await
                    .map_err(IoError::other)?;
                tokio::spawn(r);
                *self.h2.write().await = Some(s);
            }
            #[cfg(any(feature = "tlsrust", feature = "tlsnative"))]
            "https" => {
                //version depends on ALPN

                let roots = cfg
                    .tls_root
                    .as_ref()
                    .ok_or(IoError::other("No TLS root cert configured"))?;

                let (io, is_h2) = Self::wrap_tls(io, &cfg.forward.addr, roots).await?;
                if is_h2 {
                    let (s, r) = http2::handshake(TokioExecutor::new(), TokioIo::new(io))
                        .await
                        .map_err(IoError::other)?;
                    tokio::spawn(r);
                    *self.h2.write().await = Some(s);
                } else {
                    let (s, r) = http1::handshake(TokioIo::new(io))
                        .await
                        .map_err(IoError::other)?;
                    tokio::spawn(r);
                    self.add_to_h1_pool(s, cfg.h1_pool_size).await;
                }
            }
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
pub mod tls {
    use super::ProxySocket;
    use serde::Deserialize;
    use std::io::Error as IoError;
    use std::path::PathBuf;
    use std::sync::Arc;
    use tokio::net::TcpStream;
    use tokio_rustls::rustls::client::ClientConfig;
    use tokio_rustls::rustls::pki_types::{DnsName, ServerName};
    use tokio_rustls::rustls::RootCertStore;

    #[derive(Deserialize, Debug)]
    #[serde(try_from = "PathBuf")]
    pub struct RootCert(Arc<RootCertStore>);

    impl TryFrom<PathBuf> for RootCert {
        type Error = anyhow::Error;

        fn try_from(value: PathBuf) -> Result<Self, Self::Error> {
            // Open certificate file.
            let certfile = std::fs::File::open(value)?;
            let mut reader = std::io::BufReader::new(certfile);

            // Load and return certificates
            let certs = rustls_pemfile::certs(&mut reader).filter_map(|e| e.ok());

            let mut root_store = RootCertStore::empty();
            for der in certs {
                root_store.add(der)?;
            }
            Ok(Self(Arc::new(root_store)))
        }
    }

    impl RootCert {
        fn get_store(&self) -> Arc<RootCertStore> {
            self.0.clone()
        }
    }

    impl super::Client {
        pub async fn wrap_tls(
            io: TcpStream,
            proxy_addr: &ProxySocket,
            roots: &RootCert,
        ) -> Result<(tokio_rustls::client::TlsStream<TcpStream>, bool), IoError> {
            let mut cc = ClientConfig::builder()
                .with_root_certificates(roots.get_store())
                .with_no_client_auth();
            cc.alpn_protocols.push(b"h2".to_vec());
            cc.alpn_protocols.push(b"http/1.1".to_vec());
            let c: tokio_rustls::TlsConnector = std::sync::Arc::new(cc).into();

            let domain = match proxy_addr {
                ProxySocket::Ip(sa) => ServerName::IpAddress(sa.ip().into()),
                ProxySocket::Dns((n, _)) => ServerName::DnsName(
                    DnsName::try_from(n.clone()).expect("name already worked for DNS"),
                ),
            };

            let s = c.connect(domain, io).await?;
            let is_h2 = s.get_ref().1.alpn_protocol().is_some_and(|v| v == b"h2");
            Ok((s, is_h2))
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
