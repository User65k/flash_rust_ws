use std::io::{Error as IoError, ErrorKind};

use hyper::{body::Incoming, Request, Response, Version};
use hyper_util::rt::TokioIo;
use tokio::{net::TcpStream, sync::RwLock};

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
    h1: RwLock<Option<hyper::client::conn::http1::SendRequest<IncomingBody>>>,
    h2: RwLock<Option<hyper::client::conn::http2::SendRequest<IncomingBody>>>,
}
impl Client {
    pub fn new() -> Client {
        Client {
            h1: RwLock::new(None),
            h2: RwLock::new(None),
        }
    }
    async fn connect(&self, addr: &ProxySocket, scheme: &hyper::http::uri::Scheme) -> Result<(), IoError> {
        let addr = match addr {
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
                let (s, r) = hyper::client::conn::http1::handshake(TokioIo::new(io))
                    .await
                    .map_err(IoError::other)?;
                tokio::spawn(r.with_upgrades());
                *self.h1.write().await = Some(s);
            } /*
            "https" => {
            //version depends on ALPN
            let mut cc = tokio_rustls::rustls::client::ClientConfig::builder().dangerous().with_custom_certificate_verifier(verifier).with_no_client_auth();
            cc.alpn_protocols.push(b"h2".to_vec());
            cc.alpn_protocols.push(b"http/1.1".to_vec());
            let c: tokio_rustls::TlsConnector = std::sync::Arc::new(cc).into();
            let io = c.connect(domain, io).await?;
            if io.get_ref().1.alpn_protocol().is_some_and(|v|v == b"h2") {
            let (s , r) = hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(io)).await.map_err(|e|IoError::other(e))?;
            tokio::spawn(r);
             *self.h2.borrow_mut() = Some(s);
            }else{
            let (s , r) = hyper::client::conn::http1::handshake(TokioIo::new(io)).await.map_err(|e|IoError::other(e))?;
            tokio::spawn(r);
             *self.h1.borrow_mut() = Some(s);
            }
            },*/
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