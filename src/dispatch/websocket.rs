use bytes::BytesMut;
use hyper::{header, upgrade::Upgraded, Body, HeaderMap, Request, Response, StatusCode};
use log::error;
use std::net::SocketAddr;
use std::{
    io::{Error as IoError, ErrorKind},
    path::{Path, PathBuf},
};
use tokio_util::codec::{Decoder, Framed};
use websocket_codec::{ClientRequest, Message, MessageCodec, Opcode};
pub type AsyncClient = Framed<Upgraded, MessageCodec>;
use async_fcgi::stream::{FCGIAddr, Stream};
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub async fn upgrade(
    req: Request<Body>,
    ws: &Websocket,
    req_path: &Path,
    _remote_addr: SocketAddr,
) -> Result<Response<Body>, IoError> {
    //check if path is deeper than it should -> 404
    if !req_path.as_os_str().is_empty() {
        return Err(IoError::new(ErrorKind::NotFound, "WS mount had path"));
    }

    //update the request
    let mut res = Response::new(Body::empty());
    match *req.method() {
        hyper::Method::GET => {}
        hyper::Method::OPTIONS => {
            res.headers_mut()
                .insert(header::ALLOW, header::HeaderValue::from_static("GET"));
            return Ok(res);
        }
        _ => {
            *res.status_mut() = StatusCode::METHOD_NOT_ALLOWED;
            return Ok(res);
        }
    }

    let wscfg = match ws {
        /*
        Websocket::Proxy { forward } => {
            *res.status_mut() = StatusCode::NOT_IMPLEMENTED;
            return Ok(res);
        },*/
        Websocket::Unwraped(wscfg) => wscfg,
    };

    let ws_accept = if let Ok(req) = ClientRequest::parse(|name| {
        let h = req.headers().get(name)?;
        h.to_str().ok()
    }) {
        req.ws_accept()
    } else {
        return Err(IoError::new(ErrorKind::InvalidData, "wrong WS update"));
    };

    //TODO Sec-WebSocket-Protocol
    //TODO Sec-WebSocket-Extensions

    let addr: FCGIAddr = (&wscfg.assock).into();
    let forward_header = wscfg.forward_header;

    tokio::task::spawn(async move {
        let header = if forward_header {
            error!("forwarding header...");
            Some(req.headers().clone())
        } else {
            None
        };
        match hyper::upgrade::on(req).await {
            Ok(upgraded) => {
                let client = MessageCodec::server().framed(upgraded);
                websocket(addr, header, client).await;
            }
            Err(e) => error!("upgrade error: {}", e),
        }
    });

    *res.status_mut() = StatusCode::SWITCHING_PROTOCOLS;

    let headers = res.headers_mut();
    headers.insert(
        header::UPGRADE,
        header::HeaderValue::from_static("websocket"),
    );
    headers.insert(
        header::CONNECTION,
        header::HeaderValue::from_static("Upgrade"),
    );
    headers.insert(
        header::SEC_WEBSOCKET_ACCEPT,
        header::HeaderValue::from_str(&ws_accept).unwrap(),
    );
    Ok(res)
}

async fn send_header(backend: &mut Stream, header: HeaderMap) -> Result<(), IoError> {
    /*
    host: 127.0.0.1:2330
    user-agent: Mozilla/5.0
    accept: *
    accept-language: en-US,en;q=0.7,de;
    accept-encoding: gzip, deflate
    origin: http://127.0.0.1:2330
    sec-websocket-extensions: permessage-deflate
    dnt: 1
    pragma: no-cache
    cache-control: no-cache
        */
    let skip = [
        header::SEC_WEBSOCKET_VERSION,
        header::SEC_WEBSOCKET_KEY,
        header::CONNECTION,
        header::UPGRADE,
    ];
    //append all HTTP headers
    for (key, value) in header.iter() {
        if skip.iter().any(|x| x == key) {
            continue;
        }
        backend.write_all(key.as_str().as_bytes()).await?;
        backend.write_all(&b": "[..]).await?;
        backend.write_all(value.as_bytes()).await?;
        backend.write_all(&b"\r\n"[..]).await?;
    }
    backend.write_all(&b"\r\n"[..]).await?;
    Ok(())
}

async fn websocket(addr: FCGIAddr, header: Option<HeaderMap>, mut frontend: AsyncClient) {
    match Stream::connect(&addr).await {
        Ok(mut backend) => {
            if let Some(header) = header {
                //send headers
                if let Err(e) = send_header(&mut backend, header).await {
                    error!("could not send to backend: {}", e);
                    let _ = frontend.send(Message::close(None)).await;
                    return;
                }
            }

            loop {
                let mut buffer = BytesMut::with_capacity(8192);
                tokio::select! {
                    msg = frontend.next() => {
                        let msg = match msg {
                            Some(Ok(msg)) => msg,
                            Some(Err(e)) => {error!("websocket error: {}", e);break},
                            None => break,
                        };

                        match msg.opcode() {
                            Opcode::Text => {
                                /*match &wscfg.encoding {
                                    None => {*/
                                        error!("websocket without encoding got text");break
                                   /* },
                                    Some(enc) => {
                                        //TODO encode to bytes
                                    }
                                }*/
                            },
                            Opcode::Binary => {
                                if let Err(e) = backend.write_all(&msg.into_data()).await {
                                    error!("backend socket error: {}", e);
                                    break;
                                }
                            },
                            Opcode::Ping => {
                                let _ = frontend.send(Message::pong(msg.into_data())).await;
                            },
                            Opcode::Close => {
                                break;
                            }
                            Opcode::Pong => {},
                        };

                    },
                    data = backend.read_buf(&mut buffer) => {
                        let data = match data {
                            Ok(data) => data,
                            Err(e) => {error!("backend socket error: {}", e);break},
                        };
                        let _ = frontend.send(Message::binary(buffer.split_to(data))).await;
                    }
                }
            }
        }
        Err(e) => error!("could not connect backend: {}", e),
    }
    let _ = frontend.send(Message::close(None)).await;
}

impl From<&WSSock> for FCGIAddr {
    fn from(addr: &WSSock) -> FCGIAddr {
        match addr {
            WSSock::TCP(s) => FCGIAddr::Inet(*s),
            WSSock::Unix(p) => FCGIAddr::Unix(p.to_path_buf()),
        }
    }
}
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum WSSock {
    TCP(SocketAddr),
    Unix(PathBuf),
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
#[serde(deny_unknown_fields)]
pub enum Websocket {
    //    Proxy{forward: String},
    Unwraped(UnwrapedWS),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnwrapedWS {
    assock: WSSock,
    #[serde(default)]
    forward_header: bool, // = false
    encoding: Option<String>,
}
impl Websocket {
    pub async fn setup(&self) -> Result<(), String> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::UseCase;
    #[test]
    fn basic_config() {
        if let Ok(UseCase::Websocket(w)) = toml::from_str(
            r#"
            assock = "127.0.0.1:1337"
        "#,
        ) {
            if let Websocket::Unwraped(u) = w {
                assert_eq!(u.forward_header, false);
            } else {
                panic!("not a Unwraped webdav");
            }
        } else {
            panic!("not a webdav");
        }
    }
}
