use bytes::BytesMut;
use hyper::{header, upgrade::Upgraded, Body, HeaderMap, Request, Response, StatusCode};
use log::error;
use std::io::{Error as IoError, ErrorKind};
use std::net::SocketAddr;
use tokio_util::codec::{Decoder, Framed};
use websocket_codec::{ClientRequest, Message, MessageCodec, Opcode};
pub type AsyncClient = Framed<Upgraded, MessageCodec>;
use async_stream_connection::{Addr, Stream};
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub async fn upgrade(
    req: Request<Body>,
    ws: &Websocket,
    req_path: &super::WebPath<'_>,
    _remote_addr: SocketAddr,
) -> Result<Response<Body>, IoError> {
    //update the request
    let mut res = Response::new(Body::empty());
    //TODO? check if path is deeper than it should -> 404
    if !req_path.is_empty() {
        *res.status_mut() = StatusCode::NOT_FOUND;
        return Ok(res);
    }
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

    let addr = ws.assock.clone(); //TODO config lives long enough
    let forward_header = ws.forward_header;

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
                websocket(&addr, header, client).await;
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

async fn websocket(addr: &Addr, header: Option<HeaderMap>, mut frontend: AsyncClient) {
    match Stream::connect(addr).await {
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
                            Opcode::Text  | Opcode::Binary => {
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
                        if data==0 {break;}
                        let _ = frontend.send(Message::binary(buffer.split_to(data))).await;
                    }
                }
            }
        }
        Err(e) => error!("could not connect backend: {}", e),
    }
    let _ = frontend.send(Message::close(None)).await;
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Websocket {
    assock: Addr,
    #[serde(default)]
    forward_header: bool, // = false
}
impl Websocket {
    pub async fn setup(&self) -> Result<(), String> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use tokio::task::JoinHandle;

    use super::*;
    use crate::config::*;
    use crate::tests::local_socket_pair;
    #[test]
    fn basic_config() {
        if let Ok(UseCase::Websocket(w)) = toml::from_str(
            r#"
            assock = "127.0.0.1:1337"
        "#,
        ) {
            assert_eq!(w.forward_header, false);
        } else {
            panic!("not a webdav");
        }
    }
    #[test]
    fn parse_addr() {
        assert!(if let Ok(UseCase::Websocket(Websocket {
            assock: Addr::Inet(a),
            ..
        })) = toml::from_str(
            r#"
            assock = "127.0.0.1:9000"
        "#,
        ) {
            a.port() == 9000 && a.is_ipv4() && a.ip().is_loopback()
        } else {
            false
        });
        assert!(if let Ok(UseCase::Websocket(Websocket {
            assock: Addr::Inet(a),
            ..
        })) = toml::from_str(
            r#"
            assock = "localhost:9000"
        "#,
        ) {
            a.port() == 9000
        } else {
            false
        });
        assert!(if let Ok(UseCase::Websocket(Websocket {
            assock: Addr::Inet(a),
            ..
        })) = toml::from_str(
            r#"
            assock = "[::1]:9000"
        "#,
        ) {
            a.port() == 9000 && a.is_ipv6() && a.ip().is_loopback()
        } else {
            false
        });
        #[cfg(unix)]
        assert!(if let Ok(UseCase::Websocket(Websocket {
            assock: Addr::Unix(a),
            ..
        })) = toml::from_str(
            r#"
            assock = "/path"
        "#,
        ) {
            a == std::path::Path::new("/path")
        } else {
            false
        });
    }
    #[tokio::test]
    async fn insert_header() {
        let (l, a) = local_socket_pair().await.unwrap();
        tokio::spawn(async move {
            let (mut s, _a) = l.accept().await.unwrap();
            let mut buf = Vec::with_capacity(400);
            let _l = s.read_buf(&mut buf).await.unwrap();
            assert_eq!(buf, b"accept: *\r\npragma: no-cache\r\n\r\n");
        });
        let mut backend = Stream::connect(&a.into()).await.unwrap();
        let mut header = HeaderMap::new();
        header.insert("accept", "*".parse().unwrap());
        header.insert("pragma", "no-cache".parse().unwrap());
        header.insert("upgrade", "upgrade".parse().unwrap());
        send_header(&mut backend, header).await.unwrap();
    }
    async fn connect_to_ws(ws_cfg: Websocket) -> Result<tokio::net::TcpStream, Box<dyn Error>> {
        //We can not use a Request Object for the test,
        //as it has no associated connection
        let (l, a) = local_socket_pair().await?;

        let mut listening_ifs = std::collections::HashMap::new();
        let mut cfg = HostCfg::new(l.into_std()?);
        let mut vh = VHost::new(a);
        vh.paths.insert(
            Utf8PathBuf::from("a"),
            WwwRoot {
                mount: UseCase::Websocket(ws_cfg),
                header: None,
                auth: None,
            },
        );
        cfg.default_host = Some(vh);
        listening_ifs.insert(a, cfg);

        let _s = crate::prepare_hyper_servers(listening_ifs).await?;

        let mut test = tokio::net::TcpStream::connect(a).await?;
        test.write_all(b"GET /a HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: x3JJHMbDL1EzLkh9GBhXDw==\r\n\r\n").await?;
        Ok(test)
    }
    #[tokio::test]
    async fn as_sock() {
        let (l, a) = local_socket_pair().await.unwrap();

        let ws_cfg = Websocket {
            assock: Addr::Inet(a),
            forward_header: false,
        };

        let t: JoinHandle<Result<(), std::io::Error>> = tokio::spawn(async move {
            let (mut s, _a) = l.accept().await?;

            let mut buf = [0u8; 12];
            let i = s.read_exact(&mut buf).await?;
            assert_eq!(&buf[..i], b"test message");

            s.write_all(b"answ").await?;
            Ok(())
        });

        let mut test = connect_to_ws(ws_cfg).await.unwrap();

        let mut buf = [0u8; 512];
        let i = test.read(&mut buf).await.unwrap();
        assert!(i > 15);
        assert_eq!(&buf[..15], b"HTTP/1.1 101 Sw");

        /*WebSocket
            1... .... = Fin: True
            .000 .... = Reserved: 0x0
            .... 0001 = Opcode: Text (1)
            1... .... = Mask: True
            .000 1100 = Payload length: 12
            Masking-Key: e17e8eb9
            Masked payload
            Payload
        JavaScript Object Notation
        Line-based text data
            test message*/
        test.write_all(b"\x81\x8c\xe1\x7e\x8e\xb9\x95\x1b\xfd\xcd\xc1\x13\xeb\xca\x92\x1f\xe9\xdc")
            .await
            .unwrap();

        let mut vec = Vec::new();
        test.read_to_end(&mut vec).await.unwrap();

        t.await.unwrap().unwrap();
        /*
        Opcode Binary + Opcode Close
         */
        assert_eq!(vec, b"\x82\x04answ\x88\0");
    }
}
