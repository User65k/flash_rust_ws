use bytes::BytesMut;
use hyper::{header, HeaderMap, Response, StatusCode};
use log::error;
use std::io::{Error as IoError, ErrorKind};
use std::net::SocketAddr;
use tokio_util::codec::{Decoder, Framed};
use websocket_codec::{ClientRequest, Message, MessageCodec, Opcode};
type AsyncClient = Framed<MyUpgraded, MessageCodec>;
use async_stream_connection::{Addr, Stream};
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::{
    body::{BoxBody, FRWSResult, IncomingBody},
    dispatch::{upgrades::MyUpgraded, webpath::Req},
};

fn check_h2_ws(parts: &hyper::http::request::Parts) -> bool {
    //https://www.rfc-editor.org/rfc/rfc8441.html
    parts.extensions.get::<hyper::ext::Protocol>().is_some_and(|proto|proto.as_str() == "websocket")
    && !parts.headers.contains_key(header::UPGRADE)
    && !parts.headers.contains_key(header::CONNECTION)
    //do not do the processing of the Sec-WebSocket-Key and Sec-WebSocket-Accept header fields
    && parts.headers.get(header::SEC_WEBSOCKET_VERSION).is_some_and(|v|v=="13")
}

pub async fn upgrade(
    req: Req<IncomingBody>,
    ws: &Websocket,
    _remote_addr: SocketAddr,
) -> FRWSResult {
    //update the request
    let mut res = Response::new(BoxBody::empty());
    //TODO? check if path is deeper than it should -> 404
    if !req.path().is_empty() {
        *res.status_mut() = StatusCode::NOT_FOUND;
        return Ok(res);
    }
    let (mut parts, body) = req.into_parts();
    match parts.version {
        hyper::Version::HTTP_11 => {
            //https://www.rfc-editor.org/rfc/rfc6455
            match parts.method {
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
                let h = parts.headers.get(name)?;
                h.to_str().ok()
            }) {
                req.ws_accept()
            } else {
                return Err(IoError::new(ErrorKind::InvalidData, "wrong WS update"));
            };

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
            *res.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
        }
        hyper::Version::HTTP_2 => {
            //https://www.rfc-editor.org/rfc/rfc8441.html
            match parts.method {
                hyper::Method::CONNECT => {}
                hyper::Method::OPTIONS => {
                    res.headers_mut()
                        .insert(header::ALLOW, header::HeaderValue::from_static("CONNECT"));
                    return Ok(res);
                }
                _ => {
                    *res.status_mut() = StatusCode::METHOD_NOT_ALLOWED;
                    return Ok(res);
                }
            }
            if !check_h2_ws(&parts) {
                return Err(IoError::new(ErrorKind::InvalidData, "wrong WS update"));
            }
            *res.status_mut() = StatusCode::OK;
        }
        _ => {
            *res.status_mut() = StatusCode::HTTP_VERSION_NOT_SUPPORTED;
            return Ok(res);
        }
    }
    //TODO Sec-WebSocket-Protocol
    //TODO Sec-WebSocket-Extensions

    let addr = ws.assock.clone(); //TODO config lives long enough
    let forward_header = ws.forward_header;

    let header = if forward_header {
        error!("forwarding header...");
        Some(core::mem::take(&mut parts.headers))
    } else {
        None
    };
    let req = hyper::Request::from_parts(parts, body);
    tokio::task::spawn(async move {
        match hyper::upgrade::on(req).await {
            Ok(upgraded) => {
                let client = MessageCodec::server().framed(MyUpgraded::new(upgraded));
                websocket(&addr, header, client).await;
            }
            Err(e) => error!("upgrade error: {}", e),
        }
    });

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

        let _s = crate::tests::prep_test_server(
            l,
            a,
            WwwRoot {
                mount: UseCase::Websocket(ws_cfg),
                header: None,
                auth: None,
            },
            #[cfg(feature = "tlsrust")]
            None,
        )
        .await;

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
    #[cfg(any(feature = "tlsrust", feature = "tlsnative"))]
    #[tokio::test]
    async fn as_sock_h2() {
        use crate::tests::create_tls_cfg;
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

        let (mut config, tlscfg) = create_tls_cfg().await;

        let (l, a) = local_socket_pair().await.unwrap();

        let _s = crate::tests::prep_test_server(
            l,
            a,
            WwwRoot {
                mount: UseCase::Websocket(ws_cfg),
                header: None,
                auth: None,
            },
            Some(tlscfg),
        )
        .await;

        let stream = tokio::net::TcpStream::connect(a).await.unwrap();
        #[cfg(feature = "tlsrust")]
        let mut stream = {
            let dnsname =
                tokio_rustls::rustls::pki_types::ServerName::try_from("example.com").unwrap();
            config.alpn_protocols.push(b"h2".to_vec());
            let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(config));
            connector.connect(dnsname, stream).await.unwrap()
        };

        let h = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\0\0\0\x04\0\0\0\0\0";
        //                   PREFACE------------------------- Len (0)---  TypFlag ID-------------

        stream.write_all(h).await.unwrap();

        let req = b"\0\0A\x01\x04\0\0\0\x01B\x87\xbd\xabN\x9c\x17\xb7\xffD\x82`\x7fA\x8c\x9d)\xacK\xccz\x07T\xcb\x9e\xc9\xbf\x87@\x87\xb9]\x87I\xc8z?\x87\xf0X\xd0ru*\x7f@\x8fAH\xb7\x82\xc6\x83\x93\xa9R\xb7r\xd8\x83\x1e\xaf\x82\x0b?";
        /*headers = [
            (':method', 'CONNECT'),
            (':path', '/a'),
            (':authority', SERVER_NAME),
            (':scheme', 'https'),
            (':protocol','websocket'),
            ('sec-websocket-version','13')
        ]*/
        stream.write_all(req).await.unwrap();

        //                                        HEADERS + END_HEADERS
        //                                        :status = 200
        let mut buf = [0u8; 180];
        let mut ack = false;
        loop {
            println!("wait1");
            stream.read_exact(&mut buf[..4]).await.unwrap();
            assert_eq!(buf[0], 0);
            assert_eq!(buf[1], 0);
            assert_ne!(buf[3], 3); //not reset_stream
            assert_ne!(buf[3], 7); //not goaway
            let off = buf[2] as usize + 5;
            println!("wait2");
            stream.read_exact(&mut buf[4..off + 4]).await.unwrap();
            println!("got {:?}", &buf[..off + 4]);
            if !ack && buf[3] == 4 && buf[4] == 0 {
                //Settings
                //SETTINGS_ENABLE_CONNECT_PROTOCOL (8) = 1
                assert!(buf[4 + 5..].chunks(6).any(|kv| kv == b"\0\x08\0\0\0\x01"));

                println!("ack");
                let req = b"\0\0\0\x04\x01\0\0\0\0";
                stream.write_all(req).await.unwrap();
                ack = true;
            }
            if buf[3] == 1 && buf[4] == 4 {
                //Header + END_HEADERS
                assert_eq!(buf[9], 0x88); //:status = 200
                println!("done");
                break;
            }
        }
        //DATA
        //WebSocket Data
        //                                        DATA + END_STREAM
        //                                        WebSocket Data
        //DATA + END_STREAM
        //WebSocket Data

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
        stream.write_all(b"\0\0\x12\0\0\0\0\0\x01\x81\x8c\xe1\x7e\x8e\xb9\x95\x1b\xfd\xcd\xc1\x13\xeb\xca\x92\x1f\xe9\xdc")
            .await
            .unwrap();

        stream
            .read_exact(&mut buf[..6 + 5 + 4 + 2 + 5 + 4])
            .await
            .unwrap();

        t.await.unwrap().unwrap();
        /*
        Opcode Binary + Opcode Close
         */
        assert_eq!(
            &buf[..6 + 5 + 4 + 2 + 5 + 4],
            b"\0\0\x06\0\0\0\0\0\x01\x82\x04answ\0\0\x02\0\0\0\0\0\x01\x88\0"
        );
    }
}
