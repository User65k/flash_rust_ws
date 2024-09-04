use super::cfg::ProxySocket;
use super::*;
use hyper::Request;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

use crate::{
    body::{test::TestBody, FRWSResp},
    config::{UseCase, Utf8PathBuf},
};

fn create_conf(f: impl FnOnce(&mut Proxy)) -> Proxy {
    let mut p = Proxy {
        forward: "http://ignored/".to_string().try_into().unwrap(),
        add_forwarded_header: ForwardedHeader::Remove,
        add_x_forwarded_for_header: false,
        add_via_header_to_client: None,
        add_via_header_to_server: None,
        force_dir: true,
        client: None,
        allowed_upgrades: None,
        allowed_methods: None,
        filter_req_header: None,
        filter_resp_header: None,
        h1_pool_size: 2,
        tls_root: None,
    };
    f(&mut p);
    p
}

#[test]
fn basic_config() {
    if let Ok(UseCase::Proxy(p)) = toml::from_str(
        r#"
        forward = "http://remote/path"
    "#,
    ) {
        assert_eq!(p.forward.host, "remote");
        assert_eq!(p.forward.scheme, uri::Scheme::HTTP);
        assert_eq!(p.forward.path, Utf8PathBuf::from("/path"));
        assert!(p.force_dir);
        assert!(matches!(p.add_forwarded_header, ForwardedHeader::Replace));
        assert!(!p.add_x_forwarded_for_header);
    } else {
        panic!("not proxy");
    }
}
#[test]
fn resolve_dns_later() {
    use std::net::*;
    assert!(matches!(ProxySocket::from(("test", 123)), ProxySocket::Dns((s, 123)) if s == "test"));
    assert!(
        matches!(ProxySocket::from(("127.0.0.1", 123)), ProxySocket::Ip(SocketAddr::V4(ip4)) if *ip4.ip() == Ipv4Addr::LOCALHOST)
    );
    assert!(
        matches!(ProxySocket::from(("::1", 123)), ProxySocket::Ip(SocketAddr::V6(ip6)) if *ip6.ip() == Ipv6Addr::LOCALHOST)
    );
}

/// send a request to a proxy mount and return its TcpStream
/// (as well as the Task doing the request)
async fn test_forward(
    mut req: Request<TestBody>,
    mut proxy: Proxy,
) -> (TcpStream, tokio::task::JoinHandle<FRWSResp>) {
    // pick a free port
    let (app_listener, a) = crate::tests::local_socket_pair().await.unwrap();

    if let Some(host) = req.headers().get(hyper::header::HOST).cloned() {
        req.extensions_mut()
            .insert(hyper::http::uri::Authority::from_maybe_shared(host).unwrap());
    }
    let req = Req::test_on_mount(req);

    proxy.forward.addr = ProxySocket::Ip(a);
    proxy.setup().await.unwrap();

    let m = tokio::spawn(async move {
        let res = forward(req, "1.2.3.4:42".parse().unwrap(), &proxy).await;
        res.unwrap()
    });
    let (app_socket, _) = app_listener.accept().await.unwrap();
    (app_socket, m)
}
#[tokio::test]
async fn simple_fwd() {
    let req = Request::get("/mount/some/path")
        .body(TestBody::empty())
        .unwrap();
    let (mut s, t) = test_forward(
        req,
        create_conf(|p| {
            p.forward = "http://ignored/base_path".to_string().try_into().unwrap();
            p.add_via_header_to_client = Some("rproxy1".to_string());
        }),
    )
    .await;

    let mut buf = [0u8; 25];
    let i = s.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf[..i], b"GET /base_path/some/path ");

    s.write_all(b"HTTP/1.0 500 Not so OK\r\n\r\n")
        .await
        .unwrap();
    let r = t.await.unwrap();
    assert_eq!(r.status(), 500);
    assert_eq!(
        r.headers().get(header::VIA),
        Some(&HeaderValue::from_static("HTTP/1.0 rproxy1"))
    );
}
#[tokio::test]
async fn add_headers() {
    let req = Request::get("/mount/")
        .header(header::HOST, "a_host")
        .header(header::FORWARDED, "for=10.10.10.10")
        .version(hyper::Version::HTTP_10)
        .body(TestBody::empty())
        .unwrap();
    let (mut s, t) = test_forward(
        req,
        create_conf(|p| {
            p.add_forwarded_header = ForwardedHeader::Replace;
            p.add_x_forwarded_for_header = true;
            p.add_via_header_to_server = Some("rproxy1".to_string());
        }),
    )
    .await;

    let mut buf = [0u8; 16];
    let i = s.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf[..i], b"GET / HTTP/1.1\r\n");
    let mut buf = BytesMut::with_capacity(4096);
    s.read_buf(&mut buf).await.unwrap();

    assert_eq!(get_header(&buf, "via").unwrap(), b"HTTP/1.0 rproxy1");
    assert_eq!(
        get_header(&buf, "forwarded").unwrap(),
        b"for=1.2.3.4; host=a_host"
    );

    //return something else than 200
    s.write_all(b"HTTP/1.0 500 Not so OK\r\n\r\n")
        .await
        .unwrap();
    let r = t.await.unwrap();
    assert_eq!(r.status(), 500);
}
#[tokio::test]
async fn remove_hop_headers() {
    let req = Request::get("/mount/")
        .header(header::CONNECTION, "close")
        .header(header::TRANSFER_ENCODING, "value")
        .header("keep-alive", "value")
        .header(header::TE, "value")
        .header(header::TRAILER, "value")
        .header(header::PROXY_AUTHENTICATE, "value")
        .header(header::PROXY_AUTHORIZATION, "value")
        .body(TestBody::empty())
        .unwrap();
    let (mut s, t) = test_forward(req, create_conf(|_p| ())).await;

    let mut buf = Vec::with_capacity(4096);
    s.read_buf(&mut buf).await.unwrap();

    let dont_include = [
        "keep-alive",
        "transfer-encoding",
        "te",
        "trailer",
        "proxy-authorization",
        "proxy-authenticate",
    ];
    for kw in dont_include {
        assert_eq!(get_header(&buf, kw), None);
    }
    assert_eq!(get_header(&buf, "connection"), Some(&b"keep-alive"[..]));

    //return something else than 200
    s.write_all(b"HTTP/1.0 500 Not so OK\r\n\r\n")
        .await
        .unwrap();
    let r = t.await.unwrap();
    assert_eq!(r.status(), 500);
}
#[tokio::test]
async fn web_mount_is_a_folder() {
    let req = Request::get("/mount").body(TestBody::empty()).unwrap();

    let req = Req::test_on_mount(req);

    let proxy = create_conf(|p| {
        p.forward = "http://localhost:0/".to_string().try_into().unwrap();
    });

    let t = tokio::spawn(async move {
        let res = crate::dispatch::handle_wwwroot(
            req,
            &crate::config::WwwRoot {
                mount: crate::config::UseCase::Proxy(proxy),
                header: None,
                auth: None,
            },
            "1.2.3.4:42".parse().unwrap(),
        )
        .await;
        res.unwrap()
    });

    let r = t.await.unwrap();
    assert_eq!(r.status(), 301);
    assert_eq!(r.headers().get(header::LOCATION).unwrap(), "/mount/");
}
#[tokio::test]
async fn force_dir_false() {
    let req = Request::get("/mount").body(TestBody::empty()).unwrap();
    let (mut s, t) = test_forward(
        req,
        create_conf(|p| {
            p.force_dir = false;
        }),
    )
    .await;

    let mut buf = Vec::with_capacity(4096);
    s.read_buf(&mut buf).await.unwrap();

    //return something else than 200
    s.write_all(b"HTTP/1.0 201 Not so OK\r\n\r\n")
        .await
        .unwrap();
    let r = t.await.unwrap();
    assert_eq!(r.status(), 201);
}
/// ensure that via and forwarded entries are in the correct order
#[tokio::test]
async fn header_chaining() {
    let req = Request::get("/mount/")
        .header(header::VIA, "HTTP/0.9 someone")
        .header(&X_FORWARDED_FOR, "10.10.10.10")
        .header(header::FORWARDED, "for=10.10.10.10")
        .body(TestBody::empty())
        .unwrap();
    let (mut s, t) = test_forward(
        req,
        create_conf(|p| {
            p.add_forwarded_header = ForwardedHeader::Extend;
            p.add_x_forwarded_for_header = true;
            p.add_via_header_to_client = Some("my_front".to_string());
            p.add_via_header_to_server = Some("me".to_string());
        }),
    )
    .await;

    let mut buf = Vec::with_capacity(4096);
    s.read_buf(&mut buf).await.unwrap();

    assert_eq!(
        get_header(&buf, "via").unwrap(),
        b"HTTP/0.9 someone, HTTP/1.1 me"
    );
    assert_eq!(
        get_header(&buf, "forwarded").unwrap(),
        b"for=10.10.10.10, for=1.2.3.4"
    );
    assert_eq!(
        get_header(&buf, "x-forwarded-for").unwrap(),
        b"10.10.10.10, 1.2.3.4"
    );

    //return something else than 200
    s.write_all(b"HTTP/1.0 203 Not so OK\r\nvia: HTTP/0.9 another\r\n\r\n")
        .await
        .unwrap();
    let r = t.await.unwrap();
    assert_eq!(
        r.headers().get(header::VIA).unwrap().as_bytes(),
        b"HTTP/0.9 another, HTTP/1.0 my_front"
    );
    assert_eq!(r.status(), 203);
}

async fn full_server_test(
    f: impl FnOnce(&mut Proxy),
    #[cfg(any(feature = "tlsrust", feature = "tlsnative"))] tls: Option<
        crate::transport::tls::ParsedTLSConfig,
    >,
) -> Result<(tokio::net::TcpStream, tokio::net::TcpListener), Box<dyn std::error::Error>> {
    //We can not use a Request Object for the test,
    //as it has no associated connection
    let (server_listener, a) = crate::tests::local_socket_pair().await?;
    let (target_listener, target_add) = crate::tests::local_socket_pair().await.unwrap();

    let mut proxy = create_conf(f);
    proxy.forward.addr = ProxySocket::Ip(target_add);
    proxy.setup().await.unwrap();

    let _s = crate::tests::prep_test_server(
        server_listener,
        a,
        crate::config::WwwRoot {
            mount: UseCase::Proxy(proxy),
            header: None,
            auth: None,
        },
        #[cfg(any(feature = "tlsrust", feature = "tlsnative"))]
        tls,
    )
    .await;

    let client = tokio::net::TcpStream::connect(a).await?;

    Ok((client, target_listener))
}
#[cfg(feature = "tlsrust")]
async fn full_tls_server_test(
    f: impl FnOnce(&mut Proxy),
    alpn: Option<&[u8]>,
) -> Result<
    (
        tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
        tokio::net::TcpListener,
    ),
    Box<dyn std::error::Error>,
> {
    let (mut cc, tls) = crate::tests::create_tls_cfg().await;
    let (stream, l) = full_server_test(f, Some(tls)).await?;

    let dnsname = tokio_rustls::rustls::pki_types::ServerName::try_from("example.com").unwrap();
    if let Some(alpn) = alpn {
        cc.alpn_protocols.push(alpn.to_vec());
    }
    let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(cc));
    let stream = connector.connect(dnsname, stream).await.unwrap();
    Ok((stream, l))
}

///test upgrade
#[tokio::test]
async fn upgrade_h11() {
    let (mut client, target_listener) = full_server_test(
        |p| {
            p.force_dir = false;
        },
        #[cfg(any(feature = "tlsrust", feature = "tlsnative"))]
        None,
    )
    .await
    .unwrap();

    let t = tokio::spawn(async move {
        let (mut server, _) = target_listener.accept().await.unwrap();
        let mut buf = Vec::with_capacity(4096);
        server.read_buf(&mut buf).await.unwrap();
        assert_eq!(get_header(&buf, "connection").unwrap(), b"UPGRADE");
        assert_eq!(get_header(&buf, "upgrade").unwrap(), b"something");

        server
            .write_all(b"HTTP/1.1 101 SWITCHING_PROTOCOLS\r\nUpgrade: something\r\nConnection: Upgrade\r\n\r\n")
            .await
            .unwrap();

        buf.clear();
        server.read_buf(&mut buf).await.unwrap();
        assert_eq!(buf, b"\x01\x02\x03\xff");

        server.write_all(b"\xff\xfe\x00").await.unwrap();
    });

    client
        .write_all(b"GET /a HTTP/1.1\r\nUpgrade: something\r\nConnection: Upgrade\r\n\r\n")
        .await
        .unwrap();

    let mut buf = Vec::with_capacity(4096);
    client.read_buf(&mut buf).await.unwrap();
    assert_eq!(&buf[..34], b"HTTP/1.1 101 SWITCHING_PROTOCOLS\r\n");
    assert_eq!(get_header(&buf, "connection").unwrap(), b"UPGRADE");
    assert_eq!(get_header(&buf, "upgrade").unwrap(), b"something");

    client.write_all(b"\x01\x02\x03\xff").await.unwrap();
    buf.clear();
    client.read_buf(&mut buf).await.unwrap();
    assert_eq!(buf, b"\xff\xfe\x00");

    t.await.unwrap();
}

/// search a HTTP header value inside of a byte stream.
fn get_header<'a>(haystack: &'a [u8], param: &'_ str) -> Option<&'a [u8]> {
    if let Some(pos) = haystack.windows(param.len() + 4).position(|window| {
        &window[2..param.len() + 2] == param.as_bytes()
            && &window[..2] == b"\r\n"
            && &window[param.len() + 2..] == b": "
    }) {
        let start = pos + param.len() + 4;
        if let Some(len) = haystack[start..]
            .windows(2)
            .position(|window| window == b"\r\n")
        {
            return Some(&haystack[start..start + len]);
        }
    }
    None
}

#[tokio::test]
async fn h11_keep_alive() {
    let (mut client, target_listener) = full_server_test(
        |p| {
            p.force_dir = false;
        },
        #[cfg(any(feature = "tlsrust", feature = "tlsnative"))]
        None,
    )
    .await
    .unwrap();

    let t = tokio::spawn(async move {
        let (mut server, _) = target_listener.accept().await.unwrap();
        let mut buf = Vec::with_capacity(4096);

        server.read_buf(&mut buf).await.unwrap();
        assert_eq!(get_header(&buf, "connection").unwrap(), b"keep-alive");
        server
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            .await
            .unwrap();

        buf.clear();

        server.read_buf(&mut buf).await.unwrap();
        assert_eq!(get_header(&buf, "connection").unwrap(), b"keep-alive");
        server
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();

        buf.clear();
        let (mut server, _) = target_listener.accept().await.unwrap();

        server.read_buf(&mut buf).await.unwrap();
        assert_eq!(get_header(&buf, "connection").unwrap(), b"keep-alive");
        server
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            .await
            .unwrap();
    });
    let mut buf = Vec::with_capacity(4096);

    client.write_all(b"GET /a HTTP/1.1\r\n\r\n").await.unwrap();

    client.read_buf(&mut buf).await.unwrap();
    assert_eq!(&buf[..15], b"HTTP/1.1 200 OK");

    buf.clear();
    client.write_all(b"GET /a HTTP/1.1\r\n\r\n").await.unwrap();

    client.read_buf(&mut buf).await.unwrap();
    assert_eq!(&buf[..15], b"HTTP/1.1 200 OK");

    buf.clear();
    client.write_all(b"GET /a HTTP/1.1\r\n\r\n").await.unwrap();

    client.read_buf(&mut buf).await.unwrap();
    assert_eq!(&buf[..15], b"HTTP/1.1 200 OK");

    t.await.unwrap();
}

#[tokio::test]
async fn h2_simple_fwd() {
    let req = Request::get("/mount/some/path")
        .body(TestBody::empty())
        .unwrap();
    let (s, t) = test_forward(
        req,
        create_conf(|p| {
            p.forward = "h2://ignored/base_path".to_string().try_into().unwrap();
        }),
    )
    .await;

    tokio::spawn(
        hyper::server::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new())
            .serve_connection(
                hyper_util::rt::TokioIo::new(s),
                hyper::service::service_fn(|req| async move {
                    assert_eq!(req.uri(), "http://ignored/base_path/some/path");
                    hyper::Response::builder()
                        .status(301)
                        .body(TestBody::empty())
                }),
            ),
    );

    let r = t.await.unwrap();
    assert_eq!(r.status(), 301);
}

#[tokio::test]
async fn filter_headers() {
    let req = Request::get("/mount/")
        .header("some", "value")
        .header("thing", "value")
        .header("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
        .header("Accept-Encoding", "gzip, deflate, br, zstd")
        .header("Accept-Language", "en-US,en;q=0.9,de;q=0.8")
        .header("Cache-Control", "max-age=0")
        .header("Cookie", "_octo=GH1.1.821435309.1704463705; logged_in=no; _gh_sess=2qhyBsnL%2FTCqdE1MoHl9%2BMUWchfdzRz8YHHEbIFHaLSun5TRiGqaRZG88C%2B7g38pdQTspFFR3cJrrffmdxbja7XIXNTmkc7a9WT6m2EcqC0u8Ut4hWkz0JlEwSGe3bNGm60kYMcLeYF0h%2BtPLUp57gBxf6iy7l%2BljNjEVuTpQiBBMo%2FAT5VVbGXO2%2Fd%2B8tGskyizS9I227SYpU7N8WN7CI%2BGFcvLDpqmF4hr8WwJhO4OoW0hEwoyYwd4tlsePR5PtzJiZHPD91Pzow1w6dW56w%3D%3D--H8yiiZL8FqeSie7Z--3kYhBPCwCOlTLbLTigkNmw%3D%3D; preferred_color_mode=light; tz=Europe%2FBerlin")
        .header("If-None-Match", "W/\"39da1b67f97f7caf432e699491ee62a4")
        .header("Referer", "https://nnethercote.github.io/")
        .header("Sec-Ch-Ua", "\"Chromium\";v=\"123\", \"Not:A-Brand\";v=\"8\"")
        .header("Sec-Ch-Ua-Mobile", "?0")
        .header("Sec-Ch-Ua-Platform", "\"Linux\"")
        .header("Sec-Fetch-Dest", "document")
        .header("Sec-Fetch-Mode", "navigate")
        .header("Sec-Fetch-Site", "same-origin")
        .header("Sec-Fetch-User", "?1")
        .header("Upgrade-Insecure-Requests", "1")
        .header("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36")
        .body(TestBody::empty())
        .unwrap();
    let (mut s, t) = test_forward(
        req,
        create_conf(|p| {
            p.filter_req_header = Some(vec![HeaderNameCfg("some".try_into().unwrap())]);
            p.filter_resp_header = Some(vec![HeaderNameCfg("foo".try_into().unwrap())]);
        }),
    )
    .await;

    let mut buf = Vec::with_capacity(4096);
    s.read_buf(&mut buf).await.unwrap();

    assert_eq!(get_header(&buf, "thing"), None);
    assert_eq!(get_header(&buf, "some"), Some(&b"value"[..]));

    //return something else than 200
    s.write_all(b"HTTP/1.0 200 OK\r\nfoo: 1\r\nbar: 2\r\n\r\n")
        .await
        .unwrap();
    let r = t.await.unwrap();

    let h = "1".try_into().unwrap();
    assert_eq!(r.headers().get("foo"), Some(&h));
    assert_eq!(r.headers().get("bar"), None);
}

#[cfg(feature = "tlsrust")]
async fn create_tls_cfg() -> (tokio_rustls::TlsAcceptor, crate::dispatch::test::TempFile) {
    use std::sync::Arc;

    use crate::dispatch::test::TempFile;
    use rustls_pemfile::{read_one, Item};
    use tokio_rustls::{
        rustls::{pki_types::PrivateKeyDer, ServerConfig},
        TlsAcceptor,
    };

    let c = crate::transport::tls::test::CERT;
    let crt_file = TempFile::create("example.com_localhost.pem", c);
    let cert_chain = match read_one(&mut &c[..]) {
        Ok(Some(Item::X509Certificate(der))) => der,
        _ => panic!(),
    };
    let mut k = crate::transport::tls::test::ED_KEY;
    let key_der = match read_one(&mut k) {
        Ok(Some(Item::Pkcs8Key(der))) => PrivateKeyDer::Pkcs8(der),
        _ => panic!(),
    };

    let sc = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_chain], key_der)
        .unwrap();
    let connector = TlsAcceptor::from(Arc::new(sc));

    (connector, crt_file)
}
#[cfg(any(feature = "tlsrust", feature = "tlsnative"))]
#[tokio::test]
async fn https_simple_fwd() {
    let (accept, cert) = create_tls_cfg().await;

    let req = Request::get("/mount/some/path")
        .body(TestBody::empty())
        .unwrap();

    // pick a free port
    let (app_listener, a) = crate::tests::local_socket_pair().await.unwrap();
    let accept = tokio::spawn(async move {
        let (plain, _) = app_listener.accept().await?;
        accept.accept(plain).await
    });
    let req = Req::test_on_mount(req);
    let mut proxy = create_conf(|p| {
        p.forward = "https://127.0.0.1/base_path"
            .to_string()
            .try_into()
            .unwrap();
        p.tls_root = Some(cert.get_path().to_path_buf().try_into().unwrap());
    });
    proxy.forward.addr = ProxySocket::Ip(a);
    proxy.setup().await.unwrap();

    let t = tokio::spawn(async move {
        let res = forward(req, "1.2.3.4:42".parse().unwrap(), &proxy).await;
        res.unwrap()
    });

    let mut s = accept.await.unwrap().unwrap();

    let mut buf = [0u8; 25];
    let i = s.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf[..i], b"GET /base_path/some/path ");

    s.write_all(b"HTTP/1.0 301 Blah\r\n\r\n").await.unwrap();

    let r = t.await.unwrap();
    assert_eq!(r.status(), 301);
}

#[tokio::test]
async fn upgrade_h11_to_h2() {
    let (mut client, target_listener) = full_server_test(
        |p| {
            p.force_dir = false;
            p.forward = "h2://ignored/base_path".to_string().try_into().unwrap();
        },
        None,
    )
    .await
    .unwrap();

    let _t = tokio::spawn(async move {
        let (s, _) = target_listener.accept().await.unwrap();
        hyper::server::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new())
            .enable_connect_protocol()
            .serve_connection(
                hyper_util::rt::TokioIo::new(s),
                hyper::service::service_fn(|req| async move {
                    assert_eq!(req.uri(), "http://ignored/base_path/");
                    assert_eq!(req.method(), hyper::Method::CONNECT);
                    assert_eq!(
                        req.extensions().get::<hyper::ext::Protocol>().unwrap(),
                        &hyper::ext::Protocol::from_static("websocket")
                    );
                    assert_eq!(
                        req.headers()
                            .get(hyper::header::SEC_WEBSOCKET_VERSION)
                            .unwrap(),
                        "13"
                    );
                    tokio::task::spawn(async move {
                        match hyper::upgrade::on(req).await {
                            Ok(upgraded) => {
                                let mut upgraded = hyper_util::rt::TokioIo::new(upgraded);
                                let mut buf = Vec::with_capacity(4096);
                                upgraded.read_buf(&mut buf).await.unwrap();
                                assert_eq!(buf, b"\x01\x02\x03\xff");

                                upgraded.write_all(b"\xff\xfe\x00").await.unwrap();
                            }
                            Err(e) => error!("upgrade error: {}", e),
                        }
                    });
                    hyper::Response::builder().body(TestBody::empty())
                }),
            )
            .await
    });

    client
        .write_all(b"GET /a HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: x3JJHMbDL1EzLkh9GBhXDw==\r\n\r\n")
        .await
        .unwrap();

    let mut buf = Vec::with_capacity(4096);
    client.read_buf(&mut buf).await.unwrap();
    assert_eq!(&buf[..34], b"HTTP/1.1 101 Switching Protocols\r\n");
    assert_eq!(get_header(&buf, "connection").unwrap(), b"UPGRADE");
    assert_eq!(get_header(&buf, "upgrade").unwrap(), b"websocket");
    let ws_a = get_header(&buf, "sec-websocket-accept").unwrap();
    assert_eq!(ws_a, b"HSmrc0sMlYUkAGmm5OPpG2HaGWk=");

    client.write_all(b"\x01\x02\x03\xff").await.unwrap();
    buf.clear();
    client.read_buf(&mut buf).await.unwrap();
    assert_eq!(buf, b"\xff\xfe\x00");

    //t.await.unwrap().unwrap();
}

#[tokio::test]
async fn upgrade_h2_to_h11() {
    let (mut client, target_listener) = full_tls_server_test(
        |p| {
            p.force_dir = false;
        },
        Some(b"h2"),
    )
    .await
    .unwrap();

    let t = tokio::spawn(async move {
        let (mut server, _) = target_listener.accept().await.unwrap();
        let mut buf = Vec::with_capacity(4096);
        server.read_buf(&mut buf).await.unwrap();
        assert_eq!(get_header(&buf, "connection").unwrap(), b"UPGRADE");
        assert_eq!(get_header(&buf, "upgrade").unwrap(), b"websocket");
        let ws_key = get_header(&buf, "sec-websocket-key").unwrap();
        assert_eq!(ws_key.len(), 24); //20 without base64

        server
            .write_all(b"HTTP/1.1 101 SWITCHING_PROTOCOLS\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
            .await
            .unwrap();

        buf.clear();
        server.read_buf(&mut buf).await.unwrap();
        assert_eq!(buf, b"\x01\x02\x03\xff");
        println!("s recv");

        server.write_all(b"\xff\xfe\x00").await.unwrap();
        println!("s sent");
    });

    let req = b"\0\0A\x01\x04\0\0\0\x01B\x87\xbd\xabN\x9c\x17\xb7\xffD\x82`\x7fA\x8c\x9d)\xacK\xccz\x07T\xcb\x9e\xc9\xbf\x87@\x87\xb9]\x87I\xc8z?\x87\xf0X\xd0ru*\x7f@\x8fAH\xb7\x82\xc6\x83\x93\xa9R\xb7r\xd8\x83\x1e\xaf\x82\x0b?";
    /*headers = [
        (':method', 'CONNECT'),
        (':path', '/a'),
        (':authority', SERVER_NAME),
        (':scheme', 'https'),
        (':protocol','websocket'),
        ('sec-websocket-version','13')
    ]*/

    let (end_stream, header) = crate::tests::h2_client(
        &mut client,
        req,
        Some(b"\0\x08\0\0\0\x01"), //SETTINGS_ENABLE_CONNECT_PROTOCOL (8) = 1
    )
    .await
    .unwrap();
    assert!(!end_stream);
    assert_eq!(header[0], 0x88);
    //DATA
    //WebSocket Data
    //                                        DATA + END_STREAM
    //                                        WebSocket Data
    //DATA + END_STREAM
    //WebSocket Data

    /*H2
        Len
        Typ
        Flags
        Id
    WebSocket (but just a dummy here)
    */
    client
        .write_all(b"\0\0\x04\0\0\0\0\0\x01\x01\x02\x03\xff")
        .await
        .unwrap();
    println!("c sent");

    let mut buf = [0u8; 30];
    client
        .read_exact(&mut buf[..3 + 5 + 4 + 5 + 4])
        .await
        .unwrap();
    println!("c recv");

    t.await.unwrap();
    println!("s");
    /*
    Last Msg + Close
     */
    assert_eq!(
        &buf[..3 + 5 + 4 + 5 + 4],
        b"\0\0\x03\0\0\0\0\0\x01\xff\xfe\x00\0\0\0\0\x01\0\0\0\x01"
    );
}

#[tokio::test]
async fn upgrade_h2() {
    let (mut client, target_listener) = full_tls_server_test(
        |p| {
            p.force_dir = false;
            p.forward = "h2://ignored/base_path".to_string().try_into().unwrap();
        },
        Some(b"h2"),
    )
    .await
    .unwrap();

    let _t = tokio::spawn(async move {
        let (s, _) = target_listener.accept().await.unwrap();
        hyper::server::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new())
            .enable_connect_protocol()
            .serve_connection(
                hyper_util::rt::TokioIo::new(s),
                hyper::service::service_fn(|req| async move {
                    assert_eq!(req.uri(), "http://ignored/base_path/");
                    assert_eq!(req.method(), hyper::Method::CONNECT);
                    assert_eq!(
                        req.extensions().get::<hyper::ext::Protocol>().unwrap(),
                        &hyper::ext::Protocol::from_static("websocket")
                    );
                    assert_eq!(
                        req.headers()
                            .get(hyper::header::SEC_WEBSOCKET_VERSION)
                            .unwrap(),
                        "13"
                    );
                    tokio::task::spawn(async move {
                        match hyper::upgrade::on(req).await {
                            Ok(upgraded) => {
                                let mut upgraded = hyper_util::rt::TokioIo::new(upgraded);
                                let mut buf = Vec::with_capacity(4096);
                                upgraded.read_buf(&mut buf).await.unwrap();
                                assert_eq!(buf, b"\x01\x02\x03\xff");

                                upgraded.write_all(b"\xff\xfe\x00").await.unwrap();
                            }
                            Err(e) => println!("upgrade error: {}", e),
                        }
                    });
                    hyper::Response::builder().body(TestBody::empty())
                }),
            )
            .await
    });

    let req = b"\0\0A\x01\x04\0\0\0\x01B\x87\xbd\xabN\x9c\x17\xb7\xffD\x82`\x7fA\x8c\x9d)\xacK\xccz\x07T\xcb\x9e\xc9\xbf\x87@\x87\xb9]\x87I\xc8z?\x87\xf0X\xd0ru*\x7f@\x8fAH\xb7\x82\xc6\x83\x93\xa9R\xb7r\xd8\x83\x1e\xaf\x82\x0b?";
    /*headers = [
        (':method', 'CONNECT'),
        (':path', '/a'),
        (':authority', SERVER_NAME),
        (':scheme', 'https'),
        (':protocol','websocket'),
        ('sec-websocket-version','13')
    ]*/

    let (end_stream, header) = crate::tests::h2_client(
        &mut client,
        req,
        Some(b"\0\x08\0\0\0\x01"), //SETTINGS_ENABLE_CONNECT_PROTOCOL (8) = 1
    )
    .await
    .unwrap();
    assert!(!end_stream);
    assert_eq!(header[0], 0x88);
    //DATA
    //WebSocket Data
    //                                        DATA + END_STREAM
    //                                        WebSocket Data
    //DATA + END_STREAM
    //WebSocket Data

    /*H2
        Len
        Typ
        Flags
        Id
    WebSocket*/
    client
        .write_all(b"\0\0\x04\0\0\0\0\0\x01\x01\x02\x03\xff")
        .await
        .unwrap();

    let mut buf = [0u8; 30];
    client
        .read_exact(&mut buf[..3 + 5 + 4 + 5 + 4])
        .await
        .unwrap();

    //t.await.unwrap().unwrap();
    /*
    Opcode Binary + Opcode Close
     */
    assert_eq!(
        &buf[..3 + 5 + 4 + 5 + 4],
        b"\0\0\x03\0\0\0\0\0\x01\xff\xfe\x00\0\0\0\0\x01\0\0\0\x01"
    );
    println!("all done");
}

#[tokio::test]
async fn filter_method() {
    let req = Request::get("/mount/some/path")
        .header(header::CONNECTION, "Upgrade")
        .header(header::UPGRADE, "websocket")
        .version(Version::HTTP_11)
        .body(TestBody::empty())
        .unwrap();
    let (mut s, t) = test_forward(
        req,
        create_conf(|p| {
            p.forward = "http://ignored/base_path".to_string().try_into().unwrap();
            p.allowed_methods = Some(vec!["put".to_string()]);
        }),
    )
    .await;

    let mut buf = [0u8; 25];
    let i = s.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf[..i], b"GET /base_path/some/path ");

    s.write_all(b"HTTP/1.0 404 Not so OK\r\n\r\n")
        .await
        .unwrap();
    let r = t.await.unwrap();
    assert_eq!(r.status(), 404);

    let req = Request::get("/mount/some/path")
        .body(TestBody::empty())
        .unwrap();
    let (_s, t) = test_forward(
        req,
        create_conf(|p| {
            p.forward = "http://ignored/base_path".to_string().try_into().unwrap();
            p.allowed_methods = Some(vec!["put".to_string()]);
        }),
    )
    .await;

    let r = t.await.unwrap();
    assert_eq!(r.status(), 405);
}

#[tokio::test]
async fn dont_upgrade_h11() {
    let (mut client, target_listener) = full_server_test(
        |p| {
            p.force_dir = false;
            p.allowed_upgrades = Some(vec![]);
        },
        #[cfg(any(feature = "tlsrust", feature = "tlsnative"))]
        None,
    )
    .await
    .unwrap();

    let t = tokio::spawn(async move {
        let (mut server, _) = target_listener.accept().await.unwrap();
        let mut buf = Vec::with_capacity(4096);
        server.read_buf(&mut buf).await.unwrap();

        assert!(
            get_header(&buf, "connection").map_or(true, |h| !h.windows(7).any(|s| s == b"upgrade"))
        );
        assert_eq!(get_header(&buf, "upgrade"), None);
        server.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await.unwrap();
    });

    client
        .write_all(b"GET /a HTTP/1.1\r\nUpgrade: something\r\nConnection: Upgrade\r\n\r\n")
        .await
        .unwrap();

    let mut buf = Vec::with_capacity(4096);
    client.read_buf(&mut buf).await.unwrap();
    assert_eq!(&buf[..17], b"HTTP/1.1 200 OK\r\n"); //HTTP/1.1 502 Bad
    assert_eq!(get_header(&buf, "connection"), None);
    assert_eq!(get_header(&buf, "upgrade"), None);

    t.await.unwrap();
}
