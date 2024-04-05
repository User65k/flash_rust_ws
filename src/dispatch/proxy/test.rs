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

/// send a request to a FCGI mount and return its TcpStream
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
        Proxy {
            forward: "http://ignored/base_path".to_string().try_into().unwrap(),
            add_forwarded_header: ForwardedHeader::Remove,
            add_x_forwarded_for_header: false,
            add_via_header_to_client: Some("rproxy1".to_string()),
            add_via_header_to_server: None,
            force_dir: true,
            client: None,
        },
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
        Proxy {
            forward: "http://ignored/".to_string().try_into().unwrap(),
            add_forwarded_header: ForwardedHeader::Replace,
            add_x_forwarded_for_header: true,
            add_via_header_to_client: None,
            add_via_header_to_server: Some("rproxy1".to_string()),
            force_dir: true,
            client: None,
        },
    )
    .await;

    let mut buf = [0u8; 16];
    let i = s.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf[..i], b"GET / HTTP/1.0\r\n");
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
    let (mut s, t) = test_forward(
        req,
        Proxy {
            forward: "http://ignored/".to_string().try_into().unwrap(),
            add_forwarded_header: ForwardedHeader::Remove,
            add_x_forwarded_for_header: false,
            add_via_header_to_client: None,
            add_via_header_to_server: None,
            force_dir: true,
            client: None,
        },
    )
    .await;

    let mut buf = Vec::with_capacity(4096);
    s.read_buf(&mut buf).await.unwrap();

    let dont_include = [
        "keep-alive",
        "transfer-encoding",
        "te",
        "connection",
        "trailer",
        "proxy-authorization",
        "proxy-authenticate",
    ];
    for kw in dont_include {
        assert_eq!(get_header(&buf, kw), None);
    }

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

    let proxy = Proxy {
        forward: "http://localhost:0/".to_string().try_into().unwrap(),
        add_forwarded_header: ForwardedHeader::Remove,
        add_x_forwarded_for_header: false,
        add_via_header_to_client: None,
        add_via_header_to_server: None,
        force_dir: true,
        client: None,
    };

    let t = tokio::spawn(async move {
        let res = crate::dispatch::handle_wwwroot(
            req,
            &crate::config::WwwRoot {
                mount: crate::config::UseCase::Proxy(proxy),
                header: None,
                auth: None,
            },
            &Utf8PathBuf::from("/mount"),
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
        Proxy {
            forward: "http://ignored/".to_string().try_into().unwrap(),
            add_forwarded_header: ForwardedHeader::Remove,
            add_x_forwarded_for_header: false,
            add_via_header_to_client: None,
            add_via_header_to_server: None,
            force_dir: false,
            client: None,
        },
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
        Proxy {
            forward: "http://ignored/".to_string().try_into().unwrap(),
            add_forwarded_header: ForwardedHeader::Extend,
            add_x_forwarded_for_header: true,
            add_via_header_to_client: Some("my_front".to_string()),
            add_via_header_to_server: Some("me".to_string()),
            force_dir: true,
            client: None,
        },
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
) -> Result<(tokio::net::TcpStream, tokio::net::TcpListener), Box<dyn std::error::Error>> {
    //We can not use a Request Object for the test,
    //as it has no associated connection
    let (server_listener, a) = crate::tests::local_socket_pair().await?;
    let (target_listener, target_add) = crate::tests::local_socket_pair().await.unwrap();

    let mut proxy = Proxy {
        forward: "http://ignored/".to_string().try_into().unwrap(),
        add_forwarded_header: ForwardedHeader::Remove,
        add_x_forwarded_for_header: false,
        add_via_header_to_client: None,
        add_via_header_to_server: None,
        force_dir: false,
        client: None,
    };
    proxy.forward.addr = ProxySocket::Ip(target_add);
    proxy.setup().await.unwrap();

    let mut listening_ifs = std::collections::HashMap::new();
    let mut cfg = crate::config::HostCfg::new(server_listener.into_std()?);
    let mut vh = crate::config::VHost::new(a);
    vh.paths.insert(
        Utf8PathBuf::from("a"),
        crate::config::WwwRoot {
            mount: UseCase::Proxy(proxy),
            header: None,
            auth: None,
        },
    );
    cfg.default_host = Some(vh);
    listening_ifs.insert(a, cfg);

    let _s = crate::prepare_hyper_servers(listening_ifs).await?;

    let client = tokio::net::TcpStream::connect(a).await?;

    Ok((client, target_listener))
}
///test upgrade
#[tokio::test]
async fn upgrade() {
    let (mut client, target_listener) = full_server_test().await.unwrap();

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