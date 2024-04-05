use super::*;
use bytes::Bytes;
use hyper::{body::Body, header, Request, Version};
use std::future::Future;
use std::path::Path;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

use crate::body::{
    test::{to_bytes, TestBody},
    FRWSResp, FRWSResult,
};
use crate::config::{group_config, AbsPathBuf, StaticFiles, UseCase, Utf8PathBuf};

trait OldBodyApi: Body {
    fn data(&mut self) -> OldApiFut;
}
struct OldApiFut<'a>(&'a mut FRWSResp);
impl Future for OldApiFut<'_> {
    type Output = Option<Result<Bytes, std::io::Error>>;

    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        match Body::poll_frame(std::pin::pin!(self.0.body_mut()), cx) {
            std::task::Poll::Ready(Some(Ok(d))) => {
                std::task::Poll::Ready(Some(Ok(d.into_data().unwrap())))
            }
            std::task::Poll::Ready(Some(Err(e))) => std::task::Poll::Ready(Some(Err(e))),
            std::task::Poll::Ready(None) => std::task::Poll::Ready(None),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}
impl OldBodyApi for FRWSResp {
    fn data(&mut self) -> OldApiFut {
        OldApiFut(self)
    }
}

#[test]
fn parse_addr() {
    assert!(if let Ok(UseCase::FCGI(FcgiMnt {
        fcgi: FCGIApp {
            sock: Addr::Inet(a),
            ..
        },
        ..
    })) = toml::from_str(
        r#"
            fcgi.sock = "127.0.0.1:9000"
    "#,
    ) {
        a.port() == 9000 && a.is_ipv4() && a.ip().is_loopback()
    } else {
        false
    });
    assert!(if let Ok(UseCase::FCGI(FcgiMnt {
        fcgi: FCGIApp {
            sock: Addr::Inet(a),
            ..
        },
        ..
    })) = toml::from_str(
        r#"
            fcgi.sock = "localhost:9000"
    "#,
    ) {
        a.port() == 9000
    } else {
        false
    });
    assert!(if let Ok(UseCase::FCGI(FcgiMnt {
        fcgi: FCGIApp {
            sock: Addr::Inet(a),
            ..
        },
        ..
    })) = toml::from_str(
        r#"
            fcgi.sock = "[::1]:9000"
    "#,
    ) {
        a.port() == 9000 && a.is_ipv6() && a.ip().is_loopback()
    } else {
        false
    });
    #[cfg(unix)]
    assert!(if let Ok(UseCase::FCGI(FcgiMnt {
        fcgi: FCGIApp {
            sock: Addr::Unix(a),
            ..
        },
        ..
    })) = toml::from_str(
        r#"
            fcgi.sock = "/path"
    "#,
    ) {
        a == Path::new("/path")
    } else {
        false
    });
}
#[test]
fn basic_config() {
    if let Ok(UseCase::FCGI(f)) = toml::from_str(
        r#"
fcgi.sock = "127.0.0.1:9000"
dir = "."
    "#,
    ) {
        assert!(!f.fcgi.set_script_filename);
        assert!(!f.fcgi.set_request_uri);
        assert_eq!(f.fcgi.timeout, 20);
        assert!(f.static_files.is_some());
    } else {
        panic!("not fcgi");
    }
}
#[tokio::test]
async fn wrong_cfg() {
    //no static files
    let mut cfg: crate::config::Configuration = toml::from_str(
        r#"
[host]
ip = "0.0.0.0:1337"
[host.fcgi]
sock = "127.0.0.1:9000"
exec = ["php"]
"#,
    )
    .expect("parse err");
    assert!(group_config(&mut cfg).await.is_err());
    //no exec filter
    let mut cfg: crate::config::Configuration = toml::from_str(
        r#"
[host]
ip = "0.0.0.0:1337"
dir = "."
[host.fcgi]
sock = "127.0.0.1:9000"
"#,
    )
    .expect("parse err");
    assert!(group_config(&mut cfg).await.is_err());
}
#[test]
fn params_php_example() {
    let fcgi_cfg = FCGIApp {
        sock: Addr::Inet("127.0.0.1:1234".parse().unwrap()),
        exec: None,
        set_script_filename: true,
        set_request_uri: false,
        timeout: 0,
        params: None,
        bin: None,
        app: None,
        buffer_request: None,
        allow_multiline_header: false,
        multiple_header: None,
    };
    let mut req = Request::get("/mount/")
        .version(Version::HTTP_11)
        .body(TestBody::empty())
        .unwrap();
    //done in dispatch_to_vhost
    req.extensions_mut()
        .insert(hyper::http::uri::Authority::from_static("example.com"));

    let req = Req::test_on_mount(req);

    let params = create_params(
        &fcgi_cfg,
        &req,
        Some(Path::new("/opt/php/index.php")),
        None,
        "1.2.3.4:1337".parse().unwrap(),
    );

    assert_eq!(
        params.get(&Bytes::from(GATEWAY_INTERFACE)),
        Some(&CGI_VERS.into())
    );
    assert_eq!(
        params.get(&Bytes::from(SERVER_PROTOCOL)),
        Some(&"HTTP/1.1".into())
    );
    assert_eq!(
        params.get(&Bytes::from(SERVER_NAME)),
        Some(&"example.com".into())
    );
    assert_eq!(
        params.get(&Bytes::from(REMOTE_ADDR)),
        Some(&"1.2.3.4".into())
    );

    assert_eq!(
        params.get(&Bytes::from(SCRIPT_FILENAME)),
        Some(&"/opt/php/index.php".into())
    );
    assert_eq!(
        params.get(&Bytes::from(SCRIPT_NAME)),
        Some(&"/mount/index.php".into())
    );
}
#[test]
fn add_index_to_folder() {
    let fcgi_cfg = FCGIApp {
        sock: Addr::Inet("127.0.0.1:1234".parse().unwrap()),
        exec: None,
        set_script_filename: true,
        set_request_uri: false,
        timeout: 0,
        params: None,
        bin: None,
        app: None,
        buffer_request: None,
        allow_multiline_header: false,
        multiple_header: None,
    };
    let req = Request::get("/mount/php/")
        .version(Version::HTTP_11)
        .body(TestBody::empty())
        .unwrap();
    let req = Req::test_on_mount(req);

    let params = create_params(
        &fcgi_cfg,
        &req,
        Some(Path::new("/opt/php/index.php")),
        None,
        "1.2.3.4:1337".parse().unwrap(),
    );
    assert_eq!(
        params.get(&Bytes::from(SCRIPT_FILENAME)),
        Some(&"/opt/php/index.php".into())
    );
    assert_eq!(
        params.get(&Bytes::from(SCRIPT_NAME)),
        Some(&"/mount/php/index.php".into())
    );
}
#[test]
fn params_flup_example() {
    let fcgi_cfg = FCGIApp {
        sock: Addr::Inet("127.0.0.1:1234".parse().unwrap()),
        exec: None,
        set_script_filename: false,
        set_request_uri: true,
        timeout: 0,
        params: None,
        bin: None,
        app: None,
        buffer_request: None,
        allow_multiline_header: false,
        multiple_header: None,
    };
    let mut req = Request::get("/mount/status")
        .header(header::HOST, "localhost")
        .version(Version::HTTP_10)
        .body(TestBody::empty())
        .unwrap();
    //done in dispatch_to_vhost
    req.extensions_mut()
        .insert(hyper::http::uri::Authority::from_static("localhost"));
    let req = Req::test_on_mount(req);

    let params = create_params(
        &fcgi_cfg,
        &req,
        None,
        None,
        "[::1]:1337".parse().unwrap(),
    );

    assert_eq!(
        params.get(&Bytes::from(GATEWAY_INTERFACE)),
        Some(&CGI_VERS.into())
    );
    assert_eq!(
        params.get(&Bytes::from(SERVER_PROTOCOL)),
        Some(&"HTTP/1.0".into())
    );
    assert_eq!(
        params.get(&Bytes::from(SERVER_NAME)),
        Some(&"localhost".into())
    );
    assert_eq!(params.get(&Bytes::from(REMOTE_ADDR)), Some(&"::1".into()));

    assert_eq!(params.get(&Bytes::from(SCRIPT_FILENAME)), None);
    assert_eq!(
        params.get(&Bytes::from(SCRIPT_NAME)),
        Some(&"/mount".into())
    );
    assert_eq!(params.get(&Bytes::from(PATH_INFO)), Some(&"/status".into()));
    assert_eq!(
        params.get(&Bytes::from(REQUEST_URI)),
        Some(&"/mount/status".into())
    );
}

async fn handle_wwwroot(req: Request<TestBody>, mount: UseCase) -> FRWSResult {
    let wwwr = crate::config::WwwRoot {
        mount,
        header: None,
        auth: None,
    };
    let remote_addr = "127.0.0.1:8080".parse().unwrap();

    let req = Req::test_on_mount(req);

    crate::dispatch::handle_wwwroot(req, &wwwr, remote_addr).await
}
#[tokio::test]
async fn resolve_file() {
    let file_content = &b"test_fcgi_fallthroug"[..];
    let _tf = crate::dispatch::test::TempFile::create("test_fcgi_fallthroug", file_content);

    let sf = StaticFiles {
        dir: AbsPathBuf::temp_dir(),
        follow_symlinks: false,
        index: None,
        serve: None,
    };
    let mount = UseCase::FCGI(FcgiMnt {
        fcgi: FCGIApp {
            sock: Addr::Inet("127.0.0.1:1234".parse().unwrap()),
            exec: Some(vec![Utf8PathBuf::from("php")]),
            set_script_filename: false,
            set_request_uri: false,
            timeout: 0,
            params: None,
            bin: None,
            app: None,
            buffer_request: None,
            allow_multiline_header: false,
            multiple_header: None,
        },
        static_files: Some(sf),
    });

    let req = Request::get("/mount/test_fcgi_fallthroug")
        .body(TestBody::empty())
        .unwrap();
    let res = handle_wwwroot(req, mount).await;
    let res = res.unwrap();
    assert_eq!(res.status(), 200);
    let body = to_bytes(res.into_body()).await;
    assert_eq!(body, file_content);
}
#[tokio::test]
async fn dont_resolve_file() {
    let file_content = &b"test_fcgi_fallthroug"[..];
    let _tf = crate::dispatch::test::TempFile::create("dont_fallthroug.php", file_content);

    let sf = StaticFiles {
        dir: AbsPathBuf::temp_dir(),
        follow_symlinks: true, //less checks
        index: None,
        serve: None,
    };
    let mount = UseCase::FCGI(FcgiMnt {
        fcgi: FCGIApp {
            sock: Addr::Inet("127.0.0.1:1234".parse().unwrap()),
            exec: Some(vec![Utf8PathBuf::from("php")]),
            set_script_filename: false,
            set_request_uri: false,
            timeout: 0,
            params: None,
            bin: None,
            app: None,
            buffer_request: None,
            allow_multiline_header: false,
            multiple_header: None,
        },
        static_files: Some(sf),
    });

    let req = Request::get("/mount/dont_fallthroug.php%00.txt")
        .body(TestBody::empty())
        .unwrap();
    let res = handle_wwwroot(req, mount).await;
    let res = res.unwrap_err();
    assert_eq!(res.kind(), std::io::ErrorKind::InvalidInput);
}
/*#[tokio::test]
async fn body_no_len() {
    let mount = UseCase::FCGI(FcgiMnt {
        fcgi: FCGIApp {
            sock: test_sock_addr(),
            exec: None,
            set_script_filename: false,
            set_request_uri: false,
            timeout: 0,
            params: None,
            bin: None,
            app: None,
            buffer_request: None,
            allow_multiline_header: false,
            multiple_header: None,
        },
        static_files: None,
    });

    let req = Request::post("/mount/whatever")
        .body(TestBody::empty())
        .unwrap();
    let res = handle_wwwroot(req, mount, "whatever").await;
    let res = res.unwrap();
    assert_eq!(res.status(), 411);
}*/
#[tokio::test]
async fn simple_fcgi_post() {
    let fcgi_cfg = FCGIApp {
        sock: test_sock_addr(),
        exec: None,
        set_script_filename: true,
        set_request_uri: false,
        timeout: 100,
        params: None,
        bin: None,
        app: None,
        buffer_request: None,
        allow_multiline_header: false,
        multiple_header: None,
    };
    let req = Request::post("http://1/mount/Public/test.php")
        .header("Content-Length", "8")
        .header("Content-Type", "multipart/form-data")
        .body(TestBody::from("test=123"))
        .unwrap();

    let (mut app_socket, req_task) = test_from_wwwr(req, fcgi_cfg, None).await;

    let mut buf = BytesMut::with_capacity(4096);
    //actual request
    app_socket.read_buf(&mut buf).await.unwrap();

    assert_eq!(
        get_param(&buf, b"SCRIPT_FILENAME"),
        Some(&b"/Public/test.php"[..])
    );
    assert_eq!(get_param(&buf, b"QUERY_STRING"), Some(&b""[..]));
    assert_eq!(get_param(&buf, b"CONTENT_LENGTH"), Some(&b"8"[..]));

    fn find_subsequence(haystack: &[u8], needle: &[u8]) -> bool {
        haystack
            .windows(needle.len())
            .any(|window| window == needle)
    }
    assert!(find_subsequence(&buf, b"\x01\x05\0\x01\0\x08\0\0test=123"));

    let from_php = b"\x01\x06\0\x01\x00\x23\x05\0Status: 201 Created\r\n\r\n<html><body>#+#+#\x01\x03\0\x01\0\x08\0\0\0\0\0\0\0\0\0\0";
    app_socket
        .write_buf(&mut Bytes::from(&from_php[..]))
        .await
        .unwrap();

    let mut res = req_task.await.unwrap();

    assert_eq!(res.status(), hyper::StatusCode::CREATED);
    let read1 = res.data().await;
    assert!(read1.is_some());
    let read1 = read1.unwrap();
    assert!(read1.is_ok());
    if let Ok(d) = read1 {
        let body = b"<html><body>";
        assert_eq!(d, &body[..]);
    }
    let read2 = res.data().await;
    assert!(read2.is_none());
}
/// send a request to a FCGI mount and return its TcpStream
/// (as well as the Task doing the request)
async fn test_from_wwwr(
    req: Request<TestBody>,
    mut fcgi: FCGIApp,
    static_files: Option<StaticFiles>,
) -> (TcpStream, tokio::task::JoinHandle<FRWSResp>) {
    // pick a free port
    let (app_listener, a) = crate::tests::local_socket_pair().await.unwrap();
    let m = tokio::spawn(async move {
        let sock = Addr::Inet(a);

        fcgi.app = Some(FCGIAppPool::new(&sock).await.expect("ConPool failed"));
        let mount = UseCase::FCGI(FcgiMnt { fcgi, static_files });
        let res = handle_wwwroot(req, mount).await;
        res.unwrap()
    });

    let (mut app_socket, _) = app_listener.accept().await.unwrap();

    let mut buf = BytesMut::with_capacity(4096);
    //FCGI startup
    app_socket.read_buf(&mut buf).await.unwrap();
    let from_php = b"\x01\x0a\0\0\0!\x07\0\n\0MPXS_CONNS\x08\0MAX_REQS\t\0MAX_CONNS\0\0\0\0\0\0\0";
    app_socket
        .write_buf(&mut Bytes::from(&from_php[..]))
        .await
        .unwrap();

    let (app_socket, _) = app_listener.accept().await.unwrap();
    (app_socket, m)
}
fn test_sock_addr() -> Addr {
    Addr::Inet(SocketAddr::new(
        std::net::IpAddr::from([1u8, 2u8, 2u8, 4u8]),
        0,
    ))
}
/// search a FCGI param value inside of a byte stream.  
/// __only__ works for small (<=255) names and values
fn get_param<'a>(haystack: &'a [u8], param: &'_ [u8]) -> Option<&'a [u8]> {
    if let Some(pos) = haystack
        .windows(param.len())
        .position(|window| window == param)
    {
        if haystack
            .get(pos.saturating_sub(2))
            .is_some_and(|&p| p as usize == param.len())
        {
            if let Some(&len) = haystack.get(pos.saturating_sub(1)) {
                return Some(&haystack[pos + param.len()..pos + param.len() + (len as usize)]);
            }
        }
    }
    None
}
/**
 * Request /mount/test.php/path_info
 *          ^^^^^ ^^^^^^^^ ^^^^^^^^^ - path below file, does not exist
 *            |       \ -------------- file to be executed (exists on disk)
 *            \ ---------------------- web root
 */
#[tokio::test]
async fn resolve_file_with_path_info() {
    let req = Request::get("/mount/test.php/path_info")
        .body(TestBody::empty())
        .unwrap();

    let sf = StaticFiles {
        dir: AbsPathBuf::temp_dir(),
        follow_symlinks: false,
        index: None,
        serve: None,
    };
    let fcgi = FCGIApp {
        sock: test_sock_addr(),
        exec: Some(vec![Utf8PathBuf::from("php")]),
        set_script_filename: true,
        set_request_uri: false,
        timeout: 0,
        params: None,
        bin: None,
        app: None,
        buffer_request: None,
        allow_multiline_header: false,
        multiple_header: None,
    };

    let file_content = &b""[..]; // not executed anyway -> runs mock_app instead
    let tf = crate::dispatch::test::TempFile::create("test.php", file_content);

    let (mut app_socket, t) = test_from_wwwr(req, fcgi, Some(sf)).await;

    let mut buf = BytesMut::with_capacity(4096);

    //actual request
    app_socket.read_buf(&mut buf).await.unwrap();

    let from_php = b"\x01\x06\0\x01\x00\x23\x05\0Status: 201 Created\r\n\r\n<html><body>#+#+#\x01\x03\0\x01\0\x08\0\0\0\0\0\0\0\0\0\0";
    app_socket
        .write_buf(&mut Bytes::from(&from_php[..]))
        .await
        .unwrap();

    let res = t.await.unwrap();
    assert_eq!(res.status(), 201);
    assert_eq!(
        get_param(&buf, SCRIPT_FILENAME),
        Some(
            tf.get_path()
                .canonicalize()
                .unwrap()
                .to_str()
                .unwrap()
                .as_bytes()
        )
    );
    assert_eq!(
        get_param(&buf, SCRIPT_NAME).and_then(|b| std::str::from_utf8(b).ok()),
        Some("/mount/test.php")
    );
    assert_eq!(
        get_param(&buf, PATH_INFO).and_then(|b| std::str::from_utf8(b).ok()),
        Some("/path_info")
    );
}
#[tokio::test]
async fn resolve_index() {
    let req = Request::get("/mount/").body(TestBody::empty()).unwrap();

    let sf = StaticFiles {
        dir: AbsPathBuf::temp_dir(),
        follow_symlinks: true,
        index: Some(vec![Utf8PathBuf::from("index.php")]),
        serve: None,
    };
    let fcgi = FCGIApp {
        sock: test_sock_addr(),
        exec: Some(vec![Utf8PathBuf::from("php")]),
        set_script_filename: true,
        set_request_uri: false,
        timeout: 0,
        params: None,
        bin: None,
        app: None,
        buffer_request: None,
        allow_multiline_header: false,
        multiple_header: None,
    };

    let file_content = &b""[..]; // not executed anyway -> runs mock_app instead
    let tf = crate::dispatch::test::TempFile::create("index.php", file_content);

    let (mut app_socket, t) = test_from_wwwr(req, fcgi, Some(sf)).await;

    let mut buf = BytesMut::with_capacity(4096);

    //actual request
    app_socket.read_buf(&mut buf).await.unwrap();

    assert_eq!(
        get_param(&buf, SCRIPT_NAME),
        Some("/mount/index.php".as_bytes())
    );
    assert_eq!(
        get_param(&buf, SCRIPT_FILENAME),
        Some(
            tf.get_path()
                .canonicalize()
                .unwrap()
                .to_str()
                .unwrap()
                .as_bytes()
        )
    );
    assert_eq!(get_param(&buf, b"QUERY_STRING"), Some(&b""[..]));

    let from_php = b"\x01\x06\0\x01\x00\x23\x05\0Status: 201 Created\r\n\r\n<html><body>#+#+#\x01\x03\0\x01\0\x08\0\0\0\0\0\0\0\0\0\0";
    app_socket
        .write_buf(&mut Bytes::from(&from_php[..]))
        .await
        .unwrap();

    let res = t.await.unwrap();
    assert_eq!(res.status(), 201);
}
#[tokio::test]
async fn file_request_dont_add_index() {
    let req = Request::get("/mount/something.php")
        .body(TestBody::empty())
        .unwrap();

    let sf = StaticFiles {
        dir: AbsPathBuf::temp_dir(),
        follow_symlinks: true,
        index: Some(vec![Utf8PathBuf::from("noindex.php")]),
        serve: None,
    };
    let fcgi = FCGIApp {
        sock: test_sock_addr(),
        exec: Some(vec![Utf8PathBuf::from("php")]),
        set_script_filename: true,
        set_request_uri: false,
        timeout: 0,
        params: None,
        bin: None,
        app: None,
        buffer_request: None,
        allow_multiline_header: false,
        multiple_header: None,
    };

    let file_content = &b""[..]; // not executed anyway -> runs mock_app instead
    let _tf = crate::dispatch::test::TempFile::create("noindex.php", file_content);
    let picked_file = crate::dispatch::test::TempFile::create("something.php", file_content);

    let (mut app_socket, t) = test_from_wwwr(req, fcgi, Some(sf)).await;

    let mut buf = BytesMut::with_capacity(4096);

    //actual request
    app_socket.read_buf(&mut buf).await.unwrap();

    let from_php = b"\x01\x06\0\x01\x00\x23\x05\0Status: 201 Created\r\n\r\n<html><body>#+#+#\x01\x03\0\x01\0\x08\0\0\0\0\0\0\0\0\0\0";
    app_socket
        .write_buf(&mut Bytes::from(&from_php[..]))
        .await
        .unwrap();

    let res = t.await.unwrap();
    assert_eq!(res.status(), 201);
    assert_eq!(
        get_param(&buf, SCRIPT_NAME),
        Some("/mount/something.php".as_bytes())
    );
    assert_eq!(
        get_param(&buf, SCRIPT_FILENAME),
        Some(
            picked_file
                .get_path()
                .canonicalize()
                .unwrap()
                .to_str()
                .unwrap()
                .as_bytes()
        )
    );
}

#[tokio::test]
///negative test for resolve_file_with_path_info
async fn test_resolve_path() {
    let full_path = std::env::temp_dir().join("a/b/c/d");
    let sf = StaticFiles {
        dir: AbsPathBuf::temp_dir(),
        follow_symlinks: false,
        index: None,
        serve: None,
    };

    let req = Req::test_on_mount(
        Request::get("/mount/a/b/c/d")
            .body(TestBody::empty())
            .unwrap(),
    );

    assert_eq!(req.path(), "a/b/c/d");

    let e = resolve_path(full_path, false, &sf, &req).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::NotFound);
}
#[test]
/// https://www.nginx.com/resources/wiki/start/topics/examples/phpfcgi/
fn params_nginx_example() {
    let fcgi_cfg = FCGIApp {
        sock: Addr::Inet("127.0.0.1:1234".parse().unwrap()),
        exec: None,
        set_script_filename: true,
        set_request_uri: true,
        timeout: 0,
        params: None,
        bin: None,
        app: None,
        buffer_request: None,
        allow_multiline_header: false,
        multiple_header: None,
    };
    let req = Request::get("/mount/test.php/foo/bar.php?v=1")
        .version(Version::HTTP_11)
        .body(TestBody::empty())
        .unwrap();

    let req = Req::test_on_mount(req);

    let params = create_params(
        &fcgi_cfg,
        &req,
        Some(Path::new("/var/www/test.php")),
        Some(10),
        "1.2.3.4:1337".parse().unwrap(),
    );

    assert_eq!(
        params.get(&Bytes::from(SCRIPT_FILENAME)),
        Some(&"/var/www/test.php".into())
    );
    assert_eq!(
        params.get(&Bytes::from(SCRIPT_NAME)),
        Some(&"/mount/test.php".into())
    );
    assert_eq!(
        params.get(&Bytes::from(REQUEST_URI)),
        Some(&"/mount/test.php/foo/bar.php?v=1".into())
    );
    assert_eq!(
        params.get(&Bytes::from(PATH_INFO)),
        Some(&"/foo/bar.php".into())
    );
/*
  'DOCUMENT_URI' => '/test.php/foo/bar.php',
*/
}
