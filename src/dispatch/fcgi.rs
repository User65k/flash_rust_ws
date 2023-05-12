use bytes::{Bytes, BytesMut};
use hyper::{body::HttpBody, Body, Request, Response};
use log::{debug, error, info, trace};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;
use std::{
    io::{Error as IoError, ErrorKind},
    net::SocketAddr,
};
use tokio::task::yield_now;
use tokio::time::timeout;

use crate::{
    body::FCGIBody,
    config::{StaticFiles, Utf8PathBuf},
};

pub use async_fcgi::client::con_pool::ConPool as FCGIAppPool;
pub use async_stream_connection::Addr;

const SCRIPT_NAME: &[u8] = b"SCRIPT_NAME";
const PATH_INFO: &[u8] = b"PATH_INFO";
const SERVER_NAME: &[u8] = b"SERVER_NAME";
const SERVER_PORT: &[u8] = b"SERVER_PORT";
const SERVER_PROTOCOL: &[u8] = b"SERVER_PROTOCOL";
const REMOTE_ADDR: &[u8] = b"REMOTE_ADDR";
const GATEWAY_INTERFACE: &[u8] = b"GATEWAY_INTERFACE";
const CGI_VERS: &[u8] = b"CGI/1.1";
const SERVER_SOFTWARE: &[u8] = b"SERVER_SOFTWARE";
const REQUEST_URI: &[u8] = b"REQUEST_URI";
const SCRIPT_FILENAME: &[u8] = b"SCRIPT_FILENAME";

pub async fn fcgi_call(
    fcgi_cfg: &FCGIApp,
    req: Request<Body>,
    req_path: &super::WebPath<'_>,
    web_mount: &Utf8PathBuf,
    fs_full_path: Option<&Path>,
    remote_addr: SocketAddr,
) -> Result<Response<Body>, IoError> {
    let app = if let Some(app) = &fcgi_cfg.app {
        app
    } else {
        error!("FCGI app not set");
        return Err(IoError::new(
            ErrorKind::NotConnected,
            "FCGI app not available",
        ));
    };

    match *req.method() {
        hyper::http::Method::GET
        | hyper::http::Method::HEAD
        | hyper::http::Method::OPTIONS
        | hyper::http::Method::DELETE
        | hyper::http::Method::TRACE => {}
        _ => {
            if req.body().size_hint().exact().is_none() {
                return Ok(Response::builder()
                    .status(hyper::StatusCode::LENGTH_REQUIRED)
                    .body(Body::empty())
                    .expect("unable to build response"));
            }
        }
    }
    let params = create_params(
        fcgi_cfg,
        &req,
        req_path,
        web_mount,
        fs_full_path,
        remote_addr,
    );

    trace!("to FCGI: {:?}", &params);
    let resp = match fcgi_cfg.timeout {
        0 => app.forward(req, params).await,
        secs => match timeout(Duration::from_secs(secs), app.forward(req, params)).await {
            Err(_) => {
                return Err(IoError::new(
                    ErrorKind::TimedOut,
                    "FCGI app did not respond",
                ))
            }
            Ok(resp) => resp,
        },
    }?;
    debug!("FCGI response: {:?} {:?}", resp.status(), resp.headers());
    //return types:
    //doc: MUST return a Content-Type header
    //TODO fetch local resource: Location header, MUST NOT return any other header fields or a message-body
    //TODO 302Found: Abs Location header, MUST NOT return any other header fields

    Ok(resp.map(|bod| Body::wrap_stream(FCGIBody::from(bod))))
}

fn create_params(
    fcgi_cfg: &FCGIApp,
    req: &Request<Body>,
    req_path: &super::WebPath,
    web_mount: &Utf8PathBuf,
    fs_full_path: Option<&Path>,
    remote_addr: SocketAddr,
) -> HashMap<Bytes, Bytes> {
    let mut params = HashMap::new();
    if let Some(full_path) = fs_full_path {
        //full_path is completely resolved (to get index files)

        //add index file if needed
        let index_file_name = full_path.file_name().and_then(|o| o.to_str());
        let post = index_file_name.map_or(0, |v| v.len());

        let mut abs_name = req_path.prefixed_as_abs_url_path(web_mount, post);

        if let Some(f) = index_file_name {
            if !abs_name.ends_with(f) {
                abs_name.push_str(f);
            }
        }

        params.insert(
            // must CGI/1.1  4.1.13, everybody cares
            Bytes::from(SCRIPT_NAME),
            Bytes::from(abs_name),
        );

        // - PATH_INFO derived from the portion of the URI path hierarchy following the part that identifies the script itself.
        // -> not a thing, as we check if the file exists
    } else {
        //no local FS
        //the wohle mount is a single FCGI App...

        //let mut abs_web_mount = PathBuf::from("/");
        //abs_web_mount.push(web_mount);
        let mut abs_web_mount = String::with_capacity(web_mount.as_str().len() + 1);
        abs_web_mount.push('/');
        abs_web_mount.push_str(web_mount.as_str());

        params.insert(
            // must CGI/1.1  4.1.13, everybody cares
            Bytes::from(SCRIPT_NAME),
            //path_to_bytes(abs_web_mount),
            Bytes::from(abs_web_mount),
        );
        //... so everything inside it is PATH_INFO
        let abs_path = req_path.prefixed_as_abs_url_path(&Utf8PathBuf::from(""), 0);
        params.insert(
            // opt CGI/1.1   4.1.5
            Bytes::from(PATH_INFO),
            Bytes::from(abs_path),
        );
        //this matches what lighttpd does without check_local
    }

    params.insert(
        // must CGI/1.1  4.1.14, flup cares for this
        Bytes::from(SERVER_NAME),
        Bytes::from(super::get_host(req).unwrap_or_default().to_string()),
    );
    params.insert(
        // must CGI/1.1  4.1.15, flup cares for this
        Bytes::from(SERVER_PORT),
        Bytes::from(
            req.uri()
                .port()
                .map(|p| p.to_string())
                .unwrap_or_else(|| "80".to_string()),
        ),
    );
    params.insert(
        // must CGI/1.1  4.1.16, flup cares for this
        Bytes::from(SERVER_PROTOCOL),
        Bytes::from(format!("{:?}", req.version())),
    );
    params.insert(
        // must CGI/1.1  4.1.8
        Bytes::from(REMOTE_ADDR),
        Bytes::from(remote_addr.ip().to_string()),
    );
    params.insert(
        // must CGI/1.1  4.1.4
        Bytes::from(GATEWAY_INTERFACE),
        Bytes::from(CGI_VERS),
    );
    params.insert(
        // must CGI/1.1  4.1.17
        Bytes::from(SERVER_SOFTWARE),
        Bytes::from(&b"frws"[..]),
    );
    if fcgi_cfg.set_request_uri {
        params.insert(
            // REQUEST_URI common
            Bytes::from(REQUEST_URI),
            Bytes::from(req.uri().path().to_string()),
        );
    }
    if fcgi_cfg.set_script_filename {
        params.insert(
            // PHP cares for this
            Bytes::from(SCRIPT_FILENAME),
            if let Some(full_path) = fs_full_path {
                path_to_bytes(full_path)
            } else {
                // I am guessing here
                Bytes::from(req_path.prefixed_as_abs_url_path(&Utf8PathBuf::from(""), 0))
            },
        );
    }
    if let Some(kvp) = &fcgi_cfg.params {
        params.extend(
            kvp.iter()
                .map(|(k, v)| (Bytes::from(k.to_string()), Bytes::from(v.to_string()))),
        );
    }
    params
}

#[cfg(unix)]
fn path_to_bytes<P: AsRef<Path>>(path: P) -> Bytes {
    use std::os::unix::ffi::OsStrExt;
    BytesMut::from(path.as_ref().as_os_str().as_bytes()).freeze()
}

#[cfg(not(unix))]
fn path_to_bytes<P: AsRef<Path>>(path: P) -> Bytes {
    // On Windows, could use std::os::windows::ffi::OsStrExt to encode_wide(),
    // but end up with u16
    BytesMut::from(path.as_ref().to_string_lossy().to_string().as_bytes()).freeze()
}

pub async fn setup_fcgi_connection(
    fcgi_cfg: &mut FCGIApp,
) -> Result<(), Box<dyn std::error::Error>> {
    let sock = &fcgi_cfg.sock;

    if let Some(bin) = fcgi_cfg.bin.as_ref() {
        let mut cmd = FCGIAppPool::prep_server(bin.path.as_os_str(), &sock).await?;
        cmd.env_clear();
        if let Some(dir) = bin.wdir.as_ref() {
            cmd.current_dir(dir);
        }
        //gid ?
        //uid ?
        if let Some(env_map) = bin.environment.as_ref() {
            cmd.envs(env_map);
        }
        if let Some(env_copy) = bin.copy_environment.as_ref() {
            cmd.envs(
                env_copy
                    .iter()
                    .filter_map(|key| std::env::var_os(key).map(|val| (key, val))),
            );
        }
        let mut running_cmd = cmd.kill_on_drop(true).spawn()?;
        info!("Started {:?} @ {}", &bin.path, &sock);
        #[cfg(unix)]
        let delete_after_use = if let Addr::Unix(a) = &sock {
            Some(a.to_path_buf())
        } else {
            None
        };
        tokio::spawn(async move {
            tokio::select! {
                ret = running_cmd.wait() => {
                    match ret {
                        Ok(status) => error!("FCGI app exit: {}", status),
                        Err(e) => error!("FCGI app: {}", e),
                    }
                },
                _ = tokio::signal::ctrl_c() => {info!("killing");running_cmd.kill().await.expect("kill failed");}
            }
            #[cfg(unix)]
            if let Some(path) = delete_after_use {
                info!("cleanup");
                std::fs::remove_file(path).unwrap();
            }
        });
        yield_now().await;
    }
    let app = match timeout(Duration::from_secs(3), FCGIAppPool::new(&sock)).await {
        Err(_) => {
            return Err(Box::new(IoError::new(
                ErrorKind::TimedOut,
                "timeout during connect",
            )))
        }
        Ok(res) => res?,
    };

    info!("FCGI App ready @ {}", &sock);
    fcgi_cfg.app = Some(app);

    Ok(())
}

/// Information to execute a FCGI App
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FCGIAppExec {
    pub path: Utf8PathBuf,
    pub wdir: Option<Utf8PathBuf>,
    pub environment: Option<HashMap<String, String>>,
    pub copy_environment: Option<Vec<String>>,
}

/// A FCGI Application
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FCGIApp {
    pub sock: Addr,
    pub exec: Option<Vec<Utf8PathBuf>>,
    #[serde(default)]
    pub set_script_filename: bool,
    #[serde(default)]
    pub set_request_uri: bool,
    #[serde(default = "default_timeout")]
    pub timeout: u64,
    pub params: Option<HashMap<String, String>>,
    pub bin: Option<FCGIAppExec>,
    #[serde(skip)]
    pub app: Option<FCGIAppPool>,
}
fn default_timeout() -> u64 {
    20
}

#[cfg(feature = "fcgi")]
#[derive(Debug, Deserialize)]
pub struct FcgiMnt {
    pub fcgi: FCGIApp,
    #[serde(flatten)]
    pub static_files: Option<StaticFiles>,
}
impl FcgiMnt {
    pub async fn setup(&mut self) -> Result<(), String> {
        if self.fcgi.exec.is_some() && self.static_files.is_none() {
            //need a dir to check files
            return Err("dir must be specified, if exec filter is used".to_string());
        }
        if self.fcgi.exec.is_none() && self.static_files.is_some() {
            //warn that dir will not be used
            return Err(
                "reqests will always go to FCGI app. File checks will not be used - remove them"
                    .to_string(),
            );
        }
        if let Some(sf) = &self.static_files {
            let _ = sf.setup().await?;
        }
        if let Err(e) = setup_fcgi_connection(&mut self.fcgi).await {
            return Err(format!("{}", e));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use hyper::{header, Body, Request, Version};
    use std::path::Path;

    use crate::{
        config::{group_config, AbsPathBuf, UseCase, Utf8PathBuf},
        dispatch::WebPath,
    };
    #[test]
    fn parse_addr() {
        if let Ok(UseCase::FCGI(f)) = toml::from_str(
            r#"
                fcgi.sock = "127.0.0.1:9000"
        "#,
        ) {
            assert!(matches!(f.fcgi.sock, Addr::Inet(_)));
        }
        if let Ok(UseCase::FCGI(f)) = toml::from_str(
            r#"
                fcgi.sock = "localhost:9000"
        "#,
        ) {
            assert!(matches!(f.fcgi.sock, Addr::Inet(_)));
        }
        if let Ok(UseCase::FCGI(f)) = toml::from_str(
            r#"
                fcgi.sock = "[::1]:9000"
        "#,
        ) {
            assert!(matches!(f.fcgi.sock, Addr::Inet(_)));
        }
        #[cfg(unix)]
        if let Ok(UseCase::FCGI(f)) = toml::from_str(
            r#"
                fcgi.sock = "/path"
        "#,
        ) {
            assert!(matches!(f.fcgi.sock, Addr::Unix(_)));
        }
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
        };
        let req = Request::get("/php/")
            .header(header::HOST, "example.com")
            .version(Version::HTTP_11)
            .body(Body::empty())
            .unwrap();

        let params = create_params(
            &fcgi_cfg,
            &req,
            &WebPath::parsed(""),
            &Utf8PathBuf::from("php"),
            Some(&Path::new("/opt/php/index.php")),
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
            Some(&"/php/index.php".into())
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
        };
        let req = Request::get("/flup/status")
            .header(header::HOST, "localhost")
            .version(Version::HTTP_10)
            .body(Body::empty())
            .unwrap();

        let params = create_params(
            &fcgi_cfg,
            &req,
            &WebPath::parsed("status"),
            &Utf8PathBuf::from("flup"),
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
        assert_eq!(params.get(&Bytes::from(SCRIPT_NAME)), Some(&"/flup".into()));
        assert_eq!(params.get(&Bytes::from(PATH_INFO)), Some(&"/status".into()));
        assert_eq!(
            params.get(&Bytes::from(REQUEST_URI)),
            Some(&"/flup/status".into())
        );
    }

    async fn handle_wwwroot(
        req: Request<Body>,
        mount: UseCase,
        req_path: &str,
    ) -> Result<Response<Body>, std::io::Error> {
        let wwwr = crate::config::WwwRoot {
            mount,
            header: None,
            auth: None,
        };
        let remote_addr = "127.0.0.1:8080".parse().unwrap();

        crate::dispatch::handle_wwwroot(
            req,
            &wwwr,
            crate::dispatch::WebPath::parsed(req_path),
            &Utf8PathBuf::from("mount"),
            remote_addr,
        )
        .await
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
            },
            static_files: Some(sf),
        });

        let req = Request::get("/mount/test_fcgi_fallthroug")
            .body(Body::empty())
            .unwrap();
        let res = handle_wwwroot(req, mount, "test_fcgi_fallthroug").await;
        let res = res.unwrap();
        assert_eq!(res.status(), 200);
        let body = hyper::body::to_bytes(res.into_body()).await.unwrap();
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
            },
            static_files: Some(sf),
        });

        let req = Request::get("/mount/dont_fallthroug.php%00.txt")
            .body(Body::empty())
            .unwrap();
        let res = handle_wwwroot(req, mount, "dont_fallthroug.php\0.txt").await;
        let res = res.unwrap_err();
        assert_eq!(res.kind(), std::io::ErrorKind::InvalidInput);
    }
    /*#[tokio::test]
    async fn body_no_len() {
        let mount = UseCase::FCGI(FcgiMnt {
            fcgi: FCGIApp {
                sock: Addr::Inet("127.0.0.1:1234".parse().unwrap()),
                exec: None,
                set_script_filename: false,
                set_request_uri: false,
                timeout: 0,
                params: None,
                bin: None,
                app: None,
            },
            static_files: None,
        });

        let req = Request::post("/mount/whatever")
            .body(Body::empty())
            .unwrap();
        let res = handle_wwwroot(req, mount, "whatever").await;
        let res = res.unwrap();
        assert_eq!(res.status(), 411);
    }*/
    #[tokio::test]
    async fn simple_fcgi_post() {
        use tokio::{
            io::{AsyncReadExt, AsyncWriteExt},
            net::TcpListener,
        };
        async fn mock_app(app_listener: TcpListener) {
            let (mut app_socket, _) = app_listener.accept().await.unwrap();
            let mut buf = BytesMut::with_capacity(4096);
            //FCGI startup
            app_socket.read_buf(&mut buf).await.unwrap();
            let from_php =
                b"\x01\x0a\0\0\0!\x07\0\n\0MPXS_CONNS\x08\0MAX_REQS\t\0MAX_CONNS\0\0\0\0\0\0\0";
            app_socket
                .write_buf(&mut Bytes::from(&from_php[..]))
                .await
                .unwrap();

            buf.clear();
            let (mut app_socket, _) = app_listener.accept().await.unwrap();
            //actual request
            app_socket.read_buf(&mut buf).await.unwrap();

            fn find_subsequence(haystack: &[u8], needle: &[u8]) -> bool {
                haystack.windows(needle.len()).any(|window| window == needle)
            }

            assert!(find_subsequence(&buf, b"\x0f\x1cSCRIPT_FILENAME/home/daniel/Public/test.php"));
            assert!(find_subsequence(&buf, b"\x0c\0QUERY_STRING"));
            assert!(find_subsequence(&buf, b"\x0e\x01CONTENT_LENGTH8"));
            assert!(find_subsequence(&buf, b"\x01\x05\0\x01\0\x08\0\0test=123"));

            let from_php = b"\x01\x06\0\x01\x00\x23\x05\0Status: 201 Created\r\n\r\n<html><body>#+#+#\x01\x03\0\x01\0\x08\0\0\0\0\0\0\0\0\0\0";
            app_socket
                .write_buf(&mut Bytes::from(&from_php[..]))
                .await
                .unwrap();
        }

        let (app_listener, a) = crate::tests::local_socket_pair().await.unwrap();
        let m = tokio::spawn(mock_app(app_listener));
        let sock = Addr::Inet(a);

        let fcgi_cfg = FCGIApp {
            sock: sock.clone(),
            exec: None,
            set_script_filename: true,
            set_request_uri: false,
            timeout: 100,
            params: None,
            bin: None,
            app: Some(FCGIAppPool::new(&sock).await.expect("ConPool failed")),
        };
        let req = Request::post("http://1/Public/test.php")
            .header("Content-Length", "8")
            .header("Content-Type", "multipart/form-data")
            .body(Body::from("test=123"))
            .unwrap();

        let mut res = fcgi_call(
            &fcgi_cfg,
            req,
            &super::super::WebPath::parsed("Public/test.php"),
            &Utf8PathBuf::from(""),
            Some(Path::new("/home/daniel/Public/test.php")),
            "127.0.0.1:1337".parse().unwrap(),
        )
        .await
        .expect("forward failed");

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
        m.await.unwrap();
    }
}
