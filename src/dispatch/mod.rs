#[cfg(feature = "webdav")]
pub mod dav;
#[cfg(feature = "fcgi")]
pub mod fcgi;
mod staticf;
#[cfg(feature = "websocket")]
pub mod websocket;

use crate::config;
use hyper::Uri;
use hyper::{header, http::Error as HTTPError, Body, Request, Response, StatusCode, Version}; //, Method};
use hyper_staticfile::{ResolveResult, ResponseBuilder as FileResponseBuilder};
use log::{debug, error, info, trace};
use std::borrow::{Borrow, Cow};
use std::collections::HashMap;
use std::error::Error;
use std::io::{Error as IoError, ErrorKind};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub fn insert_default_headers(
    header: &mut header::HeaderMap<header::HeaderValue>,
    config_header: &Option<HashMap<String, String>>,
) -> Result<(), Box<dyn Error>> {
    if let Some(config_header) = config_header {
        for (key, value) in config_header.iter() {
            let key = header::HeaderName::from_bytes(key.as_bytes())?;
            if !header.contains_key(&key) {
                header.insert(key, header::HeaderValue::from_str(value)?);
            }
        }
    }
    let default_headers = [
        //(header::X_FRAME_OPTIONS, "sameorigin"),
        (
            header::CONTENT_SECURITY_POLICY,
            "default-src 'self';frame-ancestors 'self'",
        ),
        (header::STRICT_TRANSPORT_SECURITY, "max-age=15768000"),
        (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
    ];
    for (key, value) in default_headers.iter() {
        if !header.contains_key(key) {
            header.insert(key, header::HeaderValue::from_static(value));
        }
    }
    Ok(())
}
fn ext_in_list(list: &Option<Vec<PathBuf>>, path: &Path) -> bool {
    if let Some(whitelist) = list {
        if let Some(ext) = path.extension() {
            for e in whitelist {
                if e == ext {
                    return true;
                }
            }
        }
        return false;
    }
    true // no list == all is ok
}

fn decode_and_normalize_path(uri: &Uri) -> Result<WebPath<'_>, IoError> {
    let path = percent_encoding::percent_decode_str(&uri.path()[1..]).decode_utf8_lossy();

    let mut parts = Vec::new();
    let mut len = 0;
    for p in path.split('/') {
        match p {
            "." | "" => {}
            ".." => {
                if parts.pop().is_none() {
                    return Err(IoError::new(ErrorKind::PermissionDenied, "path traversal"));
                }
            }
            comp => {
                parts.push(comp);
                len += 1 + comp.len();
            }
        }
    }
    if len == path.len() {
        Ok(WebPath(path))
    } else {
        let mut r = String::with_capacity(len);
        for p in parts {
            r.push_str(p);
            r.push('/');
        }
        r.pop();
        Ok(WebPath(Cow::from(r)))
    }
}

#[repr(transparent)]
#[derive(Debug)]
pub struct WebPath<'a>(Cow<'a, str>);
impl<'a> WebPath<'a> {
    /// turn it into a path by appending. Never replace the existing root!
    /// rustsec_2022_0072
    pub fn prefix_with(&self, pre: &Path) -> PathBuf {
        let r: &std::ffi::OsStr = pre.as_ref();
        let mut r = r.to_os_string();
        if let Some(false) = r.to_str().map(|s| s.ends_with(std::path::MAIN_SEPARATOR)) {
            r.push::<String>(std::path::MAIN_SEPARATOR.into());
        }
        //does never start with a separator
        r.push(self.0.as_ref());
        PathBuf::from(r)
    }
    pub fn strip_prefix(&'a self, base: &'_ Path) -> Result<WebPath<'a>, ()> {
        let mut strip = base.components();
        let mut path = self.0.split('/');
        let mut offset = 0;
        loop {
            match (strip.next(), path.next()) {
                (None, None) => {
                    offset -= 1;
                    break;
                } //no next dir -> no final separator
                (Some(c), p @ Some(s)) if c.as_os_str().to_str() == p => offset += 1 + s.len(),
                (None, Some(_)) => break,
                _ => return Err(()),
            }
        }
        Ok(WebPath(Cow::from(&self.0[offset..])))
    }
    pub fn prefixed_as_abs_url_path(&self, pre: &Path, extra_cap: usize) -> String {
        //https://docs.rs/hyper-staticfile/latest/src/hyper_staticfile/response_builder.rs.html#75-123
        if let Some(pre) = pre.to_str() {
            let s = self.0.as_ref();
            let capa = pre.len() + s.len() + extra_cap + 2;
            let mut r = String::with_capacity(capa);
            if !pre.is_empty() && !pre.starts_with('/') {
                r.push('/');
            }
            r.push_str(pre);
            if !pre.ends_with('/') {
                r.push('/');
            }
            r.push_str(s);
            return r;
        }
        String::new()
    }
    pub fn clone<'b>(&self) -> WebPath<'b> {
        // not as trait as we change lifetime
        let s: &str = self.0.borrow();
        WebPath(Cow::Owned(s.to_owned()))
    }
    #[cfg(test)]
    pub fn parsed(v: &'a str) -> WebPath<'a> {
        WebPath(Cow::from(v))
    }
}

/// handle a request by
/// - checking for authentication
/// - building the absolute file path
/// - forwarding to FCGI
/// - returning a static file
async fn handle_wwwroot(
    req: Request<Body>,
    wwwr: &config::WwwRoot,
    req_path: WebPath<'_>,
    web_mount: &Path,
    remote_addr: SocketAddr,
) -> Result<Response<Body>, IoError> {
    debug!("working root {:?}", wwwr);

    if let Some(auth_conf) = wwwr.auth.as_ref() {
        //Authorisation is needed
        if let Some(resp) = crate::auth::check_is_authorized(auth_conf, &req).await? {
            return Ok(resp);
        }
    }

    //hyper_reverse_proxy::call(remote_addr.ip(), "http://127.0.0.1:13901", req)

    let sf = match &wwwr.mount {
        config::UseCase::StaticFiles(sf) => sf,
        #[cfg(feature = "fcgi")]
        config::UseCase::FCGI(fcgi::FcgiMnt { fcgi, static_files }) => {
            if fcgi.exec.is_none() {
                //FCGI + dont check for file -> always FCGI
                return fcgi::fcgi_call(fcgi, req, &req_path, web_mount, None, remote_addr).await;
            }
            match static_files {
                Some(sf) => sf,
                None => return Err(IoError::new(ErrorKind::PermissionDenied, "no dir to serve")),
            }
        }
        #[cfg(feature = "websocket")]
        config::UseCase::Websocket(ws) => {
            return websocket::upgrade(req, ws, &req_path, remote_addr).await;
        }
        #[cfg(feature = "webdav")]
        config::UseCase::Webdav(dav) => {
            return dav::do_dav(req, &req_path, dav, web_mount, remote_addr).await;
        }
        #[cfg(test)]
        config::UseCase::UnitTest(ut) => {
            return ut.body(req_path, web_mount, remote_addr);
        }
    };

    let is_dir_request = req.uri().path().as_bytes().last() == Some(&b'/');
    let full_path = req_path.prefix_with(&sf.dir);
    trace!("full_path {:?}", full_path.canonicalize());

    let (full_path, resolved_file) =
        staticf::resolve_path(&full_path, is_dir_request, &sf.index, sf.follow_symlinks).await?;

    if let ResolveResult::IsDirectory = resolved_file {
        //request for a file that is a directory
        return Ok(FileResponseBuilder::new()
            .request(&req)
            .build(ResolveResult::IsDirectory)
            .expect("unable to build response"));
    }

    #[cfg(feature = "fcgi")]
    if let config::UseCase::FCGI(fcgi::FcgiMnt { fcgi, .. }) = &wwwr.mount {
        //FCGI + check for file
        if ext_in_list(&fcgi.exec, &full_path) {
            return fcgi::fcgi_call(
                fcgi,
                req,
                &req_path,
                web_mount,
                Some(&full_path),
                remote_addr,
            )
            .await;
        }
    }

    if ext_in_list(&sf.serve, &full_path) {
        staticf::return_file(&req, resolved_file).await
    } else {
        Err(IoError::new(
            ErrorKind::PermissionDenied,
            "bad file extension",
        ))
    }
}

/// new request on a particular vHost.
/// picks the matching WwwRoot and calls `handle_wwwroot`
/// Note: /a is not part of /aa (but of /a/a and /a)
async fn handle_vhost(
    req: Request<Body>,
    cfg: &config::VHost,
    remote_addr: SocketAddr,
) -> Result<Response<Body>, IoError> {
    let req_path = decode_and_normalize_path(req.uri())?;
    debug!("req_path {:?}", req_path);

    //we want the longest match
    //BTreeMap is sorted from small to big
    for (mount_path, wwwr) in cfg.paths.iter().rev() {
        trace!("checking mount point: {:?}", mount_path);
        if let Ok(full_path) = req_path.strip_prefix(mount_path) {
            let req_path = full_path.clone(); // T_T
            drop(full_path);
            let mut resp = handle_wwwroot(req, wwwr, req_path, mount_path, remote_addr).await?;
            insert_default_headers(resp.headers_mut(), &wwwr.header).unwrap(); //save bacause checked at server start
            return Ok(resp);
        }
    }

    Err(IoError::new(
        ErrorKind::PermissionDenied,
        "not a mount path",
    ))
}

#[cfg(test)]
#[derive(Debug, Default)]
pub struct UnitTestUseCase {
    req_path: Option<&'static str>,
    mount: Option<&'static Path>,
    remote_addr: Option<SocketAddr>,
}
#[cfg(test)]
impl UnitTestUseCase {
    pub fn create_wwwroot(
        req_path: Option<&'static str>,
        mount: Option<&'static Path>,
        remote_addr: Option<SocketAddr>,
    ) -> config::WwwRoot {
        let sf = UnitTestUseCase {
            req_path,
            mount,
            remote_addr,
        };
        config::WwwRoot {
            mount: config::UseCase::UnitTest(sf),
            header: None,
            auth: None,
        }
    }
    fn body(
        &self,
        req_path: WebPath<'_>,
        web_mount: &Path,
        remote_addr: SocketAddr,
    ) -> Result<Response<Body>, IoError> {
        if let Some(r) = self.req_path {
            assert_eq!(req_path.0, r);
        }
        if let Some(m) = self.mount {
            assert_eq!(web_mount, m);
        }
        if let Some(a) = self.remote_addr {
            assert_eq!(remote_addr, a);
        }
        Ok(Response::builder().body(Body::default()).unwrap())
    }
}
#[cfg(test)]
mod mount_tests {
    use super::*;
    fn create_wwwroot(dir: &str) -> config::WwwRoot {
        let sf = config::StaticFiles {
            dir: PathBuf::from(dir),
            follow_symlinks: false,
            index: None,
            serve: None,
        };
        config::WwwRoot {
            mount: config::UseCase::StaticFiles(sf),
            header: None,
            auth: None,
        }
    }
    #[tokio::test]
    async fn test_mount_params() {
        let req = Request::get("/abc/def/ghi").body(Body::empty()).unwrap();
        let sa = "127.0.0.1:8080".parse().unwrap();
        let m = UnitTestUseCase::create_wwwroot(Some("def/ghi"), Some(Path::new("abc")), None);

        let mut cfg = config::VHost::new(sa);
        cfg.paths.insert(PathBuf::from("abc"), m);
        let res = handle_vhost(req, &cfg, sa).await;
        assert!(res.is_ok());
    }
    #[tokio::test]
    async fn test_barely_mounted() {
        let req = Request::get("/abc").body(Body::empty()).unwrap();
        let sa = "127.0.0.1:8080".parse().unwrap();
        let m = UnitTestUseCase::create_wwwroot(Some(""), Some(Path::new("abc")), None);

        let mut cfg = config::VHost::new(sa);
        cfg.paths.insert(PathBuf::from("abc"), m);
        let res = handle_vhost(req, &cfg, sa).await;
        assert!(res.is_ok());
    }
    #[tokio::test]
    async fn top_mount() {
        let req = Request::get("/abc").body(Body::empty()).unwrap();
        let sa = "127.0.0.1:8080".parse().unwrap();
        let m = UnitTestUseCase::create_wwwroot(Some("abc"), Some(Path::new("")), None);

        let mut cfg = config::VHost::new(sa);
        cfg.paths.insert(PathBuf::from(""), m);
        let res = handle_vhost(req, &cfg, sa).await;
        assert!(res.is_ok());
    }
    #[tokio::test]
    async fn no_mounts() {
        let req = Request::new(Body::empty());
        let sa = "127.0.0.1:8080".parse().unwrap();

        let cfg = config::VHost::new(sa);
        let res = handle_vhost(req, &cfg, sa).await;
        let res: IoError = res.unwrap_err();
        assert_eq!(res.into_inner().unwrap().to_string(), "not a mount path");
    }
    #[tokio::test]
    async fn full_folder_names_as_mounts() {
        let req = Request::get("/aa").body(Body::empty()).unwrap();
        let sa = "127.0.0.1:8080".parse().unwrap();

        let mut cfg = config::VHost::new(sa);
        cfg.paths.insert(PathBuf::from(""), create_wwwroot("."));
        cfg.paths.insert(PathBuf::from("aa"), create_wwwroot("."));
        cfg.paths.insert(PathBuf::from("aaa"), create_wwwroot("."));
        let res = handle_vhost(req, &cfg, sa).await;
        let res = res.unwrap();
        assert_eq!(res.status(), 301);
        assert_eq!(res.headers().get("location").unwrap(), "/aa/");
    }
    #[tokio::test]
    async fn longest_mount() {
        let req = Request::get("/aa/a").body(Body::empty()).unwrap();
        let sa = "127.0.0.1:8080".parse().unwrap();

        let mut cfg = config::VHost::new(sa);
        cfg.paths.insert(PathBuf::from("aa"), create_wwwroot("."));
        cfg.paths.insert(PathBuf::from("aa/a"), create_wwwroot("."));
        let res = handle_vhost(req, &cfg, sa).await;
        let res = res.unwrap();
        assert_eq!(res.status(), 301);
        assert_eq!(res.headers().get("location").unwrap(), "/aa/a/");
    }
    #[tokio::test]
    async fn uri_encode() {
        let req = Request::get("/aa%2Fa").body(Body::empty()).unwrap();
        let sa = "127.0.0.1:8080".parse().unwrap();

        let mut cfg = config::VHost::new(sa);
        cfg.paths.insert(PathBuf::from("aa"), create_wwwroot("."));
        cfg.paths.insert(PathBuf::from("aa/a"), create_wwwroot("."));
        let res = handle_vhost(req, &cfg, sa).await;
        let res = res.unwrap();
        assert_eq!(res.status(), 301);
        assert_eq!(res.headers().get("location").unwrap(), "/aa/a/");
    }
    #[tokio::test]
    async fn path_trav_outside_mounts() {
        let req = Request::get("/a/../b").body(Body::empty()).unwrap();
        let sa = "127.0.0.1:8080".parse().unwrap();

        let mut cfg = config::VHost::new(sa);
        cfg.paths.insert(
            PathBuf::from("a"),
            UnitTestUseCase::create_wwwroot(None, None, None),
        );
        let res = handle_vhost(req, &cfg, sa).await;
        let res = res.unwrap_err();
        assert_eq!(res.kind(), ErrorKind::PermissionDenied);
        assert_eq!(res.into_inner().unwrap().to_string(), "not a mount path");
    }
    #[tokio::test]
    async fn path_trav_outside_webroot() {
        let req = Request::get("/../b").body(Body::empty()).unwrap();
        let sa = "127.0.0.1:8080".parse().unwrap();

        let mut cfg = config::VHost::new(sa);
        cfg.paths.insert(
            PathBuf::from("b"),
            UnitTestUseCase::create_wwwroot(None, None, None),
        );
        let res = handle_vhost(req, &cfg, sa).await;
        let res = res.unwrap_err();
        assert_eq!(res.kind(), ErrorKind::PermissionDenied);
        assert_eq!(res.into_inner().unwrap().to_string(), "path traversal");
    }
    #[cfg(windows)]
    #[tokio::test]
    async fn rustsec_2022_0072_part1() {
        let req = Request::get("/c:/b").body(Body::empty()).unwrap();

        //test mapping it to a file on disk
        assert_eq!(
            decode_and_normalize_path(req.uri())
                .unwrap()
                .prefix_with(Path::new("test")),
            Path::new("test/c:/b")
        );

        //test mount logic
        let sa = "127.0.0.1:8080".parse().unwrap();

        let mut cfg = config::VHost::new(sa);
        cfg.paths.insert(
            PathBuf::from(""),
            UnitTestUseCase::create_wwwroot(Some("c:/b"), None, None),
        );
        let res = handle_vhost(req, &cfg, sa).await;
        assert!(res.is_ok());
        //Note: ":" is not a valid dir char in windows
        //      However, an FCGI App might do things with it
    }
    #[cfg(windows)]
    #[tokio::test]
    async fn rustsec_2022_0072_part2() {
        let req = Request::get("/a/c:/b/d").body(Body::empty()).unwrap();

        //test mapping it to a file on disk
        assert_eq!(
            decode_and_normalize_path(req.uri())
                .unwrap()
                .prefix_with(Path::new("test")),
            Path::new("test/a/c:/b/d")
        );

        //test mount logic
        let sa = "127.0.0.1:8080".parse().unwrap();

        let mut cfg = config::VHost::new(sa);
        cfg.paths.insert(
            PathBuf::from("a/c:/b"),
            UnitTestUseCase::create_wwwroot(Some("d"), Some(Path::new("a/c:/b")), None),
        );
        let res = handle_vhost(req, &cfg, sa).await;
        assert!(res.is_ok());
    }
    #[tokio::test]
    async fn webroot() {
        let req = Request::get("/").body(Body::empty()).unwrap();
        let sa = "127.0.0.1:8080".parse().unwrap();

        let mut cfg = config::VHost::new(sa);
        cfg.paths.insert(
            PathBuf::from(""),
            UnitTestUseCase::create_wwwroot(Some(""), Some(Path::new("")), None),
        );
        let res = handle_vhost(req, &cfg, sa).await;
        assert!(res.is_ok());
    }
    #[test]
    fn normalize() {
        assert_eq!(
            decode_and_normalize_path(&"/a/../b".parse().unwrap())
                .unwrap()
                .0,
            "b"
        );
        assert_eq!(
            decode_and_normalize_path(&"/../../".parse().unwrap())
                .unwrap_err()
                .kind(),
            ErrorKind::PermissionDenied
        );
        assert_eq!(
            decode_and_normalize_path(&"/a/c:/b".parse().unwrap())
                .unwrap()
                .0,
            "a/c:/b"
        );
        assert_eq!(
            decode_and_normalize_path(&"/c:/b".parse().unwrap())
                .unwrap()
                .0,
            "c:/b"
        );
        assert_eq!(
            decode_and_normalize_path(&"/a/b/c".parse().unwrap())
                .unwrap()
                .strip_prefix(&Path::new("a"))
                .unwrap()
                .0,
            "b/c"
        );
    }
}

/// return the Host header
fn get_host(req: &Request<Body>) -> Option<&str> {
    match req.version() {
        Version::HTTP_2 => req.uri().host(),
        Version::HTTP_11 | Version::HTTP_10 | Version::HTTP_09 => {
            if let Some(host) = req.headers().get(header::HOST) {
                if let Ok(host) = host.to_str() {
                    return Some(host.split(':').next().unwrap());
                }
            }
            None
        }
        _ => None,
    }
}

/// picks the matching vHost and calls `handle_vhost`
async fn dispatch_to_vhost(
    req: Request<Body>,
    cfg: Arc<config::HostCfg>,
    remote_addr: SocketAddr,
) -> Result<Response<Body>, IoError> {
    if let Some(host) = get_host(&req) {
        debug!("Host: {:?}", host);
        if let Some(hcfg) = cfg.vhosts.get(host) {
            //user wants this host
            return handle_vhost(req, hcfg, remote_addr).await;
        }
    }

    if let Some(hcfg) = &cfg.default_host {
        return handle_vhost(req, hcfg, remote_addr).await;
    }
    Err(IoError::new(ErrorKind::PermissionDenied, "no vHost found"))
}

#[cfg(test)]
mod vhost_tests {
    use super::*;
    fn make_host_cfg(
        default_host: Option<config::VHost>,
        named: Option<(String, config::VHost)>,
    ) -> Arc<config::HostCfg> {
        let mut map: HashMap<String, config::VHost> = HashMap::new();
        if let Some((k, v)) = named {
            map.insert(k, v);
        }
        Arc::new(config::HostCfg {
            default_host,
            vhosts: map,
            listener: None,
            #[cfg(any(feature = "tlsrust", feature = "tlsnative"))]
            tls: None,
        })
    }
    #[tokio::test]
    async fn unknown_vhost() {
        let req = Request::new(Body::empty());
        let sa = "127.0.0.1:8080".parse().unwrap();

        let cfg = make_host_cfg(None, Some(("1".to_string(), config::VHost::new(sa))));
        let res = dispatch_to_vhost(req, cfg, sa).await;
        let res: IoError = res.unwrap_err();
        assert_eq!(res.into_inner().unwrap().to_string(), "no vHost found");
    }
    #[tokio::test]
    async fn specific_vhost() {
        let mut req = Request::new(Body::empty());
        req.headers_mut()
            .insert("Host", header::HeaderValue::from_static("1:8080"));

        let sa = "127.0.0.1:8080".parse().unwrap();

        let cfg = make_host_cfg(None, Some(("1".to_string(), config::VHost::new(sa))));

        let res = dispatch_to_vhost(req, cfg, sa).await;
        let res: IoError = res.unwrap_err();
        assert_eq!(res.into_inner().unwrap().to_string(), "not a mount path");
    }
    #[tokio::test]
    async fn default_vhost() {
        let req = Request::new(Body::empty());
        let sa = "127.0.0.1:8080".parse().unwrap();

        let cfg = make_host_cfg(Some(config::VHost::new(sa)), None);

        let res = dispatch_to_vhost(req, cfg, sa).await;
        let res: IoError = res.unwrap_err();
        assert_eq!(res.into_inner().unwrap().to_string(), "not a mount path");
    }
}

/// new request on a `SocketAddr`.
/// turn errors into responses
pub(crate) async fn handle_request(
    req: Request<Body>,
    cfg: Arc<config::HostCfg>,
    remote_addr: SocketAddr,
) -> Result<Response<Body>, HTTPError> {
    info!("{} {} {}", remote_addr, req.method(), req.uri());
    dispatch_to_vhost(req, cfg, remote_addr)
        .await
        .or_else(|err| {
            error!("{}", err);
            if let Some(cause) = err.get_ref() {
                let mut e: &dyn Error = cause;
                loop {
                    error!("{}", e);
                    e = match e.source() {
                        Some(e) => {
                            error!("caused by:");
                            e
                        }
                        None => break,
                    }
                }
            }
            match err.kind() {
                ErrorKind::NotFound => Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body(Body::empty()),
                ErrorKind::PermissionDenied => Response::builder()
                    .status(StatusCode::FORBIDDEN)
                    .body(Body::empty()),
                ErrorKind::InvalidData => Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(Body::empty()),
                ErrorKind::BrokenPipe
                | ErrorKind::UnexpectedEof
                | ErrorKind::ConnectionAborted
                | ErrorKind::ConnectionRefused
                | ErrorKind::ConnectionReset => Response::builder()
                    .status(StatusCode::BAD_GATEWAY)
                    .body(Body::empty()),
                ErrorKind::TimedOut => Response::builder()
                    .status(StatusCode::GATEWAY_TIMEOUT)
                    .body(Body::empty()),
                _ => Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Body::empty()),
            }
        })
}
