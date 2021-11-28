#[cfg(feature = "webdav")]
pub mod dav;
#[cfg(feature = "fcgi")]
pub mod fcgi;
mod staticf;
#[cfg(feature = "websocket")]
pub mod websocket;

use crate::config;
use hyper::{header, http::Error as HTTPError, Body, Request, Response, StatusCode, Version}; //, Method};
use hyper_staticfile::{ResolveResult, ResponseBuilder as FileResponseBuilder};
use log::{debug, error, info, trace};
use std::collections::HashMap;
use std::error::Error;
use std::io::{Error as IoError, ErrorKind};
use std::net::SocketAddr;
use std::path::{Component, Path, PathBuf};
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

#[inline]
fn decode_percents(string: &str) -> String {
    percent_encoding::percent_decode_str(string)
        .decode_utf8_lossy()
        .into_owned()
}

/// Path.canonicalize for non existend paths
fn normalize_path(path: &Path) -> PathBuf {
    path.components()
        .fold(PathBuf::new(), |mut result, p| match p {
            Component::Normal(x) => {
                result.push(x);
                result
            }
            Component::ParentDir => {
                result.pop();
                result
            }
            _ => result,
        })
}

/// handle a request by
/// - checking for authentication
/// - building the absolute file path
/// - forwarding to FCGI
/// - returning a static file
async fn handle_wwwroot(
    req: Request<Body>,
    wwwr: &config::WwwRoot,
    req_path: &Path,
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
                return fcgi::fcgi_call(fcgi, req, req_path, web_mount, None, remote_addr).await;
            }
            match static_files {
                Some(sf) => sf,
                None => return Err(IoError::new(ErrorKind::PermissionDenied, "no dir to serve")),
            }
        }
        #[cfg(feature = "websocket")]
        config::UseCase::Websocket(ws) => {
            return websocket::upgrade(req, ws, req_path, remote_addr).await;
        }
        #[cfg(feature = "webdav")]
        config::UseCase::Webdav(dav) => {
            return dav::do_dav(req, req_path, dav, web_mount, remote_addr).await;
        }
    };

    let is_dir_request = req.uri().path().as_bytes().last() == Some(&b'/');
    let full_path = sf.dir.join(req_path);
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
            return fcgi::fcgi_call(fcgi, req, &full_path, web_mount, Some(&sf.dir), remote_addr)
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
    let request_path = PathBuf::from(decode_percents(req.uri().path()));

    let req_path = normalize_path(&request_path);
    debug!("req_path {:?}", req_path);

    //we want the longest match
    //BTreeMap is sorted from small to big
    for (mount_path, wwwr) in cfg.paths.iter().rev() {
        trace!("checking mount point: {:?}", mount_path);
        if let Ok(full_path) = req_path.strip_prefix(mount_path) {
            let mut resp = handle_wwwroot(req, wwwr, full_path, mount_path, remote_addr).await?;
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
        assert_eq!(res.headers().get("location").unwrap(), "/aa%2Fa/");
    }
    #[tokio::test]
    async fn root() {
        let req = Request::get("/a/../b").body(Body::empty()).unwrap();
        let sa = "127.0.0.1:8080".parse().unwrap();

        let mut cfg = config::VHost::new(sa);
        cfg.paths.insert(PathBuf::from("a"), create_wwwroot("."));
        let res = handle_vhost(req, &cfg, sa).await;
        let _res = res.unwrap_err();
    }
    #[test]
    fn normalize() {
        let req = PathBuf::from("a/../b");
        assert_eq!(normalize_path(&req), PathBuf::from("b"));
        let req = PathBuf::from("../../");
        assert_eq!(normalize_path(&req), PathBuf::from(""));
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
    #[tokio::test]
    async fn unknown_vhost() {
        let req = Request::new(Body::empty());
        let sa = "127.0.0.1:8080".parse().unwrap();

        let mut map: HashMap<String, config::VHost> = HashMap::new();
        map.insert("1".to_string(), config::VHost::new(sa));

        let cfg = Arc::new(config::HostCfg {
            default_host: None,
            vhosts: map,
            listener: None,
            tls: None,
        });
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

        let mut map: HashMap<String, config::VHost> = HashMap::new();
        map.insert("1".to_string(), config::VHost::new(sa));

        let cfg = Arc::new(config::HostCfg {
            default_host: None,
            vhosts: map,
            listener: None,
            tls: None,
        });

        let res = dispatch_to_vhost(req, cfg, sa).await;
        let res: IoError = res.unwrap_err();
        assert_eq!(res.into_inner().unwrap().to_string(), "not a mount path");
    }
    #[tokio::test]
    async fn default_vhost() {
        let req = Request::new(Body::empty());
        let sa = "127.0.0.1:8080".parse().unwrap();
        let map: HashMap<String, config::VHost> = HashMap::new();

        let cfg = Arc::new(config::HostCfg {
            default_host: Some(config::VHost::new(sa)),
            vhosts: map,
            listener: None,
            tls: None,
        });

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
