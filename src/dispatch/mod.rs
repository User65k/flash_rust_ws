#[cfg(feature = "webdav")]
pub mod dav;
#[cfg(feature = "fcgi")]
pub mod fcgi;
#[cfg(feature = "proxy")]
pub mod proxy;
mod staticf;
#[cfg(test)]
pub(crate) mod test;
mod webpath;
#[cfg(feature = "websocket")]
pub mod websocket;
use hyper::body::HttpBody;
pub use webpath::WebPath;

use crate::config::{self, Utf8PathBuf};
use hyper::{header, http::Error as HTTPError, Body, Request, Response, StatusCode, Version}; //, Method};
use log::{debug, error, info, trace};
use staticf::ResolveResult;
use std::collections::HashMap;
use std::error::Error;
use std::io::{Error as IoError, ErrorKind};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

pub fn insert_default_headers(
    header: &mut header::HeaderMap<header::HeaderValue>,
    config_header: &Option<HashMap<crate::config::HeaderNameCfg, crate::config::HeaderValueCfg>>,
) {
    if let Some(config_header) = config_header {
        for (key, val) in config_header.iter() {
            if !header.contains_key(&key.0) {
                header.insert(&key.0, val.0.clone());
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
}
fn ext_in_list(list: &Option<Vec<Utf8PathBuf>>, path: &Path) -> bool {
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

/// handle a request by
/// - checking for authentication
/// - building the absolute file path
/// - forwarding to FCGI
/// - returning a static file
///
/// `web_mount` first part of URI, selecting the wwwr. Used for links in the response
/// `req_path` second part of URI - a path within the wwwr. Used to select a file
async fn handle_wwwroot(
    req: Request<Body>,
    wwwr: &config::WwwRoot,
    req_path: WebPath<'_>,
    web_mount: &Utf8PathBuf,
    remote_addr: SocketAddr,
) -> Result<Response<Body>, IoError> {
    debug!("working root {:?}", wwwr);
    let is_dir_request = req.uri().path().as_bytes().last() == Some(&b'/');
    /*
    A web_mount is always a folder.
    Unless...
    - Its a Websocket
    - Its a redirection
    - FCGI does the routing

    This is mainly important in the case of acting as a reverse proxy (so relative links work).
    StaticFiles+Webdav would enforce this later (after some disk IO), so do it now
    */
    match &wwwr.mount {
        config::UseCase::Redirect(_) => {}
        #[cfg(feature = "fcgi")]
        config::UseCase::FCGI(fcgi::FcgiMnt {
            fcgi: fcgi::FCGIApp { exec: None, .. },
            static_files: None,
        }) => {
            //FCGI + dont check for file
        }
        #[cfg(feature = "websocket")]
        config::UseCase::Websocket(_) => {}
        _ => {
            if req_path.is_empty() && !is_dir_request {
                //mount paths must be a dir - always
                return Ok(staticf::redirect(&req, &req_path, web_mount));
            }
        }
    }

    if let Some(auth_conf) = wwwr.auth.as_ref() {
        //Authorisation is needed
        if let Some(resp) = crate::auth::check_is_authorized(auth_conf, &req).await? {
            return Ok(resp);
        }
    }

    let sf = match &wwwr.mount {
        config::UseCase::Redirect(redir) => {
            return Ok(Response::builder()
                .status(
                    redir
                        .code
                        .as_ref()
                        .map(|c| c.0)
                        .unwrap_or(StatusCode::MOVED_PERMANENTLY),
                )
                .header(header::LOCATION, &redir.redirect.0)
                .body(Body::empty())
                .unwrap());
        }
        config::UseCase::StaticFiles(sf) => sf,
        #[cfg(feature = "fcgi")]
        config::UseCase::FCGI(fcgi::FcgiMnt { fcgi, static_files }) => {
            if fcgi.exec.is_none() {
                //FCGI + dont check for file -> always FCGI
                return fcgi::fcgi_call(fcgi, req, &req_path, web_mount, None, None, remote_addr)
                    .await;
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
        #[cfg(feature = "proxy")]
        config::UseCase::Proxy(config) => {
            return proxy::forward(req, &req_path, remote_addr, config).await
        }
    };

    let full_path = req_path.prefix_with(&sf.dir);
    debug!("check for file: {:?}", full_path);

    #[cfg(feature = "fcgi")]
    let (full_path, resolved_file, path_info) =
        fcgi::resolve_path(full_path, is_dir_request, sf, &req_path).await?;
    #[cfg(not(feature = "fcgi"))]
    let (full_path, resolved_file) =
        staticf::resolve_path(&full_path, is_dir_request, &sf.index).await?;

    if !sf.follow_symlinks {
        //check if the canonicalized version is still inside of the (abs) root path
        let fp = full_path.canonicalize()?;
        if !fp.starts_with(&sf.dir) {
            return Err(IoError::new(
                ErrorKind::PermissionDenied,
                "Symlinks are not allowed",
            ));
        }
    }

    match resolved_file {
        ResolveResult::IsDirectory => {
            //request for a file that is a directory
            Ok(staticf::redirect(&req, &req_path, web_mount))
        }
        ResolveResult::Found(file, metadata, mime) => {
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
                        path_info.as_ref(),
                        remote_addr,
                    )
                    .await;
                }
            }

            if ext_in_list(&sf.serve, &full_path) {
                staticf::return_file(&req, file, metadata, mime).await
            } else {
                Err(IoError::new(
                    ErrorKind::PermissionDenied,
                    "bad file extension",
                ))
            }
        }
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
    let req_path: WebPath = req.uri().try_into()?;
    debug!("req_path {:?}", req_path);

    //we want the longest match
    //BTreeMap is sorted from small to big
    for (mount_path, wwwr) in cfg.paths.iter().rev() {
        trace!("checking mount point: {:?}", mount_path);
        if let Ok(full_path) = req_path.strip_prefix(mount_path) {
            let req_path = full_path.into_owned(); // T_T
            let mut resp = handle_wwwroot(req, wwwr, req_path, mount_path, remote_addr).await?;
            insert_default_headers(resp.headers_mut(), &wwwr.header);
            return Ok(resp);
        }
    }

    Err(IoError::new(
        ErrorKind::PermissionDenied,
        "not a mount path",
    ))
}

/// return the Host header
fn get_host<B: HttpBody>(req: &Request<B>) -> Option<&str> {
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
        trace!("Host: {:?}", host);
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
                ErrorKind::InvalidInput | ErrorKind::InvalidData => Response::builder()
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
