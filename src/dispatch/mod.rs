#[cfg(feature = "webdav")]
pub mod dav;
#[cfg(feature = "fcgi")]
pub mod fcgi;
mod staticf;
#[cfg(test)]
pub mod test;
mod webpath;
#[cfg(feature = "websocket")]
pub mod websocket;
pub use webpath::WebPath;

use crate::config::{self, Utf8PathBuf};
use hyper::{header, http::Error as HTTPError, Body, Request, Response, StatusCode, Version}; //, Method};
use log::{debug, error, info, trace};
use staticf::ResolveResult;
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
async fn handle_wwwroot(
    req: Request<Body>,
    wwwr: &config::WwwRoot,
    req_path: WebPath<'_>,
    web_mount: &Utf8PathBuf,
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

    let (full_path, resolved_file) =
        staticf::resolve_path(&full_path, is_dir_request, &sf.index).await?;

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
            insert_default_headers(resp.headers_mut(), &wwwr.header).unwrap(); //save bacause checked at server start
            return Ok(resp);
        }
    }

    Err(IoError::new(
        ErrorKind::PermissionDenied,
        "not a mount path",
    ))
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
