mod staticf;
pub mod fcgi;

use hyper::{Body, Request, Response, header, StatusCode, Version, http::Error as HTTPError}; //, Method};
use std::io::{Error as IoError, ErrorKind};
use log::{info, error, debug, trace};
use std::net::SocketAddr;
use std::collections::HashMap;
use std::sync::Arc;
use std::path::{Component, Path, PathBuf};
use std::error::Error;
use crate::config;


pub fn insert_default_headers(header: &mut header::HeaderMap<header::HeaderValue>,
    config_header: &Option<HashMap<String, String>>) -> Result<(),Box<dyn Error>> {
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
        (header::CONTENT_SECURITY_POLICY, "default-src 'self';frame-ancestors 'self'"),
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
fn ext_in_list(list: &Option<Vec<PathBuf>>, path: &PathBuf) -> bool {
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
    true  // no list == all is ok
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
async fn handle_wwwroot(req: Request<Body>,
    wwwr: &config::WwwRoot,
    full_path: &PathBuf,
    remote_addr: SocketAddr) -> Result<Response<Body>, IoError> {

    debug!("working root {:?}", wwwr);

    if let Some(auth_conf) = wwwr.auth.as_ref() {
        //Authorisation is needed
        if let Some(resp) = crate::auth::check_is_authorized(auth_conf, &req).await? {
            return Ok(resp);
        }
    }

    //hyper_reverse_proxy::call(remote_addr.ip(), "http://127.0.0.1:13901", req)
    
    if let Some(fcgi_cfg) = &wwwr.fcgi {
        if ext_in_list(&fcgi_cfg.exec, full_path) {
            let mut resp = fcgi::fcgi_call(&fcgi_cfg, req, full_path, remote_addr).await?;
            insert_default_headers(resp.headers_mut(), &wwwr.header).unwrap(); //save bacause checked at server start
            return Ok(resp);
        }
    }

    /*if req.method()==Method::OPTIONS {
    return Ok(Response::builder()
    .status(StatusCode::OK)
    .header(header::ALLOW, "GET,HEAD,OPTIONS")
    .body(Body::empty())
    .expect("unable to build response"))
    }*/

    if ext_in_list(&wwwr.serve, full_path) {
        let mut resp = staticf::return_file(&req, &wwwr, full_path).await?;
        insert_default_headers(resp.headers_mut(), &wwwr.header).unwrap(); //save bacause checked at server start
        Ok(resp)
    }else{
        Err(IoError::new(ErrorKind::PermissionDenied,"bad file extension"))
    }

}

/// get the full path of a requested resource
/// or return an error if the request_path is not part of this wwwroot
/// Note: /a is not part of /aa (but of /a/a and /a)
fn get_full_path(
    wwwr: &config::WwwRoot,
    req_path: &Path,
    mount_path: &Path) -> Result<PathBuf, ()> {

    match req_path.strip_prefix(mount_path) {
        Ok(req_path) => {
            let full_path = wwwr.dir.join(req_path);
            trace!("full_path {:?}", full_path.canonicalize());
            Ok(full_path)
        },
        Err(_e) => {
            Err(())
        }
    }

}

/// new request on a particular vHost.
/// picks the matching WwwRoot and calls `handle_wwwroot`
async fn handle_vhost(req: Request<Body>, cfg: &config::VHost, remote_addr: SocketAddr) -> Result<Response<Body>, IoError> {
    let request_path = PathBuf::from(decode_percents(&req.uri().path()));

    let req_path = normalize_path(&request_path);
    debug!("req_path {:?}", req_path);

    //we want the longest match
    //BTreeMap is sorted from small to big
    for (mount_path, wwwr) in cfg.paths.iter().rev() {
        trace!("checking mount point: {:?}", mount_path);
        if let Ok(full_path) = get_full_path(&wwwr, &req_path, &mount_path) {
            return handle_wwwroot(req, &wwwr, &full_path, remote_addr).await;
        }
    }

    Err(IoError::new(ErrorKind::PermissionDenied,"not a mount path"))
}

/// return the Host header
fn get_host(req: &Request<Body>) -> Option<&str> {
    match req.version() {
        Version::HTTP_2 => {
            req.uri().host()
        },
        Version::HTTP_11 | Version::HTTP_10 | Version::HTTP_09 => {
            if let Some(host) = req.headers().get(header::HOST) {
                if let Ok(host) = host.to_str() {
                    return Some(host.split(':').next().unwrap());
                }
            }
            None
        },
        _ => None,
    }
}


/// picks the matching vHost and calls `handle_vhost`
async fn dispatch_to_vhost(req: Request<Body>, cfg :Arc<config::HostCfg>, remote_addr: SocketAddr)
 -> Result<Response<Body>, IoError> {

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
    Err(IoError::new(ErrorKind::PermissionDenied,"no vHost found"))
}

/// new request on a `SocketAddr`.
/// turn errors into responses
pub(crate) async fn handle_request(req: Request<Body>, cfg :Arc<config::HostCfg>, remote_addr: SocketAddr)
 -> Result<Response<Body>, HTTPError> {
    info!("{} {} {}", remote_addr, req.method(), req.uri());

    dispatch_to_vhost(req, cfg, remote_addr).await.or_else(|err| {
        error!("{}", err);
        match err.kind() {
            ErrorKind::NotFound => {
                Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Body::empty())
            },
            ErrorKind::PermissionDenied => {
                Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(Body::empty())
            },
            ErrorKind::InvalidData => {
                Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Body::empty())
            },
            ErrorKind::UnexpectedEof
            | ErrorKind::ConnectionAborted
            | ErrorKind::ConnectionRefused
            | ErrorKind::ConnectionReset => {
                Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Body::empty())
            },
            _ => {
                Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::empty())
            },
        }
        
    })
}