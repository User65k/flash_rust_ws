mod staticf;
mod fcgi;

use http::response::Builder as HTTPResponseBuilder;
use hyper::{Body, Request, Response, header, StatusCode}; //, Method};
use std::io::{Error as IoError, ErrorKind};
use log::{info, error, debug, trace};
use std::net::SocketAddr;
use std::collections::HashMap;
use std::sync::Arc;
use std::path::{Component, Path, PathBuf};
use crate::{config, HostCfg};


fn insert_default_headers(header: &mut header::HeaderMap<header::HeaderValue>,
    config_header: &Option<HashMap<String, String>>) {
    if let Some(config_header) = config_header {
        for (key, value) in config_header.iter() {
            let key = header::HeaderName::from_bytes(key.as_bytes()).expect("wrong HTTP header");
            if !header.contains_key(&key) {
                header.insert(key, header::HeaderValue::from_str(value).expect("wrong HTTP header"));
            }
        }
    }
    let default_headers = [
        (header::X_FRAME_OPTIONS, "sameorigin"),
        (header::CONTENT_SECURITY_POLICY, "default-src https:"),
        (header::STRICT_TRANSPORT_SECURITY, "max-age=15768000"),
        (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
    ];
    for (key, value) in default_headers.iter() {
        if !header.contains_key(key) {
            header.insert(key, header::HeaderValue::from_static(value));
        }
    }
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

async fn handle_wwwroot(req: Request<Body>,
    wwwr: &config::WwwRoot,
    req_path: &Path,
    mount_path: &Path) -> Result<Response<Body>, IoError> {

    debug!("working root {:?}", wwwr);
    match req_path.strip_prefix(mount_path) {
        Ok(req_path) => {
            let full_path = wwwr.dir.join(req_path);

            if let Some(fcgi_cfg) = &wwwr.fcgi {
                if ext_in_list(&fcgi_cfg.exec, &full_path) {
                    return match fcgi::fcgi_call(&fcgi_cfg, req, &full_path).await{
                        Ok(mut resp) => {
                            insert_default_headers(resp.headers_mut(), &wwwr.header);
                            Ok(resp)
                        },
                        Err(err) => {
                            match err.kind() {
                                ErrorKind::NotFound => {
                                    Ok(HTTPResponseBuilder::new()
                                    .status(StatusCode::NOT_FOUND)
                                    .body(Body::empty())
                                    .expect("unable to build response"))
                                },
                                _ => Err(err),
                            }
                        }
                    };
                }
            }

            /*if req.method()==Method::OPTIONS {
            return Ok(HTTPResponseBuilder::new()
            .status(StatusCode::OK)
            .header(header::ALLOW, "GET,HEAD,OPTIONS")
            .body(Body::empty())
            .expect("unable to build response"))
            }*/

            if ext_in_list(&wwwr.serve, &full_path) {
                let mut resp = staticf::return_file(&req, &wwwr, &full_path).await?;
                insert_default_headers(resp.headers_mut(), &wwwr.header);
                return Ok(resp);
            }else{
                Ok(create_resp_forbidden())
            }
        },
        Err(e) => {
            error!("{}", e);
            Err(IoError::new(ErrorKind::InvalidInput, format!("{}",e)))
        }
    }

}

async fn handle_vhost(req: Request<Body>, cfg: &config::VHost) -> Result<Response<Body>, IoError> {
    let request_path = PathBuf::from(decode_percents(&req.uri().path()));

    let req_path = normalize_path(&request_path);
    debug!("req_path {:?}", req_path);
    /*let skip_num = if req_path.as_os_str() == "" {
    0
    }else{
    1
    };*/

    if cfg.paths.len()==1 {
        //fast path (don't walk request path)
        let (mount_path, wwwr) = cfg.paths.iter().next().unwrap();  // save because len == 1
        if req_path.starts_with(mount_path) {
            return handle_wwwroot(req, &wwwr, &req_path, &mount_path).await;
        }
    }
    //we want the longest match
    for path in req_path.ancestors()/*.skip(skip_num) */{
        for (mount_path, wwwr) in cfg.paths.iter() {
            trace!("checking mount point: {:?}", mount_path);
            if path.as_os_str() == mount_path {
                return handle_wwwroot(req, &wwwr, &req_path, &mount_path).await;
            }
        }
    }

    Ok(create_resp_forbidden())
}

pub(crate) async fn handle_request(req: Request<Body>, cfg :Arc<HostCfg>, remote_addr: SocketAddr) -> Result<Response<Body>, IoError> {
    info!("{} {} {}", remote_addr, req.method(), req.uri());
    if let Some(host) = req.headers().get(header::HOST) {
        debug!("Host: {:?}", host);
        if let Ok(host) = host.to_str() {
            if let Some(hcfg) = cfg.vhosts.get(host) {
                //user wants this host
                return handle_vhost(req, hcfg).await;
            }
        }
    }

    if let Some(hcfg) = &cfg.default_host {
        return handle_vhost(req, hcfg).await;
    }
    Ok(create_resp_forbidden())
}

fn create_resp_forbidden() -> Response<Body> {
    HTTPResponseBuilder::new()
    .status(StatusCode::FORBIDDEN)
    .body(Body::empty())
    .expect("unable to build response")
}