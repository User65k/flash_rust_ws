/*!

Config allows multiple vHosts on one IP. As well as different IPs.
Incomming Requests are thus filtered by IP, then vHost, then URL.

*/

use futures_util::future::join_all;
use http::response::Builder as HTTPResponseBuilder;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Request, Response, header, StatusCode, Method};
use hyper::server::conn::AddrStream;
use std::io::{Error as IoError, ErrorKind};
use log::{info, error, debug, trace};
use std::net::SocketAddr;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::task::JoinHandle;
use std::path::{Component, Path, PathBuf};
use async_fcgi::client::con_pool::ConPool as FCGIApp;
use std::convert::Into;

mod config;
mod user;
mod pidfile;
mod file_dispatch;
mod fcgi_dispatch;
mod body;
//use body::FRBody;

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

    info!("working root {:?}", wwwr);
    match req_path.strip_prefix(mount_path) {
        Ok(req_path) => {
            let full_path = wwwr.dir.join(req_path);

            if let Some(fcgi_cfg) = &wwwr.fcgi {
                if ext_in_list(&fcgi_cfg.exec, &full_path) {
                    return match fcgi_dispatch::fcgi_call(&fcgi_cfg, req, &full_path).await{
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
                let mut resp = file_dispatch::return_file(&req, &wwwr, &full_path).await?;
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
    info!("req_path {:?}", req_path);
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
            debug!("checking mount point: {:?}", mount_path);
            if path.as_os_str() == mount_path {
                return handle_wwwroot(req, &wwwr, &req_path, &mount_path).await;
            }
        }
    }
    
    Ok(create_resp_forbidden())
}

async fn handle_request(req: Request<Body>, cfg :Arc<HostCfg>, remote_addr: SocketAddr) -> Result<Response<Body>, IoError> {
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

#[derive(Debug)]
struct HostCfg {
    default_host: Option<config::VHost>,
    vhosts: HashMap<String, config::VHost>,
}
impl HostCfg{
    fn new() -> HostCfg {
        HostCfg {
            default_host: None,
            vhosts: HashMap::new()
        }
    }
}

async fn prepare_hyper_servers(mut listening_ifs: HashMap<SocketAddr, HostCfg>)
 -> Result<Vec<JoinHandle<Result<(), hyper::error::Error>>>, hyper::error::Error> {

    let mut handles = vec![];
    for (addr, cfg) in listening_ifs.drain() {
        let server = match hyper::Server::try_bind(&addr) {
            Ok(server_builder) => {
                println!("Bound to {}", &addr);
                let hcfg = Arc::new(cfg);
                let make_service = make_service_fn(move |socket: &AddrStream| {
                    let remote_addr = socket.remote_addr();
                    trace!("Connected on {}", &addr);
                    let hcfg = hcfg.clone();
                    async move {
                        Ok::<_, hyper::Error>(service_fn(move |req: Request<Body>| handle_request(req, hcfg.clone(), remote_addr) ))
                    }
                });
                server_builder.serve(make_service)
            },
            Err(err) => {
                error!("{}: {}", addr, err);
                return Err(err);
            }
        };
        handles.push(tokio::spawn(server));
    }
    Ok(handles)
}

#[tokio::main]
async fn main() {
    extern crate pretty_env_logger;
    pretty_env_logger::init();

    match config::load_config() {
        Err(e) => {
            error!("Configuration error!\r\n{}", e);
            eprintln!("Configuration error! See Logs");
        },
        Ok(mut cfg) => {
            //group config by SocketAddrs
            let mut listening_ifs = HashMap::new();
            for (vhost, mut params) in cfg.hosts.drain() {
                let addr = params.ip;
                for (_, wwwroot) in params.paths.iter_mut() {
                    wwwroot.fcgi = if let Some(mut fcgi_cfg) = wwwroot.fcgi.take() {
                        match FCGIApp::new(&(&fcgi_cfg.sock).into()).await {
                            Ok(app) => fcgi_cfg.app = Some(app),
                            Err(e) => {
                                error!("FCGIApp: {}", e);
                                eprintln!("FCGI Error! See Logs");
                                return;
                            }
                        }
                        Some(fcgi_cfg)
                    }else{
                        None
                    }
                }
                match listening_ifs.get_mut(&addr) {
                    None => {
                        let mut hcfg = HostCfg::new();
                        if Some(true) == params.validate_server_name {
                            hcfg.vhosts.insert(vhost, params);
                        }else{
                            hcfg.default_host = Some(params);
                        }
                        listening_ifs.insert(addr, hcfg);
                    },
                    Some(mut hcfg) => {
                        if Some(true) == params.validate_server_name {
                            hcfg.vhosts.insert(vhost, params);
                        }else{
                            if hcfg.default_host.is_none() {
                                hcfg.default_host = Some(params);
                            }else{
                                error!("{} is the second host on {} that does not validate the server name", vhost, addr);
                                eprintln!("Configuration error! See Logs");
                                return;
                            }
                        }
                    }
                }
            }
            debug!("{:#?}",listening_ifs);
            //setup all servers
            match prepare_hyper_servers(listening_ifs).await {
                Ok(handles) => {
                    // Switch user+group
                    if let Some(user) = cfg.user {
                        if let Err(e) = user::switch_user(&user) {
                            error!("Could not switch User: {}", e);
                            eprintln!("Error! See Logs");
                            return;
                        }
                    }
                    if let Some(group) = cfg.group {
                        if let Err(e) = user::switch_group(&group) {
                            error!("Could not switch Group: {}", e);
                            eprintln!("Error! See Logs");
                            return;
                        }
                    }
                    //Write pid file
                    if let Some(pidfile) = cfg.pidfile {
                        if let Err(e) = pidfile::create_pid_file(pidfile) {
                            error!("Could not write Pid File: {}", e);
                            eprintln!("Error! See Logs");
                            return;
                        }
                    }

                    join_all(handles).await;
                },
                Err(e) => {
                    error!("{}",e);
                    eprintln!("Error! See Logs");
                }
            }
        }
    };
}
