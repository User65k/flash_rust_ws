/*!

Config allows multiple vHosts on one IP. As well as different IPs.
Incomming Requests are thus filtered by IP, then vHost, then URL.

*/

use futures_util::future::join_all;
use http::response::Builder as HTTPResponseBuilder;
use http::{header, StatusCode};
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Request, Response};
use hyper::server::conn::AddrStream;
use std::io::{Error as IoError, ErrorKind};
use log::{info, error, debug, trace};
use std::net::SocketAddr;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::task::JoinHandle;
use hyper_staticfile::ResponseBuilder as FileResponseBuilder;
use std::path::{Component, Path, PathBuf};

mod config;
mod user;
mod pidfile;
mod file_dispatch;

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

async fn handle_wwwroot<B>(req: Request<B>,
                            wwwr: &config::WwwRoot,
                            req_path: &Path,
                            mount_path: &Path) -> Result<Response<Body>, IoError> {

    info!("working root {:?}", wwwr);
    match req_path.strip_prefix(mount_path) {
        Ok(req_path) => {
            let full_path = wwwr.dir.join(req_path);

            return file_dispatch::resolve(&wwwr, &req, &full_path).await.map(|result| {
                FileResponseBuilder::new()
                    .request(&req)
                    .cache_headers(Some(500))
                    .build(result)
                    .expect("unable to build response")
            });
        },
        Err(e) => {
            error!("{}", e);
            Err(IoError::new(ErrorKind::InvalidInput, format!("{}",e)))
        }
    }
    
}

async fn handle_vhost<B>(req: Request<B>, cfg: &config::VHost) -> Result<Response<Body>, IoError> {

    let request_path = PathBuf::from(decode_percents(&req.uri().path()));

    let req_path = normalize_path(&request_path);
    info!("req_path {:?}", req_path);
    let skip_num = if req_path.as_os_str() == "" {
        0
    }else{
        1
    };

    if cfg.paths.len()==1 {
        //fast path (don't walk request path)
        let (mount_path, wwwr) = cfg.paths.iter().next().unwrap();  // save because len == 1
        if req_path.starts_with(mount_path) {
            return handle_wwwroot(req, &wwwr, &req_path, &mount_path).await;
        }
    }
    //we want the longest match
    for path in req_path.ancestors().skip(skip_num) {
       for (mount_path, wwwr) in cfg.paths.iter() {
            if path.as_os_str() == mount_path {
                return handle_wwwroot(req, &wwwr, &req_path, &mount_path).await;
            }
        }
    }
    
    let res = HTTPResponseBuilder::new()
        .status(StatusCode::FORBIDDEN)
        .body(Body::empty())
        .expect("unable to build response");
    Ok(res)
}

async fn handle_request<B>(req: Request<B>, cfg :Arc<HostCfg>, remote_addr: SocketAddr) -> Result<Response<Body>, IoError> {
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
    let res = HTTPResponseBuilder::new()
        .status(StatusCode::FORBIDDEN)
        .body(Body::empty())
        .expect("unable to build response");
    Ok(res)
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
        },
        Ok(mut cfg) => {
            //group config by SocketAddrs
            let mut listening_ifs = HashMap::new();
            for (vhost, params) in cfg.hosts.drain() {
                let addr = params.ip;
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
                                return;
                            }
                        }
                    }
                }
            }
            debug!("{:?}",listening_ifs);
            //setup all servers
            match prepare_hyper_servers(listening_ifs).await {
                Ok(handles) => {
                    // Switch user+group
                    if let Some(user) = cfg.user {
                        if let Err(e) = user::switch_user(&user) {
                            error!("Could not switch User: {}", e);
                            return;
                        }
                    }
                    if let Some(group) = cfg.group {
                        if let Err(e) = user::switch_group(&group) {
                            error!("Could not switch Group: {}", e);
                            return;
                        }
                    }
                    //Write pid file
                    if let Some(pidfile) = cfg.pidfile {
                        if let Err(e) = pidfile::create_pid_file(pidfile) {
                            error!("Could not write Pid File: {}", e);
                            return;
                        }
                    }

                    join_all(handles).await;
                },
                Err(e) => {
                    error!("{}",e);
                }
            }
        }
    };
}
