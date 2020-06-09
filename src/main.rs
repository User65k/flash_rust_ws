/*!

Config allows multiple vHosts on one IP. As well as different IPs.
Incomming Requests are thus filtered by IP, then vHost, then URL.

*/

use futures_util::future::join_all;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Request};
use hyper::server::conn::AddrStream;
use log::{info, error, debug, trace};
use std::net::SocketAddr;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::task::JoinHandle;
use async_fcgi::client::con_pool::ConPool as FCGIApp;
use std::convert::Into;

mod config;
mod user;
mod pidfile;
mod body;
mod dispatch;

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
                info!("Bound to {}", &addr);
                let hcfg = Arc::new(cfg);
                let make_service = make_service_fn(move |socket: &AddrStream| {
                    let remote_addr = socket.remote_addr();
                    trace!("Connected on {}", &addr);
                    let hcfg = hcfg.clone();
                    async move {
                        Ok::<_, hyper::Error>(service_fn(move |req: Request<Body>| dispatch::handle_request(req, hcfg.clone(), remote_addr) ))
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
