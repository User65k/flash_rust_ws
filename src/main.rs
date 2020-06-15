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
use std::error::Error;
use std::io::{Error as IoError, ErrorKind};

mod config;
mod user;
mod pidfile;
mod body;
mod dispatch;


async fn prepare_hyper_servers(mut listening_ifs: HashMap<SocketAddr, config::HostCfg>)
 -> Result<Vec<JoinHandle<Result<(), hyper::error::Error>>>, Box<dyn Error>> {

    let mut handles = vec![];
    for (addr, mut cfg) in listening_ifs.drain() {
        let l = match cfg.listener.take() {
            Some(l) => l,
            None => {return Err(Box::new(IoError::new(ErrorKind::Other, "could not listen")));}
        };
        let server = match hyper::Server::from_tcp(l) {
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
                return Err(Box::new(err));
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
            let listening_ifs = match config::group_config(&mut cfg).await {
                Err(e) => {error!("{}", e);eprintln!("Error! See Logs");return;},
                Ok(m) => m
            };
            debug!("{:#?}",listening_ifs);
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
            //setup all servers
            match prepare_hyper_servers(listening_ifs).await {
                Ok(handles) => {
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
