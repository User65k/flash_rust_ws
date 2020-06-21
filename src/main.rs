/*!

Config allows multiple vHosts on one IP. As well as different IPs.
Incomming Requests are thus filtered by IP, then vHost, then URL.

*/

use futures_util::future::join_all;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Request};
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
mod transport;
mod logging;

use transport::{PlainIncoming, PlainStream};


async fn prepare_hyper_servers(mut listening_ifs: HashMap<SocketAddr, config::HostCfg>)
 -> Result<Vec<JoinHandle<Result<(), hyper::error::Error>>>, Box<dyn Error>> {

    let mut handles = vec![];
    for (addr, mut cfg) in listening_ifs.drain() {
        let l = match cfg.listener.take() {
            Some(l) => l,
            None => {return Err(Box::new(IoError::new(ErrorKind::Other, "could not listen")));}
        };
        let server = match PlainIncoming::from_std(l) {
            Ok(incomming) => {
                info!("Bound to {}", &addr);
                let hcfg = Arc::new(cfg);
                let make_service = make_service_fn(move |socket: &PlainStream| {
                    let remote_addr = socket.peer_addr().unwrap_or("127.0.0.1:8080".parse().unwrap());
                    trace!("Connected on {}", &addr);
                    let hcfg = hcfg.clone();
                    async move {
                        Ok::<_, hyper::Error>(service_fn(move |req: Request<Body>| dispatch::handle_request(req, hcfg.clone(), remote_addr) ))
                    }
                });
                hyper::Server::builder(incomming).serve(make_service)
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
    let logging_handle = logging::init_stderr_logging();

    match config::load_config() {
        Err(e) => {
            error!("Configuration error!\r\n{}", e);
        },
        Ok(mut cfg) => {
            //group config by SocketAddrs
            let listening_ifs = match config::group_config(&mut cfg).await {
                Err(e) => {error!("{}", e);return;},
                Ok(m) => m
            };
            // Switch user+group
            if let Some(group) = cfg.group {
                if let Err(e) = user::switch_group(&group) {
                    error!("Could not switch Group: {}", e);
                    return;
                }
            }
            if let Some(user) = cfg.user {
                if let Err(e) = user::switch_user(&user) {
                    error!("Could not switch User: {}", e);
                    return;
                }
            }
            //switch logging to value from config
            if let Some(logconf) = cfg.log.take() {
                logging::init_file(logconf, &logging_handle);
            }
            debug!("{:#?}",listening_ifs);
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
