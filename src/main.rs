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
#[cfg(any(feature = "tlsrust",feature = "tlsnative"))]
use crate::transport::tls::{TlsAcceptor, TlsStream, TLSBuilderTrait};

/// Set everything up and gather all the service handles
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
                #[cfg(any(feature = "tlsrust",feature = "tlsnative"))]
                let use_tls = cfg.tls.take();

                let hcfg = Arc::new(cfg);
                let serv_func = move |remote_addr: SocketAddr| {
                    trace!("Connected on {} by {}", &addr, &remote_addr);
                    let hcfg = hcfg.clone();
                    async move {
                        Ok::<_, hyper::Error>(service_fn(move |req: Request<Body>| dispatch::handle_request(req, hcfg.clone(), remote_addr) ))
                    }
                };
                
                #[cfg(any(feature = "tlsrust",feature = "tlsnative"))]
                if let Some(tls_cfg) = use_tls {
                    let a = TlsAcceptor::new(tls_cfg.get_config(), incomming);
                    let make_service = make_service_fn(move |socket: &TlsStream| {
                        let remote_addr = socket.remote_addr();
                        serv_func(remote_addr)
                    });
                    tokio::spawn(hyper::Server::builder(a).serve(make_service))
                }else{
                    let make_service = make_service_fn(move |socket: &PlainStream| {
                        let remote_addr = socket.remote_addr();
                        serv_func(remote_addr)
                    });
                    tokio::spawn(hyper::Server::builder(incomming).serve(make_service))
                }
                #[cfg(not(any(feature = "tlsrust",feature = "tlsnative")))]
                {
                    let make_service = make_service_fn(move |socket: &PlainStream| {
                        let remote_addr = socket.remote_addr();
                        serv_func(remote_addr)
                    });
                    tokio::spawn(hyper::Server::builder(incomming).serve(make_service))
                }
            },
            Err(err) => {
                error!("{}: {}", addr, err);
                return Err(Box::new(err));
            }
        };
        handles.push(server);
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
                if let Err(e) = logging::init_file(logconf, &logging_handle) {
                    error!("Could not setup logging: {}", e);
                    return;
                }
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
