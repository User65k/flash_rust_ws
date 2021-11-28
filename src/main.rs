/*!

Config allows multiple vHosts on one IP. As well as different IPs.
Incomming Requests are thus filtered by IP, then vHost, then URL.

*/

use futures_util::future::{join_all, select};
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Request};
use log::{debug, error, info, trace};
use std::collections::HashMap;
use std::error::Error;
use std::io::{Error as IoError, ErrorKind};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::signal;
use tokio::task::JoinHandle;

mod auth;
mod body;
mod config;
mod dispatch;
mod logging;
mod pidfile;
mod transport;
mod user;

#[cfg(any(feature = "tlsrust", feature = "tlsnative"))]
use crate::transport::tls::{TLSBuilderTrait, TlsStream};
use transport::{PlainIncoming, PlainStream};

/// Set up each `SocketAddr` and return the `JoinHandle`s
///
/// Walk trought `listening_ifs` and create a `PlainIncoming` (TCP Listener) for each `SocketAddr`.
/// If its config has TLS wrap the `PlainIncoming` into an `TlsAcceptor`
async fn prepare_hyper_servers(
    mut listening_ifs: HashMap<SocketAddr, config::HostCfg>,
) -> Result<Vec<JoinHandle<Result<(), hyper::Error>>>, Box<dyn Error>> {
    let mut handles = vec![];
    for (addr, mut cfg) in listening_ifs.drain() {
        let l = match cfg.listener.take() {
            Some(l) => l,
            None => {
                return Err(Box::new(IoError::new(ErrorKind::Other, "could not listen")));
            }
        };
        let server = match PlainIncoming::from_std(l) {
            Ok(incoming) => {
                info!("Bound to {}", &addr);
                #[cfg(any(feature = "tlsrust", feature = "tlsnative"))]
                let use_tls = cfg.tls.take();

                let hcfg = Arc::new(cfg);
                let serv_func = move |remote_addr: SocketAddr| {
                    trace!("Connected on {} by {}", &addr, &remote_addr);
                    let hcfg = hcfg.clone();
                    async move {
                        Ok::<_, hyper::Error>(service_fn(move |req: Request<Body>| {
                            dispatch::handle_request(req, hcfg.clone(), remote_addr)
                        }))
                    }
                };

                #[cfg(any(feature = "tlsrust", feature = "tlsnative"))]
                if let Some(tls_cfg) = use_tls {
                    let a = tls_cfg.get_acceptor(incoming);
                    let new_service = make_service_fn(move |socket: &TlsStream| {
                        let remote_addr = socket.remote_addr();
                        serv_func(remote_addr)
                    });
                    tokio::spawn(hyper::Server::builder(a).executor(Exec).serve(new_service))
                } else {
                    let new_service = make_service_fn(move |socket: &PlainStream| {
                        let remote_addr = socket.remote_addr();
                        serv_func(remote_addr)
                    });
                    tokio::spawn(
                        hyper::Server::builder(incoming)
                            .executor(Exec)
                            .serve(new_service),
                    )
                }
                #[cfg(not(any(feature = "tlsrust", feature = "tlsnative")))]
                {
                    let new_service = make_service_fn(move |socket: &PlainStream| {
                        let remote_addr = socket.remote_addr();
                        serv_func(remote_addr)
                    });
                    tokio::spawn(
                        hyper::Server::builder(incoming)
                            .executor(Exec)
                            .serve(new_service),
                    )
                }
            }
            Err(err) => {
                error!("{}: {}", addr, err);
                return Err(Box::new(err));
            }
        };
        handles.push(server);
    }
    Ok(handles)
}

#[derive(Clone, Copy, Debug)]
struct Exec;

impl<F> hyper::rt::Executor<F> for Exec
where
    F: std::future::Future + Send + 'static,
    F::Output: Send,
{
    fn execute(&self, task: F) {
        tokio::spawn(task);
    }
}

#[tokio::main]
async fn main() {
    let logging_handle = logging::init_stderr_logging();

    match config::load_config() {
        Err(e) => {
            error!("Configuration error!\r\n{}", e);
        }
        Ok(mut cfg) => {
            //group config by SocketAddrs
            let listening_ifs = match config::group_config(&mut cfg).await {
                Err(e) => {
                    error!("Configuration error!\r\n{}", e);
                    return;
                }
                Ok(m) => m,
            };
            //Write pid file
            if let Some(pidfile) = cfg.pidfile {
                if let Err(e) = pidfile::create_pid_file(pidfile) {
                    error!("Could not write Pid File: {}", e);
                    eprintln!("Error! See Logs");
                    return;
                }
            }
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
            debug!("{:#?}", listening_ifs);
            //setup all servers
            match prepare_hyper_servers(listening_ifs).await {
                Ok(handles) => {
                    info!("serving");
                    let all_server = join_all(handles);
                    tokio::select! {
                        ret = all_server => {
                            //print the error if hyper returned one
                            for r in ret {
                                if let Err(e) = r {
                                    error!("{}", e);
                                }
                            }
                        },
                        _ = signal::ctrl_c() => {
                            info!("ctrl+c received");
                            //TODO wait until all cleanups are done
                        }
                    }
                }
                Err(e) => {
                    error!("{}", e);
                    eprintln!("Error! See Logs");
                }
            }
        }
    };
}
