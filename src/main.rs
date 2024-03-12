/*!

Config allows multiple vHosts on one IP. As well as different IPs.
Incomming Requests are thus filtered by IP, then vHost, then URL.

*/

use futures_util::future::join_all;
use hyper::service::service_fn;
use hyper::{body::Incoming, Request};
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto,
};
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
use crate::transport::tls::TLSBuilderTrait;
use crate::transport::Connection;
use transport::PlainIncoming;

/// Set up each `SocketAddr` and return the `JoinHandle`s
///
/// Walk trought `listening_ifs` and create a `PlainIncoming` (TCP Listener) for each `SocketAddr`.
/// If its config has TLS wrap the `PlainIncoming` into an `TlsAcceptor`
async fn prepare_hyper_servers(
    mut listening_ifs: HashMap<SocketAddr, config::HostCfg>,
) -> Result<Vec<JoinHandle<Result<(), Box<dyn Error + Send + Sync>>>>, Box<dyn Error>> {
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

                #[cfg(any(feature = "tlsrust", feature = "tlsnative"))]
                if let Some(tls_cfg) = use_tls {
                    let a = tls_cfg.get_acceptor(incoming);
                    tokio::spawn(async move {
                        while let Ok(stream) = a.accept().await {
                            let remote_addr = stream.remote_addr();
                            trace!("Connected on {} by {}", &addr, &remote_addr);
                            let hcfg = hcfg.clone();
                            if let Err(e) = auto::Builder::new(TokioExecutor::new())
                                .serve_connection_with_upgrades(
                                    TokioIo::new(stream),
                                    service_fn(move |req: Request<Incoming>| {
                                        //TODO req.extensions_mut().insert(remote_addr);
                                        dispatch::handle_request(req, hcfg.clone(), remote_addr)
                                    }),
                                )
                                .await
                            {
                                return Err(e);
                            }
                        }
                        Ok(())
                    })
                } else {
                    tokio::spawn(async move {
                        while let Ok(stream) = incoming.accept().await {
                            let remote_addr = stream.remote_addr();
                            trace!("Connected on {} by {}", &addr, &remote_addr);
                            let hcfg = hcfg.clone();
                            if let Err(e) = auto::Builder::new(TokioExecutor::new())
                                .serve_connection_with_upgrades(
                                    TokioIo::new(stream),
                                    service_fn(move |req: Request<Incoming>| {
                                        //TODO req.extensions_mut().insert(remote_addr);
                                        dispatch::handle_request(req, hcfg.clone(), remote_addr)
                                    }),
                                )
                                .await
                            {
                                return Err(e);
                            }
                        }
                        Ok(())
                    })
                }
                #[cfg(not(any(feature = "tlsrust", feature = "tlsnative")))]
                {
                    tokio::spawn(async move {
                        while let Ok(stream) = incoming.accept().await {
                            let remote_addr = stream.remote_addr();
                            trace!("Connected on {} by {}", &addr, &remote_addr);
                            let hcfg = hcfg.clone();
                            if let Err(e) = auto::Builder::new(TokioExecutor::new())
                                .serve_connection_with_upgrades(
                                    TokioIo::new(stream),
                                    service_fn(move |req: Request<Incoming>| {
                                        //TODO req.extensions_mut().insert(remote_addr);
                                        dispatch::handle_request(req, hcfg.clone(), remote_addr)
                                    }),
                                )
                                .await
                            {
                                return Err(e);
                            }
                        }
                        Ok(())
                    })
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

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::config::Utf8PathBuf;
    use crate::dispatch::test::UnitTestUseCase;
    use config::{HostCfg, VHost};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
    };
    pub(crate) async fn local_socket_pair() -> Result<(TcpListener, SocketAddr), std::io::Error> {
        let a: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let app_listener = TcpListener::bind(a).await?;
        let a = app_listener.local_addr()?;
        Ok((app_listener, a))
    }
    #[tokio::test]
    async fn http_get() {
        let (l, a) = local_socket_pair().await.unwrap();

        let mut listening_ifs = HashMap::new();
        let mut cfg = HostCfg::new(l.into_std().unwrap());
        let mut vh = VHost::new(a);
        vh.paths.insert(
            Utf8PathBuf::from("a"),
            UnitTestUseCase::create_wwwroot(Some("b"), Some("a"), None),
        );
        cfg.default_host = Some(vh);
        listening_ifs.insert(a, cfg);

        let _s = prepare_hyper_servers(listening_ifs).await.unwrap();

        let mut test = TcpStream::connect(a).await.unwrap();
        test.write_all(b"GET /a/b HTTP/1.1\r\n\r\n").await.unwrap();
        let mut buf = [0u8; 15];
        test.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf[..15], b"HTTP/1.1 200 OK");

        /*s.get(0).unwrap().abort();
        drop(s);
        let mut vec = Vec::new();
        test.read_to_end(&mut vec).await.unwrap();*/
    }
}
