/*!

Config allows multiple vHosts on one IP. As well as different IPs.
Incomming Requests are thus filtered by IP, then vHost, then URL.

*/

use config::HostCfg;
use futures_util::future::join_all;
use hyper::service::service_fn;
use hyper::Version;
use hyper::{body::Incoming, Request};
use hyper_util::rt::{TokioExecutor, TokioIo};
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
            Ok(incoming) => 's: {
                info!("Bound to {}", &addr);
                #[cfg(any(feature = "tlsrust", feature = "tlsnative"))]
                let use_tls = cfg.tls.take();

                let hcfg = Arc::new(cfg);

                #[cfg(any(feature = "tlsrust", feature = "tlsnative"))]
                if let Some(tls_cfg) = use_tls {
                    let a = tls_cfg.get_acceptor(incoming);
                    break 's tokio::spawn(async move {
                        loop {
                            let (stream, remote_addr) = match a.accept().await {
                                Ok(s) => s,
                                Err(e) => {
                                    #[cfg(feature = "tlsrust_acme")]
                                    if e.get_ref()
                                        .and_then(|b| {
                                            b.downcast_ref::<transport::tls::ACMEdone>().map(|_| ())
                                        })
                                        .is_some()
                                    {
                                        //this was an ACME challenge. Don't print an error
                                        continue;
                                    }
                                    error!("{:?}", e);
                                    continue;
                                }
                            };
                            let hcfg = hcfg.clone();
                            tokio::spawn(async move {
                                trace!("Connected on {} by {}", &addr, &remote_addr);
                                let service = service_fn(move |req: Request<Incoming>| {
                                    //TODO req.extensions_mut().insert(remote_addr);
                                    dispatch::handle_request(req, hcfg.clone(), remote_addr)
                                });
                                if let Err(err) = match stream.proto() {
                                    Version::HTTP_2 => {
                                        hyper::server::conn::http2::Builder::new(
                                            TokioExecutor::new(),
                                        )
                                        .serve_connection(TokioIo::new(stream), service)
                                        .await
                                    }
                                    Version::HTTP_11 => {
                                        hyper::server::conn::http1::Builder::new()
                                            .serve_connection(TokioIo::new(stream), service)
                                            .with_upgrades()
                                            .await
                                    }
                                    _ => unreachable!("neither h1 nor h2"),
                                } {
                                    error!("{} -> {}: {}", remote_addr, addr, err);
                                }
                            });
                        }
                    });
                }
                tokio::spawn(async move {
                    run_http11_server(incoming, addr, hcfg).await?;
                    Ok(())
                })
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

#[inline]
async fn run_http11_server(
    incoming: PlainIncoming,
    addr: SocketAddr,
    hcfg: Arc<HostCfg>,
) -> Result<(), hyper::Error> {
    let builder = hyper::server::conn::http1::Builder::new();
    loop {
        let (stream, remote_addr) = match incoming.accept().await {
            Ok(s) => s,
            Err(e) => {
                error!("{:?}", e);
                continue;
            }
        };
        let hcfg = hcfg.clone();
        let builder = builder.clone();
        tokio::spawn(async move {
            trace!("Connected on {} by {}", &addr, &remote_addr);
            if let Err(err) = builder
                .serve_connection(
                    TokioIo::new(stream),
                    service_fn(move |req: Request<Incoming>| {
                        //TODO req.extensions_mut().insert(remote_addr);
                        dispatch::handle_request(req, hcfg.clone(), remote_addr)
                    }),
                )
                .with_upgrades()
                .await
            {
                error!("{} -> {}: {}", remote_addr, addr, err);
            }
        });
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
        assert_eq!(&buf, b"HTTP/1.1 200 OK");
    }
    #[tokio::test]
    async fn http_connect() {
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
        test.write_all(b"CONNECT host:80 HTTP/1.1\r\n\r\n")
            .await
            .unwrap();
        let mut buf = [0u8; 24];
        test.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"HTTP/1.1 400 Bad Request");
    }
    #[cfg(feature = "tlsrust")]
    async fn create_tls_cfg() -> (tokio_rustls::TlsConnector, transport::tls::ParsedTLSConfig) {
        use crate::dispatch::test::TempFile;
        use rustls_pemfile::{read_one, Item};
        use tokio_rustls::rustls::{ClientConfig, RootCertStore};
        use tokio_rustls::TlsConnector;

        let key_file = TempFile::create("edkey.pem", crate::transport::tls::test::ED_KEY);
        let crt_file = TempFile::create("example.com.pem", crate::transport::tls::test::CERT);

        let u1: transport::tls::TlsUserConfig = toml::from_str(
            format!(
                "host.Files = [{{key = {:?}, cert = {:?}}}]",
                key_file.get_path(),
                crt_file.get_path()
            )
            .as_str(),
        )
        .expect("cfg");
        let cfg = transport::tls::ParsedTLSConfig::new(&u1, None).expect("tls cfg");

        let mut root_cert_store = RootCertStore::empty();
        let mut c = crate::transport::tls::test::CERT;
        let der = match read_one(&mut c) {
            Ok(Some(Item::X509Certificate(der))) => der,
            _ => panic!(),
        };
        root_cert_store.add(der).unwrap();
        let config = ClientConfig::builder()
            .with_root_certificates(root_cert_store)
            .with_no_client_auth();

        let connector = TlsConnector::from(Arc::new(config));
        (connector, cfg)
    }
    #[cfg(any(feature = "tlsrust", feature = "tlsnative"))]
    #[tokio::test]
    async fn https_get() {
        let (l, a) = local_socket_pair().await.unwrap();

        let mut listening_ifs = HashMap::new();
        let mut cfg = HostCfg::new(l.into_std().unwrap());

        let (connector, tlscfg) = create_tls_cfg().await;

        cfg.tls = Some(tlscfg);

        let mut vh = VHost::new(a);
        vh.paths.insert(
            Utf8PathBuf::from("a"),
            UnitTestUseCase::create_wwwroot(Some("b"), Some("a"), None),
        );
        cfg.default_host = Some(vh);
        listening_ifs.insert(a, cfg);

        let _s = prepare_hyper_servers(listening_ifs).await.unwrap();

        let stream = TcpStream::connect(a).await.unwrap();
        #[cfg(feature = "tlsrust")]
        let mut stream = {
            let dnsname =
                tokio_rustls::rustls::pki_types::ServerName::try_from("example.com").unwrap();
            connector.connect(dnsname, stream).await.unwrap()
        };

        stream
            .write_all(b"GET /a/b HTTP/1.1\r\n\r\n")
            .await
            .unwrap();
        let mut buf = [0u8; 15];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf[..15], b"HTTP/1.1 200 OK");
    }
}
