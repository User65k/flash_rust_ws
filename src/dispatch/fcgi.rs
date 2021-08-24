
use std::{net::SocketAddr, io::{Error as IoError, ErrorKind}};
use log::{error, trace, info, debug, log_enabled, Level};
use std::collections::HashMap;
use bytes::{Bytes, BytesMut};
use hyper::{Body, Request, Response};
use std::path::PathBuf;
use std::path::Path;
use tokio::time::timeout;
use tokio::task::yield_now;
use std::time::Duration;
use serde::Deserialize;

use crate::body::FCGIBody;

pub use async_fcgi::client::con_pool::ConPool as FCGIAppPool;
pub use async_fcgi::FCGIAddr;


pub async fn fcgi_call(fcgi_cfg: &FCGIApp, req: Request<Body>, full_path: &Path, remote_addr: SocketAddr)
            -> Result<Response<Body>, IoError> {
    if let Some(app) = &fcgi_cfg.app {

        let mut params = HashMap::new();
        params.insert( // must CGI/1.1  4.1.13, everybody cares
            Bytes::from(&b"SCRIPT_NAME"[..]),
            path_to_bytes(full_path),
        );
        params.insert( // must CGI/1.1  4.1.14, flup cares for this
            Bytes::from(&b"SERVER_NAME"[..]),
            Bytes::from(&b"FRWS"[..]),
        );
        params.insert( // must CGI/1.1  4.1.15, flup cares for this
            Bytes::from(&b"SERVER_PORT"[..]),
            Bytes::from(&b"80"[..]),
        );
        params.insert(  // must CGI/1.1  4.1.16, flup cares for this
            Bytes::from(&b"SERVER_PROTOCOL"[..]),
            Bytes::from(&b"HTTP"[..]),
        );
        params.insert(  // must CGI/1.1  4.1.8
            Bytes::from(&b"REMOTE_ADDR"[..]),
            Bytes::from(remote_addr.to_string()),
        );
        // - SERVER_SOFTWARE   must CGI/1.1  4.1.17
        // - GATEWAY_INTERFACE must CGI/1.1  4.1.4

        if Some(true) == fcgi_cfg.script_filename {
            params.insert( // PHP cares for this
                Bytes::from(&b"SCRIPT_FILENAME"[..]),
                path_to_bytes(full_path),
            );
        }
        trace!("to FCGI: {:?}", &params);
        match timeout(Duration::from_secs(3), app.forward(req, params)).await {
            Err(_) => Err(IoError::new(ErrorKind::TimedOut,"FCGI app did not respond")),
            Ok(val) => {
                if log_enabled!(Level::Debug) {
                    match &val {
                        Ok(resp) => debug!("FCGI response: {:?} {:?}", resp.status(), resp.headers()),
                        Err(err) => debug!("FCGI response: {:?}", err),
                    }
                }
                Ok(val?.map(|bod|Body::wrap_stream(FCGIBody::from(bod))))
            }
        }
        //Ok(app.forward(req, params).await?.map(|bod|Body::wrap_stream(FCGIBody::from(bod))))
    }else{
        error!("FCGI app not set");
        Err(IoError::new(ErrorKind::NotConnected,"FCGI app not available"))
    }
}
#[cfg(unix)]
fn path_to_bytes<P: AsRef<Path>>(path: P) -> Bytes {
    use std::os::unix::ffi::OsStrExt;
    BytesMut::from(path.as_ref().as_os_str().as_bytes()).freeze()
}

#[cfg(not(unix))]
fn path_to_bytes<P: AsRef<Path>>(path: P) -> Bytes {
    // On Windows, could use std::os::windows::ffi::OsStrExt to encode_wide(),
    // but end up with u16
    BytesMut::from(path.as_ref().to_string_lossy().to_string().as_bytes()).freeze()
}

pub async fn setup_fcgi(fcgi_cfg: &mut FCGIApp, staticf: &Option<crate::config::StaticFiles>) -> Result<(), Box<dyn std::error::Error>> {

    if fcgi_cfg.exec.is_some() && staticf.is_none() {
        //need a dir to check files
        return Err(Box::new(IoError::new(ErrorKind::Other,"dir must be specified, if exec filter is used")));
    }
    if fcgi_cfg.exec.is_none() && staticf.is_some() {
        //warn that dir will not be used
        return Err(Box::new(IoError::new(ErrorKind::Other,"reqests will always go to FCGI app. File checks will not be used - remove them")));
    }

    let sock: FCGIAddr = (&fcgi_cfg.sock).into();

    if let Some(bin) = fcgi_cfg.bin.as_ref() {
        let mut cmd = FCGIAppPool::prep_server(&bin.path, &sock).await?;
        cmd.env_clear();
        if let Some(dir) = bin.wdir.as_ref() {
            cmd.current_dir(dir);
        }
        //gid ?
        //uid ?
        if let Some(env_map) = bin.environment.as_ref() {
            cmd.envs(env_map);
        }
        if let Some(env_copy) = bin.copy_environment.as_ref() {
            cmd.envs(env_copy.iter().filter_map(|key|std::env::var_os(key).map(|val|(key, val))));
        }
        let mut running_cmd = cmd
                            .kill_on_drop(true)
                            .spawn()?;
        info!("Started {:?} @ {}", &bin.path, &sock);
        let delete_after_use = 
        if let FCGIAddr::Unix(a) = &sock {
            Some(a.to_path_buf())
        }else{
            None
        };
        tokio::spawn(async move {
            tokio::select! {
                ret = running_cmd.wait() => {
                    match ret {
                        Ok(status) => error!("FCGI app exit: {}", status),
                        Err(e) => error!("FCGI app: {}", e),
                    }
                },
                _ = tokio::signal::ctrl_c() => {info!("killing");running_cmd.kill().await.expect("kill failed");}
            }
            
            if let Some(path) = delete_after_use {
                info!("cleanup");
                std::fs::remove_file(path).unwrap();
            }
        });
        yield_now().await;
    }
    let app =     
    match timeout(Duration::from_secs(3),FCGIAppPool::new(&sock)).await {
        Err(_) => return Err(Box::new(IoError::new(ErrorKind::TimedOut,"timeout during connect"))),
        Ok(res) => res?
    };

    info!("FCGI App ready @ {}", &sock);
    fcgi_cfg.app = Some(app);

    Ok(())
}

impl From<&FCGISock> for FCGIAddr {
    fn from(addr: &FCGISock) -> FCGIAddr {
        match addr {
            FCGISock::TCP(s) => FCGIAddr::Inet(*s),
            FCGISock::Unix(p) => FCGIAddr::Unix(p.to_path_buf()),
        }
    }
}

#[derive(Debug)]
#[derive(Deserialize)]
#[serde(untagged)]
pub enum FCGISock {
    TCP(SocketAddr),
    Unix(PathBuf),
}

/// Information to execute a FCGI App
#[derive(Debug)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FCGIAppExec {
    pub path: PathBuf,
    pub wdir: Option<PathBuf>,
    pub environment: Option<HashMap<String, String>>,
    pub copy_environment: Option<Vec<String>>,
}

/// A FCGI Application
#[derive(Debug)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FCGIApp {
    pub sock: FCGISock,
    pub exec: Option<Vec<PathBuf>>,
    pub script_filename: Option<bool>,
    pub bin: Option<FCGIAppExec>,
    #[serde(skip)]
    pub app: Option<FCGIAppPool>
}
