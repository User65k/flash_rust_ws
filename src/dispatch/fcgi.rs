use bytes::{Bytes, BytesMut};
use hyper::{body::HttpBody, Body, Request, Response};
use log::{debug, error, info, trace};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;
use std::path::PathBuf;
use std::time::Duration;
use std::{
    io::{Error as IoError, ErrorKind},
    net::SocketAddr,
};
use tokio::task::yield_now;
use tokio::time::timeout;

use crate::{body::FCGIBody, config::StaticFiles};

pub use async_fcgi::client::con_pool::ConPool as FCGIAppPool;
pub use async_fcgi::FCGIAddr;

const SCRIPT_NAME: &[u8] = b"SCRIPT_NAME";
const PATH_INFO: &[u8] = b"PATH_INFO";
const SERVER_NAME: &[u8] = b"SERVER_NAME";
const SERVER_PORT: &[u8] = b"SERVER_PORT";
const SERVER_PROTOCOL: &[u8] = b"SERVER_PROTOCOL";
const REMOTE_ADDR: &[u8] = b"REMOTE_ADDR";
const GATEWAY_INTERFACE: &[u8] = b"GATEWAY_INTERFACE";
const CGI_VERS: &[u8] = b"CGI/1.1";
const SERVER_SOFTWARE: &[u8] = b"SERVER_SOFTWARE";
const REQUEST_URI: &[u8] = b"REQUEST_URI";
const SCRIPT_FILENAME: &[u8] = b"SCRIPT_FILENAME";

pub async fn fcgi_call(
    fcgi_cfg: &FCGIApp,
    req: Request<Body>,
    req_path: &Path,
    web_mount: &Path,
    fs_root: Option<&Path>,
    remote_addr: SocketAddr,
) -> Result<Response<Body>, IoError> {
    let app = if let Some(app) = &fcgi_cfg.app {
        app
    } else {
        error!("FCGI app not set");
        return Err(IoError::new(
            ErrorKind::NotConnected,
            "FCGI app not available",
        ));
    };

    match *req.method() {
        hyper::http::Method::GET
        | hyper::http::Method::HEAD
        | hyper::http::Method::OPTIONS
        | hyper::http::Method::DELETE
        | hyper::http::Method::TRACE => {}
        _ => {
            if req.body().size_hint().exact().is_none() {
                return Ok(Response::builder()
                    .status(hyper::StatusCode::LENGTH_REQUIRED)
                    .body(Body::empty())
                    .expect("unable to build response"));
            }
        }
    }

    let mut params = HashMap::new();
    if let Some(root_dir) = fs_root {
        //req_path is completely resolved (to get index files)
        if let Ok(rel) = req_path.strip_prefix(root_dir) {
            let mut abs_name = PathBuf::from("/");
            abs_name.push(web_mount);
            abs_name.push(rel);
            params.insert(
                // must CGI/1.1  4.1.13, everybody cares
                Bytes::from(SCRIPT_NAME),
                path_to_bytes(abs_name),
            );
        } else {
            return Err(IoError::new(
                ErrorKind::PermissionDenied,
                "FCGI script not within root dir",
            ));
        }
        // - PATH_INFO derived from the portion of the URI path hierarchy following the part that identifies the script itself.
        // -> not a thing, as we check if the file exists
    } else {
        //no local FS
        //the wohle mount is a single FCGI App...
        let mut abs_web_mount = PathBuf::from("/");
        abs_web_mount.push(web_mount);
        params.insert(
            // must CGI/1.1  4.1.13, everybody cares
            Bytes::from(SCRIPT_NAME),
            path_to_bytes(abs_web_mount),
        );
        //... so everything inside it is PATH_INFO
        let mut abs_path = PathBuf::new();
        abs_path.push("/");
        abs_path.push(req_path);
        params.insert(
            // opt CGI/1.1   4.1.5
            Bytes::from(PATH_INFO),
            path_to_bytes(abs_path),
        );
        //this matches what lighttpd does without check_local
    }

    params.insert(
        // must CGI/1.1  4.1.14, flup cares for this
        Bytes::from(SERVER_NAME),
        Bytes::from(super::get_host(&req).unwrap_or_default().to_string()),
    );
    params.insert(
        // must CGI/1.1  4.1.15, flup cares for this
        Bytes::from(SERVER_PORT),
        Bytes::from(
            req.uri()
                .port()
                .map(|p| p.to_string())
                .unwrap_or_else(|| "80".to_string()),
        ),
    );
    params.insert(
        // must CGI/1.1  4.1.16, flup cares for this
        Bytes::from(SERVER_PROTOCOL),
        Bytes::from(format!("{:?}", req.version())),
    );
    params.insert(
        // must CGI/1.1  4.1.8
        Bytes::from(REMOTE_ADDR),
        Bytes::from(remote_addr.ip().to_string()),
    );
    params.insert(
        // must CGI/1.1  4.1.4
        Bytes::from(GATEWAY_INTERFACE),
        Bytes::from(CGI_VERS),
    );
    params.insert(
        // must CGI/1.1  4.1.17
        Bytes::from(SERVER_SOFTWARE),
        Bytes::from(&b"frws"[..]),
    );
    if fcgi_cfg.set_request_uri {
        params.insert(
            // REQUEST_URI common
            Bytes::from(REQUEST_URI),
            Bytes::from(req.uri().path().to_string()),
        );
    }
    if fcgi_cfg.set_script_filename {
        params.insert(
            // PHP cares for this
            Bytes::from(SCRIPT_FILENAME),
            path_to_bytes(req_path),
        );
    }
    if let Some(kvp) = &fcgi_cfg.params {
        params.extend(
            kvp.iter()
                .map(|(k, v)| (Bytes::from(k.to_string()), Bytes::from(v.to_string()))),
        );
    }
    trace!("to FCGI: {:?}", &params);
    let resp = match fcgi_cfg.timeout {
        0 => app.forward(req, params).await,
        secs => match timeout(Duration::from_secs(secs), app.forward(req, params)).await {
            Err(_) => {
                return Err(IoError::new(
                    ErrorKind::TimedOut,
                    "FCGI app did not respond",
                ))
            }
            Ok(resp) => resp,
        },
    }?;
    debug!("FCGI response: {:?} {:?}", resp.status(), resp.headers());
    //return types:
    //doc: MUST return a Content-Type header
    //TODO fetch local resource: Location header, MUST NOT return any other header fields or a message-body
    //TODO 302Found: Abs Location header, MUST NOT return any other header fields

    Ok(resp.map(|bod| Body::wrap_stream(FCGIBody::from(bod))))
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

pub async fn setup_fcgi_connection(
    fcgi_cfg: &mut FCGIApp,
) -> Result<(), Box<dyn std::error::Error>> {
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
            cmd.envs(
                env_copy
                    .iter()
                    .filter_map(|key| std::env::var_os(key).map(|val| (key, val))),
            );
        }
        let mut running_cmd = cmd.kill_on_drop(true).spawn()?;
        info!("Started {:?} @ {}", &bin.path, &sock);
        let delete_after_use = if let FCGIAddr::Unix(a) = &sock {
            Some(a.to_path_buf())
        } else {
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
    let app = match timeout(Duration::from_secs(3), FCGIAppPool::new(&sock)).await {
        Err(_) => {
            return Err(Box::new(IoError::new(
                ErrorKind::TimedOut,
                "timeout during connect",
            )))
        }
        Ok(res) => res?,
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

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum FCGISock {
    TCP(SocketAddr),
    Unix(PathBuf),
}

/// Information to execute a FCGI App
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FCGIAppExec {
    pub path: PathBuf,
    pub wdir: Option<PathBuf>,
    pub environment: Option<HashMap<String, String>>,
    pub copy_environment: Option<Vec<String>>,
}

/// A FCGI Application
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FCGIApp {
    pub sock: FCGISock,
    pub exec: Option<Vec<PathBuf>>,
    #[serde(default)]
    pub set_script_filename: bool,
    #[serde(default)]
    pub set_request_uri: bool,
    #[serde(default = "default_timeout")]
    pub timeout: u64,
    pub params: Option<HashMap<String, String>>,
    pub bin: Option<FCGIAppExec>,
    #[serde(skip)]
    pub app: Option<FCGIAppPool>,
}
fn default_timeout() -> u64 {
    20
}

#[cfg(feature = "fcgi")]
#[derive(Debug, Deserialize)]
pub struct FcgiMnt {
    pub fcgi: FCGIApp,
    #[serde(flatten)]
    pub static_files: Option<StaticFiles>,
}
impl FcgiMnt {
    pub async fn setup(&mut self) -> Result<(), String> {
        if self.fcgi.exec.is_some() && self.static_files.is_none() {
            //need a dir to check files
            return Err("dir must be specified, if exec filter is used".to_string());
        }
        if self.fcgi.exec.is_none() && self.static_files.is_some() {
            //warn that dir will not be used
            return Err(
                "reqests will always go to FCGI app. File checks will not be used - remove them"
                    .to_string(),
            );
        }
        if let Some(sf) = &self.static_files {
            let _ = sf.setup().await?;
        }
        if let Err(e) = setup_fcgi_connection(&mut self.fcgi).await {
            return Err(format!("{}", e));
        }
        Ok(())
    }
}
