use async_fcgi::client::connection::{HeaderMultilineStrategy, MultiHeaderStrategy};
use log::{error, info};
use serde::Deserialize;
use std::collections::HashMap;
use std::io::{Error as IoError, ErrorKind};
use std::time::Duration;
use tokio::task::yield_now;
use tokio::time::timeout;

use crate::config::{StaticFiles, Utf8PathBuf};

pub use async_fcgi::client::con_pool::ConPool as FCGIAppPool;
pub use async_stream_connection::Addr;

pub async fn setup_fcgi_connection(
    fcgi_cfg: &mut FCGIApp,
) -> Result<(), Box<dyn std::error::Error>> {
    let sock = &fcgi_cfg.sock;

    if let Some(bin) = fcgi_cfg.bin.as_ref() {
        let mut cmd = FCGIAppPool::prep_server(bin.path.as_os_str(), sock).await?;
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
        #[cfg(unix)]
        let delete_after_use = if let Addr::Unix(a) = &sock {
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
            #[cfg(unix)]
            if let Some(path) = delete_after_use {
                info!("cleanup");
                std::fs::remove_file(path).unwrap();
            }
        });
        yield_now().await;
    }
    let mh = match fcgi_cfg.multiple_header {
        None => MultiHeaderStrategy::OnlyFirst,
        Some(MultHeader::Last) => MultiHeaderStrategy::OnlyLast,
        Some(MultHeader::Combine) => MultiHeaderStrategy::Combine,
    };
    let ml = if fcgi_cfg.allow_multiline_header {
        HeaderMultilineStrategy::Ignore
    } else {
        HeaderMultilineStrategy::ReturnError
    };
    let app = match timeout(
        Duration::from_secs(3),
        FCGIAppPool::new_with_strategy(sock, mh, ml),
    )
    .await
    {
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

/// Information to execute a FCGI App
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FCGIAppExec {
    pub path: Utf8PathBuf,
    pub wdir: Option<Utf8PathBuf>,
    pub environment: Option<HashMap<String, String>>,
    pub copy_environment: Option<Vec<String>>,
}
#[derive(Debug, Deserialize)]
pub enum MultHeader {
    Combine,
    Last,
}
/// A FCGI Application
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FCGIApp {
    pub sock: Addr,
    pub exec: Option<Vec<Utf8PathBuf>>,
    #[serde(default)]
    pub set_script_filename: bool,
    #[serde(default)]
    pub set_request_uri: bool,
    #[serde(default)]
    pub allow_multiline_header: bool,
    pub multiple_header: Option<MultHeader>,
    #[serde(default = "default_timeout")]
    pub timeout: u64,
    pub buffer_request: Option<usize>,
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
            sf.setup().await?;
        }
        if let Err(e) = setup_fcgi_connection(&mut self.fcgi).await {
            return Err(format!("{}", e));
        }
        Ok(())
    }
}
