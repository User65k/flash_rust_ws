use std::collections::HashMap;
use serde::Deserialize;
use std::net::{SocketAddr, TcpListener};
use log::info;
use std::path::PathBuf;
use std::io::Read;
use std::fs::File;
use std::error::Error;
use std::io::{Error as IOError, ErrorKind};
use std::fmt;
use async_fcgi::client::con_pool::ConPool as FCGIAppPool;
use async_fcgi::FCGIAddr;
use hyper::header::HeaderMap;
use log4rs::file::RawConfig as LogConfig;
#[cfg(any(feature = "tlsrust",feature = "tlsnative"))]
use crate::transport::tls::{TLSConfig, TlsUserConfig, get_config};


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

/// A FCGI Application
#[derive(Debug)]
#[derive(Deserialize)]
pub struct FCGIApp {
    pub sock: FCGISock,
    pub exec: Option<Vec<PathBuf>>,
    pub script_filename: Option<bool>,
    #[serde(skip)]
    pub app: Option<FCGIAppPool>
}


/// A single directory
#[derive(Debug)]
#[derive(Deserialize)]
pub struct WwwRoot {
    pub dir: PathBuf,
    pub index: Option<Vec<PathBuf>>,
    pub serve: Option<Vec<PathBuf>>,
    pub fcgi: Option<FCGIApp>,
    pub header: Option<HashMap<String, String>>,
}

/// vHost specific configuration
#[derive(Debug)]
#[derive(Deserialize)]
pub struct VHost {
    pub ip: SocketAddr,
    #[cfg(any(feature = "tlsrust",feature = "tlsnative"))]
    pub tls: Option<TlsUserConfig>,
    pub validate_server_name: Option<bool>,
    #[serde(flatten)]
    root: Option<WwwRoot>, //only in toml -> will be added to paths
    #[serde(flatten)]
    pub paths: HashMap<PathBuf, WwwRoot>,
}

/// Gernal configuration
#[derive(Debug)]
#[derive(Deserialize)]
pub struct Configuration {
    pub logfile: Option<PathBuf>,
    pub pidfile: Option<PathBuf>,
    pub user: Option<String>,
    pub group: Option<String>,
    pub log: Option<LogConfig>,

    #[serde(flatten)]
    pub hosts: HashMap<String, VHost>,
}

#[derive(Debug)]
struct CFGError {
    errors: Vec<String>
}
impl CFGError {
    fn new() -> CFGError {
        CFGError{
            errors: Vec::new()
        }
    }
    fn add(&mut self, s: String) {
        self.errors.push(s);
    }
    fn has_errors(&self) -> bool {
        self.errors.len() > 0
    }
}
impl fmt::Display for CFGError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for err in self.errors.iter() {
            write!(f, "{}\r\n", err)?;
        }
        Ok(())
    }
}
impl Error for CFGError {

}

/// load and verify configuration options
pub fn load_config() -> Result<Configuration, Box<dyn Error>> {
    let mut path = None;
    for cfg_path in ["./config.toml", "/etc/defaults/config.toml"].iter() {
        let p: PathBuf = cfg_path.into();
        if p.is_file() {
            path = Some(p);
            break;
        }
    }
    if path.is_none() {
        return Err(Box::new(IOError::new(ErrorKind::NotFound, "No config file found!")));
    }
    let mut f = File::open(path.unwrap())?;
    let mut buffer = Vec::new();

    // read the whole file
    f.read_to_end(&mut buffer)?;

    let mut cfg = toml::from_slice::<Configuration>(&buffer)?;
    let mut errors = CFGError::new();
    for (host_name, vhost) in cfg.hosts.iter_mut() {
        info!("host: {} @ {}", host_name, vhost.ip );
        if let Some(r) = vhost.root.take() {
            vhost.paths.insert(PathBuf::new(), r);
        }
        for (k, v) in vhost.paths.iter() {
            if !v.dir.is_dir() {
                errors.add(format!("{:?} (in {}/{:?}) ist not a directory", v.dir, host_name, k));
            }
            info!("\t {:?} => {:?}", k, v.dir );
        }
        if vhost.paths.len()==0 {
            errors.add(format!("vHost '{}' does not serve anything", host_name));
        }
    }
    if errors.has_errors() {
        Err(Box::new(errors))
    }else{
        Ok(cfg)
    }
}

pub struct HostCfg {
    pub default_host: Option<VHost>,
    pub vhosts: HashMap<String, VHost>,
    pub listener: Option<TcpListener>,
    #[cfg(any(feature = "tlsrust",feature = "tlsnative"))]
    pub has_tls: Option<TLSConfig>,
}
impl HostCfg{
    fn new(listener: TcpListener) -> HostCfg {
        HostCfg {
            default_host: None,
            vhosts: HashMap::new(),
            listener: Some(listener),
            #[cfg(any(feature = "tlsrust",feature = "tlsnative"))]
            has_tls: None,
        }
    }
}
impl fmt::Debug for HostCfg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HostCfg")
        .field("default_host", &self.default_host)
        .field("vhosts", &self.vhosts)
        .finish()
    }
}

pub async fn group_config(cfg: &mut Configuration) -> Result<HashMap<SocketAddr, HostCfg>, Box<dyn Error>> {
    let mut listening_ifs = HashMap::new();
    let mut errors = CFGError::new();
    for (vhost, mut params) in cfg.hosts.drain() {
        let addr = params.ip;
        for (mount, wwwroot) in params.paths.iter_mut() {
            //setup FCGI Apps
            wwwroot.fcgi = if let Some(mut fcgi_cfg) = wwwroot.fcgi.take() {
                match FCGIAppPool::new(&(&fcgi_cfg.sock).into()).await {
                    Ok(app) => fcgi_cfg.app = Some(app),
                    Err(e) => {
                        errors.add(format!("FCGIApp @{:?}: {}", mount, e));
                    }
                }
                Some(fcgi_cfg)
            }else{
                None
            };
            //check if header are parseable
            if wwwroot.header.is_none() {continue;}
            let mut _h = HeaderMap::new();
            if let Err(e) = crate::dispatch::insert_default_headers(&mut _h, &wwwroot.header) {
                errors.add(format!("{:?}: {}", mount, e));
            }
        }
        //group vHosts by IP
        match listening_ifs.get_mut(&addr) {
            None => {
                let mut hcfg = HostCfg::new(TcpListener::bind(addr)?);
                #[cfg(any(feature = "tlsrust",feature = "tlsnative"))]
                if let Some(tlscfg) = params.tls.take() {
                    match get_config(&tlscfg) {
                        Ok(tls) => hcfg.has_tls = Some(tls),
                        Err(e) => errors.add(format!("vHosts {}:  {}", vhost, e)),
                    }
                }
                if Some(true) == params.validate_server_name {
                    hcfg.vhosts.insert(vhost, params);
                }else{
                    hcfg.default_host = Some(params);
                }
                listening_ifs.insert(addr, hcfg);
            },
            Some(mut hcfg) => {
                #[cfg(any(feature = "tlsrust",feature = "tlsnative"))]
                if params.tls.is_some() != hcfg.has_tls.is_some() {
                    errors.add(format!("All vHosts on {} must be either TLS or not", addr));
                }
                if Some(true) == params.validate_server_name {
                    hcfg.vhosts.insert(vhost, params);
                }else{
                    if hcfg.default_host.is_none() {
                        hcfg.default_host = Some(params);
                    }else{
                        errors.add(format!("{} is the second host on {} that does not validate the server name", vhost, addr));
                    }
                }
            }
        }
    }
    if errors.has_errors() {
        Err(Box::new(errors))
    }else{
        Ok(listening_ifs)
    }
}

#[test]
fn config_file(){
    use std::fs::File;
    use std::io::prelude::*;
    let mut file = File::create("./config.toml").expect("could not create cfg file");
    file.write_all(b"[host]\nip = \"0.0.0.0:1337\"\ndir=\".\"").expect("could not write cfg file");
    assert!(load_config().is_ok());

    file.write_all(b"\n[host2]\nip = \"0.0.0.0:8080\"").expect("could not write cfg file");
    assert!(load_config().is_err()); // does not serve anything


    file.write_all(b"\ndir=\"\\nonexistend\"").expect("could not write cfg file");
    assert!(load_config().is_err()); // folder non existent
}
#[test]
fn toml_to_struct() {
    let _cfg: Configuration = toml::from_str(r#"
pidfile = 'bar'

your.ip = "[::1]:1234" # hah
your.dir = "~"
[host]
ip = "0.0.0.0:1337"
[host.path]
dir = "/var/www/"
index = ["index.html", "index.htm"]
"#).expect("parse err");
    //print(&cfg);
}

#[tokio::test]
async fn vhost_conflict() {
    let mut cfg: Configuration = toml::from_str(r#"
[host]
ip = "0.0.0.0:1337"
[another]
ip = "0.0.0.0:1337"
"#).expect("parse err");
    assert!(group_config(&mut cfg).await.is_err());
}
#[tokio::test]
async fn bad_header() {
    let mut cfg: Configuration = toml::from_str(r#"
[host]
ip = "0.0.0.0:1338"
[host."/"]
dir = ""
header = {test = "bad\u0000header"}
"#).expect("parse err");
    assert!(group_config(&mut cfg).await.is_err());
    let mut cfg: Configuration = toml::from_str(r#"
[host]
ip = "0.0.0.0:1339"
[host."/"]
dir = ""
header = {"test\n" = "1"}
"#).expect("parse err");
    assert!(group_config(&mut cfg).await.is_err());
}

#[tokio::test]
async fn cant_listen() {
    let mut cfg: Configuration = toml::from_str(r#"
[host]
ip = "8.8.8.8:22"
"#).expect("parse err");
    assert!(group_config(&mut cfg).await.is_err());
}

#[cfg(feature = "tlsrust")]
#[tokio::test]
async fn tls_plain_mix() {
    let mut cfg: Configuration = toml::from_str(r#"
[host]
ip = "8.8.8.8:22"
tls.cert_file = ""
tls.key_file = ""
[host2]
ip = "8.8.8.8:22"
"#).expect("parse err");
    assert!(group_config(&mut cfg).await.is_err());
}