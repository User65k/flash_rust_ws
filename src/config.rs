use std::collections::HashMap;
use serde::Deserialize;
use std::net::SocketAddr;
use log::info;
use std::path::PathBuf;
use std::io::Read;
use std::fs::File;
use std::error::Error;
use std::io::{Error as IOError, ErrorKind};
use std::fmt;
use async_fcgi::client::con_pool::ConPool as FCGIAppPool;
use async_fcgi::FCGIAddr;


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
    pub exec: Option<Vec<String>>,
    pub serve: Option<Vec<String>>,
    #[serde(skip)]
    pub app: Option<FCGIAppPool>
}


/// A single directory
#[derive(Debug)]
#[derive(Deserialize)]
pub struct WwwRoot {
    pub dir: PathBuf,
    pub index: Option<Vec<String>>,
    pub fcgi: Option<FCGIApp>
}

/// vHost specific configuration
#[derive(Debug)]
#[derive(Deserialize)]
pub struct VHost {
    pub ip: SocketAddr,
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

#[test]
fn config_file(){
    extern crate pretty_env_logger;
    pretty_env_logger::init();
    load_config().expect("configuration error");
}
#[test]
fn toml_to_struct() {
    let _cfg: Configuration = toml::from_str(r#"
pidfile = 'bar'

your.ip = "[::1]:1234" # hah
your.dir = "~"
[host]
ip = "0.0.0.0:1337"
port = 3
[host.path]
dir = "/var/www/"
index = ["index.html", "index.htm"]
"#).expect("parse err");
    //print(&cfg);
}