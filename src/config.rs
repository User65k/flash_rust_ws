use std::collections::{HashMap, BTreeMap};
use serde::Deserialize;
use std::net::{SocketAddr, TcpListener};
use log::info;
use std::path::PathBuf;
use std::io::Read;
use std::fs::File;
use anyhow::{Result, Context};
use std::fmt;
#[cfg(feature = "fcgi")]
use crate::dispatch::fcgi::{FCGIApp, setup_fcgi};
use hyper::header::HeaderMap;
use log4rs::config::RawConfig as LogConfig;
#[cfg(any(feature = "tlsrust",feature = "tlsnative"))]
use crate::transport::tls::{TlsUserConfig, ParsedTLSConfig, TLSBuilderTrait};
use serde::de::{Deserializer, Visitor, MapAccess};
#[cfg(feature = "websocket")]
use crate::dispatch::websocket::Websocket;


#[derive(Debug)]
#[derive(Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
pub enum Authenticatoin {
    Digest{userfile: PathBuf, realm: String}, //TODO check file at startup
    //FCGI{server: FCGIApp}
}

#[derive(Debug)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StaticFiles {
    pub dir: PathBuf,
    #[serde(default)]
    pub follow_symlinks: bool, // = false
    pub index: Option<Vec<PathBuf>>,
    pub serve: Option<Vec<PathBuf>>,
}


#[derive(Debug)]
#[derive(Deserialize)]
#[serde(untagged)]
pub enum UseCase {
    #[cfg(feature = "fcgi")]
    FCGI{fcgi: FCGIApp, #[serde(flatten)] static_files: Option<StaticFiles>},
    StaticFiles(StaticFiles),
    #[cfg(feature = "websocket")]
    Websocket(Websocket),
    //Proxy{host: String, path: String},
}

/// A single directory
#[derive(Debug)]
#[derive(Deserialize)]
pub struct WwwRoot {
    #[serde(flatten)]
    pub mount: UseCase,
    pub header: Option<HashMap<String, String>>,
    pub auth: Option<Authenticatoin>,
}

/// vHost specific configuration
#[derive(Debug)]
#[derive(Deserialize)]
pub struct VHost {
    pub ip: SocketAddr,
    #[cfg(any(feature = "tlsrust",feature = "tlsnative"))]
    pub tls: Option<TlsUserConfig>,
    #[serde(default)]
    pub validate_server_name: bool, // = false
    #[serde(flatten)]
    #[serde(deserialize_with = "gather_mounts")]
    pub paths: BTreeMap<PathBuf, WwwRoot>,
}

#[cfg(test)]
impl VHost {
    pub fn new(ip: SocketAddr) -> VHost {
        VHost {
            ip,
            tls: None,
            validate_server_name: false,
            paths: BTreeMap::new()
        }
    }
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
impl std::error::Error for CFGError {

}

/// load and verify configuration options
pub fn load_config() -> anyhow::Result<Configuration> {
    #[cfg(not(test))]
    let path = {
        let mut path = None;
        for cfg_path in ["./config.toml", "/etc/defaults/frws.toml"].iter() {
            let p: PathBuf = cfg_path.into();
            if p.is_file() {
                path = Some(p);
                break;
            }
        }
        match path {
            Some(p) => p,
            None => return Err(std::io::Error::new(std::io::ErrorKind::NotFound, "No config file found!").into())
        }
    };
    #[cfg(test)]
    let path = "./test_cfg.toml";

    let mut f = File::open(&path).with_context(|| format!("Failed to open config from {:?}", path))?;
    //.metadata()?.len()
    let mut buffer = Vec::new();

    // read the whole file
    f.read_to_end(&mut buffer).with_context(|| format!("Failed to read config from {:?}", path))?;

    let mut cfg = toml::from_slice::<Configuration>(&buffer)?;
    let mut errors = CFGError::new();
    for (host_name, vhost) in cfg.hosts.iter_mut() {
        info!("host: {} @ {}", host_name, vhost.ip );
        for (k, v) in vhost.paths.iter() {
            match &v.mount {
                #[cfg(feature = "fcgi")]
                UseCase::FCGI { static_files, fcgi } => {
                    if let Some(sf) = static_files {
                        if !sf.dir.is_dir() {
                            errors.add(format!("{:?} (in \"{}/{}\") ist not a directory", sf.dir, host_name, k.to_string_lossy()));
                        }
                        info!("\t {:?} => {:?} / {:?}", k, fcgi.sock, sf.dir );
                    }
                },
                UseCase::StaticFiles(sf) => {
                    if !sf.dir.is_dir() {
                        errors.add(format!("{:?} (in \"{}/{}\") ist not a directory", sf.dir, host_name, k.to_string_lossy()));
                    }
                    info!("\t {:?} => {:?}", k, sf.dir );
                },
                #[allow(unreachable_patterns)]
                _ => {}
            }
        }
        if vhost.paths.len()==0 {
            errors.add(format!("vHost \"{}\" does not serve anything", host_name));
        }
    }
    if errors.has_errors() {
        Err(errors.into())
    }else{
        Ok(cfg)
    }
}

pub struct HostCfg {
    pub default_host: Option<VHost>,
    pub vhosts: HashMap<String, VHost>,
    pub listener: Option<TcpListener>,
    #[cfg(any(feature = "tlsrust",feature = "tlsnative"))]
    pub tls: Option<ParsedTLSConfig>,
}
impl HostCfg{
    fn new(listener: TcpListener) -> HostCfg {
        HostCfg {
            default_host: None,
            vhosts: HashMap::new(),
            listener: Some(listener),
            #[cfg(any(feature = "tlsrust",feature = "tlsnative"))]
            tls: None,
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

/// group the configuration by `SocketAddr` so that each endpoint has a config.
/// Also
/// - binds on the `SocketAddr`s,
/// - executes and connects to FCGI servers
/// - setup TLS config
pub async fn group_config(cfg: &mut Configuration) -> anyhow::Result<HashMap<SocketAddr, HostCfg>> {
    let mut listening_ifs = HashMap::new();
    let mut errors = CFGError::new();
    #[cfg(unix)]
    let mut systemd_sockets = do_tcp_socket_activation();
    for (vhost, mut params) in cfg.hosts.drain() {
        let addr = params.ip;
        for (mount, wwwroot) in params.paths.iter_mut() {
            //setup FCGI Apps
            #[cfg(feature = "fcgi")]
            if let UseCase::FCGI{ref mut fcgi, ref static_files} = wwwroot.mount {
                if let Err(e) = setup_fcgi(fcgi, static_files).await {
                    errors.add(format!("FCGIApp @\"{}/{}\": {}", vhost, mount.to_string_lossy(), e));
                }
            }
            //check if header are parseable
            if wwwroot.header.is_none() {continue;}
            let mut _h = HeaderMap::new();
            if let Err(e) = crate::dispatch::insert_default_headers(&mut _h, &wwwroot.header) {
                errors.add(format!("\"{}/{}\": {}", vhost, mount.to_string_lossy(), e));
            }
        }

        #[cfg(any(feature = "tlsrust",feature = "tlsnative"))]
        let sni = if params.validate_server_name {
            Some(vhost.as_str())
        }else{
            None
        };
        //group vHosts by IP
        match listening_ifs.get_mut(&addr) {
            None => {
                #[cfg(unix)]
                let listener = {
                    systemd_sockets.remove(&addr)
                        .ok_or(())
                        .or_else(|_| TcpListener::bind(addr)).with_context(|| format!("Failed to bind to {}", addr))?
                };
                #[cfg(not(unix))]
                let listener = TcpListener::bind(addr).with_context(|| format!("Failed to bind to {}", addr))?;
                let mut hcfg = HostCfg::new(listener);
                #[cfg(any(feature = "tlsrust",feature = "tlsnative"))]
                if let Some(tlscfg) = params.tls.as_ref() {
                    match ParsedTLSConfig::new(tlscfg, sni) {
                        Ok(tlscfg_parsed) => hcfg.tls = Some(tlscfg_parsed),
                        Err(e) => errors.add(format!("vHost {}:  {}", vhost, e)),
                    }
                }
                if params.validate_server_name {
                    hcfg.vhosts.insert(vhost, params);
                }else{
                    hcfg.default_host = Some(params);
                }
                listening_ifs.insert(addr, hcfg);
            },
            Some(mut hcfg) => {
                #[cfg(any(feature = "tlsrust",feature = "tlsnative"))]
                if params.tls.is_some() != hcfg.tls.is_some() {
                    errors.add(format!("All vHosts on {} must be either TLS or not", addr));
                }else{
                    if let Some(tlscfg) = params.tls.as_ref() {
                        if let Err(e) = hcfg.tls.as_mut().unwrap().add(tlscfg, sni) { //safe because hcfg.tls is some at this point
                            errors.add(format!("vHost {}:  {}", vhost, e));
                        }
                    }
                }
                
                if params.validate_server_name {
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
        Err(errors.into())
    }else{
        Ok(listening_ifs)
    }
}
#[cfg(unix)]
fn do_tcp_socket_activation() -> HashMap<SocketAddr, TcpListener> {
    use libsystemd::activation::IsType;
    use std::os::unix::io::FromRawFd;
    use std::os::unix::io::IntoRawFd;
    let mut ret = HashMap::new();
    if let Ok(fds) = libsystemd::activation::receive_descriptors(false) {
        for fd in fds {
            if fd.is_inet() {
                let l = unsafe{ TcpListener::from_raw_fd(fd.into_raw_fd())};
                if let Ok(addr) = l.local_addr() {
                    info!("{:?} was passed via socket activation", addr);
                    ret.insert(addr,l);
                }
            }
        }
    }
    ret
}


fn gather_mounts<'de, D>(deserializer: D) -> Result<BTreeMap<PathBuf, WwwRoot>, D::Error>
where
    D: Deserializer<'de>,
{
    struct MountVisitor();

    impl<'de> Visitor<'de> for MountVisitor
    {
        type Value = BTreeMap<PathBuf, WwwRoot>;
        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("string or map")
        }
        fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
        where
            M: MapAccess<'de>,
        {
            let mut mounts = BTreeMap::new();
            let mut lefties = HashMap::new();
            
            while let Some(key) = map.next_key::<String>()? {
                let content: serde::private::de::Content = map.next_value()?;
                let de =
                    serde::private::de::ContentRefDeserializer::<M::Error>::new(&content);
                match WwwRoot::deserialize(de) {
                    Ok(r) => {
                        let k = if let Some(skey) = key.strip_prefix("`") {
                            //should not be in a URL, use to allow keywords (like ip) as well
                            skey
                        }else{
                            &key
                        };
                        mounts.insert(PathBuf::from(k),r);
                    },
                    Err(_e) => {
                        lefties.insert(key, content);
                    }
                }
            }

            if !lefties.is_empty() {
                let iter = lefties.into_iter()
                    .map(|(k,v)|(k,serde::private::de::ContentDeserializer::new(v)));
                let mapde = serde::de::value::MapDeserializer::new(iter);
                mounts.insert(PathBuf::new(), WwwRoot::deserialize(mapde)?);
            }

            Ok(mounts)
        }
    }
    deserializer.deserialize_any(MountVisitor())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_file(){
        use std::fs::File;
        use std::io::prelude::*;
        let mut file = File::create("./test_cfg.toml").expect("could not create cfg file");
        file.write_all(b"[host]\nip = \"0.0.0.0:1337\"\ndir=\".\"").expect("could not write cfg file");
        load_config().expect("should be a valid cfg");

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
    async fn root_mount() {
        let mut cfg: Configuration = toml::from_str(r#"
    [host]
    ip = "0.0.0.0:1337"
    dir = "."
    [host.a]
    dir = ".."
    "#).expect("parse err");
        assert!(group_config(&mut cfg).await.is_ok());
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
    dir = "."
    header = {test = "bad\u0000header"}
    "#).expect("parse err");
        assert!(group_config(&mut cfg).await.is_err());

        let mut cfg: Configuration = toml::from_str(r#"
    [host]
    ip = "0.0.0.0:1339"
    [host."/"]
    dir = "."
    header = {"test\n" = "1"}
    "#).expect("parse err");
        assert!(group_config(&mut cfg).await.is_err());

        let mut cfg: Configuration = toml::from_str(r#"
    [host]
    ip = "0.0.0.0:1339"
    [host."/"]
    dir = "."
    header = {"X-ok" = "1"}
    "#).expect("parse err");
        assert!(group_config(&mut cfg).await.is_ok());
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
    [[host.tls.host]]
    cert_file = ""
    key_file = ""
    [host2]
    ip = "8.8.8.8:22"
    "#).expect("parse err");
        assert!(group_config(&mut cfg).await.is_err());
    }
}