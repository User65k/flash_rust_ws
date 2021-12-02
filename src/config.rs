#[cfg(feature = "webdav")]
use crate::dispatch::dav::Config as webdav;
#[cfg(feature = "fcgi")]
use crate::dispatch::fcgi::FcgiMnt;
#[cfg(feature = "websocket")]
use crate::dispatch::websocket::Websocket;
#[cfg(any(feature = "tlsrust", feature = "tlsnative"))]
use crate::transport::tls::{ParsedTLSConfig, TLSBuilderTrait, TlsUserConfig};
use anyhow::{Context, Result};
use hyper::header::HeaderMap;
use log::info;
use log4rs::config::RawConfig as LogConfig;
use serde::de::{Deserializer, Error as DeError, MapAccess, Visitor};
use serde::Deserialize;
use serde_value::Value as SerdeContent;
use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::fs::File;
use std::io::Read;
use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;

#[derive(Debug, Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
pub enum Authenticatoin {
    Digest { userfile: PathBuf, realm: String }, //TODO check file at startup
                                                 //FCGI{server: FCGIApp}
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StaticFiles {
    pub dir: PathBuf,
    #[serde(default)]
    pub follow_symlinks: bool, // = false
    pub index: Option<Vec<PathBuf>>,
    pub serve: Option<Vec<PathBuf>>,
}
impl StaticFiles {
    pub async fn setup(&self) -> Result<(), String> {
        if !self.dir.is_dir() {
            return Err(format!("{:?} ist not a directory", self.dir));
        }
        Ok(())
    }
}

#[derive(Debug)]
pub enum UseCase {
    #[cfg(feature = "fcgi")]
    FCGI(FcgiMnt),
    StaticFiles(StaticFiles),
    #[cfg(feature = "websocket")]
    Websocket(Websocket),
    //Proxy{host: String, path: String},
    #[cfg(feature = "webdav")]
    Webdav(webdav),
}
/// use own deserializer to get the variant from the "main" key
/// this helps to preserve usefull error messages
impl<'de> Deserialize<'de> for UseCase {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let content = SerdeContent::deserialize(deserializer)?;

        match &content {
            SerdeContent::Map(tree) => {
                if tree.contains_key(&SerdeContent::String("fcgi".to_string())) {
                    #[cfg(feature = "fcgi")]
                    return Ok(UseCase::FCGI(
                        FcgiMnt::deserialize(content).map_err(DeError::custom)?,
                    ));
                    #[cfg(not(feature = "fcgi"))]
                    return Err(DeError::custom("fcgi support is disabled"));
                } else if tree.contains_key(&SerdeContent::String("assock".to_string())) {
                    #[cfg(feature = "websocket")]
                    return Ok(UseCase::Websocket(
                        Websocket::deserialize(content).map_err(DeError::custom)?,
                    ));
                    #[cfg(not(feature = "websocket"))]
                    return Err(DeError::custom("websocket support is disabled"));
                } else if tree.contains_key(&SerdeContent::String("root".to_string())) {
                    #[cfg(feature = "webdav")]
                    return Ok(UseCase::Webdav(
                        webdav::deserialize(content).map_err(DeError::custom)?,
                    ));
                    #[cfg(not(feature = "webdav"))]
                    return Err(DeError::custom("webdav support is disabled"));
                } else if tree.contains_key(&SerdeContent::String("dir".to_string())) {
                    Ok(UseCase::StaticFiles(
                        StaticFiles::deserialize(content).map_err(DeError::custom)?,
                    ))
                } else {
                    Err(DeError::custom(
                        "Missing one of fcgi, assock, root, dir. Expected struct WwwRoot",
                    ))
                }
            }
            _ => Err(DeError::custom("Invalid type. Expected struct WwwRoot")),
        }
    }
}

/// A single directory
#[derive(Debug, Deserialize)]
pub struct WwwRoot {
    #[serde(flatten)]
    pub mount: UseCase,
    pub header: Option<HashMap<String, String>>,
    pub auth: Option<Authenticatoin>,
}

/// vHost specific configuration
#[derive(Debug, Deserialize)]
pub struct VHost {
    pub ip: SocketAddr,
    #[cfg(any(feature = "tlsrust", feature = "tlsnative"))]
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
            #[cfg(any(feature = "tlsrust", feature = "tlsnative"))]
            tls: None,
            validate_server_name: false,
            paths: BTreeMap::new(),
        }
    }
}

/// Gernal configuration
#[derive(Debug, Deserialize)]
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
    errors: Vec<String>,
}
impl CFGError {
    fn new() -> CFGError {
        CFGError { errors: Vec::new() }
    }
    fn add(&mut self, s: String) {
        self.errors.push(s);
    }
    fn has_errors(&self) -> bool {
        !self.errors.is_empty()
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
impl std::error::Error for CFGError {}

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
            None => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "No config file found!",
                )
                .into())
            }
        }
    };
    #[cfg(test)]
    let path = "./test_cfg.toml";

    let mut f =
        File::open(&path).with_context(|| format!("Failed to open config from {:?}", path))?;
    //.metadata()?.len()
    let mut buffer = Vec::new();

    // read the whole file
    f.read_to_end(&mut buffer)
        .with_context(|| format!("Failed to read config from {:?}", path))?;

    let mut cfg = toml::from_slice::<Configuration>(&buffer)?;
    for (host_name, vhost) in cfg.hosts.iter_mut() {
        info!("host: {} @ {}", host_name, vhost.ip);
        if vhost.paths.is_empty() {
            anyhow::bail!("vHost \"{}\" does not serve anything", host_name);
        }
    }
    Ok(cfg)
}

pub struct HostCfg {
    pub default_host: Option<VHost>,
    pub vhosts: HashMap<String, VHost>,
    pub listener: Option<TcpListener>,
    #[cfg(any(feature = "tlsrust", feature = "tlsnative"))]
    pub tls: Option<ParsedTLSConfig>,
}
impl HostCfg {
    fn new(listener: TcpListener) -> HostCfg {
        HostCfg {
            default_host: None,
            vhosts: HashMap::new(),
            listener: Some(listener),
            #[cfg(any(feature = "tlsrust", feature = "tlsnative"))]
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
            if let Err(e) = match &mut wwwroot.mount {
                #[cfg(feature = "fcgi")]
                UseCase::FCGI(fcgi) => fcgi.setup().await,
                #[cfg(feature = "webdav")]
                UseCase::Webdav(dav) => dav.setup().await,
                #[cfg(feature = "websocket")]
                UseCase::Websocket(f) => f.setup().await,
                UseCase::StaticFiles(sf) => sf.setup().await,
            } {
                errors.add(format!("\"{}/{}\": {}", vhost, mount.to_string_lossy(), e));
            }
            //check if header are parseable
            if wwwroot.header.is_none() {
                continue;
            }
            let mut _h = HeaderMap::new();
            if let Err(e) = crate::dispatch::insert_default_headers(&mut _h, &wwwroot.header) {
                errors.add(format!("\"{}/{}\": {}", vhost, mount.to_string_lossy(), e));
            }
        }

        #[cfg(any(feature = "tlsrust", feature = "tlsnative"))]
        let sni = if params.validate_server_name {
            Some(vhost.as_str())
        } else {
            None
        };
        //group vHosts by IP
        match listening_ifs.get_mut(&addr) {
            None => {
                #[cfg(unix)]
                let listener = {
                    systemd_sockets
                        .remove(&addr)
                        .ok_or(())
                        .or_else(|_| TcpListener::bind(addr))
                        .with_context(|| format!("Failed to bind to {}", addr))?
                };
                #[cfg(not(unix))]
                let listener = TcpListener::bind(addr)
                    .with_context(|| format!("Failed to bind to {}", addr))?;
                let mut hcfg = HostCfg::new(listener);
                #[cfg(any(feature = "tlsrust", feature = "tlsnative"))]
                if let Some(tlscfg) = params.tls.as_ref() {
                    match ParsedTLSConfig::new(tlscfg, sni) {
                        Ok(tlscfg_parsed) => hcfg.tls = Some(tlscfg_parsed),
                        Err(e) => errors.add(format!("vHost {}:  {}", vhost, e)),
                    }
                }
                if params.validate_server_name {
                    hcfg.vhosts.insert(vhost, params);
                } else {
                    hcfg.default_host = Some(params);
                }
                listening_ifs.insert(addr, hcfg);
            }
            Some(mut hcfg) => {
                #[cfg(any(feature = "tlsrust", feature = "tlsnative"))]
                if params.tls.is_some() != hcfg.tls.is_some() {
                    errors.add(format!("All vHosts on {} must be either TLS or not", addr));
                } else if let Some(tlscfg) = params.tls.as_ref() {
                    if let Err(e) = hcfg.tls.as_mut().unwrap().add(tlscfg, sni) {
                        //safe because hcfg.tls is some at this point
                        errors.add(format!("vHost {}:  {}", vhost, e));
                    }
                }

                if params.validate_server_name {
                    hcfg.vhosts.insert(vhost, params);
                } else if hcfg.default_host.is_none() {
                    hcfg.default_host = Some(params);
                } else {
                    errors.add(format!(
                        "{} is the second host on {} that does not validate the server name",
                        vhost, addr
                    ));
                }
            }
        }
    }
    if errors.has_errors() {
        Err(errors.into())
    } else {
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
                let fd = fd.into_raw_fd();

                //close FD on EXEC / when starting FCGI apps
                if -1 == unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } {
                    log::warn!("counld not set CLOEXEC");
                };

                let l = unsafe { TcpListener::from_raw_fd(fd) };
                if let Ok(addr) = l.local_addr() {
                    info!("{:?} was passed via socket activation", addr);
                    ret.insert(addr, l);
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

    impl<'de> Visitor<'de> for MountVisitor {
        type Value = BTreeMap<PathBuf, WwwRoot>;
        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("mountpoint must be a map")
        }
        fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
        where
            M: MapAccess<'de>,
        {
            let mut mounts = BTreeMap::new();
            let mut lefties = HashMap::new();

            while let Some(key) = map.next_key::<String>()? {
                let content: SerdeContent = map
                    .next_value()
                    .map_err(|e| DeError::custom(format!("{}: {}", &key, e)))?;
                let de = content.clone();
                match WwwRoot::deserialize(de) {
                    Ok(r) => {
                        let k = if let Some(skey) = key.strip_prefix('`') {
                            //should not be in a URL, use to allow keywords (like ip) as well
                            skey
                        } else {
                            &key
                        };
                        mounts.insert(PathBuf::from(k), r);
                    }
                    Err(e) => {
                        if format!("{}", &e).ends_with("Expected struct WwwRoot") {
                            //UseCase error -> maybe ok
                            lefties.insert(key, content);
                        } else {
                            //serde error -> real one
                            return Err(DeError::custom(format!("{}: {}", &key, e)));
                        }
                    }
                }
            }

            if !lefties.is_empty() {
                let iter = lefties.into_iter();
                let mapde = serde::de::value::MapDeserializer::new(iter);
                mounts.insert(
                    PathBuf::new(),
                    WwwRoot::deserialize(mapde)
                        .map_err(|e| DeError::custom(format!("webroot: {}", e)))?,
                );
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
    fn config_file() {
        use std::fs::File;
        use std::io::prelude::*;
        let mut file = File::create("./test_cfg.toml").expect("could not create cfg file");
        file.write_all(b"[host]\nip = \"0.0.0.0:1337\"\ndir=\".\"")
            .expect("could not write cfg file");
        load_config().expect("should be a valid cfg");

        file.write_all(b"\n[host2]\nip = \"0.0.0.0:8080\"")
            .expect("could not write cfg file");
        assert!(load_config().is_err()); // does not serve anything
    }
    #[test]
    fn toml_to_struct() {
        let cfg: Result<Configuration, toml::de::Error> = toml::from_str(
            r#"
    pidfile = 'bar'

    your.ip = "[::1]:1234" # hah
    your.dir = "~"
    [host]
    ip = "0.0.0.0:1337"
    [host.path]
    dir = "/var/www/"
    index = ["index.html", "index.htm"]
    "#,
        );
        assert!(cfg.is_ok());
    }
    #[test]
    fn root_mount() {
        let cfg: Result<Configuration, toml::de::Error> = toml::from_str(
            r#"
    [host]
    ip = "0.0.0.0:1337"
    dir = "."
    [host.a]
    dir = ".."
    "#,
        );
        assert!(cfg.is_ok());
    }
    #[test]
    fn keyword_mount() {
        let mut cfg: Configuration = toml::from_str(
            r#"
    [host]
    ip = "0.0.0.0:1337"
    dir = "."
    [host."`a"]
    dir = ".."
    [host."``b"]
    dir = ".."
    "#,
        )
        .expect("parse err");
        let mounts: Vec<PathBuf> = cfg
            .hosts
            .remove("host")
            .unwrap()
            .paths
            .into_keys()
            .collect();
        //eprintln!("{:?}", mounts);
        assert!(mounts == [PathBuf::from(""), PathBuf::from("`b"), PathBuf::from("a")]);
    }

    #[tokio::test]
    async fn dir_nonexistent() {
        let mut cfg: Configuration = toml::from_str(
            r#"
    [host]
    ip = "0.0.0.0:1337"
    dir = "blablahui"
    "#,
        )
        .expect("parse err");
        assert!(group_config(&mut cfg).await.is_err());
    }
    #[tokio::test]
    async fn vhost_conflict() {
        let mut cfg: Configuration = toml::from_str(
            r#"
    [host]
    ip = "0.0.0.0:1337"
    [another]
    ip = "0.0.0.0:1337"
    "#,
        )
        .expect("parse err");
        assert!(group_config(&mut cfg).await.is_err());
    }
    #[tokio::test]
    async fn bad_header() {
        let mut cfg: Configuration = toml::from_str(
            r#"
    [host]
    ip = "0.0.0.0:1338"
    [host."/"]
    dir = "."
    header = {test = "bad\u0000header"}
    "#,
        )
        .expect("parse err");
        assert!(group_config(&mut cfg).await.is_err());

        let mut cfg: Configuration = toml::from_str(
            r#"
    [host]
    ip = "0.0.0.0:1339"
    [host."/"]
    dir = "."
    header = {"test\n" = "1"}
    "#,
        )
        .expect("parse err");
        assert!(group_config(&mut cfg).await.is_err());

        let mut cfg: Configuration = toml::from_str(
            r#"
    [host]
    ip = "0.0.0.0:1339"
    [host."/"]
    dir = "."
    header = {"X-ok" = "1"}
    "#,
        )
        .expect("parse err");
        assert!(group_config(&mut cfg).await.is_ok());
    }

    #[tokio::test]
    async fn cant_listen() {
        let mut cfg: Configuration = toml::from_str(
            r#"
    [host]
    ip = "8.8.8.8:22"
    "#,
        )
        .expect("parse err");
        assert!(group_config(&mut cfg).await.is_err());
    }

    #[cfg(feature = "tlsrust")]
    #[tokio::test]
    async fn tls_plain_mix() {
        let mut cfg: Configuration = toml::from_str(
            r#"
    [host]
    ip = "8.8.8.8:22"
    [[host.tls.host.Files]]
    cert = ""
    key = ""
    [host2]
    ip = "8.8.8.8:22"
    "#,
        )
        .expect("parse err");
        assert!(group_config(&mut cfg).await.is_err());
    }
    #[test]
    fn wwwroot_parsing() {
        toml::from_str::<Configuration>(
            r#"
    [host]
    ip = "8.8.8.8:22"
    unused = 1
    "#,
        )
        .expect_err("should fail - no main key");
        toml::from_str::<Configuration>(
            r#"
    [host]
    ip = "8.8.8.8:22"
    dir = ""
    unused = 1
    "#,
        )
        .expect_err("should fail - unused key");
        toml::from_str::<Configuration>(
            r#"
    [host]
    ip = "8.8.8.8:22"
    dir = 1
    "#,
        )
        .expect_err("should fail - dir expects path");
        toml::from_str::<Configuration>(
            r#"
    [host]
    ip = "8.8.8.8:22"
    dir = "."
    header = {Referrer-Policy = "strict-origin-when-cross-origin", Feature-Policy = "microphone 'none'; geolocation 'none'"}
        "#,
        )
        .expect("should be ok");
        toml::from_str::<Configuration>(
            r#"
    [host]
    ip = "8.8.8.8:22"
    [host.mnt]
    dir = "."
        "#,
        )
        .expect("should be ok");
    }
}
