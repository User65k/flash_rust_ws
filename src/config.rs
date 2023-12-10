#[cfg(feature = "webdav")]
use crate::dispatch::dav::Config as webdav;
#[cfg(feature = "fcgi")]
use crate::dispatch::fcgi::FcgiMnt;
#[cfg(feature = "proxy")]
use crate::dispatch::proxy::Proxy;
#[cfg(test)]
use crate::dispatch::test::UnitTestUseCase;
#[cfg(feature = "websocket")]
use crate::dispatch::websocket::Websocket;
#[cfg(any(feature = "tlsrust", feature = "tlsnative"))]
use crate::transport::tls::{ParsedTLSConfig, TLSBuilderTrait, TlsUserConfig};
use anyhow::{Context, Result};
use hyper::header::HeaderName;
use hyper::http::HeaderValue;
use log::info;
use log4rs::config::RawConfig as LogConfig;
use serde::de::{Deserializer, Error as DeError, MapAccess, Visitor};
use serde::Deserialize;
use std::collections::{BTreeMap, HashMap};
use std::ffi::OsStr;
use std::fmt;
use std::fs::read_to_string;
use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;

#[derive(Debug, Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
pub enum Authenticatoin {
    Digest { userfile: PathBuf, realm: String }, //TODO check file at startup
                                                 //FCGI{server: FCGIApp}
}

/// We parse the Path from the config File (utf8)
#[derive(Debug, PartialEq, PartialOrd, Eq, Ord, Deserialize)]
#[serde(transparent)]
#[repr(transparent)]
pub struct Utf8PathBuf(PathBuf);
impl Utf8PathBuf {
    pub fn empty() -> Utf8PathBuf {
        Utf8PathBuf(PathBuf::new())
    }
    pub fn as_str(&self) -> &str {
        /*match self.0.as_os_str().to_str() {
            Some(s) => s,
            None => unreachable!()
        }*/
        // SAFETY: every Utf8Path constructor ensures that self is valid UTF-8
        unsafe { &*(self.0.as_os_str() as *const OsStr as *const str) }
    }
}
impl std::ops::Deref for Utf8PathBuf {
    type Target = std::path::Path;
    fn deref(&self) -> &std::path::Path {
        self.0.as_path()
    }
}
impl AsRef<std::path::Path> for Utf8PathBuf {
    fn as_ref(&self) -> &std::path::Path {
        self.0.as_path()
    }
}
impl PartialEq<OsStr> for Utf8PathBuf {
    fn eq(&self, other: &OsStr) -> bool {
        self.0 == other
    }
}
impl From<&str> for Utf8PathBuf {
    fn from(s: &str) -> Self {
        Utf8PathBuf(PathBuf::from(s))
    }
}

/// An absolute folder on the filesystem
#[derive(Debug, PartialEq, PartialOrd, Eq, Ord)]
#[repr(transparent)]
pub struct AbsPathBuf(PathBuf);
impl AbsPathBuf {
    #[cfg(test)]
    pub fn temp_dir() -> AbsPathBuf {
        AbsPathBuf(std::env::temp_dir().canonicalize().unwrap())
    }
}
impl<'de> Deserialize<'de> for AbsPathBuf {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = AbsPathBuf;
            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a path on the file system")
            }
            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(AbsPathBuf(
                    PathBuf::from(v).canonicalize().map_err(E::custom)?,
                ))
            }
        }
        deserializer.deserialize_str(Visitor)
    }
}
impl std::ops::Deref for AbsPathBuf {
    type Target = std::path::Path;
    fn deref(&self) -> &std::path::Path {
        self.0.as_path()
    }
}
impl AsRef<std::path::Path> for AbsPathBuf {
    fn as_ref(&self) -> &std::path::Path {
        self.0.as_path()
    }
}
#[cfg(test)]
impl From<&str> for AbsPathBuf {
    fn from(s: &str) -> Self {
        AbsPathBuf(
            PathBuf::from(s)
                .canonicalize()
                .expect("could not canonicalize"),
        )
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StaticFiles {
    pub dir: AbsPathBuf,
    #[serde(default)]
    pub follow_symlinks: bool, // = false
    pub index: Option<Vec<Utf8PathBuf>>,
    pub serve: Option<Vec<Utf8PathBuf>>,
}
impl StaticFiles {
    pub async fn setup(&self) -> Result<(), String> {
        if !self.dir.is_dir() {
            return Err(format!("{:?} ist not a directory", self.dir));
        }
        Ok(())
    }
}

/// Purpose of a single `WwwRoot`
#[derive(Debug)]
pub enum UseCase {
    #[cfg(feature = "fcgi")]
    FCGI(FcgiMnt),
    StaticFiles(StaticFiles),
    #[cfg(feature = "proxy")]
    Proxy(Proxy),
    #[cfg(feature = "websocket")]
    Websocket(Websocket),
    #[cfg(feature = "webdav")]
    Webdav(webdav),
    #[cfg(test)]
    UnitTest(UnitTestUseCase),
}
/// use own deserializer to get the variant from the "main" key
/// this helps to preserve usefull error messages
impl<'de> Deserialize<'de> for UseCase {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let tree = toml::Table::deserialize(deserializer)?;

        if tree.contains_key("fcgi") {
            #[cfg(feature = "fcgi")]
            return Ok(UseCase::FCGI(
                FcgiMnt::deserialize(tree).map_err(DeError::custom)?,
            ));
            #[cfg(not(feature = "fcgi"))]
            return Err(DeError::custom("fcgi support is disabled"));
        } else if tree.contains_key("forward") {
            #[cfg(feature = "proxy")]
            return Ok(UseCase::Proxy(
                Proxy::deserialize(tree).map_err(DeError::custom)?,
            ));
            #[cfg(not(feature = "proxy"))]
            return Err(DeError::custom("reverse proxy support is disabled"));
        } else if tree.contains_key("assock") {
            #[cfg(feature = "websocket")]
            return Ok(UseCase::Websocket(
                Websocket::deserialize(tree).map_err(DeError::custom)?,
            ));
            #[cfg(not(feature = "websocket"))]
            return Err(DeError::custom("websocket support is disabled"));
        } else if tree.contains_key("dav") {
            #[cfg(feature = "webdav")]
            return Ok(UseCase::Webdav(
                webdav::deserialize(tree).map_err(DeError::custom)?,
            ));
            #[cfg(not(feature = "webdav"))]
            return Err(DeError::custom("webdav support is disabled"));
        } else if tree.contains_key("dir") {
            Ok(UseCase::StaticFiles(
                StaticFiles::deserialize(tree).map_err(DeError::custom)?,
            ))
        } else {
            Err(DeError::custom(
                "Missing one of fcgi, assock, dav, dir - expected struct WwwRoot",
            ))
        }
    }
}

#[derive(Debug, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct HeaderNameCfg(pub HeaderName);
impl<'de> Deserialize<'de> for HeaderNameCfg {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = HeaderNameCfg;
            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a HeaderName")
            }
            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(HeaderNameCfg(
                    HeaderName::from_bytes(v.as_bytes()).map_err(E::custom)?,
                ))
            }
        }
        deserializer.deserialize_str(Visitor)
    }
}
#[derive(Debug)]
#[repr(transparent)]
pub struct HeaderValueCfg(pub HeaderValue);
impl<'de> Deserialize<'de> for HeaderValueCfg {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = HeaderValueCfg;
            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a HeaderValue")
            }
            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(HeaderValueCfg(HeaderValue::from_str(v).map_err(E::custom)?))
            }
        }
        deserializer.deserialize_str(Visitor)
    }
}

/// A single directory under a `VHost`
#[derive(Debug, Deserialize)]
pub struct WwwRoot {
    #[serde(flatten)]
    pub mount: UseCase,
    pub header: Option<HashMap<HeaderNameCfg, HeaderValueCfg>>,
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
    pub paths: BTreeMap<Utf8PathBuf, WwwRoot>,
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
///
/// Parsed from TOML Config file
#[derive(Debug, Deserialize)]
pub struct Configuration {
    pub logfile: Option<Utf8PathBuf>,
    pub pidfile: Option<Utf8PathBuf>,
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
        for cfg_path in ["./config.toml", "/etc/default/frws.toml"].iter() {
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

    // read the whole file
    let buffer =
        read_to_string(&path).with_context(|| format!("Failed to open config from {:?}", path))?;

    let mut cfg = toml::from_str::<Configuration>(&buffer)?;
    if log::log_enabled!(log::Level::Info) {
        for (host_name, vhost) in cfg.hosts.iter_mut() {
            info!("host: {} @ {}", host_name, vhost.ip);
        }
    }
    Ok(cfg)
}

/// Internal representation of `Configuration`.
pub struct HostCfg {
    pub default_host: Option<VHost>,
    pub vhosts: HashMap<String, VHost>,
    pub listener: Option<TcpListener>,
    #[cfg(any(feature = "tlsrust", feature = "tlsnative"))]
    pub tls: Option<ParsedTLSConfig>,
}
impl HostCfg {
    pub fn new(listener: TcpListener) -> HostCfg {
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
                #[cfg(feature = "proxy")]
                UseCase::Proxy(p) => p.setup().await,
                #[cfg(feature = "webdav")]
                UseCase::Webdav(dav) => dav.setup().await,
                #[cfg(feature = "websocket")]
                UseCase::Websocket(f) => f.setup().await,
                #[cfg(test)]
                UseCase::UnitTest(_) => unreachable!(),
                UseCase::StaticFiles(sf) => sf.setup().await,
            } {
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
            Some(hcfg) => {
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

/// this is like
/// ```
/// #[serde(flatten)]
/// pub paths: Map<Utf8PathBuf, WwwRoot>,
/// #[serde(flatten)]
/// pub webroot: Option<WwwRoot>
/// ```
/// but puts webroot also in the paths Map (with path "")
/// and strips acute from all the paths to allow field names as paths.
///
/// Also works as `#[serde(deny_unknown_fields)]`
fn gather_mounts<'de, D>(deserializer: D) -> Result<BTreeMap<Utf8PathBuf, WwwRoot>, D::Error>
where
    D: Deserializer<'de>,
{
    struct MountVisitor();

    impl<'de> Visitor<'de> for MountVisitor {
        type Value = BTreeMap<Utf8PathBuf, WwwRoot>;
        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("mountpoint must be a map")
        }
        fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
        where
            M: MapAccess<'de>,
        {
            let mut mounts = BTreeMap::new();
            let mut lefties = toml::Table::new();

            while let Some(key) = map.next_key::<String>()? {
                let content: toml::Value = map
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
                        mounts.insert(Utf8PathBuf::from(k), r);
                    }
                    Err(e) => {
                        if e.message().ends_with("expected struct WwwRoot") {
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
                mounts.insert(
                    Utf8PathBuf::empty(),
                    WwwRoot::deserialize(lefties)
                        .map_err(|e| DeError::custom(format!("webroot: {}", e)))?,
                );
            }

            if mounts.is_empty() {
                return Err(DeError::custom("vHost does not serve anything"));
            }

            Ok(mounts)
        }
    }
    deserializer.deserialize_map(MountVisitor())
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
    your.dir = "."
    [host]
    ip = "0.0.0.0:1337"
    [host.path]
    dir = "./"
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
            .map(|p| p.0)
            .collect();
        //eprintln!("{:?}", mounts);
        assert!(mounts == [PathBuf::from(""), PathBuf::from("`b"), PathBuf::from("a")]);
    }
    #[test]
    fn dir_nonexistent() {
        let cfg: Result<Configuration, _> = toml::from_str(
            r#"
    [host]
    ip = "0.0.0.0:1337"
    dir = "blablahui"
    "#,
        );
        cfg.expect_err("dir should not pass canonicalize");
    }
    #[tokio::test]
    async fn dir_is_file() {
        let tf = crate::dispatch::test::TempFile::create("bla", b"bla");
        let mut cfg: Configuration = toml::from_str(&format!(
            r#"
    [host]
    ip = "0.0.0.0:1337"
    dir = '{}'
    "#,
            tf.get_path().to_str().unwrap()
        ))
        .expect("parse err");
        assert!(group_config(&mut cfg).await.is_err());
    }
    #[tokio::test]
    async fn vhost_conflict() {
        let mut cfg: Configuration = toml::from_str(
            r#"
    [host]
    ip = "0.0.0.0:1337"
    dir = "."
    [another]
    ip = "0.0.0.0:1337"
    dir = "."
    "#,
        )
        .expect("parse err");
        assert!(group_config(&mut cfg).await.is_err());
    }
    #[tokio::test]
    async fn bad_header() {
        assert!(toml::from_str::<Configuration>(
            r#"
    [host]
    ip = "0.0.0.0:1338"
    [host."/"]
    dir = "."
    header = {test = "bad\u0000header"}
    "#,
        )
        .is_err());

        assert!(toml::from_str::<Configuration>(
            r#"
    [host]
    ip = "0.0.0.0:1339"
    [host."/"]
    dir = "."
    header = {"test\n" = "1"}
    "#,
        )
        .is_err());

        assert!(toml::from_str::<Configuration>(
            r#"
    [host]
    ip = "0.0.0.0:1339"
    [host."/"]
    dir = "."
    header = {"X-ok" = "1"}
    "#,
        )
        .is_ok());
    }

    #[tokio::test]
    async fn cant_listen() {
        let mut cfg: Configuration = toml::from_str(
            r#"
    [host]
    ip = "8.8.8.8:22"
    dir = "."
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
    dir = "."
    [[host.tls.host.Files]]
    cert = ""
    key = ""
    [host2]
    ip = "8.8.8.8:22"
    dir = "."
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
