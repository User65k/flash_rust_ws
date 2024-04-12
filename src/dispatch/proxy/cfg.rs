use crate::config::{HeaderNameCfg, Utf8PathBuf};
use hyper::{header::HeaderValue, http::uri, Uri};

use serde::Deserialize;
use std::convert::TryFrom;
use std::net::SocketAddr;

use super::client::Client;

#[derive(Deserialize, Debug, Default)]
#[serde(from = "bool")]
pub enum ForwardedHeader {
    Remove, //false
    Extend, //true
    #[default]
    Replace, //?
}
impl From<bool> for ForwardedHeader {
    fn from(value: bool) -> Self {
        if value {
            ForwardedHeader::Extend
        } else {
            ForwardedHeader::Remove
        }
    }
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct Proxy {
    pub(super) forward: ProxyAdress,
    #[serde(default)]
    pub(super) add_forwarded_header: ForwardedHeader,
    #[serde(default)]
    pub(super) add_x_forwarded_for_header: bool,
    pub(super) add_via_header_to_client: Option<String>,
    pub(super) add_via_header_to_server: Option<String>,
    #[serde(default = "yes")]
    pub force_dir: bool,
    #[serde(default = "pool_size")]
    pub(super) h1_pool_size: usize,
    #[cfg(any(feature = "tlsrust", feature = "tlsnative"))]
    pub(super) tls_root: Option<super::client::tls::RootCert>,
    //timeout: u8,
    //max_req_body_size: u32,
    pub(super) allowed_upgrades: Option<Vec<String>>,
    pub(super) allowed_methods: Option<Vec<String>>,
    //header_policy: u8,
    pub(super) filter_req_header: Option<Vec<HeaderNameCfg>>,
    pub(super) filter_resp_header: Option<Vec<HeaderNameCfg>>,
    #[serde(skip)]
    pub(super) client: Option<Client>,
}
fn yes() -> bool {
    true
}
fn pool_size() -> usize {
    10
}

#[derive(Deserialize, Debug)]
#[serde(try_from = "String")]
pub struct ProxyAdress {
    pub scheme: uri::Scheme,
    pub host: HeaderValue,
    pub path: Utf8PathBuf,
    pub addr: ProxySocket,
}
/// type for a late DNS request
///
/// only parse it once, if its an IP.
/// else, resolve it regularly
#[derive(Debug)]
pub enum ProxySocket {
    Ip(SocketAddr),
    Dns((String, u16)),
}

pub const HTTP2_PLAINTEXT_KNOWN: &str = "h2";
impl TryFrom<String> for ProxyAdress {
    type Error = anyhow::Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let uri = Uri::try_from(value)?;
        let p = uri.into_parts();
        let scheme = match p.scheme {
            Some(s) if s == uri::Scheme::HTTP => uri::Scheme::HTTP,
            #[cfg(any(feature = "tlsrust", feature = "tlsnative"))]
            Some(s) if s == uri::Scheme::HTTPS => uri::Scheme::HTTPS,
            #[cfg(not(any(feature = "tlsrust", feature = "tlsnative")))]
            Some(s) if s == uri::Scheme::HTTPS => {
                anyhow::bail!("TLS support is disabled");
            }
            Some(s) if s.as_str() == HTTP2_PLAINTEXT_KNOWN => s,
            Some(s) => {
                anyhow::bail!("{} is not known", s);
            }
            None => {
                anyhow::bail!("No scheme given");
            }
        };
        let authority = match p.authority {
            Some(a) => a,
            None => {
                anyhow::bail!("No authority/host given");
            }
        };
        let host = HeaderValue::from_bytes(authority.as_str().as_bytes())?;
        let port = match authority.port_u16() {
            Some(p) => p,
            None => {
                if scheme == uri::Scheme::HTTPS {
                    443
                } else {
                    80
                }
            }
        };
        let addr = (authority.host(), port).into();

        let path = if let Some(pq) = p.path_and_query {
            if pq.query().is_some() {
                anyhow::bail!("query is not supported. Please request support for it. https://github.com/User65k/flash_rust_ws/issues");
            }
            Utf8PathBuf::from(pq.as_str())
        } else {
            Utf8PathBuf::empty()
        };
        Ok(ProxyAdress {
            scheme,
            host,
            path,
            addr,
        })
    }
}
impl From<(&str, u16)> for ProxySocket {
    fn from(value: (&str, u16)) -> Self {
        let (host, port) = value;

        // try to parse the host as a regular IP address first
        if let Ok(addr) = host.parse::<std::net::Ipv4Addr>() {
            let addr = std::net::SocketAddrV4::new(addr, port);
            let addr = std::net::SocketAddr::V4(addr);

            return ProxySocket::Ip(addr);
        }

        if let Ok(addr) = host.parse::<std::net::Ipv6Addr>() {
            let addr = std::net::SocketAddrV6::new(addr, port, 0, 0);
            let addr = std::net::SocketAddr::V6(addr);

            return ProxySocket::Ip(addr);
        }

        ProxySocket::Dns((host.to_owned(), port))
    }
}
