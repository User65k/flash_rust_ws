#[cfg(feature = "tlsrust")]
mod rustls;

#[cfg(feature = "tlsrust")]
pub use self::rustls::{ParsedTLSConfig, TlsUserConfig};
#[cfg(feature = "tlsrust")]
use self::rustls::{TLSConfig, UnderlyingAccept, UnderlyingTLSStream};

use super::{Connection, PlainIncoming, PlainStream};
use hyper::Version;
use std::io;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;

use std::net::SocketAddr;

#[cfg(feature = "tlsrust_acme")]
use async_acme::acme::ACME_TLS_ALPN_NAME;

#[cfg(all(feature = "tlsrust", feature = "tlsnative"))]
compile_error!("feature \"tlsrust\" and feature \"tlsnative\" cannot be enabled at the same time");

pub(crate) trait TLSBuilderTrait {
    /// called by first vHost that wants TLS
    fn new(
        c: &TlsUserConfig,
        sni: Option<&str>,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>>
    where
        Self: std::marker::Sized;
    /// called by all but the first vHost on one socket
    fn add(
        &mut self,
        c: &TlsUserConfig,
        sni: Option<&str>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
    fn get_accept_feature(
        accept: &TlsAcceptor,
        stream: PlainStream,
    ) -> UnderlyingAccept<PlainStream>;
    fn get_acceptor(self, incoming: PlainIncoming) -> TlsAcceptor;
}

pub type TlsStream = UnderlyingTLSStream<PlainStream>;
impl Connection for TlsStream {
    fn proto(&self) -> hyper::Version {
        match self.get_ref().1.alpn_protocol() {
            Some(b"h2") => Version::HTTP_2,
            _ => Version::HTTP_11,
        }
    }
}

pub(crate) struct TlsAcceptor {
    config: Arc<TLSConfig>,
    incoming: PlainIncoming,
}

impl TlsAcceptor {
    pub(crate) fn new(config: TLSConfig, incoming: PlainIncoming) -> TlsAcceptor {
        TlsAcceptor {
            config: Arc::new(config),
            incoming,
        }
    }
    pub(crate) async fn accept(&self) -> io::Result<(TlsStream, SocketAddr)> {
        let (stream, remote) = self.incoming.accept().await?;
        let mut stream = ParsedTLSConfig::get_accept_feature(self, stream).await?;

        #[cfg(feature = "tlsrust_acme")]
        if stream.get_ref().1.alpn_protocol() == Some(ACME_TLS_ALPN_NAME) {
            log::debug!("completed acme-tls/1 handshake");
            stream.shutdown().await?;
            return Err(io::Error::other(ACMEdone()));
        }

        Ok((stream, remote))
    }
}

pub struct ACMEdone();
impl std::error::Error for ACMEdone {}
impl std::fmt::Display for ACMEdone {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("ACMEdone").finish()
    }
}
impl std::fmt::Debug for ACMEdone {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("ACMEdone").finish()
    }
}
#[cfg(test)]
pub mod test {
    pub const CERT: &[u8] = br##"-----BEGIN CERTIFICATE-----
MIIBgDCCATKgAwIBAgIIbDGujUqwPzEwBQYDK2VwMBYxFDASBgNVBAMTC2V4YW1w
bGUuY29tMB4XDTI0MDMxOTA4MzkwMFoXDTI1MDMxOTA4MzkwMFowFjEUMBIGA1UE
AxMLZXhhbXBsZS5jb20wKjAFBgMrZXADIQBcfx/hdACfq9rN7jBQxZ57oi5Al9M3
lSTRcoLdgFivbKOBnTCBmjAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBRi8hYvUxAL
gKebioi0JUu3ZBwHoDALBgNVHQ8EBAMCA+gwEwYDVR0lBAwwCgYIKwYBBQUHAwEw
FgYDVR0RBA8wDYILZXhhbXBsZS5jb20wEQYJYIZIAYb4QgEBBAQDAgZAMB4GCWCG
SAGG+EIBDQQRFg94Y2EgY2VydGlmaWNhdGUwBQYDK2VwA0EAqEuQaZiGUD6bAVam
T865WyvI01oGwWnFP0DDuM/xs1sXhlOw+0FxyRWKexxQ8jRZ0yQK4E6Uucr73ilM
FuIWAw==
-----END CERTIFICATE-----"##;
    pub const ED_KEY: &[u8] = br##"-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEII9JHUTfHYPyMtQFbxnpOL8ltt4DFWLaVY9HqG2zGR9b
-----END PRIVATE KEY-----"##;
}