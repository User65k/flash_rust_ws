use super::PlainIncoming;
use tokio_rustls::rustls::{
    crypto::ring::{default_provider, ALL_CIPHER_SUITES},
    pki_types::{CertificateDer as Certificate, PrivateKeyDer as PrivateKey},
    version, Error, SupportedCipherSuite, SupportedProtocolVersion,
};
use tokio_rustls::TlsAcceptor as RustlsAcceptor;
pub use tokio_rustls::{
    rustls::ServerConfig as TLSConfig, server::TlsStream as UnderlyingTLSStream,
    Accept as UnderlyingAccept,
};

#[cfg(feature = "tlsrust_acme")]
use async_acme::acme::ACME_TLS_ALPN_NAME;

use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::vec::Vec;
use std::{fs, io};

use super::{PlainStream, TLSBuilderTrait};

#[cfg(feature = "tlsrust_acme")]
mod acme;
#[cfg(feature = "tlsrust_acme")]
use acme::{AcmeTaskRunner, ACME};
mod resolve_key;
use resolve_key::ResolveServerCert;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeySet {
    pub cert: PathBuf,
    pub key: PathBuf,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum KeyMaterial {
    Files(Vec<KeySet>),
    #[cfg(feature = "tlsrust_acme")]
    ACME(ACME),
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsUserConfig {
    pub host: KeyMaterial,
    pub ciphersuites: Option<Vec<String>>,
    pub versions: Option<Vec<String>>,
}

pub struct ParsedTLSConfig {
    certres: ResolveServerCert,
    ciphersuites: Option<Vec<SupportedCipherSuite>>,
    versions: Option<Vec<&'static SupportedProtocolVersion>>,
    #[cfg(feature = "tlsrust_acme")]
    acmes: Vec<AcmeTaskRunner>,
}

impl TLSBuilderTrait for ParsedTLSConfig {
    fn get_accept_feature(
        accept: &super::TlsAcceptor,
        stream: PlainStream,
    ) -> UnderlyingAccept<PlainStream> {
        RustlsAcceptor::from(accept.config.clone()).accept(stream)
    }

    fn new(
        config: &TlsUserConfig,
        sni: Option<&str>,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let ciphersuites = if let Some(suites) = config.ciphersuites.as_ref() {
            Some(lookup_suites(suites)?)
        } else {
            None
        };
        let versions = if let Some(versions) = config.versions.as_ref() {
            Some(lookup_versions(versions)?)
        } else {
            None
        };
        let mut certres = ResolveServerCert::new();
        #[cfg(feature = "tlsrust_acme")]
        let mut acmes = Vec::new();

        match &config.host {
            KeyMaterial::Files(keyset) => certres.add(sni, keyset)?,
            #[cfg(feature = "tlsrust_acme")]
            KeyMaterial::ACME(acme) => AcmeTaskRunner::add_new(&mut acmes, acme, sni)?,
        }

        Ok(ParsedTLSConfig {
            certres,
            ciphersuites,
            versions,
            #[cfg(feature = "tlsrust_acme")]
            acmes,
        })
    }
    fn add(
        &mut self,
        config: &TlsUserConfig,
        sni: Option<&str>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if let Some(suites) = config.ciphersuites.as_ref() {
            let new = lookup_suites(suites)?;
            if let Some(suites) = self.ciphersuites.as_ref() {
                if new.ne(suites) {
                    return Err(Box::new(Error::General(
                        "Single IF can only have one set of ciphers".into(),
                    )));
                }
            } else {
                self.ciphersuites = Some(new);
            }
        }
        if let Some(versions) = config.versions.as_ref() {
            let new = lookup_versions(versions)?;
            if let Some(versions) = self.versions.as_ref() {
                if new.ne(versions) {
                    return Err(Box::new(Error::General(
                        "Single IF can only have one set of versions".into(),
                    )));
                }
            } else {
                self.versions = Some(new);
            }
        }
        match &config.host {
            KeyMaterial::Files(keyset) => self.certres.add(sni, keyset)?,
            #[cfg(feature = "tlsrust_acme")]
            KeyMaterial::ACME(acme) => AcmeTaskRunner::add_new(&mut self.acmes, acme, sni)?,
        }

        Ok(())
    }
    fn get_acceptor(self, incoming: PlainIncoming) -> super::TlsAcceptor {
        let certres = Arc::new(self.certres);
        #[cfg(feature = "tlsrust_acme")]
        for acme in self.acmes {
            acme.start(&certres);
        }

        let mut provider = default_provider();
        if let Some(cipher_suites) = self.ciphersuites {
            provider.cipher_suites = cipher_suites;
        }
        let config = TLSConfig::builder_with_provider(provider.into());
        let mut config = if let Some(versions) = self.versions {
            config.with_protocol_versions(versions.as_slice())
        } else {
            config.with_safe_default_protocol_versions()
        }
        .unwrap()
        .with_no_client_auth()
        .with_cert_resolver(certres);
        config.alpn_protocols = vec![
            b"h2".to_vec(),
            b"http/1.1".to_vec(),
            #[cfg(feature = "tlsrust_acme")]
            ACME_TLS_ALPN_NAME.to_vec(),
        ];

        super::TlsAcceptor::new(config, incoming)
    }
}

// Load public certificate from file.
fn load_certs(filename: &Path) -> Result<Vec<Certificate<'static>>, io::Error> {
    // Open certificate file.
    let certfile = fs::File::open(filename)?;
    let mut reader = io::BufReader::new(certfile);

    // Load and return certificate.
    Ok(rustls_pemfile::certs(&mut reader)
        .filter_map(|e| e.ok())
        .collect())
}

// Load private key from file.
fn load_private_key(filename: &Path) -> Result<PrivateKey, io::Error> {
    let keyfile = fs::File::open(filename)?;
    let mut reader = io::BufReader::new(keyfile);

    loop {
        match rustls_pemfile::read_one(&mut reader).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "cannot parse private key .pem file",
            )
        })? {
            Some(rustls_pemfile::Item::Pkcs1Key(key)) => return Ok(PrivateKey::Pkcs1(key)),
            Some(rustls_pemfile::Item::Pkcs8Key(key)) => return Ok(PrivateKey::Pkcs8(key)),
            Some(rustls_pemfile::Item::Sec1Key(key)) => return Ok(PrivateKey::Sec1(key)),
            None => break,
            _ => {}
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "expected a single private key",
    ))
}
fn lookup_suites(suites: &[String]) -> Result<Vec<SupportedCipherSuite>, io::Error> {
    let mut out = Vec::new();

    'cpr: for csname in suites {
        for suite in ALL_CIPHER_SUITES {
            let sname = format!("{:?}", suite).to_lowercase();
            if sname == csname.to_lowercase() {
                out.push(*suite);
                continue 'cpr;
            }
        }
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Chiper {} is not supported", csname),
        ));
    }
    Ok(out)
}

/// Make a vector of protocol versions named in `versions`
fn lookup_versions(
    versions: &[String],
) -> Result<Vec<&'static SupportedProtocolVersion>, io::Error> {
    let mut out = Vec::new();

    for vname in versions {
        let version = match vname.as_ref() {
            "1.2" => &version::TLS12,
            "1.3" => &version::TLS13,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "TLS Version not supported. Pick 1.2 or 1.3",
                ))
            }
        };
        out.push(version);
    }
    Ok(out)
}

#[test]
fn todo() {
    let ks = KeySet {
        cert: PathBuf::from("./test_cert.der"),
        key: PathBuf::from("./test_key.der"),
    };
    let u1 = TlsUserConfig {
        host: KeyMaterial::Files(vec![ks]),
        ciphersuites: None,
        versions: None,
    };
    let _p = ParsedTLSConfig::new(&u1, None);
}
