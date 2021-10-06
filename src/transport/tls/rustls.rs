pub use tokio_rustls::{
    server::TlsStream as UnderlyingTLSStream,
    Accept as UnderlyingAccept,
    rustls::ServerConfig as TLSConfig
};
use tokio_rustls::TlsAcceptor as RustlsAcceptor;
use tokio_rustls::rustls::{
    Certificate, PrivateKey, NoClientAuth,
    internal::pemfile,
    SupportedCipherSuite, ALL_CIPHERSUITES, ProtocolVersion
};
use super::PlainIncoming;

use async_acme::acme::ACME_TLS_ALPN_NAME;

use std::vec::Vec;
use std::sync::Arc;
use std::{fs, io};
use serde::Deserialize;
use std::path::PathBuf;

use super::{PlainStream, TLSBuilderTrait};

mod acme;
use acme::{AcmeTaskRunner, ACME};
mod resolve_key;
use resolve_key::ResolveServerCert;

#[derive(Debug)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeySet {
    pub cert: PathBuf,
    pub key: PathBuf,
}

#[derive(Debug)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub enum KeyMaterial {
    Files(Vec<KeySet>),
    ACME(ACME),
}
#[derive(Debug)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsUserConfig {
    pub host: KeyMaterial,
    pub ciphersuites: Option<Vec<String>>,
    pub versions: Option<Vec<String>>,
}

pub struct ParsedTLSConfig {
    cfg: TLSConfig,
    certres: ResolveServerCert,
    own_cipher: bool,
    own_vers: bool,
    acmes: Vec<AcmeTaskRunner>
}

impl TLSBuilderTrait for ParsedTLSConfig {
    fn get_accept_feature(accept: &super::TlsAcceptor, stream: PlainStream) -> UnderlyingAccept<PlainStream> {
        RustlsAcceptor::from(accept.config.clone()).accept(stream)
    }

    fn new(config: &TlsUserConfig, sni: Option<&str>) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let mut cfg = TLSConfig::new(NoClientAuth::new());
        cfg.set_protocols(&[b"h2".to_vec(), b"http/1.1".to_vec(), ACME_TLS_ALPN_NAME.to_vec()]);

        let mut own_cipher = false;
        let mut own_vers = false;
        if let Some(suites) = config.ciphersuites.as_ref() {
            cfg.ciphersuites = lookup_suites(suites)?;
            own_cipher = true;
        }
        if let Some(versions) = config.versions.as_ref() {
            cfg.versions = lookup_versions(versions)?;
            own_vers = true;
        }
        let mut certres = ResolveServerCert::new();
        let mut acmes = Vec::new();

        match &config.host {
            KeyMaterial::Files(keyset) => certres.add(sni, keyset)?,
            KeyMaterial::ACME(acme) => AcmeTaskRunner::add_new(&mut acmes, acme, sni)?,
        }

        Ok(ParsedTLSConfig {
            cfg,
            certres,
            own_cipher,
            own_vers,
            acmes
        })
    }
    fn add(&mut self, config: &TlsUserConfig, sni: Option<&str>) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if let Some(suites) = config.ciphersuites.as_ref() {
            let new = lookup_suites(suites)?;
            if self.own_cipher {
                if new != self.cfg.ciphersuites {
                    return Err(Box::new( tokio_rustls::rustls::TLSError::General("Single IF can only have one set of ciphers".into()) ))
                }
            }else{
                self.cfg.ciphersuites = new;
                self.own_cipher = true;
            }
        }
        if let Some(versions) = config.versions.as_ref() {
            let new = lookup_versions(versions)?;
            if self.own_vers {
                if new != self.cfg.versions {
                    return Err(Box::new( tokio_rustls::rustls::TLSError::General("Single IF can only have one set of versions".into()) ))
                }
            }else{
                self.cfg.versions = new;
                self.own_vers = true;
            }
        }
        match &config.host {
            KeyMaterial::Files(keyset) => self.certres.add(sni, keyset)?,
            KeyMaterial::ACME(acme) => AcmeTaskRunner::add_new(&mut self.acmes, acme, sni)?,
        }

        Ok(())
    }
    fn get_acceptor(self, incoming: PlainIncoming) -> super::TlsAcceptor {
        let certres = Arc::new(self.certres);
        for acme in self.acmes {
            acme.start(&certres);
        }
        let mut config = self.cfg;
        config.cert_resolver = certres;
        super::TlsAcceptor::new(config, incoming)
    }
}


// Load public certificate from file.
fn load_certs(filename: &PathBuf) -> Result<Vec<Certificate>,io::Error> {
    // Open certificate file.
    let certfile = fs::File::open(filename)?;
    let mut reader = io::BufReader::new(certfile);

    // Load and return certificate.
    pemfile::certs(&mut reader).map_err(|_|io::Error::new(io::ErrorKind::InvalidData, "could not parse cert"))
}

// Load private key from file.
fn load_private_key(filename: &PathBuf) -> Result<PrivateKey,io::Error> {
    let rsa_keys = {
        let keyfile = fs::File::open(filename)?;
        let mut reader = io::BufReader::new(keyfile);
        pemfile::rsa_private_keys(&mut reader).map_err(|_|io::Error::new(io::ErrorKind::InvalidData, "could not parse rsa priv key"))?
    };

    let pkcs8_keys = {
        let keyfile = fs::File::open(filename)?;
        let mut reader = io::BufReader::new(keyfile);
        pemfile::pkcs8_private_keys(&mut reader).map_err(|_|io::Error::new(io::ErrorKind::InvalidData, "could not parse pkcs8 priv key"))?
    };

    // Load and return a single private key.
    let keys = if pkcs8_keys.len()>0 {
        pkcs8_keys
    }else{
        rsa_keys
    };
    if keys.len() != 1 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "expected a single private key"));
    }
    Ok(keys[0].clone())
}

fn lookup_suites(suites: &Vec<String>) -> Result<Vec<&'static SupportedCipherSuite>, io::Error> {
    let mut out = Vec::new();

    'cpr: for csname in suites {
        for suite in &ALL_CIPHERSUITES {
            let sname = format!("{:?}", suite.suite).to_lowercase();
            if sname == csname.to_lowercase() {
                out.push(*suite);
                continue 'cpr;
            }
        }
        return Err(io::Error::new(io::ErrorKind::InvalidData, format!("Chiper {} is not supported", csname)));
    }
    Ok(out)
}

/// Make a vector of protocol versions named in `versions`
fn lookup_versions(versions: &Vec<String>) -> Result<Vec<ProtocolVersion>, io::Error> {
    let mut out = Vec::new();

    for vname in versions {
        let version = match vname.as_ref() {
            "1.2" => ProtocolVersion::TLSv1_2,
            "1.3" => ProtocolVersion::TLSv1_3,
            _ => return Err(io::Error::new(io::ErrorKind::InvalidData, "TLS Version not supported. Pick 1.2 or 1.3")),
        };
        out.push(version);
    }
    Ok(out)
}

#[test]
fn todo(){
    let ks = KeySet {
        cert: PathBuf::from("./test_cert.der"),
        key: PathBuf::from("./test_key.der")
    };
    let u1 = TlsUserConfig {
        host: KeyMaterial::Files(vec![ks]),
        ciphersuites: None,
        versions: None,
    };
    let p = ParsedTLSConfig::new(&u1, None);
}