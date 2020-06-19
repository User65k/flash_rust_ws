pub use tokio_rustls::{server::TlsStream as UnderlyingTLSStream, Accept as UnderlyingAccept};
pub use tokio_rustls::rustls::ServerConfig as UnderlyingConfig;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::{Certificate, PrivateKey, NoClientAuth};
use tokio_rustls::rustls::internal::pemfile;
use tokio_rustls::rustls::{SupportedCipherSuite, ALL_CIPHERSUITES, ProtocolVersion};

use std::vec::Vec;
use std::sync::Arc;
use std::{fs, io};
use serde::Deserialize;
use std::path::PathBuf;

use super::PlainStream;

#[derive(Debug)]
#[derive(Deserialize)]
pub struct TlsConfig {
    pub cert_file: PathBuf,
    pub key_file: PathBuf,
    pub ciphersuites: Option<Vec<String>>,
    pub versions: Option<Vec<String>>,
}


pub fn get_accept_feature(config: Arc<UnderlyingConfig>, stream: PlainStream) -> UnderlyingAccept<PlainStream> {
    TlsAcceptor::from(config).accept(stream)
}

pub fn get_config(config: &TlsConfig)
             -> Result<UnderlyingConfig, Box<dyn std::error::Error + Send + Sync>> {
    // Load public certificate.
    let certs = load_certs(&config.cert_file)?;
    // Load private key.
    let key = load_private_key(&config.key_file)?;
    // Do not use client certificate authentication.
    let mut cfg = UnderlyingConfig::new(NoClientAuth::new());

    if let Some(suites) = config.ciphersuites.as_ref() {
        cfg.ciphersuites = lookup_suites(suites);
    }
    if let Some(versions) = config.versions.as_ref() {
        cfg.versions = lookup_versions(versions);
    }

    // Select a certificate to use.
    cfg.set_single_cert(certs, key)?;
    // Configure ALPN to accept HTTP/2, HTTP/1.1 in that order.
    cfg.set_protocols(&[b"h2".to_vec(), b"http/1.1".to_vec()]);
    Ok(cfg)
}

// Load public certificate from file.
fn load_certs(filename: &PathBuf) -> Result<Vec<Certificate>,io::Error> {
    // Open certificate file.
    let certfile = fs::File::open(filename)?;
    let mut reader = io::BufReader::new(certfile);

    // Load and return certificate.
    pemfile::certs(&mut reader).map_err(|_|io::Error::new(io::ErrorKind::InvalidData, "could not read cert"))
}

// Load private key from file.
fn load_private_key(filename: &PathBuf) -> Result<PrivateKey,io::Error> {
    // Open keyfile.
    let keyfile = fs::File::open(filename)?;
    let mut reader = io::BufReader::new(keyfile);

    // Load and return a single private key.
    let keys = pemfile::rsa_private_keys(&mut reader).map_err(|_|io::Error::new(io::ErrorKind::InvalidData, "could not priv key"))?;
    if keys.len() != 1 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "expected a single private key"));
    }
    Ok(keys[0].clone())
}

fn lookup_suites(suites: &Vec<String>) -> Vec<&'static SupportedCipherSuite> {
    let mut out = Vec::new();

    for suite in &ALL_CIPHERSUITES {
        let sname = format!("{:?}", suite.suite).to_lowercase();
        for csname in suites {
            if sname == csname.to_lowercase() {
                out.push(*suite);
            }
        }
    }
    out
}

/// Make a vector of protocol versions named in `versions`
fn lookup_versions(versions: &Vec<String>) -> Vec<ProtocolVersion> {
    let mut out = Vec::new();

    for vname in versions {
        let version = match vname.as_ref() {
            "1.2" => ProtocolVersion::TLSv1_2,
            "1.3" => ProtocolVersion::TLSv1_3,
            _ => panic!("cannot look up version '{}', valid are '1.2' and '1.3'", vname),
        };
        out.push(version);
    }

    out
}