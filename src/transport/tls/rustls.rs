pub use tokio_rustls::{server::TlsStream as UnderlyingTLSStream, Accept as UnderlyingAccept};
pub use tokio_rustls::rustls::ServerConfig as TLSConfig;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::{Certificate, PrivateKey, NoClientAuth};
use tokio_rustls::rustls::internal::pemfile;
use tokio_rustls::rustls::{SupportedCipherSuite, ALL_CIPHERSUITES, ProtocolVersion};
use tokio_rustls::rustls::{ClientHello, ResolvesServerCert};
use tokio_rustls::rustls::sign::{CertifiedKey, any_supported_type};

use std::vec::Vec;
use std::sync::Arc;
use std::{fs, io};
use serde::Deserialize;
use std::path::PathBuf;
use log::{debug, trace};

use super::{PlainStream, TLSBuilderTrait};

#[derive(Debug)]
#[derive(Deserialize)]
pub struct TlsUserConfig {
    pub cert_file: PathBuf,
    pub key_file: PathBuf,
    pub ciphersuites: Option<Vec<String>>,
    pub versions: Option<Vec<String>>,
}

pub struct ParsedTLSConfig {
    cfg: TLSConfig,
    certres: ResolveServerCert,
    own_cipher: bool,
    own_vers: bool,
}

impl TLSBuilderTrait for ParsedTLSConfig {
    fn get_accept_feature(config: Arc<TLSConfig>, stream: PlainStream) -> UnderlyingAccept<PlainStream> {
        TlsAcceptor::from(config).accept(stream)
    }

    fn new(config: &TlsUserConfig, sni: Option<&str>) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let mut cfg = TLSConfig::new(NoClientAuth::new());
        cfg.set_protocols(&[b"h2".to_vec(), b"http/1.1".to_vec()]);

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
        // Load public certificate.
        let certs = load_certs(&config.cert_file)?;
        // Load private key.
        let key = load_private_key(&config.key_file)?;
        certres.add(sni, certs, &key)?;
        Ok(ParsedTLSConfig {
            cfg,
            certres,
            own_cipher,
            own_vers,
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

        // Load public certificate.
        let certs = load_certs(&config.cert_file)?;
        // Load private key.
        let key = load_private_key(&config.key_file)?;
        self.certres.add(sni, certs, &key)?;

        Ok(())
    }
    fn get_config(mut self) -> TLSConfig {
        self.cfg.cert_resolver = Arc::new(self.certres);
        self.cfg
    }
}


pub struct ResolveServerCert {
    by_name: std::collections::HashMap<String, CertifiedKey>,
    default: Option<CertifiedKey>
}

impl ResolveServerCert {
    /// Create a new and empty (ie, knows no certificates) resolver.
    pub fn new() -> ResolveServerCert {
        ResolveServerCert { by_name: std::collections::HashMap::new(), default: None }
    }

    /// Add a new `CertifiedKey` to be used for the given SNI `name`.
    ///
    /// This function fails if `name` is not a valid DNS name, or if
    /// it's not valid for the supplied certificate, or if the certificate
    /// chain is syntactically faulty.
    pub fn add(&mut self, sni: Option<&str>,
                chain: Vec<Certificate>,
                priv_key: &PrivateKey) -> Result<(), tokio_rustls::rustls::TLSError> {
        let key = any_supported_type(priv_key)
            .map_err(|_| tokio_rustls::rustls::TLSError::General("invalid private key".into()))?;
        let ck = CertifiedKey::new(chain, Arc::new(key));

        if let Some(name) = sni {
            let checked_name = tokio_rustls::webpki::DNSNameRef::try_from_ascii_str(name)
                .map_err(|_| tokio_rustls::rustls::TLSError::General("Bad DNS name".into()))?;
            ck.cross_check_end_entity_cert(Some(checked_name))?;
            self.by_name.insert(name.into(), ck);
        }else{
            if self.default.is_some() {
                return Err( tokio_rustls::rustls::TLSError::General("More than one default Cert/Key".into()) );
            }
            self.default = Some(ck);
        }
        Ok(())
    }
}

impl ResolvesServerCert for ResolveServerCert {
    fn resolve(&self, client_hello: ClientHello) -> Option<CertifiedKey> {
        trace!("{:?}", client_hello.sigschemes()); // -> &[SignatureScheme]
        trace!("{:#?}", client_hello.alpn()); // -> Option<&'a [&'a [u8]]>

        if let Some(name) = client_hello.server_name() {
            self.by_name.get(name.into())
                .cloned()
        } else {
            // This kind of resolver requires SNI
            None
        }
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
    // Open keyfile.
    let keyfile = fs::File::open(filename)?;
    let mut reader = io::BufReader::new(keyfile);

    // Load and return a single private key.
    let keys = pemfile::rsa_private_keys(&mut reader).map_err(|_|io::Error::new(io::ErrorKind::InvalidData, "could not parse priv key"))?;
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
    let u1 = TlsUserConfig {
        cert_file: PathBuf::from("./test_cert.der"),
        key_file: PathBuf::from("./test_key.der"),
        ciphersuites: None,
        versions: None,
    };
    let p = ParsedTLSConfig::new(&u1, None);
}