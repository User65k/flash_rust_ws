pub use tokio_rustls::{server::TlsStream as UnderlyingTLSStream, Accept as UnderlyingAccept};
pub use tokio_rustls::rustls::ServerConfig as TLSConfig;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::{Certificate, PrivateKey, NoClientAuth, SignatureScheme};
use tokio_rustls::rustls::internal::pemfile;
use tokio_rustls::rustls::{SupportedCipherSuite, ALL_CIPHERSUITES, ProtocolVersion};
use tokio_rustls::rustls::{ClientHello, ResolvesServerCert};
use tokio_rustls::rustls::sign::{CertifiedKey, RSASigningKey, any_ecdsa_type, any_eddsa_type};

use std::vec::Vec;
use std::sync::Arc;
use std::{fs, io};
use serde::Deserialize;
use std::path::PathBuf;
use log::{debug, trace};

use super::{PlainStream, TLSBuilderTrait};

#[derive(Debug)]
#[derive(Deserialize)]
pub struct KeySet {
    pub cert_file: PathBuf,
    pub key_file: PathBuf,
}
#[derive(Debug)]
#[derive(Deserialize)]
pub struct TlsUserConfig {
    pub host: Vec<KeySet>,
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
        cfg.set_protocols(&[b"h2".to_vec(), b"http/1.1".to_vec(), b"acme-tls/1".to_vec()]);

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
        certres.add(sni, &config.host)?;
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

        self.certres.add(sni, &config.host)?;

        Ok(())
    }
    fn get_config(mut self) -> TLSConfig {
        self.cfg.cert_resolver = Arc::new(self.certres);
        self.cfg
    }
}

struct CertKeys {
    rsa: Option<CertifiedKey>,
    ec: Option<CertifiedKey>,
    ed: Option<CertifiedKey>
}

pub struct ResolveServerCert {
    by_name: std::collections::HashMap<String, CertKeys>,
    default: Option<CertKeys>
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
                keyset: &Vec<KeySet>) -> Result<(), tokio_rustls::rustls::TLSError> {
        
        let ident = if let Some(name) = sni {
            self.by_name.insert(name.into(), CertKeys{rsa:None,ec:None, ed:None});
            self.by_name.get_mut(name.into()).unwrap()
        }else{
            if self.default.is_some() {
                return Err( tokio_rustls::rustls::TLSError::General("More than one default Cert/Key".into()) );
            }
            self.default = Some(CertKeys{rsa:None,ec:None, ed:None});
            self.default.as_mut().unwrap()
        };
        for set in keyset {
            let k = load_private_key(&set.key_file).map_err(|_| tokio_rustls::rustls::TLSError::General("Bad Key file".into()))?;
            let chain = load_certs(&set.cert_file).map_err(|_| tokio_rustls::rustls::TLSError::General("Bad Cert file".into()))?;
            
            if let Ok(rsa) = RSASigningKey::new(&k) {
                if ident.rsa.is_some() {
                    return Err(tokio_rustls::rustls::TLSError::General("More than one RSA key".into()));
                }
                let key = Box::new(rsa);
                let ck = CertifiedKey::new(chain, Arc::new(key));
                debug!("added RSA Cert");
                ident.rsa = Some(ck);
            }else if let Ok(key) = any_ecdsa_type(&k) {
                if ident.ec.is_some() {
                    return Err(tokio_rustls::rustls::TLSError::General("More than one EC key".into()));
                }                
                let ck = CertifiedKey::new(chain, Arc::new(key));
                debug!("added EC Cert");
                ident.ec = Some(ck);
            }else if let Ok(key) = any_eddsa_type(&k) {
                if ident.ed.is_some() {
                    return Err(tokio_rustls::rustls::TLSError::General("More than one ED key".into()));
                }
                let ck = CertifiedKey::new(chain, Arc::new(key));
                debug!("added ED Cert");
                ident.ed = Some(ck);
            }else{
                return Err(tokio_rustls::rustls::TLSError::General("Bad key type".into()));
            }
        }
        // check if all certs are usable with the vHost
        if let Some(name) = sni {
            let checked_name = tokio_rustls::webpki::DNSNameRef::try_from_ascii_str(name)
                .map_err(|_| tokio_rustls::rustls::TLSError::General("Bad DNS name".into()))?;
            if let Some(ck) = &ident.rsa {
                ck.cross_check_end_entity_cert(Some(checked_name))?;
            }
            if let Some(ck) = &ident.ec {
                ck.cross_check_end_entity_cert(Some(checked_name))?;
            }
            if let Some(ck) = &ident.ed {
                ck.cross_check_end_entity_cert(Some(checked_name))?;
            }
        }
        Ok(())
    }
}

impl ResolvesServerCert for ResolveServerCert {
    fn resolve(&self, client_hello: ClientHello) -> Option<CertifiedKey> {
        //client_hello.alpn() -> Option<&'a [&'a [u8]]>
        client_hello.alpn().and_then(|a|{
            for alp in a {
                if alp==b"acme-tls/1" {
                    return Some(())
                }
            }
            None
        });
        let mut ed = false;
        let mut ec = false;
        let mut rsa = false;
        for s in client_hello.sigschemes() {
            match s {
                SignatureScheme::ECDSA_SHA1_Legacy |
                SignatureScheme::ECDSA_NISTP256_SHA256 |
                SignatureScheme::ECDSA_NISTP384_SHA384 |
                SignatureScheme::ECDSA_NISTP521_SHA512 => {
                    ec = true;
                    if rsa && ed {
                        break;
                    }
                },
                SignatureScheme::ED25519 |
                SignatureScheme::ED448 => {
                    ed = true;
                    if rsa && ec {
                        break;
                    }
                },
                SignatureScheme::RSA_PKCS1_SHA1 |
                SignatureScheme::RSA_PKCS1_SHA256 |
                SignatureScheme::RSA_PKCS1_SHA384 |
                SignatureScheme::RSA_PKCS1_SHA512 => {
                    rsa = true;
                    if ec && ed {
                        break;
                    }
                },
                _ => {},
            }
        }
        trace!("ec: {}, ed: {}, rsa: {} - {:?}", ec, ed, rsa, client_hello.sigschemes());

        let ks = client_hello.server_name().and_then(|name|self.by_name.get(name.into()))
                                    .or(self.default.as_ref());

        //this kinda impacts the chiper order - maybe coordinate with sess.config.ignore_client_order?
        if let Some(ks) = ks {
            match (ks.ec.as_ref(), ks.ed.as_ref(), ks.rsa.as_ref(), ec, ed, rsa) {
                (Some(k), _, _, true, _, _) => Some(k.clone()), //ec
                (_, Some(k), _, _, true, _) => Some(k.clone()), //ed
                (_, _, Some(k), _, _, true) => Some(k.clone()), //rsa
                _ => None
            }
        }else{
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
        cert_file: PathBuf::from("./test_cert.der"),
        key_file: PathBuf::from("./test_key.der")
    };
    let u1 = TlsUserConfig {
        host: vec![ks],
        ciphersuites: None,
        versions: None,
    };
    let p = ParsedTLSConfig::new(&u1, None);
}