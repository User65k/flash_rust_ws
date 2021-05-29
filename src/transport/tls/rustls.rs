pub use tokio_rustls::{
    server::TlsStream as UnderlyingTLSStream,
    Accept as UnderlyingAccept,
    rustls::ServerConfig as TLSConfig
};
use tokio_rustls::TlsAcceptor as RustlsAcceptor;
use tokio_rustls::rustls::{
    Certificate, PrivateKey, NoClientAuth, SignatureScheme,
    internal::pemfile,
    SupportedCipherSuite, ALL_CIPHERSUITES, ProtocolVersion,
    ClientHello, ResolvesServerCert,
    sign::{CertifiedKey, RSASigningKey, any_ecdsa_type, any_eddsa_type}
};
use super::PlainIncoming;

use rustls_acme::acme::{ACME_TLS_ALPN_NAME, AcmeError};
use std::sync::RwLock;
use std::sync::Weak;
use tokio::time::sleep;
use super::rustls_acme_api::{order, duration_until_renewal_attempt};

use std::vec::Vec;
use std::sync::Arc;
use std::{fs, io};
use serde::Deserialize;
use std::path::PathBuf;
use log::{debug, trace, info, error};
use std::collections::HashMap;

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
    pub acme: Option<ACME>,
}
#[derive(Debug)]
#[derive(Deserialize)]
pub struct ACME {
    pub uri: String,
    pub contact: Vec<String>, //email?
    pub cache_dir: Option<PathBuf>,
    pub dns_names: Option<Vec<String>>,
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
        certres.add(sni, &config.host)?;

        let mut acmes = Vec::new();
        if let Some(acme) = &config.acme {
            Self::prep_acme(&mut acmes, acme, sni)?;
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

        self.certres.add(sni, &config.host)?;

        if let Some(acme) = &config.acme {
            Self::prep_acme(&mut self.acmes, acme, sni)?;
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
impl ParsedTLSConfig {
    fn prep_acme(acmes: &mut Vec<AcmeTaskRunner>,acme: &ACME, sni: Option<&str>) -> Result<(), io::Error>{
        let dns_names = match &acme.dns_names
        {
            Some(a) => a.clone(),
            None => match sni {
                Some(s) => vec![s.to_string()],
                None => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "ACME needs either an enforced vHost or dns_names specified"
                    ));
                }
            }
        };
        let has_name = sni.map(|s|s.to_string());
        acmes.push(AcmeTaskRunner {
            uri: acme.uri.clone(),
            contact: acme.contact.clone(),
            cache_dir: acme.cache_dir.clone(),
            dns_names,
            certres: Weak::new(),
            has_name
        });
        Ok(())
    }
}

struct AcmeTaskRunner {
    /// resolver to update with a new cert
    certres: Weak<ResolveServerCert>,
    /// what to update
    has_name: Option<String>,
    /// acme register to use
    uri: String,
    /// for acme request
    contact: Vec<String>,
    /// to store acme auth (and certs)
    cache_dir: Option<PathBuf>,
    /// dns to proof
    /// all but has_name will end up with the default server name
    dns_names: Vec<String>,
}

struct CertKeys {
    rsa: Option<CertifiedKey>,
    ec: Option<CertifiedKey>,
    ed: Option<CertifiedKey>
}

pub struct ResolveServerCert {
    /// certs by sni
    by_name: RwLock<HashMap<String, CertKeys>>,
    /// cert that is used by all other sni
    default: RwLock<Option<CertKeys>>,
    /// temp for acme challange
    acme_keys: RwLock<HashMap<String, CertifiedKey>>,
}

impl ResolveServerCert {
    /// Create a new and empty (ie, knows no certificates) resolver.
    pub fn new() -> ResolveServerCert {
        ResolveServerCert {
            by_name: RwLock::new(HashMap::new()),
            default: RwLock::new(None),
            acme_keys: RwLock::new(HashMap::new())
        }
    }

    /// Add a new `KeySet` (One Certificate with Key for each Keytype) to be used for the given `sni`.
    ///
    /// This function fails if the certificate chain is syntactically faulty
    /// or if `sni` is given but not a valid DNS name, or if
    /// it's not valid for the supplied certificate.
    pub fn add(&mut self, sni: Option<&str>,
                keyset: &Vec<KeySet>) -> Result<(), tokio_rustls::rustls::TLSError> {

        let mut ident = CertKeys{rsa:None,ec:None, ed:None};
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
        if let Some(name) = sni {
            let mut name_map = self.by_name.write().unwrap();
            name_map.insert(name.into(), ident);
        }else{
            let mut default = self.default.write().unwrap();
            if default.is_some() {
                return Err( tokio_rustls::rustls::TLSError::General("More than one default Cert/Key".into()) );
            }
            *default = Some(ident);
        }
        Ok(())
    }
}

/// ACME
impl AcmeTaskRunner {
    pub fn start(self, certres: &Arc<ResolveServerCert>) {
        let mut task = self;
        task.certres  = Arc::downgrade(certres);
        tokio::spawn(async move {
            task.acme_watcher().await;
        });
    }

    async fn acme_watcher(&self) {
        let mut err_cnt = 0usize;
        loop {
            let d = match self.certres.upgrade() {
                None => {
                    //ResolveServerCert is gone (and so is the TlsAcceptor)
                    break;
                }
                Some(resolver) => {
                    //check how long the current cert is still valid
                    let maybe = if let Some(k) = &self.has_name {
                        let by_name = resolver.by_name.read().unwrap();
                        by_name.get(k).map(|key| duration_until_renewal_attempt(key.ec.as_ref(), err_cnt))
                    }else{
                        let default = resolver.default.read().unwrap();
                        default.as_ref().map(|key| duration_until_renewal_attempt(key.ec.as_ref(), err_cnt))
                    };
                    maybe.unwrap_or_else(||duration_until_renewal_attempt(None, err_cnt))
                }
            };
            if d.as_secs() != 0 {
                info!("next renewal attempt in {}s", d.as_secs());
                sleep(d).await;
            }
            match order(
                |k,v|self.set_auth_key(k,v),
                &self.uri,
                &self.dns_names,
                self.cache_dir.as_ref(),
                &self.contact).await {
                Err(e) => {
                    error!("ACME {}", e);
                    err_cnt += 1;
                },
                Ok(cert_key) => {
                    //let pk_pem = cert.serialize_private_key_pem();
                    //Self::save_certified_key(cache_dir, file_name, pk_pem, acme_cert_pem).await;

                    match self.certres.upgrade() {
                        None => {
                            //ResolveServerCert is gone (and so is the TlsAcceptor)
                            break;
                        }
                        Some(resolver) => {
                            let v = CertKeys{
                                rsa: None,
                                ec: Some(cert_key),
                                ed: None
                            };
                            if let Some(k) = &self.has_name {
                                resolver.by_name.write().unwrap().insert(k.to_owned(), v);
                            }else{
                                resolver.default.write().unwrap().replace(v);
                            }
                        }
                    }
                    err_cnt = 0;
                }
            }
        }
    }
    fn set_auth_key(&self, key: String, cert: CertifiedKey) -> Result<(),AcmeError> {
        match self.certres.upgrade() {
            Some(resolver) => {
                resolver.acme_keys.write().unwrap().insert(key, cert);
                Ok(())
            },
            None => Err(std::io::Error::new(io::ErrorKind::BrokenPipe,"TLS shut down").into())
        }
    }
}

impl ResolvesServerCert for ResolveServerCert {
    fn resolve(&self, client_hello: ClientHello) -> Option<CertifiedKey> {
        //client_hello.alpn() -> Option<&'a [&'a [u8]]>
        if client_hello.alpn() == Some(&[ACME_TLS_ALPN_NAME]) {
            //return a not yet signed cert
            return match client_hello.server_name() {
                None => {
                    debug!("client did not supply SNI");
                    None
                }
                Some(domain) => {
                    let domain = domain.to_owned();
                    let domain: String = AsRef::<str>::as_ref(&domain).to_string();
                    self.acme_keys.read().unwrap().get(&domain).cloned()
                }
            }
        };
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

        let by_name = self.by_name.read().unwrap();
        let default = self.default.read().unwrap();
        let ks = client_hello.server_name().and_then(|name| by_name.get(name.into()))
                                    .or(default.as_ref());

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
        acme: None,
    };
    let p = ParsedTLSConfig::new(&u1, None);
}