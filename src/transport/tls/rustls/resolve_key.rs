
use log::{debug, trace};
use std::collections::HashMap;
use std::sync::RwLock;
use std::sync::Arc;
use tokio_rustls::rustls::{
    SignatureScheme, Error,
    server::{ClientHello, ResolvesServerCert},
    sign::{CertifiedKey, RsaSigningKey, any_ecdsa_type, any_eddsa_type}
};
use super::{load_private_key, load_certs, KeySet};
#[cfg(feature = "tlsrust_acme")]
use async_acme::acme::ACME_TLS_ALPN_NAME;

pub struct CertKeys {
    rsa: Option<Arc<CertifiedKey>>,
    ec:  Option<Arc<CertifiedKey>>,
    ed:  Option<Arc<CertifiedKey>>
}

pub struct ResolveServerCert {
    /// certs by sni
    by_name: RwLock<HashMap<String, CertKeys>>,
    /// cert that is used by all other sni
    default: RwLock<Option<CertKeys>>,
    /// temp for acme challange
    #[cfg(feature = "tlsrust_acme")]
    acme_keys: RwLock<HashMap<String, Arc<CertifiedKey>>>,
}
#[cfg(feature = "tlsrust_acme")]
impl CertKeys {
    pub fn ec(ck: CertifiedKey) -> CertKeys {
        CertKeys{
            rsa: None,
            ec: Some(Arc::new(ck)),
            ed: None
        }
    }
}
#[cfg(feature = "tlsrust_acme")]
impl ResolveServerCert {
    #[inline]
    pub fn update_cert(&self, mut sni: Option<String>, cert: CertKeys) {
        if let Some(k) = sni.take() {
            self.by_name.write().unwrap().insert(k, cert);
        }else{
            self.default.write().unwrap().replace(cert);
        }
    }
    #[inline]
    pub fn set_acme_cert(&self, sni: String, cert: CertifiedKey) {
        self.acme_keys.write().unwrap().insert(sni, Arc::new(cert));
    }
    #[inline]
    pub fn read_ec_cert<T, F>(&self, sni: Option<&str>, func: F) -> Option<T>
    where F: FnOnce(Option<&CertifiedKey>) -> T {
        self.read_cert(sni, |key|func(key.ec.as_deref()), false)
    }
}
impl ResolveServerCert {
    /// Create a new and empty (ie, knows no certificates) resolver.
    pub fn new() -> ResolveServerCert {
        ResolveServerCert {
            by_name: RwLock::new(HashMap::new()),
            default: RwLock::new(None),
            #[cfg(feature = "tlsrust_acme")]
            acme_keys: RwLock::new(HashMap::new())
        }
    }

    /// Add a new `KeySet` (One Certificate with Key for each Keytype) to be used for the given `sni`.
    ///
    /// This function fails if the certificate chain is syntactically faulty
    /// or if `sni` is given but not a valid DNS name, or if
    /// it's not valid for the supplied certificate.
    pub fn add(&mut self, sni: Option<&str>,
                keyset: &[KeySet]) -> Result<(), Error> {

        let mut ident = CertKeys{rsa:None,ec:None, ed:None};
        for set in keyset {
            let k = load_private_key(&set.key).map_err(|_| Error::General("Bad Key file".into()))?;
            let chain = load_certs(&set.cert).map_err(|_| Error::General("Bad Cert file".into()))?;

            if let Ok(rsa) = RsaSigningKey::new(&k) {
                if ident.rsa.is_some() {
                    return Err(Error::General("More than one RSA key".into()));
                }
                let key = Arc::new(rsa);
                let ck = Arc::new(CertifiedKey::new(chain, key));
                debug!("added RSA Cert");
                ident.rsa = Some(ck);
            }else if let Ok(key) = any_ecdsa_type(&k) {
                if ident.ec.is_some() {
                    return Err(Error::General("More than one EC key".into()));
                }
                let ck = Arc::new(CertifiedKey::new(chain, key));
                debug!("added EC Cert");
                ident.ec = Some(ck);
            }else if let Ok(key) = any_eddsa_type(&k) {
                if ident.ed.is_some() {
                    return Err(Error::General("More than one ED key".into()));
                }
                let ck = Arc::new(CertifiedKey::new(chain, key));
                debug!("added ED Cert");
                ident.ed = Some(ck);
            }else{
                return Err(Error::General("Bad key type".into()));
            }
        }
        if let Some(name) = sni {
            let mut name_map = self.by_name.write().unwrap();
            name_map.insert(name.into(), ident);
        }else{
            let mut default = self.default.write().unwrap();
            if default.is_some() {
                return Err( Error::General("More than one default Cert/Key".into()) );
            }
            *default = Some(ident);
        }
        Ok(())
    }
    ///perform read only operation with a key/cert pair
    fn read_cert<T, F>(&self, sni: Option<&str>, func: F, fallback: bool) -> Option<T>
    where F: FnOnce(&CertKeys) -> T {
        if let Some(k) = sni {
            if let Some(v) = self.by_name.read().unwrap().get(k) {
                return Some(func(v));
            }
            if !fallback {
                return None;
            }
            //SNI set but we don't know it -> use default
        }
        self.default.read().unwrap().as_ref().map(func)
    }
}

impl ResolvesServerCert for ResolveServerCert {
    fn resolve(&self, client_hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        #[cfg(feature = "tlsrust_acme")]
        if client_hello.alpn().and_then(|mut f|f.find(|alpn|*alpn==ACME_TLS_ALPN_NAME)).is_some() {
            //return a not yet signed cert
            return match client_hello.server_name() {
                None => {
                    debug!("client did not supply SNI");
                    None
                }
                Some(domain) => {
                    self.acme_keys.read().unwrap().get(domain).cloned()
                }
            }
        };
        //check what key types work with the client
        let mut ed = false;
        let mut ec = false;
        let mut rsa = false;
        for s in client_hello.signature_schemes() {
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
        trace!("ec: {}, ed: {}, rsa: {} - {:?}", ec, ed, rsa, client_hello.signature_schemes());
                
        //this kinda impacts the chiper order - maybe coordinate with sess.config.ignore_client_order?
        self.read_cert(
            client_hello.server_name(),
            |ks|{
                match (ks.ec.as_ref(), ks.ed.as_ref(), ks.rsa.as_ref(), ec, ed, rsa) {
                    (Some(k), _, _, true, _, _) => Some(k.clone()), //ec
                    (_, Some(k), _, _, true, _) => Some(k.clone()), //ed
                    (_, _, Some(k), _, _, true) => Some(k.clone()), //rsa
                    _ => None
                }
            },
            true
        ).flatten()
    }
}
