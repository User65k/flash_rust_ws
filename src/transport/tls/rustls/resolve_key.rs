
use log::{debug, trace};
use std::collections::HashMap;
use std::sync::RwLock;
use std::sync::Arc;
use tokio_rustls::rustls::{
    SignatureScheme,
    ClientHello, ResolvesServerCert,
    sign::{CertifiedKey, RSASigningKey, any_ecdsa_type, any_eddsa_type}
};
use super::{load_private_key, load_certs, KeySet};
#[cfg(feature = "tlsrust_acme")]
use async_acme::acme::ACME_TLS_ALPN_NAME;

pub struct CertKeys {
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
    #[cfg(feature = "tlsrust_acme")]
    acme_keys: RwLock<HashMap<String, CertifiedKey>>,
}
#[cfg(feature = "tlsrust_acme")]
impl CertKeys {
    pub fn ec(ck: CertifiedKey) -> CertKeys {
        CertKeys{
            rsa: None,
            ec: Some(ck),
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
        self.acme_keys.write().unwrap().insert(sni, cert);
    }
    #[inline]
    pub fn read_ec_cert<T, F>(&self, sni: Option<&str>, func: F) -> Option<T>
    where F: FnOnce(Option<&CertifiedKey>) -> T {
        self.read_cert(sni, |key|func(key.ec.as_ref()))
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
                keyset: &Vec<KeySet>) -> Result<(), tokio_rustls::rustls::TLSError> {

        let mut ident = CertKeys{rsa:None,ec:None, ed:None};
        for set in keyset {
            let k = load_private_key(&set.key).map_err(|_| tokio_rustls::rustls::TLSError::General("Bad Key file".into()))?;
            let chain = load_certs(&set.cert).map_err(|_| tokio_rustls::rustls::TLSError::General("Bad Cert file".into()))?;

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
    ///perform read only operation with a key/cert pair
    fn read_cert<T, F>(&self, sni: Option<&str>, func: F) -> Option<T>
    where F: FnOnce(&CertKeys) -> T {
        if let Some(k) = sni {
            let by_name = self.by_name.read().unwrap();
            by_name.get(k).map(func)
        }else{
            let default = self.default.read().unwrap();
            default.as_ref().map(func)
        }
    }
}

impl ResolvesServerCert for ResolveServerCert {
    fn resolve(&self, client_hello: ClientHello) -> Option<CertifiedKey> {
        #[cfg(feature = "tlsrust_acme")]
        if client_hello.alpn() == Some(&[ACME_TLS_ALPN_NAME]) {
            //return a not yet signed cert
            return match client_hello.server_name() {
                None => {
                    debug!("client did not supply SNI");
                    None
                }
                Some(domain) => {
                    self.acme_keys.read().unwrap().get(domain.into()).cloned()
                }
            }
        };
        //check what key types work with the client
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

        //this kinda impacts the chiper order - maybe coordinate with sess.config.ignore_client_order?
        self.read_cert(
            client_hello.server_name().map(|dns|dns.into()),
            |ks|{
                match (ks.ec.as_ref(), ks.ed.as_ref(), ks.rsa.as_ref(), ec, ed, rsa) {
                    (Some(k), _, _, true, _, _) => Some(k.clone()), //ec
                    (_, Some(k), _, _, true, _) => Some(k.clone()), //ed
                    (_, _, Some(k), _, _, true) => Some(k.clone()), //rsa
                    _ => None
                }
            }
        ).flatten()
    }
}