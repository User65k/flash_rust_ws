use async_acme::acme::{Account, AcmeError, Directory};
use async_acme::rustls_helper::{drive_order, duration_until_renewal_attempt, OrderError};

use super::resolve_key::{CertKeys, ResolveServerCert};
use super::{load_certs, load_private_key};
use log::{error, info};
use serde::Deserialize;
use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Weak;
use std::vec::Vec;
use tokio::time::sleep;
use tokio_rustls::rustls::{crypto::ring::sign::any_ecdsa_type, sign::CertifiedKey};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ACME {
    pub uri: String,
    pub contact: Vec<String>, //email?
    pub cache_dir: PathBuf,
    pub dns_names: Option<Vec<String>>,
}
pub struct AcmeTaskRunner {
    /// resolver to update with a new cert
    certres: Weak<ResolveServerCert>,
    /// what to update
    has_name: Option<String>,
    /// acme register to use
    uri: String,
    /// for acme request
    contact: Vec<String>,
    /// to store acme auth (and certs)
    cache_dir: PathBuf,
    /// dns to proof
    /// all but has_name will end up with the default server name
    dns_names: Vec<String>,
}
impl AcmeTaskRunner {
    pub fn add_new(
        acmes: &mut Vec<AcmeTaskRunner>,
        acme: &ACME,
        sni: Option<&str>,
    ) -> Result<(), io::Error> {
        let dns_names = match &acme.dns_names {
            Some(a) => a.clone(),
            None => match sni {
                Some(s) => vec![s.to_string()],
                None => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "ACME needs either an enforced vHost or dns_names specified",
                    ));
                }
            },
        };
        let has_name = sni.map(|s| s.to_string());
        acmes.push(AcmeTaskRunner {
            uri: acme.uri.clone(),
            contact: acme.contact.clone(),
            cache_dir: acme.cache_dir.clone(),
            dns_names,
            certres: Weak::new(),
            has_name,
        });
        Ok(())
    }

    pub fn start(self, certres: &Arc<ResolveServerCert>) {
        let mut task = self;

        let filename = task.get_cert_cache_file();
        if let (Ok(k), Ok(chain)) = (load_private_key(&filename), load_certs(&filename)) {
            if let Ok(key) = any_ecdsa_type(&k) {
                let ck = CertifiedKey::new(chain, key);
                let v = CertKeys::ec(ck);

                certres.update_cert(task.has_name.clone(), v);
            }
        }

        task.certres = Arc::downgrade(certres);
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
                    resolver
                        .read_ec_cert(self.has_name.as_deref(), |key| {
                            duration_until_renewal_attempt(key, err_cnt)
                        })
                        .unwrap_or_else(|| duration_until_renewal_attempt(None, err_cnt))
                }
            };
            if d.as_secs() != 0 {
                info!(
                    "ACME: next attempt for {:?} in {}s",
                    self.dns_names,
                    d.as_secs()
                );
                sleep(d).await;
            }
            match self.order_and_cache().await {
                Err(e) => {
                    error!("ACME {}", e);
                    err_cnt += 1;
                }
                Ok(cert_key) => {
                    match self.certres.upgrade() {
                        None => {
                            //ResolveServerCert is gone (and so is the TlsAcceptor)
                            break;
                        }
                        Some(resolver) => {
                            let v = CertKeys::ec(cert_key);
                            resolver.update_cert(self.has_name.clone(), v);
                        }
                    }
                    err_cnt = 0;
                }
            }
        }
    }
    async fn order_and_cache(&self) -> Result<CertifiedKey, OrderError> {
        let directory = Directory::discover(&self.uri).await?;
        let account =
            Account::load_or_create(directory, Some(&self.cache_dir), &self.contact).await?;

        let (cert_key, key_pem, cert_pem) = drive_order(
            |k, v| self.set_auth_key(k, v),
            self.dns_names.clone(),
            account,
        )
        .await?;

        let file = self.get_cert_cache_file();
        let content = format!("{}\n{}", key_pem, cert_pem);
        tokio::fs::write(&file, &content)
            .await
            .map_err(AcmeError::Io)?;

        Ok(cert_key)
    }
    fn set_auth_key(&self, key: String, cert: CertifiedKey) -> Result<(), AcmeError> {
        match self.certres.upgrade() {
            Some(resolver) => {
                resolver.set_acme_cert(key, cert);
                Ok(())
            }
            None => Err(std::io::Error::new(io::ErrorKind::BrokenPipe, "TLS shut down").into()),
        }
    }
    #[inline]
    fn get_cert_cache_file(&self) -> PathBuf {
        //unwrap ok, as there must be at least on dns_name (see prep_acme)
        self.cache_dir.join(self.dns_names.get(0).unwrap())
    }
}
