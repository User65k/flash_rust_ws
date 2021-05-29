/*
More or less taken from rustls-acme/src/resolver.rs

Copyright <YEAR> <COPYRIGHT HOLDER>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

use rustls_acme::acme::{Account, Directory, Order, Auth, AcmeError, Identifier};
use futures_util::future::try_join_all;
use std::time::Duration;
use tokio::time::sleep;
use rcgen::{CertificateParams, DistinguishedName, PKCS_ECDSA_P256_SHA256, RcgenError};
use tokio_rustls::rustls::{
    PrivateKey,
    internal::pemfile,
    sign::{CertifiedKey, any_ecdsa_type}
};
use thiserror::Error;
use std::sync::Arc;
use std::io;
use async_std::path::Path;
use chrono::Utc;
use x509_parser::parse_x509_certificate;

pub async fn order<P, F>(
    set_auth_key: F,
    directory_url: impl AsRef<str>,
    domains: &Vec<String>,
    cache_dir: Option<P>,
    contact: &Vec<String>,
) -> Result<CertifiedKey, OrderError>
where P: AsRef<Path>, F: Fn(String, CertifiedKey) -> Result<(), AcmeError>
{
    let mut params = CertificateParams::new(domains.clone());
    params.distinguished_name = DistinguishedName::new();
    params.alg = &PKCS_ECDSA_P256_SHA256;
    let cert = rcgen::Certificate::from_params(params)?;
    let pk = any_ecdsa_type(&PrivateKey(cert.serialize_private_key_der())).unwrap();
    let directory = Directory::discover(directory_url).await?;
    let account = Account::load_or_create(directory, cache_dir, contact).await?;
    let mut order = account.new_order(domains.clone()).await?;
    loop {
        order = match order {
            Order::Pending {
                authorizations,
                finalize,
            } => {
                let auth_futures = authorizations
                    .iter()
                    .map(|url| authorize(&set_auth_key, &account, url));
                try_join_all(auth_futures).await?;
                log::info!("completed all authorizations");
                Order::Ready { finalize }
            }
            Order::Ready { finalize } => {
                log::info!("sending csr");
                let csr = cert.serialize_request_der()?;
                account.finalize(finalize, csr).await?
            }
            Order::Valid { certificate } => {
                log::info!("download certificate");
                let acme_cert_pem = account.certificate(certificate).await?;
                /*let pems = pem::parse_many(&acme_cert_pem);
                let cert_chain = pems
                    .into_iter()
                    .map(|p| RustlsCertificate(p.contents))
                    .collect();*/
                let mut rd = acme_cert_pem.as_bytes();
                let cert_chain = pemfile::certs(&mut rd)
                    .map_err(|_e| {
                        AcmeError::Io(io::Error::new(io::ErrorKind::InvalidInput, "Error reading Cert"))
                })?;
                let cert_key = CertifiedKey::new(cert_chain, Arc::new(pk));
                return Ok(cert_key);
            }
            Order::Invalid => return Err(OrderError::BadOrder(order)),
        }
    }
}
async fn authorize<F>(
    set_auth_key: &F,
    account: &Account,
    url: &String) -> Result<(), OrderError>
 where F: Fn(String, CertifiedKey) -> Result<(), AcmeError>
    {
    let (domain, challenge_url) = match account.auth(url).await? {
        Auth::Pending {
            identifier,
            challenges,
        } => {
            let Identifier::Dns(domain) = identifier;
            log::info!("trigger challenge for {}", &domain);
            let (challenge, auth_key) = account.tls_alpn_01(&challenges, domain.clone())?;
            set_auth_key(domain.clone(), auth_key)?;
            account.challenge(&challenge.url).await?;
            (domain, challenge.url.clone())
        }
        Auth::Valid => return Ok(()),
        auth => return Err(OrderError::BadAuth(auth)),
    };
    for i in 0u8..5 {
        sleep(Duration::from_secs(1u64 << i)).await;
        match account.auth(url).await? {
            Auth::Pending { .. } => {
                log::info!("authorization for {} still pending", &domain);
                account.challenge(&challenge_url).await?
            }
            Auth::Valid => return Ok(()),
            auth => return Err(OrderError::BadAuth(auth)),
        }
    }
    Err(OrderError::TooManyAttemptsAuth(domain))
}

pub fn duration_until_renewal_attempt(cert_key: Option<&CertifiedKey>, err_cnt: usize) -> Duration {
    let valid_until = match cert_key {
        None => 0,
        Some(cert_key) => match cert_key.cert.first() {
            Some(cert) => match parse_x509_certificate(cert.0.as_slice()) {
                Ok((_, cert)) => cert.validity().not_after.timestamp(),
                Err(err) => {
                    log::error!("could not parse certificate: {}", err);
                    0
                }
            },
            None => 0,
        },
    };
    let valid_secs = (valid_until - Utc::now().timestamp()).max(0);
    let wait_secs = Duration::from_secs(valid_secs as u64 / 2);
    match err_cnt {
        0 => wait_secs,
        err_cnt => wait_secs.max(Duration::from_secs(1 << err_cnt)),
    }
}

#[derive(Error, Debug)]
pub enum OrderError {
    #[error("acme error: {0}")]
    Acme(#[from] AcmeError),
    #[error("certificate generation error: {0}")]
    Rcgen(#[from] RcgenError),
    #[error("bad order object: {0:?}")]
    BadOrder(Order),
    #[error("bad auth object: {0:?}")]
    BadAuth(Auth),
    #[error("authorization for {0} failed too many times")]
    TooManyAttemptsAuth(String),
}