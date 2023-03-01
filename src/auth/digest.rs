use crate::auth::{get_map_from_header, strip_prefix};
use hyper::{header, Body, Request, Response, StatusCode};
use lazy_static::lazy_static;
use log::{info, trace};
use md5::Context;
use rand::rngs::OsRng;
use rand::RngCore;
use std::io::{Error as IoError, ErrorKind};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::fs::File;
use tokio::io::{AsyncBufReadExt, BufReader};

use bytes::Bytes;
use log::{log_enabled, Level::Trace};

lazy_static! {
    static ref NONCESTARTHASH: Context = {
        let rnd = OsRng.next_u64();

        let mut h = Context::new();
        h.consume(rnd.to_be_bytes());
        h.consume(std::process::id().to_be_bytes());
        h
    };
}

fn create_resp_needs_auth(realm: &str, stale: bool) -> Response<Body> {
    let str_stale = if stale { "stale=true," } else { "" };
    let p = format!(
        "Digest realm=\"{}\",nonce=\"{}\",{}qop=\"auth\"",
        realm,
        create_nonce(),
        str_stale
    );

    let b = Response::builder().status(StatusCode::UNAUTHORIZED).header(
        header::WWW_AUTHENTICATE,
        header::HeaderValue::from_str(&format!("{},algorithm=\"MD5-sess\"", &p)).unwrap(),
    );

    let b = b.header(
        header::WWW_AUTHENTICATE,
        header::HeaderValue::from_str(&format!("{},algorithm=\"MD5\"", &p)).unwrap(),
    );

    b.body(Body::empty()).expect("unable to build response")
}

/// 34 char nonce
/// time+md5(rnd+pid+time)
fn create_nonce() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("creating nonces from before UNIX epoch not supported");
    let secs = now.as_secs() as u32;
    let mut h = NONCESTARTHASH.clone();
    h.consume(secs.to_be_bytes());

    let n = format!("{:08x}{:032x}", secs, h.compute());
    n[..34].to_string()
}

/// Check if a nonce is still valid.
/// Return an error if it was never valid
fn validate_nonce(nonce: &[u8]) -> Result<bool, ()> {
    if nonce.len() != 34 {
        return Err(());
    }
    //parse hex
    if let Ok(n) = std::str::from_utf8(nonce) {
        //get time
        if let Ok(secs_nonce) = u32::from_str_radix(&n[..8], 16) {
            //check time
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("creating nonces from before UNIX epoch not supported");
            let secs_now = now.as_secs() as u32;

            if let Some(dur) = secs_now.checked_sub(secs_nonce) {
                //check hash
                let mut h = NONCESTARTHASH.clone();
                h.consume(secs_nonce.to_be_bytes());
                let h = format!("{:x}", h.compute());
                if h[..26] == n[8..34] {
                    return Ok(dur < 300); // from the last 5min
                                          //Authentication-Info ?
                }
            }
        }
    }
    Err(())
}

pub async fn check_digest(
    auth_file: &Path,
    req: &Request<Body>,
    realm: &str,
) -> Result<Option<Response<Body>>, IoError> {
    match req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|h| strip_prefix(h.as_bytes(), b"Digest "))
    {
        None => Ok(Some(create_resp_needs_auth(realm, false))),
        Some(header) => {
            if let Ok(user_vals) = get_map_from_header(header) {
                if log_enabled!(Trace) {
                    use std::collections::HashMap;

                    let h: HashMap<Bytes, Bytes> = user_vals
                        .clone()
                        .into_iter()
                        .map(|(k, v)| (Bytes::copy_from_slice(k), Bytes::copy_from_slice(v)))
                        .collect();
                    trace!("from header: {:?}", h);
                }

                if let (Some(username), Some(nonce), Some(user_response)) = (
                    user_vals
                        .get(b"username".as_ref())
                        .and_then(|b| std::str::from_utf8(*b).ok()),
                    user_vals.get(b"nonce".as_ref()),
                    user_vals.get(b"response".as_ref()),
                ) {
                    //check if the nonce is from us
                    #[cfg(not(test))]
                    match validate_nonce(nonce) {
                        Ok(true) => {}                                                     // good
                        Ok(false) => return Ok(Some(create_resp_needs_auth(realm, true))), // old
                        Err(()) => {
                            return Err(IoError::new(ErrorKind::PermissionDenied, "Invalid Nonce"))
                        } // strange
                    }

                    let file = File::open(auth_file).await?;
                    let mut file = BufReader::new(file);

                    //read HA1 from file
                    //HA1 = make_md5(username+":"+realm+":"+password)
                    let mut ha1 = loop {
                        let mut buf = String::new();
                        if file.read_line(&mut buf).await? < 1 {
                            //user not found
                            info!("user not found");
                            //don't return to avaid timing attacks
                            break "USERNOTFOUND".to_string();
                        }
                        if buf.starts_with(username) {
                            //user:realm:H1
                            let p: Vec<&str> = buf.split(':').collect();
                            if p.len() == 3 && p[1] == realm && p[0].len() == username.len() {
                                break p[2].trim_end().to_string();
                            }
                        }
                    };
                    let mut ha2 = Context::new();
                    ha2.consume(req.method().as_str());
                    ha2.consume(b":");
                    if let Some(uri) = user_vals.get(b"uri".as_ref()) {
                        ha2.consume(uri);
                    }
                    let ha2 = format!("{:x}", ha2.compute());

                    let mut correct_response = None;
                    if let Some(qop) = user_vals.get(b"qop".as_ref()) {
                        if let Some(algorithm) = user_vals.get(b"algorithm".as_ref()) {
                            if algorithm == &b"MD5-sess".as_ref() {
                                trace!("MD5-sess");
                                ha1 = {
                                    let mut c = Context::new();
                                    c.consume(&ha1);
                                    c.consume(b":");
                                    c.consume(nonce);
                                    c.consume(b":");
                                    if let Some(cnonce) = user_vals.get(b"cnonce".as_ref()) {
                                        c.consume(cnonce);
                                    }
                                    format!("{:x}", c.compute())
                                };
                            }
                        }
                        if qop == &b"auth".as_ref() || qop == &b"auth-int".as_ref() {
                            trace!("qop: auth");
                            correct_response = Some({
                                let mut c = Context::new();
                                c.consume(&ha1);
                                c.consume(b":");
                                c.consume(nonce);
                                c.consume(b":");
                                if let Some(nc) = user_vals.get(b"nc".as_ref()) {
                                    c.consume(nc);
                                }
                                c.consume(b":");
                                if let Some(cnonce) = user_vals.get(b"cnonce".as_ref()) {
                                    c.consume(cnonce);
                                }
                                c.consume(b":");
                                c.consume(qop);
                                c.consume(b":");
                                c.consume(&*ha2);
                                format!("{:x}", c.compute())
                            });
                        }
                    }
                    let correct_response = match correct_response {
                        Some(r) => r,
                        None => {
                            let mut c = Context::new();
                            c.consume(&ha1);
                            c.consume(b":");
                            c.consume(nonce);
                            c.consume(b":");
                            c.consume(&*ha2);
                            format!("{:x}", c.compute())
                        }
                    };
                    return if correct_response.as_bytes() == *user_response {
                        // grant access
                        Ok(None)
                    } else {
                        info!(
                            "user {} auth failed {}!={:?}",
                            username,
                            correct_response,
                            Bytes::copy_from_slice(*user_response)
                        );
                        // wrong PW
                        Ok(Some(create_resp_needs_auth(realm, false)))
                    };
                }
            }
            //there is an auth header, but its garbage - at least to us
            Err(IoError::new(ErrorKind::InvalidData, "auth failed"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dispatch::test::TempFile;
    use crate::logging::init_stderr_logging;
    use std::path::PathBuf;

    fn create_req(header: Option<&str>) -> Request<Body> {
        match header {
            Some(h) => Request::builder()
                .header(header::AUTHORIZATION, h)
                .body(Body::empty())
                .unwrap(),
            None => Request::new(Body::empty()),
        }
    }

    #[tokio::test]
    async fn auth_required() {
        let path = PathBuf::from(r"/tmp/abc");
        let e = check_digest(&path, &create_req(None), &String::from("abc"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(e.status(), StatusCode::UNAUTHORIZED);
    }
    #[tokio::test]
    async fn auth_success() {
        let f = TempFile::create(
            r"auth_suc",
            b"dani:a realm:0d1bfde1dbff91ac4b0c219dec6fc86a",
        );

        let h = create_req(Some("Digest username=\"dani\", realm=\"a realm\", nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", uri=\"/cool\", response=\"8a1415c70ae45a88a2a83f896b30bfc3\""));
        let e = check_digest(f.get_path(), &h, &String::from("a realm"))
            .await
            .unwrap();
        assert!(e.is_none());
    }
    #[tokio::test]
    async fn auth_success_multi() {
        let f = TempFile::create(
            r"auth_suc0",
            b"egal:1:1\r\ndani:a realm:0d1bfde1dbff91ac4b0c219dec6fc86a\r\n",
        );

        let h = create_req(Some("Digest username=\"dani\", realm=\"a realm\", nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", uri=\"/cool\", response=\"8a1415c70ae45a88a2a83f896b30bfc3\""));
        let e = check_digest(f.get_path(), &h, &String::from("a realm"))
            .await
            .unwrap();
        assert!(e.is_none());
    }
    #[tokio::test]
    async fn auth_success_sess() {
        let f = TempFile::create(
            r"auth_suc2",
            b"dani:a realm:0d1bfde1dbff91ac4b0c219dec6fc86a",
        );

        let h = create_req(Some("Digest username=\"dani\", realm=\"a realm\", nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", uri=\"/favicon.ico\", algorithm=MD5-sess, response=\"f02dcc493b488cc25d503c15765a3005\", qop=auth, nc=00000002, cnonce=\"30d60c5e1664d9cb\""));
        let e = check_digest(f.get_path(), &h, &String::from("a realm"))
            .await
            .unwrap();
        assert!(e.is_none());
    }
    #[tokio::test]
    async fn auth_success_qop_auth() {
        let f = TempFile::create(
            r"auth_suc3",
            b"dani:a realm:0d1bfde1dbff91ac4b0c219dec6fc86a",
        );

        let h = create_req(Some("Digest username=\"dani\", realm=\"a realm\", nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", uri=\"/\", response=\"d2f5ad3b664dd98d2dcb700d8027afec\", qop=auth, nc=00000001, cnonce=\"ceee320d38ca229e\""));
        let e = check_digest(f.get_path(), &h, &String::from("a realm"))
            .await
            .unwrap();
        assert!(e.is_none());
    }
    #[tokio::test]
    async fn auth_wrong_pw() {
        init_stderr_logging();
        let f = TempFile::create(
            r"auth_fail",
            b"dani:a realm:0d1bfde1dbff91ac4b0c219dec6fc86a",
        );

        let h = create_req(Some("Digest username=\"dani\", realm=\"a realm\", nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", uri=\"/cool\", response=\"7a1415c70ae45a88a2a83f896b30bfc3\""));
        let e = check_digest(f.get_path(), &h, &String::from("a realm"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(e.status(), StatusCode::UNAUTHORIZED);
    }
    #[tokio::test]
    async fn auth_wrong_user() {
        let f = TempFile::create(
            r"auth_nouser",
            b"daniel:a realm:109c7da4a649a1da4a35843583146140",
        );

        let h = create_req(Some("Digest username=\"dani\", realm=\"a realm\", nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", uri=\"/cool\", response=\"8a1415c70ae45a88a2a83f896b30bfc3\""));
        let e = check_digest(f.get_path(), &h, &String::from("a realm"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(e.status(), StatusCode::UNAUTHORIZED);
    }
    #[tokio::test]
    async fn auth_wrong_realm() {
        let f = TempFile::create(
            r"auth_realm",
            b"dani:another realm:1a30634ead89d6934aa82b933863acf3",
        );

        let h = create_req(Some("Digest username=\"dani\", realm=\"a realm\", nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", uri=\"/cool\", response=\"8a1415c70ae45a88a2a83f896b30bfc3\""));
        let e = check_digest(f.get_path(), &h, &String::from("a realm"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(e.status(), StatusCode::UNAUTHORIZED);
    }
    #[tokio::test]
    async fn auth_error() {
        let path = PathBuf::from(r"/tmp/abc");
        let h = create_req(Some("Digest username=\"dani\""));
        let e = check_digest(&path, &h, &String::from("abc"))
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::InvalidData);

        let h = create_req(Some("Digest ===,,"));
        let e = check_digest(&path, &h, &String::from("abc"))
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::InvalidData);
    }
    #[test]
    fn nonce() {
        //fresh one is ok
        assert!(validate_nonce(create_nonce().as_bytes()).unwrap());
        //an old one not
        let secs = 1603288711_u32;
        let mut h = NONCESTARTHASH.clone();
        h.consume(secs.to_be_bytes());

        let n = format!("{:08x}{:032x}", secs, h.compute());
        let n = n[..34].as_bytes();
        assert!(!validate_nonce(n).unwrap());
        //garbage not
        assert!(validate_nonce(b"zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz").is_err());
    }
}
