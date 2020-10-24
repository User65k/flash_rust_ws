use hyper::{Body, Response, Request, header, StatusCode};
use std::io::{Error as IoError};
use std::path::PathBuf;
use crate::auth::{strip_prefix, get_map_from_header};
use crate::dispatch::create_resp_forbidden;
use tokio::fs::File;
use tokio::io::{BufReader, AsyncBufReadExt};
use md5::Context;
use log::info;
use rand::rngs::OsRng;
use rand::RngCore;
use std::time::{SystemTime,UNIX_EPOCH};

fn create_resp_needs_auth(realm: &String) -> Response<Body> {
    let p = format!("Digest realm=\"{}\",nonce=\"{}\",qop=\"auth\"", realm, create_nonce());

    let b = Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header(header::WWW_AUTHENTICATE, 
        header::HeaderValue::from_str(&format!("{},algorithm=\"MD5-sess\"", &p)).unwrap());

    let b = b.header(header::WWW_AUTHENTICATE, 
        header::HeaderValue::from_str(&format!("{},algorithm=\"MD5\"", &p)).unwrap());

    b.body(Body::empty())
        .expect("unable to build response")
}

/// 34 char nonce
/// time+rnd+md5(rnd+pid)
fn create_nonce() -> String {
    let now = SystemTime::now().duration_since(UNIX_EPOCH)
        .expect(&"creating nonces from before UNIX epoch not supported".to_string());
    let secs = now.as_secs() as u32;
    let rnd = OsRng.next_u32();
    let mut h = Context::new();
    h.consume(rnd.to_be_bytes());
    h.consume(std::process::id().to_be_bytes());
    
    let n = format!("{:08x}{:08x}{:032x}", secs, OsRng.next_u32(), h.compute());
    n[..34].to_string()
}

fn validate_nonce(nonce: &[u8]) -> bool {
    if nonce.len() != 34 {
        return false;
    }
    //parse hex
    if let Ok(n) = std::str::from_utf8(nonce) {
        //get time
        if let Ok(secs) = u32::from_str_radix(&n[..4], 16) {
            //TODO check time

            //get rnd
            if let Ok(rnd) = u32::from_str_radix(&n[4..8], 16) {
                //check hash
                let mut h = Context::new();
                h.consume(rnd.to_be_bytes());
                h.consume(std::process::id().to_be_bytes());
                let h = format!("{:x}", h.compute());
                return h[..16] == n[8..34];
            }
        }
    }
    false
}

pub async fn check_digest(auth_file: &PathBuf, req: &Request<Body>, realm: &String) -> Result<Option<Response<Body>>, IoError> {
    match req.headers().get(header::AUTHORIZATION)
          .and_then(|h| strip_prefix(h.as_bytes(), b"Digest ")) {
        None => {
            Ok(Some(create_resp_needs_auth(realm)))
        },
        Some(header) => {
            if let Ok(user_vals) = get_map_from_header(header) {
                if let (Ok(username), Some(nonce), Some(user_response)) =
                    (std::str::from_utf8(
                        user_vals.get(b"username".as_ref())
                        .unwrap_or(&b"\xff".as_ref())
                    )
                    ,user_vals.get(b"nonce".as_ref())
                    ,user_vals.get(b"response".as_ref()))
                {
                    //check if the nonce is from us
                    if !validate_nonce(nonce) {
                        return Ok(Some(create_resp_forbidden()));
                    }

                    let file = File::open(auth_file).await?;
                    let mut file = BufReader::new(file);
        
                    //read HA1 from file
                    //HA1 = make_md5(username+":"+realm+":"+password)
                    let mut ha1 = loop {
                        let mut buf = String::new();
                        if file.read_line(&mut buf).await? < 1 {
                            //user not found
                            return Ok(Some(create_resp_forbidden()));
                        }
                        if buf.starts_with(username) {
                            //user:realm:H1
                            let p: Vec<&str> = buf.split(':').collect();
                            if p.len() == 3
                            && p[1] == realm
                            && p[0].len() == username.len() {
                                break p[2].to_string();
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
                    }else{
                        info!("auth failed {}!={:?}", correct_response, *user_response);
                        // wrong PW
                        Ok(Some(create_resp_needs_auth(realm)))
                    };
                }
            }
            //there is an auth header, but its garbage - at least to us
            Ok(Some(create_resp_forbidden()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::prelude::*;
    use crate::logging::init_stderr_logging;

    fn create_req(header: Option<&str>) -> Request<Body> {
        match header {
            Some(h) => {
                Request::builder().header(header::AUTHORIZATION, h).body(Body::empty()).unwrap()
            },
            None => {
                Request::new(Body::empty())
            }
        }
        
    }

    #[tokio::test]
    async fn auth_required() {
        let path = PathBuf::from(r"/tmp/abc");
        let e = check_digest(&path, &create_req(None), &String::from("abc")).await.unwrap().unwrap();
        assert_eq!(e.status(), StatusCode::UNAUTHORIZED);
    }
    #[tokio::test]
    async fn auth_success() {
        let path = PathBuf::from(r"/tmp/auth_suc");
        let mut file = File::create(&path).expect("could not create htdigest file");
        file.write_all(b"dani:a realm:0d1bfde1dbff91ac4b0c219dec6fc86a").expect("could not write cfg file");

        let h = create_req(Some("Digest username=\"dani\", realm=\"a realm\", nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", uri=\"/cool\", response=\"8a1415c70ae45a88a2a83f896b30bfc3\""));
        let e = check_digest(&path, &h, &String::from("a realm")).await.unwrap();
        println!("{:?}", e);
        assert!(e.is_none());
    }
    #[tokio::test]
    async fn auth_success_sess() {
        let path = PathBuf::from(r"/tmp/auth_suc2");
        let mut file = File::create(&path).expect("could not create htdigest file");
        file.write_all(b"dani:a realm:0d1bfde1dbff91ac4b0c219dec6fc86a").expect("could not write cfg file");

        let h = create_req(Some("Digest username=\"dani\", realm=\"a realm\", nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", uri=\"/favicon.ico\", algorithm=MD5-sess, response=\"f02dcc493b488cc25d503c15765a3005\", qop=auth, nc=00000002, cnonce=\"30d60c5e1664d9cb\""));
        let e = check_digest(&path, &h, &String::from("a realm")).await.unwrap();
        println!("{:?}", e);
        assert!(e.is_none());
    }
    #[tokio::test]
    async fn auth_success_qop_auth() {
        let path = PathBuf::from(r"/tmp/auth_suc3");
        let mut file = File::create(&path).expect("could not create htdigest file");
        file.write_all(b"dani:a realm:0d1bfde1dbff91ac4b0c219dec6fc86a").expect("could not write cfg file");

        let h = create_req(Some("Digest username=\"dani\", realm=\"a realm\", nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", uri=\"/\", response=\"d2f5ad3b664dd98d2dcb700d8027afec\", qop=auth, nc=00000001, cnonce=\"ceee320d38ca229e\""));
        let e = check_digest(&path, &h, &String::from("a realm")).await.unwrap();
        println!("{:?}", e);
        assert!(e.is_none());
    }
    #[tokio::test]
    async fn auth_fail() {
        init_stderr_logging();
        let path = PathBuf::from(r"/tmp/auth_fail");
        let mut file = File::create(&path).expect("could not create htdigest file");
        file.write_all(b"dani:a realm:0d1bfde1dbff91ac4b0c219dec6fc86a").expect("could not write cfg file");

        let h = create_req(Some("Digest username=\"dani\", realm=\"a realm\", nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", uri=\"/cool\", response=\"7a1415c70ae45a88a2a83f896b30bfc3\""));
        let e = check_digest(&path, &h, &String::from("a realm")).await.unwrap().unwrap();
        assert_eq!(e.status(), StatusCode::UNAUTHORIZED);
    }
    #[tokio::test]
    async fn auth_wrong_user() {
        let path = PathBuf::from(r"/tmp/auth_nouser");
        let mut file = File::create(&path).expect("could not create htdigest file");
        file.write_all(b"daniel:a realm:109c7da4a649a1da4a35843583146140").expect("could not write cfg file");

        let h = create_req(Some("Digest username=\"dani\", realm=\"a realm\", nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", uri=\"/cool\", response=\"8a1415c70ae45a88a2a83f896b30bfc3\""));
        let e = check_digest(&path, &h, &String::from("a realm")).await.unwrap().unwrap();
        assert_eq!(e.status(), StatusCode::FORBIDDEN);
    }
    #[tokio::test]
    async fn auth_wrong_realm() {
        let path = PathBuf::from(r"/tmp/auth_realm");
        let mut file = File::create(&path).expect("could not create htdigest file");
        file.write_all(b"dani:another realm:1a30634ead89d6934aa82b933863acf3").expect("could not write cfg file");

        let h = create_req(Some("Digest username=\"dani\", realm=\"a realm\", nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", uri=\"/cool\", response=\"8a1415c70ae45a88a2a83f896b30bfc3\""));
        let e = check_digest(&path, &h, &String::from("a realm")).await.unwrap().unwrap();
        assert_eq!(e.status(), StatusCode::FORBIDDEN);
    }
    #[tokio::test]
    async fn auth_error() {
        let path = PathBuf::from(r"/tmp/abc");
        let h = create_req(Some("Digest username=\"dani\""));
        let e = check_digest(&path, &h, &String::from("abc")).await.unwrap().unwrap();
        assert_eq!(e.status(), StatusCode::FORBIDDEN);

        let h = create_req(Some("Digest ===,,"));
        let e = check_digest(&path, &h, &String::from("abc")).await.unwrap().unwrap();
        assert_eq!(e.status(), StatusCode::FORBIDDEN);
    }
}