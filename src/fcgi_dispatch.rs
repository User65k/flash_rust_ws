
use std::io::{Error as IoError, ErrorKind};
use log::{error, trace};
use std::collections::HashMap;
use bytes::{Bytes, BytesMut};
use hyper::{Body, Request, Response};
use std::path::PathBuf;
use std::path::Path;

use crate::config;
use crate::body::FCGIBody;


pub async fn is_fcgi_call(fcgi_cfg: &config::FCGIApp, _req: &Request<Body>, full_path: &PathBuf)
            -> bool {
    if let Some(whitelist) = &fcgi_cfg.exec {
        if let Some(ext) = full_path.extension() {
            for e in whitelist {
                if e == ext {
                    return true;
                }
            }
        }
        return false;
    }
    if let Some(blacklist) = &fcgi_cfg.serve {
        if let Some(ext) = full_path.extension() {
            for e in blacklist {
                if e == ext {
                    return false;
                }
            }
        }
    }

    true  // no black or whitelist - handle all
}

pub async fn fcgi_call(fcgi_cfg: &config::FCGIApp, req: Request<Body>, full_path: &PathBuf)
            -> Result<Response<Body>, IoError> {
    if let Some(app) = &fcgi_cfg.app {
        let mut params = HashMap::new();
        params.insert( // must CGI/1.1  4.1.13, everybody cares
            Bytes::from(&b"SCRIPT_NAME"[..]),
            path_to_bytes(full_path),
        );
        params.insert( // must CGI/1.1  4.1.14, flup cares for this
            Bytes::from(&b"SERVER_NAME"[..]),
            Bytes::from(&b"FRWS"[..]),
        );
        params.insert( // must CGI/1.1  4.1.15, flup cares for this
            Bytes::from(&b"SERVER_PORT"[..]),
            Bytes::from(&b"80"[..]),
        );
        params.insert(  // must CGI/1.1  4.1.16, flup cares for this
            Bytes::from(&b"SERVER_PROTOCOL"[..]),
            Bytes::from(&b"HTTP"[..]),
        );
        // - SERVER_SOFTWARE   must CGI/1.1  4.1.17
        // - REMOTE_ADDR       must CGI/1.1  4.1.8
        // - GATEWAY_INTERFACE must CGI/1.1  4.1.4
        // - REMOTE_HOST       should CGI/1.1  4.1.9
        // - REMOTE_IDENT      may CGI/1.1  4.1.10
        // - REMOTE_USER       opt CGI/1.1
        // - AUTH_TYPE         opt CGI/1.1
        // - PATH_INFO         opt CGI/1.1   4.1.5 extra-path
        // - PATH_TRANSLATED   opt CGI/1.1   4.1.6
        // - SCRIPT_FILENAME   PHP cares for this
        // - REMOTE_PORT       common
        // - SERVER_ADDR       common
        // - REQUEST_URI       common
        // - DOCUMENT_URI      common
        // - DOCUMENT_ROOT     common
        trace!("to FCGI: {:?}", &params);
        return Ok(app.forward(req, params).await?.map(|bod|Body::wrap_stream(FCGIBody::from(bod))));
    }else{
        error!("FCGI app not set");
        Err(IoError::new(ErrorKind::BrokenPipe,"FCGI app not available"))
    }
}
#[cfg(unix)]
fn path_to_bytes<P: AsRef<Path>>(path: P) -> Bytes {
    use std::os::unix::ffi::OsStrExt;
    BytesMut::from(path.as_ref().as_os_str().as_bytes()).freeze()
}

#[cfg(not(unix))]
fn path_to_bytes<P: AsRef<Path>>(path: P) -> Bytes {
    // On Windows, could use std::os::windows::ffi::OsStrExt to encode_wide(),
    // but end up with u16
    BytesMut::from(path.as_ref().to_string_lossy().to_string().as_bytes()).freeze()
}