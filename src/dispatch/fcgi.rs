
use std::io::{Error as IoError, ErrorKind};
use log::{error, trace};
use std::collections::HashMap;
use bytes::{Bytes, BytesMut};
use hyper::{Body, Request, Response};
use std::path::PathBuf;
use std::path::Path;

use crate::config;
use crate::body::FCGIBody;


pub async fn fcgi_call(fcgi_cfg: &config::FCGIApp, req: Request<Body>, full_path: &PathBuf)
            -> Result<Response<Body>, IoError> {
    if let Some(app) = &fcgi_cfg.app {
        if fcgi_cfg.exec.is_some() && !full_path.is_file() {
            // whitelist is used, check if file exists
            return Err(IoError::new(ErrorKind::NotFound, "File not found"));
        }

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

        if Some(true) == fcgi_cfg.script_filename {
            params.insert( // PHP cares for this
                Bytes::from(&b"SCRIPT_FILENAME"[..]),
                path_to_bytes(full_path),
            );
        }
        trace!("to FCGI: {:?}", &params);
        Ok(app.forward(req, params).await?.map(|bod|Body::wrap_stream(FCGIBody::from(bod))))
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