mod cfg;
#[cfg(test)]
pub(crate) mod test;
pub use cfg::*;

use bytes::{Bytes, BytesMut};
use hyper::{body::Body as _, Request, Response};
use log::{debug, error, trace};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;
use std::{
    io::{Error as IoError, ErrorKind},
    net::SocketAddr,
};
use tokio::time::timeout;

use crate::{
    body::{BoxBody, BufferedBody, FRWSResult, IncomingBody, IncomingBodyTrait as _},
    config::StaticFiles,
};

use super::staticf;
use super::webpath::Req;

const SCRIPT_NAME: &[u8] = b"SCRIPT_NAME";
const PATH_INFO: &[u8] = b"PATH_INFO";
const SERVER_NAME: &[u8] = b"SERVER_NAME";
const SERVER_PORT: &[u8] = b"SERVER_PORT";
const SERVER_PROTOCOL: &[u8] = b"SERVER_PROTOCOL";
const REMOTE_ADDR: &[u8] = b"REMOTE_ADDR";
const GATEWAY_INTERFACE: &[u8] = b"GATEWAY_INTERFACE";
const CGI_VERS: &[u8] = b"CGI/1.1";
const SERVER_SOFTWARE: &[u8] = b"SERVER_SOFTWARE";
const REQUEST_URI: &[u8] = b"REQUEST_URI";
const SCRIPT_FILENAME: &[u8] = b"SCRIPT_FILENAME";

pub async fn fcgi_call(
    fcgi_cfg: &FCGIApp,
    req: Req<IncomingBody>,
    fs_full_path: Option<&Path>,
    path_info_offset: Option<usize>,
    remote_addr: SocketAddr,
) -> FRWSResult {
    let app = if let Some(app) = &fcgi_cfg.app {
        app
    } else {
        error!("FCGI app not set");
        return Err(IoError::new(
            ErrorKind::NotConnected,
            "FCGI app not available",
        ));
    };

    let params = create_params(
        fcgi_cfg,
        &req,
        fs_full_path,
        path_info_offset,
        remote_addr,
    );
    trace!("to FCGI: {:?}", &params);

    let (req, body) = req.into_parts();

    let body = match req.method {
        hyper::http::Method::GET
        | hyper::http::Method::HEAD
        | hyper::http::Method::OPTIONS
        | hyper::http::Method::DELETE
        | hyper::http::Method::TRACE => BufferedBody::wrap(body),
        _ => {
            //request type with body...
            if body.size_hint().exact().is_none() {
                //...but no len indicator
                if let Some(max_size) = fcgi_cfg.buffer_request {
                    //read everything to memory
                    match body.buffer(max_size).await {
                        Ok(b) => b,
                        Err(e) if e.kind() == ErrorKind::PermissionDenied => {
                            //body is more than max_size -> abort
                            return Ok(Response::builder()
                                .status(hyper::StatusCode::PAYLOAD_TOO_LARGE)
                                .body(BoxBody::empty())
                                .expect("unable to build response"));
                        }
                        Err(e) => return Err(e),
                    }
                } else {
                    //reject it
                    return Ok(Response::builder()
                        .status(hyper::StatusCode::LENGTH_REQUIRED)
                        .body(BoxBody::empty())
                        .expect("unable to build response"));
                }
            } else {
                BufferedBody::wrap(body)
            }
        }
    };
    let req = Request::from_parts(req, body);

    let mut resp = match fcgi_cfg.timeout {
        0 => app.forward(req, params).await,
        secs => match timeout(Duration::from_secs(secs), app.forward(req, params)).await {
            Err(_) => {
                return Err(IoError::new(
                    ErrorKind::TimedOut,
                    "FCGI app did not respond",
                ))
            }
            Ok(resp) => resp,
        },
    }?;
    debug!("FCGI response: {:?} {:?}", resp.status(), resp.headers());
    //return types:
    resp.headers_mut().remove("Status");
    //doc: MUST return a Content-Type header or ...
    /*if resp.headers().len()==1 {
        if let Some(location) = resp.headers().get("Location") {
            if location.as_bytes().first() == Some(&b'/') {
                if resp.status() == hyper::StatusCode::OK {
                    // https://datatracker.ietf.org/doc/html/rfc3875#section-6.2.3
                    //TODO generate 302 'Found' response
                }else{
                    // https://datatracker.ietf.org/doc/html/rfc3875#section-6.2.4
                    // 3xx: Abs Location header, MUST NOT return any other header fields
                    //TODO adjust path?
                }
            }else{
                // https://datatracker.ietf.org/doc/html/rfc3875#section-6.2.2
                // Location header, MUST NOT return any other header fields or a message-body
                //TODO fetch and return local resource
            }
        }
    }*/

    Ok(resp.map(BoxBody::fcgi))
}

fn create_params(
    fcgi_cfg: &FCGIApp,
    req: &Req<IncomingBody>,
    // resolved path on file system
    fs_full_path: Option<&Path>,
    // offset in request path that is virtual/path_info
    path_info_offset: Option<usize>,
    remote_addr: SocketAddr,
) -> HashMap<Bytes, Bytes> {
    let mut params = HashMap::new();
    if let Some(full_path) = fs_full_path {
        //full_path is completely resolved (to get index files) and will never contain a PATH_INFO or be a directory

        /*
        the user entered "{web_mount}/{req_path}" to get here.
        To construct a valid SCRIPT_NAME we need to
        - strip PATH_INFO (if any)
        - add the index file (if needed)
        */
        let mut abs_name;

        if let Some(pi) = path_info_offset {
            // - PATH_INFO derived from the portion of the URI path hierarchy following the part that identifies the script itself.
            abs_name = req.path().prefixed_as_abs_url_path(req.mount(), 0, false);

            let pi = abs_name.split_off(req.mount().len() + pi); //strip path_info

            params.insert(
                // must CGI/1.1  4.1.13, everybody cares
                Bytes::from(PATH_INFO),
                Bytes::from(pi),
            );
        } else {
            let add_index = req.is_dir_req();
            'no_pi: {
                if add_index {
                    let index_file_name = full_path.file_name().and_then(|o| o.to_str());
                    if let Some(f) = index_file_name {
                        abs_name = req
                            .path()
                            .prefixed_as_abs_url_path(req.mount(), f.len()+1, false);
                        if !abs_name.ends_with('/') { // same as !req.path().is_empty()
                            abs_name.push('/');
                        }
                        abs_name.push_str(f);
                        break 'no_pi;
                    }
                }
                //nothing to add
                abs_name = req.path().prefixed_as_abs_url_path(req.mount(), 0, false);
            }
        }

        params.insert(
            // must CGI/1.1  4.1.13, everybody cares
            Bytes::from(SCRIPT_NAME),
            Bytes::from(abs_name),
        );
    } else {
        //no local FS
        //the wohle mount is a single FCGI App...

        //let mut abs_web_mount = PathBuf::from("/");
        //abs_web_mount.push(web_mount);
        let mut abs_web_mount = String::with_capacity(req.mount().len() + 1);
        abs_web_mount.push('/');
        abs_web_mount.push_str(req.mount());

        params.insert(
            // must CGI/1.1  4.1.13, everybody cares
            Bytes::from(SCRIPT_NAME),
            //path_to_bytes(abs_web_mount),
            Bytes::from(abs_web_mount),
        );
        //... so everything inside it is PATH_INFO
        let abs_path = req
            .path()
            .prefixed_as_abs_url_path("", 0, false);
        params.insert(
            // opt CGI/1.1   4.1.5
            Bytes::from(PATH_INFO),
            Bytes::from(abs_path),
        );
        //this matches what lighttpd does without check_local
    }
    let auth = req.extensions().get::<hyper::http::uri::Authority>();

    params.insert(
        // must CGI/1.1  4.1.14, flup cares for this
        Bytes::from(SERVER_NAME),
        Bytes::from(auth.map(|a| a.host()).unwrap_or_default().to_string()),
    );

    params.insert(
        // must CGI/1.1  4.1.15, flup cares for this
        Bytes::from(SERVER_PORT),
        Bytes::from(
            auth.and_then(|a| a.port())
                .map(|p| p.to_string())
                .unwrap_or_else(|| "80".to_string()),
        ),
    );
    params.insert(
        // must CGI/1.1  4.1.16, flup cares for this
        Bytes::from(SERVER_PROTOCOL),
        Bytes::from(format!("{:?}", req.version())),
    );
    params.insert(
        // must CGI/1.1  4.1.8
        Bytes::from(REMOTE_ADDR),
        Bytes::from(remote_addr.ip().to_string()),
    );
    params.insert(
        // must CGI/1.1  4.1.4
        Bytes::from(GATEWAY_INTERFACE),
        Bytes::from(CGI_VERS),
    );
    params.insert(
        // must CGI/1.1  4.1.17
        Bytes::from(SERVER_SOFTWARE),
        Bytes::from(&b"frws"[..]),
    );
    if fcgi_cfg.set_request_uri {
        let q = req.query();
        let mut r_uri = req.path().prefixed_as_abs_url_path(req.mount(), q.map_or(0, |q| q.len() + 1), false);

        if let Some(q) = q {
            r_uri.push('?');
            r_uri.push_str(q);
        }

        params.insert(
            // REQUEST_URI common
            Bytes::from(REQUEST_URI),
            Bytes::from(r_uri),
        );
    }
    if fcgi_cfg.set_script_filename {
        params.insert(
            // PHP cares for this
            Bytes::from(SCRIPT_FILENAME),
            if let Some(full_path) = fs_full_path {
                path_to_bytes(full_path)
            } else {
                // I am guessing here
                Bytes::from(
                    req.path()
                        .prefixed_as_abs_url_path("", 0, false),
                )
            },
        );
    }
    if let Some(kvp) = &fcgi_cfg.params {
        params.extend(
            kvp.iter()
                .map(|(k, v)| (Bytes::from(k.to_string()), Bytes::from(v.to_string()))),
        );
    }
    params
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
/// just like `staticf::resolve_path` but if a NotADirectory error would occur, it tries to split the request into file and PATH_INFO
pub async fn resolve_path<'a>(
    full_path: PathBuf,
    is_dir_request: bool,
    sf: &StaticFiles,
    req: &'a Req<IncomingBody>,
) -> Result<(PathBuf, staticf::ResolveResult, Option<usize>), IoError> {
    match staticf::resolve_path(&full_path, is_dir_request, &sf.index).await {
        Ok((p, r)) => Ok((p, r, None)),
        Err(err) => {
            if error_indicates_path_info(&err) {
                debug!("{:?} might have a PATH_INFO", &full_path);
                /*
                pop the last path component until we hit a file
                everything after the file will become PATH_INFO
                */
                let mut fp = full_path;
                loop {
                    if !fp.pop() {
                        // we went all the way up - should not ever happen on linux but on windows
                        return Err(err);
                    }
                    match fp.metadata() {
                        Ok(m) => {
                            if m.is_file() {
                                break;
                            } else {
                                // the first not to return ErrorKind::NotADirectory
                                // must be a file
                                return Err(err);
                            }
                        }
                        Err(e) => {
                            if error_indicates_path_info(&e) {
                                //keep going up
                            } else {
                                return Err(e);
                            }
                        }
                    }
                }
                match fp.strip_prefix(&sf.dir) {
                    Ok(file) => {
                        let path_info = req.is_prefix(file).ok().map(|i| i + 1);
                        let (p, r) = staticf::resolve_path(&fp, false, &None).await?;
                        Ok((p, r, path_info))
                    }
                    Err(_) => {
                        // we have left the webroot
                        error!(
                            "Somehow {:?} turned into {:?} and left {:?}",
                            req.path(),
                            fp,
                            sf.dir
                        );
                        Err(err)
                    }
                }
            } else {
                Err(err)
            }
        }
    }
}

//on linux its ErrorKind::NotADirectory (or 20)
//on windows its just NotFound (or 3)
#[inline]
fn error_indicates_path_info(err: &IoError) -> bool {
    #[cfg(unix)]
    return Some(20) == err.raw_os_error();
    #[cfg(windows)]
    return Some(3) == err.raw_os_error();
}
