use crate::body::{BoxBody, FRWSResult, IncomingBody};
use crate::config::AbsPathBuf;
use super::staticf::{self, resolve_path, return_file, ResolveResult};
use super::Req;
use bytes::{BufMut, Bytes, BytesMut};
use hyper::body::Body as _;
use hyper::{header, http::HeaderValue, HeaderMap, Method, Response, StatusCode};
use serde::Deserialize;
use std::{
    convert::TryFrom,
    io::{Error as IoError, ErrorKind, Write},
    net::SocketAddr,
    path::{Path, PathBuf},
    pin::Pin,
    task::{Context, Poll},
};
use tokio::{fs::metadata, io::copy as redirect};
use tokio::{
    fs::{copy, create_dir, remove_dir_all, remove_file, rename, File},
    io::AsyncRead,
};
mod propfind;
#[cfg(test)]
mod tests;

#[allow(clippy::upper_case_acronyms)]
enum DavMethod {
    PROPFIND,
    GET,
    PUT,
    COPY,
    MOVE,
    DELETE,
    MKCOL,
}

/// req_path is relative from config.root
/// web_mount is config.root from the client perspective
pub async fn do_dav(
    req: Req<IncomingBody>,
    config: &Config,
    _remote_addr: SocketAddr,
) -> FRWSResult {
    let m = match req.method() {
        &Method::OPTIONS => {
            let rb = Response::builder()
                .status(StatusCode::OK)
                .header(
                    header::ALLOW,
                    "GET,PUT,OPTIONS,DELETE,PROPFIND,COPY,MOVE,MKCOL",
                )
                .header("DAV", "1");
            return Ok(rb.body(BoxBody::empty()).unwrap());
        }
        &Method::DELETE => DavMethod::DELETE,
        &Method::GET => DavMethod::GET,
        &Method::PUT => DavMethod::PUT,
        m => match m.as_str() {
            "PROPFIND" => DavMethod::PROPFIND,
            "COPY" => DavMethod::COPY,
            "MOVE" => DavMethod::MOVE,
            "MKCOL" => DavMethod::MKCOL,
            "PROPPATCH" => {
                return Err(IoError::new(
                    ErrorKind::PermissionDenied,
                    "properties are read only",
                ))
            }
            _ => {
                return Ok(Response::builder()
                    .status(StatusCode::METHOD_NOT_ALLOWED)
                    .body(BoxBody::empty())
                    .expect("unable to build response"))
            }
        },
    };
    if config.read_only
        && matches!(
            m,
            DavMethod::PUT
                | DavMethod::COPY
                | DavMethod::MOVE
                | DavMethod::DELETE
                | DavMethod::MKCOL
        )
    {
        return Err(IoError::new(ErrorKind::PermissionDenied, "read only mount"));
    }
    let full_path = req.path().prefix_with(&config.dav);

    if !config.follow_symlinks {
        let fp = if matches!(m, DavMethod::PUT | DavMethod::MKCOL) {
            //Path will be created -> check dad:
            match full_path.parent() {
                None => {
                    return Err(IoError::new(
                        ErrorKind::Other, //should not be reachable
                        "No Parent",
                    ));
                }
                Some(p) => match p.canonicalize() {
                    Ok(c) => c,
                    Err(ref e) if e.kind() == ErrorKind::NotFound => {
                        let mut res = Response::new(BoxBody::empty());
                        *res.status_mut() = StatusCode::CONFLICT;
                        return Ok(res);
                    }
                    Err(e) => return Err(e),
                },
            }
        } else {
            full_path.canonicalize()?
        };
        //check if the canonicalized version is still inside of the (abs) root path
        if !fp.starts_with(&config.dav) {
            return Err(IoError::new(
                ErrorKind::PermissionDenied,
                "Symlinks are not allowed",
            ));
        }
    }

    match m {
        DavMethod::PROPFIND => {
            propfind::handle_propfind(req, full_path, &config.dav).await
        }
        DavMethod::GET => handle_get(req, &full_path).await,
        DavMethod::PUT => handle_put(req, &full_path, config.dont_overwrite).await,
        DavMethod::MKCOL => handle_mkdir(&full_path).await,
        DavMethod::COPY => {
            handle_copy(
                req.headers(),
                &full_path,
                &config.dav,
                req.mount(),
                config.dont_overwrite,
            )
            .await
        }
        DavMethod::MOVE => {
            handle_move(
                req.headers(),
                &full_path,
                &config.dav,
                req.mount(),
                config.dont_overwrite,
            )
            .await
        }
        DavMethod::DELETE if !config.dont_overwrite => handle_delete(&full_path).await,
        DavMethod::DELETE => Err(IoError::new(
            ErrorKind::PermissionDenied,
            "dont_overwrite forbids delete",
        )),
    }
}
async fn list_dir(full_path: &Path, url_path: String) -> FRWSResult {
    let mut dir = tokio::fs::read_dir(full_path).await?;
    let mut buf = BytesMut::new().writer();
    buf.write_all(b"<html><body>")?;
    while let Some(f) = dir.next_entry().await? {
        let path = f.path();
        let meta = match f.metadata().await {
            Ok(meta) => meta,
            Err(e) => {
                log::error!("Metadata error on {:?}. Skipping {:?}", path, e);
                continue;
            }
        };
        //percent_encoding::percent_encode_byte(byte)

        if meta.is_dir() {
            buf.write_all(
                format!(
                    "<a href=\"{0}{1}/\">{1}/</a><br/>",
                    url_path,
                    f.file_name().to_string_lossy()
                )
                .as_bytes(),
            )?;
        } else {
            buf.write_all(
                format!(
                    "<a href=\"{0}{1}\">{1}</a> {2}<br/>",
                    url_path,
                    f.file_name().to_string_lossy(),
                    meta.len()
                )
                .as_bytes(),
            )?;
        }
    }
    buf.write_all(b"</body></html>")?;
    let res = Response::builder()
        .header(header::CONTENT_TYPE, &b"text/html; charset=UTF-8"[..])
        .body(buf.into())
        .expect("unable to build response");
    Ok(res)
}

async fn handle_get(
    req: Req<IncomingBody>,
    full_path: &Path,
) -> FRWSResult {
    //we could serve dir listings as well. with a litte webdav client :-D
    let (_, file_lookup) = resolve_path(full_path, false, &None).await?;

    match file_lookup {
        ResolveResult::IsDirectory => {
            let is_dir_request = req.is_dir_req();
            if is_dir_request {
                list_dir(
                    full_path,
                    req.path().prefixed_as_abs_url_path(req.mount(), 0, true),
                )
                .await
            } else {
                Ok(staticf::redirect(&req))
            }
        }
        ResolveResult::Found(file, metadata, mime) => return_file(req, file, metadata, mime).await,
    }
}
async fn handle_delete(full_path: &Path) -> FRWSResult {
    let res = Response::new(BoxBody::empty());

    let meta = metadata(full_path).await?;
    if meta.is_dir() {
        remove_dir_all(full_path).await?;
    } else {
        remove_file(full_path).await?;
    }
    log::info!("Deleted {:?}", full_path);
    //HTTP NO_CONTENT ?
    Ok(res)
}
async fn parent_exists(path: &Path) -> Result<bool, IoError> {
    match path.parent() {
        None => Err(IoError::new(
            std::io::ErrorKind::PermissionDenied,
            "No parent",
        )),
        Some(p) => match metadata(p).await {
            Ok(m) => Ok(m.is_dir()),
            Err(ref e) if e.kind() == ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e),
        },
    }
}

async fn handle_mkdir(full_path: &Path) -> FRWSResult {
    let mut res = Response::new(BoxBody::empty());
    if !parent_exists(full_path).await? {
        /*
        A collection cannot be made at the Request-URI until
        one or more intermediate collections have been created.  The server
        MUST NOT create those intermediate collections automatically.
        */
        *res.status_mut() = StatusCode::CONFLICT;
        return Ok(res);
    }
    create_dir(full_path).await?;
    *res.status_mut() = StatusCode::CREATED;
    log::info!("Created {:?}", full_path);
    /*
    415 (Unsupported Media Type) - A body was sent
    507 (Insufficient Storage)
     */
    Ok(res)
}
struct BodyW {
    s: IncomingBody,
    b: Option<Bytes>,
}
impl AsyncRead for BodyW {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if let Some(mut data) = self.b.take() {
            if buf.remaining() < data.len() {
                let left = data.split_off(buf.remaining());
                self.b = Some(left);
            }
            buf.put_slice(&data);
            return Poll::Ready(Ok(()));
        }
        let r = Pin::new(&mut self.s).poll_frame(cx);
        match r {
            Poll::Ready(None) => Poll::Ready(Ok(())),
            Poll::Ready(Some(Ok(data))) => {
                if let Ok(mut data) = data.into_data() {
                    if buf.remaining() < data.len() {
                        let left = data.split_off(buf.remaining());
                        self.b = Some(left);
                    }
                    buf.put_slice(&data);
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Err(IoError::new(ErrorKind::BrokenPipe, e))),
            Poll::Pending => Poll::Pending,
        }
    }
}
async fn handle_put(req: Req<IncomingBody>, full_path: &Path, dont_overwrite: bool) -> FRWSResult {
    // Check if file exists before proceeding
    if dont_overwrite && metadata(full_path).await.is_ok() {
        return Err(IoError::new(
            ErrorKind::AlreadyExists,
            "file overwriting is disabled",
        ));
    }
    if !parent_exists(full_path).await? {
        //MUST 409 if folder does not exist
        let mut res = Response::new(BoxBody::empty());
        *res.status_mut() = StatusCode::CONFLICT;
        return Ok(res);
    }
    log::info!("about to store {:?}", full_path);
    let mut f = File::create(full_path).await?;
    let (_, s) = req.into_parts();
    let mut b = BodyW { s, b: None };
    redirect(&mut b, &mut f).await?;
    let res = Response::new(BoxBody::empty());
    //MAY 405 if file is a folder
    Ok(res)
}
/// get the absolute local destination dir from the request
fn get_dst(
    header: &HeaderMap<HeaderValue>,
    root: &AbsPathBuf,
    web_mount: &str,
) -> Result<PathBuf, IoError> {
    // Get the destination
    let dst = header
        .get("Destination")
        .map(|hv| hv.as_bytes())
        .and_then(|s| hyper::Uri::try_from(s).ok())
        .ok_or_else(|| IoError::new(ErrorKind::InvalidData, "no valid destination path"))?;

    let request_path = super::WebPath::try_from(&dst)?;
    let path = request_path.strip_prefix(Path::new(web_mount)).map_err(|_| {
        IoError::new(
            ErrorKind::PermissionDenied,
            "destination path outside of mount",
        )
    })?;
    let req_path = path.prefix_with(root);
    Ok(req_path)
}
async fn handle_copy(
    header: &HeaderMap<HeaderValue>,
    src_path: &Path,
    root: &AbsPathBuf,
    web_mount: &str,
    mut dont_overwrite: bool,
) -> FRWSResult {
    let dst_path = get_dst(header, root, web_mount)?;
    log::info!("Copy {:?} -> {:?}", src_path, dst_path);
    let mut res = Response::new(BoxBody::empty());
    if !parent_exists(&dst_path).await? {
        //409 (Conflict) - No parent folder
        *res.status_mut() = StatusCode::CONFLICT;
        return Ok(res);
    }
    //If a COPY request has an Overwrite header with a value of "F", and a resource exists at the Destination URL, the server MUST fail the request.
    if let Some(b"F") = header.get("Overwrite").map(|v| v.as_bytes()) {
        dont_overwrite = true;
    }
    if dont_overwrite && metadata(&dst_path).await.is_ok() {
        *res.status_mut() = StatusCode::PRECONDITION_FAILED;
        return Ok(res);
    }
    copy(src_path, dst_path).await?;
    //resulted in the creation of a new resource.
    *res.status_mut() = StatusCode::CREATED;
    /*
    204 (No Content) - copied to a preexisting destination resource.

    207 (Multi-Status) - Multiple resources were to be affected by the
    COPY, but errors on some of them prevented the operation from taking
    place.  Specific error messages, together with the most appropriate
    of the source and destination URLs, appear in the body of the multi-
    status response.  For example, if a destination resource was locked
    and could not be overwritten, then the destination resource URL
    appears with the 423 (Locked) status.

    403 (Forbidden) - The operation is forbidden.  A special case for
    COPY could be that the source and destination resources are the same
    resource.

    423 (Locked)
    502 (Bad Gateway)
    507 (Insufficient Storage)
    */
    Ok(res)
}
async fn handle_move(
    header: &HeaderMap<HeaderValue>,
    src_path: &Path,
    root: &AbsPathBuf,
    web_mount: &str,
    mut dont_overwrite: bool,
) -> FRWSResult {
    let dst_path = get_dst(header, root, web_mount)?;
    log::info!("Move {:?} -> {:?}", src_path, dst_path);
    let mut res = Response::new(BoxBody::empty());
    if !parent_exists(&dst_path).await? {
        //409 (Conflict) - No parent folder
        *res.status_mut() = StatusCode::CONFLICT;
        return Ok(res);
    }
    match header.get("Overwrite").map(|v| v.as_bytes()) {
        Some(b"F") => {
            dont_overwrite = true;
        }
        Some(b"T") => {
            //MUST perform a DELETE with "Depth: infinity" on the destination resource.
            handle_delete(&dst_path).await?;
        }
        _ => {}
    }
    if dont_overwrite && metadata(&dst_path).await.is_ok() {
        *res.status_mut() = StatusCode::PRECONDITION_FAILED;
        return Ok(res);
    }
    rename(src_path, dst_path).await?;
    //a new URL mapping was created at the destination.
    *res.status_mut() = StatusCode::CREATED;
    /*
    204 (No Content) -> see copy
    207 (Multi-Status) -> see copy
    403 (Forbidden) -> see copy
    423 (Locked)
    502 (Bad Gateway)
    */
    Ok(res)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub dav: AbsPathBuf,
    #[serde(default)]
    pub read_only: bool,
    #[serde(default)]
    pub dont_overwrite: bool,
    #[serde(default)]
    pub follow_symlinks: bool,
}
impl Config {
    pub async fn setup(&self) -> Result<(), String> {
        if !self.dav.is_dir() {
            return Err(format!("{:?} ist not a directory", self.dav));
        }
        Ok(())
    }
}
