use super::staticf::{resolve_path, return_file};
use bytes::{BufMut, Bytes, BytesMut};
use hyper::{body::HttpBody, header, Body, Request, Response, StatusCode};
use hyper_staticfile::ResolveResult;
use serde::Deserialize;
use std::{
    convert::TryFrom,
    io::{Error as IoError, ErrorKind, Write},
    net::SocketAddr,
    path::{Path, PathBuf},
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::copy as redirect;
use tokio::{
    fs::{copy, create_dir, metadata, remove_dir_all, remove_file, rename, File},
    io::AsyncRead,
};
mod propfind;
use super::decode_and_normalize_path;

/// req_path is relative from config.root
/// web_mount is config.root from the client perspective
pub async fn do_dav(
    req: Request<Body>,
    req_path: &super::WebPath,
    config: &Config,
    web_mount: &Path,
    _remote_addr: SocketAddr,
) -> Result<Response<Body>, IoError> {
    let abs_doc_root = config.dav.canonicalize()?;
    let full_path = req_path.prefix_with(&abs_doc_root);
    let mut abs_web_mount = PathBuf::from("/");
    abs_web_mount.push(web_mount);
    match req.method().as_ref() {
        //strip root
        //prepent mount
        "PROPFIND" => {
            propfind::handle_propfind(req, &full_path, abs_doc_root, &abs_web_mount).await
        }
        "OPTIONS" => {
            let rb = Response::builder()
                .status(StatusCode::OK)
                .header(
                    header::ALLOW,
                    "GET,PUT,OPTIONS,DELETE,PROPFIND,COPY,MOVE,MKCOL",
                )
                .header("DAV", "1");
            Ok(rb.body(Body::empty()).unwrap())
        }
        "GET" => handle_get(req, &full_path).await,
        "PROPPATCH" => Err(IoError::new(
            ErrorKind::PermissionDenied,
            "properties are read only",
        )),
        "PUT" if !config.read_only => handle_put(req, &full_path, config.dont_overwrite).await,
        "COPY" if !config.read_only && !config.dont_overwrite => {
            handle_copy(req, &full_path, &abs_doc_root, &abs_web_mount).await
        }
        "MOVE" if !config.read_only && !config.dont_overwrite => {
            handle_move(req, &full_path, &abs_doc_root, &abs_web_mount).await
        }
        "DELETE" if !config.read_only && !config.dont_overwrite => {
            handle_delete(req, &full_path).await
        }
        "MKCOL" if !config.read_only => handle_mkdir(req, &full_path).await,
        "PUT" | "COPY" | "MOVE" | "DELETE" | "MKCOL" => {
            Err(IoError::new(ErrorKind::PermissionDenied, "read only"))
        }
        _ => Ok(Response::builder()
            .status(StatusCode::METHOD_NOT_ALLOWED)
            .body(Body::empty())
            .expect("unable to build response")),
    }
}
async fn list_dir(req: Request<Body>, full_path: &Path) -> Result<Response<Body>, IoError> {
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
                    req.uri().path(),
                    f.file_name().to_string_lossy()
                )
                .as_bytes(),
            )?;
        } else {
            buf.write_all(
                format!(
                    "<a href=\"{0}{1}\">{1}</a> {2}<br/>",
                    req.uri().path(),
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
        .body(Body::from(buf.into_inner().freeze()))
        .expect("unable to build response");
    Ok(res)
}
async fn handle_get(req: Request<Body>, full_path: &Path) -> Result<Response<Body>, IoError> {
    let follow_symlinks = false;
    //we could serve dir listings as well. with a litte webdav client :-D
    let (_, file_lookup) = resolve_path(full_path, false, &None, follow_symlinks).await?;
    if let ResolveResult::IsDirectory = file_lookup {
        let is_dir_request = req.uri().path().as_bytes().last() == Some(&b'/');
        if is_dir_request {
            return list_dir(req, full_path).await;
        } //else -> redirect to "path/"
    }
    return_file(&req, file_lookup).await
}
async fn handle_delete(_: Request<Body>, full_path: &Path) -> Result<Response<Body>, IoError> {
    let res = Response::new(Body::empty());

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
async fn handle_mkdir(_: Request<Body>, full_path: &Path) -> Result<Response<Body>, IoError> {
    let mut res = Response::new(Body::empty());
    match create_dir(full_path).await {
        Ok(_) => *res.status_mut() = StatusCode::CREATED,
        Err(ref e) if e.kind() == ErrorKind::NotFound => {
            /*
            A collection cannot be made at the Request-URI until
            one or more intermediate collections have been created.  The server
            MUST NOT create those intermediate collections automatically.
            */
            *res.status_mut() = StatusCode::CONFLICT;
        }
        Err(e) => return Err(e),
    };
    log::info!("Created {:?}", full_path);
    /*
    415 (Unsupported Media Type) - A body was sent
    507 (Insufficient Storage)
     */
    Ok(res)
}
struct BodyW {
    s: Body,
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
        let r = Pin::new(&mut self.s).poll_data(cx);
        match r {
            Poll::Ready(None) => Poll::Ready(Ok(())),
            Poll::Ready(Some(Ok(mut data))) => {
                if buf.remaining() < data.len() {
                    let left = data.split_off(buf.remaining());
                    self.b = Some(left);
                }
                buf.put_slice(&data);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Err(IoError::new(ErrorKind::BrokenPipe, e))),
            Poll::Pending => Poll::Pending,
        }
    }
}
async fn handle_put(
    req: Request<Body>,
    full_path: &Path,
    dont_overwrite: bool,
) -> Result<Response<Body>, IoError> {
    // Check if file exists before proceeding
    if full_path.exists() && dont_overwrite {
        return Err(IoError::new(
            ErrorKind::AlreadyExists,
            "file overwriting is disabled",
        ));
    }
    log::info!("about to store {:?}", full_path);
    let mut f = File::create(full_path).await?;
    let mut b = BodyW {
        s: req.into_body(),
        b: None,
    };
    redirect(&mut b, &mut f).await?;
    let res = Response::new(Body::empty());
    //MUST 409 if folder does not exist
    //MAY 405 if file is a folder
    Ok(res)
}
/// get the absolute local destination dir from the request
fn get_dst(req: &Request<Body>, root: &Path, web_mount: &Path) -> Result<PathBuf, IoError> {
    // Get the destination
    let dst = req
        .headers()
        .get("Destination")
        .map(|hv| hv.as_bytes())
        .and_then(|s| hyper::Uri::try_from(s).ok())
        .ok_or_else(|| IoError::new(ErrorKind::InvalidData, "no valid destination path"))?;

    let request_path = decode_and_normalize_path(&dst)?;
    let path = request_path.strip_prefix(web_mount).map_err(|_| {
        IoError::new(
            ErrorKind::PermissionDenied,
            "destination path outside of mount",
        )
    })?;
    let req_path = path.prefix_with(root);
    Ok(req_path)
}
async fn handle_copy(
    req: Request<Body>,
    src_path: &Path,
    root: &Path,
    web_mount: &Path,
) -> Result<Response<Body>, IoError> {
    let dst_path = get_dst(&req, root, web_mount)?;
    log::info!("Copy {:?} -> {:?}", src_path, dst_path);
    let mut res = Response::new(Body::empty());
    //If a COPY request has an Overwrite header with a value of "F", and a resource exists at the Destination URL, the server MUST fail the request.
    if let Some(b"F") = req.headers().get("Overwrite").map(|v| v.as_bytes()) {
        if let Ok(_) = metadata(&dst_path).await {
            *res.status_mut() = StatusCode::PRECONDITION_FAILED;
            return Ok(res);
        }
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

    409 (Conflict) - No parent folder

    423 (Locked)
    502 (Bad Gateway)
    507 (Insufficient Storage)
    */
    Ok(res)
}
async fn handle_move(
    req: Request<Body>,
    src_path: &Path,
    root: &Path,
    web_mount: &Path,
) -> Result<Response<Body>, IoError> {
    let dst_path = get_dst(&req, root, web_mount)?;
    log::info!("Move {:?} -> {:?}", src_path, dst_path);
    let mut res = Response::new(Body::empty());
    match req.headers().get("Overwrite").map(|v| v.as_bytes()) {
        Some(b"F") => {
            if let Ok(_) = metadata(&dst_path).await {
                *res.status_mut() = StatusCode::PRECONDITION_FAILED;
                return Ok(res);
            }
        }
        Some(b"T") => {
            //MUST perform a DELETE with "Depth: infinity" on the destination resource.
            handle_delete(req, &dst_path).await?;
        }
        _ => {}
    }
    rename(src_path, dst_path).await?;
    //a new URL mapping was created at the destination.
    *res.status_mut() = StatusCode::CREATED;
    /*
    204 (No Content) -> see copy
    207 (Multi-Status) -> see copy
    403 (Forbidden) -> see copy
    409 (Conflict) -> see copy
    423 (Locked)
    502 (Bad Gateway)
    */
    Ok(res)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub dav: PathBuf,
    #[serde(default)]
    pub read_only: bool,
    #[serde(default)]
    pub dont_overwrite: bool,
}
impl Config {
    pub async fn setup(&self) -> Result<(), String> {
        if !self.dav.is_dir() {
            return Err(format!("{:?} ist not a directory", self.dav));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::config::{group_config, UseCase};
    #[test]
    fn basic_config() {
        if let Ok(UseCase::Webdav(w)) = toml::from_str(
            r#"
    dav = "."
        "#,
        ) {
            assert_eq!(w.read_only, false);
            assert_eq!(w.dont_overwrite, false);
        } else {
            panic!("not a webdav");
        }
    }
    #[tokio::test]
    async fn dir_nonexistent() {
        let mut cfg: crate::config::Configuration = toml::from_str(
            r#"
    [host]
    ip = "0.0.0.0:1337"
    dav = "blablahui"
    "#,
        )
        .expect("parse err");
        assert!(group_config(&mut cfg).await.is_err());
    }
}
