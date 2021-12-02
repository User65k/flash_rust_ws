use super::staticf::{resolve_path, return_file};
use bytes::Bytes;
use hyper::{body::HttpBody, header, Body, Request, Response, StatusCode};
use std::{
    convert::TryFrom,
    io::{Error as IoError, ErrorKind},
    net::SocketAddr,
    path::{Path, PathBuf},
    pin::Pin,
    task::{Context, Poll},
};
//use hyper_staticfile::ResolveResult;
use serde::Deserialize;
use tokio::io::copy as redirect;
use tokio::{
    fs::{copy, create_dir, metadata, remove_dir_all, remove_file, rename, File},
    io::AsyncRead,
};
mod propfind;
use super::{decode_percents, normalize_path};

/// req_path is relative from config.root
/// web_mount is config.root from the client perspective
pub async fn do_dav(
    req: Request<Body>,
    req_path: &Path,
    config: &Config,
    web_mount: &Path,
    _remote_addr: SocketAddr,
) -> Result<Response<Body>, IoError> {
    let abs_doc_root = config.root.canonicalize()?;
    let full_path = abs_doc_root.join(req_path);
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
        "PUT" if !config.read_only => handle_put(req, &full_path).await,
        "COPY" if !config.read_only => {
            handle_copy(req, &full_path, &abs_doc_root, &abs_web_mount).await
        }
        "MOVE" if !config.read_only => {
            handle_move(req, &full_path, &abs_doc_root, &abs_web_mount).await
        }
        "DELETE" if !config.read_only => handle_delete(req, &full_path).await,
        "MKCOL" if !config.read_only => handle_mkdir(req, &full_path).await,
        "PUT" | "COPY" | "MOVE" | "DELETE" | "MKCOL" => {
            Err(IoError::new(ErrorKind::PermissionDenied, "read only"))
        }
        _ => Ok(Response::builder()
            .status(hyper::StatusCode::METHOD_NOT_ALLOWED)
            .body(Body::empty())
            .expect("unable to build response")),
    }
}
async fn handle_get(req: Request<Body>, full_path: &Path) -> Result<Response<Body>, IoError> {
    let follow_symlinks = false;
    let (_, file_lookup) = resolve_path(full_path, false, &None, follow_symlinks).await?;
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
    Ok(res)
}
async fn handle_mkdir(_: Request<Body>, full_path: &Path) -> Result<Response<Body>, IoError> {
    let mut res = Response::new(Body::empty());
    match create_dir(full_path).await {
        Ok(_) => *res.status_mut() = StatusCode::CREATED,
        Err(ref e) if e.kind() == ErrorKind::NotFound => {
            *res.status_mut() = StatusCode::CONFLICT;
        }
        Err(e) => return Err(e),
    };
    log::info!("Created {:?}", full_path);
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
async fn handle_put(req: Request<Body>, full_path: &Path) -> Result<Response<Body>, IoError> {
    log::info!("about to store {:?}", full_path);
    let mut f = File::create(full_path).await?;
    let mut b = BodyW {
        s: req.into_body(),
        b: None,
    };
    redirect(&mut b, &mut f).await?;
    let res = Response::new(Body::empty());
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

    let request_path = PathBuf::from(decode_percents(dst.path()));
    let a = request_path.strip_prefix(web_mount).map_err(|_| {
        IoError::new(
            ErrorKind::PermissionDenied,
            "destination path outside of mount",
        )
    })?;
    let req_path = root.join(normalize_path(a));
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
    copy(src_path, dst_path).await?;
    let mut res = Response::new(Body::empty());
    *res.status_mut() = StatusCode::CREATED;
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
    rename(src_path, dst_path).await?;
    let mut res = Response::new(Body::empty());
    *res.status_mut() = StatusCode::CREATED;
    Ok(res)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub root: PathBuf,
    #[serde(default)]
    pub read_only: bool,
}
impl Config {
    pub async fn setup(&self) -> Result<(), String> {
        if !self.root.is_dir() {
            return Err(format!("{:?} ist not a directory", self.root));
        }
        Ok(())
    }
}
