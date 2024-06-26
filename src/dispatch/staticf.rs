use hyper::{Method, Response};
use hyper_staticfile::util::FileResponseBuilder;
use hyper_staticfile::ResolvedFile;
use log::debug;
use mime_guess::{Mime, MimeGuess};
use std::fs::{Metadata, OpenOptions as StdOpenOptions};
use std::io::{Error as IoError, ErrorKind as IoErrorKind};
use std::path::Path;
use std::path::PathBuf;
use tokio::fs::{File, OpenOptions};

#[cfg(windows)]
use std::os::windows::fs::OpenOptionsExt;

use crate::body::{BoxBody, FRWSResp, FRWSResult, IncomingBody};
use crate::config::Utf8PathBuf;

use super::webpath::Req;
#[cfg(windows)]
const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x02000000;

/// The result of `resolve_path`.
#[derive(Debug)]
pub enum ResolveResult {
    /// A directory was requested as a file.
    IsDirectory,
    /// The requested file was found.
    Found(File, Metadata, Mime),
}

pub async fn return_file(
    req: Req<IncomingBody>,
    file: File,
    metadata: Metadata,
    mime: Mime,
) -> FRWSResult {
    // Handle only `GET`/`HEAD` and absolute paths.
    match *req.method() {
        Method::HEAD | Method::GET => {}
        Method::OPTIONS => {
            return Ok(Response::builder()
                .status(hyper::StatusCode::OK)
                .header(hyper::header::ALLOW, "GET,HEAD,OPTIONS")
                .body(BoxBody::empty())
                .expect("unable to build response"))
        }
        _ => {
            return Ok(Response::builder()
                .status(hyper::StatusCode::METHOD_NOT_ALLOWED)
                .body(BoxBody::empty())
                .expect("unable to build response"));
        }
    }
    let (parts, body) = req.into_parts();
    let req = hyper::Request::from_parts(parts, body);

    debug!("resolved to {:?}", file);
    Ok(FileResponseBuilder::new()
        .request(&req)
        .cache_headers(Some(500))
        .build(ResolvedFile {
            handle: file,
            path: PathBuf::new(),
            size: metadata.len(),
            modified: metadata.modified().ok(),
            content_type: Some(mime.to_string()),
            encoding: None,
        })
        .expect("unable to build response")
        .map(BoxBody::File))
}

pub fn redirect(req: &Req<IncomingBody>) -> FRWSResp {
    //request for a file that is a directory
    let mut target_url = req.path().prefixed_as_abs_url_path(
        req.mount(),
        req.query().map_or(1, |q| q.len() + 2),
        true,
    );
    //if !target_url.ends_with('/') { //happens if req_path was empty
    if !req.path().is_empty() {
        target_url.push('/');
    }
    if let Some(q) = req.query() {
        target_url.push('?');
        target_url.push_str(q);
    }

    Response::builder()
        .status(hyper::StatusCode::MOVED_PERMANENTLY)
        .header(hyper::header::LOCATION, target_url)
        .body(BoxBody::empty())
        .expect("unable to build redirect")
}

/// Open a file and get metadata.
pub async fn open_with_metadata(path: impl AsRef<Path>) -> Result<(File, Metadata), IoError> {
    let mut opts = StdOpenOptions::new();
    opts.read(true);

    // On Windows, we need to set this flag to be able to open directories.
    #[cfg(windows)]
    opts.custom_flags(FILE_FLAG_BACKUP_SEMANTICS);

    let file = OpenOptions::from(opts).open(&path).await?;
    let metadata = file.metadata().await?;
    Ok((file, metadata))
}

pub async fn resolve_path(
    full_path: &Path,
    is_dir_request: bool,
    index_files: &Option<Vec<Utf8PathBuf>>,
) -> Result<(PathBuf, ResolveResult), IoError> {
    let (file, metadata) = open_with_metadata(&full_path).await?;
    debug!("have {:?}", metadata);

    // The resolved `full_path` doesn't contain the trailing slash anymore, so we may
    // have opened a file for a directory request, which we treat as 'not found'.
    if is_dir_request && !metadata.is_dir() {
        return Err(IoError::new(IoErrorKind::NotFound, ""));
    }

    // We may have opened a directory for a file request, in which case we redirect.
    if !is_dir_request && metadata.is_dir() {
        return Ok((full_path.into(), ResolveResult::IsDirectory));
    }

    // If not a directory, serve this file.
    if !is_dir_request {
        let mime = MimeGuess::from_path(full_path).first_or_octet_stream();
        return Ok((full_path.into(), ResolveResult::Found(file, metadata, mime)));
    }
    debug!("dir {:?}", full_path);

    if let Some(ifiles) = index_files {
        // Resolve the directory index.
        for index_file in ifiles {
            let full_path_index = full_path.join(index_file);
            debug!("checking for {:?}", full_path_index);
            if let Ok((file, metadata)) = open_with_metadata(&full_path_index).await {
                // The directory index cannot itself be a directory.
                if metadata.is_dir() {
                    return Err(IoError::new(IoErrorKind::NotFound, ""));
                }

                // Serve this file.
                let mime = MimeGuess::from_path(&full_path_index).first_or_octet_stream();
                return Ok((full_path_index, ResolveResult::Found(file, metadata, mime)));
            }
        }
    }
    Err(IoError::new(
        IoErrorKind::PermissionDenied,
        "dir w/o index file",
    ))
}

#[cfg(test)]
mod tests {
    use crate::{
        body::{
            test::{to_bytes, TestBody},
            FRWSResult,
        },
        config::{AbsPathBuf, StaticFiles, UseCase, Utf8PathBuf, WwwRoot},
        dispatch::{
            test::{TempDir, TempFile},
            webpath::Req,
        },
    };
    use hyper::{header, Request};
    use std::path::Path;
    //use crate::dispatch::test::

    #[test]
    fn basic_config() {
        if let Ok(UseCase::StaticFiles(s)) = toml::from_str(
            r#"
    dir = "."
        "#,
        ) {
            assert!(!s.follow_symlinks);
        } else {
            panic!("not a StaticFiles");
        }
    }

    async fn handle_wwwroot(req: Request<TestBody>, sf: StaticFiles) -> FRWSResult {
        let wwwr = WwwRoot {
            mount: UseCase::StaticFiles(sf),
            header: None,
            auth: None,
        };
        let remote_addr = "127.0.0.1:8080".parse().unwrap();

        let req = Req::test_on_mount(req);

        crate::dispatch::handle_wwwroot(req, &wwwr, remote_addr).await
    }

    #[tokio::test]
    async fn resolve_file() {
        let file_content = &b"test_resolve_file"[..];
        let _tf = TempFile::create("test_resolve_file", file_content);

        let sf = StaticFiles {
            dir: AbsPathBuf::temp_dir(),
            follow_symlinks: false,
            index: None,
            serve: None,
        };
        let req = Request::get("/mount/test_resolve_file")
            .body(TestBody::empty())
            .unwrap();
        let res = handle_wwwroot(req, sf).await;
        let res = res.unwrap();
        assert_eq!(res.status(), 200);
        let body = to_bytes(res.into_body()).await;
        assert_eq!(body, file_content);
    }
    #[tokio::test]
    async fn index_file() {
        let file_content = &b"test_index_file"[..];
        let _tf = TempFile::create("test_index_file", file_content);

        let sf = StaticFiles {
            dir: AbsPathBuf::temp_dir(),
            follow_symlinks: false,
            index: Some(vec![Utf8PathBuf::from("test_index_file")]),
            serve: None,
        };
        let req = Request::get("/mount/").body(TestBody::empty()).unwrap();
        let res = handle_wwwroot(req, sf).await;
        let res = res.unwrap();
        assert_eq!(res.status(), 200);
        let body = to_bytes(res.into_body()).await;
        assert_eq!(body, file_content);
    }
    #[tokio::test]
    async fn no_index() {
        let sf = StaticFiles {
            dir: AbsPathBuf::temp_dir(),
            follow_symlinks: false,
            index: None,
            serve: None,
        };
        let req = Request::get("/mount/").body(TestBody::empty()).unwrap();
        let res = handle_wwwroot(req, sf).await;
        let res = res.unwrap_err();
        assert_eq!(res.kind(), std::io::ErrorKind::PermissionDenied);
        assert_eq!(res.into_inner().unwrap().to_string(), "dir w/o index file");
    }
    #[tokio::test]
    async fn allowlist_blocks() {
        let file_content = &b"test_allowlist"[..];
        let _tf = TempFile::create("test_allowlist", file_content);

        let sf = StaticFiles {
            dir: AbsPathBuf::temp_dir(),
            follow_symlinks: false,
            index: None,
            serve: Some(vec![Utf8PathBuf::from("allow")]),
        };
        let req = Request::get("/mount/test_allowlist")
            .body(TestBody::empty())
            .unwrap();
        let res = handle_wwwroot(req, sf).await;
        let res = res.unwrap_err();
        assert_eq!(res.kind(), std::io::ErrorKind::PermissionDenied);
        assert_eq!(res.into_inner().unwrap().to_string(), "bad file extension");
    }
    #[tokio::test]
    async fn allowlist_allows() {
        let file_content = &b"test_allowlist_allows"[..];
        let _tf = TempFile::create("test_allowlist.allow", file_content);

        let sf = StaticFiles {
            dir: AbsPathBuf::temp_dir(),
            follow_symlinks: false,
            index: None,
            serve: Some(vec![Utf8PathBuf::from("allow")]),
        };

        let req = Request::get("/mount/test_allowlist.allow")
            .body(TestBody::empty())
            .unwrap();
        let res = handle_wwwroot(req, sf).await;
        let res = res.unwrap();
        assert_eq!(res.status(), 200);
        let body = to_bytes(res.into_body()).await;
        assert_eq!(body, file_content);
    }

    #[tokio::test]
    async fn dir_redir() {
        let _d = TempDir::create("test_dir_redir");

        let sf = StaticFiles {
            dir: AbsPathBuf::temp_dir(),
            follow_symlinks: false,
            index: None,
            serve: None,
        };
        let req = Request::get("/mount/test_dir_redir")
            .body(TestBody::empty())
            .unwrap();
        let res = handle_wwwroot(req, sf).await;
        let res = res.unwrap();
        assert_eq!(res.status(), hyper::StatusCode::MOVED_PERMANENTLY);
        assert_eq!(
            res.headers()
                .get(hyper::header::LOCATION)
                .map(|h| h.as_bytes()),
            Some(&b"/mount/test_dir_redir/"[..])
        );
    }
    #[tokio::test]
    async fn redirects_to_sanitized_path() {
        let _d = TempDir::create("redirects_to_sanitized_path");

        let sf = StaticFiles {
            dir: AbsPathBuf::temp_dir(),
            follow_symlinks: false,
            index: None,
            serve: None,
        };
        let req = Request::get("/mount//foo.org/redirects_to_sanitized_path")
            .body(TestBody::empty())
            .unwrap();
        let req_path = crate::dispatch::WebPath::try_from(req.uri()).unwrap();
        let rel_path = req_path.strip_prefix(Path::new("mount")).unwrap();

        assert_eq!(rel_path, "foo.org/redirects_to_sanitized_path");

        let res = handle_wwwroot(req, sf).await;
        let res = res.unwrap_err();
        assert_eq!(res.kind(), std::io::ErrorKind::NotFound);
    }

    #[tokio::test]
    async fn resolve_nested_file() {
        let file_content = &b"nested_resolve_file"[..];
        let _tf = TempDir::create("nested");
        std::fs::write(
            std::env::temp_dir().join("nested/resolve_file"),
            file_content,
        )
        .unwrap();

        let sf = StaticFiles {
            dir: AbsPathBuf::temp_dir(),
            follow_symlinks: false,
            index: None,
            serve: None,
        };
        let req = Request::get("/mount/nested/resolve_file")
            .body(TestBody::empty())
            .unwrap();
        let res = handle_wwwroot(req, sf).await;
        let res = res.unwrap();
        assert_eq!(res.status(), 200);
        let body = to_bytes(res.into_body()).await;
        assert_eq!(body, file_content);
    }

    #[tokio::test]
    async fn symlink_dir() {
        /*
            {temp}/lnk_target
            {temp}/lnk_nested/ <- MOUNT
            {temp}/lnk_nested/lnk -> ..

        */
        let file_content = &b"lnk_followed"[..];
        let _td1 = TempDir::create("lnk_nested");
        let _tf = TempFile::create("lnk_target", file_content);
        let link = &std::env::temp_dir().join("lnk_nested/lnk");
        let org = Path::new("..");
        let mm = std::env::temp_dir().join("lnk_nested");
        let mount = mm.as_os_str().to_str().unwrap();

        #[cfg(unix)]
        std::os::unix::fs::symlink(org, link).unwrap();
        #[cfg(windows)]
        std::os::windows::fs::symlink_dir(org, link).unwrap();

        let sf = StaticFiles {
            dir: AbsPathBuf::from(mount),
            follow_symlinks: false,
            index: None,
            serve: None,
        };
        let req = Request::get("/mount/lnk/lnk_target")
            .body(TestBody::empty())
            .unwrap();
        let res = handle_wwwroot(req, sf).await.unwrap_err();
        assert_eq!(res.kind(), std::io::ErrorKind::PermissionDenied);

        let sf = StaticFiles {
            dir: AbsPathBuf::from(mount),
            follow_symlinks: true,
            index: None,
            serve: None,
        };
        let req = Request::get("/mount/lnk/lnk_target")
            .body(TestBody::empty())
            .unwrap();
        let res = handle_wwwroot(req, sf).await.unwrap();
        assert_eq!(res.status(), 200);
        let body = to_bytes(res.into_body()).await;
        assert_eq!(body, file_content);
    }

    #[tokio::test]
    async fn symlink_file() {
        /*
            {temp}/lnk_target2
            {temp}/lnk_nested2/ <- MOUNT
            {temp}/lnk_nested2/lnk -> ../lnk_target2

        */
        let file_content = &b"lnk_followed"[..];
        let _td1 = TempDir::create("lnk_nested2");
        let _tf = TempFile::create("lnk_target2", file_content);
        let link = &std::env::temp_dir().join("lnk_nested2/lnk");
        let org = Path::new("..").join("lnk_target2");
        let mm = std::env::temp_dir().join("lnk_nested2");
        let mount = mm.as_os_str().to_str().unwrap();

        #[cfg(unix)]
        std::os::unix::fs::symlink(org, link).unwrap();
        #[cfg(windows)]
        std::os::windows::fs::symlink_file(org, link).unwrap();

        let sf = StaticFiles {
            dir: AbsPathBuf::from(mount),
            follow_symlinks: false,
            index: None,
            serve: None,
        };
        let req = Request::get("/mount/lnk").body(TestBody::empty()).unwrap();
        let res = handle_wwwroot(req, sf).await.unwrap_err();
        assert_eq!(res.kind(), std::io::ErrorKind::PermissionDenied);

        let sf = StaticFiles {
            dir: AbsPathBuf::from(mount),
            follow_symlinks: true,
            index: None,
            serve: None,
        };
        let req = Request::get("/mount/lnk").body(TestBody::empty()).unwrap();
        let res = handle_wwwroot(req, sf).await.unwrap();
        assert_eq!(res.status(), 200);
        let body = to_bytes(res.into_body()).await;
        assert_eq!(body, file_content);
    }
    #[test]
    fn redir_test() {
        let req = Request::get("/mount/this").body(TestBody::empty()).unwrap();
        let req = Req::test_on_mount(req);
        let resp = super::redirect(&req);
        assert_eq!(
            resp.headers().get(header::LOCATION).unwrap(),
            "/mount/this/"
        );

        let req = Request::get("/mount").body(TestBody::empty()).unwrap();
        let req = Req::test_on_mount(req);
        let resp = super::redirect(&req);
        assert_eq!(resp.headers().get(header::LOCATION).unwrap(), "/mount/");
    }
}
