use hyper::{Body, Method, Request, Response};
use hyper_staticfile::ResolveResult;
use hyper_staticfile::ResponseBuilder as FileResponseBuilder;
use log::debug;
use mime_guess::MimeGuess;
use std::fs::{Metadata, OpenOptions as StdOpenOptions};
use std::io::{Error as IoError, ErrorKind as IoErrorKind};
use std::path::Path;
use std::path::PathBuf;
use tokio::fs::{File, OpenOptions};

#[cfg(windows)]
use std::os::windows::fs::OpenOptionsExt;
#[cfg(windows)]
const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x02000000;

pub async fn return_file(
    req: &Request<Body>,
    resolved_file: ResolveResult,
) -> Result<Response<Body>, IoError> {
    // Handle only `GET`/`HEAD` and absolute paths.
    match *req.method() {
        Method::HEAD | Method::GET => {}
        Method::OPTIONS => {
            return Ok(Response::builder()
                .status(hyper::StatusCode::OK)
                .header(hyper::header::ALLOW, "GET,HEAD,OPTIONS")
                .body(Body::empty())
                .expect("unable to build response"))
        }
        _ => {
            return Ok(Response::builder()
                .status(hyper::StatusCode::METHOD_NOT_ALLOWED)
                .body(Body::empty())
                .expect("unable to build response"));
        }
    }

    debug!("resolved to {:?}", resolved_file);
    Ok(FileResponseBuilder::new()
        .request(req)
        .cache_headers(Some(500))
        .build(resolved_file)
        .expect("unable to build response"))
}

/// Open a file and get metadata.
async fn open_with_metadata(
    path: impl AsRef<Path>,
    follow_symlinks: bool,
) -> Result<(File, Metadata), IoError> {
    let mut opts = StdOpenOptions::new();
    opts.read(true);

    // On Windows, we need to set this flag to be able to open directories.
    #[cfg(windows)]
    opts.custom_flags(FILE_FLAG_BACKUP_SEMANTICS);

    let file = OpenOptions::from(opts).open(&path).await?;
    let metadata = if follow_symlinks {
        file.metadata().await?
    } else {
        let metadata = tokio::fs::symlink_metadata(path).await?;
        if metadata.file_type().is_symlink() {
            return Err(IoError::new(
                IoErrorKind::PermissionDenied,
                "Symlinks are not allowed",
            ));
        }
        metadata
    };
    Ok((file, metadata))
}

pub async fn resolve_path(
    full_path: &Path,
    is_dir_request: bool,
    index_files: &Option<Vec<PathBuf>>,
    follow_symlinks: bool,
) -> Result<(PathBuf, ResolveResult), IoError> {
    let (file, metadata) = open_with_metadata(&full_path, follow_symlinks).await?;
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
            if let Ok((file, metadata)) =
                open_with_metadata(&full_path_index, follow_symlinks).await
            {
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
    use std::{
        env::temp_dir,
        path::{Path, PathBuf},
    };

    use crate::config::{StaticFiles, UseCase, WwwRoot};
    use hyper::body::to_bytes;
    use hyper::{Body, Request, Response};
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

    fn create_temp_file(file_name: &str, content: &[u8]) -> TempFile {
        let mut path = temp_dir();
        path.push(file_name);
        let mut file = std::fs::File::create(&path).expect("could not create htdigest file");
        std::io::Write::write_all(&mut file, content).expect("could not write htdigest file");
        TempFile(path)
    }
    struct TempFile(PathBuf);
    impl Drop for TempFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }
    struct TempDir(PathBuf);
    fn create_tmp_dir(name: &str) -> TempDir {
        let d = temp_dir().join(name);
        std::fs::create_dir(&d).expect("could not create dir");
        TempDir(d)
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir(&self.0);
        }
    }

    async fn handle_wwwroot(
        req: Request<Body>,
        sf: StaticFiles,
        req_path: &str,
    ) -> Result<Response<Body>, std::io::Error> {
        let wwwr = WwwRoot {
            mount: UseCase::StaticFiles(sf),
            header: None,
            auth: None,
        };
        let remote_addr = "127.0.0.1:8080".parse().unwrap();

        crate::dispatch::handle_wwwroot(
            req,
            &wwwr,
            crate::dispatch::WebPath::parsed(req_path),
            Path::new("mount"),
            remote_addr,
        )
        .await
    }

    #[tokio::test]
    async fn resolve_file() {
        let file_content = &b"test_resolve_file"[..];
        let _tf = create_temp_file("test_resolve_file", file_content);

        let sf = StaticFiles {
            dir: temp_dir(),
            follow_symlinks: false,
            index: None,
            serve: None,
        };
        let req = Request::get("/mount/test_resolve_file")
            .body(Body::empty())
            .unwrap();
        let res = handle_wwwroot(req, sf, "test_resolve_file").await;
        let res = res.unwrap();
        assert_eq!(res.status(), 200);
        let body = to_bytes(res.into_body()).await.unwrap();
        assert_eq!(body, file_content);
    }
    #[tokio::test]
    async fn index_file() {
        let file_content = &b"test_index_file"[..];
        let _tf = create_temp_file("test_index_file", file_content);

        let sf = StaticFiles {
            dir: temp_dir(),
            follow_symlinks: false,
            index: Some(vec![PathBuf::from("test_index_file")]),
            serve: None,
        };
        let req = Request::get("/mount/").body(Body::empty()).unwrap();
        let res = handle_wwwroot(req, sf, "").await;
        let res = res.unwrap();
        assert_eq!(res.status(), 200);
        let body = to_bytes(res.into_body()).await.unwrap();
        assert_eq!(body, file_content);
    }
    #[tokio::test]
    async fn no_index() {
        let sf = StaticFiles {
            dir: temp_dir(),
            follow_symlinks: false,
            index: None,
            serve: None,
        };
        let req = Request::get("/mount/").body(Body::empty()).unwrap();
        let res = handle_wwwroot(req, sf, "").await;
        let res = res.unwrap_err();
        assert_eq!(res.kind(), std::io::ErrorKind::PermissionDenied);
        assert_eq!(res.into_inner().unwrap().to_string(), "dir w/o index file");
    }
    #[tokio::test]
    async fn allowlist_blocks() {
        let file_content = &b"test_allowlist"[..];
        let _tf = create_temp_file("test_allowlist", file_content);

        let sf = StaticFiles {
            dir: temp_dir(),
            follow_symlinks: false,
            index: None,
            serve: Some(vec![PathBuf::from("allow")]),
        };
        let req = Request::get("/mount/test_allowlist")
            .body(Body::empty())
            .unwrap();
        let res = handle_wwwroot(req, sf, "test_allowlist").await;
        let res = res.unwrap_err();
        assert_eq!(res.kind(), std::io::ErrorKind::PermissionDenied);
        assert_eq!(res.into_inner().unwrap().to_string(), "bad file extension");
    }
    #[tokio::test]
    async fn allowlist_allows() {
        let file_content = &b"test_allowlist_allows"[..];
        let _tf = create_temp_file("test_allowlist.allow", file_content);

        let sf = StaticFiles {
            dir: temp_dir(),
            follow_symlinks: false,
            index: None,
            serve: Some(vec![PathBuf::from("allow")]),
        };

        let req = Request::get("/mount/test_allowlist.allow")
            .body(Body::empty())
            .unwrap();
        let res = handle_wwwroot(req, sf, "test_allowlist.allow").await;
        let res = res.unwrap();
        assert_eq!(res.status(), 200);
        let body = to_bytes(res.into_body()).await.unwrap();
        assert_eq!(body, file_content);
    }

    #[tokio::test]
    async fn dir_redir() {
        let _d = create_tmp_dir("test_dir_redir");

        let sf = StaticFiles {
            dir: temp_dir(),
            follow_symlinks: false,
            index: None,
            serve: None,
        };
        let req = Request::get("/mount/test_dir_redir")
            .body(Body::empty())
            .unwrap();
        let res = handle_wwwroot(req, sf, "test_dir_redir").await;
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
        let _d = create_tmp_dir("redirects_to_sanitized_path");

        let sf = StaticFiles {
            dir: temp_dir(),
            follow_symlinks: false,
            index: None,
            serve: None,
        };
        let req = Request::get("/mount//foo.org/redirects_to_sanitized_path")
            .body(Body::empty())
            .unwrap();
        let req_path = crate::dispatch::decode_and_normalize_path(req.uri()).unwrap();
        let rel_path = req_path.strip_prefix(Path::new("mount")).unwrap();

        assert_eq!(rel_path, "foo.org/redirects_to_sanitized_path");

        let res = handle_wwwroot(req, sf, "foo.org/redirects_to_sanitized_path").await;
        let res = res.unwrap_err();
        assert_eq!(res.kind(), std::io::ErrorKind::NotFound);
    }

    //TODO symlink
    //std::os::unix::fs::symlink
}
