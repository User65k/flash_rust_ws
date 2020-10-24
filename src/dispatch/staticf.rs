use mime_guess::MimeGuess;
use std::io::{Error as IoError, ErrorKind as IoErrorKind};
use std::path::PathBuf;
use hyper_staticfile::ResolveResult;
use std::fs::{Metadata, OpenOptions as StdOpenOptions};
use std::path::Path;
use tokio::fs::{File, OpenOptions};
use log::debug;
use crate::config::WwwRoot;
use hyper_staticfile::ResponseBuilder as FileResponseBuilder;
use hyper::{Method, Body, Request, Response};

#[cfg(windows)]
use std::os::windows::fs::OpenOptionsExt;
#[cfg(windows)]
use winapi::um::winbase::FILE_FLAG_BACKUP_SEMANTICS;

pub async fn return_file(req: &Request<Body>,
                    wwwr: &WwwRoot,
                    full_path: &PathBuf) -> Result<Response<Body>, IoError> {
    resolve(wwwr, req, full_path).await.map(|result| {
        debug!("resolved to {:?}", result);
        FileResponseBuilder::new()
            .request(&req)
            .cache_headers(Some(500))
            .build(result)
            .expect("unable to build response")
    })
}

/// Open a file and get metadata.
pub async fn open_with_metadata(path: impl AsRef<Path>, follow_symlinks: bool) -> Result<(File, Metadata), IoError> {
    let mut opts = StdOpenOptions::new();
    opts.read(true);

    // On Windows, we need to set this flag to be able to open directories.
    #[cfg(windows)]
    opts.custom_flags(FILE_FLAG_BACKUP_SEMANTICS);

    let file = OpenOptions::from(opts).open(&path).await?;
    let metadata = if follow_symlinks {
        file.metadata().await?
    }else{
        let metadata = tokio::fs::symlink_metadata(path).await?;
        if metadata.file_type().is_symlink() {
            return Err(IoError::new(IoErrorKind::PermissionDenied, "Symlinks are not allowed"));
        }
        metadata
    };
    Ok((file, metadata))
}



pub async fn resolve<B>(
    root: &WwwRoot,
    req: &Request<B>,
    full_path: &PathBuf
) -> Result<ResolveResult, IoError> {
    // Handle only `GET`/`HEAD` and absolute paths.
    match *req.method() {
        Method::HEAD | Method::GET => {}
        _ => {
            return Ok(ResolveResult::MethodNotMatched);
        }
    }

    let is_dir_request = req.uri().path().as_bytes().last() == Some(&b'/');

    resolve_path(full_path, is_dir_request, &root.index, root.follow_symlinks).await
}


pub async fn resolve_path(
    full_path: &Path,
    is_dir_request: bool,
    index_files: &Option<Vec<PathBuf>>,
    follow_symlinks: bool
) -> Result<ResolveResult, IoError> {


    let (file, metadata) = open_with_metadata(&full_path, follow_symlinks).await?;
    debug!("have {:?}",metadata);

    // The resolved `full_path` doesn't contain the trailing slash anymore, so we may
    // have opened a file for a directory request, which we treat as 'not found'.
    if is_dir_request && !metadata.is_dir() {
        return Ok(ResolveResult::NotFound);
    }

    // We may have opened a directory for a file request, in which case we redirect.
    if !is_dir_request && metadata.is_dir() {
        return Ok(ResolveResult::IsDirectory);
    }

    // If not a directory, serve this file.
    if !is_dir_request {
        let mime = MimeGuess::from_path(&full_path).first_or_octet_stream();
        return Ok(ResolveResult::Found(file, metadata, mime));
    }
    debug!("dir {:?}",full_path);

    if let Some(ifiles) = index_files {
        // Resolve the directory index.
        for index_file in ifiles {
            let full_path_index = full_path.join(index_file);
            debug!("checking for {:?}",full_path_index);
            match open_with_metadata(&full_path_index, follow_symlinks).await {
                Ok((file, metadata)) => {

                    // The directory index cannot itself be a directory.
                    if metadata.is_dir() {
                        return Ok(ResolveResult::NotFound);
                    }

                    // Serve this file.
                    let mime = MimeGuess::from_path(full_path_index).first_or_octet_stream();
                    return Ok(ResolveResult::Found(file, metadata, mime))
                },
                _ => {
                    //try nex index file
                },
            }
        }
    }
    Ok(ResolveResult::PermissionDenied)
}