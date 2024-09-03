use hyper::Uri;
use std::borrow::Cow;
use std::ffi::{OsStr, OsString};
use std::io::{Error as IoError, ErrorKind};
use std::path::{Path, PathBuf, MAIN_SEPARATOR};

use crate::config::AbsPathBuf;

impl<'a> TryFrom<&'a Uri> for WebPath<'a> {
    type Error = IoError;
    fn try_from(uri: &'a Uri) -> Result<Self, Self::Error> {
        if !uri.path().starts_with('/') {
            return Err(IoError::new(ErrorKind::InvalidData, "path does not start with /"));
        }

        let path = percent_encoding::percent_decode_str(&uri.path()[1..]).decode_utf8_lossy();

        //let needs_reencoding = matches!(path, Cow::Owned(_));

        #[cfg(windows)]
        if path.contains('\\') {
            return Err(IoError::new(ErrorKind::InvalidData, "win dir sep"));
        }

        let mut parts = Vec::new();
        let mut len = 0;
        let mut offset = 0;
        let mut skip = 0;
        for p in path.split('/') {
            match p {
                "" => {
                    skip += 1;
                    if len == path.len() {
                        //a dir request ends with this and would clear the offset
                        len += 1;
                        break;
                    }
                }
                "." => {
                    skip += 2;
                }
                ".." => {
                    if parts.pop().is_none() {
                        return Err(IoError::new(ErrorKind::PermissionDenied, "path traversal"));
                    }
                    skip += 3;
                }
                comp => {
                    parts.push(comp);
                    len += 1 + comp.len();
                    continue; //don't reset the offset
                }
            }
            if parts.is_empty() {
                offset = skip + len;
            } else if offset > 0 {
                offset = 0;
            }
        }
        len = len.saturating_sub(1); //leading sep

        if len == path.len() {
            Ok(WebPath(path))
        } else {
            if offset != 0 {
                if let Cow::Borrowed(p) = path {
                    return Ok(WebPath(Cow::from(&p[offset..])));
                }
            }
            let mut r = String::with_capacity(len);
            for p in parts {
                r.push_str(p);
                r.push('/');
            }
            r.pop();
            Ok(WebPath(Cow::from(r)))
        }
    }
}

/// Normalized path
///
/// never starts or ends in /
#[repr(transparent)]
#[derive(Debug)]
pub struct WebPath<'a>(Cow<'a, str>);
impl<'a> WebPath<'a> {
    /// turn it into a path by appending. Never replace the existing root!
    /// rustsec_2022_0072
    pub fn prefix_with(&self, pre: &AbsPathBuf) -> PathBuf {
        let pres: &OsStr = pre.as_os_str();
        let mut r = OsString::with_capacity(pres.len() + 1 + self.0.len());
        r.push(pres);
        if let Some(false) = pres.to_str().map(|s| s.ends_with(MAIN_SEPARATOR)) {
            r.push::<String>(MAIN_SEPARATOR.into());
        }
        //does never start with a separator
        #[cfg(not(windows))]
        r.push(self.0.as_ref());
        #[cfg(windows)]
        {
            //we only need to this if path starts with "\\?\" - AbsPathBuf does
            let mut path = self.0.split('/');
            r.push(path.next().unwrap());
            for p in path {
                r.push::<String>(MAIN_SEPARATOR.into());
                r.push(p);
            }
        }
        PathBuf::from(r)
    }
    pub fn strip_prefix(&'a self, base: &'_ Path) -> Result<WebPath<'a>, ()> {
        let mut strip = base.components();
        let mut path = self.0.split('/');
        let mut offset = 0;
        loop {
            match (strip.next(), path.next()) {
                (None, None) => {
                    offset -= 1; //no next dir -> no final separator
                    break;
                }
                (Some(c), p @ Some(s)) if c.as_os_str().to_str() == p => offset += 1 + s.len(),
                (None, Some(_)) => break,
                _ => return Err(()),
            }
        }
        Ok(WebPath(Cow::from(&self.0[offset..])))
    }
    /// Create "/{pre}/{WebPath}" and leave extra_cap of free space at the end
    pub fn prefixed_as_abs_url_path(
        &self,
        pre: &str,
        extra_cap: usize,
        encode: bool,
    ) -> String {
        //https://docs.rs/hyper-staticfile/latest/src/hyper_staticfile/response_builder.rs.html#75-123
        let s = self.0.as_ref();
        let capa = pre.len() + s.len() + extra_cap + 2;
        let mut r = String::with_capacity(capa);
        if !pre.is_empty() && !pre.starts_with('/') {
            r.push('/');
        }
        if encode {
            for str in percent_encoding::utf8_percent_encode(pre, URI_DIR) {
                r.push_str(str);
            }
        } else {
            r.push_str(pre);
        }
        if !pre.ends_with('/') {
            r.push('/');
        }
        if encode {
            for str in percent_encoding::utf8_percent_encode(s, URI_DIR) {
                r.push_str(str);
            }
        } else {
            r.push_str(s);
        }
        r
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

enum WebPathSelfRef {
    Owned(String),
    ///index into orig_uri.path
    Borrowed(usize),
}
/// request with normalized path added
pub struct Req<B> {
    parts: hyper::http::request::Parts,
    /// normalized path
    path: WebPathSelfRef,
    /// path with striped mount point
    prefix_len: usize,
    body: B,
}
impl<B> Req<B> {
    pub fn from_req(req: hyper::Request<B>) -> Result<Req<B>, IoError> {
        let (parts, body) = req.into_parts();
        let req_path = WebPath::try_from(&parts.uri)?;
        let path = match req_path.0 {
            Cow::Borrowed(b) => WebPathSelfRef::Borrowed({
                //its either everything or starting at an offset
                parts.uri.path().len() - b.len()
            }),
            Cow::Owned(o) => WebPathSelfRef::Owned(o),
        };
        Ok(Req {
            parts,
            path,
            prefix_len: 0,
            body,
        })
    }
    #[cfg(test)]
    pub fn test_on_mount(req: hyper::Request<B>) -> Req<B> {
        let req = Self::from_req(req).unwrap();
        let offset = req
            .is_prefix(Path::new("mount"))
            .expect("request goes into /mount/...");
        req.strip_prefix(offset)
    }
    /// return the normalized path. With mount point stripped away
    pub fn path(&self) -> WebPath<'_> {
        WebPath(Cow::Borrowed(match &self.path {
            WebPathSelfRef::Owned(s) => &s[self.prefix_len..],
            WebPathSelfRef::Borrowed(b) => &self.parts.uri.path()[*b + self.prefix_len..],
        }))
    }
    #[cfg(feature = "fcgi")]
    #[inline]
    pub fn version(&self) -> hyper::Version {
        self.parts.version
    }
    #[cfg(feature = "fcgi")]
    #[inline]
    pub fn extensions(&self) -> &hyper::http::Extensions {
        &self.parts.extensions
    }
    #[inline]
    pub fn is_dir_req(&self) -> bool {
        self.parts.uri.path().as_bytes().last() == Some(&b'/')
    }
    #[inline]
    pub fn query(&self) -> Option<&str> {
        self.parts.uri.query()
    }
    #[inline]
    pub fn method(&self) -> &hyper::Method {
        &self.parts.method
    }
    #[inline]
    pub fn headers(&self) -> &hyper::HeaderMap<hyper::header::HeaderValue> {
        &self.parts.headers
    }
    pub fn into_parts(self) -> (hyper::http::request::Parts, B) {
        (self.parts, self.body)
    }
    /// return the mount point
    pub fn mount(&self) -> &str {
        let m = match &self.path {
            WebPathSelfRef::Owned(s) => &s[..self.prefix_len],
            WebPathSelfRef::Borrowed(b) => &self.parts.uri.path()[*b..*b + self.prefix_len],
        };
        if m.ends_with('/') {
            return &m[..self.prefix_len-1];
        }
        m
    }
    /// check if `.path()` has a prefix and return the prefixes length
    pub fn is_prefix(&self, base: &'_ Path) -> Result<usize, ()> {
        let path = self.path();
        let mut strip = base.components();
        let mut path = path.0.split('/');
        let mut offset = 0;
        loop {
            match (strip.next(), path.next()) {
                (None, None) => {
                    offset -= 1; //no next dir -> no final separator
                    break;
                }
                (Some(c), p @ Some(s)) if c.as_os_str().to_str() == p => offset += 1 + s.len(),
                (None, Some(_)) => break,
                _ => return Err(()),
            }
        }
        Ok(offset)
    }
    /// split off a `mount()` from `path()` at `offset`
    pub fn strip_prefix(mut self, offset: usize) -> Self {
        debug_assert_eq!(self.prefix_len, 0);
        self.prefix_len = offset;
        self
    }
}

const URI_DIR: &percent_encoding::AsciiSet = &percent_encoding::CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'<')
    .add(b'>')
    .add(b'?')
    .add(b'`')
    .add(b'{')
    .add(b'}');

#[cfg(test)]
impl PartialEq<&str> for WebPath<'_> {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn normalize() {
        assert_eq!(
            WebPath::try_from(&"/a/../b".parse().unwrap()).unwrap().0,
            "b"
        );
        assert_eq!(
            WebPath::try_from(&"/../../".parse().unwrap())
                .unwrap_err()
                .kind(),
            ErrorKind::PermissionDenied
        );
        assert_eq!(
            WebPath::try_from(&"/a/c:/b".parse().unwrap()).unwrap().0,
            "a/c:/b"
        );
        assert_eq!(
            WebPath::try_from(&"/c:/b".parse().unwrap()).unwrap().0,
            "c:/b"
        );
        assert_eq!(
            WebPath::try_from(&"/a/b/c".parse().unwrap())
                .unwrap()
                .strip_prefix(Path::new("a"))
                .unwrap()
                .0,
            "b/c"
        );
    }
    #[test]
    fn rustsec_2022_0072() {
        let td = AbsPathBuf::temp_dir();
        let temp = td.to_str().expect("Temp dir needs to be utf8 for testing");
        assert_eq!(
            WebPath::try_from(&"/c:/b".parse().unwrap())
                .unwrap()
                .prefix_with(&AbsPathBuf::temp_dir())
                .as_os_str(),
            OsString::from(format!("{0}{1}c:{1}b", temp, MAIN_SEPARATOR))
        );

        assert_eq!(
            WebPath::try_from(&"/a/c:/b/d".parse().unwrap())
                .unwrap()
                .prefix_with(&AbsPathBuf::temp_dir())
                .as_os_str(),
            OsString::from(format!("{0}{1}a{1}c:{1}b{1}d", temp, MAIN_SEPARATOR))
        );
    }
    #[test]
    fn cow() {
        assert!(matches!(
            WebPath::try_from(&"/a/b".parse().unwrap()).unwrap().0,
            Cow::Borrowed(_)
        ));
        assert!(matches!(
            WebPath::try_from(&"/c:/d".parse().unwrap()).unwrap().0,
            Cow::Borrowed(_)
        ));
        assert!(matches!(
            WebPath::try_from(&"/e//f".parse().unwrap()).unwrap().0,
            Cow::Owned(_)
        ));
        assert!(matches!(
            WebPath::try_from(&"/g/h/../i".parse().unwrap()).unwrap().0,
            Cow::Owned(_)
        ));
        assert!(matches!(
            WebPath::try_from(&"//./j/../k".parse().unwrap()).unwrap().0,
            Cow::Borrowed("k")
        ));
        assert_eq!(
            WebPath::try_from(&"//./j/../a/b/../k".parse().unwrap())
                .unwrap()
                .0,
            "a/k"
        );
        assert!(matches!(
            WebPath::try_from(&"//./j/../a/b/../k".parse().unwrap())
                .unwrap()
                .0,
            Cow::Owned(_)
        ));
        assert!(matches!(
            WebPath::try_from(&"//./j/../a/b/.././../c".parse().unwrap())
                .unwrap()
                .0,
            Cow::Borrowed("c")
        ));
        assert_eq!(
            WebPath::try_from(&"//./j/../a/.././../".parse().unwrap())
                .unwrap_err()
                .kind(),
            ErrorKind::PermissionDenied
        );
        assert_eq!(
            WebPath::try_from(&"//./j/../a/./k".parse().unwrap())
                .unwrap()
                .0,
            "a/k"
        );
    }
    #[cfg(windows)]
    #[test]
    fn windows_path_sep() {
        assert_eq!(
            WebPath::try_from(&"/a\\..\\..\\..\\..\\..\\".parse().unwrap())
                .unwrap_err()
                .kind(),
            ErrorKind::InvalidData
        );
    }
    #[test]
    fn ito_abs_url() {
        assert_eq!(
            WebPath::try_from(&"/test".parse().unwrap())
                .unwrap()
                .prefixed_as_abs_url_path("", 0, false),
            "/test"
        );
        assert_eq!(
            WebPath::try_from(&"/test".parse().unwrap())
                .unwrap()
                .prefixed_as_abs_url_path("/", 0, false),
            "/test"
        );
        assert_eq!(
            WebPath::try_from(&"/test".parse().unwrap())
                .unwrap()
                .prefixed_as_abs_url_path("/something", 0, false),
            "/something/test"
        );
        assert_eq!(
            WebPath::try_from(&"/test".parse().unwrap())
                .unwrap()
                .prefixed_as_abs_url_path("/something/", 0, false),
            "/something/test"
        );
        assert_eq!(
            WebPath::try_from(&"/".parse().unwrap())
                .unwrap()
                .prefixed_as_abs_url_path("/something/", 0, false),
            "/something/"
        );
        assert_eq!(
            WebPath::try_from(&"/".parse().unwrap())
                .unwrap()
                .prefixed_as_abs_url_path("/something", 0, false),
            "/something/"
        );
    }
    #[test]
    fn encode() {
        assert_eq!(
            WebPath::try_from(&"/test%20bla/ja".parse().unwrap())
                .unwrap()
                .prefixed_as_abs_url_path("", 0, true),
            "/test%20bla/ja"
        );
        assert_eq!(
            WebPath::try_from(&"/test%20bla/ja".parse().unwrap())
                .unwrap()
                .prefixed_as_abs_url_path("", 0, false),
            "/test bla/ja"
        );
    }
    #[test]
    fn borrowed_req() {
        let req = hyper::Request::get("/mount/dir/file").body(()).unwrap();
        let req = Req::test_on_mount(req);
        assert_eq!(req.path(), "dir/file");
        assert_eq!(req.mount(), "mount");
        assert!(matches!(req.path().0, Cow::Borrowed(_)));
    }
    #[test]
    fn misc() {
        assert!(matches!(
            WebPath::try_from(&"/test/c/".parse().unwrap())
                .unwrap()
                .0,
            Cow::Borrowed("test/c/")
        ));
    }
}
