use hyper::Uri;
use std::borrow::{Borrow, Cow};
use std::ffi::{OsStr, OsString};
use std::io::{Error as IoError, ErrorKind};
use std::path::{Path, PathBuf, MAIN_SEPARATOR};

use crate::config::Utf8PathBuf;

impl<'a> TryFrom<&'a Uri> for WebPath<'a> {
    type Error = IoError;
    fn try_from(uri: &'a Uri) -> Result<Self, Self::Error> {
        let path = percent_encoding::percent_decode_str(&uri.path()[1..]).decode_utf8_lossy();

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
                }
                "." => {
                    skip += 2;
                }
                ".." => {
                    if parts.pop().is_none() {
                        return Err(IoError::new(ErrorKind::PermissionDenied, "path traversal"));
                    }
                    skip += 3;
                    if parts.is_empty() {
                        offset = skip + len;
                    }
                }
                comp => {
                    parts.push(comp);
                    len += 1 + comp.len();
                }
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

#[repr(transparent)]
#[derive(Debug)]
pub struct WebPath<'a>(Cow<'a, str>);
impl<'a> WebPath<'a> {
    /// turn it into a path by appending. Never replace the existing root!
    /// rustsec_2022_0072
    pub fn prefix_with(&self, pre: &Path) -> PathBuf {
        let pres: &OsStr = pre.as_ref();
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
            //we only need to this if path starts with "\\?\"
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
                    offset -= 1;
                    break;
                } //no next dir -> no final separator
                (Some(c), p @ Some(s)) if c.as_os_str().to_str() == p => offset += 1 + s.len(),
                (None, Some(_)) => break,
                _ => return Err(()),
            }
        }
        Ok(WebPath(Cow::from(&self.0[offset..])))
    }
    /// Create "/{pre}/{WebPath}" and leave extra_cap of free space at the end
    pub fn prefixed_as_abs_url_path(&self, pre: &Utf8PathBuf, extra_cap: usize) -> String {
        //https://docs.rs/hyper-staticfile/latest/src/hyper_staticfile/response_builder.rs.html#75-123
        let pre = pre.as_str();
        let s = self.0.as_ref();
        let capa = pre.len() + s.len() + extra_cap + 2;
        let mut r = String::with_capacity(capa);
        if !pre.is_empty() && !pre.starts_with('/') {
            r.push('/');
        }
        r.push_str(pre);
        if !pre.ends_with('/') {
            r.push('/');
        }
        r.push_str(s);
        r
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    pub fn clone<'b>(&self) -> WebPath<'b> {
        // not as trait as we change lifetime
        let s: &str = self.0.borrow();
        WebPath(Cow::Owned(s.to_owned()))
    }
    #[cfg(test)]
    pub fn parsed(v: &'a str) -> WebPath<'a> {
        WebPath(Cow::from(v))
    }
}

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
        assert_eq!(
            WebPath::try_from(&"/c:/b".parse().unwrap())
                .unwrap()
                .prefix_with(Path::new("test")),
            Path::new("test/c:/b")
        );

        assert_eq!(
            WebPath::try_from(&"/a/c:/b/d".parse().unwrap())
                .unwrap()
                .prefix_with(Path::new("test")),
            Path::new("test/a/c:/b/d")
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
}
