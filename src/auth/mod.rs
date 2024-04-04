use crate::body::{FRWSResp, IncomingBody};
use crate::config::Authenticatoin;
use crate::dispatch::Req;
use std::collections::HashMap;
use std::io::Error as IoError;

mod digest;

pub async fn check_is_authorized(
    auth: &Authenticatoin,
    req: &Req<IncomingBody>,
) -> Result<Option<FRWSResp>, IoError> {
    match auth {
        Authenticatoin::Digest { userfile, realm } => {
            digest::check_digest(userfile, req, realm).await
        }
    }
}

fn strip_prefix<'a>(search: &'a [u8], prefix: &[u8]) -> Option<&'a [u8]> {
    let l = prefix.len();
    if search.len() < l {
        return None;
    }
    if &search[..l] == prefix {
        Some(&search[l..])
    } else {
        None
    }
}

fn get_map_from_header(header: &[u8]) -> Result<HashMap<&[u8], &[u8]>, ()> {
    let mut sep = Vec::new();
    let mut asign = Vec::new();
    let mut i: usize = 0;
    let mut esc = false;
    for c in header {
        match (c, esc) {
            (b'=', false) => asign.push(i),
            (b',', false) => sep.push(i),
            (b'"', false) => esc = true,
            (b'"', true) => esc = false,
            _ => {}
        }
        i += 1;
    }
    sep.push(i); // same len for both Vecs

    i = 0;
    let mut ret = HashMap::new();
    for (&k, &a) in sep.iter().zip(asign.iter()) {
        while header[i] == b' ' {
            i += 1;
        }
        if a <= i || k <= 1 + a {
            //keys and vals must contain one char
            return Err(());
        }
        let key = &header[i..a];
        let val = if header[1 + a] == b'"' && header[k - 1] == b'"' {
            //escaped
            &header[2 + a..k - 1]
        } else {
            //not escaped
            &header[1 + a..k]
        };
        i = 1 + k;
        ret.insert(key, val);
    }
    Ok(ret)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_prefix_from_header() {
        assert!(strip_prefix(b"Digest 1=2", b"Digest ") == Some(b"1=2"));
        assert!(strip_prefix(b"Diges 1=2", b"Digest ") == None);
    }
    #[test]
    fn get_map() {
        let m = get_map_from_header(&b"username=\"dani\", realm=\"a realm\", nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", uri=\"/favicon.ico\", algorithm=MD5-sess, response=\"f02dcc493b488cc25d503c15765a3005\", qop=auth, nc=00000002, cnonce=\"30d60c5e1664d9cb\""[..]).unwrap();

        for (k, v) in &m {
            println!(
                "{:?} = {:?}",
                std::str::from_utf8(k),
                std::str::from_utf8(v)
            );
        }

        assert_eq!(m.get(b"username".as_ref()).unwrap(), &b"dani".as_ref());
        assert_eq!(m.get(b"realm".as_ref()).unwrap(), &&b"a realm"[..]);
        assert_eq!(m.get(b"qop".as_ref()).unwrap(), &&b"auth"[..]);
        assert_eq!(
            m.get(b"nonce".as_ref()).unwrap(),
            &&b"dcd98b7102dd2f0e8b11d0f600bfb0c093"[..]
        );
        assert_eq!(m.get(b"uri".as_ref()).unwrap(), &&b"/favicon.ico"[..]);
        assert_eq!(m.get(b"algorithm".as_ref()).unwrap(), &&b"MD5-sess"[..]);
        assert_eq!(
            m.get(b"response".as_ref()).unwrap(),
            &&b"f02dcc493b488cc25d503c15765a3005"[..]
        );
        assert_eq!(m.get(b"nc".as_ref()).unwrap(), &&b"00000002"[..]);
        assert_eq!(
            m.get(b"cnonce".as_ref()).unwrap(),
            &&b"30d60c5e1664d9cb"[..]
        );

        let m = get_map_from_header(&b"username=\"dani"[..]).unwrap();
        assert_eq!(m.get(b"username".as_ref()).unwrap(), &&b"\"dani"[..]);
        let m = get_map_from_header(&b"username=dani"[..]).unwrap();
        assert_eq!(m.get(b"username".as_ref()).unwrap(), &&b"dani"[..]);
    }

    #[test]
    fn get_map_errors() {
        assert_eq!(get_map_from_header(&b""[..]).unwrap().len(), 0);
        assert!(get_map_from_header(&b"a==b,,b=\""[..]).is_err());
        assert!(get_map_from_header(&b",,12===3"[..]).is_err());
    }
}
