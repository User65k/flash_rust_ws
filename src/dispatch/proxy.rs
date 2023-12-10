use bytes::{Bytes, BytesMut};
use hyper::{
    http::uri,
    header::{self, HeaderValue, HeaderName},
    Body, Client, Request, Response, Uri, HeaderMap, StatusCode, upgrade::OnUpgrade, client::HttpConnector,
};
use log::error;
use serde::Deserialize;
use tokio::io::copy_bidirectional;
use std::net::SocketAddr;
use std::{
    convert::TryFrom,
    io::{Error as IoError, ErrorKind},
};

use crate::config::Utf8PathBuf;

/// these have to be removed
static HOP_BY_HOP_HEADERS: [HeaderName; 8] = [
    header::CONNECTION,
    header::TE,
    header::TRAILER,
    //header::UPGRADE, //... we sort of need to perform the same upgrade, so keep it
    header::TRANSFER_ENCODING,
    header::PROXY_AUTHENTICATE,
    header::PROXY_AUTHORIZATION,
    HeaderName::from_static("keep-alive"),
    HeaderName::from_static("proxy-connection")
];
//static X_FORWARDED_FOR: HeaderName = HeaderName::from_static("X-Forwarded-For");
static TRAILERS: &str = "trailers";

fn remove_hop_by_hop_headers(headers: &mut HeaderMap) {
    for hh in &HOP_BY_HOP_HEADERS {
        headers.remove(hh);
    }
}
fn remove_connection_headers(headers: &mut HeaderMap) {
    let value = match headers.get(header::CONNECTION) {
        None => return,
        Some(v) => v.clone(),
    };
    for name in value.to_str().unwrap().split(',') {
        if !name.trim().is_empty() {
            headers.remove(name.trim());
        }
    }
}

pub async fn forward(
    mut req: Request<Body>,
    req_path: &super::WebPath<'_>,
    remote_addr: SocketAddr,
    config: &Proxy,
) -> Result<Response<Body>, IoError> {

    let query = req.uri().query();

    let mut new_path = req_path.prefixed_as_abs_url_path(&config.forward.path, query.map(|s|s.len()+1).unwrap_or(0));

    if let Some(q) = query {
        new_path.push('?');
        new_path.push_str(q);
    }

    let new_uri = Uri::builder()
        .scheme(config.forward.scheme.clone())
        .authority(config.forward.authority.clone())
        .path_and_query(new_path)
        .build()
        .unwrap();//can't happen - all parts set
    *req.uri_mut() = new_uri;

    //new host header
    req.headers_mut().insert(header::HOST, HeaderValue::from_bytes(config.forward.authority.as_str().as_bytes()).expect("authority not a header value"));

    let contains_te_trailers_value = req
        .headers()
        .get(header::TE)
        .map(|value| {
            value
                .to_str()
                .unwrap()
                .split(',')
                .any(|e| e.trim() == TRAILERS)
        })
        .unwrap_or(false);
    remove_hop_by_hop_headers(req.headers_mut());
    remove_connection_headers(req.headers_mut());
    if contains_te_trailers_value {
        req.headers_mut()
            .insert(header::TE, HeaderValue::from_static(TRAILERS));
    }

    if config.add_forwarded_header {
        //https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Forwarded
        let mut buf = BytesMut::with_capacity(512);
        buf.extend_from_slice(b"for=");
        buf.extend_from_slice(remote_addr.ip().to_string().as_bytes());
        //add old forwarded-for
        for hv in req.headers().get_all(header::FORWARDED) {
            let hv = hv.as_ref();
            if let Some(pos) = hv.windows(4).position(|window| window == b"for=") {
                buf.extend_from_slice(b", ");
                if let Some(pos_end) = hv[pos..].iter().position(|c| *c == b';') {
                    buf.extend_from_slice(&hv[pos..pos + pos_end - 1]);
                } else {
                    buf.extend_from_slice(&hv[pos..]);
                }
            }
        }
        //add host header
        if let Some(host) = super::get_host(&req) {
            buf.extend_from_slice(b"; host=");
            buf.extend_from_slice(host.as_bytes());
        }
        //;proto=http;by=203.0.113.43
        req.headers_mut()
            .insert(header::FORWARDED, into_header_value(buf.freeze())?);
    }else{
        req.headers_mut().remove(header::FORWARDED);
    }
    /*if config.add_x_forwarded_for_header {
        match req.headers_mut().entry(&X_FORWARDED_FOR) {
            hyper::header::Entry::Vacant(entry) => {
                entry.insert(remote_addr.to_string().parse().expect("client IP had non ascii char"));
            },
            hyper::header::Entry::Occupied(mut entry) => {
                let client_ip_str = remote_addr.to_string();
                let mut addr =
                    BytesMut::with_capacity(entry.iter().map(|s|s.len()+2).sum::<usize>() + client_ip_str.len());

                for e in entry.iter() {
                    addr.extend_from_slice(e.as_bytes());
                    addr.extend_from_slice(b", ");
                }
                addr.extend_from_slice(client_ip_str.as_bytes());
                entry.insert(into_header_value(addr.freeze())?);
            }
        }
    }else{
        req.headers_mut().remove(&X_FORWARDED_FOR);
    }*/
    if let Some(host) = &config.add_via_header_to_server {
        //https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Via
        let mut buf = BytesMut::with_capacity(512);
        buf.extend_from_slice(format!("{:?} {}", req.version(), &host).as_bytes());
        for hv in req.headers().get_all(header::VIA) {
            buf.extend_from_slice(b", ");
            buf.extend_from_slice(hv.as_ref());
        }
        req.headers_mut()
            .insert(header::VIA, into_header_value(buf.freeze())?);
    }else{
        req.headers_mut().remove(header::VIA);
    }

    let request_upgraded = req.extensions_mut().remove::<OnUpgrade>();
    if request_upgraded.is_some() {
        req.headers_mut().insert(header::CONNECTION, HeaderValue::from_static("UPGRADE"));
    }

    let mut resp = match config.client.as_ref().unwrap().request(req).await {
        Ok(r) => r,
        Err(err) => {
            let mut resp = Response::new(Body::empty());
            *resp.status_mut() = hyper::StatusCode::BAD_GATEWAY;

            if let Some(cause) = err.into_cause() {
                if let Some(io_e) = cause.downcast_ref::<IoError>() {
                    if io_e.kind() == ErrorKind::TimedOut {
                        *resp.status_mut() = hyper::StatusCode::GATEWAY_TIMEOUT;
                    }
                }
            }
            resp
        }
    };


    remove_hop_by_hop_headers(resp.headers_mut());
    remove_connection_headers(resp.headers_mut());

    if let Some(host) = &config.add_via_header_to_client {
        //https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Via
        let mut buf = BytesMut::with_capacity(512);
        buf.extend_from_slice(format!("{:?} {}", resp.version(), &host).as_bytes());
        for hv in resp.headers().get_all(header::VIA) {
            buf.extend_from_slice(b", ");
            buf.extend_from_slice(hv.as_ref());
        }
        resp.headers_mut()
            .insert(header::VIA, into_header_value(buf.freeze())?);
    }

    if resp.status() == StatusCode::SWITCHING_PROTOCOLS {
        if let Some(request_upgraded) = request_upgraded {
            let response_upgraded = resp
                .extensions_mut()
                .remove::<OnUpgrade>()
                .expect("SWITCHING_PROTOCOLS response without upgrade extension")
                .await;

            let mut response_upgraded = match response_upgraded {
                Ok(u) => u,
                Err(e) => {
                    error!("response upgrade failed: {}", e);
                    return Err(ErrorKind::InvalidInput.into())
                }
            };

            tokio::spawn(async move {
                let mut request_upgraded =
                    request_upgraded.await.expect("failed to upgrade request");

                copy_bidirectional(&mut response_upgraded, &mut request_upgraded)
                    .await
                    .expect("coping between upgraded connections failed");
            });
        }
    }

    Ok(resp)
}
#[inline]
fn into_header_value(src: Bytes) -> Result<HeaderValue, IoError> {
    HeaderValue::from_maybe_shared(src.clone()).map_err(|_e| {
        IoError::new(
            ErrorKind::InvalidData,
            format!("Invalid Header Value for {:?}", &src),
        )
    })
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct Proxy {
    forward: ProxyAdress,
    #[serde(default = "yes")]
    add_forwarded_header: bool,
    //add_x_forwarded_for_header: bool,
    add_via_header_to_client: Option<String>,
    add_via_header_to_server: Option<String>,
    //timeout: u8,
    //max_req_body_size: u32,
    //allowed_methods: Vec<String>,
    //header_policy: u8,
    //filter_req_header: Vec<String>,
    //filter_resp_header: Vec<String>,
    #[serde(skip)]
    client: Option<Client<HttpConnector>>,
}

#[derive(Deserialize, Debug)]
#[serde(try_from = "String")]
struct ProxyAdress {
    scheme: uri::Scheme,
    authority: uri::Authority,
    path: Utf8PathBuf
}

impl TryFrom<String> for ProxyAdress {
    type Error = anyhow::Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let uri = Uri::try_from(value)?;
        let p = uri.into_parts();
        let scheme = match p.scheme {
            Some(s) => s,
            None => {
                anyhow::bail!("No scheme given");
            },
        };
        let authority = match p.authority {
            Some(a) => a,
            None => {
                anyhow::bail!("No authority/host given");
            }
        };
        let path = if let Some(pq) = p.path_and_query {
            Utf8PathBuf::from(pq.as_str())
        }else{
            Utf8PathBuf::empty()
        };
        Ok(ProxyAdress{ scheme, authority, path })
    }
}

fn yes() -> bool {
    true
}

impl Proxy {
    pub async fn setup(&mut self) -> Result<(), String> {
        self.client = Some(Client::new());
        Ok(())
    }
}

// /lol         -> https://remote/app/
// /lol/static  -> https://remote/lib/
