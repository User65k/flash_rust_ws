use crate::{
    body::{BoxBody, FRWSResult, IncomingBody},
    dispatch::{upgrades::MyUpgraded, webpath::Req},
};
use bytes::{Bytes, BytesMut};
use hyper::{
    header::{self, HeaderName, HeaderValue},
    http::uri,
    upgrade::OnUpgrade,
    HeaderMap, Request, Response, StatusCode, Uri, Version,
};
use log::{debug, error, trace};
use std::io::{Error as IoError, ErrorKind};
use std::net::SocketAddr;
use tokio::io::copy_bidirectional;

mod cfg;
mod client;
#[cfg(test)]
mod test;
use cfg::ForwardedHeader;
pub use cfg::Proxy;

/// these have to be removed
static HOP_BY_HOP_HEADERS: [HeaderName; 7] = [
    // https://datatracker.ietf.org/doc/html/rfc2616#section-13.5.1
    header::CONNECTION,
    header::TE,
    header::TRAILER,
    //header::UPGRADE, //... we sort of need to perform the same upgrade, so keep it
    header::TRANSFER_ENCODING,
    header::PROXY_AUTHENTICATE,
    header::PROXY_AUTHORIZATION,
    HeaderName::from_static("keep-alive"),
];
static X_FORWARDED_FOR: HeaderName = HeaderName::from_static("x-forwarded-for");
static TRAILERS: &str = "trailers";

fn remove_hop_by_hop_headers(headers: &mut HeaderMap) {
    for hh in &HOP_BY_HOP_HEADERS {
        headers.remove(hh);
    }
}
/// remove connection headers before http/1.1
/// https://datatracker.ietf.org/doc/html/rfc2616#section-14.10
fn remove_connection_headers(v: Version, headers: &mut HeaderMap) {
    match v {
        Version::HTTP_09 => {}
        Version::HTTP_10 => {}
        _ => return,
    }
    let value = match headers.get(header::CONNECTION) {
        None => return,
        Some(v) => v.clone(),
    };
    for name in value.to_str().unwrap().split(',') {
        let name = name.trim();
        if !name.is_empty() {
            headers.remove(name);
        }
    }
}

fn get_upgrade_type(headers: &mut HeaderMap) -> Option<HeaderValue> {
    if headers
        .get(header::CONNECTION)
        .map(|value| {
            value
                .to_str()
                .unwrap()
                .split(',')
                .any(|e| e.trim() == header::UPGRADE)
        })
        .unwrap_or(false)
    {
        if let Some(upgrade_value) = headers.remove(header::UPGRADE) {
            debug!("Found upgrade header with value: {:?}", upgrade_value);
            return Some(upgrade_value);
        }
    }

    None
}

fn change_req_from_h2_to_h11(req: &mut Request<IncomingBody>) {
    trace!("downgrading from h2 to h1.1");
    let mut value_buf = BytesMut::with_capacity(512);
    let mut first = false;
    for v in req.headers().get_all(header::COOKIE) {
        if !first {
            first = true;
        } else {
            bytes::BufMut::put_u8(&mut value_buf, b';');
        }
        let v = v.as_bytes();
        bytes::BufMut::put_slice(&mut value_buf, v); //copy
    }
    if first {
        req.headers_mut().insert(
            header::COOKIE,
            HeaderValue::from_bytes(value_buf.as_ref()).expect("was a HV before"),
        );
    }
    *req.version_mut() = hyper::Version::HTTP_11;
}

fn check_upgrade(up: HeaderValue, config: &Proxy) -> Option<HeaderValue> {
    if let Some(upgrades) = config.allowed_upgrades.as_ref() {
        //check the allow list
        for u in upgrades {
            if u == &up {
                return Some(up);
            }
        }
        None
    } else {
        // any upgrade is ok, but...
        // https://book.hacktricks.xyz/pentesting-web/h2c-smuggling
        if up == "h2c" {
            // an http proto upgrade needs to be done with the proxy, not the system behind it
            // as the proto upgrade is not specific to this usecase it is not handled here (if we handle it at all)
            None
        } else {
            Some(up)
        }
    }
}

fn check_method(method: &hyper::Method, config: &Proxy) -> bool {
    if let Some(methods) = config.allowed_methods.as_ref() {
        for m in methods {
            if method == m.as_str() {
                return true;
            }
        }
        false
    } else {
        method != hyper::Method::CONNECT
    }
}

pub async fn forward(
    req: Req<IncomingBody>,
    remote_addr: SocketAddr,
    config: &Proxy,
) -> FRWSResult {
    let query = req.query();

    let mut new_path = req.path().prefixed_as_abs_url_path(
        config.forward.path.as_str(),
        query.map(|s| s.len() + 1).unwrap_or(0),
        true,
    );

    if let Some(q) = query {
        new_path.push('?');
        new_path.push_str(q);
    }

    let (parts, body) = req.into_parts();

    if !check_method(&parts.method, config) {
        let mut resp = Response::new(BoxBody::empty());
        *resp.status_mut() = hyper::StatusCode::METHOD_NOT_ALLOWED;
        return Ok(resp);
    }

    let mut req = hyper::Request::from_parts(parts, body);

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
    let request_upgraded = req.extensions_mut().remove::<OnUpgrade>();
    let request_upgrade =
        get_upgrade_type(req.headers_mut()).and_then(|u| check_upgrade(u, config));

    remove_connection_headers(req.version(), req.headers_mut());
    remove_hop_by_hop_headers(req.headers_mut());
    if contains_te_trailers_value {
        req.headers_mut()
            .insert(header::TE, HeaderValue::from_static(TRAILERS));
    }

    match config.add_forwarded_header {
        ForwardedHeader::Replace | ForwardedHeader::Extend => {
            //https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Forwarded
            let mut buf = BytesMut::with_capacity(512);

            if let ForwardedHeader::Extend = config.add_forwarded_header {
                //add old forwarded-for
                for hv in req.headers().get_all(header::FORWARDED) {
                    let hv = hv.as_ref();
                    if let Some(pos) = hv.windows(4).position(|window| window == b"for=") {
                        if let Some(pos_end) = hv[pos..].iter().position(|c| *c == b';') {
                            buf.extend_from_slice(&hv[pos..pos + pos_end - 1]);
                        } else {
                            buf.extend_from_slice(&hv[pos..]);
                        }
                        buf.extend_from_slice(b", ");
                    }
                }
            }
            buf.extend_from_slice(b"for=");

            let ip_str = match remote_addr.ip() {
                std::net::IpAddr::V4(v4) => v4.to_string(),
                std::net::IpAddr::V6(v6) => format!("\"[{}]\"", v6),
            };

            buf.extend_from_slice(ip_str.as_bytes());
            //add host header
            if let Some(host) = req.extensions().get::<uri::Authority>() {
                buf.extend_from_slice(b"; host=");
                buf.extend_from_slice(host.as_str().as_bytes());
            }
            //;proto=http;by=203.0.113.43
            req.headers_mut()
                .insert(header::FORWARDED, into_header_value(buf.freeze())?);
        }
        ForwardedHeader::Remove => {
            req.headers_mut().remove(header::FORWARDED);
        }
    }
    if config.add_x_forwarded_for_header {
        match req.headers_mut().entry(&X_FORWARDED_FOR) {
            hyper::header::Entry::Vacant(entry) => {
                entry.insert(
                    remote_addr
                        .ip()
                        .to_string()
                        .parse()
                        .expect("client IP had non ascii char"),
                );
            }
            hyper::header::Entry::Occupied(mut entry) => {
                let client_ip_str = remote_addr.ip().to_string();
                let mut addr = BytesMut::with_capacity(
                    entry.iter().map(|s| s.len() + 2).sum::<usize>() + client_ip_str.len(),
                );

                for e in entry.iter() {
                    addr.extend_from_slice(e.as_bytes());
                    addr.extend_from_slice(b", ");
                }
                addr.extend_from_slice(client_ip_str.as_bytes());
                entry.insert(into_header_value(addr.freeze())?);
            }
        }
    } else {
        req.headers_mut().remove(&X_FORWARDED_FOR);
    }
    if let Some(host) = &config.add_via_header_to_server {
        //https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Via
        let mut buf = BytesMut::with_capacity(512);
        for hv in req.headers().get_all(header::VIA) {
            buf.extend_from_slice(hv.as_ref());
            buf.extend_from_slice(b", ");
        }
        buf.extend_from_slice(format!("{:?} {}", req.version(), &host).as_bytes());
        req.headers_mut()
            .insert(header::VIA, into_header_value(buf.freeze())?);
    } else {
        req.headers_mut().remove(header::VIA);
    }

    if let (Some(_), Some(val)) = (request_upgraded.as_ref(), request_upgrade.as_ref()) {
        req.headers_mut()
            .insert(header::CONNECTION, HeaderValue::from_static("UPGRADE"));
        req.headers_mut().insert(header::UPGRADE, val.clone());
    }

    let req_vers = config
        .client
        .as_ref()
        .unwrap()
        .get_supported_version()
        .await;
    if req_vers == Version::HTTP_11 && req.version() == Version::HTTP_2 {
        // we need to downgrade from h2 to h1.1
        change_req_from_h2_to_h11(&mut req);
    }

    if req.version() == Version::HTTP_2 {
        let new_uri = Uri::builder()
            .scheme(config.forward.scheme.clone())
            .authority(config.forward.host.as_bytes())
            .path_and_query(new_path)
            .build()
            .unwrap(); //can't happen - all parts set
        trace!("Forward h2 to {}", &new_uri);
        *req.uri_mut() = new_uri;
    } else {
        let new_uri = Uri::builder().path_and_query(new_path).build().unwrap(); //can't happen - only path_and_query set
        trace!("Forward h1 to {}", &new_uri);
        *req.uri_mut() = new_uri;
        //new host header
        req.headers_mut()
            .insert(header::HOST, config.forward.host.clone());
    }
    let mut resp = match config.request(req).await {
        Ok(r) => r,
        Err(err) => {
            error!("Bad Gateway: {}", err);
            let mut resp = Response::new(BoxBody::empty());
            *resp.status_mut() = hyper::StatusCode::BAD_GATEWAY;

            if err.kind() == ErrorKind::TimedOut {
                *resp.status_mut() = hyper::StatusCode::GATEWAY_TIMEOUT;
            }
            return Ok(resp);
        }
    };
    debug!("response: {:?} {:?}", resp.status(), resp.headers());

    let resp_upgrade = get_upgrade_type(resp.headers_mut());
    remove_connection_headers(resp.version(), resp.headers_mut());
    remove_hop_by_hop_headers(resp.headers_mut());

    if let Some(host) = &config.add_via_header_to_client {
        //https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Via
        let mut buf = BytesMut::with_capacity(512);
        for hv in resp.headers().get_all(header::VIA) {
            buf.extend_from_slice(hv.as_ref());
            buf.extend_from_slice(b", ");
        }
        buf.extend_from_slice(format!("{:?} {}", resp.version(), &host).as_bytes());
        resp.headers_mut()
            .insert(header::VIA, into_header_value(buf.freeze())?);
    }

    if resp.status() == StatusCode::SWITCHING_PROTOCOLS {
        if request_upgrade != resp_upgrade {
            error!(
                "client upgrade {:?} != server upgrade {:?}",
                request_upgrade, resp_upgrade
            );
            return Err(ErrorKind::InvalidInput.into());
        }
        if let Some(request_upgraded) = request_upgraded {
            let response_upgraded = resp
                .extensions_mut()
                .remove::<OnUpgrade>()
                .expect("SWITCHING_PROTOCOLS response without upgrade extension")
                .await;

            let mut response_upgraded = match response_upgraded {
                Ok(u) => MyUpgraded::new(u),
                Err(e) => {
                    error!("response upgrade failed: {}", e);
                    let resp = Response::builder()
                        .status(hyper::StatusCode::BAD_GATEWAY)
                        .body(BoxBody::empty())
                        .unwrap();
                    return Ok(resp);
                }
            };

            //was removed by remove_hop_by_hop_headers
            resp.headers_mut()
                .insert(header::CONNECTION, HeaderValue::from_static("UPGRADE"));
            if let Some(u) = resp_upgrade {
                resp.headers_mut().insert(header::UPGRADE, u);
            }

            tokio::spawn(async move {
                let mut request_upgraded =
                    MyUpgraded::new(request_upgraded.await.expect("failed to upgrade request"));

                copy_bidirectional(&mut response_upgraded, &mut request_upgraded)
                    .await
                    .expect("coping between upgraded connections failed");
            });
        }
    }

    Ok(resp.map(BoxBody::Proxy))
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
