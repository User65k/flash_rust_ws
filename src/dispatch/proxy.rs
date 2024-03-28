use crate::{
    body::{BoxBody, FRWSResult, IncomingBody},
    config::Utf8PathBuf,
    dispatch::upgrades::MyUpgraded,
};
use bytes::{Bytes, BytesMut};
use hyper::{
    header::{self, HeaderName, HeaderValue},
    http::uri,
    upgrade::OnUpgrade,
    HeaderMap, Request, Response, StatusCode, Uri, Version,
};
use hyper_util::{
    client::legacy::{connect::HttpConnector, Client},
    rt::TokioExecutor,
};
use log::{debug, error, trace};
use serde::Deserialize;
use std::{
    convert::TryFrom,
    io::{Error as IoError, ErrorKind},
};
use std::{error::Error, net::SocketAddr};
use tokio::io::copy_bidirectional;

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

fn get_upgrade_type(headers: &HeaderMap) -> Option<String> {
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
        if let Some(upgrade_value) = headers.get(header::UPGRADE) {
            debug!(
                "Found upgrade header with value: {:?}",
                upgrade_value
            );
            // https://book.hacktricks.xyz/pentesting-web/h2c-smuggling
            if upgrade_value == "h2c" {
                // an http proto upgrade needs to be done with the proxy, not the system behind it
                // as the proto upgrade is not specific to this usecase it is not handled here (if at all)
                return None;
            }

            return Some(upgrade_value.to_str().unwrap().to_owned());
        }
    }

    None
}

fn change_req_from_h2_to_h11(req: &mut Request<IncomingBody>) {
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
        req.headers_mut()
        .insert(header::COOKIE, HeaderValue::from_bytes(value_buf.as_ref()).expect("was a HV before"));
    }
    *req.version_mut() = hyper::Version::HTTP_11;
}

pub async fn forward(
    mut req: Request<IncomingBody>,
    req_path: &super::WebPath<'_>,
    remote_addr: SocketAddr,
    config: &Proxy,
) -> FRWSResult {
    let query = req.uri().query();

    let mut new_path = req_path.prefixed_as_abs_url_path(
        &config.forward.path,
        query.map(|s| s.len() + 1).unwrap_or(0),
        true,
    );

    if let Some(q) = query {
        new_path.push('?');
        new_path.push_str(q);
    }

    let new_uri = Uri::builder()
        .scheme(config.forward.scheme.clone())
        .authority(config.forward.authority.clone())
        .path_and_query(new_path)
        .build()
        .unwrap(); //can't happen - all parts set
    trace!("Forward to {}", &new_uri);
    *req.uri_mut() = new_uri;

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
    let request_upgrade = get_upgrade_type(req.headers());

    remove_connection_headers(req.version(), req.headers_mut());
    remove_hop_by_hop_headers(req.headers_mut());
    if contains_te_trailers_value {
        req.headers_mut()
            .insert(header::TE, HeaderValue::from_static(TRAILERS));
    }

    match config.add_forwarded_header {
        ForwardedHeader::Replace  | ForwardedHeader::Extend => {
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
            if let Some(host) = super::get_host(&req) {
                buf.extend_from_slice(b"; host=");
                buf.extend_from_slice(host.as_bytes());
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

    if request_upgraded.is_some() && request_upgrade.is_some() {
        req.headers_mut()
            .insert(header::CONNECTION, HeaderValue::from_static("UPGRADE"));
    }

    match config.forward.scheme.as_str() {
        "http" => {
            if req.version() == hyper::Version::HTTP_2 {
                change_req_from_h2_to_h11(&mut req);
            }

            //new host header
            req.headers_mut().insert(
                header::HOST,
                HeaderValue::from_bytes(config.forward.authority.as_str().as_bytes())
                    .expect("authority not a header value"),
            );
        },
        _ => unreachable!("config should not allow other values"),
    }

    let mut resp = match config.client.as_ref().unwrap().request(req).await {
        Ok(r) => r,
        Err(err) => {
            error!("Bad Gateway: {}", err);
            let mut resp = Response::new(BoxBody::empty());
            *resp.status_mut() = hyper::StatusCode::BAD_GATEWAY;

            if let Some(io_e) = err
                .source()
                .and_then(|cause| cause.downcast_ref::<IoError>())
            {
                if io_e.kind() == ErrorKind::TimedOut {
                    *resp.status_mut() = hyper::StatusCode::GATEWAY_TIMEOUT;
                }
            }
            return Ok(resp);
        }
    };
    debug!("response: {:?} {:?}", resp.status(), resp.headers());

    let resp_upgrade = get_upgrade_type(resp.headers());
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
            error!("client upgrade {:?} != server upgrade {:?}", request_upgrade, resp_upgrade);
            return Err(ErrorKind::InvalidInput.into())
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
#[derive(Deserialize, Debug, Default)]
#[serde(from = "bool")]
enum ForwardedHeader {
    Remove,     //false
    Extend,     //true
    #[default]
    Replace     //?
}
impl From<bool> for ForwardedHeader {
    fn from(value: bool) -> Self {
        if value {
            ForwardedHeader::Extend
        }else{
            ForwardedHeader::Remove
        }
    }
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct Proxy {
    forward: ProxyAdress,
    #[serde(default)]
    add_forwarded_header: ForwardedHeader,
    #[serde(default)]
    add_x_forwarded_for_header: bool,
    add_via_header_to_client: Option<String>,
    add_via_header_to_server: Option<String>,
    #[serde(default = "yes")]
    pub force_dir: bool,
    //timeout: u8,
    //max_req_body_size: u32,
    //allowed_upgrades: Vec<String>,
    //allowed_methods: Vec<String>,
    //header_policy: u8,
    //filter_req_header: Vec<HeaderNameCfg>,
    //filter_resp_header: Vec<HeaderNameCfg>,
    #[serde(skip)]
    client: Option<Client<HttpConnector, IncomingBody>>,
}

#[derive(Deserialize, Debug)]
#[serde(try_from = "String")]
struct ProxyAdress {
    scheme: uri::Scheme,
    authority: uri::Authority,
    path: Utf8PathBuf,
}

impl TryFrom<String> for ProxyAdress {
    type Error = anyhow::Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let uri = Uri::try_from(value)?;
        let p = uri.into_parts();
        let scheme = match p.scheme {
            Some(s) if s == uri::Scheme::HTTP => uri::Scheme::HTTP,
            /*#[cfg(any(feature = "tlsrust", feature = "tlsnative"))]
            Some(s) if s == uri::Scheme::HTTPS => uri::Scheme::HTTPS,
            #[cfg(not(any(feature = "tlsrust", feature = "tlsnative")))]*/
            Some(s) if s == uri::Scheme::HTTPS => {
                anyhow::bail!("TLS support is disabled");
            }
            Some(s) => {
                anyhow::bail!("{} is not known", s);
            }
            None => {
                anyhow::bail!("No scheme given");
            }
        };
        let authority = match p.authority {
            Some(a) => a,
            None => {
                anyhow::bail!("No authority/host given");
            }
        };
        let path = if let Some(pq) = p.path_and_query {
            if pq.query().is_some() {
                anyhow::bail!("query is not supported. Please request support for it. https://github.com/User65k/flash_rust_ws/issues");
            }
            Utf8PathBuf::from(pq.as_str())
        } else {
            Utf8PathBuf::empty()
        };
        Ok(ProxyAdress {
            scheme,
            authority,
            path,
        })
    }
}

fn yes() -> bool {
    true
}

impl Proxy {
    pub async fn setup(&mut self) -> Result<(), String> {
        match self.forward.scheme.as_str() {
            "http" => self.client = Some(Client::builder(TokioExecutor::new()).build_http()),
            #[cfg(any(feature = "tlsrust", feature = "tlsnative"))]
            "https" => { /*
                 let connector = Connector::new();
                 let client = Client::builder().build::<_, Body>(connector);
                 self.client = Some(client);*/
            }
            s => {
                return Err(format!("{} is not known", s));
            }
        }
        Ok(())
    }
}

/*pub struct Connector;

impl Connector {
    pub fn new() -> Connector {
        Connector {}
    }
}
#[cfg(feature = "tlsrust")]
use tokio_rustls::{TlsConnector, rustls::client::ClientConfig};


impl Service<Uri> for Connector {
    type Response = TlsStream;
    type Error = std::io::Error;
    // We can't "name" an `async` generated future.
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        // This connector is always ready, but others might not be.
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, dst: Uri) -> Self::Future {
        let fut = async move {
            let host = match dst.host() {
                Some(s) => s,
                None => {
                    return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "missing host"));
                }
            };
            let port = match dst.port() {
                Some(port) => port.as_u16(),
                None => 443,
            };
            let stream = TcpStream::connect((host, port)).await?;
            let config = ClientConfig::builder().with_safe_defaults().with_root_certificates(root_store).with_no_client_auth();
            TlsConnector::connect(&self, host, stream).await
        };

        Box::pin(fut)
    }
}*/

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::Request;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpStream,
    };

    use crate::{
        body::{test::TestBody, FRWSResp},
        config::{UseCase, Utf8PathBuf},
        dispatch::WebPath,
    };
    #[test]
    fn basic_config() {
        if let Ok(UseCase::Proxy(p)) = toml::from_str(
            r#"
            forward = "http://remote/path"
        "#,
        ) {
            assert_eq!(p.forward.authority, "remote");
            assert_eq!(p.forward.scheme, uri::Scheme::HTTP);
            assert_eq!(p.forward.path, Utf8PathBuf::from("/path"));
            assert!(p.force_dir);
            assert!(matches!(p.add_forwarded_header, ForwardedHeader::Replace));
            assert!(!p.add_x_forwarded_for_header);
        } else {
            panic!("not proxy");
        }
    }

    /// send a request to a FCGI mount and return its TcpStream
    /// (as well as the Task doing the request)
    async fn test_forward(
        req: Request<TestBody>,
        req_path: &str,
        mut proxy: Proxy,
    ) -> (TcpStream, tokio::task::JoinHandle<FRWSResp>) {
        // pick a free port
        let (app_listener, a) = crate::tests::local_socket_pair().await.unwrap();
        let req_path = req_path.to_owned();

        proxy.forward.authority = a.to_string().parse().unwrap();
        proxy.setup().await.unwrap();

        let m = tokio::spawn(async move {
            let res = forward(
                req,
                &WebPath::parsed(&req_path),
                "1.2.3.4:42".parse().unwrap(),
                &proxy,
            )
            .await;
            res.unwrap()
        });
        let (app_socket, _) = app_listener.accept().await.unwrap();
        (app_socket, m)
    }
    #[tokio::test]
    async fn simple_fwd() {
        let req = Request::get("/mount/some/path")
            .body(TestBody::empty())
            .unwrap();
        let (mut s, t) = test_forward(
            req,
            "some/path",
            Proxy {
                forward: "http://ignored/base_path".to_string().try_into().unwrap(),
                add_forwarded_header: ForwardedHeader::Remove,
                add_x_forwarded_for_header: false,
                add_via_header_to_client: Some("rproxy1".to_string()),
                add_via_header_to_server: None,
                force_dir: true,
                client: None,
            },
        )
        .await;

        let mut buf = [0u8; 25];
        let i = s.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf[..i], b"GET /base_path/some/path ");

        s.write_all(b"HTTP/1.0 500 Not so OK\r\n\r\n")
            .await
            .unwrap();
        let r = t.await.unwrap();
        assert_eq!(r.status(), 500);
        assert_eq!(
            r.headers().get(header::VIA),
            Some(&HeaderValue::from_static("HTTP/1.0 rproxy1"))
        );
    }
    #[tokio::test]
    async fn add_headers() {
        let req = Request::get("/mount/")
            .header(header::HOST, "a_host")
            .header(header::FORWARDED, "for=10.10.10.10")
            .version(hyper::Version::HTTP_10)
            .body(TestBody::empty())
            .unwrap();
        let (mut s, t) = test_forward(
            req,
            "",
            Proxy {
                forward: "http://ignored/".to_string().try_into().unwrap(),
                add_forwarded_header: ForwardedHeader::Replace,
                add_x_forwarded_for_header: true,
                add_via_header_to_client: None,
                add_via_header_to_server: Some("rproxy1".to_string()),
                force_dir: true,
                client: None,
            },
        )
        .await;

        let mut buf = [0u8; 16];
        let i = s.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf[..i], b"GET / HTTP/1.0\r\n");
        let mut buf = BytesMut::with_capacity(4096);
        s.read_buf(&mut buf).await.unwrap();

        assert_eq!(get_header(&buf, "via").unwrap(), b"HTTP/1.0 rproxy1");
        assert_eq!(
            get_header(&buf, "forwarded").unwrap(),
            b"for=1.2.3.4; host=a_host"
        );

        //return something else than 200
        s.write_all(b"HTTP/1.0 500 Not so OK\r\n\r\n")
            .await
            .unwrap();
        let r = t.await.unwrap();
        assert_eq!(r.status(), 500);
    }
    #[tokio::test]
    async fn remove_hop_headers() {
        let req = Request::get("/mount/")
            .header(header::CONNECTION, "close")
            .header(header::TRANSFER_ENCODING, "value")
            .header("keep-alive", "value")
            .header(header::TE, "value")
            .header(header::TRAILER, "value")
            .header(header::PROXY_AUTHENTICATE, "value")
            .header(header::PROXY_AUTHORIZATION, "value")
            .body(TestBody::empty())
            .unwrap();
        let (mut s, t) = test_forward(
            req,
            "",
            Proxy {
                forward: "http://ignored/".to_string().try_into().unwrap(),
                add_forwarded_header: ForwardedHeader::Remove,
                add_x_forwarded_for_header: false,
                add_via_header_to_client: None,
                add_via_header_to_server: None,
                force_dir: true,
                client: None,
            },
        )
        .await;

        let mut buf = Vec::with_capacity(4096);
        s.read_buf(&mut buf).await.unwrap();

        let dont_include = [
            "keep-alive",
            "transfer-encoding",
            "te",
            "connection",
            "trailer",
            "proxy-authorization",
            "proxy-authenticate",
        ];
        for kw in dont_include {
            assert_eq!(get_header(&buf, kw), None);
        }

        //return something else than 200
        s.write_all(b"HTTP/1.0 500 Not so OK\r\n\r\n")
            .await
            .unwrap();
        let r = t.await.unwrap();
        assert_eq!(r.status(), 500);
    }
    #[tokio::test]
    async fn web_mount_is_a_folder() {
        let req = Request::get("/mount").body(TestBody::empty()).unwrap();

        let proxy = Proxy {
            forward: "http://localhost:0/".to_string().try_into().unwrap(),
            add_forwarded_header: ForwardedHeader::Remove,
            add_x_forwarded_for_header: false,
            add_via_header_to_client: None,
            add_via_header_to_server: None,
            force_dir: true,
            client: None,
        };

        let t = tokio::spawn(async move {
            let res = crate::dispatch::handle_wwwroot(
                req,
                &crate::config::WwwRoot {
                    mount: crate::config::UseCase::Proxy(proxy),
                    header: None,
                    auth: None,
                },
                WebPath::parsed(""),
                &Utf8PathBuf::from("/mount"),
                "1.2.3.4:42".parse().unwrap(),
            )
            .await;
            res.unwrap()
        });

        let r = t.await.unwrap();
        assert_eq!(r.status(), 301);
        assert_eq!(r.headers().get(header::LOCATION).unwrap(), "/mount/");
    }
    #[tokio::test]
    async fn force_dir_false() {
        let req = Request::get("/mount").body(TestBody::empty()).unwrap();
        let (mut s, t) = test_forward(
            req,
            "",
            Proxy {
                forward: "http://ignored/".to_string().try_into().unwrap(),
                add_forwarded_header: ForwardedHeader::Remove,
                add_x_forwarded_for_header: false,
                add_via_header_to_client: None,
                add_via_header_to_server: None,
                force_dir: false,
                client: None,
            },
        )
        .await;

        let mut buf = Vec::with_capacity(4096);
        s.read_buf(&mut buf).await.unwrap();

        //return something else than 200
        s.write_all(b"HTTP/1.0 201 Not so OK\r\n\r\n")
            .await
            .unwrap();
        let r = t.await.unwrap();
        assert_eq!(r.status(), 201);
    }
    /// ensure that via and forwarded entries are in the correct order
    #[tokio::test]
    async fn header_chaining() {
        let req = Request::get("/mount/")
            .header(header::VIA, "HTTP/0.9 someone")
            .header(&X_FORWARDED_FOR, "10.10.10.10")
            .header(header::FORWARDED, "for=10.10.10.10")
            .body(TestBody::empty())
            .unwrap();
        let (mut s, t) = test_forward(
            req,
            "",
            Proxy {
                forward: "http://ignored/".to_string().try_into().unwrap(),
                add_forwarded_header: ForwardedHeader::Extend,
                add_x_forwarded_for_header: true,
                add_via_header_to_client: Some("my_front".to_string()),
                add_via_header_to_server: Some("me".to_string()),
                force_dir: true,
                client: None,
            },
        )
        .await;

        let mut buf = Vec::with_capacity(4096);
        s.read_buf(&mut buf).await.unwrap();

        assert_eq!(
            get_header(&buf, "via").unwrap(),
            b"HTTP/0.9 someone, HTTP/1.1 me"
        );
        assert_eq!(
            get_header(&buf, "forwarded").unwrap(),
            b"for=10.10.10.10, for=1.2.3.4"
        );
        assert_eq!(
            get_header(&buf, "x-forwarded-for").unwrap(),
            b"10.10.10.10, 1.2.3.4"
        );

        //return something else than 200
        s.write_all(b"HTTP/1.0 203 Not so OK\r\nvia: HTTP/0.9 another\r\n\r\n")
            .await
            .unwrap();
        let r = t.await.unwrap();
        assert_eq!(
            r.headers().get(header::VIA).unwrap().as_bytes(),
            b"HTTP/0.9 another, HTTP/1.0 my_front"
        );
        assert_eq!(r.status(), 203);
    }

    async fn full_server_test(
    ) -> Result<(tokio::net::TcpStream, tokio::net::TcpListener), Box<dyn std::error::Error>> {
        //We can not use a Request Object for the test,
        //as it has no associated connection
        let (server_listener, a) = crate::tests::local_socket_pair().await?;
        let (target_listener, target_add) = crate::tests::local_socket_pair().await.unwrap();

        let mut proxy = Proxy {
            forward: "http://ignored/".to_string().try_into().unwrap(),
            add_forwarded_header: ForwardedHeader::Remove,
            add_x_forwarded_for_header: false,
            add_via_header_to_client: None,
            add_via_header_to_server: None,
            force_dir: false,
            client: None,
        };
        proxy.forward.authority = target_add.to_string().parse().unwrap();
        proxy.setup().await.unwrap();

        let mut listening_ifs = std::collections::HashMap::new();
        let mut cfg = crate::config::HostCfg::new(server_listener.into_std()?);
        let mut vh = crate::config::VHost::new(a);
        vh.paths.insert(
            Utf8PathBuf::from("a"),
            crate::config::WwwRoot {
                mount: UseCase::Proxy(proxy),
                header: None,
                auth: None,
            },
        );
        cfg.default_host = Some(vh);
        listening_ifs.insert(a, cfg);

        let _s = crate::prepare_hyper_servers(listening_ifs).await?;

        let client = tokio::net::TcpStream::connect(a).await?;

        Ok((client, target_listener))
    }
    ///test upgrade
    #[tokio::test]
    async fn upgrade() {
        let (mut client, target_listener) = full_server_test().await.unwrap();

        let t = tokio::spawn(async move {
            let (mut server, _) = target_listener.accept().await.unwrap();
            let mut buf = Vec::with_capacity(4096);
            server.read_buf(&mut buf).await.unwrap();
            assert_eq!(get_header(&buf, "connection").unwrap(), b"UPGRADE");
            assert_eq!(get_header(&buf, "upgrade").unwrap(), b"something");

            server
                .write_all(b"HTTP/1.1 101 SWITCHING_PROTOCOLS\r\nUpgrade: something\r\nConnection: Upgrade\r\n\r\n")
                .await
                .unwrap();

            buf.clear();
            server.read_buf(&mut buf).await.unwrap();
            assert_eq!(buf, b"\x01\x02\x03\xff");

            server.write_all(b"\xff\xfe\x00").await.unwrap();
        });

        client
            .write_all(b"GET /a HTTP/1.1\r\nUpgrade: something\r\nConnection: Upgrade\r\n\r\n")
            .await
            .unwrap();

        let mut buf = Vec::with_capacity(4096);
        client.read_buf(&mut buf).await.unwrap();
        assert_eq!(&buf[..34], b"HTTP/1.1 101 SWITCHING_PROTOCOLS\r\n");
        assert_eq!(get_header(&buf, "connection").unwrap(), b"UPGRADE");
        assert_eq!(get_header(&buf, "upgrade").unwrap(), b"something");

        client.write_all(b"\x01\x02\x03\xff").await.unwrap();
        buf.clear();
        client.read_buf(&mut buf).await.unwrap();
        assert_eq!(buf, b"\xff\xfe\x00");

        t.await.unwrap();
    }

    /// search a HTTP header value inside of a byte stream.
    fn get_header<'a>(haystack: &'a [u8], param: &'_ str) -> Option<&'a [u8]> {
        if let Some(pos) = haystack.windows(param.len() + 4).position(|window| {
            &window[2..param.len() + 2] == param.as_bytes()
                && &window[..2] == b"\r\n"
                && &window[param.len() + 2..] == b": "
        }) {
            let start = pos + param.len() + 4;
            if let Some(len) = haystack[start..]
                .windows(2)
                .position(|window| window == b"\r\n")
            {
                return Some(&haystack[start..start + len]);
            }
        }
        None
    }
}
