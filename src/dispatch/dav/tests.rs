use std::{env::temp_dir, net::SocketAddr};

use hyper::{body::to_bytes, Body, Request};

use super::{do_dav, Config};
use crate::{
    config::{AbsPathBuf, UseCase, Utf8PathBuf},
    dispatch::{test::TempFile, WebPath},
};
#[test]
fn basic_config() {
    if let Ok(UseCase::Webdav(w)) = toml::from_str(
        r#"
dav = "."
    "#,
    ) {
        assert!(!w.read_only);
        assert!(!w.dont_overwrite);
    } else {
        panic!("not a webdav");
    }
}
#[test]
fn dir_nonexistent() {
    let cfg: Result<crate::config::Configuration, _> = toml::from_str(
        r#"
[host]
ip = "0.0.0.0:1337"
dav = "blablahui"
"#,
    );
    assert!(cfg.is_err());
}
async fn handle_req(
    req: hyper::http::request::Builder,
    body: Body,
    req_path: WebPath<'_>,
    config: &Config,
) -> std::io::Result<hyper::Response<Body>> {
    let req = req.body(body).unwrap();

    let addr: SocketAddr = "1.2.3.4:1234".parse().unwrap();

    do_dav(req, &req_path, config, &Utf8PathBuf::from("mount"), addr).await
}

#[tokio::test]
async fn get_file() {
    let file_content = &b"test_resolve_file_dav"[..];
    let _tf = TempFile::create("test_resolve_file_dav", file_content);

    let config = Config {
        dav: AbsPathBuf::temp_dir(),
        read_only: false,
        dont_overwrite: false,
    };
    let res = handle_req(
        Request::get("/mount/test_resolve_file_dav"),
        Body::empty(),
        WebPath::parsed("test_resolve_file_dav"),
        &config,
    )
    .await
    .unwrap();
    assert_eq!(res.status(), 200);
    let body = to_bytes(res.into_body()).await.unwrap();
    assert_eq!(body, file_content);
}

#[tokio::test]
async fn options() {
    let config = Config {
        dav: AbsPathBuf::temp_dir(),
        read_only: false,
        dont_overwrite: false,
    };
    let res = handle_req(
        Request::options("/mount/"),
        Body::empty(),
        WebPath::parsed(""),
        &config,
    )
    .await
    .unwrap();

    assert_eq!(res.status(), 200);
    assert_eq!(
        res.headers().get("DAV").map(|h| h.as_bytes()),
        Some(&b"1"[..])
    );
    assert_eq!(
        res.headers()
            .get(hyper::header::ALLOW)
            .map(|h| h.as_bytes()),
        Some(&b"GET,PUT,OPTIONS,DELETE,PROPFIND,COPY,MOVE,MKCOL"[..])
    );
}

#[tokio::test]
async fn put_move_delete() {
    let config = Config {
        dav: AbsPathBuf::temp_dir(),
        read_only: false,
        dont_overwrite: false,
    };

    // ---PUT---
    let res = handle_req(
        Request::put("/mount/test_create_file"),
        Body::from("test123"),
        WebPath::parsed("test_create_file"),
        &config,
    )
    .await
    .unwrap();
    assert_eq!(res.status(), 200);
    assert_eq!(
        std::fs::read_to_string(temp_dir().join("test_create_file")).unwrap(),
        "test123"
    );

    // ---MOVE---
    let res = handle_req(
        Request::builder()
            .method("MOVE")
            .uri("/mount/test_create_file")
            .header("Destination", "/mount/test_moved_file"),
        Body::empty(),
        WebPath::parsed("test_create_file"),
        &config,
    )
    .await
    .unwrap();
    assert_eq!(res.status(), 201);
    assert_eq!(
        std::fs::read_to_string(temp_dir().join("test_moved_file")).unwrap(),
        "test123"
    );
    assert!(!temp_dir().join("test_create_file").exists());

    // ---DELETE (File)---
    let res = handle_req(
        Request::delete("/mount/test_moved_file"),
        Body::empty(),
        WebPath::parsed("test_moved_file"),
        &config,
    )
    .await
    .unwrap();

    assert_eq!(res.status(), 200);
    assert!(!temp_dir().join("test_moved_file").exists());
}

#[tokio::test]
async fn mkcol_propfind() {
    let config = Config {
        dav: AbsPathBuf::temp_dir(),
        read_only: false,
        dont_overwrite: false,
    };
    // ---MKCOL fail---
    let res = handle_req(
        Request::builder()
            .method("MKCOL")
            .uri("/mount/no_exist_dir/dir"),
        Body::empty(),
        WebPath::parsed("no_exist_dir/dir"),
        &config,
    )
    .await
    .unwrap();
    assert_eq!(res.status(), 409);

    // ---MKCOL---
    let res = handle_req(
        Request::builder()
            .method("MKCOL")
            .uri("/mount/test_create_dir"),
        Body::empty(),
        WebPath::parsed("test_create_dir"),
        &config,
    )
    .await
    .unwrap();
    assert_eq!(res.status(), 201);

    // ---PROPFIND Dep0---
    std::fs::write(temp_dir().join("test_create_dir/file.txt"), b"Lorem ipsum").unwrap();

    let res = handle_req(
        Request::builder()
            .method("PROPFIND")
            .uri("/mount/test_create_dir/")
            .header("Depth", "0"),
        Body::from(
            r##"<?xml version="1.0"?>
<a:propfind xmlns:a="DAV:">
<a:prop><a:getcontenttype/></a:prop>
<a:prop><a:getcontentlength/></a:prop>
</a:propfind>"##,
        ),
        WebPath::parsed("test_create_dir/"),
        &config,
    )
    .await
    .unwrap();
    assert_eq!(res.status(), 207);
    let body = to_bytes(res.into_body()).await.unwrap();
    assert_eq!(
        body,
        &br##"<?xml version="1.0" encoding="utf-8"?>
<D:multistatus xmlns:D="DAV:">
  <D:response>
    <D:href>/mount/test_create_dir</D:href>
    <D:propstat>
      <D:prop>
        <D:getcontenttype>httpd/unix-directory</D:getcontenttype>
      </D:prop>
      <D:status>HTTP/1.1 200 OK</D:status>
    </D:propstat>
  </D:response>
</D:multistatus>"##[..]
    );

    // ---PROPFIND Dep 10---
    let res = handle_req(
        Request::builder()
            .method("PROPFIND")
            .uri("/mount/test_create_dir/"),
        Body::from(
            r##"<?xml version="1.0"?>
<a:propfind xmlns:a="DAV:">
<a:prop><a:getcontenttype/></a:prop>
<a:prop><a:getcontentlength/></a:prop>
</a:propfind>"##,
        ),
        WebPath::parsed("test_create_dir/"),
        &config,
    )
    .await
    .unwrap();
    assert_eq!(res.status(), 207);
    let body = to_bytes(res.into_body()).await.unwrap();
    assert_eq!(
        body,
        &br##"<?xml version="1.0" encoding="utf-8"?>
<D:multistatus xmlns:D="DAV:">
  <D:response>
    <D:href>/mount/test_create_dir</D:href>
    <D:propstat>
      <D:prop>
        <D:getcontenttype>httpd/unix-directory</D:getcontenttype>
      </D:prop>
      <D:status>HTTP/1.1 200 OK</D:status>
    </D:propstat>
  </D:response>
  <D:response>
    <D:href>/mount/test_create_dir/file.txt</D:href>
    <D:propstat>
      <D:prop>
        <D:getcontenttype>text/plain</D:getcontenttype>
      </D:prop>
      <D:status>HTTP/1.1 200 OK</D:status>
    </D:propstat>
  </D:response>
</D:multistatus>"##[..]
    );

    // ---DELETE (Dir)---
    let res = handle_req(
        Request::delete("/mount/test_create_dir"),
        Body::empty(),
        WebPath::parsed("test_create_dir"),
        &config,
    )
    .await
    .unwrap();

    assert_eq!(res.status(), 200);
    assert!(!temp_dir().join("test_create_dir").exists());
}
//TODO
//Request::builder().method("MOVE").uri(uri).header("Overwrite", "F")
//Request::builder().method("MOVE").uri(uri).header("Overwrite", "T")
//Request::builder().method("COPY").uri(uri)
//Request::builder().method("COPY").uri(uri).header("Overwrite", "F")
//Request::builder().method("PROPPATCH").uri(uri)
