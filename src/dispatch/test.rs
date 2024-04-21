use crate::body::{test::TestBody, FRWSResult};
use std::path::PathBuf;

use super::*;

#[derive(Debug, Default)]
pub struct UnitTestUseCase {
    req_path: Option<&'static str>,
    mount: Option<&'static str>,
    remote_addr: Option<SocketAddr>,
}

impl UnitTestUseCase {
    pub fn create_wwwroot(
        req_path: Option<&'static str>,
        mount: Option<&'static str>,
        remote_addr: Option<SocketAddr>,
    ) -> config::WwwRoot {
        let sf = UnitTestUseCase {
            req_path,
            mount,
            remote_addr,
        };
        config::WwwRoot {
            mount: config::UseCase::UnitTest(sf),
            header: None,
            auth: None,
        }
    }
    pub fn body(
        &self,
        req_path: WebPath<'_>,
        web_mount: &str,
        remote_addr: SocketAddr,
    ) -> FRWSResult {
        if let Some(r) = self.req_path {
            assert_eq!(req_path, r);
        }
        if let Some(m) = self.mount {
            assert_eq!(web_mount, m);
        }
        if let Some(a) = self.remote_addr {
            assert_eq!(remote_addr, a);
        }
        Ok(Response::builder().body(BoxBody::empty()).unwrap())
    }
}

mod mount {
    use super::*;
    #[tokio::test]
    async fn test_mount_params() {
        let req = Request::get("/abc/def/ghi")
            .body(TestBody::empty())
            .unwrap();
        let sa = "127.0.0.1:8080".parse().unwrap();
        let m = UnitTestUseCase::create_wwwroot(Some("def/ghi"), Some("abc"), None);

        let mut cfg = config::VHost::new(sa);
        cfg.paths.insert(Utf8PathBuf::from("abc"), m);
        let res = handle_vhost(req, &cfg, sa).await;
        assert!(res.is_ok());
    }
    #[tokio::test]
    async fn test_barely_mounted() {
        let req = Request::get("/abc").body(TestBody::empty()).unwrap();
        let sa = "127.0.0.1:8080".parse().unwrap();
        let m = UnitTestUseCase::create_wwwroot(Some(""), Some("abc"), None);

        let mut cfg = config::VHost::new(sa);
        cfg.paths.insert(Utf8PathBuf::from("abc"), m);
        let res = handle_vhost(req, &cfg, sa).await;
        assert!(res.is_ok());
    }
    #[tokio::test]
    async fn top_mount() {
        let req = Request::get("/abc").body(TestBody::empty()).unwrap();
        let sa = "127.0.0.1:8080".parse().unwrap();
        let m = UnitTestUseCase::create_wwwroot(Some("abc"), Some(""), None);

        let mut cfg = config::VHost::new(sa);
        cfg.paths.insert(Utf8PathBuf::from(""), m);
        let res = handle_vhost(req, &cfg, sa).await;
        assert!(res.is_ok());
    }
    #[tokio::test]
    async fn no_mounts() {
        let req = Request::new(TestBody::empty());
        let sa = "127.0.0.1:8080".parse().unwrap();

        let cfg = config::VHost::new(sa);
        let res = handle_vhost(req, &cfg, sa).await;
        let res: IoError = res.unwrap_err();
        assert_eq!(res.into_inner().unwrap().to_string(), "not a mount path");
    }
    #[tokio::test]
    async fn full_folder_names_as_mounts() {
        let req = Request::get("/aa").body(TestBody::empty()).unwrap();
        let sa = "127.0.0.1:8080".parse().unwrap();

        let mut cfg = config::VHost::new(sa);
        cfg.paths.insert(
            Utf8PathBuf::from(""),
            UnitTestUseCase::create_wwwroot(None, Some("#wrong"), None),
        );
        cfg.paths.insert(
            Utf8PathBuf::from("aa"),
            UnitTestUseCase::create_wwwroot(None, Some("aa"), None),
        );
        cfg.paths.insert(
            Utf8PathBuf::from("aaa"),
            UnitTestUseCase::create_wwwroot(None, Some("#wrong"), None),
        );
        let res = handle_vhost(req, &cfg, sa).await;
        assert!(res.is_ok());
    }
    #[tokio::test]
    async fn longest_mount() {
        let req = Request::get("/aa/a").body(TestBody::empty()).unwrap();
        let sa = "127.0.0.1:8080".parse().unwrap();

        let mut cfg = config::VHost::new(sa);
        cfg.paths.insert(
            Utf8PathBuf::from("aa"),
            UnitTestUseCase::create_wwwroot(None, Some("#wrong"), None),
        );
        cfg.paths.insert(
            Utf8PathBuf::from("aa/a"),
            UnitTestUseCase::create_wwwroot(None, Some("aa/a"), None),
        );
        let res = handle_vhost(req, &cfg, sa).await;
        assert!(res.is_ok());
    }
    #[tokio::test]
    async fn uri_encode() {
        let req = Request::get("/aa%2Fa").body(TestBody::empty()).unwrap();
        let sa = "127.0.0.1:8080".parse().unwrap();

        let mut cfg = config::VHost::new(sa);
        cfg.paths.insert(
            Utf8PathBuf::from("aa"),
            UnitTestUseCase::create_wwwroot(None, Some("#wrong"), None),
        );
        cfg.paths.insert(
            Utf8PathBuf::from("aa/a"),
            UnitTestUseCase::create_wwwroot(Some(""), Some("aa/a"), None),
        );
        let res = handle_vhost(req, &cfg, sa).await;
        assert!(res.is_ok());
    }
    #[tokio::test]
    async fn path_trav_outside_mounts() {
        let req = Request::get("/a/../b").body(TestBody::empty()).unwrap();
        let sa = "127.0.0.1:8080".parse().unwrap();

        let mut cfg = config::VHost::new(sa);
        cfg.paths.insert(
            Utf8PathBuf::from("a"),
            UnitTestUseCase::create_wwwroot(None, None, None),
        );
        let res = handle_vhost(req, &cfg, sa).await;
        let res = res.unwrap_err();
        assert_eq!(res.kind(), ErrorKind::PermissionDenied);
        assert_eq!(res.into_inner().unwrap().to_string(), "not a mount path");
    }
    #[tokio::test]
    async fn path_trav_outside_webroot() {
        let req = Request::get("/../b").body(TestBody::empty()).unwrap();
        let sa = "127.0.0.1:8080".parse().unwrap();

        let mut cfg = config::VHost::new(sa);
        cfg.paths.insert(
            Utf8PathBuf::from("b"),
            UnitTestUseCase::create_wwwroot(None, None, None),
        );
        let res = handle_vhost(req, &cfg, sa).await;
        let res = res.unwrap_err();
        assert_eq!(res.kind(), ErrorKind::PermissionDenied);
        assert_eq!(res.into_inner().unwrap().to_string(), "path traversal");
    }
    #[tokio::test]
    async fn rustsec_2022_0072_part1() {
        let req = Request::get("/c:/b").body(TestBody::empty()).unwrap();
        let sa = "127.0.0.1:8080".parse().unwrap();

        let mut cfg = config::VHost::new(sa);
        cfg.paths.insert(
            Utf8PathBuf::from(""),
            UnitTestUseCase::create_wwwroot(Some("c:/b"), None, None),
        );
        let res = handle_vhost(req, &cfg, sa).await;
        assert!(res.is_ok());
        //Note: ":" is not a valid dir char in windows
        //      However, an FCGI App might do things with it
    }
    #[tokio::test]
    async fn rustsec_2022_0072_part2() {
        let req = Request::get("/a/c:/b/d").body(TestBody::empty()).unwrap();
        let sa = "127.0.0.1:8080".parse().unwrap();

        let mut cfg = config::VHost::new(sa);
        cfg.paths.insert(
            Utf8PathBuf::from("a/c:/b"),
            UnitTestUseCase::create_wwwroot(Some("d"), Some("a/c:/b"), None),
        );
        let res = handle_vhost(req, &cfg, sa).await;
        assert!(res.is_ok());
    }
    #[tokio::test]
    async fn webroot() {
        let req = Request::get("/").body(TestBody::empty()).unwrap();
        let sa = "127.0.0.1:8080".parse().unwrap();

        let mut cfg = config::VHost::new(sa);
        cfg.paths.insert(
            Utf8PathBuf::from(""),
            UnitTestUseCase::create_wwwroot(Some(""), Some(""), None),
        );
        let res = handle_vhost(req, &cfg, sa).await;
        assert!(res.is_ok());
    }
    #[tokio::test]
    async fn redirect_w_status() {
        let req = Request::get("/").body(TestBody::empty()).unwrap();
        let sa = "127.0.0.1:8080".parse().unwrap();

        let mut cfg = config::VHost::new(sa);
        cfg.paths.insert(
            Utf8PathBuf::from(""),
            config::WwwRoot {
                mount: toml::from_str(
                    r#"
                    redirect = "http://some/where/"
                    code = 302
                "#,
                )
                .unwrap(),
                header: None,
                auth: None,
            },
        );
        let res = handle_vhost(req, &cfg, sa).await.unwrap();
        assert_eq!(res.status(), 302);
        assert_eq!(
            res.headers().get(header::LOCATION).unwrap(),
            "http://some/where/"
        );
    }
    #[tokio::test]
    async fn redirect() {
        let req = Request::get("/").body(TestBody::empty()).unwrap();
        let sa = "127.0.0.1:8080".parse().unwrap();

        let mut cfg = config::VHost::new(sa);
        cfg.paths.insert(
            Utf8PathBuf::from(""),
            config::WwwRoot {
                mount: toml::from_str(
                    r#"
                    redirect = "https://some:1234/"
                "#,
                )
                .unwrap(),
                header: None,
                auth: None,
            },
        );
        let res = handle_vhost(req, &cfg, sa).await.unwrap();
        assert_eq!(res.status(), 301);
        assert_eq!(
            res.headers().get(header::LOCATION).unwrap(),
            "https://some:1234/"
        );
    }
    #[tokio::test]
    async fn redirect_w_path() {
        let req = Request::get("/path").body(TestBody::empty()).unwrap();
        let sa = "127.0.0.1:8080".parse().unwrap();

        let mut cfg = config::VHost::new(sa);
        cfg.paths.insert(
            Utf8PathBuf::from(""),
            config::WwwRoot {
                mount: toml::from_str(
                    r#"
                    redirect = "https://some:1234/"
                    add_req_path = true
                "#,
                )
                .unwrap(),
                header: None,
                auth: None,
            },
        );
        let res = handle_vhost(req, &cfg, sa).await.unwrap();
        assert_eq!(res.status(), 301);
        assert_eq!(
            res.headers().get(header::LOCATION).unwrap(),
            "https://some:1234/path"
        );

        let req = Request::get("/path").body(TestBody::empty()).unwrap();
        let sa = "127.0.0.1:8080".parse().unwrap();

        let mut cfg = config::VHost::new(sa);
        cfg.paths.insert(
            Utf8PathBuf::from(""),
            config::WwwRoot {
                mount: toml::from_str(
                    r#"
                    redirect = "/folder"
                    add_req_path = true
                "#,
                )
                .unwrap(),
                header: None,
                auth: None,
            },
        );
        let res = handle_vhost(req, &cfg, sa).await.unwrap();
        assert_eq!(res.status(), 301);
        assert_eq!(res.headers().get(header::LOCATION).unwrap(), "/folder/path");
    }
}

mod vhost {
    use super::*;
    fn make_host_cfg(
        default_host: Option<config::VHost>,
        named: Option<(String, config::VHost)>,
    ) -> Arc<config::HostCfg> {
        let mut map: HashMap<String, config::VHost> = HashMap::new();
        if let Some((k, v)) = named {
            map.insert(k, v);
        }
        Arc::new(config::HostCfg {
            default_host,
            vhosts: map,
            listener: None,
            #[cfg(any(feature = "tlsrust", feature = "tlsnative"))]
            tls: None,
        })
    }
    #[tokio::test]
    async fn unknown_vhost() {
        let req = Request::new(TestBody::empty());
        let sa = "127.0.0.1:8080".parse().unwrap();

        let cfg = make_host_cfg(None, Some(("1".to_string(), config::VHost::new(sa))));
        let res = dispatch_to_vhost(req, cfg, sa).await;
        let res: IoError = res.unwrap_err();
        assert_eq!(res.into_inner().unwrap().to_string(), "no vHost found");
    }
    #[tokio::test]
    async fn specific_vhost() {
        let mut req = Request::new(TestBody::empty());
        req.headers_mut()
            .insert("Host", header::HeaderValue::from_static("1:8080"));

        let sa = "127.0.0.1:8080".parse().unwrap();

        let cfg = make_host_cfg(None, Some(("1".to_string(), config::VHost::new(sa))));

        let res = dispatch_to_vhost(req, cfg, sa).await;
        let res: IoError = res.unwrap_err();
        assert_eq!(res.into_inner().unwrap().to_string(), "not a mount path");
    }
    #[tokio::test]
    async fn default_vhost() {
        let req = Request::new(TestBody::empty());
        let sa = "127.0.0.1:8080".parse().unwrap();

        let cfg = make_host_cfg(Some(config::VHost::new(sa)), None);

        let res = dispatch_to_vhost(req, cfg, sa).await;
        let res: IoError = res.unwrap_err();
        assert_eq!(res.into_inner().unwrap().to_string(), "not a mount path");
    }
}

pub struct TempFile(PathBuf);
impl TempFile {
    pub fn create(file_name: &str, content: &[u8]) -> TempFile {
        let mut path = std::env::temp_dir();
        path.push(file_name);
        let mut file = std::fs::File::create(&path).expect("could not create file");
        std::io::Write::write_all(&mut file, content).expect("could not write file");
        TempFile(path)
    }
    pub fn get_path(&self) -> &Path {
        &self.0
    }
}
impl Drop for TempFile {
    fn drop(&mut self) {
        std::fs::remove_file(&self.0).unwrap();
    }
}
pub struct TempDir(PathBuf);
impl TempDir {
    pub fn create(name: &str) -> TempDir {
        let d = std::env::temp_dir().join(name);
        std::fs::create_dir(&d).expect("could not create dir");
        TempDir(d)
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}
