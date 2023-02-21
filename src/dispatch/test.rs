use super::*;

#[derive(Debug, Default)]
pub struct UnitTestUseCase {
    req_path: Option<&'static str>,
    mount: Option<&'static Path>,
    remote_addr: Option<SocketAddr>,
}

impl UnitTestUseCase {
    fn create_wwwroot(
        req_path: Option<&'static str>,
        mount: Option<&'static Path>,
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
        web_mount: &Path,
        remote_addr: SocketAddr,
    ) -> Result<Response<Body>, IoError> {
        if let Some(r) = self.req_path {
            assert_eq!(req_path.0, r);
        }
        if let Some(m) = self.mount {
            assert_eq!(web_mount, m);
        }
        if let Some(a) = self.remote_addr {
            assert_eq!(remote_addr, a);
        }
        Ok(Response::builder().body(Body::default()).unwrap())
    }
}

mod mount {
    use super::*;
    fn create_wwwroot(dir: &str) -> config::WwwRoot {
        let sf = config::StaticFiles {
            dir: PathBuf::from(dir),
            follow_symlinks: false,
            index: None,
            serve: None,
        };
        config::WwwRoot {
            mount: config::UseCase::StaticFiles(sf),
            header: None,
            auth: None,
        }
    }
    #[tokio::test]
    async fn test_mount_params() {
        let req = Request::get("/abc/def/ghi").body(Body::empty()).unwrap();
        let sa = "127.0.0.1:8080".parse().unwrap();
        let m = UnitTestUseCase::create_wwwroot(Some("def/ghi"), Some(Path::new("abc")), None);

        let mut cfg = config::VHost::new(sa);
        cfg.paths.insert(PathBuf::from("abc"), m);
        let res = handle_vhost(req, &cfg, sa).await;
        assert!(res.is_ok());
    }
    #[tokio::test]
    async fn test_barely_mounted() {
        let req = Request::get("/abc").body(Body::empty()).unwrap();
        let sa = "127.0.0.1:8080".parse().unwrap();
        let m = UnitTestUseCase::create_wwwroot(Some(""), Some(Path::new("abc")), None);

        let mut cfg = config::VHost::new(sa);
        cfg.paths.insert(PathBuf::from("abc"), m);
        let res = handle_vhost(req, &cfg, sa).await;
        assert!(res.is_ok());
    }
    #[tokio::test]
    async fn top_mount() {
        let req = Request::get("/abc").body(Body::empty()).unwrap();
        let sa = "127.0.0.1:8080".parse().unwrap();
        let m = UnitTestUseCase::create_wwwroot(Some("abc"), Some(Path::new("")), None);

        let mut cfg = config::VHost::new(sa);
        cfg.paths.insert(PathBuf::from(""), m);
        let res = handle_vhost(req, &cfg, sa).await;
        assert!(res.is_ok());
    }
    #[tokio::test]
    async fn no_mounts() {
        let req = Request::new(Body::empty());
        let sa = "127.0.0.1:8080".parse().unwrap();

        let cfg = config::VHost::new(sa);
        let res = handle_vhost(req, &cfg, sa).await;
        let res: IoError = res.unwrap_err();
        assert_eq!(res.into_inner().unwrap().to_string(), "not a mount path");
    }
    #[tokio::test]
    async fn full_folder_names_as_mounts() {
        let req = Request::get("/aa").body(Body::empty()).unwrap();
        let sa = "127.0.0.1:8080".parse().unwrap();

        let mut cfg = config::VHost::new(sa);
        cfg.paths.insert(PathBuf::from(""), create_wwwroot("."));
        cfg.paths.insert(PathBuf::from("aa"), create_wwwroot("."));
        cfg.paths.insert(PathBuf::from("aaa"), create_wwwroot("."));
        let res = handle_vhost(req, &cfg, sa).await;
        let res = res.unwrap();
        assert_eq!(res.status(), 301);
        assert_eq!(res.headers().get("location").unwrap(), "/aa/");
    }
    #[tokio::test]
    async fn longest_mount() {
        let req = Request::get("/aa/a").body(Body::empty()).unwrap();
        let sa = "127.0.0.1:8080".parse().unwrap();

        let mut cfg = config::VHost::new(sa);
        cfg.paths.insert(PathBuf::from("aa"), create_wwwroot("."));
        cfg.paths.insert(PathBuf::from("aa/a"), create_wwwroot("."));
        let res = handle_vhost(req, &cfg, sa).await;
        let res = res.unwrap();
        assert_eq!(res.status(), 301);
        assert_eq!(res.headers().get("location").unwrap(), "/aa/a/");
    }
    #[tokio::test]
    async fn uri_encode() {
        let req = Request::get("/aa%2Fa").body(Body::empty()).unwrap();
        let sa = "127.0.0.1:8080".parse().unwrap();

        let mut cfg = config::VHost::new(sa);
        cfg.paths.insert(PathBuf::from("aa"), create_wwwroot("."));
        cfg.paths.insert(PathBuf::from("aa/a"), create_wwwroot("."));
        let res = handle_vhost(req, &cfg, sa).await;
        let res = res.unwrap();
        assert_eq!(res.status(), 301);
        assert_eq!(res.headers().get("location").unwrap(), "/aa/a/");
    }
    #[tokio::test]
    async fn path_trav_outside_mounts() {
        let req = Request::get("/a/../b").body(Body::empty()).unwrap();
        let sa = "127.0.0.1:8080".parse().unwrap();

        let mut cfg = config::VHost::new(sa);
        cfg.paths.insert(
            PathBuf::from("a"),
            UnitTestUseCase::create_wwwroot(None, None, None),
        );
        let res = handle_vhost(req, &cfg, sa).await;
        let res = res.unwrap_err();
        assert_eq!(res.kind(), ErrorKind::PermissionDenied);
        assert_eq!(res.into_inner().unwrap().to_string(), "not a mount path");
    }
    #[tokio::test]
    async fn path_trav_outside_webroot() {
        let req = Request::get("/../b").body(Body::empty()).unwrap();
        let sa = "127.0.0.1:8080".parse().unwrap();

        let mut cfg = config::VHost::new(sa);
        cfg.paths.insert(
            PathBuf::from("b"),
            UnitTestUseCase::create_wwwroot(None, None, None),
        );
        let res = handle_vhost(req, &cfg, sa).await;
        let res = res.unwrap_err();
        assert_eq!(res.kind(), ErrorKind::PermissionDenied);
        assert_eq!(res.into_inner().unwrap().to_string(), "path traversal");
    }
    #[cfg(windows)]
    #[tokio::test]
    async fn rustsec_2022_0072_part1() {
        let req = Request::get("/c:/b").body(Body::empty()).unwrap();

        //test mapping it to a file on disk
        assert_eq!(
            decode_and_normalize_path(req.uri())
                .unwrap()
                .prefix_with(Path::new("test")),
            Path::new("test/c:/b")
        );

        //test mount logic
        let sa = "127.0.0.1:8080".parse().unwrap();

        let mut cfg = config::VHost::new(sa);
        cfg.paths.insert(
            PathBuf::from(""),
            UnitTestUseCase::create_wwwroot(Some("c:/b"), None, None),
        );
        let res = handle_vhost(req, &cfg, sa).await;
        assert!(res.is_ok());
        //Note: ":" is not a valid dir char in windows
        //      However, an FCGI App might do things with it
    }
    #[cfg(windows)]
    #[tokio::test]
    async fn rustsec_2022_0072_part2() {
        let req = Request::get("/a/c:/b/d").body(Body::empty()).unwrap();

        //test mapping it to a file on disk
        assert_eq!(
            decode_and_normalize_path(req.uri())
                .unwrap()
                .prefix_with(Path::new("test")),
            Path::new("test/a/c:/b/d")
        );

        //test mount logic
        let sa = "127.0.0.1:8080".parse().unwrap();

        let mut cfg = config::VHost::new(sa);
        cfg.paths.insert(
            PathBuf::from("a/c:/b"),
            UnitTestUseCase::create_wwwroot(Some("d"), Some(Path::new("a/c:/b")), None),
        );
        let res = handle_vhost(req, &cfg, sa).await;
        assert!(res.is_ok());
    }
    #[tokio::test]
    async fn webroot() {
        let req = Request::get("/").body(Body::empty()).unwrap();
        let sa = "127.0.0.1:8080".parse().unwrap();

        let mut cfg = config::VHost::new(sa);
        cfg.paths.insert(
            PathBuf::from(""),
            UnitTestUseCase::create_wwwroot(Some(""), Some(Path::new("")), None),
        );
        let res = handle_vhost(req, &cfg, sa).await;
        assert!(res.is_ok());
    }
    #[test]
    fn normalize() {
        assert_eq!(
            decode_and_normalize_path(&"/a/../b".parse().unwrap())
                .unwrap()
                .0,
            "b"
        );
        assert_eq!(
            decode_and_normalize_path(&"/../../".parse().unwrap())
                .unwrap_err()
                .kind(),
            ErrorKind::PermissionDenied
        );
        assert_eq!(
            decode_and_normalize_path(&"/a/c:/b".parse().unwrap())
                .unwrap()
                .0,
            "a/c:/b"
        );
        assert_eq!(
            decode_and_normalize_path(&"/c:/b".parse().unwrap())
                .unwrap()
                .0,
            "c:/b"
        );
        assert_eq!(
            decode_and_normalize_path(&"/a/b/c".parse().unwrap())
                .unwrap()
                .strip_prefix(Path::new("a"))
                .unwrap()
                .0,
            "b/c"
        );
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
        let req = Request::new(Body::empty());
        let sa = "127.0.0.1:8080".parse().unwrap();

        let cfg = make_host_cfg(None, Some(("1".to_string(), config::VHost::new(sa))));
        let res = dispatch_to_vhost(req, cfg, sa).await;
        let res: IoError = res.unwrap_err();
        assert_eq!(res.into_inner().unwrap().to_string(), "no vHost found");
    }
    #[tokio::test]
    async fn specific_vhost() {
        let mut req = Request::new(Body::empty());
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
        let req = Request::new(Body::empty());
        let sa = "127.0.0.1:8080".parse().unwrap();

        let cfg = make_host_cfg(Some(config::VHost::new(sa)), None);

        let res = dispatch_to_vhost(req, cfg, sa).await;
        let res: IoError = res.unwrap_err();
        assert_eq!(res.into_inner().unwrap().to_string(), "not a mount path");
    }
}