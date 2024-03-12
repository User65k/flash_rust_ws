use hyper::{rt::{Read as _, ReadBuf, Write as _}, upgrade::Upgraded};
use pin_project_lite::pin_project;

pin_project! {
    pub struct MyUpgraded{
        #[pin]
        u: Upgraded
    }
}
impl MyUpgraded {
    pub fn new(u: Upgraded) -> Self {
        Self {
            u
        }
    }
}

impl tokio::io::AsyncRead for MyUpgraded {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        //let b = unsafe { buf.inner_mut() };
        //let mut buf = ReadBuf::uninit(b);

        //Its totally the same type
        let buf: &mut ReadBuf = unsafe { std::mem::transmute(buf) };

        self.project().u.poll_read(cx, buf.unfilled())
    }
}
impl tokio::io::AsyncWrite for MyUpgraded {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        self.project().u.poll_write(cx, buf)
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        self.project().u.poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        self.project().u.poll_shutdown(cx)
    }
}
