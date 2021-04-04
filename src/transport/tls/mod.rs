#[cfg(feature = "tlsrust")]
mod rustls;

#[cfg(feature = "tlsrust")]
use self::rustls::{UnderlyingTLSStream, UnderlyingAccept};
#[cfg(feature = "tlsrust")]
pub use self::rustls::{TlsUserConfig, TLSConfig, ParsedTLSConfig};

use super::{PlainIncoming, PlainStream};
use core::task::{Context, Poll};
use std::pin::Pin;
use hyper::server::accept::Accept;
use futures_util::{FutureExt, ready};
use tokio_rustls::rustls::Session;
use std::io;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use std::future::Future;

use std::net::SocketAddr;
#[cfg(feature = "tlsrust")]
use rustls_acme::acme::ACME_TLS_ALPN_NAME;

enum State {
    Handshaking(UnderlyingAccept<PlainStream>),
    Streaming(UnderlyingTLSStream<PlainStream>),
}

pub(crate) trait TLSBuilderTrait {
    fn new(c: &TlsUserConfig, sni: Option<&str>) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> where Self: std::marker::Sized;
    fn add(&mut self, c: &TlsUserConfig, sni: Option<&str>) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
    fn get_config(self) -> TLSConfig;
    fn get_accept_feature(config: Arc<TLSConfig>, stream: PlainStream) -> UnderlyingAccept<PlainStream>;
}

// tokio_rustls::server::TlsStream doesn't expose constructor methods,
// so we have to TlsAcceptor::accept and handshake to have access to it
// TlsStream implements AsyncRead/AsyncWrite handshaking tokio_rustls::Accept first
pub(crate) struct TlsStream {
    state: State,
    remote_addr: SocketAddr,
}

impl TlsStream {
    fn new(stream: PlainStream, config: Arc<TLSConfig>) -> TlsStream {
        let remote_addr = stream.remote_addr();
        let accept = ParsedTLSConfig::get_accept_feature(config, stream);
        TlsStream {
            state: State::Handshaking(accept),
            remote_addr,
        }
    }
    #[inline]
    pub fn remote_addr(&self) -> SocketAddr {
        self.remote_addr
    }
}

impl AsyncRead for TlsStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let pin = self.get_mut();
        match pin.state {
            State::Handshaking(ref mut accept) => match ready!(Pin::new(accept).poll(cx)) {
                Ok(mut stream) => {
                    if stream.get_ref().1.get_alpn_protocol() == Some(ACME_TLS_ALPN_NAME) {
                        log::debug!("completed acme-tls/1 handshake");
                        stream.shutdown().poll_unpin(cx);
                    }

                    let result = Pin::new(&mut stream).poll_read(cx, buf);
                    pin.state = State::Streaming(stream);
                    result
                }
                Err(err) => Poll::Ready(Err(err)),
            },
            State::Streaming(ref mut stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for TlsStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let pin = self.get_mut();
        match pin.state {
            State::Handshaking(ref mut accept) => match ready!(Pin::new(accept).poll(cx)) {
                Ok(mut stream) => {
                    let result = Pin::new(&mut stream).poll_write(cx, buf);
                    pin.state = State::Streaming(stream);
                    result
                }
                Err(err) => Poll::Ready(Err(err)),
            },
            State::Streaming(ref mut stream) => Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.state {
            State::Handshaking(_) => Poll::Ready(Ok(())),
            State::Streaming(ref mut stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.state {
            State::Handshaking(_) => Poll::Ready(Ok(())),
            State::Streaming(ref mut stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

pub(crate) struct TlsAcceptor {
    config: Arc<TLSConfig>,
    incoming: PlainIncoming,
}

impl TlsAcceptor {
    pub(crate) fn new(config: TLSConfig, incoming: PlainIncoming) -> TlsAcceptor {
        TlsAcceptor {
            config: Arc::new(config),
            incoming,
        }
    }
}

impl Accept for TlsAcceptor {
    type Conn = TlsStream;
    type Error = io::Error;

    fn poll_accept(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Self::Conn, Self::Error>>> {
        let pin = self.get_mut();
        match ready!(Pin::new(&mut pin.incoming).poll_accept(cx)) {
            Some(Ok(sock)) => Poll::Ready(Some(Ok(TlsStream::new(sock, pin.config.clone())))),
            Some(Err(e)) => Poll::Ready(Some(Err(e))),
            None => Poll::Ready(None),
        }
    }
}

