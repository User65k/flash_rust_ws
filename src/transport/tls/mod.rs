#[cfg(feature = "tlsrust")]
mod rustls;

#[cfg(feature = "tlsrust")]
pub use self::rustls::{ParsedTLSConfig, TlsUserConfig};
#[cfg(feature = "tlsrust")]
use self::rustls::{TLSConfig, UnderlyingAccept, UnderlyingTLSStream};

use super::{Connection, PlainIncoming, PlainStream};
use core::task::{Context, Poll};
use futures_util::ready;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use std::net::SocketAddr;

#[cfg(feature = "tlsrust_acme")]
use async_acme::acme::ACME_TLS_ALPN_NAME;

#[cfg(all(feature = "tlsrust", feature = "tlsnative"))]
compile_error!("feature \"tlsrust\" and feature \"tlsnative\" cannot be enabled at the same time");

enum State {
    Handshaking(UnderlyingAccept<PlainStream>),
    Streaming(UnderlyingTLSStream<PlainStream>),
}

pub(crate) trait TLSBuilderTrait {
    /// called by first vHost that wants TLS
    fn new(
        c: &TlsUserConfig,
        sni: Option<&str>,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>>
    where
        Self: std::marker::Sized;
    /// called by all but the first vHost on one socket
    fn add(
        &mut self,
        c: &TlsUserConfig,
        sni: Option<&str>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
    fn get_accept_feature(
        accept: &TlsAcceptor,
        stream: PlainStream,
    ) -> UnderlyingAccept<PlainStream>;
    fn get_acceptor(self, incoming: PlainIncoming) -> TlsAcceptor;
}

// tokio_rustls::server::TlsStream doesn't expose constructor methods,
// so we have to TlsAcceptor::accept and handshake to have access to it
// TlsStream implements AsyncRead/AsyncWrite handshaking tokio_rustls::Accept first
pub(crate) struct TlsStream {
    state: State,
    remote_addr: SocketAddr,
}

impl TlsStream {
    fn new(stream: PlainStream, accept: &TlsAcceptor) -> TlsStream {
        let remote_addr = stream.remote_addr();
        let accept = ParsedTLSConfig::get_accept_feature(accept, stream);
        TlsStream {
            state: State::Handshaking(accept),
            remote_addr,
        }
    }
}
impl Connection for TlsStream {
    #[inline]
    fn remote_addr(&self) -> SocketAddr {
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
                    #[cfg(feature = "tlsrust_acme")]
                    if stream.get_ref().1.alpn_protocol() == Some(ACME_TLS_ALPN_NAME) {
                        log::debug!("completed acme-tls/1 handshake");
                        return Pin::new(&mut stream).poll_shutdown(cx);
                        //EOF
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
    pub(crate) async fn accept(&self) -> io::Result<TlsStream> {
        let stream = self.incoming.accept().await?;
        Ok(TlsStream::new(stream, &self))
    }
}
