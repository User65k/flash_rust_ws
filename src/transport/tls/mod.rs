#[cfg(feature = "tlsrust")]
mod rustls;

#[cfg(feature = "tlsrust")]
use self::rustls::{UnderlyingTLSStream, UnderlyingAccept, UnderlyingConfig, get_config, get_accept_feature};
#[cfg(feature = "tlsrust")]
pub use self::rustls::TlsConfig;

use super::{PlainIncoming, PlainStream};
use core::task::{Context, Poll};
use std::pin::Pin;
use hyper::server::accept::Accept;
use futures_util::ready;
use std::io;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use std::future::Future;

enum State {
    Handshaking(UnderlyingAccept<PlainStream>),
    Streaming(UnderlyingTLSStream<PlainStream>),
}

// tokio_rustls::server::TlsStream doesn't expose constructor methods,
// so we have to TlsAcceptor::accept and handshake to have access to it
// TlsStream implements AsyncRead/AsyncWrite handshaking tokio_rustls::Accept first
pub(crate) struct TlsStream {
    state: State,
    //remote_addr: SocketAddr,
}

impl TlsStream {
    fn new(stream: PlainStream, config: Arc<UnderlyingConfig>) -> TlsStream {
        //let remote_addr = stream.remote_addr();
        let accept = get_accept_feature(config, stream);
        TlsStream {
            state: State::Handshaking(accept),
            //remote_addr,
        }
    }
}

impl AsyncRead for TlsStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let pin = self.get_mut();
        match pin.state {
            State::Handshaking(ref mut accept) => match ready!(Pin::new(accept).poll(cx)) {
                Ok(mut stream) => {
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
    config: Arc<UnderlyingConfig>,
    incoming: PlainIncoming,
}

impl TlsAcceptor {
    pub fn new(listener: PlainIncoming,
                conf: &TlsConfig) -> Result<TlsAcceptor, Box<dyn std::error::Error + Send + Sync>> {
        let cfg = get_config(conf)?;
        Ok(TlsAcceptor::from_inc(cfg, listener))
    }
    pub(crate) fn from_inc(config: UnderlyingConfig, incoming: PlainIncoming) -> TlsAcceptor {
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

