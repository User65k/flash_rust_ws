/*
Taken from Hyper

Copyright (c) 2014-2018 Sean McArthur

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

use std::fmt;
use std::io;
use std::net::{SocketAddr, TcpListener as StdTcpListener};
use std::time::Duration;

use futures_util::FutureExt as _;
use tokio::net::TcpListener;
use tokio::time::Delay;

use std::future::Future;
use core::task::{Context, Poll};
use std::pin::Pin;

//use hyper::server::conn::AddrStream;
//pub use tokio::net::TcpStream as PlainStream;
use hyper::server::accept::Accept;
use log::{info, error, debug, trace};
use futures_util::ready;

use bytes::{Buf, BufMut};
#[cfg(unix)]
use std::os::unix::io::{AsRawFd, RawFd};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

#[cfg(any(feature = "tlsrust",feature = "tlsnative"))]
pub mod tls;

/// A stream of connections from binding to an address.
#[must_use = "streams do nothing unless polled"]
pub struct PlainIncoming {
    addr: SocketAddr,
    listener: TcpListener,
    sleep_on_errors: bool,
    tcp_keepalive_timeout: Option<Duration>,
    tcp_nodelay: bool,
    timeout: Option<Delay>,
}

impl PlainIncoming {
    pub(super) fn from_std(std_listener: StdTcpListener) -> Result<Self, io::Error> {
        let listener = TcpListener::from_std(std_listener)?;
        let addr = listener.local_addr()?;
        Ok(PlainIncoming {
            listener,
            addr,
            sleep_on_errors: true,
            tcp_keepalive_timeout: None,
            tcp_nodelay: false,
            timeout: None,
        })
    }

    /// Get the local address bound to this listener.
    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    /// Set whether TCP keepalive messages are enabled on accepted connections.
    ///
    /// If `None` is specified, keepalive is disabled, otherwise the duration
    /// specified will be the time to remain idle before sending TCP keepalive
    /// probes.
    pub fn set_keepalive(&mut self, keepalive: Option<Duration>) -> &mut Self {
        self.tcp_keepalive_timeout = keepalive;
        self
    }

    /// Set the value of `TCP_NODELAY` option for accepted connections.
    pub fn set_nodelay(&mut self, enabled: bool) -> &mut Self {
        self.tcp_nodelay = enabled;
        self
    }

    /// Set whether to sleep on accept errors.
    ///
    /// A possible scenario is that the process has hit the max open files
    /// allowed, and so trying to accept a new connection will fail with
    /// `EMFILE`. In some cases, it's preferable to just wait for some time, if
    /// the application will likely close some files (or connections), and try
    /// to accept the connection again. If this option is `true`, the error
    /// will be logged at the `error` level, since it is still a big deal,
    /// and then the listener will sleep for 1 second.
    ///
    /// In other cases, hitting the max open files should be treat similarly
    /// to being out-of-memory, and simply error (and shutdown). Setting
    /// this option to `false` will allow that.
    ///
    /// Default is `true`.
    pub fn set_sleep_on_errors(&mut self, val: bool) {
        self.sleep_on_errors = val;
    }

    fn poll_next_(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<PlainStream>> {
        // Check if a previous timeout is active that was set by IO errors.
        if let Some(ref mut to) = self.timeout {
            match Pin::new(to).poll(cx) {
                Poll::Ready(()) => {}
                Poll::Pending => return Poll::Pending,
            }
        }
        self.timeout = None;

        let accept = self.listener.accept();
        futures_util::pin_mut!(accept);

        loop {
            match accept.poll_unpin(cx) {
                Poll::Ready(Ok((socket, addr))) => {
                    if let Some(dur) = self.tcp_keepalive_timeout {
                        if let Err(e) = socket.set_keepalive(Some(dur)) {
                            trace!("error trying to set TCP keepalive: {}", e);
                        }
                    }
                    if let Err(e) = socket.set_nodelay(self.tcp_nodelay) {
                        trace!("error trying to set TCP nodelay: {}", e);
                    }
                    return Poll::Ready(Ok(PlainStream::new(socket, addr)));
                    //return Poll::Ready(Ok(socket));
                }
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => {
                    // Connection errors can be ignored directly, continue by
                    // accepting the next request.
                    if is_connection_error(&e) {
                        debug!("accepted connection already errored: {}", e);
                        continue;
                    }

                    if self.sleep_on_errors {
                        error!("accept error: {}", e);

                        // Sleep 1s.
                        let mut timeout = tokio::time::delay_for(Duration::from_secs(1));

                        match Pin::new(&mut timeout).poll(cx) {
                            Poll::Ready(()) => {
                                // Wow, it's been a second already? Ok then...
                                continue;
                            }
                            Poll::Pending => {
                                self.timeout = Some(timeout);
                                return Poll::Pending;
                            }
                        }
                    } else {
                        return Poll::Ready(Err(e));
                    }
                }
            }
        }
    }
}

impl Accept for PlainIncoming {
    type Conn = PlainStream;
    type Error = io::Error;

    fn poll_accept(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Self::Conn, Self::Error>>> {
        let result = ready!(self.poll_next_(cx));
        Poll::Ready(Some(result))
    }
}

/// This function defines errors that are per-connection. Which basically
/// means that if we get this error from `accept()` system call it means
/// next connection might be ready to be accepted.
///
/// All other errors will incur a timeout before next `accept()` is performed.
/// The timeout is useful to handle resource exhaustion errors like ENFILE
/// and EMFILE. Otherwise, could enter into tight loop.
fn is_connection_error(e: &io::Error) -> bool {
    match e.kind() {
        io::ErrorKind::ConnectionRefused
        | io::ErrorKind::ConnectionAborted
        | io::ErrorKind::ConnectionReset => true,
        _ => false,
    }
}

impl fmt::Debug for PlainIncoming {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PlainIncoming")
            .field("addr", &self.addr)
            .field("sleep_on_errors", &self.sleep_on_errors)
            .field("tcp_keepalive_timeout", &self.tcp_keepalive_timeout)
            .field("tcp_nodelay", &self.tcp_nodelay)
            .finish()
    }
}

#[derive(Debug)]
pub struct PlainStream {
    inner: TcpStream,
    pub(super) remote_addr: SocketAddr,
}

impl PlainStream {
    pub(super) fn new(tcp: TcpStream, addr: SocketAddr) -> PlainStream {
        PlainStream {
            inner: tcp,
            remote_addr: addr,
        }
    }

    /// Returns the remote (peer) address of this connection.
    #[inline]
    pub fn remote_addr(&self) -> SocketAddr {
        self.remote_addr
    }

    /// Consumes the PlainStream and returns the underlying IO object
    #[inline]
    pub fn into_inner(self) -> TcpStream {
        self.inner
    }

    /// Attempt to receive data on the socket, without removing that data
    /// from the queue, registering the current task for wakeup if data is
    /// not yet available.
    pub fn poll_peek(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        self.inner.poll_peek(cx, buf)
    }
}

impl AsyncRead for PlainStream {
    unsafe fn prepare_uninitialized_buffer(
        &self,
        buf: &mut [std::mem::MaybeUninit<u8>],
    ) -> bool {
        self.inner.prepare_uninitialized_buffer(buf)
    }

    #[inline]
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }

    #[inline]
    fn poll_read_buf<B: BufMut>(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut B,
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_read_buf(cx, buf)
    }
}

impl AsyncWrite for PlainStream {
    #[inline]
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    #[inline]
    fn poll_write_buf<B: Buf>(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut B,
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_buf(cx, buf)
    }

    #[inline]
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // TCP flush is a noop
        Poll::Ready(Ok(()))
    }

    #[inline]
    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(unix)]
impl AsRawFd for PlainStream {
    fn as_raw_fd(&self) -> RawFd {
        self.inner.as_raw_fd()
    }
}
