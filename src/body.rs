use bytes::{Buf, Bytes};
use futures_util::Future;
use hyper::body::{Body as HttpBody, Frame, SizeHint};
use log::trace;
use pin_project_lite::pin_project;
use std::collections::VecDeque;
use std::io::Error as IoError;
use std::marker::PhantomData;
use std::pin::Pin;
use std::task::{Context, Poll};

pub type FRWSResp = hyper::Response<BoxBody<IoError>>;
pub type FRWSResult = Result<hyper::Response<BoxBody<IoError>>, IoError>;

/// Request Body
///
/// matches Incoming from hyper, but also allows tests to do shortcuts
pub trait IncomingBodyTrait:
    HttpBody<Data = Bytes, Error = hyper::Error> + Unpin + Sized + Send + Sync
{
    ///read whole body to memory
    ///
    /// like the old `hyper::body::aggregate` but checks the len as it gathers the data
    fn buffer(self, max_size: usize) -> BufferBody<Self> {
        BufferBody {
            body: self,
            max_size,
            buf: Some(VecDeque::new()),
            len: 0,
        }
    }
}
impl IncomingBodyTrait for IncomingBody {}

#[cfg(test)]
pub type IncomingBody = test::TestBody;
#[cfg(not(test))]
pub type IncomingBody = hyper::body::Incoming;

#[cfg(test)]
pub mod test {
    use super::*;
    pub struct TestBody(Option<Bytes>);
    impl HttpBody for TestBody {
        type Data = Bytes;

        type Error = hyper::Error;

        fn poll_frame(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
            Poll::Ready(self.0.take().map(|data| Ok(Frame::data(data))))
        }
        fn size_hint(&self) -> SizeHint {
            SizeHint::with_exact(self.0.as_ref().map_or(0, |b| b.len() as u64))
        }
    }
    impl TestBody {
        pub fn from(b: &'static str) -> TestBody {
            TestBody(Some(Bytes::from_static(b.as_bytes())))
        }
        pub fn empty() -> TestBody {
            TestBody(None)
        }
        pub async fn from_incoming(body: hyper::body::Incoming) -> TestBody {
            TestBody(Some(crate::body::test::to_bytes(body).await))
        }
    }

    pin_project! {
        /// Future for `to_bytes`
        pub struct Aggregator<T: HttpBody>{
            #[pin]
            body: T,
            buf: Option<bytes::BytesMut>,
        }
    }
    ///read whole body
    ///
    ///only for tests. like the old `hyper::body::to_bytes`
    pub fn to_bytes<T: HttpBody<Data = Bytes, Error = E>, E: std::error::Error>(
        body: T,
    ) -> Aggregator<T> {
        Aggregator {
            body,
            buf: Some(bytes::BytesMut::with_capacity(1024)),
        }
    }
    impl<T: HttpBody<Data = Bytes, Error = E> + Unpin, E: std::error::Error> std::future::Future
        for Aggregator<T>
    {
        type Output = Bytes;

        fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            let mut this = self.project();

            loop {
                return match this.body.as_mut().poll_frame(cx) {
                    Poll::Ready(Some(Ok(frame))) => {
                        if let Ok(data) = frame.into_data() {
                            this.buf.as_mut().unwrap().extend_from_slice(&data);
                        }
                        continue;
                    }
                    Poll::Ready(None) => Poll::Ready(this.buf.take().unwrap().freeze()),
                    Poll::Ready(Some(Err(e))) => panic!("{:?}", e),
                    Poll::Pending => Poll::Pending,
                };
            }
        }
    }
}

pub enum BufferedBody<Body, Buf> {
    Passthrough(Body),
    Buffer { buf: VecDeque<Buf>, len: usize },
}
impl<Body> HttpBody for BufferedBody<Body, Body::Data>
where
    Body: HttpBody + Send + Sync + Unpin,
    Body::Data: Buf,
{
    type Data = Body::Data;
    type Error = Body::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match unsafe { self.get_unchecked_mut() } {
            BufferedBody::Passthrough(bod) => unsafe { Pin::new_unchecked(bod) }.poll_frame(cx),
            BufferedBody::Buffer { buf, .. } => {
                Poll::Ready(buf.pop_front().map(|d| Ok(Frame::data(d))))
            }
        }
    }

    fn size_hint(&self) -> SizeHint {
        match self {
            BufferedBody::Passthrough(body) => body.size_hint(),
            BufferedBody::Buffer { len, .. } => SizeHint::with_exact(*len as u64),
        }
    }
}
impl<Body> BufferedBody<Body, Body::Data>
where
    Body: HttpBody + Send + Sync + Unpin,
    Body::Data: Buf,
{
    /// dont buffer
    pub fn wrap(body: Body) -> BufferedBody<Body, Body::Data> {
        BufferedBody::Passthrough(body)
    }
}
pin_project! {
    /// Future for `body.buffer()`
    pub struct BufferBody<B>{
        #[pin]
        body: B,
        max_size: usize,
        buf: Option<VecDeque<Bytes>>,
        len: usize
    }
}
impl<B: HttpBody<Data = Bytes, Error = hyper::Error> + Unpin> Future for BufferBody<B> {
    type Output = Result<BufferedBody<B, Bytes>, IoError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut this = self.project();
        loop {
            return match this.body.as_mut().poll_frame(cx) {
                Poll::Ready(Some(Ok(frame))) => {
                    if let Ok(chunk) = frame.into_data() {
                        if chunk.has_remaining() {
                            *this.len += chunk.remaining();
                            this.buf.as_mut().unwrap().push_back(chunk);

                            if this.len > this.max_size {
                                return Poll::Ready(Err(IoError::new(
                                    std::io::ErrorKind::PermissionDenied,
                                    "body too big",
                                )));
                            }
                        }
                    }
                    continue;
                }
                Poll::Ready(None) => {
                    trace!("buffered input body of {} Bytes", this.len);
                    Poll::Ready(Ok(BufferedBody::Buffer {
                        buf: this.buf.take().unwrap(),
                        len: *this.len,
                    }))
                }
                Poll::Ready(Some(Err(e))) => {
                    Poll::Ready(Err(IoError::new(std::io::ErrorKind::Other, e.to_string())))
                }
                Poll::Pending => Poll::Pending,
            };
        }
    }
}

/// Return Body that can handle all types
pub struct BoxBody<E> {
    inner: Pin<Box<dyn HttpBody<Data = Bytes, Error = E> + Send + Sync + 'static>>,
}

impl<E: Send + Sync + 'static> BoxBody<E> {
    /// Create a new `BoxBody`.
    pub fn new<B>(body: B) -> Self
    where
        B: HttpBody<Data = Bytes, Error = E> + Send + Sync + 'static,
    {
        Self {
            inner: Box::pin(body),
        }
    }
    pub fn empty() -> Self {
        Self {
            inner: Box::pin(Empty(PhantomData)),
        }
    }
}

pub struct Empty<E>(PhantomData<E>);
impl<E> HttpBody for Empty<E> {
    type Data = Bytes;
    type Error = E;

    fn poll_frame(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        Poll::Ready(None)
    }
    fn size_hint(&self) -> SizeHint {
        SizeHint::with_exact(0)
    }
}

impl<E> std::fmt::Debug for BoxBody<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BoxBody").finish()
    }
}

impl<E> HttpBody for BoxBody<E> {
    type Data = Bytes;
    type Error = E;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        self.inner.as_mut().poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}
