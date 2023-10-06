use bytes::{Buf, Bytes};
use futures_util::stream::Stream;
use hyper::body::{HttpBody, SizeHint};
use log::trace;
use std::collections::VecDeque;
use std::io::Error as IoError;
use std::pin::Pin;
use std::task::{Context, Poll};

/// Streamed response
pub struct HttpBodyStream<B: HttpBody<Data = Bytes, Error = IoError> + Send + Sync + Unpin>(B);

impl<B: HttpBody<Data = Bytes, Error = IoError> + Send + Sync + Unpin> Stream
    for HttpBodyStream<B>
{
    type Item = Result<Bytes, IoError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.0).poll_data(cx)
    }
}
impl<B: HttpBody<Data = Bytes, Error = IoError> + Send + Sync + Unpin> From<B>
    for HttpBodyStream<B>
{
    #[inline]
    fn from(bod: B) -> HttpBodyStream<B> {
        HttpBodyStream(bod)
    }
}

/// Request Body
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

    fn poll_data(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Self::Data, Self::Error>>> {
        match unsafe { self.get_unchecked_mut() } {
            BufferedBody::Passthrough(bod) => unsafe { Pin::new_unchecked(bod) }.poll_data(cx),
            BufferedBody::Buffer { buf, .. } => Poll::Ready(buf.pop_front().map(Ok)),
        }
    }

    fn size_hint(&self) -> SizeHint {
        match self {
            BufferedBody::Passthrough(body) => body.size_hint(),
            BufferedBody::Buffer { len, .. } => SizeHint::with_exact(*len as u64),
        }
    }

    fn poll_trailers(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<Option<hyper::HeaderMap>, Self::Error>> {
        Poll::Ready(Ok(None))
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
impl BufferedBody<hyper::Body, Bytes> {
    ///read whole body to memory
    /// 
    /// like `hyper::body::aggregate` but checks the len as it gathers the data
    pub async fn buffer(
        mut body: hyper::Body,
        max_size: usize,
    ) -> Result<BufferedBody<hyper::Body, Bytes>, IoError> {
        let mut buf = VecDeque::new();
        let mut len = 0usize;
        while let Some(chunk) = body.data().await {
            let chunk = chunk.map_err(|e| IoError::new(std::io::ErrorKind::Other, e))?;
            if chunk.has_remaining() {
                len += chunk.remaining();
                buf.push_back(chunk);

                if len > max_size {
                    return Err(IoError::new(
                        std::io::ErrorKind::PermissionDenied,
                        "body too big",
                    ));
                }
            }
        }
        trace!("buffered input body of {} Bytes", len);
        Ok(BufferedBody::Buffer { buf, len })
    }
}
