use bytes::Bytes;
use std::io::Error as IoError;
use std::pin::Pin;
use std::task::{Context, Poll};
use hyper::body::HttpBody;
use futures_util::stream::Stream;

pub struct FCGIBody<B: HttpBody<Data = Bytes,Error = IoError> + Send + Sync+ Unpin>(B);

impl<B: HttpBody<Data = Bytes,Error = IoError> + Send + Sync + Unpin> Stream for FCGIBody<B> {
    type Item = Result<Bytes, IoError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.0).poll_data(cx)
    }
}
impl<B: HttpBody<Data = Bytes,Error = IoError> + Send + Sync + Unpin> From<B> for FCGIBody<B> {
    #[inline]
    fn from(
        bod: B,
    ) -> FCGIBody<B> {
        FCGIBody(bod)
    }
}
