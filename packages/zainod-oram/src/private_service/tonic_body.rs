//! Lazy Tonic encoding for one listener-free private-query response.

use std::{
    future::{ready, Ready},
    marker::PhantomData,
    pin::Pin,
    task::{Context, Poll},
};

use http_body::{Frame, SizeHint};
use tonic::{
    body::Body as TonicBody,
    codec::{BufferSettings, Codec, Encoder},
    codegen::{http, Body as HttpBody, Bytes, StdError},
    server::{Grpc, UnaryService},
    Request, Response, Status,
};
use tonic_prost::{ProstDecoder, ProstEncoder};

use super::{
    FixedEnvelopeRuntime, PendingFixedEnvelope, PendingQueryPage, PrivateServiceAdapter,
    ValidatedFixedEnvelope,
};
use crate::private_proto;

const UNIFORM_GRPC_MESSAGE: &str = "private%20query%20unavailable";

/// Codec that delays response-byte access until Tonic polls the response body.
struct PrivateResponseCodec<P, const N: usize> {
    _pending: PhantomData<P>,
}

impl<P, const N: usize> PrivateResponseCodec<P, N> {
    const fn new() -> Self {
        Self {
            _pending: PhantomData,
        }
    }
}

impl<P, const N: usize> Codec for PrivateResponseCodec<P, N>
where
    P: PendingFixedEnvelope<N> + Send + 'static,
{
    type Encode = PendingQueryPage<P, N>;
    type Decode = private_proto::FixedEnvelope;
    type Encoder = PrivateResponseEncoder<P, N>;
    type Decoder = ProstDecoder<private_proto::FixedEnvelope>;

    fn encoder(&mut self) -> Self::Encoder {
        PrivateResponseEncoder::new()
    }

    fn decoder(&mut self) -> Self::Decoder {
        ProstDecoder::default()
    }
}

impl<P, const N: usize> std::fmt::Debug for PrivateResponseCodec<P, N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PrivateResponseCodec { ..REDACTED.. }")
    }
}

/// Encodes only after the pending runtime value accepts release-time currentness.
struct PrivateResponseEncoder<P, const N: usize> {
    inner: ProstEncoder<private_proto::FixedEnvelope>,
    _pending: PhantomData<P>,
}

impl<P, const N: usize> PrivateResponseEncoder<P, N> {
    fn new() -> Self {
        Self {
            inner: ProstEncoder::default(),
            _pending: PhantomData,
        }
    }
}

impl<P, const N: usize> Encoder for PrivateResponseEncoder<P, N>
where
    P: PendingFixedEnvelope<N>,
{
    type Item = PendingQueryPage<P, N>;
    type Error = Status;

    fn encode(
        &mut self,
        item: Self::Item,
        destination: &mut tonic::codec::EncodeBuf<'_>,
    ) -> Result<(), Self::Error> {
        let bytes = item
            .pending_response
            .try_release_bytes()
            .map_err(coarsen_tonic_error)?;
        let response = ValidatedFixedEnvelope::from_array(*bytes).to_wire();
        let result = self
            .inner
            .encode(response, destination)
            .map_err(coarsen_tonic_error);
        drop(item);
        result
    }

    fn buffer_settings(&self) -> BufferSettings {
        self.inner.buffer_settings()
    }
}

impl<P, const N: usize> std::fmt::Debug for PrivateResponseEncoder<P, N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PrivateResponseEncoder { ..REDACTED.. }")
    }
}

/// One synchronous adapter borrow presented to Tonic's unary machinery.
struct PrivateUnary<'a, H, const N: usize> {
    adapter: &'a mut PrivateServiceAdapter<H, N>,
}

impl<H, const N: usize> UnaryService<private_proto::FixedEnvelope> for PrivateUnary<'_, H, N>
where
    H: FixedEnvelopeRuntime<N>,
    H::PendingResponse: Send + 'static,
{
    type Response = PendingQueryPage<H::PendingResponse, N>;
    type Future = Ready<Result<Response<Self::Response>, Status>>;

    fn call(&mut self, request: Request<private_proto::FixedEnvelope>) -> Self::Future {
        ready(
            self.adapter
                .query_page(request.into_inner())
                .map(Response::new)
                .map_err(coarsen_tonic_error),
        )
    }
}

/// Listener-free entry point that returns Tonic's lazily encoded response body.
pub(super) struct PrivateTonicBodyAdapter<H, const N: usize> {
    adapter: PrivateServiceAdapter<H, N>,
}

impl<H, const N: usize> PrivateTonicBodyAdapter<H, N>
where
    H: FixedEnvelopeRuntime<N>,
    H::PendingResponse: Send + 'static,
{
    pub(super) const fn new(handler: H) -> Self {
        Self {
            adapter: PrivateServiceAdapter::new(handler),
        }
    }

    pub(super) async fn query_page<B>(
        &mut self,
        request: http::Request<B>,
    ) -> http::Response<TonicBody>
    where
        B: HttpBody + Send + 'static,
        B::Error: Into<StdError> + Send,
    {
        let service = PrivateUnary {
            adapter: &mut self.adapter,
        };
        let mut grpc = Grpc::new(PrivateResponseCodec::<H::PendingResponse, N>::new());
        let mut response = grpc.unary(service, request).await;
        coarsen_initial_status(&mut response);
        let (parts, body) = response.into_parts();
        http::Response::from_parts(parts, TonicBody::new(UniformStatusBody::new(body)))
    }
}

impl<H, const N: usize> std::fmt::Debug for PrivateTonicBodyAdapter<H, N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PrivateTonicBodyAdapter { ..REDACTED.. }")
    }
}

/// Rewrites Tonic's encoder-error status to the private service's one failure.
struct UniformStatusBody {
    inner: TonicBody,
    done: bool,
}

impl UniformStatusBody {
    const fn new(inner: TonicBody) -> Self {
        Self { inner, done: false }
    }
}

impl HttpBody for UniformStatusBody {
    type Data = Bytes;
    type Error = Status;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if self.done {
            return Poll::Ready(None);
        }
        match Pin::new(&mut self.inner).poll_frame(context) {
            Poll::Ready(Some(Ok(frame))) if frame_has_failure(&frame) => {
                self.done = true;
                Poll::Ready(Some(Ok(Frame::trailers(uniform_status_headers()))))
            }
            Poll::Ready(Some(Err(_))) => {
                self.done = true;
                Poll::Ready(Some(Ok(Frame::trailers(uniform_status_headers()))))
            }
            other => other,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.done || self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        if self.done {
            SizeHint::with_exact(0)
        } else {
            self.inner.size_hint()
        }
    }
}

impl std::fmt::Debug for UniformStatusBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("UniformStatusBody { ..REDACTED.. }")
    }
}

fn frame_has_failure(frame: &Frame<Bytes>) -> bool {
    frame.trailers_ref().is_some_and(status_is_failure)
}

fn status_is_failure(headers: &http::HeaderMap) -> bool {
    headers
        .get(Status::GRPC_STATUS)
        .is_some_and(|status| status.as_bytes() != b"0")
}

fn coarsen_initial_status(response: &mut http::Response<TonicBody>) {
    if status_is_failure(response.headers()) {
        *response.headers_mut() = uniform_initial_status_headers();
        response.extensions_mut().clear();
    }
}

fn uniform_initial_status_headers() -> http::HeaderMap {
    let mut headers = uniform_status_headers();
    headers.insert(
        http::header::CONTENT_TYPE,
        http::HeaderValue::from_static("application/grpc"),
    );
    headers
}

fn uniform_status_headers() -> http::HeaderMap {
    let mut headers = http::HeaderMap::new();
    headers.insert(Status::GRPC_STATUS, http::HeaderValue::from_static("14"));
    headers.insert(
        Status::GRPC_MESSAGE,
        http::HeaderValue::from_static(UNIFORM_GRPC_MESSAGE),
    );
    headers
}

fn coarsen_tonic_error<T>(_: T) -> Status {
    Status::unavailable("private query unavailable")
}

#[cfg(test)]
mod tests {
    use std::{
        convert::Infallible,
        future::poll_fn,
        sync::{
            atomic::{AtomicBool, AtomicUsize, Ordering},
            Arc,
        },
    };

    use prost::Message;

    use super::*;
    use crate::private_service::RuntimeUnavailable;

    const ENVELOPE_BYTES: usize = 4;

    #[derive(Clone)]
    struct MockState {
        busy: Arc<AtomicBool>,
        calls: Arc<AtomicUsize>,
        current: Arc<AtomicBool>,
        release_checks: Arc<AtomicUsize>,
        released_borrows: Arc<AtomicUsize>,
    }

    impl MockState {
        fn new() -> Self {
            Self {
                busy: Arc::new(AtomicBool::new(false)),
                calls: Arc::new(AtomicUsize::new(0)),
                current: Arc::new(AtomicBool::new(true)),
                release_checks: Arc::new(AtomicUsize::new(0)),
                released_borrows: Arc::new(AtomicUsize::new(0)),
            }
        }
    }

    struct MockPendingResponse {
        response: [u8; ENVELOPE_BYTES],
        state: MockState,
    }

    impl PendingFixedEnvelope<ENVELOPE_BYTES> for MockPendingResponse {
        fn try_release_bytes(&self) -> Result<&[u8; ENVELOPE_BYTES], RuntimeUnavailable> {
            self.state.release_checks.fetch_add(1, Ordering::SeqCst);
            if !self.state.current.load(Ordering::SeqCst) {
                return Err(RuntimeUnavailable);
            }
            self.state.released_borrows.fetch_add(1, Ordering::SeqCst);
            Ok(&self.response)
        }
    }

    impl Drop for MockPendingResponse {
        fn drop(&mut self) {
            self.state.busy.store(false, Ordering::SeqCst);
        }
    }

    struct MockHandler {
        response: [u8; ENVELOPE_BYTES],
        state: MockState,
    }

    impl FixedEnvelopeRuntime<ENVELOPE_BYTES> for MockHandler {
        type PendingResponse = MockPendingResponse;

        fn query_page(
            &mut self,
            _request: [u8; ENVELOPE_BYTES],
        ) -> Result<Self::PendingResponse, RuntimeUnavailable> {
            self.state.calls.fetch_add(1, Ordering::SeqCst);
            if self.state.busy.swap(true, Ordering::SeqCst) {
                return Err(RuntimeUnavailable);
            }
            Ok(MockPendingResponse {
                response: self.response,
                state: self.state.clone(),
            })
        }
    }

    struct OneFrameBody {
        frame: Option<Bytes>,
    }

    impl HttpBody for OneFrameBody {
        type Data = Bytes;
        type Error = Infallible;

        fn poll_frame(
            mut self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
            Poll::Ready(self.frame.take().map(|frame| Ok(Frame::data(frame))))
        }
    }

    struct ErrorBody {
        error: Option<Status>,
    }

    impl HttpBody for ErrorBody {
        type Data = Bytes;
        type Error = Status;

        fn poll_frame(
            mut self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
            Poll::Ready(self.error.take().map(Err))
        }
    }

    fn fixture() -> (
        PrivateTonicBodyAdapter<MockHandler, ENVELOPE_BYTES>,
        MockState,
    ) {
        let state = MockState::new();
        let handler = MockHandler {
            response: [9, 8, 7, 6],
            state: state.clone(),
        };
        (PrivateTonicBodyAdapter::new(handler), state)
    }

    fn request(bytes: &[u8]) -> http::Request<OneFrameBody> {
        let message = private_proto::FixedEnvelope {
            envelope: bytes.to_vec(),
        }
        .encode_to_vec();
        let length = u32::try_from(message.len())
            .expect("test protobuf request length fits the gRPC prefix");
        let mut frame = Vec::with_capacity(5 + message.len());
        frame.push(0);
        frame.extend_from_slice(&length.to_be_bytes());
        frame.extend_from_slice(&message);
        http::Request::new(OneFrameBody {
            frame: Some(Bytes::from(frame)),
        })
    }

    async fn next_frame(body: &mut TonicBody) -> Option<Result<Frame<Bytes>, Status>> {
        poll_fn(|context| Pin::new(&mut *body).poll_frame(context)).await
    }

    fn assert_uniform_status(headers: &http::HeaderMap) {
        assert_eq!(
            headers.get(Status::GRPC_STATUS),
            Some(&http::HeaderValue::from_static("14"))
        );
        assert_eq!(
            headers.get(Status::GRPC_MESSAGE),
            Some(&http::HeaderValue::from_static(UNIFORM_GRPC_MESSAGE))
        );
        assert!(!headers.contains_key(Status::GRPC_STATUS_DETAILS));
    }

    fn detailed_status() -> Status {
        let mut metadata = tonic::metadata::MetadataMap::new();
        metadata.insert(
            "x-private-detail",
            "secret-metadata"
                .parse()
                .expect("test metadata value is valid"),
        );
        Status::with_details_and_metadata(
            tonic::Code::Internal,
            "secret message",
            Bytes::from_static(b"secret details"),
            metadata,
        )
    }

    #[tokio::test]
    async fn first_body_poll_checks_releases_and_emits_one_exact_data_frame(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (mut adapter, state) = fixture();
        let response = adapter.query_page(request(&[1, 2, 3, 4])).await;
        assert!(state.busy.load(Ordering::SeqCst));
        assert_eq!(state.release_checks.load(Ordering::SeqCst), 0);
        assert_eq!(state.released_borrows.load(Ordering::SeqCst), 0);

        let mut body = response.into_body();
        let frame = next_frame(&mut body)
            .await
            .expect("successful unary body emits data")?;
        let data = frame
            .into_data()
            .expect("first successful unary frame is data");
        assert_eq!(data.as_ref(), [0, 0, 0, 0, 6, 0x0a, 4, 9, 8, 7, 6]);
        assert!(!state.busy.load(Ordering::SeqCst));
        assert_eq!(state.release_checks.load(Ordering::SeqCst), 1);
        assert_eq!(state.released_borrows.load(Ordering::SeqCst), 1);

        let trailers = next_frame(&mut body)
            .await
            .expect("successful unary body emits completion trailers")?
            .into_trailers()
            .expect("second successful unary frame is trailers");
        assert_eq!(
            trailers.get(Status::GRPC_STATUS),
            Some(&http::HeaderValue::from_static("0"))
        );
        assert!(next_frame(&mut body).await.is_none());
        assert_eq!(state.release_checks.load(Ordering::SeqCst), 1);
        Ok(())
    }

    #[tokio::test]
    async fn admission_remains_closed_until_data_poll_then_reopens(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (mut adapter, state) = fixture();
        let first = adapter.query_page(request(&[1, 2, 3, 4])).await;

        let rejected = adapter.query_page(request(&[4, 3, 2, 1])).await;
        assert_uniform_status(rejected.headers());
        assert_eq!(state.calls.load(Ordering::SeqCst), 2);

        let mut first_body = first.into_body();
        let first_frame = next_frame(&mut first_body)
            .await
            .expect("first response emits one frame")?;
        assert!(first_frame.is_data());

        let admitted = adapter.query_page(request(&[4, 3, 2, 1])).await;
        assert!(!status_is_failure(admitted.headers()));
        assert_eq!(state.calls.load(Ordering::SeqCst), 3);
        drop(admitted);
        Ok(())
    }

    #[tokio::test]
    async fn stale_release_emits_no_data_and_one_uniform_status(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (mut adapter, state) = fixture();
        let response = adapter.query_page(request(&[1, 2, 3, 4])).await;
        state.current.store(false, Ordering::SeqCst);

        let mut body = response.into_body();
        let trailers = next_frame(&mut body)
            .await
            .expect("stale response emits uniform trailers")?
            .into_trailers()
            .expect("stale response never emits data");
        assert_uniform_status(&trailers);
        assert!(!state.busy.load(Ordering::SeqCst));
        assert_eq!(state.release_checks.load(Ordering::SeqCst), 1);
        assert_eq!(state.released_borrows.load(Ordering::SeqCst), 0);
        assert!(next_frame(&mut body).await.is_none());
        Ok(())
    }

    #[tokio::test]
    async fn dropping_unpolled_body_releases_without_checking_or_borrowing() {
        let (mut adapter, state) = fixture();
        let body = adapter.query_page(request(&[1, 2, 3, 4])).await.into_body();
        assert!(state.busy.load(Ordering::SeqCst));

        drop(body);
        assert!(!state.busy.load(Ordering::SeqCst));
        assert_eq!(state.release_checks.load(Ordering::SeqCst), 0);
        assert_eq!(state.released_borrows.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn boundary_failure_is_uniform_before_body_creation() {
        let (mut adapter, state) = fixture();
        let response = adapter.query_page(request(&[1, 2, 3])).await;

        assert_uniform_status(response.headers());
        assert_eq!(state.calls.load(Ordering::SeqCst), 0);
        assert_eq!(state.release_checks.load(Ordering::SeqCst), 0);
        assert!(response.into_body().is_end_stream());
    }

    #[tokio::test]
    async fn request_body_error_metadata_and_extensions_are_removed() {
        let (mut adapter, state) = fixture();
        let response = adapter
            .query_page(http::Request::new(ErrorBody {
                error: Some(detailed_status()),
            }))
            .await;

        assert_uniform_status(response.headers());
        assert_eq!(
            response.headers().get(http::header::CONTENT_TYPE),
            Some(&http::HeaderValue::from_static("application/grpc"))
        );
        assert_eq!(response.headers().len(), 3);
        assert!(!response.headers().contains_key("x-private-detail"));
        assert!(response.extensions().is_empty());
        assert_eq!(state.calls.load(Ordering::SeqCst), 0);
        assert_eq!(state.release_checks.load(Ordering::SeqCst), 0);
        assert!(response.into_body().is_end_stream());
    }

    #[tokio::test]
    async fn body_errors_become_one_uniform_trailer_and_end_the_stream(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let inner = TonicBody::new(ErrorBody {
            error: Some(detailed_status()),
        });
        let mut body = TonicBody::new(UniformStatusBody::new(inner));

        let trailers = next_frame(&mut body)
            .await
            .expect("body error emits uniform trailers")?
            .into_trailers()
            .expect("body error never emits data");
        assert_uniform_status(&trailers);
        assert_eq!(trailers.len(), 2);
        assert!(body.is_end_stream());
        assert!(next_frame(&mut body).await.is_none());
        Ok(())
    }

    #[test]
    fn tonic_body_debug_surfaces_are_redacted() {
        let (adapter, _) = fixture();
        let codec = PrivateResponseCodec::<MockPendingResponse, ENVELOPE_BYTES>::new();
        let encoder = PrivateResponseEncoder::<MockPendingResponse, ENVELOPE_BYTES>::new();

        assert_eq!(
            format!("{adapter:?}"),
            "PrivateTonicBodyAdapter { ..REDACTED.. }"
        );
        assert_eq!(
            format!("{codec:?}"),
            "PrivateResponseCodec { ..REDACTED.. }"
        );
        assert_eq!(
            format!("{encoder:?}"),
            "PrivateResponseEncoder { ..REDACTED.. }"
        );
        assert_eq!(
            format!("{:?}", UniformStatusBody::new(TonicBody::empty())),
            "UniformStatusBody { ..REDACTED.. }"
        );
    }
}
