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
#[cfg(test)]
use zaino_oram::PrivateQueryUnavailable;
use zaino_oram::{FixedEnvelopeRuntime, PendingFixedEnvelope, SessionBootstrap};

use super::{PendingQueryPage, PrivateServiceAdapter, ValidatedFixedEnvelope};
use crate::private_proto;

const UNIFORM_GRPC_MESSAGE: &str = "private%20query%20unavailable";

/// Codec that delays response-byte access until Tonic polls the response body.
struct PrivateResponseCodec<P, const N: usize> {
    current_key_epoch: u64,
    _pending: PhantomData<P>,
}

impl<P, const N: usize> PrivateResponseCodec<P, N> {
    const fn new(current_key_epoch: u64) -> Self {
        Self {
            current_key_epoch,
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
        PrivateResponseEncoder::new(self.current_key_epoch)
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
    current_key_epoch: u64,
    _pending: PhantomData<P>,
}

impl<P, const N: usize> PrivateResponseEncoder<P, N> {
    fn new(current_key_epoch: u64) -> Self {
        Self {
            inner: ProstEncoder::default(),
            current_key_epoch,
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
        let response = ValidatedFixedEnvelope::from_array(*bytes).to_wire(self.current_key_epoch);
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

/// `BootstrapRequest` carries no fields, so its wire-encoded body is empty.
const BOOTSTRAP_REQUEST_BYTES: usize = 0;

/// Distinguishable pre-open classification of one query-page request's epoch.
///
/// The epoch comparison is on public data -- the same value for every client
/// -- so an ordinary `==` is correct; the constant-time helpers elsewhere in
/// this crate exist for secret comparisons and would misstate this one as
/// sensitive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PrivateQueryOutcome {
    /// The request's key epoch does not match the runtime's live epoch.
    StaleKeyEpoch,
}

/// Classifies a request's key epoch against the runtime's live epoch before
/// any attempt to open its envelope. `None` means the epoch matches and
/// ordinary handling should proceed; under a retired key the open would fail
/// anyway, so this check exists to answer with something a wallet can act on
/// instead of an opaque refusal.
const fn classify_request_epoch(
    current_epoch: u64,
    request_epoch: u64,
) -> Option<PrivateQueryOutcome> {
    if request_epoch == current_epoch {
        None
    } else {
        Some(PrivateQueryOutcome::StaleKeyEpoch)
    }
}

/// gRPC message distinguishing a stale-epoch refusal from the uniform one.
///
/// Deliberately not folded into [`UNIFORM_GRPC_MESSAGE`]: the epoch is
/// per-generation and identical for every client, so reporting that a request
/// used a retired one leaks nothing, and a wallet has no other way to learn
/// it must re-bootstrap.
const STALE_KEY_EPOCH_GRPC_MESSAGE: &str = "stale-key-epoch";

fn status_for_query_outcome(outcome: PrivateQueryOutcome) -> Status {
    match outcome {
        PrivateQueryOutcome::StaleKeyEpoch => {
            Status::failed_precondition(STALE_KEY_EPOCH_GRPC_MESSAGE)
        }
    }
}

/// One synchronous adapter borrow presented to Tonic's unary machinery.
struct PrivateUnary<'a, H, const N: usize> {
    adapter: &'a mut PrivateServiceAdapter<H, N>,
    current_key_epoch: u64,
}

impl<H, const N: usize> UnaryService<private_proto::FixedEnvelope> for PrivateUnary<'_, H, N>
where
    H: FixedEnvelopeRuntime<N>,
    H::PendingResponse: Send + 'static,
{
    type Response = PendingQueryPage<H::PendingResponse, N>;
    type Future = Ready<Result<Response<Self::Response>, Status>>;

    fn call(&mut self, request: Request<private_proto::FixedEnvelope>) -> Self::Future {
        let envelope = request.into_inner();
        if let Some(outcome) = classify_request_epoch(self.current_key_epoch, envelope.key_epoch) {
            return ready(Err(status_for_query_outcome(outcome)));
        }
        ready(
            self.adapter
                .query_page(envelope)
                .map(Response::new)
                .map_err(coarsen_tonic_error),
        )
    }
}

/// Answers a bootstrap request with the runtime's current session material.
///
/// `BootstrapRequest` is empty on the wire, so the only work here is building
/// the response; the cap on the request itself is enforced by the codec's
/// `max_decoding_message_size` before this service is ever called.
struct RespondBootstrap<'a> {
    session_bootstrap: &'a SessionBootstrap,
}

impl UnaryService<private_proto::BootstrapRequest> for RespondBootstrap<'_> {
    type Response = private_proto::BootstrapResponse;
    type Future = Ready<Result<Response<Self::Response>, Status>>;

    fn call(&mut self, _request: Request<private_proto::BootstrapRequest>) -> Self::Future {
        ready(Ok(Response::new(session_bootstrap_to_wire(
            self.session_bootstrap,
        ))))
    }
}

/// Encodes bootstrap material as the wire response, named rather than a
/// `From`/`TryFrom` impl per this crate's boundary-conversion convention.
/// `SessionBootstrap` is foreign to this crate, so this is a plain function
/// rather than an inherent method.
fn session_bootstrap_to_wire(bootstrap: &SessionBootstrap) -> private_proto::BootstrapResponse {
    private_proto::BootstrapResponse {
        key_epoch: bootstrap.key_epoch,
        request_key: bootstrap.keys.request_key.to_vec(),
        response_key: bootstrap.keys.response_key.to_vec(),
        profile_id: bootstrap.profile_id.to_owned(),
        envelope_bytes: u32::try_from(bootstrap.envelope_bytes).unwrap_or(u32::MAX),
        // Reserved for a future TDX quote; present and empty in this release.
        attestation: Vec::new(),
    }
}

/// Drives one capped decode through Tonic, then rewrites the result to the
/// private surface's uniform response shape. Shared by every route so the
/// two routes' framing cannot drift apart even though each brings its own
/// codec, cap, and unary service.
async fn capped_unary_call<C, S, B>(
    mut grpc: Grpc<C>,
    service: S,
    request: http::Request<B>,
) -> http::Response<TonicBody>
where
    C: Codec,
    S: UnaryService<C::Decode, Response = C::Encode>,
    B: HttpBody + Send + 'static,
    B::Error: Into<StdError> + Send,
{
    let mut response = grpc.unary(service, request).await;
    coarsen_initial_status(&mut response);
    let (parts, body) = response.into_parts();
    http::Response::from_parts(parts, TonicBody::new(UniformStatusBody::new(body)))
}

/// Listener-free entry point that returns Tonic's lazily encoded response body.
pub(super) struct PrivateTonicBodyAdapter<H, const N: usize> {
    adapter: PrivateServiceAdapter<H, N>,
    session_bootstrap: SessionBootstrap,
}

impl<H, const N: usize> PrivateTonicBodyAdapter<H, N>
where
    H: FixedEnvelopeRuntime<N>,
    H::PendingResponse: Send + 'static,
{
    /// `session_bootstrap` is captured once at construction rather than
    /// re-derived per request: the epoch, keys, and profile are fixed for a
    /// runtime's process lifetime, and this is also the one live epoch the
    /// query-page route checks every request's envelope against.
    pub(super) const fn new(handler: H, session_bootstrap: SessionBootstrap) -> Self {
        Self {
            adapter: PrivateServiceAdapter::new(handler),
            session_bootstrap,
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
        let current_key_epoch = self.session_bootstrap.key_epoch;
        let service = PrivateUnary {
            adapter: &mut self.adapter,
            current_key_epoch,
        };
        let grpc = Grpc::new(PrivateResponseCodec::<H::PendingResponse, N>::new(
            current_key_epoch,
        ))
        .max_decoding_message_size(fixed_envelope_request_wire_size(N));
        capped_unary_call(grpc, service, request).await
    }

    /// Decodes and answers a bootstrap request under its own cap.
    ///
    /// `BootstrapRequest` is empty on the wire, so its cap is
    /// `fixed_envelope_wire_size(0)` — independent of `QueryPage`'s cap, which
    /// is keyed to the application envelope size `N`. Sharing one cap across
    /// both routes would let the larger of the two set the limit for both.
    pub(super) async fn bootstrap<B>(
        &mut self,
        request: http::Request<B>,
    ) -> http::Response<TonicBody>
    where
        B: HttpBody + Send + 'static,
        B::Error: Into<StdError> + Send,
    {
        let grpc = Grpc::new(tonic_prost::ProstCodec::<
            private_proto::BootstrapResponse,
            private_proto::BootstrapRequest,
        >::default())
        .max_decoding_message_size(fixed_envelope_wire_size(BOOTSTRAP_REQUEST_BYTES));
        let service = RespondBootstrap {
            session_bootstrap: &self.session_bootstrap,
        };
        capped_unary_call(grpc, service, request).await
    }
}

/// Worst-case wire bytes for the `key_epoch` field: a 1-byte tag plus the
/// widest a `uint64` varint can ever encode (10 bytes, for `u64::MAX`).
const KEY_EPOCH_FIELD_WIRE_BYTES: usize = 1 + 10;

fn fixed_envelope_wire_size(envelope_bytes: usize) -> usize {
    1 + prost::length_delimiter_len(envelope_bytes) + envelope_bytes
}

/// Decode cap for one `FixedEnvelope` request, including its `key_epoch`
/// field.
///
/// Requests now echo the epoch they were sealed under, so a cap sized for
/// `envelope` alone would reject a legitimate nonzero epoch as oversized.
/// `BootstrapRequest` carries no such field, so [`fixed_envelope_wire_size`]
/// alone is still correct for that route's cap.
fn fixed_envelope_request_wire_size(envelope_bytes: usize) -> usize {
    fixed_envelope_wire_size(envelope_bytes) + KEY_EPOCH_FIELD_WIRE_BYTES
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
    if status_is_failure(response.headers()) && !status_is_stale_key_epoch(response.headers()) {
        *response.headers_mut() = uniform_initial_status_headers();
        response.extensions_mut().clear();
    }
}

/// Recognizes this file's own stale-key-epoch status by its exact code and
/// message, so it alone survives [`coarsen_initial_status`]'s rewrite.
/// Everything else -- transport errors, handler refusals -- is still coarsened
/// uniformly; only this one outcome is deliberately distinguishable, and only
/// because the epoch it reports is public.
fn status_is_stale_key_epoch(headers: &http::HeaderMap) -> bool {
    let failed_precondition = i32::from(tonic::Code::FailedPrecondition).to_string();
    headers
        .get(Status::GRPC_STATUS)
        .is_some_and(|status| status.as_bytes() == failed_precondition.as_bytes())
        && headers
            .get(Status::GRPC_MESSAGE)
            .is_some_and(|message| message.as_bytes() == STALE_KEY_EPOCH_GRPC_MESSAGE.as_bytes())
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
    use zaino_oram::{ReleasableSessionKeys, PRIVATE_RUNTIME_KEY_BYTES};

    const ENVELOPE_BYTES: usize = 4;
    const FIXTURE_KEY_EPOCH: u64 = 0;

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
        fn try_release_bytes(&self) -> Result<&[u8; ENVELOPE_BYTES], PrivateQueryUnavailable> {
            self.state.release_checks.fetch_add(1, Ordering::SeqCst);
            if !self.state.current.load(Ordering::SeqCst) {
                return Err(PrivateQueryUnavailable);
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
        ) -> Result<Self::PendingResponse, PrivateQueryUnavailable> {
            self.state.calls.fetch_add(1, Ordering::SeqCst);
            if self.state.busy.swap(true, Ordering::SeqCst) {
                return Err(PrivateQueryUnavailable);
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

    fn session_bootstrap_fixture() -> SessionBootstrap {
        SessionBootstrap {
            key_epoch: FIXTURE_KEY_EPOCH,
            keys: ReleasableSessionKeys {
                request_key: [0x11; PRIVATE_RUNTIME_KEY_BYTES],
                response_key: [0x22; PRIVATE_RUNTIME_KEY_BYTES],
            },
            profile_id: "test-profile",
            envelope_bytes: ENVELOPE_BYTES,
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
        (
            PrivateTonicBodyAdapter::new(handler, session_bootstrap_fixture()),
            state,
        )
    }

    /// Wraps an already-encoded protobuf message in the one-frame gRPC body
    /// shape both routes' tests decode from.
    fn encoded_frame(message: Vec<u8>) -> http::Request<OneFrameBody> {
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

    fn request(bytes: &[u8]) -> http::Request<OneFrameBody> {
        request_with_epoch(bytes, FIXTURE_KEY_EPOCH)
    }

    fn request_with_epoch(bytes: &[u8], key_epoch: u64) -> http::Request<OneFrameBody> {
        encoded_frame(
            private_proto::FixedEnvelope {
                envelope: bytes.to_vec(),
                key_epoch,
            }
            .encode_to_vec(),
        )
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
    async fn oversized_body_is_rejected_with_the_uniform_refusal() {
        let (mut adapter, state) = fixture();
        let response = adapter.query_page(request(&[1, 2, 3, 4, 5])).await;

        assert_uniform_status(response.headers());
        assert_eq!(state.calls.load(Ordering::SeqCst), 0);
        assert!(response.into_body().is_end_stream());
    }

    #[tokio::test]
    async fn each_route_is_capped_at_its_own_size() {
        // A body sized well past bootstrap's empty cap must still be refused
        // by QueryPage, whose cap is the fixed envelope. Sharing one cap
        // across routes would let the larger of the two set the limit for
        // both, letting an oversized QueryPage body slip through against
        // bootstrap's ceiling.
        let (mut adapter, state) = fixture();
        let oversized_for_query = vec![0u8; ENVELOPE_BYTES + 64];
        let response = adapter.query_page(request(&oversized_for_query)).await;

        assert_uniform_status(response.headers());
        assert_eq!(
            state.calls.load(Ordering::SeqCst),
            0,
            "an oversized query body reached the runtime"
        );
        assert!(response.into_body().is_end_stream());
    }

    async fn decode_bootstrap(
        response: http::Response<TonicBody>,
    ) -> Result<private_proto::BootstrapResponse, Box<dyn std::error::Error>> {
        let mut body = response.into_body();
        let frame = next_frame(&mut body)
            .await
            .expect("a served bootstrap response emits one data frame")?;
        let data = frame
            .into_data()
            .expect("the first bootstrap frame is data, not trailers");
        // Strip the 5-byte gRPC length-prefixed-message header (compression
        // flag + big-endian length) that precedes the protobuf payload on the
        // wire; see `first_body_poll_checks_releases_and_emits_one_exact_data_frame`
        // for the same framing on the query-page route.
        Ok(private_proto::BootstrapResponse::decode(&data[5..])?)
    }

    #[tokio::test]
    async fn bootstrap_returns_the_current_epoch_and_exactly_two_keys(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (mut adapter, _state) = fixture();
        let response = adapter
            .bootstrap(encoded_frame(
                private_proto::BootstrapRequest {}.encode_to_vec(),
            ))
            .await;

        assert!(!status_is_failure(response.headers()));
        let decoded = decode_bootstrap(response).await?;

        assert_eq!(decoded.key_epoch, FIXTURE_KEY_EPOCH);
        assert_eq!(decoded.request_key.len(), PRIVATE_RUNTIME_KEY_BYTES);
        assert_eq!(decoded.response_key.len(), PRIVATE_RUNTIME_KEY_BYTES);
        assert_eq!(decoded.envelope_bytes as usize, ENVELOPE_BYTES);
        assert!(
            decoded.attestation.is_empty(),
            "attestation is deferred, not populated"
        );
        // The keys served must be the releasable pair and nothing else.
        assert_ne!(decoded.request_key, decoded.response_key);
        Ok(())
    }

    #[tokio::test]
    async fn bootstrap_over_its_empty_cap_is_refused_uniformly() {
        // BootstrapRequest is empty on the wire, so any nonzero-length
        // message exceeds its cap and must be refused before it is parsed.
        let (mut adapter, _state) = fixture();
        let response = adapter.bootstrap(encoded_frame(vec![0u8; 8])).await;

        assert_uniform_status(response.headers());
        assert!(response.into_body().is_end_stream());
    }

    /// Pure classification, independent of the wire: the epoch comparison is
    /// on public data, so an ordinary `==` decides it.
    #[test]
    fn a_request_under_a_retired_epoch_is_distinguishable() {
        const CURRENT_EPOCH: u64 = 7;

        let outcome = classify_request_epoch(CURRENT_EPOCH, CURRENT_EPOCH - 1);
        assert_eq!(outcome, Some(PrivateQueryOutcome::StaleKeyEpoch));
        assert_eq!(classify_request_epoch(CURRENT_EPOCH, CURRENT_EPOCH), None);
    }

    #[tokio::test]
    async fn a_stale_key_epoch_is_refused_before_the_handler_and_stays_distinguishable() {
        let (mut adapter, state) = fixture();

        let response = adapter
            .query_page(request_with_epoch(&[1, 2, 3, 4], FIXTURE_KEY_EPOCH + 1))
            .await;

        assert!(status_is_failure(response.headers()));
        assert_ne!(
            response.headers().get(Status::GRPC_STATUS),
            Some(&http::HeaderValue::from_static("14")),
            "a stale key epoch must not collapse into the uniform refusal code"
        );
        assert_eq!(
            state.calls.load(Ordering::SeqCst),
            0,
            "the handler must not be invoked before the epoch check"
        );
        assert!(response.into_body().is_end_stream());
    }

    #[tokio::test]
    async fn a_matching_key_epoch_reaches_the_handler() {
        let (mut adapter, state) = fixture();

        let response = adapter
            .query_page(request_with_epoch(&[1, 2, 3, 4], FIXTURE_KEY_EPOCH))
            .await;

        assert!(!status_is_failure(response.headers()));
        assert_eq!(state.calls.load(Ordering::SeqCst), 1);
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
        let codec =
            PrivateResponseCodec::<MockPendingResponse, ENVELOPE_BYTES>::new(FIXTURE_KEY_EPOCH);
        let encoder =
            PrivateResponseEncoder::<MockPendingResponse, ENVELOPE_BYTES>::new(FIXTURE_KEY_EPOCH);

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
