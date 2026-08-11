//! Lazy Tonic encoding for one listener-free private-query response.

use std::{
    future::{ready, Ready},
    marker::PhantomData,
    pin::Pin,
    sync::Arc,
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

use super::{
    release_schedule::ReleaseSchedule, PendingQueryPage, PrivateServiceAdapter,
    ValidatedFixedEnvelope,
};
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

/// gRPC status code for the stale-key-epoch refusal (`Code::FailedPrecondition`).
const STALE_KEY_EPOCH_GRPC_STATUS: &str = "9";

/// Marks a `Status` as the stale-key-epoch outcome, carried through its error
/// source rather than through its code or message text.
///
/// [`coarsen_initial_status`] keys its one exemption off this type rather
/// than off re-parsing the serialized `grpc-status`/`grpc-message` headers.
/// The marker never reaches the wire -- `Status::source` is not part of
/// `to_header_map` -- so any future `Status::failed_precondition` with this
/// same code and message, from this file or a dependency, would not also
/// carry this marker and would still be coarsened uniformly.
#[derive(Debug)]
struct StaleKeyEpochMarker;

impl std::fmt::Display for StaleKeyEpochMarker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("stale key epoch")
    }
}

impl std::error::Error for StaleKeyEpochMarker {}

fn status_for_query_outcome(outcome: PrivateQueryOutcome) -> Status {
    match outcome {
        PrivateQueryOutcome::StaleKeyEpoch => {
            let mut status = Status::failed_precondition(STALE_KEY_EPOCH_GRPC_MESSAGE);
            status.set_source(std::sync::Arc::new(StaleKeyEpochMarker));
            status
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

/// Answers a bootstrap request with the material precomputed at construction.
///
/// `BootstrapRequest` is empty on the wire and the answer is fixed for the
/// runtime's process lifetime, so there is no work to do here beyond handing
/// back a clone; the cap on the request itself is enforced by the codec's
/// `max_decoding_message_size` before this service is ever called. Holding a
/// borrow of the finished response, rather than of the runtime's session
/// material, is what lets this route be answered without touching the
/// single-admission lock -- see [`PrivateSessionBootstrap`].
struct RespondBootstrap<'a> {
    response: &'a private_proto::BootstrapResponse,
}

impl UnaryService<private_proto::BootstrapRequest> for RespondBootstrap<'_> {
    type Response = private_proto::BootstrapResponse;
    type Future = Ready<Result<Response<Self::Response>, Status>>;

    fn call(&mut self, _request: Request<private_proto::BootstrapRequest>) -> Self::Future {
        ready(Ok(Response::new(self.response.clone())))
    }
}

/// The finished bootstrap answer, built once and served without any lock.
///
/// A named wrapper rather than a bare `private_proto::BootstrapResponse` for
/// two reasons. First, prost derives `Debug` on generated messages, and the
/// derived one prints both released keys byte for byte; `SessionBootstrap`
/// redacts its own `Debug`, and that redaction must survive the reshaping into
/// wire form. Second, the type is the place to state why this material is held
/// outside the handler mutex at all: the bootstrap route is cheap,
/// unauthenticated, and exempt from the uniform-shape discipline, so if
/// answering it required the single-admission lock its latency would report
/// whether a query round is in flight -- exactly the occupancy signal
/// `poll_ready` refuses to leak.
pub(super) struct PrivateSessionBootstrap {
    response: private_proto::BootstrapResponse,
}

impl PrivateSessionBootstrap {
    /// Encodes bootstrap material as the wire response, a named method rather
    /// than a `From`/`TryFrom` impl per this crate's boundary-conversion
    /// convention. `envelope_bytes` is supplied by the caller (derived from the
    /// listener's const generic `N`) rather than read off `bootstrap`, since
    /// `SessionBootstrap` deliberately does not carry it: there is exactly one
    /// source of that number and no second copy that could disagree with it.
    pub(super) fn from_session(bootstrap: &SessionBootstrap, envelope_bytes: usize) -> Self {
        Self {
            response: private_proto::BootstrapResponse {
                key_epoch: bootstrap.key_epoch,
                request_key: bootstrap.keys.request_key.to_vec(),
                response_key: bootstrap.keys.response_key.to_vec(),
                profile_label: bootstrap.profile_label.to_owned(),
                profile_id: bootstrap.profile_id.to_vec(),
                envelope_bytes: u32::try_from(envelope_bytes).unwrap_or(u32::MAX),
                // Reserved for a future TDX quote; present and empty in this release.
                attestation: Vec::new(),
            },
        }
    }

    /// Decodes and answers a bootstrap request under its own cap.
    ///
    /// `BootstrapRequest` is empty on the wire, so its cap is
    /// `fixed_envelope_wire_size(0)` — independent of `QueryPage`'s cap, which
    /// is keyed to the application envelope size `N`. Sharing one cap across
    /// both routes would let the larger of the two set the limit for both.
    ///
    /// Takes `&self`, not `&mut self`: answering this route must not need the
    /// handler mutex, or its latency becomes an occupancy probe.
    pub(super) async fn answer<B>(&self, request: http::Request<B>) -> http::Response<TonicBody>
    where
        B: HttpBody + Send + 'static,
        B::Error: Into<StdError> + Send,
    {
        let grpc = Grpc::new(tonic_prost::ProstCodec::<
            private_proto::BootstrapResponse,
            private_proto::BootstrapRequest,
        >::default())
        .max_decoding_message_size(fixed_envelope_wire_size(BOOTSTRAP_REQUEST_BYTES));
        // The classification is discarded here rather than acted on: bootstrap
        // is the surface's one deliberate exemption from the query route's
        // shape and schedule discipline. Its answer is identical for every
        // caller, takes no client input, and is served without the admission
        // lock, so there is neither a round to equalise nor a completion time
        // that could report anything about a query.
        let (response, _) = capped_unary_call(
            grpc,
            RespondBootstrap {
                response: &self.response,
            },
            request,
        )
        .await;
        response
    }
}

impl std::fmt::Debug for PrivateSessionBootstrap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PrivateSessionBootstrap { ..REDACTED.. }")
    }
}

/// What one capped unary call produced, decided before the coarsener clears
/// the extension the decision is read from.
///
/// Returned alongside the response so a caller can act on the classification
/// without re-deriving it from the serialized headers the coarsener writes.
/// Re-reading those bytes would turn the structural stale-key-epoch marker
/// back into the header-string match it was deliberately replaced with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RouteOutcome {
    /// A response the caller will encode and write.
    Answered,
    /// The one refusal this surface keeps deliberately distinguishable.
    StaleKeyEpoch,
    /// Every other failure, already collapsed to the uniform refusal.
    Refused,
}

/// Drives one capped decode through Tonic, then rewrites the result to the
/// private surface's uniform response shape. Shared by every route so the
/// two routes' framing cannot drift apart even though each brings its own
/// codec, cap, and unary service.
async fn capped_unary_call<C, S, B>(
    mut grpc: Grpc<C>,
    service: S,
    request: http::Request<B>,
) -> (http::Response<TonicBody>, RouteOutcome)
where
    C: Codec,
    S: UnaryService<C::Decode, Response = C::Encode>,
    B: HttpBody + Send + 'static,
    B::Error: Into<StdError> + Send,
{
    let mut response = grpc.unary(service, request).await;
    let outcome = classify_route_outcome(&response);
    coarsen_initial_status(&mut response, outcome);
    let (parts, body) = response.into_parts();
    (
        http::Response::from_parts(parts, TonicBody::new(UniformStatusBody::new(body))),
        outcome,
    )
}

/// Listener-free entry point that returns Tonic's lazily encoded response body.
pub(super) struct PrivateTonicBodyAdapter<H, const N: usize> {
    adapter: PrivateServiceAdapter<H, N>,
    current_key_epoch: u64,
    /// Shared with the listener's unroutable-request arm, so a probe of an
    /// unknown route cannot be told from a refused query by how long it took.
    release_schedule: Arc<ReleaseSchedule>,
}

impl<H, const N: usize> PrivateTonicBodyAdapter<H, N>
where
    H: FixedEnvelopeRuntime<N>,
    H::PendingResponse: Send + 'static,
{
    /// `current_key_epoch` is captured once at construction rather than
    /// re-derived per request: it is fixed for a runtime's process lifetime,
    /// and it is the one live epoch this route checks every request's envelope
    /// against.
    ///
    /// Only the epoch is held here, not the whole `SessionBootstrap`: the keys
    /// belong to the lock-free bootstrap route ([`PrivateSessionBootstrap`]),
    /// and this type has no use for them.
    pub(super) const fn new(
        handler: H,
        current_key_epoch: u64,
        release_schedule: Arc<ReleaseSchedule>,
    ) -> Self {
        Self {
            adapter: PrivateServiceAdapter::new(handler),
            current_key_epoch,
            release_schedule,
        }
    }

    /// Answers one query-page request on the fixed release schedule.
    ///
    /// The caller reaches this method holding the single-admission lock, so
    /// entry here *is* the admission instant and the same fixed reference
    /// point for every protected outcome: an answer, a refusal, an epoch
    /// mismatch, or a round that ran out of bucket. Queue time ahead of
    /// admission is deliberately outside the window -- it is a function of
    /// concurrent load, which ADR 0007's profile already permits observing,
    /// and folding it in would make one client's deadline depend on another
    /// client's query.
    pub(super) async fn query_page<B>(
        &mut self,
        request: http::Request<B>,
    ) -> http::Response<TonicBody>
    where
        B: HttpBody + Send + 'static,
        B::Error: Into<StdError> + Send,
    {
        let window = self.release_schedule.admit();
        let current_key_epoch = self.current_key_epoch;
        let answered = {
            let service = PrivateUnary {
                adapter: &mut self.adapter,
                current_key_epoch,
            };
            let grpc = Grpc::new(PrivateResponseCodec::<H::PendingResponse, N>::new(
                current_key_epoch,
            ))
            .max_decoding_message_size(fixed_envelope_request_wire_size(N));
            window
                .bounded(capped_unary_call(grpc, service, request))
                .await
        };
        let response = match answered {
            // A refusal reached the deadline without asking the runtime for a
            // round; buy the one it skipped so success and semantic failure
            // cost the same work, not merely the same time. The stale-epoch
            // arm is the exception, and stays one: it is refused ahead of the
            // handler on purpose, it is already distinguishable by status, and
            // spending a round on a request under a retired key would neither
            // hide anything nor be owed to anyone.
            Some((response, RouteOutcome::Refused)) => {
                self.adapter.cover_round();
                response
            }
            Some((response, RouteOutcome::Answered | RouteOutcome::StaleKeyEpoch)) => response,
            // Fail closed. Releasing a late answer would publish exactly which
            // rounds were expensive -- the leak the schedule exists to close.
            None => uniform_refusal_response(),
        };
        window.release().await;
        response
    }
}

/// The uniform refusal, framed exactly as a coarsened one.
///
/// Built from the same header constructor and wrapped in the same
/// [`UniformStatusBody`] the coarsener uses, so an overrun is not merely
/// *similar* to the other protected refusals but assembled from the identical
/// parts.
fn uniform_refusal_response() -> http::Response<TonicBody> {
    let mut response =
        http::Response::new(TonicBody::new(UniformStatusBody::new(TonicBody::empty())));
    *response.headers_mut() = uniform_initial_status_headers();
    response
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

/// Rewrites every failure's headers to one of exactly two fixed sets, then
/// clears extensions on both paths.
///
/// The stale-key-epoch outcome is the one response this file deliberately
/// does *not* coarsen to the uniform refusal -- which is exactly why it gets
/// scrubbed the same as everything else: its own fixed minimal header set,
/// and no leftover extensions (including the marker read below) riding out
/// to the caller. Every other failure -- transport errors, handler refusals,
/// cap violations -- still collapses to the one uniform response.
fn coarsen_initial_status(response: &mut http::Response<TonicBody>, outcome: RouteOutcome) {
    match outcome {
        RouteOutcome::Answered => {}
        RouteOutcome::StaleKeyEpoch => {
            *response.headers_mut() = stale_key_epoch_initial_headers();
        }
        RouteOutcome::Refused => *response.headers_mut() = uniform_initial_status_headers(),
    }
    response.extensions_mut().clear();
}

/// Reads the outcome off the response Tonic produced, before any rewriting.
fn classify_route_outcome(response: &http::Response<TonicBody>) -> RouteOutcome {
    if !status_is_failure(response.headers()) {
        RouteOutcome::Answered
    } else if extensions_carry_stale_key_epoch(response.extensions()) {
        RouteOutcome::StaleKeyEpoch
    } else {
        RouteOutcome::Refused
    }
}

/// Recognizes the stale-key-epoch outcome structurally: by the
/// [`StaleKeyEpochMarker`] attached to the `Status` tonic inserted into
/// `response.extensions()`, not by re-deriving the decision from serialized
/// header bytes.
fn extensions_carry_stale_key_epoch(extensions: &http::Extensions) -> bool {
    extensions
        .get::<Status>()
        .and_then(|status| std::error::Error::source(status))
        .is_some_and(|source| source.is::<StaleKeyEpochMarker>())
}

fn uniform_initial_status_headers() -> http::HeaderMap {
    fixed_initial_status_headers("14", UNIFORM_GRPC_MESSAGE)
}

/// The stale-key-epoch outcome's own fixed minimal header set -- parallel to
/// [`uniform_initial_status_headers`], not a preserved copy of whatever
/// `Status::into_http` happened to produce.
fn stale_key_epoch_initial_headers() -> http::HeaderMap {
    fixed_initial_status_headers(STALE_KEY_EPOCH_GRPC_STATUS, STALE_KEY_EPOCH_GRPC_MESSAGE)
}

fn fixed_initial_status_headers(
    grpc_status: &'static str,
    grpc_message: &'static str,
) -> http::HeaderMap {
    let mut headers = http::HeaderMap::new();
    headers.insert(
        Status::GRPC_STATUS,
        http::HeaderValue::from_static(grpc_status),
    );
    headers.insert(
        Status::GRPC_MESSAGE,
        http::HeaderValue::from_static(grpc_message),
    );
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
        future::{poll_fn, Future},
        sync::{
            atomic::{AtomicBool, AtomicUsize, Ordering},
            Arc,
        },
        time::Duration,
    };

    use prost::Message;
    use tokio::time::Instant;

    use super::*;
    use zaino_oram::{ReleasableSessionKeys, PRIVATE_PROFILE_ID_BYTES, PRIVATE_RUNTIME_KEY_BYTES};

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

    /// A stand-in for the compiled profile's digest. Deliberately unrelated to
    /// `"test-profile"`: the two fields are independent values in production
    /// and the fixture must not let a test pass that assumed otherwise.
    const FIXTURE_PROFILE_ID: [u8; PRIVATE_PROFILE_ID_BYTES] = [0x5a; PRIVATE_PROFILE_ID_BYTES];

    fn session_bootstrap_fixture() -> SessionBootstrap {
        SessionBootstrap {
            key_epoch: FIXTURE_KEY_EPOCH,
            keys: ReleasableSessionKeys {
                request_key: [0x11; PRIVATE_RUNTIME_KEY_BYTES],
                response_key: [0x22; PRIVATE_RUNTIME_KEY_BYTES],
            },
            profile_label: "test-profile",
            profile_id: FIXTURE_PROFILE_ID,
        }
    }

    /// The bootstrap half of the surface, built exactly as the listener builds
    /// it. Separate from [`fixture`] because it is separate in production: the
    /// bootstrap route is answered without the handler or its mutex.
    fn bootstrap_fixture() -> PrivateSessionBootstrap {
        PrivateSessionBootstrap::from_session(&session_bootstrap_fixture(), ENVELOPE_BYTES)
    }

    /// Every adapter test below runs on a paused clock, so a zero bucket and a
    /// production one cost the same wall time. A nonzero width is still the
    /// honest fixture: it is what makes `release()` an observable wait the
    /// schedule tests can measure rather than a no-op the others silently
    /// depend on.
    const FIXTURE_BUCKET_MILLIS: u64 = 250;

    fn fixture() -> (
        PrivateTonicBodyAdapter<MockHandler, ENVELOPE_BYTES>,
        MockState,
    ) {
        let (adapter, state, _) = scheduled_fixture();
        (adapter, state)
    }

    /// As [`fixture`], keeping the shared schedule so a test can read its
    /// overrun count.
    fn scheduled_fixture() -> (
        PrivateTonicBodyAdapter<MockHandler, ENVELOPE_BYTES>,
        MockState,
        Arc<ReleaseSchedule>,
    ) {
        let state = MockState::new();
        let handler = MockHandler {
            response: [9, 8, 7, 6],
            state: state.clone(),
        };
        let schedule = Arc::new(ReleaseSchedule::from_timeout_bucket_millis(
            FIXTURE_BUCKET_MILLIS,
        ));
        (
            PrivateTonicBodyAdapter::new(handler, FIXTURE_KEY_EPOCH, Arc::clone(&schedule)),
            state,
            schedule,
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

    fn assert_stale_key_epoch_status(headers: &http::HeaderMap) {
        assert_eq!(
            headers.get(Status::GRPC_STATUS),
            Some(&http::HeaderValue::from_static(STALE_KEY_EPOCH_GRPC_STATUS))
        );
        assert_eq!(
            headers.get(Status::GRPC_MESSAGE),
            Some(&http::HeaderValue::from_static(
                STALE_KEY_EPOCH_GRPC_MESSAGE
            ))
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

    /// start_paused: this body drives a full query round, which now waits out
    /// the release bucket. A paused clock makes that wait free and exact
    /// rather than a real 250 ms sleep in every adapter test.
    #[tokio::test(start_paused = true)]
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

    /// start_paused: drives query rounds that wait out the release bucket.
    #[tokio::test(start_paused = true)]
    async fn admission_remains_closed_until_data_poll_then_reopens(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (mut adapter, state) = fixture();
        let first = adapter.query_page(request(&[1, 2, 3, 4])).await;

        let rejected = adapter.query_page(request(&[4, 3, 2, 1])).await;
        assert_uniform_status(rejected.headers());
        // Two: the refused request's own round, plus the cover round every
        // uniform refusal now buys. Both find admission closed.
        assert_eq!(state.calls.load(Ordering::SeqCst), 3);

        let mut first_body = first.into_body();
        let first_frame = next_frame(&mut first_body)
            .await
            .expect("first response emits one frame")?;
        assert!(first_frame.is_data());

        let admitted = adapter.query_page(request(&[4, 3, 2, 1])).await;
        assert!(!status_is_failure(admitted.headers()));
        assert_eq!(state.calls.load(Ordering::SeqCst), 4);
        drop(admitted);
        Ok(())
    }

    /// start_paused: drives a query round that waits out the release bucket.
    #[tokio::test(start_paused = true)]
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

    /// start_paused: drives a query round that waits out the release bucket.
    #[tokio::test(start_paused = true)]
    async fn dropping_unpolled_body_releases_without_checking_or_borrowing() {
        let (mut adapter, state) = fixture();
        let body = adapter.query_page(request(&[1, 2, 3, 4])).await.into_body();
        assert!(state.busy.load(Ordering::SeqCst));

        drop(body);
        assert!(!state.busy.load(Ordering::SeqCst));
        assert_eq!(state.release_checks.load(Ordering::SeqCst), 0);
        assert_eq!(state.released_borrows.load(Ordering::SeqCst), 0);
    }

    /// start_paused: drives a query round that waits out the release bucket.
    #[tokio::test(start_paused = true)]
    async fn boundary_failure_is_uniform_before_body_creation() {
        let (mut adapter, state) = fixture();
        let response = adapter.query_page(request(&[1, 2, 3])).await;

        assert_uniform_status(response.headers());
        // One round, exactly as an answered request costs: the wrong length is
        // caught at the wire boundary before the handler, and the cover round
        // buys back the round that check skipped.
        assert_eq!(state.calls.load(Ordering::SeqCst), 1);
        // The cover round's bytes are never released -- it is discarded, not
        // answered -- so a refusal still borrows nothing.
        assert_eq!(state.release_checks.load(Ordering::SeqCst), 0);
        assert!(response.into_body().is_end_stream());
    }

    /// start_paused: drives a query round that waits out the release bucket.
    #[tokio::test(start_paused = true)]
    async fn oversized_body_is_rejected_with_the_uniform_refusal() {
        // Sized past `fixed_envelope_request_wire_size(ENVELOPE_BYTES)` (17
        // bytes: 6 for the envelope field plus the 11-byte key_epoch
        // allowance), so this still exercises the transport-level cap
        // rejection rather than `try_from_wire`'s length check -- a body
        // merely one byte over `ENVELOPE_BYTES` now fits comfortably inside
        // the wider cap and reaches the handler's own length validation
        // instead (see `boundary_failure_is_uniform_before_body_creation`).
        let (mut adapter, state) = fixture();
        let oversized = vec![0u8; ENVELOPE_BYTES + 20];
        let response = adapter.query_page(request(&oversized)).await;

        assert_uniform_status(response.headers());
        // The transport cap rejected the body before the service saw it, so
        // the round this refusal performs is entirely the cover round.
        assert_eq!(state.calls.load(Ordering::SeqCst), 1);
        assert!(response.into_body().is_end_stream());
    }

    /// start_paused: drives a query round that waits out the release bucket.
    #[tokio::test(start_paused = true)]
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
            1,
            "an oversized query body must be refused, then covered by exactly one round"
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
        let bootstrap = bootstrap_fixture();
        let response = bootstrap
            .answer(encoded_frame(
                private_proto::BootstrapRequest {}.encode_to_vec(),
            ))
            .await;

        assert!(!status_is_failure(response.headers()));
        let decoded = decode_bootstrap(response).await?;

        // Destructured exhaustively rather than read field by field: this is
        // the test that says what the bootstrap surface publishes, so adding a
        // seventh thing a wallet is handed must not slip by silently. A new
        // field breaks this pattern at compile time and forces a decision here
        // about what it is and why a client may have it.
        let private_proto::BootstrapResponse {
            key_epoch,
            request_key,
            response_key,
            profile_label,
            envelope_bytes,
            attestation,
            profile_id,
        } = decoded;

        assert_eq!(key_epoch, FIXTURE_KEY_EPOCH);
        assert_eq!(request_key.len(), PRIVATE_RUNTIME_KEY_BYTES);
        assert_eq!(response_key.len(), PRIVATE_RUNTIME_KEY_BYTES);
        assert_eq!(envelope_bytes as usize, ENVELOPE_BYTES);
        assert!(
            attestation.is_empty(),
            "attestation is deferred, not populated"
        );
        // The keys served must be the releasable pair and nothing else.
        assert_ne!(request_key, response_key);

        // The authoritative identifier is carried at its exact width and is
        // the runtime's own digest, byte for byte.
        assert_eq!(profile_id.len(), PRIVATE_PROFILE_ID_BYTES);
        assert_eq!(profile_id, FIXTURE_PROFILE_ID);
        // Label and identifier are two distinct published values; neither is
        // an encoding of the other.
        assert_eq!(profile_label, "test-profile");
        assert_ne!(profile_id.as_slice(), profile_label.as_bytes());
        Ok(())
    }

    #[tokio::test]
    async fn bootstrap_over_its_empty_cap_is_refused_uniformly() {
        // BootstrapRequest is empty on the wire, so any nonzero-length
        // message exceeds its cap and must be refused before it is parsed.
        let response = bootstrap_fixture()
            .answer(encoded_frame(vec![0u8; 8]))
            .await;

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

    /// start_paused: drives a query round that waits out the release bucket.
    #[tokio::test(start_paused = true)]
    async fn a_stale_key_epoch_is_refused_before_the_handler_and_stays_distinguishable() {
        let (mut adapter, state) = fixture();

        let response = adapter
            .query_page(request_with_epoch(&[1, 2, 3, 4], FIXTURE_KEY_EPOCH + 1))
            .await;

        assert_stale_key_epoch_status(response.headers());
        assert_eq!(
            state.calls.load(Ordering::SeqCst),
            0,
            "the handler must not be invoked before the epoch check"
        );
        // The marker that distinguishes this response must not ride out as a
        // caller-visible extension once the coarsener has read it.
        assert!(response.extensions().is_empty());
        assert!(response.into_body().is_end_stream());
    }

    /// start_paused: drives a query round that waits out the release bucket.
    #[tokio::test(start_paused = true)]
    async fn a_matching_key_epoch_reaches_the_handler() {
        let (mut adapter, state) = fixture();

        let response = adapter
            .query_page(request_with_epoch(&[1, 2, 3, 4], FIXTURE_KEY_EPOCH))
            .await;

        assert!(!status_is_failure(response.headers()));
        assert_eq!(state.calls.load(Ordering::SeqCst), 1);
    }

    /// The 10-byte-varint case is the entire reason
    /// `KEY_EPOCH_FIELD_WIRE_BYTES` exists: if the cap under-counted it, this
    /// request would be rejected by the transport before ever reaching the
    /// epoch check, and would surface as the uniform refusal instead of the
    /// distinguishable stale-epoch one. Reaching that distinguishable status
    /// is exactly the evidence that decoding succeeded within the cap.
    /// start_paused: drives a query round that waits out the release bucket.
    #[tokio::test(start_paused = true)]
    async fn a_request_epoch_of_u64_max_fits_the_decode_cap() {
        let (mut adapter, state) = fixture();

        let response = adapter
            .query_page(request_with_epoch(&[1, 2, 3, 4], u64::MAX))
            .await;

        assert_stale_key_epoch_status(response.headers());
        assert_eq!(
            state.calls.load(Ordering::SeqCst),
            0,
            "a u64::MAX epoch mismatches the fixture and must not reach the handler"
        );
        assert!(response.into_body().is_end_stream());
    }

    /// start_paused: drives a query round that waits out the release bucket.
    #[tokio::test(start_paused = true)]
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
        // A request body that failed mid-read is a protected refusal like any
        // other, so it pays the same one round.
        assert_eq!(state.calls.load(Ordering::SeqCst), 1);
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

    /// A request body that cannot finish inside the release bucket.
    ///
    /// Built from a `Sleep` rather than a counter so it stays pending on a
    /// paused clock exactly until the runtime advances past the deadline --
    /// the overrun is produced by the schedule's own timer firing first, not
    /// by a wall-clock race between two sleeps.
    struct SlowBody {
        never_before_the_deadline: Pin<Box<tokio::time::Sleep>>,
    }

    impl SlowBody {
        fn longer_than_the_bucket() -> Self {
            Self {
                never_before_the_deadline: Box::pin(tokio::time::sleep(Duration::from_millis(
                    FIXTURE_BUCKET_MILLIS * 4,
                ))),
            }
        }
    }

    impl HttpBody for SlowBody {
        type Data = Bytes;
        type Error = Status;

        fn poll_frame(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
            self.never_before_the_deadline
                .as_mut()
                .poll(context)
                .map(|()| None)
        }
    }

    /// One outbound frame reduced to what a network observer can see of it.
    #[derive(Debug, PartialEq, Eq)]
    enum ObservedFrame {
        Data(Vec<u8>),
        Trailers(Vec<(String, Vec<u8>)>),
    }

    /// One complete response as it appears on the wire: initial headers, then
    /// every frame in order.
    ///
    /// Compared whole rather than field by field, because "indistinguishable"
    /// is a claim about the entire observation and an assertion that checked
    /// only the status would pass for two responses an observer could still
    /// tell apart by frame count or trailer set.
    #[derive(Debug, PartialEq, Eq)]
    struct ObservedResponse {
        headers: Vec<(String, Vec<u8>)>,
        frames: Vec<ObservedFrame>,
    }

    fn header_pairs(headers: &http::HeaderMap) -> Vec<(String, Vec<u8>)> {
        let mut pairs: Vec<(String, Vec<u8>)> = headers
            .iter()
            .map(|(name, value)| (name.as_str().to_owned(), value.as_bytes().to_vec()))
            .collect();
        pairs.sort();
        pairs
    }

    async fn observe(response: http::Response<TonicBody>) -> Result<ObservedResponse, Status> {
        let headers = header_pairs(response.headers());
        let mut body = response.into_body();
        let mut frames = Vec::new();
        while let Some(frame) = next_frame(&mut body).await {
            frames.push(match frame?.into_data() {
                Ok(data) => ObservedFrame::Data(data.to_vec()),
                Err(other) => ObservedFrame::Trailers(header_pairs(
                    other
                        .trailers_ref()
                        .expect("a frame that is not data carries trailers"),
                )),
            });
        }
        Ok(ObservedResponse { headers, frames })
    }

    /// The schedule's whole claim, at the adapter: when the response is
    /// written does not depend on which protected outcome produced it.
    ///
    /// start_paused: the assertion is on release *instants*. A paused clock
    /// advances only to the next timer with every task idle, so `elapsed()`
    /// below reports the schedule's arithmetic exactly rather than a
    /// wall-clock sample that would need a tolerance and would still be flaky.
    #[tokio::test(start_paused = true)]
    async fn every_protected_outcome_is_released_on_the_same_deadline() {
        let bucket = Duration::from_millis(FIXTURE_BUCKET_MILLIS);
        let cases: [(&str, http::Request<OneFrameBody>); 3] = [
            ("an answered query", request(&[1, 2, 3, 4])),
            ("a wrong-length envelope", request(&[1, 2, 3])),
            (
                "a body over the decode cap",
                request(&[0; ENVELOPE_BYTES + 20]),
            ),
        ];

        for (case, request) in cases {
            let (mut adapter, _) = fixture();
            let started = Instant::now();
            let response = adapter.query_page(request).await;
            assert_eq!(
                started.elapsed(),
                bucket,
                "{case} was not released on the bucket"
            );
            drop(response);
        }
    }

    /// The one deliberately distinguishable outcome must not become *more*
    /// distinguishable: it keeps its own status and it keeps everyone else's
    /// release instant.
    ///
    /// start_paused: asserts on a release instant; see the test above.
    #[tokio::test(start_paused = true)]
    async fn a_stale_key_epoch_is_distinguishable_by_status_and_by_nothing_else() {
        let (mut adapter, state) = fixture();
        let started = Instant::now();

        let response = adapter
            .query_page(request_with_epoch(&[1, 2, 3, 4], FIXTURE_KEY_EPOCH + 1))
            .await;

        assert_stale_key_epoch_status(response.headers());
        assert_eq!(
            started.elapsed(),
            Duration::from_millis(FIXTURE_BUCKET_MILLIS)
        );
        assert_eq!(
            state.calls.load(Ordering::SeqCst),
            0,
            "a request under a retired key is still refused ahead of the handler"
        );
    }

    /// Work that cannot fit the bucket is cancelled and answered with the
    /// uniform refusal, at the deadline rather than after it. Releasing late
    /// instead would publish exactly which rounds were expensive.
    ///
    /// start_paused: the overrun is produced by the schedule's timer firing
    /// before the body's, which a paused clock makes deterministic.
    #[tokio::test(start_paused = true)]
    async fn an_overrunning_round_fails_closed_at_the_deadline() {
        let (mut adapter, state, schedule) = scheduled_fixture();
        let started = Instant::now();

        let response = adapter
            .query_page(http::Request::new(SlowBody::longer_than_the_bucket()))
            .await;

        assert_uniform_status(response.headers());
        assert_eq!(
            started.elapsed(),
            Duration::from_millis(FIXTURE_BUCKET_MILLIS)
        );
        assert_eq!(schedule.overruns(), 1, "an overrun must be countable");
        assert_eq!(
            state.release_checks.load(Ordering::SeqCst),
            0,
            "a cancelled round must not have borrowed its response bytes"
        );
        assert!(response.into_body().is_end_stream());
    }

    /// Status equality is not enough: two refusals an observer can separate by
    /// frame count or trailer set are two refusals. This compares the whole
    /// observation for the three ways a protected request can be refused.
    ///
    /// start_paused: each case waits out a release bucket.
    #[tokio::test(start_paused = true)]
    async fn every_uniform_refusal_is_header_and_frame_identical(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (mut adapter, _) = fixture();
        let wrong_length = observe(adapter.query_page(request(&[1, 2, 3])).await).await?;
        let (mut adapter, _) = fixture();
        let over_cap =
            observe(adapter.query_page(request(&[0; ENVELOPE_BYTES + 20])).await).await?;
        let (mut adapter, _) = fixture();
        let overrun = observe(
            adapter
                .query_page(http::Request::new(SlowBody::longer_than_the_bucket()))
                .await,
        )
        .await?;

        assert_eq!(wrong_length, over_cap);
        assert_eq!(wrong_length, overrun);

        // Not vacuous: an answered query and the stale-epoch refusal are both
        // observably different from the uniform one, so the equalities above
        // are saying something about the refusals rather than about a
        // comparison that cannot fail.
        let (mut adapter, _) = fixture();
        let answered = observe(adapter.query_page(request(&[1, 2, 3, 4])).await).await?;
        let (mut adapter, _) = fixture();
        let stale = observe(
            adapter
                .query_page(request_with_epoch(&[1, 2, 3, 4], FIXTURE_KEY_EPOCH + 1))
                .await,
        )
        .await?;
        assert_ne!(answered, wrong_length);
        assert_ne!(stale, wrong_length);
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
