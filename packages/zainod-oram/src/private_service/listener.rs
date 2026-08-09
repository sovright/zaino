//! Bound gRPC endpoint for the private-query surface.
//!
//! The runtime behind this listener admits exactly one round at a time: its
//! handler is `&mut`, and the compiled profile's concurrency policy is a
//! single-worker FIFO. The mutex below is that policy, not an implementation
//! detail to be relaxed later. Serving two rounds concurrently would let the
//! observable completion order depend on which address was queried.
//!
//! Every route other than the one private method answers with the same status
//! as a failed query, so probing the surface reveals no more than calling it.

use std::{
    convert::Infallible,
    fmt,
    future::Future,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::{TcpListener, TcpStream},
    sync::{Mutex, OwnedSemaphorePermit, Semaphore},
};
use tonic::{
    body::Body as TonicBody,
    codegen::{http, Service},
    server::NamedService,
    transport::server::{Connected, Server},
};

use zaino_oram::{FixedEnvelopeRuntime, SessionBootstrap};

use super::tonic_body::PrivateTonicBodyAdapter;
use crate::private_proto;

/// The two methods this surface answers.
const QUERY_PAGE_ROUTE: &str = "/zaino.private.v1.PrivateCompactTxStreamer/QueryPage";
const BOOTSTRAP_ROUTE: &str = "/zaino.private.v1.PrivateCompactTxStreamer/BootstrapSession";
const MAX_CONCURRENT_CONNECTIONS: usize = 32;
const MAX_CONCURRENT_REQUESTS_PER_CONNECTION: usize = 1;

/// One private-query endpoint bound to a local address.
///
/// Binding is separate from serving so a caller can learn the assigned port
/// before any request is accepted, and so a bind failure is reported as such
/// rather than surfacing inside the serve loop.
pub(crate) struct PrivateQueryListener {
    listener: TcpListener,
    local_addr: SocketAddr,
}

impl PrivateQueryListener {
    pub(crate) async fn bind(address: SocketAddr) -> std::io::Result<Self> {
        let listener = TcpListener::bind(address).await?;
        let local_addr = listener.local_addr()?;
        Ok(Self {
            listener,
            local_addr,
        })
    }

    pub(crate) const fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Serves the private surface until `shutdown` resolves.
    ///
    /// `session_bootstrap` is captured once here rather than re-derived per
    /// request: it is fixed for `handler`'s process lifetime, and it is also
    /// the one live epoch the query-page route checks every request against.
    pub(crate) async fn serve<H, const N: usize>(
        self,
        handler: H,
        session_bootstrap: SessionBootstrap,
        shutdown: impl Future<Output = ()>,
    ) -> Result<(), tonic::transport::Error>
    where
        H: FixedEnvelopeRuntime<N> + Send + 'static,
        H::PendingResponse: Send + 'static,
    {
        let service = PrivateQueryService::<H, N>::new(handler, session_bootstrap);
        Server::builder()
            .concurrency_limit_per_connection(MAX_CONCURRENT_REQUESTS_PER_CONNECTION)
            .add_service(service)
            .serve_with_incoming_shutdown(
                accepted_connections(self.listener, MAX_CONCURRENT_CONNECTIONS),
                shutdown,
            )
            .await
    }
}

/// Yields accepted connections as the stream Tonic serves from.
///
/// Built here rather than pulled from a stream-adapter crate: one `unfold` over
/// the listener is the whole requirement.
fn accepted_connections(
    listener: TcpListener,
    limit: usize,
) -> impl futures::Stream<Item = std::io::Result<PermitTcpStream>> {
    let permits = Arc::new(Semaphore::new(limit));
    futures::stream::unfold((listener, permits), |(listener, permits)| async move {
        let accepted = match Arc::clone(&permits).acquire_owned().await {
            Ok(permit) => listener.accept().await.map(|(stream, _)| PermitTcpStream {
                stream,
                _permit: permit,
            }),
            Err(error) => Err(std::io::Error::other(error)),
        };
        Some((accepted, (listener, permits)))
    })
}

struct PermitTcpStream {
    stream: TcpStream,
    _permit: OwnedSemaphorePermit,
}

impl Connected for PermitTcpStream {
    type ConnectInfo = <TcpStream as Connected>::ConnectInfo;

    fn connect_info(&self) -> Self::ConnectInfo {
        self.stream.connect_info()
    }
}

impl AsyncRead for PermitTcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(context, buffer)
    }
}

impl AsyncWrite for PermitTcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        Pin::new(&mut self.stream).poll_write(context, buffer)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.stream).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.stream).poll_shutdown(context)
    }
}

impl fmt::Debug for PrivateQueryListener {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateQueryListener")
            .field("local_addr", &self.local_addr)
            .finish()
    }
}

/// Routes the one private method through the single-admission adapter.
struct PrivateQueryService<H, const N: usize> {
    adapter: Arc<Mutex<PrivateTonicBodyAdapter<H, N>>>,
}

impl<H, const N: usize> PrivateQueryService<H, N>
where
    H: FixedEnvelopeRuntime<N>,
    H::PendingResponse: Send + 'static,
{
    fn new(handler: H, session_bootstrap: SessionBootstrap) -> Self {
        Self {
            adapter: Arc::new(Mutex::new(PrivateTonicBodyAdapter::new(
                handler,
                session_bootstrap,
            ))),
        }
    }
}

// Derived `Clone` would demand `H: Clone`; the handler is never cloned, only
// the shared handle to it.
impl<H, const N: usize> Clone for PrivateQueryService<H, N> {
    fn clone(&self) -> Self {
        Self {
            adapter: Arc::clone(&self.adapter),
        }
    }
}

impl<H, const N: usize> NamedService for PrivateQueryService<H, N> {
    const NAME: &'static str = private_proto::private_compact_tx_streamer_server::SERVICE_NAME;
}

impl<H, B, const N: usize> Service<http::Request<B>> for PrivateQueryService<H, N>
where
    H: FixedEnvelopeRuntime<N> + Send + 'static,
    H::PendingResponse: Send + 'static,
    B: http_body::Body<Data = tonic::codegen::Bytes> + Send + 'static,
    B::Error: Into<tonic::codegen::StdError> + Send,
{
    type Response = http::Response<TonicBody>;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        // Readiness must not depend on whether a round is in flight: reporting
        // back-pressure here would time the surface against the runtime's
        // occupancy, which is exactly what the fixed schedule hides.
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: http::Request<B>) -> Self::Future {
        let adapter = Arc::clone(&self.adapter);
        Box::pin(async move {
            match request.uri().path() {
                QUERY_PAGE_ROUTE => {
                    let mut adapter = adapter.lock().await;
                    Ok(adapter.query_page(request).await)
                }
                BOOTSTRAP_ROUTE => {
                    let mut adapter = adapter.lock().await;
                    Ok(adapter.bootstrap(request).await)
                }
                // An unknown route answers exactly as a refused query does,
                // so route probing cannot distinguish them.
                _ => Ok(unavailable_response()),
            }
        })
    }
}

impl<H, const N: usize> fmt::Debug for PrivateQueryService<H, N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PrivateQueryService { ..REDACTED.. }")
    }
}

/// The one failure this surface reports, for every unroutable request.
///
/// An unknown method answers exactly as a rejected query does, so route
/// probing cannot distinguish "no such method" from "query refused".
fn unavailable_response() -> http::Response<TonicBody> {
    tonic::Status::unavailable("private query unavailable").into_http()
}

#[cfg(test)]
mod tests {
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };

    use futures::StreamExt;
    use zaino_oram::{
        MainnetPrivateQueryRuntime, PendingFixedEnvelope, PrivateQueryUnavailable,
        ReleasableSessionKeys,
    };

    use super::*;

    const ENVELOPE_BYTES: usize = 4;
    const RESPONSE: [u8; ENVELOPE_BYTES] = [9, 8, 7, 6];
    const FIXTURE_KEY_EPOCH: u64 = 0;

    fn session_bootstrap_fixture(key_epoch: u64) -> SessionBootstrap {
        SessionBootstrap {
            key_epoch,
            keys: ReleasableSessionKeys {
                request_key: [0x11; zaino_oram::PRIVATE_RUNTIME_KEY_BYTES],
                response_key: [0x22; zaino_oram::PRIVATE_RUNTIME_KEY_BYTES],
            },
            profile_id: "test-profile",
        }
    }

    /// One pending response, generic over its width. Shared by every handler
    /// double in this file's tests: only what each handler answers with
    /// differs, never the admission-release shape around it.
    struct FixedPending<const N: usize> {
        response: [u8; N],
        busy: Arc<AtomicBool>,
    }

    impl<const N: usize> PendingFixedEnvelope<N> for FixedPending<N> {
        fn try_release_bytes(&self) -> Result<&[u8; N], PrivateQueryUnavailable> {
            Ok(&self.response)
        }
    }

    impl<const N: usize> Drop for FixedPending<N> {
        fn drop(&mut self) {
            self.busy.store(false, Ordering::SeqCst);
        }
    }

    struct EchoHandler {
        busy: Arc<AtomicBool>,
    }

    impl FixedEnvelopeRuntime<ENVELOPE_BYTES> for EchoHandler {
        type PendingResponse = FixedPending<ENVELOPE_BYTES>;

        fn query_page(
            &mut self,
            _request: [u8; ENVELOPE_BYTES],
        ) -> Result<Self::PendingResponse, PrivateQueryUnavailable> {
            if self.busy.swap(true, Ordering::SeqCst) {
                return Err(PrivateQueryUnavailable);
            }
            Ok(FixedPending {
                response: RESPONSE,
                busy: Arc::clone(&self.busy),
            })
        }
    }

    fn handler() -> EchoHandler {
        EchoHandler {
            busy: Arc::new(AtomicBool::new(false)),
        }
    }

    #[tokio::test]
    async fn accepted_connections_waits_for_a_connection_permit(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let incoming = accepted_connections(listener, 1);
        tokio::pin!(incoming);

        let first_client = TcpStream::connect(address).await?;
        let first_server = incoming
            .next()
            .await
            .expect("the accept stream remains open")?;
        let second_client = TcpStream::connect(address).await?;

        assert!(futures::poll!(incoming.next()).is_pending());

        drop(first_server);
        let second_server = incoming
            .next()
            .await
            .expect("releasing a permit allows the next accept")?;
        drop((first_client, second_client, second_server));
        Ok(())
    }

    /// Connects and readies one real gRPC client against the bound address.
    ///
    /// Factored out of `query_page_over_the_wire` and `bootstrap_client`:
    /// both routes need the identical connect-then-ready sequence, and only
    /// the codec and route path differ between them.
    async fn connected_private_client(
        address: SocketAddr,
    ) -> Result<tonic::client::Grpc<tonic::transport::Channel>, tonic::Status> {
        let channel = tonic::transport::Endpoint::from_shared(format!("http://{address}"))
            .map_err(|_| tonic::Status::internal("endpoint"))?
            .connect()
            .await
            .map_err(|_| tonic::Status::internal("connect"))?;
        let mut client = tonic::client::Grpc::new(channel);
        client
            .ready()
            .await
            .map_err(|_| tonic::Status::internal("ready"))?;
        Ok(client)
    }

    /// Drives one real gRPC unary call against the bound address.
    ///
    /// Built on `tonic::client::Grpc` rather than a generated stub: the build
    /// deliberately emits server code only, and a server binary has no reason
    /// to ship a client.
    async fn query_page_over_the_wire(
        address: SocketAddr,
        envelope: Vec<u8>,
        key_epoch: u64,
    ) -> Result<private_proto::FixedEnvelope, tonic::Status> {
        let mut client = connected_private_client(address).await?;
        let codec = tonic_prost::ProstCodec::<
            private_proto::FixedEnvelope,
            private_proto::FixedEnvelope,
        >::default();
        client
            .unary(
                tonic::Request::new(private_proto::FixedEnvelope {
                    envelope,
                    key_epoch,
                }),
                http::uri::PathAndQuery::from_static(QUERY_PAGE_ROUTE),
                codec,
            )
            .await
            .map(tonic::Response::into_inner)
    }

    /// Drives one real `BootstrapSession` unary call against the bound
    /// address.
    ///
    /// This is the client half of the route a task review noted had no test
    /// driving it through `PrivateQueryService::call`'s own routing -- every
    /// prior bootstrap test called the adapter's `bootstrap` method directly.
    async fn bootstrap_client(
        address: SocketAddr,
    ) -> Result<private_proto::BootstrapResponse, tonic::Status> {
        let mut client = connected_private_client(address).await?;
        let codec = tonic_prost::ProstCodec::<
            private_proto::BootstrapRequest,
            private_proto::BootstrapResponse,
        >::default();
        client
            .unary(
                tonic::Request::new(private_proto::BootstrapRequest {}),
                http::uri::PathAndQuery::from_static(BOOTSTRAP_ROUTE),
                codec,
            )
            .await
            .map(tonic::Response::into_inner)
    }

    /// multi_thread required: the serve loop and the client run concurrently on
    /// separate tasks and the client blocks on a response the server must send.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_bound_listener_answers_one_exact_query() -> Result<(), Box<dyn std::error::Error>> {
        let listener = PrivateQueryListener::bind("127.0.0.1:0".parse()?).await?;
        let address = listener.local_addr();
        assert_ne!(address.port(), 0);

        let (stop, stopped) = tokio::sync::oneshot::channel();
        let served = tokio::spawn(async move {
            listener
                .serve::<_, ENVELOPE_BYTES>(
                    handler(),
                    session_bootstrap_fixture(FIXTURE_KEY_EPOCH),
                    async {
                        let _ = stopped.await;
                    },
                )
                .await
        });

        let response =
            query_page_over_the_wire(address, vec![1, 2, 3, 4], FIXTURE_KEY_EPOCH).await?;

        assert_eq!(response.envelope, RESPONSE);

        let _ = stop.send(());
        served.await??;
        Ok(())
    }

    /// The real composed runtime -- real XChaCha20 lease, real replay journal
    /// on disk -- must be servable behind this listener, and must answer the
    /// surface's one failure until a serving epoch is pinned.
    ///
    /// This is the seam the binary uses: everything below except the
    /// `refresh` call is exactly what `zainod-oram private serve` performs.
    /// Pinning an epoch needs a live chain subscriber, which no unit test can
    /// stand up, so this covers composition and transport and stops there.
    ///
    /// multi_thread required: the serve loop and the client run concurrently
    /// on separate tasks and the client blocks on a response the server sends.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_real_composed_runtime_serves_the_bound_surface(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let journal = tempfile::TempDir::new()?;
        let deployment = zaino_oram::PrivateRuntimeDeployment {
            service_namespace_id: [0x5a; 16],
            owner_generation: 1,
            replay_journal_root: journal.path().join("replay"),
            projection: zaino_oram::PrivateProjectionShape {
                network: zaino_oram::PrivateNetwork::Mainnet,
                schema_version: 1,
                key_epoch: 1,
                projection_epoch: 1,
                max_seen_outputs: 1,
                max_live_outputs: 1,
                directory_admission: 1,
                event_admission: 4096,
                max_events_per_address: zaino_oram::private_mainnet_store_reads()
                    .map_err(|_| "the compiled profile reports its store reads")?,
                directory_capacity: 8,
                event_capacity: 8192,
            },
        };
        let runtime = zaino_oram::mainnet_private_query_runtime::<zaino_state::ValidatorConnector>(
            &deployment,
            zaino_oram::PrivateRuntimeKeys::ephemeral()
                .map_err(|_| "the OS generator yields four keys")?,
        )
        .map_err(|_| "the mainnet runtime composes over a fresh journal")?;
        let session_bootstrap = runtime.session_bootstrap();
        let key_epoch = session_bootstrap.key_epoch;

        let listener = PrivateQueryListener::bind("127.0.0.1:0".parse()?).await?;
        let address = listener.local_addr();
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let served = tokio::spawn(async move {
            listener
                .serve::<_, { zaino_oram::PRIVATE_MAINNET_ENVELOPE_BYTES }>(
                    runtime,
                    session_bootstrap,
                    async {
                        let _ = stopped.await;
                    },
                )
                .await
        });

        let status = query_page_over_the_wire(
            address,
            vec![0; zaino_oram::PRIVATE_MAINNET_ENVELOPE_BYTES],
            key_epoch,
        )
        .await
        .expect_err("an unrefreshed runtime has no serving epoch to answer from");

        assert_eq!(status.message(), "private query unavailable");

        let _ = stop.send(());
        served.await??;
        Ok(())
    }

    /// A wrong-length envelope must be refused by the adapter, not by Tonic's
    /// decoder, and must reach the client as the surface's one failure.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_wrong_length_envelope_is_refused() -> Result<(), Box<dyn std::error::Error>> {
        let listener = PrivateQueryListener::bind("127.0.0.1:0".parse()?).await?;
        let address = listener.local_addr();

        let (stop, stopped) = tokio::sync::oneshot::channel();
        let served = tokio::spawn(async move {
            listener
                .serve::<_, ENVELOPE_BYTES>(
                    handler(),
                    session_bootstrap_fixture(FIXTURE_KEY_EPOCH),
                    async {
                        let _ = stopped.await;
                    },
                )
                .await
        });

        let status = query_page_over_the_wire(address, vec![1, 2, 3], FIXTURE_KEY_EPOCH)
            .await
            .expect_err("a short envelope is refused");

        assert_eq!(status.message(), "private query unavailable");

        let _ = stop.send(());
        served.await??;
        Ok(())
    }

    /// Test-only symmetric transform standing in for the crate-private AEAD a
    /// production wallet will eventually use to seal and open envelopes.
    ///
    /// Real envelope protection (`EnvelopeProtector`) is crate-internal to
    /// `zaino-oram` by design and unreachable from a listener-level test;
    /// exercising it end to end also needs a live chain subscriber to pin a
    /// serving epoch, which `a_real_composed_runtime_serves_the_bound_surface`
    /// above notes no unit test can stand up. XOR is self-inverse, so this one
    /// function backs both `seal_request` and `open_response` below; it exists
    /// only to prove that the exact key material a real `BootstrapSession`
    /// call releases is the same material a matching handler needs, driven
    /// over the real wire and the real route dispatch -- it makes no claim to
    /// stand in for the production cipher.
    fn keyed_transform<const N: usize>(
        key: &[u8; zaino_oram::PRIVATE_RUNTIME_KEY_BYTES],
        mut bytes: [u8; N],
    ) -> [u8; N] {
        for (byte, key_byte) in bytes.iter_mut().zip(key.iter().cycle()) {
            *byte ^= key_byte;
        }
        bytes
    }

    /// Seals a plaintext query with the bootstrap-released request key.
    ///
    /// Test-local XOR stand-in, not the production AEAD -- see
    /// `keyed_transform`'s doc comment.
    fn seal_request<const N: usize>(
        key: &[u8; zaino_oram::PRIVATE_RUNTIME_KEY_BYTES],
        plaintext: [u8; N],
    ) -> [u8; N] {
        keyed_transform(key, plaintext)
    }

    /// Opens a sealed response with the bootstrap-released response key.
    ///
    /// Test-local XOR stand-in, not the production AEAD -- see
    /// `keyed_transform`'s doc comment.
    fn open_response<const N: usize>(
        key: &[u8; zaino_oram::PRIVATE_RUNTIME_KEY_BYTES],
        ciphertext: [u8; N],
    ) -> [u8; N] {
        keyed_transform(key, ciphertext)
    }

    const fn sample_query() -> [u8; ENVELOPE_BYTES] {
        [0xAA, 0x55, 0x0F, 0xF0]
    }

    /// The page a correctly keyed handler must answer `sample_query()` with.
    ///
    /// Bitwise NOT of the *reversed* query, not a plain elementwise NOT:
    /// reversal makes this transform not commute with `keyed_transform`'s
    /// XOR, so it can no longer cancel out a key error the same way an
    /// elementwise NOT would. It stays deterministic and content-dependent,
    /// and is independently computable by both `KeyedEchoHandler` below and
    /// the test assertion, so a match proves the query that reached the
    /// handler is the exact one `seal_request` sealed -- not a fixed
    /// constant the handler could return regardless of what it decoded.
    const fn expected_page_for(query: [u8; ENVELOPE_BYTES]) -> [u8; ENVELOPE_BYTES] {
        let mut page = query;
        let mut i = 0;
        while i < page.len() {
            page[i] = !query[query.len() - 1 - i];
            i += 1;
        }
        page
    }

    /// A handler double that opens each request with `request_key`, answers
    /// with `expected_page_for` the opened query, and seals that answer with
    /// `response_key` -- standing in for the real runtime's envelope
    /// protector, which cannot be driven end to end without a live chain
    /// subscriber (see `a_real_composed_runtime_serves_the_bound_surface`).
    struct KeyedEchoHandler {
        request_key: [u8; zaino_oram::PRIVATE_RUNTIME_KEY_BYTES],
        response_key: [u8; zaino_oram::PRIVATE_RUNTIME_KEY_BYTES],
        busy: Arc<AtomicBool>,
    }

    impl FixedEnvelopeRuntime<ENVELOPE_BYTES> for KeyedEchoHandler {
        type PendingResponse = FixedPending<ENVELOPE_BYTES>;

        fn query_page(
            &mut self,
            request: [u8; ENVELOPE_BYTES],
        ) -> Result<Self::PendingResponse, PrivateQueryUnavailable> {
            if self.busy.swap(true, Ordering::SeqCst) {
                return Err(PrivateQueryUnavailable);
            }
            let opened_request = keyed_transform(&self.request_key, request);
            let response = keyed_transform(&self.response_key, expected_page_for(opened_request));
            Ok(FixedPending {
                response,
                busy: Arc::clone(&self.busy),
            })
        }
    }

    /// Copies a wire-delivered bootstrap response's keys into fixed-width
    /// arrays a wallet can seal and open with.
    fn releasable_keys_from_wire(
        response: &private_proto::BootstrapResponse,
    ) -> Result<ReleasableSessionKeys, Box<dyn std::error::Error>> {
        let request_key = response
            .request_key
            .clone()
            .try_into()
            .map_err(|_| "wire request_key is not the expected key length")?;
        let response_key = response
            .response_key
            .clone()
            .try_into()
            .map_err(|_| "wire response_key is not the expected key length")?;
        Ok(ReleasableSessionKeys {
            request_key,
            response_key,
        })
    }

    /// Proves the key-establishment leg #101's parity test needs: a wallet
    /// can bootstrap over the real `BootstrapSession` route and receive the
    /// exact key material the server released, driven through
    /// `PrivateQueryService::call`'s own routing, not by calling the
    /// adapter's methods directly. This closes the gap a task review noted:
    /// no prior test drove `BOOTSTRAP_ROUTE`'s match arm through the
    /// service's own dispatch, so a typo in that route string would have
    /// passed every existing test.
    ///
    /// The "seal a query, open the response" half is a test-local XOR
    /// stand-in (`seal_request`/`open_response`, backed by
    /// `keyed_transform`), not the production AEAD -- that cipher is
    /// crate-internal to `zaino-oram` by design and unreachable from a
    /// listener-level test. So this test does *not* by itself close #101:
    /// #101 still needs (a) these client helpers made reachable outside
    /// `#[cfg(test)]`, (b) a public wallet-side seal/open a real
    /// `EnvelopeProtector` will accept, and (c) a refreshed runtime, which
    /// needs a live or mock chain subscriber. What this test does prove is
    /// that the released `request_key`/`response_key` are exactly what the
    /// server holds -- checked directly below, not just inferred from a
    /// round trip.
    ///
    /// multi_thread required: the serve loop and the client run concurrently
    /// on separate tasks and the client blocks on responses the server must
    /// send.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_wallet_bootstraps_then_queries() -> Result<(), Box<dyn std::error::Error>> {
        let listener = PrivateQueryListener::bind("127.0.0.1:0".parse()?).await?;
        let address = listener.local_addr();

        // Position-varying, not a uniform fill: a reversed, rotated, or
        // partially garbled key must be detectable. A uniform `[0x33; 32]`
        // fill would make byte position unobservable and let such an error
        // through undetected.
        let request_key: [u8; zaino_oram::PRIVATE_RUNTIME_KEY_BYTES] =
            std::array::from_fn(|i| 0x33 ^ i as u8);
        let response_key: [u8; zaino_oram::PRIVATE_RUNTIME_KEY_BYTES] =
            std::array::from_fn(|i| 0x44 ^ i as u8);
        let handler = KeyedEchoHandler {
            request_key,
            response_key,
            busy: Arc::new(AtomicBool::new(false)),
        };
        let session_bootstrap = SessionBootstrap {
            key_epoch: FIXTURE_KEY_EPOCH,
            keys: ReleasableSessionKeys {
                request_key,
                response_key,
            },
            profile_id: "test-profile",
        };

        let (stop, stopped) = tokio::sync::oneshot::channel();
        let served = tokio::spawn(async move {
            listener
                .serve::<_, ENVELOPE_BYTES>(handler, session_bootstrap, async {
                    let _ = stopped.await;
                })
                .await
        });

        let bootstrap = bootstrap_client(address).await?;
        assert_eq!(bootstrap.key_epoch, FIXTURE_KEY_EPOCH);
        let released = releasable_keys_from_wire(&bootstrap)?;

        // Direct equality against the exact keys the handler was given,
        // rather than relying on the round trip below to imply it. XOR is
        // commutative, so with a plain elementwise transform the round trip
        // alone would reduce to checking `request_key ^ response_key ==
        // released.request_key ^ released.response_key` -- passing even for
        // a bootstrap response that swapped the two keys, or offset both by
        // the same delta. `expected_page_for`'s reversal breaks that
        // cancellation, but these direct checks are the unambiguous
        // verification and do not depend on that property holding.
        assert_eq!(released.request_key, request_key);
        assert_eq!(released.response_key, response_key);

        let sealed = seal_request(&released.request_key, sample_query());
        let response =
            query_page_over_the_wire(address, sealed.to_vec(), bootstrap.key_epoch).await?;
        let sealed_response: [u8; ENVELOPE_BYTES] = response
            .envelope
            .try_into()
            .map_err(|_| "query response envelope is not the expected width")?;
        let opened = open_response(&released.response_key, sealed_response);

        assert_eq!(opened, expected_page_for(sample_query()));

        let _ = stop.send(());
        served.await??;
        Ok(())
    }

    /// A wallet that keeps querying under a retired key must learn to
    /// re-bootstrap. If this returned the uniform refusal instead, the epoch
    /// would have stopped being cleartext and the client would be stuck
    /// guessing. Driven through the real listener and routing, not the
    /// adapter directly.
    ///
    /// multi_thread required: the serve loop and the client run concurrently
    /// on separate tasks and the client blocks on a response the server must
    /// send.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_retired_epoch_is_actionable_rather_than_opaque(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let listener = PrivateQueryListener::bind("127.0.0.1:0".parse()?).await?;
        let address = listener.local_addr();

        let (stop, stopped) = tokio::sync::oneshot::channel();
        let served = tokio::spawn(async move {
            listener
                .serve::<_, ENVELOPE_BYTES>(
                    handler(),
                    session_bootstrap_fixture(FIXTURE_KEY_EPOCH),
                    async {
                        let _ = stopped.await;
                    },
                )
                .await
        });

        let status = query_page_over_the_wire(address, vec![1, 2, 3, 4], FIXTURE_KEY_EPOCH + 1)
            .await
            .expect_err("a stale key epoch must be refused");

        assert_eq!(status.code(), tonic::Code::FailedPrecondition);
        assert_eq!(status.message(), "stale-key-epoch");

        let _ = stop.send(());
        served.await??;
        Ok(())
    }
}
