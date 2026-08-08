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

use zaino_oram::FixedEnvelopeRuntime;

use super::tonic_body::PrivateTonicBodyAdapter;
use crate::private_proto;

/// The one method this surface answers.
const QUERY_PAGE_ROUTE: &str = "/zaino.private.v1.PrivateCompactTxStreamer/QueryPage";
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
    pub(crate) async fn serve<H, const N: usize>(
        self,
        handler: H,
        shutdown: impl Future<Output = ()>,
    ) -> Result<(), tonic::transport::Error>
    where
        H: FixedEnvelopeRuntime<N> + Send + 'static,
        H::PendingResponse: Send + 'static,
    {
        let service = PrivateQueryService::<H, N>::new(handler);
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
    fn new(handler: H) -> Self {
        Self {
            adapter: Arc::new(Mutex::new(PrivateTonicBodyAdapter::new(handler))),
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
            if request.uri().path() != QUERY_PAGE_ROUTE {
                return Ok(unavailable_response());
            }
            let mut adapter = adapter.lock().await;
            Ok(adapter.query_page(request).await)
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
    use zaino_oram::{PendingFixedEnvelope, PrivateQueryUnavailable};

    use super::*;

    const ENVELOPE_BYTES: usize = 4;
    const RESPONSE: [u8; ENVELOPE_BYTES] = [9, 8, 7, 6];

    struct EchoPending {
        response: [u8; ENVELOPE_BYTES],
        busy: Arc<AtomicBool>,
    }

    impl PendingFixedEnvelope<ENVELOPE_BYTES> for EchoPending {
        fn try_release_bytes(&self) -> Result<&[u8; ENVELOPE_BYTES], PrivateQueryUnavailable> {
            Ok(&self.response)
        }
    }

    impl Drop for EchoPending {
        fn drop(&mut self) {
            self.busy.store(false, Ordering::SeqCst);
        }
    }

    struct EchoHandler {
        busy: Arc<AtomicBool>,
    }

    impl FixedEnvelopeRuntime<ENVELOPE_BYTES> for EchoHandler {
        type PendingResponse = EchoPending;

        fn query_page(
            &mut self,
            _request: [u8; ENVELOPE_BYTES],
        ) -> Result<Self::PendingResponse, PrivateQueryUnavailable> {
            if self.busy.swap(true, Ordering::SeqCst) {
                return Err(PrivateQueryUnavailable);
            }
            Ok(EchoPending {
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

    /// Drives one real gRPC unary call against the bound address.
    ///
    /// Built on `tonic::client::Grpc` rather than a generated stub: the build
    /// deliberately emits server code only, and a server binary has no reason
    /// to ship a client.
    async fn query_page_over_the_wire(
        address: SocketAddr,
        envelope: Vec<u8>,
    ) -> Result<private_proto::FixedEnvelope, tonic::Status> {
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
        let codec = tonic_prost::ProstCodec::<
            private_proto::FixedEnvelope,
            private_proto::FixedEnvelope,
        >::default();
        client
            .unary(
                tonic::Request::new(private_proto::FixedEnvelope { envelope }),
                http::uri::PathAndQuery::from_static(QUERY_PAGE_ROUTE),
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
                .serve::<_, ENVELOPE_BYTES>(handler(), async {
                    let _ = stopped.await;
                })
                .await
        });

        let response = query_page_over_the_wire(address, vec![1, 2, 3, 4]).await?;

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

        let listener = PrivateQueryListener::bind("127.0.0.1:0".parse()?).await?;
        let address = listener.local_addr();
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let served = tokio::spawn(async move {
            listener
                .serve::<_, { zaino_oram::PRIVATE_MAINNET_ENVELOPE_BYTES }>(runtime, async {
                    let _ = stopped.await;
                })
                .await
        });

        let status =
            query_page_over_the_wire(address, vec![0; zaino_oram::PRIVATE_MAINNET_ENVELOPE_BYTES])
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
                .serve::<_, ENVELOPE_BYTES>(handler(), async {
                    let _ = stopped.await;
                })
                .await
        });

        let status = query_page_over_the_wire(address, vec![1, 2, 3])
            .await
            .expect_err("a short envelope is refused");

        assert_eq!(status.message(), "private query unavailable");

        let _ = stop.send(());
        served.await??;
        Ok(())
    }
}
