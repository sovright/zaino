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

use tokio::{net::TcpListener, sync::Mutex};
use tonic::{
    body::Body as TonicBody,
    codegen::{http, Service},
    server::NamedService,
    transport::server::Server,
};

use zaino_oram::FixedEnvelopeRuntime;

use super::tonic_body::PrivateTonicBodyAdapter;
use crate::private_proto;

/// The one method this surface answers.
const QUERY_PAGE_ROUTE: &str = "/zaino.private.v1.PrivateCompactTxStreamer/QueryPage";

/// One private-query endpoint bound to a local address.
///
/// Binding is separate from serving so a caller can learn the assigned port
/// before any request is accepted, and so a bind failure is reported as such
/// rather than surfacing inside the serve loop.
pub(super) struct PrivateQueryListener {
    listener: TcpListener,
    local_addr: SocketAddr,
}

impl PrivateQueryListener {
    pub(super) async fn bind(address: SocketAddr) -> std::io::Result<Self> {
        let listener = TcpListener::bind(address).await?;
        let local_addr = listener.local_addr()?;
        Ok(Self {
            listener,
            local_addr,
        })
    }

    pub(super) const fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Serves the private surface until `shutdown` resolves.
    pub(super) async fn serve<H, const N: usize>(
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
            .add_service(service)
            .serve_with_incoming_shutdown(accepted_connections(self.listener), shutdown)
            .await
    }
}

/// Yields accepted connections as the stream Tonic serves from.
///
/// Built here rather than pulled from a stream-adapter crate: one `unfold` over
/// the listener is the whole requirement.
fn accepted_connections(
    listener: TcpListener,
) -> impl futures::Stream<Item = std::io::Result<tokio::net::TcpStream>> {
    futures::stream::unfold(listener, |listener| async move {
        let accepted = listener.accept().await.map(|(stream, _)| stream);
        Some((accepted, listener))
    })
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
