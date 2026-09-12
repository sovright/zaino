//! One-attempt retained TLS admission for the research private-query client.

use crate::{
    private_proto, BootstrapNetwork, ClientEvidenceError, LocalQuoteVerifier, ParsedEvidenceV1,
    ValidatedBootstrap, VerifierOwnedEvidencePolicy,
};
use hyper_util::rt::TokioIo;
use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::{verify_tls13_signature, CryptoProvider, WebPkiSupportedAlgorithms},
    pki_types::{CertificateDer, ServerName, UnixTime},
    DigitallySignedStruct, Error as RustlsError, SignatureScheme,
};
use sha2::{Digest, Sha256};
use std::{
    fmt,
    future::Future,
    io,
    net::{Shutdown, SocketAddr},
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{net::TcpStream, task::JoinHandle, time::Instant};
use tokio_rustls::TlsConnector;
use tonic::{
    transport::{Channel, Endpoint},
    Request,
};
use tower::service_fn;
use x509_parser::parse_x509_certificate;
use zaino_oram::{MainnetClientPage, MainnetClientSession, MainnetStandardAddress};

const PRIVATE_DNS_NAME: &str = "private.zaino.invalid";
const MAX_CERTIFICATE_BYTES: usize = 64 * 1024;
const MAX_CHAIN_CERTIFICATES: usize = 8;
const MAX_CHAIN_BYTES: usize = 256 * 1024;
const MAX_EVIDENCE_MESSAGE_BYTES: usize = 20 * 1024;
const MAX_BOOTSTRAP_MESSAGE_BYTES: usize = 4 * 1024;
const MAX_QUERY_MESSAGE_BYTES: usize = zaino_oram::PRIVATE_MAINNET_ENVELOPE_BYTES + 1024;

/// Immutable public inputs to one fresh connection attempt.
pub struct RetainedClientConfig {
    endpoint: SocketAddr,
    expected_network: BootstrapNetwork,
    policy: VerifierOwnedEvidencePolicy,
    verifier: LocalQuoteVerifier,
    connect_timeout: Duration,
    rpc_timeout: Duration,
    maximum_admission_age: Duration,
}

impl RetainedClientConfig {
    pub fn new(
        endpoint: SocketAddr,
        expected_network: BootstrapNetwork,
        policy: VerifierOwnedEvidencePolicy,
        verifier: LocalQuoteVerifier,
        connect_timeout: Duration,
        rpc_timeout: Duration,
        maximum_admission_age: Duration,
    ) -> Result<Self, RetainedClientError> {
        validate_durations(connect_timeout, rpc_timeout, maximum_admission_age)?;
        Ok(Self {
            endpoint,
            expected_network,
            policy,
            verifier,
            connect_timeout,
            rpc_timeout,
            maximum_admission_age,
        })
    }
}

fn validate_durations(
    connect_timeout: Duration,
    rpc_timeout: Duration,
    maximum_admission_age: Duration,
) -> Result<(), RetainedClientError> {
    if connect_timeout.is_zero() || rpc_timeout.is_zero() || maximum_admission_age.is_zero() {
        Err(RetainedClientError::Configuration)
    } else {
        Ok(())
    }
}

impl fmt::Debug for RetainedClientConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RetainedClientConfig")
            .field("endpoint", &self.endpoint)
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
pub enum RetainedClientError {
    Configuration,
    Connect,
    Handshake,
    Certificate,
    Transport,
    Evidence(ClientEvidenceError),
    Bootstrap(crate::BootstrapWireError),
    Codec,
    Rpc,
    Cancelled,
    AdmissionExpired,
}

impl fmt::Display for RetainedClientError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("retained private connection refused")
    }
}
impl std::error::Error for RetainedClientError {}

/// One TLS 1.3 stream whose peer proved possession of its certificate key.
///
/// This type performs no attestation or admission. Every RPC failure,
/// cancellation, or deadline terminally closes the sole underlying socket.
pub struct UnverifiedRetainedTlsConnection {
    channel: Option<Channel>,
    peer_spki_sha256: [u8; 32],
    socket_control: Arc<std::net::TcpStream>,
    deadline: Instant,
}

impl UnverifiedRetainedTlsConnection {
    /// Connects one non-resuming TLS stream before the caller's absolute deadline.
    pub async fn connect(
        endpoint: SocketAddr,
        deadline: Instant,
    ) -> Result<Self, RetainedClientError> {
        ensure_active(deadline)?;
        let (channel, peer_spki_sha256, socket_control) =
            tokio::time::timeout_at(deadline, connect_retained_tls_inner(endpoint))
                .await
                .map_err(|_| RetainedClientError::Cancelled)??;
        let connection = Self {
            channel: Some(channel),
            peer_spki_sha256,
            socket_control,
            deadline,
        };
        ensure_active(deadline)?;
        Ok(connection)
    }

    pub fn peer_spki_sha256(&self) -> [u8; 32] {
        self.peer_spki_sha256
    }

    /// Sends one bounded unary RPC while retaining sole ownership of the stream.
    pub async fn unary<RequestMessage, ResponseMessage>(
        &mut self,
        request: RequestMessage,
        path: http::uri::PathAndQuery,
        encoding_cap: usize,
        decoding_cap: usize,
        deadline: Instant,
    ) -> Result<ResponseMessage, RetainedClientError>
    where
        RequestMessage: prost::Message + Default + Send + Sync + 'static,
        ResponseMessage: prost::Message + Default + Send + Sync + 'static,
    {
        if deadline > self.deadline || Instant::now() >= deadline {
            self.terminate();
            return Err(RetainedClientError::Cancelled);
        }
        let channel = self
            .channel
            .as_ref()
            .ok_or(RetainedClientError::Transport)?
            .clone();
        let mut guard = UnverifiedFailureGuard::new(self);
        let rpc = async move {
            let mut grpc = tonic::client::Grpc::new(channel)
                .max_encoding_message_size(encoding_cap)
                .max_decoding_message_size(decoding_cap);
            grpc.ready().await.map_err(|_| RetainedClientError::Rpc)?;
            let codec = tonic_prost::ProstCodec::default();
            grpc.unary(Request::new(request), path, codec)
                .await
                .map(|response| response.into_inner())
                .map_err(|_| RetainedClientError::Rpc)
        };
        let response = tokio::time::timeout_at(deadline, rpc)
            .await
            .map_err(|_| RetainedClientError::Cancelled)??;
        ensure_active(deadline)?;
        guard.disarm();
        Ok(response)
    }

    fn terminate(&mut self) {
        self.channel.take();
        let _ = self.socket_control.shutdown(Shutdown::Both);
    }
}

impl fmt::Debug for UnverifiedRetainedTlsConnection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("UnverifiedRetainedTlsConnection { ..REDACTED.. }")
    }
}

impl Drop for UnverifiedRetainedTlsConnection {
    fn drop(&mut self) {
        self.terminate();
    }
}

struct UnverifiedFailureGuard<'a> {
    connection: &'a mut UnverifiedRetainedTlsConnection,
    armed: bool,
}

impl<'a> UnverifiedFailureGuard<'a> {
    fn new(connection: &'a mut UnverifiedRetainedTlsConnection) -> Self {
        Self {
            connection,
            armed: true,
        }
    }
    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for UnverifiedFailureGuard<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.connection.terminate();
        }
    }
}

/// Admitted first-page client. The channel and codec never leave this owner.
pub struct RetainedPrivateClient {
    grpc:
        private_proto::private_compact_tx_streamer_client::PrivateCompactTxStreamerClient<Channel>,
    codec: Option<MainnetClientSession>,
    socket_control: Arc<std::net::TcpStream>,
    rpc_timeout: Duration,
    admission_deadline: Instant,
    key_epoch: u64,
    evidence: ParsedEvidenceV1,
    verifier: LocalQuoteVerifier,
    _receipt: crate::LocalQuotePolicyReceipt,
}

impl fmt::Debug for RetainedPrivateClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RetainedPrivateClient { ..REDACTED.. }")
    }
}

impl RetainedPrivateClient {
    /// Performs TLS, evidence verification, and bootstrap on exactly one stream.
    pub async fn connect(config: RetainedClientConfig) -> Result<Self, RetainedClientError> {
        let admission_deadline = Instant::now()
            .checked_add(config.maximum_admission_age)
            .ok_or(RetainedClientError::Configuration)?;
        let (channel, spki, socket_control) =
            connect_retained_tls_until(config.endpoint, admission_deadline, config.connect_timeout)
                .await?;
        let pending = PendingConnection {
            channel,
            spki,
            socket_control: Some(socket_control),
        };
        let challenge = fresh_challenge()?;
        let evidence = timeout_rpc_until(
            admission_deadline,
            config.rpc_timeout,
            pending
                .client(MAX_EVIDENCE_MESSAGE_BYTES)
                .get_evidence(Request::new(private_proto::EvidenceRequest {
                    challenge: challenge.to_vec(),
                })),
        )
        .await?
        .into_inner();
        let parsed =
            ParsedEvidenceV1::try_from_wire(&evidence, challenge, pending.spki, &config.policy)
                .map_err(RetainedClientError::Evidence)?;
        ensure_active(admission_deadline)?;
        let receipt =
            verify_until(config.verifier.clone(), parsed.clone(), admission_deadline).await?;
        ensure_active(admission_deadline)?;
        let mut verified = VerifiedConnection {
            pending,
            evidence,
            receipt,
        };
        let bootstrap = timeout_rpc_until(
            admission_deadline,
            config.rpc_timeout,
            verified
                .client(MAX_BOOTSTRAP_MESSAGE_BYTES)
                .bootstrap_session(Request::new(private_proto::BootstrapRequest {})),
        )
        .await?
        .into_inner();
        ensure_active(admission_deadline)?;
        let validated = ValidatedBootstrap::try_from_wire(
            &bootstrap,
            &verified.evidence,
            config.expected_network,
        )
        .map_err(RetainedClientError::Bootstrap)?;
        let key_epoch = validated.key_epoch();
        let codec = validated
            .into_mainnet_client_session()
            .map_err(|_| RetainedClientError::Codec)?;
        ensure_active(admission_deadline)?;
        Ok(Self {
            grpc: verified.client(MAX_QUERY_MESSAGE_BYTES),
            codec: Some(codec),
            socket_control: verified
                .pending
                .socket_control
                .take()
                .ok_or(RetainedClientError::Transport)?,
            rpc_timeout: config.rpc_timeout,
            admission_deadline,
            key_epoch,
            evidence: parsed,
            verifier: config.verifier,
            _receipt: verified.receipt,
        })
    }

    /// Seals and executes one first-page transparent-address query.
    pub async fn query_first_page(
        &mut self,
        address: MainnetStandardAddress,
        minimum_height: u32,
    ) -> Result<MainnetClientPage, RetainedClientError> {
        let mut guard = QueryFailureGuard::new(self);
        if guard.client.codec.is_none() {
            return Err(RetainedClientError::Rpc);
        }
        ensure_active(guard.client.admission_deadline)?;
        verify_until(
            guard.client.verifier.clone(),
            guard.client.evidence.clone(),
            guard.client.admission_deadline,
        )
        .await?;
        ensure_active(guard.client.admission_deadline)?;
        let codec = guard
            .client
            .codec
            .as_ref()
            .ok_or(RetainedClientError::Rpc)?;
        let envelope = codec
            .seal_standard_address_query(address, minimum_height)
            .map_err(|_| RetainedClientError::Codec)?;
        let response = timeout_rpc_until(
            guard.client.admission_deadline,
            guard.client.rpc_timeout,
            guard
                .client
                .grpc
                .query_page(Request::new(private_proto::FixedEnvelope {
                    envelope: envelope.to_vec(),
                    key_epoch: guard.client.key_epoch,
                })),
        )
        .await?
        .into_inner();
        ensure_active(guard.client.admission_deadline)?;
        if response.key_epoch != guard.client.key_epoch {
            return Err(RetainedClientError::Rpc);
        }
        let response: [u8; zaino_oram::PRIVATE_MAINNET_ENVELOPE_BYTES] = response
            .envelope
            .try_into()
            .map_err(|_| RetainedClientError::Rpc)?;
        let page = codec
            .open_single_page_response(response)
            .map_err(|_| RetainedClientError::Codec)?;
        ensure_active(guard.client.admission_deadline)?;
        guard.disarm();
        Ok(page)
    }

    fn terminate(&self) {
        let _ = self.socket_control.shutdown(Shutdown::Both);
    }

    fn fail_closed(&mut self) {
        self.codec.take();
        self.terminate();
    }
}

impl Drop for RetainedPrivateClient {
    fn drop(&mut self) {
        self.terminate();
    }
}

struct QueryFailureGuard<'a> {
    client: &'a mut RetainedPrivateClient,
    armed: bool,
}

impl<'a> QueryFailureGuard<'a> {
    fn new(client: &'a mut RetainedPrivateClient) -> Self {
        Self {
            client,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for QueryFailureGuard<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.client.fail_closed();
        }
    }
}

struct PendingConnection {
    channel: Channel,
    spki: [u8; 32],
    socket_control: Option<Arc<std::net::TcpStream>>,
}

impl PendingConnection {
    fn client(
        &self,
        cap: usize,
    ) -> private_proto::private_compact_tx_streamer_client::PrivateCompactTxStreamerClient<Channel>
    {
        private_proto::private_compact_tx_streamer_client::PrivateCompactTxStreamerClient::new(
            self.channel.clone(),
        )
        .max_decoding_message_size(cap)
        .max_encoding_message_size(cap)
    }
}

impl Drop for PendingConnection {
    fn drop(&mut self) {
        if let Some(socket) = &self.socket_control {
            let _ = socket.shutdown(Shutdown::Both);
        }
    }
}

struct VerifiedConnection {
    pending: PendingConnection,
    evidence: private_proto::EvidenceResponse,
    receipt: crate::LocalQuotePolicyReceipt,
}
impl VerifiedConnection {
    fn client(
        &self,
        cap: usize,
    ) -> private_proto::private_compact_tx_streamer_client::PrivateCompactTxStreamerClient<Channel>
    {
        self.pending.client(cap)
    }
}

struct AbortOnDrop<T> {
    handle: Option<JoinHandle<T>>,
}
impl<T> AbortOnDrop<T> {
    fn new(handle: JoinHandle<T>) -> Self {
        Self {
            handle: Some(handle),
        }
    }
    async fn join(mut self) -> Result<T, RetainedClientError> {
        let result = self
            .handle
            .as_mut()
            .ok_or(RetainedClientError::Cancelled)?
            .await
            .map_err(|_| RetainedClientError::Cancelled);
        self.handle.take();
        result
    }
}
impl<T> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        if let Some(handle) = &self.handle {
            handle.abort();
        }
    }
}

async fn verify_until(
    verifier: LocalQuoteVerifier,
    evidence: ParsedEvidenceV1,
    admission_deadline: Instant,
) -> Result<crate::LocalQuotePolicyReceipt, RetainedClientError> {
    ensure_active(admission_deadline)?;
    let helper_wait = verifier
        .timeout()
        .checked_add(Duration::from_secs(2))
        .ok_or(RetainedClientError::Configuration)?;
    let helper_deadline = Instant::now()
        .checked_add(helper_wait)
        .ok_or(RetainedClientError::Configuration)?
        .min(admission_deadline);
    let verifier_task = AbortOnDrop::new(tokio::task::spawn_blocking(move || {
        verifier.verify(&evidence)
    }));
    tokio::time::timeout_at(helper_deadline, verifier_task.join())
        .await
        .map_err(|_| {
            if Instant::now() >= admission_deadline {
                RetainedClientError::AdmissionExpired
            } else {
                RetainedClientError::Cancelled
            }
        })??
        .map_err(RetainedClientError::Evidence)
}

async fn timeout_rpc_until<T>(
    deadline: Instant,
    maximum_duration: Duration,
    rpc: impl Future<Output = Result<tonic::Response<T>, tonic::Status>>,
) -> Result<tonic::Response<T>, RetainedClientError> {
    let rpc_deadline = bounded_deadline(deadline, maximum_duration)?;
    tokio::time::timeout_at(rpc_deadline, rpc)
        .await
        .map_err(|_| {
            if Instant::now() >= deadline {
                RetainedClientError::AdmissionExpired
            } else {
                RetainedClientError::Rpc
            }
        })?
        .map_err(|_| RetainedClientError::Rpc)
}

fn bounded_deadline(
    admission_deadline: Instant,
    maximum_duration: Duration,
) -> Result<Instant, RetainedClientError> {
    ensure_active(admission_deadline)?;
    let rpc_deadline = Instant::now()
        .checked_add(maximum_duration)
        .ok_or(RetainedClientError::Configuration)?;
    Ok(rpc_deadline.min(admission_deadline))
}

fn ensure_active(deadline: Instant) -> Result<(), RetainedClientError> {
    if Instant::now() >= deadline {
        Err(RetainedClientError::AdmissionExpired)
    } else {
        Ok(())
    }
}

fn fresh_challenge() -> Result<[u8; 64], RetainedClientError> {
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let mut challenge = [0; 64];
    provider
        .secure_random
        .fill(&mut challenge)
        .map_err(|_| RetainedClientError::Configuration)?;
    Ok(challenge)
}

#[cfg(test)]
async fn connect_retained_tls(
    endpoint: SocketAddr,
    timeout: Duration,
) -> Result<(Channel, [u8; 32], Arc<std::net::TcpStream>), RetainedClientError> {
    tokio::time::timeout(timeout, connect_retained_tls_inner(endpoint))
        .await
        .map_err(|_| RetainedClientError::Connect)?
}

async fn connect_retained_tls_until(
    endpoint: SocketAddr,
    admission_deadline: Instant,
    maximum_duration: Duration,
) -> Result<(Channel, [u8; 32], Arc<std::net::TcpStream>), RetainedClientError> {
    let connect_deadline = bounded_deadline(admission_deadline, maximum_duration)?;
    tokio::time::timeout_at(connect_deadline, connect_retained_tls_inner(endpoint))
        .await
        .map_err(|_| {
            if Instant::now() >= admission_deadline {
                RetainedClientError::AdmissionExpired
            } else {
                RetainedClientError::Connect
            }
        })?
}

async fn connect_retained_tls_inner(
    endpoint: SocketAddr,
) -> Result<(Channel, [u8; 32], Arc<std::net::TcpStream>), RetainedClientError> {
    let tls = client_tls_config()?;
    let tcp = TcpStream::connect(endpoint)
        .await
        .map_err(|_| RetainedClientError::Connect)?;
    let std_tcp = tcp.into_std().map_err(|_| RetainedClientError::Connect)?;
    let control = Arc::new(
        std_tcp
            .try_clone()
            .map_err(|_| RetainedClientError::Connect)?,
    );
    let mut shutdown = SocketShutdownGuard::new(Arc::clone(&control));
    std_tcp
        .set_nonblocking(true)
        .map_err(|_| RetainedClientError::Connect)?;
    let tcp = TcpStream::from_std(std_tcp).map_err(|_| RetainedClientError::Connect)?;
    let name =
        ServerName::try_from(PRIVATE_DNS_NAME).map_err(|_| RetainedClientError::Configuration)?;
    let stream = TlsConnector::from(Arc::new(tls))
        .connect(name, tcp)
        .await
        .map_err(|_| RetainedClientError::Handshake)?;
    let common = &stream.get_ref().1;
    if common.alpn_protocol() != Some(b"h2") {
        return Err(RetainedClientError::Handshake);
    }
    let chain = common
        .peer_certificates()
        .ok_or(RetainedClientError::Certificate)?;
    validate_chain(chain)?;
    let spki = spki_sha256(
        chain
            .first()
            .ok_or(RetainedClientError::Certificate)?
            .as_ref(),
    )?;
    let slot = Arc::new(Mutex::new(Some(TokioIo::new(stream))));
    let channel = Endpoint::from_static("http://private.zaino.invalid")
        .http2_max_header_list_size(16 * 1024)
        .connect_with_connector(service_fn(move |_uri: http::Uri| {
            let slot = Arc::clone(&slot);
            async move { take_retained_stream(&slot) }
        }))
        .await
        .map_err(|_| RetainedClientError::Transport)?;
    shutdown.disarm();
    Ok((channel, spki, control))
}

fn client_tls_config() -> Result<rustls::ClientConfig, RetainedClientError> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let verifier = Arc::new(AttestationBootstrapVerifier::new(&provider));
    let mut tls = rustls::ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| RetainedClientError::Configuration)?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    tls.enable_early_data = false;
    tls.resumption = rustls::client::Resumption::disabled();
    tls.alpn_protocols = vec![b"h2".to_vec()];
    Ok(tls)
}

fn take_retained_stream<T>(slot: &Mutex<Option<T>>) -> io::Result<T> {
    slot.lock()
        .map_err(|_| io::Error::other("retained connector poisoned"))?
        .take()
        .ok_or_else(|| io::Error::other("retained stream already consumed"))
}

struct SocketShutdownGuard {
    socket: Arc<std::net::TcpStream>,
    armed: bool,
}

impl SocketShutdownGuard {
    fn new(socket: Arc<std::net::TcpStream>) -> Self {
        Self {
            socket,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for SocketShutdownGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = self.socket.shutdown(Shutdown::Both);
        }
    }
}

fn validate_chain(chain: &[CertificateDer<'_>]) -> Result<(), RetainedClientError> {
    if chain.is_empty()
        || chain.len() > MAX_CHAIN_CERTIFICATES
        || chain
            .iter()
            .any(|cert| cert.is_empty() || cert.len() > MAX_CERTIFICATE_BYTES)
        || chain.iter().map(|cert| cert.len()).sum::<usize>() > MAX_CHAIN_BYTES
    {
        return Err(RetainedClientError::Certificate);
    }
    for certificate in chain {
        parse_complete_certificate(certificate.as_ref())?;
    }
    Ok(())
}

fn parse_complete_certificate(
    der: &[u8],
) -> Result<x509_parser::certificate::X509Certificate<'_>, RetainedClientError> {
    if der.is_empty() || der.len() > MAX_CERTIFICATE_BYTES {
        return Err(RetainedClientError::Certificate);
    }
    let (rest, certificate) =
        parse_x509_certificate(der).map_err(|_| RetainedClientError::Certificate)?;
    if !rest.is_empty() {
        return Err(RetainedClientError::Certificate);
    }
    Ok(certificate)
}

fn spki_sha256(der: &[u8]) -> Result<[u8; 32], RetainedClientError> {
    let certificate = parse_complete_certificate(der)?;
    Ok(Sha256::digest(certificate.tbs_certificate.subject_pki.raw).into())
}

struct AttestationBootstrapVerifier {
    algorithms: WebPkiSupportedAlgorithms,
}
impl AttestationBootstrapVerifier {
    fn new(provider: &CryptoProvider) -> Self {
        Self {
            algorithms: provider.signature_verification_algorithms,
        }
    }
}
impl fmt::Debug for AttestationBootstrapVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AttestationBootstrapVerifier")
    }
}
impl ServerCertVerifier for AttestationBootstrapVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        let mut total = end_entity.len();
        if end_entity.is_empty()
            || end_entity.len() > MAX_CERTIFICATE_BYTES
            || intermediates.len() + 1 > MAX_CHAIN_CERTIFICATES
        {
            return Err(RustlsError::InvalidCertificate(
                rustls::CertificateError::BadEncoding,
            ));
        }
        require_complete_der(end_entity)?;
        for cert in intermediates {
            total = total.saturating_add(cert.len());
            if cert.is_empty() || cert.len() > MAX_CERTIFICATE_BYTES {
                return Err(RustlsError::InvalidCertificate(
                    rustls::CertificateError::BadEncoding,
                ));
            }
            require_complete_der(cert)?;
        }
        if total > MAX_CHAIN_BYTES {
            return Err(RustlsError::InvalidCertificate(
                rustls::CertificateError::BadEncoding,
            ));
        }
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Err(RustlsError::PeerIncompatible(
            rustls::PeerIncompatible::Tls12NotOffered,
        ))
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        verify_tls13_signature(message, cert, dss, &self.algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

fn require_complete_der(certificate: &CertificateDer<'_>) -> Result<(), RustlsError> {
    let (rest, _) = parse_x509_certificate(certificate.as_ref())
        .map_err(|_| RustlsError::InvalidCertificate(rustls::CertificateError::BadEncoding))?;
    if !rest.is_empty() {
        return Err(RustlsError::InvalidCertificate(
            rustls::CertificateError::BadEncoding,
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::PublicKeyData;
    use rustls::{
        pki_types::{PrivatePkcs8KeyDer, SubjectPublicKeyInfoDer},
        sign::{CertifiedKey, Signer, SigningKey, SingleCertAndKey},
        SignatureAlgorithm,
    };
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::{
        pin::Pin,
        task::{Context, Poll},
    };
    use tdx_boot_spike_protocol::wire::{
        boot_spike_evidence_server::{BootSpikeEvidence, BootSpikeEvidenceServer},
        EvidenceRequest, EvidenceResponse,
    };
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
    use tokio::net::TcpListener;
    use tokio_rustls::client::TlsStream;
    use tokio_rustls::TlsAcceptor;
    use tonic::{Response, Status};

    struct TestTlsIo(tokio_rustls::server::TlsStream<TcpStream>);

    impl tonic::transport::server::Connected for TestTlsIo {
        type ConnectInfo = ();
        fn connect_info(&self) -> Self::ConnectInfo {}
    }

    impl AsyncRead for TestTlsIo {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.0).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for TestTlsIo {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.0).poll_write(cx, buf)
        }
        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.0).poll_flush(cx)
        }
        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.0).poll_shutdown(cx)
        }
    }

    #[test]
    fn admission_age_and_transport_durations_must_be_nonzero() {
        let one = Duration::from_secs(1);
        assert!(validate_durations(one, one, one).is_ok());
        assert!(matches!(
            validate_durations(one, one, Duration::ZERO),
            Err(RetainedClientError::Configuration)
        ));
        assert!(matches!(
            validate_durations(Duration::ZERO, one, one),
            Err(RetainedClientError::Configuration)
        ));
        assert!(matches!(
            validate_durations(one, Duration::ZERO, one),
            Err(RetainedClientError::Configuration)
        ));
    }

    #[tokio::test]
    async fn expired_admission_refuses_before_polling_an_rpc() {
        let polled = Arc::new(AtomicBool::new(false));
        let observed = Arc::clone(&polled);
        let rpc = std::future::poll_fn(move |_| {
            observed.store(true, Ordering::SeqCst);
            std::task::Poll::Ready(Ok(tonic::Response::new(())))
        });
        let result = timeout_rpc_until(Instant::now(), Duration::from_secs(1), rpc).await;
        assert!(matches!(result, Err(RetainedClientError::AdmissionExpired)));
        assert!(!polled.load(Ordering::SeqCst));
    }

    #[test]
    fn complete_der_parser_hashes_only_the_subject_public_key_info(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let certified = rcgen::generate_simple_self_signed(vec![PRIVATE_DNS_NAME.to_string()])?;
        let der = certified.cert.der();
        let expected: [u8; 32] =
            Sha256::digest(certified.signing_key.subject_public_key_info()).into();
        assert_eq!(spki_sha256(der.as_ref())?, expected);
        let mut trailing = der.as_ref().to_vec();
        trailing.push(0);
        assert!(parse_complete_certificate(&trailing).is_err());
        assert!(parse_complete_certificate(&vec![0; MAX_CERTIFICATE_BYTES + 1]).is_err());
        Ok(())
    }

    #[test]
    fn connector_releases_exactly_one_preconnected_stream() -> io::Result<()> {
        let slot = Mutex::new(Some(7_u8));
        assert_eq!(take_retained_stream(&slot)?, 7);
        assert!(take_retained_stream(&slot).is_err());
        Ok(())
    }

    #[tokio::test]
    async fn full_connect_deadline_closes_a_tls_peer_that_never_handshakes(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let peer = tokio::spawn(async move {
            let (socket, _) = listener.accept().await?;
            let mut byte = [0];
            loop {
                match socket.readable().await {
                    Ok(()) => match socket.try_read(&mut byte) {
                        Ok(0) => return Ok::<(), io::Error>(()),
                        Ok(_) => continue,
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                        Err(error) => return Err(error),
                    },
                    Err(error) => return Err(error),
                }
            }
        });
        let result = connect_retained_tls(address, Duration::from_millis(50)).await;
        assert!(matches!(result, Err(RetainedClientError::Connect)));
        tokio::time::timeout(Duration::from_secs(1), peer).await???;
        Ok(())
    }

    #[tokio::test]
    async fn dropping_an_armed_socket_guard_closes_the_peer(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let client = TcpStream::connect(address).await?;
        let (peer, _) = listener.accept().await?;
        let live_socket = client.into_std()?;
        let control = Arc::new(live_socket.try_clone()?);
        drop(SocketShutdownGuard::new(control));
        let mut byte = [0];
        let read = async {
            peer.readable()
                .await
                .and_then(|()| peer.try_read(&mut byte))
        };
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), read).await??,
            0
        );
        drop(live_socket);
        Ok(())
    }

    fn test_server_config(
        certificate: CertificateDer<'static>,
        private_key: Vec<u8>,
        corrupt_signature: Option<Arc<AtomicBool>>,
    ) -> Result<rustls::ServerConfig, Box<dyn std::error::Error>> {
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let signing_key = provider
            .key_provider
            .load_private_key(PrivatePkcs8KeyDer::from(private_key).into())?;
        let signing_key: Arc<dyn SigningKey> = if let Some(called) = corrupt_signature {
            Arc::new(CorruptSigningKey {
                inner: signing_key,
                called,
            })
        } else {
            signing_key
        };
        let certified_key = CertifiedKey::new(vec![certificate], signing_key);
        let mut server = rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(SingleCertAndKey::from(certified_key)));
        server.alpn_protocols = vec![b"h2".to_vec()];
        Ok(server)
    }

    async fn tls_pair(
        server: rustls::ServerConfig,
    ) -> Result<
        (
            Result<TlsStream<TcpStream>, io::Error>,
            JoinHandle<Result<(), io::Error>>,
        ),
        Box<dyn std::error::Error>,
    > {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let acceptor = TlsAcceptor::from(Arc::new(server));
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await?;
            acceptor.accept(socket).await.map(|_| ())
        });
        let socket = TcpStream::connect(address).await?;
        let name = ServerName::try_from(PRIVATE_DNS_NAME)?;
        let client = tokio::time::timeout(
            Duration::from_secs(1),
            TlsConnector::from(Arc::new(client_tls_config()?)).connect(name, socket),
        )
        .await?;
        Ok((client, server))
    }

    #[tokio::test]
    async fn real_tls_handshake_verifies_certificate_possession_and_peer_spki(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let certified = rcgen::generate_simple_self_signed(vec![PRIVATE_DNS_NAME.to_string()])?;
        let expected_spki: [u8; 32] =
            Sha256::digest(certified.signing_key.subject_public_key_info()).into();
        let config = test_server_config(
            certified.cert.der().clone(),
            certified.signing_key.serialize_der(),
            None,
        )?;
        let (client, server) = tls_pair(config).await?;
        let client = client?;
        let peer = client
            .get_ref()
            .1
            .peer_certificates()
            .and_then(|chain| chain.first())
            .ok_or("TLS peer leaf absent")?;
        assert_eq!(spki_sha256(peer.as_ref())?, expected_spki);
        assert_eq!(client.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));
        tokio::time::timeout(Duration::from_secs(1), server).await???;
        Ok(())
    }

    #[tokio::test]
    async fn real_tls_handshake_refuses_corrupted_certificate_verify(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let certificate = rcgen::generate_simple_self_signed(vec![PRIVATE_DNS_NAME.to_string()])?;
        let called = Arc::new(AtomicBool::new(false));
        let config = test_server_config(
            certificate.cert.der().clone(),
            certificate.signing_key.serialize_der(),
            Some(Arc::clone(&called)),
        )?;
        let (client, server) = tls_pair(config).await?;
        assert!(client.is_err());
        assert!(called.load(Ordering::SeqCst));
        let server_result = tokio::time::timeout(Duration::from_secs(1), server).await??;
        assert!(server_result.is_err());
        Ok(())
    }

    #[derive(Clone)]
    struct DelayedEvidenceService {
        delay: Duration,
        requests: Arc<std::sync::atomic::AtomicUsize>,
        cancelled: Arc<AtomicBool>,
    }

    struct CancellationMarker(Arc<AtomicBool>);

    struct ServerTask(JoinHandle<Result<(), tonic::transport::Error>>);

    impl Drop for ServerTask {
        fn drop(&mut self) {
            self.0.abort();
        }
    }

    impl Drop for CancellationMarker {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    #[tonic::async_trait]
    impl BootSpikeEvidence for DelayedEvidenceService {
        async fn get_evidence(
            &self,
            _request: Request<EvidenceRequest>,
        ) -> Result<Response<EvidenceResponse>, Status> {
            self.requests.fetch_add(1, Ordering::SeqCst);
            let _marker = CancellationMarker(Arc::clone(&self.cancelled));
            tokio::time::sleep(self.delay).await;
            Ok(Response::new(EvidenceResponse::default()))
        }
    }

    async fn delayed_evidence_server(
        delay: Duration,
    ) -> Result<
        (
            SocketAddr,
            Arc<std::sync::atomic::AtomicUsize>,
            Arc<AtomicBool>,
            ServerTask,
        ),
        Box<dyn std::error::Error>,
    > {
        let certified = rcgen::generate_simple_self_signed(vec![PRIVATE_DNS_NAME.to_string()])?;
        let config = test_server_config(
            certified.cert.der().clone(),
            certified.signing_key.serialize_der(),
            None,
        )?;
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let incoming = async_stream::stream! {
            let item = match listener.accept().await {
                Ok((socket, _)) => acceptor.accept(socket).await.map(TestTlsIo),
                Err(error) => Err(error),
            };
            yield item;
        };
        let requests = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let cancelled = Arc::new(AtomicBool::new(false));
        let service = DelayedEvidenceService {
            delay,
            requests: Arc::clone(&requests),
            cancelled: Arc::clone(&cancelled),
        };
        let server = tokio::spawn(
            tonic::transport::Server::builder()
                .add_service(BootSpikeEvidenceServer::new(service))
                .serve_with_incoming(incoming),
        );
        Ok((address, requests, cancelled, ServerTask(server)))
    }

    #[tokio::test]
    async fn cancelling_unverified_unary_terminally_closes_the_owned_stream(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (address, requests, cancelled, mut server) =
            delayed_evidence_server(Duration::from_secs(5)).await?;
        let mut connection = UnverifiedRetainedTlsConnection::connect(
            address,
            Instant::now() + Duration::from_secs(2),
        )
        .await?;
        let path = http::uri::PathAndQuery::from_static(
            "/zaino.boot_spike.v1.BootSpikeEvidence/GetEvidence",
        );
        let mut rpc = Box::pin(connection.unary::<EvidenceRequest, EvidenceResponse>(
            EvidenceRequest::default(),
            path.clone(),
            1024,
            1024,
            Instant::now() + Duration::from_secs(1),
        ));
        tokio::time::timeout(Duration::from_secs(1), async {
            while requests.load(Ordering::SeqCst) == 0 {
                tokio::select! {
                    result = &mut rpc => return Err(format!("RPC unexpectedly completed: {result:?}")),
                    () = tokio::task::yield_now() => {}
                }
            }
            Ok::<(), String>(())
        })
        .await??;
        drop(rpc);
        assert!(matches!(
            connection
                .unary::<EvidenceRequest, EvidenceResponse>(
                    EvidenceRequest::default(),
                    path,
                    1024,
                    1024,
                    Instant::now() + Duration::from_millis(100),
                )
                .await,
            Err(RetainedClientError::Transport)
        ));
        tokio::time::timeout(Duration::from_secs(1), async {
            while !cancelled.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        assert_eq!(requests.load(Ordering::SeqCst), 1);
        tokio::time::timeout(Duration::from_secs(1), &mut server.0).await???;
        Ok(())
    }

    #[tokio::test]
    async fn late_unverified_unary_result_is_refused_and_terminal(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (address, requests, cancelled, mut server) =
            delayed_evidence_server(Duration::from_secs(2)).await?;
        let mut connection = UnverifiedRetainedTlsConnection::connect(
            address,
            Instant::now() + Duration::from_secs(2),
        )
        .await?;
        let path = http::uri::PathAndQuery::from_static(
            "/zaino.boot_spike.v1.BootSpikeEvidence/GetEvidence",
        );
        assert!(matches!(
            connection
                .unary::<EvidenceRequest, EvidenceResponse>(
                    EvidenceRequest::default(),
                    path.clone(),
                    1024,
                    1024,
                    Instant::now() + Duration::from_secs(1),
                )
                .await,
            Err(RetainedClientError::Cancelled)
        ));
        assert!(matches!(
            connection
                .unary::<EvidenceRequest, EvidenceResponse>(
                    EvidenceRequest::default(),
                    path,
                    1024,
                    1024,
                    Instant::now() + Duration::from_millis(100),
                )
                .await,
            Err(RetainedClientError::Transport)
        ));
        tokio::time::timeout(Duration::from_secs(1), async {
            while !cancelled.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        assert_eq!(requests.load(Ordering::SeqCst), 1);
        tokio::time::timeout(Duration::from_secs(1), &mut server.0).await???;
        Ok(())
    }

    #[derive(Debug)]
    struct CorruptSigningKey {
        inner: Arc<dyn SigningKey>,
        called: Arc<AtomicBool>,
    }

    impl SigningKey for CorruptSigningKey {
        fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
            let called = Arc::clone(&self.called);
            self.inner
                .choose_scheme(offered)
                .map(|inner| Box::new(CorruptSigner { inner, called }) as Box<dyn Signer>)
        }

        fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
            self.inner.public_key()
        }

        fn algorithm(&self) -> SignatureAlgorithm {
            self.inner.algorithm()
        }
    }

    #[derive(Debug)]
    struct CorruptSigner {
        inner: Box<dyn Signer>,
        called: Arc<AtomicBool>,
    }

    impl Signer for CorruptSigner {
        fn sign(&self, message: &[u8]) -> Result<Vec<u8>, RustlsError> {
            self.called.store(true, Ordering::SeqCst);
            let mut signature = self.inner.sign(message)?;
            let first = signature
                .first_mut()
                .ok_or_else(|| RustlsError::General("empty test signature".into()))?;
            *first ^= 1;
            Ok(signature)
        }

        fn scheme(&self) -> SignatureScheme {
            self.inner.scheme()
        }
    }
}
