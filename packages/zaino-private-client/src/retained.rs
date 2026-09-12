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
use tokio::{net::TcpStream, task::JoinHandle};
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
}

impl RetainedClientConfig {
    pub fn new(
        endpoint: SocketAddr,
        expected_network: BootstrapNetwork,
        policy: VerifierOwnedEvidencePolicy,
        verifier: LocalQuoteVerifier,
        connect_timeout: Duration,
        rpc_timeout: Duration,
    ) -> Result<Self, RetainedClientError> {
        if connect_timeout.is_zero() || rpc_timeout.is_zero() {
            return Err(RetainedClientError::Configuration);
        }
        Ok(Self {
            endpoint,
            expected_network,
            policy,
            verifier,
            connect_timeout,
            rpc_timeout,
        })
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
}

impl fmt::Display for RetainedClientError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("retained private connection refused")
    }
}
impl std::error::Error for RetainedClientError {}

/// Admitted first-page client. The channel and codec never leave this owner.
pub struct RetainedPrivateClient {
    grpc:
        private_proto::private_compact_tx_streamer_client::PrivateCompactTxStreamerClient<Channel>,
    codec: Option<MainnetClientSession>,
    socket_control: Arc<std::net::TcpStream>,
    rpc_timeout: Duration,
    key_epoch: u64,
    _evidence: private_proto::EvidenceResponse,
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
        let (channel, spki, socket_control) =
            connect_retained_tls(config.endpoint, config.connect_timeout).await?;
        let pending = PendingConnection {
            channel,
            spki,
            socket_control: Some(socket_control),
        };
        let challenge = fresh_challenge()?;
        let evidence = timeout_rpc(
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
        let verifier_budget = config
            .verifier
            .timeout()
            .checked_add(Duration::from_secs(2))
            .ok_or(RetainedClientError::Configuration)?;
        let verifier_task = AbortOnDrop::new(tokio::task::spawn_blocking(move || {
            config.verifier.verify(&parsed)
        }));
        let receipt = tokio::time::timeout(verifier_budget, verifier_task.join())
            .await
            .map_err(|_| RetainedClientError::Cancelled)??
            .map_err(RetainedClientError::Evidence)?;
        let mut verified = VerifiedConnection {
            pending,
            evidence,
            receipt,
        };
        let bootstrap = timeout_rpc(
            config.rpc_timeout,
            verified
                .client(MAX_BOOTSTRAP_MESSAGE_BYTES)
                .bootstrap_session(Request::new(private_proto::BootstrapRequest {})),
        )
        .await?
        .into_inner();
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
        Ok(Self {
            grpc: verified.client(MAX_QUERY_MESSAGE_BYTES),
            codec: Some(codec),
            socket_control: verified
                .pending
                .socket_control
                .take()
                .ok_or(RetainedClientError::Transport)?,
            rpc_timeout: config.rpc_timeout,
            key_epoch,
            _evidence: verified.evidence,
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
        let codec = guard
            .client
            .codec
            .as_ref()
            .ok_or(RetainedClientError::Rpc)?;
        let envelope = codec
            .seal_standard_address_query(address, minimum_height)
            .map_err(|_| RetainedClientError::Codec)?;
        let response = timeout_rpc(
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

async fn timeout_rpc<T>(
    duration: Duration,
    rpc: impl Future<Output = Result<tonic::Response<T>, tonic::Status>>,
) -> Result<tonic::Response<T>, RetainedClientError> {
    tokio::time::timeout(duration, rpc)
        .await
        .map_err(|_| RetainedClientError::Rpc)?
        .map_err(|_| RetainedClientError::Rpc)
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

async fn connect_retained_tls(
    endpoint: SocketAddr,
    timeout: Duration,
) -> Result<(Channel, [u8; 32], Arc<std::net::TcpStream>), RetainedClientError> {
    tokio::time::timeout(timeout, connect_retained_tls_inner(endpoint))
        .await
        .map_err(|_| RetainedClientError::Connect)?
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
    use tokio::net::TcpListener;
    use tokio_rustls::client::TlsStream;
    use tokio_rustls::TlsAcceptor;

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
