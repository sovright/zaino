use clap::Parser;
use rcgen::{CertifiedKey, PublicKeyData};
use rustls::pki_types::PrivatePkcs8KeyDer;
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::Read,
    net::{IpAddr, SocketAddr},
    path::Path,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tdx_boot_spike_protocol::{
    report_data,
    wire::{
        boot_spike_evidence_server::{BootSpikeEvidence, BootSpikeEvidenceServer},
        EvidenceRequest, EvidenceResponse,
    },
    Challenge, CHALLENGE_BYTES, LEASE_BYTES, MAX_CCEL_LOG_BYTES, MAX_CCEL_TABLE_BYTES,
    MAX_RESPONSE_BYTES, TRANSCRIPT_VERSION,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::{TcpListener, TcpStream},
    sync::Semaphore,
};
use tokio_rustls::{server::TlsStream, TlsAcceptor};
use tonic::{
    transport::{server::Connected, Server},
    Request, Response, Status,
};
use zaino_tdx_evidence::ConfigFsTsmQuoteProvider;

const CCEL_TABLE: &str = "/sys/firmware/acpi/tables/CCEL";
const CCEL_LOG: &str = "/sys/firmware/acpi/tables/data/CCEL";

#[derive(Parser)]
struct Args {
    #[arg(long)]
    listen: SocketAddr,
    #[arg(long, default_value_t = 10)]
    provider_timeout_seconds: u64,
}

#[derive(Clone)]
struct EvidenceService {
    spki_sha256: [u8; 32],
    boot_lease_id: [u8; LEASE_BYTES],
    provider: Arc<Semaphore>,
    timeout: Duration,
}

struct EvidenceBlobs {
    quote_v4: Vec<u8>,
    ccel_table: Vec<u8>,
    ccel_log: Vec<u8>,
}

struct TlsIo(TlsStream<TcpStream>);

impl Connected for TlsIo {
    type ConnectInfo = ();
    fn connect_info(&self) -> Self::ConnectInfo {}
}

impl AsyncRead for TlsIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl AsyncWrite for TlsIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

#[tonic::async_trait]
impl BootSpikeEvidence for EvidenceService {
    async fn get_evidence(
        &self,
        request: Request<EvidenceRequest>,
    ) -> Result<Response<EvidenceResponse>, Status> {
        let challenge = Challenge::try_from_wire(request.into_inner())
            .map_err(|_| Status::invalid_argument("challenge must be exactly 64 bytes"))?;
        let report_data = report_data(challenge.into_bytes(), self.spki_sha256, self.boot_lease_id);
        let permit = Arc::clone(&self.provider)
            .try_acquire_owned()
            .map_err(|_| Status::resource_exhausted("evidence provider busy"))?;
        let worker = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            collect_configfs(report_data)
        });
        let collected = tokio::time::timeout(self.timeout, worker)
            .await
            .map_err(|_| Status::deadline_exceeded("evidence provider deadline"))?
            .map_err(|_| Status::internal("evidence provider worker failed"))?
            .map_err(|_| Status::unavailable("evidence provider refused"))?;
        Ok(Response::new(EvidenceResponse {
            transcript_version: TRANSCRIPT_VERSION,
            boot_lease_id: self.boot_lease_id.to_vec(),
            quote_v4: collected.quote_v4,
            ccel_table: collected.ccel_table,
            ccel_log: collected.ccel_log,
        }))
    }
}

fn collect_configfs(report_data: [u8; 64]) -> Result<EvidenceBlobs, std::io::Error> {
    let quote_v4 = ConfigFsTsmQuoteProvider::new()
        .quote(report_data)
        .map_err(|_| std::io::Error::other("TDX ConfigFS quote unavailable"))?;
    let ccel_table = read_bounded(Path::new(CCEL_TABLE), MAX_CCEL_TABLE_BYTES)?;
    let ccel_log = read_bounded(Path::new(CCEL_LOG), MAX_CCEL_LOG_BYTES)?;
    if ccel_table.is_empty() || ccel_log.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "empty CCEL evidence",
        ));
    }
    Ok(EvidenceBlobs {
        quote_v4,
        ccel_table,
        ccel_log,
    })
}

fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>, std::io::Error> {
    let mut file = fs::File::open(path)?;
    if !file.metadata()?.file_type().is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "not a regular file",
        ));
    }
    let mut bytes = Vec::new();
    file.by_ref()
        .take((limit + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "evidence too large",
        ));
    }
    Ok(bytes)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    if !private_listener(args.listen.ip()) || args.provider_timeout_seconds == 0 {
        return Err("listener and provider deadline must be closed and explicit".into());
    }
    let request_timeout = args
        .provider_timeout_seconds
        .checked_add(1)
        .ok_or("provider deadline overflow")?;
    let CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["tdx-boot-spike.invalid".into()])?;
    let spki_sha256 = Sha256::digest(signing_key.subject_public_key_info()).into();
    let mut boot_lease_id = [0; LEASE_BYTES];
    rustls::crypto::aws_lc_rs::default_provider()
        .secure_random
        .fill(&mut boot_lease_id)
        .map_err(|_| "OS randomness unavailable")?;
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut tls = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.der().clone()],
            PrivatePkcs8KeyDer::from(signing_key.serialize_der()).into(),
        )?;
    tls.alpn_protocols = vec![b"h2".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(tls));
    let listener = TcpListener::bind(args.listen).await?;
    let incoming = async_stream::stream! {
        loop {
            let item = match listener.accept().await {
                Ok((socket, _)) => match tokio::time::timeout(
                    Duration::from_secs(10),
                    acceptor.accept(socket),
                ).await {
                    Ok(result) => result.map(TlsIo),
                    Err(_) => Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "TLS handshake deadline",
                    )),
                },
                Err(error) => Err(error),
            };
            yield item;
        }
    };
    let service = EvidenceService {
        spki_sha256,
        boot_lease_id,
        provider: Arc::new(Semaphore::new(1)),
        timeout: Duration::from_secs(args.provider_timeout_seconds),
    };
    Server::builder()
        .concurrency_limit_per_connection(1)
        .max_concurrent_streams(1_u32)
        .http2_max_header_list_size(16 * 1024)
        .timeout(Duration::from_secs(request_timeout))
        .add_service(
            BootSpikeEvidenceServer::new(service)
                .max_decoding_message_size(CHALLENGE_BYTES + 1024)
                .max_encoding_message_size(MAX_RESPONSE_BYTES),
        )
        .serve_with_incoming(incoming)
        .await?;
    Ok(())
}

fn private_listener(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_loopback() || ip.is_private() || ip.is_link_local(),
        IpAddr::V6(ip) => ip.is_loopback() || ip.is_unique_local() || ip.is_unicast_link_local(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn listener_rejects_public_and_unspecified_addresses() {
        assert!(private_listener(
            "127.0.0.1".parse().expect("valid loopback")
        ));
        assert!(private_listener(
            "10.1.2.3".parse().expect("valid private address")
        ));
        assert!(!private_listener(
            "0.0.0.0".parse().expect("valid unspecified address")
        ));
        assert!(!private_listener(
            "8.8.8.8".parse().expect("valid public address")
        ));
    }
}
