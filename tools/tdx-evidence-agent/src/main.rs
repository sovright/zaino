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
    sync::{mpsc, Arc},
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
    sync::{oneshot, OwnedSemaphorePermit, Semaphore},
};
use tokio_rustls::{server::TlsStream, TlsAcceptor};
use tonic::{
    transport::{server::Connected, Server},
    Request, Response, Status,
};
use zaino_tdx_evidence::ConfigFsTsmQuoteProvider;

#[cfg(target_os = "linux")]
mod confinement {
    use seccompiler::{
        apply_filter_all_threads, BpfProgram, SeccompAction, SeccompFilter, SeccompRule,
    };
    use std::{collections::BTreeMap, convert::TryInto, io};

    #[repr(C)]
    struct CapHeader {
        version: u32,
        pid: i32,
    }

    #[repr(C)]
    struct CapData {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }

    const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;
    const PR_CAP_AMBIENT: libc::c_int = 47;
    const PR_CAP_AMBIENT_CLEAR_ALL: libc::c_ulong = 4;

    pub(super) fn drop_capabilities() -> io::Result<()> {
        // Drop every capability from the bounding set before clearing the
        // current thread set. Missing future capability numbers fail closed.
        let last = std::fs::read_to_string("/proc/sys/kernel/cap_last_cap")?
            .trim()
            .parse::<u32>()
            .map_err(|_| io::Error::other("invalid cap_last_cap"))?;
        for capability in 0..=last {
            // SAFETY: PR_CAPBSET_DROP accepts one integer capability number.
            if unsafe { libc::prctl(libc::PR_CAPBSET_DROP, capability, 0, 0, 0) } != 0 {
                return Err(io::Error::last_os_error());
            }
        }
        // SAFETY: this prctl operation takes no pointer arguments.
        if unsafe { libc::prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let header = CapHeader {
            version: LINUX_CAPABILITY_VERSION_3,
            pid: 0,
        };
        let data = [
            CapData {
                effective: 0,
                permitted: 0,
                inheritable: 0,
            },
            CapData {
                effective: 0,
                permitted: 0,
                inheritable: 0,
            },
        ];
        // SAFETY: capset reads the fixed header and two v3 data records.
        if unsafe { libc::syscall(libc::SYS_capset, &header, data.as_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    pub(super) fn install_seccomp() -> io::Result<()> {
        let filter = filter()?;
        apply_filter_all_threads(&filter).map_err(|_| io::Error::other("seccomp install failed"))
    }

    fn filter() -> io::Result<BpfProgram> {
        let allowed: BTreeMap<i64, Vec<SeccompRule>> = [
            libc::SYS_accept4,
            libc::SYS_arch_prctl,
            libc::SYS_bind,
            libc::SYS_brk,
            libc::SYS_clock_gettime,
            libc::SYS_close,
            libc::SYS_epoll_create1,
            libc::SYS_epoll_ctl,
            libc::SYS_epoll_pwait,
            libc::SYS_epoll_wait,
            libc::SYS_eventfd2,
            libc::SYS_exit,
            libc::SYS_exit_group,
            libc::SYS_fcntl,
            libc::SYS_fstat,
            libc::SYS_fsync,
            libc::SYS_futex,
            libc::SYS_getcwd,
            libc::SYS_getdents64,
            libc::SYS_getgid,
            libc::SYS_getpeername,
            libc::SYS_getpid,
            libc::SYS_getrandom,
            libc::SYS_getsockname,
            libc::SYS_getsockopt,
            libc::SYS_gettid,
            libc::SYS_getuid,
            libc::SYS_ioctl,
            libc::SYS_listen,
            libc::SYS_lseek,
            libc::SYS_madvise,
            libc::SYS_membarrier,
            libc::SYS_mkdir,
            libc::SYS_mkdirat,
            libc::SYS_mmap,
            libc::SYS_mprotect,
            libc::SYS_munmap,
            libc::SYS_nanosleep,
            libc::SYS_newfstatat,
            libc::SYS_openat,
            libc::SYS_pipe2,
            libc::SYS_poll,
            libc::SYS_ppoll,
            libc::SYS_prctl,
            libc::SYS_prlimit64,
            libc::SYS_pread64,
            libc::SYS_pwrite64,
            libc::SYS_read,
            libc::SYS_readlink,
            libc::SYS_readlinkat,
            libc::SYS_readv,
            libc::SYS_recvfrom,
            libc::SYS_recvmsg,
            libc::SYS_renameat,
            libc::SYS_rmdir,
            libc::SYS_rseq,
            libc::SYS_rt_sigaction,
            libc::SYS_rt_sigprocmask,
            libc::SYS_rt_sigreturn,
            libc::SYS_sched_getaffinity,
            libc::SYS_sched_yield,
            libc::SYS_sendmsg,
            libc::SYS_sendto,
            libc::SYS_set_robust_list,
            libc::SYS_setsockopt,
            libc::SYS_shutdown,
            libc::SYS_sigaltstack,
            libc::SYS_socket,
            libc::SYS_statx,
            libc::SYS_uname,
            libc::SYS_unlink,
            libc::SYS_unlinkat,
            libc::SYS_write,
            libc::SYS_writev,
        ]
        .into_iter()
        .map(|syscall| (syscall, Vec::new()))
        .collect();
        SeccompFilter::new(
            allowed.into_iter().collect(),
            SeccompAction::Trap,
            SeccompAction::Allow,
            std::env::consts::ARCH
                .try_into()
                .map_err(|_| io::Error::other("unsupported seccomp architecture"))?,
        )
        .map_err(|_| io::Error::other("seccomp policy invalid"))?
        .try_into()
        .map_err(|_| io::Error::other("seccomp compile failed"))
    }

    #[cfg(test)]
    pub(super) fn compile_for_test() -> io::Result<BpfProgram> {
        filter()
    }
}

#[cfg(not(target_os = "linux"))]
mod confinement {
    pub(super) fn drop_capabilities() -> std::io::Result<()> {
        Err(std::io::Error::other("guest confinement requires Linux"))
    }
    pub(super) fn install_seccomp() -> std::io::Result<()> {
        Err(std::io::Error::other("guest confinement requires Linux"))
    }
}

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
    provider_tx: mpsc::SyncSender<QuoteJob>,
    timeout: Duration,
}

struct EvidenceBlobs {
    quote_v4: Vec<u8>,
    ccel_table: Vec<u8>,
    ccel_log: Vec<u8>,
}

struct GuestTlsIdentity {
    acceptor: TlsAcceptor,
    spki_sha256: [u8; 32],
    boot_lease_id: [u8; LEASE_BYTES],
}

struct ServerContext {
    request_timeout: u64,
    tls: GuestTlsIdentity,
    provider_tx: mpsc::SyncSender<QuoteJob>,
    provider_timeout_seconds: u64,
    shutdown: ShutdownSignals,
}

struct ShutdownSignals {
    terminate: tokio::signal::unix::Signal,
    interrupt: tokio::signal::unix::Signal,
}

struct QuoteJob {
    report_data: [u8; 64],
    permit: OwnedSemaphorePermit,
    response: oneshot::Sender<Result<EvidenceBlobs, std::io::Error>>,
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
        let (response, receiver) = oneshot::channel();
        self.provider_tx
            .try_send(QuoteJob {
                report_data,
                permit,
                response,
            })
            .map_err(|_| Status::resource_exhausted("evidence provider busy"))?;
        let collected = tokio::time::timeout(self.timeout, receiver)
            .await
            .map_err(|_| Status::deadline_exceeded("evidence provider deadline"))?
            .map_err(|_| Status::internal("evidence provider worker stopped"))?
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

fn start_provider() -> Result<mpsc::SyncSender<QuoteJob>, std::io::Error> {
    start_provider_with(Arc::new(collect_configfs))
}

fn start_provider_with(
    collector: Arc<
        dyn Fn([u8; 64]) -> Result<EvidenceBlobs, std::io::Error> + Send + Sync + 'static,
    >,
) -> Result<mpsc::SyncSender<QuoteJob>, std::io::Error> {
    // The semaphore permits exactly one outstanding job. A one-slot channel
    // avoids a scheduling race between the ready handshake and blocking recv.
    let (sender, receiver) = mpsc::sync_channel::<QuoteJob>(1);
    let (ready_sender, ready_receiver) = mpsc::sync_channel(0);
    std::thread::Builder::new()
        .name("tdx-quote-provider".into())
        .spawn(move || {
            if ready_sender.send(()).is_err() {
                return;
            }
            while let Ok(job) = receiver.recv() {
                let result = collector(job.report_data);
                let _ = job.response.send(result);
                drop(job.permit);
            }
        })
        .map_err(|_| std::io::Error::other("evidence provider thread unavailable"))?;
    ready_receiver
        .recv()
        .map_err(|_| std::io::Error::other("evidence provider thread stopped at startup"))?;
    Ok(sender)
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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    if !private_listener(args.listen.ip()) || args.provider_timeout_seconds == 0 {
        return Err("listener and provider deadline must be closed and explicit".into());
    }
    let request_timeout = args
        .provider_timeout_seconds
        .checked_add(1)
        .ok_or("provider deadline overflow")?;
    let tls = tls_identity()?;
    // Drop privilege before thread construction so every worker inherits the
    // same empty capability state.
    confinement::drop_capabilities()?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .max_blocking_threads(1)
        .enable_io()
        .enable_time()
        .build()?;
    let provider_tx = start_provider()?;
    // Register the signal self-pipe while runtime initialization syscalls are
    // still permitted. The filtered server only polls these existing streams.
    let shutdown = {
        let _runtime = runtime.enter();
        shutdown_signals()?
    };
    // Runtime and the single fixed quote worker now exist. The synchronized
    // filter denies clone/clone3 as well as every non-allowlisted syscall.
    confinement::install_seccomp()?;
    runtime.block_on(serve(
        args.listen,
        ServerContext {
            request_timeout,
            tls,
            provider_tx,
            provider_timeout_seconds: args.provider_timeout_seconds,
            shutdown,
        },
    ))
}

fn tls_identity() -> Result<GuestTlsIdentity, Box<dyn std::error::Error>> {
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
    Ok(GuestTlsIdentity {
        acceptor,
        spki_sha256,
        boot_lease_id,
    })
}

async fn serve(
    listen: SocketAddr,
    context: ServerContext,
) -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind(listen).await?;
    serve_listener(listener, None, context).await
}

async fn serve_listener(
    listener: TcpListener,
    connection_limit: Option<usize>,
    context: ServerContext,
) -> Result<(), Box<dyn std::error::Error>> {
    let ServerContext {
        request_timeout,
        tls,
        provider_tx,
        provider_timeout_seconds,
        shutdown,
    } = context;
    let GuestTlsIdentity {
        acceptor,
        spki_sha256,
        boot_lease_id,
    } = tls;
    let incoming = async_stream::stream! {
        let mut accepted = 0_usize;
        loop {
            if connection_limit.is_some_and(|limit| accepted >= limit) {
                break;
            }
            let item = match listener.accept().await {
                Ok((socket, _)) => {
                    accepted += 1;
                    match tokio::time::timeout(Duration::from_secs(10), acceptor.accept(socket)).await {
                        Ok(result) => result.map(TlsIo),
                        Err(_) => Err(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "TLS handshake deadline",
                        )),
                    }
                }
                Err(error) => Err(error),
            };
            yield item;
        }
    };
    let service = EvidenceService {
        spki_sha256,
        boot_lease_id,
        provider: Arc::new(Semaphore::new(1)),
        provider_tx,
        timeout: Duration::from_secs(provider_timeout_seconds),
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
        .serve_with_incoming_shutdown(incoming, shutdown_signal(shutdown))
        .await?;
    Ok(())
}

#[cfg(unix)]
fn shutdown_signals() -> std::io::Result<ShutdownSignals> {
    Ok(ShutdownSignals {
        terminate: tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?,
        interrupt: tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?,
    })
}

async fn shutdown_signal(mut signals: ShutdownSignals) {
    tokio::select! {
        _ = signals.terminate.recv() => {}
        _ = signals.interrupt.recv() => {}
    }
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

    #[cfg(target_os = "linux")]
    struct ChildGuard(Option<std::process::Child>);

    #[cfg(target_os = "linux")]
    impl Drop for ChildGuard {
        fn drop(&mut self) {
            if let Some(mut child) = self.0.take() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }
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

    #[cfg(target_os = "linux")]
    #[test]
    fn confinement_policy_compiles() {
        confinement::compile_for_test().expect("closed seccomp policy compiles");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn confinement_filter_supports_precreated_runtime_and_fixed_worker() {
        let directory = tempfile::tempdir().expect("probe directory");
        let marker = directory.path().join("listener");
        let child = std::process::Command::new(std::env::current_exe().expect("test executable"))
            .args([
                "--exact",
                "tests::confinement_filter_runtime_probe_child",
                "--nocapture",
            ])
            .env("ZAINO_SECCOMP_PROBE", directory.path())
            .spawn()
            .expect("start isolated confinement probe");
        let mut child = ChildGuard(Some(child));
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while !marker.exists() && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        let address = fs::read_to_string(marker).expect("filtered listener marker");
        let address = address.parse().expect("probe listener address");
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .expect("probe client runtime");
        runtime.block_on(async {
            let mut connection = zaino_private_client::UnverifiedRetainedTlsConnection::connect(
                address,
                tokio::time::Instant::from_std(deadline),
            )
            .await
            .expect("real TLS 1.3 handshake through filtered server");
            let response: EvidenceResponse = connection
                .unary(
                    EvidenceRequest {
                        challenge: vec![7; CHALLENGE_BYTES],
                    },
                    tonic::codegen::http::uri::PathAndQuery::from_static(
                        "/zaino.boot.v1.BootSpikeEvidence/GetEvidence",
                    ),
                    CHALLENGE_BYTES + 16,
                    MAX_RESPONSE_BYTES,
                    tokio::time::Instant::from_std(deadline),
                )
                .await
                .expect("quote job crosses the filtered permanent worker");
            assert_eq!(response.quote_v4, [1]);
            assert_eq!(response.ccel_table, [2]);
            assert_eq!(response.ccel_log, [3]);
            drop(connection);
        });
        let status = loop {
            let owned = child.0.as_mut().expect("child guard retains process");
            if let Some(status) = owned.try_wait().expect("probe child state") {
                child.0.take();
                break status;
            }
            if std::time::Instant::now() >= deadline {
                panic!("filtered server did not terminate");
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        assert!(status.success(), "confinement probe was killed or refused");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn confinement_filter_runtime_probe_child() {
        let Some(directory) = std::env::var_os("ZAINO_SECCOMP_PROBE") else {
            return;
        };
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_io()
            .enable_time()
            .build()
            .expect("probe runtime");
        let report = std::path::PathBuf::from(&directory).join("report");
        let collector = Arc::new(move |_report_data: [u8; 64]| {
            fs::create_dir(&report)?;
            fs::remove_dir(&report)?;
            Ok(EvidenceBlobs {
                quote_v4: vec![1],
                ccel_table: vec![2],
                ccel_log: vec![3],
            })
        });
        let provider_tx = start_provider_with(collector).expect("fixed provider worker starts");
        let tls = tls_identity().expect("probe TLS identity");
        let shutdown = {
            let _runtime = runtime.enter();
            shutdown_signals().expect("signal streams initialize before filter")
        };
        confinement::install_seccomp().expect("install synchronized filter");
        runtime.block_on(async {
            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind probe listener");
            fs::write(
                std::path::PathBuf::from(
                    std::env::var_os("ZAINO_SECCOMP_PROBE").expect("probe directory"),
                )
                .join("listener"),
                listener.local_addr().expect("probe address").to_string(),
            )
            .expect("write listener marker");
            serve_listener(
                listener,
                Some(1),
                ServerContext {
                    request_timeout: 2,
                    tls,
                    provider_tx,
                    provider_timeout_seconds: 1,
                    shutdown,
                },
            )
            .await
            .expect("serve one filtered TLS connection");
        });
        // Avoid test-harness cleanup syscalls outside the shipped policy.
        // SAFETY: the isolated child has completed every assertion.
        unsafe { libc::_exit(0) }
    }
}
