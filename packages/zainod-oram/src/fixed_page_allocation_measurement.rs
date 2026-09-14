//! Source-bound parent/child measurement for the three-table allocation diagnostic.

use std::path::Path;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use std::{
    fs,
    os::fd::AsFd as _,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use serde::Serialize;

use crate::RunnerResult;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use crate::{
    execution_identity::verify_native_build_identity, hybrid_sizing_artifact::load_hybrid_sizing,
};

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const REVIEWED_HYBRID_DIGEST: &str =
    "2c44f5dcdf851a12053cd8e684c4f97f202f4ff88e49102ad6232b984a746828";
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const DEADLINE: Duration = Duration::from_secs(3_600);
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const SAMPLE_INTERVAL: Duration = Duration::from_millis(250);
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const RETAINED_HOLD: Duration = Duration::from_secs(30);
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const TERM_GRACE: Duration = Duration::from_secs(30);
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const MAX_STATUS_BYTES: u64 = 4 * 1024;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const EXPECTED_CAPACITIES: [usize; 3] = [4_194_304, 131_072, 131_072];

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[derive(Serialize)]
struct Registration<'a> {
    schema: &'static str,
    scope: &'static str,
    hybrid_sizing_blake2s256: &'static str,
    source_revision: &'a str,
    binary_sha256: &'a str,
    build_manifest_sha256: &'a str,
    capacities: [usize; 3],
    source_checkpoint_height: u32,
    source_checkpoint_hash: &'a str,
    allocation_profile: &'static str,
    retained_floor_bytes: u64,
    deadline_seconds: u64,
    sample_interval_millis: u128,
    retained_hold_seconds: u64,
    term_grace_seconds: u64,
    mem_available_bytes: u64,
    swap_total_bytes: u64,
    kernel_release: String,
    cgroup_membership: String,
    started_unix_millis: u128,
    exclusions: [&'static str; 7],
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[derive(Serialize)]
struct TerminalReport {
    schema: &'static str,
    classification: &'static str,
    registration_sha256: String,
    child_pid: u32,
    capacities: [usize; 3],
    construction_order: [&'static str; 3],
    simultaneous_live: bool,
    sampled_rss_max_bytes: u64,
    sampled_rss_count: u64,
    steady_rss_bytes: Option<u64>,
    kernel_lifetime_peak_bytes: Option<u64>,
    maximum_guest_swap_bytes: u64,
    ready_unix_millis: Option<u128>,
    release_unix_millis: Option<u128>,
    terminal_unix_millis: u128,
    exit_code: Option<i32>,
    signal: Option<i32>,
    reaped: bool,
    protocol_complete: bool,
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[derive(Serialize)]
struct Completion<'a> {
    schema: &'static str,
    classification: &'a str,
    registration_sha256: &'a str,
    result_sha256: &'a str,
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
struct ChildSupervisor {
    child: Option<std::process::Child>,
    pidfd: std::os::fd::OwnedFd,
    output_dir: std::path::PathBuf,
    registration_sha256: String,
    child_pid: u32,
    reaped: bool,
    evidence_complete: bool,
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
impl ChildSupervisor {
    fn poll(&mut self) -> RunnerResult<Option<wait4::ResUse>> {
        use rustix::process::{WaitId, WaitIdOptions};
        if rustix::process::waitid(
            WaitId::PidFd(self.pidfd.as_fd()),
            WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT,
        )?
        .is_some()
        {
            return self.reap().map(Some);
        }
        Ok(None)
    }

    fn terminate(&mut self, grace: Duration) -> RunnerResult<wait4::ResUse> {
        if let Some(waited) = self.poll()? {
            return Ok(waited);
        }
        match rustix::process::pidfd_send_signal(&self.pidfd, rustix::process::Signal::Term) {
            Ok(()) | Err(rustix::io::Errno::SRCH) => {}
            Err(error) => return Err(error.into()),
        }
        if let Some(waited) = self.wait_until_exit(grace)? {
            return Ok(waited);
        }
        match rustix::process::pidfd_send_signal(&self.pidfd, rustix::process::Signal::Kill) {
            Ok(()) | Err(rustix::io::Errno::SRCH) => {}
            Err(error) => return Err(error.into()),
        }
        self.wait_until_exit(grace)?
            .ok_or_else(|| "child did not become waitable after KILL".into())
    }

    fn wait_until_exit(&mut self, duration: Duration) -> RunnerResult<Option<wait4::ResUse>> {
        let deadline = std::time::Instant::now()
            .checked_add(duration)
            .ok_or("child wait deadline overflow")?;
        while std::time::Instant::now() < deadline {
            if let Some(waited) = self.poll()? {
                return Ok(Some(waited));
            }
            std::thread::sleep(
                SAMPLE_INTERVAL.min(deadline.saturating_duration_since(std::time::Instant::now())),
            );
        }
        Ok(None)
    }

    fn reap(&mut self) -> RunnerResult<wait4::ResUse> {
        let child = self.child.as_mut().ok_or("child was already reaped")?;
        let waited = wait4_retry(child)?;
        self.child = None;
        self.reaped = true;
        Ok(waited)
    }

    fn mark_evidence_complete(&mut self) {
        self.evidence_complete = true;
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
impl Drop for ChildSupervisor {
    fn drop(&mut self) {
        if !self.reaped {
            let _ = rustix::process::pidfd_send_signal(&self.pidfd, rustix::process::Signal::Kill);
            let _ = self.wait_until_exit(TERM_GRACE);
        }
        if !self.evidence_complete {
            let _ = publish_incomplete(
                &self.output_dir,
                &self.registration_sha256,
                self.child_pid,
                self.reaped,
            );
        }
    }
}

pub(super) fn run_parent(
    hybrid_dir: &Path,
    native_build_manifest: &Path,
    output_dir: &Path,
) -> RunnerResult<()> {
    #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
    {
        let _ = (hybrid_dir, native_build_manifest, output_dir);
        Err("fixed-page allocation measurement requires Linux x86_64".into())
    }
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    run_parent_linux(hybrid_dir, native_build_manifest, output_dir)
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn run_parent_linux(
    hybrid_dir: &Path,
    native_build_manifest: &Path,
    output_dir: &Path,
) -> RunnerResult<()> {
    use std::{
        os::unix::process::ExitStatusExt,
        process::{Command, Stdio},
        time::Instant,
    };
    let identity = verify_native_build_identity(native_build_manifest)?;
    let hybrid = load_hybrid_sizing(hybrid_dir, REVIEWED_HYBRID_DIGEST)?;
    let profile = zaino_oram::FixedPageAllocationProfile::try_from_report(hybrid.report())?;
    let (source_checkpoint_height, source_checkpoint_hash) = hybrid.report().source_checkpoint();
    let (mem_available_bytes, swap_total_bytes) = read_meminfo()?;
    let kernel_release = read_bounded_text(Path::new("/proc/sys/kernel/osrelease"), 256)?;
    let cgroup_membership = read_bounded_text(Path::new("/proc/self/cgroup"), 16 * 1024)?;
    let required = profile
        .retained_floor_bytes()
        .checked_add(1 << 30)
        .ok_or("resource preflight overflow")?;
    if mem_available_bytes < required {
        return Err(
            "available host memory is below diagnostic floor plus preflight reserve".into(),
        );
    }
    if swap_total_bytes != 0 {
        return Err("host swap must be disabled before preregistration".into());
    }

    use std::os::unix::fs::DirBuilderExt as _;
    fs::DirBuilder::new().mode(0o700).create(output_dir)?;
    let registration = Registration {
        schema: "zaino-oram-fixed-page-allocation-registration-v1",
        scope: "three-table-diagnostic-not-complete-service",
        hybrid_sizing_blake2s256: REVIEWED_HYBRID_DIGEST,
        source_revision: identity.source_revision(),
        binary_sha256: identity.binary_sha256(),
        build_manifest_sha256: identity.build_manifest_sha256(),
        capacities: EXPECTED_CAPACITIES,
        source_checkpoint_height,
        source_checkpoint_hash,
        allocation_profile: "reviewed-mainnet-fixed-page-three-table-v1",
        retained_floor_bytes: profile.retained_floor_bytes(),
        deadline_seconds: DEADLINE.as_secs(),
        sample_interval_millis: SAMPLE_INTERVAL.as_millis(),
        retained_hold_seconds: RETAINED_HOLD.as_secs(),
        term_grace_seconds: TERM_GRACE.as_secs(),
        mem_available_bytes,
        swap_total_bytes,
        kernel_release,
        cgroup_membership,
        started_unix_millis: now_millis()?,
        exclusions: [
            "directory-state",
            "generation-overlap",
            "growth-v2",
            "retained-floor-excludes-construction-transients",
            "full-service-rss",
            "host-swap",
            "tdx-qualification",
        ],
    };
    let registration_sha256 = publish_json(output_dir, "registration.json", &registration)?;

    let deadline = Instant::now()
        .checked_add(DEADLINE)
        .ok_or("deadline overflow")?;
    let executable = std::env::current_exe()?;
    let mut child = match Command::new(executable)
        .args([
            "qualification",
            "fixed-page-allocation-child",
            "--hybrid-sizing-dir",
        ])
        .arg(hybrid_dir)
        .arg("--native-build-manifest")
        .arg(native_build_manifest)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(child) => child,
        Err(error) => {
            publish_incomplete(output_dir, &registration_sha256, 0, false)?;
            return Err(error.into());
        }
    };
    let pid = child.id();
    let setup = (|| -> RunnerResult<_> {
        let child_pid = rustix::process::Pid::from_raw(pid as i32).ok_or("invalid child pid")?;
        let pidfd = rustix::process::pidfd_open(child_pid, rustix::process::PidfdFlags::empty())?;
        let child_status = fs::File::open(format!("/proc/{pid}/status"))?;
        let child_stdin = child.stdin.take().ok_or("child stdin missing")?;
        let stdout = child.stdout.take().ok_or("child stdout missing")?;
        Ok((pidfd, child_status, child_stdin, stdout))
    })();
    let (pidfd, mut child_status, mut child_stdin, stdout) = match setup {
        Ok(setup) => setup,
        Err(error) => {
            let reaped = kill_and_reap_setup_child(&mut child);
            publish_incomplete(output_dir, &registration_sha256, pid, reaped)?;
            return Err(error);
        }
    };
    let mut supervisor = ChildSupervisor {
        child: Some(child),
        pidfd,
        output_dir: output_dir.to_path_buf(),
        registration_sha256: registration_sha256.clone(),
        child_pid: pid,
        reaped: false,
        evidence_complete: false,
    };
    let mut stdout = stdout;
    let stdout_flags = rustix::fs::fcntl_getfl(&stdout)?;
    rustix::fs::fcntl_setfl(&stdout, stdout_flags | rustix::fs::OFlags::NONBLOCK)?;
    let outcome = monitor_child(
        &mut supervisor,
        &mut stdout,
        &mut child_stdin,
        MonitorPolicy {
            deadline,
            retained_hold: RETAINED_HOLD,
            sample_interval: SAMPLE_INTERVAL,
            term_grace: TERM_GRACE,
        },
        || read_process_memory(&mut child_status),
        now_millis,
    )?;
    let classification = outcome.classification;
    let report = TerminalReport {
        schema: "zaino-oram-fixed-page-allocation-result-v1",
        classification,
        registration_sha256: registration_sha256.clone(),
        child_pid: pid,
        capacities: EXPECTED_CAPACITIES,
        construction_order: ["base", "add", "spend"],
        simultaneous_live: outcome.protocol_complete,
        sampled_rss_max_bytes: outcome.sampled_rss_max_bytes,
        sampled_rss_count: outcome.sampled_rss_count,
        steady_rss_bytes: outcome.steady_rss_bytes,
        kernel_lifetime_peak_bytes: Some(outcome.waited.rusage.maxrss),
        maximum_guest_swap_bytes: outcome.maximum_guest_swap_bytes,
        ready_unix_millis: outcome.ready_unix_millis,
        release_unix_millis: outcome.release_unix_millis,
        terminal_unix_millis: now_millis()?,
        exit_code: outcome.waited.status.code(),
        signal: outcome.waited.status.signal(),
        reaped: true,
        protocol_complete: outcome.protocol_complete,
    };
    let result_sha256 = publish_json(output_dir, "result.json", &report)?;
    let completion = Completion {
        schema: "zaino-oram-fixed-page-allocation-complete-v1",
        classification,
        registration_sha256: &registration_sha256,
        result_sha256: &result_sha256,
    };
    publish_json(output_dir, "COMPLETE", &completion)?;
    supervisor.mark_evidence_complete();
    if classification == "allocated_cleanly" {
        Ok(())
    } else {
        Err(format!("allocation diagnostic ended as {classification}").into())
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
struct MonitorOutcome {
    waited: wait4::ResUse,
    classification: &'static str,
    protocol_complete: bool,
    sampled_rss_max_bytes: u64,
    sampled_rss_count: u64,
    steady_rss_bytes: Option<u64>,
    maximum_guest_swap_bytes: u64,
    ready_unix_millis: Option<u128>,
    release_unix_millis: Option<u128>,
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[derive(Clone, Copy)]
struct MonitorPolicy {
    deadline: std::time::Instant,
    retained_hold: Duration,
    sample_interval: Duration,
    term_grace: Duration,
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn monitor_child(
    supervisor: &mut ChildSupervisor,
    stdout: &mut impl std::io::Read,
    stdin: &mut impl std::io::Write,
    policy: MonitorPolicy,
    mut sample_memory: impl FnMut() -> RunnerResult<(u64, u64)>,
    mut wall_millis: impl FnMut() -> RunnerResult<u128>,
) -> RunnerResult<MonitorOutcome> {
    use std::os::unix::process::ExitStatusExt as _;

    let MonitorPolicy {
        deadline,
        retained_hold,
        sample_interval,
        term_grace,
    } = policy;
    let mut status_bytes = Vec::with_capacity(128);
    let mut ready_at = None;
    let mut ready_instant = None;
    let mut released_at = None;
    let mut sampled_max = 0;
    let mut sampled_count = 0_u64;
    let mut steady_rss = None;
    let mut max_swap = 0;
    let mut timed_out = false;
    let mut swap_detected = false;
    let mut protocol_failed = false;
    let waited = loop {
        if let Some(done) = supervisor.poll()? {
            timed_out = std::time::Instant::now() >= deadline;
            if read_status_nonblocking(stdout, &mut status_bytes).is_err()
                || status_bytes != b"READY v1 base=4194304 add=131072 spend=131072\n"
            {
                protocol_failed = true;
            }
            break done;
        }
        if std::time::Instant::now() >= deadline {
            timed_out = true;
            break supervisor.terminate(term_grace)?;
        }
        match read_status_nonblocking(stdout, &mut status_bytes) {
            Ok(_) => {
                if ready_at.is_none()
                    && status_bytes == b"READY v1 base=4194304 add=131072 spend=131072\n"
                {
                    ready_at = Some(wall_millis()?);
                    ready_instant = Some(std::time::Instant::now());
                }
            }
            Err(_) => {
                protocol_failed = true;
                break supervisor.terminate(term_grace)?;
            }
        }
        let sample = match sample_memory() {
            Ok(sample) => sample,
            Err(_) if released_at.is_some() => {
                std::thread::sleep(
                    sample_interval
                        .min(deadline.saturating_duration_since(std::time::Instant::now())),
                );
                continue;
            }
            Err(_) => {
                protocol_failed = true;
                break supervisor.terminate(term_grace)?;
            }
        };
        sampled_max = sampled_max.max(sample.0);
        max_swap = max_swap.max(sample.1);
        sampled_count = sampled_count
            .checked_add(1)
            .ok_or("sample counter overflow")?;
        if ready_at.is_some() && released_at.is_none() {
            steady_rss = Some(sample.0);
        }
        if sample.1 > 0 {
            swap_detected = true;
            break supervisor.terminate(term_grace)?;
        }
        if released_at.is_none()
            && ready_instant.is_some_and(|instant| instant.elapsed() >= retained_hold)
        {
            if std::time::Instant::now() >= deadline {
                timed_out = true;
                break supervisor.terminate(term_grace)?;
            }
            if stdin
                .write_all(b"RELEASE\n")
                .and_then(|()| stdin.flush())
                .is_err()
            {
                protocol_failed = true;
                break supervisor.terminate(term_grace)?;
            }
            released_at = Some(wall_millis()?);
        }
        std::thread::sleep(
            sample_interval.min(deadline.saturating_duration_since(std::time::Instant::now())),
        );
    };
    let protocol_complete = ready_at.is_some() && released_at.is_some();
    let classification = if timed_out {
        "timeout"
    } else if swap_detected {
        "swap_detected"
    } else if protocol_failed {
        "protocol_failed"
    } else if waited.status.success()
        && protocol_complete
        && steady_rss.is_some_and(|rss| rss > 0)
        && waited.rusage.maxrss > 0
    {
        "allocated_cleanly"
    } else if waited.status.signal().is_some() {
        "signal_unknown"
    } else {
        "construction_failed"
    };
    Ok(MonitorOutcome {
        waited,
        classification,
        protocol_complete,
        sampled_rss_max_bytes: sampled_max,
        sampled_rss_count: sampled_count,
        steady_rss_bytes: steady_rss,
        maximum_guest_swap_bytes: max_swap,
        ready_unix_millis: ready_at,
        release_unix_millis: released_at,
    })
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn wait4_retry(child: &mut std::process::Child) -> std::io::Result<wait4::ResUse> {
    use wait4::Wait4 as _;
    loop {
        match child.wait4() {
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            result => return result,
        }
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn kill_and_reap_setup_child(child: &mut std::process::Child) -> bool {
    let _ = child.kill();
    let Some(deadline) = std::time::Instant::now().checked_add(TERM_GRACE) else {
        return false;
    };
    while std::time::Instant::now() < deadline {
        match child.try_wait() {
            Ok(Some(_)) => return true,
            Ok(None) => std::thread::sleep(
                SAMPLE_INTERVAL.min(deadline.saturating_duration_since(std::time::Instant::now())),
            ),
            Err(_) => return false,
        }
    }
    false
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn read_status_nonblocking(
    reader: &mut impl std::io::Read,
    bytes: &mut Vec<u8>,
) -> std::io::Result<bool> {
    let mut chunk = [0_u8; 256];
    let mut eof = false;
    loop {
        match reader.read(&mut chunk) {
            Ok(0) => {
                eof = true;
                break;
            }
            Ok(count) => {
                bytes.extend_from_slice(&chunk[..count]);
                if bytes.len() as u64 > MAX_STATUS_BYTES {
                    return Err(std::io::Error::other("child status exceeds bound"));
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
    const EXPECTED: &[u8] = b"READY v1 base=4194304 add=131072 spend=131072\n";
    if !EXPECTED.starts_with(bytes.as_slice()) || (eof && bytes != EXPECTED) {
        return Err(std::io::Error::other("child status frame is malformed"));
    }
    Ok(eof)
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn publish_incomplete(
    output_dir: &Path,
    registration_sha256: &str,
    child_pid: u32,
    reaped: bool,
) -> RunnerResult<()> {
    let name = if output_dir.join("result.json").exists() {
        "incomplete.json"
    } else {
        "result.json"
    };
    publish_json(
        output_dir,
        name,
        &serde_json::json!({
            "schema": "zaino-oram-fixed-page-allocation-result-v1",
            "classification": "incomplete",
            "registration_sha256": registration_sha256,
            "child_pid": child_pid,
            "reaped": reaped,
            "protocol_complete": false,
        }),
    )?;
    Ok(())
}

pub(super) fn run_child(hybrid_dir: &Path, native_build_manifest: &Path) -> RunnerResult<()> {
    #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
    {
        let _ = (hybrid_dir, native_build_manifest);
        Err("allocation child requires Linux x86_64".into())
    }
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        use std::io::{self, BufRead, Read as _, Write};
        verify_native_build_identity(native_build_manifest)?;
        let hybrid = load_hybrid_sizing(hybrid_dir, REVIEWED_HYBRID_DIGEST)?;
        let profile = zaino_oram::FixedPageAllocationProfile::try_from_report(hybrid.report())?;
        zaino_oram::with_fixed_page_allocation(&profile, |capacities| {
            if capacities != EXPECTED_CAPACITIES {
                return Err(());
            }
            println!(
                "READY v1 base={} add={} spend={}",
                capacities[0], capacities[1], capacities[2]
            );
            if io::stdout().flush().is_err() {
                return Err(());
            }
            let mut line = String::new();
            if io::stdin()
                .lock()
                .take(MAX_STATUS_BYTES + 1)
                .read_line(&mut line)
                .is_err()
                || line != "RELEASE\n"
            {
                return Err(());
            }
            Ok(())
        })?;
        Ok(())
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn now_millis() -> RunnerResult<u128> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn publish_json(path: &Path, name: &str, value: &impl Serialize) -> RunnerResult<String> {
    let encoded = serde_json::to_vec_pretty(value)?;
    if encoded.len() > 64 * 1024 {
        return Err("published JSON exceeds evidence bound".into());
    }
    publish_bytes(path, name, &encoded)?;
    use sha2::Digest as _;
    Ok(hex::encode(sha2::Sha256::digest(encoded)))
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn publish_bytes(path: &Path, name: &str, bytes: &[u8]) -> RunnerResult<()> {
    use std::io::Write as _;
    if bytes.len() > 64 * 1024 {
        return Err("published bytes exceed evidence bound".into());
    }
    let destination = path.join(name);
    let temporary = path.join(format!(".{name}.tmp"));
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    fs::rename(&temporary, &destination)?;
    let validation = (|| -> RunnerResult<()> {
        fs::File::open(path)?.sync_all()?;
        if fs::read(&destination)? != bytes {
            return Err("published bytes failed exact read-back validation".into());
        }
        Ok(())
    })();
    if let Err(error) = validation {
        let _ = fs::remove_file(&destination);
        let _ = fs::File::open(path).and_then(|directory| directory.sync_all());
        return Err(error);
    }
    Ok(())
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn read_meminfo() -> RunnerResult<(u64, u64)> {
    let text = read_bounded_text(Path::new("/proc/meminfo"), 64 * 1024)?;
    Ok((
        parse_kib(&text, "MemAvailable:")?,
        parse_kib(&text, "SwapTotal:")?,
    ))
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn read_bounded_text(path: &Path, maximum_bytes: usize) -> RunnerResult<String> {
    use std::io::Read as _;
    let file = fs::File::open(path)?;
    let mut bytes = Vec::with_capacity(maximum_bytes.min(4096));
    file.take((maximum_bytes + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > maximum_bytes {
        return Err("bounded host input exceeds limit".into());
    }
    Ok(String::from_utf8(bytes)?)
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn read_process_memory(file: &mut fs::File) -> RunnerResult<(u64, u64)> {
    use std::io::{Read as _, Seek as _, SeekFrom};
    file.seek(SeekFrom::Start(0))?;
    let mut text = String::new();
    file.take(64 * 1024).read_to_string(&mut text)?;
    Ok((parse_kib(&text, "VmRSS:")?, parse_kib(&text, "VmSwap:")?))
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn parse_kib(text: &str, key: &str) -> RunnerResult<u64> {
    let line = text
        .lines()
        .find(|line| line.starts_with(key))
        .ok_or("memory counter missing")?;
    let value = line
        .split_whitespace()
        .nth(1)
        .ok_or("memory counter malformed")?
        .parse::<u64>()?;
    value
        .checked_mul(1024)
        .ok_or_else(|| "memory counter overflow".into())
}

#[cfg(test)]
mod tests {
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    fn spawn_supervisor(
        command: &mut std::process::Command,
        output_dir: &std::path::Path,
    ) -> Result<super::ChildSupervisor, Box<dyn std::error::Error + Send + Sync>> {
        let child = command.spawn()?;
        let pid = child.id();
        let stable_pid = rustix::process::Pid::from_raw(pid as i32).ok_or("invalid child pid")?;
        let pidfd = rustix::process::pidfd_open(stable_pid, rustix::process::PidfdFlags::empty())?;
        Ok(super::ChildSupervisor {
            child: Some(child),
            pidfd,
            output_dir: output_dir.to_path_buf(),
            registration_sha256: "00".repeat(32),
            child_pid: pid,
            reaped: false,
            evidence_complete: false,
        })
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn synthetic_proc_counters_are_bounded_and_exact(
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        assert_eq!(
            super::parse_kib("VmRSS:\t2 kB\nVmSwap:\t0 kB\n", "VmRSS:")?,
            2048
        );
        assert!(super::parse_kib("VmRSS: nope kB\n", "VmRSS:").is_err());
        Ok(())
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn status_protocol_rejects_oversize_and_trailing_bytes() {
        use std::io::Cursor;
        let oversized = vec![b'x'; super::MAX_STATUS_BYTES as usize + 1];
        assert!(
            super::read_status_nonblocking(&mut Cursor::new(oversized), &mut Vec::new()).is_err()
        );
        assert!(super::read_status_nonblocking(
            &mut Cursor::new(b"READY v1 base=4194304 add=131072 spend=131072\nextra"),
            &mut Vec::new()
        )
        .is_err());
        assert!(
            super::read_status_nonblocking(&mut Cursor::new(b"BROKEN"), &mut Vec::new()).is_err()
        );
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn completion_record_binds_both_evidence_hashes(
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let directory = tempfile::tempdir()?;
        let registration = super::publish_json(
            directory.path(),
            "registration.json",
            &serde_json::json!({"schema": "registration-test-v1"}),
        )?;
        let result = super::publish_json(
            directory.path(),
            "result.json",
            &serde_json::json!({"schema": "result-test-v1"}),
        )?;
        let complete = super::Completion {
            schema: "zaino-oram-fixed-page-allocation-complete-v1",
            classification: "allocated_cleanly",
            registration_sha256: &registration,
            result_sha256: &result,
        };
        super::publish_json(directory.path(), "COMPLETE", &complete)?;
        let wire: serde_json::Value =
            serde_json::from_slice(&std::fs::read(directory.path().join("COMPLETE"))?)?;
        assert_eq!(wire["registration_sha256"], registration);
        assert_eq!(wire["result_sha256"], result);
        Ok(())
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn completion_publication_failure_retains_incomplete_without_acceptance(
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let directory = tempfile::tempdir()?;
        super::publish_json(
            directory.path(),
            "result.json",
            &serde_json::json!({"classification": "construction_failed"}),
        )?;
        std::fs::create_dir(directory.path().join("COMPLETE"))?;
        assert!(super::publish_json(
            directory.path(),
            "COMPLETE",
            &serde_json::json!({"schema": "complete-test-v1"})
        )
        .is_err());
        super::publish_incomplete(directory.path(), &"22".repeat(32), 7, true)?;
        assert!(!directory.path().join("COMPLETE").is_file());
        assert!(directory.path().join("incomplete.json").is_file());
        Ok(())
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn term_path_returns_the_single_authoritative_wait4_result(
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        use std::{os::unix::process::ExitStatusExt as _, process::Command, time::Duration};
        let directory = tempfile::tempdir()?;
        let mut supervisor =
            spawn_supervisor(Command::new("/bin/sleep").arg("10"), directory.path())?;
        let result = supervisor.terminate(Duration::from_secs(1))?;
        supervisor.mark_evidence_complete();
        assert_eq!(result.status.signal(), Some(15));
        Ok(())
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn kill_path_is_bounded_and_reaped() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        use std::{os::unix::process::ExitStatusExt as _, process::Command, time::Duration};
        let directory = tempfile::tempdir()?;
        let ready = directory.path().join("ready");
        let script = format!(
            "trap '' TERM; : > '{}'; while :; do :; done",
            ready.display()
        );
        let mut supervisor = spawn_supervisor(
            Command::new("/bin/sh").args(["-c", &script]),
            directory.path(),
        )?;
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while !ready.is_file() && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(
            ready.is_file(),
            "synthetic child did not install TERM handler"
        );
        let result = supervisor.terminate(Duration::from_millis(50))?;
        supervisor.mark_evidence_complete();
        assert_eq!(result.status.signal(), Some(9));
        Ok(())
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn dropping_supervisor_kills_reaps_and_retains_incomplete_result(
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        use std::process::Command;
        let directory = tempfile::tempdir()?;
        let supervisor = spawn_supervisor(Command::new("/bin/sleep").arg("10"), directory.path())?;
        let pid = supervisor.child_pid;
        drop(supervisor);
        assert!(!std::path::Path::new(&format!("/proc/{pid}")).exists());
        let retained: serde_json::Value =
            serde_json::from_slice(&std::fs::read(directory.path().join("result.json"))?)?;
        assert_eq!(retained["classification"], "incomplete");
        assert_eq!(retained["reaped"], true);
        assert!(!directory.path().join("COMPLETE").exists());
        Ok(())
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn synthetic_protocol_runs_hold_release_and_binds_completion(
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        use sha2::Digest as _;
        use std::{
            cell::Cell,
            os::unix::process::ExitStatusExt as _,
            process::{Command, Stdio},
            rc::Rc,
            time::{Duration, Instant},
        };
        struct ReleaseWriter<W> {
            inner: W,
            released: Rc<Cell<bool>>,
        }
        impl<W: std::io::Write> std::io::Write for ReleaseWriter<W> {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                let written = self.inner.write(bytes)?;
                if bytes.get(..written) == Some(b"RELEASE\n") {
                    self.released.set(true);
                }
                Ok(written)
            }
            fn flush(&mut self) -> std::io::Result<()> {
                self.inner.flush()
            }
        }
        let directory = tempfile::tempdir()?;
        let post_release_sample = directory.path().join("post-release-sampled");
        let script = format!(
            "printf 'READY v1 base=4194304 add=131072 spend=131072\\n'; read line && test \"$line\" = RELEASE && while ! test -f '{}'; do sleep 0.005; done",
            post_release_sample.display()
        );
        let mut child = Command::new("/bin/sh")
            .args(["-c", &script])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()?;
        let pid = child.id();
        let stable_pid = rustix::process::Pid::from_raw(pid as i32).ok_or("invalid child pid")?;
        let pidfd = rustix::process::pidfd_open(stable_pid, rustix::process::PidfdFlags::empty())?;
        let released = Rc::new(Cell::new(false));
        let mut stdin = ReleaseWriter {
            inner: child.stdin.take().ok_or("synthetic stdin missing")?,
            released: Rc::clone(&released),
        };
        let mut stdout = child.stdout.take().ok_or("synthetic stdout missing")?;
        let mut supervisor = super::ChildSupervisor {
            child: Some(child),
            pidfd,
            output_dir: directory.path().to_path_buf(),
            registration_sha256: "11".repeat(32),
            child_pid: pid,
            reaped: false,
            evidence_complete: false,
        };
        let flags = rustix::fs::fcntl_getfl(&stdout)?;
        rustix::fs::fcntl_setfl(&stdout, flags | rustix::fs::OFlags::NONBLOCK)?;
        let mut clock = 0_u128;
        let mut phase_instants = Vec::with_capacity(2);
        let post_release_samples = Cell::new(0_u64);
        let outcome = super::monitor_child(
            &mut supervisor,
            &mut stdout,
            &mut stdin,
            super::MonitorPolicy {
                deadline: Instant::now() + Duration::from_secs(2),
                retained_hold: Duration::from_millis(20),
                sample_interval: Duration::from_millis(5),
                term_grace: Duration::from_millis(100),
            },
            || {
                if released.get() {
                    post_release_samples.set(post_release_samples.get() + 1);
                    std::fs::write(&post_release_sample, b"observed")?;
                    Ok((1024, 0))
                } else {
                    Ok((4096, 0))
                }
            },
            || {
                clock += 1;
                phase_instants.push(Instant::now());
                Ok(clock)
            },
        )?;
        assert_eq!(outcome.classification, "allocated_cleanly");
        assert_eq!(outcome.waited.status.signal(), None);
        assert_eq!(outcome.steady_rss_bytes, Some(4096));
        assert!(released.get());
        assert!(post_release_samples.get() > 0);
        assert!(phase_instants[1].duration_since(phase_instants[0]) >= Duration::from_millis(20));
        assert!(
            outcome.release_unix_millis.expect("release timestamp")
                > outcome.ready_unix_millis.expect("ready timestamp")
        );
        let registration = super::publish_json(
            directory.path(),
            "registration.json",
            &serde_json::json!({"schema": "registration-test-v1"}),
        )?;
        let result = super::publish_json(
            directory.path(),
            "result.json",
            &serde_json::json!({"classification": outcome.classification}),
        )?;
        super::publish_json(
            directory.path(),
            "COMPLETE",
            &super::Completion {
                schema: "zaino-oram-fixed-page-allocation-complete-v1",
                classification: outcome.classification,
                registration_sha256: &registration,
                result_sha256: &result,
            },
        )?;
        supervisor.mark_evidence_complete();
        let complete: serde_json::Value =
            serde_json::from_slice(&std::fs::read(directory.path().join("COMPLETE"))?)?;
        let registration_readback = std::fs::read(directory.path().join("registration.json"))?;
        let result_readback = std::fs::read(directory.path().join("result.json"))?;
        assert_eq!(
            complete["registration_sha256"],
            hex::encode(sha2::Sha256::digest(&registration_readback))
        );
        assert_eq!(
            complete["result_sha256"],
            hex::encode(sha2::Sha256::digest(&result_readback))
        );
        Ok(())
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn deadline_before_retained_hold_reaps_without_release(
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        use std::{
            process::{Command, Stdio},
            time::{Duration, Instant},
        };
        let directory = tempfile::tempdir()?;
        let release_marker = directory.path().join("released");
        let script = format!(
            "printf 'READY v1 base=4194304 add=131072 spend=131072\\n'; read line && test \"$line\" = RELEASE && : > '{}'",
            release_marker.display()
        );
        let mut child = Command::new("/bin/sh")
            .args(["-c", &script])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()?;
        let pid = child.id();
        let stable_pid = rustix::process::Pid::from_raw(pid as i32).ok_or("invalid child pid")?;
        let pidfd = rustix::process::pidfd_open(stable_pid, rustix::process::PidfdFlags::empty())?;
        let mut stdin = child.stdin.take().ok_or("synthetic stdin missing")?;
        let mut stdout = child.stdout.take().ok_or("synthetic stdout missing")?;
        let mut supervisor = super::ChildSupervisor {
            child: Some(child),
            pidfd,
            output_dir: directory.path().to_path_buf(),
            registration_sha256: "33".repeat(32),
            child_pid: pid,
            reaped: false,
            evidence_complete: false,
        };
        let flags = rustix::fs::fcntl_getfl(&stdout)?;
        rustix::fs::fcntl_setfl(&stdout, flags | rustix::fs::OFlags::NONBLOCK)?;
        let outcome = super::monitor_child(
            &mut supervisor,
            &mut stdout,
            &mut stdin,
            super::MonitorPolicy {
                deadline: Instant::now() + Duration::from_millis(100),
                retained_hold: Duration::from_secs(1),
                sample_interval: Duration::from_millis(5),
                term_grace: Duration::from_millis(100),
            },
            || Ok((4096, 0)),
            || Ok(1),
        )?;
        assert_eq!(outcome.classification, "timeout");
        assert!(!outcome.protocol_complete);
        assert!(!release_marker.exists());
        assert!(supervisor.reaped);
        supervisor.mark_evidence_complete();
        Ok(())
    }
}
