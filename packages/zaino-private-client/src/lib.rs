//! Client-owned validation of raw TDX evidence and a retained-stream research client.
//!
//! Admission accepts the caller's reviewed policy. It does not establish a
//! generally accepted guest-image policy, rollback protection, or wallet readiness.

mod bootstrap;
mod retained;
pub use bootstrap::{BootstrapNetwork, BootstrapWireError, ValidatedBootstrap};
pub use retained::{RetainedClientConfig, RetainedClientError, RetainedPrivateClient};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use std::{
    fmt,
    fs::OpenOptions,
    io::{Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

const CHALLENGE_BYTES: usize = 64;
const DIGEST_BYTES: usize = 32;
const PROFILE_ID_BYTES: usize = 16;
const REPORT_DATA_BYTES: usize = 64;
const MAX_QUOTE_BYTES: usize = 16 * 1024;
const MAX_OUTPUT_BYTES: u64 = 16 * 1024;
const MAX_HELPER_BYTES: u64 = 64 * 1024 * 1024;
const MAX_POLICY_BYTES: usize = 16 * 1024;
const TRANSCRIPT_VERSION: u16 = 1;
const TRANSCRIPT_DOMAIN: [u8; 32] = *b"zaino-tdx-report-data-v1\0\0\0\0\0\0\0\0";
const RECEIPT_SCOPE: &str = "quote_signature_current_collateral_and_supplied_field_policy_only";

/// Client-only bindings generated from the server's canonical schema.
pub mod private_proto {
    include!(concat!(env!("OUT_DIR"), "/zaino.private.v1.rs"));
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct ParsedEvidenceV1 {
    challenge: [u8; CHALLENGE_BYTES],
    tls_spki_sha256: [u8; 32],
    binary_sha256: [u8; 32],
    effective_config_sha256: [u8; 32],
    profile_id: [u8; 16],
    schema_version: u32,
    key_epoch: u64,
    checkpoint_height: u32,
    checkpoint_block_hash: [u8; 32],
    raw_quote: Vec<u8>,
    policy: VerifierOwnedEvidencePolicy,
}

impl fmt::Debug for ParsedEvidenceV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ParsedEvidenceV1")
            .field("quote_bytes", &self.raw_quote.len())
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifierOwnedEvidencePolicy {
    binary_sha256: [u8; 32],
    effective_config_sha256: [u8; 32],
    profile_id: [u8; 16],
    schema_version: u32,
    quote: QuotePolicyTemplate,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct QuotePolicyTemplate {
    minimum_qe_svn: u16,
    minimum_pce_svn: u16,
    minimum_tee_tcb_svn: String,
    mr_seam: String,
    mr_signer_seam: String,
    seam_attributes: String,
    td_attributes: String,
    xfam: String,
    mr_td: String,
    mr_config_id: String,
    mr_owner: String,
    mr_owner_config: String,
    rt_mrs: [String; 4],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientEvidenceError {
    Version,
    Width(&'static str),
    QuoteLength,
    ChallengeMismatch,
    SpkiMismatch,
    WorkloadPolicyMismatch(&'static str),
    PolicyEncoding,
    VerifierPath,
    VerifierIo,
    VerifierTimeout,
    VerifierOutput,
    VerifierRefused,
    VerifierCorrelation(&'static str),
}

impl fmt::Display for ClientEvidenceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "client evidence refused: {self:?}")
    }
}
impl std::error::Error for ClientEvidenceError {}

impl ParsedEvidenceV1 {
    pub(crate) fn try_from_wire(
        wire: &private_proto::EvidenceResponse,
        expected_challenge: [u8; 64],
        live_peer_spki_sha256: [u8; 32],
        policy: &VerifierOwnedEvidencePolicy,
    ) -> Result<Self, ClientEvidenceError> {
        if wire.transcript_version != u32::from(TRANSCRIPT_VERSION) {
            return Err(ClientEvidenceError::Version);
        }
        let challenge = fixed("challenge", &wire.challenge)?;
        let tls_spki_sha256 = fixed("tls_spki_sha256", &wire.tls_spki_sha256)?;
        let binary_sha256 = fixed("binary_sha256", &wire.binary_sha256)?;
        let effective_config_sha256 =
            fixed("effective_config_sha256", &wire.effective_config_sha256)?;
        let profile_id = fixed("profile_id", &wire.profile_id)?;
        let checkpoint_block_hash = fixed("checkpoint_block_hash", &wire.checkpoint_block_hash)?;
        if wire.raw_quote.is_empty() || wire.raw_quote.len() > MAX_QUOTE_BYTES {
            return Err(ClientEvidenceError::QuoteLength);
        }
        if challenge != expected_challenge {
            return Err(ClientEvidenceError::ChallengeMismatch);
        }
        if tls_spki_sha256 != live_peer_spki_sha256 {
            return Err(ClientEvidenceError::SpkiMismatch);
        }
        match_policy("binary_sha256", binary_sha256, policy.binary_sha256)?;
        match_policy(
            "effective_config_sha256",
            effective_config_sha256,
            policy.effective_config_sha256,
        )?;
        match_policy("profile_id", profile_id, policy.profile_id)?;
        if wire.schema_version != policy.schema_version {
            return Err(ClientEvidenceError::WorkloadPolicyMismatch(
                "schema_version",
            ));
        }
        Ok(Self {
            challenge,
            tls_spki_sha256,
            binary_sha256,
            effective_config_sha256,
            profile_id,
            schema_version: wire.schema_version,
            key_epoch: wire.key_epoch,
            checkpoint_height: wire.checkpoint_height,
            checkpoint_block_hash,
            raw_quote: wire.raw_quote.clone(),
            policy: policy.clone(),
        })
    }

    pub(crate) fn report_data(&self) -> [u8; REPORT_DATA_BYTES] {
        let mut h = Sha512::new();
        h.update(TRANSCRIPT_DOMAIN);
        h.update(TRANSCRIPT_VERSION.to_be_bytes());
        h.update(self.challenge);
        h.update(self.tls_spki_sha256);
        h.update(self.binary_sha256);
        h.update(self.effective_config_sha256);
        h.update(self.profile_id);
        h.update(self.schema_version.to_be_bytes());
        h.update(self.key_epoch.to_be_bytes());
        h.update(self.checkpoint_height.to_be_bytes());
        h.update(self.checkpoint_block_hash);
        h.finalize().into()
    }
}

impl VerifierOwnedEvidencePolicy {
    /// Builds a closed policy from reviewed workload identifiers and strict quote-policy JSON.
    pub fn new(
        binary_sha256: [u8; DIGEST_BYTES],
        effective_config_sha256: [u8; DIGEST_BYTES],
        profile_id: [u8; PROFILE_ID_BYTES],
        schema_version: u32,
        quote_policy_json: &[u8],
    ) -> Result<Self, ClientEvidenceError> {
        if quote_policy_json.is_empty() || quote_policy_json.len() > MAX_POLICY_BYTES {
            return Err(ClientEvidenceError::PolicyEncoding);
        }
        let quote: QuotePolicyTemplate = serde_json::from_slice(quote_policy_json)
            .map_err(|_| ClientEvidenceError::PolicyEncoding)?;
        quote.validate_shape()?;
        Ok(Self {
            binary_sha256,
            effective_config_sha256,
            profile_id,
            schema_version,
            quote,
        })
    }

    fn check_evidence(&self, evidence: &ParsedEvidenceV1) -> Result<(), ClientEvidenceError> {
        match_policy("binary_sha256", evidence.binary_sha256, self.binary_sha256)?;
        match_policy(
            "effective_config_sha256",
            evidence.effective_config_sha256,
            self.effective_config_sha256,
        )?;
        match_policy("profile_id", evidence.profile_id, self.profile_id)?;
        if evidence.schema_version != self.schema_version {
            return Err(ClientEvidenceError::WorkloadPolicyMismatch(
                "schema_version",
            ));
        }
        Ok(())
    }
}

impl QuotePolicyTemplate {
    fn validate_shape(&self) -> Result<(), ClientEvidenceError> {
        for (value, bytes) in [
            (&self.minimum_tee_tcb_svn, 16),
            (&self.mr_seam, 48),
            (&self.mr_signer_seam, 48),
            (&self.seam_attributes, 8),
            (&self.td_attributes, 8),
            (&self.xfam, 8),
            (&self.mr_td, 48),
            (&self.mr_config_id, 48),
            (&self.mr_owner, 48),
            (&self.mr_owner_config, 48),
        ] {
            validate_hex_width(value, bytes)?;
        }
        for value in &self.rt_mrs {
            validate_hex_width(value, 48)?;
        }
        Ok(())
    }
}

fn validate_hex_width(value: &str, bytes: usize) -> Result<(), ClientEvidenceError> {
    if value.len() != bytes * 2 || hex::decode(value).map_or(true, |decoded| decoded.len() != bytes)
    {
        return Err(ClientEvidenceError::PolicyEncoding);
    }
    Ok(())
}

fn fixed<const N: usize>(name: &'static str, bytes: &[u8]) -> Result<[u8; N], ClientEvidenceError> {
    bytes
        .try_into()
        .map_err(|_| ClientEvidenceError::Width(name))
}
fn match_policy<const N: usize>(
    name: &'static str,
    actual: [u8; N],
    expected: [u8; N],
) -> Result<(), ClientEvidenceError> {
    if actual == expected {
        Ok(())
    } else {
        Err(ClientEvidenceError::WorkloadPolicyMismatch(name))
    }
}

#[derive(Serialize)]
struct InvocationPolicy<'a> {
    report_data: String,
    #[serde(flatten)]
    template: &'a QuotePolicyTemplate,
}

/// A successful local quote/policy check only. Private fields prevent callers
/// from manufacturing it; it is not a connection or query admission token.
#[derive(Debug, PartialEq, Eq)]
pub struct LocalQuotePolicyReceipt {
    quote_sha256: [u8; 32],
    policy_sha256: [u8; 32],
    report_data: [u8; 64],
}

#[derive(Clone)]
pub struct LocalQuoteVerifier {
    executable: PathBuf,
    executable_sha256: [u8; DIGEST_BYTES],
    timeout: Duration,
}

impl LocalQuoteVerifier {
    pub fn new(
        executable: PathBuf,
        executable_sha256: [u8; DIGEST_BYTES],
        timeout: Duration,
    ) -> Result<Self, ClientEvidenceError> {
        if !executable.is_absolute() || timeout.is_zero() {
            return Err(ClientEvidenceError::VerifierPath);
        }
        let metadata = executable
            .metadata()
            .map_err(|_| ClientEvidenceError::VerifierPath)?;
        if !metadata.is_file() {
            return Err(ClientEvidenceError::VerifierPath);
        }
        if hash_regular_file(&executable, MAX_HELPER_BYTES)? != executable_sha256 {
            return Err(ClientEvidenceError::VerifierPath);
        }
        Ok(Self {
            executable,
            executable_sha256,
            timeout,
        })
    }

    const fn timeout(&self) -> Duration {
        self.timeout
    }

    fn verify(
        &self,
        evidence: &ParsedEvidenceV1,
    ) -> Result<LocalQuotePolicyReceipt, ClientEvidenceError> {
        let policy = &evidence.policy;
        policy.check_evidence(evidence)?;
        // The client host and immutable installation are trusted. This check catches
        // accidental replacement; it is not atomic against a hostile local OS.
        if hash_regular_file(&self.executable, MAX_HELPER_BYTES)? != self.executable_sha256 {
            return Err(ClientEvidenceError::VerifierPath);
        }
        let report_data = evidence.report_data();
        let policy_bytes = serde_json::to_vec(&InvocationPolicy {
            report_data: hex::encode(report_data),
            template: &policy.quote,
        })
        .map_err(|_| ClientEvidenceError::PolicyEncoding)?;
        let quote_sha256 = Sha256::digest(&evidence.raw_quote).into();
        let policy_sha256 = Sha256::digest(&policy_bytes).into();
        let dir = tempfile::Builder::new()
            .prefix("zaino-quote-verifier-")
            .tempdir()
            .map_err(|_| ClientEvidenceError::VerifierIo)?;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
            .map_err(|_| ClientEvidenceError::VerifierIo)?;
        let quote_path = dir.path().join("quote.bin");
        let policy_path = dir.path().join("policy.json");
        let stdout_path = dir.path().join("stdout");
        let stderr_path = dir.path().join("stderr");
        write_new(&quote_path, &evidence.raw_quote)?;
        write_new(&policy_path, &policy_bytes)?;
        let stdout_file = create_new(&stdout_path)?;
        let stderr_file = create_new(&stderr_path)?;
        let deadline = Instant::now()
            .checked_add(self.timeout)
            .ok_or(ClientEvidenceError::VerifierTimeout)?;
        let mut command = Command::new(&self.executable);
        command
            .arg("-quote")
            .arg(&quote_path)
            .arg("-policy")
            .arg(&policy_path)
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout_file))
            .stderr(Stdio::from(stderr_file));
        let mut child = command
            .spawn()
            .map_err(|_| ClientEvidenceError::VerifierIo)?;
        let status = loop {
            let now = Instant::now();
            if now >= deadline {
                terminate(&mut child);
                return Err(ClientEvidenceError::VerifierTimeout);
            }
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) => {}
                Err(_) => {
                    terminate(&mut child);
                    return Err(ClientEvidenceError::VerifierIo);
                }
            }
            if output_too_large(&stdout_path) || output_too_large(&stderr_path) {
                terminate(&mut child);
                return Err(ClientEvidenceError::VerifierOutput);
            }
            thread::sleep(Duration::from_millis(50).min(deadline.saturating_duration_since(now)));
        };
        let stdout = read_path_capped(&stdout_path)?;
        let _stderr = read_path_capped(&stderr_path)?;
        if !status.success() {
            return Err(ClientEvidenceError::VerifierRefused);
        }
        let receipt = parse_receipt(&stdout)?;
        correlate("quote_sha256", receipt.quote_sha256, quote_sha256)?;
        correlate("policy_sha256", receipt.policy_sha256, policy_sha256)?;
        correlate("report_data", receipt.report_data, report_data)?;
        Ok(LocalQuotePolicyReceipt {
            quote_sha256,
            policy_sha256,
            report_data,
        })
    }
}

/// Verifies raw evidence against the live peer inputs and one immutable reviewed policy.
/// The opaque receipt proves only the local quote/policy check; it grants no channel authority.
pub fn verify_evidence_v1(
    verifier: &LocalQuoteVerifier,
    wire: &private_proto::EvidenceResponse,
    expected_challenge: [u8; CHALLENGE_BYTES],
    live_peer_spki_sha256: [u8; DIGEST_BYTES],
    policy: &VerifierOwnedEvidencePolicy,
) -> Result<LocalQuotePolicyReceipt, ClientEvidenceError> {
    let parsed =
        ParsedEvidenceV1::try_from_wire(wire, expected_challenge, live_peer_spki_sha256, policy)?;
    verifier.verify(&parsed)
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), ClientEvidenceError> {
    let mut f = create_new(path)?;
    f.write_all(bytes)
        .map_err(|_| ClientEvidenceError::VerifierIo)
}
fn create_new(path: &Path) -> Result<std::fs::File, ClientEvidenceError> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|_| ClientEvidenceError::VerifierIo)
}
fn hash_regular_file(path: &Path, limit: u64) -> Result<[u8; DIGEST_BYTES], ClientEvidenceError> {
    let fd = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NONBLOCK,
        rustix::fs::Mode::empty(),
    )
    .map_err(|_| ClientEvidenceError::VerifierPath)?;
    let mut file = std::fs::File::from(fd);
    let metadata = file
        .metadata()
        .map_err(|_| ClientEvidenceError::VerifierPath)?;
    if !metadata.is_file() || metadata.len() > limit {
        return Err(ClientEvidenceError::VerifierPath);
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ClientEvidenceError::VerifierPath)?;
    if bytes.len() as u64 > limit {
        return Err(ClientEvidenceError::VerifierPath);
    }
    Ok(Sha256::digest(bytes).into())
}
fn read_path_capped(path: &Path) -> Result<Vec<u8>, ClientEvidenceError> {
    let mut reader = std::fs::File::open(path).map_err(|_| ClientEvidenceError::VerifierIo)?;
    let mut bytes = Vec::new();
    Read::by_ref(&mut reader)
        .take(MAX_OUTPUT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ClientEvidenceError::VerifierIo)?;
    if bytes.len() as u64 > MAX_OUTPUT_BYTES {
        Err(ClientEvidenceError::VerifierOutput)
    } else {
        Ok(bytes)
    }
}

fn terminate(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}
fn output_too_large(path: &Path) -> bool {
    std::fs::metadata(path).map_or(true, |metadata| metadata.len() > MAX_OUTPUT_BYTES)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReceiptJson {
    schema_version: u32,
    quote_sha256: String,
    policy_sha256: String,
    report_data: String,
    scope: String,
}
fn parse_receipt(bytes: &[u8]) -> Result<ReceiptWire, ClientEvidenceError> {
    let mut stream = serde_json::Deserializer::from_slice(bytes).into_iter::<ReceiptJson>();
    let json = stream
        .next()
        .ok_or(ClientEvidenceError::VerifierOutput)?
        .map_err(|_| ClientEvidenceError::VerifierOutput)?;
    if stream.next().is_some() || json.schema_version != 1 || json.scope != RECEIPT_SCOPE {
        return Err(ClientEvidenceError::VerifierOutput);
    }
    Ok(ReceiptWire {
        quote_sha256: decode_hex(&json.quote_sha256)?,
        policy_sha256: decode_hex(&json.policy_sha256)?,
        report_data: decode_hex(&json.report_data)?,
    })
}
struct ReceiptWire {
    quote_sha256: [u8; 32],
    policy_sha256: [u8; 32],
    report_data: [u8; 64],
}
fn decode_hex<const N: usize>(value: &str) -> Result<[u8; N], ClientEvidenceError> {
    hex::decode(value)
        .map_err(|_| ClientEvidenceError::VerifierOutput)?
        .try_into()
        .map_err(|_| ClientEvidenceError::VerifierOutput)
}
fn correlate<const N: usize>(
    name: &'static str,
    actual: [u8; N],
    expected: [u8; N],
) -> Result<(), ClientEvidenceError> {
    if actual == expected {
        Ok(())
    } else {
        Err(ClientEvidenceError::VerifierCorrelation(name))
    }
}

#[cfg(test)]
mod tests;
