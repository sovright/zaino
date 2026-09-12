use clap::Parser;
use serde::{
    de::{IgnoredAny, MapAccess, Visitor},
    Deserializer, Serialize,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::Read,
    net::SocketAddr,
    path::{Path, PathBuf},
    time::Duration,
};
use tdx_boot_spike_protocol::{
    report_data,
    wire::{EvidenceRequest, EvidenceResponse},
    ValidatedEvidence, CHALLENGE_BYTES, MAX_RESPONSE_BYTES,
};
use tokio::time::Instant;
use tonic::codegen::http::uri::PathAndQuery;
use zaino_private_client::{LocalQuoteVerifier, UnverifiedRetainedTlsConnection};

const POLICY_LIMIT: usize = 16 * 1024;
const RPC_PATH: &str = "/zaino.boot_spike.v1.BootSpikeEvidence/GetEvidence";
const RECEIPT_SCOPE: &str = "tdx_boot_spike_quote_ccel_diagnostic_v1";

#[derive(Parser)]
struct Args {
    #[arg(long)]
    endpoint: SocketAddr,
    #[arg(long)]
    verifier: PathBuf,
    #[arg(long)]
    verifier_sha256: String,
    #[arg(long)]
    policy_template: PathBuf,
    #[arg(long)]
    policy_template_sha256: String,
    #[arg(long, default_value_t = 30)]
    deadline_seconds: u64,
}

#[derive(Serialize)]
struct DiagnosticReceipt {
    schema_version: u32,
    scope: &'static str,
    challenge: String,
    peer_spki_sha256: String,
    boot_lease_id: String,
    quote_sha256: String,
    policy_sha256: String,
    ccel_table_sha256: String,
    ccel_log_sha256: String,
}

fn decode_digest(value: &str) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    Ok(hex::decode(value)?
        .try_into()
        .map_err(|_| "digest must be 32 bytes")?)
}

fn read_pinned(
    path: &Path,
    expected: [u8; 32],
    limit: usize,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let fd = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NONBLOCK,
        rustix::fs::Mode::empty(),
    )?;
    let mut file = fs::File::from(fd);
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file() || metadata.len() > limit as u64 {
        return Err("pinned input is not a bounded regular file".into());
    }
    let mut bytes = Vec::new();
    file.by_ref()
        .take((limit + 1) as u64)
        .read_to_end(&mut bytes)?;
    let actual: [u8; 32] = Sha256::digest(&bytes).into();
    if bytes.is_empty() || bytes.len() > limit || actual != expected {
        return Err("pinned input digest or length mismatch".into());
    }
    Ok(bytes)
}

fn invocation_policy(
    template: &[u8],
    report_data: [u8; 64],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    reject_duplicate_top_level(template)?;
    let mut value: Value = serde_json::from_slice(template)?;
    let object = value
        .as_object_mut()
        .ok_or("policy template must be an object")?;
    let field = object
        .get_mut("report_data")
        .ok_or("policy template omits report_data")?;
    if field.as_str() != Some(&"00".repeat(64)) {
        return Err("policy report_data placeholder must be 64 zero bytes".into());
    }
    *field = Value::String(hex::encode(report_data));
    Ok(serde_json::to_vec(&value)?)
}

fn reject_duplicate_top_level(bytes: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    struct UniqueKeys;
    impl<'de> Visitor<'de> for UniqueKeys {
        type Value = ();
        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("one JSON object with unique top-level keys")
        }
        fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<(), M::Error> {
            let mut keys = std::collections::HashSet::new();
            while let Some(key) = map.next_key::<String>()? {
                if !keys.insert(key) {
                    return Err(serde::de::Error::custom("duplicate policy field"));
                }
                map.next_value::<IgnoredAny>()?;
            }
            Ok(())
        }
    }
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    deserializer.deserialize_map(UniqueKeys)?;
    deserializer.end()?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    if args.deadline_seconds == 0 {
        return Err("deadline must be nonzero".into());
    }
    let deadline = Instant::now()
        .checked_add(Duration::from_secs(args.deadline_seconds))
        .ok_or("deadline overflow")?;
    let verifier_sha256 = decode_digest(&args.verifier_sha256)?;
    let policy_template_sha256 = decode_digest(&args.policy_template_sha256)?;
    let policy_template = read_pinned(&args.policy_template, policy_template_sha256, POLICY_LIMIT)?;
    let verifier_path = args.verifier;
    let _pinned_verifier = LocalQuoteVerifier::new(
        verifier_path.clone(),
        verifier_sha256,
        Duration::from_secs(args.deadline_seconds),
    )?;
    let mut challenge = [0; CHALLENGE_BYTES];
    rustls::crypto::aws_lc_rs::default_provider()
        .secure_random
        .fill(&mut challenge)
        .map_err(|_| "OS randomness unavailable")?;
    let mut connection = UnverifiedRetainedTlsConnection::connect(args.endpoint, deadline).await?;
    let peer_spki = connection.peer_spki_sha256();
    let wire: EvidenceResponse = connection
        .unary(
            EvidenceRequest {
                challenge: challenge.to_vec(),
            },
            PathAndQuery::from_static(RPC_PATH),
            CHALLENGE_BYTES + 1024,
            MAX_RESPONSE_BYTES,
            deadline,
        )
        .await?;
    let evidence = ValidatedEvidence::try_from_wire(wire)?;
    let expected_report_data = report_data(challenge, peer_spki, evidence.boot_lease_id());
    let policy = invocation_policy(&policy_template, expected_report_data)?;
    let quote = evidence.quote_v4().to_vec();
    let table = evidence.ccel_table().to_vec();
    let log = evidence.ccel_log().to_vec();
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err("diagnostic verification deadline".into());
    }
    let verifier = LocalQuoteVerifier::new(verifier_path, verifier_sha256, remaining)?;
    let verification = tokio::task::spawn_blocking(move || {
        verifier
            .verify_ccel_diagnostic_before(
                &quote,
                &policy,
                expected_report_data,
                &table,
                &log,
                deadline.into_std(),
            )
            .map(|_| (quote, policy, table, log))
    });
    let (quote, policy, table, log) = tokio::time::timeout_at(deadline, verification)
        .await
        .map_err(|_| "diagnostic verification deadline")??
        .map_err(|_| "diagnostic verification refused")?;
    if Instant::now() >= deadline {
        return Err("diagnostic verification deadline".into());
    }
    let receipt = DiagnosticReceipt {
        schema_version: 1,
        scope: RECEIPT_SCOPE,
        challenge: hex::encode(challenge),
        peer_spki_sha256: hex::encode(peer_spki),
        boot_lease_id: hex::encode(evidence.boot_lease_id()),
        quote_sha256: hex::encode(Sha256::digest(quote)),
        policy_sha256: hex::encode(Sha256::digest(policy)),
        ccel_table_sha256: hex::encode(Sha256::digest(table)),
        ccel_log_sha256: hex::encode(Sha256::digest(log)),
    };
    serde_json::to_writer(std::io::stdout().lock(), &receipt)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_template_requires_one_zero_report_data_placeholder() {
        let template = br#"{"report_data":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000","mr_td":"00"}"#;
        let policy = invocation_policy(template, [7; 64]).expect("valid pinned template");
        let value: Value = serde_json::from_slice(&policy).expect("generated policy JSON");
        assert_eq!(value["report_data"], hex::encode([7; 64]));

        let duplicate = br#"{"report_data":"00","report_data":"00"}"#;
        assert!(invocation_policy(duplicate, [7; 64]).is_err());
        assert!(invocation_policy(br#"{"mr_td":"00"}"#, [7; 64]).is_err());
    }
}
