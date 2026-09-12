use super::*;
use std::{fs, os::unix::fs::PermissionsExt, time::Duration};

fn template() -> QuotePolicyTemplate {
    let h = |n| "00".repeat(n);
    QuotePolicyTemplate {
        minimum_qe_svn: 0,
        minimum_pce_svn: 0,
        minimum_tee_tcb_svn: h(16),
        mr_seam: h(48),
        mr_signer_seam: h(48),
        seam_attributes: h(8),
        td_attributes: h(8),
        xfam: h(8),
        mr_td: h(48),
        mr_config_id: h(48),
        mr_owner: h(48),
        mr_owner_config: h(48),
        rt_mrs: [h(48), h(48), h(48), h(48)],
    }
}
fn policy() -> VerifierOwnedEvidencePolicy {
    VerifierOwnedEvidencePolicy {
        binary_sha256: [1; 32],
        effective_config_sha256: [2; 32],
        profile_id: [3; 16],
        schema_version: 4,
        quote: template(),
    }
}
fn wire() -> private_proto::EvidenceResponse {
    private_proto::EvidenceResponse {
        transcript_version: 1,
        challenge: vec![0; 64],
        tls_spki_sha256: vec![7; 32],
        binary_sha256: vec![1; 32],
        effective_config_sha256: vec![2; 32],
        profile_id: vec![3; 16],
        schema_version: 4,
        key_epoch: 5,
        checkpoint_height: 6,
        checkpoint_block_hash: vec![7; 32],
        raw_quote: vec![4; 8000],
    }
}
fn parsed() -> ParsedEvidenceV1 {
    ParsedEvidenceV1::try_from_wire(&wire(), [0; 64], [7; 32], &policy())
        .expect("valid evidence fixture")
}

// Allow process startup under concurrent native builds. Timeout behavior is
// tested separately with a helper that remains alive until the deadline.
const HELPER_TEST_BUDGET: Duration = Duration::from_secs(5);

#[test]
fn transcript_matches_server_golden() {
    assert_eq!(hex::encode(parsed().report_data()),"451d3a488285fb8a44d6f069e90b5c797596b00bdfb86ed415876699a33a790c0c9ee20acc2e0a78cb37249ca55480960b47c9b9ab9674bd399e2fcbdb54642f")
}

#[test]
fn strict_wire_validation_precedes_quote_use() {
    let p = policy();
    let mut w = wire();
    w.raw_quote.clear();
    assert_eq!(
        ParsedEvidenceV1::try_from_wire(&w, [0; 64], [7; 32], &p),
        Err(ClientEvidenceError::QuoteLength)
    );
    let mut w = wire();
    w.challenge.pop();
    assert_eq!(
        ParsedEvidenceV1::try_from_wire(&w, [0; 64], [7; 32], &p),
        Err(ClientEvidenceError::Width("challenge"))
    );
    let w = wire();
    assert_eq!(
        ParsedEvidenceV1::try_from_wire(&w, [9; 64], [7; 32], &p),
        Err(ClientEvidenceError::ChallengeMismatch)
    );
    assert_eq!(
        ParsedEvidenceV1::try_from_wire(&w, [0; 64], [8; 32], &p),
        Err(ClientEvidenceError::SpkiMismatch)
    );
    let mut w = wire();
    w.binary_sha256[0] ^= 1;
    assert_eq!(
        ParsedEvidenceV1::try_from_wire(&w, [0; 64], [7; 32], &p),
        Err(ClientEvidenceError::WorkloadPolicyMismatch("binary_sha256"))
    );
}

#[test]
fn transcript_changes_for_every_binding() {
    let base = parsed().report_data();
    for change in 0..9 {
        let mut w = wire();
        match change {
            0 => w.challenge[0] ^= 1,
            1 => w.tls_spki_sha256[0] ^= 1,
            2 => w.binary_sha256[0] ^= 1,
            3 => w.effective_config_sha256[0] ^= 1,
            4 => w.profile_id[0] ^= 1,
            5 => w.schema_version += 1,
            6 => w.key_epoch += 1,
            7 => w.checkpoint_height += 1,
            _ => w.checkpoint_block_hash[0] ^= 1,
        };
        let adjusted = VerifierOwnedEvidencePolicy {
            binary_sha256: w.binary_sha256.clone().try_into().expect("width"),
            effective_config_sha256: w.effective_config_sha256.clone().try_into().expect("width"),
            profile_id: w.profile_id.clone().try_into().expect("width"),
            schema_version: w.schema_version,
            quote: template(),
        };
        let e = ParsedEvidenceV1::try_from_wire(
            &w,
            w.challenge.clone().try_into().expect("width"),
            w.tls_spki_sha256.clone().try_into().expect("width"),
            &adjusted,
        )
        .expect("changed fixture valid");
        assert_ne!(e.report_data(), base);
    }
}

fn executable_with_receipt(receipt: &str) -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("verifier");
    fs::write(
        &path,
        format!(
            "#!/bin/sh\nprintf '%s' '{}'\n",
            receipt.replace('\'', "'\\''")
        ),
    )
    .expect("script");
    let mut permissions = fs::metadata(&path).expect("metadata").permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(path, permissions).expect("permissions");
    dir
}
fn verifier(path: &std::path::Path, timeout: Duration) -> LocalQuoteVerifier {
    let hash = Sha256::digest(fs::read(path).expect("helper bytes")).into();
    LocalQuoteVerifier::new(path.to_path_buf(), hash, timeout).expect("verifier")
}

fn expected_receipt(e: &ParsedEvidenceV1, p: &VerifierOwnedEvidencePolicy) -> String {
    let report = e.report_data();
    let bytes = serde_json::to_vec(&InvocationPolicy {
        report_data: hex::encode(report),
        template: &p.quote,
    })
    .expect("policy");
    serde_json::json!({"schema_version":1,"quote_sha256":hex::encode(Sha256::digest(&e.raw_quote)),"policy_sha256":hex::encode(Sha256::digest(bytes)),"report_data":hex::encode(report),"scope":RECEIPT_SCOPE}).to_string()
}

#[test]
fn local_verifier_correlates_exact_inputs() {
    let e = parsed();
    let p = policy();
    let receipt = expected_receipt(&e, &p);
    let dir = executable_with_receipt(&receipt);
    let verifier = verifier(&dir.path().join("verifier"), HELPER_TEST_BUDGET);
    verifier.verify(&e).expect("correlated helper receipt");
}

#[test]
fn local_ccel_verifier_correlates_every_exact_input_and_scope() {
    let quote = b"quote";
    let policy = b"policy";
    let table = b"table";
    let log = b"log";
    let report_data = [9; 64];
    let receipt = serde_json::json!({
        "schema_version": 1,
        "quote_sha256": hex::encode(Sha256::digest(quote)),
        "policy_sha256": hex::encode(Sha256::digest(policy)),
        "report_data": hex::encode(report_data),
        "ccel_table_sha256": hex::encode(Sha256::digest(table)),
        "ccel_log_sha256": hex::encode(Sha256::digest(log)),
        "measured_events": [1, 2, 3, 0],
        "rt_mrs_matched": [true, true, true, true],
        "scope": "tdx_quote_ccel_digest_replay_diagnostic_v1",
    })
    .to_string();
    let dir = executable_with_receipt(&receipt);
    let valid_verifier = verifier(&dir.path().join("verifier"), HELPER_TEST_BUDGET);
    valid_verifier
        .verify_ccel_diagnostic(quote, policy, report_data, table, log)
        .expect("all exact diagnostic inputs correlate");

    for bad in [
        receipt.replace(
            "tdx_quote_ccel_digest_replay_diagnostic_v1",
            "quote_signature_current_collateral_and_supplied_field_policy_only",
        ),
        receipt.replacen(&hex::encode(Sha256::digest(quote)), &"00".repeat(32), 1),
        receipt.replacen(&hex::encode(Sha256::digest(policy)), &"00".repeat(32), 1),
        receipt.replacen(&hex::encode(report_data), &"00".repeat(64), 1),
        receipt.replacen(&hex::encode(Sha256::digest(table)), &"00".repeat(32), 1),
        receipt.replacen(&hex::encode(Sha256::digest(log)), &"00".repeat(32), 1),
        receipt.replace("[true,true,true,true]", "[true,true,true,false]"),
        receipt.replacen("{", "{\"unknown\":1,", 1),
        receipt.replacen("{", "{\"scope\":\"duplicate\",", 1),
    ] {
        let dir = executable_with_receipt(&bad);
        assert!(verifier(&dir.path().join("verifier"), HELPER_TEST_BUDGET)
            .verify_ccel_diagnostic(quote, policy, report_data, table, log)
            .is_err());
    }
}

#[test]
fn expired_absolute_ccel_deadline_never_starts_the_helper() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("verifier");
    let marker = dir.path().join("started");
    fs::write(
        &path,
        format!("#!/bin/sh\nprintf started > '{}'\n", marker.display()),
    )
    .expect("script");
    let mut permissions = fs::metadata(&path).expect("metadata").permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&path, permissions).expect("permissions");
    let verifier = verifier(&path, HELPER_TEST_BUDGET);
    let deadline = std::time::Instant::now() + Duration::from_millis(10);
    std::thread::sleep(Duration::from_millis(20));
    assert_eq!(
        verifier.verify_ccel_diagnostic_before(
            b"quote", b"policy", [1; 64], b"table", b"log", deadline,
        ),
        Err(ClientEvidenceError::VerifierTimeout)
    );
    assert!(!marker.exists());
}

#[test]
fn public_entrypoint_uses_canonical_wire_type() {
    let e = parsed();
    let p = policy();
    let dir = executable_with_receipt(&expected_receipt(&e, &p));
    let verifier = verifier(&dir.path().join("verifier"), HELPER_TEST_BUDGET);
    assert!(verify_evidence_v1(&verifier, &wire(), [0; 64], [7; 32], &p).is_ok());
}

#[test]
fn local_verifier_rejects_duplicate_unknown_and_mismatch_receipts() {
    let e = parsed();
    let p = policy();
    let valid = expected_receipt(&e, &p);
    for bad in [
        valid.replacen("{", "{\"scope\":\"x\",", 1),
        valid.replacen("{", "{\"unknown\":1,", 1),
        valid.replace(&hex::encode(Sha256::digest(&e.raw_quote)), &"00".repeat(32)),
    ] {
        let dir = executable_with_receipt(&bad);
        let v = verifier(&dir.path().join("verifier"), HELPER_TEST_BUDGET);
        assert!(v.verify(&e).is_err());
    }
}

#[test]
fn trusted_client_rejects_ccel_diagnostic_receipt_scope() {
    let e = parsed();
    let p = policy();
    let diagnostic = expected_receipt(&e, &p)
        .replace(RECEIPT_SCOPE, "tdx_quote_ccel_digest_replay_diagnostic_v1");
    let dir = executable_with_receipt(&diagnostic);
    let verifier = verifier(&dir.path().join("verifier"), HELPER_TEST_BUDGET);
    assert!(verifier.verify(&e).is_err());
}

#[test]
fn local_verifier_kills_and_reaps_on_deadline() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("verifier");
    let marker = dir.path().join("marker");
    fs::write(
        &path,
        format!(
            "#!/bin/sh\nprintf '%s\\n%s\\n' $$ \"${{2%/*}}\" > '{}'\nwhile :; do :; done\n",
            marker.display()
        ),
    )
    .expect("script");
    let mut permissions = fs::metadata(&path).expect("metadata").permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&path, permissions).expect("permissions");
    let v = verifier(&path, HELPER_TEST_BUDGET);
    let started = std::time::Instant::now();
    assert_eq!(
        v.verify(&parsed()),
        Err(ClientEvidenceError::VerifierTimeout)
    );
    assert!(started.elapsed() < HELPER_TEST_BUDGET + Duration::from_secs(2));
    let marker = fs::read_to_string(marker).expect("child marker");
    let mut lines = marker.lines();
    let pid = lines.next().expect("pid");
    let invocation_dir = lines.next().expect("invocation directory");
    assert!(!std::path::Path::new(invocation_dir).exists());
    assert!(!std::process::Command::new("kill")
        .args(["-0", pid])
        .status()
        .expect("kill probe")
        .success());
}

#[test]
fn helper_replacement_and_excess_output_are_refused() {
    let e = parsed();
    let p = policy();
    let dir = executable_with_receipt(&expected_receipt(&e, &p));
    let path = dir.path().join("verifier");
    let pinned = verifier(&path, HELPER_TEST_BUDGET);
    fs::write(&path, "#!/bin/sh\nprintf changed\n").expect("replace helper");
    assert_eq!(pinned.verify(&e), Err(ClientEvidenceError::VerifierPath));

    // A shell builtin emits the bounded fixture without descendant processes
    // or pipeline scheduling competing with the verifier deadline.
    let overflow_len = usize::try_from(MAX_OUTPUT_BYTES + 1).expect("output limit fits usize");
    let dir = executable_with_receipt(&"x".repeat(overflow_len));
    let path = dir.path().join("verifier");
    assert_eq!(
        verifier(&path, HELPER_TEST_BUDGET).verify(&e),
        Err(ClientEvidenceError::VerifierOutput)
    );
}

#[test]
fn policy_constructor_rejects_oversized_and_wrong_width_json() {
    assert_eq!(
        VerifierOwnedEvidencePolicy::new(
            [1; 32],
            [2; 32],
            [3; 16],
            4,
            &vec![b' '; MAX_POLICY_BYTES + 1]
        ),
        Err(ClientEvidenceError::PolicyEncoding)
    );
    let malformed = serde_json::to_vec(&QuotePolicyTemplate {
        mr_td: "00".into(),
        ..template()
    })
    .expect("json");
    assert_eq!(
        VerifierOwnedEvidencePolicy::new([1; 32], [2; 32], [3; 16], 4, &malformed),
        Err(ClientEvidenceError::PolicyEncoding)
    );
}
