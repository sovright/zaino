//! Atomic evidence artifacts for the fixed typed-worker stress profile.

use std::path::Path;

use serde::{Deserialize, Serialize};
use zaino_oram::TypedWorkerStressQualificationReport;

use crate::corpus_artifact::{
    artifact_blake2s256_hex, publish_verified_artifact, read_artifact_file, ArtifactDirectory,
    ArtifactError, ArtifactFile,
};

const STRESS_QUALIFICATION_SCHEMA: &str = "zaino-oram-typed-worker-stress-qualification-v1";
const STRESS_PROVENANCE_SCHEMA: &str = "zaino-oram-typed-worker-stress-qualification-provenance-v1";
const STRESS_QUALIFICATION_JSON: &str = "stress-qualification.json";
const STRESS_QUALIFICATION_TEXT: &str = "stress-qualification.txt";
const PROVENANCE_JSON: &str = "provenance.json";
const MAX_STRESS_QUALIFICATION_JSON_BYTES: usize = 4 * 1024 * 1024;
const MAX_STRESS_QUALIFICATION_TEXT_BYTES: usize = 4 * 1024 * 1024;
const MAX_PROVENANCE_JSON_BYTES: usize = 64 * 1024;

fn ensure_supported_execution_target() -> Result<(), ArtifactError> {
    if is_supported_execution_target(std::env::consts::OS, std::env::consts::ARCH) {
        Ok(())
    } else {
        Err(ArtifactError::InvalidArtifact {
            reason: "typed-worker stress qualification publication requires Linux x86_64 execution",
        })
    }
}

fn is_supported_execution_target(target_os: &str, target_arch: &str) -> bool {
    target_os == "linux" && target_arch == "x86_64"
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StressQualificationArtifactV1 {
    schema: String,
    qualification: TypedWorkerStressQualificationReport,
}

impl StressQualificationArtifactV1 {
    fn new(qualification: &TypedWorkerStressQualificationReport) -> Result<Self, ArtifactError> {
        validate_qualification(qualification)?;
        Ok(Self {
            schema: STRESS_QUALIFICATION_SCHEMA.to_owned(),
            qualification: qualification.clone(),
        })
    }

    fn validate(&self) -> Result<(), ArtifactError> {
        if self.schema != STRESS_QUALIFICATION_SCHEMA {
            return Err(ArtifactError::InvalidArtifact {
                reason: "typed-worker stress qualification schema mismatch",
            });
        }
        validate_qualification(&self.qualification)
    }

    fn canonical_bytes(&self) -> Result<Vec<u8>, ArtifactError> {
        serde_json::to_vec(self).map_err(ArtifactError::Json)
    }

    fn digest(&self) -> Result<String, ArtifactError> {
        Ok(artifact_blake2s256_hex(&self.canonical_bytes()?))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StressQualificationProvenanceV1 {
    schema: String,
    runner_version: String,
    target_os: String,
    target_arch: String,
    stress_qualification_blake2s256: String,
}

impl StressQualificationProvenanceV1 {
    fn new(
        runner_version: &str,
        artifact: &StressQualificationArtifactV1,
    ) -> Result<Self, ArtifactError> {
        ensure_supported_execution_target()?;
        if runner_version.is_empty() {
            return Err(ArtifactError::InvalidArtifact {
                reason: "runner version is empty",
            });
        }
        Ok(Self {
            schema: STRESS_PROVENANCE_SCHEMA.to_owned(),
            runner_version: runner_version.to_owned(),
            target_os: std::env::consts::OS.to_owned(),
            target_arch: std::env::consts::ARCH.to_owned(),
            stress_qualification_blake2s256: artifact.digest()?,
        })
    }

    fn validate(&self, artifact: &StressQualificationArtifactV1) -> Result<(), ArtifactError> {
        if self.schema != STRESS_PROVENANCE_SCHEMA
            || self.runner_version.is_empty()
            || !is_supported_execution_target(&self.target_os, &self.target_arch)
        {
            return Err(ArtifactError::InvalidArtifact {
                reason: "typed-worker stress qualification provenance is invalid",
            });
        }
        if self.stress_qualification_blake2s256 != artifact.digest()? {
            return Err(ArtifactError::InvalidArtifact {
                reason: "typed-worker stress qualification digest mismatch",
            });
        }
        Ok(())
    }
}

fn validate_qualification(
    qualification: &TypedWorkerStressQualificationReport,
) -> Result<(), ArtifactError> {
    qualification
        .validate()
        .map_err(|_| ArtifactError::InvalidArtifact {
            reason: "typed-worker stress qualification report is invalid",
        })
}

/// Publishes a complete, read-back-validated typed-worker stress qualification.
pub(super) fn publish_stress_qualification(
    output_dir: &Path,
    qualification: &TypedWorkerStressQualificationReport,
    runner_version: &str,
) -> Result<(), ArtifactError> {
    let artifact = StressQualificationArtifactV1::new(qualification)?;
    let provenance = StressQualificationProvenanceV1::new(runner_version, &artifact)?;
    provenance.validate(&artifact)?;

    let files = [
        ArtifactFile::new(
            STRESS_QUALIFICATION_JSON,
            serde_json::to_vec_pretty(&artifact).map_err(ArtifactError::Json)?,
        ),
        ArtifactFile::new(
            STRESS_QUALIFICATION_TEXT,
            qualification.to_string().into_bytes(),
        ),
        ArtifactFile::new(
            PROVENANCE_JSON,
            serde_json::to_vec_pretty(&provenance).map_err(ArtifactError::Json)?,
        ),
    ];

    publish_verified_artifact(output_dir, &files, |stage| {
        validate_staged_qualification(stage, &artifact, &provenance)
    })
}

fn validate_staged_qualification(
    stage: &ArtifactDirectory,
    expected_artifact: &StressQualificationArtifactV1,
    expected_provenance: &StressQualificationProvenanceV1,
) -> Result<(), ArtifactError> {
    let qualification_json = read_artifact_file(
        stage,
        STRESS_QUALIFICATION_JSON,
        MAX_STRESS_QUALIFICATION_JSON_BYTES,
    )?;
    let qualification_text = read_artifact_file(
        stage,
        STRESS_QUALIFICATION_TEXT,
        MAX_STRESS_QUALIFICATION_TEXT_BYTES,
    )?;
    let provenance_json = read_artifact_file(stage, PROVENANCE_JSON, MAX_PROVENANCE_JSON_BYTES)?;

    let artifact: StressQualificationArtifactV1 =
        serde_json::from_slice(&qualification_json).map_err(ArtifactError::Json)?;
    artifact.validate()?;
    let provenance: StressQualificationProvenanceV1 =
        serde_json::from_slice(&provenance_json).map_err(ArtifactError::Json)?;
    provenance.validate(&artifact)?;
    if qualification_text != artifact.qualification.to_string().as_bytes() {
        return Err(ArtifactError::InvalidArtifact {
            reason: "typed-worker stress qualification text does not match the typed report",
        });
    }
    if artifact != *expected_artifact {
        return Err(ArtifactError::InvalidArtifact {
            reason: "typed-worker stress qualification read-back differs from the computed report",
        });
    }
    if provenance != *expected_provenance {
        return Err(ArtifactError::InvalidArtifact {
            reason: "typed-worker stress provenance read-back differs from the expected provenance",
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    use std::{collections::BTreeSet, ffi::OsString, fs};

    type TestResult<T = ()> = Result<T, Box<dyn Error>>;

    fn typed_report() -> TestResult<TypedWorkerStressQualificationReport> {
        let report: TypedWorkerStressQualificationReport =
            serde_json::from_value(serde_json::json!({
                "scenario": "typed-worker-stress-smoke-v1",
                "profile": "smoke-v1",
                "backend": "rostl-circuit-oram-volatile-v1",
                "profile_shape": {
                    "modeled_addresses": 4,
                    "hot_addresses": 2,
                    "workload_steps": 64,
                    "verification_cadence": 8,
                    "final_absent_reads": 2,
                    "healthy_worker": {
                        "directory_probes": 4,
                        "event_probes": 4,
                        "directory_capacity": 8,
                        "directory_admission_limit": 6,
                        "event_capacity": 16,
                        "event_admission_limit": 12,
                        "max_events_per_address": 3,
                        "queue_capacity": 1
                    }
                },
                "workload_summary": {
                    "scheduled_steps": 64,
                    "reads": 28,
                    "unique_appends": 12,
                    "exact_replays": 24,
                    "per_command_history_checks": 64,
                    "periodic_sweeps": 8,
                    "periodic_read_commands": 32,
                    "final_modeled_read_commands": 4,
                    "final_absent_read_commands": 2,
                    "total_healthy_worker_commands": 104,
                    "correctness_passed": true
                },
                "schedule_blake2s256":
                    "7aaada3a41cb42562eb0b0a44f074505ca7114650cde952537921f5784ec9623",
                "final_state_blake2s256":
                    "6bb89612834a3c145355a046730399982930fa9e561c385f0f0d967c681840c6",
                "healthy_worker_trace": {
                    "queue_capacity": 1,
                    "queued_at_shutdown": 0,
                    "in_flight_at_shutdown": 0,
                    "queue_high_water": 1,
                    "accepted": 104,
                    "completed": 103,
                    "failed": 1,
                    "full_rejected": 0,
                    "not_running_rejected": 0,
                    "reply_delivery_failed": 0,
                    "stopped": true,
                    "faulted": false
                },
                "nonterminal_rejection": {
                    "attempts": 1,
                    "command_rejected": 1,
                    "followup_reads": 1,
                    "followup_read_passed": true
                },
                "terminal_fault": {
                    "worker_shape": {
                        "directory_probes": 4,
                        "event_probes": 4,
                        "directory_capacity": 4,
                        "directory_admission_limit": 2,
                        "event_capacity": 4,
                        "event_admission_limit": 2,
                        "max_events_per_address": 1,
                        "queue_capacity": 1
                    },
                    "inserted_before_fault": 1,
                    "faulting_append_failed_closed": true,
                    "post_fault_read_failed_closed": true,
                    "post_fault_append_failed_closed": true,
                    "post_fault_commands_rejected_at_admission": 2,
                    "worker_trace": {
                        "queue_capacity": 1,
                        "queued_at_shutdown": 0,
                        "in_flight_at_shutdown": 0,
                        "queue_high_water": 1,
                        "accepted": 2,
                        "completed": 1,
                        "failed": 1,
                        "full_rejected": 0,
                        "not_running_rejected": 2,
                        "reply_delivery_failed": 0,
                        "stopped": true,
                        "faulted": true
                    }
                },
                "evidence_scope": {
                    "correctness_checked": true,
                    "ci_smoke": true,
                    "generic_linux_x86_64": true,
                    "target_load_measured": false,
                    "billion_operations_completed": false,
                    "target_hardware_qualified": false,
                    "latency_measured": false,
                    "rss_measured": false,
                    "stash_measured": false,
                    "queue_load_measured": false,
                    "physical_trace_measured": false,
                    "persistence_qualified": false,
                    "recovery_qualified": false,
                    "tdx_qualified": false,
                    "source_revision_bound": false,
                    "lockfile_digest_bound": false,
                    "toolchain_identity_bound": false,
                    "binary_identity_bound": false,
                    "execution_attested": false,
                    "node_year_failure_bound": false,
                    "mainnet_gate_passed": false
                }
            }))?;
        report.validate()?;
        Ok(report)
    }

    #[test]
    fn publication_target_is_strictly_linux_x86_64() {
        assert!(is_supported_execution_target("linux", "x86_64"));
        assert!(!is_supported_execution_target("macos", "x86_64"));
        assert!(!is_supported_execution_target("linux", "aarch64"));
        assert!(!is_supported_execution_target("windows", "x86_64"));
    }

    #[test]
    fn provenance_schema_rejects_unknown_fields() {
        let mut provenance = serde_json::json!({
            "schema": STRESS_PROVENANCE_SCHEMA,
            "runner_version": "test-runner",
            "target_os": "linux",
            "target_arch": "x86_64",
            "stress_qualification_blake2s256": "00".repeat(32)
        });
        provenance["unexpected"] = serde_json::json!(true);

        assert!(serde_json::from_value::<StressQualificationProvenanceV1>(provenance).is_err());
    }

    #[test]
    fn provenance_contains_only_self_reported_context_and_digest() -> Result<(), serde_json::Error>
    {
        let provenance = StressQualificationProvenanceV1 {
            schema: STRESS_PROVENANCE_SCHEMA.to_owned(),
            runner_version: "test-runner".to_owned(),
            target_os: "linux".to_owned(),
            target_arch: "x86_64".to_owned(),
            stress_qualification_blake2s256: "00".repeat(32),
        };

        assert_eq!(
            serde_json::to_value(provenance)?,
            serde_json::json!({
                "schema": STRESS_PROVENANCE_SCHEMA,
                "runner_version": "test-runner",
                "target_os": "linux",
                "target_arch": "x86_64",
                "stress_qualification_blake2s256": "00".repeat(32)
            })
        );
        Ok(())
    }

    #[test]
    fn artifact_schema_round_trips_and_rejects_schema_tampering() -> TestResult {
        let artifact = StressQualificationArtifactV1::new(&typed_report()?)?;
        let encoded = serde_json::to_value(&artifact)?;
        let decoded: StressQualificationArtifactV1 = serde_json::from_value(encoded.clone())?;

        assert_eq!(decoded, artifact);
        assert_eq!(decoded.schema, STRESS_QUALIFICATION_SCHEMA);

        let mut wrong_schema = artifact.clone();
        wrong_schema.schema = "zaino-oram-typed-worker-stress-qualification-v2".to_owned();
        assert!(wrong_schema.validate().is_err());

        let mut unknown = encoded;
        unknown["unexpected"] = serde_json::json!(true);
        assert!(serde_json::from_value::<StressQualificationArtifactV1>(unknown).is_err());
        Ok(())
    }

    #[test]
    fn artifact_rejects_overstated_stress_evidence() -> TestResult {
        let mut report = serde_json::to_value(typed_report()?)?;
        report["evidence_scope"]["target_load_measured"] = serde_json::json!(true);
        let report: TypedWorkerStressQualificationReport = serde_json::from_value(report)?;

        assert!(StressQualificationArtifactV1::new(&report).is_err());
        Ok(())
    }

    #[test]
    fn canonical_stress_qualification_digest_is_stable() -> TestResult {
        let artifact = StressQualificationArtifactV1::new(&typed_report()?)?;
        let canonical = artifact.canonical_bytes()?;
        let decoded: StressQualificationArtifactV1 = serde_json::from_slice(&canonical)?;

        assert_eq!(decoded, artifact);
        assert_eq!(decoded.digest()?, artifact.digest()?);
        assert_eq!(
            artifact.digest()?,
            "28f7aa3aec0a30a55b4f905d7d02431090cb151dd8f08ecf73c1692dfa5319d3"
        );
        Ok(())
    }

    #[test]
    fn provenance_binds_report_digest_and_rejects_context_tampering() -> TestResult {
        let artifact = StressQualificationArtifactV1::new(&typed_report()?)?;
        let provenance = StressQualificationProvenanceV1 {
            schema: STRESS_PROVENANCE_SCHEMA.to_owned(),
            runner_version: "test-runner".to_owned(),
            target_os: "linux".to_owned(),
            target_arch: "x86_64".to_owned(),
            stress_qualification_blake2s256: artifact.digest()?,
        };
        provenance.validate(&artifact)?;

        let mut wrong_schema = provenance.clone();
        wrong_schema.schema =
            "zaino-oram-typed-worker-stress-qualification-provenance-v2".to_owned();
        assert!(wrong_schema.validate(&artifact).is_err());

        let mut empty_runner = provenance.clone();
        empty_runner.runner_version.clear();
        assert!(empty_runner.validate(&artifact).is_err());

        let mut wrong_os = provenance.clone();
        wrong_os.target_os = "macos".to_owned();
        assert!(wrong_os.validate(&artifact).is_err());

        let mut wrong_arch = provenance.clone();
        wrong_arch.target_arch = "aarch64".to_owned();
        assert!(wrong_arch.validate(&artifact).is_err());

        let mut wrong_digest = provenance;
        wrong_digest.stress_qualification_blake2s256 = "00".repeat(32);
        assert!(wrong_digest.validate(&artifact).is_err());
        Ok(())
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn stress_qualification_publication_is_exact_and_self_validating() -> TestResult {
        let parent = tempfile::tempdir()?;
        let output = parent.path().join("stress-qualification");
        let report = typed_report()?;

        publish_stress_qualification(&output, &report, "test-runner")?;

        let names = fs::read_dir(&output)?
            .map(|entry| entry.map(|entry| entry.file_name()))
            .collect::<Result<BTreeSet<_>, _>>()?;
        assert_eq!(
            names,
            BTreeSet::from([
                OsString::from(PROVENANCE_JSON),
                OsString::from(STRESS_QUALIFICATION_JSON),
                OsString::from(STRESS_QUALIFICATION_TEXT),
            ])
        );

        let artifact: StressQualificationArtifactV1 =
            serde_json::from_slice(&fs::read(output.join(STRESS_QUALIFICATION_JSON))?)?;
        artifact.validate()?;
        assert_eq!(artifact, StressQualificationArtifactV1::new(&report)?);
        let provenance: StressQualificationProvenanceV1 =
            serde_json::from_slice(&fs::read(output.join(PROVENANCE_JSON))?)?;
        provenance.validate(&artifact)?;
        assert_eq!(
            fs::read(output.join(STRESS_QUALIFICATION_TEXT))?,
            report.to_string().as_bytes()
        );
        Ok(())
    }

    #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
    #[test]
    fn unsupported_host_cannot_publish_a_stress_success_report() -> TestResult {
        let parent = tempfile::tempdir()?;
        let output = parent.path().join("stress-qualification");

        assert!(publish_stress_qualification(&output, &typed_report()?, "test-runner").is_err());
        assert!(!output.exists());
        Ok(())
    }
}
