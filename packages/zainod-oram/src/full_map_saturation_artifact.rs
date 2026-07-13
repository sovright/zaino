//! Atomic evidence artifacts for fixed typed-worker full-map saturation profiles.

use std::path::Path;

use serde::{Deserialize, Serialize};
use zaino_oram::TypedWorkerFullMapSaturationReport;

use crate::corpus_artifact::{
    artifact_blake2s256_hex, publish_verified_artifact, read_artifact_file, ArtifactDirectory,
    ArtifactError, ArtifactFile,
};

const FULL_MAP_SATURATION_SCHEMA: &str = "zaino-oram-full-map-saturation-v1";
const FULL_MAP_SATURATION_PROVENANCE_SCHEMA: &str = "zaino-oram-full-map-saturation-provenance-v1";
const FULL_MAP_SATURATION_JSON: &str = "full-map-saturation.json";
const FULL_MAP_SATURATION_TEXT: &str = "full-map-saturation.txt";
const PROVENANCE_JSON: &str = "provenance.json";
const MAX_FULL_MAP_SATURATION_JSON_BYTES: usize = 4 * 1024 * 1024;
const MAX_FULL_MAP_SATURATION_TEXT_BYTES: usize = 4 * 1024 * 1024;
const MAX_PROVENANCE_JSON_BYTES: usize = 64 * 1024;

fn ensure_supported_execution_target() -> Result<(), ArtifactError> {
    if is_supported_execution_target(std::env::consts::OS, std::env::consts::ARCH) {
        Ok(())
    } else {
        Err(ArtifactError::InvalidArtifact {
            reason: "typed-worker full-map saturation publication requires Linux x86_64 execution",
        })
    }
}

fn is_supported_execution_target(target_os: &str, target_arch: &str) -> bool {
    target_os == "linux" && target_arch == "x86_64"
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FullMapSaturationArtifactV1 {
    schema: String,
    full_map_saturation: TypedWorkerFullMapSaturationReport,
}

impl FullMapSaturationArtifactV1 {
    fn new(
        full_map_saturation: &TypedWorkerFullMapSaturationReport,
    ) -> Result<Self, ArtifactError> {
        validate_full_map_saturation(full_map_saturation)?;
        Ok(Self {
            schema: FULL_MAP_SATURATION_SCHEMA.to_owned(),
            full_map_saturation: full_map_saturation.clone(),
        })
    }

    fn validate(&self) -> Result<(), ArtifactError> {
        if self.schema != FULL_MAP_SATURATION_SCHEMA {
            return Err(ArtifactError::InvalidArtifact {
                reason: "typed-worker full-map saturation schema mismatch",
            });
        }
        validate_full_map_saturation(&self.full_map_saturation)
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
struct FullMapSaturationProvenanceV1 {
    schema: String,
    runner_version: String,
    target_os: String,
    target_arch: String,
    full_map_saturation_blake2s256: String,
}

impl FullMapSaturationProvenanceV1 {
    fn new(
        runner_version: &str,
        artifact: &FullMapSaturationArtifactV1,
    ) -> Result<Self, ArtifactError> {
        ensure_supported_execution_target()?;
        if runner_version.is_empty() {
            return Err(ArtifactError::InvalidArtifact {
                reason: "runner version is empty",
            });
        }
        Ok(Self {
            schema: FULL_MAP_SATURATION_PROVENANCE_SCHEMA.to_owned(),
            runner_version: runner_version.to_owned(),
            target_os: std::env::consts::OS.to_owned(),
            target_arch: std::env::consts::ARCH.to_owned(),
            full_map_saturation_blake2s256: artifact.digest()?,
        })
    }

    fn validate(&self, artifact: &FullMapSaturationArtifactV1) -> Result<(), ArtifactError> {
        if self.schema != FULL_MAP_SATURATION_PROVENANCE_SCHEMA
            || self.runner_version.is_empty()
            || !is_supported_execution_target(&self.target_os, &self.target_arch)
        {
            return Err(ArtifactError::InvalidArtifact {
                reason: "typed-worker full-map saturation provenance is invalid",
            });
        }
        if self.full_map_saturation_blake2s256 != artifact.digest()? {
            return Err(ArtifactError::InvalidArtifact {
                reason: "typed-worker full-map saturation digest mismatch",
            });
        }
        Ok(())
    }
}

fn validate_full_map_saturation(
    full_map_saturation: &TypedWorkerFullMapSaturationReport,
) -> Result<(), ArtifactError> {
    full_map_saturation
        .validate()
        .map_err(|_| ArtifactError::InvalidArtifact {
            reason: "typed-worker full-map saturation report is invalid",
        })
}

/// Publishes a complete, read-back-validated typed-worker full-map saturation run.
pub(super) fn publish_full_map_saturation(
    output_dir: &Path,
    full_map_saturation: &TypedWorkerFullMapSaturationReport,
    runner_version: &str,
) -> Result<(), ArtifactError> {
    let artifact = FullMapSaturationArtifactV1::new(full_map_saturation)?;
    let provenance = FullMapSaturationProvenanceV1::new(runner_version, &artifact)?;
    provenance.validate(&artifact)?;

    let files = [
        ArtifactFile::new(
            FULL_MAP_SATURATION_JSON,
            serde_json::to_vec_pretty(&artifact).map_err(ArtifactError::Json)?,
        ),
        ArtifactFile::new(
            FULL_MAP_SATURATION_TEXT,
            full_map_saturation.to_string().into_bytes(),
        ),
        ArtifactFile::new(
            PROVENANCE_JSON,
            serde_json::to_vec_pretty(&provenance).map_err(ArtifactError::Json)?,
        ),
    ];

    publish_verified_artifact(output_dir, &files, |stage| {
        validate_staged_full_map_saturation(stage, &artifact, &provenance)
    })
}

fn validate_staged_full_map_saturation(
    stage: &ArtifactDirectory,
    expected_artifact: &FullMapSaturationArtifactV1,
    expected_provenance: &FullMapSaturationProvenanceV1,
) -> Result<(), ArtifactError> {
    let full_map_saturation_json = read_artifact_file(
        stage,
        FULL_MAP_SATURATION_JSON,
        MAX_FULL_MAP_SATURATION_JSON_BYTES,
    )?;
    let full_map_saturation_text = read_artifact_file(
        stage,
        FULL_MAP_SATURATION_TEXT,
        MAX_FULL_MAP_SATURATION_TEXT_BYTES,
    )?;
    let provenance_json = read_artifact_file(stage, PROVENANCE_JSON, MAX_PROVENANCE_JSON_BYTES)?;

    let artifact: FullMapSaturationArtifactV1 =
        serde_json::from_slice(&full_map_saturation_json).map_err(ArtifactError::Json)?;
    artifact.validate()?;
    let provenance: FullMapSaturationProvenanceV1 =
        serde_json::from_slice(&provenance_json).map_err(ArtifactError::Json)?;
    provenance.validate(&artifact)?;
    if full_map_saturation_text != artifact.full_map_saturation.to_string().as_bytes() {
        return Err(ArtifactError::InvalidArtifact {
            reason: "typed-worker full-map saturation text does not match the typed report",
        });
    }
    if artifact != *expected_artifact {
        return Err(ArtifactError::InvalidArtifact {
            reason: "typed-worker full-map saturation read-back differs from the computed report",
        });
    }
    if provenance != *expected_provenance {
        return Err(ArtifactError::InvalidArtifact {
            reason: "typed-worker full-map saturation provenance read-back differs from the expected provenance",
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

    fn typed_report() -> TestResult<TypedWorkerFullMapSaturationReport> {
        let report: TypedWorkerFullMapSaturationReport =
            serde_json::from_value(serde_json::json!({
                "scenario": "typed-worker-full-map-saturation-v1",
                "profile": "full-map-saturation-v1",
                "backend": "rostl-circuit-oram-volatile-v1",
                "directory_boundary": {
                    "boundary": "directory-admission",
                    "worker_shape": {
                        "directory_probes": 4,
                        "event_probes": 4,
                        "directory_capacity": 8,
                        "directory_admission_limit": 6,
                        "event_capacity": 16,
                        "event_admission_limit": 12,
                        "max_events_per_address": 8,
                        "queue_capacity": 1
                    },
                    "pre_fault_occupancy": {
                        "directory_occupied": 6,
                        "directory_admission_limit": 6,
                        "directory_admission_reserve": 0,
                        "directory_capacity": 8,
                        "directory_physical_reserve": 2,
                        "event_occupied": 6,
                        "event_admission_limit": 12,
                        "event_admission_reserve": 6,
                        "event_capacity": 16,
                        "event_physical_reserve": 10
                    },
                    "checks": {
                        "unique_appends": 6,
                        "full_history_reads": 6,
                        "exact_replays": 6,
                        "absent_reads": 2,
                        "cross_address_rejections": 1,
                        "followup_healthy_reads": 1,
                        "faulting_append_failed_closed": true,
                        "post_fault_read_failed_closed": true,
                        "post_fault_append_failed_closed": true,
                        "post_fault_commands_rejected_at_admission": 2,
                        "correctness_passed": true
                    },
                    "schedule_blake2s256":
                        "df03dc8b7b007c2b014245b561ec2cd1bf045cf0e9aeb7b5c1a2ed9f9f93991b",
                    "final_state_blake2s256":
                        "79aae8224fcbea42e2de93745c28394c1c43b525248ed80a0851e303de835f2b",
                    "boundary_condition": {
                        "directory_admission_boundary_reached": true,
                        "event_admission_boundary_reached": false,
                        "per_address_event_boundary_reached": false,
                        "physical_capacity_reached": false
                    },
                    "worker_trace": {
                        "queue_capacity": 1,
                        "queued_at_shutdown": 0,
                        "in_flight_at_shutdown": 0,
                        "queue_high_water": 1,
                        "accepted": 23,
                        "completed": 21,
                        "failed": 2,
                        "full_rejected": 0,
                        "not_running_rejected": 2,
                        "reply_delivery_failed": 0,
                        "stopped": true,
                        "faulted": true
                    }
                },
                "event_boundary": {
                    "boundary": "event-admission",
                    "worker_shape": {
                        "directory_probes": 4,
                        "event_probes": 4,
                        "directory_capacity": 8,
                        "directory_admission_limit": 6,
                        "event_capacity": 16,
                        "event_admission_limit": 12,
                        "max_events_per_address": 8,
                        "queue_capacity": 1
                    },
                    "pre_fault_occupancy": {
                        "directory_occupied": 4,
                        "directory_admission_limit": 6,
                        "directory_admission_reserve": 2,
                        "directory_capacity": 8,
                        "directory_physical_reserve": 4,
                        "event_occupied": 12,
                        "event_admission_limit": 12,
                        "event_admission_reserve": 0,
                        "event_capacity": 16,
                        "event_physical_reserve": 4
                    },
                    "checks": {
                        "unique_appends": 12,
                        "full_history_reads": 4,
                        "exact_replays": 12,
                        "absent_reads": 2,
                        "cross_address_rejections": 1,
                        "followup_healthy_reads": 1,
                        "faulting_append_failed_closed": true,
                        "post_fault_read_failed_closed": true,
                        "post_fault_append_failed_closed": true,
                        "post_fault_commands_rejected_at_admission": 2,
                        "correctness_passed": true
                    },
                    "schedule_blake2s256":
                        "0992fc8de63fc568d2eab012c4a102ddb8bfcbb33122928fa97f84712a2acde8",
                    "final_state_blake2s256":
                        "b5a2a2088377819fdbf728d65c3b54d0e961d6773fcc141ae29b2be71a78b60c",
                    "boundary_condition": {
                        "directory_admission_boundary_reached": false,
                        "event_admission_boundary_reached": true,
                        "per_address_event_boundary_reached": false,
                        "physical_capacity_reached": false
                    },
                    "worker_trace": {
                        "queue_capacity": 1,
                        "queued_at_shutdown": 0,
                        "in_flight_at_shutdown": 0,
                        "queue_high_water": 1,
                        "accepted": 33,
                        "completed": 31,
                        "failed": 2,
                        "full_rejected": 0,
                        "not_running_rejected": 2,
                        "reply_delivery_failed": 0,
                        "stopped": true,
                        "faulted": true
                    }
                },
                "evidence_scope": {
                    "deterministic_small_table_correctness_checked": true,
                    "logical_directory_admission_reached": true,
                    "logical_event_admission_reached": true,
                    "physical_capacity_reached": false,
                    "random_target_load_measured": false,
                    "adversarial_target_load_measured": false,
                    "billion_operations_completed": false,
                    "latency_measured": false,
                    "rss_measured": false,
                    "stash_measured": false,
                    "queue_load_measured": false,
                    "persistence_qualified": false,
                    "recovery_qualified": false,
                    "physical_trace_measured": false,
                    "target_hardware_qualified": false,
                    "tdx_qualified": false,
                    "source_revision_bound": false,
                    "lockfile_digest_bound": false,
                    "toolchain_identity_bound": false,
                    "binary_identity_bound": false,
                    "execution_attested": false,
                    "mainnet_sizing_qualified": false,
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
            "schema": FULL_MAP_SATURATION_PROVENANCE_SCHEMA,
            "runner_version": "test-runner",
            "target_os": "linux",
            "target_arch": "x86_64",
            "full_map_saturation_blake2s256": "00".repeat(32)
        });
        provenance["unexpected"] = serde_json::json!(true);

        assert!(serde_json::from_value::<FullMapSaturationProvenanceV1>(provenance).is_err());
    }

    #[test]
    fn provenance_contains_only_self_reported_context_and_digest() -> Result<(), serde_json::Error>
    {
        let provenance = FullMapSaturationProvenanceV1 {
            schema: FULL_MAP_SATURATION_PROVENANCE_SCHEMA.to_owned(),
            runner_version: "test-runner".to_owned(),
            target_os: "linux".to_owned(),
            target_arch: "x86_64".to_owned(),
            full_map_saturation_blake2s256: "00".repeat(32),
        };

        assert_eq!(
            serde_json::to_value(provenance)?,
            serde_json::json!({
                "schema": FULL_MAP_SATURATION_PROVENANCE_SCHEMA,
                "runner_version": "test-runner",
                "target_os": "linux",
                "target_arch": "x86_64",
                "full_map_saturation_blake2s256": "00".repeat(32)
            })
        );
        Ok(())
    }

    #[test]
    fn artifact_schema_round_trips_and_rejects_tampering() -> TestResult {
        let artifact = FullMapSaturationArtifactV1::new(&typed_report()?)?;
        let encoded = serde_json::to_value(&artifact)?;
        let decoded: FullMapSaturationArtifactV1 = serde_json::from_value(encoded.clone())?;

        assert_eq!(decoded, artifact);
        assert_eq!(decoded.schema, FULL_MAP_SATURATION_SCHEMA);

        let mut wrong_schema = artifact.clone();
        wrong_schema.schema = "zaino-oram-full-map-saturation-v2".to_owned();
        assert!(wrong_schema.validate().is_err());

        let mut unknown = encoded;
        unknown["unexpected"] = serde_json::json!(true);
        assert!(serde_json::from_value::<FullMapSaturationArtifactV1>(unknown).is_err());
        Ok(())
    }

    #[test]
    fn artifact_rejects_overstated_full_map_evidence() -> TestResult {
        let mut report = serde_json::to_value(typed_report()?)?;
        report["evidence_scope"]["physical_capacity_reached"] = serde_json::json!(true);
        let report: TypedWorkerFullMapSaturationReport = serde_json::from_value(report)?;

        assert!(FullMapSaturationArtifactV1::new(&report).is_err());
        Ok(())
    }

    #[test]
    fn canonical_full_map_saturation_digest_is_stable() -> TestResult {
        let artifact = FullMapSaturationArtifactV1::new(&typed_report()?)?;
        let canonical = artifact.canonical_bytes()?;
        let decoded: FullMapSaturationArtifactV1 = serde_json::from_slice(&canonical)?;

        assert_eq!(decoded, artifact);
        assert_eq!(decoded.digest()?, artifact.digest()?);
        assert_eq!(
            artifact.digest()?,
            "ffe052da5c479479af1fa262d288531371bfc441d6caa755014487cd654a00e1"
        );
        Ok(())
    }

    #[test]
    fn provenance_binds_report_digest_and_rejects_context_tampering() -> TestResult {
        let artifact = FullMapSaturationArtifactV1::new(&typed_report()?)?;
        let provenance = FullMapSaturationProvenanceV1 {
            schema: FULL_MAP_SATURATION_PROVENANCE_SCHEMA.to_owned(),
            runner_version: "test-runner".to_owned(),
            target_os: "linux".to_owned(),
            target_arch: "x86_64".to_owned(),
            full_map_saturation_blake2s256: artifact.digest()?,
        };
        provenance.validate(&artifact)?;

        let mut wrong_schema = provenance.clone();
        wrong_schema.schema = "zaino-oram-full-map-saturation-provenance-v2".to_owned();
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
        wrong_digest.full_map_saturation_blake2s256 = "00".repeat(32);
        assert!(wrong_digest.validate(&artifact).is_err());
        Ok(())
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn full_map_saturation_publication_is_exact_and_self_validating() -> TestResult {
        let parent = tempfile::tempdir()?;
        let output = parent.path().join("full-map-saturation");
        let report = typed_report()?;

        publish_full_map_saturation(&output, &report, "test-runner")?;

        let names = fs::read_dir(&output)?
            .map(|entry| entry.map(|entry| entry.file_name()))
            .collect::<Result<BTreeSet<_>, _>>()?;
        assert_eq!(
            names,
            BTreeSet::from([
                OsString::from(FULL_MAP_SATURATION_JSON),
                OsString::from(FULL_MAP_SATURATION_TEXT),
                OsString::from(PROVENANCE_JSON),
            ])
        );

        let artifact: FullMapSaturationArtifactV1 =
            serde_json::from_slice(&fs::read(output.join(FULL_MAP_SATURATION_JSON))?)?;
        artifact.validate()?;
        assert_eq!(artifact, FullMapSaturationArtifactV1::new(&report)?);
        let provenance: FullMapSaturationProvenanceV1 =
            serde_json::from_slice(&fs::read(output.join(PROVENANCE_JSON))?)?;
        provenance.validate(&artifact)?;
        assert_eq!(
            fs::read(output.join(FULL_MAP_SATURATION_TEXT))?,
            report.to_string().as_bytes()
        );
        Ok(())
    }

    #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
    #[test]
    fn unsupported_host_cannot_publish_full_map_saturation_success() -> TestResult {
        let parent = tempfile::tempdir()?;
        let output = parent.path().join("full-map-saturation");

        assert!(publish_full_map_saturation(&output, &typed_report()?, "test-runner").is_err());
        assert!(!output.exists());
        Ok(())
    }
}
