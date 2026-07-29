//! Atomic evidence artifacts for source-bound typed-worker cold rebuilds.

use std::{path::Path, time::Duration};

use serde::{Deserialize, Serialize};
use zaino_oram::{
    MainnetCorpusMeasurement, MainnetSizingQualification, TypedWorkerColdRebuildReport,
};

use crate::corpus_artifact::{
    artifact_blake2s256_hex, publish_verified_derived_artifact, read_artifact_file,
    validate_derived_source_lineage, ArtifactDirectory, ArtifactError, ArtifactFile,
    PreverifiedSourceSnapshotV1, ValidatedCapture, ValidatedSizing,
};

const COLD_REBUILD_SCHEMA: &str = "zaino-oram-typed-worker-cold-rebuild-v1";
const COLD_REBUILD_PROVENANCE_SCHEMA: &str = "zaino-oram-typed-worker-cold-rebuild-provenance-v1";
const COLD_REBUILD_JSON: &str = "cold-rebuild.json";
const COLD_REBUILD_TEXT: &str = "cold-rebuild.txt";
const PROVENANCE_JSON: &str = "provenance.json";
const MAX_COLD_REBUILD_JSON_BYTES: usize = 4 * 1024 * 1024;
const MAX_COLD_REBUILD_TEXT_BYTES: usize = 4 * 1024 * 1024;
const MAX_PROVENANCE_JSON_BYTES: usize = 64 * 1024;

fn ensure_supported_execution_target() -> Result<(), ArtifactError> {
    if is_supported_execution_target(std::env::consts::OS, std::env::consts::ARCH) {
        Ok(())
    } else {
        Err(ArtifactError::InvalidArtifact {
            reason: "typed-worker cold-rebuild publication requires Linux x86_64 execution",
        })
    }
}

fn is_supported_execution_target(target_os: &str, target_arch: &str) -> bool {
    target_os == "linux" && target_arch == "x86_64"
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ColdRebuildArtifactV1 {
    schema: String,
    measurement_blake2s256: String,
    qualification_blake2s256: String,
    declared_rebuild_budget_seconds: u64,
    source_snapshot: PreverifiedSourceSnapshotV1,
    cold_rebuild: TypedWorkerColdRebuildReport,
}

impl ColdRebuildArtifactV1 {
    fn new(
        cold_rebuild: &TypedWorkerColdRebuildReport,
        measurement: &MainnetCorpusMeasurement,
        sizing: &MainnetSizingQualification,
        measurement_blake2s256: &str,
        qualification_blake2s256: &str,
        declared_rebuild_budget: Duration,
        source_snapshot: &PreverifiedSourceSnapshotV1,
    ) -> Result<Self, ArtifactError> {
        let declared_rebuild_budget_seconds = exact_nonzero_seconds(declared_rebuild_budget)?;
        source_snapshot.validate(measurement)?;
        validate_cold_rebuild(
            cold_rebuild,
            measurement,
            sizing,
            measurement_blake2s256,
            qualification_blake2s256,
            declared_rebuild_budget,
        )?;
        Ok(Self {
            schema: COLD_REBUILD_SCHEMA.to_owned(),
            measurement_blake2s256: measurement_blake2s256.to_owned(),
            qualification_blake2s256: qualification_blake2s256.to_owned(),
            declared_rebuild_budget_seconds,
            source_snapshot: source_snapshot.clone(),
            cold_rebuild: cold_rebuild.clone(),
        })
    }

    fn validate(
        &self,
        measurement: &MainnetCorpusMeasurement,
        sizing: &MainnetSizingQualification,
        measurement_blake2s256: &str,
        qualification_blake2s256: &str,
        declared_rebuild_budget: Duration,
        source_snapshot: &PreverifiedSourceSnapshotV1,
    ) -> Result<(), ArtifactError> {
        if self.schema != COLD_REBUILD_SCHEMA
            || self.measurement_blake2s256 != measurement_blake2s256
            || self.qualification_blake2s256 != qualification_blake2s256
            || self.declared_rebuild_budget_seconds
                != exact_nonzero_seconds(declared_rebuild_budget)?
            || self.source_snapshot != *source_snapshot
        {
            return Err(ArtifactError::InvalidArtifact {
                reason: "typed-worker cold-rebuild schema or source lineage mismatch",
            });
        }
        self.source_snapshot.validate(measurement)?;
        validate_cold_rebuild(
            &self.cold_rebuild,
            measurement,
            sizing,
            measurement_blake2s256,
            qualification_blake2s256,
            declared_rebuild_budget,
        )
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
struct ColdRebuildProvenanceV1 {
    schema: String,
    runner_version: String,
    target_os: String,
    target_arch: String,
    cold_rebuild_blake2s256: String,
}

impl ColdRebuildProvenanceV1 {
    fn new(runner_version: &str, artifact: &ColdRebuildArtifactV1) -> Result<Self, ArtifactError> {
        ensure_supported_execution_target()?;
        if runner_version.is_empty() {
            return Err(ArtifactError::InvalidArtifact {
                reason: "runner version is empty",
            });
        }
        Ok(Self {
            schema: COLD_REBUILD_PROVENANCE_SCHEMA.to_owned(),
            runner_version: runner_version.to_owned(),
            target_os: std::env::consts::OS.to_owned(),
            target_arch: std::env::consts::ARCH.to_owned(),
            cold_rebuild_blake2s256: artifact.digest()?,
        })
    }

    fn validate(&self, artifact: &ColdRebuildArtifactV1) -> Result<(), ArtifactError> {
        if self.schema != COLD_REBUILD_PROVENANCE_SCHEMA
            || self.runner_version.is_empty()
            || !is_supported_execution_target(&self.target_os, &self.target_arch)
        {
            return Err(ArtifactError::InvalidArtifact {
                reason: "typed-worker cold-rebuild provenance is invalid",
            });
        }
        if self.cold_rebuild_blake2s256 != artifact.digest()? {
            return Err(ArtifactError::InvalidArtifact {
                reason: "typed-worker cold-rebuild digest mismatch",
            });
        }
        Ok(())
    }
}

fn exact_nonzero_seconds(duration: Duration) -> Result<u64, ArtifactError> {
    if duration.is_zero() || duration.subsec_nanos() != 0 {
        Err(ArtifactError::InvalidArtifact {
            reason: "declared rebuild budget must contain nonzero whole seconds",
        })
    } else {
        Ok(duration.as_secs())
    }
}

fn validate_cold_rebuild(
    cold_rebuild: &TypedWorkerColdRebuildReport,
    measurement: &MainnetCorpusMeasurement,
    sizing: &MainnetSizingQualification,
    measurement_blake2s256: &str,
    qualification_blake2s256: &str,
    declared_rebuild_budget: Duration,
) -> Result<(), ArtifactError> {
    cold_rebuild
        .validate()
        .map_err(|_| ArtifactError::InvalidArtifact {
            reason: "typed-worker cold-rebuild report is invalid",
        })?;
    cold_rebuild
        .validate_against(
            measurement,
            sizing,
            measurement_blake2s256,
            qualification_blake2s256,
            declared_rebuild_budget,
        )
        .map_err(|_| ArtifactError::InvalidArtifact {
            reason: "typed-worker cold-rebuild report is invalid or source-unbound",
        })
}

/// Publishes one complete, read-back-validated source-bound cold-rebuild run.
pub(super) fn publish_cold_rebuild(
    output_dir: &Path,
    capture: &ValidatedCapture,
    sizing: &ValidatedSizing,
    cold_rebuild: &TypedWorkerColdRebuildReport,
    declared_rebuild_budget: Duration,
    source_snapshot: &PreverifiedSourceSnapshotV1,
    runner_version: &str,
) -> Result<(), ArtifactError> {
    validate_derived_source_lineage(capture, sizing)?;
    let artifact = ColdRebuildArtifactV1::new(
        cold_rebuild,
        capture.measurement(),
        sizing.qualification(),
        capture.measurement_blake2s256(),
        sizing.qualification_blake2s256(),
        declared_rebuild_budget,
        source_snapshot,
    )?;
    let provenance = ColdRebuildProvenanceV1::new(runner_version, &artifact)?;
    provenance.validate(&artifact)?;

    let files = [
        ArtifactFile::new(
            COLD_REBUILD_JSON,
            serde_json::to_vec_pretty(&artifact).map_err(ArtifactError::Json)?,
        ),
        ArtifactFile::new(COLD_REBUILD_TEXT, cold_rebuild.to_string().into_bytes()),
        ArtifactFile::new(
            PROVENANCE_JSON,
            serde_json::to_vec_pretty(&provenance).map_err(ArtifactError::Json)?,
        ),
    ];

    publish_verified_derived_artifact(output_dir, capture, sizing, &files, |stage| {
        validate_staged_cold_rebuild(
            stage,
            capture,
            sizing,
            declared_rebuild_budget,
            source_snapshot,
            &artifact,
            &provenance,
        )
    })
}

fn validate_staged_cold_rebuild(
    stage: &ArtifactDirectory,
    capture: &ValidatedCapture,
    sizing: &ValidatedSizing,
    declared_rebuild_budget: Duration,
    source_snapshot: &PreverifiedSourceSnapshotV1,
    expected_artifact: &ColdRebuildArtifactV1,
    expected_provenance: &ColdRebuildProvenanceV1,
) -> Result<(), ArtifactError> {
    let cold_rebuild_json =
        read_artifact_file(stage, COLD_REBUILD_JSON, MAX_COLD_REBUILD_JSON_BYTES)?;
    let cold_rebuild_text =
        read_artifact_file(stage, COLD_REBUILD_TEXT, MAX_COLD_REBUILD_TEXT_BYTES)?;
    let provenance_json = read_artifact_file(stage, PROVENANCE_JSON, MAX_PROVENANCE_JSON_BYTES)?;

    let artifact: ColdRebuildArtifactV1 =
        serde_json::from_slice(&cold_rebuild_json).map_err(ArtifactError::Json)?;
    validate_derived_source_lineage(capture, sizing)?;
    artifact.validate(
        capture.measurement(),
        sizing.qualification(),
        capture.measurement_blake2s256(),
        sizing.qualification_blake2s256(),
        declared_rebuild_budget,
        source_snapshot,
    )?;
    let provenance: ColdRebuildProvenanceV1 =
        serde_json::from_slice(&provenance_json).map_err(ArtifactError::Json)?;
    provenance.validate(&artifact)?;
    if cold_rebuild_text != artifact.cold_rebuild.to_string().as_bytes() {
        return Err(ArtifactError::InvalidArtifact {
            reason: "typed-worker cold-rebuild text does not match the typed report",
        });
    }
    if artifact != *expected_artifact {
        return Err(ArtifactError::InvalidArtifact {
            reason: "typed-worker cold-rebuild read-back differs from the computed report",
        });
    }
    if provenance != *expected_provenance {
        return Err(ArtifactError::InvalidArtifact {
            reason:
                "typed-worker cold-rebuild provenance read-back differs from expected provenance",
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    use crate::corpus_artifact::{
        load_capture, load_sizing, publish_capture, publish_sizing, CaptureProvenance,
        SelectionMode, SnapshotMode,
    };
    use crate::corpus_artifact::{typed_test_measurement, BackendKind};
    use std::error::Error;
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    use std::{collections::BTreeSet, ffi::OsString, fs};
    use zaino_oram::{MainnetCorpusMeasurement, MainnetSizingModel};

    type TestResult<T = ()> = Result<T, Box<dyn Error>>;

    fn typed_sizing(
        measurement: &MainnetCorpusMeasurement,
    ) -> TestResult<MainnetSizingQualification> {
        let model = MainnetSizingModel::new(0, 0, 64, 48, 128, 96, 3, 4, 20_000, 1_000_000, 3_000)?;
        Ok(measurement.apply_model(&model)?)
    }

    fn typed_report(
        measurement: &MainnetCorpusMeasurement,
        sizing: &MainnetSizingQualification,
        measurement_digest: &str,
        sizing_digest: &str,
        declared_rebuild_budget: Duration,
    ) -> TestResult<TypedWorkerColdRebuildReport> {
        sizing.validate_against(measurement)?;
        let declared_rebuild_budget_ns = u64::try_from(declared_rebuild_budget.as_nanos())?;
        Ok(serde_json::from_value(serde_json::json!({
            "scenario": "typed-worker-source-bound-cold-rebuild-v1",
            "profile": "source-bound-builder-v1",
            "backend": "rostl-circuit-oram-volatile-v1",
            "source": {
                "measurement_blake2s256": measurement_digest,
                "qualification_blake2s256": sizing_digest,
                "checkpoint_height": 0,
                "checkpoint_hash": "00040fe8ec8471911baa1db1266ea15dd06b4a8a5c453883c000b031973dce08",
                "expected_blocks": 1,
                "measured_outputs": 0
            },
            "worker_shape": {
                "directory_probes": 4,
                "event_probes": 4,
                "directory_capacity": 64,
                "directory_admission_limit": 48,
                "event_capacity": 128,
                "event_admission_limit": 96,
                "max_events_per_address": 3,
                "queue_capacity": 1,
                "max_seen_outputs": 1,
                "max_live_outputs": 1
            },
            "projection_epoch": 1,
            "applied_blocks": 1,
            "final_checkpoint_height": 0,
            "final_checkpoint_hash": "00040fe8ec8471911baa1db1266ea15dd06b4a8a5c453883c000b031973dce08",
            "semantic_event_log_root_blake2s256": "33".repeat(32),
            "timing": {
                "declared_rebuild_budget_ns": declared_rebuild_budget_ns,
                "construction_ns": 1,
                "replay_to_ready_ns": 2,
                "finish_call_ns": 1,
                "ready_ns": 4,
                "shutdown_ns": 1,
                "total_lifecycle_ns": 5,
                "declared_rebuild_budget_passed": true
            },
            "rss": {
                "baseline_rss_bytes": 1_000_000,
                "post_spawn_rss_bytes": 2_000_000,
                "ready_rss_bytes": 3_000_000,
                "post_shutdown_rss_bytes": 2_000_000,
                "process_lifetime_hwm_bytes": 4_000_000
            },
            "evidence_scope": {
                "mainnet_genesis_and_chain_continuity_validated": true,
                "source_measurement_recomputed_and_matched": true,
                "exact_source_checkpoint_reached": true,
                "complete_genesis_forward_replay": true,
                "real_typed_rostl": true,
                "whole_process_rss_measured": true,
                "projection_rebuild_budget_measured": true,
                "source_cache_state_controlled": false,
                "durable_oram_state": false,
                "authenticated_manifest_used": false,
                "external_freshness_witness_used": false,
                "production_key_owner_used": false,
                "full_service_rto_measured": false,
                "target_hardware_qualified": false,
                "physical_trace_measured": false,
                "tdx_qualified": false,
                "execution_attested": false,
                "signed_provenance": false,
                "mainnet_ready": false
            }
        }))?)
    }

    #[test]
    fn publication_target_is_strictly_linux_x86_64() {
        assert!(is_supported_execution_target("linux", "x86_64"));
        assert!(!is_supported_execution_target("macos", "x86_64"));
        assert!(!is_supported_execution_target("linux", "aarch64"));
    }

    #[test]
    fn artifact_round_trips_and_rejects_lineage_and_budget_tampering() -> TestResult {
        let measurement = typed_test_measurement()?;
        let sizing = typed_sizing(&measurement)?;
        let measurement_digest = "11".repeat(32);
        let sizing_digest = "22".repeat(32);
        let declared_rebuild_budget = Duration::from_secs(60);
        let source_snapshot =
            PreverifiedSourceSnapshotV1::new_verified(BackendKind::Rpc, 0, &measurement)?;
        let report = typed_report(
            &measurement,
            &sizing,
            &measurement_digest,
            &sizing_digest,
            declared_rebuild_budget,
        )?;
        let artifact = ColdRebuildArtifactV1::new(
            &report,
            &measurement,
            &sizing,
            &measurement_digest,
            &sizing_digest,
            declared_rebuild_budget,
            &source_snapshot,
        )?;
        let encoded = serde_json::to_value(&artifact)?;
        let decoded: ColdRebuildArtifactV1 = serde_json::from_value(encoded.clone())?;
        assert_eq!(decoded, artifact);
        decoded.validate(
            &measurement,
            &sizing,
            &measurement_digest,
            &sizing_digest,
            declared_rebuild_budget,
            &source_snapshot,
        )?;

        let missed_budget = Duration::from_secs(1);
        let mut missed_value = serde_json::to_value(typed_report(
            &measurement,
            &sizing,
            &measurement_digest,
            &sizing_digest,
            missed_budget,
        )?)?;
        missed_value["timing"]["construction_ns"] = serde_json::json!(100_000_000);
        missed_value["timing"]["replay_to_ready_ns"] = serde_json::json!(900_000_000);
        missed_value["timing"]["finish_call_ns"] = serde_json::json!(100_000_000);
        missed_value["timing"]["ready_ns"] = serde_json::json!(1_100_000_000);
        missed_value["timing"]["shutdown_ns"] = serde_json::json!(100_000_000);
        missed_value["timing"]["total_lifecycle_ns"] = serde_json::json!(1_200_000_000);
        missed_value["timing"]["declared_rebuild_budget_passed"] = serde_json::json!(false);
        let missed_report: TypedWorkerColdRebuildReport = serde_json::from_value(missed_value)?;
        assert!(!missed_report.declared_rebuild_budget_passed());
        let missed_artifact = ColdRebuildArtifactV1::new(
            &missed_report,
            &measurement,
            &sizing,
            &measurement_digest,
            &sizing_digest,
            missed_budget,
            &source_snapshot,
        )?;
        missed_artifact.validate(
            &measurement,
            &sizing,
            &measurement_digest,
            &sizing_digest,
            missed_budget,
            &source_snapshot,
        )?;

        let mut wrong_lineage = artifact.clone();
        wrong_lineage.measurement_blake2s256 = "33".repeat(32);
        assert!(wrong_lineage
            .validate(
                &measurement,
                &sizing,
                &measurement_digest,
                &sizing_digest,
                declared_rebuild_budget,
                &source_snapshot,
            )
            .is_err());

        let mut wrong_budget = artifact.clone();
        wrong_budget.declared_rebuild_budget_seconds = 61;
        assert!(wrong_budget
            .validate(
                &measurement,
                &sizing,
                &measurement_digest,
                &sizing_digest,
                declared_rebuild_budget,
                &source_snapshot,
            )
            .is_err());

        let mut wrong_snapshot_value = serde_json::to_value(artifact)?;
        wrong_snapshot_value["source_snapshot"]["source_cache_mode"] = serde_json::json!("cold");
        let wrong_snapshot: ColdRebuildArtifactV1 = serde_json::from_value(wrong_snapshot_value)?;
        assert!(wrong_snapshot
            .validate(
                &measurement,
                &sizing,
                &measurement_digest,
                &sizing_digest,
                declared_rebuild_budget,
                &source_snapshot,
            )
            .is_err());
        Ok(())
    }

    #[test]
    fn provenance_detects_report_tampering() -> TestResult {
        let measurement = typed_test_measurement()?;
        let sizing = typed_sizing(&measurement)?;
        let measurement_digest = "11".repeat(32);
        let sizing_digest = "22".repeat(32);
        let declared_rebuild_budget = Duration::from_secs(60);
        let source_snapshot =
            PreverifiedSourceSnapshotV1::new_verified(BackendKind::Rpc, 0, &measurement)?;
        let report = typed_report(
            &measurement,
            &sizing,
            &measurement_digest,
            &sizing_digest,
            declared_rebuild_budget,
        )?;
        let artifact = ColdRebuildArtifactV1::new(
            &report,
            &measurement,
            &sizing,
            &measurement_digest,
            &sizing_digest,
            declared_rebuild_budget,
            &source_snapshot,
        )?;
        let mut provenance = ColdRebuildProvenanceV1 {
            schema: COLD_REBUILD_PROVENANCE_SCHEMA.to_owned(),
            runner_version: "test-runner".to_owned(),
            target_os: "linux".to_owned(),
            target_arch: "x86_64".to_owned(),
            cold_rebuild_blake2s256: artifact.digest()?,
        };
        provenance.validate(&artifact)?;
        provenance.cold_rebuild_blake2s256 = "00".repeat(32);
        assert!(provenance.validate(&artifact).is_err());
        Ok(())
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn cold_rebuild_publication_is_exact_and_self_validating() -> TestResult {
        let parent = tempfile::tempdir()?;
        let capture_dir = parent.path().join("capture");
        let sizing_dir = parent.path().join("sizing");
        let output_dir = parent.path().join("cold-rebuild");
        let measurement = typed_test_measurement()?;
        let provenance = CaptureProvenance::new(
            BackendKind::Rpc,
            SnapshotMode::NonFinalizedState,
            0,
            SelectionMode::ServiceableTip,
            "test-runner",
            &measurement,
        )?;
        publish_capture(&capture_dir, &measurement, &provenance)?;
        let capture = load_capture(&capture_dir)?;
        let qualification = typed_sizing(capture.measurement())?;
        publish_sizing(&sizing_dir, &capture, &qualification, "test-runner")?;
        let sizing = load_sizing(&sizing_dir, &capture)?;
        let declared_rebuild_budget = Duration::from_secs(60);
        let source_snapshot =
            PreverifiedSourceSnapshotV1::new_verified(BackendKind::Rpc, 0, capture.measurement())?;
        let report = typed_report(
            capture.measurement(),
            sizing.qualification(),
            capture.measurement_blake2s256(),
            sizing.qualification_blake2s256(),
            declared_rebuild_budget,
        )?;

        publish_cold_rebuild(
            &output_dir,
            &capture,
            &sizing,
            &report,
            declared_rebuild_budget,
            &source_snapshot,
            "test-runner",
        )?;

        let names = fs::read_dir(&output_dir)?
            .map(|entry| entry.map(|entry| entry.file_name()))
            .collect::<Result<BTreeSet<_>, _>>()?;
        assert_eq!(
            names,
            BTreeSet::from([
                OsString::from(COLD_REBUILD_JSON),
                OsString::from(COLD_REBUILD_TEXT),
                OsString::from(PROVENANCE_JSON),
            ])
        );
        let artifact: ColdRebuildArtifactV1 =
            serde_json::from_slice(&fs::read(output_dir.join(COLD_REBUILD_JSON))?)?;
        artifact.validate(
            capture.measurement(),
            sizing.qualification(),
            capture.measurement_blake2s256(),
            sizing.qualification_blake2s256(),
            declared_rebuild_budget,
            &source_snapshot,
        )?;
        let provenance: ColdRebuildProvenanceV1 =
            serde_json::from_slice(&fs::read(output_dir.join(PROVENANCE_JSON))?)?;
        provenance.validate(&artifact)?;
        assert_eq!(
            fs::read(output_dir.join(COLD_REBUILD_TEXT))?,
            report.to_string().as_bytes()
        );
        Ok(())
    }
}
