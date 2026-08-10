//! Atomic evidence artifacts for fixed typed-worker target-load profiles.

use std::path::Path;

use serde::{Deserialize, Serialize};
use zaino_oram::{MainnetSizingQualification, TypedWorkerTargetLoadReport};

#[cfg(test)]
use crate::corpus_artifact::is_supported_execution_target;
use crate::corpus_artifact::{
    artifact_blake2s256_hex, new_os_attested_provenance, publish_derived_evidence,
    validate_os_attested_provenance, ArtifactError, ValidatedCapture, ValidatedSizing,
};

const TARGET_LOAD_SCHEMA: &str = "zaino-oram-typed-worker-target-load-v1";
const TARGET_LOAD_PROVENANCE_SCHEMA: &str = "zaino-oram-typed-worker-target-load-provenance-v1";
const TARGET_LOAD_JSON: &str = "target-load.json";
const TARGET_LOAD_TEXT: &str = "target-load.txt";
const PROVENANCE_JSON: &str = "provenance.json";
const MAX_TARGET_LOAD_JSON_BYTES: usize = 4 * 1024 * 1024;
const MAX_TARGET_LOAD_TEXT_BYTES: usize = 4 * 1024 * 1024;
const MAX_PROVENANCE_JSON_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TargetLoadArtifactV1 {
    schema: String,
    measurement_blake2s256: String,
    qualification_blake2s256: String,
    target_load: TypedWorkerTargetLoadReport,
}

impl TargetLoadArtifactV1 {
    fn new(
        target_load: &TypedWorkerTargetLoadReport,
        sizing: &MainnetSizingQualification,
        measurement_blake2s256: &str,
        qualification_blake2s256: &str,
    ) -> Result<Self, ArtifactError> {
        validate_target_load(
            target_load,
            sizing,
            measurement_blake2s256,
            qualification_blake2s256,
        )?;
        Ok(Self {
            schema: TARGET_LOAD_SCHEMA.to_owned(),
            measurement_blake2s256: measurement_blake2s256.to_owned(),
            qualification_blake2s256: qualification_blake2s256.to_owned(),
            target_load: target_load.clone(),
        })
    }

    fn validate(
        &self,
        sizing: &MainnetSizingQualification,
        measurement_blake2s256: &str,
        qualification_blake2s256: &str,
    ) -> Result<(), ArtifactError> {
        if self.schema != TARGET_LOAD_SCHEMA
            || self.measurement_blake2s256 != measurement_blake2s256
            || self.qualification_blake2s256 != qualification_blake2s256
        {
            return Err(ArtifactError::InvalidArtifact {
                reason: "typed-worker target-load schema or source lineage mismatch",
            });
        }
        validate_target_load(
            &self.target_load,
            sizing,
            measurement_blake2s256,
            qualification_blake2s256,
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
struct TargetLoadProvenanceV1 {
    schema: String,
    runner_version: String,
    target_os: String,
    target_arch: String,
    target_load_blake2s256: String,
}

impl TargetLoadProvenanceV1 {
    fn new(runner_version: &str, artifact: &TargetLoadArtifactV1) -> Result<Self, ArtifactError> {
        new_os_attested_provenance(
            runner_version,
            artifact.digest(),
            "typed-worker target-load publication requires Linux x86_64 execution",
            |runner_version, target_os, target_arch, target_load_blake2s256| Self {
                schema: TARGET_LOAD_PROVENANCE_SCHEMA.to_owned(),
                runner_version,
                target_os,
                target_arch,
                target_load_blake2s256,
            },
        )
    }

    fn validate(&self, artifact: &TargetLoadArtifactV1) -> Result<(), ArtifactError> {
        validate_os_attested_provenance(
            self.schema == TARGET_LOAD_PROVENANCE_SCHEMA,
            &self.runner_version,
            &self.target_os,
            &self.target_arch,
            "typed-worker target-load provenance is invalid",
            &self.target_load_blake2s256,
            &artifact.digest()?,
            "typed-worker target-load digest mismatch",
        )
    }
}

fn validate_target_load(
    target_load: &TypedWorkerTargetLoadReport,
    sizing: &MainnetSizingQualification,
    measurement_blake2s256: &str,
    qualification_blake2s256: &str,
) -> Result<(), ArtifactError> {
    target_load
        .validate_against(sizing, measurement_blake2s256, qualification_blake2s256)
        .map_err(|_| ArtifactError::InvalidArtifact {
            reason: "typed-worker target-load report is invalid or source-unbound",
        })
}

/// Publishes a complete, read-back-validated typed-worker target-load run.
pub(super) fn publish_target_load(
    output_dir: &Path,
    capture: &ValidatedCapture,
    sizing: &ValidatedSizing,
    target_load: &TypedWorkerTargetLoadReport,
    runner_version: &str,
) -> Result<(), ArtifactError> {
    publish_derived_evidence(
        output_dir,
        capture,
        sizing,
        || {
            TargetLoadArtifactV1::new(
                target_load,
                sizing.qualification(),
                capture.measurement_blake2s256(),
                sizing.qualification_blake2s256(),
            )
        },
        |artifact| TargetLoadProvenanceV1::new(runner_version, artifact),
        TARGET_LOAD_JSON,
        MAX_TARGET_LOAD_JSON_BYTES,
        TARGET_LOAD_TEXT,
        MAX_TARGET_LOAD_TEXT_BYTES,
        PROVENANCE_JSON,
        MAX_PROVENANCE_JSON_BYTES,
        |artifact| artifact.target_load.to_string().into_bytes(),
        |artifact| {
            artifact.validate(
                sizing.qualification(),
                capture.measurement_blake2s256(),
                sizing.qualification_blake2s256(),
            )
        },
        |provenance, artifact| provenance.validate(artifact),
        "typed-worker target-load text does not match the typed report",
        "typed-worker target-load read-back differs from the computed report",
        "typed-worker target-load provenance read-back differs from expected provenance",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::corpus_artifact::typed_test_measurement;
    use std::error::Error;
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    use std::{collections::BTreeSet, ffi::OsString, fs};
    use zaino_oram::MainnetSizingModel;
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    use zaino_oram::{run_typed_worker_target_load, TypedWorkerTargetLoadProfile};

    type TestResult<T = ()> = Result<T, Box<dyn Error>>;

    fn typed_sizing() -> TestResult<MainnetSizingQualification> {
        let measurement = typed_test_measurement()?;
        let model = MainnetSizingModel::new(0, 0, 64, 48, 128, 96, 3, 4, 20_000, 1_000_000, 3_000)?;
        Ok(measurement.apply_model(&model)?)
    }

    fn typed_report() -> TestResult<TypedWorkerTargetLoadReport> {
        let report: TypedWorkerTargetLoadReport = serde_json::from_value(serde_json::json!({
            "scenario": "typed-worker-target-load-builder-foundation-v1",
            "profile": "builder-foundation-v1",
            "backend": "rostl-circuit-oram-volatile-v1",
            "sizing_input": {
                "measurement_blake2s256": "11".repeat(32),
                "qualification_blake2s256": "22".repeat(32),
                "checkpoint_height": 0,
                "checkpoint_hash": "00040fe8ec8471911baa1db1266ea15dd06b4a8a5c453883c000b031973dce08"
            },
            "worker_shape": {
                "directory_probes": 4,
                "event_probes": 4,
                "directory_capacity": 64,
                "directory_admission_limit": 48,
                "event_capacity": 128,
                "event_admission_limit": 96,
                "max_events_per_address": 3,
                "queue_capacity": 1
            },
            "builder_envelope": {
                "min_directory_capacity": 64,
                "max_directory_capacity": 512,
                "min_directory_admission_limit": 48,
                "min_event_capacity": 128,
                "max_event_capacity": 4096,
                "min_event_admission_limit": 96,
                "min_events_per_address": 3,
                "max_events_per_address": 64
            },
            "workload_shape": {
                "measured_commands": 256,
                "measured_reads": 208,
                "measured_unique_appends": 48,
                "measured_hot_reads": 160,
                "measured_cold_reads": 48,
                "measured_hot_appends": 32,
                "measured_cold_appends": 16,
                "hot_addresses": 16,
                "reserved_directory_slots": 16,
                "reserved_event_slots": 48,
                "cold_read_class": "resident-non-hot-warmup-set"
            },
            "workload_summary": {
                "warmup_addresses": 32,
                "warmup_events": 48,
                "measured_reads": 208,
                "measured_unique_appends": 48,
                "measured_hot_reads": 160,
                "measured_cold_reads": 48,
                "measured_hot_appends": 32,
                "measured_cold_appends": 16,
                "final_directory_occupied": 48,
                "final_event_occupied": 96,
                "total_commands": 304,
                "correctness_passed": true
            },
            "logical_probe_collisions": {
                "warmup_directory_occupied_probes": 25,
                "warmup_event_occupied_probes": 32,
                "measured_directory_occupied_probes": 39,
                "measured_event_occupied_probes": 99
            },
            "schedule_blake2s256": "9d92e272c44a6eeec247c9962120f26cd89a41e0f94c1429901199a3f87cfd31",
            "final_state_blake2s256": "0532d494803ede8fcfb02978c950863f66cf2a9f1069627d646d38cc03d83c27",
            "timing": {
                "measured_phase_wall_ns": 1000000,
                "cumulative_worker_call_wait_ns": 256000,
                "percentile_method": "nearest-rank-v1",
                "all_worker_call_latency": {
                    "count": 256,
                    "total_elapsed_ns": 256000,
                    "min_ns": 1000,
                    "p50_ns": 1000,
                    "p95_ns": 1000,
                    "p99_ns": 1000,
                    "max_ns": 1000
                },
                "read_worker_call_latency": {
                    "count": 208,
                    "total_elapsed_ns": 208000,
                    "min_ns": 1000,
                    "p50_ns": 1000,
                    "p95_ns": 1000,
                    "p99_ns": 1000,
                    "max_ns": 1000
                },
                "append_worker_call_latency": {
                    "count": 48,
                    "total_elapsed_ns": 48000,
                    "min_ns": 1000,
                    "p50_ns": 1000,
                    "p95_ns": 1000,
                    "p99_ns": 1000,
                    "max_ns": 1000
                },
                "mixed_phase_commands_per_second_floor": 256000,
                "mixed_phase_read_completions_per_second_floor": 208000,
                "mixed_phase_append_completions_per_second_floor": 48000
            },
            "rss": {
                "sampling_source": "proc-status-vmrss-vmhwm",
                "measurement_scope": "whole-process-including-driver-and-runtime",
                "baseline_rss_bytes": 1000000,
                "post_spawn_rss_bytes": 2000000,
                "post_warmup_rss_bytes": 3000000,
                "post_workload_rss_bytes": 4000000,
                "process_lifetime_hwm_bytes": 5000000
            },
            "worker_trace": {
                "queue_capacity": 1,
                "queued_at_shutdown": 0,
                "in_flight_at_shutdown": 0,
                "queue_high_water": 1,
                "accepted": 304,
                "completed": 304,
                "failed": 0,
                "full_rejected": 0,
                "not_running_rejected": 0,
                "reply_delivery_failed": 0,
                "stopped": true,
                "faulted": false
            },
            "unavailable": {
                "stash_current": "backend-unobservable",
                "stash_peak": "backend-unobservable",
                "physical_access_trace": "backend-unobservable"
            },
            "evidence_scope": {
                "correctness_checked": true,
                "single_caller_builder_linux_x86_64": true,
                "sizing_bound_shape_used": true,
                "mixed_read_insert_workload_checked": true,
                "deterministic_shuffled_workload_checked": true,
                "logical_probe_collision_schedule_checked": true,
                "typed_worker_call_latency_measured": true,
                "mixed_phase_completion_rates_measured": true,
                "whole_process_rss_measured": true,
                "queue_counters_observed": true,
                "queue_contention_measured": false,
                "stash_measured": false,
                "physical_trace_measured": false,
                "persistence_qualified": false,
                "recovery_qualified": false,
                "target_hardware_qualified": false,
                "tdx_qualified": false,
                "billion_operations_completed": false,
                "source_revision_bound": false,
                "lockfile_digest_bound": false,
                "toolchain_identity_bound": false,
                "binary_identity_bound": false,
                "execution_attested": false,
                "signed_provenance": false,
                "mainnet_ready": false
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
    }

    #[test]
    fn artifact_round_trips_and_rejects_overstated_evidence() -> TestResult {
        let sizing = typed_sizing()?;
        let measurement_digest = "11".repeat(32);
        let qualification_digest = "22".repeat(32);
        let artifact = TargetLoadArtifactV1::new(
            &typed_report()?,
            &sizing,
            &measurement_digest,
            &qualification_digest,
        )?;
        let encoded = serde_json::to_value(&artifact)?;
        let decoded: TargetLoadArtifactV1 = serde_json::from_value(encoded.clone())?;
        assert_eq!(decoded, artifact);
        decoded.validate(&sizing, &measurement_digest, &qualification_digest)?;

        let mut overstated = encoded;
        overstated["target_load"]["evidence_scope"]["tdx_qualified"] = serde_json::json!(true);
        let overstated: TargetLoadArtifactV1 = serde_json::from_value(overstated)?;
        assert!(overstated
            .validate(&sizing, &measurement_digest, &qualification_digest)
            .is_err());

        let mut wrong_lineage = serde_json::to_value(&artifact)?;
        wrong_lineage["measurement_blake2s256"] = serde_json::json!("33".repeat(32));
        let wrong_lineage: TargetLoadArtifactV1 = serde_json::from_value(wrong_lineage)?;
        assert!(wrong_lineage
            .validate(&sizing, &measurement_digest, &qualification_digest)
            .is_err());
        Ok(())
    }

    #[test]
    fn provenance_binds_the_complete_target_load_report() -> TestResult {
        let artifact = TargetLoadArtifactV1::new(
            &typed_report()?,
            &typed_sizing()?,
            &"11".repeat(32),
            &"22".repeat(32),
        )?;
        let provenance = TargetLoadProvenanceV1 {
            schema: TARGET_LOAD_PROVENANCE_SCHEMA.to_owned(),
            runner_version: "test-runner".to_owned(),
            target_os: "linux".to_owned(),
            target_arch: "x86_64".to_owned(),
            target_load_blake2s256: artifact.digest()?,
        };
        provenance.validate(&artifact)?;

        let mut wrong_digest = provenance;
        wrong_digest.target_load_blake2s256 = "00".repeat(32);
        assert!(wrong_digest.validate(&artifact).is_err());
        Ok(())
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn target_load_publication_is_exact_and_self_validating() -> TestResult {
        use crate::corpus_artifact::{
            load_capture, load_sizing, publish_capture, publish_sizing, BackendKind,
            CaptureProvenance, SelectionMode, SnapshotMode,
        };

        let parent = tempfile::tempdir()?;
        let capture_dir = parent.path().join("capture");
        let sizing_dir = parent.path().join("sizing");
        let output = parent.path().join("target-load");
        let measurement = typed_test_measurement()?;
        let capture_provenance = CaptureProvenance::new(
            BackendKind::Rpc,
            SnapshotMode::NonFinalizedState,
            0,
            SelectionMode::ServiceableTip,
            "test-runner",
            &measurement,
        )?;
        publish_capture(&capture_dir, &measurement, &capture_provenance)?;
        let capture = load_capture(&capture_dir)?;
        let qualification = typed_sizing()?;
        publish_sizing(&sizing_dir, &capture, &qualification, "test-runner")?;
        let sizing = load_sizing(&sizing_dir, &capture)?;
        let report = run_typed_worker_target_load(
            TypedWorkerTargetLoadProfile::BuilderFoundationV1,
            sizing.qualification(),
            sizing.measurement_blake2s256(),
            sizing.qualification_blake2s256(),
        )?;

        publish_target_load(&output, &capture, &sizing, &report, "test-runner")?;

        let names = fs::read_dir(&output)?
            .map(|entry| entry.map(|entry| entry.file_name()))
            .collect::<Result<BTreeSet<_>, _>>()?;
        assert_eq!(
            names,
            BTreeSet::from([
                OsString::from(TARGET_LOAD_JSON),
                OsString::from(TARGET_LOAD_TEXT),
                OsString::from(PROVENANCE_JSON),
            ])
        );
        let artifact: TargetLoadArtifactV1 =
            serde_json::from_slice(&fs::read(output.join(TARGET_LOAD_JSON))?)?;
        artifact.validate(
            sizing.qualification(),
            capture.measurement_blake2s256(),
            sizing.qualification_blake2s256(),
        )?;
        let provenance: TargetLoadProvenanceV1 =
            serde_json::from_slice(&fs::read(output.join(PROVENANCE_JSON))?)?;
        provenance.validate(&artifact)?;
        assert_eq!(
            fs::read(output.join(TARGET_LOAD_TEXT))?,
            report.to_string().as_bytes()
        );
        Ok(())
    }

    #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
    #[test]
    fn unsupported_host_cannot_construct_target_load_success_provenance() -> TestResult {
        let artifact = TargetLoadArtifactV1::new(
            &typed_report()?,
            &typed_sizing()?,
            &"11".repeat(32),
            &"22".repeat(32),
        )?;
        assert!(TargetLoadProvenanceV1::new("test-runner", &artifact).is_err());
        Ok(())
    }
}
