//! Atomic evidence artifacts for the fixed typed-worker correctness scenario.

use std::path::Path;

use serde::{Deserialize, Serialize};
use zaino_oram::TypedWorkerQualificationReport;

use crate::corpus_artifact::{
    artifact_blake2s256_hex, publish_verified_artifact, read_artifact_file, ArtifactDirectory,
    ArtifactError, ArtifactFile,
};

const QUALIFICATION_SCHEMA: &str = "zaino-oram-typed-worker-qualification-v1";
const QUALIFICATION_PROVENANCE_SCHEMA: &str = "zaino-oram-typed-worker-qualification-provenance-v1";
const QUALIFICATION_JSON: &str = "qualification.json";
const QUALIFICATION_TEXT: &str = "qualification.txt";
const PROVENANCE_JSON: &str = "provenance.json";
const MAX_QUALIFICATION_JSON_BYTES: usize = 4 * 1024 * 1024;
const MAX_QUALIFICATION_TEXT_BYTES: usize = 4 * 1024 * 1024;
const MAX_PROVENANCE_JSON_BYTES: usize = 64 * 1024;

fn ensure_supported_execution_target() -> Result<(), ArtifactError> {
    if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        Ok(())
    } else {
        Err(ArtifactError::InvalidArtifact {
            reason: "typed-worker qualification publication requires Linux x86_64 execution",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct QualificationArtifactV1 {
    schema: String,
    qualification: TypedWorkerQualificationReport,
}

impl QualificationArtifactV1 {
    fn new(qualification: &TypedWorkerQualificationReport) -> Result<Self, ArtifactError> {
        validate_qualification(qualification)?;
        Ok(Self {
            schema: QUALIFICATION_SCHEMA.to_owned(),
            qualification: qualification.clone(),
        })
    }

    fn validate(&self) -> Result<(), ArtifactError> {
        if self.schema != QUALIFICATION_SCHEMA {
            return Err(ArtifactError::InvalidArtifact {
                reason: "typed-worker qualification schema mismatch",
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
struct QualificationProvenanceV1 {
    schema: String,
    runner_version: String,
    target_os: String,
    target_arch: String,
    qualification_blake2s256: String,
}

impl QualificationProvenanceV1 {
    fn new(
        runner_version: &str,
        artifact: &QualificationArtifactV1,
    ) -> Result<Self, ArtifactError> {
        ensure_supported_execution_target()?;
        if runner_version.is_empty() {
            return Err(ArtifactError::InvalidArtifact {
                reason: "runner version is empty",
            });
        }
        Ok(Self {
            schema: QUALIFICATION_PROVENANCE_SCHEMA.to_owned(),
            runner_version: runner_version.to_owned(),
            target_os: std::env::consts::OS.to_owned(),
            target_arch: std::env::consts::ARCH.to_owned(),
            qualification_blake2s256: artifact.digest()?,
        })
    }

    fn validate(&self, artifact: &QualificationArtifactV1) -> Result<(), ArtifactError> {
        if self.schema != QUALIFICATION_PROVENANCE_SCHEMA
            || self.runner_version.is_empty()
            || self.target_os != "linux"
            || self.target_arch != "x86_64"
        {
            return Err(ArtifactError::InvalidArtifact {
                reason: "typed-worker qualification provenance is invalid",
            });
        }
        if self.qualification_blake2s256 != artifact.digest()? {
            return Err(ArtifactError::InvalidArtifact {
                reason: "typed-worker qualification digest mismatch",
            });
        }
        Ok(())
    }
}

fn validate_qualification(
    qualification: &TypedWorkerQualificationReport,
) -> Result<(), ArtifactError> {
    qualification
        .validate()
        .map_err(|_| ArtifactError::InvalidArtifact {
            reason: "typed-worker qualification report is invalid",
        })
}

/// Publishes a complete, read-back-validated typed-worker qualification.
pub(super) fn publish_qualification(
    output_dir: &Path,
    qualification: &TypedWorkerQualificationReport,
    runner_version: &str,
) -> Result<(), ArtifactError> {
    let artifact = QualificationArtifactV1::new(qualification)?;
    let provenance = QualificationProvenanceV1::new(runner_version, &artifact)?;
    provenance.validate(&artifact)?;

    let files = [
        ArtifactFile::new(
            QUALIFICATION_JSON,
            serde_json::to_vec_pretty(&artifact).map_err(ArtifactError::Json)?,
        ),
        ArtifactFile::new(QUALIFICATION_TEXT, qualification.to_string().into_bytes()),
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
    expected_artifact: &QualificationArtifactV1,
    expected_provenance: &QualificationProvenanceV1,
) -> Result<(), ArtifactError> {
    let qualification_json =
        read_artifact_file(stage, QUALIFICATION_JSON, MAX_QUALIFICATION_JSON_BYTES)?;
    let qualification_text =
        read_artifact_file(stage, QUALIFICATION_TEXT, MAX_QUALIFICATION_TEXT_BYTES)?;
    let provenance_json = read_artifact_file(stage, PROVENANCE_JSON, MAX_PROVENANCE_JSON_BYTES)?;

    let artifact: QualificationArtifactV1 =
        serde_json::from_slice(&qualification_json).map_err(ArtifactError::Json)?;
    artifact.validate()?;
    let provenance: QualificationProvenanceV1 =
        serde_json::from_slice(&provenance_json).map_err(ArtifactError::Json)?;
    provenance.validate(&artifact)?;
    if qualification_text != artifact.qualification.to_string().as_bytes() {
        return Err(ArtifactError::InvalidArtifact {
            reason: "typed-worker qualification text does not match the typed report",
        });
    }
    if artifact != *expected_artifact {
        return Err(ArtifactError::InvalidArtifact {
            reason: "typed-worker qualification read-back differs from the computed report",
        });
    }
    if provenance != *expected_provenance {
        return Err(ArtifactError::InvalidArtifact {
            reason: "typed-worker provenance read-back differs from the expected provenance",
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

    fn typed_report() -> TestResult<TypedWorkerQualificationReport> {
        let report: TypedWorkerQualificationReport = serde_json::from_value(serde_json::json!({
            "scenario": "typed-worker-deterministic-v1",
            "backend": "rostl-circuit-oram-volatile-v1",
            "backend_shape": {
                "directory_probes": 4,
                "event_probes": 4,
                "directory_capacity": 8,
                "directory_admission_limit": 6,
                "event_capacity": 16,
                "event_admission_limit": 12,
                "max_events_per_address": 8,
                "queue_capacity": 1
            },
            "command_summary": {
                "commands": 9,
                "reads": 5,
                "appends": 4,
                "inserted_appends": 3,
                "exact_replays": 1,
                "correctness_passed": true
            },
            "command_trace": [
                "read-empty",
                "append-inserted",
                "read-one-event",
                "append-exact-replay",
                "append-inserted",
                "append-inserted",
                "read-two-events",
                "read-one-event",
                "read-empty"
            ],
            "worker_trace": {
                "queue_capacity": 1,
                "queued_at_shutdown": 0,
                "in_flight_at_shutdown": 0,
                "queue_high_water": 1,
                "accepted": 9,
                "completed": 9,
                "failed": 0,
                "full_rejected": 0,
                "not_running_rejected": 0,
                "reply_delivery_failed": 0,
                "stopped": true,
                "faulted": false
            },
            "evidence_scope": {
                "correctness_checked": true,
                "execution_attested": false,
                "source_revision_bound": false,
                "lockfile_digest_bound": false,
                "toolchain_identity_bound": false,
                "binary_identity_bound": false,
                "latency_measured": false,
                "rss_measured": false,
                "physical_trace_measured": false,
                "persistence_qualified": false,
                "tdx_qualified": false
            }
        }))?;
        report.validate()?;
        Ok(report)
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn qualification_publication_is_exact_and_self_validating() -> TestResult {
        let parent = tempfile::tempdir()?;
        let output = parent.path().join("qualification");
        let report = typed_report()?;

        publish_qualification(&output, &report, "test-runner")?;

        let names = fs::read_dir(&output)?
            .map(|entry| entry.map(|entry| entry.file_name()))
            .collect::<Result<BTreeSet<_>, _>>()?;
        assert_eq!(
            names,
            BTreeSet::from([
                OsString::from(PROVENANCE_JSON),
                OsString::from(QUALIFICATION_JSON),
                OsString::from(QUALIFICATION_TEXT),
            ])
        );

        let artifact: QualificationArtifactV1 =
            serde_json::from_slice(&fs::read(output.join(QUALIFICATION_JSON))?)?;
        artifact.validate()?;
        let provenance: QualificationProvenanceV1 =
            serde_json::from_slice(&fs::read(output.join(PROVENANCE_JSON))?)?;
        provenance.validate(&artifact)?;
        assert_eq!(
            fs::read(output.join(QUALIFICATION_TEXT))?,
            report.to_string().as_bytes()
        );
        Ok(())
    }

    #[test]
    fn canonical_qualification_digest_is_stable() -> TestResult {
        let artifact = QualificationArtifactV1::new(&typed_report()?)?;
        let canonical = artifact.canonical_bytes()?;
        let decoded: QualificationArtifactV1 = serde_json::from_slice(&canonical)?;

        assert_eq!(decoded, artifact);
        assert_eq!(decoded.digest()?, artifact.digest()?);
        assert_eq!(
            artifact.digest()?,
            "181d4f4f35fb37c952e50f2d18b72e1b2dcdbefc0e4b6fef38677568c2aa9117"
        );
        Ok(())
    }

    #[test]
    fn typed_report_and_provenance_reject_overstated_or_unbound_evidence() -> TestResult {
        let report = typed_report()?;
        let mut overstated = serde_json::to_value(&report)?;
        overstated["evidence_scope"]["tdx_qualified"] = serde_json::json!(true);
        let overstated: TypedWorkerQualificationReport = serde_json::from_value(overstated)?;
        assert!(QualificationArtifactV1::new(&overstated).is_err());

        Ok(())
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn provenance_binds_the_typed_report_digest() -> TestResult {
        let artifact = QualificationArtifactV1::new(&typed_report()?)?;
        let mut provenance = QualificationProvenanceV1::new("test-runner", &artifact)?;
        assert_eq!(provenance.qualification_blake2s256, artifact.digest()?);

        provenance.qualification_blake2s256 = "00".repeat(32);
        assert!(provenance.validate(&artifact).is_err());
        Ok(())
    }

    #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
    #[test]
    fn unsupported_host_cannot_publish_a_fabricated_success_report() -> TestResult {
        let parent = tempfile::tempdir()?;
        let output = parent.path().join("qualification");

        assert!(publish_qualification(&output, &typed_report()?, "test-runner").is_err());
        assert!(!output.exists());
        Ok(())
    }
}
