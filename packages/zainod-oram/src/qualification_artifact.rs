//! Atomic evidence artifacts for the fixed typed-worker correctness scenario.

use std::path::Path;

use serde::{Deserialize, Serialize};
use zaino_oram::TypedWorkerQualificationReport;

use crate::corpus_artifact::{
    artifact_blake2s256_hex, new_os_attested_provenance, publish_unwrapped_evidence,
    validate_os_attested_provenance, ArtifactError,
};

const QUALIFICATION_SCHEMA: &str = "zaino-oram-typed-worker-qualification-v1";
const QUALIFICATION_PROVENANCE_SCHEMA: &str = "zaino-oram-typed-worker-qualification-provenance-v1";
const QUALIFICATION_JSON: &str = "qualification.json";
const QUALIFICATION_TEXT: &str = "qualification.txt";
const PROVENANCE_JSON: &str = "provenance.json";
const MAX_QUALIFICATION_JSON_BYTES: usize = 4 * 1024 * 1024;
const MAX_QUALIFICATION_TEXT_BYTES: usize = 4 * 1024 * 1024;
const MAX_PROVENANCE_JSON_BYTES: usize = 64 * 1024;

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
        new_os_attested_provenance(
            runner_version,
            artifact.digest(),
            "typed-worker qualification publication requires Linux x86_64 execution",
            |runner_version, target_os, target_arch, qualification_blake2s256| Self {
                schema: QUALIFICATION_PROVENANCE_SCHEMA.to_owned(),
                runner_version,
                target_os,
                target_arch,
                qualification_blake2s256,
            },
        )
    }

    fn validate(&self, artifact: &QualificationArtifactV1) -> Result<(), ArtifactError> {
        validate_os_attested_provenance(
            self.schema == QUALIFICATION_PROVENANCE_SCHEMA,
            &self.runner_version,
            &self.target_os,
            &self.target_arch,
            "typed-worker qualification provenance is invalid",
            &self.qualification_blake2s256,
            &artifact.digest()?,
            "typed-worker qualification digest mismatch",
        )
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
    publish_unwrapped_evidence(
        output_dir,
        || QualificationArtifactV1::new(qualification),
        |artifact| QualificationProvenanceV1::new(runner_version, artifact),
        QUALIFICATION_JSON,
        MAX_QUALIFICATION_JSON_BYTES,
        QUALIFICATION_TEXT,
        MAX_QUALIFICATION_TEXT_BYTES,
        PROVENANCE_JSON,
        MAX_PROVENANCE_JSON_BYTES,
        |artifact| artifact.qualification.to_string().into_bytes(),
        |artifact| artifact.validate(),
        |provenance, artifact| provenance.validate(artifact),
        "typed-worker qualification text does not match the typed report",
        "typed-worker qualification read-back differs from the computed report",
        "typed-worker provenance read-back differs from the expected provenance",
    )
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
