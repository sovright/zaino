//! Atomic negative evidence for the recovered historical two-table geometry.

use crate::corpus_artifact::{
    artifact_blake2s256_hex, new_os_attested_provenance, publish_derived_evidence,
    validate_os_attested_provenance, ArtifactError, ValidatedCapture, ValidatedSizing,
};
use serde::{Deserialize, Serialize};
use std::path::Path;
use zaino_oram::HistoricalTwoTableGeometry;

const REPORT_JSON: &str = "historical-two-table-geometry.json";
const REPORT_TEXT: &str = "historical-two-table-geometry.txt";
const PROVENANCE_JSON: &str = "provenance.json";
const MAX_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArtifactV1 {
    schema: String,
    geometry: HistoricalTwoTableGeometry,
}

impl ArtifactV1 {
    fn new(geometry: HistoricalTwoTableGeometry) -> Self {
        Self {
            schema: "zaino-oram-historical-two-table-geometry-artifact-v1".to_owned(),
            geometry,
        }
    }
    fn digest(&self) -> Result<String, ArtifactError> {
        Ok(artifact_blake2s256_hex(
            &serde_json::to_vec(self).map_err(ArtifactError::Json)?,
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProvenanceV1 {
    schema: String,
    runner_version: String,
    target_os: String,
    target_arch: String,
    report_blake2s256: String,
    source_revision: String,
    binary_sha256: String,
    native_build_manifest_sha256: String,
    trust_scope: String,
}

impl ProvenanceV1 {
    fn new(
        runner_version: &str,
        source_revision: &str,
        binary_sha256: &str,
        native_build_manifest_sha256: &str,
        artifact: &ArtifactV1,
    ) -> Result<Self, ArtifactError> {
        new_os_attested_provenance(
            runner_version,
            artifact.digest(),
            "historical geometry publication requires Linux x86_64 execution",
            |runner_version, target_os, target_arch, report_blake2s256| {
                Self {
                schema: "zaino-oram-historical-two-table-geometry-provenance-v1".to_owned(),
                runner_version,
                target_os,
                target_arch,
                report_blake2s256,
                source_revision: source_revision.to_owned(),
                binary_sha256: binary_sha256.to_owned(),
                native_build_manifest_sha256: native_build_manifest_sha256.to_owned(),
                trust_scope: "unsigned-ci-build-and-running-inode-identity;no-rss,no-attestation,no-execution-proof".to_owned(),
            }
            },
        )
    }
    fn validate(
        &self,
        source_revision: &str,
        binary_sha256: &str,
        native_build_manifest_sha256: &str,
        artifact: &ArtifactV1,
    ) -> Result<(), ArtifactError> {
        if self.source_revision != source_revision
            || self.binary_sha256 != binary_sha256
            || self.native_build_manifest_sha256 != native_build_manifest_sha256
            || self.trust_scope
                != "unsigned-ci-build-and-running-inode-identity;no-rss,no-attestation,no-execution-proof"
        {
            return Err(ArtifactError::InvalidArtifact {
                reason: "historical geometry executable identity differs from unsigned native build manifest",
            });
        }
        validate_os_attested_provenance(
            self.schema == "zaino-oram-historical-two-table-geometry-provenance-v1",
            &self.runner_version,
            &self.target_os,
            &self.target_arch,
            "historical geometry provenance is invalid",
            &self.report_blake2s256,
            &artifact.digest()?,
            "historical geometry digest mismatch",
        )
    }
}

fn derive(
    capture: &ValidatedCapture,
    sizing: &ValidatedSizing,
) -> Result<HistoricalTwoTableGeometry, ArtifactError> {
    HistoricalTwoTableGeometry::derive(
        capture.measurement(),
        sizing.qualification(),
        capture.measurement_blake2s256(),
        sizing.sizing_model_blake2s256(),
        sizing.qualification_blake2s256(),
    )
    .map_err(|_| ArtifactError::InvalidArtifact {
        reason: "historical geometry input or checked native arithmetic was rejected",
    })
}

pub(super) fn publish_historical_geometry(
    output_dir: &Path,
    capture: &ValidatedCapture,
    sizing: &ValidatedSizing,
    source_revision: &str,
    binary_sha256: &str,
    native_build_manifest_sha256: &str,
    runner_version: &str,
) -> Result<HistoricalTwoTableGeometry, ArtifactError> {
    let geometry = derive(capture, sizing)?;
    let expected = geometry.clone();
    publish_derived_evidence(
        output_dir,
        capture,
        sizing,
        || Ok(ArtifactV1::new(geometry)),
        |artifact| {
            ProvenanceV1::new(
                runner_version,
                source_revision,
                binary_sha256,
                native_build_manifest_sha256,
                artifact,
            )
        },
        REPORT_JSON,
        MAX_BYTES,
        REPORT_TEXT,
        MAX_BYTES,
        PROVENANCE_JSON,
        MAX_BYTES,
        |artifact| artifact.geometry.to_string().into_bytes(),
        |artifact| {
            if artifact.schema != "zaino-oram-historical-two-table-geometry-artifact-v1"
                || artifact.geometry != derive(capture, sizing)?
            {
                return Err(ArtifactError::InvalidArtifact {
                    reason: "historical geometry read-back differs from native derivation",
                });
            }
            Ok(())
        },
        |provenance, artifact| {
            provenance.validate(
                source_revision,
                binary_sha256,
                native_build_manifest_sha256,
                artifact,
            )
        },
        "historical geometry text differs from typed report",
        "historical geometry artifact differs from computed report",
        "historical geometry provenance differs from expected provenance",
    )?;
    Ok(expected)
}
