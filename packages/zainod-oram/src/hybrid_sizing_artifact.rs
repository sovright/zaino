//! Atomic evidence artifacts for source-bound hybrid-sizing analysis.

#[cfg(feature = "typed-qualification")]
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use zaino_oram::{MainnetCorpusMeasurement, SourceBoundHybridSizingReport};

use crate::corpus_artifact::{
    artifact_blake2s256_hex, ensure_matching_digest, ensure_runner_version_present,
    publish_verified_derived_artifact, read_artifact_file, validate_derived_source_lineage,
    ArtifactDirectory, ArtifactError, ArtifactFile, PreverifiedSourceSnapshotV1, ValidatedCapture,
    ValidatedSizing,
};
#[cfg(feature = "typed-qualification")]
use crate::corpus_artifact::{open_artifact_directory, validate_artifact_file_set};

const HYBRID_SIZING_SCHEMA: &str = "zaino-oram-source-bound-hybrid-sizing-v1";
const HYBRID_SIZING_PROVENANCE_SCHEMA: &str = "zaino-oram-source-bound-hybrid-sizing-provenance-v1";
const HYBRID_SIZING_JSON: &str = "hybrid-sizing.json";
const HYBRID_SIZING_TEXT: &str = "hybrid-sizing.txt";
const PROVENANCE_JSON: &str = "provenance.json";
const MAX_HYBRID_SIZING_JSON_BYTES: usize = 4 * 1024 * 1024;
const MAX_HYBRID_SIZING_TEXT_BYTES: usize = 4 * 1024 * 1024;
const MAX_PROVENANCE_JSON_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HybridSizingArtifactV1 {
    schema: String,
    measurement_blake2s256: String,
    qualification_blake2s256: String,
    source_snapshot: PreverifiedSourceSnapshotV1,
    hybrid_sizing: SourceBoundHybridSizingReport,
}

impl HybridSizingArtifactV1 {
    fn new(
        hybrid_sizing: &SourceBoundHybridSizingReport,
        measurement: &MainnetCorpusMeasurement,
        measurement_blake2s256: &str,
        qualification_blake2s256: &str,
        source_snapshot: &PreverifiedSourceSnapshotV1,
    ) -> Result<Self, ArtifactError> {
        source_snapshot.validate(measurement)?;
        validate_hybrid_sizing(hybrid_sizing, measurement, measurement_blake2s256)?;
        Ok(Self {
            schema: HYBRID_SIZING_SCHEMA.to_owned(),
            measurement_blake2s256: measurement_blake2s256.to_owned(),
            qualification_blake2s256: qualification_blake2s256.to_owned(),
            source_snapshot: source_snapshot.clone(),
            hybrid_sizing: hybrid_sizing.clone(),
        })
    }

    fn validate(
        &self,
        measurement: &MainnetCorpusMeasurement,
        measurement_blake2s256: &str,
        qualification_blake2s256: &str,
        source_snapshot: &PreverifiedSourceSnapshotV1,
    ) -> Result<(), ArtifactError> {
        self.validate_retained()?;
        if self.measurement_blake2s256 != measurement_blake2s256
            || self.qualification_blake2s256 != qualification_blake2s256
            || self.source_snapshot != *source_snapshot
        {
            return Err(ArtifactError::InvalidArtifact {
                reason: "hybrid-sizing schema or source lineage mismatch",
            });
        }
        self.source_snapshot.validate(measurement)?;
        validate_hybrid_sizing(&self.hybrid_sizing, measurement, measurement_blake2s256)
    }

    fn validate_retained(&self) -> Result<(), ArtifactError> {
        self.hybrid_sizing
            .validate()
            .map_err(|_| ArtifactError::InvalidArtifact {
                reason: "retained hybrid-sizing report is invalid",
            })?;
        let (checkpoint_height, checkpoint_hash) = self.hybrid_sizing.source_checkpoint();
        self.source_snapshot
            .validate_retained_checkpoint(checkpoint_height, checkpoint_hash)?;
        if self.schema != HYBRID_SIZING_SCHEMA
            || self.measurement_blake2s256 != self.hybrid_sizing.measurement_blake2s256()
            || !is_blake2s256_hex(&self.qualification_blake2s256)
        {
            return Err(ArtifactError::InvalidArtifact {
                reason: "retained hybrid-sizing schema or lineage is inconsistent",
            });
        }
        Ok(())
    }

    fn canonical_bytes(&self) -> Result<Vec<u8>, ArtifactError> {
        serde_json::to_vec(self).map_err(ArtifactError::Json)
    }

    fn digest(&self) -> Result<String, ArtifactError> {
        Ok(artifact_blake2s256_hex(&self.canonical_bytes()?))
    }
}

/// A self-contained hybrid-sizing bundle checked against an external digest.
#[cfg(feature = "typed-qualification")]
pub(super) struct ValidatedHybridSizing {
    report: SourceBoundHybridSizingReport,
    hybrid_sizing_blake2s256: String,
}

#[cfg(feature = "typed-qualification")]
impl ValidatedHybridSizing {
    pub(super) const fn report(&self) -> &SourceBoundHybridSizingReport {
        &self.report
    }

    pub(super) fn hybrid_sizing_blake2s256(&self) -> &str {
        &self.hybrid_sizing_blake2s256
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HybridSizingProvenanceV1 {
    schema: String,
    runner_version: String,
    hybrid_sizing_blake2s256: String,
}

impl HybridSizingProvenanceV1 {
    fn new(runner_version: &str, artifact: &HybridSizingArtifactV1) -> Result<Self, ArtifactError> {
        ensure_runner_version_present(runner_version)?;
        Ok(Self {
            schema: HYBRID_SIZING_PROVENANCE_SCHEMA.to_owned(),
            runner_version: runner_version.to_owned(),
            hybrid_sizing_blake2s256: artifact.digest()?,
        })
    }

    fn validate(&self, artifact: &HybridSizingArtifactV1) -> Result<(), ArtifactError> {
        if self.schema != HYBRID_SIZING_PROVENANCE_SCHEMA || self.runner_version.is_empty() {
            return Err(ArtifactError::InvalidArtifact {
                reason: "hybrid-sizing provenance is invalid",
            });
        }
        ensure_matching_digest(
            &self.hybrid_sizing_blake2s256,
            &artifact.digest()?,
            "hybrid-sizing digest mismatch",
        )
    }
}

fn validate_hybrid_sizing(
    hybrid_sizing: &SourceBoundHybridSizingReport,
    measurement: &MainnetCorpusMeasurement,
    measurement_blake2s256: &str,
) -> Result<(), ArtifactError> {
    hybrid_sizing
        .validate_against(measurement, measurement_blake2s256)
        .map_err(|_| ArtifactError::InvalidArtifact {
            reason: "hybrid-sizing report is invalid or source-unbound",
        })
}

/// Loads an exact-file-set retained report and binds its typed artifact to an external digest.
#[cfg(feature = "typed-qualification")]
pub(super) fn load_hybrid_sizing(
    input_dir: &Path,
    expected_hybrid_sizing_blake2s256: &str,
) -> Result<ValidatedHybridSizing, ArtifactError> {
    if !is_blake2s256_hex(expected_hybrid_sizing_blake2s256) {
        return Err(ArtifactError::InvalidArtifact {
            reason: "expected hybrid-sizing digest is invalid",
        });
    }
    let source_directory = fs::canonicalize(input_dir).map_err(|source| ArtifactError::Io {
        operation: "canonicalize retained hybrid-sizing directory",
        source,
    })?;
    let directory = open_artifact_directory(&source_directory)?;
    validate_artifact_file_set(
        &directory,
        &[HYBRID_SIZING_JSON, HYBRID_SIZING_TEXT, PROVENANCE_JSON],
    )?;
    let (artifact, provenance) = read_validated_hybrid_sizing_directory(&directory)?;
    if provenance.hybrid_sizing_blake2s256 != expected_hybrid_sizing_blake2s256 {
        return Err(ArtifactError::InvalidArtifact {
            reason: "retained hybrid-sizing digest differs from external expectation",
        });
    }
    Ok(ValidatedHybridSizing {
        report: artifact.hybrid_sizing,
        hybrid_sizing_blake2s256: provenance.hybrid_sizing_blake2s256,
    })
}

/// Publishes a complete, read-back-validated source-bound hybrid-sizing analysis.
pub(super) fn publish_hybrid_sizing(
    output_dir: &Path,
    capture: &ValidatedCapture,
    sizing: &ValidatedSizing,
    hybrid_sizing: &SourceBoundHybridSizingReport,
    source_snapshot: &PreverifiedSourceSnapshotV1,
    runner_version: &str,
) -> Result<(), ArtifactError> {
    validate_derived_source_lineage(capture, sizing)?;
    let artifact = HybridSizingArtifactV1::new(
        hybrid_sizing,
        capture.measurement(),
        capture.measurement_blake2s256(),
        sizing.qualification_blake2s256(),
        source_snapshot,
    )?;
    let provenance = HybridSizingProvenanceV1::new(runner_version, &artifact)?;
    provenance.validate(&artifact)?;

    let files = [
        ArtifactFile::new(
            HYBRID_SIZING_JSON,
            serde_json::to_vec_pretty(&artifact).map_err(ArtifactError::Json)?,
        ),
        ArtifactFile::new(HYBRID_SIZING_TEXT, hybrid_sizing.to_string().into_bytes()),
        ArtifactFile::new(
            PROVENANCE_JSON,
            serde_json::to_vec_pretty(&provenance).map_err(ArtifactError::Json)?,
        ),
    ];

    publish_verified_derived_artifact(output_dir, capture, sizing, &files, |stage| {
        validate_staged_hybrid_sizing(
            stage,
            capture,
            sizing,
            source_snapshot,
            &artifact,
            &provenance,
        )
    })
}

fn validate_staged_hybrid_sizing(
    stage: &ArtifactDirectory,
    capture: &ValidatedCapture,
    sizing: &ValidatedSizing,
    source_snapshot: &PreverifiedSourceSnapshotV1,
    expected_artifact: &HybridSizingArtifactV1,
    expected_provenance: &HybridSizingProvenanceV1,
) -> Result<(), ArtifactError> {
    let (artifact, provenance) = read_validated_hybrid_sizing_directory(stage)?;
    validate_derived_source_lineage(capture, sizing)?;
    artifact.validate(
        capture.measurement(),
        capture.measurement_blake2s256(),
        sizing.qualification_blake2s256(),
        source_snapshot,
    )?;
    if artifact != *expected_artifact {
        return Err(ArtifactError::InvalidArtifact {
            reason: "hybrid-sizing read-back differs from the computed report",
        });
    }
    if provenance != *expected_provenance {
        return Err(ArtifactError::InvalidArtifact {
            reason: "hybrid-sizing provenance read-back differs from expected provenance",
        });
    }
    Ok(())
}

fn read_validated_hybrid_sizing_directory(
    directory: &ArtifactDirectory,
) -> Result<(HybridSizingArtifactV1, HybridSizingProvenanceV1), ArtifactError> {
    let hybrid_sizing_json =
        read_artifact_file(directory, HYBRID_SIZING_JSON, MAX_HYBRID_SIZING_JSON_BYTES)?;
    let hybrid_sizing_text =
        read_artifact_file(directory, HYBRID_SIZING_TEXT, MAX_HYBRID_SIZING_TEXT_BYTES)?;
    let provenance_json =
        read_artifact_file(directory, PROVENANCE_JSON, MAX_PROVENANCE_JSON_BYTES)?;

    let artifact: HybridSizingArtifactV1 =
        serde_json::from_slice(&hybrid_sizing_json).map_err(ArtifactError::Json)?;
    artifact.validate_retained()?;
    let provenance: HybridSizingProvenanceV1 =
        serde_json::from_slice(&provenance_json).map_err(ArtifactError::Json)?;
    provenance.validate(&artifact)?;
    if hybrid_sizing_text != artifact.hybrid_sizing.to_string().as_bytes() {
        return Err(ArtifactError::InvalidArtifact {
            reason: "hybrid-sizing text does not match the typed report",
        });
    }
    Ok((artifact, provenance))
}

fn is_blake2s256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::num::NonZeroU128;

    use zaino_oram::{
        MainnetCorpusScanner, SourceBoundHybridSizingProfile, SourceBoundHybridSizingSession,
    };
    use zaino_state::{
        chain_index::types::EquihashSolution, BlockContext, BlockData, BlockHash, ChainWork,
        CommitmentTreeData, CommitmentTreeRoots, CommitmentTreeSizes, CompactDifficulty,
        CompactTxData, Height, IndexedBlock, OrchardCompactTx, SaplingCompactTx, ScriptType,
        TransactionHash, TransparentCompactTx, TxInCompact, TxOutCompact,
    };

    use crate::corpus_artifact::BackendKind;

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    struct HybridSizingFixture {
        measurement: MainnetCorpusMeasurement,
        measurement_digest: String,
        qualification_digest: String,
        source_snapshot: PreverifiedSourceSnapshotV1,
        report: SourceBoundHybridSizingReport,
    }

    fn fixture_genesis(address_count: u8) -> TestResult<IndexedBlock> {
        const MAINNET_GENESIS_DISPLAY_ORDER: [u8; 32] = [
            0x00, 0x04, 0x0f, 0xe8, 0xec, 0x84, 0x71, 0x91, 0x1b, 0xaa, 0x1d, 0xb1, 0x26, 0x6e,
            0xa1, 0x5d, 0xd0, 0x6b, 0x4a, 0x8a, 0x5c, 0x45, 0x38, 0x83, 0xc0, 0x00, 0xb0, 0x31,
            0x97, 0x3d, 0xce, 0x08,
        ];

        let outputs = (0..address_count)
            .map(|byte| {
                TxOutCompact::new(u64::from(byte) + 1, [byte + 1; 20], ScriptType::P2PKH as u8)
                    .ok_or_else(|| "known script class must construct a compact output".into())
            })
            .collect::<TestResult<Vec<_>>>()?;
        let transaction = CompactTxData::new(
            0,
            TransactionHash([0x11; 32]),
            TransparentCompactTx::new(vec![TxInCompact::null_prevout()], outputs),
            SaplingCompactTx::new(None, Vec::new(), Vec::new()),
            OrchardCompactTx::empty(),
            OrchardCompactTx::empty(),
        );
        let context = BlockContext::new(
            BlockHash::from_bytes_in_display_order(&MAINNET_GENESIS_DISPLAY_ORDER),
            BlockHash([0; 32]),
            ChainWork::new(NonZeroU128::new(1).ok_or("fixture chainwork must remain nonzero")?),
            Height::try_from(0_u32)?,
        );
        let data = BlockData::new(
            1,
            0,
            [0; 32],
            [0; 32],
            CompactDifficulty::try_from_bits(0x2007_ffff)?,
            [0; 32],
            EquihashSolution::Regtest([0; 36]),
        );
        let commitment_tree_data = CommitmentTreeData::new(
            CommitmentTreeRoots::new([0; 32], [0; 32], None),
            CommitmentTreeSizes::new(0, 0, 0),
        );
        Ok(IndexedBlock::new(
            context,
            data,
            vec![transaction],
            commitment_tree_data,
        ))
    }

    fn fixture() -> TestResult<HybridSizingFixture> {
        let block = fixture_genesis(3)?;
        let mut scanner = MainnetCorpusScanner::new();
        scanner.push(&block)?;
        let measurement = scanner.finish()?;
        let measurement_digest = "11".repeat(32);
        let qualification_digest = "22".repeat(32);
        let mut session = SourceBoundHybridSizingSession::start(
            SourceBoundHybridSizingProfile::LiveUtxoBaseDeltaV1,
            &measurement,
            &measurement_digest,
        )?;
        session.push(&block)?;
        let report = session.finish()?;
        let source_snapshot =
            PreverifiedSourceSnapshotV1::new_verified(BackendKind::Rpc, 0, &measurement)?;
        Ok(HybridSizingFixture {
            measurement,
            measurement_digest,
            qualification_digest,
            source_snapshot,
            report,
        })
    }

    fn artifact(fixture: &HybridSizingFixture) -> Result<HybridSizingArtifactV1, ArtifactError> {
        HybridSizingArtifactV1::new(
            &fixture.report,
            &fixture.measurement,
            &fixture.measurement_digest,
            &fixture.qualification_digest,
            &fixture.source_snapshot,
        )
    }

    #[test]
    fn artifact_round_trips_and_rejects_lineage_and_unknown_fields() -> TestResult {
        let fixture = fixture()?;
        let artifact = artifact(&fixture)?;
        let encoded = serde_json::to_value(&artifact)?;
        let decoded: HybridSizingArtifactV1 = serde_json::from_value(encoded)?;
        assert_eq!(decoded, artifact);
        decoded.validate(
            &fixture.measurement,
            &fixture.measurement_digest,
            &fixture.qualification_digest,
            &fixture.source_snapshot,
        )?;

        let mut wrong_lineage = artifact.clone();
        wrong_lineage.measurement_blake2s256 = "33".repeat(32);
        assert!(wrong_lineage
            .validate(
                &fixture.measurement,
                &fixture.measurement_digest,
                &fixture.qualification_digest,
                &fixture.source_snapshot,
            )
            .is_err());

        let mut wrong_sizing_lineage = artifact.clone();
        wrong_sizing_lineage.qualification_blake2s256 = "44".repeat(32);
        assert!(wrong_sizing_lineage
            .validate(
                &fixture.measurement,
                &fixture.measurement_digest,
                &fixture.qualification_digest,
                &fixture.source_snapshot,
            )
            .is_err());

        let mut unknown_field = serde_json::to_value(&artifact)?;
        unknown_field["operator_note"] = serde_json::json!("not schema-bound");
        assert!(serde_json::from_value::<HybridSizingArtifactV1>(unknown_field).is_err());
        Ok(())
    }

    #[test]
    fn provenance_binds_the_complete_artifact() -> TestResult {
        let fixture = fixture()?;
        let artifact = artifact(&fixture)?;
        let provenance = HybridSizingProvenanceV1::new("test-runner", &artifact)?;
        provenance.validate(&artifact)?;

        let mut changed_artifact = artifact;
        changed_artifact.measurement_blake2s256 = "44".repeat(32);
        assert!(provenance.validate(&changed_artifact).is_err());
        assert!(HybridSizingProvenanceV1::new("", &changed_artifact).is_err());
        Ok(())
    }

    #[cfg(feature = "typed-qualification")]
    #[test]
    fn committed_v1_bundle_remains_byte_and_digest_compatible() -> TestResult {
        let retained = Path::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../docs/evidence/oram/gate1/hybrid-mainnet-2316644-h3425046-v1"
        ));
        let expected = "2c44f5dcdf851a12053cd8e684c4f97f202f4ff88e49102ad6232b984a746828";
        let loaded = load_hybrid_sizing(retained, expected)?;

        assert_eq!(loaded.hybrid_sizing_blake2s256(), expected);
        Ok(())
    }

    #[cfg(feature = "typed-qualification")]
    #[test]
    fn retained_loader_requires_exact_files_semantics_and_external_digest() -> TestResult {
        let fixture = fixture()?;
        let artifact = artifact(&fixture)?;
        let provenance = HybridSizingProvenanceV1::new("test-runner", &artifact)?;
        let directory = tempfile::tempdir()?;
        fs::write(
            directory.path().join(HYBRID_SIZING_JSON),
            serde_json::to_vec_pretty(&artifact)?,
        )?;
        fs::write(
            directory.path().join(HYBRID_SIZING_TEXT),
            artifact.hybrid_sizing.to_string(),
        )?;
        fs::write(
            directory.path().join(PROVENANCE_JSON),
            serde_json::to_vec_pretty(&provenance)?,
        )?;

        let loaded = load_hybrid_sizing(directory.path(), &provenance.hybrid_sizing_blake2s256)?;
        assert_eq!(loaded.report(), &fixture.report);
        assert_eq!(
            loaded.hybrid_sizing_blake2s256(),
            provenance.hybrid_sizing_blake2s256
        );
        assert!(load_hybrid_sizing(directory.path(), &"00".repeat(32)).is_err());

        fs::write(directory.path().join("unexpected"), b"not admitted")?;
        assert!(
            load_hybrid_sizing(directory.path(), &provenance.hybrid_sizing_blake2s256).is_err()
        );
        Ok(())
    }
}
