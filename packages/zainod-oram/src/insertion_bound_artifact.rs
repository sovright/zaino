//! Atomic evidence artifacts for source-bound insertion-budget analysis.

use std::path::Path;

use serde::{Deserialize, Serialize};
use zaino_oram::{
    MainnetCorpusMeasurement, MainnetSizingQualification, SourceBoundInsertionBudgetReport,
};

use crate::corpus_artifact::{
    artifact_blake2s256_hex, publish_verified_derived_artifact, read_artifact_file,
    validate_derived_source_lineage, ArtifactDirectory, ArtifactError, ArtifactFile,
    PreverifiedSourceSnapshotV1, ValidatedCapture, ValidatedSizing,
};

const INSERTION_BOUND_SCHEMA: &str = "zaino-oram-source-bound-insertion-budget-v1";
const INSERTION_BOUND_PROVENANCE_SCHEMA: &str =
    "zaino-oram-source-bound-insertion-budget-provenance-v1";
const INSERTION_BOUND_JSON: &str = "insertion-bound.json";
const INSERTION_BOUND_TEXT: &str = "insertion-bound.txt";
const PROVENANCE_JSON: &str = "provenance.json";
const MAX_INSERTION_BOUND_JSON_BYTES: usize = 4 * 1024 * 1024;
const MAX_INSERTION_BOUND_TEXT_BYTES: usize = 4 * 1024 * 1024;
const MAX_PROVENANCE_JSON_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InsertionBoundArtifactV1 {
    schema: String,
    measurement_blake2s256: String,
    qualification_blake2s256: String,
    failure_budget_bps: u64,
    source_snapshot: PreverifiedSourceSnapshotV1,
    insertion_bound: SourceBoundInsertionBudgetReport,
}

impl InsertionBoundArtifactV1 {
    fn new(
        insertion_bound: &SourceBoundInsertionBudgetReport,
        measurement: &MainnetCorpusMeasurement,
        sizing: &MainnetSizingQualification,
        measurement_blake2s256: &str,
        qualification_blake2s256: &str,
        failure_budget_bps: u64,
        source_snapshot: &PreverifiedSourceSnapshotV1,
    ) -> Result<Self, ArtifactError> {
        source_snapshot.validate(measurement)?;
        validate_insertion_bound(
            insertion_bound,
            measurement,
            sizing,
            measurement_blake2s256,
            qualification_blake2s256,
            failure_budget_bps,
        )?;
        Ok(Self {
            schema: INSERTION_BOUND_SCHEMA.to_owned(),
            measurement_blake2s256: measurement_blake2s256.to_owned(),
            qualification_blake2s256: qualification_blake2s256.to_owned(),
            failure_budget_bps,
            source_snapshot: source_snapshot.clone(),
            insertion_bound: insertion_bound.clone(),
        })
    }

    fn validate(
        &self,
        measurement: &MainnetCorpusMeasurement,
        sizing: &MainnetSizingQualification,
        measurement_blake2s256: &str,
        qualification_blake2s256: &str,
        failure_budget_bps: u64,
        source_snapshot: &PreverifiedSourceSnapshotV1,
    ) -> Result<(), ArtifactError> {
        if self.schema != INSERTION_BOUND_SCHEMA
            || self.measurement_blake2s256 != measurement_blake2s256
            || self.qualification_blake2s256 != qualification_blake2s256
            || self.failure_budget_bps != failure_budget_bps
            || self.source_snapshot != *source_snapshot
        {
            return Err(ArtifactError::InvalidArtifact {
                reason: "insertion-bound schema, source lineage, or failure budget mismatch",
            });
        }
        self.source_snapshot.validate(measurement)?;
        validate_insertion_bound(
            &self.insertion_bound,
            measurement,
            sizing,
            measurement_blake2s256,
            qualification_blake2s256,
            failure_budget_bps,
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
struct InsertionBoundProvenanceV1 {
    schema: String,
    runner_version: String,
    insertion_bound_blake2s256: String,
}

impl InsertionBoundProvenanceV1 {
    fn new(
        runner_version: &str,
        artifact: &InsertionBoundArtifactV1,
    ) -> Result<Self, ArtifactError> {
        if runner_version.is_empty() {
            return Err(ArtifactError::InvalidArtifact {
                reason: "runner version is empty",
            });
        }
        Ok(Self {
            schema: INSERTION_BOUND_PROVENANCE_SCHEMA.to_owned(),
            runner_version: runner_version.to_owned(),
            insertion_bound_blake2s256: artifact.digest()?,
        })
    }

    fn validate(&self, artifact: &InsertionBoundArtifactV1) -> Result<(), ArtifactError> {
        if self.schema != INSERTION_BOUND_PROVENANCE_SCHEMA || self.runner_version.is_empty() {
            return Err(ArtifactError::InvalidArtifact {
                reason: "insertion-bound provenance is invalid",
            });
        }
        if self.insertion_bound_blake2s256 != artifact.digest()? {
            return Err(ArtifactError::InvalidArtifact {
                reason: "insertion-bound digest mismatch",
            });
        }
        Ok(())
    }
}

fn validate_insertion_bound(
    insertion_bound: &SourceBoundInsertionBudgetReport,
    measurement: &MainnetCorpusMeasurement,
    sizing: &MainnetSizingQualification,
    measurement_blake2s256: &str,
    qualification_blake2s256: &str,
    failure_budget_bps: u64,
) -> Result<(), ArtifactError> {
    insertion_bound
        .validate_against(
            measurement,
            sizing,
            measurement_blake2s256,
            qualification_blake2s256,
            failure_budget_bps,
        )
        .map_err(|_| ArtifactError::InvalidArtifact {
            reason: "insertion-bound report is invalid or source-unbound",
        })
}

/// Publishes a complete, read-back-validated source-bound insertion analysis.
pub(super) fn publish_insertion_bound(
    output_dir: &Path,
    capture: &ValidatedCapture,
    sizing: &ValidatedSizing,
    insertion_bound: &SourceBoundInsertionBudgetReport,
    failure_budget_bps: u64,
    source_snapshot: &PreverifiedSourceSnapshotV1,
    runner_version: &str,
) -> Result<(), ArtifactError> {
    validate_derived_source_lineage(capture, sizing)?;
    let artifact = InsertionBoundArtifactV1::new(
        insertion_bound,
        capture.measurement(),
        sizing.qualification(),
        capture.measurement_blake2s256(),
        sizing.qualification_blake2s256(),
        failure_budget_bps,
        source_snapshot,
    )?;
    let provenance = InsertionBoundProvenanceV1::new(runner_version, &artifact)?;
    provenance.validate(&artifact)?;

    let files = [
        ArtifactFile::new(
            INSERTION_BOUND_JSON,
            serde_json::to_vec_pretty(&artifact).map_err(ArtifactError::Json)?,
        ),
        ArtifactFile::new(
            INSERTION_BOUND_TEXT,
            insertion_bound.to_string().into_bytes(),
        ),
        ArtifactFile::new(
            PROVENANCE_JSON,
            serde_json::to_vec_pretty(&provenance).map_err(ArtifactError::Json)?,
        ),
    ];

    publish_verified_derived_artifact(output_dir, capture, sizing, &files, |stage| {
        validate_staged_insertion_bound(
            stage,
            capture,
            sizing,
            failure_budget_bps,
            source_snapshot,
            &artifact,
            &provenance,
        )
    })
}

fn validate_staged_insertion_bound(
    stage: &ArtifactDirectory,
    capture: &ValidatedCapture,
    sizing: &ValidatedSizing,
    failure_budget_bps: u64,
    source_snapshot: &PreverifiedSourceSnapshotV1,
    expected_artifact: &InsertionBoundArtifactV1,
    expected_provenance: &InsertionBoundProvenanceV1,
) -> Result<(), ArtifactError> {
    let insertion_bound_json =
        read_artifact_file(stage, INSERTION_BOUND_JSON, MAX_INSERTION_BOUND_JSON_BYTES)?;
    let insertion_bound_text =
        read_artifact_file(stage, INSERTION_BOUND_TEXT, MAX_INSERTION_BOUND_TEXT_BYTES)?;
    let provenance_json = read_artifact_file(stage, PROVENANCE_JSON, MAX_PROVENANCE_JSON_BYTES)?;

    let artifact: InsertionBoundArtifactV1 =
        serde_json::from_slice(&insertion_bound_json).map_err(ArtifactError::Json)?;
    validate_derived_source_lineage(capture, sizing)?;
    artifact.validate(
        capture.measurement(),
        sizing.qualification(),
        capture.measurement_blake2s256(),
        sizing.qualification_blake2s256(),
        failure_budget_bps,
        source_snapshot,
    )?;
    let provenance: InsertionBoundProvenanceV1 =
        serde_json::from_slice(&provenance_json).map_err(ArtifactError::Json)?;
    provenance.validate(&artifact)?;
    if insertion_bound_text != artifact.insertion_bound.to_string().as_bytes() {
        return Err(ArtifactError::InvalidArtifact {
            reason: "insertion-bound text does not match the typed report",
        });
    }
    if artifact != *expected_artifact {
        return Err(ArtifactError::InvalidArtifact {
            reason: "insertion-bound read-back differs from the computed report",
        });
    }
    if provenance != *expected_provenance {
        return Err(ArtifactError::InvalidArtifact {
            reason: "insertion-bound provenance read-back differs from expected provenance",
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::num::NonZeroU128;

    #[cfg(any(target_vendor = "apple", target_os = "linux"))]
    use std::{collections::BTreeSet, ffi::OsString, fs};
    use zaino_oram::{
        MainnetCorpusScanner, MainnetSizingModel, SourceBoundInsertionBudgetProfile,
        SourceBoundInsertionBudgetSession,
    };
    use zaino_state::{
        chain_index::types::EquihashSolution, BlockContext, BlockData, BlockHash, ChainWork,
        CommitmentTreeData, CommitmentTreeRoots, CommitmentTreeSizes, CompactDifficulty,
        CompactTxData, Height, IndexedBlock, OrchardCompactTx, SaplingCompactTx, ScriptType,
        TransactionHash, TransparentCompactTx, TxInCompact, TxOutCompact,
    };

    use crate::corpus_artifact::BackendKind;
    #[cfg(any(target_vendor = "apple", target_os = "linux"))]
    use crate::corpus_artifact::{
        load_capture, load_sizing, publish_capture, publish_sizing, CaptureProvenance,
        SelectionMode, SnapshotMode,
    };

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    struct InsertionFixture {
        measurement: MainnetCorpusMeasurement,
        sizing: MainnetSizingQualification,
        measurement_digest: String,
        qualification_digest: String,
        failure_budget_bps: u64,
        source_snapshot: PreverifiedSourceSnapshotV1,
        report: SourceBoundInsertionBudgetReport,
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

    fn source_artifacts(
        block: &IndexedBlock,
        directory_admission_limit: u64,
    ) -> TestResult<(MainnetCorpusMeasurement, MainnetSizingQualification)> {
        let mut scanner = MainnetCorpusScanner::new();
        scanner.push(block)?;
        let measurement = scanner.finish()?;
        let model = MainnetSizingModel::new(
            0,
            0,
            8,
            directory_admission_limit,
            16,
            12,
            8,
            4,
            10_000,
            1_000_000,
            3_000,
        )?;
        let sizing = measurement.apply_model(&model)?;
        Ok((measurement, sizing))
    }

    fn insertion_report(
        block: &IndexedBlock,
        measurement: &MainnetCorpusMeasurement,
        sizing: &MainnetSizingQualification,
        measurement_digest: &str,
        qualification_digest: &str,
        failure_budget_bps: u64,
    ) -> TestResult<SourceBoundInsertionBudgetReport> {
        let mut session = SourceBoundInsertionBudgetSession::start(
            SourceBoundInsertionBudgetProfile::CurrentFourProbeV1,
            measurement,
            sizing,
            measurement_digest,
            qualification_digest,
            failure_budget_bps,
        )?;
        session.push(block)?;
        Ok(session.finish()?)
    }

    fn insertion_fixture(
        address_count: u8,
        directory_admission_limit: u64,
        failure_budget_bps: u64,
    ) -> TestResult<InsertionFixture> {
        let block = fixture_genesis(address_count)?;
        let (measurement, sizing) = source_artifacts(&block, directory_admission_limit)?;
        let measurement_digest = "11".repeat(32);
        let qualification_digest = "22".repeat(32);
        let report = insertion_report(
            &block,
            &measurement,
            &sizing,
            &measurement_digest,
            &qualification_digest,
            failure_budget_bps,
        )?;
        let source_snapshot =
            PreverifiedSourceSnapshotV1::new_verified(BackendKind::Rpc, 0, &measurement)?;
        Ok(InsertionFixture {
            measurement,
            sizing,
            measurement_digest,
            qualification_digest,
            failure_budget_bps,
            source_snapshot,
            report,
        })
    }

    fn artifact(fixture: &InsertionFixture) -> Result<InsertionBoundArtifactV1, ArtifactError> {
        InsertionBoundArtifactV1::new(
            &fixture.report,
            &fixture.measurement,
            &fixture.sizing,
            &fixture.measurement_digest,
            &fixture.qualification_digest,
            fixture.failure_budget_bps,
            &fixture.source_snapshot,
        )
    }

    #[test]
    fn artifact_round_trips_and_rejects_lineage_budget_and_report_tampering() -> TestResult {
        let fixture = insertion_fixture(3, 6, 10_000)?;
        let artifact = artifact(&fixture)?;
        let encoded = serde_json::to_value(&artifact)?;
        let decoded: InsertionBoundArtifactV1 = serde_json::from_value(encoded)?;
        assert_eq!(decoded, artifact);
        decoded.validate(
            &fixture.measurement,
            &fixture.sizing,
            &fixture.measurement_digest,
            &fixture.qualification_digest,
            fixture.failure_budget_bps,
            &fixture.source_snapshot,
        )?;

        let mut wrong_lineage = artifact.clone();
        wrong_lineage.measurement_blake2s256 = "33".repeat(32);
        assert!(wrong_lineage
            .validate(
                &fixture.measurement,
                &fixture.sizing,
                &fixture.measurement_digest,
                &fixture.qualification_digest,
                fixture.failure_budget_bps,
                &fixture.source_snapshot,
            )
            .is_err());

        let mut wrong_budget = artifact.clone();
        wrong_budget.failure_budget_bps -= 1;
        assert!(wrong_budget
            .validate(
                &fixture.measurement,
                &fixture.sizing,
                &fixture.measurement_digest,
                &fixture.qualification_digest,
                fixture.failure_budget_bps,
                &fixture.source_snapshot,
            )
            .is_err());

        let mut overstated = serde_json::to_value(&artifact)?;
        overstated["insertion_bound"]["evidence_scope"]["tdx_qualified"] = serde_json::json!(true);
        let overstated: InsertionBoundArtifactV1 = serde_json::from_value(overstated)?;
        assert!(overstated
            .validate(
                &fixture.measurement,
                &fixture.sizing,
                &fixture.measurement_digest,
                &fixture.qualification_digest,
                fixture.failure_budget_bps,
                &fixture.source_snapshot,
            )
            .is_err());
        Ok(())
    }

    #[test]
    fn provenance_binds_the_complete_artifact_and_rejects_unknown_fields() -> TestResult {
        let fixture = insertion_fixture(3, 6, 10_000)?;
        let artifact = artifact(&fixture)?;
        let provenance = InsertionBoundProvenanceV1::new("test-runner", &artifact)?;
        provenance.validate(&artifact)?;

        let mut changed_artifact = artifact;
        changed_artifact.failure_budget_bps -= 1;
        assert!(provenance.validate(&changed_artifact).is_err());
        assert!(InsertionBoundProvenanceV1::new("", &changed_artifact).is_err());

        let mut unknown_field = serde_json::to_value(&provenance)?;
        unknown_field["target_os"] = serde_json::json!("linux");
        assert!(serde_json::from_value::<InsertionBoundProvenanceV1>(unknown_field).is_err());
        Ok(())
    }

    #[cfg(any(target_vendor = "apple", target_os = "linux"))]
    #[test]
    fn no_go_publication_is_exact_source_bound_and_host_independent() -> TestResult {
        let parent = tempfile::tempdir()?;
        let capture_dir = parent.path().join("capture");
        let sizing_dir = parent.path().join("sizing");
        let output_dir = parent.path().join("insertion-bound");
        let block = fixture_genesis(3)?;
        let (measurement, qualification) = source_artifacts(&block, 2)?;
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
        publish_sizing(&sizing_dir, &capture, &qualification, "test-runner")?;
        let sizing = load_sizing(&sizing_dir, &capture)?;
        let failure_budget_bps = 10_000;
        let report = insertion_report(
            &block,
            capture.measurement(),
            sizing.qualification(),
            capture.measurement_blake2s256(),
            sizing.qualification_blake2s256(),
            failure_budget_bps,
        )?;
        assert!(!report.is_go());
        let source_snapshot =
            PreverifiedSourceSnapshotV1::new_verified(BackendKind::Rpc, 0, capture.measurement())?;

        publish_insertion_bound(
            &output_dir,
            &capture,
            &sizing,
            &report,
            failure_budget_bps,
            &source_snapshot,
            "test-runner",
        )?;

        let names = fs::read_dir(&output_dir)?
            .map(|entry| entry.map(|entry| entry.file_name()))
            .collect::<Result<BTreeSet<_>, _>>()?;
        assert_eq!(
            names,
            BTreeSet::from([
                OsString::from(INSERTION_BOUND_JSON),
                OsString::from(INSERTION_BOUND_TEXT),
                OsString::from(PROVENANCE_JSON),
            ])
        );
        let artifact: InsertionBoundArtifactV1 =
            serde_json::from_slice(&fs::read(output_dir.join(INSERTION_BOUND_JSON))?)?;
        artifact.validate(
            capture.measurement(),
            sizing.qualification(),
            capture.measurement_blake2s256(),
            sizing.qualification_blake2s256(),
            failure_budget_bps,
            &source_snapshot,
        )?;
        assert!(!artifact.insertion_bound.is_go());
        assert_eq!(
            fs::read(output_dir.join(INSERTION_BOUND_TEXT))?,
            report.to_string().as_bytes()
        );
        let provenance_bytes = fs::read(output_dir.join(PROVENANCE_JSON))?;
        let provenance_value: serde_json::Value = serde_json::from_slice(&provenance_bytes)?;
        assert!(provenance_value.get("target_os").is_none());
        assert!(provenance_value.get("target_arch").is_none());
        let provenance: InsertionBoundProvenanceV1 = serde_json::from_slice(&provenance_bytes)?;
        provenance.validate(&artifact)?;
        Ok(())
    }
}
