//! Shared semantic contract for Gate 2 insertion timing evidence.

use std::fmt;

use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use zaino_oram::{ExperimentPlan, RostlTimingError, RostlTimingMode, MINIMUM_PAIRS};

pub(super) const TIMING_EVIDENCE_SCHEMA: &str = "zaino-oram-insert-timing-v3";
// This source is compiled into two binaries. These knobs are consumed only by
// the standalone driver; the qualification runner consumes the fixed contract.
#[allow(dead_code)]
pub(super) const DEFAULT_WARMUP_PAIRS: usize = 50;
#[allow(dead_code)]
pub(super) const DIRECTORY_SCHEDULE_SEED_DOMAIN: u64 = 0x5e12_33a1_a341_71d1;
#[allow(dead_code)]
pub(super) const DIRECTORY_REPORT_SEED_DOMAIN: u64 = 0x6127_0c6f_3475_8a0b;
#[allow(dead_code)]
pub(super) const EVENT_SCHEDULE_SEED_DOMAIN: u64 = 0xe7e1_82a5_7b9c_4d31;
#[allow(dead_code)]
pub(super) const EVENT_REPORT_SEED_DOMAIN: u64 = 0x7b91_ed09_451f_83c7;
pub(super) const STATE_CONTROL: &str = "matched_long_lived_logical_twin_tables_v1";
pub(super) const LABEL_ASSIGNMENT: &str = "alternating_physical_tables";
pub(super) const ORDER_BLOCKING: &str = "physical_table_role_parity_v1";
pub(super) const DIRECTORY_RECORD_MODEL: &str = "directory_single_cell_v1";
pub(super) const EVENT_RECORD_MODEL: &str = "event_single_immutable_cell_v1";
pub(super) const TARGET_PROJECTION_MODEL: &str = "chunked_generational_events";
pub(super) const STATISTICAL_SCOPE: &str = "nominal_iid_bounds_on_serially_dependent_rounds";
pub(super) const SUPPORTED_MODES: [RostlTimingMode; 3] = [
    RostlTimingMode::HitMiss,
    RostlTimingMode::ForcedHit,
    RostlTimingMode::ForcedMiss,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "snake_case")]
pub(super) enum EvidenceIntent {
    Pilot,
    QualificationCandidate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct OccupancyWindow {
    pub(super) initial: usize,
    pub(super) measured_start: usize,
    pub(super) measured_last_pre: usize,
    pub(super) final_occupancy: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum TimingContractError {
    UnderpoweredQualificationCandidate { requested: usize },
    UnbalancedQualificationCandidate,
}

impl fmt::Display for TimingContractError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnderpoweredQualificationCandidate { requested } => write!(
                formatter,
                "qualification candidate requested {requested} measured pairs; at least {MINIMUM_PAIRS} are required"
            ),
            Self::UnbalancedQualificationCandidate => formatter.write_str(
                "qualification candidate requires measured pairs divisible by four and an even warm-up pair count",
            ),
        }
    }
}

impl std::error::Error for TimingContractError {}

pub(super) fn validate_evidence_intent(
    intent: EvidenceIntent,
    pairs: usize,
    warmup_pairs: usize,
) -> Result<(), TimingContractError> {
    if intent == EvidenceIntent::QualificationCandidate && pairs < MINIMUM_PAIRS {
        return Err(TimingContractError::UnderpoweredQualificationCandidate { requested: pairs });
    }
    if intent == EvidenceIntent::QualificationCandidate
        && (!pairs.is_multiple_of(4) || !warmup_pairs.is_multiple_of(2))
    {
        return Err(TimingContractError::UnbalancedQualificationCandidate);
    }
    Ok(())
}

#[allow(dead_code)]
pub(super) const fn timed_operation_model(mode: RostlTimingMode) -> &'static str {
    match mode {
        RostlTimingMode::HitMiss => {
            "mixed_duplicate_and_unique_insert_current_single_cell_baseline_v1"
        }
        RostlTimingMode::ForcedHit => "duplicate_insert_current_single_cell_control_v1",
        RostlTimingMode::ForcedMiss => "unique_insert_current_single_cell_control_v1",
    }
}

#[allow(dead_code)]
pub(super) const fn table_set_relation(mode: RostlTimingMode) -> &'static str {
    match mode {
        RostlTimingMode::HitMiss => "one_record_substitution_equal_cardinality",
        RostlTimingMode::ForcedHit | RostlTimingMode::ForcedMiss => "identical_key_sets",
    }
}

pub(super) fn occupancy_window(
    initial: usize,
    plan: &ExperimentPlan,
) -> Result<OccupancyWindow, RostlTimingError> {
    let measured_start = initial
        .checked_add(plan.warmup_pairs())
        .ok_or(RostlTimingError::InvalidShape)?;
    let measured_last_pre = measured_start
        .checked_add(
            plan.pairs()
                .checked_sub(1)
                .ok_or(RostlTimingError::InvalidShape)?,
        )
        .ok_or(RostlTimingError::InvalidShape)?;
    let final_occupancy = initial
        .checked_add(plan.total_pairs())
        .ok_or(RostlTimingError::InvalidShape)?;
    Ok(OccupancyWindow {
        initial,
        measured_start,
        measured_last_pre,
        final_occupancy,
    })
}

#[allow(dead_code)]
pub(super) fn derive_seed(root: u64, domain: u64) -> u64 {
    let mut value = root ^ domain;
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}
