//! Source-bound deterministic insertion-budget evidence.
//!
//! This analyzer replays the exact standard-address event sequence emitted by
//! the mainnet corpus scanner through keyed fixed-probe layouts. Its eight
//! deterministic seeds are a sampled engineering schedule, not a probability
//! distribution, a worst-case proof, or a physical ORAM measurement.

use std::fmt;

use blake2::{Blake2s256, Digest};
use serde::{Deserialize, Serialize};
use zaino_state::IndexedBlock;

use crate::{
    layout::{
        FixedLayoutAllocation, LayoutIdentity, LayoutNetwork, RuntimeBoundDirectorySlot,
        RuntimeProbeLayout,
    },
    target_load::is_blake2s256_hex,
    zaino_corpus::{
        CollectedStandardAddressEvent, MainnetCorpusMeasurement, MainnetCorpusScanner,
        MainnetSizingQualification,
    },
};

const SCENARIO: &str = "source-bound-insertion-budget-v1";
const SEED_DERIVATION: &str = "blake2s256-domain-separated-fixed-profile-and-seed-index-v1";
const SEED_DOMAIN: &[u8] = b"zaino-oram/insertion-budget-seed/v1\0";
const SCHEMA_VERSION: u32 = 1;
const KEY_EPOCH: u64 = 1;
const LAYOUT_GENERATION: u64 = 1;
const SEED_COUNT: u16 = 8;
const BASIS_POINTS: u64 = 10_000;
const CAPACITY_MULTIPLIERS: [u8; 1] = [1];
const PROBE_COUNTS: [u8; 1] = [4];
const CURRENT_CAPACITY_MULTIPLIER: u8 = 1;
const CURRENT_PROBE_COUNT: u8 = 4;

/// Fixed deterministic insertion-analysis profile selected by the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SourceBoundInsertionBudgetProfile {
    /// Eight fixed schedules over the current-capacity, four-probe layout.
    CurrentFourProbeV1,
}

impl SourceBoundInsertionBudgetProfile {
    /// Returns the stable artifact label for this profile.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CurrentFourProbeV1 => "current-four-probe-v1",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceBinding {
    measurement_blake2s256: String,
    qualification_blake2s256: String,
    checkpoint_height: u32,
    checkpoint_hash: String,
    expected_blocks: u64,
}

impl SourceBinding {
    fn validate(&self) -> bool {
        is_blake2s256_hex(&self.measurement_blake2s256)
            && is_blake2s256_hex(&self.qualification_blake2s256)
            && is_blake2s256_hex(&self.checkpoint_hash)
            && self.expected_blocks == u64::from(self.checkpoint_height) + 1
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BaseLayoutShape {
    directory_capacity: u64,
    directory_admission_limit: u64,
    event_capacity: u64,
    event_admission_limit: u64,
    max_events_per_address: u64,
}

impl BaseLayoutShape {
    fn from_sizing(sizing: &MainnetSizingQualification) -> Self {
        let model = sizing.model();
        Self {
            directory_capacity: model.directory_capacity(),
            directory_admission_limit: model.directory_admission_limit(),
            event_capacity: model.event_capacity(),
            event_admission_limit: model.event_admission_limit(),
            max_events_per_address: model.max_events_per_address(),
        }
    }

    fn validate(self) -> bool {
        FixedLayoutAllocation::new(
            self.directory_capacity,
            self.directory_admission_limit,
            self.event_capacity,
            self.event_admission_limit,
            self.max_events_per_address,
        )
        .is_ok()
    }

    fn scaled(self, multiplier: u8) -> Option<(u64, u64)> {
        let multiplier = u64::from(multiplier);
        Some((
            self.directory_capacity.checked_mul(multiplier)?,
            self.event_capacity.checked_mul(multiplier)?,
        ))
    }

    fn allocation_for(
        self,
        multiplier: u8,
    ) -> Result<FixedLayoutAllocation, SourceBoundInsertionBudgetError> {
        let (directory_capacity, event_capacity) = self
            .scaled(multiplier)
            .ok_or(SourceBoundInsertionBudgetError::ConstructionFailed)?;
        FixedLayoutAllocation::new(
            directory_capacity,
            self.directory_admission_limit,
            event_capacity,
            self.event_admission_limit,
            self.max_events_per_address,
        )
        .map_err(|_| SourceBoundInsertionBudgetError::ConstructionFailed)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AnalysisInputs {
    source: SourceBinding,
    shape: BaseLayoutShape,
    failure_budget_bps: u64,
    expected_standard_addresses: u64,
    expected_standard_address_events: u64,
    expected_maximum_events_per_address: u64,
}

impl AnalysisInputs {
    fn from_artifacts(
        measurement: &MainnetCorpusMeasurement,
        sizing: &MainnetSizingQualification,
        measurement_blake2s256: &str,
        qualification_blake2s256: &str,
        failure_budget_bps: u64,
    ) -> Result<Self, SourceBoundInsertionBudgetError> {
        measurement
            .validate()
            .map_err(|_| SourceBoundInsertionBudgetError::InputRejected)?;
        sizing
            .validate_against(measurement)
            .map_err(|_| SourceBoundInsertionBudgetError::InputRejected)?;
        if failure_budget_bps > BASIS_POINTS {
            return Err(SourceBoundInsertionBudgetError::InputRejected);
        }
        let expected_standard_address_events = measurement
            .standard_address_events()
            .ok_or(SourceBoundInsertionBudgetError::InputRejected)?;
        let inputs = Self {
            source: SourceBinding {
                measurement_blake2s256: measurement_blake2s256.to_owned(),
                qualification_blake2s256: qualification_blake2s256.to_owned(),
                checkpoint_height: measurement.checkpoint().height(),
                checkpoint_hash: measurement.checkpoint().hash().to_owned(),
                expected_blocks: u64::from(measurement.checkpoint().height()) + 1,
            },
            shape: BaseLayoutShape::from_sizing(sizing),
            failure_budget_bps,
            expected_standard_addresses: measurement.distinct_standard_addresses(),
            expected_standard_address_events,
            expected_maximum_events_per_address: measurement.maximum_events_per_address(),
        };
        if !inputs.source.validate()
            || !inputs.shape.validate()
            || inputs.expected_standard_addresses == 0
            || inputs.expected_standard_address_events == 0
            || inputs.expected_maximum_events_per_address == 0
        {
            return Err(SourceBoundInsertionBudgetError::InputRejected);
        }
        Ok(inputs)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum LogicalLimitKind {
    DirectoryAdmission,
    EventAdmission,
    PerAddressEvent,
}

impl LogicalLimitKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::DirectoryAdmission => "directory-admission",
            Self::EventAdmission => "event-admission",
            Self::PerAddressEvent => "per-address-event",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum TrialDisposition {
    Completed,
    DirectoryProbeExhausted,
    EventProbeExhausted,
    DirectoryAdmissionReached,
    EventAdmissionReached,
    PerAddressEventLimitReached,
}

impl TrialDisposition {
    const fn is_failure(self) -> bool {
        !matches!(self, Self::Completed)
    }

    const fn from_logical_limit(limit: LogicalLimitKind) -> Self {
        match limit {
            LogicalLimitKind::DirectoryAdmission => Self::DirectoryAdmissionReached,
            LogicalLimitKind::EventAdmission => Self::EventAdmissionReached,
            LogicalLimitKind::PerAddressEvent => Self::PerAddressEventLimitReached,
        }
    }

    const fn logical_limit(self) -> Option<LogicalLimitKind> {
        match self {
            Self::DirectoryAdmissionReached => Some(LogicalLimitKind::DirectoryAdmission),
            Self::EventAdmissionReached => Some(LogicalLimitKind::EventAdmission),
            Self::PerAddressEventLimitReached => Some(LogicalLimitKind::PerAddressEvent),
            Self::Completed | Self::DirectoryProbeExhausted | Self::EventProbeExhausted => None,
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::DirectoryProbeExhausted => "directory-probe-exhausted",
            Self::EventProbeExhausted => "event-probe-exhausted",
            Self::DirectoryAdmissionReached => "directory-admission-reached",
            Self::EventAdmissionReached => "event-admission-reached",
            Self::PerAddressEventLimitReached => "per-address-event-limit-reached",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SeedTrialReport {
    seed_index: u16,
    directory_disposition: TrialDisposition,
    event_path_disposition: TrialDisposition,
    directory_occupied: u64,
    event_occupied: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CurvePoint {
    capacity_multiplier: u8,
    probe_count: u8,
    directory_capacity: Option<u64>,
    event_capacity: Option<u64>,
    configuration_available: bool,
    trials: Vec<SeedTrialReport>,
    failed_seed_schedules: Option<u16>,
    directory_failed_seed_schedules: Option<u16>,
    event_path_failed_seed_schedules: Option<u16>,
    direct_event_probe_failed_seed_schedules: Option<u16>,
    sampled_failure_bps: Option<u64>,
    sampled_directory_failure_bps: Option<u64>,
    sampled_event_path_failure_bps: Option<u64>,
    sampled_direct_event_probe_failure_bps: Option<u64>,
    directory_meets_sampled_failure_budget: bool,
    event_path_meets_sampled_failure_budget: bool,
    meets_sampled_failure_budget: bool,
}

impl CurvePoint {
    fn unavailable(spec: CurveSpec, shape: BaseLayoutShape) -> Self {
        let capacities = shape.scaled(spec.capacity_multiplier);
        Self {
            capacity_multiplier: spec.capacity_multiplier,
            probe_count: spec.probe_count,
            directory_capacity: capacities.map(|(directory, _)| directory),
            event_capacity: capacities.map(|(_, event)| event),
            configuration_available: false,
            trials: Vec::new(),
            failed_seed_schedules: None,
            directory_failed_seed_schedules: None,
            event_path_failed_seed_schedules: None,
            direct_event_probe_failed_seed_schedules: None,
            sampled_failure_bps: None,
            sampled_directory_failure_bps: None,
            sampled_event_path_failure_bps: None,
            sampled_direct_event_probe_failure_bps: None,
            directory_meets_sampled_failure_budget: false,
            event_path_meets_sampled_failure_budget: false,
            meets_sampled_failure_budget: false,
        }
    }

    fn from_trials(
        spec: CurveSpec,
        shape: BaseLayoutShape,
        trials: Vec<SeedTrialReport>,
        failure_budget_bps: u64,
        logical_limit: Option<LogicalLimitKind>,
    ) -> Result<Self, SourceBoundInsertionBudgetError> {
        let (directory_capacity, event_capacity) = shape
            .scaled(spec.capacity_multiplier)
            .ok_or(SourceBoundInsertionBudgetError::InvalidReport)?;
        let failed_seed_schedules =
            count_trials(&trials, |trial| trial.event_path_disposition.is_failure())?;
        let directory_failed_seed_schedules =
            count_trials(&trials, |trial| trial.directory_disposition.is_failure())?;
        let event_path_failed_seed_schedules =
            count_trials(&trials, |trial| trial.event_path_disposition.is_failure())?;
        let direct_event_probe_failed_seed_schedules = count_trials(&trials, |trial| {
            matches!(
                trial.event_path_disposition,
                TrialDisposition::EventProbeExhausted
            )
        })?;
        let sampled_failure_bps = sampled_rate_bps(failed_seed_schedules)?;
        let sampled_directory_failure_bps = sampled_rate_bps(directory_failed_seed_schedules)?;
        let sampled_event_path_failure_bps = sampled_rate_bps(event_path_failed_seed_schedules)?;
        let sampled_direct_event_probe_failure_bps =
            sampled_rate_bps(direct_event_probe_failed_seed_schedules)?;
        let directory_meets_sampled_failure_budget =
            logical_limit.is_none() && sampled_directory_failure_bps <= failure_budget_bps;
        let event_path_meets_sampled_failure_budget =
            logical_limit.is_none() && sampled_event_path_failure_bps <= failure_budget_bps;
        Ok(Self {
            capacity_multiplier: spec.capacity_multiplier,
            probe_count: spec.probe_count,
            directory_capacity: Some(directory_capacity),
            event_capacity: Some(event_capacity),
            configuration_available: true,
            trials,
            failed_seed_schedules: Some(failed_seed_schedules),
            directory_failed_seed_schedules: Some(directory_failed_seed_schedules),
            event_path_failed_seed_schedules: Some(event_path_failed_seed_schedules),
            direct_event_probe_failed_seed_schedules: Some(
                direct_event_probe_failed_seed_schedules,
            ),
            sampled_failure_bps: Some(sampled_failure_bps),
            sampled_directory_failure_bps: Some(sampled_directory_failure_bps),
            sampled_event_path_failure_bps: Some(sampled_event_path_failure_bps),
            sampled_direct_event_probe_failure_bps: Some(sampled_direct_event_probe_failure_bps),
            directory_meets_sampled_failure_budget,
            event_path_meets_sampled_failure_budget,
            meets_sampled_failure_budget: event_path_meets_sampled_failure_budget
                && sampled_failure_bps <= failure_budget_bps,
        })
    }

    const fn spec(&self) -> CurveSpec {
        CurveSpec {
            capacity_multiplier: self.capacity_multiplier,
            probe_count: self.probe_count,
        }
    }

    fn validate(
        &self,
        shape: BaseLayoutShape,
        failure_budget_bps: u64,
        logical_limit: Option<LogicalLimitKind>,
        distinct_standard_addresses: u64,
        standard_address_events: u64,
    ) -> bool {
        let spec = self.spec();
        if !CAPACITY_MULTIPLIERS.contains(&spec.capacity_multiplier)
            || !PROBE_COUNTS.contains(&spec.probe_count)
        {
            return false;
        }
        let scaled = shape.scaled(spec.capacity_multiplier);
        if self.directory_capacity != scaled.map(|(directory, _)| directory)
            || self.event_capacity != scaled.map(|(_, event)| event)
        {
            return false;
        }
        let allocation_available = curve_spec_available(shape, spec);
        if self.configuration_available != allocation_available {
            return false;
        }
        if !self.configuration_available {
            return self.trials.is_empty()
                && self.failed_seed_schedules.is_none()
                && self.directory_failed_seed_schedules.is_none()
                && self.event_path_failed_seed_schedules.is_none()
                && self.direct_event_probe_failed_seed_schedules.is_none()
                && self.sampled_failure_bps.is_none()
                && self.sampled_directory_failure_bps.is_none()
                && self.sampled_event_path_failure_bps.is_none()
                && self.sampled_direct_event_probe_failure_bps.is_none()
                && !self.directory_meets_sampled_failure_budget
                && !self.event_path_meets_sampled_failure_budget
                && !self.meets_sampled_failure_budget;
        }
        if !valid_seed_reports(
            &self.trials,
            logical_limit,
            shape,
            distinct_standard_addresses,
            standard_address_events,
            self.directory_capacity,
            self.event_capacity,
        ) {
            return false;
        }
        let Ok(expected) = Self::from_trials(
            spec,
            shape,
            self.trials.clone(),
            failure_budget_bps,
            logical_limit,
        ) else {
            return false;
        };
        *self == expected
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CurveSpec {
    capacity_multiplier: u8,
    probe_count: u8,
}

impl CurveSpec {
    const fn is_current(self) -> bool {
        self.capacity_multiplier == CURRENT_CAPACITY_MULTIPLIER
            && self.probe_count == CURRENT_PROBE_COUNT
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum InsertionVerdict {
    Go,
    NoGo,
}

impl InsertionVerdict {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Go => "go",
            Self::NoGo => "no-go",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum RecommendationKind {
    CurrentProfileMeetsBudget,
    CurrentProfileExceedsBudget,
    LogicalLimitExceeded,
}

impl RecommendationKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::CurrentProfileMeetsBudget => "current-profile-meets-budget",
            Self::CurrentProfileExceedsBudget => "current-profile-exceeds-budget",
            Self::LogicalLimitExceeded => "logical-limit-exceeded",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Recommendation {
    kind: RecommendationKind,
    capacity_multiplier: Option<u8>,
    probe_count: Option<u8>,
    directory_capacity: Option<u64>,
    event_capacity: Option<u64>,
}

impl Recommendation {
    const fn current(point: &CurvePoint) -> Self {
        Self {
            kind: RecommendationKind::CurrentProfileMeetsBudget,
            capacity_multiplier: Some(point.capacity_multiplier),
            probe_count: Some(point.probe_count),
            directory_capacity: point.directory_capacity,
            event_capacity: point.event_capacity,
        }
    }

    const fn current_miss(point: &CurvePoint) -> Self {
        Self {
            kind: RecommendationKind::CurrentProfileExceedsBudget,
            capacity_multiplier: Some(point.capacity_multiplier),
            probe_count: Some(point.probe_count),
            directory_capacity: point.directory_capacity,
            event_capacity: point.event_capacity,
        }
    }

    const fn logical_limit() -> Self {
        Self {
            kind: RecommendationKind::LogicalLimitExceeded,
            capacity_multiplier: None,
            probe_count: None,
            directory_capacity: None,
            event_capacity: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum TableRecommendationKind {
    RetainCurrentTableShape,
    CurrentTableShapeExceedsBudget,
    LogicalLimitExceeded,
}

impl TableRecommendationKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::RetainCurrentTableShape => "retain-current-table-shape",
            Self::CurrentTableShapeExceedsBudget => "current-table-shape-exceeds-budget",
            Self::LogicalLimitExceeded => "logical-limit-exceeded",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TableRecommendation {
    kind: TableRecommendationKind,
    capacity: Option<u64>,
    probe_count: Option<u8>,
    isolated_single_table_change_tested: bool,
}

impl TableRecommendation {
    const fn current(capacity: Option<u64>, probe_count: u8) -> Self {
        Self {
            kind: TableRecommendationKind::RetainCurrentTableShape,
            capacity,
            probe_count: Some(probe_count),
            isolated_single_table_change_tested: false,
        }
    }

    const fn current_miss(capacity: Option<u64>, probe_count: u8) -> Self {
        Self {
            kind: TableRecommendationKind::CurrentTableShapeExceedsBudget,
            capacity,
            probe_count: Some(probe_count),
            isolated_single_table_change_tested: false,
        }
    }

    const fn logical_limit() -> Self {
        Self {
            kind: TableRecommendationKind::LogicalLimitExceeded,
            capacity: None,
            probe_count: None,
            isolated_single_table_change_tested: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EvidenceScope {
    mainnet_genesis_and_chain_continuity_validated: bool,
    source_measurement_recomputed_and_matched: bool,
    exact_standard_event_order_replayed: bool,
    projected_growth_analyzed: bool,
    deterministic_seed_schedules_sampled: bool,
    stop_at_first_failed_insertion_per_lane: bool,
    alternative_capacity_or_probe_profiles_analyzed: bool,
    any_logical_limit_latches_all_lanes: bool,
    directory_lane_continues_after_event_path_failure: bool,
    isolated_single_table_resize_tested: bool,
    keyed_blake2s_prf_assumed_not_proven: bool,
    odd_step_double_hashing_used: bool,
    probe_independence_assumed: bool,
    sampled_schedules_are_probability_distribution: bool,
    probabilistic_failure_bound_established: bool,
    worst_case_bound_established: bool,
    physical_oram_accesses_measured: bool,
    backend_calibrated: bool,
    target_hardware_qualified: bool,
    tdx_qualified: bool,
    mainnet_ready: bool,
}

const EVIDENCE_SCOPE: EvidenceScope = EvidenceScope {
    mainnet_genesis_and_chain_continuity_validated: true,
    source_measurement_recomputed_and_matched: true,
    exact_standard_event_order_replayed: true,
    projected_growth_analyzed: false,
    deterministic_seed_schedules_sampled: true,
    stop_at_first_failed_insertion_per_lane: true,
    alternative_capacity_or_probe_profiles_analyzed: false,
    any_logical_limit_latches_all_lanes: true,
    directory_lane_continues_after_event_path_failure: true,
    isolated_single_table_resize_tested: false,
    keyed_blake2s_prf_assumed_not_proven: true,
    odd_step_double_hashing_used: true,
    probe_independence_assumed: false,
    sampled_schedules_are_probability_distribution: false,
    probabilistic_failure_bound_established: false,
    worst_case_bound_established: false,
    physical_oram_accesses_measured: false,
    backend_calibrated: false,
    target_hardware_qualified: false,
    tdx_qualified: false,
    mainnet_ready: false,
};

/// Aggregate-only evidence from one exact source-bound deterministic seed sweep.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceBoundInsertionBudgetReport {
    scenario: String,
    profile: SourceBoundInsertionBudgetProfile,
    source: SourceBinding,
    base_layout: BaseLayoutShape,
    seed_derivation: String,
    seed_count: u16,
    capacity_multipliers: Vec<u8>,
    probe_counts: Vec<u8>,
    failure_budget_bps: u64,
    applied_blocks: u64,
    standard_address_events: u64,
    distinct_standard_addresses: u64,
    maximum_events_per_address: u64,
    logical_limit: Option<LogicalLimitKind>,
    curve: Vec<CurvePoint>,
    verdict: InsertionVerdict,
    recommendation: Recommendation,
    directory_recommendation: TableRecommendation,
    event_path_recommendation: TableRecommendation,
    evidence_scope: EvidenceScope,
}

impl SourceBoundInsertionBudgetReport {
    /// Revalidates the complete self-contained sampled-schedule report.
    pub fn validate(&self) -> Result<(), SourceBoundInsertionBudgetError> {
        if self.scenario != SCENARIO
            || self.profile != SourceBoundInsertionBudgetProfile::CurrentFourProbeV1
            || !self.source.validate()
            || !self.base_layout.validate()
            || self.seed_derivation != SEED_DERIVATION
            || self.seed_count != SEED_COUNT
            || self.capacity_multipliers != CAPACITY_MULTIPLIERS
            || self.probe_counts != PROBE_COUNTS
            || self.failure_budget_bps > BASIS_POINTS
            || self.applied_blocks != self.source.expected_blocks
            || self.standard_address_events == 0
            || self.distinct_standard_addresses == 0
            || self.distinct_standard_addresses > self.standard_address_events
            || self.maximum_events_per_address == 0
            || self.maximum_events_per_address > self.standard_address_events
            || self.curve.len() != CAPACITY_MULTIPLIERS.len() * PROBE_COUNTS.len()
            || self.evidence_scope != EVIDENCE_SCOPE
            || !logical_limit_matches_observed_totals(
                self.base_layout,
                self.distinct_standard_addresses,
                self.standard_address_events,
                self.maximum_events_per_address,
                self.logical_limit,
            )
        {
            return Err(SourceBoundInsertionBudgetError::InvalidReport);
        }
        for (index, point) in self.curve.iter().enumerate() {
            let capacity_index = index / PROBE_COUNTS.len();
            let probe_index = index % PROBE_COUNTS.len();
            if point.capacity_multiplier != CAPACITY_MULTIPLIERS[capacity_index]
                || point.probe_count != PROBE_COUNTS[probe_index]
                || !point.validate(
                    self.base_layout,
                    self.failure_budget_bps,
                    self.logical_limit,
                    self.distinct_standard_addresses,
                    self.standard_address_events,
                )
            {
                return Err(SourceBoundInsertionBudgetError::InvalidReport);
            }
        }
        let (verdict, recommendation) =
            verdict_and_recommendation(&self.curve, self.logical_limit)?;
        let (directory_recommendation, event_path_recommendation) =
            table_recommendations(&self.curve, self.logical_limit)?;
        if self.verdict != verdict
            || self.recommendation != recommendation
            || self.directory_recommendation != directory_recommendation
            || self.event_path_recommendation != event_path_recommendation
        {
            return Err(SourceBoundInsertionBudgetError::InvalidReport);
        }
        Ok(())
    }

    /// Revalidates the report against its exact capture, sizing, lineage, and
    /// sampled-schedule failure budget.
    pub fn validate_against(
        &self,
        measurement: &MainnetCorpusMeasurement,
        sizing: &MainnetSizingQualification,
        measurement_blake2s256: &str,
        qualification_blake2s256: &str,
        failure_budget_bps: u64,
    ) -> Result<(), SourceBoundInsertionBudgetError> {
        self.validate()?;
        let expected = AnalysisInputs::from_artifacts(
            measurement,
            sizing,
            measurement_blake2s256,
            qualification_blake2s256,
            failure_budget_bps,
        )?;
        if self.source != expected.source
            || self.base_layout != expected.shape
            || self.failure_budget_bps != expected.failure_budget_bps
            || self.distinct_standard_addresses != expected.expected_standard_addresses
            || self.standard_address_events != expected.expected_standard_address_events
            || self.maximum_events_per_address != expected.expected_maximum_events_per_address
        {
            return Err(SourceBoundInsertionBudgetError::InvalidReport);
        }
        Ok(())
    }

    /// Returns `true` only when the current-capacity, four-probe profile meets
    /// the caller's budget across all eight sampled deterministic schedules.
    pub const fn is_go(&self) -> bool {
        matches!(self.verdict, InsertionVerdict::Go)
    }
}

impl fmt::Display for SourceBoundInsertionBudgetReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "scenario={}", self.scenario)?;
        writeln!(f, "profile={}", self.profile.as_str())?;
        writeln!(
            f,
            "source=height:{},hash:{},blocks:{},measurement_blake2s256:{},qualification_blake2s256:{}",
            self.source.checkpoint_height,
            self.source.checkpoint_hash,
            self.source.expected_blocks,
            self.source.measurement_blake2s256,
            self.source.qualification_blake2s256,
        )?;
        writeln!(
            f,
            "base_layout=directory:{}/{},event:{}/{},max_events_per_address:{}",
            self.base_layout.directory_admission_limit,
            self.base_layout.directory_capacity,
            self.base_layout.event_admission_limit,
            self.base_layout.event_capacity,
            self.base_layout.max_events_per_address,
        )?;
        writeln!(
            f,
            "sampled_schedule=seed_derivation:{},seeds:{},capacity_multipliers:1,probe_counts:4,stop_at_first_failure_per_lane:true,alternative_profiles_analyzed:false,any_logical_limit_latches_all_lanes:true,failure_budget_bps:{}",
            self.seed_derivation, self.seed_count, self.failure_budget_bps,
        )?;
        writeln!(
            f,
            "replay=blocks:{},standard_address_events:{},distinct_standard_addresses:{},maximum_events_per_address:{},logical_limit:{}",
            self.applied_blocks,
            self.standard_address_events,
            self.distinct_standard_addresses,
            self.maximum_events_per_address,
            self.logical_limit.map_or("none", LogicalLimitKind::as_str),
        )?;
        for point in &self.curve {
            writeln!(
                f,
                "curve=capacity_multiplier:{},probe_count:{},directory_capacity:{},event_capacity:{},available:{},failed_seed_schedules:{},directory_failed_seed_schedules:{},event_path_failed_seed_schedules:{},direct_event_probe_failed_seed_schedules:{},sampled_failure_bps:{},sampled_directory_failure_bps:{},sampled_event_path_failure_bps:{},sampled_direct_event_probe_failure_bps:{},directory_meets_budget:{},event_path_meets_budget:{},meets_budget:{}",
                point.capacity_multiplier,
                point.probe_count,
                optional_u64(point.directory_capacity),
                optional_u64(point.event_capacity),
                point.configuration_available,
                optional_u16(point.failed_seed_schedules),
                optional_u16(point.directory_failed_seed_schedules),
                optional_u16(point.event_path_failed_seed_schedules),
                optional_u16(point.direct_event_probe_failed_seed_schedules),
                optional_u64(point.sampled_failure_bps),
                optional_u64(point.sampled_directory_failure_bps),
                optional_u64(point.sampled_event_path_failure_bps),
                optional_u64(point.sampled_direct_event_probe_failure_bps),
                point.directory_meets_sampled_failure_budget,
                point.event_path_meets_sampled_failure_budget,
                point.meets_sampled_failure_budget,
            )?;
            for trial in &point.trials {
                writeln!(
                    f,
                    "trial=capacity_multiplier:{},probe_count:{},seed_index:{},directory_disposition:{},event_path_disposition:{},directory_occupied:{},event_occupied:{}",
                    point.capacity_multiplier,
                    point.probe_count,
                    trial.seed_index,
                    trial.directory_disposition.as_str(),
                    trial.event_path_disposition.as_str(),
                    trial.directory_occupied,
                    trial.event_occupied,
                )?;
            }
        }
        writeln!(
            f,
            "result=verdict:{},recommendation:{},capacity_multiplier:{},probe_count:{},directory_capacity:{},event_capacity:{}",
            self.verdict.as_str(),
            self.recommendation.kind.as_str(),
            optional_u8(self.recommendation.capacity_multiplier),
            optional_u8(self.recommendation.probe_count),
            optional_u64(self.recommendation.directory_capacity),
            optional_u64(self.recommendation.event_capacity),
        )?;
        writeln!(
            f,
            "directory_recommendation=kind:{},capacity:{},probe_count:{},isolated_single_table_change_tested:{}",
            self.directory_recommendation.kind.as_str(),
            optional_u64(self.directory_recommendation.capacity),
            optional_u8(self.directory_recommendation.probe_count),
            self.directory_recommendation
                .isolated_single_table_change_tested,
        )?;
        writeln!(
            f,
            "event_path_recommendation=kind:{},capacity:{},probe_count:{},isolated_single_table_change_tested:{}",
            self.event_path_recommendation.kind.as_str(),
            optional_u64(self.event_path_recommendation.capacity),
            optional_u8(self.event_path_recommendation.probe_count),
            self.event_path_recommendation
                .isolated_single_table_change_tested,
        )?;
        write!(
            f,
            "nonclaims=projected-growth,alternative-capacity-or-probe-profiles,isolated-single-table-resize,logical-limit-lane-isolation,probability-distribution,probabilistic-failure-bound,worst-case-bound,probe-independence,physical-oram-trace,backend-calibration,target-hardware,tdx,mainnet-readiness"
        )
    }
}

/// Coarse identifier-free failure from source-bound insertion analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceBoundInsertionBudgetError {
    /// Capture, sizing, lineage, digest, or budget input validation failed.
    InputRejected,
    /// A fixed layout, bitset, or sampled trial could not be constructed.
    ConstructionFailed,
    /// The supplied block sequence or recomputed source measurement was rejected.
    SourceRejected,
    /// Exact event replay or keyed probe planning failed closed.
    AnalysisFailed,
    /// A serialized report differs from its fixed inputs or claim boundary.
    InvalidReport,
}

impl fmt::Display for SourceBoundInsertionBudgetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InputRejected => f.write_str("source-bound insertion-budget input was rejected"),
            Self::ConstructionFailed => {
                f.write_str("source-bound insertion-budget construction failed")
            }
            Self::SourceRejected => {
                f.write_str("source-bound insertion-budget source sequence was rejected")
            }
            Self::AnalysisFailed => f.write_str("source-bound insertion-budget analysis failed"),
            Self::InvalidReport => f.write_str("source-bound insertion-budget report is invalid"),
        }
    }
}

impl std::error::Error for SourceBoundInsertionBudgetError {}

/// Incremental exact-source replay for deterministic insertion-budget evidence.
pub struct SourceBoundInsertionBudgetSession {
    scanner: Option<MainnetCorpusScanner>,
    expected_measurement: MainnetCorpusMeasurement,
    inputs: AnalysisInputs,
    trials: Vec<SeedTrial>,
    unavailable_specs: Vec<CurveSpec>,
    applied_blocks: u64,
    standard_address_events: u64,
    distinct_standard_addresses: u64,
    maximum_events_per_address: u64,
    logical_limit: Option<LogicalLimitKind>,
    failed_closed: bool,
}

impl SourceBoundInsertionBudgetSession {
    /// Validates the source artifacts and constructs eight fixed schedules for
    /// the current-capacity, four-probe layout.
    pub fn start(
        profile: SourceBoundInsertionBudgetProfile,
        measurement: &MainnetCorpusMeasurement,
        sizing: &MainnetSizingQualification,
        measurement_blake2s256: &str,
        qualification_blake2s256: &str,
        failure_budget_bps: u64,
    ) -> Result<Self, SourceBoundInsertionBudgetError> {
        if profile != SourceBoundInsertionBudgetProfile::CurrentFourProbeV1 {
            return Err(SourceBoundInsertionBudgetError::InputRejected);
        }
        let inputs = AnalysisInputs::from_artifacts(
            measurement,
            sizing,
            measurement_blake2s256,
            qualification_blake2s256,
            failure_budget_bps,
        )?;
        let mut trials = Vec::new();
        let mut unavailable_specs = Vec::new();
        for capacity_multiplier in CAPACITY_MULTIPLIERS {
            for probe_count in PROBE_COUNTS {
                let spec = CurveSpec {
                    capacity_multiplier,
                    probe_count,
                };
                if !curve_spec_available(inputs.shape, spec) {
                    unavailable_specs.push(spec);
                    continue;
                }
                let allocation = match inputs.shape.allocation_for(capacity_multiplier) {
                    Ok(allocation) => allocation,
                    Err(_) => {
                        unavailable_specs.push(spec);
                        continue;
                    }
                };
                for seed_index in 0..SEED_COUNT {
                    trials.push(SeedTrial::new(
                        spec,
                        seed_index,
                        allocation,
                        inputs.expected_standard_addresses,
                    )?);
                }
            }
        }
        Ok(Self {
            scanner: Some(MainnetCorpusScanner::new()),
            expected_measurement: measurement.clone(),
            inputs,
            trials,
            unavailable_specs,
            applied_blocks: 0,
            standard_address_events: 0,
            distinct_standard_addresses: 0,
            maximum_events_per_address: 0,
            logical_limit: None,
            failed_closed: false,
        })
    }

    /// Applies one canonical block exactly once and replays its resolved
    /// standard-address events in extraction order.
    pub fn push(&mut self, block: &IndexedBlock) -> Result<(), SourceBoundInsertionBudgetError> {
        if self.failed_closed || self.applied_blocks >= self.inputs.source.expected_blocks {
            self.fail_closed();
            return Err(SourceBoundInsertionBudgetError::SourceRejected);
        }
        let events = match self
            .scanner
            .as_mut()
            .ok_or(SourceBoundInsertionBudgetError::SourceRejected)?
            .push_collect_standard_addresses(block)
        {
            Ok(events) => events,
            Err(_) => {
                self.fail_closed();
                return Err(SourceBoundInsertionBudgetError::SourceRejected);
            }
        };
        for event in events {
            if let Err(error) = self.apply_standard_event(event) {
                self.fail_closed();
                return Err(error);
            }
        }
        self.applied_blocks = self
            .applied_blocks
            .checked_add(1)
            .ok_or(SourceBoundInsertionBudgetError::SourceRejected)?;
        Ok(())
    }

    /// Requires an exact source-measurement match and returns aggregate-only
    /// sampled deterministic evidence.
    pub fn finish(
        mut self,
    ) -> Result<SourceBoundInsertionBudgetReport, SourceBoundInsertionBudgetError> {
        if self.failed_closed || self.applied_blocks != self.inputs.source.expected_blocks {
            self.fail_closed();
            return Err(SourceBoundInsertionBudgetError::SourceRejected);
        }
        let recomputed = self
            .scanner
            .take()
            .ok_or(SourceBoundInsertionBudgetError::SourceRejected)?
            .finish()
            .map_err(|_| SourceBoundInsertionBudgetError::SourceRejected)?;
        if recomputed != self.expected_measurement {
            self.fail_closed();
            return Err(SourceBoundInsertionBudgetError::SourceRejected);
        }
        if self.distinct_standard_addresses != self.inputs.expected_standard_addresses
            || self.standard_address_events != self.inputs.expected_standard_address_events
            || self.maximum_events_per_address != self.inputs.expected_maximum_events_per_address
        {
            self.fail_closed();
            return Err(SourceBoundInsertionBudgetError::SourceRejected);
        }
        let curve = build_curve(
            self.trials,
            &self.unavailable_specs,
            self.inputs.shape,
            self.inputs.failure_budget_bps,
            self.logical_limit,
        )?;
        let (verdict, recommendation) = verdict_and_recommendation(&curve, self.logical_limit)?;
        let (directory_recommendation, event_path_recommendation) =
            table_recommendations(&curve, self.logical_limit)?;
        let report = SourceBoundInsertionBudgetReport {
            scenario: SCENARIO.to_owned(),
            profile: SourceBoundInsertionBudgetProfile::CurrentFourProbeV1,
            source: self.inputs.source.clone(),
            base_layout: self.inputs.shape,
            seed_derivation: SEED_DERIVATION.to_owned(),
            seed_count: SEED_COUNT,
            capacity_multipliers: CAPACITY_MULTIPLIERS.to_vec(),
            probe_counts: PROBE_COUNTS.to_vec(),
            failure_budget_bps: self.inputs.failure_budget_bps,
            applied_blocks: self.applied_blocks,
            standard_address_events: self.standard_address_events,
            distinct_standard_addresses: self.distinct_standard_addresses,
            maximum_events_per_address: self.maximum_events_per_address,
            logical_limit: self.logical_limit,
            curve,
            verdict,
            recommendation,
            directory_recommendation,
            event_path_recommendation,
            evidence_scope: EVIDENCE_SCOPE,
        };
        report.validate()?;
        Ok(report)
    }

    fn apply_standard_event(
        &mut self,
        event: CollectedStandardAddressEvent,
    ) -> Result<(), SourceBoundInsertionBudgetError> {
        let expected_ordinal = self
            .standard_address_events
            .checked_add(1)
            .ok_or(SourceBoundInsertionBudgetError::AnalysisFailed)?;
        self.standard_address_events = expected_ordinal;
        let event_count = event
            .ordinal
            .checked_add(1)
            .ok_or(SourceBoundInsertionBudgetError::AnalysisFailed)?;
        self.maximum_events_per_address = self.maximum_events_per_address.max(event_count);

        if event.first_for_address {
            if u64::from(event.address_index) != self.distinct_standard_addresses {
                return Err(SourceBoundInsertionBudgetError::AnalysisFailed);
            }
            if self.distinct_standard_addresses >= self.inputs.shape.directory_admission_limit {
                self.latch_logical_limit(LogicalLimitKind::DirectoryAdmission);
            }
            self.distinct_standard_addresses = self
                .distinct_standard_addresses
                .checked_add(1)
                .ok_or(SourceBoundInsertionBudgetError::AnalysisFailed)?;
        } else if u64::from(event.address_index) >= self.distinct_standard_addresses {
            return Err(SourceBoundInsertionBudgetError::AnalysisFailed);
        }
        if self.standard_address_events > self.inputs.shape.event_admission_limit {
            self.latch_logical_limit(LogicalLimitKind::EventAdmission);
        }
        if event.ordinal >= self.inputs.shape.max_events_per_address {
            self.latch_logical_limit(LogicalLimitKind::PerAddressEvent);
        }
        if self.logical_limit.is_some() {
            return Ok(());
        }
        for trial in &mut self.trials {
            trial.apply(event)?;
        }
        Ok(())
    }

    fn latch_logical_limit(&mut self, limit: LogicalLimitKind) {
        if self.logical_limit.is_none() {
            self.logical_limit = Some(limit);
            for trial in &mut self.trials {
                trial.latch_logical(TrialDisposition::from_logical_limit(limit));
            }
        }
    }

    fn fail_closed(&mut self) {
        self.failed_closed = true;
        self.scanner = None;
        self.trials.clear();
    }
}

struct SeedTrial {
    spec: CurveSpec,
    seed_index: u16,
    layout: RuntimeProbeLayout,
    directory: Option<OccupancyBits>,
    event: Option<OccupancyBits>,
    directory_slots: Vec<RuntimeBoundDirectorySlot>,
    directory_addresses: u64,
    directory_occupied: u64,
    event_occupied: u64,
    directory_disposition: Option<TrialDisposition>,
    event_path_disposition: Option<TrialDisposition>,
}

impl SeedTrial {
    fn new(
        spec: CurveSpec,
        seed_index: u16,
        allocation: FixedLayoutAllocation,
        expected_standard_addresses: u64,
    ) -> Result<Self, SourceBoundInsertionBudgetError> {
        let seed = derive_seed(seed_index);
        let identity = LayoutIdentity::new(
            LayoutNetwork::Mainnet,
            SCHEMA_VERSION,
            KEY_EPOCH,
            LAYOUT_GENERATION,
            seed,
        )
        .map_err(|_| SourceBoundInsertionBudgetError::ConstructionFailed)?;
        let probe_count = usize::from(spec.probe_count);
        let layout = RuntimeProbeLayout::new(identity, allocation, probe_count, probe_count)
            .map_err(|_| SourceBoundInsertionBudgetError::ConstructionFailed)?;
        let expected_standard_addresses = usize::try_from(expected_standard_addresses)
            .map_err(|_| SourceBoundInsertionBudgetError::ConstructionFailed)?;
        let mut directory_slots = Vec::new();
        directory_slots
            .try_reserve_exact(expected_standard_addresses)
            .map_err(|_| SourceBoundInsertionBudgetError::ConstructionFailed)?;
        Ok(Self {
            spec,
            seed_index,
            layout,
            directory: Some(OccupancyBits::new(u64::from(
                allocation.directory().capacity(),
            ))?),
            event: Some(OccupancyBits::new(u64::from(
                allocation.event().capacity(),
            ))?),
            directory_slots,
            directory_addresses: 0,
            directory_occupied: 0,
            event_occupied: 0,
            directory_disposition: None,
            event_path_disposition: None,
        })
    }

    fn apply(
        &mut self,
        event: CollectedStandardAddressEvent,
    ) -> Result<(), SourceBoundInsertionBudgetError> {
        if self.directory_disposition.is_some() && self.event_path_disposition.is_some() {
            return Ok(());
        }
        if event.first_for_address {
            if u64::from(event.address_index) != self.directory_addresses {
                return Err(SourceBoundInsertionBudgetError::AnalysisFailed);
            }
            if self.directory_disposition.is_some() {
                return Ok(());
            }
            let probes = self
                .layout
                .directory_probe_indices(event.address)
                .map_err(|_| SourceBoundInsertionBudgetError::AnalysisFailed)?;
            let Some(slot) = first_vacant(
                self.directory
                    .as_ref()
                    .ok_or(SourceBoundInsertionBudgetError::AnalysisFailed)?,
                probes.as_slice(),
            )?
            else {
                self.latch_directory(TrialDisposition::DirectoryProbeExhausted);
                return Ok(());
            };
            self.directory
                .as_mut()
                .ok_or(SourceBoundInsertionBudgetError::AnalysisFailed)?
                .insert(slot)?;
            if self.event_path_disposition.is_none() {
                self.directory_slots.push(
                    probes
                        .bind(slot)
                        .map_err(|_| SourceBoundInsertionBudgetError::AnalysisFailed)?,
                );
            }
            self.directory_addresses = self
                .directory_addresses
                .checked_add(1)
                .ok_or(SourceBoundInsertionBudgetError::AnalysisFailed)?;
            self.directory_occupied = self
                .directory_occupied
                .checked_add(1)
                .ok_or(SourceBoundInsertionBudgetError::AnalysisFailed)?;
        }
        if self.event_path_disposition.is_some() {
            return Ok(());
        }
        let address_index = usize::try_from(event.address_index)
            .map_err(|_| SourceBoundInsertionBudgetError::AnalysisFailed)?;
        let directory_slot = *self
            .directory_slots
            .get(address_index)
            .ok_or(SourceBoundInsertionBudgetError::AnalysisFailed)?;
        self.insert_event(directory_slot, event.ordinal)
    }

    fn insert_event(
        &mut self,
        directory_slot: RuntimeBoundDirectorySlot,
        ordinal: u64,
    ) -> Result<(), SourceBoundInsertionBudgetError> {
        let probes = self
            .layout
            .event_probe_indices(directory_slot, ordinal)
            .map_err(|_| SourceBoundInsertionBudgetError::AnalysisFailed)?;
        let Some(slot) = first_vacant(
            self.event
                .as_ref()
                .ok_or(SourceBoundInsertionBudgetError::AnalysisFailed)?,
            probes.as_slice(),
        )?
        else {
            self.latch_event_path(TrialDisposition::EventProbeExhausted);
            return Ok(());
        };
        self.event
            .as_mut()
            .ok_or(SourceBoundInsertionBudgetError::AnalysisFailed)?
            .insert(slot)?;
        self.event_occupied = self
            .event_occupied
            .checked_add(1)
            .ok_or(SourceBoundInsertionBudgetError::AnalysisFailed)?;
        Ok(())
    }

    fn latch_directory(&mut self, disposition: TrialDisposition) {
        if self.directory_disposition.is_none() {
            self.directory_disposition = Some(disposition);
            self.directory = None;
            if self.event_path_disposition.is_none() {
                self.event_path_disposition = Some(disposition);
                self.event = None;
            }
            self.release_directory_slots();
        }
    }

    fn latch_event_path(&mut self, disposition: TrialDisposition) {
        if self.event_path_disposition.is_none() {
            self.event_path_disposition = Some(disposition);
            self.event = None;
            self.release_directory_slots();
        }
    }

    fn latch_logical(&mut self, disposition: TrialDisposition) {
        if self.directory_disposition.is_none() {
            self.directory_disposition = Some(disposition);
            self.directory = None;
        }
        if self.event_path_disposition.is_none() {
            self.event_path_disposition = Some(disposition);
            self.event = None;
        }
        self.release_directory_slots();
    }

    fn release_directory_slots(&mut self) {
        self.directory_slots = Vec::new();
    }

    fn into_report(self) -> SeedTrialReport {
        SeedTrialReport {
            seed_index: self.seed_index,
            directory_disposition: self
                .directory_disposition
                .unwrap_or(TrialDisposition::Completed),
            event_path_disposition: self
                .event_path_disposition
                .unwrap_or(TrialDisposition::Completed),
            directory_occupied: self.directory_occupied,
            event_occupied: self.event_occupied,
        }
    }
}

struct OccupancyBits {
    capacity: usize,
    words: Vec<u64>,
}

impl OccupancyBits {
    fn new(capacity: u64) -> Result<Self, SourceBoundInsertionBudgetError> {
        let capacity = usize::try_from(capacity)
            .map_err(|_| SourceBoundInsertionBudgetError::ConstructionFailed)?;
        let word_count = capacity
            .checked_add(u64::BITS as usize - 1)
            .ok_or(SourceBoundInsertionBudgetError::ConstructionFailed)?
            / u64::BITS as usize;
        let mut words = Vec::new();
        words
            .try_reserve_exact(word_count)
            .map_err(|_| SourceBoundInsertionBudgetError::ConstructionFailed)?;
        words.resize(word_count, 0);
        Ok(Self { capacity, words })
    }

    fn contains(&self, index: usize) -> Result<bool, SourceBoundInsertionBudgetError> {
        if index >= self.capacity {
            return Err(SourceBoundInsertionBudgetError::AnalysisFailed);
        }
        let word_index = index / u64::BITS as usize;
        let bit_index = index % u64::BITS as usize;
        let word = self
            .words
            .get(word_index)
            .ok_or(SourceBoundInsertionBudgetError::AnalysisFailed)?;
        Ok(word & (1_u64 << bit_index) != 0)
    }

    fn insert(&mut self, index: usize) -> Result<(), SourceBoundInsertionBudgetError> {
        if index >= self.capacity {
            return Err(SourceBoundInsertionBudgetError::AnalysisFailed);
        }
        let word_index = index / u64::BITS as usize;
        let bit_index = index % u64::BITS as usize;
        let word = self
            .words
            .get_mut(word_index)
            .ok_or(SourceBoundInsertionBudgetError::AnalysisFailed)?;
        *word |= 1_u64 << bit_index;
        Ok(())
    }
}

fn first_vacant(
    occupancy: &OccupancyBits,
    probes: &[usize],
) -> Result<Option<usize>, SourceBoundInsertionBudgetError> {
    for probe in probes {
        if !occupancy.contains(*probe)? {
            return Ok(Some(*probe));
        }
    }
    Ok(None)
}

fn derive_seed(seed_index: u16) -> [u8; 32] {
    let mut hasher = Blake2s256::new();
    Digest::update(&mut hasher, SEED_DOMAIN);
    Digest::update(&mut hasher, SCENARIO.as_bytes());
    Digest::update(
        &mut hasher,
        SourceBoundInsertionBudgetProfile::CurrentFourProbeV1
            .as_str()
            .as_bytes(),
    );
    Digest::update(&mut hasher, seed_index.to_le_bytes());
    let digest = Digest::finalize(hasher);
    let mut seed = [0; 32];
    seed.copy_from_slice(&digest);
    seed
}

fn curve_spec_available(shape: BaseLayoutShape, spec: CurveSpec) -> bool {
    let Some((directory_capacity, event_capacity)) = shape.scaled(spec.capacity_multiplier) else {
        return false;
    };
    shape.allocation_for(spec.capacity_multiplier).is_ok()
        && u64::from(spec.probe_count) <= directory_capacity
        && u64::from(spec.probe_count) <= event_capacity
}

fn build_curve(
    trials: Vec<SeedTrial>,
    unavailable_specs: &[CurveSpec],
    shape: BaseLayoutShape,
    failure_budget_bps: u64,
    logical_limit: Option<LogicalLimitKind>,
) -> Result<Vec<CurvePoint>, SourceBoundInsertionBudgetError> {
    let mut reports = trials
        .into_iter()
        .map(|trial| (trial.spec, trial.into_report()))
        .collect::<Vec<_>>();
    let mut curve = Vec::with_capacity(CAPACITY_MULTIPLIERS.len() * PROBE_COUNTS.len());
    for capacity_multiplier in CAPACITY_MULTIPLIERS {
        for probe_count in PROBE_COUNTS {
            let spec = CurveSpec {
                capacity_multiplier,
                probe_count,
            };
            if unavailable_specs.contains(&spec) {
                curve.push(CurvePoint::unavailable(spec, shape));
                continue;
            }
            let mut point_trials = Vec::with_capacity(usize::from(SEED_COUNT));
            let mut remaining = Vec::new();
            for (trial_spec, report) in reports {
                if trial_spec == spec {
                    point_trials.push(report);
                } else {
                    remaining.push((trial_spec, report));
                }
            }
            reports = remaining;
            point_trials.sort_by_key(|trial| trial.seed_index);
            curve.push(CurvePoint::from_trials(
                spec,
                shape,
                point_trials,
                failure_budget_bps,
                logical_limit,
            )?);
        }
    }
    if !reports.is_empty() {
        return Err(SourceBoundInsertionBudgetError::InvalidReport);
    }
    Ok(curve)
}

fn verdict_and_recommendation(
    curve: &[CurvePoint],
    logical_limit: Option<LogicalLimitKind>,
) -> Result<(InsertionVerdict, Recommendation), SourceBoundInsertionBudgetError> {
    if logical_limit.is_some() {
        return Ok((InsertionVerdict::NoGo, Recommendation::logical_limit()));
    }
    let current = curve
        .iter()
        .find(|point| point.spec().is_current())
        .ok_or(SourceBoundInsertionBudgetError::InvalidReport)?;
    if current.meets_sampled_failure_budget {
        return Ok((InsertionVerdict::Go, Recommendation::current(current)));
    }
    Ok((
        InsertionVerdict::NoGo,
        Recommendation::current_miss(current),
    ))
}

fn table_recommendations(
    curve: &[CurvePoint],
    logical_limit: Option<LogicalLimitKind>,
) -> Result<(TableRecommendation, TableRecommendation), SourceBoundInsertionBudgetError> {
    if logical_limit.is_some() {
        return Ok((
            TableRecommendation::logical_limit(),
            TableRecommendation::logical_limit(),
        ));
    }
    let current = curve
        .iter()
        .find(|point| point.spec().is_current())
        .ok_or(SourceBoundInsertionBudgetError::InvalidReport)?;
    let directory = if current.directory_meets_sampled_failure_budget {
        TableRecommendation::current(current.directory_capacity, current.probe_count)
    } else {
        TableRecommendation::current_miss(current.directory_capacity, current.probe_count)
    };
    let event_path = if current.event_path_meets_sampled_failure_budget {
        TableRecommendation::current(current.event_capacity, current.probe_count)
    } else {
        TableRecommendation::current_miss(current.event_capacity, current.probe_count)
    };
    Ok((directory, event_path))
}

fn count_trials(
    trials: &[SeedTrialReport],
    predicate: impl Fn(&SeedTrialReport) -> bool,
) -> Result<u16, SourceBoundInsertionBudgetError> {
    let count = trials.iter().filter(|trial| predicate(trial)).count();
    u16::try_from(count).map_err(|_| SourceBoundInsertionBudgetError::InvalidReport)
}

fn sampled_rate_bps(failures: u16) -> Result<u64, SourceBoundInsertionBudgetError> {
    u64::from(failures)
        .checked_mul(BASIS_POINTS)
        .and_then(|numerator| numerator.checked_add(u64::from(SEED_COUNT) - 1))
        .map(|numerator| numerator / u64::from(SEED_COUNT))
        .ok_or(SourceBoundInsertionBudgetError::InvalidReport)
}

fn logical_limit_matches_observed_totals(
    shape: BaseLayoutShape,
    distinct_standard_addresses: u64,
    standard_address_events: u64,
    maximum_events_per_address: u64,
    logical_limit: Option<LogicalLimitKind>,
) -> bool {
    let directory_exceeded = distinct_standard_addresses > shape.directory_admission_limit;
    let event_exceeded = standard_address_events > shape.event_admission_limit;
    let per_address_exceeded = maximum_events_per_address > shape.max_events_per_address;
    match logical_limit {
        None => !directory_exceeded && !event_exceeded && !per_address_exceeded,
        Some(LogicalLimitKind::DirectoryAdmission) => directory_exceeded,
        Some(LogicalLimitKind::EventAdmission) => event_exceeded,
        Some(LogicalLimitKind::PerAddressEvent) => per_address_exceeded,
    }
}

fn valid_seed_reports(
    trials: &[SeedTrialReport],
    logical_limit: Option<LogicalLimitKind>,
    shape: BaseLayoutShape,
    distinct_standard_addresses: u64,
    standard_address_events: u64,
    directory_capacity: Option<u64>,
    event_capacity: Option<u64>,
) -> bool {
    trials.len() == usize::from(SEED_COUNT)
        && trials.iter().enumerate().all(|(index, trial)| {
            let disposition_shape_is_valid =
                !matches!(
                    trial.directory_disposition,
                    TrialDisposition::EventProbeExhausted
                ) && (!matches!(trial.event_path_disposition, TrialDisposition::Completed)
                    || matches!(trial.directory_disposition, TrialDisposition::Completed))
                    && (!matches!(
                        trial.event_path_disposition,
                        TrialDisposition::DirectoryProbeExhausted
                    ) || matches!(
                        trial.directory_disposition,
                        TrialDisposition::DirectoryProbeExhausted
                    ));
            let logical_shape_is_valid = match logical_limit {
                Some(limit) => {
                    trial.directory_disposition.logical_limit() == Some(limit)
                        && trial.event_path_disposition.logical_limit() == Some(limit)
                }
                None => {
                    trial.directory_disposition.logical_limit().is_none()
                        && trial.event_path_disposition.logical_limit().is_none()
                }
            };
            let occupancy_shape_is_valid =
                directory_capacity.is_some_and(|capacity| {
                    trial.directory_occupied
                        <= capacity
                            .min(shape.directory_admission_limit)
                            .min(distinct_standard_addresses)
                }) && event_capacity.is_some_and(|capacity| {
                    trial.event_occupied
                        <= capacity
                            .min(shape.event_admission_limit)
                            .min(standard_address_events)
                }) && (!matches!(trial.directory_disposition, TrialDisposition::Completed)
                    || trial.directory_occupied == distinct_standard_addresses)
                    && (!matches!(trial.event_path_disposition, TrialDisposition::Completed)
                        || trial.event_occupied == standard_address_events)
                    && (!matches!(
                        trial.directory_disposition,
                        TrialDisposition::DirectoryProbeExhausted
                    ) || trial.directory_occupied < distinct_standard_addresses)
                    && (!matches!(
                        trial.event_path_disposition,
                        TrialDisposition::EventProbeExhausted
                    ) || trial.event_occupied < standard_address_events);
            usize::from(trial.seed_index) == index
                && disposition_shape_is_valid
                && logical_shape_is_valid
                && occupancy_shape_is_valid
        })
}

fn optional_u8(value: Option<u8>) -> String {
    value.map_or_else(|| "none".to_owned(), |value| value.to_string())
}

fn optional_u16(value: Option<u16>) -> String {
    value.map_or_else(|| "none".to_owned(), |value| value.to_string())
}

fn optional_u64(value: Option<u64>) -> String {
    value.map_or_else(|| "none".to_owned(), |value| value.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    use zaino_state::{ScriptType, TxInCompact};

    use crate::{
        canonical_chain::CanonicalNetwork,
        layout::{StandardAddress, StandardScriptKind},
        zaino_corpus::MainnetSizingModel,
        zaino_fixtures::{indexed_block, output, transaction},
    };

    fn fixture_genesis(address_count: u8) -> Result<IndexedBlock, Box<dyn std::error::Error>> {
        let outputs = (0..address_count)
            .map(|byte| output(u64::from(byte) + 1, [byte + 1; 20], ScriptType::P2PKH))
            .collect::<Result<Vec<_>, _>>()?;
        let tx = transaction(0, [0x11; 32], vec![TxInCompact::null_prevout()], outputs);
        indexed_block(
            0,
            CanonicalNetwork::Mainnet.genesis_hash().0,
            [0; 32],
            vec![tx],
        )
    }

    fn artifacts(
        block: &IndexedBlock,
        directory_admission_limit: u64,
    ) -> Result<(MainnetCorpusMeasurement, MainnetSizingQualification), Box<dyn std::error::Error>>
    {
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

    fn run(
        block: &IndexedBlock,
        measurement: &MainnetCorpusMeasurement,
        sizing: &MainnetSizingQualification,
        failure_budget_bps: u64,
    ) -> Result<SourceBoundInsertionBudgetReport, SourceBoundInsertionBudgetError> {
        run_with_lineage(
            block,
            measurement,
            sizing,
            &"11".repeat(32),
            &"22".repeat(32),
            failure_budget_bps,
        )
    }

    fn run_with_lineage(
        block: &IndexedBlock,
        measurement: &MainnetCorpusMeasurement,
        sizing: &MainnetSizingQualification,
        measurement_blake2s256: &str,
        qualification_blake2s256: &str,
        failure_budget_bps: u64,
    ) -> Result<SourceBoundInsertionBudgetReport, SourceBoundInsertionBudgetError> {
        let mut session = SourceBoundInsertionBudgetSession::start(
            SourceBoundInsertionBudgetProfile::CurrentFourProbeV1,
            measurement,
            sizing,
            measurement_blake2s256,
            qualification_blake2s256,
            failure_budget_bps,
        )?;
        session.push(block)?;
        session.finish()
    }

    #[test]
    fn exact_replay_is_deterministic_validated_and_serde_stable(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let block = fixture_genesis(3)?;
        let (measurement, sizing) = artifacts(&block, 6)?;

        let first = run(&block, &measurement, &sizing, 10_000)?;
        let second = run(&block, &measurement, &sizing, 10_000)?;

        assert_eq!(first, second);
        assert!(first.is_go());
        assert_eq!(first.capacity_multipliers, vec![1]);
        assert_eq!(first.probe_counts, vec![4]);
        assert_eq!(first.curve.len(), 1);
        first.validate_against(
            &measurement,
            &sizing,
            &"11".repeat(32),
            &"22".repeat(32),
            10_000,
        )?;
        let encoded = serde_json::to_vec(&first)?;
        let decoded: SourceBoundInsertionBudgetReport = serde_json::from_slice(&encoded)?;
        assert_eq!(decoded, first);
        decoded.validate()?;
        assert!(decoded
            .to_string()
            .contains("probability-distribution,probabilistic-failure-bound"));
        Ok(())
    }

    #[test]
    fn sampled_seed_schedule_cannot_be_changed_by_caller_lineage_strings(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let block = fixture_genesis(3)?;
        let (measurement, sizing) = artifacts(&block, 6)?;
        let first = run_with_lineage(
            &block,
            &measurement,
            &sizing,
            &"11".repeat(32),
            &"22".repeat(32),
            10_000,
        )?;
        let second = run_with_lineage(
            &block,
            &measurement,
            &sizing,
            &"33".repeat(32),
            &"44".repeat(32),
            10_000,
        )?;

        assert_ne!(first.source, second.source);
        assert_eq!(first.seed_derivation, SEED_DERIVATION);
        assert_eq!(first.curve, second.curve);
        Ok(())
    }

    #[test]
    fn event_failure_releases_event_state_but_directory_lane_finishes(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let allocation = FixedLayoutAllocation::new(1_024, 1_023, 8, 7, 1)?;
        let mut trial = SeedTrial::new(
            CurveSpec {
                capacity_multiplier: 1,
                probe_count: 8,
            },
            0,
            allocation,
            12,
        )?;

        for address_index in 0..12_u32 {
            trial.apply(CollectedStandardAddressEvent {
                address: StandardAddress::new(
                    StandardScriptKind::PayToPublicKeyHash,
                    [u8::try_from(address_index + 1)?; 20],
                ),
                address_index,
                ordinal: 0,
                first_for_address: true,
            })?;
        }

        assert_eq!(trial.directory_addresses, 12);
        assert_eq!(trial.directory_disposition, None);
        assert_eq!(
            trial.event_path_disposition,
            Some(TrialDisposition::EventProbeExhausted)
        );
        assert!(trial.event.is_none());
        assert!(trial.directory_slots.is_empty());
        Ok(())
    }

    #[test]
    fn logical_limit_is_distinct_from_probe_exhaustion_and_forces_no_go(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let block = fixture_genesis(3)?;
        let (measurement, sizing) = artifacts(&block, 2)?;

        let report = run(&block, &measurement, &sizing, 10_000)?;

        assert!(!report.is_go());
        assert_eq!(
            report.logical_limit,
            Some(LogicalLimitKind::DirectoryAdmission)
        );
        assert_eq!(
            report.recommendation.kind,
            RecommendationKind::LogicalLimitExceeded
        );
        report.validate()?;
        Ok(())
    }

    #[test]
    fn source_mismatch_and_budget_outside_basis_points_fail_closed(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let expected_block = fixture_genesis(2)?;
        let supplied_block = fixture_genesis(3)?;
        let (measurement, sizing) = artifacts(&expected_block, 6)?;
        assert!(matches!(
            SourceBoundInsertionBudgetSession::start(
                SourceBoundInsertionBudgetProfile::CurrentFourProbeV1,
                &measurement,
                &sizing,
                &"11".repeat(32),
                &"22".repeat(32),
                BASIS_POINTS + 1,
            ),
            Err(SourceBoundInsertionBudgetError::InputRejected)
        ));

        let mut session = SourceBoundInsertionBudgetSession::start(
            SourceBoundInsertionBudgetProfile::CurrentFourProbeV1,
            &measurement,
            &sizing,
            &"11".repeat(32),
            &"22".repeat(32),
            0,
        )?;
        session.push(&supplied_block)?;
        assert!(matches!(
            session.finish(),
            Err(SourceBoundInsertionBudgetError::SourceRejected)
        ));
        Ok(())
    }

    #[test]
    fn report_validation_rejects_claim_and_curve_tampering(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let block = fixture_genesis(3)?;
        let (measurement, sizing) = artifacts(&block, 6)?;
        let report = run(&block, &measurement, &sizing, 10_000)?;

        let mut claims = report.clone();
        claims
            .evidence_scope
            .probabilistic_failure_bound_established = true;
        assert!(matches!(
            claims.validate(),
            Err(SourceBoundInsertionBudgetError::InvalidReport)
        ));

        let mut maximum = report.clone();
        maximum.maximum_events_per_address += 1;
        maximum.validate()?;
        assert!(matches!(
            maximum.validate_against(
                &measurement,
                &sizing,
                &"11".repeat(32),
                &"22".repeat(32),
                10_000,
            ),
            Err(SourceBoundInsertionBudgetError::InvalidReport)
        ));

        let mut impossible_limit = report.clone();
        impossible_limit.logical_limit = Some(LogicalLimitKind::DirectoryAdmission);
        assert!(matches!(
            impossible_limit.validate(),
            Err(SourceBoundInsertionBudgetError::InvalidReport)
        ));

        let mut curve = report;
        curve.curve[0].sampled_failure_bps = Some(0);
        curve.curve[0].failed_seed_schedules = Some(SEED_COUNT);
        assert!(matches!(
            curve.validate(),
            Err(SourceBoundInsertionBudgetError::InvalidReport)
        ));
        Ok(())
    }

    #[test]
    fn logical_limit_reports_reject_completed_lanes_and_admission_overrun(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let block = fixture_genesis(3)?;
        let (measurement, sizing) = artifacts(&block, 2)?;
        let report = run(&block, &measurement, &sizing, 10_000)?;

        let mut completed = report.clone();
        completed.curve[0].trials[0].directory_disposition = TrialDisposition::Completed;
        assert!(matches!(
            completed.validate(),
            Err(SourceBoundInsertionBudgetError::InvalidReport)
        ));

        let mut over_admission = report;
        over_admission.curve[0].trials[0].directory_occupied = 3;
        assert!(matches!(
            over_admission.validate(),
            Err(SourceBoundInsertionBudgetError::InvalidReport)
        ));
        Ok(())
    }
}
