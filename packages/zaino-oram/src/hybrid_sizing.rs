//! Source-bound sizing evidence for a live-UTXO base plus bounded deltas.
//!
//! This analyzer replays the exact kind-preserving standard-address delta
//! stream. It sizes one final live-UTXO base and genesis-aligned add/spend
//! generations without retaining addresses, outpoints, or individual
//! generations in the report. The result is logical sizing evidence only; it
//! is not an ORAM layout, insertion-failure, backend, or target-hardware
//! qualification.

use std::fmt;

use serde::{Deserialize, Serialize};
use zaino_state::IndexedBlock;

#[cfg(feature = "rostl-experimental")]
use crate::fixed_page_capacity::SelectedFixedPageDemands;
use crate::{
    target_load::is_blake2s256_hex,
    zaino_corpus::{MainnetCorpusMeasurement, MainnetCorpusScanner},
};

const SCENARIO: &str = "source-bound-hybrid-sizing-v1";
const PAGE_CANDIDATES: [u64; 3] = [1, 8, 16];
const REBUILD_INTERVALS: [u32; 3] = [288, 1_152, 8_064];
const EMPTY_POSITION: u32 = u32::MAX;
pub(super) const SELECTED_PAGE_ENTRIES: u64 = 16;
pub(super) const SELECTED_GENERATION_INTERVAL_BLOCKS: u32 = 288;
const MAINNET_BLOSSOM_ACTIVATION_HEIGHT: u64 = 653_600;
const TARGET_BLOCK_SECONDS: u64 = 75;
const GROWTH_WINDOW_DAYS: u64 = 365;
const GROWTH_WINDOW_BLOCKS: u64 = GROWTH_WINDOW_DAYS * 24 * 60 * 60 / TARGET_BLOCK_SECONDS;
const GROWTH_OBSERVATION_WINDOWS: usize = 5;
const GROWTH_PROJECTION_WINDOWS: u16 = 3;
const GROWTH_V2_MEASUREMENT_BLAKE2S256: &str =
    "aba46f64da0113d9b0e93209ab4a8a98626d6d5bc7973444c8bf766a1922b127";
const GROWTH_V2_CHECKPOINT_HEIGHT: u32 = 3_425_046;
const GROWTH_V2_CHECKPOINT_HASH: &str =
    "0000000000a1014e9564513f1d5e5ddaba027c032857a236ca3178e9a8983ad4";
const GROWTH_V2_EXPECTED_BLOCKS: u64 = 3_425_047;

/// Fixed source-bound hybrid-sizing profile selected by the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SourceBoundHybridSizingProfile {
    /// Final live-UTXO base plus genesis-aligned separate add/spend deltas.
    LiveUtxoBaseDeltaV1,
    /// V1 sizing plus fixed-window source-bound growth evidence.
    LiveUtxoBaseDeltaGrowthV2,
}

impl SourceBoundHybridSizingProfile {
    /// Returns the stable artifact label for this profile.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LiveUtxoBaseDeltaV1 => "live-utxo-base-delta-v1",
            Self::LiveUtxoBaseDeltaGrowthV2 => "live-utxo-base-delta-growth-v2",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceBinding {
    measurement_blake2s256: String,
    checkpoint_height: u32,
    checkpoint_hash: String,
    expected_blocks: u64,
}

impl SourceBinding {
    fn from_measurement(
        measurement: &MainnetCorpusMeasurement,
        measurement_blake2s256: &str,
    ) -> Result<Self, SourceBoundHybridSizingError> {
        measurement
            .validate()
            .map_err(|_| SourceBoundHybridSizingError::InputRejected)?;
        let source = Self {
            measurement_blake2s256: measurement_blake2s256.to_owned(),
            checkpoint_height: measurement.checkpoint().height(),
            checkpoint_hash: measurement.checkpoint().hash().to_owned(),
            expected_blocks: u64::from(measurement.checkpoint().height()) + 1,
        };
        if source.validate() {
            Ok(source)
        } else {
            Err(SourceBoundHybridSizingError::InputRejected)
        }
    }

    fn validate(&self) -> bool {
        is_blake2s256_hex(&self.measurement_blake2s256)
            && is_blake2s256_hex(&self.checkpoint_hash)
            && self.expected_blocks == u64::from(self.checkpoint_height) + 1
    }

    fn is_growth_v2_source(&self) -> bool {
        self.measurement_blake2s256 == GROWTH_V2_MEASUREMENT_BLAKE2S256
            && self.checkpoint_height == GROWTH_V2_CHECKPOINT_HEIGHT
            && self.checkpoint_hash == GROWTH_V2_CHECKPOINT_HASH
            && self.expected_blocks == GROWTH_V2_EXPECTED_BLOCKS
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LiveUtxoBucket {
    live_utxos: u64,
    address_count: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BasePageCandidateReport {
    entries_per_page: u64,
    base_pages: u64,
    maximum_pages_per_address: u64,
    allocated_entries: u64,
    live_entries: u64,
    padding_entries: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeltaPageCandidateReport {
    entries_per_page: u64,
    max_total_add_pages: u64,
    max_total_spend_pages: u64,
    max_total_separate_pages: u64,
    max_per_address_add_pages: u64,
    max_per_address_spend_pages: u64,
    max_per_address_separate_pages: u64,
}

impl DeltaPageCandidateReport {
    const fn empty(entries_per_page: u64) -> Self {
        Self {
            entries_per_page,
            max_total_add_pages: 0,
            max_total_spend_pages: 0,
            max_total_separate_pages: 0,
            max_per_address_add_pages: 0,
            max_per_address_spend_pages: 0,
            max_per_address_separate_pages: 0,
        }
    }

    fn update(&mut self, generation: GenerationPageSummary) {
        self.max_total_add_pages = self.max_total_add_pages.max(generation.total_add_pages);
        self.max_total_spend_pages = self.max_total_spend_pages.max(generation.total_spend_pages);
        self.max_total_separate_pages = self
            .max_total_separate_pages
            .max(generation.total_separate_pages);
        self.max_per_address_add_pages = self
            .max_per_address_add_pages
            .max(generation.max_per_address_add_pages);
        self.max_per_address_spend_pages = self
            .max_per_address_spend_pages
            .max(generation.max_per_address_spend_pages);
        self.max_per_address_separate_pages = self
            .max_per_address_separate_pages
            .max(generation.max_per_address_separate_pages);
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RebuildIntervalReport {
    interval_blocks: u32,
    generation_count: u64,
    trailing_partial_generation_blocks: u32,
    max_total_add_events: u64,
    max_total_spend_events: u64,
    max_total_delta_events: u64,
    max_per_address_add_events: u64,
    max_per_address_spend_events: u64,
    max_per_address_delta_events: u64,
    page_candidates: Vec<DeltaPageCandidateReport>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EvidenceScope {
    mainnet_genesis_and_chain_continuity_validated: bool,
    source_measurement_recomputed_and_matched: bool,
    exact_kind_preserving_standard_delta_order_replayed: bool,
    final_live_histogram_includes_zero: bool,
    base_pages_use_exact_per_address_ceils: bool,
    delta_pages_use_exact_per_address_ceils: bool,
    genesis_aligned_intervals_analyzed: bool,
    individual_generations_persisted: bool,
    projected_growth_analyzed: bool,
    oram_layout_selected: bool,
    insertion_failure_bound_established: bool,
    physical_oram_accesses_measured: bool,
    backend_calibrated: bool,
    target_hardware_qualified: bool,
    tdx_qualified: bool,
    mainnet_ready: bool,
}

const EVIDENCE_SCOPE_V1: EvidenceScope = EvidenceScope {
    mainnet_genesis_and_chain_continuity_validated: true,
    source_measurement_recomputed_and_matched: true,
    exact_kind_preserving_standard_delta_order_replayed: true,
    final_live_histogram_includes_zero: true,
    base_pages_use_exact_per_address_ceils: true,
    delta_pages_use_exact_per_address_ceils: true,
    genesis_aligned_intervals_analyzed: true,
    individual_generations_persisted: false,
    projected_growth_analyzed: false,
    oram_layout_selected: false,
    insertion_failure_bound_established: false,
    physical_oram_accesses_measured: false,
    backend_calibrated: false,
    target_hardware_qualified: false,
    tdx_qualified: false,
    mainnet_ready: false,
};

const EVIDENCE_SCOPE_V2: EvidenceScope = EvidenceScope {
    projected_growth_analyzed: true,
    ..EVIDENCE_SCOPE_V1
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GrowthStateSnapshot {
    applied_blocks: u64,
    distinct_standard_addresses: u64,
    live_standard_utxos: u64,
    base_pages: u64,
    maximum_live_utxos_per_address: u64,
    maximum_base_pages_per_address: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GrowthDeltaWindow {
    start_applied_blocks: u64,
    end_applied_blocks: u64,
    generation_count: u64,
    max_total_add_events: u64,
    max_total_spend_events: u64,
    max_total_delta_events: u64,
    max_per_address_add_events: u64,
    max_per_address_spend_events: u64,
    max_per_address_delta_events: u64,
    max_total_add_pages: u64,
    max_total_spend_pages: u64,
    max_total_separate_pages: u64,
    max_per_address_add_pages: u64,
    max_per_address_spend_pages: u64,
    max_per_address_separate_pages: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GrowthAnnualIncrement {
    distinct_standard_addresses: u64,
    live_standard_utxos: u64,
    base_pages: u64,
    maximum_live_utxos_per_address: u64,
    max_total_add_pages: u64,
    max_total_spend_pages: u64,
    max_per_address_add_pages: u64,
    max_per_address_spend_pages: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GrowthProjection {
    horizon_windows: u16,
    horizon_blocks: u64,
    qualification_expiry_height: u32,
    capacity_horizon_end_height: u32,
    distinct_standard_addresses: u64,
    live_standard_utxos: u64,
    base_pages: u64,
    maximum_live_utxos_per_address: u64,
    maximum_base_pages_per_address: u64,
    max_total_add_pages: u64,
    max_total_spend_pages: u64,
    max_per_address_add_pages: u64,
    max_per_address_spend_pages: u64,
    fixed_page_reads: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HistoricalGrowthEvidence {
    target_block_seconds: u64,
    window_days: u64,
    window_blocks: u64,
    observation_windows: u16,
    aligned_start_applied_blocks: u64,
    aligned_end_applied_blocks: u64,
    checkpoint_trailing_blocks: u32,
    state_snapshots: Vec<GrowthStateSnapshot>,
    delta_windows: Vec<GrowthDeltaWindow>,
    trailing_partial_generation: Option<GrowthDeltaWindow>,
    maximum_positive_annual_increment: GrowthAnnualIncrement,
    projection: GrowthProjection,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SelectedSizingDemands {
    base_pages: u64,
    add_pages: u64,
    spend_pages: u64,
    maximum_live_utxos_per_address: u64,
    maximum_base_pages_per_address: u64,
    max_per_address_add_pages: u64,
    max_per_address_spend_pages: u64,
}

impl SelectedSizingDemands {
    fn fixed_page_reads(self) -> Result<u64, SourceBoundHybridSizingError> {
        self.maximum_base_pages_per_address
            .checked_add(self.max_per_address_add_pages)
            .and_then(|reads| reads.checked_add(self.max_per_address_spend_pages))
            .ok_or(SourceBoundHybridSizingError::ArithmeticOverflow)
    }
}

/// Aggregate-only exact-source hybrid logical-sizing evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceBoundHybridSizingReport {
    scenario: String,
    profile: SourceBoundHybridSizingProfile,
    source: SourceBinding,
    page_candidates: Vec<u64>,
    rebuild_intervals: Vec<u32>,
    applied_blocks: u64,
    distinct_standard_addresses: u64,
    created_standard_events: u64,
    spent_standard_events: u64,
    delta_events: u64,
    final_live_standard_utxos: u64,
    maximum_live_standard_utxos: u64,
    live_utxo_histogram: Vec<LiveUtxoBucket>,
    base_page_candidates: Vec<BasePageCandidateReport>,
    rebuild_interval_reports: Vec<RebuildIntervalReport>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    historical_growth: Option<HistoricalGrowthEvidence>,
    evidence_scope: EvidenceScope,
}

impl SourceBoundHybridSizingReport {
    /// Returns the source measurement digest retained by this report.
    pub fn measurement_blake2s256(&self) -> &str {
        &self.source.measurement_blake2s256
    }

    /// Returns the public checkpoint height and hash retained by this report.
    pub fn source_checkpoint(&self) -> (u32, &str) {
        (self.source.checkpoint_height, &self.source.checkpoint_hash)
    }

    /// Revalidates the complete self-contained hybrid-sizing report.
    pub fn validate(&self) -> Result<(), SourceBoundHybridSizingError> {
        let expected_delta_events = self
            .created_standard_events
            .checked_add(self.spent_standard_events)
            .ok_or(SourceBoundHybridSizingError::InvalidReport)?;
        let expected_final_live = self
            .created_standard_events
            .checked_sub(self.spent_standard_events)
            .ok_or(SourceBoundHybridSizingError::InvalidReport)?;
        let expected_evidence_scope = match self.profile {
            SourceBoundHybridSizingProfile::LiveUtxoBaseDeltaV1 => EVIDENCE_SCOPE_V1,
            SourceBoundHybridSizingProfile::LiveUtxoBaseDeltaGrowthV2 => EVIDENCE_SCOPE_V2,
        };
        if self.scenario != SCENARIO
            || !self.source.validate()
            || self.profile == SourceBoundHybridSizingProfile::LiveUtxoBaseDeltaGrowthV2
                && !self.source.is_growth_v2_source()
            || self.page_candidates != PAGE_CANDIDATES
            || self.rebuild_intervals != REBUILD_INTERVALS
            || self.applied_blocks != self.source.expected_blocks
            || self.distinct_standard_addresses == 0
            || self.delta_events != expected_delta_events
            || self.final_live_standard_utxos != expected_final_live
            || self.maximum_live_standard_utxos < self.final_live_standard_utxos
            || self.maximum_live_standard_utxos > self.created_standard_events
            || self.base_page_candidates.len() != PAGE_CANDIDATES.len()
            || self.rebuild_interval_reports.len() != REBUILD_INTERVALS.len()
            || self.evidence_scope != expected_evidence_scope
        {
            return Err(SourceBoundHybridSizingError::InvalidReport);
        }

        validate_live_histogram(
            &self.live_utxo_histogram,
            self.distinct_standard_addresses,
            self.final_live_standard_utxos,
        )?;
        let expected_base =
            build_base_page_candidates(&self.live_utxo_histogram, self.final_live_standard_utxos)?;
        if self.base_page_candidates != expected_base {
            return Err(SourceBoundHybridSizingError::InvalidReport);
        }
        for (index, report) in self.rebuild_interval_reports.iter().enumerate() {
            if report.interval_blocks != REBUILD_INTERVALS[index]
                || !report.validate(
                    self.applied_blocks,
                    self.created_standard_events,
                    self.spent_standard_events,
                    self.delta_events,
                )?
            {
                return Err(SourceBoundHybridSizingError::InvalidReport);
            }
        }
        let selected = self.selected_sizing_demands_unvalidated()?;
        let selected_interval = select_rebuild_interval(&self.rebuild_interval_reports)?;
        match (&self.profile, &self.historical_growth) {
            (SourceBoundHybridSizingProfile::LiveUtxoBaseDeltaV1, None) => {}
            (
                SourceBoundHybridSizingProfile::LiveUtxoBaseDeltaGrowthV2,
                Some(historical_growth),
            ) => historical_growth.validate(
                self.source.expected_blocks,
                self.distinct_standard_addresses,
                self.final_live_standard_utxos,
                selected,
                selected_interval,
            )?,
            _ => return Err(SourceBoundHybridSizingError::InvalidReport),
        }
        Ok(())
    }

    /// Revalidates this report against its exact capture and digest binding.
    pub fn validate_against(
        &self,
        measurement: &MainnetCorpusMeasurement,
        measurement_blake2s256: &str,
    ) -> Result<(), SourceBoundHybridSizingError> {
        self.validate()?;
        let expected_source = SourceBinding::from_measurement(measurement, measurement_blake2s256)?;
        let expected_events = measurement
            .standard_address_events()
            .ok_or(SourceBoundHybridSizingError::InputRejected)?;
        if self.source != expected_source
            || self.distinct_standard_addresses != measurement.distinct_standard_addresses()
            || self.delta_events != expected_events
            || self.final_live_standard_utxos != measurement.live_standard_utxos()
            || !live_histogram_matches_measurement(&self.live_utxo_histogram, measurement)
        {
            return Err(SourceBoundHybridSizingError::InvalidReport);
        }
        Ok(())
    }

    #[cfg(feature = "rostl-experimental")]
    pub(super) fn selected_fixed_page_demands(
        &self,
    ) -> Result<SelectedFixedPageDemands, SourceBoundHybridSizingError> {
        self.validate()?;
        let current = self.selected_sizing_demands_unvalidated()?;
        let selected =
            select_capacity_demands(self.profile, current, self.historical_growth.as_ref())?;
        Ok(SelectedFixedPageDemands {
            base_pages: selected.base_pages,
            add_pages: selected.add_pages,
            spend_pages: selected.spend_pages,
            fixed_page_reads: selected.fixed_page_reads()?,
        })
    }

    fn selected_sizing_demands_unvalidated(
        &self,
    ) -> Result<SelectedSizingDemands, SourceBoundHybridSizingError> {
        select_sizing_demands(
            &self.live_utxo_histogram,
            &self.base_page_candidates,
            &self.rebuild_interval_reports,
        )
    }
}

fn select_sizing_demands(
    live_utxo_histogram: &[LiveUtxoBucket],
    base_page_candidates: &[BasePageCandidateReport],
    rebuild_interval_reports: &[RebuildIntervalReport],
) -> Result<SelectedSizingDemands, SourceBoundHybridSizingError> {
    let base = base_page_candidates
        .iter()
        .find(|candidate| candidate.entries_per_page == SELECTED_PAGE_ENTRIES)
        .ok_or(SourceBoundHybridSizingError::InvalidReport)?;
    let interval = select_rebuild_interval(rebuild_interval_reports)?;
    let delta = interval
        .page_candidates
        .iter()
        .find(|candidate| candidate.entries_per_page == SELECTED_PAGE_ENTRIES)
        .ok_or(SourceBoundHybridSizingError::InvalidReport)?;
    let maximum_live_utxos_per_address = live_utxo_histogram
        .last()
        .map(|bucket| bucket.live_utxos)
        .ok_or(SourceBoundHybridSizingError::InvalidReport)?;

    Ok(SelectedSizingDemands {
        base_pages: base.base_pages,
        add_pages: delta.max_total_add_pages,
        spend_pages: delta.max_total_spend_pages,
        maximum_live_utxos_per_address,
        maximum_base_pages_per_address: base.maximum_pages_per_address,
        max_per_address_add_pages: delta.max_per_address_add_pages,
        max_per_address_spend_pages: delta.max_per_address_spend_pages,
    })
}

fn select_rebuild_interval(
    rebuild_interval_reports: &[RebuildIntervalReport],
) -> Result<&RebuildIntervalReport, SourceBoundHybridSizingError> {
    rebuild_interval_reports
        .iter()
        .find(|report| report.interval_blocks == SELECTED_GENERATION_INTERVAL_BLOCKS)
        .ok_or(SourceBoundHybridSizingError::InvalidReport)
}

#[cfg(any(feature = "rostl-experimental", test))]
fn select_capacity_demands(
    profile: SourceBoundHybridSizingProfile,
    current: SelectedSizingDemands,
    historical_growth: Option<&HistoricalGrowthEvidence>,
) -> Result<SelectedSizingDemands, SourceBoundHybridSizingError> {
    match (profile, historical_growth) {
        (SourceBoundHybridSizingProfile::LiveUtxoBaseDeltaV1, None) => Ok(current),
        (SourceBoundHybridSizingProfile::LiveUtxoBaseDeltaGrowthV2, Some(historical_growth)) => {
            Ok(historical_growth.projection.selected_sizing_demands())
        }
        _ => Err(SourceBoundHybridSizingError::InvalidReport),
    }
}

impl fmt::Display for SourceBoundHybridSizingReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "scenario={}", self.scenario)?;
        writeln!(f, "profile={}", self.profile.as_str())?;
        writeln!(
            f,
            "source=height:{},hash:{},blocks:{},measurement_blake2s256:{}",
            self.source.checkpoint_height,
            self.source.checkpoint_hash,
            self.source.expected_blocks,
            self.source.measurement_blake2s256,
        )?;
        writeln!(
            f,
            "fixed_profile=page_candidates:1|8|16,rebuild_intervals:288|1152|8064"
        )?;
        writeln!(
            f,
            "replay=blocks:{},distinct_standard_addresses:{},created_standard_events:{},spent_standard_events:{},delta_events:{},final_live_standard_utxos:{},maximum_live_standard_utxos:{}",
            self.applied_blocks,
            self.distinct_standard_addresses,
            self.created_standard_events,
            self.spent_standard_events,
            self.delta_events,
            self.final_live_standard_utxos,
            self.maximum_live_standard_utxos,
        )?;
        for bucket in &self.live_utxo_histogram {
            writeln!(
                f,
                "live_utxo_bucket=live_utxos:{},address_count:{}",
                bucket.live_utxos, bucket.address_count,
            )?;
        }
        for candidate in &self.base_page_candidates {
            writeln!(
                f,
                "base_page_candidate=entries_per_page:{},base_pages:{},maximum_pages_per_address:{},allocated_entries:{},live_entries:{},padding_entries:{}",
                candidate.entries_per_page,
                candidate.base_pages,
                candidate.maximum_pages_per_address,
                candidate.allocated_entries,
                candidate.live_entries,
                candidate.padding_entries,
            )?;
        }
        for interval in &self.rebuild_interval_reports {
            writeln!(
                f,
                "rebuild_interval=blocks:{},generations:{},trailing_partial_blocks:{},max_total_add_events:{},max_total_spend_events:{},max_total_delta_events:{},max_per_address_add_events:{},max_per_address_spend_events:{},max_per_address_delta_events:{}",
                interval.interval_blocks,
                interval.generation_count,
                interval.trailing_partial_generation_blocks,
                interval.max_total_add_events,
                interval.max_total_spend_events,
                interval.max_total_delta_events,
                interval.max_per_address_add_events,
                interval.max_per_address_spend_events,
                interval.max_per_address_delta_events,
            )?;
            for candidate in &interval.page_candidates {
                writeln!(
                    f,
                    "delta_page_candidate=interval_blocks:{},entries_per_page:{},max_total_add_pages:{},max_total_spend_pages:{},max_total_separate_pages:{},max_per_address_add_pages:{},max_per_address_spend_pages:{},max_per_address_separate_pages:{}",
                    interval.interval_blocks,
                    candidate.entries_per_page,
                    candidate.max_total_add_pages,
                    candidate.max_total_spend_pages,
                    candidate.max_total_separate_pages,
                    candidate.max_per_address_add_pages,
                    candidate.max_per_address_spend_pages,
                    candidate.max_per_address_separate_pages,
                )?;
            }
        }
        if let Some(growth) = &self.historical_growth {
            writeln!(
                f,
                "growth_policy=target_block_seconds:{},window_days:{},window_blocks:{},observation_windows:{},projection_windows:{},aligned_start_applied_blocks:{},aligned_end_applied_blocks:{},checkpoint_trailing_blocks:{}",
                growth.target_block_seconds,
                growth.window_days,
                growth.window_blocks,
                growth.observation_windows,
                growth.projection.horizon_windows,
                growth.aligned_start_applied_blocks,
                growth.aligned_end_applied_blocks,
                growth.checkpoint_trailing_blocks,
            )?;
            for snapshot in &growth.state_snapshots {
                writeln!(
                    f,
                    "growth_state=applied_blocks:{},distinct_standard_addresses:{},live_standard_utxos:{},base_pages:{},maximum_live_utxos_per_address:{},maximum_base_pages_per_address:{}",
                    snapshot.applied_blocks,
                    snapshot.distinct_standard_addresses,
                    snapshot.live_standard_utxos,
                    snapshot.base_pages,
                    snapshot.maximum_live_utxos_per_address,
                    snapshot.maximum_base_pages_per_address,
                )?;
            }
            for window in &growth.delta_windows {
                write_growth_delta(f, "growth_delta_window", *window)?;
            }
            if let Some(trailing) = growth.trailing_partial_generation {
                write_growth_delta(f, "growth_trailing_generation", trailing)?;
            }
            let increment = growth.maximum_positive_annual_increment;
            writeln!(
                f,
                "growth_increment=distinct_standard_addresses:{},live_standard_utxos:{},base_pages:{},maximum_live_utxos_per_address:{},max_total_add_pages:{},max_total_spend_pages:{},max_per_address_add_pages:{},max_per_address_spend_pages:{}",
                increment.distinct_standard_addresses,
                increment.live_standard_utxos,
                increment.base_pages,
                increment.maximum_live_utxos_per_address,
                increment.max_total_add_pages,
                increment.max_total_spend_pages,
                increment.max_per_address_add_pages,
                increment.max_per_address_spend_pages,
            )?;
            let projection = growth.projection;
            writeln!(
                f,
                "growth_projection=horizon_windows:{},horizon_blocks:{},qualification_expiry_height:{},capacity_horizon_end_height:{},distinct_standard_addresses:{},live_standard_utxos:{},base_pages:{},maximum_live_utxos_per_address:{},maximum_base_pages_per_address:{},max_total_add_pages:{},max_total_spend_pages:{},max_per_address_add_pages:{},max_per_address_spend_pages:{},fixed_page_reads:{}",
                projection.horizon_windows,
                projection.horizon_blocks,
                projection.qualification_expiry_height,
                projection.capacity_horizon_end_height,
                projection.distinct_standard_addresses,
                projection.live_standard_utxos,
                projection.base_pages,
                projection.maximum_live_utxos_per_address,
                projection.maximum_base_pages_per_address,
                projection.max_total_add_pages,
                projection.max_total_spend_pages,
                projection.max_per_address_add_pages,
                projection.max_per_address_spend_pages,
                projection.fixed_page_reads,
            )?;
            write!(
                f,
                "nonclaims=growth-forecast,statistical-growth-bound,oram-layout-selection,insertion-failure-bound,probabilistic-failure-bound,worst-case-bound,individual-generation-publication,physical-oram-trace,backend-calibration,rss,latency,stash,recovery,target-hardware,tdx,mainnet-readiness"
            )
        } else {
            write!(
                f,
                "nonclaims=projected-growth,oram-layout-selection,insertion-failure-bound,probabilistic-failure-bound,worst-case-bound,individual-generation-publication,physical-oram-trace,backend-calibration,rss,latency,stash,recovery,target-hardware,tdx,mainnet-readiness"
            )
        }
    }
}

fn write_growth_delta(
    formatter: &mut fmt::Formatter<'_>,
    label: &str,
    window: GrowthDeltaWindow,
) -> fmt::Result {
    writeln!(
        formatter,
        "{label}=start_applied_blocks:{},end_applied_blocks:{},generations:{},max_total_add_events:{},max_total_spend_events:{},max_total_delta_events:{},max_per_address_add_events:{},max_per_address_spend_events:{},max_per_address_delta_events:{},max_total_add_pages:{},max_total_spend_pages:{},max_total_separate_pages:{},max_per_address_add_pages:{},max_per_address_spend_pages:{},max_per_address_separate_pages:{}",
        window.start_applied_blocks,
        window.end_applied_blocks,
        window.generation_count,
        window.max_total_add_events,
        window.max_total_spend_events,
        window.max_total_delta_events,
        window.max_per_address_add_events,
        window.max_per_address_spend_events,
        window.max_per_address_delta_events,
        window.max_total_add_pages,
        window.max_total_spend_pages,
        window.max_total_separate_pages,
        window.max_per_address_add_pages,
        window.max_per_address_spend_pages,
        window.max_per_address_separate_pages,
    )
}

/// Coarse identifier-free failure from source-bound hybrid sizing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceBoundHybridSizingError {
    /// Capture or digest input validation failed.
    InputRejected,
    /// A checked tracker or report allocation failed.
    AllocationFailed,
    /// A sizing counter or page calculation overflowed.
    ArithmeticOverflow,
    /// The supplied block sequence or recomputed measurement was rejected.
    SourceRejected,
    /// The kind-preserving delta sequence violated an analysis invariant.
    AnalysisFailed,
    /// A serialized report differs from the fixed profile or claim boundary.
    InvalidReport,
}

impl fmt::Display for SourceBoundHybridSizingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InputRejected => f.write_str("source-bound hybrid-sizing input was rejected"),
            Self::AllocationFailed => f.write_str("source-bound hybrid-sizing allocation failed"),
            Self::ArithmeticOverflow => {
                f.write_str("source-bound hybrid-sizing arithmetic overflowed")
            }
            Self::SourceRejected => {
                f.write_str("source-bound hybrid-sizing source sequence was rejected")
            }
            Self::AnalysisFailed => f.write_str("source-bound hybrid-sizing analysis failed"),
            Self::InvalidReport => f.write_str("source-bound hybrid-sizing report is invalid"),
        }
    }
}

impl std::error::Error for SourceBoundHybridSizingError {}

/// Incremental exact-source replay for hybrid logical-sizing evidence.
pub struct SourceBoundHybridSizingSession {
    profile: SourceBoundHybridSizingProfile,
    scanner: Option<MainnetCorpusScanner>,
    expected_measurement: MainnetCorpusMeasurement,
    source: SourceBinding,
    applied_blocks: u64,
    distinct_standard_addresses: u64,
    created_standard_events: u64,
    spent_standard_events: u64,
    current_live_standard_utxos: u64,
    maximum_live_standard_utxos: u64,
    next_ordinals: Vec<u64>,
    live_utxos: Vec<u64>,
    intervals: Vec<RebuildIntervalAccumulator>,
    historical_growth: Option<HistoricalGrowthAccumulator>,
    failed_closed: bool,
}

impl SourceBoundHybridSizingSession {
    /// Validates the capture and starts the fixed hybrid-sizing profile.
    pub fn start(
        profile: SourceBoundHybridSizingProfile,
        measurement: &MainnetCorpusMeasurement,
        measurement_blake2s256: &str,
    ) -> Result<Self, SourceBoundHybridSizingError> {
        let source = SourceBinding::from_measurement(measurement, measurement_blake2s256)?;
        if profile == SourceBoundHybridSizingProfile::LiveUtxoBaseDeltaGrowthV2
            && !source.is_growth_v2_source()
        {
            return Err(SourceBoundHybridSizingError::InputRejected);
        }
        let historical_growth = match profile {
            SourceBoundHybridSizingProfile::LiveUtxoBaseDeltaV1 => None,
            SourceBoundHybridSizingProfile::LiveUtxoBaseDeltaGrowthV2 => Some(
                HistoricalGrowthAccumulator::production(source.expected_blocks)?,
            ),
        };
        let mut intervals = Vec::new();
        intervals
            .try_reserve_exact(REBUILD_INTERVALS.len())
            .map_err(|_| SourceBoundHybridSizingError::AllocationFailed)?;
        for interval in REBUILD_INTERVALS {
            intervals.push(RebuildIntervalAccumulator::new(interval)?);
        }
        Ok(Self {
            profile,
            scanner: Some(MainnetCorpusScanner::new()),
            expected_measurement: measurement.clone(),
            source,
            applied_blocks: 0,
            distinct_standard_addresses: 0,
            created_standard_events: 0,
            spent_standard_events: 0,
            current_live_standard_utxos: 0,
            maximum_live_standard_utxos: 0,
            next_ordinals: Vec::new(),
            live_utxos: Vec::new(),
            intervals,
            historical_growth,
            failed_closed: false,
        })
    }

    /// Applies one canonical block exactly once in source extraction order.
    pub fn push(&mut self, block: &IndexedBlock) -> Result<(), SourceBoundHybridSizingError> {
        if self.failed_closed || self.applied_blocks >= self.source.expected_blocks {
            self.fail_closed();
            return Err(SourceBoundHybridSizingError::SourceRejected);
        }
        let events = match self
            .scanner
            .as_mut()
            .ok_or(SourceBoundHybridSizingError::SourceRejected)?
            .push_collect_standard_address_deltas(block)
        {
            Ok(events) => events,
            Err(_) => {
                self.fail_closed();
                return Err(SourceBoundHybridSizingError::SourceRejected);
            }
        };
        for event in events {
            let is_created = event.is_created();
            let is_spent = event.is_spent();
            if let Err(error) = self.apply_delta(
                event.address_index(),
                event.ordinal(),
                event.first_for_address(),
                is_created,
                is_spent,
            ) {
                self.fail_closed();
                return Err(error);
            }
        }
        let mut selected_generation = None;
        for interval in &mut self.intervals {
            let generation = match interval.finish_block() {
                Ok(generation) => generation,
                Err(error) => {
                    self.fail_closed();
                    return Err(error);
                }
            };
            if interval.interval_blocks == SELECTED_GENERATION_INTERVAL_BLOCKS {
                selected_generation = generation;
            }
        }
        self.applied_blocks = self
            .applied_blocks
            .checked_add(1)
            .ok_or(SourceBoundHybridSizingError::ArithmeticOverflow)?;
        if let Some(historical_growth) = &mut self.historical_growth {
            if let Err(error) = historical_growth.observe(
                self.applied_blocks,
                self.distinct_standard_addresses,
                self.current_live_standard_utxos,
                &self.live_utxos,
                selected_generation,
            ) {
                self.fail_closed();
                return Err(error);
            }
        }
        Ok(())
    }

    /// Requires an exact source match and returns aggregate-only logical sizing.
    pub fn finish(mut self) -> Result<SourceBoundHybridSizingReport, SourceBoundHybridSizingError> {
        if self.failed_closed || self.applied_blocks != self.source.expected_blocks {
            self.fail_closed();
            return Err(SourceBoundHybridSizingError::SourceRejected);
        }
        let recomputed = self
            .scanner
            .take()
            .ok_or(SourceBoundHybridSizingError::SourceRejected)?
            .finish()
            .map_err(|_| SourceBoundHybridSizingError::SourceRejected)?;
        if recomputed != self.expected_measurement
            || self.distinct_standard_addresses
                != self.expected_measurement.distinct_standard_addresses()
            || self
                .created_standard_events
                .checked_add(self.spent_standard_events)
                .ok_or(SourceBoundHybridSizingError::ArithmeticOverflow)?
                != self
                    .expected_measurement
                    .standard_address_events()
                    .ok_or(SourceBoundHybridSizingError::SourceRejected)?
        {
            self.fail_closed();
            return Err(SourceBoundHybridSizingError::SourceRejected);
        }

        let live_utxo_histogram = build_live_histogram(&self.live_utxos)?;
        if self.current_live_standard_utxos != self.expected_measurement.live_standard_utxos()
            || !live_histogram_matches_measurement(&live_utxo_histogram, &self.expected_measurement)
        {
            self.fail_closed();
            return Err(SourceBoundHybridSizingError::SourceRejected);
        }
        let base_page_candidates =
            build_base_page_candidates(&live_utxo_histogram, self.current_live_standard_utxos)?;
        let mut rebuild_interval_reports = Vec::new();
        rebuild_interval_reports
            .try_reserve_exact(self.intervals.len())
            .map_err(|_| SourceBoundHybridSizingError::AllocationFailed)?;
        let mut selected_trailing_generation = None;
        for interval in self.intervals {
            let is_selected = interval.interval_blocks == SELECTED_GENERATION_INTERVAL_BLOCKS;
            let (report, trailing_generation) = interval.finish_with_trailing()?;
            if is_selected {
                selected_trailing_generation = trailing_generation;
            }
            rebuild_interval_reports.push(report);
        }
        let delta_events = self
            .created_standard_events
            .checked_add(self.spent_standard_events)
            .ok_or(SourceBoundHybridSizingError::ArithmeticOverflow)?;
        let selected = select_sizing_demands(
            &live_utxo_histogram,
            &base_page_candidates,
            &rebuild_interval_reports,
        )?;
        let selected_interval = select_rebuild_interval(&rebuild_interval_reports)?;
        let historical_growth = match self.historical_growth {
            Some(historical_growth) => Some(historical_growth.finish(
                self.source.expected_blocks,
                self.distinct_standard_addresses,
                self.current_live_standard_utxos,
                selected,
                selected_interval,
                selected_trailing_generation,
            )?),
            None => None,
        };
        let evidence_scope = match self.profile {
            SourceBoundHybridSizingProfile::LiveUtxoBaseDeltaV1 => EVIDENCE_SCOPE_V1,
            SourceBoundHybridSizingProfile::LiveUtxoBaseDeltaGrowthV2 => EVIDENCE_SCOPE_V2,
        };
        let report = SourceBoundHybridSizingReport {
            scenario: SCENARIO.to_owned(),
            profile: self.profile,
            source: self.source,
            page_candidates: PAGE_CANDIDATES.to_vec(),
            rebuild_intervals: REBUILD_INTERVALS.to_vec(),
            applied_blocks: self.applied_blocks,
            distinct_standard_addresses: self.distinct_standard_addresses,
            created_standard_events: self.created_standard_events,
            spent_standard_events: self.spent_standard_events,
            delta_events,
            final_live_standard_utxos: self.current_live_standard_utxos,
            maximum_live_standard_utxos: self.maximum_live_standard_utxos,
            live_utxo_histogram,
            base_page_candidates,
            rebuild_interval_reports,
            historical_growth,
            evidence_scope,
        };
        report.validate()?;
        Ok(report)
    }

    fn apply_delta(
        &mut self,
        address_index: u32,
        ordinal: u64,
        first_for_address: bool,
        is_created: bool,
        is_spent: bool,
    ) -> Result<(), SourceBoundHybridSizingError> {
        if is_created == is_spent {
            return Err(SourceBoundHybridSizingError::AnalysisFailed);
        }
        let index = usize::try_from(address_index)
            .map_err(|_| SourceBoundHybridSizingError::AnalysisFailed)?;
        if first_for_address {
            if u64::from(address_index) != self.distinct_standard_addresses || ordinal != 0 {
                return Err(SourceBoundHybridSizingError::AnalysisFailed);
            }
            self.next_ordinals
                .try_reserve(1)
                .map_err(|_| SourceBoundHybridSizingError::AllocationFailed)?;
            self.live_utxos
                .try_reserve(1)
                .map_err(|_| SourceBoundHybridSizingError::AllocationFailed)?;
            for interval in &mut self.intervals {
                interval.register_address(address_index)?;
            }
            self.next_ordinals.push(0);
            self.live_utxos.push(0);
            self.distinct_standard_addresses = self
                .distinct_standard_addresses
                .checked_add(1)
                .ok_or(SourceBoundHybridSizingError::ArithmeticOverflow)?;
        } else if u64::from(address_index) >= self.distinct_standard_addresses {
            return Err(SourceBoundHybridSizingError::AnalysisFailed);
        }

        let next_ordinal = self
            .next_ordinals
            .get_mut(index)
            .ok_or(SourceBoundHybridSizingError::AnalysisFailed)?;
        if *next_ordinal != ordinal {
            return Err(SourceBoundHybridSizingError::AnalysisFailed);
        }
        *next_ordinal = next_ordinal
            .checked_add(1)
            .ok_or(SourceBoundHybridSizingError::ArithmeticOverflow)?;

        let live = self
            .live_utxos
            .get_mut(index)
            .ok_or(SourceBoundHybridSizingError::AnalysisFailed)?;
        if is_created {
            *live = live
                .checked_add(1)
                .ok_or(SourceBoundHybridSizingError::ArithmeticOverflow)?;
            self.created_standard_events = self
                .created_standard_events
                .checked_add(1)
                .ok_or(SourceBoundHybridSizingError::ArithmeticOverflow)?;
            self.current_live_standard_utxos = self
                .current_live_standard_utxos
                .checked_add(1)
                .ok_or(SourceBoundHybridSizingError::ArithmeticOverflow)?;
            self.maximum_live_standard_utxos = self
                .maximum_live_standard_utxos
                .max(self.current_live_standard_utxos);
        } else {
            *live = live
                .checked_sub(1)
                .ok_or(SourceBoundHybridSizingError::AnalysisFailed)?;
            self.spent_standard_events = self
                .spent_standard_events
                .checked_add(1)
                .ok_or(SourceBoundHybridSizingError::ArithmeticOverflow)?;
            self.current_live_standard_utxos = self
                .current_live_standard_utxos
                .checked_sub(1)
                .ok_or(SourceBoundHybridSizingError::AnalysisFailed)?;
        }
        for interval in &mut self.intervals {
            interval.record(address_index, is_created)?;
        }
        Ok(())
    }

    fn fail_closed(&mut self) {
        self.failed_closed = true;
        self.scanner = None;
        self.next_ordinals.clear();
        self.live_utxos.clear();
        self.intervals.clear();
        self.historical_growth = None;
    }
}

impl RebuildIntervalReport {
    fn validate(
        &self,
        applied_blocks: u64,
        created_standard_events: u64,
        spent_standard_events: u64,
        delta_events: u64,
    ) -> Result<bool, SourceBoundHybridSizingError> {
        let interval = u64::from(self.interval_blocks);
        let expected_generations = ceil_div(applied_blocks, interval)?;
        let expected_trailing = u32::try_from(applied_blocks % interval)
            .map_err(|_| SourceBoundHybridSizingError::InvalidReport)?;
        let add_generation_coverage = self
            .max_total_add_events
            .checked_mul(self.generation_count)
            .ok_or(SourceBoundHybridSizingError::InvalidReport)?;
        let spend_generation_coverage = self
            .max_total_spend_events
            .checked_mul(self.generation_count)
            .ok_or(SourceBoundHybridSizingError::InvalidReport)?;
        let delta_generation_coverage = self
            .max_total_delta_events
            .checked_mul(self.generation_count)
            .ok_or(SourceBoundHybridSizingError::InvalidReport)?;
        if self.interval_blocks == 0
            || self.generation_count != expected_generations
            || self.trailing_partial_generation_blocks != expected_trailing
            || (self.max_total_add_events == 0) != (created_standard_events == 0)
            || (self.max_total_spend_events == 0) != (spent_standard_events == 0)
            || (self.max_total_delta_events == 0) != (delta_events == 0)
            || (self.max_per_address_add_events == 0) != (created_standard_events == 0)
            || (self.max_per_address_spend_events == 0) != (spent_standard_events == 0)
            || (self.max_per_address_delta_events == 0) != (delta_events == 0)
            || add_generation_coverage < created_standard_events
            || spend_generation_coverage < spent_standard_events
            || delta_generation_coverage < delta_events
            || self.max_total_add_events > created_standard_events
            || self.max_total_spend_events > spent_standard_events
            || self.max_total_delta_events > delta_events
            || self.max_total_delta_events < self.max_total_add_events
            || self.max_total_delta_events < self.max_total_spend_events
            || self.max_total_delta_events
                > self
                    .max_total_add_events
                    .checked_add(self.max_total_spend_events)
                    .ok_or(SourceBoundHybridSizingError::InvalidReport)?
            || self.max_per_address_add_events > self.max_total_add_events
            || self.max_per_address_spend_events > self.max_total_spend_events
            || self.max_per_address_delta_events > self.max_total_delta_events
            || self.max_per_address_delta_events < self.max_per_address_add_events
            || self.max_per_address_delta_events < self.max_per_address_spend_events
            || self.max_per_address_delta_events
                > self
                    .max_per_address_add_events
                    .checked_add(self.max_per_address_spend_events)
                    .ok_or(SourceBoundHybridSizingError::InvalidReport)?
            || self.page_candidates.len() != PAGE_CANDIDATES.len()
        {
            return Ok(false);
        }

        let mut previous = None;
        for (index, candidate) in self.page_candidates.iter().enumerate() {
            if candidate.entries_per_page != PAGE_CANDIDATES[index]
                || !candidate.validate(self)?
                || previous.is_some_and(|prior: &DeltaPageCandidateReport| {
                    candidate.max_total_add_pages > prior.max_total_add_pages
                        || candidate.max_total_spend_pages > prior.max_total_spend_pages
                        || candidate.max_total_separate_pages > prior.max_total_separate_pages
                        || candidate.max_per_address_add_pages > prior.max_per_address_add_pages
                        || candidate.max_per_address_spend_pages > prior.max_per_address_spend_pages
                        || candidate.max_per_address_separate_pages
                            > prior.max_per_address_separate_pages
                })
            {
                return Ok(false);
            }
            previous = Some(candidate);
        }
        Ok(true)
    }
}

impl DeltaPageCandidateReport {
    fn validate(
        &self,
        interval: &RebuildIntervalReport,
    ) -> Result<bool, SourceBoundHybridSizingError> {
        let entries = self.entries_per_page;
        if entries == 0
            || self.max_per_address_add_pages
                != ceil_div(interval.max_per_address_add_events, entries)?
            || self.max_per_address_spend_pages
                != ceil_div(interval.max_per_address_spend_events, entries)?
            || self.max_total_add_pages < ceil_div(interval.max_total_add_events, entries)?
            || self.max_total_spend_pages < ceil_div(interval.max_total_spend_events, entries)?
            || self.max_total_add_pages > interval.max_total_add_events
            || self.max_total_spend_pages > interval.max_total_spend_events
            || self.max_total_separate_pages < self.max_total_add_pages
            || self.max_total_separate_pages < self.max_total_spend_pages
            || self.max_total_separate_pages
                > self
                    .max_total_add_pages
                    .checked_add(self.max_total_spend_pages)
                    .ok_or(SourceBoundHybridSizingError::InvalidReport)?
            || self.max_per_address_separate_pages < self.max_per_address_add_pages
            || self.max_per_address_separate_pages < self.max_per_address_spend_pages
            || self.max_per_address_separate_pages
                > self
                    .max_per_address_add_pages
                    .checked_add(self.max_per_address_spend_pages)
                    .ok_or(SourceBoundHybridSizingError::InvalidReport)?
            || self.max_total_add_pages < self.max_per_address_add_pages
            || self.max_total_spend_pages < self.max_per_address_spend_pages
            || self.max_total_separate_pages < self.max_per_address_separate_pages
        {
            return Ok(false);
        }
        if entries == 1
            && (self.max_total_add_pages != interval.max_total_add_events
                || self.max_total_spend_pages != interval.max_total_spend_events
                || self.max_total_separate_pages != interval.max_total_delta_events
                || self.max_per_address_separate_pages != interval.max_per_address_delta_events)
        {
            return Ok(false);
        }
        Ok(true)
    }
}

struct RebuildIntervalAccumulator {
    interval_blocks: u32,
    current_generation_blocks: u32,
    generation_count: u64,
    max_total_add_events: u64,
    max_total_spend_events: u64,
    max_total_delta_events: u64,
    max_per_address_add_events: u64,
    max_per_address_spend_events: u64,
    max_per_address_delta_events: u64,
    page_candidates: Vec<DeltaPageCandidateReport>,
    tracker: SparseGenerationTracker,
}

impl RebuildIntervalAccumulator {
    fn new(interval_blocks: u32) -> Result<Self, SourceBoundHybridSizingError> {
        if interval_blocks == 0 {
            return Err(SourceBoundHybridSizingError::InputRejected);
        }
        let mut page_candidates = Vec::new();
        page_candidates
            .try_reserve_exact(PAGE_CANDIDATES.len())
            .map_err(|_| SourceBoundHybridSizingError::AllocationFailed)?;
        for entries_per_page in PAGE_CANDIDATES {
            page_candidates.push(DeltaPageCandidateReport::empty(entries_per_page));
        }
        Ok(Self {
            interval_blocks,
            current_generation_blocks: 0,
            generation_count: 0,
            max_total_add_events: 0,
            max_total_spend_events: 0,
            max_total_delta_events: 0,
            max_per_address_add_events: 0,
            max_per_address_spend_events: 0,
            max_per_address_delta_events: 0,
            page_candidates,
            tracker: SparseGenerationTracker::new(),
        })
    }

    fn register_address(&mut self, address_index: u32) -> Result<(), SourceBoundHybridSizingError> {
        self.tracker.register_address(address_index)
    }

    fn record(
        &mut self,
        address_index: u32,
        is_created: bool,
    ) -> Result<(), SourceBoundHybridSizingError> {
        self.tracker.record(address_index, is_created)
    }

    fn finish_block(&mut self) -> Result<Option<GenerationSummary>, SourceBoundHybridSizingError> {
        self.current_generation_blocks = self
            .current_generation_blocks
            .checked_add(1)
            .ok_or(SourceBoundHybridSizingError::ArithmeticOverflow)?;
        if self.current_generation_blocks == self.interval_blocks {
            Ok(Some(self.finish_generation()?))
        } else if self.current_generation_blocks > self.interval_blocks {
            Err(SourceBoundHybridSizingError::AnalysisFailed)
        } else {
            Ok(None)
        }
    }

    fn finish(self) -> Result<RebuildIntervalReport, SourceBoundHybridSizingError> {
        self.finish_with_trailing().map(|(report, _)| report)
    }

    fn finish_with_trailing(
        mut self,
    ) -> Result<(RebuildIntervalReport, Option<GenerationSummary>), SourceBoundHybridSizingError>
    {
        let trailing_partial_generation_blocks = self.current_generation_blocks;
        let trailing_partial_generation = if trailing_partial_generation_blocks > 0 {
            Some(self.finish_generation()?)
        } else {
            None
        };
        let report = RebuildIntervalReport {
            interval_blocks: self.interval_blocks,
            generation_count: self.generation_count,
            trailing_partial_generation_blocks,
            max_total_add_events: self.max_total_add_events,
            max_total_spend_events: self.max_total_spend_events,
            max_total_delta_events: self.max_total_delta_events,
            max_per_address_add_events: self.max_per_address_add_events,
            max_per_address_spend_events: self.max_per_address_spend_events,
            max_per_address_delta_events: self.max_per_address_delta_events,
            page_candidates: self.page_candidates,
        };
        Ok((report, trailing_partial_generation))
    }

    fn finish_generation(&mut self) -> Result<GenerationSummary, SourceBoundHybridSizingError> {
        let summary = self.tracker.summarize_and_clear()?;
        self.generation_count = self
            .generation_count
            .checked_add(1)
            .ok_or(SourceBoundHybridSizingError::ArithmeticOverflow)?;
        self.max_total_add_events = self.max_total_add_events.max(summary.total_add_events);
        self.max_total_spend_events = self.max_total_spend_events.max(summary.total_spend_events);
        self.max_total_delta_events = self.max_total_delta_events.max(summary.total_delta_events);
        self.max_per_address_add_events = self
            .max_per_address_add_events
            .max(summary.max_per_address_add_events);
        self.max_per_address_spend_events = self
            .max_per_address_spend_events
            .max(summary.max_per_address_spend_events);
        self.max_per_address_delta_events = self
            .max_per_address_delta_events
            .max(summary.max_per_address_delta_events);
        for (candidate, page_summary) in
            self.page_candidates.iter_mut().zip(summary.page_candidates)
        {
            candidate.update(page_summary);
        }
        self.current_generation_blocks = 0;
        Ok(summary)
    }
}

struct HistoricalGrowthAccumulator {
    expected_blocks: u64,
    aligned_start_applied_blocks: u64,
    aligned_end_applied_blocks: u64,
    checkpoint_trailing_blocks: u32,
    state_snapshots: Vec<GrowthStateSnapshot>,
    delta_windows: Vec<GrowthDeltaWindow>,
}

impl HistoricalGrowthAccumulator {
    fn production(expected_blocks: u64) -> Result<Self, SourceBoundHybridSizingError> {
        let interval = u64::from(SELECTED_GENERATION_INTERVAL_BLOCKS);
        let aligned_end_applied_blocks = expected_blocks
            .checked_sub(expected_blocks % interval)
            .ok_or(SourceBoundHybridSizingError::ArithmeticOverflow)?;
        let observation_blocks = GROWTH_WINDOW_BLOCKS
            .checked_mul(
                u64::try_from(GROWTH_OBSERVATION_WINDOWS)
                    .map_err(|_| SourceBoundHybridSizingError::ArithmeticOverflow)?,
            )
            .ok_or(SourceBoundHybridSizingError::ArithmeticOverflow)?;
        let aligned_start_applied_blocks = aligned_end_applied_blocks
            .checked_sub(observation_blocks)
            .ok_or(SourceBoundHybridSizingError::InputRejected)?;
        if aligned_start_applied_blocks < MAINNET_BLOSSOM_ACTIVATION_HEIGHT
            || !GROWTH_WINDOW_BLOCKS.is_multiple_of(interval)
        {
            return Err(SourceBoundHybridSizingError::InputRejected);
        }
        let checkpoint_trailing_blocks = u32::try_from(
            expected_blocks
                .checked_sub(aligned_end_applied_blocks)
                .ok_or(SourceBoundHybridSizingError::ArithmeticOverflow)?,
        )
        .map_err(|_| SourceBoundHybridSizingError::ArithmeticOverflow)?;

        let mut state_snapshots = Vec::new();
        state_snapshots
            .try_reserve_exact(
                GROWTH_OBSERVATION_WINDOWS
                    .checked_add(1)
                    .ok_or(SourceBoundHybridSizingError::ArithmeticOverflow)?,
            )
            .map_err(|_| SourceBoundHybridSizingError::AllocationFailed)?;
        let mut delta_windows = Vec::new();
        delta_windows
            .try_reserve_exact(GROWTH_OBSERVATION_WINDOWS)
            .map_err(|_| SourceBoundHybridSizingError::AllocationFailed)?;
        for index in 0..GROWTH_OBSERVATION_WINDOWS {
            let offset = GROWTH_WINDOW_BLOCKS
                .checked_mul(
                    u64::try_from(index)
                        .map_err(|_| SourceBoundHybridSizingError::ArithmeticOverflow)?,
                )
                .ok_or(SourceBoundHybridSizingError::ArithmeticOverflow)?;
            let start_applied_blocks = aligned_start_applied_blocks
                .checked_add(offset)
                .ok_or(SourceBoundHybridSizingError::ArithmeticOverflow)?;
            let end_applied_blocks = start_applied_blocks
                .checked_add(GROWTH_WINDOW_BLOCKS)
                .ok_or(SourceBoundHybridSizingError::ArithmeticOverflow)?;
            delta_windows.push(GrowthDeltaWindow::empty(
                start_applied_blocks,
                end_applied_blocks,
            ));
        }

        Ok(Self {
            expected_blocks,
            aligned_start_applied_blocks,
            aligned_end_applied_blocks,
            checkpoint_trailing_blocks,
            state_snapshots,
            delta_windows,
        })
    }

    fn observe(
        &mut self,
        applied_blocks: u64,
        distinct_standard_addresses: u64,
        live_standard_utxos: u64,
        live_utxos: &[u64],
        selected_generation: Option<GenerationSummary>,
    ) -> Result<(), SourceBoundHybridSizingError> {
        if applied_blocks > self.expected_blocks {
            return Err(SourceBoundHybridSizingError::AnalysisFailed);
        }
        let interval = u64::from(SELECTED_GENERATION_INTERVAL_BLOCKS);
        let on_generation_boundary = applied_blocks.is_multiple_of(interval);
        if on_generation_boundary != selected_generation.is_some() {
            return Err(SourceBoundHybridSizingError::AnalysisFailed);
        }
        if applied_blocks < self.aligned_start_applied_blocks
            || applied_blocks > self.aligned_end_applied_blocks
        {
            return Ok(());
        }

        if applied_blocks > self.aligned_start_applied_blocks && on_generation_boundary {
            let offset = applied_blocks
                .checked_sub(self.aligned_start_applied_blocks)
                .and_then(|value| value.checked_sub(1))
                .ok_or(SourceBoundHybridSizingError::ArithmeticOverflow)?;
            let window_index = usize::try_from(offset / GROWTH_WINDOW_BLOCKS)
                .map_err(|_| SourceBoundHybridSizingError::ArithmeticOverflow)?;
            let window = self
                .delta_windows
                .get_mut(window_index)
                .ok_or(SourceBoundHybridSizingError::AnalysisFailed)?;
            window
                .update(selected_generation.ok_or(SourceBoundHybridSizingError::AnalysisFailed)?)?;
        }

        let since_start = applied_blocks
            .checked_sub(self.aligned_start_applied_blocks)
            .ok_or(SourceBoundHybridSizingError::ArithmeticOverflow)?;
        if since_start % GROWTH_WINDOW_BLOCKS == 0 {
            let snapshot = GrowthStateSnapshot::capture(
                applied_blocks,
                distinct_standard_addresses,
                live_standard_utxos,
                live_utxos,
            )?;
            if self
                .state_snapshots
                .last()
                .is_some_and(|previous| previous.applied_blocks >= applied_blocks)
            {
                return Err(SourceBoundHybridSizingError::AnalysisFailed);
            }
            self.state_snapshots
                .try_reserve(1)
                .map_err(|_| SourceBoundHybridSizingError::AllocationFailed)?;
            self.state_snapshots.push(snapshot);
        }
        Ok(())
    }

    fn finish(
        self,
        expected_blocks: u64,
        distinct_standard_addresses: u64,
        live_standard_utxos: u64,
        current: SelectedSizingDemands,
        full_history: &RebuildIntervalReport,
        trailing_generation: Option<GenerationSummary>,
    ) -> Result<HistoricalGrowthEvidence, SourceBoundHybridSizingError> {
        if self.expected_blocks != expected_blocks {
            return Err(SourceBoundHybridSizingError::AnalysisFailed);
        }
        let trailing_partial_generation =
            match (self.checkpoint_trailing_blocks, trailing_generation) {
                (0, None) => None,
                (blocks, Some(generation)) if blocks > 0 => {
                    let mut trailing = GrowthDeltaWindow::empty(
                        self.aligned_end_applied_blocks,
                        self.expected_blocks,
                    );
                    trailing.update(generation)?;
                    Some(trailing)
                }
                _ => return Err(SourceBoundHybridSizingError::AnalysisFailed),
            };
        let maximum_positive_annual_increment =
            GrowthAnnualIncrement::derive(&self.state_snapshots, &self.delta_windows)?;
        let projection = GrowthProjection::derive(
            expected_blocks,
            distinct_standard_addresses,
            live_standard_utxos,
            current,
            maximum_positive_annual_increment,
        )?;
        let evidence = HistoricalGrowthEvidence {
            target_block_seconds: TARGET_BLOCK_SECONDS,
            window_days: GROWTH_WINDOW_DAYS,
            window_blocks: GROWTH_WINDOW_BLOCKS,
            observation_windows: u16::try_from(GROWTH_OBSERVATION_WINDOWS)
                .map_err(|_| SourceBoundHybridSizingError::ArithmeticOverflow)?,
            aligned_start_applied_blocks: self.aligned_start_applied_blocks,
            aligned_end_applied_blocks: self.aligned_end_applied_blocks,
            checkpoint_trailing_blocks: self.checkpoint_trailing_blocks,
            state_snapshots: self.state_snapshots,
            delta_windows: self.delta_windows,
            trailing_partial_generation,
            maximum_positive_annual_increment,
            projection,
        };
        evidence.validate(
            expected_blocks,
            distinct_standard_addresses,
            live_standard_utxos,
            current,
            full_history,
        )?;
        Ok(evidence)
    }
}

impl GrowthStateSnapshot {
    fn capture(
        applied_blocks: u64,
        distinct_standard_addresses: u64,
        live_standard_utxos: u64,
        live_utxos: &[u64],
    ) -> Result<Self, SourceBoundHybridSizingError> {
        if u64::try_from(live_utxos.len())
            .map_err(|_| SourceBoundHybridSizingError::ArithmeticOverflow)?
            != distinct_standard_addresses
        {
            return Err(SourceBoundHybridSizingError::AnalysisFailed);
        }
        let mut recomputed_live = 0_u64;
        let mut base_pages = 0_u64;
        let mut maximum_live_utxos_per_address = 0_u64;
        for live in live_utxos {
            recomputed_live = recomputed_live
                .checked_add(*live)
                .ok_or(SourceBoundHybridSizingError::ArithmeticOverflow)?;
            base_pages = base_pages
                .checked_add(ceil_div(*live, SELECTED_PAGE_ENTRIES)?)
                .ok_or(SourceBoundHybridSizingError::ArithmeticOverflow)?;
            maximum_live_utxos_per_address = maximum_live_utxos_per_address.max(*live);
        }
        if recomputed_live != live_standard_utxos {
            return Err(SourceBoundHybridSizingError::AnalysisFailed);
        }
        Ok(Self {
            applied_blocks,
            distinct_standard_addresses,
            live_standard_utxos,
            base_pages,
            maximum_live_utxos_per_address,
            maximum_base_pages_per_address: ceil_div(
                maximum_live_utxos_per_address,
                SELECTED_PAGE_ENTRIES,
            )?,
        })
    }

    fn validate(self) -> Result<(), SourceBoundHybridSizingError> {
        let minimum_base_pages = ceil_div(self.live_standard_utxos, SELECTED_PAGE_ENTRIES)?;
        if self.base_pages < minimum_base_pages
            || self.base_pages > self.live_standard_utxos
            || self.maximum_live_utxos_per_address > self.live_standard_utxos
            || self.maximum_base_pages_per_address
                != ceil_div(self.maximum_live_utxos_per_address, SELECTED_PAGE_ENTRIES)?
            || self.maximum_base_pages_per_address > self.base_pages
        {
            return Err(SourceBoundHybridSizingError::InvalidReport);
        }
        Ok(())
    }
}

impl GrowthDeltaWindow {
    const fn empty(start_applied_blocks: u64, end_applied_blocks: u64) -> Self {
        Self {
            start_applied_blocks,
            end_applied_blocks,
            generation_count: 0,
            max_total_add_events: 0,
            max_total_spend_events: 0,
            max_total_delta_events: 0,
            max_per_address_add_events: 0,
            max_per_address_spend_events: 0,
            max_per_address_delta_events: 0,
            max_total_add_pages: 0,
            max_total_spend_pages: 0,
            max_total_separate_pages: 0,
            max_per_address_add_pages: 0,
            max_per_address_spend_pages: 0,
            max_per_address_separate_pages: 0,
        }
    }

    fn update(
        &mut self,
        generation: GenerationSummary,
    ) -> Result<(), SourceBoundHybridSizingError> {
        let selected_index = PAGE_CANDIDATES
            .iter()
            .position(|entries| *entries == SELECTED_PAGE_ENTRIES)
            .ok_or(SourceBoundHybridSizingError::AnalysisFailed)?;
        let pages = generation
            .page_candidates
            .get(selected_index)
            .copied()
            .ok_or(SourceBoundHybridSizingError::AnalysisFailed)?;
        self.generation_count = self
            .generation_count
            .checked_add(1)
            .ok_or(SourceBoundHybridSizingError::ArithmeticOverflow)?;
        self.max_total_add_events = self.max_total_add_events.max(generation.total_add_events);
        self.max_total_spend_events = self
            .max_total_spend_events
            .max(generation.total_spend_events);
        self.max_total_delta_events = self
            .max_total_delta_events
            .max(generation.total_delta_events);
        self.max_per_address_add_events = self
            .max_per_address_add_events
            .max(generation.max_per_address_add_events);
        self.max_per_address_spend_events = self
            .max_per_address_spend_events
            .max(generation.max_per_address_spend_events);
        self.max_per_address_delta_events = self
            .max_per_address_delta_events
            .max(generation.max_per_address_delta_events);
        self.max_total_add_pages = self.max_total_add_pages.max(pages.total_add_pages);
        self.max_total_spend_pages = self.max_total_spend_pages.max(pages.total_spend_pages);
        self.max_total_separate_pages = self
            .max_total_separate_pages
            .max(pages.total_separate_pages);
        self.max_per_address_add_pages = self
            .max_per_address_add_pages
            .max(pages.max_per_address_add_pages);
        self.max_per_address_spend_pages = self
            .max_per_address_spend_pages
            .max(pages.max_per_address_spend_pages);
        self.max_per_address_separate_pages = self
            .max_per_address_separate_pages
            .max(pages.max_per_address_separate_pages);
        Ok(())
    }

    fn validate(self, expected_generations: u64) -> Result<(), SourceBoundHybridSizingError> {
        if self.end_applied_blocks
            != self
                .start_applied_blocks
                .checked_add(GROWTH_WINDOW_BLOCKS)
                .ok_or(SourceBoundHybridSizingError::InvalidReport)?
            || self.generation_count != expected_generations
        {
            return Err(SourceBoundHybridSizingError::InvalidReport);
        }
        self.validate_maxima()
    }

    fn validate_trailing(
        self,
        expected_start: u64,
        expected_end: u64,
        expected_blocks: u32,
    ) -> Result<(), SourceBoundHybridSizingError> {
        if expected_blocks == 0
            || expected_blocks >= SELECTED_GENERATION_INTERVAL_BLOCKS
            || self.start_applied_blocks != expected_start
            || self.end_applied_blocks != expected_end
            || self.generation_count != 1
            || self
                .end_applied_blocks
                .checked_sub(self.start_applied_blocks)
                .ok_or(SourceBoundHybridSizingError::InvalidReport)?
                != u64::from(expected_blocks)
        {
            return Err(SourceBoundHybridSizingError::InvalidReport);
        }
        self.validate_maxima()
    }

    fn validate_maxima(self) -> Result<(), SourceBoundHybridSizingError> {
        if self.max_per_address_add_events > self.max_total_add_events
            || self.max_per_address_spend_events > self.max_total_spend_events
            || self.max_per_address_delta_events > self.max_total_delta_events
            || self.max_total_delta_events < self.max_total_add_events
            || self.max_total_delta_events < self.max_total_spend_events
            || self.max_total_delta_events
                > self
                    .max_total_add_events
                    .checked_add(self.max_total_spend_events)
                    .ok_or(SourceBoundHybridSizingError::InvalidReport)?
            || self.max_per_address_delta_events < self.max_per_address_add_events
            || self.max_per_address_delta_events < self.max_per_address_spend_events
            || self.max_per_address_delta_events
                > self
                    .max_per_address_add_events
                    .checked_add(self.max_per_address_spend_events)
                    .ok_or(SourceBoundHybridSizingError::InvalidReport)?
            || self.max_total_add_pages
                < ceil_div(self.max_total_add_events, SELECTED_PAGE_ENTRIES)?
            || self.max_total_spend_pages
                < ceil_div(self.max_total_spend_events, SELECTED_PAGE_ENTRIES)?
            || self.max_total_add_pages > self.max_total_add_events
            || self.max_total_spend_pages > self.max_total_spend_events
            || self.max_total_separate_pages < self.max_total_add_pages
            || self.max_total_separate_pages < self.max_total_spend_pages
            || self.max_total_separate_pages
                > self
                    .max_total_add_pages
                    .checked_add(self.max_total_spend_pages)
                    .ok_or(SourceBoundHybridSizingError::InvalidReport)?
            || self.max_per_address_add_pages
                != ceil_div(self.max_per_address_add_events, SELECTED_PAGE_ENTRIES)?
            || self.max_per_address_spend_pages
                != ceil_div(self.max_per_address_spend_events, SELECTED_PAGE_ENTRIES)?
            || self.max_per_address_separate_pages < self.max_per_address_add_pages
            || self.max_per_address_separate_pages < self.max_per_address_spend_pages
            || self.max_per_address_separate_pages
                > self
                    .max_per_address_add_pages
                    .checked_add(self.max_per_address_spend_pages)
                    .ok_or(SourceBoundHybridSizingError::InvalidReport)?
            || self.max_per_address_add_pages > self.max_total_add_pages
            || self.max_per_address_spend_pages > self.max_total_spend_pages
            || self.max_per_address_separate_pages > self.max_total_separate_pages
        {
            return Err(SourceBoundHybridSizingError::InvalidReport);
        }
        Ok(())
    }

    fn does_not_exceed(
        self,
        full_history: &RebuildIntervalReport,
    ) -> Result<bool, SourceBoundHybridSizingError> {
        let pages = full_history
            .page_candidates
            .iter()
            .find(|candidate| candidate.entries_per_page == SELECTED_PAGE_ENTRIES)
            .ok_or(SourceBoundHybridSizingError::InvalidReport)?;
        Ok(
            self.max_total_add_events <= full_history.max_total_add_events
                && self.max_total_spend_events <= full_history.max_total_spend_events
                && self.max_total_delta_events <= full_history.max_total_delta_events
                && self.max_per_address_add_events <= full_history.max_per_address_add_events
                && self.max_per_address_spend_events <= full_history.max_per_address_spend_events
                && self.max_per_address_delta_events <= full_history.max_per_address_delta_events
                && self.max_total_add_pages <= pages.max_total_add_pages
                && self.max_total_spend_pages <= pages.max_total_spend_pages
                && self.max_total_separate_pages <= pages.max_total_separate_pages
                && self.max_per_address_add_pages <= pages.max_per_address_add_pages
                && self.max_per_address_spend_pages <= pages.max_per_address_spend_pages
                && self.max_per_address_separate_pages <= pages.max_per_address_separate_pages,
        )
    }
}

impl GrowthAnnualIncrement {
    fn derive(
        state_snapshots: &[GrowthStateSnapshot],
        delta_windows: &[GrowthDeltaWindow],
    ) -> Result<Self, SourceBoundHybridSizingError> {
        if state_snapshots.len()
            != GROWTH_OBSERVATION_WINDOWS
                .checked_add(1)
                .ok_or(SourceBoundHybridSizingError::ArithmeticOverflow)?
            || delta_windows.len() != GROWTH_OBSERVATION_WINDOWS
        {
            return Err(SourceBoundHybridSizingError::InvalidReport);
        }
        let mut increment = Self {
            distinct_standard_addresses: 0,
            live_standard_utxos: 0,
            base_pages: 0,
            maximum_live_utxos_per_address: 0,
            max_total_add_pages: 0,
            max_total_spend_pages: 0,
            max_per_address_add_pages: 0,
            max_per_address_spend_pages: 0,
        };
        for pair in state_snapshots.windows(2) {
            let earlier = pair[0];
            let later = pair[1];
            increment.distinct_standard_addresses = increment.distinct_standard_addresses.max(
                later
                    .distinct_standard_addresses
                    .saturating_sub(earlier.distinct_standard_addresses),
            );
            increment.live_standard_utxos = increment.live_standard_utxos.max(
                later
                    .live_standard_utxos
                    .saturating_sub(earlier.live_standard_utxos),
            );
            increment.base_pages = increment
                .base_pages
                .max(later.base_pages.saturating_sub(earlier.base_pages));
            increment.maximum_live_utxos_per_address =
                increment.maximum_live_utxos_per_address.max(
                    later
                        .maximum_live_utxos_per_address
                        .saturating_sub(earlier.maximum_live_utxos_per_address),
                );
        }
        for pair in delta_windows.windows(2) {
            let earlier = pair[0];
            let later = pair[1];
            increment.max_total_add_pages = increment.max_total_add_pages.max(
                later
                    .max_total_add_pages
                    .saturating_sub(earlier.max_total_add_pages),
            );
            increment.max_total_spend_pages = increment.max_total_spend_pages.max(
                later
                    .max_total_spend_pages
                    .saturating_sub(earlier.max_total_spend_pages),
            );
            increment.max_per_address_add_pages = increment.max_per_address_add_pages.max(
                later
                    .max_per_address_add_pages
                    .saturating_sub(earlier.max_per_address_add_pages),
            );
            increment.max_per_address_spend_pages = increment.max_per_address_spend_pages.max(
                later
                    .max_per_address_spend_pages
                    .saturating_sub(earlier.max_per_address_spend_pages),
            );
        }
        Ok(increment)
    }
}

impl GrowthProjection {
    fn derive(
        expected_blocks: u64,
        distinct_standard_addresses: u64,
        live_standard_utxos: u64,
        current: SelectedSizingDemands,
        increment: GrowthAnnualIncrement,
    ) -> Result<Self, SourceBoundHybridSizingError> {
        let horizon = u64::from(GROWTH_PROJECTION_WINDOWS);
        let horizon_blocks = GROWTH_WINDOW_BLOCKS
            .checked_mul(horizon)
            .ok_or(SourceBoundHybridSizingError::ArithmeticOverflow)?;
        let checkpoint_height = expected_blocks
            .checked_sub(1)
            .ok_or(SourceBoundHybridSizingError::InvalidReport)?;
        let qualification_expiry_height = u32::try_from(
            checkpoint_height
                .checked_add(GROWTH_WINDOW_BLOCKS)
                .ok_or(SourceBoundHybridSizingError::ArithmeticOverflow)?,
        )
        .map_err(|_| SourceBoundHybridSizingError::ArithmeticOverflow)?;
        let capacity_horizon_end_height = u32::try_from(
            checkpoint_height
                .checked_add(horizon_blocks)
                .ok_or(SourceBoundHybridSizingError::ArithmeticOverflow)?,
        )
        .map_err(|_| SourceBoundHybridSizingError::ArithmeticOverflow)?;
        let distinct_standard_addresses = checked_linear_projection(
            distinct_standard_addresses,
            increment.distinct_standard_addresses,
            horizon,
        )?;
        let live_standard_utxos =
            checked_linear_projection(live_standard_utxos, increment.live_standard_utxos, horizon)?;
        let maximum_live_utxos_per_address = checked_linear_projection(
            current.maximum_live_utxos_per_address,
            increment.maximum_live_utxos_per_address,
            horizon,
        )?;
        let maximum_base_pages_per_address =
            ceil_div(maximum_live_utxos_per_address, SELECTED_PAGE_ENTRIES)?;
        let linearly_projected_base_pages =
            checked_linear_projection(current.base_pages, increment.base_pages, horizon)?;
        let base_pages = linearly_projected_base_pages
            .max(ceil_div(live_standard_utxos, SELECTED_PAGE_ENTRIES)?)
            .max(maximum_base_pages_per_address);
        let max_per_address_add_pages = checked_linear_projection(
            current.max_per_address_add_pages,
            increment.max_per_address_add_pages,
            horizon,
        )?;
        let max_per_address_spend_pages = checked_linear_projection(
            current.max_per_address_spend_pages,
            increment.max_per_address_spend_pages,
            horizon,
        )?;
        let max_total_add_pages =
            checked_linear_projection(current.add_pages, increment.max_total_add_pages, horizon)?
                .max(max_per_address_add_pages);
        let max_total_spend_pages = checked_linear_projection(
            current.spend_pages,
            increment.max_total_spend_pages,
            horizon,
        )?
        .max(max_per_address_spend_pages);
        let fixed_page_reads = maximum_base_pages_per_address
            .checked_add(max_per_address_add_pages)
            .and_then(|reads| reads.checked_add(max_per_address_spend_pages))
            .ok_or(SourceBoundHybridSizingError::ArithmeticOverflow)?;
        Ok(Self {
            horizon_windows: GROWTH_PROJECTION_WINDOWS,
            horizon_blocks,
            qualification_expiry_height,
            capacity_horizon_end_height,
            distinct_standard_addresses,
            live_standard_utxos,
            base_pages,
            maximum_live_utxos_per_address,
            maximum_base_pages_per_address,
            max_total_add_pages,
            max_total_spend_pages,
            max_per_address_add_pages,
            max_per_address_spend_pages,
            fixed_page_reads,
        })
    }

    #[cfg(any(feature = "rostl-experimental", test))]
    const fn selected_sizing_demands(self) -> SelectedSizingDemands {
        SelectedSizingDemands {
            base_pages: self.base_pages,
            add_pages: self.max_total_add_pages,
            spend_pages: self.max_total_spend_pages,
            maximum_live_utxos_per_address: self.maximum_live_utxos_per_address,
            maximum_base_pages_per_address: self.maximum_base_pages_per_address,
            max_per_address_add_pages: self.max_per_address_add_pages,
            max_per_address_spend_pages: self.max_per_address_spend_pages,
        }
    }
}

impl HistoricalGrowthEvidence {
    fn validate(
        &self,
        expected_blocks: u64,
        distinct_standard_addresses: u64,
        live_standard_utxos: u64,
        current: SelectedSizingDemands,
        full_history: &RebuildIntervalReport,
    ) -> Result<(), SourceBoundHybridSizingError> {
        let interval = u64::from(SELECTED_GENERATION_INTERVAL_BLOCKS);
        let expected_aligned_end = expected_blocks
            .checked_sub(expected_blocks % interval)
            .ok_or(SourceBoundHybridSizingError::InvalidReport)?;
        let expected_observation_blocks = GROWTH_WINDOW_BLOCKS
            .checked_mul(
                u64::try_from(GROWTH_OBSERVATION_WINDOWS)
                    .map_err(|_| SourceBoundHybridSizingError::InvalidReport)?,
            )
            .ok_or(SourceBoundHybridSizingError::InvalidReport)?;
        let expected_aligned_start = expected_aligned_end
            .checked_sub(expected_observation_blocks)
            .ok_or(SourceBoundHybridSizingError::InvalidReport)?;
        let expected_trailing = u32::try_from(
            expected_blocks
                .checked_sub(expected_aligned_end)
                .ok_or(SourceBoundHybridSizingError::InvalidReport)?,
        )
        .map_err(|_| SourceBoundHybridSizingError::InvalidReport)?;
        if self.target_block_seconds != TARGET_BLOCK_SECONDS
            || self.window_days != GROWTH_WINDOW_DAYS
            || self.window_blocks != GROWTH_WINDOW_BLOCKS
            || self.observation_windows
                != u16::try_from(GROWTH_OBSERVATION_WINDOWS)
                    .map_err(|_| SourceBoundHybridSizingError::InvalidReport)?
            || self.aligned_start_applied_blocks != expected_aligned_start
            || self.aligned_end_applied_blocks != expected_aligned_end
            || self.checkpoint_trailing_blocks != expected_trailing
            || expected_aligned_start < MAINNET_BLOSSOM_ACTIVATION_HEIGHT
            || self.state_snapshots.len()
                != GROWTH_OBSERVATION_WINDOWS
                    .checked_add(1)
                    .ok_or(SourceBoundHybridSizingError::InvalidReport)?
            || self.delta_windows.len() != GROWTH_OBSERVATION_WINDOWS
        {
            return Err(SourceBoundHybridSizingError::InvalidReport);
        }

        for (index, snapshot) in self.state_snapshots.iter().copied().enumerate() {
            let expected_applied_blocks = expected_aligned_start
                .checked_add(
                    GROWTH_WINDOW_BLOCKS
                        .checked_mul(
                            u64::try_from(index)
                                .map_err(|_| SourceBoundHybridSizingError::InvalidReport)?,
                        )
                        .ok_or(SourceBoundHybridSizingError::InvalidReport)?,
                )
                .ok_or(SourceBoundHybridSizingError::InvalidReport)?;
            if snapshot.applied_blocks != expected_applied_blocks
                || index > 0
                    && snapshot.distinct_standard_addresses
                        < self.state_snapshots[index - 1].distinct_standard_addresses
            {
                return Err(SourceBoundHybridSizingError::InvalidReport);
            }
            snapshot.validate()?;
        }
        let last_snapshot = self
            .state_snapshots
            .last()
            .ok_or(SourceBoundHybridSizingError::InvalidReport)?;
        if last_snapshot.distinct_standard_addresses > distinct_standard_addresses {
            return Err(SourceBoundHybridSizingError::InvalidReport);
        }

        let expected_generations = GROWTH_WINDOW_BLOCKS / interval;
        for (index, window) in self.delta_windows.iter().copied().enumerate() {
            let expected_start = expected_aligned_start
                .checked_add(
                    GROWTH_WINDOW_BLOCKS
                        .checked_mul(
                            u64::try_from(index)
                                .map_err(|_| SourceBoundHybridSizingError::InvalidReport)?,
                        )
                        .ok_or(SourceBoundHybridSizingError::InvalidReport)?,
                )
                .ok_or(SourceBoundHybridSizingError::InvalidReport)?;
            if window.start_applied_blocks != expected_start
                || !window.does_not_exceed(full_history)?
            {
                return Err(SourceBoundHybridSizingError::InvalidReport);
            }
            window.validate(expected_generations)?;
        }
        match (
            self.checkpoint_trailing_blocks,
            self.trailing_partial_generation,
        ) {
            (0, None) => {}
            (blocks, Some(trailing)) if blocks > 0 => {
                trailing.validate_trailing(expected_aligned_end, expected_blocks, blocks)?;
                if !trailing.does_not_exceed(full_history)? {
                    return Err(SourceBoundHybridSizingError::InvalidReport);
                }
            }
            _ => return Err(SourceBoundHybridSizingError::InvalidReport),
        }

        let expected_increment =
            GrowthAnnualIncrement::derive(&self.state_snapshots, &self.delta_windows)?;
        let expected_projection = GrowthProjection::derive(
            expected_blocks,
            distinct_standard_addresses,
            live_standard_utxos,
            current,
            expected_increment,
        )?;
        if self.maximum_positive_annual_increment != expected_increment
            || self.projection != expected_projection
        {
            return Err(SourceBoundHybridSizingError::InvalidReport);
        }
        Ok(())
    }
}

fn checked_linear_projection(
    current: u64,
    increment: u64,
    horizon: u64,
) -> Result<u64, SourceBoundHybridSizingError> {
    increment
        .checked_mul(horizon)
        .and_then(|growth| current.checked_add(growth))
        .ok_or(SourceBoundHybridSizingError::ArithmeticOverflow)
}

struct SparseGenerationTracker {
    positions: Vec<u32>,
    entries: Vec<GenerationEntry>,
}

impl SparseGenerationTracker {
    const fn new() -> Self {
        Self {
            positions: Vec::new(),
            entries: Vec::new(),
        }
    }

    fn register_address(&mut self, address_index: u32) -> Result<(), SourceBoundHybridSizingError> {
        let expected_index = usize::try_from(address_index)
            .map_err(|_| SourceBoundHybridSizingError::AnalysisFailed)?;
        if self.positions.len() != expected_index {
            return Err(SourceBoundHybridSizingError::AnalysisFailed);
        }
        self.positions
            .try_reserve(1)
            .map_err(|_| SourceBoundHybridSizingError::AllocationFailed)?;
        self.positions.push(EMPTY_POSITION);
        Ok(())
    }

    fn record(
        &mut self,
        address_index: u32,
        is_created: bool,
    ) -> Result<(), SourceBoundHybridSizingError> {
        let address = usize::try_from(address_index)
            .map_err(|_| SourceBoundHybridSizingError::AnalysisFailed)?;
        let position = *self
            .positions
            .get(address)
            .ok_or(SourceBoundHybridSizingError::AnalysisFailed)?;
        let entry_index = if position == EMPTY_POSITION {
            let next = u32::try_from(self.entries.len())
                .map_err(|_| SourceBoundHybridSizingError::AllocationFailed)?;
            if next == EMPTY_POSITION {
                return Err(SourceBoundHybridSizingError::AllocationFailed);
            }
            self.entries
                .try_reserve(1)
                .map_err(|_| SourceBoundHybridSizingError::AllocationFailed)?;
            self.entries.push(GenerationEntry {
                address_index,
                add_events: 0,
                spend_events: 0,
            });
            let slot = self
                .positions
                .get_mut(address)
                .ok_or(SourceBoundHybridSizingError::AnalysisFailed)?;
            *slot = next;
            usize::try_from(next).map_err(|_| SourceBoundHybridSizingError::AnalysisFailed)?
        } else {
            usize::try_from(position).map_err(|_| SourceBoundHybridSizingError::AnalysisFailed)?
        };
        let entry = self
            .entries
            .get_mut(entry_index)
            .ok_or(SourceBoundHybridSizingError::AnalysisFailed)?;
        if entry.address_index != address_index {
            return Err(SourceBoundHybridSizingError::AnalysisFailed);
        }
        if is_created {
            entry.add_events = entry
                .add_events
                .checked_add(1)
                .ok_or(SourceBoundHybridSizingError::ArithmeticOverflow)?;
        } else {
            entry.spend_events = entry
                .spend_events
                .checked_add(1)
                .ok_or(SourceBoundHybridSizingError::ArithmeticOverflow)?;
        }
        Ok(())
    }

    fn summarize_and_clear(&mut self) -> Result<GenerationSummary, SourceBoundHybridSizingError> {
        let mut summary = GenerationSummary::empty();
        for entry in &self.entries {
            summary.record(*entry)?;
        }
        for entry in &self.entries {
            let index = usize::try_from(entry.address_index)
                .map_err(|_| SourceBoundHybridSizingError::AnalysisFailed)?;
            let position = self
                .positions
                .get_mut(index)
                .ok_or(SourceBoundHybridSizingError::AnalysisFailed)?;
            *position = EMPTY_POSITION;
        }
        self.entries.clear();
        Ok(summary)
    }
}

#[derive(Clone, Copy)]
struct GenerationEntry {
    address_index: u32,
    add_events: u64,
    spend_events: u64,
}

#[derive(Clone, Copy)]
struct GenerationSummary {
    total_add_events: u64,
    total_spend_events: u64,
    total_delta_events: u64,
    max_per_address_add_events: u64,
    max_per_address_spend_events: u64,
    max_per_address_delta_events: u64,
    page_candidates: [GenerationPageSummary; PAGE_CANDIDATES.len()],
}

impl GenerationSummary {
    const fn empty() -> Self {
        Self {
            total_add_events: 0,
            total_spend_events: 0,
            total_delta_events: 0,
            max_per_address_add_events: 0,
            max_per_address_spend_events: 0,
            max_per_address_delta_events: 0,
            page_candidates: [GenerationPageSummary::EMPTY; PAGE_CANDIDATES.len()],
        }
    }

    fn record(&mut self, entry: GenerationEntry) -> Result<(), SourceBoundHybridSizingError> {
        let delta_events = entry
            .add_events
            .checked_add(entry.spend_events)
            .ok_or(SourceBoundHybridSizingError::ArithmeticOverflow)?;
        self.total_add_events = self
            .total_add_events
            .checked_add(entry.add_events)
            .ok_or(SourceBoundHybridSizingError::ArithmeticOverflow)?;
        self.total_spend_events = self
            .total_spend_events
            .checked_add(entry.spend_events)
            .ok_or(SourceBoundHybridSizingError::ArithmeticOverflow)?;
        self.total_delta_events = self
            .total_delta_events
            .checked_add(delta_events)
            .ok_or(SourceBoundHybridSizingError::ArithmeticOverflow)?;
        self.max_per_address_add_events = self.max_per_address_add_events.max(entry.add_events);
        self.max_per_address_spend_events =
            self.max_per_address_spend_events.max(entry.spend_events);
        self.max_per_address_delta_events = self.max_per_address_delta_events.max(delta_events);
        for (index, entries_per_page) in PAGE_CANDIDATES.into_iter().enumerate() {
            self.page_candidates[index].record(entry, entries_per_page)?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct GenerationPageSummary {
    total_add_pages: u64,
    total_spend_pages: u64,
    total_separate_pages: u64,
    max_per_address_add_pages: u64,
    max_per_address_spend_pages: u64,
    max_per_address_separate_pages: u64,
}

impl GenerationPageSummary {
    const EMPTY: Self = Self {
        total_add_pages: 0,
        total_spend_pages: 0,
        total_separate_pages: 0,
        max_per_address_add_pages: 0,
        max_per_address_spend_pages: 0,
        max_per_address_separate_pages: 0,
    };

    fn record(
        &mut self,
        entry: GenerationEntry,
        entries_per_page: u64,
    ) -> Result<(), SourceBoundHybridSizingError> {
        let add_pages = ceil_div(entry.add_events, entries_per_page)?;
        let spend_pages = ceil_div(entry.spend_events, entries_per_page)?;
        let separate_pages = add_pages
            .checked_add(spend_pages)
            .ok_or(SourceBoundHybridSizingError::ArithmeticOverflow)?;
        self.total_add_pages = self
            .total_add_pages
            .checked_add(add_pages)
            .ok_or(SourceBoundHybridSizingError::ArithmeticOverflow)?;
        self.total_spend_pages = self
            .total_spend_pages
            .checked_add(spend_pages)
            .ok_or(SourceBoundHybridSizingError::ArithmeticOverflow)?;
        self.total_separate_pages = self
            .total_separate_pages
            .checked_add(separate_pages)
            .ok_or(SourceBoundHybridSizingError::ArithmeticOverflow)?;
        self.max_per_address_add_pages = self.max_per_address_add_pages.max(add_pages);
        self.max_per_address_spend_pages = self.max_per_address_spend_pages.max(spend_pages);
        self.max_per_address_separate_pages =
            self.max_per_address_separate_pages.max(separate_pages);
        Ok(())
    }
}

fn build_live_histogram(
    live_utxos: &[u64],
) -> Result<Vec<LiveUtxoBucket>, SourceBoundHybridSizingError> {
    let mut sorted = Vec::new();
    sorted
        .try_reserve_exact(live_utxos.len())
        .map_err(|_| SourceBoundHybridSizingError::AllocationFailed)?;
    sorted.extend_from_slice(live_utxos);
    sorted.sort_unstable();

    let mut histogram: Vec<LiveUtxoBucket> = Vec::new();
    for live in sorted {
        match histogram.last_mut() {
            Some(bucket) if bucket.live_utxos == live => {
                bucket.address_count = bucket
                    .address_count
                    .checked_add(1)
                    .ok_or(SourceBoundHybridSizingError::ArithmeticOverflow)?;
            }
            _ => {
                histogram
                    .try_reserve(1)
                    .map_err(|_| SourceBoundHybridSizingError::AllocationFailed)?;
                histogram.push(LiveUtxoBucket {
                    live_utxos: live,
                    address_count: 1,
                });
            }
        }
    }
    Ok(histogram)
}

fn validate_live_histogram(
    histogram: &[LiveUtxoBucket],
    distinct_standard_addresses: u64,
    final_live_standard_utxos: u64,
) -> Result<(), SourceBoundHybridSizingError> {
    if histogram.is_empty() {
        return Err(SourceBoundHybridSizingError::InvalidReport);
    }
    let mut previous = None;
    let mut addresses = 0_u64;
    let mut live = 0_u64;
    for bucket in histogram {
        if bucket.address_count == 0
            || previous.is_some_and(|previous| bucket.live_utxos <= previous)
        {
            return Err(SourceBoundHybridSizingError::InvalidReport);
        }
        addresses = addresses
            .checked_add(bucket.address_count)
            .ok_or(SourceBoundHybridSizingError::InvalidReport)?;
        live = live
            .checked_add(
                bucket
                    .live_utxos
                    .checked_mul(bucket.address_count)
                    .ok_or(SourceBoundHybridSizingError::InvalidReport)?,
            )
            .ok_or(SourceBoundHybridSizingError::InvalidReport)?;
        previous = Some(bucket.live_utxos);
    }
    if addresses != distinct_standard_addresses || live != final_live_standard_utxos {
        return Err(SourceBoundHybridSizingError::InvalidReport);
    }
    Ok(())
}

fn live_histogram_matches_measurement(
    histogram: &[LiveUtxoBucket],
    measurement: &MainnetCorpusMeasurement,
) -> bool {
    let expected = measurement.live_utxos_per_address();
    histogram.len() == expected.len()
        && histogram
            .iter()
            .zip(expected)
            .all(|(bucket, (live_utxos, address_count))| {
                bucket.live_utxos == *live_utxos && bucket.address_count == *address_count
            })
        && histogram
            .last()
            .is_some_and(|bucket| bucket.live_utxos == measurement.maximum_live_utxos_per_address())
}

fn build_base_page_candidates(
    histogram: &[LiveUtxoBucket],
    final_live_standard_utxos: u64,
) -> Result<Vec<BasePageCandidateReport>, SourceBoundHybridSizingError> {
    let mut reports = Vec::new();
    reports
        .try_reserve_exact(PAGE_CANDIDATES.len())
        .map_err(|_| SourceBoundHybridSizingError::AllocationFailed)?;
    for entries_per_page in PAGE_CANDIDATES {
        let mut base_pages = 0_u64;
        let mut maximum_pages_per_address = 0_u64;
        for bucket in histogram {
            let pages = ceil_div(bucket.live_utxos, entries_per_page)?;
            base_pages = base_pages
                .checked_add(
                    pages
                        .checked_mul(bucket.address_count)
                        .ok_or(SourceBoundHybridSizingError::ArithmeticOverflow)?,
                )
                .ok_or(SourceBoundHybridSizingError::ArithmeticOverflow)?;
            maximum_pages_per_address = maximum_pages_per_address.max(pages);
        }
        let allocated_entries = base_pages
            .checked_mul(entries_per_page)
            .ok_or(SourceBoundHybridSizingError::ArithmeticOverflow)?;
        let padding_entries = allocated_entries
            .checked_sub(final_live_standard_utxos)
            .ok_or(SourceBoundHybridSizingError::AnalysisFailed)?;
        reports.push(BasePageCandidateReport {
            entries_per_page,
            base_pages,
            maximum_pages_per_address,
            allocated_entries,
            live_entries: final_live_standard_utxos,
            padding_entries,
        });
    }
    Ok(reports)
}

fn ceil_div(value: u64, divisor: u64) -> Result<u64, SourceBoundHybridSizingError> {
    if divisor == 0 {
        return Err(SourceBoundHybridSizingError::ArithmeticOverflow);
    }
    let quotient = value / divisor;
    quotient
        .checked_add(u64::from(!value.is_multiple_of(divisor)))
        .ok_or(SourceBoundHybridSizingError::ArithmeticOverflow)
}

#[cfg(test)]
mod tests {
    use super::*;

    use zaino_state::{ScriptType, TxInCompact};

    use crate::{
        canonical_chain::CanonicalNetwork,
        zaino_corpus::MainnetCorpusScanner,
        zaino_fixtures::{indexed_block, output, transaction},
    };

    fn source_fixture(
    ) -> Result<([IndexedBlock; 2], MainnetCorpusMeasurement), Box<dyn std::error::Error>> {
        let genesis_hash = CanonicalNetwork::Mainnet.genesis_hash().0;
        let first_txid = [0x51; 32];
        let first = transaction(
            0,
            first_txid,
            vec![TxInCompact::null_prevout()],
            vec![
                output(10, [0xa1; 20], ScriptType::P2PKH)?,
                output(20, [0xb2; 20], ScriptType::P2SH)?,
            ],
        );
        let second = transaction(
            0,
            [0x52; 32],
            vec![TxInCompact::new(first_txid, 0)],
            vec![output(30, [0xb2; 20], ScriptType::P2SH)?],
        );
        let blocks = [
            indexed_block(0, genesis_hash, [0; 32], vec![first])?,
            indexed_block(1, [0x92; 32], genesis_hash, vec![second])?,
        ];
        let mut scanner = MainnetCorpusScanner::new();
        for block in &blocks {
            scanner.push(block)?;
        }
        Ok((blocks, scanner.finish()?))
    }

    fn source_report(
        blocks: &[IndexedBlock],
        measurement: &MainnetCorpusMeasurement,
    ) -> Result<SourceBoundHybridSizingReport, SourceBoundHybridSizingError> {
        let mut session = SourceBoundHybridSizingSession::start(
            SourceBoundHybridSizingProfile::LiveUtxoBaseDeltaV1,
            measurement,
            &"11".repeat(32),
        )?;
        for block in blocks {
            session.push(block)?;
        }
        session.finish()
    }

    #[test]
    fn live_histogram_keeps_zero_and_base_pages_use_exact_ceils(
    ) -> Result<(), SourceBoundHybridSizingError> {
        let histogram = build_live_histogram(&[0, 1, 8, 9, 9])?;
        assert_eq!(
            histogram,
            vec![
                LiveUtxoBucket {
                    live_utxos: 0,
                    address_count: 1,
                },
                LiveUtxoBucket {
                    live_utxos: 1,
                    address_count: 1,
                },
                LiveUtxoBucket {
                    live_utxos: 8,
                    address_count: 1,
                },
                LiveUtxoBucket {
                    live_utxos: 9,
                    address_count: 2,
                },
            ]
        );
        validate_live_histogram(&histogram, 5, 27)?;
        let reports = build_base_page_candidates(&histogram, 27)?;
        assert_eq!(reports[0].base_pages, 27);
        assert_eq!(reports[1].base_pages, 6);
        assert_eq!(reports[1].allocated_entries, 48);
        assert_eq!(reports[1].padding_entries, 21);
        assert_eq!(reports[2].base_pages, 4);
        assert_eq!(reports[2].maximum_pages_per_address, 1);
        Ok(())
    }

    #[test]
    fn sparse_tracker_sums_per_address_ceils_before_generation_maxima(
    ) -> Result<(), SourceBoundHybridSizingError> {
        let mut interval = RebuildIntervalAccumulator::new(2)?;
        interval.register_address(0)?;
        interval.register_address(1)?;
        for _ in 0..9 {
            interval.record(0, true)?;
        }
        interval.record(1, true)?;
        interval.record(1, false)?;
        let _ = interval.finish_block()?;
        let _ = interval.finish_block()?;

        for _ in 0..8 {
            interval.record(0, false)?;
        }
        let _ = interval.finish_block()?;
        let report = interval.finish()?;

        assert_eq!(report.generation_count, 2);
        assert_eq!(report.trailing_partial_generation_blocks, 1);
        assert_eq!(report.max_total_add_events, 10);
        assert_eq!(report.max_total_spend_events, 8);
        assert_eq!(report.max_total_delta_events, 11);
        assert_eq!(report.max_per_address_delta_events, 9);
        assert_eq!(report.page_candidates[1].entries_per_page, 8);
        assert_eq!(report.page_candidates[1].max_total_add_pages, 3);
        assert_eq!(report.page_candidates[1].max_total_spend_pages, 1);
        assert_eq!(report.page_candidates[1].max_total_separate_pages, 4);
        assert_eq!(report.page_candidates[1].max_per_address_separate_pages, 2);
        Ok(())
    }

    #[test]
    fn sparse_positions_reset_without_scanning_the_registered_domain(
    ) -> Result<(), SourceBoundHybridSizingError> {
        let mut tracker = SparseGenerationTracker::new();
        tracker.register_address(0)?;
        tracker.register_address(1)?;
        tracker.record(1, true)?;
        let first = tracker.summarize_and_clear()?;
        assert_eq!(first.total_add_events, 1);
        assert_eq!(tracker.positions, vec![EMPTY_POSITION, EMPTY_POSITION]);
        assert!(tracker.entries.is_empty());

        tracker.record(1, false)?;
        let second = tracker.summarize_and_clear()?;
        assert_eq!(second.total_spend_events, 1);
        assert_eq!(tracker.positions, vec![EMPTY_POSITION, EMPTY_POSITION]);
        Ok(())
    }

    fn generation_with_events(
        add_events: u64,
        spend_events: u64,
    ) -> Result<GenerationSummary, SourceBoundHybridSizingError> {
        let mut summary = GenerationSummary::empty();
        summary.record(GenerationEntry {
            address_index: 0,
            add_events,
            spend_events,
        })?;
        Ok(summary)
    }

    #[test]
    fn fixed_growth_profile_derives_and_revalidates_absolute_projection(
    ) -> Result<(), SourceBoundHybridSizingError> {
        let observation_blocks = GROWTH_WINDOW_BLOCKS
            .checked_mul(
                u64::try_from(GROWTH_OBSERVATION_WINDOWS)
                    .map_err(|_| SourceBoundHybridSizingError::ArithmeticOverflow)?,
            )
            .ok_or(SourceBoundHybridSizingError::ArithmeticOverflow)?;
        let aligned_end = MAINNET_BLOSSOM_ACTIVATION_HEIGHT
            .div_ceil(u64::from(SELECTED_GENERATION_INTERVAL_BLOCKS))
            .checked_mul(u64::from(SELECTED_GENERATION_INTERVAL_BLOCKS))
            .and_then(|start| start.checked_add(observation_blocks))
            .ok_or(SourceBoundHybridSizingError::ArithmeticOverflow)?;
        let expected_blocks = aligned_end
            .checked_add(151)
            .ok_or(SourceBoundHybridSizingError::ArithmeticOverflow)?;
        let mut accumulator = HistoricalGrowthAccumulator::production(expected_blocks)?;
        let aligned_start = accumulator.aligned_start_applied_blocks;
        let mut live_utxos = vec![16, 16];
        accumulator.observe(
            aligned_start,
            2,
            32,
            &live_utxos,
            Some(GenerationSummary::empty()),
        )?;

        let window_events = [(16, 16), (32, 16), (16, 32), (48, 16), (80, 48)];
        let window_states = [
            vec![32, 16, 1],
            vec![16, 16, 1],
            vec![64, 16, 1, 1],
            vec![80, 16, 1, 1],
            vec![80, 32, 1, 1, 1],
        ];
        let generations_per_window =
            GROWTH_WINDOW_BLOCKS / u64::from(SELECTED_GENERATION_INTERVAL_BLOCKS);
        for (window_index, ((add_events, spend_events), state)) in
            window_events.into_iter().zip(window_states).enumerate()
        {
            for generation_index in 1..=generations_per_window {
                let absolute_generation = u64::try_from(window_index)
                    .map_err(|_| SourceBoundHybridSizingError::ArithmeticOverflow)?
                    .checked_mul(generations_per_window)
                    .and_then(|offset| offset.checked_add(generation_index))
                    .ok_or(SourceBoundHybridSizingError::ArithmeticOverflow)?;
                let applied_blocks = aligned_start
                    .checked_add(
                        absolute_generation
                            .checked_mul(u64::from(SELECTED_GENERATION_INTERVAL_BLOCKS))
                            .ok_or(SourceBoundHybridSizingError::ArithmeticOverflow)?,
                    )
                    .ok_or(SourceBoundHybridSizingError::ArithmeticOverflow)?;
                if generation_index == generations_per_window {
                    live_utxos = state.clone();
                }
                let live_standard_utxos = live_utxos.iter().try_fold(0_u64, |total, live| {
                    total
                        .checked_add(*live)
                        .ok_or(SourceBoundHybridSizingError::ArithmeticOverflow)
                })?;
                accumulator.observe(
                    applied_blocks,
                    u64::try_from(live_utxos.len())
                        .map_err(|_| SourceBoundHybridSizingError::ArithmeticOverflow)?,
                    live_standard_utxos,
                    &live_utxos,
                    Some(generation_with_events(add_events, spend_events)?),
                )?;
            }
        }

        let current = SelectedSizingDemands {
            base_pages: 11,
            add_pages: 5,
            spend_pages: 3,
            maximum_live_utxos_per_address: 96,
            maximum_base_pages_per_address: 6,
            max_per_address_add_pages: 5,
            max_per_address_spend_pages: 3,
        };
        let full_history = RebuildIntervalReport {
            interval_blocks: SELECTED_GENERATION_INTERVAL_BLOCKS,
            generation_count: observation_blocks / u64::from(SELECTED_GENERATION_INTERVAL_BLOCKS)
                + 1,
            trailing_partial_generation_blocks: 151,
            max_total_add_events: 80,
            max_total_spend_events: 48,
            max_total_delta_events: 128,
            max_per_address_add_events: 80,
            max_per_address_spend_events: 48,
            max_per_address_delta_events: 128,
            page_candidates: vec![DeltaPageCandidateReport {
                entries_per_page: SELECTED_PAGE_ENTRIES,
                max_total_add_pages: 5,
                max_total_spend_pages: 3,
                max_total_separate_pages: 8,
                max_per_address_add_pages: 5,
                max_per_address_spend_pages: 3,
                max_per_address_separate_pages: 8,
            }],
        };
        let evidence = accumulator.finish(
            expected_blocks,
            5,
            131,
            current,
            &full_history,
            Some(generation_with_events(32, 16)?),
        )?;
        assert_eq!(
            evidence.maximum_positive_annual_increment,
            GrowthAnnualIncrement {
                distinct_standard_addresses: 1,
                live_standard_utxos: 49,
                base_pages: 4,
                maximum_live_utxos_per_address: 48,
                max_total_add_pages: 2,
                max_total_spend_pages: 2,
                max_per_address_add_pages: 2,
                max_per_address_spend_pages: 2,
            }
        );
        assert_eq!(evidence.projection.distinct_standard_addresses, 8);
        assert_eq!(evidence.projection.live_standard_utxos, 278);
        assert_eq!(evidence.projection.base_pages, 23);
        assert_eq!(evidence.projection.maximum_live_utxos_per_address, 240);
        assert_eq!(evidence.projection.maximum_base_pages_per_address, 15);
        assert_eq!(evidence.projection.max_total_add_pages, 11);
        assert_eq!(evidence.projection.max_total_spend_pages, 9);
        assert_eq!(evidence.projection.fixed_page_reads, 35);
        assert_eq!(
            evidence.projection.qualification_expiry_height,
            u32::try_from(expected_blocks - 1 + GROWTH_WINDOW_BLOCKS)
                .map_err(|_| SourceBoundHybridSizingError::ArithmeticOverflow)?
        );
        assert_eq!(
            evidence.projection.capacity_horizon_end_height,
            u32::try_from(
                expected_blocks - 1 + GROWTH_WINDOW_BLOCKS * u64::from(GROWTH_PROJECTION_WINDOWS)
            )
            .map_err(|_| SourceBoundHybridSizingError::ArithmeticOverflow)?
        );
        let trailing = evidence
            .trailing_partial_generation
            .ok_or(SourceBoundHybridSizingError::InvalidReport)?;
        assert_eq!(trailing.start_applied_blocks, aligned_end);
        assert_eq!(trailing.end_applied_blocks, expected_blocks);
        assert_eq!(trailing.max_total_add_events, 32);
        assert_eq!(trailing.max_total_spend_events, 16);
        assert_eq!(
            select_capacity_demands(
                SourceBoundHybridSizingProfile::LiveUtxoBaseDeltaV1,
                current,
                None,
            )?,
            current
        );
        let projected = select_capacity_demands(
            SourceBoundHybridSizingProfile::LiveUtxoBaseDeltaGrowthV2,
            current,
            Some(&evidence),
        )?;
        assert_eq!(projected.base_pages, 23);
        assert_eq!(projected.add_pages, 11);
        assert_eq!(projected.spend_pages, 9);
        assert_eq!(projected.fixed_page_reads()?, 35);
        evidence.validate(expected_blocks, 5, 131, current, &full_history)?;

        let mut tampered = evidence.clone();
        tampered.projection.base_pages = tampered
            .projection
            .base_pages
            .checked_add(1)
            .ok_or(SourceBoundHybridSizingError::ArithmeticOverflow)?;
        assert_eq!(
            tampered.validate(expected_blocks, 5, 131, current, &full_history),
            Err(SourceBoundHybridSizingError::InvalidReport)
        );

        let mut impossible = evidence.clone();
        impossible.delta_windows[0].max_per_address_add_events = impossible.delta_windows[0]
            .max_total_add_events
            .checked_add(1)
            .ok_or(SourceBoundHybridSizingError::ArithmeticOverflow)?;
        assert_eq!(
            impossible.validate(expected_blocks, 5, 131, current, &full_history),
            Err(SourceBoundHybridSizingError::InvalidReport)
        );

        let mut above_full_history = evidence.clone();
        above_full_history.delta_windows[0].max_total_add_pages = 6;
        above_full_history.delta_windows[0].max_total_separate_pages = 6;
        assert_eq!(
            above_full_history.validate(expected_blocks, 5, 131, current, &full_history),
            Err(SourceBoundHybridSizingError::InvalidReport)
        );

        let mut missing_trailing = evidence;
        missing_trailing.trailing_partial_generation = None;
        assert_eq!(
            missing_trailing.validate(expected_blocks, 5, 131, current, &full_history),
            Err(SourceBoundHybridSizingError::InvalidReport)
        );
        Ok(())
    }

    #[test]
    fn growth_v2_source_and_window_boundaries_are_exactly_pinned(
    ) -> Result<(), SourceBoundHybridSizingError> {
        let source = SourceBinding {
            measurement_blake2s256: GROWTH_V2_MEASUREMENT_BLAKE2S256.to_owned(),
            checkpoint_height: GROWTH_V2_CHECKPOINT_HEIGHT,
            checkpoint_hash: GROWTH_V2_CHECKPOINT_HASH.to_owned(),
            expected_blocks: GROWTH_V2_EXPECTED_BLOCKS,
        };
        assert!(source.validate());
        assert!(source.is_growth_v2_source());

        let accumulator = HistoricalGrowthAccumulator::production(GROWTH_V2_EXPECTED_BLOCKS)?;
        assert_eq!(accumulator.aligned_start_applied_blocks, 1_322_496);
        assert_eq!(accumulator.aligned_end_applied_blocks, 3_424_896);
        assert_eq!(accumulator.checkpoint_trailing_blocks, 151);
        assert_eq!(
            accumulator
                .delta_windows
                .iter()
                .map(|window| (window.start_applied_blocks, window.end_applied_blocks))
                .collect::<Vec<_>>(),
            vec![
                (1_322_496, 1_742_976),
                (1_742_976, 2_163_456),
                (2_163_456, 2_583_936),
                (2_583_936, 3_004_416),
                (3_004_416, 3_424_896),
            ]
        );

        let mut wrong_source = source;
        wrong_source.measurement_blake2s256 = "11".repeat(32);
        assert!(!wrong_source.is_growth_v2_source());
        Ok(())
    }

    #[test]
    fn growth_profile_rejects_a_source_without_five_complete_windows(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (_blocks, measurement) = source_fixture()?;
        assert!(matches!(
            SourceBoundHybridSizingSession::start(
                SourceBoundHybridSizingProfile::LiveUtxoBaseDeltaGrowthV2,
                &measurement,
                &"11".repeat(32),
            ),
            Err(SourceBoundHybridSizingError::InputRejected)
        ));
        Ok(())
    }

    #[test]
    fn report_validation_rejects_overstated_evidence() -> Result<(), SourceBoundHybridSizingError> {
        let histogram = vec![
            LiveUtxoBucket {
                live_utxos: 0,
                address_count: 1,
            },
            LiveUtxoBucket {
                live_utxos: 1,
                address_count: 1,
            },
        ];
        let base_page_candidates = build_base_page_candidates(&histogram, 1)?;
        let mut rebuild_interval_reports = Vec::new();
        for interval_blocks in REBUILD_INTERVALS {
            rebuild_interval_reports.push(RebuildIntervalReport {
                interval_blocks,
                generation_count: 1,
                trailing_partial_generation_blocks: 1,
                max_total_add_events: 1,
                max_total_spend_events: 0,
                max_total_delta_events: 1,
                max_per_address_add_events: 1,
                max_per_address_spend_events: 0,
                max_per_address_delta_events: 1,
                page_candidates: PAGE_CANDIDATES
                    .into_iter()
                    .map(|entries_per_page| DeltaPageCandidateReport {
                        entries_per_page,
                        max_total_add_pages: 1,
                        max_total_spend_pages: 0,
                        max_total_separate_pages: 1,
                        max_per_address_add_pages: 1,
                        max_per_address_spend_pages: 0,
                        max_per_address_separate_pages: 1,
                    })
                    .collect(),
            });
        }
        let mut report = SourceBoundHybridSizingReport {
            scenario: SCENARIO.to_owned(),
            profile: SourceBoundHybridSizingProfile::LiveUtxoBaseDeltaV1,
            source: SourceBinding {
                measurement_blake2s256: "11".repeat(32),
                checkpoint_height: 0,
                checkpoint_hash: "22".repeat(32),
                expected_blocks: 1,
            },
            page_candidates: PAGE_CANDIDATES.to_vec(),
            rebuild_intervals: REBUILD_INTERVALS.to_vec(),
            applied_blocks: 1,
            distinct_standard_addresses: 2,
            created_standard_events: 1,
            spent_standard_events: 0,
            delta_events: 1,
            final_live_standard_utxos: 1,
            maximum_live_standard_utxos: 1,
            live_utxo_histogram: histogram,
            base_page_candidates,
            rebuild_interval_reports,
            historical_growth: None,
            evidence_scope: EVIDENCE_SCOPE_V1,
        };
        report.validate()?;
        report.evidence_scope.target_hardware_qualified = true;
        assert_eq!(
            report.validate(),
            Err(SourceBoundHybridSizingError::InvalidReport)
        );
        Ok(())
    }

    #[test]
    fn exact_source_session_round_trips_and_validates_against_measurement(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (blocks, measurement) = source_fixture()?;
        let report = source_report(&blocks, &measurement)?;

        assert_eq!(
            report.live_utxo_histogram,
            vec![
                LiveUtxoBucket {
                    live_utxos: 0,
                    address_count: 1,
                },
                LiveUtxoBucket {
                    live_utxos: 2,
                    address_count: 1,
                },
            ]
        );
        report.validate_against(&measurement, &"11".repeat(32))?;
        let encoded = serde_json::to_vec(&report)?;
        assert!(!encoded
            .windows(b"historical_growth".len())
            .any(|window| window == b"historical_growth"));
        let decoded: SourceBoundHybridSizingReport = serde_json::from_slice(&encoded)?;
        assert_eq!(decoded, report);
        decoded.validate_against(&measurement, &"11".repeat(32))?;
        assert!(decoded.rebuild_interval_reports.iter().all(|interval| {
            interval.generation_count == 1 && interval.trailing_partial_generation_blocks == 2
        }));
        Ok(())
    }

    #[cfg(all(
        feature = "rostl-experimental",
        target_os = "linux",
        target_arch = "x86_64"
    ))]
    #[test]
    fn selected_tuple_drives_fixed_page_capacity_from_the_validated_report(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (blocks, measurement) = source_fixture()?;
        let report = source_report(&blocks, &measurement)?;
        let lower_bound =
            crate::fixed_page_capacity::derive_fixed_page_capacity_lower_bound(&report)?;

        assert_eq!(lower_bound.fixed_page_reads(), 3);
        assert_eq!(lower_bound.base().logical_records(), 1);
        assert_eq!(lower_bound.base().rounded_capacity(), 2);
        assert_eq!(lower_bound.add().logical_records(), 2);
        assert_eq!(lower_bound.add().rounded_capacity(), 4);
        assert_eq!(lower_bound.spend().logical_records(), 1);
        assert_eq!(lower_bound.spend().rounded_capacity(), 4);
        Ok(())
    }

    #[test]
    fn source_validation_rejects_a_recomputed_but_wrong_base_histogram(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (blocks, measurement) = source_fixture()?;
        let mut report = source_report(&blocks, &measurement)?;
        report.live_utxo_histogram = vec![LiveUtxoBucket {
            live_utxos: 1,
            address_count: 2,
        }];
        report.base_page_candidates = build_base_page_candidates(&report.live_utxo_histogram, 2)?;

        report.validate()?;
        assert_eq!(
            report.validate_against(&measurement, &"11".repeat(32)),
            Err(SourceBoundHybridSizingError::InvalidReport)
        );
        Ok(())
    }

    #[test]
    fn report_validation_rejects_zeroed_delta_generation_maxima(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (blocks, measurement) = source_fixture()?;
        let mut report = source_report(&blocks, &measurement)?;
        let interval = report
            .rebuild_interval_reports
            .first_mut()
            .ok_or("fixed interval report must exist")?;
        interval.max_total_add_events = 0;
        interval.max_total_spend_events = 0;
        interval.max_total_delta_events = 0;
        interval.max_per_address_add_events = 0;
        interval.max_per_address_spend_events = 0;
        interval.max_per_address_delta_events = 0;
        for candidate in &mut interval.page_candidates {
            *candidate = DeltaPageCandidateReport::empty(candidate.entries_per_page);
        }

        assert_eq!(
            report.validate(),
            Err(SourceBoundHybridSizingError::InvalidReport)
        );
        Ok(())
    }
}
