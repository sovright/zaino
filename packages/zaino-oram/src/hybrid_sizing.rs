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

use crate::{
    target_load::is_blake2s256_hex,
    zaino_corpus::{MainnetCorpusMeasurement, MainnetCorpusScanner},
};

const SCENARIO: &str = "source-bound-hybrid-sizing-v1";
const PAGE_CANDIDATES: [u64; 3] = [1, 8, 16];
const REBUILD_INTERVALS: [u32; 3] = [288, 1_152, 8_064];
const EMPTY_POSITION: u32 = u32::MAX;

/// Fixed source-bound hybrid-sizing profile selected by the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SourceBoundHybridSizingProfile {
    /// Final live-UTXO base plus genesis-aligned separate add/spend deltas.
    LiveUtxoBaseDeltaV1,
}

impl SourceBoundHybridSizingProfile {
    /// Returns the stable artifact label for this profile.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LiveUtxoBaseDeltaV1 => "live-utxo-base-delta-v1",
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

const EVIDENCE_SCOPE: EvidenceScope = EvidenceScope {
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
    evidence_scope: EvidenceScope,
}

impl SourceBoundHybridSizingReport {
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
        if self.scenario != SCENARIO
            || self.profile != SourceBoundHybridSizingProfile::LiveUtxoBaseDeltaV1
            || !self.source.validate()
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
            || self.evidence_scope != EVIDENCE_SCOPE
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
        write!(
            f,
            "nonclaims=projected-growth,oram-layout-selection,insertion-failure-bound,probabilistic-failure-bound,worst-case-bound,individual-generation-publication,physical-oram-trace,backend-calibration,rss,latency,stash,recovery,target-hardware,tdx,mainnet-readiness"
        )
    }
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
    failed_closed: bool,
}

impl SourceBoundHybridSizingSession {
    /// Validates the capture and starts the fixed hybrid-sizing profile.
    pub fn start(
        profile: SourceBoundHybridSizingProfile,
        measurement: &MainnetCorpusMeasurement,
        measurement_blake2s256: &str,
    ) -> Result<Self, SourceBoundHybridSizingError> {
        if profile != SourceBoundHybridSizingProfile::LiveUtxoBaseDeltaV1 {
            return Err(SourceBoundHybridSizingError::InputRejected);
        }
        let source = SourceBinding::from_measurement(measurement, measurement_blake2s256)?;
        let mut intervals = Vec::new();
        intervals
            .try_reserve_exact(REBUILD_INTERVALS.len())
            .map_err(|_| SourceBoundHybridSizingError::AllocationFailed)?;
        for interval in REBUILD_INTERVALS {
            intervals.push(RebuildIntervalAccumulator::new(interval)?);
        }
        Ok(Self {
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
        for interval in &mut self.intervals {
            if let Err(error) = interval.finish_block() {
                self.fail_closed();
                return Err(error);
            }
        }
        self.applied_blocks = self
            .applied_blocks
            .checked_add(1)
            .ok_or(SourceBoundHybridSizingError::ArithmeticOverflow)?;
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
        for interval in self.intervals {
            rebuild_interval_reports.push(interval.finish()?);
        }
        let delta_events = self
            .created_standard_events
            .checked_add(self.spent_standard_events)
            .ok_or(SourceBoundHybridSizingError::ArithmeticOverflow)?;
        let report = SourceBoundHybridSizingReport {
            scenario: SCENARIO.to_owned(),
            profile: SourceBoundHybridSizingProfile::LiveUtxoBaseDeltaV1,
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
            evidence_scope: EVIDENCE_SCOPE,
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

    fn finish_block(&mut self) -> Result<(), SourceBoundHybridSizingError> {
        self.current_generation_blocks = self
            .current_generation_blocks
            .checked_add(1)
            .ok_or(SourceBoundHybridSizingError::ArithmeticOverflow)?;
        if self.current_generation_blocks == self.interval_blocks {
            self.finish_generation()?;
        } else if self.current_generation_blocks > self.interval_blocks {
            return Err(SourceBoundHybridSizingError::AnalysisFailed);
        }
        Ok(())
    }

    fn finish(mut self) -> Result<RebuildIntervalReport, SourceBoundHybridSizingError> {
        let trailing_partial_generation_blocks = self.current_generation_blocks;
        if trailing_partial_generation_blocks > 0 {
            self.finish_generation()?;
        }
        Ok(RebuildIntervalReport {
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
        })
    }

    fn finish_generation(&mut self) -> Result<(), SourceBoundHybridSizingError> {
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
        Ok(())
    }
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
        interval.finish_block()?;
        interval.finish_block()?;

        for _ in 0..8 {
            interval.record(0, false)?;
        }
        interval.finish_block()?;
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
            evidence_scope: EVIDENCE_SCOPE,
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
        let decoded: SourceBoundHybridSizingReport = serde_json::from_slice(&encoded)?;
        assert_eq!(decoded, report);
        decoded.validate_against(&measurement, &"11".repeat(32))?;
        assert!(decoded.rebuild_interval_reports.iter().all(|interval| {
            interval.generation_count == 1 && interval.trailing_partial_generation_blocks == 2
        }));
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
