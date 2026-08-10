//! Deterministic recent-snapshot scan-width sizing from replay evidence.
//!
//! ADR 0007 requires every query to perform "a complete fixed-work scan of the
//! bounded non-finalised-state snapshot". The width of that scan is therefore a
//! privacy parameter, not a tuning knob: it is hashed into the profile
//! identifier and it must not vary with the address being queried. This module
//! turns measured replay evidence into that width, or refuses to.
//!
//! # Which statistic sizes the width
//!
//! The recent snapshot is **one flat all-address array**. Conversion appends one
//! slot per standard delta event observed in the recent window, across every
//! address (see `recent_snapshot::zaino`), and fails closed with
//! `CapacityExceeded` when the array is full. The demand it must cover is
//! therefore the *total* delta events in the widest generation of the selected
//! rebuild interval — `max_total_delta_events` — and **not**
//! `max_per_address_delta_events`, which is the wrong marginal for a
//! capacity that is shared by all addresses at once.
//!
//! The statistic is an exact **maximum over generations**, with a growth
//! margin, and deliberately not a quantile. On the finalized side a width below
//! an address's demand costs that one address an extra round trip; here a width
//! below a generation's demand means the generation cannot be published at all,
//! so the service has nothing fresh to serve and stops serving for everyone. A
//! 99.9th-percentile width over the mainnet capture's 11,893 generations still
//! admits roughly twelve unpublishable generations, i.e. twelve outages. There
//! is no partial-credit regime to trade against, so the policy is: cover the
//! maximum, or declare the width unserviceable and change the design.
//!
//! # What makes a width serviceable
//!
//! Per query the engine performs, over a snapshot of `slots` entries:
//!
//! - `store_reads * slots` pairings in `finalized_snapshot_relation`, once per
//!   finalized slot read,
//! - `slots` pairings in the recent-slot sweep, one address comparison each.
//!
//! so the cost is `(store_reads + 1) * slots` — linear in the width, and paid
//! in full by every request including misses. A width is serviceable only when
//! that polynomial fits a stated per-query comparison budget.
//!
//! Two further `slots^2` terms used to sit in this polynomial:
//! `recent_snapshot_is_semantically_valid` and `recent_creation_is_live`. Both
//! read the snapshot and nothing else, so both were hoisted to snapshot
//! publication (see `recent_snapshot::RecentSnapshotScan`) where they are paid
//! once per generation rather than once per query. The engine still sweeps
//! every slot; it just reads their results in `O(1)` per slot.
//!
//! All arithmetic here is integer and checked. No floating point and no
//! hash-map iteration influences a selected width, so a width is reproducible
//! from the same evidence on any host.

use std::fmt;

#[cfg(test)]
use crate::profile::MAINNET_QUERY_SLOTS;
use crate::profile::MAINNET_STORE_READS;

/// Denominator for basis-point margins.
const BASIS_POINTS_DENOMINATOR: u64 = 10_000;

/// Headroom the accepted design point is allowed to grow into.
///
/// This policy accepts up to four times the reviewed design point's per-query
/// cost, which is a stated operational choice rather than a measurement: it
/// bounds how much fixed work a width may add relative to a design point that
/// has already been reviewed. Raising it is a profile change and needs its own
/// justification.
const ACCEPTED_COMPARISON_HEADROOM: u64 = 4;

/// Per-query slot pairings the reviewed 256-slot design point cost.
///
/// `2 * 256^2 + 1028 * 256`, the pre-hoist engine's charge for
/// `MAINNET_QUERY_SLOTS` against `MAINNET_STORE_READS`. Hoisting the two
/// query-independent quadratic terms to publication removed work from the
/// query; it did not change how much per-query work an operator is willing to
/// fund. The budget therefore stays anchored to this reviewed figure, and what
/// rises is the width it admits — which is the entire point of the hoist.
/// `the_reviewed_budget_is_the_pre_hoist_design_point_cost` keeps the
/// arithmetic checkable now that the polynomial no longer reproduces it.
const REVIEWED_DESIGN_POINT_COMPARISONS: u64 = 394_240;

/// Growth margin applied to measured demand before it becomes a width.
///
/// The width is hashed into the profile identifier, so it cannot be raised
/// without minting a new profile and re-attesting. A capture is a point in
/// time; this reserves room for the interval's demand to grow before the
/// profile must be reissued.
const RECENT_SNAPSHOT_GROWTH_MARGIN_BPS: u64 = 2_500;

/// Measured recent-state demand for one rebuild interval.
///
/// Constructed from a validated `SourceBoundHybridSizingReport` interval, or
/// from the committed capture's published figures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct RecentSnapshotDemand {
    interval_blocks: u32,
    max_total_delta_events: u64,
}

impl RecentSnapshotDemand {
    /// Records the widest generation observed for one rebuild interval.
    pub(super) const fn new(interval_blocks: u32, max_total_delta_events: u64) -> Self {
        Self {
            interval_blocks,
            max_total_delta_events,
        }
    }

    /// Returns the rebuild interval this demand was measured over.
    pub(super) const fn interval_blocks(&self) -> u32 {
        self.interval_blocks
    }

    /// Returns the widest generation's total standard delta events.
    pub(super) const fn max_total_delta_events(&self) -> u64 {
        self.max_total_delta_events
    }
}

/// Risk policy converting a measured demand into a fixed scan width.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ScanWidthPolicy {
    store_reads: u64,
    comparison_budget: u64,
    growth_margin_bps: u64,
}

impl ScanWidthPolicy {
    /// Builds a policy from its authoritative dimensions.
    pub(super) const fn new(
        store_reads: u64,
        comparison_budget: u64,
        growth_margin_bps: u64,
    ) -> Result<Self, ScanWidthError> {
        if store_reads == 0 {
            return Err(ScanWidthError::ZeroStoreReads);
        }
        if comparison_budget == 0 {
            return Err(ScanWidthError::ZeroComparisonBudget);
        }
        Ok(Self {
            store_reads,
            comparison_budget,
            growth_margin_bps,
        })
    }

    /// Returns the per-query comparison budget a width must fit.
    pub(super) const fn comparison_budget(&self) -> u64 {
        self.comparison_budget
    }
}

/// A width that both covers the measured demand and fits the budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ServiceableScanWidth {
    slots: u64,
    query_comparisons: u64,
    serviceable_ceiling: u64,
}

impl ServiceableScanWidth {
    /// Returns the fixed scan width in slots.
    pub(super) const fn slots(&self) -> u64 {
        self.slots
    }

    /// Returns the per-query slot pairings this width costs.
    pub(super) const fn query_comparisons(&self) -> u64 {
        self.query_comparisons
    }

    /// Returns the widest width the budget admits at all.
    pub(super) const fn serviceable_ceiling(&self) -> u64 {
        self.serviceable_ceiling
    }
}

/// A demand no width can cover inside the budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct UnserviceableScanWidth {
    required_slots: u64,
    required_query_comparisons: u64,
    serviceable_ceiling: u64,
    comparison_budget: u64,
}

impl UnserviceableScanWidth {
    /// Returns the width the measured demand and margin require.
    pub(super) const fn required_slots(&self) -> u64 {
        self.required_slots
    }

    /// Returns the per-query slot pairings the required width would cost.
    pub(super) const fn required_query_comparisons(&self) -> u64 {
        self.required_query_comparisons
    }

    /// Returns the widest width the budget admits.
    pub(super) const fn serviceable_ceiling(&self) -> u64 {
        self.serviceable_ceiling
    }

    /// Returns how many times over budget the required width is, rounded down.
    pub(super) const fn budget_overrun_factor(&self) -> u64 {
        self.required_query_comparisons / self.comparison_budget
    }
}

/// Outcome of sizing a recent-snapshot scan from evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ScanWidthDecision {
    /// The measured demand fits the per-query budget at this fixed width.
    Serviceable(ServiceableScanWidth),
    /// No fixed width covers the measured demand inside the budget.
    Unserviceable(UnserviceableScanWidth),
}

/// Sizes a fixed recent-snapshot scan width from measured demand.
///
/// Returns [`ScanWidthDecision::Unserviceable`] rather than a truncated width
/// whenever the demand cannot be covered: a width that fails closed on mainnet
/// and a width that no host can execute are both non-answers, and the caller
/// must be able to tell them apart from a real one.
pub(super) fn recent_snapshot_scan_width(
    demand: RecentSnapshotDemand,
    policy: ScanWidthPolicy,
) -> Result<ScanWidthDecision, ScanWidthError> {
    if demand.max_total_delta_events == 0 {
        return Err(ScanWidthError::ZeroDemand);
    }
    let required_slots = apply_growth_margin(demand.max_total_delta_events, policy)?;
    let required_query_comparisons = query_slot_comparisons(required_slots, policy.store_reads)?;
    let serviceable_ceiling = serviceable_slot_ceiling(policy)?;
    if required_query_comparisons <= policy.comparison_budget {
        Ok(ScanWidthDecision::Serviceable(ServiceableScanWidth {
            slots: required_slots,
            query_comparisons: required_query_comparisons,
            serviceable_ceiling,
        }))
    } else {
        Ok(ScanWidthDecision::Unserviceable(UnserviceableScanWidth {
            required_slots,
            required_query_comparisons,
            serviceable_ceiling,
            comparison_budget: policy.comparison_budget,
        }))
    }
}

/// Grows a measured demand by the policy margin, rounding up.
fn apply_growth_margin(
    max_total_delta_events: u64,
    policy: ScanWidthPolicy,
) -> Result<u64, ScanWidthError> {
    let scale = BASIS_POINTS_DENOMINATOR
        .checked_add(policy.growth_margin_bps)
        .ok_or(ScanWidthError::ArithmeticOverflow)?;
    let scaled = max_total_delta_events
        .checked_mul(scale)
        .ok_or(ScanWidthError::ArithmeticOverflow)?;
    let rounded = scaled
        .checked_add(BASIS_POINTS_DENOMINATOR - 1)
        .ok_or(ScanWidthError::ArithmeticOverflow)?;
    Ok(rounded / BASIS_POINTS_DENOMINATOR)
}

/// Returns the per-query slot pairings a scan of `slots` entries costs.
///
/// `(store_reads + 1) * slots`, mirroring the two engine loops that still touch
/// the recent snapshot per query: `finalized_snapshot_relation` once per
/// finalized slot read, and one address comparison per recent slot. The two
/// former `slots^2` terms are now paid once per published generation instead.
fn query_slot_comparisons(slots: u64, store_reads: u64) -> Result<u64, ScanWidthError> {
    store_reads
        .checked_add(1)
        .and_then(|per_slot| per_slot.checked_mul(slots))
        .ok_or(ScanWidthError::ArithmeticOverflow)
}

/// Returns the widest width whose per-query cost fits the policy budget.
///
/// Integer bisection over a monotonically increasing cost, so the result is
/// exact and reproducible without floating point.
fn serviceable_slot_ceiling(policy: ScanWidthPolicy) -> Result<u64, ScanWidthError> {
    if query_slot_comparisons(1, policy.store_reads)? > policy.comparison_budget {
        return Err(ScanWidthError::BudgetBelowMinimumWidth);
    }
    let mut low = 1_u64;
    // `store_reads >= 1` makes the per-slot charge at least two, so an
    // admissible width never exceeds half the budget; the budget itself is
    // always an upper bound and the search cannot overflow.
    let mut high = policy.comparison_budget;
    while low < high {
        let midpoint = low
            .checked_add(
                high.checked_sub(low)
                    .ok_or(ScanWidthError::SearchInvariant)?
                    / 2
                    + 1,
            )
            .ok_or(ScanWidthError::ArithmeticOverflow)?;
        if query_slot_comparisons(midpoint, policy.store_reads)? <= policy.comparison_budget {
            low = midpoint;
        } else {
            high = midpoint
                .checked_sub(1)
                .ok_or(ScanWidthError::SearchInvariant)?;
        }
    }
    Ok(low)
}

/// One bucket of the per-address delta-event distribution.
///
/// This is the marginal `SourceBoundHybridSizingReport` records: for each
/// observed count, how many (address, generation) pairs saw exactly that many
/// delta events. It cannot size the shared scan array, but it is exactly the
/// right evidence for how many round trips an address's recent results take.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct DeltaEventObservation {
    delta_events: u64,
    address_count: u64,
}

impl DeltaEventObservation {
    /// Records one bucket of the per-address delta-event distribution.
    pub(super) const fn new(delta_events: u64, address_count: u64) -> Self {
        Self {
            delta_events,
            address_count,
        }
    }
}

/// How much of the per-address population one response width serves in full.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct PaginationCoverage {
    covered_addresses: u64,
    total_addresses: u64,
    coverage_basis_points: u64,
    maximum_delta_events: u64,
}

impl PaginationCoverage {
    /// Returns the (address, generation) pairs fully served in one round trip.
    pub(super) const fn covered_addresses(&self) -> u64 {
        self.covered_addresses
    }

    /// Returns the total (address, generation) pairs in the distribution.
    pub(super) const fn total_addresses(&self) -> u64 {
        self.total_addresses
    }

    /// Returns the covered fraction in basis points, rounded down.
    pub(super) const fn coverage_basis_points(&self) -> u64 {
        self.coverage_basis_points
    }

    /// Returns the largest per-address delta-event count observed.
    pub(super) const fn maximum_delta_events(&self) -> u64 {
        self.maximum_delta_events
    }
}

/// Measures how much of a per-address distribution a response width covers.
///
/// The distribution must be ascending by `delta_events` with no empty buckets,
/// which is the order and shape the sizing report validates and serializes, so
/// the traversal is deterministic without sorting.
pub(super) fn per_address_pagination_coverage(
    distribution: &[DeltaEventObservation],
    response_slots: u64,
) -> Result<PaginationCoverage, ScanWidthError> {
    if distribution.is_empty() {
        return Err(ScanWidthError::UnmeasuredDistribution);
    }
    if response_slots == 0 {
        return Err(ScanWidthError::ZeroResponseSlots);
    }
    let mut previous: Option<u64> = None;
    let mut covered_addresses = 0_u64;
    let mut total_addresses = 0_u64;
    for bucket in distribution {
        if bucket.delta_events == 0 || bucket.address_count == 0 {
            return Err(ScanWidthError::MalformedDistribution);
        }
        if previous.is_some_and(|previous| bucket.delta_events <= previous) {
            return Err(ScanWidthError::MalformedDistribution);
        }
        total_addresses = total_addresses
            .checked_add(bucket.address_count)
            .ok_or(ScanWidthError::ArithmeticOverflow)?;
        if bucket.delta_events <= response_slots {
            covered_addresses = covered_addresses
                .checked_add(bucket.address_count)
                .ok_or(ScanWidthError::ArithmeticOverflow)?;
        }
        previous = Some(bucket.delta_events);
    }
    let maximum_delta_events = previous.ok_or(ScanWidthError::UnmeasuredDistribution)?;
    let coverage_basis_points = covered_addresses
        .checked_mul(BASIS_POINTS_DENOMINATOR)
        .ok_or(ScanWidthError::ArithmeticOverflow)?
        / total_addresses;
    Ok(PaginationCoverage {
        covered_addresses,
        total_addresses,
        coverage_basis_points,
        maximum_delta_events,
    })
}

/// Widest generation of the selected 288-block interval in the Gate 1 capture.
///
/// Published by `docs/evidence/oram/gate1/hybrid-mainnet-2316644-h3425046-v1/`
/// at mainnet height 3,425,046:
/// `rebuild_interval=blocks:288,generations:11893,...,max_total_delta_events:1386025`.
pub(super) const MAINNET_CAPTURE_MAX_TOTAL_DELTA_EVENTS: u64 = 1_386_025;

/// The 288-block interval the hybrid sizing report selects.
pub(super) const MAINNET_CAPTURE_INTERVAL_BLOCKS: u32 = 288;

/// Returns the risk policy the mainnet profile is sized under.
pub(super) fn mainnet_scan_width_policy() -> Result<ScanWidthPolicy, ScanWidthError> {
    let store_reads =
        u64::try_from(MAINNET_STORE_READS).map_err(|_| ScanWidthError::PolicyInput)?;
    let comparison_budget = REVIEWED_DESIGN_POINT_COMPARISONS
        .checked_mul(ACCEPTED_COMPARISON_HEADROOM)
        .ok_or(ScanWidthError::ArithmeticOverflow)?;
    ScanWidthPolicy::new(
        store_reads,
        comparison_budget,
        RECENT_SNAPSHOT_GROWTH_MARGIN_BPS,
    )
}

/// Sizes the mainnet recent-snapshot scan from the committed Gate 1 capture.
///
/// This is the evidence path the profile's width must justify itself against.
/// It currently returns [`ScanWidthDecision::Unserviceable`]; see
/// `docs/notes/recent-snapshot-scan-width.md`.
pub(super) fn mainnet_recent_snapshot_scan_width() -> Result<ScanWidthDecision, ScanWidthError> {
    recent_snapshot_scan_width(
        RecentSnapshotDemand::new(
            MAINNET_CAPTURE_INTERVAL_BLOCKS,
            MAINNET_CAPTURE_MAX_TOTAL_DELTA_EVENTS,
        ),
        mainnet_scan_width_policy()?,
    )
}

/// One typed failure from recent-snapshot scan-width sizing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ScanWidthError {
    /// A policy declared no finalized store reads.
    ZeroStoreReads,
    /// A policy declared no per-query comparison budget.
    ZeroComparisonBudget,
    /// The budget cannot fund even a single scanned slot.
    BudgetBelowMinimumWidth,
    /// The evidence recorded no delta events to size against.
    ZeroDemand,
    /// A distribution was empty, meaning unmeasured rather than absent.
    UnmeasuredDistribution,
    /// A distribution was not strictly ascending or held an empty bucket.
    MalformedDistribution,
    /// A coverage query supplied no response slots.
    ZeroResponseSlots,
    /// A compiled profile dimension did not fit the sizing domain.
    PolicyInput,
    /// A checked sizing computation overflowed.
    ArithmeticOverflow,
    /// The width bisection left its own invariant.
    SearchInvariant,
}

impl fmt::Display for ScanWidthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroStoreReads => f.write_str("scan-width policy declares no store reads"),
            Self::ZeroComparisonBudget => {
                f.write_str("scan-width policy declares no comparison budget")
            }
            Self::BudgetBelowMinimumWidth => {
                f.write_str("scan-width budget cannot fund a single scanned slot")
            }
            Self::ZeroDemand => f.write_str("scan-width evidence records no delta events"),
            Self::UnmeasuredDistribution => {
                f.write_str("per-address delta distribution is unmeasured")
            }
            Self::MalformedDistribution => {
                f.write_str("per-address delta distribution is not strictly ascending")
            }
            Self::ZeroResponseSlots => f.write_str("coverage query supplied no response slots"),
            Self::PolicyInput => {
                f.write_str("compiled profile dimension exceeds the sizing domain")
            }
            Self::ArithmeticOverflow => f.write_str("scan-width computation overflowed"),
            Self::SearchInvariant => f.write_str("scan-width bisection left its invariant"),
        }
    }
}

impl std::error::Error for ScanWidthError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(store_reads: u64, comparison_budget: u64) -> ScanWidthPolicy {
        ScanWidthPolicy::new(store_reads, comparison_budget, 0)
            .expect("test policy declares non-zero store reads and budget")
    }

    #[test]
    fn cost_polynomial_mirrors_the_two_remaining_per_query_engine_loops() {
        // (4 + 1) * 8, linear in the width now that the two snapshot-only
        // quadratic terms are paid at publication.
        assert_eq!(
            query_slot_comparisons(8, 4).expect("small width does not overflow"),
            40
        );
    }

    /// The hoisted terms are gone from the per-query polynomial, not renamed.
    #[test]
    fn the_polynomial_is_linear_in_the_scan_width() {
        let single = query_slot_comparisons(1, 1_028).expect("no overflow");
        for width in [2_u64, 16, 1_024, 1_000_000] {
            assert_eq!(
                query_slot_comparisons(width, 1_028).expect("no overflow"),
                single * width
            );
        }
    }

    #[test]
    fn ceiling_is_the_largest_width_inside_the_budget() {
        let policy = policy(4, 40);
        let ceiling = serviceable_slot_ceiling(policy).expect("budget funds at least one slot");
        assert_eq!(ceiling, 8);
        assert!(query_slot_comparisons(ceiling, 4).expect("no overflow") <= 40);
        assert!(query_slot_comparisons(ceiling + 1, 4).expect("no overflow") > 40);
    }

    #[test]
    fn ceiling_rejects_a_budget_below_one_slot() {
        assert_eq!(
            serviceable_slot_ceiling(policy(4, 4)),
            Err(ScanWidthError::BudgetBelowMinimumWidth)
        );
    }

    #[test]
    fn growth_margin_rounds_up() {
        let policy = ScanWidthPolicy::new(4, 1_000_000, 2_500).expect("valid policy");
        assert_eq!(apply_growth_margin(3, policy).expect("no overflow"), 4);
        assert_eq!(apply_growth_margin(100, policy).expect("no overflow"), 125);
    }

    #[test]
    fn a_demand_inside_the_budget_is_serviceable() {
        let decision = recent_snapshot_scan_width(
            RecentSnapshotDemand::new(288, 8),
            ScanWidthPolicy::new(4, 40, 0).expect("valid policy"),
        )
        .expect("sizing succeeds");
        let ScanWidthDecision::Serviceable(width) = decision else {
            panic!("a demand of 8 slots fits a budget that funds 8 slots");
        };
        assert_eq!(width.slots(), 8);
        assert_eq!(width.query_comparisons(), 40);
        assert_eq!(width.serviceable_ceiling(), 8);
    }

    /// The core regression #105 asks for: the width tracks the evidence.
    #[test]
    fn a_larger_measured_generation_selects_a_larger_width() {
        let policy = ScanWidthPolicy::new(4, 1_000_000, 0).expect("valid policy");
        let narrow = recent_snapshot_scan_width(RecentSnapshotDemand::new(288, 8), policy)
            .expect("sizing succeeds");
        let wide = recent_snapshot_scan_width(RecentSnapshotDemand::new(288, 64), policy)
            .expect("sizing succeeds");
        let (
            ScanWidthDecision::Serviceable(narrow_width),
            ScanWidthDecision::Serviceable(wide_width),
        ) = (narrow, wide)
        else {
            panic!("both demands fit a one-million-comparison budget");
        };
        assert_eq!(narrow_width.slots(), 8);
        assert_eq!(wide_width.slots(), 64);
        assert!(wide_width.query_comparisons() > narrow_width.query_comparisons());
    }

    /// The other half of the same regression: evidence can also refuse a width.
    #[test]
    fn a_generation_past_the_ceiling_is_refused_rather_than_truncated() {
        let policy = ScanWidthPolicy::new(4, 40, 0).expect("valid policy");
        let decision = recent_snapshot_scan_width(RecentSnapshotDemand::new(288, 9), policy)
            .expect("sizing succeeds");
        let ScanWidthDecision::Unserviceable(refusal) = decision else {
            panic!("a demand of 9 slots does not fit a budget that funds 8");
        };
        assert_eq!(refusal.required_slots(), 9);
        assert_eq!(refusal.serviceable_ceiling(), 8);
        // Refusal reports the demand, never a truncated servable width.
        assert!(refusal.required_slots() > refusal.serviceable_ceiling());
    }

    #[test]
    fn a_demand_reports_the_interval_it_was_measured_over() {
        let demand = RecentSnapshotDemand::new(288, 1_386_025);
        assert_eq!(demand.interval_blocks(), 288);
        assert_eq!(demand.max_total_delta_events(), 1_386_025);
    }

    #[test]
    fn zero_demand_is_rejected_rather_than_sized_to_nothing() {
        assert_eq!(
            recent_snapshot_scan_width(RecentSnapshotDemand::new(288, 0), policy(4, 160)),
            Err(ScanWidthError::ZeroDemand)
        );
    }

    #[test]
    fn sizing_is_reproducible_for_identical_evidence() {
        let demand = RecentSnapshotDemand::new(288, 1_000);
        let policy = ScanWidthPolicy::new(1_028, 1_000_000_000, 2_500).expect("valid policy");
        let first = recent_snapshot_scan_width(demand, policy).expect("sizing succeeds");
        for _ in 0..8 {
            assert_eq!(
                recent_snapshot_scan_width(demand, policy).expect("sizing succeeds"),
                first
            );
        }
    }

    /// The committed mainnet capture does not admit a serviceable width.
    ///
    /// This test is the evidence link #105 asks for. It fails the moment the
    /// capture, the cost polynomial, or the accepted headroom changes enough to
    /// make the mainnet recent-snapshot scan servable, at which point the
    /// profile's width can finally be derived rather than asserted.
    #[test]
    fn the_committed_mainnet_capture_is_unserviceable() {
        let decision = mainnet_recent_snapshot_scan_width().expect("mainnet sizing succeeds");
        let ScanWidthDecision::Unserviceable(refusal) = decision else {
            panic!("the Gate 1 capture's 1,386,025-event generation cannot be scanned per query");
        };
        // 1,386,025 grown by 25%.
        assert_eq!(refusal.required_slots(), 1_732_532);
        // The budget funds roughly fifteen hundred slots, not roughly two
        // million. Hoisting the two snapshot-only quadratic terms raised this
        // from 667; it did not close a gap three orders of magnitude wide.
        assert_eq!(refusal.serviceable_ceiling(), 1_532);
        // 1,732,532 * 1029.
        assert_eq!(refusal.required_query_comparisons(), 1_782_775_428);
        // Three orders of magnitude over budget, not a tuning gap.
        assert_eq!(refusal.budget_overrun_factor(), 1_130);
    }

    /// The width the profile actually ships is inside the budget it declares.
    #[test]
    fn the_accepted_mainnet_width_is_inside_its_own_budget() {
        let policy = mainnet_scan_width_policy().expect("mainnet policy is well formed");
        let accepted = u64::try_from(MAINNET_QUERY_SLOTS).expect("accepted width fits u64");
        let ceiling = serviceable_slot_ceiling(policy).expect("budget funds at least one slot");
        // Four times the 394,240 pairings the reviewed design point cost.
        assert_eq!(policy.comparison_budget(), 1_576_960);
        // 1,576,960 / 1029, up from 667 before the hoist.
        assert_eq!(ceiling, 1_532);
        assert!(accepted <= ceiling);
    }

    /// The frozen budget is still the reviewed design point's own cost.
    ///
    /// The per-query polynomial no longer reproduces this figure, so the
    /// arithmetic that justifies the constant is asserted here instead of
    /// being recomputed in production.
    #[test]
    fn the_reviewed_budget_is_the_pre_hoist_design_point_cost() {
        let slots = u64::try_from(MAINNET_QUERY_SLOTS).expect("accepted width fits u64");
        let store_reads = u64::try_from(MAINNET_STORE_READS).expect("store reads fit u64");
        assert_eq!(
            2 * slots * slots + store_reads * slots,
            REVIEWED_DESIGN_POINT_COMPARISONS
        );
    }

    #[test]
    fn coverage_counts_only_buckets_the_width_serves_in_full() {
        let distribution = [
            DeltaEventObservation::new(1, 900),
            DeltaEventObservation::new(4, 90),
            DeltaEventObservation::new(4_096, 10),
        ];
        let coverage =
            per_address_pagination_coverage(&distribution, 4).expect("coverage succeeds");
        assert_eq!(coverage.covered_addresses(), 990);
        assert_eq!(coverage.total_addresses(), 1_000);
        assert_eq!(coverage.coverage_basis_points(), 9_900);
        assert_eq!(coverage.maximum_delta_events(), 4_096);
    }

    /// Shifting mass into the tail moves the measured coverage, so the response
    /// width is answerable from the distribution rather than from a constant.
    #[test]
    fn a_heavier_tail_lowers_measured_coverage() {
        let light = [
            DeltaEventObservation::new(1, 990),
            DeltaEventObservation::new(4_096, 10),
        ];
        let heavy = [
            DeltaEventObservation::new(1, 500),
            DeltaEventObservation::new(4_096, 500),
        ];
        let light_coverage = per_address_pagination_coverage(&light, 4).expect("coverage succeeds");
        let heavy_coverage = per_address_pagination_coverage(&heavy, 4).expect("coverage succeeds");
        assert_eq!(light_coverage.coverage_basis_points(), 9_900);
        assert_eq!(heavy_coverage.coverage_basis_points(), 5_000);
        assert!(heavy_coverage.coverage_basis_points() < light_coverage.coverage_basis_points());
    }

    #[test]
    fn an_unmeasured_distribution_is_not_treated_as_full_coverage() {
        assert_eq!(
            per_address_pagination_coverage(&[], 256),
            Err(ScanWidthError::UnmeasuredDistribution)
        );
    }

    #[test]
    fn a_descending_distribution_is_rejected() {
        let distribution = [
            DeltaEventObservation::new(4, 1),
            DeltaEventObservation::new(1, 1),
        ];
        assert_eq!(
            per_address_pagination_coverage(&distribution, 4),
            Err(ScanWidthError::MalformedDistribution)
        );
    }

    #[test]
    fn an_empty_bucket_is_rejected() {
        let distribution = [
            DeltaEventObservation::new(1, 1),
            DeltaEventObservation::new(4, 0),
        ];
        assert_eq!(
            per_address_pagination_coverage(&distribution, 4),
            Err(ScanWidthError::MalformedDistribution)
        );
    }
}
