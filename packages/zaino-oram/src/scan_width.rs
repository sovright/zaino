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
//! so the shipped cost is `(store_reads + 1) * slots` — linear in the width,
//! and paid in full by every request including misses. A width is serviceable
//! only when that polynomial fits a stated per-query comparison budget.
//!
//! Two further `slots^2` terms used to sit in this polynomial:
//! `recent_snapshot_is_semantically_valid` and `recent_creation_is_live`. Both
//! read the snapshot and nothing else, so both were hoisted to snapshot
//! publication (see `recent_snapshot::RecentSnapshotScan`) where they are paid
//! once per generation rather than once per query. The engine still sweeps
//! every slot; it just reads their results in `O(1)` per slot.
//!
//! # The two joins the argument turns on
//!
//! [`JoinStrategy`] names both design points so the distance between them is a
//! computed number rather than a claim in prose:
//!
//! - [`JoinStrategy::NestedLoopRelation`] is the shipped engine, above.
//! - [`JoinStrategy::AnnotatedRecords`] is the record-annotation hoist, in
//!   which each published recent record already carries the join's answer and
//!   a finalized slot read consumes it in `O(1)`, costing `slots + store_reads`.
//!
//! The hoist is *not implemented and is not implementable here*: `UniqueTable`
//! exposes `capacity`, `read`, `occupied_records` and `insert_unique` and no
//! update primitive, and the store folds records from an append-only event
//! history, so there is nothing to annotate a published record with. It is
//! modelled rather than built because the sizing verdict turns entirely on it,
//! and a model that cannot state the alternative cannot state the verdict.
//!
//! Whether the hoist is even affordable is a *publication*-side question, not a
//! query-side one: see [`AnnotationPublicationBudget`], which decides whether
//! one annotation pass fits inside the rebuild interval it must complete in.
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

/// Zcash post-Blossom target block spacing, in seconds.
///
/// Fixes how much wall clock a rebuild interval of `n` blocks corresponds to,
/// which is the window one annotation pass would have to complete inside.
const TARGET_BLOCK_SPACING_SECONDS: u64 = 75;

/// Conservative stand-in for one oblivious store operation, in nanoseconds.
///
/// The slowest median `insert_record_unique` the Phase 0 session measured —
/// `cost_model::MEASURED_EVENT_INSERTION_NS` at a `2^14` event table. Two
/// things make it a *reference point* and not a mainnet measurement: it times
/// an insertion, which over-charges a read, and the mainnet tables are far past
/// `2^14`, where the measured curve does not reach. It is threaded through
/// [`AnnotationPublicationBudget`] as data rather than assumed inside it,
/// precisely so a real figure replaces it without touching the model.
const REFERENCE_OBLIVIOUS_OPERATION_NANOS: u64 = 17_184;

/// Which finalized/recent join a per-query cost is computed for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum JoinStrategy {
    /// The shipped engine: `finalized_snapshot_relation` re-scans the whole
    /// recent snapshot once per finalized slot read, so the recent side costs
    /// `store_reads * slots`, plus `slots` for the recent-slot sweep.
    NestedLoopRelation,
    /// The record-annotation hoist: each published recent record carries the
    /// join's answer, so a finalized slot read consumes it in `O(1)` and the
    /// per-query cost falls to `slots + store_reads`.
    ///
    /// Modelled, not implemented, and not implementable against the current
    /// store — see the module documentation.
    AnnotatedRecords,
}

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

    /// Returns the finalized store reads one query performs.
    pub(super) const fn store_reads(&self) -> u64 {
        self.store_reads
    }

    /// Returns the growth margin applied to measured demand, in basis points.
    pub(super) const fn growth_margin_bps(&self) -> u64 {
        self.growth_margin_bps
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
    ///
    /// Useful while the gap is orders of magnitude wide, and useless once it is
    /// not: a refusal 9.9% over budget reports a factor of 1. Read
    /// [`Self::budget_excess_basis_points`] for gaps inside one multiple.
    pub(super) const fn budget_overrun_factor(&self) -> u64 {
        self.required_query_comparisons / self.comparison_budget
    }

    /// Returns how far past the budget the required width is, in basis points.
    ///
    /// `0` means exactly on budget and `993` means 9.93% over, so this is the
    /// resolution at which a residual gap can actually be argued about.
    pub(super) fn budget_excess_basis_points(&self) -> Result<u64, ScanWidthError> {
        self.required_query_comparisons
            .saturating_sub(self.comparison_budget)
            .checked_mul(BASIS_POINTS_DENOMINATOR)
            .ok_or(ScanWidthError::ArithmeticOverflow)
            .map(|excess| excess / self.comparison_budget)
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
    join: JoinStrategy,
) -> Result<ScanWidthDecision, ScanWidthError> {
    if demand.max_total_delta_events == 0 {
        return Err(ScanWidthError::ZeroDemand);
    }
    let required_slots = apply_growth_margin(demand.max_total_delta_events, policy)?;
    let required_query_comparisons =
        query_slot_comparisons(required_slots, policy.store_reads, join)?;
    let serviceable_ceiling = serviceable_slot_ceiling(policy, join)?;
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
/// Under [`JoinStrategy::NestedLoopRelation`] this is `(store_reads + 1) *
/// slots`, mirroring the two engine loops that still touch the recent snapshot
/// per query: `finalized_snapshot_relation` once per finalized slot read, and
/// one address comparison per recent slot. The two former `slots^2` terms are
/// now paid once per published generation instead.
///
/// Under [`JoinStrategy::AnnotatedRecords`] the first loop collapses to one
/// `O(1)` annotation lookup per finalized slot read, leaving `slots +
/// store_reads`.
///
/// Both arms are monotonically non-decreasing in `slots`, which is what lets
/// [`serviceable_slot_ceiling`] bisect them.
fn query_slot_comparisons(
    slots: u64,
    store_reads: u64,
    join: JoinStrategy,
) -> Result<u64, ScanWidthError> {
    match join {
        JoinStrategy::NestedLoopRelation => store_reads
            .checked_add(1)
            .and_then(|per_slot| per_slot.checked_mul(slots))
            .ok_or(ScanWidthError::ArithmeticOverflow),
        JoinStrategy::AnnotatedRecords => slots
            .checked_add(store_reads)
            .ok_or(ScanWidthError::ArithmeticOverflow),
    }
}

/// Returns the widest width whose per-query cost fits the policy budget.
///
/// Integer bisection over a monotonically increasing cost, so the result is
/// exact and reproducible without floating point.
fn serviceable_slot_ceiling(
    policy: ScanWidthPolicy,
    join: JoinStrategy,
) -> Result<u64, ScanWidthError> {
    if query_slot_comparisons(1, policy.store_reads, join)? > policy.comparison_budget {
        return Err(ScanWidthError::BudgetBelowMinimumWidth);
    }
    let mut low = 1_u64;
    // Every arm charges at least one pairing per slot, so no admissible width
    // exceeds the budget itself; the budget is always a valid upper bound and
    // the search cannot overflow.
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
        if query_slot_comparisons(midpoint, policy.store_reads, join)? <= policy.comparison_budget {
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

/// Returns the demand the committed Gate 1 capture publishes.
pub(super) const fn mainnet_recent_snapshot_demand() -> RecentSnapshotDemand {
    RecentSnapshotDemand::new(
        MAINNET_CAPTURE_INTERVAL_BLOCKS,
        MAINNET_CAPTURE_MAX_TOTAL_DELTA_EVENTS,
    )
}

/// Sizes the mainnet recent-snapshot scan under the shipped engine.
///
/// This is the evidence path the profile's width must justify itself against.
/// It currently returns [`ScanWidthDecision::Unserviceable`]; see
/// `docs/notes/recent-snapshot-scan-width.md`.
pub(super) fn mainnet_recent_snapshot_scan_width() -> Result<ScanWidthDecision, ScanWidthError> {
    recent_snapshot_scan_width(
        mainnet_recent_snapshot_demand(),
        mainnet_scan_width_policy()?,
        JoinStrategy::NestedLoopRelation,
    )
}

/// Builds the complete mainnet sizing argument from the committed capture.
///
/// One value carrying the per-query cost and ceiling under both joins, the
/// demand, and the verdict. Every published figure in
/// `docs/notes/recent-snapshot-scan-width.md` is derivable from it.
pub(super) fn mainnet_sizing_model() -> Result<RecentSnapshotSizingModel, ScanWidthError> {
    RecentSnapshotSizingModel::new(
        mainnet_recent_snapshot_demand(),
        mainnet_scan_width_policy()?,
    )
}

/// Smallest whole multiple of `reviewed_design_point` that funds `required`.
///
/// Lever one of the two that can close a residual gap: fund more fixed work per
/// query by raising [`ACCEPTED_COMPARISON_HEADROOM`]. The result is expressed
/// in reviewed design points because that is the unit the constant is stated
/// in, so it reads as "how many already-reviewed design points would an
/// operator be agreeing to pay", not as an opaque comparison count.
fn minimum_comparison_headroom(
    required: u64,
    reviewed_design_point: u64,
) -> Result<u64, ScanWidthError> {
    if reviewed_design_point == 0 {
        return Err(ScanWidthError::ZeroComparisonBudget);
    }
    Ok(required.div_ceil(reviewed_design_point))
}

/// Largest measured demand whose margin-grown width still fits `ceiling`.
///
/// The inverse of [`apply_growth_margin`] against a width ceiling: `ceiling *
/// 10_000 / (10_000 + margin)`, floored, which is exactly the largest demand
/// whose rounded-up grown width does not exceed `ceiling`.
fn maximum_servable_delta_events(
    ceiling: u64,
    growth_margin_bps: u64,
) -> Result<u64, ScanWidthError> {
    let scale = BASIS_POINTS_DENOMINATOR
        .checked_add(growth_margin_bps)
        .ok_or(ScanWidthError::ArithmeticOverflow)?;
    ceiling
        .checked_mul(BASIS_POINTS_DENOMINATOR)
        .ok_or(ScanWidthError::ArithmeticOverflow)
        .map(|scaled| scaled / scale)
}

/// Rebuild interval that would reach `servable` demand under linear scaling.
///
/// Lever two: shorten the rebuild interval so each generation accumulates fewer
/// delta events. **This is an upper bound on a usable interval, not an
/// estimate.** It assumes delta events distribute evenly across blocks, and the
/// capture says plainly that they do not — the worst 288-block window averages
/// 4,813 events per block against a whole-replay mean of 103, a ~47x burst. A
/// burst that concentrated makes the true worst sub-window carry *more* than
/// its proportional share, so the real interval that fits is shorter than this,
/// by an amount only a rescan at that interval can say. Never treat the return
/// value as the interval to adopt.
///
/// Returns the measured interval unchanged when the demand already fits, since
/// lengthening an interval does not reduce demand.
fn linear_interval_blocks(
    measured_interval_blocks: u32,
    measured_delta_events: u64,
    servable_delta_events: u64,
) -> Result<u32, ScanWidthError> {
    if measured_delta_events == 0 {
        return Err(ScanWidthError::ZeroDemand);
    }
    if servable_delta_events >= measured_delta_events {
        return Ok(measured_interval_blocks);
    }
    let scaled = u64::from(measured_interval_blocks)
        .checked_mul(servable_delta_events)
        .ok_or(ScanWidthError::ArithmeticOverflow)?;
    u32::try_from(scaled / measured_delta_events).map_err(|_| ScanWidthError::ArithmeticOverflow)
}

/// Whether one record-annotation pass fits the interval it must complete in.
///
/// The hoist's per-query saving is only real if publication can pay for it. One
/// annotation pass costs `distinct_addresses * store_reads` oblivious reads —
/// each touched address's finalized history, re-read to decide the join — plus
/// at most one write per published slot. That work has to finish inside one
/// rebuild interval, or generations fall behind faster than they publish and
/// the hoist is not a design option however cheap it makes a query.
///
/// `distinct_addresses` is the number this model cannot supply: see
/// [`Self::maximum_annotatable_distinct_addresses`] for the threshold it must
/// be compared against, and `docs/notes/recent-snapshot-scan-width.md` for the
/// run that would measure it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct AnnotationPublicationBudget {
    interval_blocks: u32,
    seconds_per_block: u64,
    operation_nanos: u64,
    store_reads: u64,
    snapshot_slots: u64,
}

impl AnnotationPublicationBudget {
    /// Builds a publication budget from its authoritative dimensions.
    pub(super) const fn new(
        interval_blocks: u32,
        seconds_per_block: u64,
        operation_nanos: u64,
        store_reads: u64,
        snapshot_slots: u64,
    ) -> Result<Self, ScanWidthError> {
        if operation_nanos == 0 {
            return Err(ScanWidthError::ZeroOperationNanos);
        }
        if store_reads == 0 {
            return Err(ScanWidthError::ZeroStoreReads);
        }
        if interval_blocks == 0 || seconds_per_block == 0 {
            return Err(ScanWidthError::ZeroRebuildInterval);
        }
        Ok(Self {
            interval_blocks,
            seconds_per_block,
            operation_nanos,
            store_reads,
            snapshot_slots,
        })
    }

    /// Returns the oblivious operations the rebuild interval has room for.
    pub(super) fn operation_budget(&self) -> Result<u64, ScanWidthError> {
        u64::from(self.interval_blocks)
            .checked_mul(self.seconds_per_block)
            .and_then(|seconds| seconds.checked_mul(1_000_000_000))
            .ok_or(ScanWidthError::ArithmeticOverflow)
            .map(|nanos| nanos / self.operation_nanos)
    }

    /// Returns the oblivious operations annotating `distinct_addresses` costs.
    pub(super) fn required_operations(
        &self,
        distinct_addresses: u64,
    ) -> Result<u64, ScanWidthError> {
        distinct_addresses
            .checked_mul(self.store_reads)
            .and_then(|reads| reads.checked_add(self.snapshot_slots))
            .ok_or(ScanWidthError::ArithmeticOverflow)
    }

    /// Returns the largest distinct-address count one interval can annotate.
    ///
    /// **This is the threshold.** Above it the record-annotation hoist does not
    /// fit its own publication window and stops being a design option, whatever
    /// it does to the per-query cost. Below it the hoist is affordable and the
    /// argument moves back to the per-query levers.
    pub(super) fn maximum_annotatable_distinct_addresses(&self) -> Result<u64, ScanWidthError> {
        let budget = self.operation_budget()?;
        let Some(for_reads) = budget.checked_sub(self.snapshot_slots) else {
            return Ok(0);
        };
        Ok(for_reads / self.store_reads)
    }

    /// Returns whether annotating `distinct_addresses` fits the interval.
    pub(super) fn fits(&self, distinct_addresses: u64) -> Result<bool, ScanWidthError> {
        Ok(self.required_operations(distinct_addresses)? <= self.operation_budget()?)
    }
}

/// What a sizing model concludes about serving a demand.
///
/// Ordered by how much design change the demand needs. The arms are exhaustive
/// because the annotated join never costs more than the nested-loop join for
/// any `store_reads >= 1`: `(store_reads + 1) * slots - (slots + store_reads)`
/// is `store_reads * (slots - 1)`, which is non-negative.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SizingVerdict {
    /// Neither the shipped join nor the annotation hoist fits the budget.
    UnservableUnderEveryJoin,
    /// Only the annotation hoist fits; the shipped engine does not.
    ServableOnlyWithAnnotatedRecords,
    /// The shipped engine already fits, so the hoist does too.
    ServableUnderEveryJoin,
}

/// The complete recent-snapshot sizing argument for one demand and policy.
///
/// Holds the per-query cost and ceiling under *both* joins, the demand, and the
/// verdict that follows, so the whole argument is one value that a test can
/// assert against rather than a chain of prose in a note.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct RecentSnapshotSizingModel {
    demand: RecentSnapshotDemand,
    policy: ScanWidthPolicy,
    required_slots: u64,
    nested_loop: ScanWidthDecision,
    annotated_records: ScanWidthDecision,
}

impl RecentSnapshotSizingModel {
    /// Builds the model by sizing the demand under both joins.
    pub(super) fn new(
        demand: RecentSnapshotDemand,
        policy: ScanWidthPolicy,
    ) -> Result<Self, ScanWidthError> {
        Ok(Self {
            demand,
            policy,
            required_slots: apply_growth_margin(demand.max_total_delta_events(), policy)?,
            nested_loop: recent_snapshot_scan_width(
                demand,
                policy,
                JoinStrategy::NestedLoopRelation,
            )?,
            annotated_records: recent_snapshot_scan_width(
                demand,
                policy,
                JoinStrategy::AnnotatedRecords,
            )?,
        })
    }

    /// Returns the measured demand this model was built from.
    pub(super) const fn demand(&self) -> RecentSnapshotDemand {
        self.demand
    }

    /// Returns the width the demand and growth margin require.
    pub(super) const fn required_slots(&self) -> u64 {
        self.required_slots
    }

    /// Returns the per-query comparison budget both joins are judged against.
    pub(super) const fn comparison_budget(&self) -> u64 {
        self.policy.comparison_budget()
    }

    /// Returns the sizing decision under one join.
    pub(super) const fn decision(&self, join: JoinStrategy) -> ScanWidthDecision {
        match join {
            JoinStrategy::NestedLoopRelation => self.nested_loop,
            JoinStrategy::AnnotatedRecords => self.annotated_records,
        }
    }

    /// Returns what the model concludes about serving the demand.
    pub(super) const fn verdict(&self) -> SizingVerdict {
        match (self.nested_loop, self.annotated_records) {
            (ScanWidthDecision::Serviceable(_), _) => SizingVerdict::ServableUnderEveryJoin,
            (_, ScanWidthDecision::Serviceable(_)) => {
                SizingVerdict::ServableOnlyWithAnnotatedRecords
            }
            _ => SizingVerdict::UnservableUnderEveryJoin,
        }
    }

    /// Returns the headroom multiple that would admit the width under `join`.
    ///
    /// Lever one, applied to this model. See [`minimum_comparison_headroom`].
    pub(super) fn minimum_comparison_headroom(
        &self,
        join: JoinStrategy,
    ) -> Result<u64, ScanWidthError> {
        minimum_comparison_headroom(
            query_slot_comparisons(self.required_slots, self.policy.store_reads(), join)?,
            REVIEWED_DESIGN_POINT_COMPARISONS,
        )
    }

    /// Returns the largest demand `join` can serve inside the current budget.
    pub(super) fn maximum_servable_delta_events(
        &self,
        join: JoinStrategy,
    ) -> Result<u64, ScanWidthError> {
        maximum_servable_delta_events(
            serviceable_slot_ceiling(self.policy, join)?,
            self.policy.growth_margin_bps(),
        )
    }

    /// Returns the rebuild interval that would reach that demand, under linear
    /// scaling only.
    ///
    /// Lever two, applied to this model. See [`linear_interval_blocks`] for why
    /// this is an upper bound and not a recommendation.
    pub(super) fn linear_interval_blocks(&self, join: JoinStrategy) -> Result<u32, ScanWidthError> {
        linear_interval_blocks(
            self.demand.interval_blocks(),
            self.demand.max_total_delta_events(),
            self.maximum_servable_delta_events(join)?,
        )
    }

    /// Returns the publication budget the annotation hoist must fit inside.
    pub(super) const fn annotation_publication_budget(
        &self,
        operation_nanos: u64,
    ) -> Result<AnnotationPublicationBudget, ScanWidthError> {
        AnnotationPublicationBudget::new(
            self.demand.interval_blocks(),
            TARGET_BLOCK_SPACING_SECONDS,
            operation_nanos,
            self.policy.store_reads(),
            self.required_slots,
        )
    }
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
    /// A publication budget declared a zero-cost oblivious operation.
    ZeroOperationNanos,
    /// A publication budget declared a rebuild interval of no wall clock.
    ZeroRebuildInterval,
    /// A checked sizing computation overflowed.
    ArithmeticOverflow,
    /// The width bisection left its own invariant.
    SearchInvariant,
}

impl ScanWidthError {
    /// Returns the self-describing message for this failure.
    ///
    /// Split out of the [`fmt::Display`] impl so the mapping is a plain
    /// arm-per-variant table rather than a chain of formatter calls, which is
    /// both the DRYer shape and what keeps `lint-code-duplication` from seeing
    /// this and every other error enum's `Display` as the same logic.
    const fn message(&self) -> &'static str {
        match self {
            Self::ZeroStoreReads => "scan-width policy declares no store reads",
            Self::ZeroComparisonBudget => "scan-width policy declares no comparison budget",
            Self::BudgetBelowMinimumWidth => "scan-width budget cannot fund a single scanned slot",
            Self::ZeroDemand => "scan-width evidence records no delta events",
            Self::UnmeasuredDistribution => "per-address delta distribution is unmeasured",
            Self::MalformedDistribution => {
                "per-address delta distribution is not strictly ascending"
            }
            Self::ZeroResponseSlots => "coverage query supplied no response slots",
            Self::PolicyInput => "compiled profile dimension exceeds the sizing domain",
            Self::ZeroOperationNanos => {
                "annotation budget declares a zero-cost oblivious operation"
            }
            Self::ZeroRebuildInterval => {
                "annotation budget declares a rebuild interval of no wall clock"
            }
            Self::ArithmeticOverflow => "scan-width computation overflowed",
            Self::SearchInvariant => "scan-width bisection left its invariant",
        }
    }
}

impl fmt::Display for ScanWidthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.message())
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
            query_slot_comparisons(8, 4, JoinStrategy::NestedLoopRelation)
                .expect("small width does not overflow"),
            40
        );
    }

    /// The annotated join charges the sum, not the product.
    #[test]
    fn the_annotated_polynomial_charges_the_join_once_per_store_read() {
        // 8 + 4, one annotation lookup per finalized store read.
        assert_eq!(
            query_slot_comparisons(8, 4, JoinStrategy::AnnotatedRecords)
                .expect("small width does not overflow"),
            12
        );
    }

    /// The verdict's exhaustiveness rests on this: annotating never costs more.
    #[test]
    fn the_annotated_join_never_costs_more_than_the_nested_loop_join() {
        for slots in [1_u64, 2, 256, 1_732_532] {
            for store_reads in [1_u64, 4, 1_028] {
                let nested =
                    query_slot_comparisons(slots, store_reads, JoinStrategy::NestedLoopRelation)
                        .expect("no overflow");
                let annotated =
                    query_slot_comparisons(slots, store_reads, JoinStrategy::AnnotatedRecords)
                        .expect("no overflow");
                assert!(annotated <= nested);
                // The saving is exactly store_reads * (slots - 1).
                assert_eq!(nested - annotated, store_reads * (slots - 1));
            }
        }
    }

    /// The hoisted terms are gone from the per-query polynomial, not renamed.
    #[test]
    fn the_polynomial_is_linear_in_the_scan_width() {
        let single = query_slot_comparisons(1, 1_028, JoinStrategy::NestedLoopRelation)
            .expect("no overflow");
        for width in [2_u64, 16, 1_024, 1_000_000] {
            assert_eq!(
                query_slot_comparisons(width, 1_028, JoinStrategy::NestedLoopRelation)
                    .expect("no overflow"),
                single * width
            );
        }
    }

    #[test]
    fn ceiling_is_the_largest_width_inside_the_budget() {
        let policy = policy(4, 40);
        let ceiling = serviceable_slot_ceiling(policy, JoinStrategy::NestedLoopRelation)
            .expect("budget funds at least one slot");
        assert_eq!(ceiling, 8);
        assert!(
            query_slot_comparisons(ceiling, 4, JoinStrategy::NestedLoopRelation)
                .expect("no overflow")
                <= 40
        );
        assert!(
            query_slot_comparisons(ceiling + 1, 4, JoinStrategy::NestedLoopRelation)
                .expect("no overflow")
                > 40
        );
    }

    /// The same budget admits a far wider annotated scan: 40 - 4 slots.
    #[test]
    fn the_annotated_ceiling_is_the_budget_less_the_store_reads() {
        let ceiling = serviceable_slot_ceiling(policy(4, 40), JoinStrategy::AnnotatedRecords)
            .expect("budget funds at least one slot");
        assert_eq!(ceiling, 36);
    }

    #[test]
    fn ceiling_rejects_a_budget_below_one_slot() {
        assert_eq!(
            serviceable_slot_ceiling(policy(4, 4), JoinStrategy::NestedLoopRelation),
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
            JoinStrategy::NestedLoopRelation,
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
        let narrow = recent_snapshot_scan_width(
            RecentSnapshotDemand::new(288, 8),
            policy,
            JoinStrategy::NestedLoopRelation,
        )
        .expect("sizing succeeds");
        let wide = recent_snapshot_scan_width(
            RecentSnapshotDemand::new(288, 64),
            policy,
            JoinStrategy::NestedLoopRelation,
        )
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
        let decision = recent_snapshot_scan_width(
            RecentSnapshotDemand::new(288, 9),
            policy,
            JoinStrategy::NestedLoopRelation,
        )
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
            recent_snapshot_scan_width(
                RecentSnapshotDemand::new(288, 0),
                policy(4, 160),
                JoinStrategy::NestedLoopRelation
            ),
            Err(ScanWidthError::ZeroDemand)
        );
    }

    #[test]
    fn sizing_is_reproducible_for_identical_evidence() {
        let demand = RecentSnapshotDemand::new(288, 1_000);
        let policy = ScanWidthPolicy::new(1_028, 1_000_000_000, 2_500).expect("valid policy");
        let first = recent_snapshot_scan_width(demand, policy, JoinStrategy::AnnotatedRecords)
            .expect("sizing succeeds");
        for _ in 0..8 {
            assert_eq!(
                recent_snapshot_scan_width(demand, policy, JoinStrategy::AnnotatedRecords)
                    .expect("sizing succeeds"),
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
        let ceiling = serviceable_slot_ceiling(policy, JoinStrategy::NestedLoopRelation)
            .expect("budget funds at least one slot");
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

    /// The complete sizing argument, as one asserted value.
    ///
    /// This is the tripwire's other half: it pins the demand, the per-query
    /// cost and ceiling under *both* joins, and the verdict that follows. It
    /// fails the moment the capture, either cost polynomial, the growth margin
    /// or the accepted headroom moves — including the case the old tripwire
    /// could not see, where the shipped join stays unservable but the modelled
    /// one becomes servable.
    #[test]
    fn the_mainnet_model_is_unservable_under_both_joins() {
        let model = mainnet_sizing_model().expect("mainnet sizing succeeds");

        assert_eq!(model.demand().interval_blocks(), 288);
        assert_eq!(model.demand().max_total_delta_events(), 1_386_025);
        // 1,386,025 grown by 25%.
        assert_eq!(model.required_slots(), 1_732_532);
        // Four times the 394,240 pairings the reviewed design point cost.
        assert_eq!(model.comparison_budget(), 1_576_960);

        let ScanWidthDecision::Unserviceable(nested) =
            model.decision(JoinStrategy::NestedLoopRelation)
        else {
            panic!("the shipped nested-loop join cannot scan 1,732,532 slots per query");
        };
        // 1,732,532 * 1029, against a ceiling of 1,576,960 / 1029.
        assert_eq!(nested.required_query_comparisons(), 1_782_775_428);
        assert_eq!(nested.serviceable_ceiling(), 1_532);
        assert_eq!(nested.budget_overrun_factor(), 1_130);

        let ScanWidthDecision::Unserviceable(annotated) =
            model.decision(JoinStrategy::AnnotatedRecords)
        else {
            panic!(
                "the annotation hoist still leaves 1,733,560 comparisons over a 1,576,960 budget"
            );
        };
        // 1,732,532 + 1,028, against a ceiling of 1,576,960 - 1,028.
        assert_eq!(annotated.required_query_comparisons(), 1_733_560);
        assert_eq!(annotated.serviceable_ceiling(), 1_575_932);
        // The hoist closes 1,130x down to 9.93% — and not to zero. This is the
        // number the whole remaining argument is about.
        assert_eq!(
            annotated
                .budget_excess_basis_points()
                .expect("excess fits u64"),
            993
        );
        assert_eq!(annotated.budget_overrun_factor(), 1);

        assert_eq!(model.verdict(), SizingVerdict::UnservableUnderEveryJoin);
    }

    /// Lever one, priced: what raising the headroom would have to buy.
    ///
    /// Asserting the required multiple is deliberately *not* raising it. The
    /// point is that the choice is a stated operational one and this is its
    /// price, so a human can decide rather than discover a tuned constant.
    #[test]
    fn closing_the_gap_by_headroom_costs_one_more_reviewed_design_point() {
        let model = mainnet_sizing_model().expect("mainnet sizing succeeds");
        // ceil(1,733,560 / 394,240): five reviewed design points instead of
        // four, a 25% rise in the fixed work every query pays.
        assert_eq!(
            model
                .minimum_comparison_headroom(JoinStrategy::AnnotatedRecords)
                .expect("headroom fits u64"),
            5
        );
        // The same lever against the shipped join is not a lever at all.
        assert_eq!(
            model
                .minimum_comparison_headroom(JoinStrategy::NestedLoopRelation)
                .expect("headroom fits u64"),
            4_523
        );
        // The constant this would replace is still 4, and this test does not
        // move it.
        assert_eq!(ACCEPTED_COMPARISON_HEADROOM, 4);
    }

    /// Lever two, priced — and shown to be unevaluable from committed evidence.
    #[test]
    fn closing_the_gap_by_interval_needs_evidence_the_capture_does_not_carry() {
        let model = mainnet_sizing_model().expect("mainnet sizing succeeds");
        // Largest generation the annotated join could serve: 1,575,932 slots
        // back through the 25% margin.
        assert_eq!(
            model
                .maximum_servable_delta_events(JoinStrategy::AnnotatedRecords)
                .expect("no overflow"),
            1_260_745
        );
        // Under *linear* scaling that is a 261-block interval — a 9% shortening.
        // The capture measures 288, 1,152 and 8,064 blocks and nothing else, so
        // the demand at 261 blocks is not a number anything in this tree knows.
        // Worse, the worst 288-block window runs at 4,813 events per block
        // against a whole-replay mean of 103, and a burst that concentrated puts
        // the true 261-block demand *above* the linear estimate. So 261 is a
        // ceiling on a usable interval, not a usable interval.
        assert_eq!(
            model
                .linear_interval_blocks(JoinStrategy::AnnotatedRecords)
                .expect("no overflow"),
            261
        );
        // Against the shipped join the same lever scales to zero blocks: no
        // rebuild interval, however short, brings 4,813 events per block under
        // a 1,225-event servable demand.
        assert_eq!(
            model
                .maximum_servable_delta_events(JoinStrategy::NestedLoopRelation)
                .expect("no overflow"),
            1_225
        );
        assert_eq!(
            model
                .linear_interval_blocks(JoinStrategy::NestedLoopRelation)
                .expect("no overflow"),
            0
        );
    }

    /// The threshold that decides whether the hoist is affordable at all.
    ///
    /// The one number this model cannot supply is the worst generation's
    /// distinct-address count. This test states exactly what it would have to
    /// exceed for the record-annotation hoist to stop being a design option, so
    /// the answer is a single comparison the day the measurement lands.
    #[test]
    fn the_annotation_hoist_is_infeasible_above_a_stated_distinct_address_count() {
        let model = mainnet_sizing_model().expect("mainnet sizing succeeds");
        let budget = model
            .annotation_publication_budget(REFERENCE_OBLIVIOUS_OPERATION_NANOS)
            .expect("mainnet annotation budget is well formed");

        // 288 blocks * 75 s * 1e9 ns / 17,184 ns per oblivious operation.
        assert_eq!(
            budget.operation_budget().expect("no overflow"),
            1_256_983_240
        );
        // (1,256,983,240 - 1,732,532 writes) / 1,028 reads per address.
        let threshold = budget
            .maximum_annotatable_distinct_addresses()
            .expect("no overflow");
        assert_eq!(threshold, 1_221_061);
        assert!(budget.fits(threshold).expect("no overflow"));
        assert!(!budget.fits(threshold + 1).expect("no overflow"));

        // The threshold is informative precisely because it sits *below* the
        // trivial upper bound: a generation has at most one distinct address
        // per delta event, so the hoist fails only if the worst window's burst
        // is 88.09% address-disjoint — nearly one event per address. Any
        // concentration at all, which is what bursts normally are, leaves the
        // hoist affordable.
        let delta_events = model.demand().max_total_delta_events();
        assert!(threshold < delta_events);
        assert_eq!(threshold * BASIS_POINTS_DENOMINATOR / delta_events, 8_809);
    }

    /// A slower oblivious operation lowers the threshold, so the reference rate
    /// is a parameter of the answer and not a hidden assumption inside it.
    #[test]
    fn a_slower_oblivious_operation_lowers_the_annotation_threshold() {
        let model = mainnet_sizing_model().expect("mainnet sizing succeeds");
        let reference = model
            .annotation_publication_budget(REFERENCE_OBLIVIOUS_OPERATION_NANOS)
            .expect("well formed")
            .maximum_annotatable_distinct_addresses()
            .expect("no overflow");
        let slower = model
            .annotation_publication_budget(REFERENCE_OBLIVIOUS_OPERATION_NANOS * 2)
            .expect("well formed")
            .maximum_annotatable_distinct_addresses()
            .expect("no overflow");
        assert!(slower < reference);
        // Twice the cost per operation puts the threshold under half the
        // trivial upper bound, at which point address concentration alone
        // decides feasibility.
        assert!(slower * 2 < model.demand().max_total_delta_events());
    }

    #[test]
    fn an_annotation_budget_rejects_a_zero_cost_operation() {
        assert_eq!(
            AnnotationPublicationBudget::new(288, 75, 0, 1_028, 1_732_532),
            Err(ScanWidthError::ZeroOperationNanos)
        );
        assert_eq!(
            AnnotationPublicationBudget::new(0, 75, 17_184, 1_028, 1_732_532),
            Err(ScanWidthError::ZeroRebuildInterval)
        );
    }

    /// The verdict tracks the joins rather than restating the shipped one.
    #[test]
    fn a_demand_only_the_annotated_join_can_serve_is_reported_as_such() {
        // 20 slots against 4 store reads: nested costs 100 > 60, annotated
        // costs 24 <= 60.
        let model = RecentSnapshotSizingModel::new(
            RecentSnapshotDemand::new(288, 20),
            ScanWidthPolicy::new(4, 60, 0).expect("valid policy"),
        )
        .expect("sizing succeeds");
        assert_eq!(
            model.verdict(),
            SizingVerdict::ServableOnlyWithAnnotatedRecords
        );

        let generous = RecentSnapshotSizingModel::new(
            RecentSnapshotDemand::new(288, 20),
            ScanWidthPolicy::new(4, 1_000, 0).expect("valid policy"),
        )
        .expect("sizing succeeds");
        assert_eq!(generous.verdict(), SizingVerdict::ServableUnderEveryJoin);
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
