//! Logical access-cost model for comparing private-query schedule alternatives
//! in milliseconds instead of repeating multi-hour builder campaigns.
//!
//! This is not target-hardware or physical-obliviousness evidence. The
//! nanoseconds-per-insertion curve preserves the five observed builder medians and
//! uses a least-squares, log2-capacity extrapolation outside them; every report
//! that consumes an extrapolated point says `EXTRAPOLATED`. Summing those
//! median inputs produces a screening model, not a p99 estimate: fixed logical
//! work does not remove cache, ORAM, operating-system, or hardware latency
//! variance. These observations time a complete `insert_record_unique`
//! operation, while the schedules count individual logical table accesses.
//! The timing result is therefore an explicitly labelled
//! insertion-equivalent scenario, not a per-access latency estimate. A p99 or
//! feasible-cap verdict requires measured read/write inputs with the same unit
//! as the schedule.
//!
//! Three operator decisions remain unset. `FlatFullHistory` versus the explicit
//! `BoundedPerRequest` cap maps to the fixed-work decision;
//! `CompactedPages` and its explicit page width/cap map to the growth and page
//! scheme; `LatencyBudget` maps to wire/leakage acceptance. Modeling those
//! inputs does not choose them. A compacted page has a different record size
//! from the measured one-event record, so this module reports its access count
//! but refuses to price it without page-specific latency evidence.
//!
//! Two gaps separate `CompactedPages` from the fixed-page scheme now in the
//! tree, and both make this model optimistic rather than conservative:
//!
//! 1. Page width is a caller-supplied parameter. Passing anything other than
//!    [`SELECTED_PAGE_ENTRIES`] models a scheme that does not exist.
//! 2. The selected scheme spreads pages across three independent tables
//!    (base, add, spend), while this model charges page work against a single
//!    event table. Real per-request work is therefore higher than reported
//!    here by a factor this module does not attempt to derive.
//!
//! Treat the page numbers as a floor on the real schedule, never a budget.
//!
//! Latency observations come from the July 2026 GCP c3-standard-44 Gate 2
//! session recorded by
//! `docs/notes/oram-fixed-work-slo-consistency-2026-07-31.md` at commit
//! `3bb699bd`. Corpus aggregates come from the Gate 1 Mainnet capture recorded
//! by `docs/notes/oram-phase0-mainnet-capture-log-2026-07-26.md` on branch
//! `docs/oram-gate1-hybrid-result`. The full events-per-address histogram is not
//! committed, so this module deliberately has no file loader; one can be added
//! if the histogram later becomes an in-repository evidence artifact.

use std::{fmt, num::NonZeroU64};

/// Probe counts fixed by the selected layout.
struct ProbeShape {
    directory_probes: u64,
    event_probes: u64,
}

/// Fixed-work access schedule being evaluated.
enum AccessSchedule {
    /// Every request scans the complete configured per-address event bound.
    FlatFullHistory { max_events_per_address: u64 },
    /// Every request scans exactly `cap` event ordinals.
    ///
    /// The fixed-work decision is unset; `cap` is operator input.
    BoundedPerRequest { cap: NonZeroU64 },
    /// Every request scans exactly `cap` compacted pages.
    ///
    /// The page-growth decision is unset; both values are operator input.
    CompactedPages {
        events_per_page: NonZeroU64,
        cap: NonZeroU64,
    },
}

/// Logical table accesses charged to one fixed-work request.
struct RequestAccesses {
    directory_accesses: u64,
    event_accesses: u64,
    total_accesses: u64,
}

/// Median `insert_record_unique` cost measured on a GCP c3-standard-44 during
/// the Phase 0 measurement session (2026-07). These prose-only observations
/// are recorded in `docs/notes/oram-fixed-work-slo-consistency-2026-07-31.md`
/// at commit `3bb699bd`; they are not target-hardware evidence. Capacities are
/// represented by their base-two exponent.
const MEASURED_DIRECTORY_INSERTION_NS: [(u32, f64); 5] = [
    (10, 4_849.0),
    (11, 5_883.0),
    (12, 11_115.0),
    (13, 11_728.0),
    (14, 12_424.0),
];
const MEASURED_EVENT_INSERTION_NS: [(u32, f64); 5] = [
    (10, 8_525.0),
    (11, 9_803.0),
    (12, 15_300.0),
    (13, 16_118.0),
    (14, 17_184.0),
];
const MINIMUM_MEASURED_EXPONENT: f64 = 10.0;
const MAXIMUM_MEASURED_EXPONENT: f64 = 14.0;

/// Entries per page in the selected fixed-page scheme.
///
/// Mirrors `hybrid_sizing::SELECTED_PAGE_ENTRIES`, which cannot be imported
/// here: `hybrid_sizing` is `corpus-zaino`-gated while this module stays
/// available in the default build. The `corpus-zaino` test
/// `mirrored_page_width_matches_the_selected_scheme` pins the two together so
/// the mirror cannot drift unnoticed.
///
/// Note the selected scheme spreads pages across three independent tables
/// (base, add, spend). This model charges page work against a single event
/// table, so its page counts are a lower bound on the real topology.
const SELECTED_PAGE_ENTRIES: u64 = 16;

struct InsertionLatencyCurve {
    directory: TableInsertionLatencyCurve,
    event: TableInsertionLatencyCurve,
}

struct TableInsertionLatencyCurve {
    measured: &'static [(u32, f64); 5],
    slope: f64,
    intercept: f64,
}

struct InsertionLatencyEstimate {
    ns_per_insertion: f64,
    extrapolated: bool,
}

impl InsertionLatencyCurve {
    fn from_measured() -> Self {
        Self {
            directory: TableInsertionLatencyCurve::fit(&MEASURED_DIRECTORY_INSERTION_NS),
            event: TableInsertionLatencyCurve::fit(&MEASURED_EVENT_INSERTION_NS),
        }
    }

    fn directory(&self, capacity: u64) -> Result<InsertionLatencyEstimate, CostModelError> {
        self.directory.estimate(capacity)
    }

    fn event(&self, capacity: u64) -> Result<InsertionLatencyEstimate, CostModelError> {
        self.event.estimate(capacity)
    }
}

impl TableInsertionLatencyCurve {
    fn fit(measured: &'static [(u32, f64); 5]) -> Self {
        let count = measured.len() as f64;
        let (sum_x, sum_y, sum_xy, sum_x_squared) = measured.iter().fold(
            (0.0, 0.0, 0.0, 0.0),
            |(sum_x, sum_y, sum_xy, sum_x_squared), (exponent, latency)| {
                let exponent = f64::from(*exponent);
                (
                    sum_x + exponent,
                    sum_y + latency,
                    sum_xy + exponent * latency,
                    sum_x_squared + exponent * exponent,
                )
            },
        );
        let denominator = count * sum_x_squared - sum_x * sum_x;
        let slope = (count * sum_xy - sum_x * sum_y) / denominator;
        let intercept = (sum_y - slope * sum_x) / count;
        Self {
            measured,
            slope,
            intercept,
        }
    }

    fn estimate(&self, capacity: u64) -> Result<InsertionLatencyEstimate, CostModelError> {
        if capacity == 0 {
            return Err(CostModelError::ZeroCapacity);
        }
        for (exponent, latency) in self.measured {
            if capacity == 1_u64 << exponent {
                return Ok(InsertionLatencyEstimate {
                    ns_per_insertion: *latency,
                    extrapolated: false,
                });
            }
        }

        // Circuit-ORAM work grows with tree depth, so the estimator uses a
        // least-squares line in log2(capacity). Values at 2^24 and 2^29 are
        // extrapolations far beyond the measurements and are the weakest
        // numerical inputs in this analysis.
        let exponent = (capacity as f64).log2();
        let ns_per_insertion = self.slope * exponent + self.intercept;
        if !ns_per_insertion.is_finite() || ns_per_insertion <= 0.0 {
            return Err(CostModelError::InvalidLatencyEstimate);
        }
        Ok(InsertionLatencyEstimate {
            ns_per_insertion,
            extrapolated: !(MINIMUM_MEASURED_EXPONENT..=MAXIMUM_MEASURED_EXPONENT)
                .contains(&exponent),
        })
    }
}

/// Corpus heat and capacity inputs used by a cost evaluation.
enum CostCorpus {
    MainnetCapture2026_07(CorpusHeat),
    /// Clearly synthetic input for exploring hypothetical distributions.
    Synthetic(CorpusHeat),
}

/// Aggregate corpus values needed by the fixed-work SLO model.
#[derive(Clone, Copy)]
struct CorpusHeat {
    hottest_event_count: u64,
    second_hottest_event_count: u64,
    distinct_standard_addresses: u64,
    total_standard_events: u64,
    directory_capacity: u64,
    event_capacity: u64,
}

/// Aggregates transcribed from the Gate 1 Mainnet capture at height 3,425,046,
/// block `0000000000a1014e9564513f1d5e5ddaba027c032857a236ca3178e9a8983ad4`,
/// measurement BLAKE2s-256
/// `aba46f64da0113d9b0e93209ab4a8a98626d6d5bc7973444c8bf766a1922b127`.
/// See `docs/notes/oram-phase0-mainnet-capture-log-2026-07-26.md` on branch
/// `docs/oram-gate1-hybrid-result`. The full events-per-address histogram is
/// builder-only; fixed work makes the recorded hottest tail sufficient here.
const MAINNET_CAPTURE_HEAT: CorpusHeat = CorpusHeat {
    hottest_event_count: 3_360_022,
    second_hottest_event_count: 3_360_020,
    distinct_standard_addresses: 9_193_009,
    total_standard_events: 351_872_272,
    directory_capacity: 1 << 24,
    event_capacity: 1 << 29,
};

impl CostCorpus {
    const fn mainnet_capture() -> Self {
        Self::MainnetCapture2026_07(MAINNET_CAPTURE_HEAT)
    }

    fn synthetic(heat: CorpusHeat) -> Result<Self, CostModelError> {
        if heat.hottest_event_count > MAINNET_CAPTURE_HEAT.hottest_event_count
            || heat.second_hottest_event_count > MAINNET_CAPTURE_HEAT.second_hottest_event_count
        {
            return Err(CostModelError::SyntheticExceedsMainnetHeat);
        }
        Ok(Self::Synthetic(heat))
    }

    const fn heat(&self) -> &CorpusHeat {
        match self {
            Self::MainnetCapture2026_07(heat) | Self::Synthetic(heat) => heat,
        }
    }
}

struct LatencyBudget {
    millis: NonZeroU64,
}

struct CostReport {
    directory_accesses_per_request: u64,
    event_accesses_per_request: u64,
    total_accesses_per_request: u64,
    requests_to_complete: u64,
    insertion_equivalent_nanos_per_request: f64,
    insertion_equivalent_nanos_to_complete: f64,
    within_budget_per_request: bool,
    within_budget_to_complete: bool,
    extrapolated: bool,
}

struct InsertionEquivalentCapReport {
    cap: Option<NonZeroU64>,
    extrapolated: bool,
}

impl LatencyBudget {
    fn nanos(&self) -> Result<u128, CostModelError> {
        u128::from(self.millis.get())
            .checked_mul(1_000_000)
            .ok_or(CostModelError::ArithmeticOverflow)
    }
}

impl fmt::Display for CostReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let evidence = if self.extrapolated {
            "EXTRAPOLATED"
        } else {
            "MEASURED OR INTERPOLATED"
        };
        write!(
            f,
            "cost model: {evidence}; INSERTION-EQUIVALENT MEDIAN INPUT, NOT P99\n\
             accesses/request: directory={}, event={}, total={}\n\
             requests/complete-history: {}\n\
             insertion-equivalent ns/request: {:.3} (within budget={})\n\
             insertion-equivalent ns/complete-history: {:.3} (within budget={})",
            self.directory_accesses_per_request,
            self.event_accesses_per_request,
            self.total_accesses_per_request,
            self.requests_to_complete,
            self.insertion_equivalent_nanos_per_request,
            self.within_budget_per_request,
            self.insertion_equivalent_nanos_to_complete,
            self.within_budget_to_complete,
        )
    }
}

impl fmt::Display for InsertionEquivalentCapReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let evidence = if self.extrapolated {
            "EXTRAPOLATED"
        } else {
            "MEASURED OR INTERPOLATED"
        };
        match self.cap {
            Some(cap) => write!(
                f,
                "max_insertion_equivalent_cap={} evidence={evidence} model=MEDIAN_INPUT_NOT_P99_OR_FEASIBILITY",
                cap.get()
            ),
            None => write!(
                f,
                "max_insertion_equivalent_cap=NONE evidence={evidence} model=MEDIAN_INPUT_NOT_P99_OR_FEASIBILITY"
            ),
        }
    }
}

/// Evaluates deterministic logical work under an insertion-equivalent scenario.
/// The curve times a complete insertion while the schedule counts individual
/// reads, so this is a deliberately conservative planning screen, not an actual
/// request projection, feasible-cap proof, or latency quantile.
fn evaluate(
    schedule: &AccessSchedule,
    shape: &ProbeShape,
    corpus: &CostCorpus,
    curve: &InsertionLatencyCurve,
    budget: &LatencyBudget,
) -> Result<CostReport, CostModelError> {
    if matches!(schedule, AccessSchedule::CompactedPages { .. }) {
        return Err(CostModelError::CompactedPageLatencyUnmeasured);
    }
    let heat = corpus.heat();
    let accesses = schedule.accesses_per_request(shape, heat.hottest_event_count)?;
    let requests_to_complete = schedule.requests_to_complete(heat.hottest_event_count)?;
    let directory_latency = curve.directory(heat.directory_capacity)?;
    let event_latency = curve.event(heat.event_capacity)?;
    let insertion_equivalent_nanos_per_request = insertion_equivalent_nanos(
        &accesses,
        directory_latency.ns_per_insertion,
        event_latency.ns_per_insertion,
    )?;
    let insertion_equivalent_nanos_to_complete =
        insertion_equivalent_nanos_per_request * requests_to_complete as f64;
    if !insertion_equivalent_nanos_to_complete.is_finite() {
        return Err(CostModelError::InvalidLatencyEstimate);
    }
    let budget_nanos = budget.nanos()? as f64;
    Ok(CostReport {
        directory_accesses_per_request: accesses.directory_accesses,
        event_accesses_per_request: accesses.event_accesses,
        total_accesses_per_request: accesses.total_accesses,
        requests_to_complete,
        insertion_equivalent_nanos_per_request,
        insertion_equivalent_nanos_to_complete,
        within_budget_per_request: insertion_equivalent_nanos_per_request <= budget_nanos,
        within_budget_to_complete: insertion_equivalent_nanos_to_complete <= budget_nanos,
        extrapolated: directory_latency.extrapolated || event_latency.extrapolated,
    })
}

/// Largest bounded event-ordinal cap whose current `4 + 4K` schedule fits the
/// supplied insertion-equivalent scenario budget. This is exact within that
/// deliberately conservative scenario, but does not establish a feasible cap
/// or p99 SLO because the observations are complete insertions rather than the
/// schedule's individual reads. The fixed-work decision remains unset.
fn max_cap_for_insertion_equivalent_budget(
    curve: &InsertionLatencyCurve,
    corpus: &CostCorpus,
    budget: &LatencyBudget,
) -> Result<InsertionEquivalentCapReport, CostModelError> {
    const DIRECTORY_PROBES: u64 = 4;
    const EVENT_PROBES: u64 = 4;

    let heat = corpus.heat();
    let directory_latency = curve.directory(heat.directory_capacity)?;
    let event_latency = curve.event(heat.event_capacity)?;
    let directory_nanos_per_insertion =
        round_up_insertion_nanos(directory_latency.ns_per_insertion)?;
    let event_nanos_per_insertion = round_up_insertion_nanos(event_latency.ns_per_insertion)?;
    let directory_nanos = u128::from(DIRECTORY_PROBES)
        .checked_mul(directory_nanos_per_insertion)
        .ok_or(CostModelError::ArithmeticOverflow)?;
    let event_ordinal_nanos = u128::from(EVENT_PROBES)
        .checked_mul(event_nanos_per_insertion)
        .ok_or(CostModelError::ArithmeticOverflow)?;
    Ok(InsertionEquivalentCapReport {
        cap: max_cap_for_integer_budget(directory_nanos, event_ordinal_nanos, budget.nanos()?)?,
        extrapolated: directory_latency.extrapolated || event_latency.extrapolated,
    })
}

/// Solves the scenario-cap inequality in integer nanoseconds. Insertion
/// estimates are rounded up before reaching this helper, making its boundary
/// conservative within the scenario and avoiding loss of integer precision
/// above f64's 2^53 exact range.
fn max_cap_for_integer_budget(
    directory_nanos: u128,
    event_ordinal_nanos: u128,
    budget_nanos: u128,
) -> Result<Option<NonZeroU64>, CostModelError> {
    if event_ordinal_nanos == 0 {
        return Err(CostModelError::InvalidLatencyEstimate);
    }
    let minimum_nanos = directory_nanos
        .checked_add(event_ordinal_nanos)
        .ok_or(CostModelError::ArithmeticOverflow)?;
    if budget_nanos < minimum_nanos {
        return Ok(None);
    }

    let raw_cap = (budget_nanos - directory_nanos) / event_ordinal_nanos;
    let cap_value = u64::try_from(raw_cap).unwrap_or(u64::MAX);
    let Some(cap) = NonZeroU64::new(cap_value) else {
        return Err(CostModelError::InvalidCapSolution);
    };
    let candidate_nanos = u128::from(cap.get())
        .checked_mul(event_ordinal_nanos)
        .and_then(|event_nanos| directory_nanos.checked_add(event_nanos))
        .ok_or(CostModelError::ArithmeticOverflow)?;
    if candidate_nanos > budget_nanos {
        return Err(CostModelError::InvalidCapSolution);
    }
    if let Some(next_cap) = cap.get().checked_add(1) {
        let next_nanos = u128::from(next_cap)
            .checked_mul(event_ordinal_nanos)
            .and_then(|event_nanos| directory_nanos.checked_add(event_nanos));
        if next_nanos.is_some_and(|nanos| nanos <= budget_nanos) {
            return Err(CostModelError::InvalidCapSolution);
        }
    }
    Ok(Some(cap))
}

fn round_up_insertion_nanos(latency: f64) -> Result<u128, CostModelError> {
    if !latency.is_finite() || latency <= 0.0 {
        return Err(CostModelError::InvalidLatencyEstimate);
    }
    let rounded = latency.ceil();
    if rounded > u128::MAX as f64 {
        return Err(CostModelError::InvalidLatencyEstimate);
    }
    Ok(rounded as u128)
}

fn insertion_equivalent_nanos(
    accesses: &RequestAccesses,
    directory_ns_per_insertion: f64,
    event_ns_per_insertion: f64,
) -> Result<f64, CostModelError> {
    let total = accesses.directory_accesses as f64 * directory_ns_per_insertion
        + accesses.event_accesses as f64 * event_ns_per_insertion;
    if !total.is_finite() || total < 0.0 {
        return Err(CostModelError::InvalidLatencyEstimate);
    }
    Ok(total)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CostModelError {
    ArithmeticOverflow,
    AddressEventBoundExceeded,
    ZeroCapacity,
    InvalidLatencyEstimate,
    CompactedPageLatencyUnmeasured,
    SyntheticExceedsMainnetHeat,
    InvalidCapSolution,
}

impl fmt::Display for CostModelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ArithmeticOverflow => f.write_str("cost-model arithmetic overflowed"),
            Self::AddressEventBoundExceeded => {
                f.write_str("address events exceed the fixed schedule bound")
            }
            Self::ZeroCapacity => f.write_str("table capacity must be nonzero"),
            Self::InvalidLatencyEstimate => {
                f.write_str("latency curve produced a non-positive or non-finite estimate")
            }
            Self::CompactedPageLatencyUnmeasured => {
                f.write_str("compacted-page latency has not been measured for its record size")
            }
            Self::SyntheticExceedsMainnetHeat => {
                f.write_str("synthetic corpus exceeds the captured Mainnet hot-address tail")
            }
            Self::InvalidCapSolution => {
                f.write_str("SLO inequality did not produce a maximal nonzero cap")
            }
        }
    }
}

impl std::error::Error for CostModelError {}

impl AccessSchedule {
    fn accesses_per_request(
        &self,
        shape: &ProbeShape,
        address_events: u64,
    ) -> Result<RequestAccesses, CostModelError> {
        let event_units = match self {
            Self::FlatFullHistory {
                max_events_per_address,
            } => {
                validate_event_bound(address_events, *max_events_per_address)?;
                *max_events_per_address
            }
            Self::BoundedPerRequest { cap } | Self::CompactedPages { cap, .. } => cap.get(),
        };
        checked_accesses(shape, event_units)
    }

    fn requests_to_complete(&self, address_events: u64) -> Result<u64, CostModelError> {
        let requests = match self {
            Self::FlatFullHistory {
                max_events_per_address,
            } => {
                validate_event_bound(address_events, *max_events_per_address)?;
                1
            }
            Self::BoundedPerRequest { cap } => address_events.div_ceil(cap.get()).max(1),
            Self::CompactedPages {
                events_per_page,
                cap,
            } => address_events
                .div_ceil(events_per_page.get())
                .div_ceil(cap.get())
                .max(1),
        };
        Ok(requests)
    }
}

fn validate_event_bound(address_events: u64, bound: u64) -> Result<(), CostModelError> {
    if address_events > bound {
        return Err(CostModelError::AddressEventBoundExceeded);
    }
    Ok(())
}

fn checked_accesses(
    shape: &ProbeShape,
    event_units: u64,
) -> Result<RequestAccesses, CostModelError> {
    let event_accesses = shape
        .event_probes
        .checked_mul(event_units)
        .ok_or(CostModelError::ArithmeticOverflow)?;
    let total_accesses = shape
        .directory_probes
        .checked_add(event_accesses)
        .ok_or(CostModelError::ArithmeticOverflow)?;
    Ok(RequestAccesses {
        directory_accesses: shape.directory_probes,
        event_accesses,
        total_accesses,
    })
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU64;

    use super::*;

    const MAINNET_HOTTEST_EVENTS: u64 = 3_360_022;

    const fn four_probe_shape() -> ProbeShape {
        ProbeShape {
            directory_probes: 4,
            event_probes: 4,
        }
    }

    fn one_second_budget() -> LatencyBudget {
        LatencyBudget {
            millis: NonZeroU64::new(1_000).expect("test latency budget is nonzero"),
        }
    }

    #[test]
    fn flat_schedule_reproduces_the_recorded_mainnet_floor() -> Result<(), CostModelError> {
        let schedule = AccessSchedule::FlatFullHistory {
            max_events_per_address: MAINNET_HOTTEST_EVENTS,
        };
        let accesses =
            schedule.accesses_per_request(&four_probe_shape(), MAINNET_HOTTEST_EVENTS)?;

        assert_eq!(accesses.directory_accesses, 4);
        assert_eq!(accesses.event_accesses, 13_440_088);
        assert_eq!(accesses.total_accesses, 13_440_092);
        assert_eq!(schedule.requests_to_complete(MAINNET_HOTTEST_EVENTS)?, 1);
        Ok(())
    }

    #[test]
    fn bounded_schedule_caps_per_request_work_and_counts_requests() -> Result<(), CostModelError> {
        let cap = NonZeroU64::new(1_000).expect("test cap is nonzero");
        let schedule = AccessSchedule::BoundedPerRequest { cap };
        let accesses =
            schedule.accesses_per_request(&four_probe_shape(), MAINNET_HOTTEST_EVENTS)?;

        assert_eq!(accesses.directory_accesses, 4);
        assert_eq!(accesses.event_accesses, 4_000);
        assert_eq!(accesses.total_accesses, 4_004);
        assert_eq!(
            schedule.requests_to_complete(MAINNET_HOTTEST_EVENTS)?,
            3_361
        );
        Ok(())
    }

    #[test]
    fn compacted_schedule_scales_with_pages_not_events() -> Result<(), CostModelError> {
        let events_per_page =
            NonZeroU64::new(SELECTED_PAGE_ENTRIES).expect("selected page width is nonzero");
        let cap = NonZeroU64::new(5_000).expect("test cap is nonzero");
        let schedule = AccessSchedule::CompactedPages {
            events_per_page,
            cap,
        };
        let accesses =
            schedule.accesses_per_request(&four_probe_shape(), MAINNET_HOTTEST_EVENTS)?;

        assert_eq!(
            MAINNET_HOTTEST_EVENTS.div_ceil(events_per_page.get()),
            210_002
        );
        assert_eq!(accesses.directory_accesses, 4);
        assert_eq!(accesses.event_accesses, 20_000);
        assert_eq!(accesses.total_accesses, 20_004);
        assert_eq!(schedule.requests_to_complete(MAINNET_HOTTEST_EVENTS)?, 43);
        Ok(())
    }

    /// The model mirrors `SELECTED_PAGE_ENTRIES` because `hybrid_sizing` is
    /// `corpus-zaino`-gated while this module must stay available in the
    /// default build. Mirroring risks silent drift, so pin the two together
    /// whenever the authoritative constant is actually compiled in.
    #[cfg(feature = "corpus-zaino")]
    #[test]
    fn mirrored_page_width_matches_the_selected_scheme() {
        assert_eq!(
            SELECTED_PAGE_ENTRIES,
            crate::hybrid_sizing::SELECTED_PAGE_ENTRIES
        );
    }

    #[test]
    fn curve_reproduces_measured_points_exactly_and_unflagged() -> Result<(), CostModelError> {
        let curve = InsertionLatencyCurve::from_measured();
        for (exponent, expected) in MEASURED_DIRECTORY_INSERTION_NS {
            let estimate = curve.directory(1_u64 << exponent)?;
            assert_eq!(estimate.ns_per_insertion, expected);
            assert!(!estimate.extrapolated);
        }
        for (exponent, expected) in MEASURED_EVENT_INSERTION_NS {
            let estimate = curve.event(1_u64 << exponent)?;
            assert_eq!(estimate.ns_per_insertion, expected);
            assert!(!estimate.extrapolated);
        }
        Ok(())
    }

    #[test]
    fn production_capacities_are_flagged_extrapolations_in_the_expected_band(
    ) -> Result<(), CostModelError> {
        let curve = InsertionLatencyCurve::from_measured();
        let directory = curve.directory(1_u64 << 24)?;
        let event = curve.event(1_u64 << 29)?;

        assert!(directory.extrapolated);
        assert!((34_000.0..35_000.0).contains(&directory.ns_per_insertion));
        assert!(event.extrapolated);
        assert!((53_000.0..54_000.0).contains(&event.ns_per_insertion));
        Ok(())
    }

    #[test]
    fn embedded_mainnet_summary_matches_the_capture_log() {
        let corpus = CostCorpus::mainnet_capture();
        let heat = corpus.heat();

        assert!(matches!(corpus, CostCorpus::MainnetCapture2026_07(_)));
        assert_eq!(heat.hottest_event_count, 3_360_022);
        assert_eq!(heat.second_hottest_event_count, 3_360_020);
        assert_eq!(heat.distinct_standard_addresses, 9_193_009);
        assert_eq!(heat.total_standard_events, 351_872_272);
        assert_eq!(heat.directory_capacity, 1 << 24);
        assert_eq!(heat.event_capacity, 1 << 29);
    }

    #[test]
    fn synthetic_fallback_is_clearly_marked_and_never_exceeds_mainnet_heat(
    ) -> Result<(), CostModelError> {
        let mainnet = CostCorpus::mainnet_capture();
        let mainnet_heat = *mainnet.heat();
        let synthetic_heat = CorpusHeat {
            hottest_event_count: 10_000,
            second_hottest_event_count: 9_000,
            distinct_standard_addresses: 100_000,
            total_standard_events: 1_000_000,
            directory_capacity: 1 << 18,
            event_capacity: 1 << 21,
        };
        let synthetic = CostCorpus::synthetic(synthetic_heat)?;

        assert!(matches!(synthetic, CostCorpus::Synthetic(_)));
        assert!(synthetic.heat().hottest_event_count <= mainnet_heat.hottest_event_count);
        assert!(
            synthetic.heat().second_hottest_event_count <= mainnet_heat.second_hottest_event_count
        );

        let too_hot = CorpusHeat {
            hottest_event_count: mainnet_heat.hottest_event_count + 1,
            ..synthetic_heat
        };
        assert!(matches!(
            CostCorpus::synthetic(too_hot),
            Err(CostModelError::SyntheticExceedsMainnetHeat)
        ));
        Ok(())
    }

    #[test]
    fn flat_schedule_insertion_equivalent_screen_exceeds_one_second_by_orders_of_magnitude(
    ) -> Result<(), CostModelError> {
        let corpus = CostCorpus::mainnet_capture();
        let schedule = AccessSchedule::FlatFullHistory {
            max_events_per_address: corpus.heat().hottest_event_count,
        };
        let report = evaluate(
            &schedule,
            &four_probe_shape(),
            &corpus,
            &InsertionLatencyCurve::from_measured(),
            &one_second_budget(),
        )?;
        let scenario_seconds = report.insertion_equivalent_nanos_per_request / 1_000_000_000.0;
        println!("flat_schedule_insertion_equivalent_seconds={scenario_seconds:.9}");

        assert_eq!(report.total_accesses_per_request, 13_440_092);
        assert!((700.0..750.0).contains(&scenario_seconds));
        let toy_capacity_insertion_equivalent_nanos =
            report.total_accesses_per_request as f64 * MEASURED_DIRECTORY_INSERTION_NS[0].1;
        assert!(toy_capacity_insertion_equivalent_nanos >= 60.0 * 1_000_000_000.0);
        assert!(!report.within_budget_per_request);
        assert!(!report.within_budget_to_complete);
        assert!(report.extrapolated);
        let rendered = format!("{report}");
        assert!(rendered.contains("EXTRAPOLATED"));
        assert!(rendered.contains("INSERTION-EQUIVALENT MEDIAN INPUT, NOT P99"));
        Ok(())
    }

    #[test]
    fn insertion_equivalent_budget_cap_is_low_thousands_but_not_a_feasibility_claim(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let report = max_cap_for_insertion_equivalent_budget(
            &InsertionLatencyCurve::from_measured(),
            &CostCorpus::mainnet_capture(),
            &one_second_budget(),
        )?;
        println!("{report}");
        let cap = report
            .cap
            .ok_or("one event ordinal should fit the insertion-equivalent budget")?;

        assert!((4_500..=4_800).contains(&cap.get()));
        assert_eq!(cap.get(), 4_666);
        assert!(report.extrapolated);
        let rendered = format!("{report}");
        assert!(rendered.contains("evidence=EXTRAPOLATED"));
        assert!(rendered.contains("MEDIAN_INPUT_NOT_P99_OR_FEASIBILITY"));
        Ok(())
    }

    #[test]
    fn compaction_counts_twelve_requests_but_refuses_unmeasured_page_pricing(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let curve = InsertionLatencyCurve::from_measured();
        let corpus = CostCorpus::mainnet_capture();
        let budget = one_second_budget();
        let cap = max_cap_for_insertion_equivalent_budget(&curve, &corpus, &budget)?
            .cap
            .ok_or("one event ordinal should fit the insertion-equivalent budget")?;
        let schedule = AccessSchedule::CompactedPages {
            events_per_page: NonZeroU64::new(64).expect("test page width is nonzero"),
            cap,
        };
        let accesses =
            schedule.accesses_per_request(&four_probe_shape(), MAINNET_HOTTEST_EVENTS)?;

        assert_eq!(accesses.total_accesses, 18_668);
        assert_eq!(schedule.requests_to_complete(MAINNET_HOTTEST_EVENTS)?, 12);
        assert!(matches!(
            evaluate(&schedule, &four_probe_shape(), &corpus, &curve, &budget),
            Err(CostModelError::CompactedPageLatencyUnmeasured)
        ));
        Ok(())
    }

    #[test]
    fn integer_cap_returns_none_when_one_event_ordinal_exceeds_the_budget(
    ) -> Result<(), CostModelError> {
        assert_eq!(max_cap_for_integer_budget(4, 5, 8)?, None);
        Ok(())
    }

    #[test]
    fn integer_cap_includes_an_exact_budget_boundary() -> Result<(), CostModelError> {
        let cap =
            max_cap_for_integer_budget(4, 5, 19)?.ok_or(CostModelError::InvalidCapSolution)?;
        assert_eq!(cap.get(), 3);
        Ok(())
    }

    #[test]
    fn integer_cap_stays_exact_above_the_f64_integer_range() -> Result<(), CostModelError> {
        let expected = (1_u64 << 60) + 3;
        let budget = 17_u128 + u128::from(expected) * 9;
        let cap =
            max_cap_for_integer_budget(17, 9, budget)?.ok_or(CostModelError::InvalidCapSolution)?;
        assert_eq!(cap.get(), expected);
        Ok(())
    }

    #[test]
    fn integer_cap_saturates_at_the_largest_representable_cap() -> Result<(), CostModelError> {
        let budget = 17_u128 + u128::from(u64::MAX) * 9 + 8;
        let cap =
            max_cap_for_integer_budget(17, 9, budget)?.ok_or(CostModelError::InvalidCapSolution)?;
        assert_eq!(cap.get(), u64::MAX);
        Ok(())
    }

    #[test]
    fn integer_cap_treats_next_candidate_overflow_as_over_budget() -> Result<(), CostModelError> {
        let event_ordinal_nanos = u128::MAX / 2 + 1;
        let cap = max_cap_for_integer_budget(0, event_ordinal_nanos, u128::MAX)?
            .ok_or(CostModelError::InvalidCapSolution)?;
        assert_eq!(cap.get(), 1);
        Ok(())
    }
}
