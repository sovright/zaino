//! Scheduling and preconditions for the paired access-path timing experiment.
//!
//! This is the portable scheduler. It decides *what* to measure and in *what
//! order*. It never measures the host environment itself: the synchronous
//! platform driver must enforce CPU affinity and quiescence immediately before
//! and after calling [`run`]. The caller supplies a [`PairedProbe`] that performs
//! one timed insertion against a fresh, equal-occupancy table.
//!
//! # Why quiescence is a precondition, not a caveat
//!
//! CPU pinning fixes which core the measured thread runs on. It does nothing
//! about last-level-cache pressure, memory bandwidth, SMT siblings, or the
//! frequency and thermal effects of load elsewhere on the machine. An ORAM
//! insertion touches a large working set, so memory-subsystem contention is the
//! dominant noise term for this workload — precisely the term pinning does not
//! isolate.
//!
//! Concurrent load inflates variance and widens confidence intervals, making an
//! equivalence result harder to obtain. More importantly, uncontrolled load can
//! create, erase, or reorder timing effects, so a noisy run is not conservative
//! evidence in either direction. The platform driver therefore applies its
//! [`QuiescencePolicy`] before, between, and after the record-kind experiments
//! and records scheduler contention around every timed insertion.

use std::fmt;

use crate::timing_equivalence::{ArmMeasurement, Pair, PairOrder, Rng, Seed, MINIMUM_PAIRS};
use serde::Serialize;

/// Which side of the pair is being measured.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Arm {
    /// The key is already present.
    Hit,
    /// The key is absent.
    Miss,
}

/// One timed insertion against a fresh, equal-occupancy table.
///
/// Implementations must rebuild state between calls so that occupancy is
/// identical for both arms; otherwise the experiment measures table growth
/// rather than the hit/miss distinction.
pub(crate) trait PairedProbe {
    /// Why a measurement could not be taken.
    type Error;

    /// Performs one insertion on `arm`.
    fn measure(&mut self, arm: Arm) -> Result<ArmMeasurement, Self::Error>;
}

/// Why an experiment plan was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlanError {
    /// Fewer pairs than the kill-gate report's floor of [`MINIMUM_PAIRS`].
    Underpowered {
        /// The requested pair count.
        requested: usize,
    },
    /// A run with no warm-up measures cold caches, not steady state.
    NoWarmup,
    /// The warm-up and measured pair counts cannot be added safely.
    IterationCountOverflow,
}

impl fmt::Display for PlanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Underpowered { requested } => write!(
                formatter,
                "timing plan requested {requested} pairs; at least {MINIMUM_PAIRS} are required"
            ),
            Self::NoWarmup => formatter.write_str("timing plan requires at least one warm-up pair"),
            Self::IterationCountOverflow => {
                formatter.write_str("timing plan pair count overflows usize")
            }
        }
    }
}

impl std::error::Error for PlanError {}

/// A validated experiment plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ExperimentPlan {
    pairs: usize,
    warmup_pairs: usize,
    seed: Seed,
}

impl ExperimentPlan {
    /// Validates a plan, refusing one that could not qualify anything.
    pub fn new(pairs: usize, warmup_pairs: usize, seed: Seed) -> Result<Self, PlanError> {
        if pairs < MINIMUM_PAIRS {
            return Err(PlanError::Underpowered { requested: pairs });
        }
        if warmup_pairs == 0 {
            return Err(PlanError::NoWarmup);
        }
        warmup_pairs
            .checked_add(pairs)
            .ok_or(PlanError::IterationCountOverflow)?;
        Ok(Self {
            pairs,
            warmup_pairs,
            seed,
        })
    }

    /// How many measured pairs the plan collects.
    pub const fn pairs(&self) -> usize {
        self.pairs
    }

    /// How many discarded pairs precede them.
    pub const fn warmup_pairs(&self) -> usize {
        self.warmup_pairs
    }
}

/// An observation of how busy the machine was.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub struct Quiescence {
    load_average_1m: f64,
    competing_processes: usize,
}

impl Quiescence {
    /// Records one machine-state observation.
    pub const fn new(load_average_1m: f64, competing_processes: usize) -> Self {
        Self {
            load_average_1m,
            competing_processes,
        }
    }
}

/// The machine conditions a run requires.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub struct QuiescencePolicy {
    max_load_average_1m: f64,
    max_competing_processes: usize,
}

impl QuiescencePolicy {
    /// Declares the admissible conditions at every environment snapshot.
    pub const fn new(max_load_average_1m: f64, max_competing_processes: usize) -> Self {
        Self {
            max_load_average_1m,
            max_competing_processes,
        }
    }

    /// Whether the observed machine state is fit to measure on.
    pub fn admits(&self, observed: &Quiescence) -> bool {
        self.max_load_average_1m.is_finite()
            && self.max_load_average_1m >= 0.0
            && observed.load_average_1m.is_finite()
            && observed.load_average_1m >= 0.0
            && observed.load_average_1m <= self.max_load_average_1m
            && observed.competing_processes <= self.max_competing_processes
    }
}

/// Runs the plan, returning one [`Pair`] per measured iteration.
///
/// Warm-up pairs are measured and discarded. Within each pair the two arms are
/// measured in a seed-determined, exactly balanced order (within one pair for an
/// odd count), so monotonic drift falls on both arms in expectation rather than
/// systematically accumulating against one of them.
pub(crate) fn run<P: PairedProbe>(
    plan: &ExperimentPlan,
    probe: &mut P,
) -> Result<Vec<Pair>, P::Error> {
    let mut rng = Rng::new(plan.seed.value() ^ 0xa1b2_c3d4_e5f6_0789);
    let warmup_orders = balanced_orders(plan.warmup_pairs, &mut rng);
    measure_orders(probe, &warmup_orders, |_| {})?;

    let measured_orders = balanced_orders(plan.pairs, &mut rng);
    let mut pairs = Vec::with_capacity(plan.pairs);
    measure_orders(probe, &measured_orders, |pair| pairs.push(pair))?;
    Ok(pairs)
}

fn measure_orders<P, F>(
    probe: &mut P,
    miss_first_orders: &[bool],
    mut retain: F,
) -> Result<(), P::Error>
where
    P: PairedProbe,
    F: FnMut(Pair),
{
    for &miss_first in miss_first_orders {
        retain(measure_pair(probe, miss_first)?);
    }
    Ok(())
}

fn balanced_orders(count: usize, rng: &mut Rng) -> Vec<bool> {
    let mut orders: Vec<bool> = (0..count).map(|index| index.is_multiple_of(2)).collect();
    for index in (1..orders.len()).rev() {
        let other = rng.below(index + 1);
        orders.swap(index, other);
    }
    orders
}

fn measure_pair<P: PairedProbe>(probe: &mut P, miss_first: bool) -> Result<Pair, P::Error> {
    if miss_first {
        let miss = probe.measure(Arm::Miss)?;
        let hit = probe.measure(Arm::Hit)?;
        Ok(Pair::from_measurements(hit, miss, PairOrder::MissFirst))
    } else {
        let hit = probe.measure(Arm::Hit)?;
        let miss = probe.measure(Arm::Miss)?;
        Ok(Pair::from_measurements(hit, miss, PairOrder::HitFirst))
    }
}

/// Whether `Cpus_allowed_list` names exactly one CPU.
///
/// Pinning is checked rather than assumed: a run that believes it is pinned but
/// is not will migrate between cores mid-experiment, and the migration cost
/// lands on whichever arm happens to be executing.
fn single_cpu_allowed(cpus_allowed_list: &str) -> bool {
    single_allowed_cpu(cpus_allowed_list).is_some()
}

/// Returns the sole CPU named by `Cpus_allowed_list`, if there is exactly one.
pub fn single_allowed_cpu(cpus_allowed_list: &str) -> Option<u32> {
    cpus_allowed_list.trim().parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct FakeProbe {
        order: Vec<Arm>,
        calls: usize,
    }

    impl PairedProbe for FakeProbe {
        type Error = ();

        fn measure(&mut self, arm: Arm) -> Result<ArmMeasurement, ()> {
            self.order.push(arm);
            self.calls += 1;
            let nanos = match arm {
                Arm::Hit => 1_000,
                Arm::Miss => 1_000,
            };
            Ok(ArmMeasurement::duration_only(nanos))
        }
    }

    #[test]
    fn a_plan_below_the_power_floor_is_refused() {
        assert_eq!(
            ExperimentPlan::new(MINIMUM_PAIRS - 1, 10, Seed::new(1)),
            Err(PlanError::Underpowered {
                requested: MINIMUM_PAIRS - 1
            })
        );
        assert!(ExperimentPlan::new(MINIMUM_PAIRS, 10, Seed::new(1)).is_ok());
    }

    #[test]
    fn a_plan_without_warmup_is_refused() {
        assert_eq!(
            ExperimentPlan::new(MINIMUM_PAIRS, 0, Seed::new(1)),
            Err(PlanError::NoWarmup)
        );
    }

    #[test]
    fn a_plan_with_an_overflowing_iteration_count_is_refused() {
        assert_eq!(
            ExperimentPlan::new(usize::MAX, 1, Seed::new(1)),
            Err(PlanError::IterationCountOverflow)
        );
    }

    /// A noisy environment is inadmissible evidence in either direction.
    #[test]
    fn a_busy_machine_is_rejected_by_policy() {
        let policy = QuiescencePolicy::new(0.5, 0);

        let loaded = Quiescence::new(3.7, 0);
        assert!(!policy.admits(&loaded));

        let competing = Quiescence::new(0.1, 2);
        assert!(!policy.admits(&competing));
        assert!(policy.admits(&Quiescence::new(0.1, 0)));
        assert!(!QuiescencePolicy::new(f64::NAN, 0).admits(&Quiescence::new(0.1, 0)));
    }

    #[test]
    fn warmup_pairs_are_measured_and_discarded() {
        let plan = ExperimentPlan::new(MINIMUM_PAIRS, 7, Seed::new(9)).expect("valid plan");
        let mut probe = FakeProbe::default();
        let pairs = run(&plan, &mut probe).expect("probe succeeds");

        assert_eq!(pairs.len(), MINIMUM_PAIRS);
        // Every pair, warm-up included, costs two measurements.
        assert_eq!(probe.calls, (MINIMUM_PAIRS + 7) * 2);
    }

    #[test]
    fn each_pair_measures_both_arms_exactly_once() {
        let plan = ExperimentPlan::new(MINIMUM_PAIRS, 1, Seed::new(5)).expect("valid plan");
        let mut probe = FakeProbe::default();
        run(&plan, &mut probe).expect("probe succeeds");

        for window in probe.order.chunks(2) {
            assert_eq!(window.len(), 2);
            assert_ne!(window[0], window[1], "a pair measured the same arm twice");
        }
    }

    /// AB/BA ordering must actually vary, or drift over the run accumulates
    /// against whichever arm is always measured first.
    #[test]
    fn arm_ordering_is_randomised_and_balanced() {
        let plan = ExperimentPlan::new(2_000, 1, Seed::new(11)).expect("valid plan");
        let mut probe = FakeProbe::default();
        run(&plan, &mut probe).expect("probe succeeds");

        let measured_order = &probe.order[plan.warmup_pairs() * 2..];
        let hit_first = measured_order
            .chunks(2)
            .filter(|window| window[0] == Arm::Hit)
            .count();
        let total = measured_order.len() / 2;
        let miss_first = total - hit_first;
        assert!(
            hit_first.abs_diff(miss_first) <= 1,
            "ordering was not exactly balanced: hit-first={hit_first}, miss-first={miss_first}"
        );
    }

    #[test]
    fn ordering_is_reproducible_from_the_recorded_seed() {
        let order_for = |seed: u64| {
            let plan = ExperimentPlan::new(MINIMUM_PAIRS, 1, Seed::new(seed)).expect("valid plan");
            let mut probe = FakeProbe::default();
            run(&plan, &mut probe).expect("probe succeeds");
            probe.order
        };
        assert_eq!(order_for(3), order_for(3));
        assert_ne!(order_for(3), order_for(4));
    }

    #[test]
    fn only_a_single_pinned_cpu_is_accepted() {
        assert!(single_cpu_allowed("3"));
        assert!(single_cpu_allowed(" 11 "));
        assert!(!single_cpu_allowed("0-15"));
        assert!(!single_cpu_allowed("0,2"));
        assert!(!single_cpu_allowed("2-3,7"));
        assert!(!single_cpu_allowed(""));
        assert!(!single_cpu_allowed("cpu3"));
        assert_eq!(single_allowed_cpu(" 11 "), Some(11));
    }
}
