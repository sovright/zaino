//! Scheduling and preconditions for the paired access-path timing experiment.
//!
//! This is the portable half of the driver. It decides *what* to measure and in
//! *what order*, and it decides whether the machine is fit to measure on at
//! all. It never measures anything itself: the caller supplies a [`PairedProbe`]
//! that performs one timed insertion against a fresh, equal-occupancy worker.
//! That split keeps the scheduling rules testable on any host, and confines the
//! platform-specific work to a thin implementation of one trait method.
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
//! That matters in a specific and dangerous direction. Concurrent load inflates
//! variance, a wider distribution widens the bootstrap interval, and a wide
//! interval is *easier* to fit inside an equivalence bound. A noisy machine
//! therefore biases this experiment toward falsely reporting "indistinguishable".
//! So [`QuiescencePolicy`] is checked before a run and its observation is
//! recorded with the result, rather than the run proceeding and the noise being
//! mentioned afterwards.

use crate::timing_equivalence::{Pair, Rng, Seed, MINIMUM_PAIRS};
use serde::{Deserialize, Serialize};

/// Which side of the pair is being measured.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Arm {
    /// The key is already present.
    Hit,
    /// The key is absent.
    Miss,
}

/// One timed insertion against a fresh, equal-occupancy worker.
///
/// Implementations must rebuild state between calls so that occupancy is
/// identical for both arms; otherwise the experiment measures table growth
/// rather than the hit/miss distinction.
pub trait PairedProbe {
    /// Why a measurement could not be taken.
    type Error;

    /// Performs one insertion on `arm` and returns its duration in nanoseconds.
    fn measure(&mut self, arm: Arm) -> Result<u64, Self::Error>;
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
}

/// A validated experiment plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Quiescence {
    load_average_1m: f64,
    competing_processes: usize,
}

impl Quiescence {
    /// Records a machine-state observation taken immediately before a run.
    pub const fn new(load_average_1m: f64, competing_processes: usize) -> Self {
        Self {
            load_average_1m,
            competing_processes,
        }
    }
}

/// The machine conditions a run requires.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct QuiescencePolicy {
    max_load_average_1m: f64,
    max_competing_processes: usize,
}

impl QuiescencePolicy {
    /// Declares the admissible conditions before the run.
    pub const fn new(max_load_average_1m: f64, max_competing_processes: usize) -> Self {
        Self {
            max_load_average_1m,
            max_competing_processes,
        }
    }

    /// Whether the observed machine state is fit to measure on.
    pub fn admits(&self, observed: &Quiescence) -> bool {
        observed.load_average_1m <= self.max_load_average_1m
            && observed.competing_processes <= self.max_competing_processes
    }
}

/// Why a run was refused or abandoned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunError<E> {
    /// The machine was too busy for the measurement to mean anything.
    NotQuiescent,
    /// The probe could not take a measurement.
    Probe(E),
}

/// Runs the plan, returning one [`Pair`] per measured iteration.
///
/// Warm-up pairs are measured and discarded. Within each pair the two arms are
/// measured in a seed-determined order, so any monotonic drift over the run
/// falls on both arms equally rather than accumulating against one of them.
pub fn run<P: PairedProbe>(
    plan: &ExperimentPlan,
    policy: &QuiescencePolicy,
    observed: &Quiescence,
    probe: &mut P,
) -> Result<Vec<Pair>, RunError<P::Error>> {
    if !policy.admits(observed) {
        return Err(RunError::NotQuiescent);
    }

    let mut rng = Rng::new(plan.seed.value() ^ 0xa1b2_c3d4_e5f6_0789);
    let mut pairs = Vec::with_capacity(plan.pairs);
    for index in 0..(plan.warmup_pairs + plan.pairs) {
        let miss_first = rng.next_u64() & 1 == 0;
        let pair = measure_pair(probe, miss_first).map_err(RunError::Probe)?;
        if index >= plan.warmup_pairs {
            pairs.push(pair);
        }
    }
    Ok(pairs)
}

fn measure_pair<P: PairedProbe>(probe: &mut P, miss_first: bool) -> Result<Pair, P::Error> {
    if miss_first {
        let miss = probe.measure(Arm::Miss)?;
        let hit = probe.measure(Arm::Hit)?;
        Ok(Pair::new(hit, miss))
    } else {
        let hit = probe.measure(Arm::Hit)?;
        let miss = probe.measure(Arm::Miss)?;
        Ok(Pair::new(hit, miss))
    }
}

/// Whether `Cpus_allowed_list` names exactly one CPU.
///
/// Pinning is checked rather than assumed: a run that believes it is pinned but
/// is not will migrate between cores mid-experiment, and the migration cost
/// lands on whichever arm happens to be executing.
pub fn single_cpu_allowed(cpus_allowed_list: &str) -> bool {
    let list = cpus_allowed_list.trim();
    !list.is_empty() && !list.contains(',') && !list.contains('-')
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

        fn measure(&mut self, arm: Arm) -> Result<u64, ()> {
            self.order.push(arm);
            self.calls += 1;
            Ok(match arm {
                Arm::Hit => 1_000,
                Arm::Miss => 1_000,
            })
        }
    }

    fn quiet() -> (QuiescencePolicy, Quiescence) {
        (QuiescencePolicy::new(0.5, 0), Quiescence::new(0.1, 0))
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

    /// A busy machine biases this experiment toward a false "equivalent", so the
    /// run must refuse rather than proceed and caveat.
    #[test]
    fn a_busy_machine_refuses_to_produce_measurements() {
        let plan = ExperimentPlan::new(MINIMUM_PAIRS, 4, Seed::new(1)).expect("valid plan");
        let policy = QuiescencePolicy::new(0.5, 0);
        let mut probe = FakeProbe::default();

        let loaded = Quiescence::new(3.7, 0);
        assert_eq!(
            run(&plan, &policy, &loaded, &mut probe),
            Err(RunError::NotQuiescent)
        );

        let competing = Quiescence::new(0.1, 2);
        assert_eq!(
            run(&plan, &policy, &competing, &mut probe),
            Err(RunError::NotQuiescent)
        );

        // Nothing was measured, so no partial result can be published.
        assert_eq!(probe.calls, 0);
    }

    #[test]
    fn warmup_pairs_are_measured_and_discarded() {
        let plan = ExperimentPlan::new(MINIMUM_PAIRS, 7, Seed::new(9)).expect("valid plan");
        let (policy, observed) = quiet();
        let mut probe = FakeProbe::default();
        let pairs = run(&plan, &policy, &observed, &mut probe).expect("quiet machine");

        assert_eq!(pairs.len(), MINIMUM_PAIRS);
        // Every pair, warm-up included, costs two measurements.
        assert_eq!(probe.calls, (MINIMUM_PAIRS + 7) * 2);
    }

    #[test]
    fn each_pair_measures_both_arms_exactly_once() {
        let plan = ExperimentPlan::new(MINIMUM_PAIRS, 1, Seed::new(5)).expect("valid plan");
        let (policy, observed) = quiet();
        let mut probe = FakeProbe::default();
        run(&plan, &policy, &observed, &mut probe).expect("quiet machine");

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
        let (policy, observed) = quiet();
        let mut probe = FakeProbe::default();
        run(&plan, &policy, &observed, &mut probe).expect("quiet machine");

        let hit_first = probe
            .order
            .chunks(2)
            .filter(|window| window[0] == Arm::Hit)
            .count();
        let total = probe.order.len() / 2;
        let share = hit_first as f64 / total as f64;
        assert!(
            (0.45..=0.55).contains(&share),
            "ordering was lopsided: {share}"
        );
    }

    #[test]
    fn ordering_is_reproducible_from_the_recorded_seed() {
        let (policy, observed) = quiet();
        let order_for = |seed: u64| {
            let plan = ExperimentPlan::new(MINIMUM_PAIRS, 1, Seed::new(seed)).expect("valid plan");
            let mut probe = FakeProbe::default();
            run(&plan, &policy, &observed, &mut probe).expect("quiet machine");
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
    }
}
