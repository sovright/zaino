//! Scheduling and preconditions for the paired access-path timing experiment.
//!
//! This is the portable scheduler. It decides *what* to measure and in *what
//! order*. It never measures the host environment itself: the synchronous
//! platform driver must enforce CPU affinity and quiescence immediately before
//! and after calling [`run`]. The caller supplies a [`PairedProbe`] that performs
//! two timed insertions against matched equal-occupancy state and then advances
//! that state at the explicit pair boundary.
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

use crate::timing_equivalence::{ArmMeasurement, Pair, PairOrder, Rng, Seed};
use serde::{de::Error as _, Deserialize, Deserializer, Serialize};

const TIMING_ORDER_SEED_DOMAIN: u64 = 0xa1b2_c3d4_e5f6_0789;

/// Which side of the pair is being measured.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Arm {
    /// The key is already present.
    Hit,
    /// The key is absent.
    Miss,
}

/// Two timed insertions against matched, equal-occupancy state.
///
/// Implementations must present identical public occupancy to both arms in a
/// pair. [`Self::finish_pair`] is called exactly once after both arms succeed so
/// a long-lived probe can restore its matched-state invariant before the next
/// pair. Warm-up pairs use the same lifecycle as retained pairs.
pub(crate) trait PairedProbe {
    /// Why a measurement could not be taken.
    type Error;

    /// Performs one insertion on `arm`.
    fn measure(&mut self, arm: Arm) -> Result<ArmMeasurement, Self::Error>;

    /// Restores the probe's pair-boundary invariant after both arms succeed.
    fn finish_pair(&mut self) -> Result<(), Self::Error>;
}

/// Why an experiment plan was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlanError {
    /// A plan must retain at least one measured pair.
    NoMeasuredPairs,
    /// A run with no warm-up measures cold caches, not steady state.
    NoWarmup,
    /// The warm-up and measured pair counts cannot be added safely.
    IterationCountOverflow,
}

impl fmt::Display for PlanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoMeasuredPairs => {
                formatter.write_str("timing plan requires at least one measured pair")
            }
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
    total_pairs: usize,
    seed: Seed,
}

impl ExperimentPlan {
    /// Validates the scheduler mechanics for a timing plan.
    ///
    /// Qualification sample-size policy belongs to the evidence driver, which
    /// can distinguish a deliberately small pilot from a qualification
    /// candidate. This layer only refuses plans it cannot execute safely.
    pub fn new(pairs: usize, warmup_pairs: usize, seed: Seed) -> Result<Self, PlanError> {
        if pairs == 0 {
            return Err(PlanError::NoMeasuredPairs);
        }
        if warmup_pairs == 0 {
            return Err(PlanError::NoWarmup);
        }
        let total_pairs = warmup_pairs
            .checked_add(pairs)
            .ok_or(PlanError::IterationCountOverflow)?;
        Ok(Self {
            pairs,
            warmup_pairs,
            total_pairs,
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

    /// Total pair-boundary transitions, including discarded warm-up pairs.
    pub const fn total_pairs(&self) -> usize {
        self.total_pairs
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SerializedExperimentPlan {
    pairs: usize,
    warmup_pairs: usize,
    total_pairs: usize,
    seed: Seed,
}

impl<'de> Deserialize<'de> for ExperimentPlan {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let serialized = SerializedExperimentPlan::deserialize(deserializer)?;
        let plan = Self::new(serialized.pairs, serialized.warmup_pairs, serialized.seed)
            .map_err(D::Error::custom)?;
        if plan.total_pairs != serialized.total_pairs {
            return Err(D::Error::custom(
                "timing plan total_pairs does not equal pairs plus warmup_pairs",
            ));
        }
        Ok(plan)
    }
}

/// An observation of how busy the machine was.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
    let mut rng = timing_order_rng(plan);
    let warmup_orders = balanced_orders(plan.warmup_pairs, &mut rng);
    measure_orders(probe, &warmup_orders, |_| {})?;

    let measured_orders = balanced_orders(plan.pairs, &mut rng);
    let mut pairs = Vec::with_capacity(plan.pairs);
    measure_orders(probe, &measured_orders, |pair| pairs.push(pair))?;
    Ok(pairs)
}

/// Reproduces the retained AB/BA schedule declared by `plan`.
///
/// The warm-up schedule is generated and discarded first so the retained
/// sequence reflects the exact RNG state used by [`run`].
pub fn expected_timing_pair_orders(plan: &ExperimentPlan) -> Vec<PairOrder> {
    let mut rng = timing_order_rng(plan);
    drop(balanced_orders(plan.warmup_pairs, &mut rng));
    let measured_orders = balanced_orders(plan.pairs, &mut rng);
    measured_orders.into_iter().map(pair_order).collect()
}

/// Whether retained timing pairs exactly follow the schedule declared by `plan`.
pub fn timing_pair_orders_match_plan(plan: &ExperimentPlan, pairs: &[Pair]) -> bool {
    let expected_orders = expected_timing_pair_orders(plan);
    pairs.len() == expected_orders.len()
        && pairs
            .iter()
            .zip(expected_orders)
            .all(|(pair, expected)| pair.order() == expected)
}

fn timing_order_rng(plan: &ExperimentPlan) -> Rng {
    Rng::new(plan.seed.value() ^ TIMING_ORDER_SEED_DOMAIN)
}

const fn pair_order(miss_first: bool) -> PairOrder {
    if miss_first {
        PairOrder::MissFirst
    } else {
        PairOrder::HitFirst
    }
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
    let mut orders = vec![false; count];
    // The long-lived probe alternates physical hit/miss roles every pair.
    // Balance AB/BA independently inside each parity stratum so table identity
    // cannot become correlated with which timed label executes first.
    for parity in 0..2 {
        let stratum_len = (parity..count).step_by(2).count();
        let mut stratum: Vec<bool> = (0..stratum_len)
            // Opposite extras keep the two odd-length strata globally balanced.
            .map(|index| (index + parity).is_multiple_of(2))
            .collect();
        for index in (1..stratum.len()).rev() {
            let other = rng.below(index + 1);
            stratum.swap(index, other);
        }
        for (index, miss_first) in (parity..count).step_by(2).zip(stratum) {
            orders[index] = miss_first;
        }
    }
    orders
}

fn measure_pair<P: PairedProbe>(probe: &mut P, miss_first: bool) -> Result<Pair, P::Error> {
    let order = pair_order(miss_first);
    let pair = if miss_first {
        let miss = probe.measure(Arm::Miss)?;
        let hit = probe.measure(Arm::Hit)?;
        Pair::from_measurements(hit, miss, order)
    } else {
        let hit = probe.measure(Arm::Hit)?;
        let miss = probe.measure(Arm::Miss)?;
        Pair::from_measurements(hit, miss, order)
    };
    probe.finish_pair()?;
    Ok(pair)
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
    use crate::MINIMUM_PAIRS;

    #[derive(Default)]
    struct FakeProbe {
        order: Vec<Arm>,
        calls: usize,
        finished_pairs: usize,
        fail_finish: bool,
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

        fn finish_pair(&mut self) -> Result<(), ()> {
            if self.fail_finish {
                return Err(());
            }
            self.finished_pairs += 1;
            Ok(())
        }
    }

    #[test]
    fn plan_accepts_small_pilots_but_not_zero_measured_pairs() {
        assert!(ExperimentPlan::new(1, 1, Seed::new(1)).is_ok());
        assert_eq!(
            ExperimentPlan::new(0, 1, Seed::new(1)),
            Err(PlanError::NoMeasuredPairs)
        );
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

    #[test]
    fn experiment_plan_deserialization_preserves_validation_and_rejects_unknown_fields(
    ) -> Result<(), serde_json::Error> {
        let plan = ExperimentPlan::new(8, 3, Seed::new(11)).expect("valid plan");
        let encoded = serde_json::to_string(&plan)?;

        assert_eq!(serde_json::from_str::<ExperimentPlan>(&encoded)?, plan);
        assert!(serde_json::from_str::<ExperimentPlan>(
            r#"{"pairs":8,"warmup_pairs":0,"total_pairs":8,"seed":11}"#
        )
        .is_err());
        assert!(serde_json::from_str::<ExperimentPlan>(
            r#"{"pairs":8,"warmup_pairs":3,"total_pairs":12,"seed":11}"#
        )
        .is_err());
        assert!(serde_json::from_str::<ExperimentPlan>(
            r#"{"pairs":8,"warmup_pairs":3,"total_pairs":11,"seed":11,"extra":true}"#
        )
        .is_err());
        Ok(())
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
    fn quiescence_evidence_round_trips_through_json() -> Result<(), serde_json::Error> {
        let observed = Quiescence::new(0.25, 1);
        let policy = QuiescencePolicy::new(0.5, 2);

        let observed_json = serde_json::to_string(&observed)?;
        let policy_json = serde_json::to_string(&policy)?;

        assert_eq!(
            serde_json::from_str::<Quiescence>(&observed_json)?,
            observed
        );
        assert_eq!(
            serde_json::from_str::<QuiescencePolicy>(&policy_json)?,
            policy
        );
        assert!(serde_json::from_str::<Quiescence>(
            r#"{"load_average_1m":0.25,"competing_processes":1,"extra":true}"#
        )
        .is_err());
        assert!(serde_json::from_str::<QuiescencePolicy>(
            r#"{"max_load_average_1m":0.5,"max_competing_processes":2,"extra":true}"#
        )
        .is_err());
        Ok(())
    }

    #[test]
    fn expected_pair_orders_bind_the_exact_retained_schedule() {
        let plan = ExperimentPlan::new(8, 3, Seed::new(11)).expect("valid plan");

        assert_eq!(
            expected_timing_pair_orders(&plan),
            vec![
                PairOrder::MissFirst,
                PairOrder::HitFirst,
                PairOrder::MissFirst,
                PairOrder::MissFirst,
                PairOrder::HitFirst,
                PairOrder::HitFirst,
                PairOrder::HitFirst,
                PairOrder::MissFirst,
            ]
        );
    }

    #[test]
    fn pair_order_plan_match_rejects_reordering_and_wrong_lengths() {
        let plan = ExperimentPlan::new(8, 3, Seed::new(11)).expect("valid plan");
        let mut probe = FakeProbe::default();
        let pairs = run(&plan, &mut probe).expect("probe succeeds");
        assert!(timing_pair_orders_match_plan(&plan, &pairs));

        let mut reordered = pairs.clone();
        reordered.swap(0, 1);
        assert!(!timing_pair_orders_match_plan(&plan, &reordered));
        assert!(!timing_pair_orders_match_plan(
            &plan,
            &pairs[..pairs.len() - 1]
        ));

        let mut extra = pairs;
        extra.push(Pair::new(1_000, 1_000, PairOrder::HitFirst));
        assert!(!timing_pair_orders_match_plan(&plan, &extra));
    }

    #[test]
    fn warmup_pairs_are_measured_and_discarded() {
        let plan = ExperimentPlan::new(MINIMUM_PAIRS, 7, Seed::new(9)).expect("valid plan");
        let mut probe = FakeProbe::default();
        let pairs = run(&plan, &mut probe).expect("probe succeeds");

        assert_eq!(pairs.len(), MINIMUM_PAIRS);
        // Every pair, warm-up included, costs two measurements.
        assert_eq!(probe.calls, (MINIMUM_PAIRS + 7) * 2);
        assert_eq!(probe.finished_pairs, MINIMUM_PAIRS + 7);
        assert_eq!(plan.total_pairs(), MINIMUM_PAIRS + 7);
    }

    #[test]
    fn pair_finalization_failure_prevents_retention() {
        let plan = ExperimentPlan::new(1, 1, Seed::new(9)).expect("valid pilot plan");
        let mut probe = FakeProbe {
            fail_finish: true,
            ..FakeProbe::default()
        };

        assert_eq!(run(&plan, &mut probe), Err(()));
        assert_eq!(probe.calls, 2);
        assert_eq!(probe.finished_pairs, 0);
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
    fn arm_ordering_is_balanced_within_each_physical_role() {
        let plan = ExperimentPlan::new(500, 2, Seed::new(11)).expect("valid plan");
        let mut probe = FakeProbe::default();
        run(&plan, &mut probe).expect("probe succeeds");

        let measured_order = &probe.order[plan.warmup_pairs() * 2..];
        for parity in 0..2 {
            let mut hit_first = 0usize;
            let mut miss_first = 0usize;
            for (pair_index, pair) in measured_order.chunks_exact(2).enumerate() {
                if pair_index % 2 == parity {
                    if pair[0] == Arm::Hit {
                        hit_first += 1;
                    } else {
                        miss_first += 1;
                    }
                }
            }
            assert_eq!(
                hit_first, miss_first,
                "physical-role stratum {parity} was not balanced"
            );
        }
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
