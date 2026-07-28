//! Paired-timing equivalence statistics for access-path qualification.
//!
//! Phase 0 kill-gate 2 requires that a host observer cannot distinguish a hit
//! from a miss on the ORAM insertion path. Static codegen evidence must test
//! whether the secret reaches a branch; this module supplies the wall-clock
//! statistics for a paired experiment that tries, and should fail, to tell the
//! two apart.
//!
//! Everything here is pure and deterministic given a seed, so a published
//! result can be recomputed exactly from its recorded inputs. That is a
//! requirement for evidence, not a convenience: a qualification number nobody
//! can reproduce is not evidence.
//!
//! The platform-specific experiment driver that produces [`Pair`]s owns state
//! control, CPU pinning, warm-up, and randomised AB/BA ordering. This module
//! never measures anything itself and does not assume that sequential pairs
//! are statistically independent.
//!
//! # Reading the result
//!
//! Absence of a detected difference is not proof of obliviousness. The
//! equivalence bounds make the claim falsifiable: they state the largest mean
//! and CDF differences the experiment would have accepted as
//! "indistinguishable", and a result is only meaningful relative to those
//! bounds.
//! This bounds mean and single-threshold timing distinguishability; it does not
//! establish equivalence against every nonlinear classifier or host side
//! channel.

use std::fmt;

use serde::{Deserialize, Serialize};

/// The report's own power floor, from the kill-gate report's requirement of at
/// least 500 paired observations.
pub const MINIMUM_PAIRS: usize = 500;

const BOOTSTRAP_RESAMPLES: usize = 20_000;
const PERMUTATIONS: usize = 2_000;
/// Pooled, two order-conditioned, and two position-conditioned contrasts.
const QUALIFYING_CONTRASTS: f64 = 5.0;
/// Each contrast has one mean and one CDF bound.
const INFERENTIAL_BOUNDS: f64 = QUALIFYING_CONTRASTS * 2.0;
/// Bonferroni-adjusted two-sided tail for joint family-wise 95% coverage.
const TAIL: f64 = 0.025 / INFERENTIAL_BOUNDS;
/// Bonferroni-adjusted error budget, with a union bound over each pair of CDFs.
const CDF_ALPHA: f64 = 0.05 / INFERENTIAL_BOUNDS;
/// The balanced design places half of [`MINIMUM_PAIRS`] in each order.
const MINIMUM_PAIRS_PER_ORDER: usize = MINIMUM_PAIRS / 2;

/// Which arm was measured first in one timing pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PairOrder {
    /// The hit was measured before the miss.
    HitFirst,
    /// The miss was measured before the hit.
    MissFirst,
}

/// Scheduler-counter deltas bracketing one timed insertion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct TimedSchedulerDelta {
    pub(crate) cpu_time_nanos: u64,
    pub(crate) runqueue_wait_nanos: u64,
    pub(crate) timeslices: u64,
}

/// One arm measurement before the scheduler orders it into a pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ArmMeasurement {
    nanos: u64,
    scheduler: Option<TimedSchedulerDelta>,
}

impl ArmMeasurement {
    pub(crate) const fn duration_only(nanos: u64) -> Self {
        Self {
            nanos,
            scheduler: None,
        }
    }

    pub(crate) const fn with_scheduler(nanos: u64, scheduler: TimedSchedulerDelta) -> Self {
        Self {
            nanos,
            scheduler: Some(scheduler),
        }
    }
}

/// One paired observation: the same insertion performed against a present and
/// an absent record, under identical occupancy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pair {
    hit_nanos: u64,
    miss_nanos: u64,
    order: PairOrder,
    hit_scheduler: Option<TimedSchedulerDelta>,
    miss_scheduler: Option<TimedSchedulerDelta>,
}

impl Pair {
    /// Records a synthetic hit/miss timing pair without host scheduler data.
    ///
    /// Native probe output uses an internal constructor that also records
    /// scheduler counters bracketing each timed insertion.
    pub const fn new(hit_nanos: u64, miss_nanos: u64, order: PairOrder) -> Self {
        Self {
            hit_nanos,
            miss_nanos,
            order,
            hit_scheduler: None,
            miss_scheduler: None,
        }
    }

    pub(crate) const fn from_measurements(
        hit: ArmMeasurement,
        miss: ArmMeasurement,
        order: PairOrder,
    ) -> Self {
        Self {
            hit_nanos: hit.nanos,
            miss_nanos: miss.nanos,
            order,
            hit_scheduler: hit.scheduler,
            miss_scheduler: miss.scheduler,
        }
    }

    pub(crate) const fn timed_scheduler_measurements(
        &self,
    ) -> Option<((u64, TimedSchedulerDelta), (u64, TimedSchedulerDelta))> {
        match (self.hit_scheduler, self.miss_scheduler) {
            (Some(hit), Some(miss)) => Some(((self.hit_nanos, hit), (self.miss_nanos, miss))),
            _ => None,
        }
    }

    fn difference(self) -> f64 {
        self.hit_nanos as f64 - self.miss_nanos as f64
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
struct ContrastReport {
    hit_samples: usize,
    miss_samples: usize,
    mean_difference_nanos: f64,
    bootstrap_low_nanos: f64,
    bootstrap_high_nanos: f64,
    empirical_cdf_distance: f64,
    cdf_distance_upper_95: f64,
    meets_minimum_samples: bool,
    bounds_satisfied: bool,
}

/// Predeclared limits for mean drift and whole-distribution distinguishability.
///
/// Declaring these before measuring makes the result falsifiable. The
/// Kolmogorov-Smirnov distance covers every single-threshold timing classifier,
/// including distribution-shape differences for which AUC happens to be 0.5.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub struct EquivalenceBounds {
    mean_difference_nanos: f64,
    cdf_distance: f64,
}

impl EquivalenceBounds {
    /// Declares both bounds before the experiment runs.
    pub fn new(mean_difference_nanos: f64, cdf_distance: f64) -> Result<Self, BoundError> {
        if !mean_difference_nanos.is_finite() || mean_difference_nanos <= 0.0 {
            return Err(BoundError::MeanDifference);
        }
        if !cdf_distance.is_finite() || !(0.0..=1.0).contains(&cdf_distance) {
            return Err(BoundError::DistributionDistance);
        }
        Ok(Self {
            mean_difference_nanos,
            cdf_distance,
        })
    }
}

/// Why a timing-equivalence bound was invalid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoundError {
    /// The mean-difference limit was not finite and positive.
    MeanDifference,
    /// The CDF-distance limit was not finite or outside `[0, 1]`.
    DistributionDistance,
}

impl fmt::Display for BoundError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MeanDifference => {
                formatter.write_str("mean timing-equivalence bound must be finite and positive")
            }
            Self::DistributionDistance => {
                formatter.write_str("CDF timing-equivalence bound must be finite and within [0, 1]")
            }
        }
    }
}

impl std::error::Error for BoundError {}

/// The recorded seed, so a published result can be recomputed exactly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Seed(u64);

impl Seed {
    pub(crate) const fn value(self) -> u64 {
        self.0
    }

    /// Records the seed a published result can be recomputed from.
    pub const fn new(seed: u64) -> Self {
        Self(seed)
    }
}

/// The outcome of one paired equivalence experiment.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct EquivalenceReport {
    pairs: usize,
    mean_difference_nanos: f64,
    bootstrap_low_nanos: f64,
    bootstrap_high_nanos: f64,
    permutation_p_value: f64,
    classifier_auc: f64,
    empirical_cdf_distance: f64,
    cdf_distance_upper_95: f64,
    mean_equivalence_bound_nanos: f64,
    cdf_distance_bound: f64,
    meets_minimum_pairs: bool,
    order_balanced: bool,
    hit_first: ContrastReport,
    miss_first: ContrastReport,
    first_position: ContrastReport,
    second_position: ContrastReport,
    bounds_satisfied: bool,
    seed: Seed,
}

impl EquivalenceReport {
    /// How many paired observations the experiment collected.
    pub const fn pairs(&self) -> usize {
        self.pairs
    }

    /// Mean of hit minus miss, in nanoseconds. Negative means hits were faster.
    pub const fn mean_difference_nanos(&self) -> f64 {
        self.mean_difference_nanos
    }

    /// Nominal family-wise 95% percentile-bootstrap interval for the mean
    /// difference.
    pub const fn bootstrap_interval_nanos(&self) -> (f64, f64) {
        (self.bootstrap_low_nanos, self.bootstrap_high_nanos)
    }

    /// Sign-flip permutation p-value against the no-difference null.
    pub const fn permutation_p_value(&self) -> f64 {
        self.permutation_p_value
    }

    /// Area under the ROC curve for a timing-only hit/miss classifier. A value
    /// of 0.5 is a coin flip; both 0.0 and 1.0 are perfect rank separation. AUC
    /// is diagnostic because symmetric shape differences can still score 0.5;
    /// the CDF-distance confidence bound is the distribution qualification gate.
    pub const fn classifier_auc(&self) -> f64 {
        self.classifier_auc
    }

    /// Empirical Kolmogorov-Smirnov distance between hit and miss timings.
    pub const fn empirical_cdf_distance(&self) -> f64 {
        self.empirical_cdf_distance
    }

    /// Family-wise distribution-free 95% upper confidence limit for the true
    /// CDF distance.
    pub const fn cdf_distance_upper_95(&self) -> f64 {
        self.cdf_distance_upper_95
    }

    /// Whether the experiment met [`MINIMUM_PAIRS`].
    ///
    /// This is a sample-count floor, not a general claim of statistical power.
    pub const fn meets_minimum_pairs(&self) -> bool {
        self.meets_minimum_pairs
    }

    /// Whether hit-first and miss-first pair counts differ by at most one.
    pub const fn order_balanced(&self) -> bool {
        self.order_balanced
    }

    /// Whether the order was balanced and all pooled, order-conditioned, and
    /// position-conditioned contrasts met their predeclared bounds and sample
    /// floors.
    ///
    /// This is a statistical result only. It does not assert that the host
    /// controls required by the experiment driver were satisfied.
    pub const fn bounds_satisfied(&self) -> bool {
        self.bounds_satisfied
    }
}

/// Evaluates a paired experiment. Pure and deterministic given `seed`.
pub fn evaluate(pairs: &[Pair], bound: EquivalenceBounds, seed: Seed) -> EquivalenceReport {
    let differences: Vec<f64> = pairs.iter().map(|pair| pair.difference()).collect();
    let mean_difference_nanos = mean(&differences);
    let (bootstrap_low_nanos, bootstrap_high_nanos) = bootstrap_interval(&differences, seed);
    let permutation_p_value = permutation_p_value(&differences, mean_difference_nanos, seed);
    let classifier_auc = classifier_auc(pairs);
    let hits: Vec<u64> = pairs.iter().map(|pair| pair.hit_nanos).collect();
    let misses: Vec<u64> = pairs.iter().map(|pair| pair.miss_nanos).collect();
    let empirical_cdf_distance = empirical_cdf_distance(&hits, &misses);
    let cdf_distance_upper_95 =
        cdf_distance_upper_95(empirical_cdf_distance, hits.len(), misses.len());

    let hit_first_pairs: Vec<Pair> = pairs
        .iter()
        .copied()
        .filter(|pair| pair.order == PairOrder::HitFirst)
        .collect();
    let miss_first_pairs: Vec<Pair> = pairs
        .iter()
        .copied()
        .filter(|pair| pair.order == PairOrder::MissFirst)
        .collect();
    let hit_first = paired_contrast(
        &hit_first_pairs,
        bound,
        Seed(seed.0 ^ 0x6869_745f_6669_7273),
    );
    let miss_first = paired_contrast(
        &miss_first_pairs,
        bound,
        Seed(seed.0 ^ 0x6d69_7373_5f66_6972),
    );

    let first_position_hits: Vec<u64> = hit_first_pairs.iter().map(|pair| pair.hit_nanos).collect();
    let first_position_misses: Vec<u64> = miss_first_pairs
        .iter()
        .map(|pair| pair.miss_nanos)
        .collect();
    let second_position_hits: Vec<u64> =
        miss_first_pairs.iter().map(|pair| pair.hit_nanos).collect();
    let second_position_misses: Vec<u64> =
        hit_first_pairs.iter().map(|pair| pair.miss_nanos).collect();
    let first_position = unpaired_contrast(
        &first_position_hits,
        &first_position_misses,
        bound,
        Seed(seed.0 ^ 0x6669_7273_745f_706f),
    );
    let second_position = unpaired_contrast(
        &second_position_hits,
        &second_position_misses,
        bound,
        Seed(seed.0 ^ 0x7365_636f_6e64_706f),
    );

    let meets_minimum_pairs = pairs.len() >= MINIMUM_PAIRS;
    let order_balanced = hit_first_pairs.len().abs_diff(miss_first_pairs.len()) <= 1;
    let mean_satisfied = bootstrap_low_nanos >= -bound.mean_difference_nanos
        && bootstrap_high_nanos <= bound.mean_difference_nanos;
    let distribution_satisfied = cdf_distance_upper_95 <= bound.cdf_distance;
    let bounds_satisfied = meets_minimum_pairs
        && order_balanced
        && mean_satisfied
        && distribution_satisfied
        && hit_first.bounds_satisfied
        && miss_first.bounds_satisfied
        && first_position.bounds_satisfied
        && second_position.bounds_satisfied;

    EquivalenceReport {
        pairs: pairs.len(),
        mean_difference_nanos,
        bootstrap_low_nanos,
        bootstrap_high_nanos,
        permutation_p_value,
        classifier_auc,
        empirical_cdf_distance,
        cdf_distance_upper_95,
        mean_equivalence_bound_nanos: bound.mean_difference_nanos,
        cdf_distance_bound: bound.cdf_distance,
        meets_minimum_pairs,
        order_balanced,
        hit_first,
        miss_first,
        first_position,
        second_position,
        bounds_satisfied,
        seed,
    }
}

fn paired_contrast(pairs: &[Pair], bound: EquivalenceBounds, seed: Seed) -> ContrastReport {
    let hits: Vec<u64> = pairs.iter().map(|pair| pair.hit_nanos).collect();
    let misses: Vec<u64> = pairs.iter().map(|pair| pair.miss_nanos).collect();
    let differences: Vec<f64> = pairs.iter().map(|pair| pair.difference()).collect();
    contrast_report(
        &hits,
        &misses,
        bootstrap_interval(&differences, seed),
        bound,
    )
}

fn unpaired_contrast(
    hits: &[u64],
    misses: &[u64],
    bound: EquivalenceBounds,
    seed: Seed,
) -> ContrastReport {
    contrast_report(
        hits,
        misses,
        unpaired_bootstrap_interval(hits, misses, seed),
        bound,
    )
}

fn contrast_report(
    hits: &[u64],
    misses: &[u64],
    bootstrap_interval: (f64, f64),
    bound: EquivalenceBounds,
) -> ContrastReport {
    let mean_difference_nanos = mean_u64(hits) - mean_u64(misses);
    let empirical_cdf_distance = empirical_cdf_distance(hits, misses);
    let cdf_distance_upper_95 =
        cdf_distance_upper_95(empirical_cdf_distance, hits.len(), misses.len());
    let meets_minimum_samples =
        hits.len() >= MINIMUM_PAIRS_PER_ORDER && misses.len() >= MINIMUM_PAIRS_PER_ORDER;
    let mean_satisfied = bootstrap_interval.0 >= -bound.mean_difference_nanos
        && bootstrap_interval.1 <= bound.mean_difference_nanos;
    let distribution_satisfied = cdf_distance_upper_95 <= bound.cdf_distance;
    ContrastReport {
        hit_samples: hits.len(),
        miss_samples: misses.len(),
        mean_difference_nanos,
        bootstrap_low_nanos: bootstrap_interval.0,
        bootstrap_high_nanos: bootstrap_interval.1,
        empirical_cdf_distance,
        cdf_distance_upper_95,
        meets_minimum_samples,
        bounds_satisfied: meets_minimum_samples && mean_satisfied && distribution_satisfied,
    }
}

fn mean(values: &[f64]) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    values.iter().sum::<f64>() / values.len() as f64
}

fn mean_u64(values: &[u64]) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    values.iter().map(|value| *value as f64).sum::<f64>() / values.len() as f64
}

/// Percentile bootstrap over resampled paired differences.
fn bootstrap_interval(differences: &[f64], seed: Seed) -> (f64, f64) {
    if differences.is_empty() {
        return (0.0, 0.0);
    }
    let mut rng = Rng::new(seed.0 ^ 0x600d_5eed);
    let mut means = Vec::with_capacity(BOOTSTRAP_RESAMPLES);
    for _ in 0..BOOTSTRAP_RESAMPLES {
        let mut total = 0.0;
        for _ in 0..differences.len() {
            total += differences[rng.below(differences.len())];
        }
        means.push(total / differences.len() as f64);
    }
    means.sort_by(f64::total_cmp);
    (percentile(&means, TAIL), percentile(&means, 1.0 - TAIL))
}

/// Percentile bootstrap over two independently sampled timing groups.
fn unpaired_bootstrap_interval(hits: &[u64], misses: &[u64], seed: Seed) -> (f64, f64) {
    if hits.is_empty() || misses.is_empty() {
        return (0.0, 0.0);
    }
    let mut rng = Rng::new(seed.0 ^ 0x756e_7061_6972_6564);
    let mut differences = Vec::with_capacity(BOOTSTRAP_RESAMPLES);
    for _ in 0..BOOTSTRAP_RESAMPLES {
        let hit_total: f64 = (0..hits.len())
            .map(|_| hits[rng.below(hits.len())] as f64)
            .sum();
        let miss_total: f64 = (0..misses.len())
            .map(|_| misses[rng.below(misses.len())] as f64)
            .sum();
        differences.push(hit_total / hits.len() as f64 - miss_total / misses.len() as f64);
    }
    differences.sort_by(f64::total_cmp);
    (
        percentile(&differences, TAIL),
        percentile(&differences, 1.0 - TAIL),
    )
}

fn percentile(sorted: &[f64], quantile: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let last = sorted.len() - 1;
    let index = (last as f64 * quantile).round() as usize;
    sorted[index.min(last)]
}

/// Sign-flip permutation test for paired differences.
///
/// Under the null the sign of each difference is symmetric, so flipping signs
/// at random generates the null distribution of the mean.
fn permutation_p_value(differences: &[f64], observed_mean: f64, seed: Seed) -> f64 {
    if differences.is_empty() {
        return 1.0;
    }
    let mut rng = Rng::new(seed.0 ^ 0xfeed_face);
    let observed = observed_mean.abs();
    let mut at_least_as_extreme = 0usize;
    for _ in 0..PERMUTATIONS {
        let mut total = 0.0;
        for &difference in differences {
            total += if rng.next_u64() & 1 == 0 {
                difference
            } else {
                -difference
            };
        }
        if (total / differences.len() as f64).abs() >= observed {
            at_least_as_extreme += 1;
        }
    }
    // The +1 keeps the p-value strictly positive: no finite experiment can
    // report impossibility.
    (at_least_as_extreme + 1) as f64 / (PERMUTATIONS + 1) as f64
}

/// Mann-Whitney based AUC with tie-averaged ranks.
fn classifier_auc(pairs: &[Pair]) -> f64 {
    if pairs.is_empty() {
        return 0.5;
    }
    let hits = pairs.len();
    let misses = pairs.len();
    let mut observations: Vec<(f64, bool)> = Vec::with_capacity(hits + misses);
    for pair in pairs {
        observations.push((pair.hit_nanos as f64, true));
        observations.push((pair.miss_nanos as f64, false));
    }
    observations.sort_by(|a, b| a.0.total_cmp(&b.0));

    let mut hit_rank_total = 0.0;
    let mut index = 0;
    while index < observations.len() {
        let mut end = index;
        while end + 1 < observations.len() && observations[end + 1].0 == observations[index].0 {
            end += 1;
        }
        // Ranks are one-based; tied observations all take the group average.
        let average_rank = ((index + 1) + (end + 1)) as f64 / 2.0;
        for observation in &observations[index..=end] {
            if observation.1 {
                hit_rank_total += average_rank;
            }
        }
        index = end + 1;
    }

    let hits_f = hits as f64;
    let statistic = hit_rank_total - hits_f * (hits_f + 1.0) / 2.0;
    statistic / (hits_f * misses as f64)
}

/// Maximum difference between the empirical hit and miss CDFs.
fn empirical_cdf_distance(hits: &[u64], misses: &[u64]) -> f64 {
    if hits.is_empty() || misses.is_empty() {
        return 0.0;
    }

    let mut hits = hits.to_vec();
    let mut misses = misses.to_vec();
    hits.sort_unstable();
    misses.sort_unstable();

    let hit_count = hits.len() as f64;
    let miss_count = misses.len() as f64;
    let mut hit_index = 0usize;
    let mut miss_index = 0usize;
    let mut maximum = 0.0_f64;
    while hit_index < hits.len() || miss_index < misses.len() {
        let next = match (hits.get(hit_index), misses.get(miss_index)) {
            (Some(hit), Some(miss)) => (*hit).min(*miss),
            (Some(hit), None) => *hit,
            (None, Some(miss)) => *miss,
            (None, None) => break,
        };
        while hits.get(hit_index).is_some_and(|value| *value == next) {
            hit_index += 1;
        }
        while misses.get(miss_index).is_some_and(|value| *value == next) {
            miss_index += 1;
        }
        let distance = (hit_index as f64 / hit_count - miss_index as f64 / miss_count).abs();
        maximum = maximum.max(distance);
    }
    maximum
}

/// Dvoretzky-Kiefer-Wolfowitz upper bound with a union bound over both CDFs.
///
/// This assumes observations are independent across rounds. Paired hit and miss
/// observations within one round may remain dependent.
fn cdf_distance_upper_95(empirical_distance: f64, hit_samples: usize, miss_samples: usize) -> f64 {
    if hit_samples == 0 || miss_samples == 0 {
        return 1.0;
    }
    let epsilon = |samples: usize| ((4.0 / CDF_ALPHA).ln() / (2.0 * samples as f64)).sqrt();
    (empirical_distance + epsilon(hit_samples) + epsilon(miss_samples)).min(1.0)
}

/// Small deterministic xorshift, so a published result is reproducible from its
/// recorded seed without depending on an external generator's version.
pub(crate) struct Rng(u64);

impl Rng {
    pub(crate) fn new(seed: u64) -> Self {
        Self(
            seed.wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407)
                | 1,
        )
    }

    pub(crate) fn next_u64(&mut self) -> u64 {
        let mut state = self.0;
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        self.0 = state;
        state.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    pub(crate) fn below(&mut self, bound: usize) -> usize {
        (self.next_u64() % bound as u64) as usize
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bounds(mean_nanos: f64, cdf_distance: f64) -> EquivalenceBounds {
        EquivalenceBounds::new(mean_nanos, cdf_distance).expect("valid equivalence bounds")
    }

    fn pair(index: usize, hit_nanos: u64, miss_nanos: u64) -> Pair {
        let order = if index.is_multiple_of(2) {
            PairOrder::HitFirst
        } else {
            PairOrder::MissFirst
        };
        Pair::new(hit_nanos, miss_nanos, order)
    }

    /// Two constant, identical timings must produce an exactly zero difference,
    /// a p-value of one, and a coin-flip classifier.
    #[test]
    fn identical_timings_are_indistinguishable() {
        let pairs: Vec<Pair> = (0..500).map(|index| pair(index, 1_000, 1_000)).collect();
        let report = evaluate(&pairs, bounds(50.0, 0.24), Seed::new(7));
        assert_eq!(report.mean_difference_nanos(), 0.0);
        assert_eq!(report.classifier_auc(), 0.5);
        assert_eq!(report.empirical_cdf_distance(), 0.0);
        assert!((0.16..0.17).contains(&report.cdf_distance_upper_95()));
        assert!(report.bounds_satisfied());
    }

    /// A difference far larger than the bound must be detected: the interval
    /// excludes zero, the permutation test rejects, and equivalence fails.
    #[test]
    fn a_large_separation_is_detected() {
        let pairs: Vec<Pair> = (0..500)
            .map(|index| {
                let jitter = (index % 5) as u64;
                pair(index, 1_000 + jitter, 5_000 + jitter)
            })
            .collect();
        let report = evaluate(&pairs, bounds(50.0, 1.0), Seed::new(7));
        assert!(report.mean_difference_nanos() < -3_900.0);
        assert!(report.permutation_p_value() < 0.01);
        assert!(!report.bounds_satisfied());
        assert_eq!(report.classifier_auc(), 0.0);
    }

    /// A classifier that always separates one way scores 1.0, and the inverse
    /// scores 0.0; both are equally distinguishable diagnostics.
    #[test]
    fn classifier_auc_reports_separation_in_both_directions() {
        let hot: Vec<Pair> = (0..100).map(|index| pair(index, 9_000, 1_000)).collect();
        let cold: Vec<Pair> = (0..100).map(|index| pair(index, 1_000, 9_000)).collect();
        assert_eq!(
            evaluate(&hot, bounds(1.0, 1.0), Seed::new(1)).classifier_auc(),
            1.0
        );
        assert_eq!(
            evaluate(&cold, bounds(1.0, 1.0), Seed::new(1)).classifier_auc(),
            0.0
        );
    }

    /// AUC can be a coin flip even when the two timing distributions have
    /// disjoint shapes. The CDF gate must catch that classifier blind spot.
    #[test]
    fn symmetric_shape_separation_fails_distribution_equivalence() {
        let pairs: Vec<Pair> = (0..MINIMUM_PAIRS)
            .map(|index| {
                if index.is_multiple_of(2) {
                    pair(index, 500, 1_000)
                } else {
                    pair(index, 1_500, 1_000)
                }
            })
            .collect();
        let report = evaluate(&pairs, bounds(100.0, 0.25), Seed::new(8));

        assert_eq!(report.mean_difference_nanos(), 0.0);
        assert_eq!(report.classifier_auc(), 0.5);
        assert_eq!(report.empirical_cdf_distance(), 0.5);
        assert!(!report.bounds_satisfied());
    }

    #[test]
    fn cdf_confidence_limit_enforces_the_sample_size_power_floor() {
        let pairs: Vec<Pair> = (0..MINIMUM_PAIRS)
            .map(|index| pair(index, 1_000, 1_000))
            .collect();
        assert!(evaluate(&pairs, bounds(1.0, 0.24), Seed::new(1)).bounds_satisfied());
        assert!(!evaluate(&pairs, bounds(1.0, 0.23), Seed::new(1)).bounds_satisfied());
    }

    #[test]
    fn empirical_cdf_distance_advances_ties_together() {
        assert_eq!(empirical_cdf_distance(&[1, 2], &[2, 3]), 0.5);
    }

    #[test]
    fn invalid_equivalence_bounds_are_refused() {
        for invalid in [f64::NAN, f64::INFINITY, -1.0, 0.0] {
            assert_eq!(
                EquivalenceBounds::new(invalid, 0.2),
                Err(BoundError::MeanDifference)
            );
        }
        for invalid in [f64::NAN, f64::INFINITY, -0.1, 1.1] {
            assert_eq!(
                EquivalenceBounds::new(1.0, invalid),
                Err(BoundError::DistributionDistance)
            );
        }
        assert!(EquivalenceBounds::new(1.0, 0.0).is_ok());
        assert!(EquivalenceBounds::new(1.0, 1.0).is_ok());
    }

    /// The same seed and inputs must reproduce a published result exactly.
    #[test]
    fn results_are_reproducible_from_the_recorded_seed() {
        let pairs: Vec<Pair> = (0..300)
            .map(|index| {
                pair(
                    index,
                    1_000 + (index % 17) as u64,
                    1_000 + (index % 19) as u64,
                )
            })
            .collect();
        let first = evaluate(&pairs, bounds(25.0, 1.0), Seed::new(42));
        let second = evaluate(&pairs, bounds(25.0, 1.0), Seed::new(42));
        assert_eq!(first, second);

        let other = evaluate(&pairs, bounds(25.0, 1.0), Seed::new(43));
        assert_ne!(
            first.bootstrap_interval_nanos(),
            other.bootstrap_interval_nanos()
        );
    }

    /// Equivalence requires the whole interval inside the bound, so a small but
    /// real difference is not laundered into a pass by widening the bound only
    /// far enough to cover the point estimate.
    #[test]
    fn equivalence_requires_the_interval_inside_the_bound() {
        let pairs: Vec<Pair> = (0..500)
            .map(|index| pair(index, 1_000, 1_040 + (index % 21) as u64))
            .collect();
        let mean = evaluate(&pairs, bounds(10_000.0, 1.0), Seed::new(3))
            .mean_difference_nanos()
            .abs();
        // A bound just above the point estimate must still fail, because the
        // interval reaches roughly half a nanosecond past the mean.
        let tight = evaluate(&pairs, bounds(mean + 0.1, 1.0), Seed::new(3));
        assert!(!tight.bounds_satisfied());
        let generous = evaluate(&pairs, bounds(mean * 4.0, 1.0), Seed::new(3));
        assert!(generous.bounds_satisfied());
    }

    #[test]
    fn reversing_an_arm_effect_by_pair_order_cannot_cancel_into_a_pass() {
        let pairs: Vec<Pair> = (0..MINIMUM_PAIRS)
            .map(|index| {
                if index.is_multiple_of(2) {
                    pair(index, 900, 1_100)
                } else {
                    pair(index, 1_100, 900)
                }
            })
            .collect();
        let report = evaluate(&pairs, bounds(25.0, 0.25), Seed::new(4));

        assert_eq!(report.mean_difference_nanos(), 0.0);
        assert_eq!(report.classifier_auc(), 0.5);
        assert_eq!(report.empirical_cdf_distance(), 0.0);
        assert!(!report.hit_first.bounds_satisfied);
        assert!(!report.miss_first.bounds_satisfied);
        assert!(report.first_position.bounds_satisfied);
        assert!(report.second_position.bounds_satisfied);
        assert!(!report.bounds_satisfied());
    }

    #[test]
    fn an_arm_by_measurement_position_effect_cannot_cancel_into_a_pass() {
        let pairs: Vec<Pair> = (0..MINIMUM_PAIRS)
            .map(|index| {
                if index.is_multiple_of(2) {
                    pair(index, 900, 900)
                } else {
                    pair(index, 1_100, 1_100)
                }
            })
            .collect();
        let report = evaluate(&pairs, bounds(25.0, 0.25), Seed::new(5));

        assert_eq!(report.mean_difference_nanos(), 0.0);
        assert_eq!(report.classifier_auc(), 0.5);
        assert_eq!(report.empirical_cdf_distance(), 0.0);
        assert!(report.hit_first.bounds_satisfied);
        assert!(report.miss_first.bounds_satisfied);
        assert!(!report.first_position.bounds_satisfied);
        assert!(!report.second_position.bounds_satisfied);
        assert!(!report.bounds_satisfied());
    }

    /// An experiment with too few pairs cannot qualify anything, and must say
    /// so rather than reporting a confident-looking number.
    #[test]
    fn an_underpowered_experiment_is_refused() {
        let pairs: Vec<Pair> = (0..MINIMUM_PAIRS - 1)
            .map(|index| pair(index, 10, 10))
            .collect();
        let report = evaluate(&pairs, bounds(1.0, 1.0), Seed::new(1));
        assert!(!report.meets_minimum_pairs());
        assert!(!report.bounds_satisfied());
    }

    #[test]
    fn an_imbalanced_order_schedule_is_refused() {
        let mut pairs: Vec<Pair> = (0..MINIMUM_PAIRS_PER_ORDER + 2)
            .map(|_| Pair::new(10, 10, PairOrder::HitFirst))
            .collect();
        pairs.extend((0..MINIMUM_PAIRS_PER_ORDER).map(|_| Pair::new(10, 10, PairOrder::MissFirst)));

        let report = evaluate(&pairs, bounds(1.0, 0.24), Seed::new(1));
        assert!(report.meets_minimum_pairs());
        assert!(!report.order_balanced());
        assert!(!report.bounds_satisfied());
    }

    #[test]
    fn an_empty_experiment_does_not_panic_or_claim_equivalence() {
        let report = evaluate(&[], bounds(1.0, 1.0), Seed::new(1));
        assert!(!report.bounds_satisfied());
        assert!(!report.meets_minimum_pairs());
        assert_eq!(report.pairs(), 0);
    }
}
