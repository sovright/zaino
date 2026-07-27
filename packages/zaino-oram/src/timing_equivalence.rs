//! Paired-timing equivalence statistics for access-path qualification.
//!
//! Phase 0 kill-gate 2 requires that a host observer cannot distinguish a hit
//! from a miss on the ORAM insertion path. Static codegen evidence shows the
//! secret reaches no branch; this module supplies the *dynamic* half — the
//! statistics for a paired experiment that tries, and should fail, to tell the
//! two apart by wall-clock time.
//!
//! Everything here is pure and deterministic given a seed, so a published
//! result can be recomputed exactly from its recorded inputs. That is a
//! requirement for evidence, not a convenience: a qualification number nobody
//! can reproduce is not evidence.
//!
//! The experiment driver that produces [`Pair`]s — fresh equal-occupancy
//! workers, CPU pinning, warm-up, randomised AB/BA ordering — is separate and
//! platform-specific. This module never measures anything itself.
//!
//! # Reading the result
//!
//! Absence of a detected difference is not proof of obliviousness. The
//! equivalence bound makes the claim falsifiable: it states the largest
//! difference the experiment would have accepted as "indistinguishable", and a
//! result is only meaningful relative to that bound.

use serde::{Deserialize, Serialize};

/// The report's own power floor, from the kill-gate report's requirement of at
/// least 500 paired observations.
pub const MINIMUM_PAIRS: usize = 500;

const BOOTSTRAP_RESAMPLES: usize = 2_000;
const PERMUTATIONS: usize = 2_000;
/// Two-sided 95% interval.
const TAIL: f64 = 0.025;

/// One paired observation: the same insertion performed against a present and
/// an absent record, under identical occupancy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pair {
    hit_nanos: u64,
    miss_nanos: u64,
}

impl Pair {
    /// Records one hit/miss timing pair, in nanoseconds.
    pub const fn new(hit_nanos: u64, miss_nanos: u64) -> Self {
        Self {
            hit_nanos,
            miss_nanos,
        }
    }

    fn difference(self) -> f64 {
        self.hit_nanos as f64 - self.miss_nanos as f64
    }
}

/// The largest mean difference the experiment will accept as indistinguishable.
///
/// Declaring this before measuring is what makes the result falsifiable: a
/// "no difference detected" claim means nothing without the size of difference
/// the experiment could have detected.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct EquivalenceBound(f64);

impl EquivalenceBound {
    /// Declares the bound, in nanoseconds, before the experiment runs.
    pub const fn new(nanos: f64) -> Self {
        Self(nanos)
    }
}

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
    equivalence_bound_nanos: f64,
    sufficiently_powered: bool,
    equivalent: bool,
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

    /// Percentile bootstrap 95% interval for the mean difference.
    pub const fn bootstrap_interval_nanos(&self) -> (f64, f64) {
        (self.bootstrap_low_nanos, self.bootstrap_high_nanos)
    }

    /// Sign-flip permutation p-value against the no-difference null.
    pub const fn permutation_p_value(&self) -> f64 {
        self.permutation_p_value
    }

    /// Area under the ROC curve for a timing-only hit/miss classifier. A value
    /// of 0.5 is a coin flip; both 0.0 and 1.0 are perfect separation, which is
    /// why equivalence judges the distance from 0.5.
    pub const fn classifier_auc(&self) -> f64 {
        self.classifier_auc
    }

    /// Whether the experiment met [`MINIMUM_PAIRS`].
    pub const fn sufficiently_powered(&self) -> bool {
        self.sufficiently_powered
    }

    /// True only when the experiment had enough pairs and the whole bootstrap
    /// interval lies inside the declared bound. Never true for an empty or
    /// underpowered experiment.
    pub const fn equivalent(&self) -> bool {
        self.equivalent
    }
}

/// Evaluates a paired experiment. Pure and deterministic given `seed`.
pub fn evaluate(pairs: &[Pair], bound: EquivalenceBound, seed: Seed) -> EquivalenceReport {
    let differences: Vec<f64> = pairs.iter().map(|pair| pair.difference()).collect();
    let mean_difference_nanos = mean(&differences);
    let (bootstrap_low_nanos, bootstrap_high_nanos) = bootstrap_interval(&differences, seed);
    let permutation_p_value = permutation_p_value(&differences, mean_difference_nanos, seed);
    let classifier_auc = classifier_auc(pairs);

    let sufficiently_powered = pairs.len() >= MINIMUM_PAIRS;
    let equivalent =
        sufficiently_powered && bootstrap_low_nanos >= -bound.0 && bootstrap_high_nanos <= bound.0;

    EquivalenceReport {
        pairs: pairs.len(),
        mean_difference_nanos,
        bootstrap_low_nanos,
        bootstrap_high_nanos,
        permutation_p_value,
        classifier_auc,
        equivalence_bound_nanos: bound.0,
        sufficiently_powered,
        equivalent,
        seed,
    }
}

fn mean(values: &[f64]) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    values.iter().sum::<f64>() / values.len() as f64
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

    /// Two constant, identical timings must produce an exactly zero difference,
    /// a p-value of one, and a coin-flip classifier.
    #[test]
    fn identical_timings_are_indistinguishable() {
        let pairs: Vec<Pair> = (0..500).map(|_| Pair::new(1_000, 1_000)).collect();
        let report = evaluate(&pairs, EquivalenceBound::new(50.0), Seed::new(7));
        assert_eq!(report.mean_difference_nanos(), 0.0);
        assert_eq!(report.classifier_auc(), 0.5);
        assert!(report.equivalent());
    }

    /// A difference far larger than the bound must be detected: the interval
    /// excludes zero, the permutation test rejects, and equivalence fails.
    #[test]
    fn a_large_separation_is_detected() {
        let pairs: Vec<Pair> = (0..500u64)
            .map(|i| Pair::new(1_000 + (i % 5), 5_000 + (i % 5)))
            .collect();
        let report = evaluate(&pairs, EquivalenceBound::new(50.0), Seed::new(7));
        assert!(report.mean_difference_nanos() < -3_900.0);
        assert!(report.permutation_p_value() < 0.01);
        assert!(!report.equivalent());
        assert_eq!(report.classifier_auc(), 0.0);
    }

    /// A classifier that always separates one way scores 1.0, and the inverse
    /// scores 0.0; both are equally distinguishable, which is why the report
    /// judges |AUC - 0.5| rather than AUC itself.
    #[test]
    fn classifier_auc_reports_separation_in_both_directions() {
        let hot: Vec<Pair> = (0..100).map(|_| Pair::new(9_000, 1_000)).collect();
        let cold: Vec<Pair> = (0..100).map(|_| Pair::new(1_000, 9_000)).collect();
        assert_eq!(
            evaluate(&hot, EquivalenceBound::new(1.0), Seed::new(1)).classifier_auc(),
            1.0
        );
        assert_eq!(
            evaluate(&cold, EquivalenceBound::new(1.0), Seed::new(1)).classifier_auc(),
            0.0
        );
    }

    /// The same seed and inputs must reproduce a published result exactly.
    #[test]
    fn results_are_reproducible_from_the_recorded_seed() {
        let pairs: Vec<Pair> = (0..300u64)
            .map(|i| Pair::new(1_000 + (i % 17), 1_000 + (i % 19)))
            .collect();
        let first = evaluate(&pairs, EquivalenceBound::new(25.0), Seed::new(42));
        let second = evaluate(&pairs, EquivalenceBound::new(25.0), Seed::new(42));
        assert_eq!(first, second);

        let other = evaluate(&pairs, EquivalenceBound::new(25.0), Seed::new(43));
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
        let pairs: Vec<Pair> = (0..500u64)
            .map(|i| Pair::new(1_000, 1_040 + (i % 21)))
            .collect();
        let mean = evaluate(&pairs, EquivalenceBound::new(10_000.0), Seed::new(3))
            .mean_difference_nanos()
            .abs();
        // A bound just above the point estimate must still fail, because the
        // interval reaches roughly half a nanosecond past the mean.
        let tight = evaluate(&pairs, EquivalenceBound::new(mean + 0.1), Seed::new(3));
        assert!(!tight.equivalent());
        let generous = evaluate(&pairs, EquivalenceBound::new(mean * 4.0), Seed::new(3));
        assert!(generous.equivalent());
    }

    /// An experiment with too few pairs cannot qualify anything, and must say
    /// so rather than reporting a confident-looking number.
    #[test]
    fn an_underpowered_experiment_is_refused() {
        let pairs: Vec<Pair> = (0..MINIMUM_PAIRS - 1).map(|_| Pair::new(10, 10)).collect();
        let report = evaluate(&pairs, EquivalenceBound::new(1.0), Seed::new(1));
        assert!(!report.sufficiently_powered());
        assert!(!report.equivalent());
    }

    #[test]
    fn an_empty_experiment_does_not_panic_or_claim_equivalence() {
        let report = evaluate(&[], EquivalenceBound::new(1.0), Seed::new(1));
        assert!(!report.equivalent());
        assert!(!report.sufficiently_powered());
        assert_eq!(report.pairs(), 0);
    }
}
