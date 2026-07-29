//! High-level entry point for the native `rostl` insertion timing experiment.
//!
//! The raw table and probe types remain private. Callers can select the record
//! monomorphization and run a validated schedule, but cannot use this seam to
//! reach the backend outside the qualification experiment.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{ExperimentPlan, Pair};

/// Which fixed-record insertion monomorphization to measure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RostlTimingRecordKind {
    /// The 38-byte address-directory record.
    Directory,
    /// The 82-byte address-event-page record.
    Event,
}

/// Which insertion operation each scheduled timing label executes.
///
/// [`Self::HitMiss`] measures the real hit/miss distinction. The forced modes
/// are null controls: the scheduler still emits balanced hit and miss labels,
/// but both labels execute the same insertion outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RostlTimingMode {
    /// Execute the operation named by each scheduled label.
    HitMiss,
    /// Execute a duplicate-key insertion for both scheduled labels.
    ForcedHit,
    /// Execute a missing-key insertion for both scheduled labels.
    ForcedMiss,
}

/// Why the native insertion timing probe could not run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RostlTimingError {
    /// The experiment needs `rostl-experimental` on Linux x86_64.
    UnsupportedPlatform,
    /// Capacity or occupancy cannot represent equal hit and miss arms.
    InvalidShape,
    /// A fresh table or one of its filler records could not be prepared.
    Setup,
    /// Linux scheduler counters were unavailable, invalid, or inconsistent.
    SchedulerStats,
    /// The timed insertion returned an outcome inconsistent with its arm.
    WrongOutcome,
    /// The long-lived probe did not observe exactly one hit and one miss label
    /// before a pair boundary, or its matched-state invariant drifted.
    PairState,
}

impl fmt::Display for RostlTimingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedPlatform => formatter.write_str(
                "rostl timing qualification requires rostl-experimental on Linux x86_64",
            ),
            Self::InvalidShape => formatter.write_str(
                "rostl timing shape requires a supported capacity and occupancy in 1..capacity",
            ),
            Self::Setup => formatter.write_str("rostl timing probe setup failed"),
            Self::SchedulerStats => {
                formatter.write_str("rostl timing scheduler counters were unavailable or invalid")
            }
            Self::WrongOutcome => {
                formatter.write_str("rostl timing probe observed an unexpected insertion outcome")
            }
            Self::PairState => {
                formatter.write_str("rostl timing probe pair-state invariant failed")
            }
        }
    }
}

impl std::error::Error for RostlTimingError {}

/// Scheduler contention conservatively bracketed around measured insertions.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RostlTimingSchedulerSummary {
    measurements: usize,
    timed_wall_nanos: u64,
    cpu_time_nanos: u64,
    runqueue_wait_nanos: u64,
    timeslices: u64,
    aggregate_runqueue_wait_ratio: f64,
    maximum_measurement_runqueue_wait_ratio: f64,
}

impl RostlTimingSchedulerSummary {
    /// Whether both aggregate and worst-measurement wait ratios meet a bound.
    pub fn admits(&self, max_runqueue_wait_ratio: f64) -> bool {
        max_runqueue_wait_ratio.is_finite()
            && (0.0..=1.0).contains(&max_runqueue_wait_ratio)
            && self.aggregate_runqueue_wait_ratio <= max_runqueue_wait_ratio
            && self.maximum_measurement_runqueue_wait_ratio <= max_runqueue_wait_ratio
    }
}

/// Raw pairs plus scheduler counters bracketing their timed regions.
#[derive(Debug, Clone, PartialEq)]
pub struct RostlTimingRun {
    pairs: Vec<Pair>,
    scheduler: RostlTimingSchedulerSummary,
}

impl RostlTimingRun {
    /// Separates the raw observations from their scheduler summary.
    pub fn into_parts(self) -> (Vec<Pair>, RostlTimingSchedulerSummary) {
        (self.pairs, self.scheduler)
    }
}

/// Runs one record kind against long-lived, logically matched tables.
///
/// The caller owns platform controls: it must check CPU affinity and machine
/// quiescence immediately before and after this call.
pub fn run_rostl_insert_timing(
    kind: RostlTimingRecordKind,
    capacity: usize,
    occupancy: usize,
    plan: &ExperimentPlan,
) -> Result<RostlTimingRun, RostlTimingError> {
    run_rostl_insert_timing_mode(kind, RostlTimingMode::HitMiss, capacity, occupancy, plan)
}

/// Runs one record kind in a selected real or null-control timing mode.
///
/// Pair fields retain their scheduled hit/miss labels in every mode. In a
/// forced mode those labels do not describe the executed insertion outcome;
/// both labels execute the operation selected by `mode`.
///
/// The caller owns platform controls: it must check CPU affinity and machine
/// quiescence immediately before and after this call.
pub fn run_rostl_insert_timing_mode(
    kind: RostlTimingRecordKind,
    mode: RostlTimingMode,
    capacity: usize,
    occupancy: usize,
    plan: &ExperimentPlan,
) -> Result<RostlTimingRun, RostlTimingError> {
    #[cfg(feature = "rostl-experimental")]
    {
        validate_rostl_timing_shape(kind, capacity, occupancy, plan)?;
        let mut probe = crate::layout::rostl_insert_timing_probe(
            kind,
            mode,
            capacity,
            occupancy,
            plan.total_pairs(),
        )?;
        let pairs = crate::timing_experiment::run(plan, &mut probe)?;
        let scheduler = summarize_rostl_timing_scheduler(&pairs)?;
        Ok(RostlTimingRun { pairs, scheduler })
    }

    #[cfg(not(feature = "rostl-experimental"))]
    {
        let _ = (kind, mode, capacity, occupancy, plan);
        Err(RostlTimingError::UnsupportedPlatform)
    }
}

/// Recomputes scheduler-contention evidence from retained timing pairs.
///
/// This pure replay path does not invoke the native timing probe. It rejects
/// empty inputs, missing per-arm scheduler counters, zero-duration
/// measurements, and arithmetic overflow.
pub fn summarize_rostl_timing_scheduler(
    pairs: &[Pair],
) -> Result<RostlTimingSchedulerSummary, RostlTimingError> {
    let mut measurements = 0usize;
    let mut timed_wall_nanos = 0u64;
    let mut cpu_time_nanos = 0u64;
    let mut runqueue_wait_nanos = 0u64;
    let mut timeslices = 0u64;
    let mut maximum_measurement_runqueue_wait_ratio = 0.0_f64;

    for pair in pairs {
        let (hit, miss) = pair
            .timed_scheduler_measurements()
            .ok_or(RostlTimingError::SchedulerStats)?;
        for (wall_nanos, delta) in [hit, miss] {
            measurements = measurements
                .checked_add(1)
                .ok_or(RostlTimingError::SchedulerStats)?;
            timed_wall_nanos = timed_wall_nanos
                .checked_add(wall_nanos)
                .ok_or(RostlTimingError::SchedulerStats)?;
            cpu_time_nanos = cpu_time_nanos
                .checked_add(delta.cpu_time_nanos)
                .ok_or(RostlTimingError::SchedulerStats)?;
            runqueue_wait_nanos = runqueue_wait_nanos
                .checked_add(delta.runqueue_wait_nanos)
                .ok_or(RostlTimingError::SchedulerStats)?;
            timeslices = timeslices
                .checked_add(delta.timeslices)
                .ok_or(RostlTimingError::SchedulerStats)?;
            if wall_nanos == 0 {
                return Err(RostlTimingError::SchedulerStats);
            }
            maximum_measurement_runqueue_wait_ratio = maximum_measurement_runqueue_wait_ratio
                .max(delta.runqueue_wait_nanos as f64 / wall_nanos as f64);
        }
    }

    if measurements == 0 || timed_wall_nanos == 0 {
        return Err(RostlTimingError::SchedulerStats);
    }
    Ok(RostlTimingSchedulerSummary {
        measurements,
        timed_wall_nanos,
        cpu_time_nanos,
        runqueue_wait_nanos,
        timeslices,
        aggregate_runqueue_wait_ratio: runqueue_wait_nanos as f64 / timed_wall_nanos as f64,
        maximum_measurement_runqueue_wait_ratio,
    })
}

/// Validates a native record kind, capacity, and occupancy without measuring.
pub fn validate_rostl_timing_shape(
    kind: RostlTimingRecordKind,
    capacity: usize,
    occupancy: usize,
    plan: &ExperimentPlan,
) -> Result<(), RostlTimingError> {
    #[cfg(feature = "rostl-experimental")]
    {
        let _ = kind;
        crate::layout::validate_rostl_insert_timing_shape(capacity, occupancy, plan.total_pairs())
    }

    #[cfg(not(feature = "rostl-experimental"))]
    {
        let _ = (kind, capacity, occupancy, plan);
        Err(RostlTimingError::UnsupportedPlatform)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::timing_equivalence::{ArmMeasurement, PairOrder, TimedSchedulerDelta};
    #[cfg(all(
        feature = "rostl-experimental",
        target_os = "linux",
        target_arch = "x86_64"
    ))]
    use crate::{EquivalenceBounds, TimingSeed, MINIMUM_PAIRS};

    #[test]
    fn timing_modes_use_stable_snake_case_names() -> Result<(), serde_json::Error> {
        for (mode, encoded) in [
            (RostlTimingMode::HitMiss, "\"hit_miss\""),
            (RostlTimingMode::ForcedHit, "\"forced_hit\""),
            (RostlTimingMode::ForcedMiss, "\"forced_miss\""),
        ] {
            assert_eq!(serde_json::to_string(&mode)?, encoded);
            assert_eq!(serde_json::from_str::<RostlTimingMode>(encoded)?, mode);
        }
        Ok(())
    }

    #[cfg(all(
        feature = "rostl-experimental",
        target_os = "linux",
        target_arch = "x86_64"
    ))]
    #[test]
    fn forced_modes_emit_complete_labelled_pairs_for_both_record_kinds(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let plan = ExperimentPlan::new(MINIMUM_PAIRS, 1, TimingSeed::new(0xfeed_cafe))?;

        for kind in [
            RostlTimingRecordKind::Directory,
            RostlTimingRecordKind::Event,
        ] {
            for mode in [RostlTimingMode::ForcedHit, RostlTimingMode::ForcedMiss] {
                let run = run_rostl_insert_timing_mode(kind, mode, 1_024, 7, &plan)?;
                let (pairs, _) = run.into_parts();
                assert_eq!(pairs.len(), MINIMUM_PAIRS);

                let encoded = serde_json::to_value(&pairs)?;
                let Some(encoded_pairs) = encoded.as_array() else {
                    panic!("timing pairs must serialize as an array");
                };
                let hit_first = encoded_pairs
                    .iter()
                    .filter(|pair| pair["order"] == "hit_first")
                    .count();
                let miss_first = encoded_pairs
                    .iter()
                    .filter(|pair| pair["order"] == "miss_first")
                    .count();

                assert_eq!(hit_first, MINIMUM_PAIRS / 2);
                assert_eq!(miss_first, MINIMUM_PAIRS / 2);
                assert!(encoded_pairs.iter().all(|pair| {
                    pair["hit_nanos"].as_u64().is_some()
                        && pair["miss_nanos"].as_u64().is_some()
                        && pair["hit_scheduler"].is_object()
                        && pair["miss_scheduler"].is_object()
                }));
            }
        }
        Ok(())
    }

    /// Runs both identical-operation controls through the production timing
    /// entry point and rejects gross label-dependent harness separation.
    ///
    /// Scheduled labels still select the matched physical table and retain the
    /// normal AB/BA lifecycle. The forced mode changes only the executed
    /// insertion outcome, so both labels perform the same logical operation.
    ///
    /// Ignored by default: it performs two full 500-pair schedules and must run
    /// only on a pinned, quiescent Linux host.
    #[cfg(all(
        feature = "rostl-experimental",
        target_os = "linux",
        target_arch = "x86_64"
    ))]
    #[test]
    #[ignore = "long-running calibration; run explicitly on a quiescent host"]
    fn production_forced_modes_stay_within_null_control_bounds(
    ) -> Result<(), Box<dyn std::error::Error>> {
        // With 500 balanced pairs, the order-conditioned contrasts have only
        // 250 samples per arm and a roughly 0.23 distribution-free confidence
        // floor. The CDF bound leaves about 0.17 empirical-distance headroom:
        // wide enough for a stable smoke control, but still able to reject
        // gross symmetric shape separation that AUC can miss.
        const MEAN_BOUND_NANOS: f64 = 1_000.0;
        const CDF_DISTANCE_BOUND: f64 = 0.40;
        const AUC_DEVIATION_BOUND: f64 = 0.10;

        let seed = TimingSeed::new(20_260_728);
        let plan = ExperimentPlan::new(500, 50, seed)?;
        let bounds = EquivalenceBounds::new(MEAN_BOUND_NANOS, CDF_DISTANCE_BOUND)?;

        for mode in [RostlTimingMode::ForcedMiss, RostlTimingMode::ForcedHit] {
            let run = run_rostl_insert_timing_mode(
                RostlTimingRecordKind::Directory,
                mode,
                1_024,
                256,
                &plan,
            )?;
            let (pairs, _) = run.into_parts();
            let report = crate::timing_equivalence::evaluate(&pairs, bounds, seed);

            println!(
                "null control mode={mode:?} auc={:.4} cdf={:.4} \
                 cdf_upper_95={:.4} mean={:.1}ns p={:.4}",
                report.classifier_auc(),
                report.empirical_cdf_distance(),
                report.cdf_distance_upper_95(),
                report.mean_difference_nanos(),
                report.permutation_p_value(),
            );

            assert!(
                report.bounds_satisfied(),
                "null control mode {mode:?} exceeded the predeclared mean or \
                 distribution bound: {report:?}"
            );

            let auc_deviation = (report.classifier_auc() - 0.5).abs();
            assert!(
                auc_deviation < AUC_DEVIATION_BOUND,
                "null control mode {mode:?} has AUC deviation \
                 {auc_deviation:.4}; rank separation remains uninterpretable"
            );
        }
        Ok(())
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn long_lived_probe_requires_pair_growth_headroom() {
        let plan = ExperimentPlan::new(3, 2, TimingSeed::new(7)).expect("valid pilot plan");

        assert_eq!(
            validate_rostl_timing_shape(RostlTimingRecordKind::Directory, 8, 3, &plan),
            Err(RostlTimingError::InvalidShape)
        );
        assert!(
            validate_rostl_timing_shape(RostlTimingRecordKind::Directory, 16, 3, &plan).is_ok()
        );
    }

    fn measured_pair(
        order: PairOrder,
        hit_scheduler: TimedSchedulerDelta,
        miss_scheduler: TimedSchedulerDelta,
    ) -> Pair {
        Pair::from_measurements(
            ArmMeasurement::with_scheduler(100, hit_scheduler),
            ArmMeasurement::with_scheduler(100, miss_scheduler),
            order,
        )
    }

    #[test]
    fn scheduler_summary_gates_aggregate_and_worst_measurement_wait() {
        let quiet = TimedSchedulerDelta {
            cpu_time_nanos: 90,
            runqueue_wait_nanos: 10,
            timeslices: 1,
        };
        let noisy = TimedSchedulerDelta {
            cpu_time_nanos: 60,
            runqueue_wait_nanos: 40,
            timeslices: 2,
        };
        let summary =
            summarize_rostl_timing_scheduler(&[measured_pair(PairOrder::HitFirst, quiet, noisy)])
                .expect("scheduler deltas are valid");

        assert_eq!(summary.aggregate_runqueue_wait_ratio, 0.25);
        assert_eq!(summary.maximum_measurement_runqueue_wait_ratio, 0.40);
        assert!(summary.admits(0.40));
        assert!(!summary.admits(0.39));
    }

    #[test]
    fn scheduler_summary_round_trips_through_json() -> Result<(), serde_json::Error> {
        let delta = TimedSchedulerDelta {
            cpu_time_nanos: 90,
            runqueue_wait_nanos: 10,
            timeslices: 1,
        };
        let summary =
            summarize_rostl_timing_scheduler(&[measured_pair(PairOrder::HitFirst, delta, delta)])
                .expect("scheduler deltas are valid");
        let encoded = serde_json::to_string(&summary)?;

        assert_eq!(
            serde_json::from_str::<RostlTimingSchedulerSummary>(&encoded)?,
            summary
        );
        Ok(())
    }

    #[test]
    fn scheduler_summary_rejects_unknown_fields() -> Result<(), serde_json::Error> {
        let delta = TimedSchedulerDelta {
            cpu_time_nanos: 90,
            runqueue_wait_nanos: 10,
            timeslices: 1,
        };
        let summary =
            summarize_rostl_timing_scheduler(&[measured_pair(PairOrder::HitFirst, delta, delta)])
                .expect("scheduler deltas are valid");
        let mut encoded = serde_json::to_value(summary)?;
        let Some(object) = encoded.as_object_mut() else {
            panic!("scheduler summary must serialize as an object");
        };
        object.insert("extra".to_owned(), serde_json::Value::Bool(true));

        assert!(serde_json::from_value::<RostlTimingSchedulerSummary>(encoded).is_err());
        Ok(())
    }

    #[test]
    fn scheduler_summary_rejects_pairs_without_timed_counters() {
        assert_eq!(
            summarize_rostl_timing_scheduler(&[Pair::new(100, 100, PairOrder::HitFirst)]),
            Err(RostlTimingError::SchedulerStats)
        );
    }
}
