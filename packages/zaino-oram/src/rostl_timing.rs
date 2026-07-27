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
        }
    }
}

impl std::error::Error for RostlTimingError {}

/// Scheduler contention conservatively bracketed around measured insertions.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
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

/// Runs one record kind against fresh equal-occupancy tables.
///
/// The caller owns platform controls: it must check CPU affinity and machine
/// quiescence immediately before and after this call.
pub fn run_rostl_insert_timing(
    kind: RostlTimingRecordKind,
    capacity: usize,
    occupancy: usize,
    plan: &ExperimentPlan,
) -> Result<RostlTimingRun, RostlTimingError> {
    #[cfg(feature = "rostl-experimental")]
    {
        let mut probe = crate::layout::rostl_insert_timing_probe(kind, capacity, occupancy)?;
        let pairs = crate::timing_experiment::run(plan, &mut probe)?;
        let scheduler = summarize_scheduler(&pairs)?;
        Ok(RostlTimingRun { pairs, scheduler })
    }

    #[cfg(not(feature = "rostl-experimental"))]
    {
        let _ = (kind, capacity, occupancy, plan);
        Err(RostlTimingError::UnsupportedPlatform)
    }
}

#[cfg(feature = "rostl-experimental")]
fn summarize_scheduler(pairs: &[Pair]) -> Result<RostlTimingSchedulerSummary, RostlTimingError> {
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
) -> Result<(), RostlTimingError> {
    #[cfg(feature = "rostl-experimental")]
    {
        crate::layout::rostl_insert_timing_probe(kind, capacity, occupancy).map(|_| ())
    }

    #[cfg(not(feature = "rostl-experimental"))]
    {
        let _ = (kind, capacity, occupancy);
        Err(RostlTimingError::UnsupportedPlatform)
    }
}

#[cfg(all(test, feature = "rostl-experimental"))]
mod tests {
    use super::*;
    use crate::timing_equivalence::{ArmMeasurement, PairOrder, TimedSchedulerDelta};

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
        let summary = summarize_scheduler(&[measured_pair(PairOrder::HitFirst, quiet, noisy)])
            .expect("scheduler deltas are valid");

        assert_eq!(summary.aggregate_runqueue_wait_ratio, 0.25);
        assert_eq!(summary.maximum_measurement_runqueue_wait_ratio, 0.40);
        assert!(summary.admits(0.40));
        assert!(!summary.admits(0.39));
    }

    #[test]
    fn scheduler_summary_rejects_pairs_without_timed_counters() {
        assert_eq!(
            summarize_scheduler(&[Pair::new(100, 100, PairOrder::HitFirst)]),
            Err(RostlTimingError::SchedulerStats)
        );
    }
}
