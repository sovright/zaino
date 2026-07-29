//! Shared synchronous execution driver for Gate 2 timing evidence.

use std::{error::Error, fmt, fs};

use serde::{Deserialize, Serialize};
use zaino_oram::{
    evaluate_timing_equivalence, run_rostl_insert_timing_mode, single_allowed_cpu,
    validate_rostl_timing_shape, EquivalenceBounds, EquivalenceReport, ExperimentPlan, Pair,
    Quiescence, QuiescencePolicy, RostlTimingMode, RostlTimingRecordKind,
    RostlTimingSchedulerSummary, TimingSeed, MINIMUM_PAIRS,
};

use crate::timing_contract::{
    derive_seed, occupancy_window, table_set_relation, timed_operation_model,
    validate_evidence_intent, EvidenceIntent, OccupancyWindow, DIRECTORY_RECORD_MODEL,
    DIRECTORY_REPORT_SEED_DOMAIN, DIRECTORY_SCHEDULE_SEED_DOMAIN, EVENT_RECORD_MODEL,
    EVENT_REPORT_SEED_DOMAIN, EVENT_SCHEDULE_SEED_DOMAIN, LABEL_ASSIGNMENT, ORDER_BLOCKING,
    STATE_CONTROL, STATISTICAL_SCOPE, TARGET_PROJECTION_MODEL, TIMING_EVIDENCE_SCHEMA,
};

pub(crate) type TimingDriverResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

/// Fully predeclared inputs for one independent timing-matrix cell.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TimingRunInputs {
    mode: RostlTimingMode,
    evidence_intent: EvidenceIntent,
    pairs: usize,
    warmup_pairs: usize,
    directory_capacity: usize,
    directory_initial_occupancy: usize,
    event_capacity: usize,
    event_initial_occupancy: usize,
    mean_bound_nanos: f64,
    cdf_distance_bound: f64,
    max_load_average_1m: f64,
    max_competing_processes: usize,
    max_runqueue_wait_ratio: f64,
    seed: u64,
}

// This source is compiled into both binaries; the manifest runner consumes
// accessors that the standalone driver intentionally does not need.
#[allow(dead_code)]
impl TimingRunInputs {
    /// Constructs the exact input contract consumed by the synchronous driver.
    #[allow(clippy::too_many_arguments)]
    pub(crate) const fn new(
        mode: RostlTimingMode,
        evidence_intent: EvidenceIntent,
        pairs: usize,
        warmup_pairs: usize,
        directory_capacity: usize,
        directory_initial_occupancy: usize,
        event_capacity: usize,
        event_initial_occupancy: usize,
        mean_bound_nanos: f64,
        cdf_distance_bound: f64,
        max_load_average_1m: f64,
        max_competing_processes: usize,
        max_runqueue_wait_ratio: f64,
        seed: u64,
    ) -> Self {
        Self {
            mode,
            evidence_intent,
            pairs,
            warmup_pairs,
            directory_capacity,
            directory_initial_occupancy,
            event_capacity,
            event_initial_occupancy,
            mean_bound_nanos,
            cdf_distance_bound,
            max_load_average_1m,
            max_competing_processes,
            max_runqueue_wait_ratio,
            seed,
        }
    }

    pub(crate) const fn mode(&self) -> RostlTimingMode {
        self.mode
    }

    pub(crate) const fn evidence_intent(&self) -> EvidenceIntent {
        self.evidence_intent
    }

    pub(crate) const fn pairs(&self) -> usize {
        self.pairs
    }

    pub(crate) const fn warmup_pairs(&self) -> usize {
        self.warmup_pairs
    }

    pub(crate) const fn directory_capacity(&self) -> usize {
        self.directory_capacity
    }

    pub(crate) const fn directory_initial_occupancy(&self) -> usize {
        self.directory_initial_occupancy
    }

    pub(crate) const fn event_capacity(&self) -> usize {
        self.event_capacity
    }

    pub(crate) const fn event_initial_occupancy(&self) -> usize {
        self.event_initial_occupancy
    }

    pub(crate) const fn mean_bound_nanos(&self) -> f64 {
        self.mean_bound_nanos
    }

    pub(crate) const fn cdf_distance_bound(&self) -> f64 {
        self.cdf_distance_bound
    }

    pub(crate) const fn max_load_average_1m(&self) -> f64 {
        self.max_load_average_1m
    }

    pub(crate) const fn max_competing_processes(&self) -> usize {
        self.max_competing_processes
    }

    pub(crate) const fn max_runqueue_wait_ratio(&self) -> f64 {
        self.max_runqueue_wait_ratio
    }

    pub(crate) const fn seed(&self) -> u64 {
        self.seed
    }

    pub(crate) fn validate_contract(&self) -> TimingDriverResult<()> {
        if !cfg!(all(target_os = "linux", target_arch = "x86_64")) {
            return Err(TimingDriverError::UnsupportedPlatform.into());
        }
        if !self.max_load_average_1m.is_finite() || self.max_load_average_1m < 0.0 {
            return Err(TimingDriverError::InvalidQuiescencePolicy.into());
        }
        if !self.max_runqueue_wait_ratio.is_finite()
            || !(0.0..=1.0).contains(&self.max_runqueue_wait_ratio)
        {
            return Err(TimingDriverError::InvalidRunqueueWaitPolicy.into());
        }
        validate_evidence_intent(self.evidence_intent, self.pairs, self.warmup_pairs)?;

        let directory_plan = self.directory_plan()?;
        let event_plan = self.event_plan()?;
        validate_rostl_timing_shape(
            RostlTimingRecordKind::Directory,
            self.directory_capacity,
            self.directory_initial_occupancy,
            &directory_plan,
        )?;
        validate_rostl_timing_shape(
            RostlTimingRecordKind::Event,
            self.event_capacity,
            self.event_initial_occupancy,
            &event_plan,
        )?;
        let _ = EquivalenceBounds::new(self.mean_bound_nanos, self.cdf_distance_bound)?;
        Ok(())
    }

    fn directory_plan(&self) -> TimingDriverResult<ExperimentPlan> {
        Ok(ExperimentPlan::new(
            self.pairs,
            self.warmup_pairs,
            TimingSeed::new(derive_seed(self.seed, DIRECTORY_SCHEDULE_SEED_DOMAIN)),
        )?)
    }

    fn event_plan(&self) -> TimingDriverResult<ExperimentPlan> {
        Ok(ExperimentPlan::new(
            self.pairs,
            self.warmup_pairs,
            TimingSeed::new(derive_seed(self.seed, EVENT_SCHEDULE_SEED_DOMAIN)),
        )?)
    }
}

/// A timing cell whose complete fallible preflight has passed.
///
/// Constructing this value does not allocate an ORAM. The first ORAM
/// allocation remains the first `run_rostl_insert_timing_mode` call in
/// [`execute_prepared_timing_run`].
pub(crate) struct PreparedTimingRun {
    inputs: TimingRunInputs,
    directory_plan: ExperimentPlan,
    event_plan: ExperimentPlan,
    directory_occupancy: OccupancyWindow,
    event_occupancy: OccupancyWindow,
    bounds: EquivalenceBounds,
    policy: QuiescencePolicy,
    before: EnvironmentSnapshot,
    pinned_cpu: u32,
}

#[allow(dead_code)]
impl PreparedTimingRun {
    pub(crate) const fn pinned_cpu(&self) -> u32 {
        self.pinned_cpu
    }

    pub(crate) fn cpus_allowed_list(&self) -> &str {
        &self.before.cpus_allowed_list
    }

    pub(crate) fn inputs(&self) -> &TimingRunInputs {
        &self.inputs
    }
}

/// Exact raw-v3 bytes and the process outcome for one completed timing cell.
pub(crate) struct CompletedTimingRun {
    raw_v3_bytes: Vec<u8>,
    outcome: RunOutcome,
}

#[allow(dead_code)]
impl CompletedTimingRun {
    pub(crate) fn raw_v3_bytes(&self) -> &[u8] {
        &self.raw_v3_bytes
    }

    pub(crate) const fn outcome(&self) -> RunOutcome {
        self.outcome
    }

    pub(crate) fn into_parts(self) -> (Vec<u8>, RunOutcome) {
        (self.raw_v3_bytes, self.outcome)
    }
}

/// Result of execution after a caller-provided durable-start commit.
#[allow(dead_code)]
pub(crate) enum StartedExecution<T, R = CompletedTimingRun> {
    Completed {
        started: T,
        completed: R,
    },
    Failed {
        started: T,
        source: Box<dyn Error + Send + Sync>,
    },
}

/// Commits a caller-defined durable start token before entering ORAM setup.
///
/// If `mark_started` fails, this function returns without invoking the timing
/// executor. Once it succeeds, every execution outcome carries the returned
/// token so a caller can bind the corresponding terminal record.
#[allow(dead_code)]
pub(crate) fn start_and_execute_timing_run<T, E>(
    prepared: PreparedTimingRun,
    mark_started: impl FnOnce(&PreparedTimingRun) -> Result<T, E>,
) -> Result<StartedExecution<T>, E> {
    start_then_execute(prepared, mark_started, execute_prepared_timing_run)
}

fn start_then_execute<C, T, E, R>(
    context: C,
    mark_started: impl FnOnce(&C) -> Result<T, E>,
    execute: impl FnOnce(C) -> TimingDriverResult<R>,
) -> Result<StartedExecution<T, R>, E> {
    let started = mark_started(&context)?;
    Ok(match execute(context) {
        Ok(completed) => StartedExecution::Completed { started, completed },
        Err(source) => StartedExecution::Failed { started, source },
    })
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EnvironmentSnapshot {
    pub(crate) cpus_allowed_list: String,
    pub(crate) allowed_cpu: Option<u32>,
    pub(crate) quiescence: Quiescence,
    pub(crate) scheduler_stats_enabled: bool,
}

#[derive(Debug, Serialize)]
pub(crate) struct RecordEvidence {
    pub(crate) kind: RostlTimingRecordKind,
    pub(crate) capacity: usize,
    pub(crate) initial_occupancy: usize,
    pub(crate) measured_start_occupancy: usize,
    pub(crate) measured_last_pre_occupancy: usize,
    pub(crate) final_occupancy: usize,
    pub(crate) growth_per_pair: usize,
    pub(crate) table_count: usize,
    pub(crate) state_control: &'static str,
    pub(crate) label_assignment: &'static str,
    pub(crate) order_blocking: &'static str,
    pub(crate) record_model: &'static str,
    pub(crate) plan: ExperimentPlan,
    pub(crate) report_seed: TimingSeed,
    pub(crate) raw_pairs: Vec<Pair>,
    pub(crate) report: EquivalenceReport,
    pub(crate) timed_scheduler: RostlTimingSchedulerSummary,
    pub(crate) scheduler_admitted: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EnvironmentAdmission {
    pub(crate) before_quiescence_admitted: bool,
    pub(crate) between_records_quiescence_admitted: bool,
    pub(crate) after_quiescence_admitted: bool,
    pub(crate) affinity_stable: bool,
    pub(crate) scheduler_stats_stayed_enabled: bool,
    pub(crate) directory_scheduler_admitted: bool,
    pub(crate) event_scheduler_admitted: bool,
    pub(crate) environment_admitted: bool,
}

#[derive(Debug, Serialize)]
pub(crate) struct TimingEvidenceMetadata {
    pub(crate) schema: &'static str,
    pub(crate) runner_version: &'static str,
    pub(crate) platform_os: &'static str,
    pub(crate) platform_arch: &'static str,
    pub(crate) mode: RostlTimingMode,
    pub(crate) evidence_intent: EvidenceIntent,
    pub(crate) minimum_qualification_pairs: usize,
    pub(crate) wall_clock_only: bool,
    pub(crate) physical_trace_complete: bool,
    pub(crate) oram_state_seed_bound: bool,
    pub(crate) serial_independence_established: bool,
    pub(crate) statistical_scope: &'static str,
    pub(crate) target_projection_model: &'static str,
    pub(crate) target_projection_model_implemented: bool,
    pub(crate) timed_operation_model: &'static str,
    pub(crate) cover_insertions_per_table_per_pair: usize,
    pub(crate) cover_physical_order: [usize; 2],
    pub(crate) table_set_relation: &'static str,
    pub(crate) can_clear_gate2: bool,
    pub(crate) policy: QuiescencePolicy,
    pub(crate) before: EnvironmentSnapshot,
    pub(crate) between_records: EnvironmentSnapshot,
    pub(crate) after: EnvironmentSnapshot,
    pub(crate) max_runqueue_wait_ratio: f64,
    #[serde(flatten)]
    pub(crate) admission: EnvironmentAdmission,
}

#[derive(Debug, Serialize)]
pub(crate) struct TimingEvidence {
    #[serde(flatten)]
    pub(crate) metadata: TimingEvidenceMetadata,
    pub(crate) directory: RecordEvidence,
    pub(crate) event: RecordEvidence,
    pub(crate) declared_wall_clock_criteria_satisfied: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RunOutcome {
    pub(crate) evidence_intent: EvidenceIntent,
    pub(crate) environment_admitted: bool,
    pub(crate) declared_wall_clock_criteria_satisfied: bool,
}

#[allow(dead_code)]
impl RunOutcome {
    pub(crate) const fn exit_success(self) -> bool {
        match self.evidence_intent {
            EvidenceIntent::Pilot => self.environment_admitted,
            EvidenceIntent::QualificationCandidate => self.declared_wall_clock_criteria_satisfied,
        }
    }

    pub(crate) const fn evidence_intent(self) -> EvidenceIntent {
        self.evidence_intent
    }

    pub(crate) const fn environment_admitted(self) -> bool {
        self.environment_admitted
    }

    pub(crate) const fn declared_wall_clock_criteria_satisfied(self) -> bool {
        self.declared_wall_clock_criteria_satisfied
    }
}

/// Performs every fallible input and host admission check before ORAM setup.
pub(crate) fn prepare_timing_run(inputs: TimingRunInputs) -> TimingDriverResult<PreparedTimingRun> {
    inputs.validate_contract()?;
    let directory_plan = inputs.directory_plan()?;
    let event_plan = inputs.event_plan()?;
    let directory_occupancy =
        occupancy_window(inputs.directory_initial_occupancy, &directory_plan)?;
    let event_occupancy = occupancy_window(inputs.event_initial_occupancy, &event_plan)?;
    let bounds = EquivalenceBounds::new(inputs.mean_bound_nanos, inputs.cdf_distance_bound)?;
    let policy = QuiescencePolicy::new(inputs.max_load_average_1m, inputs.max_competing_processes);
    let before = read_environment()?;
    let Some(pinned_cpu) = before.allowed_cpu else {
        return Err(TimingDriverError::CpuNotPinned.into());
    };
    validate_start_environment(&before, &policy, pinned_cpu)?;

    Ok(PreparedTimingRun {
        inputs,
        directory_plan,
        event_plan,
        directory_occupancy,
        event_occupancy,
        bounds,
        policy,
        before,
        pinned_cpu,
    })
}

/// Executes one prepared cell and returns its exact raw timing-v3 bytes.
///
/// This function's first ORAM-related operation is the directory timing call.
pub(crate) fn execute_prepared_timing_run(
    prepared: PreparedTimingRun,
) -> TimingDriverResult<CompletedTimingRun> {
    let PreparedTimingRun {
        inputs,
        directory_plan,
        event_plan,
        directory_occupancy,
        event_occupancy,
        bounds,
        policy,
        before: _,
        pinned_cpu,
    } = prepared;

    // Durable attempt-ledger publication may happen between preparation and
    // execution. Resample the cheap timing controls after that publication and
    // immediately before the first ORAM-related operation.
    let before = read_environment()?;
    validate_start_environment(&before, &policy, pinned_cpu)?;
    let directory_run = run_rostl_insert_timing_mode(
        RostlTimingRecordKind::Directory,
        inputs.mode,
        inputs.directory_capacity,
        inputs.directory_initial_occupancy,
        &directory_plan,
    )?;
    let (directory_pairs, directory_scheduler) = directory_run.into_parts();
    let between_records = read_environment()?;
    let event_run = run_rostl_insert_timing_mode(
        RostlTimingRecordKind::Event,
        inputs.mode,
        inputs.event_capacity,
        inputs.event_initial_occupancy,
        &event_plan,
    )?;
    let (event_pairs, event_scheduler) = event_run.into_parts();
    let after = read_environment()?;

    let directory_report = evaluate_timing_equivalence(
        &directory_pairs,
        bounds,
        TimingSeed::new(derive_seed(inputs.seed, DIRECTORY_REPORT_SEED_DOMAIN)),
    );
    let event_report = evaluate_timing_equivalence(
        &event_pairs,
        bounds,
        TimingSeed::new(derive_seed(inputs.seed, EVENT_REPORT_SEED_DOMAIN)),
    );
    let directory_scheduler_admitted = directory_scheduler.admits(inputs.max_runqueue_wait_ratio);
    let event_scheduler_admitted = event_scheduler.admits(inputs.max_runqueue_wait_ratio);
    let admission = evaluate_environment_admission(
        &policy,
        pinned_cpu,
        &before,
        &between_records,
        &after,
        directory_scheduler_admitted,
        event_scheduler_admitted,
    );
    let declared_wall_clock_criteria_satisfied = inputs.evidence_intent
        == EvidenceIntent::QualificationCandidate
        && admission.environment_admitted
        && directory_report.bounds_satisfied()
        && event_report.bounds_satisfied();
    let environment_admitted = admission.environment_admitted;

    let evidence = TimingEvidence {
        metadata: TimingEvidenceMetadata {
            schema: TIMING_EVIDENCE_SCHEMA,
            runner_version: env!("CARGO_PKG_VERSION"),
            platform_os: std::env::consts::OS,
            platform_arch: std::env::consts::ARCH,
            mode: inputs.mode,
            evidence_intent: inputs.evidence_intent,
            minimum_qualification_pairs: MINIMUM_PAIRS,
            wall_clock_only: true,
            physical_trace_complete: false,
            oram_state_seed_bound: false,
            serial_independence_established: false,
            statistical_scope: STATISTICAL_SCOPE,
            target_projection_model: TARGET_PROJECTION_MODEL,
            target_projection_model_implemented: false,
            timed_operation_model: timed_operation_model(inputs.mode),
            cover_insertions_per_table_per_pair: 1,
            cover_physical_order: [0, 1],
            table_set_relation: table_set_relation(inputs.mode),
            can_clear_gate2: false,
            policy,
            before,
            between_records,
            after,
            max_runqueue_wait_ratio: inputs.max_runqueue_wait_ratio,
            admission,
        },
        directory: RecordEvidence {
            kind: RostlTimingRecordKind::Directory,
            capacity: inputs.directory_capacity,
            initial_occupancy: directory_occupancy.initial,
            measured_start_occupancy: directory_occupancy.measured_start,
            measured_last_pre_occupancy: directory_occupancy.measured_last_pre,
            final_occupancy: directory_occupancy.final_occupancy,
            growth_per_pair: 1,
            table_count: 2,
            state_control: STATE_CONTROL,
            label_assignment: LABEL_ASSIGNMENT,
            order_blocking: ORDER_BLOCKING,
            record_model: DIRECTORY_RECORD_MODEL,
            plan: directory_plan,
            report_seed: TimingSeed::new(derive_seed(inputs.seed, DIRECTORY_REPORT_SEED_DOMAIN)),
            raw_pairs: directory_pairs,
            report: directory_report,
            timed_scheduler: directory_scheduler,
            scheduler_admitted: directory_scheduler_admitted,
        },
        event: RecordEvidence {
            kind: RostlTimingRecordKind::Event,
            capacity: inputs.event_capacity,
            initial_occupancy: event_occupancy.initial,
            measured_start_occupancy: event_occupancy.measured_start,
            measured_last_pre_occupancy: event_occupancy.measured_last_pre,
            final_occupancy: event_occupancy.final_occupancy,
            growth_per_pair: 1,
            table_count: 2,
            state_control: STATE_CONTROL,
            label_assignment: LABEL_ASSIGNMENT,
            order_blocking: ORDER_BLOCKING,
            record_model: EVENT_RECORD_MODEL,
            plan: event_plan,
            report_seed: TimingSeed::new(derive_seed(inputs.seed, EVENT_REPORT_SEED_DOMAIN)),
            raw_pairs: event_pairs,
            report: event_report,
            timed_scheduler: event_scheduler,
            scheduler_admitted: event_scheduler_admitted,
        },
        declared_wall_clock_criteria_satisfied,
    };
    let mut raw_v3_bytes = serde_json::to_vec_pretty(&evidence)?;
    raw_v3_bytes.push(b'\n');
    let _: serde_json::Value = serde_json::from_slice(&raw_v3_bytes)?;
    Ok(CompletedTimingRun {
        raw_v3_bytes,
        outcome: RunOutcome {
            evidence_intent: inputs.evidence_intent,
            environment_admitted,
            declared_wall_clock_criteria_satisfied,
        },
    })
}

fn validate_start_environment(
    snapshot: &EnvironmentSnapshot,
    policy: &QuiescencePolicy,
    pinned_cpu: u32,
) -> TimingDriverResult<()> {
    if snapshot.allowed_cpu != Some(pinned_cpu) {
        return Err(TimingDriverError::CpuAffinityChangedBeforeExecution.into());
    }
    if !snapshot.scheduler_stats_enabled {
        return Err(TimingDriverError::SchedulerStatsDisabled.into());
    }
    if !policy.admits(&snapshot.quiescence) {
        return Err(TimingDriverError::InitiallyNotQuiescent.into());
    }
    Ok(())
}

pub(super) fn evaluate_environment_admission(
    policy: &QuiescencePolicy,
    pinned_cpu: u32,
    before: &EnvironmentSnapshot,
    between_records: &EnvironmentSnapshot,
    after: &EnvironmentSnapshot,
    directory_scheduler_admitted: bool,
    event_scheduler_admitted: bool,
) -> EnvironmentAdmission {
    let before_quiescence_admitted = policy.admits(&before.quiescence);
    let between_records_quiescence_admitted = policy.admits(&between_records.quiescence);
    let after_quiescence_admitted = policy.admits(&after.quiescence);
    let affinity_stable = [before, between_records, after]
        .iter()
        .all(|snapshot| snapshot.allowed_cpu == Some(pinned_cpu));
    let scheduler_stats_stayed_enabled = [before, between_records, after]
        .iter()
        .all(|snapshot| snapshot.scheduler_stats_enabled);
    let environment_admitted = before_quiescence_admitted
        && between_records_quiescence_admitted
        && after_quiescence_admitted
        && affinity_stable
        && scheduler_stats_stayed_enabled
        && directory_scheduler_admitted
        && event_scheduler_admitted;
    EnvironmentAdmission {
        before_quiescence_admitted,
        between_records_quiescence_admitted,
        after_quiescence_admitted,
        affinity_stable,
        scheduler_stats_stayed_enabled,
        directory_scheduler_admitted,
        event_scheduler_admitted,
        environment_admitted,
    }
}

fn read_environment() -> TimingDriverResult<EnvironmentSnapshot> {
    let status = fs::read_to_string("/proc/self/status")?;
    let cpus_allowed_list = parse_cpus_allowed_list(&status)?.to_owned();
    let allowed_cpu = single_allowed_cpu(&cpus_allowed_list);
    let loadavg = fs::read_to_string("/proc/loadavg")?;
    let quiescence = parse_loadavg(&loadavg)?;
    let scheduler_stats_control = fs::read_to_string("/proc/sys/kernel/sched_schedstats")?;
    let scheduler_stats_enabled = parse_scheduler_stats_control(&scheduler_stats_control)?;
    Ok(EnvironmentSnapshot {
        cpus_allowed_list,
        allowed_cpu,
        quiescence,
        scheduler_stats_enabled,
    })
}

pub(crate) fn parse_cpus_allowed_list(status: &str) -> Result<&str, TimingDriverError> {
    status
        .lines()
        .find_map(|line| line.strip_prefix("Cpus_allowed_list:"))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or(TimingDriverError::MissingCpuAllowance)
}

pub(crate) fn parse_loadavg(loadavg: &str) -> Result<Quiescence, TimingDriverError> {
    let mut fields = loadavg.split_whitespace();
    let load_average_1m = fields
        .next()
        .ok_or(TimingDriverError::InvalidLoadAverage)?
        .parse::<f64>()
        .map_err(|_| TimingDriverError::InvalidLoadAverage)?;
    if !load_average_1m.is_finite() || load_average_1m < 0.0 {
        return Err(TimingDriverError::InvalidLoadAverage);
    }
    let runnable = fields
        .nth(2)
        .ok_or(TimingDriverError::InvalidRunnableProcesses)?;
    let (running, _) = runnable
        .split_once('/')
        .ok_or(TimingDriverError::InvalidRunnableProcesses)?;
    let running = running
        .parse::<usize>()
        .map_err(|_| TimingDriverError::InvalidRunnableProcesses)?;
    if running == 0 {
        return Err(TimingDriverError::InvalidRunnableProcesses);
    }
    Ok(Quiescence::new(load_average_1m, running.saturating_sub(1)))
}

pub(crate) fn parse_scheduler_stats_control(value: &str) -> Result<bool, TimingDriverError> {
    match value.trim() {
        "0" => Ok(false),
        "1" => Ok(true),
        _ => Err(TimingDriverError::InvalidSchedulerStatsControl),
    }
}

#[derive(Debug)]
pub(crate) enum TimingDriverError {
    UnsupportedPlatform,
    MissingCpuAllowance,
    InvalidLoadAverage,
    InvalidRunnableProcesses,
    CpuNotPinned,
    CpuAffinityChangedBeforeExecution,
    InvalidQuiescencePolicy,
    InvalidRunqueueWaitPolicy,
    InitiallyNotQuiescent,
    InvalidSchedulerStatsControl,
    SchedulerStatsDisabled,
}

impl fmt::Display for TimingDriverError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedPlatform => {
                formatter.write_str("timing qualification requires Linux x86_64")
            }
            Self::MissingCpuAllowance => {
                formatter.write_str("/proc/self/status has no Cpus_allowed_list")
            }
            Self::InvalidLoadAverage => formatter.write_str("/proc/loadavg is malformed"),
            Self::InvalidRunnableProcesses => {
                formatter.write_str("/proc/loadavg has an invalid runnable-process count")
            }
            Self::CpuNotPinned => {
                formatter.write_str("timing process must be pinned to exactly one CPU")
            }
            Self::CpuAffinityChangedBeforeExecution => {
                formatter.write_str("CPU affinity changed before timing execution")
            }
            Self::InvalidQuiescencePolicy => {
                formatter.write_str("maximum load average must be finite and non-negative")
            }
            Self::InvalidRunqueueWaitPolicy => {
                formatter.write_str("maximum run-queue wait ratio must be finite and within [0, 1]")
            }
            Self::InitiallyNotQuiescent => {
                formatter.write_str("host is not quiescent enough to start timing")
            }
            Self::InvalidSchedulerStatsControl => {
                formatter.write_str("/proc/sys/kernel/sched_schedstats is malformed")
            }
            Self::SchedulerStatsDisabled => {
                formatter.write_str("Linux scheduler statistics must be enabled before timing")
            }
        }
    }
}

impl Error for TimingDriverError {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::Cell, io};

    #[test]
    fn failed_durable_start_does_not_enter_executor() {
        let executed = Cell::new(false);
        let result: Result<StartedExecution<(), ()>, &str> = start_then_execute(
            (),
            |_| Err("injected durable-start failure"),
            |_| {
                executed.set(true);
                Ok(())
            },
        );

        assert!(result.is_err());
        assert!(!executed.get());
    }

    #[test]
    fn post_start_failure_retains_start_token() {
        let result: Result<StartedExecution<&str, ()>, io::Error> = start_then_execute(
            (),
            |_| Ok("durable-start-token"),
            |_| Err(io::Error::other("injected execution failure").into()),
        );

        match result {
            Ok(StartedExecution::Failed { started, source }) => {
                assert_eq!(started, "durable-start-token");
                assert_eq!(source.to_string(), "injected execution failure");
            }
            Ok(StartedExecution::Completed { .. }) => {
                panic!("injected execution failure must not complete")
            }
            Err(error) => panic!("durable start unexpectedly failed: {error}"),
        }
    }
}
