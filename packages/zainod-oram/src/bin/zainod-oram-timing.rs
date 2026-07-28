//! Synchronous Linux driver for Gate 2 paired insertion timing evidence.

#![forbid(unsafe_code)]

use std::{
    error::Error,
    fmt,
    fs::{self, File},
    io::{self, Write},
    path::{Path, PathBuf},
    process::ExitCode,
};

use clap::{Parser, ValueEnum};
use rustix::fs::{renameat_with, RenameFlags, CWD};
use serde::Serialize;
use tempfile::NamedTempFile;
use zaino_oram::{
    evaluate_timing_equivalence, run_rostl_insert_timing_mode, single_allowed_cpu,
    validate_rostl_timing_shape, EquivalenceBounds, EquivalenceReport, ExperimentPlan, Pair,
    Quiescence, QuiescencePolicy, RostlTimingError, RostlTimingMode, RostlTimingRecordKind,
    RostlTimingSchedulerSummary, TimingSeed, MINIMUM_PAIRS,
};

type DriverResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

const SCHEMA: &str = "zaino-oram-insert-timing-v3";
const DEFAULT_WARMUP_PAIRS: usize = 50;
const DIRECTORY_SCHEDULE_SEED_DOMAIN: u64 = 0x5e12_33a1_a341_71d1;
const DIRECTORY_REPORT_SEED_DOMAIN: u64 = 0x6127_0c6f_3475_8a0b;
const EVENT_SCHEDULE_SEED_DOMAIN: u64 = 0xe7e1_82a5_7b9c_4d31;
const EVENT_REPORT_SEED_DOMAIN: u64 = 0x7b91_ed09_451f_83c7;
const STATE_CONTROL: &str = "matched_long_lived_logical_twin_tables_v1";
const LABEL_ASSIGNMENT: &str = "alternating_physical_tables";
const ORDER_BLOCKING: &str = "physical_table_role_parity_v1";
const DIRECTORY_RECORD_MODEL: &str = "directory_single_cell_v1";
const EVENT_RECORD_MODEL: &str = "event_single_immutable_cell_v1";
const TARGET_PROJECTION_MODEL: &str = "chunked_generational_events";
const STATISTICAL_SCOPE: &str = "nominal_iid_bounds_on_serially_dependent_rounds";

#[derive(Debug, Parser)]
#[command(
    name = "zainod-oram-timing",
    version,
    about = "Run the synchronous Gate 2 insertion timing experiment"
)]
struct Cli {
    /// Comparison mode: real hit/miss arms or an equal-operation null control.
    #[arg(long, value_enum, default_value = "hit-miss")]
    mode: TimingModeArgument,

    /// Whether this is a small apparatus pilot or a qualification candidate.
    #[arg(long, value_enum, default_value = "qualification-candidate")]
    evidence_intent: EvidenceIntent,

    /// Number of retained AB/BA pairs.
    #[arg(long, default_value_t = MINIMUM_PAIRS)]
    pairs: usize,

    /// Number of discarded pairs that warm the same long-lived state machine.
    #[arg(long, default_value_t = DEFAULT_WARMUP_PAIRS)]
    warmup_pairs: usize,

    /// Allocated address-directory table slots.
    #[arg(long)]
    directory_capacity: usize,

    /// Address-directory records present before warm-up growth begins.
    #[arg(long)]
    directory_initial_occupancy: usize,

    /// Allocated address-event table slots.
    #[arg(long)]
    event_capacity: usize,

    /// Address-event records present before warm-up growth begins.
    #[arg(long)]
    event_initial_occupancy: usize,

    /// Predeclared maximum absolute scheduled-label mean difference in nanoseconds.
    #[arg(long)]
    mean_bound_nanos: f64,

    /// Predeclared maximum true scheduled-label CDF distance.
    #[arg(long)]
    cdf_distance_bound: f64,

    /// Largest admitted one-minute host load average.
    #[arg(long)]
    max_load_average_1m: f64,

    /// Largest admitted count of runnable processes other than this driver.
    #[arg(long)]
    max_competing_processes: usize,

    /// Largest admitted fraction of timed wall-clock time spent waiting to run.
    #[arg(long)]
    max_runqueue_wait_ratio: f64,

    /// Root seed domain-separated into both record schedules and reports.
    #[arg(long)]
    seed: u64,

    /// New JSON file that will receive raw pairs and aggregate statistics.
    #[arg(long, value_name = "FILE")]
    output: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum TimingModeArgument {
    HitMiss,
    ForcedHit,
    ForcedMiss,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ValueEnum)]
#[serde(rename_all = "snake_case")]
enum EvidenceIntent {
    Pilot,
    QualificationCandidate,
}

impl TimingModeArgument {
    const fn rostl_mode(self) -> RostlTimingMode {
        match self {
            Self::HitMiss => RostlTimingMode::HitMiss,
            Self::ForcedHit => RostlTimingMode::ForcedHit,
            Self::ForcedMiss => RostlTimingMode::ForcedMiss,
        }
    }
}

#[derive(Debug, Serialize)]
struct EnvironmentSnapshot {
    cpus_allowed_list: String,
    allowed_cpu: Option<u32>,
    quiescence: Quiescence,
    scheduler_stats_enabled: bool,
}

#[derive(Debug, Serialize)]
struct RecordEvidence {
    kind: RostlTimingRecordKind,
    capacity: usize,
    initial_occupancy: usize,
    measured_start_occupancy: usize,
    measured_last_pre_occupancy: usize,
    final_occupancy: usize,
    growth_per_pair: usize,
    table_count: usize,
    state_control: &'static str,
    label_assignment: &'static str,
    order_blocking: &'static str,
    record_model: &'static str,
    plan: ExperimentPlan,
    report_seed: TimingSeed,
    raw_pairs: Vec<Pair>,
    report: EquivalenceReport,
    timed_scheduler: RostlTimingSchedulerSummary,
    scheduler_admitted: bool,
}

#[derive(Debug, Serialize)]
struct EnvironmentAdmission {
    before_quiescence_admitted: bool,
    between_records_quiescence_admitted: bool,
    after_quiescence_admitted: bool,
    affinity_stable: bool,
    scheduler_stats_stayed_enabled: bool,
    directory_scheduler_admitted: bool,
    event_scheduler_admitted: bool,
    environment_admitted: bool,
}

#[derive(Debug, Serialize)]
struct TimingEvidenceMetadata {
    schema: &'static str,
    runner_version: &'static str,
    platform_os: &'static str,
    platform_arch: &'static str,
    mode: RostlTimingMode,
    evidence_intent: EvidenceIntent,
    minimum_qualification_pairs: usize,
    wall_clock_only: bool,
    physical_trace_complete: bool,
    oram_state_seed_bound: bool,
    serial_independence_established: bool,
    statistical_scope: &'static str,
    target_projection_model: &'static str,
    target_projection_model_implemented: bool,
    timed_operation_model: &'static str,
    cover_insertions_per_table_per_pair: usize,
    cover_physical_order: [usize; 2],
    table_set_relation: &'static str,
    can_clear_gate2: bool,
    policy: QuiescencePolicy,
    before: EnvironmentSnapshot,
    between_records: EnvironmentSnapshot,
    after: EnvironmentSnapshot,
    max_runqueue_wait_ratio: f64,
    #[serde(flatten)]
    admission: EnvironmentAdmission,
}

#[derive(Debug, Serialize)]
struct TimingEvidence {
    #[serde(flatten)]
    metadata: TimingEvidenceMetadata,
    directory: RecordEvidence,
    event: RecordEvidence,
    declared_wall_clock_criteria_satisfied: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct OccupancyWindow {
    initial: usize,
    measured_start: usize,
    measured_last_pre: usize,
    final_occupancy: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RunOutcome {
    evidence_intent: EvidenceIntent,
    environment_admitted: bool,
    declared_wall_clock_criteria_satisfied: bool,
}

impl RunOutcome {
    const fn exit_success(self) -> bool {
        match self.evidence_intent {
            EvidenceIntent::Pilot => self.environment_admitted,
            EvidenceIntent::QualificationCandidate => self.declared_wall_clock_criteria_satisfied,
        }
    }
}

#[derive(Debug)]
enum DriverError {
    UnsupportedPlatform,
    OutputExists,
    MissingCpuAllowance,
    InvalidLoadAverage,
    InvalidRunnableProcesses,
    CpuNotPinned,
    InvalidQuiescencePolicy,
    InvalidRunqueueWaitPolicy,
    UnderpoweredQualificationCandidate { requested: usize },
    UnbalancedQualificationCandidate,
    InitiallyNotQuiescent,
    InvalidSchedulerStatsControl,
    SchedulerStatsDisabled,
    PublishedButDurabilityUncertain { source: io::Error },
}

impl fmt::Display for DriverError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedPlatform => {
                formatter.write_str("timing qualification requires Linux x86_64")
            }
            Self::OutputExists => formatter.write_str("timing output path already exists"),
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
            Self::InvalidQuiescencePolicy => {
                formatter.write_str("maximum load average must be finite and non-negative")
            }
            Self::InvalidRunqueueWaitPolicy => {
                formatter.write_str("maximum run-queue wait ratio must be finite and within [0, 1]")
            }
            Self::UnderpoweredQualificationCandidate { requested } => write!(
                formatter,
                "qualification candidate requested {requested} measured pairs; at least {MINIMUM_PAIRS} are required"
            ),
            Self::UnbalancedQualificationCandidate => formatter.write_str(
                "qualification candidate requires measured pairs divisible by four and an even warm-up pair count",
            ),
            Self::InitiallyNotQuiescent => {
                formatter.write_str("host is not quiescent enough to start timing")
            }
            Self::InvalidSchedulerStatsControl => {
                formatter.write_str("/proc/sys/kernel/sched_schedstats is malformed")
            }
            Self::SchedulerStatsDisabled => {
                formatter.write_str("Linux scheduler statistics must be enabled before timing")
            }
            Self::PublishedButDurabilityUncertain { .. } => formatter
                .write_str("timing output was published but parent durability is uncertain"),
        }
    }
}

impl Error for DriverError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::PublishedButDurabilityUncertain { source } => Some(source),
            _ => None,
        }
    }
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(outcome) if outcome.exit_success() => ExitCode::SUCCESS,
        Ok(_) => {
            eprintln!("timing experiment was not admitted for its declared evidence intent");
            ExitCode::FAILURE
        }
        Err(error) => {
            eprintln!("timing qualification failed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> DriverResult<RunOutcome> {
    if !cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        return Err(DriverError::UnsupportedPlatform.into());
    }
    if cli.output.try_exists()? {
        return Err(DriverError::OutputExists.into());
    }
    if !cli.max_load_average_1m.is_finite() || cli.max_load_average_1m < 0.0 {
        return Err(DriverError::InvalidQuiescencePolicy.into());
    }
    if !cli.max_runqueue_wait_ratio.is_finite()
        || !(0.0..=1.0).contains(&cli.max_runqueue_wait_ratio)
    {
        return Err(DriverError::InvalidRunqueueWaitPolicy.into());
    }
    validate_evidence_intent(cli.evidence_intent, cli.pairs, cli.warmup_pairs)?;

    let directory_schedule_seed = derive_seed(cli.seed, DIRECTORY_SCHEDULE_SEED_DOMAIN);
    let directory_report_seed = derive_seed(cli.seed, DIRECTORY_REPORT_SEED_DOMAIN);
    let event_schedule_seed = derive_seed(cli.seed, EVENT_SCHEDULE_SEED_DOMAIN);
    let event_report_seed = derive_seed(cli.seed, EVENT_REPORT_SEED_DOMAIN);
    let directory_plan = ExperimentPlan::new(
        cli.pairs,
        cli.warmup_pairs,
        TimingSeed::new(directory_schedule_seed),
    )?;
    let event_plan = ExperimentPlan::new(
        cli.pairs,
        cli.warmup_pairs,
        TimingSeed::new(event_schedule_seed),
    )?;

    validate_rostl_timing_shape(
        RostlTimingRecordKind::Directory,
        cli.directory_capacity,
        cli.directory_initial_occupancy,
        &directory_plan,
    )?;
    validate_rostl_timing_shape(
        RostlTimingRecordKind::Event,
        cli.event_capacity,
        cli.event_initial_occupancy,
        &event_plan,
    )?;

    let bounds = EquivalenceBounds::new(cli.mean_bound_nanos, cli.cdf_distance_bound)?;
    let policy = QuiescencePolicy::new(cli.max_load_average_1m, cli.max_competing_processes);
    let before = read_environment()?;
    let Some(pinned_cpu) = before.allowed_cpu else {
        return Err(DriverError::CpuNotPinned.into());
    };
    if !before.scheduler_stats_enabled {
        return Err(DriverError::SchedulerStatsDisabled.into());
    }
    if !policy.admits(&before.quiescence) {
        return Err(DriverError::InitiallyNotQuiescent.into());
    }

    let mode = cli.mode.rostl_mode();
    let directory_run = run_rostl_insert_timing_mode(
        RostlTimingRecordKind::Directory,
        mode,
        cli.directory_capacity,
        cli.directory_initial_occupancy,
        &directory_plan,
    )?;
    let (directory_pairs, directory_scheduler) = directory_run.into_parts();
    let between_records = read_environment()?;
    let event_run = run_rostl_insert_timing_mode(
        RostlTimingRecordKind::Event,
        mode,
        cli.event_capacity,
        cli.event_initial_occupancy,
        &event_plan,
    )?;
    let (event_pairs, event_scheduler) = event_run.into_parts();
    let after = read_environment()?;

    let directory_report = evaluate_timing_equivalence(
        &directory_pairs,
        bounds,
        TimingSeed::new(directory_report_seed),
    );
    let event_report =
        evaluate_timing_equivalence(&event_pairs, bounds, TimingSeed::new(event_report_seed));
    let directory_scheduler_admitted = directory_scheduler.admits(cli.max_runqueue_wait_ratio);
    let event_scheduler_admitted = event_scheduler.admits(cli.max_runqueue_wait_ratio);
    let admission = evaluate_environment_admission(
        &policy,
        pinned_cpu,
        &before,
        &between_records,
        &after,
        directory_scheduler_admitted,
        event_scheduler_admitted,
    );
    let declared_wall_clock_criteria_satisfied = cli.evidence_intent
        == EvidenceIntent::QualificationCandidate
        && admission.environment_admitted
        && directory_report.bounds_satisfied()
        && event_report.bounds_satisfied();
    let environment_admitted = admission.environment_admitted;
    let directory_occupancy = occupancy_window(cli.directory_initial_occupancy, &directory_plan)?;
    let event_occupancy = occupancy_window(cli.event_initial_occupancy, &event_plan)?;

    let evidence = TimingEvidence {
        metadata: TimingEvidenceMetadata {
            schema: SCHEMA,
            runner_version: env!("CARGO_PKG_VERSION"),
            platform_os: std::env::consts::OS,
            platform_arch: std::env::consts::ARCH,
            mode,
            evidence_intent: cli.evidence_intent,
            minimum_qualification_pairs: MINIMUM_PAIRS,
            wall_clock_only: true,
            physical_trace_complete: false,
            oram_state_seed_bound: false,
            serial_independence_established: false,
            statistical_scope: STATISTICAL_SCOPE,
            target_projection_model: TARGET_PROJECTION_MODEL,
            target_projection_model_implemented: false,
            timed_operation_model: timed_operation_model(mode),
            cover_insertions_per_table_per_pair: 1,
            cover_physical_order: [0, 1],
            table_set_relation: table_set_relation(mode),
            can_clear_gate2: false,
            policy,
            before,
            between_records,
            after,
            max_runqueue_wait_ratio: cli.max_runqueue_wait_ratio,
            admission,
        },
        directory: RecordEvidence {
            kind: RostlTimingRecordKind::Directory,
            capacity: cli.directory_capacity,
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
            report_seed: TimingSeed::new(directory_report_seed),
            raw_pairs: directory_pairs,
            report: directory_report,
            timed_scheduler: directory_scheduler,
            scheduler_admitted: directory_scheduler_admitted,
        },
        event: RecordEvidence {
            kind: RostlTimingRecordKind::Event,
            capacity: cli.event_capacity,
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
            report_seed: TimingSeed::new(event_report_seed),
            raw_pairs: event_pairs,
            report: event_report,
            timed_scheduler: event_scheduler,
            scheduler_admitted: event_scheduler_admitted,
        },
        declared_wall_clock_criteria_satisfied,
    };
    publish_json(&cli.output, &evidence)?;
    println!("timing_evidence={}", cli.output.display());
    Ok(RunOutcome {
        evidence_intent: cli.evidence_intent,
        environment_admitted,
        declared_wall_clock_criteria_satisfied,
    })
}

fn validate_evidence_intent(
    intent: EvidenceIntent,
    pairs: usize,
    warmup_pairs: usize,
) -> Result<(), DriverError> {
    if intent == EvidenceIntent::QualificationCandidate && pairs < MINIMUM_PAIRS {
        return Err(DriverError::UnderpoweredQualificationCandidate { requested: pairs });
    }
    if intent == EvidenceIntent::QualificationCandidate
        && (!pairs.is_multiple_of(4) || !warmup_pairs.is_multiple_of(2))
    {
        return Err(DriverError::UnbalancedQualificationCandidate);
    }
    Ok(())
}

const fn timed_operation_model(mode: RostlTimingMode) -> &'static str {
    match mode {
        RostlTimingMode::HitMiss => {
            "mixed_duplicate_and_unique_insert_current_single_cell_baseline_v1"
        }
        RostlTimingMode::ForcedHit => "duplicate_insert_current_single_cell_control_v1",
        RostlTimingMode::ForcedMiss => "unique_insert_current_single_cell_control_v1",
    }
}

const fn table_set_relation(mode: RostlTimingMode) -> &'static str {
    match mode {
        RostlTimingMode::HitMiss => "one_record_substitution_equal_cardinality",
        RostlTimingMode::ForcedHit | RostlTimingMode::ForcedMiss => "identical_key_sets",
    }
}

fn occupancy_window(
    initial: usize,
    plan: &ExperimentPlan,
) -> Result<OccupancyWindow, RostlTimingError> {
    let measured_start = initial
        .checked_add(plan.warmup_pairs())
        .ok_or(RostlTimingError::InvalidShape)?;
    let measured_last_pre = measured_start
        .checked_add(
            plan.pairs()
                .checked_sub(1)
                .ok_or(RostlTimingError::InvalidShape)?,
        )
        .ok_or(RostlTimingError::InvalidShape)?;
    let final_occupancy = initial
        .checked_add(plan.total_pairs())
        .ok_or(RostlTimingError::InvalidShape)?;
    Ok(OccupancyWindow {
        initial,
        measured_start,
        measured_last_pre,
        final_occupancy,
    })
}

fn derive_seed(root: u64, domain: u64) -> u64 {
    let mut value = root ^ domain;
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

fn evaluate_environment_admission(
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

fn read_environment() -> DriverResult<EnvironmentSnapshot> {
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

fn parse_cpus_allowed_list(status: &str) -> Result<&str, DriverError> {
    status
        .lines()
        .find_map(|line| line.strip_prefix("Cpus_allowed_list:"))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or(DriverError::MissingCpuAllowance)
}

fn parse_loadavg(loadavg: &str) -> Result<Quiescence, DriverError> {
    let mut fields = loadavg.split_whitespace();
    let load_average_1m = fields
        .next()
        .ok_or(DriverError::InvalidLoadAverage)?
        .parse::<f64>()
        .map_err(|_| DriverError::InvalidLoadAverage)?;
    if !load_average_1m.is_finite() || load_average_1m < 0.0 {
        return Err(DriverError::InvalidLoadAverage);
    }
    let runnable = fields.nth(2).ok_or(DriverError::InvalidRunnableProcesses)?;
    let (running, _) = runnable
        .split_once('/')
        .ok_or(DriverError::InvalidRunnableProcesses)?;
    let running = running
        .parse::<usize>()
        .map_err(|_| DriverError::InvalidRunnableProcesses)?;
    if running == 0 {
        return Err(DriverError::InvalidRunnableProcesses);
    }
    Ok(Quiescence::new(load_average_1m, running.saturating_sub(1)))
}

fn parse_scheduler_stats_control(value: &str) -> Result<bool, DriverError> {
    match value.trim() {
        "0" => Ok(false),
        "1" => Ok(true),
        _ => Err(DriverError::InvalidSchedulerStatsControl),
    }
}

fn publish_json(path: &Path, evidence: &impl Serialize) -> DriverResult<()> {
    publish_json_with_parent_sync(path, evidence, sync_parent)
}

fn publish_json_with_parent_sync<F>(
    path: &Path,
    evidence: &impl Serialize,
    sync_parent: F,
) -> DriverResult<()>
where
    F: FnOnce(&Path) -> io::Result<()>,
{
    let parent = path
        .parent()
        .filter(|candidate| !candidate.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut encoded = serde_json::to_vec_pretty(evidence)?;
    encoded.push(b'\n');
    let _: serde_json::Value = serde_json::from_slice(&encoded)?;

    let mut temporary = NamedTempFile::new_in(parent)?;
    temporary.write_all(&encoded)?;
    temporary.flush()?;
    temporary.as_file().sync_all()?;
    match renameat_with(CWD, temporary.path(), CWD, path, RenameFlags::NOREPLACE) {
        Ok(()) => {}
        Err(rustix::io::Errno::EXIST) => return Err(DriverError::OutputExists.into()),
        Err(error) => return Err(error.into()),
    }
    sync_parent(parent)
        .map_err(|source| DriverError::PublishedButDurabilityUncertain { source })?;
    Ok(())
}

fn sync_parent(parent: &Path) -> io::Result<()> {
    File::open(parent)?.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot(
        load_average_1m: f64,
        allowed_cpu: Option<u32>,
        scheduler_stats_enabled: bool,
    ) -> EnvironmentSnapshot {
        EnvironmentSnapshot {
            cpus_allowed_list: allowed_cpu.map_or_else(|| "0-3".to_owned(), |cpu| cpu.to_string()),
            allowed_cpu,
            quiescence: Quiescence::new(load_average_1m, 0),
            scheduler_stats_enabled,
        }
    }

    fn admission(
        before: &EnvironmentSnapshot,
        between_records: &EnvironmentSnapshot,
        after: &EnvironmentSnapshot,
        directory_scheduler_admitted: bool,
        event_scheduler_admitted: bool,
    ) -> EnvironmentAdmission {
        evaluate_environment_admission(
            &QuiescencePolicy::new(1.0, 0),
            3,
            before,
            between_records,
            after,
            directory_scheduler_admitted,
            event_scheduler_admitted,
        )
    }

    #[test]
    fn parses_linux_environment_fields() -> Result<(), Box<dyn Error>> {
        let status = "Name:\tzainod\nCpus_allowed_list:\t7\n";
        assert_eq!(parse_cpus_allowed_list(status)?, "7");

        let quiescence = parse_loadavg("0.25 0.40 0.80 3/901 42\n")?;
        assert!(QuiescencePolicy::new(0.25, 2).admits(&quiescence));
        assert!(!QuiescencePolicy::new(0.24, 2).admits(&quiescence));
        assert!(!QuiescencePolicy::new(0.25, 1).admits(&quiescence));

        assert!(parse_scheduler_stats_control("1\n")?);
        assert!(!parse_scheduler_stats_control("0\n")?);
        Ok(())
    }

    #[test]
    fn rejects_malformed_linux_environment_fields() {
        assert!(matches!(
            parse_cpus_allowed_list("Name:\tzainod\n"),
            Err(DriverError::MissingCpuAllowance)
        ));
        assert!(matches!(
            parse_loadavg("not-a-number 0.1 0.2 1/2 3"),
            Err(DriverError::InvalidLoadAverage)
        ));
        assert!(matches!(
            parse_loadavg("0.1 0.1 0.2 invalid 3"),
            Err(DriverError::InvalidRunnableProcesses)
        ));
        assert!(matches!(
            parse_loadavg("0.1 0.1 0.2 0/3 4"),
            Err(DriverError::InvalidRunnableProcesses)
        ));
        assert!(matches!(
            parse_scheduler_stats_control("enabled"),
            Err(DriverError::InvalidSchedulerStatsControl)
        ));
    }

    #[test]
    fn before_quiescence_failure_rejects_environment() {
        let before = snapshot(1.01, Some(3), true);
        let between_records = snapshot(0.5, Some(3), true);
        let after = snapshot(0.5, Some(3), true);

        let result = admission(&before, &between_records, &after, true, true);

        assert!(!result.before_quiescence_admitted);
        assert!(result.between_records_quiescence_admitted);
        assert!(result.after_quiescence_admitted);
        assert!(!result.environment_admitted);
    }

    #[test]
    fn between_records_quiescence_failure_rejects_environment() {
        let before = snapshot(0.5, Some(3), true);
        let between_records = snapshot(1.01, Some(3), true);
        let after = snapshot(0.5, Some(3), true);

        let result = admission(&before, &between_records, &after, true, true);

        assert!(result.before_quiescence_admitted);
        assert!(!result.between_records_quiescence_admitted);
        assert!(result.after_quiescence_admitted);
        assert!(!result.environment_admitted);
    }

    #[test]
    fn after_quiescence_failure_rejects_environment() {
        let before = snapshot(0.5, Some(3), true);
        let between_records = snapshot(0.5, Some(3), true);
        let after = snapshot(1.01, Some(3), true);

        let result = admission(&before, &between_records, &after, true, true);

        assert!(result.before_quiescence_admitted);
        assert!(result.between_records_quiescence_admitted);
        assert!(!result.after_quiescence_admitted);
        assert!(!result.environment_admitted);
    }

    #[test]
    fn affinity_drift_rejects_environment() {
        let before = snapshot(0.5, Some(3), true);
        let between_records = snapshot(0.5, Some(4), true);
        let after = snapshot(0.5, Some(3), true);

        let result = admission(&before, &between_records, &after, true, true);

        assert!(!result.affinity_stable);
        assert!(!result.environment_admitted);
    }

    #[test]
    fn scheduler_stats_loss_rejects_environment() {
        let before = snapshot(0.5, Some(3), true);
        let between_records = snapshot(0.5, Some(3), true);
        let after = snapshot(0.5, Some(3), false);

        let result = admission(&before, &between_records, &after, true, true);

        assert!(!result.scheduler_stats_stayed_enabled);
        assert!(!result.environment_admitted);
    }

    #[test]
    fn either_scheduler_summary_failure_rejects_environment() {
        let before = snapshot(0.5, Some(3), true);
        let between_records = snapshot(0.5, Some(3), true);
        let after = snapshot(0.5, Some(3), true);

        let directory_failure = admission(&before, &between_records, &after, false, true);
        let event_failure = admission(&before, &between_records, &after, true, false);

        assert!(!directory_failure.directory_scheduler_admitted);
        assert!(!directory_failure.environment_admitted);
        assert!(!event_failure.event_scheduler_admitted);
        assert!(!event_failure.environment_admitted);
    }

    #[test]
    fn v3_metadata_records_scope_mode_and_all_admission_fields() -> Result<(), serde_json::Error> {
        let before = snapshot(0.5, Some(3), true);
        let between_records = snapshot(0.5, Some(3), true);
        let after = snapshot(0.5, Some(3), true);
        let admission = admission(&before, &between_records, &after, true, true);
        let metadata = TimingEvidenceMetadata {
            schema: SCHEMA,
            runner_version: env!("CARGO_PKG_VERSION"),
            platform_os: "linux",
            platform_arch: "x86_64",
            mode: RostlTimingMode::ForcedHit,
            evidence_intent: EvidenceIntent::Pilot,
            minimum_qualification_pairs: MINIMUM_PAIRS,
            wall_clock_only: true,
            physical_trace_complete: false,
            oram_state_seed_bound: false,
            serial_independence_established: false,
            statistical_scope: STATISTICAL_SCOPE,
            target_projection_model: TARGET_PROJECTION_MODEL,
            target_projection_model_implemented: false,
            timed_operation_model: timed_operation_model(RostlTimingMode::ForcedHit),
            cover_insertions_per_table_per_pair: 1,
            cover_physical_order: [0, 1],
            table_set_relation: table_set_relation(RostlTimingMode::ForcedHit),
            can_clear_gate2: false,
            policy: QuiescencePolicy::new(1.0, 0),
            before,
            between_records,
            after,
            max_runqueue_wait_ratio: 0.01,
            admission,
        };

        let json = serde_json::to_value(metadata)?;

        assert_eq!(json["schema"], SCHEMA);
        assert_eq!(json["mode"], "forced_hit");
        assert_eq!(json["evidence_intent"], "pilot");
        assert_eq!(json["minimum_qualification_pairs"], MINIMUM_PAIRS);
        assert_eq!(json["wall_clock_only"], true);
        assert_eq!(json["physical_trace_complete"], false);
        assert_eq!(json["oram_state_seed_bound"], false);
        assert_eq!(json["serial_independence_established"], false);
        assert_eq!(json["statistical_scope"], STATISTICAL_SCOPE);
        assert_eq!(json["target_projection_model"], TARGET_PROJECTION_MODEL);
        assert_eq!(json["target_projection_model_implemented"], false);
        assert_eq!(
            json["timed_operation_model"],
            timed_operation_model(RostlTimingMode::ForcedHit)
        );
        assert_eq!(json["cover_insertions_per_table_per_pair"], 1);
        assert_eq!(json["cover_physical_order"], serde_json::json!([0, 1]));
        assert_eq!(
            json["table_set_relation"],
            table_set_relation(RostlTimingMode::ForcedHit)
        );
        assert_eq!(json["can_clear_gate2"], false);
        for field in [
            "before_quiescence_admitted",
            "between_records_quiescence_admitted",
            "after_quiescence_admitted",
            "affinity_stable",
            "scheduler_stats_stayed_enabled",
            "directory_scheduler_admitted",
            "event_scheduler_admitted",
            "environment_admitted",
        ] {
            assert_eq!(json[field], true, "{field} must be an admitted boolean");
        }
        Ok(())
    }

    #[test]
    fn qualification_intent_requires_power_and_balanced_counts() {
        assert!(matches!(
            validate_evidence_intent(
                EvidenceIntent::QualificationCandidate,
                MINIMUM_PAIRS - 1,
                DEFAULT_WARMUP_PAIRS
            ),
            Err(DriverError::UnderpoweredQualificationCandidate { .. })
        ));
        assert!(matches!(
            validate_evidence_intent(
                EvidenceIntent::QualificationCandidate,
                MINIMUM_PAIRS + 1,
                DEFAULT_WARMUP_PAIRS
            ),
            Err(DriverError::UnbalancedQualificationCandidate)
        ));
        assert!(matches!(
            validate_evidence_intent(
                EvidenceIntent::QualificationCandidate,
                MINIMUM_PAIRS + 2,
                DEFAULT_WARMUP_PAIRS
            ),
            Err(DriverError::UnbalancedQualificationCandidate)
        ));
        assert!(matches!(
            validate_evidence_intent(
                EvidenceIntent::QualificationCandidate,
                MINIMUM_PAIRS,
                DEFAULT_WARMUP_PAIRS + 1
            ),
            Err(DriverError::UnbalancedQualificationCandidate)
        ));
        assert!(validate_evidence_intent(
            EvidenceIntent::QualificationCandidate,
            MINIMUM_PAIRS,
            DEFAULT_WARMUP_PAIRS
        )
        .is_ok());
        assert!(validate_evidence_intent(EvidenceIntent::Pilot, 1, 1).is_ok());
    }

    #[test]
    fn occupancy_window_records_warmup_and_measured_growth() -> Result<(), Box<dyn Error>> {
        let plan = ExperimentPlan::new(6, 4, TimingSeed::new(3))?;

        assert_eq!(
            occupancy_window(20, &plan)?,
            OccupancyWindow {
                initial: 20,
                measured_start: 24,
                measured_last_pre: 29,
                final_occupancy: 30,
            }
        );
        Ok(())
    }

    #[test]
    fn seed_roles_are_domain_separated_and_reproducible() {
        let domains = [
            DIRECTORY_SCHEDULE_SEED_DOMAIN,
            DIRECTORY_REPORT_SEED_DOMAIN,
            EVENT_SCHEDULE_SEED_DOMAIN,
            EVENT_REPORT_SEED_DOMAIN,
        ];
        let derived: Vec<_> = domains
            .into_iter()
            .map(|domain| derive_seed(17, domain))
            .collect();

        assert_eq!(
            derived,
            domains
                .into_iter()
                .map(|domain| derive_seed(17, domain))
                .collect::<Vec<_>>()
        );
        for (index, seed) in derived.iter().enumerate() {
            assert!(
                !derived[..index].contains(seed),
                "seed domain collision at index {index}"
            );
        }
    }

    #[test]
    fn evidence_intent_controls_process_success_without_qualifying_pilots() {
        let admitted_pilot = RunOutcome {
            evidence_intent: EvidenceIntent::Pilot,
            environment_admitted: true,
            declared_wall_clock_criteria_satisfied: false,
        };
        let rejected_pilot = RunOutcome {
            environment_admitted: false,
            ..admitted_pilot
        };
        let rejected_candidate = RunOutcome {
            evidence_intent: EvidenceIntent::QualificationCandidate,
            environment_admitted: true,
            declared_wall_clock_criteria_satisfied: false,
        };
        let admitted_candidate = RunOutcome {
            declared_wall_clock_criteria_satisfied: true,
            ..rejected_candidate
        };

        assert!(admitted_pilot.exit_success());
        assert!(!admitted_pilot.declared_wall_clock_criteria_satisfied);
        assert!(!rejected_pilot.exit_success());
        assert!(!rejected_candidate.exit_success());
        assert!(admitted_candidate.exit_success());
    }

    #[test]
    fn operation_and_set_models_are_mode_specific() {
        assert_eq!(
            timed_operation_model(RostlTimingMode::HitMiss),
            "mixed_duplicate_and_unique_insert_current_single_cell_baseline_v1"
        );
        assert_eq!(
            timed_operation_model(RostlTimingMode::ForcedHit),
            "duplicate_insert_current_single_cell_control_v1"
        );
        assert_eq!(
            timed_operation_model(RostlTimingMode::ForcedMiss),
            "unique_insert_current_single_cell_control_v1"
        );
        assert_eq!(
            table_set_relation(RostlTimingMode::HitMiss),
            "one_record_substitution_equal_cardinality"
        );
        assert_eq!(
            table_set_relation(RostlTimingMode::ForcedHit),
            "identical_key_sets"
        );
        assert_eq!(
            table_set_relation(RostlTimingMode::ForcedMiss),
            "identical_key_sets"
        );
    }

    #[test]
    fn cli_modes_map_to_library_modes() {
        let cases = [
            ("hit-miss", RostlTimingMode::HitMiss),
            ("forced-hit", RostlTimingMode::ForcedHit),
            ("forced-miss", RostlTimingMode::ForcedMiss),
        ];

        for (argument, expected) in cases {
            let parsed = TimingModeArgument::from_str(argument, true)
                .expect("documented timing mode must parse");
            assert_eq!(parsed.rostl_mode(), expected);
        }
    }

    #[test]
    fn cli_accepts_explicit_pilot_pair_counts() -> Result<(), clap::Error> {
        let cli = Cli::try_parse_from([
            "zainod-oram-timing",
            "--evidence-intent",
            "pilot",
            "--pairs",
            "12",
            "--warmup-pairs",
            "4",
            "--directory-capacity",
            "64",
            "--directory-initial-occupancy",
            "8",
            "--event-capacity",
            "64",
            "--event-initial-occupancy",
            "8",
            "--mean-bound-nanos",
            "10",
            "--cdf-distance-bound",
            "0.2",
            "--max-load-average-1m",
            "1",
            "--max-competing-processes",
            "0",
            "--max-runqueue-wait-ratio",
            "0.01",
            "--seed",
            "7",
            "--output",
            "pilot.json",
        ])?;

        assert_eq!(cli.evidence_intent, EvidenceIntent::Pilot);
        assert_eq!(cli.pairs, 12);
        assert_eq!(cli.warmup_pairs, 4);
        Ok(())
    }

    #[test]
    fn cli_rejects_legacy_occupancy_names_with_changed_semantics() {
        let error = Cli::try_parse_from(["zainod-oram-timing", "--directory-occupancy", "8"])
            .expect_err("the v2 occupancy name must not silently select v3 semantics");

        assert_eq!(error.kind(), clap::error::ErrorKind::UnknownArgument);
    }

    #[test]
    fn output_is_create_new() -> Result<(), Box<dyn Error + Send + Sync>> {
        let directory = tempfile::tempdir()?;
        let output = directory.path().join("timing.json");
        fs::write(&output, b"existing")?;

        let error = publish_json(&output, &serde_json::json!({"qualified": false}))
            .expect_err("existing output must not be overwritten");
        assert!(matches!(
            error.downcast_ref::<DriverError>(),
            Some(DriverError::OutputExists)
        ));
        assert_eq!(fs::read(&output)?, b"existing");
        Ok(())
    }

    #[test]
    fn output_is_published_as_valid_json() -> Result<(), Box<dyn Error + Send + Sync>> {
        let directory = tempfile::tempdir()?;
        let output = directory.path().join("timing.json");
        publish_json(&output, &serde_json::json!({"declared": true}))?;

        let published: serde_json::Value = serde_json::from_slice(&fs::read(output)?)?;
        assert_eq!(published, serde_json::json!({"declared": true}));
        Ok(())
    }

    #[test]
    fn parent_sync_failure_reports_published_state() -> Result<(), Box<dyn Error + Send + Sync>> {
        let directory = tempfile::tempdir()?;
        let output = directory.path().join("timing.json");
        let error =
            publish_json_with_parent_sync(&output, &serde_json::json!({"declared": false}), |_| {
                Err(io::Error::other("injected parent sync failure"))
            })
            .expect_err("injected parent sync failure must be reported");

        assert!(matches!(
            error.downcast_ref::<DriverError>(),
            Some(DriverError::PublishedButDurabilityUncertain { .. })
        ));
        let published: serde_json::Value = serde_json::from_slice(&fs::read(output)?)?;
        assert_eq!(published, serde_json::json!({"declared": false}));
        Ok(())
    }
}
