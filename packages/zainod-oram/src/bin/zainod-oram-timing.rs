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

use clap::Parser;
use rustix::fs::{renameat_with, RenameFlags, CWD};
use serde::Serialize;
use tempfile::NamedTempFile;
use zaino_oram::{
    evaluate_timing_equivalence, run_rostl_insert_timing, single_allowed_cpu,
    validate_rostl_timing_shape, EquivalenceBounds, EquivalenceReport, ExperimentPlan, Pair,
    Quiescence, QuiescencePolicy, RostlTimingRecordKind, RostlTimingSchedulerSummary, TimingSeed,
    MINIMUM_PAIRS,
};

type DriverResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

const SCHEMA: &str = "zaino-oram-insert-timing-v1";
const WARMUP_PAIRS: usize = 50;
const EVENT_SEED_DOMAIN: u64 = 0xe7e1_82a5_7b9c_4d31;

#[derive(Debug, Parser)]
#[command(
    name = "zainod-oram-timing",
    version,
    about = "Run the synchronous Gate 2 insertion timing experiment"
)]
struct Cli {
    /// Allocated address-directory table slots.
    #[arg(long)]
    directory_capacity: usize,

    /// Address-directory records present before every timed insertion.
    #[arg(long)]
    directory_occupancy: usize,

    /// Allocated address-event table slots.
    #[arg(long)]
    event_capacity: usize,

    /// Address-event records present before every timed insertion.
    #[arg(long)]
    event_occupancy: usize,

    /// Predeclared maximum absolute mean hit/miss difference in nanoseconds.
    #[arg(long)]
    mean_bound_nanos: f64,

    /// Predeclared maximum true hit/miss CDF distance.
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

    /// Seed that fixes the directory AB/BA schedule and statistical resampling.
    #[arg(long)]
    seed: u64,

    /// New JSON file that will receive raw pairs and aggregate statistics.
    #[arg(long, value_name = "FILE")]
    output: PathBuf,
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
    occupancy: usize,
    plan: ExperimentPlan,
    raw_pairs: Vec<Pair>,
    report: EquivalenceReport,
    timed_scheduler: RostlTimingSchedulerSummary,
    scheduler_admitted: bool,
}

#[derive(Debug, Serialize)]
struct TimingEvidence {
    schema: &'static str,
    runner_version: &'static str,
    platform_os: &'static str,
    platform_arch: &'static str,
    policy: QuiescencePolicy,
    before: EnvironmentSnapshot,
    between_records: EnvironmentSnapshot,
    after: EnvironmentSnapshot,
    max_runqueue_wait_ratio: f64,
    environment_admitted: bool,
    directory: RecordEvidence,
    event: RecordEvidence,
    declared_criteria_satisfied: bool,
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
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => {
            eprintln!("timing experiment did not satisfy its predeclared criteria");
            ExitCode::FAILURE
        }
        Err(error) => {
            eprintln!("timing qualification failed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> DriverResult<bool> {
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

    validate_rostl_timing_shape(
        RostlTimingRecordKind::Directory,
        cli.directory_capacity,
        cli.directory_occupancy,
    )?;
    validate_rostl_timing_shape(
        RostlTimingRecordKind::Event,
        cli.event_capacity,
        cli.event_occupancy,
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

    let directory_plan =
        ExperimentPlan::new(MINIMUM_PAIRS, WARMUP_PAIRS, TimingSeed::new(cli.seed))?;
    let event_seed = cli.seed ^ EVENT_SEED_DOMAIN;
    let event_plan = ExperimentPlan::new(MINIMUM_PAIRS, WARMUP_PAIRS, TimingSeed::new(event_seed))?;

    let directory_run = run_rostl_insert_timing(
        RostlTimingRecordKind::Directory,
        cli.directory_capacity,
        cli.directory_occupancy,
        &directory_plan,
    )?;
    let (directory_pairs, directory_scheduler) = directory_run.into_parts();
    let between_records = read_environment()?;
    let event_run = run_rostl_insert_timing(
        RostlTimingRecordKind::Event,
        cli.event_capacity,
        cli.event_occupancy,
        &event_plan,
    )?;
    let (event_pairs, event_scheduler) = event_run.into_parts();
    let after = read_environment()?;

    let directory_report =
        evaluate_timing_equivalence(&directory_pairs, bounds, TimingSeed::new(cli.seed));
    let event_report =
        evaluate_timing_equivalence(&event_pairs, bounds, TimingSeed::new(event_seed));
    let affinity_stable =
        between_records.allowed_cpu == Some(pinned_cpu) && after.allowed_cpu == Some(pinned_cpu);
    let scheduler_stats_stayed_enabled =
        between_records.scheduler_stats_enabled && after.scheduler_stats_enabled;
    let directory_scheduler_admitted = directory_scheduler.admits(cli.max_runqueue_wait_ratio);
    let event_scheduler_admitted = event_scheduler.admits(cli.max_runqueue_wait_ratio);
    let environment_admitted = affinity_stable
        && scheduler_stats_stayed_enabled
        && directory_scheduler_admitted
        && event_scheduler_admitted;
    let declared_criteria_satisfied = environment_admitted
        && directory_report.bounds_satisfied()
        && event_report.bounds_satisfied();

    let evidence = TimingEvidence {
        schema: SCHEMA,
        runner_version: env!("CARGO_PKG_VERSION"),
        platform_os: std::env::consts::OS,
        platform_arch: std::env::consts::ARCH,
        policy,
        before,
        between_records,
        after,
        max_runqueue_wait_ratio: cli.max_runqueue_wait_ratio,
        environment_admitted,
        directory: RecordEvidence {
            kind: RostlTimingRecordKind::Directory,
            capacity: cli.directory_capacity,
            occupancy: cli.directory_occupancy,
            plan: directory_plan,
            raw_pairs: directory_pairs,
            report: directory_report,
            timed_scheduler: directory_scheduler,
            scheduler_admitted: directory_scheduler_admitted,
        },
        event: RecordEvidence {
            kind: RostlTimingRecordKind::Event,
            capacity: cli.event_capacity,
            occupancy: cli.event_occupancy,
            plan: event_plan,
            raw_pairs: event_pairs,
            report: event_report,
            timed_scheduler: event_scheduler,
            scheduler_admitted: event_scheduler_admitted,
        },
        declared_criteria_satisfied,
    };
    publish_json(&cli.output, &evidence)?;
    println!("timing_evidence={}", cli.output.display());
    Ok(declared_criteria_satisfied)
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
