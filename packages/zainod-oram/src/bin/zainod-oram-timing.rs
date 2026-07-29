//! Synchronous Linux driver for Gate 2 paired insertion timing evidence.

#![forbid(unsafe_code)]

#[cfg(test)]
use std::fs;
use std::{
    error::Error,
    fmt,
    fs::File,
    io::{self, Write},
    path::{Path, PathBuf},
    process::ExitCode,
};

use clap::{Parser, ValueEnum};
use rustix::fs::{renameat_with, RenameFlags, CWD};
use serde::Serialize;
use tempfile::NamedTempFile;
#[cfg(test)]
use zaino_oram::{ExperimentPlan, Quiescence, QuiescencePolicy, TimingSeed};
use zaino_oram::{RostlTimingMode, MINIMUM_PAIRS};

#[path = "../timing_contract.rs"]
mod timing_contract;
#[path = "../timing_driver.rs"]
mod timing_driver;

#[cfg(test)]
use timing_contract::{
    derive_seed, occupancy_window, table_set_relation, timed_operation_model,
    validate_evidence_intent, DIRECTORY_REPORT_SEED_DOMAIN, DIRECTORY_SCHEDULE_SEED_DOMAIN,
    EVENT_REPORT_SEED_DOMAIN, EVENT_SCHEDULE_SEED_DOMAIN, STATISTICAL_SCOPE,
    TARGET_PROJECTION_MODEL, TIMING_EVIDENCE_SCHEMA as SCHEMA,
};
use timing_contract::{EvidenceIntent, DEFAULT_WARMUP_PAIRS, SUPPORTED_MODES};
#[cfg(test)]
use timing_driver::{
    evaluate_environment_admission, parse_cpus_allowed_list, parse_loadavg,
    parse_scheduler_stats_control, EnvironmentAdmission, EnvironmentSnapshot, TimingDriverError,
    TimingEvidenceMetadata,
};
use timing_driver::{execute_prepared_timing_run, prepare_timing_run, RunOutcome, TimingRunInputs};

type DriverResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

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

impl TimingModeArgument {
    const fn rostl_mode(self) -> RostlTimingMode {
        match self {
            Self::HitMiss => SUPPORTED_MODES[0],
            Self::ForcedHit => SUPPORTED_MODES[1],
            Self::ForcedMiss => SUPPORTED_MODES[2],
        }
    }
}

#[derive(Debug)]
enum DriverError {
    OutputExists,
    PublishedButDurabilityUncertain { source: io::Error },
}

impl fmt::Display for DriverError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OutputExists => formatter.write_str("timing output path already exists"),
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
    if cli.output.try_exists()? {
        return Err(DriverError::OutputExists.into());
    }
    let inputs = TimingRunInputs::new(
        cli.mode.rostl_mode(),
        cli.evidence_intent,
        cli.pairs,
        cli.warmup_pairs,
        cli.directory_capacity,
        cli.directory_initial_occupancy,
        cli.event_capacity,
        cli.event_initial_occupancy,
        cli.mean_bound_nanos,
        cli.cdf_distance_bound,
        cli.max_load_average_1m,
        cli.max_competing_processes,
        cli.max_runqueue_wait_ratio,
        cli.seed,
    );
    let completed = execute_prepared_timing_run(prepare_timing_run(inputs)?)?;
    publish_bytes(&cli.output, completed.raw_v3_bytes())?;
    println!("timing_evidence={}", cli.output.display());
    Ok(completed.outcome())
}

#[allow(dead_code)]
fn publish_json(path: &Path, evidence: &impl Serialize) -> DriverResult<()> {
    publish_json_with_parent_sync(path, evidence, sync_parent)
}

#[allow(dead_code)]
fn publish_json_with_parent_sync<F>(
    path: &Path,
    evidence: &impl Serialize,
    sync_parent: F,
) -> DriverResult<()>
where
    F: FnOnce(&Path) -> io::Result<()>,
{
    let mut encoded = serde_json::to_vec_pretty(evidence)?;
    encoded.push(b'\n');
    publish_bytes_with_parent_sync(path, &encoded, sync_parent)
}

fn publish_bytes(path: &Path, encoded: &[u8]) -> DriverResult<()> {
    publish_bytes_with_parent_sync(path, encoded, sync_parent)
}

fn publish_bytes_with_parent_sync<F>(
    path: &Path,
    encoded: &[u8],
    sync_parent: F,
) -> DriverResult<()>
where
    F: FnOnce(&Path) -> io::Result<()>,
{
    let parent = path
        .parent()
        .filter(|candidate| !candidate.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let _: serde_json::Value = serde_json::from_slice(encoded)?;

    let mut temporary = NamedTempFile::new_in(parent)?;
    temporary.write_all(encoded)?;
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
            Err(TimingDriverError::MissingCpuAllowance)
        ));
        assert!(matches!(
            parse_loadavg("not-a-number 0.1 0.2 1/2 3"),
            Err(TimingDriverError::InvalidLoadAverage)
        ));
        assert!(matches!(
            parse_loadavg("0.1 0.1 0.2 invalid 3"),
            Err(TimingDriverError::InvalidRunnableProcesses)
        ));
        assert!(matches!(
            parse_loadavg("0.1 0.1 0.2 0/3 4"),
            Err(TimingDriverError::InvalidRunnableProcesses)
        ));
        assert!(matches!(
            parse_scheduler_stats_control("enabled"),
            Err(TimingDriverError::InvalidSchedulerStatsControl)
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
            Err(timing_contract::TimingContractError::UnderpoweredQualificationCandidate { .. })
        ));
        assert!(matches!(
            validate_evidence_intent(
                EvidenceIntent::QualificationCandidate,
                MINIMUM_PAIRS + 1,
                DEFAULT_WARMUP_PAIRS
            ),
            Err(timing_contract::TimingContractError::UnbalancedQualificationCandidate)
        ));
        assert!(matches!(
            validate_evidence_intent(
                EvidenceIntent::QualificationCandidate,
                MINIMUM_PAIRS + 2,
                DEFAULT_WARMUP_PAIRS
            ),
            Err(timing_contract::TimingContractError::UnbalancedQualificationCandidate)
        ));
        assert!(matches!(
            validate_evidence_intent(
                EvidenceIntent::QualificationCandidate,
                MINIMUM_PAIRS,
                DEFAULT_WARMUP_PAIRS + 1
            ),
            Err(timing_contract::TimingContractError::UnbalancedQualificationCandidate)
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
            timing_contract::OccupancyWindow {
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
