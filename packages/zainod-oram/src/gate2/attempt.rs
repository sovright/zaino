//! Durable, manifest-bound attempt records for Gate 2 timing cells.

use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    ffi::{OsStr, OsString},
    fmt, fs, io,
    path::{Path, PathBuf},
    process::Command,
};

use blake2::{Blake2s256, Digest};
use serde::{Deserialize, Serialize};

use crate::{
    corpus_artifact::{
        artifact_blake2s256_hex, artifact_directory_entry_names, lock_artifact_directory_exclusive,
        open_artifact_child_directory, open_artifact_directory, publish_verified_child_artifact,
        read_artifact_file, validate_artifact_file_set, ArtifactDirectory, ArtifactError,
        ArtifactFile,
    },
    timing_contract::{
        derive_seed, EvidenceIntent, DIRECTORY_REPORT_SEED_DOMAIN, DIRECTORY_SCHEDULE_SEED_DOMAIN,
        EVENT_REPORT_SEED_DOMAIN, EVENT_SCHEDULE_SEED_DOMAIN, TARGET_PROJECTION_MODEL,
        TIMING_EVIDENCE_SCHEMA,
    },
    timing_driver::{
        parse_cpus_allowed_list, parse_scheduler_stats_control, prepare_timing_run,
        start_and_execute_timing_run, PreparedTimingRun, StartedExecution, TimingRunInputs,
    },
};

use super::manifest::{
    admit_timing_manifest, inspect_timing_manifest_execution, AdmittedTimingManifest,
    TimingExecutionCellV1, TimingManifestError, TimingManifestInspectInputs,
    TimingManifestRecordBindingV1, TimingManifestVerifyInputs,
};

const ATTEMPT_SCHEMA: &str = "zaino-oram-gate2-attempt-v1";
const CPU_ENVIRONMENT_SCHEMA: &str = "zaino-oram-gate2-cpu-environment-v1";
const ATTEMPT_ID_DOMAIN: &[u8] = b"zaino-oram-gate2-attempt-id-v1";
const RECORD_JSON: &str = "record.json";
const TIMING_V3_JSON: &str = "timing-v3.json";
const MAX_RECORD_BYTES: usize = 4 * 1024 * 1024;
const MAX_TIMING_V3_BYTES: usize = 512 * 1024 * 1024;
const MAX_CONTROL_BYTES: usize = 4 * 1024 * 1024;
const LINK_NAME_WIDTH: usize = 20;
const NUMACTL_PATH: &str = "/usr/bin/numactl";
const CPU_ONLINE_PATH: &str = "/sys/devices/system/cpu/online";
const SMT_ACTIVE_PATH: &str = "/sys/devices/system/cpu/smt/active";
const SMT_CONTROL_PATH: &str = "/sys/devices/system/cpu/smt/control";
const GLOBAL_BOOST_PATH: &str = "/sys/devices/system/cpu/cpufreq/boost";
const INTEL_NO_TURBO_PATH: &str = "/sys/devices/system/cpu/intel_pstate/no_turbo";
const AMD_PSTATE_STATUS_PATH: &str = "/sys/devices/system/cpu/amd_pstate/status";
const CPU_INFO_PATH: &str = "/proc/cpuinfo";
const SELF_STATUS_PATH: &str = "/proc/self/status";
const SCHED_STATS_PATH: &str = "/proc/sys/kernel/sched_schedstats";
const KERNEL_CMDLINE_PATH: &str = "/proc/cmdline";
const CLOCKSOURCE_PATH: &str = "/sys/devices/system/clocksource/clocksource0/current_clocksource";
const VULNERABILITIES_PATH: &str = "/sys/devices/system/cpu/vulnerabilities";
const TASK_MITIGATION_FIELDS: [&str; 4] = [
    "SpeculationIndirectBranch",
    "Speculation_Store_Bypass",
    "x86_Thread_features",
    "x86_Thread_features_locked",
];
const BOOST_AND_TURBO_CONTROL_NAMES: [&str; 3] = [
    "amd_pstate_status",
    "global_cpufreq_boost",
    "intel_pstate_no_turbo",
];
const NUMACTL_CONTROL_NAMES: [&str; 7] = [
    "cpubind",
    "membind",
    "nodebind",
    "physcpubind",
    "policy",
    "preferred",
    "preferred node",
];

pub(crate) struct TimingAttemptRunInputs {
    pub(crate) manifest_dir: PathBuf,
    pub(crate) release_receipt: PathBuf,
    pub(crate) expected_manifest_blake2s256: String,
    pub(crate) ledger_dir: PathBuf,
}

pub(crate) struct TimingAttemptInspectInputs {
    pub(crate) manifest_dir: PathBuf,
    pub(crate) expected_manifest_blake2s256: String,
    pub(crate) ledger_dir: PathBuf,
    pub(crate) expected_head_sequence: Option<u64>,
    pub(crate) expected_head_blake2s256: Option<String>,
}

pub(crate) struct TimingAttemptSealInputs {
    pub(crate) manifest_dir: PathBuf,
    pub(crate) expected_manifest_blake2s256: String,
    pub(crate) ledger_dir: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TimingAttemptTerminalState {
    CompletedPositive,
    CompletedNegative,
    StartedError,
}

#[derive(Debug)]
pub(crate) struct TimingAttemptSummary {
    cell_id: String,
    terminal_state: TimingAttemptTerminalState,
    head_sequence: u64,
    head_blake2s256: String,
}

impl TimingAttemptSummary {
    pub(crate) fn cell_id(&self) -> &str {
        &self.cell_id
    }

    pub(crate) const fn terminal_state(&self) -> TimingAttemptTerminalState {
        self.terminal_state
    }

    pub(crate) const fn head_sequence(&self) -> u64 {
        self.head_sequence
    }

    pub(crate) fn head_blake2s256(&self) -> &str {
        &self.head_blake2s256
    }
}

#[derive(Debug)]
pub(crate) struct TimingLedgerSummary {
    manifest_blake2s256: String,
    cell_count: usize,
    started_cells: usize,
    terminal_cells: usize,
    positive_cells: usize,
    negative_cells: usize,
    started_error_cells: usize,
    dangling_cell_id: Option<String>,
    head: Option<HeadV1>,
    externally_witnessed: bool,
    all_cells_terminal: bool,
    all_cells_declared_positive: bool,
}

impl TimingLedgerSummary {
    pub(crate) fn manifest_blake2s256(&self) -> &str {
        &self.manifest_blake2s256
    }

    pub(crate) const fn cell_count(&self) -> usize {
        self.cell_count
    }

    pub(crate) const fn started_cells(&self) -> usize {
        self.started_cells
    }

    pub(crate) const fn terminal_cells(&self) -> usize {
        self.terminal_cells
    }

    pub(crate) const fn positive_cells(&self) -> usize {
        self.positive_cells
    }

    pub(crate) const fn negative_cells(&self) -> usize {
        self.negative_cells
    }

    pub(crate) const fn started_error_cells(&self) -> usize {
        self.started_error_cells
    }

    pub(crate) fn dangling_cell_id(&self) -> Option<&str> {
        self.dangling_cell_id.as_deref()
    }

    pub(crate) fn head(&self) -> Option<(u64, &str)> {
        self.head
            .as_ref()
            .map(|head| (head.sequence, head.record_blake2s256.as_str()))
    }

    pub(crate) const fn externally_witnessed(&self) -> bool {
        self.externally_witnessed
    }

    pub(crate) const fn all_cells_terminal(&self) -> bool {
        self.all_cells_terminal
    }

    pub(crate) const fn all_cells_declared_positive(&self) -> bool {
        self.all_cells_declared_positive
    }
}

pub(crate) enum TimingAttemptOutcome {
    Completed(TimingAttemptSummary),
    ExecutionError {
        summary: TimingAttemptSummary,
        source: Box<dyn Error + Send + Sync>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PreviousLinkV1 {
    sequence: u64,
    record_blake2s256: String,
}

type HeadV1 = PreviousLinkV1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AttemptLimitationsV1 {
    self_reported: bool,
    temporally_attested: bool,
    external_head_witness_in_record: bool,
    detects_retained_interior_omission: bool,
    detects_unwitnessed_suffix_or_root_deletion: bool,
    raw_outcome_independently_recomputed: bool,
    can_clear_gate2: bool,
}

impl AttemptLimitationsV1 {
    const fn fixed() -> Self {
        Self {
            self_reported: true,
            temporally_attested: false,
            external_head_witness_in_record: false,
            detects_retained_interior_omission: true,
            detects_unwitnessed_suffix_or_root_deletion: false,
            raw_outcome_independently_recomputed: false,
            can_clear_gate2: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NamedControlV1 {
    name: String,
    value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NumaPolicyV1 {
    reporter: String,
    reporter_blake2s256: String,
    controls: Vec<NamedControlV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CpuEnvironmentV1 {
    schema: String,
    selected_cpu: u32,
    cpus_allowed_list: String,
    mems_allowed_list: String,
    numa_policy: NumaPolicyV1,
    online_cpu_list: String,
    selected_cpu_online_state: String,
    thread_siblings_list: String,
    smt_active: Option<bool>,
    smt_control: Option<String>,
    scaling_driver: Option<String>,
    scaling_governor: Option<String>,
    scaling_min_frequency: Option<String>,
    scaling_max_frequency: Option<String>,
    scaling_current_frequency: Option<String>,
    boost_and_turbo_controls: Vec<NamedControlV1>,
    task_mitigation_controls: Vec<NamedControlV1>,
    microcode: String,
    cpu_flags_blake2s256: String,
    cpu_flag_count: usize,
    cpu_bugs_blake2s256: String,
    cpu_bug_count: usize,
    vulnerabilities_blake2s256: String,
    vulnerability_entry_count: usize,
    kernel_cmdline_blake2s256: String,
    current_clocksource: String,
    scheduler_stats_enabled: bool,
    self_reported: bool,
    attested: bool,
}

impl CpuEnvironmentV1 {
    fn capture(prepared: &PreparedTimingRun) -> Result<Self, TimingAttemptError> {
        capture_environment(prepared.pinned_cpu(), prepared.cpus_allowed_list())
    }

    fn validate(&self) -> Result<(), TimingAttemptError> {
        if self.schema != CPU_ENVIRONMENT_SCHEMA
            || self.cpus_allowed_list != self.selected_cpu.to_string()
            || self.mems_allowed_list.is_empty()
            || self.numa_policy.reporter != NUMACTL_PATH
            || self.online_cpu_list.is_empty()
            || self.selected_cpu_online_state.is_empty()
            || self.thread_siblings_list.is_empty()
            || self.microcode.is_empty()
            || self.current_clocksource.is_empty()
            || !self.scheduler_stats_enabled
            || !self.self_reported
            || self.attested
        {
            return Err(TimingAttemptError::InvalidCpuEnvironment {
                reason: "attempt CPU environment binding is invalid",
            });
        }
        validate_digest(&self.numa_policy.reporter_blake2s256)?;
        validate_named_controls(
            &self.numa_policy.controls,
            &NUMACTL_CONTROL_NAMES,
            "NUMA memory-policy controls are invalid",
        )?;
        if !self
            .numa_policy
            .controls
            .iter()
            .any(|control| control.name == "policy")
            || !self
                .numa_policy
                .controls
                .iter()
                .any(|control| control.name == "membind")
        {
            return Err(TimingAttemptError::InvalidCpuEnvironment {
                reason: "NUMA memory-policy controls omit policy or membind",
            });
        }
        validate_named_controls(
            &self.boost_and_turbo_controls,
            &BOOST_AND_TURBO_CONTROL_NAMES,
            "boost and turbo controls are invalid",
        )?;
        validate_named_controls(
            &self.task_mitigation_controls,
            &TASK_MITIGATION_FIELDS,
            "task mitigation controls are invalid",
        )?;
        for digest in [
            &self.cpu_flags_blake2s256,
            &self.cpu_bugs_blake2s256,
            &self.vulnerabilities_blake2s256,
            &self.kernel_cmdline_blake2s256,
        ] {
            validate_digest(digest)?;
        }
        Ok(())
    }

    fn stable_controls_equal(&self, other: &Self) -> bool {
        let mut left = self.clone();
        let mut right = other.clone();
        left.scaling_current_frequency = None;
        right.scaling_current_frequency = None;
        left == right
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTimingBindingV1 {
    file: String,
    blake2s256: String,
    size_bytes: u64,
    raw_declared_wall_clock_criteria_satisfied: bool,
    overall_attempt_admitted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CompletionPayloadV1 {
    started_record_blake2s256: String,
    cpu_environment_after: CpuEnvironmentV1,
    controls_stable: bool,
    raw: RawTimingBindingV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum StartedErrorStageV1 {
    TimingExecution,
    PostExecutionEnvironmentCapture,
    PriorProcessInterrupted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StartedErrorPayloadV1 {
    started_record_blake2s256: String,
    failure_stage: StartedErrorStageV1,
    error_code: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", content = "payload", rename_all = "snake_case")]
enum AttemptStateV1 {
    Started {
        cpu_environment_before: CpuEnvironmentV1,
    },
    CompletedPositive(CompletionPayloadV1),
    CompletedNegative(CompletionPayloadV1),
    StartedError(StartedErrorPayloadV1),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AttemptRecordV1 {
    schema: String,
    execution_runner_version: String,
    record_writer_version: String,
    sequence: u64,
    previous: Option<PreviousLinkV1>,
    attempt_id_blake2s256: String,
    manifest: TimingManifestRecordBindingV1,
    cell: TimingExecutionCellV1,
    limitations: AttemptLimitationsV1,
    #[serde(flatten)]
    state: AttemptStateV1,
}

impl AttemptRecordV1 {
    fn new(
        sequence: u64,
        previous: Option<PreviousLinkV1>,
        manifest: &TimingManifestRecordBindingV1,
        cell: &TimingExecutionCellV1,
        runner_version: &str,
        state: AttemptStateV1,
    ) -> Result<Self, TimingAttemptError> {
        let record = Self {
            schema: ATTEMPT_SCHEMA.to_owned(),
            execution_runner_version: manifest.runner_version().to_owned(),
            record_writer_version: runner_version.to_owned(),
            sequence,
            previous,
            attempt_id_blake2s256: attempt_id(manifest, cell),
            manifest: manifest.clone(),
            cell: cell.clone(),
            limitations: AttemptLimitationsV1::fixed(),
            state,
        };
        record.validate_common(manifest, cell)?;
        Ok(record)
    }

    fn validate_common(
        &self,
        manifest: &TimingManifestRecordBindingV1,
        cell: &TimingExecutionCellV1,
    ) -> Result<(), TimingAttemptError> {
        if self.schema != ATTEMPT_SCHEMA
            || self.execution_runner_version != manifest.runner_version()
            || self.record_writer_version.is_empty()
            || self.manifest != *manifest
            || self.cell != *cell
            || self.attempt_id_blake2s256 != attempt_id(manifest, cell)
            || self.limitations != AttemptLimitationsV1::fixed()
        {
            return Err(TimingAttemptError::InvalidLedger {
                reason: "attempt record identity or fixed contract mismatch",
            });
        }
        if let Some(previous) = &self.previous {
            validate_digest(&previous.record_blake2s256)?;
        }
        match &self.state {
            AttemptStateV1::Started {
                cpu_environment_before,
            } => {
                if self.record_writer_version != self.execution_runner_version {
                    return Err(TimingAttemptError::InvalidLedger {
                        reason: "started record writer differs from the manifest runner",
                    });
                }
                cpu_environment_before.validate()?;
            }
            AttemptStateV1::CompletedPositive(payload)
            | AttemptStateV1::CompletedNegative(payload) => {
                if self.record_writer_version != self.execution_runner_version {
                    return Err(TimingAttemptError::InvalidLedger {
                        reason: "completed record writer differs from the manifest runner",
                    });
                }
                validate_digest(&payload.started_record_blake2s256)?;
                payload.cpu_environment_after.validate()?;
                validate_digest(&payload.raw.blake2s256)?;
                if payload.raw.file != TIMING_V3_JSON || payload.raw.size_bytes == 0 {
                    return Err(TimingAttemptError::InvalidLedger {
                        reason: "completed attempt raw timing binding is invalid",
                    });
                }
            }
            AttemptStateV1::StartedError(payload) => {
                if payload.failure_stage != StartedErrorStageV1::PriorProcessInterrupted
                    && self.record_writer_version != self.execution_runner_version
                {
                    return Err(TimingAttemptError::InvalidLedger {
                        reason: "execution-error record writer differs from the manifest runner",
                    });
                }
                validate_digest(&payload.started_record_blake2s256)?;
                if payload.error_code.is_empty() {
                    return Err(TimingAttemptError::InvalidLedger {
                        reason: "started-error attempt code is empty",
                    });
                }
            }
        }
        Ok(())
    }

    fn canonical_bytes(&self) -> Result<Vec<u8>, TimingAttemptError> {
        Ok(serde_json::to_vec(self)?)
    }
}

struct StartedToken {
    record: AttemptRecordV1,
    digest: String,
}

struct LoadedLedger {
    head: Option<HeadV1>,
    next_sequence: u64,
    next_cell_ordinal: usize,
    started_cells: usize,
    terminal_cells: usize,
    positive_cells: usize,
    negative_cells: usize,
    started_error_cells: usize,
    dangling: Option<StartedToken>,
    baseline_environment: Option<CpuEnvironmentV1>,
}

impl LoadedLedger {
    fn all_cells_terminal(&self, manifest: &AdmittedTimingManifest) -> bool {
        self.dangling.is_none() && self.next_cell_ordinal == manifest.cells().len()
    }

    fn summary(
        &self,
        manifest: &AdmittedTimingManifest,
        externally_witnessed: bool,
    ) -> TimingLedgerSummary {
        let all_cells_terminal = self.all_cells_terminal(manifest);
        TimingLedgerSummary {
            manifest_blake2s256: manifest.record_binding().manifest_blake2s256().to_owned(),
            cell_count: manifest.cells().len(),
            started_cells: self.started_cells,
            terminal_cells: self.terminal_cells,
            positive_cells: self.positive_cells,
            negative_cells: self.negative_cells,
            started_error_cells: self.started_error_cells,
            dangling_cell_id: self
                .dangling
                .as_ref()
                .map(|started| started.record.cell.id().to_owned()),
            head: self.head.clone(),
            externally_witnessed,
            all_cells_terminal,
            all_cells_declared_positive: all_cells_terminal
                && self.positive_cells == manifest.cells().len(),
        }
    }
}

pub(crate) fn run_timing_attempt(
    inputs: TimingAttemptRunInputs,
    runner_version: &str,
) -> Result<TimingAttemptOutcome, TimingAttemptError> {
    let manifest = admit_timing_manifest(
        TimingManifestVerifyInputs {
            manifest_dir: inputs.manifest_dir,
            release_receipt: inputs.release_receipt,
            expected_manifest_blake2s256: inputs.expected_manifest_blake2s256,
        },
        runner_version,
    )?;
    let ledger_dir = open_artifact_directory(&inputs.ledger_dir)?;
    lock_artifact_directory_exclusive(&ledger_dir)?;
    let ledger = load_ledger(&ledger_dir, &manifest)?;
    if ledger.dangling.is_some() {
        return Err(TimingAttemptError::DanglingStarted);
    }
    if ledger.all_cells_terminal(&manifest) {
        return Err(TimingAttemptError::MatrixComplete);
    }
    let cell = manifest
        .cells()
        .get(ledger.next_cell_ordinal)
        .ok_or(TimingAttemptError::InvalidLedger {
            reason: "next timing cell ordinal is outside the manifest",
        })?
        .clone();
    let prepared = prepare_timing_run(cell.inputs().clone())
        .map_err(|source| TimingAttemptError::Prestart { source })?;
    let environment_before = CpuEnvironmentV1::capture(&prepared)?;
    if ledger
        .baseline_environment
        .as_ref()
        .is_some_and(|baseline| !baseline.stable_controls_equal(&environment_before))
    {
        return Err(TimingAttemptError::CrossCellEnvironmentMismatch);
    }
    let started_record = AttemptRecordV1::new(
        ledger.next_sequence,
        ledger.head,
        manifest.record_binding(),
        &cell,
        runner_version,
        AttemptStateV1::Started {
            cpu_environment_before: environment_before.clone(),
        },
    )?;

    let execution = start_and_execute_timing_run(prepared, |_| {
        append_record(&ledger_dir, started_record.clone(), None)
    })?;
    match execution {
        StartedExecution::Completed { started, completed } => {
            let (raw_v3_bytes, raw_outcome) = completed.into_parts();
            let environment_after = match capture_after(&environment_before) {
                Ok(environment) => environment,
                Err(source) => {
                    let summary = append_started_error(
                        &ledger_dir,
                        &manifest,
                        &cell,
                        started,
                        StartedErrorStageV1::PostExecutionEnvironmentCapture,
                        "post_execution_environment_capture_failed",
                        runner_version,
                    )?;
                    return Ok(TimingAttemptOutcome::ExecutionError {
                        summary,
                        source: Box::new(source),
                    });
                }
            };
            let controls_stable = environment_before.stable_controls_equal(&environment_after);
            let overall_attempt_admitted =
                raw_outcome.declared_wall_clock_criteria_satisfied() && controls_stable;
            let raw_binding = RawTimingBindingV1 {
                file: TIMING_V3_JSON.to_owned(),
                blake2s256: artifact_blake2s256_hex(&raw_v3_bytes),
                size_bytes: u64::try_from(raw_v3_bytes.len()).map_err(|_| {
                    TimingAttemptError::InvalidLedger {
                        reason: "raw timing evidence size does not fit u64",
                    }
                })?,
                raw_declared_wall_clock_criteria_satisfied: raw_outcome
                    .declared_wall_clock_criteria_satisfied(),
                overall_attempt_admitted,
            };
            let payload = CompletionPayloadV1 {
                started_record_blake2s256: started.digest.clone(),
                cpu_environment_after: environment_after,
                controls_stable,
                raw: raw_binding,
            };
            let (state, terminal_state) = if overall_attempt_admitted {
                (
                    AttemptStateV1::CompletedPositive(payload),
                    TimingAttemptTerminalState::CompletedPositive,
                )
            } else {
                (
                    AttemptStateV1::CompletedNegative(payload),
                    TimingAttemptTerminalState::CompletedNegative,
                )
            };
            let terminal = terminal_record(&manifest, &cell, &started, state, runner_version)?;
            let terminal = append_record(&ledger_dir, terminal, Some(&raw_v3_bytes))?;
            Ok(TimingAttemptOutcome::Completed(summary_from_terminal(
                &cell,
                terminal_state,
                &terminal,
            )))
        }
        StartedExecution::Failed { started, source } => {
            let summary = append_started_error(
                &ledger_dir,
                &manifest,
                &cell,
                started,
                StartedErrorStageV1::TimingExecution,
                "timing_driver_execution_failed",
                runner_version,
            )?;
            Ok(TimingAttemptOutcome::ExecutionError { summary, source })
        }
    }
}

pub(crate) fn inspect_timing_attempt_ledger(
    inputs: TimingAttemptInspectInputs,
) -> Result<TimingLedgerSummary, TimingAttemptError> {
    validate_external_head_pair(
        inputs.expected_head_sequence,
        inputs.expected_head_blake2s256.as_deref(),
    )?;
    let manifest = inspect_timing_manifest_execution(TimingManifestInspectInputs {
        manifest_dir: inputs.manifest_dir,
        expected_manifest_blake2s256: inputs.expected_manifest_blake2s256,
    })?;
    inspect_admitted_timing_attempt_ledger(
        &manifest,
        &inputs.ledger_dir,
        inputs.expected_head_sequence,
        inputs.expected_head_blake2s256.as_deref(),
    )
}

fn inspect_admitted_timing_attempt_ledger(
    manifest: &AdmittedTimingManifest,
    ledger_path: &Path,
    expected_head_sequence: Option<u64>,
    expected_head_blake2s256: Option<&str>,
) -> Result<TimingLedgerSummary, TimingAttemptError> {
    validate_external_head_pair(expected_head_sequence, expected_head_blake2s256)?;
    let ledger_dir = open_artifact_directory(ledger_path)?;
    lock_artifact_directory_exclusive(&ledger_dir)?;
    let ledger = load_ledger(&ledger_dir, manifest)?;
    let externally_witnessed = match (expected_head_sequence, expected_head_blake2s256) {
        (Some(sequence), Some(digest)) => {
            if ledger.head
                != Some(HeadV1 {
                    sequence,
                    record_blake2s256: digest.to_owned(),
                })
            {
                return Err(TimingAttemptError::ExternalHeadMismatch);
            }
            true
        }
        (None, None) => false,
        _ => {
            return Err(TimingAttemptError::InvalidExternalHead);
        }
    };
    Ok(ledger.summary(manifest, externally_witnessed))
}

pub(crate) fn seal_dangling_timing_attempt(
    inputs: TimingAttemptSealInputs,
    runner_version: &str,
) -> Result<TimingAttemptSummary, TimingAttemptError> {
    let manifest = inspect_timing_manifest_execution(TimingManifestInspectInputs {
        manifest_dir: inputs.manifest_dir,
        expected_manifest_blake2s256: inputs.expected_manifest_blake2s256,
    })?;
    seal_admitted_dangling_timing_attempt(&manifest, &inputs.ledger_dir, runner_version)
}

fn seal_admitted_dangling_timing_attempt(
    manifest: &AdmittedTimingManifest,
    ledger_path: &Path,
    runner_version: &str,
) -> Result<TimingAttemptSummary, TimingAttemptError> {
    let ledger_dir = open_artifact_directory(ledger_path)?;
    lock_artifact_directory_exclusive(&ledger_dir)?;
    let ledger = load_ledger(&ledger_dir, manifest)?;
    let started = ledger
        .dangling
        .ok_or(TimingAttemptError::NoDanglingStarted)?;
    let cell = started.record.cell.clone();
    append_started_error(
        &ledger_dir,
        manifest,
        &cell,
        started,
        StartedErrorStageV1::PriorProcessInterrupted,
        "prior_process_interrupted",
        runner_version,
    )
}

fn capture_after(before: &CpuEnvironmentV1) -> Result<CpuEnvironmentV1, TimingAttemptError> {
    capture_environment(before.selected_cpu, &before.cpus_allowed_list)
}

fn append_started_error(
    ledger_dir: &ArtifactDirectory,
    manifest: &AdmittedTimingManifest,
    cell: &TimingExecutionCellV1,
    started: StartedToken,
    failure_stage: StartedErrorStageV1,
    error_code: &str,
    runner_version: &str,
) -> Result<TimingAttemptSummary, TimingAttemptError> {
    let terminal = terminal_record(
        manifest,
        cell,
        &started,
        AttemptStateV1::StartedError(StartedErrorPayloadV1 {
            started_record_blake2s256: started.digest.clone(),
            failure_stage,
            error_code: error_code.to_owned(),
        }),
        runner_version,
    )?;
    let terminal = append_record(ledger_dir, terminal, None)?;
    Ok(summary_from_terminal(
        cell,
        TimingAttemptTerminalState::StartedError,
        &terminal,
    ))
}

fn terminal_record(
    manifest: &AdmittedTimingManifest,
    cell: &TimingExecutionCellV1,
    started: &StartedToken,
    state: AttemptStateV1,
    runner_version: &str,
) -> Result<AttemptRecordV1, TimingAttemptError> {
    let sequence =
        started
            .record
            .sequence
            .checked_add(1)
            .ok_or(TimingAttemptError::InvalidLedger {
                reason: "attempt link sequence overflow",
            })?;
    AttemptRecordV1::new(
        sequence,
        Some(PreviousLinkV1 {
            sequence: started.record.sequence,
            record_blake2s256: started.digest.clone(),
        }),
        manifest.record_binding(),
        cell,
        runner_version,
        state,
    )
}

fn summary_from_terminal(
    cell: &TimingExecutionCellV1,
    terminal_state: TimingAttemptTerminalState,
    terminal: &StartedToken,
) -> TimingAttemptSummary {
    TimingAttemptSummary {
        cell_id: cell.id().to_owned(),
        terminal_state,
        head_sequence: terminal.record.sequence,
        head_blake2s256: terminal.digest.clone(),
    }
}

fn load_ledger(
    ledger_dir: &ArtifactDirectory,
    manifest: &AdmittedTimingManifest,
) -> Result<LoadedLedger, TimingAttemptError> {
    let names = artifact_directory_entry_names(ledger_dir)?;
    let mut link_names = Vec::new();
    let mut orphan_stage_targets = Vec::new();
    for name in names {
        if canonical_link_sequence(name.as_os_str()).is_some() {
            link_names.push(name);
        } else if let Some(target_sequence) = attempt_stage_target_sequence(name.as_os_str()) {
            // A crash can strand the publisher's private stage directory. Its
            // name is ignored only after proving it is a real child directory;
            // symlinks, files, and every other dot-name remain fatal.
            let _stage = open_artifact_child_directory(ledger_dir, name.as_os_str())?;
            orphan_stage_targets.push(target_sequence);
        } else {
            return Err(TimingAttemptError::InvalidLedger {
                reason: "attempt ledger contains a noncanonical entry name",
            });
        }
    }
    let mut head: Option<HeadV1> = None;
    let mut next_sequence = 0_u64;
    let mut next_cell_ordinal = 0_usize;
    let mut started_cells = 0_usize;
    let mut terminal_cells = 0_usize;
    let mut positive_cells = 0_usize;
    let mut negative_cells = 0_usize;
    let mut started_error_cells = 0_usize;
    let mut dangling: Option<StartedToken> = None;
    let mut baseline_environment: Option<CpuEnvironmentV1> = None;

    for name in link_names {
        let expected_name = link_name(next_sequence);
        if name != OsString::from(&expected_name) {
            return Err(TimingAttemptError::InvalidLedger {
                reason: "attempt ledger link names are not a gap-free canonical sequence",
            });
        }
        let directory = open_artifact_child_directory(ledger_dir, name.as_os_str())?;
        let record_bytes = read_artifact_file(&directory, RECORD_JSON, MAX_RECORD_BYTES)?;
        let record: AttemptRecordV1 = serde_json::from_slice(&record_bytes)?;
        if record.canonical_bytes()? != record_bytes || record.sequence != next_sequence {
            return Err(TimingAttemptError::InvalidLedger {
                reason: "attempt record JSON or link sequence is noncanonical",
            });
        }
        if record.previous != head {
            return Err(TimingAttemptError::InvalidLedger {
                reason: "attempt record previous-link digest does not match the retained head",
            });
        }
        let cell = manifest.cells().get(record.cell.ordinal()).ok_or(
            TimingAttemptError::InvalidLedger {
                reason: "attempt record cell ordinal is outside the manifest",
            },
        )?;
        record.validate_common(manifest.record_binding(), cell)?;
        let digest = artifact_blake2s256_hex(&record_bytes);
        match &record.state {
            AttemptStateV1::Started {
                cpu_environment_before,
            } => {
                validate_artifact_file_set(&directory, &[RECORD_JSON])?;
                if dangling.is_some() || record.cell.ordinal() != next_cell_ordinal {
                    return Err(TimingAttemptError::InvalidLedger {
                        reason: "attempt ledger contains an illegal started transition",
                    });
                }
                if baseline_environment
                    .as_ref()
                    .is_some_and(|baseline| !baseline.stable_controls_equal(cpu_environment_before))
                {
                    return Err(TimingAttemptError::InvalidLedger {
                        reason: "attempt ledger mixes CPU control baselines across cells",
                    });
                }
                if baseline_environment.is_none() {
                    baseline_environment = Some(cpu_environment_before.clone());
                }
                started_cells =
                    started_cells
                        .checked_add(1)
                        .ok_or(TimingAttemptError::InvalidLedger {
                            reason: "attempt started-cell count overflow",
                        })?;
                dangling = Some(StartedToken {
                    record: record.clone(),
                    digest: digest.clone(),
                });
            }
            AttemptStateV1::CompletedPositive(payload)
            | AttemptStateV1::CompletedNegative(payload) => {
                validate_artifact_file_set(&directory, &[RECORD_JSON, TIMING_V3_JSON])?;
                let started = dangling.take().ok_or(TimingAttemptError::InvalidLedger {
                    reason: "completed attempt has no immediately preceding started link",
                })?;
                validate_terminal_start_binding(
                    &record,
                    payload.started_record_blake2s256.as_str(),
                    &started,
                )?;
                if record.execution_runner_version != started.record.execution_runner_version
                    || record.record_writer_version != started.record.record_writer_version
                {
                    return Err(TimingAttemptError::InvalidLedger {
                        reason: "completed attempt runner version differs from its started record",
                    });
                }
                let raw_bytes =
                    read_artifact_file(&directory, TIMING_V3_JSON, MAX_TIMING_V3_BYTES)?;
                validate_raw_binding(&record, payload, &raw_bytes, &started)?;
                next_cell_ordinal =
                    next_cell_ordinal
                        .checked_add(1)
                        .ok_or(TimingAttemptError::InvalidLedger {
                            reason: "attempt terminal-cell count overflow",
                        })?;
                terminal_cells =
                    terminal_cells
                        .checked_add(1)
                        .ok_or(TimingAttemptError::InvalidLedger {
                            reason: "attempt terminal-cell count overflow",
                        })?;
                if matches!(&record.state, AttemptStateV1::CompletedPositive(_)) {
                    positive_cells =
                        positive_cells
                            .checked_add(1)
                            .ok_or(TimingAttemptError::InvalidLedger {
                                reason: "positive attempt count overflow",
                            })?;
                } else {
                    negative_cells =
                        negative_cells
                            .checked_add(1)
                            .ok_or(TimingAttemptError::InvalidLedger {
                                reason: "negative attempt count overflow",
                            })?;
                }
            }
            AttemptStateV1::StartedError(payload) => {
                validate_artifact_file_set(&directory, &[RECORD_JSON])?;
                let started = dangling.take().ok_or(TimingAttemptError::InvalidLedger {
                    reason: "started-error attempt has no immediately preceding started link",
                })?;
                validate_terminal_start_binding(
                    &record,
                    payload.started_record_blake2s256.as_str(),
                    &started,
                )?;
                next_cell_ordinal =
                    next_cell_ordinal
                        .checked_add(1)
                        .ok_or(TimingAttemptError::InvalidLedger {
                            reason: "attempt terminal-cell count overflow",
                        })?;
                terminal_cells =
                    terminal_cells
                        .checked_add(1)
                        .ok_or(TimingAttemptError::InvalidLedger {
                            reason: "attempt terminal-cell count overflow",
                        })?;
                started_error_cells = started_error_cells.checked_add(1).ok_or(
                    TimingAttemptError::InvalidLedger {
                        reason: "started-error attempt count overflow",
                    },
                )?;
            }
        }
        head = Some(HeadV1 {
            sequence: record.sequence,
            record_blake2s256: digest,
        });
        next_sequence = next_sequence
            .checked_add(1)
            .ok_or(TimingAttemptError::InvalidLedger {
                reason: "attempt link sequence overflow",
            })?;
    }
    if orphan_stage_targets
        .into_iter()
        .any(|target_sequence| target_sequence > next_sequence)
    {
        return Err(TimingAttemptError::InvalidLedger {
            reason: "orphan attempt stage targets a future ledger sequence",
        });
    }
    Ok(LoadedLedger {
        head,
        next_sequence,
        next_cell_ordinal,
        started_cells,
        terminal_cells,
        positive_cells,
        negative_cells,
        started_error_cells,
        dangling,
        baseline_environment,
    })
}

fn validate_terminal_start_binding(
    terminal: &AttemptRecordV1,
    started_record_blake2s256: &str,
    started: &StartedToken,
) -> Result<(), TimingAttemptError> {
    if terminal.cell != started.record.cell
        || started_record_blake2s256 != started.digest
        || terminal.previous
            != Some(PreviousLinkV1 {
                sequence: started.record.sequence,
                record_blake2s256: started.digest.clone(),
            })
    {
        return Err(TimingAttemptError::InvalidLedger {
            reason: "attempt terminal does not bind its immediately preceding started record",
        });
    }
    Ok(())
}

fn validate_raw_binding(
    record: &AttemptRecordV1,
    payload: &CompletionPayloadV1,
    raw_bytes: &[u8],
    started: &StartedToken,
) -> Result<(), TimingAttemptError> {
    let raw_size =
        u64::try_from(raw_bytes.len()).map_err(|_| TimingAttemptError::InvalidLedger {
            reason: "retained raw timing evidence size does not fit u64",
        })?;
    let before = match &started.record.state {
        AttemptStateV1::Started {
            cpu_environment_before,
        } => cpu_environment_before,
        _ => {
            return Err(TimingAttemptError::InvalidLedger {
                reason: "attempt terminal predecessor is not a started state",
            });
        }
    };
    if payload.raw.blake2s256 != artifact_blake2s256_hex(raw_bytes)
        || payload.raw.size_bytes != raw_size
        || payload.controls_stable != before.stable_controls_equal(&payload.cpu_environment_after)
    {
        return Err(TimingAttemptError::InvalidLedger {
            reason: "retained raw timing evidence digest, size, or controls binding mismatch",
        });
    }
    let declared = validate_raw_timing_v3(
        raw_bytes,
        record.cell.inputs(),
        &started.record.execution_runner_version,
    )?;
    if declared != payload.raw.raw_declared_wall_clock_criteria_satisfied
        || payload.raw.overall_attempt_admitted != (declared && payload.controls_stable)
    {
        return Err(TimingAttemptError::InvalidLedger {
            reason: "retained raw timing outcome does not match the terminal record",
        });
    }
    match &record.state {
        AttemptStateV1::CompletedPositive(_) if !payload.raw.overall_attempt_admitted => {
            Err(TimingAttemptError::InvalidLedger {
                reason: "positive attempt terminal does not contain an admitted result",
            })
        }
        AttemptStateV1::CompletedNegative(_) if payload.raw.overall_attempt_admitted => {
            Err(TimingAttemptError::InvalidLedger {
                reason: "negative attempt terminal overstates an admitted result",
            })
        }
        _ => Ok(()),
    }
}

fn append_record(
    ledger_dir: &ArtifactDirectory,
    record: AttemptRecordV1,
    raw_v3_bytes: Option<&[u8]>,
) -> Result<StartedToken, TimingAttemptError> {
    let record_bytes = record.canonical_bytes()?;
    let mut files = vec![ArtifactFile::new(RECORD_JSON, record_bytes.clone())];
    if let Some(raw_v3_bytes) = raw_v3_bytes {
        files.push(ArtifactFile::new(TIMING_V3_JSON, raw_v3_bytes.to_vec()));
    }
    let output_name = link_name(record.sequence);
    publish_verified_child_artifact(ledger_dir, OsStr::new(&output_name), &files, |stage| {
        let expected_files = if raw_v3_bytes.is_some() {
            &[RECORD_JSON, TIMING_V3_JSON][..]
        } else {
            &[RECORD_JSON][..]
        };
        validate_artifact_file_set(stage, expected_files)?;
        if read_artifact_file(stage, RECORD_JSON, MAX_RECORD_BYTES)? != record_bytes {
            return Err(ArtifactError::InvalidArtifact {
                reason: "staged attempt record differs after read-back",
            });
        }
        if let Some(expected_raw) = raw_v3_bytes {
            if read_artifact_file(stage, TIMING_V3_JSON, MAX_TIMING_V3_BYTES)? != expected_raw {
                return Err(ArtifactError::InvalidArtifact {
                    reason: "staged raw timing evidence differs after read-back",
                });
            }
        }
        Ok(())
    })?;
    Ok(StartedToken {
        digest: artifact_blake2s256_hex(&record_bytes),
        record,
    })
}

fn validate_raw_timing_v3(
    bytes: &[u8],
    inputs: &TimingRunInputs,
    expected_runner_version: &str,
) -> Result<bool, TimingAttemptError> {
    if bytes.last().copied() != Some(b'\n') {
        return Err(TimingAttemptError::InvalidLedger {
            reason: "raw timing-v3 evidence lacks its required trailing newline",
        });
    }
    let value: serde_json::Value = serde_json::from_slice(bytes)?;
    expect_json(
        &value,
        &["schema"],
        serde_json::json!(TIMING_EVIDENCE_SCHEMA),
    )?;
    expect_json(
        &value,
        &["runner_version"],
        serde_json::json!(expected_runner_version),
    )?;
    expect_json(&value, &["platform_os"], serde_json::json!("linux"))?;
    expect_json(&value, &["platform_arch"], serde_json::json!("x86_64"))?;
    expect_json(&value, &["mode"], serde_json::to_value(inputs.mode())?)?;
    expect_json(
        &value,
        &["evidence_intent"],
        serde_json::to_value(EvidenceIntent::QualificationCandidate)?,
    )?;
    expect_json(&value, &["wall_clock_only"], serde_json::json!(true))?;
    expect_json(
        &value,
        &["physical_trace_complete"],
        serde_json::json!(false),
    )?;
    expect_json(&value, &["oram_state_seed_bound"], serde_json::json!(false))?;
    expect_json(
        &value,
        &["serial_independence_established"],
        serde_json::json!(false),
    )?;
    expect_json(
        &value,
        &["target_projection_model"],
        serde_json::json!(TARGET_PROJECTION_MODEL),
    )?;
    expect_json(
        &value,
        &["target_projection_model_implemented"],
        serde_json::json!(false),
    )?;
    expect_json(&value, &["can_clear_gate2"], serde_json::json!(false))?;
    expect_json(
        &value,
        &["policy", "max_load_average_1m"],
        serde_json::json!(inputs.max_load_average_1m()),
    )?;
    expect_json(
        &value,
        &["policy", "max_competing_processes"],
        serde_json::json!(inputs.max_competing_processes()),
    )?;
    expect_json(
        &value,
        &["max_runqueue_wait_ratio"],
        serde_json::json!(inputs.max_runqueue_wait_ratio()),
    )?;
    validate_raw_record(
        &value,
        "directory",
        inputs.directory_capacity(),
        inputs.directory_initial_occupancy(),
        inputs,
        DIRECTORY_SCHEDULE_SEED_DOMAIN,
        DIRECTORY_REPORT_SEED_DOMAIN,
    )?;
    validate_raw_record(
        &value,
        "event",
        inputs.event_capacity(),
        inputs.event_initial_occupancy(),
        inputs,
        EVENT_SCHEDULE_SEED_DOMAIN,
        EVENT_REPORT_SEED_DOMAIN,
    )?;
    let declared = json_path(&value, &["declared_wall_clock_criteria_satisfied"])?
        .as_bool()
        .ok_or(TimingAttemptError::InvalidLedger {
            reason: "raw timing-v3 completion flag is not boolean",
        })?;
    let environment_admitted = required_bool(&value, &["environment_admitted"])?;
    let directory_bounds_satisfied =
        required_bool(&value, &["directory", "report", "bounds_satisfied"])?;
    let event_bounds_satisfied = required_bool(&value, &["event", "report", "bounds_satisfied"])?;
    if declared != (environment_admitted && directory_bounds_satisfied && event_bounds_satisfied) {
        return Err(TimingAttemptError::InvalidLedger {
            reason: "raw timing-v3 completion flag is internally inconsistent",
        });
    }
    if required_bool(&value, &["directory_scheduler_admitted"])?
        != required_bool(&value, &["directory", "scheduler_admitted"])?
        || required_bool(&value, &["event_scheduler_admitted"])?
            != required_bool(&value, &["event", "scheduler_admitted"])?
    {
        return Err(TimingAttemptError::InvalidLedger {
            reason: "raw timing-v3 scheduler admission is internally inconsistent",
        });
    }
    Ok(declared)
}

fn validate_raw_record(
    value: &serde_json::Value,
    name: &'static str,
    capacity: usize,
    initial_occupancy: usize,
    inputs: &TimingRunInputs,
    schedule_seed_domain: u64,
    report_seed_domain: u64,
) -> Result<(), TimingAttemptError> {
    expect_json(value, &[name, "capacity"], serde_json::json!(capacity))?;
    expect_json(
        value,
        &[name, "initial_occupancy"],
        serde_json::json!(initial_occupancy),
    )?;
    expect_json(
        value,
        &[name, "plan", "pairs"],
        serde_json::json!(inputs.pairs()),
    )?;
    expect_json(
        value,
        &[name, "plan", "warmup_pairs"],
        serde_json::json!(inputs.warmup_pairs()),
    )?;
    let total_pairs = inputs.pairs().checked_add(inputs.warmup_pairs()).ok_or(
        TimingAttemptError::InvalidLedger {
            reason: "raw timing-v3 pair count overflows",
        },
    )?;
    expect_json(
        value,
        &[name, "plan", "total_pairs"],
        serde_json::json!(total_pairs),
    )?;
    expect_json(
        value,
        &[name, "plan", "seed"],
        serde_json::json!(derive_seed(inputs.seed(), schedule_seed_domain)),
    )?;
    expect_json(
        value,
        &[name, "report_seed"],
        serde_json::json!(derive_seed(inputs.seed(), report_seed_domain)),
    )?;
    expect_json(
        value,
        &[name, "report", "pairs"],
        serde_json::json!(inputs.pairs()),
    )?;
    expect_json(
        value,
        &[name, "report", "mean_equivalence_bound_nanos"],
        serde_json::json!(inputs.mean_bound_nanos()),
    )?;
    expect_json(
        value,
        &[name, "report", "cdf_distance_bound"],
        serde_json::json!(inputs.cdf_distance_bound()),
    )?;
    expect_json(
        value,
        &[name, "report", "seed"],
        serde_json::json!(derive_seed(inputs.seed(), report_seed_domain)),
    )?;
    let pairs = json_path(value, &[name, "raw_pairs"])?.as_array().ok_or(
        TimingAttemptError::InvalidLedger {
            reason: "raw timing-v3 pairs field is not an array",
        },
    )?;
    if pairs.len() != inputs.pairs() {
        return Err(TimingAttemptError::InvalidLedger {
            reason: "raw timing-v3 pair count does not match the manifest cell",
        });
    }
    Ok(())
}

fn expect_json(
    value: &serde_json::Value,
    path: &[&str],
    expected: serde_json::Value,
) -> Result<(), TimingAttemptError> {
    if json_path(value, path)? == &expected {
        Ok(())
    } else {
        Err(TimingAttemptError::InvalidLedger {
            reason: "raw timing-v3 field does not match its manifest cell",
        })
    }
}

fn json_path<'a>(
    value: &'a serde_json::Value,
    path: &[&str],
) -> Result<&'a serde_json::Value, TimingAttemptError> {
    let mut current = value;
    for component in path {
        current = current
            .get(component)
            .ok_or(TimingAttemptError::InvalidLedger {
                reason: "raw timing-v3 evidence is missing a required field",
            })?;
    }
    Ok(current)
}

fn required_bool(value: &serde_json::Value, path: &[&str]) -> Result<bool, TimingAttemptError> {
    json_path(value, path)?
        .as_bool()
        .ok_or(TimingAttemptError::InvalidLedger {
            reason: "raw timing-v3 required boolean field is invalid",
        })
}

fn attempt_id(manifest: &TimingManifestRecordBindingV1, cell: &TimingExecutionCellV1) -> String {
    let mut digest = Blake2s256::new();
    digest.update(ATTEMPT_ID_DOMAIN);
    digest.update(manifest.manifest_blake2s256().as_bytes());
    digest.update((cell.id().len() as u64).to_be_bytes());
    digest.update(cell.id().as_bytes());
    hex::encode(digest.finalize())
}

fn link_name(sequence: u64) -> String {
    format!("{sequence:0LINK_NAME_WIDTH$}")
}

fn canonical_link_sequence(name: &OsStr) -> Option<u64> {
    let name = name.to_str()?;
    if name.len() != LINK_NAME_WIDTH || !name.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let sequence = name.parse::<u64>().ok()?;
    (link_name(sequence) == name).then_some(sequence)
}

fn attempt_stage_target_sequence(name: &OsStr) -> Option<u64> {
    let name = name.to_str()?.strip_prefix('.')?;
    let (target, suffix) = name.split_once(".stage-")?;
    let target_sequence = canonical_link_sequence(OsStr::new(target))?;
    let (pid, stage_id) = suffix.split_once('-')?;
    if !canonical_decimal::<u32>(pid) || !canonical_decimal::<u64>(stage_id) {
        return None;
    }
    Some(target_sequence)
}

fn canonical_decimal<T>(value: &str) -> bool
where
    T: std::str::FromStr + fmt::Display,
{
    !value.is_empty()
        && value.bytes().all(|byte| byte.is_ascii_digit())
        && value
            .parse::<T>()
            .is_ok_and(|parsed| parsed.to_string() == value)
}

fn validate_external_head_pair(
    sequence: Option<u64>,
    digest: Option<&str>,
) -> Result<(), TimingAttemptError> {
    match (sequence, digest) {
        (Some(_), Some(digest)) => validate_digest(digest),
        (None, None) => Ok(()),
        _ => Err(TimingAttemptError::InvalidExternalHead),
    }
}

fn validate_digest(digest: &str) -> Result<(), TimingAttemptError> {
    if digest.len() == 64
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(TimingAttemptError::InvalidLedger {
            reason: "attempt digest must be 64 lowercase hexadecimal characters",
        })
    }
}

struct SelectedCpuInfo {
    microcode: String,
    flags: BTreeSet<String>,
    bugs: BTreeSet<String>,
}

fn selected_cpu_info(
    cpu_info: &str,
    selected_cpu: u32,
) -> Result<SelectedCpuInfo, TimingAttemptError> {
    for block in cpu_info.split("\n\n") {
        let fields = block
            .lines()
            .filter_map(|line| line.split_once(':'))
            .map(|(key, value)| (key.trim(), value.trim()))
            .collect::<BTreeMap<_, _>>();
        let Some(processor) = fields.get("processor") else {
            continue;
        };
        if processor.parse::<u32>().ok() != Some(selected_cpu) {
            continue;
        }
        let microcode = fields
            .get("microcode")
            .filter(|value| !value.is_empty())
            .ok_or(TimingAttemptError::InvalidCpuEnvironment {
                reason: "selected CPU has no microcode identity",
            })?
            .to_string();
        let flags = split_control_set(fields.get("flags").ok_or(
            TimingAttemptError::InvalidCpuEnvironment {
                reason: "selected CPU has no feature flags",
            },
        )?)?;
        let bugs = fields
            .get("bugs")
            .map(|value| split_control_set(value))
            .transpose()?
            .unwrap_or_default();
        return Ok(SelectedCpuInfo {
            microcode,
            flags,
            bugs,
        });
    }
    Err(TimingAttemptError::InvalidCpuEnvironment {
        reason: "selected CPU is absent from /proc/cpuinfo",
    })
}

fn split_control_set(value: &str) -> Result<BTreeSet<String>, TimingAttemptError> {
    let values = value
        .split_whitespace()
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    if values.is_empty() {
        Err(TimingAttemptError::InvalidCpuEnvironment {
            reason: "CPU control set is empty",
        })
    } else {
        Ok(values)
    }
}

fn read_vulnerabilities() -> Result<BTreeMap<String, String>, TimingAttemptError> {
    let mut values = BTreeMap::new();
    for entry in fs::read_dir(VULNERABILITIES_PATH).map_err(|source| TimingAttemptError::Io {
        operation: "read CPU vulnerabilities directory",
        source,
    })? {
        let entry = entry.map_err(|source| TimingAttemptError::Io {
            operation: "read CPU vulnerability entry",
            source,
        })?;
        let name = entry.file_name().into_string().map_err(|_| {
            TimingAttemptError::InvalidCpuEnvironment {
                reason: "CPU vulnerability filename is not UTF-8",
            }
        })?;
        if values
            .insert(name, read_required_path(&entry.path())?)
            .is_some()
        {
            return Err(TimingAttemptError::InvalidCpuEnvironment {
                reason: "CPU vulnerability filenames are duplicated",
            });
        }
    }
    if values.is_empty() {
        return Err(TimingAttemptError::InvalidCpuEnvironment {
            reason: "CPU vulnerability status set is empty",
        });
    }
    Ok(values)
}

fn read_required_text(path: &'static str) -> Result<String, TimingAttemptError> {
    read_required_path(Path::new(path))
}

fn read_required_path(path: &Path) -> Result<String, TimingAttemptError> {
    read_optional_text(path)?.ok_or(TimingAttemptError::InvalidCpuEnvironment {
        reason: "required CPU environment input is unavailable",
    })
}

fn read_optional_text(path: &Path) -> Result<Option<String>, TimingAttemptError> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(source) if source.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(TimingAttemptError::Io {
                operation: "read CPU environment input",
                source,
            });
        }
    };
    if bytes.is_empty() || bytes.len() > MAX_CONTROL_BYTES {
        return Err(TimingAttemptError::InvalidCpuEnvironment {
            reason: "CPU environment input is empty or oversized",
        });
    }
    let value =
        std::str::from_utf8(&bytes).map_err(|_| TimingAttemptError::InvalidCpuEnvironment {
            reason: "CPU environment input is not UTF-8",
        })?;
    let value = value.trim();
    if value.is_empty() || value.contains('\0') {
        return Err(TimingAttemptError::InvalidCpuEnvironment {
            reason: "CPU environment input is empty or contains NUL",
        });
    }
    Ok(Some(value.to_owned()))
}

fn parse_zero_one(value: &str, _label: &'static str) -> Result<bool, TimingAttemptError> {
    match value {
        "0" => Ok(false),
        "1" => Ok(true),
        _ => Err(TimingAttemptError::InvalidCpuEnvironment {
            reason: "binary CPU control is not zero or one",
        }),
    }
}

fn canonical_digest(value: &impl Serialize) -> Result<String, TimingAttemptError> {
    Ok(artifact_blake2s256_hex(&serde_json::to_vec(value)?))
}

fn capture_environment(
    selected_cpu: u32,
    expected_cpu_list: &str,
) -> Result<CpuEnvironmentV1, TimingAttemptError> {
    if !cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        return Err(TimingAttemptError::UnsupportedHost);
    }
    let status = read_required_text(SELF_STATUS_PATH)?;
    let cpus_allowed_list = parse_cpus_allowed_list(&status)
        .map_err(|_| TimingAttemptError::InvalidCpuEnvironment {
            reason: "process CPU allowance is missing or malformed",
        })?
        .to_owned();
    if cpus_allowed_list != expected_cpu_list {
        return Err(TimingAttemptError::InvalidCpuEnvironment {
            reason: "process CPU allowance changed during environment capture",
        });
    }
    let mems_allowed_list = parse_status_value(&status, "Mems_allowed_list").ok_or(
        TimingAttemptError::InvalidCpuEnvironment {
            reason: "process NUMA allowance is missing or malformed",
        },
    )?;
    let mut task_mitigation_controls = TASK_MITIGATION_FIELDS
        .iter()
        .filter_map(|name| {
            parse_status_value(&status, name).map(|value| NamedControlV1 {
                name: (*name).to_owned(),
                value,
            })
        })
        .collect::<Vec<_>>();
    task_mitigation_controls.sort_by(|left, right| left.name.cmp(&right.name));
    let numa_policy = capture_numa_policy()?;
    let cpu_root = PathBuf::from(format!("/sys/devices/system/cpu/cpu{selected_cpu}"));
    let cpufreq_root = cpu_root.join("cpufreq");
    let selected_cpu_online_state =
        read_optional_text(&cpu_root.join("online"))?.unwrap_or_else(|| "implicit-online".into());
    let cpu_info = selected_cpu_info(&read_required_text(CPU_INFO_PATH)?, selected_cpu)?;
    let vulnerabilities = read_vulnerabilities()?;
    let mut boost_and_turbo_controls = Vec::new();
    for (name, path) in [
        ("global_cpufreq_boost", GLOBAL_BOOST_PATH),
        ("intel_pstate_no_turbo", INTEL_NO_TURBO_PATH),
        ("amd_pstate_status", AMD_PSTATE_STATUS_PATH),
    ] {
        if let Some(value) = read_optional_text(Path::new(path))? {
            boost_and_turbo_controls.push(NamedControlV1 {
                name: name.to_owned(),
                value,
            });
        }
    }
    boost_and_turbo_controls.sort_by(|left, right| left.name.cmp(&right.name));
    let scheduler_stats_enabled =
        parse_scheduler_stats_control(&read_required_text(SCHED_STATS_PATH)?).map_err(|_| {
            TimingAttemptError::InvalidCpuEnvironment {
                reason: "scheduler statistics control is malformed",
            }
        })?;
    let environment = CpuEnvironmentV1 {
        schema: CPU_ENVIRONMENT_SCHEMA.to_owned(),
        selected_cpu,
        cpus_allowed_list,
        mems_allowed_list,
        numa_policy,
        online_cpu_list: read_required_text(CPU_ONLINE_PATH)?,
        selected_cpu_online_state,
        thread_siblings_list: read_required_path(&cpu_root.join("topology/thread_siblings_list"))?,
        smt_active: read_optional_text(Path::new(SMT_ACTIVE_PATH))?
            .map(|value| parse_zero_one(&value, "SMT active state"))
            .transpose()?,
        smt_control: read_optional_text(Path::new(SMT_CONTROL_PATH))?,
        scaling_driver: read_optional_text(&cpufreq_root.join("scaling_driver"))?,
        scaling_governor: read_optional_text(&cpufreq_root.join("scaling_governor"))?,
        scaling_min_frequency: read_optional_text(&cpufreq_root.join("scaling_min_freq"))?,
        scaling_max_frequency: read_optional_text(&cpufreq_root.join("scaling_max_freq"))?,
        scaling_current_frequency: read_optional_text(&cpufreq_root.join("scaling_cur_freq"))?,
        boost_and_turbo_controls,
        task_mitigation_controls,
        microcode: cpu_info.microcode,
        cpu_flags_blake2s256: canonical_digest(&cpu_info.flags)?,
        cpu_flag_count: cpu_info.flags.len(),
        cpu_bugs_blake2s256: canonical_digest(&cpu_info.bugs)?,
        cpu_bug_count: cpu_info.bugs.len(),
        vulnerabilities_blake2s256: canonical_digest(&vulnerabilities)?,
        vulnerability_entry_count: vulnerabilities.len(),
        kernel_cmdline_blake2s256: artifact_blake2s256_hex(
            read_required_text(KERNEL_CMDLINE_PATH)?.as_bytes(),
        ),
        current_clocksource: read_required_text(CLOCKSOURCE_PATH)?,
        scheduler_stats_enabled,
        self_reported: true,
        attested: false,
    };
    environment.validate()?;
    Ok(environment)
}

fn parse_status_value(status: &str, name: &str) -> Option<String> {
    let prefix = format!("{name}:");
    status
        .lines()
        .find_map(|line| line.strip_prefix(&prefix))
        .map(str::trim)
        .filter(|value| !value.is_empty() && !value.contains('\0'))
        .map(str::to_owned)
}

fn capture_numa_policy() -> Result<NumaPolicyV1, TimingAttemptError> {
    if !cfg!(target_os = "linux") {
        return Err(TimingAttemptError::UnsupportedHost);
    }
    let reporter_bytes = fs::read(NUMACTL_PATH).map_err(|source| TimingAttemptError::Io {
        operation: "read numactl reporter",
        source,
    })?;
    if reporter_bytes.is_empty() || reporter_bytes.len() > MAX_CONTROL_BYTES {
        return Err(TimingAttemptError::InvalidCpuEnvironment {
            reason: "numactl reporter is empty or oversized",
        });
    }
    let output = Command::new(NUMACTL_PATH)
        .arg("--show")
        .output()
        .map_err(|source| TimingAttemptError::Io {
            operation: "query current thread NUMA memory policy",
            source,
        })?;
    if !output.status.success() || !output.stderr.is_empty() {
        return Err(TimingAttemptError::InvalidCpuEnvironment {
            reason: "numactl failed to report NUMA memory policy without warnings",
        });
    }
    let stdout = std::str::from_utf8(&output.stdout).map_err(|_| {
        TimingAttemptError::InvalidCpuEnvironment {
            reason: "numactl NUMA memory-policy output is not UTF-8",
        }
    })?;
    let controls = parse_numa_policy_output(stdout)?;
    Ok(NumaPolicyV1 {
        reporter: NUMACTL_PATH.to_owned(),
        reporter_blake2s256: artifact_blake2s256_hex(&reporter_bytes),
        controls,
    })
}

fn parse_numa_policy_output(stdout: &str) -> Result<Vec<NamedControlV1>, TimingAttemptError> {
    let mut parsed = BTreeMap::new();
    for line in stdout.lines() {
        let (name, value) =
            line.split_once(':')
                .ok_or(TimingAttemptError::InvalidCpuEnvironment {
                    reason: "numactl NUMA memory-policy output is malformed",
                })?;
        let name = name.trim();
        let value = value.split_whitespace().collect::<Vec<_>>().join(" ");
        let value = if value.is_empty() {
            "<none>".to_owned()
        } else {
            value
        };
        if !NUMACTL_CONTROL_NAMES.contains(&name) || parsed.insert(name.to_owned(), value).is_some()
        {
            return Err(TimingAttemptError::InvalidCpuEnvironment {
                reason: "numactl NUMA memory-policy fields are unknown or duplicated",
            });
        }
    }
    if !parsed.contains_key("policy") || !parsed.contains_key("membind") {
        return Err(TimingAttemptError::InvalidCpuEnvironment {
            reason: "numactl NUMA memory-policy output omits policy or membind",
        });
    }
    Ok(parsed
        .into_iter()
        .map(|(name, value)| NamedControlV1 { name, value })
        .collect())
}

fn validate_named_controls(
    controls: &[NamedControlV1],
    allowed_names: &[&str],
    reason: &'static str,
) -> Result<(), TimingAttemptError> {
    let mut previous_name: Option<&str> = None;
    for control in controls {
        if control.value.is_empty()
            || control.value.contains('\0')
            || !allowed_names.contains(&control.name.as_str())
            || previous_name.is_some_and(|previous| previous >= control.name.as_str())
        {
            return Err(TimingAttemptError::InvalidCpuEnvironment { reason });
        }
        previous_name = Some(&control.name);
    }
    Ok(())
}

#[derive(Debug)]
pub(crate) enum TimingAttemptError {
    UnsupportedHost,
    InvalidCpuEnvironment {
        reason: &'static str,
    },
    InvalidLedger {
        reason: &'static str,
    },
    DanglingStarted,
    NoDanglingStarted,
    MatrixComplete,
    CrossCellEnvironmentMismatch,
    InvalidExternalHead,
    ExternalHeadMismatch,
    Prestart {
        source: Box<dyn Error + Send + Sync>,
    },
    Manifest(TimingManifestError),
    Artifact(ArtifactError),
    Json(serde_json::Error),
    Io {
        operation: &'static str,
        source: io::Error,
    },
}

impl fmt::Display for TimingAttemptError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedHost => formatter.write_str("timing attempts require Linux x86_64"),
            Self::InvalidCpuEnvironment { reason } | Self::InvalidLedger { reason } => {
                formatter.write_str(reason)
            }
            Self::DanglingStarted => formatter.write_str(
                "attempt ledger has a consumed dangling started cell; seal it before continuing",
            ),
            Self::NoDanglingStarted => {
                formatter.write_str("attempt ledger has no dangling started cell to seal")
            }
            Self::MatrixComplete => {
                formatter.write_str("every timing manifest cell already has a terminal attempt")
            }
            Self::CrossCellEnvironmentMismatch => formatter
                .write_str("timing attempt CPU controls differ from the retained matrix baseline"),
            Self::InvalidExternalHead => {
                formatter.write_str("expected head sequence and digest must be supplied together")
            }
            Self::ExternalHeadMismatch => {
                formatter.write_str("attempt ledger head does not match the external witness")
            }
            Self::Prestart { .. } => {
                formatter.write_str("timing attempt prestart admission failed")
            }
            Self::Manifest(_) => formatter.write_str("timing attempt manifest admission failed"),
            Self::Artifact(_) => formatter.write_str("timing attempt artifact operation failed"),
            Self::Json(_) => formatter.write_str("timing attempt JSON is invalid"),
            Self::Io { operation, .. } => write!(formatter, "failed to {operation}"),
        }
    }
}

impl Error for TimingAttemptError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Prestart { source } => Some(source.as_ref()),
            Self::Manifest(source) => Some(source),
            Self::Artifact(source) => Some(source),
            Self::Json(source) => Some(source),
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

impl From<TimingManifestError> for TimingAttemptError {
    fn from(source: TimingManifestError) -> Self {
        Self::Manifest(source)
    }
}

impl From<ArtifactError> for TimingAttemptError {
    fn from(source: ArtifactError) -> Self {
        Self::Artifact(source)
    }
}

impl From<serde_json::Error> for TimingAttemptError {
    fn from(source: serde_json::Error) -> Self {
        Self::Json(source)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gate2::manifest::{
        test_admitted_timing_manifest, test_admitted_timing_manifest_with_runner,
    };
    use std::error::Error;
    #[cfg(any(target_vendor = "apple", target_os = "linux"))]
    use std::os::unix::fs::symlink;

    type TestResult<T = ()> = Result<T, Box<dyn Error>>;

    fn environment() -> CpuEnvironmentV1 {
        CpuEnvironmentV1 {
            schema: CPU_ENVIRONMENT_SCHEMA.to_owned(),
            selected_cpu: 7,
            cpus_allowed_list: "7".to_owned(),
            mems_allowed_list: "0".to_owned(),
            numa_policy: NumaPolicyV1 {
                reporter: NUMACTL_PATH.to_owned(),
                reporter_blake2s256: "55".repeat(32),
                controls: vec![
                    NamedControlV1 {
                        name: "membind".to_owned(),
                        value: "0".to_owned(),
                    },
                    NamedControlV1 {
                        name: "policy".to_owned(),
                        value: "default".to_owned(),
                    },
                ],
            },
            online_cpu_list: "0-7".to_owned(),
            selected_cpu_online_state: "1".to_owned(),
            thread_siblings_list: "7".to_owned(),
            smt_active: Some(false),
            smt_control: Some("off".to_owned()),
            scaling_driver: Some("test-driver".to_owned()),
            scaling_governor: Some("performance".to_owned()),
            scaling_min_frequency: Some("1000".to_owned()),
            scaling_max_frequency: Some("2000".to_owned()),
            scaling_current_frequency: Some("1500".to_owned()),
            boost_and_turbo_controls: vec![NamedControlV1 {
                name: "global_cpufreq_boost".to_owned(),
                value: "0".to_owned(),
            }],
            task_mitigation_controls: vec![
                NamedControlV1 {
                    name: "SpeculationIndirectBranch".to_owned(),
                    value: "conditional enabled".to_owned(),
                },
                NamedControlV1 {
                    name: "Speculation_Store_Bypass".to_owned(),
                    value: "thread mitigated".to_owned(),
                },
            ],
            microcode: "0x1".to_owned(),
            cpu_flags_blake2s256: "11".repeat(32),
            cpu_flag_count: 1,
            cpu_bugs_blake2s256: "22".repeat(32),
            cpu_bug_count: 1,
            vulnerabilities_blake2s256: "33".repeat(32),
            vulnerability_entry_count: 1,
            kernel_cmdline_blake2s256: "44".repeat(32),
            current_clocksource: "tsc".to_owned(),
            scheduler_stats_enabled: true,
            self_reported: true,
            attested: false,
        }
    }

    fn append_started(
        directory: &ArtifactDirectory,
        manifest: &AdmittedTimingManifest,
        cell_ordinal: usize,
        sequence: u64,
        previous: Option<PreviousLinkV1>,
    ) -> Result<StartedToken, TimingAttemptError> {
        append_started_with_environment(
            directory,
            manifest,
            cell_ordinal,
            sequence,
            previous,
            "test-runner",
            environment(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn append_started_with_environment(
        directory: &ArtifactDirectory,
        manifest: &AdmittedTimingManifest,
        cell_ordinal: usize,
        sequence: u64,
        previous: Option<PreviousLinkV1>,
        runner_version: &str,
        cpu_environment_before: CpuEnvironmentV1,
    ) -> Result<StartedToken, TimingAttemptError> {
        let cell = manifest
            .cells()
            .get(cell_ordinal)
            .ok_or(TimingAttemptError::InvalidLedger {
                reason: "test cell ordinal is outside the manifest",
            })?;
        let record = AttemptRecordV1::new(
            sequence,
            previous,
            manifest.record_binding(),
            cell,
            runner_version,
            AttemptStateV1::Started {
                cpu_environment_before,
            },
        )?;
        append_record(directory, record, None)
    }

    fn append_error(
        directory: &ArtifactDirectory,
        manifest: &AdmittedTimingManifest,
        started: StartedToken,
    ) -> Result<StartedToken, TimingAttemptError> {
        let terminal = started_error_record(
            manifest,
            &started,
            StartedErrorStageV1::PriorProcessInterrupted,
            "prior_process_interrupted",
            "test-runner",
        )?;
        append_record(directory, terminal, None)
    }

    fn started_error_record(
        manifest: &AdmittedTimingManifest,
        started: &StartedToken,
        failure_stage: StartedErrorStageV1,
        error_code: &str,
        runner_version: &str,
    ) -> Result<AttemptRecordV1, TimingAttemptError> {
        let cell = started.record.cell.clone();
        terminal_record(
            manifest,
            &cell,
            started,
            AttemptStateV1::StartedError(StartedErrorPayloadV1 {
                started_record_blake2s256: started.digest.clone(),
                failure_stage,
                error_code: error_code.to_owned(),
            }),
            runner_version,
        )
    }

    fn append_completed(
        directory: &ArtifactDirectory,
        manifest: &AdmittedTimingManifest,
        started: StartedToken,
        terminal_runner_version: &str,
        raw_runner_version: &str,
        declared: bool,
    ) -> Result<StartedToken, TimingAttemptError> {
        let (terminal, raw_bytes) = completed_record_and_raw(
            manifest,
            &started,
            terminal_runner_version,
            raw_runner_version,
            declared,
        )?;
        append_record(directory, terminal, Some(&raw_bytes))
    }

    fn completed_record_and_raw(
        manifest: &AdmittedTimingManifest,
        started: &StartedToken,
        terminal_runner_version: &str,
        raw_runner_version: &str,
        declared: bool,
    ) -> Result<(AttemptRecordV1, Vec<u8>), TimingAttemptError> {
        let cell = started.record.cell.clone();
        let raw_bytes = raw_v3_bytes(cell.inputs(), declared, raw_runner_version)?;
        let raw = RawTimingBindingV1 {
            file: TIMING_V3_JSON.to_owned(),
            blake2s256: artifact_blake2s256_hex(&raw_bytes),
            size_bytes: u64::try_from(raw_bytes.len()).map_err(|_| {
                TimingAttemptError::InvalidLedger {
                    reason: "test raw timing evidence size does not fit u64",
                }
            })?,
            raw_declared_wall_clock_criteria_satisfied: declared,
            overall_attempt_admitted: declared,
        };
        let payload = CompletionPayloadV1 {
            started_record_blake2s256: started.digest.clone(),
            cpu_environment_after: environment(),
            controls_stable: true,
            raw,
        };
        let state = if declared {
            AttemptStateV1::CompletedPositive(payload)
        } else {
            AttemptStateV1::CompletedNegative(payload)
        };
        let terminal = terminal_record(manifest, &cell, started, state, terminal_runner_version)?;
        Ok((terminal, raw_bytes))
    }

    fn raw_v3_bytes(
        inputs: &TimingRunInputs,
        declared: bool,
        runner_version: &str,
    ) -> Result<Vec<u8>, serde_json::Error> {
        let record = |capacity: usize,
                      initial_occupancy: usize,
                      schedule_domain: u64,
                      report_domain: u64| {
            serde_json::json!({
                "capacity": capacity,
                "initial_occupancy": initial_occupancy,
                "plan": {
                    "pairs": inputs.pairs(),
                    "warmup_pairs": inputs.warmup_pairs(),
                    "total_pairs": inputs.pairs() + inputs.warmup_pairs(),
                    "seed": derive_seed(inputs.seed(), schedule_domain),
                },
                "report_seed": derive_seed(inputs.seed(), report_domain),
                "raw_pairs": vec![serde_json::json!({}); inputs.pairs()],
                "report": {
                    "pairs": inputs.pairs(),
                    "mean_equivalence_bound_nanos": inputs.mean_bound_nanos(),
                    "cdf_distance_bound": inputs.cdf_distance_bound(),
                    "bounds_satisfied": declared,
                    "seed": derive_seed(inputs.seed(), report_domain),
                },
                "scheduler_admitted": true,
            })
        };
        let value = serde_json::json!({
            "schema": TIMING_EVIDENCE_SCHEMA,
            "runner_version": runner_version,
            "platform_os": "linux",
            "platform_arch": "x86_64",
            "mode": inputs.mode(),
            "evidence_intent": EvidenceIntent::QualificationCandidate,
            "wall_clock_only": true,
            "physical_trace_complete": false,
            "oram_state_seed_bound": false,
            "serial_independence_established": false,
            "target_projection_model": TARGET_PROJECTION_MODEL,
            "target_projection_model_implemented": false,
            "can_clear_gate2": false,
            "policy": {
                "max_load_average_1m": inputs.max_load_average_1m(),
                "max_competing_processes": inputs.max_competing_processes(),
            },
            "max_runqueue_wait_ratio": inputs.max_runqueue_wait_ratio(),
            "environment_admitted": true,
            "directory_scheduler_admitted": true,
            "event_scheduler_admitted": true,
            "directory": record(
                inputs.directory_capacity(),
                inputs.directory_initial_occupancy(),
                DIRECTORY_SCHEDULE_SEED_DOMAIN,
                DIRECTORY_REPORT_SEED_DOMAIN,
            ),
            "event": record(
                inputs.event_capacity(),
                inputs.event_initial_occupancy(),
                EVENT_SCHEDULE_SEED_DOMAIN,
                EVENT_REPORT_SEED_DOMAIN,
            ),
            "declared_wall_clock_criteria_satisfied": declared,
        });
        let mut bytes = serde_json::to_vec_pretty(&value)?;
        bytes.push(b'\n');
        Ok(bytes)
    }

    type MalformedLedgerBuilder =
        fn(&ArtifactDirectory, &AdmittedTimingManifest) -> Result<(), TimingAttemptError>;

    fn build_duplicate_started(
        directory: &ArtifactDirectory,
        manifest: &AdmittedTimingManifest,
    ) -> Result<(), TimingAttemptError> {
        let first = append_started(directory, manifest, 0, 0, None)?;
        let _second = append_started(
            directory,
            manifest,
            0,
            1,
            Some(PreviousLinkV1 {
                sequence: first.record.sequence,
                record_blake2s256: first.digest,
            }),
        )?;
        Ok(())
    }

    fn build_terminal_without_started(
        directory: &ArtifactDirectory,
        manifest: &AdmittedTimingManifest,
    ) -> Result<(), TimingAttemptError> {
        let cell = manifest
            .cells()
            .first()
            .ok_or(TimingAttemptError::InvalidLedger {
                reason: "test manifest has no first cell",
            })?;
        let raw_bytes = raw_v3_bytes(cell.inputs(), false, "test-runner")?;
        let record = AttemptRecordV1::new(
            0,
            None,
            manifest.record_binding(),
            cell,
            "test-runner",
            AttemptStateV1::CompletedNegative(CompletionPayloadV1 {
                started_record_blake2s256: "11".repeat(32),
                cpu_environment_after: environment(),
                controls_stable: true,
                raw: RawTimingBindingV1 {
                    file: TIMING_V3_JSON.to_owned(),
                    blake2s256: artifact_blake2s256_hex(&raw_bytes),
                    size_bytes: u64::try_from(raw_bytes.len()).map_err(|_| {
                        TimingAttemptError::InvalidLedger {
                            reason: "test raw timing evidence size does not fit u64",
                        }
                    })?,
                    raw_declared_wall_clock_criteria_satisfied: false,
                    overall_attempt_admitted: false,
                },
            }),
        )?;
        let _terminal = append_record(directory, record, Some(&raw_bytes))?;
        Ok(())
    }

    fn build_wrong_previous(
        directory: &ArtifactDirectory,
        manifest: &AdmittedTimingManifest,
    ) -> Result<(), TimingAttemptError> {
        let started = append_started(directory, manifest, 0, 0, None)?;
        let mut terminal = started_error_record(
            manifest,
            &started,
            StartedErrorStageV1::PriorProcessInterrupted,
            "prior_process_interrupted",
            "test-runner",
        )?;
        terminal.previous = Some(PreviousLinkV1 {
            sequence: started.record.sequence,
            record_blake2s256: "66".repeat(32),
        });
        let _terminal = append_record(directory, terminal, None)?;
        Ok(())
    }

    fn build_wrong_started_digest(
        directory: &ArtifactDirectory,
        manifest: &AdmittedTimingManifest,
    ) -> Result<(), TimingAttemptError> {
        let started = append_started(directory, manifest, 0, 0, None)?;
        let mut terminal = started_error_record(
            manifest,
            &started,
            StartedErrorStageV1::PriorProcessInterrupted,
            "prior_process_interrupted",
            "test-runner",
        )?;
        match &mut terminal.state {
            AttemptStateV1::StartedError(payload) => {
                payload.started_record_blake2s256 = "77".repeat(32);
            }
            _ => {
                return Err(TimingAttemptError::InvalidLedger {
                    reason: "test terminal is not a started-error record",
                });
            }
        }
        let _terminal = append_record(directory, terminal, None)?;
        Ok(())
    }

    fn build_skipped_cell(
        directory: &ArtifactDirectory,
        manifest: &AdmittedTimingManifest,
    ) -> Result<(), TimingAttemptError> {
        let _started = append_started(directory, manifest, 1, 0, None)?;
        Ok(())
    }

    #[test]
    fn legal_started_error_chain_consumes_exactly_one_cell() -> TestResult {
        let parent = tempfile::tempdir()?;
        let path = parent.path().join("ledger");
        fs::create_dir(&path)?;
        let directory = open_artifact_directory(&path)?;
        let manifest = test_admitted_timing_manifest(2);

        let empty = load_ledger(&directory, &manifest)?;
        assert_eq!(empty.next_sequence, 0);
        assert_eq!(empty.next_cell_ordinal, 0);

        let started = append_started(&directory, &manifest, 0, 0, None)?;
        let dangling = load_ledger(&directory, &manifest)?;
        assert_eq!(dangling.started_cells, 1);
        assert_eq!(dangling.terminal_cells, 0);
        assert!(dangling.dangling.is_some());
        assert_eq!(dangling.next_cell_ordinal, 0);

        let _terminal = append_error(&directory, &manifest, started)?;
        let sealed = load_ledger(&directory, &manifest)?;
        assert_eq!(sealed.started_cells, 1);
        assert_eq!(sealed.terminal_cells, 1);
        assert!(sealed.dangling.is_none());
        assert_eq!(sealed.next_cell_ordinal, 1);
        assert!(!sealed.all_cells_terminal(&manifest));
        Ok(())
    }

    #[test]
    fn malformed_state_transitions_are_rejected_on_replay() -> TestResult {
        let cases: [(&str, MalformedLedgerBuilder); 5] = [
            ("duplicate started", build_duplicate_started),
            ("terminal without started", build_terminal_without_started),
            ("wrong previous", build_wrong_previous),
            ("wrong started digest", build_wrong_started_digest),
            ("skipped cell", build_skipped_cell),
        ];
        for (name, build) in cases {
            let parent = tempfile::tempdir()?;
            let path = parent.path().join("ledger");
            fs::create_dir(&path)?;
            let directory = open_artifact_directory(&path)?;
            let manifest = test_admitted_timing_manifest(2);
            build(&directory, &manifest)?;
            assert!(
                load_ledger(&directory, &manifest).is_err(),
                "malformed case unexpectedly replayed: {name}"
            );
        }
        Ok(())
    }

    #[test]
    fn all_cells_terminal_does_not_overstate_started_errors() -> TestResult {
        let parent = tempfile::tempdir()?;
        let path = parent.path().join("ledger");
        fs::create_dir(&path)?;
        let directory = open_artifact_directory(&path)?;
        let manifest = test_admitted_timing_manifest(1);
        let started = append_started(&directory, &manifest, 0, 0, None)?;
        let _terminal = append_error(&directory, &manifest, started)?;

        let ledger = load_ledger(&directory, &manifest)?;
        let summary = ledger.summary(&manifest, false);
        assert!(summary.all_cells_terminal());
        assert!(!summary.all_cells_declared_positive());
        assert_eq!(summary.positive_cells(), 0);
        assert_eq!(summary.negative_cells(), 0);
        assert_eq!(summary.started_error_cells(), 1);
        Ok(())
    }

    #[test]
    fn completed_attempts_use_the_started_runner_version_offline() -> TestResult {
        let parent = tempfile::tempdir()?;
        let path = parent.path().join("ledger");
        fs::create_dir(&path)?;
        let directory = open_artifact_directory(&path)?;
        let manifest = test_admitted_timing_manifest_with_runner(1, "archived-runner");
        let started = append_started_with_environment(
            &directory,
            &manifest,
            0,
            0,
            None,
            "archived-runner",
            environment(),
        )?;
        let _terminal = append_completed(
            &directory,
            &manifest,
            started,
            "archived-runner",
            "archived-runner",
            true,
        )?;

        let ledger = load_ledger(&directory, &manifest)?;
        let summary = ledger.summary(&manifest, false);
        assert!(summary.all_cells_terminal());
        assert!(summary.all_cells_declared_positive());
        assert_eq!(summary.positive_cells(), 1);
        Ok(())
    }

    #[test]
    fn legal_positive_and_negative_chain_reports_matrix_outcome() -> TestResult {
        let parent = tempfile::tempdir()?;
        let path = parent.path().join("ledger");
        fs::create_dir(&path)?;
        let directory = open_artifact_directory(&path)?;
        let manifest = test_admitted_timing_manifest(2);
        let started_zero = append_started(&directory, &manifest, 0, 0, None)?;
        let terminal_zero = append_completed(
            &directory,
            &manifest,
            started_zero,
            "test-runner",
            "test-runner",
            true,
        )?;
        let started_one = append_started(
            &directory,
            &manifest,
            1,
            2,
            Some(PreviousLinkV1 {
                sequence: terminal_zero.record.sequence,
                record_blake2s256: terminal_zero.digest,
            }),
        )?;
        let _terminal_one = append_completed(
            &directory,
            &manifest,
            started_one,
            "test-runner",
            "test-runner",
            false,
        )?;

        let summary = load_ledger(&directory, &manifest)?.summary(&manifest, false);
        assert!(summary.all_cells_terminal());
        assert!(!summary.all_cells_declared_positive());
        assert_eq!(summary.positive_cells(), 1);
        assert_eq!(summary.negative_cells(), 1);
        assert_eq!(summary.started_error_cells(), 0);
        Ok(())
    }

    #[test]
    fn completed_attempt_rejects_a_different_terminal_runner() -> TestResult {
        let parent = tempfile::tempdir()?;
        let path = parent.path().join("ledger");
        fs::create_dir(&path)?;
        let directory = open_artifact_directory(&path)?;
        let manifest = test_admitted_timing_manifest_with_runner(1, "archived-runner");
        let started = append_started_with_environment(
            &directory,
            &manifest,
            0,
            0,
            None,
            "archived-runner",
            environment(),
        )?;
        let (mut terminal, raw_bytes) = completed_record_and_raw(
            &manifest,
            &started,
            "archived-runner",
            "archived-runner",
            true,
        )?;
        terminal.record_writer_version = "newer-runner".to_owned();
        let _terminal = append_record(&directory, terminal, Some(&raw_bytes))?;

        assert!(load_ledger(&directory, &manifest).is_err());
        Ok(())
    }

    #[test]
    fn ledger_replay_rejects_tampered_raw_timing_evidence() -> TestResult {
        let parent = tempfile::tempdir()?;
        let path = parent.path().join("ledger");
        fs::create_dir(&path)?;
        let directory = open_artifact_directory(&path)?;
        let manifest = test_admitted_timing_manifest(1);
        let started = append_started(&directory, &manifest, 0, 0, None)?;
        let terminal = append_completed(
            &directory,
            &manifest,
            started,
            "test-runner",
            "test-runner",
            true,
        )?;
        let raw_path = path
            .join(link_name(terminal.record.sequence))
            .join(TIMING_V3_JSON);
        let mut raw_bytes = fs::read(&raw_path)?;
        let first = raw_bytes
            .first_mut()
            .ok_or_else(|| io::Error::other("test raw timing evidence is empty"))?;
        *first ^= 1;
        fs::write(raw_path, raw_bytes)?;

        assert!(load_ledger(&directory, &manifest).is_err());
        Ok(())
    }

    #[test]
    fn matrix_rejects_cross_cell_cpu_control_drift() -> TestResult {
        let parent = tempfile::tempdir()?;
        let path = parent.path().join("ledger");
        fs::create_dir(&path)?;
        let directory = open_artifact_directory(&path)?;
        let manifest = test_admitted_timing_manifest(2);
        let started_zero = append_started(&directory, &manifest, 0, 0, None)?;
        let terminal_zero = append_error(&directory, &manifest, started_zero)?;
        let mut changed = environment();
        changed.scaling_governor = Some("powersave".to_owned());
        let _started_one = append_started_with_environment(
            &directory,
            &manifest,
            1,
            2,
            Some(PreviousLinkV1 {
                sequence: terminal_zero.record.sequence,
                record_blake2s256: terminal_zero.digest,
            }),
            "test-runner",
            changed,
        )?;

        assert!(load_ledger(&directory, &manifest).is_err());
        Ok(())
    }

    #[test]
    fn link_gap_is_rejected() -> TestResult {
        let parent = tempfile::tempdir()?;
        let path = parent.path().join("ledger");
        fs::create_dir(&path)?;
        let directory = open_artifact_directory(&path)?;
        let manifest = test_admitted_timing_manifest(1);
        let _started = append_started(&directory, &manifest, 0, 0, None)?;
        fs::rename(path.join(link_name(0)), path.join(link_name(1)))?;

        assert!(load_ledger(&directory, &manifest).is_err());
        Ok(())
    }

    #[test]
    fn orphan_publisher_stage_does_not_poison_crash_recovery() -> TestResult {
        let parent = tempfile::tempdir()?;
        let path = parent.path().join("ledger");
        fs::create_dir(&path)?;
        let directory = open_artifact_directory(&path)?;
        let manifest = test_admitted_timing_manifest(1);
        let _started = append_started(&directory, &manifest, 0, 0, None)?;
        let orphan = path.join(format!(".{}.stage-123-0", link_name(1)));
        fs::create_dir(&orphan)?;
        fs::write(orphan.join(RECORD_JSON), b"{\"partial\":true}")?;

        let dangling = load_ledger(&directory, &manifest)?;
        assert!(dangling.dangling.is_some());
        let _sealed = seal_admitted_dangling_timing_attempt(&manifest, &path, "sealer-v2")?;
        assert!(load_ledger(&directory, &manifest)?.all_cells_terminal(&manifest));
        Ok(())
    }

    #[test]
    fn malformed_or_future_publisher_stages_are_rejected() -> TestResult {
        for stage_name in [
            format!(".{}.stage-0123-0", link_name(0)),
            format!(".{}.stage-123-0", link_name(1)),
        ] {
            let parent = tempfile::tempdir()?;
            let path = parent.path().join("ledger");
            fs::create_dir(&path)?;
            fs::create_dir(path.join(stage_name))?;
            let directory = open_artifact_directory(&path)?;
            let manifest = test_admitted_timing_manifest(1);
            assert!(load_ledger(&directory, &manifest).is_err());
        }
        Ok(())
    }

    #[test]
    fn unwitnessed_suffix_deletion_remains_a_valid_incomplete_prefix() -> TestResult {
        let parent = tempfile::tempdir()?;
        let path = parent.path().join("ledger");
        fs::create_dir(&path)?;
        let directory = open_artifact_directory(&path)?;
        let manifest = test_admitted_timing_manifest(2);
        let started_zero = append_started(&directory, &manifest, 0, 0, None)?;
        let terminal_zero = append_error(&directory, &manifest, started_zero)?;
        let started_one = append_started(
            &directory,
            &manifest,
            1,
            2,
            Some(PreviousLinkV1 {
                sequence: terminal_zero.record.sequence,
                record_blake2s256: terminal_zero.digest.clone(),
            }),
        )?;
        let terminal_one = append_error(&directory, &manifest, started_one)?;
        let complete = load_ledger(&directory, &manifest)?;
        assert!(complete.all_cells_terminal(&manifest));
        let complete_head = complete
            .head
            .ok_or_else(|| io::Error::other("complete test ledger has no head"))?;
        let witnessed = inspect_admitted_timing_attempt_ledger(
            &manifest,
            &path,
            Some(complete_head.sequence),
            Some(&complete_head.record_blake2s256),
        )?;
        assert!(witnessed.externally_witnessed());

        fs::remove_dir_all(path.join(link_name(terminal_one.record.sequence)))?;
        fs::remove_dir_all(path.join(link_name(2)))?;
        let prefix = load_ledger(&directory, &manifest)?;
        assert!(!prefix.all_cells_terminal(&manifest));
        assert_eq!(prefix.next_cell_ordinal, 1);
        assert_ne!(prefix.head, Some(complete_head.clone()));
        assert!(!prefix.summary(&manifest, false).externally_witnessed());
        let unwitnessed = inspect_admitted_timing_attempt_ledger(&manifest, &path, None, None)?;
        assert!(!unwitnessed.externally_witnessed());
        assert!(matches!(
            inspect_admitted_timing_attempt_ledger(
                &manifest,
                &path,
                Some(complete_head.sequence),
                Some(&complete_head.record_blake2s256),
            ),
            Err(TimingAttemptError::ExternalHeadMismatch)
        ));
        Ok(())
    }

    #[test]
    fn sealing_a_dangling_start_is_terminal_and_nonrepeatable() -> TestResult {
        let parent = tempfile::tempdir()?;
        let path = parent.path().join("ledger");
        fs::create_dir(&path)?;
        let directory = open_artifact_directory(&path)?;
        let manifest = test_admitted_timing_manifest(1);
        let _started = append_started(&directory, &manifest, 0, 0, None)?;

        let sealed = seal_admitted_dangling_timing_attempt(&manifest, &path, "sealer-v2")?;
        assert_eq!(
            sealed.terminal_state(),
            TimingAttemptTerminalState::StartedError
        );
        let ledger = load_ledger(&directory, &manifest)?;
        assert!(ledger.all_cells_terminal(&manifest));
        assert_eq!(ledger.started_error_cells, 1);
        let terminal_directory =
            open_artifact_child_directory(&directory, OsStr::new(&link_name(1)))?;
        let terminal: AttemptRecordV1 = serde_json::from_slice(&read_artifact_file(
            &terminal_directory,
            RECORD_JSON,
            MAX_RECORD_BYTES,
        )?)?;
        assert!(matches!(
            terminal.state,
            AttemptStateV1::StartedError(StartedErrorPayloadV1 {
                failure_stage: StartedErrorStageV1::PriorProcessInterrupted,
                ..
            })
        ));
        assert!(matches!(
            seal_admitted_dangling_timing_attempt(&manifest, &path, "sealer-v2"),
            Err(TimingAttemptError::NoDanglingStarted)
        ));
        Ok(())
    }

    #[cfg(any(target_vendor = "apple", target_os = "linux"))]
    #[test]
    fn ledger_root_symlink_is_rejected() -> TestResult {
        let parent = tempfile::tempdir()?;
        let target = parent.path().join("target");
        let alias = parent.path().join("alias");
        fs::create_dir(&target)?;
        symlink(&target, &alias)?;

        assert!(open_artifact_directory(&alias).is_err());
        Ok(())
    }

    #[cfg(any(target_vendor = "apple", target_os = "linux"))]
    #[test]
    fn numeric_ledger_child_symlink_and_regular_file_are_rejected() -> TestResult {
        let parent = tempfile::tempdir()?;
        let path = parent.path().join("ledger");
        let target = parent.path().join("valid-looking-link");
        fs::create_dir(&path)?;
        fs::create_dir(&target)?;
        fs::write(target.join(RECORD_JSON), b"{}")?;
        let directory = open_artifact_directory(&path)?;
        let manifest = test_admitted_timing_manifest(1);
        let numeric_child = path.join(link_name(0));

        symlink(&target, &numeric_child)?;
        assert!(load_ledger(&directory, &manifest).is_err());
        fs::remove_file(&numeric_child)?;

        fs::write(&numeric_child, b"not a directory")?;
        assert!(load_ledger(&directory, &manifest).is_err());
        fs::remove_file(&numeric_child)?;

        let stage_child = path.join(format!(".{}.stage-123-0", link_name(0)));
        symlink(&target, &stage_child)?;
        assert!(load_ledger(&directory, &manifest).is_err());
        Ok(())
    }

    #[test]
    fn raw_v3_validation_binds_mode_shape_policy_and_seeds() -> TestResult {
        let manifest = test_admitted_timing_manifest(1);
        let inputs = manifest
            .cells()
            .first()
            .ok_or_else(|| io::Error::other("test manifest has no timing cell"))?
            .inputs();
        let bytes = raw_v3_bytes(inputs, true, "archived-runner")?;
        assert!(validate_raw_timing_v3(&bytes, inputs, "archived-runner")?);

        let mut value: serde_json::Value = serde_json::from_slice(&bytes)?;
        value["mode"] = serde_json::json!("forced_miss");
        let mut tampered = serde_json::to_vec_pretty(&value)?;
        tampered.push(b'\n');
        assert!(validate_raw_timing_v3(&tampered, inputs, "archived-runner").is_err());
        assert!(validate_raw_timing_v3(&bytes, inputs, "newer-inspector").is_err());
        Ok(())
    }

    #[test]
    fn control_stability_ignores_observed_frequency_but_not_governor() {
        let before = environment();
        let mut after = before.clone();
        after.scaling_current_frequency = Some("1700".to_owned());
        assert!(before.stable_controls_equal(&after));

        after.scaling_governor = Some("powersave".to_owned());
        assert!(!before.stable_controls_equal(&after));

        let mut mitigation_changed = before.clone();
        mitigation_changed.task_mitigation_controls[0].value = "different".to_owned();
        assert!(!before.stable_controls_equal(&mitigation_changed));

        let mut numa_changed = before.clone();
        numa_changed.numa_policy.controls[0].value = "1".to_owned();
        assert!(!before.stable_controls_equal(&numa_changed));
    }

    #[test]
    fn numactl_policy_parser_is_normalized_and_fail_closed() -> TestResult {
        let controls = parse_numa_policy_output(
            "policy: default\npreferred node: current\nmembind: 0\npreferred:\n",
        )?;
        assert_eq!(
            controls,
            vec![
                NamedControlV1 {
                    name: "membind".to_owned(),
                    value: "0".to_owned(),
                },
                NamedControlV1 {
                    name: "policy".to_owned(),
                    value: "default".to_owned(),
                },
                NamedControlV1 {
                    name: "preferred".to_owned(),
                    value: "<none>".to_owned(),
                },
                NamedControlV1 {
                    name: "preferred node".to_owned(),
                    value: "current".to_owned(),
                },
            ]
        );
        assert!(parse_numa_policy_output("policy: default\n").is_err());
        assert!(parse_numa_policy_output("policy: default\nmembind: 0\nfuture: 1\n").is_err());
        Ok(())
    }

    #[test]
    fn external_head_requires_a_complete_pair() {
        assert!(validate_external_head_pair(None, None).is_ok());
        assert!(validate_external_head_pair(Some(0), Some(&"11".repeat(32))).is_ok());
        assert!(validate_external_head_pair(Some(0), None).is_err());
        assert!(validate_external_head_pair(None, Some(&"11".repeat(32))).is_err());
    }
}
