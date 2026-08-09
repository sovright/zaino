//! Fixed-shape correctness evidence for the volatile typed worker.
//!
//! This facade exists only to exercise the real typed backend without a
//! listener. It reports aggregate command and worker counters. It does not
//! measure latency, memory, physical traces, persistence, or TDX behavior.

use std::fmt;

use serde::{Deserialize, Serialize};

#[cfg(test)]
use crate::layout::AtomicQualificationSnapshot;
use crate::{
    layout::{
        spawn_typed_rostl_worker, AtomicQualificationAppendDisposition,
        AtomicQualificationAppendResult, AtomicQueueCapacity, AtomicWorker, AtomicWorkerBuildError,
        DirectoryTableConfiguration, EventTableConfiguration, FixedProbeLayout, LayoutIdentity,
        LayoutNetwork, StandardAddress, StandardScriptKind,
    },
    records::{UtxoEvent, UtxoScriptClass},
    trace::WorkerTrace,
};

const SCENARIO: &str = "typed-worker-deterministic-v1";
const BACKEND: &str = "rostl-circuit-oram-volatile-v1";
const DIRECTORY_PROBES_U64: u64 = 4;
const EVENT_PROBES_U64: u64 = 4;
const DIRECTORY_PROBES: usize = DIRECTORY_PROBES_U64 as usize;
const EVENT_PROBES: usize = EVENT_PROBES_U64 as usize;
const DIRECTORY_CAPACITY: u64 = 8;
const DIRECTORY_ADMISSION_LIMIT: u64 = 6;
const EVENT_CAPACITY: u64 = 16;
const EVENT_ADMISSION_LIMIT: u64 = 12;
const MAX_EVENTS_PER_ADDRESS: u64 = 8;
const QUEUE_CAPACITY_U64: u64 = 1;
const QUEUE_CAPACITY: usize = QUEUE_CAPACITY_U64 as usize;
const LAYOUT_SCHEMA_VERSION: u32 = 1;
const LAYOUT_KEY_EPOCH: u64 = 1;
const LAYOUT_GENERATION: u64 = 1;
const LAYOUT_SEED: [u8; 32] = [0x5a; 32];
const ADDRESS_A: StandardAddress =
    StandardAddress::new(StandardScriptKind::PayToPublicKeyHash, [0x11; 20]);
const ADDRESS_B: StandardAddress =
    StandardAddress::new(StandardScriptKind::PayToScriptHash, [0x22; 20]);
const ADDRESS_C: StandardAddress =
    StandardAddress::new(StandardScriptKind::PayToPublicKeyHash, [0x33; 20]);
const EVENT_A_CREATED: UtxoEvent = UtxoEvent::created(
    [0x41; 32],
    0,
    100,
    100,
    UtxoScriptClass::PayToPublicKeyHash,
    [0x11; 20],
);
const EVENT_A_SPENT: UtxoEvent = UtxoEvent::spent(
    [0x41; 32],
    0,
    100,
    101,
    UtxoScriptClass::PayToPublicKeyHash,
    [0x11; 20],
);
const EVENT_B_CREATED: UtxoEvent = UtxoEvent::created(
    [0x42; 32],
    1,
    200,
    102,
    UtxoScriptClass::PayToScriptHash,
    [0x22; 20],
);
const EMPTY_HISTORY: [UtxoEvent; 0] = [];
const A_CREATED_HISTORY: [UtxoEvent; 1] = [EVENT_A_CREATED];
const A_SPENT_HISTORY: [UtxoEvent; 2] = [EVENT_A_CREATED, EVENT_A_SPENT];
const B_CREATED_HISTORY: [UtxoEvent; 1] = [EVENT_B_CREATED];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum QualificationStep {
    ReadEmpty,
    ReadOneEvent,
    ReadTwoEvents,
    AppendInserted,
    AppendExactReplay,
}

#[derive(Clone, Copy)]
enum ExpectedHistory {
    Empty,
    AddressACreated,
    AddressASpent,
    AddressBCreated,
}

impl ExpectedHistory {
    const fn events(self) -> &'static [UtxoEvent] {
        match self {
            Self::Empty => &EMPTY_HISTORY,
            Self::AddressACreated => &A_CREATED_HISTORY,
            Self::AddressASpent => &A_SPENT_HISTORY,
            Self::AddressBCreated => &B_CREATED_HISTORY,
        }
    }

    const fn read_step(self) -> QualificationStep {
        match self {
            Self::Empty => QualificationStep::ReadEmpty,
            Self::AddressACreated | Self::AddressBCreated => QualificationStep::ReadOneEvent,
            Self::AddressASpent => QualificationStep::ReadTwoEvents,
        }
    }
}

#[derive(Clone, Copy)]
enum ExpectedAppendDisposition {
    Inserted,
    ExactReplay,
}

#[derive(Clone, Copy)]
enum ScenarioCommand {
    Read {
        address: StandardAddress,
        expected: ExpectedHistory,
    },
    Append {
        address: StandardAddress,
        event: UtxoEvent,
        expected: ExpectedHistory,
        disposition: ExpectedAppendDisposition,
    },
}

impl ScenarioCommand {
    const fn qualification_step(self) -> QualificationStep {
        match self {
            Self::Read { expected, .. } => expected.read_step(),
            Self::Append {
                disposition: ExpectedAppendDisposition::Inserted,
                ..
            } => QualificationStep::AppendInserted,
            Self::Append {
                disposition: ExpectedAppendDisposition::ExactReplay,
                ..
            } => QualificationStep::AppendExactReplay,
        }
    }
}

const SCENARIO_COMMANDS: [ScenarioCommand; 9] = [
    ScenarioCommand::Read {
        address: ADDRESS_A,
        expected: ExpectedHistory::Empty,
    },
    ScenarioCommand::Append {
        address: ADDRESS_A,
        event: EVENT_A_CREATED,
        expected: ExpectedHistory::AddressACreated,
        disposition: ExpectedAppendDisposition::Inserted,
    },
    ScenarioCommand::Read {
        address: ADDRESS_A,
        expected: ExpectedHistory::AddressACreated,
    },
    ScenarioCommand::Append {
        address: ADDRESS_A,
        event: EVENT_A_CREATED,
        expected: ExpectedHistory::AddressACreated,
        disposition: ExpectedAppendDisposition::ExactReplay,
    },
    ScenarioCommand::Append {
        address: ADDRESS_A,
        event: EVENT_A_SPENT,
        expected: ExpectedHistory::AddressASpent,
        disposition: ExpectedAppendDisposition::Inserted,
    },
    ScenarioCommand::Append {
        address: ADDRESS_B,
        event: EVENT_B_CREATED,
        expected: ExpectedHistory::AddressBCreated,
        disposition: ExpectedAppendDisposition::Inserted,
    },
    ScenarioCommand::Read {
        address: ADDRESS_A,
        expected: ExpectedHistory::AddressASpent,
    },
    ScenarioCommand::Read {
        address: ADDRESS_B,
        expected: ExpectedHistory::AddressBCreated,
    },
    ScenarioCommand::Read {
        address: ADDRESS_C,
        expected: ExpectedHistory::Empty,
    },
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct QualificationBackendShape {
    directory_probes: u64,
    event_probes: u64,
    directory_capacity: u64,
    directory_admission_limit: u64,
    event_capacity: u64,
    event_admission_limit: u64,
    max_events_per_address: u64,
    queue_capacity: u64,
}

impl QualificationBackendShape {
    const EXPECTED: Self = Self {
        directory_probes: DIRECTORY_PROBES_U64,
        event_probes: EVENT_PROBES_U64,
        directory_capacity: DIRECTORY_CAPACITY,
        directory_admission_limit: DIRECTORY_ADMISSION_LIMIT,
        event_capacity: EVENT_CAPACITY,
        event_admission_limit: EVENT_ADMISSION_LIMIT,
        max_events_per_address: MAX_EVENTS_PER_ADDRESS,
        queue_capacity: QUEUE_CAPACITY_U64,
    };
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct QualificationCommandSummary {
    commands: u64,
    reads: u64,
    appends: u64,
    inserted_appends: u64,
    exact_replays: u64,
    correctness_passed: bool,
}

impl QualificationCommandSummary {
    const EMPTY: Self = Self {
        commands: 0,
        reads: 0,
        appends: 0,
        inserted_appends: 0,
        exact_replays: 0,
        correctness_passed: false,
    };

    const fn record(&mut self, command: ScenarioCommand) {
        self.commands += 1;
        match command {
            ScenarioCommand::Read { .. } => self.reads += 1,
            ScenarioCommand::Append {
                disposition: ExpectedAppendDisposition::Inserted,
                ..
            } => {
                self.appends += 1;
                self.inserted_appends += 1;
            }
            ScenarioCommand::Append {
                disposition: ExpectedAppendDisposition::ExactReplay,
                ..
            } => {
                self.appends += 1;
                self.exact_replays += 1;
            }
        }
    }
}

#[derive(Clone, Copy)]
struct ScenarioEvidence {
    summary: QualificationCommandSummary,
    trace: [QualificationStep; 9],
}

const fn derive_scenario_evidence() -> ScenarioEvidence {
    let mut evidence = ScenarioEvidence {
        summary: QualificationCommandSummary::EMPTY,
        trace: [QualificationStep::ReadEmpty; 9],
    };
    let mut index = 0;
    while index < SCENARIO_COMMANDS.len() {
        let command = SCENARIO_COMMANDS[index];
        evidence.summary.record(command);
        evidence.trace[index] = command.qualification_step();
        index += 1;
    }
    evidence.summary.correctness_passed = true;
    evidence
}

const EXPECTED_SCENARIO_EVIDENCE: ScenarioEvidence = derive_scenario_evidence();

/// The one worker trace a fully successful, uncontended qualification run can
/// produce.
const EXPECTED_QUALIFICATION_WORKER_TRACE: WorkerTrace = WorkerTrace {
    queue_capacity: QUEUE_CAPACITY_U64,
    queued_at_shutdown: 0,
    in_flight_at_shutdown: 0,
    queue_high_water: 1,
    accepted: EXPECTED_SCENARIO_EVIDENCE.summary.commands,
    completed: EXPECTED_SCENARIO_EVIDENCE.summary.commands,
    failed: 0,
    full_rejected: 0,
    not_running_rejected: 0,
    reply_delivery_failed: 0,
    stopped: true,
    faulted: false,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct QualificationEvidenceScope {
    correctness_checked: bool,
    execution_attested: bool,
    source_revision_bound: bool,
    lockfile_digest_bound: bool,
    toolchain_identity_bound: bool,
    binary_identity_bound: bool,
    latency_measured: bool,
    rss_measured: bool,
    physical_trace_measured: bool,
    persistence_qualified: bool,
    tdx_qualified: bool,
}

impl QualificationEvidenceScope {
    const EXPECTED: Self = Self {
        correctness_checked: true,
        execution_attested: false,
        source_revision_bound: false,
        lockfile_digest_bound: false,
        toolchain_identity_bound: false,
        binary_identity_bound: false,
        latency_measured: false,
        rss_measured: false,
        physical_trace_measured: false,
        persistence_qualified: false,
        tdx_qualified: false,
    };
}

/// Identifier-free evidence from the fixed typed-worker correctness scenario.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TypedWorkerQualificationReport {
    scenario: String,
    backend: String,
    backend_shape: QualificationBackendShape,
    command_summary: QualificationCommandSummary,
    command_trace: [QualificationStep; 9],
    worker_trace: WorkerTrace,
    evidence_scope: QualificationEvidenceScope,
}

impl TypedWorkerQualificationReport {
    /// Revalidates the fixed scenario, backend shape, counters, and negative evidence markers.
    pub fn validate(&self) -> Result<(), TypedWorkerQualificationError> {
        if self.scenario != SCENARIO
            || self.backend != BACKEND
            || self.backend_shape != QualificationBackendShape::EXPECTED
            || self.command_summary != EXPECTED_SCENARIO_EVIDENCE.summary
            || self.command_trace != EXPECTED_SCENARIO_EVIDENCE.trace
            || self.worker_trace != EXPECTED_QUALIFICATION_WORKER_TRACE
            || self.evidence_scope != QualificationEvidenceScope::EXPECTED
        {
            return Err(TypedWorkerQualificationError::InvalidReport);
        }
        Ok(())
    }
}

impl fmt::Display for TypedWorkerQualificationReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "scenario={}", self.scenario)?;
        writeln!(f, "backend={}", self.backend)?;
        writeln!(
            f,
            "backend_shape=directory:{}:{},event:{}:{},max_events_per_address:{},queue:{}",
            self.backend_shape.directory_capacity,
            self.backend_shape.directory_admission_limit,
            self.backend_shape.event_capacity,
            self.backend_shape.event_admission_limit,
            self.backend_shape.max_events_per_address,
            self.backend_shape.queue_capacity,
        )?;
        writeln!(
            f,
            "commands=total:{},reads:{},appends:{},inserted:{},exact_replays:{},correct:{}",
            self.command_summary.commands,
            self.command_summary.reads,
            self.command_summary.appends,
            self.command_summary.inserted_appends,
            self.command_summary.exact_replays,
            self.command_summary.correctness_passed,
        )?;
        writeln!(
            f,
            "worker=accepted:{},completed:{},failed:{},queue_high_water:{},full_rejected:{},not_running_rejected:{},reply_failures:{},stopped:{},faulted:{}",
            self.worker_trace.accepted,
            self.worker_trace.completed,
            self.worker_trace.failed,
            self.worker_trace.queue_high_water,
            self.worker_trace.full_rejected,
            self.worker_trace.not_running_rejected,
            self.worker_trace.reply_delivery_failed,
            self.worker_trace.stopped,
            self.worker_trace.faulted,
        )?;
        writeln!(
            f,
            "unbound=source-revision,lockfile,toolchain,binary,execution-attestation"
        )?;
        write!(f, "not_measured=latency,rss,physical-trace,persistence,tdx")
    }
}

/// Coarse, identifier-free failure from the fixed typed-worker exercise.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TypedWorkerQualificationError {
    /// The real typed backend is not compiled for this target and feature set.
    TypedBackendUnavailable,
    /// The fixed layout, queue, or typed backend could not be constructed.
    ConstructionFailed,
    /// One accepted worker command failed before a correctness comparison.
    CommandFailed,
    /// A command returned a history or append disposition different from the fixed expectation.
    CorrectnessMismatch,
    /// The worker did not stop cleanly after the complete scenario.
    ShutdownFailed,
    /// A report does not match the fixed schema and expected aggregate values.
    InvalidReport,
}

impl fmt::Display for TypedWorkerQualificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TypedBackendUnavailable => {
                f.write_str("typed-worker qualification backend is unavailable")
            }
            Self::ConstructionFailed => {
                f.write_str("typed-worker qualification construction failed")
            }
            Self::CommandFailed => f.write_str("typed-worker qualification command failed"),
            Self::CorrectnessMismatch => {
                f.write_str("typed-worker qualification correctness mismatch")
            }
            Self::ShutdownFailed => f.write_str("typed-worker qualification shutdown failed"),
            Self::InvalidReport => f.write_str("typed-worker qualification report is invalid"),
        }
    }
}

impl std::error::Error for TypedWorkerQualificationError {}

/// Runs one fixed, listener-free correctness scenario against the real typed backend.
pub fn run_typed_worker_qualification(
) -> Result<TypedWorkerQualificationReport, TypedWorkerQualificationError> {
    let layout = FixedProbeLayout::new(
        LayoutIdentity::new(
            LayoutNetwork::Regtest,
            LAYOUT_SCHEMA_VERSION,
            LAYOUT_KEY_EPOCH,
            LAYOUT_GENERATION,
            LAYOUT_SEED,
        )
        .map_err(|_| TypedWorkerQualificationError::ConstructionFailed)?,
        DirectoryTableConfiguration::<DIRECTORY_PROBES>::new(
            DIRECTORY_CAPACITY,
            DIRECTORY_ADMISSION_LIMIT,
        )
        .map_err(|_| TypedWorkerQualificationError::ConstructionFailed)?,
        EventTableConfiguration::<EVENT_PROBES>::new(EVENT_CAPACITY, EVENT_ADMISSION_LIMIT)
            .map_err(|_| TypedWorkerQualificationError::ConstructionFailed)?,
        MAX_EVENTS_PER_ADDRESS,
    )
    .map_err(|_| TypedWorkerQualificationError::ConstructionFailed)?;
    let queue_capacity = AtomicQueueCapacity::try_new(QUEUE_CAPACITY)
        .map_err(|_| TypedWorkerQualificationError::ConstructionFailed)?;
    let worker = spawn_typed_rostl_worker(layout, queue_capacity).map_err(map_worker_build)?;

    let scenario_evidence = run_fixed_scenario(&worker)?;
    let snapshot = worker
        .qualification_shutdown()
        .map_err(|_| TypedWorkerQualificationError::ShutdownFailed)?;
    let report = TypedWorkerQualificationReport {
        scenario: SCENARIO.to_owned(),
        backend: BACKEND.to_owned(),
        backend_shape: QualificationBackendShape::EXPECTED,
        command_summary: scenario_evidence.summary,
        command_trace: scenario_evidence.trace,
        worker_trace: WorkerTrace::try_from_snapshot(snapshot)
            .map_err(|_| TypedWorkerQualificationError::InvalidReport)?,
        evidence_scope: QualificationEvidenceScope::EXPECTED,
    };
    report.validate()?;
    Ok(report)
}

fn run_fixed_scenario(
    worker: &AtomicWorker,
) -> Result<ScenarioEvidence, TypedWorkerQualificationError> {
    let mut evidence = ScenarioEvidence {
        summary: QualificationCommandSummary::EMPTY,
        trace: [QualificationStep::ReadEmpty; 9],
    };
    for (trace, command) in evidence.trace.iter_mut().zip(SCENARIO_COMMANDS) {
        match command {
            ScenarioCommand::Read { address, expected } => {
                let actual = worker
                    .qualification_read_history(address)
                    .map_err(|_| TypedWorkerQualificationError::CommandFailed)?;
                verify_history(actual, expected.events())?;
            }
            ScenarioCommand::Append {
                address,
                event,
                expected,
                disposition,
            } => {
                let actual: AtomicQualificationAppendResult = worker
                    .qualification_append(address, event)
                    .map_err(|_| TypedWorkerQualificationError::CommandFailed)?;
                verify_append_disposition(actual.disposition, disposition)?;
                verify_history(actual.history, expected.events())?;
            }
        }
        evidence.summary.record(command);
        *trace = command.qualification_step();
    }
    evidence.summary.correctness_passed = true;
    Ok(evidence)
}

fn verify_history(
    actual: Vec<Option<UtxoEvent>>,
    expected_events: &[UtxoEvent],
) -> Result<(), TypedWorkerQualificationError> {
    let expected_length = usize::try_from(MAX_EVENTS_PER_ADDRESS)
        .map_err(|_| TypedWorkerQualificationError::ConstructionFailed)?;
    let mut expected = Vec::new();
    expected
        .try_reserve_exact(expected_length)
        .map_err(|_| TypedWorkerQualificationError::ConstructionFailed)?;
    expected.resize(expected_length, None);
    for (slot, event) in expected.iter_mut().zip(expected_events.iter().copied()) {
        *slot = Some(event);
    }
    if actual != expected {
        return Err(TypedWorkerQualificationError::CorrectnessMismatch);
    }
    Ok(())
}

fn verify_append_disposition(
    actual: AtomicQualificationAppendDisposition,
    expected: ExpectedAppendDisposition,
) -> Result<(), TypedWorkerQualificationError> {
    if matches!(
        (actual, expected),
        (
            AtomicQualificationAppendDisposition::Inserted,
            ExpectedAppendDisposition::Inserted
        ) | (
            AtomicQualificationAppendDisposition::ExactReplay,
            ExpectedAppendDisposition::ExactReplay
        )
    ) {
        Ok(())
    } else {
        Err(TypedWorkerQualificationError::CorrectnessMismatch)
    }
}

const fn map_worker_build(error: AtomicWorkerBuildError) -> TypedWorkerQualificationError {
    match error {
        #[cfg(not(all(
            feature = "rostl-experimental",
            target_os = "linux",
            target_arch = "x86_64"
        )))]
        AtomicWorkerBuildError::TypedBackendUnavailable => {
            TypedWorkerQualificationError::TypedBackendUnavailable
        }
        AtomicWorkerBuildError::ConstructionFailed => {
            TypedWorkerQualificationError::ConstructionFailed
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    fn expected_snapshot() -> AtomicQualificationSnapshot {
        AtomicQualificationSnapshot {
            queue_capacity: 1,
            queued: 0,
            in_flight: 0,
            queue_high_water: 1,
            accepted: EXPECTED_SCENARIO_EVIDENCE.summary.commands,
            completed: EXPECTED_SCENARIO_EVIDENCE.summary.commands,
            failed: 0,
            full_rejected: 0,
            not_running_rejected: 0,
            reply_delivery_failed: 0,
            stopped: true,
            faulted: false,
        }
    }

    fn expected_report() -> TestResult<TypedWorkerQualificationReport> {
        let report = TypedWorkerQualificationReport {
            scenario: SCENARIO.to_owned(),
            backend: BACKEND.to_owned(),
            backend_shape: QualificationBackendShape::EXPECTED,
            command_summary: EXPECTED_SCENARIO_EVIDENCE.summary,
            command_trace: EXPECTED_SCENARIO_EVIDENCE.trace,
            worker_trace: WorkerTrace::try_from_snapshot(expected_snapshot())?,
            evidence_scope: QualificationEvidenceScope::EXPECTED,
        };
        report.validate()?;
        Ok(report)
    }

    #[test]
    fn report_round_trip_revalidates() -> TestResult {
        let report = expected_report()?;
        let encoded = serde_json::to_vec(&report)?;
        let decoded: TypedWorkerQualificationReport = serde_json::from_slice(&encoded)?;

        assert_eq!(decoded, report);
        decoded.validate()?;
        Ok(())
    }

    #[test]
    fn report_rejects_unknown_and_non_evidence_fields() -> TestResult {
        let report = expected_report()?;
        let mut unknown = serde_json::to_value(&report)?;
        unknown["unexpected"] = serde_json::json!(true);
        assert!(serde_json::from_value::<TypedWorkerQualificationReport>(unknown).is_err());

        let mut overstated = report;
        overstated.evidence_scope.rss_measured = true;
        assert_eq!(
            overstated.validate(),
            Err(TypedWorkerQualificationError::InvalidReport)
        );
        Ok(())
    }

    #[test]
    fn text_report_is_identifier_free_and_scopes_negative_evidence() -> TestResult {
        let text = expected_report()?.to_string();

        assert!(text.contains("not_measured=latency,rss,physical-trace,persistence,tdx"));
        assert!(text
            .contains("unbound=source-revision,lockfile,toolchain,binary,execution-attestation"));
        assert!(!text.contains("11111111111111111111"));
        assert!(!text.contains("4141414141414141"));
        Ok(())
    }

    #[cfg(not(all(
        feature = "rostl-experimental",
        target_os = "linux",
        target_arch = "x86_64"
    )))]
    #[test]
    fn unsupported_host_rejects_the_real_backend() {
        assert_eq!(
            run_typed_worker_qualification(),
            Err(TypedWorkerQualificationError::TypedBackendUnavailable)
        );
    }

    #[cfg(all(
        feature = "rostl-experimental",
        target_os = "linux",
        target_arch = "x86_64"
    ))]
    #[test]
    fn native_typed_worker_completes_the_fixed_scenario() -> TestResult {
        let report = run_typed_worker_qualification()?;
        report.validate()?;
        Ok(())
    }
}
