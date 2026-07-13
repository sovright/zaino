//! Fixed mixed-workload correctness evidence for the volatile typed worker.
//!
//! `SmokeV1` is deliberately small and immutable. It exercises deterministic
//! mixed commands, a healthy rejection, and a separate terminal fault. The
//! aggregate report is CI-smoke evidence only, not a benchmark or a mainnet,
//! target-hardware, persistence, recovery, physical-trace, or TDX gate.

use std::fmt;

use blake2::{Blake2s256, Digest};
use serde::{Deserialize, Serialize};

use crate::{
    layout::{
        spawn_typed_rostl_worker, AtomicQualificationAppendDisposition,
        AtomicQualificationCommandError, AtomicQualificationSnapshot, AtomicQueueCapacity,
        AtomicWorker, AtomicWorkerBuildError, DirectoryTableConfiguration, EventTableConfiguration,
        FixedProbeLayout, LayoutIdentity, LayoutNetwork, StandardAddress, StandardScriptKind,
    },
    records::{UtxoEvent, UtxoScriptClass},
};

const SCENARIO: &str = "typed-worker-stress-smoke-v1";
const BACKEND: &str = "rostl-circuit-oram-volatile-v1";
const DERIVATION_DOMAIN: &[u8] = b"zaino-oram-typed-worker-stress-v1";
const DERIVATION_SEED: [u8; 32] = [0x73; 32];
const HEALTHY_LAYOUT_SEED: [u8; 32] = [0x01; 32];
const FAULT_LAYOUT_SEED: [u8; 32] = [0x6b; 32];
const DIRECTORY_PROBES_U64: u64 = 4;
const EVENT_PROBES_U64: u64 = 4;
const DIRECTORY_PROBES: usize = DIRECTORY_PROBES_U64 as usize;
const EVENT_PROBES: usize = EVENT_PROBES_U64 as usize;
const MODELED_ADDRESSES: usize = 4;
const MODELED_ADDRESSES_U64: u64 = MODELED_ADDRESSES as u64;
const HOT_ADDRESSES_U64: u64 = 2;
const MAX_EVENTS_PER_ADDRESS: usize = 3;
const MAX_EVENTS_PER_ADDRESS_U64: u64 = MAX_EVENTS_PER_ADDRESS as u64;
const WORKLOAD_STEPS: u64 = 64;
const VERIFICATION_CADENCE: u64 = 8;
const FINAL_ABSENT_READS: u64 = 2;
const LAYOUT_SCHEMA_VERSION: u32 = 1;
const LAYOUT_KEY_EPOCH: u64 = 1;
const HEALTHY_LAYOUT_GENERATION: u64 = 2;
const FAULT_LAYOUT_GENERATION: u64 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
/// Fixed typed-worker stress profiles.
pub enum TypedWorkerStressProfile {
    /// The bounded deterministic CI correctness and fail-closed smoke profile.
    SmokeV1,
}

impl TypedWorkerStressProfile {
    const fn as_str(self) -> &'static str {
        match self {
            Self::SmokeV1 => "smoke-v1",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StressWorkerShape {
    directory_probes: u64,
    event_probes: u64,
    directory_capacity: u64,
    directory_admission_limit: u64,
    event_capacity: u64,
    event_admission_limit: u64,
    max_events_per_address: u64,
    queue_capacity: u64,
}

const HEALTHY_WORKER_SHAPE: StressWorkerShape = StressWorkerShape {
    directory_probes: DIRECTORY_PROBES_U64,
    event_probes: EVENT_PROBES_U64,
    directory_capacity: 8,
    directory_admission_limit: 6,
    event_capacity: 16,
    event_admission_limit: 12,
    max_events_per_address: MAX_EVENTS_PER_ADDRESS_U64,
    queue_capacity: 1,
};

const FAULT_WORKER_SHAPE: StressWorkerShape = StressWorkerShape {
    directory_probes: DIRECTORY_PROBES_U64,
    event_probes: EVENT_PROBES_U64,
    directory_capacity: 4,
    directory_admission_limit: 2,
    event_capacity: 4,
    event_admission_limit: 2,
    max_events_per_address: 1,
    queue_capacity: 1,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StressProfileShape {
    modeled_addresses: u64,
    hot_addresses: u64,
    workload_steps: u64,
    verification_cadence: u64,
    final_absent_reads: u64,
    healthy_worker: StressWorkerShape,
}

const PROFILE_SHAPE: StressProfileShape = StressProfileShape {
    modeled_addresses: MODELED_ADDRESSES_U64,
    hot_addresses: HOT_ADDRESSES_U64,
    workload_steps: WORKLOAD_STEPS,
    verification_cadence: VERIFICATION_CADENCE,
    final_absent_reads: FINAL_ABSENT_READS,
    healthy_worker: HEALTHY_WORKER_SHAPE,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StressWorkloadSummary {
    scheduled_steps: u64,
    reads: u64,
    unique_appends: u64,
    exact_replays: u64,
    per_command_history_checks: u64,
    periodic_sweeps: u64,
    periodic_read_commands: u64,
    final_modeled_read_commands: u64,
    final_absent_read_commands: u64,
    total_healthy_worker_commands: u64,
    correctness_passed: bool,
}

impl StressWorkloadSummary {
    const EMPTY: Self = Self {
        scheduled_steps: 0,
        reads: 0,
        unique_appends: 0,
        exact_replays: 0,
        per_command_history_checks: 0,
        periodic_sweeps: 0,
        periodic_read_commands: 0,
        final_modeled_read_commands: 0,
        final_absent_read_commands: 0,
        total_healthy_worker_commands: 0,
        correctness_passed: false,
    };
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StressWorkerTrace {
    queue_capacity: u64,
    queued_at_shutdown: u64,
    in_flight_at_shutdown: u64,
    queue_high_water: u64,
    accepted: u64,
    completed: u64,
    failed: u64,
    full_rejected: u64,
    not_running_rejected: u64,
    reply_delivery_failed: u64,
    stopped: bool,
    faulted: bool,
}

impl StressWorkerTrace {
    fn try_from_snapshot(
        snapshot: AtomicQualificationSnapshot,
    ) -> Result<Self, TypedWorkerStressQualificationError> {
        Ok(Self {
            queue_capacity: u64::try_from(snapshot.queue_capacity)
                .map_err(|_| TypedWorkerStressQualificationError::InvalidReport)?,
            queued_at_shutdown: u64::try_from(snapshot.queued)
                .map_err(|_| TypedWorkerStressQualificationError::InvalidReport)?,
            in_flight_at_shutdown: u64::try_from(snapshot.in_flight)
                .map_err(|_| TypedWorkerStressQualificationError::InvalidReport)?,
            queue_high_water: u64::try_from(snapshot.queue_high_water)
                .map_err(|_| TypedWorkerStressQualificationError::InvalidReport)?,
            accepted: snapshot.accepted,
            completed: snapshot.completed,
            failed: snapshot.failed,
            full_rejected: snapshot.full_rejected,
            not_running_rejected: snapshot.not_running_rejected,
            reply_delivery_failed: snapshot.reply_delivery_failed,
            stopped: snapshot.stopped,
            faulted: snapshot.faulted,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NonterminalRejectionSummary {
    attempts: u64,
    command_rejected: u64,
    followup_reads: u64,
    followup_read_passed: bool,
}

const NONTERMINAL_REJECTION_SUMMARY: NonterminalRejectionSummary = NonterminalRejectionSummary {
    attempts: 1,
    command_rejected: 1,
    followup_reads: 1,
    followup_read_passed: true,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TerminalFaultSummary {
    worker_shape: StressWorkerShape,
    inserted_before_fault: u64,
    faulting_append_failed_closed: bool,
    post_fault_read_failed_closed: bool,
    post_fault_append_failed_closed: bool,
    post_fault_commands_rejected_at_admission: u64,
    worker_trace: StressWorkerTrace,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StressEvidenceScope {
    correctness_checked: bool,
    ci_smoke: bool,
    generic_linux_x86_64: bool,
    target_load_measured: bool,
    billion_operations_completed: bool,
    target_hardware_qualified: bool,
    latency_measured: bool,
    rss_measured: bool,
    stash_measured: bool,
    queue_load_measured: bool,
    physical_trace_measured: bool,
    persistence_qualified: bool,
    recovery_qualified: bool,
    tdx_qualified: bool,
    source_revision_bound: bool,
    lockfile_digest_bound: bool,
    toolchain_identity_bound: bool,
    binary_identity_bound: bool,
    execution_attested: bool,
    node_year_failure_bound: bool,
    mainnet_gate_passed: bool,
}

const EVIDENCE_SCOPE: StressEvidenceScope = StressEvidenceScope {
    correctness_checked: true,
    ci_smoke: true,
    generic_linux_x86_64: true,
    target_load_measured: false,
    billion_operations_completed: false,
    target_hardware_qualified: false,
    latency_measured: false,
    rss_measured: false,
    stash_measured: false,
    queue_load_measured: false,
    physical_trace_measured: false,
    persistence_qualified: false,
    recovery_qualified: false,
    tdx_qualified: false,
    source_revision_bound: false,
    lockfile_digest_bound: false,
    toolchain_identity_bound: false,
    binary_identity_bound: false,
    execution_attested: false,
    node_year_failure_bound: false,
    mainnet_gate_passed: false,
};

/// Aggregate-only evidence from one fixed typed-worker stress smoke profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TypedWorkerStressQualificationReport {
    scenario: String,
    profile: TypedWorkerStressProfile,
    backend: String,
    profile_shape: StressProfileShape,
    workload_summary: StressWorkloadSummary,
    schedule_blake2s256: String,
    final_state_blake2s256: String,
    healthy_worker_trace: StressWorkerTrace,
    nonterminal_rejection: NonterminalRejectionSummary,
    terminal_fault: TerminalFaultSummary,
    evidence_scope: StressEvidenceScope,
}

impl TypedWorkerStressQualificationReport {
    /// Revalidates the fixed profile, aggregate counters, digests, and evidence boundary.
    pub fn validate(&self) -> Result<(), TypedWorkerStressQualificationError> {
        let plan =
            HealthyPlan::build().map_err(|_| TypedWorkerStressQualificationError::InvalidReport)?;
        let expected_healthy_trace = expected_healthy_trace(&plan);
        let expected_fault_trace = expected_fault_trace();
        let expected_fault = expected_terminal_fault(expected_fault_trace);

        if self.scenario != SCENARIO
            || self.profile != TypedWorkerStressProfile::SmokeV1
            || self.backend != BACKEND
            || self.profile_shape != PROFILE_SHAPE
            || self.workload_summary != plan.summary
            || self.schedule_blake2s256 != plan.schedule_blake2s256
            || self.final_state_blake2s256 != plan.final_state_blake2s256
            || self.healthy_worker_trace != expected_healthy_trace
            || self.nonterminal_rejection != NONTERMINAL_REJECTION_SUMMARY
            || self.terminal_fault != expected_fault
            || self.evidence_scope != EVIDENCE_SCOPE
        {
            return Err(TypedWorkerStressQualificationError::InvalidReport);
        }
        Ok(())
    }
}

impl fmt::Display for TypedWorkerStressQualificationReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "scenario={}", self.scenario)?;
        writeln!(f, "profile={}", self.profile.as_str())?;
        writeln!(f, "backend={}", self.backend)?;
        writeln!(
            f,
            "workload=steps:{},reads:{},unique_appends:{},exact_replays:{},periodic_sweeps:{},healthy_commands:{},correct:{}",
            self.workload_summary.scheduled_steps,
            self.workload_summary.reads,
            self.workload_summary.unique_appends,
            self.workload_summary.exact_replays,
            self.workload_summary.periodic_sweeps,
            self.workload_summary.total_healthy_worker_commands,
            self.workload_summary.correctness_passed,
        )?;
        writeln!(f, "schedule_blake2s256={}", self.schedule_blake2s256)?;
        writeln!(f, "final_state_blake2s256={}", self.final_state_blake2s256)?;
        writeln!(
            f,
            "healthy_worker=accepted:{},completed:{},failed:{},queue_high_water:{},stopped:{},faulted:{}",
            self.healthy_worker_trace.accepted,
            self.healthy_worker_trace.completed,
            self.healthy_worker_trace.failed,
            self.healthy_worker_trace.queue_high_water,
            self.healthy_worker_trace.stopped,
            self.healthy_worker_trace.faulted,
        )?;
        writeln!(
            f,
            "nonterminal_rejection=attempts:{},command_rejected:{},followup_read_passed:{}",
            self.nonterminal_rejection.attempts,
            self.nonterminal_rejection.command_rejected,
            self.nonterminal_rejection.followup_read_passed,
        )?;
        writeln!(
            f,
            "terminal_fault=inserted_before_fault:{},faulting_append_failed_closed:{},post_fault_rejected_at_admission:{},stopped:{},faulted:{}",
            self.terminal_fault.inserted_before_fault,
            self.terminal_fault.faulting_append_failed_closed,
            self.terminal_fault.post_fault_commands_rejected_at_admission,
            self.terminal_fault.worker_trace.stopped,
            self.terminal_fault.worker_trace.faulted,
        )?;
        writeln!(f, "evidence=correctness,ci-smoke,generic-linux-x86_64")?;
        writeln!(
            f,
            "unbound=source-revision,lockfile,toolchain,binary,execution-attestation"
        )?;
        write!(
            f,
            "not_qualified=target-load,billion-operations,target-hardware,latency,rss,stash,queue-load,physical-trace,persistence,recovery,tdx,node-year-failure,mainnet-gate"
        )
    }
}

/// Coarse, identifier-free failure from the fixed typed-worker stress exercise.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TypedWorkerStressQualificationError {
    /// The real typed backend is not compiled for this target and feature set.
    TypedBackendUnavailable,
    /// A fixed layout, queue, or typed backend could not be constructed.
    ConstructionFailed,
    /// An ordinary accepted worker command failed before comparison.
    CommandFailed,
    /// A result differed from the bounded reference model.
    CorrectnessMismatch,
    /// The healthy ownership-rejection probe did not preserve worker health.
    NonterminalRejectionMismatch,
    /// The separate event-limit fault did not remain terminal and fail closed.
    TerminalFaultMismatch,
    /// A worker did not stop with its fixed aggregate counters.
    ShutdownFailed,
    /// A report differs from the fixed schema, counters, digests, or evidence scope.
    InvalidReport,
}

impl fmt::Display for TypedWorkerStressQualificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TypedBackendUnavailable => {
                f.write_str("typed-worker stress qualification backend is unavailable")
            }
            Self::ConstructionFailed => {
                f.write_str("typed-worker stress qualification construction failed")
            }
            Self::CommandFailed => f.write_str("typed-worker stress qualification command failed"),
            Self::CorrectnessMismatch => {
                f.write_str("typed-worker stress qualification correctness mismatch")
            }
            Self::NonterminalRejectionMismatch => {
                f.write_str("typed-worker stress nonterminal rejection mismatch")
            }
            Self::TerminalFaultMismatch => {
                f.write_str("typed-worker stress terminal fault mismatch")
            }
            Self::ShutdownFailed => {
                f.write_str("typed-worker stress qualification shutdown failed")
            }
            Self::InvalidReport => {
                f.write_str("typed-worker stress qualification report is invalid")
            }
        }
    }
}

impl std::error::Error for TypedWorkerStressQualificationError {}

#[derive(Clone, Copy)]
enum PlannedCommand {
    WorkloadRead {
        address: u8,
    },
    WorkloadInsert {
        address: u8,
        ordinal: u8,
    },
    WorkloadReplay {
        address: u8,
        ordinal: u8,
    },
    PeriodicRead {
        address: u8,
    },
    FinalModeledRead {
        address: u8,
    },
    FinalAbsentRead {
        absent: u8,
    },
    OwnerMismatch {
        requested: u8,
        actual_owner: u8,
        ordinal: u8,
    },
    PostRejectionRead {
        address: u8,
    },
}

impl PlannedCommand {
    const fn descriptor(self) -> [u8; 4] {
        match self {
            Self::WorkloadRead { address } => [1, address, 0, 0],
            Self::WorkloadInsert { address, ordinal } => [2, address, ordinal, 0],
            Self::WorkloadReplay { address, ordinal } => [3, address, ordinal, 0],
            Self::PeriodicRead { address } => [4, address, 0, 0],
            Self::FinalModeledRead { address } => [5, address, 0, 0],
            Self::FinalAbsentRead { absent } => [6, absent, 0, 0],
            Self::OwnerMismatch {
                requested,
                actual_owner,
                ordinal,
            } => [7, requested, actual_owner, ordinal],
            Self::PostRejectionRead { address } => [8, address, 0, 0],
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ReferenceState {
    histories: [[Option<UtxoEvent>; MAX_EVENTS_PER_ADDRESS]; MODELED_ADDRESSES],
    event_ordinals: [[Option<u8>; MAX_EVENTS_PER_ADDRESS]; MODELED_ADDRESSES],
}

impl ReferenceState {
    const EMPTY: Self = Self {
        histories: [[None; MAX_EVENTS_PER_ADDRESS]; MODELED_ADDRESSES],
        event_ordinals: [[None; MAX_EVENTS_PER_ADDRESS]; MODELED_ADDRESSES],
    };

    fn insert(
        &mut self,
        address: u8,
        ordinal: u8,
        event: UtxoEvent,
    ) -> Result<(), TypedWorkerStressQualificationError> {
        let address = usize::from(address);
        let ordinal_index = usize::from(ordinal);
        if address >= MODELED_ADDRESSES
            || ordinal_index >= MAX_EVENTS_PER_ADDRESS
            || self.histories[address][ordinal_index].is_some()
        {
            return Err(TypedWorkerStressQualificationError::CorrectnessMismatch);
        }
        if self.histories[address][..ordinal_index]
            .iter()
            .any(Option::is_none)
        {
            return Err(TypedWorkerStressQualificationError::CorrectnessMismatch);
        }
        self.histories[address][ordinal_index] = Some(event);
        self.event_ordinals[address][ordinal_index] = Some(ordinal);
        Ok(())
    }

    fn history(
        &self,
        address: u8,
    ) -> Result<&[Option<UtxoEvent>; MAX_EVENTS_PER_ADDRESS], TypedWorkerStressQualificationError>
    {
        self.histories
            .get(usize::from(address))
            .ok_or(TypedWorkerStressQualificationError::CorrectnessMismatch)
    }
}

struct HealthyPlan {
    commands: Vec<PlannedCommand>,
    summary: StressWorkloadSummary,
    schedule_blake2s256: String,
    final_state_blake2s256: String,
    expected_final_state: ReferenceState,
}

impl HealthyPlan {
    fn build() -> Result<Self, TypedWorkerStressQualificationError> {
        let mut commands = Vec::with_capacity(104);
        let mut total_commands = 0_u64;
        let mut summary = StressWorkloadSummary::EMPTY;
        let mut inserted_per_address = [0_u8; MODELED_ADDRESSES];
        let mut unique_insert_count = 0_u8;
        let mut mixed_count = 0_u64;

        for step in 0..WORKLOAD_STEPS {
            let command = if step % 4 == 0
                && usize::from(unique_insert_count) < MODELED_ADDRESSES * MAX_EVENTS_PER_ADDRESS
            {
                let address = unique_insert_count % MODELED_ADDRESSES as u8;
                let ordinal = unique_insert_count / MODELED_ADDRESSES as u8;
                unique_insert_count += 1;
                inserted_per_address[usize::from(address)] += 1;
                summary.unique_appends += 1;
                PlannedCommand::WorkloadInsert { address, ordinal }
            } else {
                let digest = derive_digest(b"workload-step", step);
                let address = select_workload_address(&digest);
                let inserted = inserted_per_address[usize::from(address)];
                let command = if mixed_count.is_multiple_of(2) || inserted == 0 {
                    summary.reads += 1;
                    PlannedCommand::WorkloadRead { address }
                } else {
                    let ordinal = digest[2] % inserted;
                    summary.exact_replays += 1;
                    PlannedCommand::WorkloadReplay { address, ordinal }
                };
                mixed_count += 1;
                command
            };
            push_command(&mut commands, &mut total_commands, command);
            summary.scheduled_steps += 1;
            summary.per_command_history_checks += 1;

            if (step + 1) % VERIFICATION_CADENCE == 0 {
                summary.periodic_sweeps += 1;
                for address in 0..MODELED_ADDRESSES as u8 {
                    push_command(
                        &mut commands,
                        &mut total_commands,
                        PlannedCommand::PeriodicRead { address },
                    );
                    summary.periodic_read_commands += 1;
                }
            }
        }

        for address in 0..MODELED_ADDRESSES as u8 {
            push_command(
                &mut commands,
                &mut total_commands,
                PlannedCommand::FinalModeledRead { address },
            );
            summary.final_modeled_read_commands += 1;
        }
        for absent in 0..FINAL_ABSENT_READS as u8 {
            push_command(
                &mut commands,
                &mut total_commands,
                PlannedCommand::FinalAbsentRead { absent },
            );
            summary.final_absent_read_commands += 1;
        }
        push_command(
            &mut commands,
            &mut total_commands,
            PlannedCommand::OwnerMismatch {
                requested: 0,
                actual_owner: 3,
                ordinal: 0,
            },
        );
        push_command(
            &mut commands,
            &mut total_commands,
            PlannedCommand::PostRejectionRead { address: 0 },
        );

        summary.total_healthy_worker_commands = total_commands;
        summary.correctness_passed = true;
        let expected_final_state = expected_final_state(&commands)?;
        let schedule_blake2s256 = schedule_digest(&commands);
        let final_state_blake2s256 = final_state_digest(&expected_final_state);
        Ok(Self {
            commands,
            summary,
            schedule_blake2s256,
            final_state_blake2s256,
            expected_final_state,
        })
    }
}

fn push_command(commands: &mut Vec<PlannedCommand>, total: &mut u64, command: PlannedCommand) {
    commands.push(command);
    *total += 1;
}

fn expected_final_state(
    commands: &[PlannedCommand],
) -> Result<ReferenceState, TypedWorkerStressQualificationError> {
    let mut state = ReferenceState::EMPTY;
    for command in commands {
        if let PlannedCommand::WorkloadInsert { address, ordinal } = *command {
            let event = modeled_event(address, ordinal);
            state.insert(address, ordinal, event)?;
        }
    }
    Ok(state)
}

fn select_workload_address(digest: &[u8; 32]) -> u8 {
    if digest[0] % 4 < 3 {
        digest[1] % HOT_ADDRESSES_U64 as u8
    } else {
        HOT_ADDRESSES_U64 as u8 + digest[1] % (MODELED_ADDRESSES_U64 - HOT_ADDRESSES_U64) as u8
    }
}

fn derive_digest(label: &[u8], counter: u64) -> [u8; 32] {
    let mut hasher = Blake2s256::new();
    Digest::update(&mut hasher, DERIVATION_DOMAIN);
    Digest::update(&mut hasher, DERIVATION_SEED);
    Digest::update(&mut hasher, label);
    Digest::update(&mut hasher, counter.to_le_bytes());
    let digest = Digest::finalize(hasher);
    let mut bytes = [0; 32];
    bytes.copy_from_slice(&digest);
    bytes
}

fn modeled_address_parts(address: u8) -> (StandardScriptKind, UtxoScriptClass, [u8; 20]) {
    let digest = derive_digest(b"modeled-address", u64::from(address));
    let mut hash = [0; 20];
    hash.copy_from_slice(&digest[..20]);
    if address.is_multiple_of(2) {
        (
            StandardScriptKind::PayToPublicKeyHash,
            UtxoScriptClass::PayToPublicKeyHash,
            hash,
        )
    } else {
        (
            StandardScriptKind::PayToScriptHash,
            UtxoScriptClass::PayToScriptHash,
            hash,
        )
    }
}

fn modeled_address(address: u8) -> StandardAddress {
    let (kind, _, hash) = modeled_address_parts(address);
    StandardAddress::new(kind, hash)
}

fn absent_address(absent: u8) -> StandardAddress {
    let digest = derive_digest(b"absent-address", u64::from(absent));
    let mut hash = [0; 20];
    hash.copy_from_slice(&digest[..20]);
    let kind = if absent.is_multiple_of(2) {
        StandardScriptKind::PayToPublicKeyHash
    } else {
        StandardScriptKind::PayToScriptHash
    };
    StandardAddress::new(kind, hash)
}

fn event_counter(address: u8, ordinal: u8) -> u64 {
    u64::from(ordinal) * MODELED_ADDRESSES_U64 + u64::from(address)
}

fn modeled_event(address: u8, ordinal: u8) -> UtxoEvent {
    let counter = event_counter(address, ordinal);
    let txid = derive_digest(b"modeled-event", counter);
    let (_, script_class, script_hash) = modeled_address_parts(address);
    UtxoEvent::created(
        txid,
        u32::from(ordinal),
        10_000 + counter,
        500 + u32::from(address) * MAX_EVENTS_PER_ADDRESS as u32 + u32::from(ordinal),
        script_class,
        script_hash,
    )
}

fn schedule_digest(commands: &[PlannedCommand]) -> String {
    let mut hasher = Blake2s256::new();
    Digest::update(&mut hasher, b"zaino-oram-stress-schedule-v1");
    for (index, command) in commands.iter().enumerate() {
        Digest::update(&mut hasher, (index as u64).to_le_bytes());
        Digest::update(&mut hasher, command.descriptor());
    }
    digest_hex(Digest::finalize(hasher).as_slice())
}

fn final_state_digest(state: &ReferenceState) -> String {
    let mut hasher = Blake2s256::new();
    Digest::update(&mut hasher, b"zaino-oram-stress-final-state-v1");
    for address in 0..MODELED_ADDRESSES as u8 {
        let (kind, _, hash) = modeled_address_parts(address);
        let kind_tag = match kind {
            StandardScriptKind::PayToPublicKeyHash => 1,
            StandardScriptKind::PayToScriptHash => 2,
        };
        Digest::update(&mut hasher, [address, kind_tag]);
        Digest::update(&mut hasher, hash);
        for (slot, ordinal) in state.event_ordinals[usize::from(address)]
            .iter()
            .copied()
            .enumerate()
        {
            Digest::update(&mut hasher, [slot as u8]);
            match ordinal {
                Some(ordinal) => {
                    Digest::update(&mut hasher, [1, ordinal]);
                    Digest::update(
                        &mut hasher,
                        derive_digest(b"modeled-event", event_counter(address, ordinal)),
                    );
                }
                None => Digest::update(&mut hasher, [0, 0]),
            }
        }
    }
    digest_hex(Digest::finalize(hasher).as_slice())
}

fn digest_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(*byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(*byte & 0x0f)]));
    }
    encoded
}

fn expected_healthy_trace(plan: &HealthyPlan) -> StressWorkerTrace {
    StressWorkerTrace {
        queue_capacity: 1,
        queued_at_shutdown: 0,
        in_flight_at_shutdown: 0,
        queue_high_water: 1,
        accepted: plan.summary.total_healthy_worker_commands,
        completed: plan.summary.total_healthy_worker_commands - 1,
        failed: 1,
        full_rejected: 0,
        not_running_rejected: 0,
        reply_delivery_failed: 0,
        stopped: true,
        faulted: false,
    }
}

const fn expected_fault_trace() -> StressWorkerTrace {
    StressWorkerTrace {
        queue_capacity: 1,
        queued_at_shutdown: 0,
        in_flight_at_shutdown: 0,
        queue_high_water: 1,
        accepted: 2,
        completed: 1,
        failed: 1,
        full_rejected: 0,
        not_running_rejected: 2,
        reply_delivery_failed: 0,
        stopped: true,
        faulted: true,
    }
}

const fn expected_terminal_fault(worker_trace: StressWorkerTrace) -> TerminalFaultSummary {
    TerminalFaultSummary {
        worker_shape: FAULT_WORKER_SHAPE,
        inserted_before_fault: 1,
        faulting_append_failed_closed: true,
        post_fault_read_failed_closed: true,
        post_fault_append_failed_closed: true,
        post_fault_commands_rejected_at_admission: 2,
        worker_trace,
    }
}

fn build_report(
    plan: &HealthyPlan,
    healthy_worker_trace: StressWorkerTrace,
    fault_worker_trace: StressWorkerTrace,
) -> TypedWorkerStressQualificationReport {
    TypedWorkerStressQualificationReport {
        scenario: SCENARIO.to_owned(),
        profile: TypedWorkerStressProfile::SmokeV1,
        backend: BACKEND.to_owned(),
        profile_shape: PROFILE_SHAPE,
        workload_summary: plan.summary,
        schedule_blake2s256: plan.schedule_blake2s256.clone(),
        final_state_blake2s256: plan.final_state_blake2s256.clone(),
        healthy_worker_trace,
        nonterminal_rejection: NONTERMINAL_REJECTION_SUMMARY,
        terminal_fault: expected_terminal_fault(fault_worker_trace),
        evidence_scope: EVIDENCE_SCOPE,
    }
}

/// Runs one fixed, listener-free stress smoke profile against the real typed backend.
pub fn run_typed_worker_stress_qualification(
    profile: TypedWorkerStressProfile,
) -> Result<TypedWorkerStressQualificationReport, TypedWorkerStressQualificationError> {
    match profile {
        TypedWorkerStressProfile::SmokeV1 => run_smoke_v1(),
    }
}

fn run_smoke_v1(
) -> Result<TypedWorkerStressQualificationReport, TypedWorkerStressQualificationError> {
    let plan = HealthyPlan::build()?;
    let healthy_worker = spawn_stress_worker(
        HEALTHY_WORKER_SHAPE,
        HEALTHY_LAYOUT_GENERATION,
        HEALTHY_LAYOUT_SEED,
    )?;
    let actual_final_state = run_healthy_commands(&healthy_worker, &plan)?;
    if actual_final_state != plan.expected_final_state
        || final_state_digest(&actual_final_state) != plan.final_state_blake2s256
    {
        return Err(TypedWorkerStressQualificationError::CorrectnessMismatch);
    }
    let healthy_snapshot = healthy_worker
        .qualification_shutdown()
        .map_err(|_| TypedWorkerStressQualificationError::ShutdownFailed)?;
    let healthy_trace = StressWorkerTrace::try_from_snapshot(healthy_snapshot)?;
    if healthy_trace != expected_healthy_trace(&plan) {
        return Err(TypedWorkerStressQualificationError::ShutdownFailed);
    }

    let fault_worker = spawn_stress_worker(
        FAULT_WORKER_SHAPE,
        FAULT_LAYOUT_GENERATION,
        FAULT_LAYOUT_SEED,
    )?;
    let fault_trace = run_terminal_fault(fault_worker)?;
    if fault_trace != expected_fault_trace() {
        return Err(TypedWorkerStressQualificationError::TerminalFaultMismatch);
    }

    let report = build_report(&plan, healthy_trace, fault_trace);
    report.validate()?;
    Ok(report)
}

fn spawn_stress_worker(
    shape: StressWorkerShape,
    generation: u64,
    seed: [u8; 32],
) -> Result<AtomicWorker, TypedWorkerStressQualificationError> {
    let layout = build_stress_layout(shape, generation, seed)?;
    let queue_capacity = usize::try_from(shape.queue_capacity)
        .map_err(|_| TypedWorkerStressQualificationError::ConstructionFailed)?;
    let queue_capacity = AtomicQueueCapacity::try_new(queue_capacity)
        .map_err(|_| TypedWorkerStressQualificationError::ConstructionFailed)?;
    spawn_typed_rostl_worker(layout, queue_capacity).map_err(map_worker_build)
}

fn build_stress_layout(
    shape: StressWorkerShape,
    generation: u64,
    seed: [u8; 32],
) -> Result<FixedProbeLayout<DIRECTORY_PROBES, EVENT_PROBES>, TypedWorkerStressQualificationError> {
    FixedProbeLayout::new(
        LayoutIdentity::new(
            LayoutNetwork::Regtest,
            LAYOUT_SCHEMA_VERSION,
            LAYOUT_KEY_EPOCH,
            generation,
            seed,
        )
        .map_err(|_| TypedWorkerStressQualificationError::ConstructionFailed)?,
        DirectoryTableConfiguration::<DIRECTORY_PROBES>::new(
            shape.directory_capacity,
            shape.directory_admission_limit,
        )
        .map_err(|_| TypedWorkerStressQualificationError::ConstructionFailed)?,
        EventTableConfiguration::<EVENT_PROBES>::new(
            shape.event_capacity,
            shape.event_admission_limit,
        )
        .map_err(|_| TypedWorkerStressQualificationError::ConstructionFailed)?,
        shape.max_events_per_address,
    )
    .map_err(|_| TypedWorkerStressQualificationError::ConstructionFailed)
}

fn run_healthy_commands(
    worker: &AtomicWorker,
    plan: &HealthyPlan,
) -> Result<ReferenceState, TypedWorkerStressQualificationError> {
    let mut reference = ReferenceState::EMPTY;
    let empty_history = [None; MAX_EVENTS_PER_ADDRESS];

    for command in &plan.commands {
        match *command {
            PlannedCommand::WorkloadRead { address }
            | PlannedCommand::PeriodicRead { address }
            | PlannedCommand::FinalModeledRead { address }
            | PlannedCommand::PostRejectionRead { address } => {
                let actual = worker
                    .qualification_read_history_typed(modeled_address(address))
                    .map_err(|_| TypedWorkerStressQualificationError::CommandFailed)?;
                verify_history(actual, reference.history(address)?)?;
            }
            PlannedCommand::WorkloadInsert { address, ordinal } => {
                let event = modeled_event(address, ordinal);
                let actual = worker
                    .qualification_append_typed(modeled_address(address), event)
                    .map_err(|_| TypedWorkerStressQualificationError::CommandFailed)?;
                if actual.disposition != AtomicQualificationAppendDisposition::Inserted {
                    return Err(TypedWorkerStressQualificationError::CorrectnessMismatch);
                }
                let mut candidate = reference;
                candidate.insert(address, ordinal, event)?;
                verify_history(actual.history, candidate.history(address)?)?;
                reference = candidate;
            }
            PlannedCommand::WorkloadReplay { address, ordinal } => {
                let actual = worker
                    .qualification_append_typed(
                        modeled_address(address),
                        modeled_event(address, ordinal),
                    )
                    .map_err(|_| TypedWorkerStressQualificationError::CommandFailed)?;
                if actual.disposition != AtomicQualificationAppendDisposition::ExactReplay {
                    return Err(TypedWorkerStressQualificationError::CorrectnessMismatch);
                }
                verify_history(actual.history, reference.history(address)?)?;
            }
            PlannedCommand::FinalAbsentRead { absent } => {
                let actual = worker
                    .qualification_read_history_typed(absent_address(absent))
                    .map_err(|_| TypedWorkerStressQualificationError::CommandFailed)?;
                verify_history(actual, &empty_history)?;
            }
            PlannedCommand::OwnerMismatch {
                requested,
                actual_owner,
                ordinal,
            } => {
                if !matches!(
                    worker.qualification_append_typed(
                        modeled_address(requested),
                        modeled_event(actual_owner, ordinal),
                    ),
                    Err(AtomicQualificationCommandError::CommandRejected)
                ) {
                    return Err(TypedWorkerStressQualificationError::NonterminalRejectionMismatch);
                }
            }
        }
    }
    Ok(reference)
}

fn run_terminal_fault(
    worker: AtomicWorker,
) -> Result<StressWorkerTrace, TypedWorkerStressQualificationError> {
    let address_a = modeled_address(0);
    let event_a0 = modeled_event(0, 0);
    let first = worker
        .qualification_append_typed(address_a, event_a0)
        .map_err(|_| TypedWorkerStressQualificationError::TerminalFaultMismatch)?;
    if first.disposition != AtomicQualificationAppendDisposition::Inserted {
        return Err(TypedWorkerStressQualificationError::TerminalFaultMismatch);
    }
    verify_history(first.history, &[Some(event_a0)])?;

    if !matches!(
        worker.qualification_append_typed(address_a, modeled_event(0, 1)),
        Err(AtomicQualificationCommandError::FailedClosed)
    ) || !matches!(
        worker.qualification_read_history_typed(address_a),
        Err(AtomicQualificationCommandError::FailedClosed)
    ) || !matches!(
        worker.qualification_append_typed(modeled_address(1), modeled_event(1, 0)),
        Err(AtomicQualificationCommandError::FailedClosed)
    ) {
        return Err(TypedWorkerStressQualificationError::TerminalFaultMismatch);
    }

    let snapshot = worker
        .qualification_shutdown()
        .map_err(|_| TypedWorkerStressQualificationError::ShutdownFailed)?;
    StressWorkerTrace::try_from_snapshot(snapshot)
}

fn verify_history(
    actual: Vec<Option<UtxoEvent>>,
    expected: &[Option<UtxoEvent>],
) -> Result<(), TypedWorkerStressQualificationError> {
    if actual.as_slice() != expected {
        return Err(TypedWorkerStressQualificationError::CorrectnessMismatch);
    }
    Ok(())
}

const fn map_worker_build(error: AtomicWorkerBuildError) -> TypedWorkerStressQualificationError {
    match error {
        #[cfg(not(all(
            feature = "rostl-experimental",
            target_os = "linux",
            target_arch = "x86_64"
        )))]
        AtomicWorkerBuildError::TypedBackendUnavailable => {
            TypedWorkerStressQualificationError::TypedBackendUnavailable
        }
        AtomicWorkerBuildError::ConstructionFailed => {
            TypedWorkerStressQualificationError::ConstructionFailed
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        layout::{spawn_atomic_worker_for_tests, BackendFailure, UniqueTable},
        records::{PersistentAddressDirectory, PersistentAddressEventPage},
    };

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    struct MemoryTable<T> {
        slots: Vec<Option<T>>,
        occupied: u64,
    }

    impl<T> MemoryTable<T> {
        fn new(capacity: usize) -> Self {
            Self {
                slots: std::iter::repeat_with(|| None).take(capacity).collect(),
                occupied: 0,
            }
        }
    }

    impl<T: Copy> UniqueTable<T> for MemoryTable<T> {
        fn capacity(&self) -> usize {
            self.slots.len()
        }

        fn read(&mut self, index: usize) -> Result<Option<T>, BackendFailure> {
            self.slots.get(index).copied().ok_or(BackendFailure)
        }

        fn occupied_records(&mut self) -> Result<u64, BackendFailure> {
            Ok(self.occupied)
        }

        fn insert_unique(&mut self, index: usize, value: T) -> Result<(), BackendFailure> {
            let slot = self.slots.get_mut(index).ok_or(BackendFailure)?;
            if slot.is_some() {
                return Err(BackendFailure);
            }
            *slot = Some(value);
            self.occupied = self.occupied.checked_add(1).ok_or(BackendFailure)?;
            Ok(())
        }
    }

    fn fake_worker(
        shape: StressWorkerShape,
        generation: u64,
        seed: [u8; 32],
    ) -> TestResult<AtomicWorker> {
        let layout = build_stress_layout(shape, generation, seed)?;
        let directory = MemoryTable::<PersistentAddressDirectory>::new(usize::try_from(
            shape.directory_capacity,
        )?);
        let events =
            MemoryTable::<PersistentAddressEventPage>::new(usize::try_from(shape.event_capacity)?);
        let queue_capacity = AtomicQueueCapacity::try_new(usize::try_from(shape.queue_capacity)?)?;
        Ok(spawn_atomic_worker_for_tests(
            layout,
            directory,
            events,
            queue_capacity,
        )?)
    }

    fn expected_report(
    ) -> Result<TypedWorkerStressQualificationReport, TypedWorkerStressQualificationError> {
        let plan = HealthyPlan::build()?;
        Ok(build_report(
            &plan,
            expected_healthy_trace(&plan),
            expected_fault_trace(),
        ))
    }

    #[test]
    fn smoke_plan_is_fixed_mixed_bounded_and_aggregate_only() -> TestResult {
        let plan = HealthyPlan::build()?;

        assert_eq!(plan.summary.scheduled_steps, 64);
        assert_eq!(plan.summary.unique_appends, 12);
        assert!(plan.summary.reads > 0);
        assert!(plan.summary.exact_replays > 0);
        assert_eq!(plan.summary.periodic_sweeps, 8);
        assert_eq!(plan.summary.periodic_read_commands, 32);
        assert_eq!(plan.summary.final_modeled_read_commands, 4);
        assert_eq!(plan.summary.final_absent_read_commands, 2);
        assert_eq!(plan.summary.total_healthy_worker_commands, 104);
        assert_eq!(
            plan.expected_final_state,
            expected_final_state(&plan.commands)?
        );
        assert_eq!(plan.schedule_blake2s256.len(), 64);
        assert_eq!(plan.final_state_blake2s256.len(), 64);
        Ok(())
    }

    #[test]
    fn exact_smoke_profile_fits_probe_sets_and_exercises_both_workers() -> TestResult {
        let plan = HealthyPlan::build()?;
        let worker = fake_worker(
            HEALTHY_WORKER_SHAPE,
            HEALTHY_LAYOUT_GENERATION,
            HEALTHY_LAYOUT_SEED,
        )?;

        let final_state = run_healthy_commands(&worker, &plan)?;
        assert_eq!(final_state, plan.expected_final_state);
        let snapshot = worker
            .qualification_shutdown()
            .map_err(|_| TypedWorkerStressQualificationError::ShutdownFailed)?;
        assert_eq!(
            StressWorkerTrace::try_from_snapshot(snapshot)?,
            expected_healthy_trace(&plan)
        );

        let fault_worker = fake_worker(
            FAULT_WORKER_SHAPE,
            FAULT_LAYOUT_GENERATION,
            FAULT_LAYOUT_SEED,
        )?;
        assert_eq!(run_terminal_fault(fault_worker)?, expected_fault_trace());
        Ok(())
    }

    #[test]
    fn report_round_trip_revalidates_and_rejects_overclaim() -> TestResult {
        let report = expected_report()?;
        report.validate()?;
        let encoded = serde_json::to_vec(&report)?;
        let decoded: TypedWorkerStressQualificationReport = serde_json::from_slice(&encoded)?;
        assert_eq!(decoded, report);

        let mut overstated = report;
        overstated.evidence_scope.target_load_measured = true;
        assert_eq!(
            overstated.validate(),
            Err(TypedWorkerStressQualificationError::InvalidReport)
        );
        Ok(())
    }

    #[test]
    fn report_rejects_unknown_fields_and_text_is_identifier_free() -> TestResult {
        let report = expected_report()?;
        let mut unknown = serde_json::to_value(&report)?;
        unknown["unexpected"] = serde_json::json!(true);
        assert!(serde_json::from_value::<TypedWorkerStressQualificationReport>(unknown).is_err());

        let text = report.to_string();
        assert!(text.contains("evidence=correctness,ci-smoke,generic-linux-x86_64"));
        assert!(text.contains("not_qualified=target-load,billion-operations"));
        assert!(!text.contains("7373737373737373"));
        assert!(!text.contains("modeled-address"));
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
            run_typed_worker_stress_qualification(TypedWorkerStressProfile::SmokeV1),
            Err(TypedWorkerStressQualificationError::TypedBackendUnavailable)
        );
    }

    #[cfg(all(
        feature = "rostl-experimental",
        target_os = "linux",
        target_arch = "x86_64"
    ))]
    #[test]
    fn native_typed_worker_completes_smoke_v1() -> TestResult {
        let report = run_typed_worker_stress_qualification(TypedWorkerStressProfile::SmokeV1)?;
        report.validate()?;
        Ok(())
    }
}
