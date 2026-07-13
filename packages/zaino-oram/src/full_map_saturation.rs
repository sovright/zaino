//! Deterministic logical admitted-map boundary evidence for the typed worker.
//!
//! `FullMapSaturationV1` uses independent workers for the directory-admission
//! and event-admission boundaries. It deliberately retains physical table
//! reserve and is not a random target-load, benchmark, persistence, recovery,
//! physical-trace, target-hardware, TDX, or mainnet qualification.

use std::fmt;

use blake2::{Blake2s256, Digest};
use serde::{Deserialize, Serialize};

use crate::{
    layout::{
        spawn_typed_rostl_worker, AtomicQualificationAppendDisposition,
        AtomicQualificationCommandError, AtomicQualificationSnapshot, AtomicQueueCapacity,
        AtomicWorker, AtomicWorkerBuildError, DirectoryTableConfiguration, EventTableConfiguration,
        FixedProbeLayout, LayoutIdentity, LayoutNetwork,
    },
    records::UtxoEvent,
    stress_qualification::{absent_address, digest_hex, modeled_address, modeled_event},
};

const SCENARIO: &str = "typed-worker-full-map-saturation-v1";
const BACKEND: &str = "rostl-circuit-oram-volatile-v1";
const DIRECTORY_PROBES_U64: u64 = 4;
const EVENT_PROBES_U64: u64 = 4;
const DIRECTORY_PROBES: usize = DIRECTORY_PROBES_U64 as usize;
const EVENT_PROBES: usize = EVENT_PROBES_U64 as usize;
const LAYOUT_SCHEMA_VERSION: u32 = 1;
const LAYOUT_KEY_EPOCH: u64 = 1;
const DIRECTORY_LAYOUT_GENERATION: u64 = 4;
const EVENT_LAYOUT_GENERATION: u64 = 5;
const DIRECTORY_LAYOUT_SEED: [u8; 32] = [0x35; 32];
const EVENT_LAYOUT_SEED: [u8; 32] = [0x01; 32];
const FINAL_ABSENT_READS: u64 = 2;
const MAX_EVENTS_PER_ADDRESS: u8 = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
/// Fixed typed-worker logical admitted-map saturation profiles.
pub enum TypedWorkerFullMapSaturationProfile {
    /// Independent deterministic directory- and event-admission boundary cases.
    FullMapSaturationV1,
}

impl TypedWorkerFullMapSaturationProfile {
    const fn as_str(self) -> &'static str {
        match self {
            Self::FullMapSaturationV1 => "full-map-saturation-v1",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
enum BoundaryKind {
    DirectoryAdmission,
    EventAdmission,
}

impl BoundaryKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::DirectoryAdmission => "directory-admission",
            Self::EventAdmission => "event-admission",
        }
    }

    const fn tag(self) -> u8 {
        match self {
            Self::DirectoryAdmission => 1,
            Self::EventAdmission => 2,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SaturationWorkerShape {
    directory_probes: u64,
    event_probes: u64,
    directory_capacity: u64,
    directory_admission_limit: u64,
    event_capacity: u64,
    event_admission_limit: u64,
    max_events_per_address: u64,
    queue_capacity: u64,
}

const WORKER_SHAPE: SaturationWorkerShape = SaturationWorkerShape {
    directory_probes: DIRECTORY_PROBES_U64,
    event_probes: EVENT_PROBES_U64,
    directory_capacity: 8,
    directory_admission_limit: 6,
    event_capacity: 16,
    event_admission_limit: 12,
    max_events_per_address: MAX_EVENTS_PER_ADDRESS as u64,
    queue_capacity: 1,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CaseSpec {
    boundary: BoundaryKind,
    modeled_addresses: u8,
    events_per_address: u8,
    fault_address: u8,
    fault_ordinal: u8,
    generation: u64,
    seed: [u8; 32],
}

const DIRECTORY_CASE: CaseSpec = CaseSpec {
    boundary: BoundaryKind::DirectoryAdmission,
    modeled_addresses: 6,
    events_per_address: 1,
    fault_address: 6,
    fault_ordinal: 0,
    generation: DIRECTORY_LAYOUT_GENERATION,
    seed: DIRECTORY_LAYOUT_SEED,
};

const EVENT_CASE: CaseSpec = CaseSpec {
    boundary: BoundaryKind::EventAdmission,
    modeled_addresses: 4,
    events_per_address: 3,
    fault_address: 0,
    fault_ordinal: 3,
    generation: EVENT_LAYOUT_GENERATION,
    seed: EVENT_LAYOUT_SEED,
};

impl CaseSpec {
    const fn inserted_events(self) -> u64 {
        self.modeled_addresses as u64 * self.events_per_address as u64
    }

    const fn expected_accepted(self) -> u64 {
        let inserted = self.inserted_events();
        inserted + self.modeled_addresses as u64 + inserted + FINAL_ABSENT_READS + 1 + 1 + 1
    }

    const fn expected_completed(self) -> u64 {
        self.expected_accepted() - 2
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PreFaultOccupancy {
    directory_occupied: u64,
    directory_admission_limit: u64,
    directory_admission_reserve: u64,
    directory_capacity: u64,
    directory_physical_reserve: u64,
    event_occupied: u64,
    event_admission_limit: u64,
    event_admission_reserve: u64,
    event_capacity: u64,
    event_physical_reserve: u64,
}

impl PreFaultOccupancy {
    const fn for_spec(spec: CaseSpec) -> Self {
        let directory_occupied = spec.modeled_addresses as u64;
        let event_occupied = spec.inserted_events();
        Self {
            directory_occupied,
            directory_admission_limit: WORKER_SHAPE.directory_admission_limit,
            directory_admission_reserve: WORKER_SHAPE.directory_admission_limit
                - directory_occupied,
            directory_capacity: WORKER_SHAPE.directory_capacity,
            directory_physical_reserve: WORKER_SHAPE.directory_capacity - directory_occupied,
            event_occupied,
            event_admission_limit: WORKER_SHAPE.event_admission_limit,
            event_admission_reserve: WORKER_SHAPE.event_admission_limit - event_occupied,
            event_capacity: WORKER_SHAPE.event_capacity,
            event_physical_reserve: WORKER_SHAPE.event_capacity - event_occupied,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BoundaryChecks {
    unique_appends: u64,
    full_history_reads: u64,
    exact_replays: u64,
    absent_reads: u64,
    cross_address_rejections: u64,
    followup_healthy_reads: u64,
    faulting_append_failed_closed: bool,
    post_fault_read_failed_closed: bool,
    post_fault_append_failed_closed: bool,
    post_fault_commands_rejected_at_admission: u64,
    correctness_passed: bool,
}

impl BoundaryChecks {
    const fn for_spec(spec: CaseSpec) -> Self {
        Self {
            unique_appends: spec.inserted_events(),
            full_history_reads: spec.modeled_addresses as u64,
            exact_replays: spec.inserted_events(),
            absent_reads: FINAL_ABSENT_READS,
            cross_address_rejections: 1,
            followup_healthy_reads: 1,
            faulting_append_failed_closed: true,
            post_fault_read_failed_closed: true,
            post_fault_append_failed_closed: true,
            post_fault_commands_rejected_at_admission: 2,
            correctness_passed: true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
// This records the pre-fault boundary state. The worker deliberately exposes
// only `FailedClosed`, so this is not an internal executor-cause discriminator.
struct BoundaryCondition {
    directory_admission_boundary_reached: bool,
    event_admission_boundary_reached: bool,
    per_address_event_boundary_reached: bool,
    physical_capacity_reached: bool,
}

impl BoundaryCondition {
    const fn for_boundary(boundary: BoundaryKind) -> Self {
        Self {
            directory_admission_boundary_reached: matches!(
                boundary,
                BoundaryKind::DirectoryAdmission
            ),
            event_admission_boundary_reached: matches!(boundary, BoundaryKind::EventAdmission),
            per_address_event_boundary_reached: false,
            physical_capacity_reached: false,
        }
    }

    fn is_one_hot_logical(self) -> bool {
        u8::from(self.directory_admission_boundary_reached)
            + u8::from(self.event_admission_boundary_reached)
            + u8::from(self.per_address_event_boundary_reached)
            == 1
            && !self.physical_capacity_reached
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SaturationWorkerTrace {
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

impl SaturationWorkerTrace {
    fn try_from_snapshot(
        snapshot: AtomicQualificationSnapshot,
    ) -> Result<Self, TypedWorkerFullMapSaturationError> {
        Ok(Self {
            queue_capacity: u64::try_from(snapshot.queue_capacity)
                .map_err(|_| TypedWorkerFullMapSaturationError::InvalidReport)?,
            queued_at_shutdown: u64::try_from(snapshot.queued)
                .map_err(|_| TypedWorkerFullMapSaturationError::InvalidReport)?,
            in_flight_at_shutdown: u64::try_from(snapshot.in_flight)
                .map_err(|_| TypedWorkerFullMapSaturationError::InvalidReport)?,
            queue_high_water: u64::try_from(snapshot.queue_high_water)
                .map_err(|_| TypedWorkerFullMapSaturationError::InvalidReport)?,
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

    const fn expected(spec: CaseSpec) -> Self {
        Self {
            queue_capacity: WORKER_SHAPE.queue_capacity,
            queued_at_shutdown: 0,
            in_flight_at_shutdown: 0,
            queue_high_water: 1,
            accepted: spec.expected_accepted(),
            completed: spec.expected_completed(),
            failed: 2,
            full_rejected: 0,
            not_running_rejected: 2,
            reply_delivery_failed: 0,
            stopped: true,
            faulted: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SaturationCaseReport {
    boundary: BoundaryKind,
    worker_shape: SaturationWorkerShape,
    pre_fault_occupancy: PreFaultOccupancy,
    checks: BoundaryChecks,
    schedule_blake2s256: String,
    final_state_blake2s256: String,
    boundary_condition: BoundaryCondition,
    worker_trace: SaturationWorkerTrace,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FullMapEvidenceScope {
    deterministic_small_table_correctness_checked: bool,
    logical_directory_admission_reached: bool,
    logical_event_admission_reached: bool,
    physical_capacity_reached: bool,
    random_target_load_measured: bool,
    adversarial_target_load_measured: bool,
    billion_operations_completed: bool,
    latency_measured: bool,
    rss_measured: bool,
    stash_measured: bool,
    queue_load_measured: bool,
    persistence_qualified: bool,
    recovery_qualified: bool,
    physical_trace_measured: bool,
    target_hardware_qualified: bool,
    tdx_qualified: bool,
    source_revision_bound: bool,
    lockfile_digest_bound: bool,
    toolchain_identity_bound: bool,
    binary_identity_bound: bool,
    execution_attested: bool,
    mainnet_sizing_qualified: bool,
    mainnet_gate_passed: bool,
}

const EVIDENCE_SCOPE: FullMapEvidenceScope = FullMapEvidenceScope {
    deterministic_small_table_correctness_checked: true,
    logical_directory_admission_reached: true,
    logical_event_admission_reached: true,
    physical_capacity_reached: false,
    random_target_load_measured: false,
    adversarial_target_load_measured: false,
    billion_operations_completed: false,
    latency_measured: false,
    rss_measured: false,
    stash_measured: false,
    queue_load_measured: false,
    persistence_qualified: false,
    recovery_qualified: false,
    physical_trace_measured: false,
    target_hardware_qualified: false,
    tdx_qualified: false,
    source_revision_bound: false,
    lockfile_digest_bound: false,
    toolchain_identity_bound: false,
    binary_identity_bound: false,
    execution_attested: false,
    mainnet_sizing_qualified: false,
    mainnet_gate_passed: false,
};

/// Aggregate-only evidence from one fixed logical admitted-map boundary profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TypedWorkerFullMapSaturationReport {
    scenario: String,
    profile: TypedWorkerFullMapSaturationProfile,
    backend: String,
    directory_boundary: SaturationCaseReport,
    event_boundary: SaturationCaseReport,
    evidence_scope: FullMapEvidenceScope,
}

impl TypedWorkerFullMapSaturationReport {
    /// Revalidates both fixed cases, counters, digests, and negative evidence flags.
    pub fn validate(&self) -> Result<(), TypedWorkerFullMapSaturationError> {
        let expected = build_report(
            SaturationWorkerTrace::expected(DIRECTORY_CASE),
            SaturationWorkerTrace::expected(EVENT_CASE),
        );
        if *self != expected
            || !self
                .directory_boundary
                .boundary_condition
                .is_one_hot_logical()
            || !self.event_boundary.boundary_condition.is_one_hot_logical()
        {
            return Err(TypedWorkerFullMapSaturationError::InvalidReport);
        }
        Ok(())
    }
}

impl fmt::Display for TypedWorkerFullMapSaturationReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "scenario={}", self.scenario)?;
        writeln!(f, "profile={}", self.profile.as_str())?;
        writeln!(f, "backend={}", self.backend)?;
        for case in [&self.directory_boundary, &self.event_boundary] {
            writeln!(
                f,
                "boundary={}:directory_occupied:{}/{},directory_physical_reserve:{},event_occupied:{}/{},event_physical_reserve:{},unique_appends:{},history_reads:{},exact_replays:{},failed_closed:{},stopped:{},faulted:{}",
                case.boundary.as_str(),
                case.pre_fault_occupancy.directory_occupied,
                case.pre_fault_occupancy.directory_admission_limit,
                case.pre_fault_occupancy.directory_physical_reserve,
                case.pre_fault_occupancy.event_occupied,
                case.pre_fault_occupancy.event_admission_limit,
                case.pre_fault_occupancy.event_physical_reserve,
                case.checks.unique_appends,
                case.checks.full_history_reads,
                case.checks.exact_replays,
                case.checks.faulting_append_failed_closed,
                case.worker_trace.stopped,
                case.worker_trace.faulted,
            )?;
            writeln!(
                f,
                "schedule_blake2s256={}:{}",
                case.boundary.as_str(),
                case.schedule_blake2s256
            )?;
            writeln!(
                f,
                "final_state_blake2s256={}:{}",
                case.boundary.as_str(),
                case.final_state_blake2s256
            )?;
        }
        writeln!(
            f,
            "evidence=deterministic-small-table-correctness,logical-directory-admission,logical-event-admission"
        )?;
        writeln!(
            f,
            "unbound=source-revision,lockfile,toolchain,binary,execution-attestation"
        )?;
        write!(
            f,
            "not_qualified=physical-capacity,random-target-load,adversarial-target-load,billion-operations,latency,rss,stash,queue-load,persistence,recovery,physical-trace,target-hardware,tdx,mainnet-sizing,mainnet-gate"
        )
    }
}

/// Coarse, identifier-free failure from the fixed admitted-map exercise.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TypedWorkerFullMapSaturationError {
    /// The real typed backend is not compiled for this target and feature set.
    TypedBackendUnavailable,
    /// A fixed layout, queue, or typed backend could not be constructed.
    ConstructionFailed,
    /// An ordinary accepted worker command failed before comparison.
    CommandFailed,
    /// A result differed from the deterministic expected history.
    CorrectnessMismatch,
    /// A boundary-crossing command did not fail closed and latch terminal state.
    BoundaryFaultMismatch,
    /// A worker did not stop with the fixed aggregate counters.
    ShutdownFailed,
    /// A report differs from the fixed schema, counters, digests, or evidence scope.
    InvalidReport,
}

impl fmt::Display for TypedWorkerFullMapSaturationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TypedBackendUnavailable => {
                f.write_str("typed-worker full-map saturation backend is unavailable")
            }
            Self::ConstructionFailed => {
                f.write_str("typed-worker full-map saturation construction failed")
            }
            Self::CommandFailed => f.write_str("typed-worker full-map saturation command failed"),
            Self::CorrectnessMismatch => {
                f.write_str("typed-worker full-map saturation correctness mismatch")
            }
            Self::BoundaryFaultMismatch => {
                f.write_str("typed-worker full-map saturation boundary fault mismatch")
            }
            Self::ShutdownFailed => f.write_str("typed-worker full-map saturation shutdown failed"),
            Self::InvalidReport => {
                f.write_str("typed-worker full-map saturation report is invalid")
            }
        }
    }
}

impl std::error::Error for TypedWorkerFullMapSaturationError {}

/// Runs the fixed listener-free admitted-map boundary profile against the typed backend.
pub fn run_typed_worker_full_map_saturation(
    profile: TypedWorkerFullMapSaturationProfile,
) -> Result<TypedWorkerFullMapSaturationReport, TypedWorkerFullMapSaturationError> {
    match profile {
        TypedWorkerFullMapSaturationProfile::FullMapSaturationV1 => run_full_map_saturation_v1(),
    }
}

fn run_full_map_saturation_v1(
) -> Result<TypedWorkerFullMapSaturationReport, TypedWorkerFullMapSaturationError> {
    let directory_trace =
        run_boundary_case(spawn_saturation_worker(DIRECTORY_CASE)?, DIRECTORY_CASE)?;
    if directory_trace != SaturationWorkerTrace::expected(DIRECTORY_CASE) {
        return Err(TypedWorkerFullMapSaturationError::ShutdownFailed);
    }

    let event_trace = run_boundary_case(spawn_saturation_worker(EVENT_CASE)?, EVENT_CASE)?;
    if event_trace != SaturationWorkerTrace::expected(EVENT_CASE) {
        return Err(TypedWorkerFullMapSaturationError::ShutdownFailed);
    }

    let report = build_report(directory_trace, event_trace);
    report.validate()?;
    Ok(report)
}

fn build_report(
    directory_trace: SaturationWorkerTrace,
    event_trace: SaturationWorkerTrace,
) -> TypedWorkerFullMapSaturationReport {
    TypedWorkerFullMapSaturationReport {
        scenario: SCENARIO.to_owned(),
        profile: TypedWorkerFullMapSaturationProfile::FullMapSaturationV1,
        backend: BACKEND.to_owned(),
        directory_boundary: build_case_report(DIRECTORY_CASE, directory_trace),
        event_boundary: build_case_report(EVENT_CASE, event_trace),
        evidence_scope: EVIDENCE_SCOPE,
    }
}

fn build_case_report(spec: CaseSpec, worker_trace: SaturationWorkerTrace) -> SaturationCaseReport {
    SaturationCaseReport {
        boundary: spec.boundary,
        worker_shape: WORKER_SHAPE,
        pre_fault_occupancy: PreFaultOccupancy::for_spec(spec),
        checks: BoundaryChecks::for_spec(spec),
        schedule_blake2s256: schedule_digest(spec),
        final_state_blake2s256: final_state_digest(spec),
        boundary_condition: BoundaryCondition::for_boundary(spec.boundary),
        worker_trace,
    }
}

fn spawn_saturation_worker(
    spec: CaseSpec,
) -> Result<AtomicWorker, TypedWorkerFullMapSaturationError> {
    let layout = build_saturation_layout(spec)?;
    let queue_capacity = usize::try_from(WORKER_SHAPE.queue_capacity)
        .map_err(|_| TypedWorkerFullMapSaturationError::ConstructionFailed)?;
    let queue_capacity = AtomicQueueCapacity::try_new(queue_capacity)
        .map_err(|_| TypedWorkerFullMapSaturationError::ConstructionFailed)?;
    spawn_typed_rostl_worker(layout, queue_capacity).map_err(map_worker_build)
}

fn build_saturation_layout(
    spec: CaseSpec,
) -> Result<FixedProbeLayout<DIRECTORY_PROBES, EVENT_PROBES>, TypedWorkerFullMapSaturationError> {
    FixedProbeLayout::new(
        LayoutIdentity::new(
            LayoutNetwork::Regtest,
            LAYOUT_SCHEMA_VERSION,
            LAYOUT_KEY_EPOCH,
            spec.generation,
            spec.seed,
        )
        .map_err(|_| TypedWorkerFullMapSaturationError::ConstructionFailed)?,
        DirectoryTableConfiguration::<DIRECTORY_PROBES>::new(
            WORKER_SHAPE.directory_capacity,
            WORKER_SHAPE.directory_admission_limit,
        )
        .map_err(|_| TypedWorkerFullMapSaturationError::ConstructionFailed)?,
        EventTableConfiguration::<EVENT_PROBES>::new(
            WORKER_SHAPE.event_capacity,
            WORKER_SHAPE.event_admission_limit,
        )
        .map_err(|_| TypedWorkerFullMapSaturationError::ConstructionFailed)?,
        WORKER_SHAPE.max_events_per_address,
    )
    .map_err(|_| TypedWorkerFullMapSaturationError::ConstructionFailed)
}

fn run_boundary_case(
    worker: AtomicWorker,
    spec: CaseSpec,
) -> Result<SaturationWorkerTrace, TypedWorkerFullMapSaturationError> {
    for address in 0..spec.modeled_addresses {
        for ordinal in 0..spec.events_per_address {
            let event = modeled_event(address, ordinal);
            let actual = worker
                .qualification_append_typed(modeled_address(address), event)
                .map_err(|_| TypedWorkerFullMapSaturationError::CommandFailed)?;
            if actual.disposition != AtomicQualificationAppendDisposition::Inserted {
                return Err(TypedWorkerFullMapSaturationError::CorrectnessMismatch);
            }
            verify_history(
                actual.history,
                &expected_history(address, ordinal.saturating_add(1)),
            )?;
        }
    }

    for address in 0..spec.modeled_addresses {
        let expected = expected_history(address, spec.events_per_address);
        let actual = worker
            .qualification_read_history_typed(modeled_address(address))
            .map_err(|_| TypedWorkerFullMapSaturationError::CommandFailed)?;
        verify_history(actual, &expected)?;
    }

    for address in 0..spec.modeled_addresses {
        let expected = expected_history(address, spec.events_per_address);
        for ordinal in 0..spec.events_per_address {
            let actual = worker
                .qualification_append_typed(
                    modeled_address(address),
                    modeled_event(address, ordinal),
                )
                .map_err(|_| TypedWorkerFullMapSaturationError::CommandFailed)?;
            if actual.disposition != AtomicQualificationAppendDisposition::ExactReplay {
                return Err(TypedWorkerFullMapSaturationError::CorrectnessMismatch);
            }
            verify_history(actual.history, &expected)?;
        }
    }

    for absent in 0..FINAL_ABSENT_READS as u8 {
        let actual = worker
            .qualification_read_history_typed(absent_address(absent.saturating_add(8)))
            .map_err(|_| TypedWorkerFullMapSaturationError::CommandFailed)?;
        verify_history(actual, &expected_history(0, 0))?;
    }

    let actual_owner = spec.modeled_addresses.saturating_sub(1);
    if !matches!(
        worker.qualification_append_typed(modeled_address(0), modeled_event(actual_owner, 0),),
        Err(AtomicQualificationCommandError::CommandRejected)
    ) {
        return Err(TypedWorkerFullMapSaturationError::CorrectnessMismatch);
    }

    let followup = worker
        .qualification_read_history_typed(modeled_address(0))
        .map_err(|_| TypedWorkerFullMapSaturationError::CommandFailed)?;
    verify_history(followup, &expected_history(0, spec.events_per_address))?;

    if !matches!(
        worker.qualification_append_typed(
            modeled_address(spec.fault_address),
            modeled_event(spec.fault_address, spec.fault_ordinal),
        ),
        Err(AtomicQualificationCommandError::FailedClosed)
    ) || !matches!(
        worker.qualification_read_history_typed(modeled_address(0)),
        Err(AtomicQualificationCommandError::FailedClosed)
    ) || !matches!(
        worker.qualification_append_typed(
            modeled_address(0),
            modeled_event(0, spec.events_per_address),
        ),
        Err(AtomicQualificationCommandError::FailedClosed)
    ) {
        return Err(TypedWorkerFullMapSaturationError::BoundaryFaultMismatch);
    }

    let snapshot = worker
        .qualification_shutdown()
        .map_err(|_| TypedWorkerFullMapSaturationError::ShutdownFailed)?;
    SaturationWorkerTrace::try_from_snapshot(snapshot)
}

fn expected_history(address: u8, event_count: u8) -> Vec<Option<UtxoEvent>> {
    (0..MAX_EVENTS_PER_ADDRESS)
        .map(|ordinal| (ordinal < event_count).then(|| modeled_event(address, ordinal)))
        .collect()
}

fn verify_history(
    actual: Vec<Option<UtxoEvent>>,
    expected: &[Option<UtxoEvent>],
) -> Result<(), TypedWorkerFullMapSaturationError> {
    if actual.as_slice() != expected {
        return Err(TypedWorkerFullMapSaturationError::CorrectnessMismatch);
    }
    Ok(())
}

fn schedule_digest(spec: CaseSpec) -> String {
    let mut hasher = Blake2s256::new();
    Digest::update(&mut hasher, b"zaino-oram-full-map-saturation-schedule-v1");
    Digest::update(&mut hasher, [spec.boundary.tag()]);
    let mut index = 0_u64;
    for address in 0..spec.modeled_addresses {
        for ordinal in 0..spec.events_per_address {
            update_schedule(&mut hasher, &mut index, [1, address, ordinal, 0]);
        }
    }
    for address in 0..spec.modeled_addresses {
        update_schedule(&mut hasher, &mut index, [2, address, 0, 0]);
    }
    for address in 0..spec.modeled_addresses {
        for ordinal in 0..spec.events_per_address {
            update_schedule(&mut hasher, &mut index, [3, address, ordinal, 0]);
        }
    }
    for absent in 0..FINAL_ABSENT_READS as u8 {
        update_schedule(&mut hasher, &mut index, [4, absent, 0, 0]);
    }
    update_schedule(
        &mut hasher,
        &mut index,
        [5, 0, spec.modeled_addresses.saturating_sub(1), 0],
    );
    update_schedule(&mut hasher, &mut index, [6, 0, 0, 0]);
    update_schedule(
        &mut hasher,
        &mut index,
        [7, spec.fault_address, spec.fault_ordinal, 0],
    );
    update_schedule(&mut hasher, &mut index, [8, 0, 0, 0]);
    update_schedule(&mut hasher, &mut index, [9, 0, spec.events_per_address, 0]);
    digest_hex(Digest::finalize(hasher).as_slice())
}

fn update_schedule(hasher: &mut Blake2s256, index: &mut u64, descriptor: [u8; 4]) {
    Digest::update(hasher, index.to_le_bytes());
    Digest::update(hasher, descriptor);
    *index += 1;
}

fn final_state_digest(spec: CaseSpec) -> String {
    let mut hasher = Blake2s256::new();
    Digest::update(
        &mut hasher,
        b"zaino-oram-full-map-saturation-final-state-v1",
    );
    Digest::update(&mut hasher, [spec.boundary.tag()]);
    for address in 0..spec.modeled_addresses {
        Digest::update(&mut hasher, [address, spec.events_per_address]);
        for ordinal in 0..spec.events_per_address {
            let event = modeled_event(address, ordinal);
            Digest::update(&mut hasher, [ordinal]);
            Digest::update(&mut hasher, event.value_zat().to_le_bytes());
            Digest::update(&mut hasher, event.script_hash());
        }
    }
    digest_hex(Digest::finalize(hasher).as_slice())
}

const fn map_worker_build(error: AtomicWorkerBuildError) -> TypedWorkerFullMapSaturationError {
    match error {
        #[cfg(not(all(
            feature = "rostl-experimental",
            target_os = "linux",
            target_arch = "x86_64"
        )))]
        AtomicWorkerBuildError::TypedBackendUnavailable => {
            TypedWorkerFullMapSaturationError::TypedBackendUnavailable
        }
        AtomicWorkerBuildError::ConstructionFailed => {
            TypedWorkerFullMapSaturationError::ConstructionFailed
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

    fn fake_worker(spec: CaseSpec) -> TestResult<AtomicWorker> {
        let layout = build_saturation_layout(spec)?;
        let directory = MemoryTable::<PersistentAddressDirectory>::new(usize::try_from(
            WORKER_SHAPE.directory_capacity,
        )?);
        let events = MemoryTable::<PersistentAddressEventPage>::new(usize::try_from(
            WORKER_SHAPE.event_capacity,
        )?);
        let queue_capacity =
            AtomicQueueCapacity::try_new(usize::try_from(WORKER_SHAPE.queue_capacity)?)?;
        Ok(spawn_atomic_worker_for_tests(
            layout,
            directory,
            events,
            queue_capacity,
        )?)
    }

    fn expected_report() -> TypedWorkerFullMapSaturationReport {
        build_report(
            SaturationWorkerTrace::expected(DIRECTORY_CASE),
            SaturationWorkerTrace::expected(EVENT_CASE),
        )
    }

    #[test]
    fn exact_profile_exercises_directory_logical_boundary() -> TestResult {
        let directory_trace = run_boundary_case(fake_worker(DIRECTORY_CASE)?, DIRECTORY_CASE)?;
        assert_eq!(
            directory_trace,
            SaturationWorkerTrace::expected(DIRECTORY_CASE)
        );
        Ok(())
    }

    #[test]
    fn exact_profile_exercises_event_logical_boundary() -> TestResult {
        let event_trace = run_boundary_case(fake_worker(EVENT_CASE)?, EVENT_CASE)?;
        assert_eq!(event_trace, SaturationWorkerTrace::expected(EVENT_CASE));
        Ok(())
    }

    #[test]
    fn report_pins_occupancy_reserve_and_one_hot_boundaries() -> TestResult {
        let report = expected_report();
        report.validate()?;

        assert_eq!(
            report.directory_boundary.pre_fault_occupancy,
            PreFaultOccupancy {
                directory_occupied: 6,
                directory_admission_limit: 6,
                directory_admission_reserve: 0,
                directory_capacity: 8,
                directory_physical_reserve: 2,
                event_occupied: 6,
                event_admission_limit: 12,
                event_admission_reserve: 6,
                event_capacity: 16,
                event_physical_reserve: 10,
            }
        );
        assert_eq!(
            report.event_boundary.pre_fault_occupancy,
            PreFaultOccupancy {
                directory_occupied: 4,
                directory_admission_limit: 6,
                directory_admission_reserve: 2,
                directory_capacity: 8,
                directory_physical_reserve: 4,
                event_occupied: 12,
                event_admission_limit: 12,
                event_admission_reserve: 0,
                event_capacity: 16,
                event_physical_reserve: 4,
            }
        );
        assert!(report
            .directory_boundary
            .boundary_condition
            .is_one_hot_logical());
        assert!(report
            .event_boundary
            .boundary_condition
            .is_one_hot_logical());
        Ok(())
    }

    #[test]
    fn report_round_trip_revalidates_and_rejects_overclaim() -> TestResult {
        let report = expected_report();
        let encoded = serde_json::to_vec(&report)?;
        let decoded: TypedWorkerFullMapSaturationReport = serde_json::from_slice(&encoded)?;
        assert_eq!(decoded, report);
        decoded.validate()?;

        let mut overstated = report;
        overstated.evidence_scope.physical_capacity_reached = true;
        assert_eq!(
            overstated.validate(),
            Err(TypedWorkerFullMapSaturationError::InvalidReport)
        );
        Ok(())
    }

    #[test]
    fn report_rejects_unknown_fields_and_text_is_identifier_free() -> TestResult {
        let report = expected_report();
        let mut unknown = serde_json::to_value(&report)?;
        unknown["unexpected"] = serde_json::json!(true);
        assert!(serde_json::from_value::<TypedWorkerFullMapSaturationReport>(unknown).is_err());

        let text = report.to_string();
        assert!(text.contains("logical-directory-admission,logical-event-admission"));
        assert!(text.contains("not_qualified=physical-capacity,random-target-load"));
        assert!(!text.contains("modeled-address"));
        assert!(!text.contains("3535353535353535"));
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
            run_typed_worker_full_map_saturation(
                TypedWorkerFullMapSaturationProfile::FullMapSaturationV1,
            ),
            Err(TypedWorkerFullMapSaturationError::TypedBackendUnavailable)
        );
    }

    #[cfg(all(
        feature = "rostl-experimental",
        target_os = "linux",
        target_arch = "x86_64"
    ))]
    #[test]
    fn native_typed_worker_completes_full_map_saturation_v1() -> TestResult {
        let report = run_typed_worker_full_map_saturation(
            TypedWorkerFullMapSaturationProfile::FullMapSaturationV1,
        )?;
        report.validate()?;
        Ok(())
    }
}
