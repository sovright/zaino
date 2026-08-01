//! Source-bound target-load experiments for the real typed worker.
//!
//! This module intentionally measures only the single-caller boundary that the
//! current worker exposes. It does not infer backend stash state, physical
//! access traces, queue contention, persistence, or target-hardware behavior.

use std::{
    collections::BTreeMap,
    fmt,
    time::{Duration, Instant},
};

use blake2::{Blake2s256, Digest};
use serde::{Deserialize, Serialize};

use crate::{
    layout::{
        spawn_typed_rostl_worker, AtomicQualificationAppendDisposition,
        AtomicQualificationSnapshot, AtomicQueueCapacity, AtomicWorker, AtomicWorkerBuildError,
        DirectoryTableConfiguration, EventTableConfiguration, FixedProbeLayout, LayoutIdentity,
        LayoutNetwork, StandardAddress, StandardScriptKind,
    },
    process_memory::{sample_process_memory, ProcessMemorySample},
    records::{UtxoEvent, UtxoScriptClass},
    stress_qualification::digest_hex,
    zaino_corpus::MainnetSizingQualification,
};

const SCENARIO: &str = "typed-worker-target-load-builder-foundation-v1";
const BACKEND: &str = "rostl-circuit-oram-volatile-v1";
const DERIVATION_DOMAIN: &[u8] = b"zaino-oram-target-load-builder-foundation-v1";
const DIRECTORY_PROBES_U64: u64 = 4;
const EVENT_PROBES_U64: u64 = 4;
const DIRECTORY_PROBES: usize = DIRECTORY_PROBES_U64 as usize;
const EVENT_PROBES: usize = EVENT_PROBES_U64 as usize;
const QUEUE_CAPACITY: u64 = 1;
const LAYOUT_SCHEMA_VERSION: u32 = 1;
const LAYOUT_KEY_EPOCH: u64 = 1;
const LAYOUT_GENERATION: u64 = 6;
const MAX_LAYOUT_PLAN_ATTEMPTS: u64 = 64;
const MAX_ADDRESS_CANDIDATES: u64 = 1_000_000;

const MEASURED_COMMANDS: u64 = 256;
const MEASURED_HOT_READS: u64 = 160;
const MEASURED_COLD_READS: u64 = 48;
const MEASURED_HOT_APPENDS: u64 = 32;
const MEASURED_COLD_APPENDS: u64 = 16;
const HOT_ADDRESSES: u64 = 16;
const RESERVED_DIRECTORY_SLOTS: u64 = MEASURED_COLD_APPENDS;
const RESERVED_EVENT_SLOTS: u64 = MEASURED_HOT_APPENDS + MEASURED_COLD_APPENDS;

const MIN_DIRECTORY_CAPACITY: u64 = 64;
const MAX_DIRECTORY_CAPACITY: u64 = 512;
const MIN_DIRECTORY_ADMISSION_LIMIT: u64 = 48;
const MIN_EVENT_CAPACITY: u64 = 128;
const MAX_EVENT_CAPACITY: u64 = 4_096;
const MIN_EVENT_ADMISSION_LIMIT: u64 = 96;
const MIN_EVENTS_PER_ADDRESS: u64 = 3;
const MAX_EVENTS_PER_ADDRESS: u64 = 64;
const MIN_MEASURED_DIRECTORY_PROBE_COLLISIONS: u64 = 8;
const MIN_MEASURED_EVENT_PROBE_COLLISIONS: u64 = 24;
const NANOS_PER_SECOND: u128 = 1_000_000_000;

/// Fixed target-load profiles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TypedWorkerTargetLoadProfile {
    /// A bounded single-caller experiment for the generic Linux x86_64 builder.
    BuilderFoundationV1,
}

impl TypedWorkerTargetLoadProfile {
    const fn as_str(self) -> &'static str {
        match self {
            Self::BuilderFoundationV1 => "builder-foundation-v1",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TargetLoadSizingInput {
    measurement_blake2s256: String,
    qualification_blake2s256: String,
    checkpoint_height: u32,
    checkpoint_hash: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TargetLoadWorkerShape {
    directory_probes: u64,
    event_probes: u64,
    directory_capacity: u64,
    directory_admission_limit: u64,
    event_capacity: u64,
    event_admission_limit: u64,
    max_events_per_address: u64,
    queue_capacity: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TargetLoadBuilderEnvelope {
    min_directory_capacity: u64,
    max_directory_capacity: u64,
    min_directory_admission_limit: u64,
    min_event_capacity: u64,
    max_event_capacity: u64,
    min_event_admission_limit: u64,
    min_events_per_address: u64,
    max_events_per_address: u64,
}

const BUILDER_ENVELOPE: TargetLoadBuilderEnvelope = TargetLoadBuilderEnvelope {
    min_directory_capacity: MIN_DIRECTORY_CAPACITY,
    max_directory_capacity: MAX_DIRECTORY_CAPACITY,
    min_directory_admission_limit: MIN_DIRECTORY_ADMISSION_LIMIT,
    min_event_capacity: MIN_EVENT_CAPACITY,
    max_event_capacity: MAX_EVENT_CAPACITY,
    min_event_admission_limit: MIN_EVENT_ADMISSION_LIMIT,
    min_events_per_address: MIN_EVENTS_PER_ADDRESS,
    max_events_per_address: MAX_EVENTS_PER_ADDRESS,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TargetLoadWorkloadShape {
    measured_commands: u64,
    measured_reads: u64,
    measured_unique_appends: u64,
    measured_hot_reads: u64,
    measured_cold_reads: u64,
    measured_hot_appends: u64,
    measured_cold_appends: u64,
    hot_addresses: u64,
    reserved_directory_slots: u64,
    reserved_event_slots: u64,
    cold_read_class: TargetLoadColdReadClass,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum TargetLoadColdReadClass {
    ResidentNonHotWarmupSet,
}

const WORKLOAD_SHAPE: TargetLoadWorkloadShape = TargetLoadWorkloadShape {
    measured_commands: MEASURED_COMMANDS,
    measured_reads: MEASURED_HOT_READS + MEASURED_COLD_READS,
    measured_unique_appends: MEASURED_HOT_APPENDS + MEASURED_COLD_APPENDS,
    measured_hot_reads: MEASURED_HOT_READS,
    measured_cold_reads: MEASURED_COLD_READS,
    measured_hot_appends: MEASURED_HOT_APPENDS,
    measured_cold_appends: MEASURED_COLD_APPENDS,
    hot_addresses: HOT_ADDRESSES,
    reserved_directory_slots: RESERVED_DIRECTORY_SLOTS,
    reserved_event_slots: RESERVED_EVENT_SLOTS,
    cold_read_class: TargetLoadColdReadClass::ResidentNonHotWarmupSet,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TargetLoadWorkloadSummary {
    warmup_addresses: u64,
    warmup_events: u64,
    measured_reads: u64,
    measured_unique_appends: u64,
    measured_hot_reads: u64,
    measured_cold_reads: u64,
    measured_hot_appends: u64,
    measured_cold_appends: u64,
    final_directory_occupied: u64,
    final_event_occupied: u64,
    total_commands: u64,
    correctness_passed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TargetLoadLogicalProbeCollisions {
    warmup_directory_occupied_probes: u64,
    warmup_event_occupied_probes: u64,
    measured_directory_occupied_probes: u64,
    measured_event_occupied_probes: u64,
}

impl TargetLoadLogicalProbeCollisions {
    const ZERO: Self = Self {
        warmup_directory_occupied_probes: 0,
        warmup_event_occupied_probes: 0,
        measured_directory_occupied_probes: 0,
        measured_event_occupied_probes: 0,
    };
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TargetLoadLatencySummary {
    count: u64,
    total_elapsed_ns: u64,
    min_ns: u64,
    p50_ns: u64,
    p95_ns: u64,
    p99_ns: u64,
    max_ns: u64,
}

impl TargetLoadLatencySummary {
    fn validate(&self) -> bool {
        if self.count == 0
            || self.min_ns > self.p50_ns
            || self.p50_ns > self.p95_ns
            || self.p95_ns > self.p99_ns
            || self.p99_ns > self.max_ns
            || self.total_elapsed_ns < self.max_ns
        {
            return false;
        }
        let total = u128::from(self.total_elapsed_ns);
        let count = u128::from(self.count);
        u128::from(self.min_ns) * count <= total && total <= u128::from(self.max_ns) * count
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TargetLoadTimingReport {
    measured_phase_wall_ns: u64,
    cumulative_worker_call_wait_ns: u64,
    percentile_method: TargetLoadPercentileMethod,
    all_worker_call_latency: TargetLoadLatencySummary,
    read_worker_call_latency: TargetLoadLatencySummary,
    append_worker_call_latency: TargetLoadLatencySummary,
    mixed_phase_commands_per_second_floor: u64,
    mixed_phase_read_completions_per_second_floor: u64,
    mixed_phase_append_completions_per_second_floor: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum TargetLoadPercentileMethod {
    NearestRankV1,
}

impl TargetLoadPercentileMethod {
    const fn as_str(self) -> &'static str {
        match self {
            Self::NearestRankV1 => "nearest-rank-v1",
        }
    }
}

impl TargetLoadTimingReport {
    fn validate(&self) -> bool {
        let Some(combined_total) = self
            .read_worker_call_latency
            .total_elapsed_ns
            .checked_add(self.append_worker_call_latency.total_elapsed_ns)
        else {
            return false;
        };
        self.measured_phase_wall_ns > 0
            && self.percentile_method == TargetLoadPercentileMethod::NearestRankV1
            && self.all_worker_call_latency.validate()
            && self.read_worker_call_latency.validate()
            && self.append_worker_call_latency.validate()
            && self.all_worker_call_latency.count == MEASURED_COMMANDS
            && self.read_worker_call_latency.count == WORKLOAD_SHAPE.measured_reads
            && self.append_worker_call_latency.count == WORKLOAD_SHAPE.measured_unique_appends
            && self.all_worker_call_latency.total_elapsed_ns == combined_total
            && self.cumulative_worker_call_wait_ns == self.all_worker_call_latency.total_elapsed_ns
            && self.cumulative_worker_call_wait_ns <= self.measured_phase_wall_ns
            && throughput_floor(MEASURED_COMMANDS, self.measured_phase_wall_ns)
                == Some(self.mixed_phase_commands_per_second_floor)
            && throughput_floor(WORKLOAD_SHAPE.measured_reads, self.measured_phase_wall_ns)
                == Some(self.mixed_phase_read_completions_per_second_floor)
            && throughput_floor(
                WORKLOAD_SHAPE.measured_unique_appends,
                self.measured_phase_wall_ns,
            ) == Some(self.mixed_phase_append_completions_per_second_floor)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TargetLoadRssReport {
    sampling_source: String,
    measurement_scope: String,
    baseline_rss_bytes: u64,
    post_spawn_rss_bytes: u64,
    post_warmup_rss_bytes: u64,
    post_workload_rss_bytes: u64,
    process_lifetime_hwm_bytes: u64,
}

impl TargetLoadRssReport {
    fn validate(&self) -> bool {
        let samples = [
            self.baseline_rss_bytes,
            self.post_spawn_rss_bytes,
            self.post_warmup_rss_bytes,
            self.post_workload_rss_bytes,
        ];
        self.sampling_source == "proc-status-vmrss-vmhwm"
            && self.measurement_scope == "whole-process-including-driver-and-runtime"
            && samples.iter().all(|sample| *sample > 0)
            && self.process_lifetime_hwm_bytes > 0
            && samples
                .iter()
                .all(|sample| self.process_lifetime_hwm_bytes >= *sample)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TargetLoadWorkerTrace {
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

impl TargetLoadWorkerTrace {
    fn try_from_snapshot(
        snapshot: AtomicQualificationSnapshot,
    ) -> Result<Self, TypedWorkerTargetLoadError> {
        Ok(Self {
            queue_capacity: u64::try_from(snapshot.queue_capacity)
                .map_err(|_| TypedWorkerTargetLoadError::InvalidReport)?,
            queued_at_shutdown: u64::try_from(snapshot.queued)
                .map_err(|_| TypedWorkerTargetLoadError::InvalidReport)?,
            in_flight_at_shutdown: u64::try_from(snapshot.in_flight)
                .map_err(|_| TypedWorkerTargetLoadError::InvalidReport)?,
            queue_high_water: u64::try_from(snapshot.queue_high_water)
                .map_err(|_| TypedWorkerTargetLoadError::InvalidReport)?,
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

    const fn expected(total_commands: u64) -> Self {
        Self {
            queue_capacity: QUEUE_CAPACITY,
            queued_at_shutdown: 0,
            in_flight_at_shutdown: 0,
            queue_high_water: 1,
            accepted: total_commands,
            completed: total_commands,
            failed: 0,
            full_rejected: 0,
            not_running_rejected: 0,
            reply_delivery_failed: 0,
            stopped: true,
            faulted: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum TargetLoadUnavailableSignal {
    BackendUnobservable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TargetLoadUnavailableMarkers {
    stash_current: TargetLoadUnavailableSignal,
    stash_peak: TargetLoadUnavailableSignal,
    physical_access_trace: TargetLoadUnavailableSignal,
}

const UNAVAILABLE_MARKERS: TargetLoadUnavailableMarkers = TargetLoadUnavailableMarkers {
    stash_current: TargetLoadUnavailableSignal::BackendUnobservable,
    stash_peak: TargetLoadUnavailableSignal::BackendUnobservable,
    physical_access_trace: TargetLoadUnavailableSignal::BackendUnobservable,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TargetLoadEvidenceScope {
    correctness_checked: bool,
    single_caller_builder_linux_x86_64: bool,
    sizing_bound_shape_used: bool,
    mixed_read_insert_workload_checked: bool,
    deterministic_shuffled_workload_checked: bool,
    logical_probe_collision_schedule_checked: bool,
    typed_worker_call_latency_measured: bool,
    mixed_phase_completion_rates_measured: bool,
    whole_process_rss_measured: bool,
    queue_counters_observed: bool,
    queue_contention_measured: bool,
    stash_measured: bool,
    physical_trace_measured: bool,
    persistence_qualified: bool,
    recovery_qualified: bool,
    target_hardware_qualified: bool,
    tdx_qualified: bool,
    billion_operations_completed: bool,
    source_revision_bound: bool,
    lockfile_digest_bound: bool,
    toolchain_identity_bound: bool,
    binary_identity_bound: bool,
    execution_attested: bool,
    signed_provenance: bool,
    mainnet_ready: bool,
}

const EVIDENCE_SCOPE: TargetLoadEvidenceScope = TargetLoadEvidenceScope {
    correctness_checked: true,
    single_caller_builder_linux_x86_64: true,
    sizing_bound_shape_used: true,
    mixed_read_insert_workload_checked: true,
    deterministic_shuffled_workload_checked: true,
    logical_probe_collision_schedule_checked: true,
    typed_worker_call_latency_measured: true,
    mixed_phase_completion_rates_measured: true,
    whole_process_rss_measured: true,
    queue_counters_observed: true,
    queue_contention_measured: false,
    stash_measured: false,
    physical_trace_measured: false,
    persistence_qualified: false,
    recovery_qualified: false,
    target_hardware_qualified: false,
    tdx_qualified: false,
    billion_operations_completed: false,
    source_revision_bound: false,
    lockfile_digest_bound: false,
    toolchain_identity_bound: false,
    binary_identity_bound: false,
    execution_attested: false,
    signed_provenance: false,
    mainnet_ready: false,
};

/// Aggregate-only evidence from one sizing-bound builder target-load run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TypedWorkerTargetLoadReport {
    scenario: String,
    profile: TypedWorkerTargetLoadProfile,
    backend: String,
    sizing_input: TargetLoadSizingInput,
    worker_shape: TargetLoadWorkerShape,
    builder_envelope: TargetLoadBuilderEnvelope,
    workload_shape: TargetLoadWorkloadShape,
    workload_summary: TargetLoadWorkloadSummary,
    logical_probe_collisions: TargetLoadLogicalProbeCollisions,
    schedule_blake2s256: String,
    final_state_blake2s256: String,
    timing: TargetLoadTimingReport,
    rss: TargetLoadRssReport,
    worker_trace: TargetLoadWorkerTrace,
    unavailable: TargetLoadUnavailableMarkers,
    evidence_scope: TargetLoadEvidenceScope,
}

impl TypedWorkerTargetLoadReport {
    /// Revalidates the self-contained shape, deterministic plan, aggregate metrics, and claims.
    ///
    /// Validation against the original capture and sizing artifact occurs at the daemon boundary.
    pub fn validate(&self) -> Result<(), TypedWorkerTargetLoadError> {
        let inputs = TargetLoadInputs {
            sizing_input: self.sizing_input.clone(),
            worker_shape: self.worker_shape,
        };
        inputs.validate()?;
        let plan = TargetLoadPlan::build(&inputs)?;
        if self.scenario != SCENARIO
            || self.profile != TypedWorkerTargetLoadProfile::BuilderFoundationV1
            || self.backend != BACKEND
            || self.builder_envelope != BUILDER_ENVELOPE
            || self.workload_shape != WORKLOAD_SHAPE
            || self.workload_summary != plan.summary
            || self.logical_probe_collisions != plan.collisions
            || self.schedule_blake2s256 != plan.schedule_blake2s256
            || self.final_state_blake2s256 != plan.final_state_blake2s256
            || !self.timing.validate()
            || !self.rss.validate()
            || self.worker_trace != TargetLoadWorkerTrace::expected(plan.summary.total_commands)
            || self.unavailable != UNAVAILABLE_MARKERS
            || self.evidence_scope != EVIDENCE_SCOPE
        {
            return Err(TypedWorkerTargetLoadError::InvalidReport);
        }
        Ok(())
    }

    /// Revalidates this report against the sizing qualification and lineage supplied by a caller.
    pub fn validate_against(
        &self,
        sizing: &MainnetSizingQualification,
        measurement_blake2s256: &str,
        qualification_blake2s256: &str,
    ) -> Result<(), TypedWorkerTargetLoadError> {
        self.validate()?;
        let expected = TargetLoadInputs::from_qualification(
            sizing,
            measurement_blake2s256,
            qualification_blake2s256,
        )?;
        if self.sizing_input != expected.sizing_input || self.worker_shape != expected.worker_shape
        {
            return Err(TypedWorkerTargetLoadError::InvalidReport);
        }
        Ok(())
    }
}

impl fmt::Display for TypedWorkerTargetLoadReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "scenario={}", self.scenario)?;
        writeln!(f, "profile={}", self.profile.as_str())?;
        writeln!(f, "backend={}", self.backend)?;
        writeln!(
            f,
            "sizing_input=checkpoint_height:{},measurement_blake2s256:{},qualification_blake2s256:{}",
            self.sizing_input.checkpoint_height,
            self.sizing_input.measurement_blake2s256,
            self.sizing_input.qualification_blake2s256,
        )?;
        writeln!(
            f,
            "worker_shape=directory:{}/{},event:{}/{},max_events_per_address:{},queue:{}",
            self.worker_shape.directory_admission_limit,
            self.worker_shape.directory_capacity,
            self.worker_shape.event_admission_limit,
            self.worker_shape.event_capacity,
            self.worker_shape.max_events_per_address,
            self.worker_shape.queue_capacity,
        )?;
        writeln!(
            f,
            "workload=warmup_addresses:{},warmup_events:{},measured_commands:{},reads:{},appends:{},final_directory:{},final_events:{},correct:{}",
            self.workload_summary.warmup_addresses,
            self.workload_summary.warmup_events,
            MEASURED_COMMANDS,
            self.workload_summary.measured_reads,
            self.workload_summary.measured_unique_appends,
            self.workload_summary.final_directory_occupied,
            self.workload_summary.final_event_occupied,
            self.workload_summary.correctness_passed,
        )?;
        writeln!(
            f,
            "timing=phase_wall_ns:{},worker_call_wait_ns:{},percentile_method:{},mixed_phase_commands_per_second_floor:{},read_worker_call_p99_ns:{},append_worker_call_p99_ns:{}",
            self.timing.measured_phase_wall_ns,
            self.timing.cumulative_worker_call_wait_ns,
            self.timing.percentile_method.as_str(),
            self.timing.mixed_phase_commands_per_second_floor,
            self.timing.read_worker_call_latency.p99_ns,
            self.timing.append_worker_call_latency.p99_ns,
        )?;
        writeln!(
            f,
            "rss=source:{},scope:{},baseline:{},post_spawn:{},post_warmup:{},post_workload:{},process_lifetime_hwm:{}",
            self.rss.sampling_source,
            self.rss.measurement_scope,
            self.rss.baseline_rss_bytes,
            self.rss.post_spawn_rss_bytes,
            self.rss.post_warmup_rss_bytes,
            self.rss.post_workload_rss_bytes,
            self.rss.process_lifetime_hwm_bytes,
        )?;
        writeln!(f, "schedule_blake2s256={}", self.schedule_blake2s256)?;
        writeln!(f, "final_state_blake2s256={}", self.final_state_blake2s256)?;
        writeln!(
            f,
            "unavailable=stash-current:backend-unobservable,stash-peak:backend-unobservable,physical-access-trace:backend-unobservable",
        )?;
        write!(
            f,
            "nonclaims=queue-contention,persistence,recovery,target-hardware,tdx,billion-operations,attestation,signed-provenance,mainnet-readiness"
        )
    }
}

/// Coarse identifier-free target-load failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TypedWorkerTargetLoadError {
    /// The real typed backend is unavailable on this feature/target combination.
    TypedBackendUnavailable,
    /// A source digest, sizing shape, or immutable profile precondition was rejected.
    InputRejected,
    /// The layout, queue, or typed backend could not be constructed.
    ConstructionFailed,
    /// An accepted worker command failed.
    CommandFailed,
    /// A worker result differed from the in-memory reference model.
    CorrectnessMismatch,
    /// A required caller-visible timing or process-memory measurement failed.
    MeasurementFailed,
    /// The worker did not stop with a clean aggregate snapshot.
    ShutdownFailed,
    /// A report differs from its deterministic inputs or fixed claim boundary.
    InvalidReport,
}

impl fmt::Display for TypedWorkerTargetLoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TypedBackendUnavailable => {
                f.write_str("typed-worker target-load backend is unavailable")
            }
            Self::InputRejected => f.write_str("typed-worker target-load input was rejected"),
            Self::ConstructionFailed => f.write_str("typed-worker target-load construction failed"),
            Self::CommandFailed => f.write_str("typed-worker target-load command failed"),
            Self::CorrectnessMismatch => {
                f.write_str("typed-worker target-load correctness mismatch")
            }
            Self::MeasurementFailed => f.write_str("typed-worker target-load measurement failed"),
            Self::ShutdownFailed => f.write_str("typed-worker target-load shutdown failed"),
            Self::InvalidReport => f.write_str("typed-worker target-load report is invalid"),
        }
    }
}

impl std::error::Error for TypedWorkerTargetLoadError {}

#[derive(Clone)]
struct TargetLoadInputs {
    sizing_input: TargetLoadSizingInput,
    worker_shape: TargetLoadWorkerShape,
}

impl TargetLoadInputs {
    fn from_qualification(
        sizing: &MainnetSizingQualification,
        measurement_blake2s256: &str,
        qualification_blake2s256: &str,
    ) -> Result<Self, TypedWorkerTargetLoadError> {
        sizing
            .validate()
            .map_err(|_| TypedWorkerTargetLoadError::InputRejected)?;
        let model = sizing.model();
        let inputs = Self {
            sizing_input: TargetLoadSizingInput {
                measurement_blake2s256: measurement_blake2s256.to_owned(),
                qualification_blake2s256: qualification_blake2s256.to_owned(),
                checkpoint_height: sizing.checkpoint().height(),
                checkpoint_hash: sizing.checkpoint().hash().to_owned(),
            },
            worker_shape: TargetLoadWorkerShape {
                directory_probes: DIRECTORY_PROBES_U64,
                event_probes: EVENT_PROBES_U64,
                directory_capacity: model.directory_capacity(),
                directory_admission_limit: model.directory_admission_limit(),
                event_capacity: model.event_capacity(),
                event_admission_limit: model.event_admission_limit(),
                max_events_per_address: model.max_events_per_address(),
                queue_capacity: QUEUE_CAPACITY,
            },
        };
        inputs.validate()?;
        Ok(inputs)
    }

    fn validate(&self) -> Result<(), TypedWorkerTargetLoadError> {
        if !is_blake2s256_hex(&self.sizing_input.measurement_blake2s256)
            || !is_blake2s256_hex(&self.sizing_input.qualification_blake2s256)
            || !is_blake2s256_hex(&self.sizing_input.checkpoint_hash)
            || !worker_shape_is_supported(self.worker_shape)
        {
            return Err(TypedWorkerTargetLoadError::InputRejected);
        }
        Ok(())
    }
}

fn worker_shape_is_supported(shape: TargetLoadWorkerShape) -> bool {
    if shape.directory_probes != DIRECTORY_PROBES_U64
        || shape.event_probes != EVENT_PROBES_U64
        || shape.queue_capacity != QUEUE_CAPACITY
        || !shape.directory_capacity.is_power_of_two()
        || !shape.event_capacity.is_power_of_two()
        || !(MIN_DIRECTORY_CAPACITY..=MAX_DIRECTORY_CAPACITY).contains(&shape.directory_capacity)
        || !(MIN_EVENT_CAPACITY..=MAX_EVENT_CAPACITY).contains(&shape.event_capacity)
        || shape.directory_admission_limit < MIN_DIRECTORY_ADMISSION_LIMIT
        || shape.directory_admission_limit >= shape.directory_capacity
        || shape.event_admission_limit < MIN_EVENT_ADMISSION_LIMIT
        || shape.event_admission_limit >= shape.event_capacity
        || !(MIN_EVENTS_PER_ADDRESS..=MAX_EVENTS_PER_ADDRESS)
            .contains(&shape.max_events_per_address)
    {
        return false;
    }
    let Some(warm_directory_target) = shape
        .directory_admission_limit
        .checked_sub(RESERVED_DIRECTORY_SLOTS)
    else {
        return false;
    };
    let Some(warm_event_target) = shape
        .event_admission_limit
        .checked_sub(RESERVED_EVENT_SLOTS)
    else {
        return false;
    };
    let Some(nonhot_addresses) = warm_directory_target.checked_sub(HOT_ADDRESSES) else {
        return false;
    };
    let Some(max_warm_events) = nonhot_addresses
        .checked_mul(shape.max_events_per_address)
        .and_then(|events| events.checked_add(HOT_ADDRESSES))
    else {
        return false;
    };
    warm_directory_target >= HOT_ADDRESSES * 2
        && warm_event_target >= warm_directory_target
        && warm_event_target <= max_warm_events
}

pub(super) fn is_blake2s256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[derive(Clone, Copy)]
struct PlannedAppend {
    address_index: u64,
    ordinal: u64,
}

#[derive(Clone, Copy)]
enum PlannedCommand {
    HotRead { address_index: u64 },
    ColdRead { address_index: u64 },
    HotAppend(PlannedAppend),
    ColdAppend(PlannedAppend),
}

#[derive(Clone, Copy)]
enum PlanToken {
    HotRead(u64),
    ColdRead(u64),
    HotAppend(u64),
    ColdAppend(u64),
}

struct TargetLoadPlan {
    layout_seed: [u8; 32],
    warmup: Vec<PlannedAppend>,
    measured: Vec<PlannedCommand>,
    summary: TargetLoadWorkloadSummary,
    collisions: TargetLoadLogicalProbeCollisions,
    schedule_blake2s256: String,
    final_state_blake2s256: String,
}

impl TargetLoadPlan {
    fn build(inputs: &TargetLoadInputs) -> Result<Self, TypedWorkerTargetLoadError> {
        inputs.validate()?;
        for nonce in 0..MAX_LAYOUT_PLAN_ATTEMPTS {
            let layout_seed = derive_digest(inputs, b"layout-seed", nonce);
            let layout = build_target_layout(inputs.worker_shape, layout_seed)?;
            if let Some(plan) = Self::try_build_with_layout(inputs, &layout, layout_seed)? {
                return Ok(plan);
            }
        }
        Err(TypedWorkerTargetLoadError::InputRejected)
    }

    fn try_build_with_layout(
        inputs: &TargetLoadInputs,
        layout: &FixedProbeLayout<DIRECTORY_PROBES, EVENT_PROBES>,
        layout_seed: [u8; 32],
    ) -> Result<Option<Self>, TypedWorkerTargetLoadError> {
        let shape = inputs.worker_shape;
        let warm_directory_target = shape
            .directory_admission_limit
            .checked_sub(RESERVED_DIRECTORY_SLOTS)
            .ok_or(TypedWorkerTargetLoadError::InputRejected)?;
        let warm_event_target = shape
            .event_admission_limit
            .checked_sub(RESERVED_EVENT_SLOTS)
            .ok_or(TypedWorkerTargetLoadError::InputRejected)?;
        let mut state = PlanState::new(shape)?;
        let mut candidate = 0_u64;
        let mut warmup = Vec::with_capacity(
            usize::try_from(warm_event_target)
                .map_err(|_| TypedWorkerTargetLoadError::InputRejected)?,
        );
        let mut warm_addresses = Vec::with_capacity(
            usize::try_from(warm_directory_target)
                .map_err(|_| TypedWorkerTargetLoadError::InputRejected)?,
        );

        for _ in 0..warm_directory_target {
            let Some(append) =
                state.select_new_address(layout, inputs, &mut candidate, CollisionPhase::Warmup)?
            else {
                return Ok(None);
            };
            warm_addresses.push(append.address_index);
            warmup.push(append);
        }

        let hot_count = usize::try_from(HOT_ADDRESSES)
            .map_err(|_| TypedWorkerTargetLoadError::InputRejected)?;
        let Some(hot_addresses) = warm_addresses.get(..hot_count) else {
            return Ok(None);
        };
        let Some(cold_read_addresses) = warm_addresses.get(hot_count..) else {
            return Ok(None);
        };
        if cold_read_addresses.is_empty() {
            return Ok(None);
        }

        while state.event_occupied < warm_event_target {
            let before = state.event_occupied;
            for address_index in cold_read_addresses {
                if state.event_occupied == warm_event_target {
                    break;
                }
                if let Some(append) =
                    state.append_existing(layout, *address_index, CollisionPhase::Warmup)?
                {
                    warmup.push(append);
                }
            }
            if state.event_occupied == before {
                return Ok(None);
            }
        }

        let mut tokens = plan_tokens()?;
        shuffle_tokens(inputs, &mut tokens);
        let mut measured = Vec::with_capacity(tokens.len());
        for token in tokens {
            let command = match token {
                PlanToken::HotRead(sequence) => {
                    let index = selection_index(inputs, b"hot-read", sequence, hot_addresses.len());
                    let Some(address_index) = hot_addresses.get(index).copied() else {
                        return Ok(None);
                    };
                    PlannedCommand::HotRead { address_index }
                }
                PlanToken::ColdRead(sequence) => {
                    let index =
                        selection_index(inputs, b"cold-read", sequence, cold_read_addresses.len());
                    let Some(address_index) = cold_read_addresses.get(index).copied() else {
                        return Ok(None);
                    };
                    PlannedCommand::ColdRead { address_index }
                }
                PlanToken::HotAppend(sequence) => {
                    let index = usize::try_from(sequence % HOT_ADDRESSES)
                        .map_err(|_| TypedWorkerTargetLoadError::InputRejected)?;
                    let Some(address_index) = hot_addresses.get(index).copied() else {
                        return Ok(None);
                    };
                    let Some(append) =
                        state.append_existing(layout, address_index, CollisionPhase::Measured)?
                    else {
                        return Ok(None);
                    };
                    PlannedCommand::HotAppend(append)
                }
                PlanToken::ColdAppend(_sequence) => {
                    let Some(append) = state.select_new_address(
                        layout,
                        inputs,
                        &mut candidate,
                        CollisionPhase::Measured,
                    )?
                    else {
                        return Ok(None);
                    };
                    PlannedCommand::ColdAppend(append)
                }
            };
            measured.push(command);
        }

        if state.directory_occupied != shape.directory_admission_limit
            || state.event_occupied != shape.event_admission_limit
            || state.collisions.measured_directory_occupied_probes
                < MIN_MEASURED_DIRECTORY_PROBE_COLLISIONS
            || state.collisions.measured_event_occupied_probes < MIN_MEASURED_EVENT_PROBE_COLLISIONS
        {
            return Ok(None);
        }

        let total_commands = warm_event_target
            .checked_add(MEASURED_COMMANDS)
            .ok_or(TypedWorkerTargetLoadError::InputRejected)?;
        let summary = TargetLoadWorkloadSummary {
            warmup_addresses: warm_directory_target,
            warmup_events: warm_event_target,
            measured_reads: WORKLOAD_SHAPE.measured_reads,
            measured_unique_appends: WORKLOAD_SHAPE.measured_unique_appends,
            measured_hot_reads: MEASURED_HOT_READS,
            measured_cold_reads: MEASURED_COLD_READS,
            measured_hot_appends: MEASURED_HOT_APPENDS,
            measured_cold_appends: MEASURED_COLD_APPENDS,
            final_directory_occupied: state.directory_occupied,
            final_event_occupied: state.event_occupied,
            total_commands,
            correctness_passed: true,
        };
        let schedule_blake2s256 = schedule_digest(inputs, &warmup, &measured);
        let mut reference = ReferenceModel::default();
        for append in &warmup {
            reference.append(inputs, *append)?;
        }
        for command in &measured {
            if let PlannedCommand::HotAppend(append) | PlannedCommand::ColdAppend(append) = command
            {
                reference.append(inputs, *append)?;
            }
        }
        let final_state_blake2s256 = reference.digest();

        Ok(Some(Self {
            layout_seed,
            warmup,
            measured,
            summary,
            collisions: state.collisions,
            schedule_blake2s256,
            final_state_blake2s256,
        }))
    }
}

#[derive(Clone, Copy)]
struct PlannedAddressState {
    address: StandardAddress,
    directory_index: usize,
    next_ordinal: u64,
}

struct PlanState {
    shape: TargetLoadWorkerShape,
    directory_slots: Vec<bool>,
    event_slots: Vec<bool>,
    addresses: BTreeMap<u64, PlannedAddressState>,
    directory_occupied: u64,
    event_occupied: u64,
    collisions: TargetLoadLogicalProbeCollisions,
}

impl PlanState {
    fn new(shape: TargetLoadWorkerShape) -> Result<Self, TypedWorkerTargetLoadError> {
        Ok(Self {
            shape,
            directory_slots: vec![
                false;
                usize::try_from(shape.directory_capacity)
                    .map_err(|_| TypedWorkerTargetLoadError::InputRejected)?
            ],
            event_slots: vec![
                false;
                usize::try_from(shape.event_capacity)
                    .map_err(|_| TypedWorkerTargetLoadError::InputRejected)?
            ],
            addresses: BTreeMap::new(),
            directory_occupied: 0,
            event_occupied: 0,
            collisions: TargetLoadLogicalProbeCollisions::ZERO,
        })
    }

    fn select_new_address(
        &mut self,
        layout: &FixedProbeLayout<DIRECTORY_PROBES, EVENT_PROBES>,
        inputs: &TargetLoadInputs,
        candidate: &mut u64,
        phase: CollisionPhase,
    ) -> Result<Option<PlannedAppend>, TypedWorkerTargetLoadError> {
        while *candidate < MAX_ADDRESS_CANDIDATES {
            let address_index = *candidate;
            *candidate = candidate
                .checked_add(1)
                .ok_or(TypedWorkerTargetLoadError::InputRejected)?;
            let address = synthetic_address(inputs, address_index);
            let directory_indices = layout
                .qualification_directory_probe_indices(address)
                .map_err(|_| TypedWorkerTargetLoadError::ConstructionFailed)?;
            let Some(directory) = inspect_reservation(&self.directory_slots, directory_indices)
            else {
                continue;
            };
            let event_indices = layout
                .qualification_event_probe_indices(address, directory.index, 0)
                .map_err(|_| TypedWorkerTargetLoadError::ConstructionFailed)?;
            let Some(event) = inspect_reservation(&self.event_slots, event_indices) else {
                continue;
            };
            commit_reservation(&mut self.directory_slots, directory.index)?;
            commit_reservation(&mut self.event_slots, event.index)?;
            self.directory_occupied = self
                .directory_occupied
                .checked_add(1)
                .ok_or(TypedWorkerTargetLoadError::InputRejected)?;
            self.event_occupied = self
                .event_occupied
                .checked_add(1)
                .ok_or(TypedWorkerTargetLoadError::InputRejected)?;
            self.record_collisions(phase, directory.occupied_probes, event.occupied_probes)?;
            self.addresses.insert(
                address_index,
                PlannedAddressState {
                    address,
                    directory_index: directory.index,
                    next_ordinal: 1,
                },
            );
            return Ok(Some(PlannedAppend {
                address_index,
                ordinal: 0,
            }));
        }
        Ok(None)
    }

    fn append_existing(
        &mut self,
        layout: &FixedProbeLayout<DIRECTORY_PROBES, EVENT_PROBES>,
        address_index: u64,
        phase: CollisionPhase,
    ) -> Result<Option<PlannedAppend>, TypedWorkerTargetLoadError> {
        let Some(address_state) = self.addresses.get(&address_index).copied() else {
            return Err(TypedWorkerTargetLoadError::InputRejected);
        };
        if address_state.next_ordinal >= self.shape.max_events_per_address {
            return Ok(None);
        }
        let indices = layout
            .qualification_event_probe_indices(
                address_state.address,
                address_state.directory_index,
                address_state.next_ordinal,
            )
            .map_err(|_| TypedWorkerTargetLoadError::ConstructionFailed)?;
        let Some(reservation) = inspect_reservation(&self.event_slots, indices) else {
            return Ok(None);
        };
        commit_reservation(&mut self.event_slots, reservation.index)?;
        self.event_occupied = self
            .event_occupied
            .checked_add(1)
            .ok_or(TypedWorkerTargetLoadError::InputRejected)?;
        self.record_collisions(phase, 0, reservation.occupied_probes)?;
        let append = PlannedAppend {
            address_index,
            ordinal: address_state.next_ordinal,
        };
        let Some(address_state) = self.addresses.get_mut(&address_index) else {
            return Err(TypedWorkerTargetLoadError::InputRejected);
        };
        address_state.next_ordinal = address_state
            .next_ordinal
            .checked_add(1)
            .ok_or(TypedWorkerTargetLoadError::InputRejected)?;
        Ok(Some(append))
    }

    fn record_collisions(
        &mut self,
        phase: CollisionPhase,
        directory: u64,
        event: u64,
    ) -> Result<(), TypedWorkerTargetLoadError> {
        let (directory_total, event_total) = match phase {
            CollisionPhase::Warmup => (
                &mut self.collisions.warmup_directory_occupied_probes,
                &mut self.collisions.warmup_event_occupied_probes,
            ),
            CollisionPhase::Measured => (
                &mut self.collisions.measured_directory_occupied_probes,
                &mut self.collisions.measured_event_occupied_probes,
            ),
        };
        *directory_total = directory_total
            .checked_add(directory)
            .ok_or(TypedWorkerTargetLoadError::InputRejected)?;
        *event_total = event_total
            .checked_add(event)
            .ok_or(TypedWorkerTargetLoadError::InputRejected)?;
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum CollisionPhase {
    Warmup,
    Measured,
}

#[derive(Clone, Copy)]
struct Reservation {
    index: usize,
    occupied_probes: u64,
}

fn inspect_reservation<const PROBES: usize>(
    slots: &[bool],
    indices: [usize; PROBES],
) -> Option<Reservation> {
    let mut first_vacant = None;
    let mut occupied_probes = 0_u64;
    for index in indices {
        match slots.get(index).copied() {
            Some(true) => occupied_probes = occupied_probes.checked_add(1)?,
            Some(false) if first_vacant.is_none() => first_vacant = Some(index),
            Some(false) => {}
            None => return None,
        }
    }
    first_vacant.map(|index| Reservation {
        index,
        occupied_probes,
    })
}

fn commit_reservation(slots: &mut [bool], index: usize) -> Result<(), TypedWorkerTargetLoadError> {
    let Some(slot) = slots.get_mut(index) else {
        return Err(TypedWorkerTargetLoadError::ConstructionFailed);
    };
    if *slot {
        return Err(TypedWorkerTargetLoadError::ConstructionFailed);
    }
    *slot = true;
    Ok(())
}

fn plan_tokens() -> Result<Vec<PlanToken>, TypedWorkerTargetLoadError> {
    let capacity = usize::try_from(MEASURED_COMMANDS)
        .map_err(|_| TypedWorkerTargetLoadError::InputRejected)?;
    let mut tokens = Vec::with_capacity(capacity);
    tokens.extend((0..MEASURED_HOT_READS).map(PlanToken::HotRead));
    tokens.extend((0..MEASURED_COLD_READS).map(PlanToken::ColdRead));
    tokens.extend((0..MEASURED_HOT_APPENDS).map(PlanToken::HotAppend));
    tokens.extend((0..MEASURED_COLD_APPENDS).map(PlanToken::ColdAppend));
    if tokens.len() != capacity {
        return Err(TypedWorkerTargetLoadError::InputRejected);
    }
    Ok(tokens)
}

fn shuffle_tokens(inputs: &TargetLoadInputs, tokens: &mut [PlanToken]) {
    for index in (1..tokens.len()).rev() {
        let digest = derive_digest(inputs, b"schedule-shuffle", index as u64);
        let mut word = [0; 8];
        word.copy_from_slice(&digest[..8]);
        let target = (u64::from_le_bytes(word) % (index as u64 + 1)) as usize;
        tokens.swap(index, target);
    }
}

fn selection_index(inputs: &TargetLoadInputs, label: &[u8], sequence: u64, len: usize) -> usize {
    let digest = derive_digest(inputs, label, sequence);
    let mut word = [0; 8];
    word.copy_from_slice(&digest[..8]);
    (u64::from_le_bytes(word) % len as u64) as usize
}

fn derive_digest(inputs: &TargetLoadInputs, label: &[u8], counter: u64) -> [u8; 32] {
    let mut hasher = Blake2s256::new();
    Digest::update(&mut hasher, DERIVATION_DOMAIN);
    Digest::update(
        &mut hasher,
        inputs.sizing_input.measurement_blake2s256.as_bytes(),
    );
    Digest::update(
        &mut hasher,
        inputs.sizing_input.qualification_blake2s256.as_bytes(),
    );
    update_shape_digest(&mut hasher, inputs.worker_shape);
    Digest::update(&mut hasher, label);
    Digest::update(&mut hasher, counter.to_le_bytes());
    let digest = Digest::finalize(hasher);
    let mut bytes = [0; 32];
    bytes.copy_from_slice(&digest);
    bytes
}

fn update_shape_digest(hasher: &mut Blake2s256, shape: TargetLoadWorkerShape) {
    for value in [
        shape.directory_probes,
        shape.event_probes,
        shape.directory_capacity,
        shape.directory_admission_limit,
        shape.event_capacity,
        shape.event_admission_limit,
        shape.max_events_per_address,
        shape.queue_capacity,
    ] {
        Digest::update(hasher, value.to_le_bytes());
    }
}

fn synthetic_address(inputs: &TargetLoadInputs, address_index: u64) -> StandardAddress {
    let digest = derive_digest(inputs, b"synthetic-address", address_index);
    let mut hash = [0; 20];
    hash.copy_from_slice(&digest[..20]);
    let kind = if digest[20].is_multiple_of(2) {
        StandardScriptKind::PayToPublicKeyHash
    } else {
        StandardScriptKind::PayToScriptHash
    };
    StandardAddress::new(kind, hash)
}

fn synthetic_event(
    inputs: &TargetLoadInputs,
    append: PlannedAppend,
) -> Result<UtxoEvent, TypedWorkerTargetLoadError> {
    let address_digest = derive_digest(inputs, b"synthetic-address", append.address_index);
    let mut script_hash = [0; 20];
    script_hash.copy_from_slice(&address_digest[..20]);
    let script_class = if address_digest[20].is_multiple_of(2) {
        UtxoScriptClass::PayToPublicKeyHash
    } else {
        UtxoScriptClass::PayToScriptHash
    };
    let event_counter = append
        .address_index
        .checked_mul(inputs.worker_shape.max_events_per_address)
        .and_then(|value| value.checked_add(append.ordinal))
        .ok_or(TypedWorkerTargetLoadError::InputRejected)?;
    let txid = derive_digest(inputs, b"synthetic-event", event_counter);
    let output_index =
        u32::try_from(append.ordinal).map_err(|_| TypedWorkerTargetLoadError::InputRejected)?;
    let value_zat = 10_000_u64
        .checked_add(event_counter)
        .ok_or(TypedWorkerTargetLoadError::InputRejected)?;
    let height_offset = u32::try_from(event_counter % 100_000_000)
        .map_err(|_| TypedWorkerTargetLoadError::InputRejected)?;
    let height = 500_u32
        .checked_add(height_offset)
        .ok_or(TypedWorkerTargetLoadError::InputRejected)?;
    Ok(UtxoEvent::created(
        txid,
        output_index,
        value_zat,
        height,
        script_class,
        script_hash,
    ))
}

fn build_target_layout(
    shape: TargetLoadWorkerShape,
    seed: [u8; 32],
) -> Result<FixedProbeLayout<DIRECTORY_PROBES, EVENT_PROBES>, TypedWorkerTargetLoadError> {
    FixedProbeLayout::new(
        LayoutIdentity::new(
            LayoutNetwork::Mainnet,
            LAYOUT_SCHEMA_VERSION,
            LAYOUT_KEY_EPOCH,
            LAYOUT_GENERATION,
            seed,
        )
        .map_err(|_| TypedWorkerTargetLoadError::ConstructionFailed)?,
        DirectoryTableConfiguration::<DIRECTORY_PROBES>::new(
            shape.directory_capacity,
            shape.directory_admission_limit,
        )
        .map_err(|_| TypedWorkerTargetLoadError::ConstructionFailed)?,
        EventTableConfiguration::<EVENT_PROBES>::new(
            shape.event_capacity,
            shape.event_admission_limit,
        )
        .map_err(|_| TypedWorkerTargetLoadError::ConstructionFailed)?,
        shape.max_events_per_address,
    )
    .map_err(|_| TypedWorkerTargetLoadError::ConstructionFailed)
}

fn schedule_digest(
    inputs: &TargetLoadInputs,
    warmup: &[PlannedAppend],
    measured: &[PlannedCommand],
) -> String {
    let mut hasher = Blake2s256::new();
    Digest::update(&mut hasher, b"zaino-oram-target-load-schedule-v1");
    update_shape_digest(&mut hasher, inputs.worker_shape);
    for (index, append) in warmup.iter().enumerate() {
        update_schedule_digest(&mut hasher, index as u64, 1, *append);
    }
    let offset = warmup.len() as u64;
    for (index, command) in measured.iter().enumerate() {
        let (tag, append) = match *command {
            PlannedCommand::HotRead { address_index } => (
                2,
                PlannedAppend {
                    address_index,
                    ordinal: 0,
                },
            ),
            PlannedCommand::ColdRead { address_index } => (
                3,
                PlannedAppend {
                    address_index,
                    ordinal: 0,
                },
            ),
            PlannedCommand::HotAppend(append) => (4, append),
            PlannedCommand::ColdAppend(append) => (5, append),
        };
        update_schedule_digest(&mut hasher, offset + index as u64, tag, append);
    }
    digest_hex(Digest::finalize(hasher).as_slice())
}

fn update_schedule_digest(hasher: &mut Blake2s256, index: u64, tag: u8, append: PlannedAppend) {
    Digest::update(hasher, index.to_le_bytes());
    Digest::update(hasher, [tag]);
    Digest::update(hasher, append.address_index.to_le_bytes());
    Digest::update(hasher, append.ordinal.to_le_bytes());
}

#[derive(Default)]
struct ReferenceModel {
    histories: BTreeMap<u64, Vec<(u64, UtxoEvent)>>,
}

impl ReferenceModel {
    fn append(
        &mut self,
        inputs: &TargetLoadInputs,
        append: PlannedAppend,
    ) -> Result<UtxoEvent, TypedWorkerTargetLoadError> {
        let history = self.histories.entry(append.address_index).or_default();
        if u64::try_from(history.len()).map_err(|_| TypedWorkerTargetLoadError::InputRejected)?
            != append.ordinal
        {
            return Err(TypedWorkerTargetLoadError::InputRejected);
        }
        let event = synthetic_event(inputs, append)?;
        history.push((append.ordinal, event));
        Ok(event)
    }

    fn expected_history(
        &self,
        address_index: u64,
        max_events_per_address: u64,
    ) -> Result<Vec<Option<UtxoEvent>>, TypedWorkerTargetLoadError> {
        let mut expected = vec![
            None;
            usize::try_from(max_events_per_address)
                .map_err(|_| TypedWorkerTargetLoadError::InputRejected)?
        ];
        if let Some(history) = self.histories.get(&address_index) {
            for (slot, (_, event)) in history.iter().copied().enumerate() {
                let Some(destination) = expected.get_mut(slot) else {
                    return Err(TypedWorkerTargetLoadError::CorrectnessMismatch);
                };
                *destination = Some(event);
            }
        }
        Ok(expected)
    }

    fn digest(&self) -> String {
        let mut hasher = Blake2s256::new();
        Digest::update(&mut hasher, b"zaino-oram-target-load-final-state-v1");
        for (address_index, history) in &self.histories {
            Digest::update(&mut hasher, address_index.to_le_bytes());
            Digest::update(&mut hasher, (history.len() as u64).to_le_bytes());
            for (ordinal, event) in history {
                Digest::update(&mut hasher, ordinal.to_le_bytes());
                Digest::update(&mut hasher, event.value_zat().to_le_bytes());
                Digest::update(&mut hasher, event.script_hash());
            }
        }
        digest_hex(Digest::finalize(hasher).as_slice())
    }
}

/// Runs one fixed sizing-bound target-load profile against the real typed backend.
///
/// The caller must first validate `sizing` against its source measurement. The
/// `zainod-oram` artifact runner performs that validation and rebinds publication
/// to the loaded capture and sizing artifacts.
pub fn run_typed_worker_target_load(
    profile: TypedWorkerTargetLoadProfile,
    sizing: &MainnetSizingQualification,
    measurement_blake2s256: &str,
    qualification_blake2s256: &str,
) -> Result<TypedWorkerTargetLoadReport, TypedWorkerTargetLoadError> {
    match profile {
        TypedWorkerTargetLoadProfile::BuilderFoundationV1 => {
            run_builder_foundation_v1(sizing, measurement_blake2s256, qualification_blake2s256)
        }
    }
}

fn run_builder_foundation_v1(
    sizing: &MainnetSizingQualification,
    measurement_blake2s256: &str,
    qualification_blake2s256: &str,
) -> Result<TypedWorkerTargetLoadReport, TypedWorkerTargetLoadError> {
    ensure_typed_backend_available()?;
    let inputs = TargetLoadInputs::from_qualification(
        sizing,
        measurement_blake2s256,
        qualification_blake2s256,
    )?;
    let plan = TargetLoadPlan::build(&inputs)?;
    let baseline =
        sample_process_memory().map_err(|_| TypedWorkerTargetLoadError::MeasurementFailed)?;
    let layout = build_target_layout(inputs.worker_shape, plan.layout_seed)?;
    let queue_capacity = AtomicQueueCapacity::try_new(
        usize::try_from(inputs.worker_shape.queue_capacity)
            .map_err(|_| TypedWorkerTargetLoadError::ConstructionFailed)?,
    )
    .map_err(|_| TypedWorkerTargetLoadError::ConstructionFailed)?;
    let worker = spawn_typed_rostl_worker(layout, queue_capacity).map_err(map_worker_build)?;
    execute_with_worker(worker, &inputs, &plan, baseline, || {
        sample_process_memory().map_err(|_| TypedWorkerTargetLoadError::MeasurementFailed)
    })
}

#[cfg(all(
    feature = "rostl-experimental",
    target_os = "linux",
    target_arch = "x86_64"
))]
const fn ensure_typed_backend_available() -> Result<(), TypedWorkerTargetLoadError> {
    Ok(())
}

#[cfg(not(all(
    feature = "rostl-experimental",
    target_os = "linux",
    target_arch = "x86_64"
)))]
const fn ensure_typed_backend_available() -> Result<(), TypedWorkerTargetLoadError> {
    Err(TypedWorkerTargetLoadError::TypedBackendUnavailable)
}

const fn map_worker_build(error: AtomicWorkerBuildError) -> TypedWorkerTargetLoadError {
    match error {
        #[cfg(not(all(
            feature = "rostl-experimental",
            target_os = "linux",
            target_arch = "x86_64"
        )))]
        AtomicWorkerBuildError::TypedBackendUnavailable => {
            TypedWorkerTargetLoadError::TypedBackendUnavailable
        }
        AtomicWorkerBuildError::ConstructionFailed => {
            TypedWorkerTargetLoadError::ConstructionFailed
        }
    }
}

struct ExecutionEvidence {
    timing: TargetLoadTimingReport,
    rss: TargetLoadRssReport,
    final_state_blake2s256: String,
}

fn execute_with_worker<F>(
    worker: AtomicWorker,
    inputs: &TargetLoadInputs,
    plan: &TargetLoadPlan,
    baseline: ProcessMemorySample,
    mut sample_memory: F,
) -> Result<TypedWorkerTargetLoadReport, TypedWorkerTargetLoadError>
where
    F: FnMut() -> Result<ProcessMemorySample, TypedWorkerTargetLoadError>,
{
    let execution = (|| {
        let post_spawn = sample_memory()?;
        let mut reference = ReferenceModel::default();
        run_warmup(&worker, inputs, plan, &mut reference)?;
        let post_warmup = sample_memory()?;
        let timing = run_measured(&worker, inputs, plan, &mut reference)?;
        let post_workload = sample_memory()?;
        let rss = TargetLoadRssReport {
            sampling_source: "proc-status-vmrss-vmhwm".to_owned(),
            measurement_scope: "whole-process-including-driver-and-runtime".to_owned(),
            baseline_rss_bytes: baseline.rss_bytes(),
            post_spawn_rss_bytes: post_spawn.rss_bytes(),
            post_warmup_rss_bytes: post_warmup.rss_bytes(),
            post_workload_rss_bytes: post_workload.rss_bytes(),
            process_lifetime_hwm_bytes: post_workload.hwm_bytes(),
        };
        if !rss.validate() {
            return Err(TypedWorkerTargetLoadError::MeasurementFailed);
        }
        Ok(ExecutionEvidence {
            timing,
            rss,
            final_state_blake2s256: reference.digest(),
        })
    })();

    let shutdown = worker.qualification_shutdown();
    let evidence = match execution {
        Ok(evidence) => evidence,
        Err(primary) => {
            let _ = shutdown;
            return Err(primary);
        }
    };
    let snapshot = shutdown.map_err(|_| TypedWorkerTargetLoadError::ShutdownFailed)?;
    let worker_trace = TargetLoadWorkerTrace::try_from_snapshot(snapshot)?;
    if worker_trace != TargetLoadWorkerTrace::expected(plan.summary.total_commands) {
        return Err(TypedWorkerTargetLoadError::ShutdownFailed);
    }
    if evidence.final_state_blake2s256 != plan.final_state_blake2s256 {
        return Err(TypedWorkerTargetLoadError::CorrectnessMismatch);
    }
    let report = TypedWorkerTargetLoadReport {
        scenario: SCENARIO.to_owned(),
        profile: TypedWorkerTargetLoadProfile::BuilderFoundationV1,
        backend: BACKEND.to_owned(),
        sizing_input: inputs.sizing_input.clone(),
        worker_shape: inputs.worker_shape,
        builder_envelope: BUILDER_ENVELOPE,
        workload_shape: WORKLOAD_SHAPE,
        workload_summary: plan.summary,
        logical_probe_collisions: plan.collisions,
        schedule_blake2s256: plan.schedule_blake2s256.clone(),
        final_state_blake2s256: plan.final_state_blake2s256.clone(),
        timing: evidence.timing,
        rss: evidence.rss,
        worker_trace,
        unavailable: UNAVAILABLE_MARKERS,
        evidence_scope: EVIDENCE_SCOPE,
    };
    report.validate()?;
    Ok(report)
}

fn run_warmup(
    worker: &AtomicWorker,
    inputs: &TargetLoadInputs,
    plan: &TargetLoadPlan,
    reference: &mut ReferenceModel,
) -> Result<(), TypedWorkerTargetLoadError> {
    for append in &plan.warmup {
        run_append(worker, inputs, reference, *append)?;
    }
    Ok(())
}

fn run_measured(
    worker: &AtomicWorker,
    inputs: &TargetLoadInputs,
    plan: &TargetLoadPlan,
    reference: &mut ReferenceModel,
) -> Result<TargetLoadTimingReport, TypedWorkerTargetLoadError> {
    let mut latencies = LatencyCollector::default();
    let phase_started = Instant::now();
    for command in &plan.measured {
        match *command {
            PlannedCommand::HotRead { address_index }
            | PlannedCommand::ColdRead { address_index } => {
                let address = synthetic_address(inputs, address_index);
                let started = Instant::now();
                let actual = worker
                    .qualification_read_history_typed(address)
                    .map_err(|_| TypedWorkerTargetLoadError::CommandFailed)?;
                let elapsed = started.elapsed();
                latencies.push_read(elapsed)?;
                verify_history(
                    actual,
                    reference.expected_history(
                        address_index,
                        inputs.worker_shape.max_events_per_address,
                    )?,
                )?;
            }
            PlannedCommand::HotAppend(append) | PlannedCommand::ColdAppend(append) => {
                let event = synthetic_event(inputs, append)?;
                let address = synthetic_address(inputs, append.address_index);
                let started = Instant::now();
                let actual = worker
                    .qualification_append_typed(address, event)
                    .map_err(|_| TypedWorkerTargetLoadError::CommandFailed)?;
                let elapsed = started.elapsed();
                latencies.push_append(elapsed)?;
                if actual.disposition != AtomicQualificationAppendDisposition::Inserted {
                    return Err(TypedWorkerTargetLoadError::CorrectnessMismatch);
                }
                let expected_event = reference.append(inputs, append)?;
                if expected_event != event {
                    return Err(TypedWorkerTargetLoadError::CorrectnessMismatch);
                }
                verify_history(
                    actual.history,
                    reference.expected_history(
                        append.address_index,
                        inputs.worker_shape.max_events_per_address,
                    )?,
                )?;
            }
        }
    }
    latencies.finish(phase_started.elapsed())
}

fn run_append(
    worker: &AtomicWorker,
    inputs: &TargetLoadInputs,
    reference: &mut ReferenceModel,
    append: PlannedAppend,
) -> Result<(), TypedWorkerTargetLoadError> {
    let event = synthetic_event(inputs, append)?;
    let actual = worker
        .qualification_append_typed(synthetic_address(inputs, append.address_index), event)
        .map_err(|_| TypedWorkerTargetLoadError::CommandFailed)?;
    if actual.disposition != AtomicQualificationAppendDisposition::Inserted {
        return Err(TypedWorkerTargetLoadError::CorrectnessMismatch);
    }
    let expected_event = reference.append(inputs, append)?;
    if expected_event != event {
        return Err(TypedWorkerTargetLoadError::CorrectnessMismatch);
    }
    verify_history(
        actual.history,
        reference.expected_history(
            append.address_index,
            inputs.worker_shape.max_events_per_address,
        )?,
    )
}

fn verify_history(
    actual: Vec<Option<UtxoEvent>>,
    expected: Vec<Option<UtxoEvent>>,
) -> Result<(), TypedWorkerTargetLoadError> {
    if actual != expected {
        return Err(TypedWorkerTargetLoadError::CorrectnessMismatch);
    }
    Ok(())
}

#[derive(Default)]
struct LatencyCollector {
    all: Vec<u64>,
    reads: Vec<u64>,
    appends: Vec<u64>,
}

impl LatencyCollector {
    fn push_read(&mut self, elapsed: Duration) -> Result<(), TypedWorkerTargetLoadError> {
        let elapsed = duration_ns(elapsed)?;
        self.all.push(elapsed);
        self.reads.push(elapsed);
        Ok(())
    }

    fn push_append(&mut self, elapsed: Duration) -> Result<(), TypedWorkerTargetLoadError> {
        let elapsed = duration_ns(elapsed)?;
        self.all.push(elapsed);
        self.appends.push(elapsed);
        Ok(())
    }

    fn finish(
        self,
        measured_phase_wall: Duration,
    ) -> Result<TargetLoadTimingReport, TypedWorkerTargetLoadError> {
        let measured_phase_wall_ns = duration_ns(measured_phase_wall)?;
        if measured_phase_wall_ns == 0 {
            return Err(TypedWorkerTargetLoadError::MeasurementFailed);
        }
        let all_worker_call_latency = summarize_latencies(self.all)?;
        let read_worker_call_latency = summarize_latencies(self.reads)?;
        let append_worker_call_latency = summarize_latencies(self.appends)?;
        let report = TargetLoadTimingReport {
            measured_phase_wall_ns,
            cumulative_worker_call_wait_ns: all_worker_call_latency.total_elapsed_ns,
            percentile_method: TargetLoadPercentileMethod::NearestRankV1,
            all_worker_call_latency,
            read_worker_call_latency,
            append_worker_call_latency,
            mixed_phase_commands_per_second_floor: throughput_floor(
                MEASURED_COMMANDS,
                measured_phase_wall_ns,
            )
            .ok_or(TypedWorkerTargetLoadError::MeasurementFailed)?,
            mixed_phase_read_completions_per_second_floor: throughput_floor(
                WORKLOAD_SHAPE.measured_reads,
                measured_phase_wall_ns,
            )
            .ok_or(TypedWorkerTargetLoadError::MeasurementFailed)?,
            mixed_phase_append_completions_per_second_floor: throughput_floor(
                WORKLOAD_SHAPE.measured_unique_appends,
                measured_phase_wall_ns,
            )
            .ok_or(TypedWorkerTargetLoadError::MeasurementFailed)?,
        };
        if !report.validate() {
            return Err(TypedWorkerTargetLoadError::MeasurementFailed);
        }
        Ok(report)
    }
}

fn duration_ns(duration: Duration) -> Result<u64, TypedWorkerTargetLoadError> {
    u64::try_from(duration.as_nanos()).map_err(|_| TypedWorkerTargetLoadError::MeasurementFailed)
}

fn summarize_latencies(
    mut samples: Vec<u64>,
) -> Result<TargetLoadLatencySummary, TypedWorkerTargetLoadError> {
    if samples.is_empty() {
        return Err(TypedWorkerTargetLoadError::MeasurementFailed);
    }
    samples.sort_unstable();
    let count =
        u64::try_from(samples.len()).map_err(|_| TypedWorkerTargetLoadError::MeasurementFailed)?;
    let total_elapsed_ns = samples.iter().try_fold(0_u64, |total, sample| {
        total
            .checked_add(*sample)
            .ok_or(TypedWorkerTargetLoadError::MeasurementFailed)
    })?;
    let Some(min_ns) = samples.first().copied() else {
        return Err(TypedWorkerTargetLoadError::MeasurementFailed);
    };
    let Some(max_ns) = samples.last().copied() else {
        return Err(TypedWorkerTargetLoadError::MeasurementFailed);
    };
    let summary = TargetLoadLatencySummary {
        count,
        total_elapsed_ns,
        min_ns,
        p50_ns: percentile(&samples, 50)?,
        p95_ns: percentile(&samples, 95)?,
        p99_ns: percentile(&samples, 99)?,
        max_ns,
    };
    if !summary.validate() {
        return Err(TypedWorkerTargetLoadError::MeasurementFailed);
    }
    Ok(summary)
}

fn percentile(samples: &[u64], percentage: usize) -> Result<u64, TypedWorkerTargetLoadError> {
    let rank = samples
        .len()
        .checked_mul(percentage)
        .and_then(|value| value.checked_add(99))
        .map(|value| value / 100)
        .and_then(|value| value.checked_sub(1))
        .ok_or(TypedWorkerTargetLoadError::MeasurementFailed)?;
    samples
        .get(rank)
        .copied()
        .ok_or(TypedWorkerTargetLoadError::MeasurementFailed)
}

fn throughput_floor(count: u64, wall_ns: u64) -> Option<u64> {
    if wall_ns == 0 {
        return None;
    }
    let rate = u128::from(count)
        .checked_mul(NANOS_PER_SECOND)?
        .checked_div(u128::from(wall_ns))?;
    u64::try_from(rate).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        layout::{spawn_qualification_worker, QualificationMemoryTable},
        records::{PersistentAddressDirectory, PersistentAddressEventPage},
    };

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    fn test_inputs() -> TargetLoadInputs {
        TargetLoadInputs {
            sizing_input: TargetLoadSizingInput {
                measurement_blake2s256: "11".repeat(32),
                qualification_blake2s256: "22".repeat(32),
                checkpoint_height: 0,
                checkpoint_hash: "00040fe8ec8471911baa1db1266ea15dd06b4a8a5c453883c000b031973dce08"
                    .to_owned(),
            },
            worker_shape: TargetLoadWorkerShape {
                directory_probes: DIRECTORY_PROBES_U64,
                event_probes: EVENT_PROBES_U64,
                directory_capacity: 64,
                directory_admission_limit: 48,
                event_capacity: 128,
                event_admission_limit: 96,
                max_events_per_address: 3,
                queue_capacity: QUEUE_CAPACITY,
            },
        }
    }

    fn fake_worker(inputs: &TargetLoadInputs, plan: &TargetLoadPlan) -> TestResult<AtomicWorker> {
        let layout = build_target_layout(inputs.worker_shape, plan.layout_seed)?;
        let directory = QualificationMemoryTable::<PersistentAddressDirectory>::try_new(
            usize::try_from(inputs.worker_shape.directory_capacity)?,
        )
        .map_err(|_| "directory table allocation failed")?;
        let events = QualificationMemoryTable::<PersistentAddressEventPage>::try_new(
            usize::try_from(inputs.worker_shape.event_capacity)?,
        )
        .map_err(|_| "event table allocation failed")?;
        let queue_capacity = AtomicQueueCapacity::try_new(usize::try_from(QUEUE_CAPACITY)?)?;
        Ok(spawn_qualification_worker(
            layout,
            directory,
            events,
            queue_capacity,
        )?)
    }

    fn execute_fake_report() -> TestResult<TypedWorkerTargetLoadReport> {
        let inputs = test_inputs();
        let plan = TargetLoadPlan::build(&inputs)?;
        let worker = fake_worker(&inputs, &plan)?;
        let mut samples = [
            ProcessMemorySample::new(2_000_000, 5_000_000),
            ProcessMemorySample::new(3_000_000, 5_000_000),
            ProcessMemorySample::new(4_000_000, 5_000_000),
        ]
        .into_iter();
        Ok(execute_with_worker(
            worker,
            &inputs,
            &plan,
            ProcessMemorySample::new(1_000_000, 1_000_000),
            || {
                samples
                    .next()
                    .ok_or(TypedWorkerTargetLoadError::MeasurementFailed)
            },
        )?)
    }

    #[test]
    fn plan_is_deterministic_loaded_and_collision_checked() -> TestResult {
        let inputs = test_inputs();
        let first = TargetLoadPlan::build(&inputs)?;
        let second = TargetLoadPlan::build(&inputs)?;

        assert_eq!(first.schedule_blake2s256, second.schedule_blake2s256);
        assert_eq!(first.final_state_blake2s256, second.final_state_blake2s256);
        assert_eq!(first.summary.final_directory_occupied, 48);
        assert_eq!(first.summary.final_event_occupied, 96);
        assert_eq!(first.summary.total_commands, 304);
        assert!(
            first.collisions.measured_directory_occupied_probes
                >= MIN_MEASURED_DIRECTORY_PROBE_COLLISIONS
        );
        assert!(
            first.collisions.measured_event_occupied_probes >= MIN_MEASURED_EVENT_PROBE_COLLISIONS
        );
        Ok(())
    }

    #[test]
    fn builder_envelope_rejects_unbounded_or_underfilled_shapes() {
        let mut inputs = test_inputs();
        inputs.worker_shape.event_capacity = MAX_EVENT_CAPACITY * 2;
        assert_eq!(
            inputs.validate(),
            Err(TypedWorkerTargetLoadError::InputRejected)
        );

        let mut inputs = test_inputs();
        inputs.worker_shape.directory_admission_limit = 32;
        assert_eq!(
            inputs.validate(),
            Err(TypedWorkerTargetLoadError::InputRejected)
        );

        let mut inputs = test_inputs();
        inputs.worker_shape.directory_admission_limit = inputs.worker_shape.directory_capacity;
        assert_eq!(
            inputs.validate(),
            Err(TypedWorkerTargetLoadError::InputRejected)
        );

        let mut inputs = test_inputs();
        inputs.worker_shape.event_admission_limit = inputs.worker_shape.event_capacity;
        assert_eq!(
            inputs.validate(),
            Err(TypedWorkerTargetLoadError::InputRejected)
        );

        let mut inputs = test_inputs();
        inputs.sizing_input.measurement_blake2s256 = "AA".repeat(32);
        assert_eq!(
            inputs.validate(),
            Err(TypedWorkerTargetLoadError::InputRejected)
        );
    }

    #[test]
    fn fake_worker_executes_the_exact_plan_and_validates_report() -> TestResult {
        let report = execute_fake_report()?;

        report.validate()?;
        assert_eq!(report.worker_trace.accepted, 304);
        assert_eq!(report.worker_trace.completed, 304);
        assert!(!report.evidence_scope.queue_contention_measured);
        Ok(())
    }

    #[test]
    fn report_rejects_overstated_evidence() -> TestResult {
        let report = execute_fake_report()?;
        let mut value = serde_json::to_value(report)?;
        value["evidence_scope"]["target_hardware_qualified"] = serde_json::json!(true);
        let report: TypedWorkerTargetLoadReport = serde_json::from_value(value)?;

        assert_eq!(
            report.validate(),
            Err(TypedWorkerTargetLoadError::InvalidReport)
        );
        Ok(())
    }

    #[test]
    fn report_rejects_command_wait_above_sequential_phase_wall() -> TestResult {
        let mut report = execute_fake_report()?;
        report.timing.measured_phase_wall_ns = report
            .timing
            .cumulative_worker_call_wait_ns
            .checked_sub(1)
            .ok_or(TypedWorkerTargetLoadError::MeasurementFailed)?;
        report.timing.mixed_phase_commands_per_second_floor =
            throughput_floor(MEASURED_COMMANDS, report.timing.measured_phase_wall_ns)
                .ok_or(TypedWorkerTargetLoadError::MeasurementFailed)?;
        report.timing.mixed_phase_read_completions_per_second_floor = throughput_floor(
            WORKLOAD_SHAPE.measured_reads,
            report.timing.measured_phase_wall_ns,
        )
        .ok_or(TypedWorkerTargetLoadError::MeasurementFailed)?;
        report
            .timing
            .mixed_phase_append_completions_per_second_floor = throughput_floor(
            WORKLOAD_SHAPE.measured_unique_appends,
            report.timing.measured_phase_wall_ns,
        )
        .ok_or(TypedWorkerTargetLoadError::MeasurementFailed)?;

        assert_eq!(
            report.validate(),
            Err(TypedWorkerTargetLoadError::InvalidReport)
        );
        Ok(())
    }

    #[test]
    fn latency_summary_rejects_total_above_count_times_maximum() {
        let impossible = TargetLoadLatencySummary {
            count: 2,
            total_elapsed_ns: 3,
            min_ns: 1,
            p50_ns: 1,
            p95_ns: 1,
            p99_ns: 1,
            max_ns: 1,
        };
        assert!(!impossible.validate());
    }
}
