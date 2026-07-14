//! Source-bound cold-rebuild measurement over a fresh typed projection owner.

use std::{
    cell::RefCell,
    fmt,
    rc::Rc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use blake2::{Blake2s256, Digest};
use serde::{Deserialize, Serialize};
use zaino_state::IndexedBlock;

use super::{
    OfflineProjectionOwner, ProjectionOwnerBuildError, ProjectionOwnerReadiness,
    ProjectionOwnerShutdownOutcome,
};
use crate::{
    canonical_chain::{CanonicalNetwork, PublicChainCheckpoint},
    checkpoint::{ProjectionCheckpointPublisher, ProjectionPublication},
    layout::{
        DirectoryTableConfiguration, EventTableConfiguration, FixedProbeLayout, LayoutIdentity,
        LayoutNetwork,
    },
    process_memory::{sample_process_memory, ProcessMemorySample},
    projection::{ProjectionCapacities, ProjectionConfig},
    stress_qualification::digest_hex,
    target_load::is_blake2s256_hex,
    zaino_corpus::{MainnetCorpusMeasurement, MainnetCorpusScanner, MainnetSizingQualification},
};

const SCENARIO: &str = "typed-worker-source-bound-cold-rebuild-v1";
const BACKEND: &str = "rostl-circuit-oram-volatile-v1";
const DIRECTORY_PROBES: usize = 4;
const EVENT_PROBES: usize = 4;
const DIRECTORY_PROBES_U64: u64 = DIRECTORY_PROBES as u64;
const EVENT_PROBES_U64: u64 = EVENT_PROBES as u64;
const QUEUE_CAPACITY: u64 = 1;
const SCHEMA_VERSION: u32 = 1;
const KEY_EPOCH: u64 = 1;
const LAYOUT_SEED_DOMAIN: &[u8] = b"zaino-oram/cold-rebuild-layout-seed/v1\0";
const PROJECTION_EPOCH_DOMAIN: &[u8] = b"zaino-oram/cold-rebuild-projection-epoch/v1\0";

/// Fixed source-bound cold-rebuild workload selected by the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TypedWorkerColdRebuildProfile {
    /// Generic Linux x86_64 builder profile with fixed probes and queue depth.
    SourceBoundBuilderV1,
}

impl TypedWorkerColdRebuildProfile {
    const fn as_str(self) -> &'static str {
        match self {
            Self::SourceBoundBuilderV1 => "source-bound-builder-v1",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ColdRebuildSourceBinding {
    measurement_blake2s256: String,
    qualification_blake2s256: String,
    checkpoint_height: u32,
    checkpoint_hash: String,
    expected_blocks: u64,
    measured_outputs: u64,
}

impl ColdRebuildSourceBinding {
    fn validate(&self) -> bool {
        is_blake2s256_hex(&self.measurement_blake2s256)
            && is_blake2s256_hex(&self.qualification_blake2s256)
            && is_blake2s256_hex(&self.checkpoint_hash)
            && self.expected_blocks == u64::from(self.checkpoint_height) + 1
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ColdRebuildWorkerShape {
    directory_probes: u64,
    event_probes: u64,
    directory_capacity: u64,
    directory_admission_limit: u64,
    event_capacity: u64,
    event_admission_limit: u64,
    max_events_per_address: u64,
    queue_capacity: u64,
    max_seen_outputs: u64,
    max_live_outputs: u64,
}

impl ColdRebuildWorkerShape {
    fn validate(self) -> bool {
        self.directory_probes == DIRECTORY_PROBES_U64
            && self.event_probes == EVENT_PROBES_U64
            && self.queue_capacity == QUEUE_CAPACITY
            && self.directory_capacity.is_power_of_two()
            && self.event_capacity.is_power_of_two()
            && self.directory_capacity >= self.directory_probes
            && self.event_capacity >= self.event_probes
            && self.directory_admission_limit > 0
            && self.directory_admission_limit < self.directory_capacity
            && self.event_admission_limit > 0
            && self.event_admission_limit < self.event_capacity
            && self.max_events_per_address > 0
            && self.max_events_per_address <= self.event_admission_limit
            && self.max_seen_outputs > 0
            && self.max_live_outputs > 0
            && self.max_live_outputs <= self.max_seen_outputs
    }
}

#[derive(Clone, PartialEq, Eq)]
struct ColdRebuildInputs {
    source: ColdRebuildSourceBinding,
    worker_shape: ColdRebuildWorkerShape,
    declared_rebuild_budget_ns: u64,
}

impl ColdRebuildInputs {
    fn from_artifacts(
        measurement: &MainnetCorpusMeasurement,
        sizing: &MainnetSizingQualification,
        measurement_blake2s256: &str,
        qualification_blake2s256: &str,
        declared_rebuild_budget: Duration,
    ) -> Result<Self, TypedWorkerColdRebuildError> {
        measurement
            .validate()
            .map_err(|_| TypedWorkerColdRebuildError::InputRejected)?;
        sizing
            .validate_against(measurement)
            .map_err(|_| TypedWorkerColdRebuildError::InputRejected)?;
        if !sizing.captured_corpus_fits_configured_limits() {
            return Err(TypedWorkerColdRebuildError::InputRejected);
        }
        let declared_rebuild_budget_ns = duration_ns(declared_rebuild_budget)?;
        if declared_rebuild_budget_ns == 0 {
            return Err(TypedWorkerColdRebuildError::InputRejected);
        }
        let model = sizing.model();
        let measured_outputs = measurement.output_count();
        let conservative_output_bound = measured_outputs.max(1);
        let inputs = Self {
            source: ColdRebuildSourceBinding {
                measurement_blake2s256: measurement_blake2s256.to_owned(),
                qualification_blake2s256: qualification_blake2s256.to_owned(),
                checkpoint_height: measurement.checkpoint().height(),
                checkpoint_hash: measurement.checkpoint().hash().to_owned(),
                expected_blocks: u64::from(measurement.checkpoint().height()) + 1,
                measured_outputs,
            },
            worker_shape: ColdRebuildWorkerShape {
                directory_probes: DIRECTORY_PROBES_U64,
                event_probes: EVENT_PROBES_U64,
                directory_capacity: model.directory_capacity(),
                directory_admission_limit: model.directory_admission_limit(),
                event_capacity: model.event_capacity(),
                event_admission_limit: model.event_admission_limit(),
                max_events_per_address: model.max_events_per_address(),
                queue_capacity: QUEUE_CAPACITY,
                max_seen_outputs: conservative_output_bound,
                max_live_outputs: conservative_output_bound,
            },
            declared_rebuild_budget_ns,
        };
        if !inputs.source.validate() || !inputs.worker_shape.validate() {
            return Err(TypedWorkerColdRebuildError::InputRejected);
        }
        Ok(inputs)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ColdRebuildTimingReport {
    declared_rebuild_budget_ns: u64,
    construction_ns: u64,
    replay_to_ready_ns: u64,
    finish_call_ns: u64,
    ready_ns: u64,
    shutdown_ns: u64,
    total_lifecycle_ns: u64,
    declared_rebuild_budget_passed: bool,
}

impl ColdRebuildTimingReport {
    fn validate(self) -> bool {
        let Some(pre_ready_accounted) = self.construction_ns.checked_add(self.replay_to_ready_ns)
        else {
            return false;
        };
        let Some(lifecycle_accounted) = self.ready_ns.checked_add(self.shutdown_ns) else {
            return false;
        };
        self.declared_rebuild_budget_ns > 0
            && self.construction_ns > 0
            && self.replay_to_ready_ns > 0
            && self.finish_call_ns > 0
            && self.ready_ns >= pre_ready_accounted
            && self.shutdown_ns > 0
            && self.total_lifecycle_ns >= lifecycle_accounted
            && self.finish_call_ns <= self.replay_to_ready_ns
            && self.declared_rebuild_budget_passed
                == (self.ready_ns <= self.declared_rebuild_budget_ns)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ColdRebuildRssReport {
    baseline_rss_bytes: u64,
    post_spawn_rss_bytes: u64,
    ready_rss_bytes: u64,
    post_shutdown_rss_bytes: u64,
    process_lifetime_hwm_bytes: u64,
}

impl ColdRebuildRssReport {
    fn from_samples(
        baseline: ProcessMemorySample,
        post_spawn: ProcessMemorySample,
        ready: ProcessMemorySample,
        post_shutdown: ProcessMemorySample,
    ) -> Self {
        Self {
            baseline_rss_bytes: baseline.rss_bytes(),
            post_spawn_rss_bytes: post_spawn.rss_bytes(),
            ready_rss_bytes: ready.rss_bytes(),
            post_shutdown_rss_bytes: post_shutdown.rss_bytes(),
            process_lifetime_hwm_bytes: post_shutdown.hwm_bytes(),
        }
    }

    fn validate(self) -> bool {
        let samples = [
            self.baseline_rss_bytes,
            self.post_spawn_rss_bytes,
            self.ready_rss_bytes,
            self.post_shutdown_rss_bytes,
        ];
        samples.iter().all(|sample| *sample > 0)
            && self.process_lifetime_hwm_bytes > 0
            && samples
                .iter()
                .all(|sample| self.process_lifetime_hwm_bytes >= *sample)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ColdRebuildEvidenceScope {
    mainnet_genesis_and_chain_continuity_validated: bool,
    source_measurement_recomputed_and_matched: bool,
    exact_source_checkpoint_reached: bool,
    complete_genesis_forward_replay: bool,
    real_typed_rostl: bool,
    whole_process_rss_measured: bool,
    projection_rebuild_budget_measured: bool,
    source_cache_state_controlled: bool,
    durable_oram_state: bool,
    authenticated_manifest_used: bool,
    external_freshness_witness_used: bool,
    production_key_owner_used: bool,
    full_service_rto_measured: bool,
    target_hardware_qualified: bool,
    physical_trace_measured: bool,
    tdx_qualified: bool,
    execution_attested: bool,
    signed_provenance: bool,
    mainnet_ready: bool,
}

const EVIDENCE_SCOPE: ColdRebuildEvidenceScope = ColdRebuildEvidenceScope {
    mainnet_genesis_and_chain_continuity_validated: true,
    source_measurement_recomputed_and_matched: true,
    exact_source_checkpoint_reached: true,
    complete_genesis_forward_replay: true,
    real_typed_rostl: true,
    whole_process_rss_measured: true,
    projection_rebuild_budget_measured: true,
    source_cache_state_controlled: false,
    durable_oram_state: false,
    authenticated_manifest_used: false,
    external_freshness_witness_used: false,
    production_key_owner_used: false,
    full_service_rto_measured: false,
    target_hardware_qualified: false,
    physical_trace_measured: false,
    tdx_qualified: false,
    execution_attested: false,
    signed_provenance: false,
    mainnet_ready: false,
};

/// Aggregate-only evidence from one source-bound typed-worker cold rebuild.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TypedWorkerColdRebuildReport {
    scenario: String,
    profile: TypedWorkerColdRebuildProfile,
    backend: String,
    source: ColdRebuildSourceBinding,
    worker_shape: ColdRebuildWorkerShape,
    projection_epoch: u64,
    applied_blocks: u64,
    final_checkpoint_height: u32,
    final_checkpoint_hash: String,
    semantic_event_log_root_blake2s256: String,
    timing: ColdRebuildTimingReport,
    rss: ColdRebuildRssReport,
    evidence_scope: ColdRebuildEvidenceScope,
}

impl TypedWorkerColdRebuildReport {
    /// Revalidates all self-contained source, shape, timing, memory, and claim fields.
    pub fn validate(&self) -> Result<(), TypedWorkerColdRebuildError> {
        if self.scenario != SCENARIO
            || self.profile != TypedWorkerColdRebuildProfile::SourceBoundBuilderV1
            || self.backend != BACKEND
            || !self.source.validate()
            || !self.worker_shape.validate()
            || self.worker_shape.max_seen_outputs != self.source.measured_outputs.max(1)
            || self.worker_shape.max_live_outputs != self.source.measured_outputs.max(1)
            || self.projection_epoch == 0
            || self.applied_blocks != self.source.expected_blocks
            || self.final_checkpoint_height != self.source.checkpoint_height
            || self.final_checkpoint_hash != self.source.checkpoint_hash
            || !is_blake2s256_hex(&self.semantic_event_log_root_blake2s256)
            || !self.timing.validate()
            || !self.rss.validate()
            || self.evidence_scope != EVIDENCE_SCOPE
        {
            return Err(TypedWorkerColdRebuildError::InvalidReport);
        }
        Ok(())
    }

    /// Revalidates this report against its exact capture, sizing, lineage, and budget inputs.
    pub fn validate_against(
        &self,
        measurement: &MainnetCorpusMeasurement,
        sizing: &MainnetSizingQualification,
        measurement_blake2s256: &str,
        qualification_blake2s256: &str,
        declared_rebuild_budget: Duration,
    ) -> Result<(), TypedWorkerColdRebuildError> {
        self.validate()?;
        let expected = ColdRebuildInputs::from_artifacts(
            measurement,
            sizing,
            measurement_blake2s256,
            qualification_blake2s256,
            declared_rebuild_budget,
        )?;
        if self.source != expected.source
            || self.worker_shape != expected.worker_shape
            || self.timing.declared_rebuild_budget_ns != expected.declared_rebuild_budget_ns
        {
            return Err(TypedWorkerColdRebuildError::InvalidReport);
        }
        Ok(())
    }

    /// Returns whether allocation through validated readiness met the declared rebuild budget.
    pub const fn declared_rebuild_budget_passed(&self) -> bool {
        self.timing.declared_rebuild_budget_passed
    }
}

impl fmt::Display for TypedWorkerColdRebuildReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "scenario={}", self.scenario)?;
        writeln!(f, "profile={}", self.profile.as_str())?;
        writeln!(f, "backend={}", self.backend)?;
        writeln!(
            f,
            "source=height:{},hash:{},blocks:{},measurement_blake2s256:{},qualification_blake2s256:{}",
            self.source.checkpoint_height,
            self.source.checkpoint_hash,
            self.source.expected_blocks,
            self.source.measurement_blake2s256,
            self.source.qualification_blake2s256,
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
            "result=applied_blocks:{},projection_epoch:{},semantic_event_log_root_blake2s256:{}",
            self.applied_blocks, self.projection_epoch, self.semantic_event_log_root_blake2s256,
        )?;
        writeln!(
            f,
            "timing=declared_rebuild_budget_ns:{},construction_ns:{},replay_to_ready_ns:{},finish_call_ns:{},ready_ns:{},shutdown_ns:{},total_lifecycle_ns:{},passed:{}",
            self.timing.declared_rebuild_budget_ns,
            self.timing.construction_ns,
            self.timing.replay_to_ready_ns,
            self.timing.finish_call_ns,
            self.timing.ready_ns,
            self.timing.shutdown_ns,
            self.timing.total_lifecycle_ns,
            self.timing.declared_rebuild_budget_passed,
        )?;
        writeln!(
            f,
            "rss=source:proc-status-vmrss-vmhwm,scope:whole-process-including-driver-and-runtime,baseline:{},post_spawn:{},ready:{},post_shutdown:{},process_lifetime_hwm:{}",
            self.rss.baseline_rss_bytes,
            self.rss.post_spawn_rss_bytes,
            self.rss.ready_rss_bytes,
            self.rss.post_shutdown_rss_bytes,
            self.rss.process_lifetime_hwm_bytes,
        )?;
        write!(
            f,
            "nonclaims=source-cache-control,durable-oram,authenticated-manifest,external-freshness-witness,production-key-owner,full-service-rto,target-hardware,physical-trace,tdx,attestation,signed-provenance,mainnet-readiness"
        )
    }
}

/// Coarse identifier-free failure from a source-bound cold rebuild.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TypedWorkerColdRebuildError {
    /// The real typed backend is unavailable on this feature or target.
    TypedBackendUnavailable,
    /// Capture, sizing, lineage, shape, or rebuild-budget input validation failed.
    InputRejected,
    /// Projection, layout, queue, or typed-worker construction failed.
    ConstructionFailed,
    /// The supplied block sequence or final checkpoint was rejected.
    SourceRejected,
    /// An accepted projection command failed closed.
    CommandFailed,
    /// A required wall-clock or process-memory measurement failed.
    MeasurementFailed,
    /// The fresh worker did not stop cleanly from its ready checkpoint.
    ShutdownFailed,
    /// A report differs from its inputs or fixed claim boundary.
    InvalidReport,
}

impl fmt::Display for TypedWorkerColdRebuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TypedBackendUnavailable => {
                f.write_str("typed-worker cold-rebuild backend is unavailable")
            }
            Self::InputRejected => f.write_str("typed-worker cold-rebuild input was rejected"),
            Self::ConstructionFailed => {
                f.write_str("typed-worker cold-rebuild construction failed")
            }
            Self::SourceRejected => {
                f.write_str("typed-worker cold-rebuild source sequence was rejected")
            }
            Self::CommandFailed => f.write_str("typed-worker cold-rebuild command failed"),
            Self::MeasurementFailed => f.write_str("typed-worker cold-rebuild measurement failed"),
            Self::ShutdownFailed => f.write_str("typed-worker cold-rebuild shutdown failed"),
            Self::InvalidReport => f.write_str("typed-worker cold-rebuild report is invalid"),
        }
    }
}

impl std::error::Error for TypedWorkerColdRebuildError {}

#[derive(Clone)]
struct RecordingPublisher {
    latest: Rc<RefCell<Option<ProjectionPublication>>>,
}

impl RecordingPublisher {
    fn new() -> Self {
        Self {
            latest: Rc::new(RefCell::new(None)),
        }
    }

    fn latest(&self) -> Result<ProjectionPublication, TypedWorkerColdRebuildError> {
        self.latest
            .try_borrow()
            .map_err(|_| TypedWorkerColdRebuildError::CommandFailed)?
            .as_ref()
            .copied()
            .ok_or(TypedWorkerColdRebuildError::SourceRejected)
    }
}

#[derive(Debug, Clone, Copy)]
struct RecordingPublisherError;

impl ProjectionCheckpointPublisher for RecordingPublisher {
    type Error = RecordingPublisherError;

    fn publish_and_wait(&mut self, publication: &ProjectionPublication) -> Result<(), Self::Error> {
        let mut latest = self
            .latest
            .try_borrow_mut()
            .map_err(|_| RecordingPublisherError)?;
        *latest = Some(*publication);
        Ok(())
    }
}

/// Incremental source-bound rebuild owning one fresh typed projection candidate.
pub struct TypedWorkerColdRebuildSession {
    owner: Option<OfflineProjectionOwner<RecordingPublisher>>,
    recorder: RecordingPublisher,
    source_scanner: Option<MainnetCorpusScanner>,
    expected_measurement: MainnetCorpusMeasurement,
    inputs: ColdRebuildInputs,
    projection_epoch: u64,
    started_at: Instant,
    replay_started_at: Instant,
    construction_ns: u64,
    baseline_memory: ProcessMemorySample,
    post_spawn_memory: ProcessMemorySample,
    applied_blocks: u64,
    latest_checkpoint: Option<PublicChainCheckpoint>,
    failed_closed: bool,
}

impl TypedWorkerColdRebuildSession {
    /// Validates source artifacts and allocates one fresh volatile typed worker.
    pub fn start(
        profile: TypedWorkerColdRebuildProfile,
        measurement: &MainnetCorpusMeasurement,
        sizing: &MainnetSizingQualification,
        measurement_blake2s256: &str,
        qualification_blake2s256: &str,
        declared_rebuild_budget: Duration,
    ) -> Result<Self, TypedWorkerColdRebuildError> {
        if profile != TypedWorkerColdRebuildProfile::SourceBoundBuilderV1 {
            return Err(TypedWorkerColdRebuildError::InputRejected);
        }
        let inputs = ColdRebuildInputs::from_artifacts(
            measurement,
            sizing,
            measurement_blake2s256,
            qualification_blake2s256,
            declared_rebuild_budget,
        )?;
        ensure_typed_backend_available()?;

        let baseline_memory =
            sample_process_memory().map_err(|_| TypedWorkerColdRebuildError::MeasurementFailed)?;
        let layout_seed = derive_layout_seed(&inputs);
        let projection_epoch = derive_projection_epoch(&inputs)?;
        let projection = build_projection_config(inputs.worker_shape, projection_epoch)?;
        let layout = build_layout(inputs.worker_shape, layout_seed, projection_epoch)?;
        let recorder = RecordingPublisher::new();
        let started_at = Instant::now();
        let owner = OfflineProjectionOwner::new_with_publisher(
            projection,
            layout,
            usize::try_from(QUEUE_CAPACITY)
                .map_err(|_| TypedWorkerColdRebuildError::ConstructionFailed)?,
            recorder.clone(),
        )
        .map_err(map_owner_build)?;
        let mut session = Self {
            owner: Some(owner),
            recorder,
            source_scanner: Some(MainnetCorpusScanner::new()),
            expected_measurement: measurement.clone(),
            inputs,
            projection_epoch,
            started_at,
            replay_started_at: started_at,
            construction_ns: 0,
            baseline_memory,
            post_spawn_memory: baseline_memory,
            applied_blocks: 0,
            latest_checkpoint: None,
            failed_closed: false,
        };
        session.post_spawn_memory =
            sample_process_memory().map_err(|_| TypedWorkerColdRebuildError::MeasurementFailed)?;
        session.construction_ns = elapsed_ns(started_at)?;
        session.replay_started_at = Instant::now();
        Ok(session)
    }

    /// Applies one canonical indexed block and waits for every projected event mutation.
    pub fn push(&mut self, block: &IndexedBlock) -> Result<(), TypedWorkerColdRebuildError> {
        if self.failed_closed || self.applied_blocks >= self.inputs.source.expected_blocks {
            self.fail_and_discard();
            return Err(TypedWorkerColdRebuildError::SourceRejected);
        }
        if self
            .source_scanner
            .as_mut()
            .ok_or(TypedWorkerColdRebuildError::SourceRejected)?
            .push(block)
            .is_err()
        {
            self.fail_and_discard();
            return Err(TypedWorkerColdRebuildError::SourceRejected);
        }
        let result = self
            .owner
            .as_mut()
            .ok_or(TypedWorkerColdRebuildError::CommandFailed)?
            .apply_finalized(block);
        match result {
            Ok(checkpoint) => {
                self.applied_blocks = self
                    .applied_blocks
                    .checked_add(1)
                    .ok_or(TypedWorkerColdRebuildError::SourceRejected)?;
                self.latest_checkpoint = Some(checkpoint);
                Ok(())
            }
            Err(_) => {
                self.fail_and_discard();
                Err(TypedWorkerColdRebuildError::CommandFailed)
            }
        }
    }

    /// Reaches the exact source checkpoint, shuts down cleanly, and returns aggregate evidence.
    pub fn finish(mut self) -> Result<TypedWorkerColdRebuildReport, TypedWorkerColdRebuildError> {
        if self.failed_closed || self.applied_blocks != self.inputs.source.expected_blocks {
            self.fail_and_discard();
            return Err(TypedWorkerColdRebuildError::SourceRejected);
        }
        let recomputed_measurement = self
            .source_scanner
            .take()
            .ok_or(TypedWorkerColdRebuildError::SourceRejected)?
            .finish()
            .map_err(|_| TypedWorkerColdRebuildError::SourceRejected)?;
        if recomputed_measurement != self.expected_measurement {
            self.fail_and_discard();
            return Err(TypedWorkerColdRebuildError::SourceRejected);
        }
        let checkpoint = match self.latest_checkpoint {
            Some(checkpoint) if checkpoint_matches(checkpoint, &self.inputs.source) => checkpoint,
            _ => {
                self.fail_and_discard();
                return Err(TypedWorkerColdRebuildError::SourceRejected);
            }
        };

        let finish_started_at = Instant::now();
        let finish_result = self
            .owner
            .as_mut()
            .ok_or(TypedWorkerColdRebuildError::CommandFailed)?
            .finish(checkpoint);
        let finish_call_ns = elapsed_ns(finish_started_at)?;
        let ready_checkpoint = match finish_result {
            Ok(ready) if checkpoint_matches(ready, &self.inputs.source) => ready,
            _ => {
                self.fail_and_discard();
                return Err(TypedWorkerColdRebuildError::CommandFailed);
            }
        };
        let replay_to_ready_ns = elapsed_ns(self.replay_started_at)?;
        let ready_memory =
            sample_process_memory().map_err(|_| TypedWorkerColdRebuildError::MeasurementFailed)?;
        let publication = self.recorder.latest()?;
        if publication.chain() != ready_checkpoint {
            self.fail_and_discard();
            return Err(TypedWorkerColdRebuildError::SourceRejected);
        }
        let semantic_event_log_root_blake2s256 =
            digest_hex(publication.event_log_root().as_bytes());
        let ready_ns = elapsed_ns(self.started_at)?;
        let declared_rebuild_budget_passed = ready_ns <= self.inputs.declared_rebuild_budget_ns;

        let owner = self
            .owner
            .take()
            .ok_or(TypedWorkerColdRebuildError::ShutdownFailed)?;
        let shutdown_started_at = Instant::now();
        let shutdown = owner.shutdown();
        let shutdown_ns = elapsed_ns(shutdown_started_at)?;
        if !matches!(
            shutdown,
            ProjectionOwnerShutdownOutcome::Stopped {
                readiness: ProjectionOwnerReadiness::Ready { checkpoint }
            } if checkpoint == ready_checkpoint
        ) {
            return Err(TypedWorkerColdRebuildError::ShutdownFailed);
        }
        let post_shutdown_memory =
            sample_process_memory().map_err(|_| TypedWorkerColdRebuildError::MeasurementFailed)?;
        let total_lifecycle_ns = elapsed_ns(self.started_at)?;
        let report = TypedWorkerColdRebuildReport {
            scenario: SCENARIO.to_owned(),
            profile: TypedWorkerColdRebuildProfile::SourceBoundBuilderV1,
            backend: BACKEND.to_owned(),
            source: self.inputs.source.clone(),
            worker_shape: self.inputs.worker_shape,
            projection_epoch: self.projection_epoch,
            applied_blocks: self.applied_blocks,
            final_checkpoint_height: ready_checkpoint.height(),
            final_checkpoint_hash: ready_checkpoint.block_hash().to_rpc_hex(),
            semantic_event_log_root_blake2s256,
            timing: ColdRebuildTimingReport {
                declared_rebuild_budget_ns: self.inputs.declared_rebuild_budget_ns,
                construction_ns: self.construction_ns,
                replay_to_ready_ns,
                finish_call_ns,
                ready_ns,
                shutdown_ns,
                total_lifecycle_ns,
                declared_rebuild_budget_passed,
            },
            rss: ColdRebuildRssReport::from_samples(
                self.baseline_memory,
                self.post_spawn_memory,
                ready_memory,
                post_shutdown_memory,
            ),
            evidence_scope: EVIDENCE_SCOPE,
        };
        report.validate()?;
        Ok(report)
    }

    fn fail_and_discard(&mut self) {
        self.failed_closed = true;
        self.source_scanner = None;
        if let Some(owner) = self.owner.take() {
            let _ = owner.shutdown();
        }
    }
}

impl Drop for TypedWorkerColdRebuildSession {
    fn drop(&mut self) {
        self.fail_and_discard();
    }
}

fn build_projection_config(
    shape: ColdRebuildWorkerShape,
    projection_epoch: u64,
) -> Result<ProjectionConfig, TypedWorkerColdRebuildError> {
    let capacities = ProjectionCapacities::new(
        usize::try_from(shape.max_seen_outputs)
            .map_err(|_| TypedWorkerColdRebuildError::ConstructionFailed)?,
        usize::try_from(shape.max_live_outputs)
            .map_err(|_| TypedWorkerColdRebuildError::ConstructionFailed)?,
        usize::try_from(shape.directory_admission_limit)
            .map_err(|_| TypedWorkerColdRebuildError::ConstructionFailed)?,
        usize::try_from(shape.event_admission_limit)
            .map_err(|_| TypedWorkerColdRebuildError::ConstructionFailed)?,
        usize::try_from(shape.max_events_per_address)
            .map_err(|_| TypedWorkerColdRebuildError::ConstructionFailed)?,
    )
    .map_err(|_| TypedWorkerColdRebuildError::ConstructionFailed)?;
    ProjectionConfig::new(
        CanonicalNetwork::Mainnet,
        SCHEMA_VERSION,
        KEY_EPOCH,
        projection_epoch,
        capacities,
    )
    .map_err(|_| TypedWorkerColdRebuildError::ConstructionFailed)
}

fn build_layout(
    shape: ColdRebuildWorkerShape,
    seed: [u8; 32],
    generation: u64,
) -> Result<FixedProbeLayout<DIRECTORY_PROBES, EVENT_PROBES>, TypedWorkerColdRebuildError> {
    FixedProbeLayout::new(
        LayoutIdentity::new(
            LayoutNetwork::Mainnet,
            SCHEMA_VERSION,
            KEY_EPOCH,
            generation,
            seed,
        )
        .map_err(|_| TypedWorkerColdRebuildError::ConstructionFailed)?,
        DirectoryTableConfiguration::<DIRECTORY_PROBES>::new(
            shape.directory_capacity,
            shape.directory_admission_limit,
        )
        .map_err(|_| TypedWorkerColdRebuildError::ConstructionFailed)?,
        EventTableConfiguration::<EVENT_PROBES>::new(
            shape.event_capacity,
            shape.event_admission_limit,
        )
        .map_err(|_| TypedWorkerColdRebuildError::ConstructionFailed)?,
        shape.max_events_per_address,
    )
    .map_err(|_| TypedWorkerColdRebuildError::ConstructionFailed)
}

fn derive_layout_seed(inputs: &ColdRebuildInputs) -> [u8; 32] {
    let mut hasher = Blake2s256::new();
    Digest::update(&mut hasher, LAYOUT_SEED_DOMAIN);
    Digest::update(&mut hasher, inputs.source.measurement_blake2s256.as_bytes());
    Digest::update(
        &mut hasher,
        inputs.source.qualification_blake2s256.as_bytes(),
    );
    let digest = Digest::finalize(hasher);
    let mut seed = [0; 32];
    seed.copy_from_slice(&digest);
    seed
}

fn derive_projection_epoch(inputs: &ColdRebuildInputs) -> Result<u64, TypedWorkerColdRebuildError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| TypedWorkerColdRebuildError::MeasurementFailed)?;
    let mut hasher = Blake2s256::new();
    Digest::update(&mut hasher, PROJECTION_EPOCH_DOMAIN);
    Digest::update(&mut hasher, now.as_nanos().to_le_bytes());
    Digest::update(&mut hasher, std::process::id().to_le_bytes());
    Digest::update(&mut hasher, inputs.source.measurement_blake2s256.as_bytes());
    let digest = Digest::finalize(hasher);
    let mut bytes = [0; 8];
    bytes.copy_from_slice(&digest[..8]);
    Ok(u64::from_le_bytes(bytes) | 1)
}

fn checkpoint_matches(
    checkpoint: PublicChainCheckpoint,
    source: &ColdRebuildSourceBinding,
) -> bool {
    checkpoint.network() == CanonicalNetwork::Mainnet
        && checkpoint.height() == source.checkpoint_height
        && checkpoint.block_hash().to_rpc_hex() == source.checkpoint_hash
}

fn duration_ns(duration: Duration) -> Result<u64, TypedWorkerColdRebuildError> {
    u64::try_from(duration.as_nanos()).map_err(|_| TypedWorkerColdRebuildError::InputRejected)
}

fn elapsed_ns(started_at: Instant) -> Result<u64, TypedWorkerColdRebuildError> {
    u64::try_from(started_at.elapsed().as_nanos())
        .map_err(|_| TypedWorkerColdRebuildError::MeasurementFailed)
}

#[cfg(all(
    feature = "rostl-experimental",
    target_os = "linux",
    target_arch = "x86_64"
))]
const fn ensure_typed_backend_available() -> Result<(), TypedWorkerColdRebuildError> {
    Ok(())
}

#[cfg(not(all(
    feature = "rostl-experimental",
    target_os = "linux",
    target_arch = "x86_64"
)))]
const fn ensure_typed_backend_available() -> Result<(), TypedWorkerColdRebuildError> {
    Err(TypedWorkerColdRebuildError::TypedBackendUnavailable)
}

const fn map_owner_build(error: ProjectionOwnerBuildError) -> TypedWorkerColdRebuildError {
    match error {
        #[cfg(not(all(
            feature = "rostl-experimental",
            target_os = "linux",
            target_arch = "x86_64"
        )))]
        ProjectionOwnerBuildError::TypedBackendUnavailable => {
            TypedWorkerColdRebuildError::TypedBackendUnavailable
        }
        ProjectionOwnerBuildError::ConfigMismatch(_)
        | ProjectionOwnerBuildError::ConstructionFailed => {
            TypedWorkerColdRebuildError::ConstructionFailed
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zaino_corpus::MainnetSizingModel;

    #[cfg(all(
        feature = "rostl-experimental",
        target_os = "linux",
        target_arch = "x86_64"
    ))]
    use std::num::NonZeroU128;
    #[cfg(all(
        feature = "rostl-experimental",
        target_os = "linux",
        target_arch = "x86_64"
    ))]
    use zaino_state::{
        BlockContext, BlockData, BlockHash, ChainWork, CommitmentTreeData, CommitmentTreeRoots,
        CommitmentTreeSizes, CompactDifficulty, EquihashSolution, Height,
    };

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    fn measurement() -> TestResult<MainnetCorpusMeasurement> {
        Ok(serde_json::from_value(serde_json::json!({
            "checkpoint": {
                "network": "mainnet",
                "height": 0,
                "hash": "00040fe8ec8471911baa1db1266ea15dd06b4a8a5c453883c000b031973dce08"
            },
            "aggregate": {
                "blocks": 1,
                "transactions": 0,
                "outputs": 0,
                "spends": 0,
                "distinct_standard_addresses": 0,
                "live_standard_utxos": 0,
                "live_nonstandard_utxos": 0,
                "script_totals": [
                    {"outputs": 0, "spends": 0, "live_utxos": 0},
                    {"outputs": 0, "spends": 0, "live_utxos": 0},
                    {"outputs": 0, "spends": 0, "live_utxos": 0}
                ],
                "events_per_address": [],
                "live_utxos_per_address": [],
                "peak_live_utxos_per_address": [],
                "address_state_histogram": [],
                "event_distribution": {"p50": 0, "p90": 0, "p99": 0, "p999": 0, "maximum": 0},
                "live_distribution": {"p50": 0, "p90": 0, "p99": 0, "p999": 0, "maximum": 0},
                "peak_live_distribution": {"p50": 0, "p90": 0, "p99": 0, "p999": 0, "maximum": 0},
                "hottest_event_counts": [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                "record_sizes": {
                    "address_key_bytes": 32,
                    "business_utxo_bytes": 88,
                    "persistent_utxo_bytes": 88,
                    "persistent_event_bytes": 72,
                    "logical_store_slot_bytes": 96,
                    "directory_cell_bytes": 38,
                    "event_cell_bytes": 82
                }
            }
        }))?)
    }

    fn sizing(measurement: &MainnetCorpusMeasurement) -> TestResult<MainnetSizingQualification> {
        let model = MainnetSizingModel::new(0, 0, 64, 48, 128, 96, 3, 4, 20_000, 1_000_000, 3_000)?;
        Ok(measurement.apply_model(&model)?)
    }

    fn report_fixture(
        measurement: &MainnetCorpusMeasurement,
        sizing: &MainnetSizingQualification,
    ) -> TestResult<TypedWorkerColdRebuildReport> {
        let inputs = ColdRebuildInputs::from_artifacts(
            measurement,
            sizing,
            &"11".repeat(32),
            &"22".repeat(32),
            Duration::from_secs(60),
        )?;
        Ok(TypedWorkerColdRebuildReport {
            scenario: SCENARIO.to_owned(),
            profile: TypedWorkerColdRebuildProfile::SourceBoundBuilderV1,
            backend: BACKEND.to_owned(),
            source: inputs.source,
            worker_shape: inputs.worker_shape,
            projection_epoch: 1,
            applied_blocks: 1,
            final_checkpoint_height: 0,
            final_checkpoint_hash:
                "00040fe8ec8471911baa1db1266ea15dd06b4a8a5c453883c000b031973dce08".to_owned(),
            semantic_event_log_root_blake2s256: "33".repeat(32),
            timing: ColdRebuildTimingReport {
                declared_rebuild_budget_ns: inputs.declared_rebuild_budget_ns,
                construction_ns: 1,
                replay_to_ready_ns: 2,
                finish_call_ns: 1,
                ready_ns: 4,
                shutdown_ns: 1,
                total_lifecycle_ns: 5,
                declared_rebuild_budget_passed: true,
            },
            rss: ColdRebuildRssReport {
                baseline_rss_bytes: 1_000_000,
                post_spawn_rss_bytes: 2_000_000,
                ready_rss_bytes: 3_000_000,
                post_shutdown_rss_bytes: 2_000_000,
                process_lifetime_hwm_bytes: 4_000_000,
            },
            evidence_scope: EVIDENCE_SCOPE,
        })
    }

    #[test]
    fn inputs_bind_exact_artifacts_and_keep_empty_fixture_bounds_nonzero() -> TestResult {
        let measurement = measurement()?;
        let sizing = sizing(&measurement)?;
        let inputs = ColdRebuildInputs::from_artifacts(
            &measurement,
            &sizing,
            &"11".repeat(32),
            &"22".repeat(32),
            Duration::from_secs(60),
        )?;
        assert_eq!(inputs.source.expected_blocks, 1);
        assert_eq!(inputs.source.measured_outputs, 0);
        assert_eq!(inputs.worker_shape.max_seen_outputs, 1);
        assert_eq!(inputs.worker_shape.max_live_outputs, 1);
        assert!(matches!(
            ColdRebuildInputs::from_artifacts(
                &measurement,
                &sizing,
                &"AA".repeat(32),
                &"22".repeat(32),
                Duration::from_secs(60),
            ),
            Err(TypedWorkerColdRebuildError::InputRejected)
        ));
        assert!(matches!(
            ColdRebuildInputs::from_artifacts(
                &measurement,
                &sizing,
                &"11".repeat(32),
                &"22".repeat(32),
                Duration::ZERO,
            ),
            Err(TypedWorkerColdRebuildError::InputRejected)
        ));
        Ok(())
    }

    #[test]
    fn report_validation_accepts_a_real_budget_miss_and_rejects_tampering() -> TestResult {
        let measurement = measurement()?;
        let sizing = sizing(&measurement)?;
        let report = report_fixture(&measurement, &sizing)?;
        report.validate_against(
            &measurement,
            &sizing,
            &"11".repeat(32),
            &"22".repeat(32),
            Duration::from_secs(60),
        )?;

        let mut overstated = report.clone();
        overstated.evidence_scope.tdx_qualified = true;
        assert_eq!(
            overstated.validate(),
            Err(TypedWorkerColdRebuildError::InvalidReport)
        );

        let mut wrong_source = report.clone();
        wrong_source.applied_blocks = 2;
        assert_eq!(
            wrong_source.validate(),
            Err(TypedWorkerColdRebuildError::InvalidReport)
        );

        let mut impossible_timing = report;
        impossible_timing.timing.finish_call_ns = 0;
        assert_eq!(
            impossible_timing.validate(),
            Err(TypedWorkerColdRebuildError::InvalidReport)
        );

        let mut missed_budget = report_fixture(&measurement, &sizing)?;
        missed_budget.timing.declared_rebuild_budget_ns = 3;
        missed_budget.timing.declared_rebuild_budget_passed = false;
        missed_budget.validate()?;
        assert!(!missed_budget.declared_rebuild_budget_passed());
        Ok(())
    }

    #[cfg(not(all(
        feature = "rostl-experimental",
        target_os = "linux",
        target_arch = "x86_64"
    )))]
    #[test]
    fn unsupported_target_rejects_session_before_worker_allocation() -> TestResult {
        let measurement = measurement()?;
        let sizing = sizing(&measurement)?;
        assert!(matches!(
            TypedWorkerColdRebuildSession::start(
                TypedWorkerColdRebuildProfile::SourceBoundBuilderV1,
                &measurement,
                &sizing,
                &"11".repeat(32),
                &"22".repeat(32),
                Duration::from_secs(60),
            ),
            Err(TypedWorkerColdRebuildError::TypedBackendUnavailable)
        ));
        Ok(())
    }

    #[cfg(all(
        feature = "rostl-experimental",
        target_os = "linux",
        target_arch = "x86_64"
    ))]
    fn empty_mainnet_genesis() -> TestResult<IndexedBlock> {
        let display_hash = [
            0x00, 0x04, 0x0f, 0xe8, 0xec, 0x84, 0x71, 0x91, 0x1b, 0xaa, 0x1d, 0xb1, 0x26, 0x6e,
            0xa1, 0x5d, 0xd0, 0x6b, 0x4a, 0x8a, 0x5c, 0x45, 0x38, 0x83, 0xc0, 0x00, 0xb0, 0x31,
            0x97, 0x3d, 0xce, 0x08,
        ];
        let chainwork = NonZeroU128::new(1).ok_or("test chainwork must remain nonzero")?;
        let context = BlockContext::new(
            BlockHash::from_bytes_in_display_order(&display_hash),
            BlockHash([0; 32]),
            ChainWork::new(chainwork),
            Height::try_from(0)?,
        );
        let data = BlockData::new(
            1,
            0,
            [0; 32],
            [0; 32],
            CompactDifficulty::try_from_bits(0x2007_ffff)?,
            [0; 32],
            EquihashSolution::Regtest([0; 36]),
        );
        Ok(IndexedBlock::new(
            context,
            data,
            Vec::new(),
            CommitmentTreeData::new(
                CommitmentTreeRoots::new([0; 32], [0; 32], None),
                CommitmentTreeSizes::new(0, 0, 0),
            ),
        ))
    }

    #[cfg(all(
        feature = "rostl-experimental",
        target_os = "linux",
        target_arch = "x86_64"
    ))]
    fn native_report(
        measurement: &MainnetCorpusMeasurement,
        sizing: &MainnetSizingQualification,
    ) -> TestResult<TypedWorkerColdRebuildReport> {
        let mut session = TypedWorkerColdRebuildSession::start(
            TypedWorkerColdRebuildProfile::SourceBoundBuilderV1,
            measurement,
            sizing,
            &"11".repeat(32),
            &"22".repeat(32),
            Duration::from_secs(60),
        )?;
        session.push(&empty_mainnet_genesis()?)?;
        Ok(session.finish()?)
    }

    #[cfg(all(
        feature = "rostl-experimental",
        target_os = "linux",
        target_arch = "x86_64"
    ))]
    #[test]
    fn native_rebuild_is_ready_clean_and_semantically_reproducible() -> TestResult {
        let measurement = measurement()?;
        let qualification = sizing(&measurement)?;
        let first = native_report(&measurement, &qualification)?;
        let second = native_report(&measurement, &qualification)?;
        first.validate_against(
            &measurement,
            &qualification,
            &"11".repeat(32),
            &"22".repeat(32),
            Duration::from_secs(60),
        )?;
        assert!(first.declared_rebuild_budget_passed());
        assert_eq!(
            first.semantic_event_log_root_blake2s256,
            second.semantic_event_log_root_blake2s256
        );

        let premature = TypedWorkerColdRebuildSession::start(
            TypedWorkerColdRebuildProfile::SourceBoundBuilderV1,
            &measurement,
            &qualification,
            &"11".repeat(32),
            &"22".repeat(32),
            Duration::from_secs(60),
        )?;
        assert!(matches!(
            premature.finish(),
            Err(TypedWorkerColdRebuildError::SourceRejected)
        ));

        let mut mismatched_value = serde_json::to_value(&measurement)?;
        mismatched_value["aggregate"]["transactions"] = serde_json::json!(1);
        let mismatched_measurement = serde_json::from_value(mismatched_value)?;
        let mismatched_sizing = sizing(&mismatched_measurement)?;
        let mut mismatched = TypedWorkerColdRebuildSession::start(
            TypedWorkerColdRebuildProfile::SourceBoundBuilderV1,
            &mismatched_measurement,
            &mismatched_sizing,
            &"11".repeat(32),
            &"22".repeat(32),
            Duration::from_secs(60),
        )?;
        mismatched.push(&empty_mainnet_genesis()?)?;
        assert!(matches!(
            mismatched.finish(),
            Err(TypedWorkerColdRebuildError::SourceRejected)
        ));
        Ok(())
    }
}
