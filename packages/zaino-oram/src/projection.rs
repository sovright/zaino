//! Plaintext offline finalized-projection oracle for deterministic fixtures.
//!
//! This module models canonical ingest, replay, rebuild, and fail-closed
//! lifecycle semantics. A private generic coordinator stages each whole block,
//! waits for every ordered standard-event sink mutation, and commits its
//! in-memory checkpoint last. Its ordinary maps are neither an ORAM nor durable
//! or authenticated storage. The sink seam is privately bound to the atomic
//! worker, but no coordinator constructs that candidate and nothing here is
//! suitable for serving queries.

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fmt,
    num::NonZeroUsize,
    panic::{catch_unwind, AssertUnwindSafe},
};

use blake2::{Blake2s256, Digest};
use zaino_state::{
    extract_transparent_events, AddrScript, IndexedBlock, Outpoint, ScriptType,
    TransparentBlockEvent, TransparentEventError,
};

use crate::{
    canonical_chain::{
        CanonicalBlockCursor, CanonicalChainError, CanonicalNetwork, PublicChainCheckpoint,
    },
    checkpoint::{
        NoopProjectionCheckpointPublisher, ProjectionCheckpointPublisher, ProjectionEventLogRoot,
        ProjectionPublication,
    },
    records::{
        persistent_utxo_event_commitment, TransparentUtxo, UtxoEvent, UtxoRecordError,
        UtxoScriptClass,
    },
};

const PROJECTION_EVENT_LOG_INITIAL_DOMAIN: &[u8] = b"zaino-oram-projection-event-log-initial-v1";
const PROJECTION_EVENT_LOG_STEP_DOMAIN: &[u8] = b"zaino-oram-projection-event-log-step-v1";

/// Explicit bounds for every identifier-bearing offline projection collection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ProjectionCapacities {
    max_seen_outputs: NonZeroUsize,
    max_live_outputs: NonZeroUsize,
    max_standard_addresses: NonZeroUsize,
    max_total_events: NonZeroUsize,
    max_events_per_address: NonZeroUsize,
}

impl ProjectionCapacities {
    pub(super) fn new(
        max_seen_outputs: usize,
        max_live_outputs: usize,
        max_standard_addresses: usize,
        max_total_events: usize,
        max_events_per_address: usize,
    ) -> Result<Self, ProjectionConfigError> {
        Ok(Self {
            max_seen_outputs: NonZeroUsize::new(max_seen_outputs).ok_or(
                ProjectionConfigError::EmptyCapacity {
                    dimension: CapacityDimension::SeenOutputs,
                },
            )?,
            max_live_outputs: NonZeroUsize::new(max_live_outputs).ok_or(
                ProjectionConfigError::EmptyCapacity {
                    dimension: CapacityDimension::LiveOutputs,
                },
            )?,
            max_standard_addresses: NonZeroUsize::new(max_standard_addresses).ok_or(
                ProjectionConfigError::EmptyCapacity {
                    dimension: CapacityDimension::StandardAddresses,
                },
            )?,
            max_total_events: NonZeroUsize::new(max_total_events).ok_or(
                ProjectionConfigError::EmptyCapacity {
                    dimension: CapacityDimension::TotalEvents,
                },
            )?,
            max_events_per_address: NonZeroUsize::new(max_events_per_address).ok_or(
                ProjectionConfigError::EmptyCapacity {
                    dimension: CapacityDimension::AddressEvents,
                },
            )?,
        })
    }

    const fn limit(self, dimension: CapacityDimension) -> NonZeroUsize {
        match dimension {
            CapacityDimension::SeenOutputs => self.max_seen_outputs,
            CapacityDimension::LiveOutputs => self.max_live_outputs,
            CapacityDimension::StandardAddresses => self.max_standard_addresses,
            CapacityDimension::TotalEvents => self.max_total_events,
            CapacityDimension::AddressEvents => self.max_events_per_address,
        }
    }

    pub(super) const fn max_standard_addresses(self) -> usize {
        self.max_standard_addresses.get()
    }

    pub(super) const fn max_total_events(self) -> usize {
        self.max_total_events.get()
    }

    pub(super) const fn max_events_per_address(self) -> usize {
        self.max_events_per_address.get()
    }
}

/// Offline model identity and capacity configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ProjectionConfig {
    network: CanonicalNetwork,
    schema_version: u32,
    key_epoch: u64,
    projection_epoch: u64,
    capacities: ProjectionCapacities,
}

impl ProjectionConfig {
    pub(super) fn new(
        network: CanonicalNetwork,
        schema_version: u32,
        key_epoch: u64,
        projection_epoch: u64,
        capacities: ProjectionCapacities,
    ) -> Result<Self, ProjectionConfigError> {
        if schema_version == 0 {
            return Err(ProjectionConfigError::SchemaVersionZero);
        }
        if projection_epoch == 0 {
            return Err(ProjectionConfigError::InvalidProjectionEpoch);
        }
        Ok(Self {
            network,
            schema_version,
            key_epoch,
            projection_epoch,
            capacities,
        })
    }

    pub(super) const fn network(self) -> CanonicalNetwork {
        self.network
    }

    pub(super) const fn schema_version(self) -> u32 {
        self.schema_version
    }

    pub(super) const fn key_epoch(self) -> u64 {
        self.key_epoch
    }

    pub(super) const fn projection_epoch(self) -> u64 {
        self.projection_epoch
    }

    pub(super) const fn capacities(self) -> ProjectionCapacities {
        self.capacities
    }
}

/// Invalid offline model configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ProjectionConfigError {
    SchemaVersionZero,
    InvalidProjectionEpoch,
    EmptyCapacity { dimension: CapacityDimension },
}

impl fmt::Display for ProjectionConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SchemaVersionZero => f.write_str("offline projection schema version is zero"),
            Self::InvalidProjectionEpoch => {
                f.write_str("offline projection lifecycle epoch is zero")
            }
            Self::EmptyCapacity { dimension } => {
                write!(f, "offline projection {} capacity is zero", dimension)
            }
        }
    }
}

impl std::error::Error for ProjectionConfigError {}

/// One public, in-memory-only checkpoint for the offline projection oracle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct OfflineProjectionCheckpoint {
    chain: PublicChainCheckpoint,
    schema_version: u32,
    key_epoch: u64,
    projection_epoch: u64,
}

impl OfflineProjectionCheckpoint {
    const fn new(
        chain: PublicChainCheckpoint,
        schema_version: u32,
        key_epoch: u64,
        projection_epoch: u64,
    ) -> Self {
        Self {
            chain,
            schema_version,
            key_epoch,
            projection_epoch,
        }
    }

    const fn chain(&self) -> PublicChainCheckpoint {
        self.chain
    }

    const fn schema_version(&self) -> u32 {
        self.schema_version
    }

    const fn key_epoch(&self) -> u64 {
        self.key_epoch
    }

    const fn projection_epoch(&self) -> u64 {
        self.projection_epoch
    }
}

/// Current usability of the offline oracle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProjectionReadiness {
    Building,
    Ready(OfflineProjectionCheckpoint),
    FailedClosed(ProjectionFault),
}

/// Identifier-free health category latched after an ingest or target failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProjectionFault {
    Lifecycle,
    CanonicalChain,
    Extraction,
    EventSink,
    Publication,
    InvalidEvent,
    DuplicateOutput,
    UnknownSpend,
    Capacity,
    CorruptState,
    Record,
    Target,
}

/// Public startup comparison between the current model and authoritative state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReconcileAction {
    Ready,
    Finish,
    ReplayFrom { next_height: u32 },
    RebuildRequired { reason: RebuildReason },
}

/// Reason a projection must be rebuilt instead of replayed forward.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RebuildReason {
    FailedClosed,
    NetworkMismatch,
    SchemaVersionMismatch,
    KeyEpochMismatch,
    ProjectionEpochMismatch,
    LocalAhead,
    HashMismatch,
}

#[derive(Clone, PartialEq, Eq)]
struct AddressState {
    events: Vec<UtxoEvent>,
    live_utxos: BTreeMap<Outpoint, TransparentUtxo>,
}

impl AddressState {
    fn new() -> Self {
        Self {
            events: Vec::new(),
            live_utxos: BTreeMap::new(),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum LiveOutput {
    Standard {
        address: AddrScript,
        created: UtxoEvent,
    },
    NonStandard,
}

#[derive(Clone, PartialEq, Eq)]
struct ProjectionState {
    addresses: BTreeMap<AddrScript, AddressState>,
    seen_outputs: HashSet<Outpoint>,
    live_outputs: HashMap<Outpoint, LiveOutput>,
    total_events: usize,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct ProjectionEventLogAccumulator {
    root: ProjectionEventLogRoot,
    events: u64,
}

impl ProjectionEventLogAccumulator {
    fn new(config: ProjectionConfig) -> Self {
        let mut hasher = Blake2s256::new();
        hasher.update(PROJECTION_EVENT_LOG_INITIAL_DOMAIN);
        hasher.update([canonical_network_tag(config.network())]);
        hasher.update(config.schema_version().to_le_bytes());
        hasher.update(config.key_epoch().to_le_bytes());
        Self {
            root: ProjectionEventLogRoot::from_bytes(finalize_blake2s(hasher)),
            events: 0,
        }
    }

    fn append(&mut self, event: &UtxoEvent) -> Result<(), ProjectionError> {
        let next_events = self
            .events
            .checked_add(1)
            .ok_or(ProjectionError::EventLogCounterOverflow)?;
        let commitment = persistent_utxo_event_commitment(event);
        let mut hasher = Blake2s256::new();
        hasher.update(PROJECTION_EVENT_LOG_STEP_DOMAIN);
        hasher.update(self.root.as_bytes());
        hasher.update(next_events.to_le_bytes());
        hasher.update(commitment);
        self.root = ProjectionEventLogRoot::from_bytes(finalize_blake2s(hasher));
        self.events = next_events;
        Ok(())
    }

    const fn root(self) -> ProjectionEventLogRoot {
        self.root
    }
}

impl ProjectionState {
    fn new() -> Self {
        Self {
            addresses: BTreeMap::new(),
            seen_outputs: HashSet::new(),
            live_outputs: HashMap::new(),
            total_events: 0,
        }
    }

    fn apply(
        &mut self,
        event: TransparentBlockEvent,
        capacities: ProjectionCapacities,
    ) -> Result<Option<UtxoEvent>, ProjectionError> {
        match event {
            TransparentBlockEvent::Created {
                location,
                outpoint,
                address,
                value_zat,
                script_class,
                ..
            } => self.apply_created(
                outpoint,
                address,
                value_zat,
                location.block_height(),
                script_class,
                capacities,
            ),
            TransparentBlockEvent::Spent {
                location, previous, ..
            } => self.apply_spent(previous, location.block_height(), capacities),
        }
    }

    fn apply_created(
        &mut self,
        outpoint: Outpoint,
        address: Option<AddrScript>,
        value_zat: u64,
        height: u32,
        script_class: ScriptType,
        capacities: ProjectionCapacities,
    ) -> Result<Option<UtxoEvent>, ProjectionError> {
        if self.seen_outputs.contains(&outpoint) {
            return Err(ProjectionError::DuplicateCreatedOutpoint);
        }
        let _next_seen = checked_capacity_increment(
            self.seen_outputs.len(),
            capacities,
            CapacityDimension::SeenOutputs,
        )?;
        let _next_live = checked_capacity_increment(
            self.live_outputs.len(),
            capacities,
            CapacityDimension::LiveOutputs,
        )?;

        let (owner, projected) = match script_class {
            ScriptType::P2PKH | ScriptType::P2SH => {
                let address = address.ok_or(ProjectionError::MissingStandardAddress)?;
                if address.script_type() != script_class as u8 {
                    return Err(ProjectionError::AddressClassMismatch);
                }
                let is_new_address = !self.addresses.contains_key(&address);
                if is_new_address {
                    let _next_addresses = checked_capacity_increment(
                        self.addresses.len(),
                        capacities,
                        CapacityDimension::StandardAddresses,
                    )?;
                }
                let current_address_events = self
                    .addresses
                    .get(&address)
                    .map_or(0, |state| state.events.len());
                let _next_address_events = checked_capacity_increment(
                    current_address_events,
                    capacities,
                    CapacityDimension::AddressEvents,
                )?;
                let next_total_events = checked_capacity_increment(
                    self.total_events,
                    capacities,
                    CapacityDimension::TotalEvents,
                )?;
                let event_class = map_script_class(script_class);
                let created = UtxoEvent::created(
                    *outpoint.prev_txid(),
                    outpoint.prev_index(),
                    value_zat,
                    height,
                    event_class,
                    *address.hash(),
                );
                let script = address
                    .to_script_pubkey()
                    .ok_or(ProjectionError::InvalidStandardAddress)?;
                let utxo = TransparentUtxo::new(
                    *outpoint.prev_txid(),
                    outpoint.prev_index(),
                    value_zat,
                    height,
                    &script,
                )
                .map_err(ProjectionError::Record)?;
                let address_state = self
                    .addresses
                    .entry(address)
                    .or_insert_with(AddressState::new);
                address_state.events.push(created);
                address_state.live_utxos.insert(outpoint, utxo);
                self.total_events = next_total_events;
                (LiveOutput::Standard { address, created }, Some(created))
            }
            ScriptType::NonStandard => {
                if address.is_some() {
                    return Err(ProjectionError::UnexpectedNonStandardAddress);
                }
                (LiveOutput::NonStandard, None)
            }
        };

        self.seen_outputs.insert(outpoint);
        self.live_outputs.insert(outpoint, owner);
        Ok(projected)
    }

    fn apply_spent(
        &mut self,
        previous: Outpoint,
        spending_height: u32,
        capacities: ProjectionCapacities,
    ) -> Result<Option<UtxoEvent>, ProjectionError> {
        let owner = self
            .live_outputs
            .get(&previous)
            .copied()
            .ok_or(ProjectionError::UnknownSpentOutpoint)?;
        let projected = match owner {
            LiveOutput::NonStandard => None,
            LiveOutput::Standard { address, created } => {
                let address_state = self
                    .addresses
                    .get(&address)
                    .ok_or(ProjectionError::CorruptAddressState)?;
                let _next_address_events = checked_capacity_increment(
                    address_state.events.len(),
                    capacities,
                    CapacityDimension::AddressEvents,
                )?;
                let next_total_events = checked_capacity_increment(
                    self.total_events,
                    capacities,
                    CapacityDimension::TotalEvents,
                )?;
                if !address_state.live_utxos.contains_key(&previous) {
                    return Err(ProjectionError::CorruptAddressState);
                }
                let spent = UtxoEvent::spent(
                    *previous.prev_txid(),
                    previous.prev_index(),
                    created.value_zat(),
                    spending_height,
                    created.script_class(),
                    *created.script_hash(),
                );
                let address_state = self
                    .addresses
                    .get_mut(&address)
                    .ok_or(ProjectionError::CorruptAddressState)?;
                address_state.live_utxos.remove(&previous);
                address_state.events.push(spent);
                self.total_events = next_total_events;
                Some(spent)
            }
        };
        self.live_outputs.remove(&previous);
        Ok(projected)
    }
}

struct StagedFinalizedBlock {
    cursor: CanonicalBlockCursor,
    checkpoint: PublicChainCheckpoint,
    state: ProjectionState,
    events: Vec<UtxoEvent>,
    event_log: ProjectionEventLogAccumulator,
}

/// Deterministic plaintext oracle for finalized `IndexedBlock` fixtures.
#[derive(Clone)]
struct OfflineFinalizedProjection {
    config: ProjectionConfig,
    cursor: CanonicalBlockCursor,
    state: ProjectionState,
    event_log: ProjectionEventLogAccumulator,
    readiness: ProjectionReadiness,
}

impl OfflineFinalizedProjection {
    fn new(config: ProjectionConfig) -> Self {
        Self {
            cursor: CanonicalBlockCursor::new(config.network),
            event_log: ProjectionEventLogAccumulator::new(config),
            config,
            state: ProjectionState::new(),
            readiness: ProjectionReadiness::Building,
        }
    }

    fn build<'a>(
        config: ProjectionConfig,
        target: OfflineProjectionCheckpoint,
        blocks: impl IntoIterator<Item = &'a IndexedBlock>,
    ) -> Result<Self, ProjectionError> {
        let mut projection = Self::new(config);
        for block in blocks {
            projection.apply_finalized(block)?;
        }
        projection.finish(target)?;
        Ok(projection)
    }

    /// Builds a fresh candidate without mutating the currently ready oracle.
    fn build_replacement<'a>(
        &self,
        target: OfflineProjectionCheckpoint,
        blocks: impl IntoIterator<Item = &'a IndexedBlock>,
    ) -> Result<Self, ProjectionError> {
        if !matches!(self.readiness, ProjectionReadiness::Ready(_)) {
            return Err(ProjectionError::ReplacementSourceNotReady);
        }
        Self::build(self.config, target, blocks)
    }

    /// Replays missing canonical blocks into a fresh clone of a ready oracle.
    ///
    /// The original remains ready unless the caller explicitly replaces it
    /// with the successfully finished return value.
    fn replay_from_ready<'a>(
        &self,
        target: OfflineProjectionCheckpoint,
        blocks: impl IntoIterator<Item = &'a IndexedBlock>,
    ) -> Result<Self, ProjectionError> {
        if !matches!(self.readiness, ProjectionReadiness::Ready(_)) {
            return Err(ProjectionError::ReplacementSourceNotReady);
        }
        let mut candidate = self.clone();
        candidate.readiness = ProjectionReadiness::Building;
        for block in blocks {
            candidate.apply_finalized(block)?;
        }
        candidate.finish(target)?;
        Ok(candidate)
    }

    /// Stages a complete block and publishes its public checkpoint last.
    fn apply_finalized(
        &mut self,
        block: &IndexedBlock,
    ) -> Result<OfflineProjectionCheckpoint, ProjectionError> {
        self.ensure_building()?;

        let staged = self.stage_block(block);
        match staged {
            Ok(staged) => Ok(self.commit_staged(staged)),
            Err(error) => {
                self.fail_closed(&error);
                Err(error)
            }
        }
    }

    fn ensure_building(&mut self) -> Result<(), ProjectionError> {
        match self.readiness {
            ProjectionReadiness::FailedClosed(fault) => {
                return Err(ProjectionError::AlreadyFailedClosed { fault });
            }
            ProjectionReadiness::Ready(_) => {
                let error = ProjectionError::ApplyAfterReady;
                self.fail_closed(&error);
                return Err(error);
            }
            ProjectionReadiness::Building => {}
        }
        Ok(())
    }

    fn stage_block(&self, block: &IndexedBlock) -> Result<StagedFinalizedBlock, ProjectionError> {
        let candidate = self
            .cursor
            .validate_next(block)
            .map_err(ProjectionError::CanonicalChain)?;
        let events = extract_transparent_events(block).map_err(ProjectionError::Extraction)?;
        let mut state = self.state.clone();
        let mut event_log = self.event_log;
        let mut projected_events = Vec::with_capacity(events.len());
        for event in events {
            if let Some(event) = state.apply(event, self.config.capacities)? {
                event_log.append(&event)?;
                projected_events.push(event);
            }
        }
        let (cursor, committed) = self
            .cursor
            .stage_advance(candidate)
            .map_err(ProjectionError::CanonicalChain)?;
        Ok(StagedFinalizedBlock {
            cursor,
            checkpoint: committed,
            state,
            events: projected_events,
            event_log,
        })
    }

    fn commit_staged(&mut self, staged: StagedFinalizedBlock) -> OfflineProjectionCheckpoint {
        self.state = staged.state;
        self.event_log = staged.event_log;
        self.cursor = staged.cursor;
        self.checkpoint_for(staged.checkpoint)
    }

    /// Publishes readiness only for an exact, explicitly supplied target.
    fn finish(
        &mut self,
        target: OfflineProjectionCheckpoint,
    ) -> Result<OfflineProjectionCheckpoint, ProjectionError> {
        match self.readiness {
            ProjectionReadiness::FailedClosed(fault) => {
                return Err(ProjectionError::AlreadyFailedClosed { fault });
            }
            ProjectionReadiness::Ready(checkpoint) => {
                if checkpoint == target {
                    return Ok(checkpoint);
                }
                let error = ProjectionError::FinishAfterReadyWithDifferentTarget;
                self.fail_closed(&error);
                return Err(error);
            }
            ProjectionReadiness::Building => {}
        }
        let result = self.validate_target(target);
        match result {
            Ok(checkpoint) => {
                self.readiness = ProjectionReadiness::Ready(checkpoint);
                Ok(checkpoint)
            }
            Err(error) => {
                self.fail_closed(&error);
                Err(error)
            }
        }
    }

    fn validate_target(
        &self,
        target: OfflineProjectionCheckpoint,
    ) -> Result<OfflineProjectionCheckpoint, ProjectionError> {
        let target_chain = target.chain();
        if target_chain.network() != self.config.network {
            return Err(ProjectionError::TargetNetworkMismatch);
        }
        if target.schema_version() != self.config.schema_version {
            return Err(ProjectionError::TargetSchemaVersionMismatch);
        }
        if target.key_epoch() != self.config.key_epoch {
            return Err(ProjectionError::TargetKeyEpochMismatch);
        }
        if target.projection_epoch() != self.config.projection_epoch {
            return Err(ProjectionError::TargetProjectionEpochMismatch);
        }
        let committed = self.cursor.checkpoint();
        let Some(committed) = committed else {
            return Err(ProjectionError::TargetNotReached {
                target_height: target_chain.height(),
                committed_height: None,
            });
        };
        if committed.height() < target_chain.height() {
            return Err(ProjectionError::TargetNotReached {
                target_height: target_chain.height(),
                committed_height: Some(committed.height()),
            });
        }
        if committed.height() > target_chain.height() {
            return Err(ProjectionError::TargetExceeded {
                target_height: target_chain.height(),
                committed_height: committed.height(),
            });
        }
        if committed.block_hash() != target_chain.block_hash() {
            return Err(ProjectionError::TargetHashMismatch {
                height: target_chain.height(),
            });
        }
        Ok(self.checkpoint_for(committed))
    }

    fn reconcile(&self, authoritative: OfflineProjectionCheckpoint) -> ReconcileAction {
        if matches!(self.readiness, ProjectionReadiness::FailedClosed(_)) {
            return ReconcileAction::RebuildRequired {
                reason: RebuildReason::FailedClosed,
            };
        }
        let authoritative_chain = authoritative.chain();
        if authoritative_chain.network() != self.config.network {
            return ReconcileAction::RebuildRequired {
                reason: RebuildReason::NetworkMismatch,
            };
        }
        if authoritative.schema_version() != self.config.schema_version {
            return ReconcileAction::RebuildRequired {
                reason: RebuildReason::SchemaVersionMismatch,
            };
        }
        if authoritative.key_epoch() != self.config.key_epoch {
            return ReconcileAction::RebuildRequired {
                reason: RebuildReason::KeyEpochMismatch,
            };
        }
        if authoritative.projection_epoch() != self.config.projection_epoch {
            return ReconcileAction::RebuildRequired {
                reason: RebuildReason::ProjectionEpochMismatch,
            };
        }
        let Some(local) = self.cursor.checkpoint() else {
            return ReconcileAction::ReplayFrom { next_height: 0 };
        };
        if local.height() < authoritative_chain.height() {
            return ReconcileAction::ReplayFrom {
                // The strict comparison proves the local height is below
                // `u32::MAX`; saturating addition also keeps this total.
                next_height: local.height().saturating_add(1),
            };
        }
        if local.height() > authoritative_chain.height() {
            return ReconcileAction::RebuildRequired {
                reason: RebuildReason::LocalAhead,
            };
        }
        if local.block_hash() != authoritative_chain.block_hash() {
            return ReconcileAction::RebuildRequired {
                reason: RebuildReason::HashMismatch,
            };
        }
        match self.readiness {
            ProjectionReadiness::Ready(_) => ReconcileAction::Ready,
            ProjectionReadiness::Building => ReconcileAction::Finish,
            ProjectionReadiness::FailedClosed(_) => ReconcileAction::RebuildRequired {
                reason: RebuildReason::FailedClosed,
            },
        }
    }

    fn ready_checkpoint(&self) -> Result<OfflineProjectionCheckpoint, ProjectionUnavailable> {
        match self.readiness {
            ProjectionReadiness::Ready(checkpoint) => Ok(checkpoint),
            ProjectionReadiness::Building => Err(ProjectionUnavailable::Building),
            ProjectionReadiness::FailedClosed(fault) => {
                Err(ProjectionUnavailable::FailedClosed { fault })
            }
        }
    }

    /// Returns a plaintext copy of exact standard-script UTXOs for fixtures.
    fn fixture_live_utxos(
        &self,
        address: &AddrScript,
    ) -> Result<Vec<TransparentUtxo>, ProjectionUnavailable> {
        self.ready_checkpoint()?;
        Ok(self
            .state
            .addresses
            .get(address)
            .map_or_else(Vec::new, |state| {
                state.live_utxos.values().copied().collect()
            }))
    }

    /// Returns the append-only plaintext event history for fixture assertions.
    fn fixture_events(
        &self,
        address: &AddrScript,
    ) -> Result<Vec<UtxoEvent>, ProjectionUnavailable> {
        self.ready_checkpoint()?;
        Ok(self
            .state
            .addresses
            .get(address)
            .map_or_else(Vec::new, |state| state.events.clone()))
    }

    fn committed_checkpoint(&self) -> Option<OfflineProjectionCheckpoint> {
        self.cursor
            .checkpoint()
            .map(|chain| self.checkpoint_for(chain))
    }

    const fn checkpoint_for(&self, chain: PublicChainCheckpoint) -> OfflineProjectionCheckpoint {
        OfflineProjectionCheckpoint::new(
            chain,
            self.config.schema_version,
            self.config.key_epoch,
            self.config.projection_epoch,
        )
    }

    fn fail_closed(&mut self, error: &ProjectionError) {
        self.readiness = ProjectionReadiness::FailedClosed(error.fault());
    }
}

/// Synchronous completion boundary for the offline publication-order model.
pub(super) trait ProjectionEventSink {
    type Error;

    /// Returns `Ok` only after the event mutation has completed.
    ///
    /// `Err` may represent a rejected, partial, or indeterminate mutation; the
    /// coordinator therefore discards the whole sink candidate uniformly.
    fn append_and_wait(&mut self, event: UtxoEvent) -> Result<(), Self::Error>;
}

/// Owns one volatile sink candidate and publishes its rebuild checkpoint last.
pub(super) struct ProjectionCheckpointCoordinator<S, P = NoopProjectionCheckpointPublisher> {
    projection: OfflineFinalizedProjection,
    sink: Option<S>,
    publisher: Option<P>,
}

impl<S> ProjectionCheckpointCoordinator<S, NoopProjectionCheckpointPublisher>
where
    S: ProjectionEventSink,
{
    pub(super) fn new(config: ProjectionConfig, sink: S) -> Self {
        Self::with_publisher(config, sink, NoopProjectionCheckpointPublisher)
    }
}

impl<S, P> ProjectionCheckpointCoordinator<S, P>
where
    S: ProjectionEventSink,
    P: ProjectionCheckpointPublisher,
{
    pub(super) fn with_publisher(config: ProjectionConfig, sink: S, publisher: P) -> Self {
        Self {
            projection: OfflineFinalizedProjection::new(config),
            sink: Some(sink),
            publisher: Some(publisher),
        }
    }

    fn apply_finalized(
        &mut self,
        block: &IndexedBlock,
    ) -> Result<OfflineProjectionCheckpoint, ProjectionError> {
        if let Err(error) = self.projection.ensure_building() {
            return Err(self.terminate(error));
        }
        let staged = match self.projection.stage_block(block) {
            Ok(staged) => staged,
            Err(error) => return Err(self.terminate(error)),
        };
        let publication = match ProjectionPublication::new(
            staged.checkpoint,
            self.projection.config.schema_version(),
            self.projection.config.key_epoch(),
            self.projection.config.projection_epoch(),
            staged.event_log.root(),
        ) {
            Ok(publication) => publication,
            Err(_) => return Err(self.terminate(ProjectionError::Publication)),
        };
        let append_result = catch_unwind(AssertUnwindSafe(|| {
            self.append_staged_events(&staged.events)
        }));
        if !matches!(append_result, Ok(Ok(()))) {
            return Err(self.terminate(ProjectionError::EventSink));
        }
        let publication_result = catch_unwind(AssertUnwindSafe(|| {
            self.publish_staged_checkpoint(&publication)
        }));
        if !matches!(publication_result, Ok(Ok(()))) {
            return Err(self.terminate(ProjectionError::Publication));
        }
        Ok(self.projection.commit_staged(staged))
    }

    fn finish(
        &mut self,
        target: OfflineProjectionCheckpoint,
    ) -> Result<OfflineProjectionCheckpoint, ProjectionError> {
        match self.projection.finish(target) {
            Ok(checkpoint) => Ok(checkpoint),
            Err(error) => {
                self.drop_sink();
                self.drop_publisher();
                Err(error)
            }
        }
    }

    fn ready_checkpoint(&self) -> Result<OfflineProjectionCheckpoint, ProjectionUnavailable> {
        self.projection.ready_checkpoint()
    }

    fn committed_checkpoint(&self) -> Option<OfflineProjectionCheckpoint> {
        self.projection.committed_checkpoint()
    }

    pub(super) fn apply_finalized_chain(
        &mut self,
        block: &IndexedBlock,
    ) -> Result<PublicChainCheckpoint, ProjectionCoordinatorCommandError> {
        self.apply_finalized(block)
            .map(|checkpoint| checkpoint.chain())
            .map_err(|_| ProjectionCoordinatorCommandError::FailedClosed)
    }

    pub(super) fn finish_chain(
        &mut self,
        target: PublicChainCheckpoint,
    ) -> Result<PublicChainCheckpoint, ProjectionCoordinatorCommandError> {
        let target = self.projection.checkpoint_for(target);
        self.finish(target)
            .map(|checkpoint| checkpoint.chain())
            .map_err(|_| ProjectionCoordinatorCommandError::FailedClosed)
    }

    pub(super) fn status(&self) -> ProjectionCoordinatorStatus {
        match self.projection.readiness {
            ProjectionReadiness::Building => ProjectionCoordinatorStatus::Building {
                committed: self
                    .projection
                    .committed_checkpoint()
                    .map(|checkpoint| checkpoint.chain()),
            },
            ProjectionReadiness::Ready(checkpoint) => ProjectionCoordinatorStatus::Ready {
                checkpoint: checkpoint.chain(),
            },
            ProjectionReadiness::FailedClosed(_) => ProjectionCoordinatorStatus::FailedClosed {
                committed: self
                    .projection
                    .committed_checkpoint()
                    .map(|checkpoint| checkpoint.chain()),
            },
        }
    }

    pub(super) fn into_shutdown_parts(mut self) -> (ProjectionCoordinatorStatus, Option<S>) {
        let status = self.status();
        self.drop_publisher();
        let sink = self.sink.take();
        (status, sink)
    }

    /// Extracts the exact configuration, checkpoint, and sink only after finish.
    pub(super) fn into_ready_parts(
        mut self,
    ) -> Option<(ProjectionConfig, PublicChainCheckpoint, S)> {
        let ready = self
            .projection
            .ready_checkpoint()
            .ok()
            .map(|checkpoint| checkpoint.chain());
        self.drop_publisher();
        match (ready, self.sink.take()) {
            (Some(checkpoint), Some(sink)) => Some((self.projection.config, checkpoint, sink)),
            (Some(_), None) | (None, _) => None,
        }
    }

    fn append_staged_events(&mut self, events: &[UtxoEvent]) -> Result<(), ()> {
        let Some(sink) = self.sink.as_mut() else {
            return Err(());
        };
        for event in events.iter().copied() {
            if sink.append_and_wait(event).is_err() {
                return Err(());
            }
        }
        Ok(())
    }

    fn publish_staged_checkpoint(&mut self, publication: &ProjectionPublication) -> Result<(), ()> {
        let Some(publisher) = self.publisher.as_mut() else {
            return Err(());
        };
        publisher.publish_and_wait(publication).map_err(|_| ())
    }

    fn terminate(&mut self, error: ProjectionError) -> ProjectionError {
        self.projection.fail_closed(&error);
        self.drop_sink();
        self.drop_publisher();
        error
    }

    fn drop_sink(&mut self) {
        let Some(sink) = self.sink.take() else {
            return;
        };
        let _ = catch_unwind(AssertUnwindSafe(|| drop(sink)));
    }

    fn drop_publisher(&mut self) {
        let Some(publisher) = self.publisher.take() else {
            return;
        };
        let _ = catch_unwind(AssertUnwindSafe(|| drop(publisher)));
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ProjectionCoordinatorStatus {
    Building {
        committed: Option<PublicChainCheckpoint>,
    },
    Ready {
        checkpoint: PublicChainCheckpoint,
    },
    FailedClosed {
        committed: Option<PublicChainCheckpoint>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ProjectionCoordinatorCommandError {
    FailedClosed,
}

impl<S, P> fmt::Debug for ProjectionCheckpointCoordinator<S, P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ProjectionCheckpointCoordinator { ..REDACTED.. }")
    }
}

impl fmt::Debug for OfflineFinalizedProjection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OfflineFinalizedProjection")
            .field("readiness", &self.readiness)
            .field("addresses", &self.state.addresses.len())
            .field("seen_outputs", &self.state.seen_outputs.len())
            .field("live_outputs", &self.state.live_outputs.len())
            .field("events", &self.state.total_events)
            .finish_non_exhaustive()
    }
}

/// A ready-only fixture lookup was attempted in another lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProjectionUnavailable {
    Building,
    FailedClosed { fault: ProjectionFault },
}

impl fmt::Display for ProjectionUnavailable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Building => f.write_str("offline projection is still building"),
            Self::FailedClosed { fault } => {
                write!(f, "offline projection is failed closed: {fault:?}")
            }
        }
    }
}

impl std::error::Error for ProjectionUnavailable {}

/// Identifier-free offline ingest, lifecycle, or target failure.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ProjectionError {
    AlreadyFailedClosed {
        fault: ProjectionFault,
    },
    ApplyAfterReady,
    FinishAfterReadyWithDifferentTarget,
    ReplacementSourceNotReady,
    CanonicalChain(CanonicalChainError),
    Extraction(TransparentEventError),
    EventSink,
    Publication,
    EventLogCounterOverflow,
    DuplicateCreatedOutpoint,
    UnknownSpentOutpoint,
    MissingStandardAddress,
    UnexpectedNonStandardAddress,
    AddressClassMismatch,
    InvalidStandardAddress,
    CapacityExceeded {
        dimension: CapacityDimension,
        capacity: usize,
    },
    CounterOverflow {
        dimension: CapacityDimension,
    },
    CorruptAddressState,
    Record(UtxoRecordError),
    TargetNetworkMismatch,
    TargetSchemaVersionMismatch,
    TargetKeyEpochMismatch,
    TargetProjectionEpochMismatch,
    TargetNotReached {
        target_height: u32,
        committed_height: Option<u32>,
    },
    TargetExceeded {
        target_height: u32,
        committed_height: u32,
    },
    TargetHashMismatch {
        height: u32,
    },
}

impl ProjectionError {
    const fn fault(&self) -> ProjectionFault {
        match self {
            Self::AlreadyFailedClosed { fault } => *fault,
            Self::ApplyAfterReady
            | Self::FinishAfterReadyWithDifferentTarget
            | Self::ReplacementSourceNotReady => ProjectionFault::Lifecycle,
            Self::CanonicalChain(_) => ProjectionFault::CanonicalChain,
            Self::Extraction(_) => ProjectionFault::Extraction,
            Self::EventSink => ProjectionFault::EventSink,
            Self::Publication => ProjectionFault::Publication,
            Self::EventLogCounterOverflow => ProjectionFault::CorruptState,
            Self::DuplicateCreatedOutpoint => ProjectionFault::DuplicateOutput,
            Self::UnknownSpentOutpoint => ProjectionFault::UnknownSpend,
            Self::MissingStandardAddress
            | Self::UnexpectedNonStandardAddress
            | Self::AddressClassMismatch
            | Self::InvalidStandardAddress => ProjectionFault::InvalidEvent,
            Self::CapacityExceeded { .. } | Self::CounterOverflow { .. } => {
                ProjectionFault::Capacity
            }
            Self::CorruptAddressState => ProjectionFault::CorruptState,
            Self::Record(_) => ProjectionFault::Record,
            Self::TargetNetworkMismatch
            | Self::TargetSchemaVersionMismatch
            | Self::TargetKeyEpochMismatch
            | Self::TargetProjectionEpochMismatch
            | Self::TargetNotReached { .. }
            | Self::TargetExceeded { .. }
            | Self::TargetHashMismatch { .. } => ProjectionFault::Target,
        }
    }
}

impl fmt::Display for ProjectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyFailedClosed { fault } => {
                write!(f, "offline projection is already failed closed: {fault:?}")
            }
            Self::ApplyAfterReady => {
                f.write_str("offline projection rejected block ingest after readiness")
            }
            Self::FinishAfterReadyWithDifferentTarget => {
                f.write_str("ready offline projection received a different finish target")
            }
            Self::ReplacementSourceNotReady => {
                f.write_str("offline projection replacement requires a ready source")
            }
            Self::CanonicalChain(error) => {
                write!(f, "offline projection canonical-chain validation failed: {error}")
            }
            Self::Extraction(error) => {
                write!(f, "offline projection event extraction failed: {error}")
            }
            Self::EventSink => {
                f.write_str("offline projection event sink failed closed")
            }
            Self::Publication => {
                f.write_str("offline projection checkpoint publication failed closed")
            }
            Self::EventLogCounterOverflow => {
                f.write_str("offline projection event-log counter overflowed")
            }
            Self::DuplicateCreatedOutpoint => {
                f.write_str("offline projection rejected a previously seen created outpoint")
            }
            Self::UnknownSpentOutpoint => {
                f.write_str("offline projection spend references an unknown or spent outpoint")
            }
            Self::MissingStandardAddress => {
                f.write_str("offline projection standard output has no exact address identity")
            }
            Self::UnexpectedNonStandardAddress => {
                f.write_str("offline projection nonstandard output unexpectedly has an address")
            }
            Self::AddressClassMismatch => {
                f.write_str("offline projection address and script classifications disagree")
            }
            Self::InvalidStandardAddress => {
                f.write_str("offline projection could not reconstruct a standard locking script")
            }
            Self::CapacityExceeded {
                dimension,
                capacity,
            } => write!(
                f,
                "offline projection {} capacity {capacity} exceeded",
                dimension
            ),
            Self::CounterOverflow { dimension } => {
                write!(f, "offline projection {} counter overflowed", dimension)
            }
            Self::CorruptAddressState => {
                f.write_str("offline projection internal address state is inconsistent")
            }
            Self::Record(error) => write!(f, "offline projection record rejected: {error}"),
            Self::TargetNetworkMismatch => {
                f.write_str("offline projection target network does not match configuration")
            }
            Self::TargetSchemaVersionMismatch => {
                f.write_str("offline projection target schema version does not match configuration")
            }
            Self::TargetKeyEpochMismatch => {
                f.write_str("offline projection target key epoch does not match configuration")
            }
            Self::TargetProjectionEpochMismatch => {
                f.write_str("offline projection target lifecycle epoch does not match configuration")
            }
            Self::TargetNotReached {
                target_height,
                committed_height,
            } => match committed_height {
                Some(committed_height) => write!(
                    f,
                    "offline projection target height {target_height} was not reached; committed height is {committed_height}"
                ),
                None => write!(
                    f,
                    "offline projection target height {target_height} was not reached; no block is committed"
                ),
            },
            Self::TargetExceeded {
                target_height,
                committed_height,
            } => write!(
                f,
                "offline projection committed height {committed_height} is ahead of target height {target_height}"
            ),
            Self::TargetHashMismatch { height } => write!(
                f,
                "offline projection target hash mismatches at public height {height}"
            ),
        }
    }
}

impl std::error::Error for ProjectionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::CanonicalChain(error) => Some(error),
            Self::Extraction(error) => Some(error),
            Self::Record(error) => Some(error),
            Self::AlreadyFailedClosed { .. }
            | Self::ApplyAfterReady
            | Self::FinishAfterReadyWithDifferentTarget
            | Self::ReplacementSourceNotReady
            | Self::EventSink
            | Self::Publication
            | Self::EventLogCounterOverflow
            | Self::DuplicateCreatedOutpoint
            | Self::UnknownSpentOutpoint
            | Self::MissingStandardAddress
            | Self::UnexpectedNonStandardAddress
            | Self::AddressClassMismatch
            | Self::InvalidStandardAddress
            | Self::CapacityExceeded { .. }
            | Self::CounterOverflow { .. }
            | Self::CorruptAddressState
            | Self::TargetNetworkMismatch
            | Self::TargetSchemaVersionMismatch
            | Self::TargetKeyEpochMismatch
            | Self::TargetProjectionEpochMismatch
            | Self::TargetNotReached { .. }
            | Self::TargetExceeded { .. }
            | Self::TargetHashMismatch { .. } => None,
        }
    }
}

/// Identifier-free bounded collection dimension.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CapacityDimension {
    SeenOutputs,
    LiveOutputs,
    StandardAddresses,
    TotalEvents,
    AddressEvents,
}

impl fmt::Display for CapacityDimension {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SeenOutputs => f.write_str("seen-output"),
            Self::LiveOutputs => f.write_str("live-output"),
            Self::StandardAddresses => f.write_str("standard-address"),
            Self::TotalEvents => f.write_str("total-event"),
            Self::AddressEvents => f.write_str("per-address-event"),
        }
    }
}

fn checked_capacity_increment(
    current: usize,
    capacities: ProjectionCapacities,
    dimension: CapacityDimension,
) -> Result<usize, ProjectionError> {
    let next = current
        .checked_add(1)
        .ok_or(ProjectionError::CounterOverflow { dimension })?;
    let capacity = capacities.limit(dimension).get();
    if next > capacity {
        return Err(ProjectionError::CapacityExceeded {
            dimension,
            capacity,
        });
    }
    Ok(next)
}

const fn map_script_class(script_class: ScriptType) -> UtxoScriptClass {
    match script_class {
        ScriptType::P2PKH => UtxoScriptClass::PayToPublicKeyHash,
        ScriptType::P2SH => UtxoScriptClass::PayToScriptHash,
        ScriptType::NonStandard => UtxoScriptClass::NonStandard,
    }
}

const fn canonical_network_tag(network: CanonicalNetwork) -> u8 {
    match network {
        CanonicalNetwork::Mainnet => 1,
        CanonicalNetwork::Testnet => 2,
        CanonicalNetwork::Regtest => 3,
    }
}

fn finalize_blake2s(hasher: Blake2s256) -> [u8; 32] {
    let digest = hasher.finalize();
    let mut bytes = [0; 32];
    bytes.copy_from_slice(&digest);
    bytes
}

#[cfg(test)]
mod tests {
    use std::{
        cell::{Cell, RefCell},
        rc::Rc,
    };

    use super::*;
    use zaino_state::{BlockHash, TxInCompact};

    use crate::zaino_fixtures::{
        indexed_block, output, projection_chain, transaction, FixtureResult, SECOND_HASH,
        THIRD_HASH,
    };

    const SCHEMA_VERSION: u32 = 1;
    const KEY_EPOCH: u64 = 7;
    const PROJECTION_EPOCH: u64 = 11;

    #[derive(Clone)]
    struct SinkObservation {
        events: Rc<RefCell<Vec<UtxoEvent>>>,
        attempts: Rc<Cell<usize>>,
        dropped: Rc<Cell<bool>>,
    }

    struct RecordingSink {
        observation: SinkObservation,
        fail_at: Option<usize>,
        panic_at: Option<usize>,
        panic_on_drop: bool,
    }

    #[derive(Clone)]
    struct PublisherObservation {
        checkpoints: Rc<RefCell<Vec<PublicChainCheckpoint>>>,
        roots: Rc<RefCell<Vec<ProjectionEventLogRoot>>>,
        attempts: Rc<Cell<usize>>,
        dropped: Rc<Cell<bool>>,
    }

    struct RecordingPublisher {
        observation: PublisherObservation,
        sink_attempts: Rc<Cell<usize>>,
        required_sink_attempts: Vec<usize>,
        fail_at: Option<usize>,
        panic_at: Option<usize>,
        panic_on_drop: bool,
    }

    impl RecordingSink {
        fn new(fail_at: Option<usize>) -> (Self, SinkObservation) {
            Self::with_faults(fail_at, None, false)
        }

        fn with_faults(
            fail_at: Option<usize>,
            panic_at: Option<usize>,
            panic_on_drop: bool,
        ) -> (Self, SinkObservation) {
            let observation = SinkObservation {
                events: Rc::new(RefCell::new(Vec::new())),
                attempts: Rc::new(Cell::new(0)),
                dropped: Rc::new(Cell::new(false)),
            };
            (
                Self {
                    observation: observation.clone(),
                    fail_at,
                    panic_at,
                    panic_on_drop,
                },
                observation,
            )
        }
    }

    impl ProjectionEventSink for RecordingSink {
        type Error = ();

        fn append_and_wait(&mut self, event: UtxoEvent) -> Result<(), Self::Error> {
            let attempt = self.observation.attempts.get();
            self.observation.attempts.set(attempt.saturating_add(1));
            if self.fail_at == Some(attempt) {
                return Err(());
            }
            self.observation.events.borrow_mut().push(event);
            if self.panic_at == Some(attempt) {
                panic!("identifier-free injected sink panic");
            }
            Ok(())
        }
    }

    impl Drop for RecordingSink {
        fn drop(&mut self) {
            self.observation.dropped.set(true);
            assert!(!self.panic_on_drop, "identifier-free injected drop panic");
        }
    }

    impl RecordingPublisher {
        fn with_faults(
            sink_observation: &SinkObservation,
            required_sink_attempts: Vec<usize>,
            fail_at: Option<usize>,
            panic_at: Option<usize>,
            panic_on_drop: bool,
        ) -> (Self, PublisherObservation) {
            let observation = PublisherObservation {
                checkpoints: Rc::new(RefCell::new(Vec::new())),
                roots: Rc::new(RefCell::new(Vec::new())),
                attempts: Rc::new(Cell::new(0)),
                dropped: Rc::new(Cell::new(false)),
            };
            (
                Self {
                    observation: observation.clone(),
                    sink_attempts: Rc::clone(&sink_observation.attempts),
                    required_sink_attempts,
                    fail_at,
                    panic_at,
                    panic_on_drop,
                },
                observation,
            )
        }
    }

    impl ProjectionCheckpointPublisher for RecordingPublisher {
        type Error = ();

        fn publish_and_wait(
            &mut self,
            publication: &ProjectionPublication,
        ) -> Result<(), Self::Error> {
            let attempt = self.observation.attempts.get();
            let required = self
                .required_sink_attempts
                .get(attempt)
                .copied()
                .ok_or(())?;
            if self.sink_attempts.get() != required {
                return Err(());
            }
            self.observation.attempts.set(attempt.saturating_add(1));
            self.observation
                .checkpoints
                .borrow_mut()
                .push(publication.chain());
            self.observation
                .roots
                .borrow_mut()
                .push(publication.event_log_root());
            if self.panic_at == Some(attempt) {
                panic!("identifier-free injected publisher panic");
            }
            if self.fail_at == Some(attempt) {
                Err(())
            } else {
                Ok(())
            }
        }
    }

    impl Drop for RecordingPublisher {
        fn drop(&mut self) {
            self.observation.dropped.set(true);
            assert!(
                !self.panic_on_drop,
                "identifier-free injected publisher drop panic"
            );
        }
    }

    fn capacities() -> Result<ProjectionCapacities, ProjectionConfigError> {
        ProjectionCapacities::new(64, 64, 16, 128, 32)
    }

    fn config() -> Result<ProjectionConfig, ProjectionConfigError> {
        ProjectionConfig::new(
            CanonicalNetwork::Regtest,
            SCHEMA_VERSION,
            KEY_EPOCH,
            PROJECTION_EPOCH,
            capacities()?,
        )
    }

    fn target(
        height: u32,
        block_hash: BlockHash,
        schema_version: u32,
        key_epoch: u64,
    ) -> OfflineProjectionCheckpoint {
        target_with_projection_epoch(
            height,
            block_hash,
            schema_version,
            key_epoch,
            PROJECTION_EPOCH,
        )
    }

    fn target_with_projection_epoch(
        height: u32,
        block_hash: BlockHash,
        schema_version: u32,
        key_epoch: u64,
        projection_epoch: u64,
    ) -> OfflineProjectionCheckpoint {
        OfflineProjectionCheckpoint::new(
            PublicChainCheckpoint::new(CanonicalNetwork::Regtest, height, block_hash),
            schema_version,
            key_epoch,
            projection_epoch,
        )
    }

    fn canonical_target(height: u32, block_hash: BlockHash) -> OfflineProjectionCheckpoint {
        target(height, block_hash, SCHEMA_VERSION, KEY_EPOCH)
    }

    fn address(hash: [u8; 20], script_type: ScriptType) -> AddrScript {
        AddrScript::new(hash, script_type as u8)
    }

    fn expected_projected_events() -> [UtxoEvent; 7] {
        [
            UtxoEvent::created(
                [0x11; 32],
                0,
                50,
                0,
                UtxoScriptClass::PayToPublicKeyHash,
                [0xa1; 20],
            ),
            UtxoEvent::created(
                [0x11; 32],
                1,
                60,
                0,
                UtxoScriptClass::PayToPublicKeyHash,
                [0xa1; 20],
            ),
            UtxoEvent::spent(
                [0x11; 32],
                0,
                50,
                0,
                UtxoScriptClass::PayToPublicKeyHash,
                [0xa1; 20],
            ),
            UtxoEvent::created(
                [0x22; 32],
                0,
                40,
                0,
                UtxoScriptClass::PayToScriptHash,
                [0xb2; 20],
            ),
            UtxoEvent::spent(
                [0x22; 32],
                0,
                40,
                1,
                UtxoScriptClass::PayToScriptHash,
                [0xb2; 20],
            ),
            UtxoEvent::created(
                [0x33; 32],
                0,
                30,
                1,
                UtxoScriptClass::PayToPublicKeyHash,
                [0xa1; 20],
            ),
            UtxoEvent::created(
                [0x33; 32],
                1,
                20,
                1,
                UtxoScriptClass::PayToScriptHash,
                [0xc3; 20],
            ),
        ]
    }

    fn expected_utxo(
        txid: [u8; 32],
        output_index: u32,
        value_zat: u64,
        height: u32,
        address: &AddrScript,
    ) -> FixtureResult<TransparentUtxo> {
        let script = address
            .to_script_pubkey()
            .ok_or("fixture address must reconstruct a standard script")?;
        Ok(TransparentUtxo::new(
            txid,
            output_index,
            value_zat,
            height,
            &script,
        )?)
    }

    #[test]
    fn checkpoint_coordinator_preserves_event_order_and_skips_nonstandard_history_writes(
    ) -> FixtureResult<()> {
        let blocks = projection_chain()?;
        let (sink, observation) = RecordingSink::new(None);
        let mut coordinator = ProjectionCheckpointCoordinator::new(config()?, sink);

        let first = coordinator.apply_finalized(&blocks[0])?;
        assert_eq!(
            first,
            canonical_target(0, CanonicalNetwork::Regtest.genesis_hash())
        );
        assert_eq!(observation.attempts.get(), 4);

        let second = coordinator.apply_finalized(&blocks[1])?;
        assert_eq!(second, canonical_target(1, BlockHash(SECOND_HASH)));
        assert_eq!(observation.attempts.get(), 7);

        let third = coordinator.apply_finalized(&blocks[2])?;
        assert_eq!(third, canonical_target(2, BlockHash(THIRD_HASH)));
        assert_eq!(observation.attempts.get(), 7);
        assert_eq!(
            observation.events.borrow().as_slice(),
            &expected_projected_events()
        );

        assert_eq!(coordinator.finish(third)?, third);
        assert_eq!(coordinator.ready_checkpoint(), Ok(third));
        assert!(!observation.dropped.get());
        Ok(())
    }

    #[test]
    fn checkpoint_coordinator_publishes_after_sink_completion_before_commit() -> FixtureResult<()> {
        let blocks = projection_chain()?;
        let (sink, sink_observation) = RecordingSink::new(None);
        let (publisher, publication_observation) =
            RecordingPublisher::with_faults(&sink_observation, vec![4, 7, 7], None, None, false);
        let mut coordinator =
            ProjectionCheckpointCoordinator::with_publisher(config()?, sink, publisher);

        let first = coordinator.apply_finalized(&blocks[0])?;
        assert_eq!(publication_observation.attempts.get(), 1);
        assert_eq!(
            publication_observation.checkpoints.borrow().as_slice(),
            &[first.chain()]
        );
        assert_eq!(coordinator.committed_checkpoint(), Some(first));

        let second = coordinator.apply_finalized(&blocks[1])?;
        assert_eq!(publication_observation.attempts.get(), 2);
        assert_eq!(
            publication_observation.checkpoints.borrow().as_slice(),
            &[first.chain(), second.chain()]
        );
        assert_ne!(
            publication_observation.roots.borrow()[0],
            publication_observation.roots.borrow()[1]
        );
        assert_eq!(coordinator.committed_checkpoint(), Some(second));
        Ok(())
    }

    #[test]
    fn checkpoint_publication_failure_keeps_prior_commit_and_forbids_retry() -> FixtureResult<()> {
        let blocks = projection_chain()?;
        let (sink, sink_observation) = RecordingSink::new(None);
        let (publisher, publication_observation) =
            RecordingPublisher::with_faults(&sink_observation, vec![4, 7], Some(1), None, false);
        let mut coordinator =
            ProjectionCheckpointCoordinator::with_publisher(config()?, sink, publisher);
        let committed = coordinator.apply_finalized(&blocks[0])?;

        assert_eq!(
            coordinator.apply_finalized(&blocks[1]),
            Err(ProjectionError::Publication)
        );
        assert_eq!(publication_observation.attempts.get(), 2);
        assert_eq!(coordinator.committed_checkpoint(), Some(committed));
        assert!(sink_observation.dropped.get());
        assert!(publication_observation.dropped.get());
        assert!(matches!(
            coordinator.ready_checkpoint(),
            Err(ProjectionUnavailable::FailedClosed {
                fault: ProjectionFault::Publication,
            })
        ));
        assert_eq!(
            coordinator.apply_finalized(&blocks[1]),
            Err(ProjectionError::AlreadyFailedClosed {
                fault: ProjectionFault::Publication,
            })
        );
        assert_eq!(sink_observation.attempts.get(), 7);
        Ok(())
    }

    #[test]
    fn checkpoint_coordinator_contains_publisher_and_drop_panics() -> FixtureResult<()> {
        let blocks = projection_chain()?;
        let (sink, sink_observation) = RecordingSink::new(None);
        let (publisher, publication_observation) =
            RecordingPublisher::with_faults(&sink_observation, vec![4], None, Some(0), true);
        let mut coordinator =
            ProjectionCheckpointCoordinator::with_publisher(config()?, sink, publisher);

        assert_eq!(
            coordinator.apply_finalized(&blocks[0]),
            Err(ProjectionError::Publication)
        );
        assert!(sink_observation.dropped.get());
        assert!(publication_observation.dropped.get());
        assert_eq!(coordinator.committed_checkpoint(), None);
        assert!(matches!(
            coordinator.ready_checkpoint(),
            Err(ProjectionUnavailable::FailedClosed {
                fault: ProjectionFault::Publication,
            })
        ));
        Ok(())
    }

    #[test]
    fn checkpoint_coordinator_stages_late_validation_failure_before_sink_calls() -> FixtureResult<()>
    {
        let blocks = projection_chain()?;
        let (sink, observation) = RecordingSink::new(None);
        let mut coordinator = ProjectionCheckpointCoordinator::new(config()?, sink);
        let committed = coordinator.apply_finalized(&blocks[0])?;
        let attempts_before = observation.attempts.get();
        let events_before = observation.events.borrow().len();
        let spend = TxInCompact::new([0x22; 32], 0);
        let first_spend = transaction(0, [0x57; 32], vec![spend], Vec::new());
        let second_spend = transaction(1, [0x58; 32], vec![spend], Vec::new());
        let invalid = indexed_block(
            1,
            SECOND_HASH,
            CanonicalNetwork::Regtest.genesis_hash().0,
            vec![first_spend, second_spend],
        )?;

        assert_eq!(
            coordinator.apply_finalized(&invalid),
            Err(ProjectionError::UnknownSpentOutpoint)
        );
        assert_eq!(observation.attempts.get(), attempts_before);
        assert_eq!(observation.events.borrow().len(), events_before);
        assert_eq!(coordinator.committed_checkpoint(), Some(committed));
        assert!(observation.dropped.get());
        assert!(matches!(
            coordinator.ready_checkpoint(),
            Err(ProjectionUnavailable::FailedClosed {
                fault: ProjectionFault::UnknownSpend,
            })
        ));
        assert_eq!(
            coordinator.apply_finalized(&blocks[1]),
            Err(ProjectionError::AlreadyFailedClosed {
                fault: ProjectionFault::UnknownSpend,
            })
        );
        assert_eq!(observation.attempts.get(), attempts_before);
        Ok(())
    }

    #[test]
    fn checkpoint_coordinator_sink_failure_keeps_prior_checkpoint_and_stops_calls(
    ) -> FixtureResult<()> {
        let blocks = projection_chain()?;
        let (sink, observation) = RecordingSink::new(Some(5));
        let mut coordinator = ProjectionCheckpointCoordinator::new(config()?, sink);
        let committed = coordinator.apply_finalized(&blocks[0])?;

        assert_eq!(
            coordinator.apply_finalized(&blocks[1]),
            Err(ProjectionError::EventSink)
        );
        assert_eq!(observation.attempts.get(), 6);
        assert_eq!(
            observation.events.borrow().as_slice(),
            &expected_projected_events()[..5]
        );
        assert_eq!(coordinator.committed_checkpoint(), Some(committed));
        assert!(observation.dropped.get());
        assert!(matches!(
            coordinator.ready_checkpoint(),
            Err(ProjectionUnavailable::FailedClosed {
                fault: ProjectionFault::EventSink,
            })
        ));

        assert_eq!(
            coordinator.apply_finalized(&blocks[1]),
            Err(ProjectionError::AlreadyFailedClosed {
                fault: ProjectionFault::EventSink,
            })
        );
        assert_eq!(observation.attempts.get(), 6);
        Ok(())
    }

    #[test]
    fn checkpoint_coordinator_catches_sink_panic_and_forbids_retry() -> FixtureResult<()> {
        let blocks = projection_chain()?;
        let (sink, observation) = RecordingSink::with_faults(None, Some(5), false);
        let mut coordinator = ProjectionCheckpointCoordinator::new(config()?, sink);
        let committed = coordinator.apply_finalized(&blocks[0])?;

        assert_eq!(
            coordinator.apply_finalized(&blocks[1]),
            Err(ProjectionError::EventSink)
        );
        assert_eq!(observation.attempts.get(), 6);
        assert_eq!(observation.events.borrow().len(), 6);
        assert_eq!(coordinator.committed_checkpoint(), Some(committed));
        assert!(observation.dropped.get());
        assert!(matches!(
            coordinator.ready_checkpoint(),
            Err(ProjectionUnavailable::FailedClosed {
                fault: ProjectionFault::EventSink,
            })
        ));

        assert_eq!(
            coordinator.apply_finalized(&blocks[1]),
            Err(ProjectionError::AlreadyFailedClosed {
                fault: ProjectionFault::EventSink,
            })
        );
        assert_eq!(observation.attempts.get(), 6);
        Ok(())
    }

    #[test]
    fn checkpoint_coordinator_finish_failure_contains_sink_drop_panic() -> FixtureResult<()> {
        let blocks = projection_chain()?;
        let (sink, observation) = RecordingSink::with_faults(None, None, true);
        let mut coordinator = ProjectionCheckpointCoordinator::new(config()?, sink);
        let committed = coordinator.apply_finalized(&blocks[0])?;

        assert!(matches!(
            coordinator.finish(canonical_target(1, BlockHash(SECOND_HASH))),
            Err(ProjectionError::TargetNotReached {
                target_height: 1,
                committed_height: Some(0),
            })
        ));
        assert!(observation.dropped.get());
        assert_eq!(observation.attempts.get(), 4);
        assert_eq!(coordinator.committed_checkpoint(), Some(committed));
        assert!(matches!(
            coordinator.ready_checkpoint(),
            Err(ProjectionUnavailable::FailedClosed {
                fault: ProjectionFault::Target,
            })
        ));

        assert_eq!(
            coordinator.apply_finalized(&blocks[1]),
            Err(ProjectionError::AlreadyFailedClosed {
                fault: ProjectionFault::Target,
            })
        );
        assert_eq!(observation.attempts.get(), 4);
        Ok(())
    }

    #[test]
    fn checkpoint_coordinator_debug_and_sink_error_are_redacted() -> FixtureResult<()> {
        let (sink, _observation) = RecordingSink::new(None);
        let coordinator = ProjectionCheckpointCoordinator::new(config()?, sink);

        assert_eq!(
            format!("{coordinator:?}"),
            "ProjectionCheckpointCoordinator { ..REDACTED.. }"
        );
        assert_eq!(
            ProjectionError::EventSink.to_string(),
            "offline projection event sink failed closed"
        );
        Ok(())
    }

    #[test]
    fn projection_build_has_exact_multi_output_and_spend_semantics() -> FixtureResult<()> {
        let blocks = projection_chain()?;
        let projection = OfflineFinalizedProjection::build(
            config()?,
            canonical_target(2, BlockHash(THIRD_HASH)),
            blocks.iter(),
        )?;
        let address_a = address([0xa1; 20], ScriptType::P2PKH);
        let address_b = address([0xb2; 20], ScriptType::P2SH);
        let address_c = address([0xc3; 20], ScriptType::P2SH);
        let absent = address([0xee; 20], ScriptType::P2PKH);

        assert_eq!(
            projection.fixture_live_utxos(&address_a)?,
            vec![
                expected_utxo([0x11; 32], 1, 60, 0, &address_a)?,
                expected_utxo([0x33; 32], 0, 30, 1, &address_a)?,
            ]
        );
        assert!(projection.fixture_live_utxos(&address_b)?.is_empty());
        assert_eq!(
            projection.fixture_live_utxos(&address_c)?,
            vec![expected_utxo([0x33; 32], 1, 20, 1, &address_c)?]
        );
        assert!(projection.fixture_live_utxos(&absent)?.is_empty());
        assert_eq!(projection.state.live_outputs.len(), 3);
        assert_eq!(projection.state.seen_outputs.len(), 6);

        let expected_address_a_events = expected_projected_events()
            .into_iter()
            .filter(|event| event.script_hash() == &[0xa1; 20])
            .collect::<Vec<_>>();
        assert_eq!(
            projection.fixture_events(&address_a)?,
            expected_address_a_events
        );
        assert_eq!(projection.fixture_events(&address_b)?.len(), 2);
        assert_eq!(projection.fixture_events(&address_c)?.len(), 1);
        assert_eq!(projection.state.total_events, 7);
        assert_eq!(
            projection.ready_checkpoint()?,
            canonical_target(2, BlockHash(THIRD_HASH))
        );
        Ok(())
    }

    #[test]
    fn identical_rebuilds_have_identical_semantic_state() -> FixtureResult<()> {
        let blocks = projection_chain()?;
        let target = canonical_target(2, BlockHash(THIRD_HASH));
        let first = OfflineFinalizedProjection::build(config()?, target, blocks.iter())?;
        let second = OfflineFinalizedProjection::build(config()?, target, blocks.iter())?;

        assert_eq!(first.ready_checkpoint()?, second.ready_checkpoint()?);
        assert!(first.state == second.state);
        assert_eq!(first.event_log.root(), second.event_log.root());
        Ok(())
    }

    #[test]
    fn semantic_root_changes_only_with_the_projected_event_stream() -> FixtureResult<()> {
        let blocks = projection_chain()?;
        let empty_root = OfflineFinalizedProjection::new(config()?).event_log.root();
        let mut first = OfflineFinalizedProjection::new(config()?);
        first.apply_finalized(&blocks[0])?;
        let first_root = first.event_log.root();
        assert_ne!(first_root, empty_root);

        first.apply_finalized(&blocks[1])?;
        let second_root = first.event_log.root();
        assert_ne!(second_root, first_root);

        first.apply_finalized(&blocks[2])?;
        assert_eq!(first.event_log.root(), second_root);
        Ok(())
    }

    #[test]
    fn late_block_failure_preserves_state_and_latches_unavailability() -> FixtureResult<()> {
        let blocks = projection_chain()?;
        let mut projection = OfflineFinalizedProjection::new(config()?);
        let committed = projection.apply_finalized(&blocks[0])?;
        let before = projection.state.clone();
        let valid_create = transaction(
            0,
            [0x55; 32],
            Vec::new(),
            vec![output(10, [0xa1; 20], ScriptType::P2PKH)?],
        );
        let late_unknown_spend = transaction(
            1,
            [0x56; 32],
            vec![TxInCompact::new([0xff; 32], 0)],
            Vec::new(),
        );
        let invalid = indexed_block(
            1,
            SECOND_HASH,
            CanonicalNetwork::Regtest.genesis_hash().0,
            vec![valid_create, late_unknown_spend],
        )?;

        assert_eq!(
            projection.apply_finalized(&invalid),
            Err(ProjectionError::UnknownSpentOutpoint)
        );
        assert!(projection.state == before);
        assert_eq!(projection.committed_checkpoint(), Some(committed));
        assert!(matches!(
            projection.fixture_live_utxos(&address([0xa1; 20], ScriptType::P2PKH)),
            Err(ProjectionUnavailable::FailedClosed {
                fault: ProjectionFault::UnknownSpend,
            })
        ));
        assert!(matches!(
            projection.apply_finalized(&blocks[1]),
            Err(ProjectionError::AlreadyFailedClosed {
                fault: ProjectionFault::UnknownSpend,
            })
        ));
        Ok(())
    }

    #[test]
    fn double_spend_rolls_back_the_entire_staged_block() -> FixtureResult<()> {
        let blocks = projection_chain()?;
        let mut projection = OfflineFinalizedProjection::new(config()?);
        let committed = projection.apply_finalized(&blocks[0])?;
        let before = projection.state.clone();
        let spend = TxInCompact::new([0x22; 32], 0);
        let first_spend = transaction(0, [0x57; 32], vec![spend], Vec::new());
        let second_spend = transaction(1, [0x58; 32], vec![spend], Vec::new());
        let invalid = indexed_block(
            1,
            SECOND_HASH,
            CanonicalNetwork::Regtest.genesis_hash().0,
            vec![first_spend, second_spend],
        )?;

        assert_eq!(
            projection.apply_finalized(&invalid),
            Err(ProjectionError::UnknownSpentOutpoint)
        );
        assert!(projection.state == before);
        assert_eq!(projection.committed_checkpoint(), Some(committed));
        assert!(matches!(
            projection.ready_checkpoint(),
            Err(ProjectionUnavailable::FailedClosed {
                fault: ProjectionFault::UnknownSpend,
            })
        ));
        Ok(())
    }

    #[test]
    fn duplicate_outpoint_after_spend_fails_the_whole_block() -> FixtureResult<()> {
        let txid = [0x61; 32];
        let create = transaction(
            0,
            txid,
            Vec::new(),
            vec![output(10, [0xa1; 20], ScriptType::P2PKH)?],
        );
        let spend = transaction(1, [0x62; 32], vec![TxInCompact::new(txid, 0)], Vec::new());
        let recreate = transaction(
            2,
            txid,
            Vec::new(),
            vec![output(11, [0xa1; 20], ScriptType::P2PKH)?],
        );
        let block = indexed_block(
            0,
            CanonicalNetwork::Regtest.genesis_hash().0,
            [0; 32],
            vec![create, spend, recreate],
        )?;
        let mut projection = OfflineFinalizedProjection::new(config()?);

        assert_eq!(
            projection.apply_finalized(&block),
            Err(ProjectionError::DuplicateCreatedOutpoint)
        );
        assert!(projection.state.seen_outputs.is_empty());
        assert_eq!(projection.committed_checkpoint(), None);
        assert!(matches!(
            projection.ready_checkpoint(),
            Err(ProjectionUnavailable::FailedClosed {
                fault: ProjectionFault::DuplicateOutput,
            })
        ));
        Ok(())
    }

    fn capacity_genesis(same_address: bool) -> FixtureResult<IndexedBlock> {
        let second_hash = if same_address { [0xa1; 20] } else { [0xb2; 20] };
        let create = transaction(
            0,
            [0x71; 32],
            Vec::new(),
            vec![
                output(10, [0xa1; 20], ScriptType::P2PKH)?,
                output(11, second_hash, ScriptType::P2PKH)?,
            ],
        );
        indexed_block(
            0,
            CanonicalNetwork::Regtest.genesis_hash().0,
            [0; 32],
            vec![create],
        )
    }

    #[test]
    fn every_collection_capacity_fails_closed_before_commit() -> FixtureResult<()> {
        let cases = [
            (
                CapacityDimension::SeenOutputs,
                ProjectionCapacities::new(1, 8, 8, 8, 8)?,
                true,
            ),
            (
                CapacityDimension::LiveOutputs,
                ProjectionCapacities::new(8, 1, 8, 8, 8)?,
                true,
            ),
            (
                CapacityDimension::StandardAddresses,
                ProjectionCapacities::new(8, 8, 1, 8, 8)?,
                false,
            ),
            (
                CapacityDimension::TotalEvents,
                ProjectionCapacities::new(8, 8, 8, 1, 8)?,
                true,
            ),
            (
                CapacityDimension::AddressEvents,
                ProjectionCapacities::new(8, 8, 8, 8, 1)?,
                true,
            ),
        ];

        for (dimension, capacities, same_address) in cases {
            let config = ProjectionConfig::new(
                CanonicalNetwork::Regtest,
                SCHEMA_VERSION,
                KEY_EPOCH,
                PROJECTION_EPOCH,
                capacities,
            )?;
            let mut projection = OfflineFinalizedProjection::new(config);
            assert_eq!(
                projection.apply_finalized(&capacity_genesis(same_address)?),
                Err(ProjectionError::CapacityExceeded {
                    dimension,
                    capacity: 1,
                })
            );
            assert!(projection.state.seen_outputs.is_empty());
            assert_eq!(projection.committed_checkpoint(), None);
            assert!(matches!(
                projection.ready_checkpoint(),
                Err(ProjectionUnavailable::FailedClosed {
                    fault: ProjectionFault::Capacity,
                })
            ));
        }

        assert_eq!(
            checked_capacity_increment(usize::MAX, capacities()?, CapacityDimension::SeenOutputs,),
            Err(ProjectionError::CounterOverflow {
                dimension: CapacityDimension::SeenOutputs,
            })
        );
        Ok(())
    }

    fn assert_provenance_failure(
        initial: Option<&IndexedBlock>,
        invalid: &IndexedBlock,
        expected: CanonicalChainError,
    ) -> FixtureResult<()> {
        let mut projection = OfflineFinalizedProjection::new(config()?);
        if let Some(initial) = initial {
            projection.apply_finalized(initial)?;
        }
        assert_eq!(
            projection.apply_finalized(invalid),
            Err(ProjectionError::CanonicalChain(expected))
        );
        assert!(matches!(
            projection.ready_checkpoint(),
            Err(ProjectionUnavailable::FailedClosed {
                fault: ProjectionFault::CanonicalChain,
            })
        ));
        Ok(())
    }

    #[test]
    fn provenance_failures_are_typed_and_fail_closed() -> FixtureResult<()> {
        let blocks = projection_chain()?;
        let wrong_genesis = indexed_block(0, [0x01; 32], [0; 32], Vec::new())?;
        assert_provenance_failure(
            None,
            &wrong_genesis,
            CanonicalChainError::GenesisHashMismatch,
        )?;
        let nonnull_genesis_parent = indexed_block(
            0,
            CanonicalNetwork::Regtest.genesis_hash().0,
            [0xee; 32],
            Vec::new(),
        )?;
        assert_provenance_failure(
            None,
            &nonnull_genesis_parent,
            CanonicalChainError::GenesisParentMismatch,
        )?;
        let missing_genesis = indexed_block(1, SECOND_HASH, [0; 32], Vec::new())?;
        assert_provenance_failure(
            None,
            &missing_genesis,
            CanonicalChainError::MissingGenesis { first_height: 1 },
        )?;
        let skipped = indexed_block(
            2,
            THIRD_HASH,
            CanonicalNetwork::Regtest.genesis_hash().0,
            Vec::new(),
        )?;
        assert_provenance_failure(
            Some(&blocks[0]),
            &skipped,
            CanonicalChainError::NonContiguousHeight {
                expected: 1,
                actual: 2,
            },
        )?;
        let wrong_parent = indexed_block(1, SECOND_HASH, [0xee; 32], Vec::new())?;
        assert_provenance_failure(
            Some(&blocks[0]),
            &wrong_parent,
            CanonicalChainError::ParentHashMismatch { height: 1 },
        )?;
        assert_provenance_failure(
            Some(&blocks[0]),
            &blocks[0],
            CanonicalChainError::NonContiguousHeight {
                expected: 1,
                actual: 0,
            },
        )?;
        Ok(())
    }

    #[test]
    fn reconcile_replay_and_replacement_preserve_ready_source() -> FixtureResult<()> {
        let blocks = projection_chain()?;
        let genesis_target = canonical_target(0, CanonicalNetwork::Regtest.genesis_hash());
        let second_target = canonical_target(1, BlockHash(SECOND_HASH));
        let original = OfflineFinalizedProjection::build(config()?, genesis_target, [&blocks[0]])?;

        assert_eq!(original.reconcile(genesis_target), ReconcileAction::Ready);
        assert_eq!(
            original.reconcile(second_target),
            ReconcileAction::ReplayFrom { next_height: 1 }
        );
        let replayed = original.replay_from_ready(second_target, [&blocks[1]])?;
        assert_eq!(replayed.ready_checkpoint()?, second_target);
        assert_eq!(original.ready_checkpoint()?, genesis_target);
        assert_eq!(
            replayed.reconcile(genesis_target),
            ReconcileAction::RebuildRequired {
                reason: RebuildReason::LocalAhead,
            }
        );
        assert_eq!(
            replayed.reconcile(canonical_target(1, BlockHash([0xee; 32]))),
            ReconcileAction::RebuildRequired {
                reason: RebuildReason::HashMismatch,
            }
        );
        assert_eq!(
            replayed.reconcile(OfflineProjectionCheckpoint::new(
                PublicChainCheckpoint::new(
                    CanonicalNetwork::Mainnet,
                    1,
                    CanonicalNetwork::Mainnet.genesis_hash(),
                ),
                SCHEMA_VERSION,
                KEY_EPOCH,
                PROJECTION_EPOCH,
            )),
            ReconcileAction::RebuildRequired {
                reason: RebuildReason::NetworkMismatch,
            }
        );
        assert_eq!(
            replayed.reconcile(target(1, BlockHash(SECOND_HASH), 2, KEY_EPOCH)),
            ReconcileAction::RebuildRequired {
                reason: RebuildReason::SchemaVersionMismatch,
            }
        );
        assert_eq!(
            replayed.reconcile(target(1, BlockHash(SECOND_HASH), SCHEMA_VERSION, 8)),
            ReconcileAction::RebuildRequired {
                reason: RebuildReason::KeyEpochMismatch,
            }
        );
        assert_eq!(
            replayed.reconcile(target_with_projection_epoch(
                1,
                BlockHash(SECOND_HASH),
                SCHEMA_VERSION,
                KEY_EPOCH,
                PROJECTION_EPOCH + 1,
            )),
            ReconcileAction::RebuildRequired {
                reason: RebuildReason::ProjectionEpochMismatch,
            }
        );

        let mut building = OfflineFinalizedProjection::new(config()?);
        assert_eq!(
            building.reconcile(genesis_target),
            ReconcileAction::ReplayFrom { next_height: 0 }
        );
        building.apply_finalized(&blocks[0])?;
        assert_eq!(building.reconcile(genesis_target), ReconcileAction::Finish);
        assert!(matches!(
            building.build_replacement(second_target, [&blocks[0], &blocks[1]]),
            Err(ProjectionError::ReplacementSourceNotReady)
        ));

        let failed_replay = original.replay_from_ready(second_target, [&blocks[2]]);
        assert!(matches!(
            failed_replay,
            Err(ProjectionError::CanonicalChain(
                CanonicalChainError::NonContiguousHeight {
                    expected: 1,
                    actual: 2,
                },
            ))
        ));
        assert_eq!(original.ready_checkpoint()?, genesis_target);

        let failed_replacement = original.build_replacement(second_target, [&blocks[1]]);
        assert!(matches!(
            failed_replacement,
            Err(ProjectionError::CanonicalChain(
                CanonicalChainError::MissingGenesis { first_height: 1 },
            ))
        ));
        assert_eq!(original.ready_checkpoint()?, genesis_target);
        let replacement = original.build_replacement(second_target, [&blocks[0], &blocks[1]])?;
        assert_eq!(replacement.ready_checkpoint()?, second_target);
        assert_eq!(original.ready_checkpoint()?, genesis_target);

        let wrong_genesis = indexed_block(0, [0xee; 32], [0; 32], Vec::new())?;
        let mut failed = OfflineFinalizedProjection::new(config()?);
        assert!(failed.apply_finalized(&wrong_genesis).is_err());
        assert_eq!(
            failed.reconcile(genesis_target),
            ReconcileAction::RebuildRequired {
                reason: RebuildReason::FailedClosed,
            }
        );
        Ok(())
    }

    #[test]
    fn target_and_ready_lifecycle_failures_never_serve_partial_state() -> FixtureResult<()> {
        let blocks = projection_chain()?;
        let config = config()?;
        assert!(matches!(
            OfflineFinalizedProjection::build(
                config,
                canonical_target(1, BlockHash(SECOND_HASH)),
                [&blocks[0]],
            ),
            Err(ProjectionError::TargetNotReached {
                target_height: 1,
                committed_height: Some(0),
            })
        ));
        assert!(matches!(
            OfflineFinalizedProjection::build(
                config,
                canonical_target(0, CanonicalNetwork::Regtest.genesis_hash()),
                [&blocks[0], &blocks[1]],
            ),
            Err(ProjectionError::TargetExceeded {
                target_height: 0,
                committed_height: 1,
            })
        ));
        assert!(matches!(
            OfflineFinalizedProjection::build(
                config,
                canonical_target(0, BlockHash([0xee; 32])),
                [&blocks[0]],
            ),
            Err(ProjectionError::TargetHashMismatch { height: 0 })
        ));
        let mainnet_target = OfflineProjectionCheckpoint::new(
            PublicChainCheckpoint::new(
                CanonicalNetwork::Mainnet,
                0,
                CanonicalNetwork::Mainnet.genesis_hash(),
            ),
            SCHEMA_VERSION,
            KEY_EPOCH,
            PROJECTION_EPOCH,
        );
        assert!(matches!(
            OfflineFinalizedProjection::build(config, mainnet_target, [&blocks[0]]),
            Err(ProjectionError::TargetNetworkMismatch)
        ));
        assert!(matches!(
            OfflineFinalizedProjection::build(
                config,
                target(0, CanonicalNetwork::Regtest.genesis_hash(), 2, KEY_EPOCH,),
                [&blocks[0]],
            ),
            Err(ProjectionError::TargetSchemaVersionMismatch)
        ));
        assert!(matches!(
            OfflineFinalizedProjection::build(
                config,
                target(
                    0,
                    CanonicalNetwork::Regtest.genesis_hash(),
                    SCHEMA_VERSION,
                    8,
                ),
                [&blocks[0]],
            ),
            Err(ProjectionError::TargetKeyEpochMismatch)
        ));
        assert!(matches!(
            OfflineFinalizedProjection::build(
                config,
                target_with_projection_epoch(
                    0,
                    CanonicalNetwork::Regtest.genesis_hash(),
                    SCHEMA_VERSION,
                    KEY_EPOCH,
                    PROJECTION_EPOCH + 1,
                ),
                [&blocks[0]],
            ),
            Err(ProjectionError::TargetProjectionEpochMismatch)
        ));

        let target = canonical_target(0, CanonicalNetwork::Regtest.genesis_hash());
        let mut ready = OfflineFinalizedProjection::build(config, target, [&blocks[0]])?;
        assert_eq!(
            ready.apply_finalized(&blocks[1]),
            Err(ProjectionError::ApplyAfterReady)
        );
        assert!(matches!(
            ready.ready_checkpoint(),
            Err(ProjectionUnavailable::FailedClosed {
                fault: ProjectionFault::Lifecycle,
            })
        ));
        Ok(())
    }

    #[test]
    fn configuration_and_debug_surfaces_are_identifier_free() -> FixtureResult<()> {
        for (dimension, values) in [
            (CapacityDimension::SeenOutputs, [0, 1, 1, 1, 1]),
            (CapacityDimension::LiveOutputs, [1, 0, 1, 1, 1]),
            (CapacityDimension::StandardAddresses, [1, 1, 0, 1, 1]),
            (CapacityDimension::TotalEvents, [1, 1, 1, 0, 1]),
            (CapacityDimension::AddressEvents, [1, 1, 1, 1, 0]),
        ] {
            assert_eq!(
                ProjectionCapacities::new(values[0], values[1], values[2], values[3], values[4]),
                Err(ProjectionConfigError::EmptyCapacity { dimension })
            );
        }
        assert_eq!(
            ProjectionConfig::new(
                CanonicalNetwork::Regtest,
                0,
                KEY_EPOCH,
                PROJECTION_EPOCH,
                capacities()?,
            ),
            Err(ProjectionConfigError::SchemaVersionZero)
        );
        assert_eq!(
            ProjectionConfig::new(
                CanonicalNetwork::Regtest,
                SCHEMA_VERSION,
                KEY_EPOCH,
                0,
                capacities()?,
            ),
            Err(ProjectionConfigError::InvalidProjectionEpoch)
        );

        let blocks = projection_chain()?;
        let projection = OfflineFinalizedProjection::build(
            config()?,
            canonical_target(2, BlockHash(THIRD_HASH)),
            blocks.iter(),
        )?;
        let debug = format!("{projection:?}");
        for private_fragment in ["11111111", "33333333", "a1a1a1a1", "c3c3c3c3"] {
            assert!(!debug.contains(private_fragment));
        }
        assert!(debug.contains("seen_outputs"));
        assert!(
            format!("{:?}", ProjectionError::UnknownSpentOutpoint).contains("UnknownSpentOutpoint")
        );
        Ok(())
    }

    #[cfg(feature = "shadow-parity")]
    #[tokio::test]
    async fn offline_projection_matches_ordinary_source_at_static_checkpoint() -> FixtureResult<()>
    {
        let fixture = zaino_state::test_dependencies::load_ordinary_utxo_shadow_fixture().await?;
        assert_eq!(
            fixture.indexed_blocks().len(),
            fixture.checkpoint_height() as usize + 1,
            "fixture must contain one genesis-forward block per checkpoint height"
        );

        let capacities = ProjectionCapacities::new(100_000, 100_000, 10_000, 200_000, 10_000)?;
        let config = ProjectionConfig::new(
            CanonicalNetwork::Regtest,
            SCHEMA_VERSION,
            KEY_EPOCH,
            PROJECTION_EPOCH,
            capacities,
        )?;
        let target = OfflineProjectionCheckpoint::new(
            PublicChainCheckpoint::new(
                CanonicalNetwork::Regtest,
                fixture.checkpoint_height(),
                *fixture.checkpoint_hash(),
            ),
            SCHEMA_VERSION,
            KEY_EPOCH,
            PROJECTION_EPOCH,
        );
        let projection =
            OfflineFinalizedProjection::build(config, target, fixture.indexed_blocks().iter())?;
        assert_eq!(projection.ready_checkpoint()?, target);

        assert!(fixture.cases().len() > 1);
        let mut nonempty_case_count = 0;
        let mut largest_case = 0;
        for case in fixture.cases() {
            let projected = projection.fixture_live_utxos(case.address_script())?;
            let mut ordinary_source = case.ordinary_utxos().iter().collect::<Vec<_>>();
            ordinary_source.sort_by_key(|utxo| (*utxo.txid(), utxo.output_index()));
            let ordinary = ordinary_source
                .into_iter()
                .map(|utxo| {
                    TransparentUtxo::new(
                        *utxo.txid(),
                        utxo.output_index(),
                        utxo.value_zat(),
                        utxo.height(),
                        utxo.script(),
                    )
                })
                .collect::<Result<Vec<_>, _>>()?;

            if case.must_be_empty() {
                assert!(
                    ordinary.is_empty(),
                    "{} must be the empty case",
                    case.name()
                );
            } else {
                nonempty_case_count += usize::from(!ordinary.is_empty());
            }
            largest_case = largest_case.max(ordinary.len());
            assert_eq!(projected, ordinary, "{} result differs", case.name());
        }
        assert!(
            nonempty_case_count > 0,
            "shadow parity must exercise a nonempty ordinary result"
        );
        assert!(
            largest_case > 1,
            "shadow parity must exercise multiple live UTXOs for one address"
        );
        Ok(())
    }
}
