//! Crate-internal owner for one offline projection candidate and its atomic worker.

mod cold_rebuild;
mod serving_store;

pub use cold_rebuild::{
    TypedWorkerColdRebuildError, TypedWorkerColdRebuildProfile, TypedWorkerColdRebuildReport,
    TypedWorkerColdRebuildSession,
};

use std::fmt;

use zaino_state::IndexedBlock;

use crate::{
    canonical_chain::{CanonicalNetwork, PublicChainCheckpoint},
    checkpoint::{NoopProjectionCheckpointPublisher, ProjectionCheckpointPublisher},
    layout::{
        shutdown_atomic_worker, spawn_typed_rostl_worker, AtomicQueueCapacity,
        AtomicQueueCapacityError, AtomicWorker, AtomicWorkerBuildError, FixedProbeLayout,
        LayoutNetwork,
    },
    projection::{ProjectionCheckpointCoordinator, ProjectionConfig, ProjectionCoordinatorStatus},
};

/// Owns the only worker handle for one unpublished offline projection candidate.
struct OfflineProjectionOwner<P = NoopProjectionCheckpointPublisher> {
    coordinator: ProjectionCheckpointCoordinator<AtomicWorker, P>,
}

impl OfflineProjectionOwner<NoopProjectionCheckpointPublisher> {
    fn new<const DIRECTORY_PROBES: usize, const EVENT_PROBES: usize>(
        projection: ProjectionConfig,
        layout: FixedProbeLayout<DIRECTORY_PROBES, EVENT_PROBES>,
        queue_capacity: usize,
    ) -> Result<Self, ProjectionOwnerBuildError> {
        Self::new_with_publisher(
            projection,
            layout,
            queue_capacity,
            NoopProjectionCheckpointPublisher,
        )
    }

    fn from_worker(projection: ProjectionConfig, worker: AtomicWorker) -> Self {
        Self {
            coordinator: ProjectionCheckpointCoordinator::new(projection, worker),
        }
    }
}

impl<P> OfflineProjectionOwner<P>
where
    P: ProjectionCheckpointPublisher,
{
    fn new_with_publisher<const DIRECTORY_PROBES: usize, const EVENT_PROBES: usize>(
        projection: ProjectionConfig,
        layout: FixedProbeLayout<DIRECTORY_PROBES, EVENT_PROBES>,
        queue_capacity: usize,
        publisher: P,
    ) -> Result<Self, ProjectionOwnerBuildError> {
        validate_configuration(projection, &layout)?;
        let queue_capacity = validated_queue_capacity(queue_capacity)
            .map_err(|_| ProjectionOwnerBuildError::ConstructionFailed)?;
        let worker = spawn_typed_rostl_worker(layout, queue_capacity).map_err(map_worker_build)?;
        Ok(Self::from_worker_with_publisher(
            projection, worker, publisher,
        ))
    }

    fn from_worker_with_publisher(
        projection: ProjectionConfig,
        worker: AtomicWorker,
        publisher: P,
    ) -> Self {
        Self {
            coordinator: ProjectionCheckpointCoordinator::with_publisher(
                projection, worker, publisher,
            ),
        }
    }

    fn apply_finalized(
        &mut self,
        block: &IndexedBlock,
    ) -> Result<PublicChainCheckpoint, ProjectionOwnerCommandError> {
        self.coordinator
            .apply_finalized_chain(block)
            .map_err(|_| ProjectionOwnerCommandError::FailedClosed)
    }

    fn finish(
        &mut self,
        target: PublicChainCheckpoint,
    ) -> Result<PublicChainCheckpoint, ProjectionOwnerCommandError> {
        self.coordinator
            .finish_chain(target)
            .map_err(|_| ProjectionOwnerCommandError::FailedClosed)
    }

    fn readiness(&self) -> ProjectionOwnerReadiness {
        readiness_from_status(self.coordinator.status())
    }

    fn committed_checkpoint(&self) -> Option<PublicChainCheckpoint> {
        committed_from_readiness(self.readiness())
    }

    fn shutdown(self) -> ProjectionOwnerShutdownOutcome {
        let (status, worker) = self.coordinator.into_shutdown_parts();
        let readiness = readiness_from_status(status);
        let committed = committed_from_readiness(readiness);
        let worker_stopped = worker.is_some_and(|worker| shutdown_atomic_worker(worker).is_ok());

        if worker_stopped && !matches!(readiness, ProjectionOwnerReadiness::FailedClosed { .. }) {
            ProjectionOwnerShutdownOutcome::Stopped { readiness }
        } else {
            ProjectionOwnerShutdownOutcome::FailedClosed { committed }
        }
    }
}

impl<P> fmt::Debug for OfflineProjectionOwner<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OfflineProjectionOwner { ..REDACTED.. }")
    }
}

fn validate_configuration<const DIRECTORY_PROBES: usize, const EVENT_PROBES: usize>(
    projection: ProjectionConfig,
    layout: &FixedProbeLayout<DIRECTORY_PROBES, EVENT_PROBES>,
) -> Result<(), ProjectionOwnerBuildError> {
    let capacities = projection.capacities();
    let mismatch = if !network_matches(projection.network(), layout.network()) {
        Some(ProjectionOwnerConfigMismatch::Network)
    } else if projection.schema_version() != layout.schema_version() {
        Some(ProjectionOwnerConfigMismatch::SchemaVersion)
    } else if projection.key_epoch() != layout.key_epoch() {
        Some(ProjectionOwnerConfigMismatch::KeyEpoch)
    } else if !usize_matches_u32(
        capacities.max_standard_addresses(),
        layout.directory_admission_limit(),
    ) {
        Some(ProjectionOwnerConfigMismatch::DirectoryAdmissionLimit)
    } else if !usize_matches_u32(
        capacities.max_total_events(),
        layout.event_admission_limit(),
    ) {
        Some(ProjectionOwnerConfigMismatch::EventAdmissionLimit)
    } else if !usize_matches_u32(
        capacities.max_events_per_address(),
        layout.max_events_per_address(),
    ) {
        Some(ProjectionOwnerConfigMismatch::EventsPerAddress)
    } else {
        None
    };

    match mismatch {
        Some(mismatch) => Err(ProjectionOwnerBuildError::ConfigMismatch(mismatch)),
        None => Ok(()),
    }
}

const fn network_matches(projection: CanonicalNetwork, layout: LayoutNetwork) -> bool {
    matches!(
        (projection, layout),
        (CanonicalNetwork::Mainnet, LayoutNetwork::Mainnet)
            | (CanonicalNetwork::Testnet, LayoutNetwork::Testnet)
            | (CanonicalNetwork::Regtest, LayoutNetwork::Regtest)
    )
}

fn usize_matches_u32(value: usize, expected: u32) -> bool {
    u32::try_from(value).is_ok_and(|value| value == expected)
}

fn validated_queue_capacity(value: usize) -> Result<AtomicQueueCapacity, AtomicQueueCapacityError> {
    AtomicQueueCapacity::try_new(value)
}

const fn map_worker_build(error: AtomicWorkerBuildError) -> ProjectionOwnerBuildError {
    match error {
        #[cfg(not(all(
            feature = "rostl-experimental",
            target_os = "linux",
            target_arch = "x86_64"
        )))]
        AtomicWorkerBuildError::TypedBackendUnavailable => {
            ProjectionOwnerBuildError::TypedBackendUnavailable
        }
        AtomicWorkerBuildError::ConstructionFailed => ProjectionOwnerBuildError::ConstructionFailed,
    }
}

const fn readiness_from_status(status: ProjectionCoordinatorStatus) -> ProjectionOwnerReadiness {
    match status {
        ProjectionCoordinatorStatus::Building { committed } => {
            ProjectionOwnerReadiness::Building { committed }
        }
        ProjectionCoordinatorStatus::Ready { checkpoint } => {
            ProjectionOwnerReadiness::Ready { checkpoint }
        }
        ProjectionCoordinatorStatus::FailedClosed { committed } => {
            ProjectionOwnerReadiness::FailedClosed { committed }
        }
    }
}

const fn committed_from_readiness(
    readiness: ProjectionOwnerReadiness,
) -> Option<PublicChainCheckpoint> {
    match readiness {
        ProjectionOwnerReadiness::Building { committed }
        | ProjectionOwnerReadiness::FailedClosed { committed } => committed,
        ProjectionOwnerReadiness::Ready { checkpoint } => Some(checkpoint),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProjectionOwnerConfigMismatch {
    Network,
    SchemaVersion,
    KeyEpoch,
    DirectoryAdmissionLimit,
    EventAdmissionLimit,
    EventsPerAddress,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProjectionOwnerBuildError {
    ConfigMismatch(ProjectionOwnerConfigMismatch),
    #[cfg(not(all(
        feature = "rostl-experimental",
        target_os = "linux",
        target_arch = "x86_64"
    )))]
    TypedBackendUnavailable,
    ConstructionFailed,
}

impl fmt::Display for ProjectionOwnerBuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConfigMismatch(_) => f.write_str("projection and layout configuration mismatch"),
            #[cfg(not(all(
                feature = "rostl-experimental",
                target_os = "linux",
                target_arch = "x86_64"
            )))]
            Self::TypedBackendUnavailable => f.write_str("typed projection backend is unavailable"),
            Self::ConstructionFailed => f.write_str("projection owner construction failed"),
        }
    }
}

impl std::error::Error for ProjectionOwnerBuildError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProjectionOwnerCommandError {
    FailedClosed,
}

impl fmt::Display for ProjectionOwnerCommandError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FailedClosed => f.write_str("projection owner failed closed"),
        }
    }
}

impl std::error::Error for ProjectionOwnerCommandError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProjectionOwnerReadiness {
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
enum ProjectionOwnerShutdownOutcome {
    Stopped {
        readiness: ProjectionOwnerReadiness,
    },
    FailedClosed {
        committed: Option<PublicChainCheckpoint>,
    },
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap,
        sync::{Arc, Mutex},
    };

    use tempfile::TempDir;

    use super::serving_store::FinalizedProjectionServingStoreBuildError;
    use super::*;
    use crate::{
        checkpoint::{
            Blake2sManifestAuthenticator, ProjectionFreshness, ProjectionFreshnessWitness,
            ProjectionManifestStore, ProjectionRestartPlan, PublishedProjectionManifest,
        },
        layout::{
            derive_standard_address_key, spawn_atomic_worker_for_tests, BackendFailure,
            DirectoryTableConfiguration, EventTableConfiguration, LayoutIdentity, StandardAddress,
            StandardScriptKind, UniqueTable,
        },
        projection::ProjectionCapacities,
        recent_snapshot::{FinalizedServingStore, RecentSnapshotIdentity},
        records::{
            AddressKey, PersistentAddressDirectory, PersistentAddressEventPage, ADDRESS_KEY_BYTES,
        },
        zaino_fixtures::{projection_chain, FixtureResult},
    };

    const DIRECTORY_PROBES: usize = 4;
    const EVENT_PROBES: usize = 8;
    const SCHEMA_VERSION: u32 = 1;
    const KEY_EPOCH: u64 = 7;
    const PROJECTION_EPOCH: u64 = 11;
    const GENERATION: u64 = 11;
    const DIRECTORY_CAPACITY: u64 = 8;
    const DIRECTORY_ADMISSION: u64 = 3;
    const EVENT_CAPACITY: u64 = 16;
    const EVENT_ADMISSION: u64 = 7;
    const MAX_EVENTS_PER_ADDRESS: u64 = 4;

    type OwnerLayout = FixedProbeLayout<DIRECTORY_PROBES, EVENT_PROBES>;
    type RecoveryPublisher =
        ProjectionManifestStore<Blake2sManifestAuthenticator, SharedFreshnessWitness>;

    const MANIFEST_KEY: [u8; 32] = [0x72; 32];

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum FreshnessWitnessError {
        Conflict,
        InvalidTransition,
        Poisoned,
    }

    impl fmt::Display for FreshnessWitnessError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::Conflict => f.write_str("freshness witness compare conflict"),
                Self::InvalidTransition => f.write_str("freshness witness transition is invalid"),
                Self::Poisoned => f.write_str("freshness witness mutex poisoned"),
            }
        }
    }

    impl std::error::Error for FreshnessWitnessError {}

    #[derive(Clone, Default)]
    struct SharedFreshnessWitness(Arc<Mutex<Option<ProjectionFreshness>>>);

    impl ProjectionFreshnessWitness for SharedFreshnessWitness {
        type Error = FreshnessWitnessError;

        fn current(&mut self) -> Result<Option<ProjectionFreshness>, Self::Error> {
            self.0
                .lock()
                .map(|value| *value)
                .map_err(|_| FreshnessWitnessError::Poisoned)
        }

        fn compare_and_advance(
            &mut self,
            expected: Option<ProjectionFreshness>,
            next: ProjectionFreshness,
        ) -> Result<(), Self::Error> {
            let mut value = self.0.lock().map_err(|_| FreshnessWitnessError::Poisoned)?;
            if *value != expected {
                return Err(FreshnessWitnessError::Conflict);
            }
            let valid_transition = match expected {
                None => next.sequence() == 1,
                Some(current) => current
                    .sequence()
                    .checked_add(1)
                    .is_some_and(|sequence| sequence == next.sequence()),
            };
            if !valid_transition {
                return Err(FreshnessWitnessError::InvalidTransition);
            }
            *value = Some(next);
            Ok(())
        }
    }

    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
    struct TableStats {
        reads: usize,
        writes: usize,
        drops: usize,
    }

    #[derive(Clone, Default)]
    struct TableObservation(Arc<Mutex<TableStats>>);

    impl TableObservation {
        fn stats(&self) -> FixtureResult<TableStats> {
            self.0
                .lock()
                .map(|stats| *stats)
                .map_err(|_| "table observation mutex poisoned".into())
        }
    }

    struct FakeTable<T> {
        capacity: usize,
        cells: BTreeMap<usize, T>,
        observation: TableObservation,
        fail_on_write: Option<usize>,
    }

    impl<T> FakeTable<T> {
        fn new(
            capacity: usize,
            observation: TableObservation,
            fail_on_write: Option<usize>,
        ) -> Self {
            Self {
                capacity,
                cells: BTreeMap::new(),
                observation,
                fail_on_write,
            }
        }
    }

    impl<T: Copy> UniqueTable<T> for FakeTable<T> {
        fn capacity(&self) -> usize {
            self.capacity
        }

        fn read(&mut self, index: usize) -> Result<Option<T>, BackendFailure> {
            if index >= self.capacity {
                return Err(BackendFailure);
            }
            let mut stats = self.observation.0.lock().map_err(|_| BackendFailure)?;
            stats.reads = stats.reads.checked_add(1).ok_or(BackendFailure)?;
            drop(stats);
            Ok(self.cells.get(&index).copied())
        }

        fn occupied_records(&mut self) -> Result<u64, BackendFailure> {
            u64::try_from(self.cells.len()).map_err(|_| BackendFailure)
        }

        fn insert_unique(&mut self, index: usize, value: T) -> Result<(), BackendFailure> {
            if index >= self.capacity || self.cells.contains_key(&index) {
                return Err(BackendFailure);
            }

            let write_ordinal = {
                let mut stats = self.observation.0.lock().map_err(|_| BackendFailure)?;
                stats.writes = stats.writes.checked_add(1).ok_or(BackendFailure)?;
                stats.writes
            };
            let _ = self.cells.insert(index, value);

            if self.fail_on_write == Some(write_ordinal) {
                Err(BackendFailure)
            } else {
                Ok(())
            }
        }
    }

    impl<T> Drop for FakeTable<T> {
        fn drop(&mut self) {
            if let Ok(mut stats) = self.observation.0.lock() {
                stats.drops = stats.drops.saturating_add(1);
            }
        }
    }

    fn projection_config(
        network: CanonicalNetwork,
        schema_version: u32,
        key_epoch: u64,
        max_standard_addresses: usize,
        max_total_events: usize,
        max_events_per_address: usize,
    ) -> FixtureResult<ProjectionConfig> {
        projection_config_with_epoch(
            network,
            schema_version,
            key_epoch,
            PROJECTION_EPOCH,
            max_standard_addresses,
            max_total_events,
            max_events_per_address,
        )
    }

    fn projection_config_with_epoch(
        network: CanonicalNetwork,
        schema_version: u32,
        key_epoch: u64,
        projection_epoch: u64,
        max_standard_addresses: usize,
        max_total_events: usize,
        max_events_per_address: usize,
    ) -> FixtureResult<ProjectionConfig> {
        let capacities = ProjectionCapacities::new(
            6,
            4,
            max_standard_addresses,
            max_total_events,
            max_events_per_address,
        )?;
        Ok(ProjectionConfig::new(
            network,
            schema_version,
            key_epoch,
            projection_epoch,
            capacities,
        )?)
    }

    fn compatible_projection_config() -> FixtureResult<ProjectionConfig> {
        compatible_projection_config_with_epoch(PROJECTION_EPOCH)
    }

    fn compatible_projection_config_with_epoch(
        projection_epoch: u64,
    ) -> FixtureResult<ProjectionConfig> {
        projection_config_with_epoch(
            CanonicalNetwork::Regtest,
            SCHEMA_VERSION,
            KEY_EPOCH,
            projection_epoch,
            usize::try_from(DIRECTORY_ADMISSION)?,
            usize::try_from(EVENT_ADMISSION)?,
            usize::try_from(MAX_EVENTS_PER_ADDRESS)?,
        )
    }

    fn recovery_publisher(
        directory: &TempDir,
        witness: SharedFreshnessWitness,
    ) -> FixtureResult<RecoveryPublisher> {
        Ok(ProjectionManifestStore::new(
            directory.path(),
            Blake2sManifestAuthenticator::new(MANIFEST_KEY),
            witness,
        ))
    }

    fn restart_manifest_and_epoch(
        directory: &TempDir,
        witness: SharedFreshnessWitness,
        authoritative: PublicChainCheckpoint,
    ) -> FixtureResult<(PublishedProjectionManifest, u64)> {
        let mut reader = recovery_publisher(directory, witness)?;
        let ProjectionRestartPlan::Rebuild {
            prior_manifest: Some(manifest),
            authoritative: planned,
            next_projection_epoch,
        } = reader.restart_plan(
            CanonicalNetwork::Regtest,
            SCHEMA_VERSION,
            KEY_EPOCH,
            authoritative,
        )
        else {
            return Err("completed volatile worker must produce a rebuild plan".into());
        };
        if planned != authoritative {
            return Err("rebuild plan changed the authoritative checkpoint".into());
        }
        Ok((manifest, next_projection_epoch))
    }

    fn owner_layout(
        network: LayoutNetwork,
        schema_version: u32,
        key_epoch: u64,
        directory_admission: u64,
        event_admission: u64,
        max_events_per_address: u64,
    ) -> FixtureResult<OwnerLayout> {
        Ok(FixedProbeLayout::new(
            LayoutIdentity::new(network, schema_version, key_epoch, GENERATION, [0x5a; 32])?,
            DirectoryTableConfiguration::new(DIRECTORY_CAPACITY, directory_admission)?,
            EventTableConfiguration::new(EVENT_CAPACITY, event_admission)?,
            max_events_per_address,
        )?)
    }

    fn compatible_layout() -> FixtureResult<OwnerLayout> {
        owner_layout(
            LayoutNetwork::Regtest,
            SCHEMA_VERSION,
            KEY_EPOCH,
            DIRECTORY_ADMISSION,
            EVENT_ADMISSION,
            MAX_EVENTS_PER_ADDRESS,
        )
    }

    fn fake_owner(
        fail_on_event_write: Option<usize>,
    ) -> FixtureResult<(OfflineProjectionOwner, TableObservation, TableObservation)> {
        let projection = compatible_projection_config()?;
        let (worker, directory_observation, event_observation) =
            fake_worker(projection, fail_on_event_write)?;
        Ok((
            OfflineProjectionOwner::from_worker(projection, worker),
            directory_observation,
            event_observation,
        ))
    }

    fn fake_worker(
        projection: ProjectionConfig,
        fail_on_event_write: Option<usize>,
    ) -> FixtureResult<(AtomicWorker, TableObservation, TableObservation)> {
        let layout = compatible_layout()?;
        validate_configuration(projection, &layout)?;
        let directory_observation = TableObservation::default();
        let event_observation = TableObservation::default();
        let directory = FakeTable::<PersistentAddressDirectory>::new(
            usize::try_from(DIRECTORY_CAPACITY)?,
            directory_observation.clone(),
            None,
        );
        let events = FakeTable::<PersistentAddressEventPage>::new(
            usize::try_from(EVENT_CAPACITY)?,
            event_observation.clone(),
            fail_on_event_write,
        );
        let worker =
            spawn_atomic_worker_for_tests(layout, directory, events, validated_queue_capacity(1)?)?;
        Ok((worker, directory_observation, event_observation))
    }

    fn assert_mismatch(
        projection: ProjectionConfig,
        layout: OwnerLayout,
        expected: ProjectionOwnerConfigMismatch,
    ) -> FixtureResult<()> {
        let error = OfflineProjectionOwner::new(projection, layout, 0)
            .expect_err("configuration mismatch must precede queue validation");
        assert_eq!(error, ProjectionOwnerBuildError::ConfigMismatch(expected));
        Ok(())
    }

    fn run_owner_to_ready<P>(
        mut owner: OfflineProjectionOwner<P>,
        blocks: &[IndexedBlock],
    ) -> FixtureResult<PublicChainCheckpoint>
    where
        P: ProjectionCheckpointPublisher,
    {
        let mut target = None;
        for block in blocks {
            target = Some(owner.apply_finalized(block)?);
        }
        let target = target.ok_or("fixture chain must be nonempty")?;
        assert_eq!(owner.finish(target)?, target);
        assert!(matches!(
            owner.shutdown(),
            ProjectionOwnerShutdownOutcome::Stopped {
                readiness: ProjectionOwnerReadiness::Ready { checkpoint },
            } if checkpoint == target
        ));
        Ok(target)
    }

    #[test]
    fn rejects_each_cross_layer_configuration_mismatch_before_allocation() -> FixtureResult<()> {
        assert_mismatch(
            projection_config(
                CanonicalNetwork::Testnet,
                SCHEMA_VERSION,
                KEY_EPOCH,
                3,
                7,
                4,
            )?,
            compatible_layout()?,
            ProjectionOwnerConfigMismatch::Network,
        )?;
        assert_mismatch(
            projection_config(CanonicalNetwork::Regtest, 2, KEY_EPOCH, 3, 7, 4)?,
            compatible_layout()?,
            ProjectionOwnerConfigMismatch::SchemaVersion,
        )?;
        assert_mismatch(
            projection_config(CanonicalNetwork::Regtest, SCHEMA_VERSION, 8, 3, 7, 4)?,
            compatible_layout()?,
            ProjectionOwnerConfigMismatch::KeyEpoch,
        )?;
        assert_mismatch(
            projection_config(
                CanonicalNetwork::Regtest,
                SCHEMA_VERSION,
                KEY_EPOCH,
                4,
                7,
                4,
            )?,
            compatible_layout()?,
            ProjectionOwnerConfigMismatch::DirectoryAdmissionLimit,
        )?;
        assert_mismatch(
            projection_config(
                CanonicalNetwork::Regtest,
                SCHEMA_VERSION,
                KEY_EPOCH,
                3,
                8,
                4,
            )?,
            compatible_layout()?,
            ProjectionOwnerConfigMismatch::EventAdmissionLimit,
        )?;
        assert_mismatch(
            projection_config(
                CanonicalNetwork::Regtest,
                SCHEMA_VERSION,
                KEY_EPOCH,
                3,
                7,
                5,
            )?,
            compatible_layout()?,
            ProjectionOwnerConfigMismatch::EventsPerAddress,
        )?;
        Ok(())
    }

    #[test]
    fn portable_owner_builds_finishes_and_shuts_down_without_exposing_tables() -> FixtureResult<()>
    {
        let blocks = projection_chain()?;
        let (mut owner, directory, events) = fake_owner(None)?;
        assert_eq!(
            owner.readiness(),
            ProjectionOwnerReadiness::Building { committed: None }
        );

        let first = owner.apply_finalized(&blocks[0])?;
        assert_eq!(first.height(), 0);
        let second = owner.apply_finalized(&blocks[1])?;
        assert_eq!(second.height(), 1);
        assert_eq!(directory.stats()?.writes, 3);
        assert_eq!(events.stats()?.writes, 7);

        let third = owner.apply_finalized(&blocks[2])?;
        assert_eq!(third.height(), 2);
        assert_eq!(directory.stats()?.writes, 3);
        assert_eq!(events.stats()?.writes, 7);
        assert_eq!(owner.finish(third)?, third);
        assert_eq!(
            owner.readiness(),
            ProjectionOwnerReadiness::Ready { checkpoint: third }
        );

        assert_eq!(
            owner.shutdown(),
            ProjectionOwnerShutdownOutcome::Stopped {
                readiness: ProjectionOwnerReadiness::Ready { checkpoint: third },
            }
        );
        assert_eq!(directory.stats()?.drops, 1);
        assert_eq!(events.stats()?.drops, 1);
        Ok(())
    }

    #[test]
    fn ready_owner_issues_exact_identity_bound_serving_store() -> FixtureResult<()> {
        let blocks = projection_chain()?;
        let projection = compatible_projection_config()?;
        let (mut owner, directory, events) = fake_owner(None)?;
        let mut target = None;
        for block in &blocks {
            target = Some(owner.apply_finalized(block)?);
        }
        let target = target.ok_or("fixture chain must be nonempty")?;
        owner.finish(target)?;

        let store = owner.into_serving_store()?;
        assert_eq!(store.committed_checkpoint(), target);
        assert_eq!(
            store.serving_identity(),
            RecentSnapshotIdentity::from_finalized_projection(
                projection.network(),
                target.height(),
                target.block_hash().bytes_in_display_order(),
                projection.schema_version(),
                projection.projection_epoch(),
                projection.key_epoch(),
            )
        );
        assert_eq!(
            crate::store::ObliviousStore::slots_per_key(&store),
            usize::try_from(MAX_EVENTS_PER_ADDRESS)?
        );
        assert_eq!(
            format!("{store:?}"),
            "FinalizedProjectionServingStore { ..REDACTED.. }"
        );

        drop(store);
        assert_eq!(directory.stats()?.drops, 1);
        assert_eq!(events.stats()?.drops, 1);
        Ok(())
    }

    fn fixture_address_key(kind: StandardScriptKind, hash: [u8; 20]) -> AddressKey {
        derive_standard_address_key(
            LayoutNetwork::Regtest,
            SCHEMA_VERSION,
            StandardAddress::new(kind, hash),
        )
    }

    fn assert_one_complete_read(
        before_directory: TableStats,
        after_directory: TableStats,
        before_events: TableStats,
        after_events: TableStats,
    ) {
        let max_events = usize::try_from(MAX_EVENTS_PER_ADDRESS)
            .expect("test max-events profile fits the host usize");
        assert_eq!(
            after_directory.reads - before_directory.reads,
            DIRECTORY_PROBES
        );
        assert_eq!(
            after_events.reads - before_events.reads,
            EVENT_PROBES * max_events
        );
    }

    #[test]
    fn serving_store_reads_dense_live_slots_with_one_complete_command_each() -> FixtureResult<()> {
        let blocks = projection_chain()?;
        let (mut owner, directory, events) = fake_owner(None)?;
        let mut target = None;
        for block in &blocks {
            target = Some(owner.apply_finalized(block)?);
        }
        let target = target.ok_or("fixture chain must be nonempty")?;
        owner.finish(target)?;
        let mut store = owner.into_serving_store()?;

        let address_a = fixture_address_key(StandardScriptKind::PayToPublicKeyHash, [0xa1; 20]);
        let mut first_script = [0; 25];
        first_script[..3].copy_from_slice(&[0x76, 0xa9, 0x14]);
        first_script[3..23].copy_from_slice(&[0xa1; 20]);
        first_script[23..].copy_from_slice(&[0x88, 0xac]);
        let expected_first =
            crate::records::TransparentUtxo::new([0x11; 32], 1, 60, 0, &first_script)?;
        let expected_second =
            crate::records::TransparentUtxo::new([0x33; 32], 0, 30, 1, &first_script)?;

        let before_directory = directory.stats()?;
        let before_events = events.stats()?;
        let first = crate::store::ObliviousStore::read_slot(&mut store, &address_a, 0)?;
        assert!(first.is_occupied());
        assert_eq!(first.record(), &expected_first);
        assert_one_complete_read(
            before_directory,
            directory.stats()?,
            before_events,
            events.stats()?,
        );

        let before_directory = directory.stats()?;
        let before_events = events.stats()?;
        let second = crate::store::ObliviousStore::read_slot(&mut store, &address_a, 1)?;
        assert!(second.is_occupied());
        assert_eq!(second.record(), &expected_second);
        assert_one_complete_read(
            before_directory,
            directory.stats()?,
            before_events,
            events.stats()?,
        );

        let before_directory = directory.stats()?;
        let before_events = events.stats()?;
        let padding = crate::store::ObliviousStore::read_slot(&mut store, &address_a, 2)?;
        assert!(!padding.is_occupied());
        assert_one_complete_read(
            before_directory,
            directory.stats()?,
            before_events,
            events.stats()?,
        );

        let spent_address = fixture_address_key(StandardScriptKind::PayToScriptHash, [0xb2; 20]);
        let before_directory = directory.stats()?;
        let before_events = events.stats()?;
        let spent = crate::store::ObliviousStore::read_slot(&mut store, &spent_address, 0)?;
        assert!(!spent.is_occupied());
        assert_one_complete_read(
            before_directory,
            directory.stats()?,
            before_events,
            events.stats()?,
        );

        let missing = AddressKey::new([0xff; ADDRESS_KEY_BYTES]);
        let before_directory = directory.stats()?;
        let before_events = events.stats()?;
        let miss = crate::store::ObliviousStore::read_slot(&mut store, &missing, 0)?;
        assert!(!miss.is_occupied());
        assert_one_complete_read(
            before_directory,
            directory.stats()?,
            before_events,
            events.stats()?,
        );
        Ok(())
    }

    #[test]
    fn non_ready_owner_cannot_issue_a_serving_store() -> FixtureResult<()> {
        let (building, building_directory, building_events) = fake_owner(None)?;
        assert!(matches!(
            building.into_serving_store(),
            Err(FinalizedProjectionServingStoreBuildError)
        ));
        assert_eq!(building_directory.stats()?.drops, 1);
        assert_eq!(building_events.stats()?.drops, 1);

        let blocks = projection_chain()?;
        let (mut failed, failed_directory, failed_events) = fake_owner(Some(6))?;
        failed.apply_finalized(&blocks[0])?;
        assert_eq!(
            failed.apply_finalized(&blocks[1]),
            Err(ProjectionOwnerCommandError::FailedClosed)
        );
        assert!(matches!(
            failed.into_serving_store(),
            Err(FinalizedProjectionServingStoreBuildError)
        ));
        assert_eq!(failed_directory.stats()?.drops, 1);
        assert_eq!(failed_events.stats()?.drops, 1);
        Ok(())
    }

    #[test]
    fn replacement_owner_rolls_the_serving_identity_projection_epoch() -> FixtureResult<()> {
        let blocks = projection_chain()?;
        let first_config = compatible_projection_config_with_epoch(PROJECTION_EPOCH)?;
        let (first_worker, _, _) = fake_worker(first_config, None)?;
        let mut first_owner = OfflineProjectionOwner::from_worker(first_config, first_worker);
        let mut first_target = None;
        for block in &blocks {
            first_target = Some(first_owner.apply_finalized(block)?);
        }
        let first_target = first_target.ok_or("fixture chain must be nonempty")?;
        first_owner.finish(first_target)?;
        let first_store = first_owner.into_serving_store()?;

        let second_config = compatible_projection_config_with_epoch(PROJECTION_EPOCH + 1)?;
        let (second_worker, _, _) = fake_worker(second_config, None)?;
        let mut second_owner = OfflineProjectionOwner::from_worker(second_config, second_worker);
        let mut second_target = None;
        for block in &blocks {
            second_target = Some(second_owner.apply_finalized(block)?);
        }
        let second_target = second_target.ok_or("fixture chain must be nonempty")?;
        second_owner.finish(second_target)?;
        let second_store = second_owner.into_serving_store()?;

        assert_eq!(first_target, second_target);
        assert_ne!(
            first_store.serving_identity(),
            second_store.serving_identity()
        );
        Ok(())
    }

    #[test]
    fn partial_backend_mutation_latches_failure_and_forbids_retry() -> FixtureResult<()> {
        let blocks = projection_chain()?;
        let (mut owner, directory, events) = fake_owner(Some(6))?;
        let committed = owner.apply_finalized(&blocks[0])?;

        assert_eq!(
            owner.apply_finalized(&blocks[1]),
            Err(ProjectionOwnerCommandError::FailedClosed)
        );
        assert_eq!(owner.committed_checkpoint(), Some(committed));
        assert_eq!(
            owner.readiness(),
            ProjectionOwnerReadiness::FailedClosed {
                committed: Some(committed),
            }
        );
        let writes_after_failure = events.stats()?.writes;
        assert_eq!(writes_after_failure, 6);
        assert_eq!(directory.stats()?.drops, 1);
        assert_eq!(events.stats()?.drops, 1);

        assert_eq!(
            owner.apply_finalized(&blocks[2]),
            Err(ProjectionOwnerCommandError::FailedClosed)
        );
        assert_eq!(events.stats()?.writes, writes_after_failure);
        assert_eq!(
            owner.shutdown(),
            ProjectionOwnerShutdownOutcome::FailedClosed {
                committed: Some(committed),
            }
        );
        assert_eq!(directory.stats()?.drops, 1);
        assert_eq!(events.stats()?.drops, 1);
        Ok(())
    }

    #[test]
    fn authenticated_manifest_restart_rebuilds_a_fresh_worker_with_a_new_epoch() -> FixtureResult<()>
    {
        let directory = TempDir::new()?;
        let witness = SharedFreshnessWitness::default();
        let blocks = projection_chain()?;
        let first_config = compatible_projection_config()?;
        let (first_worker, _, _) = fake_worker(first_config, None)?;
        let first_owner = OfflineProjectionOwner::from_worker_with_publisher(
            first_config,
            first_worker,
            recovery_publisher(&directory, witness.clone())?,
        );
        let target = run_owner_to_ready(first_owner, &blocks)?;

        let (first_manifest, next_projection_epoch) =
            restart_manifest_and_epoch(&directory, witness.clone(), target)?;
        assert_eq!(next_projection_epoch, PROJECTION_EPOCH + 1);

        let second_config = compatible_projection_config_with_epoch(next_projection_epoch)?;
        let (second_worker, _, _) = fake_worker(second_config, None)?;
        let second_owner = OfflineProjectionOwner::from_worker_with_publisher(
            second_config,
            second_worker,
            recovery_publisher(&directory, witness.clone())?,
        );
        let rebuilt_target = run_owner_to_ready(second_owner, &blocks)?;
        assert_eq!(rebuilt_target, target);

        let (second_manifest, later_epoch) =
            restart_manifest_and_epoch(&directory, witness, target)?;
        assert_eq!(second_manifest.projection_epoch(), next_projection_epoch);
        assert_eq!(later_epoch, next_projection_epoch + 1);
        assert_eq!(
            second_manifest.event_log_root(),
            first_manifest.event_log_root()
        );
        assert!(second_manifest.publication_sequence() > first_manifest.publication_sequence());
        Ok(())
    }

    #[cfg(not(all(
        feature = "rostl-experimental",
        target_os = "linux",
        target_arch = "x86_64"
    )))]
    #[test]
    fn typed_owner_is_unavailable_without_the_supported_backend() -> FixtureResult<()> {
        let error =
            OfflineProjectionOwner::new(compatible_projection_config()?, compatible_layout()?, 1)
                .expect_err("unsupported hosts must not construct a typed owner");
        assert_eq!(error, ProjectionOwnerBuildError::TypedBackendUnavailable);
        Ok(())
    }

    #[cfg(all(
        feature = "rostl-experimental",
        target_os = "linux",
        target_arch = "x86_64"
    ))]
    #[test]
    fn linux_rostl_owner_builds_finishes_and_serves_a_dense_slot() -> FixtureResult<()> {
        let blocks = projection_chain()?;
        let mut owner =
            OfflineProjectionOwner::new(compatible_projection_config()?, compatible_layout()?, 1)?;
        let mut target = None;
        for block in &blocks {
            target = Some(owner.apply_finalized(block)?);
        }
        let target = target.ok_or("fixture chain must be nonempty")?;
        assert_eq!(owner.finish(target)?, target);
        let mut store = owner.into_serving_store()?;
        let address = fixture_address_key(StandardScriptKind::PayToPublicKeyHash, [0xa1; 20]);
        let slot = crate::store::ObliviousStore::read_slot(&mut store, &address, 0)?;
        assert!(slot.is_occupied());
        assert_eq!(slot.record().txid(), &[0x11; 32]);
        assert_eq!(slot.record().output_index(), 1);
        Ok(())
    }

    #[cfg(all(
        feature = "rostl-experimental",
        target_os = "linux",
        target_arch = "x86_64"
    ))]
    #[test]
    fn linux_rostl_owner_rebuilds_from_authenticated_manifest_with_a_new_epoch() -> FixtureResult<()>
    {
        let directory = TempDir::new()?;
        let witness = SharedFreshnessWitness::default();
        let blocks = projection_chain()?;
        let first_owner = OfflineProjectionOwner::new_with_publisher(
            compatible_projection_config()?,
            compatible_layout()?,
            1,
            recovery_publisher(&directory, witness.clone())?,
        )?;
        let target = run_owner_to_ready(first_owner, &blocks)?;
        let (first_manifest, next_epoch) =
            restart_manifest_and_epoch(&directory, witness.clone(), target)?;

        let second_owner = OfflineProjectionOwner::new_with_publisher(
            compatible_projection_config_with_epoch(next_epoch)?,
            compatible_layout()?,
            1,
            recovery_publisher(&directory, witness.clone())?,
        )?;
        assert_eq!(run_owner_to_ready(second_owner, &blocks)?, target);
        let (second_manifest, later_epoch) =
            restart_manifest_and_epoch(&directory, witness, target)?;
        assert_eq!(second_manifest.projection_epoch(), next_epoch);
        assert_eq!(later_epoch, next_epoch + 1);
        assert_eq!(
            second_manifest.event_log_root(),
            first_manifest.event_log_root()
        );
        Ok(())
    }

    #[test]
    fn debug_and_coarse_errors_are_identifier_free() -> FixtureResult<()> {
        let (owner, _, _) = fake_owner(None)?;
        assert_eq!(
            format!("{owner:?}"),
            "OfflineProjectionOwner { ..REDACTED.. }"
        );
        assert_eq!(
            ProjectionOwnerBuildError::ConfigMismatch(
                ProjectionOwnerConfigMismatch::DirectoryAdmissionLimit,
            )
            .to_string(),
            "projection and layout configuration mismatch"
        );
        assert_eq!(
            ProjectionOwnerCommandError::FailedClosed.to_string(),
            "projection owner failed closed"
        );
        let _ = owner.shutdown();
        Ok(())
    }
}
