//! Crate-internal owner for one offline projection candidate and its atomic worker.

use std::fmt;

use zaino_state::IndexedBlock;

use crate::{
    canonical_chain::{CanonicalNetwork, PublicChainCheckpoint},
    layout::{
        shutdown_atomic_worker, spawn_typed_rostl_worker, AtomicQueueCapacity,
        AtomicQueueCapacityError, AtomicWorker, AtomicWorkerBuildError, FixedProbeLayout,
        LayoutNetwork,
    },
    projection::{ProjectionCheckpointCoordinator, ProjectionConfig, ProjectionCoordinatorStatus},
};

/// Owns the only worker handle for one unpublished offline projection candidate.
struct OfflineProjectionOwner {
    coordinator: ProjectionCheckpointCoordinator<AtomicWorker>,
}

impl OfflineProjectionOwner {
    fn new<const DIRECTORY_PROBES: usize, const EVENT_PROBES: usize>(
        projection: ProjectionConfig,
        layout: FixedProbeLayout<DIRECTORY_PROBES, EVENT_PROBES>,
        queue_capacity: usize,
    ) -> Result<Self, ProjectionOwnerBuildError> {
        validate_configuration(projection, &layout)?;
        let queue_capacity = validated_queue_capacity(queue_capacity)
            .map_err(|_| ProjectionOwnerBuildError::ConstructionFailed)?;
        let worker = spawn_typed_rostl_worker(layout, queue_capacity).map_err(map_worker_build)?;
        Ok(Self::from_worker(projection, worker))
    }

    fn from_worker(projection: ProjectionConfig, worker: AtomicWorker) -> Self {
        Self {
            coordinator: ProjectionCheckpointCoordinator::new(projection, worker),
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

impl fmt::Debug for OfflineProjectionOwner {
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
    TypedBackendUnavailable,
    ConstructionFailed,
}

impl fmt::Display for ProjectionOwnerBuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConfigMismatch(_) => f.write_str("projection and layout configuration mismatch"),
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

    use super::*;
    use crate::{
        layout::{
            spawn_atomic_worker_for_tests, BackendFailure, DirectoryTableConfiguration,
            EventTableConfiguration, LayoutIdentity, UniqueTable,
        },
        projection::ProjectionCapacities,
        records::{PersistentAddressDirectory, PersistentAddressEventPage},
        zaino_fixtures::{projection_chain, FixtureResult},
    };

    const DIRECTORY_PROBES: usize = 4;
    const EVENT_PROBES: usize = 8;
    const SCHEMA_VERSION: u32 = 1;
    const KEY_EPOCH: u64 = 7;
    const GENERATION: u64 = 11;
    const DIRECTORY_CAPACITY: u64 = 8;
    const DIRECTORY_ADMISSION: u64 = 3;
    const EVENT_CAPACITY: u64 = 16;
    const EVENT_ADMISSION: u64 = 7;
    const MAX_EVENTS_PER_ADDRESS: u64 = 4;

    type OwnerLayout = FixedProbeLayout<DIRECTORY_PROBES, EVENT_PROBES>;

    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
    struct TableStats {
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
            capacities,
        )?)
    }

    fn compatible_projection_config() -> FixtureResult<ProjectionConfig> {
        projection_config(
            CanonicalNetwork::Regtest,
            SCHEMA_VERSION,
            KEY_EPOCH,
            usize::try_from(DIRECTORY_ADMISSION)?,
            usize::try_from(EVENT_ADMISSION)?,
            usize::try_from(MAX_EVENTS_PER_ADDRESS)?,
        )
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
        Ok((
            OfflineProjectionOwner::from_worker(projection, worker),
            directory_observation,
            event_observation,
        ))
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
    fn linux_rostl_owner_builds_finishes_and_shuts_down() -> FixtureResult<()> {
        let blocks = projection_chain()?;
        let mut owner =
            OfflineProjectionOwner::new(compatible_projection_config()?, compatible_layout()?, 1)?;
        let mut target = None;
        for block in &blocks {
            target = Some(owner.apply_finalized(block)?);
        }
        let target = target.ok_or("fixture chain must be nonempty")?;
        assert_eq!(owner.finish(target)?, target);
        assert_eq!(
            owner.shutdown(),
            ProjectionOwnerShutdownOutcome::Stopped {
                readiness: ProjectionOwnerReadiness::Ready { checkpoint: target },
            }
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
