//! Read-only serving handoff for one completed finalized projection generation.

use std::fmt;

use crate::{
    canonical_chain::PublicChainCheckpoint,
    checkpoint::ProjectionCheckpointPublisher,
    recent_snapshot::{FinalizedServingStore, RecentSnapshotIdentity},
    records::AddressKey,
    store::{ObliviousStore, StoreSlot},
};

use super::OfflineProjectionOwner;

/// Owns the exact atomic worker consumed from one Ready finalized projection.
///
/// Construction consumes the offline owner so no append-capable handle remains
/// beside this read-only facade. This is a logical fixed-shape adapter over the
/// research worker; it does not establish persistence or physical obliviousness.
pub(crate) struct FinalizedProjectionServingStore {
    checkpoint: PublicChainCheckpoint,
    identity: RecentSnapshotIdentity,
    slots_per_key: usize,
    worker: crate::layout::AtomicWorker,
}

impl<P> OfflineProjectionOwner<P>
where
    P: ProjectionCheckpointPublisher,
{
    /// Consumes a Ready projection owner into its read-only serving facade.
    pub(super) fn into_serving_store(
        self,
    ) -> Result<FinalizedProjectionServingStore, FinalizedProjectionServingStoreBuildError> {
        let (config, checkpoint, worker) = self
            .coordinator
            .into_ready_parts()
            .ok_or(FinalizedProjectionServingStoreBuildError)?;
        if checkpoint.network() != config.network() {
            return Err(FinalizedProjectionServingStoreBuildError);
        }

        Ok(FinalizedProjectionServingStore {
            checkpoint,
            identity: RecentSnapshotIdentity::from_finalized_projection(
                config.network(),
                checkpoint.height(),
                checkpoint.block_hash().bytes_in_display_order(),
                config.schema_version(),
                config.projection_epoch(),
                config.key_epoch(),
            ),
            slots_per_key: config.capacities().max_events_per_address(),
            worker,
        })
    }
}

impl FinalizedProjectionServingStore {
    /// Returns the public checkpoint captured by the consumed Ready owner.
    pub(super) const fn committed_checkpoint(&self) -> PublicChainCheckpoint {
        self.checkpoint
    }
}

impl ObliviousStore for FinalizedProjectionServingStore {
    type Error = FinalizedProjectionServingStoreUnavailable;

    fn slots_per_key(&self) -> usize {
        self.slots_per_key
    }

    fn read_slot(
        &mut self,
        address_key: &AddressKey,
        slot: usize,
    ) -> Result<StoreSlot, Self::Error> {
        match self
            .worker
            .serving_read_slot(address_key, slot, self.checkpoint.height())
            .map_err(|()| FinalizedProjectionServingStoreUnavailable)?
        {
            Some(record) => Ok(StoreSlot::occupied(record)),
            None => Ok(StoreSlot::dummy()),
        }
    }
}

impl FinalizedServingStore for FinalizedProjectionServingStore {
    fn serving_identity(&self) -> RecentSnapshotIdentity {
        self.identity
    }
}

impl fmt::Debug for FinalizedProjectionServingStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FinalizedProjectionServingStore { ..REDACTED.. }")
    }
}

/// A completed owner could not issue a finalized serving-store generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct FinalizedProjectionServingStoreBuildError;

impl fmt::Display for FinalizedProjectionServingStoreBuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("finalized projection is unavailable for serving")
    }
}

impl std::error::Error for FinalizedProjectionServingStoreBuildError {}

/// A finalized serving read failed without exposing protected identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FinalizedProjectionServingStoreUnavailable;

impl fmt::Display for FinalizedProjectionServingStoreUnavailable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("finalized projection serving store is unavailable")
    }
}

impl std::error::Error for FinalizedProjectionServingStoreUnavailable {}
