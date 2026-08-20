//! Read-only serving handoff for one completed finalized projection generation.

use std::{collections::BTreeSet, fmt};

use crate::{
    canonical_chain::PublicChainCheckpoint,
    checkpoint::ProjectionCheckpointPublisher,
    recent_snapshot::{FinalizedServingStore, RecentSnapshotIdentity},
    records::{finalized_live_slots, AddressKey, RecordAnnotation, TransparentUtxo},
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
    appended: BTreeSet<AddressKey>,
}

impl<P> OfflineProjectionOwner<P>
where
    P: ProjectionCheckpointPublisher,
{
    /// Consumes a Ready projection owner into its read-only serving facade.
    pub(crate) fn into_serving_store(
        self,
    ) -> Result<FinalizedProjectionServingStore, FinalizedProjectionServingStoreBuildError> {
        let (config, checkpoint, worker, appended) = self
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
            appended,
        })
    }
}

impl FinalizedProjectionServingStore {
    /// Returns the public checkpoint captured by the consumed Ready owner.
    pub(crate) const fn committed_checkpoint(&self) -> PublicChainCheckpoint {
        self.checkpoint
    }

    /// Returns every address this projection appended an event for.
    ///
    /// ADR 0902 obligation 6's third term. A record appended since the last
    /// completed annotation pass carries no annotation, so the next pass has to
    /// visit its address; the store's tables offer no enumeration, so this set
    /// is accumulated as the events are applied and carried here.
    pub(crate) const fn appended_addresses(&self) -> &BTreeSet<AddressKey> {
        &self.appended
    }

    /// Runs one generation's record-annotation pass over `visit`.
    ///
    /// This is the only write this facade performs, and it is the reason the
    /// facade rather than a separate handle owns it. Construction consumed the
    /// append-capable owner precisely so no writer could exist beside the
    /// serving reads; publication still has to annotate, so the capability lives
    /// here, reachable only through `&mut self` and never through
    /// [`ObliviousStore`], which is all a query ever sees.
    ///
    /// `annotate` decides both the value and whether to write at all. Returning
    /// `None` skips the record, which is how ADR 0902 obligation 7's filter is
    /// applied: a record named by neither the current nor the previous snapshot
    /// cannot have changed, and issuing a write for it would pay for an
    /// oblivious upsert schedule to change nothing. The caller owns that
    /// decision because it holds the snapshots; this store is not generic over
    /// the snapshot width and does not need to be.
    ///
    /// Records are addressed through [`finalized_live_slots`], so only occupied
    /// creation ordinals are ever written --- annotating a padding ordinal would
    /// insert a record that does not exist (obligation 7).
    #[cfg(feature = "corpus-zaino")]
    pub(crate) fn annotate_generation(
        &mut self,
        visit: &BTreeSet<AddressKey>,
        annotate: &dyn Fn(&AddressKey, &TransparentUtxo) -> Option<RecordAnnotation>,
    ) -> Result<(), AnnotationPassFailed> {
        for address_key in visit {
            let history = self
                .worker
                .serving_read_history(address_key)
                .map_err(|()| AnnotationPassFailed)?;
            let live = finalized_live_slots(&history, self.checkpoint.height())
                .map_err(|_| AnnotationPassFailed)?;
            for slot in live.iter().flatten() {
                let Some(annotation) = annotate(address_key, &slot.utxo()) else {
                    continue;
                };
                let ordinal = u64::try_from(slot.ordinal()).map_err(|_| AnnotationPassFailed)?;
                self.worker
                    .serving_annotate(address_key, ordinal, annotation)
                    .map_err(|()| AnnotationPassFailed)?;
            }
        }
        Ok(())
    }
}

/// One generation's annotation pass did not complete.
///
/// Identifier-free by construction: the pass fails as a whole and the caller
/// discards the generation (ADR 0902 obligations 2 and 5), so nothing about
/// which address or record failed is reportable or useful.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AnnotationPassFailed;

impl fmt::Display for AnnotationPassFailed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the generation's annotation pass did not complete")
    }
}

impl std::error::Error for AnnotationPassFailed {}

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
            Some(slot) => Ok(StoreSlot::occupied(slot.utxo(), slot.annotation())),
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
pub(crate) struct FinalizedProjectionServingStoreBuildError;

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
