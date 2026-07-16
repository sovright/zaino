//! Coherent chain-native inputs for transparent-state projections.

use std::collections::BTreeSet;

use super::{
    non_finalised_state::{
        CanonicalRecentChainSnapshot, CanonicalRecentChainSnapshotError, ChainIndexSnapshot,
    },
    source::BlockchainSource,
    types::{
        extract_transparent_events, BlockIndex, FinalizedOutpointSnapshot, Outpoint,
        TransparentBlockEvent, TransparentEventError,
    },
    NodeBackedChainIndexSubscriber, ZebraNetwork,
};
use crate::error::FinalisedStateError;

/// One value-bound transparent projection input captured across finalized and recent state.
///
/// This value deliberately contains no projection schema, key epoch, publication generation, or
/// database handle. Those belong to the projection owner that consumes this chain-native input.
#[derive(Clone)]
#[allow(dead_code)] // Consumed by the immediately stacked zaino-oram controller integration.
pub(super) struct CanonicalTransparentProjectionInput {
    network: ZebraNetwork,
    recent: CanonicalRecentChainSnapshot,
    finalized_outpoints: FinalizedOutpointSnapshot,
}

impl CanonicalTransparentProjectionInput {
    /// Returns the network whose activation rules govern this chain input.
    #[allow(dead_code)] // Consumed by the immediately stacked zaino-oram controller integration.
    pub(super) fn network(&self) -> &ZebraNetwork {
        &self.network
    }

    /// Returns the immutable canonical recent-chain segment.
    #[allow(dead_code)] // Consumed by the immediately stacked zaino-oram controller integration.
    pub(super) fn recent(&self) -> &CanonicalRecentChainSnapshot {
        &self.recent
    }

    /// Returns the exact-seam finalized outpoint classifications.
    #[allow(dead_code)] // Consumed by the immediately stacked zaino-oram controller integration.
    pub(super) fn finalized_outpoints(&self) -> &FinalizedOutpointSnapshot {
        &self.finalized_outpoints
    }
}

/// Why a coherent transparent projection input could not be captured.
#[derive(Debug, thiserror::Error)]
#[allow(dead_code)] // Error surface for the staged capture entrypoint below.
pub(super) enum CanonicalTransparentProjectionInputError {
    /// The chain index has not published a non-finalized state yet.
    #[error("transparent projection input is unavailable while non-finalized state is syncing")]
    NonFinalizedStateUnavailable,
    /// The retained non-finalized snapshot had no canonical checkpoint.
    #[error("transparent projection input has no retained canonical checkpoint")]
    RetainedCheckpointUnavailable,
    /// The canonical recent segment was malformed or unavailable.
    #[error(transparent)]
    CanonicalRecentChain(#[from] CanonicalRecentChainSnapshotError),
    /// A recent block could not be represented in the transparent event domain.
    #[error(transparent)]
    TransparentEvents(#[from] TransparentEventError),
    /// Finalized storage was unavailable, inconsistent, or did not match the requested checkpoint.
    #[error("finalized outpoint materialization failed")]
    FinalizedState(#[from] FinalisedStateError),
    /// The finalized materializer returned a different checkpoint or request cardinality.
    #[error("finalized outpoint materialization did not match the requested projection input")]
    FinalizedMaterializationMismatch,
}

impl<Source: BlockchainSource> NodeBackedChainIndexSubscriber<Source> {
    /// Captures all chain-native data needed to construct a transparent projection generation.
    ///
    /// This method never falls back to the backing validator. It joins one immutable canonical
    /// recent snapshot to a finalized outpoint snapshot materialized at the exact retained seam.
    /// The result is value-coherent even if live state advances afterward; freshness belongs to the
    /// projection owner's serving-epoch lease.
    #[allow(dead_code)] // Consumed by the immediately stacked zaino-oram controller integration.
    pub(super) async fn capture_canonical_transparent_projection_input(
        &self,
    ) -> Result<CanonicalTransparentProjectionInput, CanonicalTransparentProjectionInputError> {
        let snapshot = self.direct_non_finalized_snapshot()?;
        let checkpoint = retained_checkpoint(&snapshot)?;
        let recent = snapshot.canonical_recent_chain(checkpoint)?;
        let (expected_new_outpoints, required_outpoints) = partition_referenced_outpoints(&recent)?;
        let requested_outpoint_count = expected_new_outpoints.len() + required_outpoints.len();

        let finalized_outpoints = self
            .finalized_state
            .materialize_finalized_outpoints(checkpoint, expected_new_outpoints, required_outpoints)
            .await?;
        if finalized_outpoints.checkpoint() != checkpoint
            || finalized_outpoints.len() != requested_outpoint_count
        {
            return Err(CanonicalTransparentProjectionInputError::FinalizedMaterializationMismatch);
        }

        Ok(CanonicalTransparentProjectionInput {
            network: self.network.clone(),
            recent,
            finalized_outpoints,
        })
    }

    #[allow(dead_code)] // Helper for the staged capture entrypoint above.
    fn direct_non_finalized_snapshot(
        &self,
    ) -> Result<ChainIndexSnapshot, CanonicalTransparentProjectionInputError> {
        let non_finalized_state = self
            .non_finalized_state
            .load_full()
            .ok_or(CanonicalTransparentProjectionInputError::NonFinalizedStateUnavailable)?;

        Ok(ChainIndexSnapshot::NonFinalizedStateExists {
            non_finalized_snapshot: non_finalized_state.get_snapshot(),
        })
    }
}

#[allow(dead_code)] // Helper for the staged capture entrypoint above.
fn retained_checkpoint(
    snapshot: &ChainIndexSnapshot,
) -> Result<BlockIndex, CanonicalTransparentProjectionInputError> {
    let non_finalized = snapshot
        .get_nfs_snapshot()
        .ok_or(CanonicalTransparentProjectionInputError::NonFinalizedStateUnavailable)?;
    let height = non_finalized
        .heights_to_hashes
        .keys()
        .min()
        .copied()
        .ok_or(CanonicalTransparentProjectionInputError::RetainedCheckpointUnavailable)?;
    let hash = non_finalized
        .heights_to_hashes
        .get(&height)
        .copied()
        .ok_or(CanonicalTransparentProjectionInputError::RetainedCheckpointUnavailable)?;

    Ok(BlockIndex { height, hash })
}

#[allow(dead_code)] // Helper for the staged capture entrypoint above.
fn partition_referenced_outpoints(
    recent: &CanonicalRecentChainSnapshot,
) -> Result<(Vec<Outpoint>, Vec<Outpoint>), TransparentEventError> {
    let mut referenced = BTreeSet::new();
    let mut expected_new = BTreeSet::new();
    for block in recent.blocks() {
        for event in extract_transparent_events(block)? {
            match event {
                TransparentBlockEvent::Created { outpoint, .. } => {
                    referenced.insert(outpoint);
                    expected_new.insert(outpoint);
                }
                TransparentBlockEvent::Spent { previous, .. } => {
                    referenced.insert(previous);
                }
            }
        }
    }
    let required = referenced.difference(&expected_new).copied().collect();
    Ok((expected_new.into_iter().collect(), required))
}
