//! Coherent chain-native inputs for transparent-state projections.

use std::{collections::BTreeSet, fmt, sync::Arc};

use super::{
    non_finalised_state::{
        CanonicalRecentChainSnapshot, CanonicalRecentChainSnapshotError, ChainIndexSnapshot,
        NonfinalizedBlockCacheSnapshot,
    },
    source::BlockchainSource,
    types::{
        extract_transparent_events, BlockIndex, FinalizedOutpointSnapshot, FinalizedOutpointState,
        Outpoint, TransparentBlockEvent, TransparentEventError,
    },
    NodeBackedChainIndexSubscriber, ZebraNetwork,
};
use crate::{error::FinalisedStateError, StatusType};

/// Public identity and opaque in-memory revision of one canonical transparent capture.
///
/// The public fields describe the chain values observed from one immutable
/// non-finalized snapshot. [`Self::same_capture`] additionally compares the
/// private snapshot allocation, so replacing an `Arc` with equal values still
/// counts as a distinct capture revision.
#[derive(Clone)]
pub struct CanonicalTransparentProjectionBoundary {
    network: ZebraNetwork,
    finalized: BlockIndex,
    tip: BlockIndex,
    revision: Arc<NonfinalizedBlockCacheSnapshot>,
}

impl CanonicalTransparentProjectionBoundary {
    fn new(
        network: ZebraNetwork,
        finalized: BlockIndex,
        tip: BlockIndex,
        revision: Arc<NonfinalizedBlockCacheSnapshot>,
    ) -> Self {
        Self {
            network,
            finalized,
            tip,
            revision,
        }
    }

    /// Returns the network whose activation rules govern this boundary.
    pub fn network(&self) -> &ZebraNetwork {
        &self.network
    }

    /// Returns the retained finalized checkpoint at the capture seam.
    pub fn finalized(&self) -> BlockIndex {
        self.finalized
    }

    /// Returns the canonical non-finalized tip observed by the capture.
    pub fn tip(&self) -> BlockIndex {
        self.tip
    }

    /// Returns true only when both boundaries came from the exact same snapshot allocation.
    pub fn same_capture(&self, other: &Self) -> bool {
        self.network == other.network
            && self.finalized == other.finalized
            && self.tip == other.tip
            && Arc::ptr_eq(&self.revision, &other.revision)
    }
}

impl fmt::Debug for CanonicalTransparentProjectionBoundary {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CanonicalTransparentProjectionBoundary { ..REDACTED.. }")
    }
}

/// One value-bound transparent projection input captured across finalized and recent state.
///
/// This value deliberately contains no projection schema, key epoch, publication generation, or
/// database handle. Those belong to the projection owner that consumes this chain-native input.
#[derive(Clone)]
pub struct CanonicalTransparentProjectionInput {
    recent: CanonicalRecentChainSnapshot,
    finalized_outpoints: FinalizedOutpointSnapshot,
    boundary: CanonicalTransparentProjectionBoundary,
}

impl CanonicalTransparentProjectionInput {
    /// Returns the network whose activation rules govern this chain input.
    pub fn network(&self) -> &ZebraNetwork {
        self.boundary.network()
    }

    /// Returns the immutable canonical recent-chain segment.
    pub fn recent(&self) -> &CanonicalRecentChainSnapshot {
        &self.recent
    }

    /// Returns the exact finalized checkpoint used for all classifications.
    pub fn finalized_checkpoint(&self) -> BlockIndex {
        self.finalized_outpoints.checkpoint()
    }

    /// Returns the number of unique outpoints materialized at the finalized seam.
    #[cfg(test)]
    pub(super) fn finalized_outpoint_count(&self) -> usize {
        self.finalized_outpoints.len()
    }

    /// Returns the materialized finalized state for a requested outpoint.
    ///
    /// `None` means the outpoint was not part of this bounded capture, not that
    /// it was absent from the chain.
    pub fn classify_finalized_outpoint(
        &self,
        outpoint: &Outpoint,
    ) -> Option<FinalizedOutpointState> {
        self.finalized_outpoints.classify(outpoint)
    }

    /// Returns the public values and opaque NFS revision for freshness checks.
    pub fn boundary(&self) -> &CanonicalTransparentProjectionBoundary {
        &self.boundary
    }
}

/// Why a coherent transparent projection input could not be captured.
#[derive(Debug, thiserror::Error)]
pub enum CanonicalTransparentProjectionInputError {
    /// A current boundary was requested before each required canonical component was ready.
    #[error("transparent projection boundary is unavailable while the chain index is not ready")]
    ChainIndexNotReady,
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
    pub async fn capture_canonical_transparent_projection_input(
        &self,
    ) -> Result<CanonicalTransparentProjectionInput, CanonicalTransparentProjectionInputError> {
        let revision = self.direct_non_finalized_snapshot()?;
        let snapshot = ChainIndexSnapshot::NonFinalizedStateExists {
            non_finalized_snapshot: Arc::clone(&revision),
        };
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

        let network = self.network.clone();
        let boundary = CanonicalTransparentProjectionBoundary::new(
            network.clone(),
            checkpoint,
            recent.tip(),
            revision,
        );
        Ok(CanonicalTransparentProjectionInput {
            recent,
            finalized_outpoints,
            boundary,
        })
    }

    /// Returns the current direct-NFS boundary without finalized DB or source work.
    ///
    /// This synchronous check is deliberately unavailable unless the
    /// canonical chain-index and finalized-state components are both ready;
    /// unrelated mempool readiness does not participate. Readiness and the
    /// opaque NFS revision are observed twice so a sync iteration cannot race
    /// the snapshot load and make a stale revision look current.
    pub fn current_canonical_transparent_projection_boundary(
        &self,
    ) -> Result<CanonicalTransparentProjectionBoundary, CanonicalTransparentProjectionInputError>
    {
        current_projection_boundary_from_observers(
            self.network.clone(),
            || (self.status.load(), self.finalized_state.status()),
            || self.direct_non_finalized_snapshot(),
        )
    }

    fn direct_non_finalized_snapshot(
        &self,
    ) -> Result<Arc<NonfinalizedBlockCacheSnapshot>, CanonicalTransparentProjectionInputError> {
        let non_finalized_state = self
            .non_finalized_state
            .load_full()
            .ok_or(CanonicalTransparentProjectionInputError::NonFinalizedStateUnavailable)?;

        Ok(non_finalized_state.get_snapshot())
    }
}

/// Performs the production double observation through injected read seams so
/// deterministic tests exercise the same ordering as the live subscriber.
fn current_projection_boundary_from_observers<ObserveStatus, ObserveRevision>(
    network: ZebraNetwork,
    mut observe_status: ObserveStatus,
    mut observe_revision: ObserveRevision,
) -> Result<CanonicalTransparentProjectionBoundary, CanonicalTransparentProjectionInputError>
where
    ObserveStatus: FnMut() -> (StatusType, StatusType),
    ObserveRevision: FnMut() -> Result<
        Arc<NonfinalizedBlockCacheSnapshot>,
        CanonicalTransparentProjectionInputError,
    >,
{
    let (chain_index_status, finalized_state_status) = observe_status();
    if !projection_components_are_ready(chain_index_status, finalized_state_status) {
        return Err(CanonicalTransparentProjectionInputError::ChainIndexNotReady);
    }

    let revision = observe_revision()?;
    let snapshot = ChainIndexSnapshot::NonFinalizedStateExists {
        non_finalized_snapshot: Arc::clone(&revision),
    };
    let finalized = retained_checkpoint(&snapshot)?;

    // Observe readiness before reloading the revision. A successful read
    // linearizes at this Ready observation: a transition already in flight
    // fails readiness, one that completes before the reload changes the Arc,
    // and one that begins afterward is later than the observation.
    let (current_chain_index_status, current_finalized_state_status) = observe_status();
    if !projection_components_are_ready(current_chain_index_status, current_finalized_state_status)
    {
        return Err(CanonicalTransparentProjectionInputError::ChainIndexNotReady);
    }
    let current_revision = observe_revision()?;
    if !Arc::ptr_eq(&revision, &current_revision) {
        return Err(CanonicalTransparentProjectionInputError::ChainIndexNotReady);
    }

    Ok(CanonicalTransparentProjectionBoundary::new(
        network,
        finalized,
        revision.best_tip,
        revision,
    ))
}

/// Projection freshness depends on canonical chain components, not mempool readiness.
fn projection_components_are_ready(chain_index: StatusType, finalized_state: StatusType) -> bool {
    chain_index == StatusType::Ready && finalized_state == StatusType::Ready
}

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

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::{BlockHash, Height};

    fn revision(index: BlockIndex) -> Arc<NonfinalizedBlockCacheSnapshot> {
        Arc::new(NonfinalizedBlockCacheSnapshot {
            blocks: HashMap::new(),
            heights_to_hashes: HashMap::from([(index.height, index.hash)]),
            best_tip: index,
        })
    }

    fn observed_boundary(
        statuses: [(StatusType, StatusType); 2],
        revisions: [Arc<NonfinalizedBlockCacheSnapshot>; 2],
    ) -> Result<CanonicalTransparentProjectionBoundary, CanonicalTransparentProjectionInputError>
    {
        let mut statuses = statuses.into_iter();
        let mut revisions = revisions.into_iter();
        current_projection_boundary_from_observers(
            ZebraNetwork::Mainnet,
            || {
                statuses
                    .next()
                    .unwrap_or((StatusType::Syncing, StatusType::Syncing))
            },
            || {
                revisions
                    .next()
                    .ok_or(CanonicalTransparentProjectionInputError::NonFinalizedStateUnavailable)
            },
        )
    }

    #[test]
    fn same_capture_rejects_equal_value_arc_replacement() {
        let finalized = BlockIndex {
            height: Height(100),
            hash: BlockHash([0x11; 32]),
        };
        let tip = BlockIndex {
            height: Height(102),
            hash: BlockHash([0x22; 32]),
        };
        let original_revision = revision(tip);
        let original = CanonicalTransparentProjectionBoundary::new(
            ZebraNetwork::Mainnet,
            finalized,
            tip,
            Arc::clone(&original_revision),
        );
        let same_revision = CanonicalTransparentProjectionBoundary::new(
            ZebraNetwork::Mainnet,
            finalized,
            tip,
            Arc::clone(&original_revision),
        );
        let equal_value_replacement = CanonicalTransparentProjectionBoundary::new(
            ZebraNetwork::Mainnet,
            finalized,
            tip,
            revision(tip),
        );

        assert!(original.same_capture(&same_revision));
        assert!(!original.same_capture(&equal_value_replacement));
        assert_eq!(
            format!("{original:?}"),
            "CanonicalTransparentProjectionBoundary { ..REDACTED.. }"
        );
    }

    #[test]
    fn projection_readiness_requires_only_canonical_chain_components() {
        assert!(projection_components_are_ready(
            StatusType::Ready,
            StatusType::Ready
        ));
        assert!(!projection_components_are_ready(
            StatusType::Syncing,
            StatusType::Ready
        ));
        assert!(!projection_components_are_ready(
            StatusType::Ready,
            StatusType::Syncing
        ));
    }

    #[test]
    fn boundary_observation_rejects_ready_to_syncing_transition() {
        let index = BlockIndex {
            height: Height(100),
            hash: BlockHash([0x33; 32]),
        };
        let captured_revision = revision(index);

        assert!(matches!(
            observed_boundary(
                [
                    (StatusType::Ready, StatusType::Ready),
                    (StatusType::Syncing, StatusType::Ready),
                ],
                [Arc::clone(&captured_revision), captured_revision],
            ),
            Err(CanonicalTransparentProjectionInputError::ChainIndexNotReady)
        ));
    }

    #[test]
    fn boundary_observation_rejects_equal_value_revision_replacement() {
        let index = BlockIndex {
            height: Height(100),
            hash: BlockHash([0x44; 32]),
        };
        let captured_revision = revision(index);
        let equal_value_replacement = revision(index);

        assert!(matches!(
            observed_boundary(
                [
                    (StatusType::Ready, StatusType::Ready),
                    (StatusType::Ready, StatusType::Ready),
                ],
                [captured_revision, equal_value_replacement],
            ),
            Err(CanonicalTransparentProjectionInputError::ChainIndexNotReady)
        ));
    }

    #[test]
    fn boundary_observation_accepts_one_unchanged_ready_revision() {
        let index = BlockIndex {
            height: Height(100),
            hash: BlockHash([0x55; 32]),
        };
        let captured_revision = revision(index);
        let boundary = observed_boundary(
            [
                (StatusType::Ready, StatusType::Ready),
                (StatusType::Ready, StatusType::Ready),
            ],
            [Arc::clone(&captured_revision), captured_revision],
        )
        .expect("unchanged ready revision forms one coherent test boundary");

        assert_eq!(boundary.finalized(), index);
        assert_eq!(boundary.tip(), index);
    }
}
