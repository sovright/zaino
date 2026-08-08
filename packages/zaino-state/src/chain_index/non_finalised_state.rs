use super::{
    finalised_state::{reader::DbReader, FinalisedState},
    source::BlockchainSource,
    OPERATIONAL_NFS_DEPTH,
};
#[cfg(feature = "prometheus")]
use crate::metric_names::*;
use crate::{
    chain_index::types::{
        self, BlockHash, BlockIndex, BlockMetadata, BlockWithMetadata, Height, TreeRootData,
    },
    error::FinalisedStateError,
    ChainWork, IndexedBlock,
};
use arc_swap::ArcSwap;
use futures::lock::Mutex;
use std::{collections::HashMap, sync::Arc};
use tokio::sync::mpsc;
use tracing::{info, instrument, warn};
use zebra_chain::{parameters::Network, serialization::BytesInDisplayOrder};
use zebra_state::HashOrHeight;

/// Hard cap on how many blocks below the tip the non-finalised state retains in memory.
///
/// [`NonFinalizedState::update`] normally trims everything below the finalised database height,
/// but that height can lag far behind the tip while the finalised DB syncs in the background, and
/// is pinned at `0` in ephemeral mode. Without an independent floor the snapshot would grow by one
/// block per new block indefinitely. This caps retention to a fixed window regardless, a small
/// margin above [`OPERATIONAL_NFS_DEPTH`] so it never trims inside the reorg-possible range.
///
/// It also bounds the non-finalised ancestry walkers ([`NonFinalizedState::handle_reorg`] and
/// [`NonFinalizedState::add_nonbest_block`]): neither should recurse further back than the window
/// they maintain. The bound is load-bearing for `add_nonbest_block` on the state backend, where
/// `source.get_block` serves *any* block by hash (including finalised blocks below the window), so
/// without it a side chain rooted below the anchor would recurse to genesis and overflow the stack.
const MAX_NFS_DEPTH: u32 = OPERATIONAL_NFS_DEPTH + 10;

/// Holds the block cache
#[derive(Debug)]
pub struct NonFinalizedState<Source: BlockchainSource> {
    /// We need access to the validator's best block hash, as well
    /// as a source of blocks
    pub(super) source: Source,
    /// This lock should not be exposed to consumers. Rather,
    /// clone the Arc and offer that. This means we can overwrite the arc
    /// without interfering with readers, who will hold a stale copy
    current: ArcSwap<NonfinalizedBlockCacheSnapshot>,
    /// Used mostly to determine activation heights
    pub(crate) network: Network,
    /// Listener used to detect non-best-chain blocks, if available
    #[allow(clippy::type_complexity)]
    nfs_change_listener: Option<
        Mutex<
            tokio::sync::mpsc::Receiver<(zebra_chain::block::Hash, Arc<zebra_chain::block::Block>)>,
        >,
    >,
}

#[derive(Debug, Clone)]
/// A snapshot of the chain index
///
/// If zaino has synced above the validator's finalized tip,
/// this contains a snapshot of the non-finalized state.
///
/// If zaino is still syncing, this contains only the height
/// of the validator's finalized tip as of snapshot creation,
/// which is used to determine how high we can pass through
/// calls to the backing validator without serving nonfinalized
/// data.
pub enum ChainIndexSnapshot {
    /// Zaino is ready to serve non-finalized data.
    NonFinalizedStateExists {
        /// The snapshot of the non_finalized state.
        #[allow(private_interfaces)]
        // Rust doesn't support private fields of enum variants
        // The type of this field being private gives us something like it, though
        non_finalized_snapshot: Arc<NonfinalizedBlockCacheSnapshot>,
    },
    /// Zaino is not ready to serve non-finalized data.
    StillSyncingFinalizedState {
        /// The height the validater had last finalized as of snapshot creation.
        validator_finalized_height: Height,
    },
}

/// One structurally consistent, immutable canonical chain segment above a finalized checkpoint.
///
/// [`Self::blocks`] contains only blocks strictly above [`Self::finalized`], in
/// ascending height order through [`Self::tip`]. The segment owns cloned block
/// values so it cannot observe a later non-finalized-state publication. It is a
/// value-bound join against one immutable non-finalized snapshot, not an atomic
/// capture of finalized storage and non-finalized state.
#[derive(Clone)]
pub struct CanonicalRecentChainSnapshot {
    finalized: BlockIndex,
    tip: BlockIndex,
    blocks: Arc<[IndexedBlock]>,
}

impl CanonicalRecentChainSnapshot {
    /// Constructs a canonical recent-chain fixture without repeating cache validation.
    #[cfg(feature = "test_dependencies")]
    #[doc(hidden)]
    pub fn from_parts_for_tests(
        finalized: BlockIndex,
        tip: BlockIndex,
        blocks: Vec<IndexedBlock>,
    ) -> Self {
        Self {
            finalized,
            tip,
            blocks: blocks.into(),
        }
    }

    /// Returns the finalized checkpoint that immediately precedes the recent blocks.
    pub fn finalized(&self) -> BlockIndex {
        self.finalized
    }

    /// Returns the canonical tip captured by this snapshot.
    pub fn tip(&self) -> BlockIndex {
        self.tip
    }

    /// Returns canonical blocks strictly above the finalized checkpoint, oldest first.
    pub fn blocks(&self) -> &[IndexedBlock] {
        &self.blocks
    }
}

/// Why a canonical recent-chain segment could not be derived from one chain-index snapshot.
///
/// Errors carry public heights only. They intentionally omit hashes and block data so normal
/// error formatting cannot disclose or accidentally retain full snapshot contents.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum CanonicalRecentChainSnapshotError {
    /// The chain index has not published a non-finalized snapshot yet.
    #[error("canonical recent chain is unavailable while finalized state is still syncing")]
    StillSyncing,
    /// The requested finalized checkpoint is above the immutable snapshot tip.
    #[error("finalized checkpoint height {finalized_height} is above snapshot tip {tip_height}")]
    FinalizedAboveTip {
        /// Requested finalized checkpoint height.
        finalized_height: Height,
        /// Immutable snapshot tip height.
        tip_height: Height,
    },
    /// The canonical height map or block map does not retain the requested finalized checkpoint.
    #[error("finalized checkpoint is missing at height {height}")]
    FinalizedCheckpointMissing {
        /// Missing finalized checkpoint height.
        height: Height,
    },
    /// The canonical height map binds the finalized height to a different hash.
    #[error("finalized checkpoint hash does not match at height {height}")]
    FinalizedCheckpointHashMismatch {
        /// Mismatched finalized checkpoint height.
        height: Height,
    },
    /// The finalized block payload does not identify itself as the requested checkpoint.
    #[error("finalized checkpoint payload identity does not match at height {height}")]
    FinalizedCheckpointIdentityMismatch {
        /// Mismatched finalized checkpoint height.
        height: Height,
    },
    /// The declared best tip and canonical height map disagree.
    #[error("canonical height map does not match the declared tip at height {height}")]
    TipMismatch {
        /// Declared tip height.
        height: Height,
    },
    /// A height is absent between the finalized checkpoint and the declared tip.
    #[error("canonical recent chain is not contiguous at height {height}")]
    NonContiguousHeight {
        /// First missing canonical height.
        height: Height,
    },
    /// The height map points to a block hash that has no corresponding block payload.
    #[error("canonical block payload is missing at height {height}")]
    CanonicalBlockMissing {
        /// Height whose canonical block payload is missing.
        height: Height,
    },
    /// A mapped block payload's internal height or hash disagrees with the canonical map.
    #[error("canonical block payload identity does not match at height {height}")]
    CanonicalBlockIdentityMismatch {
        /// Height whose canonical block payload has the wrong identity.
        height: Height,
    },
    /// A canonical block does not name the preceding canonical block as its parent.
    #[error("canonical parent link does not match at height {height}")]
    ParentHashMismatch {
        /// Height whose parent link is inconsistent.
        height: Height,
    },
}

impl ChainIndexSnapshot {
    /// Derives the canonical recent chain above `finalized` from this immutable snapshot only.
    ///
    /// This method never consults finalized storage or a backing validator. It verifies the exact
    /// finalized height/hash seam, the declared best tip, every canonical height and mapped block
    /// payload identity, and parent-hash continuity before returning cloned blocks in ascending
    /// height order. Blocks present only in the side-chain cache are ignored because canonical
    /// membership comes solely from the snapshot's height-to-hash map. The caller-supplied
    /// checkpoint is joined by value to one immutable non-finalized snapshot; finalized storage is
    /// not captured atomically with it.
    pub fn canonical_recent_chain(
        &self,
        finalized: BlockIndex,
    ) -> Result<CanonicalRecentChainSnapshot, CanonicalRecentChainSnapshotError> {
        let non_finalized_snapshot = match self {
            Self::NonFinalizedStateExists {
                non_finalized_snapshot,
            } => non_finalized_snapshot,
            Self::StillSyncingFinalizedState { .. } => {
                return Err(CanonicalRecentChainSnapshotError::StillSyncing)
            }
        };
        let tip = non_finalized_snapshot.best_tip;

        if finalized.height > tip.height {
            return Err(CanonicalRecentChainSnapshotError::FinalizedAboveTip {
                finalized_height: finalized.height,
                tip_height: tip.height,
            });
        }

        let tip_hash = non_finalized_snapshot
            .heights_to_hashes
            .get(&tip.height)
            .ok_or(CanonicalRecentChainSnapshotError::TipMismatch { height: tip.height })?;
        if *tip_hash != tip.hash
            || non_finalized_snapshot
                .heights_to_hashes
                .keys()
                .any(|height| *height > tip.height)
        {
            return Err(CanonicalRecentChainSnapshotError::TipMismatch { height: tip.height });
        }

        let finalized_hash = non_finalized_snapshot
            .heights_to_hashes
            .get(&finalized.height)
            .ok_or(
                CanonicalRecentChainSnapshotError::FinalizedCheckpointMissing {
                    height: finalized.height,
                },
            )?;
        if *finalized_hash != finalized.hash {
            return Err(
                CanonicalRecentChainSnapshotError::FinalizedCheckpointHashMismatch {
                    height: finalized.height,
                },
            );
        }

        let finalized_block = non_finalized_snapshot.blocks.get(&finalized.hash).ok_or(
            CanonicalRecentChainSnapshotError::FinalizedCheckpointMissing {
                height: finalized.height,
            },
        )?;
        if finalized_block.height() != finalized.height || *finalized_block.hash() != finalized.hash
        {
            return Err(
                CanonicalRecentChainSnapshotError::FinalizedCheckpointIdentityMismatch {
                    height: finalized.height,
                },
            );
        }

        let mut previous_hash = finalized.hash;
        let mut recent_blocks = Vec::new();
        for height in Height::range_inclusive(finalized.height, tip.height).skip(1) {
            let canonical_hash = non_finalized_snapshot
                .heights_to_hashes
                .get(&height)
                .ok_or(CanonicalRecentChainSnapshotError::NonContiguousHeight { height })?;
            let block = non_finalized_snapshot
                .blocks
                .get(canonical_hash)
                .ok_or(CanonicalRecentChainSnapshotError::CanonicalBlockMissing { height })?;
            if block.height() != height || block.hash() != canonical_hash {
                return Err(
                    CanonicalRecentChainSnapshotError::CanonicalBlockIdentityMismatch { height },
                );
            }
            if *block.context.parent_hash() != previous_hash {
                return Err(CanonicalRecentChainSnapshotError::ParentHashMismatch { height });
            }
            previous_hash = *canonical_hash;
            recent_blocks.push(block.clone());
        }

        Ok(CanonicalRecentChainSnapshot {
            finalized,
            tip,
            blocks: recent_blocks.into(),
        })
    }

    /// Convenience fn to go from ChainIndexSnapshot to Option<NonFinalizedBlockCacheSnapshot>,
    /// throwing away the validator_finalized_height in the None case. For ease of mapping, etc.
    pub(crate) fn get_nfs_snapshot(&self) -> Option<&NonfinalizedBlockCacheSnapshot> {
        match self {
            ChainIndexSnapshot::NonFinalizedStateExists {
                non_finalized_snapshot,
            } => Some(non_finalized_snapshot),
            ChainIndexSnapshot::StillSyncingFinalizedState { .. } => None,
        }
    }
}

#[derive(Debug, Clone)]
/// A snapshot of the nonfinalized state as it existed when this was created.
pub(crate) struct NonfinalizedBlockCacheSnapshot {
    /// the set of all known blocks less than `OPERATIONAL_NFS_DEPTH` blocks old
    /// this includes all blocks on-chain, as well as
    /// all blocks known to have been on-chain before being
    /// removed by a reorg. Blocks reorged away have no height.
    pub blocks: HashMap<BlockHash, IndexedBlock>,
    /// hashes indexed by height
    /// Hashes in this map are part of the best chain.
    pub heights_to_hashes: HashMap<Height, BlockHash>,
    // Do we need height here?
    /// The highest known block
    // best_tip is a BestTip, which contains
    // a Height, and a BlockHash as named fields.
    pub best_tip: BlockIndex,
}

#[derive(Debug)]
/// Could not connect to a validator
pub enum NodeConnectionError {
    /// The Uri provided was invalid
    BadUri(String),
    /// Could not connect to the zebrad.
    /// This is a network issue.
    ConnectionFailure(reqwest::Error),
    /// The Zebrad provided invalid or corrupt data. Something has gone wrong
    /// and we need to shut down.
    UnrecoverableError(Box<dyn std::error::Error + Send>),
}

#[derive(Debug)]
struct MissingBlockError(String);

impl std::fmt::Display for MissingBlockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "missing block: {}", self.0)
    }
}

impl std::error::Error for MissingBlockError {}

#[derive(Debug, thiserror::Error)]
/// An error occurred during sync of the NonFinalized State.
pub enum SyncError {
    /// The backing validator node returned corrupt, invalid, or incomplete data.
    #[error("failed to connect to validator: {0:?}")]
    ValidatorConnectionError(NodeConnectionError),
    /// The blockchain source returned a transient error (e.g. node temporarily
    /// unreachable). The sync loop should retry.
    #[error("transient source error: {0}")]
    ErrorFromSource(Box<dyn std::error::Error + Send>),
    /// The channel used to store new blocks has been closed. This should only happen
    /// during shutdown.
    #[error("staging channel closed. Shutdown in progress")]
    StagingChannelClosed,
    /// Sync has been called multiple times in parallel, or another process has
    /// written to the block snapshot.
    #[error("multiple sync processes running")]
    CompetingSyncProcess,
    /// Sync attempted a reorg, and something went wrong.
    #[error("reorg failed: {0}")]
    ReorgFailure(String),
    /// UnrecoverableFinalizedStateError
    #[error("error reading nonfinalized state")]
    CannotReadFinalizedState(#[from] FinalisedStateError),
}

impl From<UpdateError> for SyncError {
    fn from(value: UpdateError) -> Self {
        match value {
            UpdateError::ReceiverDisconnected => SyncError::StagingChannelClosed,
            UpdateError::StaleSnapshot => SyncError::CompetingSyncProcess,
            UpdateError::FinalizedStateCorruption => SyncError::CannotReadFinalizedState(
                FinalisedStateError::Custom("mystery update failure".to_string()),
            ),
            UpdateError::DatabaseHole => {
                SyncError::ReorgFailure(String::from("could not determine best chain"))
            }
            UpdateError::ValidatorConnectionError(e) => SyncError::ValidatorConnectionError(
                NodeConnectionError::UnrecoverableError(Box::new(MissingBlockError(e.to_string()))),
            ),
        }
    }
}

#[derive(thiserror::Error, Debug)]
#[error("Genesis block missing in validator")]
struct MissingGenesisBlock;

#[derive(thiserror::Error, Debug)]
#[error("data from validator invalid: {0}")]
struct InvalidData(String);

#[derive(Debug, thiserror::Error)]
/// An error occured during initial creation of the NonFinalizedState
pub enum InitError {
    #[error("zebra returned invalid data: {0}")]
    /// the connected node returned garbage data
    InvalidNodeData(Box<dyn std::error::Error + Send + Sync + 'static>),
    #[error(transparent)]
    /// The mempool state failed to initialize
    MempoolInitialzationError(#[from] crate::error::MempoolError),
    #[error(transparent)]
    /// The finalized state failed to initialize
    FinalisedStateInitialzationError(#[from] FinalisedStateError),
    /// the initial block provided was not on the best chain
    #[error("initial block not on best chain")]
    InitalBlockMissingHeight,
}

/// This is the core of the concurrent block cache.
impl BlockIndex {
    /// Create a BlockID from an IndexedBlock
    fn from_block(block: &IndexedBlock) -> Self {
        let height = block.height();
        let hash = *block.hash();
        Self { height, hash }
    }
}

impl NonfinalizedBlockCacheSnapshot {
    /// Create initial snapshot from a single block
    fn from_initial_block(block: IndexedBlock) -> Self {
        let best_tip = BlockIndex::from_block(&block);
        let hash = *block.hash();
        let height = best_tip.height;

        let mut blocks = HashMap::new();
        let mut heights_to_hashes = HashMap::new();

        blocks.insert(hash, block);
        heights_to_hashes.insert(height, hash);

        Self {
            blocks,
            heights_to_hashes,
            best_tip,
        }
    }

    fn add_block_new_chaintip(&mut self, block: IndexedBlock) {
        self.best_tip = BlockIndex {
            height: block.height(),
            hash: *block.hash(),
        };
        self.add_block(block)
    }

    fn get_block_by_hash_bytes_in_serialized_order(&self, hash: [u8; 32]) -> Option<&IndexedBlock> {
        self.blocks
            .values()
            .find(|block| block.hash_bytes_serialized_order() == hash)
    }

    fn remove_finalized_blocks(&mut self, finalized_height: Height) {
        let top_block_hash = match self
            .heights_to_hashes
            .iter()
            .max_by_key(|(height, _hash)| *height)
        {
            Some((_height, hash)) => *hash,
            // We have no blocks. There's nothing to remove
            None => return,
        };
        // Keep the last finalized block. This means we don't have to check
        // the finalized state when the entire non-finalized state is reorged away.
        // If all blocks are below the finalized height, keep the highest anyway,
        // so we don't need to re-connect the the finalized state to get chainwork, etc.
        self.blocks.retain(|_hash, block| {
            block.height() >= finalized_height || block.hash() == &top_block_hash
        });
        self.heights_to_hashes
            .retain(|height, hash| height >= &finalized_height || hash == &top_block_hash);
    }

    fn add_block(&mut self, block: IndexedBlock) {
        self.heights_to_hashes.insert(block.height(), *block.hash());
        self.blocks.insert(*block.hash(), block);
    }
}

impl<Source: BlockchainSource> NonFinalizedState<Source> {
    /// Create a nonfinalized state, in a coherent initial state
    ///
    /// TODO: Currently, we can't initate without an snapshot, we need to create a cache
    /// of at least one block. Should this be tied to the instantiation of the data structure
    /// itself?
    #[instrument(name = "NonFinalizedState::initialize", skip(source, start_block), fields(network = %network))]
    pub async fn initialize(
        source: Source,
        network: Network,
        start_block: Option<IndexedBlock>,
    ) -> Result<Self, InitError> {
        info!(network = %network, "Initializing non-finalized state");

        // Resolve the initial block (provided or genesis)
        let initial_block = Self::resolve_initial_block(&source, &network, start_block).await?;

        // Create initial snapshot from the block
        let snapshot = NonfinalizedBlockCacheSnapshot::from_initial_block(initial_block);

        // Set up optional listener
        let nfs_change_listener = Self::setup_listener(&source).await;

        Ok(Self {
            source,
            current: ArcSwap::new(Arc::new(snapshot)),
            network,
            nfs_change_listener,
        })
    }

    /// Fetch the genesis block and convert it to IndexedBlock
    async fn get_genesis_indexed_block(
        source: &Source,
        network: &Network,
    ) -> Result<IndexedBlock, InitError> {
        let genesis_block = source
            .get_block(HashOrHeight::Height(zebra_chain::block::Height(0)))
            .await
            .map_err(|e| InitError::InvalidNodeData(Box::new(e)))?
            .ok_or_else(|| InitError::InvalidNodeData(Box::new(MissingGenesisBlock)))?;

        let (sapling_root_and_len, orchard_root_and_len, ironwood_root_and_len) = source
            .get_commitment_tree_roots(genesis_block.hash().into())
            .await
            .map_err(|e| InitError::InvalidNodeData(Box::new(e)))?;

        let tree_roots = TreeRootData {
            sapling: sapling_root_and_len,
            orchard: orchard_root_and_len,
            ironwood: ironwood_root_and_len,
        };

        // Genesis has no parent — pass None so create_block_context computes
        // chainwork as just the genesis block's own work.
        Self::create_indexed_block_with_optional_roots(
            genesis_block.as_ref(),
            &tree_roots,
            None,
            network.clone(),
        )
        .map_err(|e| InitError::InvalidNodeData(Box::new(InvalidData(e))))
    }

    /// Resolve the initial block - either use provided block or fetch genesis
    async fn resolve_initial_block(
        source: &Source,
        network: &Network,
        start_block: Option<IndexedBlock>,
    ) -> Result<IndexedBlock, InitError> {
        match start_block {
            Some(block) => Ok(block),
            None => Self::get_genesis_indexed_block(source, network).await,
        }
    }

    /// Resolve the non-finalised state's anchor (root) block at `anchor_height`.
    ///
    /// Prefers the finalised reader, which serves the block from the persistent DB when the height
    /// is in range, or from the validator via the ReadOnly ephemeral passthrough while the finalised
    /// DB is catching up in the background. Falls back to building the block directly from the
    /// validator source when the reader cannot serve it yet — e.g. the first worker iteration, before
    /// any passthrough is installed — so the anchor never silently drops to genesis (issue #1261).
    ///
    /// The anchor sits below the reorg-possible range, so its chainwork is irrelevant to best-chain
    /// selection; it is set to zero, matching the ephemeral passthrough's own anchor build.
    pub(super) async fn resolve_anchor_block(
        source: &Source,
        reader: &DbReader<Source>,
        network: &Network,
        anchor_height: Height,
    ) -> Result<IndexedBlock, FinalisedStateError> {
        if let Some(block) = reader.get_chain_block_by_height(anchor_height).await? {
            return Ok(block);
        }

        let block = source
            .get_block(HashOrHeight::Height(zebra_chain::block::Height(
                anchor_height.0,
            )))
            .await?
            .ok_or_else(|| {
                FinalisedStateError::DataUnavailable(format!(
                    "anchor block {} unavailable from validator",
                    anchor_height.0
                ))
            })?;

        let (sapling, orchard, ironwood) = source
            .get_commitment_tree_roots(block.hash().into())
            .await?;
        let tree_roots = TreeRootData {
            sapling,
            orchard,
            ironwood,
        };

        Self::create_indexed_block_with_optional_roots(
            block.as_ref(),
            &tree_roots,
            None,
            network.clone(),
        )
        .map_err(FinalisedStateError::Custom)
    }

    /// Set up the optional non-finalized change listener
    async fn setup_listener(
        source: &Source,
    ) -> Option<
        Mutex<
            tokio::sync::mpsc::Receiver<(zebra_chain::block::Hash, Arc<zebra_chain::block::Block>)>,
        >,
    > {
        source
            .nonfinalized_listener()
            .await
            .ok()
            .flatten()
            .map(Mutex::new)
    }

    /// Sync to the iter-committed `chain_height`, trimming to the finalised
    /// tip.
    ///
    /// `chain_height` is the worker's snapshot of the source's best block
    /// height at the start of this iter (the same value `fs.sync_to_height`
    /// was called against). NFS extension is bounded by that height, so a
    /// source advance mid-iter — the validator producing new blocks while
    /// the worker's NFS-sync loop is still running — is deferred to iter
    /// N+1, which will read a fresh `chain_height` and trim the published
    /// snapshot with the correct finalised floor. Closes #1126.
    #[instrument(name = "NonFinalizedState::sync", skip(self, finalized_db))]
    pub(super) async fn sync(
        &self,
        finalized_db: Arc<FinalisedState<Source>>,
        chain_height: Height,
    ) -> Result<(), SyncError> {
        let mut initial_state = self.get_snapshot();
        let local_finalized_tip = finalized_db.to_reader().db_height().await?;
        // Anchor floor: the non-finalised state must never start more than `OPERATIONAL_NFS_DEPTH`
        // blocks below the chain tip, even when the finalised DB tip lags far behind during
        // background catch-up. Without this floor a freshly-initialised (or genesis-fallback)
        // snapshot would try to bridge the entire gap from the finalised tip up to the chain tip one
        // block at a time — millions of sequential validator fetches that never converge (#1261).
        // When the floor sits above the finalised tip the anchor block isn't in the persistent DB;
        // `resolve_anchor_block` serves it via the passthrough or builds it from the validator.
        let anchor_height = Height(
            local_finalized_tip
                .map(|height| height.0)
                .unwrap_or(0)
                .max(u32::from(chain_height).saturating_sub(OPERATIONAL_NFS_DEPTH)),
        );
        if initial_state.best_tip.height.0 < anchor_height.0 {
            let anchor_block = Self::resolve_anchor_block(
                &self.source,
                &finalized_db.to_reader(),
                &self.network,
                anchor_height,
            )
            .await?;
            self.current.swap(Arc::new(
                NonfinalizedBlockCacheSnapshot::from_initial_block(anchor_block),
            ));
            initial_state = self.get_snapshot()
        }
        let mut working_snapshot = initial_state.as_ref().clone();

        // currently this only gets main-chain blocks
        // once readstateservice supports serving sidechain data, this
        // must be rewritten to match
        //
        // see https://github.com/ZcashFoundation/zebra/issues/9541

        while let Some(block) = self
            .source
            .get_block(HashOrHeight::Height(zebra_chain::block::Height(
                u32::from(working_snapshot.best_tip.height) + 1,
            )))
            .await
            .map_err(|e| {
                // TODO: Check error. Determine what kind of error to return, this may be recoverable
                SyncError::ValidatorConnectionError(NodeConnectionError::UnrecoverableError(
                    Box::new(e),
                ))
            })?
        {
            // Bail before applying any block that lies above the iter's
            // committed `chain_height`. The speculative `get_block` above
            // can return a block that wasn't yet on the source when the
            // worker committed (the mid-iter source-advance race in
            // #1126); applying it would silently widen this iter's
            // publish past its iter-start `fs.sync_to_height` floor.
            if u32::from(working_snapshot.best_tip.height) + 1 > u32::from(chain_height) {
                break;
            }
            let parent_hash = BlockHash::from(block.header.previous_block_hash);
            if parent_hash == working_snapshot.best_tip.hash {
                // Normal chain progression
                let prev_block = working_snapshot
                    .blocks
                    .get(&working_snapshot.best_tip.hash)
                    .ok_or_else(|| {
                        SyncError::ReorgFailure(format!(
                            "found blocks {:?}, expected block {:?}",
                            working_snapshot
                                .blocks
                                .values()
                                .map(|block| (block.context.index.hash, block.context.index.height))
                                .collect::<Vec<_>>(),
                            working_snapshot.best_tip
                        ))
                    })?;
                let chainblock = self.block_to_chainblock(prev_block, &block).await?;
                info!(
                    height = (working_snapshot.best_tip.height + 1).0,
                    hash = %chainblock.context.index.hash,
                    "Syncing block"
                );
                working_snapshot.add_block_new_chaintip(chainblock);
            } else {
                self.handle_reorg(&mut working_snapshot, block.as_ref(), 0)
                    .await?;
                // There's been a reorg. The fresh block is the new chaintip
                // we need to work backwards from it and update heights_to_hashes
                // with it and all its parents.
            }
            if initial_state.best_tip.height + OPERATIONAL_NFS_DEPTH
                < working_snapshot.best_tip.height
            {
                self.update(finalized_db.clone(), initial_state, working_snapshot)
                    .await?;
                initial_state = self.current.load_full();
                working_snapshot = initial_state.as_ref().clone();
            }
        }
        self.check_for_nonhigher_reorgs(&mut working_snapshot, None)
            .await?;
        // Handle non-finalized change listener
        self.handle_nfs_change_listener(&mut working_snapshot)
            .await?;

        self.update(finalized_db.clone(), initial_state, working_snapshot)
            .await?;

        Ok(())
    }

    /// Handle a blockchain reorg by finding the common ancestor
    async fn handle_reorg(
        &self,
        working_snapshot: &mut NonfinalizedBlockCacheSnapshot,
        block: &impl Block,
        recursion_count: u8,
    ) -> Result<IndexedBlock, SyncError> {
        // We should never recurse back more than the non-finalised window, assuming a complete
        // reorg of the entire nonfinalized state. `MAX_NFS_DEPTH` adds a small safety margin.
        if u32::from(recursion_count) > MAX_NFS_DEPTH {
            return Err(SyncError::ReorgFailure(
                "reorg handling recursed beyond reason".to_string(),
            ));
        }
        let prev_block = match working_snapshot
            .get_block_by_hash_bytes_in_serialized_order(block.prev_hash_bytes_serialized_order())
            .cloned()
        {
            Some(prev_block) => {
                if !working_snapshot
                    .heights_to_hashes
                    .values()
                    .any(|hash| hash == prev_block.hash())
                {
                    Box::pin(self.handle_reorg(working_snapshot, &prev_block, recursion_count + 1))
                        .await?
                } else {
                    prev_block
                }
            }
            None => {
                let prev_block = self
                    .source
                    .get_block(HashOrHeight::Hash(
                        zebra_chain::block::Hash::from_bytes_in_serialized_order(
                            block.prev_hash_bytes_serialized_order(),
                        ),
                    ))
                    .await
                    .map_err(|e| {
                        SyncError::ValidatorConnectionError(
                            NodeConnectionError::UnrecoverableError(Box::new(e)),
                        )
                    })?
                    .ok_or(SyncError::ValidatorConnectionError(
                        NodeConnectionError::UnrecoverableError(Box::new(MissingBlockError(
                            "zebrad missing block in best chain".to_string(),
                        ))),
                    ))?;
                Box::pin(self.handle_reorg(working_snapshot, &*prev_block, recursion_count + 1))
                    .await?
            }
        };
        let indexed_block = block.to_indexed_block(&prev_block, self).await?;
        working_snapshot.add_block_new_chaintip(indexed_block.clone());
        Ok(indexed_block)
    }

    async fn check_for_nonhigher_reorgs(
        &self,
        working_snapshot: &mut NonfinalizedBlockCacheSnapshot,
        // Callers should provide None. Used for self-recursion case only
        height_to_recurse_to: Option<Height>,
    ) -> Result<(), SyncError> {
        if height_to_recurse_to
            .is_some_and(|height| height + MAX_NFS_DEPTH < working_snapshot.best_tip.height)
        {
            return Err(SyncError::ReorgFailure(
                "reorg detection recursed beyond reason".to_string(),
            ));
        }
        let target_height = height_to_recurse_to.unwrap_or(working_snapshot.best_tip.height);
        match self
            .source
            .get_block(HashOrHeight::Height(zebra_chain::block::Height(u32::from(
                target_height,
            ))))
            .await
            .map_err(|e| {
                // TODO: Check error. Determine what kind of error to return, this may be recoverable
                SyncError::ValidatorConnectionError(NodeConnectionError::UnrecoverableError(
                    Box::new(e),
                ))
            })? {
            Some(block) => {
                if block.hash() != working_snapshot.best_tip.hash {
                    self.handle_reorg(working_snapshot, block.as_ref(), 0)
                        .await?;
                }
                Ok(())
            }
            None => {
                Box::pin(self.check_for_nonhigher_reorgs(working_snapshot, Some(target_height - 1)))
                    .await
            }
        }
    }

    /// Handle non-finalized change listener events
    async fn handle_nfs_change_listener(
        &self,
        working_snapshot: &mut NonfinalizedBlockCacheSnapshot,
    ) -> Result<(), SyncError> {
        let Some(ref listener) = self.nfs_change_listener else {
            return Ok(());
        };

        let Some(mut listener) = listener.try_lock() else {
            warn!("Error fetching non-finalized change listener");
            return Err(SyncError::CompetingSyncProcess);
        };

        loop {
            match listener.try_recv() {
                Ok((hash, block)) => {
                    if !self
                        .current
                        .load()
                        .blocks
                        .contains_key(&types::BlockHash(hash.0))
                    {
                        // Best-effort: a skipped side block (`Ok(None)`) is fine, it just isn't
                        // cached; only a hard error fails the sync.
                        self.add_nonbest_block(working_snapshot, &*block, 0).await?;
                    }
                }
                Err(mpsc::error::TryRecvError::Empty) => break,
                Err(e @ mpsc::error::TryRecvError::Disconnected) => {
                    return Err(SyncError::ValidatorConnectionError(
                        NodeConnectionError::UnrecoverableError(Box::new(e)),
                    ))
                }
            }
        }
        Ok(())
    }

    /// Add all blocks from the staging area, and save a new cache snapshot, trimming block below the finalised tip.
    pub(super) async fn update(
        &self,
        finalized_db: Arc<FinalisedState<Source>>,
        initial_state: Arc<NonfinalizedBlockCacheSnapshot>,
        mut new_snapshot: NonfinalizedBlockCacheSnapshot,
    ) -> Result<(), UpdateError> {
        let finalized_height = finalized_db
            .to_reader()
            .db_height()
            .await
            .map_err(|_e| UpdateError::FinalizedStateCorruption)?
            .unwrap_or(Height(0));

        // Trim below the finalised height, but never retain more than `MAX_NFS_DEPTH` blocks below
        // the tip even when `db_height` under-reports (background sync) or is `0` (ephemeral mode).
        // This bounds NFS memory to a fixed window; the `max` keeps the normal finalised-height
        // floor in healthy operation, where it sits above the tip-relative cap.
        let tip_height = new_snapshot.best_tip.height.0;
        let trim_height = Height(
            finalized_height
                .0
                .max(tip_height.saturating_sub(MAX_NFS_DEPTH)),
        );

        new_snapshot.remove_finalized_blocks(trim_height);
        let best_block = &new_snapshot
            .blocks
            .values()
            .max_by_key(|block| block.chainwork())
            .cloned()
            .expect("empty snapshot impossible");
        self.handle_reorg(&mut new_snapshot, best_block, 0)
            .await
            .map_err(|_e| UpdateError::DatabaseHole)?;

        // Need to get best hash at some point in this process
        let stored = self
            .current
            .compare_and_swap(&initial_state, Arc::new(new_snapshot));

        if Arc::ptr_eq(&stored, &initial_state) {
            let stale_best_tip = initial_state.best_tip;
            let new_best_tip = stored.best_tip;

            // Log chain tip change
            if new_best_tip != stale_best_tip {
                if new_best_tip.height > stale_best_tip.height {
                    info!(
                        old_height = stale_best_tip.height.0,
                        new_height = new_best_tip.height.0,
                        old_hash = %stale_best_tip.hash,
                        new_hash = %new_best_tip.hash,
                        "Non-finalized tip advanced"
                    );
                } else if new_best_tip.height == stale_best_tip.height
                    && new_best_tip.hash != stale_best_tip.hash
                {
                    info!(
                        height = new_best_tip.height.0,
                        old_hash = %stale_best_tip.hash,
                        new_hash = %new_best_tip.hash,
                        "Non-finalized tip reorg"
                    );
                } else if new_best_tip.height < stale_best_tip.height {
                    info!(
                        old_height = stale_best_tip.height.0,
                        new_height = new_best_tip.height.0,
                        old_hash = %stale_best_tip.hash,
                        new_hash = %new_best_tip.hash,
                        "Non-finalized tip rollback"
                    );
                }

                #[cfg(feature = "prometheus")]
                {
                    if new_best_tip.height == stale_best_tip.height
                        && new_best_tip.hash != stale_best_tip.hash
                    {
                        metrics::counter!(SYNC_REORG_TOTAL).increment(1);
                        metrics::histogram!(SYNC_REORG_DEPTH).record(0.0);
                    } else if new_best_tip.height < stale_best_tip.height {
                        metrics::counter!(SYNC_REORG_TOTAL).increment(1);
                        metrics::histogram!(SYNC_REORG_DEPTH)
                            .record((stale_best_tip.height.0 - new_best_tip.height.0) as f64);
                    }
                }
            }
            Ok(())
        } else {
            Err(UpdateError::StaleSnapshot)
        }
    }

    /// Get a snapshot of the block cache
    pub(super) fn get_snapshot(&self) -> Arc<NonfinalizedBlockCacheSnapshot> {
        self.current.load_full()
    }

    async fn block_to_chainblock(
        &self,
        prev_block: &IndexedBlock,
        block: &zebra_chain::block::Block,
    ) -> Result<IndexedBlock, SyncError> {
        let tree_roots = self
            .get_tree_roots_from_source(block.hash().into())
            .await
            .map_err(|e| {
                SyncError::ValidatorConnectionError(NodeConnectionError::UnrecoverableError(
                    Box::new(InvalidData(format!("{}", e))),
                ))
            })?;

        Self::create_indexed_block_with_optional_roots(
            block,
            &tree_roots,
            Some(*prev_block.chainwork()),
            self.network.clone(),
        )
        .map_err(|e| {
            SyncError::ValidatorConnectionError(NodeConnectionError::UnrecoverableError(Box::new(
                InvalidData(e),
            )))
        })
    }

    /// Get commitment tree roots from the blockchain source
    async fn get_tree_roots_from_source(
        &self,
        block_hash: BlockHash,
    ) -> Result<TreeRootData, super::source::BlockchainSourceError> {
        let (sapling_root_and_len, orchard_root_and_len, ironwood_root_and_len) =
            self.source.get_commitment_tree_roots(block_hash).await?;

        Ok(TreeRootData {
            sapling: sapling_root_and_len,
            orchard: orchard_root_and_len,
            ironwood: ironwood_root_and_len,
        })
    }

    /// Create IndexedBlock with optional tree roots (for genesis/sync cases)
    ///
    /// TODO: Issue #604 - This uses `unwrap_or_default()` uniformly for both Sapling and Orchard,
    /// but they have different activation heights. This masks potential bugs and prevents proper
    /// validation based on network upgrade activation.
    fn create_indexed_block_with_optional_roots(
        block: &zebra_chain::block::Block,
        tree_roots: &TreeRootData,
        parent_chainwork: Option<ChainWork>,
        network: Network,
    ) -> Result<IndexedBlock, String> {
        let (sapling_root, sapling_size, orchard_root, orchard_size, ironwood) =
            tree_roots.clone().extract_with_defaults();

        let metadata = BlockMetadata {
            sapling_root,
            sapling_size: sapling_size as u32,
            orchard_root,
            orchard_size: orchard_size as u32,
            ironwood: ironwood.map(|(root, size)| (root, size as u32)),
            parent_chainwork,
            network,
        };

        let block_with_metadata = BlockWithMetadata::new(block, metadata);
        IndexedBlock::try_from(block_with_metadata)
    }

    /// Cache a non-best (side-chain) block, recursively resolving any ancestors not already in the
    /// working snapshot.
    ///
    /// Returns `Ok(None)` when the block cannot be placed within the non-finalised window: the walk
    /// back to a known ancestor exceeded [`MAX_NFS_DEPTH`], so the side chain is rooted in finalised
    /// history. Skipping it is safe and intentional — zaino does not guarantee knowledge of all
    /// sidechain data (see `ChainIndexReader::find_fork_point`). Without this bound the walk would
    /// follow `source.get_block` down into finalised history (on the state backend `get_block`
    /// serves any block by hash) and overflow the worker stack.
    async fn add_nonbest_block(
        &self,
        working_snapshot: &mut NonfinalizedBlockCacheSnapshot,
        block: &impl Block,
        recursion_count: u8,
    ) -> Result<Option<IndexedBlock>, SyncError> {
        if u32::from(recursion_count) > MAX_NFS_DEPTH {
            warn!(
                depth = recursion_count,
                "non-best block ancestry walk exceeded the non-finalised window; \
                 skipping side chain rooted in finalised history"
            );
            return Ok(None);
        }
        let prev_block = match working_snapshot
            .get_block_by_hash_bytes_in_serialized_order(block.prev_hash_bytes_serialized_order())
            .cloned()
        {
            Some(block) => block,
            None => {
                let prev_block = self
                    .source
                    .get_block(HashOrHeight::Hash(
                        zebra_chain::block::Hash::from_bytes_in_serialized_order(
                            block.prev_hash_bytes_serialized_order(),
                        ),
                    ))
                    .await
                    .map_err(|e| {
                        SyncError::ValidatorConnectionError(
                            NodeConnectionError::UnrecoverableError(Box::new(e)),
                        )
                    })?
                    .ok_or(SyncError::ValidatorConnectionError(
                        NodeConnectionError::UnrecoverableError(Box::new(MissingBlockError(
                            "zebrad missing block".to_string(),
                        ))),
                    ))?;
                match Box::pin(self.add_nonbest_block(
                    working_snapshot,
                    &*prev_block,
                    recursion_count + 1,
                ))
                .await?
                {
                    Some(prev_block) => prev_block,
                    // The parent could not be resolved within the window, so this block can't be
                    // placed either. Skip it (best-effort), matching the ancestor's decision.
                    None => return Ok(None),
                }
            }
        };
        let indexed_block = block.to_indexed_block(&prev_block, self).await?;
        working_snapshot
            .blocks
            .insert(*indexed_block.hash(), indexed_block.clone());
        Ok(Some(indexed_block))
    }
}

/// Errors that occur during a snapshot update
pub enum UpdateError {
    /// The block reciever disconnected. This should only happen during shutdown.
    ReceiverDisconnected,
    /// The snapshot was already updated by a different process, between when this update started
    /// and when it completed.
    StaleSnapshot,

    /// Something has gone unrecoverably wrong in the finalized
    /// state. A full rebuild is likely needed
    FinalizedStateCorruption,

    /// A block in the snapshot is missing
    DatabaseHole,

    /// Failed to connect to the backing validator
    ValidatorConnectionError(Box<dyn std::error::Error>),
}

trait Block {
    fn hash_bytes_serialized_order(&self) -> [u8; 32];
    fn prev_hash_bytes_serialized_order(&self) -> [u8; 32];
    async fn to_indexed_block<Source: BlockchainSource>(
        &self,
        prev_block: &IndexedBlock,
        nfs: &NonFinalizedState<Source>,
    ) -> Result<IndexedBlock, SyncError>;
}

impl Block for IndexedBlock {
    fn hash_bytes_serialized_order(&self) -> [u8; 32] {
        self.hash().0
    }

    fn prev_hash_bytes_serialized_order(&self) -> [u8; 32] {
        self.context.parent_hash.0
    }

    async fn to_indexed_block<Source: BlockchainSource>(
        &self,
        _prev_block: &IndexedBlock,
        _nfs: &NonFinalizedState<Source>,
    ) -> Result<IndexedBlock, SyncError> {
        Ok(self.clone())
    }
}
impl Block for zebra_chain::block::Block {
    fn hash_bytes_serialized_order(&self) -> [u8; 32] {
        self.hash().bytes_in_serialized_order()
    }

    fn prev_hash_bytes_serialized_order(&self) -> [u8; 32] {
        self.header.previous_block_hash.bytes_in_serialized_order()
    }

    async fn to_indexed_block<Source: BlockchainSource>(
        &self,
        prev_block: &IndexedBlock,
        nfs: &NonFinalizedState<Source>,
    ) -> Result<IndexedBlock, SyncError> {
        nfs.block_to_chainblock(prev_block, self).await
    }
}
