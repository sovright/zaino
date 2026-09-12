//! Deterministic live-subscriber fixture exported only for cross-crate tests.

use std::{fmt, time::Duration};

use tempfile::TempDir;
use zaino_common::{network::ActivationHeights, DatabaseConfig, StorageConfig};

use super::{
    finalised_state::capability::CapabilityRequest,
    finalized_height_floor,
    shadow_vectors::{
        build_active_mockchain_source, load_test_vectors, try_indexed_block_chain,
        TestVectorBlockData,
    },
    source::{mockchain_source::MockchainSource, BlockchainSource},
    NodeBackedChainIndex, NodeBackedChainIndexSubscriber,
};
use crate::shadow_parity::{
    observed_standard_cases, OrdinaryUtxoShadowCase, OrdinaryUtxoShadowError,
};
use crate::{ChainIndexConfig, IndexedBlock};

// Height 100 keeps the checked-in starting window within the production
// 256-slot recent-snapshot budget. With `fast-test-seam` (or in-crate tests),
// the next block also advances the finalized boundary from genesis to height
// one. Cross-crate tests must enable that feature to exercise seam movement.
const INITIAL_ACTIVE_HEIGHT: u32 = 100;
const READY_BUDGET: Duration = Duration::from_secs(10);
const READY_POLL_INTERVAL: Duration = Duration::from_millis(25);

/// A checked-in chain driven through the real chain-index subscriber lifecycle.
pub struct CanonicalProjectionTestFixture {
    indexer: NodeBackedChainIndex<MockchainSource>,
    subscriber: NodeBackedChainIndexSubscriber<MockchainSource>,
    source: MockchainSource,
    indexed_blocks: Vec<IndexedBlock>,
    vector_blocks: Vec<TestVectorBlockData>,
    _database_dir: TempDir,
}

/// Failure to construct, advance, or cleanly stop the live test fixture.
#[derive(Debug)]
pub struct CanonicalProjectionTestFixtureError(String);

impl fmt::Display for CanonicalProjectionTestFixtureError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for CanonicalProjectionTestFixtureError {}

impl CanonicalProjectionTestFixture {
    /// Starts an actual persistent chain index over the checked-in regtest chain.
    pub async fn start() -> Result<Self, CanonicalProjectionTestFixtureError> {
        Self::start_at_height(INITIAL_ACTIVE_HEIGHT).await
    }

    /// Starts the fixture at a chosen checked-in height for bounded capacity tests.
    pub async fn start_at_height(
        active_height: u32,
    ) -> Result<Self, CanonicalProjectionTestFixtureError> {
        let vectors = load_test_vectors().map_err(|error| {
            CanonicalProjectionTestFixtureError(format!("test vectors could not load: {error}"))
        })?;
        let indexed_blocks = try_indexed_block_chain(&vectors.blocks)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| {
                CanonicalProjectionTestFixtureError(format!(
                    "test vectors could not be indexed: {error}"
                ))
            })?;
        if active_height as usize >= vectors.blocks.len() {
            return Err(CanonicalProjectionTestFixtureError(format!(
                "fixture active height {active_height} exceeds checked-in chain"
            )));
        }
        let source = build_active_mockchain_source(active_height, vectors.blocks.clone());
        let database_dir = tempfile::tempdir().map_err(|error| {
            CanonicalProjectionTestFixtureError(format!(
                "fixture database directory could not be created: {error}"
            ))
        })?;
        let config = ChainIndexConfig {
            storage: StorageConfig {
                database: DatabaseConfig {
                    path: database_dir.path().to_path_buf(),
                    ..Default::default()
                },
                ..Default::default()
            },
            ephemeral: false,
            db_version: 1,
            network: ActivationHeights::default().to_regtest_network(),
        };
        let indexer = NodeBackedChainIndex::new(source.clone(), config)
            .await
            .map_err(|error| {
                CanonicalProjectionTestFixtureError(format!(
                    "fixture chain index could not start: {error}"
                ))
            })?;
        let subscriber = indexer.subscriber();
        let fixture = Self {
            indexer,
            subscriber,
            source,
            indexed_blocks,
            vector_blocks: vectors.blocks,
            _database_dir: database_dir,
        };
        if let Err(error) = fixture.await_active_tip().await {
            let _ = fixture.indexer.shutdown().await;
            return Err(error);
        }
        Ok(fixture)
    }

    /// Returns the actual subscriber owned by the running chain index.
    pub fn subscriber(&self) -> &NodeBackedChainIndexSubscriber<MockchainSource> {
        &self.subscriber
    }

    /// Returns the canonical finalized prefix for the source's current public tip.
    pub fn finalized_blocks(&self) -> &[IndexedBlock] {
        let finalized_len = finalized_height_floor(self.source.active_height()).0 as usize + 1;
        &self.indexed_blocks[..finalized_len]
    }

    /// Queries the ordinary source for standard-address UTXOs at the fixture's active tip.
    pub async fn ordinary_utxo_cases(
        &self,
    ) -> Result<Vec<OrdinaryUtxoShadowCase>, OrdinaryUtxoShadowError> {
        let active_len = self.source.active_height() as usize + 1;
        let blocks = self.vector_blocks.get(..active_len).ok_or(
            OrdinaryUtxoShadowError::MissingCheckpoint {
                height: self.source.active_height(),
            },
        )?;
        // Reuse the independent ordinary-source oracle used by shadow parity;
        // it applies the source's own spent-output filtering.
        observed_standard_cases(blocks, &self.source).await
    }

    /// Advances the public source and waits until the real subscriber publishes that tip.
    pub async fn mine_blocks(
        &self,
        blocks: u32,
    ) -> Result<(), CanonicalProjectionTestFixtureError> {
        self.source.mine_blocks(blocks);
        self.await_active_tip().await
    }

    async fn await_active_tip(&self) -> Result<(), CanonicalProjectionTestFixtureError> {
        let expected_tip = self.source.active_height();
        let expected_hash = self
            .source
            .get_best_block_hash()
            .await
            .map_err(|error| {
                CanonicalProjectionTestFixtureError(format!(
                    "fixture source tip hash was unavailable: {error}"
                ))
            })?
            .ok_or_else(|| {
                CanonicalProjectionTestFixtureError(
                    "fixture source did not publish a tip hash".to_string(),
                )
            })?;
        let expected_finalized = self
            .finalized_blocks()
            .last()
            .map(|block| block.context.index)
            .ok_or_else(|| {
                CanonicalProjectionTestFixtureError(
                    "fixture source did not have a finalized checkpoint".to_string(),
                )
            })?;
        let ready = || {
            self.subscriber
                .current_canonical_transparent_projection_boundary()
                .is_ok_and(|boundary| {
                    boundary.tip().height.0 == expected_tip
                        && boundary.tip().hash.0 == expected_hash.0
                        && boundary.finalized() == expected_finalized
                })
        };
        tokio::time::timeout(READY_BUDGET, async {
            loop {
                if ready() {
                    break;
                }
                tokio::time::sleep(READY_POLL_INTERVAL).await;
            }

            self.indexer.finalized_db.wait_until_synced().await;
            if self.indexer.finalized_db.status() == crate::StatusType::CriticalError {
                return Err(CanonicalProjectionTestFixtureError(
                    "fixture finalized database entered a critical state".to_string(),
                ));
            }
            loop {
                if ready() {
                    self.indexer
                        .finalized_db
                        .backend_for_cap(CapabilityRequest::TransparentHistExt)
                        .map_err(|error| {
                            CanonicalProjectionTestFixtureError(format!(
                                "fixture finalized transparent history was unavailable: {error}"
                            ))
                        })?;
                    return Ok(());
                }
                tokio::time::sleep(READY_POLL_INTERVAL).await;
            }
        })
        .await
        .map_err(|_| {
            CanonicalProjectionTestFixtureError(format!(
                "fixture chain index did not publish tip {expected_tip} within {READY_BUDGET:?}"
            ))
        })?
    }

    /// Stops the index before its temporary database directory is removed.
    pub async fn shutdown(self) -> Result<(), CanonicalProjectionTestFixtureError> {
        self.indexer.shutdown().await.map_err(|error| {
            CanonicalProjectionTestFixtureError(format!(
                "fixture chain index did not shut down cleanly: {error}"
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// multi_thread required: the persistent-v1 fixture transitively uses `block_in_place`.
    #[tokio::test(flavor = "multi_thread")]
    async fn readiness_waits_for_persistent_background_work(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let fixture = CanonicalProjectionTestFixture::start().await?;
        let result = async {
            fixture
                .subscriber()
                .current_canonical_transparent_projection_boundary()?;
            let operation = fixture.indexer.finalized_db.hold_background_op_for_test();
            let pending =
                tokio::time::timeout(Duration::from_millis(150), fixture.await_active_tip()).await;
            drop(operation);
            if pending.is_ok() {
                return Err(
                    "synchronous boundary exposed unfinished persistent background work".into(),
                );
            }
            fixture.await_active_tip().await?;
            fixture
                .subscriber()
                .capture_canonical_transparent_projection_input()
                .await?;
            Ok::<_, Box<dyn std::error::Error>>(())
        }
        .await;
        let shutdown = fixture.shutdown().await;
        result?;
        shutdown?;
        Ok(())
    }

    /// multi_thread required: the persistent-v1 fixture transitively uses `block_in_place`.
    #[tokio::test(flavor = "multi_thread")]
    async fn fixture_publishes_a_real_forward_update() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = CanonicalProjectionTestFixture::start().await?;
        let result = async {
            let initial = fixture
                .subscriber()
                .capture_canonical_transparent_projection_input()
                .await?;
            assert!(!initial.recent().blocks().is_empty());
            let initial_tip = initial.recent().tip();
            let initial_cases = fixture.ordinary_utxo_cases().await?;
            let stable_case = initial_cases
                .iter()
                .filter(|case| !case.ordinary_utxos().is_empty())
                .min_by_key(|case| case.ordinary_utxos().len())
                .ok_or("fixture has no present-address UTXO case at height 100")?;
            let stable_address = *stable_case.address_script();

            fixture.mine_blocks(1).await?;
            let advanced = fixture
                .subscriber()
                .capture_canonical_transparent_projection_input()
                .await?;
            assert!(!advanced.recent().blocks().is_empty());
            assert_ne!(advanced.recent().tip(), initial_tip);
            let advanced_cases = fixture.ordinary_utxo_cases().await?;
            advanced_cases
                .iter()
                .find(|case| case.address_script() == &stable_address)
                .ok_or("height-100 ordinary UTXO address disappeared at height 101")?;
            Ok::<_, Box<dyn std::error::Error>>(())
        }
        .await;
        let shutdown = fixture.shutdown().await;
        result?;
        shutdown?;
        Ok(())
    }
}
