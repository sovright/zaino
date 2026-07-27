//! Public canonical-chain provenance shared by offline `IndexedBlock` consumers.

use std::fmt;

use zaino_state::{BlockHash, IndexedBlock};

/// Public Zcash network bound into an offline chain checkpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CanonicalNetwork {
    Mainnet,
    Testnet,
    Regtest,
}

impl CanonicalNetwork {
    pub(super) fn genesis_hash(self) -> BlockHash {
        let display_order = match self {
            Self::Mainnet => [
                0x00, 0x04, 0x0f, 0xe8, 0xec, 0x84, 0x71, 0x91, 0x1b, 0xaa, 0x1d, 0xb1, 0x26, 0x6e,
                0xa1, 0x5d, 0xd0, 0x6b, 0x4a, 0x8a, 0x5c, 0x45, 0x38, 0x83, 0xc0, 0x00, 0xb0, 0x31,
                0x97, 0x3d, 0xce, 0x08,
            ],
            Self::Testnet => [
                0x05, 0xa6, 0x0a, 0x92, 0xd9, 0x9d, 0x85, 0x99, 0x7c, 0xce, 0x3b, 0x87, 0x61, 0x6c,
                0x08, 0x9f, 0x61, 0x24, 0xd7, 0x34, 0x2a, 0xf3, 0x71, 0x06, 0xed, 0xc7, 0x61, 0x26,
                0x33, 0x4a, 0x2c, 0x38,
            ],
            Self::Regtest => [
                0x02, 0x9f, 0x11, 0xd8, 0x0e, 0xf9, 0x76, 0x56, 0x02, 0x23, 0x5e, 0x1b, 0xc9, 0x72,
                0x7e, 0x3e, 0xb6, 0xba, 0x20, 0x83, 0x93, 0x19, 0xf7, 0x61, 0xfe, 0xe9, 0x20, 0xd6,
                0x34, 0x01, 0xe3, 0x27,
            ],
        };
        BlockHash::from_bytes_in_display_order(&display_order)
    }
}

impl fmt::Display for CanonicalNetwork {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Mainnet => f.write_str("mainnet"),
            Self::Testnet => f.write_str("testnet"),
            Self::Regtest => f.write_str("regtest"),
        }
    }
}

/// Public canonical block identity committed by an offline consumer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct PublicChainCheckpoint {
    network: CanonicalNetwork,
    height: u32,
    block_hash: BlockHash,
}

impl PublicChainCheckpoint {
    pub(super) const fn new(network: CanonicalNetwork, height: u32, block_hash: BlockHash) -> Self {
        Self {
            network,
            height,
            block_hash,
        }
    }

    pub(super) const fn network(&self) -> CanonicalNetwork {
        self.network
    }

    pub(super) const fn height(&self) -> u32 {
        self.height
    }

    pub(super) const fn block_hash(&self) -> &BlockHash {
        &self.block_hash
    }
}

/// Validates a genesis-forward `IndexedBlock` sequence without mutating it.
#[derive(Clone, Copy)]
pub(super) struct CanonicalBlockCursor {
    network: CanonicalNetwork,
    committed: Option<PublicChainCheckpoint>,
}

/// Opaque checkpoint candidate bound to the cursor state that validated it.
#[derive(Clone, Copy)]
pub(super) struct ValidatedBlockCheckpoint {
    checkpoint: PublicChainCheckpoint,
    expected_previous: Option<PublicChainCheckpoint>,
}

impl ValidatedBlockCheckpoint {
    pub(super) const fn checkpoint(&self) -> PublicChainCheckpoint {
        self.checkpoint
    }
}

impl CanonicalBlockCursor {
    pub(super) const fn new(network: CanonicalNetwork) -> Self {
        Self {
            network,
            committed: None,
        }
    }

    /// Validates the next block and returns a candidate checkpoint.
    ///
    /// The cursor advances only when the caller stages and later publishes the
    /// result of [`Self::stage_advance`], allowing block state to be committed
    /// before the public checkpoint cursor.
    pub(super) fn validate_next(
        &self,
        block: &IndexedBlock,
    ) -> Result<ValidatedBlockCheckpoint, CanonicalChainError> {
        let height = u32::from(block.height());
        let block_hash = *block.hash();
        let parent_hash = *block.context.parent_hash();
        match self.committed {
            None => {
                if height != 0 {
                    return Err(CanonicalChainError::MissingGenesis {
                        first_height: height,
                    });
                }
                if block_hash != self.network.genesis_hash() {
                    return Err(CanonicalChainError::GenesisHashMismatch);
                }
                if parent_hash != BlockHash([0; 32]) {
                    return Err(CanonicalChainError::GenesisParentMismatch);
                }
            }
            Some(previous) => {
                let expected = previous
                    .height
                    .checked_add(1)
                    .ok_or(CanonicalChainError::BlockHeightOverflow)?;
                if height != expected {
                    return Err(CanonicalChainError::NonContiguousHeight {
                        expected,
                        actual: height,
                    });
                }
                if parent_hash != previous.block_hash {
                    return Err(CanonicalChainError::ParentHashMismatch { height });
                }
            }
        }
        Ok(ValidatedBlockCheckpoint {
            checkpoint: PublicChainCheckpoint::new(self.network, height, block_hash),
            expected_previous: self.committed,
        })
    }

    pub(super) fn stage_advance(
        &self,
        candidate: ValidatedBlockCheckpoint,
    ) -> Result<(Self, PublicChainCheckpoint), CanonicalChainError> {
        if candidate.expected_previous != self.committed
            || candidate.checkpoint.network != self.network
        {
            return Err(CanonicalChainError::ValidatedCheckpointMismatch);
        }
        let mut advanced = *self;
        advanced.committed = Some(candidate.checkpoint);
        Ok((advanced, candidate.checkpoint))
    }

    pub(super) const fn checkpoint(&self) -> Option<PublicChainCheckpoint> {
        self.committed
    }
}

impl fmt::Debug for CanonicalBlockCursor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CanonicalBlockCursor")
            .field("network", &self.network)
            .field("committed", &self.committed)
            .finish()
    }
}

/// Public-chain provenance failure with no transaction or address identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CanonicalChainError {
    MissingGenesis { first_height: u32 },
    GenesisHashMismatch,
    GenesisParentMismatch,
    BlockHeightOverflow,
    NonContiguousHeight { expected: u32, actual: u32 },
    ParentHashMismatch { height: u32 },
    ValidatedCheckpointMismatch,
}

impl fmt::Display for CanonicalChainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingGenesis { first_height } => write!(
                f,
                "canonical sequence starts at height {first_height}; genesis height 0 is required"
            ),
            Self::GenesisHashMismatch => {
                f.write_str("canonical genesis hash does not match the configured network")
            }
            Self::GenesisParentMismatch => {
                f.write_str("canonical genesis block has a non-null parent hash")
            }
            Self::BlockHeightOverflow => {
                f.write_str("canonical block height cannot advance beyond u32::MAX")
            }
            Self::NonContiguousHeight { expected, actual } => write!(
                f,
                "canonical sequence expected public height {expected} but received {actual}"
            ),
            Self::ParentHashMismatch { height } => {
                write!(
                    f,
                    "canonical parent hash mismatch at public height {height}"
                )
            }
            Self::ValidatedCheckpointMismatch => {
                f.write_str("validated checkpoint does not match the current canonical cursor")
            }
        }
    }
}

impl std::error::Error for CanonicalChainError {}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::zaino_fixtures::{indexed_block, FixtureResult};

    #[test]
    fn validated_candidates_are_cursor_and_predecessor_bound() -> FixtureResult<()> {
        let regtest_genesis = indexed_block(
            0,
            CanonicalNetwork::Regtest.genesis_hash().0,
            [0; 32],
            Vec::new(),
        )?;
        let regtest = CanonicalBlockCursor::new(CanonicalNetwork::Regtest);
        let candidate = regtest.validate_next(&regtest_genesis)?;
        let (regtest, committed) = regtest.stage_advance(candidate)?;
        assert_eq!(committed.height(), 0);
        assert!(matches!(
            regtest.stage_advance(candidate),
            Err(CanonicalChainError::ValidatedCheckpointMismatch)
        ));

        let mainnet_genesis = indexed_block(
            0,
            CanonicalNetwork::Mainnet.genesis_hash().0,
            [0; 32],
            Vec::new(),
        )?;
        let mainnet = CanonicalBlockCursor::new(CanonicalNetwork::Mainnet);
        let mainnet_candidate = mainnet.validate_next(&mainnet_genesis)?;
        let empty_regtest = CanonicalBlockCursor::new(CanonicalNetwork::Regtest);
        assert!(matches!(
            empty_regtest.stage_advance(mainnet_candidate),
            Err(CanonicalChainError::ValidatedCheckpointMismatch)
        ));
        Ok(())
    }
}
