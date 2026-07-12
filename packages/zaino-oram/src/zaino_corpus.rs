use std::fmt;

use zaino_state::{
    extract_transparent_events, BlockHash, IndexedBlock, ScriptType, TransparentBlockEvent,
    TransparentEventError,
};

use crate::{
    corpus::{
        CorpusAccumulator, CorpusAddress, CorpusError, CorpusEvent, CorpusOutpoint, CorpusReport,
        CorpusScriptClass, GrowthAssumption,
    },
    sizing::SizingParameters,
};

/// Public chain identity required before aggregate scanning begins.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct CorpusChainIdentity {
    network: CorpusNetwork,
}

impl CorpusChainIdentity {
    pub(super) const fn new(network: CorpusNetwork) -> Self {
        Self { network }
    }
}

/// Public Zcash network label recorded in a corpus report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CorpusNetwork {
    Mainnet,
    Testnet,
    Regtest,
}

impl fmt::Display for CorpusNetwork {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Mainnet => f.write_str("mainnet"),
            Self::Testnet => f.write_str("testnet"),
            Self::Regtest => f.write_str("regtest"),
        }
    }
}

impl CorpusNetwork {
    fn genesis_hash(self) -> BlockHash {
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

/// Aggregate report paired with its public canonical-chain checkpoint.
pub(super) struct ZainoCorpusReport {
    network: CorpusNetwork,
    final_height: u32,
    final_hash: BlockHash,
    aggregate: CorpusReport,
}

impl fmt::Debug for ZainoCorpusReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ZainoCorpusReport { public_checkpoint: true, aggregates_only: true, .. }")
    }
}

impl fmt::Display for ZainoCorpusReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "network={}", self.network)?;
        writeln!(f, "final_height={}", self.final_height)?;
        writeln!(f, "final_hash={}", self.final_hash.to_rpc_hex())?;
        write!(f, "{}", self.aggregate)
    }
}

/// Validated growth and sizing inputs for a one-shot mainnet corpus scan.
///
/// Every value is supplied explicitly by the operator. This research API does
/// not guess privacy-profile or target-TDX constants.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct MainnetCorpusModel {
    growth: GrowthAssumption,
    sizing: SizingParameters,
}

impl MainnetCorpusModel {
    /// Validates the complete aggregate growth and logical-storage model.
    #[expect(
        clippy::too_many_arguments,
        reason = "the one-shot model validates every operator-selected capacity dimension together"
    )]
    pub fn new(
        growth_horizon_years: u16,
        annual_growth_bps: u64,
        events_per_page: u64,
        page_overhead_bytes: u64,
        directory_entry_bytes: u64,
        position_map_entry_bytes: u64,
        backend_expansion_bps: u64,
        tdx_memory_bytes: u64,
        required_headroom_bps: u64,
    ) -> Result<Self, MainnetCorpusError> {
        let growth = GrowthAssumption::new(growth_horizon_years, annual_growth_bps)
            .map_err(ZainoCorpusError::Aggregate)?;
        let sizing = SizingParameters::new(
            events_per_page,
            page_overhead_bytes,
            directory_entry_bytes,
            position_map_entry_bytes,
            backend_expansion_bps,
            tdx_memory_bytes,
            required_headroom_bps,
        )
        .map_err(CorpusError::Sizing)
        .map_err(ZainoCorpusError::Aggregate)?;
        Ok(Self { growth, sizing })
    }
}

impl fmt::Debug for MainnetCorpusModel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MainnetCorpusModel { aggregate_parameters: true, .. }")
    }
}

/// Incremental, genesis-forward mainnet scanner for the non-published corpus
/// runner.
///
/// The scanner does not retain blocks. It necessarily retains public-chain
/// address and outpoint identities while resolving spends, then consumes that
/// state into an identifier-free [`MainnetCorpusReport`].
pub struct MainnetCorpusScanner {
    inner: ZainoCorpusScanner,
}

impl MainnetCorpusScanner {
    /// Starts an empty scanner bound to the canonical mainnet genesis hash.
    pub fn new(model: MainnetCorpusModel) -> Self {
        Self {
            inner: ZainoCorpusScanner::new(
                CorpusChainIdentity::new(CorpusNetwork::Mainnet),
                model.growth,
                model.sizing,
            ),
        }
    }

    /// Applies one canonical indexed block without retaining the block.
    pub fn push(&mut self, block: &IndexedBlock) -> Result<(), MainnetCorpusError> {
        self.inner.push(block).map_err(Into::into)
    }

    /// Consumes all identifier-bearing scan state and returns aggregates only.
    pub fn finish(self) -> Result<MainnetCorpusReport, MainnetCorpusError> {
        self.inner
            .finish()
            .map(|inner| MainnetCorpusReport { inner })
            .map_err(Into::into)
    }
}

impl fmt::Debug for MainnetCorpusScanner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MainnetCorpusScanner { identifiers: [REDACTED], .. }")
    }
}

/// Identifier-free aggregate output bound to a public mainnet checkpoint.
pub struct MainnetCorpusReport {
    inner: ZainoCorpusReport,
}

impl fmt::Debug for MainnetCorpusReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MainnetCorpusReport { public_checkpoint: true, aggregates_only: true, .. }")
    }
}

impl fmt::Display for MainnetCorpusReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.inner.fmt(f)
    }
}

/// Redacted failure from mainnet model validation or corpus accumulation.
#[derive(Debug)]
pub struct MainnetCorpusError {
    inner: ZainoCorpusError,
}

impl From<ZainoCorpusError> for MainnetCorpusError {
    fn from(inner: ZainoCorpusError) -> Self {
        Self { inner }
    }
}

impl fmt::Display for MainnetCorpusError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.inner.fmt(f)
    }
}

impl std::error::Error for MainnetCorpusError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.inner)
    }
}

/// Scans canonical indexed blocks from genesis and emits only aggregate data.
///
/// The in-memory accumulator necessarily holds public-chain identifiers while
/// resolving spends. Its returned report owns no address, transaction, or
/// outpoint identity. A scan that starts after genesis fails on the first
/// unresolved previous outpoint unless a future complete seed API is used.
pub(super) fn scan_indexed_blocks<'a>(
    blocks: impl IntoIterator<Item = &'a IndexedBlock>,
    chain: CorpusChainIdentity,
    growth: GrowthAssumption,
    sizing: SizingParameters,
) -> Result<ZainoCorpusReport, ZainoCorpusError> {
    let mut scanner = ZainoCorpusScanner::new(chain, growth, sizing);
    for block in blocks {
        scanner.push(block)?;
    }
    scanner.finish()
}

/// Incremental adapter from canonical Zaino blocks to aggregate corpus state.
///
/// The adapter never retains an [`IndexedBlock`]. It retains only the previous
/// public checkpoint plus the identifier-bearing maps required to resolve
/// transparent spends. Those maps are consumed into an aggregate-only report
/// by [`Self::finish`].
struct ZainoCorpusScanner {
    chain: CorpusChainIdentity,
    growth: GrowthAssumption,
    sizing: SizingParameters,
    accumulator: Option<CorpusAccumulator>,
    previous: Option<(u32, BlockHash)>,
}

impl ZainoCorpusScanner {
    fn new(chain: CorpusChainIdentity, growth: GrowthAssumption, sizing: SizingParameters) -> Self {
        Self {
            chain,
            growth,
            sizing,
            accumulator: Some(CorpusAccumulator::from_genesis()),
            previous: None,
        }
    }

    /// Validates and applies one canonical block without retaining it.
    ///
    /// Extraction and provenance failures happen before aggregate mutation and
    /// may be retried with corrected input. Once aggregate mutation begins, any
    /// failure consumes the accumulator and permanently poisons the scanner so
    /// partially applied state cannot be reused.
    fn push(&mut self, block: &IndexedBlock) -> Result<(), ZainoCorpusError> {
        if self.accumulator.is_none() {
            return Err(ZainoCorpusError::ScannerPoisoned);
        }

        let height = u32::from(block.height());
        let hash = *block.hash();
        let parent_hash = *block.context.parent_hash();
        match self.previous {
            None => {
                if height != 0 {
                    return Err(ZainoCorpusError::MissingGenesis {
                        first_height: height,
                    });
                }
                if hash != self.chain.network.genesis_hash() {
                    return Err(ZainoCorpusError::GenesisHashMismatch);
                }
                if parent_hash != BlockHash([0; 32]) {
                    return Err(ZainoCorpusError::GenesisParentMismatch);
                }
            }
            Some((previous_height, previous_hash)) => {
                let expected_height = previous_height
                    .checked_add(1)
                    .ok_or(ZainoCorpusError::BlockHeightOverflow)?;
                if height != expected_height {
                    return Err(ZainoCorpusError::NonContiguousHeight {
                        expected: expected_height,
                        actual: height,
                    });
                }
                if parent_hash != previous_hash {
                    return Err(ZainoCorpusError::ParentHashMismatch { height });
                }
            }
        }
        let transaction_count = u64::try_from(block.transactions().len())
            .map_err(|_| ZainoCorpusError::TransactionCountOverflow { height })?;
        let events = extract_transparent_events(block).map_err(ZainoCorpusError::Extraction)?;

        let mut accumulator = self
            .accumulator
            .take()
            .ok_or(ZainoCorpusError::ScannerPoisoned)?;
        accumulator
            .record_block(transaction_count)
            .map_err(ZainoCorpusError::Aggregate)?;
        for event in events {
            apply_transparent_event(&mut accumulator, event)?;
        }

        self.accumulator = Some(accumulator);
        self.previous = Some((height, hash));
        Ok(())
    }

    fn finish(self) -> Result<ZainoCorpusReport, ZainoCorpusError> {
        let accumulator = self.accumulator.ok_or(ZainoCorpusError::ScannerPoisoned)?;
        let (final_height, final_hash) = self.previous.ok_or(ZainoCorpusError::EmptyChain)?;
        let aggregate = accumulator
            .finish(self.growth, self.sizing)
            .map_err(ZainoCorpusError::Aggregate)?;
        Ok(ZainoCorpusReport {
            network: self.chain.network,
            final_height,
            final_hash,
            aggregate,
        })
    }
}

fn apply_transparent_event(
    accumulator: &mut CorpusAccumulator,
    event: TransparentBlockEvent,
) -> Result<(), ZainoCorpusError> {
    let event = match event {
        TransparentBlockEvent::Created {
            outpoint,
            address,
            script_class,
            ..
        } => CorpusEvent::Created {
            outpoint: CorpusOutpoint::new(*outpoint.prev_txid(), outpoint.prev_index()),
            address: address.and_then(|address| {
                CorpusAddress::new(*address.hash(), map_script_class(script_class))
            }),
            script_class: map_script_class(script_class),
        },
        TransparentBlockEvent::Spent { previous, .. } => CorpusEvent::Spent {
            previous: CorpusOutpoint::new(*previous.prev_txid(), previous.prev_index()),
        },
    };
    accumulator
        .apply(event)
        .map_err(ZainoCorpusError::Aggregate)
}

const fn map_script_class(script_class: ScriptType) -> CorpusScriptClass {
    match script_class {
        ScriptType::P2PKH => CorpusScriptClass::PayToPublicKeyHash,
        ScriptType::P2SH => CorpusScriptClass::PayToScriptHash,
        ScriptType::NonStandard => CorpusScriptClass::NonStandard,
    }
}

/// Indexed-block extraction or aggregate scan failure with redacted identity.
#[derive(Debug)]
pub(super) enum ZainoCorpusError {
    EmptyChain,
    /// Aggregate mutation failed and the partial scanner state was discarded.
    ScannerPoisoned,
    MissingGenesis {
        first_height: u32,
    },
    GenesisHashMismatch,
    GenesisParentMismatch,
    BlockHeightOverflow,
    NonContiguousHeight {
        expected: u32,
        actual: u32,
    },
    ParentHashMismatch {
        height: u32,
    },
    /// One block contains more transactions than an aggregate `u64` can count.
    TransactionCountOverflow {
        /// Public block height containing the rejected count.
        height: u32,
    },
    /// Pure compact-event extraction rejected a fixed-domain value.
    Extraction(TransparentEventError),
    /// Aggregate accumulation or sizing failed.
    Aggregate(CorpusError),
}

impl fmt::Display for ZainoCorpusError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyChain => {
                f.write_str("corpus scan requires a nonempty genesis-forward chain")
            }
            Self::ScannerPoisoned => {
                f.write_str("corpus scanner cannot continue after an aggregate mutation failure")
            }
            Self::MissingGenesis { first_height } => write!(
                f,
                "corpus scan starts at height {first_height}; canonical genesis height 0 is required"
            ),
            Self::GenesisHashMismatch => {
                f.write_str("corpus scan genesis hash does not match the configured network")
            }
            Self::GenesisParentMismatch => {
                f.write_str("corpus scan genesis block has a non-null parent hash")
            }
            Self::BlockHeightOverflow => {
                f.write_str("corpus scan block height cannot advance beyond u32::MAX")
            }
            Self::NonContiguousHeight { expected, actual } => write!(
                f,
                "corpus scan expected public height {expected} but received {actual}"
            ),
            Self::ParentHashMismatch { height } => write!(
                f,
                "corpus scan parent hash mismatch at public height {height}"
            ),
            Self::TransactionCountOverflow { height } => write!(
                f,
                "transaction count at public height {height} exceeds u64 capacity"
            ),
            Self::Extraction(error) => write!(f, "transparent event extraction failed: {error}"),
            Self::Aggregate(error) => write!(f, "aggregate corpus scan failed: {error}"),
        }
    }
}

impl std::error::Error for ZainoCorpusError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Extraction(error) => Some(error),
            Self::Aggregate(error) => Some(error),
            Self::EmptyChain
            | Self::ScannerPoisoned
            | Self::MissingGenesis { .. }
            | Self::GenesisHashMismatch
            | Self::GenesisParentMismatch
            | Self::BlockHeightOverflow
            | Self::NonContiguousHeight { .. }
            | Self::ParentHashMismatch { .. }
            | Self::TransactionCountOverflow { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{collections::BTreeMap, num::NonZeroU128};
    use zaino_state::{
        chain_index::types::EquihashSolution, AddrScript, BlockContext, BlockData, BlockHash,
        ChainWork, CommitmentTreeData, CommitmentTreeRoots, CommitmentTreeSizes, CompactDifficulty,
        CompactTxData, Height, OrchardCompactTx, Outpoint, SaplingCompactTx, TransactionHash,
        TransparentCompactTx, TxInCompact, TxLocation, TxOutCompact,
    };

    fn sizing() -> Result<SizingParameters, crate::sizing::SizingError> {
        SizingParameters::new(2, 16, 32, 4, 20_000, 1_000_000, 3_000)
    }

    fn transaction(
        index: u64,
        txid: [u8; 32],
        inputs: Vec<TxInCompact>,
        outputs: Vec<TxOutCompact>,
    ) -> CompactTxData {
        CompactTxData::new(
            index,
            TransactionHash(txid),
            TransparentCompactTx::new(inputs, outputs),
            SaplingCompactTx::new(None, Vec::new(), Vec::new()),
            OrchardCompactTx::empty(),
            OrchardCompactTx::empty(),
        )
    }

    fn output(
        value: u64,
        hash: [u8; 20],
        script_class: ScriptType,
    ) -> Result<TxOutCompact, Box<dyn std::error::Error>> {
        TxOutCompact::new(value, hash, script_class as u8)
            .ok_or_else(|| "known script class must construct a compact output".into())
    }

    fn indexed_block(
        height: u32,
        hash: [u8; 32],
        parent_hash: [u8; 32],
        transactions: Vec<CompactTxData>,
    ) -> Result<IndexedBlock, Box<dyn std::error::Error>> {
        let height_value = Height::try_from(height)?;
        let work_value = u128::from(height)
            .checked_add(1)
            .and_then(NonZeroU128::new)
            .ok_or("test chainwork must remain nonzero")?;
        let context = BlockContext::new(
            BlockHash(hash),
            BlockHash(parent_hash),
            ChainWork::new(work_value),
            height_value,
        );
        let data = BlockData::new(
            1,
            i64::from(height),
            [0; 32],
            [0; 32],
            CompactDifficulty::try_from_bits(0x2007_ffff)?,
            [0; 32],
            EquihashSolution::Regtest([0; 36]),
        );
        let commitment_tree_data = CommitmentTreeData::new(
            CommitmentTreeRoots::new([0; 32], [0; 32], None),
            CommitmentTreeSizes::new(0, 0, 0),
        );
        Ok(IndexedBlock::new(
            context,
            data,
            transactions,
            commitment_tree_data,
        ))
    }

    fn fixture_genesis() -> Result<IndexedBlock, Box<dyn std::error::Error>> {
        let created_txid = [0x11; 32];
        let created = transaction(
            0,
            created_txid,
            vec![TxInCompact::null_prevout()],
            vec![
                output(50, [0xa1; 20], ScriptType::P2PKH)?,
                output(75, [0xb2; 20], ScriptType::NonStandard)?,
            ],
        );
        let same_block_spend = transaction(
            1,
            [0x22; 32],
            vec![TxInCompact::new(created_txid, 0)],
            vec![output(40, [0xc3; 20], ScriptType::P2SH)?],
        );
        indexed_block(
            0,
            CorpusNetwork::Regtest.genesis_hash().0,
            [0; 32],
            vec![created, same_block_spend],
        )
    }

    fn fixture_second_block() -> Result<IndexedBlock, Box<dyn std::error::Error>> {
        let spend_and_create = transaction(
            0,
            [0x33; 32],
            vec![TxInCompact::new([0x22; 32], 0)],
            vec![output(30, [0xd4; 20], ScriptType::P2PKH)?],
        );
        indexed_block(
            1,
            [0x92; 32],
            CorpusNetwork::Regtest.genesis_hash().0,
            vec![spend_and_create],
        )
    }

    #[test]
    fn network_labels_bind_canonical_genesis_hashes() {
        assert_eq!(
            CorpusNetwork::Mainnet.genesis_hash().to_rpc_hex(),
            "00040fe8ec8471911baa1db1266ea15dd06b4a8a5c453883c000b031973dce08"
        );
        assert_eq!(
            CorpusNetwork::Testnet.genesis_hash().to_rpc_hex(),
            "05a60a92d99d85997cce3b87616c089f6124d7342af37106edc76126334a2c38"
        );
        assert_eq!(
            CorpusNetwork::Regtest.genesis_hash().to_rpc_hex(),
            "029f11d80ef9765602235e1bc9727e3eb6ba20839319f761fee920d63401e327"
        );
    }

    #[test]
    fn empty_scan_is_rejected_before_emitting_a_report() -> Result<(), Box<dyn std::error::Error>> {
        let result = scan_indexed_blocks(
            std::iter::empty::<&IndexedBlock>(),
            CorpusChainIdentity::new(CorpusNetwork::Mainnet),
            GrowthAssumption::new(0, 0)?,
            sizing()?,
        );

        assert!(matches!(result, Err(ZainoCorpusError::EmptyChain)));
        Ok(())
    }

    #[test]
    fn nonempty_canonical_fixture_runs_extraction_adapter_and_aggregate_report(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let genesis = fixture_genesis()?;
        let report = scan_indexed_blocks(
            [&genesis],
            CorpusChainIdentity::new(CorpusNetwork::Regtest),
            GrowthAssumption::new(0, 0)?,
            sizing()?,
        )?;
        let output = report.to_string();

        assert!(output.contains("network=regtest"));
        assert!(output.contains("final_height=0"));
        assert!(output.contains("blocks=1"));
        assert!(output.contains("transactions=2"));
        assert!(output.contains("outputs=3"));
        assert!(output.contains("spends=1"));
        assert_eq!(report.aggregate.distinct_standard_addresses(), 2);
        assert_eq!(report.aggregate.live_standard_utxos(), 1);
        assert_eq!(report.aggregate.live_nonstandard_utxos(), 1);
        assert_eq!(
            report.aggregate.events_per_address(),
            &BTreeMap::from([(1, 1), (2, 1)])
        );
        Ok(())
    }

    #[test]
    fn incremental_scanner_matches_iterator_helper_without_retaining_blocks(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let genesis = fixture_genesis()?;
        let second = fixture_second_block()?;
        let chain = CorpusChainIdentity::new(CorpusNetwork::Regtest);
        let mut scanner = ZainoCorpusScanner::new(chain, GrowthAssumption::new(0, 0)?, sizing()?);

        scanner.push(&genesis)?;
        scanner.push(&second)?;
        let incremental = scanner.finish()?;
        let iterator = scan_indexed_blocks(
            [&genesis, &second],
            chain,
            GrowthAssumption::new(0, 0)?,
            sizing()?,
        )?;

        assert_eq!(incremental.to_string(), iterator.to_string());
        assert!(incremental.to_string().contains("final_height=1"));
        Ok(())
    }

    #[test]
    fn aggregate_mutation_failure_permanently_poisons_incremental_scanner(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let unknown_spend = transaction(
            0,
            [0x44; 32],
            vec![TxInCompact::new([0xff; 32], 0)],
            Vec::new(),
        );
        let invalid_genesis = indexed_block(
            0,
            CorpusNetwork::Regtest.genesis_hash().0,
            [0; 32],
            vec![unknown_spend],
        )?;
        let mut scanner = ZainoCorpusScanner::new(
            CorpusChainIdentity::new(CorpusNetwork::Regtest),
            GrowthAssumption::new(0, 0)?,
            sizing()?,
        );

        assert!(matches!(
            scanner.push(&invalid_genesis),
            Err(ZainoCorpusError::Aggregate(
                CorpusError::UnknownSpentOutpoint
            ))
        ));
        assert!(matches!(
            scanner.push(&invalid_genesis),
            Err(ZainoCorpusError::ScannerPoisoned)
        ));
        assert!(matches!(
            scanner.finish(),
            Err(ZainoCorpusError::ScannerPoisoned)
        ));
        Ok(())
    }

    #[test]
    fn chain_provenance_rejects_wrong_genesis_and_noncontiguous_parent(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let genesis = fixture_genesis()?;
        let wrong_genesis = scan_indexed_blocks(
            [&genesis],
            CorpusChainIdentity::new(CorpusNetwork::Mainnet),
            GrowthAssumption::new(0, 0)?,
            sizing()?,
        );
        assert!(matches!(
            wrong_genesis,
            Err(ZainoCorpusError::GenesisHashMismatch)
        ));

        let wrong_parent = indexed_block(1, [0x92; 32], [0xee; 32], Vec::new())?;
        let discontinuous = scan_indexed_blocks(
            [&genesis, &wrong_parent],
            CorpusChainIdentity::new(CorpusNetwork::Regtest),
            GrowthAssumption::new(0, 0)?,
            sizing()?,
        );
        assert!(matches!(
            discontinuous,
            Err(ZainoCorpusError::ParentHashMismatch { height: 1 })
        ));
        Ok(())
    }

    #[test]
    fn adapter_preserves_standard_and_nonstandard_aggregate_semantics(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let standard_outpoint = Outpoint::new([0x11; 32], 0);
        let nonstandard_outpoint = Outpoint::new([0x22; 32], 1);
        let mut accumulator = CorpusAccumulator::from_genesis();
        apply_transparent_event(
            &mut accumulator,
            TransparentBlockEvent::Created {
                location: TxLocation::new(1, 0),
                output_index: 0,
                outpoint: standard_outpoint,
                address: Some(AddrScript::new([0xaa; 20], ScriptType::P2PKH as u8)),
                value_zat: 50,
                script_class: ScriptType::P2PKH,
            },
        )?;
        apply_transparent_event(
            &mut accumulator,
            TransparentBlockEvent::Created {
                location: TxLocation::new(1, 0),
                output_index: 1,
                outpoint: nonstandard_outpoint,
                address: None,
                value_zat: 75,
                script_class: ScriptType::NonStandard,
            },
        )?;
        apply_transparent_event(
            &mut accumulator,
            TransparentBlockEvent::Spent {
                location: TxLocation::new(2, 0),
                input_index: 0,
                previous: standard_outpoint,
            },
        )?;

        let report = accumulator.finish(GrowthAssumption::new(0, 0)?, sizing()?)?;
        assert_eq!(report.distinct_standard_addresses(), 1);
        assert_eq!(report.live_standard_utxos(), 0);
        assert_eq!(report.live_nonstandard_utxos(), 1);
        assert_eq!(report.events_per_address(), &BTreeMap::from([(2, 1)]));
        Ok(())
    }
}
