//! Shared plain constructors for synchronous `IndexedBlock` fixture tests.

use std::num::NonZeroU128;

use zaino_state::{
    chain_index::types::EquihashSolution, BlockContext, BlockData, BlockHash, ChainWork,
    CommitmentTreeData, CommitmentTreeRoots, CommitmentTreeSizes, CompactDifficulty, CompactTxData,
    Height, IndexedBlock, OrchardCompactTx, SaplingCompactTx, ScriptType, TransactionHash,
    TransparentCompactTx, TxInCompact, TxOutCompact,
};

pub(super) type FixtureResult<T> = Result<T, Box<dyn std::error::Error>>;

pub(super) fn transaction(
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

pub(super) fn output(
    value: u64,
    hash: [u8; 20],
    script_class: ScriptType,
) -> FixtureResult<TxOutCompact> {
    TxOutCompact::new(value, hash, script_class as u8)
        .ok_or_else(|| "known script class must construct a compact output".into())
}

pub(super) fn indexed_block(
    height: u32,
    hash: [u8; 32],
    parent_hash: [u8; 32],
    transactions: Vec<CompactTxData>,
) -> FixtureResult<IndexedBlock> {
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
