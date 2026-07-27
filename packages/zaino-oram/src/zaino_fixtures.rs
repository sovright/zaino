//! Shared plain constructors for synchronous `IndexedBlock` fixture tests.

use std::num::NonZeroU128;

use zaino_state::{
    chain_index::types::EquihashSolution, BlockContext, BlockData, BlockHash, ChainWork,
    CommitmentTreeData, CommitmentTreeRoots, CommitmentTreeSizes, CompactDifficulty, CompactTxData,
    Height, IndexedBlock, OrchardCompactTx, SaplingCompactTx, ScriptType, TransactionHash,
    TransparentCompactTx, TxInCompact, TxOutCompact,
};

use crate::canonical_chain::CanonicalNetwork;

pub(super) type FixtureResult<T> = Result<T, Box<dyn std::error::Error>>;

pub(super) const SECOND_HASH: [u8; 32] = [0x92; 32];
pub(super) const THIRD_HASH: [u8; 32] = [0x93; 32];

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

pub(super) fn projection_chain() -> FixtureResult<[IndexedBlock; 3]> {
    let address_a = [0xa1; 20];
    let address_b = [0xb2; 20];
    let address_c = [0xc3; 20];
    let first_txid = [0x11; 32];
    let second_txid = [0x22; 32];
    let third_txid = [0x33; 32];

    let first = transaction(
        0,
        first_txid,
        vec![TxInCompact::null_prevout()],
        vec![
            output(50, address_a, ScriptType::P2PKH)?,
            output(60, address_a, ScriptType::P2PKH)?,
            output(70, [0xdd; 20], ScriptType::NonStandard)?,
        ],
    );
    let same_block_spend = transaction(
        1,
        second_txid,
        vec![TxInCompact::new(first_txid, 0)],
        vec![output(40, address_b, ScriptType::P2SH)?],
    );
    let genesis = indexed_block(
        0,
        CanonicalNetwork::Regtest.genesis_hash().0,
        [0; 32],
        vec![first, same_block_spend],
    )?;

    let cross_block_spend = transaction(
        0,
        third_txid,
        vec![TxInCompact::new(second_txid, 0)],
        vec![
            output(30, address_a, ScriptType::P2PKH)?,
            output(20, address_c, ScriptType::P2SH)?,
        ],
    );
    let second = indexed_block(
        1,
        SECOND_HASH,
        CanonicalNetwork::Regtest.genesis_hash().0,
        vec![cross_block_spend],
    )?;

    let nonstandard_spend = transaction(
        0,
        [0x44; 32],
        vec![TxInCompact::new(first_txid, 2)],
        Vec::new(),
    );
    let third = indexed_block(2, THIRD_HASH, SECOND_HASH, vec![nonstandard_spend])?;
    Ok([genesis, second, third])
}
