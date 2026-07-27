//! Transaction-bound materialization of finalized transparent outpoint state.

use super::*;

use crate::{
    chain_index::types::{
        AddrScript, BlockIndex, FinalizedOutpointSnapshot, FinalizedOutpointState, ScriptType,
    },
    ZainoVersionedSerde,
};
use corez::io::Cursor as CoreCursor;
use lmdb::RoTransaction;
use std::collections::{hash_map::Entry, BTreeMap, HashMap};

#[derive(Clone, Copy)]
enum OutpointExpectation {
    ExpectedNewAfterCheckpoint,
    MustExistAtCheckpoint,
}

/// Forward-index rows for one block, decoded and integrity-checked together.
struct VerifiedTransparentBlock {
    txids: TxidList,
    transactions: TransparentTxList,
}

impl DbV1 {
    /// Materializes every required existing outpoint at `checkpoint` from one immutable LMDB view.
    ///
    /// The blocking task owns a detached database handle, begins exactly one read transaction,
    /// and validates all metadata, checkpoint, reverse-index, forward-row, and spent-index data
    /// before constructing the returned business-layer snapshot.
    pub(in crate::chain_index::finalised_state::finalised_source) async fn materialize_outpoint_snapshot(
        &self,
        checkpoint: BlockIndex,
        expected_new_outpoints: Vec<Outpoint>,
        required_outpoints: Vec<Outpoint>,
    ) -> Result<FinalizedOutpointSnapshot, FinalisedStateError> {
        let database = self.detached_handle();

        tokio::task::spawn_blocking(move || {
            database.materialize_outpoint_snapshot_blocking(
                checkpoint,
                expected_new_outpoints,
                required_outpoints,
            )
        })
        .await
        .map_err(|error| {
            FinalisedStateError::Custom(format!(
                "finalized outpoint materialization task failed: {error}"
            ))
        })?
    }

    fn materialize_outpoint_snapshot_blocking(
        &self,
        checkpoint: BlockIndex,
        expected_new_outpoints: Vec<Outpoint>,
        required_outpoints: Vec<Outpoint>,
    ) -> Result<FinalizedOutpointSnapshot, FinalisedStateError> {
        let transaction = self.env.begin_ro_txn()?;

        self.validate_materialization_metadata(&transaction)?;
        self.validate_materialization_checkpoint(&transaction, checkpoint)?;

        let mut requested = BTreeMap::new();
        for outpoint in required_outpoints {
            requested.insert(outpoint, OutpointExpectation::MustExistAtCheckpoint);
        }
        for outpoint in expected_new_outpoints {
            requested.insert(outpoint, OutpointExpectation::ExpectedNewAfterCheckpoint);
        }
        let mut block_cache = HashMap::new();
        let mut states = BTreeMap::new();

        for (outpoint, expectation) in requested {
            let state = self.materialize_outpoint_in_transaction(
                &transaction,
                checkpoint,
                outpoint,
                expectation,
                &mut block_cache,
            )?;
            states.insert(outpoint, state);
        }

        Ok(FinalizedOutpointSnapshot::new(checkpoint, states))
    }

    fn validate_materialization_metadata(
        &self,
        transaction: &RoTransaction<'_>,
    ) -> Result<(), FinalisedStateError> {
        const METADATA_KEY: &[u8] = b"metadata";

        let raw = match transaction.get(self.metadata, &METADATA_KEY) {
            Ok(raw) => raw,
            Err(lmdb::Error::NotFound) => {
                return Err(FinalisedStateError::DataUnavailable(
                    "finalized database metadata is unavailable".to_string(),
                ));
            }
            Err(error) => return Err(FinalisedStateError::LmdbError(error)),
        };
        let entry = Self::decode_exact::<StoredEntryFixed<DbMetadata>>(raw, "metadata")?;

        if !entry.verify(METADATA_KEY) {
            return Err(Self::materialization_integrity_error(
                "metadata checksum mismatch",
            ));
        }

        let metadata = entry.inner();
        if metadata.version != DB_VERSION_V1 {
            return Err(FinalisedStateError::DataUnavailable(
                "finalized database schema version is not current".to_string(),
            ));
        }
        if metadata.schema_hash != DB_SCHEMA_V1_HASH {
            return Err(Self::materialization_integrity_error(
                "metadata schema hash mismatch",
            ));
        }
        if metadata.migration_status != MigrationStatus::Empty {
            return Err(FinalisedStateError::DataUnavailable(
                "finalized database migration is in progress".to_string(),
            ));
        }

        Ok(())
    }

    fn validate_materialization_checkpoint(
        &self,
        transaction: &RoTransaction<'_>,
        checkpoint: BlockIndex,
    ) -> Result<(), FinalisedStateError> {
        let (height_bytes, raw_header) = {
            let cursor = transaction.open_ro_cursor(self.headers)?;
            match cursor.get(None, None, lmdb_sys::MDB_LAST) {
                Ok((Some(height_bytes), raw_header)) => {
                    (height_bytes.to_vec(), raw_header.to_vec())
                }
                Ok((None, _)) => {
                    return Err(Self::materialization_integrity_error(
                        "tip header cursor returned no key",
                    ));
                }
                Err(lmdb::Error::NotFound) => {
                    return Err(FinalisedStateError::DataUnavailable(
                        "finalized checkpoint is unavailable".to_string(),
                    ));
                }
                Err(error) => return Err(FinalisedStateError::LmdbError(error)),
            }
        };

        let tip_height = Self::decode_exact::<Height>(&height_bytes, "tip height key")?;
        let header = Self::decode_verified_var_row::<BlockHeaderData>(
            &height_bytes,
            &raw_header,
            "tip header",
        )?;

        if header.context.index.height != tip_height {
            return Err(Self::materialization_integrity_error(
                "tip header height does not match its key",
            ));
        }
        if tip_height != checkpoint.height {
            return Err(FinalisedStateError::DataUnavailable(
                "requested finalized checkpoint is not the database tip".to_string(),
            ));
        }
        if header.context.index != checkpoint {
            return Err(FinalisedStateError::DataUnavailable(
                "requested finalized checkpoint hash does not match the database tip".to_string(),
            ));
        }

        Ok(())
    }

    fn materialize_outpoint_in_transaction(
        &self,
        transaction: &RoTransaction<'_>,
        checkpoint: BlockIndex,
        outpoint: Outpoint,
        expectation: OutpointExpectation,
        block_cache: &mut HashMap<u32, VerifiedTransparentBlock>,
    ) -> Result<FinalizedOutpointState, FinalisedStateError> {
        let outpoint_key = outpoint.to_bytes().map_err(|error| {
            Self::materialization_integrity_error(format!(
                "outpoint key could not be encoded: {error}"
            ))
        })?;
        let spender =
            self.read_verified_location(transaction, self.spent, &outpoint_key, "spent index")?;

        let txid_key = *outpoint.prev_txid();
        let creator = self.read_verified_location(
            transaction,
            self.txid_location,
            &txid_key,
            "txid location index",
        )?;

        let Some(creator) = creator else {
            if spender.is_some() {
                return Err(Self::materialization_integrity_error(
                    "spent index references an outpoint with no creating transaction",
                ));
            }
            return match expectation {
                OutpointExpectation::ExpectedNewAfterCheckpoint => {
                    Ok(FinalizedOutpointState::NeverSeen)
                }
                OutpointExpectation::MustExistAtCheckpoint => {
                    Err(Self::materialization_integrity_error(
                        "required outpoint has no creating transaction index entry",
                    ))
                }
            };
        };

        if creator.block_height() > checkpoint.height.0 {
            return Err(Self::materialization_integrity_error(
                "creating transaction location is beyond the checkpoint",
            ));
        }

        let expected_txid = TransactionHash::from(txid_key);
        let output = {
            let block = self.verified_transparent_block(
                transaction,
                Height(creator.block_height()),
                block_cache,
            )?;
            let transaction_index = usize::from(creator.tx_index());
            let forward_txid = block.txids.txids().get(transaction_index).ok_or_else(|| {
                Self::materialization_integrity_error(
                    "creating transaction location is outside its forward txid row",
                )
            })?;

            if forward_txid != &expected_txid {
                return Err(Self::materialization_integrity_error(
                    "txid location index disagrees with the forward txid row",
                ));
            }

            let transparent = block
                .transactions
                .tx()
                .get(transaction_index)
                .ok_or_else(|| {
                    Self::materialization_integrity_error(
                        "creating transaction location is outside its transparent row",
                    )
                })?;
            let output_index = usize::try_from(outpoint.prev_index()).map_err(|error| {
                Self::materialization_integrity_error(format!(
                    "output index cannot be represented in memory: {error}"
                ))
            })?;

            transparent
                .as_ref()
                .and_then(|transaction| transaction.outputs().get(output_index))
                .copied()
        };

        let Some(output) = output else {
            if spender.is_some() {
                return Err(Self::materialization_integrity_error(
                    "spent index references an outpoint with no creating output",
                ));
            }
            return match expectation {
                OutpointExpectation::ExpectedNewAfterCheckpoint => {
                    Ok(FinalizedOutpointState::NeverSeen)
                }
                OutpointExpectation::MustExistAtCheckpoint => {
                    Err(Self::materialization_integrity_error(
                        "required outpoint has no creating output",
                    ))
                }
            };
        };

        if let Some(spender) = spender {
            self.validate_spender(
                transaction,
                checkpoint,
                outpoint,
                creator,
                spender,
                block_cache,
            )?;
            return Ok(FinalizedOutpointState::Spent);
        }

        let created_height = Height(creator.block_height());
        match output.script_type_enum() {
            Some(ScriptType::P2PKH | ScriptType::P2SH) => {
                Ok(FinalizedOutpointState::LiveStandard {
                    address: AddrScript::new(*output.script_hash(), output.script_type()),
                    value_zat: output.value(),
                    created_height,
                })
            }
            Some(ScriptType::NonStandard) => {
                Ok(FinalizedOutpointState::LiveNonStandard { created_height })
            }
            None => Err(Self::materialization_integrity_error(
                "transparent output carries an invalid script type",
            )),
        }
    }

    fn validate_spender(
        &self,
        transaction: &RoTransaction<'_>,
        checkpoint: BlockIndex,
        outpoint: Outpoint,
        creator: TxLocation,
        spender: TxLocation,
        block_cache: &mut HashMap<u32, VerifiedTransparentBlock>,
    ) -> Result<(), FinalisedStateError> {
        if spender.block_height() > checkpoint.height.0 {
            return Err(Self::materialization_integrity_error(
                "spending transaction location is beyond the checkpoint",
            ));
        }
        if !Self::location_is_after(spender, creator) {
            return Err(Self::materialization_integrity_error(
                "spending transaction does not follow the creating transaction",
            ));
        }

        let block = self.verified_transparent_block(
            transaction,
            Height(spender.block_height()),
            block_cache,
        )?;
        let transaction_index = usize::from(spender.tx_index());
        let transparent = block
            .transactions
            .tx()
            .get(transaction_index)
            .ok_or_else(|| {
                Self::materialization_integrity_error(
                    "spending transaction location is outside its transparent row",
                )
            })?;
        let transparent = transparent.as_ref().ok_or_else(|| {
            Self::materialization_integrity_error(
                "spent index points to a transaction with no transparent component",
            )
        })?;
        let contains_outpoint = transparent.inputs().iter().any(|input| {
            !input.is_null_prevout()
                && input.prevout_txid() == outpoint.prev_txid()
                && input.prevout_index() == outpoint.prev_index()
        });

        if !contains_outpoint {
            return Err(Self::materialization_integrity_error(
                "spent index disagrees with the spending transaction inputs",
            ));
        }

        Ok(())
    }

    fn verified_transparent_block<'cache>(
        &self,
        transaction: &RoTransaction<'_>,
        height: Height,
        block_cache: &'cache mut HashMap<u32, VerifiedTransparentBlock>,
    ) -> Result<&'cache VerifiedTransparentBlock, FinalisedStateError> {
        match block_cache.entry(height.0) {
            Entry::Occupied(entry) => Ok(entry.into_mut()),
            Entry::Vacant(entry) => {
                let block = self.load_verified_transparent_block(transaction, height)?;
                Ok(entry.insert(block))
            }
        }
    }

    fn load_verified_transparent_block(
        &self,
        transaction: &RoTransaction<'_>,
        height: Height,
    ) -> Result<VerifiedTransparentBlock, FinalisedStateError> {
        let height_key = height.to_bytes().map_err(|error| {
            Self::materialization_integrity_error(format!(
                "block height key could not be encoded: {error}"
            ))
        })?;
        let header = self.read_required_verified_var_row::<BlockHeaderData>(
            transaction,
            self.headers,
            &height_key,
            "header",
        )?;
        let txids = self.read_required_verified_var_row::<TxidList>(
            transaction,
            self.txids,
            &height_key,
            "txids",
        )?;
        let transactions = self.read_required_verified_var_row::<TransparentTxList>(
            transaction,
            self.transparent,
            &height_key,
            "transparent transactions",
        )?;

        if header.context.index.height != height {
            return Err(Self::materialization_integrity_error(
                "header height does not match its row key",
            ));
        }
        if txids.txids().len() != transactions.tx().len() {
            return Err(Self::materialization_integrity_error(
                "txid and transparent transaction rows have different lengths",
            ));
        }
        if txids.txids().is_empty() {
            return Err(Self::materialization_integrity_error(
                "block transaction row is empty",
            ));
        }

        let txid_bytes: Vec<[u8; 32]> = txids.txids().iter().map(|txid| txid.0).collect();
        let calculated_merkle_root = Self::calculate_block_merkle_root(&txid_bytes);
        if header.data().merkle_root() != &calculated_merkle_root {
            return Err(Self::materialization_integrity_error(
                "header merkle root disagrees with the transaction row",
            ));
        }

        Ok(VerifiedTransparentBlock {
            txids,
            transactions,
        })
    }

    fn read_required_verified_var_row<T: ZainoVersionedSerde>(
        &self,
        transaction: &RoTransaction<'_>,
        database: lmdb::Database,
        key: &[u8],
        label: &str,
    ) -> Result<T, FinalisedStateError> {
        let raw = match transaction.get(database, &key) {
            Ok(raw) => raw,
            Err(lmdb::Error::NotFound) => {
                return Err(Self::materialization_integrity_error(format!(
                    "required {label} row is missing"
                )));
            }
            Err(error) => return Err(FinalisedStateError::LmdbError(error)),
        };

        Self::decode_verified_var_row(key, raw, label)
    }

    fn decode_verified_var_row<T: ZainoVersionedSerde>(
        key: &[u8],
        raw: &[u8],
        label: &str,
    ) -> Result<T, FinalisedStateError> {
        let mut cursor = CoreCursor::new(raw);
        let stored_entry_version = crate::read_u8(&mut cursor).map_err(|error| {
            Self::materialization_integrity_error(format!(
                "{label} row framing could not be decoded: {error}"
            ))
        })?;
        if stored_entry_version != StoredEntryVar::<T>::VERSION {
            return Err(Self::materialization_integrity_error(format!(
                "{label} row has an unsupported stored-entry version"
            )));
        }

        let item_len = CompactSize::read(&mut cursor)
            .and_then(|length| {
                usize::try_from(length).map_err(|_| {
                    corez::io::Error::new(
                        corez::io::ErrorKind::InvalidData,
                        "stored-entry item length cannot be represented",
                    )
                })
            })
            .map_err(|error| {
                Self::materialization_integrity_error(format!(
                    "{label} row length could not be decoded: {error}"
                ))
            })?;
        let item_start = usize::try_from(cursor.position()).map_err(|error| {
            Self::materialization_integrity_error(format!(
                "{label} row item offset cannot be represented: {error}"
            ))
        })?;
        let item_end = item_start.checked_add(item_len).ok_or_else(|| {
            Self::materialization_integrity_error(format!("{label} row item length overflow"))
        })?;
        let row_end = item_end.checked_add(32).ok_or_else(|| {
            Self::materialization_integrity_error(format!("{label} row length overflow"))
        })?;
        if row_end != raw.len() {
            return Err(Self::materialization_integrity_error(format!(
                "{label} row framing does not consume the exact value"
            )));
        }

        let item_bytes = &raw[item_start..item_end];
        let expected_checksum: [u8; 32] = raw[item_end..row_end].try_into().map_err(|_| {
            Self::materialization_integrity_error(format!(
                "{label} row checksum has the wrong length"
            ))
        })?;
        let calculated_checksum = StoredEntryVar::<T>::blake2b256(&[key, item_bytes].concat());
        if calculated_checksum != expected_checksum {
            return Err(Self::materialization_integrity_error(format!(
                "{label} row checksum mismatch"
            )));
        }

        let mut item_cursor = CoreCursor::new(item_bytes);
        let item = T::deserialize(&mut item_cursor).map_err(|error| {
            Self::materialization_integrity_error(format!(
                "{label} row item could not be decoded: {error}"
            ))
        })?;
        let consumed = usize::try_from(item_cursor.position()).map_err(|error| {
            Self::materialization_integrity_error(format!(
                "{label} row item decoded length cannot be represented: {error}"
            ))
        })?;
        if consumed != item_bytes.len() {
            return Err(Self::materialization_integrity_error(format!(
                "{label} row item contains trailing bytes"
            )));
        }

        Ok(item)
    }

    fn read_verified_location(
        &self,
        transaction: &RoTransaction<'_>,
        database: lmdb::Database,
        key: &[u8],
        label: &str,
    ) -> Result<Option<TxLocation>, FinalisedStateError> {
        let raw = match transaction.get(database, &key) {
            Ok(raw) => raw,
            Err(lmdb::Error::NotFound) => return Ok(None),
            Err(error) => return Err(FinalisedStateError::LmdbError(error)),
        };
        let entry = Self::decode_exact::<StoredEntryFixed<TxLocation>>(raw, label)?;
        if !entry.verify(key) {
            return Err(Self::materialization_integrity_error(format!(
                "{label} row checksum mismatch"
            )));
        }

        Ok(Some(entry.item))
    }

    fn decode_exact<T: ZainoVersionedSerde>(
        raw: &[u8],
        label: &str,
    ) -> Result<T, FinalisedStateError> {
        let mut cursor = CoreCursor::new(raw);
        let item = T::deserialize(&mut cursor).map_err(|error| {
            Self::materialization_integrity_error(format!(
                "{label} row could not be decoded: {error}"
            ))
        })?;
        let consumed = usize::try_from(cursor.position()).map_err(|error| {
            Self::materialization_integrity_error(format!(
                "{label} row decoded length cannot be represented: {error}"
            ))
        })?;
        if consumed != raw.len() {
            return Err(Self::materialization_integrity_error(format!(
                "{label} row contains trailing bytes"
            )));
        }

        Ok(item)
    }

    fn location_is_after(candidate: TxLocation, reference: TxLocation) -> bool {
        candidate.block_height() > reference.block_height()
            || (candidate.block_height() == reference.block_height()
                && candidate.tx_index() > reference.tx_index())
    }

    fn materialization_integrity_error(message: impl Into<String>) -> FinalisedStateError {
        FinalisedStateError::Custom(format!(
            "finalized outpoint materialization integrity failure: {}",
            message.into()
        ))
    }
}
