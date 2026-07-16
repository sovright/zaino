use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::{Debug, Display},
};

use lmdb::{Database, Environment, Transaction as _, WriteFlags};

use super::{load_test_vectors_and_sync_chain_index, MockchainMode};
use crate::chain_index::{
    finalised_state::entry::{StoredEntryFixed, StoredEntryVar},
    finalized_height_floor,
    tests::finalised_state::v1::load_vectors_v1db_and_reader,
    tests::vectors::indexed_block_chain,
    types::{extract_transparent_events, FinalizedOutpointState, Outpoint, TransparentBlockEvent},
};
use crate::{CompactSize, Height, TxLocation, TxidList, ZainoVersionedSerde};
use zaino_common::network::ActivationHeights;

/// multi_thread required: the persistent-v1 fixture transitively uses `block_in_place`.
#[tokio::test(flavor = "multi_thread")]
async fn captures_value_coherent_transparent_projection_input(
) -> Result<(), Box<dyn std::error::Error>> {
    let (_blocks, indexer, subscriber, mockchain) =
        load_test_vectors_and_sync_chain_index(MockchainMode::Active).await;

    let input = subscriber
        .capture_canonical_transparent_projection_input()
        .await?;
    let expected_finalized_height = finalized_height_floor(mockchain.active_height());

    assert_eq!(
        input.network(),
        &ActivationHeights::default().to_regtest_network()
    );
    assert_eq!(input.recent().finalized().height, expected_finalized_height);
    assert_eq!(
        input.finalized_outpoints().checkpoint(),
        input.recent().finalized()
    );

    let mut referenced = BTreeSet::<Outpoint>::new();
    let mut created = BTreeSet::<Outpoint>::new();
    for block in input.recent().blocks() {
        for event in extract_transparent_events(block)? {
            match event {
                TransparentBlockEvent::Created { outpoint, .. } => {
                    referenced.insert(outpoint);
                    created.insert(outpoint);
                }
                TransparentBlockEvent::Spent { previous, .. } => {
                    referenced.insert(previous);
                }
            }
        }
    }

    assert_eq!(input.finalized_outpoints().len(), referenced.len());
    let mut never_seen = 0usize;
    let mut live = 0usize;
    for outpoint in &referenced {
        match input.finalized_outpoints().classify(outpoint) {
            Some(FinalizedOutpointState::NeverSeen) => never_seen += 1,
            Some(FinalizedOutpointState::LiveStandard { .. })
            | Some(FinalizedOutpointState::LiveNonStandard { .. }) => live += 1,
            Some(FinalizedOutpointState::Spent) => {
                panic!("a recent canonical spend cannot already be spent at the finalized seam")
            }
            None => panic!("every referenced outpoint must be materialized exactly once"),
        }
    }

    for outpoint in created {
        assert_eq!(
            input.finalized_outpoints().classify(&outpoint),
            Some(FinalizedOutpointState::NeverSeen)
        );
    }
    assert!(
        never_seen > 0,
        "fixture must exercise never-seen resolution"
    );
    assert!(live > 0, "fixture must exercise live finalized resolution");

    indexer.shutdown().await?;
    Ok(())
}

/// multi_thread required: the persistent-v1 fixture transitively uses `block_in_place`.
#[tokio::test(flavor = "multi_thread")]
async fn finalized_materializer_deduplicates_and_validates_exact_checkpoint(
) -> Result<(), Box<dyn std::error::Error>> {
    let (vectors, _db_dir, database, reader) = load_vectors_v1db_and_reader().await;
    let blocks = vectors.blocks;
    let tip_height = crate::Height(
        blocks
            .last()
            .expect("checked-in block vectors must not be empty")
            .height,
    );
    let checkpoint = reader.get_block_header(tip_height).await?.context.index;

    let mut created_standard = BTreeMap::new();
    let mut spent_outpoints = BTreeSet::new();
    let mut spent_events = Vec::new();
    for block in
        indexed_block_chain(&blocks).take_while(|block| block.height() <= checkpoint.height)
    {
        for event in extract_transparent_events(&block)? {
            match event {
                TransparentBlockEvent::Created {
                    location,
                    outpoint,
                    address: Some(address),
                    value_zat,
                    ..
                } => {
                    created_standard.insert(
                        outpoint,
                        (
                            address,
                            value_zat,
                            Height(location.block_height()),
                            location,
                        ),
                    );
                }
                TransparentBlockEvent::Created { .. } => {}
                TransparentBlockEvent::Spent {
                    location, previous, ..
                } => {
                    spent_outpoints.insert(previous);
                    spent_events.push((previous, location));
                }
            }
        }
    }

    let (spent, actual_spender) = spent_events
        .first()
        .copied()
        .expect("fixture must contain a finalized transparent spend");
    let wrong_spender = spent_events
        .iter()
        .rev()
        .find_map(|(candidate, location)| {
            (*candidate != spent && location_is_after(*location, actual_spender))
                .then_some(*location)
        })
        .expect("fixture must contain a later, unrelated transparent spend");
    let (live, (live_address, live_value_zat, live_created_height, live_creator)) =
        created_standard
            .iter()
            .find(|(outpoint, _)| !spent_outpoints.contains(outpoint))
            .map(|(outpoint, state)| (*outpoint, *state))
            .expect("fixture must contain a live standard transparent output");
    let wrong_creator = spent_events
        .iter()
        .map(|(_, location)| *location)
        .find(|location| *location != live_creator)
        .expect("fixture must contain a transaction distinct from the live output creator");
    let expected_live = FinalizedOutpointState::LiveStandard {
        address: live_address,
        value_zat: live_value_zat,
        created_height: live_created_height,
    };
    let unknown = Outpoint::new([0xa5; 32], 7);

    let materialized = reader
        .materialize_finalized_outpoints(
            checkpoint,
            vec![unknown, unknown, live, spent],
            vec![spent, spent, live],
        )
        .await?;
    assert_eq!(materialized.len(), 3);
    assert_eq!(
        materialized.classify(&spent),
        Some(FinalizedOutpointState::Spent)
    );
    assert_eq!(
        materialized.classify(&unknown),
        Some(FinalizedOutpointState::NeverSeen)
    );
    // `live` and `spent` are deliberately supplied in both partitions. Expected-new wins each
    // partition overlap, but real pre-checkpoint collisions must still resolve to their exact
    // existing states rather than `NeverSeen`.
    assert_eq!(materialized.classify(&live), Some(expected_live));

    let backend = database.router().primary_backend();
    let environment = backend.env()?;
    let spent_database = backend.spent_db()?;
    let txid_location_database = backend.txid_location_db()?;
    let txids_database = backend.txids_db()?;

    let spent_key = spent.to_bytes()?;
    let original_spent_row = read_row(&environment, spent_database, &spent_key)?;
    let mut corrupt_spent_row = original_spent_row.clone();
    let checksum_byte = corrupt_spent_row
        .last_mut()
        .expect("a checksummed spent row must not be empty");
    *checksum_byte ^= 1;
    write_row(&environment, spent_database, &spent_key, &corrupt_spent_row)?;
    let corrupt_spent_result = reader
        .materialize_finalized_outpoints(checkpoint, Vec::new(), vec![spent])
        .await;
    write_row(
        &environment,
        spent_database,
        &spent_key,
        &original_spent_row,
    )?;
    assert_error_contains(corrupt_spent_result, "spent index row checksum mismatch");

    let live_height_key = live_created_height.to_bytes()?;
    let original_txids_row = read_row(&environment, txids_database, &live_height_key)?;
    let mut outer_trailing_txids_row = original_txids_row.clone();
    outer_trailing_txids_row.push(0x5a);
    write_row(
        &environment,
        txids_database,
        &live_height_key,
        &outer_trailing_txids_row,
    )?;
    let outer_trailing_result = reader
        .materialize_finalized_outpoints(checkpoint, Vec::new(), vec![live])
        .await;
    write_row(
        &environment,
        txids_database,
        &live_height_key,
        &original_txids_row,
    )?;
    assert_error_contains(
        outer_trailing_result,
        "txids row framing does not consume the exact value",
    );

    let txids = StoredEntryVar::<TxidList>::from_bytes(&original_txids_row)?
        .inner()
        .clone();
    let inner_trailing_txids_row =
        encode_var_row_with_inner_trailing_byte(&live_height_key, &txids, 0x5a)?;
    write_row(
        &environment,
        txids_database,
        &live_height_key,
        &inner_trailing_txids_row,
    )?;
    let inner_trailing_result = reader
        .materialize_finalized_outpoints(checkpoint, Vec::new(), vec![live])
        .await;
    write_row(
        &environment,
        txids_database,
        &live_height_key,
        &original_txids_row,
    )?;
    assert_error_contains(
        inner_trailing_result,
        "txids row item contains trailing bytes",
    );

    let live_txid_key = live.prev_txid();
    let original_creator_row = read_row(&environment, txid_location_database, live_txid_key)?;
    let wrong_creator_row = StoredEntryFixed::new(live_txid_key, wrong_creator).to_bytes()?;
    write_row(
        &environment,
        txid_location_database,
        live_txid_key,
        &wrong_creator_row,
    )?;
    let wrong_creator_result = reader
        .materialize_finalized_outpoints(checkpoint, Vec::new(), vec![live])
        .await;
    write_row(
        &environment,
        txid_location_database,
        live_txid_key,
        &original_creator_row,
    )?;
    assert_error_contains(
        wrong_creator_result,
        "txid location index disagrees with the forward txid row",
    );

    delete_row(&environment, txid_location_database, live_txid_key)?;
    let missing_creator_result = reader
        .materialize_finalized_outpoints(checkpoint, Vec::new(), vec![live])
        .await;
    write_row(
        &environment,
        txid_location_database,
        live_txid_key,
        &original_creator_row,
    )?;
    assert_error_contains(
        missing_creator_result,
        "required outpoint has no creating transaction index entry",
    );

    let wrong_spender_row = StoredEntryFixed::new(&spent_key, wrong_spender).to_bytes()?;
    write_row(&environment, spent_database, &spent_key, &wrong_spender_row)?;
    let wrong_spender_result = reader
        .materialize_finalized_outpoints(checkpoint, Vec::new(), vec![spent])
        .await;
    write_row(
        &environment,
        spent_database,
        &spent_key,
        &original_spent_row,
    )?;
    assert_error_contains(
        wrong_spender_result,
        "spent index disagrees with the spending transaction inputs",
    );

    let empty = reader
        .materialize_finalized_outpoints(checkpoint, Vec::new(), Vec::new())
        .await?;
    assert_eq!(empty.len(), 0);

    let mut wrong_checkpoint = checkpoint;
    wrong_checkpoint.hash.0[0] ^= 1;
    assert!(reader
        .materialize_finalized_outpoints(wrong_checkpoint, Vec::new(), Vec::new())
        .await
        .is_err());

    database.shutdown().await?;
    Ok(())
}

fn location_is_after(candidate: TxLocation, reference: TxLocation) -> bool {
    candidate.block_height() > reference.block_height()
        || (candidate.block_height() == reference.block_height()
            && candidate.tx_index() > reference.tx_index())
}

fn read_row(
    environment: &Environment,
    database: Database,
    key: &[u8],
) -> Result<Vec<u8>, lmdb::Error> {
    let transaction = environment.begin_ro_txn()?;
    Ok(transaction.get(database, &key)?.to_vec())
}

fn write_row(
    environment: &Environment,
    database: Database,
    key: &[u8],
    value: &[u8],
) -> Result<(), lmdb::Error> {
    let mut transaction = environment.begin_rw_txn()?;
    transaction.put(database, &key, &value, WriteFlags::empty())?;
    transaction.commit()
}

fn delete_row(
    environment: &Environment,
    database: Database,
    key: &[u8],
) -> Result<(), lmdb::Error> {
    let mut transaction = environment.begin_rw_txn()?;
    transaction.del(database, &key, None)?;
    transaction.commit()
}

fn encode_var_row_with_inner_trailing_byte<T: ZainoVersionedSerde>(
    key: &[u8],
    item: &T,
    trailing_byte: u8,
) -> corez::io::Result<Vec<u8>> {
    let mut item_bytes = item.to_bytes()?;
    item_bytes.push(trailing_byte);
    let checksum = StoredEntryVar::<T>::blake2b256(&[key, &item_bytes].concat());

    let mut encoded = vec![StoredEntryVar::<T>::VERSION];
    CompactSize::write(&mut encoded, item_bytes.len())?;
    encoded.extend_from_slice(&item_bytes);
    encoded.extend_from_slice(&checksum);
    Ok(encoded)
}

fn assert_error_contains<T: Debug, E: Display>(result: Result<T, E>, expected: &str) {
    let error = result.expect_err("corrupt finalized-state row must fail materialization");
    let message = error.to_string();
    assert!(
        message.contains(expected),
        "expected error containing {expected:?}, got {message:?}"
    );
}
