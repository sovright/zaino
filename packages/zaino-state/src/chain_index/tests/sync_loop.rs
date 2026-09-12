use super::{
    load_test_vectors_and_sync_chain_index, load_test_vectors_and_sync_chain_index_with_timings,
    MockchainMode,
};
use crate::chain_index::{ChainIndex, ChainIndexSnapshot, SyncTimings};
use std::{sync::Arc, time::Instant};
use tokio::time::{sleep, Duration};
use zaino_common::status::{Status as _, StatusType};

/// Regression test (fixes #593): a source failure should not kill the
/// sync loop.
///
/// The sync loop (chain_index.rs) sleeps 500ms between iterations. On
/// failure, it used to propagate via `?` and set CriticalError. The
/// indexer serve loop (indexer.rs) checks status every 100ms — so within
/// 100ms of the sync loop failing it called close(), dropping the
/// TonicServer. Integration test clients then got ConnectionRefused
/// because the gRPC port was never reachable.
///
/// The sync loop now retries with exponential backoff and remains live.
#[tokio::test(flavor = "multi_thread")]
async fn survives_transient_source_failure() {
    let (_blocks, _indexer, index_reader, mockchain) =
        load_test_vectors_and_sync_chain_index(MockchainMode::Active).await;

    let start = Instant::now();
    mockchain.set_failing(true);
    sleep(Duration::from_secs(2)).await;

    let status = index_reader.status();
    let elapsed = start.elapsed();

    assert_ne!(
        status,
        StatusType::CriticalError,
        "sync loop should survive transient source failure, not set CriticalError"
    );
    let max_time_to_critical = SyncTimings::default().max_backoff_window() + Duration::from_secs(5);
    assert!(
        elapsed < max_time_to_critical,
        "test took {elapsed:?}, which exceeds the maximum possible backoff window"
    );
}

/// After `max_consecutive_failures` with exponential backoff, the sync loop
/// should escalate to [`StatusType::CriticalError`].
///
/// Uses [`SyncTimings::fast`] (10× shrunk) so the full backoff schedule fits
/// in a few seconds instead of ~40 s.
#[tokio::test(flavor = "multi_thread")]
async fn escalates_to_critical_after_persistent_failure() {
    let timings = SyncTimings::fast();
    let (_blocks, _indexer, index_reader, mockchain) =
        load_test_vectors_and_sync_chain_index_with_timings(MockchainMode::Active, timings).await;

    let start = Instant::now();
    mockchain.set_failing(true);

    // 5× slack over the nominal backoff sum to absorb scheduling jitter and
    // the per-iteration sync work the loop performs between sleeps.
    let max_time_to_critical = timings.max_backoff_window() * 5;
    let poll_interval = timings.initial_backoff;

    loop {
        sleep(poll_interval).await;

        if index_reader.status() == StatusType::CriticalError {
            break;
        }

        assert!(
            start.elapsed() < max_time_to_critical,
            "CriticalError was not reached within {max_time_to_critical:?}"
        );
    }

    let elapsed = start.elapsed();
    assert!(
        elapsed < max_time_to_critical,
        "CriticalError took {elapsed:?}, exceeding the maximum backoff window"
    );
}

/// Moved here from the integration test
/// `chain_cache::sync_large_chain_{zebrad,zcashd}`. That test contained one
/// whitebox read — `snapshot.best_tip.height` (W11 in the issue #1044
/// audit) — asserting the indexer tip matched the validator tip after
/// ~150 blocks were produced in a burst. That property is about the sync
/// loop absorbing many new source blocks between iterations, not about
/// chain-cache shape, so it belongs next to the other sync-loop tests
/// and inside the crate where the snapshot's fields are reachable.
///
/// `sync_blocks_after_startup` covers the one-block-at-a-time trickle.
/// This test covers the distinct case where multiple blocks appear on
/// the source before the next sync iteration runs. Porting to
/// `MockchainSource` (which implements `BlockchainReader`) keeps the
/// indexer's production sync code in the loop while removing the podman
/// / live-validator fixture dependency the original test required.
#[tokio::test(flavor = "multi_thread")]
async fn tip_converges_after_burst_mine() {
    let (_blocks, _indexer, index_reader, mockchain) =
        load_test_vectors_and_sync_chain_index(MockchainMode::Active).await;

    let initial_tip = mockchain.active_height();
    mockchain.mine_blocks(20);
    let expected_tip = mockchain.active_height();
    assert!(
        expected_tip > initial_tip,
        "mockchain did not advance: burst mine was a no-op \
         (initial_tip={initial_tip}, max_chain_height={})",
        mockchain.max_chain_height(),
    );

    super::poll::poll_until(
        "indexer tip to match mined mockchain tip",
        Duration::from_secs(10),
        Duration::from_millis(25),
        || async {
            let tip = index_reader
                .snapshot_nonfinalized_state()
                .await
                .ok()?
                .get_nfs_snapshot()?
                .best_tip
                .height
                .0;
            (tip == expected_tip).then_some(())
        },
    )
    .await;

    let indexer_tip = index_reader
        .snapshot_nonfinalized_state()
        .await
        .unwrap()
        .get_nfs_snapshot()
        .unwrap()
        .best_tip
        .height
        .0;
    assert_eq!(indexer_tip, expected_tip);
}

// Multi-thread required: the persistent-v1 fixture uses block_in_place while its sync worker runs.
#[tokio::test(flavor = "multi_thread")]
async fn no_op_poll_preserves_snapshot_identity_until_chain_advances() {
    let (_blocks, _indexer, index_reader, mockchain) =
        load_test_vectors_and_sync_chain_index(MockchainMode::Active).await;

    let initial = match index_reader.snapshot_nonfinalized_state().await.unwrap() {
        ChainIndexSnapshot::NonFinalizedStateExists {
            non_finalized_snapshot,
        } => non_finalized_snapshot,
        ChainIndexSnapshot::StillSyncingFinalizedState { .. } => {
            panic!("harness must publish non-finalized state")
        }
    };

    // Exercise multiple production polling intervals before checking that an
    // unchanged poll did not replace the captured snapshot.
    sleep(SyncTimings::default().interval * 3).await;
    super::poll::poll_until(
        "chain index to return to Ready after an unchanged poll",
        Duration::from_secs(5),
        Duration::from_millis(10),
        || async { (index_reader.status() == StatusType::Ready).then_some(()) },
    )
    .await;

    let unchanged = match index_reader.snapshot_nonfinalized_state().await.unwrap() {
        ChainIndexSnapshot::NonFinalizedStateExists {
            non_finalized_snapshot,
        } => non_finalized_snapshot,
        ChainIndexSnapshot::StillSyncingFinalizedState { .. } => {
            panic!("unchanged poll must retain non-finalized state")
        }
    };
    assert!(
        Arc::ptr_eq(&initial, &unchanged),
        "an unchanged production poll must preserve the serving snapshot identity"
    );

    mockchain.mine_blocks(1);
    super::poll::poll_until(
        "chain advance to publish a distinct snapshot",
        Duration::from_secs(10),
        Duration::from_millis(25),
        || async {
            let snapshot = index_reader.snapshot_nonfinalized_state().await.ok()?;
            match snapshot {
                ChainIndexSnapshot::NonFinalizedStateExists {
                    non_finalized_snapshot,
                } => (!Arc::ptr_eq(&initial, &non_finalized_snapshot)).then_some(()),
                ChainIndexSnapshot::StillSyncingFinalizedState { .. } => None,
            }
        },
    )
    .await;
}
