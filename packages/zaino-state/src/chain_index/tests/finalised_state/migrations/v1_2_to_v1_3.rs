//! V1.2.1 to V1.3.0 migration tests.
//!
//! Coverage note: these tests use `ActivationHeights::default()`, whose NU6.3 activation is `None`,
//! so the migration takes the below-activation branch (rebuild each commitment row in place from the
//! legacy fixed-length table, no ironwood). The at/above-activation *ironwood backfill* branch —
//! which refetches block data from the validator — cannot be exercised yet: `MockchainSource`
//! serves no ironwood commitment roots (see its `get_commitment_tree_roots` TODO) and the test
//! vectors carry no ironwood actions, so building a post-NU6.3 block would fail resolving the
//! (required) ironwood root. That path needs ironwood-capable test vectors before it can be tested.

use std::{error::Error, fs, path::PathBuf, sync::Arc, time::Duration};
use tempfile::TempDir;
use zaino_common::network::ActivationHeights;
use zaino_common::{DatabaseConfig, StorageConfig};

use crate::chain_index::finalised_state::capability::{DbVersion, MigrationStatus};
use crate::chain_index::finalised_state::finalised_source::v1::{
    canonical_schema_hash_for_test, DB_VERSION_V1,
};
use crate::chain_index::finalised_state::{
    pause_schema_migration, verify_schema_admission_held, verify_schema_admission_released,
    FinalisedState,
};
use crate::chain_index::source::mockchain_source::MockchainSource;
use crate::chain_index::tests::init_tracing;
use crate::chain_index::tests::vectors::{
    build_active_mockchain_source, load_test_vectors, TestVectorData,
};
use crate::{ChainIndexConfig, Height, StatusType};

fn v1_2_1() -> DbVersion {
    DbVersion {
        major: 1,
        minor: 2,
        patch: 1,
    }
}

fn expected_schema_hash(version: DbVersion) -> [u8; 32] {
    canonical_schema_hash_for_test(version)
        .expect("every migration fixture version must have a canonical schema hash")
}

async fn build_v1_2_1_fixture(
) -> Result<(TempDir, ChainIndexConfig, MockchainSource), Box<dyn Error>> {
    let TestVectorData { blocks, .. } = load_test_vectors()?;
    let temporary_directory = tempfile::tempdir()?;
    let database_path: PathBuf = temporary_directory.path().to_path_buf();

    let database_config = ChainIndexConfig {
        storage: StorageConfig {
            database: DatabaseConfig {
                path: database_path,
                ..Default::default()
            },
            ..Default::default()
        },
        ephemeral: false,
        db_version: 1,
        network: ActivationHeights::default().to_regtest_network(),
    };

    let source = build_active_mockchain_source(150, blocks);
    let old_database =
        FinalisedState::build_db_to_version(database_config.clone(), source.clone(), v1_2_1())
            .await?;
    old_database.wait_until_synced().await;
    let old_metadata = old_database.get_metadata().await?;
    assert_eq!(old_metadata.version, v1_2_1());
    assert_eq!(old_metadata.schema_hash, expected_schema_hash(v1_2_1()));
    old_database.shutdown().await?;
    drop(old_database);

    Ok((temporary_directory, database_config, source))
}

/// Regression test for the startup ordering bug: opening a pre-1.3.0 cache used to start the
/// background validator concurrently with the v1.2.1 → v1.3.0 migration. The validator's
/// `initial_block_scan` read the freshly-created-empty `commitment_tree_data_1_3_0` table before the
/// migration rebuilt it, failing with `MDB_NOTFOUND` ("block scan") and latching `CriticalError`.
///
/// The fix defers the validator until every migration finishes. This test builds an on-disk v1.2.1
/// database, then reopens it through the production `FinalisedState::spawn` path (which migrates to
/// the current schema and only then starts the validator) and asserts it reaches `Ready` — i.e. the
/// migration completed *before* validation, and validation then passed.
// multi_thread required: the background validator runs blocking LMDB validation
// (`validate_block_blocking`) inline on its task, which would starve this test's status polling on
// a current-thread runtime.
#[tokio::test(flavor = "multi_thread")]
async fn v1_2_1_cache_migrates_to_current_then_validates() -> Result<(), Box<dyn Error>> {
    init_tracing();

    let (_temporary_directory, database_config, source) = build_v1_2_1_fixture().await?;
    let active_height = Height(150);

    // Reopen through the production spawn path: it runs the v1.2.1 → v1.3.0 migration and only then
    // starts the validator. Before the ordering fix this raced the migration and latched
    // `CriticalError`; now it must migrate first and validate cleanly.
    let migrated_database = FinalisedState::spawn(database_config.clone(), source.clone()).await?;
    migrated_database.wait_until_synced().await;

    assert_eq!(
        migrated_database.status(),
        StatusType::Ready,
        "the validator must run only after the migration completes, and then reach Ready"
    );

    let migrated_metadata = migrated_database.get_metadata().await?;
    assert_eq!(migrated_metadata.version, DB_VERSION_V1);
    assert_eq!(migrated_metadata.migration_status, MigrationStatus::Empty);
    assert_eq!(
        migrated_metadata.schema_hash,
        expected_schema_hash(DB_VERSION_V1)
    );

    let migrated_height = migrated_database
        .db_height()
        .await?
        .ok_or_else(|| std::io::Error::other("migrated database has no height"))?;
    assert_eq!(migrated_height, active_height);

    migrated_database.shutdown().await?;
    Ok(())
}

// multi_thread required: the background migration and validator perform blocking LMDB work while
// this test polls their lifecycle.
#[tokio::test(flavor = "multi_thread")]
async fn data_only_v1_2_1_restore_is_discovered_and_migrated() -> Result<(), Box<dyn Error>> {
    init_tracing();

    let (_temporary_directory, database_config, source) = build_v1_2_1_fixture().await?;
    let lock_path = database_config
        .storage
        .database
        .path
        .join("regtest")
        .join("v1")
        .join("lock.mdb");
    fs::remove_file(&lock_path)?;
    assert!(
        !lock_path.exists(),
        "test fixture must omit disposable lock.mdb"
    );

    let migrated_database = FinalisedState::spawn(database_config, source).await?;
    migrated_database.wait_until_synced().await;

    assert_eq!(migrated_database.status(), StatusType::Ready);
    assert_eq!(
        migrated_database.get_metadata().await?.version,
        DB_VERSION_V1
    );

    migrated_database.shutdown().await?;
    Ok(())
}

// multi_thread required: this test exercises concurrent production startup and migration while
// the V1 opener uses `block_in_place` for LMDB access.
#[tokio::test(flavor = "multi_thread")]
async fn concurrent_spawns_serialize_one_v1_2_1_migration() -> Result<(), Box<dyn Error>> {
    init_tracing();

    let (_temporary_directory, database_config, source) = build_v1_2_1_fixture().await?;
    let migration_pause = pause_schema_migration(&database_config);
    let first = FinalisedState::spawn(database_config.clone(), source.clone()).await?;
    tokio::time::timeout(
        Duration::from_secs(2),
        migration_pause.wait_until_migration_entered(),
    )
    .await?;
    verify_schema_admission_held(&database_config)?;

    let second_config = database_config.clone();
    let second_source = source.clone();
    let second_spawn =
        tokio::spawn(async move { FinalisedState::spawn(second_config, second_source).await });
    tokio::time::timeout(
        Duration::from_secs(2),
        migration_pause.wait_until_admission_contended(),
    )
    .await?;
    assert!(
        !second_spawn.is_finished(),
        "a second spawn that reached admission must wait for the paused schema migration"
    );

    migration_pause.release();
    first.wait_until_synced().await;
    assert_eq!(first.get_metadata().await?.version, DB_VERSION_V1);
    assert_eq!(first.status(), StatusType::Ready);
    assert!(
        !second_spawn.is_finished(),
        "the second process must remain excluded after migration completes"
    );
    verify_schema_admission_held(&database_config)?;

    first.shutdown().await?;
    assert!(
        !second_spawn.is_finished(),
        "shutdown alone must not release the process-lifetime lease while the router is reachable"
    );
    drop(first);

    let second = tokio::time::timeout(Duration::from_secs(10), second_spawn).await???;
    second.wait_until_ready().await;
    assert_eq!(second.get_metadata().await?.version, DB_VERSION_V1);
    assert_eq!(second.status(), StatusType::Ready);

    second.shutdown().await?;
    drop(second);
    verify_schema_admission_released(&database_config).await?;
    Ok(())
}

// multi_thread required: the migration runs in a background task and uses blocking LMDB work while
// this test injects and observes a panic at its async startup boundary.
#[tokio::test(flavor = "multi_thread")]
async fn migration_panic_closes_routing_and_retains_admission() -> Result<(), Box<dyn Error>> {
    init_tracing();

    let (_temporary_directory, database_config, source) = build_v1_2_1_fixture().await?;
    let migration_pause = pause_schema_migration(&database_config);
    let state = FinalisedState::spawn(database_config.clone(), source).await?;
    tokio::time::timeout(
        Duration::from_secs(2),
        migration_pause.wait_until_migration_entered(),
    )
    .await?;

    migration_pause.panic_on_release();
    migration_pause.release();
    tokio::time::timeout(Duration::from_secs(2), state.wait_until_synced()).await?;

    assert_eq!(state.status(), StatusType::CriticalError);
    verify_schema_admission_held(&database_config)?;
    let read_error = state
        .db_height()
        .await
        .expect_err("routing must remain closed after a migration panic");
    assert!(
        read_error.to_string().contains("routing is closed"),
        "unexpected post-panic read rejection: {read_error}"
    );

    state.shutdown().await?;
    let post_shutdown_read_error = state
        .db_height()
        .await
        .expect_err("shutdown must not reopen routing after a migration panic");
    assert!(
        post_shutdown_read_error
            .to_string()
            .contains("routing is closed"),
        "unexpected post-shutdown read rejection: {post_shutdown_read_error}"
    );
    let post_shutdown_write_error = state
        .delete_block_at_height(Height(150))
        .await
        .expect_err("shutdown must not reopen writes after a migration panic");
    assert!(
        post_shutdown_write_error
            .to_string()
            .contains("shutdown has begun"),
        "unexpected post-shutdown write rejection: {post_shutdown_write_error}"
    );
    drop(state);
    verify_schema_admission_released(&database_config).await?;
    Ok(())
}

// multi_thread required: shutdown and the paused migration must make progress concurrently, and
// the migration performs blocking LMDB work after the pause is released.
#[tokio::test(flavor = "multi_thread")]
async fn shutdown_waits_for_migration_and_prevents_validator_restart() -> Result<(), Box<dyn Error>>
{
    init_tracing();

    let (_temporary_directory, database_config, source) = build_v1_2_1_fixture().await?;
    let migration_pause = pause_schema_migration(&database_config);
    let state = Arc::new(FinalisedState::spawn(database_config.clone(), source).await?);
    tokio::time::timeout(
        Duration::from_secs(2),
        migration_pause.wait_until_migration_entered(),
    )
    .await?;

    let shutdown_state = Arc::clone(&state);
    let shutdown_task = tokio::spawn(async move { shutdown_state.shutdown().await });
    tokio::time::timeout(Duration::from_secs(2), async {
        while !state.shutdown_requested() {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    assert!(
        !shutdown_task.is_finished(),
        "shutdown must wait while the owned migration task is paused"
    );

    migration_pause.release();
    tokio::time::timeout(Duration::from_secs(10), shutdown_task).await???;
    assert_ne!(
        state.status(),
        StatusType::Ready,
        "a migration completing during shutdown must not start the validator"
    );

    drop(state);
    verify_schema_admission_released(&database_config).await?;
    Ok(())
}
