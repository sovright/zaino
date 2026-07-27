//! Exact finalised-database schema-version admission tests.

use std::{
    error::Error,
    fs,
    path::{Path, PathBuf},
    time::Duration,
};

use lmdb::{DatabaseFlags, Environment, EnvironmentFlags, Transaction as _, WriteFlags};
use tempfile::TempDir;
use zaino_common::{network::ActivationHeights, DatabaseConfig, StorageConfig};

use crate::{
    chain_index::{
        finalised_state::{
            capability::{DbMetadata, DbVersion, MigrationStatus},
            entry::StoredEntryFixed,
            finalised_source::v1::{
                canonical_schema_hash_for_test, DB_SCHEMA_V1_HASH, DB_VERSION_V1,
            },
            verify_schema_admission_released, FinalisedState,
        },
        tests::vectors::{build_active_mockchain_source, load_test_vectors, TestVectorData},
    },
    ChainIndexConfig, Height, StatusType, ZainoVersionedSerde as _,
};

const UNKNOWN_OLDER_VERSION: DbVersion = DbVersion {
    major: 1,
    minor: 2,
    patch: 2,
};

const HISTORICAL_V1_0_0: DbVersion = DbVersion {
    major: 1,
    minor: 0,
    patch: 0,
};

const FUTURE_VERSION: DbVersion = DbVersion {
    major: 1,
    minor: 4,
    patch: 0,
};

fn historical_v1_0_0_schema_hash() -> Result<[u8; 32], Box<dyn Error>> {
    Ok(
        canonical_schema_hash_for_test(HISTORICAL_V1_0_0).ok_or_else(|| {
            std::io::Error::other("v1.0.0 must have a canonical supported schema hash")
        })?,
    )
}

fn database_config(database_path: PathBuf) -> ChainIndexConfig {
    ChainIndexConfig {
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
    }
}

fn v1_database_path(config: &ChainIndexConfig) -> PathBuf {
    config.storage.database.path.join("regtest").join("v1")
}

fn write_minimal_metadata_fixture(
    config: &ChainIndexConfig,
    version: DbVersion,
) -> Result<PathBuf, Box<dyn Error>> {
    write_minimal_metadata_fixture_with_hash_and_status(
        config,
        version,
        DB_SCHEMA_V1_HASH,
        MigrationStatus::Empty,
    )
}

fn write_minimal_metadata_fixture_with_hash_and_status(
    config: &ChainIndexConfig,
    version: DbVersion,
    schema_hash: [u8; 32],
    migration_status: MigrationStatus,
) -> Result<PathBuf, Box<dyn Error>> {
    let database_path = v1_database_path(config);
    fs::create_dir_all(&database_path)?;

    let env = Environment::new().set_max_dbs(16).open(&database_path)?;
    let metadata = env.create_db(Some("metadata"), DatabaseFlags::empty())?;
    let stored = StoredEntryFixed::new(
        b"metadata",
        DbMetadata::new(version, schema_hash, migration_status),
    );
    let raw_metadata = stored.to_bytes()?;
    let mut txn = env.begin_rw_txn()?;
    txn.put(
        metadata,
        b"metadata",
        &raw_metadata,
        WriteFlags::NO_OVERWRITE,
    )?;
    txn.commit()?;
    drop(env);

    Ok(database_path)
}

fn open_read_only(database_path: &Path) -> Result<Environment, lmdb::Error> {
    Environment::new()
        .set_max_dbs(16)
        .set_flags(EnvironmentFlags::READ_ONLY | EnvironmentFlags::NO_TLS)
        .open(database_path)
}

fn assert_current_tables_absent(env: &Environment) -> Result<(), Box<dyn Error>> {
    for table_name in [
        "headers_1_0_0",
        "ironwood_1_3_0",
        "commitment_tree_data_1_3_0",
    ] {
        if !matches!(env.open_db(Some(table_name)), Err(lmdb::Error::NotFound)) {
            return Err(std::io::Error::other(format!(
                "rejected startup created table {table_name}"
            ))
            .into());
        }
    }

    Ok(())
}

fn read_metadata_without_current_tables(database_path: &Path) -> Result<Vec<u8>, Box<dyn Error>> {
    let env = open_read_only(database_path)?;
    assert_current_tables_absent(&env)?;

    let metadata = env.open_db(Some("metadata"))?;
    let txn = env.begin_ro_txn()?;
    Ok(txn.get(metadata, b"metadata")?.to_vec())
}

async fn reject_minimal_metadata_fixture_without_schema_changes(
    version: DbVersion,
    schema_hash: [u8; 32],
    migration_status: MigrationStatus,
    unexpected_open: &str,
) -> Result<String, Box<dyn Error>> {
    let TestVectorData { blocks, .. } = load_test_vectors()?;
    let temporary_directory = TempDir::new()?;
    let config = database_config(temporary_directory.path().to_path_buf());
    let database_path = write_minimal_metadata_fixture_with_hash_and_status(
        &config,
        version,
        schema_hash,
        migration_status,
    )?;
    let before = read_metadata_without_current_tables(&database_path)?;
    let source = build_active_mockchain_source(150, blocks);

    let error = match FinalisedState::spawn(config, source).await {
        Ok(opened) => {
            opened.shutdown().await?;
            return Err(std::io::Error::other(unexpected_open).into());
        }
        Err(error) => error,
    };
    let after = read_metadata_without_current_tables(&database_path)?;
    assert_eq!(after, before, "startup must not rewrite rejected metadata");

    Ok(error.to_string())
}

async fn assert_unsupported_existing_schema_version(
    version: DbVersion,
    expected_error: &str,
) -> Result<(), Box<dyn Error>> {
    let error = reject_minimal_metadata_fixture_without_schema_changes(
        version,
        DB_SCHEMA_V1_HASH,
        MigrationStatus::Empty,
        &format!("unsupported database version {version} unexpectedly opened"),
    )
    .await?;
    assert!(
        error.contains(expected_error),
        "unexpected rejection for {version}: {error}"
    );
    Ok(())
}

// multi_thread required: the production V1 opener uses `block_in_place` for LMDB access.
#[tokio::test(flavor = "multi_thread")]
async fn unknown_older_schema_version_is_rejected_without_schema_changes(
) -> Result<(), Box<dyn Error>> {
    assert_unsupported_existing_schema_version(
        UNKNOWN_OLDER_VERSION,
        "unsupported database schema version",
    )
    .await
}

// multi_thread required: the production V1 opener uses `block_in_place` for LMDB access.
#[tokio::test(flavor = "multi_thread")]
async fn future_schema_version_is_rejected_without_schema_changes() -> Result<(), Box<dyn Error>> {
    assert_unsupported_existing_schema_version(FUTURE_VERSION, "newer than compiled version").await
}

// multi_thread required: the production V1 opener uses `block_in_place` for LMDB access.
#[cfg(not(feature = "transparent_address_history_experimental"))]
#[tokio::test(flavor = "multi_thread")]
async fn historical_schema_hash_mismatch_is_rejected_without_schema_changes(
) -> Result<(), Box<dyn Error>> {
    let wrong_hash = [0xa5; 32];
    assert_ne!(wrong_hash, historical_v1_0_0_schema_hash()?);
    let error = reject_minimal_metadata_fixture_without_schema_changes(
        HISTORICAL_V1_0_0,
        wrong_hash,
        MigrationStatus::Empty,
        "supported historical version with the wrong schema hash unexpectedly opened",
    )
    .await?;

    assert!(
        error.contains("database schema hash mismatch for supported version"),
        "unexpected historical-hash rejection: {error}"
    );
    Ok(())
}

// multi_thread required: the production V1 opener uses `block_in_place` for LMDB access.
#[cfg(not(feature = "transparent_address_history_experimental"))]
#[tokio::test(flavor = "multi_thread")]
async fn historical_schema_missing_required_table_is_rejected_without_schema_changes(
) -> Result<(), Box<dyn Error>> {
    let error = reject_minimal_metadata_fixture_without_schema_changes(
        HISTORICAL_V1_0_0,
        historical_v1_0_0_schema_hash()?,
        MigrationStatus::Empty,
        "supported historical version with missing required tables unexpectedly opened",
    )
    .await?;

    assert!(
        error.contains("1.0.0 database is missing required table"),
        "unexpected historical-table rejection: {error}"
    );
    Ok(())
}

// multi_thread required: the production V1 opener uses `block_in_place` for LMDB access.
#[cfg(feature = "transparent_address_history_experimental")]
#[tokio::test(flavor = "multi_thread")]
async fn historical_schema_is_rejected_when_address_history_is_enabled_without_schema_changes(
) -> Result<(), Box<dyn Error>> {
    let error = reject_minimal_metadata_fixture_without_schema_changes(
        HISTORICAL_V1_0_0,
        historical_v1_0_0_schema_hash()?,
        MigrationStatus::Empty,
        "historical schema unexpectedly opened with transparent address history enabled",
    )
    .await?;

    assert!(
        error.contains(
            "historical database migration is unsupported when transparent address history is enabled"
        ),
        "unexpected address-history migration rejection: {error}"
    );
    Ok(())
}

// multi_thread required: the production V1 opener uses `block_in_place` for LMDB access.
#[tokio::test(flavor = "multi_thread")]
async fn current_schema_hash_mismatch_is_rejected_without_schema_changes(
) -> Result<(), Box<dyn Error>> {
    let error = reject_minimal_metadata_fixture_without_schema_changes(
        DB_VERSION_V1,
        [0xa5; 32],
        MigrationStatus::Empty,
        "current version with the wrong schema hash unexpectedly opened",
    )
    .await?;
    assert!(
        error.contains("database schema hash mismatch for current version"),
        "unexpected current-hash rejection: {error}"
    );
    Ok(())
}

// multi_thread required: the production V1 opener uses `block_in_place` for LMDB access.
#[tokio::test(flavor = "multi_thread")]
async fn current_schema_non_empty_migration_status_is_rejected_without_schema_changes(
) -> Result<(), Box<dyn Error>> {
    let error = reject_minimal_metadata_fixture_without_schema_changes(
        DB_VERSION_V1,
        DB_SCHEMA_V1_HASH,
        MigrationStatus::FinalBuildInProgress,
        "current schema with a non-empty migration status unexpectedly opened",
    )
    .await?;

    assert!(
        error.contains("current database schema version")
            && error.contains("has non-empty migration status"),
        "unexpected current migration-status rejection: {error}"
    );
    Ok(())
}

// multi_thread required: the production V1 opener uses `block_in_place` for LMDB access.
#[tokio::test(flavor = "multi_thread")]
async fn current_schema_missing_required_table_is_rejected_without_schema_changes(
) -> Result<(), Box<dyn Error>> {
    let error = reject_minimal_metadata_fixture_without_schema_changes(
        DB_VERSION_V1,
        DB_SCHEMA_V1_HASH,
        MigrationStatus::Empty,
        "current version with missing required tables unexpectedly opened",
    )
    .await?;
    assert!(
        error.contains("current v1 database is missing required table"),
        "unexpected missing-table rejection: {error}"
    );
    Ok(())
}

// multi_thread required: the production V1 opener uses `block_in_place` for LMDB access.
#[tokio::test(flavor = "multi_thread")]
async fn rejected_startup_releases_schema_admission_lock() -> Result<(), Box<dyn Error>> {
    let TestVectorData { blocks, .. } = load_test_vectors()?;
    let temporary_directory = TempDir::new()?;
    let config = database_config(temporary_directory.path().to_path_buf());
    write_minimal_metadata_fixture(&config, UNKNOWN_OLDER_VERSION)?;
    let source = build_active_mockchain_source(150, blocks);

    let rejected = tokio::time::timeout(
        Duration::from_secs(2),
        FinalisedState::spawn(config.clone(), source),
    )
    .await?;
    assert!(
        rejected.is_err(),
        "unsupported metadata unexpectedly opened"
    );

    tokio::time::timeout(
        Duration::from_secs(2),
        verify_schema_admission_released(&config),
    )
    .await??;
    Ok(())
}

async fn assert_incomplete_metadata_fails_closed(
    create_metadata_table: bool,
    expected_error: &str,
) -> Result<(), Box<dyn Error>> {
    let TestVectorData { blocks, .. } = load_test_vectors()?;
    let temporary_directory = TempDir::new()?;
    let config = database_config(temporary_directory.path().to_path_buf());
    let database_path = v1_database_path(&config);
    fs::create_dir_all(&database_path)?;
    let env = Environment::new().set_max_dbs(16).open(&database_path)?;
    if create_metadata_table {
        env.create_db(Some("metadata"), DatabaseFlags::empty())?;
    }
    drop(env);
    let source = build_active_mockchain_source(150, blocks);

    let error = match FinalisedState::spawn(config, source).await {
        Ok(opened) => {
            opened.shutdown().await?;
            return Err(std::io::Error::other(
                "existing database with incomplete metadata unexpectedly opened",
            )
            .into());
        }
        Err(error) => error,
    };
    assert!(
        error.to_string().contains(expected_error),
        "unexpected missing-metadata rejection: {error}"
    );

    let env = open_read_only(&database_path)?;
    assert_current_tables_absent(&env)?;
    if create_metadata_table {
        let metadata = env.open_db(Some("metadata"))?;
        let txn = env.begin_ro_txn()?;
        assert!(matches!(
            txn.get(metadata, b"metadata"),
            Err(lmdb::Error::NotFound)
        ));
    } else {
        assert!(matches!(
            env.open_db(Some("metadata")),
            Err(lmdb::Error::NotFound)
        ));
    }
    Ok(())
}

// multi_thread required: the production V1 opener uses `block_in_place` for LMDB access.
#[tokio::test(flavor = "multi_thread")]
async fn existing_database_without_metadata_table_fails_closed() -> Result<(), Box<dyn Error>> {
    assert_incomplete_metadata_fails_closed(false, "missing the metadata table").await
}

// multi_thread required: the production V1 opener uses `block_in_place` for LMDB access.
#[tokio::test(flavor = "multi_thread")]
async fn existing_database_without_metadata_singleton_fails_closed() -> Result<(), Box<dyn Error>> {
    assert_incomplete_metadata_fails_closed(true, "missing the metadata singleton").await
}

// multi_thread required: the production V1 opener and validator perform blocking LMDB work.
#[tokio::test(flavor = "multi_thread")]
async fn critical_state_rejects_persistent_mutation() -> Result<(), Box<dyn Error>> {
    let TestVectorData { blocks, .. } = load_test_vectors()?;
    let temporary_directory = TempDir::new()?;
    let config = database_config(temporary_directory.path().to_path_buf());
    let source = build_active_mockchain_source(150, blocks);
    let state = FinalisedState::spawn(config, source.clone()).await?;
    state.wait_until_ready().await;
    state
        .router()
        .store_primary_status(StatusType::CriticalError);

    let error = state
        .sync_to_height(Height(1), &source)
        .await
        .expect_err("critical state must reject persistent writes");
    assert!(
        error.to_string().contains("refusing to mutate"),
        "unexpected critical-state rejection: {error}"
    );
    let delete_error = state
        .delete_block_at_height(Height(0))
        .await
        .expect_err("critical state must reject direct deletion");
    assert!(
        delete_error.to_string().contains("refusing to mutate"),
        "unexpected critical-state deletion rejection: {delete_error}"
    );
    let read_error = state
        .db_height()
        .await
        .expect_err("critical state must close persistent read routing");
    assert!(
        read_error.to_string().contains("routing is closed"),
        "unexpected critical-state read rejection: {read_error}"
    );

    state.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn migration_target_helper_rejects_unsupported_exact_versions() -> Result<(), Box<dyn Error>>
{
    let TestVectorData { blocks, .. } = load_test_vectors()?;
    let temporary_directory = TempDir::new()?;
    let config = database_config(temporary_directory.path().to_path_buf());
    let source = build_active_mockchain_source(150, blocks);

    for version in [UNKNOWN_OLDER_VERSION, FUTURE_VERSION] {
        let error = match FinalisedState::spawn_with_target_version(
            config.clone(),
            source.clone(),
            version,
        )
        .await
        {
            Ok(opened) => {
                opened.shutdown().await?;
                return Err(std::io::Error::other(format!(
                    "unsupported migration target {version} unexpectedly opened"
                ))
                .into());
            }
            Err(error) => error,
        };
        assert!(
            error.to_string().contains("unsupported database version"),
            "unexpected target rejection for {version}: {error}"
        );
    }

    Ok(())
}
