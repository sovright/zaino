//! Atomic, self-validating artifacts for one fixed mainnet corpus capture.

use std::{
    collections::BTreeSet,
    error::Error,
    ffi::OsString,
    fmt, fs,
    fs::{File, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use blake2::{Blake2s256, Digest};
#[cfg(any(target_vendor = "apple", target_os = "linux"))]
use rustix::fs::{renameat_with, RenameFlags, CWD};
use serde::{Deserialize, Serialize};
use zaino_oram::{MainnetCorpusError, MainnetCorpusMeasurement};

const MEASUREMENT_SCHEMA: &str = "zaino-oram-mainnet-measurement-v1";
const PROVENANCE_SCHEMA: &str = "zaino-oram-capture-provenance-v1";
const MEASUREMENT_JSON: &str = "measurement.json";
const MEASUREMENT_TEXT: &str = "measurement.txt";
const PROVENANCE_JSON: &str = "provenance.json";
const MAX_STAGE_ATTEMPTS: u64 = 128;

static NEXT_STAGE_ID: AtomicU64 = AtomicU64::new(0);

/// Chain-data backend used for the capture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(super) enum BackendKind {
    /// Direct validator backend.
    Direct,
    /// JSON-RPC validator backend.
    Rpc,
}

/// Public snapshot state selected for the capture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(super) enum SnapshotMode {
    /// A non-finalized overlay existed above finalized state.
    NonFinalizedState,
}

/// Public rule that selected the fixed capture checkpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(super) enum SelectionMode {
    /// Capture the snapshot's maximum serviceable height.
    ServiceableTip,
    /// Capture an explicitly supplied public height and hash.
    ExplicitCheckpoint,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MeasurementArtifactV1 {
    schema: String,
    measurement: MainnetCorpusMeasurement,
}

impl MeasurementArtifactV1 {
    fn new(measurement: &MainnetCorpusMeasurement) -> Result<Self, ArtifactError> {
        measurement.validate().map_err(ArtifactError::Measurement)?;
        Ok(Self {
            schema: MEASUREMENT_SCHEMA.to_owned(),
            measurement: measurement.clone(),
        })
    }

    fn validate(&self) -> Result<(), ArtifactError> {
        if self.schema != MEASUREMENT_SCHEMA {
            return Err(ArtifactError::InvalidArtifact {
                reason: "measurement schema mismatch",
            });
        }
        self.measurement
            .validate()
            .map_err(ArtifactError::Measurement)
    }

    fn canonical_bytes(&self) -> Result<Vec<u8>, ArtifactError> {
        serde_json::to_vec(self).map_err(ArtifactError::Json)
    }

    fn digest(&self) -> Result<String, ArtifactError> {
        Ok(blake2s256_hex(&self.canonical_bytes()?))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CaptureProvenanceV1 {
    schema: String,
    backend_kind: BackendKind,
    snapshot_mode: SnapshotMode,
    serviceable_height: u32,
    selection_mode: SelectionMode,
    runner_version: String,
    verified_checkpoint_height: u32,
    verified_checkpoint_hash: String,
    measurement_blake2s256: String,
}

/// Secret-free public provenance stored beside one corpus measurement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct CaptureProvenance {
    inner: CaptureProvenanceV1,
}

impl CaptureProvenance {
    /// Constructs provenance from public capture state and a validated measurement.
    pub(super) fn new(
        backend_kind: BackendKind,
        snapshot_mode: SnapshotMode,
        serviceable_height: u32,
        selection_mode: SelectionMode,
        runner_version: &str,
        measurement: &MainnetCorpusMeasurement,
    ) -> Result<Self, ArtifactError> {
        if runner_version.is_empty() {
            return Err(ArtifactError::InvalidArtifact {
                reason: "runner version is empty",
            });
        }

        let artifact = MeasurementArtifactV1::new(measurement)?;
        let checkpoint = measurement.checkpoint();
        if checkpoint.height() > serviceable_height {
            return Err(ArtifactError::InvalidArtifact {
                reason: "verified checkpoint exceeds the serviceable height",
            });
        }
        if selection_mode == SelectionMode::ServiceableTip
            && checkpoint.height() != serviceable_height
        {
            return Err(ArtifactError::InvalidArtifact {
                reason: "serviceable-tip selection does not match the verified checkpoint",
            });
        }

        Ok(Self {
            inner: CaptureProvenanceV1 {
                schema: PROVENANCE_SCHEMA.to_owned(),
                backend_kind,
                snapshot_mode,
                serviceable_height,
                selection_mode,
                runner_version: runner_version.to_owned(),
                verified_checkpoint_height: checkpoint.height(),
                verified_checkpoint_hash: checkpoint.hash().to_owned(),
                measurement_blake2s256: artifact.digest()?,
            },
        })
    }
}

/// Publishes a complete capture into a new output directory.
///
/// The three files are written and synchronized in a unique sibling directory,
/// read back and semantically revalidated, then renamed into place. The final
/// directory is never overwritten.
pub(super) fn publish_capture(
    output_dir: &Path,
    measurement: &MainnetCorpusMeasurement,
    provenance: &CaptureProvenance,
) -> Result<(), ArtifactError> {
    let artifact = MeasurementArtifactV1::new(measurement)?;
    validate_provenance(&artifact, &provenance.inner)?;

    let files = CaptureFiles {
        measurement_json: serde_json::to_vec_pretty(&artifact).map_err(ArtifactError::Json)?,
        measurement_text: measurement.to_string().into_bytes(),
        provenance_json: serde_json::to_vec_pretty(&provenance.inner)
            .map_err(ArtifactError::Json)?,
    };

    publish_files(output_dir, &files, PublishFailpoint::None, |stage| {
        validate_staged_capture(stage, &artifact, &provenance.inner)
    })
}

struct CaptureFiles {
    measurement_json: Vec<u8>,
    measurement_text: Vec<u8>,
    provenance_json: Vec<u8>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum PublishFailpoint {
    None,
    AfterMeasurementJson,
    BeforePublish,
}

fn publish_files(
    output_dir: &Path,
    files: &CaptureFiles,
    failpoint: PublishFailpoint,
    validate: impl FnOnce(&Path) -> Result<(), ArtifactError>,
) -> Result<(), ArtifactError> {
    ensure_absent(output_dir)?;
    let parent = output_dir.parent().unwrap_or_else(|| Path::new("."));
    let parent = if parent.as_os_str().is_empty() {
        Path::new(".")
    } else {
        parent
    };
    let output_name = output_dir
        .file_name()
        .ok_or(ArtifactError::InvalidOutputPath)?;
    let stage = create_stage_dir(parent, output_name)?;

    let staged = (|| {
        write_synced_file(&stage, MEASUREMENT_JSON, &files.measurement_json)?;
        if failpoint == PublishFailpoint::AfterMeasurementJson {
            return Err(ArtifactError::InjectedFailure);
        }
        write_synced_file(&stage, MEASUREMENT_TEXT, &files.measurement_text)?;
        write_synced_file(&stage, PROVENANCE_JSON, &files.provenance_json)?;
        sync_directory(&stage, "synchronize staged artifact directory")?;
        validate(&stage)?;
        sync_directory(parent, "synchronize staging parent directory")?;
        if failpoint == PublishFailpoint::BeforePublish {
            fs::create_dir(output_dir).map_err(|source| ArtifactError::Io {
                operation: "inject concurrent output directory",
                source,
            })?;
        }
        rename_noreplace(&stage, output_dir)?;
        Ok(())
    })();

    match staged {
        // The no-replace rename is the commit point. No fallible work follows
        // it, so an error never accompanies a visible final artifact.
        Ok(()) => Ok(()),
        Err(primary) => cleanup_stage(stage, primary),
    }
}

#[cfg(any(target_vendor = "apple", target_os = "linux"))]
fn rename_noreplace(stage: &Path, output_dir: &Path) -> Result<(), ArtifactError> {
    match renameat_with(CWD, stage, CWD, output_dir, RenameFlags::NOREPLACE) {
        Ok(()) => Ok(()),
        Err(source) if source == rustix::io::Errno::EXIST => Err(ArtifactError::OutputExists),
        Err(source) => Err(ArtifactError::Io {
            operation: "publish staged artifact directory without replacement",
            source: source.into(),
        }),
    }
}

#[cfg(not(any(target_vendor = "apple", target_os = "linux")))]
fn rename_noreplace(_stage: &Path, _output_dir: &Path) -> Result<(), ArtifactError> {
    Err(ArtifactError::UnsupportedPlatform)
}

fn validate_staged_capture(
    stage: &Path,
    expected_artifact: &MeasurementArtifactV1,
    expected_provenance: &CaptureProvenanceV1,
) -> Result<(), ArtifactError> {
    validate_file_set(stage)?;
    let measurement_json = read_file(stage, MEASUREMENT_JSON)?;
    let measurement_text = read_file(stage, MEASUREMENT_TEXT)?;
    let provenance_json = read_file(stage, PROVENANCE_JSON)?;

    let artifact: MeasurementArtifactV1 =
        serde_json::from_slice(&measurement_json).map_err(ArtifactError::Json)?;
    artifact.validate()?;
    if artifact != *expected_artifact {
        return Err(ArtifactError::InvalidArtifact {
            reason: "measurement read-back differs from the captured measurement",
        });
    }

    let provenance: CaptureProvenanceV1 =
        serde_json::from_slice(&provenance_json).map_err(ArtifactError::Json)?;
    if provenance != *expected_provenance {
        return Err(ArtifactError::InvalidArtifact {
            reason: "provenance read-back differs from the captured provenance",
        });
    }
    validate_provenance(&artifact, &provenance)?;

    if measurement_text != artifact.measurement.to_string().as_bytes() {
        return Err(ArtifactError::InvalidArtifact {
            reason: "measurement text does not match the typed measurement",
        });
    }
    Ok(())
}

fn validate_file_set(stage: &Path) -> Result<(), ArtifactError> {
    let actual = fs::read_dir(stage)
        .map_err(|source| ArtifactError::Io {
            operation: "list staged artifact directory",
            source,
        })?
        .map(|entry| {
            entry
                .map(|entry| entry.file_name())
                .map_err(|source| ArtifactError::Io {
                    operation: "read staged artifact entry",
                    source,
                })
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    let expected = BTreeSet::from([
        OsString::from(MEASUREMENT_JSON),
        OsString::from(MEASUREMENT_TEXT),
        OsString::from(PROVENANCE_JSON),
    ]);
    if actual == expected {
        Ok(())
    } else {
        Err(ArtifactError::InvalidArtifact {
            reason: "artifact directory does not contain exactly the required files",
        })
    }
}

fn validate_provenance(
    artifact: &MeasurementArtifactV1,
    provenance: &CaptureProvenanceV1,
) -> Result<(), ArtifactError> {
    if provenance.schema != PROVENANCE_SCHEMA {
        return Err(ArtifactError::InvalidArtifact {
            reason: "provenance schema mismatch",
        });
    }
    let checkpoint = artifact.measurement.checkpoint();
    if provenance.verified_checkpoint_height != checkpoint.height()
        || provenance.verified_checkpoint_hash != checkpoint.hash()
    {
        return Err(ArtifactError::InvalidArtifact {
            reason: "provenance checkpoint does not match the typed measurement",
        });
    }
    if provenance.measurement_blake2s256 != artifact.digest()? {
        return Err(ArtifactError::InvalidArtifact {
            reason: "measurement digest mismatch",
        });
    }
    if checkpoint.height() > provenance.serviceable_height {
        return Err(ArtifactError::InvalidArtifact {
            reason: "provenance serviceable height precedes the checkpoint",
        });
    }
    if provenance.selection_mode == SelectionMode::ServiceableTip
        && checkpoint.height() != provenance.serviceable_height
    {
        return Err(ArtifactError::InvalidArtifact {
            reason: "provenance serviceable-tip selection is inconsistent",
        });
    }
    Ok(())
}

fn create_stage_dir(
    parent: &Path,
    output_name: &std::ffi::OsStr,
) -> Result<PathBuf, ArtifactError> {
    for _ in 0..MAX_STAGE_ATTEMPTS {
        let id = NEXT_STAGE_ID.fetch_add(1, Ordering::Relaxed);
        let mut stage_name = OsString::from(".");
        stage_name.push(output_name);
        stage_name.push(format!(".stage-{}-{id}", std::process::id()));
        let stage = parent.join(stage_name);
        match fs::create_dir(&stage) {
            Ok(()) => return Ok(stage),
            Err(source) if source.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(source) => {
                return Err(ArtifactError::Io {
                    operation: "create sibling staging directory",
                    source,
                });
            }
        }
    }
    Err(ArtifactError::StageNameExhausted)
}

fn ensure_absent(path: &Path) -> Result<(), ArtifactError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Err(ArtifactError::OutputExists),
        Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(ArtifactError::Io {
            operation: "inspect artifact output directory",
            source,
        }),
    }
}

fn write_synced_file(directory: &Path, name: &str, bytes: &[u8]) -> Result<(), ArtifactError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(directory.join(name))
        .map_err(|source| ArtifactError::Io {
            operation: "create staged artifact file",
            source,
        })?;
    file.write_all(bytes).map_err(|source| ArtifactError::Io {
        operation: "write staged artifact file",
        source,
    })?;
    file.sync_all().map_err(|source| ArtifactError::Io {
        operation: "synchronize staged artifact file",
        source,
    })
}

fn read_file(directory: &Path, name: &str) -> Result<Vec<u8>, ArtifactError> {
    fs::read(directory.join(name)).map_err(|source| ArtifactError::Io {
        operation: "read back staged artifact file",
        source,
    })
}

fn sync_directory(directory: &Path, operation: &'static str) -> Result<(), ArtifactError> {
    let file = File::open(directory).map_err(|source| ArtifactError::Io { operation, source })?;
    file.sync_all()
        .map_err(|source| ArtifactError::Io { operation, source })
}

fn cleanup_stage(stage: PathBuf, primary: ArtifactError) -> Result<(), ArtifactError> {
    match fs::remove_dir_all(stage) {
        Ok(()) => Err(primary),
        Err(cleanup) if cleanup.kind() == io::ErrorKind::NotFound => Err(primary),
        Err(cleanup) => Err(ArtifactError::Cleanup {
            primary: Box::new(primary),
            cleanup,
        }),
    }
}

fn blake2s256_hex(bytes: &[u8]) -> String {
    hex::encode(Blake2s256::digest(bytes))
}

/// Artifact construction or atomic-publication failure.
#[derive(Debug)]
pub(super) enum ArtifactError {
    InvalidOutputPath,
    #[cfg(not(any(target_vendor = "apple", target_os = "linux")))]
    UnsupportedPlatform,
    OutputExists,
    StageNameExhausted,
    InjectedFailure,
    InvalidArtifact {
        reason: &'static str,
    },
    Measurement(MainnetCorpusError),
    Json(serde_json::Error),
    Io {
        operation: &'static str,
        source: io::Error,
    },
    Cleanup {
        primary: Box<Self>,
        cleanup: io::Error,
    },
}

impl fmt::Display for ArtifactError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidOutputPath => f.write_str("artifact output must name a directory"),
            #[cfg(not(any(target_vendor = "apple", target_os = "linux")))]
            Self::UnsupportedPlatform => {
                f.write_str("atomic no-replace artifact publication is unsupported on this host")
            }
            Self::OutputExists => f.write_str("artifact output directory already exists"),
            Self::StageNameExhausted => {
                f.write_str("could not allocate a unique sibling staging directory")
            }
            Self::InjectedFailure => f.write_str("injected artifact publication failure"),
            Self::InvalidArtifact { reason } => write!(f, "artifact validation failed: {reason}"),
            Self::Measurement(error) => write!(f, "measurement validation failed: {error}"),
            Self::Json(error) => write!(f, "artifact JSON failed: {error}"),
            Self::Io { operation, source } => write!(f, "{operation} failed: {source}"),
            Self::Cleanup { primary, cleanup } => write!(
                f,
                "{primary}; sibling staging-directory cleanup also failed: {cleanup}"
            ),
        }
    }
}

impl Error for ArtifactError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Measurement(error) => Some(error),
            Self::Json(error) => Some(error),
            Self::Io { source, .. } => Some(source),
            Self::Cleanup { primary, .. } => Some(primary),
            #[cfg(not(any(target_vendor = "apple", target_os = "linux")))]
            Self::UnsupportedPlatform => None,
            Self::InvalidOutputPath
            | Self::OutputExists
            | Self::StageNameExhausted
            | Self::InjectedFailure
            | Self::InvalidArtifact { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult<T = ()> = Result<T, Box<dyn Error>>;

    fn typed_measurement() -> TestResult<MainnetCorpusMeasurement> {
        let value = serde_json::json!({
            "checkpoint": {
                "network": "mainnet",
                "height": 0,
                "hash": "00040fe8ec8471911baa1db1266ea15dd06b4a8a5c453883c000b031973dce08"
            },
            "aggregate": {
                "blocks": 1,
                "transactions": 0,
                "outputs": 0,
                "spends": 0,
                "distinct_standard_addresses": 0,
                "live_standard_utxos": 0,
                "live_nonstandard_utxos": 0,
                "script_totals": [
                    {"outputs": 0, "spends": 0, "live_utxos": 0},
                    {"outputs": 0, "spends": 0, "live_utxos": 0},
                    {"outputs": 0, "spends": 0, "live_utxos": 0}
                ],
                "events_per_address": [],
                "live_utxos_per_address": [],
                "peak_live_utxos_per_address": [],
                "address_state_histogram": [],
                "event_distribution": {"p50": 0, "p90": 0, "p99": 0, "p999": 0, "maximum": 0},
                "live_distribution": {"p50": 0, "p90": 0, "p99": 0, "p999": 0, "maximum": 0},
                "peak_live_distribution": {"p50": 0, "p90": 0, "p99": 0, "p999": 0, "maximum": 0},
                "hottest_event_counts": [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                "record_sizes": {
                    "address_key_bytes": 32,
                    "business_utxo_bytes": 88,
                    "persistent_utxo_bytes": 88,
                    "persistent_event_bytes": 72,
                    "logical_store_slot_bytes": 96,
                    "directory_cell_bytes": 38,
                    "event_cell_bytes": 82
                }
            }
        });
        Ok(serde_json::from_value(value)?)
    }

    fn test_files() -> CaptureFiles {
        CaptureFiles {
            measurement_json: br#"{"schema":"test","measurement":1}"#.to_vec(),
            measurement_text: b"measurement=1\n".to_vec(),
            provenance_json: br#"{"schema":"test-provenance"}"#.to_vec(),
        }
    }

    fn validate_test_files(stage: &Path, expected: &CaptureFiles) -> Result<(), ArtifactError> {
        for (name, bytes) in [
            (MEASUREMENT_JSON, expected.measurement_json.as_slice()),
            (MEASUREMENT_TEXT, expected.measurement_text.as_slice()),
            (PROVENANCE_JSON, expected.provenance_json.as_slice()),
        ] {
            if read_file(stage, name)? != bytes {
                return Err(ArtifactError::InvalidArtifact {
                    reason: "test read-back mismatch",
                });
            }
        }
        Ok(())
    }

    fn sibling_stages(parent: &Path, output_name: &str) -> Result<Vec<PathBuf>, io::Error> {
        let prefix = format!(".{output_name}.stage-");
        fs::read_dir(parent)?
            .filter_map(|entry| match entry {
                Ok(entry) if entry.file_name().to_string_lossy().starts_with(&prefix) => {
                    Some(Ok(entry.path()))
                }
                Ok(_) => None,
                Err(error) => Some(Err(error)),
            })
            .collect()
    }

    #[test]
    fn publishes_complete_directory_after_successful_read_back() -> TestResult {
        let parent = tempfile::tempdir()?;
        let output = parent.path().join("capture");
        let files = test_files();

        publish_files(&output, &files, PublishFailpoint::None, |stage| {
            validate_test_files(stage, &files)
        })?;

        validate_test_files(&output, &files)?;
        assert!(sibling_stages(parent.path(), "capture")?.is_empty());
        Ok(())
    }

    #[test]
    fn typed_capture_publication_binds_digest_and_secret_free_provenance() -> TestResult {
        let parent = tempfile::tempdir()?;
        let output = parent.path().join("capture");
        let measurement = typed_measurement()?;
        let provenance = CaptureProvenance::new(
            BackendKind::Rpc,
            SnapshotMode::NonFinalizedState,
            0,
            SelectionMode::ServiceableTip,
            "test-runner",
            &measurement,
        )?;

        publish_capture(&output, &measurement, &provenance)?;

        let artifact = MeasurementArtifactV1::new(&measurement)?;
        validate_staged_capture(&output, &artifact, &provenance.inner)?;
        let provenance_text = fs::read_to_string(output.join(PROVENANCE_JSON))?;
        for forbidden in ["endpoint", "path", "cookie", "credential", "config"] {
            assert!(!provenance_text.contains(forbidden));
        }
        assert!(provenance_text.contains("measurement_blake2s256"));
        Ok(())
    }

    #[test]
    fn typed_validation_rejects_digest_schema_and_file_set_tampering() -> TestResult {
        let parent = tempfile::tempdir()?;
        let output = parent.path().join("capture");
        let measurement = typed_measurement()?;
        let provenance = CaptureProvenance::new(
            BackendKind::Direct,
            SnapshotMode::NonFinalizedState,
            0,
            SelectionMode::ServiceableTip,
            "test-runner",
            &measurement,
        )?;
        let artifact = MeasurementArtifactV1::new(&measurement)?;

        let mut wrong_digest = provenance.inner.clone();
        wrong_digest.measurement_blake2s256 = "00".repeat(32);
        assert!(matches!(
            validate_provenance(&artifact, &wrong_digest),
            Err(ArtifactError::InvalidArtifact {
                reason: "measurement digest mismatch"
            })
        ));

        let mut wrong_schema = provenance.inner.clone();
        wrong_schema.schema = "unknown".to_owned();
        assert!(matches!(
            validate_provenance(&artifact, &wrong_schema),
            Err(ArtifactError::InvalidArtifact {
                reason: "provenance schema mismatch"
            })
        ));

        publish_capture(&output, &measurement, &provenance)?;
        fs::write(output.join("unexpected"), b"extra")?;
        assert!(matches!(
            validate_staged_capture(&output, &artifact, &provenance.inner),
            Err(ArtifactError::InvalidArtifact {
                reason: "artifact directory does not contain exactly the required files"
            })
        ));
        Ok(())
    }

    #[test]
    fn existing_output_is_never_replaced() -> TestResult {
        let parent = tempfile::tempdir()?;
        let output = parent.path().join("capture");
        fs::create_dir(&output)?;
        fs::write(output.join("owner"), b"existing")?;
        let files = test_files();

        let result = publish_files(&output, &files, PublishFailpoint::None, |stage| {
            validate_test_files(stage, &files)
        });

        assert!(matches!(result, Err(ArtifactError::OutputExists)));
        assert_eq!(fs::read(output.join("owner"))?, b"existing");
        assert!(sibling_stages(parent.path(), "capture")?.is_empty());
        Ok(())
    }

    #[test]
    fn output_created_at_commit_is_not_replaced() -> TestResult {
        let parent = tempfile::tempdir()?;
        let output = parent.path().join("capture");
        let files = test_files();

        let result = publish_files(&output, &files, PublishFailpoint::BeforePublish, |stage| {
            validate_test_files(stage, &files)
        });

        assert!(matches!(result, Err(ArtifactError::OutputExists)));
        assert!(output.is_dir());
        assert_eq!(fs::read_dir(&output)?.count(), 0);
        assert!(sibling_stages(parent.path(), "capture")?.is_empty());
        Ok(())
    }

    #[test]
    fn injected_failure_cleans_owned_stage() -> TestResult {
        let parent = tempfile::tempdir()?;
        let output = parent.path().join("capture");
        let files = test_files();

        let result = publish_files(
            &output,
            &files,
            PublishFailpoint::AfterMeasurementJson,
            |stage| validate_test_files(stage, &files),
        );

        assert!(matches!(result, Err(ArtifactError::InjectedFailure)));
        assert!(!output.exists());
        assert!(sibling_stages(parent.path(), "capture")?.is_empty());
        Ok(())
    }

    #[test]
    fn read_back_helper_rejects_tampering() -> TestResult {
        let parent = tempfile::tempdir()?;
        let files = test_files();
        write_synced_file(parent.path(), MEASUREMENT_JSON, &files.measurement_json)?;
        write_synced_file(parent.path(), MEASUREMENT_TEXT, b"tampered\n")?;
        write_synced_file(parent.path(), PROVENANCE_JSON, &files.provenance_json)?;

        assert!(matches!(
            validate_test_files(parent.path(), &files),
            Err(ArtifactError::InvalidArtifact {
                reason: "test read-back mismatch"
            })
        ));
        Ok(())
    }
}
