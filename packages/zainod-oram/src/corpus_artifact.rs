//! Atomic, self-validating artifacts for offline ORAM research evidence.

use std::{
    collections::BTreeSet,
    error::Error,
    ffi::OsString,
    fmt, fs,
    fs::File,
    io::{self, Read, Write},
    path::Path,
    sync::atomic::{AtomicU64, Ordering},
};
#[cfg(any(target_vendor = "apple", target_os = "linux"))]
use std::{os::fd::OwnedFd, os::unix::ffi::OsStringExt};

use blake2::{Blake2s256, Digest};
#[cfg(any(target_vendor = "apple", target_os = "linux"))]
use rustix::fs::{
    fstat, fsync, mkdirat, open, openat, renameat_with, unlinkat, AtFlags, Dir, Mode, OFlags,
    RenameFlags,
};
use serde::{Deserialize, Serialize};
use zaino_oram::{MainnetCorpusError, MainnetCorpusMeasurement, MainnetSizingQualification};

const MEASUREMENT_SCHEMA: &str = "zaino-oram-mainnet-measurement-v1";
const CAPTURE_PROVENANCE_SCHEMA: &str = "zaino-oram-capture-provenance-v1";
const SIZING_SCHEMA: &str = "zaino-oram-mainnet-sizing-v1";
const SIZING_PROVENANCE_SCHEMA: &str = "zaino-oram-sizing-provenance-v1";
const MEASUREMENT_JSON: &str = "measurement.json";
const MEASUREMENT_TEXT: &str = "measurement.txt";
const PROVENANCE_JSON: &str = "provenance.json";
const QUALIFICATION_JSON: &str = "qualification.json";
const QUALIFICATION_TEXT: &str = "qualification.txt";
const MAX_MEASUREMENT_JSON_BYTES: usize = 256 * 1024 * 1024;
const MAX_MEASUREMENT_TEXT_BYTES: usize = 256 * 1024 * 1024;
const MAX_QUALIFICATION_JSON_BYTES: usize = 4 * 1024 * 1024;
const MAX_QUALIFICATION_TEXT_BYTES: usize = 4 * 1024 * 1024;
const MAX_PROVENANCE_JSON_BYTES: usize = 64 * 1024;
const MAX_STAGE_ATTEMPTS: u64 = 128;

static NEXT_STAGE_ID: AtomicU64 = AtomicU64::new(0);

#[cfg(any(target_vendor = "apple", target_os = "linux"))]
pub(super) struct ArtifactDirectory {
    fd: OwnedFd,
}

#[cfg(not(any(target_vendor = "apple", target_os = "linux")))]
pub(super) struct ArtifactDirectory;

struct ArtifactOutput {
    parent: ArtifactDirectory,
    name: OsString,
}

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
                schema: CAPTURE_PROVENANCE_SCHEMA.to_owned(),
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

/// A semantically validated capture with its canonical typed digest.
pub(super) struct ValidatedCapture {
    directory: ArtifactDirectory,
    measurement: MainnetCorpusMeasurement,
    measurement_blake2s256: String,
}

impl ValidatedCapture {
    /// Returns the validated identifier-free measurement.
    pub(super) const fn measurement(&self) -> &MainnetCorpusMeasurement {
        &self.measurement
    }

    pub(super) fn measurement_blake2s256(&self) -> &str {
        &self.measurement_blake2s256
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SizingArtifactV1 {
    schema: String,
    measurement_blake2s256: String,
    qualification: MainnetSizingQualification,
}

impl SizingArtifactV1 {
    fn new(
        capture: &ValidatedCapture,
        qualification: &MainnetSizingQualification,
    ) -> Result<Self, ArtifactError> {
        qualification
            .validate_against(capture.measurement())
            .map_err(ArtifactError::Qualification)?;
        Ok(Self {
            schema: SIZING_SCHEMA.to_owned(),
            measurement_blake2s256: capture.measurement_blake2s256().to_owned(),
            qualification: qualification.clone(),
        })
    }

    fn validate(&self) -> Result<(), ArtifactError> {
        if self.schema != SIZING_SCHEMA {
            return Err(ArtifactError::InvalidArtifact {
                reason: "sizing schema mismatch",
            });
        }
        self.qualification
            .validate()
            .map_err(ArtifactError::Qualification)
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
struct SizingProvenanceV1 {
    schema: String,
    runner_version: String,
    target_os: String,
    target_arch: String,
    verified_checkpoint_height: u32,
    verified_checkpoint_hash: String,
    measurement_blake2s256: String,
    sizing_model_blake2s256: String,
    qualification_blake2s256: String,
}

impl SizingProvenanceV1 {
    fn new(
        runner_version: &str,
        capture: &ValidatedCapture,
        artifact: &SizingArtifactV1,
    ) -> Result<Self, ArtifactError> {
        if runner_version.is_empty() {
            return Err(ArtifactError::InvalidArtifact {
                reason: "runner version is empty",
            });
        }
        validate_sizing_binding(capture, artifact)?;
        let checkpoint = artifact.qualification.checkpoint();
        let model_bytes =
            serde_json::to_vec(artifact.qualification.model()).map_err(ArtifactError::Json)?;
        Ok(Self {
            schema: SIZING_PROVENANCE_SCHEMA.to_owned(),
            runner_version: runner_version.to_owned(),
            target_os: std::env::consts::OS.to_owned(),
            target_arch: std::env::consts::ARCH.to_owned(),
            verified_checkpoint_height: checkpoint.height(),
            verified_checkpoint_hash: checkpoint.hash().to_owned(),
            measurement_blake2s256: capture.measurement_blake2s256().to_owned(),
            sizing_model_blake2s256: blake2s256_hex(&model_bytes),
            qualification_blake2s256: artifact.digest()?,
        })
    }
}

/// A semantically validated sizing qualification with its canonical typed lineage.
pub(super) struct ValidatedSizing {
    #[cfg(feature = "typed-qualification")]
    directory: ArtifactDirectory,
    qualification: MainnetSizingQualification,
    measurement_blake2s256: String,
    qualification_blake2s256: String,
}

impl ValidatedSizing {
    /// Returns the validated sizing qualification.
    pub(super) const fn qualification(&self) -> &MainnetSizingQualification {
        &self.qualification
    }

    /// Returns the digest of the capture measurement bound to this qualification.
    pub(super) fn measurement_blake2s256(&self) -> &str {
        &self.measurement_blake2s256
    }

    /// Returns the digest of the canonical typed sizing artifact.
    pub(super) fn qualification_blake2s256(&self) -> &str {
        &self.qualification_blake2s256
    }
}

/// Loads and revalidates an exact three-file capture directory.
pub(super) fn load_capture(input_dir: &Path) -> Result<ValidatedCapture, ArtifactError> {
    let source_directory = fs::canonicalize(input_dir).map_err(|source| ArtifactError::Io {
        operation: "canonicalize validated capture directory",
        source,
    })?;
    let directory = open_artifact_directory(&source_directory)?;
    let (artifact, _) = read_validated_capture_directory(&directory)?;
    let measurement_blake2s256 = artifact.digest()?;
    Ok(ValidatedCapture {
        directory,
        measurement: artifact.measurement,
        measurement_blake2s256,
    })
}

/// Loads and revalidates an exact three-file sizing directory against its capture.
pub(super) fn load_sizing(
    input_dir: &Path,
    capture: &ValidatedCapture,
) -> Result<ValidatedSizing, ArtifactError> {
    let source_directory = fs::canonicalize(input_dir).map_err(|source| ArtifactError::Io {
        operation: "canonicalize validated sizing directory",
        source,
    })?;
    let directory = open_artifact_directory(&source_directory)?;
    let (artifact, _) = read_validated_sizing_directory(&directory, capture)?;
    let qualification_blake2s256 = artifact.digest()?;
    Ok(ValidatedSizing {
        #[cfg(feature = "typed-qualification")]
        directory,
        qualification: artifact.qualification,
        measurement_blake2s256: artifact.measurement_blake2s256,
        qualification_blake2s256,
    })
}

/// Revalidates the common capture-to-sizing lineage for derived evidence.
#[cfg(feature = "typed-qualification")]
pub(super) fn validate_derived_source_lineage(
    capture: &ValidatedCapture,
    sizing: &ValidatedSizing,
) -> Result<(), ArtifactError> {
    sizing
        .qualification()
        .validate_against(capture.measurement())
        .map_err(ArtifactError::Qualification)?;
    if sizing.measurement_blake2s256() != capture.measurement_blake2s256() {
        return Err(ArtifactError::InvalidArtifact {
            reason: "derived artifact capture and sizing lineage mismatch",
        });
    }
    Ok(())
}

/// Publishes a complete offline sizing result into a new output directory.
pub(super) fn publish_sizing(
    output_dir: &Path,
    capture: &ValidatedCapture,
    qualification: &MainnetSizingQualification,
    runner_version: &str,
) -> Result<(), ArtifactError> {
    let output_dir = canonical_sizing_output(output_dir, capture)?;
    let artifact = SizingArtifactV1::new(capture, qualification)?;
    let provenance = SizingProvenanceV1::new(runner_version, capture, &artifact)?;
    validate_sizing_provenance(capture, &artifact, &provenance)?;

    let files = [
        ArtifactFile::new(
            QUALIFICATION_JSON,
            serde_json::to_vec_pretty(&artifact).map_err(ArtifactError::Json)?,
        ),
        ArtifactFile::new(QUALIFICATION_TEXT, qualification.to_string().into_bytes()),
        ArtifactFile::new(
            PROVENANCE_JSON,
            serde_json::to_vec_pretty(&provenance).map_err(ArtifactError::Json)?,
        ),
    ];

    publish_verified_output(&output_dir, &files, PublishFailpoint::None, |stage| {
        validate_staged_sizing(stage, capture, &artifact, &provenance)
    })
}

fn canonical_sizing_output(
    output_dir: &Path,
    capture: &ValidatedCapture,
) -> Result<ArtifactOutput, ArtifactError> {
    let output = open_artifact_output(output_dir)?;
    if directory_is_within(&capture.directory, &output.parent)? {
        return Err(ArtifactError::InvalidArtifact {
            reason: "sizing output must not be nested inside its capture input",
        });
    }
    Ok(output)
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

    let files = [
        ArtifactFile::new(
            MEASUREMENT_JSON,
            serde_json::to_vec_pretty(&artifact).map_err(ArtifactError::Json)?,
        ),
        ArtifactFile::new(MEASUREMENT_TEXT, measurement.to_string().into_bytes()),
        ArtifactFile::new(
            PROVENANCE_JSON,
            serde_json::to_vec_pretty(&provenance.inner).map_err(ArtifactError::Json)?,
        ),
    ];

    publish_verified_directory(output_dir, &files, PublishFailpoint::None, |stage| {
        validate_staged_capture(stage, &artifact, &provenance.inner)
    })
}

pub(super) struct ArtifactFile {
    name: &'static str,
    bytes: Vec<u8>,
}

impl ArtifactFile {
    pub(super) fn new(name: &'static str, bytes: Vec<u8>) -> Self {
        Self { name, bytes }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum PublishFailpoint {
    None,
    AfterFirstFile,
    BeforePublish,
    AfterCommittedRenameError,
}

enum PublicationState {
    Committed,
    NotCommitted,
    Uncertain,
}

fn publish_verified_directory(
    output_dir: &Path,
    files: &[ArtifactFile],
    failpoint: PublishFailpoint,
    validate: impl FnOnce(&ArtifactDirectory) -> Result<(), ArtifactError>,
) -> Result<(), ArtifactError> {
    let output = open_artifact_output(output_dir)?;
    publish_verified_output(&output, files, failpoint, validate)
}

/// Publishes a read-back-validated artifact through the shared no-clobber path.
#[cfg(feature = "typed-qualification")]
pub(super) fn publish_verified_artifact(
    output_dir: &Path,
    files: &[ArtifactFile],
    validate: impl FnOnce(&ArtifactDirectory) -> Result<(), ArtifactError>,
) -> Result<(), ArtifactError> {
    publish_verified_directory(output_dir, files, PublishFailpoint::None, validate)
}

/// Publishes a derived artifact outside both validated source directories.
#[cfg(feature = "typed-qualification")]
pub(super) fn publish_verified_derived_artifact(
    output_dir: &Path,
    capture: &ValidatedCapture,
    sizing: &ValidatedSizing,
    files: &[ArtifactFile],
    validate: impl FnOnce(&ArtifactDirectory) -> Result<(), ArtifactError>,
) -> Result<(), ArtifactError> {
    let output = open_artifact_output(output_dir)?;
    if directory_is_within(&capture.directory, &output.parent)? {
        return Err(ArtifactError::InvalidArtifact {
            reason: "derived artifact output must not be nested inside its capture input",
        });
    }
    if directory_is_within(&sizing.directory, &output.parent)? {
        return Err(ArtifactError::InvalidArtifact {
            reason: "derived artifact output must not be nested inside its sizing input",
        });
    }
    publish_verified_output(&output, files, PublishFailpoint::None, validate)
}

fn publish_verified_output(
    output: &ArtifactOutput,
    files: &[ArtifactFile],
    failpoint: PublishFailpoint,
    validate: impl FnOnce(&ArtifactDirectory) -> Result<(), ArtifactError>,
) -> Result<(), ArtifactError> {
    let expected_names = validate_file_names(files)?;
    ensure_absent(&output.parent, output.name.as_os_str())?;
    let (stage_name, stage) = create_stage_dir(&output.parent, output.name.as_os_str())?;

    let precommit = (|| {
        for (index, file) in files.iter().enumerate() {
            write_synced_file(&stage, file.name, &file.bytes)?;
            if index == 0 && failpoint == PublishFailpoint::AfterFirstFile {
                return Err(ArtifactError::InjectedFailure);
            }
        }
        sync_directory(&stage, "synchronize staged artifact directory")?;
        validate_file_set(&stage, &expected_names)?;
        validate(&stage)?;
        sync_directory(&output.parent, "synchronize staging parent directory")?;
        if failpoint == PublishFailpoint::BeforePublish {
            create_directory(
                &output.parent,
                output.name.as_os_str(),
                "inject concurrent output directory",
            )?;
        }
        Ok(())
    })();
    if let Err(primary) = precommit {
        return cleanup_stage(&output.parent, &stage_name, &stage, files, primary);
    }

    let mut rename_result = rename_noreplace(
        &output.parent,
        stage_name.as_os_str(),
        output.name.as_os_str(),
    );
    if rename_result.is_ok() && failpoint == PublishFailpoint::AfterCommittedRenameError {
        rename_result = Err(ArtifactError::InjectedFailure);
    }
    if let Err(primary) = rename_result {
        return match publication_state(
            &output.parent,
            stage_name.as_os_str(),
            output.name.as_os_str(),
            &stage,
        ) {
            Ok(PublicationState::Committed) => sync_published_parent(&output.parent),
            Ok(PublicationState::NotCommitted) => {
                cleanup_stage(&output.parent, &stage_name, &stage, files, primary)
            }
            Ok(PublicationState::Uncertain) => Err(ArtifactError::PublicationStateUncertain {
                primary: Box::new(primary),
                inspection: None,
            }),
            Err(inspection) => Err(ArtifactError::PublicationStateUncertain {
                primary: Box::new(primary),
                inspection: Some(inspection),
            }),
        };
    }

    // The rename is the commit point. A post-commit synchronization error
    // reports uncertain crash durability but never rolls back or removes the
    // now-visible, already validated artifact.
    sync_published_parent(&output.parent)
}

#[cfg(any(target_vendor = "apple", target_os = "linux"))]
fn publication_state(
    parent: &ArtifactDirectory,
    stage_name: &std::ffi::OsStr,
    output_name: &std::ffi::OsStr,
    stage: &ArtifactDirectory,
) -> Result<PublicationState, io::Error> {
    let stage_stat = fstat(&stage.fd).map_err(io::Error::from)?;
    let stage_name_matches = directory_name_matches(parent, stage_name, &stage_stat)?;
    let output_name_matches = directory_name_matches(parent, output_name, &stage_stat)?;
    match (stage_name_matches, output_name_matches) {
        (false, true) => Ok(PublicationState::Committed),
        (true, false) => Ok(PublicationState::NotCommitted),
        _ => Ok(PublicationState::Uncertain),
    }
}

#[cfg(any(target_vendor = "apple", target_os = "linux"))]
fn directory_name_matches(
    parent: &ArtifactDirectory,
    name: &std::ffi::OsStr,
    expected: &rustix::fs::Stat,
) -> Result<bool, io::Error> {
    match rustix::fs::statat(&parent.fd, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(actual) => Ok(actual.st_dev == expected.st_dev && actual.st_ino == expected.st_ino),
        Err(source) if source == rustix::io::Errno::NOENT => Ok(false),
        Err(source) => Err(source.into()),
    }
}

#[cfg(not(any(target_vendor = "apple", target_os = "linux")))]
fn publication_state(
    _parent: &ArtifactDirectory,
    _stage_name: &std::ffi::OsStr,
    _output_name: &std::ffi::OsStr,
    _stage: &ArtifactDirectory,
) -> Result<PublicationState, io::Error> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "artifact publication identity checks are unsupported on this host",
    ))
}

fn validate_file_names(files: &[ArtifactFile]) -> Result<BTreeSet<OsString>, ArtifactError> {
    if files.is_empty() {
        return Err(ArtifactError::InvalidArtifact {
            reason: "artifact must contain at least one file",
        });
    }
    let mut names = BTreeSet::new();
    for file in files {
        let path = Path::new(file.name);
        if file.name.is_empty() || path.file_name() != Some(path.as_os_str()) {
            return Err(ArtifactError::InvalidArtifact {
                reason: "artifact filenames must be single relative path components",
            });
        }
        if !names.insert(OsString::from(file.name)) {
            return Err(ArtifactError::InvalidArtifact {
                reason: "artifact filenames must be unique",
            });
        }
    }
    Ok(names)
}

#[cfg(any(target_vendor = "apple", target_os = "linux"))]
fn rename_noreplace(
    parent: &ArtifactDirectory,
    stage_name: &std::ffi::OsStr,
    output_name: &std::ffi::OsStr,
) -> Result<(), ArtifactError> {
    match renameat_with(
        &parent.fd,
        stage_name,
        &parent.fd,
        output_name,
        RenameFlags::NOREPLACE,
    ) {
        Ok(()) => Ok(()),
        Err(source) if source == rustix::io::Errno::EXIST => Err(ArtifactError::OutputExists),
        Err(source) => Err(ArtifactError::Io {
            operation: "publish staged artifact directory without replacement",
            source: source.into(),
        }),
    }
}

#[cfg(not(any(target_vendor = "apple", target_os = "linux")))]
fn rename_noreplace(
    _parent: &ArtifactDirectory,
    _stage_name: &std::ffi::OsStr,
    _output_name: &std::ffi::OsStr,
) -> Result<(), ArtifactError> {
    Err(ArtifactError::UnsupportedPlatform)
}

fn validate_staged_capture(
    stage: &ArtifactDirectory,
    expected_artifact: &MeasurementArtifactV1,
    expected_provenance: &CaptureProvenanceV1,
) -> Result<(), ArtifactError> {
    let (artifact, provenance) = read_validated_capture_directory(stage)?;
    if artifact != *expected_artifact {
        return Err(ArtifactError::InvalidArtifact {
            reason: "measurement read-back differs from the captured measurement",
        });
    }
    if provenance != *expected_provenance {
        return Err(ArtifactError::InvalidArtifact {
            reason: "provenance read-back differs from the captured provenance",
        });
    }
    Ok(())
}

fn read_validated_capture_directory(
    directory: &ArtifactDirectory,
) -> Result<(MeasurementArtifactV1, CaptureProvenanceV1), ArtifactError> {
    validate_file_set(
        directory,
        &BTreeSet::from([
            OsString::from(MEASUREMENT_JSON),
            OsString::from(MEASUREMENT_TEXT),
            OsString::from(PROVENANCE_JSON),
        ]),
    )?;
    let measurement_json = read_file(directory, MEASUREMENT_JSON, MAX_MEASUREMENT_JSON_BYTES)?;
    let measurement_text = read_file(directory, MEASUREMENT_TEXT, MAX_MEASUREMENT_TEXT_BYTES)?;
    let provenance_json = read_file(directory, PROVENANCE_JSON, MAX_PROVENANCE_JSON_BYTES)?;

    let artifact: MeasurementArtifactV1 =
        serde_json::from_slice(&measurement_json).map_err(ArtifactError::Json)?;
    artifact.validate()?;
    let provenance: CaptureProvenanceV1 =
        serde_json::from_slice(&provenance_json).map_err(ArtifactError::Json)?;
    validate_provenance(&artifact, &provenance)?;

    if measurement_text != artifact.measurement.to_string().as_bytes() {
        return Err(ArtifactError::InvalidArtifact {
            reason: "measurement text does not match the typed measurement",
        });
    }
    Ok((artifact, provenance))
}

fn open_artifact_output(output_dir: &Path) -> Result<ArtifactOutput, ArtifactError> {
    let name = output_dir
        .file_name()
        .ok_or(ArtifactError::InvalidOutputPath)?
        .to_owned();
    let parent = output_dir.parent().unwrap_or_else(|| Path::new("."));
    let parent = if parent.as_os_str().is_empty() {
        Path::new(".")
    } else {
        parent
    };
    let canonical_parent = fs::canonicalize(parent).map_err(|source| ArtifactError::Io {
        operation: "canonicalize artifact output parent directory",
        source,
    })?;
    let parent = open_artifact_directory(&canonical_parent)?;
    Ok(ArtifactOutput { parent, name })
}

#[cfg(any(target_vendor = "apple", target_os = "linux"))]
pub(super) fn open_artifact_directory(
    directory: &Path,
) -> Result<ArtifactDirectory, ArtifactError> {
    let fd = open(
        directory,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|source| ArtifactError::Io {
        operation: "open artifact directory without following links",
        source: source.into(),
    })?;
    Ok(ArtifactDirectory { fd })
}

#[cfg(not(any(target_vendor = "apple", target_os = "linux")))]
pub(super) fn open_artifact_directory(
    _directory: &Path,
) -> Result<ArtifactDirectory, ArtifactError> {
    Err(ArtifactError::UnsupportedPlatform)
}

#[cfg(any(target_vendor = "apple", target_os = "linux"))]
fn directory_is_within(
    ancestor: &ArtifactDirectory,
    descendant: &ArtifactDirectory,
) -> Result<bool, ArtifactError> {
    const MAX_PARENT_STEPS: usize = 1_024;

    let ancestor_stat = fstat(&ancestor.fd).map_err(|source| ArtifactError::Io {
        operation: "inspect capture directory identity",
        source: source.into(),
    })?;
    let mut current = openat(
        &descendant.fd,
        ".",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|source| ArtifactError::Io {
        operation: "duplicate output parent directory handle",
        source: source.into(),
    })?;

    for _ in 0..MAX_PARENT_STEPS {
        let current_stat = fstat(&current).map_err(|source| ArtifactError::Io {
            operation: "inspect output ancestor directory identity",
            source: source.into(),
        })?;
        if current_stat.st_dev == ancestor_stat.st_dev
            && current_stat.st_ino == ancestor_stat.st_ino
        {
            return Ok(true);
        }
        let parent = openat(
            &current,
            "..",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|source| ArtifactError::Io {
            operation: "open output ancestor directory",
            source: source.into(),
        })?;
        let parent_stat = fstat(&parent).map_err(|source| ArtifactError::Io {
            operation: "inspect output parent directory identity",
            source: source.into(),
        })?;
        if parent_stat.st_dev == current_stat.st_dev && parent_stat.st_ino == current_stat.st_ino {
            return Ok(false);
        }
        current = parent;
    }
    Err(ArtifactError::InvalidArtifact {
        reason: "sizing output parent ancestry exceeds the validation limit",
    })
}

#[cfg(not(any(target_vendor = "apple", target_os = "linux")))]
fn directory_is_within(
    _ancestor: &ArtifactDirectory,
    _descendant: &ArtifactDirectory,
) -> Result<bool, ArtifactError> {
    Err(ArtifactError::UnsupportedPlatform)
}

#[cfg(any(target_vendor = "apple", target_os = "linux"))]
fn validate_file_set(
    directory: &ArtifactDirectory,
    expected: &BTreeSet<OsString>,
) -> Result<(), ArtifactError> {
    let entries = Dir::read_from(&directory.fd).map_err(|source| ArtifactError::Io {
        operation: "open artifact directory stream",
        source: source.into(),
    })?;
    let mut actual = BTreeSet::new();
    for entry in entries {
        let entry = entry.map_err(|source| ArtifactError::Io {
            operation: "read artifact directory entry",
            source: source.into(),
        })?;
        let name = entry.file_name().to_bytes();
        if name == b"." || name == b".." {
            continue;
        }
        let name = OsString::from_vec(name.to_vec());
        if !expected.contains(&name) || !actual.insert(name) {
            return Err(ArtifactError::InvalidArtifact {
                reason: "artifact directory does not contain exactly the required files",
            });
        }
    }
    if actual == *expected {
        Ok(())
    } else {
        Err(ArtifactError::InvalidArtifact {
            reason: "artifact directory does not contain exactly the required files",
        })
    }
}

#[cfg(not(any(target_vendor = "apple", target_os = "linux")))]
fn validate_file_set(
    _directory: &ArtifactDirectory,
    _expected: &BTreeSet<OsString>,
) -> Result<(), ArtifactError> {
    Err(ArtifactError::UnsupportedPlatform)
}

fn validate_provenance(
    artifact: &MeasurementArtifactV1,
    provenance: &CaptureProvenanceV1,
) -> Result<(), ArtifactError> {
    if provenance.schema != CAPTURE_PROVENANCE_SCHEMA || provenance.runner_version.is_empty() {
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

fn validate_sizing_binding(
    capture: &ValidatedCapture,
    artifact: &SizingArtifactV1,
) -> Result<(), ArtifactError> {
    if artifact.measurement_blake2s256 != capture.measurement_blake2s256() {
        return Err(ArtifactError::InvalidArtifact {
            reason: "sizing artifact measurement digest mismatch",
        });
    }
    artifact
        .qualification
        .validate_against(capture.measurement())
        .map_err(|_| ArtifactError::InvalidArtifact {
            reason: "sizing qualification does not match the captured measurement and model",
        })
}

fn validate_sizing_provenance(
    capture: &ValidatedCapture,
    artifact: &SizingArtifactV1,
    provenance: &SizingProvenanceV1,
) -> Result<(), ArtifactError> {
    if provenance.schema != SIZING_PROVENANCE_SCHEMA
        || provenance.runner_version.is_empty()
        || provenance.target_os != std::env::consts::OS
        || provenance.target_arch != std::env::consts::ARCH
    {
        return Err(ArtifactError::InvalidArtifact {
            reason: "sizing provenance schema or runner version is invalid",
        });
    }
    validate_sizing_binding(capture, artifact)?;
    let checkpoint = artifact.qualification.checkpoint();
    if provenance.verified_checkpoint_height != checkpoint.height()
        || provenance.verified_checkpoint_hash != checkpoint.hash()
    {
        return Err(ArtifactError::InvalidArtifact {
            reason: "sizing provenance checkpoint does not match the qualification",
        });
    }
    if provenance.measurement_blake2s256 != capture.measurement_blake2s256() {
        return Err(ArtifactError::InvalidArtifact {
            reason: "sizing provenance measurement digest mismatch",
        });
    }
    let model_bytes =
        serde_json::to_vec(artifact.qualification.model()).map_err(ArtifactError::Json)?;
    if provenance.sizing_model_blake2s256 != blake2s256_hex(&model_bytes) {
        return Err(ArtifactError::InvalidArtifact {
            reason: "sizing model digest mismatch",
        });
    }
    if provenance.qualification_blake2s256 != artifact.digest()? {
        return Err(ArtifactError::InvalidArtifact {
            reason: "sizing qualification digest mismatch",
        });
    }
    Ok(())
}

fn validate_staged_sizing(
    stage: &ArtifactDirectory,
    capture: &ValidatedCapture,
    expected_artifact: &SizingArtifactV1,
    expected_provenance: &SizingProvenanceV1,
) -> Result<(), ArtifactError> {
    let (artifact, provenance) = read_validated_sizing_directory(stage, capture)?;
    if artifact != *expected_artifact {
        return Err(ArtifactError::InvalidArtifact {
            reason: "sizing read-back differs from the computed qualification",
        });
    }
    if provenance != *expected_provenance {
        return Err(ArtifactError::InvalidArtifact {
            reason: "sizing provenance read-back differs from the expected provenance",
        });
    }
    Ok(())
}

fn read_validated_sizing_directory(
    directory: &ArtifactDirectory,
    capture: &ValidatedCapture,
) -> Result<(SizingArtifactV1, SizingProvenanceV1), ArtifactError> {
    validate_file_set(
        directory,
        &BTreeSet::from([
            OsString::from(QUALIFICATION_JSON),
            OsString::from(QUALIFICATION_TEXT),
            OsString::from(PROVENANCE_JSON),
        ]),
    )?;
    let qualification_json =
        read_file(directory, QUALIFICATION_JSON, MAX_QUALIFICATION_JSON_BYTES)?;
    let qualification_text =
        read_file(directory, QUALIFICATION_TEXT, MAX_QUALIFICATION_TEXT_BYTES)?;
    let provenance_json = read_file(directory, PROVENANCE_JSON, MAX_PROVENANCE_JSON_BYTES)?;

    let artifact: SizingArtifactV1 =
        serde_json::from_slice(&qualification_json).map_err(ArtifactError::Json)?;
    artifact.validate()?;
    let provenance: SizingProvenanceV1 =
        serde_json::from_slice(&provenance_json).map_err(ArtifactError::Json)?;
    validate_sizing_provenance(capture, &artifact, &provenance)?;
    if qualification_text != artifact.qualification.to_string().as_bytes() {
        return Err(ArtifactError::InvalidArtifact {
            reason: "sizing text does not match the typed qualification",
        });
    }
    Ok((artifact, provenance))
}

#[cfg(any(target_vendor = "apple", target_os = "linux"))]
fn create_stage_dir(
    parent: &ArtifactDirectory,
    output_name: &std::ffi::OsStr,
) -> Result<(OsString, ArtifactDirectory), ArtifactError> {
    for _ in 0..MAX_STAGE_ATTEMPTS {
        let id = NEXT_STAGE_ID.fetch_add(1, Ordering::Relaxed);
        let mut stage_name = OsString::from(".");
        stage_name.push(output_name);
        stage_name.push(format!(".stage-{}-{id}", std::process::id()));
        match mkdirat(&parent.fd, stage_name.as_os_str(), Mode::RWXU) {
            Ok(()) => {
                let fd = match openat(
                    &parent.fd,
                    stage_name.as_os_str(),
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                ) {
                    Ok(fd) => fd,
                    Err(source) => {
                        let primary = ArtifactError::Io {
                            operation: "open created staging directory",
                            source: source.into(),
                        };
                        return match unlinkat(
                            &parent.fd,
                            stage_name.as_os_str(),
                            AtFlags::REMOVEDIR,
                        ) {
                            Ok(()) => Err(primary),
                            Err(cleanup) => Err(ArtifactError::Cleanup {
                                primary: Box::new(primary),
                                cleanup: cleanup.into(),
                            }),
                        };
                    }
                };
                return Ok((stage_name, ArtifactDirectory { fd }));
            }
            Err(source) if source == rustix::io::Errno::EXIST => continue,
            Err(source) => {
                return Err(ArtifactError::Io {
                    operation: "create sibling staging directory",
                    source: source.into(),
                });
            }
        }
    }
    Err(ArtifactError::StageNameExhausted)
}

#[cfg(not(any(target_vendor = "apple", target_os = "linux")))]
fn create_stage_dir(
    _parent: &ArtifactDirectory,
    _output_name: &std::ffi::OsStr,
) -> Result<(OsString, ArtifactDirectory), ArtifactError> {
    Err(ArtifactError::UnsupportedPlatform)
}

#[cfg(any(target_vendor = "apple", target_os = "linux"))]
fn create_directory(
    parent: &ArtifactDirectory,
    name: &std::ffi::OsStr,
    operation: &'static str,
) -> Result<(), ArtifactError> {
    mkdirat(&parent.fd, name, Mode::RWXU).map_err(|source| ArtifactError::Io {
        operation,
        source: source.into(),
    })
}

#[cfg(not(any(target_vendor = "apple", target_os = "linux")))]
fn create_directory(
    _parent: &ArtifactDirectory,
    _name: &std::ffi::OsStr,
    _operation: &'static str,
) -> Result<(), ArtifactError> {
    Err(ArtifactError::UnsupportedPlatform)
}

#[cfg(any(target_vendor = "apple", target_os = "linux"))]
fn ensure_absent(parent: &ArtifactDirectory, name: &std::ffi::OsStr) -> Result<(), ArtifactError> {
    match rustix::fs::statat(&parent.fd, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(_) => Err(ArtifactError::OutputExists),
        Err(source) if source == rustix::io::Errno::NOENT => Ok(()),
        Err(source) => Err(ArtifactError::Io {
            operation: "inspect artifact output directory",
            source: source.into(),
        }),
    }
}

#[cfg(not(any(target_vendor = "apple", target_os = "linux")))]
fn ensure_absent(
    _parent: &ArtifactDirectory,
    _name: &std::ffi::OsStr,
) -> Result<(), ArtifactError> {
    Err(ArtifactError::UnsupportedPlatform)
}

#[cfg(any(target_vendor = "apple", target_os = "linux"))]
fn write_synced_file(
    directory: &ArtifactDirectory,
    name: &'static str,
    bytes: &[u8],
) -> Result<(), ArtifactError> {
    let fd = openat(
        &directory.fd,
        name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .map_err(|source| ArtifactError::Io {
        operation: "create staged artifact file",
        source: source.into(),
    })?;
    let mut file = File::from(fd);
    file.write_all(bytes).map_err(|source| ArtifactError::Io {
        operation: "write staged artifact file",
        source,
    })?;
    file.sync_all().map_err(|source| ArtifactError::Io {
        operation: "synchronize staged artifact file",
        source,
    })
}

#[cfg(not(any(target_vendor = "apple", target_os = "linux")))]
fn write_synced_file(
    _directory: &ArtifactDirectory,
    _name: &'static str,
    _bytes: &[u8],
) -> Result<(), ArtifactError> {
    Err(ArtifactError::UnsupportedPlatform)
}

#[cfg(any(target_vendor = "apple", target_os = "linux"))]
fn read_file(
    directory: &ArtifactDirectory,
    name: &'static str,
    maximum_bytes: usize,
) -> Result<Vec<u8>, ArtifactError> {
    let fd = openat(
        &directory.fd,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|source| {
        if source == rustix::io::Errno::LOOP {
            ArtifactError::NonRegularFile { name }
        } else {
            ArtifactError::Io {
                operation: "open artifact file without following links",
                source: source.into(),
            }
        }
    })?;
    let file = File::from(fd);
    let metadata = file.metadata().map_err(|source| ArtifactError::Io {
        operation: "inspect opened artifact file",
        source,
    })?;
    if !metadata.is_file() {
        return Err(ArtifactError::NonRegularFile { name });
    }
    if metadata.len() > maximum_bytes as u64 {
        return Err(ArtifactError::FileTooLarge {
            name,
            maximum_bytes,
        });
    }

    let mut bytes = Vec::new();
    file.take(maximum_bytes as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| ArtifactError::Io {
            operation: "read bounded artifact file",
            source,
        })?;
    if bytes.len() > maximum_bytes {
        return Err(ArtifactError::FileTooLarge {
            name,
            maximum_bytes,
        });
    }
    Ok(bytes)
}

#[cfg(not(any(target_vendor = "apple", target_os = "linux")))]
fn read_file(
    _directory: &ArtifactDirectory,
    _name: &'static str,
    _maximum_bytes: usize,
) -> Result<Vec<u8>, ArtifactError> {
    Err(ArtifactError::UnsupportedPlatform)
}

/// Reads one regular artifact file without following links and with a byte cap.
#[cfg(feature = "typed-qualification")]
pub(super) fn read_artifact_file(
    directory: &ArtifactDirectory,
    name: &'static str,
    maximum_bytes: usize,
) -> Result<Vec<u8>, ArtifactError> {
    read_file(directory, name, maximum_bytes)
}

/// Requires an opened artifact directory to contain exactly the named files.
#[cfg(feature = "typed-qualification")]
pub(super) fn validate_artifact_file_set(
    directory: &ArtifactDirectory,
    names: &[&'static str],
) -> Result<(), ArtifactError> {
    let files: Vec<_> = names
        .iter()
        .map(|name| ArtifactFile::new(name, Vec::new()))
        .collect();
    let expected = validate_file_names(&files)?;
    validate_file_set(directory, &expected)
}

#[cfg(any(target_vendor = "apple", target_os = "linux"))]
fn sync_directory(
    directory: &ArtifactDirectory,
    operation: &'static str,
) -> Result<(), ArtifactError> {
    fsync(&directory.fd).map_err(|source| ArtifactError::Io {
        operation,
        source: source.into(),
    })
}

#[cfg(not(any(target_vendor = "apple", target_os = "linux")))]
fn sync_directory(
    _directory: &ArtifactDirectory,
    _operation: &'static str,
) -> Result<(), ArtifactError> {
    Err(ArtifactError::UnsupportedPlatform)
}

#[cfg(any(target_vendor = "apple", target_os = "linux"))]
fn sync_published_parent(parent: &ArtifactDirectory) -> Result<(), ArtifactError> {
    fsync(&parent.fd).map_err(|source| ArtifactError::PublishedButDurabilityUncertain {
        source: source.into(),
    })
}

#[cfg(not(any(target_vendor = "apple", target_os = "linux")))]
fn sync_published_parent(_parent: &ArtifactDirectory) -> Result<(), ArtifactError> {
    Err(ArtifactError::UnsupportedPlatform)
}

#[cfg(any(target_vendor = "apple", target_os = "linux"))]
fn cleanup_stage(
    parent: &ArtifactDirectory,
    stage_name: &OsString,
    stage: &ArtifactDirectory,
    files: &[ArtifactFile],
    primary: ArtifactError,
) -> Result<(), ArtifactError> {
    let mut cleanup_error = None;
    for file in files {
        if let Err(source) = unlinkat(&stage.fd, file.name, AtFlags::empty()) {
            if source != rustix::io::Errno::NOENT && cleanup_error.is_none() {
                cleanup_error = Some(io::Error::from(source));
            }
        }
    }
    if let Err(source) = unlinkat(&parent.fd, stage_name.as_os_str(), AtFlags::REMOVEDIR) {
        if source != rustix::io::Errno::NOENT && cleanup_error.is_none() {
            cleanup_error = Some(io::Error::from(source));
        }
    }
    if cleanup_error.is_none() {
        if let Err(source) = fsync(&parent.fd) {
            cleanup_error = Some(io::Error::from(source));
        }
    }
    match cleanup_error {
        None => Err(primary),
        Some(cleanup) => Err(ArtifactError::Cleanup {
            primary: Box::new(primary),
            cleanup,
        }),
    }
}

#[cfg(not(any(target_vendor = "apple", target_os = "linux")))]
fn cleanup_stage(
    _parent: &ArtifactDirectory,
    _stage_name: &OsString,
    _stage: &ArtifactDirectory,
    _files: &[ArtifactFile],
    primary: ArtifactError,
) -> Result<(), ArtifactError> {
    Err(primary)
}

fn blake2s256_hex(bytes: &[u8]) -> String {
    hex::encode(Blake2s256::digest(bytes))
}

/// Returns the canonical artifact digest encoding shared by sibling formats.
#[cfg(feature = "typed-qualification")]
pub(super) fn artifact_blake2s256_hex(bytes: &[u8]) -> String {
    blake2s256_hex(bytes)
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
    NonRegularFile {
        name: &'static str,
    },
    FileTooLarge {
        name: &'static str,
        maximum_bytes: usize,
    },
    PublishedButDurabilityUncertain {
        source: io::Error,
    },
    PublicationStateUncertain {
        primary: Box<Self>,
        inspection: Option<io::Error>,
    },
    InvalidArtifact {
        reason: &'static str,
    },
    Measurement(MainnetCorpusError),
    Qualification(MainnetCorpusError),
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
            Self::NonRegularFile { name } => {
                write!(f, "artifact entry {name} is not a regular file")
            }
            Self::FileTooLarge {
                name,
                maximum_bytes,
            } => write!(
                f,
                "artifact entry {name} exceeds its {maximum_bytes}-byte limit"
            ),
            Self::PublishedButDurabilityUncertain { source } => write!(
                f,
                "artifact is published, but parent synchronization failed and crash durability is uncertain: {source}"
            ),
            Self::PublicationStateUncertain {
                primary,
                inspection: Some(inspection),
            } => write!(
                f,
                "artifact publication state is uncertain after {primary}; identity inspection also failed: {inspection}"
            ),
            Self::PublicationStateUncertain {
                primary,
                inspection: None,
            } => write!(
                f,
                "artifact publication state is uncertain after {primary}; recovery left both directory names untouched"
            ),
            Self::InvalidArtifact { reason } => write!(f, "artifact validation failed: {reason}"),
            Self::Measurement(error) => write!(f, "measurement validation failed: {error}"),
            Self::Qualification(error) => {
                write!(f, "sizing qualification validation failed: {error}")
            }
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
            Self::Qualification(error) => Some(error),
            Self::Json(error) => Some(error),
            Self::Io { source, .. } => Some(source),
            Self::PublishedButDurabilityUncertain { source } => Some(source),
            Self::PublicationStateUncertain { primary, .. } => Some(primary),
            Self::Cleanup { primary, .. } => Some(primary),
            #[cfg(not(any(target_vendor = "apple", target_os = "linux")))]
            Self::UnsupportedPlatform => None,
            Self::InvalidOutputPath
            | Self::OutputExists
            | Self::StageNameExhausted
            | Self::InjectedFailure
            | Self::NonRegularFile { .. }
            | Self::FileTooLarge { .. }
            | Self::InvalidArtifact { .. } => None,
        }
    }
}

#[cfg(test)]
pub(crate) fn typed_test_measurement() -> Result<MainnetCorpusMeasurement, serde_json::Error> {
    serde_json::from_value(serde_json::json!({
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
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use zaino_oram::MainnetSizingModel;

    type TestResult<T = ()> = Result<T, Box<dyn Error>>;

    fn typed_measurement_with_one_address() -> TestResult<MainnetCorpusMeasurement> {
        let mut value = serde_json::to_value(typed_test_measurement()?)?;
        value["aggregate"]["transactions"] = serde_json::json!(1);
        value["aggregate"]["outputs"] = serde_json::json!(1);
        value["aggregate"]["distinct_standard_addresses"] = serde_json::json!(1);
        value["aggregate"]["live_standard_utxos"] = serde_json::json!(1);
        value["aggregate"]["script_totals"][0] =
            serde_json::json!({"outputs": 1, "spends": 0, "live_utxos": 1});
        value["aggregate"]["events_per_address"] = serde_json::json!([{"value": 1, "count": 1}]);
        value["aggregate"]["live_utxos_per_address"] =
            serde_json::json!([{"value": 1, "count": 1}]);
        value["aggregate"]["peak_live_utxos_per_address"] =
            serde_json::json!([{"value": 1, "count": 1}]);
        value["aggregate"]["address_state_histogram"] = serde_json::json!([{
            "events": 1,
            "live_utxos": 1,
            "peak_live_utxos": 1,
            "address_count": 1
        }]);
        let distribution = serde_json::json!({
            "p50": 1,
            "p90": 1,
            "p99": 1,
            "p999": 1,
            "maximum": 1
        });
        value["aggregate"]["event_distribution"] = distribution.clone();
        value["aggregate"]["live_distribution"] = distribution.clone();
        value["aggregate"]["peak_live_distribution"] = distribution;
        value["aggregate"]["hottest_event_counts"] =
            serde_json::json!([1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        Ok(serde_json::from_value(value)?)
    }

    fn sizing_model(annual_growth_bps: u64) -> TestResult<MainnetSizingModel> {
        Ok(MainnetSizingModel::new(
            2,
            annual_growth_bps,
            8,
            6,
            16,
            12,
            8,
            4,
            20_000,
            1_000_000,
            3_000,
        )?)
    }

    fn publish_and_load_capture(parent: &Path) -> TestResult<(PathBuf, ValidatedCapture)> {
        let output = parent.join("capture");
        let measurement = typed_test_measurement()?;
        let provenance = CaptureProvenance::new(
            BackendKind::Rpc,
            SnapshotMode::NonFinalizedState,
            0,
            SelectionMode::ServiceableTip,
            "test-runner",
            &measurement,
        )?;
        publish_capture(&output, &measurement, &provenance)?;
        let capture = load_capture(&output)?;
        Ok((output, capture))
    }

    fn test_files() -> [ArtifactFile; 3] {
        [
            ArtifactFile::new(
                MEASUREMENT_JSON,
                br#"{"schema":"test","measurement":1}"#.to_vec(),
            ),
            ArtifactFile::new(MEASUREMENT_TEXT, b"measurement=1\n".to_vec()),
            ArtifactFile::new(PROVENANCE_JSON, br#"{"schema":"test-provenance"}"#.to_vec()),
        ]
    }

    fn validate_test_files(
        stage: &ArtifactDirectory,
        expected: &[ArtifactFile],
    ) -> Result<(), ArtifactError> {
        for file in expected {
            if read_file(stage, file.name, 1_024)? != file.bytes {
                return Err(ArtifactError::InvalidArtifact {
                    reason: "test read-back mismatch",
                });
            }
        }
        Ok(())
    }

    fn validate_test_files_path(
        stage: &Path,
        expected: &[ArtifactFile],
    ) -> Result<(), ArtifactError> {
        validate_test_files(&open_artifact_directory(stage)?, expected)
    }

    fn validate_test_capture_path(
        stage: &Path,
        artifact: &MeasurementArtifactV1,
        provenance: &CaptureProvenanceV1,
    ) -> Result<(), ArtifactError> {
        validate_staged_capture(&open_artifact_directory(stage)?, artifact, provenance)
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

    fn replace_with_oversized_file(path: &Path, maximum_bytes: usize) -> io::Result<()> {
        let file = fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(path)?;
        file.set_len(maximum_bytes as u64 + 1)
    }

    fn mutate_json_file(
        path: &Path,
        mutate: impl FnOnce(&mut serde_json::Value),
    ) -> TestResult<Vec<u8>> {
        let original = fs::read(path)?;
        let mut value = serde_json::from_slice(&original)?;
        mutate(&mut value);
        fs::write(path, serde_json::to_vec_pretty(&value)?)?;
        Ok(original)
    }

    #[test]
    fn publishes_complete_directory_after_successful_read_back() -> TestResult {
        let parent = tempfile::tempdir()?;
        let output = parent.path().join("capture");
        let files = test_files();

        publish_verified_directory(&output, &files, PublishFailpoint::None, |stage| {
            validate_test_files(stage, &files)
        })?;

        validate_test_files_path(&output, &files)?;
        assert!(sibling_stages(parent.path(), "capture")?.is_empty());
        Ok(())
    }

    #[test]
    fn generic_publisher_rejects_empty_duplicate_and_path_filenames() -> TestResult {
        let parent = tempfile::tempdir()?;
        let output = parent.path().join("invalid");
        let empty: [ArtifactFile; 0] = [];
        assert!(
            publish_verified_directory(&output, &empty, PublishFailpoint::None, |_| Ok(()))
                .is_err()
        );

        let duplicate = [
            ArtifactFile::new("same", vec![1]),
            ArtifactFile::new("same", vec![2]),
        ];
        assert!(publish_verified_directory(
            &output,
            &duplicate,
            PublishFailpoint::None,
            |_| Ok(())
        )
        .is_err());

        let nested = [ArtifactFile::new("nested/file", vec![1])];
        assert!(
            publish_verified_directory(&output, &nested, PublishFailpoint::None, |_| Ok(()))
                .is_err()
        );
        assert!(!output.exists());
        Ok(())
    }

    #[test]
    fn typed_capture_publication_binds_digest_and_secret_free_provenance() -> TestResult {
        let parent = tempfile::tempdir()?;
        let output = parent.path().join("capture");
        let measurement = typed_test_measurement()?;
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
        validate_test_capture_path(&output, &artifact, &provenance.inner)?;
        let provenance_text = fs::read_to_string(output.join(PROVENANCE_JSON))?;
        for forbidden in ["endpoint", "path", "cookie", "credential", "config"] {
            assert!(!provenance_text.contains(forbidden));
        }
        assert!(provenance_text.contains("measurement_blake2s256"));
        Ok(())
    }

    #[test]
    fn typed_sizing_publication_is_deterministic_and_binds_all_digests() -> TestResult {
        let parent = tempfile::tempdir()?;
        let (_, capture) = publish_and_load_capture(parent.path())?;
        let model = sizing_model(1_000)?;
        let qualification = capture.measurement().apply_model(&model)?;
        let first = parent.path().join("sizing-first");
        let second = parent.path().join("sizing-second");

        publish_sizing(&first, &capture, &qualification, "test-runner")?;
        publish_sizing(&second, &capture, &qualification, "test-runner")?;

        let sizing = load_sizing(&first, &capture)?;
        let artifact = SizingArtifactV1::new(&capture, &qualification)?;
        let sizing_directory = open_artifact_directory(&first)?;
        let (_, provenance) = read_validated_sizing_directory(&sizing_directory, &capture)?;
        assert_eq!(sizing.qualification(), &qualification);
        assert_eq!(
            sizing.measurement_blake2s256(),
            capture.measurement_blake2s256()
        );
        assert_eq!(sizing.qualification_blake2s256(), artifact.digest()?);
        assert_eq!(
            provenance.qualification_blake2s256,
            sizing.qualification_blake2s256()
        );
        assert_eq!(
            provenance.sizing_model_blake2s256,
            blake2s256_hex(&serde_json::to_vec(&model)?)
        );
        let other_model = sizing_model(0)?;
        let other_qualification = capture.measurement().apply_model(&other_model)?;
        let other_artifact = SizingArtifactV1::new(&capture, &other_qualification)?;
        let other_provenance = SizingProvenanceV1::new("test-runner", &capture, &other_artifact)?;
        assert_ne!(artifact.digest()?, other_artifact.digest()?);
        assert_ne!(
            provenance.sizing_model_blake2s256,
            other_provenance.sizing_model_blake2s256
        );
        assert_eq!(fs::read_dir(&first)?.count(), 3);
        for name in [QUALIFICATION_JSON, QUALIFICATION_TEXT, PROVENANCE_JSON] {
            assert_eq!(fs::read(first.join(name))?, fs::read(second.join(name))?);
        }
        let provenance_text = fs::read_to_string(first.join(PROVENANCE_JSON))?;
        for forbidden in ["endpoint", "path", "cookie", "credential", "config"] {
            assert!(!provenance_text.contains(forbidden));
        }
        Ok(())
    }

    #[test]
    fn sizing_load_rejects_a_different_validated_capture() -> TestResult {
        let parent = tempfile::tempdir()?;
        let (_, capture) = publish_and_load_capture(parent.path())?;
        let qualification = capture.measurement().apply_model(&sizing_model(0)?)?;
        let sizing_dir = parent.path().join("sizing");
        publish_sizing(&sizing_dir, &capture, &qualification, "test-runner")?;

        let other_measurement = typed_measurement_with_one_address()?;
        let other_provenance = CaptureProvenance::new(
            BackendKind::Rpc,
            SnapshotMode::NonFinalizedState,
            0,
            SelectionMode::ServiceableTip,
            "test-runner",
            &other_measurement,
        )?;
        let other_capture_dir = parent.path().join("other-capture");
        publish_capture(&other_capture_dir, &other_measurement, &other_provenance)?;
        let other_capture = load_capture(&other_capture_dir)?;

        assert!(matches!(
            load_sizing(&sizing_dir, &other_capture),
            Err(ArtifactError::InvalidArtifact {
                reason: "sizing artifact measurement digest mismatch"
            })
        ));
        Ok(())
    }

    #[test]
    fn sizing_v1_canonical_json_and_digests_are_golden() -> TestResult {
        const MODEL_JSON: &str = r#"{"growth_horizon_years":0,"annual_growth_bps":0,"directory_capacity":8,"directory_admission_limit":6,"event_capacity":16,"event_admission_limit":12,"max_events_per_address":8,"position_map_entry_bytes":4,"backend_expansion_bps":20000,"tdx_memory_bytes":1000000,"required_headroom_bps":3000}"#;
        const MODEL_DIGEST: &str =
            "479b8b9a500340d1c5637eba6c9e430da01fc7dadc7030dc26376c159c6681a5";
        const ARTIFACT_JSON: &str = r#"{"schema":"zaino-oram-mainnet-sizing-v1","measurement_blake2s256":"f98ee2710b69837cb9fc53c69a82153e80f67e89a237279fc757c4e34e953ed0","qualification":{"checkpoint":{"network":"mainnet","height":0,"hash":"00040fe8ec8471911baa1db1266ea15dd06b4a8a5c453883c000b031973dce08"},"model":{"growth_horizon_years":0,"annual_growth_bps":0,"directory_capacity":8,"directory_admission_limit":6,"event_capacity":16,"event_admission_limit":12,"max_events_per_address":8,"position_map_entry_bytes":4,"backend_expansion_bps":20000,"tdx_memory_bytes":1000000,"required_headroom_bps":3000},"compiled_record_bytes":{"directory_cell_bytes":38,"event_cell_bytes":82},"evidence":{"insertion_bound":false,"backend_calibrated":false,"rss_measured":false,"load_bps_rounding":"floor","load_bps_capped":false},"projections":[{"year":0,"standard_addresses":0,"events":0,"max_events_per_address":0,"directory_load_bps":"0","event_load_bps":"0","allocated_directory_bytes":304,"allocated_event_bytes":1312,"allocated_table_bytes":1616,"logical_position_map_bytes":96,"logical_total_bytes":1712,"backend_expanded_bytes":3424,"usable_memory_bytes":700000,"fits_directory_admission":true,"fits_event_admission":true,"fits_address_event_limit":true,"fits_configured_limits":true,"fits_modeled_memory":true,"fits_modeled_constraints":true}]}}"#;
        const ARTIFACT_DIGEST: &str =
            "547fa0ada595055f8dbbfa5f36409951313f59534cc00b0c09d02765137e3afb";

        let parent = tempfile::tempdir()?;
        let (_, capture) = publish_and_load_capture(parent.path())?;
        let model = MainnetSizingModel::new(0, 0, 8, 6, 16, 12, 8, 4, 20_000, 1_000_000, 3_000)?;
        let qualification = capture.measurement().apply_model(&model)?;
        let artifact = SizingArtifactV1::new(&capture, &qualification)?;
        let model_bytes = serde_json::to_vec(&model)?;
        let artifact_bytes = artifact.canonical_bytes()?;

        assert_eq!(model_bytes, MODEL_JSON.as_bytes());
        assert_eq!(blake2s256_hex(&model_bytes), MODEL_DIGEST);
        assert_eq!(artifact_bytes, ARTIFACT_JSON.as_bytes());
        assert_eq!(blake2s256_hex(&artifact_bytes), ARTIFACT_DIGEST);
        Ok(())
    }

    #[test]
    fn sizing_validation_rejects_fabricated_lineage_and_digest_tampering() -> TestResult {
        let parent = tempfile::tempdir()?;
        let (_, capture) = publish_and_load_capture(parent.path())?;
        let model = sizing_model(1_000)?;
        let other_measurement = typed_measurement_with_one_address()?;
        let fabricated = other_measurement.apply_model(&model)?;
        let fabricated_artifact = SizingArtifactV1 {
            schema: SIZING_SCHEMA.to_owned(),
            measurement_blake2s256: capture.measurement_blake2s256().to_owned(),
            qualification: fabricated.clone(),
        };
        assert!(matches!(
            validate_sizing_binding(&capture, &fabricated_artifact),
            Err(ArtifactError::InvalidArtifact {
                reason: "sizing qualification does not match the captured measurement and model"
            })
        ));

        let sizing_dir = parent.path().join("fabricated-sizing");
        let qualification = capture.measurement().apply_model(&model)?;
        publish_sizing(&sizing_dir, &capture, &qualification, "test-runner")?;
        let qualification_path = sizing_dir.join(QUALIFICATION_JSON);
        let mut persisted: SizingArtifactV1 =
            serde_json::from_slice(&fs::read(&qualification_path)?)?;
        persisted.qualification = fabricated.clone();
        fs::write(&qualification_path, serde_json::to_vec_pretty(&persisted)?)?;
        fs::write(sizing_dir.join(QUALIFICATION_TEXT), fabricated.to_string())?;
        assert!(matches!(
            load_sizing(&sizing_dir, &capture),
            Err(ArtifactError::InvalidArtifact {
                reason: "sizing qualification does not match the captured measurement and model"
            })
        ));

        let artifact = SizingArtifactV1::new(&capture, &qualification)?;
        let provenance = SizingProvenanceV1::new("test-runner", &capture, &artifact)?;

        let mut wrong_measurement = provenance.clone();
        wrong_measurement.measurement_blake2s256 = "00".repeat(32);
        assert!(matches!(
            validate_sizing_provenance(&capture, &artifact, &wrong_measurement),
            Err(ArtifactError::InvalidArtifact {
                reason: "sizing provenance measurement digest mismatch"
            })
        ));

        let mut wrong_model = provenance.clone();
        wrong_model.sizing_model_blake2s256 = "00".repeat(32);
        assert!(matches!(
            validate_sizing_provenance(&capture, &artifact, &wrong_model),
            Err(ArtifactError::InvalidArtifact {
                reason: "sizing model digest mismatch"
            })
        ));

        let mut wrong_qualification = provenance;
        wrong_qualification.qualification_blake2s256 = "00".repeat(32);
        assert!(matches!(
            validate_sizing_provenance(&capture, &artifact, &wrong_qualification),
            Err(ArtifactError::InvalidArtifact {
                reason: "sizing qualification digest mismatch"
            })
        ));
        Ok(())
    }

    #[test]
    fn sizing_load_rejects_typed_json_and_provenance_tampering() -> TestResult {
        let parent = tempfile::tempdir()?;
        let (_, capture) = publish_and_load_capture(parent.path())?;
        let qualification = capture.measurement().apply_model(&sizing_model(0)?)?;
        let sizing_dir = parent.path().join("sizing");
        publish_sizing(&sizing_dir, &capture, &qualification, "test-runner")?;

        let qualification_path = sizing_dir.join(QUALIFICATION_JSON);
        let original_qualification = mutate_json_file(&qualification_path, |value| {
            value["schema"] = serde_json::json!("wrong-sizing-schema");
        })?;
        assert!(matches!(
            load_sizing(&sizing_dir, &capture),
            Err(ArtifactError::InvalidArtifact {
                reason: "sizing schema mismatch"
            })
        ));
        fs::write(&qualification_path, original_qualification)?;

        let provenance_path = sizing_dir.join(PROVENANCE_JSON);
        let original_provenance = mutate_json_file(&provenance_path, |value| {
            value["schema"] = serde_json::json!("wrong-sizing-provenance-schema");
        })?;
        assert!(matches!(
            load_sizing(&sizing_dir, &capture),
            Err(ArtifactError::InvalidArtifact {
                reason: "sizing provenance schema or runner version is invalid"
            })
        ));
        fs::write(&provenance_path, &original_provenance)?;

        let original_provenance = mutate_json_file(&provenance_path, |value| {
            value["target_os"] = serde_json::json!("different-host-os");
        })?;
        assert!(matches!(
            load_sizing(&sizing_dir, &capture),
            Err(ArtifactError::InvalidArtifact {
                reason: "sizing provenance schema or runner version is invalid"
            })
        ));
        fs::write(&provenance_path, &original_provenance)?;

        let original_provenance = mutate_json_file(&provenance_path, |value| {
            value["verified_checkpoint_height"] = serde_json::json!(1);
        })?;
        assert!(matches!(
            load_sizing(&sizing_dir, &capture),
            Err(ArtifactError::InvalidArtifact {
                reason: "sizing provenance checkpoint does not match the qualification"
            })
        ));
        fs::write(&provenance_path, &original_provenance)?;

        let original_provenance = mutate_json_file(&provenance_path, |value| {
            value["sizing_model_blake2s256"] = serde_json::json!("00".repeat(32));
        })?;
        assert!(matches!(
            load_sizing(&sizing_dir, &capture),
            Err(ArtifactError::InvalidArtifact {
                reason: "sizing model digest mismatch"
            })
        ));
        fs::write(&provenance_path, &original_provenance)?;

        let original_provenance = mutate_json_file(&provenance_path, |value| {
            value["qualification_blake2s256"] = serde_json::json!("00".repeat(32));
        })?;
        assert!(matches!(
            load_sizing(&sizing_dir, &capture),
            Err(ArtifactError::InvalidArtifact {
                reason: "sizing qualification digest mismatch"
            })
        ));
        fs::write(&provenance_path, original_provenance)?;
        Ok(())
    }

    #[test]
    fn sizing_read_back_rejects_text_file_set_and_nested_output_tampering() -> TestResult {
        let parent = tempfile::tempdir()?;
        let (capture_dir, capture) = publish_and_load_capture(parent.path())?;
        let qualification = capture.measurement().apply_model(&sizing_model(0)?)?;
        let output = parent.path().join("sizing");
        publish_sizing(&output, &capture, &qualification, "test-runner")?;

        let qualification_text_path = output.join(QUALIFICATION_TEXT);
        let qualification_text = fs::read(&qualification_text_path)?;
        fs::write(&qualification_text_path, b"tampered\n")?;
        assert!(matches!(
            load_sizing(&output, &capture),
            Err(ArtifactError::InvalidArtifact {
                reason: "sizing text does not match the typed qualification"
            })
        ));
        fs::write(&qualification_text_path, qualification_text)?;

        fs::write(output.join("unexpected"), b"extra")?;
        assert!(matches!(
            load_sizing(&output, &capture),
            Err(ArtifactError::InvalidArtifact {
                reason: "artifact directory does not contain exactly the required files"
            })
        ));
        fs::remove_file(output.join("unexpected"))?;

        fs::remove_file(output.join(PROVENANCE_JSON))?;
        assert!(matches!(
            load_sizing(&output, &capture),
            Err(ArtifactError::InvalidArtifact {
                reason: "artifact directory does not contain exactly the required files"
            })
        ));

        let nested = capture_dir.join("sizing");
        assert!(matches!(
            publish_sizing(&nested, &capture, &qualification, "test-runner"),
            Err(ArtifactError::InvalidArtifact {
                reason: "sizing output must not be nested inside its capture input"
            })
        ));
        Ok(())
    }

    #[cfg(any(target_vendor = "apple", target_os = "linux"))]
    #[test]
    fn sizing_load_rejects_symlink_and_nonregular_entries_without_reading_them() -> TestResult {
        use std::os::unix::fs::symlink;

        let parent = tempfile::tempdir()?;
        let (_, capture) = publish_and_load_capture(parent.path())?;
        let qualification = capture.measurement().apply_model(&sizing_model(0)?)?;
        let sizing_dir = parent.path().join("sizing");
        publish_sizing(&sizing_dir, &capture, &qualification, "test-runner")?;

        let qualification_json = sizing_dir.join(QUALIFICATION_JSON);
        let original_json = fs::read(&qualification_json)?;
        fs::remove_file(&qualification_json)?;
        symlink(QUALIFICATION_TEXT, &qualification_json)?;
        assert!(matches!(
            load_sizing(&sizing_dir, &capture),
            Err(ArtifactError::NonRegularFile {
                name: QUALIFICATION_JSON
            })
        ));

        fs::remove_file(&qualification_json)?;
        fs::write(&qualification_json, original_json)?;
        let qualification_text = sizing_dir.join(QUALIFICATION_TEXT);
        fs::remove_file(&qualification_text)?;
        fs::create_dir(&qualification_text)?;
        assert!(matches!(
            load_sizing(&sizing_dir, &capture),
            Err(ArtifactError::NonRegularFile {
                name: QUALIFICATION_TEXT
            })
        ));
        Ok(())
    }

    #[cfg(any(target_vendor = "apple", target_os = "linux"))]
    #[test]
    fn capture_load_rejects_symlink_and_nonregular_entries_without_reading_them() -> TestResult {
        use std::os::unix::fs::symlink;

        let parent = tempfile::tempdir()?;
        let (capture_dir, _) = publish_and_load_capture(parent.path())?;
        let measurement_json = capture_dir.join(MEASUREMENT_JSON);
        let original_json = fs::read(&measurement_json)?;
        fs::remove_file(&measurement_json)?;
        symlink(MEASUREMENT_TEXT, &measurement_json)?;
        assert!(matches!(
            load_capture(&capture_dir),
            Err(ArtifactError::NonRegularFile {
                name: MEASUREMENT_JSON
            })
        ));

        fs::remove_file(&measurement_json)?;
        fs::write(&measurement_json, original_json)?;
        let measurement_text = capture_dir.join(MEASUREMENT_TEXT);
        fs::remove_file(&measurement_text)?;
        fs::create_dir(&measurement_text)?;
        assert!(matches!(
            load_capture(&capture_dir),
            Err(ArtifactError::NonRegularFile {
                name: MEASUREMENT_TEXT
            })
        ));
        Ok(())
    }

    #[test]
    fn artifact_reads_reject_every_oversized_capture_and_sizing_input() -> TestResult {
        let parent = tempfile::tempdir()?;
        let (capture_dir, capture) = publish_and_load_capture(parent.path())?;
        for (name, maximum_bytes) in [
            (MEASUREMENT_JSON, MAX_MEASUREMENT_JSON_BYTES),
            (MEASUREMENT_TEXT, MAX_MEASUREMENT_TEXT_BYTES),
            (PROVENANCE_JSON, MAX_PROVENANCE_JSON_BYTES),
        ] {
            let path = capture_dir.join(name);
            let original = fs::read(&path)?;
            replace_with_oversized_file(&path, maximum_bytes)?;
            assert!(matches!(
                load_capture(&capture_dir),
                Err(ArtifactError::FileTooLarge {
                    name: rejected,
                    maximum_bytes: rejected_maximum,
                }) if rejected == name && rejected_maximum == maximum_bytes
            ));
            fs::write(path, original)?;
        }

        let qualification = capture.measurement().apply_model(&sizing_model(0)?)?;
        let sizing_dir = parent.path().join("sizing");
        publish_sizing(&sizing_dir, &capture, &qualification, "test-runner")?;
        for (name, maximum_bytes) in [
            (QUALIFICATION_JSON, MAX_QUALIFICATION_JSON_BYTES),
            (QUALIFICATION_TEXT, MAX_QUALIFICATION_TEXT_BYTES),
            (PROVENANCE_JSON, MAX_PROVENANCE_JSON_BYTES),
        ] {
            let path = sizing_dir.join(name);
            let original = fs::read(&path)?;
            replace_with_oversized_file(&path, maximum_bytes)?;
            assert!(matches!(
                load_sizing(&sizing_dir, &capture),
                Err(ArtifactError::FileTooLarge {
                    name: rejected,
                    maximum_bytes: rejected_maximum,
                }) if rejected == name && rejected_maximum == maximum_bytes
            ));
            fs::write(path, original)?;
        }
        Ok(())
    }

    #[cfg(any(target_vendor = "apple", target_os = "linux"))]
    #[test]
    fn canonical_capture_identity_rejects_nested_output_through_symlink_alias() -> TestResult {
        use std::os::unix::fs::symlink;

        let parent = tempfile::tempdir()?;
        let (capture_dir, _) = publish_and_load_capture(parent.path())?;
        let alias = parent.path().join("capture-alias");
        symlink(&capture_dir, &alias)?;
        let capture = load_capture(&alias)?;
        let qualification = capture.measurement().apply_model(&sizing_model(0)?)?;

        assert!(matches!(
            publish_sizing(
                &alias.join("nested-sizing"),
                &capture,
                &qualification,
                "test-runner"
            ),
            Err(ArtifactError::InvalidArtifact {
                reason: "sizing output must not be nested inside its capture input"
            })
        ));
        Ok(())
    }

    #[cfg(all(
        feature = "typed-qualification",
        any(target_vendor = "apple", target_os = "linux")
    ))]
    #[test]
    fn derived_artifact_rejects_direct_and_symlink_nested_source_outputs() -> TestResult {
        use std::os::unix::fs::symlink;

        let parent = tempfile::tempdir()?;
        let (capture_dir, capture) = publish_and_load_capture(parent.path())?;
        let qualification = capture.measurement().apply_model(&sizing_model(0)?)?;
        let sizing_dir = parent.path().join("sizing");
        publish_sizing(&sizing_dir, &capture, &qualification, "test-runner")?;
        let sizing = load_sizing(&sizing_dir, &capture)?;

        assert!(matches!(
            publish_verified_derived_artifact(
                &capture_dir.join("nested-derived"),
                &capture,
                &sizing,
                &test_files(),
                |_| Ok(())
            ),
            Err(ArtifactError::InvalidArtifact {
                reason: "derived artifact output must not be nested inside its capture input"
            })
        ));
        assert!(matches!(
            publish_verified_derived_artifact(
                &sizing_dir.join("nested-derived"),
                &capture,
                &sizing,
                &test_files(),
                |_| Ok(())
            ),
            Err(ArtifactError::InvalidArtifact {
                reason: "derived artifact output must not be nested inside its sizing input"
            })
        ));

        let capture_alias = parent.path().join("capture-alias");
        let sizing_alias = parent.path().join("sizing-alias");
        symlink(&capture_dir, &capture_alias)?;
        symlink(&sizing_dir, &sizing_alias)?;
        assert!(matches!(
            publish_verified_derived_artifact(
                &capture_alias.join("nested-derived"),
                &capture,
                &sizing,
                &test_files(),
                |_| Ok(())
            ),
            Err(ArtifactError::InvalidArtifact {
                reason: "derived artifact output must not be nested inside its capture input"
            })
        ));
        assert!(matches!(
            publish_verified_derived_artifact(
                &sizing_alias.join("nested-derived"),
                &capture,
                &sizing,
                &test_files(),
                |_| Ok(())
            ),
            Err(ArtifactError::InvalidArtifact {
                reason: "derived artifact output must not be nested inside its sizing input"
            })
        ));
        Ok(())
    }

    #[test]
    fn typed_validation_rejects_digest_schema_and_file_set_tampering() -> TestResult {
        let parent = tempfile::tempdir()?;
        let output = parent.path().join("capture");
        let measurement = typed_test_measurement()?;
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
            validate_test_capture_path(&output, &artifact, &provenance.inner),
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

        let result = publish_verified_directory(&output, &files, PublishFailpoint::None, |stage| {
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

        let result =
            publish_verified_directory(&output, &files, PublishFailpoint::BeforePublish, |stage| {
                validate_test_files(stage, &files)
            });

        assert!(matches!(result, Err(ArtifactError::OutputExists)));
        assert!(output.is_dir());
        assert_eq!(fs::read_dir(&output)?.count(), 0);
        assert!(sibling_stages(parent.path(), "capture")?.is_empty());
        Ok(())
    }

    #[test]
    fn committed_rename_error_is_resolved_without_deleting_published_files() -> TestResult {
        let parent = tempfile::tempdir()?;
        let output = parent.path().join("capture");
        let files = test_files();

        publish_verified_directory(
            &output,
            &files,
            PublishFailpoint::AfterCommittedRenameError,
            |stage| validate_test_files(stage, &files),
        )?;

        validate_test_files_path(&output, &files)?;
        assert!(sibling_stages(parent.path(), "capture")?.is_empty());
        Ok(())
    }

    #[test]
    fn injected_failure_cleans_owned_stage() -> TestResult {
        let parent = tempfile::tempdir()?;
        let output = parent.path().join("capture");
        let files = test_files();

        let result = publish_verified_directory(
            &output,
            &files,
            PublishFailpoint::AfterFirstFile,
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
        let directory = open_artifact_directory(parent.path())?;
        write_synced_file(&directory, files[0].name, &files[0].bytes)?;
        write_synced_file(&directory, files[1].name, b"tampered\n")?;
        write_synced_file(&directory, files[2].name, &files[2].bytes)?;

        assert!(matches!(
            validate_test_files(&directory, &files),
            Err(ArtifactError::InvalidArtifact {
                reason: "test read-back mismatch"
            })
        ));
        Ok(())
    }
}
