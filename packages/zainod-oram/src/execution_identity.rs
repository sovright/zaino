//! Self-reported build receipts for listener-free ORAM qualification binaries.

use std::{
    collections::HashSet,
    error::Error,
    ffi::{OsStr, OsString},
    fmt,
    fs::{self, File},
    io::{self, Read, Seek, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

#[cfg(any(target_vendor = "apple", target_os = "linux"))]
use rustix::fs::{
    fsync, open, openat, renameat_with, statat, unlinkat, AtFlags, Mode, OFlags, RenameFlags,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::corpus_artifact::artifact_blake2s256_hex;

const RECEIPT_SCHEMA: &str = "zaino-oram-release-receipt-v1";
const PRODUCT: &str = "zainod-oram";
const BINARY_NAME: &str = "zainod-oram";
const TARGET_TRIPLE: &str = "x86_64-unknown-linux-musl";
const BUILD_PROFILE: &str = "release";
const FEATURES: &str = "typed-qualification";
const RUSTFLAGS: &str = "-C codegen-units=1 -C target-feature=+crt-static -C linker=clang -C link-arg=-fuse-ld=mold -C link-arg=/usr/lib/libc++.a -C link-arg=/usr/lib/libc++abi.a -C link-arg=-Wl,--build-id=none";
const SOURCE_DATE_EPOCH: u64 = 1;
const OBSERVED_BUILD_ARTIFACT_COUNT: u8 = 2;
const TRUST_CLASSIFICATION: &str = "self-reported-procedure-local-integrity-and-identity-only-v1";
const SHA256_HEX_BYTES: usize = 64;
const SOURCE_REVISION_HEX_BYTES: usize = 40;
const MAX_SOURCE_ARCHIVE_BYTES: usize = 512 * 1024 * 1024;
const MAX_CARGO_LOCK_BYTES: usize = 16 * 1024 * 1024;
const MAX_RUST_TOOLCHAIN_BYTES: usize = 64 * 1024;
const MAX_DOCKERFILE_BYTES: usize = 4 * 1024 * 1024;
const MAX_BINARY_BYTES: usize = 512 * 1024 * 1024;
const MAX_RECEIPT_BYTES: usize = 64 * 1024;
const MAX_GLOBAL_PAX_BYTES: u64 = 16 * 1024;
const READ_BUFFER_BYTES: usize = 64 * 1024;
const MAX_STAGE_ATTEMPTS: u64 = 128;
const ARCHIVE_CARGO_LOCK: &[u8] = b"Cargo.lock";
const ARCHIVE_RUST_TOOLCHAIN: &[u8] = b"rust-toolchain.toml";
const ARCHIVE_DOCKERFILE: &[u8] = b"Dockerfile.deterministic";

static NEXT_STAGE_ID: AtomicU64 = AtomicU64::new(0);

/// Inputs accepted by the fixed release-receipt constructor.
pub(super) struct ReleaseReceiptInputs {
    pub(super) source_revision: String,
    pub(super) source_archive: PathBuf,
    pub(super) cargo_lock: PathBuf,
    pub(super) rust_toolchain: PathBuf,
    pub(super) dockerfile: PathBuf,
    pub(super) binary: PathBuf,
    pub(super) reproducible_binary: PathBuf,
    pub(super) output: PathBuf,
}

/// Canonical release receipt verified against the currently running executable.
pub(super) struct VerifiedReleaseReceipt {
    canonical_bytes: Vec<u8>,
    metadata: ReleaseReceiptMetadata,
}

/// Fields a canonical receipt binds independently of executable admission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ReleaseReceiptMetadata {
    receipt_blake2s256: String,
    source_revision: String,
    binary_sha256: String,
    binary_size_bytes: u64,
}

impl VerifiedReleaseReceipt {
    pub(super) fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub(super) const fn metadata(&self) -> &ReleaseReceiptMetadata {
        &self.metadata
    }
}

impl ReleaseReceiptMetadata {
    pub(super) fn receipt_blake2s256(&self) -> &str {
        &self.receipt_blake2s256
    }

    pub(super) fn source_revision(&self) -> &str {
        &self.source_revision
    }

    pub(super) fn binary_sha256(&self) -> &str {
        &self.binary_sha256
    }

    pub(super) const fn binary_size_bytes(&self) -> u64 {
        self.binary_size_bytes
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseReceiptV1 {
    schema: String,
    product: String,
    binary_name: String,
    source_revision: String,
    clean_tree_self_reported: bool,
    observed_build_artifact_count: u8,
    observed_distinct_binary_inodes: bool,
    observed_binary_digest_agreement: bool,
    signed: bool,
    execution_attested: bool,
    physical_trace_measured: bool,
    source_derivation_attested: bool,
    trust_classification: String,
    source_archive_sha256: String,
    cargo_lock_sha256: String,
    rust_toolchain_sha256: String,
    deterministic_dockerfile_sha256: String,
    binary_sha256: String,
    binary_size_bytes: u64,
    target_triple: String,
    build_profile: String,
    features: String,
    rustflags: String,
    source_date_epoch: u64,
}

impl ReleaseReceiptV1 {
    fn new(
        source_revision: String,
        source_archive_sha256: String,
        cargo_lock_sha256: String,
        rust_toolchain_sha256: String,
        deterministic_dockerfile_sha256: String,
        binary_sha256: String,
        binary_size_bytes: u64,
    ) -> Result<Self, ReleaseReceiptError> {
        let receipt = Self {
            schema: RECEIPT_SCHEMA.to_owned(),
            product: PRODUCT.to_owned(),
            binary_name: BINARY_NAME.to_owned(),
            source_revision,
            clean_tree_self_reported: true,
            observed_build_artifact_count: OBSERVED_BUILD_ARTIFACT_COUNT,
            observed_distinct_binary_inodes: true,
            observed_binary_digest_agreement: true,
            signed: false,
            execution_attested: false,
            physical_trace_measured: false,
            source_derivation_attested: false,
            trust_classification: TRUST_CLASSIFICATION.to_owned(),
            source_archive_sha256,
            cargo_lock_sha256,
            rust_toolchain_sha256,
            deterministic_dockerfile_sha256,
            binary_sha256,
            binary_size_bytes,
            target_triple: TARGET_TRIPLE.to_owned(),
            build_profile: BUILD_PROFILE.to_owned(),
            features: FEATURES.to_owned(),
            rustflags: RUSTFLAGS.to_owned(),
            source_date_epoch: SOURCE_DATE_EPOCH,
        };
        receipt.validate()?;
        Ok(receipt)
    }

    fn validate(&self) -> Result<(), ReleaseReceiptError> {
        if self.schema != RECEIPT_SCHEMA
            || self.product != PRODUCT
            || self.binary_name != BINARY_NAME
            || !self.clean_tree_self_reported
            || self.observed_build_artifact_count != OBSERVED_BUILD_ARTIFACT_COUNT
            || !self.observed_distinct_binary_inodes
            || !self.observed_binary_digest_agreement
            || self.signed
            || self.execution_attested
            || self.physical_trace_measured
            || self.source_derivation_attested
            || self.trust_classification != TRUST_CLASSIFICATION
            || self.target_triple != TARGET_TRIPLE
            || self.build_profile != BUILD_PROFILE
            || self.features != FEATURES
            || self.rustflags != RUSTFLAGS
            || self.source_date_epoch != SOURCE_DATE_EPOCH
            || self.binary_size_bytes == 0
            || self.binary_size_bytes > MAX_BINARY_BYTES as u64
        {
            return Err(ReleaseReceiptError::InvalidFixedBuildIdentity);
        }
        validate_lower_hex(
            &self.source_revision,
            SOURCE_REVISION_HEX_BYTES,
            ReleaseReceiptError::InvalidSourceRevision,
        )?;
        for digest in [
            &self.source_archive_sha256,
            &self.cargo_lock_sha256,
            &self.rust_toolchain_sha256,
            &self.deterministic_dockerfile_sha256,
            &self.binary_sha256,
        ] {
            validate_lower_hex(digest, SHA256_HEX_BYTES, ReleaseReceiptError::InvalidDigest)?;
        }
        Ok(())
    }

    fn canonical_bytes(&self) -> Result<Vec<u8>, ReleaseReceiptError> {
        serde_json::to_vec(self).map_err(ReleaseReceiptError::Json)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum FileRole {
    SourceArchive,
    CargoLock,
    RustToolchain,
    Dockerfile,
    Binary,
    ReproducibleBinary,
    Receipt,
    RunningExecutable,
}

impl FileRole {
    const fn label(self) -> &'static str {
        match self {
            Self::SourceArchive => "source archive",
            Self::CargoLock => "Cargo.lock",
            Self::RustToolchain => "rust-toolchain.toml",
            Self::Dockerfile => "Dockerfile.deterministic",
            Self::Binary => "primary binary",
            Self::ReproducibleBinary => "second no-cache build artifact",
            Self::Receipt => "release receipt",
            Self::RunningExecutable => "running executable",
        }
    }

    const fn maximum_bytes(self) -> usize {
        match self {
            Self::SourceArchive => MAX_SOURCE_ARCHIVE_BYTES,
            Self::CargoLock => MAX_CARGO_LOCK_BYTES,
            Self::RustToolchain => MAX_RUST_TOOLCHAIN_BYTES,
            Self::Dockerfile => MAX_DOCKERFILE_BYTES,
            Self::Binary | Self::ReproducibleBinary | Self::RunningExecutable => MAX_BINARY_BYTES,
            Self::Receipt => MAX_RECEIPT_BYTES,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct OpenedDigest {
    sha256: String,
    device: u64,
    inode: u64,
    size_bytes: u64,
}

struct OpenedBytes {
    digest: OpenedDigest,
    bytes: Vec<u8>,
}

struct ArchiveInputs<'a> {
    cargo_lock: &'a [u8],
    rust_toolchain: &'a [u8],
    dockerfile: &'a [u8],
}

#[cfg(any(target_vendor = "apple", target_os = "linux"))]
struct ReceiptOutput {
    parent: std::os::fd::OwnedFd,
    name: OsString,
}

/// Creates one self-reported receipt bound to the invoking executable.
pub(super) fn create_release_receipt(
    inputs: ReleaseReceiptInputs,
) -> Result<(), ReleaseReceiptError> {
    if !current_build_supports_executable_identity() {
        return Err(ReleaseReceiptError::UnsupportedExecutableIdentityBuild);
    }
    let creator = hash_opened_file(open_running_executable()?, FileRole::RunningExecutable)?;
    create_release_receipt_for_creator(inputs, creator)
}

fn create_release_receipt_for_creator(
    inputs: ReleaseReceiptInputs,
    creator: OpenedDigest,
) -> Result<(), ReleaseReceiptError> {
    validate_lower_hex(
        &inputs.source_revision,
        SOURCE_REVISION_HEX_BYTES,
        ReleaseReceiptError::InvalidSourceRevision,
    )?;
    let cargo_lock = read_path(&inputs.cargo_lock, FileRole::CargoLock)?;
    let rust_toolchain = read_path(&inputs.rust_toolchain, FileRole::RustToolchain)?;
    let dockerfile = read_path(&inputs.dockerfile, FileRole::Dockerfile)?;
    let source_archive = inspect_source_archive(
        &inputs.source_archive,
        &inputs.source_revision,
        ArchiveInputs {
            cargo_lock: &cargo_lock.bytes,
            rust_toolchain: &rust_toolchain.bytes,
            dockerfile: &dockerfile.bytes,
        },
    )?;
    let binary = hash_path(&inputs.binary, FileRole::Binary)?;
    let reproduced = hash_path(&inputs.reproducible_binary, FileRole::ReproducibleBinary)?;
    if creator.sha256 != binary.sha256 || creator.size_bytes != binary.size_bytes {
        return Err(ReleaseReceiptError::ReceiptCreatorMismatch);
    }
    if binary.device == reproduced.device && binary.inode == reproduced.inode {
        return Err(ReleaseReceiptError::ObservedBuildFilesShareInode);
    }
    if binary.sha256 != reproduced.sha256 || binary.size_bytes != reproduced.size_bytes {
        return Err(ReleaseReceiptError::ObservedBuildDigestMismatch);
    }

    let receipt = ReleaseReceiptV1::new(
        inputs.source_revision,
        source_archive.sha256,
        cargo_lock.digest.sha256,
        rust_toolchain.digest.sha256,
        dockerfile.digest.sha256,
        binary.sha256,
        binary.size_bytes,
    )?;
    let bytes = receipt.canonical_bytes()?;
    publish_receipt(&inputs.output, &bytes, &receipt)?;
    let published = load_release_receipt(&inputs.output)?;
    if published != receipt {
        return Err(ReleaseReceiptError::PublishedReadbackMismatch);
    }
    Ok(())
}

/// Checks local receipt integrity and running-executable identity only.
pub(super) fn verify_release_receipt(path: &Path) -> Result<(), ReleaseReceiptError> {
    verify_release_receipt_binding(path).map(|_| ())
}

/// Checks the receipt and returns the exact canonical bytes and executable binding.
pub(super) fn verify_release_receipt_binding(
    path: &Path,
) -> Result<VerifiedReleaseReceipt, ReleaseReceiptError> {
    if !current_build_supports_executable_identity() {
        return Err(ReleaseReceiptError::UnsupportedExecutableIdentityBuild);
    }
    let executable = open_running_executable()?;
    let digest = hash_opened_file(executable, FileRole::RunningExecutable)?;
    verify_release_receipt_for_executable(path, &digest)
}

fn verify_release_receipt_for_executable(
    path: &Path,
    executable: &OpenedDigest,
) -> Result<VerifiedReleaseReceipt, ReleaseReceiptError> {
    let (receipt, canonical_bytes) = load_release_receipt_with_bytes(path)?;
    verify_executable_identity(&receipt, executable)?;
    let metadata = release_receipt_metadata(&receipt, &canonical_bytes);
    Ok(VerifiedReleaseReceipt {
        canonical_bytes,
        metadata,
    })
}

/// Parses and validates exact canonical receipt bytes without admitting an executable.
pub(super) fn release_receipt_metadata_from_canonical_bytes(
    bytes: &[u8],
) -> Result<ReleaseReceiptMetadata, ReleaseReceiptError> {
    let receipt = load_receipt_from_bytes(bytes)?;
    Ok(release_receipt_metadata(&receipt, bytes))
}

fn release_receipt_metadata(
    receipt: &ReleaseReceiptV1,
    canonical_bytes: &[u8],
) -> ReleaseReceiptMetadata {
    ReleaseReceiptMetadata {
        receipt_blake2s256: artifact_blake2s256_hex(canonical_bytes),
        source_revision: receipt.source_revision.clone(),
        binary_sha256: receipt.binary_sha256.clone(),
        binary_size_bytes: receipt.binary_size_bytes,
    }
}

fn current_build_supports_executable_identity() -> bool {
    is_supported_executable_identity_build(
        std::env::consts::OS,
        std::env::consts::ARCH,
        cfg!(target_env = "musl"),
        cfg!(feature = "typed-qualification"),
        !cfg!(debug_assertions),
    )
}

fn is_supported_executable_identity_build(
    os: &str,
    arch: &str,
    target_is_musl: bool,
    typed_qualification_enabled: bool,
    release_profile: bool,
) -> bool {
    os == "linux"
        && arch == "x86_64"
        && target_is_musl
        && typed_qualification_enabled
        && release_profile
}

fn verify_executable_identity(
    receipt: &ReleaseReceiptV1,
    actual: &OpenedDigest,
) -> Result<(), ReleaseReceiptError> {
    if receipt.binary_sha256 == actual.sha256 && receipt.binary_size_bytes == actual.size_bytes {
        Ok(())
    } else {
        Err(ReleaseReceiptError::RunningExecutableMismatch)
    }
}

fn validate_lower_hex(
    value: &str,
    expected_len: usize,
    error: ReleaseReceiptError,
) -> Result<(), ReleaseReceiptError> {
    if value.len() != expected_len
        || value.bytes().all(|byte| byte == b'0')
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Err(error)
    } else {
        Ok(())
    }
}

#[cfg(any(target_vendor = "apple", target_os = "linux"))]
fn open_regular_path(path: &Path, role: FileRole) -> Result<File, ReleaseReceiptError> {
    let fd = open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|source| map_open_error(source, role))?;
    let file = File::from(fd);
    validate_opened_file(&file, role)?;
    Ok(file)
}

#[cfg(not(any(target_vendor = "apple", target_os = "linux")))]
fn open_regular_path(_path: &Path, _role: FileRole) -> Result<File, ReleaseReceiptError> {
    Err(ReleaseReceiptError::UnsupportedFilesystemHost)
}

#[cfg(target_os = "linux")]
fn open_running_executable() -> Result<File, ReleaseReceiptError> {
    let fd = open(
        "/proc/self/exe",
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|source| ReleaseReceiptError::Io {
        operation: "open running /proc/self/exe inode",
        source: source.into(),
    })?;
    let file = File::from(fd);
    validate_opened_file(&file, FileRole::RunningExecutable)?;
    Ok(file)
}

#[cfg(not(target_os = "linux"))]
fn open_running_executable() -> Result<File, ReleaseReceiptError> {
    Err(ReleaseReceiptError::UnsupportedExecutableIdentityBuild)
}

fn validate_opened_file(file: &File, role: FileRole) -> Result<(), ReleaseReceiptError> {
    let metadata = file.metadata().map_err(|source| ReleaseReceiptError::Io {
        operation: "inspect opened release input",
        source,
    })?;
    if !metadata.is_file() {
        return Err(ReleaseReceiptError::NonRegularFile { role });
    }
    if metadata.len() == 0 {
        return Err(ReleaseReceiptError::EmptyFile { role });
    }
    if metadata.len() > role.maximum_bytes() as u64 {
        return Err(ReleaseReceiptError::FileTooLarge {
            role,
            maximum_bytes: role.maximum_bytes(),
        });
    }
    Ok(())
}

fn hash_path(path: &Path, role: FileRole) -> Result<OpenedDigest, ReleaseReceiptError> {
    hash_opened_file(open_regular_path(path, role)?, role)
}

#[cfg(unix)]
fn hash_opened_file(mut file: File, role: FileRole) -> Result<OpenedDigest, ReleaseReceiptError> {
    let before = metadata_snapshot(&file, "inspect release input before hashing")?;
    let (sha256, total) = hash_reader(&mut file, role)?;
    let after = metadata_snapshot(&file, "inspect release input after hashing")?;
    ensure_unchanged(&before, &after, total, role)?;
    Ok(OpenedDigest {
        sha256,
        device: after.device,
        inode: after.inode,
        size_bytes: after.size_bytes,
    })
}

#[cfg(not(unix))]
fn hash_opened_file(_file: File, _role: FileRole) -> Result<OpenedDigest, ReleaseReceiptError> {
    Err(ReleaseReceiptError::UnsupportedFilesystemHost)
}

fn hash_reader(
    reader: &mut impl Read,
    role: FileRole,
) -> Result<(String, u64), ReleaseReceiptError> {
    let mut hasher = Sha256::new();
    let mut total = 0u64;
    let mut buffer = [0u8; READ_BUFFER_BYTES];
    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(|source| ReleaseReceiptError::Io {
                operation: "hash bounded release input",
                source,
            })?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .ok_or(ReleaseReceiptError::FileTooLarge {
                role,
                maximum_bytes: role.maximum_bytes(),
            })?;
        if total > role.maximum_bytes() as u64 {
            return Err(ReleaseReceiptError::FileTooLarge {
                role,
                maximum_bytes: role.maximum_bytes(),
            });
        }
        hasher.update(&buffer[..read]);
    }
    if total == 0 {
        return Err(ReleaseReceiptError::EmptyFile { role });
    }
    Ok((hex::encode(hasher.finalize()), total))
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct MetadataSnapshot {
    device: u64,
    inode: u64,
    size_bytes: u64,
    mode: u32,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

#[cfg(unix)]
fn metadata_snapshot(
    file: &File,
    operation: &'static str,
) -> Result<MetadataSnapshot, ReleaseReceiptError> {
    use std::os::unix::fs::MetadataExt as _;

    let metadata = file
        .metadata()
        .map_err(|source| ReleaseReceiptError::Io { operation, source })?;
    Ok(MetadataSnapshot {
        device: metadata.dev(),
        inode: metadata.ino(),
        size_bytes: metadata.len(),
        mode: metadata.mode(),
        modified_seconds: metadata.mtime(),
        modified_nanoseconds: metadata.mtime_nsec(),
        changed_seconds: metadata.ctime(),
        changed_nanoseconds: metadata.ctime_nsec(),
    })
}

#[cfg(unix)]
fn ensure_unchanged(
    before: &MetadataSnapshot,
    after: &MetadataSnapshot,
    bytes_read: u64,
    role: FileRole,
) -> Result<(), ReleaseReceiptError> {
    if before != after || bytes_read != after.size_bytes {
        Err(ReleaseReceiptError::FileChangedDuringRead { role })
    } else {
        Ok(())
    }
}

fn read_path(path: &Path, role: FileRole) -> Result<OpenedBytes, ReleaseReceiptError> {
    read_opened_file(open_regular_path(path, role)?, role)
}

#[cfg(unix)]
fn read_opened_file(mut file: File, role: FileRole) -> Result<OpenedBytes, ReleaseReceiptError> {
    validate_opened_file(&file, role)?;
    let before = metadata_snapshot(&file, "inspect release input before reading")?;
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(role.maximum_bytes() as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| ReleaseReceiptError::Io {
            operation: "read bounded release input",
            source,
        })?;
    if bytes.len() > role.maximum_bytes() {
        return Err(ReleaseReceiptError::FileTooLarge {
            role,
            maximum_bytes: role.maximum_bytes(),
        });
    }
    if bytes.is_empty() {
        return Err(ReleaseReceiptError::EmptyFile { role });
    }
    let after = metadata_snapshot(&file, "inspect release input after reading")?;
    ensure_unchanged(&before, &after, bytes.len() as u64, role)?;
    Ok(OpenedBytes {
        digest: OpenedDigest {
            sha256: sha256_hex(&bytes),
            device: after.device,
            inode: after.inode,
            size_bytes: after.size_bytes,
        },
        bytes,
    })
}

#[cfg(not(unix))]
fn read_opened_file(_file: File, _role: FileRole) -> Result<OpenedBytes, ReleaseReceiptError> {
    Err(ReleaseReceiptError::UnsupportedFilesystemHost)
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[cfg(unix)]
fn inspect_source_archive(
    path: &Path,
    source_revision: &str,
    expected: ArchiveInputs<'_>,
) -> Result<OpenedDigest, ReleaseReceiptError> {
    let mut file = open_regular_path(path, FileRole::SourceArchive)?;
    let before = metadata_snapshot(&file, "inspect source archive before reading")?;
    let (sha256, bytes_read) = hash_reader(&mut file, FileRole::SourceArchive)?;
    rewind_archive(&mut file)?;
    validate_archive_revision(&mut file, source_revision)?;
    rewind_archive(&mut file)?;
    validate_archive_inputs(&mut file, expected)?;
    let after = metadata_snapshot(&file, "inspect source archive after reading")?;
    ensure_unchanged(&before, &after, bytes_read, FileRole::SourceArchive)?;
    Ok(OpenedDigest {
        sha256,
        device: after.device,
        inode: after.inode,
        size_bytes: after.size_bytes,
    })
}

#[cfg(not(unix))]
fn inspect_source_archive(
    _path: &Path,
    _source_revision: &str,
    _expected: ArchiveInputs<'_>,
) -> Result<OpenedDigest, ReleaseReceiptError> {
    Err(ReleaseReceiptError::UnsupportedFilesystemHost)
}

fn rewind_archive(file: &mut File) -> Result<(), ReleaseReceiptError> {
    file.rewind().map_err(|source| ReleaseReceiptError::Io {
        operation: "rewind source archive",
        source,
    })
}

fn validate_archive_revision(
    file: &mut File,
    source_revision: &str,
) -> Result<(), ReleaseReceiptError> {
    let mut archive = tar::Archive::new(file);
    archive.set_ignore_zeros(true);
    let entries = archive
        .entries()
        .map_err(|source| ReleaseReceiptError::Archive {
            operation: "read raw source archive entries",
            source,
        })?
        .raw(true);
    let mut global_header_seen = false;
    let mut archive_revision: Option<Vec<u8>> = None;
    for entry in entries {
        let mut entry = entry.map_err(|source| ReleaseReceiptError::Archive {
            operation: "read raw source archive entry",
            source,
        })?;
        if !entry.header().entry_type().is_pax_global_extensions() {
            continue;
        }
        if global_header_seen {
            return Err(ReleaseReceiptError::DuplicateArchiveRevisionHeader);
        }
        global_header_seen = true;
        if entry.size() > MAX_GLOBAL_PAX_BYTES {
            return Err(ReleaseReceiptError::ArchiveRevisionHeaderTooLarge);
        }
        let extensions = entry
            .pax_extensions()
            .map_err(|source| ReleaseReceiptError::Archive {
                operation: "read source archive global PAX header",
                source,
            })?
            .ok_or(ReleaseReceiptError::MissingArchiveRevision)?;
        for extension in extensions {
            let extension = extension.map_err(|source| ReleaseReceiptError::Archive {
                operation: "parse source archive global PAX header",
                source,
            })?;
            if extension.key_bytes() == b"comment" {
                if archive_revision.is_some() {
                    return Err(ReleaseReceiptError::DuplicateArchiveRevisionHeader);
                }
                archive_revision = Some(extension.value_bytes().to_vec());
            }
        }
    }
    let archive_revision = archive_revision.ok_or(ReleaseReceiptError::MissingArchiveRevision)?;
    if archive_revision != source_revision.as_bytes() {
        return Err(ReleaseReceiptError::ArchiveRevisionMismatch);
    }
    validate_lower_hex(
        source_revision,
        SOURCE_REVISION_HEX_BYTES,
        ReleaseReceiptError::InvalidSourceRevision,
    )
}

fn validate_archive_inputs(
    file: &mut File,
    expected: ArchiveInputs<'_>,
) -> Result<(), ReleaseReceiptError> {
    let mut archive = tar::Archive::new(file);
    archive.set_ignore_zeros(true);
    let entries = archive
        .entries()
        .map_err(|source| ReleaseReceiptError::Archive {
            operation: "read source archive entries",
            source,
        })?;
    let mut paths = HashSet::new();
    let mut cargo_lock_seen = false;
    let mut rust_toolchain_seen = false;
    let mut dockerfile_seen = false;
    for entry in entries {
        let mut entry = entry.map_err(|source| ReleaseReceiptError::Archive {
            operation: "read source archive entry",
            source,
        })?;
        if entry.header().entry_type().is_pax_global_extensions() {
            continue;
        }
        let path = canonical_archive_path(
            entry.path_bytes().as_ref(),
            entry.header().entry_type().is_dir(),
        )?;
        if !paths.insert(path.clone()) {
            return Err(ReleaseReceiptError::DuplicateArchivePath);
        }
        match path.as_slice() {
            ARCHIVE_CARGO_LOCK => {
                validate_embedded_input(&mut entry, FileRole::CargoLock, expected.cargo_lock)?;
                cargo_lock_seen = true;
            }
            ARCHIVE_RUST_TOOLCHAIN => {
                validate_embedded_input(
                    &mut entry,
                    FileRole::RustToolchain,
                    expected.rust_toolchain,
                )?;
                rust_toolchain_seen = true;
            }
            ARCHIVE_DOCKERFILE => {
                validate_embedded_input(&mut entry, FileRole::Dockerfile, expected.dockerfile)?;
                dockerfile_seen = true;
            }
            _ => {}
        }
    }
    for (seen, role) in [
        (cargo_lock_seen, FileRole::CargoLock),
        (rust_toolchain_seen, FileRole::RustToolchain),
        (dockerfile_seen, FileRole::Dockerfile),
    ] {
        if !seen {
            return Err(ReleaseReceiptError::MissingArchiveInput { role });
        }
    }
    Ok(())
}

fn canonical_archive_path(path: &[u8], directory: bool) -> Result<Vec<u8>, ReleaseReceiptError> {
    if path.is_empty() || path.starts_with(b"/") || path.contains(&b'\\') || path.contains(&0) {
        return Err(ReleaseReceiptError::ConfusedArchivePath);
    }
    let canonical = if path.ends_with(b"/") {
        if !directory {
            return Err(ReleaseReceiptError::ConfusedArchivePath);
        }
        &path[..path.len() - 1]
    } else {
        path
    };
    if canonical.is_empty()
        || canonical
            .split(|byte| *byte == b'/')
            .any(|component| component.is_empty() || component == b"." || component == b"..")
    {
        return Err(ReleaseReceiptError::ConfusedArchivePath);
    }
    Ok(canonical.to_vec())
}

fn validate_embedded_input<R: Read>(
    entry: &mut tar::Entry<'_, R>,
    role: FileRole,
    expected: &[u8],
) -> Result<(), ReleaseReceiptError> {
    if !entry.header().entry_type().is_file() {
        return Err(ReleaseReceiptError::NonRegularArchiveInput { role });
    }
    if entry.size() > role.maximum_bytes() as u64 {
        return Err(ReleaseReceiptError::FileTooLarge {
            role,
            maximum_bytes: role.maximum_bytes(),
        });
    }
    if entry.size() != expected.len() as u64 {
        return Err(ReleaseReceiptError::ArchiveInputMismatch { role });
    }
    let mut bytes = Vec::new();
    entry
        .take(role.maximum_bytes() as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| ReleaseReceiptError::Archive {
            operation: "read embedded source archive input",
            source,
        })?;
    if bytes != expected {
        return Err(ReleaseReceiptError::ArchiveInputMismatch { role });
    }
    Ok(())
}

fn load_release_receipt(path: &Path) -> Result<ReleaseReceiptV1, ReleaseReceiptError> {
    load_release_receipt_with_bytes(path).map(|(receipt, _)| receipt)
}

fn load_release_receipt_with_bytes(
    path: &Path,
) -> Result<(ReleaseReceiptV1, Vec<u8>), ReleaseReceiptError> {
    let file = open_regular_path(path, FileRole::Receipt)?;
    let bytes = read_opened_file(file, FileRole::Receipt)?.bytes;
    let receipt = load_receipt_from_bytes(&bytes)?;
    Ok((receipt, bytes))
}

fn load_receipt_from_file(file: File) -> Result<ReleaseReceiptV1, ReleaseReceiptError> {
    let bytes = read_opened_file(file, FileRole::Receipt)?.bytes;
    load_receipt_from_bytes(&bytes)
}

fn load_receipt_from_bytes(bytes: &[u8]) -> Result<ReleaseReceiptV1, ReleaseReceiptError> {
    let receipt: ReleaseReceiptV1 =
        serde_json::from_slice(bytes).map_err(ReleaseReceiptError::Json)?;
    receipt.validate()?;
    if receipt.canonical_bytes()? != bytes {
        return Err(ReleaseReceiptError::NonCanonicalJson);
    }
    Ok(receipt)
}

#[cfg(test)]
pub(super) fn canonical_test_release_receipt() -> Result<Vec<u8>, ReleaseReceiptError> {
    let digest = "1".repeat(SHA256_HEX_BYTES);
    ReleaseReceiptV1::new(
        "0123456789abcdef0123456789abcdef01234567".to_owned(),
        digest.clone(),
        digest.clone(),
        digest.clone(),
        digest.clone(),
        digest,
        1_024,
    )?
    .canonical_bytes()
}

#[cfg(any(target_vendor = "apple", target_os = "linux"))]
fn publish_receipt(
    output_path: &Path,
    bytes: &[u8],
    expected: &ReleaseReceiptV1,
) -> Result<(), ReleaseReceiptError> {
    let output = open_receipt_output(output_path)?;
    ensure_output_absent(&output)?;
    for _ in 0..MAX_STAGE_ATTEMPTS {
        let stage_name = next_stage_name();
        let fd = match openat(
            &output.parent,
            stage_name.as_os_str(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        ) {
            Ok(fd) => fd,
            Err(source) if source == rustix::io::Errno::EXIST => continue,
            Err(source) => {
                return Err(ReleaseReceiptError::Io {
                    operation: "create staged release receipt",
                    source: source.into(),
                });
            }
        };
        let mut stage = File::from(fd);
        let staged_result = (|| {
            stage
                .write_all(bytes)
                .map_err(|source| ReleaseReceiptError::Io {
                    operation: "write staged release receipt",
                    source,
                })?;
            stage.sync_all().map_err(|source| ReleaseReceiptError::Io {
                operation: "synchronize staged release receipt",
                source,
            })?;
            drop(stage);
            let staged = load_receipt_at(&output.parent, stage_name.as_os_str())?;
            if staged != *expected {
                return Err(ReleaseReceiptError::StagedReadbackMismatch);
            }
            renameat_with(
                &output.parent,
                stage_name.as_os_str(),
                &output.parent,
                output.name.as_os_str(),
                RenameFlags::NOREPLACE,
            )
            .map_err(|source| {
                if source == rustix::io::Errno::EXIST {
                    ReleaseReceiptError::OutputExists
                } else {
                    ReleaseReceiptError::Io {
                        operation: "publish release receipt without replacement",
                        source: source.into(),
                    }
                }
            })?;
            fsync(&output.parent).map_err(|source| {
                ReleaseReceiptError::PublishedButDurabilityUncertain {
                    source: source.into(),
                }
            })?;
            Ok(())
        })();
        if staged_result.is_err() {
            let _ = unlinkat(&output.parent, stage_name.as_os_str(), AtFlags::empty());
        }
        staged_result?;
        let published = load_receipt_at(&output.parent, output.name.as_os_str())?;
        if published != *expected {
            return Err(ReleaseReceiptError::PublishedReadbackMismatch);
        }
        return Ok(());
    }
    Err(ReleaseReceiptError::StageNameExhausted)
}

#[cfg(not(any(target_vendor = "apple", target_os = "linux")))]
fn publish_receipt(
    _output_path: &Path,
    _bytes: &[u8],
    _expected: &ReleaseReceiptV1,
) -> Result<(), ReleaseReceiptError> {
    Err(ReleaseReceiptError::UnsupportedFilesystemHost)
}

#[cfg(any(target_vendor = "apple", target_os = "linux"))]
fn open_receipt_output(path: &Path) -> Result<ReceiptOutput, ReleaseReceiptError> {
    let name = path
        .file_name()
        .ok_or(ReleaseReceiptError::InvalidOutputPath)?
        .to_owned();
    if name.is_empty() || name == OsStr::new(".") || name == OsStr::new("..") {
        return Err(ReleaseReceiptError::InvalidOutputPath);
    }
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let parent = if parent.as_os_str().is_empty() {
        Path::new(".")
    } else {
        parent
    };
    let canonical_parent = fs::canonicalize(parent).map_err(|source| ReleaseReceiptError::Io {
        operation: "canonicalize release receipt output parent",
        source,
    })?;
    let parent = open(
        &canonical_parent,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|source| ReleaseReceiptError::Io {
        operation: "open release receipt output parent",
        source: source.into(),
    })?;
    Ok(ReceiptOutput { parent, name })
}

#[cfg(any(target_vendor = "apple", target_os = "linux"))]
fn ensure_output_absent(output: &ReceiptOutput) -> Result<(), ReleaseReceiptError> {
    match statat(
        &output.parent,
        output.name.as_os_str(),
        AtFlags::SYMLINK_NOFOLLOW,
    ) {
        Ok(_) => Err(ReleaseReceiptError::OutputExists),
        Err(source) if source == rustix::io::Errno::NOENT => Ok(()),
        Err(source) => Err(ReleaseReceiptError::Io {
            operation: "inspect release receipt output",
            source: source.into(),
        }),
    }
}

#[cfg(any(target_vendor = "apple", target_os = "linux"))]
fn load_receipt_at(
    parent: &std::os::fd::OwnedFd,
    name: &OsStr,
) -> Result<ReleaseReceiptV1, ReleaseReceiptError> {
    let fd = openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|source| map_open_error(source, FileRole::Receipt))?;
    load_receipt_from_file(File::from(fd))
}

#[cfg(any(target_vendor = "apple", target_os = "linux"))]
fn next_stage_name() -> OsString {
    let id = NEXT_STAGE_ID.fetch_add(1, Ordering::Relaxed);
    OsString::from(format!(
        ".zaino-oram-release-receipt-stage-{}-{id}",
        std::process::id()
    ))
}

#[cfg(any(target_vendor = "apple", target_os = "linux"))]
fn map_open_error(source: rustix::io::Errno, role: FileRole) -> ReleaseReceiptError {
    if source == rustix::io::Errno::LOOP {
        ReleaseReceiptError::NonRegularFile { role }
    } else {
        ReleaseReceiptError::Io {
            operation: "open release input without following links",
            source: source.into(),
        }
    }
}

/// Release-receipt construction, publication, or verification failure.
#[derive(Debug)]
pub(super) enum ReleaseReceiptError {
    InvalidSourceRevision,
    InvalidDigest,
    InvalidFixedBuildIdentity,
    InvalidOutputPath,
    NonRegularFile {
        role: FileRole,
    },
    EmptyFile {
        role: FileRole,
    },
    FileTooLarge {
        role: FileRole,
        maximum_bytes: usize,
    },
    FileChangedDuringRead {
        role: FileRole,
    },
    MissingArchiveRevision,
    DuplicateArchiveRevisionHeader,
    ArchiveRevisionHeaderTooLarge,
    ArchiveRevisionMismatch,
    ConfusedArchivePath,
    DuplicateArchivePath,
    MissingArchiveInput {
        role: FileRole,
    },
    NonRegularArchiveInput {
        role: FileRole,
    },
    ArchiveInputMismatch {
        role: FileRole,
    },
    ReceiptCreatorMismatch,
    ObservedBuildFilesShareInode,
    ObservedBuildDigestMismatch,
    RunningExecutableMismatch,
    NonCanonicalJson,
    OutputExists,
    StageNameExhausted,
    StagedReadbackMismatch,
    PublishedReadbackMismatch,
    #[cfg(not(any(target_vendor = "apple", target_os = "linux")))]
    UnsupportedFilesystemHost,
    UnsupportedExecutableIdentityBuild,
    PublishedButDurabilityUncertain {
        source: io::Error,
    },
    Io {
        operation: &'static str,
        source: io::Error,
    },
    Archive {
        operation: &'static str,
        source: io::Error,
    },
    Json(serde_json::Error),
}

impl fmt::Display for ReleaseReceiptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSourceRevision => {
                f.write_str("source revision must be exactly 40 nonzero lowercase hex characters")
            }
            Self::InvalidDigest => {
                f.write_str("release receipt digest is not canonical nonzero SHA-256 hex")
            }
            Self::InvalidFixedBuildIdentity => {
                f.write_str("release receipt fixed build identity is invalid")
            }
            Self::InvalidOutputPath => f.write_str("release receipt output path is invalid"),
            Self::NonRegularFile { role } => {
                write!(f, "{} is not a no-follow regular file", role.label())
            }
            Self::EmptyFile { role } => write!(f, "{} is empty", role.label()),
            Self::FileTooLarge {
                role,
                maximum_bytes,
            } => write!(
                f,
                "{} exceeds its {maximum_bytes}-byte limit",
                role.label()
            ),
            Self::FileChangedDuringRead { role } => {
                write!(f, "{} changed while it was being read", role.label())
            }
            Self::MissingArchiveRevision => {
                f.write_str("source archive is missing its global PAX commit comment")
            }
            Self::DuplicateArchiveRevisionHeader => {
                f.write_str("source archive has ambiguous global PAX commit comments")
            }
            Self::ArchiveRevisionHeaderTooLarge => {
                f.write_str("source archive global PAX header exceeds its fixed limit")
            }
            Self::ArchiveRevisionMismatch => {
                f.write_str("source archive commit comment does not match the requested revision")
            }
            Self::ConfusedArchivePath => {
                f.write_str("source archive contains a non-canonical member path")
            }
            Self::DuplicateArchivePath => {
                f.write_str("source archive contains duplicate member paths")
            }
            Self::MissingArchiveInput { role } => {
                write!(f, "source archive is missing embedded {}", role.label())
            }
            Self::NonRegularArchiveInput { role } => {
                write!(f, "embedded {} is not a regular archive member", role.label())
            }
            Self::ArchiveInputMismatch { role } => {
                write!(f, "embedded {} differs from the supplied file", role.label())
            }
            Self::ReceiptCreatorMismatch => {
                f.write_str("receipt creator executable differs from the primary binary")
            }
            Self::ObservedBuildFilesShareInode => {
                f.write_str("the two observed build artifacts resolve to the same file inode")
            }
            Self::ObservedBuildDigestMismatch => {
                f.write_str("the two observed build artifact digests differ")
            }
            Self::RunningExecutableMismatch => {
                f.write_str("the running executable does not match the release receipt")
            }
            Self::NonCanonicalJson => f.write_str("release receipt JSON is not canonical"),
            Self::OutputExists => f.write_str("release receipt output already exists"),
            Self::StageNameExhausted => {
                f.write_str("release receipt staging names are exhausted")
            }
            Self::StagedReadbackMismatch => {
                f.write_str("staged release receipt differs after read-back")
            }
            Self::PublishedReadbackMismatch => {
                f.write_str("published release receipt differs after read-back")
            }
            #[cfg(not(any(target_vendor = "apple", target_os = "linux")))]
            Self::UnsupportedFilesystemHost => {
                f.write_str("release receipt filesystem operations are unsupported on this host")
            }
            Self::UnsupportedExecutableIdentityBuild => {
                f.write_str(
                    "local executable identity checks require a release-profile Linux x86_64 musl binary built with typed-qualification",
                )
            }
            Self::PublishedButDurabilityUncertain { .. } => {
                f.write_str("release receipt was published but parent durability is uncertain")
            }
            Self::Io { operation, .. } => write!(f, "failed to {operation}"),
            Self::Archive { operation, .. } => write!(f, "failed to {operation}"),
            Self::Json(_) => f.write_str("release receipt JSON is invalid"),
        }
    }
}

impl Error for ReleaseReceiptError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::PublishedButDurabilityUncertain { source }
            | Self::Io { source, .. }
            | Self::Archive { source, .. } => Some(source),
            Self::Json(source) => Some(source),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, io};

    use tempfile::TempDir;

    const TEST_REVISION: &str = "0123456789abcdef0123456789abcdef01234567";
    const OTHER_REVISION: &str = "89abcdef0123456789abcdef0123456789abcdef";
    const TEST_CARGO_LOCK: &[u8] = b"version = 4\n";
    const TEST_RUST_TOOLCHAIN: &[u8] = b"[toolchain]\nchannel = \"1.88.0\"\n";
    const TEST_DOCKERFILE: &[u8] = b"FROM scratch\n";
    const TEST_BINARY: &[u8] = b"fixed-zainod-oram-binary";

    type TestResult<T = ()> = Result<T, Box<dyn Error>>;

    #[derive(Clone, Copy)]
    struct ArchiveMember<'a> {
        path: &'a str,
        bytes: &'a [u8],
        entry_type: tar::EntryType,
    }

    struct Fixture {
        temp: TempDir,
        source_archive: PathBuf,
        cargo_lock: PathBuf,
        rust_toolchain: PathBuf,
        dockerfile: PathBuf,
        binary: PathBuf,
        second_binary: PathBuf,
    }

    impl Fixture {
        fn new() -> TestResult<Self> {
            let temp = tempfile::tempdir()?;
            let fixture = Self {
                source_archive: temp.path().join("source.tar"),
                cargo_lock: temp.path().join("Cargo.lock"),
                rust_toolchain: temp.path().join("rust-toolchain.toml"),
                dockerfile: temp.path().join("Dockerfile.deterministic"),
                binary: temp.path().join("zainod-oram-a"),
                second_binary: temp.path().join("zainod-oram-b"),
                temp,
            };
            fs::write(&fixture.cargo_lock, TEST_CARGO_LOCK)?;
            fs::write(&fixture.rust_toolchain, TEST_RUST_TOOLCHAIN)?;
            fs::write(&fixture.dockerfile, TEST_DOCKERFILE)?;
            fs::write(&fixture.binary, TEST_BINARY)?;
            fs::write(&fixture.second_binary, TEST_BINARY)?;
            fixture.write_default_archive()?;
            Ok(fixture)
        }

        fn write_default_archive(&self) -> io::Result<()> {
            write_archive(
                &self.source_archive,
                &[TEST_REVISION],
                &default_archive_members(),
            )
        }

        fn inputs(&self, output_name: &str) -> ReleaseReceiptInputs {
            ReleaseReceiptInputs {
                source_revision: TEST_REVISION.to_owned(),
                source_archive: self.source_archive.clone(),
                cargo_lock: self.cargo_lock.clone(),
                rust_toolchain: self.rust_toolchain.clone(),
                dockerfile: self.dockerfile.clone(),
                binary: self.binary.clone(),
                reproducible_binary: self.second_binary.clone(),
                output: self.temp.path().join(output_name),
            }
        }

        fn creator(&self) -> Result<OpenedDigest, ReleaseReceiptError> {
            hash_path(&self.binary, FileRole::Binary)
        }

        fn create(&self, output_name: &str) -> Result<(), ReleaseReceiptError> {
            create_release_receipt_for_creator(self.inputs(output_name), self.creator()?)
        }
    }

    fn default_archive_members() -> [ArchiveMember<'static>; 3] {
        [
            ArchiveMember {
                path: "Cargo.lock",
                bytes: TEST_CARGO_LOCK,
                entry_type: tar::EntryType::Regular,
            },
            ArchiveMember {
                path: "rust-toolchain.toml",
                bytes: TEST_RUST_TOOLCHAIN,
                entry_type: tar::EntryType::Regular,
            },
            ArchiveMember {
                path: "Dockerfile.deterministic",
                bytes: TEST_DOCKERFILE,
                entry_type: tar::EntryType::Regular,
            },
        ]
    }

    fn write_archive(
        path: &Path,
        revisions: &[&str],
        members: &[ArchiveMember<'_>],
    ) -> io::Result<()> {
        let file = File::create(path)?;
        let mut builder = tar::Builder::new(file);
        for revision in revisions {
            let record = pax_record("comment", revision);
            let mut header = tar::Header::new_ustar();
            header.set_entry_type(tar::EntryType::XGlobalHeader);
            header.set_size(record.len() as u64);
            header.set_mode(0o644);
            header.set_mtime(SOURCE_DATE_EPOCH);
            builder.append_data(&mut header, "pax_global_header", record.as_slice())?;
        }
        for member in members {
            let mut header = tar::Header::new_ustar();
            header.set_entry_type(member.entry_type);
            header.set_size(member.bytes.len() as u64);
            header.set_mode(0o644);
            header.set_mtime(SOURCE_DATE_EPOCH);
            builder.append_data(&mut header, member.path, member.bytes)?;
        }
        builder.finish()?;
        builder.into_inner()?.sync_all()
    }

    fn pax_record(key: &str, value: &str) -> Vec<u8> {
        let body = format!("{key}={value}\n");
        let mut reported_len = body.len() + 2;
        loop {
            let record = format!("{reported_len} {body}");
            if record.len() == reported_len {
                return record.into_bytes();
            }
            reported_len = record.len();
        }
    }

    fn valid_receipt() -> Result<ReleaseReceiptV1, ReleaseReceiptError> {
        let digest = "1".repeat(SHA256_HEX_BYTES);
        ReleaseReceiptV1::new(
            TEST_REVISION.to_owned(),
            digest.clone(),
            digest.clone(),
            digest.clone(),
            digest.clone(),
            digest,
            TEST_BINARY.len() as u64,
        )
    }

    #[test]
    fn creates_compact_self_reported_receipt_with_fixed_scope() -> TestResult {
        let fixture = Fixture::new()?;
        fixture.create("receipt.json")?;
        let output = fixture.temp.path().join("receipt.json");
        let bytes = fs::read(&output)?;
        let receipt = load_release_receipt(&output)?;

        assert_eq!(receipt.source_revision, TEST_REVISION);
        assert!(receipt.clean_tree_self_reported);
        assert_eq!(receipt.observed_build_artifact_count, 2);
        assert!(receipt.observed_distinct_binary_inodes);
        assert!(receipt.observed_binary_digest_agreement);
        assert!(!receipt.signed);
        assert!(!receipt.execution_attested);
        assert!(!receipt.physical_trace_measured);
        assert!(!receipt.source_derivation_attested);
        assert_eq!(receipt.trust_classification, TRUST_CLASSIFICATION);
        assert_eq!(receipt.binary_size_bytes, TEST_BINARY.len() as u64);
        assert_eq!(receipt.binary_sha256, sha256_hex(TEST_BINARY));
        assert_eq!(bytes, receipt.canonical_bytes()?);
        assert!(!bytes.contains(&b'\n'));
        Ok(())
    }

    #[test]
    fn rejects_creator_drift_shared_inode_and_digest_disagreement() -> TestResult {
        let fixture = Fixture::new()?;
        let other = fixture.temp.path().join("other-creator");
        fs::write(&other, b"other executable")?;
        let creator_error = create_release_receipt_for_creator(
            fixture.inputs("creator.json"),
            hash_path(&other, FileRole::RunningExecutable)?,
        );
        assert!(matches!(
            creator_error,
            Err(ReleaseReceiptError::ReceiptCreatorMismatch)
        ));

        let mut shared_inode = fixture.inputs("shared.json");
        shared_inode.reproducible_binary = fixture.binary.clone();
        let shared_error = create_release_receipt_for_creator(shared_inode, fixture.creator()?);
        assert!(matches!(
            shared_error,
            Err(ReleaseReceiptError::ObservedBuildFilesShareInode)
        ));

        fs::write(&fixture.second_binary, b"different build artifact")?;
        let digest_error = fixture.create("digest.json");
        assert!(matches!(
            digest_error,
            Err(ReleaseReceiptError::ObservedBuildDigestMismatch)
        ));
        Ok(())
    }

    #[test]
    fn rejects_archive_revision_and_embedded_input_mismatches() -> TestResult {
        let fixture = Fixture::new()?;
        write_archive(
            &fixture.source_archive,
            &[OTHER_REVISION],
            &default_archive_members(),
        )?;
        assert!(matches!(
            fixture.create("revision.json"),
            Err(ReleaseReceiptError::ArchiveRevisionMismatch)
        ));

        let mismatched = [
            ArchiveMember {
                path: "Cargo.lock",
                bytes: b"different lock",
                entry_type: tar::EntryType::Regular,
            },
            default_archive_members()[1],
            default_archive_members()[2],
        ];
        write_archive(&fixture.source_archive, &[TEST_REVISION], &mismatched)?;
        assert!(matches!(
            fixture.create("embedded.json"),
            Err(ReleaseReceiptError::ArchiveInputMismatch {
                role: FileRole::CargoLock
            })
        ));
        Ok(())
    }

    #[test]
    fn rejects_missing_duplicate_confused_and_nonregular_archive_inputs() -> TestResult {
        let fixture = Fixture::new()?;
        let defaults = default_archive_members();
        write_archive(
            &fixture.source_archive,
            &[TEST_REVISION],
            &[defaults[0], defaults[2]],
        )?;
        assert!(matches!(
            fixture.create("missing.json"),
            Err(ReleaseReceiptError::MissingArchiveInput {
                role: FileRole::RustToolchain
            })
        ));

        write_archive(
            &fixture.source_archive,
            &[TEST_REVISION],
            &[defaults[0], defaults[0], defaults[1], defaults[2]],
        )?;
        assert!(matches!(
            fixture.create("duplicate.json"),
            Err(ReleaseReceiptError::DuplicateArchivePath)
        ));

        let confused = [
            ArchiveMember {
                path: "Cargo.lock\\",
                ..defaults[0]
            },
            defaults[1],
            defaults[2],
        ];
        write_archive(&fixture.source_archive, &[TEST_REVISION], &confused)?;
        assert!(matches!(
            fixture.create("confused.json"),
            Err(ReleaseReceiptError::ConfusedArchivePath)
        ));

        let nonregular = [
            ArchiveMember {
                entry_type: tar::EntryType::Symlink,
                bytes: b"",
                ..defaults[0]
            },
            defaults[1],
            defaults[2],
        ];
        write_archive(&fixture.source_archive, &[TEST_REVISION], &nonregular)?;
        assert!(matches!(
            fixture.create("nonregular.json"),
            Err(ReleaseReceiptError::NonRegularArchiveInput {
                role: FileRole::CargoLock
            })
        ));
        Ok(())
    }

    #[test]
    fn archive_paths_must_be_unambiguous_relative_member_names() {
        for path in [
            b"".as_slice(),
            b"/Cargo.lock",
            b"./Cargo.lock",
            b"a//Cargo.lock",
            b"a/../Cargo.lock",
            b"a\\Cargo.lock",
            b"Cargo.lock/",
            b"Cargo\0.lock",
        ] {
            assert!(matches!(
                canonical_archive_path(path, false),
                Err(ReleaseReceiptError::ConfusedArchivePath)
            ));
        }
        assert_eq!(
            canonical_archive_path(b"packages/zainod-oram/", true)
                .expect("directory archive path should canonicalize"),
            b"packages/zainod-oram".to_vec()
        );
    }

    #[test]
    fn rejects_missing_duplicate_and_oversized_archive_revision_headers() -> TestResult {
        let fixture = Fixture::new()?;
        write_archive(&fixture.source_archive, &[], &default_archive_members())?;
        assert!(matches!(
            fixture.create("no-revision.json"),
            Err(ReleaseReceiptError::MissingArchiveRevision)
        ));

        write_archive(
            &fixture.source_archive,
            &[TEST_REVISION, TEST_REVISION],
            &default_archive_members(),
        )?;
        assert!(matches!(
            fixture.create("duplicate-revision.json"),
            Err(ReleaseReceiptError::DuplicateArchiveRevisionHeader)
        ));

        let oversized_comment = "a".repeat(MAX_GLOBAL_PAX_BYTES as usize);
        write_archive(
            &fixture.source_archive,
            &[oversized_comment.as_str()],
            &default_archive_members(),
        )?;
        assert!(matches!(
            fixture.create("oversized-revision.json"),
            Err(ReleaseReceiptError::ArchiveRevisionHeaderTooLarge)
        ));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn rejects_invalid_empty_oversized_nonregular_and_symlink_inputs() -> TestResult {
        use std::os::unix::fs::symlink;

        let fixture = Fixture::new()?;
        let mut invalid_revision = fixture.inputs("invalid-revision.json");
        invalid_revision.source_revision = TEST_REVISION.to_uppercase();
        assert!(matches!(
            create_release_receipt_for_creator(invalid_revision, fixture.creator()?),
            Err(ReleaseReceiptError::InvalidSourceRevision)
        ));
        let mut zero_revision = fixture.inputs("zero-revision.json");
        zero_revision.source_revision = "0".repeat(SOURCE_REVISION_HEX_BYTES);
        assert!(matches!(
            create_release_receipt_for_creator(zero_revision, fixture.creator()?),
            Err(ReleaseReceiptError::InvalidSourceRevision)
        ));

        fs::write(&fixture.rust_toolchain, [])?;
        assert!(matches!(
            fixture.create("empty.json"),
            Err(ReleaseReceiptError::EmptyFile {
                role: FileRole::RustToolchain
            })
        ));
        fs::write(
            &fixture.rust_toolchain,
            vec![b'x'; MAX_RUST_TOOLCHAIN_BYTES + 1],
        )?;
        assert!(matches!(
            fixture.create("oversized.json"),
            Err(ReleaseReceiptError::FileTooLarge {
                role: FileRole::RustToolchain,
                ..
            })
        ));
        fs::write(&fixture.rust_toolchain, TEST_RUST_TOOLCHAIN)?;

        let directory = fixture.temp.path().join("directory-input");
        fs::create_dir(&directory)?;
        let mut directory_input = fixture.inputs("directory.json");
        directory_input.rust_toolchain = directory;
        assert!(matches!(
            create_release_receipt_for_creator(directory_input, fixture.creator()?),
            Err(ReleaseReceiptError::NonRegularFile {
                role: FileRole::RustToolchain
            })
        ));

        let link = fixture.temp.path().join("toolchain-link");
        symlink(&fixture.rust_toolchain, &link)?;
        let mut linked_input = fixture.inputs("linked.json");
        linked_input.rust_toolchain = link;
        assert!(matches!(
            create_release_receipt_for_creator(linked_input, fixture.creator()?),
            Err(ReleaseReceiptError::NonRegularFile {
                role: FileRole::RustToolchain
            })
        ));
        Ok(())
    }

    #[test]
    fn receipt_loader_rejects_unknown_noncanonical_and_invalid_fixed_fields() -> TestResult {
        let temp = tempfile::tempdir()?;
        let receipt = valid_receipt()?;

        let pretty = temp.path().join("pretty.json");
        fs::write(&pretty, serde_json::to_vec_pretty(&receipt)?)?;
        assert!(matches!(
            load_release_receipt(&pretty),
            Err(ReleaseReceiptError::NonCanonicalJson)
        ));

        let mut value = serde_json::to_value(&receipt)?;
        value["unexpected"] = serde_json::Value::Bool(true);
        let unknown = temp.path().join("unknown.json");
        fs::write(&unknown, serde_json::to_vec(&value)?)?;
        assert!(matches!(
            load_release_receipt(&unknown),
            Err(ReleaseReceiptError::Json(_))
        ));

        let mut signed = serde_json::to_value(&receipt)?;
        signed["signed"] = serde_json::Value::Bool(true);
        let invalid_fixed = temp.path().join("invalid-fixed.json");
        fs::write(&invalid_fixed, serde_json::to_vec(&signed)?)?;
        assert!(matches!(
            load_release_receipt(&invalid_fixed),
            Err(ReleaseReceiptError::InvalidFixedBuildIdentity)
        ));

        let mut digest = serde_json::to_value(&receipt)?;
        digest["binary_sha256"] = serde_json::Value::String("A".repeat(SHA256_HEX_BYTES));
        let invalid_digest = temp.path().join("invalid-digest.json");
        fs::write(&invalid_digest, serde_json::to_vec(&digest)?)?;
        assert!(matches!(
            load_release_receipt(&invalid_digest),
            Err(ReleaseReceiptError::InvalidDigest)
        ));

        let mut zero_digest = serde_json::to_value(&receipt)?;
        zero_digest["binary_sha256"] = serde_json::Value::String("0".repeat(SHA256_HEX_BYTES));
        let zero_digest_path = temp.path().join("zero-digest.json");
        fs::write(&zero_digest_path, serde_json::to_vec(&zero_digest)?)?;
        assert!(matches!(
            load_release_receipt(&zero_digest_path),
            Err(ReleaseReceiptError::InvalidDigest)
        ));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn receipt_loader_rejects_empty_oversized_and_symlink_files() -> TestResult {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir()?;
        let empty = temp.path().join("empty.json");
        fs::write(&empty, [])?;
        assert!(matches!(
            load_release_receipt(&empty),
            Err(ReleaseReceiptError::EmptyFile {
                role: FileRole::Receipt
            })
        ));

        let oversized = temp.path().join("oversized.json");
        fs::write(&oversized, vec![b'x'; MAX_RECEIPT_BYTES + 1])?;
        assert!(matches!(
            load_release_receipt(&oversized),
            Err(ReleaseReceiptError::FileTooLarge {
                role: FileRole::Receipt,
                ..
            })
        ));

        let valid = temp.path().join("valid.json");
        fs::write(&valid, valid_receipt()?.canonical_bytes()?)?;
        let link = temp.path().join("link.json");
        symlink(&valid, &link)?;
        assert!(matches!(
            load_release_receipt(&link),
            Err(ReleaseReceiptError::NonRegularFile {
                role: FileRole::Receipt
            })
        ));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn publication_never_replaces_existing_path_or_symlink() -> TestResult {
        use std::os::unix::fs::symlink;

        let fixture = Fixture::new()?;
        let existing = fixture.temp.path().join("existing.json");
        fs::write(&existing, b"keep-me")?;
        assert!(matches!(
            fixture.create("existing.json"),
            Err(ReleaseReceiptError::OutputExists)
        ));
        assert_eq!(fs::read(&existing)?, b"keep-me");

        let target = fixture.temp.path().join("target.json");
        fs::write(&target, b"also-keep-me")?;
        let link = fixture.temp.path().join("linked-output.json");
        symlink(&target, &link)?;
        assert!(matches!(
            fixture.create("linked-output.json"),
            Err(ReleaseReceiptError::OutputExists)
        ));
        assert_eq!(fs::read(&target)?, b"also-keep-me");
        Ok(())
    }

    #[test]
    fn verifier_scope_checks_only_supported_build_digest_and_size() -> TestResult {
        assert!(is_supported_executable_identity_build(
            "linux", "x86_64", true, true, true
        ));
        for (os, arch, target_is_musl, feature_enabled, release_profile) in [
            ("macos", "x86_64", true, true, true),
            ("linux", "aarch64", true, true, true),
            ("linux", "x86_64", false, true, true),
            ("linux", "x86_64", true, false, true),
            ("linux", "x86_64", true, true, false),
        ] {
            assert!(!is_supported_executable_identity_build(
                os,
                arch,
                target_is_musl,
                feature_enabled,
                release_profile
            ));
        }

        let receipt = valid_receipt()?;
        let matching = OpenedDigest {
            sha256: receipt.binary_sha256.clone(),
            device: 1,
            inode: 2,
            size_bytes: receipt.binary_size_bytes,
        };
        verify_executable_identity(&receipt, &matching)?;

        let wrong_size = OpenedDigest {
            size_bytes: matching.size_bytes + 1,
            ..matching.clone()
        };
        assert!(matches!(
            verify_executable_identity(&receipt, &wrong_size),
            Err(ReleaseReceiptError::RunningExecutableMismatch)
        ));
        let wrong_digest = OpenedDigest {
            sha256: "2".repeat(SHA256_HEX_BYTES),
            ..matching
        };
        assert!(matches!(
            verify_executable_identity(&receipt, &wrong_digest),
            Err(ReleaseReceiptError::RunningExecutableMismatch)
        ));
        Ok(())
    }

    #[test]
    fn verified_receipt_binding_returns_the_exact_validated_bytes() -> TestResult {
        let fixture = Fixture::new()?;
        fixture.create("receipt.json")?;
        let receipt_path = fixture.temp.path().join("receipt.json");
        let expected_bytes = fs::read(&receipt_path)?;
        let expected_receipt = load_release_receipt(&receipt_path)?;

        let verified = verify_release_receipt_for_executable(&receipt_path, &fixture.creator()?)?;

        assert_eq!(verified.canonical_bytes(), expected_bytes);
        let metadata = verified.metadata();
        assert_eq!(
            metadata.receipt_blake2s256(),
            artifact_blake2s256_hex(&expected_bytes)
        );
        assert_eq!(metadata.source_revision(), expected_receipt.source_revision);
        assert_eq!(metadata.binary_sha256(), expected_receipt.binary_sha256);
        assert_eq!(
            metadata.binary_size_bytes(),
            expected_receipt.binary_size_bytes
        );
        let wrong_executable = OpenedDigest {
            sha256: "2".repeat(SHA256_HEX_BYTES),
            ..fixture.creator()?
        };
        assert!(matches!(
            verify_release_receipt_for_executable(&receipt_path, &wrong_executable),
            Err(ReleaseReceiptError::RunningExecutableMismatch)
        ));

        fs::write(&receipt_path, b"replaced after verification")?;
        assert_eq!(verified.canonical_bytes(), expected_bytes);
        Ok(())
    }

    #[cfg(not(all(
        target_os = "linux",
        target_arch = "x86_64",
        target_env = "musl",
        feature = "typed-qualification",
        not(debug_assertions)
    )))]
    #[test]
    fn production_entrypoints_reject_an_unsupported_compile_identity() {
        let unavailable = PathBuf::from("/definitely/unavailable");
        let inputs = ReleaseReceiptInputs {
            source_revision: TEST_REVISION.to_owned(),
            source_archive: unavailable.clone(),
            cargo_lock: unavailable.clone(),
            rust_toolchain: unavailable.clone(),
            dockerfile: unavailable.clone(),
            binary: unavailable.clone(),
            reproducible_binary: unavailable.clone(),
            output: unavailable.clone(),
        };
        assert!(matches!(
            create_release_receipt(inputs),
            Err(ReleaseReceiptError::UnsupportedExecutableIdentityBuild)
        ));
        assert!(matches!(
            verify_release_receipt(&unavailable),
            Err(ReleaseReceiptError::UnsupportedExecutableIdentityBuild)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn mutation_detection_covers_mode_and_time_metadata() {
        let before = MetadataSnapshot {
            device: 1,
            inode: 2,
            size_bytes: 3,
            mode: 0o100644,
            modified_seconds: 4,
            modified_nanoseconds: 5,
            changed_seconds: 6,
            changed_nanoseconds: 7,
        };
        assert!(ensure_unchanged(&before, &before, 3, FileRole::CargoLock).is_ok());

        let changed_mode = MetadataSnapshot {
            mode: 0o100600,
            ..before
        };
        assert!(matches!(
            ensure_unchanged(&before, &changed_mode, 3, FileRole::CargoLock),
            Err(ReleaseReceiptError::FileChangedDuringRead {
                role: FileRole::CargoLock
            })
        ));
        let changed_time = MetadataSnapshot {
            changed_nanoseconds: 8,
            ..before
        };
        assert!(matches!(
            ensure_unchanged(&before, &changed_time, 3, FileRole::CargoLock),
            Err(ReleaseReceiptError::FileChangedDuringRead {
                role: FileRole::CargoLock
            })
        ));
    }
}
