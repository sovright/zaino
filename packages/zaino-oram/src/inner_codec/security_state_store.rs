//! Witness-bound local security-state persistence.
//!
//! This module fixes the ordering and recovery contract needed by later replay,
//! nonce-reservation, and trusted-time providers. It deliberately supplies no
//! concrete external witness, provider journal, runtime construction path, or
//! production rollback evidence. A successful mutation orders future component
//! files first, this fixed local snapshot second, and the external freshness
//! witness last. Any ambiguous local commit or witness advance latches the store
//! unavailable for the rest of its in-process lifetime.

use std::{
    fmt, fs,
    io::{self, Read, Write},
    path::PathBuf,
};

use blake2::{Blake2s256, Digest};
use tempfile::NamedTempFile;

use crate::{
    persistence::fs_atomic::{
        create_unique_file, ensure_real_directory, sync_directory, RealDirectoryError,
    },
    profile::PROFILE_ID_BYTES,
};

use super::SESSION_BINDING_BYTES;

const SERVICE_ID_BYTES: usize = 16;
const SECURITY_EPOCH_BINDING_BYTES: usize = 32;
const STATE_DIGEST_BYTES: usize = 32;
const SECURITY_STATE_FILE_MAGIC: &[u8; 8] = b"ZORAMSS1";
const SECURITY_STATE_FILE_VERSION: u16 = 1;
const SECURITY_STATE_DIGEST_VERSION: u16 = 1;
const SECURITY_STATE_DIGEST_DOMAIN: &[u8] = b"zaino-oram/security-state-commitment-digest/v1\0";
const CURRENT_STATE_FILE: &str = "current.bin";
const STAGING_DIRECTORY: &str = "staging";

const FILE_MAGIC_START: usize = 0;
const FILE_VERSION_START: usize = FILE_MAGIC_START + SECURITY_STATE_FILE_MAGIC.len();
const SEQUENCE_START: usize = FILE_VERSION_START + size_of::<u16>();
const SERVICE_ID_START: usize = SEQUENCE_START + size_of::<u64>();
const PROTOCOL_VERSION_START: usize = SERVICE_ID_START + SERVICE_ID_BYTES;
const OWNER_GENERATION_START: usize = PROTOCOL_VERSION_START + size_of::<u16>();
const KEY_EPOCH_START: usize = OWNER_GENERATION_START + size_of::<u64>();
const PROJECTION_EPOCH_START: usize = KEY_EPOCH_START + size_of::<u64>();
const PROFILE_ID_START: usize = PROJECTION_EPOCH_START + size_of::<u64>();
const SESSION_BINDING_START: usize = PROFILE_ID_START + PROFILE_ID_BYTES;
const SECURITY_EPOCH_BINDING_START: usize = SESSION_BINDING_START + SESSION_BINDING_BYTES;
const SERVING_IDENTITY_DIGEST_START: usize =
    SECURITY_EPOCH_BINDING_START + SECURITY_EPOCH_BINDING_BYTES;
const COMPONENT_STATE_DIGEST_START: usize = SERVING_IDENTITY_DIGEST_START + STATE_DIGEST_BYTES;
const PERSISTENT_SECURITY_STATE_BYTES: usize = COMPONENT_STATE_DIGEST_START + STATE_DIGEST_BYTES;

const _: () = {
    assert!(FILE_MAGIC_START == 0);
    assert!(FILE_VERSION_START == 8);
    assert!(SEQUENCE_START == 10);
    assert!(SERVICE_ID_START == 18);
    assert!(PROTOCOL_VERSION_START == 34);
    assert!(OWNER_GENERATION_START == 36);
    assert!(KEY_EPOCH_START == 44);
    assert!(PROJECTION_EPOCH_START == 52);
    assert!(PROFILE_ID_START == 60);
    assert!(SESSION_BINDING_START == 76);
    assert!(SECURITY_EPOCH_BINDING_START == 108);
    assert!(SERVING_IDENTITY_DIGEST_START == 140);
    assert!(COMPONENT_STATE_DIGEST_START == 172);
    assert!(PERSISTENT_SECURITY_STATE_BYTES == 204);
};

/// Monotonic versions and epochs bound into one security identity.
#[derive(Clone, Copy, PartialEq, Eq)]
struct SecurityStateEpochs {
    protocol_version: u16,
    owner_generation: u64,
    key_epoch: u64,
    projection_epoch: u64,
}

impl SecurityStateEpochs {
    fn new(
        protocol_version: u16,
        owner_generation: u64,
        key_epoch: u64,
        projection_epoch: u64,
    ) -> Result<Self, SecurityStateValueError> {
        if protocol_version == 0 {
            return Err(SecurityStateValueError::ProtocolVersionIsZero);
        }
        if owner_generation == 0 {
            return Err(SecurityStateValueError::OwnerGenerationIsMissing);
        }
        if key_epoch == 0 {
            return Err(SecurityStateValueError::KeyEpochIsMissing);
        }
        if projection_epoch == 0 {
            return Err(SecurityStateValueError::ProjectionEpochIsMissing);
        }
        Ok(Self {
            protocol_version,
            owner_generation,
            key_epoch,
            projection_epoch,
        })
    }
}

/// Stable identity of one future active security owner.
#[derive(Clone, Copy, PartialEq, Eq)]
struct SecurityStateIdentity {
    service_id: [u8; SERVICE_ID_BYTES],
    epochs: SecurityStateEpochs,
    profile_id: [u8; PROFILE_ID_BYTES],
    session_binding: [u8; SESSION_BINDING_BYTES],
    security_epoch_binding: [u8; SECURITY_EPOCH_BINDING_BYTES],
}

impl SecurityStateIdentity {
    fn new(
        service_id: [u8; SERVICE_ID_BYTES],
        epochs: SecurityStateEpochs,
        profile_id: [u8; PROFILE_ID_BYTES],
        session_binding: [u8; SESSION_BINDING_BYTES],
        security_epoch_binding: [u8; SECURITY_EPOCH_BINDING_BYTES],
    ) -> Result<Self, SecurityStateValueError> {
        if all_zero(&service_id) {
            return Err(SecurityStateValueError::ServiceIdIsEmpty);
        }
        if all_zero(&profile_id) {
            return Err(SecurityStateValueError::ProfileIdIsEmpty);
        }
        if all_zero(&session_binding) {
            return Err(SecurityStateValueError::SessionBindingIsEmpty);
        }
        if all_zero(&security_epoch_binding) {
            return Err(SecurityStateValueError::SecurityEpochBindingIsEmpty);
        }
        Ok(Self {
            service_id,
            epochs,
            profile_id,
            session_binding,
            security_epoch_binding,
        })
    }

    /// Validates one same-namespace state update or complete owner rotation.
    fn validate_successor(&self, next: &Self) -> Result<(), SecurityStateSuccessorError> {
        if next.service_id != self.service_id {
            return Err(SecurityStateSuccessorError::ServiceIdentityChanged);
        }
        if next.epochs.protocol_version != self.epochs.protocol_version {
            return Err(SecurityStateSuccessorError::ProtocolVersionChanged);
        }
        if next.profile_id != self.profile_id {
            return Err(SecurityStateSuccessorError::ProfileIdentityChanged);
        }
        if next.epochs.owner_generation < self.epochs.owner_generation {
            return Err(SecurityStateSuccessorError::OwnerGenerationRegressed);
        }
        if next.epochs.key_epoch < self.epochs.key_epoch {
            return Err(SecurityStateSuccessorError::KeyEpochRegressed);
        }
        if next.epochs.projection_epoch < self.epochs.projection_epoch {
            return Err(SecurityStateSuccessorError::ProjectionEpochRegressed);
        }

        let epochs_changed = next.epochs.owner_generation != self.epochs.owner_generation
            || next.epochs.key_epoch != self.epochs.key_epoch
            || next.epochs.projection_epoch != self.epochs.projection_epoch;
        let bindings_changed = next.session_binding != self.session_binding
            || next.security_epoch_binding != self.security_epoch_binding;
        if !epochs_changed && !bindings_changed {
            return Ok(());
        }
        if next.epochs.owner_generation == self.epochs.owner_generation {
            return Err(SecurityStateSuccessorError::OwnerGenerationDidNotAdvance);
        }
        if next.session_binding == self.session_binding {
            return Err(SecurityStateSuccessorError::SessionBindingNotRotated);
        }
        if next.security_epoch_binding == self.security_epoch_binding {
            return Err(SecurityStateSuccessorError::SecurityEpochBindingNotRotated);
        }
        Ok(())
    }
}

impl fmt::Debug for SecurityStateIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecurityStateIdentity { ..REDACTED.. }")
    }
}

/// Exact identity plus opaque digests of serving and mutable component state.
#[derive(Clone, Copy, PartialEq, Eq)]
struct SecurityStateCommitment {
    identity: SecurityStateIdentity,
    serving_identity_digest: [u8; STATE_DIGEST_BYTES],
    component_state_digest: [u8; STATE_DIGEST_BYTES],
}

impl SecurityStateCommitment {
    fn new(
        identity: SecurityStateIdentity,
        serving_identity_digest: [u8; STATE_DIGEST_BYTES],
        component_state_digest: [u8; STATE_DIGEST_BYTES],
    ) -> Result<Self, SecurityStateValueError> {
        if all_zero(&serving_identity_digest) {
            return Err(SecurityStateValueError::ServingIdentityDigestIsEmpty);
        }
        if all_zero(&component_state_digest) {
            return Err(SecurityStateValueError::ComponentStateDigestIsEmpty);
        }
        Ok(Self {
            identity,
            serving_identity_digest,
            component_state_digest,
        })
    }

    fn digest(&self) -> SecurityStateDigest {
        let mut hasher = Blake2s256::new();
        Digest::update(&mut hasher, SECURITY_STATE_DIGEST_DOMAIN);
        Digest::update(&mut hasher, SECURITY_STATE_DIGEST_VERSION.to_be_bytes());
        Digest::update(&mut hasher, self.identity.service_id);
        Digest::update(
            &mut hasher,
            self.identity.epochs.protocol_version.to_be_bytes(),
        );
        Digest::update(
            &mut hasher,
            self.identity.epochs.owner_generation.to_be_bytes(),
        );
        Digest::update(&mut hasher, self.identity.epochs.key_epoch.to_be_bytes());
        Digest::update(
            &mut hasher,
            self.identity.epochs.projection_epoch.to_be_bytes(),
        );
        Digest::update(&mut hasher, self.identity.profile_id);
        Digest::update(&mut hasher, self.identity.session_binding);
        Digest::update(&mut hasher, self.identity.security_epoch_binding);
        Digest::update(&mut hasher, self.serving_identity_digest);
        Digest::update(&mut hasher, self.component_state_digest);
        SecurityStateDigest(hasher.finalize().into())
    }
}

impl fmt::Debug for SecurityStateCommitment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecurityStateCommitment { ..REDACTED.. }")
    }
}

/// One witness-sequenced security-state snapshot.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct SecurityStateSnapshot {
    sequence: u64,
    commitment: SecurityStateCommitment,
}

impl SecurityStateSnapshot {
    fn new(
        sequence: u64,
        commitment: SecurityStateCommitment,
    ) -> Result<Self, SecurityStateValueError> {
        if sequence == 0 {
            return Err(SecurityStateValueError::SequenceIsMissing);
        }
        Ok(Self {
            sequence,
            commitment,
        })
    }

    const fn sequence(&self) -> u64 {
        self.sequence
    }

    fn freshness(&self) -> SecurityFreshness {
        SecurityFreshness {
            sequence: self.sequence,
            state_digest: self.commitment.digest(),
        }
    }
}

impl fmt::Debug for SecurityStateSnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecurityStateSnapshot { ..REDACTED.. }")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SecurityStateValueError {
    ServiceIdIsEmpty,
    ProtocolVersionIsZero,
    OwnerGenerationIsMissing,
    KeyEpochIsMissing,
    ProjectionEpochIsMissing,
    ProfileIdIsEmpty,
    SessionBindingIsEmpty,
    SecurityEpochBindingIsEmpty,
    ServingIdentityDigestIsEmpty,
    ComponentStateDigestIsEmpty,
    SequenceIsMissing,
}

impl fmt::Display for SecurityStateValueError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ServiceIdIsEmpty => f.write_str("security state has a zero service identity"),
            Self::ProtocolVersionIsZero => {
                f.write_str("security state has a zero protocol version")
            }
            Self::OwnerGenerationIsMissing => {
                f.write_str("security state has a zero owner generation")
            }
            Self::KeyEpochIsMissing => f.write_str("security state has a zero key epoch"),
            Self::ProjectionEpochIsMissing => {
                f.write_str("security state has a zero projection epoch")
            }
            Self::ProfileIdIsEmpty => f.write_str("security state has a zero profile identity"),
            Self::SessionBindingIsEmpty => f.write_str("security state has a zero session binding"),
            Self::SecurityEpochBindingIsEmpty => {
                f.write_str("security state has a zero security epoch binding")
            }
            Self::ServingIdentityDigestIsEmpty => {
                f.write_str("security state has a zero serving identity digest")
            }
            Self::ComponentStateDigestIsEmpty => {
                f.write_str("security state has a zero component-state digest")
            }
            Self::SequenceIsMissing => f.write_str("security state has a zero sequence"),
        }
    }
}

impl std::error::Error for SecurityStateValueError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SecurityStateSuccessorError {
    ServiceIdentityChanged,
    ProtocolVersionChanged,
    ProfileIdentityChanged,
    OwnerGenerationRegressed,
    KeyEpochRegressed,
    ProjectionEpochRegressed,
    OwnerGenerationDidNotAdvance,
    SessionBindingNotRotated,
    SecurityEpochBindingNotRotated,
}

impl fmt::Display for SecurityStateSuccessorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("security state identity transition is invalid")
    }
}

impl std::error::Error for SecurityStateSuccessorError {}

/// Collision-resistant content identity carried by the external witness.
#[derive(Clone, Copy, PartialEq, Eq)]
struct SecurityStateDigest([u8; STATE_DIGEST_BYTES]);

impl fmt::Debug for SecurityStateDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecurityStateDigest([REDACTED])")
    }
}

/// Monotonic sequence and exact state digest named by an external authority.
#[derive(Clone, Copy, PartialEq, Eq)]
struct SecurityFreshness {
    sequence: u64,
    state_digest: SecurityStateDigest,
}

impl SecurityFreshness {
    const fn sequence(&self) -> u64 {
        self.sequence
    }
}

impl fmt::Debug for SecurityFreshness {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecurityFreshness { ..REDACTED.. }")
    }
}

/// Externally authoritative rollback/freshness boundary.
///
/// Implementations must make `next` crash-durable before returning `Ok` and
/// reject every successful transition except `None -> 1` or exact
/// `n -> n + 1`. An `Err` is indeterminate: the witness may be unchanged or
/// may already contain `next`, so the caller must fail closed and reconcile.
trait SecurityFreshnessWitness {
    type Error;

    fn current(&mut self) -> Result<Option<SecurityFreshness>, Self::Error>;

    fn compare_and_advance(
        &mut self,
        expected: Option<SecurityFreshness>,
        next: SecurityFreshness,
    ) -> Result<(), Self::Error>;
}

/// Fixed-width bytes for one local security-state snapshot.
pub(super) struct PersistentSecurityState([u8; PERSISTENT_SECURITY_STATE_BYTES]);

impl PersistentSecurityState {
    /// Encodes one validated business-layer snapshot.
    pub(super) fn from_business(state: &SecurityStateSnapshot) -> Self {
        let mut bytes = [0; PERSISTENT_SECURITY_STATE_BYTES];
        bytes[FILE_MAGIC_START..FILE_VERSION_START].copy_from_slice(SECURITY_STATE_FILE_MAGIC);
        bytes[FILE_VERSION_START..SEQUENCE_START]
            .copy_from_slice(&SECURITY_STATE_FILE_VERSION.to_be_bytes());
        bytes[SEQUENCE_START..SERVICE_ID_START].copy_from_slice(&state.sequence.to_be_bytes());
        bytes[SERVICE_ID_START..PROTOCOL_VERSION_START]
            .copy_from_slice(&state.commitment.identity.service_id);
        bytes[PROTOCOL_VERSION_START..OWNER_GENERATION_START].copy_from_slice(
            &state
                .commitment
                .identity
                .epochs
                .protocol_version
                .to_be_bytes(),
        );
        bytes[OWNER_GENERATION_START..KEY_EPOCH_START].copy_from_slice(
            &state
                .commitment
                .identity
                .epochs
                .owner_generation
                .to_be_bytes(),
        );
        bytes[KEY_EPOCH_START..PROJECTION_EPOCH_START]
            .copy_from_slice(&state.commitment.identity.epochs.key_epoch.to_be_bytes());
        bytes[PROJECTION_EPOCH_START..PROFILE_ID_START].copy_from_slice(
            &state
                .commitment
                .identity
                .epochs
                .projection_epoch
                .to_be_bytes(),
        );
        bytes[PROFILE_ID_START..SESSION_BINDING_START]
            .copy_from_slice(&state.commitment.identity.profile_id);
        bytes[SESSION_BINDING_START..SECURITY_EPOCH_BINDING_START]
            .copy_from_slice(&state.commitment.identity.session_binding);
        bytes[SECURITY_EPOCH_BINDING_START..SERVING_IDENTITY_DIGEST_START]
            .copy_from_slice(&state.commitment.identity.security_epoch_binding);
        bytes[SERVING_IDENTITY_DIGEST_START..COMPONENT_STATE_DIGEST_START]
            .copy_from_slice(&state.commitment.serving_identity_digest);
        bytes[COMPONENT_STATE_DIGEST_START..]
            .copy_from_slice(&state.commitment.component_state_digest);
        Self(bytes)
    }

    /// Decodes and validates one fixed-width local snapshot.
    pub(super) fn into_business(
        self,
    ) -> Result<SecurityStateSnapshot, PersistentSecurityStateError> {
        if &self.0[FILE_MAGIC_START..FILE_VERSION_START] != SECURITY_STATE_FILE_MAGIC {
            return Err(PersistentSecurityStateError::InvalidMagic);
        }
        let file_version = read_u16(&self.0, FILE_VERSION_START)?;
        if file_version != SECURITY_STATE_FILE_VERSION {
            return Err(PersistentSecurityStateError::UnsupportedVersion {
                actual: file_version,
            });
        }
        let sequence = read_u64(&self.0, SEQUENCE_START)?;
        let epochs = SecurityStateEpochs::new(
            read_u16(&self.0, PROTOCOL_VERSION_START)?,
            read_u64(&self.0, OWNER_GENERATION_START)?,
            read_u64(&self.0, KEY_EPOCH_START)?,
            read_u64(&self.0, PROJECTION_EPOCH_START)?,
        )
        .map_err(PersistentSecurityStateError::InvalidState)?;
        let identity = SecurityStateIdentity::new(
            read_array(&self.0, SERVICE_ID_START)?,
            epochs,
            read_array(&self.0, PROFILE_ID_START)?,
            read_array(&self.0, SESSION_BINDING_START)?,
            read_array(&self.0, SECURITY_EPOCH_BINDING_START)?,
        )
        .map_err(PersistentSecurityStateError::InvalidState)?;
        let commitment = SecurityStateCommitment::new(
            identity,
            read_array(&self.0, SERVING_IDENTITY_DIGEST_START)?,
            read_array(&self.0, COMPONENT_STATE_DIGEST_START)?,
        )
        .map_err(PersistentSecurityStateError::InvalidState)?;
        SecurityStateSnapshot::new(sequence, commitment)
            .map_err(PersistentSecurityStateError::InvalidState)
    }

    fn try_from_bytes(bytes: &[u8]) -> Result<Self, PersistentSecurityStateError> {
        if bytes.len() != PERSISTENT_SECURITY_STATE_BYTES {
            return Err(PersistentSecurityStateError::InvalidFixedLayout);
        }
        let mut fixed = [0; PERSISTENT_SECURITY_STATE_BYTES];
        fixed.copy_from_slice(bytes);
        Ok(Self(fixed))
    }

    fn as_bytes(&self) -> &[u8; PERSISTENT_SECURITY_STATE_BYTES] {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PersistentSecurityStateError {
    InvalidFixedLayout,
    InvalidMagic,
    UnsupportedVersion { actual: u16 },
    InvalidState(SecurityStateValueError),
}

impl fmt::Display for PersistentSecurityStateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidFixedLayout => f.write_str("security state has an invalid fixed layout"),
            Self::InvalidMagic => f.write_str("security state has invalid magic bytes"),
            Self::UnsupportedVersion { .. } => {
                f.write_str("security state has an unsupported file version")
            }
            Self::InvalidState(_) => f.write_str("security state violates identity invariants"),
        }
    }
}

impl std::error::Error for PersistentSecurityStateError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidState(error) => Some(error),
            _ => None,
        }
    }
}

/// Local/witness reconciliation or commit failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SecurityStateStoreError {
    LatchedIndeterminate,
    WitnessUnavailable,
    UnexpectedLocalStateWithoutWitness,
    WitnessBoundStateMissing,
    WitnessBoundStateUnreadable,
    WitnessBoundStateCorrupt,
    WitnessLocalMismatch,
    ExpectedStateMismatch,
    InvalidSequenceTransition,
    InvalidIdentityTransition(SecurityStateSuccessorError),
    UnsafeRecoveryPath,
    LocalStateStageUnavailable,
    LocalStateIndeterminate,
    WitnessAdvanceUnresolved,
}

impl fmt::Display for SecurityStateStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LatchedIndeterminate => {
                f.write_str("security state store is latched indeterminate")
            }
            Self::WitnessUnavailable => f.write_str("security freshness witness is unavailable"),
            Self::UnexpectedLocalStateWithoutWitness => {
                f.write_str("local security state exists without witness authority")
            }
            Self::WitnessBoundStateMissing => {
                f.write_str("freshness-bound local security state is missing")
            }
            Self::WitnessBoundStateUnreadable => {
                f.write_str("freshness-bound local security state is unreadable")
            }
            Self::WitnessBoundStateCorrupt => {
                f.write_str("freshness-bound local security state is corrupt")
            }
            Self::WitnessLocalMismatch => {
                f.write_str("local security state does not match freshness authority")
            }
            Self::ExpectedStateMismatch => f.write_str("expected security state is not current"),
            Self::InvalidSequenceTransition => {
                f.write_str("security state sequence transition is invalid")
            }
            Self::InvalidIdentityTransition(_) => {
                f.write_str("security state identity transition is invalid")
            }
            Self::UnsafeRecoveryPath => {
                f.write_str("security state recovery path is not a real directory")
            }
            Self::LocalStateStageUnavailable => {
                f.write_str("security state could not be staged durably")
            }
            Self::LocalStateIndeterminate => {
                f.write_str("local security-state commit is indeterminate")
            }
            Self::WitnessAdvanceUnresolved => {
                f.write_str("security freshness witness advance is unresolved")
            }
        }
    }
}

impl std::error::Error for SecurityStateStoreError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SecurityStateStoreHealth {
    Ready,
    Indeterminate,
}

#[derive(Debug)]
enum LocalStateLoadError {
    Missing,
    Unreadable,
    Corrupt,
}

/// Local snapshot store coupled to an externally authoritative witness.
struct SecurityStateStore<W> {
    recovery_directory: PathBuf,
    witness: W,
    health: SecurityStateStoreHealth,
}

/// Locally staged state plus the witness transition it will authorize.
struct StagedSecurityState {
    file: NamedTempFile,
    expected_freshness: Option<SecurityFreshness>,
    next_freshness: SecurityFreshness,
}

/// A locally durable state transition awaiting witness authorization.
struct DurableSecurityStateAdvance {
    expected_freshness: Option<SecurityFreshness>,
    next_freshness: SecurityFreshness,
}

impl<W> SecurityStateStore<W> {
    fn new(root: impl Into<PathBuf>, witness: W) -> Self {
        Self {
            recovery_directory: root.into(),
            witness,
            health: SecurityStateStoreHealth::Ready,
        }
    }

    fn current_path(&self) -> PathBuf {
        self.recovery_directory.join(CURRENT_STATE_FILE)
    }

    fn staging_directory(&self) -> PathBuf {
        self.recovery_directory.join(STAGING_DIRECTORY)
    }

    fn load_local_state(&self) -> Result<SecurityStateSnapshot, LocalStateLoadError> {
        let path = self.current_path();
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(LocalStateLoadError::Missing);
            }
            Err(_) => return Err(LocalStateLoadError::Unreadable),
        };
        if !metadata.file_type().is_file() {
            return Err(LocalStateLoadError::Corrupt);
        }
        let mut file = match fs::File::open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(LocalStateLoadError::Missing);
            }
            Err(_) => return Err(LocalStateLoadError::Unreadable),
        };
        let mut bytes = [0; PERSISTENT_SECURITY_STATE_BYTES];
        match file.read_exact(&mut bytes) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
                return Err(LocalStateLoadError::Corrupt);
            }
            Err(_) => return Err(LocalStateLoadError::Unreadable),
        }
        let mut trailing = [0; 1];
        match file.read(&mut trailing) {
            Ok(0) => {}
            Ok(_) => return Err(LocalStateLoadError::Corrupt),
            Err(_) => return Err(LocalStateLoadError::Unreadable),
        }
        PersistentSecurityState(bytes)
            .into_business()
            .map_err(|_| LocalStateLoadError::Corrupt)
    }

    fn ensure_directories(&self) -> Result<(), SecurityStateStoreError> {
        ensure_real_directory(&self.recovery_directory).map_err(map_security_directory_error)?;
        ensure_real_directory(&self.staging_directory()).map_err(map_security_directory_error)?;
        if let Some(parent) = self
            .recovery_directory
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            sync_directory(parent)
                .map_err(|_| SecurityStateStoreError::LocalStateStageUnavailable)?;
        }
        sync_directory(&self.recovery_directory)
            .map_err(|_| SecurityStateStoreError::LocalStateStageUnavailable)?;
        sync_directory(&self.staging_directory())
            .map_err(|_| SecurityStateStoreError::LocalStateStageUnavailable)
    }

    fn latch(&mut self, error: SecurityStateStoreError) -> SecurityStateStoreError {
        self.health = SecurityStateStoreHealth::Indeterminate;
        error
    }
}

impl<W> SecurityStateStore<W>
where
    W: SecurityFreshnessWitness,
{
    /// Returns only local state that exactly matches the external witness.
    fn current(&mut self) -> Result<Option<SecurityStateSnapshot>, SecurityStateStoreError> {
        if self.health == SecurityStateStoreHealth::Indeterminate {
            return Err(SecurityStateStoreError::LatchedIndeterminate);
        }
        let freshness = self
            .witness
            .current()
            .map_err(|_| SecurityStateStoreError::WitnessUnavailable)?;
        reconcile_local_state(freshness, self.load_local_state())
    }

    /// Advances the exact state after committing it locally and before return.
    fn compare_and_advance(
        &mut self,
        expected: Option<SecurityStateSnapshot>,
        next: SecurityStateSnapshot,
    ) -> Result<(), SecurityStateStoreError> {
        let staged = self.stage_advance(expected, next)?;
        let durable = self.make_local_advance_durable(staged)?;
        self.advance_witness(durable)
    }

    /// Validates and stages the next local state without replacing authority.
    fn stage_advance(
        &mut self,
        expected: Option<SecurityStateSnapshot>,
        next: SecurityStateSnapshot,
    ) -> Result<StagedSecurityState, SecurityStateStoreError> {
        let current = self.current()?;
        if current != expected {
            return Err(SecurityStateStoreError::ExpectedStateMismatch);
        }
        let valid_sequence = match current {
            None => next.sequence() == 1,
            Some(state) => state
                .sequence()
                .checked_add(1)
                .is_some_and(|sequence| sequence == next.sequence()),
        };
        if !valid_sequence {
            return Err(SecurityStateStoreError::InvalidSequenceTransition);
        }
        if let Some(current) = current {
            current
                .commitment
                .identity
                .validate_successor(&next.commitment.identity)
                .map_err(SecurityStateStoreError::InvalidIdentityTransition)?;
        }

        self.ensure_directories()?;
        let persistent = PersistentSecurityState::from_business(&next);
        let mut stage = create_unique_file(&self.staging_directory(), "security-state")
            .map_err(|_| SecurityStateStoreError::LocalStateStageUnavailable)?;
        stage
            .write_all(persistent.as_bytes())
            .and_then(|()| stage.as_file().sync_all())
            .map_err(|_| SecurityStateStoreError::LocalStateStageUnavailable)?;
        Ok(StagedSecurityState {
            file: stage,
            expected_freshness: expected.map(|state| state.freshness()),
            next_freshness: next.freshness(),
        })
    }

    /// Atomically replaces and synchronizes local authority before witness I/O.
    fn make_local_advance_durable(
        &mut self,
        staged: StagedSecurityState,
    ) -> Result<DurableSecurityStateAdvance, SecurityStateStoreError> {
        if fs::rename(staged.file.path(), self.current_path()).is_err() {
            return Err(self.latch(SecurityStateStoreError::LocalStateIndeterminate));
        }
        drop(staged.file);
        if sync_directory(&self.recovery_directory).is_err()
            || sync_directory(&self.staging_directory()).is_err()
        {
            return Err(self.latch(SecurityStateStoreError::LocalStateIndeterminate));
        }
        Ok(DurableSecurityStateAdvance {
            expected_freshness: staged.expected_freshness,
            next_freshness: staged.next_freshness,
        })
    }

    /// Makes a durable local transition externally authoritative.
    fn advance_witness(
        &mut self,
        durable: DurableSecurityStateAdvance,
    ) -> Result<(), SecurityStateStoreError> {
        if self
            .witness
            .compare_and_advance(durable.expected_freshness, durable.next_freshness)
            .is_err()
        {
            return Err(self.latch(SecurityStateStoreError::WitnessAdvanceUnresolved));
        }
        Ok(())
    }
}

impl<W> fmt::Debug for SecurityStateStore<W> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecurityStateStore")
            .field("recovery_directory", &self.recovery_directory)
            .field("witness", &"..REDACTED..")
            .field("health", &self.health)
            .finish()
    }
}

fn map_security_directory_error(error: RealDirectoryError) -> SecurityStateStoreError {
    match error {
        RealDirectoryError::Io(_) => SecurityStateStoreError::LocalStateStageUnavailable,
        RealDirectoryError::UnsafePath => SecurityStateStoreError::UnsafeRecoveryPath,
    }
}

fn reconcile_local_state(
    freshness: Option<SecurityFreshness>,
    local: Result<SecurityStateSnapshot, LocalStateLoadError>,
) -> Result<Option<SecurityStateSnapshot>, SecurityStateStoreError> {
    match (freshness, local) {
        (None, Err(LocalStateLoadError::Missing)) => Ok(None),
        (None, _) => Err(SecurityStateStoreError::UnexpectedLocalStateWithoutWitness),
        (Some(_), Err(LocalStateLoadError::Missing)) => {
            Err(SecurityStateStoreError::WitnessBoundStateMissing)
        }
        (Some(_), Err(LocalStateLoadError::Unreadable)) => {
            Err(SecurityStateStoreError::WitnessBoundStateUnreadable)
        }
        (Some(_), Err(LocalStateLoadError::Corrupt)) => {
            Err(SecurityStateStoreError::WitnessBoundStateCorrupt)
        }
        (Some(freshness), Ok(state)) => {
            if state.freshness() == freshness {
                Ok(Some(state))
            } else {
                Err(SecurityStateStoreError::WitnessLocalMismatch)
            }
        }
    }
}

fn all_zero<const N: usize>(bytes: &[u8; N]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

fn read_u16(
    bytes: &[u8; PERSISTENT_SECURITY_STATE_BYTES],
    offset: usize,
) -> Result<u16, PersistentSecurityStateError> {
    Ok(u16::from_be_bytes(read_array(bytes, offset)?))
}

fn read_u64(
    bytes: &[u8; PERSISTENT_SECURITY_STATE_BYTES],
    offset: usize,
) -> Result<u64, PersistentSecurityStateError> {
    Ok(u64::from_be_bytes(read_array(bytes, offset)?))
}

fn read_array<const N: usize>(
    bytes: &[u8; PERSISTENT_SECURITY_STATE_BYTES],
    offset: usize,
) -> Result<[u8; N], PersistentSecurityStateError> {
    let end = offset
        .checked_add(N)
        .ok_or(PersistentSecurityStateError::InvalidFixedLayout)?;
    bytes
        .get(offset..end)
        .ok_or(PersistentSecurityStateError::InvalidFixedLayout)?
        .try_into()
        .map_err(|_| PersistentSecurityStateError::InvalidFixedLayout)
}

#[cfg(test)]
mod tests {
    use std::{
        error::Error,
        fs,
        path::{Path, PathBuf},
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc, Mutex,
        },
    };

    use super::*;

    type TestResult<T = ()> = Result<T, Box<dyn Error>>;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum TestWitnessError {
        Unavailable,
        Conflict,
        InvalidTransition,
        LocalOrder,
        Poisoned,
    }

    impl fmt::Display for TestWitnessError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::Unavailable => f.write_str("test witness unavailable"),
                Self::Conflict => f.write_str("test witness compare conflict"),
                Self::InvalidTransition => f.write_str("test witness transition invalid"),
                Self::LocalOrder => f.write_str("test witness observed non-durable local state"),
                Self::Poisoned => f.write_str("test witness mutex poisoned"),
            }
        }
    }

    impl Error for TestWitnessError {}

    #[derive(Clone)]
    struct SharedWitness {
        state: Arc<Mutex<Option<SecurityFreshness>>>,
        available: Arc<AtomicBool>,
        reject_advance: Arc<AtomicBool>,
        advance_then_fail: Arc<AtomicBool>,
        inspected_current_path: Arc<Mutex<Option<PathBuf>>>,
        saw_matching_local_state: Arc<AtomicBool>,
    }

    impl SharedWitness {
        fn empty() -> Self {
            Self {
                state: Arc::new(Mutex::new(None)),
                available: Arc::new(AtomicBool::new(true)),
                reject_advance: Arc::new(AtomicBool::new(false)),
                advance_then_fail: Arc::new(AtomicBool::new(false)),
                inspected_current_path: Arc::new(Mutex::new(None)),
                saw_matching_local_state: Arc::new(AtomicBool::new(false)),
            }
        }

        fn value(&self) -> Result<Option<SecurityFreshness>, TestWitnessError> {
            self.state
                .lock()
                .map(|guard| *guard)
                .map_err(|_| TestWitnessError::Poisoned)
        }

        fn force(&self, value: Option<SecurityFreshness>) -> Result<(), TestWitnessError> {
            let mut guard = self.state.lock().map_err(|_| TestWitnessError::Poisoned)?;
            *guard = value;
            Ok(())
        }

        fn set_available(&self, available: bool) {
            self.available.store(available, Ordering::SeqCst);
        }

        fn set_reject_advance(&self, reject: bool) {
            self.reject_advance.store(reject, Ordering::SeqCst);
        }

        fn set_advance_then_fail(&self) {
            self.advance_then_fail.store(true, Ordering::SeqCst);
        }

        fn inspect_current_path(&self, path: PathBuf) -> Result<(), TestWitnessError> {
            let mut guard = self
                .inspected_current_path
                .lock()
                .map_err(|_| TestWitnessError::Poisoned)?;
            *guard = Some(path);
            Ok(())
        }

        fn saw_matching_local_state(&self) -> bool {
            self.saw_matching_local_state.load(Ordering::SeqCst)
        }

        fn verify_local_before_advance(
            &self,
            next: SecurityFreshness,
        ) -> Result<(), TestWitnessError> {
            let path = self
                .inspected_current_path
                .lock()
                .map_err(|_| TestWitnessError::Poisoned)?
                .clone();
            let Some(path) = path else {
                return Ok(());
            };
            let bytes = fs::read(path).map_err(|_| TestWitnessError::LocalOrder)?;
            let state = PersistentSecurityState::try_from_bytes(&bytes)
                .and_then(PersistentSecurityState::into_business)
                .map_err(|_| TestWitnessError::LocalOrder)?;
            if state.freshness() != next {
                return Err(TestWitnessError::LocalOrder);
            }
            self.saw_matching_local_state.store(true, Ordering::SeqCst);
            Ok(())
        }
    }

    impl SecurityFreshnessWitness for SharedWitness {
        type Error = TestWitnessError;

        fn current(&mut self) -> Result<Option<SecurityFreshness>, Self::Error> {
            if !self.available.load(Ordering::SeqCst) {
                return Err(TestWitnessError::Unavailable);
            }
            self.value()
        }

        fn compare_and_advance(
            &mut self,
            expected: Option<SecurityFreshness>,
            next: SecurityFreshness,
        ) -> Result<(), Self::Error> {
            if !self.available.load(Ordering::SeqCst) {
                return Err(TestWitnessError::Unavailable);
            }
            self.verify_local_before_advance(next)?;
            let mut guard = self.state.lock().map_err(|_| TestWitnessError::Poisoned)?;
            if *guard != expected {
                return Err(TestWitnessError::Conflict);
            }
            let valid_sequence = match expected {
                None => next.sequence() == 1,
                Some(current) => current
                    .sequence()
                    .checked_add(1)
                    .is_some_and(|sequence| sequence == next.sequence()),
            };
            if !valid_sequence {
                return Err(TestWitnessError::InvalidTransition);
            }
            if self.advance_then_fail.swap(false, Ordering::SeqCst) {
                *guard = Some(next);
                return Err(TestWitnessError::Unavailable);
            }
            if self.reject_advance.load(Ordering::SeqCst) {
                return Err(TestWitnessError::Unavailable);
            }
            *guard = Some(next);
            Ok(())
        }
    }

    fn identity(seed: u8) -> Result<SecurityStateIdentity, SecurityStateValueError> {
        let epochs = SecurityStateEpochs::new(
            u16::from(seed),
            u64::from(seed) + 1,
            u64::from(seed) + 2,
            u64::from(seed) + 3,
        )?;
        SecurityStateIdentity::new(
            [seed; SERVICE_ID_BYTES],
            epochs,
            [seed.wrapping_add(1); PROFILE_ID_BYTES],
            [seed.wrapping_add(2); SESSION_BINDING_BYTES],
            [seed.wrapping_add(3); SECURITY_EPOCH_BINDING_BYTES],
        )
    }

    fn commitment(seed: u8) -> Result<SecurityStateCommitment, SecurityStateValueError> {
        commitment_for_identity(identity(seed)?, seed)
    }

    fn commitment_for_identity(
        identity: SecurityStateIdentity,
        seed: u8,
    ) -> Result<SecurityStateCommitment, SecurityStateValueError> {
        SecurityStateCommitment::new(
            identity,
            [seed.wrapping_add(4); STATE_DIGEST_BYTES],
            [seed.wrapping_add(5); STATE_DIGEST_BYTES],
        )
    }

    fn state(sequence: u64, seed: u8) -> Result<SecurityStateSnapshot, SecurityStateValueError> {
        SecurityStateSnapshot::new(sequence, commitment(seed)?)
    }

    fn state_with_identity(
        sequence: u64,
        identity: SecurityStateIdentity,
        seed: u8,
    ) -> Result<SecurityStateSnapshot, SecurityStateValueError> {
        SecurityStateSnapshot::new(sequence, commitment_for_identity(identity, seed)?)
    }

    fn write_local_state(root: &Path, state: SecurityStateSnapshot) -> TestResult {
        fs::create_dir_all(root)?;
        fs::write(
            root.join(CURRENT_STATE_FILE),
            PersistentSecurityState::from_business(&state).as_bytes(),
        )?;
        Ok(())
    }

    fn assert_digest_changed(
        base: SecurityStateCommitment,
        mutate: impl FnOnce(&mut SecurityStateCommitment),
    ) {
        let mut changed = base;
        mutate(&mut changed);
        assert_ne!(changed.digest(), base.digest());
    }

    #[test]
    fn security_state_values_reject_every_zero_required_field() -> TestResult {
        let valid = identity(1)?;
        assert_eq!(
            SecurityStateIdentity::new(
                [0; SERVICE_ID_BYTES],
                valid.epochs,
                valid.profile_id,
                valid.session_binding,
                valid.security_epoch_binding,
            ),
            Err(SecurityStateValueError::ServiceIdIsEmpty)
        );
        assert!(matches!(
            SecurityStateEpochs::new(
                0,
                valid.epochs.owner_generation,
                valid.epochs.key_epoch,
                valid.epochs.projection_epoch,
            ),
            Err(SecurityStateValueError::ProtocolVersionIsZero)
        ));
        assert!(matches!(
            SecurityStateEpochs::new(
                valid.epochs.protocol_version,
                0,
                valid.epochs.key_epoch,
                valid.epochs.projection_epoch,
            ),
            Err(SecurityStateValueError::OwnerGenerationIsMissing)
        ));
        assert!(matches!(
            SecurityStateEpochs::new(
                valid.epochs.protocol_version,
                valid.epochs.owner_generation,
                0,
                valid.epochs.projection_epoch,
            ),
            Err(SecurityStateValueError::KeyEpochIsMissing)
        ));
        assert!(matches!(
            SecurityStateEpochs::new(
                valid.epochs.protocol_version,
                valid.epochs.owner_generation,
                valid.epochs.key_epoch,
                0,
            ),
            Err(SecurityStateValueError::ProjectionEpochIsMissing)
        ));
        assert_eq!(
            SecurityStateIdentity::new(
                valid.service_id,
                valid.epochs,
                [0; PROFILE_ID_BYTES],
                valid.session_binding,
                valid.security_epoch_binding,
            ),
            Err(SecurityStateValueError::ProfileIdIsEmpty)
        );
        assert_eq!(
            SecurityStateIdentity::new(
                valid.service_id,
                valid.epochs,
                valid.profile_id,
                [0; SESSION_BINDING_BYTES],
                valid.security_epoch_binding,
            ),
            Err(SecurityStateValueError::SessionBindingIsEmpty)
        );
        assert_eq!(
            SecurityStateIdentity::new(
                valid.service_id,
                valid.epochs,
                valid.profile_id,
                valid.session_binding,
                [0; SECURITY_EPOCH_BINDING_BYTES],
            ),
            Err(SecurityStateValueError::SecurityEpochBindingIsEmpty)
        );
        assert_eq!(
            SecurityStateCommitment::new(valid, [0; STATE_DIGEST_BYTES], [1; STATE_DIGEST_BYTES]),
            Err(SecurityStateValueError::ServingIdentityDigestIsEmpty)
        );
        assert_eq!(
            SecurityStateCommitment::new(valid, [1; STATE_DIGEST_BYTES], [0; STATE_DIGEST_BYTES]),
            Err(SecurityStateValueError::ComponentStateDigestIsEmpty)
        );
        assert_eq!(
            SecurityStateSnapshot::new(0, commitment(1)?),
            Err(SecurityStateValueError::SequenceIsMissing)
        );
        Ok(())
    }

    #[test]
    fn security_state_identity_successor_rejects_namespace_and_epoch_rollback() -> TestResult {
        let current = identity(7)?;
        assert_eq!(current.validate_successor(&current), Ok(()));

        let mut changed_service = current;
        changed_service.service_id[0] ^= 1;
        assert_eq!(
            current.validate_successor(&changed_service),
            Err(SecurityStateSuccessorError::ServiceIdentityChanged)
        );

        let mut changed_protocol = current;
        changed_protocol.epochs.protocol_version += 1;
        assert_eq!(
            current.validate_successor(&changed_protocol),
            Err(SecurityStateSuccessorError::ProtocolVersionChanged)
        );

        let mut changed_profile = current;
        changed_profile.profile_id[0] ^= 1;
        assert_eq!(
            current.validate_successor(&changed_profile),
            Err(SecurityStateSuccessorError::ProfileIdentityChanged)
        );

        let mut regressed_owner = current;
        regressed_owner.epochs.owner_generation -= 1;
        assert_eq!(
            current.validate_successor(&regressed_owner),
            Err(SecurityStateSuccessorError::OwnerGenerationRegressed)
        );

        let mut regressed_key = current;
        regressed_key.epochs.key_epoch -= 1;
        assert_eq!(
            current.validate_successor(&regressed_key),
            Err(SecurityStateSuccessorError::KeyEpochRegressed)
        );

        let mut regressed_projection = current;
        regressed_projection.epochs.projection_epoch -= 1;
        assert_eq!(
            current.validate_successor(&regressed_projection),
            Err(SecurityStateSuccessorError::ProjectionEpochRegressed)
        );

        let mut key_only_rotation = current;
        key_only_rotation.epochs.key_epoch += 1;
        assert_eq!(
            current.validate_successor(&key_only_rotation),
            Err(SecurityStateSuccessorError::OwnerGenerationDidNotAdvance)
        );

        let mut incomplete_rotation = current;
        incomplete_rotation.epochs.owner_generation += 1;
        incomplete_rotation.epochs.key_epoch += 1;
        incomplete_rotation.epochs.projection_epoch += 1;
        assert_eq!(
            current.validate_successor(&incomplete_rotation),
            Err(SecurityStateSuccessorError::SessionBindingNotRotated)
        );
        incomplete_rotation.session_binding[0] ^= 1;
        assert_eq!(
            current.validate_successor(&incomplete_rotation),
            Err(SecurityStateSuccessorError::SecurityEpochBindingNotRotated)
        );
        incomplete_rotation.security_epoch_binding[0] ^= 1;
        assert_eq!(current.validate_successor(&incomplete_rotation), Ok(()));
        Ok(())
    }

    #[test]
    fn persistent_security_state_round_trips_exact_fixed_layout() -> TestResult {
        let state = state(9, 7)?;
        let persistent = PersistentSecurityState::from_business(&state);
        assert_eq!(persistent.as_bytes().len(), PERSISTENT_SECURITY_STATE_BYTES);
        assert_eq!(
            &persistent.as_bytes()[FILE_MAGIC_START..FILE_VERSION_START],
            SECURITY_STATE_FILE_MAGIC
        );
        assert_eq!(
            &persistent.as_bytes()[FILE_VERSION_START..SEQUENCE_START],
            &SECURITY_STATE_FILE_VERSION.to_be_bytes()
        );
        assert_eq!(
            &persistent.as_bytes()[SEQUENCE_START..SERVICE_ID_START],
            &9_u64.to_be_bytes()
        );
        assert_eq!(
            std::mem::size_of::<PersistentSecurityState>(),
            PERSISTENT_SECURITY_STATE_BYTES
        );
        let encoded_hex = persistent
            .as_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        assert_eq!(
            encoded_hex,
            concat!(
                "5a4f52414d535331",
                "0001",
                "0000000000000009",
                "07070707070707070707070707070707",
                "0007",
                "0000000000000008",
                "0000000000000009",
                "000000000000000a",
                "08080808080808080808080808080808",
                "09090909090909090909090909090909",
                "09090909090909090909090909090909",
                "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a",
                "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a",
                "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
                "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
                "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
                "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
            )
        );
        assert_eq!(persistent.into_business()?, state);
        Ok(())
    }

    #[test]
    fn persistent_security_state_rejects_layout_version_and_business_mutations() -> TestResult {
        let state = state(1, 3)?;
        let valid = PersistentSecurityState::from_business(&state);
        assert!(matches!(
            PersistentSecurityState::try_from_bytes(
                &valid.as_bytes()[..PERSISTENT_SECURITY_STATE_BYTES - 1]
            ),
            Err(PersistentSecurityStateError::InvalidFixedLayout)
        ));

        let mut wrong_magic = PersistentSecurityState::from_business(&state);
        wrong_magic.0[FILE_MAGIC_START] ^= 1;
        assert_eq!(
            wrong_magic.into_business(),
            Err(PersistentSecurityStateError::InvalidMagic)
        );

        let mut wrong_version = PersistentSecurityState::from_business(&state);
        wrong_version.0[FILE_VERSION_START..SEQUENCE_START].copy_from_slice(&2_u16.to_be_bytes());
        assert_eq!(
            wrong_version.into_business(),
            Err(PersistentSecurityStateError::UnsupportedVersion { actual: 2 })
        );

        let mut zero_sequence = PersistentSecurityState::from_business(&state);
        zero_sequence.0[SEQUENCE_START..SERVICE_ID_START].fill(0);
        assert_eq!(
            zero_sequence.into_business(),
            Err(PersistentSecurityStateError::InvalidState(
                SecurityStateValueError::SequenceIsMissing
            ))
        );

        let mut zero_session = PersistentSecurityState::from_business(&state);
        zero_session.0[SESSION_BINDING_START..SECURITY_EPOCH_BINDING_START].fill(0);
        assert_eq!(
            zero_session.into_business(),
            Err(PersistentSecurityStateError::InvalidState(
                SecurityStateValueError::SessionBindingIsEmpty
            ))
        );
        Ok(())
    }

    #[test]
    fn commitment_digest_binds_every_field_but_sequence_is_separate() -> TestResult {
        let base = commitment(4)?;
        assert_digest_changed(base, |value| value.identity.service_id[0] ^= 1);
        assert_digest_changed(base, |value| value.identity.epochs.protocol_version += 1);
        assert_digest_changed(base, |value| value.identity.epochs.owner_generation += 1);
        assert_digest_changed(base, |value| value.identity.epochs.key_epoch += 1);
        assert_digest_changed(base, |value| value.identity.epochs.projection_epoch += 1);
        assert_digest_changed(base, |value| value.identity.profile_id[0] ^= 1);
        assert_digest_changed(base, |value| value.identity.session_binding[0] ^= 1);
        assert_digest_changed(base, |value| value.identity.security_epoch_binding[0] ^= 1);
        assert_digest_changed(base, |value| value.serving_identity_digest[0] ^= 1);
        assert_digest_changed(base, |value| value.component_state_digest[0] ^= 1);

        let first = SecurityStateSnapshot::new(1, base)?;
        let second = SecurityStateSnapshot::new(2, base)?;
        assert_eq!(first.commitment.digest(), second.commitment.digest());
        assert_ne!(first.freshness(), second.freshness());
        Ok(())
    }

    #[test]
    fn current_returns_none_only_when_witness_and_local_state_are_absent() -> TestResult {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("security");
        let witness = SharedWitness::empty();
        let mut store = SecurityStateStore::new(&root, witness.clone());
        assert_eq!(store.current(), Ok(None));

        witness.set_available(false);
        assert_eq!(
            store.current(),
            Err(SecurityStateStoreError::WitnessUnavailable)
        );
        witness.set_available(true);
        assert_eq!(store.current(), Ok(None));
        Ok(())
    }

    #[test]
    fn current_rejects_every_local_and_witness_mismatch_class() -> TestResult {
        let local_without_witness = tempfile::tempdir()?;
        let local_root = local_without_witness.path().join("security");
        let local_state = state(1, 8)?;
        write_local_state(&local_root, local_state)?;
        let mut store = SecurityStateStore::new(&local_root, SharedWitness::empty());
        assert_eq!(
            store.current(),
            Err(SecurityStateStoreError::UnexpectedLocalStateWithoutWitness)
        );

        let witness_without_local = tempfile::tempdir()?;
        let missing_root = witness_without_local.path().join("security");
        let missing_witness = SharedWitness::empty();
        missing_witness.force(Some(local_state.freshness()))?;
        let mut store = SecurityStateStore::new(&missing_root, missing_witness);
        assert_eq!(
            store.current(),
            Err(SecurityStateStoreError::WitnessBoundStateMissing)
        );

        let corrupt_directory = tempfile::tempdir()?;
        let corrupt_root = corrupt_directory.path().join("security");
        fs::create_dir_all(&corrupt_root)?;
        fs::write(corrupt_root.join(CURRENT_STATE_FILE), b"corrupt")?;
        let corrupt_witness = SharedWitness::empty();
        corrupt_witness.force(Some(local_state.freshness()))?;
        let mut store = SecurityStateStore::new(&corrupt_root, corrupt_witness);
        assert_eq!(
            store.current(),
            Err(SecurityStateStoreError::WitnessBoundStateCorrupt)
        );

        assert_eq!(
            reconcile_local_state(
                Some(local_state.freshness()),
                Err(LocalStateLoadError::Unreadable)
            ),
            Err(SecurityStateStoreError::WitnessBoundStateUnreadable)
        );
        assert_eq!(
            reconcile_local_state(None, Err(LocalStateLoadError::Unreadable)),
            Err(SecurityStateStoreError::UnexpectedLocalStateWithoutWitness)
        );

        let mismatch_directory = tempfile::tempdir()?;
        let mismatch_root = mismatch_directory.path().join("security");
        write_local_state(&mismatch_root, local_state)?;
        let mismatch_witness = SharedWitness::empty();
        mismatch_witness.force(Some(state(2, 9)?.freshness()))?;
        let mut store = SecurityStateStore::new(&mismatch_root, mismatch_witness);
        assert_eq!(
            store.current(),
            Err(SecurityStateStoreError::WitnessLocalMismatch)
        );
        Ok(())
    }

    #[test]
    fn current_rejects_an_oversized_local_snapshot() -> TestResult {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("security");
        let local_state = state(1, 9)?;
        fs::create_dir_all(&root)?;
        let mut oversized = PersistentSecurityState::from_business(&local_state)
            .as_bytes()
            .to_vec();
        oversized.push(0);
        fs::write(root.join(CURRENT_STATE_FILE), oversized)?;
        let witness = SharedWitness::empty();
        witness.force(Some(local_state.freshness()))?;
        let mut store = SecurityStateStore::new(&root, witness);

        assert_eq!(
            store.current(),
            Err(SecurityStateStoreError::WitnessBoundStateCorrupt)
        );
        Ok(())
    }

    #[test]
    fn stale_staging_files_are_never_recovery_authority() -> TestResult {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("security");
        fs::create_dir_all(root.join(STAGING_DIRECTORY))?;
        fs::write(root.join(STAGING_DIRECTORY).join("orphan.tmp"), b"state")?;
        let mut store = SecurityStateStore::new(&root, SharedWitness::empty());
        assert_eq!(store.current(), Ok(None));
        Ok(())
    }

    #[test]
    fn compare_and_advance_commits_local_state_before_witness() -> TestResult {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("security");
        let witness = SharedWitness::empty();
        witness.inspect_current_path(root.join(CURRENT_STATE_FILE))?;
        let mut store = SecurityStateStore::new(&root, witness.clone());
        let first = state(1, 10)?;

        store.compare_and_advance(None, first)?;

        assert!(witness.saw_matching_local_state());
        assert_eq!(witness.value()?, Some(first.freshness()));
        assert_eq!(store.current()?, Some(first));
        Ok(())
    }

    #[test]
    fn compare_and_advance_requires_exact_expected_state_and_successor_sequence() -> TestResult {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("security");
        let witness = SharedWitness::empty();
        let mut store = SecurityStateStore::new(&root, witness);
        let first = state(1, 11)?;
        let alternate_first = state(1, 12)?;
        let second = state_with_identity(2, first.commitment.identity, 13)?;
        let skipped = state_with_identity(3, first.commitment.identity, 14)?;

        assert_eq!(
            store.compare_and_advance(Some(alternate_first), first),
            Err(SecurityStateStoreError::ExpectedStateMismatch)
        );
        assert_eq!(
            store.compare_and_advance(None, second),
            Err(SecurityStateStoreError::InvalidSequenceTransition)
        );
        store.compare_and_advance(None, first)?;
        assert_eq!(
            store.compare_and_advance(Some(alternate_first), second),
            Err(SecurityStateStoreError::ExpectedStateMismatch)
        );
        assert_eq!(
            store.compare_and_advance(Some(first), skipped),
            Err(SecurityStateStoreError::InvalidSequenceTransition)
        );
        store.compare_and_advance(Some(first), second)?;
        assert_eq!(store.current()?, Some(second));
        Ok(())
    }

    #[test]
    fn compare_and_advance_rejects_identity_rollback_before_local_mutation() -> TestResult {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("security");
        let witness = SharedWitness::empty();
        let mut store = SecurityStateStore::new(&root, witness.clone());
        let first = state(1, 24)?;
        store.compare_and_advance(None, first)?;

        let mut regressed_commitment = first.commitment;
        regressed_commitment.identity.epochs.key_epoch -= 1;
        let regressed = SecurityStateSnapshot::new(2, regressed_commitment)?;
        assert_eq!(
            store.compare_and_advance(Some(first), regressed),
            Err(SecurityStateStoreError::InvalidIdentityTransition(
                SecurityStateSuccessorError::KeyEpochRegressed
            ))
        );
        assert_eq!(witness.value()?, Some(first.freshness()));
        assert_eq!(store.current()?, Some(first));
        Ok(())
    }

    #[test]
    fn sequence_overflow_fails_before_local_mutation() -> TestResult {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("security");
        let witness = SharedWitness::empty();
        let current = state(u64::MAX, 15)?;
        write_local_state(&root, current)?;
        witness.force(Some(current.freshness()))?;
        let mut store = SecurityStateStore::new(&root, witness.clone());

        assert_eq!(
            store.compare_and_advance(Some(current), current),
            Err(SecurityStateStoreError::InvalidSequenceTransition)
        );
        assert_eq!(witness.value()?, Some(current.freshness()));
        assert_eq!(store.current()?, Some(current));
        Ok(())
    }

    #[test]
    fn staged_but_unreplaced_state_is_ignored_after_restart() -> TestResult {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("security");
        let witness = SharedWitness::empty();
        let mut store = SecurityStateStore::new(&root, witness.clone());
        let first = state(1, 16)?;
        let second = state_with_identity(2, first.commitment.identity, 17)?;
        store.compare_and_advance(None, first)?;

        let staged = store.stage_advance(Some(first), second)?;
        let (_staged_file, staged_path) = staged.file.keep()?;
        drop(store);

        assert!(staged_path.exists());
        assert_eq!(witness.value()?, Some(first.freshness()));
        let mut restarted = SecurityStateStore::new(&root, witness);
        assert_eq!(restarted.current()?, Some(first));
        restarted.compare_and_advance(Some(first), second)?;
        assert_eq!(restarted.current()?, Some(second));
        Ok(())
    }

    #[test]
    fn durable_local_advance_without_witness_is_rejected_after_restart() -> TestResult {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("security");
        let witness = SharedWitness::empty();
        let mut store = SecurityStateStore::new(&root, witness.clone());
        let first = state(1, 18)?;
        let second = state_with_identity(2, first.commitment.identity, 19)?;
        store.compare_and_advance(None, first)?;

        let staged = store.stage_advance(Some(first), second)?;
        let _durable = store.make_local_advance_durable(staged)?;
        drop(store);

        let mut restarted = SecurityStateStore::new(&root, witness.clone());
        assert_eq!(
            restarted.current(),
            Err(SecurityStateStoreError::WitnessLocalMismatch)
        );
        assert_eq!(witness.value()?, Some(first.freshness()));
        witness.force(Some(second.freshness()))?;
        assert_eq!(restarted.current()?, Some(second));
        Ok(())
    }

    #[test]
    fn rejected_witness_advance_latches_after_local_commit() -> TestResult {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("security");
        let witness = SharedWitness::empty();
        let mut store = SecurityStateStore::new(&root, witness.clone());
        let first = state(1, 20)?;
        let second = state_with_identity(2, first.commitment.identity, 21)?;
        store.compare_and_advance(None, first)?;
        witness.set_reject_advance(true);

        assert_eq!(
            store.compare_and_advance(Some(first), second),
            Err(SecurityStateStoreError::WitnessAdvanceUnresolved)
        );
        assert_eq!(
            store.current(),
            Err(SecurityStateStoreError::LatchedIndeterminate)
        );
        assert_eq!(witness.value()?, Some(first.freshness()));

        witness.set_reject_advance(false);
        let mut restarted = SecurityStateStore::new(&root, witness.clone());
        assert_eq!(
            restarted.current(),
            Err(SecurityStateStoreError::WitnessLocalMismatch)
        );
        witness.force(Some(second.freshness()))?;
        assert_eq!(restarted.current()?, Some(second));
        Ok(())
    }

    #[test]
    fn ambiguous_witness_error_recovers_only_after_fresh_reconciliation() -> TestResult {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("security");
        let witness = SharedWitness::empty();
        let mut store = SecurityStateStore::new(&root, witness.clone());
        let first = state(1, 22)?;
        let second = state_with_identity(2, first.commitment.identity, 23)?;
        store.compare_and_advance(None, first)?;
        witness.set_advance_then_fail();

        assert_eq!(
            store.compare_and_advance(Some(first), second),
            Err(SecurityStateStoreError::WitnessAdvanceUnresolved)
        );
        assert_eq!(witness.value()?, Some(second.freshness()));
        assert_eq!(
            store.current(),
            Err(SecurityStateStoreError::LatchedIndeterminate)
        );

        let mut restarted = SecurityStateStore::new(&root, witness);
        assert_eq!(restarted.current()?, Some(second));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn compare_and_advance_rejects_a_symlinked_recovery_directory() -> TestResult {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir()?;
        let outside = tempfile::tempdir()?;
        let root = directory.path().join("security");
        symlink(outside.path(), &root)?;
        let mut store = SecurityStateStore::new(&root, SharedWitness::empty());

        assert_eq!(
            store.compare_and_advance(None, state(1, 20)?),
            Err(SecurityStateStoreError::UnsafeRecoveryPath)
        );
        assert!(!outside.path().join(CURRENT_STATE_FILE).exists());
        Ok(())
    }

    #[test]
    fn security_state_debug_output_redacts_identity_and_witness_values() -> TestResult {
        let state = state(1, 21)?;
        assert_eq!(
            format!("{:?}", state.commitment.identity),
            "SecurityStateIdentity { ..REDACTED.. }"
        );
        assert_eq!(
            format!("{:?}", state.commitment),
            "SecurityStateCommitment { ..REDACTED.. }"
        );
        assert_eq!(
            format!("{:?}", state.freshness()),
            "SecurityFreshness { ..REDACTED.. }"
        );
        let store = SecurityStateStore::new("/redacted/path", SharedWitness::empty());
        let debug = format!("{store:?}");
        assert!(debug.contains("REDACTED"));
        assert!(!debug.contains("SharedWitness"));
        Ok(())
    }
}
