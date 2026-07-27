//! Authenticated projection-checkpoint publication and volatile-worker recovery.
//!
//! The experimental ORAM worker is deliberately volatile: every restart rebuilds
//! it from the authoritative finalized chain. This module persists only the
//! authenticated public projection lineage needed to select the next projection
//! epoch and to detect host-controlled rollback or equivocation. Authority comes
//! from an injected external freshness witness that binds both the monotonic
//! sequence and the exact manifest digest. The local `CURRENT` file is only a
//! replaceable lookup hint and is never consulted when deciding what is current.

use std::{
    convert::Infallible,
    fmt,
    fs::{self, File},
    io::{self, Write},
    path::PathBuf,
};

use blake2::{
    digest::{KeyInit, Mac},
    Blake2s256, Blake2sMac256, Digest,
};
use zeroize::Zeroizing;

use crate::{
    canonical_chain::{CanonicalNetwork, PublicChainCheckpoint},
    persistence::fs_atomic::{
        create_unique_file, ensure_real_directory, sync_directory, RealDirectoryError,
    },
};

const EVENT_LOG_ROOT_BYTES: usize = 32;
const MANIFEST_DIGEST_BYTES: usize = 32;
const MANIFEST_MAC_BYTES: usize = 32;
const PERSISTENT_MANIFEST_BYTES: usize = 160;
const MANIFEST_BLOB_BYTES: usize = PERSISTENT_MANIFEST_BYTES + MANIFEST_MAC_BYTES;

const PERSISTENT_MANIFEST_MAGIC: &[u8; 8] = b"ZORAMPM1";
const PERSISTENT_MANIFEST_VERSION: u16 = 1;
const CURRENT_HINT_MAGIC: &[u8; 8] = b"ZORAMCU1";
const CURRENT_HINT_BYTES: usize = 8 + 8 + MANIFEST_DIGEST_BYTES;
const MANIFEST_MAC_DOMAIN: &[u8] = b"zaino-oram/projection-manifest-mac/v1\0";
const MANIFEST_DIGEST_DOMAIN: &[u8] = b"zaino-oram/projection-manifest-digest/v1\0";
const MANIFEST_DIRECTORY: &str = "manifests";
const STAGING_DIRECTORY: &str = "staging";
const CURRENT_HINT_FILE: &str = "CURRENT";
#[cfg(test)]
const MAX_UNIQUE_FILE_ATTEMPTS: usize = 64;

/// Authenticated root of every finalized projection event through a checkpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) struct ProjectionEventLogRoot([u8; EVENT_LOG_ROOT_BYTES]);

impl ProjectionEventLogRoot {
    pub(super) const fn from_bytes(bytes: [u8; EVENT_LOG_ROOT_BYTES]) -> Self {
        Self(bytes)
    }

    pub(super) const fn as_bytes(&self) -> &[u8; EVENT_LOG_ROOT_BYTES] {
        &self.0
    }

    pub(super) const fn into_bytes(self) -> [u8; EVENT_LOG_ROOT_BYTES] {
        self.0
    }
}

/// A fully validated public checkpoint publication from the projection owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ProjectionPublication {
    chain: PublicChainCheckpoint,
    schema_version: u32,
    key_epoch: u64,
    projection_epoch: u64,
    event_log_root: ProjectionEventLogRoot,
}

impl ProjectionPublication {
    pub(super) fn new(
        chain: PublicChainCheckpoint,
        schema_version: u32,
        key_epoch: u64,
        projection_epoch: u64,
        event_log_root: ProjectionEventLogRoot,
    ) -> Result<Self, ProjectionPublicationError> {
        if schema_version == 0 {
            return Err(ProjectionPublicationError::ZeroSchemaVersion);
        }
        if projection_epoch == 0 {
            return Err(ProjectionPublicationError::ZeroProjectionEpoch);
        }
        Ok(Self {
            chain,
            schema_version,
            key_epoch,
            projection_epoch,
            event_log_root,
        })
    }

    pub(super) const fn chain(&self) -> PublicChainCheckpoint {
        self.chain
    }

    pub(super) const fn schema_version(&self) -> u32 {
        self.schema_version
    }

    pub(super) const fn key_epoch(&self) -> u64 {
        self.key_epoch
    }

    pub(super) const fn projection_epoch(&self) -> u64 {
        self.projection_epoch
    }

    pub(super) const fn event_log_root(&self) -> ProjectionEventLogRoot {
        self.event_log_root
    }
}

/// A projection publication omitted a required nonzero version or epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ProjectionPublicationError {
    ZeroSchemaVersion,
    ZeroProjectionEpoch,
}

impl fmt::Display for ProjectionPublicationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroSchemaVersion => f.write_str("projection schema version is zero"),
            Self::ZeroProjectionEpoch => f.write_str("projection epoch is zero"),
        }
    }
}

impl std::error::Error for ProjectionPublicationError {}

/// Synchronous publication boundary used by the finalized projection owner.
pub(super) trait ProjectionCheckpointPublisher {
    type Error;

    /// Returns only after the publication is externally freshness-bound.
    fn publish_and_wait(&mut self, publication: &ProjectionPublication) -> Result<(), Self::Error>;
}

/// Publication sink for tests or deliberately non-durable offline owners.
#[derive(Debug, Default, Clone, Copy)]
pub(super) struct NoopProjectionCheckpointPublisher;

impl ProjectionCheckpointPublisher for NoopProjectionCheckpointPublisher {
    type Error = Infallible;

    fn publish_and_wait(
        &mut self,
        _publication: &ProjectionPublication,
    ) -> Result<(), Self::Error> {
        Ok(())
    }
}

/// Durability contract of the projection state named by a manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ProjectionDurabilityMode {
    /// Manifest metadata is durable, but the worker must be rebuilt on restart.
    VolatileWorkerRebuildRequiredV1,
}

impl ProjectionDurabilityMode {
    const fn tag(self) -> u8 {
        match self {
            Self::VolatileWorkerRebuildRequiredV1 => 1,
        }
    }

    const fn try_from_tag(tag: u8) -> Result<Self, PersistentProjectionManifestError> {
        match tag {
            1 => Ok(Self::VolatileWorkerRebuildRequiredV1),
            actual => Err(PersistentProjectionManifestError::UnknownDurabilityTag { actual }),
        }
    }
}

/// Digest of the complete fixed manifest payload and its keyed authenticator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) struct ProjectionManifestDigest([u8; MANIFEST_DIGEST_BYTES]);

impl ProjectionManifestDigest {
    pub(super) const fn from_bytes(bytes: [u8; MANIFEST_DIGEST_BYTES]) -> Self {
        Self(bytes)
    }

    pub(super) const fn as_bytes(&self) -> &[u8; MANIFEST_DIGEST_BYTES] {
        &self.0
    }

    pub(super) const fn into_bytes(self) -> [u8; MANIFEST_DIGEST_BYTES] {
        self.0
    }
}

/// One authenticated public projection lineage entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct PublishedProjectionManifest {
    chain: PublicChainCheckpoint,
    schema_version: u32,
    key_epoch: u64,
    projection_epoch: u64,
    sequence: u64,
    event_log_root: ProjectionEventLogRoot,
    previous_manifest_digest: Option<ProjectionManifestDigest>,
    durability_mode: ProjectionDurabilityMode,
}

impl PublishedProjectionManifest {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        chain: PublicChainCheckpoint,
        schema_version: u32,
        key_epoch: u64,
        projection_epoch: u64,
        sequence: u64,
        event_log_root: ProjectionEventLogRoot,
        previous_manifest_digest: Option<ProjectionManifestDigest>,
        durability_mode: ProjectionDurabilityMode,
    ) -> Result<Self, PublishedProjectionManifestError> {
        if schema_version == 0 {
            return Err(PublishedProjectionManifestError::ZeroSchemaVersion);
        }
        if projection_epoch == 0 {
            return Err(PublishedProjectionManifestError::ZeroProjectionEpoch);
        }
        if sequence == 0 {
            return Err(PublishedProjectionManifestError::ZeroSequence);
        }
        match (sequence, previous_manifest_digest) {
            (1, None) | (2.., Some(_)) => {}
            (1, Some(_)) => {
                return Err(PublishedProjectionManifestError::UnexpectedPreviousDigest);
            }
            (2.., None) => {
                return Err(PublishedProjectionManifestError::MissingPreviousDigest);
            }
            (0, _) => return Err(PublishedProjectionManifestError::ZeroSequence),
        }
        Ok(Self {
            chain,
            schema_version,
            key_epoch,
            projection_epoch,
            sequence,
            event_log_root,
            previous_manifest_digest,
            durability_mode,
        })
    }

    pub(super) const fn chain(&self) -> PublicChainCheckpoint {
        self.chain
    }

    pub(super) const fn schema_version(&self) -> u32 {
        self.schema_version
    }

    pub(super) const fn key_epoch(&self) -> u64 {
        self.key_epoch
    }

    pub(super) const fn projection_epoch(&self) -> u64 {
        self.projection_epoch
    }

    pub(super) const fn sequence(&self) -> u64 {
        self.sequence
    }

    pub(super) const fn publication_sequence(&self) -> u64 {
        self.sequence
    }

    pub(super) const fn event_log_root(&self) -> ProjectionEventLogRoot {
        self.event_log_root
    }

    pub(super) const fn previous_manifest_digest(&self) -> Option<ProjectionManifestDigest> {
        self.previous_manifest_digest
    }

    pub(super) const fn durability_mode(&self) -> ProjectionDurabilityMode {
        self.durability_mode
    }

    fn matches_publication(&self, publication: &ProjectionPublication) -> bool {
        self.chain == publication.chain
            && self.schema_version == publication.schema_version
            && self.key_epoch == publication.key_epoch
            && self.projection_epoch == publication.projection_epoch
            && self.event_log_root == publication.event_log_root
    }
}

/// A business manifest violated its monotonic fixed-format invariants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PublishedProjectionManifestError {
    ZeroSchemaVersion,
    ZeroProjectionEpoch,
    ZeroSequence,
    MissingPreviousDigest,
    UnexpectedPreviousDigest,
}

impl fmt::Display for PublishedProjectionManifestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroSchemaVersion => f.write_str("published projection schema version is zero"),
            Self::ZeroProjectionEpoch => f.write_str("published projection epoch is zero"),
            Self::ZeroSequence => f.write_str("published projection sequence is zero"),
            Self::MissingPreviousDigest => {
                f.write_str("non-initial projection manifest has no previous digest")
            }
            Self::UnexpectedPreviousDigest => {
                f.write_str("initial projection manifest has a previous digest")
            }
        }
    }
}

impl std::error::Error for PublishedProjectionManifestError {}

/// Exact padding-free disk representation of [`PublishedProjectionManifest`].
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct PersistentPublishedProjectionManifest([u8; PERSISTENT_MANIFEST_BYTES]);

const _: [(); PERSISTENT_MANIFEST_BYTES] =
    [(); std::mem::size_of::<PersistentPublishedProjectionManifest>()];

impl PersistentPublishedProjectionManifest {
    pub(super) fn from_business(src: &PublishedProjectionManifest) -> Self {
        let mut bytes = [0; PERSISTENT_MANIFEST_BYTES];
        bytes[0..8].copy_from_slice(PERSISTENT_MANIFEST_MAGIC);
        bytes[8..10].copy_from_slice(&PERSISTENT_MANIFEST_VERSION.to_be_bytes());
        bytes[10] = network_tag(src.chain.network());
        bytes[11] = src.durability_mode.tag();
        bytes[12] = u8::from(src.previous_manifest_digest.is_some());
        bytes[16..20].copy_from_slice(&src.chain.height().to_be_bytes());
        bytes[20..24].copy_from_slice(&src.schema_version.to_be_bytes());
        bytes[24..32].copy_from_slice(&src.key_epoch.to_be_bytes());
        bytes[32..40].copy_from_slice(&src.projection_epoch.to_be_bytes());
        bytes[40..48].copy_from_slice(&src.sequence.to_be_bytes());
        bytes[48..80].copy_from_slice(&src.chain.block_hash().bytes_in_display_order());
        bytes[80..112].copy_from_slice(src.event_log_root.as_bytes());
        if let Some(previous) = src.previous_manifest_digest {
            bytes[112..144].copy_from_slice(previous.as_bytes());
        }
        Self(bytes)
    }

    pub(super) fn into_business(
        self,
    ) -> Result<PublishedProjectionManifest, PersistentProjectionManifestError> {
        if &self.0[0..8] != PERSISTENT_MANIFEST_MAGIC {
            return Err(PersistentProjectionManifestError::InvalidMagic);
        }
        let version = read_u16(&self.0, 8)?;
        if version != PERSISTENT_MANIFEST_VERSION {
            return Err(PersistentProjectionManifestError::UnsupportedVersion { actual: version });
        }
        let network = network_from_tag(self.0[10])?;
        let durability_mode = ProjectionDurabilityMode::try_from_tag(self.0[11])?;
        let has_previous = match self.0[12] {
            0 => false,
            1 => true,
            actual => {
                return Err(PersistentProjectionManifestError::InvalidPreviousDigestTag { actual });
            }
        };
        if self.0[13..16].iter().any(|byte| *byte != 0)
            || self.0[144..160].iter().any(|byte| *byte != 0)
        {
            return Err(PersistentProjectionManifestError::NonzeroReservedBytes);
        }

        let height = read_u32(&self.0, 16)?;
        let schema_version = read_u32(&self.0, 20)?;
        let key_epoch = read_u64(&self.0, 24)?;
        let projection_epoch = read_u64(&self.0, 32)?;
        let sequence = read_u64(&self.0, 40)?;
        let block_hash_display = read_array::<32>(&self.0, 48)?;
        let event_log_root = ProjectionEventLogRoot::from_bytes(read_array::<32>(&self.0, 80)?);
        let previous_bytes = read_array::<32>(&self.0, 112)?;
        let previous_manifest_digest = if has_previous {
            Some(ProjectionManifestDigest::from_bytes(previous_bytes))
        } else {
            if previous_bytes.iter().any(|byte| *byte != 0) {
                return Err(PersistentProjectionManifestError::NoncanonicalAbsentDigest);
            }
            None
        };
        PublishedProjectionManifest::new(
            PublicChainCheckpoint::new(
                network,
                height,
                zaino_state::BlockHash::from_bytes_in_display_order(&block_hash_display),
            ),
            schema_version,
            key_epoch,
            projection_epoch,
            sequence,
            event_log_root,
            previous_manifest_digest,
            durability_mode,
        )
        .map_err(PersistentProjectionManifestError::InvalidBusinessManifest)
    }

    const fn as_bytes(&self) -> &[u8; PERSISTENT_MANIFEST_BYTES] {
        &self.0
    }

    fn from_bytes(bytes: [u8; PERSISTENT_MANIFEST_BYTES]) -> Self {
        Self(bytes)
    }
}

impl fmt::Debug for PersistentPublishedProjectionManifest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PersistentPublishedProjectionManifest([REDACTED; 160])")
    }
}

/// A fixed-width manifest payload is noncanonical or unsupported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PersistentProjectionManifestError {
    InvalidMagic,
    UnsupportedVersion { actual: u16 },
    UnknownNetworkTag { actual: u8 },
    UnknownDurabilityTag { actual: u8 },
    InvalidPreviousDigestTag { actual: u8 },
    NonzeroReservedBytes,
    NoncanonicalAbsentDigest,
    InvalidFixedLayout,
    InvalidBusinessManifest(PublishedProjectionManifestError),
}

impl fmt::Display for PersistentProjectionManifestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMagic => f.write_str("projection manifest magic is invalid"),
            Self::UnsupportedVersion { actual } => {
                write!(f, "projection manifest version {actual} is unsupported")
            }
            Self::UnknownNetworkTag { actual } => {
                write!(f, "projection manifest network tag {actual} is unknown")
            }
            Self::UnknownDurabilityTag { actual } => {
                write!(f, "projection manifest durability tag {actual} is unknown")
            }
            Self::InvalidPreviousDigestTag { actual } => {
                write!(
                    f,
                    "projection manifest previous-digest tag {actual} is invalid"
                )
            }
            Self::NonzeroReservedBytes => {
                f.write_str("projection manifest reserved bytes are nonzero")
            }
            Self::NoncanonicalAbsentDigest => {
                f.write_str("absent previous manifest digest contains nonzero bytes")
            }
            Self::InvalidFixedLayout => f.write_str("projection manifest fixed layout is invalid"),
            Self::InvalidBusinessManifest(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for PersistentProjectionManifestError {}

/// Keyed authenticator used for immutable projection manifest payloads.
pub(super) trait ProjectionManifestAuthenticator {
    type Error;

    fn authenticate(&self, payload: &[u8]) -> Result<[u8; MANIFEST_MAC_BYTES], Self::Error>;

    fn verify(
        &self,
        payload: &[u8],
        authenticator: &[u8; MANIFEST_MAC_BYTES],
    ) -> Result<bool, Self::Error>;
}

/// Proper keyed BLAKE2s-256 MAC for projection manifest payloads.
pub(super) struct Blake2sManifestAuthenticator {
    key: Zeroizing<[u8; 32]>,
}

impl Blake2sManifestAuthenticator {
    pub(super) fn new(key: [u8; 32]) -> Self {
        Self {
            key: Zeroizing::new(key),
        }
    }

    fn mac(&self, payload: &[u8]) -> Result<Blake2sMac256, Blake2sManifestAuthenticatorError> {
        let mut mac = <Blake2sMac256 as KeyInit>::new_from_slice(&self.key[..])
            .map_err(|_| Blake2sManifestAuthenticatorError::EngineRejectedFixedKey)?;
        Mac::update(&mut mac, MANIFEST_MAC_DOMAIN);
        Mac::update(&mut mac, payload);
        Ok(mac)
    }
}

impl ProjectionManifestAuthenticator for Blake2sManifestAuthenticator {
    type Error = Blake2sManifestAuthenticatorError;

    fn authenticate(&self, payload: &[u8]) -> Result<[u8; MANIFEST_MAC_BYTES], Self::Error> {
        Ok(self.mac(payload)?.finalize().into_bytes().into())
    }

    fn verify(
        &self,
        payload: &[u8],
        authenticator: &[u8; MANIFEST_MAC_BYTES],
    ) -> Result<bool, Self::Error> {
        Ok(self.mac(payload)?.verify_slice(authenticator).is_ok())
    }
}

impl fmt::Debug for Blake2sManifestAuthenticator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Blake2sManifestAuthenticator { ..REDACTED.. }")
    }
}

/// A fixed-width BLAKE2s manifest MAC key was unexpectedly rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Blake2sManifestAuthenticatorError {
    EngineRejectedFixedKey,
}

impl fmt::Display for Blake2sManifestAuthenticatorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EngineRejectedFixedKey => {
                f.write_str("BLAKE2s rejected a fixed 32-byte manifest key")
            }
        }
    }
}

impl std::error::Error for Blake2sManifestAuthenticatorError {}

/// Externally authoritative freshness value for one immutable manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ProjectionFreshness {
    sequence: u64,
    manifest_digest: ProjectionManifestDigest,
}

impl ProjectionFreshness {
    pub(super) const fn new(sequence: u64, manifest_digest: ProjectionManifestDigest) -> Self {
        Self {
            sequence,
            manifest_digest,
        }
    }

    pub(super) const fn sequence(&self) -> u64 {
        self.sequence
    }

    pub(super) const fn manifest_digest(&self) -> ProjectionManifestDigest {
        self.manifest_digest
    }
}

/// Trusted monotonic storage outside the host-controlled recovery directory.
///
/// One implementation owns one stable namespace for the projection identity.
/// That namespace must survive process and host restarts and must never reset,
/// disappear, or revert to an older value outside an explicit recovery ceremony
/// that this interface does not model. `current` and `compare_and_advance` must
/// be linearizable with respect to each other and all concurrent callers.
pub(super) trait ProjectionFreshnessWitness {
    type Error;

    /// Reads the exact externally authoritative sequence and manifest digest.
    fn current(&mut self) -> Result<Option<ProjectionFreshness>, Self::Error>;

    /// Atomically advances only if both expected sequence and digest match.
    ///
    /// Before returning `Ok`, implementations must synchronously make `next`
    /// crash-durable. They must leave the value unchanged on `Err` and reject
    /// any transition other than `None -> sequence 1` or exact `n -> n + 1`.
    /// Once successful, later `current` calls must observe `next` or a newer
    /// value, including after crash/restart.
    fn compare_and_advance(
        &mut self,
        expected: Option<ProjectionFreshness>,
        next: ProjectionFreshness,
    ) -> Result<(), Self::Error>;
}

/// Restart outcome for a projection whose worker state is always volatile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ProjectionRestartPlan {
    Rebuild {
        prior_manifest: Option<PublishedProjectionManifest>,
        authoritative: PublicChainCheckpoint,
        next_projection_epoch: u64,
    },
    Unready {
        reason: ProjectionRestartUnreadyReason,
    },
}

/// Fail-closed startup reason that prevents projection construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ProjectionRestartUnreadyReason {
    WitnessUnavailable,
    WitnessBoundManifestMissing,
    WitnessBoundManifestUnavailable,
    WitnessBoundManifestCorrupt,
    WitnessBoundManifestAuthenticationFailed,
    ManifestAuthenticatorUnavailable,
    ManifestConfigurationMismatch,
    LocalCheckpointAhead,
    LocalCheckpointHashMismatch,
    ProjectionEpochOverflow,
}

/// Authenticated immutable-manifest store coupled to an external witness.
pub(super) struct ProjectionManifestStore<A, W> {
    recovery_directory: PathBuf,
    authenticator: A,
    witness: W,
    #[cfg(test)]
    failpoint: Option<PublishFailpoint>,
}

impl<A, W> ProjectionManifestStore<A, W> {
    pub(super) fn new(root: impl Into<PathBuf>, authenticator: A, witness: W) -> Self {
        Self {
            recovery_directory: root.into(),
            authenticator,
            witness,
            #[cfg(test)]
            failpoint: None,
        }
    }
}

impl<A, W> ProjectionManifestStore<A, W>
where
    A: ProjectionManifestAuthenticator,
    W: ProjectionFreshnessWitness,
{
    /// Selects only the exact manifest named by the external witness.
    pub(super) fn restart_plan(
        &mut self,
        expected_network: CanonicalNetwork,
        expected_schema_version: u32,
        expected_key_epoch: u64,
        authoritative: PublicChainCheckpoint,
    ) -> ProjectionRestartPlan {
        if authoritative.network() != expected_network || expected_schema_version == 0 {
            return ProjectionRestartPlan::Unready {
                reason: ProjectionRestartUnreadyReason::ManifestConfigurationMismatch,
            };
        }
        let freshness = match self.witness.current() {
            Ok(value) => value,
            Err(_) => {
                return ProjectionRestartPlan::Unready {
                    reason: ProjectionRestartUnreadyReason::WitnessUnavailable,
                };
            }
        };
        let Some(freshness) = freshness else {
            return ProjectionRestartPlan::Rebuild {
                prior_manifest: None,
                authoritative,
                next_projection_epoch: 1,
            };
        };
        let manifest = match self.load_manifest(freshness.manifest_digest) {
            Ok(manifest) => manifest,
            Err(error) => {
                return ProjectionRestartPlan::Unready {
                    reason: restart_reason_from_load(error),
                };
            }
        };
        if manifest.sequence != freshness.sequence {
            return ProjectionRestartPlan::Unready {
                reason: ProjectionRestartUnreadyReason::WitnessBoundManifestCorrupt,
            };
        }
        if manifest.chain.network() != expected_network
            || manifest.schema_version != expected_schema_version
            || manifest.key_epoch != expected_key_epoch
            || manifest.durability_mode != ProjectionDurabilityMode::VolatileWorkerRebuildRequiredV1
        {
            return ProjectionRestartPlan::Unready {
                reason: ProjectionRestartUnreadyReason::ManifestConfigurationMismatch,
            };
        }
        if manifest.chain.height() > authoritative.height() {
            return ProjectionRestartPlan::Unready {
                reason: ProjectionRestartUnreadyReason::LocalCheckpointAhead,
            };
        }
        if manifest.chain.height() == authoritative.height()
            && manifest.chain.block_hash() != authoritative.block_hash()
        {
            return ProjectionRestartPlan::Unready {
                reason: ProjectionRestartUnreadyReason::LocalCheckpointHashMismatch,
            };
        }
        let Some(next_projection_epoch) = manifest.projection_epoch.checked_add(1) else {
            return ProjectionRestartPlan::Unready {
                reason: ProjectionRestartUnreadyReason::ProjectionEpochOverflow,
            };
        };
        ProjectionRestartPlan::Rebuild {
            prior_manifest: Some(manifest),
            authoritative,
            next_projection_epoch,
        }
    }

    fn publish_manifest(
        &mut self,
        publication: &ProjectionPublication,
    ) -> Result<(), ProjectionManifestStoreError> {
        self.ensure_directories()?;
        let expected = self
            .witness
            .current()
            .map_err(|_| ProjectionManifestStoreError::WitnessUnavailable)?;
        let prior = match expected {
            Some(freshness) => {
                let manifest = self
                    .load_manifest(freshness.manifest_digest)
                    .map_err(ProjectionManifestStoreError::from_current_load)?;
                if manifest.sequence != freshness.sequence {
                    return Err(ProjectionManifestStoreError::CurrentManifestCorrupt);
                }
                if manifest.matches_publication(publication) {
                    return Ok(());
                }
                validate_publication_successor(&manifest, publication)?;
                Some((manifest, freshness))
            }
            None => None,
        };
        let sequence = match prior {
            Some((manifest, _)) => manifest
                .sequence
                .checked_add(1)
                .ok_or(ProjectionManifestStoreError::SequenceOverflow)?,
            None => 1,
        };
        let previous_manifest_digest = prior.map(|(_, freshness)| freshness.manifest_digest);
        let manifest = PublishedProjectionManifest::new(
            publication.chain,
            publication.schema_version,
            publication.key_epoch,
            publication.projection_epoch,
            sequence,
            publication.event_log_root,
            previous_manifest_digest,
            ProjectionDurabilityMode::VolatileWorkerRebuildRequiredV1,
        )
        .map_err(ProjectionManifestStoreError::InvalidManifest)?;
        let (blob, digest) = encode_manifest_blob(&self.authenticator, &manifest)
            .map_err(|_| ProjectionManifestStoreError::ManifestAuthenticatorUnavailable)?;
        self.commit_immutable_manifest(&blob, digest)?;
        self.trigger_failpoint(PublishFailpoint::AfterImmutableCommit)?;

        let next = ProjectionFreshness::new(sequence, digest);
        self.write_current_hint(next)?;
        self.trigger_failpoint(PublishFailpoint::AfterCurrentBeforeWitness)?;
        self.witness
            .compare_and_advance(expected, next)
            .map_err(|_| ProjectionManifestStoreError::WitnessAdvanceRejected)?;
        self.trigger_failpoint(PublishFailpoint::AfterWitnessBeforeReturn)?;
        Ok(())
    }

    fn ensure_directories(&self) -> Result<(), ProjectionManifestStoreError> {
        ensure_real_directory(&self.recovery_directory).map_err(map_real_directory_error)?;
        ensure_real_directory(&self.manifest_directory()).map_err(map_real_directory_error)?;
        ensure_real_directory(&self.staging_directory()).map_err(map_real_directory_error)?;
        if let Some(parent) = self
            .recovery_directory
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            sync_directory(parent)?;
        }
        sync_directory(&self.recovery_directory)?;
        sync_directory(&self.manifest_directory())?;
        sync_directory(&self.staging_directory())?;
        Ok(())
    }

    fn commit_immutable_manifest(
        &mut self,
        blob: &[u8; MANIFEST_BLOB_BYTES],
        digest: ProjectionManifestDigest,
    ) -> Result<(), ProjectionManifestStoreError> {
        let mut stage = create_unique_file(&self.staging_directory(), "manifest")?;
        stage.write_all(blob)?;
        stage.as_file().sync_all()?;
        self.trigger_failpoint(PublishFailpoint::BeforeManifestCommit)?;

        let committed_path = self.manifest_path(digest);
        match fs::hard_link(stage.path(), &committed_path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                let existing = fs::read(&committed_path)?;
                if existing.as_slice() != blob {
                    return Err(ProjectionManifestStoreError::ImmutableManifestConflict);
                }
            }
            Err(error) => return Err(ProjectionManifestStoreError::Io(error)),
        }
        File::open(&committed_path)?.sync_all()?;
        sync_directory(&self.manifest_directory())?;
        stage.close()?;
        sync_directory(&self.staging_directory())?;
        Ok(())
    }

    fn write_current_hint(
        &self,
        freshness: ProjectionFreshness,
    ) -> Result<(), ProjectionManifestStoreError> {
        let mut temporary = create_unique_file(&self.recovery_directory, "current")?;
        let bytes = current_hint_bytes(freshness);
        temporary.write_all(&bytes)?;
        temporary.as_file().sync_all()?;
        if let Err(error) = fs::rename(temporary.path(), self.current_hint_path()) {
            return Err(ProjectionManifestStoreError::Io(error));
        }
        drop(temporary);
        sync_directory(&self.recovery_directory)?;
        Ok(())
    }

    fn load_manifest(
        &self,
        expected_digest: ProjectionManifestDigest,
    ) -> Result<PublishedProjectionManifest, LoadManifestError> {
        let path = self.manifest_path(expected_digest);
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(LoadManifestError::Missing);
            }
            Err(_) => return Err(LoadManifestError::Io),
        };
        if !metadata.file_type().is_file() {
            return Err(LoadManifestError::Corrupt);
        }
        let bytes = match fs::read(path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(LoadManifestError::Missing);
            }
            Err(_) => return Err(LoadManifestError::Io),
        };
        if bytes.len() != MANIFEST_BLOB_BYTES {
            return Err(LoadManifestError::Corrupt);
        }
        let mut blob = [0; MANIFEST_BLOB_BYTES];
        blob.copy_from_slice(&bytes);
        if manifest_digest(&blob) != expected_digest {
            return Err(LoadManifestError::Corrupt);
        }
        let mut payload = [0; PERSISTENT_MANIFEST_BYTES];
        payload.copy_from_slice(&blob[..PERSISTENT_MANIFEST_BYTES]);
        let mut mac = [0; MANIFEST_MAC_BYTES];
        mac.copy_from_slice(&blob[PERSISTENT_MANIFEST_BYTES..]);
        match self.authenticator.verify(&payload, &mac) {
            Ok(true) => {}
            Ok(false) => return Err(LoadManifestError::AuthenticationFailed),
            Err(_) => return Err(LoadManifestError::AuthenticatorUnavailable),
        }
        PersistentPublishedProjectionManifest::from_bytes(payload)
            .into_business()
            .map_err(|_| LoadManifestError::Corrupt)
    }

    fn trigger_failpoint(
        &mut self,
        point: PublishFailpoint,
    ) -> Result<(), ProjectionManifestStoreError> {
        #[cfg(test)]
        if matches!(self.failpoint, Some(configured) if configured == point) {
            self.failpoint = None;
            return Err(ProjectionManifestStoreError::InjectedFailure);
        }
        let _ = point;
        Ok(())
    }

    fn manifest_directory(&self) -> PathBuf {
        self.recovery_directory.join(MANIFEST_DIRECTORY)
    }

    fn staging_directory(&self) -> PathBuf {
        self.recovery_directory.join(STAGING_DIRECTORY)
    }

    fn current_hint_path(&self) -> PathBuf {
        self.recovery_directory.join(CURRENT_HINT_FILE)
    }

    fn manifest_path(&self, digest: ProjectionManifestDigest) -> PathBuf {
        self.manifest_directory().join(manifest_filename(digest))
    }

    #[cfg(test)]
    fn set_failpoint(&mut self, failpoint: PublishFailpoint) {
        self.failpoint = Some(failpoint);
    }
}

impl<A, W> ProjectionCheckpointPublisher for ProjectionManifestStore<A, W>
where
    A: ProjectionManifestAuthenticator,
    W: ProjectionFreshnessWitness,
{
    type Error = ProjectionManifestStoreError;

    fn publish_and_wait(&mut self, publication: &ProjectionPublication) -> Result<(), Self::Error> {
        self.publish_manifest(publication)
    }
}

impl<A, W> fmt::Debug for ProjectionManifestStore<A, W> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProjectionManifestStore")
            .field("recovery_directory", &self.recovery_directory)
            .field("authenticator", &"..REDACTED..")
            .field("witness", &"..REDACTED..")
            .finish()
    }
}

/// Publication failed before or while advancing the exact external witness.
#[derive(Debug)]
pub(super) enum ProjectionManifestStoreError {
    Io(io::Error),
    WitnessUnavailable,
    WitnessAdvanceRejected,
    CurrentManifestMissing,
    CurrentManifestUnavailable,
    CurrentManifestCorrupt,
    CurrentManifestAuthenticationFailed,
    ManifestAuthenticatorUnavailable,
    InvalidManifest(PublishedProjectionManifestError),
    ImmutableManifestConflict,
    UnsafeRecoveryPath,
    ConfigurationChanged,
    ChainDidNotAdvance,
    ChainHeightOverflow,
    RebuildDidNotStartAtGenesis,
    RebuildGenesisHashMismatch,
    ProjectionEpochRegressed,
    ProjectionEpochSkipped,
    SequenceOverflow,
    #[cfg(test)]
    InjectedFailure,
}

impl ProjectionManifestStoreError {
    fn from_current_load(error: LoadManifestError) -> Self {
        match error {
            LoadManifestError::Missing => Self::CurrentManifestMissing,
            LoadManifestError::Io => Self::CurrentManifestUnavailable,
            LoadManifestError::Corrupt => Self::CurrentManifestCorrupt,
            LoadManifestError::AuthenticationFailed => Self::CurrentManifestAuthenticationFailed,
            LoadManifestError::AuthenticatorUnavailable => Self::ManifestAuthenticatorUnavailable,
        }
    }
}

impl From<io::Error> for ProjectionManifestStoreError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl fmt::Display for ProjectionManifestStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(_) => f.write_str("projection manifest filesystem operation failed"),
            Self::WitnessUnavailable => f.write_str("projection freshness witness is unavailable"),
            Self::WitnessAdvanceRejected => {
                f.write_str("projection freshness witness rejected compare-and-advance")
            }
            Self::CurrentManifestMissing => {
                f.write_str("freshness-bound current projection manifest is missing")
            }
            Self::CurrentManifestUnavailable => {
                f.write_str("freshness-bound current projection manifest is unavailable")
            }
            Self::CurrentManifestCorrupt => {
                f.write_str("freshness-bound current projection manifest is corrupt")
            }
            Self::CurrentManifestAuthenticationFailed => {
                f.write_str("freshness-bound current projection manifest failed authentication")
            }
            Self::ManifestAuthenticatorUnavailable => {
                f.write_str("projection manifest authenticator is unavailable")
            }
            Self::InvalidManifest(error) => error.fmt(f),
            Self::ImmutableManifestConflict => {
                f.write_str("immutable projection manifest path contains conflicting bytes")
            }
            Self::UnsafeRecoveryPath => {
                f.write_str("projection recovery path is not a real directory")
            }
            Self::ConfigurationChanged => {
                f.write_str("projection publication configuration changed")
            }
            Self::ChainDidNotAdvance => {
                f.write_str("projection publication chain height did not advance")
            }
            Self::ChainHeightOverflow => {
                f.write_str("projection publication chain height overflowed")
            }
            Self::RebuildDidNotStartAtGenesis => {
                f.write_str("new projection epoch did not restart from genesis")
            }
            Self::RebuildGenesisHashMismatch => {
                f.write_str("new projection epoch has the wrong genesis hash")
            }
            Self::ProjectionEpochRegressed => f.write_str("projection publication epoch regressed"),
            Self::ProjectionEpochSkipped => {
                f.write_str("projection publication skipped a projection epoch")
            }
            Self::SequenceOverflow => f.write_str("projection manifest sequence overflowed"),
            #[cfg(test)]
            Self::InjectedFailure => f.write_str("projection publication failpoint fired"),
        }
    }
}

impl std::error::Error for ProjectionManifestStoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::InvalidManifest(error) => Some(error),
            _ => None,
        }
    }
}

#[derive(Debug)]
enum LoadManifestError {
    Missing,
    Io,
    Corrupt,
    AuthenticationFailed,
    AuthenticatorUnavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PublishFailpoint {
    BeforeManifestCommit,
    AfterImmutableCommit,
    AfterCurrentBeforeWitness,
    AfterWitnessBeforeReturn,
}

fn validate_publication_successor(
    prior: &PublishedProjectionManifest,
    publication: &ProjectionPublication,
) -> Result<(), ProjectionManifestStoreError> {
    if prior.chain.network() != publication.chain.network()
        || prior.schema_version != publication.schema_version
        || prior.key_epoch != publication.key_epoch
    {
        return Err(ProjectionManifestStoreError::ConfigurationChanged);
    }
    if publication.projection_epoch < prior.projection_epoch {
        return Err(ProjectionManifestStoreError::ProjectionEpochRegressed);
    }
    if publication.projection_epoch == prior.projection_epoch {
        let next_height = prior
            .chain
            .height()
            .checked_add(1)
            .ok_or(ProjectionManifestStoreError::ChainHeightOverflow)?;
        if publication.chain.height() != next_height {
            return Err(ProjectionManifestStoreError::ChainDidNotAdvance);
        }
        return Ok(());
    }
    let next_epoch = prior
        .projection_epoch
        .checked_add(1)
        .ok_or(ProjectionManifestStoreError::ProjectionEpochSkipped)?;
    if publication.projection_epoch != next_epoch {
        return Err(ProjectionManifestStoreError::ProjectionEpochSkipped);
    }
    if publication.chain.height() != 0 {
        return Err(ProjectionManifestStoreError::RebuildDidNotStartAtGenesis);
    }
    if publication.chain.block_hash() != &publication.chain.network().genesis_hash() {
        return Err(ProjectionManifestStoreError::RebuildGenesisHashMismatch);
    }
    Ok(())
}

fn encode_manifest_blob<A: ProjectionManifestAuthenticator>(
    authenticator: &A,
    manifest: &PublishedProjectionManifest,
) -> Result<([u8; MANIFEST_BLOB_BYTES], ProjectionManifestDigest), A::Error> {
    let persistent = PersistentPublishedProjectionManifest::from_business(manifest);
    let mac = authenticator.authenticate(persistent.as_bytes())?;
    let mut blob = [0; MANIFEST_BLOB_BYTES];
    blob[..PERSISTENT_MANIFEST_BYTES].copy_from_slice(persistent.as_bytes());
    blob[PERSISTENT_MANIFEST_BYTES..].copy_from_slice(&mac);
    let digest = manifest_digest(&blob);
    Ok((blob, digest))
}

fn manifest_digest(blob: &[u8; MANIFEST_BLOB_BYTES]) -> ProjectionManifestDigest {
    let mut hasher = Blake2s256::new();
    Digest::update(&mut hasher, MANIFEST_DIGEST_DOMAIN);
    Digest::update(&mut hasher, blob);
    ProjectionManifestDigest::from_bytes(hasher.finalize().into())
}

fn restart_reason_from_load(error: LoadManifestError) -> ProjectionRestartUnreadyReason {
    match error {
        LoadManifestError::Missing => ProjectionRestartUnreadyReason::WitnessBoundManifestMissing,
        LoadManifestError::Io => ProjectionRestartUnreadyReason::WitnessBoundManifestUnavailable,
        LoadManifestError::Corrupt => ProjectionRestartUnreadyReason::WitnessBoundManifestCorrupt,
        LoadManifestError::AuthenticationFailed => {
            ProjectionRestartUnreadyReason::WitnessBoundManifestAuthenticationFailed
        }
        LoadManifestError::AuthenticatorUnavailable => {
            ProjectionRestartUnreadyReason::ManifestAuthenticatorUnavailable
        }
    }
}

fn network_tag(network: CanonicalNetwork) -> u8 {
    match network {
        CanonicalNetwork::Mainnet => 1,
        CanonicalNetwork::Testnet => 2,
        CanonicalNetwork::Regtest => 3,
    }
}

fn network_from_tag(tag: u8) -> Result<CanonicalNetwork, PersistentProjectionManifestError> {
    match tag {
        1 => Ok(CanonicalNetwork::Mainnet),
        2 => Ok(CanonicalNetwork::Testnet),
        3 => Ok(CanonicalNetwork::Regtest),
        actual => Err(PersistentProjectionManifestError::UnknownNetworkTag { actual }),
    }
}

fn read_u16(
    bytes: &[u8; PERSISTENT_MANIFEST_BYTES],
    offset: usize,
) -> Result<u16, PersistentProjectionManifestError> {
    Ok(u16::from_be_bytes(read_array::<2>(bytes, offset)?))
}

fn read_u32(
    bytes: &[u8; PERSISTENT_MANIFEST_BYTES],
    offset: usize,
) -> Result<u32, PersistentProjectionManifestError> {
    Ok(u32::from_be_bytes(read_array::<4>(bytes, offset)?))
}

fn read_u64(
    bytes: &[u8; PERSISTENT_MANIFEST_BYTES],
    offset: usize,
) -> Result<u64, PersistentProjectionManifestError> {
    Ok(u64::from_be_bytes(read_array::<8>(bytes, offset)?))
}

fn read_array<const N: usize>(
    bytes: &[u8; PERSISTENT_MANIFEST_BYTES],
    offset: usize,
) -> Result<[u8; N], PersistentProjectionManifestError> {
    bytes
        .get(offset..offset.saturating_add(N))
        .ok_or(PersistentProjectionManifestError::InvalidFixedLayout)?
        .try_into()
        .map_err(|_| PersistentProjectionManifestError::InvalidFixedLayout)
}

fn current_hint_bytes(freshness: ProjectionFreshness) -> [u8; CURRENT_HINT_BYTES] {
    let mut bytes = [0; CURRENT_HINT_BYTES];
    bytes[..8].copy_from_slice(CURRENT_HINT_MAGIC);
    bytes[8..16].copy_from_slice(&freshness.sequence.to_be_bytes());
    bytes[16..].copy_from_slice(freshness.manifest_digest.as_bytes());
    bytes
}

fn manifest_filename(digest: ProjectionManifestDigest) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut name = String::with_capacity(MANIFEST_DIGEST_BYTES * 2 + ".manifest".len());
    for byte in digest.as_bytes() {
        name.push(char::from(HEX[usize::from(byte >> 4)]));
        name.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    name.push_str(".manifest");
    name
}

fn map_real_directory_error(error: RealDirectoryError) -> ProjectionManifestStoreError {
    match error {
        RealDirectoryError::Io(error) => ProjectionManifestStoreError::Io(error),
        RealDirectoryError::UnsafePath => ProjectionManifestStoreError::UnsafeRecoveryPath,
    }
}

#[cfg(test)]
mod tests {
    use std::{
        error::Error,
        fs::{self, OpenOptions},
        io::{self, Write},
        path::{Path, PathBuf},
        sync::{
            atomic::{AtomicBool, AtomicU64, Ordering},
            Arc, Mutex,
        },
    };

    use zaino_state::BlockHash;

    use super::*;

    const SCHEMA_VERSION: u32 = 7;
    const KEY_EPOCH: u64 = 11;
    const MANIFEST_KEY: [u8; 32] = [0x6b; 32];

    type TestResult<T = ()> = Result<T, Box<dyn Error>>;

    static TEST_DIRECTORY_COUNTER: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new(label: &str) -> io::Result<Self> {
            for _ in 0..MAX_UNIQUE_FILE_ATTEMPTS {
                let counter = TEST_DIRECTORY_COUNTER.fetch_add(1, Ordering::Relaxed);
                let path = std::env::temp_dir().join(format!(
                    "zaino-oram-checkpoint-{label}-{}-{counter}",
                    std::process::id()
                ));
                match fs::create_dir(&path) {
                    Ok(()) => return Ok(Self(path)),
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                    Err(error) => return Err(error),
                }
            }
            Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "could not allocate a checkpoint test directory",
            ))
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum TestWitnessError {
        Unavailable,
        Conflict,
        InvalidTransition,
        Poisoned,
    }

    impl fmt::Display for TestWitnessError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::Unavailable => f.write_str("test witness unavailable"),
                Self::Conflict => f.write_str("test witness compare conflict"),
                Self::InvalidTransition => f.write_str("test witness transition invalid"),
                Self::Poisoned => f.write_str("test witness mutex poisoned"),
            }
        }
    }

    impl Error for TestWitnessError {}

    #[derive(Clone)]
    struct SharedWitness {
        state: Arc<Mutex<Option<ProjectionFreshness>>>,
        available: Arc<AtomicBool>,
    }

    impl SharedWitness {
        fn empty() -> Self {
            Self {
                state: Arc::new(Mutex::new(None)),
                available: Arc::new(AtomicBool::new(true)),
            }
        }

        fn value(&self) -> Result<Option<ProjectionFreshness>, TestWitnessError> {
            self.state
                .lock()
                .map(|guard| *guard)
                .map_err(|_| TestWitnessError::Poisoned)
        }

        fn force(&self, value: Option<ProjectionFreshness>) -> Result<(), TestWitnessError> {
            let mut guard = self.state.lock().map_err(|_| TestWitnessError::Poisoned)?;
            *guard = value;
            Ok(())
        }

        fn set_available(&self, available: bool) {
            self.available.store(available, Ordering::SeqCst);
        }
    }

    impl ProjectionFreshnessWitness for SharedWitness {
        type Error = TestWitnessError;

        fn current(&mut self) -> Result<Option<ProjectionFreshness>, Self::Error> {
            if !self.available.load(Ordering::SeqCst) {
                return Err(TestWitnessError::Unavailable);
            }
            self.value()
        }

        fn compare_and_advance(
            &mut self,
            expected: Option<ProjectionFreshness>,
            next: ProjectionFreshness,
        ) -> Result<(), Self::Error> {
            if !self.available.load(Ordering::SeqCst) {
                return Err(TestWitnessError::Unavailable);
            }
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
            *guard = Some(next);
            Ok(())
        }
    }

    type TestStore = ProjectionManifestStore<Blake2sManifestAuthenticator, SharedWitness>;

    fn test_store(directory: &TestDirectory, witness: SharedWitness) -> TestResult<TestStore> {
        Ok(ProjectionManifestStore::new(
            directory.path(),
            Blake2sManifestAuthenticator::new(MANIFEST_KEY),
            witness,
        ))
    }

    fn checkpoint(network: CanonicalNetwork, height: u32, hash_byte: u8) -> PublicChainCheckpoint {
        PublicChainCheckpoint::new(
            network,
            height,
            BlockHash::from_bytes_in_display_order(&[hash_byte; 32]),
        )
    }

    fn publication(
        height: u32,
        hash_byte: u8,
        projection_epoch: u64,
        root_byte: u8,
    ) -> Result<ProjectionPublication, ProjectionPublicationError> {
        ProjectionPublication::new(
            checkpoint(CanonicalNetwork::Regtest, height, hash_byte),
            SCHEMA_VERSION,
            KEY_EPOCH,
            projection_epoch,
            ProjectionEventLogRoot::from_bytes([root_byte; 32]),
        )
    }

    fn initial_manifest(
        projection_epoch: u64,
        root_byte: u8,
    ) -> Result<PublishedProjectionManifest, PublishedProjectionManifestError> {
        PublishedProjectionManifest::new(
            checkpoint(CanonicalNetwork::Regtest, 4, 0x44),
            SCHEMA_VERSION,
            KEY_EPOCH,
            projection_epoch,
            1,
            ProjectionEventLogRoot::from_bytes([root_byte; 32]),
            None,
            ProjectionDurabilityMode::VolatileWorkerRebuildRequiredV1,
        )
    }

    fn require_freshness(witness: &SharedWitness) -> TestResult<ProjectionFreshness> {
        witness.value()?.ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "test witness has no value").into()
        })
    }

    fn manifest_count(store: &TestStore) -> io::Result<usize> {
        let mut count = 0;
        for entry in fs::read_dir(store.manifest_directory())? {
            let entry = entry?;
            if entry.file_type()?.is_file() {
                count += 1;
            }
        }
        Ok(count)
    }

    fn assert_injected(result: Result<(), ProjectionManifestStoreError>) {
        assert!(matches!(
            result,
            Err(ProjectionManifestStoreError::InjectedFailure)
        ));
    }

    #[test]
    fn publication_validates_required_fields_and_exposes_exact_values() -> TestResult {
        let chain = checkpoint(CanonicalNetwork::Regtest, 9, 0x99);
        let root = ProjectionEventLogRoot::from_bytes([0x31; 32]);
        let publication = ProjectionPublication::new(chain, 3, 0, 5, root)?;
        assert_eq!(publication.chain(), chain);
        assert_eq!(publication.schema_version(), 3);
        assert_eq!(publication.key_epoch(), 0);
        assert_eq!(publication.projection_epoch(), 5);
        assert_eq!(publication.event_log_root(), root);
        assert_eq!(root.as_bytes(), &[0x31; 32]);
        assert_eq!(root.into_bytes(), [0x31; 32]);
        assert_eq!(
            ProjectionPublication::new(chain, 0, 0, 5, root),
            Err(ProjectionPublicationError::ZeroSchemaVersion)
        );
        assert_eq!(
            ProjectionPublication::new(chain, 3, 0, 0, root),
            Err(ProjectionPublicationError::ZeroProjectionEpoch)
        );
        Ok(())
    }

    #[test]
    fn noop_publisher_accepts_a_valid_publication() -> TestResult {
        let mut publisher = NoopProjectionCheckpointPublisher;
        publisher.publish_and_wait(&publication(0, 1, 1, 2)?)?;
        Ok(())
    }

    #[test]
    fn persistent_manifest_round_trips_initial_and_chained_entries() -> TestResult {
        let initial = initial_manifest(3, 0xa1)?;
        let initial_persistent = PersistentPublishedProjectionManifest::from_business(&initial);
        assert_eq!(initial_persistent.into_business()?, initial);
        assert_eq!(
            initial.chain(),
            checkpoint(CanonicalNetwork::Regtest, 4, 0x44)
        );
        assert_eq!(initial.schema_version(), SCHEMA_VERSION);
        assert_eq!(initial.key_epoch(), KEY_EPOCH);
        assert_eq!(initial.projection_epoch(), 3);
        assert_eq!(initial.sequence(), 1);
        assert_eq!(initial.publication_sequence(), 1);
        assert_eq!(initial.event_log_root().into_bytes(), [0xa1; 32]);
        assert_eq!(initial.previous_manifest_digest(), None);
        assert_eq!(
            initial.durability_mode(),
            ProjectionDurabilityMode::VolatileWorkerRebuildRequiredV1
        );

        let previous = ProjectionManifestDigest::from_bytes([0x55; 32]);
        let chained = PublishedProjectionManifest::new(
            checkpoint(CanonicalNetwork::Mainnet, 500, 0x62),
            9,
            0,
            4,
            2,
            ProjectionEventLogRoot::from_bytes([0x72; 32]),
            Some(previous),
            ProjectionDurabilityMode::VolatileWorkerRebuildRequiredV1,
        )?;
        let persistent = PersistentPublishedProjectionManifest::from_business(&chained);
        assert_eq!(persistent.into_business()?, chained);
        assert_eq!(previous.as_bytes(), &[0x55; 32]);
        assert_eq!(previous.into_bytes(), [0x55; 32]);
        assert_eq!(
            std::mem::size_of::<PersistentPublishedProjectionManifest>(),
            PERSISTENT_MANIFEST_BYTES
        );
        Ok(())
    }

    #[test]
    fn persistent_manifest_rejects_magic_version_tags_and_reserved_mutations() -> TestResult {
        let valid = PersistentPublishedProjectionManifest::from_business(&initial_manifest(1, 2)?);

        let mut wrong_magic = valid;
        wrong_magic.0[0] ^= 1;
        assert_eq!(
            wrong_magic.into_business(),
            Err(PersistentProjectionManifestError::InvalidMagic)
        );

        let mut wrong_version = valid;
        wrong_version.0[8..10].copy_from_slice(&2_u16.to_be_bytes());
        assert_eq!(
            wrong_version.into_business(),
            Err(PersistentProjectionManifestError::UnsupportedVersion { actual: 2 })
        );

        let mut wrong_network = valid;
        wrong_network.0[10] = 0xff;
        assert_eq!(
            wrong_network.into_business(),
            Err(PersistentProjectionManifestError::UnknownNetworkTag { actual: 0xff })
        );

        let mut wrong_durability = valid;
        wrong_durability.0[11] = 0xff;
        assert_eq!(
            wrong_durability.into_business(),
            Err(PersistentProjectionManifestError::UnknownDurabilityTag { actual: 0xff })
        );

        let mut wrong_previous_tag = valid;
        wrong_previous_tag.0[12] = 2;
        assert_eq!(
            wrong_previous_tag.into_business(),
            Err(PersistentProjectionManifestError::InvalidPreviousDigestTag { actual: 2 })
        );

        for offset in [13, 15, 144, 159] {
            let mut nonzero_reserved = valid;
            nonzero_reserved.0[offset] = 1;
            assert_eq!(
                nonzero_reserved.into_business(),
                Err(PersistentProjectionManifestError::NonzeroReservedBytes)
            );
        }

        let mut noncanonical_absent = valid;
        noncanonical_absent.0[112] = 1;
        assert_eq!(
            noncanonical_absent.into_business(),
            Err(PersistentProjectionManifestError::NoncanonicalAbsentDigest)
        );
        Ok(())
    }

    #[test]
    fn persistent_manifest_revalidates_business_invariants() -> TestResult {
        let valid = PersistentPublishedProjectionManifest::from_business(&initial_manifest(1, 2)?);

        let mut zero_schema = valid;
        zero_schema.0[20..24].fill(0);
        assert_eq!(
            zero_schema.into_business(),
            Err(PersistentProjectionManifestError::InvalidBusinessManifest(
                PublishedProjectionManifestError::ZeroSchemaVersion
            ))
        );

        let mut zero_epoch = valid;
        zero_epoch.0[32..40].fill(0);
        assert_eq!(
            zero_epoch.into_business(),
            Err(PersistentProjectionManifestError::InvalidBusinessManifest(
                PublishedProjectionManifestError::ZeroProjectionEpoch
            ))
        );

        let mut zero_sequence = valid;
        zero_sequence.0[40..48].fill(0);
        assert_eq!(
            zero_sequence.into_business(),
            Err(PersistentProjectionManifestError::InvalidBusinessManifest(
                PublishedProjectionManifestError::ZeroSequence
            ))
        );

        let previous = ProjectionManifestDigest::from_bytes([9; 32]);
        let chained = PublishedProjectionManifest::new(
            checkpoint(CanonicalNetwork::Regtest, 5, 5),
            SCHEMA_VERSION,
            KEY_EPOCH,
            1,
            2,
            ProjectionEventLogRoot::from_bytes([4; 32]),
            Some(previous),
            ProjectionDurabilityMode::VolatileWorkerRebuildRequiredV1,
        )?;
        let mut missing_previous = PersistentPublishedProjectionManifest::from_business(&chained);
        missing_previous.0[12] = 0;
        missing_previous.0[112..144].fill(0);
        assert_eq!(
            missing_previous.into_business(),
            Err(PersistentProjectionManifestError::InvalidBusinessManifest(
                PublishedProjectionManifestError::MissingPreviousDigest
            ))
        );
        Ok(())
    }

    #[test]
    fn keyed_blake2s_authenticator_is_redacted_and_rejects_mutations() -> TestResult {
        let authenticator = Blake2sManifestAuthenticator::new(MANIFEST_KEY);
        let payload = [0x42; PERSISTENT_MANIFEST_BYTES];
        let tag = authenticator.authenticate(&payload)?;
        assert!(authenticator.verify(&payload, &tag)?);
        let mut mutated_payload = payload;
        mutated_payload[73] ^= 1;
        assert!(!authenticator.verify(&mutated_payload, &tag)?);
        let mut mutated_tag = tag;
        mutated_tag[19] ^= 1;
        assert!(!authenticator.verify(&payload, &mutated_tag)?);
        let debug = format!("{authenticator:?}");
        assert!(debug.contains("REDACTED"));
        assert!(!debug.contains("107"));
        Ok(())
    }

    #[test]
    fn manifest_digest_binds_payload_and_mac() -> TestResult {
        let manifest = initial_manifest(1, 0x33)?;
        let first = Blake2sManifestAuthenticator::new([0x11; 32]);
        let second = Blake2sManifestAuthenticator::new([0x22; 32]);
        let (first_blob, first_digest) = encode_manifest_blob(&first, &manifest)?;
        let (second_blob, second_digest) = encode_manifest_blob(&second, &manifest)?;
        assert_ne!(first_blob, second_blob);
        assert_ne!(first_digest, second_digest);
        let mut changed_mac = first_blob;
        changed_mac[MANIFEST_BLOB_BYTES - 1] ^= 1;
        assert_ne!(manifest_digest(&changed_mac), first_digest);
        Ok(())
    }

    #[test]
    fn failpoint_before_manifest_commit_keeps_witness_empty() -> TestResult {
        let directory = TestDirectory::new("before-commit")?;
        let witness = SharedWitness::empty();
        let mut store = test_store(&directory, witness.clone())?;
        store.set_failpoint(PublishFailpoint::BeforeManifestCommit);
        assert_injected(store.publish_and_wait(&publication(0, 1, 1, 2)?));
        assert_eq!(witness.value()?, None);
        assert_eq!(manifest_count(&store)?, 0);
        assert_eq!(
            store.restart_plan(
                CanonicalNetwork::Regtest,
                SCHEMA_VERSION,
                KEY_EPOCH,
                checkpoint(CanonicalNetwork::Regtest, 0, 1)
            ),
            ProjectionRestartPlan::Rebuild {
                prior_manifest: None,
                authoritative: checkpoint(CanonicalNetwork::Regtest, 0, 1),
                next_projection_epoch: 1,
            }
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn publication_rejects_a_symlinked_manifest_directory() -> TestResult {
        use std::os::unix::fs::symlink;

        let directory = TestDirectory::new("symlink-root")?;
        let outside = TestDirectory::new("symlink-outside")?;
        symlink(outside.path(), directory.path().join(MANIFEST_DIRECTORY))?;
        let witness = SharedWitness::empty();
        let mut store = test_store(&directory, witness.clone())?;

        assert!(matches!(
            store.publish_and_wait(&publication(0, 1, 1, 2)?),
            Err(ProjectionManifestStoreError::UnsafeRecoveryPath)
        ));
        assert_eq!(witness.value()?, None);
        Ok(())
    }

    #[test]
    fn publication_requires_a_preexisting_recovery_parent() -> TestResult {
        let directory = TestDirectory::new("missing-parent")?;
        let witness = SharedWitness::empty();
        let recovery_directory = directory.path().join("missing").join("recovery");
        let mut store = ProjectionManifestStore::new(
            recovery_directory,
            Blake2sManifestAuthenticator::new(MANIFEST_KEY),
            witness.clone(),
        );

        assert!(matches!(
            store.publish_and_wait(&publication(0, 1, 1, 2)?),
            Err(ProjectionManifestStoreError::UnsafeRecoveryPath)
        ));
        assert!(!directory.path().join("missing").exists());
        assert_eq!(witness.value()?, None);
        Ok(())
    }

    #[test]
    fn stale_predictable_temporary_names_cannot_wedge_publication() -> TestResult {
        let directory = TestDirectory::new("stale-temporaries")?;
        let staging = directory.path().join(STAGING_DIRECTORY);
        fs::create_dir(&staging)?;
        for counter in 0..(MAX_UNIQUE_FILE_ATTEMPTS * 2) {
            fs::write(staging.join(format!(".manifest.1.{counter}.tmp")), b"stale")?;
            fs::write(
                directory.path().join(format!(".current.1.{counter}.tmp")),
                b"stale",
            )?;
        }
        let witness = SharedWitness::empty();
        let mut store = test_store(&directory, witness.clone())?;

        store.publish_and_wait(&publication(0, 1, 1, 2)?)?;

        assert_eq!(require_freshness(&witness)?.sequence(), 1);
        assert_eq!(manifest_count(&store)?, 1);
        Ok(())
    }

    #[test]
    fn failpoint_after_immutable_commit_leaves_ignored_retryable_orphan() -> TestResult {
        let directory = TestDirectory::new("after-immutable")?;
        let witness = SharedWitness::empty();
        let mut store = test_store(&directory, witness.clone())?;
        let publication = publication(0, 1, 1, 2)?;
        store.set_failpoint(PublishFailpoint::AfterImmutableCommit);
        assert_injected(store.publish_and_wait(&publication));
        assert_eq!(witness.value()?, None);
        assert_eq!(manifest_count(&store)?, 1);
        assert!(!store.current_hint_path().exists());
        store.publish_and_wait(&publication)?;
        assert_eq!(require_freshness(&witness)?.sequence(), 1);
        assert_eq!(manifest_count(&store)?, 1);
        Ok(())
    }

    #[test]
    fn failpoint_after_current_keeps_current_a_non_authoritative_hint() -> TestResult {
        let directory = TestDirectory::new("after-current")?;
        let witness = SharedWitness::empty();
        let mut store = test_store(&directory, witness.clone())?;
        let publication = publication(0, 1, 1, 2)?;
        store.set_failpoint(PublishFailpoint::AfterCurrentBeforeWitness);
        assert_injected(store.publish_and_wait(&publication));
        assert_eq!(witness.value()?, None);
        assert!(store.current_hint_path().is_file());
        assert_eq!(
            store.restart_plan(
                CanonicalNetwork::Regtest,
                SCHEMA_VERSION,
                KEY_EPOCH,
                checkpoint(CanonicalNetwork::Regtest, 0, 1)
            ),
            ProjectionRestartPlan::Rebuild {
                prior_manifest: None,
                authoritative: checkpoint(CanonicalNetwork::Regtest, 0, 1),
                next_projection_epoch: 1,
            }
        );
        store.publish_and_wait(&publication)?;
        assert_eq!(require_freshness(&witness)?.sequence(), 1);
        Ok(())
    }

    #[test]
    fn failpoint_after_witness_makes_exact_retry_idempotent() -> TestResult {
        let directory = TestDirectory::new("after-witness")?;
        let witness = SharedWitness::empty();
        let mut store = test_store(&directory, witness.clone())?;
        let publication = publication(0, 1, 1, 2)?;
        store.set_failpoint(PublishFailpoint::AfterWitnessBeforeReturn);
        assert_injected(store.publish_and_wait(&publication));
        let authoritative_freshness = require_freshness(&witness)?;
        assert_eq!(authoritative_freshness.sequence(), 1);
        assert_eq!(manifest_count(&store)?, 1);
        store.publish_and_wait(&publication)?;
        assert_eq!(require_freshness(&witness)?, authoritative_freshness);
        assert_eq!(manifest_count(&store)?, 1);
        Ok(())
    }

    #[test]
    fn witness_digest_defeats_same_sequence_current_equivocation() -> TestResult {
        let directory = TestDirectory::new("equivocation")?;
        let witness = SharedWitness::empty();
        let mut store = test_store(&directory, witness.clone())?;
        let original_publication = publication(0, 1, 1, 2)?;
        store.publish_and_wait(&original_publication)?;
        let original_freshness = require_freshness(&witness)?;

        let alternate = PublishedProjectionManifest::new(
            original_publication.chain(),
            original_publication.schema_version(),
            original_publication.key_epoch(),
            original_publication.projection_epoch(),
            1,
            ProjectionEventLogRoot::from_bytes([0xee; 32]),
            None,
            ProjectionDurabilityMode::VolatileWorkerRebuildRequiredV1,
        )?;
        let (alternate_blob, alternate_digest) =
            encode_manifest_blob(&store.authenticator, &alternate)?;
        fs::write(store.manifest_path(alternate_digest), alternate_blob)?;
        store.write_current_hint(ProjectionFreshness::new(1, alternate_digest))?;

        let plan = store.restart_plan(
            CanonicalNetwork::Regtest,
            SCHEMA_VERSION,
            KEY_EPOCH,
            original_publication.chain(),
        );
        assert!(matches!(
            plan,
            ProjectionRestartPlan::Rebuild {
                prior_manifest: Some(manifest),
                next_projection_epoch: 2,
                ..
            } if manifest.event_log_root() == original_publication.event_log_root()
        ));

        fs::remove_file(store.manifest_path(original_freshness.manifest_digest()))?;
        assert_eq!(
            store.restart_plan(
                CanonicalNetwork::Regtest,
                SCHEMA_VERSION,
                KEY_EPOCH,
                original_publication.chain()
            ),
            ProjectionRestartPlan::Unready {
                reason: ProjectionRestartUnreadyReason::WitnessBoundManifestMissing
            }
        );
        Ok(())
    }

    #[test]
    fn rolled_back_or_corrupt_current_cannot_select_an_older_manifest() -> TestResult {
        let directory = TestDirectory::new("rollback")?;
        let witness = SharedWitness::empty();
        let mut store = test_store(&directory, witness.clone())?;
        let first = publication(0, 1, 1, 2)?;
        store.publish_and_wait(&first)?;
        let first_freshness = require_freshness(&witness)?;
        let second = publication(1, 2, 1, 3)?;
        store.publish_and_wait(&second)?;
        let second_freshness = require_freshness(&witness)?;

        store.write_current_hint(first_freshness)?;
        let plan = store.restart_plan(
            CanonicalNetwork::Regtest,
            SCHEMA_VERSION,
            KEY_EPOCH,
            second.chain(),
        );
        assert!(matches!(
            plan,
            ProjectionRestartPlan::Rebuild {
                prior_manifest: Some(manifest),
                next_projection_epoch: 2,
                ..
            } if manifest.publication_sequence() == 2 && manifest.chain() == second.chain()
        ));

        fs::write(store.current_hint_path(), b"host-controlled garbage")?;
        assert!(matches!(
            store.restart_plan(
                CanonicalNetwork::Regtest,
                SCHEMA_VERSION,
                KEY_EPOCH,
                second.chain()
            ),
            ProjectionRestartPlan::Rebuild {
                prior_manifest: Some(manifest),
                ..
            } if manifest.publication_sequence() == 2
        ));

        fs::remove_file(store.manifest_path(second_freshness.manifest_digest()))?;
        assert_eq!(
            store.restart_plan(
                CanonicalNetwork::Regtest,
                SCHEMA_VERSION,
                KEY_EPOCH,
                second.chain()
            ),
            ProjectionRestartPlan::Unready {
                reason: ProjectionRestartUnreadyReason::WitnessBoundManifestMissing
            }
        );
        assert!(store
            .manifest_path(first_freshness.manifest_digest())
            .is_file());
        Ok(())
    }

    #[test]
    fn torn_manifest_and_authenticated_tag_mutation_fail_closed() -> TestResult {
        let torn_directory = TestDirectory::new("torn")?;
        let torn_witness = SharedWitness::empty();
        let mut torn_store = test_store(&torn_directory, torn_witness.clone())?;
        let publication = publication(0, 1, 1, 2)?;
        torn_store.publish_and_wait(&publication)?;
        let freshness = require_freshness(&torn_witness)?;
        let path = torn_store.manifest_path(freshness.manifest_digest());
        let mut torn = OpenOptions::new().write(true).truncate(true).open(path)?;
        torn.write_all(&[0; 17])?;
        torn.sync_all()?;
        assert_eq!(
            torn_store.restart_plan(
                CanonicalNetwork::Regtest,
                SCHEMA_VERSION,
                KEY_EPOCH,
                publication.chain()
            ),
            ProjectionRestartPlan::Unready {
                reason: ProjectionRestartUnreadyReason::WitnessBoundManifestCorrupt
            }
        );

        let auth_directory = TestDirectory::new("auth-invalid")?;
        let auth_witness = SharedWitness::empty();
        let mut auth_store = test_store(&auth_directory, auth_witness.clone())?;
        auth_store.ensure_directories()?;
        let manifest = initial_manifest(1, 2)?;
        let (mut invalid_blob, _) = encode_manifest_blob(&auth_store.authenticator, &manifest)?;
        invalid_blob[MANIFEST_BLOB_BYTES - 1] ^= 1;
        let invalid_digest = manifest_digest(&invalid_blob);
        fs::write(auth_store.manifest_path(invalid_digest), invalid_blob)?;
        auth_witness.force(Some(ProjectionFreshness::new(1, invalid_digest)))?;
        assert_eq!(
            auth_store.restart_plan(
                CanonicalNetwork::Regtest,
                SCHEMA_VERSION,
                KEY_EPOCH,
                manifest.chain()
            ),
            ProjectionRestartPlan::Unready {
                reason: ProjectionRestartUnreadyReason::WitnessBoundManifestAuthenticationFailed
            }
        );
        Ok(())
    }

    #[test]
    fn restart_plans_fresh_equal_and_behind_checkpoints_as_rebuilds() -> TestResult {
        let directory = TestDirectory::new("restart-rebuild")?;
        let witness = SharedWitness::empty();
        let mut store = test_store(&directory, witness.clone())?;
        let authoritative = checkpoint(CanonicalNetwork::Regtest, 4, 4);
        assert_eq!(
            store.restart_plan(
                CanonicalNetwork::Regtest,
                SCHEMA_VERSION,
                KEY_EPOCH,
                authoritative
            ),
            ProjectionRestartPlan::Rebuild {
                prior_manifest: None,
                authoritative,
                next_projection_epoch: 1,
            }
        );

        let local = publication(4, 4, 1, 5)?;
        store.publish_and_wait(&local)?;
        assert!(matches!(
            store.restart_plan(
                CanonicalNetwork::Regtest,
                SCHEMA_VERSION,
                KEY_EPOCH,
                local.chain()
            ),
            ProjectionRestartPlan::Rebuild {
                prior_manifest: Some(_),
                next_projection_epoch: 2,
                ..
            }
        ));
        let ahead_authoritative = checkpoint(CanonicalNetwork::Regtest, 9, 9);
        assert!(matches!(
            store.restart_plan(
                CanonicalNetwork::Regtest,
                SCHEMA_VERSION,
                KEY_EPOCH,
                ahead_authoritative
            ),
            ProjectionRestartPlan::Rebuild {
                prior_manifest: Some(_),
                authoritative,
                next_projection_epoch: 2,
            } if authoritative == ahead_authoritative
        ));
        Ok(())
    }

    #[test]
    fn restart_fails_closed_for_witness_config_and_chain_conflicts() -> TestResult {
        let directory = TestDirectory::new("restart-unready")?;
        let witness = SharedWitness::empty();
        let mut store = test_store(&directory, witness.clone())?;
        let local = publication(4, 4, 1, 5)?;
        store.publish_and_wait(&local)?;

        assert_eq!(
            store.restart_plan(
                CanonicalNetwork::Regtest,
                SCHEMA_VERSION + 1,
                KEY_EPOCH,
                local.chain()
            ),
            ProjectionRestartPlan::Unready {
                reason: ProjectionRestartUnreadyReason::ManifestConfigurationMismatch
            }
        );
        assert_eq!(
            store.restart_plan(
                CanonicalNetwork::Regtest,
                SCHEMA_VERSION,
                KEY_EPOCH,
                checkpoint(CanonicalNetwork::Regtest, 3, 3)
            ),
            ProjectionRestartPlan::Unready {
                reason: ProjectionRestartUnreadyReason::LocalCheckpointAhead
            }
        );
        assert_eq!(
            store.restart_plan(
                CanonicalNetwork::Regtest,
                SCHEMA_VERSION,
                KEY_EPOCH,
                checkpoint(CanonicalNetwork::Regtest, 4, 0xff)
            ),
            ProjectionRestartPlan::Unready {
                reason: ProjectionRestartUnreadyReason::LocalCheckpointHashMismatch
            }
        );
        witness.set_available(false);
        assert_eq!(
            store.restart_plan(
                CanonicalNetwork::Regtest,
                SCHEMA_VERSION,
                KEY_EPOCH,
                local.chain()
            ),
            ProjectionRestartPlan::Unready {
                reason: ProjectionRestartUnreadyReason::WitnessUnavailable
            }
        );
        Ok(())
    }

    #[test]
    fn restart_rejects_projection_epoch_overflow() -> TestResult {
        let directory = TestDirectory::new("epoch-overflow")?;
        let witness = SharedWitness::empty();
        let mut store = test_store(&directory, witness)?;
        let publication = publication(0, 1, u64::MAX, 2)?;
        store.publish_and_wait(&publication)?;
        assert_eq!(
            store.restart_plan(
                CanonicalNetwork::Regtest,
                SCHEMA_VERSION,
                KEY_EPOCH,
                publication.chain()
            ),
            ProjectionRestartPlan::Unready {
                reason: ProjectionRestartUnreadyReason::ProjectionEpochOverflow
            }
        );
        Ok(())
    }

    #[test]
    fn publication_lineage_rejects_skips_regressions_and_config_changes() -> TestResult {
        let directory = TestDirectory::new("lineage")?;
        let witness = SharedWitness::empty();
        let mut store = test_store(&directory, witness)?;
        let first = publication(4, 4, 1, 1)?;
        store.publish_and_wait(&first)?;

        assert!(matches!(
            store.publish_and_wait(&publication(6, 6, 1, 2)?),
            Err(ProjectionManifestStoreError::ChainDidNotAdvance)
        ));
        assert!(matches!(
            store.publish_and_wait(&publication(5, 5, 3, 2)?),
            Err(ProjectionManifestStoreError::ProjectionEpochSkipped)
        ));
        let wrong_config = ProjectionPublication::new(
            checkpoint(CanonicalNetwork::Regtest, 5, 5),
            SCHEMA_VERSION + 1,
            KEY_EPOCH,
            1,
            ProjectionEventLogRoot::from_bytes([2; 32]),
        )?;
        assert!(matches!(
            store.publish_and_wait(&wrong_config),
            Err(ProjectionManifestStoreError::ConfigurationChanged)
        ));

        let wrong_genesis = publication(0, 0xff, 2, 3)?;
        assert!(matches!(
            store.publish_and_wait(&wrong_genesis),
            Err(ProjectionManifestStoreError::RebuildGenesisHashMismatch)
        ));
        let rebuilt = ProjectionPublication::new(
            PublicChainCheckpoint::new(
                CanonicalNetwork::Regtest,
                0,
                CanonicalNetwork::Regtest.genesis_hash(),
            ),
            SCHEMA_VERSION,
            KEY_EPOCH,
            2,
            ProjectionEventLogRoot::from_bytes([3; 32]),
        )?;
        store.publish_and_wait(&rebuilt)?;
        assert_eq!(rebuilt.projection_epoch(), 2);
        let skipped_genesis = publication(1, 0xff, 3, 4)?;
        assert!(matches!(
            store.publish_and_wait(&skipped_genesis),
            Err(ProjectionManifestStoreError::RebuildDidNotStartAtGenesis)
        ));
        Ok(())
    }

    #[test]
    fn freshness_witness_compare_binds_sequence_and_digest() -> TestResult {
        let mut witness = SharedWitness::empty();
        let first = ProjectionFreshness::new(1, ProjectionManifestDigest::from_bytes([1; 32]));
        witness.compare_and_advance(None, first)?;
        let wrong_expected = ProjectionFreshness::new(
            first.sequence(),
            ProjectionManifestDigest::from_bytes([2; 32]),
        );
        let second = ProjectionFreshness::new(2, ProjectionManifestDigest::from_bytes([3; 32]));
        assert_eq!(
            witness.compare_and_advance(Some(wrong_expected), second),
            Err(TestWitnessError::Conflict)
        );
        assert_eq!(witness.value()?, Some(first));
        witness.compare_and_advance(Some(first), second)?;
        assert_eq!(witness.value()?, Some(second));
        Ok(())
    }
}
