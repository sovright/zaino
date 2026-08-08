//! Crash-durable local replay-journal foundation.
//!
//! The journal records the request lane and the continuation real-or-cover
//! lane as one ordered local transaction. Fixed-size record bodies are sealed
//! behind an injected protector so the first file format does not expose lane
//! tags, replay identities, or counters in plaintext. The production protector
//! lives in the [`xchacha20`] submodule; this module deliberately supplies no
//! external freshness witness, trusted time, runtime wiring, or oblivious
//! memory, page, storage, or timing access. It also assumes exactly one live
//! writer for a recovery
//! directory; no process lock or multi-writer linearizability is provided.
//!
//! The v6 journal is append-only and capacity counts total committed
//! transactions, not live claims. Request claims have no expiry. A continuation
//! claim keeps its opaque key and profile-derived expiry bucket ordinal
//! inseparable in entry v2. Current-state v3 can persist a monotonic inclusive
//! expiry-bucket watermark through a dedicated typed transition, but this
//! module supplies no trusted authority or non-test caller for that transition.
//! There is still no claim deletion, count reduction, compaction, or capacity
//! reclamation.

use std::{
    collections::HashSet,
    fmt,
    fs::{self, File},
    io::{self, Read, Write},
    num::NonZeroU64,
    path::{Path, PathBuf},
};

use blake2::{Blake2s256, Digest};
use tempfile::NamedTempFile;

use crate::{
    continuation_token::{ContinuationReplayGuard, ContinuationReplayPlan},
    persistence::fs_atomic::{
        create_unique_file, ensure_real_directory, sync_directory, RealDirectoryError,
    },
    profile::{CompiledReplayPolicy, PrivacyProfile, PROFILE_ID_BYTES},
    protection::{AuthenticationDecision, ProtectionUnavailable},
    runtime_security::{
        ReplayCommitAuthority, ReplayCommitResult, ReplayCommitUnavailable,
        ReplayDuplicateDecision, RequestReplayKey, SecurityRoundCapture, REPLAY_RECORD_KEY_BYTES,
    },
};

use super::{
    security_state_binding::{
        preflight_successor, provision_initial_snapshot, successor_after_replay_commit,
        successor_after_replay_maintenance, verify_current, SecurityStateBindingError,
    },
    security_state_store::{
        SecurityFreshnessWitness, SecurityStateIdentity, SecurityStateSnapshot, SecurityStateStore,
        SecurityStateStoreError, STATE_DIGEST_BYTES,
    },
};

#[cfg(test)]
use super::security_state_store::witness_conformance;

mod xchacha20;

pub(super) use xchacha20::{record_protector, OsJournalRecordNonces};

const CURRENT_FORMAT_VERSION: u16 = 3;
const ENTRY_FORMAT_VERSION: u16 = 2;
const U16_BYTES: usize = 2;
const U64_BYTES: usize = 8;
const DIGEST_BYTES: usize = 32;
const RECORD_MAGIC_BYTES: usize = 8;
const PROTECTION_OVERHEAD_BYTES: usize = 40;
const CURRENT_RESERVED_BYTES: usize = 40;
const ENTRY_RESERVED_BYTES: usize = 15;

const CURRENT_MAGIC: [u8; RECORD_MAGIC_BYTES] = *b"ZORJCUR3";
const ENTRY_MAGIC: [u8; RECORD_MAGIC_BYTES] = *b"ZORJENT2";
const CURRENT_STATE_FILE: &str = "current.bin";
const ENTRIES_DIRECTORY: &str = "entries";
const STAGING_DIRECTORY: &str = "staging";
const ENTRY_FILE_SUFFIX: &str = ".bin";

const ENTRY_PAYLOAD_DOMAIN: &[u8] = b"zaino-oram/replay-journal/entry-payload";
const ENTRY_CHAIN_DOMAIN: &[u8] = b"zaino-oram/replay-journal/entry-chain";
const COMPONENT_STATE_DOMAIN: &[u8] = b"zaino-oram/replay-journal/component-state";

const CURRENT_LIMIT_TRANSACTIONS_START: usize = 0;
const CURRENT_PROFILE_ID_START: usize = CURRENT_LIMIT_TRANSACTIONS_START + U64_BYTES;
const CURRENT_SEQUENCE_START: usize = CURRENT_PROFILE_ID_START + PROFILE_ID_BYTES;
const CURRENT_REQUEST_COUNT_START: usize = CURRENT_SEQUENCE_START + U64_BYTES;
const CURRENT_CONTINUATION_COUNT_START: usize = CURRENT_REQUEST_COUNT_START + U64_BYTES;
const CURRENT_CHAIN_DIGEST_START: usize = CURRENT_CONTINUATION_COUNT_START + U64_BYTES;
const CURRENT_MAINTENANCE_WATERMARK_START: usize = CURRENT_CHAIN_DIGEST_START + DIGEST_BYTES;
const CURRENT_RESERVED_START: usize = CURRENT_MAINTENANCE_WATERMARK_START + U64_BYTES;
const CURRENT_BODY_BYTES: usize = CURRENT_RESERVED_START + CURRENT_RESERVED_BYTES;
const CURRENT_PROTECTED_BYTES: usize = CURRENT_BODY_BYTES + PROTECTION_OVERHEAD_BYTES;
const CURRENT_PROTECTED_START: usize = RECORD_MAGIC_BYTES + U16_BYTES;
const CURRENT_RECORD_BYTES: usize = CURRENT_PROTECTED_START + CURRENT_PROTECTED_BYTES;

const ENTRY_SEQUENCE_START: usize = 0;
const ENTRY_REQUEST_KEY_START: usize = ENTRY_SEQUENCE_START + U64_BYTES;
const ENTRY_CONTINUATION_TAG_START: usize = ENTRY_REQUEST_KEY_START + REPLAY_RECORD_KEY_BYTES;
const ENTRY_CONTINUATION_KEY_START: usize = ENTRY_CONTINUATION_TAG_START + 1;
const ENTRY_CONTINUATION_EXPIRY_BUCKET_ORDINAL_START: usize =
    ENTRY_CONTINUATION_KEY_START + REPLAY_RECORD_KEY_BYTES;
const ENTRY_RESERVED_START: usize = ENTRY_CONTINUATION_EXPIRY_BUCKET_ORDINAL_START + U64_BYTES;
const ENTRY_BODY_BYTES: usize = ENTRY_RESERVED_START + ENTRY_RESERVED_BYTES;
const ENTRY_PROTECTED_BYTES: usize = ENTRY_BODY_BYTES + PROTECTION_OVERHEAD_BYTES;
const ENTRY_PROTECTED_START: usize = RECORD_MAGIC_BYTES + U16_BYTES;
const ENTRY_RECORD_BYTES: usize = ENTRY_PROTECTED_START + ENTRY_PROTECTED_BYTES;

const CONTINUATION_COVER_TAG: u8 = 0;
const CONTINUATION_CLAIM_TAG: u8 = 1;

const _: [(); 128] = [(); CURRENT_BODY_BYTES];
const _: [(); 178] = [(); CURRENT_RECORD_BYTES];
const _: [(); 96] = [(); ENTRY_BODY_BYTES];
const _: [(); 146] = [(); ENTRY_RECORD_BYTES];

/// Protects one fixed-size local replay-journal record body.
///
/// The opaque protected output has a fixed forty-byte overhead so a future
/// production implementation can carry its own nonce and authentication
/// material without changing the journal framing. A production implementation
/// must authenticate `context`, `kind`, and the format version; reserve a
/// nonce that is unique across both record kinds under the effective
/// journal-specific key; authenticate before writing plaintext; and leave the
/// output unchanged on rejection or provider error. Existing request,
/// response, and continuation-token role keys must not be reused. This PR
/// intentionally supplies only a deterministic test implementation.
pub(super) trait ReplayJournalRecordProtector {
    fn seal(
        &self,
        context: &ReplayJournalProtectionContext,
        kind: ReplayJournalRecordKind,
        plaintext: &[u8],
        protected: &mut [u8],
    ) -> Result<(), ProtectionUnavailable>;

    fn open(
        &self,
        context: &ReplayJournalProtectionContext,
        kind: ReplayJournalRecordKind,
        protected: &[u8],
        plaintext: &mut [u8],
    ) -> Result<AuthenticationDecision, ProtectionUnavailable>;
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct ReplayJournalProtectionContext([u8; DIGEST_BYTES]);

impl ReplayJournalProtectionContext {
    pub(super) const fn new(binding: [u8; DIGEST_BYTES]) -> Self {
        Self(binding)
    }

    const fn as_bytes(&self) -> &[u8; DIGEST_BYTES] {
        &self.0
    }
}

impl fmt::Debug for ReplayJournalProtectionContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ReplayJournalProtectionContext([REDACTED])")
    }
}

// Debug and PartialEq carry no secret: the variants are the record's public
// format tag, already written in the clear as part of every record header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ReplayJournalRecordKind {
    CurrentStateV3,
    ImmutableEntryV2,
}

impl ReplayJournalRecordKind {
    const fn tag(self) -> u8 {
        match self {
            Self::CurrentStateV3 => 0,
            Self::ImmutableEntryV2 => 1,
        }
    }

    const fn format_version(self) -> u16 {
        match self {
            Self::CurrentStateV3 => CURRENT_FORMAT_VERSION,
            Self::ImmutableEntryV2 => ENTRY_FORMAT_VERSION,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct ReplayJournalLimits {
    /// Maximum lifetime append count; v6 never reclaims consumed capacity.
    max_transactions: u64,
}

impl ReplayJournalLimits {
    fn new(max_transactions: u64) -> Result<Self, ReplayJournalValueError> {
        if max_transactions == 0 {
            return Err(ReplayJournalValueError::ZeroLimit);
        }
        Ok(Self { max_transactions })
    }

    fn from_compiled_policy(policy: CompiledReplayPolicy) -> Self {
        Self {
            max_transactions: policy.transaction_capacity(),
        }
    }
}

impl fmt::Debug for ReplayJournalLimits {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ReplayJournalLimits { ..REDACTED.. }")
    }
}

/// Recorded inclusive continuation expiry-bucket ceiling for maintenance.
///
/// Zero means that no continuation bucket is maintenance-addressable. A
/// nonzero value is classification metadata only: it is not trusted-time
/// authority and does not authorize deletion, claim-count reduction,
/// compaction, or capacity reclamation.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct ReplayMaintenanceWatermark(u64);

impl ReplayMaintenanceWatermark {
    const NONE: Self = Self(0);

    const fn new(inclusive_expiry_bucket_ordinal: u64) -> Self {
        Self(inclusive_expiry_bucket_ordinal)
    }

    const fn inclusive_expiry_bucket_ordinal(self) -> u64 {
        self.0
    }
}

impl fmt::Debug for ReplayMaintenanceWatermark {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ReplayMaintenanceWatermark([REDACTED])")
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ReplayJournalContinuationLane {
    Cover,
    Claim {
        key: [u8; REPLAY_RECORD_KEY_BYTES],
        expiry_bucket_ordinal: NonZeroU64,
    },
}

impl fmt::Debug for ReplayJournalContinuationLane {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ReplayJournalContinuationLane([REDACTED])")
    }
}

/// One immutable v2 transaction entry.
///
/// The continuation claim is an opaque digest that already binds its exact
/// token expiry plus its profile-derived nonzero one-based expiry bucket
/// ordinal. Request claims still carry no expiry metadata.
#[derive(Clone, Copy, PartialEq, Eq)]
struct ReplayJournalEntry {
    sequence: u64,
    request_key: [u8; REPLAY_RECORD_KEY_BYTES],
    continuation_lane: ReplayJournalContinuationLane,
}

impl ReplayJournalEntry {
    fn canonical_body(&self) -> [u8; ENTRY_BODY_BYTES] {
        let mut body = [0; ENTRY_BODY_BYTES];
        body[ENTRY_SEQUENCE_START..ENTRY_REQUEST_KEY_START]
            .copy_from_slice(&self.sequence.to_be_bytes());
        body[ENTRY_REQUEST_KEY_START..ENTRY_CONTINUATION_TAG_START]
            .copy_from_slice(&self.request_key);
        match self.continuation_lane {
            ReplayJournalContinuationLane::Cover => {
                body[ENTRY_CONTINUATION_TAG_START] = CONTINUATION_COVER_TAG;
            }
            ReplayJournalContinuationLane::Claim {
                key,
                expiry_bucket_ordinal,
            } => {
                body[ENTRY_CONTINUATION_TAG_START] = CONTINUATION_CLAIM_TAG;
                body[ENTRY_CONTINUATION_KEY_START..ENTRY_CONTINUATION_EXPIRY_BUCKET_ORDINAL_START]
                    .copy_from_slice(&key);
                body[ENTRY_CONTINUATION_EXPIRY_BUCKET_ORDINAL_START..ENTRY_RESERVED_START]
                    .copy_from_slice(&expiry_bucket_ordinal.get().to_be_bytes());
            }
        }
        body
    }

    fn payload_digest(&self) -> [u8; DIGEST_BYTES] {
        versioned_digest(
            ENTRY_PAYLOAD_DOMAIN,
            ENTRY_FORMAT_VERSION,
            &[&self.canonical_body()],
        )
    }
}

impl fmt::Debug for ReplayJournalEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ReplayJournalEntry { ..REDACTED.. }")
    }
}

/// Opaque committed state of the local replay component.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct ReplayJournalComponentStateDigest([u8; DIGEST_BYTES]);

impl ReplayJournalComponentStateDigest {
    pub(super) const fn as_bytes(&self) -> &[u8; DIGEST_BYTES] {
        &self.0
    }
}

impl fmt::Debug for ReplayJournalComponentStateDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ReplayJournalComponentStateDigest([REDACTED])")
    }
}

/// Monotonic v6 replay head reconstructed from every committed entry plus the
/// independently persisted maintenance watermark.
///
/// Both claim counts only increase. This state has no deletion base, live-count
/// distinction, or authority to retire claims or capacity.
#[derive(Clone, Copy, PartialEq, Eq)]
struct ReplayJournalState {
    limits: ReplayJournalLimits,
    profile_id: [u8; PROFILE_ID_BYTES],
    committed_sequence: u64,
    claimed_request_count: u64,
    claimed_continuation_count: u64,
    entry_chain_digest: [u8; DIGEST_BYTES],
    maintenance_expiry_bucket_watermark: ReplayMaintenanceWatermark,
}

impl ReplayJournalState {
    const fn empty(limits: ReplayJournalLimits, profile_id: [u8; PROFILE_ID_BYTES]) -> Self {
        Self {
            limits,
            profile_id,
            committed_sequence: 0,
            claimed_request_count: 0,
            claimed_continuation_count: 0,
            entry_chain_digest: [0; DIGEST_BYTES],
            maintenance_expiry_bucket_watermark: ReplayMaintenanceWatermark::NONE,
        }
    }

    fn validate(&self) -> Result<(), ReplayJournalValueError> {
        if all_zero(&self.profile_id) {
            return Err(ReplayJournalValueError::ProfileIdIsEmpty);
        }
        if self.committed_sequence > self.limits.max_transactions
            || self.claimed_request_count > self.committed_sequence
            || self.claimed_continuation_count > self.claimed_request_count
        {
            return Err(ReplayJournalValueError::InvalidState);
        }
        if self.committed_sequence == 0
            && (self.claimed_request_count != 0
                || self.claimed_continuation_count != 0
                || self.entry_chain_digest != [0; DIGEST_BYTES])
        {
            return Err(ReplayJournalValueError::InvalidState);
        }
        Ok(())
    }

    fn canonical_current_body(&self) -> [u8; CURRENT_BODY_BYTES] {
        let mut body = [0; CURRENT_BODY_BYTES];
        body[CURRENT_LIMIT_TRANSACTIONS_START..CURRENT_PROFILE_ID_START]
            .copy_from_slice(&self.limits.max_transactions.to_be_bytes());
        body[CURRENT_PROFILE_ID_START..CURRENT_SEQUENCE_START].copy_from_slice(&self.profile_id);
        body[CURRENT_SEQUENCE_START..CURRENT_REQUEST_COUNT_START]
            .copy_from_slice(&self.committed_sequence.to_be_bytes());
        body[CURRENT_REQUEST_COUNT_START..CURRENT_CONTINUATION_COUNT_START]
            .copy_from_slice(&self.claimed_request_count.to_be_bytes());
        body[CURRENT_CONTINUATION_COUNT_START..CURRENT_CHAIN_DIGEST_START]
            .copy_from_slice(&self.claimed_continuation_count.to_be_bytes());
        body[CURRENT_CHAIN_DIGEST_START..CURRENT_MAINTENANCE_WATERMARK_START]
            .copy_from_slice(&self.entry_chain_digest);
        body[CURRENT_MAINTENANCE_WATERMARK_START..CURRENT_RESERVED_START].copy_from_slice(
            &self
                .maintenance_expiry_bucket_watermark
                .inclusive_expiry_bucket_ordinal()
                .to_be_bytes(),
        );
        body
    }

    fn preview_entry(
        &self,
        request_claims: &HashSet<[u8; REPLAY_RECORD_KEY_BYTES]>,
        continuation_claims: &HashSet<[u8; REPLAY_RECORD_KEY_BYTES]>,
        entry: &ReplayJournalEntry,
    ) -> Result<(Self, ReplayJournalDelta, ReplayDuplicateDecision), ReplayJournalTransitionError>
    {
        let expected_sequence = self
            .committed_sequence
            .checked_add(1)
            .ok_or(ReplayJournalTransitionError::SequenceOverflow)?;
        if entry.sequence != expected_sequence {
            return Err(ReplayJournalTransitionError::InvalidSequence);
        }
        if entry.sequence > self.limits.max_transactions {
            return Err(ReplayJournalTransitionError::TransactionCapacityExceeded);
        }

        let request_is_fresh = !request_claims.contains(&entry.request_key);
        let (insert_continuation, decision) = if request_is_fresh {
            match entry.continuation_lane {
                ReplayJournalContinuationLane::Cover => (None, ReplayDuplicateDecision::Fresh),
                ReplayJournalContinuationLane::Claim { key, .. } => {
                    if continuation_claims.contains(&key) {
                        return Err(ReplayJournalTransitionError::InvalidDuplicateContinuationLane);
                    }
                    (Some(key), ReplayDuplicateDecision::Fresh)
                }
            }
        } else {
            if entry.continuation_lane != ReplayJournalContinuationLane::Cover {
                return Err(ReplayJournalTransitionError::InvalidDuplicateRequestLane);
            }
            (None, ReplayDuplicateDecision::RequestDuplicate)
        };

        let claimed_request_count = self
            .claimed_request_count
            .checked_add(u64::from(request_is_fresh))
            .ok_or(ReplayJournalTransitionError::InconsistentClaimSet)?;
        let claimed_continuation_count = self
            .claimed_continuation_count
            .checked_add(u64::from(insert_continuation.is_some()))
            .ok_or(ReplayJournalTransitionError::InconsistentClaimSet)?;

        let payload_digest = entry.payload_digest();
        let entry_chain_digest = versioned_digest(
            ENTRY_CHAIN_DOMAIN,
            ENTRY_FORMAT_VERSION,
            &[&self.entry_chain_digest, &payload_digest],
        );
        let next = Self {
            limits: self.limits,
            profile_id: self.profile_id,
            committed_sequence: entry.sequence,
            claimed_request_count,
            claimed_continuation_count,
            entry_chain_digest,
            maintenance_expiry_bucket_watermark: self.maintenance_expiry_bucket_watermark,
        };
        Ok((
            next,
            ReplayJournalDelta {
                insert_request: request_is_fresh.then_some(entry.request_key),
                insert_continuation,
            },
            decision,
        ))
    }

    fn apply_entry(
        &self,
        request_claims: &mut HashSet<[u8; REPLAY_RECORD_KEY_BYTES]>,
        continuation_claims: &mut HashSet<[u8; REPLAY_RECORD_KEY_BYTES]>,
        entry: &ReplayJournalEntry,
    ) -> Result<(Self, ReplayDuplicateDecision), ReplayJournalTransitionError> {
        let (next, delta, decision) =
            self.preview_entry(request_claims, continuation_claims, entry)?;
        if let Some(key) = delta.insert_request {
            if !request_claims.insert(key) {
                return Err(ReplayJournalTransitionError::InconsistentClaimSet);
            }
        }
        if let Some(key) = delta.insert_continuation {
            if !continuation_claims.insert(key) {
                return Err(ReplayJournalTransitionError::InconsistentClaimSet);
            }
        }
        Ok((next, decision))
    }

    fn component_state_digest(&self) -> ReplayJournalComponentStateDigest {
        ReplayJournalComponentStateDigest(versioned_digest(
            COMPONENT_STATE_DOMAIN,
            CURRENT_FORMAT_VERSION,
            &[&self.canonical_current_body()],
        ))
    }

    fn preview_maintenance_watermark(
        &self,
        proposed: ReplayMaintenanceWatermark,
    ) -> Result<Option<Self>, ReplayJournalStoreError> {
        if proposed < self.maintenance_expiry_bucket_watermark {
            return Err(ReplayJournalStoreError::MaintenanceWatermarkRegressed);
        }
        if proposed == self.maintenance_expiry_bucket_watermark {
            return Ok(None);
        }
        Ok(Some(Self {
            maintenance_expiry_bucket_watermark: proposed,
            ..*self
        }))
    }

    const fn has_persisted_transition(&self) -> bool {
        self.committed_sequence != 0 || self.maintenance_expiry_bucket_watermark.0 != 0
    }
}

impl fmt::Debug for ReplayJournalState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ReplayJournalState { ..REDACTED.. }")
    }
}

#[derive(Clone, Copy)]
struct ReplayJournalDelta {
    insert_request: Option<[u8; REPLAY_RECORD_KEY_BYTES]>,
    insert_continuation: Option<[u8; REPLAY_RECORD_KEY_BYTES]>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ReplayJournalValueError {
    ZeroLimit,
    ProfileIdIsEmpty,
    InvalidState,
    InvalidContinuationTag,
    NonZeroReservedBytes,
    NonZeroCoverKey,
    NonZeroCoverExpiryBucketOrdinal,
    ZeroClaimExpiryBucketOrdinal,
}

impl fmt::Debug for ReplayJournalValueError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ReplayJournalValueError([REDACTED])")
    }
}

impl fmt::Display for ReplayJournalValueError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("replay journal value is invalid")
    }
}

impl std::error::Error for ReplayJournalValueError {}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ReplayJournalTransitionError {
    InvalidSequence,
    InvalidDuplicateRequestLane,
    InvalidDuplicateContinuationLane,
    TransactionCapacityExceeded,
    SequenceOverflow,
    InconsistentClaimSet,
}

impl fmt::Debug for ReplayJournalTransitionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ReplayJournalTransitionError([REDACTED])")
    }
}

struct PersistentReplayJournalCurrentStateV3([u8; CURRENT_RECORD_BYTES]);

impl PersistentReplayJournalCurrentStateV3 {
    fn from_business<P>(
        state: &ReplayJournalState,
        context: &ReplayJournalProtectionContext,
        protector: &P,
    ) -> Result<Self, ReplayJournalRecordError>
    where
        P: ReplayJournalRecordProtector,
    {
        state
            .validate()
            .map_err(ReplayJournalRecordError::InvalidValue)?;
        if !state.has_persisted_transition() {
            return Err(ReplayJournalRecordError::InvalidValue(
                ReplayJournalValueError::InvalidState,
            ));
        }

        let body = state.canonical_current_body();

        let mut bytes = [0; CURRENT_RECORD_BYTES];
        bytes[..RECORD_MAGIC_BYTES].copy_from_slice(&CURRENT_MAGIC);
        bytes[RECORD_MAGIC_BYTES..CURRENT_PROTECTED_START]
            .copy_from_slice(&CURRENT_FORMAT_VERSION.to_be_bytes());
        protector
            .seal(
                context,
                ReplayJournalRecordKind::CurrentStateV3,
                &body,
                &mut bytes[CURRENT_PROTECTED_START..],
            )
            .map_err(|_| ReplayJournalRecordError::ProtectionUnavailable)?;
        Ok(Self(bytes))
    }

    fn into_business<P>(
        self,
        context: &ReplayJournalProtectionContext,
        protector: &P,
    ) -> Result<ReplayJournalState, ReplayJournalRecordError>
    where
        P: ReplayJournalRecordProtector,
    {
        validate_header(&self.0, CURRENT_MAGIC, CURRENT_FORMAT_VERSION)?;
        let mut body = [0; CURRENT_BODY_BYTES];
        match protector
            .open(
                context,
                ReplayJournalRecordKind::CurrentStateV3,
                &self.0[CURRENT_PROTECTED_START..],
                &mut body,
            )
            .map_err(|_| ReplayJournalRecordError::ProtectionUnavailable)?
        {
            AuthenticationDecision::Accepted => {}
            AuthenticationDecision::Rejected => {
                return Err(ReplayJournalRecordError::AuthenticationFailed);
            }
        }
        if !all_zero(&body[CURRENT_RESERVED_START..]) {
            return Err(ReplayJournalRecordError::InvalidValue(
                ReplayJournalValueError::NonZeroReservedBytes,
            ));
        }
        let limits = ReplayJournalLimits::new(read_u64(&body, CURRENT_LIMIT_TRANSACTIONS_START))
            .map_err(ReplayJournalRecordError::InvalidValue)?;
        let state = ReplayJournalState {
            limits,
            profile_id: read_array(&body, CURRENT_PROFILE_ID_START),
            committed_sequence: read_u64(&body, CURRENT_SEQUENCE_START),
            claimed_request_count: read_u64(&body, CURRENT_REQUEST_COUNT_START),
            claimed_continuation_count: read_u64(&body, CURRENT_CONTINUATION_COUNT_START),
            entry_chain_digest: read_array(&body, CURRENT_CHAIN_DIGEST_START),
            maintenance_expiry_bucket_watermark: ReplayMaintenanceWatermark::new(read_u64(
                &body,
                CURRENT_MAINTENANCE_WATERMARK_START,
            )),
        };
        state
            .validate()
            .map_err(ReplayJournalRecordError::InvalidValue)?;
        if !state.has_persisted_transition() {
            return Err(ReplayJournalRecordError::InvalidValue(
                ReplayJournalValueError::InvalidState,
            ));
        }
        Ok(state)
    }

    const fn as_bytes(&self) -> &[u8; CURRENT_RECORD_BYTES] {
        &self.0
    }
}

impl fmt::Debug for PersistentReplayJournalCurrentStateV3 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PersistentReplayJournalCurrentStateV3([REDACTED])")
    }
}

struct PersistentReplayJournalEntry([u8; ENTRY_RECORD_BYTES]);

impl PersistentReplayJournalEntry {
    fn from_business<P>(
        entry: &ReplayJournalEntry,
        context: &ReplayJournalProtectionContext,
        protector: &P,
    ) -> Result<Self, ReplayJournalRecordError>
    where
        P: ReplayJournalRecordProtector,
    {
        if entry.sequence == 0 {
            return Err(ReplayJournalRecordError::InvalidValue(
                ReplayJournalValueError::InvalidState,
            ));
        }
        let body = entry.canonical_body();
        let mut bytes = [0; ENTRY_RECORD_BYTES];
        bytes[..RECORD_MAGIC_BYTES].copy_from_slice(&ENTRY_MAGIC);
        bytes[RECORD_MAGIC_BYTES..ENTRY_PROTECTED_START]
            .copy_from_slice(&ENTRY_FORMAT_VERSION.to_be_bytes());
        protector
            .seal(
                context,
                ReplayJournalRecordKind::ImmutableEntryV2,
                &body,
                &mut bytes[ENTRY_PROTECTED_START..],
            )
            .map_err(|_| ReplayJournalRecordError::ProtectionUnavailable)?;
        Ok(Self(bytes))
    }

    fn into_business<P>(
        self,
        context: &ReplayJournalProtectionContext,
        protector: &P,
    ) -> Result<ReplayJournalEntry, ReplayJournalRecordError>
    where
        P: ReplayJournalRecordProtector,
    {
        validate_header(&self.0, ENTRY_MAGIC, ENTRY_FORMAT_VERSION)?;
        let mut body = [0; ENTRY_BODY_BYTES];
        match protector
            .open(
                context,
                ReplayJournalRecordKind::ImmutableEntryV2,
                &self.0[ENTRY_PROTECTED_START..],
                &mut body,
            )
            .map_err(|_| ReplayJournalRecordError::ProtectionUnavailable)?
        {
            AuthenticationDecision::Accepted => {}
            AuthenticationDecision::Rejected => {
                return Err(ReplayJournalRecordError::AuthenticationFailed);
            }
        }
        if !all_zero(&body[ENTRY_RESERVED_START..]) {
            return Err(ReplayJournalRecordError::InvalidValue(
                ReplayJournalValueError::NonZeroReservedBytes,
            ));
        }

        let continuation_key =
            read_array::<REPLAY_RECORD_KEY_BYTES>(&body, ENTRY_CONTINUATION_KEY_START);
        let continuation_expiry_bucket_ordinal =
            read_u64(&body, ENTRY_CONTINUATION_EXPIRY_BUCKET_ORDINAL_START);
        let continuation_lane = match body[ENTRY_CONTINUATION_TAG_START] {
            CONTINUATION_COVER_TAG => {
                if continuation_key != [0; REPLAY_RECORD_KEY_BYTES] {
                    return Err(ReplayJournalRecordError::InvalidValue(
                        ReplayJournalValueError::NonZeroCoverKey,
                    ));
                }
                if continuation_expiry_bucket_ordinal != 0 {
                    return Err(ReplayJournalRecordError::InvalidValue(
                        ReplayJournalValueError::NonZeroCoverExpiryBucketOrdinal,
                    ));
                }
                ReplayJournalContinuationLane::Cover
            }
            CONTINUATION_CLAIM_TAG => ReplayJournalContinuationLane::Claim {
                key: continuation_key,
                expiry_bucket_ordinal: NonZeroU64::new(continuation_expiry_bucket_ordinal).ok_or(
                    ReplayJournalRecordError::InvalidValue(
                        ReplayJournalValueError::ZeroClaimExpiryBucketOrdinal,
                    ),
                )?,
            },
            _ => {
                return Err(ReplayJournalRecordError::InvalidValue(
                    ReplayJournalValueError::InvalidContinuationTag,
                ));
            }
        };
        let entry = ReplayJournalEntry {
            sequence: read_u64(&body, ENTRY_SEQUENCE_START),
            request_key: read_array(&body, ENTRY_REQUEST_KEY_START),
            continuation_lane,
        };
        if entry.sequence == 0 {
            return Err(ReplayJournalRecordError::InvalidValue(
                ReplayJournalValueError::InvalidState,
            ));
        }
        Ok(entry)
    }

    const fn as_bytes(&self) -> &[u8; ENTRY_RECORD_BYTES] {
        &self.0
    }
}

impl fmt::Debug for PersistentReplayJournalEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PersistentReplayJournalEntry([REDACTED])")
    }
}

#[derive(Debug)]
enum ReplayJournalRecordError {
    InvalidMagic,
    UnsupportedVersion,
    AuthenticationFailed,
    ProtectionUnavailable,
    InvalidValue(ReplayJournalValueError),
}

impl fmt::Display for ReplayJournalRecordError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("replay journal record is invalid")
    }
}

impl std::error::Error for ReplayJournalRecordError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidValue(error) => Some(error),
            _ => None,
        }
    }
}

#[derive(Clone, Copy)]
struct PreparedReplayJournalCommit {
    entry: ReplayJournalEntry,
    next_state: ReplayJournalState,
    delta: ReplayJournalDelta,
    decision: ReplayDuplicateDecision,
}

enum ReplayMaintenancePreparation {
    NoAdvance,
    Advance(PreparedReplayMaintenanceAdvance),
}

struct PreparedReplayMaintenanceAdvance {
    previous_digest: ReplayJournalComponentStateDigest,
    next_state: ReplayJournalState,
}

impl fmt::Debug for ReplayMaintenancePreparation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ReplayMaintenancePreparation { ..REDACTED.. }")
    }
}

impl fmt::Debug for PreparedReplayJournalCommit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PreparedReplayJournalCommit { ..REDACTED.. }")
    }
}

mod committed_advance {
    use std::sync::Arc;

    use super::*;

    #[derive(Clone)]
    pub(super) struct ReplayJournalInstanceIdentity(Arc<()>);

    impl ReplayJournalInstanceIdentity {
        pub(super) fn new() -> Self {
            Self(Arc::new(()))
        }

        fn matches(&self, other: &Self) -> bool {
            Arc::ptr_eq(&self.0, &other.0)
        }
    }

    struct ReplayJournalAdvanceEvidence {
        instance_identity: ReplayJournalInstanceIdentity,
        previous_digest: ReplayJournalComponentStateDigest,
        committed_digest: ReplayJournalComponentStateDigest,
    }

    impl ReplayJournalAdvanceEvidence {
        fn new(
            instance_identity: ReplayJournalInstanceIdentity,
            previous_digest: ReplayJournalComponentStateDigest,
            committed_digest: ReplayJournalComponentStateDigest,
        ) -> Self {
            Self {
                instance_identity,
                previous_digest,
                committed_digest,
            }
        }

        fn into_digests(
            self,
        ) -> (
            ReplayJournalComponentStateDigest,
            ReplayJournalComponentStateDigest,
        ) {
            (self.previous_digest, self.committed_digest)
        }

        fn was_minted_for(&self, instance_identity: &ReplayJournalInstanceIdentity) -> bool {
            self.instance_identity.matches(instance_identity)
        }
    }

    /// Move-only evidence minted after one replay transaction's durable
    /// boundary.
    pub(in crate::inner_codec) struct ReplayJournalAdvanceReceipt {
        evidence: ReplayJournalAdvanceEvidence,
    }

    impl ReplayJournalAdvanceReceipt {
        pub(in crate::inner_codec) fn into_digests(
            self,
        ) -> (
            ReplayJournalComponentStateDigest,
            ReplayJournalComponentStateDigest,
        ) {
            self.evidence.into_digests()
        }

        pub(super) fn was_minted_for(
            &self,
            instance_identity: &ReplayJournalInstanceIdentity,
        ) -> bool {
            self.evidence.was_minted_for(instance_identity)
        }
    }

    impl fmt::Debug for ReplayJournalAdvanceReceipt {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("ReplayJournalAdvanceReceipt { ..REDACTED.. }")
        }
    }

    /// Move-only evidence minted after one maintenance-watermark advance's
    /// durable boundary.
    ///
    /// This distinct type cannot be consumed by the request-commit binding
    /// path. It proves only a replay-current mutation, not trusted-time
    /// authority, claim retirement, deletion, or capacity reclamation.
    pub(in crate::inner_codec) struct ReplayJournalMaintenanceAdvanceReceipt {
        evidence: ReplayJournalAdvanceEvidence,
    }

    impl ReplayJournalMaintenanceAdvanceReceipt {
        pub(in crate::inner_codec) fn into_digests(
            self,
        ) -> (
            ReplayJournalComponentStateDigest,
            ReplayJournalComponentStateDigest,
        ) {
            self.evidence.into_digests()
        }

        pub(super) fn was_minted_for(
            &self,
            instance_identity: &ReplayJournalInstanceIdentity,
        ) -> bool {
            self.evidence.was_minted_for(instance_identity)
        }
    }

    impl fmt::Debug for ReplayJournalMaintenanceAdvanceReceipt {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("ReplayJournalMaintenanceAdvanceReceipt { ..REDACTED.. }")
        }
    }

    pub(super) struct ReplayJournalCommittedAdvance {
        pub(super) result: ReplayCommitResult,
        pub(super) receipt: ReplayJournalAdvanceReceipt,
    }

    impl ReplayJournalCommittedAdvance {
        pub(super) fn into_parts(self) -> (ReplayCommitResult, ReplayJournalAdvanceReceipt) {
            (self.result, self.receipt)
        }
    }

    impl fmt::Debug for ReplayJournalCommittedAdvance {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("ReplayJournalCommittedAdvance { ..REDACTED.. }")
        }
    }

    impl<P> ReplayJournalStore<P>
    where
        P: ReplayJournalRecordProtector,
    {
        pub(super) fn commit_transaction_and_capture(
            &mut self,
            security_round: &SecurityRoundCapture,
            request_key: &RequestReplayKey,
            continuation_plan: &ContinuationReplayPlan,
        ) -> Result<ReplayJournalCommittedAdvance, ReplayJournalStoreError> {
            let previous_digest = self.state.component_state_digest();
            let prepared = self.prepare_commit(request_key, continuation_plan)?;
            let staged_entry = self.stage_entry_file(&prepared)?;
            let replaced_entry = self.replace_entry_file(staged_entry, &prepared)?;
            self.confirm_entry_file_durable(replaced_entry)?;
            let staged_current = match self.stage_current_state(&prepared.next_state) {
                Ok(staged_current) => staged_current,
                Err(error) => return Err(self.latch(error)),
            };
            let replaced_current = self.replace_current_state(staged_current)?;
            self.confirm_current_state_durable(replaced_current)?;
            let result = self.apply_prepared_commit_in_memory(security_round, prepared);
            let receipt = ReplayJournalAdvanceReceipt {
                evidence: ReplayJournalAdvanceEvidence::new(
                    self.instance_identity.clone(),
                    previous_digest,
                    self.state.component_state_digest(),
                ),
            };
            Ok(ReplayJournalCommittedAdvance { result, receipt })
        }

        pub(super) fn commit_prepared_maintenance_and_capture(
            &mut self,
            prepared: PreparedReplayMaintenanceAdvance,
        ) -> Result<ReplayJournalMaintenanceAdvanceReceipt, ReplayJournalStoreError> {
            if self.health == ReplayJournalStoreHealth::Indeterminate {
                return Err(ReplayJournalStoreError::LatchedIndeterminate);
            }
            if self.state.component_state_digest() != prepared.previous_digest {
                return Err(ReplayJournalStoreError::CurrentStateMismatch);
            }
            self.ensure_directories()?;
            let staged_current = self.stage_current_state(&prepared.next_state)?;
            let replaced_current = self.replace_current_state(staged_current)?;
            self.confirm_current_state_durable(replaced_current)?;
            self.state = prepared.next_state;
            Ok(ReplayJournalMaintenanceAdvanceReceipt {
                evidence: ReplayJournalAdvanceEvidence::new(
                    self.instance_identity.clone(),
                    prepared.previous_digest,
                    self.state.component_state_digest(),
                ),
            })
        }

        #[cfg(test)]
        pub(super) fn test_receipt_for_digests(
            &self,
            previous_digest: ReplayJournalComponentStateDigest,
            committed_digest: ReplayJournalComponentStateDigest,
        ) -> ReplayJournalAdvanceReceipt {
            ReplayJournalAdvanceReceipt {
                evidence: ReplayJournalAdvanceEvidence::new(
                    self.instance_identity.clone(),
                    previous_digest,
                    committed_digest,
                ),
            }
        }

        #[cfg(test)]
        pub(super) fn test_maintenance_receipt_for_digests(
            &self,
            previous_digest: ReplayJournalComponentStateDigest,
            committed_digest: ReplayJournalComponentStateDigest,
        ) -> ReplayJournalMaintenanceAdvanceReceipt {
            ReplayJournalMaintenanceAdvanceReceipt {
                evidence: ReplayJournalAdvanceEvidence::new(
                    self.instance_identity.clone(),
                    previous_digest,
                    committed_digest,
                ),
            }
        }
    }
}

use committed_advance::ReplayJournalInstanceIdentity;
pub(super) use committed_advance::{
    ReplayJournalAdvanceReceipt, ReplayJournalMaintenanceAdvanceReceipt,
};

struct StagedReplayJournalEntry {
    file: NamedTempFile,
}

struct ReplacedReplayJournalEntry {
    path: PathBuf,
}

struct StagedReplayJournalCurrentState {
    file: NamedTempFile,
}

struct ReplacedReplayJournalCurrentState;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReplayJournalStoreHealth {
    Ready,
    Indeterminate,
}

mod sealed {
    pub trait Sealed {}
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ReplayJournalComponentStateUnavailable;

impl fmt::Display for ReplayJournalComponentStateUnavailable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("replay journal component state is unavailable")
    }
}

impl std::error::Error for ReplayJournalComponentStateUnavailable {}

/// Supplies the current committed replay identity only while the store is ready.
pub(super) trait ReplayJournalComponentState: sealed::Sealed {
    fn component_state_digest(
        &self,
    ) -> Result<ReplayJournalComponentStateDigest, ReplayJournalComponentStateUnavailable>;

    fn recognizes_receipt(&self, receipt: &ReplayJournalAdvanceReceipt) -> bool;

    fn recognizes_maintenance_receipt(
        &self,
        receipt: &ReplayJournalMaintenanceAdvanceReceipt,
    ) -> bool;
}

pub(super) struct ReplayJournalStore<P> {
    recovery_directory: PathBuf,
    protection_context: ReplayJournalProtectionContext,
    protector: P,
    instance_identity: ReplayJournalInstanceIdentity,
    state: ReplayJournalState,
    // Both claim sets are plain hash sets, on purpose, even though this crate
    // otherwise buys fixed work. Three facts make a constant-time membership
    // scan the wrong trade here:
    //
    // 1. The verdict is not secret. A `RequestDuplicate` becomes
    //    `QueryOutcome::ProjectionNotReady` and a `ContinuationDuplicate`
    //    becomes `QueryOutcome::InvalidContinuation` in the response the same
    //    caller receives. A lookup-timing oracle would reveal only what the
    //    reply already states, and each lookup asks about the caller's own key
    //    -- never another caller's claim.
    // 2. The measurement would have to survive the commit it is embedded in.
    //    Every `commit_transaction_and_capture` stages, renames, and `fsync`s
    //    an entry file and the current-state file before returning; those
    //    durable steps dominate a probe-and-compare by several orders of
    //    magnitude, and they are identical on the fresh and duplicate paths
    //    (see `duplicate_cover_commit_matches_the_fresh_claim_durable_footprint`).
    // 3. Bucket placement is unpredictable anyway: keys are Blake2s256 digests
    //    over the session-bound namespace, and `RandomState` re-keys SipHash
    //    per process, so an attacker cannot aim probes at a chosen bucket.
    //
    // The obliviousness this module owes its callers is the durable record
    // shape -- fixed-size sealed bodies that hide lane tags and identities --
    // not in-process memory access. Oblivious memory remains an explicit
    // non-goal of this module (see the module docs). Revisit if the duplicate
    // verdict ever stops being visible in the response.
    request_claims: HashSet<[u8; REPLAY_RECORD_KEY_BYTES]>,
    continuation_claims: HashSet<[u8; REPLAY_RECORD_KEY_BYTES]>,
    health: ReplayJournalStoreHealth,
}

impl<P> sealed::Sealed for ReplayJournalStore<P> {}

impl<P> ReplayJournalComponentState for ReplayJournalStore<P> {
    fn component_state_digest(
        &self,
    ) -> Result<ReplayJournalComponentStateDigest, ReplayJournalComponentStateUnavailable> {
        match self.health {
            ReplayJournalStoreHealth::Ready => Ok(self.state.component_state_digest()),
            ReplayJournalStoreHealth::Indeterminate => Err(ReplayJournalComponentStateUnavailable),
        }
    }

    fn recognizes_receipt(&self, receipt: &ReplayJournalAdvanceReceipt) -> bool {
        receipt.was_minted_for(&self.instance_identity)
    }

    fn recognizes_maintenance_receipt(
        &self,
        receipt: &ReplayJournalMaintenanceAdvanceReceipt,
    ) -> bool {
        receipt.was_minted_for(&self.instance_identity)
    }
}

impl<P> ReplayJournalStore<P>
where
    P: ReplayJournalRecordProtector,
{
    pub(super) fn open(
        root: impl Into<PathBuf>,
        profile: &PrivacyProfile,
        protection_context: ReplayJournalProtectionContext,
        protector: P,
    ) -> Result<Self, ReplayJournalStoreError> {
        Self::open_with_limits(
            root,
            ReplayJournalLimits::from_compiled_policy(profile.replay_policy()),
            *profile.profile_id(),
            protection_context,
            protector,
        )
    }

    fn open_with_limits(
        root: impl Into<PathBuf>,
        limits: ReplayJournalLimits,
        expected_profile_id: [u8; PROFILE_ID_BYTES],
        protection_context: ReplayJournalProtectionContext,
        protector: P,
    ) -> Result<Self, ReplayJournalStoreError> {
        if all_zero(&expected_profile_id) {
            return Err(ReplayJournalStoreError::ConfigurationMismatch);
        }
        let recovery_directory = root.into();
        let instance_identity = ReplayJournalInstanceIdentity::new();
        validate_recovery_paths(&recovery_directory)?;
        let current_path = recovery_directory.join(CURRENT_STATE_FILE);
        let current_bytes = match read_exact_record::<CURRENT_RECORD_BYTES>(&current_path) {
            Ok(bytes) => bytes,
            Err(ExactRecordReadError::Missing) => {
                // `current.bin` is the sole local authority, so its absence is
                // the empty state even if a pre-commit candidate remains.
                // Distinguishing first initialization from marker deletion
                // requires the external freshness witness deferred by ADR 0009.
                return Ok(Self {
                    recovery_directory,
                    protection_context,
                    protector,
                    instance_identity,
                    state: ReplayJournalState::empty(limits, expected_profile_id),
                    request_claims: HashSet::new(),
                    continuation_claims: HashSet::new(),
                    health: ReplayJournalStoreHealth::Ready,
                });
            }
            Err(ExactRecordReadError::UnsafePath | ExactRecordReadError::WrongLength) => {
                return Err(ReplayJournalStoreError::CurrentStateCorrupt);
            }
            Err(ExactRecordReadError::Unreadable) => {
                return Err(ReplayJournalStoreError::CurrentStateUnreadable);
            }
        };
        let persisted_state = PersistentReplayJournalCurrentStateV3(current_bytes)
            .into_business(&protection_context, &protector);
        let persisted_state = match persisted_state {
            Ok(state) => state,
            Err(ReplayJournalRecordError::AuthenticationFailed) => {
                return Err(ReplayJournalStoreError::CurrentStateAuthenticationFailed);
            }
            Err(ReplayJournalRecordError::ProtectionUnavailable) => {
                return Err(ReplayJournalStoreError::CurrentStateProtectionUnavailable);
            }
            Err(_) => return Err(ReplayJournalStoreError::CurrentStateCorrupt),
        };
        if persisted_state.limits != limits || persisted_state.profile_id != expected_profile_id {
            return Err(ReplayJournalStoreError::ConfigurationMismatch);
        }

        let entries_directory = recovery_directory.join(ENTRIES_DIRECTORY);
        validate_committed_entries_directory(&entries_directory)?;
        let mut state = ReplayJournalState::empty(limits, expected_profile_id);
        let mut request_claims = HashSet::new();
        let mut continuation_claims = HashSet::new();
        // Recovery rebuilds both exact claim sets from the complete authoritative
        // prefix. Deleting a committed entry is therefore unsafe until a new
        // authenticated base/checkpoint format replaces this invariant.
        for expected_sequence in 1..=persisted_state.committed_sequence {
            let entry = load_authoritative_entry(
                &entries_directory,
                expected_sequence,
                &protection_context,
                &protector,
            )?;
            let (next, _) = state
                .apply_entry(&mut request_claims, &mut continuation_claims, &entry)
                .map_err(|_| ReplayJournalStoreError::CommittedEntryCorrupt)?;
            state = next;
        }
        state.maintenance_expiry_bucket_watermark =
            persisted_state.maintenance_expiry_bucket_watermark;
        if state != persisted_state {
            return Err(ReplayJournalStoreError::CurrentStateMismatch);
        }
        Ok(Self {
            recovery_directory,
            protection_context,
            protector,
            instance_identity,
            state,
            request_claims,
            continuation_claims,
            health: ReplayJournalStoreHealth::Ready,
        })
    }

    fn entries_directory(&self) -> PathBuf {
        self.recovery_directory.join(ENTRIES_DIRECTORY)
    }

    fn staging_directory(&self) -> PathBuf {
        self.recovery_directory.join(STAGING_DIRECTORY)
    }

    fn current_path(&self) -> PathBuf {
        self.recovery_directory.join(CURRENT_STATE_FILE)
    }

    fn entry_path(&self, sequence: u64) -> PathBuf {
        self.entries_directory().join(entry_filename(sequence))
    }

    fn prepare_commit(
        &self,
        request_key: &RequestReplayKey,
        continuation_plan: &ContinuationReplayPlan,
    ) -> Result<PreparedReplayJournalCommit, ReplayJournalStoreError> {
        if self.health == ReplayJournalStoreHealth::Indeterminate {
            return Err(ReplayJournalStoreError::LatchedIndeterminate);
        }
        let sequence = self
            .state
            .committed_sequence
            .checked_add(1)
            .ok_or(ReplayJournalStoreError::SequenceOverflow)?;
        if sequence > self.state.limits.max_transactions {
            return Err(ReplayJournalStoreError::TransactionCapacityExceeded);
        }
        let request_key = *request_key.as_bytes();
        let (continuation_lane, decision) = if self.request_claims.contains(&request_key) {
            (
                ReplayJournalContinuationLane::Cover,
                ReplayDuplicateDecision::RequestDuplicate,
            )
        } else {
            match continuation_plan {
                ContinuationReplayPlan::Cover => (
                    ReplayJournalContinuationLane::Cover,
                    ReplayDuplicateDecision::Fresh,
                ),
                ContinuationReplayPlan::ClaimOrCover(claim) => {
                    let key = *claim.replay_key_bytes();
                    if self.continuation_claims.contains(&key) {
                        (
                            ReplayJournalContinuationLane::Cover,
                            ReplayDuplicateDecision::ContinuationDuplicate,
                        )
                    } else {
                        (
                            ReplayJournalContinuationLane::Claim {
                                key,
                                expiry_bucket_ordinal: claim.expiry_bucket_ordinal(),
                            },
                            ReplayDuplicateDecision::Fresh,
                        )
                    }
                }
            }
        };
        let entry = ReplayJournalEntry {
            sequence,
            request_key,
            continuation_lane,
        };
        let (next_state, delta, _) = self
            .state
            .preview_entry(&self.request_claims, &self.continuation_claims, &entry)
            .map_err(map_prepare_transition_error)?;
        Ok(PreparedReplayJournalCommit {
            entry,
            next_state,
            delta,
            decision,
        })
    }

    fn prepare_maintenance_watermark(
        &self,
        watermark: ReplayMaintenanceWatermark,
    ) -> Result<ReplayMaintenancePreparation, ReplayJournalStoreError> {
        if self.health == ReplayJournalStoreHealth::Indeterminate {
            return Err(ReplayJournalStoreError::LatchedIndeterminate);
        }
        let Some(next_state) = self.state.preview_maintenance_watermark(watermark)? else {
            return Ok(ReplayMaintenancePreparation::NoAdvance);
        };
        Ok(ReplayMaintenancePreparation::Advance(
            PreparedReplayMaintenanceAdvance {
                previous_digest: self.state.component_state_digest(),
                next_state,
            },
        ))
    }

    fn ensure_directories(&self) -> Result<(), ReplayJournalStoreError> {
        ensure_real_directory(&self.recovery_directory).map_err(map_directory_error)?;
        ensure_real_directory(&self.entries_directory()).map_err(map_directory_error)?;
        ensure_real_directory(&self.staging_directory()).map_err(map_directory_error)?;
        if let Some(parent) = self
            .recovery_directory
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            sync_directory(parent).map_err(|_| ReplayJournalStoreError::LocalStageUnavailable)?;
        }
        sync_directory(&self.recovery_directory)
            .and_then(|()| sync_directory(&self.entries_directory()))
            .and_then(|()| sync_directory(&self.staging_directory()))
            .map_err(|_| ReplayJournalStoreError::LocalStageUnavailable)
    }

    fn stage_entry_file(
        &self,
        prepared: &PreparedReplayJournalCommit,
    ) -> Result<StagedReplayJournalEntry, ReplayJournalStoreError> {
        self.ensure_directories()?;
        let persistent = PersistentReplayJournalEntry::from_business(
            &prepared.entry,
            &self.protection_context,
            &self.protector,
        )
        .map_err(map_entry_record_for_commit)?;
        let mut file = create_unique_file(&self.staging_directory(), "replay-entry")
            .map_err(|_| ReplayJournalStoreError::LocalStageUnavailable)?;
        file.write_all(persistent.as_bytes())
            .and_then(|()| file.as_file().sync_all())
            .map_err(|_| ReplayJournalStoreError::LocalStageUnavailable)?;
        Ok(StagedReplayJournalEntry { file })
    }

    fn replace_entry_file(
        &mut self,
        staged: StagedReplayJournalEntry,
        prepared: &PreparedReplayJournalCommit,
    ) -> Result<ReplacedReplayJournalEntry, ReplayJournalStoreError> {
        let final_path = self.entry_path(prepared.entry.sequence);
        if fs::rename(staged.file.path(), &final_path).is_err() {
            return Err(self.latch(ReplayJournalStoreError::CandidateStateIndeterminate));
        }
        drop(staged);
        Ok(ReplacedReplayJournalEntry { path: final_path })
    }

    fn confirm_entry_file_durable(
        &mut self,
        replaced: ReplacedReplayJournalEntry,
    ) -> Result<(), ReplayJournalStoreError> {
        if File::open(replaced.path)
            .and_then(|file| file.sync_all())
            .and_then(|()| sync_directory(&self.entries_directory()))
            .and_then(|()| sync_directory(&self.staging_directory()))
            .is_err()
        {
            return Err(self.latch(ReplayJournalStoreError::CandidateStateIndeterminate));
        }
        Ok(())
    }

    fn stage_current_state(
        &self,
        next_state: &ReplayJournalState,
    ) -> Result<StagedReplayJournalCurrentState, ReplayJournalStoreError> {
        let persistent = PersistentReplayJournalCurrentStateV3::from_business(
            next_state,
            &self.protection_context,
            &self.protector,
        )
        .map_err(map_current_record_for_commit)?;
        let mut file = create_unique_file(&self.staging_directory(), "replay-current")
            .map_err(|_| ReplayJournalStoreError::LocalStageUnavailable)?;
        file.write_all(persistent.as_bytes())
            .and_then(|()| file.as_file().sync_all())
            .map_err(|_| ReplayJournalStoreError::LocalStageUnavailable)?;
        Ok(StagedReplayJournalCurrentState { file })
    }

    fn replace_current_state(
        &mut self,
        staged: StagedReplayJournalCurrentState,
    ) -> Result<ReplacedReplayJournalCurrentState, ReplayJournalStoreError> {
        if fs::rename(staged.file.path(), self.current_path()).is_err() {
            return Err(self.latch(ReplayJournalStoreError::CurrentStateIndeterminate));
        }
        drop(staged);
        Ok(ReplacedReplayJournalCurrentState)
    }

    fn confirm_current_state_durable(
        &mut self,
        _replaced: ReplacedReplayJournalCurrentState,
    ) -> Result<(), ReplayJournalStoreError> {
        if sync_directory(&self.recovery_directory).is_err()
            || sync_directory(&self.staging_directory()).is_err()
        {
            return Err(self.latch(ReplayJournalStoreError::CurrentStateIndeterminate));
        }
        Ok(())
    }

    fn apply_prepared_commit_in_memory(
        &mut self,
        security_round: &SecurityRoundCapture,
        prepared: PreparedReplayJournalCommit,
    ) -> ReplayCommitResult {
        if let Some(key) = prepared.delta.insert_request {
            self.request_claims.insert(key);
        }
        if let Some(key) = prepared.delta.insert_continuation {
            self.continuation_claims.insert(key);
        }
        self.state = prepared.next_state;
        ReplayCommitResult::new(
            ReplayCommitAuthority::new(security_round),
            prepared.decision,
        )
    }

    fn commit_transaction(
        &mut self,
        security_round: &SecurityRoundCapture,
        request_key: &RequestReplayKey,
        continuation_plan: &ContinuationReplayPlan,
    ) -> Result<ReplayCommitResult, ReplayJournalStoreError> {
        let (result, _receipt) = self
            .commit_transaction_and_capture(security_round, request_key, continuation_plan)?
            .into_parts();
        Ok(result)
    }

    fn latch(&mut self, error: ReplayJournalStoreError) -> ReplayJournalStoreError {
        self.health = ReplayJournalStoreHealth::Indeterminate;
        error
    }
}

impl<P> ContinuationReplayGuard for ReplayJournalStore<P>
where
    P: ReplayJournalRecordProtector,
{
    fn commit_request_and_continuation(
        &mut self,
        security_round: &SecurityRoundCapture,
        request_key: &RequestReplayKey,
        continuation_plan: &ContinuationReplayPlan,
    ) -> Result<ReplayCommitResult, ReplayCommitUnavailable> {
        self.commit_transaction(security_round, request_key, continuation_plan)
            .map_err(|_| ReplayCommitUnavailable)
    }
}

/// Module-local owner of one replay journal and its exact outer snapshot.
///
/// This is a fail-closed coordination protocol, not an atomic transaction
/// across the journal, local snapshot, and external freshness witness. Once a
/// replay commit succeeds, any unresolved outer advance latches this instance
/// indeterminate and withholds the replay authority. It coordinates only
/// request-triggered replay commits and private maintenance-watermark advances.
/// It supplies no trusted maintenance authority or non-test maintenance caller.
struct ReplaySnapshotCoordinator<P, W> {
    replay_journal: ReplayJournalStore<P>,
    security_state: SecurityStateStore<W>,
    current_snapshot: SecurityStateSnapshot,
    health: ReplaySnapshotCoordinatorHealth,
}

struct ReplaySnapshotInitialState {
    identity: SecurityStateIdentity,
    serving_identity_digest: [u8; STATE_DIGEST_BYTES],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReplaySnapshotCoordinatorHealth {
    Ready,
    Indeterminate,
}

impl<P, W> ReplaySnapshotCoordinator<P, W>
where
    P: ReplayJournalRecordProtector,
    W: SecurityFreshnessWitness,
{
    /// Opens only a previously provisioned pair that matches exactly.
    fn open_existing(
        replay_root: impl Into<PathBuf>,
        security_state_root: impl Into<PathBuf>,
        profile: &PrivacyProfile,
        protection_context: ReplayJournalProtectionContext,
        protector: P,
        witness: W,
    ) -> Result<Self, ReplaySnapshotCoordinatorOpenError> {
        let mut security_state = SecurityStateStore::new(security_state_root, witness);
        let current_snapshot = security_state
            .current()
            .map_err(ReplaySnapshotCoordinatorOpenError::SecurityState)?
            .ok_or(ReplaySnapshotCoordinatorOpenError::OuterSnapshotMissing)?;
        if current_snapshot.profile_id() != profile.profile_id() {
            return Err(ReplaySnapshotCoordinatorOpenError::ProfileIdentityMismatch);
        }
        let replay_journal =
            ReplayJournalStore::open(replay_root, profile, protection_context, protector)
                .map_err(ReplaySnapshotCoordinatorOpenError::ReplayJournal)?;
        verify_current(&current_snapshot, &replay_journal)
            .map_err(ReplaySnapshotCoordinatorOpenError::SnapshotBinding)?;

        Ok(Self {
            replay_journal,
            security_state,
            current_snapshot,
            health: ReplaySnapshotCoordinatorHealth::Ready,
        })
    }

    /// Explicitly provisions an absent outer snapshot for the current journal.
    fn provision_initial(
        replay_root: impl Into<PathBuf>,
        security_state_root: impl Into<PathBuf>,
        profile: &PrivacyProfile,
        protection_context: ReplayJournalProtectionContext,
        protector: P,
        witness: W,
        initial_state: ReplaySnapshotInitialState,
    ) -> Result<Self, ReplaySnapshotCoordinatorOpenError> {
        if initial_state.identity.profile_id() != profile.profile_id() {
            return Err(ReplaySnapshotCoordinatorOpenError::ProfileIdentityMismatch);
        }
        let replay_journal =
            ReplayJournalStore::open(replay_root, profile, protection_context, protector)
                .map_err(ReplaySnapshotCoordinatorOpenError::ReplayJournal)?;
        let mut security_state = SecurityStateStore::new(security_state_root, witness);
        if security_state
            .current()
            .map_err(ReplaySnapshotCoordinatorOpenError::SecurityState)?
            .is_some()
        {
            return Err(ReplaySnapshotCoordinatorOpenError::OuterSnapshotAlreadyProvisioned);
        }

        let current_snapshot = provision_initial_snapshot(
            initial_state.identity,
            initial_state.serving_identity_digest,
            &replay_journal,
        )
        .map_err(ReplaySnapshotCoordinatorOpenError::SnapshotBinding)?;
        security_state
            .compare_and_advance(None, current_snapshot)
            .map_err(ReplaySnapshotCoordinatorOpenError::SecurityState)?;

        Ok(Self {
            replay_journal,
            security_state,
            current_snapshot,
            health: ReplaySnapshotCoordinatorHealth::Ready,
        })
    }

    fn commit_request_and_snapshot(
        &mut self,
        security_round: &SecurityRoundCapture,
        request_key: &RequestReplayKey,
        continuation_plan: &ContinuationReplayPlan,
    ) -> Result<ReplayCommitResult, ReplaySnapshotCoordinatorCommitError> {
        if self.health == ReplaySnapshotCoordinatorHealth::Indeterminate {
            return Err(ReplaySnapshotCoordinatorCommitError::LatchedIndeterminate);
        }

        preflight_successor(&self.current_snapshot)
            .map_err(ReplaySnapshotCoordinatorCommitError::OuterAdvancePreflight)?;

        let committed = match self.replay_journal.commit_transaction_and_capture(
            security_round,
            request_key,
            continuation_plan,
        ) {
            Ok(committed) => committed,
            Err(error) => {
                if self.replay_journal.health == ReplayJournalStoreHealth::Indeterminate {
                    self.health = ReplaySnapshotCoordinatorHealth::Indeterminate;
                }
                return Err(ReplaySnapshotCoordinatorCommitError::ReplayJournal(error));
            }
        };

        let next_snapshot = match successor_after_replay_commit(
            &self.current_snapshot,
            committed.receipt,
            &self.replay_journal,
        ) {
            Ok(next_snapshot) => next_snapshot,
            Err(error) => {
                self.latch_after_replay();
                return Err(
                    ReplaySnapshotCoordinatorCommitError::OuterAdvanceAfterReplay(
                        ReplaySnapshotCoordinatorOuterAdvanceError::SnapshotBinding(error),
                    ),
                );
            }
        };
        if let Err(error) = self
            .security_state
            .compare_and_advance(Some(self.current_snapshot), next_snapshot)
        {
            self.latch_after_replay();
            return Err(
                ReplaySnapshotCoordinatorCommitError::OuterAdvanceAfterReplay(
                    ReplaySnapshotCoordinatorOuterAdvanceError::SecurityState(error),
                ),
            );
        }

        self.current_snapshot = next_snapshot;
        Ok(committed.result)
    }

    /// Advances only journal-local maintenance metadata.
    ///
    /// This stays private and has no non-test caller. Any future visibility
    /// widening or runtime wiring must replace the raw watermark with a
    /// move-only grant bound to a live epoch, profile, and currentness proof.
    fn commit_maintenance_watermark(
        &mut self,
        watermark: ReplayMaintenanceWatermark,
    ) -> Result<
        ReplaySnapshotCoordinatorMaintenanceOutcome,
        ReplaySnapshotCoordinatorMaintenanceError,
    > {
        if self.health == ReplaySnapshotCoordinatorHealth::Indeterminate {
            return Err(ReplaySnapshotCoordinatorMaintenanceError::LatchedIndeterminate);
        }

        let prepared = self
            .replay_journal
            .prepare_maintenance_watermark(watermark)
            .map_err(ReplaySnapshotCoordinatorMaintenanceError::ReplayJournal)?;
        let ReplayMaintenancePreparation::Advance(prepared) = prepared else {
            return Ok(ReplaySnapshotCoordinatorMaintenanceOutcome::NoAdvance);
        };

        preflight_successor(&self.current_snapshot)
            .map_err(ReplaySnapshotCoordinatorMaintenanceError::OuterAdvancePreflight)?;

        let receipt = match self
            .replay_journal
            .commit_prepared_maintenance_and_capture(prepared)
        {
            Ok(receipt) => receipt,
            Err(error) => {
                if self.replay_journal.health == ReplayJournalStoreHealth::Indeterminate {
                    self.health = ReplaySnapshotCoordinatorHealth::Indeterminate;
                }
                return Err(ReplaySnapshotCoordinatorMaintenanceError::ReplayJournal(
                    error,
                ));
            }
        };

        let next_snapshot = match successor_after_replay_maintenance(
            &self.current_snapshot,
            receipt,
            &self.replay_journal,
        ) {
            Ok(next_snapshot) => next_snapshot,
            Err(error) => {
                self.latch_after_replay();
                return Err(
                    ReplaySnapshotCoordinatorMaintenanceError::OuterAdvanceAfterReplay(
                        ReplaySnapshotCoordinatorOuterAdvanceError::SnapshotBinding(error),
                    ),
                );
            }
        };
        if let Err(error) = self
            .security_state
            .compare_and_advance(Some(self.current_snapshot), next_snapshot)
        {
            self.latch_after_replay();
            return Err(
                ReplaySnapshotCoordinatorMaintenanceError::OuterAdvanceAfterReplay(
                    ReplaySnapshotCoordinatorOuterAdvanceError::SecurityState(error),
                ),
            );
        }

        self.current_snapshot = next_snapshot;
        Ok(ReplaySnapshotCoordinatorMaintenanceOutcome::Advanced)
    }

    fn latch_after_replay(&mut self) {
        self.health = ReplaySnapshotCoordinatorHealth::Indeterminate;
    }
}

impl<P, W> ContinuationReplayGuard for ReplaySnapshotCoordinator<P, W>
where
    P: ReplayJournalRecordProtector,
    W: SecurityFreshnessWitness,
{
    fn commit_request_and_continuation(
        &mut self,
        security_round: &SecurityRoundCapture,
        request_key: &RequestReplayKey,
        continuation_plan: &ContinuationReplayPlan,
    ) -> Result<ReplayCommitResult, ReplayCommitUnavailable> {
        self.commit_request_and_snapshot(security_round, request_key, continuation_plan)
            .map_err(|_| ReplayCommitUnavailable)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReplaySnapshotCoordinatorOpenError {
    ReplayJournal(ReplayJournalStoreError),
    SecurityState(SecurityStateStoreError),
    OuterSnapshotMissing,
    OuterSnapshotAlreadyProvisioned,
    ProfileIdentityMismatch,
    SnapshotBinding(SecurityStateBindingError),
}

impl fmt::Display for ReplaySnapshotCoordinatorOpenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReplayJournal(_) => f.write_str("replay journal could not be opened"),
            Self::SecurityState(_) => f.write_str("outer security state could not be reconciled"),
            Self::OuterSnapshotMissing => {
                f.write_str("outer security snapshot has not been provisioned")
            }
            Self::OuterSnapshotAlreadyProvisioned => {
                f.write_str("outer security snapshot is already provisioned")
            }
            Self::ProfileIdentityMismatch => {
                f.write_str("outer security snapshot does not match the compiled privacy profile")
            }
            Self::SnapshotBinding(_) => {
                f.write_str("outer security snapshot does not match the replay journal")
            }
        }
    }
}

impl std::error::Error for ReplaySnapshotCoordinatorOpenError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ReplayJournal(error) => Some(error),
            Self::SecurityState(error) => Some(error),
            Self::SnapshotBinding(error) => Some(error),
            Self::OuterSnapshotMissing
            | Self::OuterSnapshotAlreadyProvisioned
            | Self::ProfileIdentityMismatch => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReplaySnapshotCoordinatorCommitError {
    LatchedIndeterminate,
    OuterAdvancePreflight(SecurityStateBindingError),
    ReplayJournal(ReplayJournalStoreError),
    OuterAdvanceAfterReplay(ReplaySnapshotCoordinatorOuterAdvanceError),
}

impl fmt::Display for ReplaySnapshotCoordinatorCommitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LatchedIndeterminate => {
                f.write_str("replay snapshot coordinator is indeterminate")
            }
            Self::OuterAdvancePreflight(_) => f.write_str("outer security snapshot cannot advance"),
            Self::ReplayJournal(_) => f.write_str("replay journal commit failed"),
            Self::OuterAdvanceAfterReplay(_) => {
                f.write_str("outer security-state advance failed after replay commit")
            }
        }
    }
}

impl std::error::Error for ReplaySnapshotCoordinatorCommitError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::OuterAdvancePreflight(error) => Some(error),
            Self::ReplayJournal(error) => Some(error),
            Self::OuterAdvanceAfterReplay(error) => Some(error),
            Self::LatchedIndeterminate => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReplaySnapshotCoordinatorMaintenanceError {
    LatchedIndeterminate,
    OuterAdvancePreflight(SecurityStateBindingError),
    ReplayJournal(ReplayJournalStoreError),
    OuterAdvanceAfterReplay(ReplaySnapshotCoordinatorOuterAdvanceError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReplaySnapshotCoordinatorMaintenanceOutcome {
    NoAdvance,
    Advanced,
}

impl fmt::Display for ReplaySnapshotCoordinatorMaintenanceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LatchedIndeterminate => {
                f.write_str("replay snapshot coordinator is indeterminate")
            }
            Self::OuterAdvancePreflight(_) => f.write_str("outer security snapshot cannot advance"),
            Self::ReplayJournal(_) => f.write_str("replay maintenance watermark advance failed"),
            Self::OuterAdvanceAfterReplay(_) => {
                f.write_str("outer security-state advance failed after replay maintenance")
            }
        }
    }
}

impl std::error::Error for ReplaySnapshotCoordinatorMaintenanceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::OuterAdvancePreflight(error) => Some(error),
            Self::ReplayJournal(error) => Some(error),
            Self::OuterAdvanceAfterReplay(error) => Some(error),
            Self::LatchedIndeterminate => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReplaySnapshotCoordinatorOuterAdvanceError {
    SnapshotBinding(SecurityStateBindingError),
    SecurityState(SecurityStateStoreError),
}

impl fmt::Display for ReplaySnapshotCoordinatorOuterAdvanceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SnapshotBinding(_) => {
                f.write_str("replay transition receipt did not match the outer snapshot")
            }
            Self::SecurityState(_) => f.write_str("outer security-state transition is unresolved"),
        }
    }
}

impl std::error::Error for ReplaySnapshotCoordinatorOuterAdvanceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::SnapshotBinding(error) => Some(error),
            Self::SecurityState(error) => Some(error),
        }
    }
}

impl<P> fmt::Debug for ReplayJournalStore<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReplayJournalStore")
            .field("recovery_directory", &self.recovery_directory)
            .field("protector", &"..REDACTED..")
            .field("state", &"..REDACTED..")
            .field("request_claims", &"..REDACTED..")
            .field("continuation_claims", &"..REDACTED..")
            .field("health", &self.health)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ReplayJournalStoreError {
    LatchedIndeterminate,
    UnsafeRecoveryPath,
    ConfigurationMismatch,
    CurrentStateUnreadable,
    CurrentStateCorrupt,
    CurrentStateAuthenticationFailed,
    CurrentStateProtectionUnavailable,
    CommittedEntryMissing,
    CommittedEntryUnreadable,
    CommittedEntryCorrupt,
    CommittedEntryAuthenticationFailed,
    CommittedEntryProtectionUnavailable,
    CurrentStateMismatch,
    TransactionCapacityExceeded,
    SequenceOverflow,
    MaintenanceWatermarkRegressed,
    LocalStageUnavailable,
    CandidateStateIndeterminate,
    CurrentStateIndeterminate,
}

impl fmt::Display for ReplayJournalStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("replay journal is unavailable")
    }
}

impl std::error::Error for ReplayJournalStoreError {}

#[derive(Clone, Copy)]
enum ExactRecordReadError {
    Missing,
    UnsafePath,
    Unreadable,
    WrongLength,
}

fn validate_header<const N: usize>(
    bytes: &[u8; N],
    expected_magic: [u8; RECORD_MAGIC_BYTES],
    expected_version: u16,
) -> Result<(), ReplayJournalRecordError> {
    if bytes[..RECORD_MAGIC_BYTES] != expected_magic {
        return Err(ReplayJournalRecordError::InvalidMagic);
    }
    if read_u16(bytes, RECORD_MAGIC_BYTES) != expected_version {
        return Err(ReplayJournalRecordError::UnsupportedVersion);
    }
    Ok(())
}

fn validate_recovery_paths(root: &Path) -> Result<(), ReplayJournalStoreError> {
    match fs::symlink_metadata(root) {
        Ok(metadata) if metadata.file_type().is_dir() => {}
        Ok(_) => return Err(ReplayJournalStoreError::UnsafeRecoveryPath),
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(ReplayJournalStoreError::UnsafeRecoveryPath),
    }
    validate_optional_directory(&root.join(ENTRIES_DIRECTORY))?;
    validate_optional_directory(&root.join(STAGING_DIRECTORY))?;
    let current = root.join(CURRENT_STATE_FILE);
    match fs::symlink_metadata(current) {
        Ok(metadata) if metadata.file_type().is_file() => Ok(()),
        Ok(_) => Err(ReplayJournalStoreError::UnsafeRecoveryPath),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(ReplayJournalStoreError::UnsafeRecoveryPath),
    }
}

fn validate_optional_directory(path: &Path) -> Result<(), ReplayJournalStoreError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_dir() => Ok(()),
        Ok(_) => Err(ReplayJournalStoreError::UnsafeRecoveryPath),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(ReplayJournalStoreError::UnsafeRecoveryPath),
    }
}

fn validate_committed_entries_directory(
    entries_directory: &Path,
) -> Result<(), ReplayJournalStoreError> {
    let metadata = fs::symlink_metadata(entries_directory)
        .map_err(|_| ReplayJournalStoreError::CommittedEntryMissing)?;
    if !metadata.file_type().is_dir() {
        return Err(ReplayJournalStoreError::UnsafeRecoveryPath);
    }
    Ok(())
}

fn load_authoritative_entry<P>(
    entries_directory: &Path,
    expected_sequence: u64,
    context: &ReplayJournalProtectionContext,
    protector: &P,
) -> Result<ReplayJournalEntry, ReplayJournalStoreError>
where
    P: ReplayJournalRecordProtector,
{
    let path = entries_directory.join(entry_filename(expected_sequence));
    let bytes = match read_exact_record::<ENTRY_RECORD_BYTES>(&path) {
        Ok(bytes) => bytes,
        Err(ExactRecordReadError::Missing) => {
            return Err(ReplayJournalStoreError::CommittedEntryMissing);
        }
        Err(ExactRecordReadError::Unreadable) => {
            return Err(ReplayJournalStoreError::CommittedEntryUnreadable);
        }
        Err(ExactRecordReadError::UnsafePath | ExactRecordReadError::WrongLength) => {
            return Err(ReplayJournalStoreError::CommittedEntryCorrupt);
        }
    };
    let entry = match PersistentReplayJournalEntry(bytes).into_business(context, protector) {
        Ok(entry) => entry,
        Err(ReplayJournalRecordError::AuthenticationFailed) => {
            return Err(ReplayJournalStoreError::CommittedEntryAuthenticationFailed);
        }
        Err(ReplayJournalRecordError::ProtectionUnavailable) => {
            return Err(ReplayJournalStoreError::CommittedEntryProtectionUnavailable);
        }
        Err(_) => return Err(ReplayJournalStoreError::CommittedEntryCorrupt),
    };
    if entry.sequence != expected_sequence {
        return Err(ReplayJournalStoreError::CommittedEntryCorrupt);
    }
    Ok(entry)
}

fn entry_filename(sequence: u64) -> String {
    format!("{sequence:020}{ENTRY_FILE_SUFFIX}")
}

fn read_exact_record<const N: usize>(path: &Path) -> Result<[u8; N], ExactRecordReadError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Err(ExactRecordReadError::Missing);
        }
        Err(_) => return Err(ExactRecordReadError::Unreadable),
    };
    if !metadata.file_type().is_file() {
        return Err(ExactRecordReadError::UnsafePath);
    }
    let mut file = File::open(path).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            ExactRecordReadError::Missing
        } else {
            ExactRecordReadError::Unreadable
        }
    })?;
    let mut bytes = [0; N];
    match file.read_exact(&mut bytes) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
            return Err(ExactRecordReadError::WrongLength);
        }
        Err(_) => return Err(ExactRecordReadError::Unreadable),
    }
    let mut trailing = [0; 1];
    match file.read(&mut trailing) {
        Ok(0) => Ok(bytes),
        Ok(_) => Err(ExactRecordReadError::WrongLength),
        Err(_) => Err(ExactRecordReadError::Unreadable),
    }
}

fn map_directory_error(error: RealDirectoryError) -> ReplayJournalStoreError {
    match error {
        RealDirectoryError::UnsafePath => ReplayJournalStoreError::UnsafeRecoveryPath,
        RealDirectoryError::Io(_) => ReplayJournalStoreError::LocalStageUnavailable,
    }
}

fn map_prepare_transition_error(error: ReplayJournalTransitionError) -> ReplayJournalStoreError {
    match error {
        ReplayJournalTransitionError::TransactionCapacityExceeded => {
            ReplayJournalStoreError::TransactionCapacityExceeded
        }
        ReplayJournalTransitionError::SequenceOverflow => ReplayJournalStoreError::SequenceOverflow,
        ReplayJournalTransitionError::InvalidSequence
        | ReplayJournalTransitionError::InvalidDuplicateRequestLane
        | ReplayJournalTransitionError::InvalidDuplicateContinuationLane
        | ReplayJournalTransitionError::InconsistentClaimSet => {
            ReplayJournalStoreError::CurrentStateMismatch
        }
    }
}

fn map_current_record_for_commit(error: ReplayJournalRecordError) -> ReplayJournalStoreError {
    match error {
        ReplayJournalRecordError::ProtectionUnavailable => {
            ReplayJournalStoreError::CurrentStateProtectionUnavailable
        }
        _ => ReplayJournalStoreError::CurrentStateCorrupt,
    }
}

fn map_entry_record_for_commit(error: ReplayJournalRecordError) -> ReplayJournalStoreError {
    match error {
        ReplayJournalRecordError::ProtectionUnavailable => {
            ReplayJournalStoreError::CommittedEntryProtectionUnavailable
        }
        _ => ReplayJournalStoreError::CommittedEntryCorrupt,
    }
}

fn versioned_digest(domain: &[u8], version: u16, parts: &[&[u8]]) -> [u8; DIGEST_BYTES] {
    let mut hasher = Blake2s256::new();
    Digest::update(&mut hasher, domain);
    Digest::update(&mut hasher, version.to_be_bytes());
    for part in parts {
        Digest::update(&mut hasher, part);
    }
    Digest::finalize(hasher).into()
}

fn all_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

fn read_u16(bytes: &[u8], start: usize) -> u16 {
    u16::from_be_bytes(read_array(bytes, start))
}

fn read_u64(bytes: &[u8], start: usize) -> u64 {
    u64::from_be_bytes(read_array(bytes, start))
}

fn read_array<const N: usize>(bytes: &[u8], start: usize) -> [u8; N] {
    let mut value = [0; N];
    value.copy_from_slice(&bytes[start..start + N]);
    value
}

#[cfg(test)]
mod tests {
    use std::{cell::Cell, error::Error, fs, path::Path, rc::Rc};

    use tempfile::TempDir;

    use super::*;
    use crate::{
        continuation_token::ContinuationReplayClaim,
        inner_codec::{
            security_state_binding::{
                provision_initial_snapshot, successor_after_replay_commit,
                successor_after_replay_maintenance, verify_current, SecurityStateBindingError,
            },
            security_state_store::{
                test_security_state_identity, test_security_state_identity_with_profile_id,
                PersistentSecurityState, SecurityFreshness, SecurityStateValueError,
                STATE_DIGEST_BYTES,
            },
        },
        profile::test_profile_without_recent_snapshot,
        runtime_security::{ContinuationReplayKey, ReplayNamespace, SecurityEpochTag},
    };

    const TEST_PROTECTION_NONCE_BYTES: usize = 24;
    const TEST_PROTECTION_AUTHENTICATION_BYTES: usize = 16;
    const TEST_NONCE_DOMAIN: &[u8] = b"zaino-oram/replay-journal/test-nonce";
    const TEST_STREAM_DOMAIN: &[u8] = b"zaino-oram/replay-journal/test-stream";
    const TEST_AUTHENTICATION_DOMAIN: &[u8] = b"zaino-oram/replay-journal/test-authentication";
    const TEST_KEY: [u8; DIGEST_BYTES] = [0x91; DIGEST_BYTES];

    type TestResult = Result<(), Box<dyn Error>>;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum CoordinatorWitnessError {
        Conflict,
        Rejected,
        InvalidTransition,
        AdvanceUnresolved,
    }

    impl fmt::Display for CoordinatorWitnessError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("coordinator witness rejected the transition")
        }
    }

    impl Error for CoordinatorWitnessError {}

    #[derive(Clone)]
    struct CoordinatorWitness {
        state: Rc<Cell<Option<SecurityFreshness>>>,
        reject_advance: Rc<Cell<bool>>,
        advance_then_fail: Rc<Cell<bool>>,
    }

    impl CoordinatorWitness {
        fn empty() -> Self {
            Self {
                state: Rc::new(Cell::new(None)),
                reject_advance: Rc::new(Cell::new(false)),
                advance_then_fail: Rc::new(Cell::new(false)),
            }
        }

        fn set_reject_advance(&self, reject: bool) {
            self.reject_advance.set(reject);
        }

        fn set_advance_then_fail(&self) {
            self.advance_then_fail.set(true);
        }
    }

    impl SecurityFreshnessWitness for CoordinatorWitness {
        type Error = CoordinatorWitnessError;

        fn current(&mut self) -> Result<Option<SecurityFreshness>, Self::Error> {
            Ok(self.state.get())
        }

        fn compare_and_advance(
            &mut self,
            expected: Option<SecurityFreshness>,
            next: SecurityFreshness,
        ) -> Result<(), Self::Error> {
            if self.reject_advance.get() {
                return Err(CoordinatorWitnessError::Rejected);
            }
            if self.state.get() != expected {
                return Err(CoordinatorWitnessError::Conflict);
            }
            // A real authority admits only `None -> 1` and exact `n -> n + 1`.
            // Without this the double would accept sequences the coordinator
            // could never observe in production, and coordinator tests would
            // be passing over transitions no conforming witness allows.
            let valid_sequence = match expected {
                None => next.test_sequence() == 1,
                Some(current) => current
                    .test_sequence()
                    .checked_add(1)
                    .is_some_and(|sequence| sequence == next.test_sequence()),
            };
            if !valid_sequence {
                return Err(CoordinatorWitnessError::InvalidTransition);
            }
            self.state.set(Some(next));
            if self.advance_then_fail.replace(false) {
                return Err(CoordinatorWitnessError::AdvanceUnresolved);
            }
            Ok(())
        }
    }

    /// The coordinator's witness double stands in for the external freshness
    /// authority in every coordinator test, so a double that accepts
    /// transitions the real contract forbids would let those tests pass over
    /// sequences no conforming authority would ever produce.
    #[test]
    fn the_coordinator_witness_satisfies_the_freshness_contract() -> Result<(), Box<dyn Error>> {
        witness_conformance::assert_witness_conforms(CoordinatorWitness::empty)?;
        Ok(())
    }

    // Non-cryptographic fixture: its plaintext-derived nonce is deterministic
    // and deliberately does not satisfy the production uniqueness contract.
    #[derive(Clone)]
    struct DeterministicTestProtector {
        key: [u8; DIGEST_BYTES],
        available: Rc<Cell<bool>>,
        open_calls: Rc<Cell<usize>>,
    }

    impl DeterministicTestProtector {
        fn available() -> Self {
            Self {
                key: TEST_KEY,
                available: Rc::new(Cell::new(true)),
                open_calls: Rc::new(Cell::new(0)),
            }
        }

        fn unavailable() -> Self {
            let protector = Self::available();
            protector.available.set(false);
            protector
        }

        fn set_available(&self, available: bool) {
            self.available.set(available);
        }

        fn open_calls(&self) -> usize {
            self.open_calls.get()
        }

        fn xor_stream(
            &self,
            context: &ReplayJournalProtectionContext,
            kind: ReplayJournalRecordKind,
            nonce: &[u8],
            input: &[u8],
            output: &mut [u8],
        ) {
            for (chunk_index, (input_chunk, output_chunk)) in input
                .chunks(DIGEST_BYTES)
                .zip(output.chunks_mut(DIGEST_BYTES))
                .enumerate()
            {
                let stream = versioned_digest(
                    TEST_STREAM_DOMAIN,
                    kind.format_version(),
                    &[
                        &self.key,
                        context.as_bytes(),
                        &[kind.tag()],
                        nonce,
                        &(chunk_index as u64).to_be_bytes(),
                    ],
                );
                for ((input_byte, output_byte), stream_byte) in input_chunk
                    .iter()
                    .zip(output_chunk.iter_mut())
                    .zip(stream.iter())
                {
                    *output_byte = *input_byte ^ *stream_byte;
                }
            }
        }

        fn authentication(
            &self,
            context: &ReplayJournalProtectionContext,
            kind: ReplayJournalRecordKind,
            nonce: &[u8],
            ciphertext: &[u8],
        ) -> [u8; TEST_PROTECTION_AUTHENTICATION_BYTES] {
            let digest = versioned_digest(
                TEST_AUTHENTICATION_DOMAIN,
                kind.format_version(),
                &[
                    &self.key,
                    context.as_bytes(),
                    &[kind.tag()],
                    nonce,
                    ciphertext,
                ],
            );
            read_array(&digest, 0)
        }
    }

    impl ReplayJournalRecordProtector for DeterministicTestProtector {
        fn seal(
            &self,
            context: &ReplayJournalProtectionContext,
            kind: ReplayJournalRecordKind,
            plaintext: &[u8],
            protected: &mut [u8],
        ) -> Result<(), ProtectionUnavailable> {
            if !self.available.get()
                || protected.len() != plaintext.len() + PROTECTION_OVERHEAD_BYTES
            {
                return Err(ProtectionUnavailable);
            }
            let nonce_digest = versioned_digest(
                TEST_NONCE_DOMAIN,
                kind.format_version(),
                &[&self.key, context.as_bytes(), &[kind.tag()], plaintext],
            );
            protected[..TEST_PROTECTION_NONCE_BYTES]
                .copy_from_slice(&nonce_digest[..TEST_PROTECTION_NONCE_BYTES]);
            let ciphertext_start =
                TEST_PROTECTION_NONCE_BYTES + TEST_PROTECTION_AUTHENTICATION_BYTES;
            let nonce = read_array::<TEST_PROTECTION_NONCE_BYTES>(protected, 0);
            self.xor_stream(
                context,
                kind,
                &nonce,
                plaintext,
                &mut protected[ciphertext_start..],
            );
            let authentication = self.authentication(
                context,
                kind,
                &protected[..TEST_PROTECTION_NONCE_BYTES],
                &protected[ciphertext_start..],
            );
            protected[TEST_PROTECTION_NONCE_BYTES..ciphertext_start]
                .copy_from_slice(&authentication);
            Ok(())
        }

        fn open(
            &self,
            context: &ReplayJournalProtectionContext,
            kind: ReplayJournalRecordKind,
            protected: &[u8],
            plaintext: &mut [u8],
        ) -> Result<AuthenticationDecision, ProtectionUnavailable> {
            self.open_calls.set(self.open_calls.get() + 1);
            if !self.available.get()
                || protected.len() != plaintext.len() + PROTECTION_OVERHEAD_BYTES
            {
                return Err(ProtectionUnavailable);
            }
            let ciphertext_start =
                TEST_PROTECTION_NONCE_BYTES + TEST_PROTECTION_AUTHENTICATION_BYTES;
            let expected = self.authentication(
                context,
                kind,
                &protected[..TEST_PROTECTION_NONCE_BYTES],
                &protected[ciphertext_start..],
            );
            let supplied = &protected[TEST_PROTECTION_NONCE_BYTES..ciphertext_start];
            let accepted = supplied
                .iter()
                .zip(expected)
                .fold(0_u8, |difference, (left, right)| {
                    difference | (*left ^ right)
                })
                == 0;
            if !accepted {
                return Ok(AuthenticationDecision::Rejected);
            }
            self.xor_stream(
                context,
                kind,
                &protected[..TEST_PROTECTION_NONCE_BYTES],
                &protected[ciphertext_start..],
                plaintext,
            );
            Ok(AuthenticationDecision::Accepted)
        }
    }

    fn limits() -> ReplayJournalLimits {
        ReplayJournalLimits::new(32).expect("fixture limit is nonzero")
    }

    const fn test_profile_id() -> [u8; PROFILE_ID_BYTES] {
        [0x81; PROFILE_ID_BYTES]
    }

    fn replay_profile() -> PrivacyProfile {
        test_profile_without_recent_snapshot("replay-journal", 1, 1, 1, 1, 1)
            .expect("fixture privacy profile is valid")
    }

    fn same_capacity_different_profile(profile: PrivacyProfile) -> PrivacyProfile {
        let policy = profile.replay_policy();
        profile
            .with_test_replay_policy(
                policy.transaction_capacity(),
                policy
                    .expiry_bucket_width_seconds()
                    .checked_add(1)
                    .expect("fixture replay expiry bucket leaves increment headroom"),
                policy.garbage_collection_interval_seconds(),
            )
            .expect("fixture replay policy remains valid")
    }

    fn protection_context() -> ReplayJournalProtectionContext {
        ReplayJournalProtectionContext::new([0x92; DIGEST_BYTES])
    }

    fn namespace() -> ReplayNamespace {
        ReplayNamespace::new([0x11; 16], 1, 2, 3, [0x22; 16], [0x33; 32])
    }

    fn request_key(byte: u8) -> RequestReplayKey {
        RequestReplayKey::new(&namespace(), [byte; 24])
    }

    fn continuation_key(byte: u8) -> ContinuationReplayKey {
        ContinuationReplayKey::new(
            &namespace(),
            4,
            [byte; 32],
            u64::from(byte),
            1_000 + u64::from(byte),
            [byte; 24],
            [byte.wrapping_add(1); 32],
        )
    }

    fn continuation_claim(
        key: ContinuationReplayKey,
        expiry_bucket_ordinal: u64,
    ) -> ContinuationReplayClaim {
        ContinuationReplayClaim::for_test(
            key,
            NonZeroU64::new(expiry_bucket_ordinal)
                .expect("fixture expiry bucket ordinal is nonzero"),
        )
    }

    fn claim_lane(byte: u8, expiry_bucket_ordinal: u64) -> ReplayJournalContinuationLane {
        ReplayJournalContinuationLane::Claim {
            key: [byte; REPLAY_RECORD_KEY_BYTES],
            expiry_bucket_ordinal: NonZeroU64::new(expiry_bucket_ordinal)
                .expect("fixture expiry bucket ordinal is nonzero"),
        }
    }

    fn security_round() -> (SecurityEpochTag, SecurityRoundCapture) {
        let epoch = SecurityEpochTag::new([0x44; 32]);
        let round = SecurityRoundCapture::new(&epoch);
        (epoch, round)
    }

    fn open_store(
        directory: &TempDir,
    ) -> Result<ReplayJournalStore<DeterministicTestProtector>, ReplayJournalStoreError> {
        ReplayJournalStore::open_with_limits(
            directory.path().join("journal"),
            limits(),
            test_profile_id(),
            protection_context(),
            DeterministicTestProtector::available(),
        )
    }

    fn advance_maintenance_watermark(
        store: &mut ReplayJournalStore<DeterministicTestProtector>,
        watermark: ReplayMaintenanceWatermark,
    ) -> Result<Option<ReplayJournalMaintenanceAdvanceReceipt>, ReplayJournalStoreError> {
        match store.prepare_maintenance_watermark(watermark)? {
            ReplayMaintenancePreparation::NoAdvance => Ok(None),
            ReplayMaintenancePreparation::Advance(prepared) => store
                .commit_prepared_maintenance_and_capture(prepared)
                .map(Some),
        }
    }

    fn provision_coordinator(
        replay_root: &Path,
        security_state_root: &Path,
        protector: DeterministicTestProtector,
        witness: CoordinatorWitness,
    ) -> Result<
        ReplaySnapshotCoordinator<DeterministicTestProtector, CoordinatorWitness>,
        ReplaySnapshotCoordinatorOpenError,
    > {
        provision_coordinator_with_profile(
            replay_root,
            security_state_root,
            &replay_profile(),
            protector,
            witness,
        )
    }

    fn provision_coordinator_with_profile(
        replay_root: &Path,
        security_state_root: &Path,
        profile: &PrivacyProfile,
        protector: DeterministicTestProtector,
        witness: CoordinatorWitness,
    ) -> Result<
        ReplaySnapshotCoordinator<DeterministicTestProtector, CoordinatorWitness>,
        ReplaySnapshotCoordinatorOpenError,
    > {
        ReplaySnapshotCoordinator::provision_initial(
            replay_root.to_path_buf(),
            security_state_root.to_path_buf(),
            profile,
            protection_context(),
            protector,
            witness,
            ReplaySnapshotInitialState {
                identity: test_security_state_identity_with_profile_id(0x71, *profile.profile_id())
                    .expect("coordinator fixture security identity is valid"),
                serving_identity_digest: [0x72; STATE_DIGEST_BYTES],
            },
        )
    }

    fn open_coordinator(
        replay_root: &Path,
        security_state_root: &Path,
        protector: DeterministicTestProtector,
        witness: CoordinatorWitness,
    ) -> Result<
        ReplaySnapshotCoordinator<DeterministicTestProtector, CoordinatorWitness>,
        ReplaySnapshotCoordinatorOpenError,
    > {
        open_coordinator_with_profile(
            replay_root,
            security_state_root,
            &replay_profile(),
            protector,
            witness,
        )
    }

    fn open_coordinator_with_profile(
        replay_root: &Path,
        security_state_root: &Path,
        profile: &PrivacyProfile,
        protector: DeterministicTestProtector,
        witness: CoordinatorWitness,
    ) -> Result<
        ReplaySnapshotCoordinator<DeterministicTestProtector, CoordinatorWitness>,
        ReplaySnapshotCoordinatorOpenError,
    > {
        ReplaySnapshotCoordinator::open_existing(
            replay_root.to_path_buf(),
            security_state_root.to_path_buf(),
            profile,
            protection_context(),
            protector,
            witness,
        )
    }

    fn entry(
        sequence: u64,
        request: u8,
        continuation_lane: ReplayJournalContinuationLane,
    ) -> ReplayJournalEntry {
        ReplayJournalEntry {
            sequence,
            request_key: [request; REPLAY_RECORD_KEY_BYTES],
            continuation_lane,
        }
    }

    fn one_entry_state(
        limits: ReplayJournalLimits,
        replay_entry: &ReplayJournalEntry,
    ) -> ReplayJournalState {
        let mut requests = HashSet::new();
        let mut continuations = HashSet::new();
        ReplayJournalState::empty(limits, test_profile_id())
            .apply_entry(&mut requests, &mut continuations, replay_entry)
            .expect("fixture entry is valid")
            .0
    }

    fn write_current(
        root: &Path,
        state: &ReplayJournalState,
        protector: &DeterministicTestProtector,
    ) -> TestResult {
        fs::create_dir_all(root)?;
        let persistent = PersistentReplayJournalCurrentStateV3::from_business(
            state,
            &protection_context(),
            protector,
        )?;
        fs::write(root.join(CURRENT_STATE_FILE), persistent.as_bytes())?;
        Ok(())
    }

    fn write_entry(
        root: &Path,
        replay_entry: &ReplayJournalEntry,
        protector: &DeterministicTestProtector,
    ) -> TestResult {
        let entries = root.join(ENTRIES_DIRECTORY);
        fs::create_dir_all(&entries)?;
        let persistent = PersistentReplayJournalEntry::from_business(
            replay_entry,
            &protection_context(),
            protector,
        )?;
        fs::write(
            entries.join(entry_filename(replay_entry.sequence)),
            persistent.as_bytes(),
        )?;
        Ok(())
    }

    fn protect_entry_body(
        body: &[u8; ENTRY_BODY_BYTES],
        context: &ReplayJournalProtectionContext,
        protector: &DeterministicTestProtector,
    ) -> Result<PersistentReplayJournalEntry, ProtectionUnavailable> {
        let mut record = [0; ENTRY_RECORD_BYTES];
        record[..RECORD_MAGIC_BYTES].copy_from_slice(&ENTRY_MAGIC);
        record[RECORD_MAGIC_BYTES..ENTRY_PROTECTED_START]
            .copy_from_slice(&ENTRY_FORMAT_VERSION.to_be_bytes());
        protector.seal(
            context,
            ReplayJournalRecordKind::ImmutableEntryV2,
            body,
            &mut record[ENTRY_PROTECTED_START..],
        )?;
        Ok(PersistentReplayJournalEntry(record))
    }

    #[test]
    fn limits_reject_zero_transactions() {
        assert_eq!(
            ReplayJournalLimits::new(0),
            Err(ReplayJournalValueError::ZeroLimit)
        );
    }

    #[test]
    fn fixed_width_records_round_trip_without_plaintext_semantics() -> TestResult {
        let protector = DeterministicTestProtector::available();
        let context = protection_context();
        let replay_entry = entry(1, 0x51, claim_lane(0x61, 7));
        let state = one_entry_state(limits(), &replay_entry);
        let persistent_entry =
            PersistentReplayJournalEntry::from_business(&replay_entry, &context, &protector)?;
        let persistent_current =
            PersistentReplayJournalCurrentStateV3::from_business(&state, &context, &protector)?;

        assert_eq!(persistent_entry.as_bytes().len(), ENTRY_RECORD_BYTES);
        assert_eq!(persistent_current.as_bytes().len(), CURRENT_RECORD_BYTES);
        assert_eq!(
            &persistent_entry.as_bytes()[..RECORD_MAGIC_BYTES],
            &ENTRY_MAGIC
        );
        assert_eq!(
            &persistent_current.as_bytes()[..RECORD_MAGIC_BYTES],
            &CURRENT_MAGIC
        );
        assert_eq!(
            read_u16(persistent_entry.as_bytes(), RECORD_MAGIC_BYTES),
            ENTRY_FORMAT_VERSION
        );
        assert_eq!(
            read_u16(persistent_current.as_bytes(), RECORD_MAGIC_BYTES),
            CURRENT_FORMAT_VERSION
        );
        assert!(!persistent_entry
            .as_bytes()
            .windows(REPLAY_RECORD_KEY_BYTES)
            .any(|window| window == replay_entry.request_key));
        assert!(!persistent_current
            .as_bytes()
            .windows(PROFILE_ID_BYTES)
            .any(|window| window == state.profile_id));
        assert!(!persistent_current
            .as_bytes()
            .windows(DIGEST_BYTES)
            .any(|window| window == state.entry_chain_digest));
        assert_eq!(
            PersistentReplayJournalEntry(*persistent_entry.as_bytes())
                .into_business(&context, &protector)?,
            replay_entry
        );
        assert_eq!(
            PersistentReplayJournalCurrentStateV3(*persistent_current.as_bytes())
                .into_business(&context, &protector)?,
            state
        );
        Ok(())
    }

    #[test]
    fn current_v3_body_layout_is_canonical() {
        let replay_entry = entry(1, 0x51, claim_lane(0x61, 7));
        let mut state = one_entry_state(limits(), &replay_entry);
        state.maintenance_expiry_bucket_watermark = ReplayMaintenanceWatermark::new(9);
        let body = state.canonical_current_body();

        assert_eq!(
            &body[CURRENT_LIMIT_TRANSACTIONS_START..CURRENT_PROFILE_ID_START],
            &limits().max_transactions.to_be_bytes()
        );
        assert_eq!(
            &body[CURRENT_PROFILE_ID_START..CURRENT_SEQUENCE_START],
            &test_profile_id()
        );
        assert_eq!(
            &body[CURRENT_SEQUENCE_START..CURRENT_REQUEST_COUNT_START],
            &1_u64.to_be_bytes()
        );
        assert_eq!(
            &body[CURRENT_REQUEST_COUNT_START..CURRENT_CONTINUATION_COUNT_START],
            &1_u64.to_be_bytes()
        );
        assert_eq!(
            &body[CURRENT_CONTINUATION_COUNT_START..CURRENT_CHAIN_DIGEST_START],
            &1_u64.to_be_bytes()
        );
        assert_eq!(
            &body[CURRENT_CHAIN_DIGEST_START..CURRENT_MAINTENANCE_WATERMARK_START],
            &state.entry_chain_digest
        );
        assert_eq!(
            &body[CURRENT_MAINTENANCE_WATERMARK_START..CURRENT_RESERVED_START],
            &9_u64.to_be_bytes()
        );
        assert!(all_zero(&body[CURRENT_RESERVED_START..]));
        assert_eq!(CURRENT_MAGIC, *b"ZORJCUR3");
        assert_eq!(CURRENT_FORMAT_VERSION, 3);
        assert_eq!(body.len(), 128);
        assert_eq!(CURRENT_RECORD_BYTES, 178);
    }

    #[test]
    fn current_v3_round_trips_watermark_without_entries() -> TestResult {
        let protector = DeterministicTestProtector::available();
        let context = protection_context();
        let state = ReplayJournalState::empty(limits(), test_profile_id())
            .preview_maintenance_watermark(ReplayMaintenanceWatermark::new(7))?
            .expect("greater fixture watermark prepares an advance");
        let persistent =
            PersistentReplayJournalCurrentStateV3::from_business(&state, &context, &protector)?;

        assert_eq!(
            PersistentReplayJournalCurrentStateV3(*persistent.as_bytes())
                .into_business(&context, &protector)?,
            state
        );
        assert_eq!(state.committed_sequence, 0);
        assert_eq!(state.claimed_request_count, 0);
        assert_eq!(state.claimed_continuation_count, 0);
        assert_eq!(
            state.maintenance_expiry_bucket_watermark,
            ReplayMaintenanceWatermark::new(7)
        );
        Ok(())
    }

    #[test]
    fn entry_v2_body_layout_is_canonical() {
        let cover = entry(7, 0x51, ReplayJournalContinuationLane::Cover).canonical_body();
        assert_eq!(
            &cover[ENTRY_SEQUENCE_START..ENTRY_REQUEST_KEY_START],
            &7_u64.to_be_bytes()
        );
        assert_eq!(
            &cover[ENTRY_REQUEST_KEY_START..ENTRY_CONTINUATION_TAG_START],
            &[0x51; REPLAY_RECORD_KEY_BYTES]
        );
        assert_eq!(cover[ENTRY_CONTINUATION_TAG_START], CONTINUATION_COVER_TAG);
        assert!(all_zero(
            &cover[ENTRY_CONTINUATION_KEY_START..ENTRY_RESERVED_START]
        ));
        assert!(all_zero(&cover[ENTRY_RESERVED_START..]));

        let claim = entry(7, 0x51, claim_lane(0x61, 9)).canonical_body();
        assert_eq!(claim[ENTRY_CONTINUATION_TAG_START], CONTINUATION_CLAIM_TAG);
        assert_eq!(
            &claim[ENTRY_CONTINUATION_KEY_START..ENTRY_CONTINUATION_EXPIRY_BUCKET_ORDINAL_START],
            &[0x61; REPLAY_RECORD_KEY_BYTES]
        );
        assert_eq!(
            &claim[ENTRY_CONTINUATION_EXPIRY_BUCKET_ORDINAL_START..ENTRY_RESERVED_START],
            &9_u64.to_be_bytes()
        );
        assert!(all_zero(&claim[ENTRY_RESERVED_START..]));
        assert_eq!(ENTRY_MAGIC, *b"ZORJENT2");
        assert_eq!(ENTRY_FORMAT_VERSION, 2);
        assert_eq!(claim.len(), 96);
    }

    #[test]
    fn record_headers_and_authentication_fail_closed() -> TestResult {
        let protector = DeterministicTestProtector::available();
        let context = protection_context();
        let replay_entry = entry(1, 0x51, ReplayJournalContinuationLane::Cover);
        let persistent =
            PersistentReplayJournalEntry::from_business(&replay_entry, &context, &protector)?;
        let current = PersistentReplayJournalCurrentStateV3::from_business(
            &one_entry_state(limits(), &replay_entry),
            &context,
            &protector,
        )?;

        let mut wrong_magic = *persistent.as_bytes();
        wrong_magic[0] ^= 1;
        assert!(matches!(
            PersistentReplayJournalEntry(wrong_magic).into_business(&context, &protector),
            Err(ReplayJournalRecordError::InvalidMagic)
        ));

        let mut wrong_version = *persistent.as_bytes();
        wrong_version[RECORD_MAGIC_BYTES + 1] ^= 1;
        assert!(matches!(
            PersistentReplayJournalEntry(wrong_version).into_business(&context, &protector),
            Err(ReplayJournalRecordError::UnsupportedVersion)
        ));

        let mut wrong_current_magic = *current.as_bytes();
        wrong_current_magic[0] ^= 1;
        assert!(matches!(
            PersistentReplayJournalCurrentStateV3(wrong_current_magic)
                .into_business(&context, &protector),
            Err(ReplayJournalRecordError::InvalidMagic)
        ));

        let mut wrong_current_version = *current.as_bytes();
        wrong_current_version[RECORD_MAGIC_BYTES + 1] ^= 1;
        assert!(matches!(
            PersistentReplayJournalCurrentStateV3(wrong_current_version)
                .into_business(&context, &protector),
            Err(ReplayJournalRecordError::UnsupportedVersion)
        ));

        for index in CURRENT_PROTECTED_START..CURRENT_RECORD_BYTES {
            let mut tampered = *current.as_bytes();
            tampered[index] ^= 1;
            assert!(matches!(
                PersistentReplayJournalCurrentStateV3(tampered).into_business(&context, &protector),
                Err(ReplayJournalRecordError::AuthenticationFailed)
            ));
        }

        for index in ENTRY_PROTECTED_START..ENTRY_RECORD_BYTES {
            let mut tampered = *persistent.as_bytes();
            tampered[index] ^= 1;
            assert!(matches!(
                PersistentReplayJournalEntry(tampered).into_business(&context, &protector),
                Err(ReplayJournalRecordError::AuthenticationFailed)
            ));
        }
        Ok(())
    }

    #[test]
    fn protection_context_rejects_cross_journal_transplants() -> TestResult {
        let protector = DeterministicTestProtector::available();
        let context = protection_context();
        let other_context = ReplayJournalProtectionContext::new([0x93; DIGEST_BYTES]);
        let replay_entry = entry(1, 0x51, ReplayJournalContinuationLane::Cover);
        let persistent =
            PersistentReplayJournalEntry::from_business(&replay_entry, &context, &protector)?;

        assert!(matches!(
            PersistentReplayJournalEntry(*persistent.as_bytes())
                .into_business(&other_context, &protector),
            Err(ReplayJournalRecordError::AuthenticationFailed)
        ));
        Ok(())
    }

    #[test]
    fn invalid_entry_semantics_are_rejected_after_authentication() -> TestResult {
        let protector = DeterministicTestProtector::available();
        let context = protection_context();
        let mut invalid_tag = entry(1, 0x51, ReplayJournalContinuationLane::Cover).canonical_body();
        invalid_tag[ENTRY_CONTINUATION_TAG_START] = 9;
        let tag_record = protect_entry_body(&invalid_tag, &context, &protector)?;
        assert!(matches!(
            tag_record.into_business(&context, &protector),
            Err(ReplayJournalRecordError::InvalidValue(
                ReplayJournalValueError::InvalidContinuationTag
            ))
        ));

        let mut nonzero_cover =
            entry(1, 0x51, ReplayJournalContinuationLane::Cover).canonical_body();
        nonzero_cover[ENTRY_CONTINUATION_KEY_START] = 1;
        let cover_record = protect_entry_body(&nonzero_cover, &context, &protector)?;
        assert!(matches!(
            cover_record.into_business(&context, &protector),
            Err(ReplayJournalRecordError::InvalidValue(
                ReplayJournalValueError::NonZeroCoverKey
            ))
        ));

        let mut nonzero_cover_bucket =
            entry(1, 0x51, ReplayJournalContinuationLane::Cover).canonical_body();
        nonzero_cover_bucket[ENTRY_RESERVED_START - 1] = 1;
        let cover_bucket_record = protect_entry_body(&nonzero_cover_bucket, &context, &protector)?;
        assert!(matches!(
            cover_bucket_record.into_business(&context, &protector),
            Err(ReplayJournalRecordError::InvalidValue(
                ReplayJournalValueError::NonZeroCoverExpiryBucketOrdinal
            ))
        ));

        let mut nonzero_cover_tail =
            entry(1, 0x51, ReplayJournalContinuationLane::Cover).canonical_body();
        nonzero_cover_tail[ENTRY_RESERVED_START] = 1;
        let cover_tail_record = protect_entry_body(&nonzero_cover_tail, &context, &protector)?;
        assert!(matches!(
            cover_tail_record.into_business(&context, &protector),
            Err(ReplayJournalRecordError::InvalidValue(
                ReplayJournalValueError::NonZeroReservedBytes
            ))
        ));

        let mut zero_claim_bucket = entry(1, 0x51, claim_lane(0x61, 7)).canonical_body();
        zero_claim_bucket[ENTRY_CONTINUATION_EXPIRY_BUCKET_ORDINAL_START..ENTRY_RESERVED_START]
            .fill(0);
        let zero_claim_record = protect_entry_body(&zero_claim_bucket, &context, &protector)?;
        assert!(matches!(
            zero_claim_record.into_business(&context, &protector),
            Err(ReplayJournalRecordError::InvalidValue(
                ReplayJournalValueError::ZeroClaimExpiryBucketOrdinal
            ))
        ));

        for reserved_index in ENTRY_RESERVED_START..ENTRY_BODY_BYTES {
            let mut nonzero_reserved = entry(1, 0x51, claim_lane(0x61, 7)).canonical_body();
            nonzero_reserved[reserved_index] = 1;
            let reserved_record = protect_entry_body(&nonzero_reserved, &context, &protector)?;
            assert!(matches!(
                reserved_record.into_business(&context, &protector),
                Err(ReplayJournalRecordError::InvalidValue(
                    ReplayJournalValueError::NonZeroReservedBytes
                ))
            ));
        }
        Ok(())
    }

    #[test]
    fn recovery_rejects_entry_v1_without_migration() -> TestResult {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("journal");
        let protector = DeterministicTestProtector::available();
        let replay_entry = entry(1, 0x51, claim_lane(0x61, 7));
        let state = one_entry_state(limits(), &replay_entry);
        write_current(&root, &state, &protector)?;
        let entries = root.join(ENTRIES_DIRECTORY);
        fs::create_dir_all(&entries)?;
        let mut legacy_entry = [0; ENTRY_RECORD_BYTES];
        legacy_entry[..RECORD_MAGIC_BYTES].copy_from_slice(b"ZORJENT1");
        legacy_entry[RECORD_MAGIC_BYTES..ENTRY_PROTECTED_START]
            .copy_from_slice(&1_u16.to_be_bytes());
        fs::write(entries.join(entry_filename(1)), legacy_entry)?;

        assert_eq!(
            ReplayJournalStore::open_with_limits(
                root,
                limits(),
                test_profile_id(),
                protection_context(),
                protector,
            )
            .expect_err("entry v1 has no explicit expiry bucket and must not be migrated"),
            ReplayJournalStoreError::CommittedEntryCorrupt
        );
        Ok(())
    }

    #[test]
    fn recovery_rejects_current_v2_without_migration() -> TestResult {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("journal");
        fs::create_dir_all(&root)?;
        let mut legacy_current = [0; CURRENT_RECORD_BYTES];
        legacy_current[..RECORD_MAGIC_BYTES].copy_from_slice(b"ZORJCUR2");
        legacy_current[RECORD_MAGIC_BYTES..CURRENT_PROTECTED_START]
            .copy_from_slice(&2_u16.to_be_bytes());
        fs::write(root.join(CURRENT_STATE_FILE), legacy_current)?;

        assert_eq!(
            ReplayJournalStore::open_with_limits(
                root,
                limits(),
                test_profile_id(),
                protection_context(),
                DeterministicTestProtector::available(),
            )
            .expect_err("current v2 must not be reinterpreted as profile-v6 current state"),
            ReplayJournalStoreError::CurrentStateCorrupt
        );
        Ok(())
    }

    #[test]
    fn rejected_protection_never_exposes_plaintext() -> TestResult {
        let protector = DeterministicTestProtector::available();
        let context = protection_context();
        let plaintext = [0x71; ENTRY_BODY_BYTES];
        let mut protected = [0; ENTRY_PROTECTED_BYTES];
        protector.seal(
            &context,
            ReplayJournalRecordKind::ImmutableEntryV2,
            &plaintext,
            &mut protected,
        )?;
        protected[TEST_PROTECTION_AUTHENTICATION_BYTES] ^= 1;
        let mut output = [0; ENTRY_BODY_BYTES];
        assert_eq!(
            protector.open(
                &context,
                ReplayJournalRecordKind::ImmutableEntryV2,
                &protected,
                &mut output
            )?,
            AuthenticationDecision::Rejected
        );
        assert_eq!(output, [0; ENTRY_BODY_BYTES]);
        Ok(())
    }

    #[test]
    fn debug_output_redacts_replay_material() {
        let replay_entry = entry(1, 0x51, claim_lane(0x61, 7));
        let state = one_entry_state(limits(), &replay_entry);
        assert_eq!(
            format!("{replay_entry:?}"),
            "ReplayJournalEntry { ..REDACTED.. }"
        );
        assert_eq!(format!("{state:?}"), "ReplayJournalState { ..REDACTED.. }");
    }

    #[test]
    fn entry_payload_digest_binds_every_semantic_field() {
        let baseline = entry(1, 0x51, claim_lane(0x61, 7));
        assert_ne!(
            baseline.payload_digest(),
            entry(2, 0x51, claim_lane(0x61, 7)).payload_digest()
        );
        assert_ne!(
            baseline.payload_digest(),
            entry(1, 0x52, claim_lane(0x61, 7)).payload_digest()
        );
        assert_ne!(
            baseline.payload_digest(),
            entry(1, 0x51, ReplayJournalContinuationLane::Cover).payload_digest()
        );
        assert_ne!(
            baseline.payload_digest(),
            entry(1, 0x51, claim_lane(0x62, 7)).payload_digest()
        );
        assert_ne!(
            baseline.payload_digest(),
            entry(1, 0x51, claim_lane(0x61, 8)).payload_digest()
        );
    }

    #[test]
    fn chain_and_component_digests_bind_order_and_state() {
        let first = entry(1, 0x51, ReplayJournalContinuationLane::Cover);
        let second = entry(2, 0x52, ReplayJournalContinuationLane::Cover);
        let swapped_first = entry(1, 0x52, ReplayJournalContinuationLane::Cover);
        let swapped_second = entry(2, 0x51, ReplayJournalContinuationLane::Cover);
        let mut requests = HashSet::new();
        let mut continuations = HashSet::new();
        let (first_state, _) = ReplayJournalState::empty(limits(), test_profile_id())
            .apply_entry(&mut requests, &mut continuations, &first)
            .expect("first fixture entry is valid");
        let (ordered, _) = first_state
            .apply_entry(&mut requests, &mut continuations, &second)
            .expect("second fixture entry is valid");

        let mut swapped_requests = HashSet::new();
        let mut swapped_continuations = HashSet::new();
        let (swapped_first_state, _) = ReplayJournalState::empty(limits(), test_profile_id())
            .apply_entry(
                &mut swapped_requests,
                &mut swapped_continuations,
                &swapped_first,
            )
            .expect("swapped first fixture entry is valid");
        let (swapped, _) = swapped_first_state
            .apply_entry(
                &mut swapped_requests,
                &mut swapped_continuations,
                &swapped_second,
            )
            .expect("swapped second fixture entry is valid");

        assert_ne!(ordered.entry_chain_digest, swapped.entry_chain_digest);
        assert_ne!(
            ordered.component_state_digest(),
            swapped.component_state_digest()
        );
        let mut changed = ordered;
        changed.claimed_request_count -= 1;
        assert_ne!(
            ordered.component_state_digest(),
            changed.component_state_digest()
        );
        changed = ordered;
        changed.limits.max_transactions += 1;
        assert_ne!(
            ordered.component_state_digest(),
            changed.component_state_digest()
        );
        changed = ordered;
        changed.profile_id[0] ^= 1;
        assert_ne!(
            ordered.component_state_digest(),
            changed.component_state_digest()
        );
        changed = ordered;
        changed.maintenance_expiry_bucket_watermark = ReplayMaintenanceWatermark::new(7);
        assert_ne!(
            ordered.component_state_digest(),
            changed.component_state_digest()
        );

        let mut bucket_seven_requests = HashSet::new();
        let mut bucket_seven_continuations = HashSet::new();
        let (bucket_seven, _) = ReplayJournalState::empty(limits(), test_profile_id())
            .apply_entry(
                &mut bucket_seven_requests,
                &mut bucket_seven_continuations,
                &entry(1, 0x51, claim_lane(0x61, 7)),
            )
            .expect("bucket-seven fixture entry is valid");
        let mut bucket_eight_requests = HashSet::new();
        let mut bucket_eight_continuations = HashSet::new();
        let (bucket_eight, _) = ReplayJournalState::empty(limits(), test_profile_id())
            .apply_entry(
                &mut bucket_eight_requests,
                &mut bucket_eight_continuations,
                &entry(1, 0x51, claim_lane(0x61, 8)),
            )
            .expect("bucket-eight fixture entry is valid");
        assert_ne!(
            bucket_seven.entry_chain_digest,
            bucket_eight.entry_chain_digest
        );
        assert_ne!(
            bucket_seven.component_state_digest(),
            bucket_eight.component_state_digest()
        );
    }

    #[test]
    fn committed_component_digest_changes_after_every_transaction() -> TestResult {
        let directory = tempfile::tempdir()?;
        let mut store = open_store(&directory)?;
        let (_, round) = security_round();
        let initial = store.component_state_digest()?;

        store.commit_transaction(&round, &request_key(1), &ContinuationReplayPlan::Cover)?;
        let fresh_cover = store.component_state_digest()?;
        assert_ne!(fresh_cover, initial);

        store.commit_transaction(&round, &request_key(1), &ContinuationReplayPlan::Cover)?;
        let duplicate_request = store.component_state_digest()?;
        assert_ne!(duplicate_request, fresh_cover);

        let continuation = continuation_key(2);
        let claim = continuation_claim(continuation, 7);
        store.commit_transaction(
            &round,
            &request_key(2),
            &ContinuationReplayPlan::ClaimOrCover(claim),
        )?;
        let fresh_continuation = store.component_state_digest()?;
        assert_ne!(fresh_continuation, duplicate_request);

        store.commit_transaction(
            &round,
            &request_key(3),
            &ContinuationReplayPlan::ClaimOrCover(claim),
        )?;
        assert_ne!(store.component_state_digest()?, fresh_continuation);
        Ok(())
    }

    #[test]
    fn maintenance_watermark_advance_is_current_only_and_recoverable() -> TestResult {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("journal");
        let mut store = open_store(&directory)?;
        let initial_state = store.state;
        let initial_request_claims = store.request_claims.clone();
        let initial_continuation_claims = store.continuation_claims.clone();
        let initial_digest = store.component_state_digest()?;

        let receipt =
            advance_maintenance_watermark(&mut store, ReplayMaintenanceWatermark::new(7))?
                .expect("greater watermark must mint a maintenance receipt");
        assert_eq!(
            format!("{receipt:?}"),
            "ReplayJournalMaintenanceAdvanceReceipt { ..REDACTED.. }"
        );
        let (previous_digest, committed_digest) = receipt.into_digests();
        assert_eq!(previous_digest, initial_digest);
        assert_eq!(committed_digest, store.component_state_digest()?);
        assert_ne!(committed_digest, initial_digest);
        assert_eq!(
            store.state.committed_sequence,
            initial_state.committed_sequence
        );
        assert_eq!(
            store.state.claimed_request_count,
            initial_state.claimed_request_count
        );
        assert_eq!(
            store.state.claimed_continuation_count,
            initial_state.claimed_continuation_count
        );
        assert_eq!(store.request_claims, initial_request_claims);
        assert_eq!(store.continuation_claims, initial_continuation_claims);
        assert_eq!(
            store.state.maintenance_expiry_bucket_watermark,
            ReplayMaintenanceWatermark::new(7)
        );
        assert_eq!(fs::read_dir(root.join(ENTRIES_DIRECTORY))?.count(), 0);
        assert_eq!(
            fs::metadata(root.join(CURRENT_STATE_FILE))?.len(),
            CURRENT_RECORD_BYTES as u64
        );
        drop(store);

        let mut reopened = open_store(&directory)?;
        assert_eq!(
            reopened.state.maintenance_expiry_bucket_watermark,
            ReplayMaintenanceWatermark::new(7)
        );
        assert_eq!(reopened.state.committed_sequence, 0);
        let (_, round) = security_round();
        reopened.commit_transaction(&round, &request_key(1), &ContinuationReplayPlan::Cover)?;
        assert_eq!(reopened.state.committed_sequence, 1);
        assert_eq!(
            reopened.state.maintenance_expiry_bucket_watermark,
            ReplayMaintenanceWatermark::new(7)
        );
        Ok(())
    }

    #[test]
    fn maintenance_watermark_equal_is_noop_and_regressions_do_not_latch() -> TestResult {
        let directory = tempfile::tempdir()?;
        let mut store = open_store(&directory)?;
        assert!(
            advance_maintenance_watermark(&mut store, ReplayMaintenanceWatermark::NONE)?.is_none()
        );
        assert_eq!(store.health, ReplayJournalStoreHealth::Ready);
        advance_maintenance_watermark(&mut store, ReplayMaintenanceWatermark::new(7))?
            .expect("greater watermark must advance");
        let state_at_seven = store.state;
        let digest_at_seven = store.component_state_digest()?;

        assert!(
            advance_maintenance_watermark(&mut store, ReplayMaintenanceWatermark::new(7))?
                .is_none()
        );
        assert_eq!(
            advance_maintenance_watermark(&mut store, ReplayMaintenanceWatermark::new(6),)
                .expect_err("maintenance watermark must not regress"),
            ReplayJournalStoreError::MaintenanceWatermarkRegressed
        );
        assert_eq!(
            advance_maintenance_watermark(&mut store, ReplayMaintenanceWatermark::NONE)
                .expect_err("zero must not replace a nonzero maintenance watermark"),
            ReplayJournalStoreError::MaintenanceWatermarkRegressed
        );
        assert_eq!(store.health, ReplayJournalStoreHealth::Ready);
        assert_eq!(store.state, state_at_seven);
        assert_eq!(store.component_state_digest()?, digest_at_seven);

        advance_maintenance_watermark(&mut store, ReplayMaintenanceWatermark::new(u64::MAX))?
            .expect("skipped greater watermark must advance");
        assert_eq!(
            store.state.maintenance_expiry_bucket_watermark,
            ReplayMaintenanceWatermark::new(u64::MAX)
        );
        assert_eq!(store.state.committed_sequence, 0);
        Ok(())
    }

    #[test]
    fn stale_prepared_maintenance_after_request_commit_is_non_latching() -> TestResult {
        let directory = tempfile::tempdir()?;
        let mut store = open_store(&directory)?;
        let prepared =
            match store.prepare_maintenance_watermark(ReplayMaintenanceWatermark::new(7))? {
                ReplayMaintenancePreparation::Advance(prepared) => prepared,
                ReplayMaintenancePreparation::NoAdvance => {
                    return Err("greater fixture watermark must prepare an advance".into());
                }
            };
        let (_, round) = security_round();
        store.commit_transaction(&round, &request_key(1), &ContinuationReplayPlan::Cover)?;
        let state_after_request = store.state;

        assert_eq!(
            store
                .commit_prepared_maintenance_and_capture(prepared)
                .expect_err("intervening request must stale the prepared maintenance advance"),
            ReplayJournalStoreError::CurrentStateMismatch
        );
        assert_eq!(store.health, ReplayJournalStoreHealth::Ready);
        assert_eq!(store.state, state_after_request);
        assert_eq!(
            store.state.maintenance_expiry_bucket_watermark,
            ReplayMaintenanceWatermark::NONE
        );

        advance_maintenance_watermark(&mut store, ReplayMaintenanceWatermark::new(7))?
            .expect("freshly prepared greater watermark must advance");
        assert_eq!(store.health, ReplayJournalStoreHealth::Ready);
        assert_eq!(
            store.state.maintenance_expiry_bucket_watermark,
            ReplayMaintenanceWatermark::new(7)
        );
        Ok(())
    }

    #[test]
    fn maintenance_stage_failure_before_rename_keeps_store_ready() -> TestResult {
        let directory = tempfile::tempdir()?;
        let protector = DeterministicTestProtector::available();
        let mut store = ReplayJournalStore::open_with_limits(
            directory.path().join("journal"),
            limits(),
            test_profile_id(),
            protection_context(),
            protector.clone(),
        )?;
        let initial_state = store.state;
        let prepared =
            match store.prepare_maintenance_watermark(ReplayMaintenanceWatermark::new(7))? {
                ReplayMaintenancePreparation::NoAdvance => {
                    return Err("greater fixture watermark did not prepare an advance".into());
                }
                ReplayMaintenancePreparation::Advance(prepared) => prepared,
            };

        protector.set_available(false);
        assert_eq!(
            store
                .commit_prepared_maintenance_and_capture(prepared)
                .expect_err("pre-rename protector failure must not mint a receipt"),
            ReplayJournalStoreError::CurrentStateProtectionUnavailable
        );
        assert_eq!(store.health, ReplayJournalStoreHealth::Ready);
        assert_eq!(store.state, initial_state);

        protector.set_available(true);
        advance_maintenance_watermark(&mut store, ReplayMaintenanceWatermark::new(7))?
            .expect("retry after a safe stage failure must advance");
        assert_eq!(
            store.state.maintenance_expiry_bucket_watermark,
            ReplayMaintenanceWatermark::new(7)
        );
        Ok(())
    }

    #[test]
    fn coordinator_separates_initial_provisioning_from_existing_open() -> TestResult {
        let directory = tempfile::tempdir()?;
        let replay_root = directory.path().join("replay");
        let security_state_root = directory.path().join("security-state");
        let witness = CoordinatorWitness::empty();

        assert!(matches!(
            open_coordinator(
                &replay_root,
                &security_state_root,
                DeterministicTestProtector::available(),
                witness.clone(),
            ),
            Err(ReplaySnapshotCoordinatorOpenError::OuterSnapshotMissing)
        ));

        let coordinator = provision_coordinator(
            &replay_root,
            &security_state_root,
            DeterministicTestProtector::available(),
            witness.clone(),
        )?;
        assert_eq!(coordinator.current_snapshot.test_sequence(), 1);
        verify_current(&coordinator.current_snapshot, &coordinator.replay_journal)?;
        drop(coordinator);

        assert!(matches!(
            provision_coordinator(
                &replay_root,
                &security_state_root,
                DeterministicTestProtector::available(),
                witness.clone(),
            ),
            Err(ReplaySnapshotCoordinatorOpenError::OuterSnapshotAlreadyProvisioned)
        ));

        let reopened = open_coordinator(
            &replay_root,
            &security_state_root,
            DeterministicTestProtector::available(),
            witness,
        )?;
        assert_eq!(reopened.current_snapshot.test_sequence(), 1);
        verify_current(&reopened.current_snapshot, &reopened.replay_journal)?;
        Ok(())
    }

    #[test]
    fn coordinator_advances_outer_snapshot_for_fresh_and_duplicate_commits() -> TestResult {
        let directory = tempfile::tempdir()?;
        let replay_root = directory.path().join("replay");
        let security_state_root = directory.path().join("security-state");
        let witness = CoordinatorWitness::empty();
        let mut coordinator = provision_coordinator(
            &replay_root,
            &security_state_root,
            DeterministicTestProtector::available(),
            witness.clone(),
        )?;
        let (_, round) = security_round();
        let request = request_key(1);

        let first = coordinator.commit_request_and_snapshot(
            &round,
            &request,
            &ContinuationReplayPlan::Cover,
        )?;
        let (_authority, first_decision) = first.into_parts();
        assert_eq!(first_decision, ReplayDuplicateDecision::Fresh);
        assert_eq!(coordinator.current_snapshot.test_sequence(), 2);

        let duplicate = coordinator.commit_request_and_snapshot(
            &round,
            &request,
            &ContinuationReplayPlan::Cover,
        )?;
        let (_authority, duplicate_decision) = duplicate.into_parts();
        assert_eq!(
            duplicate_decision,
            ReplayDuplicateDecision::RequestDuplicate
        );
        assert_eq!(coordinator.current_snapshot.test_sequence(), 3);
        verify_current(&coordinator.current_snapshot, &coordinator.replay_journal)?;
        drop(coordinator);

        let reopened = open_coordinator(
            &replay_root,
            &security_state_root,
            DeterministicTestProtector::available(),
            witness,
        )?;
        assert_eq!(reopened.current_snapshot.test_sequence(), 3);
        verify_current(&reopened.current_snapshot, &reopened.replay_journal)?;
        Ok(())
    }

    #[test]
    fn coordinator_advances_outer_snapshot_for_maintenance_watermark() -> TestResult {
        let directory = tempfile::tempdir()?;
        let replay_root = directory.path().join("replay");
        let security_state_root = directory.path().join("security-state");
        let witness = CoordinatorWitness::empty();
        let mut coordinator = provision_coordinator(
            &replay_root,
            &security_state_root,
            DeterministicTestProtector::available(),
            witness.clone(),
        )?;

        assert_eq!(
            coordinator.commit_maintenance_watermark(ReplayMaintenanceWatermark::new(7))?,
            ReplaySnapshotCoordinatorMaintenanceOutcome::Advanced
        );
        assert_eq!(coordinator.current_snapshot.test_sequence(), 2);
        assert_eq!(
            coordinator
                .replay_journal
                .state
                .maintenance_expiry_bucket_watermark,
            ReplayMaintenanceWatermark::new(7)
        );
        assert_eq!(coordinator.replay_journal.state.committed_sequence, 0);
        verify_current(&coordinator.current_snapshot, &coordinator.replay_journal)?;
        drop(coordinator);

        let reopened = open_coordinator(
            &replay_root,
            &security_state_root,
            DeterministicTestProtector::available(),
            witness,
        )?;
        assert_eq!(reopened.current_snapshot.test_sequence(), 2);
        assert_eq!(
            reopened
                .replay_journal
                .state
                .maintenance_expiry_bucket_watermark,
            ReplayMaintenanceWatermark::new(7)
        );
        verify_current(&reopened.current_snapshot, &reopened.replay_journal)?;
        Ok(())
    }

    #[test]
    fn coordinator_rejects_watermark_current_rollback_with_zero_entries() -> TestResult {
        let directory = tempfile::tempdir()?;
        let replay_root = directory.path().join("replay");
        let security_state_root = directory.path().join("security-state");
        let witness = CoordinatorWitness::empty();
        let mut coordinator = provision_coordinator(
            &replay_root,
            &security_state_root,
            DeterministicTestProtector::available(),
            witness.clone(),
        )?;
        assert_eq!(
            coordinator.commit_maintenance_watermark(ReplayMaintenanceWatermark::new(7))?,
            ReplaySnapshotCoordinatorMaintenanceOutcome::Advanced
        );
        assert_eq!(coordinator.replay_journal.state.committed_sequence, 0);
        drop(coordinator);

        fs::remove_file(replay_root.join(CURRENT_STATE_FILE))?;
        assert!(matches!(
            open_coordinator(
                &replay_root,
                &security_state_root,
                DeterministicTestProtector::available(),
                witness,
            ),
            Err(ReplaySnapshotCoordinatorOpenError::SnapshotBinding(
                SecurityStateBindingError::ReplayComponentMismatch,
            ))
        ));
        Ok(())
    }

    #[test]
    fn coordinator_noops_nonadvancing_watermark_without_latching() -> TestResult {
        let directory = tempfile::tempdir()?;
        let replay_root = directory.path().join("replay");
        let security_state_root = directory.path().join("security-state");
        let witness = CoordinatorWitness::empty();
        let mut coordinator = provision_coordinator(
            &replay_root,
            &security_state_root,
            DeterministicTestProtector::available(),
            witness,
        )?;
        let initial_snapshot = coordinator.current_snapshot;
        assert_eq!(
            coordinator.commit_maintenance_watermark(ReplayMaintenanceWatermark::NONE)?,
            ReplaySnapshotCoordinatorMaintenanceOutcome::NoAdvance
        );
        assert_eq!(coordinator.current_snapshot, initial_snapshot);
        assert_eq!(
            coordinator
                .replay_journal
                .state
                .maintenance_expiry_bucket_watermark,
            ReplayMaintenanceWatermark::NONE
        );
        assert_eq!(
            coordinator.commit_maintenance_watermark(ReplayMaintenanceWatermark::new(7))?,
            ReplaySnapshotCoordinatorMaintenanceOutcome::Advanced
        );
        let snapshot_at_seven = coordinator.current_snapshot;

        assert_eq!(
            coordinator.commit_maintenance_watermark(ReplayMaintenanceWatermark::new(7))?,
            ReplaySnapshotCoordinatorMaintenanceOutcome::NoAdvance
        );
        assert_eq!(coordinator.health, ReplaySnapshotCoordinatorHealth::Ready);
        assert_eq!(coordinator.current_snapshot, snapshot_at_seven);
        verify_current(&coordinator.current_snapshot, &coordinator.replay_journal)?;

        assert_eq!(
            coordinator.commit_maintenance_watermark(ReplayMaintenanceWatermark::new(8))?,
            ReplaySnapshotCoordinatorMaintenanceOutcome::Advanced
        );
        assert_eq!(coordinator.current_snapshot.test_sequence(), 3);
        verify_current(&coordinator.current_snapshot, &coordinator.replay_journal)?;
        Ok(())
    }

    #[test]
    fn coordinator_latches_when_witness_rejects_after_maintenance_advance() -> TestResult {
        let directory = tempfile::tempdir()?;
        let replay_root = directory.path().join("replay");
        let security_state_root = directory.path().join("security-state");
        let witness = CoordinatorWitness::empty();
        let mut coordinator = provision_coordinator(
            &replay_root,
            &security_state_root,
            DeterministicTestProtector::available(),
            witness.clone(),
        )?;
        witness.set_reject_advance(true);

        assert_eq!(
            coordinator
                .commit_maintenance_watermark(ReplayMaintenanceWatermark::new(7))
                .expect_err("rejected witness must leave maintenance unresolved"),
            ReplaySnapshotCoordinatorMaintenanceError::OuterAdvanceAfterReplay(
                ReplaySnapshotCoordinatorOuterAdvanceError::SecurityState(
                    SecurityStateStoreError::WitnessAdvanceUnresolved,
                ),
            )
        );
        assert_eq!(
            coordinator
                .commit_maintenance_watermark(ReplayMaintenanceWatermark::new(8))
                .expect_err("coordinator must remain latched"),
            ReplaySnapshotCoordinatorMaintenanceError::LatchedIndeterminate
        );

        witness.set_reject_advance(false);
        drop(coordinator);
        assert!(matches!(
            open_coordinator(
                &replay_root,
                &security_state_root,
                DeterministicTestProtector::available(),
                witness,
            ),
            Err(ReplaySnapshotCoordinatorOpenError::SecurityState(
                SecurityStateStoreError::WitnessLocalMismatch,
            ))
        ));
        Ok(())
    }

    #[test]
    fn coordinator_reopens_when_maintenance_witness_advanced_before_error() -> TestResult {
        let directory = tempfile::tempdir()?;
        let replay_root = directory.path().join("replay");
        let security_state_root = directory.path().join("security-state");
        let witness = CoordinatorWitness::empty();
        let mut coordinator = provision_coordinator(
            &replay_root,
            &security_state_root,
            DeterministicTestProtector::available(),
            witness.clone(),
        )?;
        witness.set_advance_then_fail();

        assert_eq!(
            coordinator
                .commit_maintenance_watermark(ReplayMaintenanceWatermark::new(7))
                .expect_err("ambiguous witness result must latch maintenance"),
            ReplaySnapshotCoordinatorMaintenanceError::OuterAdvanceAfterReplay(
                ReplaySnapshotCoordinatorOuterAdvanceError::SecurityState(
                    SecurityStateStoreError::WitnessAdvanceUnresolved,
                ),
            )
        );
        drop(coordinator);

        let reopened = open_coordinator(
            &replay_root,
            &security_state_root,
            DeterministicTestProtector::available(),
            witness,
        )?;
        assert_eq!(reopened.current_snapshot.test_sequence(), 2);
        assert_eq!(
            reopened
                .replay_journal
                .state
                .maintenance_expiry_bucket_watermark,
            ReplayMaintenanceWatermark::new(7)
        );
        verify_current(&reopened.current_snapshot, &reopened.replay_journal)?;
        Ok(())
    }

    #[test]
    fn coordinator_latches_when_witness_rejects_after_replay_commit() -> TestResult {
        let directory = tempfile::tempdir()?;
        let replay_root = directory.path().join("replay");
        let security_state_root = directory.path().join("security-state");
        let witness = CoordinatorWitness::empty();
        let mut coordinator = provision_coordinator(
            &replay_root,
            &security_state_root,
            DeterministicTestProtector::available(),
            witness.clone(),
        )?;
        witness.set_reject_advance(true);
        let (_, round) = security_round();

        assert_eq!(
            coordinator
                .commit_request_and_snapshot(
                    &round,
                    &request_key(1),
                    &ContinuationReplayPlan::Cover,
                )
                .expect_err("rejected witness must withhold replay authority"),
            ReplaySnapshotCoordinatorCommitError::OuterAdvanceAfterReplay(
                ReplaySnapshotCoordinatorOuterAdvanceError::SecurityState(
                    SecurityStateStoreError::WitnessAdvanceUnresolved,
                ),
            )
        );
        assert_eq!(
            coordinator
                .commit_request_and_snapshot(
                    &round,
                    &request_key(2),
                    &ContinuationReplayPlan::Cover,
                )
                .expect_err("coordinator must remain latched"),
            ReplaySnapshotCoordinatorCommitError::LatchedIndeterminate
        );
        assert!(matches!(
            coordinator.commit_request_and_continuation(
                &round,
                &request_key(3),
                &ContinuationReplayPlan::Cover,
            ),
            Err(ReplayCommitUnavailable)
        ));

        witness.set_reject_advance(false);
        drop(coordinator);
        assert!(matches!(
            open_coordinator(
                &replay_root,
                &security_state_root,
                DeterministicTestProtector::available(),
                witness,
            ),
            Err(ReplaySnapshotCoordinatorOpenError::SecurityState(
                SecurityStateStoreError::WitnessLocalMismatch,
            ))
        ));
        Ok(())
    }

    #[test]
    fn coordinator_reopens_when_witness_advanced_before_ambiguous_error() -> TestResult {
        let directory = tempfile::tempdir()?;
        let replay_root = directory.path().join("replay");
        let security_state_root = directory.path().join("security-state");
        let witness = CoordinatorWitness::empty();
        let mut coordinator = provision_coordinator(
            &replay_root,
            &security_state_root,
            DeterministicTestProtector::available(),
            witness.clone(),
        )?;
        witness.set_advance_then_fail();
        let (_, round) = security_round();

        assert_eq!(
            coordinator
                .commit_request_and_snapshot(
                    &round,
                    &request_key(1),
                    &ContinuationReplayPlan::Cover,
                )
                .expect_err("ambiguous witness result must withhold replay authority"),
            ReplaySnapshotCoordinatorCommitError::OuterAdvanceAfterReplay(
                ReplaySnapshotCoordinatorOuterAdvanceError::SecurityState(
                    SecurityStateStoreError::WitnessAdvanceUnresolved,
                ),
            )
        );
        assert_eq!(
            coordinator
                .commit_request_and_snapshot(
                    &round,
                    &request_key(2),
                    &ContinuationReplayPlan::Cover,
                )
                .expect_err("coordinator must remain latched"),
            ReplaySnapshotCoordinatorCommitError::LatchedIndeterminate
        );
        drop(coordinator);

        let reopened = open_coordinator(
            &replay_root,
            &security_state_root,
            DeterministicTestProtector::available(),
            witness,
        )?;
        assert_eq!(reopened.current_snapshot.test_sequence(), 2);
        verify_current(&reopened.current_snapshot, &reopened.replay_journal)?;
        Ok(())
    }

    #[test]
    fn coordinator_latches_on_stale_cached_snapshot_after_replay_commit() -> TestResult {
        let directory = tempfile::tempdir()?;
        let replay_root = directory.path().join("replay");
        let security_state_root = directory.path().join("security-state");
        let witness = CoordinatorWitness::empty();
        let mut coordinator = provision_coordinator(
            &replay_root,
            &security_state_root,
            DeterministicTestProtector::available(),
            witness.clone(),
        )?;
        let (_, round) = security_round();
        drop(coordinator.replay_journal.commit_transaction(
            &round,
            &request_key(1),
            &ContinuationReplayPlan::Cover,
        )?);

        assert_eq!(
            coordinator
                .commit_request_and_snapshot(
                    &round,
                    &request_key(2),
                    &ContinuationReplayPlan::Cover,
                )
                .expect_err("snapshot mismatch after replay must withhold authority"),
            ReplaySnapshotCoordinatorCommitError::OuterAdvanceAfterReplay(
                ReplaySnapshotCoordinatorOuterAdvanceError::SnapshotBinding(
                    SecurityStateBindingError::ReplayComponentMismatch,
                ),
            )
        );
        assert_eq!(
            coordinator.health,
            ReplaySnapshotCoordinatorHealth::Indeterminate
        );
        assert_eq!(
            coordinator
                .commit_request_and_snapshot(
                    &round,
                    &request_key(3),
                    &ContinuationReplayPlan::Cover,
                )
                .expect_err("coordinator must remain latched"),
            ReplaySnapshotCoordinatorCommitError::LatchedIndeterminate
        );
        drop(coordinator);

        assert!(matches!(
            open_coordinator(
                &replay_root,
                &security_state_root,
                DeterministicTestProtector::available(),
                witness,
            ),
            Err(ReplaySnapshotCoordinatorOpenError::SnapshotBinding(
                SecurityStateBindingError::ReplayComponentMismatch,
            ))
        ));
        Ok(())
    }

    #[test]
    fn coordinator_latches_on_outer_stage_failure_after_replay_commit() -> TestResult {
        let directory = tempfile::tempdir()?;
        let replay_root = directory.path().join("replay");
        let security_state_root = directory.path().join("security-state");
        let witness = CoordinatorWitness::empty();
        let mut coordinator = provision_coordinator(
            &replay_root,
            &security_state_root,
            DeterministicTestProtector::available(),
            witness.clone(),
        )?;
        let outer_staging_directory = security_state_root.join(STAGING_DIRECTORY);
        fs::remove_dir(&outer_staging_directory)?;
        fs::write(&outer_staging_directory, b"not a directory")?;
        let (_, round) = security_round();

        assert_eq!(
            coordinator
                .commit_request_and_snapshot(
                    &round,
                    &request_key(1),
                    &ContinuationReplayPlan::Cover,
                )
                .expect_err("outer stage failure after replay must withhold authority"),
            ReplaySnapshotCoordinatorCommitError::OuterAdvanceAfterReplay(
                ReplaySnapshotCoordinatorOuterAdvanceError::SecurityState(
                    SecurityStateStoreError::UnsafeRecoveryPath,
                ),
            )
        );
        assert_eq!(
            coordinator.health,
            ReplaySnapshotCoordinatorHealth::Indeterminate
        );
        assert_eq!(
            coordinator
                .commit_request_and_snapshot(
                    &round,
                    &request_key(2),
                    &ContinuationReplayPlan::Cover,
                )
                .expect_err("coordinator must remain latched"),
            ReplaySnapshotCoordinatorCommitError::LatchedIndeterminate
        );
        drop(coordinator);

        assert!(matches!(
            open_coordinator(
                &replay_root,
                &security_state_root,
                DeterministicTestProtector::available(),
                witness,
            ),
            Err(ReplaySnapshotCoordinatorOpenError::SnapshotBinding(
                SecurityStateBindingError::ReplayComponentMismatch,
            ))
        ));
        Ok(())
    }

    #[test]
    fn coordinator_latches_on_outer_stage_failure_after_maintenance_advance() -> TestResult {
        let directory = tempfile::tempdir()?;
        let replay_root = directory.path().join("replay");
        let security_state_root = directory.path().join("security-state");
        let witness = CoordinatorWitness::empty();
        let mut coordinator = provision_coordinator(
            &replay_root,
            &security_state_root,
            DeterministicTestProtector::available(),
            witness.clone(),
        )?;
        let outer_staging_directory = security_state_root.join(STAGING_DIRECTORY);
        fs::remove_dir(&outer_staging_directory)?;
        fs::write(&outer_staging_directory, b"not a directory")?;

        assert_eq!(
            coordinator
                .commit_maintenance_watermark(ReplayMaintenanceWatermark::new(7))
                .expect_err("outer stage failure after maintenance must latch"),
            ReplaySnapshotCoordinatorMaintenanceError::OuterAdvanceAfterReplay(
                ReplaySnapshotCoordinatorOuterAdvanceError::SecurityState(
                    SecurityStateStoreError::UnsafeRecoveryPath,
                ),
            )
        );
        assert_eq!(
            coordinator.health,
            ReplaySnapshotCoordinatorHealth::Indeterminate
        );
        assert_eq!(
            coordinator
                .commit_maintenance_watermark(ReplayMaintenanceWatermark::new(8))
                .expect_err("coordinator must remain latched"),
            ReplaySnapshotCoordinatorMaintenanceError::LatchedIndeterminate
        );
        drop(coordinator);

        assert!(matches!(
            open_coordinator(
                &replay_root,
                &security_state_root,
                DeterministicTestProtector::available(),
                witness,
            ),
            Err(ReplaySnapshotCoordinatorOpenError::SnapshotBinding(
                SecurityStateBindingError::ReplayComponentMismatch,
            ))
        ));
        Ok(())
    }

    #[test]
    fn coordinator_safe_pre_authority_failure_keeps_pair_ready() -> TestResult {
        let directory = tempfile::tempdir()?;
        let replay_root = directory.path().join("replay");
        let security_state_root = directory.path().join("security-state");
        let witness = CoordinatorWitness::empty();
        let protector = DeterministicTestProtector::available();
        let mut coordinator = provision_coordinator(
            &replay_root,
            &security_state_root,
            protector.clone(),
            witness,
        )?;
        let initial_snapshot = coordinator.current_snapshot;
        let (_, round) = security_round();

        protector.set_available(false);
        assert_eq!(
            coordinator
                .commit_request_and_snapshot(
                    &round,
                    &request_key(1),
                    &ContinuationReplayPlan::Cover,
                )
                .expect_err("protector failure must not mint replay authority"),
            ReplaySnapshotCoordinatorCommitError::ReplayJournal(
                ReplayJournalStoreError::CommittedEntryProtectionUnavailable,
            )
        );
        assert_eq!(coordinator.health, ReplaySnapshotCoordinatorHealth::Ready);
        assert_eq!(coordinator.current_snapshot, initial_snapshot);
        verify_current(&coordinator.current_snapshot, &coordinator.replay_journal)?;

        protector.set_available(true);
        let result = coordinator.commit_request_and_snapshot(
            &round,
            &request_key(1),
            &ContinuationReplayPlan::Cover,
        )?;
        let (_authority, decision) = result.into_parts();
        assert_eq!(decision, ReplayDuplicateDecision::Fresh);
        assert_eq!(coordinator.current_snapshot.test_sequence(), 2);
        verify_current(&coordinator.current_snapshot, &coordinator.replay_journal)?;
        Ok(())
    }

    #[test]
    fn coordinator_preflights_outer_sequence_before_replay_commit() -> TestResult {
        let directory = tempfile::tempdir()?;
        let replay_root = directory.path().join("replay");
        let security_state_root = directory.path().join("security-state");
        let witness = CoordinatorWitness::empty();
        let mut coordinator = provision_coordinator(
            &replay_root,
            &security_state_root,
            DeterministicTestProtector::available(),
            witness,
        )?;
        let initial_snapshot = coordinator.current_snapshot;
        let replay_before = coordinator.replay_journal.state;
        coordinator.current_snapshot = initial_snapshot.test_with_sequence(u64::MAX)?;
        let (_, round) = security_round();

        assert_eq!(
            coordinator
                .commit_request_and_snapshot(
                    &round,
                    &request_key(1),
                    &ContinuationReplayPlan::Cover,
                )
                .expect_err("outer sequence exhaustion must precede replay persistence"),
            ReplaySnapshotCoordinatorCommitError::OuterAdvancePreflight(
                SecurityStateBindingError::InvalidSnapshot(
                    SecurityStateValueError::SequenceOverflow,
                ),
            )
        );
        assert_eq!(coordinator.replay_journal.state, replay_before);
        assert_eq!(
            coordinator.replay_journal.health,
            ReplayJournalStoreHealth::Ready
        );
        assert_eq!(coordinator.health, ReplaySnapshotCoordinatorHealth::Ready);
        assert_eq!(
            coordinator.security_state.current()?,
            Some(initial_snapshot)
        );

        coordinator.current_snapshot = initial_snapshot;
        let result = coordinator.commit_request_and_snapshot(
            &round,
            &request_key(1),
            &ContinuationReplayPlan::Cover,
        )?;
        assert_eq!(result.into_parts().1, ReplayDuplicateDecision::Fresh);
        assert_eq!(coordinator.current_snapshot.test_sequence(), 2);
        Ok(())
    }

    #[test]
    fn coordinator_preflights_outer_sequence_before_maintenance_advance() -> TestResult {
        let directory = tempfile::tempdir()?;
        let replay_root = directory.path().join("replay");
        let security_state_root = directory.path().join("security-state");
        let witness = CoordinatorWitness::empty();
        let mut coordinator = provision_coordinator(
            &replay_root,
            &security_state_root,
            DeterministicTestProtector::available(),
            witness,
        )?;
        let initial_snapshot = coordinator.current_snapshot;
        let replay_before = coordinator.replay_journal.state;
        coordinator.current_snapshot = initial_snapshot.test_with_sequence(u64::MAX)?;

        assert_eq!(
            coordinator
                .commit_maintenance_watermark(ReplayMaintenanceWatermark::new(7))
                .expect_err("outer sequence exhaustion must precede maintenance persistence"),
            ReplaySnapshotCoordinatorMaintenanceError::OuterAdvancePreflight(
                SecurityStateBindingError::InvalidSnapshot(
                    SecurityStateValueError::SequenceOverflow,
                ),
            )
        );
        assert_eq!(coordinator.replay_journal.state, replay_before);
        assert_eq!(
            coordinator.replay_journal.health,
            ReplayJournalStoreHealth::Ready
        );
        assert_eq!(coordinator.health, ReplaySnapshotCoordinatorHealth::Ready);
        assert_eq!(
            coordinator.security_state.current()?,
            Some(initial_snapshot)
        );

        coordinator.current_snapshot = initial_snapshot;
        assert_eq!(
            coordinator.commit_maintenance_watermark(ReplayMaintenanceWatermark::new(7))?,
            ReplaySnapshotCoordinatorMaintenanceOutcome::Advanced
        );
        assert_eq!(coordinator.current_snapshot.test_sequence(), 2);
        Ok(())
    }

    #[test]
    fn coordinator_rejects_a_same_capacity_different_profile() -> TestResult {
        let directory = tempfile::tempdir()?;
        let replay_root = directory.path().join("replay");
        let security_state_root = directory.path().join("security-state");
        let witness = CoordinatorWitness::empty();
        let profile = replay_profile();
        let different_profile = same_capacity_different_profile(profile);
        assert_ne!(different_profile.profile_id(), profile.profile_id());
        assert_eq!(
            different_profile.replay_policy().transaction_capacity(),
            profile.replay_policy().transaction_capacity()
        );
        let rejected_replay_root = directory.path().join("rejected-replay");
        let rejected_security_state_root = directory.path().join("rejected-security-state");
        assert!(matches!(
            ReplaySnapshotCoordinator::provision_initial(
                &rejected_replay_root,
                &rejected_security_state_root,
                &profile,
                protection_context(),
                DeterministicTestProtector::unavailable(),
                CoordinatorWitness::empty(),
                ReplaySnapshotInitialState {
                    identity: test_security_state_identity_with_profile_id(
                        0x71,
                        *different_profile.profile_id(),
                    )?,
                    serving_identity_digest: [0x72; STATE_DIGEST_BYTES],
                },
            ),
            Err(ReplaySnapshotCoordinatorOpenError::ProfileIdentityMismatch)
        ));
        assert!(!rejected_replay_root.exists());
        assert!(!rejected_security_state_root.exists());

        let coordinator = provision_coordinator_with_profile(
            &replay_root,
            &security_state_root,
            &profile,
            DeterministicTestProtector::available(),
            witness.clone(),
        )?;
        drop(coordinator);

        assert!(matches!(
            open_coordinator_with_profile(
                &replay_root,
                &security_state_root,
                &different_profile,
                DeterministicTestProtector::unavailable(),
                witness,
            ),
            Err(ReplaySnapshotCoordinatorOpenError::ProfileIdentityMismatch)
        ));
        Ok(())
    }

    #[test]
    fn provision_rejects_nonempty_journal_from_same_capacity_different_profile() -> TestResult {
        let directory = tempfile::tempdir()?;
        let replay_root = directory.path().join("replay");
        let security_state_root = directory.path().join("security-state");
        let profile_a = replay_profile();
        let profile_b = same_capacity_different_profile(profile_a);
        assert_eq!(
            profile_a.replay_policy().transaction_capacity(),
            profile_b.replay_policy().transaction_capacity()
        );
        assert_ne!(profile_a.profile_id(), profile_b.profile_id());
        let protector = DeterministicTestProtector::available();
        let mut journal = ReplayJournalStore::open(
            &replay_root,
            &profile_a,
            protection_context(),
            protector.clone(),
        )?;
        let (_, round) = security_round();
        journal.commit_transaction(&round, &request_key(1), &ContinuationReplayPlan::Cover)?;
        drop(journal);

        let open_calls_before_rejected_provision = protector.open_calls();
        assert!(matches!(
            ReplaySnapshotCoordinator::provision_initial(
                &replay_root,
                &security_state_root,
                &profile_b,
                protection_context(),
                protector.clone(),
                CoordinatorWitness::empty(),
                ReplaySnapshotInitialState {
                    identity: test_security_state_identity_with_profile_id(
                        0x71,
                        *profile_b.profile_id(),
                    )?,
                    serving_identity_digest: [0x72; STATE_DIGEST_BYTES],
                },
            ),
            Err(ReplaySnapshotCoordinatorOpenError::ReplayJournal(
                ReplayJournalStoreError::ConfigurationMismatch,
            ))
        ));
        assert_eq!(
            protector.open_calls() - open_calls_before_rejected_provision,
            1,
            "profile mismatch must reject after current-state open and before entry reconstruction"
        );
        assert!(!security_state_root.exists());

        let journal = ReplayJournalStore::open(
            &replay_root,
            &profile_a,
            protection_context(),
            protector.clone(),
        )?;
        assert_eq!(journal.state.committed_sequence, 1);
        assert_eq!(journal.state.profile_id, *profile_a.profile_id());
        drop(journal);
        assert_eq!(
            ReplayJournalStore::open(&replay_root, &profile_b, protection_context(), protector,)
                .expect_err("rejected provisioning must not rebind the persisted journal"),
            ReplayJournalStoreError::ConfigurationMismatch
        );
        Ok(())
    }

    #[test]
    fn replay_component_binding_is_exact_across_commit_and_replay_reopen() -> TestResult {
        let directory = tempfile::tempdir()?;
        let mut store = open_store(&directory)?;
        let previous_replay_digest = store.component_state_digest()?;
        let initial = provision_initial_snapshot(
            test_security_state_identity(0x61)?,
            [0x65; STATE_DIGEST_BYTES],
            &store,
        )?;

        assert_ne!(
            initial.component_state_digest(),
            *previous_replay_digest.as_bytes()
        );
        assert_eq!(
            initial.component_state_digest(),
            [
                0x30, 0x64, 0x43, 0xa4, 0x74, 0x04, 0xd8, 0xbc, 0xbd, 0x86, 0xfc, 0x37, 0xfb, 0xa2,
                0xc2, 0x3c, 0x70, 0x22, 0x26, 0x4a, 0x65, 0x80, 0x0c, 0x2b, 0xce, 0x2b, 0x00, 0x5a,
                0x0e, 0x8d, 0xb5, 0xf9,
            ]
        );
        verify_current(&initial, &store)?;
        let no_op_receipt =
            store.test_receipt_for_digests(previous_replay_digest, previous_replay_digest);
        assert_eq!(
            successor_after_replay_commit(&initial, no_op_receipt, &store),
            Err(SecurityStateBindingError::ReplayComponentDidNotAdvance)
        );
        assert_eq!(
            PersistentSecurityState::from_business(&initial).into_business()?,
            initial
        );

        let (_, round) = security_round();
        let committed = store.commit_transaction_and_capture(
            &round,
            &request_key(1),
            &ContinuationReplayPlan::Cover,
        )?;
        assert_eq!(
            format!("{committed:?}"),
            "ReplayJournalCommittedAdvance { ..REDACTED.. }"
        );
        let (_result, receipt) = committed.into_parts();
        assert_eq!(
            format!("{receipt:?}"),
            "ReplayJournalAdvanceReceipt { ..REDACTED.. }"
        );
        assert_eq!(
            verify_current(&initial, &store),
            Err(SecurityStateBindingError::ReplayComponentMismatch)
        );

        let successor = successor_after_replay_commit(&initial, receipt, &store)?;
        assert_ne!(successor, initial);
        verify_current(&successor, &store)?;
        assert_eq!(
            PersistentSecurityState::from_business(&successor).into_business()?,
            successor
        );

        drop(store);
        let reopened = open_store(&directory)?;
        verify_current(&successor, &reopened)?;
        assert_eq!(
            verify_current(&initial, &reopened),
            Err(SecurityStateBindingError::ReplayComponentMismatch)
        );

        let mut reopened = reopened;
        let second_committed = reopened.commit_transaction_and_capture(
            &round,
            &request_key(2),
            &ContinuationReplayPlan::Cover,
        )?;
        let (_result, second_receipt) = second_committed.into_parts();
        assert_eq!(
            successor_after_replay_commit(&initial, second_receipt, &reopened),
            Err(SecurityStateBindingError::ReplayComponentMismatch)
        );
        Ok(())
    }

    #[test]
    fn replay_receipt_requires_its_live_instance_and_current_head() -> TestResult {
        let first_directory = tempfile::tempdir()?;
        let second_directory = tempfile::tempdir()?;
        let mut first_store = open_store(&first_directory)?;
        let mut second_store = open_store(&second_directory)?;
        let initial = provision_initial_snapshot(
            test_security_state_identity(0x62)?,
            [0x66; STATE_DIGEST_BYTES],
            &first_store,
        )?;
        let (_, round) = security_round();

        let first_advance = first_store.commit_transaction_and_capture(
            &round,
            &request_key(1),
            &ContinuationReplayPlan::Cover,
        )?;
        second_store.commit_transaction(&round, &request_key(1), &ContinuationReplayPlan::Cover)?;
        assert_eq!(
            first_store.component_state_digest()?,
            second_store.component_state_digest()?
        );
        let (_result, first_receipt) = first_advance.into_parts();
        assert_eq!(
            successor_after_replay_commit(&initial, first_receipt, &second_store),
            Err(SecurityStateBindingError::ReplayJournalInstanceMismatch)
        );

        let stale_directory = tempfile::tempdir()?;
        let mut stale_store = open_store(&stale_directory)?;
        let stale_initial = provision_initial_snapshot(
            test_security_state_identity(0x63)?,
            [0x67; STATE_DIGEST_BYTES],
            &stale_store,
        )?;
        let stale_advance = stale_store.commit_transaction_and_capture(
            &round,
            &request_key(1),
            &ContinuationReplayPlan::Cover,
        )?;
        stale_store.commit_transaction(&round, &request_key(2), &ContinuationReplayPlan::Cover)?;
        let (_result, stale_receipt) = stale_advance.into_parts();
        assert_eq!(
            successor_after_replay_commit(&stale_initial, stale_receipt, &stale_store),
            Err(SecurityStateBindingError::ReplayReceiptNotCurrent)
        );
        Ok(())
    }

    #[test]
    fn maintenance_receipt_requires_its_live_instance_and_current_head() -> TestResult {
        let first_directory = tempfile::tempdir()?;
        let second_directory = tempfile::tempdir()?;
        let mut first_store = open_store(&first_directory)?;
        let mut second_store = open_store(&second_directory)?;
        let previous_digest = first_store.component_state_digest()?;
        let initial = provision_initial_snapshot(
            test_security_state_identity(0x64)?,
            [0x68; STATE_DIGEST_BYTES],
            &first_store,
        )?;

        let no_op_receipt =
            first_store.test_maintenance_receipt_for_digests(previous_digest, previous_digest);
        assert_eq!(
            successor_after_replay_maintenance(&initial, no_op_receipt, &first_store),
            Err(SecurityStateBindingError::ReplayComponentDidNotAdvance)
        );

        let first_receipt =
            advance_maintenance_watermark(&mut first_store, ReplayMaintenanceWatermark::new(7))?
                .expect("greater watermark must mint a receipt");
        let digest_at_seven = first_store.component_state_digest()?;
        let successor = successor_after_replay_maintenance(&initial, first_receipt, &first_store)?;
        verify_current(&successor, &first_store)?;

        let second_receipt =
            advance_maintenance_watermark(&mut second_store, ReplayMaintenanceWatermark::new(7))?
                .expect("greater watermark must mint a receipt");
        assert_eq!(second_store.component_state_digest()?, digest_at_seven);
        assert_eq!(
            successor_after_replay_maintenance(&initial, second_receipt, &first_store),
            Err(SecurityStateBindingError::ReplayJournalInstanceMismatch)
        );

        advance_maintenance_watermark(&mut first_store, ReplayMaintenanceWatermark::new(8))?
            .expect("greater watermark must advance");
        let stale_receipt =
            first_store.test_maintenance_receipt_for_digests(previous_digest, digest_at_seven);
        assert_eq!(
            successor_after_replay_maintenance(&initial, stale_receipt, &first_store),
            Err(SecurityStateBindingError::ReplayReceiptNotCurrent)
        );
        Ok(())
    }

    #[test]
    fn indeterminate_replay_store_cannot_bind_an_outer_snapshot() -> TestResult {
        let directory = tempfile::tempdir()?;
        let mut store = open_store(&directory)?;
        let initial = provision_initial_snapshot(
            test_security_state_identity(0x71)?,
            [0x75; STATE_DIGEST_BYTES],
            &store,
        )?;
        let (_, round) = security_round();
        let prepared = store.prepare_commit(&request_key(1), &ContinuationReplayPlan::Cover)?;
        let staged_entry = store.stage_entry_file(&prepared)?;
        let replaced_entry = store.replace_entry_file(staged_entry, &prepared)?;
        store.confirm_entry_file_durable(replaced_entry)?;
        let staged_current = store.stage_current_state(&prepared.next_state)?;
        let _replaced_current = store.replace_current_state(staged_current)?;
        // Model a directory-sync failure after the authoritative marker rename.
        assert_eq!(
            store.latch(ReplayJournalStoreError::CurrentStateIndeterminate),
            ReplayJournalStoreError::CurrentStateIndeterminate
        );

        assert_eq!(
            store.component_state_digest(),
            Err(ReplayJournalComponentStateUnavailable)
        );
        assert_eq!(
            provision_initial_snapshot(
                test_security_state_identity(0x72)?,
                [0x76; STATE_DIGEST_BYTES],
                &store,
            ),
            Err(SecurityStateBindingError::ReplayComponentUnavailable)
        );
        assert_eq!(
            verify_current(&initial, &store),
            Err(SecurityStateBindingError::ReplayComponentUnavailable)
        );
        assert!(matches!(
            store.commit_transaction_and_capture(
                &round,
                &request_key(2),
                &ContinuationReplayPlan::Cover,
            ),
            Err(ReplayJournalStoreError::LatchedIndeterminate)
        ));

        drop(store);
        let reopened = open_store(&directory)?;
        assert_eq!(
            verify_current(&initial, &reopened),
            Err(SecurityStateBindingError::ReplayComponentMismatch)
        );
        Ok(())
    }

    #[test]
    fn prepare_derives_fresh_cover_and_fresh_claim_semantics() -> TestResult {
        let directory = tempfile::tempdir()?;
        let store = open_store(&directory)?;
        let cover = store.prepare_commit(&request_key(1), &ContinuationReplayPlan::Cover)?;
        assert_eq!(cover.decision, ReplayDuplicateDecision::Fresh);
        assert_eq!(
            cover.entry.continuation_lane,
            ReplayJournalContinuationLane::Cover
        );

        let claim_key = continuation_key(2);
        let claim_plan = continuation_claim(claim_key, 7);
        let claim = store.prepare_commit(
            &request_key(2),
            &ContinuationReplayPlan::ClaimOrCover(claim_plan),
        )?;
        assert_eq!(claim.decision, ReplayDuplicateDecision::Fresh);
        assert_eq!(
            claim.entry.continuation_lane,
            ReplayJournalContinuationLane::Claim {
                key: *claim_key.as_bytes(),
                expiry_bucket_ordinal: NonZeroU64::new(7)
                    .expect("fixture expiry bucket ordinal is nonzero"),
            }
        );
        Ok(())
    }

    /// The claim sets decide `Fresh` versus duplicate, so the durable footprint
    /// of that decision is the channel that matters: it survives the process,
    /// is readable by anyone with the recovery directory, and is the only part
    /// of the commit an adversary can observe without nanosecond-scale local
    /// measurement. Pin it so a later "skip the write for duplicates"
    /// optimisation cannot make a duplicate cheaper on disk than a fresh claim.
    #[test]
    fn duplicate_cover_commit_matches_the_fresh_claim_durable_footprint() -> TestResult {
        fn footprint(
            store: &ReplayJournalStore<DeterministicTestProtector>,
            sequence: u64,
        ) -> Result<(u64, u64, usize, usize), io::Error> {
            let entry_len = fs::metadata(store.entry_path(sequence))?.len();
            let current_len = fs::metadata(store.current_path())?.len();
            let entries = fs::read_dir(store.entries_directory())?.count();
            let staged = fs::read_dir(store.staging_directory())?.count();
            Ok((entry_len, current_len, entries, staged))
        }

        let fresh_directory = tempfile::tempdir()?;
        let mut fresh_store = open_store(&fresh_directory)?;
        let (_, fresh_round) = security_round();
        let fresh = fresh_store.commit_transaction(
            &fresh_round,
            &request_key(1),
            &ContinuationReplayPlan::ClaimOrCover(continuation_claim(continuation_key(2), 7)),
        )?;
        let (_, fresh_decision) = fresh.into_parts();
        assert_eq!(fresh_decision, ReplayDuplicateDecision::Fresh);

        let duplicate_directory = tempfile::tempdir()?;
        let mut duplicate_store = open_store(&duplicate_directory)?;
        let (_, duplicate_round) = security_round();
        duplicate_store.commit_transaction(
            &duplicate_round,
            &request_key(1),
            &ContinuationReplayPlan::Cover,
        )?;
        let duplicate = duplicate_store.commit_transaction(
            &duplicate_round,
            &request_key(1),
            &ContinuationReplayPlan::ClaimOrCover(continuation_claim(continuation_key(2), 7)),
        )?;
        let (_, duplicate_decision) = duplicate.into_parts();
        assert_eq!(
            duplicate_decision,
            ReplayDuplicateDecision::RequestDuplicate
        );

        // Same per-commit record sizes, one new entry file per commit, and no
        // staging residue — on either decision.
        assert_eq!(
            footprint(&fresh_store, 1)?,
            (ENTRY_RECORD_BYTES as u64, CURRENT_RECORD_BYTES as u64, 1, 0)
        );
        assert_eq!(
            footprint(&duplicate_store, 2)?,
            (ENTRY_RECORD_BYTES as u64, CURRENT_RECORD_BYTES as u64, 2, 0)
        );
        Ok(())
    }

    #[test]
    fn duplicate_request_forces_cover_without_consuming_continuation() -> TestResult {
        let directory = tempfile::tempdir()?;
        let mut store = open_store(&directory)?;
        let (_, round) = security_round();
        let request = request_key(1);
        store.commit_transaction(&round, &request, &ContinuationReplayPlan::Cover)?;
        let new_continuation = continuation_key(2);
        let prepared = store.prepare_commit(
            &request,
            &ContinuationReplayPlan::ClaimOrCover(continuation_claim(new_continuation, 7)),
        )?;

        assert_eq!(prepared.decision, ReplayDuplicateDecision::RequestDuplicate);
        assert_eq!(
            prepared.entry.continuation_lane,
            ReplayJournalContinuationLane::Cover
        );
        assert!(prepared.delta.insert_continuation.is_none());
        Ok(())
    }

    #[test]
    fn duplicate_continuation_claim_commits_fresh_request_only() -> TestResult {
        let directory = tempfile::tempdir()?;
        let mut store = open_store(&directory)?;
        let (_, round) = security_round();
        let continuation = continuation_key(2);
        let first_claim = continuation_claim(continuation, 7);
        let second_claim = continuation_claim(continuation, 8);
        store.commit_transaction(
            &round,
            &request_key(1),
            &ContinuationReplayPlan::ClaimOrCover(first_claim),
        )?;
        let prepared = store.prepare_commit(
            &request_key(2),
            &ContinuationReplayPlan::ClaimOrCover(second_claim),
        )?;

        assert_eq!(
            prepared.decision,
            ReplayDuplicateDecision::ContinuationDuplicate
        );
        assert!(prepared.delta.insert_request.is_some());
        assert!(prepared.delta.insert_continuation.is_none());
        assert_eq!(
            prepared.entry.continuation_lane,
            ReplayJournalContinuationLane::Cover
        );
        Ok(())
    }

    #[test]
    fn recovery_rejects_claim_lane_for_already_claimed_continuation() -> TestResult {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("journal");
        let protector = DeterministicTestProtector::available();
        let first = entry(1, 0x51, claim_lane(0x61, 7));
        let second = entry(2, 0x52, claim_lane(0x61, 8));
        write_entry(&root, &first, &protector)?;
        write_entry(&root, &second, &protector)?;
        let noncanonical_state = ReplayJournalState {
            limits: limits(),
            profile_id: test_profile_id(),
            committed_sequence: 2,
            claimed_request_count: 2,
            claimed_continuation_count: 1,
            entry_chain_digest: [0x71; DIGEST_BYTES],
            maintenance_expiry_bucket_watermark: ReplayMaintenanceWatermark::NONE,
        };
        write_current(&root, &noncanonical_state, &protector)?;

        assert_eq!(
            ReplayJournalStore::open_with_limits(
                root,
                limits(),
                test_profile_id(),
                protection_context(),
                protector,
            )
            .expect_err("duplicate continuation must be recorded as cover"),
            ReplayJournalStoreError::CommittedEntryCorrupt
        );
        Ok(())
    }

    #[test]
    fn profile_transaction_capacity_failure_leaves_state_ready_and_unchanged() -> TestResult {
        let directory = tempfile::tempdir()?;
        let limited_profile = replay_profile().with_test_replay_policy(1, 60, 300)?;
        let mut store = ReplayJournalStore::open(
            directory.path().join("journal"),
            &limited_profile,
            protection_context(),
            DeterministicTestProtector::available(),
        )?;
        let (_, round) = security_round();
        store.commit_transaction(&round, &request_key(1), &ContinuationReplayPlan::Cover)?;
        let before = store.state;

        assert_eq!(
            store
                .prepare_commit(&request_key(2), &ContinuationReplayPlan::Cover)
                .expect_err("second transaction exceeds capacity"),
            ReplayJournalStoreError::TransactionCapacityExceeded
        );
        assert_eq!(store.state, before);
        assert_eq!(store.health, ReplayJournalStoreHealth::Ready);
        Ok(())
    }

    #[test]
    fn expiry_bucket_metadata_does_not_reclaim_transaction_capacity() -> TestResult {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("journal");
        let one_transaction = ReplayJournalLimits::new(1)?;
        let mut store = ReplayJournalStore::open_with_limits(
            root.clone(),
            one_transaction,
            test_profile_id(),
            protection_context(),
            DeterministicTestProtector::available(),
        )?;
        let (_, round) = security_round();
        let claim = continuation_claim(continuation_key(2), 1);
        store.commit_transaction(
            &round,
            &request_key(1),
            &ContinuationReplayPlan::ClaimOrCover(claim),
        )?;
        drop(store);

        let reopened = ReplayJournalStore::open_with_limits(
            root,
            one_transaction,
            test_profile_id(),
            protection_context(),
            DeterministicTestProtector::available(),
        )?;
        assert_eq!(reopened.state.committed_sequence, 1);
        assert_eq!(reopened.state.claimed_request_count, 1);
        assert_eq!(reopened.state.claimed_continuation_count, 1);
        assert!(reopened
            .continuation_claims
            .contains(claim.replay_key_bytes()));
        assert_eq!(
            reopened
                .prepare_commit(&request_key(2), &ContinuationReplayPlan::Cover)
                .expect_err("expiry bucket metadata does not authorize capacity reclamation"),
            ReplayJournalStoreError::TransactionCapacityExceeded
        );
        Ok(())
    }

    #[test]
    fn full_commit_reopens_and_returns_round_authority() -> TestResult {
        let directory = tempfile::tempdir()?;
        let mut store = open_store(&directory)?;
        let (epoch, round) = security_round();
        let result =
            store.commit_transaction(&round, &request_key(1), &ContinuationReplayPlan::Cover)?;
        let (authority, decision) = result.into_parts();

        assert!(authority.matches(&epoch, &round));
        assert_eq!(decision, ReplayDuplicateDecision::Fresh);
        drop(store);
        let reopened = open_store(&directory)?;
        assert_eq!(reopened.state.committed_sequence, 1);
        assert_eq!(reopened.state.claimed_request_count, 1);
        Ok(())
    }

    #[test]
    fn replaced_candidate_is_ignored_then_uniformly_overwritten() -> TestResult {
        let directory = tempfile::tempdir()?;
        let mut store = open_store(&directory)?;
        let (_, round) = security_round();
        let prepared = store.prepare_commit(&request_key(1), &ContinuationReplayPlan::Cover)?;
        let staged = store.stage_entry_file(&prepared)?;
        let replaced = store.replace_entry_file(staged, &prepared)?;
        store.confirm_entry_file_durable(replaced)?;
        drop(store);

        let mut reopened = open_store(&directory)?;
        assert_eq!(reopened.state.committed_sequence, 0);
        let result =
            reopened.commit_transaction(&round, &request_key(2), &ContinuationReplayPlan::Cover)?;
        assert_eq!(result.into_parts().1, ReplayDuplicateDecision::Fresh);
        assert_eq!(reopened.state.committed_sequence, 1);
        assert!(reopened.request_claims.contains(request_key(2).as_bytes()));
        assert!(!reopened.request_claims.contains(request_key(1).as_bytes()));
        Ok(())
    }

    #[test]
    fn candidate_replacement_before_directory_sync_is_non_authoritative() -> TestResult {
        let directory = tempfile::tempdir()?;
        let mut store = open_store(&directory)?;
        let (_, round) = security_round();
        let prepared = store.prepare_commit(&request_key(1), &ContinuationReplayPlan::Cover)?;
        let staged = store.stage_entry_file(&prepared)?;
        let _replaced = store.replace_entry_file(staged, &prepared)?;
        drop(store);

        let mut reopened = open_store(&directory)?;
        assert_eq!(reopened.state.committed_sequence, 0);
        reopened.commit_transaction(&round, &request_key(2), &ContinuationReplayPlan::Cover)?;
        assert_eq!(reopened.state.committed_sequence, 1);
        Ok(())
    }

    #[test]
    fn candidate_presence_and_contents_do_not_change_commit_shape() -> TestResult {
        let candidates = [
            None,
            Some(vec![0x11; 7]),
            Some(vec![0x22; ENTRY_RECORD_BYTES + 1]),
        ];
        for candidate in candidates {
            let directory = tempfile::tempdir()?;
            let root = directory.path().join("journal");
            fs::create_dir_all(root.join(ENTRIES_DIRECTORY))?;
            fs::create_dir_all(root.join(STAGING_DIRECTORY))?;
            if let Some(bytes) = candidate {
                fs::write(root.join(ENTRIES_DIRECTORY).join(entry_filename(1)), bytes)?;
            }
            let mut store = ReplayJournalStore::open_with_limits(
                &root,
                limits(),
                test_profile_id(),
                protection_context(),
                DeterministicTestProtector::available(),
            )?;
            let (_, round) = security_round();
            store.commit_transaction(&round, &request_key(1), &ContinuationReplayPlan::Cover)?;

            assert_eq!(
                fs::metadata(root.join(CURRENT_STATE_FILE))?.len(),
                CURRENT_RECORD_BYTES as u64
            );
            assert_eq!(
                fs::metadata(root.join(ENTRIES_DIRECTORY).join(entry_filename(1)))?.len(),
                ENTRY_RECORD_BYTES as u64
            );
            assert_eq!(fs::read_dir(root.join(ENTRIES_DIRECTORY))?.count(), 1);
            assert_eq!(fs::read_dir(root.join(STAGING_DIRECTORY))?.count(), 0);
        }
        Ok(())
    }

    #[test]
    fn recovery_never_opens_the_non_authoritative_next_candidate() -> TestResult {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("journal");
        let protector = DeterministicTestProtector::available();
        let mut store = ReplayJournalStore::open_with_limits(
            &root,
            limits(),
            test_profile_id(),
            protection_context(),
            protector.clone(),
        )?;
        let (_, round) = security_round();
        store.commit_transaction(&round, &request_key(1), &ContinuationReplayPlan::Cover)?;
        drop(store);
        write_entry(
            &root,
            &entry(2, 0x7f, ReplayJournalContinuationLane::Cover),
            &protector,
        )?;
        let calls_before_open = protector.open_calls();

        let reopened = ReplayJournalStore::open_with_limits(
            root,
            limits(),
            test_profile_id(),
            protection_context(),
            protector.clone(),
        )?;
        assert_eq!(reopened.state.committed_sequence, 1);
        assert_eq!(protector.open_calls() - calls_before_open, 2);
        Ok(())
    }

    #[test]
    fn later_commits_never_replace_committed_entry_bytes() -> TestResult {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("journal");
        let mut store = open_store(&directory)?;
        let (_, round) = security_round();
        store.commit_transaction(&round, &request_key(1), &ContinuationReplayPlan::Cover)?;
        let first_path = root.join(ENTRIES_DIRECTORY).join(entry_filename(1));
        let first_before = fs::read(&first_path)?;

        store.commit_transaction(&round, &request_key(2), &ContinuationReplayPlan::Cover)?;

        assert_eq!(fs::read(first_path)?, first_before);
        Ok(())
    }

    #[test]
    fn durable_current_before_memory_apply_is_recovered_exactly() -> TestResult {
        let directory = tempfile::tempdir()?;
        let mut store = open_store(&directory)?;
        let (_, round) = security_round();
        let request = request_key(1);
        let prepared = store.prepare_commit(&request, &ContinuationReplayPlan::Cover)?;
        let staged_entry = store.stage_entry_file(&prepared)?;
        let replaced_entry = store.replace_entry_file(staged_entry, &prepared)?;
        store.confirm_entry_file_durable(replaced_entry)?;
        let staged_current = store.stage_current_state(&prepared.next_state)?;
        let replaced_current = store.replace_current_state(staged_current)?;
        store.confirm_current_state_durable(replaced_current)?;
        assert_eq!(store.state.committed_sequence, 0);
        drop(store);

        let mut reopened = open_store(&directory)?;
        assert_eq!(reopened.state.committed_sequence, 1);
        let retry =
            reopened.commit_transaction(&round, &request, &ContinuationReplayPlan::Cover)?;
        assert_eq!(
            retry.into_parts().1,
            ReplayDuplicateDecision::RequestDuplicate
        );
        assert_eq!(reopened.state.committed_sequence, 2);
        Ok(())
    }

    #[test]
    fn staged_current_without_replacement_keeps_old_head() -> TestResult {
        let directory = tempfile::tempdir()?;
        let mut store = open_store(&directory)?;
        let (_, round) = security_round();
        let prepared = store.prepare_commit(&request_key(1), &ContinuationReplayPlan::Cover)?;
        let staged_entry = store.stage_entry_file(&prepared)?;
        let replaced_entry = store.replace_entry_file(staged_entry, &prepared)?;
        store.confirm_entry_file_durable(replaced_entry)?;
        let _staged_current = store.stage_current_state(&prepared.next_state)?;
        drop(store);

        let mut reopened = open_store(&directory)?;
        assert_eq!(reopened.state.committed_sequence, 0);
        reopened.commit_transaction(&round, &request_key(2), &ContinuationReplayPlan::Cover)?;
        assert_eq!(reopened.state.committed_sequence, 1);
        Ok(())
    }

    #[test]
    fn replaced_current_before_directory_sync_reopens_as_new_head() -> TestResult {
        let directory = tempfile::tempdir()?;
        let mut store = open_store(&directory)?;
        let prepared = store.prepare_commit(&request_key(1), &ContinuationReplayPlan::Cover)?;
        let staged_entry = store.stage_entry_file(&prepared)?;
        let replaced_entry = store.replace_entry_file(staged_entry, &prepared)?;
        store.confirm_entry_file_durable(replaced_entry)?;
        let staged_current = store.stage_current_state(&prepared.next_state)?;
        let _replaced_current = store.replace_current_state(staged_current)?;
        drop(store);

        let reopened = open_store(&directory)?;
        assert_eq!(reopened.state.committed_sequence, 1);
        assert_eq!(reopened.state.claimed_request_count, 1);
        Ok(())
    }

    #[test]
    fn absent_current_is_empty_without_an_external_freshness_witness() -> TestResult {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("journal");
        fs::create_dir_all(root.join(ENTRIES_DIRECTORY))?;
        fs::create_dir_all(root.join(STAGING_DIRECTORY))?;
        fs::write(root.join(ENTRIES_DIRECTORY).join("unrelated"), [0x11; 7])?;
        fs::write(
            root.join(ENTRIES_DIRECTORY).join(entry_filename(1)),
            [0x22; ENTRY_RECORD_BYTES],
        )?;
        fs::write(root.join(STAGING_DIRECTORY).join("stale.tmp"), [0x33; 9])?;

        let store = ReplayJournalStore::open_with_limits(
            root,
            limits(),
            test_profile_id(),
            protection_context(),
            DeterministicTestProtector::available(),
        )?;
        assert_eq!(
            store.state,
            ReplayJournalState::empty(limits(), test_profile_id())
        );
        Ok(())
    }

    #[test]
    fn recovery_rejects_configuration_mismatch() -> TestResult {
        let directory = tempfile::tempdir()?;
        let mut store = open_store(&directory)?;
        let (_, round) = security_round();
        store.commit_transaction(&round, &request_key(1), &ContinuationReplayPlan::Cover)?;
        drop(store);

        let different_limits = ReplayJournalLimits::new(31)?;
        assert_eq!(
            ReplayJournalStore::open_with_limits(
                directory.path().join("journal"),
                different_limits,
                test_profile_id(),
                protection_context(),
                DeterministicTestProtector::available()
            )
            .expect_err("persisted limits must match"),
            ReplayJournalStoreError::ConfigurationMismatch
        );
        Ok(())
    }

    #[test]
    fn recovery_rejects_a_different_protection_context() -> TestResult {
        let directory = tempfile::tempdir()?;
        let mut store = open_store(&directory)?;
        let (_, round) = security_round();
        store.commit_transaction(&round, &request_key(1), &ContinuationReplayPlan::Cover)?;
        drop(store);

        assert_eq!(
            ReplayJournalStore::open_with_limits(
                directory.path().join("journal"),
                limits(),
                test_profile_id(),
                ReplayJournalProtectionContext::new([0x93; DIGEST_BYTES]),
                DeterministicTestProtector::available(),
            )
            .expect_err("journal context must authenticate the current record"),
            ReplayJournalStoreError::CurrentStateAuthenticationFailed
        );
        Ok(())
    }

    #[test]
    fn recovery_rejects_missing_authoritative_entry() -> TestResult {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("journal");
        let protector = DeterministicTestProtector::available();
        let replay_entry = entry(1, 0x51, ReplayJournalContinuationLane::Cover);
        write_current(&root, &one_entry_state(limits(), &replay_entry), &protector)?;
        fs::create_dir(root.join(ENTRIES_DIRECTORY))?;

        assert_eq!(
            ReplayJournalStore::open_with_limits(
                root,
                limits(),
                test_profile_id(),
                protection_context(),
                protector,
            )
            .expect_err("current requires every authoritative entry"),
            ReplayJournalStoreError::CommittedEntryMissing
        );
        Ok(())
    }

    #[test]
    fn recovery_rejects_current_state_mismatch() -> TestResult {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("journal");
        let protector = DeterministicTestProtector::available();
        let replay_entry = entry(1, 0x51, ReplayJournalContinuationLane::Cover);
        write_entry(&root, &replay_entry, &protector)?;
        let mut mismatched = one_entry_state(limits(), &replay_entry);
        mismatched.entry_chain_digest[0] ^= 1;
        write_current(&root, &mismatched, &protector)?;

        assert_eq!(
            ReplayJournalStore::open_with_limits(
                root,
                limits(),
                test_profile_id(),
                protection_context(),
                protector,
            )
            .expect_err("current must equal reconstructed entries"),
            ReplayJournalStoreError::CurrentStateMismatch
        );
        Ok(())
    }

    #[test]
    fn exact_size_reads_reject_oversized_current_and_entry() -> TestResult {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("journal");
        let protector = DeterministicTestProtector::available();
        let replay_entry = entry(1, 0x51, ReplayJournalContinuationLane::Cover);
        write_entry(&root, &replay_entry, &protector)?;
        write_current(&root, &one_entry_state(limits(), &replay_entry), &protector)?;
        let mut current = fs::read(root.join(CURRENT_STATE_FILE))?;
        current.push(0);
        fs::write(root.join(CURRENT_STATE_FILE), current)?;
        assert_eq!(
            ReplayJournalStore::open_with_limits(
                root.clone(),
                limits(),
                test_profile_id(),
                protection_context(),
                protector.clone(),
            )
            .expect_err("oversized current is corrupt"),
            ReplayJournalStoreError::CurrentStateCorrupt
        );

        write_current(&root, &one_entry_state(limits(), &replay_entry), &protector)?;
        let entry_path = root
            .join(ENTRIES_DIRECTORY)
            .join(entry_filename(replay_entry.sequence));
        let mut entry_bytes = fs::read(&entry_path)?;
        entry_bytes.push(0);
        fs::write(entry_path, entry_bytes)?;
        assert_eq!(
            ReplayJournalStore::open_with_limits(
                root,
                limits(),
                test_profile_id(),
                protection_context(),
                protector,
            )
            .expect_err("oversized authoritative entry is corrupt"),
            ReplayJournalStoreError::CommittedEntryCorrupt
        );
        Ok(())
    }

    #[test]
    fn protection_unavailability_fails_without_authority() -> TestResult {
        let directory = tempfile::tempdir()?;
        let protector = DeterministicTestProtector::available();
        let mut store = ReplayJournalStore::open_with_limits(
            directory.path().join("journal"),
            limits(),
            test_profile_id(),
            protection_context(),
            protector.clone(),
        )?;
        let (_, round) = security_round();
        protector.set_available(false);
        assert_eq!(
            store
                .commit_transaction(&round, &request_key(1), &ContinuationReplayPlan::Cover)
                .expect_err("unavailable protector prevents commit"),
            ReplayJournalStoreError::CommittedEntryProtectionUnavailable
        );
        assert_eq!(store.state.committed_sequence, 0);
        assert_eq!(store.health, ReplayJournalStoreHealth::Ready);
        assert!(ContinuationReplayGuard::commit_request_and_continuation(
            &mut store,
            &round,
            &request_key(1),
            &ContinuationReplayPlan::Cover
        )
        .is_err());
        Ok(())
    }

    #[test]
    fn unavailable_protector_rejects_persisted_current() -> TestResult {
        let directory = tempfile::tempdir()?;
        let mut store = open_store(&directory)?;
        let (_, round) = security_round();
        store.commit_transaction(&round, &request_key(1), &ContinuationReplayPlan::Cover)?;
        drop(store);

        assert_eq!(
            ReplayJournalStore::open_with_limits(
                directory.path().join("journal"),
                limits(),
                test_profile_id(),
                protection_context(),
                DeterministicTestProtector::unavailable()
            )
            .expect_err("current cannot be opened without protection"),
            ReplayJournalStoreError::CurrentStateProtectionUnavailable
        );
        Ok(())
    }

    #[test]
    fn missing_parent_is_rejected_on_first_commit() -> TestResult {
        let directory = tempfile::tempdir()?;
        let missing_parent = directory.path().join("missing").join("journal");
        let mut store = ReplayJournalStore::open_with_limits(
            &missing_parent,
            limits(),
            test_profile_id(),
            protection_context(),
            DeterministicTestProtector::available(),
        )?;
        let (_, round) = security_round();
        assert_eq!(
            store
                .commit_transaction(&round, &request_key(1), &ContinuationReplayPlan::Cover)
                .expect_err("journal parent must already be real"),
            ReplayJournalStoreError::UnsafeRecoveryPath
        );
        assert!(!missing_parent.exists());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_recovery_paths_are_rejected() -> TestResult {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir()?;
        let real = directory.path().join("real");
        fs::create_dir(&real)?;
        let linked_root = directory.path().join("linked-root");
        symlink(&real, &linked_root)?;
        assert_eq!(
            ReplayJournalStore::open_with_limits(
                linked_root,
                limits(),
                test_profile_id(),
                protection_context(),
                DeterministicTestProtector::available()
            )
            .expect_err("symlinked root is unsafe"),
            ReplayJournalStoreError::UnsafeRecoveryPath
        );

        let root = directory.path().join("journal");
        fs::create_dir(&root)?;
        symlink(&real, root.join(ENTRIES_DIRECTORY))?;
        assert_eq!(
            ReplayJournalStore::open_with_limits(
                root,
                limits(),
                test_profile_id(),
                protection_context(),
                DeterministicTestProtector::available(),
            )
            .expect_err("symlinked entries directory is unsafe"),
            ReplayJournalStoreError::UnsafeRecoveryPath
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn next_candidate_symlink_is_replaced_without_touching_its_target() -> TestResult {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir()?;
        let root = directory.path().join("journal");
        let entries = root.join(ENTRIES_DIRECTORY);
        fs::create_dir_all(&entries)?;
        fs::create_dir(root.join(STAGING_DIRECTORY))?;
        let target = directory.path().join("target");
        let target_bytes = [0x7a; 17];
        fs::write(&target, target_bytes)?;
        let candidate = entries.join(entry_filename(1));
        symlink(&target, &candidate)?;

        let mut store = ReplayJournalStore::open_with_limits(
            &root,
            limits(),
            test_profile_id(),
            protection_context(),
            DeterministicTestProtector::available(),
        )?;
        let (_, round) = security_round();
        store.commit_transaction(&round, &request_key(1), &ContinuationReplayPlan::Cover)?;

        assert_eq!(fs::read(target)?, target_bytes);
        assert!(fs::symlink_metadata(candidate)?.file_type().is_file());
        Ok(())
    }
}
