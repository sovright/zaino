//! Crash-durable local replay-journal foundation.
//!
//! The journal records the request lane and the continuation real-or-cover
//! lane as one ordered local transaction. Fixed-size record bodies are sealed
//! behind an injected protector so the first file format does not expose lane
//! tags, replay identities, or counters in plaintext. This module deliberately
//! supplies no production protector, external freshness witness, trusted time,
//! durable nonce owner, runtime wiring, or oblivious memory, page, storage, or
//! timing access. It also assumes exactly one live writer for a recovery
//! directory; no process lock or multi-writer linearizability is provided.

use std::{
    collections::HashSet,
    fmt,
    fs::{self, File},
    io::{self, Read, Write},
    path::{Path, PathBuf},
};

use blake2::{Blake2s256, Digest};
use tempfile::NamedTempFile;

use crate::{
    continuation_token::ContinuationReplayGuard,
    persistence::fs_atomic::{
        create_unique_file, ensure_real_directory, sync_directory, RealDirectoryError,
    },
    protection::{AuthenticationDecision, ProtectionUnavailable},
    runtime_security::{
        ContinuationReplayPlan, ReplayCommitAuthority, ReplayCommitResult, ReplayCommitUnavailable,
        ReplayDuplicateDecision, RequestReplayKey, SecurityRoundCapture, REPLAY_RECORD_KEY_BYTES,
    },
};

const FORMAT_VERSION: u16 = 1;
const U16_BYTES: usize = 2;
const U64_BYTES: usize = 8;
const DIGEST_BYTES: usize = 32;
const RECORD_MAGIC_BYTES: usize = 8;
const PROTECTION_OVERHEAD_BYTES: usize = 40;
const CURRENT_RESERVED_BYTES: usize = 48;
const ENTRY_RESERVED_BYTES: usize = 23;

const CURRENT_MAGIC: [u8; RECORD_MAGIC_BYTES] = *b"ZORJCUR1";
const ENTRY_MAGIC: [u8; RECORD_MAGIC_BYTES] = *b"ZORJENT1";
const CURRENT_STATE_FILE: &str = "current.bin";
const ENTRIES_DIRECTORY: &str = "entries";
const STAGING_DIRECTORY: &str = "staging";
const ENTRY_FILE_SUFFIX: &str = ".bin";

const ENTRY_PAYLOAD_DOMAIN: &[u8] = b"zaino-oram/replay-journal/entry-payload";
const ENTRY_CHAIN_DOMAIN: &[u8] = b"zaino-oram/replay-journal/entry-chain";
const COMPONENT_STATE_DOMAIN: &[u8] = b"zaino-oram/replay-journal/component-state";

const CURRENT_LIMIT_TRANSACTIONS_START: usize = 0;
const CURRENT_SEQUENCE_START: usize = CURRENT_LIMIT_TRANSACTIONS_START + U64_BYTES;
const CURRENT_REQUEST_COUNT_START: usize = CURRENT_SEQUENCE_START + U64_BYTES;
const CURRENT_CONTINUATION_COUNT_START: usize = CURRENT_REQUEST_COUNT_START + U64_BYTES;
const CURRENT_CHAIN_DIGEST_START: usize = CURRENT_CONTINUATION_COUNT_START + U64_BYTES;
const CURRENT_RESERVED_START: usize = CURRENT_CHAIN_DIGEST_START + DIGEST_BYTES;
const CURRENT_BODY_BYTES: usize = CURRENT_RESERVED_START + CURRENT_RESERVED_BYTES;
const CURRENT_PROTECTED_BYTES: usize = CURRENT_BODY_BYTES + PROTECTION_OVERHEAD_BYTES;
const CURRENT_PROTECTED_START: usize = RECORD_MAGIC_BYTES + U16_BYTES;
const CURRENT_RECORD_BYTES: usize = CURRENT_PROTECTED_START + CURRENT_PROTECTED_BYTES;

const ENTRY_SEQUENCE_START: usize = 0;
const ENTRY_REQUEST_KEY_START: usize = ENTRY_SEQUENCE_START + U64_BYTES;
const ENTRY_CONTINUATION_TAG_START: usize = ENTRY_REQUEST_KEY_START + REPLAY_RECORD_KEY_BYTES;
const ENTRY_CONTINUATION_KEY_START: usize = ENTRY_CONTINUATION_TAG_START + 1;
const ENTRY_RESERVED_START: usize = ENTRY_CONTINUATION_KEY_START + REPLAY_RECORD_KEY_BYTES;
const ENTRY_BODY_BYTES: usize = ENTRY_RESERVED_START + ENTRY_RESERVED_BYTES;
const ENTRY_PROTECTED_BYTES: usize = ENTRY_BODY_BYTES + PROTECTION_OVERHEAD_BYTES;
const ENTRY_PROTECTED_START: usize = RECORD_MAGIC_BYTES + U16_BYTES;
const ENTRY_RECORD_BYTES: usize = ENTRY_PROTECTED_START + ENTRY_PROTECTED_BYTES;

const CONTINUATION_COVER_TAG: u8 = 0;
const CONTINUATION_CLAIM_TAG: u8 = 1;

const _: [(); 112] = [(); CURRENT_BODY_BYTES];
const _: [(); 162] = [(); CURRENT_RECORD_BYTES];
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
trait ReplayJournalRecordProtector {
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
struct ReplayJournalProtectionContext([u8; DIGEST_BYTES]);

impl ReplayJournalProtectionContext {
    const fn new(binding: [u8; DIGEST_BYTES]) -> Self {
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

#[derive(Clone, Copy)]
enum ReplayJournalRecordKind {
    CurrentStateV1,
    ImmutableEntryV1,
}

impl ReplayJournalRecordKind {
    const fn tag(self) -> u8 {
        match self {
            Self::CurrentStateV1 => 0,
            Self::ImmutableEntryV1 => 1,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct ReplayJournalLimits {
    max_transactions: u64,
}

impl ReplayJournalLimits {
    fn new(max_transactions: u64) -> Result<Self, ReplayJournalValueError> {
        if max_transactions == 0 {
            return Err(ReplayJournalValueError::ZeroLimit);
        }
        Ok(Self { max_transactions })
    }
}

impl fmt::Debug for ReplayJournalLimits {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ReplayJournalLimits { ..REDACTED.. }")
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ReplayJournalContinuationLane {
    Cover,
    Claim([u8; REPLAY_RECORD_KEY_BYTES]),
}

impl fmt::Debug for ReplayJournalContinuationLane {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ReplayJournalContinuationLane([REDACTED])")
    }
}

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
            ReplayJournalContinuationLane::Claim(key) => {
                body[ENTRY_CONTINUATION_TAG_START] = CONTINUATION_CLAIM_TAG;
                body[ENTRY_CONTINUATION_KEY_START..ENTRY_RESERVED_START].copy_from_slice(&key);
            }
        }
        body
    }

    fn payload_digest(&self) -> [u8; DIGEST_BYTES] {
        versioned_digest(ENTRY_PAYLOAD_DOMAIN, &[&self.canonical_body()])
    }
}

impl fmt::Debug for ReplayJournalEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ReplayJournalEntry { ..REDACTED.. }")
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct ReplayJournalState {
    limits: ReplayJournalLimits,
    committed_sequence: u64,
    claimed_request_count: u64,
    claimed_continuation_count: u64,
    entry_chain_digest: [u8; DIGEST_BYTES],
}

impl ReplayJournalState {
    const fn empty(limits: ReplayJournalLimits) -> Self {
        Self {
            limits,
            committed_sequence: 0,
            claimed_request_count: 0,
            claimed_continuation_count: 0,
            entry_chain_digest: [0; DIGEST_BYTES],
        }
    }

    fn validate(&self) -> Result<(), ReplayJournalValueError> {
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
                ReplayJournalContinuationLane::Claim(key) => {
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
            &[&self.entry_chain_digest, &payload_digest],
        );
        let next = Self {
            limits: self.limits,
            committed_sequence: entry.sequence,
            claimed_request_count,
            claimed_continuation_count,
            entry_chain_digest,
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

    fn component_state_digest(&self) -> [u8; DIGEST_BYTES] {
        versioned_digest(
            COMPONENT_STATE_DOMAIN,
            &[
                &self.limits.max_transactions.to_be_bytes(),
                &self.committed_sequence.to_be_bytes(),
                &self.claimed_request_count.to_be_bytes(),
                &self.claimed_continuation_count.to_be_bytes(),
                &self.entry_chain_digest,
            ],
        )
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
    InvalidState,
    InvalidContinuationTag,
    NonZeroReservedBytes,
    NonZeroCoverKey,
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

struct PersistentReplayJournalCurrentState([u8; CURRENT_RECORD_BYTES]);

impl PersistentReplayJournalCurrentState {
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
        if state.committed_sequence == 0 {
            return Err(ReplayJournalRecordError::InvalidValue(
                ReplayJournalValueError::InvalidState,
            ));
        }

        let mut body = [0; CURRENT_BODY_BYTES];
        body[CURRENT_LIMIT_TRANSACTIONS_START..CURRENT_SEQUENCE_START]
            .copy_from_slice(&state.limits.max_transactions.to_be_bytes());
        body[CURRENT_SEQUENCE_START..CURRENT_REQUEST_COUNT_START]
            .copy_from_slice(&state.committed_sequence.to_be_bytes());
        body[CURRENT_REQUEST_COUNT_START..CURRENT_CONTINUATION_COUNT_START]
            .copy_from_slice(&state.claimed_request_count.to_be_bytes());
        body[CURRENT_CONTINUATION_COUNT_START..CURRENT_CHAIN_DIGEST_START]
            .copy_from_slice(&state.claimed_continuation_count.to_be_bytes());
        body[CURRENT_CHAIN_DIGEST_START..CURRENT_RESERVED_START]
            .copy_from_slice(&state.entry_chain_digest);

        let mut bytes = [0; CURRENT_RECORD_BYTES];
        bytes[..RECORD_MAGIC_BYTES].copy_from_slice(&CURRENT_MAGIC);
        bytes[RECORD_MAGIC_BYTES..CURRENT_PROTECTED_START]
            .copy_from_slice(&FORMAT_VERSION.to_be_bytes());
        protector
            .seal(
                context,
                ReplayJournalRecordKind::CurrentStateV1,
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
        validate_header(&self.0, CURRENT_MAGIC)?;
        let mut body = [0; CURRENT_BODY_BYTES];
        match protector
            .open(
                context,
                ReplayJournalRecordKind::CurrentStateV1,
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
            committed_sequence: read_u64(&body, CURRENT_SEQUENCE_START),
            claimed_request_count: read_u64(&body, CURRENT_REQUEST_COUNT_START),
            claimed_continuation_count: read_u64(&body, CURRENT_CONTINUATION_COUNT_START),
            entry_chain_digest: read_array(&body, CURRENT_CHAIN_DIGEST_START),
        };
        state
            .validate()
            .map_err(ReplayJournalRecordError::InvalidValue)?;
        if state.committed_sequence == 0 {
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

impl fmt::Debug for PersistentReplayJournalCurrentState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PersistentReplayJournalCurrentState([REDACTED])")
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
            .copy_from_slice(&FORMAT_VERSION.to_be_bytes());
        protector
            .seal(
                context,
                ReplayJournalRecordKind::ImmutableEntryV1,
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
        validate_header(&self.0, ENTRY_MAGIC)?;
        let mut body = [0; ENTRY_BODY_BYTES];
        match protector
            .open(
                context,
                ReplayJournalRecordKind::ImmutableEntryV1,
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
        let continuation_lane = match body[ENTRY_CONTINUATION_TAG_START] {
            CONTINUATION_COVER_TAG => {
                if continuation_key != [0; REPLAY_RECORD_KEY_BYTES] {
                    return Err(ReplayJournalRecordError::InvalidValue(
                        ReplayJournalValueError::NonZeroCoverKey,
                    ));
                }
                ReplayJournalContinuationLane::Cover
            }
            CONTINUATION_CLAIM_TAG => ReplayJournalContinuationLane::Claim(continuation_key),
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

impl fmt::Debug for PreparedReplayJournalCommit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PreparedReplayJournalCommit { ..REDACTED.. }")
    }
}

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

struct ReplayJournalStore<P> {
    recovery_directory: PathBuf,
    protection_context: ReplayJournalProtectionContext,
    protector: P,
    state: ReplayJournalState,
    request_claims: HashSet<[u8; REPLAY_RECORD_KEY_BYTES]>,
    continuation_claims: HashSet<[u8; REPLAY_RECORD_KEY_BYTES]>,
    health: ReplayJournalStoreHealth,
}

impl<P> ReplayJournalStore<P>
where
    P: ReplayJournalRecordProtector,
{
    fn open(
        root: impl Into<PathBuf>,
        limits: ReplayJournalLimits,
        protection_context: ReplayJournalProtectionContext,
        protector: P,
    ) -> Result<Self, ReplayJournalStoreError> {
        let recovery_directory = root.into();
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
                    state: ReplayJournalState::empty(limits),
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
        let persisted_state = PersistentReplayJournalCurrentState(current_bytes)
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
        if persisted_state.limits != limits {
            return Err(ReplayJournalStoreError::ConfigurationMismatch);
        }

        let entries_directory = recovery_directory.join(ENTRIES_DIRECTORY);
        validate_committed_entries_directory(&entries_directory)?;
        let mut state = ReplayJournalState::empty(limits);
        let mut request_claims = HashSet::new();
        let mut continuation_claims = HashSet::new();
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
        if state != persisted_state {
            return Err(ReplayJournalStoreError::CurrentStateMismatch);
        }
        Ok(Self {
            recovery_directory,
            protection_context,
            protector,
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
                ContinuationReplayPlan::ClaimOrCover(key) => {
                    let key = *key.as_bytes();
                    if self.continuation_claims.contains(&key) {
                        (
                            ReplayJournalContinuationLane::Cover,
                            ReplayDuplicateDecision::ContinuationDuplicate,
                        )
                    } else {
                        (
                            ReplayJournalContinuationLane::Claim(key),
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
        &mut self,
        prepared: &PreparedReplayJournalCommit,
    ) -> Result<StagedReplayJournalCurrentState, ReplayJournalStoreError> {
        let persistent = PersistentReplayJournalCurrentState::from_business(
            &prepared.next_state,
            &self.protection_context,
            &self.protector,
        )
        .map_err(|error| self.latch(map_current_record_for_commit(error)))?;
        let mut file = create_unique_file(&self.staging_directory(), "replay-current")
            .map_err(|_| self.latch(ReplayJournalStoreError::CandidateStateIndeterminate))?;
        file.write_all(persistent.as_bytes())
            .and_then(|()| file.as_file().sync_all())
            .map_err(|_| self.latch(ReplayJournalStoreError::CandidateStateIndeterminate))?;
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
        let prepared = self.prepare_commit(request_key, continuation_plan)?;
        let staged_entry = self.stage_entry_file(&prepared)?;
        let replaced_entry = self.replace_entry_file(staged_entry, &prepared)?;
        self.confirm_entry_file_durable(replaced_entry)?;
        let staged_current = self.stage_current_state(&prepared)?;
        let replaced_current = self.replace_current_state(staged_current)?;
        self.confirm_current_state_durable(replaced_current)?;
        Ok(self.apply_prepared_commit_in_memory(security_round, prepared))
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
enum ReplayJournalStoreError {
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
) -> Result<(), ReplayJournalRecordError> {
    if bytes[..RECORD_MAGIC_BYTES] != expected_magic {
        return Err(ReplayJournalRecordError::InvalidMagic);
    }
    if read_u16(bytes, RECORD_MAGIC_BYTES) != FORMAT_VERSION {
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

fn versioned_digest(domain: &[u8], parts: &[&[u8]]) -> [u8; DIGEST_BYTES] {
    let mut hasher = Blake2s256::new();
    Digest::update(&mut hasher, domain);
    Digest::update(&mut hasher, FORMAT_VERSION.to_be_bytes());
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
    use std::{cell::Cell, error::Error, fs, rc::Rc};

    use tempfile::TempDir;

    use super::*;
    use crate::runtime_security::{ContinuationReplayKey, ReplayNamespace, SecurityEpochTag};

    const TEST_PROTECTION_NONCE_BYTES: usize = 24;
    const TEST_PROTECTION_AUTHENTICATION_BYTES: usize = 16;
    const TEST_NONCE_DOMAIN: &[u8] = b"zaino-oram/replay-journal/test-nonce";
    const TEST_STREAM_DOMAIN: &[u8] = b"zaino-oram/replay-journal/test-stream";
    const TEST_AUTHENTICATION_DOMAIN: &[u8] = b"zaino-oram/replay-journal/test-authentication";
    const TEST_KEY: [u8; DIGEST_BYTES] = [0x91; DIGEST_BYTES];

    type TestResult = Result<(), Box<dyn Error>>;

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

    fn security_round() -> (SecurityEpochTag, SecurityRoundCapture) {
        let epoch = SecurityEpochTag::new([0x44; 32]);
        let round = SecurityRoundCapture::new(&epoch);
        (epoch, round)
    }

    fn open_store(
        directory: &TempDir,
    ) -> Result<ReplayJournalStore<DeterministicTestProtector>, ReplayJournalStoreError> {
        ReplayJournalStore::open(
            directory.path().join("journal"),
            limits(),
            protection_context(),
            DeterministicTestProtector::available(),
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
        ReplayJournalState::empty(limits)
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
        let persistent = PersistentReplayJournalCurrentState::from_business(
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
        let replay_entry = entry(
            1,
            0x51,
            ReplayJournalContinuationLane::Claim([0x61; REPLAY_RECORD_KEY_BYTES]),
        );
        let state = one_entry_state(limits(), &replay_entry);
        let persistent_entry =
            PersistentReplayJournalEntry::from_business(&replay_entry, &context, &protector)?;
        let persistent_current =
            PersistentReplayJournalCurrentState::from_business(&state, &context, &protector)?;

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
        assert!(!persistent_entry
            .as_bytes()
            .windows(REPLAY_RECORD_KEY_BYTES)
            .any(|window| window == replay_entry.request_key));
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
            PersistentReplayJournalCurrentState(*persistent_current.as_bytes())
                .into_business(&context, &protector)?,
            state
        );
        Ok(())
    }

    #[test]
    fn record_headers_and_authentication_fail_closed() -> TestResult {
        let protector = DeterministicTestProtector::available();
        let context = protection_context();
        let replay_entry = entry(1, 0x51, ReplayJournalContinuationLane::Cover);
        let persistent =
            PersistentReplayJournalEntry::from_business(&replay_entry, &context, &protector)?;

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
        let mut tag_record = [0; ENTRY_RECORD_BYTES];
        tag_record[..RECORD_MAGIC_BYTES].copy_from_slice(&ENTRY_MAGIC);
        tag_record[RECORD_MAGIC_BYTES..ENTRY_PROTECTED_START]
            .copy_from_slice(&FORMAT_VERSION.to_be_bytes());
        protector.seal(
            &context,
            ReplayJournalRecordKind::ImmutableEntryV1,
            &invalid_tag,
            &mut tag_record[ENTRY_PROTECTED_START..],
        )?;
        assert!(matches!(
            PersistentReplayJournalEntry(tag_record).into_business(&context, &protector),
            Err(ReplayJournalRecordError::InvalidValue(
                ReplayJournalValueError::InvalidContinuationTag
            ))
        ));

        let mut nonzero_cover =
            entry(1, 0x51, ReplayJournalContinuationLane::Cover).canonical_body();
        nonzero_cover[ENTRY_CONTINUATION_KEY_START] = 1;
        let mut cover_record = [0; ENTRY_RECORD_BYTES];
        cover_record[..RECORD_MAGIC_BYTES].copy_from_slice(&ENTRY_MAGIC);
        cover_record[RECORD_MAGIC_BYTES..ENTRY_PROTECTED_START]
            .copy_from_slice(&FORMAT_VERSION.to_be_bytes());
        protector.seal(
            &context,
            ReplayJournalRecordKind::ImmutableEntryV1,
            &nonzero_cover,
            &mut cover_record[ENTRY_PROTECTED_START..],
        )?;
        assert!(matches!(
            PersistentReplayJournalEntry(cover_record).into_business(&context, &protector),
            Err(ReplayJournalRecordError::InvalidValue(
                ReplayJournalValueError::NonZeroCoverKey
            ))
        ));
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
            ReplayJournalRecordKind::ImmutableEntryV1,
            &plaintext,
            &mut protected,
        )?;
        protected[TEST_PROTECTION_AUTHENTICATION_BYTES] ^= 1;
        let mut output = [0; ENTRY_BODY_BYTES];
        assert_eq!(
            protector.open(
                &context,
                ReplayJournalRecordKind::ImmutableEntryV1,
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
        let replay_entry = entry(
            1,
            0x51,
            ReplayJournalContinuationLane::Claim([0x61; REPLAY_RECORD_KEY_BYTES]),
        );
        let state = one_entry_state(limits(), &replay_entry);
        assert_eq!(
            format!("{replay_entry:?}"),
            "ReplayJournalEntry { ..REDACTED.. }"
        );
        assert_eq!(format!("{state:?}"), "ReplayJournalState { ..REDACTED.. }");
    }

    #[test]
    fn entry_payload_digest_binds_every_semantic_field() {
        let baseline = entry(
            1,
            0x51,
            ReplayJournalContinuationLane::Claim([0x61; REPLAY_RECORD_KEY_BYTES]),
        );
        assert_ne!(
            baseline.payload_digest(),
            entry(
                2,
                0x51,
                ReplayJournalContinuationLane::Claim([0x61; REPLAY_RECORD_KEY_BYTES])
            )
            .payload_digest()
        );
        assert_ne!(
            baseline.payload_digest(),
            entry(
                1,
                0x52,
                ReplayJournalContinuationLane::Claim([0x61; REPLAY_RECORD_KEY_BYTES])
            )
            .payload_digest()
        );
        assert_ne!(
            baseline.payload_digest(),
            entry(1, 0x51, ReplayJournalContinuationLane::Cover).payload_digest()
        );
        assert_ne!(
            baseline.payload_digest(),
            entry(
                1,
                0x51,
                ReplayJournalContinuationLane::Claim([0x62; REPLAY_RECORD_KEY_BYTES])
            )
            .payload_digest()
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
        let (first_state, _) = ReplayJournalState::empty(limits())
            .apply_entry(&mut requests, &mut continuations, &first)
            .expect("first fixture entry is valid");
        let (ordered, _) = first_state
            .apply_entry(&mut requests, &mut continuations, &second)
            .expect("second fixture entry is valid");

        let mut swapped_requests = HashSet::new();
        let mut swapped_continuations = HashSet::new();
        let (swapped_first_state, _) = ReplayJournalState::empty(limits())
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
        let claim = store.prepare_commit(
            &request_key(2),
            &ContinuationReplayPlan::ClaimOrCover(claim_key),
        )?;
        assert_eq!(claim.decision, ReplayDuplicateDecision::Fresh);
        assert_eq!(
            claim.entry.continuation_lane,
            ReplayJournalContinuationLane::Claim(*claim_key.as_bytes())
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
            &ContinuationReplayPlan::ClaimOrCover(new_continuation),
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
        store.commit_transaction(
            &round,
            &request_key(1),
            &ContinuationReplayPlan::ClaimOrCover(continuation),
        )?;
        let prepared = store.prepare_commit(
            &request_key(2),
            &ContinuationReplayPlan::ClaimOrCover(continuation),
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
        let continuation = [0x61; REPLAY_RECORD_KEY_BYTES];
        let first = entry(1, 0x51, ReplayJournalContinuationLane::Claim(continuation));
        let second = entry(2, 0x52, ReplayJournalContinuationLane::Claim(continuation));
        write_entry(&root, &first, &protector)?;
        write_entry(&root, &second, &protector)?;
        let noncanonical_state = ReplayJournalState {
            limits: limits(),
            committed_sequence: 2,
            claimed_request_count: 2,
            claimed_continuation_count: 1,
            entry_chain_digest: [0x71; DIGEST_BYTES],
        };
        write_current(&root, &noncanonical_state, &protector)?;

        assert_eq!(
            ReplayJournalStore::open(root, limits(), protection_context(), protector)
                .expect_err("duplicate continuation must be recorded as cover"),
            ReplayJournalStoreError::CommittedEntryCorrupt
        );
        Ok(())
    }

    #[test]
    fn transaction_capacity_failure_leaves_state_ready_and_unchanged() -> TestResult {
        let directory = tempfile::tempdir()?;
        let limited = ReplayJournalLimits::new(1)?;
        let mut store = ReplayJournalStore::open(
            directory.path().join("journal"),
            limited,
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
            let mut store = ReplayJournalStore::open(
                &root,
                limits(),
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
        let mut store =
            ReplayJournalStore::open(&root, limits(), protection_context(), protector.clone())?;
        let (_, round) = security_round();
        store.commit_transaction(&round, &request_key(1), &ContinuationReplayPlan::Cover)?;
        drop(store);
        write_entry(
            &root,
            &entry(2, 0x7f, ReplayJournalContinuationLane::Cover),
            &protector,
        )?;
        let calls_before_open = protector.open_calls();

        let reopened =
            ReplayJournalStore::open(root, limits(), protection_context(), protector.clone())?;
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
        let staged_current = store.stage_current_state(&prepared)?;
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
        let _staged_current = store.stage_current_state(&prepared)?;
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
        let staged_current = store.stage_current_state(&prepared)?;
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

        let store = ReplayJournalStore::open(
            root,
            limits(),
            protection_context(),
            DeterministicTestProtector::available(),
        )?;
        assert_eq!(store.state, ReplayJournalState::empty(limits()));
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
            ReplayJournalStore::open(
                directory.path().join("journal"),
                different_limits,
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
            ReplayJournalStore::open(
                directory.path().join("journal"),
                limits(),
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
            ReplayJournalStore::open(root, limits(), protection_context(), protector)
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
            ReplayJournalStore::open(root, limits(), protection_context(), protector)
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
            ReplayJournalStore::open(
                root.clone(),
                limits(),
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
            ReplayJournalStore::open(root, limits(), protection_context(), protector)
                .expect_err("oversized authoritative entry is corrupt"),
            ReplayJournalStoreError::CommittedEntryCorrupt
        );
        Ok(())
    }

    #[test]
    fn protection_unavailability_fails_without_authority() -> TestResult {
        let directory = tempfile::tempdir()?;
        let protector = DeterministicTestProtector::available();
        let mut store = ReplayJournalStore::open(
            directory.path().join("journal"),
            limits(),
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
            ReplayJournalStore::open(
                directory.path().join("journal"),
                limits(),
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
        let mut store = ReplayJournalStore::open(
            &missing_parent,
            limits(),
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
            ReplayJournalStore::open(
                linked_root,
                limits(),
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
            ReplayJournalStore::open(
                root,
                limits(),
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

        let mut store = ReplayJournalStore::open(
            &root,
            limits(),
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
