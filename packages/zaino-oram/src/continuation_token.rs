//! Fixed continuation-token codec and replay-admission preparation.
//!
//! Token expiry is evaluated against a caller-supplied Unix-seconds
//! observation. This module neither establishes that observation as trusted
//! time nor authorizes replay-journal claim retirement from it.

use std::{fmt, mem::size_of};

use blake2::{Blake2s256, Digest};

use crate::{
    profile::PROFILE_ID_BYTES,
    protection::{AuthenticationDecision, ProtectionUnavailable},
    runtime_security::{
        ContinuationReplayKey, ContinuationReplayPlan, ReplayCommitAuthority, ReplayCommitResult,
        ReplayCommitUnavailable, ReplayDuplicateDecision, ReplayNamespace, RequestReplayKey,
        SecurityRoundCapture,
    },
};

mod xchacha20;

const QUERY_DIGEST_BYTES: usize = 32;
const NONCE_BYTES: usize = 24;
const AUTHENTICATION_BYTES: usize = 16;
const PROTECTED_BODY_BYTES: usize = 88;
const CONTINUATION_CONTEXT_DIGEST_VERSION: u16 = 1;
const CONTINUATION_CONTEXT_DIGEST_DOMAIN: &[u8] = b"zaino-oram/continuation-token/context-digest";
pub(super) const CONTINUATION_VERSION: u16 = 1;
pub(super) const CONTINUATION_CONTEXT_BYTES: usize = 89;
pub(super) const CONTINUATION_TOKEN_BYTES: usize =
    NONCE_BYTES + PROTECTED_BODY_BYTES + AUTHENTICATION_BYTES;

const VERSION_START: usize = 0;
const PROFILE_ID_START: usize = VERSION_START + size_of::<u16>();
const QUERY_DIGEST_START: usize = PROFILE_ID_START + PROFILE_ID_BYTES;
const PROJECTION_EPOCH_START: usize = QUERY_DIGEST_START + QUERY_DIGEST_BYTES;
const CURSOR_START: usize = PROJECTION_EPOCH_START + size_of::<u64>();
const EXPIRY_START: usize = CURSOR_START + size_of::<u64>();
const RESERVED_START: usize = EXPIRY_START + size_of::<u64>();

const PROTECTED_BODY_TOKEN_START: usize = NONCE_BYTES;
const AUTHENTICATION_TOKEN_START: usize = PROTECTED_BODY_TOKEN_START + PROTECTED_BODY_BYTES;

/// Canonical checkpoint and session-binding bytes used as token-protector
/// associated data.
///
/// The projection epoch is intended to roll on every restart/rebuild so tokens
/// from an earlier volatile worker lifecycle cannot be replayed into the new
/// candidate. The checkpoint still has no authenticated semantic projection
/// root; adding one requires a token format and profile version change.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct ContinuationProtectionContext([u8; CONTINUATION_CONTEXT_BYTES]);

impl ContinuationProtectionContext {
    pub(super) const fn new(bytes: [u8; CONTINUATION_CONTEXT_BYTES]) -> Self {
        Self(bytes)
    }

    pub(super) const fn as_bytes(&self) -> &[u8; CONTINUATION_CONTEXT_BYTES] {
        &self.0
    }
}

impl fmt::Debug for ContinuationProtectionContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ContinuationProtectionContext { ..REDACTED.. }")
    }
}

/// State carried between fixed-shape private query rounds.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct ContinuationState {
    version: u16,
    profile_id: [u8; PROFILE_ID_BYTES],
    query_digest: [u8; QUERY_DIGEST_BYTES],
    projection_epoch: u64,
    cursor: u64,
    expires_at_unix_seconds: u64,
    nonce: [u8; NONCE_BYTES],
}

impl ContinuationState {
    pub(super) const fn new(
        version: u16,
        profile_id: [u8; PROFILE_ID_BYTES],
        query_digest: [u8; QUERY_DIGEST_BYTES],
        projection_epoch: u64,
        cursor: u64,
        expires_at_unix_seconds: u64,
        nonce: [u8; NONCE_BYTES],
    ) -> Self {
        Self {
            version,
            profile_id,
            query_digest,
            projection_epoch,
            cursor,
            expires_at_unix_seconds,
            nonce,
        }
    }
}

impl fmt::Debug for ContinuationState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ContinuationState { ..REDACTED.. }")
    }
}

/// Expected public and request-bound values for token validation.
///
/// `now_unix_seconds` is an observed host/fixture input. The expiry comparison
/// below enforces token semantics for that observation; it is not evidence of
/// a monotonic or rollback-resistant time authority.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct ContinuationExpectation {
    version: u16,
    profile_id: [u8; PROFILE_ID_BYTES],
    query_digest: [u8; QUERY_DIGEST_BYTES],
    projection_epoch: u64,
    now_unix_seconds: u64,
    cursor_limit: u64,
}

impl ContinuationExpectation {
    pub(super) const fn new(
        version: u16,
        profile_id: [u8; PROFILE_ID_BYTES],
        query_digest: [u8; QUERY_DIGEST_BYTES],
        projection_epoch: u64,
        now_unix_seconds: u64,
        cursor_limit: u64,
    ) -> Self {
        Self {
            version,
            profile_id,
            query_digest,
            projection_epoch,
            now_unix_seconds,
            cursor_limit,
        }
    }
}

impl fmt::Debug for ContinuationExpectation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ContinuationExpectation { ..REDACTED.. }")
    }
}

/// An opaque, exactly sized continuation token.
///
/// This type defines only the fixed codec and validation contract. The injected
/// protector must provide reviewed authenticated encryption before this format
/// is used outside the deterministic research model.
#[repr(transparent)]
#[derive(Clone, PartialEq, Eq)]
pub(super) struct ContinuationToken([u8; CONTINUATION_TOKEN_BYTES]);

impl ContinuationToken {
    /// Carries one exact inner-envelope field without validating token semantics.
    ///
    /// The listener-free runtime calls [`Self::inspect_optional`] and then
    /// performs the returned real-or-cover replay operation before engine use.
    pub(super) const fn from_opaque_bytes(bytes: [u8; CONTINUATION_TOKEN_BYTES]) -> Self {
        Self(bytes)
    }

    /// Encodes and protects one continuation state.
    ///
    /// The caller must supply a nonce that is unique for the protector's key.
    /// This API remains private until a production protector owns nonce
    /// generation and can enforce that invariant rather than trusting callers.
    pub(super) fn issue<P>(
        state: &ContinuationState,
        context: &ContinuationProtectionContext,
        protector: &P,
    ) -> Result<Self, ProtectionUnavailable>
    where
        P: ContinuationTokenProtector,
    {
        let mut body = encode_state(state);
        let authentication = protector.seal(context, &state.nonce, &mut body)?;
        let mut token = [0; CONTINUATION_TOKEN_BYTES];
        token[..NONCE_BYTES].copy_from_slice(&state.nonce);
        token[PROTECTED_BODY_TOKEN_START..AUTHENTICATION_TOKEN_START].copy_from_slice(&body);
        token[AUTHENTICATION_TOKEN_START..].copy_from_slice(&authentication);
        Ok(Self(token))
    }

    fn try_from_bytes(bytes: &[u8]) -> Result<Self, ContinuationTokenError> {
        if bytes.len() != CONTINUATION_TOKEN_BYTES {
            return Err(ContinuationTokenError::WrongLength {
                expected: CONTINUATION_TOKEN_BYTES,
                actual: bytes.len(),
            });
        }

        let mut token = [0; CONTINUATION_TOKEN_BYTES];
        token.copy_from_slice(bytes);
        Ok(Self(token))
    }

    pub(super) const fn opaque_bytes(&self) -> &[u8; CONTINUATION_TOKEN_BYTES] {
        &self.0
    }

    fn validate_semantics<P>(
        &self,
        protector: &P,
        context: &ContinuationProtectionContext,
        expectation: &ContinuationExpectation,
    ) -> Result<ContinuationState, ContinuationTokenError>
    where
        P: ContinuationTokenProtector,
    {
        match inspect_candidate(
            Some(self),
            protector,
            context,
            expectation,
            [0; NONCE_BYTES],
        ) {
            InspectedContinuation::Continue(state) => Ok(state),
            InspectedContinuation::Invalid(error) => Err(error),
            InspectedContinuation::ProtectionUnavailable => {
                Err(ContinuationTokenError::ProtectionUnavailable)
            }
            InspectedContinuation::Initial => Err(ContinuationTokenError::AuthenticationFailed),
        }
    }

    /// Performs exactly one real-or-cover open and every semantic comparison.
    /// Replay access is deliberately a separate step so the runtime can prove
    /// its ordered logical phase schedule.
    ///
    /// A real continuation claim commits the token's exact
    /// `expires_at_unix_seconds` into [`ContinuationReplayKey`]. The v4 replay
    /// journal receives only that opaque key: it has no explicit expiry bucket
    /// or independently validated key-and-bucket pair.
    pub(super) fn inspect_optional<P>(
        token: Option<&Self>,
        protector: &P,
        context: &ContinuationProtectionContext,
        expectation: &ContinuationExpectation,
        replay_namespace: &ReplayNamespace,
        authenticated_request_nonce: [u8; NONCE_BYTES],
    ) -> ContinuationInspection
    where
        P: ContinuationTokenProtector,
    {
        let disposition = inspect_candidate(
            token,
            protector,
            context,
            expectation,
            authenticated_request_nonce,
        );
        let context_digest = continuation_context_digest(context);
        let continuation_plan = match disposition {
            InspectedContinuation::Continue(state) => {
                ContinuationReplayPlan::ClaimOrCover(ContinuationReplayKey::new(
                    replay_namespace,
                    state.projection_epoch,
                    state.query_digest,
                    state.cursor,
                    state.expires_at_unix_seconds,
                    state.nonce,
                    context_digest,
                ))
            }
            InspectedContinuation::Initial
            | InspectedContinuation::Invalid(_)
            | InspectedContinuation::ProtectionUnavailable => ContinuationReplayPlan::Cover,
        };
        ContinuationInspection {
            replay_namespace: *replay_namespace,
            authenticated_request_nonce,
            continuation_plan,
            disposition,
        }
    }
}

impl fmt::Debug for ContinuationToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ContinuationToken")
            .field("len", &CONTINUATION_TOKEN_BYTES)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum InspectedContinuation {
    Initial,
    Continue(ContinuationState),
    Invalid(ContinuationTokenError),
    ProtectionUnavailable,
}

/// Authenticated token work awaiting its one real-or-cover replay operation.
pub(super) struct ContinuationInspection {
    replay_namespace: ReplayNamespace,
    authenticated_request_nonce: [u8; NONCE_BYTES],
    continuation_plan: ContinuationReplayPlan,
    disposition: InspectedContinuation,
}

impl ContinuationInspection {
    /// Performs exactly one combined request-and-continuation replay commit.
    pub(super) fn finish_replay<R>(
        self,
        security_round: &SecurityRoundCapture,
        replay_guard: &mut R,
    ) -> ContinuationReplayOutcome
    where
        R: ContinuationReplayGuard,
    {
        let request_key =
            RequestReplayKey::new(&self.replay_namespace, self.authenticated_request_nonce);
        match replay_guard.commit_request_and_continuation(
            security_round,
            &request_key,
            &self.continuation_plan,
        ) {
            Ok(result) => {
                let (authority, decision) = result.into_parts();
                let continuation_use = match decision {
                    ReplayDuplicateDecision::Fresh => match self.disposition {
                        InspectedContinuation::Initial => ContinuationUse::Initial,
                        InspectedContinuation::Continue(state) => ContinuationUse::Continue {
                            cursor: state.cursor,
                            expires_at_unix_seconds: state.expires_at_unix_seconds,
                        },
                        InspectedContinuation::Invalid(_) => ContinuationUse::InvalidContinuation,
                        InspectedContinuation::ProtectionUnavailable => {
                            ContinuationUse::ProtectionUnavailable
                        }
                    },
                    ReplayDuplicateDecision::RequestDuplicate => {
                        ContinuationUse::ProjectionNotReady
                    }
                    ReplayDuplicateDecision::ContinuationDuplicate => {
                        ContinuationUse::InvalidContinuation
                    }
                };
                ContinuationReplayOutcome::committed(continuation_use, authority)
            }
            Err(ReplayCommitUnavailable) => ContinuationReplayOutcome::unavailable(),
        }
    }
}

/// Runtime-safe replay decision plus its commit capability when committed.
pub(super) struct ContinuationReplayOutcome {
    continuation_use: ContinuationUse,
    replay_commit_authority: Option<ReplayCommitAuthority>,
}

impl ContinuationReplayOutcome {
    fn committed(
        continuation_use: ContinuationUse,
        replay_commit_authority: ReplayCommitAuthority,
    ) -> Self {
        Self {
            continuation_use,
            replay_commit_authority: Some(replay_commit_authority),
        }
    }

    fn unavailable() -> Self {
        Self {
            continuation_use: ContinuationUse::ProjectionNotReady,
            replay_commit_authority: None,
        }
    }

    /// Transfers the semantic decision and any completed commit capability.
    pub(super) fn into_parts(self) -> (ContinuationUse, Option<ReplayCommitAuthority>) {
        (self.continuation_use, self.replay_commit_authority)
    }
}

/// Runtime-safe continuation decision after the fixed replay operation.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum ContinuationUse {
    Initial,
    Continue {
        cursor: u64,
        expires_at_unix_seconds: u64,
    },
    InvalidContinuation,
    ProjectionNotReady,
    ProtectionUnavailable,
}

impl fmt::Debug for ContinuationUse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ContinuationUse([REDACTED])")
    }
}

/// Protects and authenticates the fixed token body.
///
/// The token nonce remains visible but must be bound as the AEAD nonce or
/// associated data. `seal` may encrypt the body in place and returns its fixed
/// authentication field. `open` must authenticate before exposing plaintext
/// and may decrypt in place only on success. The crate-internal
/// XChaCha20-Poly1305 implementation remains a primitive, not a production key,
/// nonce, replay, or service owner.
pub(super) trait ContinuationTokenProtector {
    /// Protects `body`, or reports that no token can be issued.
    fn seal(
        &self,
        context: &ContinuationProtectionContext,
        nonce: &[u8; NONCE_BYTES],
        body: &mut [u8; PROTECTED_BODY_BYTES],
    ) -> Result<[u8; AUTHENTICATION_BYTES], ProtectionUnavailable>;

    /// Authenticates `body` without exposing plaintext on rejection or error.
    fn open(
        &self,
        context: &ContinuationProtectionContext,
        nonce: &[u8; NONCE_BYTES],
        body: &mut [u8; PROTECTED_BODY_BYTES],
        authentication: &[u8; AUTHENTICATION_BYTES],
    ) -> Result<AuthenticationDecision, ProtectionUnavailable>;
}

/// Builds the crate-internal token protector without exposing its concrete
/// key-bearing type outside this module.
pub(super) fn xchacha20_token_protector(
    key: zeroize::Zeroizing<[u8; crate::xchacha20::KEY_BYTES]>,
) -> impl ContinuationTokenProtector {
    xchacha20::token_protector(key)
}

/// Atomically commits the request lane and continuation real-or-cover lane.
pub(super) trait ContinuationReplayGuard {
    /// Executes one indivisible logical transaction over both lanes.
    ///
    /// A fresh request commits its request key, then either commits cover or
    /// claims the requested continuation and commits cover on a duplicate. An
    /// already-committed request must execute continuation cover regardless of
    /// `continuation_plan`; it must never consume a fresh continuation key.
    /// Fresh, request-duplicate, and continuation-duplicate decisions are all
    /// authoritative commits and return a capability for `security_round`.
    /// Only unavailable or ambiguous completion returns an error, with no
    /// authority and no partial externally visible mutation in either lane.
    /// This is one profile-visible logical access; the contract makes no claim
    /// about a provider's physical access count.
    fn commit_request_and_continuation(
        &mut self,
        security_round: &SecurityRoundCapture,
        request_key: &RequestReplayKey,
        continuation_plan: &ContinuationReplayPlan,
    ) -> Result<ReplayCommitResult, ReplayCommitUnavailable>;
}

/// A continuation token was malformed or invalid for the current request.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ContinuationTokenError {
    WrongLength { expected: usize, actual: usize },
    AuthenticationFailed,
    ProtectionUnavailable,
    MalformedEncoding,
    VersionMismatch,
    ProfileMismatch,
    QueryMismatch,
    ProjectionEpochMismatch,
    Expired,
    CursorOutOfRange,
}

impl fmt::Debug for ContinuationTokenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ContinuationTokenError([REDACTED])")
    }
}

impl fmt::Display for ContinuationTokenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("continuation token is invalid")
    }
}

impl std::error::Error for ContinuationTokenError {}

fn inspect_candidate<P>(
    token: Option<&ContinuationToken>,
    protector: &P,
    context: &ContinuationProtectionContext,
    expectation: &ContinuationExpectation,
    authenticated_request_nonce: [u8; NONCE_BYTES],
) -> InspectedContinuation
where
    P: ContinuationTokenProtector,
{
    let present = token.is_some();
    let candidate = match token {
        Some(token) => token.clone(),
        None => ContinuationToken([0; CONTINUATION_TOKEN_BYTES]),
    };
    let mut nonce = [0; NONCE_BYTES];
    nonce.copy_from_slice(&candidate.0[..NONCE_BYTES]);
    let mut body = [0; PROTECTED_BODY_BYTES];
    body.copy_from_slice(&candidate.0[PROTECTED_BODY_TOKEN_START..AUTHENTICATION_TOKEN_START]);
    let mut authentication = [0; AUTHENTICATION_BYTES];
    authentication.copy_from_slice(&candidate.0[AUTHENTICATION_TOKEN_START..]);

    let (authenticated, protection_unavailable) =
        match protector.open(context, &nonce, &mut body, &authentication) {
            Ok(AuthenticationDecision::Accepted) => (true, false),
            Ok(AuthenticationDecision::Rejected) => (false, false),
            Err(ProtectionUnavailable) => (false, true),
        };
    let (state, reserved_zero) = if authenticated {
        (decode_state(&body, nonce), reserved_bytes_are_zero(&body))
    } else {
        let state = cover_state(expectation, authenticated_request_nonce);
        let cover_body = encode_state(&state);
        (state, reserved_bytes_are_zero(&cover_body))
    };
    let failure = semantic_failure(authenticated, reserved_zero, &state, expectation);

    if protection_unavailable {
        InspectedContinuation::ProtectionUnavailable
    } else if !present {
        InspectedContinuation::Initial
    } else if let Some(error) = failure {
        InspectedContinuation::Invalid(error)
    } else {
        InspectedContinuation::Continue(state)
    }
}

fn continuation_context_digest(
    context: &ContinuationProtectionContext,
) -> [u8; QUERY_DIGEST_BYTES] {
    let mut hasher = Blake2s256::new();
    Digest::update(&mut hasher, CONTINUATION_CONTEXT_DIGEST_DOMAIN);
    Digest::update(
        &mut hasher,
        CONTINUATION_CONTEXT_DIGEST_VERSION.to_be_bytes(),
    );
    Digest::update(&mut hasher, context.as_bytes());
    Digest::finalize(hasher).into()
}

fn cover_state(
    expectation: &ContinuationExpectation,
    nonce: [u8; NONCE_BYTES],
) -> ContinuationState {
    ContinuationState::new(
        expectation.version,
        expectation.profile_id,
        expectation.query_digest,
        expectation.projection_epoch,
        1,
        expectation.now_unix_seconds.saturating_add(1),
        nonce,
    )
}

fn semantic_failure(
    authenticated: bool,
    reserved_zero: bool,
    state: &ContinuationState,
    expectation: &ContinuationExpectation,
) -> Option<ContinuationTokenError> {
    let version_matches = state.version == expectation.version;
    let profile_matches = state.profile_id == expectation.profile_id;
    let query_matches = state.query_digest == expectation.query_digest;
    let projection_matches = state.projection_epoch == expectation.projection_epoch;
    let unexpired = expectation.now_unix_seconds < state.expires_at_unix_seconds;
    let cursor_in_range = state.cursor > 0 && state.cursor < expectation.cursor_limit;

    if !authenticated {
        Some(ContinuationTokenError::AuthenticationFailed)
    } else if !reserved_zero {
        Some(ContinuationTokenError::MalformedEncoding)
    } else if !version_matches {
        Some(ContinuationTokenError::VersionMismatch)
    } else if !profile_matches {
        Some(ContinuationTokenError::ProfileMismatch)
    } else if !query_matches {
        Some(ContinuationTokenError::QueryMismatch)
    } else if !projection_matches {
        Some(ContinuationTokenError::ProjectionEpochMismatch)
    } else if !unexpired {
        Some(ContinuationTokenError::Expired)
    } else if !cursor_in_range {
        Some(ContinuationTokenError::CursorOutOfRange)
    } else {
        None
    }
}

fn reserved_bytes_are_zero(body: &[u8; PROTECTED_BODY_BYTES]) -> bool {
    body[RESERVED_START..]
        .iter()
        .fold(0_u8, |difference, byte| difference | byte)
        == 0
}

fn encode_state(state: &ContinuationState) -> [u8; PROTECTED_BODY_BYTES] {
    let mut body = [0; PROTECTED_BODY_BYTES];
    write_array(&mut body, VERSION_START, &state.version.to_be_bytes());
    write_array(&mut body, PROFILE_ID_START, &state.profile_id);
    write_array(&mut body, QUERY_DIGEST_START, &state.query_digest);
    write_array(
        &mut body,
        PROJECTION_EPOCH_START,
        &state.projection_epoch.to_be_bytes(),
    );
    write_array(&mut body, CURSOR_START, &state.cursor.to_be_bytes());
    write_array(
        &mut body,
        EXPIRY_START,
        &state.expires_at_unix_seconds.to_be_bytes(),
    );
    body
}

fn decode_state(body: &[u8; PROTECTED_BODY_BYTES], nonce: [u8; NONCE_BYTES]) -> ContinuationState {
    ContinuationState::new(
        u16::from_be_bytes(read_array(body, VERSION_START)),
        read_array(body, PROFILE_ID_START),
        read_array(body, QUERY_DIGEST_START),
        u64::from_be_bytes(read_array(body, PROJECTION_EPOCH_START)),
        u64::from_be_bytes(read_array(body, CURSOR_START)),
        u64::from_be_bytes(read_array(body, EXPIRY_START)),
        nonce,
    )
}

fn write_array<const N: usize>(
    destination: &mut [u8; PROTECTED_BODY_BYTES],
    start: usize,
    value: &[u8; N],
) {
    destination[start..start + N].copy_from_slice(value);
}

fn read_array<const N: usize>(source: &[u8; PROTECTED_BODY_BYTES], start: usize) -> [u8; N] {
    let mut value = [0; N];
    value.copy_from_slice(&source[start..start + N]);
    value
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;
    use crate::runtime_security::SecurityEpochTag;

    const TEST_KEY: [u8; AUTHENTICATION_BYTES] = [0x6b; AUTHENTICATION_BYTES];

    struct DeterministicTestProtector {
        key: [u8; AUTHENTICATION_BYTES],
    }

    impl DeterministicTestProtector {
        const fn new(key: [u8; AUTHENTICATION_BYTES]) -> Self {
            Self { key }
        }

        fn authentication(
            &self,
            context: &ContinuationProtectionContext,
            nonce: &[u8; NONCE_BYTES],
            body: &[u8; PROTECTED_BODY_BYTES],
        ) -> [u8; AUTHENTICATION_BYTES] {
            let mut authentication = self.key;
            for (index, byte) in context
                .as_bytes()
                .iter()
                .chain(nonce)
                .chain(body)
                .enumerate()
            {
                let slot = index % AUTHENTICATION_BYTES;
                authentication[slot] = authentication[slot]
                    .rotate_left((index % u8::BITS as usize) as u32)
                    ^ byte
                    ^ (index as u8).wrapping_mul(17);
            }
            authentication
        }
    }

    impl ContinuationTokenProtector for DeterministicTestProtector {
        fn seal(
            &self,
            context: &ContinuationProtectionContext,
            nonce: &[u8; NONCE_BYTES],
            body: &mut [u8; PROTECTED_BODY_BYTES],
        ) -> Result<[u8; AUTHENTICATION_BYTES], ProtectionUnavailable> {
            Ok(self.authentication(context, nonce, body))
        }

        fn open(
            &self,
            context: &ContinuationProtectionContext,
            nonce: &[u8; NONCE_BYTES],
            body: &mut [u8; PROTECTED_BODY_BYTES],
            authentication: &[u8; AUTHENTICATION_BYTES],
        ) -> Result<AuthenticationDecision, ProtectionUnavailable> {
            let expected = self.authentication(context, nonce, body);
            let accepted = expected
                .iter()
                .zip(authentication)
                .fold(0_u8, |difference, (left, right)| {
                    difference | (left ^ right)
                })
                == 0;
            Ok(if accepted {
                AuthenticationDecision::Accepted
            } else {
                AuthenticationDecision::Rejected
            })
        }
    }

    struct UnavailableTestProtector;

    impl ContinuationTokenProtector for UnavailableTestProtector {
        fn seal(
            &self,
            _context: &ContinuationProtectionContext,
            _nonce: &[u8; NONCE_BYTES],
            _body: &mut [u8; PROTECTED_BODY_BYTES],
        ) -> Result<[u8; AUTHENTICATION_BYTES], ProtectionUnavailable> {
            Err(ProtectionUnavailable)
        }

        fn open(
            &self,
            _context: &ContinuationProtectionContext,
            _nonce: &[u8; NONCE_BYTES],
            _body: &mut [u8; PROTECTED_BODY_BYTES],
            _authentication: &[u8; AUTHENTICATION_BYTES],
        ) -> Result<AuthenticationDecision, ProtectionUnavailable> {
            Err(ProtectionUnavailable)
        }
    }

    #[derive(Default)]
    struct OneUseReplayGuard {
        claimed_requests: HashSet<[u8; QUERY_DIGEST_BYTES]>,
        claimed_continuations: HashSet<[u8; QUERY_DIGEST_BYTES]>,
        cover_commits: usize,
        available: bool,
    }

    impl OneUseReplayGuard {
        fn available() -> Self {
            Self {
                claimed_requests: HashSet::new(),
                claimed_continuations: HashSet::new(),
                cover_commits: 0,
                available: true,
            }
        }
    }

    impl ContinuationReplayGuard for OneUseReplayGuard {
        fn commit_request_and_continuation(
            &mut self,
            security_round: &SecurityRoundCapture,
            request_key: &RequestReplayKey,
            continuation_plan: &ContinuationReplayPlan,
        ) -> Result<ReplayCommitResult, ReplayCommitUnavailable> {
            if !self.available {
                self.cover_commits += 1;
                return Err(ReplayCommitUnavailable);
            }

            let request_key = *request_key.as_bytes();
            let decision = if !self.claimed_requests.insert(request_key) {
                self.cover_commits += 1;
                ReplayDuplicateDecision::RequestDuplicate
            } else {
                match continuation_plan {
                    ContinuationReplayPlan::Cover => {
                        self.cover_commits += 1;
                        ReplayDuplicateDecision::Fresh
                    }
                    ContinuationReplayPlan::ClaimOrCover(continuation_key) => {
                        if self
                            .claimed_continuations
                            .insert(*continuation_key.as_bytes())
                        {
                            ReplayDuplicateDecision::Fresh
                        } else {
                            self.cover_commits += 1;
                            ReplayDuplicateDecision::ContinuationDuplicate
                        }
                    }
                }
            };
            Ok(ReplayCommitResult::new(
                ReplayCommitAuthority::new(security_round),
                decision,
            ))
        }
    }

    fn replay_namespace() -> ReplayNamespace {
        ReplayNamespace::new(
            [0x71; 16],
            1,
            2,
            3,
            [0x11; PROFILE_ID_BYTES],
            [0x72; QUERY_DIGEST_BYTES],
        )
    }

    fn security_epoch() -> SecurityEpochTag {
        SecurityEpochTag::new([0x73; QUERY_DIGEST_BYTES])
    }

    fn finish(
        inspection: ContinuationInspection,
        replay_guard: &mut OneUseReplayGuard,
    ) -> (
        ContinuationUse,
        Option<ReplayCommitAuthority>,
        SecurityEpochTag,
        SecurityRoundCapture,
    ) {
        let epoch = security_epoch();
        let round = SecurityRoundCapture::new(&epoch);
        let (continuation_use, authority) =
            inspection.finish_replay(&round, replay_guard).into_parts();
        (continuation_use, authority, epoch, round)
    }

    fn assert_committed_for_round(
        authority: Option<ReplayCommitAuthority>,
        epoch: &SecurityEpochTag,
        round: &SecurityRoundCapture,
    ) {
        let authority = authority.expect("fixture replay commit returned an authority");
        assert!(authority.matches(epoch, round));
    }

    fn continuation_plan_key(plan: &ContinuationReplayPlan) -> &[u8; QUERY_DIGEST_BYTES] {
        match plan {
            ContinuationReplayPlan::ClaimOrCover(key) => key.as_bytes(),
            ContinuationReplayPlan::Cover => {
                panic!("valid fixture token must select a real continuation claim")
            }
        }
    }

    fn state() -> ContinuationState {
        ContinuationState::new(1, [0x11; 16], [0x22; 32], 41, 7, 1_000, [0x33; 24])
    }

    fn expectation() -> ContinuationExpectation {
        ContinuationExpectation::new(1, [0x11; 16], [0x22; 32], 41, 999, 16)
    }

    fn context() -> ContinuationProtectionContext {
        ContinuationProtectionContext::new([0x44; CONTINUATION_CONTEXT_BYTES])
    }

    fn protector() -> DeterministicTestProtector {
        DeterministicTestProtector::new(TEST_KEY)
    }

    fn issue(state: &ContinuationState) -> ContinuationToken {
        ContinuationToken::issue(state, &context(), &protector())
            .expect("deterministic test protection is available")
    }

    #[test]
    fn token_round_trip_preserves_state_and_exact_size() -> Result<(), ContinuationTokenError> {
        let state = state();
        let token = issue(&state);
        let encoded = ContinuationToken::try_from_bytes(token.opaque_bytes())?;
        let decoded = encoded.validate_semantics(&protector(), &context(), &expectation())?;

        assert_eq!(decoded, state);
        assert_eq!(token.opaque_bytes().len(), CONTINUATION_TOKEN_BYTES);
        assert_eq!(size_of::<ContinuationToken>(), CONTINUATION_TOKEN_BYTES);
        Ok(())
    }

    #[test]
    fn token_rejects_non_exact_outer_lengths() {
        assert_eq!(
            ContinuationToken::try_from_bytes(&[0; CONTINUATION_TOKEN_BYTES - 1]),
            Err(ContinuationTokenError::WrongLength {
                expected: CONTINUATION_TOKEN_BYTES,
                actual: CONTINUATION_TOKEN_BYTES - 1,
            })
        );
        assert_eq!(
            ContinuationToken::try_from_bytes(&[0; CONTINUATION_TOKEN_BYTES + 1]),
            Err(ContinuationTokenError::WrongLength {
                expected: CONTINUATION_TOKEN_BYTES,
                actual: CONTINUATION_TOKEN_BYTES + 1,
            })
        );
    }

    #[test]
    fn protection_unavailability_returns_no_token_and_uses_cover_replay() {
        assert_eq!(
            ContinuationToken::issue(&state(), &context(), &UnavailableTestProtector),
            Err(ProtectionUnavailable)
        );

        let token = issue(&state());
        let inspection = ContinuationToken::inspect_optional(
            Some(&token),
            &UnavailableTestProtector,
            &context(),
            &expectation(),
            &replay_namespace(),
            [0x55; NONCE_BYTES],
        );
        let mut replay_guard = OneUseReplayGuard::available();
        let (continuation_use, authority, epoch, round) = finish(inspection, &mut replay_guard);
        assert_eq!(continuation_use, ContinuationUse::ProtectionUnavailable);
        assert_committed_for_round(authority, &epoch, &round);
        assert!(replay_guard.claimed_continuations.is_empty());
        assert_eq!(replay_guard.cover_commits, 1);
    }

    #[test]
    fn every_token_byte_is_authenticated() -> Result<(), ContinuationTokenError> {
        let token = issue(&state());

        for index in 0..CONTINUATION_TOKEN_BYTES {
            let mut tampered = *token.opaque_bytes();
            tampered[index] ^= 0x80;
            let tampered = ContinuationToken::try_from_bytes(&tampered)?;
            assert_eq!(
                tampered.validate_semantics(&protector(), &context(), &expectation()),
                Err(ContinuationTokenError::AuthenticationFailed),
                "byte {index} was not authenticated"
            );
        }
        Ok(())
    }

    #[test]
    fn absent_and_invalid_tokens_select_typed_cover_replay() {
        let namespace = replay_namespace();
        let absent = ContinuationToken::inspect_optional(
            None,
            &protector(),
            &context(),
            &expectation(),
            &namespace,
            [0x56; NONCE_BYTES],
        );
        let mut tampered = *issue(&state()).opaque_bytes();
        tampered[AUTHENTICATION_TOKEN_START] ^= 1;
        let invalid = ContinuationToken::inspect_optional(
            Some(&ContinuationToken::from_opaque_bytes(tampered)),
            &protector(),
            &context(),
            &expectation(),
            &namespace,
            [0x57; NONCE_BYTES],
        );

        assert!(matches!(
            absent.continuation_plan,
            ContinuationReplayPlan::Cover
        ));
        assert!(matches!(
            invalid.continuation_plan,
            ContinuationReplayPlan::Cover
        ));
    }

    #[test]
    fn authenticated_nonzero_reserved_bytes_are_rejected() -> Result<(), ContinuationTokenError> {
        let state = state();
        let protector = protector();
        let mut body = encode_state(&state);
        body[RESERVED_START] = 1;
        let authentication = protector
            .seal(&context(), &state.nonce, &mut body)
            .expect("deterministic test protection is available");
        let mut bytes = [0; CONTINUATION_TOKEN_BYTES];
        bytes[..NONCE_BYTES].copy_from_slice(&state.nonce);
        bytes[PROTECTED_BODY_TOKEN_START..AUTHENTICATION_TOKEN_START].copy_from_slice(&body);
        bytes[AUTHENTICATION_TOKEN_START..].copy_from_slice(&authentication);
        let token = ContinuationToken::try_from_bytes(&bytes)?;

        assert_eq!(
            token.validate_semantics(&protector, &context(), &expectation()),
            Err(ContinuationTokenError::MalformedEncoding)
        );
        Ok(())
    }

    #[test]
    fn token_rejects_version_profile_query_and_epoch_mismatches() {
        let token = issue(&state());

        let mut wrong_version = expectation();
        wrong_version.version += 1;
        assert_validation_error(
            &token,
            &wrong_version,
            ContinuationTokenError::VersionMismatch,
        );

        let mut wrong_profile = expectation();
        wrong_profile.profile_id[0] ^= 1;
        assert_validation_error(
            &token,
            &wrong_profile,
            ContinuationTokenError::ProfileMismatch,
        );

        let mut wrong_query = expectation();
        wrong_query.query_digest[0] ^= 1;
        assert_validation_error(&token, &wrong_query, ContinuationTokenError::QueryMismatch);

        let mut wrong_epoch = expectation();
        wrong_epoch.projection_epoch += 1;
        assert_validation_error(
            &token,
            &wrong_epoch,
            ContinuationTokenError::ProjectionEpochMismatch,
        );
    }

    #[test]
    fn token_expires_at_its_declared_boundary() {
        let token = issue(&state());
        let mut expired = expectation();
        expired.now_unix_seconds = 1_000;
        assert_validation_error(&token, &expired, ContinuationTokenError::Expired);
    }

    #[test]
    fn token_binds_checkpoint_context_and_cursor_domain() {
        let token = issue(&state());
        let mut changed_context = [0x44; CONTINUATION_CONTEXT_BYTES];
        changed_context[17] ^= 1;
        assert_eq!(
            token.validate_semantics(
                &protector(),
                &ContinuationProtectionContext::new(changed_context),
                &expectation(),
            ),
            Err(ContinuationTokenError::AuthenticationFailed)
        );

        let mut cursor_out_of_range = expectation();
        cursor_out_of_range.cursor_limit = 7;
        assert_validation_error(
            &token,
            &cursor_out_of_range,
            ContinuationTokenError::CursorOutOfRange,
        );
    }

    #[test]
    fn combined_replay_commit_preserves_duplicate_authority_and_token_use() {
        let token = issue(&state());
        let mut replay_guard = OneUseReplayGuard::available();
        let namespace = replay_namespace();

        let duplicate_request_nonce = [0x81; NONCE_BYTES];
        let initial = ContinuationToken::inspect_optional(
            None,
            &protector(),
            &context(),
            &expectation(),
            &namespace,
            duplicate_request_nonce,
        );
        let (initial_use, initial_authority, initial_epoch, initial_round) =
            finish(initial, &mut replay_guard);
        assert_eq!(initial_use, ContinuationUse::Initial);
        assert_committed_for_round(initial_authority, &initial_epoch, &initial_round);

        let duplicate_request = ContinuationToken::inspect_optional(
            Some(&token),
            &protector(),
            &context(),
            &expectation(),
            &namespace,
            duplicate_request_nonce,
        );
        let (duplicate_request_use, request_authority, request_epoch, request_round) =
            finish(duplicate_request, &mut replay_guard);
        assert_eq!(duplicate_request_use, ContinuationUse::ProjectionNotReady);
        assert_committed_for_round(request_authority, &request_epoch, &request_round);
        assert!(
            replay_guard.claimed_continuations.is_empty(),
            "a duplicate request must not consume its valid continuation"
        );

        let fresh_request = ContinuationToken::inspect_optional(
            Some(&token),
            &protector(),
            &context(),
            &expectation(),
            &namespace,
            [0x82; NONCE_BYTES],
        );
        let (fresh_use, fresh_authority, fresh_epoch, fresh_round) =
            finish(fresh_request, &mut replay_guard);
        assert_eq!(
            fresh_use,
            ContinuationUse::Continue {
                cursor: 7,
                expires_at_unix_seconds: 1_000,
            }
        );
        assert_committed_for_round(fresh_authority, &fresh_epoch, &fresh_round);
        assert_eq!(replay_guard.claimed_continuations.len(), 1);

        let duplicate_continuation = ContinuationToken::inspect_optional(
            Some(&token),
            &protector(),
            &context(),
            &expectation(),
            &namespace,
            [0x83; NONCE_BYTES],
        );
        let (duplicate_use, duplicate_authority, duplicate_epoch, duplicate_round) =
            finish(duplicate_continuation, &mut replay_guard);
        assert_eq!(duplicate_use, ContinuationUse::InvalidContinuation);
        assert_committed_for_round(duplicate_authority, &duplicate_epoch, &duplicate_round);
        assert_eq!(replay_guard.cover_commits, 3);
    }

    #[test]
    fn replay_commit_unavailability_maps_to_projection_not_ready_without_authority() {
        let token = issue(&state());
        let inspection = ContinuationToken::inspect_optional(
            Some(&token),
            &protector(),
            &context(),
            &expectation(),
            &replay_namespace(),
            [0x84; NONCE_BYTES],
        );
        let mut replay_guard = OneUseReplayGuard::default();
        let (continuation_use, authority, _, _) = finish(inspection, &mut replay_guard);

        assert_eq!(continuation_use, ContinuationUse::ProjectionNotReady);
        assert!(authority.is_none());
        assert!(replay_guard.claimed_requests.is_empty());
        assert!(replay_guard.claimed_continuations.is_empty());
        assert_eq!(replay_guard.cover_commits, 1);
    }

    #[test]
    fn valid_continuation_key_binds_canonical_context_digest() {
        let state = state();
        let original_context = context();
        let original_token = issue(&state);
        let mut changed_context_bytes = *original_context.as_bytes();
        changed_context_bytes[17] ^= 1;
        let changed_context = ContinuationProtectionContext::new(changed_context_bytes);
        let changed_token = ContinuationToken::issue(&state, &changed_context, &protector())
            .expect("deterministic test protection is available");
        let namespace = replay_namespace();

        let original = ContinuationToken::inspect_optional(
            Some(&original_token),
            &protector(),
            &original_context,
            &expectation(),
            &namespace,
            [0x85; NONCE_BYTES],
        );
        let changed = ContinuationToken::inspect_optional(
            Some(&changed_token),
            &protector(),
            &changed_context,
            &expectation(),
            &namespace,
            [0x85; NONCE_BYTES],
        );

        assert_eq!(
            continuation_context_digest(&original_context),
            continuation_context_digest(&context())
        );
        assert_ne!(
            continuation_context_digest(&original_context),
            continuation_context_digest(&changed_context)
        );
        assert_ne!(
            continuation_plan_key(&original.continuation_plan),
            continuation_plan_key(&changed.continuation_plan)
        );
    }

    #[test]
    fn debug_output_redacts_token_state_and_decisions() {
        let state = state();
        let token = issue(&state);

        assert_eq!(format!("{state:?}"), "ContinuationState { ..REDACTED.. }");
        assert_eq!(format!("{token:?}"), "ContinuationToken { len: 128, .. }");
        assert_eq!(
            format!("{:?}", expectation()),
            "ContinuationExpectation { ..REDACTED.. }"
        );
        assert_eq!(
            format!(
                "{:?}",
                ContinuationUse::Continue {
                    cursor: 7,
                    expires_at_unix_seconds: 1_000,
                }
            ),
            "ContinuationUse([REDACTED])"
        );
        assert_eq!(
            format!("{:?}", ContinuationTokenError::QueryMismatch),
            "ContinuationTokenError([REDACTED])"
        );
        assert_eq!(
            ContinuationTokenError::Expired.to_string(),
            "continuation token is invalid"
        );
    }

    fn assert_validation_error(
        token: &ContinuationToken,
        expectation: &ContinuationExpectation,
        expected: ContinuationTokenError,
    ) {
        assert_eq!(
            token.validate_semantics(&protector(), &context(), expectation),
            Err(expected)
        );
    }
}
