use std::{fmt, mem::size_of};

use crate::profile::PROFILE_ID_BYTES;

const QUERY_DIGEST_BYTES: usize = 32;
const NONCE_BYTES: usize = 24;
const AUTHENTICATION_BYTES: usize = 16;
const PROTECTED_BODY_BYTES: usize = 88;
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

    const fn replay_binding(&self) -> ReplayBinding {
        ReplayBinding {
            version: self.version,
            profile_id: self.profile_id,
            query_digest: self.query_digest,
            projection_epoch: self.projection_epoch,
            cursor: self.cursor,
            expires_at_unix_seconds: self.expires_at_unix_seconds,
            nonce: self.nonce,
        }
    }
}

impl fmt::Debug for ContinuationState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ContinuationState { ..REDACTED.. }")
    }
}

/// Expected public and request-bound values for token validation.
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
    ) -> Self
    where
        P: ContinuationTokenProtector,
    {
        let mut body = encode_state(state);
        let authentication = protector.seal(context, &state.nonce, &mut body);
        let mut token = [0; CONTINUATION_TOKEN_BYTES];
        token[..NONCE_BYTES].copy_from_slice(&state.nonce);
        token[PROTECTED_BODY_TOKEN_START..AUTHENTICATION_TOKEN_START].copy_from_slice(&body);
        token[AUTHENTICATION_TOKEN_START..].copy_from_slice(&authentication);
        Self(token)
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

    fn validate<P, R>(
        &self,
        protector: &P,
        context: &ContinuationProtectionContext,
        expectation: &ContinuationExpectation,
        replay_guard: &mut R,
    ) -> Result<ContinuationState, ContinuationTokenError>
    where
        P: ContinuationTokenProtector,
        R: ContinuationReplayGuard,
    {
        let inspection = Self::inspect_optional(
            Some(self),
            protector,
            context,
            expectation,
            [0; NONCE_BYTES],
        );
        if let Some(error) = inspection.failure {
            return Err(error);
        }
        replay_guard
            .claim_or_cover(&inspection.replay_binding, true)
            .map_err(ContinuationTokenError::from_replay_guard)?;
        Ok(inspection.state)
    }

    /// Performs exactly one real-or-cover open and every semantic comparison.
    /// Replay access is deliberately a separate step so the runtime can prove
    /// its ordered logical phase schedule.
    pub(super) fn inspect_optional<P>(
        token: Option<&Self>,
        protector: &P,
        context: &ContinuationProtectionContext,
        expectation: &ContinuationExpectation,
        request_nonce: [u8; NONCE_BYTES],
    ) -> ContinuationInspection
    where
        P: ContinuationTokenProtector,
    {
        let present = token.is_some();
        let candidate = token
            .cloned()
            .unwrap_or(Self([0; CONTINUATION_TOKEN_BYTES]));
        let mut nonce = [0; NONCE_BYTES];
        nonce.copy_from_slice(&candidate.0[..NONCE_BYTES]);
        let mut body = [0; PROTECTED_BODY_BYTES];
        body.copy_from_slice(&candidate.0[PROTECTED_BODY_TOKEN_START..AUTHENTICATION_TOKEN_START]);
        let mut authentication = [0; AUTHENTICATION_BYTES];
        authentication.copy_from_slice(&candidate.0[AUTHENTICATION_TOKEN_START..]);

        let authenticated = protector.open(context, &nonce, &mut body, &authentication);
        let (state, reserved_zero) = if authenticated {
            (decode_state(&body, nonce), reserved_bytes_are_zero(&body))
        } else {
            let state = cover_state(expectation, request_nonce);
            let cover_body = encode_state(&state);
            (state, reserved_bytes_are_zero(&cover_body))
        };
        let failure = semantic_failure(authenticated, reserved_zero, &state, expectation);
        let disposition = if !present {
            ContinuationDisposition::Initial
        } else if failure.is_none() {
            ContinuationDisposition::Continue
        } else {
            ContinuationDisposition::Invalid
        };
        let replay_binding = if matches!(disposition, ContinuationDisposition::Continue) {
            state.replay_binding()
        } else {
            ReplayBinding::cover(expectation, request_nonce)
        };
        ContinuationInspection {
            state,
            replay_binding,
            disposition,
            failure: if present { failure } else { None },
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
enum ContinuationDisposition {
    Initial,
    Continue,
    Invalid,
}

/// Authenticated token work awaiting its one real-or-cover replay operation.
pub(super) struct ContinuationInspection {
    state: ContinuationState,
    replay_binding: ReplayBinding,
    disposition: ContinuationDisposition,
    failure: Option<ContinuationTokenError>,
}

impl ContinuationInspection {
    /// Performs exactly one replay-guard operation and collapses token details
    /// into the protected runtime outcome classes.
    pub(super) fn claim_or_cover<R>(self, replay_guard: &mut R) -> ContinuationUse
    where
        R: ContinuationReplayGuard,
    {
        let claim = matches!(self.disposition, ContinuationDisposition::Continue);
        match replay_guard.claim_or_cover(&self.replay_binding, claim) {
            Ok(()) => match self.disposition {
                ContinuationDisposition::Initial => ContinuationUse::Initial,
                ContinuationDisposition::Continue => ContinuationUse::Continue {
                    cursor: self.state.cursor,
                    expires_at_unix_seconds: self.state.expires_at_unix_seconds,
                },
                ContinuationDisposition::Invalid => ContinuationUse::InvalidContinuation,
            },
            Err(ReplayGuardError::AlreadyClaimed) => ContinuationUse::InvalidContinuation,
            Err(ReplayGuardError::Unavailable) => ContinuationUse::ProjectionNotReady,
        }
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
/// and may decrypt in place only on success. The codec deliberately supplies no
/// concrete production implementation until the private service selects and
/// audits an AEAD construction.
pub(super) trait ContinuationTokenProtector {
    fn seal(
        &self,
        context: &ContinuationProtectionContext,
        nonce: &[u8; NONCE_BYTES],
        body: &mut [u8; PROTECTED_BODY_BYTES],
    ) -> [u8; AUTHENTICATION_BYTES];

    fn open(
        &self,
        context: &ContinuationProtectionContext,
        nonce: &[u8; NONCE_BYTES],
        body: &mut [u8; PROTECTED_BODY_BYTES],
        authentication: &[u8; AUTHENTICATION_BYTES],
    ) -> bool;
}

/// The complete authenticated identity of one token use.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub(super) struct ReplayBinding {
    version: u16,
    profile_id: [u8; PROFILE_ID_BYTES],
    query_digest: [u8; QUERY_DIGEST_BYTES],
    projection_epoch: u64,
    cursor: u64,
    expires_at_unix_seconds: u64,
    nonce: [u8; NONCE_BYTES],
}

impl ReplayBinding {
    const fn cover(
        expectation: &ContinuationExpectation,
        request_nonce: [u8; NONCE_BYTES],
    ) -> Self {
        Self {
            version: expectation.version,
            profile_id: expectation.profile_id,
            query_digest: expectation.query_digest,
            projection_epoch: expectation.projection_epoch,
            cursor: 0,
            expires_at_unix_seconds: expectation.now_unix_seconds,
            nonce: request_nonce,
        }
    }
}

impl fmt::Debug for ReplayBinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ReplayBinding { ..REDACTED.. }")
    }
}

/// Atomically claims a successfully authenticated, unexpired token use.
pub(super) trait ContinuationReplayGuard {
    /// Executes one fixed logical lookup and one write-back for every binding.
    /// `claim = false` writes only a non-durable cover slot and must not mutate
    /// the durable real-token namespace.
    fn claim_or_cover(
        &mut self,
        binding: &ReplayBinding,
        claim: bool,
    ) -> Result<(), ReplayGuardError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ReplayGuardError {
    AlreadyClaimed,
    Unavailable,
}

/// A continuation token was malformed or invalid for the current request.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ContinuationTokenError {
    WrongLength { expected: usize, actual: usize },
    AuthenticationFailed,
    MalformedEncoding,
    VersionMismatch,
    ProfileMismatch,
    QueryMismatch,
    ProjectionEpochMismatch,
    Expired,
    CursorOutOfRange,
    ReplayDetected,
    ReplayGuardUnavailable,
}

impl fmt::Debug for ContinuationTokenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ContinuationTokenError([REDACTED])")
    }
}

impl ContinuationTokenError {
    const fn from_replay_guard(error: ReplayGuardError) -> Self {
        match error {
            ReplayGuardError::AlreadyClaimed => Self::ReplayDetected,
            ReplayGuardError::Unavailable => Self::ReplayGuardUnavailable,
        }
    }
}

impl fmt::Display for ContinuationTokenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("continuation token is invalid")
    }
}

impl std::error::Error for ContinuationTokenError {}

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
        ) -> [u8; AUTHENTICATION_BYTES] {
            self.authentication(context, nonce, body)
        }

        fn open(
            &self,
            context: &ContinuationProtectionContext,
            nonce: &[u8; NONCE_BYTES],
            body: &mut [u8; PROTECTED_BODY_BYTES],
            authentication: &[u8; AUTHENTICATION_BYTES],
        ) -> bool {
            let expected = self.authentication(context, nonce, body);
            expected
                .iter()
                .zip(authentication)
                .fold(0_u8, |difference, (left, right)| {
                    difference | (left ^ right)
                })
                == 0
        }
    }

    #[derive(Default)]
    struct OneUseReplayGuard {
        claimed: HashSet<ReplayBinding>,
        cover_slot: Option<ReplayBinding>,
        available: bool,
    }

    impl OneUseReplayGuard {
        fn available() -> Self {
            Self {
                claimed: HashSet::new(),
                cover_slot: None,
                available: true,
            }
        }
    }

    impl ContinuationReplayGuard for OneUseReplayGuard {
        fn claim_or_cover(
            &mut self,
            binding: &ReplayBinding,
            claim: bool,
        ) -> Result<(), ReplayGuardError> {
            let already_claimed = self.claimed.contains(binding);
            if !self.available {
                self.cover_slot = Some(*binding);
                return Err(ReplayGuardError::Unavailable);
            }
            if claim && already_claimed {
                self.cover_slot = Some(*binding);
                return Err(ReplayGuardError::AlreadyClaimed);
            }
            if claim {
                self.claimed.insert(*binding);
            } else {
                self.cover_slot = Some(*binding);
            }
            Ok(())
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

    #[test]
    fn token_round_trip_preserves_state_and_exact_size() -> Result<(), ContinuationTokenError> {
        let state = state();
        let token = ContinuationToken::issue(&state, &context(), &protector());
        let encoded = ContinuationToken::try_from_bytes(token.opaque_bytes())?;
        let decoded = encoded.validate(
            &protector(),
            &context(),
            &expectation(),
            &mut OneUseReplayGuard::available(),
        )?;

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
    fn every_token_byte_is_authenticated() -> Result<(), ContinuationTokenError> {
        let token = ContinuationToken::issue(&state(), &context(), &protector());

        for index in 0..CONTINUATION_TOKEN_BYTES {
            let mut tampered = *token.opaque_bytes();
            tampered[index] ^= 0x80;
            let tampered = ContinuationToken::try_from_bytes(&tampered)?;
            assert_eq!(
                tampered.validate(
                    &protector(),
                    &context(),
                    &expectation(),
                    &mut OneUseReplayGuard::available(),
                ),
                Err(ContinuationTokenError::AuthenticationFailed),
                "byte {index} was not authenticated"
            );
        }
        Ok(())
    }

    #[test]
    fn authenticated_nonzero_reserved_bytes_are_rejected() -> Result<(), ContinuationTokenError> {
        let state = state();
        let protector = protector();
        let mut body = encode_state(&state);
        body[RESERVED_START] = 1;
        let authentication = protector.seal(&context(), &state.nonce, &mut body);
        let mut bytes = [0; CONTINUATION_TOKEN_BYTES];
        bytes[..NONCE_BYTES].copy_from_slice(&state.nonce);
        bytes[PROTECTED_BODY_TOKEN_START..AUTHENTICATION_TOKEN_START].copy_from_slice(&body);
        bytes[AUTHENTICATION_TOKEN_START..].copy_from_slice(&authentication);
        let token = ContinuationToken::try_from_bytes(&bytes)?;

        assert_eq!(
            token.validate(
                &protector,
                &context(),
                &expectation(),
                &mut OneUseReplayGuard::available(),
            ),
            Err(ContinuationTokenError::MalformedEncoding)
        );
        Ok(())
    }

    #[test]
    fn token_rejects_version_profile_query_and_epoch_mismatches() {
        let token = ContinuationToken::issue(&state(), &context(), &protector());

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
        let token = ContinuationToken::issue(&state(), &context(), &protector());
        let mut expired = expectation();
        expired.now_unix_seconds = 1_000;
        assert_validation_error(&token, &expired, ContinuationTokenError::Expired);
    }

    #[test]
    fn token_binds_checkpoint_context_and_cursor_domain() {
        let token = ContinuationToken::issue(&state(), &context(), &protector());
        let mut changed_context = [0x44; CONTINUATION_CONTEXT_BYTES];
        changed_context[17] ^= 1;
        assert_eq!(
            token.validate(
                &protector(),
                &ContinuationProtectionContext::new(changed_context),
                &expectation(),
                &mut OneUseReplayGuard::available(),
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
    fn token_can_be_claimed_only_once() -> Result<(), ContinuationTokenError> {
        let token = ContinuationToken::issue(&state(), &context(), &protector());
        let mut replay_guard = OneUseReplayGuard::available();

        token.validate(&protector(), &context(), &expectation(), &mut replay_guard)?;
        assert_eq!(
            token.validate(&protector(), &context(), &expectation(), &mut replay_guard),
            Err(ContinuationTokenError::ReplayDetected)
        );
        Ok(())
    }

    #[test]
    fn token_fails_closed_when_replay_guard_is_unavailable() {
        let token = ContinuationToken::issue(&state(), &context(), &protector());
        assert_eq!(
            token.validate(
                &protector(),
                &context(),
                &expectation(),
                &mut OneUseReplayGuard::default(),
            ),
            Err(ContinuationTokenError::ReplayGuardUnavailable)
        );
    }

    #[test]
    fn debug_output_redacts_token_state_and_replay_binding() {
        let state = state();
        let token = ContinuationToken::issue(&state, &context(), &protector());

        assert_eq!(format!("{state:?}"), "ContinuationState { ..REDACTED.. }");
        assert_eq!(format!("{token:?}"), "ContinuationToken { len: 128, .. }");
        assert_eq!(
            format!("{:?}", state.replay_binding()),
            "ReplayBinding { ..REDACTED.. }"
        );
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
            token.validate(
                &protector(),
                &context(),
                expectation,
                &mut OneUseReplayGuard::available(),
            ),
            Err(expected)
        );
    }
}
