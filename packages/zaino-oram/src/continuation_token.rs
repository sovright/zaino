use std::{fmt, mem::size_of};

use crate::profile::PROFILE_ID_BYTES;

const QUERY_DIGEST_BYTES: usize = 32;
const NONCE_BYTES: usize = 24;
const AUTHENTICATION_BYTES: usize = 16;
const PROTECTED_BODY_BYTES: usize = 88;
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

/// State carried between fixed-shape private query rounds.
#[derive(Clone, Copy, PartialEq, Eq)]
struct ContinuationState {
    version: u16,
    profile_id: [u8; PROFILE_ID_BYTES],
    query_digest: [u8; QUERY_DIGEST_BYTES],
    projection_epoch: u64,
    cursor: u64,
    expires_at_unix_seconds: u64,
    nonce: [u8; NONCE_BYTES],
}

impl ContinuationState {
    const fn new(
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
struct ContinuationExpectation {
    version: u16,
    profile_id: [u8; PROFILE_ID_BYTES],
    query_digest: [u8; QUERY_DIGEST_BYTES],
    projection_epoch: u64,
    now_unix_seconds: u64,
}

impl ContinuationExpectation {
    const fn new(
        version: u16,
        profile_id: [u8; PROFILE_ID_BYTES],
        query_digest: [u8; QUERY_DIGEST_BYTES],
        projection_epoch: u64,
        now_unix_seconds: u64,
    ) -> Self {
        Self {
            version,
            profile_id,
            query_digest,
            projection_epoch,
            now_unix_seconds,
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
    /// A runtime adapter must call [`Self::validate`] before the token can reach
    /// replay protection or engine execution.
    pub(super) const fn from_opaque_bytes(bytes: [u8; CONTINUATION_TOKEN_BYTES]) -> Self {
        Self(bytes)
    }

    /// Encodes and protects one continuation state.
    ///
    /// The caller must supply a nonce that is unique for the protector's key.
    /// This API remains private until a production protector owns nonce
    /// generation and can enforce that invariant rather than trusting callers.
    fn issue<P>(state: &ContinuationState, protector: &P) -> Self
    where
        P: ContinuationTokenProtector,
    {
        let mut body = encode_state(state);
        let authentication = protector.seal(&state.nonce, &mut body);
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
        expectation: &ContinuationExpectation,
        replay_guard: &mut R,
    ) -> Result<ContinuationState, ContinuationTokenError>
    where
        P: ContinuationTokenProtector,
        R: ContinuationReplayGuard,
    {
        let mut nonce = [0; NONCE_BYTES];
        nonce.copy_from_slice(&self.0[..NONCE_BYTES]);
        let mut body = [0; PROTECTED_BODY_BYTES];
        body.copy_from_slice(&self.0[PROTECTED_BODY_TOKEN_START..AUTHENTICATION_TOKEN_START]);
        let mut authentication = [0; AUTHENTICATION_BYTES];
        authentication.copy_from_slice(&self.0[AUTHENTICATION_TOKEN_START..]);

        if !protector.open(&nonce, &mut body, &authentication) {
            return Err(ContinuationTokenError::AuthenticationFailed);
        }
        if body[RESERVED_START..].iter().any(|byte| *byte != 0) {
            return Err(ContinuationTokenError::MalformedEncoding);
        }

        let state = decode_state(&body, nonce);
        if state.version != expectation.version {
            return Err(ContinuationTokenError::VersionMismatch);
        }
        if state.profile_id != expectation.profile_id {
            return Err(ContinuationTokenError::ProfileMismatch);
        }
        if state.query_digest != expectation.query_digest {
            return Err(ContinuationTokenError::QueryMismatch);
        }
        if state.projection_epoch != expectation.projection_epoch {
            return Err(ContinuationTokenError::ProjectionEpochMismatch);
        }
        if expectation.now_unix_seconds >= state.expires_at_unix_seconds {
            return Err(ContinuationTokenError::Expired);
        }

        replay_guard
            .claim(&state.replay_binding())
            .map_err(ContinuationTokenError::from_replay_guard)?;
        Ok(state)
    }
}

impl fmt::Debug for ContinuationToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ContinuationToken")
            .field("len", &CONTINUATION_TOKEN_BYTES)
            .finish_non_exhaustive()
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
trait ContinuationTokenProtector {
    fn seal(
        &self,
        nonce: &[u8; NONCE_BYTES],
        body: &mut [u8; PROTECTED_BODY_BYTES],
    ) -> [u8; AUTHENTICATION_BYTES];

    fn open(
        &self,
        nonce: &[u8; NONCE_BYTES],
        body: &mut [u8; PROTECTED_BODY_BYTES],
        authentication: &[u8; AUTHENTICATION_BYTES],
    ) -> bool;
}

/// The complete authenticated identity of one token use.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct ReplayBinding {
    version: u16,
    profile_id: [u8; PROFILE_ID_BYTES],
    query_digest: [u8; QUERY_DIGEST_BYTES],
    projection_epoch: u64,
    cursor: u64,
    expires_at_unix_seconds: u64,
    nonce: [u8; NONCE_BYTES],
}

impl fmt::Debug for ReplayBinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ReplayBinding { ..REDACTED.. }")
    }
}

/// Atomically claims a successfully authenticated, unexpired token use.
trait ContinuationReplayGuard {
    fn claim(&mut self, binding: &ReplayBinding) -> Result<(), ReplayGuardError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReplayGuardError {
    AlreadyClaimed,
    Unavailable,
}

/// A continuation token was malformed or invalid for the current request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ContinuationTokenError {
    WrongLength { expected: usize, actual: usize },
    AuthenticationFailed,
    MalformedEncoding,
    VersionMismatch,
    ProfileMismatch,
    QueryMismatch,
    ProjectionEpochMismatch,
    Expired,
    ReplayDetected,
    ReplayGuardUnavailable,
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
        match self {
            Self::WrongLength { expected, actual } => {
                write!(
                    f,
                    "continuation token requires {expected} bytes; received {actual}"
                )
            }
            Self::AuthenticationFailed => f.write_str("continuation token authentication failed"),
            Self::MalformedEncoding => f.write_str("continuation token encoding is invalid"),
            Self::VersionMismatch => f.write_str("continuation token version does not match"),
            Self::ProfileMismatch => f.write_str("continuation token profile does not match"),
            Self::QueryMismatch => f.write_str("continuation token query does not match"),
            Self::ProjectionEpochMismatch => {
                f.write_str("continuation token projection epoch does not match")
            }
            Self::Expired => f.write_str("continuation token has expired"),
            Self::ReplayDetected => f.write_str("continuation token was already used"),
            Self::ReplayGuardUnavailable => {
                f.write_str("continuation token replay protection is unavailable")
            }
        }
    }
}

impl std::error::Error for ContinuationTokenError {}

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
            nonce: &[u8; NONCE_BYTES],
            body: &[u8; PROTECTED_BODY_BYTES],
        ) -> [u8; AUTHENTICATION_BYTES] {
            let mut authentication = self.key;
            for (index, byte) in nonce.iter().chain(body).enumerate() {
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
            nonce: &[u8; NONCE_BYTES],
            body: &mut [u8; PROTECTED_BODY_BYTES],
        ) -> [u8; AUTHENTICATION_BYTES] {
            self.authentication(nonce, body)
        }

        fn open(
            &self,
            nonce: &[u8; NONCE_BYTES],
            body: &mut [u8; PROTECTED_BODY_BYTES],
            authentication: &[u8; AUTHENTICATION_BYTES],
        ) -> bool {
            let expected = self.authentication(nonce, body);
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
        available: bool,
    }

    impl OneUseReplayGuard {
        fn available() -> Self {
            Self {
                claimed: HashSet::new(),
                available: true,
            }
        }
    }

    impl ContinuationReplayGuard for OneUseReplayGuard {
        fn claim(&mut self, binding: &ReplayBinding) -> Result<(), ReplayGuardError> {
            if !self.available {
                return Err(ReplayGuardError::Unavailable);
            }
            if !self.claimed.insert(*binding) {
                return Err(ReplayGuardError::AlreadyClaimed);
            }
            Ok(())
        }
    }

    fn state() -> ContinuationState {
        ContinuationState::new(1, [0x11; 16], [0x22; 32], 41, 7, 1_000, [0x33; 24])
    }

    fn expectation() -> ContinuationExpectation {
        ContinuationExpectation::new(1, [0x11; 16], [0x22; 32], 41, 999)
    }

    fn protector() -> DeterministicTestProtector {
        DeterministicTestProtector::new(TEST_KEY)
    }

    #[test]
    fn token_round_trip_preserves_state_and_exact_size() -> Result<(), ContinuationTokenError> {
        let state = state();
        let token = ContinuationToken::issue(&state, &protector());
        let encoded = ContinuationToken::try_from_bytes(token.opaque_bytes())?;
        let decoded = encoded.validate(
            &protector(),
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
        let token = ContinuationToken::issue(&state(), &protector());

        for index in 0..CONTINUATION_TOKEN_BYTES {
            let mut tampered = *token.opaque_bytes();
            tampered[index] ^= 0x80;
            let tampered = ContinuationToken::try_from_bytes(&tampered)?;
            assert_eq!(
                tampered.validate(
                    &protector(),
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
        let authentication = protector.seal(&state.nonce, &mut body);
        let mut bytes = [0; CONTINUATION_TOKEN_BYTES];
        bytes[..NONCE_BYTES].copy_from_slice(&state.nonce);
        bytes[PROTECTED_BODY_TOKEN_START..AUTHENTICATION_TOKEN_START].copy_from_slice(&body);
        bytes[AUTHENTICATION_TOKEN_START..].copy_from_slice(&authentication);
        let token = ContinuationToken::try_from_bytes(&bytes)?;

        assert_eq!(
            token.validate(
                &protector,
                &expectation(),
                &mut OneUseReplayGuard::available(),
            ),
            Err(ContinuationTokenError::MalformedEncoding)
        );
        Ok(())
    }

    #[test]
    fn token_rejects_version_profile_query_and_epoch_mismatches() {
        let token = ContinuationToken::issue(&state(), &protector());

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
        let token = ContinuationToken::issue(&state(), &protector());
        let mut expired = expectation();
        expired.now_unix_seconds = 1_000;
        assert_validation_error(&token, &expired, ContinuationTokenError::Expired);
    }

    #[test]
    fn token_can_be_claimed_only_once() -> Result<(), ContinuationTokenError> {
        let token = ContinuationToken::issue(&state(), &protector());
        let mut replay_guard = OneUseReplayGuard::available();

        token.validate(&protector(), &expectation(), &mut replay_guard)?;
        assert_eq!(
            token.validate(&protector(), &expectation(), &mut replay_guard),
            Err(ContinuationTokenError::ReplayDetected)
        );
        Ok(())
    }

    #[test]
    fn token_fails_closed_when_replay_guard_is_unavailable() {
        let token = ContinuationToken::issue(&state(), &protector());
        assert_eq!(
            token.validate(
                &protector(),
                &expectation(),
                &mut OneUseReplayGuard::default(),
            ),
            Err(ContinuationTokenError::ReplayGuardUnavailable)
        );
    }

    #[test]
    fn debug_output_redacts_token_state_and_replay_binding() {
        let state = state();
        let token = ContinuationToken::issue(&state, &protector());

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
    }

    fn assert_validation_error(
        token: &ContinuationToken,
        expectation: &ContinuationExpectation,
        expected: ContinuationTokenError,
    ) {
        assert_eq!(
            token.validate(
                &protector(),
                expectation,
                &mut OneUseReplayGuard::available(),
            ),
            Err(expected)
        );
    }
}
