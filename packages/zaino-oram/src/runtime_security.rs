//! Crate-private value contracts for runtime security-state ownership.
//!
//! The canonical replay digests are stable, versioned record identities. The
//! epoch, round, reservation, and commit capabilities below only bind values
//! inside deterministic fixtures and one live process. Their `Arc` identities
//! prevent equal-value ABA and cross-round mixing in memory; they are not
//! durable reservation, commit, freshness, trusted-time, or rollback evidence.
//! The v5 replay identities also do not encode a maintenance transition.

use std::{fmt, sync::Arc};

use blake2::{Blake2s256, Digest};

const CANONICAL_REPLAY_ENCODING_VERSION: u16 = 1;
/// Fixed width of one opaque persistence-facing replay record identity.
pub(super) const REPLAY_RECORD_KEY_BYTES: usize = 32;
const REPLAY_DIGEST_BYTES: usize = REPLAY_RECORD_KEY_BYTES;
const NONCE_BYTES: usize = 24;

const REPLAY_NAMESPACE_DOMAIN: &[u8] = b"zaino-oram/runtime-security/replay-namespace";
const REQUEST_REPLAY_KEY_DOMAIN: &[u8] = b"zaino-oram/runtime-security/request-replay-key";
const CONTINUATION_REPLAY_KEY_DOMAIN: &[u8] =
    b"zaino-oram/runtime-security/continuation-replay-key";

/// Canonical, versioned namespace shared by both replay-record lanes.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct ReplayNamespace {
    digest: [u8; REPLAY_DIGEST_BYTES],
}

impl ReplayNamespace {
    /// Commits the complete stable replay namespace in canonical field order.
    pub(super) fn new(
        service_id: [u8; 16],
        protocol_version: u16,
        owner_generation: u64,
        key_epoch: u64,
        profile_id: [u8; 16],
        session_binding: [u8; 32],
    ) -> Self {
        let mut hasher = versioned_hasher(REPLAY_NAMESPACE_DOMAIN);
        Digest::update(&mut hasher, service_id);
        Digest::update(&mut hasher, protocol_version.to_be_bytes());
        Digest::update(&mut hasher, owner_generation.to_be_bytes());
        Digest::update(&mut hasher, key_epoch.to_be_bytes());
        Digest::update(&mut hasher, profile_id);
        Digest::update(&mut hasher, session_binding);
        Self {
            digest: finish_digest(hasher),
        }
    }
}

impl fmt::Debug for ReplayNamespace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ReplayNamespace { ..REDACTED.. }")
    }
}

/// Opaque canonical identity for one authenticated request nonce.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct RequestReplayKey {
    digest: [u8; REPLAY_DIGEST_BYTES],
}

impl RequestReplayKey {
    /// Binds only the stable namespace and authenticated request nonce.
    ///
    /// Request payload and query fields are deliberately absent. There is also
    /// no request expiry or retirement field, so continuation expiry cannot
    /// justify deleting this lane's claim.
    pub(super) fn new(namespace: &ReplayNamespace, authenticated_nonce: [u8; NONCE_BYTES]) -> Self {
        let mut hasher = versioned_hasher(REQUEST_REPLAY_KEY_DOMAIN);
        Digest::update(&mut hasher, namespace.digest);
        Digest::update(&mut hasher, authenticated_nonce);
        Self {
            digest: finish_digest(hasher),
        }
    }

    /// Returns the opaque persistence-facing record identity.
    pub(super) const fn as_bytes(&self) -> &[u8; REPLAY_DIGEST_BYTES] {
        &self.digest
    }
}

impl fmt::Debug for RequestReplayKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RequestReplayKey { ..REDACTED.. }")
    }
}

/// Opaque canonical identity for one continuation-token use.
///
/// The digest binds the exact token expiry. The post-authentication token
/// module pairs this key with its profile-derived expiry-bucket ordinal before
/// persistence can observe a continuation claim.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct ContinuationReplayKey {
    digest: [u8; REPLAY_DIGEST_BYTES],
}

impl ContinuationReplayKey {
    /// Commits every stable continuation claim field, including the exact
    /// expiry Unix second, in canonical order.
    pub(super) fn new(
        namespace: &ReplayNamespace,
        projection_epoch: u64,
        query_digest: [u8; 32],
        cursor: u64,
        expires_at_unix_seconds: u64,
        token_nonce: [u8; NONCE_BYTES],
        context_digest: [u8; 32],
    ) -> Self {
        let mut hasher = versioned_hasher(CONTINUATION_REPLAY_KEY_DOMAIN);
        Digest::update(&mut hasher, namespace.digest);
        Digest::update(&mut hasher, projection_epoch.to_be_bytes());
        Digest::update(&mut hasher, query_digest);
        Digest::update(&mut hasher, cursor.to_be_bytes());
        Digest::update(&mut hasher, expires_at_unix_seconds.to_be_bytes());
        Digest::update(&mut hasher, token_nonce);
        Digest::update(&mut hasher, context_digest);
        Self {
            digest: finish_digest(hasher),
        }
    }

    /// Returns the opaque persistence-facing record identity.
    pub(super) const fn as_bytes(&self) -> &[u8; REPLAY_DIGEST_BYTES] {
        &self.digest
    }
}

impl fmt::Debug for ContinuationReplayKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ContinuationReplayKey { ..REDACTED.. }")
    }
}

/// Semantic duplicate decision from one completed two-lane replay transaction.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum ReplayDuplicateDecision {
    /// Both requested real identities were fresh.
    Fresh,
    /// The authenticated request nonce was already committed.
    RequestDuplicate,
    /// The request was fresh but the requested continuation was already used.
    ContinuationDuplicate,
}

impl fmt::Debug for ReplayDuplicateDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ReplayDuplicateDecision([REDACTED])")
    }
}

struct SecurityEpochIdentity {
    _allocation_identity: u8,
}

/// Opaque identity of one live in-process security-epoch instance.
///
/// Equal stable bindings minted at different times intentionally do not match.
#[derive(Clone)]
pub(super) struct SecurityEpochTag {
    stable_binding: [u8; REPLAY_DIGEST_BYTES],
    identity: Arc<SecurityEpochIdentity>,
}

impl SecurityEpochTag {
    /// Creates one fixture epoch identity for the supplied stable binding.
    ///
    /// This constructor does not establish durable freshness or rollback
    /// resistance.
    pub(super) fn new(stable_binding: [u8; REPLAY_DIGEST_BYTES]) -> Self {
        Self {
            stable_binding,
            identity: Arc::new(SecurityEpochIdentity {
                _allocation_identity: 0,
            }),
        }
    }

    /// Checks pointer identity as well as the stable epoch binding.
    pub(super) fn same_capture(&self, candidate: &Self) -> bool {
        self.stable_binding == candidate.stable_binding
            && Arc::ptr_eq(&self.identity, &candidate.identity)
    }
}

impl fmt::Debug for SecurityEpochTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecurityEpochTag { ..REDACTED.. }")
    }
}

struct SecurityRoundIdentity {
    _allocation_identity: u8,
}

/// Cloneable capture shared by both authorities for exactly one round.
///
/// The capture is an in-process fixture binding, not durable commit evidence.
#[derive(Clone)]
pub(super) struct SecurityRoundCapture {
    epoch: SecurityEpochTag,
    identity: Arc<SecurityRoundIdentity>,
}

impl SecurityRoundCapture {
    /// Captures a fresh round identity under the live epoch instance.
    pub(super) fn new(epoch: &SecurityEpochTag) -> Self {
        Self {
            epoch: epoch.clone(),
            identity: Arc::new(SecurityRoundIdentity {
                _allocation_identity: 0,
            }),
        }
    }

    fn matches(&self, current_epoch: &SecurityEpochTag, candidate: &Self) -> bool {
        self.epoch.same_capture(current_epoch)
            && candidate.epoch.same_capture(current_epoch)
            && Arc::ptr_eq(&self.identity, &candidate.identity)
    }
}

impl fmt::Debug for SecurityRoundCapture {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecurityRoundCapture { ..REDACTED.. }")
    }
}

/// Non-cloneable fixture capability for one exact nonce/time reservation.
///
/// Ownership only proves that the values came from the same in-process
/// fixture contract. It is not durable nonce reservation or trusted-time
/// evidence.
pub(super) struct RoundReservationAuthority {
    round: SecurityRoundCapture,
    now_unix_seconds: u64,
    response_nonce: [u8; NONCE_BYTES],
    token_nonce: [u8; NONCE_BYTES],
}

impl RoundReservationAuthority {
    /// Binds one exact material tuple to the supplied round capture.
    pub(super) fn new(
        round: &SecurityRoundCapture,
        now_unix_seconds: u64,
        response_nonce: [u8; NONCE_BYTES],
        token_nonce: [u8; NONCE_BYTES],
    ) -> Self {
        Self {
            round: round.clone(),
            now_unix_seconds,
            response_nonce,
            token_nonce,
        }
    }

    /// Checks the exact material, same round, and same live epoch instance.
    pub(super) fn matches(
        &self,
        current_epoch: &SecurityEpochTag,
        round: &SecurityRoundCapture,
        now_unix_seconds: u64,
        response_nonce: &[u8; NONCE_BYTES],
        token_nonce: &[u8; NONCE_BYTES],
    ) -> bool {
        self.round.matches(current_epoch, round)
            && self.now_unix_seconds == now_unix_seconds
            && &self.response_nonce == response_nonce
            && &self.token_nonce == token_nonce
    }
}

impl fmt::Debug for RoundReservationAuthority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RoundReservationAuthority { ..REDACTED.. }")
    }
}

/// Non-cloneable fixture capability for one completed replay transaction.
///
/// Ownership is not durable replay-commit or rollback evidence.
pub(super) struct ReplayCommitAuthority {
    round: SecurityRoundCapture,
}

impl ReplayCommitAuthority {
    /// Binds a completed fixture transaction to one round capture.
    pub(super) fn new(round: &SecurityRoundCapture) -> Self {
        Self {
            round: round.clone(),
        }
    }

    /// Checks the same round and same live epoch instance.
    pub(super) fn matches(
        &self,
        current_epoch: &SecurityEpochTag,
        round: &SecurityRoundCapture,
    ) -> bool {
        self.round.matches(current_epoch, round)
    }
}

impl fmt::Debug for ReplayCommitAuthority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ReplayCommitAuthority { ..REDACTED.. }")
    }
}

/// One completed replay decision and its non-cloneable round capability.
pub(super) struct ReplayCommitResult {
    authority: ReplayCommitAuthority,
    decision: ReplayDuplicateDecision,
}

impl ReplayCommitResult {
    /// Couples a completed decision to its exact commit authority.
    pub(super) fn new(authority: ReplayCommitAuthority, decision: ReplayDuplicateDecision) -> Self {
        Self {
            authority,
            decision,
        }
    }

    /// Transfers both pieces without cloning the capability.
    pub(super) fn into_parts(self) -> (ReplayCommitAuthority, ReplayDuplicateDecision) {
        (self.authority, self.decision)
    }
}

impl fmt::Debug for ReplayCommitResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ReplayCommitResult { ..REDACTED.. }")
    }
}

/// The combined replay transaction did not produce an unambiguous commit.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct ReplayCommitUnavailable;

impl fmt::Debug for ReplayCommitUnavailable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ReplayCommitUnavailable")
    }
}

impl fmt::Display for ReplayCommitUnavailable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("replay commit unavailable")
    }
}

impl std::error::Error for ReplayCommitUnavailable {}

fn versioned_hasher(domain: &[u8]) -> Blake2s256 {
    let mut hasher = Blake2s256::new();
    Digest::update(&mut hasher, domain);
    Digest::update(&mut hasher, CANONICAL_REPLAY_ENCODING_VERSION.to_be_bytes());
    hasher
}

fn finish_digest(hasher: Blake2s256) -> [u8; REPLAY_DIGEST_BYTES] {
    Digest::finalize(hasher).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SERVICE_ID: [u8; 16] = [0x11; 16];
    const PROFILE_ID: [u8; 16] = [0x22; 16];
    const SESSION_BINDING: [u8; 32] = [0x33; 32];
    const REQUEST_NONCE: [u8; NONCE_BYTES] = [0x44; NONCE_BYTES];
    const TOKEN_NONCE: [u8; NONCE_BYTES] = [0x55; NONCE_BYTES];
    const RESPONSE_NONCE: [u8; NONCE_BYTES] = [0x66; NONCE_BYTES];
    const QUERY_DIGEST: [u8; 32] = [0x77; 32];
    const CONTEXT_DIGEST: [u8; 32] = [0x88; 32];

    fn namespace() -> ReplayNamespace {
        ReplayNamespace::new(SERVICE_ID, 2, 3, 4, PROFILE_ID, SESSION_BINDING)
    }

    fn continuation_key(namespace: &ReplayNamespace) -> ContinuationReplayKey {
        ContinuationReplayKey::new(
            namespace,
            5,
            QUERY_DIGEST,
            6,
            7,
            TOKEN_NONCE,
            CONTEXT_DIGEST,
        )
    }

    #[test]
    fn namespace_digest_is_sensitive_to_every_canonical_field() {
        let baseline = namespace();

        assert_ne!(
            baseline,
            ReplayNamespace::new([0x12; 16], 2, 3, 4, PROFILE_ID, SESSION_BINDING)
        );
        assert_ne!(
            baseline,
            ReplayNamespace::new(SERVICE_ID, 9, 3, 4, PROFILE_ID, SESSION_BINDING)
        );
        assert_ne!(
            baseline,
            ReplayNamespace::new(SERVICE_ID, 2, 9, 4, PROFILE_ID, SESSION_BINDING)
        );
        assert_ne!(
            baseline,
            ReplayNamespace::new(SERVICE_ID, 2, 3, 9, PROFILE_ID, SESSION_BINDING)
        );
        assert_ne!(
            baseline,
            ReplayNamespace::new(SERVICE_ID, 2, 3, 4, [0x23; 16], SESSION_BINDING)
        );
        assert_ne!(
            baseline,
            ReplayNamespace::new(SERVICE_ID, 2, 3, 4, PROFILE_ID, [0x34; 32])
        );
    }

    #[test]
    fn request_key_depends_only_on_namespace_and_authenticated_nonce() {
        let namespace = namespace();
        let baseline = RequestReplayKey::new(&namespace, REQUEST_NONCE);

        assert_eq!(baseline, RequestReplayKey::new(&namespace, REQUEST_NONCE));
        assert_ne!(
            baseline,
            RequestReplayKey::new(&namespace, [0x45; NONCE_BYTES])
        );
        assert_ne!(
            baseline,
            RequestReplayKey::new(
                &ReplayNamespace::new(SERVICE_ID, 2, 3, 5, PROFILE_ID, SESSION_BINDING,),
                REQUEST_NONCE,
            )
        );
        // Payload and query values cannot affect the key because the
        // constructor accepts neither.
    }

    #[test]
    fn continuation_key_is_sensitive_to_every_canonical_field() {
        let namespace = namespace();
        let baseline = continuation_key(&namespace);

        assert_ne!(
            baseline,
            ContinuationReplayKey::new(
                &ReplayNamespace::new(SERVICE_ID, 2, 3, 5, PROFILE_ID, SESSION_BINDING,),
                5,
                QUERY_DIGEST,
                6,
                7,
                TOKEN_NONCE,
                CONTEXT_DIGEST,
            )
        );
        assert_ne!(
            baseline,
            ContinuationReplayKey::new(
                &namespace,
                8,
                QUERY_DIGEST,
                6,
                7,
                TOKEN_NONCE,
                CONTEXT_DIGEST,
            )
        );
        assert_ne!(
            baseline,
            ContinuationReplayKey::new(
                &namespace,
                5,
                [0x78; 32],
                6,
                7,
                TOKEN_NONCE,
                CONTEXT_DIGEST,
            )
        );
        assert_ne!(
            baseline,
            ContinuationReplayKey::new(
                &namespace,
                5,
                QUERY_DIGEST,
                8,
                7,
                TOKEN_NONCE,
                CONTEXT_DIGEST,
            )
        );
        assert_ne!(
            baseline,
            ContinuationReplayKey::new(
                &namespace,
                5,
                QUERY_DIGEST,
                6,
                8,
                TOKEN_NONCE,
                CONTEXT_DIGEST,
            )
        );
        assert_ne!(
            baseline,
            ContinuationReplayKey::new(
                &namespace,
                5,
                QUERY_DIGEST,
                6,
                7,
                [0x56; NONCE_BYTES],
                CONTEXT_DIGEST,
            )
        );
        assert_ne!(
            baseline,
            ContinuationReplayKey::new(&namespace, 5, QUERY_DIGEST, 6, 7, TOKEN_NONCE, [0x89; 32],)
        );
    }

    #[test]
    fn replay_domains_are_distinct_and_stable_fields_ignore_arc_addresses() {
        let first_namespace = namespace();
        let second_namespace = namespace();
        let request = RequestReplayKey::new(&first_namespace, REQUEST_NONCE);
        let continuation = continuation_key(&first_namespace);

        assert_eq!(
            request,
            RequestReplayKey::new(&second_namespace, REQUEST_NONCE)
        );
        assert_eq!(continuation, continuation_key(&second_namespace));
        assert_ne!(first_namespace.digest, *request.as_bytes());
        assert_ne!(*request.as_bytes(), *continuation.as_bytes());
    }

    #[test]
    fn recreated_equal_value_epoch_does_not_match_live_capture() {
        let live_epoch = SecurityEpochTag::new([0xaa; REPLAY_DIGEST_BYTES]);
        let recreated_epoch = SecurityEpochTag::new([0xaa; REPLAY_DIGEST_BYTES]);
        let round = SecurityRoundCapture::new(&live_epoch);
        let reservation = RoundReservationAuthority::new(&round, 100, RESPONSE_NONCE, TOKEN_NONCE);

        assert!(reservation.matches(&live_epoch, &round, 100, &RESPONSE_NONCE, &TOKEN_NONCE,));
        assert!(!reservation.matches(&recreated_epoch, &round, 100, &RESPONSE_NONCE, &TOKEN_NONCE,));
    }

    #[test]
    fn authorities_from_distinct_rounds_cannot_be_mixed() {
        let epoch = SecurityEpochTag::new([0xaa; REPLAY_DIGEST_BYTES]);
        let first_round = SecurityRoundCapture::new(&epoch);
        let second_round = SecurityRoundCapture::new(&epoch);
        let reservation =
            RoundReservationAuthority::new(&first_round, 100, RESPONSE_NONCE, TOKEN_NONCE);
        let first_commit = ReplayCommitAuthority::new(&first_round);
        let second_commit = ReplayCommitAuthority::new(&second_round);

        assert!(reservation.matches(&epoch, &first_round, 100, &RESPONSE_NONCE, &TOKEN_NONCE,));
        assert!(first_commit.matches(&epoch, &first_round));
        assert!(!reservation.matches(&epoch, &second_round, 100, &RESPONSE_NONCE, &TOKEN_NONCE,));
        assert!(!second_commit.matches(&epoch, &first_round));
    }

    #[test]
    fn reservation_matching_is_sensitive_to_every_exact_value() {
        let epoch = SecurityEpochTag::new([0xaa; REPLAY_DIGEST_BYTES]);
        let round = SecurityRoundCapture::new(&epoch);
        let reservation = RoundReservationAuthority::new(&round, 100, RESPONSE_NONCE, TOKEN_NONCE);

        assert!(!reservation.matches(&epoch, &round, 101, &RESPONSE_NONCE, &TOKEN_NONCE,));
        assert!(!reservation.matches(&epoch, &round, 100, &[0x67; NONCE_BYTES], &TOKEN_NONCE,));
        assert!(!reservation.matches(&epoch, &round, 100, &RESPONSE_NONCE, &[0x56; NONCE_BYTES],));
    }

    #[test]
    fn replay_result_transfers_authority_and_decision() {
        let epoch = SecurityEpochTag::new([0xaa; REPLAY_DIGEST_BYTES]);
        let round = SecurityRoundCapture::new(&epoch);
        let result = ReplayCommitResult::new(
            ReplayCommitAuthority::new(&round),
            ReplayDuplicateDecision::RequestDuplicate,
        );
        let (authority, decision) = result.into_parts();

        assert_eq!(decision, ReplayDuplicateDecision::RequestDuplicate);
        assert!(authority.matches(&epoch, &round));
    }

    #[test]
    fn debug_output_redacts_all_identity_and_capability_material() {
        let namespace = namespace();
        let request = RequestReplayKey::new(&namespace, REQUEST_NONCE);
        let continuation = continuation_key(&namespace);
        let epoch = SecurityEpochTag::new([0xaa; REPLAY_DIGEST_BYTES]);
        let round = SecurityRoundCapture::new(&epoch);
        let reservation = RoundReservationAuthority::new(&round, 100, RESPONSE_NONCE, TOKEN_NONCE);
        let commit = ReplayCommitAuthority::new(&round);

        assert_eq!(format!("{namespace:?}"), "ReplayNamespace { ..REDACTED.. }");
        assert_eq!(format!("{request:?}"), "RequestReplayKey { ..REDACTED.. }");
        assert_eq!(
            format!("{continuation:?}"),
            "ContinuationReplayKey { ..REDACTED.. }"
        );
        assert_eq!(format!("{epoch:?}"), "SecurityEpochTag { ..REDACTED.. }");
        assert_eq!(
            format!("{round:?}"),
            "SecurityRoundCapture { ..REDACTED.. }"
        );
        assert_eq!(
            format!("{reservation:?}"),
            "RoundReservationAuthority { ..REDACTED.. }"
        );
        assert_eq!(
            format!("{commit:?}"),
            "ReplayCommitAuthority { ..REDACTED.. }"
        );
    }
}
