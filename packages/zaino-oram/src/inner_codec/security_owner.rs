//! Profile-bound ownership of the private runtime's security providers.
//!
//! The lease below is an internal lifetime contract. Its in-process epoch and
//! authority checks make fixture ownership and release ordering explicit, but
//! do not establish durable replay, trusted time, nonce persistence, rollback
//! resistance, key custody, or TDX evidence. In particular, the Unix-seconds
//! value carried through a round is an observation supplied by the host or
//! fixture, not an independently trusted time authority.

use std::sync::{Arc, Mutex};

use rand::TryRngCore as _;

use crate::{
    continuation_token::{
        ContinuationInspection, ContinuationReplayGuard, ContinuationReplayOutcome,
        ContinuationTokenProtector,
    },
    profile::PROFILE_ID_BYTES,
    runtime_security::{
        ReplayCommitAuthority, ReplayNamespace, RoundReservationAuthority, SecurityEpochTag,
        SecurityRoundCapture,
    },
};

use super::{EnvelopeProtector, ENVELOPE_NONCE_BYTES, SESSION_BINDING_BYTES};

#[cfg(test)]
use crate::profile::CompiledQueryShape;

#[cfg(test)]
use super::UniformExternalFailure;

const RUNTIME_SECURITY_PROTOCOL_VERSION: u16 = 1;

/// Server-owned material acquired once before any continuation replay commit.
///
/// `now_unix_seconds` is part of the exact in-process reservation tuple. That
/// binding prevents values from different fixture rounds being mixed, but does
/// not establish that the observation is monotonic, fresh, or suitable for
/// authorizing replay-claim retirement.
pub(super) struct RoundMaterial {
    now_unix_seconds: u64,
    response_nonce: [u8; ENVELOPE_NONCE_BYTES],
    token_nonce: [u8; ENVELOPE_NONCE_BYTES],
    security_round: SecurityRoundCapture,
    reservation_authority: RoundReservationAuthority,
}

impl RoundMaterial {
    pub(super) fn new(
        now_unix_seconds: u64,
        response_nonce: [u8; ENVELOPE_NONCE_BYTES],
        token_nonce: [u8; ENVELOPE_NONCE_BYTES],
        security_round: SecurityRoundCapture,
        reservation_authority: RoundReservationAuthority,
    ) -> Self {
        Self {
            now_unix_seconds,
            response_nonce,
            token_nonce,
            security_round,
            reservation_authority,
        }
    }

    pub(super) const fn now_unix_seconds(&self) -> u64 {
        self.now_unix_seconds
    }

    pub(super) const fn response_nonce(&self) -> [u8; ENVELOPE_NONCE_BYTES] {
        self.response_nonce
    }

    pub(super) const fn token_nonce(&self) -> [u8; ENVELOPE_NONCE_BYTES] {
        self.token_nonce
    }

    pub(super) const fn security_round(&self) -> &SecurityRoundCapture {
        &self.security_round
    }

    pub(super) fn into_parts(
        self,
    ) -> (
        u64,
        [u8; ENVELOPE_NONCE_BYTES],
        [u8; ENVELOPE_NONCE_BYTES],
        SecurityRoundCapture,
        RoundReservationAuthority,
    ) {
        (
            self.now_unix_seconds,
            self.response_nonce,
            self.token_nonce,
            self.security_round,
            self.reservation_authority,
        )
    }
}

impl std::fmt::Debug for RoundMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RoundMaterial { ..REDACTED.. }")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct RoundMaterialUnavailable;

/// Acquires clock and nonce values plus one opaque round reservation.
///
/// Implementations must eventually be supplied by a production owner. The
/// time field remains an observed host/fixture input: the trait alone proves no
/// time trust, nonce uniqueness, durability, or rollback resistance, and does
/// not provide a replay-maintenance authority or cadence.
pub(super) trait RoundMaterialSource {
    fn next_round_material(
        &mut self,
        security_epoch: &SecurityEpochTag,
    ) -> Result<RoundMaterial, RoundMaterialUnavailable>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct SecurityEpochUnavailable;

#[derive(Clone)]
struct InProcessSecurityEpochCurrentness {
    state: Arc<Mutex<InProcessSecurityEpochState>>,
}

struct InProcessSecurityEpochState {
    active: Option<SecurityEpochTag>,
    available: bool,
    #[cfg(test)]
    observations: usize,
}

impl InProcessSecurityEpochCurrentness {
    fn new(active: SecurityEpochTag) -> Self {
        Self {
            state: Arc::new(Mutex::new(InProcessSecurityEpochState {
                active: Some(active),
                available: true,
                #[cfg(test)]
                observations: 0,
            })),
        }
    }

    fn release_witness(&self, expected: SecurityEpochTag) -> SecurityEpochReleaseWitness {
        SecurityEpochReleaseWitness {
            expected,
            state: Arc::clone(&self.state),
        }
    }

    fn retire(&self) {
        match self.state.lock() {
            Ok(mut state) => retire_security_epoch(&mut state),
            Err(poisoned) => retire_security_epoch(&mut poisoned.into_inner()),
        }
    }

    #[cfg(all(test, feature = "corpus-zaino"))]
    fn state_for_tests(&self) -> (bool, bool, usize) {
        match self.state.lock() {
            Ok(state) => (state.active.is_some(), state.available, state.observations),
            Err(poisoned) => {
                let state = poisoned.into_inner();
                (state.active.is_some(), state.available, state.observations)
            }
        }
    }

    #[cfg(all(test, feature = "corpus-zaino"))]
    fn make_unavailable_for_tests(&self) {
        match self.state.lock() {
            Ok(mut state) => state.available = false,
            Err(poisoned) => poisoned.into_inner().available = false,
        }
    }

    #[cfg(all(test, feature = "corpus-zaino"))]
    fn remint_for_tests(&self, stable_binding: [u8; 32]) {
        match self.state.lock() {
            Ok(mut state) => state.active = Some(SecurityEpochTag::new(stable_binding)),
            Err(poisoned) => {
                poisoned.into_inner().active = Some(SecurityEpochTag::new(stable_binding));
            }
        }
    }
}

impl std::fmt::Debug for InProcessSecurityEpochCurrentness {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("InProcessSecurityEpochCurrentness { ..REDACTED.. }")
    }
}

/// Minimal process-local capability retained until response release.
pub(super) struct SecurityEpochReleaseWitness {
    expected: SecurityEpochTag,
    state: Arc<Mutex<InProcessSecurityEpochState>>,
}

impl SecurityEpochReleaseWitness {
    #[cfg(feature = "corpus-zaino")]
    pub(super) fn retire(&self) {
        match self.state.lock() {
            Ok(mut state) => retire_security_epoch(&mut state),
            Err(poisoned) => retire_security_epoch(&mut poisoned.into_inner()),
        }
    }

    pub(super) fn observe_and_match(
        &self,
        security_round: &SecurityRoundCapture,
        reservation_authority: &RoundReservationAuthority,
        replay_commit_authority: &ReplayCommitAuthority,
        now_unix_seconds: u64,
        response_nonce: &[u8; ENVELOPE_NONCE_BYTES],
        token_nonce: &[u8; ENVELOPE_NONCE_BYTES],
    ) -> Result<(), SecurityEpochUnavailable> {
        let matches = {
            let state = self.state.lock().map_err(|_| SecurityEpochUnavailable)?;
            #[cfg(test)]
            let mut state = state;
            if !state.available {
                return Err(SecurityEpochUnavailable);
            }
            #[cfg(test)]
            {
                state.observations = state
                    .observations
                    .checked_add(1)
                    .ok_or(SecurityEpochUnavailable)?;
            }
            state.active.as_ref().is_some_and(|active| {
                active.same_capture(&self.expected)
                    && reservation_authority.matches(
                        active,
                        security_round,
                        now_unix_seconds,
                        response_nonce,
                        token_nonce,
                    )
                    && replay_commit_authority.matches(active, security_round)
            })
        };
        if !matches {
            return Err(SecurityEpochUnavailable);
        }
        let state = self.state.lock().map_err(|_| SecurityEpochUnavailable)?;
        if state.available
            && state
                .active
                .as_ref()
                .is_some_and(|active| active.same_capture(&self.expected))
        {
            Ok(())
        } else {
            Err(SecurityEpochUnavailable)
        }
    }
}

impl std::fmt::Debug for SecurityEpochReleaseWitness {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecurityEpochReleaseWitness { ..REDACTED.. }")
    }
}

fn retire_security_epoch(state: &mut InProcessSecurityEpochState) {
    state.active = None;
    state.available = false;
}

/// The sole owner of all mutable and immutable runtime security providers.
///
/// The lease is intentionally non-`Clone`. It is bound to one compiled profile
/// before construction and stores only the derived replay namespace, never the
/// namespace seed fields.
pub(super) struct ActiveSecurityLease<E, T, R, M> {
    key_epoch: u64,
    session_binding: [u8; SESSION_BINDING_BYTES],
    profile_id: [u8; PROFILE_ID_BYTES],
    replay_namespace: ReplayNamespace,
    security_epoch_tag: SecurityEpochTag,
    currentness: InProcessSecurityEpochCurrentness,
    envelope_protector: E,
    token_protector: T,
    replay_guard: R,
    material_source: M,
}

impl<E, T, R, M> ActiveSecurityLease<E, T, R, M> {
    pub(super) const fn key_epoch(&self) -> u64 {
        self.key_epoch
    }

    pub(super) const fn session_binding(&self) -> [u8; SESSION_BINDING_BYTES] {
        self.session_binding
    }

    pub(super) const fn profile_id(&self) -> &[u8; PROFILE_ID_BYTES] {
        &self.profile_id
    }

    pub(super) const fn replay_namespace(&self) -> &ReplayNamespace {
        &self.replay_namespace
    }

    pub(super) const fn envelope_protector(&self) -> &E {
        &self.envelope_protector
    }

    pub(super) const fn token_protector(&self) -> &T {
        &self.token_protector
    }

    pub(super) fn release_witness(&self) -> SecurityEpochReleaseWitness {
        self.currentness
            .release_witness(self.security_epoch_tag.clone())
    }

    #[cfg(feature = "corpus-zaino")]
    pub(super) fn retire(&self) {
        self.currentness.retire();
    }

    #[cfg(test)]
    pub(super) const fn security_epoch_tag_for_tests(&self) -> &SecurityEpochTag {
        &self.security_epoch_tag
    }

    #[cfg(test)]
    pub(super) const fn replay_guard_for_tests(&self) -> &R {
        &self.replay_guard
    }

    #[cfg(test)]
    pub(super) fn replay_guard_mut_for_tests(&mut self) -> &mut R {
        &mut self.replay_guard
    }

    #[cfg(test)]
    pub(super) const fn material_source_for_tests(&self) -> &M {
        &self.material_source
    }

    #[cfg(all(test, feature = "corpus-zaino"))]
    pub(super) fn security_state_for_tests(&self) -> (bool, bool, usize) {
        self.currentness.state_for_tests()
    }

    #[cfg(all(test, feature = "corpus-zaino"))]
    pub(super) fn make_security_unavailable_for_tests(&self) {
        self.currentness.make_unavailable_for_tests();
    }

    #[cfg(all(test, feature = "corpus-zaino"))]
    pub(super) fn remint_security_epoch_for_tests(&self, stable_binding: [u8; 32]) {
        self.currentness.remint_for_tests(stable_binding);
    }
}

impl<E, T, R, M> ActiveSecurityLease<E, T, R, M>
where
    E: EnvelopeProtector,
    T: ContinuationTokenProtector,
    R: ContinuationReplayGuard,
    M: RoundMaterialSource,
{
    pub(super) fn next_round_material(
        &mut self,
    ) -> Result<RoundMaterial, RoundMaterialUnavailable> {
        self.material_source
            .next_round_material(&self.security_epoch_tag)
    }

    pub(super) fn finish_replay(
        &mut self,
        inspection: ContinuationInspection,
        security_round: &SecurityRoundCapture,
    ) -> ContinuationReplayOutcome {
        inspection.finish_replay(security_round, &mut self.replay_guard)
    }
}

impl<E, T, R, M> std::fmt::Debug for ActiveSecurityLease<E, T, R, M> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ActiveSecurityLease { ..REDACTED.. }")
    }
}

impl<E, T, R, M> Drop for ActiveSecurityLease<E, T, R, M> {
    fn drop(&mut self) {
        self.currentness.retire();
    }
}

/// Stable fixture inputs used to mint one opaque in-process security lease.
#[cfg(test)]
pub(super) struct FixtureSecurityLeaseIdentity {
    key_epoch: u64,
    session_binding: [u8; SESSION_BINDING_BYTES],
    service_namespace_id: [u8; 16],
    owner_generation: u64,
    security_epoch_binding: [u8; 32],
}

#[cfg(test)]
impl FixtureSecurityLeaseIdentity {
    pub(super) fn new(
        key_epoch: u64,
        session_binding: [u8; SESSION_BINDING_BYTES],
        service_namespace_id: [u8; 16],
        owner_generation: u64,
        security_epoch_binding: [u8; 32],
    ) -> Result<Self, UniformExternalFailure> {
        if key_epoch == 0
            || session_binding.iter().all(|byte| *byte == 0)
            || service_namespace_id.iter().all(|byte| *byte == 0)
            || owner_generation == 0
            || security_epoch_binding.iter().all(|byte| *byte == 0)
        {
            return Err(UniformExternalFailure);
        }
        Ok(Self {
            key_epoch,
            session_binding,
            service_namespace_id,
            owner_generation,
            security_epoch_binding,
        })
    }
}

#[cfg(test)]
impl<E, T, R, M> ActiveSecurityLease<E, T, R, M> {
    pub(super) fn from_fixture<const RESPONSE_SLOTS: usize, const ENVELOPE_BYTES: usize>(
        shape: CompiledQueryShape<RESPONSE_SLOTS, ENVELOPE_BYTES>,
        identity: FixtureSecurityLeaseIdentity,
        envelope_protector: E,
        token_protector: T,
        replay_guard: R,
        material_source: M,
    ) -> Self {
        let FixtureSecurityLeaseIdentity {
            key_epoch,
            session_binding,
            service_namespace_id,
            owner_generation,
            security_epoch_binding,
        } = identity;
        let profile_id = *shape.profile().profile_id();
        let replay_namespace = ReplayNamespace::new(
            service_namespace_id,
            RUNTIME_SECURITY_PROTOCOL_VERSION,
            owner_generation,
            key_epoch,
            profile_id,
            session_binding,
        );
        let security_epoch_tag = SecurityEpochTag::new(security_epoch_binding);
        let currentness = InProcessSecurityEpochCurrentness::new(security_epoch_tag.clone());
        Self {
            key_epoch,
            session_binding,
            profile_id,
            replay_namespace,
            security_epoch_tag,
            currentness,
            envelope_protector,
            token_protector,
            replay_guard,
            material_source,
        }
    }
}

/// Test-only composer for the three concrete XChaCha20 keys and fixture state.
#[cfg(test)]
pub(super) fn xchacha20_fixture_security_lease<
    R,
    M,
    const RESPONSE_SLOTS: usize,
    const ENVELOPE_BYTES: usize,
>(
    shape: CompiledQueryShape<RESPONSE_SLOTS, ENVELOPE_BYTES>,
    identity: FixtureSecurityLeaseIdentity,
    request_key: zeroize::Zeroizing<[u8; crate::xchacha20::KEY_BYTES]>,
    response_key: zeroize::Zeroizing<[u8; crate::xchacha20::KEY_BYTES]>,
    token_key: zeroize::Zeroizing<[u8; crate::xchacha20::KEY_BYTES]>,
    replay_guard: R,
    material_source: M,
) -> ActiveSecurityLease<impl EnvelopeProtector, impl ContinuationTokenProtector, R, M> {
    ActiveSecurityLease::from_fixture(
        shape,
        identity,
        super::xchacha20_envelope_protector(request_key, response_key),
        crate::continuation_token::xchacha20_token_protector(token_key),
        replay_guard,
        material_source,
    )
}

/// Fills a buffer with unpredictable bytes for one round's nonces.
///
/// Injected rather than called directly so nonce handling is testable: a real
/// generator cannot be made to fail, repeat, or collide on demand, and those
/// are exactly the paths that must fail closed.
pub(super) trait RoundEntropy {
    fn fill(&mut self, bytes: &mut [u8]) -> Result<(), RoundMaterialUnavailable>;
}

/// Observes wall-clock time in Unix seconds.
///
/// This is a host observation, not a trusted time authority; see the module
/// header. Injected for the same reason as [`RoundEntropy`] — a real clock
/// cannot be made to fail or run backwards on demand.
pub(super) trait RoundClock {
    fn now_unix_seconds(&mut self) -> Result<u64, RoundMaterialUnavailable>;
}

/// Draws nonce bytes from the operating system generator.
///
/// `OsRng` is stateless and reseeds nothing in-process, so a round never
/// depends on process-local generator state surviving a restart. A generator
/// failure surfaces as [`RoundMaterialUnavailable`] and the round is refused;
/// there is deliberately no fallback source, because silently degrading to a
/// weaker generator is the failure mode this type exists to prevent.
pub(super) struct OsEntropy;

impl RoundEntropy for OsEntropy {
    fn fill(&mut self, bytes: &mut [u8]) -> Result<(), RoundMaterialUnavailable> {
        rand::rngs::OsRng
            .try_fill_bytes(bytes)
            .map_err(|_| RoundMaterialUnavailable)
    }
}

/// Reads the host wall clock.
///
/// A pre-epoch reading is refused rather than saturated: a clock that far wrong
/// is not an observation worth binding a round to.
pub(super) struct SystemRoundClock;

impl RoundClock for SystemRoundClock {
    fn now_unix_seconds(&mut self) -> Result<u64, RoundMaterialUnavailable> {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_secs())
            .map_err(|_| RoundMaterialUnavailable)
    }
}

/// Round material drawn from an entropy source and a host clock.
///
/// Supplies the two per-round nonces from `E` and the time observation from
/// `C`, binding both to the caller's security epoch. Every failure path returns
/// [`RoundMaterialUnavailable`] and yields no material.
///
/// What this does establish: nonces come from the injected generator rather
/// than a counter, the two nonces in a round are distinct, and an observed
/// clock that moves backwards is refused.
///
/// What it still does not establish, per the module header: trusted time,
/// durable nonce persistence across restarts, rollback resistance beyond the
/// in-process observation below, or key custody.
pub(super) struct OwnedRoundMaterialSource<E, C> {
    entropy: E,
    clock: C,
    last_observed_seconds: Option<u64>,
}

impl<E, C> OwnedRoundMaterialSource<E, C> {
    pub(super) const fn new(entropy: E, clock: C) -> Self {
        Self {
            entropy,
            clock,
            last_observed_seconds: None,
        }
    }
}

impl<E, C> RoundMaterialSource for OwnedRoundMaterialSource<E, C>
where
    E: RoundEntropy,
    C: RoundClock,
{
    fn next_round_material(
        &mut self,
        security_epoch: &SecurityEpochTag,
    ) -> Result<RoundMaterial, RoundMaterialUnavailable> {
        let now_unix_seconds = self.clock.now_unix_seconds()?;
        // A repeated second is ordinary; a decrease is not. Accepting a
        // backwards jump would let an already-retired reservation window be
        // observed again, so refuse rather than trust the host clock.
        if self
            .last_observed_seconds
            .is_some_and(|last| now_unix_seconds < last)
        {
            return Err(RoundMaterialUnavailable);
        }

        let mut response_nonce = [0_u8; ENVELOPE_NONCE_BYTES];
        self.entropy.fill(&mut response_nonce)?;
        let mut token_nonce = [0_u8; ENVELOPE_NONCE_BYTES];
        self.entropy.fill(&mut token_nonce)?;

        // Two independent draws colliding means the generator is broken.
        // Reusing one nonce across the response and continuation-token
        // keystreams would cross-contaminate them, so fail closed.
        if response_nonce == token_nonce {
            return Err(RoundMaterialUnavailable);
        }

        let security_round = SecurityRoundCapture::new(security_epoch);
        let reservation_authority = RoundReservationAuthority::new(
            &security_round,
            now_unix_seconds,
            response_nonce,
            token_nonce,
        );
        // Commit the observation only once the round cannot still fail.
        self.last_observed_seconds = Some(now_unix_seconds);
        Ok(RoundMaterial::new(
            now_unix_seconds,
            response_nonce,
            token_nonce,
            security_round,
            reservation_authority,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        profile::test_profile_with_recent_snapshot,
        runtime_security::{ReplayCommitAuthority, RoundReservationAuthority},
    };

    /// Entropy stub returning scripted bytes, then failing.
    struct ScriptedEntropy {
        draws: Vec<u8>,
        next: usize,
        fail_after: Option<usize>,
    }

    impl ScriptedEntropy {
        fn new(draws: Vec<u8>) -> Self {
            Self {
                draws,
                next: 0,
                fail_after: None,
            }
        }

        fn failing_after(draws: Vec<u8>, fail_after: usize) -> Self {
            Self {
                draws,
                next: 0,
                fail_after: Some(fail_after),
            }
        }
    }

    impl RoundEntropy for ScriptedEntropy {
        fn fill(&mut self, bytes: &mut [u8]) -> Result<(), RoundMaterialUnavailable> {
            if self.fail_after.is_some_and(|limit| self.next >= limit) {
                return Err(RoundMaterialUnavailable);
            }
            let fill = *self.draws.get(self.next).ok_or(RoundMaterialUnavailable)?;
            self.next += 1;
            bytes.fill(fill);
            Ok(())
        }
    }

    /// Clock stub replaying a scripted sequence of observations.
    struct ScriptedClock {
        observations: Vec<Option<u64>>,
        next: usize,
    }

    impl ScriptedClock {
        fn new(observations: Vec<Option<u64>>) -> Self {
            Self {
                observations,
                next: 0,
            }
        }
    }

    impl RoundClock for ScriptedClock {
        fn now_unix_seconds(&mut self) -> Result<u64, RoundMaterialUnavailable> {
            let observation = *self
                .observations
                .get(self.next)
                .ok_or(RoundMaterialUnavailable)?;
            self.next += 1;
            observation.ok_or(RoundMaterialUnavailable)
        }
    }

    fn epoch_tag() -> Result<SecurityEpochTag, Box<dyn std::error::Error>> {
        let profile =
            test_profile_with_recent_snapshot("round-material-test-v1", 4, 4, 1, 512, 3, 60)?;
        let shape = CompiledQueryShape::<1, 512>::new(profile)?;
        let identity = FixtureSecurityLeaseIdentity::new(1, [1; 32], [2; 16], 1, [3; 32])?;
        let lease = ActiveSecurityLease::from_fixture(shape, identity, (), (), (), ());
        Ok(lease.security_epoch_tag.clone())
    }

    /// Sanity-checks that the OS generator is wired to real entropy rather than
    /// a zeroed or constant buffer. Two draws matching, or either draw being
    /// all-zero, would mean it is not.
    #[test]
    fn os_entropy_produces_varying_nonzero_draws() -> Result<(), Box<dyn std::error::Error>> {
        let mut entropy = OsEntropy;
        let mut first = [0_u8; ENVELOPE_NONCE_BYTES];
        let mut second = [0_u8; ENVELOPE_NONCE_BYTES];

        entropy
            .fill(&mut first)
            .map_err(|_| "OS entropy must be available")?;
        entropy
            .fill(&mut second)
            .map_err(|_| "OS entropy must be available")?;

        assert_ne!(first, [0_u8; ENVELOPE_NONCE_BYTES]);
        assert_ne!(second, [0_u8; ENVELOPE_NONCE_BYTES]);
        assert_ne!(first, second);
        Ok(())
    }

    /// The production pairing must produce a usable round end to end.
    #[test]
    fn os_backed_source_produces_a_distinct_nonce_round() -> Result<(), Box<dyn std::error::Error>>
    {
        let tag = epoch_tag()?;
        let mut source = OwnedRoundMaterialSource::new(OsEntropy, SystemRoundClock);

        let material = source
            .next_round_material(&tag)
            .map_err(|_| "OS-backed round must succeed")?;

        assert_ne!(material.response_nonce(), material.token_nonce());
        assert!(material.now_unix_seconds() > 1_700_000_000);
        Ok(())
    }

    /// Sanity-checks that the system clock is wired to a real clock: any
    /// reading at or before the 2023 constant would mean it is not.
    #[test]
    fn system_clock_reports_a_plausible_present() -> Result<(), Box<dyn std::error::Error>> {
        let observed = SystemRoundClock
            .now_unix_seconds()
            .map_err(|_| "host clock must be readable")?;

        assert!(observed > 1_700_000_000);
        Ok(())
    }

    #[test]
    fn owned_source_draws_two_distinct_nonces_from_entropy(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let tag = epoch_tag()?;
        let mut source = OwnedRoundMaterialSource::new(
            ScriptedEntropy::new(vec![0xa1, 0xb2]),
            ScriptedClock::new(vec![Some(1_700_000_000)]),
        );

        let material = source
            .next_round_material(&tag)
            .map_err(|_| "scripted round must succeed")?;

        assert_eq!(material.now_unix_seconds(), 1_700_000_000);
        assert_eq!(material.response_nonce(), [0xa1; ENVELOPE_NONCE_BYTES]);
        assert_eq!(material.token_nonce(), [0xb2; ENVELOPE_NONCE_BYTES]);
        Ok(())
    }

    #[test]
    fn owned_source_refuses_when_entropy_is_unavailable() -> Result<(), Box<dyn std::error::Error>>
    {
        let tag = epoch_tag()?;
        // Response nonce succeeds; the token nonce draw fails.
        let mut source = OwnedRoundMaterialSource::new(
            ScriptedEntropy::failing_after(vec![0xa1, 0xb2], 1),
            ScriptedClock::new(vec![Some(1_700_000_000)]),
        );

        assert!(matches!(
            source.next_round_material(&tag),
            Err(RoundMaterialUnavailable)
        ));
        Ok(())
    }

    #[test]
    fn owned_source_refuses_when_the_clock_is_unavailable() -> Result<(), Box<dyn std::error::Error>>
    {
        let tag = epoch_tag()?;
        let mut source = OwnedRoundMaterialSource::new(
            ScriptedEntropy::new(vec![0xa1, 0xb2]),
            ScriptedClock::new(vec![None]),
        );

        assert!(matches!(
            source.next_round_material(&tag),
            Err(RoundMaterialUnavailable)
        ));
        Ok(())
    }

    /// A clock that jumps backwards would let a retired reservation window be
    /// reused, so the source fails closed rather than trusting the host.
    #[test]
    fn owned_source_refuses_a_clock_that_moves_backwards() -> Result<(), Box<dyn std::error::Error>>
    {
        let tag = epoch_tag()?;
        let mut source = OwnedRoundMaterialSource::new(
            ScriptedEntropy::new(vec![0xa1, 0xb2, 0xc3, 0xd4]),
            ScriptedClock::new(vec![Some(1_700_000_010), Some(1_700_000_009)]),
        );

        source
            .next_round_material(&tag)
            .map_err(|_| "first round must succeed")?;
        assert!(matches!(
            source.next_round_material(&tag),
            Err(RoundMaterialUnavailable)
        ));
        Ok(())
    }

    /// Two rounds inside the same second are ordinary, not a rollback.
    #[test]
    fn owned_source_accepts_a_repeated_second() -> Result<(), Box<dyn std::error::Error>> {
        let tag = epoch_tag()?;
        let mut source = OwnedRoundMaterialSource::new(
            ScriptedEntropy::new(vec![0xa1, 0xb2, 0xc3, 0xd4]),
            ScriptedClock::new(vec![Some(1_700_000_010), Some(1_700_000_010)]),
        );

        source
            .next_round_material(&tag)
            .map_err(|_| "first round must succeed")?;
        let second = source
            .next_round_material(&tag)
            .map_err(|_| "same-second round must succeed")?;

        assert_eq!(second.now_unix_seconds(), 1_700_000_010);
        Ok(())
    }

    /// Identical draws mean the entropy source is broken. Reusing one nonce for
    /// both the response and the continuation token would cross-contaminate two
    /// keystreams, so the round fails closed.
    #[test]
    fn owned_source_refuses_identical_nonce_draws() -> Result<(), Box<dyn std::error::Error>> {
        let tag = epoch_tag()?;
        let mut source = OwnedRoundMaterialSource::new(
            ScriptedEntropy::new(vec![0x7f, 0x7f]),
            ScriptedClock::new(vec![Some(1_700_000_000)]),
        );

        assert!(matches!(
            source.next_round_material(&tag),
            Err(RoundMaterialUnavailable)
        ));
        Ok(())
    }

    #[test]
    fn dropping_lease_retires_an_already_minted_release_witness(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let profile =
            test_profile_with_recent_snapshot("security-owner-test-v1", 4, 4, 1, 512, 3, 60)?;
        let shape = CompiledQueryShape::<1, 512>::new(profile)?;
        let identity = FixtureSecurityLeaseIdentity::new(1, [1; 32], [2; 16], 1, [3; 32])?;
        let lease = ActiveSecurityLease::from_fixture(shape, identity, (), (), (), ());
        let security_round = SecurityRoundCapture::new(&lease.security_epoch_tag);
        let response_nonce = [4; ENVELOPE_NONCE_BYTES];
        let token_nonce = [5; ENVELOPE_NONCE_BYTES];
        let reservation_authority =
            RoundReservationAuthority::new(&security_round, 6, response_nonce, token_nonce);
        let replay_commit_authority = ReplayCommitAuthority::new(&security_round);
        let witness = lease.release_witness();

        assert!(witness
            .observe_and_match(
                &security_round,
                &reservation_authority,
                &replay_commit_authority,
                6,
                &response_nonce,
                &token_nonce,
            )
            .is_ok());
        drop(lease);

        assert!(witness
            .observe_and_match(
                &security_round,
                &reservation_authority,
                &replay_commit_authority,
                6,
                &response_nonce,
                &token_nonce,
            )
            .is_err());
        Ok(())
    }
}
