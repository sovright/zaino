//! Profile-bound ownership of the private runtime's security providers.
//!
//! The lease below is an internal lifetime contract. Its in-process epoch and
//! authority checks make fixture ownership and release ordering explicit, but
//! do not establish durable replay, trusted time, nonce persistence, rollback
//! resistance, key custody, or TDX evidence. In particular, the Unix-seconds
//! value carried through a round is an observation supplied by the host or
//! fixture, not an independently trusted time authority.

use std::sync::{Arc, Mutex};

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        profile::test_profile_with_recent_snapshot,
        runtime_security::{ReplayCommitAuthority, RoundReservationAuthority},
    };

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
