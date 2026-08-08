//! Listener-free composition of the fixed codec, token controller, engine, and
//! logical phase recorder.
//!
//! This module proves only a deterministic source-level logical schedule for
//! the injected research fixtures and withholds a completed envelope unless
//! its pinned serving epoch is still current after response encoding. It does
//! not provide a production key/session owner, nonce source, trusted clock,
//! replay database, listener, transport-write guard, physical ORAM trace,
//! timing result, or TDX claim. The round's Unix-seconds value is only observed
//! host/fixture input used by token issue and validation; it does not authorize
//! replay-journal maintenance or claim retirement.

use crate::{
    continuation_token::{
        ContinuationExpectation, ContinuationReplayGuard, ContinuationState, ContinuationToken,
        ContinuationTokenProtector, ContinuationUse, CONTINUATION_TOKEN_BYTES,
        CONTINUATION_VERSION,
    },
    engine::PrivateQueryEngine,
    envelope::FixedEnvelope,
    profile::CompiledQueryShape,
    recent_snapshot::{
        bind_query_digest, content_digest, lineage_binding_digest, FrozenRecentSnapshot,
        RecentSnapshotIdentity, RecentSnapshotSlot, ServingEpochBoundary, ServingEpochCurrentness,
        ServingEpochLease, ServingEpochStore,
    },
    records::{QueryOutcome, UtxoResultPage},
    runtime_security::{ReplayCommitAuthority, RoundReservationAuthority, SecurityRoundCapture},
    store::ObliviousStore,
    trace::{AccessTrace, CompletionShape, RuntimePhase, TraceRecorder},
};

#[cfg(feature = "corpus-zaino")]
use crate::{
    canonical_chain::CanonicalNetwork,
    private_runtime::{FixedEnvelopeRuntime, PendingFixedEnvelope, PrivateQueryUnavailable},
    projection_owner::FinalizedProjectionServingStore,
    recent_snapshot::{
        CanonicalServingEpochCurrentness, RecentSnapshotRefreshController,
        ServingEpochReleaseWitness,
    },
};

#[cfg(feature = "corpus-zaino")]
use zaino_state::{
    chain_index::CanonicalTransparentProjectionBoundary, BlockchainSource,
    NodeBackedChainIndexSubscriber,
};

#[cfg(feature = "corpus-zaino")]
use std::sync::{
    atomic::{AtomicU8, Ordering},
    Arc, OnceLock,
};

#[cfg(test)]
use crate::{
    protection::{AuthenticationDecision, ProtectionUnavailable},
    recent_snapshot::{ServingEpochObservation, ServingEpochUnavailable},
};

use super::{
    security_owner::{ActiveSecurityLease, RoundMaterialSource},
    EnvelopeProtector, InnerCodecError, PrivateQueryCheckpoint, PrivateQueryCodec,
    PrivateQueryResponse, UniformExternalFailure, ENVELOPE_NONCE_BYTES,
};

#[cfg(feature = "corpus-zaino")]
use super::{security_owner::SecurityEpochReleaseWitness, PrivateNetwork};

#[cfg(test)]
use super::security_owner::{
    xchacha20_security_lease, RoundMaterial, RoundMaterialUnavailable, SecurityLeaseIdentity,
};

/// One encoded response retaining both fixture-contract authorities.
struct EncodedRuntimeRound<const ENVELOPE_BYTES: usize> {
    envelope: FixedEnvelope<ENVELOPE_BYTES>,
    trace: AccessTrace,
    now_unix_seconds: u64,
    response_nonce: [u8; ENVELOPE_NONCE_BYTES],
    token_nonce: [u8; ENVELOPE_NONCE_BYTES],
    security_round: SecurityRoundCapture,
    reservation_authority: RoundReservationAuthority,
    replay_commit_authority: ReplayCommitAuthority,
}

impl<const ENVELOPE_BYTES: usize> EncodedRuntimeRound<ENVELOPE_BYTES> {
    fn into_released(self) -> RuntimeRound<ENVELOPE_BYTES> {
        RuntimeRound {
            envelope: self.envelope,
            trace: self.trace,
        }
    }
}

/// One completed protected envelope authorized for caller release.
struct RuntimeRound<const ENVELOPE_BYTES: usize> {
    envelope: FixedEnvelope<ENVELOPE_BYTES>,
    trace: AccessTrace,
}

impl<const ENVELOPE_BYTES: usize> RuntimeRound<ENVELOPE_BYTES> {
    #[cfg(test)]
    const fn envelope(&self) -> &FixedEnvelope<ENVELOPE_BYTES> {
        &self.envelope
    }

    #[cfg(test)]
    const fn trace(&self) -> &AccessTrace {
        &self.trace
    }
}

#[cfg(feature = "corpus-zaino")]
const RESPONSE_RELEASE_IDLE: u8 = 0;
#[cfg(feature = "corpus-zaino")]
const RESPONSE_RELEASE_PENDING: u8 = 1;
#[cfg(feature = "corpus-zaino")]
const RESPONSE_RELEASE_REFRESHING: u8 = 2;
#[cfg(feature = "corpus-zaino")]
const RESPONSE_RELEASE_CLOSED: u8 = 3;
#[cfg(feature = "corpus-zaino")]
const RESPONSE_RELEASE_CHECKING: u8 = 4;
#[cfg(feature = "corpus-zaino")]
const RESPONSE_RELEASE_AUTHORIZED: u8 = 5;

/// Single-owner exclusion between response release and epoch lifecycle work.
///
/// This gate does not know about a listener or transport. A later caller must
/// retain the pending-round permit for exactly as long as its response remains
/// eligible for release. Until then, refresh and shutdown fail before changing
/// the retained epoch.
#[cfg(feature = "corpus-zaino")]
struct ResponseReleaseGate {
    state: Arc<AtomicU8>,
}

#[cfg(feature = "corpus-zaino")]
impl ResponseReleaseGate {
    fn new() -> Self {
        Self {
            state: Arc::new(AtomicU8::new(RESPONSE_RELEASE_IDLE)),
        }
    }

    fn begin_response(&self) -> Result<ResponseReleasePermit, FinalizedRuntimeOwnerError> {
        self.begin(RESPONSE_RELEASE_PENDING)
    }

    fn begin_refresh(&self) -> Result<ResponseReleasePermit, FinalizedRuntimeOwnerError> {
        self.begin(RESPONSE_RELEASE_REFRESHING)
    }

    fn begin(&self, held_state: u8) -> Result<ResponseReleasePermit, FinalizedRuntimeOwnerError> {
        self.state
            .compare_exchange(
                RESPONSE_RELEASE_IDLE,
                held_state,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .map_err(|_| FinalizedRuntimeOwnerError)?;
        Ok(ResponseReleasePermit {
            state: Arc::clone(&self.state),
            held_state,
        })
    }

    fn stop(&self) -> Result<(), FinalizedRuntimeOwnerError> {
        match self.state.compare_exchange(
            RESPONSE_RELEASE_IDLE,
            RESPONSE_RELEASE_CLOSED,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) | Err(RESPONSE_RELEASE_CLOSED) => Ok(()),
            Err(_) => Err(FinalizedRuntimeOwnerError),
        }
    }

    fn close(&self) {
        self.state.store(RESPONSE_RELEASE_CLOSED, Ordering::Release);
    }

    fn is_idle(&self) -> bool {
        self.state.load(Ordering::Acquire) == RESPONSE_RELEASE_IDLE
    }

    #[cfg(test)]
    fn is_refreshing_for_tests(&self) -> bool {
        self.state.load(Ordering::Acquire) == RESPONSE_RELEASE_REFRESHING
    }

    #[cfg(test)]
    fn is_closed_for_tests(&self) -> bool {
        self.state.load(Ordering::Acquire) == RESPONSE_RELEASE_CLOSED
    }
}

#[cfg(feature = "corpus-zaino")]
impl std::fmt::Debug for ResponseReleaseGate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ResponseReleaseGate { ..REDACTED.. }")
    }
}

/// Unique proof that one response or refresh owns the release gate.
#[cfg(feature = "corpus-zaino")]
struct ResponseReleasePermit {
    state: Arc<AtomicU8>,
    held_state: u8,
}

#[cfg(feature = "corpus-zaino")]
impl ResponseReleasePermit {
    fn begin_response_release(&self) -> bool {
        self.held_state == RESPONSE_RELEASE_PENDING
            && self
                .state
                .compare_exchange(
                    RESPONSE_RELEASE_PENDING,
                    RESPONSE_RELEASE_CHECKING,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
    }

    fn authorize_response_release(&self) -> bool {
        self.state
            .compare_exchange(
                RESPONSE_RELEASE_CHECKING,
                RESPONSE_RELEASE_AUTHORIZED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }

    fn fail_closed(&self) {
        self.state.store(RESPONSE_RELEASE_CLOSED, Ordering::Release);
    }
}

#[cfg(feature = "corpus-zaino")]
impl Drop for ResponseReleasePermit {
    fn drop(&mut self) {
        if self
            .state
            .compare_exchange(
                self.held_state,
                RESPONSE_RELEASE_IDLE,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
        {
            return;
        }
        if self.held_state == RESPONSE_RELEASE_PENDING
            && self
                .state
                .compare_exchange(
                    RESPONSE_RELEASE_AUTHORIZED,
                    RESPONSE_RELEASE_IDLE,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
        {
            return;
        }
        self.fail_closed();
    }
}

#[cfg(feature = "corpus-zaino")]
impl std::fmt::Debug for ResponseReleasePermit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ResponseReleasePermit { ..REDACTED.. }")
    }
}

/// One completed runtime round whose release permit remains outstanding.
#[cfg(feature = "corpus-zaino")]
struct PendingRuntimeRound<B, C, const ENVELOPE_BYTES: usize> {
    round: EncodedRuntimeRound<ENVELOPE_BYTES>,
    serving_release_witness: ServingEpochReleaseWitness<B, C>,
    security_release_witness: SecurityEpochReleaseWitness,
    release_decision: OnceLock<Result<(), UniformExternalFailure>>,
    release_permit: ResponseReleasePermit,
}

#[cfg(feature = "corpus-zaino")]
impl<B, C, const ENVELOPE_BYTES: usize> PendingRuntimeRound<B, C, ENVELOPE_BYTES>
where
    B: ServingEpochBoundary,
    C: ServingEpochCurrentness<B>,
{
    fn try_release_bytes(&self) -> Result<&[u8; ENVELOPE_BYTES], UniformExternalFailure> {
        let decision = self.release_decision.get_or_init(|| {
            if !self.release_permit.begin_response_release() {
                self.fail_closed();
                return Err(UniformExternalFailure);
            }
            if self.serving_release_witness.observe_and_match().is_err()
                || self
                    .security_release_witness
                    .observe_and_match(
                        &self.round.security_round,
                        &self.round.reservation_authority,
                        &self.round.replay_commit_authority,
                        self.round.now_unix_seconds,
                        &self.round.response_nonce,
                        &self.round.token_nonce,
                    )
                    .is_err()
            {
                self.fail_closed();
                return Err(UniformExternalFailure);
            }
            if !self.release_permit.authorize_response_release() {
                self.fail_closed();
                return Err(UniformExternalFailure);
            }
            Ok(())
        });
        match decision {
            Ok(()) => Ok(self.round.envelope.as_bytes()),
            Err(_) => Err(UniformExternalFailure),
        }
    }

    fn fail_closed(&self) {
        self.security_release_witness.retire();
        self.release_permit.fail_closed();
    }
}

#[cfg(feature = "corpus-zaino")]
impl<B, C, const ENVELOPE_BYTES: usize> PendingFixedEnvelope<ENVELOPE_BYTES>
    for PendingRuntimeRound<B, C, ENVELOPE_BYTES>
where
    B: ServingEpochBoundary,
    C: ServingEpochCurrentness<B>,
{
    fn try_release_bytes(&self) -> Result<&[u8; ENVELOPE_BYTES], PrivateQueryUnavailable> {
        PendingRuntimeRound::try_release_bytes(self).map_err(|_| PrivateQueryUnavailable)
    }
}

#[cfg(all(feature = "corpus-zaino", test))]
impl<B, C, const ENVELOPE_BYTES: usize> PendingRuntimeRound<B, C, ENVELOPE_BYTES> {
    const fn trace(&self) -> &AccessTrace {
        &self.round.trace
    }
}

#[cfg(feature = "corpus-zaino")]
impl<B, C, const ENVELOPE_BYTES: usize> std::fmt::Debug
    for PendingRuntimeRound<B, C, ENVELOPE_BYTES>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PendingRuntimeRound { ..REDACTED.. }")
    }
}

/// Epoch-scoped query state replaced only after one coherent controller refresh.
struct PrivateQueryRuntimeEpoch<
    S,
    C,
    B,
    const RESPONSE_SLOTS: usize,
    const ENVELOPE_BYTES: usize,
    const RECENT_SNAPSHOT_SLOTS: usize,
> {
    engine: PrivateQueryEngine<ServingEpochStore<S>, RESPONSE_SLOTS, ENVELOPE_BYTES>,
    recent_snapshot: FrozenRecentSnapshot<RECENT_SNAPSHOT_SLOTS>,
    recent_snapshot_content_digest: [u8; 32],
    recent_snapshot_binding_digest: [u8; 32],
    serving_epoch: ServingEpochLease<RECENT_SNAPSHOT_SLOTS, B, S, C>,
    checkpoint: PrivateQueryCheckpoint,
}

impl<
        S,
        C,
        B,
        const RESPONSE_SLOTS: usize,
        const ENVELOPE_BYTES: usize,
        const RECENT_SNAPSHOT_SLOTS: usize,
    > PrivateQueryRuntimeEpoch<S, C, B, RESPONSE_SLOTS, ENVELOPE_BYTES, RECENT_SNAPSHOT_SLOTS>
where
    S: ObliviousStore,
{
    fn new(
        serving_epoch: ServingEpochLease<RECENT_SNAPSHOT_SLOTS, B, S, C>,
        shape: CompiledQueryShape<RESPONSE_SLOTS, ENVELOPE_BYTES>,
        checkpoint: PrivateQueryCheckpoint,
    ) -> Result<Self, UniformExternalFailure> {
        let recent_snapshot = serving_epoch.snapshot().clone();
        if recent_snapshot.slots() != RECENT_SNAPSHOT_SLOTS
            || recent_snapshot.identity() != recent_snapshot_identity(&checkpoint)
        {
            return Err(UniformExternalFailure);
        }
        let recent_snapshot_content_digest = recent_snapshot.content_digest();
        let recent_snapshot_binding_digest = recent_snapshot.binding_digest();
        let engine = PrivateQueryEngine::new(serving_epoch.finalized_store(), shape)
            .map_err(|_| UniformExternalFailure)?;
        Ok(Self {
            engine,
            recent_snapshot,
            recent_snapshot_content_digest,
            recent_snapshot_binding_digest,
            serving_epoch,
            checkpoint,
        })
    }
}

/// Private synchronous adapter for one process-lifetime protection context.
struct PrivateQueryRuntime<
    S,
    E,
    T,
    R,
    N,
    C,
    B,
    const RESPONSE_SLOTS: usize,
    const ENVELOPE_BYTES: usize,
    const RECENT_SNAPSHOT_SLOTS: usize,
> {
    shape: CompiledQueryShape<RESPONSE_SLOTS, ENVELOPE_BYTES>,
    codec: PrivateQueryCodec<RESPONSE_SLOTS, ENVELOPE_BYTES>,
    security: ActiveSecurityLease<E, T, R, N>,
    epoch: Option<
        PrivateQueryRuntimeEpoch<S, C, B, RESPONSE_SLOTS, ENVELOPE_BYTES, RECENT_SNAPSHOT_SLOTS>,
    >,
    healthy: bool,
}

impl<
        S,
        E,
        T,
        R,
        N,
        C,
        B,
        const RESPONSE_SLOTS: usize,
        const ENVELOPE_BYTES: usize,
        const RECENT_SNAPSHOT_SLOTS: usize,
    >
    PrivateQueryRuntime<S, E, T, R, N, C, B, RESPONSE_SLOTS, ENVELOPE_BYTES, RECENT_SNAPSHOT_SLOTS>
where
    S: ObliviousStore,
    E: EnvelopeProtector,
    T: ContinuationTokenProtector,
    R: ContinuationReplayGuard,
    N: RoundMaterialSource,
    C: ServingEpochCurrentness<B>,
    B: ServingEpochBoundary,
{
    fn without_epoch(
        shape: CompiledQueryShape<RESPONSE_SLOTS, ENVELOPE_BYTES>,
        security: ActiveSecurityLease<E, T, R, N>,
    ) -> Result<Self, UniformExternalFailure> {
        shape
            .profile()
            .validate_recent_snapshot_slots::<RECENT_SNAPSHOT_SLOTS>()
            .map_err(|_| UniformExternalFailure)?;
        let combined_scan_slots = shape
            .profile()
            .combined_scan_slots()
            .map_err(|_| UniformExternalFailure)?;
        u64::try_from(combined_scan_slots).map_err(|_| UniformExternalFailure)?;
        if security.profile_id() != shape.profile().profile_id() {
            return Err(UniformExternalFailure);
        }
        let codec = PrivateQueryCodec::new(&shape, security.session_binding())
            .map_err(InnerCodecError::into_uniform_external_failure)?;
        Ok(Self {
            shape,
            codec,
            security,
            epoch: None,
            healthy: true,
        })
    }

    fn new(
        serving_epoch: ServingEpochLease<RECENT_SNAPSHOT_SLOTS, B, S, C>,
        shape: CompiledQueryShape<RESPONSE_SLOTS, ENVELOPE_BYTES>,
        checkpoint: PrivateQueryCheckpoint,
        security: ActiveSecurityLease<E, T, R, N>,
    ) -> Result<Self, UniformExternalFailure> {
        let mut runtime = Self::without_epoch(shape, security)?;
        runtime.activate_epoch(serving_epoch, checkpoint)?;
        Ok(runtime)
    }

    fn activate_epoch(
        &mut self,
        serving_epoch: ServingEpochLease<RECENT_SNAPSHOT_SLOTS, B, S, C>,
        checkpoint: PrivateQueryCheckpoint,
    ) -> Result<(), UniformExternalFailure> {
        self.epoch = None;
        if !self.healthy || checkpoint.key_epoch != self.security.key_epoch() {
            return Err(UniformExternalFailure);
        }
        let epoch = PrivateQueryRuntimeEpoch::new(serving_epoch, self.shape, checkpoint)?;
        self.epoch = Some(epoch);
        Ok(())
    }

    #[cfg(feature = "corpus-zaino")]
    fn retire_epoch(&mut self) {
        self.epoch = None;
    }

    #[cfg(feature = "corpus-zaino")]
    fn retire_security_epoch(&mut self) {
        self.security.retire();
    }

    #[cfg(test)]
    fn epoch_for_tests(
        &self,
    ) -> &PrivateQueryRuntimeEpoch<S, C, B, RESPONSE_SLOTS, ENVELOPE_BYTES, RECENT_SNAPSHOT_SLOTS>
    {
        self.epoch
            .as_ref()
            .expect("test runtime has an active serving epoch")
    }

    #[cfg(test)]
    fn epoch_mut_for_tests(
        &mut self,
    ) -> &mut PrivateQueryRuntimeEpoch<S, C, B, RESPONSE_SLOTS, ENVELOPE_BYTES, RECENT_SNAPSHOT_SLOTS>
    {
        self.epoch
            .as_mut()
            .expect("test runtime has an active serving epoch")
    }

    #[cfg(test)]
    fn continuation_query_digest_for_tests(&self, query: &crate::records::UtxoQuery) -> [u8; 32] {
        self.continuation_query_digest(self.epoch_for_tests(), query)
    }

    /// Handles one fixed request without owning any listener or transport.
    fn handle(
        &mut self,
        envelope: &FixedEnvelope<ENVELOPE_BYTES>,
    ) -> Result<RuntimeRound<ENVELOPE_BYTES>, UniformExternalFailure> {
        if !self.healthy {
            return Err(UniformExternalFailure);
        }
        let mut epoch = self.epoch.take().ok_or(UniformExternalFailure)?;
        let result = self.handle_epoch(&mut epoch, envelope);
        self.epoch = Some(epoch);
        result
    }

    fn handle_epoch(
        &mut self,
        epoch: &mut PrivateQueryRuntimeEpoch<
            S,
            C,
            B,
            RESPONSE_SLOTS,
            ENVELOPE_BYTES,
            RECENT_SNAPSHOT_SLOTS,
        >,
        envelope: &FixedEnvelope<ENVELOPE_BYTES>,
    ) -> Result<RuntimeRound<ENVELOPE_BYTES>, UniformExternalFailure> {
        let round = self.execute_epoch(epoch, envelope)?;
        let observation = match epoch.serving_epoch.observe_current() {
            Ok(observation) => observation,
            Err(_) => return Err(self.latch_failure()),
        };
        if !epoch.serving_epoch.is_current(&observation) {
            return Err(self.latch_failure());
        }
        let security_release_witness = self.security.release_witness();
        if security_release_witness
            .observe_and_match(
                &round.security_round,
                &round.reservation_authority,
                &round.replay_commit_authority,
                round.now_unix_seconds,
                &round.response_nonce,
                &round.token_nonce,
            )
            .is_err()
        {
            return Err(self.latch_failure());
        }
        Ok(round.into_released())
    }

    #[cfg(feature = "corpus-zaino")]
    fn handle_with_release_witness(
        &mut self,
        envelope: &FixedEnvelope<ENVELOPE_BYTES>,
    ) -> Result<
        (
            EncodedRuntimeRound<ENVELOPE_BYTES>,
            ServingEpochReleaseWitness<B, C>,
            SecurityEpochReleaseWitness,
        ),
        UniformExternalFailure,
    > {
        let mut epoch = self.epoch.take().ok_or(UniformExternalFailure)?;
        let security_release_witness = self.security.release_witness();
        let result = self.execute_epoch(&mut epoch, envelope).map(|round| {
            (
                round,
                epoch.serving_epoch.release_witness(),
                security_release_witness,
            )
        });
        self.epoch = Some(epoch);
        result
    }

    fn execute_epoch(
        &mut self,
        epoch: &mut PrivateQueryRuntimeEpoch<
            S,
            C,
            B,
            RESPONSE_SLOTS,
            ENVELOPE_BYTES,
            RECENT_SNAPSHOT_SLOTS,
        >,
        envelope: &FixedEnvelope<ENVELOPE_BYTES>,
    ) -> Result<EncodedRuntimeRound<ENVELOPE_BYTES>, UniformExternalFailure> {
        let decoded_request = self
            .codec
            .decode_request_with_nonce(envelope, self.security.envelope_protector());
        let (request, request_nonce) = match decoded_request {
            Ok(request) => request,
            Err(InnerCodecError::ProtectionUnavailable) => return Err(self.latch_failure()),
            Err(error) => return Err(error.into_uniform_external_failure()),
        };

        let profile = *epoch.engine.profile();
        let mut trace = TraceRecorder::new();
        trace
            .record_request_frame(ENVELOPE_BYTES)
            .map_err(|_| self.latch_failure())?;
        trace
            .record_runtime_phase(RuntimePhase::RequestDecode)
            .map_err(|_| self.latch_failure())?;

        let material = self
            .security
            .next_round_material()
            .map_err(|_| self.latch_failure())?;
        trace
            .record_runtime_phase(RuntimePhase::NonceAcquisition)
            .map_err(|_| self.latch_failure())?;

        let query_digest = self.continuation_query_digest(epoch, request.query());
        let cursor_limit = u64::try_from(
            profile
                .combined_scan_slots()
                .map_err(|_| self.latch_failure())?,
        )
        .map_err(|_| self.latch_failure())?;
        // This observed round value drives token semantics only. Matching it to
        // the reservation later prevents cross-round mixing, but does not turn
        // it into a trusted clock or an eviction/maintenance cutoff.
        let initial_expiry = material
            .now_unix_seconds()
            .checked_add(profile.continuation_ttl_seconds())
            .ok_or_else(|| self.latch_failure())?;
        let token_context = self
            .codec
            .continuation_protection_context(&epoch.checkpoint)
            .map_err(|error| {
                self.healthy = false;
                error.into_uniform_external_failure()
            })?;
        let expectation = ContinuationExpectation::new(
            CONTINUATION_VERSION,
            &profile,
            query_digest,
            epoch.checkpoint.projection_epoch,
            material.now_unix_seconds(),
            cursor_limit,
        );
        let inspection = ContinuationToken::inspect_optional(
            request.continuation.as_ref(),
            self.security.token_protector(),
            &token_context,
            &expectation,
            self.security.replay_namespace(),
            request_nonce,
        );
        trace
            .record_runtime_phase(RuntimePhase::TokenOpen)
            .map_err(|_| self.latch_failure())?;

        let (continuation_use, replay_commit_authority) = self
            .security
            .finish_replay(inspection, material.security_round())
            .into_parts();
        trace
            .record_replay_access()
            .map_err(|_| self.latch_failure())?;
        trace
            .record_runtime_phase(RuntimePhase::ReplayGuard)
            .map_err(|_| self.latch_failure())?;

        let was_healthy = self.healthy;
        let checkpoint_matches = request.checkpoint == epoch.checkpoint;
        let replay_unavailable = replay_commit_authority.is_none();
        let (
            cursor,
            continuation_expiry,
            invalid_continuation,
            request_duplicate,
            mut token_protection_unavailable,
        ) = match continuation_use {
            ContinuationUse::Initial => (0, initial_expiry, false, false, false),
            ContinuationUse::Continue {
                cursor,
                expires_at_unix_seconds,
            } => (
                usize::try_from(cursor).map_err(|_| self.latch_failure())?,
                expires_at_unix_seconds,
                false,
                false,
                false,
            ),
            ContinuationUse::InvalidContinuation => (0, initial_expiry, true, false, false),
            ContinuationUse::ProjectionNotReady => (0, initial_expiry, false, true, false),
            ContinuationUse::ProtectionUnavailable => (0, initial_expiry, false, false, true),
        };
        if replay_unavailable || token_protection_unavailable {
            self.healthy = false;
        }
        trace
            .record_runtime_phase(RuntimePhase::ReadinessSelect)
            .map_err(|_| self.latch_failure())?;
        trace
            .record_runtime_phase(RuntimePhase::EngineExecution)
            .map_err(|_| self.latch_failure())?;

        let mut recent_snapshot = [RecentSnapshotSlot::dummy(); RECENT_SNAPSHOT_SLOTS];
        let mut recent_snapshot_failed = false;
        for (ordinal, destination) in recent_snapshot.iter_mut().enumerate() {
            trace
                .record_recent_snapshot_read(ordinal)
                .map_err(|_| self.latch_failure())?;
            match epoch.recent_snapshot.read_slot(ordinal) {
                Ok(slot) => *destination = slot,
                Err(_) => recent_snapshot_failed = true,
            }
        }
        trace
            .complete_recent_snapshot_scan(RECENT_SNAPSHOT_SLOTS)
            .map_err(|_| self.latch_failure())?;
        let scanned_content_digest = content_digest(&recent_snapshot);
        if epoch.recent_snapshot.slots() != RECENT_SNAPSHOT_SLOTS
            || epoch.recent_snapshot.identity() != recent_snapshot_identity(&epoch.checkpoint)
            || scanned_content_digest != epoch.recent_snapshot_content_digest
            || lineage_binding_digest(epoch.recent_snapshot.lineage(), scanned_content_digest)
                != epoch.recent_snapshot_binding_digest
        {
            recent_snapshot_failed = true;
        }

        let execution = epoch
            .engine
            .execute_from(request.query(), cursor, &recent_snapshot, &mut trace)
            .map_err(|_| self.latch_failure())?;
        trace
            .record_runtime_phase(RuntimePhase::ResultNormalization)
            .map_err(|_| self.latch_failure())?;

        let engine_outcome = execution.page().outcome();
        if matches!(
            engine_outcome,
            QueryOutcome::StoreFailure | QueryOutcome::ProjectionNotReady
        ) || recent_snapshot_failed
        {
            self.healthy = false;
        }
        let protected_outcome = if engine_outcome == QueryOutcome::StoreFailure {
            QueryOutcome::StoreFailure
        } else if engine_outcome == QueryOutcome::ProjectionNotReady
            || recent_snapshot_failed
            || !was_healthy
            || !checkpoint_matches
            || request_duplicate
            || replay_unavailable
            || token_protection_unavailable
        {
            QueryOutcome::ProjectionNotReady
        } else if invalid_continuation {
            QueryOutcome::InvalidContinuation
        } else {
            engine_outcome
        };
        let (mut page, next_cursor) = execution.into_parts();
        if matches!(
            protected_outcome,
            QueryOutcome::StoreFailure
                | QueryOutcome::ProjectionNotReady
                | QueryOutcome::InvalidContinuation
        ) {
            page = UtxoResultPage::empty();
        }
        page.set_outcome(protected_outcome);

        let issue_cursor =
            u64::try_from(next_cursor.unwrap_or(1)).map_err(|_| self.latch_failure())?;
        let issue_state = ContinuationState::new(
            CONTINUATION_VERSION,
            *profile.profile_id(),
            query_digest,
            epoch.checkpoint.projection_epoch,
            issue_cursor,
            continuation_expiry,
            material.token_nonce(),
        );
        let issued = match ContinuationToken::issue(
            &issue_state,
            &token_context,
            self.security.token_protector(),
        ) {
            Ok(token) => token,
            Err(_) => {
                self.healthy = false;
                token_protection_unavailable = true;
                ContinuationToken::from_opaque_bytes([0; CONTINUATION_TOKEN_BYTES])
            }
        };
        trace
            .record_runtime_phase(RuntimePhase::TokenIssue)
            .map_err(|_| self.latch_failure())?;

        let has_more = protected_outcome == QueryOutcome::ResultBudgetExceeded;
        let continuation = if has_more { Some(issued) } else { None };
        let response = PrivateQueryResponse::new(epoch.checkpoint, page, has_more, continuation)
            .map_err(|error| {
                self.healthy = false;
                error.into_uniform_external_failure()
            })?;
        let envelope = self
            .codec
            .encode_response(
                &response,
                material.response_nonce(),
                self.security.envelope_protector(),
            )
            .map_err(|error| {
                self.healthy = false;
                error.into_uniform_external_failure()
            })?;
        trace
            .record_runtime_phase(RuntimePhase::ResponseEncode)
            .map_err(|_| self.latch_failure())?;
        trace
            .record_response_frame(ENVELOPE_BYTES)
            .map_err(|_| self.latch_failure())?;
        trace
            .record_runtime_phase(RuntimePhase::Completion)
            .map_err(|_| self.latch_failure())?;
        trace
            .record_completion(CompletionShape::UnaryFixedEnvelope)
            .map_err(|_| self.latch_failure())?;
        let trace = trace
            .finish(profile.access_budget())
            .map_err(|_| self.latch_failure())?;
        if token_protection_unavailable || replay_unavailable {
            return Err(self.latch_failure());
        }
        let replay_commit_authority =
            replay_commit_authority.ok_or_else(|| self.latch_failure())?;
        let (now_unix_seconds, response_nonce, token_nonce, security_round, reservation_authority) =
            material.into_parts();
        Ok(EncodedRuntimeRound {
            envelope,
            trace,
            now_unix_seconds,
            response_nonce,
            token_nonce,
            security_round,
            reservation_authority,
            replay_commit_authority,
        })
    }

    fn latch_failure(&mut self) -> UniformExternalFailure {
        self.healthy = false;
        UniformExternalFailure
    }

    fn continuation_query_digest(
        &self,
        epoch: &PrivateQueryRuntimeEpoch<
            S,
            C,
            B,
            RESPONSE_SLOTS,
            ENVELOPE_BYTES,
            RECENT_SNAPSHOT_SLOTS,
        >,
        query: &crate::records::UtxoQuery,
    ) -> [u8; 32] {
        bind_query_digest(
            self.codec.query_digest(query),
            epoch.recent_snapshot_binding_digest,
        )
    }
}

#[cfg(feature = "corpus-zaino")]
impl PrivateQueryCheckpoint {
    fn try_from_serving_identity(
        identity: RecentSnapshotIdentity,
    ) -> Result<Self, FinalizedRuntimeBuildError> {
        let network = PrivateNetwork::try_from_tag(identity.network_tag())
            .map_err(|_| FinalizedRuntimeBuildError)?;
        Ok(Self::new(
            network,
            identity.finalized_height(),
            *identity.finalized_hash_display(),
            identity.schema_version(),
            identity.projection_epoch(),
            identity.key_epoch(),
        ))
    }
}

#[cfg(feature = "corpus-zaino")]
impl<
        E,
        T,
        R,
        N,
        C,
        B,
        const RESPONSE_SLOTS: usize,
        const ENVELOPE_BYTES: usize,
        const RECENT_SNAPSHOT_SLOTS: usize,
    >
    PrivateQueryRuntime<
        FinalizedProjectionServingStore,
        E,
        T,
        R,
        N,
        C,
        B,
        RESPONSE_SLOTS,
        ENVELOPE_BYTES,
        RECENT_SNAPSHOT_SLOTS,
    >
where
    E: EnvelopeProtector,
    T: ContinuationTokenProtector,
    R: ContinuationReplayGuard,
    N: RoundMaterialSource,
    C: ServingEpochCurrentness<B>,
    B: ServingEpochBoundary,
{
    /// Consumes one coherent finalized serving epoch into one stateful runtime.
    ///
    /// The checkpoint is derived from the epoch identity. Callers cannot pair
    /// an independently supplied checkpoint or store with the retained lease.
    /// The returned runtime must be retained across rounds because its replay,
    /// material-source, and fail-closed health state are runtime-local.
    fn from_finalized_serving_epoch(
        serving_epoch: ServingEpochLease<
            RECENT_SNAPSHOT_SLOTS,
            B,
            FinalizedProjectionServingStore,
            C,
        >,
        shape: CompiledQueryShape<RESPONSE_SLOTS, ENVELOPE_BYTES>,
        security: ActiveSecurityLease<E, T, R, N>,
    ) -> Result<Self, FinalizedRuntimeBuildError> {
        let mut runtime =
            Self::without_epoch(shape, security).map_err(|_| FinalizedRuntimeBuildError)?;
        runtime.activate_finalized_serving_epoch(serving_epoch)?;
        Ok(runtime)
    }

    fn activate_finalized_serving_epoch(
        &mut self,
        serving_epoch: ServingEpochLease<
            RECENT_SNAPSHOT_SLOTS,
            B,
            FinalizedProjectionServingStore,
            C,
        >,
    ) -> Result<(), FinalizedRuntimeBuildError> {
        self.retire_epoch();
        if !self.healthy {
            return Err(FinalizedRuntimeBuildError);
        }
        let checkpoint =
            PrivateQueryCheckpoint::try_from_serving_identity(serving_epoch.identity())?;
        self.activate_epoch(serving_epoch, checkpoint)
            .map_err(|_| FinalizedRuntimeBuildError)
    }
}

/// Replaces only the epoch-scoped portion of one finalized runtime.
///
/// Retirement happens before the candidate future is polled, so cancellation
/// while an asynchronous refresh is pending cannot leave the prior epoch
/// eligible for later requests. Process-scoped protection, replay, material,
/// session, profile, and health state remain owned by `runtime`.
#[cfg(feature = "corpus-zaino")]
async fn replace_finalized_runtime_epoch_from<
    E,
    T,
    R,
    N,
    C,
    B,
    Candidate,
    const RESPONSE_SLOTS: usize,
    const ENVELOPE_BYTES: usize,
    const RECENT_SNAPSHOT_SLOTS: usize,
>(
    runtime: &mut PrivateQueryRuntime<
        FinalizedProjectionServingStore,
        E,
        T,
        R,
        N,
        C,
        B,
        RESPONSE_SLOTS,
        ENVELOPE_BYTES,
        RECENT_SNAPSHOT_SLOTS,
    >,
    stopped: bool,
    candidate: Candidate,
) -> Result<(), FinalizedRuntimeOwnerError>
where
    E: EnvelopeProtector,
    T: ContinuationTokenProtector,
    R: ContinuationReplayGuard,
    N: RoundMaterialSource,
    C: ServingEpochCurrentness<B>,
    B: ServingEpochBoundary,
    Candidate: std::future::Future<
        Output = Result<
            ServingEpochLease<RECENT_SNAPSHOT_SLOTS, B, FinalizedProjectionServingStore, C>,
            FinalizedRuntimeOwnerError,
        >,
    >,
{
    runtime.retire_epoch();
    if stopped || !runtime.healthy {
        return Err(FinalizedRuntimeOwnerError);
    }

    let serving_epoch = candidate.await?;
    runtime
        .activate_finalized_serving_epoch(serving_epoch)
        .map_err(coarsen_runtime_owner_error)
}

/// Runs one round while returning the unique response-release permit with it.
#[cfg(feature = "corpus-zaino")]
fn handle_finalized_runtime_round<
    E,
    T,
    R,
    N,
    C,
    B,
    const RESPONSE_SLOTS: usize,
    const ENVELOPE_BYTES: usize,
    const RECENT_SNAPSHOT_SLOTS: usize,
>(
    runtime: &mut PrivateQueryRuntime<
        FinalizedProjectionServingStore,
        E,
        T,
        R,
        N,
        C,
        B,
        RESPONSE_SLOTS,
        ENVELOPE_BYTES,
        RECENT_SNAPSHOT_SLOTS,
    >,
    stopped: bool,
    response_release: &ResponseReleaseGate,
    envelope: &FixedEnvelope<ENVELOPE_BYTES>,
) -> Result<PendingRuntimeRound<B, C, ENVELOPE_BYTES>, UniformExternalFailure>
where
    E: EnvelopeProtector,
    T: ContinuationTokenProtector,
    R: ContinuationReplayGuard,
    N: RoundMaterialSource,
    C: ServingEpochCurrentness<B>,
    B: ServingEpochBoundary,
{
    if stopped {
        return Err(UniformExternalFailure);
    }
    let release_permit = response_release
        .begin_response()
        .map_err(|_| UniformExternalFailure)?;
    if !runtime.healthy {
        return Err(UniformExternalFailure);
    }
    let (round, serving_release_witness, security_release_witness) =
        runtime.handle_with_release_witness(envelope)?;
    Ok(PendingRuntimeRound {
        round,
        serving_release_witness,
        security_release_witness,
        release_decision: OnceLock::new(),
        release_permit,
    })
}

/// Retires terminal runtime state without turning a busy rejection into cleanup.
#[cfg(feature = "corpus-zaino")]
fn retire_unhealthy_finalized_runtime_after_round<
    E,
    T,
    R,
    N,
    C,
    B,
    const RESPONSE_SLOTS: usize,
    const ENVELOPE_BYTES: usize,
    const RECENT_SNAPSHOT_SLOTS: usize,
>(
    runtime: &mut PrivateQueryRuntime<
        FinalizedProjectionServingStore,
        E,
        T,
        R,
        N,
        C,
        B,
        RESPONSE_SLOTS,
        ENVELOPE_BYTES,
        RECENT_SNAPSHOT_SLOTS,
    >,
    protected_response_pending: bool,
    response_release: &ResponseReleaseGate,
) -> bool
where
    E: EnvelopeProtector,
    T: ContinuationTokenProtector,
    R: ContinuationReplayGuard,
    N: RoundMaterialSource,
    C: ServingEpochCurrentness<B>,
    B: ServingEpochBoundary,
{
    if runtime.healthy || (!protected_response_pending && !response_release.is_idle()) {
        return false;
    }
    response_release.close();
    runtime.retire_security_epoch();
    runtime.retire_epoch();
    true
}

#[cfg(feature = "corpus-zaino")]
fn stop_finalized_runtime<
    E,
    T,
    R,
    N,
    C,
    B,
    const RESPONSE_SLOTS: usize,
    const ENVELOPE_BYTES: usize,
    const RECENT_SNAPSHOT_SLOTS: usize,
>(
    runtime: &mut PrivateQueryRuntime<
        FinalizedProjectionServingStore,
        E,
        T,
        R,
        N,
        C,
        B,
        RESPONSE_SLOTS,
        ENVELOPE_BYTES,
        RECENT_SNAPSHOT_SLOTS,
    >,
    stopped: &mut bool,
) where
    E: EnvelopeProtector,
    T: ContinuationTokenProtector,
    R: ContinuationReplayGuard,
    N: RoundMaterialSource,
    C: ServingEpochCurrentness<B>,
    B: ServingEpochBoundary,
{
    *stopped = true;
    runtime.retire_security_epoch();
    runtime.retire_epoch();
}

#[cfg(feature = "corpus-zaino")]
fn stop_finalized_runtime_after_responses<
    E,
    T,
    R,
    N,
    C,
    B,
    const RESPONSE_SLOTS: usize,
    const ENVELOPE_BYTES: usize,
    const RECENT_SNAPSHOT_SLOTS: usize,
>(
    runtime: &mut PrivateQueryRuntime<
        FinalizedProjectionServingStore,
        E,
        T,
        R,
        N,
        C,
        B,
        RESPONSE_SLOTS,
        ENVELOPE_BYTES,
        RECENT_SNAPSHOT_SLOTS,
    >,
    stopped: &mut bool,
    response_release: &ResponseReleaseGate,
) -> Result<(), FinalizedRuntimeOwnerError>
where
    E: EnvelopeProtector,
    T: ContinuationTokenProtector,
    R: ContinuationReplayGuard,
    N: RoundMaterialSource,
    C: ServingEpochCurrentness<B>,
    B: ServingEpochBoundary,
{
    response_release.stop()?;
    stop_finalized_runtime(runtime, stopped);
    Ok(())
}

#[cfg(feature = "corpus-zaino")]
type FinalizedProcessRuntime<
    Source,
    E,
    T,
    R,
    N,
    const RESPONSE_SLOTS: usize,
    const ENVELOPE_BYTES: usize,
    const RECENT_SNAPSHOT_SLOTS: usize,
> = PrivateQueryRuntime<
    FinalizedProjectionServingStore,
    E,
    T,
    R,
    N,
    CanonicalServingEpochCurrentness<Source>,
    CanonicalTransparentProjectionBoundary,
    RESPONSE_SLOTS,
    ENVELOPE_BYTES,
    RECENT_SNAPSHOT_SLOTS,
>;

#[cfg(feature = "corpus-zaino")]
type FinalizedPendingRuntimeRound<Source, const ENVELOPE_BYTES: usize> = PendingRuntimeRound<
    CanonicalTransparentProjectionBoundary,
    CanonicalServingEpochCurrentness<Source>,
    ENVELOPE_BYTES,
>;

/// Process-lifetime owner for one controller and at most one active epoch.
#[cfg(feature = "corpus-zaino")]
struct FinalizedRuntimeOwner<
    Source,
    E,
    T,
    R,
    N,
    const RESPONSE_SLOTS: usize,
    const ENVELOPE_BYTES: usize,
    const RECENT_SNAPSHOT_SLOTS: usize,
> where
    Source: BlockchainSource,
{
    controller: RecentSnapshotRefreshController<
        RECENT_SNAPSHOT_SLOTS,
        FinalizedProjectionServingStore,
        CanonicalServingEpochCurrentness<Source>,
    >,
    runtime: FinalizedProcessRuntime<
        Source,
        E,
        T,
        R,
        N,
        RESPONSE_SLOTS,
        ENVELOPE_BYTES,
        RECENT_SNAPSHOT_SLOTS,
    >,
    response_release: ResponseReleaseGate,
    stopped: bool,
}

#[cfg(feature = "corpus-zaino")]
impl<
        Source,
        E,
        T,
        R,
        N,
        const RESPONSE_SLOTS: usize,
        const ENVELOPE_BYTES: usize,
        const RECENT_SNAPSHOT_SLOTS: usize,
    >
    FinalizedRuntimeOwner<Source, E, T, R, N, RESPONSE_SLOTS, ENVELOPE_BYTES, RECENT_SNAPSHOT_SLOTS>
where
    Source: BlockchainSource,
    E: EnvelopeProtector,
    T: ContinuationTokenProtector,
    R: ContinuationReplayGuard,
    N: RoundMaterialSource,
{
    fn new(
        network: CanonicalNetwork,
        schema_version: u32,
        projection_epoch: u64,
        shape: CompiledQueryShape<RESPONSE_SLOTS, ENVELOPE_BYTES>,
        security: ActiveSecurityLease<E, T, R, N>,
    ) -> Result<Self, FinalizedRuntimeOwnerError> {
        let key_epoch = security.key_epoch();
        let controller = RecentSnapshotRefreshController::new(
            network,
            schema_version,
            projection_epoch,
            key_epoch,
        )
        .map_err(coarsen_runtime_owner_error)?;
        let runtime = PrivateQueryRuntime::without_epoch(shape, security)
            .map_err(coarsen_runtime_owner_error)?;
        Ok(Self {
            controller,
            runtime,
            response_release: ResponseReleaseGate::new(),
            stopped: false,
        })
    }

    /// Retires the prior epoch before capture and publishes no stale fallback.
    async fn refresh(
        &mut self,
        subscriber: &NodeBackedChainIndexSubscriber<Source>,
        finalized_store: FinalizedProjectionServingStore,
    ) -> Result<(), FinalizedRuntimeOwnerError> {
        let _refresh_permit = self.response_release.begin_refresh()?;
        let committed_finalized = finalized_store.committed_checkpoint();
        let controller = &mut self.controller;
        let candidate = async move {
            controller
                .refresh(subscriber, committed_finalized, finalized_store)
                .await
                .map_err(coarsen_runtime_owner_error)?;
            controller
                .pin_serving_epoch()
                .ok_or(FinalizedRuntimeOwnerError)
        };
        let result =
            replace_finalized_runtime_epoch_from(&mut self.runtime, self.stopped, candidate).await;
        if result.is_err() {
            self.controller.invalidate_publication();
        }
        result
    }

    fn handle(
        &mut self,
        envelope: &FixedEnvelope<ENVELOPE_BYTES>,
    ) -> Result<FinalizedPendingRuntimeRound<Source, ENVELOPE_BYTES>, UniformExternalFailure> {
        let result = handle_finalized_runtime_round(
            &mut self.runtime,
            self.stopped,
            &self.response_release,
            envelope,
        );
        if retire_unhealthy_finalized_runtime_after_round(
            &mut self.runtime,
            result.is_ok(),
            &self.response_release,
        ) {
            self.controller.invalidate_publication();
        }
        result
    }

    fn shutdown(&mut self) -> Result<(), FinalizedRuntimeOwnerError> {
        stop_finalized_runtime_after_responses(
            &mut self.runtime,
            &mut self.stopped,
            &self.response_release,
        )?;
        self.controller.invalidate_publication();
        Ok(())
    }
}

#[cfg(feature = "corpus-zaino")]
impl<
        Source,
        E,
        T,
        R,
        N,
        const RESPONSE_SLOTS: usize,
        const ENVELOPE_BYTES: usize,
        const RECENT_SNAPSHOT_SLOTS: usize,
    > FixedEnvelopeRuntime<ENVELOPE_BYTES>
    for FinalizedRuntimeOwner<
        Source,
        E,
        T,
        R,
        N,
        RESPONSE_SLOTS,
        ENVELOPE_BYTES,
        RECENT_SNAPSHOT_SLOTS,
    >
where
    Source: BlockchainSource,
    E: EnvelopeProtector,
    T: ContinuationTokenProtector,
    R: ContinuationReplayGuard,
    N: RoundMaterialSource,
{
    type PendingResponse = FinalizedPendingRuntimeRound<Source, ENVELOPE_BYTES>;

    fn query_page(
        &mut self,
        request: [u8; ENVELOPE_BYTES],
    ) -> Result<Self::PendingResponse, PrivateQueryUnavailable> {
        self.handle(&FixedEnvelope::from_array(request))
            .map_err(|_| PrivateQueryUnavailable)
    }
}

#[cfg(feature = "corpus-zaino")]
impl<
        Source,
        E,
        T,
        R,
        N,
        const RESPONSE_SLOTS: usize,
        const ENVELOPE_BYTES: usize,
        const RECENT_SNAPSHOT_SLOTS: usize,
    > Drop
    for FinalizedRuntimeOwner<
        Source,
        E,
        T,
        R,
        N,
        RESPONSE_SLOTS,
        ENVELOPE_BYTES,
        RECENT_SNAPSHOT_SLOTS,
    >
where
    Source: BlockchainSource,
{
    fn drop(&mut self) {
        self.response_release.close();
        self.runtime.security.retire();
    }
}

#[cfg(feature = "corpus-zaino")]
impl<
        Source,
        E,
        T,
        R,
        N,
        const RESPONSE_SLOTS: usize,
        const ENVELOPE_BYTES: usize,
        const RECENT_SNAPSHOT_SLOTS: usize,
    > std::fmt::Debug
    for FinalizedRuntimeOwner<
        Source,
        E,
        T,
        R,
        N,
        RESPONSE_SLOTS,
        ENVELOPE_BYTES,
        RECENT_SNAPSHOT_SLOTS,
    >
where
    Source: BlockchainSource,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("FinalizedRuntimeOwner { ..REDACTED.. }")
    }
}

#[cfg(feature = "corpus-zaino")]
fn coarsen_runtime_owner_error<T>(_: T) -> FinalizedRuntimeOwnerError {
    FinalizedRuntimeOwnerError
}

/// Coarsened process-lifecycle failure without epoch identifiers.
#[cfg(feature = "corpus-zaino")]
#[derive(Clone, Copy, PartialEq, Eq)]
struct FinalizedRuntimeOwnerError;

#[cfg(feature = "corpus-zaino")]
impl std::fmt::Debug for FinalizedRuntimeOwnerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("FinalizedRuntimeOwnerError { ..REDACTED.. }")
    }
}

#[cfg(feature = "corpus-zaino")]
impl std::fmt::Display for FinalizedRuntimeOwnerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("private-query runtime owner unavailable")
    }
}

#[cfg(feature = "corpus-zaino")]
impl std::error::Error for FinalizedRuntimeOwnerError {}

/// Coarsened finalized-runtime construction failure without epoch identifiers.
#[cfg(feature = "corpus-zaino")]
#[derive(Clone, Copy, PartialEq, Eq)]
struct FinalizedRuntimeBuildError;

#[cfg(feature = "corpus-zaino")]
impl std::fmt::Debug for FinalizedRuntimeBuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("FinalizedRuntimeBuildError { ..REDACTED.. }")
    }
}

#[cfg(feature = "corpus-zaino")]
impl std::fmt::Display for FinalizedRuntimeBuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("finalized private-query runtime unavailable")
    }
}

#[cfg(feature = "corpus-zaino")]
impl std::error::Error for FinalizedRuntimeBuildError {}

fn recent_snapshot_identity(checkpoint: &PrivateQueryCheckpoint) -> RecentSnapshotIdentity {
    RecentSnapshotIdentity::new(
        checkpoint.network.tag(),
        checkpoint.height,
        checkpoint.block_hash_display,
        checkpoint.schema_version,
        checkpoint.projection_epoch,
        checkpoint.key_epoch,
    )
}

#[cfg(test)]
mod tests {
    use std::{cell::Cell, sync::Arc};

    use super::*;
    use crate::{
        continuation_token::{ContinuationProtectionContext, ContinuationReplayPlan},
        profile::test_profile_with_recent_snapshot,
        recent_snapshot::{
            serving_epoch_for_tests, FrozenRecentSnapshot, RecentSnapshotLineage,
            RecentSnapshotSlot,
        },
        records::{AddressKey, TransparentUtxo, UtxoQuery, ADDRESS_KEY_BYTES, TXID_BYTES},
        runtime_security::{
            ReplayCommitAuthority, ReplayCommitResult, ReplayCommitUnavailable,
            ReplayDuplicateDecision, RequestReplayKey, RoundReservationAuthority, SecurityEpochTag,
            SecurityRoundCapture, REPLAY_RECORD_KEY_BYTES,
        },
        store::{PlaintextMockStore, PlaintextMockStoreError},
        trace::RuntimePhase,
    };

    #[cfg(feature = "corpus-zaino")]
    use crate::{
        projection_owner::finalized_serving_store_for_runtime_tests,
        recent_snapshot::FinalizedServingStore,
    };

    const RESPONSE_SLOTS: usize = 2;
    const ENVELOPE_BYTES: usize = 512;
    const SESSION_BINDING: [u8; 32] = [0x22; 32];
    const SERVICE_NAMESPACE_ID: [u8; 16] = [0x23; 16];
    const OWNER_GENERATION: u64 = 1;
    const SECURITY_EPOCH_BINDING: [u8; 32] = [0x24; 32];
    const TOKEN_TTL_SECONDS: u64 = 60;
    const BLOCK_HASH_DISPLAY: [u8; 32] = [0x31; 32];
    const RECENT_TIP_HASH_DISPLAY: [u8; 32] = [0x32; 32];
    const RECENT_SNAPSHOT_SLOTS: usize = 4;
    const XCHACHA_REQUEST_KEY: [u8; crate::xchacha20::KEY_BYTES] =
        [0x91; crate::xchacha20::KEY_BYTES];
    const XCHACHA_RESPONSE_KEY: [u8; crate::xchacha20::KEY_BYTES] =
        [0x92; crate::xchacha20::KEY_BYTES];
    const XCHACHA_TOKEN_KEY: [u8; crate::xchacha20::KEY_BYTES] =
        [0x93; crate::xchacha20::KEY_BYTES];

    type TestRecentSnapshot = FrozenRecentSnapshot<RECENT_SNAPSHOT_SLOTS>;

    #[derive(Clone)]
    struct TestBoundary {
        revision: Arc<()>,
    }

    impl TestBoundary {
        fn new() -> Self {
            Self {
                revision: Arc::new(()),
            }
        }

        fn replacement(&self) -> Self {
            Self::new()
        }
    }

    impl ServingEpochBoundary for TestBoundary {
        fn same_capture(&self, other: &Self) -> bool {
            Arc::ptr_eq(&self.revision, &other.revision)
        }
    }

    struct DeterministicServingEpochCurrentness {
        identity: RecentSnapshotIdentity,
        boundary: TestBoundary,
        available: bool,
        calls: usize,
        after_comparison: Option<Arc<dyn Fn() + Send + Sync>>,
    }

    impl DeterministicServingEpochCurrentness {
        fn available(identity: RecentSnapshotIdentity, boundary: TestBoundary) -> Self {
            Self {
                identity,
                boundary,
                available: true,
                calls: 0,
                after_comparison: None,
            }
        }
    }

    impl ServingEpochCurrentness<TestBoundary> for DeterministicServingEpochCurrentness {
        fn binding(&self) -> Option<(RecentSnapshotIdentity, &TestBoundary)> {
            Some((self.identity, &self.boundary))
        }

        fn observe(
            &mut self,
        ) -> Result<ServingEpochObservation<TestBoundary>, ServingEpochUnavailable> {
            self.calls = self.calls.checked_add(1).ok_or(ServingEpochUnavailable)?;
            if !self.available {
                return Err(ServingEpochUnavailable);
            }
            let observation = ServingEpochObservation::new(self.identity, self.boundary.clone());
            Ok(
                if let Some(hook) = self.after_comparison.as_ref().map(Arc::clone) {
                    observation.with_after_comparison_for_tests(move || hook())
                } else {
                    observation
                },
            )
        }
    }

    type TestRuntime = PrivateQueryRuntime<
        PlaintextMockStore,
        DeterministicEnvelopeProtector,
        CountingTokenProtector,
        CountingReplayGuard,
        DeterministicMaterialSource,
        DeterministicServingEpochCurrentness,
        TestBoundary,
        RESPONSE_SLOTS,
        ENVELOPE_BYTES,
        RECENT_SNAPSHOT_SLOTS,
    >;

    #[cfg(feature = "corpus-zaino")]
    type FinalizedTestRuntime = PrivateQueryRuntime<
        FinalizedProjectionServingStore,
        DeterministicEnvelopeProtector,
        CountingTokenProtector,
        CountingReplayGuard,
        DeterministicMaterialSource,
        DeterministicServingEpochCurrentness,
        TestBoundary,
        RESPONSE_SLOTS,
        ENVELOPE_BYTES,
        RECENT_SNAPSHOT_SLOTS,
    >;

    #[cfg(feature = "corpus-zaino")]
    type FinalizedTestEpoch = ServingEpochLease<
        RECENT_SNAPSHOT_SLOTS,
        TestBoundary,
        FinalizedProjectionServingStore,
        DeterministicServingEpochCurrentness,
    >;

    #[cfg(feature = "corpus-zaino")]
    type FinalizedTestPendingRound =
        PendingRuntimeRound<TestBoundary, DeterministicServingEpochCurrentness, ENVELOPE_BYTES>;

    #[cfg(feature = "corpus-zaino")]
    type FinalizedTestOwner = FinalizedRuntimeOwner<
        zaino_state::ValidatorConnector,
        DeterministicEnvelopeProtector,
        CountingTokenProtector,
        CountingReplayGuard,
        DeterministicMaterialSource,
        RESPONSE_SLOTS,
        ENVELOPE_BYTES,
        RECENT_SNAPSHOT_SLOTS,
    >;

    #[cfg(feature = "corpus-zaino")]
    fn assert_send_and_static<T: Send + 'static>() {}

    fn finalized_store_reads(runtime: &TestRuntime) -> usize {
        runtime
            .epoch_for_tests()
            .engine
            .store()
            .inspect_for_tests(|store| store.read_slots().len())
            .expect("serving-epoch test store mutex is not poisoned")
    }

    fn with_serving_epoch_currentness<S, T>(
        runtime: &PrivateQueryRuntime<
            S,
            DeterministicEnvelopeProtector,
            CountingTokenProtector,
            CountingReplayGuard,
            DeterministicMaterialSource,
            DeterministicServingEpochCurrentness,
            TestBoundary,
            RESPONSE_SLOTS,
            ENVELOPE_BYTES,
            RECENT_SNAPSHOT_SLOTS,
        >,
        inspect: impl FnOnce(&mut DeterministicServingEpochCurrentness) -> T,
    ) -> T
    where
        S: ObliviousStore,
    {
        runtime
            .epoch_for_tests()
            .serving_epoch
            .with_currentness_for_tests(inspect)
            .expect("serving-epoch test currentness mutex is not poisoned")
    }

    fn serving_epoch_observations<S>(
        runtime: &PrivateQueryRuntime<
            S,
            DeterministicEnvelopeProtector,
            CountingTokenProtector,
            CountingReplayGuard,
            DeterministicMaterialSource,
            DeterministicServingEpochCurrentness,
            TestBoundary,
            RESPONSE_SLOTS,
            ENVELOPE_BYTES,
            RECENT_SNAPSHOT_SLOTS,
        >,
    ) -> usize
    where
        S: ObliviousStore,
    {
        with_serving_epoch_currentness(runtime, |currentness| currentness.calls)
    }

    fn serving_epoch<const N: usize>(
        snapshot: FrozenRecentSnapshot<N>,
        store: PlaintextMockStore,
    ) -> ServingEpochLease<N, TestBoundary, PlaintextMockStore, DeterministicServingEpochCurrentness>
    {
        serving_epoch_with_store(snapshot, store)
    }

    fn serving_epoch_with_store<const N: usize, S>(
        snapshot: FrozenRecentSnapshot<N>,
        store: S,
    ) -> ServingEpochLease<N, TestBoundary, S, DeterministicServingEpochCurrentness>
    where
        S: ObliviousStore,
    {
        let boundary = TestBoundary::new();
        let currentness =
            DeterministicServingEpochCurrentness::available(snapshot.identity(), boundary.clone());
        serving_epoch_for_tests(snapshot, boundary, store, currentness)
    }

    fn folded_authentication<'a>(key: [u8; 16], bytes: impl Iterator<Item = &'a u8>) -> [u8; 16] {
        let mut authentication = key;
        for (index, byte) in bytes.enumerate() {
            let slot = index % authentication.len();
            authentication[slot] = authentication[slot]
                .rotate_left((index % u8::BITS as usize) as u32)
                ^ byte
                ^ (index as u8).wrapping_mul(29);
        }
        authentication
    }

    #[derive(Default)]
    struct DeterministicEnvelopeProtector {
        opens: Cell<usize>,
        seals: Cell<usize>,
        open_unavailable: Cell<bool>,
        seal_unavailable: Cell<bool>,
    }

    impl DeterministicEnvelopeProtector {
        fn make_open_unavailable(&self) {
            self.open_unavailable.set(true);
        }

        fn make_seal_unavailable(&self) {
            self.seal_unavailable.set(true);
        }

        fn authentication(
            &self,
            context: &super::super::EnvelopeProtectionContext,
            nonce: &[u8; ENVELOPE_NONCE_BYTES],
            body: &[u8],
        ) -> [u8; 16] {
            let version = context.format_version.to_be_bytes();
            let direction = [context.direction.tag()];
            folded_authentication(
                [0x5a; 16],
                version
                    .iter()
                    .chain(&direction)
                    .chain(&context.profile_id)
                    .chain(&context.session_binding)
                    .chain(nonce)
                    .chain(body),
            )
        }
    }

    impl EnvelopeProtector for DeterministicEnvelopeProtector {
        fn seal(
            &self,
            context: &super::super::EnvelopeProtectionContext,
            nonce: &[u8; ENVELOPE_NONCE_BYTES],
            body: &mut [u8],
        ) -> Result<[u8; 16], ProtectionUnavailable> {
            self.seals.set(self.seals.get() + 1);
            if self.seal_unavailable.get() {
                return Err(ProtectionUnavailable);
            }
            Ok(self.authentication(context, nonce, body))
        }

        fn open(
            &self,
            context: &super::super::EnvelopeProtectionContext,
            nonce: &[u8; ENVELOPE_NONCE_BYTES],
            body: &mut [u8],
            authentication: &[u8; 16],
        ) -> Result<AuthenticationDecision, ProtectionUnavailable> {
            self.opens.set(self.opens.get() + 1);
            if self.open_unavailable.get() {
                return Err(ProtectionUnavailable);
            }
            Ok(
                if constant_time_equal(&self.authentication(context, nonce, body), authentication) {
                    AuthenticationDecision::Accepted
                } else {
                    AuthenticationDecision::Rejected
                },
            )
        }
    }

    #[derive(Default)]
    struct CountingTokenProtector {
        opens: Cell<usize>,
        seals: Cell<usize>,
        open_unavailable: Cell<bool>,
        seal_unavailable: Cell<bool>,
    }

    impl CountingTokenProtector {
        fn make_open_unavailable(&self) {
            self.open_unavailable.set(true);
        }

        fn make_seal_unavailable(&self) {
            self.seal_unavailable.set(true);
        }

        fn authentication(
            &self,
            context: &ContinuationProtectionContext,
            nonce: &[u8; ENVELOPE_NONCE_BYTES],
            body: &[u8],
        ) -> [u8; 16] {
            folded_authentication(
                [0x6b; 16],
                context.as_bytes().iter().chain(nonce).chain(body),
            )
        }
    }

    impl ContinuationTokenProtector for CountingTokenProtector {
        fn seal(
            &self,
            context: &ContinuationProtectionContext,
            nonce: &[u8; ENVELOPE_NONCE_BYTES],
            body: &mut [u8; 88],
        ) -> Result<[u8; 16], ProtectionUnavailable> {
            self.seals.set(self.seals.get() + 1);
            if self.seal_unavailable.get() {
                return Err(ProtectionUnavailable);
            }
            Ok(self.authentication(context, nonce, body))
        }

        fn open(
            &self,
            context: &ContinuationProtectionContext,
            nonce: &[u8; ENVELOPE_NONCE_BYTES],
            body: &mut [u8; 88],
            authentication: &[u8; 16],
        ) -> Result<AuthenticationDecision, ProtectionUnavailable> {
            self.opens.set(self.opens.get() + 1);
            if self.open_unavailable.get() {
                return Err(ProtectionUnavailable);
            }
            Ok(
                if constant_time_equal(&self.authentication(context, nonce, body), authentication) {
                    AuthenticationDecision::Accepted
                } else {
                    AuthenticationDecision::Rejected
                },
            )
        }
    }

    fn constant_time_equal(left: &[u8; 16], right: &[u8; 16]) -> bool {
        left.iter()
            .zip(right)
            .fold(0_u8, |difference, (left, right)| {
                difference | (left ^ right)
            })
            == 0
    }

    struct CountingReplayGuard {
        claimed_requests: [Option<RequestReplayKey>; 16],
        claimed: [Option<[u8; REPLAY_RECORD_KEY_BYTES]>; 16],
        calls: usize,
        real_claim_attempts: usize,
        logical_reads: usize,
        logical_writes: usize,
        available: bool,
    }

    impl CountingReplayGuard {
        fn available() -> Self {
            Self {
                claimed_requests: [None; 16],
                claimed: [None; 16],
                calls: 0,
                real_claim_attempts: 0,
                logical_reads: 0,
                logical_writes: 0,
                available: true,
            }
        }

        fn unavailable() -> Self {
            Self {
                available: false,
                ..Self::available()
            }
        }
    }

    impl ContinuationReplayGuard for CountingReplayGuard {
        fn commit_request_and_continuation(
            &mut self,
            security_round: &SecurityRoundCapture,
            request_key: &RequestReplayKey,
            continuation_plan: &ContinuationReplayPlan,
        ) -> Result<ReplayCommitResult, ReplayCommitUnavailable> {
            self.calls += 1;
            self.logical_reads += 1;
            self.logical_writes += 1;
            if !self.available {
                return Err(ReplayCommitUnavailable);
            }

            let request_duplicate = self
                .claimed_requests
                .iter()
                .any(|candidate| candidate.as_ref() == Some(request_key));
            let (continuation_key, continuation_duplicate) = if request_duplicate {
                (None, false)
            } else {
                match continuation_plan {
                    ContinuationReplayPlan::Cover => (None, false),
                    ContinuationReplayPlan::ClaimOrCover(claim) => {
                        self.real_claim_attempts += 1;
                        let key = *claim.replay_key_bytes();
                        let duplicate = self
                            .claimed
                            .iter()
                            .any(|candidate| candidate.as_ref() == Some(&key));
                        (Some(key), duplicate)
                    }
                }
            };
            let decision = if request_duplicate {
                ReplayDuplicateDecision::RequestDuplicate
            } else if continuation_duplicate {
                ReplayDuplicateDecision::ContinuationDuplicate
            } else {
                ReplayDuplicateDecision::Fresh
            };

            if !request_duplicate {
                let request_slot = self
                    .claimed_requests
                    .iter()
                    .position(Option::is_none)
                    .ok_or(ReplayCommitUnavailable)?;
                let continuation_slot = if continuation_key.is_some() && !continuation_duplicate {
                    Some(
                        self.claimed
                            .iter()
                            .position(Option::is_none)
                            .ok_or(ReplayCommitUnavailable)?,
                    )
                } else {
                    None
                };
                self.claimed_requests[request_slot] = Some(*request_key);
                if let (Some(slot), Some(key)) = (continuation_slot, continuation_key) {
                    self.claimed[slot] = Some(key);
                }
            }

            Ok(ReplayCommitResult::new(
                ReplayCommitAuthority::new(security_round),
                decision,
            ))
        }
    }

    struct DeterministicMaterialSource {
        now_unix_seconds: u64,
        calls: usize,
        fail_next: bool,
    }

    impl DeterministicMaterialSource {
        const fn at(now_unix_seconds: u64) -> Self {
            Self {
                now_unix_seconds,
                calls: 0,
                fail_next: false,
            }
        }

        const fn failing(now_unix_seconds: u64) -> Self {
            Self {
                now_unix_seconds,
                calls: 0,
                fail_next: true,
            }
        }
    }

    impl RoundMaterialSource for DeterministicMaterialSource {
        fn next_round_material(
            &mut self,
            security_epoch: &SecurityEpochTag,
        ) -> Result<RoundMaterial, RoundMaterialUnavailable> {
            self.calls += 1;
            if self.fail_next {
                self.fail_next = false;
                return Err(RoundMaterialUnavailable);
            }
            let ordinal = u8::try_from(self.calls).map_err(|_| RoundMaterialUnavailable)?;
            let response_nonce = [ordinal.wrapping_add(0x80); ENVELOPE_NONCE_BYTES];
            let token_nonce = [ordinal.wrapping_add(0x40); ENVELOPE_NONCE_BYTES];
            let security_round = SecurityRoundCapture::new(security_epoch);
            let reservation_authority = RoundReservationAuthority::new(
                &security_round,
                self.now_unix_seconds,
                response_nonce,
                token_nonce,
            );
            let material = RoundMaterial::new(
                self.now_unix_seconds,
                response_nonce,
                token_nonce,
                security_round,
                reservation_authority,
            );
            self.now_unix_seconds = self
                .now_unix_seconds
                .checked_add(1)
                .ok_or(RoundMaterialUnavailable)?;
            Ok(material)
        }
    }

    fn checkpoint() -> PrivateQueryCheckpoint {
        PrivateQueryCheckpoint::new(
            super::super::PrivateNetwork::Mainnet,
            2_000_000,
            BLOCK_HASH_DISPLAY,
            1,
            9,
            3,
        )
    }

    fn address(byte: u8) -> AddressKey {
        AddressKey::new([byte; ADDRESS_KEY_BYTES])
    }

    fn utxo(byte: u8, height: u32) -> TransparentUtxo {
        TransparentUtxo::new(
            [byte; TXID_BYTES],
            u32::from(byte),
            100,
            height,
            &[0x51; 25],
        )
        .expect("test transparent script fits the fixed record")
    }

    fn store(
        store_reads: usize,
        entries: &[(usize, TransparentUtxo)],
    ) -> Result<PlaintextMockStore, PlaintextMockStoreError> {
        let key = address(1);
        let mut store = PlaintextMockStore::new(store_reads, entries.len());
        for (slot, record) in entries {
            store.insert(&key, *slot, record)?;
        }
        Ok(store)
    }

    fn runtime(
        store_reads: usize,
        entries: &[(usize, TransparentUtxo)],
    ) -> Result<TestRuntime, Box<dyn std::error::Error>> {
        runtime_with_components(
            store(store_reads, entries)?,
            store_reads,
            CountingReplayGuard::available(),
            DeterministicMaterialSource::at(100),
        )
    }

    fn runtime_with_components(
        store: PlaintextMockStore,
        store_reads: usize,
        replay_guard: CountingReplayGuard,
        material_source: DeterministicMaterialSource,
    ) -> Result<TestRuntime, Box<dyn std::error::Error>> {
        runtime_with_snapshot_components(
            store,
            store_reads,
            empty_recent_snapshot(),
            replay_guard,
            material_source,
        )
    }

    fn runtime_with_session_components(
        store: PlaintextMockStore,
        store_reads: usize,
        session_binding: [u8; 32],
        replay_guard: CountingReplayGuard,
        material_source: DeterministicMaterialSource,
    ) -> Result<TestRuntime, Box<dyn std::error::Error>> {
        runtime_with_snapshot_and_session_components(
            store,
            store_reads,
            empty_recent_snapshot(),
            session_binding,
            replay_guard,
            material_source,
        )
    }

    fn runtime_with_snapshot_components(
        store: PlaintextMockStore,
        store_reads: usize,
        recent_snapshot: TestRecentSnapshot,
        replay_guard: CountingReplayGuard,
        material_source: DeterministicMaterialSource,
    ) -> Result<TestRuntime, Box<dyn std::error::Error>> {
        let shape = runtime_shape(store_reads)?;
        let security_lease = fixture_security_lease(shape, replay_guard, material_source)?;
        runtime_with_snapshot_and_security_lease(store, recent_snapshot, shape, security_lease)
    }

    fn runtime_with_snapshot_and_session_components(
        store: PlaintextMockStore,
        store_reads: usize,
        recent_snapshot: TestRecentSnapshot,
        session_binding: [u8; 32],
        replay_guard: CountingReplayGuard,
        material_source: DeterministicMaterialSource,
    ) -> Result<TestRuntime, Box<dyn std::error::Error>> {
        let shape = runtime_shape(store_reads)?;
        let security_lease = fixture_security_lease_with_session(
            shape,
            session_binding,
            replay_guard,
            material_source,
        )?;
        runtime_with_snapshot_and_security_lease(store, recent_snapshot, shape, security_lease)
    }

    fn runtime_with_snapshot_and_security_lease(
        store: PlaintextMockStore,
        recent_snapshot: TestRecentSnapshot,
        shape: CompiledQueryShape<RESPONSE_SLOTS, ENVELOPE_BYTES>,
        security_lease: ActiveSecurityLease<
            DeterministicEnvelopeProtector,
            CountingTokenProtector,
            CountingReplayGuard,
            DeterministicMaterialSource,
        >,
    ) -> Result<TestRuntime, Box<dyn std::error::Error>> {
        let serving_epoch = serving_epoch(recent_snapshot, store);
        Ok(TestRuntime::new(
            serving_epoch,
            shape,
            checkpoint(),
            security_lease,
        )?)
    }

    fn runtime_shape(
        store_reads: usize,
    ) -> Result<CompiledQueryShape<RESPONSE_SLOTS, ENVELOPE_BYTES>, Box<dyn std::error::Error>>
    {
        runtime_shape_with_recent_snapshot_slots(store_reads, RECENT_SNAPSHOT_SLOTS)
    }

    fn runtime_shape_with_recent_snapshot_slots(
        store_reads: usize,
        recent_snapshot_slots: usize,
    ) -> Result<CompiledQueryShape<RESPONSE_SLOTS, ENVELOPE_BYTES>, Box<dyn std::error::Error>>
    {
        let profile = test_profile_with_recent_snapshot(
            "runtime-test-v1",
            store_reads,
            recent_snapshot_slots,
            RESPONSE_SLOTS,
            ENVELOPE_BYTES,
            3,
            TOKEN_TTL_SECONDS,
        )?;
        Ok(CompiledQueryShape::new(profile)?)
    }

    fn fixture_security_lease(
        shape: CompiledQueryShape<RESPONSE_SLOTS, ENVELOPE_BYTES>,
        replay_guard: CountingReplayGuard,
        material_source: DeterministicMaterialSource,
    ) -> Result<
        ActiveSecurityLease<
            DeterministicEnvelopeProtector,
            CountingTokenProtector,
            CountingReplayGuard,
            DeterministicMaterialSource,
        >,
        UniformExternalFailure,
    > {
        fixture_security_lease_with_identity(
            shape,
            checkpoint().key_epoch,
            SESSION_BINDING,
            replay_guard,
            material_source,
        )
    }

    fn fixture_security_lease_with_session(
        shape: CompiledQueryShape<RESPONSE_SLOTS, ENVELOPE_BYTES>,
        session_binding: [u8; 32],
        replay_guard: CountingReplayGuard,
        material_source: DeterministicMaterialSource,
    ) -> Result<
        ActiveSecurityLease<
            DeterministicEnvelopeProtector,
            CountingTokenProtector,
            CountingReplayGuard,
            DeterministicMaterialSource,
        >,
        UniformExternalFailure,
    > {
        fixture_security_lease_with_identity(
            shape,
            checkpoint().key_epoch,
            session_binding,
            replay_guard,
            material_source,
        )
    }

    fn fixture_security_lease_with_identity(
        shape: CompiledQueryShape<RESPONSE_SLOTS, ENVELOPE_BYTES>,
        key_epoch: u64,
        session_binding: [u8; 32],
        replay_guard: CountingReplayGuard,
        material_source: DeterministicMaterialSource,
    ) -> Result<
        ActiveSecurityLease<
            DeterministicEnvelopeProtector,
            CountingTokenProtector,
            CountingReplayGuard,
            DeterministicMaterialSource,
        >,
        UniformExternalFailure,
    > {
        Ok(ActiveSecurityLease::mint(
            shape,
            fixture_security_lease_identity(key_epoch, session_binding)?,
            DeterministicEnvelopeProtector::default(),
            CountingTokenProtector::default(),
            replay_guard,
            material_source,
        ))
    }

    fn fixture_security_lease_identity(
        key_epoch: u64,
        session_binding: [u8; 32],
    ) -> Result<SecurityLeaseIdentity, UniformExternalFailure> {
        SecurityLeaseIdentity::new(
            key_epoch,
            session_binding,
            SERVICE_NAMESPACE_ID,
            OWNER_GENERATION,
            SECURITY_EPOCH_BINDING,
        )
    }

    fn empty_recent_snapshot() -> TestRecentSnapshot {
        recent_snapshot([RecentSnapshotSlot::dummy(); RECENT_SNAPSHOT_SLOTS])
    }

    fn recent_snapshot(slots: [RecentSnapshotSlot; RECENT_SNAPSHOT_SLOTS]) -> TestRecentSnapshot {
        recent_snapshot_with_lineage(
            slots,
            recent_snapshot_lineage(recent_snapshot_identity(&checkpoint())),
        )
    }

    fn recent_snapshot_with_lineage(
        slots: [RecentSnapshotSlot; RECENT_SNAPSHOT_SLOTS],
        lineage: RecentSnapshotLineage,
    ) -> TestRecentSnapshot {
        FrozenRecentSnapshot::from_parts_for_tests(lineage, slots)
    }

    fn recent_snapshot_lineage(identity: RecentSnapshotIdentity) -> RecentSnapshotLineage {
        recent_snapshot_lineage_at_generation(identity, 1)
    }

    fn recent_snapshot_lineage_at_generation(
        identity: RecentSnapshotIdentity,
        generation: u64,
    ) -> RecentSnapshotLineage {
        RecentSnapshotLineage::from_parts_for_tests(
            generation,
            identity,
            identity
                .finalized_height()
                .checked_add(1)
                .expect("runtime fixture finalized height leaves room for a recent tip"),
            RECENT_TIP_HASH_DISPLAY,
        )
        .expect("runtime fixture lineage is internally consistent")
    }

    #[cfg(feature = "corpus-zaino")]
    fn finalized_test_epoch(
        map_identity: impl FnOnce(RecentSnapshotIdentity) -> RecentSnapshotIdentity,
    ) -> Result<(FinalizedTestEpoch, RecentSnapshotIdentity, usize), Box<dyn std::error::Error>>
    {
        finalized_test_epoch_at_generation(1, map_identity)
    }

    #[cfg(feature = "corpus-zaino")]
    fn finalized_test_epoch_at_generation(
        generation: u64,
        map_identity: impl FnOnce(RecentSnapshotIdentity) -> RecentSnapshotIdentity,
    ) -> Result<(FinalizedTestEpoch, RecentSnapshotIdentity, usize), Box<dyn std::error::Error>>
    {
        let store = finalized_serving_store_for_runtime_tests()?;
        let owner_identity = store.serving_identity();
        let store_reads = store.slots_per_key();
        let snapshot_identity = map_identity(owner_identity);
        let snapshot = recent_snapshot_with_lineage(
            [RecentSnapshotSlot::dummy(); RECENT_SNAPSHOT_SLOTS],
            recent_snapshot_lineage_at_generation(snapshot_identity, generation),
        );
        Ok((
            serving_epoch_with_store(snapshot, store),
            owner_identity,
            store_reads,
        ))
    }

    #[cfg(feature = "corpus-zaino")]
    fn finalized_runtime_from_epoch(
        serving_epoch: FinalizedTestEpoch,
        shape: CompiledQueryShape<RESPONSE_SLOTS, ENVELOPE_BYTES>,
        replay_guard: CountingReplayGuard,
        material_source: DeterministicMaterialSource,
    ) -> Result<FinalizedTestRuntime, FinalizedRuntimeBuildError> {
        let key_epoch = serving_epoch.identity().key_epoch();
        let security_lease = fixture_security_lease_with_identity(
            shape,
            key_epoch,
            SESSION_BINDING,
            replay_guard,
            material_source,
        )
        .map_err(|_| FinalizedRuntimeBuildError)?;
        FinalizedTestRuntime::from_finalized_serving_epoch(serving_epoch, shape, security_lease)
    }

    fn runtime_with_recent(
        store_reads: usize,
        entries: &[(usize, TransparentUtxo)],
        recent_slots: [RecentSnapshotSlot; RECENT_SNAPSHOT_SLOTS],
    ) -> Result<TestRuntime, Box<dyn std::error::Error>> {
        runtime_with_snapshot_components(
            store(store_reads, entries)?,
            store_reads,
            recent_snapshot(recent_slots),
            CountingReplayGuard::available(),
            DeterministicMaterialSource::at(100),
        )
    }

    fn request_envelope<S, E, T, R, N, C, B>(
        runtime: &PrivateQueryRuntime<
            S,
            E,
            T,
            R,
            N,
            C,
            B,
            RESPONSE_SLOTS,
            ENVELOPE_BYTES,
            RECENT_SNAPSHOT_SLOTS,
        >,
        checkpoint: PrivateQueryCheckpoint,
        query: UtxoQuery,
        continuation: Option<ContinuationToken>,
        nonce_byte: u8,
    ) -> Result<FixedEnvelope<ENVELOPE_BYTES>, InnerCodecError>
    where
        S: ObliviousStore,
        E: EnvelopeProtector,
        C: ServingEpochCurrentness<B>,
        B: ServingEpochBoundary,
    {
        runtime.codec.encode_request(
            &super::super::PrivateQueryRequest::new(checkpoint, query, continuation),
            [nonce_byte; ENVELOPE_NONCE_BYTES],
            runtime.security.envelope_protector(),
        )
    }

    #[cfg(feature = "corpus-zaino")]
    fn finalized_handle_and_decode(
        runtime: &mut FinalizedTestRuntime,
        request: &FixedEnvelope<ENVELOPE_BYTES>,
    ) -> Result<PrivateQueryResponse<RESPONSE_SLOTS>, Box<dyn std::error::Error>> {
        let round = runtime.handle(request)?;
        Ok(runtime
            .codec
            .decode_response(round.envelope(), runtime.security.envelope_protector())?)
    }

    #[cfg(feature = "corpus-zaino")]
    fn release_finalized_pending_and_decode(
        runtime: &FinalizedTestRuntime,
        pending: &FinalizedTestPendingRound,
    ) -> Result<PrivateQueryResponse<RESPONSE_SLOTS>, Box<dyn std::error::Error>> {
        let envelope =
            FixedEnvelope::from_array(*<FinalizedTestPendingRound as PendingFixedEnvelope<
                ENVELOPE_BYTES,
            >>::try_release_bytes(pending)?);
        Ok(runtime
            .codec
            .decode_response(&envelope, runtime.security.envelope_protector())?)
    }

    #[cfg(feature = "corpus-zaino")]
    fn finalized_pending_fixture() -> Result<
        (
            FinalizedTestRuntime,
            FixedEnvelope<ENVELOPE_BYTES>,
            ResponseReleaseGate,
        ),
        Box<dyn std::error::Error>,
    > {
        let (serving_epoch, _, store_reads) =
            finalized_test_epoch_at_generation(1, |identity| identity)?;
        let runtime = finalized_runtime_from_epoch(
            serving_epoch,
            runtime_shape(store_reads)?,
            CountingReplayGuard::available(),
            DeterministicMaterialSource::at(100),
        )?;
        let request = request_envelope(
            &runtime,
            runtime.epoch_for_tests().checkpoint,
            UtxoQuery::new(address(0xee), 0),
            None,
            1,
        )?;
        Ok((runtime, request, ResponseReleaseGate::new()))
    }

    #[cfg(feature = "corpus-zaino")]
    fn finalized_pending_round_fixture() -> Result<
        (
            FinalizedTestRuntime,
            ResponseReleaseGate,
            FinalizedTestPendingRound,
        ),
        Box<dyn std::error::Error>,
    > {
        let (mut runtime, request, response_release) = finalized_pending_fixture()?;
        let pending =
            handle_finalized_runtime_round(&mut runtime, false, &response_release, &request)?;
        Ok((runtime, response_release, pending))
    }

    #[cfg(feature = "corpus-zaino")]
    fn fixture_security_state(runtime: &FinalizedTestRuntime) -> (bool, bool, usize) {
        runtime.security.security_state_for_tests()
    }

    #[cfg(feature = "corpus-zaino")]
    fn assert_terminal_security_release_failure(
        runtime: &FinalizedTestRuntime,
        response_release: &ResponseReleaseGate,
        pending: &FinalizedTestPendingRound,
        expected_security_observations: usize,
    ) {
        let serving_observations = serving_epoch_observations(runtime);
        let (active, _, security_observations) = fixture_security_state(runtime);
        assert!(active);

        assert!(matches!(
            pending.try_release_bytes(),
            Err(UniformExternalFailure)
        ));
        assert_eq!(
            serving_epoch_observations(runtime),
            serving_observations + 1
        );
        assert_eq!(
            fixture_security_state(runtime),
            (
                false,
                false,
                security_observations + expected_security_observations,
            )
        );
        assert!(response_release.is_closed_for_tests());

        assert!(matches!(
            pending.try_release_bytes(),
            Err(UniformExternalFailure)
        ));
        assert_eq!(
            serving_epoch_observations(runtime),
            serving_observations + 1
        );
        assert_eq!(
            fixture_security_state(runtime),
            (
                false,
                false,
                security_observations + expected_security_observations,
            )
        );
    }

    #[cfg(feature = "corpus-zaino")]
    fn assert_pending_release_rejects_currentness_change(
        change: impl FnOnce(&mut DeterministicServingEpochCurrentness),
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (mut runtime, request, response_release) = finalized_pending_fixture()?;
        let observations = serving_epoch_observations(&runtime);
        let pending =
            handle_finalized_runtime_round(&mut runtime, false, &response_release, &request)?;
        assert_eq!(serving_epoch_observations(&runtime), observations);

        with_serving_epoch_currentness(&runtime, change);
        assert!(matches!(
            pending.try_release_bytes(),
            Err(UniformExternalFailure)
        ));
        assert_eq!(serving_epoch_observations(&runtime), observations + 1);
        assert!(response_release.is_closed_for_tests());
        drop(pending);
        assert!(response_release.is_closed_for_tests());
        Ok(())
    }

    #[cfg(feature = "corpus-zaino")]
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct FinalizedProcessCounters {
        envelope_opens: usize,
        envelope_seals: usize,
        token_opens: usize,
        token_seals: usize,
        replay_calls: usize,
        replay_claims: usize,
        replay_reads: usize,
        replay_writes: usize,
        material_calls: usize,
    }

    #[cfg(feature = "corpus-zaino")]
    impl FinalizedProcessCounters {
        fn capture<C, B>(
            runtime: &PrivateQueryRuntime<
                FinalizedProjectionServingStore,
                DeterministicEnvelopeProtector,
                CountingTokenProtector,
                CountingReplayGuard,
                DeterministicMaterialSource,
                C,
                B,
                RESPONSE_SLOTS,
                ENVELOPE_BYTES,
                RECENT_SNAPSHOT_SLOTS,
            >,
        ) -> Self
        where
            C: ServingEpochCurrentness<B>,
            B: ServingEpochBoundary,
        {
            let replay_guard = runtime.security.replay_guard_for_tests();
            Self {
                envelope_opens: runtime.security.envelope_protector().opens.get(),
                envelope_seals: runtime.security.envelope_protector().seals.get(),
                token_opens: runtime.security.token_protector().opens.get(),
                token_seals: runtime.security.token_protector().seals.get(),
                replay_calls: replay_guard.calls,
                replay_claims: replay_guard.real_claim_attempts,
                replay_reads: replay_guard.logical_reads,
                replay_writes: replay_guard.logical_writes,
                material_calls: runtime.security.material_source_for_tests().calls,
            }
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct RuntimeCounters {
        envelope_opens: usize,
        envelope_seals: usize,
        token_opens: usize,
        token_seals: usize,
        replay_calls: usize,
        replay_reads: usize,
        replay_writes: usize,
        material_calls: usize,
        serving_epoch_observations: usize,
        recent_snapshot_reads: usize,
        store_reads: usize,
    }

    impl RuntimeCounters {
        fn capture(runtime: &TestRuntime) -> Self {
            let replay_guard = runtime.security.replay_guard_for_tests();
            Self {
                envelope_opens: runtime.security.envelope_protector().opens.get(),
                envelope_seals: runtime.security.envelope_protector().seals.get(),
                token_opens: runtime.security.token_protector().opens.get(),
                token_seals: runtime.security.token_protector().seals.get(),
                replay_calls: replay_guard.calls,
                replay_reads: replay_guard.logical_reads,
                replay_writes: replay_guard.logical_writes,
                material_calls: runtime.security.material_source_for_tests().calls,
                serving_epoch_observations: serving_epoch_observations(runtime),
                recent_snapshot_reads: runtime.epoch_for_tests().recent_snapshot.read_calls(),
                store_reads: finalized_store_reads(runtime),
            }
        }

        fn assert_complete_round(&self, runtime: &TestRuntime) {
            self.assert_fixed_work_counts(runtime, 1, 1);
        }

        fn assert_fixed_work_before_release_failure(&self, runtime: &TestRuntime) {
            self.assert_fixed_work_counts(runtime, 1, 0);
        }

        fn assert_fixed_work_counts(
            &self,
            runtime: &TestRuntime,
            response_seal_attempts: usize,
            expected_currentness_observations: usize,
        ) {
            assert_eq!(
                runtime.security.envelope_protector().opens.get() - self.envelope_opens,
                1
            );
            assert_eq!(
                runtime.security.envelope_protector().seals.get() - self.envelope_seals,
                response_seal_attempts
            );
            assert_eq!(
                runtime.security.token_protector().opens.get() - self.token_opens,
                1
            );
            assert_eq!(
                runtime.security.token_protector().seals.get() - self.token_seals,
                1
            );
            let replay_guard = runtime.security.replay_guard_for_tests();
            assert_eq!(replay_guard.calls - self.replay_calls, 1);
            assert_eq!(replay_guard.logical_reads - self.replay_reads, 1);
            assert_eq!(replay_guard.logical_writes - self.replay_writes, 1);
            assert_eq!(
                runtime.security.material_source_for_tests().calls - self.material_calls,
                1
            );
            assert_eq!(
                serving_epoch_observations(runtime) - self.serving_epoch_observations,
                expected_currentness_observations
            );
            assert_eq!(
                runtime.epoch_for_tests().recent_snapshot.read_calls() - self.recent_snapshot_reads,
                RECENT_SNAPSHOT_SLOTS
            );
            assert_eq!(
                finalized_store_reads(runtime) - self.store_reads,
                runtime.epoch_for_tests().engine.profile().store_reads()
            );
        }
    }

    fn handle_and_decode(
        runtime: &mut TestRuntime,
        request: &FixedEnvelope<ENVELOPE_BYTES>,
    ) -> Result<(AccessTrace, PrivateQueryResponse<RESPONSE_SLOTS>), Box<dyn std::error::Error>>
    {
        let counters = RuntimeCounters::capture(runtime);
        let round = runtime.handle(request)?;
        counters.assert_complete_round(runtime);
        let decoded = decode_runtime_round(
            &runtime.codec,
            runtime.security.envelope_protector(),
            &round,
        )?;
        assert_complete_runtime_trace(
            &decoded.0,
            runtime.epoch_for_tests().engine.profile().store_reads(),
        );
        Ok(decoded)
    }

    fn handle_and_decode_protected<S, E, T, R, N, C, B>(
        runtime: &mut PrivateQueryRuntime<
            S,
            E,
            T,
            R,
            N,
            C,
            B,
            RESPONSE_SLOTS,
            ENVELOPE_BYTES,
            RECENT_SNAPSHOT_SLOTS,
        >,
        request: &FixedEnvelope<ENVELOPE_BYTES>,
    ) -> Result<(AccessTrace, PrivateQueryResponse<RESPONSE_SLOTS>), Box<dyn std::error::Error>>
    where
        S: ObliviousStore,
        E: EnvelopeProtector,
        T: ContinuationTokenProtector,
        R: ContinuationReplayGuard,
        N: RoundMaterialSource,
        C: ServingEpochCurrentness<B>,
        B: ServingEpochBoundary,
    {
        let round = runtime.handle(request)?;
        let decoded = decode_runtime_round(
            &runtime.codec,
            runtime.security.envelope_protector(),
            &round,
        )?;
        assert_complete_runtime_trace(
            &decoded.0,
            runtime.epoch_for_tests().engine.profile().store_reads(),
        );
        Ok(decoded)
    }

    fn decode_runtime_round<E>(
        codec: &PrivateQueryCodec<RESPONSE_SLOTS, ENVELOPE_BYTES>,
        envelope_protector: &E,
        round: &RuntimeRound<ENVELOPE_BYTES>,
    ) -> Result<(AccessTrace, PrivateQueryResponse<RESPONSE_SLOTS>), Box<dyn std::error::Error>>
    where
        E: EnvelopeProtector,
    {
        let trace = *round.trace();
        let response = codec.decode_response(round.envelope(), envelope_protector)?;
        Ok((trace, response))
    }

    fn assert_complete_runtime_trace(trace: &AccessTrace, expected_store_reads: usize) {
        assert_eq!(trace.runtime_phases(), RuntimePhase::COUNT);
        assert_eq!(trace.store_reads(), expected_store_reads);
        assert_eq!(trace.recent_snapshot_reads(), RECENT_SNAPSHOT_SLOTS);
        assert_eq!(trace.replay_reads(), 1);
        assert_eq!(trace.replay_writes(), 1);
        assert_eq!(trace.request_frames(), 1);
        assert_eq!(trace.response_frames(), 1);
        assert_eq!(trace.request_bytes(), ENVELOPE_BYTES);
        assert_eq!(trace.response_bytes(), ENVELOPE_BYTES);
        assert_eq!(trace.completion(), CompletionShape::UnaryFixedEnvelope);
    }

    fn assert_late_serving_epoch_failure_completes_fixed_work(
        runtime: &mut TestRuntime,
        request: &FixedEnvelope<ENVELOPE_BYTES>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let counters = RuntimeCounters::capture(runtime);

        assert!(matches!(
            runtime.handle(request),
            Err(UniformExternalFailure)
        ));
        counters.assert_complete_round(runtime);
        assert!(!runtime.healthy);
        Ok(())
    }

    fn uniform_failure<T>(result: Result<T, UniformExternalFailure>) -> UniformExternalFailure {
        match result {
            Ok(_) => panic!("protection failure cannot produce a runtime round"),
            Err(failure) => failure,
        }
    }

    fn assert_protection_failure_completes_fixed_work(
        entries: &[(usize, TransparentUtxo)],
        make_unavailable: impl FnOnce(&TestRuntime),
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut runtime = runtime(4, entries)?;
        let request = request_envelope(
            &runtime,
            checkpoint(),
            UtxoQuery::new(address(1), 0),
            None,
            1,
        )?;
        let counters = RuntimeCounters::capture(&runtime);
        make_unavailable(&runtime);

        let failure = uniform_failure(runtime.handle(&request));

        assert_eq!(failure.to_string(), "private query failed");
        counters.assert_fixed_work_before_release_failure(&runtime);
        assert_eq!(
            runtime
                .security
                .replay_guard_for_tests()
                .real_claim_attempts,
            0
        );
        assert!(!runtime.healthy);
        Ok(())
    }

    fn run_initial(
        entries: &[(usize, TransparentUtxo)],
        query: UtxoQuery,
    ) -> Result<(AccessTrace, PrivateQueryResponse<RESPONSE_SLOTS>), Box<dyn std::error::Error>>
    {
        let mut runtime = runtime(4, entries)?;
        let request = request_envelope(&runtime, checkpoint(), query, None, 1)?;
        handle_and_decode(&mut runtime, &request)
    }

    #[test]
    fn xchacha20_runtime_round_trips_continuations_and_rejects_tampering(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let entries = [(0, utxo(1, 10)), (1, utxo(2, 11)), (2, utxo(3, 12))];
        let serving_epoch = serving_epoch(empty_recent_snapshot(), store(4, &entries)?);
        let shape = runtime_shape(4)?;
        let security_lease = xchacha20_security_lease(
            shape,
            fixture_security_lease_identity(checkpoint().key_epoch, SESSION_BINDING)?,
            zeroize::Zeroizing::new(XCHACHA_REQUEST_KEY),
            zeroize::Zeroizing::new(XCHACHA_RESPONSE_KEY),
            zeroize::Zeroizing::new(XCHACHA_TOKEN_KEY),
            CountingReplayGuard::available(),
            DeterministicMaterialSource::at(100),
        );
        let mut runtime =
            PrivateQueryRuntime::new(serving_epoch, shape, checkpoint(), security_lease)?;
        let query = UtxoQuery::new(address(1), 0);

        let wrong_request_protector = super::super::xchacha20_envelope_protector(
            zeroize::Zeroizing::new([0xa1; crate::xchacha20::KEY_BYTES]),
            zeroize::Zeroizing::new(XCHACHA_RESPONSE_KEY),
        );
        let wrong_key_request = runtime.codec.encode_request(
            &super::super::PrivateQueryRequest::new(checkpoint(), query, None),
            [0x11; ENVELOPE_NONCE_BYTES],
            &wrong_request_protector,
        )?;
        let wrong_key_failure = uniform_failure(runtime.handle(&wrong_key_request));
        assert_eq!(wrong_key_failure.to_string(), "private query failed");
        assert_eq!(runtime.security.material_source_for_tests().calls, 0);
        assert_eq!(runtime.security.replay_guard_for_tests().calls, 0);
        assert!(runtime.healthy);

        let initial_request = request_envelope(&runtime, checkpoint(), query, None, 0x12)?;
        let (initial_trace, initial_response) =
            handle_and_decode_protected(&mut runtime, &initial_request)?;
        assert_eq!(
            initial_response.page.outcome(),
            QueryOutcome::ResultBudgetExceeded
        );
        let continuation = initial_response
            .continuation
            .clone()
            .expect("capped XChaCha page carries one protected token");

        let mut tampered_token_bytes = *continuation.opaque_bytes();
        tampered_token_bytes[0] ^= 1;
        let tampered_token = ContinuationToken::from_opaque_bytes(tampered_token_bytes);
        let tampered_request =
            request_envelope(&runtime, checkpoint(), query, Some(tampered_token), 0x13)?;
        let (tampered_trace, tampered_response) =
            handle_and_decode_protected(&mut runtime, &tampered_request)?;
        assert_eq!(tampered_trace, initial_trace);
        assert_eq!(
            tampered_response.page.outcome(),
            QueryOutcome::InvalidContinuation
        );
        assert!(tampered_response.page.is_all_dummy());
        assert_eq!(
            runtime
                .security
                .replay_guard_for_tests()
                .real_claim_attempts,
            0
        );

        let continued_request = request_envelope(
            &runtime,
            checkpoint(),
            query,
            Some(continuation.clone()),
            0x14,
        )?;
        let (continued_trace, continued_response) =
            handle_and_decode_protected(&mut runtime, &continued_request)?;
        assert_eq!(continued_trace, initial_trace);
        assert_eq!(continued_response.page.outcome(), QueryOutcome::Complete);
        assert_eq!(continued_response.page.real_count(), 1);
        assert_eq!(
            continued_response.page.slots()[0].padded_utxo().txid(),
            &[3; TXID_BYTES]
        );

        let replay_request =
            request_envelope(&runtime, checkpoint(), query, Some(continuation), 0x15)?;
        let (replay_trace, replay_response) =
            handle_and_decode_protected(&mut runtime, &replay_request)?;
        assert_eq!(replay_trace, initial_trace);
        assert_eq!(
            replay_response.page.outcome(),
            QueryOutcome::InvalidContinuation
        );
        assert!(replay_response.page.is_all_dummy());
        assert_eq!(runtime.security.material_source_for_tests().calls, 4);
        let replay_guard = runtime.security.replay_guard_for_tests();
        assert_eq!(replay_guard.calls, 4);
        assert_eq!(replay_guard.real_claim_attempts, 2);
        assert_eq!(replay_guard.claimed.iter().flatten().count(), 1);
        Ok(())
    }

    #[cfg(feature = "corpus-zaino")]
    #[test]
    fn finalized_runtime_owner_is_unready_before_refresh_and_stops_once(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let store_reads = finalized_serving_store_for_runtime_tests()?.slots_per_key();
        let shape = runtime_shape(store_reads)?;
        let mut owner = FinalizedTestOwner::new(
            CanonicalNetwork::Mainnet,
            1,
            7,
            shape,
            fixture_security_lease_with_identity(
                shape,
                9,
                SESSION_BINDING,
                CountingReplayGuard::available(),
                DeterministicMaterialSource::at(100),
            )?,
        )?;
        let request = FixedEnvelope::from_array([0; ENVELOPE_BYTES]);

        assert!(matches!(
            <FinalizedTestOwner as FixedEnvelopeRuntime<ENVELOPE_BYTES>>::query_page(
                &mut owner,
                [0; ENVELOPE_BYTES],
            ),
            Err(PrivateQueryUnavailable)
        ));
        assert!(owner.runtime.healthy);
        assert!(owner.runtime.epoch.is_none());
        assert!(owner.controller.pin_serving_epoch().is_none());
        assert_eq!(
            format!("{owner:?}"),
            "FinalizedRuntimeOwner { ..REDACTED.. }"
        );
        let error = FinalizedRuntimeOwnerError;
        assert_eq!(
            format!("{error:?}"),
            "FinalizedRuntimeOwnerError { ..REDACTED.. }"
        );
        assert_eq!(error.to_string(), "private-query runtime owner unavailable");

        let counters = FinalizedProcessCounters::capture(&owner.runtime);
        owner.shutdown()?;
        owner.shutdown()?;
        assert!(owner.stopped);
        assert!(owner.runtime.epoch.is_none());
        assert!(owner.controller.pin_serving_epoch().is_none());
        assert!(matches!(
            owner.handle(&request),
            Err(UniformExternalFailure)
        ));
        assert_eq!(FinalizedProcessCounters::capture(&owner.runtime), counters);
        let _refresh = FinalizedTestOwner::refresh;
        Ok(())
    }

    #[cfg(feature = "corpus-zaino")]
    #[test]
    fn owner_drop_closes_detached_response_permit() -> Result<(), Box<dyn std::error::Error>> {
        let store_reads = finalized_serving_store_for_runtime_tests()?.slots_per_key();
        let shape = runtime_shape(store_reads)?;
        let owner = FinalizedTestOwner::new(
            CanonicalNetwork::Mainnet,
            1,
            7,
            shape,
            fixture_security_lease_with_identity(
                shape,
                9,
                SESSION_BINDING,
                CountingReplayGuard::available(),
                DeterministicMaterialSource::at(100),
            )?,
        )?;
        let release_state = Arc::clone(&owner.response_release.state);
        let permit = owner.response_release.begin_response()?;
        assert_eq!(
            format!("{:?}", owner.response_release),
            "ResponseReleaseGate { ..REDACTED.. }"
        );
        assert_eq!(
            format!("{permit:?}"),
            "ResponseReleasePermit { ..REDACTED.. }"
        );

        drop(owner);
        assert_eq!(
            release_state.load(Ordering::Acquire),
            RESPONSE_RELEASE_CLOSED
        );
        drop(permit);
        assert_eq!(
            release_state.load(Ordering::Acquire),
            RESPONSE_RELEASE_CLOSED
        );
        Ok(())
    }

    #[cfg(feature = "corpus-zaino")]
    #[test]
    fn pending_release_rejects_late_identity_and_boundary_changes(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let current = checkpoint();
        assert_pending_release_rejects_currentness_change(|currentness| {
            currentness.identity = RecentSnapshotIdentity::new(
                current.network.tag(),
                current
                    .height
                    .checked_add(1)
                    .expect("test checkpoint height leaves room to advance"),
                current.block_hash_display,
                current.schema_version,
                current.projection_epoch,
                current.key_epoch,
            );
        })?;
        assert_pending_release_rejects_currentness_change(|currentness| {
            currentness.boundary = currentness.boundary.replacement();
        })?;
        Ok(())
    }

    #[cfg(feature = "corpus-zaino")]
    #[test]
    fn owner_close_before_release_skips_observation_and_fails_closed(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (mut runtime, request, response_release) = finalized_pending_fixture()?;
        let observations = serving_epoch_observations(&runtime);
        let pending =
            handle_finalized_runtime_round(&mut runtime, false, &response_release, &request)?;
        response_release.close();

        assert!(matches!(
            <FinalizedTestPendingRound as PendingFixedEnvelope<ENVELOPE_BYTES>>::try_release_bytes(
                &pending,
            ),
            Err(PrivateQueryUnavailable)
        ));
        assert_eq!(serving_epoch_observations(&runtime), observations);
        drop(pending);
        assert!(response_release.is_closed_for_tests());
        Ok(())
    }

    #[cfg(feature = "corpus-zaino")]
    #[test]
    fn owner_close_during_release_prevents_authorization() -> Result<(), Box<dyn std::error::Error>>
    {
        let (mut runtime, request, response_release) = finalized_pending_fixture()?;
        let observations = serving_epoch_observations(&runtime);
        let pending =
            handle_finalized_runtime_round(&mut runtime, false, &response_release, &request)?;
        let release_state = Arc::clone(&response_release.state);
        with_serving_epoch_currentness(&runtime, |currentness| {
            currentness.after_comparison = Some(Arc::new(move || {
                release_state.store(RESPONSE_RELEASE_CLOSED, Ordering::Release);
            }));
        });

        assert!(matches!(
            pending.try_release_bytes(),
            Err(UniformExternalFailure)
        ));
        assert_eq!(serving_epoch_observations(&runtime), observations + 1);
        assert!(response_release.is_closed_for_tests());
        drop(pending);
        assert!(response_release.is_closed_for_tests());
        Ok(())
    }

    #[cfg(feature = "corpus-zaino")]
    #[test]
    fn security_release_unavailability_is_terminal_and_cached(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (runtime, response_release, pending) = finalized_pending_round_fixture()?;
        runtime.security.make_security_unavailable_for_tests();

        assert_terminal_security_release_failure(&runtime, &response_release, &pending, 0);
        Ok(())
    }

    #[cfg(feature = "corpus-zaino")]
    #[test]
    fn security_release_rejects_equal_value_epoch_remint() -> Result<(), Box<dyn std::error::Error>>
    {
        let (runtime, response_release, pending) = finalized_pending_round_fixture()?;
        runtime
            .security
            .remint_security_epoch_for_tests(SECURITY_EPOCH_BINDING);

        assert_terminal_security_release_failure(&runtime, &response_release, &pending, 1);
        Ok(())
    }

    #[cfg(feature = "corpus-zaino")]
    #[test]
    fn security_release_rejects_each_cross_round_authority(
    ) -> Result<(), Box<dyn std::error::Error>> {
        {
            let (runtime, response_release, mut pending) = finalized_pending_round_fixture()?;
            let other_round =
                SecurityRoundCapture::new(runtime.security.security_epoch_tag_for_tests());
            pending.round.replay_commit_authority = ReplayCommitAuthority::new(&other_round);

            assert_terminal_security_release_failure(&runtime, &response_release, &pending, 1);
        }

        let (runtime, response_release, mut pending) = finalized_pending_round_fixture()?;
        let other_round =
            SecurityRoundCapture::new(runtime.security.security_epoch_tag_for_tests());
        pending.round.reservation_authority = RoundReservationAuthority::new(
            &other_round,
            pending.round.now_unix_seconds,
            pending.round.response_nonce,
            pending.round.token_nonce,
        );

        assert_terminal_security_release_failure(&runtime, &response_release, &pending, 1);
        Ok(())
    }

    #[cfg(feature = "corpus-zaino")]
    #[test]
    fn pending_response_blocks_lifecycle_before_mutation() -> Result<(), Box<dyn std::error::Error>>
    {
        assert_send_and_static::<FinalizedTestPendingRound>();
        assert_send_and_static::<
            FinalizedPendingRuntimeRound<zaino_state::ValidatorConnector, ENVELOPE_BYTES>,
        >();
        let (first_epoch, _, store_reads) =
            finalized_test_epoch_at_generation(1, |identity| identity)?;
        let mut runtime = finalized_runtime_from_epoch(
            first_epoch,
            runtime_shape(store_reads)?,
            CountingReplayGuard::available(),
            DeterministicMaterialSource::at(100),
        )?;
        let checkpoint = runtime.epoch_for_tests().checkpoint;
        let request = request_envelope(
            &runtime,
            checkpoint,
            UtxoQuery::new(address(0xee), 0),
            None,
            1,
        )?;
        let response_release = ResponseReleaseGate::new();
        let mut stopped = false;
        let observations = serving_epoch_observations(&runtime);

        let pending =
            handle_finalized_runtime_round(&mut runtime, stopped, &response_release, &request)?;
        assert_eq!(serving_epoch_observations(&runtime), observations);
        let encoded_pointer = pending.round.envelope.as_bytes().as_ptr();
        assert_eq!(pending.try_release_bytes()?.as_ptr(), encoded_pointer);
        assert_eq!(serving_epoch_observations(&runtime), observations + 1);
        let response = release_finalized_pending_and_decode(&runtime, &pending)?;
        assert_eq!(serving_epoch_observations(&runtime), observations + 1);
        assert_eq!(response.page.outcome(), QueryOutcome::Complete);
        assert_eq!(
            pending.trace().completion(),
            CompletionShape::UnaryFixedEnvelope
        );
        assert_eq!(
            format!("{pending:?}"),
            "PendingRuntimeRound { ..REDACTED.. }"
        );
        let counters = FinalizedProcessCounters::capture(&runtime);
        let generation = runtime
            .epoch_for_tests()
            .recent_snapshot
            .lineage()
            .generation();

        assert!(matches!(
            handle_finalized_runtime_round(&mut runtime, stopped, &response_release, &request),
            Err(UniformExternalFailure)
        ));
        assert_eq!(FinalizedProcessCounters::capture(&runtime), counters);

        let refresh_work_started = Cell::new(false);
        let refresh_admission = response_release.begin_refresh().inspect(|_| {
            refresh_work_started.set(true);
        });
        assert!(matches!(refresh_admission, Err(FinalizedRuntimeOwnerError)));
        assert!(!refresh_work_started.get());
        assert_eq!(
            runtime
                .epoch_for_tests()
                .recent_snapshot
                .lineage()
                .generation(),
            generation
        );
        assert_eq!(FinalizedProcessCounters::capture(&runtime), counters);

        assert_eq!(
            stop_finalized_runtime_after_responses(&mut runtime, &mut stopped, &response_release,),
            Err(FinalizedRuntimeOwnerError)
        );
        assert!(!stopped);
        assert_eq!(
            runtime
                .epoch_for_tests()
                .recent_snapshot
                .lineage()
                .generation(),
            generation
        );
        assert_eq!(FinalizedProcessCounters::capture(&runtime), counters);

        let release_state = Arc::clone(&response_release.state);
        response_release.close();
        assert_eq!(
            release_state.load(Ordering::Acquire),
            RESPONSE_RELEASE_CLOSED
        );
        drop(pending);
        assert_eq!(
            release_state.load(Ordering::Acquire),
            RESPONSE_RELEASE_CLOSED
        );
        Ok(())
    }

    #[cfg(feature = "corpus-zaino")]
    #[tokio::test]
    async fn dropping_pending_response_allows_generation_two_replacement(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (first_epoch, _, store_reads) =
            finalized_test_epoch_at_generation(1, |identity| identity)?;
        let mut runtime = finalized_runtime_from_epoch(
            first_epoch,
            runtime_shape(store_reads)?,
            CountingReplayGuard::available(),
            DeterministicMaterialSource::at(100),
        )?;
        let checkpoint = runtime.epoch_for_tests().checkpoint;
        let query = UtxoQuery::new(address(0xee), 0);
        let request = request_envelope(&runtime, checkpoint, query, None, 1)?;
        let response_release = ResponseReleaseGate::new();
        let observations = serving_epoch_observations(&runtime);

        let pending =
            handle_finalized_runtime_round(&mut runtime, false, &response_release, &request)?;
        assert!(!response_release.is_idle());
        assert_eq!(serving_epoch_observations(&runtime), observations);
        let counters = FinalizedProcessCounters::capture(&runtime);
        drop(pending);
        assert!(response_release.is_idle());
        assert_eq!(serving_epoch_observations(&runtime), observations);

        let (replacement, _, replacement_store_reads) =
            finalized_test_epoch_at_generation(2, |identity| identity)?;
        assert_eq!(replacement_store_reads, store_reads);
        {
            let _refresh_permit = response_release.begin_refresh()?;
            replace_finalized_runtime_epoch_from(
                &mut runtime,
                false,
                std::future::ready(Ok(replacement)),
            )
            .await?;
        }
        assert!(response_release.is_idle());
        assert_eq!(
            runtime
                .epoch_for_tests()
                .recent_snapshot
                .lineage()
                .generation(),
            2
        );
        assert_eq!(FinalizedProcessCounters::capture(&runtime), counters);

        let replacement_request = request_envelope(&runtime, checkpoint, query, None, 2)?;
        let replacement_observations = serving_epoch_observations(&runtime);
        let replacement_pending = handle_finalized_runtime_round(
            &mut runtime,
            false,
            &response_release,
            &replacement_request,
        )?;
        assert_eq!(
            serving_epoch_observations(&runtime),
            replacement_observations
        );
        let replacement_response =
            release_finalized_pending_and_decode(&runtime, &replacement_pending)?;
        assert_eq!(
            serving_epoch_observations(&runtime),
            replacement_observations + 1
        );
        assert_eq!(replacement_response.page.outcome(), QueryOutcome::Complete);
        drop(replacement_pending);
        assert!(response_release.is_idle());
        assert!(runtime.healthy);
        Ok(())
    }

    #[cfg(feature = "corpus-zaino")]
    #[test]
    fn protected_failure_retires_security_and_makes_pending_response_unreleasable(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (first_epoch, _, store_reads) =
            finalized_test_epoch_at_generation(1, |identity| identity)?;
        let mut runtime = finalized_runtime_from_epoch(
            first_epoch,
            runtime_shape(store_reads)?,
            CountingReplayGuard::available(),
            DeterministicMaterialSource::at(100),
        )?;
        let lineage = runtime.epoch_for_tests().recent_snapshot.lineage();
        runtime.epoch_mut_for_tests().recent_snapshot = FrozenRecentSnapshot::failing(
            lineage,
            [RecentSnapshotSlot::dummy(); RECENT_SNAPSHOT_SLOTS],
            0,
        );
        let checkpoint = runtime.epoch_for_tests().checkpoint;
        let request = request_envelope(
            &runtime,
            checkpoint,
            UtxoQuery::new(address(0xee), 0),
            None,
            1,
        )?;
        let response_release = ResponseReleaseGate::new();

        let pending =
            handle_finalized_runtime_round(&mut runtime, false, &response_release, &request)?;
        assert!(!runtime.healthy);
        assert!(!response_release.is_idle());
        assert!(retire_unhealthy_finalized_runtime_after_round(
            &mut runtime,
            true,
            &response_release,
        ));
        assert!(runtime.epoch.is_none());
        assert!(response_release.is_closed_for_tests());
        assert!(!runtime.security.security_state_for_tests().0);
        assert!(matches!(
            pending.try_release_bytes(),
            Err(UniformExternalFailure)
        ));

        drop(pending);
        assert!(response_release.is_closed_for_tests());
        Ok(())
    }

    #[cfg(feature = "corpus-zaino")]
    #[test]
    fn unavailable_release_closes_admission_and_keeps_shutdown_available(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (first_epoch, _, store_reads) =
            finalized_test_epoch_at_generation(1, |identity| identity)?;
        let mut runtime = finalized_runtime_from_epoch(
            first_epoch,
            runtime_shape(store_reads)?,
            CountingReplayGuard::available(),
            DeterministicMaterialSource::at(100),
        )?;
        let checkpoint = runtime.epoch_for_tests().checkpoint;
        let request = request_envelope(
            &runtime,
            checkpoint,
            UtxoQuery::new(address(0xee), 0),
            None,
            1,
        )?;
        let response_release = ResponseReleaseGate::new();
        runtime
            .epoch_for_tests()
            .serving_epoch
            .with_currentness_for_tests(|currentness| currentness.available = false)
            .ok_or("serving-epoch currentness mutex is poisoned")?;
        let observations = serving_epoch_observations(&runtime);

        let pending =
            handle_finalized_runtime_round(&mut runtime, false, &response_release, &request)?;
        assert_eq!(serving_epoch_observations(&runtime), observations);
        assert!(runtime.healthy);
        assert!(runtime.security.security_state_for_tests().0);
        let counters = FinalizedProcessCounters::capture(&runtime);

        assert!(matches!(
            pending.try_release_bytes(),
            Err(UniformExternalFailure)
        ));
        assert_eq!(serving_epoch_observations(&runtime), observations + 1);
        assert!(response_release.is_closed_for_tests());
        assert!(!runtime.security.security_state_for_tests().0);
        assert!(matches!(
            pending.try_release_bytes(),
            Err(UniformExternalFailure)
        ));
        assert_eq!(serving_epoch_observations(&runtime), observations + 1);
        drop(pending);
        assert!(response_release.is_closed_for_tests());
        assert_eq!(FinalizedProcessCounters::capture(&runtime), counters);
        assert!(matches!(
            handle_finalized_runtime_round(&mut runtime, false, &response_release, &request),
            Err(UniformExternalFailure)
        ));
        assert!(matches!(
            response_release.begin_refresh(),
            Err(FinalizedRuntimeOwnerError)
        ));
        assert_eq!(FinalizedProcessCounters::capture(&runtime), counters);

        let mut stopped = false;
        stop_finalized_runtime_after_responses(&mut runtime, &mut stopped, &response_release)?;
        stop_finalized_runtime_after_responses(&mut runtime, &mut stopped, &response_release)?;
        assert!(stopped);
        assert!(response_release.is_closed_for_tests());
        Ok(())
    }

    #[cfg(feature = "corpus-zaino")]
    #[tokio::test]
    async fn cancelled_refresh_reopens_admission_without_stale_fallback(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (first_epoch, _, store_reads) =
            finalized_test_epoch_at_generation(1, |identity| identity)?;
        let mut runtime = finalized_runtime_from_epoch(
            first_epoch,
            runtime_shape(store_reads)?,
            CountingReplayGuard::available(),
            DeterministicMaterialSource::at(100),
        )?;
        let checkpoint = runtime.epoch_for_tests().checkpoint;
        let request = request_envelope(
            &runtime,
            checkpoint,
            UtxoQuery::new(address(0xee), 0),
            None,
            1,
        )?;
        let response_release = ResponseReleaseGate::new();
        let counters = FinalizedProcessCounters::capture(&runtime);

        {
            let _refresh_permit = response_release.begin_refresh()?;
            let replacement = replace_finalized_runtime_epoch_from(
                &mut runtime,
                false,
                std::future::pending::<Result<FinalizedTestEpoch, FinalizedRuntimeOwnerError>>(),
            );
            tokio::pin!(replacement);
            tokio::select! {
                biased;
                result = &mut replacement => {
                    panic!("pending replacement completed unexpectedly: {result:?}")
                }
                _ = async {} => {}
            }
            assert!(response_release.is_refreshing_for_tests());
        }

        assert!(response_release.is_idle());
        assert!(runtime.epoch.is_none());
        assert!(runtime.healthy);
        assert!(matches!(
            handle_finalized_runtime_round(&mut runtime, false, &response_release, &request),
            Err(UniformExternalFailure)
        ));
        assert!(response_release.is_idle());
        assert_eq!(FinalizedProcessCounters::capture(&runtime), counters);

        let (replacement, _, replacement_store_reads) =
            finalized_test_epoch_at_generation(2, |identity| identity)?;
        assert_eq!(replacement_store_reads, store_reads);
        {
            let _refresh_permit = response_release.begin_refresh()?;
            replace_finalized_runtime_epoch_from(
                &mut runtime,
                false,
                std::future::ready(Ok(replacement)),
            )
            .await?;
        }
        assert!(response_release.is_idle());
        assert_eq!(
            runtime
                .epoch_for_tests()
                .recent_snapshot
                .lineage()
                .generation(),
            2
        );
        assert_eq!(FinalizedProcessCounters::capture(&runtime), counters);
        Ok(())
    }

    #[cfg(feature = "corpus-zaino")]
    #[tokio::test]
    async fn ready_finalized_runtime_stop_is_idempotent_and_prevents_reactivation(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (serving_epoch, _, store_reads) =
            finalized_test_epoch_at_generation(1, |identity| identity)?;
        let mut runtime = finalized_runtime_from_epoch(
            serving_epoch,
            runtime_shape(store_reads)?,
            CountingReplayGuard::available(),
            DeterministicMaterialSource::at(100),
        )?;
        let checkpoint = runtime.epoch_for_tests().checkpoint;
        let request = request_envelope(
            &runtime,
            checkpoint,
            UtxoQuery::new(address(0xee), 0),
            None,
            1,
        )?;
        let response = finalized_handle_and_decode(&mut runtime, &request)?;
        assert_eq!(response.page.outcome(), QueryOutcome::Complete);
        let counters = FinalizedProcessCounters::capture(&runtime);

        let mut stopped = false;
        stop_finalized_runtime(&mut runtime, &mut stopped);
        stop_finalized_runtime(&mut runtime, &mut stopped);
        assert!(stopped);
        assert!(runtime.epoch.is_none());
        assert!(runtime.healthy);
        assert!(matches!(
            runtime.handle(&request),
            Err(UniformExternalFailure)
        ));
        assert_eq!(FinalizedProcessCounters::capture(&runtime), counters);

        let (replacement, _, replacement_store_reads) =
            finalized_test_epoch_at_generation(2, |identity| identity)?;
        assert_eq!(replacement_store_reads, store_reads);
        assert_eq!(
            replace_finalized_runtime_epoch_from(
                &mut runtime,
                stopped,
                std::future::ready(Ok(replacement)),
            )
            .await,
            Err(FinalizedRuntimeOwnerError)
        );
        assert!(runtime.epoch.is_none());
        assert_eq!(FinalizedProcessCounters::capture(&runtime), counters);
        Ok(())
    }

    #[cfg(feature = "corpus-zaino")]
    #[test]
    fn finalized_epoch_factory_derives_checkpoint_and_retains_runtime_state(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (serving_epoch, identity, store_reads) = finalized_test_epoch(|identity| identity)?;
        let mut runtime = finalized_runtime_from_epoch(
            serving_epoch,
            runtime_shape(store_reads)?,
            CountingReplayGuard::available(),
            DeterministicMaterialSource::at(100),
        )?;

        let checkpoint = runtime.epoch_for_tests().checkpoint;
        assert_eq!(checkpoint.network.tag(), identity.network_tag());
        assert_eq!(checkpoint.height, identity.finalized_height());
        assert_eq!(
            checkpoint.block_hash_display,
            *identity.finalized_hash_display()
        );
        assert_eq!(checkpoint.schema_version, identity.schema_version());
        assert_eq!(checkpoint.projection_epoch, identity.projection_epoch());
        assert_eq!(checkpoint.key_epoch, identity.key_epoch());

        for nonce_byte in [1, 2] {
            let request = runtime.codec.encode_request(
                &super::super::PrivateQueryRequest::new(
                    checkpoint,
                    UtxoQuery::new(address(0xee), 0),
                    None,
                ),
                [nonce_byte; ENVELOPE_NONCE_BYTES],
                runtime.security.envelope_protector(),
            )?;
            let round = runtime.handle(&request)?;
            let response = runtime
                .codec
                .decode_response(round.envelope(), runtime.security.envelope_protector())?;
            assert_eq!(response.page.outcome(), QueryOutcome::Complete);
        }
        assert_eq!(runtime.security.material_source_for_tests().calls, 2);
        assert!(runtime.healthy);
        Ok(())
    }

    #[cfg(feature = "corpus-zaino")]
    #[tokio::test]
    async fn pending_finalized_epoch_replacement_retires_before_await_without_state_reset(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (first_epoch, _, store_reads) =
            finalized_test_epoch_at_generation(1, |identity| identity)?;
        let mut runtime = finalized_runtime_from_epoch(
            first_epoch,
            runtime_shape(store_reads)?,
            CountingReplayGuard::available(),
            DeterministicMaterialSource::at(100),
        )?;
        let checkpoint = runtime.epoch_for_tests().checkpoint;
        let request = request_envelope(
            &runtime,
            checkpoint,
            UtxoQuery::new(address(0xee), 0),
            None,
            1,
        )?;
        let response = finalized_handle_and_decode(&mut runtime, &request)?;
        assert_eq!(response.page.outcome(), QueryOutcome::Complete);
        let counters = FinalizedProcessCounters::capture(&runtime);

        {
            let replacement = replace_finalized_runtime_epoch_from(
                &mut runtime,
                false,
                std::future::pending::<Result<FinalizedTestEpoch, FinalizedRuntimeOwnerError>>(),
            );
            tokio::pin!(replacement);
            tokio::select! {
                biased;
                result = &mut replacement => {
                    panic!("pending replacement completed unexpectedly: {result:?}")
                }
                _ = async {} => {}
            }
        }

        assert!(runtime.epoch.is_none());
        assert!(runtime.healthy);
        assert_eq!(FinalizedProcessCounters::capture(&runtime), counters);
        assert!(matches!(
            runtime.handle(&request),
            Err(UniformExternalFailure)
        ));
        assert_eq!(FinalizedProcessCounters::capture(&runtime), counters);
        Ok(())
    }

    #[cfg(feature = "corpus-zaino")]
    #[tokio::test]
    async fn finalized_epoch_replacement_preserves_process_state_and_monotonic_health(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (first_epoch, _, store_reads) =
            finalized_test_epoch_at_generation(1, |identity| identity)?;
        let key_epoch = first_epoch.identity().key_epoch();
        let shape = runtime_shape(store_reads)?;
        let mut runtime = FinalizedTestRuntime::without_epoch(
            shape,
            fixture_security_lease_with_identity(
                shape,
                key_epoch,
                SESSION_BINDING,
                CountingReplayGuard::available(),
                DeterministicMaterialSource::at(100),
            )?,
        )?;
        runtime.activate_finalized_serving_epoch(first_epoch)?;
        let checkpoint = runtime.epoch_for_tests().checkpoint;
        let query = UtxoQuery::new(address(0xee), 0);
        let first_binding_digest = runtime.epoch_for_tests().recent_snapshot_binding_digest;
        assert_eq!(
            runtime
                .epoch_for_tests()
                .recent_snapshot
                .lineage()
                .generation(),
            1
        );

        let first_request = request_envelope(&runtime, checkpoint, query, None, 1)?;
        let first_response = finalized_handle_and_decode(&mut runtime, &first_request)?;
        assert_eq!(first_response.page.outcome(), QueryOutcome::Complete);
        assert_eq!(runtime.security.replay_guard_for_tests().calls, 1);
        assert_eq!(runtime.security.material_source_for_tests().calls, 1);

        let profile = *runtime.epoch_for_tests().engine.profile();
        let token_context = runtime.codec.continuation_protection_context(&checkpoint)?;
        let old_continuation = ContinuationToken::issue(
            &ContinuationState::new(
                CONTINUATION_VERSION,
                *profile.profile_id(),
                runtime.continuation_query_digest_for_tests(&query),
                checkpoint.projection_epoch,
                1,
                160,
                [0x41; ENVELOPE_NONCE_BYTES],
            ),
            &token_context,
            runtime.security.token_protector(),
        )?;
        let counters_before_replacement = FinalizedProcessCounters::capture(&runtime);

        let (replacement_epoch, _, replacement_store_reads) =
            finalized_test_epoch_at_generation(2, |identity| identity)?;
        assert_eq!(replacement_store_reads, store_reads);
        replace_finalized_runtime_epoch_from(
            &mut runtime,
            false,
            std::future::ready(Ok(replacement_epoch)),
        )
        .await?;
        assert_eq!(
            runtime
                .epoch_for_tests()
                .recent_snapshot
                .lineage()
                .generation(),
            2
        );
        assert_ne!(
            runtime.epoch_for_tests().recent_snapshot_binding_digest,
            first_binding_digest
        );
        assert_eq!(runtime.epoch_for_tests().checkpoint, checkpoint);
        assert_eq!(
            FinalizedProcessCounters::capture(&runtime),
            counters_before_replacement
        );

        let old_continuation_request =
            request_envelope(&runtime, checkpoint, query, Some(old_continuation), 2)?;
        let old_continuation_response =
            finalized_handle_and_decode(&mut runtime, &old_continuation_request)?;
        assert_eq!(
            old_continuation_response.page.outcome(),
            QueryOutcome::InvalidContinuation
        );
        assert!(old_continuation_response.page.is_all_dummy());

        let replacement_request = request_envelope(&runtime, checkpoint, query, None, 3)?;
        let replacement_response = finalized_handle_and_decode(&mut runtime, &replacement_request)?;
        assert_eq!(replacement_response.page.outcome(), QueryOutcome::Complete);
        assert_eq!(runtime.security.replay_guard_for_tests().calls, 3);
        assert_eq!(runtime.security.material_source_for_tests().calls, 3);
        assert!(runtime.healthy);

        runtime
            .epoch_for_tests()
            .serving_epoch
            .with_currentness_for_tests(|currentness| currentness.available = false)
            .ok_or("serving-epoch currentness mutex is poisoned")?;
        let unavailable_request = request_envelope(&runtime, checkpoint, query, None, 4)?;
        assert!(matches!(
            runtime.handle(&unavailable_request),
            Err(UniformExternalFailure)
        ));
        assert!(!runtime.healthy);
        assert_eq!(runtime.security.replay_guard_for_tests().calls, 4);
        assert_eq!(runtime.security.material_source_for_tests().calls, 4);

        let (recovery_epoch, _, _) = finalized_test_epoch_at_generation(3, |identity| identity)?;
        assert_eq!(
            replace_finalized_runtime_epoch_from(
                &mut runtime,
                false,
                std::future::ready(Ok(recovery_epoch)),
            )
            .await,
            Err(FinalizedRuntimeOwnerError)
        );
        assert!(runtime.epoch.is_none());
        assert!(matches!(
            runtime.handle(&unavailable_request),
            Err(UniformExternalFailure)
        ));
        assert_eq!(runtime.security.replay_guard_for_tests().calls, 4);
        assert_eq!(runtime.security.material_source_for_tests().calls, 4);
        Ok(())
    }

    #[cfg(feature = "corpus-zaino")]
    #[tokio::test]
    async fn failed_finalized_epoch_replacements_never_fall_back_and_can_recover(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (first_epoch, _, store_reads) =
            finalized_test_epoch_at_generation(1, |identity| identity)?;
        let mut runtime = finalized_runtime_from_epoch(
            first_epoch,
            runtime_shape(store_reads)?,
            CountingReplayGuard::available(),
            DeterministicMaterialSource::at(100),
        )?;
        let checkpoint = runtime.epoch_for_tests().checkpoint;
        let request = request_envelope(
            &runtime,
            checkpoint,
            UtxoQuery::new(address(0xee), 0),
            None,
            1,
        )?;
        let counters = FinalizedProcessCounters::capture(&runtime);

        assert_eq!(
            replace_finalized_runtime_epoch_from(
                &mut runtime,
                false,
                std::future::ready(Err(FinalizedRuntimeOwnerError)),
            )
            .await,
            Err(FinalizedRuntimeOwnerError)
        );
        assert!(runtime.epoch.is_none());
        assert!(runtime.healthy);
        assert!(matches!(
            runtime.handle(&request),
            Err(UniformExternalFailure)
        ));
        assert_eq!(FinalizedProcessCounters::capture(&runtime), counters);

        let (invalid_epoch, _, _) = finalized_test_epoch(|identity| {
            RecentSnapshotIdentity::new(
                u8::MAX,
                identity.finalized_height(),
                *identity.finalized_hash_display(),
                identity.schema_version(),
                identity.projection_epoch(),
                identity.key_epoch(),
            )
        })?;
        assert_eq!(
            replace_finalized_runtime_epoch_from(
                &mut runtime,
                false,
                std::future::ready(Ok(invalid_epoch)),
            )
            .await,
            Err(FinalizedRuntimeOwnerError)
        );
        assert!(runtime.epoch.is_none());
        assert!(runtime.healthy);
        assert!(matches!(
            runtime.handle(&request),
            Err(UniformExternalFailure)
        ));
        assert_eq!(FinalizedProcessCounters::capture(&runtime), counters);

        let (recovery_epoch, _, recovery_store_reads) =
            finalized_test_epoch_at_generation(2, |identity| identity)?;
        assert_eq!(recovery_store_reads, store_reads);
        replace_finalized_runtime_epoch_from(
            &mut runtime,
            false,
            std::future::ready(Ok(recovery_epoch)),
        )
        .await?;
        assert_eq!(
            runtime
                .epoch_for_tests()
                .recent_snapshot
                .lineage()
                .generation(),
            2
        );
        assert_eq!(FinalizedProcessCounters::capture(&runtime), counters);

        let response = finalized_handle_and_decode(&mut runtime, &request)?;
        assert_eq!(response.page.outcome(), QueryOutcome::Complete);
        assert!(runtime.healthy);
        assert_eq!(runtime.security.replay_guard_for_tests().calls, 1);
        assert_eq!(runtime.security.material_source_for_tests().calls, 1);
        Ok(())
    }

    #[cfg(feature = "corpus-zaino")]
    #[test]
    fn finalized_epoch_factory_rejects_unknown_network_without_identifiers(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (serving_epoch, _, store_reads) = finalized_test_epoch(|identity| {
            RecentSnapshotIdentity::new(
                u8::MAX,
                identity.finalized_height(),
                *identity.finalized_hash_display(),
                identity.schema_version(),
                identity.projection_epoch(),
                identity.key_epoch(),
            )
        })?;
        let result = finalized_runtime_from_epoch(
            serving_epoch,
            runtime_shape(store_reads)?,
            CountingReplayGuard::available(),
            DeterministicMaterialSource::at(100),
        );
        let Err(error) = result else {
            return Err("unknown internal network tag must reject runtime construction".into());
        };
        assert_eq!(error, FinalizedRuntimeBuildError);
        assert_eq!(
            format!("{error:?}"),
            "FinalizedRuntimeBuildError { ..REDACTED.. }"
        );
        assert_eq!(
            error.to_string(),
            "finalized private-query runtime unavailable"
        );
        Ok(())
    }

    #[cfg(feature = "corpus-zaino")]
    #[test]
    fn finalized_epoch_factory_coarsens_store_shape_mismatch(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (serving_epoch, _, store_reads) = finalized_test_epoch(|identity| identity)?;
        let mismatched_reads = store_reads
            .checked_sub(1)
            .ok_or("finalized store fixture must expose at least one slot")?;
        let result = finalized_runtime_from_epoch(
            serving_epoch,
            runtime_shape(mismatched_reads)?,
            CountingReplayGuard::available(),
            DeterministicMaterialSource::at(100),
        );
        let Err(error) = result else {
            return Err("store/profile mismatch must reject runtime construction".into());
        };
        assert_eq!(error, FinalizedRuntimeBuildError);
        Ok(())
    }

    #[cfg(feature = "corpus-zaino")]
    #[test]
    fn finalized_epoch_factory_coarsens_recent_snapshot_shape_mismatch(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (serving_epoch, _, store_reads) = finalized_test_epoch(|identity| identity)?;
        let mismatched_slots = RECENT_SNAPSHOT_SLOTS
            .checked_sub(1)
            .ok_or("recent-snapshot fixture must expose at least one slot")?;
        let result = finalized_runtime_from_epoch(
            serving_epoch,
            runtime_shape_with_recent_snapshot_slots(store_reads, mismatched_slots)?,
            CountingReplayGuard::available(),
            DeterministicMaterialSource::at(100),
        );
        let Err(error) = result else {
            return Err("recent-snapshot shape mismatch must reject runtime construction".into());
        };
        assert_eq!(error, FinalizedRuntimeBuildError);
        Ok(())
    }

    #[test]
    fn stale_serving_epoch_discards_the_encoded_response_after_complete_fixed_work(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let query = UtxoQuery::new(address(1), 0);

        let mut finalized_advanced = runtime(4, &[(0, utxo(1, 10))])?;
        let request = request_envelope(&finalized_advanced, checkpoint(), query, None, 1)?;
        let current = checkpoint();
        with_serving_epoch_currentness(&finalized_advanced, |currentness| {
            currentness.identity = RecentSnapshotIdentity::new(
                current.network.tag(),
                current.height + 1,
                current.block_hash_display,
                current.schema_version,
                current.projection_epoch,
                current.key_epoch,
            );
        });
        assert_late_serving_epoch_failure_completes_fixed_work(&mut finalized_advanced, &request)?;

        let mut equal_value_boundary_replacement = runtime(4, &[(0, utxo(1, 10))])?;
        let request = request_envelope(
            &equal_value_boundary_replacement,
            checkpoint(),
            query,
            None,
            2,
        )?;
        with_serving_epoch_currentness(&equal_value_boundary_replacement, |currentness| {
            currentness.boundary = currentness.boundary.replacement();
        });
        assert_late_serving_epoch_failure_completes_fixed_work(
            &mut equal_value_boundary_replacement,
            &request,
        )?;

        let mut unavailable = runtime(4, &[(0, utxo(1, 10))])?;
        let request = request_envelope(&unavailable, checkpoint(), query, None, 3)?;
        with_serving_epoch_currentness(&unavailable, |currentness| {
            currentness.available = false;
        });
        assert_late_serving_epoch_failure_completes_fixed_work(&mut unavailable, &request)?;

        let mut in_flight_refresh = runtime(4, &[(0, utxo(1, 10))])?;
        let request = request_envelope(&in_flight_refresh, checkpoint(), query, None, 4)?;
        let invalidator = in_flight_refresh
            .epoch_for_tests()
            .serving_epoch
            .invalidator_for_tests();
        with_serving_epoch_currentness(&in_flight_refresh, |currentness| {
            currentness.after_comparison = Some(Arc::new(move || invalidator.clear_epoch()));
        });
        assert_late_serving_epoch_failure_completes_fixed_work(&mut in_flight_refresh, &request)?;
        Ok(())
    }

    #[test]
    fn secret_and_protected_error_cases_have_identical_complete_runtime_traces(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let key = address(1);
        let (baseline, hit) = run_initial(&[(0, utxo(1, 10))], UtxoQuery::new(key, 0))?;
        assert_eq!(hit.page.outcome(), QueryOutcome::Complete);
        assert_eq!(hit.page.real_count(), 1);

        let cases = [
            run_initial(&[], UtxoQuery::new(address(9), 0))?,
            run_initial(&[(0, utxo(1, 10))], UtxoQuery::new(key, 11))?,
            run_initial(
                &[(0, utxo(1, 10)), (1, utxo(2, 11))],
                UtxoQuery::new(key, 0),
            )?,
            run_initial(
                &[(0, utxo(1, 10)), (1, utxo(2, 11)), (2, utxo(3, 12))],
                UtxoQuery::new(key, 0),
            )?,
            run_initial(&[(3, utxo(4, 13))], UtxoQuery::new(key, 0))?,
            run_initial(
                &[(0, utxo(1, 10))],
                UtxoQuery::from_untrusted_address_key(&[7; 31], 0),
            )?,
        ];
        let expected_outcomes = [
            QueryOutcome::Complete,
            QueryOutcome::Complete,
            QueryOutcome::Complete,
            QueryOutcome::ResultBudgetExceeded,
            QueryOutcome::Complete,
            QueryOutcome::InvalidDomain,
        ];
        for ((trace, response), expected_outcome) in cases.iter().zip(expected_outcomes) {
            assert_eq!(*trace, baseline);
            assert_eq!(response.page.outcome(), expected_outcome);
        }

        let mut recent_hit = runtime_with_recent(
            4,
            &[],
            [
                RecentSnapshotSlot::created(key, utxo(5, 14)),
                RecentSnapshotSlot::dummy(),
                RecentSnapshotSlot::dummy(),
                RecentSnapshotSlot::dummy(),
            ],
        )?;
        let request = request_envelope(&recent_hit, checkpoint(), UtxoQuery::new(key, 0), None, 7)?;
        let (recent_trace, recent_response) = handle_and_decode(&mut recent_hit, &request)?;
        assert_eq!(recent_trace, baseline);
        assert_eq!(recent_response.page.outcome(), QueryOutcome::Complete);
        assert_eq!(recent_response.page.real_count(), 1);
        Ok(())
    }

    #[test]
    fn combined_store_and_recent_cursor_pages_without_duplicates(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let key = address(1);
        let entries = [(0, utxo(1, 10)), (1, utxo(2, 11)), (2, utxo(3, 12))];
        let mut runtime = runtime_with_recent(
            4,
            &entries,
            [
                RecentSnapshotSlot::created(key, utxo(4, 13)),
                RecentSnapshotSlot::created(key, utxo(5, 14)),
                RecentSnapshotSlot::dummy(),
                RecentSnapshotSlot::dummy(),
            ],
        )?;
        let query = UtxoQuery::new(key, 0);

        let first_request = request_envelope(&runtime, checkpoint(), query, None, 1)?;
        let (first_trace, first) = handle_and_decode(&mut runtime, &first_request)?;
        let first_token = first
            .continuation
            .clone()
            .expect("first mixed-layer page carries a token");

        let second_request = request_envelope(&runtime, checkpoint(), query, Some(first_token), 2)?;
        let (second_trace, second) = handle_and_decode(&mut runtime, &second_request)?;
        let second_token = second
            .continuation
            .clone()
            .expect("second mixed-layer page carries a token");

        let token_context = runtime
            .codec
            .continuation_protection_context(&checkpoint())?;
        let profile = *runtime.epoch_for_tests().engine.profile();
        let expectation = ContinuationExpectation::new(
            CONTINUATION_VERSION,
            &profile,
            runtime.continuation_query_digest_for_tests(&query),
            checkpoint().projection_epoch,
            102,
            8,
        );
        let inspection = ContinuationToken::inspect_optional(
            Some(&second_token),
            &CountingTokenProtector::default(),
            &token_context,
            &expectation,
            runtime.security.replay_namespace(),
            [0; ENVELOPE_NONCE_BYTES],
        );
        let security_round =
            SecurityRoundCapture::new(runtime.security.security_epoch_tag_for_tests());
        let mut replay_guard = CountingReplayGuard::available();
        let (continuation_use, replay_commit_authority) = inspection
            .finish_replay(&security_round, &mut replay_guard)
            .into_parts();
        let replay_commit_authority =
            replay_commit_authority.ok_or("fixture replay commit must return an authority")?;
        assert!(replay_commit_authority.matches(
            runtime.security.security_epoch_tag_for_tests(),
            &security_round
        ));
        assert_eq!(
            continuation_use,
            ContinuationUse::Continue {
                cursor: 5,
                expires_at_unix_seconds: 160,
            }
        );

        let third_request = request_envelope(&runtime, checkpoint(), query, Some(second_token), 3)?;
        let (third_trace, third) = handle_and_decode(&mut runtime, &third_request)?;
        assert_eq!(first_trace, second_trace);
        assert_eq!(first_trace, third_trace);
        assert_eq!(first.page.outcome(), QueryOutcome::ResultBudgetExceeded);
        assert_eq!(second.page.outcome(), QueryOutcome::ResultBudgetExceeded);
        assert_eq!(third.page.outcome(), QueryOutcome::Complete);

        let returned_txids: Vec<[u8; TXID_BYTES]> = first
            .page
            .slots()
            .iter()
            .chain(second.page.slots())
            .chain(third.page.slots())
            .filter(|slot| slot.is_occupied())
            .map(|slot| *slot.padded_utxo().txid())
            .collect();
        assert_eq!(
            returned_txids,
            vec![
                [1; TXID_BYTES],
                [2; TXID_BYTES],
                [3; TXID_BYTES],
                [4; TXID_BYTES],
                [5; TXID_BYTES]
            ]
        );
        assert_eq!(
            runtime.epoch_for_tests().recent_snapshot.read_calls(),
            3 * RECENT_SNAPSHOT_SLOTS
        );
        Ok(())
    }

    #[test]
    fn snapshot_content_drift_completes_fixed_work_and_latches_readiness(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let key = address(1);
        let entries = [(0, utxo(1, 10)), (1, utxo(2, 11)), (2, utxo(3, 12))];
        let mut runtime = runtime(4, &entries)?;
        let query = UtxoQuery::new(key, 0);

        let first_request = request_envelope(&runtime, checkpoint(), query, None, 1)?;
        let (baseline, first) = handle_and_decode(&mut runtime, &first_request)?;
        let token = first
            .continuation
            .expect("capped first page carries a continuation");
        runtime
            .epoch_mut_for_tests()
            .recent_snapshot
            .replace_slot(0, RecentSnapshotSlot::created(key, utxo(4, 13)));

        let second_request = request_envelope(&runtime, checkpoint(), query, Some(token), 2)?;
        let (drift_trace, drift_response) = handle_and_decode(&mut runtime, &second_request)?;
        assert_eq!(drift_trace, baseline);
        assert_eq!(
            drift_response.page.outcome(),
            QueryOutcome::ProjectionNotReady
        );
        assert!(drift_response.page.is_all_dummy());
        assert!(!runtime.healthy);
        assert_eq!(
            runtime.epoch_for_tests().recent_snapshot.read_calls(),
            2 * RECENT_SNAPSHOT_SLOTS
        );
        assert_eq!(finalized_store_reads(&runtime), 8);
        Ok(())
    }

    #[test]
    fn snapshot_identity_drift_completes_fixed_work_and_latches_readiness(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let key = address(1);
        let mut runtime = runtime(4, &[(0, utxo(1, 10))])?;
        let current = checkpoint();
        runtime
            .epoch_mut_for_tests()
            .recent_snapshot
            .replace_identity(RecentSnapshotIdentity::new(
                current.network.tag(),
                current.height + 1,
                current.block_hash_display,
                current.schema_version,
                current.projection_epoch,
                current.key_epoch,
            ));

        let request = request_envelope(&runtime, checkpoint(), UtxoQuery::new(key, 0), None, 1)?;
        let (trace, response) = handle_and_decode(&mut runtime, &request)?;
        assert_eq!(trace.store_reads(), 4);
        assert_eq!(trace.recent_snapshot_reads(), RECENT_SNAPSHOT_SLOTS);
        assert_eq!(response.page.outcome(), QueryOutcome::ProjectionNotReady);
        assert!(response.page.is_all_dummy());
        assert!(!runtime.healthy);
        Ok(())
    }

    #[test]
    fn snapshot_lineage_drift_completes_fixed_work_and_latches_readiness(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let key = address(1);
        let mut runtime = runtime(4, &[(0, utxo(1, 10))])?;
        let current = runtime.epoch_for_tests().recent_snapshot.lineage();
        runtime
            .epoch_mut_for_tests()
            .recent_snapshot
            .replace_lineage(RecentSnapshotLineage::from_parts_for_tests(
                current
                    .generation()
                    .checked_add(1)
                    .expect("runtime fixture generation leaves successor room"),
                current.finalized(),
                current.recent_tip_height(),
                *current.recent_tip_hash_display(),
            )?);

        let request = request_envelope(&runtime, checkpoint(), UtxoQuery::new(key, 0), None, 1)?;
        let (trace, response) = handle_and_decode(&mut runtime, &request)?;
        assert_eq!(trace.store_reads(), 4);
        assert_eq!(trace.recent_snapshot_reads(), RECENT_SNAPSHOT_SLOTS);
        assert_eq!(response.page.outcome(), QueryOutcome::ProjectionNotReady);
        assert!(response.page.is_all_dummy());
        assert!(!runtime.healthy);
        Ok(())
    }

    #[test]
    fn malformed_snapshot_completes_fixed_work_and_latches_readiness(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let key = address(1);
        let output = utxo(4, 13);
        let mut runtime = runtime_with_recent(
            4,
            &[],
            [
                RecentSnapshotSlot::created(key, output),
                RecentSnapshotSlot::created(key, output),
                RecentSnapshotSlot::dummy(),
                RecentSnapshotSlot::dummy(),
            ],
        )?;
        let query = UtxoQuery::new(key, 0);
        let request = request_envelope(&runtime, checkpoint(), query, None, 1)?;
        let (trace, response) = handle_and_decode(&mut runtime, &request)?;

        assert_eq!(trace.store_reads(), 4);
        assert_eq!(trace.recent_snapshot_reads(), RECENT_SNAPSHOT_SLOTS);
        assert_eq!(response.page.outcome(), QueryOutcome::ProjectionNotReady);
        assert!(response.page.is_all_dummy());
        assert!(!runtime.healthy);
        assert_eq!(
            runtime.epoch_for_tests().recent_snapshot.read_calls(),
            RECENT_SNAPSHOT_SLOTS
        );
        Ok(())
    }

    #[test]
    fn continuation_rejects_different_snapshot_contents_across_runtime_lifecycles(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let key = address(1);
        let entries = [(0, utxo(1, 10)), (1, utxo(2, 11)), (2, utxo(3, 12))];
        let query = UtxoQuery::new(key, 0);
        let mut issuer = runtime(4, &entries)?;
        let initial_request = request_envelope(&issuer, checkpoint(), query, None, 1)?;
        let (baseline, initial_response) = handle_and_decode(&mut issuer, &initial_request)?;
        let token = initial_response
            .continuation
            .expect("capped issuer page carries a continuation");

        let mut changed = runtime_with_recent(
            4,
            &entries,
            [
                RecentSnapshotSlot::created(key, utxo(4, 13)),
                RecentSnapshotSlot::dummy(),
                RecentSnapshotSlot::dummy(),
                RecentSnapshotSlot::dummy(),
            ],
        )?;
        let continued_request = request_envelope(&changed, checkpoint(), query, Some(token), 2)?;
        let (changed_trace, changed_response) =
            handle_and_decode(&mut changed, &continued_request)?;
        assert_eq!(changed_trace, baseline);
        assert_eq!(
            changed_response.page.outcome(),
            QueryOutcome::InvalidContinuation
        );
        assert!(changed_response.page.is_all_dummy());
        Ok(())
    }

    #[test]
    fn continuation_rejects_new_generation_with_identical_snapshot_contents(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let key = address(1);
        let entries = [(0, utxo(1, 10)), (1, utxo(2, 11)), (2, utxo(3, 12))];
        let query = UtxoQuery::new(key, 0);
        let mut issuer = runtime(4, &entries)?;
        let initial_request = request_envelope(&issuer, checkpoint(), query, None, 1)?;
        let (baseline, initial_response) = handle_and_decode(&mut issuer, &initial_request)?;
        let token = initial_response
            .continuation
            .expect("capped issuer page carries a continuation");

        let current = issuer.epoch_for_tests().recent_snapshot.lineage();
        let next_lineage = RecentSnapshotLineage::from_parts_for_tests(
            current
                .generation()
                .checked_add(1)
                .expect("runtime fixture generation leaves successor room"),
            current.finalized(),
            current.recent_tip_height(),
            *current.recent_tip_hash_display(),
        )?;
        let mut changed = runtime_with_snapshot_components(
            store(4, &entries)?,
            4,
            recent_snapshot_with_lineage(
                [RecentSnapshotSlot::dummy(); RECENT_SNAPSHOT_SLOTS],
                next_lineage,
            ),
            CountingReplayGuard::available(),
            DeterministicMaterialSource::at(101),
        )?;
        let continued_request = request_envelope(&changed, checkpoint(), query, Some(token), 2)?;
        let (changed_trace, changed_response) =
            handle_and_decode(&mut changed, &continued_request)?;
        assert_eq!(changed_trace, baseline);
        assert_eq!(
            changed_response.page.outcome(),
            QueryOutcome::InvalidContinuation
        );
        assert!(changed_response.page.is_all_dummy());
        Ok(())
    }

    #[test]
    fn continuation_pages_use_absolute_combined_cursors_without_duplicates(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let entries = [
            (0, utxo(1, 10)),
            (2, utxo(2, 11)),
            (4, utxo(3, 12)),
            (7, utxo(4, 13)),
            (9, utxo(5, 14)),
        ];
        let mut runtime = runtime(10, &entries)?;
        let query = UtxoQuery::new(address(1), 0);

        let first_request = request_envelope(&runtime, checkpoint(), query, None, 1)?;
        let (first_trace, first) = handle_and_decode(&mut runtime, &first_request)?;
        assert_eq!(first.page.outcome(), QueryOutcome::ResultBudgetExceeded);
        let first_token = first
            .continuation
            .clone()
            .expect("capped first page carries one fixed token");

        let second_request = request_envelope(&runtime, checkpoint(), query, Some(first_token), 2)?;
        let (second_trace, second) = handle_and_decode(&mut runtime, &second_request)?;
        assert_eq!(second.page.outcome(), QueryOutcome::ResultBudgetExceeded);
        let second_token = second
            .continuation
            .clone()
            .expect("capped second page carries one fixed token");

        let token_context = runtime
            .codec
            .continuation_protection_context(&checkpoint())?;
        let profile = *runtime.epoch_for_tests().engine.profile();
        let expectation = ContinuationExpectation::new(
            CONTINUATION_VERSION,
            &profile,
            runtime.continuation_query_digest_for_tests(&query),
            checkpoint().projection_epoch,
            102,
            14,
        );
        let inspection = ContinuationToken::inspect_optional(
            Some(&second_token),
            &CountingTokenProtector::default(),
            &token_context,
            &expectation,
            runtime.security.replay_namespace(),
            [0; ENVELOPE_NONCE_BYTES],
        );
        let security_round =
            SecurityRoundCapture::new(runtime.security.security_epoch_tag_for_tests());
        let mut replay_guard = CountingReplayGuard::available();
        let (continuation_use, replay_commit_authority) = inspection
            .finish_replay(&security_round, &mut replay_guard)
            .into_parts();
        let replay_commit_authority =
            replay_commit_authority.ok_or("fixture replay commit must return an authority")?;
        assert!(replay_commit_authority.matches(
            runtime.security.security_epoch_tag_for_tests(),
            &security_round
        ));
        assert_eq!(
            continuation_use,
            ContinuationUse::Continue {
                cursor: 9,
                expires_at_unix_seconds: 160,
            }
        );

        let third_request = request_envelope(&runtime, checkpoint(), query, Some(second_token), 3)?;
        let (third_trace, third) = handle_and_decode(&mut runtime, &third_request)?;
        assert_eq!(third.page.outcome(), QueryOutcome::Complete);
        assert!(third.continuation.is_none());
        assert_eq!(first_trace, second_trace);
        assert_eq!(first_trace, third_trace);

        let returned_txids: Vec<[u8; TXID_BYTES]> = first
            .page
            .slots()
            .iter()
            .chain(second.page.slots())
            .chain(third.page.slots())
            .filter(|slot| slot.is_occupied())
            .map(|slot| *slot.padded_utxo().txid())
            .collect();
        assert_eq!(
            returned_txids,
            vec![
                [1; TXID_BYTES],
                [2; TXID_BYTES],
                [3; TXID_BYTES],
                [4; TXID_BYTES],
                [5; TXID_BYTES]
            ]
        );
        assert_eq!(
            runtime
                .security
                .replay_guard_for_tests()
                .real_claim_attempts,
            2
        );
        Ok(())
    }

    #[test]
    fn invalid_expired_mismatched_and_replayed_tokens_finish_the_same_schedule(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let entries = [(0, utxo(1, 10)), (1, utxo(2, 11)), (2, utxo(3, 12))];
        let query = UtxoQuery::new(address(1), 0);

        let mut replay_runtime = runtime(4, &entries)?;
        let initial_request = request_envelope(&replay_runtime, checkpoint(), query, None, 1)?;
        let (_, initial) = handle_and_decode(&mut replay_runtime, &initial_request)?;
        let token = initial
            .continuation
            .clone()
            .expect("capped initial page carries a token");
        let valid_request =
            request_envelope(&replay_runtime, checkpoint(), query, Some(token.clone()), 2)?;
        let (baseline, valid) = handle_and_decode(&mut replay_runtime, &valid_request)?;
        assert_eq!(valid.page.outcome(), QueryOutcome::Complete);
        let replay_request =
            request_envelope(&replay_runtime, checkpoint(), query, Some(token.clone()), 3)?;
        let (replay_trace, replay) = handle_and_decode(&mut replay_runtime, &replay_request)?;
        assert_eq!(replay_trace, baseline);
        assert_invalid_continuation(&replay);

        let mut tampered_bytes = *token.opaque_bytes();
        tampered_bytes[17] ^= 0x80;
        let tampered = ContinuationToken::from_opaque_bytes(tampered_bytes);
        let mut tampered_runtime = runtime(4, &entries)?;
        let tampered_request =
            request_envelope(&tampered_runtime, checkpoint(), query, Some(tampered), 4)?;
        let (tampered_trace, tampered_response) =
            handle_and_decode(&mut tampered_runtime, &tampered_request)?;
        assert_eq!(tampered_trace, baseline);
        assert_invalid_continuation(&tampered_response);

        let mut expired_runtime = runtime_with_components(
            store(4, &entries)?,
            4,
            CountingReplayGuard::available(),
            DeterministicMaterialSource::at(160),
        )?;
        let expired_request = request_envelope(
            &expired_runtime,
            checkpoint(),
            query,
            Some(token.clone()),
            5,
        )?;
        let (expired_trace, expired) = handle_and_decode(&mut expired_runtime, &expired_request)?;
        assert_eq!(expired_trace, baseline);
        assert_invalid_continuation(&expired);

        let mut mismatch_runtime = runtime(4, &entries)?;
        let mismatch_request = request_envelope(
            &mismatch_runtime,
            checkpoint(),
            UtxoQuery::new(address(1), 11),
            Some(token),
            6,
        )?;
        let (mismatch_trace, mismatch) =
            handle_and_decode(&mut mismatch_runtime, &mismatch_request)?;
        assert_eq!(mismatch_trace, baseline);
        assert_invalid_continuation(&mismatch);

        let mut cursor_runtime = runtime(4, &entries)?;
        let cursor_profile = *cursor_runtime.epoch_for_tests().engine.profile();
        let cursor_state = ContinuationState::new(
            CONTINUATION_VERSION,
            *cursor_profile.profile_id(),
            cursor_runtime.continuation_query_digest_for_tests(&query),
            checkpoint().projection_epoch,
            0,
            160,
            [0x71; ENVELOPE_NONCE_BYTES],
        );
        let cursor_token = ContinuationToken::issue(
            &cursor_state,
            &cursor_runtime
                .codec
                .continuation_protection_context(&checkpoint())?,
            cursor_runtime.security.token_protector(),
        )?;
        let cursor_request =
            request_envelope(&cursor_runtime, checkpoint(), query, Some(cursor_token), 7)?;
        let (cursor_trace, cursor_response) =
            handle_and_decode(&mut cursor_runtime, &cursor_request)?;
        assert_eq!(cursor_trace, baseline);
        assert_invalid_continuation(&cursor_response);

        for (wrong_profile, wrong_epoch, nonce_byte) in [(true, false, 8_u8), (false, true, 9_u8)] {
            let mut binding_runtime = runtime(4, &entries)?;
            let binding_profile = *binding_runtime.epoch_for_tests().engine.profile();
            let mut profile_id = *binding_profile.profile_id();
            if wrong_profile {
                profile_id[0] ^= 1;
            }
            let projection_epoch = checkpoint().projection_epoch + u64::from(wrong_epoch);
            let binding_state = ContinuationState::new(
                CONTINUATION_VERSION,
                profile_id,
                binding_runtime.continuation_query_digest_for_tests(&query),
                projection_epoch,
                2,
                160,
                [nonce_byte; ENVELOPE_NONCE_BYTES],
            );
            let binding_token = ContinuationToken::issue(
                &binding_state,
                &binding_runtime
                    .codec
                    .continuation_protection_context(&checkpoint())?,
                binding_runtime.security.token_protector(),
            )?;
            let binding_request = request_envelope(
                &binding_runtime,
                checkpoint(),
                query,
                Some(binding_token),
                nonce_byte,
            )?;
            let (binding_trace, binding_response) =
                handle_and_decode(&mut binding_runtime, &binding_request)?;
            assert_eq!(binding_trace, baseline);
            assert_invalid_continuation(&binding_response);
        }
        Ok(())
    }

    fn assert_invalid_continuation(response: &PrivateQueryResponse<RESPONSE_SLOTS>) {
        assert_eq!(response.page.outcome(), QueryOutcome::InvalidContinuation);
        assert!(response.page.is_all_dummy());
        assert!(!response.has_more);
        assert!(response.continuation.is_none());
    }

    #[test]
    fn continuation_tokens_are_bound_to_the_codec_session() -> Result<(), Box<dyn std::error::Error>>
    {
        let entries = [(0, utxo(1, 10)), (2, utxo(2, 11)), (3, utxo(3, 12))];
        let query = UtxoQuery::new(address(1), 0);
        let mut issuer = runtime(4, &entries)?;
        let initial_request = request_envelope(&issuer, checkpoint(), query, None, 1)?;
        let (baseline, initial) = handle_and_decode(&mut issuer, &initial_request)?;
        let token = initial
            .continuation
            .expect("capped issuer response carries a session-bound token");

        let mut other_session = runtime_with_session_components(
            store(4, &entries)?,
            4,
            [0x33; 32],
            CountingReplayGuard::available(),
            DeterministicMaterialSource::at(101),
        )?;
        let request = request_envelope(&other_session, checkpoint(), query, Some(token), 2)?;
        let (trace, response) = handle_and_decode(&mut other_session, &request)?;

        assert_eq!(trace, baseline);
        assert_invalid_continuation(&response);
        assert_eq!(
            other_session
                .security
                .replay_guard_for_tests()
                .real_claim_attempts,
            0
        );
        Ok(())
    }

    #[test]
    fn duplicate_request_nonce_ignores_query_and_does_not_consume_continuation(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let entries = [(0, utxo(1, 10)), (2, utxo(2, 11)), (3, utxo(3, 12))];
        let continuation_query = UtxoQuery::new(address(1), 0);
        let different_query = UtxoQuery::new(address(2), 0);
        let mut runtime = runtime(4, &entries)?;

        let initial_request =
            request_envelope(&runtime, checkpoint(), continuation_query, None, 1)?;
        let (_, initial_response) = handle_and_decode(&mut runtime, &initial_request)?;
        let continuation = initial_response
            .continuation
            .expect("capped initial page carries a continuation");

        let marker_request = request_envelope(&runtime, checkpoint(), different_query, None, 2)?;
        let (_, marker_response) = handle_and_decode(&mut runtime, &marker_request)?;
        assert_eq!(marker_response.page.outcome(), QueryOutcome::Complete);

        let duplicate_request = request_envelope(
            &runtime,
            checkpoint(),
            continuation_query,
            Some(continuation.clone()),
            2,
        )?;
        let (_, duplicate_response) = handle_and_decode(&mut runtime, &duplicate_request)?;
        assert_eq!(
            duplicate_response.page.outcome(),
            QueryOutcome::ProjectionNotReady
        );
        assert!(runtime.healthy);
        let replay_guard = runtime.security.replay_guard_for_tests();
        assert_eq!(replay_guard.real_claim_attempts, 0);
        assert!(replay_guard.claimed.iter().all(Option::is_none));

        let fresh_request = request_envelope(
            &runtime,
            checkpoint(),
            continuation_query,
            Some(continuation),
            3,
        )?;
        let (_, fresh_response) = handle_and_decode(&mut runtime, &fresh_request)?;
        assert_eq!(fresh_response.page.outcome(), QueryOutcome::Complete);
        let replay_guard = runtime.security.replay_guard_for_tests();
        assert_eq!(replay_guard.real_claim_attempts, 1);
        assert_eq!(replay_guard.claimed.iter().flatten().count(), 1);
        assert_eq!(replay_guard.claimed_requests.iter().flatten().count(), 3);
        Ok(())
    }

    #[test]
    fn checkpoint_replay_guard_and_each_store_failure_are_protected_full_rounds(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let query = UtxoQuery::new(address(1), 0);
        let entries = [(0, utxo(1, 10))];
        let (baseline, _) = run_initial(&entries, query)?;

        let current = checkpoint();
        let stale_checkpoints = [
            PrivateQueryCheckpoint::new(
                super::super::PrivateNetwork::Testnet,
                current.height,
                current.block_hash_display,
                current.schema_version,
                current.projection_epoch,
                current.key_epoch,
            ),
            PrivateQueryCheckpoint::new(
                current.network,
                current.height + 1,
                current.block_hash_display,
                current.schema_version,
                current.projection_epoch,
                current.key_epoch,
            ),
            PrivateQueryCheckpoint::new(
                current.network,
                current.height,
                [0x32; 32],
                current.schema_version,
                current.projection_epoch,
                current.key_epoch,
            ),
            PrivateQueryCheckpoint::new(
                current.network,
                current.height,
                current.block_hash_display,
                current.schema_version + 1,
                current.projection_epoch,
                current.key_epoch,
            ),
            PrivateQueryCheckpoint::new(
                current.network,
                current.height,
                current.block_hash_display,
                current.schema_version,
                current.projection_epoch + 1,
                current.key_epoch,
            ),
            PrivateQueryCheckpoint::new(
                current.network,
                current.height,
                current.block_hash_display,
                current.schema_version,
                current.projection_epoch,
                current.key_epoch + 1,
            ),
        ];
        let mut stale_runtime = runtime(4, &entries)?;
        for (index, stale) in stale_checkpoints.into_iter().enumerate() {
            let nonce = u8::try_from(index + 1).expect("six checkpoint cases fit u8");
            let stale_request = request_envelope(&stale_runtime, stale, query, None, nonce)?;
            let (stale_trace, stale_response) =
                handle_and_decode(&mut stale_runtime, &stale_request)?;
            assert_eq!(stale_trace, baseline);
            assert_eq!(
                stale_response.page.outcome(),
                QueryOutcome::ProjectionNotReady
            );
            assert!(stale_response.page.is_all_dummy());
        }

        let token_entries = [(0, utxo(1, 10)), (2, utxo(2, 11)), (3, utxo(3, 12))];
        let mut issuer = runtime(4, &token_entries)?;
        let issuer_request = request_envelope(&issuer, checkpoint(), query, None, 7)?;
        let (_, issuer_response) = handle_and_decode(&mut issuer, &issuer_request)?;
        let retryable_token = issuer_response
            .continuation
            .expect("capped issuer response carries a retryable token");
        let mut unavailable_runtime = runtime_with_components(
            store(4, &token_entries)?,
            4,
            CountingReplayGuard::unavailable(),
            DeterministicMaterialSource::at(101),
        )?;
        let unavailable_request = request_envelope(
            &unavailable_runtime,
            checkpoint(),
            query,
            Some(retryable_token),
            8,
        )?;
        let unavailable_counters = RuntimeCounters::capture(&unavailable_runtime);
        assert!(matches!(
            unavailable_runtime.handle(&unavailable_request),
            Err(UniformExternalFailure)
        ));
        unavailable_counters.assert_fixed_work_before_release_failure(&unavailable_runtime);
        let replay_guard = unavailable_runtime.security.replay_guard_for_tests();
        assert_eq!(replay_guard.real_claim_attempts, 0);
        assert!(replay_guard.claimed_requests.iter().all(Option::is_none));
        assert!(replay_guard.claimed.iter().all(Option::is_none));
        assert!(!unavailable_runtime.healthy);
        let unavailable_after_failure = RuntimeCounters::capture(&unavailable_runtime);
        unavailable_runtime
            .security
            .replay_guard_mut_for_tests()
            .available = true;
        assert!(matches!(
            unavailable_runtime.handle(&unavailable_request),
            Err(UniformExternalFailure)
        ));
        assert_eq!(
            RuntimeCounters::capture(&unavailable_runtime),
            unavailable_after_failure
        );

        for failing_ordinal in 1..=4 {
            let failing_store = store(4, &entries)?.with_failure_on_read(failing_ordinal);
            let mut failing_runtime = runtime_with_components(
                failing_store,
                4,
                CountingReplayGuard::available(),
                DeterministicMaterialSource::at(100),
            )?;
            let request = request_envelope(&failing_runtime, checkpoint(), query, None, 3)?;
            let (trace, response) = handle_and_decode(&mut failing_runtime, &request)?;
            assert_eq!(trace, baseline);
            assert_eq!(response.page.outcome(), QueryOutcome::StoreFailure);
            assert!(response.page.is_all_dummy());
            assert!(!failing_runtime.healthy);
        }
        Ok(())
    }

    #[test]
    fn each_recent_snapshot_failure_completes_fixed_work_and_latches_readiness(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let query = UtxoQuery::new(address(1), 0);
        let entries = [(0, utxo(1, 10))];
        let (baseline, _) = run_initial(&entries, query)?;
        let recent_slots = [
            RecentSnapshotSlot::created(address(1), utxo(2, 11)),
            RecentSnapshotSlot::dummy(),
            RecentSnapshotSlot::dummy(),
            RecentSnapshotSlot::dummy(),
        ];

        for failing_ordinal in 0..RECENT_SNAPSHOT_SLOTS {
            let recent_snapshot = FrozenRecentSnapshot::failing(
                recent_snapshot_lineage(recent_snapshot_identity(&checkpoint())),
                recent_slots,
                failing_ordinal,
            );
            let mut runtime = runtime_with_snapshot_components(
                store(4, &entries)?,
                4,
                recent_snapshot,
                CountingReplayGuard::available(),
                DeterministicMaterialSource::at(100),
            )?;

            let request = request_envelope(&runtime, checkpoint(), query, None, 1)?;
            let (trace, response) = handle_and_decode(&mut runtime, &request)?;
            assert_eq!(trace, baseline);
            assert_eq!(response.page.outcome(), QueryOutcome::ProjectionNotReady);
            assert!(response.page.is_all_dummy());
            assert!(!runtime.healthy);

            let rejected = request_envelope(&runtime, checkpoint(), query, None, 2)?;
            let counters = RuntimeCounters::capture(&runtime);
            assert!(matches!(
                runtime.handle(&rejected),
                Err(UniformExternalFailure)
            ));
            assert_eq!(RuntimeCounters::capture(&runtime), counters);
            assert_eq!(
                runtime.epoch_for_tests().recent_snapshot.read_calls(),
                RECENT_SNAPSHOT_SLOTS
            );
            assert_eq!(finalized_store_reads(&runtime), 4);
        }

        let recent_snapshot = FrozenRecentSnapshot::failing(
            recent_snapshot_lineage(recent_snapshot_identity(&checkpoint())),
            recent_slots,
            0,
        );
        let mut both_fail = runtime_with_snapshot_components(
            store(4, &entries)?.with_failure_on_read(1),
            4,
            recent_snapshot,
            CountingReplayGuard::available(),
            DeterministicMaterialSource::at(100),
        )?;
        let request = request_envelope(&both_fail, checkpoint(), query, None, 3)?;
        let (trace, response) = handle_and_decode(&mut both_fail, &request)?;
        assert_eq!(trace, baseline);
        assert_eq!(response.page.outcome(), QueryOutcome::StoreFailure);
        assert!(response.page.is_all_dummy());
        Ok(())
    }

    #[test]
    fn runtime_rejects_lease_bound_to_different_replay_policy(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let profile_a = test_profile_with_recent_snapshot(
            "runtime-replay-policy",
            4,
            RECENT_SNAPSHOT_SLOTS,
            RESPONSE_SLOTS,
            ENVELOPE_BYTES,
            3,
            TOKEN_TTL_SECONDS,
        )?;
        let replay_policy_a = profile_a.replay_policy();
        let profile_b = profile_a.with_test_replay_policy(
            replay_policy_a
                .transaction_capacity()
                .checked_add(1)
                .expect("fixture replay capacity leaves increment headroom"),
            replay_policy_a.expiry_bucket_width_seconds(),
            replay_policy_a.garbage_collection_interval_seconds(),
        )?;
        assert_ne!(
            profile_a.replay_policy().transaction_capacity(),
            profile_b.replay_policy().transaction_capacity()
        );
        assert_eq!(
            profile_a.replay_policy().expiry_bucket_width_seconds(),
            profile_b.replay_policy().expiry_bucket_width_seconds()
        );
        assert_eq!(
            profile_a
                .replay_policy()
                .garbage_collection_interval_seconds(),
            profile_b
                .replay_policy()
                .garbage_collection_interval_seconds()
        );
        let shape_a = CompiledQueryShape::new(profile_a)?;
        let shape_b = CompiledQueryShape::new(profile_b)?;
        assert_ne!(
            shape_a.profile().profile_id(),
            shape_b.profile().profile_id()
        );
        let security_lease = fixture_security_lease(
            shape_a,
            CountingReplayGuard::available(),
            DeterministicMaterialSource::at(100),
        )?;

        let runtime = TestRuntime::without_epoch(shape_b, security_lease);

        assert!(matches!(runtime, Err(UniformExternalFailure)));
        Ok(())
    }

    #[test]
    fn runtime_rejects_snapshot_shape_and_checkpoint_identity_mismatches(
    ) -> Result<(), Box<dyn std::error::Error>> {
        type ThreeSlotRuntime = PrivateQueryRuntime<
            PlaintextMockStore,
            DeterministicEnvelopeProtector,
            CountingTokenProtector,
            CountingReplayGuard,
            DeterministicMaterialSource,
            DeterministicServingEpochCurrentness,
            TestBoundary,
            RESPONSE_SLOTS,
            ENVELOPE_BYTES,
            3,
        >;

        let profile = test_profile_with_recent_snapshot(
            "runtime-test-v1",
            4,
            RECENT_SNAPSHOT_SLOTS,
            RESPONSE_SLOTS,
            ENVELOPE_BYTES,
            3,
            TOKEN_TTL_SECONDS,
        )?;
        let shape = CompiledQueryShape::new(profile)?;
        let shape_mismatch_epoch = serving_epoch(
            FrozenRecentSnapshot::from_parts_for_tests(
                recent_snapshot_lineage(recent_snapshot_identity(&checkpoint())),
                [RecentSnapshotSlot::dummy(); 3],
            ),
            store(4, &[])?,
        );
        let shape_mismatch = ThreeSlotRuntime::new(
            shape_mismatch_epoch,
            shape,
            checkpoint(),
            fixture_security_lease(
                shape,
                CountingReplayGuard::available(),
                DeterministicMaterialSource::at(100),
            )?,
        );
        assert!(matches!(shape_mismatch, Err(UniformExternalFailure)));

        let current = checkpoint();
        let mismatched_identities = [
            RecentSnapshotIdentity::new(
                current.network.tag() ^ 1,
                current.height,
                current.block_hash_display,
                current.schema_version,
                current.projection_epoch,
                current.key_epoch,
            ),
            RecentSnapshotIdentity::new(
                current.network.tag(),
                current.height + 1,
                current.block_hash_display,
                current.schema_version,
                current.projection_epoch,
                current.key_epoch,
            ),
            RecentSnapshotIdentity::new(
                current.network.tag(),
                current.height,
                [0x32; 32],
                current.schema_version,
                current.projection_epoch,
                current.key_epoch,
            ),
            RecentSnapshotIdentity::new(
                current.network.tag(),
                current.height,
                current.block_hash_display,
                current.schema_version + 1,
                current.projection_epoch,
                current.key_epoch,
            ),
            RecentSnapshotIdentity::new(
                current.network.tag(),
                current.height,
                current.block_hash_display,
                current.schema_version,
                current.projection_epoch + 1,
                current.key_epoch,
            ),
            RecentSnapshotIdentity::new(
                current.network.tag(),
                current.height,
                current.block_hash_display,
                current.schema_version,
                current.projection_epoch,
                current.key_epoch + 1,
            ),
        ];
        for mismatched_identity in mismatched_identities {
            let profile = test_profile_with_recent_snapshot(
                "runtime-test-v1",
                4,
                RECENT_SNAPSHOT_SLOTS,
                RESPONSE_SLOTS,
                ENVELOPE_BYTES,
                3,
                TOKEN_TTL_SECONDS,
            )?;
            let identity_mismatch_epoch = serving_epoch(
                FrozenRecentSnapshot::from_parts_for_tests(
                    recent_snapshot_lineage(mismatched_identity),
                    [RecentSnapshotSlot::dummy(); RECENT_SNAPSHOT_SLOTS],
                ),
                store(4, &[])?,
            );
            let shape = CompiledQueryShape::new(profile)?;
            let identity_mismatch = TestRuntime::new(
                identity_mismatch_epoch,
                shape,
                current,
                fixture_security_lease(
                    shape,
                    CountingReplayGuard::available(),
                    DeterministicMaterialSource::at(100),
                )?,
            );
            assert!(matches!(identity_mismatch, Err(UniformExternalFailure)));
        }
        Ok(())
    }

    #[test]
    fn readiness_precedence_and_claim_commit_survive_downstream_failure_and_latch(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let entries = [(0, utxo(1, 10)), (2, utxo(2, 11)), (3, utxo(3, 12))];
        let query = UtxoQuery::new(address(1), 0);
        let mut issuer = runtime(4, &entries)?;
        let initial_request = request_envelope(&issuer, checkpoint(), query, None, 1)?;
        let (baseline, initial) = handle_and_decode(&mut issuer, &initial_request)?;
        let token = initial
            .continuation
            .expect("capped issuer response carries a retryable token");
        let mut tampered_bytes = *token.opaque_bytes();
        tampered_bytes[17] ^= 0x80;
        let tampered = ContinuationToken::from_opaque_bytes(tampered_bytes);

        let mut failing = runtime_with_components(
            store(4, &entries)?.with_failure_on_read(1),
            4,
            CountingReplayGuard::available(),
            DeterministicMaterialSource::at(101),
        )?;
        let invalid_failure_request =
            request_envelope(&failing, checkpoint(), query, Some(tampered.clone()), 2)?;
        let (invalid_failure_trace, invalid_failure) =
            handle_and_decode(&mut failing, &invalid_failure_request)?;
        assert_eq!(invalid_failure_trace, baseline);
        assert_eq!(invalid_failure.page.outcome(), QueryOutcome::StoreFailure);

        let mut stale = checkpoint();
        stale.height += 1;
        let mut stale_runtime = runtime(4, &entries)?;
        let stale_request = request_envelope(&stale_runtime, stale, query, Some(tampered), 3)?;
        let (stale_trace, stale_response) = handle_and_decode(&mut stale_runtime, &stale_request)?;
        assert_eq!(stale_trace, baseline);
        assert_eq!(
            stale_response.page.outcome(),
            QueryOutcome::ProjectionNotReady
        );

        let mut claimed_then_failed = runtime_with_components(
            store(4, &entries)?.with_failure_on_read(1),
            4,
            CountingReplayGuard::available(),
            DeterministicMaterialSource::at(101),
        )?;
        let request = request_envelope(
            &claimed_then_failed,
            checkpoint(),
            query,
            Some(token.clone()),
            4,
        )?;
        let (trace, response) = handle_and_decode(&mut claimed_then_failed, &request)?;
        assert_eq!(trace, baseline);
        assert_eq!(response.page.outcome(), QueryOutcome::StoreFailure);
        assert_eq!(
            claimed_then_failed
                .security
                .replay_guard_for_tests()
                .real_claim_attempts,
            1
        );
        assert_eq!(
            claimed_then_failed
                .security
                .replay_guard_for_tests()
                .claimed
                .iter()
                .flatten()
                .count(),
            1
        );

        let rejected = request_envelope(&claimed_then_failed, checkpoint(), query, Some(token), 5)?;
        let counters = RuntimeCounters::capture(&claimed_then_failed);
        assert!(matches!(
            claimed_then_failed.handle(&rejected),
            Err(UniformExternalFailure)
        ));
        assert_eq!(RuntimeCounters::capture(&claimed_then_failed), counters);
        Ok(())
    }

    #[test]
    fn envelope_open_unavailability_latches_before_private_work(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut runtime = runtime(4, &[(0, utxo(1, 10))])?;
        let request = request_envelope(
            &runtime,
            checkpoint(),
            UtxoQuery::new(address(1), 0),
            None,
            1,
        )?;
        let counters = RuntimeCounters::capture(&runtime);
        runtime
            .security
            .envelope_protector()
            .make_open_unavailable();

        let failure = uniform_failure(runtime.handle(&request));

        assert_eq!(failure.to_string(), "private query failed");
        assert_eq!(
            runtime.security.envelope_protector().opens.get() - counters.envelope_opens,
            1
        );
        assert_eq!(
            runtime.security.envelope_protector().seals.get() - counters.envelope_seals,
            0
        );
        assert_eq!(
            runtime.security.token_protector().opens.get() - counters.token_opens,
            0
        );
        assert_eq!(
            runtime.security.token_protector().seals.get() - counters.token_seals,
            0
        );
        assert_eq!(
            runtime.security.replay_guard_for_tests().calls - counters.replay_calls,
            0
        );
        assert_eq!(
            runtime.security.material_source_for_tests().calls - counters.material_calls,
            0
        );
        assert_eq!(
            runtime.epoch_for_tests().recent_snapshot.read_calls() - counters.recent_snapshot_reads,
            0
        );
        assert_eq!(finalized_store_reads(&runtime) - counters.store_reads, 0);
        assert_eq!(
            serving_epoch_observations(&runtime) - counters.serving_epoch_observations,
            0
        );
        assert!(!runtime.healthy);
        Ok(())
    }

    #[test]
    fn token_open_unavailability_completes_fixed_work_and_withholds_round(
    ) -> Result<(), Box<dyn std::error::Error>> {
        assert_protection_failure_completes_fixed_work(&[(0, utxo(1, 10))], |runtime| {
            runtime.security.token_protector().make_open_unavailable()
        })
    }

    #[test]
    fn token_seal_unavailability_completes_capped_fixed_work_and_withholds_round(
    ) -> Result<(), Box<dyn std::error::Error>> {
        assert_protection_failure_completes_fixed_work(
            &[(0, utxo(1, 10)), (1, utxo(2, 11)), (2, utxo(3, 12))],
            |runtime| runtime.security.token_protector().make_seal_unavailable(),
        )
    }

    #[test]
    fn envelope_seal_unavailability_completes_fixed_work_and_withholds_round(
    ) -> Result<(), Box<dyn std::error::Error>> {
        assert_protection_failure_completes_fixed_work(&[(0, utxo(1, 10))], |runtime| {
            runtime
                .security
                .envelope_protector()
                .make_seal_unavailable()
        })
    }

    #[test]
    fn material_failure_precedes_replay_claim_and_outer_failures_are_uniform(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let entries = [(0, utxo(1, 10)), (1, utxo(2, 11)), (2, utxo(3, 12))];
        let query = UtxoQuery::new(address(1), 0);
        let mut issuer = runtime(4, &entries)?;
        let initial_request = request_envelope(&issuer, checkpoint(), query, None, 1)?;
        let (_, initial_response) = handle_and_decode(&mut issuer, &initial_request)?;
        let retryable_token = initial_response
            .continuation
            .expect("capped issuer response carries a retryable token");

        let mut failing_runtime = runtime_with_components(
            store(4, &entries)?,
            4,
            CountingReplayGuard::available(),
            DeterministicMaterialSource::failing(100),
        )?;
        let request = request_envelope(
            &failing_runtime,
            checkpoint(),
            query,
            Some(retryable_token),
            2,
        )?;
        let failure = match failing_runtime.handle(&request) {
            Ok(_) => panic!("material failure cannot produce a protected response"),
            Err(failure) => failure,
        };
        assert_eq!(failure.to_string(), "private query failed");
        assert_eq!(
            failing_runtime.security.material_source_for_tests().calls,
            1
        );
        let replay_guard = failing_runtime.security.replay_guard_for_tests();
        assert_eq!(replay_guard.calls, 0);
        assert_eq!(replay_guard.real_claim_attempts, 0);
        assert_eq!(replay_guard.logical_reads, 0);
        assert_eq!(replay_guard.logical_writes, 0);
        assert_eq!(failing_runtime.security.token_protector().opens.get(), 0);
        assert_eq!(failing_runtime.security.token_protector().seals.get(), 0);
        assert!(!failing_runtime.healthy);

        let mut malformed_runtime = runtime(4, &[])?;
        let valid = request_envelope(
            &malformed_runtime,
            checkpoint(),
            UtxoQuery::new(address(1), 0),
            None,
            2,
        )?;
        let mut tampered = *valid.as_bytes();
        tampered[ENVELOPE_NONCE_BYTES + 3] ^= 0x80;
        let failure = match malformed_runtime.handle(&FixedEnvelope::from_array(tampered)) {
            Ok(_) => panic!("unauthenticated envelope cannot enter private work"),
            Err(failure) => failure,
        };
        assert_eq!(failure.to_string(), "private query failed");
        assert_eq!(
            malformed_runtime.security.material_source_for_tests().calls,
            0
        );
        assert_eq!(malformed_runtime.security.replay_guard_for_tests().calls, 0);
        assert!(malformed_runtime.healthy);

        let mut noncanonical_runtime = runtime(4, &[])?;
        let canonical = request_envelope(
            &noncanonical_runtime,
            checkpoint(),
            UtxoQuery::new(address(1), 0),
            None,
            3,
        )?;
        let mut bytes = *canonical.as_bytes();
        let (nonce, body, authentication) = super::super::split_envelope_mut(&mut bytes)?;
        body[super::super::REQUEST_FLAGS_START] = 0x80;
        *authentication = noncanonical_runtime.security.envelope_protector().seal(
            &noncanonical_runtime
                .codec
                .protection_context(super::super::EnvelopeDirection::Request),
            nonce,
            body,
        )?;
        let failure = match noncanonical_runtime.handle(&FixedEnvelope::from_array(bytes)) {
            Ok(_) => panic!("authenticated noncanonical envelope cannot enter private work"),
            Err(failure) => failure,
        };
        assert_eq!(failure.to_string(), "private query failed");
        assert_eq!(
            noncanonical_runtime
                .security
                .material_source_for_tests()
                .calls,
            0
        );
        assert_eq!(
            noncanonical_runtime.security.replay_guard_for_tests().calls,
            0
        );
        assert!(noncanonical_runtime.healthy);
        Ok(())
    }

    #[test]
    fn runtime_debug_surfaces_redact_private_material() {
        let security_epoch = SecurityEpochTag::new(SECURITY_EPOCH_BINDING);
        let security_round = SecurityRoundCapture::new(&security_epoch);
        let response_nonce = [0x44; ENVELOPE_NONCE_BYTES];
        let token_nonce = [0x55; ENVELOPE_NONCE_BYTES];
        let reservation_authority =
            RoundReservationAuthority::new(&security_round, 123_456, response_nonce, token_nonce);
        let material = RoundMaterial::new(
            123_456,
            response_nonce,
            token_nonce,
            security_round,
            reservation_authority,
        );
        let context = runtime(4, &[])
            .expect("test runtime profile is valid")
            .codec
            .continuation_protection_context(&checkpoint())
            .expect("fixed checkpoint encoding fits its exact context");
        assert_eq!(format!("{material:?}"), "RoundMaterial { ..REDACTED.. }");
        assert_eq!(
            format!("{context:?}"),
            "ContinuationProtectionContext { ..REDACTED.. }"
        );
        assert_eq!(
            format!("{:?}", UniformExternalFailure),
            "UniformExternalFailure"
        );
    }
}
