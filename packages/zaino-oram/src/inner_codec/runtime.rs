//! Listener-free composition of the fixed codec, token controller, engine, and
//! logical phase recorder.
//!
//! This module proves only a deterministic source-level logical schedule for
//! the injected research fixtures. It does not provide a production nonce
//! source, trusted clock, replay database, AEAD, listener, transport, physical
//! ORAM trace, timing result, or TDX claim.

use crate::{
    continuation_token::{
        ContinuationExpectation, ContinuationReplayGuard, ContinuationState, ContinuationToken,
        ContinuationTokenProtector, ContinuationUse, CONTINUATION_VERSION,
    },
    engine::PrivateQueryEngine,
    envelope::FixedEnvelope,
    profile::CompiledQueryShape,
    recent_snapshot::{
        bind_query_digest, content_digest, FrozenRecentSnapshot, RecentSnapshotIdentity,
        RecentSnapshotSlot,
    },
    records::{QueryOutcome, UtxoResultPage},
    store::ObliviousStore,
    trace::{AccessTrace, CompletionShape, RuntimePhase, TraceRecorder},
};

use super::{
    EnvelopeProtector, InnerCodecError, PrivateQueryCheckpoint, PrivateQueryCodec,
    PrivateQueryResponse, UniformExternalFailure, ENVELOPE_NONCE_BYTES,
};

/// Server-owned material acquired once before any real continuation claim.
#[derive(Clone, Copy)]
struct RoundMaterial {
    now_unix_seconds: u64,
    response_nonce: [u8; ENVELOPE_NONCE_BYTES],
    token_nonce: [u8; ENVELOPE_NONCE_BYTES],
}

impl RoundMaterial {
    const fn new(
        now_unix_seconds: u64,
        response_nonce: [u8; ENVELOPE_NONCE_BYTES],
        token_nonce: [u8; ENVELOPE_NONCE_BYTES],
    ) -> Self {
        Self {
            now_unix_seconds,
            response_nonce,
            token_nonce,
        }
    }
}

impl std::fmt::Debug for RoundMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RoundMaterial { ..REDACTED.. }")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RoundMaterialUnavailable;

/// Injected trusted-clock and domain-separated nonce owner.
trait RoundMaterialSource {
    fn next_round_material(&mut self) -> Result<RoundMaterial, RoundMaterialUnavailable>;
}

/// One completed protected envelope and its key-free logical trace.
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

/// Injected protection, replay, clock, and nonce dependencies.
struct RuntimeDependencies<E, T, R, N> {
    envelope_protector: E,
    token_protector: T,
    replay_guard: R,
    material_source: N,
}

impl<E, T, R, N> RuntimeDependencies<E, T, R, N> {
    const fn new(
        envelope_protector: E,
        token_protector: T,
        replay_guard: R,
        material_source: N,
    ) -> Self {
        Self {
            envelope_protector,
            token_protector,
            replay_guard,
            material_source,
        }
    }
}

/// Private synchronous adapter for one compiled logical research profile.
struct PrivateQueryRuntime<
    S,
    E,
    T,
    R,
    N,
    const RESPONSE_SLOTS: usize,
    const ENVELOPE_BYTES: usize,
    const RECENT_SNAPSHOT_SLOTS: usize,
> {
    codec: PrivateQueryCodec<RESPONSE_SLOTS, ENVELOPE_BYTES>,
    engine: PrivateQueryEngine<S, RESPONSE_SLOTS, ENVELOPE_BYTES>,
    recent_snapshot: FrozenRecentSnapshot<RECENT_SNAPSHOT_SLOTS>,
    recent_snapshot_digest: [u8; 32],
    envelope_protector: E,
    token_protector: T,
    replay_guard: R,
    material_source: N,
    checkpoint: PrivateQueryCheckpoint,
    healthy: bool,
}

impl<
        S,
        E,
        T,
        R,
        N,
        const RESPONSE_SLOTS: usize,
        const ENVELOPE_BYTES: usize,
        const RECENT_SNAPSHOT_SLOTS: usize,
    > PrivateQueryRuntime<S, E, T, R, N, RESPONSE_SLOTS, ENVELOPE_BYTES, RECENT_SNAPSHOT_SLOTS>
where
    S: ObliviousStore,
    E: EnvelopeProtector,
    T: ContinuationTokenProtector,
    R: ContinuationReplayGuard,
    N: RoundMaterialSource,
{
    fn new(
        store: S,
        recent_snapshot: FrozenRecentSnapshot<RECENT_SNAPSHOT_SLOTS>,
        shape: CompiledQueryShape<RESPONSE_SLOTS, ENVELOPE_BYTES>,
        session_binding: [u8; 32],
        checkpoint: PrivateQueryCheckpoint,
        dependencies: RuntimeDependencies<E, T, R, N>,
    ) -> Result<Self, UniformExternalFailure> {
        shape
            .profile()
            .validate_recent_snapshot_slots::<RECENT_SNAPSHOT_SLOTS>()
            .map_err(|_| UniformExternalFailure)?;
        if recent_snapshot.slots() != RECENT_SNAPSHOT_SLOTS
            || recent_snapshot.identity() != recent_snapshot_identity(&checkpoint)
        {
            return Err(UniformExternalFailure);
        }
        let recent_snapshot_digest = recent_snapshot.content_digest();
        let combined_scan_slots = shape
            .profile()
            .combined_scan_slots()
            .map_err(|_| UniformExternalFailure)?;
        u64::try_from(combined_scan_slots).map_err(|_| UniformExternalFailure)?;
        let codec = PrivateQueryCodec::new(&shape, session_binding)
            .map_err(InnerCodecError::into_uniform_external_failure)?;
        let engine = PrivateQueryEngine::new(store, shape).map_err(|_| UniformExternalFailure)?;
        Ok(Self {
            codec,
            engine,
            recent_snapshot,
            recent_snapshot_digest,
            envelope_protector: dependencies.envelope_protector,
            token_protector: dependencies.token_protector,
            replay_guard: dependencies.replay_guard,
            material_source: dependencies.material_source,
            checkpoint,
            healthy: true,
        })
    }

    /// Handles one fixed request without owning any listener or transport.
    fn handle(
        &mut self,
        envelope: &FixedEnvelope<ENVELOPE_BYTES>,
    ) -> Result<RuntimeRound<ENVELOPE_BYTES>, UniformExternalFailure> {
        let (request, request_nonce) = self
            .codec
            .decode_request_with_nonce(envelope, &self.envelope_protector)
            .map_err(InnerCodecError::into_uniform_external_failure)?;

        let profile = *self.engine.profile();
        let mut trace = TraceRecorder::new();
        trace
            .record_request_frame(ENVELOPE_BYTES)
            .map_err(|_| self.latch_failure())?;
        trace
            .record_runtime_phase(RuntimePhase::RequestDecode)
            .map_err(|_| self.latch_failure())?;

        let material = self
            .material_source
            .next_round_material()
            .map_err(|_| self.latch_failure())?;
        trace
            .record_runtime_phase(RuntimePhase::NonceAcquisition)
            .map_err(|_| self.latch_failure())?;

        let query_digest = self.continuation_query_digest(request.query());
        let cursor_limit = u64::try_from(
            profile
                .combined_scan_slots()
                .map_err(|_| self.latch_failure())?,
        )
        .map_err(|_| self.latch_failure())?;
        let initial_expiry = material
            .now_unix_seconds
            .checked_add(profile.continuation_ttl_seconds())
            .ok_or_else(|| self.latch_failure())?;
        let token_context = self
            .codec
            .continuation_protection_context(&self.checkpoint)
            .map_err(|error| {
                self.healthy = false;
                error.into_uniform_external_failure()
            })?;
        let expectation = ContinuationExpectation::new(
            CONTINUATION_VERSION,
            *profile.profile_id(),
            query_digest,
            self.checkpoint.projection_epoch,
            material.now_unix_seconds,
            cursor_limit,
        );
        let inspection = ContinuationToken::inspect_optional(
            request.continuation.as_ref(),
            &self.token_protector,
            &token_context,
            &expectation,
            request_nonce,
        );
        trace
            .record_runtime_phase(RuntimePhase::TokenOpen)
            .map_err(|_| self.latch_failure())?;

        let continuation_use = inspection.claim_or_cover(&mut self.replay_guard);
        trace
            .record_replay_access()
            .map_err(|_| self.latch_failure())?;
        trace
            .record_runtime_phase(RuntimePhase::ReplayGuard)
            .map_err(|_| self.latch_failure())?;

        let was_healthy = self.healthy;
        let checkpoint_matches = request.checkpoint == self.checkpoint;
        let (cursor, continuation_expiry, invalid_continuation, replay_unavailable) =
            match continuation_use {
                ContinuationUse::Initial => (0, initial_expiry, false, false),
                ContinuationUse::Continue {
                    cursor,
                    expires_at_unix_seconds,
                } => (
                    usize::try_from(cursor).map_err(|_| self.latch_failure())?,
                    expires_at_unix_seconds,
                    false,
                    false,
                ),
                ContinuationUse::InvalidContinuation => (0, initial_expiry, true, false),
                ContinuationUse::ProjectionNotReady => (0, initial_expiry, false, true),
            };
        if replay_unavailable {
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
            match self.recent_snapshot.read_slot(ordinal) {
                Ok(slot) => *destination = slot,
                Err(_) => recent_snapshot_failed = true,
            }
        }
        trace
            .complete_recent_snapshot_scan(RECENT_SNAPSHOT_SLOTS)
            .map_err(|_| self.latch_failure())?;
        if self.recent_snapshot.slots() != RECENT_SNAPSHOT_SLOTS
            || self.recent_snapshot.identity() != recent_snapshot_identity(&self.checkpoint)
            || content_digest(&recent_snapshot) != self.recent_snapshot_digest
        {
            recent_snapshot_failed = true;
        }

        let execution = self
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
            || replay_unavailable
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
            self.checkpoint.projection_epoch,
            issue_cursor,
            continuation_expiry,
            material.token_nonce,
        );
        let issued = ContinuationToken::issue(&issue_state, &token_context, &self.token_protector);
        trace
            .record_runtime_phase(RuntimePhase::TokenIssue)
            .map_err(|_| self.latch_failure())?;

        let has_more = protected_outcome == QueryOutcome::ResultBudgetExceeded;
        let continuation = if has_more { Some(issued) } else { None };
        let response = PrivateQueryResponse::new(self.checkpoint, page, has_more, continuation)
            .map_err(|error| {
                self.healthy = false;
                error.into_uniform_external_failure()
            })?;
        let envelope = self
            .codec
            .encode_response(&response, material.response_nonce, &self.envelope_protector)
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
        Ok(RuntimeRound { envelope, trace })
    }

    fn latch_failure(&mut self) -> UniformExternalFailure {
        self.healthy = false;
        UniformExternalFailure
    }

    fn continuation_query_digest(&self, query: &crate::records::UtxoQuery) -> [u8; 32] {
        bind_query_digest(self.codec.query_digest(query), self.recent_snapshot_digest)
    }
}

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
    use std::cell::Cell;

    use super::*;
    use crate::{
        continuation_token::{ContinuationProtectionContext, ReplayBinding, ReplayGuardError},
        profile::test_profile_with_recent_snapshot,
        recent_snapshot::{FrozenRecentSnapshot, RecentSnapshotSlot},
        records::{AddressKey, TransparentUtxo, UtxoQuery, ADDRESS_KEY_BYTES, TXID_BYTES},
        store::{PlaintextMockStore, PlaintextMockStoreError},
        trace::RuntimePhase,
    };

    const RESPONSE_SLOTS: usize = 2;
    const ENVELOPE_BYTES: usize = 512;
    const SESSION_BINDING: [u8; 32] = [0x22; 32];
    const TOKEN_TTL_SECONDS: u64 = 60;
    const BLOCK_HASH_DISPLAY: [u8; 32] = [0x31; 32];
    const RECENT_SNAPSHOT_SLOTS: usize = 4;

    type TestRecentSnapshot = FrozenRecentSnapshot<RECENT_SNAPSHOT_SLOTS>;

    type TestRuntime = PrivateQueryRuntime<
        PlaintextMockStore,
        DeterministicEnvelopeProtector,
        CountingTokenProtector,
        CountingReplayGuard,
        DeterministicMaterialSource,
        RESPONSE_SLOTS,
        ENVELOPE_BYTES,
        RECENT_SNAPSHOT_SLOTS,
    >;

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
    }

    impl DeterministicEnvelopeProtector {
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
        ) -> [u8; 16] {
            self.seals.set(self.seals.get() + 1);
            self.authentication(context, nonce, body)
        }

        fn open(
            &self,
            context: &super::super::EnvelopeProtectionContext,
            nonce: &[u8; ENVELOPE_NONCE_BYTES],
            body: &mut [u8],
            authentication: &[u8; 16],
        ) -> bool {
            self.opens.set(self.opens.get() + 1);
            constant_time_equal(&self.authentication(context, nonce, body), authentication)
        }
    }

    #[derive(Default)]
    struct CountingTokenProtector {
        opens: Cell<usize>,
        seals: Cell<usize>,
    }

    impl CountingTokenProtector {
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
        ) -> [u8; 16] {
            self.seals.set(self.seals.get() + 1);
            self.authentication(context, nonce, body)
        }

        fn open(
            &self,
            context: &ContinuationProtectionContext,
            nonce: &[u8; ENVELOPE_NONCE_BYTES],
            body: &mut [u8; 88],
            authentication: &[u8; 16],
        ) -> bool {
            self.opens.set(self.opens.get() + 1);
            constant_time_equal(&self.authentication(context, nonce, body), authentication)
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
        claimed: [Option<ReplayBinding>; 16],
        cover_slot: Option<ReplayBinding>,
        calls: usize,
        real_claim_attempts: usize,
        logical_reads: usize,
        logical_writes: usize,
        available: bool,
    }

    impl CountingReplayGuard {
        fn available() -> Self {
            Self {
                claimed: [None; 16],
                cover_slot: None,
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
        fn claim_or_cover(
            &mut self,
            binding: &ReplayBinding,
            claim: bool,
        ) -> Result<(), ReplayGuardError> {
            self.calls += 1;
            self.logical_reads += 1;
            if claim {
                self.real_claim_attempts += 1;
            }
            let mut already_claimed = false;
            let mut first_vacant = None;
            for (index, candidate) in self.claimed.iter().enumerate() {
                if candidate.as_ref() == Some(binding) {
                    already_claimed = true;
                }
                if candidate.is_none() && first_vacant.is_none() {
                    first_vacant = Some(index);
                }
            }
            if !self.available {
                self.cover_slot = Some(*binding);
                self.logical_writes += 1;
                return Err(ReplayGuardError::Unavailable);
            }
            if claim {
                if already_claimed {
                    self.cover_slot = Some(*binding);
                    self.logical_writes += 1;
                    return Err(ReplayGuardError::AlreadyClaimed);
                }
                let Some(vacant) = first_vacant else {
                    self.cover_slot = Some(*binding);
                    self.logical_writes += 1;
                    return Err(ReplayGuardError::Unavailable);
                };
                self.claimed[vacant] = Some(*binding);
            } else {
                self.cover_slot = Some(*binding);
            }
            self.logical_writes += 1;
            Ok(())
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
        fn next_round_material(&mut self) -> Result<RoundMaterial, RoundMaterialUnavailable> {
            self.calls += 1;
            if self.fail_next {
                self.fail_next = false;
                return Err(RoundMaterialUnavailable);
            }
            let ordinal = u8::try_from(self.calls).map_err(|_| RoundMaterialUnavailable)?;
            let material = RoundMaterial::new(
                self.now_unix_seconds,
                [ordinal.wrapping_add(0x80); ENVELOPE_NONCE_BYTES],
                [ordinal.wrapping_add(0x40); ENVELOPE_NONCE_BYTES],
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
        runtime_with_session_components(
            store,
            store_reads,
            SESSION_BINDING,
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
        runtime_with_snapshot_components(
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
        session_binding: [u8; 32],
        replay_guard: CountingReplayGuard,
        material_source: DeterministicMaterialSource,
    ) -> Result<TestRuntime, Box<dyn std::error::Error>> {
        let profile = test_profile_with_recent_snapshot(
            "runtime-test-v1",
            store_reads,
            RECENT_SNAPSHOT_SLOTS,
            RESPONSE_SLOTS,
            ENVELOPE_BYTES,
            3,
            TOKEN_TTL_SECONDS,
        )?;
        let shape = CompiledQueryShape::new(profile)?;
        Ok(TestRuntime::new(
            store,
            recent_snapshot,
            shape,
            session_binding,
            checkpoint(),
            RuntimeDependencies::new(
                DeterministicEnvelopeProtector::default(),
                CountingTokenProtector::default(),
                replay_guard,
                material_source,
            ),
        )?)
    }

    fn empty_recent_snapshot() -> TestRecentSnapshot {
        recent_snapshot([RecentSnapshotSlot::dummy(); RECENT_SNAPSHOT_SLOTS])
    }

    fn recent_snapshot(slots: [RecentSnapshotSlot; RECENT_SNAPSHOT_SLOTS]) -> TestRecentSnapshot {
        FrozenRecentSnapshot::new(recent_snapshot_identity(&checkpoint()), slots)
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
            SESSION_BINDING,
            CountingReplayGuard::available(),
            DeterministicMaterialSource::at(100),
        )
    }

    fn request_envelope(
        runtime: &TestRuntime,
        checkpoint: PrivateQueryCheckpoint,
        query: UtxoQuery,
        continuation: Option<ContinuationToken>,
        nonce_byte: u8,
    ) -> Result<FixedEnvelope<ENVELOPE_BYTES>, InnerCodecError> {
        runtime.codec.encode_request(
            &super::super::PrivateQueryRequest::new(checkpoint, query, continuation),
            [nonce_byte; ENVELOPE_NONCE_BYTES],
            &runtime.envelope_protector,
        )
    }

    fn handle_and_decode(
        runtime: &mut TestRuntime,
        request: &FixedEnvelope<ENVELOPE_BYTES>,
    ) -> Result<(AccessTrace, PrivateQueryResponse<RESPONSE_SLOTS>), Box<dyn std::error::Error>>
    {
        let envelope_opens = runtime.envelope_protector.opens.get();
        let envelope_seals = runtime.envelope_protector.seals.get();
        let token_opens = runtime.token_protector.opens.get();
        let token_seals = runtime.token_protector.seals.get();
        let replay_calls = runtime.replay_guard.calls;
        let replay_reads = runtime.replay_guard.logical_reads;
        let replay_writes = runtime.replay_guard.logical_writes;
        let material_calls = runtime.material_source.calls;
        let recent_snapshot_reads = runtime.recent_snapshot.read_calls();
        let round = runtime.handle(request)?;
        assert_eq!(runtime.envelope_protector.opens.get() - envelope_opens, 1);
        assert_eq!(runtime.envelope_protector.seals.get() - envelope_seals, 1);
        let trace = *round.trace();
        let response = runtime
            .codec
            .decode_response(round.envelope(), &runtime.envelope_protector)?;
        assert_eq!(runtime.token_protector.opens.get() - token_opens, 1);
        assert_eq!(runtime.token_protector.seals.get() - token_seals, 1);
        assert_eq!(runtime.replay_guard.calls - replay_calls, 1);
        assert_eq!(runtime.replay_guard.logical_reads - replay_reads, 1);
        assert_eq!(runtime.replay_guard.logical_writes - replay_writes, 1);
        assert_eq!(runtime.material_source.calls - material_calls, 1);
        assert_eq!(
            runtime.recent_snapshot.read_calls() - recent_snapshot_reads,
            RECENT_SNAPSHOT_SLOTS
        );
        assert_eq!(trace.runtime_phases(), RuntimePhase::COUNT);
        assert_eq!(trace.store_reads(), runtime.engine.profile().store_reads());
        assert_eq!(trace.recent_snapshot_reads(), RECENT_SNAPSHOT_SLOTS);
        assert_eq!(trace.replay_reads(), 1);
        assert_eq!(trace.replay_writes(), 1);
        assert_eq!(trace.request_frames(), 1);
        assert_eq!(trace.response_frames(), 1);
        assert_eq!(trace.request_bytes(), ENVELOPE_BYTES);
        assert_eq!(trace.response_bytes(), ENVELOPE_BYTES);
        assert_eq!(trace.completion(), CompletionShape::UnaryFixedEnvelope);
        Ok((trace, response))
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
        let profile = *runtime.engine.profile();
        let expectation = ContinuationExpectation::new(
            CONTINUATION_VERSION,
            *profile.profile_id(),
            runtime.continuation_query_digest(&query),
            checkpoint().projection_epoch,
            102,
            8,
        );
        let inspection = ContinuationToken::inspect_optional(
            Some(&second_token),
            &CountingTokenProtector::default(),
            &token_context,
            &expectation,
            [0; ENVELOPE_NONCE_BYTES],
        );
        assert_eq!(
            inspection.claim_or_cover(&mut CountingReplayGuard::available()),
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
            runtime.recent_snapshot.read_calls(),
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
            runtime.recent_snapshot.read_calls(),
            2 * RECENT_SNAPSHOT_SLOTS
        );
        assert_eq!(runtime.engine.store().read_slots().len(), 8);
        Ok(())
    }

    #[test]
    fn snapshot_identity_drift_completes_fixed_work_and_latches_readiness(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let key = address(1);
        let mut runtime = runtime(4, &[(0, utxo(1, 10))])?;
        let current = checkpoint();
        runtime
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
        assert_eq!(runtime.recent_snapshot.read_calls(), RECENT_SNAPSHOT_SLOTS);
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
        let profile = *runtime.engine.profile();
        let expectation = ContinuationExpectation::new(
            CONTINUATION_VERSION,
            *profile.profile_id(),
            runtime.continuation_query_digest(&query),
            checkpoint().projection_epoch,
            102,
            14,
        );
        let inspection = ContinuationToken::inspect_optional(
            Some(&second_token),
            &CountingTokenProtector::default(),
            &token_context,
            &expectation,
            [0; ENVELOPE_NONCE_BYTES],
        );
        assert_eq!(
            inspection.claim_or_cover(&mut CountingReplayGuard::available()),
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
        assert_eq!(runtime.replay_guard.real_claim_attempts, 2);
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
        let cursor_profile = *cursor_runtime.engine.profile();
        let cursor_state = ContinuationState::new(
            CONTINUATION_VERSION,
            *cursor_profile.profile_id(),
            cursor_runtime.continuation_query_digest(&query),
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
            &cursor_runtime.token_protector,
        );
        let cursor_request =
            request_envelope(&cursor_runtime, checkpoint(), query, Some(cursor_token), 7)?;
        let (cursor_trace, cursor_response) =
            handle_and_decode(&mut cursor_runtime, &cursor_request)?;
        assert_eq!(cursor_trace, baseline);
        assert_invalid_continuation(&cursor_response);

        for (wrong_profile, wrong_epoch, nonce_byte) in [(true, false, 8_u8), (false, true, 9_u8)] {
            let mut binding_runtime = runtime(4, &entries)?;
            let binding_profile = *binding_runtime.engine.profile();
            let mut profile_id = *binding_profile.profile_id();
            if wrong_profile {
                profile_id[0] ^= 1;
            }
            let projection_epoch = checkpoint().projection_epoch + u64::from(wrong_epoch);
            let binding_state = ContinuationState::new(
                CONTINUATION_VERSION,
                profile_id,
                binding_runtime.continuation_query_digest(&query),
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
                &binding_runtime.token_protector,
            );
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
        assert_eq!(other_session.replay_guard.real_claim_attempts, 0);
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
        let (unavailable_trace, unavailable_response) =
            handle_and_decode(&mut unavailable_runtime, &unavailable_request)?;
        assert_eq!(unavailable_trace, baseline);
        assert_eq!(
            unavailable_response.page.outcome(),
            QueryOutcome::ProjectionNotReady
        );
        assert_eq!(unavailable_runtime.replay_guard.real_claim_attempts, 1);
        assert!(!unavailable_runtime.healthy);

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
                recent_snapshot_identity(&checkpoint()),
                recent_slots,
                failing_ordinal,
            );
            let mut runtime = runtime_with_snapshot_components(
                store(4, &entries)?,
                4,
                recent_snapshot,
                SESSION_BINDING,
                CountingReplayGuard::available(),
                DeterministicMaterialSource::at(100),
            )?;

            for nonce in [1_u8, 2_u8] {
                let request = request_envelope(&runtime, checkpoint(), query, None, nonce)?;
                let (trace, response) = handle_and_decode(&mut runtime, &request)?;
                assert_eq!(trace, baseline);
                assert_eq!(response.page.outcome(), QueryOutcome::ProjectionNotReady);
                assert!(response.page.is_all_dummy());
                assert!(!runtime.healthy);
            }
            assert_eq!(
                runtime.recent_snapshot.read_calls(),
                2 * RECENT_SNAPSHOT_SLOTS
            );
            assert_eq!(runtime.engine.store().read_slots().len(), 8);
        }

        let recent_snapshot =
            FrozenRecentSnapshot::failing(recent_snapshot_identity(&checkpoint()), recent_slots, 0);
        let mut both_fail = runtime_with_snapshot_components(
            store(4, &entries)?.with_failure_on_read(1),
            4,
            recent_snapshot,
            SESSION_BINDING,
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
    fn runtime_rejects_snapshot_shape_and_checkpoint_identity_mismatches(
    ) -> Result<(), Box<dyn std::error::Error>> {
        type ThreeSlotRuntime = PrivateQueryRuntime<
            PlaintextMockStore,
            DeterministicEnvelopeProtector,
            CountingTokenProtector,
            CountingReplayGuard,
            DeterministicMaterialSource,
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
        let shape_mismatch = ThreeSlotRuntime::new(
            store(4, &[])?,
            FrozenRecentSnapshot::new(
                recent_snapshot_identity(&checkpoint()),
                [RecentSnapshotSlot::dummy(); 3],
            ),
            shape,
            SESSION_BINDING,
            checkpoint(),
            RuntimeDependencies::new(
                DeterministicEnvelopeProtector::default(),
                CountingTokenProtector::default(),
                CountingReplayGuard::available(),
                DeterministicMaterialSource::at(100),
            ),
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
            let identity_mismatch = TestRuntime::new(
                store(4, &[])?,
                FrozenRecentSnapshot::new(
                    mismatched_identity,
                    [RecentSnapshotSlot::dummy(); RECENT_SNAPSHOT_SLOTS],
                ),
                CompiledQueryShape::new(profile)?,
                SESSION_BINDING,
                current,
                RuntimeDependencies::new(
                    DeterministicEnvelopeProtector::default(),
                    CountingTokenProtector::default(),
                    CountingReplayGuard::available(),
                    DeterministicMaterialSource::at(100),
                ),
            );
            assert!(matches!(identity_mismatch, Err(UniformExternalFailure)));
        }
        Ok(())
    }

    #[test]
    fn readiness_precedence_and_claim_consumption_survive_downstream_failure(
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
        for (nonce, expected_outcome) in [
            (4_u8, QueryOutcome::StoreFailure),
            (5_u8, QueryOutcome::ProjectionNotReady),
        ] {
            let request = request_envelope(
                &claimed_then_failed,
                checkpoint(),
                query,
                Some(token.clone()),
                nonce,
            )?;
            let (trace, response) = handle_and_decode(&mut claimed_then_failed, &request)?;
            assert_eq!(trace, baseline);
            assert_eq!(response.page.outcome(), expected_outcome);
        }
        assert_eq!(claimed_then_failed.replay_guard.real_claim_attempts, 2);
        assert_eq!(
            claimed_then_failed
                .replay_guard
                .claimed
                .iter()
                .flatten()
                .count(),
            1
        );
        Ok(())
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
        assert_eq!(failing_runtime.material_source.calls, 1);
        assert_eq!(failing_runtime.replay_guard.calls, 0);
        assert_eq!(failing_runtime.replay_guard.real_claim_attempts, 0);
        assert_eq!(failing_runtime.replay_guard.logical_reads, 0);
        assert_eq!(failing_runtime.replay_guard.logical_writes, 0);
        assert_eq!(failing_runtime.token_protector.opens.get(), 0);
        assert_eq!(failing_runtime.token_protector.seals.get(), 0);
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
        assert_eq!(malformed_runtime.material_source.calls, 0);
        assert_eq!(malformed_runtime.replay_guard.calls, 0);
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
        *authentication = noncanonical_runtime.envelope_protector.seal(
            &noncanonical_runtime
                .codec
                .protection_context(super::super::EnvelopeDirection::Request),
            nonce,
            body,
        );
        let failure = match noncanonical_runtime.handle(&FixedEnvelope::from_array(bytes)) {
            Ok(_) => panic!("authenticated noncanonical envelope cannot enter private work"),
            Err(failure) => failure,
        };
        assert_eq!(failure.to_string(), "private query failed");
        assert_eq!(noncanonical_runtime.material_source.calls, 0);
        assert_eq!(noncanonical_runtime.replay_guard.calls, 0);
        assert!(noncanonical_runtime.healthy);
        Ok(())
    }

    #[test]
    fn runtime_debug_surfaces_redact_private_material() {
        let material = RoundMaterial::new(123_456, [0x44; 24], [0x55; 24]);
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
