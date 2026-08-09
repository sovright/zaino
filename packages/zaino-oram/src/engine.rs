use crate::{
    profile::{CompiledQueryShape, PrivacyProfile, PrivacyProfileError},
    recent_snapshot::{RecentSnapshotSlot, RecentUtxoChange, RecentUtxoChangeKind},
    records::{QueryOutcome, TransparentUtxo, UtxoQuery, UtxoResultPage},
    store::{ObliviousStore, StoreSlot},
    trace::{TraceDimension, TraceError, TraceRecorder},
};

/// The fixed page and next logical store-slot cursor produced by one query.
pub(super) struct QueryExecution<const RESPONSE_SLOTS: usize> {
    page: UtxoResultPage<RESPONSE_SLOTS>,
    next_cursor: Option<usize>,
    #[cfg(test)]
    conditional_slot_writes: usize,
}

impl<const RESPONSE_SLOTS: usize> QueryExecution<RESPONSE_SLOTS> {
    pub(super) const fn page(&self) -> &UtxoResultPage<RESPONSE_SLOTS> {
        &self.page
    }

    const fn next_cursor(&self) -> Option<usize> {
        self.next_cursor
    }

    #[cfg(test)]
    const fn conditional_slot_writes(&self) -> usize {
        self.conditional_slot_writes
    }

    pub(super) fn into_parts(self) -> (UtxoResultPage<RESPONSE_SLOTS>, Option<usize>) {
        (self.page, self.next_cursor)
    }
}

/// A synchronous transparent-UTXO logical-schedule model.
///
/// In addition to an exact logical store-call sequence and fixed Rust data
/// shapes, candidate selection uses fixed response-slot sweeps and
/// source-level non-short-circuiting/masked operations so its control flow and
/// coarse memory accesses do not depend on query matches or result count.
/// This does not guarantee constant-time machine code: Rust and LLVM may
/// transform these operations, and allocations, the ORAM backend, and the
/// whole binary remain outside this source-level claim.
pub(super) struct PrivateQueryEngine<S, const RESPONSE_SLOTS: usize, const ENVELOPE_BYTES: usize> {
    store: S,
    shape: CompiledQueryShape<RESPONSE_SLOTS, ENVELOPE_BYTES>,
}

impl<S, const RESPONSE_SLOTS: usize, const ENVELOPE_BYTES: usize>
    PrivateQueryEngine<S, RESPONSE_SLOTS, ENVELOPE_BYTES>
where
    S: ObliviousStore,
{
    pub(super) fn new(
        store: S,
        shape: CompiledQueryShape<RESPONSE_SLOTS, ENVELOPE_BYTES>,
    ) -> Result<Self, PrivacyProfileError> {
        let required = shape.profile().store_reads();
        let available = store.slots_per_key();
        if available != required {
            return Err(PrivacyProfileError::StoreShapeMismatch {
                required,
                available,
            });
        }
        Ok(Self { store, shape })
    }

    pub(super) fn profile(&self) -> &PrivacyProfile {
        self.shape.profile()
    }

    /// Returns the injected store for adjacent logical-schedule assertions.
    #[cfg(test)]
    pub(super) const fn store(&self) -> &S {
        &self.store
    }

    /// Executes the complete per-key slot domain and returns a fixed page.
    ///
    /// Store errors never short-circuit later calls. They become a protected
    /// [`QueryOutcome::StoreFailure`] after the configured call sequence; the
    /// later runtime must also latch a redacted health fault and fail readiness.
    ///
    /// `cursor` is an absolute ordinal in the finalized-store domain followed
    /// by the fixed recent-snapshot domain. Every execution still reads the
    /// complete configured store; the runtime materializes the complete recent
    /// snapshot before this call. Matching candidates below the cursor are
    /// ignored and the first omitted match becomes the next cursor.
    pub(super) fn execute_from<const RECENT_SNAPSHOT_SLOTS: usize>(
        &mut self,
        query: &UtxoQuery,
        cursor: usize,
        recent_snapshot: &[RecentSnapshotSlot; RECENT_SNAPSHOT_SLOTS],
        trace: &mut TraceRecorder,
    ) -> Result<QueryExecution<RESPONSE_SLOTS>, TraceError> {
        let mut page = UtxoResultPage::empty();
        let mut selection = CandidateSelectionState::new();
        let mut store_failed = false;
        let mut recent_snapshot_valid = recent_snapshot_is_semantically_valid(recent_snapshot);
        let store_reads = self.profile().store_reads();

        for slot in 0..store_reads {
            trace.record_store_read(slot)?;
            let store_slot = match self.store.read_slot(query.address_key(), slot) {
                Ok(store_slot) => store_slot,
                Err(_) => {
                    store_failed = true;
                    StoreSlot::dummy()
                }
            };
            let candidate: TransparentUtxo = *store_slot.record();
            let (survives_recent_snapshot, finalized_relation_valid) =
                finalized_snapshot_relation(query.address_key(), &candidate, recent_snapshot);
            recent_snapshot_valid &= !store_slot.is_occupied() | finalized_relation_valid;
            let matches = store_slot.is_occupied()
                & query.domain_valid()
                & (candidate.height() >= query.minimum_height())
                & survives_recent_snapshot;
            consider_candidate(&mut page, &mut selection, cursor, slot, candidate, matches);
        }

        for (recent_ordinal, recent_slot) in recent_snapshot.iter().enumerate() {
            // Slot presence is public snapshot shape/data shared by every query
            // in the generation, so this branch is not query-dependent.
            let Some(change) = recent_slot.change() else {
                continue;
            };
            let combined_ordinal =
                store_reads
                    .checked_add(recent_ordinal)
                    .ok_or(TraceError::CounterOverflow {
                        dimension: TraceDimension::CombinedCursor,
                    })?;
            let candidate = *change.utxo();
            let matches = query.domain_valid()
                & (change.kind() == RecentUtxoChangeKind::Created)
                & same_address(change.address_key(), query.address_key())
                & (candidate.height() >= query.minimum_height())
                & recent_creation_is_live(recent_ordinal, change, recent_snapshot);
            consider_candidate(
                &mut page,
                &mut selection,
                cursor,
                combined_ordinal,
                candidate,
                matches,
            );
        }

        let projection_not_ready = !store_failed & !recent_snapshot_valid;
        let invalid_domain = !store_failed & recent_snapshot_valid & !query.domain_valid();
        let budget_exceeded = !store_failed
            & recent_snapshot_valid
            & query.domain_valid()
            & selection.next_cursor_found;
        let clear_results = store_failed | projection_not_ready;
        page.conditional_clear(ct::mask(clear_results));
        selection.next_cursor_found &= !clear_results;
        let next_cursor = selection
            .next_cursor_found
            .then_some(selection.next_cursor_value);
        let mut outcome = QueryOutcome::Complete;
        outcome = outcome.conditional_select(
            QueryOutcome::ResultBudgetExceeded,
            ct::mask(budget_exceeded),
        );
        outcome = outcome.conditional_select(QueryOutcome::InvalidDomain, ct::mask(invalid_domain));
        outcome = outcome.conditional_select(
            QueryOutcome::ProjectionNotReady,
            ct::mask(projection_not_ready),
        );
        outcome = outcome.conditional_select(QueryOutcome::StoreFailure, ct::mask(store_failed));
        page.set_outcome(outcome);
        Ok(QueryExecution {
            page,
            next_cursor,
            #[cfg(test)]
            conditional_slot_writes: selection.conditional_slot_writes,
        })
    }
}

struct CandidateSelectionState {
    real_slots: usize,
    next_cursor_value: usize,
    next_cursor_found: bool,
    #[cfg(test)]
    conditional_slot_writes: usize,
}

impl CandidateSelectionState {
    const fn new() -> Self {
        Self {
            real_slots: 0,
            next_cursor_value: 0,
            next_cursor_found: false,
            #[cfg(test)]
            conditional_slot_writes: 0,
        }
    }
}

fn consider_candidate<const RESPONSE_SLOTS: usize>(
    page: &mut UtxoResultPage<RESPONSE_SLOTS>,
    state: &mut CandidateSelectionState,
    cursor: usize,
    ordinal: usize,
    candidate: TransparentUtxo,
    matches: bool,
) {
    let eligible = matches & (ordinal >= cursor);
    let has_capacity = state.real_slots < RESPONSE_SLOTS;
    let insert = eligible & has_capacity;
    for slot_index in 0..RESPONSE_SLOTS {
        let select = insert & (slot_index == state.real_slots);
        page.conditional_set_slot(slot_index, candidate, ct::mask(select));
        #[cfg(test)]
        {
            state.conditional_slot_writes += 1;
        }
    }
    state.real_slots = ct::select_usize(state.real_slots, state.real_slots + 1, insert);

    let set_cursor = eligible & !has_capacity & !state.next_cursor_found;
    state.next_cursor_value = ct::select_usize(state.next_cursor_value, ordinal, set_cursor);
    state.next_cursor_found = ct::select_bool(state.next_cursor_found, true, set_cursor);
}

fn finalized_snapshot_relation<const RECENT_SNAPSHOT_SLOTS: usize>(
    address_key: &crate::records::AddressKey,
    candidate: &TransparentUtxo,
    recent_snapshot: &[RecentSnapshotSlot; RECENT_SNAPSHOT_SLOTS],
) -> (bool, bool) {
    let mut survives = true;
    let mut valid = true;
    for slot in recent_snapshot {
        // Slot presence is public snapshot data shared by every query in the
        // generation, so this branch is not query-dependent.
        let Some(change) = slot.change() else {
            continue;
        };
        let same = same_outpoint(change.utxo(), candidate);
        let is_valid_spend = same_address(change.address_key(), address_key)
            & (change.kind() == RecentUtxoChangeKind::Spent);
        valid &= !same | is_valid_spend;
        survives &= !(same & is_valid_spend);
    }
    (survives, valid)
}

fn recent_snapshot_is_semantically_valid<const RECENT_SNAPSHOT_SLOTS: usize>(
    recent_snapshot: &[RecentSnapshotSlot; RECENT_SNAPSHOT_SLOTS],
) -> bool {
    let mut valid = true;
    for (later_ordinal, later_slot) in recent_snapshot.iter().enumerate() {
        for (earlier_ordinal, earlier_slot) in recent_snapshot.iter().enumerate() {
            let Some(later) = later_slot.change() else {
                continue;
            };
            let Some(earlier) = earlier_slot.change() else {
                continue;
            };
            if earlier_ordinal < later_ordinal && same_outpoint(earlier.utxo(), later.utxo()) {
                valid &= earlier.address_key() == later.address_key()
                    && earlier.kind() == RecentUtxoChangeKind::Created
                    && later.kind() == RecentUtxoChangeKind::Spent;
            }
        }
    }
    valid
}

fn recent_creation_is_live<const RECENT_SNAPSHOT_SLOTS: usize>(
    ordinal: usize,
    candidate: &RecentUtxoChange,
    recent_snapshot: &[RecentSnapshotSlot; RECENT_SNAPSHOT_SLOTS],
) -> bool {
    let mut spent_later = false;
    for (later_ordinal, slot) in recent_snapshot.iter().enumerate() {
        let Some(later) = slot.change() else {
            continue;
        };
        spent_later |= (later_ordinal > ordinal)
            & same_address(later.address_key(), candidate.address_key())
            & same_outpoint(later.utxo(), candidate.utxo());
    }
    !spent_later
}

fn same_outpoint(left: &TransparentUtxo, right: &TransparentUtxo) -> bool {
    ct::eq_bytes(left.txid(), right.txid()) & (left.output_index() == right.output_index())
}

fn same_address(left: &crate::records::AddressKey, right: &crate::records::AddressKey) -> bool {
    ct::eq_bytes(left.as_bytes(), right.as_bytes())
}

/// Minimal source-level masked operations used by candidate selection.
mod ct {
    pub(super) const fn mask(choice: bool) -> usize {
        0usize.wrapping_sub(choice as usize)
    }

    pub(super) const fn select_usize(current: usize, replacement: usize, choice: bool) -> usize {
        let mask = mask(choice);
        (current & !mask) | (replacement & mask)
    }

    pub(super) const fn select_bool(current: bool, replacement: bool, choice: bool) -> bool {
        select_usize(current as usize, replacement as usize, choice) != 0
    }

    pub(super) fn eq_bytes<const N: usize>(left: &[u8; N], right: &[u8; N]) -> bool {
        let mut difference = 0;
        for index in 0..N {
            difference |= left[index] ^ right[index];
        }
        difference == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        profile::test_profile_without_recent_snapshot,
        records::{AddressKey, ADDRESS_KEY_BYTES, TXID_BYTES},
        store::{PlaintextMockStore, PlaintextMockStoreError},
        trace::RuntimePhase,
    };

    const RESPONSE_SLOTS: usize = 2;
    const ENVELOPE_BYTES: usize = 128;

    type TestEngine = PrivateQueryEngine<PlaintextMockStore, RESPONSE_SLOTS, ENVELOPE_BYTES>;

    fn profile() -> PrivacyProfile {
        test_profile_without_recent_snapshot(
            "unit-test-v1",
            4,
            RESPONSE_SLOTS,
            ENVELOPE_BYTES,
            2,
            60,
        )
        .expect("unit-test privacy profile constants are valid")
    }

    fn shape() -> CompiledQueryShape<RESPONSE_SLOTS, ENVELOPE_BYTES> {
        CompiledQueryShape::new(profile())
            .expect("unit-test profile exactly matches its compiled shapes")
    }

    fn address(byte: u8) -> AddressKey {
        AddressKey::new([byte; ADDRESS_KEY_BYTES])
    }

    fn utxo(byte: u8, height: u32) -> TransparentUtxo {
        utxo_with_outpoint(byte, u32::from(byte), height)
    }

    fn utxo_with_outpoint(txid_byte: u8, output_index: u32, height: u32) -> TransparentUtxo {
        TransparentUtxo::new(
            [txid_byte; TXID_BYTES],
            output_index,
            100,
            height,
            &[0x51; 25],
        )
        .expect("unit-test transparent script fits the fixed record")
    }

    fn engine_with(
        entries: &[(usize, TransparentUtxo)],
    ) -> Result<TestEngine, PlaintextMockStoreError> {
        let key = address(1);
        let mut store = PlaintextMockStore::new(4, entries.len());
        for (slot, record) in entries {
            store.insert(&key, *slot, record)?;
        }
        Ok(TestEngine::new(store, shape())
            .expect("mock and profile expose the same complete slot domain"))
    }

    fn assert_fixed_logical_schedule(
        execution: &QueryExecution<RESPONSE_SLOTS>,
        expected_outcome: QueryOutcome,
        expected_real_count: usize,
        expected_next_cursor: Option<usize>,
    ) {
        assert_eq!(execution.page().outcome(), expected_outcome);
        assert_eq!(execution.page().slots().len(), RESPONSE_SLOTS);
        assert_eq!(execution.page().real_count(), expected_real_count);
        assert_eq!(execution.next_cursor(), expected_next_cursor);
    }

    fn execute(
        engine: &mut TestEngine,
        query: &UtxoQuery,
        cursor: usize,
    ) -> Result<QueryExecution<RESPONSE_SLOTS>, TraceError> {
        execute_with_recent(engine, query, cursor, &[])
    }

    fn execute_with_recent<const RECENT_SNAPSHOT_SLOTS: usize>(
        engine: &mut TestEngine,
        query: &UtxoQuery,
        cursor: usize,
        recent_snapshot: &[RecentSnapshotSlot; RECENT_SNAPSHOT_SLOTS],
    ) -> Result<QueryExecution<RESPONSE_SLOTS>, TraceError> {
        let mut trace = TraceRecorder::new();
        open_engine_execution(&mut trace)?;
        for ordinal in 0..RECENT_SNAPSHOT_SLOTS {
            trace.record_recent_snapshot_read(ordinal)?;
        }
        trace.complete_recent_snapshot_scan(RECENT_SNAPSHOT_SLOTS)?;
        engine.execute_from(query, cursor, recent_snapshot, &mut trace)
    }

    fn open_engine_execution(trace: &mut TraceRecorder) -> Result<(), TraceError> {
        for phase in [
            RuntimePhase::RequestDecode,
            RuntimePhase::NonceAcquisition,
            RuntimePhase::TokenOpen,
            RuntimePhase::ReplayGuard,
            RuntimePhase::ReadinessSelect,
            RuntimePhase::EngineExecution,
        ] {
            trace.record_runtime_phase(phase)?;
        }
        Ok(())
    }

    #[test]
    fn secret_cases_have_the_same_modeled_access_and_completion_shape(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let key = address(1);

        let mut hit = engine_with(&[(0, utxo(1, 10))])?;
        let hit_execution = execute(&mut hit, &UtxoQuery::new(key, 0), 0)?;
        assert_fixed_logical_schedule(&hit_execution, QueryOutcome::Complete, 1, None);

        let mut miss = engine_with(&[])?;
        let miss_execution = execute(&mut miss, &UtxoQuery::new(address(9), 0), 0)?;
        assert_fixed_logical_schedule(&miss_execution, QueryOutcome::Complete, 0, None);
        assert_eq!(
            hit_execution.conditional_slot_writes(),
            miss_execution.conditional_slot_writes()
        );
        assert_eq!(
            hit_execution.conditional_slot_writes(),
            expected_schedule_slots().len() * RESPONSE_SLOTS
        );

        let mut filtered = engine_with(&[(0, utxo(1, 10))])?;
        let filtered_execution = execute(&mut filtered, &UtxoQuery::new(key, 11), 0)?;
        assert_fixed_logical_schedule(&filtered_execution, QueryOutcome::Complete, 0, None);

        let mut exactly_full = engine_with(&[(0, utxo(1, 10)), (1, utxo(2, 11))])?;
        let exactly_full_execution = execute(&mut exactly_full, &UtxoQuery::new(key, 0), 0)?;
        assert_fixed_logical_schedule(
            &exactly_full_execution,
            QueryOutcome::Complete,
            RESPONSE_SLOTS,
            None,
        );

        let mut cap_hit = engine_with(&[(0, utxo(1, 10)), (1, utxo(2, 11)), (2, utxo(3, 12))])?;
        let cap_hit_execution = execute(&mut cap_hit, &UtxoQuery::new(key, 0), 0)?;
        assert_fixed_logical_schedule(
            &cap_hit_execution,
            QueryOutcome::ResultBudgetExceeded,
            RESPONSE_SLOTS,
            Some(2),
        );

        let mut late = engine_with(&[(3, utxo(4, 13))])?;
        let late_execution = execute(&mut late, &UtxoQuery::new(key, 0), 0)?;
        assert_fixed_logical_schedule(&late_execution, QueryOutcome::Complete, 1, None);

        for engine in [&hit, &miss, &filtered, &exactly_full, &cap_hit, &late] {
            assert_eq!(engine.store.read_slots(), &expected_schedule_slots());
        }
        Ok(())
    }

    fn expected_schedule_slots() -> [usize; 4] {
        [0, 1, 2, 3]
    }

    #[test]
    fn branchless_candidate_selection_matches_previous_semantics() {
        let cases = [
            ([false, false, false, false], 0),
            ([true, false, false, false], 0),
            ([true, true, false, false], 0),
            ([true, true, true, true], 0),
            ([true, true, true, true], 2),
        ];

        for (matches, cursor) in cases {
            let candidate_count = matches.len();
            let mut actual_page: UtxoResultPage<RESPONSE_SLOTS> = UtxoResultPage::empty();
            let mut actual = CandidateSelectionState::new();
            let mut expected_page: UtxoResultPage<RESPONSE_SLOTS> = UtxoResultPage::empty();
            let mut expected_count = 0;
            let mut expected_next_cursor = None;

            for (ordinal, matches) in matches.into_iter().enumerate() {
                let candidate = utxo(ordinal as u8 + 1, ordinal as u32 + 10);
                consider_candidate(
                    &mut actual_page,
                    &mut actual,
                    cursor,
                    ordinal,
                    candidate,
                    matches,
                );
                if matches && ordinal >= cursor {
                    if expected_count < RESPONSE_SLOTS {
                        expected_page.set_slot(expected_count, candidate);
                        expected_count += 1;
                    } else if expected_next_cursor.is_none() {
                        expected_next_cursor = Some(ordinal);
                    }
                }
            }

            assert_eq!(actual_page, expected_page);
            assert_eq!(actual.real_slots, expected_count);
            assert_eq!(
                actual.next_cursor_found.then_some(actual.next_cursor_value),
                expected_next_cursor
            );
            assert_eq!(
                actual.conditional_slot_writes,
                candidate_count * RESPONSE_SLOTS
            );
        }
    }

    #[test]
    fn invalid_domain_and_each_store_failure_ordinal_complete_the_schedule(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let key = address(1);
        let invalid_query = UtxoQuery::from_untrusted_address_key(&[7; 31], 0);
        let mut invalid = engine_with(&[(0, utxo(1, 10))])
            .expect("unit-test mock entries fit their bounded slot domain");
        let invalid_execution = execute(&mut invalid, &invalid_query, 0)?;
        assert_fixed_logical_schedule(&invalid_execution, QueryOutcome::InvalidDomain, 0, None);
        assert_eq!(invalid.store.read_slots(), &expected_schedule_slots());

        for failing_ordinal in 1..=4 {
            let mut store = PlaintextMockStore::new(4, 1);
            store
                .insert(&key, 0, &utxo(1, 10))
                .expect("unit-test mock entry fits its bounded slot domain");
            let store = store.with_failure_on_read(failing_ordinal);
            let mut failing = TestEngine::new(store, shape())
                .expect("mock and profile expose the same complete slot domain");
            let failure_execution = execute(&mut failing, &UtxoQuery::new(key, 0), 0)?;
            assert_fixed_logical_schedule(&failure_execution, QueryOutcome::StoreFailure, 0, None);
            assert_eq!(failing.store.read_slots(), &expected_schedule_slots());
        }
        Ok(())
    }

    #[test]
    fn continuation_cursor_is_the_first_omitted_store_slot(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let key = address(1);
        let entries = [(0, utxo(1, 10)), (2, utxo(2, 11)), (3, utxo(3, 12))];
        let mut engine = engine_with(&entries)?;

        let first = execute(&mut engine, &UtxoQuery::new(key, 0), 0)?;
        assert_fixed_logical_schedule(
            &first,
            QueryOutcome::ResultBudgetExceeded,
            RESPONSE_SLOTS,
            Some(3),
        );

        let second = execute(&mut engine, &UtxoQuery::new(key, 0), 3)?;
        assert_fixed_logical_schedule(&second, QueryOutcome::Complete, 1, None);
        assert_eq!(engine.store.read_slots(), &[0, 1, 2, 3, 0, 1, 2, 3]);
        Ok(())
    }

    #[test]
    fn recent_snapshot_effects_are_fully_merged_before_paging(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let key = address(1);
        let first = utxo(1, 10);
        let second = utxo(2, 11);
        let third = utxo(3, 12);
        let mut engine = engine_with(&[(0, first), (1, second), (2, third)])?;
        let recent = [
            RecentSnapshotSlot::spent(key, first),
            RecentSnapshotSlot::dummy(),
        ];

        let execution = execute_with_recent(&mut engine, &UtxoQuery::new(key, 0), 0, &recent)?;
        assert_fixed_logical_schedule(&execution, QueryOutcome::Complete, 2, None);
        assert_eq!(
            real_txids(execution.page()),
            vec![[2; TXID_BYTES], [3; TXID_BYTES]]
        );

        let mut replacement = engine_with(&[(0, first), (1, second)])?;
        let recent = [
            RecentSnapshotSlot::spent(key, first),
            RecentSnapshotSlot::created(key, third),
        ];
        let execution = execute_with_recent(&mut replacement, &UtxoQuery::new(key, 0), 0, &recent)?;
        assert_fixed_logical_schedule(&execution, QueryOutcome::Complete, 2, None);
        assert_eq!(
            real_txids(execution.page()),
            vec![[2; TXID_BYTES], [3; TXID_BYTES]]
        );
        Ok(())
    }

    #[test]
    fn recent_spend_before_continuation_boundary_does_not_skip_results(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let key = address(1);
        let first = utxo(1, 10);
        let second = utxo(2, 11);
        let third = utxo(3, 12);
        let fourth = utxo(4, 13);
        let recent_created = utxo(5, 14);
        let mut engine = engine_with(&[(0, first), (1, second), (2, third), (3, fourth)])?;
        let recent = [
            RecentSnapshotSlot::spent(key, first),
            RecentSnapshotSlot::created(key, recent_created),
        ];
        let query = UtxoQuery::new(key, 0);

        let first_page = execute_with_recent(&mut engine, &query, 0, &recent)?;
        assert_fixed_logical_schedule(&first_page, QueryOutcome::ResultBudgetExceeded, 2, Some(3));
        assert_eq!(
            real_txids(first_page.page()),
            vec![[2; TXID_BYTES], [3; TXID_BYTES]]
        );

        let second_page = execute_with_recent(&mut engine, &query, 3, &recent)?;
        assert_fixed_logical_schedule(&second_page, QueryOutcome::Complete, 2, None);
        assert_eq!(
            real_txids(second_page.page()),
            vec![[4; TXID_BYTES], [5; TXID_BYTES]]
        );
        assert_eq!(engine.store.read_slots().len(), 8);
        Ok(())
    }

    #[test]
    fn recent_snapshot_matches_exact_outpoints_and_last_effect_wins(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let key = address(1);
        let finalized = utxo_with_outpoint(1, 1, 10);
        let different_vout = utxo_with_outpoint(1, 2, 10);
        let recent_created = utxo(4, 12);
        let mut engine = engine_with(&[(0, finalized)])?;
        let recent = [
            RecentSnapshotSlot::spent(key, different_vout),
            RecentSnapshotSlot::created(key, recent_created),
            RecentSnapshotSlot::spent(key, recent_created),
            RecentSnapshotSlot::created(address(9), utxo(5, 13)),
        ];

        let execution = execute_with_recent(&mut engine, &UtxoQuery::new(key, 0), 0, &recent)?;
        assert_fixed_logical_schedule(&execution, QueryOutcome::Complete, 1, None);
        assert_eq!(real_txids(execution.page()), vec![[1; TXID_BYTES]]);

        let mut filtered = engine_with(&[])?;
        let recent = [RecentSnapshotSlot::created(key, utxo(6, 9))];
        let execution = execute_with_recent(&mut filtered, &UtxoQuery::new(key, 10), 0, &recent)?;
        assert_fixed_logical_schedule(&execution, QueryOutcome::Complete, 0, None);
        Ok(())
    }

    #[test]
    fn malformed_recent_snapshot_sequences_fail_closed_after_full_store_work(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let key = address(1);
        let other_key = address(9);
        let output = utxo(7, 12);
        let malformed = [
            [
                RecentSnapshotSlot::created(key, output),
                RecentSnapshotSlot::created(key, output),
                RecentSnapshotSlot::dummy(),
            ],
            [
                RecentSnapshotSlot::spent(key, output),
                RecentSnapshotSlot::created(key, output),
                RecentSnapshotSlot::dummy(),
            ],
            [
                RecentSnapshotSlot::created(key, output),
                RecentSnapshotSlot::spent(key, output),
                RecentSnapshotSlot::spent(key, output),
            ],
            [
                RecentSnapshotSlot::created(key, output),
                RecentSnapshotSlot::spent(other_key, output),
                RecentSnapshotSlot::dummy(),
            ],
        ];

        for recent in malformed {
            let mut engine = engine_with(&[])?;
            let execution = execute_with_recent(&mut engine, &UtxoQuery::new(key, 0), 0, &recent)?;
            assert_fixed_logical_schedule(&execution, QueryOutcome::ProjectionNotReady, 0, None);
            assert_eq!(engine.store.read_slots(), &expected_schedule_slots());
        }
        Ok(())
    }

    #[test]
    fn malformed_finalized_snapshot_relations_fail_closed() -> Result<(), Box<dyn std::error::Error>>
    {
        let key = address(1);
        let finalized = utxo(1, 10);
        let malformed = [
            RecentSnapshotSlot::spent(address(9), finalized),
            RecentSnapshotSlot::created(key, finalized),
        ];

        for recent_slot in malformed {
            let mut engine = engine_with(&[(0, finalized)])?;
            let recent = [recent_slot];
            let execution = execute_with_recent(&mut engine, &UtxoQuery::new(key, 0), 0, &recent)?;
            assert_fixed_logical_schedule(&execution, QueryOutcome::ProjectionNotReady, 0, None);
            assert_eq!(engine.store.read_slots(), &expected_schedule_slots());
        }
        Ok(())
    }

    #[test]
    fn combined_cursor_pages_store_then_recent_ordinals_without_duplicates(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let key = address(1);
        let mut engine = engine_with(&[(0, utxo(1, 10)), (1, utxo(2, 11)), (2, utxo(3, 12))])?;
        let recent = [
            RecentSnapshotSlot::created(key, utxo(4, 13)),
            RecentSnapshotSlot::created(key, utxo(5, 14)),
        ];
        let query = UtxoQuery::new(key, 0);

        let first = execute_with_recent(&mut engine, &query, 0, &recent)?;
        assert_fixed_logical_schedule(&first, QueryOutcome::ResultBudgetExceeded, 2, Some(2));
        assert_eq!(
            real_txids(first.page()),
            vec![[1; TXID_BYTES], [2; TXID_BYTES]]
        );

        let second = execute_with_recent(&mut engine, &query, 2, &recent)?;
        assert_fixed_logical_schedule(&second, QueryOutcome::ResultBudgetExceeded, 2, Some(5));
        assert_eq!(
            real_txids(second.page()),
            vec![[3; TXID_BYTES], [4; TXID_BYTES]]
        );

        let third = execute_with_recent(&mut engine, &query, 5, &recent)?;
        assert_fixed_logical_schedule(&third, QueryOutcome::Complete, 1, None);
        assert_eq!(real_txids(third.page()), vec![[5; TXID_BYTES]]);
        assert_eq!(engine.store.read_slots().len(), 12);
        Ok(())
    }

    fn real_txids(page: &UtxoResultPage<RESPONSE_SLOTS>) -> Vec<[u8; TXID_BYTES]> {
        page.slots()
            .iter()
            .filter(|slot| slot.is_occupied())
            .map(|slot| *slot.padded_utxo().txid())
            .collect()
    }

    #[test]
    fn engine_rejects_incomplete_store_slot_domain() {
        let store = PlaintextMockStore::new(3, 0);
        assert!(matches!(
            TestEngine::new(store, shape()),
            Err(PrivacyProfileError::StoreShapeMismatch {
                required: 4,
                available: 3,
            })
        ));
    }
}
