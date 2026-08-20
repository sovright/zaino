use crate::{
    profile::{CompiledQueryShape, PrivacyProfile, PrivacyProfileError},
    recent_snapshot::{RecentSnapshotScan, RecentSnapshotSlot, RecentUtxoChangeKind},
    records::{QueryOutcome, RecordAnnotation, TransparentUtxo, UtxoQuery, UtxoResultPage},
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
    /// Lends the store so a test can publish a generation's annotations.
    #[cfg(test)]
    pub(super) const fn store_mut(&mut self) -> &mut S {
        &mut self.store
    }

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
        recent_snapshot: &RecentSnapshotScan<RECENT_SNAPSHOT_SLOTS>,
        trace: &mut TraceRecorder,
    ) -> Result<QueryExecution<RESPONSE_SLOTS>, TraceError> {
        let mut page = UtxoResultPage::empty();
        let mut selection = CandidateSelectionState::new();
        let mut store_failed = false;
        // Both snapshot-only facts were computed once when this generation was
        // published; see `RecentSnapshotScan`. They are read here, never
        // recomputed, and they never shorten the sweeps below.
        let mut recent_snapshot_valid = recent_snapshot.semantically_valid();
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
            // ADR 0902: this join was computed once, at publication, and stored
            // on the record. Reading it here is the whole of the hoist -- it
            // replaces the `store_reads * N` rescan this loop used to run on
            // every slot, which was the query's last quadratic term.
            let (annotated, survives_recent_snapshot, finalized_relation_valid) =
                store_slot.annotation().bits();
            // Fail closed on an occupied record the publication pass has not
            // covered for this generation: it carries no answer, and recomputing
            // the join here would silently restore the cost the hoist exists to
            // remove. `ProjectionNotReady` is what an incompletely published
            // generation already reports.
            recent_snapshot_valid &=
                !store_slot.is_occupied() | (annotated & finalized_relation_valid);
            let matches = store_slot.is_occupied()
                & query.domain_valid()
                & (candidate.height() >= query.minimum_height())
                & survives_recent_snapshot;
            consider_candidate(&mut page, &mut selection, cursor, slot, candidate, matches);
        }

        // The sweep still visits every snapshot ordinal. The precomputed
        // liveness bit only replaces the inner `O(N)` rescan each visit used to
        // perform; it never selects which ordinals are visited.
        for (recent_ordinal, (recent_slot, live)) in recent_snapshot
            .slots()
            .iter()
            .zip(recent_snapshot.liveness().iter())
            .enumerate()
        {
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
                & *live;
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

fn finalized_snapshot_relation(
    address_key: &crate::records::AddressKey,
    candidate: &TransparentUtxo,
    recent_snapshot: &[RecentSnapshotSlot],
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

/// Computes the annotation the publication pass stores on one record.
///
/// This is the whole of ADR 0902's obligation 1: a pure function of the
/// record, its owning address, and the generation's published snapshot. It
/// takes no clock, no iteration order, no host input and no prior annotation,
/// which is what makes the result reproducible from `(source, generation)`.
///
/// It shares [`finalized_snapshot_relation`] with the query path rather than
/// restating the join, so publication and serving cannot drift apart: the
/// stored answer is by construction the one the query would have computed.
pub(crate) fn annotate_record(
    owner: &crate::records::AddressKey,
    record: &TransparentUtxo,
    recent_snapshot: &[RecentSnapshotSlot],
) -> RecordAnnotation {
    let (survives, valid) = finalized_snapshot_relation(owner, record, recent_snapshot);
    RecordAnnotation::Annotated { survives, valid }
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
        recent_snapshot::RecentUtxoChange,
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
        // Stand in for the publication pass. The query under test reads
        // annotations and never recomputes the join, so this generation's
        // annotations have to exist before it runs (ADR 0902).
        engine
            .store_mut()
            .publish_annotations(&|owner, record| annotate_record(owner, record, recent_snapshot))
            .expect("mock entries round-trip through their persistent form");
        engine.execute_from(
            query,
            cursor,
            &RecentSnapshotScan::from_slots(*recent_snapshot),
            &mut trace,
        )
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

    /// Runs one query against annotations chosen by the caller, with no
    /// publication pass in between.
    fn execute_with_annotation(
        engine: &mut TestEngine,
        query: &UtxoQuery,
        annotation: RecordAnnotation,
    ) -> Result<QueryExecution<RESPONSE_SLOTS>, Box<dyn std::error::Error>> {
        let mut trace = TraceRecorder::new();
        open_engine_execution(&mut trace)?;
        trace.complete_recent_snapshot_scan(0)?;
        engine
            .store_mut()
            .publish_annotations(&|_, _| annotation)
            .expect("mock entries round-trip through their persistent form");
        Ok(engine.execute_from(query, 0, &RecentSnapshotScan::from_slots([]), &mut trace)?)
    }

    /// The whole of ADR 0902: the query returns the annotation it was given.
    ///
    /// The snapshot here is empty, so recomputing the join would say the record
    /// survives and is valid. Storing the opposite and watching the answer
    /// change is what proves the join is read rather than recomputed --- a query
    /// that still computed it would ignore all three annotations below.
    #[test]
    fn the_query_answers_from_the_stored_annotation_and_not_a_recomputed_join(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let key = address(1);
        let query = UtxoQuery::new(key, 0);

        let mut published = engine_with(&[(0, utxo(1, 10))])?;
        let execution = execute_with_annotation(
            &mut published,
            &query,
            RecordAnnotation::Annotated {
                survives: true,
                valid: true,
            },
        )?;
        assert_fixed_logical_schedule(&execution, QueryOutcome::Complete, 1, None);

        // `survives = false` is what the pass writes for a record the recent
        // snapshot spends. The query drops it without consulting the snapshot.
        let mut spent = engine_with(&[(0, utxo(1, 10))])?;
        let execution = execute_with_annotation(
            &mut spent,
            &query,
            RecordAnnotation::Annotated {
                survives: false,
                valid: true,
            },
        )?;
        assert_fixed_logical_schedule(&execution, QueryOutcome::Complete, 0, None);

        // `valid = false` is the generation's own inconsistency, which is not a
        // per-record answer but a reason to serve nothing.
        let mut invalid = engine_with(&[(0, utxo(1, 10))])?;
        let execution = execute_with_annotation(
            &mut invalid,
            &query,
            RecordAnnotation::Annotated {
                survives: true,
                valid: false,
            },
        )?;
        assert_fixed_logical_schedule(&execution, QueryOutcome::ProjectionNotReady, 0, None);
        Ok(())
    }

    /// An occupied record the publication pass never covered has no answer.
    ///
    /// Failing closed is the point: recomputing the join here would work, and
    /// would silently restore the per-query cost the hoist exists to remove,
    /// while serving an answer the generation never published.
    #[test]
    fn an_unannotated_record_fails_closed_rather_than_recomputing_the_join(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let key = address(1);
        let mut engine = engine_with(&[(0, utxo(1, 10))])?;
        let execution = execute_with_annotation(
            &mut engine,
            &UtxoQuery::new(key, 0),
            RecordAnnotation::Unannotated,
        )?;
        assert_fixed_logical_schedule(&execution, QueryOutcome::ProjectionNotReady, 0, None);

        // An address with nothing stored is unaffected: there is no occupied
        // record to be missing an annotation, so the empty answer is complete.
        let mut empty = engine_with(&[])?;
        let execution = execute_with_annotation(
            &mut empty,
            &UtxoQuery::new(key, 0),
            RecordAnnotation::Unannotated,
        )?;
        assert_fixed_logical_schedule(&execution, QueryOutcome::Complete, 0, None);
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

    /// The annotation the publication pass will store is exactly the join the
    /// query used to recompute per slot, so this pins the three outcomes that
    /// distinguish it. `Unannotated` is deliberately unreachable here: the
    /// function always answers, and absence means no pass has run.
    #[test]
    fn the_stored_annotation_is_the_join_the_query_no_longer_recomputes() {
        let owner = address(1);
        let held = utxo(1, 10);

        // Nothing in the snapshot touches this outpoint.
        let untouched = [RecentSnapshotSlot::spent(owner, utxo(2, 11))];
        assert_eq!(
            annotate_record(&owner, &held, &untouched),
            RecordAnnotation::Annotated {
                survives: true,
                valid: true
            }
        );

        // The owner spends it: the record must not survive, and the snapshot
        // remains semantically valid.
        let spent_by_owner = [RecentSnapshotSlot::spent(owner, held)];
        assert_eq!(
            annotate_record(&owner, &held, &spent_by_owner),
            RecordAnnotation::Annotated {
                survives: false,
                valid: true
            }
        );

        // Some other address claims to spend it. That is a malformed snapshot,
        // not a spend, so the record survives and validity fails closed.
        let spent_by_stranger = [RecentSnapshotSlot::spent(address(9), held)];
        assert_eq!(
            annotate_record(&owner, &held, &spent_by_stranger),
            RecordAnnotation::Annotated {
                survives: true,
                valid: false
            }
        );
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

    /// The pre-hoist `recent_snapshot_is_semantically_valid`, verbatim.
    ///
    /// Kept as an oracle so the publication-time precomputation is proved
    /// against the predicate it replaced rather than against itself.
    fn legacy_semantically_valid<const N: usize>(
        recent_snapshot: &[RecentSnapshotSlot; N],
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

    /// The pre-hoist `recent_creation_is_live`, verbatim.
    fn legacy_creation_is_live<const N: usize>(
        ordinal: usize,
        candidate: &RecentUtxoChange,
        recent_snapshot: &[RecentSnapshotSlot; N],
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

    /// Builds the scan the way the engine used to, one predicate per query.
    fn legacy_scan<const N: usize>(slots: [RecentSnapshotSlot; N]) -> RecentSnapshotScan<N> {
        let mut live = [true; N];
        for (ordinal, slot) in slots.iter().enumerate() {
            let (Some(change), Some(destination)) = (slot.change(), live.get_mut(ordinal)) else {
                continue;
            };
            *destination = legacy_creation_is_live(ordinal, change, &slots);
        }
        RecentSnapshotScan::from_parts_for_tests(slots, live, legacy_semantically_valid(&slots))
    }

    /// One equivalence fixture: label, store entries, snapshot, floor, cursor.
    type HoistCase = (
        &'static str,
        Vec<(usize, TransparentUtxo)>,
        [RecentSnapshotSlot; 4],
        u32,
        usize,
    );

    /// Every case the hoist could have changed, run both ways.
    fn hoist_equivalence_cases() -> Vec<HoistCase> {
        let key = address(1);
        let first = utxo(1, 10);
        let second = utxo(2, 11);
        let third = utxo(3, 12);
        let recent_created = utxo(4, 13);
        let also_created = utxo(5, 14);
        vec![
            ("empty", vec![], [RecentSnapshotSlot::dummy(); 4], 0, 0),
            (
                "no-match",
                vec![(0, first)],
                [
                    RecentSnapshotSlot::created(address(9), recent_created),
                    RecentSnapshotSlot::dummy(),
                    RecentSnapshotSlot::dummy(),
                    RecentSnapshotSlot::dummy(),
                ],
                99,
                0,
            ),
            (
                "single-match",
                vec![(0, first)],
                [
                    RecentSnapshotSlot::created(key, recent_created),
                    RecentSnapshotSlot::dummy(),
                    RecentSnapshotSlot::dummy(),
                    RecentSnapshotSlot::dummy(),
                ],
                0,
                0,
            ),
            (
                "pagination-first-page",
                vec![(0, first), (1, second), (2, third)],
                [
                    RecentSnapshotSlot::created(key, recent_created),
                    RecentSnapshotSlot::created(key, also_created),
                    RecentSnapshotSlot::dummy(),
                    RecentSnapshotSlot::dummy(),
                ],
                0,
                0,
            ),
            (
                "pagination-continued",
                vec![(0, first), (1, second), (2, third)],
                [
                    RecentSnapshotSlot::created(key, recent_created),
                    RecentSnapshotSlot::created(key, also_created),
                    RecentSnapshotSlot::dummy(),
                    RecentSnapshotSlot::dummy(),
                ],
                0,
                2,
            ),
            (
                "spent-later",
                vec![(0, first)],
                [
                    RecentSnapshotSlot::created(key, recent_created),
                    RecentSnapshotSlot::spent(key, recent_created),
                    RecentSnapshotSlot::created(key, also_created),
                    RecentSnapshotSlot::dummy(),
                ],
                0,
                0,
            ),
            (
                "recent-spend-of-finalized",
                vec![(0, first), (1, second)],
                [
                    RecentSnapshotSlot::spent(key, first),
                    RecentSnapshotSlot::dummy(),
                    RecentSnapshotSlot::dummy(),
                    RecentSnapshotSlot::dummy(),
                ],
                0,
                0,
            ),
            (
                "duplicate-outpoint",
                vec![],
                [
                    RecentSnapshotSlot::created(key, recent_created),
                    RecentSnapshotSlot::created(key, recent_created),
                    RecentSnapshotSlot::dummy(),
                    RecentSnapshotSlot::dummy(),
                ],
                0,
                0,
            ),
            // One outpoint under two addresses. Grouping by outpoint alone puts
            // these in one run, so the run must still reject on the address
            // comparison rather than on its length.
            (
                "same-outpoint-different-addresses",
                vec![(0, first)],
                [
                    RecentSnapshotSlot::created(key, recent_created),
                    RecentSnapshotSlot::created(address(9), recent_created),
                    RecentSnapshotSlot::dummy(),
                    RecentSnapshotSlot::dummy(),
                ],
                0,
                0,
            ),
            // The create-then-spend pair inverted. Ordinal order is the whole
            // predicate here, so it must survive being sorted by outpoint.
            (
                "spend-then-recreate",
                vec![(0, first)],
                [
                    RecentSnapshotSlot::spent(key, recent_created),
                    RecentSnapshotSlot::created(key, recent_created),
                    RecentSnapshotSlot::dummy(),
                    RecentSnapshotSlot::dummy(),
                ],
                0,
                0,
            ),
            // A third occurrence of one outpoint, which the run-length arm
            // rejects without comparing fields. The oracle rejects it through
            // the two ordered pairs that contradict each other.
            (
                "outpoint-restated-three-times",
                vec![(0, first)],
                [
                    RecentSnapshotSlot::created(key, recent_created),
                    RecentSnapshotSlot::spent(key, recent_created),
                    RecentSnapshotSlot::created(key, recent_created),
                    RecentSnapshotSlot::dummy(),
                ],
                0,
                0,
            ),
            // No dummy slots at all, so every ordinal participates in both
            // facts and none is skipped by the occupancy filter.
            (
                "fully-populated",
                vec![(0, first), (1, second)],
                [
                    RecentSnapshotSlot::created(key, recent_created),
                    RecentSnapshotSlot::spent(key, recent_created),
                    RecentSnapshotSlot::created(key, also_created),
                    RecentSnapshotSlot::spent(key, first),
                ],
                0,
                0,
            ),
        ]
    }

    /// Every distinguishable slot value, for exhaustive snapshot enumeration.
    ///
    /// Two addresses and three outpoints that disagree in the txid and in the
    /// output index separately, so an ordering that ignores either field is
    /// distinguishable, plus the dummy.
    fn exhaustive_slot_alphabet() -> Vec<RecentSnapshotSlot> {
        let mut alphabet = vec![RecentSnapshotSlot::dummy()];
        for address_byte in [1, 9] {
            for outpoint in [
                utxo_with_outpoint(1, 1, 10),
                utxo_with_outpoint(1, 2, 10),
                utxo_with_outpoint(2, 1, 10),
            ] {
                alphabet.push(RecentSnapshotSlot::created(address(address_byte), outpoint));
                alphabet.push(RecentSnapshotSlot::spent(address(address_byte), outpoint));
            }
        }
        alphabet
    }

    /// Sorting derives both facts bit-identically on every three-slot snapshot.
    ///
    /// The fixtures below name the interesting cases; this closes the gap by
    /// enumerating the whole three-slot domain over an alphabet rich enough to
    /// separate outpoint, address, kind, ordinal, and occupancy. Every
    /// duplication and ordering pattern the run-grouping can encounter appears
    /// here, checked against the verbatim pre-hoist predicates.
    #[test]
    fn every_three_slot_snapshot_derives_the_same_facts_as_the_oracles() {
        let alphabet = exhaustive_slot_alphabet();
        let mut checked = 0_usize;
        for first in &alphabet {
            for second in &alphabet {
                for third in &alphabet {
                    let slots = [*first, *second, *third];
                    assert_eq!(
                        RecentSnapshotScan::from_slots(slots),
                        legacy_scan(slots),
                        "{checked}"
                    );
                    checked += 1;
                }
            }
        }
        assert_eq!(checked, alphabet.len().pow(3));
    }

    /// The precomputed facts equal the predicates they replaced, case by case.
    #[test]
    fn hoisted_snapshot_facts_match_the_per_query_predicates() {
        for (label, _, recent, _, _) in hoist_equivalence_cases() {
            assert_eq!(
                RecentSnapshotScan::from_slots(recent),
                legacy_scan(recent),
                "{label}"
            );
        }
    }

    /// Identical pages and cursors whichever derivation the engine is handed.
    #[test]
    fn hoisted_and_per_query_derivations_produce_identical_results(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let key = address(1);
        for (label, entries, recent, minimum_height, cursor) in hoist_equivalence_cases() {
            let query = UtxoQuery::new(key, minimum_height);
            let mut hoisted_engine = engine_with(&entries)?;
            let hoisted = run_with_scan(
                &mut hoisted_engine,
                &query,
                cursor,
                &RecentSnapshotScan::from_slots(recent),
            )?;
            let mut legacy_engine = engine_with(&entries)?;
            let legacy = run_with_scan(&mut legacy_engine, &query, cursor, &legacy_scan(recent))?;

            assert_eq!(hoisted.page(), legacy.page(), "{label}");
            assert_eq!(hoisted.next_cursor(), legacy.next_cursor(), "{label}");
            assert_eq!(
                hoisted_engine.store.read_slots(),
                legacy_engine.store.read_slots(),
                "{label}"
            );
        }
        Ok(())
    }

    fn run_with_scan<const N: usize>(
        engine: &mut TestEngine,
        query: &UtxoQuery,
        cursor: usize,
        scan: &RecentSnapshotScan<N>,
    ) -> Result<QueryExecution<RESPONSE_SLOTS>, TraceError> {
        let mut trace = TraceRecorder::new();
        open_engine_execution(&mut trace)?;
        for ordinal in 0..N {
            trace.record_recent_snapshot_read(ordinal)?;
        }
        trace.complete_recent_snapshot_scan(N)?;
        engine.execute_from(query, cursor, scan, &mut trace)
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
