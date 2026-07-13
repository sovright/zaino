use crate::{
    profile::{CompiledQueryShape, PrivacyProfile, PrivacyProfileError},
    records::{QueryOutcome, TransparentUtxo, UtxoQuery, UtxoResultPage},
    store::{ObliviousStore, StoreSlot},
    trace::{TraceError, TraceRecorder},
};

/// The fixed page and next logical store-slot cursor produced by one query.
pub(super) struct QueryExecution<const RESPONSE_SLOTS: usize> {
    page: UtxoResultPage<RESPONSE_SLOTS>,
    next_cursor: Option<usize>,
}

impl<const RESPONSE_SLOTS: usize> QueryExecution<RESPONSE_SLOTS> {
    pub(super) const fn page(&self) -> &UtxoResultPage<RESPONSE_SLOTS> {
        &self.page
    }

    const fn next_cursor(&self) -> Option<usize> {
        self.next_cursor
    }

    pub(super) fn into_parts(self) -> (UtxoResultPage<RESPONSE_SLOTS>, Option<usize>) {
        (self.page, self.next_cursor)
    }
}

/// A synchronous transparent-UTXO logical-schedule model.
///
/// This foundation guarantees only an exact logical store-call sequence and
/// fixed Rust data shapes. It does not claim data-independent instructions,
/// memory accesses, allocations, or timing.
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

    /// Executes the complete per-key slot domain and returns a fixed page.
    ///
    /// Store errors never short-circuit later calls. They become a protected
    /// [`QueryOutcome::StoreFailure`] after the configured call sequence; the
    /// later runtime must also latch a redacted health fault and fail readiness.
    ///
    /// `cursor` is an absolute logical store-slot ordinal. Every execution
    /// still reads the complete configured domain; matching slots below the
    /// cursor are ignored and the first omitted match becomes the next cursor.
    pub(super) fn execute_from(
        &mut self,
        query: &UtxoQuery,
        cursor: usize,
        trace: &mut TraceRecorder,
    ) -> Result<QueryExecution<RESPONSE_SLOTS>, TraceError> {
        let mut page = UtxoResultPage::empty();
        let mut real_slots = 0;
        let mut next_cursor = None;
        let mut store_failed = false;

        for slot in 0..self.profile().store_reads() {
            trace.record_store_read(slot)?;
            let store_slot = match self.store.read_slot(query.address_key(), slot) {
                Ok(store_slot) => store_slot,
                Err(_) => {
                    store_failed = true;
                    StoreSlot::dummy()
                }
            };
            let candidate: TransparentUtxo = *store_slot.record();
            let matches = store_slot.is_occupied()
                && query.domain_valid()
                && candidate.height() >= query.minimum_height()
                && slot >= cursor;
            if matches {
                if real_slots < self.profile().response_slots() {
                    page.set_slot(real_slots, candidate);
                    real_slots += 1;
                } else if next_cursor.is_none() {
                    next_cursor = Some(slot);
                }
            }
        }

        let outcome = if store_failed {
            page = UtxoResultPage::empty();
            next_cursor = None;
            QueryOutcome::StoreFailure
        } else if !query.domain_valid() {
            QueryOutcome::InvalidDomain
        } else if next_cursor.is_some() {
            QueryOutcome::ResultBudgetExceeded
        } else {
            QueryOutcome::Complete
        };
        page.set_outcome(outcome);
        Ok(QueryExecution { page, next_cursor })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        records::{AddressKey, ADDRESS_KEY_BYTES, TXID_BYTES},
        store::{PlaintextMockStore, PlaintextMockStoreError},
    };

    const RESPONSE_SLOTS: usize = 2;
    const ENVELOPE_BYTES: usize = 128;

    type TestEngine = PrivateQueryEngine<PlaintextMockStore, RESPONSE_SLOTS, ENVELOPE_BYTES>;

    fn profile() -> PrivacyProfile {
        PrivacyProfile::new("unit-test-v1", 4, RESPONSE_SLOTS, ENVELOPE_BYTES, 2, 60)
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
        TransparentUtxo::new(
            [byte; TXID_BYTES],
            u32::from(byte),
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
        engine.execute_from(query, cursor, &mut TraceRecorder::new())
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
