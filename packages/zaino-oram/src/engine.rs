use crate::{
    profile::{CompiledQueryShape, PrivacyProfile, PrivacyProfileError},
    records::{QueryOutcome, TransparentUtxo, UtxoQuery, UtxoResultPage},
    store::{ObliviousStore, StoreSlot},
};

/// One public-class logical operation in the modeled query schedule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AccessKind {
    /// One store call at a public, profile-fixed ordinal.
    StoreRead {
        /// Public logical slot ordinal.
        slot: usize,
    },
}

/// A key-free model of the logical store-call schedule for one query.
///
/// The model deliberately records no address, outcome, count, or protected
/// value. It does not measure physical work: instruction, allocation, memory,
/// page, timing, and packet equivalence remain later release-binary gates.
#[derive(Debug, Clone, PartialEq, Eq)]
struct AccessTrace {
    operations: Vec<AccessKind>,
}

impl AccessTrace {
    fn with_read_capacity(reads: usize) -> Self {
        Self {
            operations: Vec::with_capacity(reads),
        }
    }

    fn record_store_read(&mut self, slot: usize) {
        self.operations.push(AccessKind::StoreRead { slot });
    }

    fn operations(&self) -> &[AccessKind] {
        &self.operations
    }

    fn store_read_count(&self) -> usize {
        self.operations.len()
    }
}

/// The fixed page and modeled logical schedule produced by one query.
struct QueryExecution<const RESPONSE_SLOTS: usize> {
    page: UtxoResultPage<RESPONSE_SLOTS>,
    trace: AccessTrace,
}

impl<const RESPONSE_SLOTS: usize> QueryExecution<RESPONSE_SLOTS> {
    fn page(&self) -> &UtxoResultPage<RESPONSE_SLOTS> {
        &self.page
    }

    fn trace(&self) -> &AccessTrace {
        &self.trace
    }
}

/// A synchronous transparent-UTXO logical-schedule model.
///
/// This foundation guarantees only an exact logical store-call sequence and
/// fixed Rust data shapes. It does not claim data-independent instructions,
/// memory accesses, allocations, or timing.
struct PrivateQueryEngine<S, const RESPONSE_SLOTS: usize, const ENVELOPE_BYTES: usize> {
    store: S,
    shape: CompiledQueryShape<RESPONSE_SLOTS, ENVELOPE_BYTES>,
}

impl<S, const RESPONSE_SLOTS: usize, const ENVELOPE_BYTES: usize>
    PrivateQueryEngine<S, RESPONSE_SLOTS, ENVELOPE_BYTES>
where
    S: ObliviousStore,
{
    fn new(
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

    fn profile(&self) -> &PrivacyProfile {
        self.shape.profile()
    }

    /// Executes the complete per-key slot domain and returns a fixed page.
    ///
    /// Store errors never short-circuit later calls. They become a protected
    /// [`QueryOutcome::StoreFailure`] after the configured call sequence; the
    /// later runtime must also latch a redacted health fault and fail readiness.
    fn execute(&mut self, query: &UtxoQuery) -> QueryExecution<RESPONSE_SLOTS> {
        let mut trace = AccessTrace::with_read_capacity(self.profile().store_reads());
        let mut page = UtxoResultPage::empty();
        let mut real_slots = 0;
        let mut result_budget_exceeded = false;
        let mut store_failed = false;

        for slot in 0..self.profile().store_reads() {
            trace.record_store_read(slot);
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
                && candidate.height() >= query.minimum_height();
            if matches {
                if real_slots < self.profile().response_slots() {
                    page.set_slot(real_slots, candidate);
                    real_slots += 1;
                } else {
                    result_budget_exceeded = true;
                }
            }
        }

        let outcome = if store_failed {
            page = UtxoResultPage::empty();
            QueryOutcome::StoreFailure
        } else if !query.domain_valid() {
            QueryOutcome::InvalidDomain
        } else if result_budget_exceeded {
            QueryOutcome::ResultBudgetExceeded
        } else {
            QueryOutcome::Complete
        };
        page.set_outcome(outcome);
        QueryExecution { page, trace }
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
        PrivacyProfile::new("unit-test-v1", 4, RESPONSE_SLOTS, ENVELOPE_BYTES, 2)
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

    fn expected_schedule() -> [AccessKind; 4] {
        [
            AccessKind::StoreRead { slot: 0 },
            AccessKind::StoreRead { slot: 1 },
            AccessKind::StoreRead { slot: 2 },
            AccessKind::StoreRead { slot: 3 },
        ]
    }

    fn assert_fixed_logical_schedule(
        execution: &QueryExecution<RESPONSE_SLOTS>,
        expected_outcome: QueryOutcome,
        expected_real_count: usize,
    ) {
        assert_eq!(execution.page().outcome(), expected_outcome);
        assert_eq!(execution.page().slots().len(), RESPONSE_SLOTS);
        assert_eq!(execution.page().real_count(), expected_real_count);
        assert_eq!(execution.trace().store_read_count(), 4);
        assert_eq!(execution.trace().operations(), &expected_schedule());
    }

    #[test]
    fn secret_cases_have_the_same_logical_store_call_schedule(
    ) -> Result<(), PlaintextMockStoreError> {
        let key = address(1);

        let mut hit = engine_with(&[(0, utxo(1, 10))])?;
        let hit_execution = hit.execute(&UtxoQuery::new(key, 0));
        assert_fixed_logical_schedule(&hit_execution, QueryOutcome::Complete, 1);

        let mut miss = engine_with(&[])?;
        let miss_execution = miss.execute(&UtxoQuery::new(address(9), 0));
        assert_fixed_logical_schedule(&miss_execution, QueryOutcome::Complete, 0);

        let mut filtered = engine_with(&[(0, utxo(1, 10))])?;
        let filtered_execution = filtered.execute(&UtxoQuery::new(key, 11));
        assert_fixed_logical_schedule(&filtered_execution, QueryOutcome::Complete, 0);

        let mut exactly_full = engine_with(&[(0, utxo(1, 10)), (1, utxo(2, 11))])?;
        let exactly_full_execution = exactly_full.execute(&UtxoQuery::new(key, 0));
        assert_fixed_logical_schedule(
            &exactly_full_execution,
            QueryOutcome::Complete,
            RESPONSE_SLOTS,
        );

        let mut cap_hit = engine_with(&[(0, utxo(1, 10)), (1, utxo(2, 11)), (2, utxo(3, 12))])?;
        let cap_hit_execution = cap_hit.execute(&UtxoQuery::new(key, 0));
        assert_fixed_logical_schedule(
            &cap_hit_execution,
            QueryOutcome::ResultBudgetExceeded,
            RESPONSE_SLOTS,
        );

        let mut late = engine_with(&[(3, utxo(4, 13))])?;
        let late_execution = late.execute(&UtxoQuery::new(key, 0));
        assert_fixed_logical_schedule(&late_execution, QueryOutcome::Complete, 1);

        for engine in [&hit, &miss, &filtered, &exactly_full, &cap_hit, &late] {
            assert_eq!(engine.store.read_slots(), &expected_schedule_slots());
        }
        assert_eq!(hit_execution.trace(), miss_execution.trace());
        assert_eq!(hit_execution.trace(), filtered_execution.trace());
        assert_eq!(hit_execution.trace(), exactly_full_execution.trace());
        assert_eq!(hit_execution.trace(), cap_hit_execution.trace());
        assert_eq!(hit_execution.trace(), late_execution.trace());
        Ok(())
    }

    fn expected_schedule_slots() -> [usize; 4] {
        [0, 1, 2, 3]
    }

    #[test]
    fn invalid_domain_and_each_store_failure_ordinal_complete_the_schedule() {
        let key = address(1);
        let invalid_query = UtxoQuery::from_untrusted_address_key(&[7; 31], 0);
        let mut invalid = engine_with(&[(0, utxo(1, 10))])
            .expect("unit-test mock entries fit their bounded slot domain");
        let invalid_execution = invalid.execute(&invalid_query);
        assert_fixed_logical_schedule(&invalid_execution, QueryOutcome::InvalidDomain, 0);
        assert_eq!(invalid.store.read_slots(), &expected_schedule_slots());

        for failing_ordinal in 1..=4 {
            let mut store = PlaintextMockStore::new(4, 1);
            store
                .insert(&key, 0, &utxo(1, 10))
                .expect("unit-test mock entry fits its bounded slot domain");
            let store = store.with_failure_on_read(failing_ordinal);
            let mut failing = TestEngine::new(store, shape())
                .expect("mock and profile expose the same complete slot domain");
            let failure_execution = failing.execute(&UtxoQuery::new(key, 0));
            assert_fixed_logical_schedule(&failure_execution, QueryOutcome::StoreFailure, 0);
            assert_eq!(failing.store.read_slots(), &expected_schedule_slots());
            assert_eq!(invalid_execution.trace(), failure_execution.trace());
        }
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
