use std::fmt;

/// The public completion shape modeled for one offline query round.
///
/// This describes application-envelope completion only. It is not evidence
/// about protobuf, gRPC, HTTP/2, TLS, or packet framing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CompletionShape {
    /// One fixed request envelope completes with one fixed response envelope.
    UnaryFixedEnvelope,
}

/// Version of the ordered logical runtime schedule bound into each profile.
pub(super) const RUNTIME_SCHEDULE_VERSION: u16 = 1;

/// One public, ordered phase in a successfully protected query round.
///
/// These phases model logical control-plane work only. They do not establish
/// equal instructions, allocations, memory accesses, timing, or transport
/// behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RuntimePhase {
    /// The fixed request envelope was opened and canonically decoded.
    RequestDecode,
    /// One clock read and both server-owned output nonces were acquired.
    NonceAcquisition,
    /// One continuation open and the complete semantic comparison set ran.
    TokenOpen,
    /// One real or cover replay-guard operation ran.
    ReplayGuard,
    /// Runtime and checkpoint readiness were selected without early return.
    ReadinessSelect,
    /// The engine began its complete configured store schedule.
    EngineExecution,
    /// The fixed result page was normalized to its protected outcome.
    ResultNormalization,
    /// One real or cover continuation token was issued.
    TokenIssue,
    /// One fixed response was built, encoded, and protected.
    ResponseEncode,
    /// The unary fixed-envelope round completed.
    Completion,
}

impl RuntimePhase {
    pub(super) const COUNT: usize = 10;

    const fn ordinal(self) -> usize {
        match self {
            Self::RequestDecode => 0,
            Self::NonceAcquisition => 1,
            Self::TokenOpen => 2,
            Self::ReplayGuard => 3,
            Self::ReadinessSelect => 4,
            Self::EngineExecution => 5,
            Self::ResultNormalization => 6,
            Self::TokenIssue => 7,
            Self::ResponseEncode => 8,
            Self::Completion => 9,
        }
    }
}

/// The complete logical-access budget for one fixed-profile query round.
///
/// Frame and byte fields model application envelopes, not network frames or
/// transport bytes. Allocation counts are explicit logical allocations, not
/// measurements from the Rust allocator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct QueryAccessBudget {
    store_reads: usize,
    envelope_bytes: usize,
}

impl QueryAccessBudget {
    /// Builds the only logical query shape currently supported by the engine.
    ///
    /// The query is read-only, performs no query-derived source calls or
    /// explicit logical allocations, and models exactly one fixed request and
    /// response application envelope.
    pub(super) const fn read_only_unary_fixed_envelope(
        store_reads: usize,
        envelope_bytes: usize,
    ) -> Self {
        Self {
            store_reads,
            envelope_bytes,
        }
    }

    /// Returns the exact logical store-read count.
    pub(super) const fn store_reads(&self) -> usize {
        self.store_reads
    }

    /// Returns the exact logical store-write count.
    pub(super) const fn store_writes(&self) -> usize {
        0
    }

    /// Returns the exact modeled logical-allocation count.
    pub(super) const fn allocations(&self) -> usize {
        0
    }

    /// Returns the exact query-derived source-call count.
    pub(super) const fn source_calls(&self) -> usize {
        0
    }

    /// Returns the exact logical replay-state lookup count.
    pub(super) const fn replay_reads(&self) -> usize {
        1
    }

    /// Returns the exact real-or-cover replay-state write-back count.
    pub(super) const fn replay_writes(&self) -> usize {
        1
    }

    /// Returns the modeled request application-frame count.
    pub(super) const fn request_frames(&self) -> usize {
        1
    }

    /// Returns the modeled response application-frame count.
    pub(super) const fn response_frames(&self) -> usize {
        1
    }

    /// Returns the modeled request application-envelope byte count.
    pub(super) const fn request_bytes(&self) -> usize {
        self.envelope_bytes
    }

    /// Returns the modeled response application-envelope byte count.
    pub(super) const fn response_bytes(&self) -> usize {
        self.envelope_bytes
    }

    /// Returns the public completion shape.
    pub(super) const fn completion(&self) -> CompletionShape {
        CompletionShape::UnaryFixedEnvelope
    }

    /// Returns the exact ordered runtime-phase count.
    pub(super) const fn runtime_phases(&self) -> usize {
        RuntimePhase::COUNT
    }
}

/// An allocation-free, key-free logical trace for one offline query round.
///
/// The trace contains only profile-public counts and a public completion
/// shape. It deliberately contains no query key, token, result count, private
/// outcome, record, or source identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct AccessTrace {
    store_reads: usize,
    store_writes: usize,
    allocations: usize,
    source_calls: usize,
    replay_reads: usize,
    replay_writes: usize,
    request_frames: usize,
    response_frames: usize,
    request_bytes: usize,
    response_bytes: usize,
    runtime_phases: usize,
    completion: CompletionShape,
}

impl AccessTrace {
    /// Returns the completed logical store-read count.
    #[cfg(test)]
    pub(super) const fn store_reads(&self) -> usize {
        self.store_reads
    }

    /// Returns the completed logical store-write count.
    #[cfg(test)]
    pub(super) const fn store_writes(&self) -> usize {
        self.store_writes
    }

    /// Returns the completed modeled allocation count.
    #[cfg(test)]
    pub(super) const fn allocations(&self) -> usize {
        self.allocations
    }

    /// Returns the completed query-derived source-call count.
    #[cfg(test)]
    pub(super) const fn source_calls(&self) -> usize {
        self.source_calls
    }

    /// Returns the completed logical replay-state lookup count.
    #[cfg(test)]
    pub(super) const fn replay_reads(&self) -> usize {
        self.replay_reads
    }

    /// Returns the completed logical replay-state write-back count.
    #[cfg(test)]
    pub(super) const fn replay_writes(&self) -> usize {
        self.replay_writes
    }

    /// Returns the modeled request application-frame count.
    #[cfg(test)]
    pub(super) const fn request_frames(&self) -> usize {
        self.request_frames
    }

    /// Returns the modeled response application-frame count.
    #[cfg(test)]
    pub(super) const fn response_frames(&self) -> usize {
        self.response_frames
    }

    /// Returns the modeled request application-envelope bytes.
    #[cfg(test)]
    pub(super) const fn request_bytes(&self) -> usize {
        self.request_bytes
    }

    /// Returns the modeled response application-envelope bytes.
    #[cfg(test)]
    pub(super) const fn response_bytes(&self) -> usize {
        self.response_bytes
    }

    /// Returns the completed ordered runtime-phase count.
    #[cfg(test)]
    pub(super) const fn runtime_phases(&self) -> usize {
        self.runtime_phases
    }

    /// Returns the completed public application-envelope shape.
    #[cfg(test)]
    pub(super) const fn completion(&self) -> CompletionShape {
        self.completion
    }
}

/// Builds one fixed logical trace without allocating.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(super) struct TraceRecorder {
    store_reads: usize,
    store_writes: usize,
    allocations: usize,
    source_calls: usize,
    replay_reads: usize,
    replay_writes: usize,
    request_frames: usize,
    response_frames: usize,
    request_bytes: usize,
    response_bytes: usize,
    next_read_ordinal: usize,
    next_runtime_phase: usize,
    completion: Option<CompletionShape>,
}

impl TraceRecorder {
    /// Builds an empty allocation-free recorder.
    pub(super) const fn new() -> Self {
        Self {
            store_reads: 0,
            store_writes: 0,
            allocations: 0,
            source_calls: 0,
            replay_reads: 0,
            replay_writes: 0,
            request_frames: 0,
            response_frames: 0,
            request_bytes: 0,
            response_bytes: 0,
            next_read_ordinal: 0,
            next_runtime_phase: 0,
            completion: None,
        }
    }

    /// Records the next phase in the profile's public logical runtime order.
    pub(super) fn record_runtime_phase(&mut self, phase: RuntimePhase) -> Result<(), TraceError> {
        let actual = phase.ordinal();
        if actual != self.next_runtime_phase {
            return Err(TraceError::RuntimePhaseOrder {
                expected: self.next_runtime_phase,
                actual,
            });
        }
        self.next_runtime_phase =
            increment(self.next_runtime_phase, TraceDimension::RuntimePhases)?;
        Ok(())
    }

    /// Records one fixed replay lookup and one real-or-cover write-back.
    pub(super) fn record_replay_access(&mut self) -> Result<(), TraceError> {
        self.replay_reads = increment(self.replay_reads, TraceDimension::ReplayReads)?;
        self.replay_writes = increment(self.replay_writes, TraceDimension::ReplayWrites)?;
        Ok(())
    }

    /// Records the next public, sequential logical store-read ordinal.
    pub(super) fn record_store_read(&mut self, ordinal: usize) -> Result<(), TraceError> {
        if ordinal != self.next_read_ordinal {
            return Err(TraceError::StoreReadOrdinal {
                expected: self.next_read_ordinal,
                actual: ordinal,
            });
        }
        self.store_reads = increment(self.store_reads, TraceDimension::StoreReads)?;
        self.next_read_ordinal =
            increment(self.next_read_ordinal, TraceDimension::StoreReadOrdinal)?;
        Ok(())
    }

    /// Records one explicit logical store write.
    fn record_store_write(&mut self) -> Result<(), TraceError> {
        self.store_writes = increment(self.store_writes, TraceDimension::StoreWrites)?;
        Ok(())
    }

    /// Records one explicit modeled logical allocation.
    fn record_allocation(&mut self) -> Result<(), TraceError> {
        self.allocations = increment(self.allocations, TraceDimension::Allocations)?;
        Ok(())
    }

    /// Records one query-derived call outside the protected projection.
    fn record_source_call(&mut self) -> Result<(), TraceError> {
        self.source_calls = increment(self.source_calls, TraceDimension::SourceCalls)?;
        Ok(())
    }

    /// Records one modeled request application envelope.
    pub(super) fn record_request_frame(&mut self, bytes: usize) -> Result<(), TraceError> {
        let frames = increment(self.request_frames, TraceDimension::RequestFrames)?;
        let total_bytes = add(self.request_bytes, bytes, TraceDimension::RequestBytes)?;
        self.request_frames = frames;
        self.request_bytes = total_bytes;
        Ok(())
    }

    /// Records one modeled response application envelope.
    pub(super) fn record_response_frame(&mut self, bytes: usize) -> Result<(), TraceError> {
        let frames = increment(self.response_frames, TraceDimension::ResponseFrames)?;
        let total_bytes = add(self.response_bytes, bytes, TraceDimension::ResponseBytes)?;
        self.response_frames = frames;
        self.response_bytes = total_bytes;
        Ok(())
    }

    /// Records the public completion shape exactly once.
    pub(super) fn record_completion(
        &mut self,
        completion: CompletionShape,
    ) -> Result<(), TraceError> {
        if self.completion.is_some() {
            return Err(TraceError::CompletionAlreadyRecorded);
        }
        self.completion = Some(completion);
        Ok(())
    }

    /// Validates every modeled dimension and returns the completed trace.
    pub(super) fn finish(self, expected: QueryAccessBudget) -> Result<AccessTrace, TraceError> {
        validate_dimension(
            TraceDimension::StoreReads,
            expected.store_reads(),
            self.store_reads,
        )?;
        validate_dimension(
            TraceDimension::StoreWrites,
            expected.store_writes(),
            self.store_writes,
        )?;
        validate_dimension(
            TraceDimension::Allocations,
            expected.allocations(),
            self.allocations,
        )?;
        validate_dimension(
            TraceDimension::SourceCalls,
            expected.source_calls(),
            self.source_calls,
        )?;
        validate_dimension(
            TraceDimension::ReplayReads,
            expected.replay_reads(),
            self.replay_reads,
        )?;
        validate_dimension(
            TraceDimension::ReplayWrites,
            expected.replay_writes(),
            self.replay_writes,
        )?;
        validate_dimension(
            TraceDimension::RequestFrames,
            expected.request_frames(),
            self.request_frames,
        )?;
        validate_dimension(
            TraceDimension::ResponseFrames,
            expected.response_frames(),
            self.response_frames,
        )?;
        validate_dimension(
            TraceDimension::RequestBytes,
            expected.request_bytes(),
            self.request_bytes,
        )?;
        validate_dimension(
            TraceDimension::ResponseBytes,
            expected.response_bytes(),
            self.response_bytes,
        )?;
        validate_dimension(
            TraceDimension::RuntimePhases,
            expected.runtime_phases(),
            self.next_runtime_phase,
        )?;

        let completion = self.completion.ok_or(TraceError::MissingCompletion)?;
        if completion != expected.completion() {
            return Err(TraceError::CompletionMismatch {
                expected: expected.completion(),
                actual: completion,
            });
        }

        Ok(AccessTrace {
            store_reads: self.store_reads,
            store_writes: self.store_writes,
            allocations: self.allocations,
            source_calls: self.source_calls,
            replay_reads: self.replay_reads,
            replay_writes: self.replay_writes,
            request_frames: self.request_frames,
            response_frames: self.response_frames,
            request_bytes: self.request_bytes,
            response_bytes: self.response_bytes,
            runtime_phases: self.next_runtime_phase,
            completion,
        })
    }
}

/// One public trace dimension used in typed model failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum TraceDimension {
    /// Logical store reads.
    StoreReads,
    /// Logical store writes.
    StoreWrites,
    /// Sequential store-read ordinal.
    StoreReadOrdinal,
    /// Explicit modeled logical allocations.
    Allocations,
    /// Query-derived source calls.
    SourceCalls,
    /// Logical replay-state lookups.
    ReplayReads,
    /// Logical real-or-cover replay-state write-backs.
    ReplayWrites,
    /// Modeled request application frames.
    RequestFrames,
    /// Modeled response application frames.
    ResponseFrames,
    /// Modeled request application-envelope bytes.
    RequestBytes,
    /// Modeled response application-envelope bytes.
    ResponseBytes,
    /// Ordered logical runtime phases.
    RuntimePhases,
}

impl fmt::Display for TraceDimension {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::StoreReads => "store reads",
            Self::StoreWrites => "store writes",
            Self::StoreReadOrdinal => "store-read ordinal",
            Self::Allocations => "modeled allocations",
            Self::SourceCalls => "source calls",
            Self::ReplayReads => "replay reads",
            Self::ReplayWrites => "replay writes",
            Self::RequestFrames => "modeled request frames",
            Self::ResponseFrames => "modeled response frames",
            Self::RequestBytes => "modeled request bytes",
            Self::ResponseBytes => "modeled response bytes",
            Self::RuntimePhases => "ordered runtime phases",
        };
        f.write_str(label)
    }
}

/// A logical trace violated its compiled public budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum TraceError {
    /// Store reads did not use the complete sequential public slot domain.
    StoreReadOrdinal {
        /// Next required ordinal.
        expected: usize,
        /// Ordinal the engine attempted.
        actual: usize,
    },
    /// Runtime phases were recorded out of their fixed public order.
    RuntimePhaseOrder {
        /// Next required phase ordinal.
        expected: usize,
        /// Phase ordinal the runtime attempted.
        actual: usize,
    },
    /// One public counter overflowed.
    CounterOverflow {
        /// Counter that overflowed.
        dimension: TraceDimension,
    },
    /// A public dimension differed from its compiled budget.
    BudgetMismatch {
        /// Dimension that differed.
        dimension: TraceDimension,
        /// Compiled public count.
        expected: usize,
        /// Recorded public count.
        actual: usize,
    },
    /// The recorder was completed more than once.
    CompletionAlreadyRecorded,
    /// The recorder was finished without a completion shape.
    MissingCompletion,
    /// The completion shape differed from the compiled profile.
    CompletionMismatch {
        /// Compiled public completion shape.
        expected: CompletionShape,
        /// Recorded public completion shape.
        actual: CompletionShape,
    },
}

impl fmt::Display for TraceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StoreReadOrdinal { expected, actual } => write!(
                f,
                "logical store read ordinal {actual} does not match next public ordinal {expected}"
            ),
            Self::RuntimePhaseOrder { expected, actual } => write!(
                f,
                "logical runtime phase {actual} does not match next public phase {expected}"
            ),
            Self::CounterOverflow { dimension } => {
                write!(f, "logical trace {dimension} counter overflowed")
            }
            Self::BudgetMismatch {
                dimension,
                expected,
                actual,
            } => write!(
                f,
                "logical trace expected {expected} {dimension}; recorded {actual}"
            ),
            Self::CompletionAlreadyRecorded => {
                f.write_str("logical trace completion was already recorded")
            }
            Self::MissingCompletion => f.write_str("logical trace completion is missing"),
            Self::CompletionMismatch { expected, actual } => write!(
                f,
                "logical trace completion {actual:?} does not match {expected:?}"
            ),
        }
    }
}

impl std::error::Error for TraceError {}

fn increment(value: usize, dimension: TraceDimension) -> Result<usize, TraceError> {
    add(value, 1, dimension)
}

fn add(value: usize, amount: usize, dimension: TraceDimension) -> Result<usize, TraceError> {
    value
        .checked_add(amount)
        .ok_or(TraceError::CounterOverflow { dimension })
}

fn validate_dimension(
    dimension: TraceDimension,
    expected: usize,
    actual: usize,
) -> Result<(), TraceError> {
    if expected != actual {
        return Err(TraceError::BudgetMismatch {
            dimension,
            expected,
            actual,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const ENVELOPE_BYTES: usize = 128;

    const fn budget() -> QueryAccessBudget {
        QueryAccessBudget::read_only_unary_fixed_envelope(2, ENVELOPE_BYTES)
    }

    fn record_prefix(recorder: &mut TraceRecorder) -> Result<(), TraceError> {
        recorder.record_runtime_phase(RuntimePhase::RequestDecode)?;
        recorder.record_runtime_phase(RuntimePhase::NonceAcquisition)?;
        recorder.record_runtime_phase(RuntimePhase::TokenOpen)?;
        recorder.record_replay_access()?;
        recorder.record_runtime_phase(RuntimePhase::ReplayGuard)?;
        recorder.record_runtime_phase(RuntimePhase::ReadinessSelect)?;
        recorder.record_runtime_phase(RuntimePhase::EngineExecution)
    }

    fn record_suffix(recorder: &mut TraceRecorder) -> Result<(), TraceError> {
        recorder.record_runtime_phase(RuntimePhase::ResultNormalization)?;
        recorder.record_runtime_phase(RuntimePhase::TokenIssue)?;
        recorder.record_runtime_phase(RuntimePhase::ResponseEncode)?;
        recorder.record_runtime_phase(RuntimePhase::Completion)
    }

    fn completed_trace() -> Result<AccessTrace, TraceError> {
        let mut recorder = TraceRecorder::new();
        recorder.record_request_frame(ENVELOPE_BYTES)?;
        record_prefix(&mut recorder)?;
        recorder.record_store_read(0)?;
        recorder.record_store_read(1)?;
        recorder.record_runtime_phase(RuntimePhase::ResultNormalization)?;
        recorder.record_runtime_phase(RuntimePhase::TokenIssue)?;
        recorder.record_runtime_phase(RuntimePhase::ResponseEncode)?;
        recorder.record_response_frame(ENVELOPE_BYTES)?;
        recorder.record_runtime_phase(RuntimePhase::Completion)?;
        recorder.record_completion(CompletionShape::UnaryFixedEnvelope)?;
        recorder.finish(budget())
    }

    #[test]
    fn recorder_finishes_an_exact_read_only_application_round() -> Result<(), TraceError> {
        let trace = completed_trace()?;
        assert_eq!(trace.store_reads(), 2);
        assert_eq!(trace.store_writes(), 0);
        assert_eq!(trace.allocations(), 0);
        assert_eq!(trace.source_calls(), 0);
        assert_eq!(trace.replay_reads(), 1);
        assert_eq!(trace.replay_writes(), 1);
        assert_eq!(trace.request_frames(), 1);
        assert_eq!(trace.response_frames(), 1);
        assert_eq!(trace.request_bytes(), ENVELOPE_BYTES);
        assert_eq!(trace.response_bytes(), ENVELOPE_BYTES);
        assert_eq!(trace.runtime_phases(), RuntimePhase::COUNT);
        assert_eq!(trace.completion(), CompletionShape::UnaryFixedEnvelope);
        Ok(())
    }

    #[test]
    fn recorder_rejects_nonsequential_reads_and_incomplete_budgets() -> Result<(), TraceError> {
        let mut wrong_ordinal = TraceRecorder::new();
        assert_eq!(
            wrong_ordinal.record_store_read(1),
            Err(TraceError::StoreReadOrdinal {
                expected: 0,
                actual: 1,
            })
        );

        let mut incomplete = TraceRecorder::new();
        incomplete.record_request_frame(ENVELOPE_BYTES)?;
        incomplete.record_store_read(0)?;
        incomplete.record_response_frame(ENVELOPE_BYTES)?;
        incomplete.record_completion(CompletionShape::UnaryFixedEnvelope)?;
        assert_eq!(
            incomplete.finish(budget()),
            Err(TraceError::BudgetMismatch {
                dimension: TraceDimension::StoreReads,
                expected: 2,
                actual: 1,
            })
        );
        Ok(())
    }

    #[test]
    fn recorder_validates_zero_write_allocation_and_source_budgets() -> Result<(), TraceError> {
        for record_extra in [
            TraceRecorder::record_store_write,
            TraceRecorder::record_allocation,
            TraceRecorder::record_source_call,
        ] {
            let mut recorder = TraceRecorder::new();
            recorder.record_request_frame(ENVELOPE_BYTES)?;
            record_prefix(&mut recorder)?;
            recorder.record_store_read(0)?;
            recorder.record_store_read(1)?;
            record_extra(&mut recorder)?;
            record_suffix(&mut recorder)?;
            recorder.record_response_frame(ENVELOPE_BYTES)?;
            recorder.record_completion(CompletionShape::UnaryFixedEnvelope)?;
            assert!(matches!(
                recorder.finish(budget()),
                Err(TraceError::BudgetMismatch { actual: 1, .. })
            ));
        }

        let mut duplicate_replay = TraceRecorder::new();
        duplicate_replay.record_request_frame(ENVELOPE_BYTES)?;
        record_prefix(&mut duplicate_replay)?;
        duplicate_replay.record_store_read(0)?;
        duplicate_replay.record_store_read(1)?;
        duplicate_replay.record_replay_access()?;
        record_suffix(&mut duplicate_replay)?;
        duplicate_replay.record_response_frame(ENVELOPE_BYTES)?;
        duplicate_replay.record_completion(CompletionShape::UnaryFixedEnvelope)?;
        assert_eq!(
            duplicate_replay.finish(budget()),
            Err(TraceError::BudgetMismatch {
                dimension: TraceDimension::ReplayReads,
                expected: 1,
                actual: 2,
            })
        );
        Ok(())
    }

    #[test]
    fn recorder_rejects_wrong_bytes_and_duplicate_or_missing_completion() -> Result<(), TraceError>
    {
        let mut wrong_bytes = TraceRecorder::new();
        wrong_bytes.record_request_frame(ENVELOPE_BYTES - 1)?;
        record_prefix(&mut wrong_bytes)?;
        wrong_bytes.record_store_read(0)?;
        wrong_bytes.record_store_read(1)?;
        record_suffix(&mut wrong_bytes)?;
        wrong_bytes.record_response_frame(ENVELOPE_BYTES)?;
        wrong_bytes.record_completion(CompletionShape::UnaryFixedEnvelope)?;
        assert_eq!(
            wrong_bytes.finish(budget()),
            Err(TraceError::BudgetMismatch {
                dimension: TraceDimension::RequestBytes,
                expected: ENVELOPE_BYTES,
                actual: ENVELOPE_BYTES - 1,
            })
        );

        let mut duplicate = TraceRecorder::new();
        duplicate.record_completion(CompletionShape::UnaryFixedEnvelope)?;
        assert_eq!(
            duplicate.record_completion(CompletionShape::UnaryFixedEnvelope),
            Err(TraceError::CompletionAlreadyRecorded)
        );

        let mut missing = TraceRecorder::new();
        missing.record_request_frame(ENVELOPE_BYTES)?;
        record_prefix(&mut missing)?;
        missing.record_store_read(0)?;
        missing.record_store_read(1)?;
        record_suffix(&mut missing)?;
        missing.record_response_frame(ENVELOPE_BYTES)?;
        assert_eq!(missing.finish(budget()), Err(TraceError::MissingCompletion));
        Ok(())
    }

    #[test]
    fn recorder_rejects_skipped_or_reordered_runtime_phases() {
        let mut skipped = TraceRecorder::new();
        assert_eq!(
            skipped.record_runtime_phase(RuntimePhase::TokenOpen),
            Err(TraceError::RuntimePhaseOrder {
                expected: 0,
                actual: 2,
            })
        );

        skipped
            .record_runtime_phase(RuntimePhase::RequestDecode)
            .expect("first runtime phase is valid");
        assert_eq!(
            skipped.record_runtime_phase(RuntimePhase::RequestDecode),
            Err(TraceError::RuntimePhaseOrder {
                expected: 1,
                actual: 0,
            })
        );
    }

    #[test]
    fn trace_debug_contains_only_public_shape_counts() -> Result<(), TraceError> {
        let secret_fixture = "address=tmSecret txid=deadbeef token=cursor outcome=hit";
        let debug = format!("{:?}", completed_trace()?);
        for secret in secret_fixture.split_whitespace() {
            assert!(!debug.contains(secret));
        }
        assert!(debug.contains("store_reads: 2"));
        assert!(debug.contains("request_bytes: 128"));
        Ok(())
    }
}
