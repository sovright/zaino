//! Private typed `rostl` tables for the exclusive business-command worker.
//!
//! This remains a volatile, Linux-x86_64-only research backend. The portable
//! insertion core is kept here so its missing/duplicate schedule can be tested
//! on every host that enables `rostl-experimental`.
//! The Linux-only worker constructor is consumed only by the crate-internal
//! offline projection owner.

use std::{fmt, marker::PhantomData};

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use std::{fs, time::Instant};

use bytemuck::Pod;
use rostl_primitives::traits::Cmov;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use super::super::{AtomicStoreError, ExclusiveTwoTableExecutor};
use super::super::{BackendFailure, UniqueTable};
#[cfg(all(feature = "corpus-zaino", target_os = "linux", target_arch = "x86_64"))]
use super::AtomicWorkerBuildError;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use super::{AtomicQueueCapacity, AtomicWorker, AtomicWorkerError};
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use crate::layout::FixedProbeLayout;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use crate::records::{
    AddressDirectory, AddressEventPage, AddressKey, UtxoEvent, UtxoScriptClass, TXID_BYTES,
};
#[cfg(any(test, all(target_os = "linux", target_arch = "x86_64")))]
use crate::records::{PersistentAddressDirectory, PersistentAddressEventPage};
use crate::timing_equivalence::ArmMeasurement;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use crate::timing_equivalence::TimedSchedulerDelta;
use crate::timing_experiment::{Arm, PairedProbe};
use crate::{RostlTimingError, RostlTimingMode, RostlTimingRecordKind};

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use rand::Rng as _;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use rostl_oram::{
    circuit_oram::CircuitORAM, prelude::PositionType, recursive_oram::RecursivePositionMap,
};
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use std::panic::{catch_unwind, AssertUnwindSafe};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UniqueInsertDisposition {
    Inserted,
    Duplicate,
}

/// The raw outcome of one fixed two-access insertion.
///
/// This is deliberately a dumb record. It carries the secret-derived flags out
/// of the access path without interpreting them, so the access path itself
/// needs no control flow at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct UniqueInsertCommit {
    found_before: bool,
    found_after: bool,
    occupied_before: u64,
    occupied_records: u64,
}

impl UniqueInsertCommit {
    /// Classifies a completed commit.
    ///
    /// Every branch here runs after both ORAM accesses have already been
    /// performed, so none of them can change the schedule a host observer sees.
    fn classify(self) -> Result<UniqueInsertDisposition, RostlStoreError> {
        if self.found_after != self.found_before {
            return Err(RostlStoreError::FoundMismatch);
        }
        // A hit on an empty table is corruption rather than a duplicate. It is
        // rejected here, not before the second access, so that the corrupt and
        // healthy cases keep the same two-access schedule.
        if self.found_before && self.occupied_before == 0 {
            return Err(RostlStoreError::OccupancyInvariant);
        }
        if self.found_before {
            Ok(UniqueInsertDisposition::Duplicate)
        } else {
            Ok(UniqueInsertDisposition::Inserted)
        }
    }
}

trait FixedUniqueInsertAccess<T> {
    fn read_and_remap(&mut self, key: usize, value: &mut T) -> bool;

    fn write_or_insert_and_remap(&mut self, key: usize, value: T) -> bool;
}

/// Exact-upsert access wrappers are forced into the inspected symbol while the
/// already-qualified unique-insert wrappers retain their measured codegen.
trait FixedExactUpsertAccess<T> {
    fn exact_read_and_remap(&mut self, key: usize, value: &mut T) -> bool;

    fn exact_write_or_insert_and_remap(&mut self, key: usize, value: T) -> bool;
}

/// Decides from public state alone whether an insertion may be attempted.
///
/// This runs before the first access and deliberately cannot observe the
/// record. A full table therefore refuses every insertion with zero accesses
/// and a non-full table always performs exactly two, so occupancy — which is
/// public — is the only thing that selects between those two schedules.
fn admit_insert(occupied_records: u64, capacity: u64) -> Result<(), RostlStoreError> {
    if occupied_records > capacity {
        return Err(RostlStoreError::OccupancyInvariant);
    }
    if occupied_records == capacity {
        return Err(RostlStoreError::TableFull);
    }
    Ok(())
}

/// Performs the fixed two-access insertion.
///
/// The body contains no control flow: the secret hit/miss result reaches only
/// `Cmov` and integer arithmetic. Callers must first admit the insertion via
/// [`admit_insert`], which establishes `occupied_records < capacity`, and
/// [`RostlTable::new`] caps capacity at `u32::MAX`, so the increment cannot
/// overflow and needs no checked-arithmetic branch.
///
/// `#[inline(never)]` is load-bearing rather than a performance hint: it keeps
/// each monomorphization as its own symbol so `check-oram-codegen` can
/// disassemble the access path and reject any branch that could carry the
/// secret. One call per insertion is negligible against the measured fixed-work
/// floor of 13,440,092 logical accesses per request.
#[inline(never)]
fn fixed_unique_insert<T, A>(
    access: &mut A,
    key: usize,
    candidate: T,
    occupied_records: u64,
) -> UniqueInsertCommit
where
    T: Cmov + Copy + Default,
    A: FixedUniqueInsertAccess<T>,
{
    let mut prior = T::default();
    let found_before = access.read_and_remap(key, &mut prior);

    let mut selected = candidate;
    selected.cmov(&prior, found_before);
    let found_after = access.write_or_insert_and_remap(key, selected);

    UniqueInsertCommit {
        found_before,
        found_after,
        occupied_before: occupied_records,
        occupied_records: occupied_records + u64::from(!found_before),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExactUpsertDisposition {
    Inserted,
    Updated,
}

#[derive(Clone, Copy)]
struct InsertOrUpdateRequest<T> {
    expected_present: bool,
    expected_prior: T,
    replacement: T,
}

impl<T> InsertOrUpdateRequest<T>
where
    T: Default,
{
    fn insert(replacement: T) -> Self {
        Self {
            expected_present: false,
            expected_prior: T::default(),
            replacement,
        }
    }

    fn update(expected_prior: T, replacement: T) -> Self {
        Self {
            expected_present: true,
            expected_prior,
            replacement,
        }
    }
}

/// The raw result of one exact insert-or-update schedule.
///
/// Classification deliberately happens only after both protected accesses.
/// An unexpected absence is therefore materialized by the write-or-insert
/// access before the mismatch fails the table closed. The owner must discard
/// that whole generation rather than retrying or publishing the mutation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ExactUpsertCommit {
    found_before: bool,
    found_after: bool,
    expected_present: bool,
    prior_matches: bool,
    occupied_before: u64,
    occupied_records: u64,
}

impl ExactUpsertCommit {
    #[allow(clippy::needless_bitwise_bool)]
    fn classify(self) -> Result<ExactUpsertDisposition, RostlStoreError> {
        if self.found_after != self.found_before {
            return Err(RostlStoreError::FoundMismatch);
        }
        if self.found_before && self.occupied_before == 0 {
            return Err(RostlStoreError::OccupancyInvariant);
        }

        let expectation_matches = (!self.expected_present & !self.found_before)
            | (self.expected_present & self.found_before & self.prior_matches);
        if !expectation_matches {
            return Err(RostlStoreError::ExactUpsertMismatch);
        }

        if self.expected_present {
            Ok(ExactUpsertDisposition::Updated)
        } else {
            Ok(ExactUpsertDisposition::Inserted)
        }
    }
}

/// Admits an insert-or-update from public occupancy alone.
///
/// Every accepted call starts with at least two physical slots free. An
/// unexpected absence can therefore consume one slot before post-schedule
/// classification fails closed while still retaining the profile's mandatory
/// public spare slot.
fn admit_exact_upsert(occupied_records: u64, capacity: u64) -> Result<(), RostlStoreError> {
    if capacity < 2 || occupied_records > capacity {
        return Err(RostlStoreError::OccupancyInvariant);
    }
    if occupied_records >= capacity - 1 {
        return Err(RostlStoreError::UpsertReserveExhausted);
    }
    Ok(())
}

/// Compares every byte of two fixed-width plain-data records.
///
/// The loop bound is a public compile-time record width. Its result feeds only
/// bitwise boolean composition and `Cmov` inside [`fixed_exact_upsert`].
#[inline(always)]
fn fixed_width_pod_eq<T>(left: &T, right: &T) -> bool
where
    T: Pod,
{
    let left = bytemuck::bytes_of(left);
    let right = bytemuck::bytes_of(right);
    let mut difference = 0_u8;
    for index in 0..std::mem::size_of::<T>() {
        difference |= left[index] ^ right[index];
    }
    difference == 0
}

/// Performs one fixed-schedule exact insert or compare-and-update.
///
/// The secret hit and equality results cannot select an access: every admitted
/// call performs one read/remap followed by one write-or-insert/remap. On an
/// absent key the replacement is always written, including when presence was
/// expected; that mismatch is classified only after the complete schedule and
/// requires the caller to discard the failed-closed generation. On an occupied
/// key, an expectation or value mismatch writes the prior value back.
///
/// `#[inline(never)]` preserves one inspectable symbol per record type for the
/// dedicated `fixed-exact-upsert` codegen gate.
#[allow(clippy::needless_bitwise_bool)]
#[inline(never)]
fn fixed_exact_upsert<T, A>(
    access: &mut A,
    key: usize,
    request: InsertOrUpdateRequest<T>,
    occupied_records: u64,
) -> ExactUpsertCommit
where
    T: Cmov + Copy + Default + Pod,
    A: FixedExactUpsertAccess<T>,
{
    let mut prior = T::default();
    let found_before = access.exact_read_and_remap(key, &mut prior);
    let prior_matches = fixed_width_pod_eq(&prior, &request.expected_prior);

    let write_replacement = !found_before | (request.expected_present & prior_matches);
    let mut selected = prior;
    selected.cmov(&request.replacement, write_replacement);
    let found_after = access.exact_write_or_insert_and_remap(key, selected);

    ExactUpsertCommit {
        found_before,
        found_after,
        expected_present: request.expected_present,
        prior_matches,
        occupied_before: occupied_records,
        occupied_records: occupied_records + u64::from(!found_before),
    }
}

struct RostlTable<T>
where
    T: Cmov + Pod + Default + Clone + fmt::Debug,
{
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    oram: CircuitORAM<T>,
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    position_map: RecursivePositionMap,
    capacity: usize,
    occupied_records: u64,
    failed_closed: bool,
    record: PhantomData<T>,
}

impl<T> RostlTable<T>
where
    T: Cmov + Pod + Default + Clone + fmt::Debug,
{
    fn new(capacity: usize) -> Result<Self, RostlStoreError> {
        validate_capacity(capacity)?;

        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        {
            catch_upstream(|| Self {
                oram: CircuitORAM::new(capacity),
                position_map: RecursivePositionMap::new(capacity),
                capacity,
                occupied_records: 0,
                failed_closed: false,
                record: PhantomData,
            })
            .map_err(|()| RostlStoreError::UpstreamPanic)
        }

        #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
        {
            let _ = capacity;
            Err(RostlStoreError::UnsupportedPlatform)
        }
    }

    const fn capacity_value(&self) -> usize {
        self.capacity
    }

    fn read_record(&mut self, key: usize) -> Result<Option<T>, RostlStoreError> {
        self.validate_key(key)?;

        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        {
            let mut value = T::default();
            let result = catch_upstream(|| self.read_and_remap(key, &mut value));
            let found = self.finish_upstream(result)?;
            Ok(found.then_some(value))
        }

        #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
        {
            let _ = key;
            Err(RostlStoreError::UnsupportedPlatform)
        }
    }

    fn insert_record_unique(&mut self, key: usize, value: T) -> Result<(), RostlStoreError> {
        self.validate_key(key)?;

        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        {
            let capacity = u64::try_from(self.capacity).map_err(|_| {
                self.failed_closed = true;
                RostlStoreError::OccupancyInvariant
            })?;
            let occupied_records = self.occupied_records;
            // Admitted from public occupancy before the access path runs, so a
            // refusal never depends on whether the key is present.
            match admit_insert(occupied_records, capacity) {
                Ok(()) => {}
                // A full table is a consistent state and a plain refusal, so it
                // leaves the store usable. Only an impossible occupancy is
                // corruption worth latching.
                Err(RostlStoreError::TableFull) => return Err(RostlStoreError::TableFull),
                Err(error) => {
                    self.failed_closed = true;
                    return Err(error);
                }
            }
            let result = catch_upstream(|| fixed_unique_insert(self, key, value, occupied_records));
            let commit = self.finish_upstream(result)?;
            let disposition = commit.classify().inspect_err(|_| {
                self.failed_closed = true;
            })?;
            self.occupied_records = commit.occupied_records;
            match disposition {
                UniqueInsertDisposition::Inserted => Ok(()),
                UniqueInsertDisposition::Duplicate => Err(RostlStoreError::DuplicateKey),
            }
        }

        #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
        {
            let _ = (key, value);
            Err(RostlStoreError::UnsupportedPlatform)
        }
    }

    fn insert_or_update_record(
        &mut self,
        key: usize,
        request: InsertOrUpdateRequest<T>,
    ) -> Result<ExactUpsertDisposition, RostlStoreError> {
        self.validate_key(key)?;

        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        {
            let capacity = u64::try_from(self.capacity).map_err(|_| {
                self.failed_closed = true;
                RostlStoreError::OccupancyInvariant
            })?;
            let occupied_records = self.occupied_records;
            match admit_exact_upsert(occupied_records, capacity) {
                Ok(()) => {}
                Err(RostlStoreError::UpsertReserveExhausted) => {
                    return Err(RostlStoreError::UpsertReserveExhausted);
                }
                Err(error) => {
                    self.failed_closed = true;
                    return Err(error);
                }
            }

            let result =
                catch_upstream(|| fixed_exact_upsert(self, key, request, occupied_records));
            let commit = self.finish_upstream(result)?;
            let disposition = commit.classify().inspect_err(|_| {
                self.failed_closed = true;
            })?;
            self.occupied_records = commit.occupied_records;
            Ok(disposition)
        }

        #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
        {
            let _ = request;
            Err(RostlStoreError::UnsupportedPlatform)
        }
    }

    fn occupied_record_count(&self) -> Result<u64, RostlStoreError> {
        self.ensure_ready()?;
        Ok(self.occupied_records)
    }

    fn ensure_ready(&self) -> Result<(), RostlStoreError> {
        if self.failed_closed {
            Err(RostlStoreError::FailedClosed)
        } else {
            Ok(())
        }
    }

    fn validate_key(&self, key: usize) -> Result<(), RostlStoreError> {
        self.ensure_ready()?;
        if key >= self.capacity {
            Err(RostlStoreError::KeyOutsideCapacity)
        } else {
            Ok(())
        }
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    fn sample_new_position(&self) -> PositionType {
        rand::rng().random_range(0..self.capacity as PositionType)
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    fn finish_upstream<R>(&mut self, result: Result<R, ()>) -> Result<R, RostlStoreError> {
        match result {
            Ok(value) => Ok(value),
            Err(()) => {
                self.failed_closed = true;
                Err(RostlStoreError::UpstreamPanic)
            }
        }
    }
}

fn validate_capacity(capacity: usize) -> Result<(), RostlStoreError> {
    if capacity < 2 || capacity > u32::MAX as usize || !capacity.is_power_of_two() {
        Err(RostlStoreError::InvalidCapacity)
    } else {
        Ok(())
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
impl<T> FixedUniqueInsertAccess<T> for RostlTable<T>
where
    T: Cmov + Pod + Default + Clone + fmt::Debug,
{
    fn read_and_remap(&mut self, key: usize, value: &mut T) -> bool {
        let new_position = self.sample_new_position();
        let old_position = self.position_map.access_position(key, new_position);
        self.oram.read(old_position, new_position, key, value)
    }

    fn write_or_insert_and_remap(&mut self, key: usize, value: T) -> bool {
        let new_position = self.sample_new_position();
        let old_position = self.position_map.access_position(key, new_position);
        self.oram
            .write_or_insert(old_position, new_position, key, value)
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
impl<T> FixedExactUpsertAccess<T> for RostlTable<T>
where
    T: Cmov + Pod + Default + Clone + fmt::Debug,
{
    // These two small bodies intentionally mirror `FixedUniqueInsertAccess`.
    // A shared function cannot carry exact-upsert-only `inline(always)`
    // semantics without also changing the qualified unique-insert symbol.
    #[inline(always)]
    fn exact_read_and_remap(&mut self, key: usize, value: &mut T) -> bool {
        let new_position = self.sample_new_position();
        let old_position = self.position_map.access_position(key, new_position);
        self.oram.read(old_position, new_position, key, value)
    }

    #[inline(always)]
    fn exact_write_or_insert_and_remap(&mut self, key: usize, value: T) -> bool {
        let new_position = self.sample_new_position();
        let old_position = self.position_map.access_position(key, new_position);
        self.oram
            .write_or_insert(old_position, new_position, key, value)
    }
}

impl<T> UniqueTable<T> for RostlTable<T>
where
    T: Cmov + Pod + Default + Clone + fmt::Debug,
{
    fn capacity(&self) -> usize {
        self.capacity_value()
    }

    fn read(&mut self, index: usize) -> Result<Option<T>, BackendFailure> {
        self.read_record(index).map_err(|_| BackendFailure)
    }

    fn occupied_records(&mut self) -> Result<u64, BackendFailure> {
        self.occupied_record_count().map_err(|_| BackendFailure)
    }

    fn insert_unique(&mut self, index: usize, value: T) -> Result<(), BackendFailure> {
        self.insert_record_unique(index, value)
            .map_err(|_| BackendFailure)
    }

    /// Rewrites one record through the already-qualified exact-upsert schedule.
    ///
    /// Obliviousness comes from [`fixed_exact_upsert`], not from this wrapper:
    /// every admitted call performs exactly one read/remap followed by one
    /// write-or-insert/remap regardless of whether the key was present, whether
    /// the prior bytes matched, or what the replacement contains. The hit flag
    /// and the byte comparison reach only `Cmov` and bitwise boolean
    /// composition; the outcome is classified after the complete schedule. Its
    /// symbol is disassembled and pinned by the `fixed-exact-upsert` gate in
    /// `check-oram-codegen`.
    ///
    /// Admission is decided from public occupancy alone
    /// ([`admit_exact_upsert`]), so a refusal never depends on the key.
    fn update_present(
        &mut self,
        index: usize,
        expected_prior: T,
        replacement: T,
    ) -> Result<(), BackendFailure> {
        self.insert_or_update_record(
            index,
            InsertOrUpdateRequest::update(expected_prior, replacement),
        )
        .map_err(|_| BackendFailure)
        .and_then(|disposition| match disposition {
            ExactUpsertDisposition::Updated => Ok(()),
            // An insertion means the record the caller read was gone. The
            // schedule already ran, so this is reported rather than prevented.
            ExactUpsertDisposition::Inserted => Err(BackendFailure),
        })
    }
}

impl<T> fmt::Debug for RostlTable<T>
where
    T: Cmov + Pod + Default + Clone + fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RostlTable { ..REDACTED.. }")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RostlStoreError {
    #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
    UnsupportedPlatform,
    InvalidCapacity,
    KeyOutsideCapacity,
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    DuplicateKey,
    OccupancyInvariant,
    TableFull,
    FoundMismatch,
    ExactUpsertMismatch,
    UpsertReserveExhausted,
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    UpstreamPanic,
    FailedClosed,
}

impl fmt::Display for RostlStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
            Self::UnsupportedPlatform => f.write_str("typed rostl store is unavailable"),
            Self::InvalidCapacity => f.write_str("typed rostl store capacity is invalid"),
            Self::KeyOutsideCapacity => f.write_str("typed rostl store key is outside capacity"),
            #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
            Self::DuplicateKey => f.write_str("typed rostl store rejected a duplicate key"),
            Self::OccupancyInvariant => f.write_str("typed rostl store occupancy is inconsistent"),
            Self::TableFull => f.write_str("typed rostl store is at capacity"),
            Self::FoundMismatch => f.write_str("typed rostl store access results are inconsistent"),
            Self::ExactUpsertMismatch => {
                f.write_str("typed rostl store exact upsert expectation did not match")
            }
            Self::UpsertReserveExhausted => {
                f.write_str("typed rostl store mutable spare reserve is exhausted")
            }
            #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
            Self::UpstreamPanic => f.write_str("typed rostl store failed closed"),
            Self::FailedClosed => f.write_str("typed rostl store is failed closed"),
        }
    }
}

impl std::error::Error for RostlStoreError {}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
enum RostlWorkerBuildError {
    Store(RostlStoreError),
    Executor(AtomicStoreError),
    Worker(AtomicWorkerError),
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
impl fmt::Debug for RostlWorkerBuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RostlWorkerBuildError { ..REDACTED.. }")
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
impl fmt::Display for RostlWorkerBuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Store(_) => f.write_str("typed rostl worker store construction failed"),
            Self::Executor(_) => f.write_str("typed rostl worker executor construction failed"),
            Self::Worker(_) => f.write_str("typed rostl worker construction failed"),
        }
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
impl std::error::Error for RostlWorkerBuildError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Store(error) => Some(error),
            Self::Executor(error) => Some(error),
            Self::Worker(error) => Some(error),
        }
    }
}

#[cfg(all(feature = "corpus-zaino", target_os = "linux", target_arch = "x86_64"))]
/// Builds the exact typed worker while erasing backend-specific failures.
pub(super) fn spawn_rostl_worker<const DIRECTORY_PROBES: usize, const EVENT_PROBES: usize>(
    layout: FixedProbeLayout<DIRECTORY_PROBES, EVENT_PROBES>,
    queue_capacity: AtomicQueueCapacity,
) -> Result<AtomicWorker, AtomicWorkerBuildError> {
    build_rostl_worker(layout, queue_capacity)
        .map_err(|_| AtomicWorkerBuildError::ConstructionFailed)
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn build_rostl_worker<const DIRECTORY_PROBES: usize, const EVENT_PROBES: usize>(
    layout: FixedProbeLayout<DIRECTORY_PROBES, EVENT_PROBES>,
    queue_capacity: AtomicQueueCapacity,
) -> Result<AtomicWorker, RostlWorkerBuildError> {
    let directory_capacity = usize::try_from(layout.directory.0.capacity)
        .map_err(|_| RostlWorkerBuildError::Store(RostlStoreError::InvalidCapacity))?;
    let event_capacity = usize::try_from(layout.event.0.capacity)
        .map_err(|_| RostlWorkerBuildError::Store(RostlStoreError::InvalidCapacity))?;
    let directory = RostlTable::<PersistentAddressDirectory>::new(directory_capacity)
        .map_err(RostlWorkerBuildError::Store)?;
    let events = RostlTable::<PersistentAddressEventPage>::new(event_capacity)
        .map_err(RostlWorkerBuildError::Store)?;
    let executor = ExclusiveTwoTableExecutor::new(layout, directory, events)
        .map_err(RostlWorkerBuildError::Executor)?;
    AtomicWorker::spawn(executor, queue_capacity).map_err(RostlWorkerBuildError::Worker)
}

/// Opaque probe returned only to the crate's high-level timing entry point.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub(crate) struct RostlInsertTimingProbe {
    inner: RostlInsertTimingProbeKind,
    mode: RostlTimingMode,
}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
pub(crate) struct RostlInsertTimingProbe;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
enum RostlInsertTimingProbeKind {
    Directory(InsertProbe<PersistentAddressDirectory>),
    Event(InsertProbe<PersistentAddressEventPage>),
}

pub(crate) fn rostl_insert_timing_probe(
    kind: RostlTimingRecordKind,
    mode: RostlTimingMode,
    capacity: usize,
    occupancy: usize,
    total_pairs: usize,
) -> Result<RostlInsertTimingProbe, RostlTimingError> {
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        match kind {
            RostlTimingRecordKind::Directory => {
                InsertProbe::new(capacity, occupancy, total_pairs, mode).map(|probe| {
                    RostlInsertTimingProbe {
                        inner: RostlInsertTimingProbeKind::Directory(probe),
                        mode,
                    }
                })
            }
            RostlTimingRecordKind::Event => {
                InsertProbe::new(capacity, occupancy, total_pairs, mode).map(|probe| {
                    RostlInsertTimingProbe {
                        inner: RostlInsertTimingProbeKind::Event(probe),
                        mode,
                    }
                })
            }
        }
    }

    #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
    {
        let _ = (kind, mode, capacity, occupancy, total_pairs);
        Err(RostlTimingError::UnsupportedPlatform)
    }
}

pub(crate) fn validate_rostl_insert_timing_shape(
    capacity: usize,
    occupancy: usize,
    total_pairs: usize,
) -> Result<(), RostlTimingError> {
    if validate_capacity(capacity).is_err() || occupancy == 0 || total_pairs == 0 {
        return Err(RostlTimingError::InvalidShape);
    }
    let final_occupancy = occupancy
        .checked_add(total_pairs)
        .ok_or(RostlTimingError::InvalidShape)?;
    // The hit/miss invariant holds one exclusive key per table, so the union
    // needs one key-space slot beyond each table's final occupancy. The final
    // duplicate cover insertion also requires public occupancy below capacity.
    if final_occupancy >= capacity {
        return Err(RostlTimingError::InvalidShape);
    }
    Ok(())
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
impl RostlInsertTimingProbe {
    fn executed_arm(&self, scheduled: Arm) -> Arm {
        match self.mode {
            RostlTimingMode::HitMiss => scheduled,
            RostlTimingMode::ForcedHit => Arm::Hit,
            RostlTimingMode::ForcedMiss => Arm::Miss,
        }
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
impl PairedProbe for RostlInsertTimingProbe {
    type Error = RostlTimingError;

    fn measure(&mut self, scheduled: Arm) -> Result<ArmMeasurement, Self::Error> {
        let executed = self.executed_arm(scheduled);
        match &mut self.inner {
            RostlInsertTimingProbeKind::Directory(probe) => probe.measure(scheduled, executed),
            RostlInsertTimingProbeKind::Event(probe) => probe.measure(scheduled, executed),
        }
    }

    fn finish_pair(&mut self) -> Result<(), Self::Error> {
        match &mut self.inner {
            RostlInsertTimingProbeKind::Directory(probe) => probe.finish_pair(),
            RostlInsertTimingProbeKind::Event(probe) => probe.finish_pair(),
        }
    }
}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
impl PairedProbe for RostlInsertTimingProbe {
    type Error = RostlTimingError;

    fn measure(&mut self, _arm: Arm) -> Result<ArmMeasurement, Self::Error> {
        Err(RostlTimingError::UnsupportedPlatform)
    }

    fn finish_pair(&mut self) -> Result<(), Self::Error> {
        Err(RostlTimingError::UnsupportedPlatform)
    }
}

/// Times insertions against two long-lived, logically matched tables.
///
/// At every pair boundary both tables have equal public occupancy. Hit/miss
/// mode keeps a one-record substitution (one exclusive key per table) and
/// alternates the physical table assigned to each label. Forced modes keep
/// identical key sets. After both timed arms, one untimed fixed-work cover
/// insertion runs on each physical table and restores the invariant for the
/// next pair.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
struct InsertProbe<T>
where
    T: TimingProbeRecord,
{
    tables: [RostlTable<T>; 2],
    mode: RostlTimingMode,
    hit_label_table: usize,
    probe_key: usize,
    substitute_key: Option<usize>,
    next_fresh_key: usize,
    current_occupancy: usize,
    measured_hit: bool,
    measured_miss: bool,
    #[cfg(test)]
    cover_trace: Vec<usize>,
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
impl<T> InsertProbe<T>
where
    T: TimingProbeRecord,
{
    fn new(
        capacity: usize,
        occupancy: usize,
        total_pairs: usize,
        mode: RostlTimingMode,
    ) -> Result<Self, RostlTimingError> {
        validate_rostl_insert_timing_shape(capacity, occupancy, total_pairs)?;
        let (tables, probe_key, substitute_key, next_fresh_key) = match mode {
            RostlTimingMode::HitMiss => {
                let common_records = occupancy - 1;
                let hit_key = common_records;
                let miss_key = occupancy;
                (
                    [
                        build_timing_table(capacity, common_records, Some(hit_key))?,
                        build_timing_table(capacity, common_records, Some(miss_key))?,
                    ],
                    hit_key,
                    Some(miss_key),
                    occupancy
                        .checked_add(1)
                        .ok_or(RostlTimingError::InvalidShape)?,
                )
            }
            RostlTimingMode::ForcedHit => (
                [
                    build_timing_table(capacity, occupancy, None)?,
                    build_timing_table(capacity, occupancy, None)?,
                ],
                occupancy - 1,
                None,
                occupancy,
            ),
            RostlTimingMode::ForcedMiss => (
                [
                    build_timing_table(capacity, occupancy, None)?,
                    build_timing_table(capacity, occupancy, None)?,
                ],
                occupancy,
                None,
                occupancy
                    .checked_add(1)
                    .ok_or(RostlTimingError::InvalidShape)?,
            ),
        };
        Ok(Self {
            tables,
            mode,
            hit_label_table: 0,
            probe_key,
            substitute_key,
            next_fresh_key,
            current_occupancy: occupancy,
            measured_hit: false,
            measured_miss: false,
            #[cfg(test)]
            cover_trace: Vec::new(),
        })
    }

    fn measure(
        &mut self,
        scheduled: Arm,
        executed: Arm,
    ) -> Result<ArmMeasurement, RostlTimingError> {
        self.admit_arm(scheduled, executed)?;
        let table_index = self.table_index(scheduled)?;
        let table = self
            .tables
            .get_mut(table_index)
            .ok_or(RostlTimingError::PairState)?;
        let occupied_before = usize::try_from(
            table
                .occupied_record_count()
                .map_err(|_| RostlTimingError::PairState)?,
        )
        .map_err(|_| RostlTimingError::PairState)?;
        if occupied_before != self.current_occupancy {
            return Err(RostlTimingError::PairState);
        }
        let candidate = T::filler(self.probe_key)?;

        let scheduler_before = read_scheduler_counters()?;
        let started = Instant::now();
        let outcome = table.insert_record_unique(self.probe_key, candidate);
        let elapsed = started.elapsed();
        let scheduler_after = read_scheduler_counters()?;
        let scheduler = scheduler_after.delta_from(scheduler_before)?;
        require_insert_outcome(executed, outcome)?;

        match scheduled {
            Arm::Hit => self.measured_hit = true,
            Arm::Miss => self.measured_miss = true,
        }
        let nanos =
            u64::try_from(elapsed.as_nanos()).map_err(|_| RostlTimingError::WrongOutcome)?;
        Ok(ArmMeasurement::with_scheduler(nanos, scheduler))
    }

    fn finish_pair(&mut self) -> Result<(), RostlTimingError> {
        if !self.measured_hit || !self.measured_miss {
            return Err(RostlTimingError::PairState);
        }
        match self.mode {
            RostlTimingMode::HitMiss => self.finish_hit_miss_pair()?,
            RostlTimingMode::ForcedHit => self.finish_forced_hit_pair()?,
            RostlTimingMode::ForcedMiss => self.finish_forced_miss_pair()?,
        }
        let next_occupancy = self
            .current_occupancy
            .checked_add(1)
            .ok_or(RostlTimingError::PairState)?;
        self.verify_pair_boundary(next_occupancy)?;
        self.current_occupancy = next_occupancy;
        self.hit_label_table = other_table(self.hit_label_table)?;
        self.measured_hit = false;
        self.measured_miss = false;
        Ok(())
    }

    fn verify_pair_boundary(&self, expected_occupancy: usize) -> Result<(), RostlTimingError> {
        for table in &self.tables {
            let observed = usize::try_from(
                table
                    .occupied_record_count()
                    .map_err(|_| RostlTimingError::PairState)?,
            )
            .map_err(|_| RostlTimingError::PairState)?;
            if observed != expected_occupancy {
                return Err(RostlTimingError::PairState);
            }
        }
        Ok(())
    }

    fn admit_arm(&self, scheduled: Arm, executed: Arm) -> Result<(), RostlTimingError> {
        let already_measured = match scheduled {
            Arm::Hit => self.measured_hit,
            Arm::Miss => self.measured_miss,
        };
        let expected = match self.mode {
            RostlTimingMode::HitMiss => scheduled,
            RostlTimingMode::ForcedHit => Arm::Hit,
            RostlTimingMode::ForcedMiss => Arm::Miss,
        };
        if already_measured || executed != expected {
            return Err(RostlTimingError::PairState);
        }
        Ok(())
    }

    fn table_index(&self, scheduled: Arm) -> Result<usize, RostlTimingError> {
        match scheduled {
            Arm::Hit => Ok(self.hit_label_table),
            Arm::Miss => other_table(self.hit_label_table),
        }
    }

    fn finish_hit_miss_pair(&mut self) -> Result<(), RostlTimingError> {
        let hit_table = self.hit_label_table;
        for table_index in 0..self.tables.len() {
            let (key, expected) = if table_index == hit_table {
                (self.next_fresh_key, Arm::Miss)
            } else {
                (self.probe_key, Arm::Hit)
            };
            insert_cover(
                self.tables
                    .get_mut(table_index)
                    .ok_or(RostlTimingError::PairState)?,
                key,
                expected,
            )?;
            #[cfg(test)]
            self.cover_trace.push(table_index);
        }
        self.probe_key = self
            .substitute_key
            .replace(self.next_fresh_key)
            .ok_or(RostlTimingError::PairState)?;
        self.next_fresh_key = self
            .next_fresh_key
            .checked_add(1)
            .ok_or(RostlTimingError::PairState)?;
        Ok(())
    }

    fn finish_forced_hit_pair(&mut self) -> Result<(), RostlTimingError> {
        for table in &mut self.tables {
            insert_cover(table, self.next_fresh_key, Arm::Miss)?;
        }
        self.probe_key = self.next_fresh_key;
        self.next_fresh_key = self
            .next_fresh_key
            .checked_add(1)
            .ok_or(RostlTimingError::PairState)?;
        Ok(())
    }

    fn finish_forced_miss_pair(&mut self) -> Result<(), RostlTimingError> {
        for table in &mut self.tables {
            insert_cover(table, self.probe_key, Arm::Hit)?;
        }
        self.probe_key = self.next_fresh_key;
        self.next_fresh_key = self
            .next_fresh_key
            .checked_add(1)
            .ok_or(RostlTimingError::PairState)?;
        Ok(())
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn build_timing_table<T>(
    capacity: usize,
    common_records: usize,
    exclusive_key: Option<usize>,
) -> Result<RostlTable<T>, RostlTimingError>
where
    T: TimingProbeRecord,
{
    retain_exact_upsert_codegen::<T>();
    let mut table = RostlTable::<T>::new(capacity).map_err(|_| RostlTimingError::Setup)?;
    for key in 0..common_records {
        insert_cover(&mut table, key, Arm::Miss).map_err(|_| RostlTimingError::Setup)?;
    }
    if let Some(key) = exclusive_key {
        insert_cover(&mut table, key, Arm::Miss).map_err(|_| RostlTimingError::Setup)?;
    }
    Ok(table)
}

/// Retains the additive backend upsert seam for release-codegen inspection.
///
/// The opaque function pointer makes the wrapper and its `#[inline(never)]`
/// fixed access path addressable in the linked timing binary without executing
/// either one. Legacy timing-table construction therefore keeps its original
/// unique-insert state transitions. This is only a codegen retention anchor:
/// it is not exact-upsert timing evidence or production executor wiring.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
type ExactUpsertAnchor<T> = fn(
    &mut RostlTable<T>,
    usize,
    InsertOrUpdateRequest<T>,
) -> Result<ExactUpsertDisposition, RostlStoreError>;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn retain_exact_upsert_codegen<T>()
where
    T: TimingProbeRecord,
{
    let anchor: ExactUpsertAnchor<T> = RostlTable::insert_or_update_record;
    std::hint::black_box(anchor);
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn insert_cover<T>(
    table: &mut RostlTable<T>,
    key: usize,
    expected: Arm,
) -> Result<(), RostlTimingError>
where
    T: TimingProbeRecord,
{
    let candidate = T::filler(key)?;
    require_insert_outcome(expected, table.insert_record_unique(key, candidate))
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn require_insert_outcome(
    expected: Arm,
    outcome: Result<(), RostlStoreError>,
) -> Result<(), RostlTimingError> {
    if matches!(
        (expected, outcome),
        (Arm::Hit, Err(RostlStoreError::DuplicateKey)) | (Arm::Miss, Ok(()))
    ) {
        Ok(())
    } else {
        Err(RostlTimingError::WrongOutcome)
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn other_table(table: usize) -> Result<usize, RostlTimingError> {
    match table {
        0 => Ok(1),
        1 => Ok(0),
        _ => Err(RostlTimingError::PairState),
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[derive(Debug, Clone, Copy)]
struct SchedulerCounters {
    cpu_time_nanos: u64,
    runqueue_wait_nanos: u64,
    timeslices: u64,
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
impl SchedulerCounters {
    fn delta_from(self, before: Self) -> Result<TimedSchedulerDelta, RostlTimingError> {
        Ok(TimedSchedulerDelta {
            cpu_time_nanos: self
                .cpu_time_nanos
                .checked_sub(before.cpu_time_nanos)
                .ok_or(RostlTimingError::SchedulerStats)?,
            runqueue_wait_nanos: self
                .runqueue_wait_nanos
                .checked_sub(before.runqueue_wait_nanos)
                .ok_or(RostlTimingError::SchedulerStats)?,
            timeslices: self
                .timeslices
                .checked_sub(before.timeslices)
                .ok_or(RostlTimingError::SchedulerStats)?,
        })
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn read_scheduler_counters() -> Result<SchedulerCounters, RostlTimingError> {
    let schedstat =
        fs::read_to_string("/proc/self/schedstat").map_err(|_| RostlTimingError::SchedulerStats)?;
    let mut fields = schedstat.split_whitespace();
    let mut next_counter = || {
        fields
            .next()
            .ok_or(RostlTimingError::SchedulerStats)?
            .parse::<u64>()
            .map_err(|_| RostlTimingError::SchedulerStats)
    };
    Ok(SchedulerCounters {
        cpu_time_nanos: next_counter()?,
        runqueue_wait_nanos: next_counter()?,
        timeslices: next_counter()?,
    })
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
trait TimingProbeRecord: Cmov + Pod + Default + Clone + fmt::Debug {
    fn filler(index: usize) -> Result<Self, RostlTimingError>;
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
impl TimingProbeRecord for PersistentAddressDirectory {
    fn filler(index: usize) -> Result<Self, RostlTimingError> {
        let slot = u32::try_from(index).map_err(|_| RostlTimingError::Setup)?;
        let byte = (index % 251) as u8 + 1;
        Ok(Self::from_business(&AddressDirectory::real(
            slot,
            AddressKey::new([byte; 32]),
        )))
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
impl TimingProbeRecord for PersistentAddressEventPage {
    fn filler(index: usize) -> Result<Self, RostlTimingError> {
        let directory_slot = u32::try_from(index).map_err(|_| RostlTimingError::Setup)?;
        let byte = (index % 251) as u8 + 1;
        let event = UtxoEvent::created(
            [byte; TXID_BYTES],
            1,
            50_000,
            100,
            UtxoScriptClass::PayToPublicKeyHash,
            [byte; 20],
        );
        let page = AddressEventPage::real(directory_slot, 0, event)
            .map_err(|_| RostlTimingError::Setup)?;
        Ok(Self::from_business(&page))
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn catch_upstream<R>(operation: impl FnOnce() -> R) -> Result<R, ()> {
    catch_unwind(AssertUnwindSafe(operation)).map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    use crate::{
        fixed_page_capacity::TARGET_ROSTL_TABLE_OBJECT_BYTES,
        layout::{
            DirectoryTableConfiguration, EventTableConfiguration, LayoutIdentity, LayoutNetwork,
            StandardAddress, StandardScriptKind,
        },
        records::{
            AddressDirectory, AddressEventPage, AddressKey, PersistentBaseUtxoPage16, UtxoEvent,
            UtxoScriptClass, TXID_BYTES,
        },
    };

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn fixed_page_capacity_model_matches_linux_table_object_layout() {
        assert_eq!(
            u64::try_from(std::mem::size_of::<RostlTable<PersistentBaseUtxoPage16>>()),
            Ok(TARGET_ROSTL_TABLE_OBJECT_BYTES)
        );
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum AccessKind {
        Read,
        WriteOrInsert,
    }

    #[derive(Default)]
    struct FakeAccess {
        record: Option<u64>,
        trace: Vec<AccessKind>,
        forced_write_result: Option<bool>,
    }

    impl FixedUniqueInsertAccess<u64> for FakeAccess {
        fn read_and_remap(&mut self, _key: usize, value: &mut u64) -> bool {
            self.trace.push(AccessKind::Read);
            match self.record {
                Some(record) => {
                    *value = record;
                    true
                }
                None => false,
            }
        }

        fn write_or_insert_and_remap(&mut self, _key: usize, value: u64) -> bool {
            self.trace.push(AccessKind::WriteOrInsert);
            let found = self.record.is_some();
            self.record = Some(value);
            self.forced_write_result.unwrap_or(found)
        }
    }

    impl FixedExactUpsertAccess<u64> for FakeAccess {
        fn exact_read_and_remap(&mut self, key: usize, value: &mut u64) -> bool {
            self.read_and_remap(key, value)
        }

        fn exact_write_or_insert_and_remap(&mut self, key: usize, value: u64) -> bool {
            self.write_or_insert_and_remap(key, value)
        }
    }

    /// Runs the whole insertion path against a fake backend and reports both the
    /// classified result and the exact access schedule it produced.
    fn run_insert(
        record: Option<u64>,
        occupied_records: u64,
        capacity: u64,
    ) -> (
        Result<UniqueInsertDisposition, RostlStoreError>,
        Vec<AccessKind>,
        Option<u64>,
    ) {
        let mut access = FakeAccess {
            record,
            ..FakeAccess::default()
        };
        let result = admit_insert(occupied_records, capacity)
            .and_then(|()| fixed_unique_insert(&mut access, 3, 7, occupied_records).classify());
        (result, access.trace, access.record)
    }

    fn run_exact_upsert(
        record: Option<u64>,
        request: InsertOrUpdateRequest<u64>,
        occupied_records: u64,
        capacity: u64,
    ) -> (
        Result<ExactUpsertDisposition, RostlStoreError>,
        Vec<AccessKind>,
        Option<u64>,
        Option<u64>,
    ) {
        let mut access = FakeAccess {
            record,
            ..FakeAccess::default()
        };
        let (result, occupied_after) = match admit_exact_upsert(occupied_records, capacity) {
            Ok(()) => {
                let commit = fixed_exact_upsert(&mut access, 3, request, occupied_records);
                (commit.classify(), Some(commit.occupied_records))
            }
            Err(error) => (Err(error), None),
        };
        (result, access.trace, access.record, occupied_after)
    }

    #[test]
    fn exact_upsert_matrix_preserves_the_fixed_schedule_and_expected_state() {
        const SCHEDULE: [AccessKind; 2] = [AccessKind::Read, AccessKind::WriteOrInsert];
        let cases = [
            (
                "expected absent, actual absent",
                None,
                InsertOrUpdateRequest::insert(7),
                Ok(ExactUpsertDisposition::Inserted),
                Some(7),
                2,
            ),
            (
                "expected absent, actual present",
                Some(11),
                InsertOrUpdateRequest::insert(7),
                Err(RostlStoreError::ExactUpsertMismatch),
                Some(11),
                1,
            ),
            (
                "expected present, actual absent",
                None,
                InsertOrUpdateRequest::update(11, 7),
                Err(RostlStoreError::ExactUpsertMismatch),
                Some(7),
                2,
            ),
            (
                "expected present, matching actual",
                Some(11),
                InsertOrUpdateRequest::update(11, 7),
                Ok(ExactUpsertDisposition::Updated),
                Some(7),
                1,
            ),
            (
                "expected present, mismatching actual",
                Some(11),
                InsertOrUpdateRequest::update(12, 7),
                Err(RostlStoreError::ExactUpsertMismatch),
                Some(11),
                1,
            ),
        ];

        for (name, record, request, expected, stored, occupied_after) in cases {
            let (result, trace, actual_stored, actual_occupied_after) =
                run_exact_upsert(record, request, 1, 8);
            assert_eq!(result, expected, "{name}");
            assert_eq!(trace, SCHEDULE, "{name}");
            assert_eq!(actual_stored, stored, "{name}");
            assert_eq!(actual_occupied_after, Some(occupied_after), "{name}");
        }
    }

    #[test]
    fn exact_upsert_reserve_and_invalid_occupancy_refuse_before_access() {
        let (_, admitted_trace, _, _) =
            run_exact_upsert(None, InsertOrUpdateRequest::insert(7), 6, 8);
        assert_eq!(
            admitted_trace,
            vec![AccessKind::Read, AccessKind::WriteOrInsert]
        );

        for (occupied, expected) in [
            (7, RostlStoreError::UpsertReserveExhausted),
            (8, RostlStoreError::UpsertReserveExhausted),
            (9, RostlStoreError::OccupancyInvariant),
        ] {
            let (result, trace, _, occupied_after) =
                run_exact_upsert(None, InsertOrUpdateRequest::insert(7), occupied, 8);
            assert_eq!(result, Err(expected), "occupied={occupied}");
            assert_eq!(trace, Vec::new(), "occupied={occupied}");
            assert_eq!(occupied_after, None, "occupied={occupied}");
        }
    }

    #[test]
    fn exact_upsert_corruption_is_classified_after_both_accesses() {
        let (result, trace, stored, occupied_after) =
            run_exact_upsert(Some(11), InsertOrUpdateRequest::update(11, 7), 0, 8);
        assert_eq!(result, Err(RostlStoreError::OccupancyInvariant));
        assert_eq!(trace, vec![AccessKind::Read, AccessKind::WriteOrInsert]);
        assert_eq!(stored, Some(7));
        assert_eq!(occupied_after, Some(0));
    }

    #[test]
    fn exact_upsert_found_mismatch_is_rejected_after_both_accesses() {
        let mut access = FakeAccess {
            record: Some(11),
            forced_write_result: Some(false),
            ..FakeAccess::default()
        };
        let commit = fixed_exact_upsert(&mut access, 3, InsertOrUpdateRequest::update(11, 7), 1);
        assert_eq!(commit.classify(), Err(RostlStoreError::FoundMismatch));
        assert_eq!(
            access.trace,
            vec![AccessKind::Read, AccessKind::WriteOrInsert]
        );
        assert_eq!(access.record, Some(7));
    }

    #[test]
    fn fixed_width_equality_checks_every_record_position() {
        let baseline = [0x5a_u8; 8];
        assert!(fixed_width_pod_eq(&baseline, &baseline));
        for index in 0..baseline.len() {
            let mut different = baseline;
            different[index] ^= 1;
            assert!(
                !fixed_width_pod_eq(&baseline, &different),
                "difference at index {index} was ignored"
            );
        }
    }

    /// The Gate 2 property: at every public occupancy a present record and an
    /// absent record must produce identical access schedules.
    #[test]
    fn hit_and_miss_share_an_access_schedule_at_every_public_occupancy() {
        const CAPACITY: u64 = 8;
        for occupied in [0, 1, 7, CAPACITY] {
            let (_, hit, _) = run_insert(Some(11), occupied, CAPACITY);
            let (_, miss, _) = run_insert(None, occupied, CAPACITY);
            assert_eq!(hit, miss, "schedules diverged at occupied={occupied}");
        }
    }

    /// Pins the two schedules the property test compares so it cannot pass
    /// vacuously by refusing, or accessing, in every state alike.
    #[test]
    fn admitted_insertions_access_twice_and_refused_insertions_never_access() {
        const CAPACITY: u64 = 8;
        let (_, admitted, _) = run_insert(None, 1, CAPACITY);
        assert_eq!(admitted, vec![AccessKind::Read, AccessKind::WriteOrInsert]);

        let (refused, refused_trace, _) = run_insert(None, CAPACITY, CAPACITY);
        assert_eq!(refused, Err(RostlStoreError::TableFull));
        assert_eq!(refused_trace, Vec::new());
    }

    #[test]
    fn healthy_missing_and_duplicate_use_the_same_two_access_schedule() {
        let (inserted, inserted_trace, stored) = run_insert(None, 0, 8);
        assert_eq!(inserted, Ok(UniqueInsertDisposition::Inserted));
        assert_eq!(stored, Some(7));

        let (duplicate, duplicate_trace, preserved) = run_insert(Some(11), 1, 8);
        assert_eq!(duplicate, Ok(UniqueInsertDisposition::Duplicate));
        assert_eq!(preserved, Some(11));

        assert_eq!(inserted_trace, duplicate_trace);
        assert_eq!(
            inserted_trace,
            vec![AccessKind::Read, AccessKind::WriteOrInsert]
        );
    }

    /// This case formerly short-circuited after a single access. A hit on an
    /// empty table now costs the full schedule and is rejected only afterwards.
    #[test]
    fn hit_on_an_empty_table_is_rejected_after_both_accesses() {
        let (result, trace, _) = run_insert(Some(11), 0, 8);
        assert_eq!(result, Err(RostlStoreError::OccupancyInvariant));
        assert_eq!(trace, vec![AccessKind::Read, AccessKind::WriteOrInsert]);
    }

    #[test]
    fn found_mismatch_is_rejected_after_both_accesses() {
        let mut access = FakeAccess {
            record: Some(11),
            forced_write_result: Some(false),
            ..FakeAccess::default()
        };
        assert_eq!(
            fixed_unique_insert(&mut access, 3, 99, 1).classify(),
            Err(RostlStoreError::FoundMismatch)
        );
        assert_eq!(
            access.trace,
            vec![AccessKind::Read, AccessKind::WriteOrInsert]
        );
        assert_eq!(access.record, Some(11));
    }

    #[test]
    fn inconsistent_occupancy_is_refused_before_any_access() {
        let (result, trace, _) = run_insert(None, 9, 8);
        assert_eq!(result, Err(RostlStoreError::OccupancyInvariant));
        assert_eq!(trace, Vec::new());
    }

    #[test]
    fn exact_typed_stores_require_power_of_two_capacity() {
        assert!(matches!(
            RostlTable::<PersistentAddressDirectory>::new(1),
            Err(RostlStoreError::InvalidCapacity)
        ));
        assert!(matches!(
            RostlTable::<PersistentAddressEventPage>::new(3),
            Err(RostlStoreError::InvalidCapacity)
        ));
    }

    #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
    #[test]
    fn exact_typed_stores_reject_unsupported_hosts() {
        assert!(matches!(
            RostlTable::<PersistentAddressDirectory>::new(8),
            Err(RostlStoreError::UnsupportedPlatform)
        ));
        assert!(matches!(
            RostlTable::<PersistentAddressEventPage>::new(8),
            Err(RostlStoreError::UnsupportedPlatform)
        ));
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    fn directory_record(byte: u8, slot: u32) -> PersistentAddressDirectory {
        PersistentAddressDirectory::from_business(&AddressDirectory::real(
            slot,
            AddressKey::new([byte; 32]),
        ))
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    fn event_record(
        byte: u8,
        directory_slot: u32,
    ) -> Result<PersistentAddressEventPage, Box<dyn std::error::Error>> {
        let event = UtxoEvent::created(
            [byte; TXID_BYTES],
            1,
            50_000,
            100,
            UtxoScriptClass::PayToPublicKeyHash,
            [byte; 20],
        );
        Ok(PersistentAddressEventPage::from_business(
            &AddressEventPage::real(directory_slot, 0, event)?,
        ))
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn exact_typed_stores_preserve_duplicate_values_and_do_not_alias(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut directory = RostlTable::<PersistentAddressDirectory>::new(8)?;
        let mut events = RostlTable::<PersistentAddressEventPage>::new(8)?;
        let directory_original = directory_record(0x31, 3);
        let directory_replacement = directory_record(0x32, 4);
        let event_original = event_record(0x41, 3)?;
        let event_replacement = event_record(0x42, 4)?;

        let directory_before = directory.oram.evict_counter;
        directory.insert_record_unique(3, directory_original)?;
        let directory_after_insert = directory.oram.evict_counter;
        assert_eq!((directory_after_insert + 8 - directory_before) % 8, 4);
        assert_eq!(directory.occupied_record_count()?, 1);
        assert_eq!(
            directory.insert_record_unique(3, directory_replacement),
            Err(RostlStoreError::DuplicateKey)
        );
        let directory_after_duplicate = directory.oram.evict_counter;
        assert_eq!(
            (directory_after_duplicate + 8 - directory_after_insert) % 8,
            4
        );
        assert_eq!(directory.occupied_record_count()?, 1);
        assert_eq!(directory.read_record(3)?, Some(directory_original));

        events.insert_record_unique(3, event_original)?;
        assert_eq!(
            events.insert_record_unique(3, event_replacement),
            Err(RostlStoreError::DuplicateKey)
        );
        assert_eq!(events.occupied_record_count()?, 1);
        assert_eq!(events.read_record(3)?, Some(event_original));
        Ok(())
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn exact_typed_stores_insert_and_update_both_record_widths(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut directory = RostlTable::<PersistentAddressDirectory>::new(8)?;
        let directory_original = directory_record(0x31, 3);
        let directory_replacement = directory_record(0x32, 3);

        let directory_before = directory.oram.evict_counter;
        assert_eq!(
            directory
                .insert_or_update_record(3, InsertOrUpdateRequest::insert(directory_original))?,
            ExactUpsertDisposition::Inserted
        );
        let directory_after_insert = directory.oram.evict_counter;
        assert_eq!((directory_after_insert + 8 - directory_before) % 8, 4);
        assert_eq!(directory.occupied_record_count()?, 1);

        assert_eq!(
            directory.insert_or_update_record(
                3,
                InsertOrUpdateRequest::update(directory_original, directory_replacement)
            )?,
            ExactUpsertDisposition::Updated
        );
        let directory_after_update = directory.oram.evict_counter;
        assert_eq!((directory_after_update + 8 - directory_after_insert) % 8, 4);
        assert_eq!(directory.occupied_record_count()?, 1);
        assert_eq!(directory.read_record(3)?, Some(directory_replacement));

        let mut events = RostlTable::<PersistentAddressEventPage>::new(8)?;
        let event_original = event_record(0x41, 3)?;
        let event_replacement = event_record(0x42, 3)?;
        assert_eq!(
            events.insert_or_update_record(3, InsertOrUpdateRequest::insert(event_original))?,
            ExactUpsertDisposition::Inserted
        );
        assert_eq!(
            events.insert_or_update_record(
                3,
                InsertOrUpdateRequest::update(event_original, event_replacement)
            )?,
            ExactUpsertDisposition::Updated
        );
        assert_eq!(events.occupied_record_count()?, 1);
        assert_eq!(events.read_record(3)?, Some(event_replacement));
        Ok(())
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn exact_upsert_mismatches_latch_the_real_store_after_full_schedule(
    ) -> Result<(), RostlStoreError> {
        let original = directory_record(0x31, 3);
        let replacement = directory_record(0x32, 3);
        let wrong_prior = directory_record(0x33, 3);

        let mut occupied_mismatch = RostlTable::<PersistentAddressDirectory>::new(8)?;
        assert_eq!(
            occupied_mismatch
                .insert_or_update_record(3, InsertOrUpdateRequest::insert(original))?,
            ExactUpsertDisposition::Inserted
        );
        let before_occupied_mismatch = occupied_mismatch.oram.evict_counter;
        assert_eq!(
            occupied_mismatch.insert_or_update_record(
                3,
                InsertOrUpdateRequest::update(wrong_prior, replacement)
            ),
            Err(RostlStoreError::ExactUpsertMismatch)
        );
        assert_eq!(
            (occupied_mismatch.oram.evict_counter + 8 - before_occupied_mismatch) % 8,
            4
        );
        assert_eq!(
            occupied_mismatch.read_record(3),
            Err(RostlStoreError::FailedClosed)
        );

        let mut absent_mismatch = RostlTable::<PersistentAddressDirectory>::new(8)?;
        let before_absent_mismatch = absent_mismatch.oram.evict_counter;
        assert_eq!(
            absent_mismatch
                .insert_or_update_record(3, InsertOrUpdateRequest::update(original, replacement)),
            Err(RostlStoreError::ExactUpsertMismatch)
        );
        assert_eq!(
            (absent_mismatch.oram.evict_counter + 8 - before_absent_mismatch) % 8,
            4
        );
        assert_eq!(
            absent_mismatch.occupied_record_count(),
            Err(RostlStoreError::FailedClosed)
        );
        Ok(())
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn exact_upsert_reserve_refusal_keeps_the_real_store_usable() -> Result<(), RostlStoreError> {
        let mut store = RostlTable::<PersistentAddressDirectory>::new(8)?;
        for key in 0..7 {
            store.insert_record_unique(key, directory_record(key as u8 + 1, key as u32))?;
        }
        assert_eq!(store.occupied_record_count()?, 7);

        let before = store.oram.evict_counter;
        assert_eq!(
            store.insert_or_update_record(
                3,
                InsertOrUpdateRequest::update(directory_record(4, 3), directory_record(0xf0, 3))
            ),
            Err(RostlStoreError::UpsertReserveExhausted)
        );
        assert_eq!(store.oram.evict_counter, before);
        assert_eq!(store.occupied_record_count()?, 7);
        assert_eq!(store.read_record(3)?, Some(directory_record(4, 3)));
        Ok(())
    }

    /// A full table is refused from public occupancy alone, before any access,
    /// so no insertion into it can reveal whether the key was present.
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn full_store_refuses_every_insertion_without_accessing() -> Result<(), RostlStoreError> {
        let mut store = RostlTable::<PersistentAddressDirectory>::new(8)?;
        for key in 0..8 {
            store.insert_record_unique(key, directory_record(key as u8 + 1, key as u32))?;
        }
        assert_eq!(store.occupied_record_count()?, 8);

        let before = store.oram.evict_counter;
        assert_eq!(
            store.insert_record_unique(3, directory_record(0xf0, 7)),
            Err(RostlStoreError::TableFull)
        );
        assert_eq!(store.oram.evict_counter, before);

        // A full table is a refusal, not corruption: the store must stay
        // readable rather than latching failed-closed.
        assert_eq!(store.occupied_record_count()?, 8);
        assert_eq!(store.read_record(3)?, Some(directory_record(4, 3)));
        Ok(())
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    fn test_layout() -> Result<FixedProbeLayout<4, 4>, crate::layout::LayoutConfigError> {
        FixedProbeLayout::new(
            LayoutIdentity::new(LayoutNetwork::Mainnet, 1, 1, 1, [0x5a; 32])?,
            DirectoryTableConfiguration::<4>::new(8, 6)?,
            EventTableConfiguration::<4>::new(16, 12)?,
            2,
        )
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn exact_typed_executor_runs_behind_the_business_worker(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let worker = build_rostl_worker(test_layout()?, AtomicQueueCapacity::try_new(2)?)?;
        let handle = worker.handle();
        let address = StandardAddress::new(StandardScriptKind::PayToPublicKeyHash, [0x61; 20]);
        let event = UtxoEvent::created(
            [0x71; TXID_BYTES],
            1,
            50_000,
            100,
            UtxoScriptClass::PayToPublicKeyHash,
            [0x61; 20],
        );

        let appended = handle.try_append(address, event)?.wait()?;
        assert_eq!(appended.events(), &[Some(event), None]);
        let read = handle.try_read_history(address)?.wait()?;
        assert_eq!(read.events(), &[Some(event), None]);
        let snapshot = worker.shutdown()?;
        assert_eq!(snapshot.completed, 2);
        assert_eq!(snapshot.failed, 0);
        Ok(())
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    fn probe_contains<T>(
        probe: &mut InsertProbe<T>,
        table: usize,
        key: usize,
    ) -> Result<bool, RostlTimingError>
    where
        T: TimingProbeRecord,
    {
        probe
            .tables
            .get_mut(table)
            .ok_or(RostlTimingError::PairState)?
            .read_record(key)
            .map(|record| record.is_some())
            .map_err(|_| RostlTimingError::PairState)
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    fn assert_probe_boundary<T>(
        probe: &mut InsertProbe<T>,
        mode: RostlTimingMode,
        expected_occupancy: usize,
    ) -> Result<(), RostlTimingError>
    where
        T: TimingProbeRecord,
    {
        assert_eq!(probe.current_occupancy, expected_occupancy);
        for table in &probe.tables {
            assert_eq!(
                usize::try_from(
                    table
                        .occupied_record_count()
                        .map_err(|_| RostlTimingError::PairState)?
                )
                .map_err(|_| RostlTimingError::PairState)?,
                expected_occupancy
            );
        }
        let hit_table = probe.hit_label_table;
        let miss_table = other_table(hit_table)?;
        let probe_key = probe.probe_key;
        match mode {
            RostlTimingMode::HitMiss => {
                let substitute = probe.substitute_key.ok_or(RostlTimingError::PairState)?;
                assert!(probe_contains(probe, hit_table, probe_key)?);
                assert!(!probe_contains(probe, miss_table, probe_key)?);
                assert!(!probe_contains(probe, hit_table, substitute)?);
                assert!(probe_contains(probe, miss_table, substitute)?);
            }
            RostlTimingMode::ForcedHit => {
                assert!(probe_contains(probe, hit_table, probe_key)?);
                assert!(probe_contains(probe, miss_table, probe_key)?);
            }
            RostlTimingMode::ForcedMiss => {
                assert!(!probe_contains(probe, hit_table, probe_key)?);
                assert!(!probe_contains(probe, miss_table, probe_key)?);
            }
        }
        Ok(())
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    fn exercise_long_lived_probe<T>(mode: RostlTimingMode) -> Result<(), RostlTimingError>
    where
        T: TimingProbeRecord,
    {
        const INITIAL_OCCUPANCY: usize = 3;
        const PAIRS: usize = 4;
        let mut probe = InsertProbe::<T>::new(16, INITIAL_OCCUPANCY, PAIRS, mode)?;

        for pair in 0..PAIRS {
            assert_probe_boundary(&mut probe, mode, INITIAL_OCCUPANCY + pair)?;
            let before_hit_table = probe.hit_label_table;
            let scheduled = if pair.is_multiple_of(2) {
                [Arm::Hit, Arm::Miss]
            } else {
                [Arm::Miss, Arm::Hit]
            };
            for arm in scheduled {
                let executed = match mode {
                    RostlTimingMode::HitMiss => arm,
                    RostlTimingMode::ForcedHit => Arm::Hit,
                    RostlTimingMode::ForcedMiss => Arm::Miss,
                };
                let _ = probe.measure(arm, executed)?;
            }
            probe.finish_pair()?;
            assert_eq!(probe.hit_label_table, other_table(before_hit_table)?);
        }
        assert_probe_boundary(&mut probe, mode, INITIAL_OCCUPANCY + PAIRS)?;
        if mode == RostlTimingMode::HitMiss {
            assert_eq!(probe.cover_trace, vec![0, 1, 0, 1, 0, 1, 0, 1]);
        }
        Ok(())
    }

    /// Both scheduled orders preserve equal occupancy and the mode-specific key
    /// invariant for both production record widths.
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn long_lived_probes_preserve_pair_invariants_for_both_record_kinds(
    ) -> Result<(), RostlTimingError> {
        for mode in [
            RostlTimingMode::HitMiss,
            RostlTimingMode::ForcedHit,
            RostlTimingMode::ForcedMiss,
        ] {
            exercise_long_lived_probe::<PersistentAddressDirectory>(mode)?;
            exercise_long_lived_probe::<PersistentAddressEventPage>(mode)?;
        }
        Ok(())
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn malformed_pair_lifecycle_fails_closed() -> Result<(), RostlTimingError> {
        let mut duplicate =
            InsertProbe::<PersistentAddressDirectory>::new(16, 3, 2, RostlTimingMode::HitMiss)?;
        let _ = duplicate.measure(Arm::Hit, Arm::Hit)?;
        assert_eq!(
            duplicate.measure(Arm::Hit, Arm::Hit),
            Err(RostlTimingError::PairState)
        );

        let mut incomplete =
            InsertProbe::<PersistentAddressDirectory>::new(16, 3, 2, RostlTimingMode::HitMiss)?;
        let _ = incomplete.measure(Arm::Hit, Arm::Hit)?;
        assert_eq!(incomplete.finish_pair(), Err(RostlTimingError::PairState));

        let mut drifted =
            InsertProbe::<PersistentAddressDirectory>::new(16, 3, 2, RostlTimingMode::HitMiss)?;
        drifted.tables[0].occupied_records = 4;
        assert_eq!(
            drifted.verify_pair_boundary(3),
            Err(RostlTimingError::PairState)
        );
        Ok(())
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn probe_shape_reserves_growth_and_one_union_key() {
        assert_eq!(
            InsertProbe::<PersistentAddressDirectory>::new(8, 0, 1, RostlTimingMode::HitMiss).err(),
            Some(RostlTimingError::InvalidShape)
        );
        assert_eq!(
            InsertProbe::<PersistentAddressDirectory>::new(8, 3, 5, RostlTimingMode::HitMiss).err(),
            Some(RostlTimingError::InvalidShape)
        );
        assert!(
            InsertProbe::<PersistentAddressDirectory>::new(16, 3, 5, RostlTimingMode::HitMiss)
                .is_ok()
        );
        assert_eq!(
            InsertProbe::<PersistentAddressDirectory>::new(7, 3, 1, RostlTimingMode::HitMiss).err(),
            Some(RostlTimingError::InvalidShape)
        );
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn synthetic_caught_panic_latches_and_blocks_later_access() -> Result<(), RostlStoreError> {
        let mut store = RostlTable::<PersistentAddressDirectory>::new(8)?;
        let panic = catch_upstream(|| -> () { panic!("identifier-free injected panic") });
        assert_eq!(
            store.finish_upstream(panic),
            Err(RostlStoreError::UpstreamPanic)
        );
        assert_eq!(
            store.occupied_record_count(),
            Err(RostlStoreError::FailedClosed)
        );
        assert_eq!(store.read_record(0), Err(RostlStoreError::FailedClosed));
        let accesses = store.oram.evict_counter;
        assert_eq!(
            store.insert_record_unique(0, directory_record(1, 0)),
            Err(RostlStoreError::FailedClosed)
        );
        assert_eq!(store.oram.evict_counter, accesses);
        Ok(())
    }
}
