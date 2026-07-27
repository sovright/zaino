//! Private typed `rostl` tables for the exclusive business-command worker.
//!
//! This remains a volatile, Linux-x86_64-only research backend. The portable
//! insertion core is kept here so its missing/duplicate schedule can be tested
//! on every host that enables `rostl-experimental`.
//! The Linux-only worker constructor is consumed only by the crate-internal
//! offline projection owner.

use std::{fmt, marker::PhantomData};

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
#[cfg(any(test, all(target_os = "linux", target_arch = "x86_64")))]
use crate::records::{PersistentAddressDirectory, PersistentAddressEventPage};

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct UniqueInsertCommit {
    disposition: UniqueInsertDisposition,
    occupied_records: u64,
}

trait FixedUniqueInsertAccess<T> {
    fn read_and_remap(&mut self, key: usize, value: &mut T) -> bool;

    fn write_or_insert_and_remap(&mut self, key: usize, value: T) -> bool;
}

fn fixed_unique_insert<T, A>(
    access: &mut A,
    key: usize,
    candidate: T,
    occupied_records: u64,
    capacity: u64,
) -> Result<UniqueInsertCommit, RostlStoreError>
where
    T: Cmov + Copy + Default,
    A: FixedUniqueInsertAccess<T>,
{
    let mut prior = T::default();
    let found_before = access.read_and_remap(key, &mut prior);

    // A healthy accepted-domain miss and duplicate both continue to the second
    // access. These early exits are only for already-inconsistent occupancy,
    // where attempting a missing-key insertion could exceed physical capacity.
    if occupied_records > capacity
        || (found_before && occupied_records == 0)
        || (!found_before && occupied_records == capacity)
    {
        return Err(RostlStoreError::OccupancyInvariant);
    }
    let next_occupied = occupied_records
        .checked_add(u64::from(!found_before))
        .ok_or(RostlStoreError::OccupancyInvariant)?;

    let mut selected = candidate;
    selected.cmov(&prior, found_before);
    let found_after = access.write_or_insert_and_remap(key, selected);
    if found_after != found_before {
        return Err(RostlStoreError::FoundMismatch);
    }

    Ok(UniqueInsertCommit {
        disposition: if found_before {
            UniqueInsertDisposition::Duplicate
        } else {
            UniqueInsertDisposition::Inserted
        },
        occupied_records: next_occupied,
    })
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
        if capacity < 2 || capacity > u32::MAX as usize || !capacity.is_power_of_two() {
            return Err(RostlStoreError::InvalidCapacity);
        }

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
            let result = catch_upstream(|| {
                fixed_unique_insert(self, key, value, occupied_records, capacity)
            });
            let commit = match self.finish_upstream(result)? {
                Ok(commit) => commit,
                Err(error) => {
                    self.failed_closed = true;
                    return Err(error);
                }
            };
            self.occupied_records = commit.occupied_records;
            match commit.disposition {
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
    FoundMismatch,
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
            Self::FoundMismatch => f.write_str("typed rostl store access results are inconsistent"),
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

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn catch_upstream<R>(operation: impl FnOnce() -> R) -> Result<R, ()> {
    catch_unwind(AssertUnwindSafe(operation)).map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    use crate::{
        layout::{
            DirectoryTableConfiguration, EventTableConfiguration, LayoutIdentity, LayoutNetwork,
            StandardAddress, StandardScriptKind,
        },
        records::{
            AddressDirectory, AddressEventPage, AddressKey, UtxoEvent, UtxoScriptClass, TXID_BYTES,
        },
    };

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

    #[test]
    fn healthy_missing_and_duplicate_use_the_same_two_access_schedule(
    ) -> Result<(), RostlStoreError> {
        let mut missing = FakeAccess::default();
        let inserted = fixed_unique_insert(&mut missing, 3, 7, 0, 8)?;
        assert_eq!(inserted.disposition, UniqueInsertDisposition::Inserted);
        assert_eq!(inserted.occupied_records, 1);
        assert_eq!(missing.record, Some(7));

        let mut duplicate = FakeAccess {
            record: Some(11),
            ..FakeAccess::default()
        };
        let rejected = fixed_unique_insert(&mut duplicate, 3, 99, 1, 8)?;
        assert_eq!(rejected.disposition, UniqueInsertDisposition::Duplicate);
        assert_eq!(rejected.occupied_records, 1);
        assert_eq!(duplicate.record, Some(11));
        assert_eq!(missing.trace, duplicate.trace);
        assert_eq!(
            missing.trace,
            vec![AccessKind::Read, AccessKind::WriteOrInsert]
        );
        Ok(())
    }

    #[test]
    fn found_mismatch_is_rejected_after_both_accesses() {
        let mut access = FakeAccess {
            record: Some(11),
            forced_write_result: Some(false),
            ..FakeAccess::default()
        };
        assert_eq!(
            fixed_unique_insert(&mut access, 3, 99, 1, 8),
            Err(RostlStoreError::FoundMismatch)
        );
        assert_eq!(
            access.trace,
            vec![AccessKind::Read, AccessKind::WriteOrInsert]
        );
        assert_eq!(access.record, Some(11));
    }

    #[test]
    fn impossible_occupancy_fails_before_a_risky_second_access() {
        let mut access = FakeAccess::default();
        assert_eq!(
            fixed_unique_insert(&mut access, 3, 99, 8, 8),
            Err(RostlStoreError::OccupancyInvariant)
        );
        assert_eq!(access.trace, vec![AccessKind::Read]);
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
    fn full_store_duplicate_still_completes_both_accesses() -> Result<(), RostlStoreError> {
        let mut store = RostlTable::<PersistentAddressDirectory>::new(8)?;
        for key in 0..8 {
            store.insert_record_unique(key, directory_record(key as u8 + 1, key as u32))?;
        }
        assert_eq!(store.occupied_record_count()?, 8);
        let before = store.oram.evict_counter;
        assert_eq!(
            store.insert_record_unique(3, directory_record(0xf0, 7)),
            Err(RostlStoreError::DuplicateKey)
        );
        let after = store.oram.evict_counter;
        assert_eq!((after + 8 - before) % 8, 4);
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
