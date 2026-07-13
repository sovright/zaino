//! Exclusive, in-memory two-table execution for one fixed layout generation.
//!
//! This module models a synchronous owner and a nested bounded worker that
//! consumes that complete owner. A private projection sink seam can drive the
//! worker, but no projection coordinator, query engine, or service constructs
//! that owner, and it makes no persistence or physical-obliviousness claim.
//! "Exclusive" means one executor command completes its scan and preflight
//! without another executor command interleaving. A new-address append still
//! performs two sequential writes; it is not an all-or-nothing transaction,
//! and a second-write failure leaves an unusable partial candidate.
//!
//! Catching a backend panic does not suppress the process-wide panic hook.
//! Real backend integration therefore remains blocked on a panic-free or
//! otherwise controlled backend boundary.

use std::{
    fmt,
    panic::{catch_unwind, AssertUnwindSafe},
};

use super::*;

mod worker;

/// A sparse fixed-capacity table whose insert never overwrites an existing key.
///
/// Each handle must have unaliased backing state for the lifetime of a command.
/// A backend error is deliberately opaque. Once any operation errors or
/// panics, the executor terminal-latches the complete two-table generation as
/// unusable pending owner-managed discard because a read may have remapped
/// backend state and a write outcome may be uncertain. This does not zeroize or
/// physically discard backend state. Backend panic payloads must not contain
/// identifiers or other protected data because the process-wide panic hook
/// still runs.
trait UniqueTable<T> {
    fn capacity(&self) -> usize;

    fn read(&mut self, index: usize) -> Result<Option<T>, BackendFailure>;

    /// Returns the backend-owned count of occupied records.
    fn occupied_records(&mut self) -> Result<u64, BackendFailure>;

    fn insert_unique(&mut self, index: usize, value: T) -> Result<(), BackendFailure>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BackendFailure;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExecutorState {
    Ready,
    Discarded,
}

/// Fixed-profile history returned only inside the offline experiment.
#[derive(PartialEq, Eq)]
struct FixedEventHistory {
    slots: Vec<Option<UtxoEvent>>,
}

impl FixedEventHistory {
    fn events(&self) -> &[Option<UtxoEvent>] {
        &self.slots
    }
}

impl fmt::Debug for FixedEventHistory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FixedEventHistory { ..REDACTED.. }")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AppendDisposition {
    Inserted,
    ExactReplay,
}

#[derive(PartialEq, Eq)]
struct AppendResult {
    disposition: AppendDisposition,
    history: FixedEventHistory,
}

impl fmt::Debug for AppendResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AppendResult { ..REDACTED.. }")
    }
}

struct AtomicPlan<const DIRECTORY_PROBES: usize> {
    profile_binding: [u8; 32],
    address: StandardAddress,
    directory: DirectoryProbePlan<DIRECTORY_PROBES>,
    append: Option<UtxoEvent>,
}

impl<const DIRECTORY_PROBES: usize> fmt::Debug for AtomicPlan<DIRECTORY_PROBES> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AtomicPlan { ..REDACTED.. }")
    }
}

enum DirectoryPreflight {
    Found(BoundDirectory),
    Vacant {
        vacancy: DirectoryVacancy,
        prospective: Option<ProspectiveDirectory>,
    },
    Full,
    Corrupt,
}

enum NextEventPreflight {
    Vacant(EventVacancy),
    Full,
}

/// Owns one directory-backend handle and one event-backend handle.
struct ExclusiveTwoTableExecutor<D, E, const DIRECTORY_PROBES: usize, const EVENT_PROBES: usize>
where
    D: UniqueTable<PersistentAddressDirectory>,
    E: UniqueTable<PersistentAddressEventPage>,
{
    layout: FixedProbeLayout<DIRECTORY_PROBES, EVENT_PROBES>,
    directory: D,
    events: E,
    state: ExecutorState,
}

impl<D, E, const DIRECTORY_PROBES: usize, const EVENT_PROBES: usize>
    ExclusiveTwoTableExecutor<D, E, DIRECTORY_PROBES, EVENT_PROBES>
where
    D: UniqueTable<PersistentAddressDirectory>,
    E: UniqueTable<PersistentAddressEventPage>,
{
    fn new(
        layout: FixedProbeLayout<DIRECTORY_PROBES, EVENT_PROBES>,
        directory: D,
        events: E,
    ) -> Result<Self, AtomicStoreError> {
        let directory_capacity = usize::try_from(layout.directory.0.capacity).map_err(|_| {
            AtomicStoreError::BackendCapacityMismatch {
                table: TableKind::Directory,
            }
        })?;
        if directory.capacity() != directory_capacity {
            return Err(AtomicStoreError::BackendCapacityMismatch {
                table: TableKind::Directory,
            });
        }
        let event_capacity = usize::try_from(layout.event.0.capacity).map_err(|_| {
            AtomicStoreError::BackendCapacityMismatch {
                table: TableKind::Event,
            }
        })?;
        if events.capacity() != event_capacity {
            return Err(AtomicStoreError::BackendCapacityMismatch {
                table: TableKind::Event,
            });
        }
        Ok(Self {
            layout,
            directory,
            events,
            state: ExecutorState::Ready,
        })
    }

    fn read_history(
        &mut self,
        address: StandardAddress,
    ) -> Result<FixedEventHistory, AtomicStoreError> {
        let plan = self.plan(address, None);
        self.execute(plan).map(|result| result.history)
    }

    fn append(
        &mut self,
        address: StandardAddress,
        event: UtxoEvent,
    ) -> Result<AppendResult, AtomicStoreError> {
        let plan = self.plan(address, Some(event));
        self.execute(plan)
    }

    fn plan(
        &self,
        address: StandardAddress,
        append: Option<UtxoEvent>,
    ) -> AtomicPlan<DIRECTORY_PROBES> {
        AtomicPlan {
            profile_binding: self.layout.profile_binding,
            address,
            directory: self.layout.directory_plan(address),
            append,
        }
    }

    fn execute(
        &mut self,
        plan: AtomicPlan<DIRECTORY_PROBES>,
    ) -> Result<AppendResult, AtomicStoreError> {
        self.ensure_ready()?;
        if plan
            .append
            .is_some_and(|event| StandardAddress::from_event(&event) != Ok(plan.address))
        {
            return Err(AtomicStoreError::Conflict);
        }
        match catch_unwind(AssertUnwindSafe(|| self.execute_inner(plan))) {
            Ok(result) => result,
            Err(_) => Err(self.discard(AtomicStoreError::UnexpectedPanic)),
        }
    }

    fn execute_inner(
        &mut self,
        plan: AtomicPlan<DIRECTORY_PROBES>,
    ) -> Result<AppendResult, AtomicStoreError> {
        let directory_indices = self.validate_plan(&plan)?;
        let max_events = usize::try_from(self.layout.max_events_per_address)
            .map_err(|_| AtomicStoreError::ResultAllocationFailed)?;
        let mut history = Vec::new();
        history
            .try_reserve_exact(max_events)
            .map_err(|_| AtomicStoreError::ResultAllocationFailed)?;
        history.resize(max_events, None);

        let directory_reads = self.read_directory(directory_indices)?;
        let directory_scan = self.layout.scan_directory(&plan.directory, directory_reads);
        let mut terminal = None;
        let mut directory = match directory_scan {
            Ok(DirectoryScan::Found(bound)) => DirectoryPreflight::Found(bound),
            Ok(DirectoryScan::Vacant(vacancy)) => {
                let prospective = if plan.append.is_some() {
                    match self.layout.prospective_directory(&vacancy) {
                        Ok(prospective) => Some(prospective),
                        Err(_) => {
                            latch_error(&mut terminal, AtomicStoreError::CorruptLayout);
                            None
                        }
                    }
                } else {
                    None
                };
                DirectoryPreflight::Vacant {
                    vacancy,
                    prospective,
                }
            }
            Ok(DirectoryScan::Full) => DirectoryPreflight::Full,
            Err(_) => {
                latch_error(&mut terminal, AtomicStoreError::CorruptLayout);
                DirectoryPreflight::Corrupt
            }
        };

        let mut gap_seen = false;
        let mut found_events = 0_u64;
        let mut exact_replays = 0_u64;
        let mut next_event = None;
        for (ordinal_index, history_slot) in history.iter_mut().enumerate() {
            let ordinal = u64::try_from(ordinal_index)
                .map_err(|_| self.discard(AtomicStoreError::CorruptLayout))?;
            let event_plan = match &directory {
                DirectoryPreflight::Found(bound) => self.layout.event_plan(bound, ordinal),
                DirectoryPreflight::Vacant {
                    prospective: Some(prospective),
                    ..
                } => self.layout.prospective_event_plan(prospective, ordinal),
                DirectoryPreflight::Vacant {
                    prospective: None, ..
                }
                | DirectoryPreflight::Full
                | DirectoryPreflight::Corrupt => self.layout.cover_event_plan(ordinal),
            };
            let event_plan = match event_plan {
                Ok(plan) => plan,
                Err(_) => {
                    latch_error(&mut terminal, AtomicStoreError::CorruptLayout);
                    self.layout
                        .cover_event_plan(ordinal)
                        .map_err(|_| self.discard(AtomicStoreError::CorruptLayout))?
                }
            };
            let event_indices = self
                .layout
                .event_backend_indices(&event_plan)
                .map_err(|_| self.discard(AtomicStoreError::CorruptLayout))?;
            let event_reads = self.read_events(event_indices)?;
            let scan = self.layout.scan_event(&event_plan, event_reads);
            match scan {
                Ok(EventScan::Found(page)) => {
                    if !matches!(directory, DirectoryPreflight::Found(_)) {
                        latch_error(&mut terminal, AtomicStoreError::ProspectiveEventOrphan);
                    }
                    if gap_seen {
                        latch_error(&mut terminal, AtomicStoreError::NonContiguousEventHistory);
                    }
                    match page.event().copied() {
                        Some(found) => {
                            *history_slot = Some(found);
                            found_events = found_events.saturating_add(1);
                            if plan.append == Some(found) {
                                exact_replays = exact_replays.saturating_add(1);
                            }
                        }
                        None => latch_error(&mut terminal, AtomicStoreError::CorruptLayout),
                    }
                }
                Ok(EventScan::Vacant(vacancy)) => {
                    if !gap_seen {
                        next_event = Some(NextEventPreflight::Vacant(vacancy));
                    }
                    gap_seen = true;
                }
                Ok(EventScan::Full) => {
                    if !gap_seen {
                        next_event = Some(NextEventPreflight::Full);
                    }
                    gap_seen = true;
                }
                Err(_) => {
                    latch_error(&mut terminal, AtomicStoreError::CorruptLayout);
                    gap_seen = true;
                }
            }
        }

        if exact_replays > 1 {
            latch_error(&mut terminal, AtomicStoreError::Conflict);
        }
        if matches!(directory, DirectoryPreflight::Found(_)) && found_events == 0 {
            latch_error(&mut terminal, AtomicStoreError::CorruptLayout);
        }
        let append_occupancies = if plan.append.is_some() {
            let occupancies = self.backend_occupancies()?;
            if found_events > occupancies.1
                || (matches!(directory, DirectoryPreflight::Found(_)) && occupancies.0 == 0)
            {
                latch_error(&mut terminal, AtomicStoreError::OccupancyInvariant);
            }
            Some(occupancies)
        } else {
            None
        };
        if let Some(error) = terminal {
            return Err(self.discard(error));
        }

        let fixed_history = FixedEventHistory { slots: history };
        let Some(event) = plan.append else {
            return Ok(AppendResult {
                disposition: AppendDisposition::ExactReplay,
                history: fixed_history,
            });
        };
        if exact_replays == 1 {
            return Ok(AppendResult {
                disposition: AppendDisposition::ExactReplay,
                history: fixed_history,
            });
        }

        if matches!(directory, DirectoryPreflight::Full) {
            return Err(self.discard(AtomicStoreError::ProbeSetFull {
                table: TableKind::Directory,
            }));
        }
        if found_events == u64::from(self.layout.max_events_per_address) {
            return Err(self.discard(AtomicStoreError::AddressEventLimitReached));
        }
        let event_vacancy = match next_event {
            Some(NextEventPreflight::Vacant(vacancy)) => vacancy,
            Some(NextEventPreflight::Full) | None => {
                return Err(self.discard(AtomicStoreError::ProbeSetFull {
                    table: TableKind::Event,
                }));
            }
        };

        let Some((directory_occupancy, event_occupancy)) = append_occupancies else {
            return Err(self.discard(AtomicStoreError::OccupancyInvariant));
        };
        let inserted_ordinal = usize::try_from(found_events)
            .map_err(|_| self.discard(AtomicStoreError::OccupancyInvariant))?;
        let mut inserted_history = fixed_history;
        let Some(inserted_slot) = inserted_history.slots.get_mut(inserted_ordinal) else {
            return Err(self.discard(AtomicStoreError::OccupancyInvariant));
        };
        *inserted_slot = Some(event);

        let prepared_event = self
            .layout
            .prepare_event_insert(EventScan::Vacant(event_vacancy), event, event_occupancy)
            .map_err(|error| self.map_mutation_error(error))?;
        let event_insert = self
            .layout
            .backend_event_insert(prepared_event)
            .map_err(|_| self.discard(AtomicStoreError::CorruptLayout))?;

        let directory_insert = match &mut directory {
            DirectoryPreflight::Vacant { vacancy, .. } => {
                let vacancy = DirectoryVacancy {
                    profile_binding: vacancy.profile_binding,
                    address_key: vacancy.address_key,
                    slot: vacancy.slot,
                };
                let prepared = self
                    .layout
                    .prepare_directory_insert(DirectoryScan::Vacant(vacancy), directory_occupancy)
                    .map_err(|error| self.map_mutation_error(error))?;
                Some(
                    self.layout
                        .backend_directory_insert(prepared)
                        .map_err(|_| self.discard(AtomicStoreError::CorruptLayout))?,
                )
            }
            DirectoryPreflight::Found(_) => None,
            DirectoryPreflight::Full | DirectoryPreflight::Corrupt => {
                return Err(self.discard(AtomicStoreError::CorruptLayout));
            }
        };

        if let Some((index, value)) = directory_insert {
            self.insert_directory(index, value)?;
        }
        self.insert_event(event_insert.0, event_insert.1)?;

        Ok(AppendResult {
            disposition: AppendDisposition::Inserted,
            history: inserted_history,
        })
    }

    fn validate_plan(
        &self,
        plan: &AtomicPlan<DIRECTORY_PROBES>,
    ) -> Result<[usize; DIRECTORY_PROBES], AtomicStoreError> {
        if !fixed_bytes_equal(&plan.profile_binding, &self.layout.profile_binding) {
            return Err(AtomicStoreError::PlanProfileMismatch);
        }
        let expected = self.layout.directory_plan(plan.address);
        if expected.address_key != plan.directory.address_key
            || expected.slots != plan.directory.slots
        {
            return Err(AtomicStoreError::InvalidPlan);
        }
        self.layout
            .directory_backend_indices(&plan.directory)
            .map_err(|_| AtomicStoreError::InvalidPlan)
    }

    fn read_directory(
        &mut self,
        indices: [usize; DIRECTORY_PROBES],
    ) -> Result<[ProbeRead<PersistentAddressDirectory>; DIRECTORY_PROBES], AtomicStoreError> {
        let mut reads = [ProbeRead::Miss; DIRECTORY_PROBES];
        for (read, index) in reads.iter_mut().zip(indices) {
            let result = catch_unwind(AssertUnwindSafe(|| self.directory.read(index)));
            *read = match result {
                Ok(Ok(Some(value))) => ProbeRead::Found(value),
                Ok(Ok(None)) => ProbeRead::Miss,
                Ok(Err(_)) => {
                    return Err(self.discard(AtomicStoreError::BackendFailure {
                        table: TableKind::Directory,
                    }));
                }
                Err(_) => {
                    return Err(self.discard(AtomicStoreError::BackendPanic {
                        table: TableKind::Directory,
                    }));
                }
            };
        }
        Ok(reads)
    }

    fn read_events(
        &mut self,
        indices: [usize; EVENT_PROBES],
    ) -> Result<[ProbeRead<PersistentAddressEventPage>; EVENT_PROBES], AtomicStoreError> {
        let mut reads = [ProbeRead::Miss; EVENT_PROBES];
        for (read, index) in reads.iter_mut().zip(indices) {
            let result = catch_unwind(AssertUnwindSafe(|| self.events.read(index)));
            *read = match result {
                Ok(Ok(Some(value))) => ProbeRead::Found(value),
                Ok(Ok(None)) => ProbeRead::Miss,
                Ok(Err(_)) => {
                    return Err(self.discard(AtomicStoreError::BackendFailure {
                        table: TableKind::Event,
                    }));
                }
                Err(_) => {
                    return Err(self.discard(AtomicStoreError::BackendPanic {
                        table: TableKind::Event,
                    }));
                }
            };
        }
        Ok(reads)
    }

    fn insert_directory(
        &mut self,
        index: usize,
        value: PersistentAddressDirectory,
    ) -> Result<(), AtomicStoreError> {
        match catch_unwind(AssertUnwindSafe(|| {
            self.directory.insert_unique(index, value)
        })) {
            Ok(Ok(())) => Ok(()),
            Ok(Err(_)) => Err(self.discard(AtomicStoreError::BackendFailure {
                table: TableKind::Directory,
            })),
            Err(_) => Err(self.discard(AtomicStoreError::BackendPanic {
                table: TableKind::Directory,
            })),
        }
    }

    fn insert_event(
        &mut self,
        index: usize,
        value: PersistentAddressEventPage,
    ) -> Result<(), AtomicStoreError> {
        match catch_unwind(AssertUnwindSafe(|| self.events.insert_unique(index, value))) {
            Ok(Ok(())) => Ok(()),
            Ok(Err(_)) => Err(self.discard(AtomicStoreError::BackendFailure {
                table: TableKind::Event,
            })),
            Err(_) => Err(self.discard(AtomicStoreError::BackendPanic {
                table: TableKind::Event,
            })),
        }
    }

    fn backend_occupancies(&mut self) -> Result<(u64, u64), AtomicStoreError> {
        let directory = match catch_unwind(AssertUnwindSafe(|| self.directory.occupied_records())) {
            Ok(Ok(occupied)) => occupied,
            Ok(Err(_)) => {
                return Err(self.discard(AtomicStoreError::BackendFailure {
                    table: TableKind::Directory,
                }));
            }
            Err(_) => {
                return Err(self.discard(AtomicStoreError::BackendPanic {
                    table: TableKind::Directory,
                }));
            }
        };
        let events = match catch_unwind(AssertUnwindSafe(|| self.events.occupied_records())) {
            Ok(Ok(occupied)) => occupied,
            Ok(Err(_)) => {
                return Err(self.discard(AtomicStoreError::BackendFailure {
                    table: TableKind::Event,
                }));
            }
            Err(_) => {
                return Err(self.discard(AtomicStoreError::BackendPanic {
                    table: TableKind::Event,
                }));
            }
        };
        if directory > u64::from(self.layout.directory.0.capacity)
            || events > u64::from(self.layout.event.0.capacity)
            || directory > u64::from(self.layout.directory.0.admission_limit)
            || events > u64::from(self.layout.event.0.admission_limit)
        {
            return Err(self.discard(AtomicStoreError::OccupancyInvariant));
        }
        Ok((directory, events))
    }

    fn map_mutation_error(&mut self, error: MutationPlanError) -> AtomicStoreError {
        match error {
            MutationPlanError::AdmissionLimitReached { table } => {
                self.discard(AtomicStoreError::AdmissionLimitReached { table })
            }
            MutationPlanError::ProbeSetFull { table } => {
                self.discard(AtomicStoreError::ProbeSetFull { table })
            }
            MutationPlanError::EventOwnerMismatch | MutationPlanError::AlreadyPresent { .. } => {
                self.discard(AtomicStoreError::Conflict)
            }
            MutationPlanError::VacancyProfileMismatch { .. }
            | MutationPlanError::PreparedProfileMismatch { .. }
            | MutationPlanError::BackendIndexOutsideHostDomain { .. }
            | MutationPlanError::CoverPlanNotInsertable => {
                self.discard(AtomicStoreError::CorruptLayout)
            }
        }
    }

    fn ensure_ready(&self) -> Result<(), AtomicStoreError> {
        match self.state {
            ExecutorState::Ready => Ok(()),
            ExecutorState::Discarded => Err(AtomicStoreError::Discarded),
        }
    }

    fn discard(&mut self, error: AtomicStoreError) -> AtomicStoreError {
        self.state = ExecutorState::Discarded;
        error
    }
}

fn latch_error(destination: &mut Option<AtomicStoreError>, error: AtomicStoreError) {
    if destination.is_none() {
        *destination = Some(error);
    }
}

/// Identifier-free outcome from the exclusive offline model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AtomicStoreError {
    BackendCapacityMismatch { table: TableKind },
    PlanProfileMismatch,
    InvalidPlan,
    ResultAllocationFailed,
    AdmissionLimitReached { table: TableKind },
    ProbeSetFull { table: TableKind },
    AddressEventLimitReached,
    ProspectiveEventOrphan,
    NonContiguousEventHistory,
    OccupancyInvariant,
    Conflict,
    CorruptLayout,
    BackendFailure { table: TableKind },
    BackendPanic { table: TableKind },
    UnexpectedPanic,
    Discarded,
}

impl fmt::Display for AtomicStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BackendCapacityMismatch { table } => {
                write!(f, "{table:?} backend capacity does not match the layout")
            }
            Self::PlanProfileMismatch => f.write_str("atomic plan belongs to another profile"),
            Self::InvalidPlan => f.write_str("atomic plan is invalid"),
            Self::ResultAllocationFailed => f.write_str("fixed history allocation failed"),
            Self::AdmissionLimitReached { table } => {
                write!(f, "{table:?} admission limit is reached")
            }
            Self::ProbeSetFull { table } => write!(f, "{table:?} probe set is full"),
            Self::AddressEventLimitReached => f.write_str("address event limit is reached"),
            Self::ProspectiveEventOrphan => {
                f.write_str("prospective directory slot already owns an event")
            }
            Self::NonContiguousEventHistory => {
                f.write_str("address event history is not contiguous")
            }
            Self::OccupancyInvariant => f.write_str("authoritative occupancy is inconsistent"),
            Self::Conflict => f.write_str("append conflicts with owned table state"),
            Self::CorruptLayout => f.write_str("protected layout is corrupt"),
            Self::BackendFailure { table } => write!(f, "{table:?} backend failed"),
            Self::BackendPanic { table } => write!(f, "{table:?} backend panicked"),
            Self::UnexpectedPanic => f.write_str("atomic execution panicked"),
            Self::Discarded => {
                f.write_str("two-table generation is unusable pending owner discard")
            }
        }
    }
}

impl std::error::Error for AtomicStoreError {}

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, collections::BTreeMap, rc::Rc};

    use super::*;
    use crate::records::TXID_BYTES;

    const DIRECTORY_PROBES: usize = 4;
    const EVENT_PROBES: usize = 4;
    const MAX_EVENTS: u64 = 3;

    type TestLayout = FixedProbeLayout<DIRECTORY_PROBES, EVENT_PROBES>;
    type TestExecutor = ExclusiveTwoTableExecutor<
        FakeTable<PersistentAddressDirectory>,
        FakeTable<PersistentAddressEventPage>,
        DIRECTORY_PROBES,
        EVENT_PROBES,
    >;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum FakeOperation {
        Read { table: TableKind, index: usize },
        Count { table: TableKind },
        Write { table: TableKind, index: usize },
    }

    struct FakeTable<T> {
        table: TableKind,
        capacity: usize,
        records: BTreeMap<usize, T>,
        reads: Vec<usize>,
        writes: Vec<usize>,
        trace: Rc<RefCell<Vec<FakeOperation>>>,
        reported_occupancy: Option<u64>,
        fail_next_insert: bool,
        mutate_then_fail_next_insert: bool,
        mutate_then_panic_next_insert: bool,
        panic_next_read: bool,
    }

    impl<T> FakeTable<T> {
        fn new(table: TableKind, capacity: usize, trace: Rc<RefCell<Vec<FakeOperation>>>) -> Self {
            Self {
                table,
                capacity,
                records: BTreeMap::new(),
                reads: Vec::new(),
                writes: Vec::new(),
                trace,
                reported_occupancy: None,
                fail_next_insert: false,
                mutate_then_fail_next_insert: false,
                mutate_then_panic_next_insert: false,
                panic_next_read: false,
            }
        }
    }

    impl<T: Copy> UniqueTable<T> for FakeTable<T> {
        fn capacity(&self) -> usize {
            self.capacity
        }

        fn read(&mut self, index: usize) -> Result<Option<T>, BackendFailure> {
            self.reads.push(index);
            self.trace.borrow_mut().push(FakeOperation::Read {
                table: self.table,
                index,
            });
            if self.panic_next_read {
                self.panic_next_read = false;
                panic!("injected backend read panic");
            }
            Ok(self.records.get(&index).copied())
        }

        fn occupied_records(&mut self) -> Result<u64, BackendFailure> {
            self.trace
                .borrow_mut()
                .push(FakeOperation::Count { table: self.table });
            self.reported_occupancy.map_or_else(
                || u64::try_from(self.records.len()).map_err(|_| BackendFailure),
                Ok,
            )
        }

        fn insert_unique(&mut self, index: usize, value: T) -> Result<(), BackendFailure> {
            self.writes.push(index);
            self.trace.borrow_mut().push(FakeOperation::Write {
                table: self.table,
                index,
            });
            if self.fail_next_insert {
                self.fail_next_insert = false;
                return Err(BackendFailure);
            }
            if self.records.contains_key(&index) {
                return Err(BackendFailure);
            }
            if self.mutate_then_fail_next_insert {
                self.mutate_then_fail_next_insert = false;
                self.records.insert(index, value);
                return Err(BackendFailure);
            }
            if self.mutate_then_panic_next_insert {
                self.mutate_then_panic_next_insert = false;
                self.records.insert(index, value);
                panic!("injected backend insert panic");
            }
            self.records.insert(index, value);
            Ok(())
        }
    }

    fn fake_tables(
        directory_capacity: usize,
        event_capacity: usize,
    ) -> (
        FakeTable<PersistentAddressDirectory>,
        FakeTable<PersistentAddressEventPage>,
    ) {
        let trace = Rc::new(RefCell::new(Vec::new()));
        (
            FakeTable::new(TableKind::Directory, directory_capacity, Rc::clone(&trace)),
            FakeTable::new(TableKind::Event, event_capacity, trace),
        )
    }

    fn layout(
        directory_admission: u64,
        event_admission: u64,
        generation: u64,
    ) -> Result<TestLayout, LayoutConfigError> {
        layout_with_max_events(directory_admission, event_admission, generation, MAX_EVENTS)
    }

    fn layout_with_max_events(
        directory_admission: u64,
        event_admission: u64,
        generation: u64,
        max_events: u64,
    ) -> Result<TestLayout, LayoutConfigError> {
        FixedProbeLayout::new(
            LayoutIdentity::new(LayoutNetwork::Mainnet, 1, 7, generation, [0x5a; 32])?,
            DirectoryTableConfiguration::new(8, directory_admission)?,
            EventTableConfiguration::new(16, event_admission)?,
            max_events,
        )
    }

    fn executor(
        directory_admission: u64,
        event_admission: u64,
    ) -> Result<TestExecutor, Box<dyn std::error::Error>> {
        let (directory, events) = fake_tables(8, 16);
        Ok(ExclusiveTwoTableExecutor::new(
            layout(directory_admission, event_admission, 11)?,
            directory,
            events,
        )?)
    }

    const fn address(byte: u8) -> StandardAddress {
        StandardAddress::new(StandardScriptKind::PayToPublicKeyHash, [byte; 20])
    }

    fn event(address: StandardAddress, byte: u8) -> UtxoEvent {
        UtxoEvent::created(
            [byte; TXID_BYTES],
            u32::from(byte),
            10_000 + u64::from(byte),
            100 + u32::from(byte),
            match address.kind {
                StandardScriptKind::PayToPublicKeyHash => UtxoScriptClass::PayToPublicKeyHash,
                StandardScriptKind::PayToScriptHash => UtxoScriptClass::PayToScriptHash,
            },
            address.hash,
        )
    }

    fn fixed_read_count() -> usize {
        DIRECTORY_PROBES
            + usize::try_from(MAX_EVENTS).expect("test maximum fits usize") * EVENT_PROBES
    }

    fn reads_from_records<T: Copy, const PROBES: usize>(
        records: &BTreeMap<usize, T>,
        indices: [usize; PROBES],
    ) -> [ProbeRead<T>; PROBES] {
        indices.map(|index| {
            records
                .get(&index)
                .copied()
                .map_or(ProbeRead::Miss, ProbeRead::Found)
        })
    }

    #[test]
    fn append_query_and_exact_replay_complete_the_fixed_read_schedule(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut executor = executor(6, 12)?;
        let owner = address(0x11);
        let first = event(owner, 0x21);
        let directory_plan = executor.layout.directory_plan(owner);
        let directory_indices = executor.layout.directory_backend_indices(&directory_plan)?;
        let DirectoryScan::Vacant(vacancy) = executor
            .layout
            .scan_directory(&directory_plan, [ProbeRead::Miss; DIRECTORY_PROBES])?
        else {
            return Err("empty directory did not produce a vacancy".into());
        };
        let prospective = executor.layout.prospective_directory(&vacancy)?;
        let mut expected_reads = Vec::with_capacity(fixed_read_count());
        expected_reads.extend(directory_indices.map(|index| FakeOperation::Read {
            table: TableKind::Directory,
            index,
        }));
        for ordinal in 0..MAX_EVENTS {
            let event_plan = executor
                .layout
                .prospective_event_plan(&prospective, ordinal)?;
            let event_indices = executor.layout.event_backend_indices(&event_plan)?;
            expected_reads.extend(event_indices.map(|index| FakeOperation::Read {
                table: TableKind::Event,
                index,
            }));
        }

        let inserted = executor.append(owner, first)?;
        assert_eq!(inserted.disposition, AppendDisposition::Inserted);
        assert_eq!(inserted.history.events()[0], Some(first));
        assert_eq!(executor.directory.reads.len(), DIRECTORY_PROBES);
        assert_eq!(
            executor.events.reads.len(),
            fixed_read_count() - DIRECTORY_PROBES
        );
        assert_eq!(executor.directory.writes.len(), 1);
        assert_eq!(executor.events.writes.len(), 1);
        {
            let trace = executor.directory.trace.borrow();
            assert_eq!(trace.len(), fixed_read_count() + 4);
            assert_eq!(&trace[..fixed_read_count()], expected_reads.as_slice());
            assert!(matches!(
                trace[fixed_read_count()],
                FakeOperation::Count {
                    table: TableKind::Directory
                }
            ));
            assert!(matches!(
                trace[fixed_read_count() + 1],
                FakeOperation::Count {
                    table: TableKind::Event
                }
            ));
            assert!(matches!(
                trace[fixed_read_count() + 2],
                FakeOperation::Write {
                    table: TableKind::Directory,
                    ..
                }
            ));
            assert!(matches!(
                trace[fixed_read_count() + 3],
                FakeOperation::Write {
                    table: TableKind::Event,
                    ..
                }
            ));
        }

        let replay = executor.append(owner, first)?;
        assert_eq!(replay.disposition, AppendDisposition::ExactReplay);
        assert_eq!(executor.directory.reads.len(), DIRECTORY_PROBES * 2);
        assert_eq!(
            executor.events.reads.len(),
            (fixed_read_count() - DIRECTORY_PROBES) * 2
        );
        assert_eq!(executor.directory.writes.len(), 1);
        assert_eq!(executor.events.writes.len(), 1);
        {
            let trace = executor.directory.trace.borrow();
            let replay_start = fixed_read_count() + 4;
            assert_eq!(trace.len(), replay_start + fixed_read_count() + 2);
            assert_eq!(
                &trace[replay_start..replay_start + fixed_read_count()],
                expected_reads.as_slice()
            );
            assert!(matches!(
                trace[replay_start + fixed_read_count()],
                FakeOperation::Count {
                    table: TableKind::Directory
                }
            ));
            assert!(matches!(
                trace[replay_start + fixed_read_count() + 1],
                FakeOperation::Count {
                    table: TableKind::Event
                }
            ));
        }

        let history = executor.read_history(owner)?;
        assert_eq!(history.events()[0], Some(first));
        assert_eq!(executor.directory.reads.len(), DIRECTORY_PROBES * 3);
        assert_eq!(
            executor.events.reads.len(),
            (fixed_read_count() - DIRECTORY_PROBES) * 3
        );
        Ok(())
    }

    #[test]
    fn second_append_uses_the_next_contiguous_ordinal() -> Result<(), Box<dyn std::error::Error>> {
        let mut executor = executor(6, 12)?;
        let owner = address(0x31);
        let first = event(owner, 0x41);
        let second = event(owner, 0x42);
        executor.append(owner, first)?;
        let result = executor.append(owner, second)?;

        assert_eq!(result.disposition, AppendDisposition::Inserted);
        assert_eq!(result.history.events()[..2], [Some(first), Some(second)]);
        assert_eq!(executor.directory.records.len(), 1);
        assert_eq!(executor.events.records.len(), 2);
        assert_eq!(executor.directory.writes.len(), 1);
        assert_eq!(executor.events.writes.len(), 2);
        Ok(())
    }

    #[test]
    fn event_admission_preflight_prevents_a_partial_new_directory_write(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (directory, events) = fake_tables(8, 16);
        let mut executor = ExclusiveTwoTableExecutor::new(
            layout_with_max_events(6, 1, 11, 1)?,
            directory,
            events,
        )?;
        let first_owner = address(0x51);
        executor.append(first_owner, event(first_owner, 0x52))?;
        let directory_writes = executor.directory.writes.len();
        let event_writes = executor.events.writes.len();
        let second_owner = address(0x53);
        let attempt_start = executor.directory.trace.borrow().len();

        assert_eq!(
            executor.append(second_owner, event(second_owner, 0x54)),
            Err(AtomicStoreError::AdmissionLimitReached {
                table: TableKind::Event,
            })
        );
        assert_eq!(executor.directory.writes.len(), directory_writes);
        assert_eq!(executor.events.writes.len(), event_writes);
        assert_eq!(executor.state, ExecutorState::Discarded);
        {
            let trace = executor.directory.trace.borrow();
            let attempt_reads = DIRECTORY_PROBES + EVENT_PROBES;
            assert_eq!(trace.len() - attempt_start, attempt_reads + 2);
            assert!(matches!(
                trace[attempt_start + attempt_reads],
                FakeOperation::Count {
                    table: TableKind::Directory
                }
            ));
            assert!(matches!(
                trace[attempt_start + attempt_reads + 1],
                FakeOperation::Count {
                    table: TableKind::Event
                }
            ));
        }
        assert_eq!(
            executor.read_history(second_owner),
            Err(AtomicStoreError::Discarded)
        );
        Ok(())
    }

    #[test]
    fn backend_owned_counts_enforce_admission_and_invariant_boundaries(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let owner = address(0x55);
        let mut at_admission = executor(6, 12)?;
        at_admission.directory.reported_occupancy = Some(6);
        assert_eq!(
            at_admission.append(owner, event(owner, 0x56)),
            Err(AtomicStoreError::AdmissionLimitReached {
                table: TableKind::Directory,
            })
        );
        assert!(at_admission.directory.writes.is_empty());
        assert!(at_admission.events.writes.is_empty());
        assert_eq!(at_admission.state, ExecutorState::Discarded);
        {
            let trace = at_admission.directory.trace.borrow();
            assert_eq!(trace.len(), fixed_read_count() + 2);
            assert!(matches!(
                trace[fixed_read_count()],
                FakeOperation::Count {
                    table: TableKind::Directory
                }
            ));
            assert!(matches!(
                trace[fixed_read_count() + 1],
                FakeOperation::Count {
                    table: TableKind::Event
                }
            ));
        }

        let mut above_admission = executor(6, 12)?;
        above_admission.directory.reported_occupancy = Some(7);
        assert_eq!(
            above_admission.append(owner, event(owner, 0x57)),
            Err(AtomicStoreError::OccupancyInvariant)
        );
        assert!(above_admission.directory.writes.is_empty());
        assert!(above_admission.events.writes.is_empty());
        assert_eq!(above_admission.state, ExecutorState::Discarded);
        Ok(())
    }

    #[test]
    fn owner_mismatch_is_rejected_before_io_without_discarding(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut executor = executor(6, 12)?;
        let requested = address(0x61);
        let other = address(0x62);

        assert_eq!(
            executor.append(requested, event(other, 0x63)),
            Err(AtomicStoreError::Conflict)
        );
        assert!(executor.directory.reads.is_empty());
        assert!(executor.events.reads.is_empty());
        assert!(executor.directory.writes.is_empty());
        assert!(executor.events.writes.is_empty());
        assert!(executor.directory.trace.borrow().is_empty());
        assert_eq!(executor.state, ExecutorState::Ready);
        assert_eq!(
            executor
                .append(requested, event(requested, 0x64))?
                .disposition,
            AppendDisposition::Inserted
        );
        Ok(())
    }

    #[test]
    fn directory_corruption_uses_cover_reads_before_discarding(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut executor = executor(6, 12)?;
        let owner = address(0x71);
        let plan = executor.layout.directory_plan(owner);
        let indices = executor.layout.directory_backend_indices(&plan)?;
        executor
            .directory
            .records
            .insert(indices[0], PersistentAddressDirectory::default());
        assert_eq!(
            executor.read_history(owner),
            Err(AtomicStoreError::CorruptLayout)
        );
        assert_eq!(executor.directory.reads.len(), DIRECTORY_PROBES);
        assert_eq!(
            executor.events.reads.len(),
            fixed_read_count() - DIRECTORY_PROBES
        );
        assert_eq!(executor.state, ExecutorState::Discarded);
        Ok(())
    }

    #[test]
    fn noncontiguous_event_ordinals_complete_reads_and_counts_then_discard(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut executor = executor(6, 12)?;
        let owner = address(0x74);
        let first = event(owner, 0x75);
        let skipped = event(owner, 0x76);
        executor.append(owner, first)?;

        let directory_plan = executor.layout.directory_plan(owner);
        let directory_indices = executor.layout.directory_backend_indices(&directory_plan)?;
        let directory_scan = executor.layout.scan_directory(
            &directory_plan,
            reads_from_records(&executor.directory.records, directory_indices),
        )?;
        let DirectoryScan::Found(bound) = directory_scan else {
            return Err("seeded directory was not found".into());
        };
        let ordinal_two_plan = executor.layout.event_plan(&bound, 2)?;
        let ordinal_two_indices = executor.layout.event_backend_indices(&ordinal_two_plan)?;
        let ordinal_two_scan = executor.layout.scan_event(
            &ordinal_two_plan,
            reads_from_records(&executor.events.records, ordinal_two_indices),
        )?;
        let EventScan::Vacant(vacancy) = ordinal_two_scan else {
            return Err("ordinal two had no seed vacancy".into());
        };
        let prepared = executor.layout.prepare_event_insert(
            EventScan::Vacant(vacancy),
            skipped,
            u64::try_from(executor.events.records.len())?,
        )?;
        let (index, value) = executor.layout.backend_event_insert(prepared)?;
        assert!(executor.events.records.insert(index, value).is_none());

        executor.directory.trace.borrow_mut().clear();
        executor.directory.reads.clear();
        executor.events.reads.clear();
        executor.directory.writes.clear();
        executor.events.writes.clear();
        assert_eq!(
            executor.append(owner, event(owner, 0x77)),
            Err(AtomicStoreError::NonContiguousEventHistory)
        );
        let trace = executor.directory.trace.borrow();
        assert_eq!(trace.len(), fixed_read_count() + 2);
        assert!(matches!(
            trace[fixed_read_count()],
            FakeOperation::Count {
                table: TableKind::Directory
            }
        ));
        assert!(matches!(
            trace[fixed_read_count() + 1],
            FakeOperation::Count {
                table: TableKind::Event
            }
        ));
        assert!(executor.directory.writes.is_empty());
        assert!(executor.events.writes.is_empty());
        assert_eq!(executor.state, ExecutorState::Discarded);
        Ok(())
    }

    #[test]
    fn prospective_event_orphan_completes_reads_and_counts_then_discards(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut executor = executor(6, 12)?;
        let owner = address(0x78);
        let directory_plan = executor.layout.directory_plan(owner);
        let directory_indices = executor.layout.directory_backend_indices(&directory_plan)?;
        let directory_scan = executor.layout.scan_directory(
            &directory_plan,
            reads_from_records(&executor.directory.records, directory_indices),
        )?;
        let DirectoryScan::Vacant(directory_vacancy) = directory_scan else {
            return Err("new address had no directory vacancy".into());
        };
        let prospective = executor.layout.prospective_directory(&directory_vacancy)?;
        let event_plan = executor.layout.prospective_event_plan(&prospective, 0)?;
        let event_indices = executor.layout.event_backend_indices(&event_plan)?;
        let event_scan = executor.layout.scan_event(
            &event_plan,
            reads_from_records(&executor.events.records, event_indices),
        )?;
        let EventScan::Vacant(event_vacancy) = event_scan else {
            return Err("prospective event had no seed vacancy".into());
        };
        let orphan = event(owner, 0x79);
        let prepared =
            executor
                .layout
                .prepare_event_insert(EventScan::Vacant(event_vacancy), orphan, 0)?;
        let (index, value) = executor.layout.backend_event_insert(prepared)?;
        assert!(executor.events.records.insert(index, value).is_none());

        assert_eq!(
            executor.append(owner, orphan),
            Err(AtomicStoreError::ProspectiveEventOrphan)
        );
        let trace = executor.directory.trace.borrow();
        assert_eq!(trace.len(), fixed_read_count() + 2);
        assert!(matches!(
            trace[fixed_read_count()],
            FakeOperation::Count {
                table: TableKind::Directory
            }
        ));
        assert!(matches!(
            trace[fixed_read_count() + 1],
            FakeOperation::Count {
                table: TableKind::Event
            }
        ));
        assert_eq!(executor.state, ExecutorState::Discarded);
        Ok(())
    }

    #[test]
    fn partial_new_address_write_discards_and_forbids_retry(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut executor = executor(6, 12)?;
        executor.events.fail_next_insert = true;
        let owner = address(0x81);
        let result = executor.append(owner, event(owner, 0x82));

        assert_eq!(
            result,
            Err(AtomicStoreError::BackendFailure {
                table: TableKind::Event,
            })
        );
        assert_eq!(executor.directory.records.len(), 1);
        assert!(executor.events.records.is_empty());
        assert_eq!(executor.state, ExecutorState::Discarded);
        assert_eq!(
            executor.append(owner, event(owner, 0x82)),
            Err(AtomicStoreError::Discarded)
        );
        Ok(())
    }

    #[test]
    fn uncertain_event_write_discards_and_stops_all_later_backend_operations(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut executor = executor(6, 12)?;
        executor.events.mutate_then_fail_next_insert = true;
        let owner = address(0x89);
        let event = event(owner, 0x8a);

        assert_eq!(
            executor.append(owner, event),
            Err(AtomicStoreError::BackendFailure {
                table: TableKind::Event,
            })
        );
        assert_eq!(executor.directory.records.len(), 1);
        assert_eq!(executor.events.records.len(), 1);
        assert_eq!(executor.state, ExecutorState::Discarded);
        let trace_len = executor.directory.trace.borrow().len();

        assert_eq!(
            executor.append(owner, event),
            Err(AtomicStoreError::Discarded)
        );
        assert_eq!(executor.directory.trace.borrow().len(), trace_len);
        Ok(())
    }

    #[test]
    fn panicking_event_write_after_mutation_discards_and_forbids_retry(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut executor = executor(6, 12)?;
        executor.events.mutate_then_panic_next_insert = true;
        let owner = address(0x8b);
        let event = event(owner, 0x8c);

        assert_eq!(
            executor.append(owner, event),
            Err(AtomicStoreError::BackendPanic {
                table: TableKind::Event,
            })
        );
        assert_eq!(executor.directory.records.len(), 1);
        assert_eq!(executor.events.records.len(), 1);
        assert_eq!(executor.state, ExecutorState::Discarded);
        let trace_len = executor.directory.trace.borrow().len();
        assert_eq!(
            executor.append(owner, event),
            Err(AtomicStoreError::Discarded)
        );
        assert_eq!(executor.directory.trace.borrow().len(), trace_len);
        Ok(())
    }

    #[test]
    fn backend_panic_discards_without_claiming_complete_reads(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut executor = executor(6, 12)?;
        executor.events.panic_next_read = true;
        let owner = address(0x91);

        assert_eq!(
            executor.read_history(owner),
            Err(AtomicStoreError::BackendPanic {
                table: TableKind::Event,
            })
        );
        assert_eq!(executor.directory.reads.len(), DIRECTORY_PROBES);
        assert_eq!(executor.events.reads.len(), 1);
        assert_eq!(executor.state, ExecutorState::Discarded);
        Ok(())
    }

    #[test]
    fn constructor_rejects_either_capacity_mismatch() -> Result<(), LayoutConfigError> {
        let (short_directory, events) = fake_tables(4, 16);
        assert!(matches!(
            ExclusiveTwoTableExecutor::new(layout(6, 12, 11)?, short_directory, events,),
            Err(AtomicStoreError::BackendCapacityMismatch {
                table: TableKind::Directory,
            })
        ));
        let (directory, short_events) = fake_tables(8, 8);
        assert!(matches!(
            ExclusiveTwoTableExecutor::new(layout(6, 12, 11)?, directory, short_events,),
            Err(AtomicStoreError::BackendCapacityMismatch {
                table: TableKind::Event,
            })
        ));
        Ok(())
    }

    #[test]
    fn foreign_profile_plan_is_rejected_before_backend_reads(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut executor = executor(6, 12)?;
        let foreign = layout(6, 12, 12)?;
        let owner = address(0xa1);
        let plan = AtomicPlan {
            profile_binding: foreign.profile_binding,
            address: owner,
            directory: foreign.directory_plan(owner),
            append: None,
        };

        assert_eq!(
            executor.execute(plan),
            Err(AtomicStoreError::PlanProfileMismatch)
        );
        assert!(executor.directory.reads.is_empty());
        assert!(executor.events.reads.is_empty());
        assert_eq!(executor.state, ExecutorState::Ready);
        Ok(())
    }

    #[test]
    fn plans_results_and_errors_keep_identifiers_redacted() -> Result<(), Box<dyn std::error::Error>>
    {
        let executor = executor(6, 12)?;
        let owner = address(0xab);
        let sensitive_event = event(owner, 0xcd);
        let plan = executor.plan(owner, Some(sensitive_event));
        assert_eq!(format!("{plan:?}"), "AtomicPlan { ..REDACTED.. }");

        let history = FixedEventHistory {
            slots: vec![Some(sensitive_event)],
        };
        assert_eq!(format!("{history:?}"), "FixedEventHistory { ..REDACTED.. }");
        let result = AppendResult {
            disposition: AppendDisposition::Inserted,
            history,
        };
        assert_eq!(format!("{result:?}"), "AppendResult { ..REDACTED.. }");

        let errors = [
            AtomicStoreError::BackendCapacityMismatch {
                table: TableKind::Directory,
            },
            AtomicStoreError::PlanProfileMismatch,
            AtomicStoreError::InvalidPlan,
            AtomicStoreError::ResultAllocationFailed,
            AtomicStoreError::AdmissionLimitReached {
                table: TableKind::Event,
            },
            AtomicStoreError::ProbeSetFull {
                table: TableKind::Directory,
            },
            AtomicStoreError::AddressEventLimitReached,
            AtomicStoreError::ProspectiveEventOrphan,
            AtomicStoreError::NonContiguousEventHistory,
            AtomicStoreError::OccupancyInvariant,
            AtomicStoreError::Conflict,
            AtomicStoreError::CorruptLayout,
            AtomicStoreError::BackendFailure {
                table: TableKind::Event,
            },
            AtomicStoreError::BackendPanic {
                table: TableKind::Directory,
            },
            AtomicStoreError::UnexpectedPanic,
            AtomicStoreError::Discarded,
        ];
        for error in errors {
            let rendered = format!("{error:?} {error}");
            for sensitive in ["171", "205", "0xab", "0xcd"] {
                assert!(!rendered.contains(sensitive));
            }
        }
        Ok(())
    }
}
