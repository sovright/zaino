//! Bounded single-owner scheduling for the exclusive two-table command core.
//!
//! The worker consumes the complete executor, so no raw table handle, slot,
//! read, or insert operation crosses the command boundary. It remains a
//! volatile, module-private research model. Its feature-gated child can build
//! the exact typed `rostl` executor on Linux x86_64 for the crate-internal
//! offline projection owner, but no query engine or service owns it.
//! Append reply tickets fail the worker closed when dropped unconsumed, while
//! merely retaining a ticket never stalls later work or shutdown. Deliberately
//! leaking a ticket with `mem::forget` is outside this trusted module-private
//! model; no consumer exists yet.

use std::{
    fmt, io,
    num::NonZeroUsize,
    panic::{catch_unwind, AssertUnwindSafe},
    sync::{
        mpsc::{self, Receiver, SyncSender, TryRecvError, TrySendError},
        Arc, Mutex, MutexGuard,
    },
    thread::{self, JoinHandle},
};

use super::*;
#[cfg(feature = "corpus-zaino")]
use crate::projection::ProjectionEventSink;

#[cfg(feature = "rostl-experimental")]
mod rostl;

const REPLY_CHANNEL_CAPACITY: usize = 1;
// Allocation guard for the offline experiment, not an approved service profile.
const MAX_WORKER_QUEUE_CAPACITY: usize = 4_096;
const WORKER_THREAD_NAME: &str = "zaino-oram-atomic";

#[derive(Clone, Copy)]
pub(crate) struct AtomicQueueCapacity(NonZeroUsize);

impl AtomicQueueCapacity {
    pub(crate) fn try_new(value: usize) -> Result<Self, AtomicQueueCapacityError> {
        match NonZeroUsize::new(value) {
            Some(value) if value.get() <= MAX_WORKER_QUEUE_CAPACITY => Ok(Self(value)),
            Some(_) | None => Err(AtomicQueueCapacityError::Invalid),
        }
    }

    const fn get(self) -> usize {
        self.0.get()
    }
}

/// Owns the worker thread and the only command handle into its executor.
pub(crate) struct AtomicWorker {
    handle: AtomicWorkerHandle,
    join: Option<JoinHandle<WorkerExit>>,
}

impl AtomicWorker {
    fn spawn<D, E, const DIRECTORY_PROBES: usize, const EVENT_PROBES: usize>(
        executor: ExclusiveTwoTableExecutor<D, E, DIRECTORY_PROBES, EVENT_PROBES>,
        queue_capacity: AtomicQueueCapacity,
    ) -> Result<Self, AtomicWorkerError>
    where
        D: UniqueTable<PersistentAddressDirectory> + Send + 'static,
        E: UniqueTable<PersistentAddressEventPage> + Send + 'static,
    {
        let queue_capacity = queue_capacity.get();
        let (sender, receiver) = mpsc::sync_channel(queue_capacity);
        let shared = Arc::new(WorkerShared {
            state: Mutex::new(WorkerState::new(queue_capacity)),
        });
        let worker_shared = Arc::clone(&shared);
        let join = thread::Builder::new()
            .name(WORKER_THREAD_NAME.to_owned())
            .spawn(move || worker_entry(executor, receiver, &worker_shared))
            .map_err(AtomicWorkerError::ThreadSpawn)?;
        {
            let mut state = lock_state(&shared);
            state.lifecycle = WorkerLifecycle::Ready;
        }
        Ok(Self {
            handle: AtomicWorkerHandle { sender, shared },
            join: Some(join),
        })
    }

    fn handle(&self) -> AtomicWorkerHandle {
        self.handle.clone()
    }

    fn snapshot(&self) -> AtomicWorkerSnapshot {
        self.handle.snapshot()
    }

    fn shutdown(mut self) -> Result<AtomicWorkerSnapshot, AtomicWorkerError> {
        let signal_result = self.signal_shutdown();
        let join_result = self.join_worker();
        match join_result {
            Err(error) => Err(error),
            Ok(()) => signal_result.map(|()| self.snapshot()),
        }
    }

    fn signal_shutdown(&self) -> Result<(), AtomicWorkerError> {
        let (reply, response) = mpsc::sync_channel(REPLY_CHANNEL_CAPACITY);
        let mut state = lock_state(&self.handle.shared);
        match state.lifecycle {
            WorkerLifecycle::Starting | WorkerLifecycle::Ready => {
                state.lifecycle = WorkerLifecycle::Draining;
            }
            WorkerLifecycle::Draining => return Err(AtomicWorkerError::NotRunning),
            WorkerLifecycle::Stopped => return Ok(()),
        }
        drop(state);
        if self
            .handle
            .sender
            .send(WorkerCommand::Shutdown { reply })
            .is_err()
        {
            let mut state = lock_state(&self.handle.shared);
            state.latch_fault(WorkerFault::Terminal);
            state.mark_stopped();
            return Err(AtomicWorkerError::WorkerDisconnected);
        }
        response.recv().map_err(|_| {
            let mut state = lock_state(&self.handle.shared);
            state.latch_fault(WorkerFault::Terminal);
            state.mark_stopped();
            AtomicWorkerError::WorkerDisconnected
        })
    }

    fn join_worker(&mut self) -> Result<(), AtomicWorkerError> {
        let Some(join) = self.join.take() else {
            return Ok(());
        };
        match join.join() {
            Ok(WorkerExit::Clean) => Ok(()),
            Ok(WorkerExit::Panicked) | Err(_) => {
                let mut state = lock_state(&self.handle.shared);
                state.latch_fault(WorkerFault::Terminal);
                state.mark_stopped();
                Err(AtomicWorkerError::WorkerPanicked)
            }
        }
    }
}

#[cfg(feature = "corpus-zaino")]
pub(crate) fn spawn_typed_rostl_worker<const DIRECTORY_PROBES: usize, const EVENT_PROBES: usize>(
    layout: FixedProbeLayout<DIRECTORY_PROBES, EVENT_PROBES>,
    queue_capacity: AtomicQueueCapacity,
) -> Result<AtomicWorker, AtomicWorkerBuildError> {
    #[cfg(all(
        feature = "rostl-experimental",
        target_os = "linux",
        target_arch = "x86_64"
    ))]
    {
        return rostl::spawn_rostl_worker(layout, queue_capacity);
    }

    #[cfg(not(all(
        feature = "rostl-experimental",
        target_os = "linux",
        target_arch = "x86_64"
    )))]
    {
        let _ = (layout, queue_capacity);
        Err(AtomicWorkerBuildError::TypedBackendUnavailable)
    }
}

#[cfg(feature = "corpus-zaino")]
pub(crate) fn shutdown_atomic_worker(worker: AtomicWorker) -> Result<(), ()> {
    worker.shutdown().map(|_| ()).map_err(|_| ())
}

#[cfg(all(test, feature = "corpus-zaino"))]
pub(super) fn spawn_atomic_worker_for_tests<
    D,
    E,
    const DIRECTORY_PROBES: usize,
    const EVENT_PROBES: usize,
>(
    executor: ExclusiveTwoTableExecutor<D, E, DIRECTORY_PROBES, EVENT_PROBES>,
    queue_capacity: AtomicQueueCapacity,
) -> Result<AtomicWorker, AtomicWorkerBuildError>
where
    D: UniqueTable<PersistentAddressDirectory> + Send + 'static,
    E: UniqueTable<PersistentAddressEventPage> + Send + 'static,
{
    AtomicWorker::spawn(executor, queue_capacity)
        .map_err(|_| AtomicWorkerBuildError::ConstructionFailed)
}

#[cfg(feature = "corpus-zaino")]
impl ProjectionEventSink for AtomicWorker {
    type Error = AtomicProjectionSinkError;

    fn append_and_wait(&mut self, event: UtxoEvent) -> Result<(), Self::Error> {
        let address = StandardAddress::from_event(&event).map_err(|_| AtomicProjectionSinkError)?;
        self.handle
            .try_append(address, event)
            .map_err(|_| AtomicProjectionSinkError)?
            .wait()
            .map(|_| ())
            .map_err(|_| AtomicProjectionSinkError)
    }
}

impl Drop for AtomicWorker {
    fn drop(&mut self) {
        if self.join.is_none() {
            return;
        }
        let _ = self.signal_shutdown();
        let _ = self.join_worker();
    }
}

impl fmt::Debug for AtomicWorker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AtomicWorker { ..REDACTED.. }")
    }
}

/// Cloneable bounded-admission handle with no raw backend operations.
#[derive(Clone)]
struct AtomicWorkerHandle {
    sender: SyncSender<WorkerCommand>,
    shared: Arc<WorkerShared>,
}

impl AtomicWorkerHandle {
    fn try_read_history(
        &self,
        address: StandardAddress,
    ) -> Result<AtomicWorkerReply<FixedEventHistory>, AtomicWorkerError> {
        let (reply, response) = mpsc::sync_channel(REPLY_CHANNEL_CAPACITY);
        self.admit(WorkerCommand::ReadHistory { address, reply })?;
        Ok(AtomicWorkerReply {
            response,
            shared: Arc::clone(&self.shared),
            consumed: false,
            terminal_on_abandonment: false,
        })
    }

    fn try_append(
        &self,
        address: StandardAddress,
        event: UtxoEvent,
    ) -> Result<AtomicWorkerReply<FixedEventHistory>, AtomicWorkerError> {
        let (reply, response) = mpsc::sync_channel(REPLY_CHANNEL_CAPACITY);
        self.admit(WorkerCommand::Append {
            address,
            event,
            reply,
        })?;
        Ok(AtomicWorkerReply {
            response,
            shared: Arc::clone(&self.shared),
            consumed: false,
            terminal_on_abandonment: true,
        })
    }

    fn snapshot(&self) -> AtomicWorkerSnapshot {
        AtomicWorkerSnapshot::from_state(&lock_state(&self.shared))
    }

    fn admit(&self, command: WorkerCommand) -> Result<(), AtomicWorkerError> {
        let mut state = lock_state(&self.shared);
        if state.fault.is_some() {
            state.not_running_rejected = state.not_running_rejected.saturating_add(1);
            return Err(AtomicWorkerError::FailedClosed);
        }
        match state.lifecycle {
            WorkerLifecycle::Ready => {}
            WorkerLifecycle::Starting | WorkerLifecycle::Draining | WorkerLifecycle::Stopped => {
                state.not_running_rejected = state.not_running_rejected.saturating_add(1);
                return Err(AtomicWorkerError::NotRunning);
            }
        }
        if state.queued >= state.queue_capacity {
            state.full_rejected = state.full_rejected.saturating_add(1);
            return Err(AtomicWorkerError::QueueFull);
        }
        match self.sender.try_send(command) {
            Ok(()) => {
                state.queued += 1;
                state.queue_high_water = state.queue_high_water.max(state.queued);
                state.accepted = state.accepted.saturating_add(1);
                Ok(())
            }
            Err(TrySendError::Full(_)) => {
                state.full_rejected = state.full_rejected.saturating_add(1);
                Err(AtomicWorkerError::QueueFull)
            }
            Err(TrySendError::Disconnected(_)) => {
                state.not_running_rejected = state.not_running_rejected.saturating_add(1);
                state.latch_fault(WorkerFault::Terminal);
                state.mark_stopped();
                Err(AtomicWorkerError::WorkerDisconnected)
            }
        }
    }

    #[cfg(test)]
    fn try_panic_worker_loop(
        &self,
        entered: SyncSender<()>,
        release: Receiver<()>,
    ) -> Result<AtomicWorkerReply<()>, AtomicWorkerError> {
        let (reply, response) = mpsc::sync_channel(REPLY_CHANNEL_CAPACITY);
        self.admit(WorkerCommand::PanicWorkerLoop {
            entered,
            release,
            reply,
        })?;
        Ok(AtomicWorkerReply {
            response,
            shared: Arc::clone(&self.shared),
            consumed: false,
            terminal_on_abandonment: false,
        })
    }
}

impl fmt::Debug for AtomicWorkerHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AtomicWorkerHandle { ..REDACTED.. }")
    }
}

/// One accepted command's fixed-capacity reply path.
#[must_use = "accepted worker replies must be consumed or explicitly dropped"]
struct AtomicWorkerReply<T> {
    response: Receiver<Result<T, AtomicWorkerError>>,
    shared: Arc<WorkerShared>,
    consumed: bool,
    terminal_on_abandonment: bool,
}

impl<T> AtomicWorkerReply<T> {
    fn wait(mut self) -> Result<T, AtomicWorkerError> {
        let result = match self.response.recv() {
            Ok(result) => result,
            Err(_) => return Err(AtomicWorkerError::AcceptedOutcomeIndeterminate),
        };
        self.consumed = true;
        result
    }
}

impl<T> Drop for AtomicWorkerReply<T> {
    fn drop(&mut self) {
        if self.consumed {
            return;
        }
        let mut state = lock_state(&self.shared);
        state.reply_delivery_failed = state.reply_delivery_failed.saturating_add(1);
        if self.terminal_on_abandonment {
            state.latch_fault(WorkerFault::Terminal);
        }
    }
}

impl<T> fmt::Debug for AtomicWorkerReply<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AtomicWorkerReply { ..REDACTED.. }")
    }
}

/// Fixed-schema aggregate worker telemetry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AtomicWorkerSnapshot {
    queue_capacity: usize,
    queued: usize,
    in_flight: usize,
    queue_high_water: usize,
    accepted: u64,
    completed: u64,
    failed: u64,
    full_rejected: u64,
    not_running_rejected: u64,
    reply_delivery_failed: u64,
    lifecycle: WorkerLifecycle,
    fault: Option<WorkerFault>,
}

impl AtomicWorkerSnapshot {
    const fn from_state(state: &WorkerState) -> Self {
        Self {
            queue_capacity: state.queue_capacity,
            queued: state.queued,
            in_flight: state.in_flight,
            queue_high_water: state.queue_high_water,
            accepted: state.accepted,
            completed: state.completed,
            failed: state.failed,
            full_rejected: state.full_rejected,
            not_running_rejected: state.not_running_rejected,
            reply_delivery_failed: state.reply_delivery_failed,
            lifecycle: state.lifecycle,
            fault: state.fault,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum WorkerLifecycle {
    Starting,
    Ready,
    Draining,
    Stopped,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WorkerFault {
    Terminal,
}

struct WorkerShared {
    state: Mutex<WorkerState>,
}

struct WorkerState {
    queue_capacity: usize,
    queued: usize,
    in_flight: usize,
    queue_high_water: usize,
    accepted: u64,
    completed: u64,
    failed: u64,
    full_rejected: u64,
    not_running_rejected: u64,
    reply_delivery_failed: u64,
    lifecycle: WorkerLifecycle,
    fault: Option<WorkerFault>,
}

impl WorkerState {
    const fn new(queue_capacity: usize) -> Self {
        Self {
            queue_capacity,
            queued: 0,
            in_flight: 0,
            queue_high_water: 0,
            accepted: 0,
            completed: 0,
            failed: 0,
            full_rejected: 0,
            not_running_rejected: 0,
            reply_delivery_failed: 0,
            lifecycle: WorkerLifecycle::Starting,
            fault: None,
        }
    }

    fn latch_fault(&mut self, fault: WorkerFault) {
        if self.fault.is_none() {
            self.fault = Some(fault);
        }
    }

    fn mark_stopped(&mut self) {
        self.lifecycle = WorkerLifecycle::Stopped;
    }
}

fn lock_state(shared: &WorkerShared) -> MutexGuard<'_, WorkerState> {
    match shared.state.lock() {
        Ok(state) => state,
        Err(poisoned) => {
            let mut state = poisoned.into_inner();
            state.latch_fault(WorkerFault::Terminal);
            state
        }
    }
}

enum WorkerCommand {
    ReadHistory {
        address: StandardAddress,
        reply: SyncSender<Result<FixedEventHistory, AtomicWorkerError>>,
    },
    Append {
        address: StandardAddress,
        event: UtxoEvent,
        reply: SyncSender<Result<FixedEventHistory, AtomicWorkerError>>,
    },
    Shutdown {
        reply: SyncSender<()>,
    },
    #[cfg(test)]
    PanicWorkerLoop {
        entered: SyncSender<()>,
        release: Receiver<()>,
        reply: SyncSender<Result<(), AtomicWorkerError>>,
    },
}

fn worker_entry<D, E, const DIRECTORY_PROBES: usize, const EVENT_PROBES: usize>(
    mut executor: ExclusiveTwoTableExecutor<D, E, DIRECTORY_PROBES, EVENT_PROBES>,
    receiver: Receiver<WorkerCommand>,
    shared: &WorkerShared,
) -> WorkerExit
where
    D: UniqueTable<PersistentAddressDirectory> + Send + 'static,
    E: UniqueTable<PersistentAddressEventPage> + Send + 'static,
{
    match catch_unwind(AssertUnwindSafe(|| {
        worker_loop(&mut executor, &receiver, shared)
    })) {
        Ok(exit) => exit,
        Err(_) => {
            {
                let mut state = lock_state(shared);
                state.latch_fault(WorkerFault::Terminal);
                if state.in_flight != 0 {
                    state.in_flight = 0;
                    state.failed = state.failed.saturating_add(1);
                }
            }
            drain_failed_commands(&receiver, shared);
            lock_state(shared).mark_stopped();
            let _ = catch_unwind(AssertUnwindSafe(|| drop(executor)));
            WorkerExit::Panicked
        }
    }
}

fn worker_loop<D, E, const DIRECTORY_PROBES: usize, const EVENT_PROBES: usize>(
    executor: &mut ExclusiveTwoTableExecutor<D, E, DIRECTORY_PROBES, EVENT_PROBES>,
    receiver: &Receiver<WorkerCommand>,
    shared: &WorkerShared,
) -> WorkerExit
where
    D: UniqueTable<PersistentAddressDirectory> + Send + 'static,
    E: UniqueTable<PersistentAddressEventPage> + Send + 'static,
{
    loop {
        let command = match receiver.recv() {
            Ok(command) => command,
            Err(_) => {
                lock_state(shared).mark_stopped();
                return WorkerExit::Clean;
            }
        };
        match command {
            WorkerCommand::ReadHistory { address, reply } => {
                mark_dequeued(shared);
                let result =
                    execute_command(executor, shared, |executor| executor.read_history(address));
                send_reply(reply, result);
            }
            WorkerCommand::Append {
                address,
                event,
                reply,
            } => {
                mark_dequeued(shared);
                let result = execute_command(executor, shared, |executor| {
                    executor.append(address, event).map(|result| result.history)
                });
                send_reply(reply, result);
            }
            WorkerCommand::Shutdown { reply } => {
                lock_state(shared).mark_stopped();
                if reply.send(()).is_err() {
                    increment_reply_delivery_failed(shared);
                }
                return WorkerExit::Clean;
            }
            #[cfg(test)]
            WorkerCommand::PanicWorkerLoop {
                entered,
                release,
                reply: _reply,
            } => {
                mark_dequeued(shared);
                let _ = entered.send(());
                let _ = release.recv();
                panic!("injected atomic worker-loop panic");
            }
        }
    }
}

fn execute_command<D, E, T, const DIRECTORY_PROBES: usize, const EVENT_PROBES: usize>(
    executor: &mut ExclusiveTwoTableExecutor<D, E, DIRECTORY_PROBES, EVENT_PROBES>,
    shared: &WorkerShared,
    operation: impl FnOnce(
        &mut ExclusiveTwoTableExecutor<D, E, DIRECTORY_PROBES, EVENT_PROBES>,
    ) -> Result<T, AtomicStoreError>,
) -> Result<T, AtomicWorkerError>
where
    D: UniqueTable<PersistentAddressDirectory>,
    E: UniqueTable<PersistentAddressEventPage>,
{
    {
        let mut state = lock_state(shared);
        if state.fault.is_some()
            || !matches!(
                state.lifecycle,
                WorkerLifecycle::Ready | WorkerLifecycle::Draining
            )
        {
            state.failed = state.failed.saturating_add(1);
            finish_in_flight(&mut state);
            return Err(AtomicWorkerError::FailedClosed);
        }
    }

    let outcome = operation(executor);
    let executor_discarded = matches!(executor.state, ExecutorState::Discarded);
    let mut state = lock_state(shared);
    if executor_discarded {
        state.latch_fault(WorkerFault::Terminal);
    }
    let result = if state.fault.is_some() && !executor_discarded {
        state.failed = state.failed.saturating_add(1);
        Err(AtomicWorkerError::FailedClosed)
    } else {
        match outcome {
            Ok(_value) if executor_discarded => {
                state.failed = state.failed.saturating_add(1);
                Err(AtomicWorkerError::FailedClosed)
            }
            Ok(value) => {
                state.completed = state.completed.saturating_add(1);
                Ok(value)
            }
            Err(error) => {
                state.failed = state.failed.saturating_add(1);
                if executor_discarded {
                    Err(AtomicWorkerError::FailedClosed)
                } else {
                    let _ = error;
                    Err(AtomicWorkerError::CommandRejected)
                }
            }
        }
    };
    finish_in_flight(&mut state);
    result
}

fn mark_dequeued(shared: &WorkerShared) {
    let mut state = lock_state(shared);
    match state.queued.checked_sub(1) {
        Some(queued) => state.queued = queued,
        None => state.latch_fault(WorkerFault::Terminal),
    }
    if state.in_flight == 0 {
        state.in_flight = 1;
    } else {
        state.latch_fault(WorkerFault::Terminal);
    }
}

fn finish_in_flight(state: &mut WorkerState) {
    if state.in_flight == 1 {
        state.in_flight = 0;
    } else {
        state.latch_fault(WorkerFault::Terminal);
    }
}

fn send_reply<T>(
    reply: SyncSender<Result<T, AtomicWorkerError>>,
    result: Result<T, AtomicWorkerError>,
) {
    let _ = reply.send(result);
}

fn increment_reply_delivery_failed(shared: &WorkerShared) {
    let mut state = lock_state(shared);
    state.reply_delivery_failed = state.reply_delivery_failed.saturating_add(1);
}

fn drain_failed_commands(receiver: &Receiver<WorkerCommand>, shared: &WorkerShared) {
    loop {
        match receiver.try_recv() {
            Ok(WorkerCommand::ReadHistory { reply, .. }) => {
                resolve_queued_failure(shared);
                send_reply(reply, Err(AtomicWorkerError::FailedClosed));
            }
            Ok(WorkerCommand::Append { reply, .. }) => {
                resolve_queued_failure(shared);
                send_reply(reply, Err(AtomicWorkerError::FailedClosed));
            }
            Ok(WorkerCommand::Shutdown { reply }) => {
                if reply.send(()).is_err() {
                    increment_reply_delivery_failed(shared);
                }
                return;
            }
            #[cfg(test)]
            Ok(WorkerCommand::PanicWorkerLoop { reply, .. }) => {
                resolve_queued_failure(shared);
                send_reply(reply, Err(AtomicWorkerError::FailedClosed));
            }
            Err(TryRecvError::Empty | TryRecvError::Disconnected) => return,
        }
    }
}

fn resolve_queued_failure(shared: &WorkerShared) {
    let mut state = lock_state(shared);
    match state.queued.checked_sub(1) {
        Some(queued) => state.queued = queued,
        None => state.latch_fault(WorkerFault::Terminal),
    }
    state.failed = state.failed.saturating_add(1);
}

#[derive(Clone, Copy)]
enum WorkerExit {
    Clean,
    Panicked,
}

/// Identifier-free queue-bound validation failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AtomicQueueCapacityError {
    Invalid,
}

impl fmt::Display for AtomicQueueCapacityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid => write!(
                f,
                "atomic worker queue capacity must be in 1..={MAX_WORKER_QUEUE_CAPACITY}"
            ),
        }
    }
}

impl std::error::Error for AtomicQueueCapacityError {}

/// Coarse typed-worker construction failure for the offline owner.
#[cfg(feature = "corpus-zaino")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AtomicWorkerBuildError {
    TypedBackendUnavailable,
    ConstructionFailed,
}

#[cfg(feature = "corpus-zaino")]
impl fmt::Display for AtomicWorkerBuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TypedBackendUnavailable => {
                f.write_str("typed atomic worker backend is unavailable")
            }
            Self::ConstructionFailed => f.write_str("typed atomic worker construction failed"),
        }
    }
}

#[cfg(feature = "corpus-zaino")]
impl std::error::Error for AtomicWorkerBuildError {}

/// Identifier-free failure from worker startup, admission, execution, or join.
#[derive(Debug)]
enum AtomicWorkerError {
    ThreadSpawn(io::Error),
    QueueFull,
    NotRunning,
    WorkerDisconnected,
    // The command was accepted and may already have mutated volatile state.
    // Automatic retry is forbidden until the candidate is rebuilt/reconciled.
    AcceptedOutcomeIndeterminate,
    CommandRejected,
    FailedClosed,
    WorkerPanicked,
}

/// Identifier-free projection-to-worker boundary failure.
#[cfg(feature = "corpus-zaino")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AtomicProjectionSinkError;

#[cfg(feature = "corpus-zaino")]
impl fmt::Display for AtomicProjectionSinkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("projection event mutation failed")
    }
}

#[cfg(feature = "corpus-zaino")]
impl std::error::Error for AtomicProjectionSinkError {}

impl fmt::Display for AtomicWorkerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ThreadSpawn(_) => f.write_str("atomic worker could not start"),
            Self::QueueFull => f.write_str("atomic worker queue is full"),
            Self::NotRunning => f.write_str("atomic worker is not accepting work"),
            Self::WorkerDisconnected => f.write_str("atomic worker command channel is closed"),
            Self::AcceptedOutcomeIndeterminate => {
                f.write_str("accepted atomic command outcome is indeterminate")
            }
            Self::CommandRejected => f.write_str("atomic command was rejected"),
            Self::FailedClosed => f.write_str("atomic worker is failed closed"),
            Self::WorkerPanicked => f.write_str("atomic worker thread panicked"),
        }
    }
}

impl std::error::Error for AtomicWorkerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ThreadSpawn(error) => Some(error),
            Self::QueueFull
            | Self::NotRunning
            | Self::WorkerDisconnected
            | Self::AcceptedOutcomeIndeterminate
            | Self::CommandRejected
            | Self::FailedClosed
            | Self::WorkerPanicked => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap,
        sync::{Condvar, MutexGuard},
        thread::ThreadId,
        time::{Duration, Instant},
    };

    use super::*;
    use crate::records::{UtxoScriptClass, TXID_BYTES};

    const DIRECTORY_PROBES: usize = 4;
    const EVENT_PROBES: usize = 4;
    const MAX_EVENTS: u64 = 3;

    type TestExecutor = ExclusiveTwoTableExecutor<
        TestTable<PersistentAddressDirectory>,
        TestTable<PersistentAddressEventPage>,
        DIRECTORY_PROBES,
        EVENT_PROBES,
    >;
    type ObservationLog = Arc<Mutex<Vec<ObservedCall>>>;
    type TestResult<T> = Result<T, Box<dyn std::error::Error>>;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum OperationKind {
        Read,
        Count,
        Write,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct ObservedCall {
        owner: ThreadId,
        table: TableKind,
        operation: OperationKind,
    }

    #[derive(Default)]
    struct GateState {
        entered: bool,
        released: bool,
    }

    #[derive(Default)]
    struct Gate {
        state: Mutex<GateState>,
        changed: Condvar,
    }

    impl Gate {
        fn enter_and_wait(&self) {
            let mut state = lock_test(&self.state);
            state.entered = true;
            self.changed.notify_all();
            while !state.released {
                state = match self.changed.wait(state) {
                    Ok(state) => state,
                    Err(poisoned) => poisoned.into_inner(),
                };
            }
        }

        fn wait_until_entered(&self) {
            let deadline = Instant::now() + Duration::from_secs(5);
            let mut state = lock_test(&self.state);
            while !state.entered {
                let now = Instant::now();
                assert!(now < deadline, "test backend did not enter its gate");
                let timeout = deadline.saturating_duration_since(now);
                state = match self.changed.wait_timeout(state, timeout) {
                    Ok((state, _)) => state,
                    Err(poisoned) => poisoned.into_inner().0,
                };
            }
        }

        fn release(&self) {
            let mut state = lock_test(&self.state);
            state.released = true;
            self.changed.notify_all();
        }
    }

    #[derive(Clone)]
    struct ReadControl {
        call: usize,
        gate: Arc<Gate>,
        fail: bool,
    }

    #[derive(Clone, Copy)]
    enum WriteOutcome {
        MutateThenFail,
        MutateThenPanic,
    }

    #[derive(Clone, Copy)]
    struct WriteControl {
        call: usize,
        outcome: WriteOutcome,
    }

    struct TestTable<T> {
        table: TableKind,
        capacity: usize,
        records: BTreeMap<usize, T>,
        observation: Arc<Mutex<Vec<ObservedCall>>>,
        read_control: Option<ReadControl>,
        read_calls: usize,
        write_control: Option<WriteControl>,
        write_calls: usize,
        panic_on_drop: bool,
    }

    impl<T> TestTable<T> {
        fn new(
            table: TableKind,
            capacity: usize,
            observation: Arc<Mutex<Vec<ObservedCall>>>,
            read_control: Option<ReadControl>,
            write_control: Option<WriteControl>,
        ) -> Self {
            Self {
                table,
                capacity,
                records: BTreeMap::new(),
                observation,
                read_control,
                read_calls: 0,
                write_control,
                write_calls: 0,
                panic_on_drop: false,
            }
        }

        fn record(&self, operation: OperationKind) {
            lock_test(&self.observation).push(ObservedCall {
                owner: thread::current().id(),
                table: self.table,
                operation,
            });
        }
    }

    impl<T> Drop for TestTable<T> {
        fn drop(&mut self) {
            if self.panic_on_drop {
                panic!("injected table destructor panic");
            }
        }
    }

    impl<T: Copy> UniqueTable<T> for TestTable<T> {
        fn capacity(&self) -> usize {
            self.capacity
        }

        fn read(&mut self, index: usize) -> Result<Option<T>, BackendFailure> {
            self.record(OperationKind::Read);
            self.read_calls += 1;
            if let Some(control) = self
                .read_control
                .as_ref()
                .filter(|control| control.call == self.read_calls)
                .cloned()
            {
                control.gate.enter_and_wait();
                if control.fail {
                    return Err(BackendFailure);
                }
            }
            Ok(self.records.get(&index).copied())
        }

        fn occupied_records(&mut self) -> Result<u64, BackendFailure> {
            self.record(OperationKind::Count);
            u64::try_from(self.records.len()).map_err(|_| BackendFailure)
        }

        fn insert_unique(&mut self, index: usize, value: T) -> Result<(), BackendFailure> {
            self.record(OperationKind::Write);
            self.write_calls += 1;
            if self.records.contains_key(&index) {
                return Err(BackendFailure);
            }
            if let Some(control) = self
                .write_control
                .filter(|control| control.call == self.write_calls)
            {
                self.records.insert(index, value);
                match control.outcome {
                    WriteOutcome::MutateThenFail => return Err(BackendFailure),
                    WriteOutcome::MutateThenPanic => {
                        panic!("injected mutate-then-panic table write")
                    }
                }
            }
            self.records.insert(index, value);
            Ok(())
        }
    }

    fn lock_test<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
        match mutex.lock() {
            Ok(value) => value,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    fn queue_capacity(value: usize) -> AtomicQueueCapacity {
        AtomicQueueCapacity::try_new(value).expect("test queue capacity must be valid")
    }

    fn executor(
        directory_control: Option<ReadControl>,
        event_write_control: Option<WriteControl>,
    ) -> TestResult<(TestExecutor, ObservationLog)> {
        let observation = Arc::new(Mutex::new(Vec::new()));
        let directory = TestTable::new(
            TableKind::Directory,
            8,
            Arc::clone(&observation),
            directory_control,
            None,
        );
        let events = TestTable::new(
            TableKind::Event,
            16,
            Arc::clone(&observation),
            None,
            event_write_control,
        );
        let layout = FixedProbeLayout::new(
            LayoutIdentity::new(LayoutNetwork::Mainnet, 1, 7, 11, [0x5a; 32])?,
            DirectoryTableConfiguration::new(8, 6)?,
            EventTableConfiguration::new(16, 12)?,
            MAX_EVENTS,
        )?;
        Ok((
            ExclusiveTwoTableExecutor::new(layout, directory, events)?,
            observation,
        ))
    }

    fn worker(
        queue_capacity: usize,
        directory_control: Option<ReadControl>,
    ) -> TestResult<(AtomicWorker, ObservationLog)> {
        let (executor, observation) = executor(directory_control, None)?;
        Ok((
            AtomicWorker::spawn(executor, self::queue_capacity(queue_capacity))?,
            observation,
        ))
    }

    fn worker_with_event_write(
        event_write_control: WriteControl,
    ) -> TestResult<(AtomicWorker, ObservationLog)> {
        let (executor, observation) = executor(None, Some(event_write_control))?;
        Ok((
            AtomicWorker::spawn(executor, queue_capacity(1))?,
            observation,
        ))
    }

    fn worker_with_event_drop_panic() -> TestResult<(AtomicWorker, ObservationLog)> {
        let (mut executor, observation) = executor(None, None)?;
        executor.events.panic_on_drop = true;
        Ok((
            AtomicWorker::spawn(executor, queue_capacity(2))?,
            observation,
        ))
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
            UtxoScriptClass::PayToPublicKeyHash,
            address.hash,
        )
    }

    #[test]
    #[cfg(feature = "corpus-zaino")]
    fn projection_sink_waits_for_the_worker_mutation() -> TestResult<()> {
        let (mut worker, observation) = worker(1, None)?;
        let owner = StandardAddress::new(StandardScriptKind::PayToScriptHash, [0x2a; 20]);
        let projected = UtxoEvent::created(
            [0x4a; TXID_BYTES],
            14,
            15,
            16,
            UtxoScriptClass::PayToScriptHash,
            owner.hash,
        );

        ProjectionEventSink::append_and_wait(&mut worker, projected)?;

        let snapshot = worker.snapshot();
        assert_eq!(snapshot.accepted, 1);
        assert_eq!(snapshot.completed, 1);
        assert_eq!(snapshot.queued, 0);
        assert_eq!(snapshot.in_flight, 0);
        assert_eq!(
            lock_test(&observation)
                .iter()
                .filter(|call| call.operation == OperationKind::Write)
                .count(),
            2
        );
        let history = worker.handle().try_read_history(owner)?.wait()?;
        assert_eq!(history.events()[0], Some(projected));
        worker.shutdown()?;
        Ok(())
    }

    #[test]
    #[cfg(feature = "corpus-zaino")]
    fn projection_sink_consumes_terminal_mutation_failure() -> TestResult<()> {
        let control = WriteControl {
            call: 1,
            outcome: WriteOutcome::MutateThenFail,
        };
        let (mut worker, observation) = worker_with_event_write(control)?;
        let owner = address(0x2b);

        assert_eq!(
            ProjectionEventSink::append_and_wait(&mut worker, event(owner, 0x4b)),
            Err(AtomicProjectionSinkError)
        );
        let snapshot = worker.snapshot();
        assert_eq!(snapshot.fault, Some(WorkerFault::Terminal));
        assert_eq!(snapshot.reply_delivery_failed, 0);
        let calls_after_failure = lock_test(&observation).len();
        assert!(matches!(
            worker.handle().try_read_history(owner),
            Err(AtomicWorkerError::FailedClosed)
        ));
        assert_eq!(lock_test(&observation).len(), calls_after_failure);
        worker.shutdown()?;
        Ok(())
    }

    #[test]
    #[cfg(feature = "corpus-zaino")]
    fn projection_sink_rejects_nonstandard_events_before_admission() -> TestResult<()> {
        let (mut worker, observation) = worker(1, None)?;
        let event = UtxoEvent::created(
            [0x6b; TXID_BYTES],
            11,
            12,
            13,
            UtxoScriptClass::NonStandard,
            [0x7c; 20],
        );

        assert_eq!(
            ProjectionEventSink::append_and_wait(&mut worker, event),
            Err(AtomicProjectionSinkError)
        );
        let snapshot = worker.snapshot();
        assert_eq!(snapshot.accepted, 0);
        assert_eq!(snapshot.completed, 0);
        assert_eq!(snapshot.failed, 0);
        assert!(lock_test(&observation).is_empty());
        worker.shutdown()?;
        Ok(())
    }

    #[test]
    #[cfg(feature = "corpus-zaino")]
    fn projection_sink_errors_and_debug_output_are_identifier_free() -> TestResult<()> {
        let (worker, _) = worker(1, None)?;

        assert_eq!(
            AtomicProjectionSinkError.to_string(),
            "projection event mutation failed"
        );
        assert_eq!(
            format!("{AtomicProjectionSinkError:?}"),
            "AtomicProjectionSinkError"
        );
        assert_eq!(format!("{worker:?}"), "AtomicWorker { ..REDACTED.. }");
        worker.shutdown()?;
        Ok(())
    }

    fn wait_for(
        handle: &AtomicWorkerHandle,
        predicate: impl Fn(AtomicWorkerSnapshot) -> bool,
    ) -> AtomicWorkerSnapshot {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let snapshot = handle.snapshot();
            if predicate(snapshot) {
                return snapshot;
            }
            assert!(
                Instant::now() < deadline,
                "worker did not reach the expected state"
            );
            thread::yield_now();
        }
    }

    fn assert_accounting(snapshot: AtomicWorkerSnapshot) {
        assert!(snapshot.queued <= snapshot.queue_capacity);
        assert!(snapshot.queue_high_water <= snapshot.queue_capacity);
        assert!(snapshot.in_flight <= 1);
        let unresolved = u64::try_from(snapshot.queued + snapshot.in_flight)
            .expect("bounded test counts must fit u64");
        assert_eq!(
            snapshot.accepted,
            snapshot.completed + snapshot.failed + unresolved
        );
    }

    #[test]
    fn business_commands_execute_once_in_fifo_order_on_one_thread(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (worker, observation) = worker(2, None)?;
        let handle = worker.handle();
        let first_owner = address(0x11);
        let second_owner = address(0x22);
        let first_event = event(first_owner, 0x31);
        let second_event = event(second_owner, 0x42);

        let first = handle.try_append(first_owner, first_event)?;
        let second = handle.try_append(second_owner, second_event)?;
        assert_eq!(first.wait()?.events()[0], Some(first_event));
        assert_eq!(second.wait()?.events()[0], Some(second_event));
        let history = handle.try_read_history(first_owner)?.wait()?;
        assert_eq!(history.events()[0], Some(first_event));

        let calls = lock_test(&observation);
        let owner = calls
            .first()
            .expect("commands must touch the backend")
            .owner;
        assert!(calls.iter().all(|call| call.owner == owner));
        assert_eq!(
            calls
                .iter()
                .filter(|call| call.operation == OperationKind::Write)
                .count(),
            4
        );
        drop(calls);
        let snapshot = worker.shutdown()?;
        assert_eq!(snapshot.lifecycle, WorkerLifecycle::Stopped);
        assert_eq!(snapshot.accepted, 3);
        assert_eq!(snapshot.completed, 3);
        assert_accounting(snapshot);
        Ok(())
    }

    #[test]
    fn bounded_queue_rejects_excess_work_without_fallback() -> Result<(), Box<dyn std::error::Error>>
    {
        let gate = Arc::new(Gate::default());
        let control = ReadControl {
            call: 1,
            gate: Arc::clone(&gate),
            fail: false,
        };
        let (worker, _) = worker(1, Some(control))?;
        let handle = worker.handle();
        let owner = address(0x12);
        let first = handle.try_append(owner, event(owner, 0x32))?;
        gate.wait_until_entered();
        let queued = handle.try_read_history(owner)?;
        assert!(matches!(
            handle.try_read_history(owner),
            Err(AtomicWorkerError::QueueFull)
        ));

        gate.release();
        wait_for(&handle, |snapshot| snapshot.completed == 2);
        first.wait()?;
        queued.wait()?;
        let snapshot = worker.shutdown()?;
        assert_eq!(snapshot.full_rejected, 1);
        assert_eq!(snapshot.queue_high_water, 1);
        assert_accounting(snapshot);
        Ok(())
    }

    #[test]
    fn shutdown_drains_accepted_work_and_rejects_cloned_handles(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let gate = Arc::new(Gate::default());
        let control = ReadControl {
            call: 1,
            gate: Arc::clone(&gate),
            fail: false,
        };
        let (worker, _) = worker(2, Some(control))?;
        let handle = worker.handle();
        let cloned = handle.clone();
        let owner = address(0x1d);
        let active = handle.try_read_history(owner)?;
        gate.wait_until_entered();
        let queued = handle.try_read_history(owner)?;
        let shutdown = thread::spawn(move || worker.shutdown());
        wait_for(&handle, |snapshot| {
            snapshot.lifecycle == WorkerLifecycle::Draining
        });
        assert!(matches!(
            cloned.try_read_history(owner),
            Err(AtomicWorkerError::NotRunning)
        ));

        gate.release();
        active.wait()?;
        queued.wait()?;
        let snapshot = shutdown
            .join()
            .expect("shutdown test thread must not panic")?;
        assert_eq!(snapshot.lifecycle, WorkerLifecycle::Stopped);
        assert_eq!(snapshot.accepted, 2);
        assert_eq!(snapshot.completed, 2);
        assert_accounting(snapshot);
        Ok(())
    }

    #[test]
    fn owner_drop_closes_admission_and_joins_worker() -> Result<(), Box<dyn std::error::Error>> {
        let handle = {
            let (worker, _) = worker(1, None)?;
            let handle = worker.handle();
            handle.try_read_history(address(0x1e))?.wait()?;
            handle
        };
        let snapshot = handle.snapshot();
        assert_eq!(snapshot.lifecycle, WorkerLifecycle::Stopped);
        assert!(matches!(
            handle.try_read_history(address(0x1e)),
            Err(AtomicWorkerError::NotRunning)
        ));
        assert_accounting(snapshot);
        Ok(())
    }

    #[test]
    fn nonterminal_command_rejection_keeps_worker_ready() -> Result<(), Box<dyn std::error::Error>>
    {
        let (worker, _) = worker(1, None)?;
        let handle = worker.handle();
        let requested = address(0x13);
        let other = address(0x14);
        let rejected = handle.try_append(requested, event(other, 0x33))?.wait();
        assert!(matches!(rejected, Err(AtomicWorkerError::CommandRejected)));
        handle.try_read_history(requested)?.wait()?;

        let snapshot = worker.shutdown()?;
        assert_eq!(snapshot.fault, None);
        assert_eq!(snapshot.completed, 1);
        assert_eq!(snapshot.failed, 1);
        assert_accounting(snapshot);
        Ok(())
    }

    #[test]
    fn dropped_nonterminal_append_rejection_still_fails_closed(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (worker, _) = worker(2, None)?;
        let handle = worker.handle();
        let requested = address(0x1f);
        let other = address(0x20);
        let rejected = handle.try_append(requested, event(other, 0x3f))?;
        let marker = handle.try_read_history(requested)?;
        wait_for(&handle, |snapshot| {
            snapshot.failed == 1 && snapshot.completed == 1
        });
        drop(rejected);
        let snapshot = handle.snapshot();
        assert_eq!(snapshot.fault, Some(WorkerFault::Terminal));
        assert_eq!(snapshot.reply_delivery_failed, 1);
        marker.wait()?;
        assert!(matches!(
            handle.try_read_history(requested),
            Err(AtomicWorkerError::FailedClosed)
        ));
        worker.shutdown()?;
        Ok(())
    }

    #[test]
    fn terminal_executor_error_fails_queued_and_future_commands_without_io(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let gate = Arc::new(Gate::default());
        let control = ReadControl {
            call: 1,
            gate: Arc::clone(&gate),
            fail: true,
        };
        let (worker, observation) = worker(2, Some(control))?;
        let handle = worker.handle();
        let owner = address(0x15);
        let terminal = handle.try_read_history(owner)?;
        gate.wait_until_entered();
        let queued = handle.try_read_history(owner)?;
        gate.release();

        assert!(matches!(
            terminal.wait(),
            Err(AtomicWorkerError::FailedClosed)
        ));
        let calls_after_terminal = lock_test(&observation).len();
        assert!(matches!(
            queued.wait(),
            Err(AtomicWorkerError::FailedClosed)
        ));
        assert_eq!(lock_test(&observation).len(), calls_after_terminal);
        assert!(matches!(
            handle.try_read_history(owner),
            Err(AtomicWorkerError::FailedClosed)
        ));

        let snapshot = worker.shutdown()?;
        assert_eq!(snapshot.fault, Some(WorkerFault::Terminal));
        assert_eq!(snapshot.failed, 2);
        assert_accounting(snapshot);
        Ok(())
    }

    fn assert_partial_event_write_fails_closed(
        outcome: WriteOutcome,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let control = WriteControl { call: 1, outcome };
        let (worker, observation) = worker_with_event_write(control)?;
        let handle = worker.handle();
        let owner = address(0x21);
        assert!(matches!(
            handle.try_append(owner, event(owner, 0x41))?.wait(),
            Err(AtomicWorkerError::FailedClosed)
        ));
        let calls_after_terminal = lock_test(&observation).len();
        assert!(matches!(
            handle.try_read_history(owner),
            Err(AtomicWorkerError::FailedClosed)
        ));
        assert_eq!(lock_test(&observation).len(), calls_after_terminal);
        let snapshot = worker.shutdown()?;
        assert_eq!(snapshot.fault, Some(WorkerFault::Terminal));
        assert_eq!(snapshot.reply_delivery_failed, 0);
        assert_accounting(snapshot);
        Ok(())
    }

    #[test]
    fn partial_event_write_error_and_panic_are_coarsely_failed_closed(
    ) -> Result<(), Box<dyn std::error::Error>> {
        assert_partial_event_write_fails_closed(WriteOutcome::MutateThenFail)?;
        assert_partial_event_write_fails_closed(WriteOutcome::MutateThenPanic)
    }

    #[test]
    fn dropped_read_reply_is_nonterminal() -> Result<(), Box<dyn std::error::Error>> {
        let gate = Arc::new(Gate::default());
        let control = ReadControl {
            call: 1,
            gate: Arc::clone(&gate),
            fail: false,
        };
        let (worker, _) = worker(1, Some(control))?;
        let handle = worker.handle();
        let owner = address(0x16);
        let abandoned = handle.try_read_history(owner)?;
        gate.wait_until_entered();
        drop(abandoned);
        gate.release();
        wait_for(&handle, |snapshot| snapshot.completed == 1);

        handle.try_read_history(owner)?.wait()?;
        let snapshot = worker.shutdown()?;
        assert_eq!(snapshot.fault, None);
        assert_eq!(snapshot.reply_delivery_failed, 1);
        assert_eq!(snapshot.completed, 2);
        assert_accounting(snapshot);
        Ok(())
    }

    #[test]
    fn retained_append_ticket_does_not_block_later_work_or_shutdown(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (worker, _) = worker(2, None)?;
        let handle = worker.handle();
        let owner = address(0x19);
        let retained = handle.try_append(owner, event(owner, 0x39))?;
        let later = handle.try_read_history(owner)?;
        wait_for(&handle, |snapshot| snapshot.completed == 2);
        assert_eq!(later.wait()?.events()[0], Some(event(owner, 0x39)));

        let snapshot = worker.shutdown()?;
        assert_eq!(snapshot.lifecycle, WorkerLifecycle::Stopped);
        assert_eq!(snapshot.reply_delivery_failed, 0);
        assert_eq!(retained.wait()?.events()[0], Some(event(owner, 0x39)));
        assert_eq!(handle.snapshot().reply_delivery_failed, 0);
        Ok(())
    }

    #[test]
    fn dropping_buffered_append_reply_latches_one_coarse_delivery_failure(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (worker, _) = worker(2, None)?;
        let handle = worker.handle();
        let owner = address(0x1a);
        let buffered = handle.try_append(owner, event(owner, 0x3a))?;
        let marker = handle.try_read_history(owner)?;
        // The FIFO worker cannot start and complete the marker until it has
        // successfully buffered the preceding append response.
        wait_for(&handle, |snapshot| snapshot.completed == 2);
        drop(buffered);
        let snapshot = handle.snapshot();
        assert_eq!(snapshot.fault, Some(WorkerFault::Terminal));
        assert_eq!(snapshot.reply_delivery_failed, 1);
        marker.wait()?;
        assert!(matches!(
            handle.try_read_history(owner),
            Err(AtomicWorkerError::FailedClosed)
        ));
        worker.shutdown()?;
        Ok(())
    }

    #[test]
    fn dropped_queued_append_never_enters_executor() -> Result<(), Box<dyn std::error::Error>> {
        let gate = Arc::new(Gate::default());
        let control = ReadControl {
            call: 1,
            gate: Arc::clone(&gate),
            fail: false,
        };
        let (worker, observation) = worker(2, Some(control))?;
        let handle = worker.handle();
        let owner = address(0x1b);
        let active = handle.try_read_history(owner)?;
        gate.wait_until_entered();
        let queued = handle.try_append(owner, event(owner, 0x3b))?;
        drop(queued);
        assert_eq!(handle.snapshot().fault, Some(WorkerFault::Terminal));
        gate.release();
        assert!(matches!(
            active.wait(),
            Err(AtomicWorkerError::FailedClosed)
        ));
        let calls_after_active = lock_test(&observation).len();
        wait_for(&handle, |snapshot| snapshot.failed == 2);
        assert_eq!(lock_test(&observation).len(), calls_after_active);
        assert_eq!(
            lock_test(&observation)
                .iter()
                .filter(|call| call.operation == OperationKind::Write)
                .count(),
            0
        );
        worker.shutdown()?;
        Ok(())
    }

    #[test]
    fn in_flight_command_finishes_io_after_latch_but_queued_command_does_not(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let gate = Arc::new(Gate::default());
        let control = ReadControl {
            call: DIRECTORY_PROBES + 1,
            gate: Arc::clone(&gate),
            fail: false,
        };
        let (worker, observation) = worker(2, Some(control))?;
        let handle = worker.handle();
        let owner = address(0x1c);
        let buffered = handle.try_append(owner, event(owner, 0x3c))?;
        let in_flight = handle.try_read_history(owner)?;
        gate.wait_until_entered();
        let queued = handle.try_read_history(owner)?;
        drop(buffered);
        assert_eq!(handle.snapshot().fault, Some(WorkerFault::Terminal));
        gate.release();

        assert!(matches!(
            in_flight.wait(),
            Err(AtomicWorkerError::FailedClosed)
        ));
        let calls_after_in_flight = lock_test(&observation).len();
        assert!(matches!(
            queued.wait(),
            Err(AtomicWorkerError::FailedClosed)
        ));
        assert_eq!(lock_test(&observation).len(), calls_after_in_flight);
        let snapshot = worker.shutdown()?;
        assert_eq!(snapshot.reply_delivery_failed, 1);
        assert_eq!(snapshot.fault, Some(WorkerFault::Terminal));
        assert_accounting(snapshot);
        Ok(())
    }

    fn assert_dropped_append_latches(
        control_call: usize,
        prime_exact_replay: bool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let gate = Arc::new(Gate::default());
        let control = ReadControl {
            call: control_call,
            gate: Arc::clone(&gate),
            fail: false,
        };
        let (worker, _) = worker(1, Some(control))?;
        let handle = worker.handle();
        let owner = address(0x17);
        let value = event(owner, 0x37);
        if prime_exact_replay {
            handle.try_append(owner, value)?.wait()?;
        }
        let abandoned = handle.try_append(owner, value)?;
        gate.wait_until_entered();
        drop(abandoned);
        gate.release();
        let snapshot = wait_for(&handle, |snapshot| {
            snapshot.fault == Some(WorkerFault::Terminal)
        });
        assert_eq!(snapshot.reply_delivery_failed, 1);
        assert!(matches!(
            handle.try_read_history(owner),
            Err(AtomicWorkerError::FailedClosed)
        ));
        let snapshot = worker.shutdown()?;
        assert_eq!(snapshot.lifecycle, WorkerLifecycle::Stopped);
        assert_eq!(snapshot.fault, Some(WorkerFault::Terminal));
        assert_accounting(snapshot);
        Ok(())
    }

    #[test]
    fn dropped_insert_and_exact_replay_replies_fail_closed_uniformly(
    ) -> Result<(), Box<dyn std::error::Error>> {
        assert_dropped_append_latches(1, false)?;
        // One append performs four directory reads; gate the first directory
        // read of the exact replay command.
        assert_dropped_append_latches(DIRECTORY_PROBES + 1, true)
    }

    fn assert_outer_worker_panic(panic_on_event_drop: bool) -> TestResult<()> {
        let (worker, observation) = if panic_on_event_drop {
            worker_with_event_drop_panic()?
        } else {
            worker(2, None)?
        };
        let handle = worker.handle();
        let (entered, entered_response) = mpsc::sync_channel(REPLY_CHANNEL_CAPACITY);
        let (release, release_response) = mpsc::sync_channel(REPLY_CHANNEL_CAPACITY);
        let active = handle.try_panic_worker_loop(entered, release_response)?;
        entered_response
            .recv()
            .expect("injected panic command must enter the worker");
        let queued = handle.try_read_history(address(0x18))?;
        release
            .send(())
            .expect("injected panic command must be releasable");

        assert!(matches!(
            active.wait(),
            Err(AtomicWorkerError::AcceptedOutcomeIndeterminate)
        ));
        assert!(matches!(
            queued.wait(),
            Err(AtomicWorkerError::FailedClosed)
        ));
        let snapshot = wait_for(&handle, |snapshot| {
            snapshot.lifecycle == WorkerLifecycle::Stopped
        });
        assert_eq!(snapshot.fault, Some(WorkerFault::Terminal));
        assert!(lock_test(&observation).is_empty());
        assert_accounting(snapshot);
        assert!(matches!(
            worker.shutdown(),
            Err(AtomicWorkerError::WorkerPanicked)
        ));
        Ok(())
    }

    #[test]
    fn outer_worker_and_backend_drop_panics_drain_queue_before_stopping() -> TestResult<()> {
        assert_outer_worker_panic(false)?;
        assert_outer_worker_panic(true)
    }

    #[test]
    fn queue_bounds_and_debug_surfaces_are_identifier_free(
    ) -> Result<(), Box<dyn std::error::Error>> {
        assert!(matches!(
            AtomicQueueCapacity::try_new(0),
            Err(AtomicQueueCapacityError::Invalid)
        ));
        assert!(matches!(
            AtomicQueueCapacity::try_new(MAX_WORKER_QUEUE_CAPACITY + 1),
            Err(AtomicQueueCapacityError::Invalid)
        ));

        let (worker, _) = worker(1, None)?;
        let handle = worker.handle();
        let reply = handle.try_read_history(address(0x6a))?;
        for rendered in [
            format!("{worker:?}"),
            format!("{handle:?}"),
            format!("{reply:?}"),
            format!("{:?}", handle.snapshot()),
            format!("{:?}", AtomicWorkerError::CommandRejected),
        ] {
            assert!(!rendered.contains("106"));
            assert!(!rendered.contains("6a6a"));
        }
        reply.wait()?;
        worker.shutdown()?;
        Ok(())
    }
}
