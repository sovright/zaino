//! Bounded single-owner execution for the volatile `rostl` candidate.
//!
//! This worker serializes candidate reads and inserts because both operations
//! mutate ORAM position state. It is an offline scheduling and failure model,
//! not an [`crate::store::ObliviousStore`] implementation: it has no durable
//! commit, recovery, address-query, or physical-obliviousness contract.

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

use crate::records::PersistentUtxoEvent;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use crate::rostl_adapter::{RostlAdapterError, RostlCandidateStore};

const REPLY_CHANNEL_CAPACITY: usize = 1;
// Allocation guard for the offline experiment, not an approved service profile.
const MAX_WORKER_QUEUE_CAPACITY: usize = 4_096;
const WORKER_THREAD_NAME: &str = "zaino-oram-rostl";

#[derive(Clone, Copy)]
struct RostlQueueCapacity(NonZeroUsize);

impl RostlQueueCapacity {
    fn try_new(value: usize) -> Result<Self, RostlWorkerError> {
        match NonZeroUsize::new(value) {
            Some(value) if value.get() <= MAX_WORKER_QUEUE_CAPACITY => Ok(Self(value)),
            Some(_) | None => Err(RostlWorkerError::InvalidQueueCapacity),
        }
    }

    const fn get(self) -> usize {
        self.0.get()
    }
}

/// Owns the worker thread and its only command handle.
struct RostlWorker {
    handle: RostlWorkerHandle,
    join: Option<JoinHandle<WorkerExit>>,
}

impl RostlWorker {
    fn spawn(
        store_capacity: usize,
        queue_capacity: RostlQueueCapacity,
    ) -> Result<Self, RostlWorkerError> {
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        {
            let backend = RostlCandidateStore::new(store_capacity)
                .map_err(|_| RostlWorkerError::BackendUnavailable)?;
            Self::spawn_backend(backend, queue_capacity)
        }

        #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
        {
            let _ = (store_capacity, queue_capacity);
            Err(RostlWorkerError::BackendUnavailable)
        }
    }

    fn spawn_backend<B>(
        backend: B,
        queue_capacity: RostlQueueCapacity,
    ) -> Result<Self, RostlWorkerError>
    where
        B: WorkerBackend,
    {
        let queue_capacity = queue_capacity.get();
        let (sender, receiver) = mpsc::sync_channel(queue_capacity);
        let shared = Arc::new(WorkerShared {
            state: Mutex::new(WorkerState::new(queue_capacity)),
        });
        let worker_shared = Arc::clone(&shared);
        let join = thread::Builder::new()
            .name(WORKER_THREAD_NAME.to_owned())
            .spawn(move || worker_entry(backend, receiver, &worker_shared))
            .map_err(RostlWorkerError::ThreadSpawn)?;
        {
            let mut state = lock_state(&shared);
            state.lifecycle = WorkerLifecycle::Ready;
        }
        Ok(Self {
            handle: RostlWorkerHandle { sender, shared },
            join: Some(join),
        })
    }

    fn handle(&self) -> RostlWorkerHandle {
        self.handle.clone()
    }

    fn snapshot(&self) -> RostlWorkerSnapshot {
        self.handle.snapshot()
    }

    fn shutdown(mut self) -> Result<RostlWorkerSnapshot, RostlWorkerError> {
        let signal_result = self.signal_shutdown();
        let join_result = self.join_worker();
        match join_result {
            Err(error) => Err(error),
            Ok(()) => signal_result.map(|()| self.snapshot()),
        }
    }

    fn signal_shutdown(&self) -> Result<(), RostlWorkerError> {
        let (reply, response) = mpsc::sync_channel(REPLY_CHANNEL_CAPACITY);
        let mut state = lock_state(&self.handle.shared);
        match state.lifecycle {
            WorkerLifecycle::Starting | WorkerLifecycle::Ready => {
                state.lifecycle = WorkerLifecycle::Draining;
            }
            WorkerLifecycle::Draining => return Err(RostlWorkerError::NotRunning),
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
            state.latch_fault(WorkerFault::WorkerExited);
            state.mark_stopped();
            return Err(RostlWorkerError::WorkerDisconnected);
        }
        response.recv().map_err(|_| {
            let mut state = lock_state(&self.handle.shared);
            state.latch_fault(WorkerFault::WorkerExited);
            state.mark_stopped();
            RostlWorkerError::WorkerDisconnected
        })
    }

    fn join_worker(&mut self) -> Result<(), RostlWorkerError> {
        let Some(join) = self.join.take() else {
            return Ok(());
        };
        match join.join() {
            Ok(WorkerExit::Clean) => Ok(()),
            Ok(WorkerExit::Panicked) | Err(_) => {
                let mut state = lock_state(&self.handle.shared);
                state.latch_fault(WorkerFault::WorkerPanic);
                state.mark_stopped();
                Err(RostlWorkerError::WorkerPanicked)
            }
        }
    }
}

impl Drop for RostlWorker {
    fn drop(&mut self) {
        if self.join.is_none() {
            return;
        }
        let _ = self.signal_shutdown();
        let _ = self.join_worker();
    }
}

impl fmt::Debug for RostlWorker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RostlWorker { ..REDACTED.. }")
    }
}

/// Cloneable bounded-admission handle. It never exposes the owned backend.
#[derive(Clone)]
struct RostlWorkerHandle {
    sender: SyncSender<WorkerCommand>,
    shared: Arc<WorkerShared>,
}

impl RostlWorkerHandle {
    fn try_insert(
        &self,
        key: usize,
        value: PersistentUtxoEvent,
    ) -> Result<RostlWorkerReply<()>, RostlWorkerError> {
        let (reply, response) = mpsc::sync_channel(REPLY_CHANNEL_CAPACITY);
        self.admit(WorkerCommand::Insert { key, value, reply })?;
        Ok(RostlWorkerReply { response })
    }

    fn try_read(
        &self,
        key: usize,
    ) -> Result<RostlWorkerReply<Option<PersistentUtxoEvent>>, RostlWorkerError> {
        let (reply, response) = mpsc::sync_channel(REPLY_CHANNEL_CAPACITY);
        self.admit(WorkerCommand::Read { key, reply })?;
        Ok(RostlWorkerReply { response })
    }

    fn snapshot(&self) -> RostlWorkerSnapshot {
        RostlWorkerSnapshot::from(&*lock_state(&self.shared))
    }

    fn admit(&self, command: WorkerCommand) -> Result<(), RostlWorkerError> {
        let mut state = lock_state(&self.shared);
        if state.fault.is_some() {
            state.not_running_rejected = state.not_running_rejected.saturating_add(1);
            return Err(RostlWorkerError::FailedClosed);
        }
        match state.lifecycle {
            WorkerLifecycle::Ready => {}
            WorkerLifecycle::Starting | WorkerLifecycle::Draining | WorkerLifecycle::Stopped => {
                state.not_running_rejected = state.not_running_rejected.saturating_add(1);
                return Err(RostlWorkerError::NotRunning);
            }
        }
        if state.queued >= state.queue_capacity {
            state.full_rejected = state.full_rejected.saturating_add(1);
            return Err(RostlWorkerError::QueueFull);
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
                Err(RostlWorkerError::QueueFull)
            }
            Err(TrySendError::Disconnected(_)) => {
                state.not_running_rejected = state.not_running_rejected.saturating_add(1);
                state.latch_fault(WorkerFault::WorkerExited);
                state.mark_stopped();
                Err(RostlWorkerError::WorkerDisconnected)
            }
        }
    }
}

impl fmt::Debug for RostlWorkerHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RostlWorkerHandle { ..REDACTED.. }")
    }
}

/// One accepted command's fixed-capacity reply path.
struct RostlWorkerReply<T> {
    response: Receiver<Result<T, RostlWorkerError>>,
}

impl<T> RostlWorkerReply<T> {
    fn wait(self) -> Result<T, RostlWorkerError> {
        self.response
            .recv()
            .map_err(|_| RostlWorkerError::AcceptedOutcomeIndeterminate)?
    }
}

impl<T> fmt::Debug for RostlWorkerReply<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RostlWorkerReply { ..REDACTED.. }")
    }
}

/// Fixed-schema aggregate worker telemetry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RostlWorkerSnapshot {
    queue_capacity: usize,
    queued: usize,
    in_flight: usize,
    queue_high_water: usize,
    accepted: u64,
    completed: u64,
    failed: u64,
    full_rejected: u64,
    not_running_rejected: u64,
    reply_send_failed: u64,
    lifecycle: WorkerLifecycle,
    fault: Option<WorkerFault>,
}

impl From<&WorkerState> for RostlWorkerSnapshot {
    fn from(state: &WorkerState) -> Self {
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
            reply_send_failed: state.reply_send_failed,
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
    Backend,
    BackendPanic,
    WorkerPanic,
    WorkerExited,
    InternalState,
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
    reply_send_failed: u64,
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
            reply_send_failed: 0,
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
            state.latch_fault(WorkerFault::InternalState);
            state
        }
    }
}

enum WorkerCommand {
    Insert {
        key: usize,
        value: PersistentUtxoEvent,
        reply: SyncSender<Result<(), RostlWorkerError>>,
    },
    Read {
        key: usize,
        reply: SyncSender<Result<Option<PersistentUtxoEvent>, RostlWorkerError>>,
    },
    Shutdown {
        reply: SyncSender<()>,
    },
    #[cfg(test)]
    PanicWorkerLoop {
        entered: SyncSender<()>,
        release: Receiver<()>,
        reply: SyncSender<Result<(), RostlWorkerError>>,
    },
}

trait WorkerBackend: Send + 'static {
    fn insert(&mut self, key: usize, value: PersistentUtxoEvent)
        -> Result<(), BackendCommandError>;

    fn read(&mut self, key: usize) -> Result<Option<PersistentUtxoEvent>, BackendCommandError>;
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
impl WorkerBackend for RostlCandidateStore {
    fn insert(
        &mut self,
        key: usize,
        value: PersistentUtxoEvent,
    ) -> Result<(), BackendCommandError> {
        RostlCandidateStore::insert(self, key, value).map_err(classify_adapter_error)
    }

    fn read(&mut self, key: usize) -> Result<Option<PersistentUtxoEvent>, BackendCommandError> {
        RostlCandidateStore::read(self, key).map_err(classify_adapter_error)
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const fn classify_adapter_error(error: RostlAdapterError) -> BackendCommandError {
    match error {
        RostlAdapterError::KeyOutsideCapacity { .. } => BackendCommandError::Rejected,
        RostlAdapterError::InvalidCapacity { .. }
        | RostlAdapterError::DuplicateKey
        | RostlAdapterError::InvalidRecord(_)
        | RostlAdapterError::UpstreamPanic
        | RostlAdapterError::FailedClosed => BackendCommandError::Terminal,
    }
}

#[derive(Clone, Copy)]
enum BackendCommandError {
    Rejected,
    Terminal,
}

fn worker_entry<B>(
    mut backend: B,
    receiver: Receiver<WorkerCommand>,
    shared: &WorkerShared,
) -> WorkerExit
where
    B: WorkerBackend,
{
    match catch_unwind(AssertUnwindSafe(|| {
        worker_loop(&mut backend, &receiver, shared)
    })) {
        Ok(exit) => exit,
        Err(_) => {
            {
                let mut state = lock_state(shared);
                state.latch_fault(WorkerFault::WorkerPanic);
                if state.in_flight != 0 {
                    state.in_flight = 0;
                    state.failed = state.failed.saturating_add(1);
                }
            }
            drain_failed_commands(&receiver, shared);
            lock_state(shared).mark_stopped();
            WorkerExit::Panicked
        }
    }
}

fn worker_loop<B>(
    backend: &mut B,
    receiver: &Receiver<WorkerCommand>,
    shared: &WorkerShared,
) -> WorkerExit
where
    B: WorkerBackend,
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
            WorkerCommand::Insert { key, value, reply } => {
                mark_dequeued(shared);
                let result = execute_command(shared, || backend.insert(key, value));
                send_reply(reply, result, shared);
            }
            WorkerCommand::Read { key, reply } => {
                mark_dequeued(shared);
                let result = execute_command(shared, || backend.read(key));
                send_reply(reply, result, shared);
            }
            WorkerCommand::Shutdown { reply } => {
                lock_state(shared).mark_stopped();
                if reply.send(()).is_err() {
                    increment_reply_send_failed(shared);
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
                panic!("injected generic worker-loop panic");
            }
        }
    }
}

fn execute_command<T>(
    shared: &WorkerShared,
    operation: impl FnOnce() -> Result<T, BackendCommandError>,
) -> Result<T, RostlWorkerError> {
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
            return Err(RostlWorkerError::FailedClosed);
        }
    }
    let outcome = catch_unwind(AssertUnwindSafe(operation));
    let mut state = lock_state(shared);
    if state.fault.is_some() {
        state.failed = state.failed.saturating_add(1);
        finish_in_flight(&mut state);
        return Err(RostlWorkerError::FailedClosed);
    }
    let result = match outcome {
        Ok(Ok(value)) => {
            state.completed = state.completed.saturating_add(1);
            Ok(value)
        }
        Ok(Err(BackendCommandError::Rejected)) => {
            state.failed = state.failed.saturating_add(1);
            Err(RostlWorkerError::CommandRejected)
        }
        Ok(Err(BackendCommandError::Terminal)) => {
            state.failed = state.failed.saturating_add(1);
            state.latch_fault(WorkerFault::Backend);
            Err(RostlWorkerError::FailedClosed)
        }
        Err(_) => {
            state.failed = state.failed.saturating_add(1);
            state.latch_fault(WorkerFault::BackendPanic);
            Err(RostlWorkerError::FailedClosed)
        }
    };
    finish_in_flight(&mut state);
    result
}

fn mark_dequeued(shared: &WorkerShared) {
    let mut state = lock_state(shared);
    match state.queued.checked_sub(1) {
        Some(queued) => state.queued = queued,
        None => state.latch_fault(WorkerFault::InternalState),
    }
    if state.in_flight == 0 {
        state.in_flight = 1;
    } else {
        state.latch_fault(WorkerFault::InternalState);
    }
}

fn finish_in_flight(state: &mut WorkerState) {
    if state.in_flight == 1 {
        state.in_flight = 0;
    } else {
        state.latch_fault(WorkerFault::InternalState);
    }
}

fn send_reply<T>(
    reply: SyncSender<Result<T, RostlWorkerError>>,
    result: Result<T, RostlWorkerError>,
    shared: &WorkerShared,
) {
    if reply.send(result).is_err() {
        increment_reply_send_failed(shared);
    }
}

fn increment_reply_send_failed(shared: &WorkerShared) {
    let mut state = lock_state(shared);
    state.reply_send_failed = state.reply_send_failed.saturating_add(1);
}

fn drain_failed_commands(receiver: &Receiver<WorkerCommand>, shared: &WorkerShared) {
    loop {
        match receiver.try_recv() {
            Ok(WorkerCommand::Insert { reply, .. }) => {
                resolve_queued_failure(shared);
                send_reply(reply, Err(RostlWorkerError::FailedClosed), shared);
            }
            Ok(WorkerCommand::Read { reply, .. }) => {
                resolve_queued_failure(shared);
                send_reply(reply, Err(RostlWorkerError::FailedClosed), shared);
            }
            Ok(WorkerCommand::Shutdown { reply }) => {
                if reply.send(()).is_err() {
                    increment_reply_send_failed(shared);
                }
                return;
            }
            #[cfg(test)]
            Ok(WorkerCommand::PanicWorkerLoop { reply, .. }) => {
                resolve_queued_failure(shared);
                send_reply(reply, Err(RostlWorkerError::FailedClosed), shared);
            }
            Err(TryRecvError::Empty | TryRecvError::Disconnected) => return,
        }
    }
}

fn resolve_queued_failure(shared: &WorkerShared) {
    let mut state = lock_state(shared);
    match state.queued.checked_sub(1) {
        Some(queued) => state.queued = queued,
        None => state.latch_fault(WorkerFault::InternalState),
    }
    state.failed = state.failed.saturating_add(1);
}

#[derive(Clone, Copy)]
enum WorkerExit {
    Clean,
    Panicked,
}

/// Identifier-free failure from worker startup, admission, execution, or join.
#[derive(Debug)]
enum RostlWorkerError {
    InvalidQueueCapacity,
    BackendUnavailable,
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

impl fmt::Display for RostlWorkerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidQueueCapacity => write!(
                f,
                "volatile candidate queue capacity must be in 1..={MAX_WORKER_QUEUE_CAPACITY}"
            ),
            Self::BackendUnavailable => f.write_str("volatile candidate backend is unavailable"),
            Self::ThreadSpawn(_) => f.write_str("volatile candidate worker could not start"),
            Self::QueueFull => f.write_str("volatile candidate worker queue is full"),
            Self::NotRunning => f.write_str("volatile candidate worker is not accepting work"),
            Self::WorkerDisconnected => {
                f.write_str("volatile candidate worker command channel is closed")
            }
            Self::AcceptedOutcomeIndeterminate => {
                f.write_str("accepted volatile command outcome is indeterminate")
            }
            Self::CommandRejected => f.write_str("volatile candidate backend rejected the command"),
            Self::FailedClosed => f.write_str("volatile candidate worker is failed closed"),
            Self::WorkerPanicked => f.write_str("volatile candidate worker thread panicked"),
        }
    }
}

impl std::error::Error for RostlWorkerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ThreadSpawn(error) => Some(error),
            Self::InvalidQueueCapacity
            | Self::BackendUnavailable
            | Self::QueueFull
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
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    use std::sync::OnceLock;
    use std::{
        collections::BTreeMap,
        sync::Condvar,
        thread::ThreadId,
        time::{Duration, Instant},
    };

    use super::*;
    use crate::records::{UtxoEvent, UtxoScriptClass, TXID_BYTES};

    fn queue_capacity(value: usize) -> RostlQueueCapacity {
        RostlQueueCapacity::try_new(value).expect("test queue capacity must be within bounds")
    }

    fn fixed_event(byte: u8) -> PersistentUtxoEvent {
        PersistentUtxoEvent::from_business(&UtxoEvent::created(
            [byte; TXID_BYTES],
            u32::from(byte),
            30_000 + u64::from(byte),
            100 + u32::from(byte),
            UtxoScriptClass::PayToScriptHash,
            [byte.wrapping_add(1); 20],
        ))
    }

    fn assert_accounting(snapshot: RostlWorkerSnapshot) {
        assert!(snapshot.queued <= snapshot.queue_capacity);
        assert!(snapshot.queue_high_water <= snapshot.queue_capacity);
        assert!(snapshot.in_flight <= 1);
        let unresolved = u64::try_from(snapshot.queued + snapshot.in_flight)
            .expect("bounded worker counts must fit u64");
        assert_eq!(
            snapshot.accepted,
            snapshot.completed + snapshot.failed + unresolved
        );
    }

    fn wait_for_lifecycle(handle: &RostlWorkerHandle, expected: WorkerLifecycle) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while handle.snapshot().lifecycle != expected {
            assert!(
                Instant::now() < deadline,
                "worker did not reach the expected lifecycle"
            );
            thread::yield_now();
        }
    }

    #[derive(Default)]
    struct Observation {
        owner: Option<ThreadId>,
        calls: Vec<ObservedCall>,
        maximum_in_flight: usize,
        in_flight: usize,
    }

    impl Observation {
        fn enter(&mut self, call: ObservedCall) -> Result<(), BackendCommandError> {
            let current = thread::current().id();
            match self.owner {
                Some(owner) if owner != current => return Err(BackendCommandError::Terminal),
                Some(_) => {}
                None => self.owner = Some(current),
            }
            self.in_flight += 1;
            self.maximum_in_flight = self.maximum_in_flight.max(self.in_flight);
            self.calls.push(call);
            Ok(())
        }

        fn leave(&mut self) {
            self.in_flight = self.in_flight.saturating_sub(1);
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum ObservedCall {
        Insert(usize),
        Read(usize),
    }

    struct RecordingBackend {
        records: BTreeMap<usize, PersistentUtxoEvent>,
        observation: Arc<Mutex<Observation>>,
    }

    impl RecordingBackend {
        fn new(observation: Arc<Mutex<Observation>>) -> Self {
            Self {
                records: BTreeMap::new(),
                observation,
            }
        }

        fn observe<T>(
            &self,
            call: ObservedCall,
            operation: impl FnOnce() -> T,
        ) -> Result<T, BackendCommandError> {
            lock_observation(&self.observation).enter(call)?;
            let result = operation();
            lock_observation(&self.observation).leave();
            Ok(result)
        }
    }

    impl WorkerBackend for RecordingBackend {
        fn insert(
            &mut self,
            key: usize,
            value: PersistentUtxoEvent,
        ) -> Result<(), BackendCommandError> {
            self.observe(ObservedCall::Insert(key), || ())?;
            if key == usize::MAX {
                return Err(BackendCommandError::Rejected);
            }
            if self.records.insert(key, value).is_some() {
                return Err(BackendCommandError::Terminal);
            }
            Ok(())
        }

        fn read(&mut self, key: usize) -> Result<Option<PersistentUtxoEvent>, BackendCommandError> {
            if key == usize::MAX {
                self.observe(ObservedCall::Read(key), || ())?;
                return Err(BackendCommandError::Rejected);
            }
            self.observe(ObservedCall::Read(key), || self.records.get(&key).copied())
        }
    }

    fn lock_observation(observation: &Mutex<Observation>) -> MutexGuard<'_, Observation> {
        observation
            .lock()
            .expect("test observation mutex must not be poisoned")
    }

    #[derive(Default)]
    struct GateState {
        entered: bool,
        release: bool,
    }

    #[derive(Default)]
    struct Gate {
        state: Mutex<GateState>,
        changed: Condvar,
    }

    impl Gate {
        fn enter_and_wait(&self) {
            let mut state = self
                .state
                .lock()
                .expect("test gate mutex must not be poisoned");
            state.entered = true;
            self.changed.notify_all();
            while !state.release {
                state = self
                    .changed
                    .wait(state)
                    .expect("test gate mutex must not be poisoned while waiting");
            }
        }

        fn wait_until_entered(&self) {
            let mut state = self
                .state
                .lock()
                .expect("test gate mutex must not be poisoned");
            while !state.entered {
                state = self
                    .changed
                    .wait(state)
                    .expect("test gate mutex must not be poisoned while waiting");
            }
        }

        fn release(&self) {
            let mut state = self
                .state
                .lock()
                .expect("test gate mutex must not be poisoned");
            state.release = true;
            self.changed.notify_all();
        }
    }

    enum BlockingOutcome {
        Success,
        Terminal,
        Panic,
    }

    struct BlockingBackend {
        gate: Arc<Gate>,
        calls: Arc<Mutex<usize>>,
        outcome: BlockingOutcome,
    }

    impl BlockingBackend {
        fn run(&self) -> Result<(), BackendCommandError> {
            {
                let mut calls = self
                    .calls
                    .lock()
                    .expect("test call-count mutex must not be poisoned");
                *calls += 1;
            }
            self.gate.enter_and_wait();
            match self.outcome {
                BlockingOutcome::Success => Ok(()),
                BlockingOutcome::Terminal => Err(BackendCommandError::Terminal),
                BlockingOutcome::Panic => panic!("injected generic backend panic"),
            }
        }
    }

    impl WorkerBackend for BlockingBackend {
        fn insert(
            &mut self,
            _key: usize,
            _value: PersistentUtxoEvent,
        ) -> Result<(), BackendCommandError> {
            self.run()
        }

        fn read(
            &mut self,
            _key: usize,
        ) -> Result<Option<PersistentUtxoEvent>, BackendCommandError> {
            self.run().map(|()| None)
        }
    }

    #[test]
    fn commands_execute_once_in_fifo_order_on_one_thread() -> Result<(), RostlWorkerError> {
        let observation = Arc::new(Mutex::new(Observation::default()));
        let worker = RostlWorker::spawn_backend(
            RecordingBackend::new(Arc::clone(&observation)),
            queue_capacity(4),
        )?;
        let handle = worker.handle();
        let first = fixed_event(0x11);
        let second = fixed_event(0x22);

        let insert_first = handle.try_insert(3, first)?;
        let read_first = handle.try_read(3)?;
        let insert_second = handle.try_insert(5, second)?;
        let read_second = handle.try_read(5)?;
        insert_first.wait()?;
        assert_eq!(read_first.wait()?, Some(first));
        insert_second.wait()?;
        assert_eq!(read_second.wait()?, Some(second));

        let snapshot = worker.shutdown()?;
        assert_accounting(snapshot);
        let observation = lock_observation(&observation);
        assert_eq!(
            observation.calls,
            [
                ObservedCall::Insert(3),
                ObservedCall::Read(3),
                ObservedCall::Insert(5),
                ObservedCall::Read(5),
            ]
        );
        assert_eq!(observation.maximum_in_flight, 1);
        assert_eq!(snapshot.accepted, 4);
        assert_eq!(snapshot.completed, 4);
        assert_eq!(snapshot.failed, 0);
        assert_eq!(snapshot.lifecycle, WorkerLifecycle::Stopped);
        Ok(())
    }

    #[test]
    fn bounded_queue_rejects_excess_work_without_fallback() -> Result<(), RostlWorkerError> {
        let gate = Arc::new(Gate::default());
        let calls = Arc::new(Mutex::new(0));
        let worker = RostlWorker::spawn_backend(
            BlockingBackend {
                gate: Arc::clone(&gate),
                calls: Arc::clone(&calls),
                outcome: BlockingOutcome::Success,
            },
            queue_capacity(1),
        )?;
        let handle = worker.handle();
        let first = handle.try_insert(1, fixed_event(1))?;
        gate.wait_until_entered();
        let second = handle.try_insert(2, fixed_event(2))?;
        let full = handle
            .try_read(0x5151)
            .expect_err("work beyond the fixed queue bound must be rejected");
        assert!(matches!(&full, RostlWorkerError::QueueFull));
        assert_eq!(full.to_string(), "volatile candidate worker queue is full");
        assert!(!format!("{full:?}").contains("5151"));
        let saturated = handle.snapshot();
        assert_accounting(saturated);
        assert_eq!(saturated.queued, 1);
        assert_eq!(saturated.queue_high_water, 1);
        assert_eq!(saturated.full_rejected, 1);

        gate.release();
        first.wait()?;
        second.wait()?;
        let snapshot = worker.shutdown()?;
        assert_accounting(snapshot);
        assert_eq!(snapshot.accepted, 2);
        assert_eq!(snapshot.completed, 2);
        assert_eq!(snapshot.queue_high_water, snapshot.queue_capacity);
        assert_eq!(
            *calls
                .lock()
                .expect("test call-count mutex must not be poisoned"),
            2
        );
        Ok(())
    }

    #[test]
    fn terminal_backend_failure_rejects_queued_and_future_work() -> Result<(), RostlWorkerError> {
        let gate = Arc::new(Gate::default());
        let calls = Arc::new(Mutex::new(0));
        let worker = RostlWorker::spawn_backend(
            BlockingBackend {
                gate: Arc::clone(&gate),
                calls: Arc::clone(&calls),
                outcome: BlockingOutcome::Terminal,
            },
            queue_capacity(1),
        )?;
        let handle = worker.handle();
        let triggering = handle.try_insert(1, fixed_event(1))?;
        gate.wait_until_entered();
        let queued = handle.try_insert(2, fixed_event(2))?;
        gate.release();
        assert!(matches!(
            triggering.wait(),
            Err(RostlWorkerError::FailedClosed)
        ));
        assert!(matches!(queued.wait(), Err(RostlWorkerError::FailedClosed)));
        assert!(matches!(
            handle.try_read(1),
            Err(RostlWorkerError::FailedClosed)
        ));

        let snapshot = worker.shutdown()?;
        assert_accounting(snapshot);
        assert_eq!(snapshot.fault, Some(WorkerFault::Backend));
        assert_eq!(snapshot.lifecycle, WorkerLifecycle::Stopped);
        assert_eq!(snapshot.accepted, 2);
        assert_eq!(snapshot.failed, 2);
        assert_eq!(
            *calls
                .lock()
                .expect("test call-count mutex must not be poisoned"),
            1
        );
        Ok(())
    }

    #[test]
    fn command_rejection_does_not_latch_worker() -> Result<(), RostlWorkerError> {
        let observation = Arc::new(Mutex::new(Observation::default()));
        let worker =
            RostlWorker::spawn_backend(RecordingBackend::new(observation), queue_capacity(1))?;
        let handle = worker.handle();
        assert!(matches!(
            handle.try_read(usize::MAX)?.wait(),
            Err(RostlWorkerError::CommandRejected)
        ));
        let event = fixed_event(9);
        handle.try_insert(9, event)?.wait()?;
        assert_eq!(handle.try_read(9)?.wait()?, Some(event));

        let snapshot = worker.shutdown()?;
        assert_accounting(snapshot);
        assert_eq!(snapshot.lifecycle, WorkerLifecycle::Stopped);
        assert_eq!(snapshot.fault, None);
        assert_eq!(snapshot.accepted, 3);
        assert_eq!(snapshot.completed, 2);
        assert_eq!(snapshot.failed, 1);
        Ok(())
    }

    #[test]
    fn backend_panic_is_caught_and_latches_redacted_failure() -> Result<(), RostlWorkerError> {
        let gate = Arc::new(Gate::default());
        let calls = Arc::new(Mutex::new(0));
        let worker = RostlWorker::spawn_backend(
            BlockingBackend {
                gate: Arc::clone(&gate),
                calls,
                outcome: BlockingOutcome::Panic,
            },
            queue_capacity(1),
        )?;
        let handle = worker.handle();
        let reply = handle.try_insert(0x5151, fixed_event(0x51))?;
        gate.wait_until_entered();
        gate.release();
        let error = reply
            .wait()
            .expect_err("injected backend panic must fail closed");
        assert_eq!(
            error.to_string(),
            "volatile candidate worker is failed closed"
        );
        assert!(!format!("{error:?}").contains("5151"));
        assert!(matches!(
            handle.try_read(0x5151),
            Err(RostlWorkerError::FailedClosed)
        ));
        let snapshot = worker.shutdown()?;
        assert_accounting(snapshot);
        assert_eq!(snapshot.fault, Some(WorkerFault::BackendPanic));
        assert_eq!(snapshot.lifecycle, WorkerLifecycle::Stopped);
        Ok(())
    }

    #[test]
    fn outer_worker_panic_marks_active_outcome_indeterminate_and_drains_queue(
    ) -> Result<(), RostlWorkerError> {
        let observation = Arc::new(Mutex::new(Observation::default()));
        let worker =
            RostlWorker::spawn_backend(RecordingBackend::new(observation), queue_capacity(1))?;
        let handle = worker.handle();
        let (entered, entered_response) = mpsc::sync_channel(REPLY_CHANNEL_CAPACITY);
        let (release, release_response) = mpsc::sync_channel(REPLY_CHANNEL_CAPACITY);
        let (reply, response) = mpsc::sync_channel(REPLY_CHANNEL_CAPACITY);
        handle.admit(WorkerCommand::PanicWorkerLoop {
            entered,
            release: release_response,
            reply,
        })?;
        entered_response
            .recv()
            .expect("injected worker panic command must start");
        let queued = handle.try_insert(8, fixed_event(8))?;
        release
            .send(())
            .expect("injected worker panic command must still be active");

        let active = RostlWorkerReply { response }
            .wait()
            .expect_err("outer worker panic must make the active outcome indeterminate");
        assert!(matches!(
            active,
            RostlWorkerError::AcceptedOutcomeIndeterminate
        ));
        assert!(matches!(queued.wait(), Err(RostlWorkerError::FailedClosed)));
        assert!(matches!(
            worker.shutdown(),
            Err(RostlWorkerError::WorkerPanicked)
        ));
        let snapshot = handle.snapshot();
        assert_accounting(snapshot);
        assert_eq!(snapshot.lifecycle, WorkerLifecycle::Stopped);
        assert_eq!(snapshot.fault, Some(WorkerFault::WorkerPanic));
        assert_eq!(snapshot.accepted, 2);
        assert_eq!(snapshot.failed, 2);
        Ok(())
    }

    #[test]
    fn dropped_reply_receiver_does_not_cancel_an_accepted_command() -> Result<(), RostlWorkerError>
    {
        let gate = Arc::new(Gate::default());
        let calls = Arc::new(Mutex::new(0));
        let worker = RostlWorker::spawn_backend(
            BlockingBackend {
                gate: Arc::clone(&gate),
                calls: Arc::clone(&calls),
                outcome: BlockingOutcome::Success,
            },
            queue_capacity(2),
        )?;
        let handle = worker.handle();
        let abandoned = handle.try_insert(7, fixed_event(7))?;
        gate.wait_until_entered();
        drop(abandoned);
        gate.release();
        assert_eq!(handle.try_read(7)?.wait()?, None);
        let snapshot = worker.shutdown()?;
        assert_accounting(snapshot);
        assert_eq!(snapshot.accepted, 2);
        assert_eq!(snapshot.completed, 2);
        assert_eq!(snapshot.reply_send_failed, 1);
        assert_eq!(
            *calls
                .lock()
                .expect("test call-count mutex must not be poisoned"),
            2
        );
        Ok(())
    }

    #[test]
    fn shutdown_drains_accepted_work_and_closes_cloned_handles() -> Result<(), RostlWorkerError> {
        let gate = Arc::new(Gate::default());
        let calls = Arc::new(Mutex::new(0));
        let worker = RostlWorker::spawn_backend(
            BlockingBackend {
                gate: Arc::clone(&gate),
                calls,
                outcome: BlockingOutcome::Success,
            },
            queue_capacity(1),
        )?;
        let handle = worker.handle();
        let first = handle.try_insert(1, fixed_event(1))?;
        gate.wait_until_entered();
        let second = handle.try_insert(2, fixed_event(2))?;
        let shutdown = thread::spawn(move || worker.shutdown());
        wait_for_lifecycle(&handle, WorkerLifecycle::Draining);
        gate.release();
        first.wait()?;
        second.wait()?;
        let snapshot = shutdown.join().expect("shutdown thread must not panic")?;
        assert_accounting(snapshot);
        assert_eq!(snapshot.lifecycle, WorkerLifecycle::Stopped);
        assert_eq!(snapshot.accepted, 2);
        assert_eq!(snapshot.completed, 2);
        assert!(matches!(
            handle.try_read(1),
            Err(RostlWorkerError::NotRunning)
        ));
        Ok(())
    }

    #[test]
    fn drop_closes_admission_and_joins_the_worker() -> Result<(), RostlWorkerError> {
        let observation = Arc::new(Mutex::new(Observation::default()));
        let worker =
            RostlWorker::spawn_backend(RecordingBackend::new(observation), queue_capacity(1))?;
        let handle = worker.handle();
        handle.try_insert(4, fixed_event(4))?.wait()?;
        drop(worker);
        assert!(matches!(
            handle.try_read(4),
            Err(RostlWorkerError::NotRunning)
        ));
        assert_eq!(handle.snapshot().lifecycle, WorkerLifecycle::Stopped);
        Ok(())
    }

    #[test]
    fn debug_and_telemetry_surfaces_remain_identifier_free() -> Result<(), RostlWorkerError> {
        let observation = Arc::new(Mutex::new(Observation::default()));
        let worker =
            RostlWorker::spawn_backend(RecordingBackend::new(observation), queue_capacity(1))?;
        let handle = worker.handle();
        let ticket = handle.try_insert(0x7171, fixed_event(0x71))?;
        assert_eq!(format!("{worker:?}"), "RostlWorker { ..REDACTED.. }");
        assert_eq!(format!("{handle:?}"), "RostlWorkerHandle { ..REDACTED.. }");
        assert_eq!(format!("{ticket:?}"), "RostlWorkerReply { ..REDACTED.. }");
        ticket.wait()?;
        assert_eq!(
            format!("{:?}", worker.snapshot()),
            "RostlWorkerSnapshot { queue_capacity: 1, queued: 0, in_flight: 0, queue_high_water: 1, accepted: 1, completed: 1, failed: 0, full_rejected: 0, not_running_rejected: 0, reply_send_failed: 0, lifecycle: Ready, fault: None }"
        );
        worker.shutdown()?;
        Ok(())
    }

    #[test]
    fn queue_capacity_is_checked_before_channel_allocation() {
        assert!(matches!(
            RostlQueueCapacity::try_new(0),
            Err(RostlWorkerError::InvalidQueueCapacity)
        ));
        assert!(RostlQueueCapacity::try_new(MAX_WORKER_QUEUE_CAPACITY).is_ok());
        assert!(matches!(
            RostlQueueCapacity::try_new(MAX_WORKER_QUEUE_CAPACITY + 1),
            Err(RostlWorkerError::InvalidQueueCapacity)
        ));
    }

    #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
    #[test]
    fn unsupported_host_rejects_real_worker_before_spawning() {
        assert!(matches!(
            RostlWorker::spawn(8, queue_capacity(1)),
            Err(RostlWorkerError::BackendUnavailable)
        ));
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn linux_candidate_is_send_and_round_trips_through_worker() -> Result<(), RostlWorkerError> {
        fn assert_send<T: Send>() {}
        static EVENT: OnceLock<PersistentUtxoEvent> = OnceLock::new();

        assert_send::<RostlCandidateStore>();
        let worker = RostlWorker::spawn(8, queue_capacity(2))?;
        let handle = worker.handle();
        let event = *EVENT.get_or_init(|| fixed_event(0x31));
        handle.try_insert(3, event)?.wait()?;
        assert_eq!(handle.try_read(3)?.wait()?, Some(event));
        worker.shutdown()?;
        Ok(())
    }
}
