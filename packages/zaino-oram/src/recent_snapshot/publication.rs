//! Fail-closed publication of immutable recent-state generations.
//!
//! The owner is deliberately a single-writer type: every state transition
//! requires exclusive access, while pinned leases retain immutable snapshots.
//! Beginning any update removes the active publication before validating or
//! building its replacement, so a query can perform a final current-generation
//! check immediately before returning a response to its eventual transport.

use std::{
    fmt,
    sync::{Arc, Mutex},
};

use arc_swap::ArcSwapOption;

#[cfg(feature = "corpus-zaino")]
use super::zaino::ConvertedRecentSnapshot;
use super::{
    content_digest, lineage_binding_digest, RecentSnapshotIdentity, RecentSnapshotReadError,
    RecentSnapshotSlot,
};
use crate::{
    records::AddressKey,
    store::{ObliviousStore, StoreSlot},
};
#[cfg(feature = "corpus-zaino")]
mod controller;
#[cfg(feature = "corpus-zaino")]
pub(crate) use controller::{CanonicalServingEpochCurrentness, RecentSnapshotRefreshController};

/// Lineage that distinguishes every immutable recent snapshot generation.
///
/// The finalized identity defines the exact seam with the protected projection.
/// The recent tip binds canonical chain freshness even when two generations have
/// identical transparent effects. Generations are monotonic within one owner
/// lifecycle and therefore prevent continuation-token ABA across an advance,
/// same-height reorg, or shortening reorg. A durable rebuild must roll the
/// projection epoch because this in-memory generation is not rollback proof.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct RecentSnapshotLineage {
    generation: u64,
    finalized: RecentSnapshotIdentity,
    recent_tip_height: u32,
    recent_tip_hash_display: [u8; 32],
}

impl RecentSnapshotLineage {
    fn new(
        generation: u64,
        finalized: RecentSnapshotIdentity,
        recent_tip_height: u32,
        recent_tip_hash_display: [u8; 32],
    ) -> Result<Self, RecentSnapshotLineageError> {
        if generation == 0 {
            return Err(RecentSnapshotLineageError::ZeroGeneration);
        }
        if recent_tip_height < finalized.finalized_height() {
            return Err(RecentSnapshotLineageError::RecentTipBelowFinalized);
        }
        if recent_tip_height == finalized.finalized_height()
            && recent_tip_hash_display != *finalized.finalized_hash_display()
        {
            return Err(RecentSnapshotLineageError::SeamTipHashMismatch);
        }
        Ok(Self {
            generation,
            finalized,
            recent_tip_height,
            recent_tip_hash_display,
        })
    }

    #[cfg(test)]
    pub(crate) fn from_parts_for_tests(
        generation: u64,
        finalized: RecentSnapshotIdentity,
        recent_tip_height: u32,
        recent_tip_hash_display: [u8; 32],
    ) -> Result<Self, RecentSnapshotLineageError> {
        Self::new(
            generation,
            finalized,
            recent_tip_height,
            recent_tip_hash_display,
        )
    }

    pub(crate) const fn generation(&self) -> u64 {
        self.generation
    }

    pub(crate) const fn finalized(&self) -> RecentSnapshotIdentity {
        self.finalized
    }

    pub(crate) const fn recent_tip_height(&self) -> u32 {
        self.recent_tip_height
    }

    pub(crate) const fn recent_tip_hash_display(&self) -> &[u8; 32] {
        &self.recent_tip_hash_display
    }
}

impl fmt::Debug for RecentSnapshotLineage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RecentSnapshotLineage { ..REDACTED.. }")
    }
}

/// A public recent-snapshot lineage is internally inconsistent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RecentSnapshotLineageError {
    ZeroGeneration,
    RecentTipBelowFinalized,
    SeamTipHashMismatch,
}

impl fmt::Display for RecentSnapshotLineageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroGeneration => f.write_str("recent snapshot generation is zero"),
            Self::RecentTipBelowFinalized => {
                f.write_str("recent snapshot tip is below the finalized seam")
            }
            Self::SeamTipHashMismatch => {
                f.write_str("empty recent snapshot tip does not match the finalized seam")
            }
        }
    }
}

impl std::error::Error for RecentSnapshotLineageError {}

/// Fixed, oldest-to-newest snapshot owned by one private runtime lifecycle.
pub(crate) struct FrozenRecentSnapshot<const N: usize> {
    lineage: RecentSnapshotLineage,
    slots: [RecentSnapshotSlot; N],
    content_digest: [u8; 32],
    binding_digest: [u8; 32],
    #[cfg(test)]
    failing_ordinal: Option<usize>,
    #[cfg(test)]
    read_calls: usize,
}

impl<const N: usize> Clone for FrozenRecentSnapshot<N> {
    fn clone(&self) -> Self {
        Self {
            lineage: self.lineage,
            slots: self.slots,
            content_digest: self.content_digest,
            binding_digest: self.binding_digest,
            #[cfg(test)]
            failing_ordinal: self.failing_ordinal,
            #[cfg(test)]
            // A clone is a fresh scan view of the same immutable generation.
            read_calls: 0,
        }
    }
}

impl<const N: usize> FrozenRecentSnapshot<N> {
    fn new(lineage: RecentSnapshotLineage, slots: [RecentSnapshotSlot; N]) -> Self {
        let content_digest = content_digest(&slots);
        let binding_digest = lineage_binding_digest(lineage, content_digest);
        Self {
            lineage,
            slots,
            content_digest,
            binding_digest,
            #[cfg(test)]
            failing_ordinal: None,
            #[cfg(test)]
            read_calls: 0,
        }
    }

    #[cfg(test)]
    pub(crate) fn from_parts_for_tests(
        lineage: RecentSnapshotLineage,
        slots: [RecentSnapshotSlot; N],
    ) -> Self {
        Self::new(lineage, slots)
    }

    #[cfg(test)]
    pub(crate) fn failing(
        lineage: RecentSnapshotLineage,
        slots: [RecentSnapshotSlot; N],
        failing_ordinal: usize,
    ) -> Self {
        let content_digest = content_digest(&slots);
        let binding_digest = lineage_binding_digest(lineage, content_digest);
        Self {
            lineage,
            slots,
            content_digest,
            binding_digest,
            failing_ordinal: Some(failing_ordinal),
            read_calls: 0,
        }
    }

    pub(crate) const fn slots(&self) -> usize {
        N
    }

    pub(crate) const fn identity(&self) -> RecentSnapshotIdentity {
        self.lineage.finalized
    }

    pub(crate) const fn lineage(&self) -> RecentSnapshotLineage {
        self.lineage
    }

    pub(crate) const fn content_digest(&self) -> [u8; 32] {
        self.content_digest
    }

    pub(crate) const fn binding_digest(&self) -> [u8; 32] {
        self.binding_digest
    }

    /// Reads one public slot without accepting any query-derived identifier.
    pub(crate) fn read_slot(
        &mut self,
        ordinal: usize,
    ) -> Result<RecentSnapshotSlot, RecentSnapshotReadError> {
        #[cfg(test)]
        {
            let calls = self.read_calls;
            let expected = calls.checked_rem(N).ok_or(RecentSnapshotReadError)?;
            if ordinal != expected || ordinal >= N {
                return Err(RecentSnapshotReadError);
            }
            self.read_calls = calls.checked_add(1).ok_or(RecentSnapshotReadError)?;
            if self.failing_ordinal == Some(ordinal) {
                return Err(RecentSnapshotReadError);
            }
        }
        self.slots
            .get(ordinal)
            .copied()
            .ok_or(RecentSnapshotReadError)
    }

    #[cfg(test)]
    pub(crate) const fn read_calls(&self) -> usize {
        self.read_calls
    }

    /// Simulates post-construction corruption without changing the bound digest.
    #[cfg(test)]
    pub(crate) fn replace_slot(&mut self, ordinal: usize, slot: RecentSnapshotSlot) {
        if let Some(destination) = self.slots.get_mut(ordinal) {
            *destination = slot;
        }
    }

    /// Simulates post-construction checkpoint-identity corruption.
    #[cfg(test)]
    pub(crate) fn replace_identity(&mut self, identity: RecentSnapshotIdentity) {
        self.lineage.finalized = identity;
    }

    /// Simulates post-construction generation or recent-tip corruption.
    #[cfg(test)]
    pub(crate) fn replace_lineage(&mut self, lineage: RecentSnapshotLineage) {
        self.lineage = lineage;
    }
}

/// Models the active immutable recent snapshot and its single-writer lineage.
struct RecentSnapshotPublicationOwner<const N: usize> {
    active: Arc<ArcSwapOption<FrozenRecentSnapshot<N>>>,
    finalized: Option<RecentSnapshotIdentity>,
    last_generation: u64,
    outstanding: Option<Arc<UpdateSeal>>,
}

impl<const N: usize> RecentSnapshotPublicationOwner<N> {
    /// Starts an in-memory generation sequence at one.
    ///
    /// A caller replacing this owner must roll the durable projection epoch;
    /// otherwise an identical first publication would reproduce its binding.
    fn new() -> Self {
        Self {
            active: Arc::new(ArcSwapOption::empty()),
            finalized: None,
            last_generation: 0,
            outstanding: None,
        }
    }

    /// Invalidates the active generation and reserves the next build ticket.
    ///
    /// Clearing occurs first, including for rejected updates. Once publication
    /// begins moving, callers must fail closed until a matching build activates.
    fn begin_update(
        &mut self,
        finalized: RecentSnapshotIdentity,
        recent_tip_height: u32,
        recent_tip_hash_display: [u8; 32],
    ) -> Result<RecentSnapshotUpdateTicket, RecentSnapshotPublicationError> {
        self.clear_publication();
        validate_finalized_transition(self.finalized, finalized)?;

        let generation = self
            .last_generation
            .checked_add(1)
            .ok_or(RecentSnapshotPublicationError::RebuildRequired)?;
        let lineage = RecentSnapshotLineage::new(
            generation,
            finalized,
            recent_tip_height,
            recent_tip_hash_display,
        )
        .map_err(|_| RecentSnapshotPublicationError::InvalidUpdate)?;

        let seal = Arc::new(UpdateSeal { lineage });
        self.finalized = Some(finalized);
        self.last_generation = generation;
        self.outstanding = Some(Arc::clone(&seal));
        Ok(RecentSnapshotUpdateTicket { seal })
    }

    /// Publishes synthetic slots only for the feature-independent owner tests.
    #[cfg(test)]
    fn activate(
        &mut self,
        ticket: RecentSnapshotUpdateTicket,
        slots: [RecentSnapshotSlot; N],
    ) -> Result<(), RecentSnapshotPublicationError> {
        let lineage = self.take_outstanding(&ticket)?;
        self.publish_with_lineage(lineage, slots);
        Ok(())
    }

    /// Publishes a converted candidate only when it matches the outstanding lineage.
    #[cfg(feature = "corpus-zaino")]
    fn activate_converted(
        &mut self,
        ticket: RecentSnapshotUpdateTicket,
        converted: ConvertedRecentSnapshot<N>,
    ) -> Result<(), RecentSnapshotPublicationError> {
        let lineage = self.take_outstanding(&ticket)?;
        if converted.finalized() != lineage.finalized()
            || converted.recent_tip_height() != lineage.recent_tip_height()
            || converted.recent_tip_hash_display() != lineage.recent_tip_hash_display()
        {
            return Err(RecentSnapshotPublicationError::InvalidUpdate);
        }

        self.publish_with_lineage(lineage, converted.into_slots());
        Ok(())
    }

    fn publish_with_lineage(
        &mut self,
        lineage: RecentSnapshotLineage,
        slots: [RecentSnapshotSlot; N],
    ) {
        let snapshot = Arc::new(FrozenRecentSnapshot::new(lineage, slots));
        self.active.store(Some(snapshot));
    }

    /// Records a failed build and consumes its outstanding capability.
    fn fail_update(
        &mut self,
        ticket: RecentSnapshotUpdateTicket,
    ) -> Result<(), RecentSnapshotPublicationError> {
        self.take_outstanding(&ticket)?;
        self.active.store(None);
        Ok(())
    }

    fn pin(&self) -> Option<RecentSnapshotLease<N>> {
        self.active.load_full().map(|snapshot| RecentSnapshotLease {
            active: Arc::clone(&self.active),
            snapshot,
        })
    }

    fn clear_publication(&mut self) {
        self.active.store(None);
        self.outstanding = None;
    }

    fn take_outstanding(
        &mut self,
        ticket: &RecentSnapshotUpdateTicket,
    ) -> Result<RecentSnapshotLineage, RecentSnapshotPublicationError> {
        let lineage = match self.outstanding.as_ref() {
            Some(outstanding) if Arc::ptr_eq(&ticket.seal, outstanding) => outstanding.lineage,
            _ => return Err(RecentSnapshotPublicationError::ActivationRejected),
        };
        self.outstanding = None;
        Ok(lineage)
    }
}

impl<const N: usize> Drop for RecentSnapshotPublicationOwner<N> {
    fn drop(&mut self) {
        self.active.store(None);
    }
}

impl<const N: usize> fmt::Debug for RecentSnapshotPublicationOwner<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RecentSnapshotPublicationOwner { ..REDACTED.. }")
    }
}

/// A pinned immutable generation retained across publication transitions.
struct RecentSnapshotLease<const N: usize> {
    active: Arc<ArcSwapOption<FrozenRecentSnapshot<N>>>,
    snapshot: Arc<FrozenRecentSnapshot<N>>,
}

impl<const N: usize> RecentSnapshotLease<N> {
    fn snapshot(&self) -> &FrozenRecentSnapshot<N> {
        &self.snapshot
    }

    /// Performs the final fail-closed generation check against the active Arc.
    fn is_current(&self) -> bool {
        self.active
            .load_full()
            .is_some_and(|active| Arc::ptr_eq(&self.snapshot, &active))
    }
}

impl<const N: usize> fmt::Debug for RecentSnapshotLease<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RecentSnapshotLease { ..REDACTED.. }")
    }
}

/// Opaque capture identity used to bind and re-observe one serving epoch.
///
/// Implementations must compare capture identity rather than only public field
/// equality so an equal-value ABA replacement is rejected.
pub(crate) trait ServingEpochBoundary: Clone {
    fn same_capture(&self, other: &Self) -> bool;
}

/// Query-independent currentness capability bound into one serving epoch.
///
/// Publication compares the capability's declared binding with the exact
/// finalized identity and opaque capture boundary being published. Returning
/// `None` fails publication closed rather than admitting an unbound observer.
pub(crate) trait ServingEpochCurrentness<B> {
    fn binding(&self) -> Option<(RecentSnapshotIdentity, &B)>;

    fn observe(&mut self) -> Result<ServingEpochObservation<B>, ServingEpochUnavailable>;
}

/// Immutable finalized projection generation eligible for epoch publication.
///
/// Implementations are issued by the finalized projection owner and must keep
/// the returned identity attached to the exact store generation they expose.
pub(crate) trait FinalizedServingStore: ObliviousStore {
    fn serving_identity(&self) -> RecentSnapshotIdentity;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ServingEpochUnavailable;

/// One response-release observation made after private query work completes.
pub(crate) struct ServingEpochObservation<B> {
    identity: RecentSnapshotIdentity,
    boundary: B,
    #[cfg(test)]
    after_comparison: Option<Box<dyn Fn()>>,
}

impl<B> ServingEpochObservation<B> {
    pub(crate) fn new(identity: RecentSnapshotIdentity, boundary: B) -> Self {
        Self {
            identity,
            boundary,
            #[cfg(test)]
            after_comparison: None,
        }
    }

    #[cfg(test)]
    pub(crate) fn with_after_comparison_for_tests(mut self, hook: impl Fn() + 'static) -> Self {
        self.after_comparison = Some(Box::new(hook));
        self
    }
}

impl<B> fmt::Debug for ServingEpochObservation<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ServingEpochObservation { ..REDACTED.. }")
    }
}

/// Single-writer publication of one atomic whole-serving-epoch binding.
struct ServingEpochPublicationOwner<const N: usize, B, S, C> {
    active: Arc<ArcSwapOption<ServingEpoch<N, B, S, C>>>,
}

impl<const N: usize, B, S, C> ServingEpochPublicationOwner<N, B, S, C> {
    fn new() -> Self {
        Self {
            active: Arc::new(ArcSwapOption::empty()),
        }
    }

    /// Publishes last, after validating the exact recent/finalized binding.
    fn publish(
        &mut self,
        recent: RecentSnapshotLease<N>,
        identity: RecentSnapshotIdentity,
        boundary: B,
        finalized_store: S,
        currentness: C,
    ) -> Result<(), RecentSnapshotPublicationError>
    where
        B: ServingEpochBoundary,
        S: FinalizedServingStore,
        C: ServingEpochCurrentness<B>,
    {
        self.clear();
        let Some((currentness_identity, currentness_boundary)) = currentness.binding() else {
            return Err(RecentSnapshotPublicationError::InvalidUpdate);
        };
        if !recent.is_current()
            || recent.snapshot().identity() != identity
            || finalized_store.serving_identity() != identity
            || currentness_identity != identity
            || !boundary.same_capture(currentness_boundary)
        {
            return Err(RecentSnapshotPublicationError::InvalidUpdate);
        }

        let epoch = compose_serving_epoch(recent, identity, boundary, finalized_store, currentness);
        if !epoch.recent.is_current() {
            return Err(RecentSnapshotPublicationError::InvalidUpdate);
        }
        self.active.store(Some(epoch));
        Ok(())
    }

    fn pin(&self) -> Option<ServingEpochLease<N, B, S, C>> {
        self.active.load_full().map(|epoch| ServingEpochLease {
            active: Arc::clone(&self.active),
            epoch,
        })
    }

    fn clear(&mut self) {
        self.active.store(None);
    }
}

impl<const N: usize, B, S, C> Drop for ServingEpochPublicationOwner<N, B, S, C> {
    fn drop(&mut self) {
        self.active.store(None);
    }
}

impl<const N: usize, B, S, C> fmt::Debug for ServingEpochPublicationOwner<N, B, S, C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ServingEpochPublicationOwner { ..REDACTED.. }")
    }
}

struct ServingEpoch<const N: usize, B, S, C> {
    recent: RecentSnapshotLease<N>,
    /// Exact network/checkpoint/schema/key identity. `projection_epoch` must
    /// roll whenever the finalized projection owner is rebuilt or replaced.
    identity: RecentSnapshotIdentity,
    boundary: B,
    finalized_store: Arc<Mutex<S>>,
    finalized_store_slots_per_key: usize,
    currentness: Arc<Mutex<C>>,
}

fn compose_serving_epoch<const N: usize, B, S, C>(
    recent: RecentSnapshotLease<N>,
    identity: RecentSnapshotIdentity,
    boundary: B,
    finalized_store: S,
    currentness: C,
) -> Arc<ServingEpoch<N, B, S, C>>
where
    S: ObliviousStore,
{
    let finalized_store_slots_per_key = finalized_store.slots_per_key();
    Arc::new(ServingEpoch {
        recent,
        identity,
        boundary,
        finalized_store: Arc::new(Mutex::new(finalized_store)),
        finalized_store_slots_per_key,
        currentness: Arc::new(Mutex::new(currentness)),
    })
}

/// A pinned whole-serving-epoch binding retained for one private query.
pub(crate) struct ServingEpochLease<const N: usize, B, S, C> {
    active: Arc<ArcSwapOption<ServingEpoch<N, B, S, C>>>,
    epoch: Arc<ServingEpoch<N, B, S, C>>,
}

impl<const N: usize, B, S, C> ServingEpochLease<N, B, S, C> {
    pub(crate) fn snapshot(&self) -> &FrozenRecentSnapshot<N> {
        self.epoch.recent.snapshot()
    }

    pub(crate) fn identity(&self) -> RecentSnapshotIdentity {
        self.epoch.identity
    }

    pub(crate) fn finalized_store(&self) -> ServingEpochStore<S> {
        ServingEpochStore {
            inner: Arc::clone(&self.epoch.finalized_store),
            slots_per_key: self.epoch.finalized_store_slots_per_key,
        }
    }

    fn local_binding_is_current(&self) -> bool {
        self.active
            .load_full()
            .is_some_and(|active| Arc::ptr_eq(&self.epoch, &active))
            && self.epoch.recent.is_current()
            && self.epoch.recent.snapshot().identity() == self.epoch.identity
    }

    #[cfg(test)]
    pub(crate) fn invalidator_for_tests(&self) -> ServingEpochInvalidator<N, B, S, C> {
        ServingEpochInvalidator {
            active: Arc::clone(&self.active),
            recent_active: Arc::clone(&self.epoch.recent.active),
        }
    }

    #[cfg(test)]
    pub(crate) fn with_currentness_for_tests<T>(
        &self,
        inspect: impl FnOnce(&mut C) -> T,
    ) -> Option<T> {
        self.epoch
            .currentness
            .lock()
            .ok()
            .map(|mut currentness| inspect(&mut currentness))
    }
}

impl<const N: usize, B: ServingEpochBoundary, S, C> ServingEpochLease<N, B, S, C> {
    /// Checks the atomic epoch and recent Arc both before and after comparing
    /// the response-release observation. The second check rejects a refresh
    /// that races the otherwise-current observation.
    pub(crate) fn is_current(&self, observation: &ServingEpochObservation<B>) -> bool {
        if !self.local_binding_is_current() {
            return false;
        }
        let observation_matches = self.epoch.identity == observation.identity
            && self.epoch.boundary.same_capture(&observation.boundary);
        #[cfg(test)]
        if let Some(hook) = observation.after_comparison.as_ref() {
            hook();
        }
        observation_matches && self.local_binding_is_current()
    }
}

impl<const N: usize, B, S, C> ServingEpochLease<N, B, S, C>
where
    C: ServingEpochCurrentness<B>,
{
    pub(crate) fn observe_current(
        &self,
    ) -> Result<ServingEpochObservation<B>, ServingEpochUnavailable> {
        let mut currentness = self
            .epoch
            .currentness
            .lock()
            .map_err(|_| ServingEpochUnavailable)?;
        currentness.observe()
    }
}

impl<const N: usize, B, S, C> fmt::Debug for ServingEpochLease<N, B, S, C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ServingEpochLease { ..REDACTED.. }")
    }
}

/// The finalized store generation owned by one serving-epoch lease.
///
/// The wrapper prevents runtime construction from injecting a store that was
/// not published in the same atomic epoch as the recent snapshot and boundary.
pub(crate) struct ServingEpochStore<S> {
    inner: Arc<Mutex<S>>,
    slots_per_key: usize,
}

impl<S> Clone for ServingEpochStore<S> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            slots_per_key: self.slots_per_key,
        }
    }
}

impl<S: ObliviousStore> ObliviousStore for ServingEpochStore<S> {
    type Error = ServingEpochStoreUnavailable;

    fn slots_per_key(&self) -> usize {
        self.slots_per_key
    }

    fn read_slot(
        &mut self,
        address_key: &AddressKey,
        slot: usize,
    ) -> Result<StoreSlot, Self::Error> {
        let mut store = self
            .inner
            .lock()
            .map_err(|_| ServingEpochStoreUnavailable)?;
        store
            .read_slot(address_key, slot)
            .map_err(|_| ServingEpochStoreUnavailable)
    }
}

impl<S> fmt::Debug for ServingEpochStore<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ServingEpochStore { ..REDACTED.. }")
    }
}

impl<S> ServingEpochStore<S> {
    #[cfg(test)]
    pub(crate) fn inspect_for_tests<T>(&self, inspect: impl FnOnce(&S) -> T) -> Option<T> {
        self.inner.lock().ok().map(|store| inspect(&store))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ServingEpochStoreUnavailable;

#[cfg(test)]
pub(crate) struct ServingEpochInvalidator<const N: usize, B, S, C> {
    active: Arc<ArcSwapOption<ServingEpoch<N, B, S, C>>>,
    recent_active: Arc<ArcSwapOption<FrozenRecentSnapshot<N>>>,
}

#[cfg(test)]
impl<const N: usize, B, S, C> ServingEpochInvalidator<N, B, S, C> {
    pub(crate) fn clear_epoch(&self) {
        self.active.store(None);
    }

    fn clear_recent(&self) {
        self.recent_active.store(None);
    }
}

#[cfg(test)]
impl<const N: usize, B, S, C> fmt::Debug for ServingEpochInvalidator<N, B, S, C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ServingEpochInvalidator { ..REDACTED.. }")
    }
}

#[cfg(test)]
pub(crate) fn serving_epoch_for_tests<const N: usize, B, S, C>(
    snapshot: FrozenRecentSnapshot<N>,
    boundary: B,
    finalized_store: S,
    currentness: C,
) -> ServingEpochLease<N, B, S, C>
where
    S: ObliviousStore,
{
    let snapshot = Arc::new(snapshot);
    let recent_active = Arc::new(ArcSwapOption::from(Some(Arc::clone(&snapshot))));
    let recent = RecentSnapshotLease {
        active: recent_active,
        snapshot,
    };
    let identity = recent.snapshot().identity();
    let epoch = compose_serving_epoch(recent, identity, boundary, finalized_store, currentness);
    let active = Arc::new(ArcSwapOption::from(Some(Arc::clone(&epoch))));
    ServingEpochLease { active, epoch }
}

/// Unforgeable capability for exactly one outstanding snapshot build.
struct RecentSnapshotUpdateTicket {
    seal: Arc<UpdateSeal>,
}

impl fmt::Debug for RecentSnapshotUpdateTicket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RecentSnapshotUpdateTicket { ..REDACTED.. }")
    }
}

struct UpdateSeal {
    lineage: RecentSnapshotLineage,
}

/// Fail-closed publication rejection without checkpoint or generation details.
#[derive(Clone, Copy, PartialEq, Eq)]
enum RecentSnapshotPublicationError {
    RebuildRequired,
    InvalidUpdate,
    ActivationRejected,
}

impl fmt::Debug for RecentSnapshotPublicationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RecentSnapshotPublicationError { ..REDACTED.. }")
    }
}

impl fmt::Display for RecentSnapshotPublicationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RebuildRequired => f.write_str("recent snapshot rebuild required"),
            Self::InvalidUpdate => f.write_str("recent snapshot update rejected"),
            Self::ActivationRejected => f.write_str("recent snapshot activation rejected"),
        }
    }
}

impl std::error::Error for RecentSnapshotPublicationError {}

fn validate_finalized_transition(
    current: Option<RecentSnapshotIdentity>,
    proposed: RecentSnapshotIdentity,
) -> Result<(), RecentSnapshotPublicationError> {
    let Some(current) = current else {
        return Ok(());
    };

    if current.network_tag() != proposed.network_tag()
        || current.schema_version() != proposed.schema_version()
        || current.projection_epoch() != proposed.projection_epoch()
        || current.key_epoch() != proposed.key_epoch()
        || proposed.finalized_height() < current.finalized_height()
        || (proposed.finalized_height() == current.finalized_height()
            && proposed.finalized_hash_display() != current.finalized_hash_display())
    {
        return Err(RecentSnapshotPublicationError::RebuildRequired);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "corpus-zaino")]
    use super::super::zaino::ConvertedRecentSnapshot;
    use super::*;
    #[cfg(feature = "corpus-zaino")]
    use crate::records::{AddressKey, TransparentUtxo, ADDRESS_KEY_BYTES};

    const FINALIZED_HASH: [u8; 32] = [0x11; 32];
    const ADVANCED_FINALIZED_HASH: [u8; 32] = [0x12; 32];
    const TIP_HASH_A: [u8; 32] = [0x21; 32];
    const TIP_HASH_B: [u8; 32] = [0x22; 32];
    const TIP_HASH_C: [u8; 32] = [0x23; 32];
    const SLOT_COUNT: usize = 2;

    type TestOwner = RecentSnapshotPublicationOwner<SLOT_COUNT>;
    type TestServingOwner =
        ServingEpochPublicationOwner<SLOT_COUNT, TestBoundary, TestFinalizedStore, TestCurrentness>;
    type TestServingLease =
        ServingEpochLease<SLOT_COUNT, TestBoundary, TestFinalizedStore, TestCurrentness>;
    type ActivatedServingEpoch = (TestOwner, TestServingOwner, TestServingLease, TestBoundary);

    struct TestFinalizedStore {
        generation: u8,
        identity: RecentSnapshotIdentity,
    }

    impl TestFinalizedStore {
        const fn new(generation: u8, identity: RecentSnapshotIdentity) -> Self {
            Self {
                generation,
                identity,
            }
        }
    }

    impl ObliviousStore for TestFinalizedStore {
        type Error = ();

        fn slots_per_key(&self) -> usize {
            4
        }

        fn read_slot(
            &mut self,
            _address_key: &AddressKey,
            _slot: usize,
        ) -> Result<StoreSlot, Self::Error> {
            Ok(StoreSlot::dummy())
        }
    }

    impl FinalizedServingStore for TestFinalizedStore {
        fn serving_identity(&self) -> RecentSnapshotIdentity {
            self.identity
        }
    }

    #[derive(Clone)]
    struct TestBoundary {
        capture: u8,
        revision: Arc<()>,
    }

    impl TestBoundary {
        fn new() -> Self {
            Self {
                capture: 7,
                revision: Arc::new(()),
            }
        }

        fn replacement(&self) -> Self {
            Self {
                capture: self.capture,
                revision: Arc::new(()),
            }
        }
    }

    impl ServingEpochBoundary for TestBoundary {
        fn same_capture(&self, other: &Self) -> bool {
            self.capture == other.capture && Arc::ptr_eq(&self.revision, &other.revision)
        }
    }

    struct TestCurrentness {
        identity: RecentSnapshotIdentity,
        boundary: TestBoundary,
    }

    impl ServingEpochCurrentness<TestBoundary> for TestCurrentness {
        fn binding(&self) -> Option<(RecentSnapshotIdentity, &TestBoundary)> {
            Some((self.identity, &self.boundary))
        }

        fn observe(
            &mut self,
        ) -> Result<ServingEpochObservation<TestBoundary>, ServingEpochUnavailable> {
            Ok(ServingEpochObservation::new(
                self.identity,
                self.boundary.clone(),
            ))
        }
    }

    fn identity(height: u32, hash: [u8; 32]) -> RecentSnapshotIdentity {
        identity_at_epoch(height, hash, 7)
    }

    fn identity_at_epoch(
        height: u32,
        hash: [u8; 32],
        projection_epoch: u64,
    ) -> RecentSnapshotIdentity {
        RecentSnapshotIdentity::new(0, height, hash, 1, projection_epoch, 9)
    }

    fn slots() -> [RecentSnapshotSlot; SLOT_COUNT] {
        [RecentSnapshotSlot::dummy(); SLOT_COUNT]
    }

    fn activated_owner() -> Result<TestOwner, RecentSnapshotPublicationError> {
        let mut owner = TestOwner::new();
        let ticket = owner.begin_update(identity(100, FINALIZED_HASH), 102, TIP_HASH_A)?;
        owner.activate(ticket, slots())?;
        Ok(owner)
    }

    fn activated_serving_epoch() -> Result<ActivatedServingEpoch, RecentSnapshotPublicationError> {
        let owner = activated_owner()?;
        let recent = owner
            .pin()
            .ok_or(RecentSnapshotPublicationError::ActivationRejected)?;
        let boundary = TestBoundary::new();
        let finalized = identity(100, FINALIZED_HASH);
        let mut serving = ServingEpochPublicationOwner::new();
        serving.publish(
            recent,
            finalized,
            boundary.clone(),
            TestFinalizedStore::new(17, finalized),
            TestCurrentness {
                identity: finalized,
                boundary: boundary.clone(),
            },
        )?;
        let lease = serving
            .pin()
            .ok_or(RecentSnapshotPublicationError::ActivationRejected)?;
        Ok((owner, serving, lease, boundary))
    }

    fn assert_currentness_binding_rejected(
        currentness_identity: RecentSnapshotIdentity,
        published_boundary: TestBoundary,
        currentness_boundary: TestBoundary,
    ) -> Result<(), RecentSnapshotPublicationError> {
        let owner = activated_owner()?;
        let recent = owner
            .pin()
            .ok_or(RecentSnapshotPublicationError::ActivationRejected)?;
        let current_identity = identity(100, FINALIZED_HASH);
        let mut serving = ServingEpochPublicationOwner::new();

        assert_eq!(
            serving.publish(
                recent,
                current_identity,
                published_boundary,
                TestFinalizedStore::new(17, current_identity),
                TestCurrentness {
                    identity: currentness_identity,
                    boundary: currentness_boundary,
                },
            ),
            Err(RecentSnapshotPublicationError::InvalidUpdate)
        );
        assert!(serving.pin().is_none());
        Ok(())
    }

    #[test]
    fn serving_epoch_binds_exact_finalized_recent_and_boundary_identity(
    ) -> Result<(), RecentSnapshotPublicationError> {
        let (_owner, _serving, lease, boundary) = activated_serving_epoch()?;
        let exact = ServingEpochObservation::new(lease.identity(), boundary.clone());
        assert!(lease.is_current(&exact));
        let owner_observation = lease
            .observe_current()
            .map_err(|_| RecentSnapshotPublicationError::InvalidUpdate)?;
        assert!(lease.is_current(&owner_observation));
        assert_eq!(
            lease
                .finalized_store()
                .inspect_for_tests(|store| store.generation),
            Some(17)
        );

        let current = lease.identity();
        let mismatched_finalized_or_projection_identities = [
            RecentSnapshotIdentity::new(
                current.network_tag() ^ 1,
                current.finalized_height(),
                *current.finalized_hash_display(),
                current.schema_version(),
                current.projection_epoch(),
                current.key_epoch(),
            ),
            RecentSnapshotIdentity::new(
                current.network_tag(),
                current.finalized_height() + 1,
                *current.finalized_hash_display(),
                current.schema_version(),
                current.projection_epoch(),
                current.key_epoch(),
            ),
            RecentSnapshotIdentity::new(
                current.network_tag(),
                current.finalized_height(),
                ADVANCED_FINALIZED_HASH,
                current.schema_version(),
                current.projection_epoch(),
                current.key_epoch(),
            ),
            RecentSnapshotIdentity::new(
                current.network_tag(),
                current.finalized_height(),
                *current.finalized_hash_display(),
                current.schema_version() + 1,
                current.projection_epoch(),
                current.key_epoch(),
            ),
            RecentSnapshotIdentity::new(
                current.network_tag(),
                current.finalized_height(),
                *current.finalized_hash_display(),
                current.schema_version(),
                current.projection_epoch() + 1,
                current.key_epoch(),
            ),
            RecentSnapshotIdentity::new(
                current.network_tag(),
                current.finalized_height(),
                *current.finalized_hash_display(),
                current.schema_version(),
                current.projection_epoch(),
                current.key_epoch() + 1,
            ),
        ];
        for mismatched in mismatched_finalized_or_projection_identities {
            let observation = ServingEpochObservation::new(mismatched, boundary.clone());
            assert!(!lease.is_current(&observation));
        }

        let equal_value_replacement =
            ServingEpochObservation::new(lease.identity(), boundary.replacement());
        assert!(!lease.is_current(&equal_value_replacement));
        Ok(())
    }

    #[test]
    fn serving_epoch_rejects_a_store_issued_for_another_identity(
    ) -> Result<(), RecentSnapshotPublicationError> {
        let owner = activated_owner()?;
        let recent = owner
            .pin()
            .ok_or(RecentSnapshotPublicationError::ActivationRejected)?;
        let boundary = TestBoundary::new();
        let current_identity = identity(100, FINALIZED_HASH);
        let mut serving = ServingEpochPublicationOwner::new();

        assert_eq!(
            serving.publish(
                recent,
                current_identity,
                boundary.clone(),
                TestFinalizedStore::new(17, identity(101, ADVANCED_FINALIZED_HASH)),
                TestCurrentness {
                    identity: current_identity,
                    boundary,
                },
            ),
            Err(RecentSnapshotPublicationError::InvalidUpdate)
        );
        assert!(serving.pin().is_none());
        Ok(())
    }

    #[test]
    fn serving_epoch_rejects_mismatched_currentness_binding(
    ) -> Result<(), RecentSnapshotPublicationError> {
        let boundary = TestBoundary::new();
        assert_currentness_binding_rejected(
            identity(101, ADVANCED_FINALIZED_HASH),
            boundary.clone(),
            boundary.clone(),
        )?;
        assert_currentness_binding_rejected(
            identity(100, FINALIZED_HASH),
            boundary.clone(),
            boundary.replacement(),
        )
    }

    #[test]
    fn serving_epoch_second_check_rejects_refresh_after_observation(
    ) -> Result<(), RecentSnapshotPublicationError> {
        let (_owner, _serving, lease, boundary) = activated_serving_epoch()?;
        let invalidator = lease.invalidator_for_tests();
        let observation = ServingEpochObservation::new(lease.identity(), boundary)
            .with_after_comparison_for_tests(move || invalidator.clear_epoch());

        assert!(!lease.is_current(&observation));
        Ok(())
    }

    #[test]
    fn serving_epoch_rejects_recent_invalidation_and_clears_atomically(
    ) -> Result<(), RecentSnapshotPublicationError> {
        let (_owner, _serving, recent_invalidated, boundary) = activated_serving_epoch()?;
        let observation =
            ServingEpochObservation::new(recent_invalidated.identity(), boundary.clone());
        recent_invalidated.invalidator_for_tests().clear_recent();
        assert!(!recent_invalidated.is_current(&observation));

        let (_owner, mut serving, epoch_invalidated, boundary) = activated_serving_epoch()?;
        let observation = ServingEpochObservation::new(epoch_invalidated.identity(), boundary);
        serving.clear();
        assert!(!epoch_invalidated.is_current(&observation));
        Ok(())
    }

    #[test]
    fn dropping_recent_owner_invalidates_recent_lease() -> Result<(), RecentSnapshotPublicationError>
    {
        let lease = {
            let owner = activated_owner()?;
            owner
                .pin()
                .ok_or(RecentSnapshotPublicationError::ActivationRejected)?
        };

        assert!(!lease.is_current());
        Ok(())
    }

    #[test]
    fn dropping_serving_owner_invalidates_serving_lease(
    ) -> Result<(), RecentSnapshotPublicationError> {
        let (_owner, serving, lease, boundary) = activated_serving_epoch()?;
        let observation = ServingEpochObservation::new(lease.identity(), boundary);

        drop(serving);

        assert!(!lease.is_current(&observation));
        Ok(())
    }

    #[test]
    fn dropping_recent_owner_invalidates_serving_lease(
    ) -> Result<(), RecentSnapshotPublicationError> {
        let (owner, _serving, lease, boundary) = activated_serving_epoch()?;
        let observation = ServingEpochObservation::new(lease.identity(), boundary);

        drop(owner);

        assert!(!lease.is_current(&observation));
        Ok(())
    }

    #[cfg(feature = "corpus-zaino")]
    fn converted_candidate(
        finalized: RecentSnapshotIdentity,
        recent_tip_height: u32,
        recent_tip_hash_display: [u8; 32],
    ) -> ConvertedRecentSnapshot<SLOT_COUNT> {
        converted_candidate_with_slots(
            finalized,
            recent_tip_height,
            recent_tip_hash_display,
            slots(),
        )
    }

    #[cfg(feature = "corpus-zaino")]
    fn converted_candidate_with_slots(
        finalized: RecentSnapshotIdentity,
        recent_tip_height: u32,
        recent_tip_hash_display: [u8; 32],
        slots: [RecentSnapshotSlot; SLOT_COUNT],
    ) -> ConvertedRecentSnapshot<SLOT_COUNT> {
        ConvertedRecentSnapshot::from_parts_for_tests(
            finalized,
            recent_tip_height,
            recent_tip_hash_display,
            slots,
        )
    }

    #[cfg(feature = "corpus-zaino")]
    fn occupied_slots() -> [RecentSnapshotSlot; SLOT_COUNT] {
        let utxo = TransparentUtxo::new([0x41; 32], 3, 75, 101, &[0x51])
            .expect("publication fixture script fits the fixed transparent record");
        [
            RecentSnapshotSlot::created(AddressKey::new([0x42; ADDRESS_KEY_BYTES]), utxo),
            RecentSnapshotSlot::dummy(),
        ]
    }

    #[cfg(feature = "corpus-zaino")]
    #[test]
    fn converted_candidate_activates_with_owner_assigned_lineage(
    ) -> Result<(), RecentSnapshotPublicationError> {
        let finalized = identity(100, FINALIZED_HASH);
        let mut owner = TestOwner::new();
        let ticket = owner.begin_update(finalized, 102, TIP_HASH_A)?;

        owner.activate_converted(ticket, converted_candidate(finalized, 102, TIP_HASH_A))?;

        let lease = owner
            .pin()
            .ok_or(RecentSnapshotPublicationError::ActivationRejected)?;
        let snapshot = lease.snapshot();
        assert_eq!(snapshot.lineage().generation(), 1);
        assert_eq!(snapshot.identity(), finalized);
        assert_eq!(snapshot.lineage().recent_tip_height(), 102);
        assert_eq!(snapshot.lineage().recent_tip_hash_display(), &TIP_HASH_A);
        assert_eq!(
            snapshot.content_digest(),
            super::super::content_digest(&slots())
        );
        assert_eq!(
            snapshot.binding_digest(),
            super::super::lineage_binding_digest(snapshot.lineage(), snapshot.content_digest())
        );
        assert!(lease.is_current());
        Ok(())
    }

    #[cfg(feature = "corpus-zaino")]
    #[test]
    fn converted_candidate_must_match_every_ticket_lineage_field(
    ) -> Result<(), RecentSnapshotPublicationError> {
        let finalized = identity(100, FINALIZED_HASH);
        let mismatches = [
            (
                RecentSnapshotIdentity::new(1, 100, FINALIZED_HASH, 1, 7, 9),
                102,
                TIP_HASH_A,
            ),
            (identity(99, FINALIZED_HASH), 102, TIP_HASH_A),
            (identity(100, ADVANCED_FINALIZED_HASH), 102, TIP_HASH_A),
            (
                RecentSnapshotIdentity::new(0, 100, FINALIZED_HASH, 2, 7, 9),
                102,
                TIP_HASH_A,
            ),
            (
                RecentSnapshotIdentity::new(0, 100, FINALIZED_HASH, 1, 8, 9),
                102,
                TIP_HASH_A,
            ),
            (
                RecentSnapshotIdentity::new(0, 100, FINALIZED_HASH, 1, 7, 10),
                102,
                TIP_HASH_A,
            ),
            (finalized, 103, TIP_HASH_A),
            (finalized, 102, TIP_HASH_B),
        ];

        for (candidate_finalized, candidate_tip_height, candidate_tip_hash) in mismatches {
            let mut owner = TestOwner::new();
            let ticket = owner.begin_update(finalized, 102, TIP_HASH_A)?;
            assert_eq!(
                owner.activate_converted(
                    ticket,
                    converted_candidate(
                        candidate_finalized,
                        candidate_tip_height,
                        candidate_tip_hash,
                    ),
                ),
                Err(RecentSnapshotPublicationError::InvalidUpdate)
            );
            assert!(owner.pin().is_none());
            assert!(owner.outstanding.is_none());

            let retry = owner.begin_update(finalized, 102, TIP_HASH_A)?;
            owner.activate_converted(retry, converted_candidate(finalized, 102, TIP_HASH_A))?;
            let lease = owner
                .pin()
                .ok_or(RecentSnapshotPublicationError::ActivationRejected)?;
            assert_eq!(lease.snapshot().lineage().generation(), 2);
        }
        Ok(())
    }

    #[cfg(feature = "corpus-zaino")]
    #[test]
    fn stale_converted_candidate_preserves_newer_outstanding_update(
    ) -> Result<(), RecentSnapshotPublicationError> {
        let finalized = identity(100, FINALIZED_HASH);
        for (candidate_tip_height, candidate_tip_hash) in [(101, TIP_HASH_A), (102, TIP_HASH_B)] {
            let mut owner = TestOwner::new();
            let stale = owner.begin_update(finalized, 101, TIP_HASH_A)?;
            let current = owner.begin_update(finalized, 102, TIP_HASH_B)?;

            assert_eq!(
                owner.activate_converted(
                    stale,
                    converted_candidate(finalized, candidate_tip_height, candidate_tip_hash),
                ),
                Err(RecentSnapshotPublicationError::ActivationRejected)
            );
            assert!(owner.pin().is_none());

            owner.activate_converted(current, converted_candidate(finalized, 102, TIP_HASH_B))?;
            let lease = owner
                .pin()
                .ok_or(RecentSnapshotPublicationError::ActivationRejected)?;
            assert_eq!(lease.snapshot().lineage().generation(), 2);
            assert!(lease.is_current());
        }
        Ok(())
    }

    #[cfg(feature = "corpus-zaino")]
    #[test]
    fn converted_candidate_content_is_bound_under_identical_public_metadata(
    ) -> Result<(), RecentSnapshotPublicationError> {
        let finalized = identity(100, FINALIZED_HASH);
        let mut owner = TestOwner::new();
        let first_ticket = owner.begin_update(finalized, 102, TIP_HASH_A)?;
        owner.activate_converted(
            first_ticket,
            converted_candidate(finalized, 102, TIP_HASH_A),
        )?;
        let first = owner
            .pin()
            .ok_or(RecentSnapshotPublicationError::ActivationRejected)?;

        let second_ticket = owner.begin_update(finalized, 102, TIP_HASH_A)?;
        owner.activate_converted(
            second_ticket,
            converted_candidate_with_slots(finalized, 102, TIP_HASH_A, occupied_slots()),
        )?;
        let second = owner
            .pin()
            .ok_or(RecentSnapshotPublicationError::ActivationRejected)?;

        assert_ne!(
            first.snapshot().content_digest(),
            second.snapshot().content_digest()
        );
        assert_ne!(
            first.snapshot().binding_digest(),
            second.snapshot().binding_digest()
        );
        assert!(!first.is_current());
        assert!(second.is_current());
        Ok(())
    }

    #[cfg(feature = "corpus-zaino")]
    #[test]
    fn identical_converted_contents_receive_distinct_generation_bindings(
    ) -> Result<(), RecentSnapshotPublicationError> {
        let finalized = identity(100, FINALIZED_HASH);
        let mut owner = TestOwner::new();
        let first_ticket = owner.begin_update(finalized, 102, TIP_HASH_A)?;
        owner.activate_converted(
            first_ticket,
            converted_candidate(finalized, 102, TIP_HASH_A),
        )?;
        let first = owner
            .pin()
            .ok_or(RecentSnapshotPublicationError::ActivationRejected)?;

        let second_ticket = owner.begin_update(finalized, 102, TIP_HASH_A)?;
        owner.activate_converted(
            second_ticket,
            converted_candidate(finalized, 102, TIP_HASH_A),
        )?;
        let second = owner
            .pin()
            .ok_or(RecentSnapshotPublicationError::ActivationRejected)?;

        assert_eq!(
            first.snapshot().content_digest(),
            second.snapshot().content_digest()
        );
        assert_ne!(
            first.snapshot().lineage().generation(),
            second.snapshot().lineage().generation()
        );
        assert_ne!(
            first.snapshot().binding_digest(),
            second.snapshot().binding_digest()
        );
        assert!(!first.is_current());
        assert!(second.is_current());
        Ok(())
    }

    #[test]
    fn initial_and_updated_generations_activate() -> Result<(), RecentSnapshotPublicationError> {
        let mut owner = TestOwner::new();
        assert!(owner.pin().is_none());

        let initial = owner.begin_update(identity(100, FINALIZED_HASH), 101, TIP_HASH_A)?;
        assert!(owner.pin().is_none());
        owner.activate(initial, slots())?;
        let first = owner
            .pin()
            .ok_or(RecentSnapshotPublicationError::ActivationRejected)?;
        assert_eq!(first.snapshot().lineage().generation(), 1);
        assert!(first.is_current());

        let updated = owner.begin_update(identity(100, FINALIZED_HASH), 102, TIP_HASH_B)?;
        owner.activate(updated, slots())?;
        let second = owner
            .pin()
            .ok_or(RecentSnapshotPublicationError::ActivationRejected)?;
        assert_eq!(second.snapshot().lineage().generation(), 2);
        assert!(second.is_current());
        assert!(!first.is_current());
        Ok(())
    }

    #[test]
    fn begin_immediately_invalidates_a_pinned_lease() -> Result<(), RecentSnapshotPublicationError>
    {
        let mut owner = activated_owner()?;
        let lease = owner
            .pin()
            .ok_or(RecentSnapshotPublicationError::ActivationRejected)?;

        let _ticket = owner.begin_update(identity(100, FINALIZED_HASH), 103, TIP_HASH_B)?;

        assert!(owner.pin().is_none());
        assert!(!lease.is_current());
        Ok(())
    }

    #[test]
    fn advances_and_reorgs_publish_new_bindings_for_identical_content(
    ) -> Result<(), RecentSnapshotPublicationError> {
        let mut owner = TestOwner::new();
        let first_ticket = owner.begin_update(identity(100, FINALIZED_HASH), 102, TIP_HASH_A)?;
        owner.activate(first_ticket, slots())?;
        let first = owner
            .pin()
            .ok_or(RecentSnapshotPublicationError::ActivationRejected)?;
        let content = first.snapshot().content_digest();
        let first_binding = first.snapshot().binding_digest();

        let advance_ticket = owner.begin_update(identity(100, FINALIZED_HASH), 103, TIP_HASH_A)?;
        owner.activate(advance_ticket, slots())?;
        let advanced = owner
            .pin()
            .ok_or(RecentSnapshotPublicationError::ActivationRejected)?;
        assert_eq!(advanced.snapshot().content_digest(), content);
        assert_ne!(advanced.snapshot().binding_digest(), first_binding);

        let same_height_reorg =
            owner.begin_update(identity(100, FINALIZED_HASH), 103, TIP_HASH_B)?;
        owner.activate(same_height_reorg, slots())?;
        let reorged = owner
            .pin()
            .ok_or(RecentSnapshotPublicationError::ActivationRejected)?;
        assert_eq!(reorged.snapshot().content_digest(), content);
        assert_ne!(
            reorged.snapshot().binding_digest(),
            advanced.snapshot().binding_digest()
        );

        let shortening_reorg =
            owner.begin_update(identity(100, FINALIZED_HASH), 101, TIP_HASH_C)?;
        owner.activate(shortening_reorg, slots())?;
        let shortened = owner
            .pin()
            .ok_or(RecentSnapshotPublicationError::ActivationRejected)?;
        assert_eq!(shortened.snapshot().content_digest(), content);
        assert_ne!(
            shortened.snapshot().binding_digest(),
            reorged.snapshot().binding_digest()
        );
        Ok(())
    }

    #[test]
    fn stale_ticket_rejection_preserves_the_outstanding_update(
    ) -> Result<(), RecentSnapshotPublicationError> {
        let mut owner = TestOwner::new();
        let stale = owner.begin_update(identity(100, FINALIZED_HASH), 101, TIP_HASH_A)?;
        let current = owner.begin_update(identity(100, FINALIZED_HASH), 102, TIP_HASH_B)?;

        assert_eq!(
            owner.activate(stale, slots()),
            Err(RecentSnapshotPublicationError::ActivationRejected)
        );
        assert!(owner.pin().is_none());
        owner.activate(current, slots())?;
        let lease = owner
            .pin()
            .ok_or(RecentSnapshotPublicationError::ActivationRejected)?;
        assert_eq!(lease.snapshot().lineage().generation(), 2);
        assert!(lease.is_current());
        Ok(())
    }

    #[test]
    fn stale_completion_cannot_unpublish_the_current_generation(
    ) -> Result<(), RecentSnapshotPublicationError> {
        let mut activation_owner = TestOwner::new();
        let stale_activation =
            activation_owner.begin_update(identity(100, FINALIZED_HASH), 101, TIP_HASH_A)?;
        let current_activation =
            activation_owner.begin_update(identity(100, FINALIZED_HASH), 102, TIP_HASH_B)?;
        activation_owner.activate(current_activation, slots())?;
        let activated_lease = activation_owner
            .pin()
            .ok_or(RecentSnapshotPublicationError::ActivationRejected)?;

        assert_eq!(
            activation_owner.activate(stale_activation, slots()),
            Err(RecentSnapshotPublicationError::ActivationRejected)
        );
        assert!(activated_lease.is_current());

        let mut failure_owner = TestOwner::new();
        let stale_failure =
            failure_owner.begin_update(identity(100, FINALIZED_HASH), 101, TIP_HASH_A)?;
        let current_activation =
            failure_owner.begin_update(identity(100, FINALIZED_HASH), 102, TIP_HASH_B)?;
        failure_owner.activate(current_activation, slots())?;
        let failure_lease = failure_owner
            .pin()
            .ok_or(RecentSnapshotPublicationError::ActivationRejected)?;

        assert_eq!(
            failure_owner.fail_update(stale_failure),
            Err(RecentSnapshotPublicationError::ActivationRejected)
        );
        assert!(failure_lease.is_current());
        Ok(())
    }

    #[test]
    fn finalized_height_can_advance_without_changing_configuration(
    ) -> Result<(), RecentSnapshotPublicationError> {
        let mut owner = activated_owner()?;
        let advanced_identity = identity(101, ADVANCED_FINALIZED_HASH);
        let ticket = owner.begin_update(
            advanced_identity,
            advanced_identity.finalized_height(),
            *advanced_identity.finalized_hash_display(),
        )?;
        owner.activate(ticket, slots())?;

        let lease = owner
            .pin()
            .ok_or(RecentSnapshotPublicationError::ActivationRejected)?;
        assert_eq!(lease.snapshot().identity(), advanced_identity);
        assert_eq!(lease.snapshot().lineage().generation(), 2);
        Ok(())
    }

    #[test]
    fn finalized_rollback_and_same_height_hash_change_require_rebuild(
    ) -> Result<(), RecentSnapshotPublicationError> {
        let mut rollback_owner = activated_owner()?;
        assert!(matches!(
            rollback_owner.begin_update(identity(99, ADVANCED_FINALIZED_HASH), 101, TIP_HASH_A),
            Err(RecentSnapshotPublicationError::RebuildRequired)
        ));
        assert!(rollback_owner.pin().is_none());

        let mut hash_owner = activated_owner()?;
        assert!(matches!(
            hash_owner.begin_update(identity(100, ADVANCED_FINALIZED_HASH), 101, TIP_HASH_A),
            Err(RecentSnapshotPublicationError::RebuildRequired)
        ));
        assert!(hash_owner.pin().is_none());

        let retry = hash_owner.begin_update(identity(100, FINALIZED_HASH), 101, TIP_HASH_A)?;
        hash_owner.activate(retry, slots())?;
        let retried = hash_owner
            .pin()
            .ok_or(RecentSnapshotPublicationError::ActivationRejected)?;
        assert_eq!(retried.snapshot().lineage().generation(), 2);
        Ok(())
    }

    #[test]
    fn finalized_configuration_changes_require_rebuild(
    ) -> Result<(), RecentSnapshotPublicationError> {
        let base = identity(100, FINALIZED_HASH);
        let mismatches = [
            RecentSnapshotIdentity::new(1, 100, FINALIZED_HASH, 1, 7, 9),
            RecentSnapshotIdentity::new(0, 100, FINALIZED_HASH, 2, 7, 9),
            RecentSnapshotIdentity::new(0, 100, FINALIZED_HASH, 1, 8, 9),
            RecentSnapshotIdentity::new(0, 100, FINALIZED_HASH, 1, 7, 10),
        ];

        for mismatch in mismatches {
            let mut owner = TestOwner::new();
            let ticket = owner.begin_update(base, 101, TIP_HASH_A)?;
            owner.activate(ticket, slots())?;
            assert!(matches!(
                owner.begin_update(mismatch, 101, TIP_HASH_B),
                Err(RecentSnapshotPublicationError::RebuildRequired)
            ));
            assert!(owner.pin().is_none());
        }
        Ok(())
    }

    #[test]
    fn failed_build_remains_unready_and_consumes_its_generation(
    ) -> Result<(), RecentSnapshotPublicationError> {
        let mut owner = TestOwner::new();
        let failed = owner.begin_update(identity(100, FINALIZED_HASH), 101, TIP_HASH_A)?;
        owner.fail_update(failed)?;
        assert!(owner.pin().is_none());

        let retry = owner.begin_update(identity(100, FINALIZED_HASH), 101, TIP_HASH_A)?;
        owner.activate(retry, slots())?;
        let lease = owner
            .pin()
            .ok_or(RecentSnapshotPublicationError::ActivationRejected)?;
        assert_eq!(lease.snapshot().lineage().generation(), 2);
        Ok(())
    }

    #[test]
    fn generation_overflow_requires_rebuild_and_clears_active(
    ) -> Result<(), RecentSnapshotPublicationError> {
        let mut owner = activated_owner()?;
        owner.last_generation = u64::MAX;

        assert!(matches!(
            owner.begin_update(identity(100, FINALIZED_HASH), 103, TIP_HASH_B),
            Err(RecentSnapshotPublicationError::RebuildRequired)
        ));
        assert!(owner.pin().is_none());
        Ok(())
    }

    #[test]
    fn owner_recreation_with_a_rolled_projection_epoch_changes_the_binding(
    ) -> Result<(), RecentSnapshotPublicationError> {
        let mut first_owner = TestOwner::new();
        let first_ticket =
            first_owner.begin_update(identity_at_epoch(100, FINALIZED_HASH, 7), 102, TIP_HASH_A)?;
        first_owner.activate(first_ticket, slots())?;
        let first_binding = first_owner
            .pin()
            .ok_or(RecentSnapshotPublicationError::ActivationRejected)?
            .snapshot()
            .binding_digest();

        let mut replacement_owner = TestOwner::new();
        let replacement_ticket = replacement_owner.begin_update(
            identity_at_epoch(100, FINALIZED_HASH, 8),
            102,
            TIP_HASH_A,
        )?;
        replacement_owner.activate(replacement_ticket, slots())?;
        let replacement_binding = replacement_owner
            .pin()
            .ok_or(RecentSnapshotPublicationError::ActivationRejected)?
            .snapshot()
            .binding_digest();

        assert_ne!(replacement_binding, first_binding);
        Ok(())
    }
}
