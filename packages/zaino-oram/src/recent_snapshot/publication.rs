//! Fail-closed publication of immutable recent-state generations.
//!
//! The owner is deliberately a single-writer type: every state transition
//! requires exclusive access, while pinned leases retain immutable snapshots.
//! Beginning any update removes the active publication before validating or
//! building its replacement, so a query can perform a final current-generation
//! check immediately before releasing a response.

use std::{fmt, sync::Arc};

use arc_swap::ArcSwapOption;

use super::{
    FrozenRecentSnapshot, RecentSnapshotIdentity, RecentSnapshotLineage, RecentSnapshotSlot,
};

/// Models the active immutable recent snapshot and its single-writer lineage.
struct RecentSnapshotPublicationOwner<const N: usize> {
    active: ArcSwapOption<FrozenRecentSnapshot<N>>,
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
            active: ArcSwapOption::empty(),
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

    /// Publishes a completed build only when its opaque ticket is outstanding.
    fn activate(
        &mut self,
        ticket: RecentSnapshotUpdateTicket,
        slots: [RecentSnapshotSlot; N],
    ) -> Result<(), RecentSnapshotPublicationError> {
        let lineage = self.take_outstanding(&ticket)?;

        let snapshot = Arc::new(FrozenRecentSnapshot::new(lineage, slots));
        self.active.store(Some(snapshot));
        Ok(())
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
        self.active
            .load_full()
            .map(|snapshot| RecentSnapshotLease { snapshot })
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

impl<const N: usize> fmt::Debug for RecentSnapshotPublicationOwner<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RecentSnapshotPublicationOwner { ..REDACTED.. }")
    }
}

/// A pinned immutable generation retained across publication transitions.
struct RecentSnapshotLease<const N: usize> {
    snapshot: Arc<FrozenRecentSnapshot<N>>,
}

impl<const N: usize> RecentSnapshotLease<N> {
    fn snapshot(&self) -> &FrozenRecentSnapshot<N> {
        &self.snapshot
    }

    /// Performs the final fail-closed generation check against the active Arc.
    fn is_current(&self, owner: &RecentSnapshotPublicationOwner<N>) -> bool {
        owner
            .active
            .load_full()
            .is_some_and(|active| Arc::ptr_eq(&self.snapshot, &active))
    }
}

impl<const N: usize> fmt::Debug for RecentSnapshotLease<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RecentSnapshotLease { ..REDACTED.. }")
    }
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
    use super::*;

    const FINALIZED_HASH: [u8; 32] = [0x11; 32];
    const ADVANCED_FINALIZED_HASH: [u8; 32] = [0x12; 32];
    const TIP_HASH_A: [u8; 32] = [0x21; 32];
    const TIP_HASH_B: [u8; 32] = [0x22; 32];
    const TIP_HASH_C: [u8; 32] = [0x23; 32];
    const SLOT_COUNT: usize = 2;

    type TestOwner = RecentSnapshotPublicationOwner<SLOT_COUNT>;

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
        assert!(first.is_current(&owner));

        let updated = owner.begin_update(identity(100, FINALIZED_HASH), 102, TIP_HASH_B)?;
        owner.activate(updated, slots())?;
        let second = owner
            .pin()
            .ok_or(RecentSnapshotPublicationError::ActivationRejected)?;
        assert_eq!(second.snapshot().lineage().generation(), 2);
        assert!(second.is_current(&owner));
        assert!(!first.is_current(&owner));
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
        assert!(!lease.is_current(&owner));
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
        assert!(lease.is_current(&owner));
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
        assert!(activated_lease.is_current(&activation_owner));

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
        assert!(failure_lease.is_current(&failure_owner));
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
