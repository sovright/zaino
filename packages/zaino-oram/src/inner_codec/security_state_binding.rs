//! Typed binding between committed replay state and the outer security snapshot.
//!
//! This module only constructs and verifies business-layer snapshot values. It
//! does not infer recovery direction, mutate the replay journal, advance the
//! freshness witness, or own the ordering between those operations. This slice
//! deliberately has no non-test runtime or security-owner caller; store
//! construction, persistence coordination, and any required visibility
//! widening belong to the later owner-integration slice.

use std::{error::Error, fmt};

use blake2::{Blake2s256, Digest};

use super::{
    replay_journal::{
        ReplayJournalAdvanceReceipt, ReplayJournalComponentState,
        ReplayJournalComponentStateDigest, ReplayJournalMaintenanceAdvanceReceipt,
    },
    security_state_store::{
        SecurityStateIdentity, SecurityStateSnapshot, SecurityStateValueError, STATE_DIGEST_BYTES,
    },
};

const COMPONENT_STATE_DIGEST_DOMAIN: &[u8] = b"zaino-oram/security-component-state";
const COMPONENT_STATE_DIGEST_VERSION: u16 = 1;

#[derive(Clone, Copy, PartialEq, Eq)]
struct SecurityComponentStateDigest([u8; STATE_DIGEST_BYTES]);

impl SecurityComponentStateDigest {
    fn from_replay_journal(replay_digest: ReplayJournalComponentStateDigest) -> Self {
        let mut hasher = Blake2s256::new();
        Digest::update(&mut hasher, COMPONENT_STATE_DIGEST_DOMAIN);
        Digest::update(&mut hasher, COMPONENT_STATE_DIGEST_VERSION.to_be_bytes());
        Digest::update(&mut hasher, replay_digest.as_bytes());
        Self(hasher.finalize().into())
    }

    const fn into_bytes(self) -> [u8; STATE_DIGEST_BYTES] {
        self.0
    }
}

impl fmt::Debug for SecurityComponentStateDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecurityComponentStateDigest([REDACTED])")
    }
}

/// Explicitly provisions the first outer snapshot from the live replay state.
///
/// Calling this function is a provisioning decision. It must not be used to
/// infer that a missing outer snapshot means a previously committed state was
/// never present.
pub(super) fn provision_initial_snapshot<R>(
    identity: SecurityStateIdentity,
    serving_identity_digest: [u8; STATE_DIGEST_BYTES],
    replay_journal: &R,
) -> Result<SecurityStateSnapshot, SecurityStateBindingError>
where
    R: ReplayJournalComponentState + ?Sized,
{
    let component_digest =
        SecurityComponentStateDigest::from_replay_journal(current_replay_digest(replay_journal)?);
    SecurityStateSnapshot::initial_with_component_state_digest(
        identity,
        serving_identity_digest,
        component_digest.into_bytes(),
    )
    .map_err(SecurityStateBindingError::InvalidSnapshot)
}

/// Accepts reopened component state only when it exactly matches the snapshot.
///
/// A mismatch never selects initialize, repair, or advance. Authoritative
/// recovery direction belongs to a later explicit recovery ceremony.
pub(super) fn verify_current<R>(
    snapshot: &SecurityStateSnapshot,
    replay_journal: &R,
) -> Result<(), SecurityStateBindingError>
where
    R: ReplayJournalComponentState + ?Sized,
{
    let component_digest =
        SecurityComponentStateDigest::from_replay_journal(current_replay_digest(replay_journal)?);
    if snapshot.component_state_digest() == component_digest.into_bytes() {
        Ok(())
    } else {
        Err(SecurityStateBindingError::ReplayComponentMismatch)
    }
}

/// Rejects an exhausted outer sequence before a replay commit can become durable.
pub(super) fn preflight_successor(
    expected_snapshot: &SecurityStateSnapshot,
) -> Result<(), SecurityStateBindingError> {
    expected_snapshot
        .checked_successor_sequence()
        .map(|_| ())
        .map_err(SecurityStateBindingError::InvalidSnapshot)
}

/// Constructs a successor from one durably committed replay transaction.
///
/// The move-only receipt proves that the replay journal minted the transition
/// after its durable boundary. This function accepts only the snapshot that
/// names the receipt's immediate predecessor and never reads reopened disk
/// state or infers a recovery direction.
pub(super) fn successor_after_replay_commit<R>(
    expected_snapshot: &SecurityStateSnapshot,
    receipt: ReplayJournalAdvanceReceipt,
    replay_journal: &R,
) -> Result<SecurityStateSnapshot, SecurityStateBindingError>
where
    R: ReplayJournalComponentState + ?Sized,
{
    if !replay_journal.recognizes_receipt(&receipt) {
        return Err(SecurityStateBindingError::ReplayJournalInstanceMismatch);
    }

    let (previous_replay_digest, committed_replay_digest) = receipt.into_digests();
    successor_after_replay_transition(
        expected_snapshot,
        previous_replay_digest,
        committed_replay_digest,
        replay_journal,
    )
}

/// Constructs a successor from one durably committed maintenance watermark.
///
/// The distinct move-only receipt cannot be substituted for request replay
/// evidence. This function validates transition identity only; it does not
/// establish trusted-time authority or authorize claim deletion.
pub(super) fn successor_after_replay_maintenance<R>(
    expected_snapshot: &SecurityStateSnapshot,
    receipt: ReplayJournalMaintenanceAdvanceReceipt,
    replay_journal: &R,
) -> Result<SecurityStateSnapshot, SecurityStateBindingError>
where
    R: ReplayJournalComponentState + ?Sized,
{
    if !replay_journal.recognizes_maintenance_receipt(&receipt) {
        return Err(SecurityStateBindingError::ReplayJournalInstanceMismatch);
    }

    let (previous_replay_digest, committed_replay_digest) = receipt.into_digests();
    successor_after_replay_transition(
        expected_snapshot,
        previous_replay_digest,
        committed_replay_digest,
        replay_journal,
    )
}

fn successor_after_replay_transition<R>(
    expected_snapshot: &SecurityStateSnapshot,
    previous_replay_digest: ReplayJournalComponentStateDigest,
    committed_replay_digest: ReplayJournalComponentStateDigest,
    replay_journal: &R,
) -> Result<SecurityStateSnapshot, SecurityStateBindingError>
where
    R: ReplayJournalComponentState + ?Sized,
{
    let expected_component =
        SecurityComponentStateDigest::from_replay_journal(previous_replay_digest);
    if expected_snapshot.component_state_digest() != expected_component.into_bytes() {
        return Err(SecurityStateBindingError::ReplayComponentMismatch);
    }

    if committed_replay_digest == previous_replay_digest {
        return Err(SecurityStateBindingError::ReplayComponentDidNotAdvance);
    }
    if current_replay_digest(replay_journal)? != committed_replay_digest {
        return Err(SecurityStateBindingError::ReplayReceiptNotCurrent);
    }
    let current_component =
        SecurityComponentStateDigest::from_replay_journal(committed_replay_digest);
    expected_snapshot
        .successor_with_component_state_digest(current_component.into_bytes())
        .map_err(SecurityStateBindingError::InvalidSnapshot)
}

fn current_replay_digest<R>(
    replay_journal: &R,
) -> Result<ReplayJournalComponentStateDigest, SecurityStateBindingError>
where
    R: ReplayJournalComponentState + ?Sized,
{
    replay_journal
        .component_state_digest()
        .map_err(|_| SecurityStateBindingError::ReplayComponentUnavailable)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SecurityStateBindingError {
    ReplayComponentMismatch,
    ReplayComponentDidNotAdvance,
    ReplayComponentUnavailable,
    ReplayJournalInstanceMismatch,
    ReplayReceiptNotCurrent,
    InvalidSnapshot(SecurityStateValueError),
}

impl fmt::Display for SecurityStateBindingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReplayComponentMismatch => {
                f.write_str("replay component does not match the outer security snapshot")
            }
            Self::ReplayComponentDidNotAdvance => {
                f.write_str("replay transition receipt did not advance the component")
            }
            Self::ReplayComponentUnavailable => {
                f.write_str("replay component state is unavailable")
            }
            Self::ReplayJournalInstanceMismatch => {
                f.write_str("replay transition receipt belongs to a different journal instance")
            }
            Self::ReplayReceiptNotCurrent => {
                f.write_str("replay transition receipt no longer names the current journal state")
            }
            Self::InvalidSnapshot(_) => {
                f.write_str("replay component produced an invalid security snapshot")
            }
        }
    }
}

impl Error for SecurityStateBindingError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidSnapshot(error) => Some(error),
            Self::ReplayComponentMismatch
            | Self::ReplayComponentDidNotAdvance
            | Self::ReplayComponentUnavailable
            | Self::ReplayJournalInstanceMismatch
            | Self::ReplayReceiptNotCurrent => None,
        }
    }
}
