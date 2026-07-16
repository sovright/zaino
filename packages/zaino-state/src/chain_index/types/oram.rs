//! Business-layer snapshots used to hand finalized transparent state to ORAM consumers.

use std::{collections::BTreeMap, fmt};

use super::{AddrScript, BlockIndex, Height, Outpoint};

/// One outpoint's state at an exact finalized checkpoint.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(in crate::chain_index) enum FinalizedOutpointState {
    /// The creating output did not exist at the checkpoint.
    NeverSeen,
    /// The output existed and had already been spent by the checkpoint.
    Spent,
    /// A live standard transparent output.
    LiveStandard {
        /// Exact P2PKH or P2SH address identity.
        address: AddrScript,
        /// Output value in zatoshis.
        value_zat: u64,
        /// Height at which the output was created.
        created_height: Height,
    },
    /// A live output whose script is not a supported standard address form.
    LiveNonStandard {
        /// Height at which the output was created.
        created_height: Height,
    },
}

impl fmt::Debug for FinalizedOutpointState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NeverSeen => formatter.write_str("NeverSeen"),
            Self::Spent => formatter.write_str("Spent"),
            Self::LiveStandard { .. } => formatter.write_str("LiveStandard { ..REDACTED.. }"),
            Self::LiveNonStandard { .. } => formatter.write_str("LiveNonStandard { ..REDACTED.. }"),
        }
    }
}

/// Fully materialized outpoint states from one immutable finalized-database read transaction.
#[derive(Clone, PartialEq, Eq)]
pub(in crate::chain_index) struct FinalizedOutpointSnapshot {
    checkpoint: BlockIndex,
    states: BTreeMap<Outpoint, FinalizedOutpointState>,
}

impl fmt::Debug for FinalizedOutpointSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FinalizedOutpointSnapshot")
            .field("checkpoint_height", &self.checkpoint.height)
            .field("state_count", &self.states.len())
            .finish_non_exhaustive()
    }
}

impl FinalizedOutpointSnapshot {
    /// Constructs one transaction-bound finalized snapshot.
    pub(in crate::chain_index) fn new(
        checkpoint: BlockIndex,
        states: BTreeMap<Outpoint, FinalizedOutpointState>,
    ) -> Self {
        Self { checkpoint, states }
    }

    /// Returns the exact finalized checkpoint observed by the read transaction.
    #[allow(dead_code)] // Consumed by the immediately stacked zaino-oram controller integration.
    pub(in crate::chain_index) fn checkpoint(&self) -> BlockIndex {
        self.checkpoint
    }

    /// Returns the materialized state for `outpoint`, if it was requested.
    #[allow(dead_code)] // Consumed by the immediately stacked zaino-oram controller integration.
    pub(in crate::chain_index) fn classify(
        &self,
        outpoint: &Outpoint,
    ) -> Option<FinalizedOutpointState> {
        self.states.get(outpoint).copied()
    }

    /// Returns the number of unique requested outpoints.
    #[allow(dead_code)] // Consumed by the immediately stacked zaino-oram controller integration.
    pub(in crate::chain_index) fn len(&self) -> usize {
        self.states.len()
    }
}
