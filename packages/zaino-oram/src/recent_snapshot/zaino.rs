//! Conversion from one value-bound Zaino recent-chain snapshot into fixed slots.
//!
//! This module deliberately stops before generation assignment and publication.
//! Its finalized classifier is an injected immutable view pinned to the same
//! public checkpoint identity as the recent chain.
//!
//! Finalized and recent-tip hash fields use display-order bytes. Outpoint and
//! fixed-record transaction IDs retain Zaino's internal byte order; conversion
//! never reverses those transaction-ID bytes.

use std::{collections::HashMap, fmt};

use zaino_state::{
    extract_transparent_events, AddrScript, CanonicalRecentChainSnapshot, Outpoint, ScriptType,
    TransparentBlockEvent, TransparentEventError,
};

use super::{RecentSnapshotIdentity, RecentSnapshotSlot};
use crate::{
    layout::{derive_standard_address_key, LayoutNetwork, StandardAddress, StandardScriptKind},
    records::{TransparentUtxo, UtxoRecordError},
};

/// One immutable finalized-state classification for an outpoint.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum FinalizedOutpointClassification {
    /// The outpoint did not exist at the pinned finalized checkpoint.
    NeverSeen,
    /// The outpoint existed and was already spent by the pinned checkpoint.
    Spent,
    /// A live standard output at the pinned checkpoint.
    LiveStandard {
        address: AddrScript,
        value_zat: u64,
        created_height: u32,
    },
    /// A live non-standard output at the pinned checkpoint.
    LiveNonStandard { created_height: u32 },
}

impl FinalizedOutpointClassification {
    const fn class(self) -> OutpointStateClass {
        match self {
            Self::NeverSeen => OutpointStateClass::NeverSeen,
            Self::Spent => OutpointStateClass::Spent,
            Self::LiveStandard { .. } => OutpointStateClass::LiveStandard,
            Self::LiveNonStandard { .. } => OutpointStateClass::LiveNonStandard,
        }
    }
}

/// One coarsened failure from an immutable finalized outpoint classifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct FinalizedOutpointSnapshotError;

impl fmt::Display for FinalizedOutpointSnapshotError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("finalized outpoint classification is unavailable")
    }
}

impl std::error::Error for FinalizedOutpointSnapshotError {}

/// Immutable synchronous view of outpoints at one exact finalized identity.
///
/// Implementations must be fully materialized before conversion. Neither
/// [`Self::identity`] nor [`Self::classify`] may perform database, source, or
/// network I/O, and every result must come from the same pinned view.
pub(super) trait FinalizedOutpointSnapshot {
    /// Returns the public identity pinning every classification result.
    fn identity(&self) -> RecentSnapshotIdentity;

    /// Classifies one outpoint from the preloaded view identified by `identity`.
    fn classify(
        &self,
        outpoint: &Outpoint,
    ) -> Result<FinalizedOutpointClassification, FinalizedOutpointSnapshotError>;
}

/// Generation-free fixed-slot candidate produced by one complete conversion.
///
/// This value is not a [`super::FrozenRecentSnapshot`]: it has no publication
/// generation, binding digest, or lifecycle ownership.
pub(super) struct ConvertedRecentSnapshot<const N: usize> {
    finalized: RecentSnapshotIdentity,
    recent_tip_height: u32,
    recent_tip_hash_display: [u8; 32],
    slots: [RecentSnapshotSlot; N],
}

impl<const N: usize> ConvertedRecentSnapshot<N> {
    pub(super) const fn finalized(&self) -> RecentSnapshotIdentity {
        self.finalized
    }

    pub(super) const fn recent_tip_height(&self) -> u32 {
        self.recent_tip_height
    }

    pub(super) const fn recent_tip_hash_display(&self) -> &[u8; 32] {
        &self.recent_tip_hash_display
    }

    pub(super) const fn slots(&self) -> &[RecentSnapshotSlot; N] {
        &self.slots
    }
}

/// Converts an already-validated recent chain into a dense standard-event prefix.
pub(super) fn convert_canonical_recent_snapshot<
    const N: usize,
    S: FinalizedOutpointSnapshot + ?Sized,
>(
    recent: &CanonicalRecentChainSnapshot,
    finalized: &S,
) -> Result<ConvertedRecentSnapshot<N>, RecentSnapshotConversionError> {
    let identity = finalized.identity();
    let canonical_finalized = recent.finalized();
    let canonical_finalized_height = u32::from(canonical_finalized.height);
    if identity.finalized_height() != canonical_finalized_height {
        return Err(RecentSnapshotConversionError::FinalizedHeightMismatch {
            canonical_height: canonical_finalized_height,
            classifier_height: identity.finalized_height(),
        });
    }
    if identity.finalized_hash_display() != &canonical_finalized.hash.bytes_in_display_order() {
        return Err(RecentSnapshotConversionError::FinalizedHashMismatch {
            height: canonical_finalized_height,
        });
    }
    let network = map_network(identity.network_tag())?;
    let schema_version = identity.schema_version();
    if schema_version == 0 {
        return Err(RecentSnapshotConversionError::ZeroSchemaVersion);
    }
    if identity.projection_epoch() == 0 {
        return Err(RecentSnapshotConversionError::ZeroProjectionEpoch);
    }

    let mut converter = Converter::<N, S> {
        finalized,
        finalized_height: canonical_finalized_height,
        network,
        schema_version,
        states: HashMap::new(),
        slots: [RecentSnapshotSlot::dummy(); N],
        occupied: 0,
    };
    for block in recent.blocks() {
        for event in extract_transparent_events(block)
            .map_err(RecentSnapshotConversionError::TransparentEvents)?
        {
            converter.apply(event)?;
        }
    }

    let tip = recent.tip();
    Ok(ConvertedRecentSnapshot {
        finalized: identity,
        recent_tip_height: u32::from(tip.height),
        recent_tip_hash_display: tip.hash.bytes_in_display_order(),
        slots: converter.slots,
    })
}

struct Converter<'a, const N: usize, S: FinalizedOutpointSnapshot + ?Sized> {
    finalized: &'a S,
    finalized_height: u32,
    network: LayoutNetwork,
    schema_version: u32,
    states: HashMap<Outpoint, RecentOutpointState>,
    slots: [RecentSnapshotSlot; N],
    occupied: usize,
}

impl<const N: usize, S: FinalizedOutpointSnapshot + ?Sized> Converter<'_, N, S> {
    fn apply(&mut self, event: TransparentBlockEvent) -> Result<(), RecentSnapshotConversionError> {
        match event {
            TransparentBlockEvent::Created {
                location,
                outpoint,
                address,
                value_zat,
                script_class,
                ..
            } => self.create(
                location.block_height(),
                outpoint,
                address,
                value_zat,
                script_class,
            ),
            TransparentBlockEvent::Spent {
                location, previous, ..
            } => self.spend(location.block_height(), previous),
        }
    }

    fn create(
        &mut self,
        height: u32,
        outpoint: Outpoint,
        address: Option<AddrScript>,
        value_zat: u64,
        script_class: ScriptType,
    ) -> Result<(), RecentSnapshotConversionError> {
        if let Some(existing) = self.states.get(&outpoint).copied() {
            return Err(RecentSnapshotConversionError::DuplicateCreation {
                height,
                prior: existing.class(),
            });
        }
        let finalized = self
            .finalized
            .classify(&outpoint)
            .map_err(RecentSnapshotConversionError::FinalizedClassifier)?;
        if finalized != FinalizedOutpointClassification::NeverSeen {
            return Err(RecentSnapshotConversionError::DuplicateCreation {
                height,
                prior: finalized.class(),
            });
        }

        match (script_class, address) {
            (ScriptType::P2PKH | ScriptType::P2SH, Some(address)) => {
                let (address_key, utxo) =
                    self.standard_utxo(height, outpoint, address, value_zat, height)?;
                self.push(RecentSnapshotSlot::created(address_key, utxo))?;
                self.states.insert(
                    outpoint,
                    RecentOutpointState::LiveStandard { address_key, utxo },
                );
            }
            (ScriptType::NonStandard, None) => {
                self.states
                    .insert(outpoint, RecentOutpointState::LiveNonStandard);
            }
            (script_class, _) => {
                return Err(RecentSnapshotConversionError::InvalidStandardScriptClass {
                    height,
                    script_class: script_class as u8,
                });
            }
        }
        Ok(())
    }

    fn spend(
        &mut self,
        height: u32,
        outpoint: Outpoint,
    ) -> Result<(), RecentSnapshotConversionError> {
        if let Some(local) = self.states.get(&outpoint).copied() {
            return match local {
                RecentOutpointState::LiveStandard { address_key, utxo } => {
                    self.push(RecentSnapshotSlot::spent(address_key, utxo))?;
                    self.states.insert(outpoint, RecentOutpointState::Spent);
                    Ok(())
                }
                RecentOutpointState::LiveNonStandard => {
                    self.states.insert(outpoint, RecentOutpointState::Spent);
                    Ok(())
                }
                RecentOutpointState::Spent => {
                    Err(RecentSnapshotConversionError::AlreadySpent { height })
                }
            };
        }

        let finalized = self
            .finalized
            .classify(&outpoint)
            .map_err(RecentSnapshotConversionError::FinalizedClassifier)?;
        match finalized {
            FinalizedOutpointClassification::NeverSeen => {
                Err(RecentSnapshotConversionError::UnknownSpend { height })
            }
            FinalizedOutpointClassification::Spent => {
                self.states.insert(outpoint, RecentOutpointState::Spent);
                Err(RecentSnapshotConversionError::AlreadySpent { height })
            }
            FinalizedOutpointClassification::LiveStandard {
                address,
                value_zat,
                created_height,
            } => {
                self.validate_resolved_height(created_height, OutpointStateClass::LiveStandard)?;
                let (address_key, utxo) =
                    self.standard_utxo(height, outpoint, address, value_zat, created_height)?;
                self.push(RecentSnapshotSlot::spent(address_key, utxo))?;
                self.states.insert(outpoint, RecentOutpointState::Spent);
                Ok(())
            }
            FinalizedOutpointClassification::LiveNonStandard { created_height } => {
                self.validate_resolved_height(created_height, OutpointStateClass::LiveNonStandard)?;
                self.states.insert(outpoint, RecentOutpointState::Spent);
                Ok(())
            }
        }
    }

    fn standard_utxo(
        &self,
        event_height: u32,
        outpoint: Outpoint,
        address: AddrScript,
        value_zat: u64,
        created_height: u32,
    ) -> Result<(crate::records::AddressKey, TransparentUtxo), RecentSnapshotConversionError> {
        let kind = match ScriptType::try_from(address.script_type()) {
            Ok(ScriptType::P2PKH) => StandardScriptKind::PayToPublicKeyHash,
            Ok(ScriptType::P2SH) => StandardScriptKind::PayToScriptHash,
            Ok(ScriptType::NonStandard) | Err(()) => {
                return Err(RecentSnapshotConversionError::InvalidStandardScriptClass {
                    height: event_height,
                    script_class: address.script_type(),
                });
            }
        };
        let script = address.to_script_pubkey().ok_or(
            RecentSnapshotConversionError::InvalidStandardScriptClass {
                height: event_height,
                script_class: address.script_type(),
            },
        )?;
        let address_key = derive_standard_address_key(
            self.network,
            self.schema_version,
            StandardAddress::new(kind, *address.hash()),
        );
        let utxo = TransparentUtxo::new(
            *outpoint.prev_txid(),
            outpoint.prev_index(),
            value_zat,
            created_height,
            &script,
        )
        .map_err(RecentSnapshotConversionError::UtxoRecord)?;
        Ok((address_key, utxo))
    }

    fn validate_resolved_height(
        &self,
        created_height: u32,
        class: OutpointStateClass,
    ) -> Result<(), RecentSnapshotConversionError> {
        if created_height > self.finalized_height {
            return Err(
                RecentSnapshotConversionError::ResolvedHeightAboveFinalized {
                    created_height,
                    finalized_height: self.finalized_height,
                    class,
                },
            );
        }
        Ok(())
    }

    fn push(&mut self, slot: RecentSnapshotSlot) -> Result<(), RecentSnapshotConversionError> {
        let required = self.occupied.checked_add(1).ok_or(
            RecentSnapshotConversionError::CapacityExceeded {
                capacity: N,
                required: usize::MAX,
            },
        )?;
        let destination = self.slots.get_mut(self.occupied).ok_or(
            RecentSnapshotConversionError::CapacityExceeded {
                capacity: N,
                required,
            },
        )?;
        *destination = slot;
        self.occupied = required;
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum RecentOutpointState {
    LiveStandard {
        address_key: crate::records::AddressKey,
        utxo: TransparentUtxo,
    },
    LiveNonStandard,
    Spent,
}

impl RecentOutpointState {
    const fn class(self) -> OutpointStateClass {
        match self {
            Self::LiveStandard { .. } => OutpointStateClass::LiveStandard,
            Self::LiveNonStandard => OutpointStateClass::LiveNonStandard,
            Self::Spent => OutpointStateClass::Spent,
        }
    }
}

/// Publicly describable classifier state without an outpoint or address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum OutpointStateClass {
    NeverSeen,
    Spent,
    LiveStandard,
    LiveNonStandard,
}

/// A canonical recent snapshot could not be converted without truncation or ambiguity.
#[derive(Debug)]
pub(super) enum RecentSnapshotConversionError {
    FinalizedHeightMismatch {
        canonical_height: u32,
        classifier_height: u32,
    },
    FinalizedHashMismatch {
        height: u32,
    },
    UnknownNetworkTag {
        network_tag: u8,
    },
    ZeroSchemaVersion,
    ZeroProjectionEpoch,
    TransparentEvents(TransparentEventError),
    FinalizedClassifier(FinalizedOutpointSnapshotError),
    DuplicateCreation {
        height: u32,
        prior: OutpointStateClass,
    },
    UnknownSpend {
        height: u32,
    },
    AlreadySpent {
        height: u32,
    },
    ResolvedHeightAboveFinalized {
        created_height: u32,
        finalized_height: u32,
        class: OutpointStateClass,
    },
    InvalidStandardScriptClass {
        height: u32,
        script_class: u8,
    },
    CapacityExceeded {
        capacity: usize,
        required: usize,
    },
    UtxoRecord(UtxoRecordError),
}

impl fmt::Display for RecentSnapshotConversionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FinalizedHeightMismatch {
                canonical_height,
                classifier_height,
            } => write!(
                f,
                "canonical finalized height {canonical_height} does not match classifier height {classifier_height}"
            ),
            Self::FinalizedHashMismatch { height } => {
                write!(f, "finalized classifier hash does not match at height {height}")
            }
            Self::UnknownNetworkTag { network_tag } => {
                write!(f, "recent snapshot network tag {network_tag} is unsupported")
            }
            Self::ZeroSchemaVersion => {
                f.write_str("recent snapshot schema version must be nonzero")
            }
            Self::ZeroProjectionEpoch => {
                f.write_str("recent snapshot projection epoch must be nonzero")
            }
            Self::TransparentEvents(error) => {
                write!(f, "transparent event extraction failed: {error}")
            }
            Self::FinalizedClassifier(error) => write!(f, "{error}"),
            Self::DuplicateCreation { height, prior } => write!(
                f,
                "output creation at public height {height} conflicts with prior {prior:?} state"
            ),
            Self::UnknownSpend { height } => {
                write!(f, "output spend at public height {height} has no prior creation")
            }
            Self::AlreadySpent { height } => {
                write!(f, "output at public height {height} was already spent")
            }
            Self::ResolvedHeightAboveFinalized {
                created_height,
                finalized_height,
                class,
            } => write!(
                f,
                "resolved {class:?} output height {created_height} exceeds finalized height {finalized_height}"
            ),
            Self::InvalidStandardScriptClass {
                height,
                script_class,
            } => write!(
                f,
                "standard output at public height {height} has unsupported script class {script_class}"
            ),
            Self::CapacityExceeded { capacity, required } => write!(
                f,
                "recent snapshot requires {required} occupied slots but capacity is {capacity}"
            ),
            Self::UtxoRecord(error) => write!(f, "fixed transparent output is invalid: {error}"),
        }
    }
}

impl std::error::Error for RecentSnapshotConversionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::TransparentEvents(error) => Some(error),
            Self::FinalizedClassifier(error) => Some(error),
            Self::UtxoRecord(error) => Some(error),
            Self::FinalizedHeightMismatch { .. }
            | Self::FinalizedHashMismatch { .. }
            | Self::UnknownNetworkTag { .. }
            | Self::ZeroSchemaVersion
            | Self::ZeroProjectionEpoch
            | Self::DuplicateCreation { .. }
            | Self::UnknownSpend { .. }
            | Self::AlreadySpent { .. }
            | Self::ResolvedHeightAboveFinalized { .. }
            | Self::InvalidStandardScriptClass { .. }
            | Self::CapacityExceeded { .. } => None,
        }
    }
}

const fn map_network(network_tag: u8) -> Result<LayoutNetwork, RecentSnapshotConversionError> {
    match network_tag {
        0 => Ok(LayoutNetwork::Mainnet),
        1 => Ok(LayoutNetwork::Testnet),
        2 => Ok(LayoutNetwork::Regtest),
        _ => Err(RecentSnapshotConversionError::UnknownNetworkTag { network_tag }),
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use zaino_state::{
        chain_index::types::BlockIndex, BlockHash, CanonicalRecentChainSnapshot, Height, Outpoint,
        TxInCompact,
    };

    use super::*;
    use crate::{
        recent_snapshot::{content_digest, RecentUtxoChangeKind},
        zaino_fixtures::{indexed_block, output, transaction, FixtureResult},
    };

    const FINALIZED_HEIGHT: u32 = 100;
    const FINALIZED_HASH: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];
    const TIP_HASH: [u8; 32] = [
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e,
        0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d,
        0x3e, 0x3f,
    ];
    const STANDARD_HASH: [u8; 20] = [0xa1; 20];

    struct TestFinalizedSnapshot {
        identity: RecentSnapshotIdentity,
        states: HashMap<Outpoint, FinalizedOutpointClassification>,
        calls: Cell<usize>,
        unavailable: bool,
    }

    impl TestFinalizedSnapshot {
        fn new(identity: RecentSnapshotIdentity) -> Self {
            Self {
                identity,
                states: HashMap::new(),
                calls: Cell::new(0),
                unavailable: false,
            }
        }

        fn with_state(
            mut self,
            outpoint: Outpoint,
            state: FinalizedOutpointClassification,
        ) -> Self {
            self.states.insert(outpoint, state);
            self
        }

        fn unavailable(mut self) -> Self {
            self.unavailable = true;
            self
        }

        fn calls(&self) -> usize {
            self.calls.get()
        }
    }

    impl FinalizedOutpointSnapshot for TestFinalizedSnapshot {
        fn identity(&self) -> RecentSnapshotIdentity {
            self.identity
        }

        fn classify(
            &self,
            outpoint: &Outpoint,
        ) -> Result<FinalizedOutpointClassification, FinalizedOutpointSnapshotError> {
            self.calls.set(self.calls.get().saturating_add(1));
            if self.unavailable {
                return Err(FinalizedOutpointSnapshotError);
            }
            Ok(self
                .states
                .get(outpoint)
                .copied()
                .unwrap_or(FinalizedOutpointClassification::NeverSeen))
        }
    }

    fn identity() -> RecentSnapshotIdentity {
        RecentSnapshotIdentity::new(
            2,
            FINALIZED_HEIGHT,
            BlockHash(FINALIZED_HASH).bytes_in_display_order(),
            1,
            7,
            9,
        )
    }

    fn index(height: u32, hash: [u8; 32]) -> FixtureResult<BlockIndex> {
        Ok(BlockIndex {
            height: Height::try_from(height)?,
            hash: BlockHash(hash),
        })
    }

    fn snapshot(
        blocks: Vec<zaino_state::IndexedBlock>,
    ) -> FixtureResult<CanonicalRecentChainSnapshot> {
        let finalized = index(FINALIZED_HEIGHT, FINALIZED_HASH)?;
        let tip = match blocks.last() {
            Some(block) => BlockIndex {
                height: block.height(),
                hash: *block.hash(),
            },
            None => finalized,
        };
        Ok(CanonicalRecentChainSnapshot::from_parts_for_tests(
            finalized, tip, blocks,
        ))
    }

    fn standard_create_and_spend_block(
        script_class: ScriptType,
    ) -> FixtureResult<zaino_state::IndexedBlock> {
        let created_txid = [0x41; 32];
        let create = transaction(
            0,
            created_txid,
            vec![TxInCompact::null_prevout()],
            vec![output(50, STANDARD_HASH, script_class)?],
        );
        let spend = transaction(
            1,
            [0x42; 32],
            vec![TxInCompact::new(created_txid, 0)],
            Vec::new(),
        );
        indexed_block(
            FINALIZED_HEIGHT + 1,
            TIP_HASH,
            FINALIZED_HASH,
            vec![create, spend],
        )
    }

    fn spend_block(outpoints: &[Outpoint]) -> FixtureResult<zaino_state::IndexedBlock> {
        let inputs = outpoints
            .iter()
            .map(|outpoint| TxInCompact::new(*outpoint.prev_txid(), outpoint.prev_index()))
            .collect();
        indexed_block(
            FINALIZED_HEIGHT + 1,
            TIP_HASH,
            FINALIZED_HASH,
            vec![transaction(0, [0x52; 32], inputs, Vec::new())],
        )
    }

    fn occupied_change<const N: usize>(
        converted: &ConvertedRecentSnapshot<N>,
        ordinal: usize,
    ) -> FixtureResult<&super::super::RecentUtxoChange> {
        converted
            .slots()
            .get(ordinal)
            .and_then(RecentSnapshotSlot::change)
            .ok_or_else(|| "expected occupied recent snapshot slot".into())
    }

    #[test]
    fn empty_recent_chain_is_all_dummies_without_classifier_lookup() -> FixtureResult<()> {
        let recent = snapshot(Vec::new())?;
        let finalized = TestFinalizedSnapshot::new(identity());

        let converted = convert_canonical_recent_snapshot::<3, _>(&recent, &finalized)?;

        assert_eq!(converted.finalized(), identity());
        assert_eq!(converted.recent_tip_height(), FINALIZED_HEIGHT);
        assert_eq!(
            converted.recent_tip_hash_display(),
            identity().finalized_hash_display()
        );
        assert!(converted.slots().iter().all(|slot| slot.change().is_none()));
        assert_eq!(finalized.calls(), 0);
        Ok(())
    }

    #[test]
    fn recent_standard_create_and_spend_preserve_order_and_exact_utxo() -> FixtureResult<()> {
        let recent = snapshot(vec![standard_create_and_spend_block(ScriptType::P2PKH)?])?;
        let finalized = TestFinalizedSnapshot::new(identity());

        let converted = convert_canonical_recent_snapshot::<4, _>(&recent, &finalized)?;
        let created = occupied_change(&converted, 0)?;
        let spent = occupied_change(&converted, 1)?;

        assert!(matches!(created.kind(), RecentUtxoChangeKind::Created));
        assert!(matches!(spent.kind(), RecentUtxoChangeKind::Spent));
        assert_eq!(created.address_key(), spent.address_key());
        assert_eq!(created.utxo(), spent.utxo());
        assert_eq!(created.utxo().txid(), &[0x41; 32]);
        assert_eq!(created.utxo().output_index(), 0);
        assert_eq!(created.utxo().value_zat(), 50);
        assert_eq!(created.utxo().height(), FINALIZED_HEIGHT + 1);
        assert!(converted.slots()[2..]
            .iter()
            .all(|slot| slot.change().is_none()));
        assert_eq!(
            finalized.calls(),
            1,
            "the local spend must not resolve again"
        );
        Ok(())
    }

    #[test]
    fn recent_nonstandard_lifecycle_emits_no_slots_and_resolves_only_creation() -> FixtureResult<()>
    {
        let recent = snapshot(vec![standard_create_and_spend_block(
            ScriptType::NonStandard,
        )?])?;
        let finalized = TestFinalizedSnapshot::new(identity());

        let converted = convert_canonical_recent_snapshot::<2, _>(&recent, &finalized)?;

        assert!(converted.slots().iter().all(|slot| slot.change().is_none()));
        assert_eq!(finalized.calls(), 1);
        Ok(())
    }

    #[test]
    fn cross_seam_standard_and_nonstandard_spends_use_pinned_classifier() -> FixtureResult<()> {
        let standard = Outpoint::new([0x61; 32], 3);
        let nonstandard = Outpoint::new([0x62; 32], 4);
        let recent = snapshot(vec![spend_block(&[standard, nonstandard])?])?;
        let finalized = TestFinalizedSnapshot::new(identity())
            .with_state(
                standard,
                FinalizedOutpointClassification::LiveStandard {
                    address: AddrScript::new(STANDARD_HASH, ScriptType::P2SH as u8),
                    value_zat: 75,
                    created_height: 90,
                },
            )
            .with_state(
                nonstandard,
                FinalizedOutpointClassification::LiveNonStandard { created_height: 91 },
            );

        let converted = convert_canonical_recent_snapshot::<2, _>(&recent, &finalized)?;
        let spent = occupied_change(&converted, 0)?;

        assert!(matches!(spent.kind(), RecentUtxoChangeKind::Spent));
        assert_eq!(spent.utxo().txid(), standard.prev_txid());
        assert_eq!(spent.utxo().output_index(), standard.prev_index());
        assert_eq!(spent.utxo().value_zat(), 75);
        assert_eq!(spent.utxo().height(), 90);
        assert!(converted.slots()[1].change().is_none());
        assert_eq!(finalized.calls(), 2);
        Ok(())
    }

    #[test]
    fn creation_rejects_every_pre_seam_state_class_and_recent_duplicate() -> FixtureResult<()> {
        let txid = [0x71; 32];
        let outpoint = Outpoint::new(txid, 0);
        let block = indexed_block(
            FINALIZED_HEIGHT + 1,
            TIP_HASH,
            FINALIZED_HASH,
            vec![transaction(
                0,
                txid,
                vec![TxInCompact::null_prevout()],
                vec![output(1, STANDARD_HASH, ScriptType::P2PKH)?],
            )],
        )?;
        let recent = snapshot(vec![block.clone()])?;
        let prior_states = [
            FinalizedOutpointClassification::Spent,
            FinalizedOutpointClassification::LiveStandard {
                address: AddrScript::new(STANDARD_HASH, ScriptType::P2PKH as u8),
                value_zat: 1,
                created_height: 80,
            },
            FinalizedOutpointClassification::LiveNonStandard { created_height: 80 },
        ];
        for prior in prior_states {
            let finalized = TestFinalizedSnapshot::new(identity()).with_state(outpoint, prior);
            assert!(matches!(
                convert_canonical_recent_snapshot::<1, _>(&recent, &finalized),
                Err(RecentSnapshotConversionError::DuplicateCreation { .. })
            ));
        }

        let duplicated = snapshot(vec![indexed_block(
            FINALIZED_HEIGHT + 1,
            TIP_HASH,
            FINALIZED_HASH,
            vec![
                block.transactions()[0].clone(),
                block.transactions()[0].clone(),
            ],
        )?])?;
        let finalized = TestFinalizedSnapshot::new(identity());
        assert!(matches!(
            convert_canonical_recent_snapshot::<2, _>(&duplicated, &finalized),
            Err(RecentSnapshotConversionError::DuplicateCreation {
                prior: OutpointStateClass::LiveStandard,
                ..
            })
        ));
        assert_eq!(finalized.calls(), 1);
        Ok(())
    }

    #[test]
    fn double_and_unknown_spends_fail_without_reclassifying_local_spent_state() -> FixtureResult<()>
    {
        let live = Outpoint::new([0x81; 32], 0);
        let doubled = snapshot(vec![spend_block(&[live, live])?])?;
        let finalized = TestFinalizedSnapshot::new(identity()).with_state(
            live,
            FinalizedOutpointClassification::LiveNonStandard { created_height: 80 },
        );
        assert!(matches!(
            convert_canonical_recent_snapshot::<0, _>(&doubled, &finalized),
            Err(RecentSnapshotConversionError::AlreadySpent { .. })
        ));
        assert_eq!(finalized.calls(), 1);

        let unknown = snapshot(vec![spend_block(&[Outpoint::new([0x82; 32], 0)])?])?;
        let finalized = TestFinalizedSnapshot::new(identity());
        assert!(matches!(
            convert_canonical_recent_snapshot::<0, _>(&unknown, &finalized),
            Err(RecentSnapshotConversionError::UnknownSpend { .. })
        ));
        assert_eq!(finalized.calls(), 1);
        Ok(())
    }

    #[test]
    fn unavailable_classifier_is_coarsened() -> FixtureResult<()> {
        let recent = snapshot(vec![standard_create_and_spend_block(ScriptType::P2PKH)?])?;
        let finalized = TestFinalizedSnapshot::new(identity()).unavailable();

        let error = convert_canonical_recent_snapshot::<2, _>(&recent, &finalized);

        assert!(matches!(
            error,
            Err(RecentSnapshotConversionError::FinalizedClassifier(
                FinalizedOutpointSnapshotError
            ))
        ));
        assert_eq!(finalized.calls(), 1);
        Ok(())
    }

    #[test]
    fn resolved_output_height_must_not_exceed_seam() -> FixtureResult<()> {
        let cases = [
            (
                Outpoint::new([0x91; 32], 0),
                FinalizedOutpointClassification::LiveStandard {
                    address: AddrScript::new(STANDARD_HASH, ScriptType::P2PKH as u8),
                    value_zat: 1,
                    created_height: FINALIZED_HEIGHT + 1,
                },
                OutpointStateClass::LiveStandard,
            ),
            (
                Outpoint::new([0x92; 32], 0),
                FinalizedOutpointClassification::LiveNonStandard {
                    created_height: FINALIZED_HEIGHT + 1,
                },
                OutpointStateClass::LiveNonStandard,
            ),
        ];
        for (outpoint, classification, expected_class) in cases {
            let recent = snapshot(vec![spend_block(&[outpoint])?])?;
            let finalized =
                TestFinalizedSnapshot::new(identity()).with_state(outpoint, classification);
            let Err(RecentSnapshotConversionError::ResolvedHeightAboveFinalized { class, .. }) =
                convert_canonical_recent_snapshot::<2, _>(&recent, &finalized)
            else {
                return Err("resolved output above the finalized seam must fail".into());
            };
            assert_eq!(class, expected_class);
        }
        Ok(())
    }

    #[test]
    fn public_identity_network_tags_map_to_layout_domains() {
        assert!(matches!(map_network(0), Ok(LayoutNetwork::Mainnet)));
        assert!(matches!(map_network(1), Ok(LayoutNetwork::Testnet)));
        assert!(matches!(map_network(2), Ok(LayoutNetwork::Regtest)));
        assert!(matches!(
            map_network(3),
            Err(RecentSnapshotConversionError::UnknownNetworkTag { network_tag: 3 })
        ));
    }

    #[test]
    fn exact_capacity_succeeds_and_smaller_or_zero_capacity_fails() -> FixtureResult<()> {
        let txid = [0xa1; 32];
        let block = indexed_block(
            FINALIZED_HEIGHT + 1,
            TIP_HASH,
            FINALIZED_HASH,
            vec![transaction(
                0,
                txid,
                vec![TxInCompact::null_prevout()],
                vec![
                    output(1, [0xb1; 20], ScriptType::P2PKH)?,
                    output(2, [0xb2; 20], ScriptType::P2SH)?,
                ],
            )],
        )?;
        let recent = snapshot(vec![block])?;

        let exact = convert_canonical_recent_snapshot::<2, _>(
            &recent,
            &TestFinalizedSnapshot::new(identity()),
        )?;
        assert!(exact.slots().iter().all(|slot| slot.change().is_some()));
        assert!(matches!(
            convert_canonical_recent_snapshot::<1, _>(
                &recent,
                &TestFinalizedSnapshot::new(identity())
            ),
            Err(RecentSnapshotConversionError::CapacityExceeded {
                capacity: 1,
                required: 2
            })
        ));
        assert!(matches!(
            convert_canonical_recent_snapshot::<0, _>(
                &recent,
                &TestFinalizedSnapshot::new(identity())
            ),
            Err(RecentSnapshotConversionError::CapacityExceeded {
                capacity: 0,
                required: 1
            })
        ));
        Ok(())
    }

    #[test]
    fn identity_mismatches_fail_before_any_lookup() -> FixtureResult<()> {
        let recent = snapshot(vec![standard_create_and_spend_block(ScriptType::P2PKH)?])?;
        let wrong_height = RecentSnapshotIdentity::new(
            2,
            FINALIZED_HEIGHT - 1,
            BlockHash(FINALIZED_HASH).bytes_in_display_order(),
            1,
            7,
            9,
        );
        let finalized = TestFinalizedSnapshot::new(wrong_height);
        assert!(matches!(
            convert_canonical_recent_snapshot::<2, _>(&recent, &finalized),
            Err(RecentSnapshotConversionError::FinalizedHeightMismatch { .. })
        ));
        assert_eq!(finalized.calls(), 0);

        let wrong_hash = RecentSnapshotIdentity::new(2, FINALIZED_HEIGHT, [0xee; 32], 1, 7, 9);
        let finalized = TestFinalizedSnapshot::new(wrong_hash);
        assert!(matches!(
            convert_canonical_recent_snapshot::<2, _>(&recent, &finalized),
            Err(RecentSnapshotConversionError::FinalizedHashMismatch { .. })
        ));
        assert_eq!(finalized.calls(), 0);
        Ok(())
    }

    #[test]
    fn invalid_public_identity_fields_fail_before_any_lookup() -> FixtureResult<()> {
        let recent = snapshot(vec![standard_create_and_spend_block(ScriptType::P2PKH)?])?;
        let unknown_network = RecentSnapshotIdentity::new(
            3,
            FINALIZED_HEIGHT,
            BlockHash(FINALIZED_HASH).bytes_in_display_order(),
            1,
            7,
            9,
        );
        let finalized = TestFinalizedSnapshot::new(unknown_network);
        assert!(matches!(
            convert_canonical_recent_snapshot::<2, _>(&recent, &finalized),
            Err(RecentSnapshotConversionError::UnknownNetworkTag { network_tag: 3 })
        ));
        assert_eq!(finalized.calls(), 0);

        let zero_schema = RecentSnapshotIdentity::new(
            2,
            FINALIZED_HEIGHT,
            BlockHash(FINALIZED_HASH).bytes_in_display_order(),
            0,
            7,
            9,
        );
        let finalized = TestFinalizedSnapshot::new(zero_schema);
        assert!(matches!(
            convert_canonical_recent_snapshot::<2, _>(&recent, &finalized),
            Err(RecentSnapshotConversionError::ZeroSchemaVersion)
        ));
        assert_eq!(finalized.calls(), 0);

        let zero_projection_epoch = RecentSnapshotIdentity::new(
            2,
            FINALIZED_HEIGHT,
            BlockHash(FINALIZED_HASH).bytes_in_display_order(),
            1,
            0,
            9,
        );
        let finalized = TestFinalizedSnapshot::new(zero_projection_epoch);
        assert!(matches!(
            convert_canonical_recent_snapshot::<2, _>(&recent, &finalized),
            Err(RecentSnapshotConversionError::ZeroProjectionEpoch)
        ));
        assert_eq!(finalized.calls(), 0);
        Ok(())
    }

    #[test]
    fn p2pkh_and_p2sh_keys_match_layout_derivation() -> FixtureResult<()> {
        let txid = [0xc1; 32];
        let p2pkh_hash = [0xc2; 20];
        let p2sh_hash = [0xc3; 20];
        let recent = snapshot(vec![indexed_block(
            FINALIZED_HEIGHT + 1,
            TIP_HASH,
            FINALIZED_HASH,
            vec![transaction(
                0,
                txid,
                vec![TxInCompact::null_prevout()],
                vec![
                    output(1, p2pkh_hash, ScriptType::P2PKH)?,
                    output(2, p2sh_hash, ScriptType::P2SH)?,
                ],
            )],
        )?])?;
        let converted = convert_canonical_recent_snapshot::<2, _>(
            &recent,
            &TestFinalizedSnapshot::new(identity()),
        )?;

        assert_eq!(
            occupied_change(&converted, 0)?.address_key(),
            &derive_standard_address_key(
                LayoutNetwork::Regtest,
                1,
                StandardAddress::new(StandardScriptKind::PayToPublicKeyHash, p2pkh_hash)
            )
        );
        assert_eq!(
            occupied_change(&converted, 1)?.address_key(),
            &derive_standard_address_key(
                LayoutNetwork::Regtest,
                1,
                StandardAddress::new(StandardScriptKind::PayToScriptHash, p2sh_hash)
            )
        );
        Ok(())
    }

    #[test]
    fn repeated_conversion_and_content_digest_are_deterministic() -> FixtureResult<()> {
        let recent = snapshot(vec![standard_create_and_spend_block(ScriptType::P2SH)?])?;
        let finalized = TestFinalizedSnapshot::new(identity());

        let first = convert_canonical_recent_snapshot::<4, _>(&recent, &finalized)?;
        let second = convert_canonical_recent_snapshot::<4, _>(&recent, &finalized)?;

        assert_eq!(first.slots(), second.slots());
        assert_eq!(
            content_digest(first.slots()),
            content_digest(second.slots())
        );
        assert_eq!(first.recent_tip_height(), FINALIZED_HEIGHT + 1);
        assert_eq!(
            first.recent_tip_hash_display(),
            &BlockHash(TIP_HASH).bytes_in_display_order()
        );
        Ok(())
    }
}
