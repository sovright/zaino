//! Ordinal-only frozen recent-state input for the listener-free query model.
//!
//! The read interface deliberately accepts only a public slot ordinal. It
//! cannot receive an address, transaction identifier, or query-derived key.
//! Occupied transitions use canonical oldest-to-newest ordinal order; larger
//! ordinals are later effects when the same outpoint appears twice.
//! The optional Zaino adapter builds from one value-coherent chain-index
//! capture and binds its opaque non-finalized revision into a whole-serving-
//! epoch lease. The listener-free runtime returns a response only after
//! re-observing that exact boundary and passing the lease's final double
//! currentness check.
//! This remains a listener-free research model; it does not supply a
//! process-wide service owner or keep the lease through a transport write.

use std::fmt;

use blake2::{Blake2s256, Digest};

#[cfg(feature = "corpus-zaino")]
use crate::canonical_chain::CanonicalNetwork;
use crate::records::{AddressKey, TransparentUtxo, ADDRESS_KEY_BYTES};

mod publication;
#[cfg(test)]
pub(crate) use publication::serving_epoch_for_tests;
#[cfg(feature = "corpus-zaino")]
pub(super) use publication::FinalizedServingStore;
#[cfg(test)]
use publication::RecentSnapshotLineageError;
#[cfg(feature = "corpus-zaino")]
pub(super) use publication::ServingEpochReleaseWitness;
#[cfg(feature = "corpus-zaino")]
pub(crate) use publication::{CanonicalServingEpochCurrentness, RecentSnapshotRefreshController};
pub(super) use publication::{FrozenRecentSnapshot, RecentSnapshotLineage};
pub(super) use publication::{
    ServingEpochBoundary, ServingEpochCurrentness, ServingEpochLease, ServingEpochStore,
};
#[cfg(test)]
pub(crate) use publication::{ServingEpochObservation, ServingEpochUnavailable};
#[cfg(feature = "corpus-zaino")]
mod zaino;

const CONTENT_DIGEST_DOMAIN: &[u8] = b"zaino-oram-recent-snapshot-content-v1";
const LINEAGE_BINDING_DOMAIN: &[u8] = b"zaino-oram-recent-snapshot-lineage-v1";
const QUERY_BINDING_DOMAIN: &[u8] = b"zaino-oram-recent-snapshot-query-v2";

/// Public checkpoint seam that owns one immutable recent snapshot.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct RecentSnapshotIdentity {
    network_tag: u8,
    finalized_height: u32,
    finalized_hash_display: [u8; 32],
    schema_version: u32,
    projection_epoch: u64,
    key_epoch: u64,
}

impl RecentSnapshotIdentity {
    #[cfg(feature = "corpus-zaino")]
    /// Derives the shared finalized-serving identity from typed projection fields.
    pub(super) const fn from_finalized_projection(
        network: CanonicalNetwork,
        finalized_height: u32,
        finalized_hash_display: [u8; 32],
        schema_version: u32,
        projection_epoch: u64,
        key_epoch: u64,
    ) -> Self {
        let network_tag = match network {
            CanonicalNetwork::Mainnet => 0,
            CanonicalNetwork::Testnet => 1,
            CanonicalNetwork::Regtest => 2,
        };
        Self::new(
            network_tag,
            finalized_height,
            finalized_hash_display,
            schema_version,
            projection_epoch,
            key_epoch,
        )
    }

    pub(super) const fn new(
        network_tag: u8,
        finalized_height: u32,
        finalized_hash_display: [u8; 32],
        schema_version: u32,
        projection_epoch: u64,
        key_epoch: u64,
    ) -> Self {
        Self {
            network_tag,
            finalized_height,
            finalized_hash_display,
            schema_version,
            projection_epoch,
            key_epoch,
        }
    }

    pub(super) const fn network_tag(&self) -> u8 {
        self.network_tag
    }

    pub(super) const fn finalized_height(&self) -> u32 {
        self.finalized_height
    }

    pub(super) const fn finalized_hash_display(&self) -> &[u8; 32] {
        &self.finalized_hash_display
    }

    pub(super) const fn schema_version(&self) -> u32 {
        self.schema_version
    }

    pub(super) const fn projection_epoch(&self) -> u64 {
        self.projection_epoch
    }

    pub(super) const fn key_epoch(&self) -> u64 {
        self.key_epoch
    }
}

impl fmt::Debug for RecentSnapshotIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RecentSnapshotIdentity { ..REDACTED.. }")
    }
}

/// One public-chain change represented in a frozen recent snapshot.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum RecentUtxoChangeKind {
    /// A recent block created the output.
    Created,
    /// A recent block spent the output.
    Spent,
}

/// One fixed recent output transition.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct RecentUtxoChange {
    kind: RecentUtxoChangeKind,
    address_key: AddressKey,
    utxo: TransparentUtxo,
}

impl RecentUtxoChange {
    const fn new(
        kind: RecentUtxoChangeKind,
        address_key: AddressKey,
        utxo: TransparentUtxo,
    ) -> Self {
        Self {
            kind,
            address_key,
            utxo,
        }
    }

    pub(super) const fn kind(&self) -> RecentUtxoChangeKind {
        self.kind
    }

    pub(super) const fn address_key(&self) -> &AddressKey {
        &self.address_key
    }

    pub(super) const fn utxo(&self) -> &TransparentUtxo {
        &self.utxo
    }
}

impl fmt::Debug for RecentUtxoChange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RecentUtxoChange { ..REDACTED.. }")
    }
}

/// One occupied or canonical dummy slot in a frozen recent snapshot.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct RecentSnapshotSlot {
    occupied: bool,
    change: RecentUtxoChange,
}

impl RecentSnapshotSlot {
    /// Returns the canonical dummy slot used after an injected read failure.
    pub(super) const fn dummy() -> Self {
        Self {
            occupied: false,
            change: RecentUtxoChange::new(
                RecentUtxoChangeKind::Created,
                AddressKey::new([0; ADDRESS_KEY_BYTES]),
                TransparentUtxo::dummy(),
            ),
        }
    }

    /// Builds one occupied recent output-creation slot.
    pub(super) const fn created(address_key: AddressKey, utxo: TransparentUtxo) -> Self {
        Self::occupied(RecentUtxoChangeKind::Created, address_key, utxo)
    }

    /// Builds one occupied recent output-spend slot.
    pub(super) const fn spent(address_key: AddressKey, utxo: TransparentUtxo) -> Self {
        Self::occupied(RecentUtxoChangeKind::Spent, address_key, utxo)
    }

    const fn occupied(
        kind: RecentUtxoChangeKind,
        address_key: AddressKey,
        utxo: TransparentUtxo,
    ) -> Self {
        Self {
            occupied: true,
            change: RecentUtxoChange::new(kind, address_key, utxo),
        }
    }

    pub(super) const fn change(&self) -> Option<&RecentUtxoChange> {
        if self.occupied {
            Some(&self.change)
        } else {
            None
        }
    }
}

impl fmt::Debug for RecentSnapshotSlot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RecentSnapshotSlot { ..REDACTED.. }")
    }
}

/// Commits every fixed snapshot slot in public ordinal order.
pub(super) fn content_digest<const N: usize>(slots: &[RecentSnapshotSlot; N]) -> [u8; 32] {
    let mut hasher = Blake2s256::new();
    Digest::update(&mut hasher, CONTENT_DIGEST_DOMAIN);
    Digest::update(&mut hasher, (N as u128).to_be_bytes());
    for slot in slots {
        Digest::update(&mut hasher, [u8::from(slot.occupied)]);
        Digest::update(
            &mut hasher,
            [match slot.change.kind {
                RecentUtxoChangeKind::Created => 0,
                RecentUtxoChangeKind::Spent => 1,
            }],
        );
        Digest::update(&mut hasher, slot.change.address_key.as_bytes());
        Digest::update(&mut hasher, slot.change.utxo.txid());
        Digest::update(&mut hasher, slot.change.utxo.output_index().to_be_bytes());
        Digest::update(&mut hasher, slot.change.utxo.value_zat().to_be_bytes());
        Digest::update(&mut hasher, slot.change.utxo.height().to_be_bytes());
        Digest::update(
            &mut hasher,
            (slot.change.utxo.script_len() as u128).to_be_bytes(),
        );
        Digest::update(&mut hasher, slot.change.utxo.padded_script());
    }
    finalize_digest(hasher)
}

/// Binds one slot commitment to its finalized seam, recent tip, and generation.
pub(super) fn lineage_binding_digest(
    lineage: RecentSnapshotLineage,
    snapshot_content_digest: [u8; 32],
) -> [u8; 32] {
    let finalized = lineage.finalized();
    let mut hasher = Blake2s256::new();
    Digest::update(&mut hasher, LINEAGE_BINDING_DOMAIN);
    Digest::update(&mut hasher, lineage.generation().to_be_bytes());
    Digest::update(&mut hasher, [finalized.network_tag]);
    Digest::update(&mut hasher, finalized.finalized_height.to_be_bytes());
    Digest::update(&mut hasher, finalized.finalized_hash_display);
    Digest::update(&mut hasher, finalized.schema_version.to_be_bytes());
    Digest::update(&mut hasher, finalized.projection_epoch.to_be_bytes());
    Digest::update(&mut hasher, finalized.key_epoch.to_be_bytes());
    Digest::update(&mut hasher, lineage.recent_tip_height().to_be_bytes());
    Digest::update(&mut hasher, lineage.recent_tip_hash_display());
    Digest::update(&mut hasher, snapshot_content_digest);
    finalize_digest(hasher)
}

/// Binds continuation state to both the request and frozen snapshot lineage.
pub(super) fn bind_query_digest(
    query_digest: [u8; 32],
    recent_snapshot_binding_digest: [u8; 32],
) -> [u8; 32] {
    let mut hasher = Blake2s256::new();
    Digest::update(&mut hasher, QUERY_BINDING_DOMAIN);
    Digest::update(&mut hasher, query_digest);
    Digest::update(&mut hasher, recent_snapshot_binding_digest);
    finalize_digest(hasher)
}

fn finalize_digest(hasher: Blake2s256) -> [u8; 32] {
    let digest = Digest::finalize(hasher);
    let mut output = [0; 32];
    output.copy_from_slice(&digest);
    output
}

/// One ordinal read from the injected frozen snapshot could not complete.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct RecentSnapshotReadError;

impl fmt::Display for RecentSnapshotReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("frozen recent-snapshot read failed")
    }
}

impl std::error::Error for RecentSnapshotReadError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::records::TXID_BYTES;

    const FINALIZED_HASH: [u8; 32] = [0x31; 32];
    const RECENT_TIP_HASH: [u8; 32] = [0x32; 32];

    fn address(byte: u8) -> AddressKey {
        AddressKey::new([byte; ADDRESS_KEY_BYTES])
    }

    const fn identity() -> RecentSnapshotIdentity {
        RecentSnapshotIdentity::new(0, 100, FINALIZED_HASH, 1, 7, 9)
    }

    fn lineage(
        generation: u64,
        recent_tip_height: u32,
        recent_tip_hash_display: [u8; 32],
    ) -> RecentSnapshotLineage {
        RecentSnapshotLineage::from_parts_for_tests(
            generation,
            identity(),
            recent_tip_height,
            recent_tip_hash_display,
        )
        .expect("lineage fixture is internally consistent")
    }

    fn utxo(
        txid_byte: u8,
        output_index: u32,
        value_zat: u64,
        height: u32,
        script: &[u8],
    ) -> TransparentUtxo {
        TransparentUtxo::new(
            [txid_byte; TXID_BYTES],
            output_index,
            value_zat,
            height,
            script,
        )
        .expect("commitment fixture script fits the fixed transparent record")
    }

    #[test]
    fn content_commitment_covers_every_slot_field_and_ordinal() {
        let base_utxo = utxo(1, 2, 3, 4, &[0x51]);
        let base = RecentSnapshotSlot::created(address(1), base_utxo);
        let base_digest = content_digest(&[base]);
        let unoccupied_same_payload = RecentSnapshotSlot {
            occupied: false,
            change: base.change,
        };
        let variants = [
            unoccupied_same_payload,
            RecentSnapshotSlot::spent(address(1), base_utxo),
            RecentSnapshotSlot::created(address(2), base_utxo),
            RecentSnapshotSlot::created(address(1), utxo(2, 2, 3, 4, &[0x51])),
            RecentSnapshotSlot::created(address(1), utxo(1, 3, 3, 4, &[0x51])),
            RecentSnapshotSlot::created(address(1), utxo(1, 2, 4, 4, &[0x51])),
            RecentSnapshotSlot::created(address(1), utxo(1, 2, 3, 5, &[0x51])),
            RecentSnapshotSlot::created(address(1), utxo(1, 2, 3, 4, &[0x52])),
            RecentSnapshotSlot::created(address(1), utxo(1, 2, 3, 4, &[0x51, 0x00])),
        ];
        for variant in variants {
            assert_ne!(content_digest(&[variant]), base_digest);
        }

        let other = RecentSnapshotSlot::created(address(2), utxo(9, 8, 7, 6, &[0x53]));
        assert_ne!(
            content_digest(&[base, other]),
            content_digest(&[other, base])
        );
        assert_ne!(
            content_digest(&[base]),
            content_digest(&[base, RecentSnapshotSlot::dummy()])
        );
    }

    #[test]
    fn lineage_binding_covers_generation_tip_and_snapshot_contents() {
        let snapshot_content = content_digest(&[RecentSnapshotSlot::created(
            address(1),
            utxo(1, 2, 3, 4, &[0x51]),
        )]);
        let base = lineage_binding_digest(lineage(1, 101, RECENT_TIP_HASH), snapshot_content);
        let variants = [
            lineage_binding_digest(lineage(2, 101, RECENT_TIP_HASH), snapshot_content),
            lineage_binding_digest(lineage(1, 102, RECENT_TIP_HASH), snapshot_content),
            lineage_binding_digest(lineage(1, 101, [0x33; 32]), snapshot_content),
            lineage_binding_digest(
                lineage(1, 101, RECENT_TIP_HASH),
                content_digest(&[RecentSnapshotSlot::dummy()]),
            ),
        ];
        for variant in variants {
            assert_ne!(variant, base);
        }

        let finalized_variants = [
            RecentSnapshotIdentity::new(1, 100, FINALIZED_HASH, 1, 7, 9),
            RecentSnapshotIdentity::new(0, 99, FINALIZED_HASH, 1, 7, 9),
            RecentSnapshotIdentity::new(0, 100, [0x30; 32], 1, 7, 9),
            RecentSnapshotIdentity::new(0, 100, FINALIZED_HASH, 2, 7, 9),
            RecentSnapshotIdentity::new(0, 100, FINALIZED_HASH, 1, 8, 9),
            RecentSnapshotIdentity::new(0, 100, FINALIZED_HASH, 1, 7, 10),
        ];
        for finalized in finalized_variants {
            let variant_lineage =
                RecentSnapshotLineage::from_parts_for_tests(1, finalized, 101, RECENT_TIP_HASH)
                    .expect("field-sensitivity lineage remains internally consistent");
            assert_ne!(
                lineage_binding_digest(variant_lineage, snapshot_content),
                base
            );
        }
    }

    #[test]
    fn lineage_rejects_zero_generation_and_invalid_seam_bounds() {
        assert_eq!(
            RecentSnapshotLineage::from_parts_for_tests(0, identity(), 101, RECENT_TIP_HASH),
            Err(RecentSnapshotLineageError::ZeroGeneration)
        );
        assert_eq!(
            RecentSnapshotLineage::from_parts_for_tests(1, identity(), 99, RECENT_TIP_HASH),
            Err(RecentSnapshotLineageError::RecentTipBelowFinalized)
        );
        assert_eq!(
            RecentSnapshotLineage::from_parts_for_tests(1, identity(), 100, RECENT_TIP_HASH),
            Err(RecentSnapshotLineageError::SeamTipHashMismatch)
        );
        assert!(
            RecentSnapshotLineage::from_parts_for_tests(1, identity(), 100, FINALIZED_HASH).is_ok()
        );
    }

    #[test]
    fn continuation_binding_covers_query_and_lineage_commitments() {
        let snapshot_binding = lineage_binding_digest(
            lineage(1, 101, RECENT_TIP_HASH),
            content_digest(&[RecentSnapshotSlot::created(
                address(1),
                utxo(1, 2, 3, 4, &[0x51]),
            )]),
        );
        let other_snapshot_binding = lineage_binding_digest(
            lineage(2, 101, RECENT_TIP_HASH),
            content_digest(&[RecentSnapshotSlot::dummy()]),
        );
        assert_ne!(
            bind_query_digest([1; 32], snapshot_binding),
            bind_query_digest([2; 32], snapshot_binding)
        );
        assert_ne!(
            bind_query_digest([1; 32], snapshot_binding),
            bind_query_digest([1; 32], other_snapshot_binding)
        );
    }
}
