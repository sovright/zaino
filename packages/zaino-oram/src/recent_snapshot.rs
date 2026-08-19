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

use std::{collections::BTreeSet, fmt};

use blake2::{Blake2s256, Digest};

#[cfg(feature = "corpus-zaino")]
use crate::canonical_chain::CanonicalNetwork;
use crate::records::{AddressKey, TransparentUtxo, ADDRESS_KEY_BYTES, TXID_BYTES};

mod publication;
#[cfg(any(test, feature = "wallet-parity-harness"))]
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
#[cfg(any(test, feature = "wallet-parity-harness"))]
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

/// A published slot array together with the facts no query can influence.
///
/// Both carried facts are functions of the slot array alone. Semantic validity
/// asks whether every repeated outpoint in the snapshot is one address's
/// create-then-spend pair; per-ordinal liveness asks whether a later slot
/// supersedes that ordinal's change. Neither reads a query. Computing them once
/// here, when a generation is published, replaces two `N^2` per-query sweeps in
/// the engine with `O(1)` reads.
///
/// This costs nothing in leakage: the results are public generation-wide shape,
/// identical for every query against the generation, exactly like slot
/// occupancy which the engine already branches on. The engine still sweeps
/// every slot on every query; only the per-slot work shrinks.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct RecentSnapshotScan<const N: usize> {
    slots: [RecentSnapshotSlot; N],
    live: [bool; N],
    semantically_valid: bool,
}

impl<const N: usize> RecentSnapshotScan<N> {
    /// Precomputes the query-independent snapshot facts once, at publication.
    ///
    /// Both facts are equi-joins of the snapshot with itself on outpoint, so
    /// one `(outpoint, address, ordinal)` ordering serves both and each fact
    /// then falls out of a single linear scan over equal-outpoint runs. The
    /// shared sort is what keeps publication at `O(N log N)`; deriving either
    /// fact from the unordered array costs the `N^2` ordered-pair sweep this
    /// replaces.
    pub(super) fn from_slots(slots: [RecentSnapshotSlot; N]) -> Self {
        let grouped = grouped_occupied_changes(&slots);
        let semantically_valid = snapshot_is_semantically_valid(&grouped);
        let live = creation_liveness(&grouped);
        Self {
            slots,
            live,
            semantically_valid,
        }
    }

    /// Injects independently derived facts so a test can compare derivations.
    #[cfg(test)]
    pub(crate) const fn from_parts_for_tests(
        slots: [RecentSnapshotSlot; N],
        live: [bool; N],
        semantically_valid: bool,
    ) -> Self {
        Self {
            slots,
            live,
            semantically_valid,
        }
    }

    pub(super) const fn slots(&self) -> &[RecentSnapshotSlot; N] {
        &self.slots
    }

    /// Returns whether every repeated outpoint is a single address's
    /// create-then-spend pair in ordinal order.
    pub(super) const fn semantically_valid(&self) -> bool {
        self.semantically_valid
    }

    /// Returns, per ordinal, whether no later slot supersedes that change.
    pub(super) const fn liveness(&self) -> &[bool; N] {
        &self.live
    }

    /// Simulates post-publication slot corruption without touching the facts
    /// derived from the uncorrupted array, which is what corruption means.
    #[cfg(test)]
    pub(crate) fn replace_slot(&mut self, ordinal: usize, slot: RecentSnapshotSlot) {
        if let Some(destination) = self.slots.get_mut(ordinal) {
            *destination = slot;
        }
    }
}

impl<const N: usize> fmt::Debug for RecentSnapshotScan<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RecentSnapshotScan { ..REDACTED.. }")
    }
}

/// One occupied snapshot change, decorated with the key both facts group by.
///
/// Publication-time only, so this holds ordinary copies of public snapshot
/// fields and compares them with ordinary operators. It exists to be sorted:
/// both facts below are equi-joins on outpoint, and sorting collapses each
/// join into a walk over consecutive equal-outpoint runs.
struct GroupedChange {
    txid: [u8; TXID_BYTES],
    output_index: u32,
    address_key: [u8; ADDRESS_KEY_BYTES],
    ordinal: usize,
    kind: RecentUtxoChangeKind,
}

impl GroupedChange {
    /// Returns whether two changes restate the same outpoint.
    fn has_same_outpoint(&self, other: &Self) -> bool {
        self.txid == other.txid && self.output_index == other.output_index
    }

    /// Returns whether two changes restate one address's same outpoint.
    fn has_same_outpoint_and_address(&self, other: &Self) -> bool {
        self.has_same_outpoint(other) && self.address_key == other.address_key
    }
}

/// Orders every occupied change by `(outpoint, address, ordinal)`.
///
/// Publication-time only: this takes the snapshot and nothing else, runs once
/// per generation, and never observes a query, so an ordinary comparison sort
/// is appropriate and its data-dependent branching carries no per-query
/// signal. Unoccupied slots are dropped here because neither fact consults
/// them.
///
/// The ordering is total and the ordinal tiebreak makes it deterministic, so
/// a published generation derives the same facts on any host.
fn grouped_occupied_changes<const N: usize>(slots: &[RecentSnapshotSlot; N]) -> Vec<GroupedChange> {
    let mut grouped: Vec<GroupedChange> = slots
        .iter()
        .enumerate()
        .filter_map(|(ordinal, slot)| {
            let change = slot.change()?;
            Some(GroupedChange {
                txid: *change.utxo().txid(),
                output_index: change.utxo().output_index(),
                address_key: *change.address_key().as_bytes(),
                ordinal,
                kind: change.kind(),
            })
        })
        .collect();
    grouped.sort_unstable_by(|left, right| {
        left.txid
            .cmp(&right.txid)
            .then(left.output_index.cmp(&right.output_index))
            .then(left.address_key.cmp(&right.address_key))
            .then(left.ordinal.cmp(&right.ordinal))
    });
    grouped
}

/// Returns whether repeated outpoints are all one address's create-then-spend
/// pair, in ordinal order.
///
/// Equivalent to the ordered-pair sweep this replaces: that sweep constrained
/// every earlier/later pair sharing an outpoint, and every such pair lies
/// inside one run here.
fn snapshot_is_semantically_valid(grouped: &[GroupedChange]) -> bool {
    let mut valid = true;
    for group in grouped.chunk_by(GroupedChange::has_same_outpoint) {
        valid &= outpoint_group_is_one_create_then_spend(group);
    }
    valid
}

/// Returns whether one equal-outpoint run is a single create-then-spend pair.
///
/// A third occurrence is unconditionally malformed and needs no field
/// comparison: the middle change would have to be the spend closing the first
/// pair and the creation opening the second at once, which the ordered-pair
/// sweep rejected through those same two pairs.
fn outpoint_group_is_one_create_then_spend(group: &[GroupedChange]) -> bool {
    match group {
        [] | [_] => true,
        [earlier, later] => {
            earlier.address_key == later.address_key
                && earlier.kind == RecentUtxoChangeKind::Created
                && later.kind == RecentUtxoChangeKind::Spent
        }
        _ => false,
    }
}

/// Returns, per ordinal, whether no later slot restates that ordinal's
/// outpoint for the same address.
///
/// Publication-time only, for the same reason as [`grouped_occupied_changes`].
/// Unoccupied ordinals keep the vacuous `true`; the engine never consults them.
///
/// Each run holds one address's restatements of one outpoint in ascending
/// ordinal order, so exactly its last member has no later restatement — which
/// is the predicate this replaces, evaluated once per run instead of once per
/// ordered pair.
fn creation_liveness<const N: usize>(grouped: &[GroupedChange]) -> [bool; N] {
    let mut live = [true; N];
    for group in grouped.chunk_by(GroupedChange::has_same_outpoint_and_address) {
        let Some((_, superseded)) = group.split_last() else {
            continue;
        };
        for change in superseded {
            if let Some(destination) = live.get_mut(change.ordinal) {
                *destination = false;
            }
        }
    }
    live
}

/// Returns every address whose stored annotations one pass must recompute.
///
/// ADR 0902 obligation 6. An annotation is a pure function of `(record, owner,
/// published snapshot)`, so a record already annotated for the previous
/// generation can only need a new value if the snapshot's content for its owner
/// changed. Every such owner appears in one of the two snapshots, because each
/// occupied slot carries the owning address key. The delta of newly stored
/// records supplies the rest: those had no annotation to keep.
///
/// Taking `previous` rather than the generation's finalized delta is what makes
/// the pass correct. A snapshot entry that disappears without finalizing --- a
/// reorged spend --- changes an annotation while emitting no finalized delta
/// event, so a delta-only visit set leaves the record marked `survives = false`
/// and invisible to its owner. `previous` is `None` only for the first
/// generation, which has no prior annotations to correct.
///
/// This is publication-time work over public data (obligation 3), so it uses an
/// ordinary ordered set. The ordering is by address key, not by slot ordinal, so
/// the visit order is reproducible from `(source, generation)` and does not leak
/// the snapshot's internal layout.
pub(super) fn annotation_visit_set<const N: usize>(
    current: &[RecentSnapshotSlot; N],
    previous: Option<&[RecentSnapshotSlot; N]>,
    appended_since_last_pass: impl IntoIterator<Item = AddressKey>,
) -> BTreeSet<AddressKey> {
    let snapshots = std::iter::once(current).chain(previous);
    snapshots
        .flat_map(|slots| slots.iter().filter_map(RecentSnapshotSlot::change))
        .map(|change| *change.address_key())
        .chain(appended_since_last_pass)
        .collect()
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

    /// ADR 0902 obligation 6. The address whose only appearance is in the
    /// *previous* snapshot is the one a finalized-delta-only pass would miss:
    /// its spend was reorged away, so it emits no delta event, and the record it
    /// marked `survives = false` would stay invisible to its owner.
    #[test]
    fn the_visit_set_keeps_the_owner_whose_recent_spend_vanished_without_finalizing() {
        let reorged = address(0xa1);
        let still_present = address(0xa2);
        let newly_stored = address(0xa3);
        let spend = utxo(0xb1, 0, 1, 1, &[0x51]);

        let previous = [
            RecentSnapshotSlot::spent(reorged, spend),
            RecentSnapshotSlot::created(still_present, spend),
        ];
        let current = [
            RecentSnapshotSlot::created(still_present, spend),
            RecentSnapshotSlot::dummy(),
        ];

        assert_eq!(
            annotation_visit_set(&current, Some(&previous), [newly_stored]),
            BTreeSet::from([reorged, still_present, newly_stored])
        );

        // Without the prior generation there is nothing to correct, and the
        // unoccupied slot contributes no owner.
        assert_eq!(
            annotation_visit_set(&current, None, []),
            BTreeSet::from([still_present])
        );
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
