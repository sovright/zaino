use std::{fmt, num::NonZeroU64};

#[cfg(feature = "corpus-zaino")]
use blake2::{Blake2s256, Digest};
#[cfg(feature = "rostl-experimental")]
use rostl_primitives::traits::Cmov;

/// Byte length of an address-derived ORAM key.
pub(super) const ADDRESS_KEY_BYTES: usize = 32;

/// Byte length of a Zcash transaction identifier.
pub(super) const TXID_BYTES: usize = 32;

/// Fixed storage reserved for a supported transparent locking script.
///
/// The research corpus gate must confirm that every script accepted by the
/// private transparent-address API fits this bound. Unsupported shapes fail
/// closed instead of entering a variable-length fallback.
pub(super) const TRANSPARENT_SCRIPT_CAPACITY: usize = 34;

/// Exact byte width of the append-only event candidate exercised by the
/// experimental ORAM adapter.
const PERSISTENT_UTXO_EVENT_BYTES: usize = 72;

/// Exact byte width of one immutable protected-directory cell.
const PERSISTENT_ADDRESS_DIRECTORY_BYTES: usize = 38;

/// Exact byte width of one immutable one-event protected page.
const PERSISTENT_ADDRESS_EVENT_PAGE_BYTES: usize = 82;

/// Number of records in every selected hybrid base/add/spend page.
const FIXED_UTXO_PAGE_ENTRIES: usize = 16;

/// Exact byte width of the self-binding header on a fixed hybrid page.
const PERSISTENT_FIXED_UTXO_PAGE_HEADER_BYTES: usize = 56;

/// Exact byte width of one selected hybrid base/add/spend page.
const PERSISTENT_FIXED_UTXO_PAGE_BYTES: usize = PERSISTENT_FIXED_UTXO_PAGE_HEADER_BYTES
    + (FIXED_UTXO_PAGE_ENTRIES * PERSISTENT_UTXO_EVENT_BYTES);

const UTXO_EVENT_FORMAT_VERSION: u8 = 1;
const UTXO_EVENT_FLAG_MINED: u8 = 1 << 0;
const UTXO_EVENT_FLAG_SPENT: u8 = 1 << 1;
const UTXO_EVENT_KNOWN_FLAGS: u8 = UTXO_EVENT_FLAG_MINED | UTXO_EVENT_FLAG_SPENT;
const ADDRESS_CELL_FORMAT_VERSION: u8 = 1;
const ADDRESS_CELL_FLAG_OCCUPIED: u8 = 1 << 0;
/// The stored record carries a published join answer for the current generation.
const ADDRESS_CELL_FLAG_ANNOTATED: u8 = 1 << 1;
/// The annotated record survives the published recent snapshot.
const ADDRESS_CELL_FLAG_SURVIVES: u8 = 1 << 2;
/// The annotated record's recent-snapshot relation is semantically valid.
const ADDRESS_CELL_FLAG_VALID: u8 = 1 << 3;
/// A directory cell has no annotation, so only the occupancy bit is legal.
const ADDRESS_DIRECTORY_CELL_FLAGS: u8 = ADDRESS_CELL_FLAG_OCCUPIED;
/// An event page may additionally carry the three annotation bits.
const ADDRESS_EVENT_CELL_FLAGS: u8 = ADDRESS_CELL_FLAG_OCCUPIED
    | ADDRESS_CELL_FLAG_ANNOTATED
    | ADDRESS_CELL_FLAG_SURVIVES
    | ADDRESS_CELL_FLAG_VALID;
const FIXED_UTXO_PAGE_FORMAT_VERSION: u8 = 1;
#[cfg(feature = "corpus-zaino")]
const PERSISTENT_UTXO_EVENT_COMMITMENT_DOMAIN: &[u8] =
    b"zaino-oram-persistent-utxo-event-commitment-v1";

/// A domain-separated digest of a canonical transparent locking script.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(super) struct AddressKey([u8; ADDRESS_KEY_BYTES]);

impl AddressKey {
    /// Builds an address key from an already domain-separated digest.
    pub(super) const fn new(bytes: [u8; ADDRESS_KEY_BYTES]) -> Self {
        Self(bytes)
    }

    /// Returns the fixed digest bytes.
    pub(super) const fn as_bytes(&self) -> &[u8; ADDRESS_KEY_BYTES] {
        &self.0
    }
}

impl fmt::Debug for AddressKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AddressKey([REDACTED; 32])")
    }
}

/// A fixed-shape transparent UTXO record returned by the private engine.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct TransparentUtxo {
    txid: [u8; TXID_BYTES],
    output_index: u32,
    value_zat: u64,
    height: u32,
    script_len: u8,
    script: [u8; TRANSPARENT_SCRIPT_CAPACITY],
}

impl TransparentUtxo {
    pub(super) const fn dummy() -> Self {
        Self {
            txid: [0; TXID_BYTES],
            output_index: 0,
            value_zat: 0,
            height: 0,
            script_len: 0,
            script: [0; TRANSPARENT_SCRIPT_CAPACITY],
        }
    }

    /// Selects `replacement` when `mask` is all ones, otherwise keeps `self`.
    ///
    /// Callers must pass either `0` or `usize::MAX`. This arithmetic form is
    /// intended to avoid source-level secret-dependent control flow; Rust and
    /// LLVM do not guarantee that the emitted machine code remains branchless.
    pub(super) fn conditional_select(self, replacement: Self, mask: usize) -> Self {
        let byte_mask = mask as u8;
        let word_mask = mask as u32;
        let wide_mask = mask as u64;
        let mut txid = self.txid;
        for (selected, replacement) in txid.iter_mut().zip(replacement.txid) {
            *selected = (*selected & !byte_mask) | (replacement & byte_mask);
        }
        let mut script = self.script;
        for (selected, replacement) in script.iter_mut().zip(replacement.script) {
            *selected = (*selected & !byte_mask) | (replacement & byte_mask);
        }
        Self {
            txid,
            output_index: (self.output_index & !word_mask) | (replacement.output_index & word_mask),
            value_zat: (self.value_zat & !wide_mask) | (replacement.value_zat & wide_mask),
            height: (self.height & !word_mask) | (replacement.height & word_mask),
            script_len: (self.script_len & !byte_mask) | (replacement.script_len & byte_mask),
            script,
        }
    }

    /// Validates and builds a fixed transparent UTXO.
    pub(super) fn new(
        txid: [u8; TXID_BYTES],
        output_index: u32,
        value_zat: u64,
        height: u32,
        script: &[u8],
    ) -> Result<Self, UtxoRecordError> {
        if script.len() > TRANSPARENT_SCRIPT_CAPACITY {
            return Err(UtxoRecordError::ScriptTooLong {
                actual: script.len(),
                capacity: TRANSPARENT_SCRIPT_CAPACITY,
            });
        }
        let mut fixed_script = [0; TRANSPARENT_SCRIPT_CAPACITY];
        fixed_script[..script.len()].copy_from_slice(script);
        Ok(Self {
            txid,
            output_index,
            value_zat,
            height,
            script_len: script.len() as u8,
            script: fixed_script,
        })
    }

    /// Returns the transaction identifier.
    pub(super) const fn txid(&self) -> &[u8; TXID_BYTES] {
        &self.txid
    }

    /// Returns the transparent output index.
    pub(super) const fn output_index(&self) -> u32 {
        self.output_index
    }

    /// Returns the output value in zatoshis.
    pub(super) const fn value_zat(&self) -> u64 {
        self.value_zat
    }

    /// Returns the mined height.
    pub(super) const fn height(&self) -> u32 {
        self.height
    }

    /// Returns the occupied locking-script byte length.
    pub(super) const fn script_len(&self) -> usize {
        self.script_len as usize
    }

    /// Returns every real and padded locking-script byte.
    pub(super) const fn padded_script(&self) -> &[u8; TRANSPARENT_SCRIPT_CAPACITY] {
        &self.script
    }
}

impl fmt::Debug for TransparentUtxo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TransparentUtxo { ..REDACTED.. }")
    }
}

/// A fixed UTXO record rejected a non-representable business value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum UtxoRecordError {
    /// The locking script exceeds the fixed record capacity.
    ScriptTooLong {
        /// Received byte length.
        actual: usize,
        /// Fixed record capacity.
        capacity: usize,
    },
}

impl fmt::Display for UtxoRecordError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ScriptTooLong { actual, capacity } => write!(
                f,
                "transparent script has {actual} bytes; fixed record capacity is {capacity}"
            ),
        }
    }
}

impl std::error::Error for UtxoRecordError {}

/// Append-only operation represented by one fixed event record.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum UtxoEventKind {
    Created,
    Spent,
}

impl UtxoEventKind {
    const fn to_byte(self) -> u8 {
        match self {
            Self::Created => 1,
            Self::Spent => 2,
        }
    }

    const fn try_from_byte(value: u8) -> Result<Self, PersistentUtxoEventError> {
        match value {
            1 => Ok(Self::Created),
            2 => Ok(Self::Spent),
            actual => Err(PersistentUtxoEventError::InvalidEventKind { actual }),
        }
    }
}

/// Fixed script classification retained by an append-only event.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum UtxoScriptClass {
    PayToPublicKeyHash,
    PayToScriptHash,
    NonStandard,
}

impl UtxoScriptClass {
    const fn to_byte(self) -> u8 {
        match self {
            Self::PayToPublicKeyHash => 0,
            Self::PayToScriptHash => 1,
            Self::NonStandard => 2,
        }
    }

    const fn try_from_byte(value: u8) -> Result<Self, PersistentUtxoEventError> {
        match value {
            0 => Ok(Self::PayToPublicKeyHash),
            1 => Ok(Self::PayToScriptHash),
            2 => Ok(Self::NonStandard),
            actual => Err(PersistentUtxoEventError::InvalidScriptClass { actual }),
        }
    }
}

/// Business-layer event folded into a private transparent UTXO result.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct UtxoEvent {
    kind: UtxoEventKind,
    txid: [u8; TXID_BYTES],
    output_index: u32,
    value_zat: u64,
    height: u32,
    script_class: UtxoScriptClass,
    script_hash: [u8; 20],
    mined: bool,
    spent: bool,
}

impl UtxoEvent {
    /// Builds a finalized output-creation event.
    pub(super) const fn created(
        txid: [u8; TXID_BYTES],
        output_index: u32,
        value_zat: u64,
        height: u32,
        script_class: UtxoScriptClass,
        script_hash: [u8; 20],
    ) -> Self {
        Self::with_kind(
            UtxoEventKind::Created,
            txid,
            output_index,
            value_zat,
            height,
            script_class,
            script_hash,
        )
    }

    /// Builds a finalized output-spend event.
    pub(super) const fn spent(
        txid: [u8; TXID_BYTES],
        output_index: u32,
        value_zat: u64,
        height: u32,
        script_class: UtxoScriptClass,
        script_hash: [u8; 20],
    ) -> Self {
        Self::with_kind(
            UtxoEventKind::Spent,
            txid,
            output_index,
            value_zat,
            height,
            script_class,
            script_hash,
        )
    }

    const fn with_kind(
        kind: UtxoEventKind,
        txid: [u8; TXID_BYTES],
        output_index: u32,
        value_zat: u64,
        height: u32,
        script_class: UtxoScriptClass,
        script_hash: [u8; 20],
    ) -> Self {
        Self {
            kind,
            txid,
            output_index,
            value_zat,
            height,
            script_class,
            script_hash,
            mined: true,
            spent: matches!(kind, UtxoEventKind::Spent),
        }
    }

    const fn kind(&self) -> UtxoEventKind {
        self.kind
    }

    const fn txid(&self) -> &[u8; TXID_BYTES] {
        &self.txid
    }

    const fn output_index(&self) -> u32 {
        self.output_index
    }

    pub(super) const fn value_zat(&self) -> u64 {
        self.value_zat
    }

    const fn height(&self) -> u32 {
        self.height
    }

    pub(super) const fn script_class(&self) -> UtxoScriptClass {
        self.script_class
    }

    pub(super) const fn script_hash(&self) -> &[u8; 20] {
        &self.script_hash
    }

    fn has_canonical_finalized_state(&self) -> bool {
        self.mined
            && self.spent
                == match self.kind {
                    UtxoEventKind::Created => false,
                    UtxoEventKind::Spent => true,
                }
    }

    fn has_same_outpoint(&self, other: &Self) -> bool {
        self.txid == other.txid && self.output_index == other.output_index
    }

    fn is_valid_spend_of(&self, created: &Self) -> bool {
        self.kind == UtxoEventKind::Spent
            && created.kind == UtxoEventKind::Created
            && self.has_canonical_finalized_state()
            && created.has_canonical_finalized_state()
            && self.has_same_outpoint(created)
            && self.value_zat == created.value_zat
            && self.height >= created.height
            && self.script_class == created.script_class
            && self.script_hash == created.script_hash
    }

    fn created_utxo(&self) -> Option<TransparentUtxo> {
        if self.kind != UtxoEventKind::Created || !self.has_canonical_finalized_state() {
            return None;
        }

        let mut script = [0; TRANSPARENT_SCRIPT_CAPACITY];
        let script_len = match self.script_class {
            UtxoScriptClass::PayToPublicKeyHash => {
                script[..3].copy_from_slice(&[0x76, 0xa9, 0x14]);
                script[3..23].copy_from_slice(&self.script_hash);
                script[23..25].copy_from_slice(&[0x88, 0xac]);
                25
            }
            UtxoScriptClass::PayToScriptHash => {
                script[..2].copy_from_slice(&[0xa9, 0x14]);
                script[2..22].copy_from_slice(&self.script_hash);
                script[22] = 0x87;
                23
            }
            UtxoScriptClass::NonStandard => return None,
        };
        Some(TransparentUtxo {
            txid: self.txid,
            output_index: self.output_index,
            value_zat: self.value_zat,
            height: self.height,
            script_len,
            script,
        })
    }
}

impl fmt::Debug for UtxoEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("UtxoEvent { ..REDACTED.. }")
    }
}

#[derive(Clone, Copy)]
struct FinalizedCreation {
    ordinal: usize,
    event: UtxoEvent,
    utxo: TransparentUtxo,
    spent: bool,
}

/// One live output and the history ordinal of the creation that produced it.
///
/// The two indices differ: spent creations keep their history ordinal but
/// contribute no live slot. The query addresses outputs by live slot, while the
/// annotation pass writes to the stored event at its ordinal, so anything that
/// crosses between them needs both (ADR 0902).
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct FinalizedLiveSlot {
    ordinal: usize,
    utxo: TransparentUtxo,
}

impl FinalizedLiveSlot {
    /// Returns the history ordinal of the creating event.
    pub(super) const fn ordinal(self) -> usize {
        self.ordinal
    }

    /// Returns the live output the creation yields.
    pub(super) const fn utxo(self) -> TransparentUtxo {
        self.utxo
    }
}

impl fmt::Debug for FinalizedLiveSlot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FinalizedLiveSlot { ..REDACTED.. }")
    }
}

/// Identifier-free failure while folding one complete padded finalized history.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum FinalizedEventHistoryError {
    /// Fixed scratch storage could not be reserved.
    AllocationFailed,
    /// The event sequence is not a canonical finalized create/spend history.
    Invalid,
}

/// Selects one creation-order dense live slot from a complete padded history.
///
/// A thin selector over [`finalized_live_slots`], which holds the validation
/// contract. Both the fold and this selection are fixed-width in the history
/// length, so neither reveals how many outputs the address holds.
pub(super) fn finalized_live_utxo_at(
    history: &[Option<UtxoEvent>],
    logical_slot: usize,
    maximum_finalized_height: u32,
) -> Result<Option<TransparentUtxo>, FinalizedEventHistoryError> {
    if logical_slot >= history.len() {
        return Err(FinalizedEventHistoryError::Invalid);
    }
    Ok(finalized_live_slots(history, maximum_finalized_height)?
        .get(logical_slot)
        .copied()
        .flatten()
        .map(FinalizedLiveSlot::utxo))
}

/// Folds a complete padded event history into its creation-order live slots.
///
/// Every event is validated before any slot is returned. Padding must be a
/// contiguous suffix, creations must be unique, and each spend must match one
/// earlier live creation. A spend at the creation height is valid because a
/// later transaction in the same finalized block can consume the output.
///
/// The result is always the history's width, holding the live slots as a dense
/// prefix, so its length is the public fixed page width rather than the address's
/// live-output count.
pub(super) fn finalized_live_slots(
    history: &[Option<UtxoEvent>],
    maximum_finalized_height: u32,
) -> Result<Vec<Option<FinalizedLiveSlot>>, FinalizedEventHistoryError> {
    let mut creations = Vec::new();
    creations
        .try_reserve_exact(history.len())
        .map_err(|_| FinalizedEventHistoryError::AllocationFailed)?;
    creations.resize(history.len(), None::<FinalizedCreation>);
    let mut padding_started = false;
    let mut last_height = None;
    let mut invalid = false;
    for (ordinal, entry) in history.iter().enumerate() {
        let mut first_empty = None;
        let mut matching_index = None;
        let mut matching_count = 0_usize;
        for (index, creation) in creations.iter().enumerate() {
            match creation {
                Some(creation)
                    if entry.is_some_and(|event| creation.event.has_same_outpoint(&event)) =>
                {
                    matching_count = matching_count.saturating_add(1);
                    if matching_index.is_none() {
                        matching_index = Some(index);
                    }
                }
                Some(_) => {}
                None => {
                    if first_empty.is_none() {
                        first_empty = Some(index);
                    }
                }
            }
        }

        let Some(event) = entry else {
            padding_started = true;
            continue;
        };
        invalid |= padding_started
            || !event.has_canonical_finalized_state()
            || event.height > maximum_finalized_height
            || last_height.is_some_and(|height| event.height < height);
        last_height =
            Some(last_height.map_or(event.height, |height: u32| height.max(event.height)));
        match event.kind {
            UtxoEventKind::Created => {
                invalid |= matching_count != 0;
                let utxo = event.created_utxo();
                invalid |= utxo.is_none();
                match (first_empty, utxo) {
                    (Some(index), Some(utxo)) if matching_count == 0 => {
                        creations[index] = Some(FinalizedCreation {
                            ordinal,
                            event: *event,
                            utxo,
                            spent: false,
                        });
                    }
                    (Some(_), Some(_)) | (Some(_), None) => {}
                    (None, _) => invalid = true,
                }
            }
            UtxoEventKind::Spent => {
                invalid |= matching_count != 1;
                if let Some(index) = matching_index {
                    match creations.get_mut(index).and_then(Option::as_mut) {
                        Some(created)
                            if matching_count == 1
                                && !created.spent
                                && event.is_valid_spend_of(&created.event) =>
                        {
                            created.spent = true;
                        }
                        Some(_) | None => invalid = true,
                    }
                }
            }
        }
    }

    let mut selected = Vec::new();
    selected
        .try_reserve_exact(history.len())
        .map_err(|_| FinalizedEventHistoryError::AllocationFailed)?;
    selected.resize(history.len(), None::<FinalizedLiveSlot>);
    let mut live_slot = 0_usize;
    for creation in creations.into_iter().flatten() {
        if !creation.spent {
            match selected.get_mut(live_slot) {
                Some(entry) => {
                    *entry = Some(FinalizedLiveSlot {
                        ordinal: creation.ordinal,
                        utxo: creation.utxo,
                    });
                }
                None => invalid = true,
            }
            match live_slot.checked_add(1) {
                Some(next) => live_slot = next,
                None => invalid = true,
            }
        }
    }
    if invalid {
        Err(FinalizedEventHistoryError::Invalid)
    } else {
        Ok(selected)
    }
}

/// Exact, padding-free storage representation of [`UtxoEvent`].
///
/// The byte-array representation makes its width and initialization explicit.
/// With `rostl-experimental`, the derive verifies the exact candidate satisfies
/// `rostl`'s `Pod` requirement; trace-oblivious execution remains limited to
/// the separately gated Linux x86_64 adapter.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(
    feature = "rostl-experimental",
    derive(bytemuck::Pod, bytemuck::Zeroable)
)]
pub(super) struct PersistentUtxoEvent([u8; PERSISTENT_UTXO_EVENT_BYTES]);

const _: [(); PERSISTENT_UTXO_EVENT_BYTES] = [(); std::mem::size_of::<PersistentUtxoEvent>()];

impl PersistentUtxoEvent {
    pub(super) fn from_business(src: &UtxoEvent) -> Self {
        let mut bytes = [0; PERSISTENT_UTXO_EVENT_BYTES];
        bytes[0] = UTXO_EVENT_FORMAT_VERSION;
        bytes[1] = src.kind.to_byte();
        bytes[2] = src.script_class.to_byte();
        bytes[3] = (u8::from(src.mined) * UTXO_EVENT_FLAG_MINED)
            | (u8::from(src.spent) * UTXO_EVENT_FLAG_SPENT);
        bytes[4..36].copy_from_slice(&src.txid);
        bytes[36..40].copy_from_slice(&src.output_index.to_le_bytes());
        bytes[40..48].copy_from_slice(&src.value_zat.to_le_bytes());
        bytes[48..52].copy_from_slice(&src.height.to_le_bytes());
        bytes[52..72].copy_from_slice(&src.script_hash);
        Self(bytes)
    }

    pub(super) fn into_business(self) -> Result<UtxoEvent, PersistentUtxoEventError> {
        if self.0[0] != UTXO_EVENT_FORMAT_VERSION {
            return Err(PersistentUtxoEventError::UnsupportedVersion { actual: self.0[0] });
        }
        let flags = self.0[3];
        if flags & !UTXO_EVENT_KNOWN_FLAGS != 0 {
            return Err(PersistentUtxoEventError::InvalidFlags { actual: flags });
        }
        let kind = UtxoEventKind::try_from_byte(self.0[1])?;
        let mined = flags & UTXO_EVENT_FLAG_MINED != 0;
        let spent = flags & UTXO_EVENT_FLAG_SPENT != 0;
        match (kind, mined, spent) {
            (UtxoEventKind::Created, true, false) | (UtxoEventKind::Spent, true, true) => {}
            (UtxoEventKind::Created, mined, spent) => {
                return Err(PersistentUtxoEventError::InvalidCreatedState { mined, spent });
            }
            (UtxoEventKind::Spent, mined, spent) => {
                return Err(PersistentUtxoEventError::InvalidSpentState { mined, spent });
            }
        }

        let mut txid = [0; TXID_BYTES];
        txid.copy_from_slice(&self.0[4..36]);
        let mut script_hash = [0; 20];
        script_hash.copy_from_slice(&self.0[52..72]);
        let output_index = u32::from_le_bytes(
            self.0[36..40]
                .try_into()
                .map_err(|_| PersistentUtxoEventError::InvalidFixedLayout)?,
        );
        let value_zat = u64::from_le_bytes(
            self.0[40..48]
                .try_into()
                .map_err(|_| PersistentUtxoEventError::InvalidFixedLayout)?,
        );
        let height = u32::from_le_bytes(
            self.0[48..52]
                .try_into()
                .map_err(|_| PersistentUtxoEventError::InvalidFixedLayout)?,
        );
        let script_class = UtxoScriptClass::try_from_byte(self.0[2])?;
        Ok(match kind {
            UtxoEventKind::Created => UtxoEvent::created(
                txid,
                output_index,
                value_zat,
                height,
                script_class,
                script_hash,
            ),
            UtxoEventKind::Spent => UtxoEvent::spent(
                txid,
                output_index,
                value_zat,
                height,
                script_class,
                script_hash,
            ),
        })
    }
}

/// Commits to the exact named persistence-boundary encoding of one event.
///
/// Keeping this helper beside [`PersistentUtxoEvent`] prevents the projection
/// accumulator from duplicating the on-disk field layout or adding byte
/// accessors to the persistence-only type.
#[cfg(feature = "corpus-zaino")]
pub(super) fn persistent_utxo_event_commitment(src: &UtxoEvent) -> [u8; 32] {
    let persistent = PersistentUtxoEvent::from_business(src);
    let mut hasher = Blake2s256::new();
    hasher.update(PERSISTENT_UTXO_EVENT_COMMITMENT_DOMAIN);
    hasher.update(persistent.0);
    let digest = hasher.finalize();
    let mut commitment = [0; 32];
    commitment.copy_from_slice(&digest);
    commitment
}

impl Default for PersistentUtxoEvent {
    fn default() -> Self {
        Self([0; PERSISTENT_UTXO_EVENT_BYTES])
    }
}

#[cfg(feature = "rostl-experimental")]
impl rostl_primitives::traits::Cmov for PersistentUtxoEvent {
    fn cmov(&mut self, other: &Self, choice: bool) {
        cmov_pod_bytes(self, other, choice);
    }

    fn cxchg(&mut self, other: &mut Self, choice: bool) {
        cxchg_pod_bytes(self, other, choice);
    }
}

#[cfg(feature = "rostl-experimental")]
fn cmov_pod_bytes<T: bytemuck::Pod>(destination: &mut T, source: &T, choice: bool) {
    for (destination, source) in bytemuck::bytes_of_mut(destination)
        .iter_mut()
        .zip(bytemuck::bytes_of(source))
    {
        rostl_primitives::traits::Cmov::cmov(destination, source, choice);
    }
}

#[cfg(feature = "rostl-experimental")]
fn cxchg_pod_bytes<T: bytemuck::Pod>(left: &mut T, right: &mut T, choice: bool) {
    for (left, right) in bytemuck::bytes_of_mut(left)
        .iter_mut()
        .zip(bytemuck::bytes_of_mut(right))
    {
        rostl_primitives::traits::Cmov::cxchg(left, right, choice);
    }
}

impl fmt::Debug for PersistentUtxoEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PersistentUtxoEvent([REDACTED])")
    }
}

/// Fixed event bytes rejected during storage-boundary validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PersistentUtxoEventError {
    UnsupportedVersion { actual: u8 },
    InvalidEventKind { actual: u8 },
    InvalidScriptClass { actual: u8 },
    InvalidFlags { actual: u8 },
    InvalidCreatedState { mined: bool, spent: bool },
    InvalidSpentState { mined: bool, spent: bool },
    InvalidFixedLayout,
}

impl fmt::Display for PersistentUtxoEventError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedVersion { actual } => {
                write!(f, "unsupported persistent UTXO event version {actual}")
            }
            Self::InvalidEventKind { actual } => {
                write!(f, "invalid persistent UTXO event kind {actual}")
            }
            Self::InvalidScriptClass { actual } => {
                write!(f, "invalid persistent UTXO script class {actual}")
            }
            Self::InvalidFlags { actual } => {
                write!(f, "invalid persistent UTXO event flags {actual}")
            }
            Self::InvalidCreatedState { mined, spent } => write!(
                f,
                "persistent created UTXO event has invalid state mined={mined}, spent={spent}"
            ),
            Self::InvalidSpentState { mined, spent } => write!(
                f,
                "persistent spent UTXO event has invalid state mined={mined}, spent={spent}"
            ),
            Self::InvalidFixedLayout => {
                f.write_str("persistent UTXO event has an invalid fixed layout")
            }
        }
    }
}

impl std::error::Error for PersistentUtxoEventError {}

/// Public table class encoded into every selected hybrid page.
///
/// Base and add pages contain created events; spend pages contain spent events.
/// Keeping the class in the record prevents a page from being accepted in a
/// different logical domain solely because its opaque ORAM key collides or is
/// misrouted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FixedUtxoPageKind {
    Base,
    Add,
    Spend,
}

impl FixedUtxoPageKind {
    const fn to_byte(self) -> u8 {
        match self {
            Self::Base => 1,
            Self::Add => 2,
            Self::Spend => 3,
        }
    }

    const fn expected_event_kind(self) -> UtxoEventKind {
        match self {
            Self::Base | Self::Add => UtxoEventKind::Created,
            Self::Spend => UtxoEventKind::Spent,
        }
    }

    const fn try_from_byte(value: u8) -> Result<Self, PersistentFixedUtxoPageError> {
        match value {
            1 => Ok(Self::Base),
            2 => Ok(Self::Add),
            3 => Ok(Self::Spend),
            actual => Err(PersistentFixedUtxoPageError::InvalidPageKind { actual }),
        }
    }
}

/// Full logical identity repeated inside every selected hybrid page.
///
/// The address key binds the record to its logical owner. The generation and
/// page ordinal separate the immutable base and active delta records selected
/// by a future manifest. The inclusive height range binds the events summarized
/// by the page. A topology layer must construct a profile-validated manifest
/// identity and require an exact match on all fields before using a decoded
/// real page.
#[derive(Clone, Copy, PartialEq, Eq)]
struct FixedUtxoPageIdentity {
    address_key: AddressKey,
    generation: NonZeroU64,
    page_ordinal: u32,
    lower_height: u32,
    upper_height: u32,
}

impl FixedUtxoPageIdentity {
    fn new(
        address_key: AddressKey,
        generation: u64,
        page_ordinal: u32,
        lower_height: u32,
        upper_height: u32,
    ) -> Result<Self, FixedUtxoPageIdentityError> {
        if lower_height > upper_height {
            return Err(FixedUtxoPageIdentityError::InvalidHeightRange {
                lower: lower_height,
                upper: upper_height,
            });
        }
        Ok(Self {
            address_key,
            generation: NonZeroU64::new(generation)
                .ok_or(FixedUtxoPageIdentityError::ZeroGeneration)?,
            page_ordinal,
            lower_height,
            upper_height,
        })
    }

    const fn address_key(&self) -> &AddressKey {
        &self.address_key
    }

    const fn generation(&self) -> u64 {
        self.generation.get()
    }

    const fn page_ordinal(&self) -> u32 {
        self.page_ordinal
    }

    const fn lower_height(&self) -> u32 {
        self.lower_height
    }

    const fn upper_height(&self) -> u32 {
        self.upper_height
    }

    const fn contains_height(&self, height: u32) -> bool {
        height >= self.lower_height && height <= self.upper_height
    }
}

impl fmt::Debug for FixedUtxoPageIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FixedUtxoPageIdentity { ..REDACTED.. }")
    }
}

/// A selected hybrid page identity is not usable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FixedUtxoPageIdentityError {
    ZeroGeneration,
    InvalidHeightRange { lower: u32, upper: u32 },
}

impl fmt::Display for FixedUtxoPageIdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroGeneration => f.write_str("fixed UTXO page generation must be nonzero"),
            Self::InvalidHeightRange { lower, upper } => write!(
                f,
                "fixed UTXO page height range is invalid: lower {lower}, upper {upper}"
            ),
        }
    }
}

impl std::error::Error for FixedUtxoPageIdentityError {}

/// One fixed 16-entry page in the selected live-base plus add/spend design.
///
/// Real entries always form a prefix and padding is represented only by
/// trailing `None` values. A canonical dummy has no identity or entries but
/// retains its public page class. All real entries belong to one standard
/// address, use canonical `(height, stored txid bytes, output index)` order,
/// and have unique outpoints.
#[derive(Clone, Copy, PartialEq, Eq)]
struct FixedUtxoPage {
    kind: FixedUtxoPageKind,
    identity: Option<FixedUtxoPageIdentity>,
    occupied_entries: u8,
    entries: [Option<UtxoEvent>; FIXED_UTXO_PAGE_ENTRIES],
}

impl FixedUtxoPage {
    const fn dummy(kind: FixedUtxoPageKind) -> Self {
        Self {
            kind,
            identity: None,
            occupied_entries: 0,
            entries: [None; FIXED_UTXO_PAGE_ENTRIES],
        }
    }

    fn real(
        kind: FixedUtxoPageKind,
        identity: FixedUtxoPageIdentity,
        entries: &[UtxoEvent],
        derive_owner_key: &impl Fn(UtxoScriptClass, [u8; 20]) -> AddressKey,
    ) -> Result<Self, FixedUtxoPageError> {
        if entries.is_empty() {
            return Err(FixedUtxoPageError::EmptyRealPage);
        }
        if entries.len() > FIXED_UTXO_PAGE_ENTRIES {
            return Err(FixedUtxoPageError::TooManyEntries {
                actual: entries.len(),
                capacity: FIXED_UTXO_PAGE_ENTRIES,
            });
        }

        let mut fixed_entries = [None; FIXED_UTXO_PAGE_ENTRIES];
        for (destination, entry) in fixed_entries.iter_mut().zip(entries.iter().copied()) {
            *destination = Some(entry);
        }
        Self::from_fixed_entries(
            kind,
            identity,
            entries.len() as u8,
            fixed_entries,
            derive_owner_key,
        )
    }

    fn from_fixed_entries(
        kind: FixedUtxoPageKind,
        identity: FixedUtxoPageIdentity,
        occupied_entries: u8,
        entries: [Option<UtxoEvent>; FIXED_UTXO_PAGE_ENTRIES],
        derive_owner_key: &impl Fn(UtxoScriptClass, [u8; 20]) -> AddressKey,
    ) -> Result<Self, FixedUtxoPageError> {
        validate_fixed_utxo_page_entries(
            kind,
            &identity,
            usize::from(occupied_entries),
            &entries,
            derive_owner_key,
        )?;
        Ok(Self {
            kind,
            identity: Some(identity),
            occupied_entries,
            entries,
        })
    }

    const fn kind(&self) -> FixedUtxoPageKind {
        self.kind
    }

    const fn identity(&self) -> Option<&FixedUtxoPageIdentity> {
        self.identity.as_ref()
    }

    const fn occupied_entries(&self) -> usize {
        self.occupied_entries as usize
    }

    const fn entries(&self) -> &[Option<UtxoEvent>; FIXED_UTXO_PAGE_ENTRIES] {
        &self.entries
    }

    const fn is_dummy(&self) -> bool {
        self.occupied_entries == 0
    }
}

impl fmt::Debug for FixedUtxoPage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FixedUtxoPage { ..REDACTED.. }")
    }
}

fn validate_fixed_utxo_page_entries(
    kind: FixedUtxoPageKind,
    identity: &FixedUtxoPageIdentity,
    occupied_entries: usize,
    entries: &[Option<UtxoEvent>; FIXED_UTXO_PAGE_ENTRIES],
    derive_owner_key: &impl Fn(UtxoScriptClass, [u8; 20]) -> AddressKey,
) -> Result<(), FixedUtxoPageError> {
    if occupied_entries == 0 {
        return Err(FixedUtxoPageError::EmptyRealPage);
    }
    if occupied_entries > FIXED_UTXO_PAGE_ENTRIES {
        return Err(FixedUtxoPageError::TooManyEntries {
            actual: occupied_entries,
            capacity: FIXED_UTXO_PAGE_ENTRIES,
        });
    }

    let expected_kind = kind.expected_event_kind();
    let mut owner = None;
    let mut previous_order = None;

    for (index, entry) in entries.iter().take(occupied_entries).enumerate() {
        let event = entry
            .as_ref()
            .ok_or(FixedUtxoPageError::MissingEntry { index })?;
        if event.kind() != expected_kind {
            return Err(FixedUtxoPageError::WrongEventKind {
                index,
                expected: expected_kind.to_byte(),
                actual: event.kind().to_byte(),
            });
        }
        if !is_standard_address_event(event) {
            return Err(FixedUtxoPageError::NonStandardEvent { index });
        }

        let event_owner = (event.script_class(), *event.script_hash());
        if owner.is_some_and(|owner| owner != event_owner) {
            return Err(FixedUtxoPageError::MixedAddress { index });
        }
        owner = Some(event_owner);

        let order = (event.height(), event.txid(), event.output_index());
        if previous_order.is_some_and(|previous| order < previous) {
            return Err(FixedUtxoPageError::NoncanonicalOrder { index });
        }
        if !identity.contains_height(event.height()) {
            return Err(FixedUtxoPageError::HeightOutOfRange { index });
        }
        previous_order = Some(order);

        if entries[..index]
            .iter()
            .flatten()
            .any(|prior| prior.has_same_outpoint(event))
        {
            return Err(FixedUtxoPageError::DuplicateOutpoint { index });
        }
    }

    if let Some(index) = entries
        .iter()
        .enumerate()
        .skip(occupied_entries)
        .find_map(|(index, entry)| entry.is_some().then_some(index))
    {
        return Err(FixedUtxoPageError::NoncanonicalPadding { index });
    }
    let owner = owner.ok_or(FixedUtxoPageError::EmptyRealPage)?;
    if derive_owner_key(owner.0, owner.1) != *identity.address_key() {
        return Err(FixedUtxoPageError::AddressKeyMismatch { index: 0 });
    }
    Ok(())
}

/// A business record cannot enter a fixed hybrid page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FixedUtxoPageError {
    EmptyRealPage,
    TooManyEntries {
        actual: usize,
        capacity: usize,
    },
    MissingEntry {
        index: usize,
    },
    NoncanonicalPadding {
        index: usize,
    },
    WrongEventKind {
        index: usize,
        expected: u8,
        actual: u8,
    },
    NonStandardEvent {
        index: usize,
    },
    MixedAddress {
        index: usize,
    },
    AddressKeyMismatch {
        index: usize,
    },
    NoncanonicalOrder {
        index: usize,
    },
    HeightOutOfRange {
        index: usize,
    },
    DuplicateOutpoint {
        index: usize,
    },
}

impl fmt::Display for FixedUtxoPageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyRealPage => f.write_str("fixed UTXO page must contain at least one entry"),
            Self::TooManyEntries { actual, capacity } => write!(
                f,
                "fixed UTXO page contains {actual} entries but its capacity is {capacity}"
            ),
            Self::MissingEntry { index } => {
                write!(f, "fixed UTXO page is missing occupied entry {index}")
            }
            Self::NoncanonicalPadding { index } => {
                write!(
                    f,
                    "fixed UTXO page has a real entry in padding slot {index}"
                )
            }
            Self::WrongEventKind {
                index,
                expected,
                actual,
            } => write!(
                f,
                "fixed UTXO page entry {index} has kind {actual}, expected {expected}"
            ),
            Self::NonStandardEvent { index } => {
                write!(f, "fixed UTXO page entry {index} is nonstandard")
            }
            Self::MixedAddress { index } => {
                write!(
                    f,
                    "fixed UTXO page entry {index} belongs to another address"
                )
            }
            Self::AddressKeyMismatch { index } => write!(
                f,
                "fixed UTXO page entry {index} does not derive its page address key"
            ),
            Self::NoncanonicalOrder { index } => write!(
                f,
                "fixed UTXO page entry {index} is below its predecessor in canonical order"
            ),
            Self::HeightOutOfRange { index } => {
                write!(
                    f,
                    "fixed UTXO page entry {index} is outside its height range"
                )
            }
            Self::DuplicateOutpoint { index } => {
                write!(f, "fixed UTXO page entry {index} repeats an outpoint")
            }
        }
    }
}

impl std::error::Error for FixedUtxoPageError {}

/// One immutable 16-entry live-UTXO base page.
#[derive(Clone, Copy, PartialEq, Eq)]
struct BaseUtxoPage16(FixedUtxoPage);

impl BaseUtxoPage16 {
    const fn dummy() -> Self {
        Self(FixedUtxoPage::dummy(FixedUtxoPageKind::Base))
    }

    fn real(
        identity: FixedUtxoPageIdentity,
        entries: &[UtxoEvent],
        derive_owner_key: &impl Fn(UtxoScriptClass, [u8; 20]) -> AddressKey,
    ) -> Result<Self, FixedUtxoPageError> {
        FixedUtxoPage::real(FixedUtxoPageKind::Base, identity, entries, derive_owner_key).map(Self)
    }
}

impl fmt::Debug for BaseUtxoPage16 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BaseUtxoPage16 { ..REDACTED.. }")
    }
}

/// One mutable 16-entry created-event delta page.
#[derive(Clone, Copy, PartialEq, Eq)]
struct AddUtxoPage16(FixedUtxoPage);

impl AddUtxoPage16 {
    const fn dummy() -> Self {
        Self(FixedUtxoPage::dummy(FixedUtxoPageKind::Add))
    }

    fn real(
        identity: FixedUtxoPageIdentity,
        entries: &[UtxoEvent],
        derive_owner_key: &impl Fn(UtxoScriptClass, [u8; 20]) -> AddressKey,
    ) -> Result<Self, FixedUtxoPageError> {
        FixedUtxoPage::real(FixedUtxoPageKind::Add, identity, entries, derive_owner_key).map(Self)
    }
}

impl fmt::Debug for AddUtxoPage16 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AddUtxoPage16 { ..REDACTED.. }")
    }
}

/// One mutable 16-entry spent-event delta page.
#[derive(Clone, Copy, PartialEq, Eq)]
struct SpendUtxoPage16(FixedUtxoPage);

impl SpendUtxoPage16 {
    const fn dummy() -> Self {
        Self(FixedUtxoPage::dummy(FixedUtxoPageKind::Spend))
    }

    fn real(
        identity: FixedUtxoPageIdentity,
        entries: &[UtxoEvent],
        derive_owner_key: &impl Fn(UtxoScriptClass, [u8; 20]) -> AddressKey,
    ) -> Result<Self, FixedUtxoPageError> {
        FixedUtxoPage::real(
            FixedUtxoPageKind::Spend,
            identity,
            entries,
            derive_owner_key,
        )
        .map(Self)
    }
}

impl fmt::Debug for SpendUtxoPage16 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SpendUtxoPage16 { ..REDACTED.. }")
    }
}

/// Exact storage representation shared by the selected base/add/spend tables.
///
/// Bytes `0..56` are a versioned self-binding header:
///
/// - format version, page class, occupied-prefix length, reserved zero byte;
/// - full 32-byte address key;
/// - nonzero generation and page ordinal, little endian; and
/// - inclusive lower and upper heights, little endian.
///
/// The remaining bytes are exactly sixteen 72-byte event slots. Unoccupied
/// slots are all zero. `Default` remains invalid scratch storage so a missed
/// backend read cannot be mistaken for a canonical dummy.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(
    feature = "rostl-experimental",
    derive(bytemuck::Pod, bytemuck::Zeroable)
)]
struct PersistentFixedUtxoPage([u8; PERSISTENT_FIXED_UTXO_PAGE_BYTES]);

const _: [(); PERSISTENT_FIXED_UTXO_PAGE_BYTES] =
    [(); std::mem::size_of::<PersistentFixedUtxoPage>()];

fn encode_fixed_page_identity(
    identity: &FixedUtxoPageIdentity,
) -> [u8; PERSISTENT_FIXED_UTXO_PAGE_HEADER_BYTES - 4] {
    let mut bytes = [0; PERSISTENT_FIXED_UTXO_PAGE_HEADER_BYTES - 4];
    bytes[..ADDRESS_KEY_BYTES].copy_from_slice(identity.address_key().as_bytes());
    bytes[32..40].copy_from_slice(&identity.generation().to_le_bytes());
    bytes[40..44].copy_from_slice(&identity.page_ordinal().to_le_bytes());
    bytes[44..48].copy_from_slice(&identity.lower_height().to_le_bytes());
    bytes[48..52].copy_from_slice(&identity.upper_height().to_le_bytes());
    bytes
}

impl PersistentFixedUtxoPage {
    /// Encodes a validated page outside the protected serving/update path.
    ///
    /// The `_offline` suffix intentionally narrows the repository's canonical
    /// `from_business` name: this variable-work encoder branches on dummy state
    /// and occupancy, so using the shorter name could invite it into a
    /// protected transform. No protected page encode/decode/edit API exists in
    /// this records-only slice.
    fn from_business_offline(src: &FixedUtxoPage) -> Self {
        let mut bytes = [0; PERSISTENT_FIXED_UTXO_PAGE_BYTES];
        bytes[0] = FIXED_UTXO_PAGE_FORMAT_VERSION;
        bytes[1] = src.kind().to_byte();
        bytes[2] = src.occupied_entries;

        if let Some(identity) = src.identity() {
            bytes[4..PERSISTENT_FIXED_UTXO_PAGE_HEADER_BYTES]
                .copy_from_slice(&encode_fixed_page_identity(identity));
        }
        for (slot, event) in src
            .entries()
            .iter()
            .take(src.occupied_entries())
            .flatten()
            .enumerate()
        {
            let start =
                PERSISTENT_FIXED_UTXO_PAGE_HEADER_BYTES + (slot * PERSISTENT_UTXO_EVENT_BYTES);
            bytes[start..start + PERSISTENT_UTXO_EVENT_BYTES]
                .copy_from_slice(&PersistentUtxoEvent::from_business(event).0);
        }
        Self(bytes)
    }

    /// Validates bytes outside the protected serving/update path.
    ///
    /// This decoder intentionally reports precise corruption errors and is
    /// therefore variable-work. Protected reads and mutations must retain this
    /// value as opaque bytes and use a separately audited fixed-work transform
    /// that processes all sixteen slots. Every real header must match the
    /// already profile-validated manifest identity; a canonical dummy has no
    /// stored identity and may satisfy any expected logical page.
    fn into_business_offline(
        self,
        expected_kind: FixedUtxoPageKind,
        expected_identity: FixedUtxoPageIdentity,
        derive_owner_key: &impl Fn(UtxoScriptClass, [u8; 20]) -> AddressKey,
    ) -> Result<FixedUtxoPage, PersistentFixedUtxoPageError> {
        if self.0[0] != FIXED_UTXO_PAGE_FORMAT_VERSION {
            return Err(PersistentFixedUtxoPageError::UnsupportedVersion { actual: self.0[0] });
        }
        let kind = FixedUtxoPageKind::try_from_byte(self.0[1])?;
        if kind != expected_kind {
            return Err(PersistentFixedUtxoPageError::WrongPageKind {
                expected: expected_kind.to_byte(),
                actual: kind.to_byte(),
            });
        }
        let occupied_entries = usize::from(self.0[2]);
        if self.0[3] != 0 {
            return Err(PersistentFixedUtxoPageError::NonzeroReservedByte { actual: self.0[3] });
        }
        if occupied_entries > FIXED_UTXO_PAGE_ENTRIES {
            return Err(PersistentFixedUtxoPageError::OccupancyOutOfRange {
                actual: self.0[2],
                capacity: FIXED_UTXO_PAGE_ENTRIES as u8,
            });
        }
        if occupied_entries == 0 {
            if self.0[3..].iter().any(|byte| *byte != 0) {
                return Err(PersistentFixedUtxoPageError::NoncanonicalDummy);
            }
            return Ok(FixedUtxoPage::dummy(kind));
        }

        let mut address_key = [0; ADDRESS_KEY_BYTES];
        address_key.copy_from_slice(&self.0[4..36]);
        let mut generation = [0; 8];
        generation.copy_from_slice(&self.0[36..44]);
        let mut page_ordinal = [0; 4];
        page_ordinal.copy_from_slice(&self.0[44..48]);
        let mut lower_height = [0; 4];
        lower_height.copy_from_slice(&self.0[48..52]);
        let mut upper_height = [0; 4];
        upper_height.copy_from_slice(&self.0[52..56]);
        let identity = FixedUtxoPageIdentity::new(
            AddressKey::new(address_key),
            u64::from_le_bytes(generation),
            u32::from_le_bytes(page_ordinal),
            u32::from_le_bytes(lower_height),
            u32::from_le_bytes(upper_height),
        )
        .map_err(PersistentFixedUtxoPageError::InvalidIdentity)?;
        if identity != expected_identity {
            return Err(PersistentFixedUtxoPageError::UnexpectedIdentity);
        }

        let mut entries = [None; FIXED_UTXO_PAGE_ENTRIES];
        for (slot, destination) in entries.iter_mut().take(occupied_entries).enumerate() {
            let start =
                PERSISTENT_FIXED_UTXO_PAGE_HEADER_BYTES + (slot * PERSISTENT_UTXO_EVENT_BYTES);
            let mut event = [0; PERSISTENT_UTXO_EVENT_BYTES];
            event.copy_from_slice(&self.0[start..start + PERSISTENT_UTXO_EVENT_BYTES]);
            *destination = Some(
                PersistentUtxoEvent(event)
                    .into_business()
                    .map_err(|error| PersistentFixedUtxoPageError::InvalidEvent {
                        index: slot,
                        error,
                    })?,
            );
        }
        let padding_start = PERSISTENT_FIXED_UTXO_PAGE_HEADER_BYTES
            + (occupied_entries * PERSISTENT_UTXO_EVENT_BYTES);
        if self.0[padding_start..].iter().any(|byte| *byte != 0) {
            return Err(PersistentFixedUtxoPageError::NoncanonicalPadding);
        }

        FixedUtxoPage::from_fixed_entries(kind, identity, self.0[2], entries, derive_owner_key)
            .map_err(PersistentFixedUtxoPageError::InvalidPage)
    }
}

impl Default for PersistentFixedUtxoPage {
    fn default() -> Self {
        Self([0; PERSISTENT_FIXED_UTXO_PAGE_BYTES])
    }
}

impl fmt::Debug for PersistentFixedUtxoPage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PersistentFixedUtxoPage([REDACTED])")
    }
}

#[cfg(feature = "rostl-experimental")]
impl rostl_primitives::traits::Cmov for PersistentFixedUtxoPage {
    fn cmov(&mut self, other: &Self, choice: bool) {
        cmov_pod_bytes(self, other, choice);
    }

    fn cxchg(&mut self, other: &mut Self, choice: bool) {
        cxchg_pod_bytes(self, other, choice);
    }
}

/// Exact 1,208-byte storage representation of [`BaseUtxoPage16`].
#[repr(transparent)]
#[derive(Clone, Copy, Default, PartialEq, Eq)]
#[cfg_attr(
    feature = "rostl-experimental",
    derive(bytemuck::Pod, bytemuck::Zeroable)
)]
pub(super) struct PersistentBaseUtxoPage16(PersistentFixedUtxoPage);

const _: [(); PERSISTENT_FIXED_UTXO_PAGE_BYTES] =
    [(); std::mem::size_of::<PersistentBaseUtxoPage16>()];

impl PersistentBaseUtxoPage16 {
    fn from_business_offline(src: &BaseUtxoPage16) -> Self {
        Self(PersistentFixedUtxoPage::from_business_offline(&src.0))
    }

    fn into_business_offline(
        self,
        expected_identity: FixedUtxoPageIdentity,
        derive_owner_key: &impl Fn(UtxoScriptClass, [u8; 20]) -> AddressKey,
    ) -> Result<BaseUtxoPage16, PersistentFixedUtxoPageError> {
        self.0
            .into_business_offline(FixedUtxoPageKind::Base, expected_identity, derive_owner_key)
            .map(BaseUtxoPage16)
    }
}

impl fmt::Debug for PersistentBaseUtxoPage16 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PersistentBaseUtxoPage16([REDACTED])")
    }
}

#[cfg(feature = "rostl-experimental")]
impl rostl_primitives::traits::Cmov for PersistentBaseUtxoPage16 {
    fn cmov(&mut self, other: &Self, choice: bool) {
        cmov_pod_bytes(self, other, choice);
    }

    fn cxchg(&mut self, other: &mut Self, choice: bool) {
        cxchg_pod_bytes(self, other, choice);
    }
}

/// Exact 1,208-byte storage representation of [`AddUtxoPage16`].
#[repr(transparent)]
#[derive(Clone, Copy, Default, PartialEq, Eq)]
#[cfg_attr(
    feature = "rostl-experimental",
    derive(bytemuck::Pod, bytemuck::Zeroable)
)]
pub(super) struct PersistentAddUtxoPage16(PersistentFixedUtxoPage);

const _: [(); PERSISTENT_FIXED_UTXO_PAGE_BYTES] =
    [(); std::mem::size_of::<PersistentAddUtxoPage16>()];

impl PersistentAddUtxoPage16 {
    fn from_business_offline(src: &AddUtxoPage16) -> Self {
        Self(PersistentFixedUtxoPage::from_business_offline(&src.0))
    }

    fn into_business_offline(
        self,
        expected_identity: FixedUtxoPageIdentity,
        derive_owner_key: &impl Fn(UtxoScriptClass, [u8; 20]) -> AddressKey,
    ) -> Result<AddUtxoPage16, PersistentFixedUtxoPageError> {
        self.0
            .into_business_offline(FixedUtxoPageKind::Add, expected_identity, derive_owner_key)
            .map(AddUtxoPage16)
    }
}

impl fmt::Debug for PersistentAddUtxoPage16 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PersistentAddUtxoPage16([REDACTED])")
    }
}

#[cfg(feature = "rostl-experimental")]
impl rostl_primitives::traits::Cmov for PersistentAddUtxoPage16 {
    fn cmov(&mut self, other: &Self, choice: bool) {
        cmov_pod_bytes(self, other, choice);
    }

    fn cxchg(&mut self, other: &mut Self, choice: bool) {
        cxchg_pod_bytes(self, other, choice);
    }
}

/// Exact 1,208-byte storage representation of [`SpendUtxoPage16`].
#[repr(transparent)]
#[derive(Clone, Copy, Default, PartialEq, Eq)]
#[cfg_attr(
    feature = "rostl-experimental",
    derive(bytemuck::Pod, bytemuck::Zeroable)
)]
pub(super) struct PersistentSpendUtxoPage16(PersistentFixedUtxoPage);

const _: [(); PERSISTENT_FIXED_UTXO_PAGE_BYTES] =
    [(); std::mem::size_of::<PersistentSpendUtxoPage16>()];

impl PersistentSpendUtxoPage16 {
    fn from_business_offline(src: &SpendUtxoPage16) -> Self {
        Self(PersistentFixedUtxoPage::from_business_offline(&src.0))
    }

    fn into_business_offline(
        self,
        expected_identity: FixedUtxoPageIdentity,
        derive_owner_key: &impl Fn(UtxoScriptClass, [u8; 20]) -> AddressKey,
    ) -> Result<SpendUtxoPage16, PersistentFixedUtxoPageError> {
        self.0
            .into_business_offline(
                FixedUtxoPageKind::Spend,
                expected_identity,
                derive_owner_key,
            )
            .map(SpendUtxoPage16)
    }
}

impl fmt::Debug for PersistentSpendUtxoPage16 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PersistentSpendUtxoPage16([REDACTED])")
    }
}

#[cfg(feature = "rostl-experimental")]
impl rostl_primitives::traits::Cmov for PersistentSpendUtxoPage16 {
    fn cmov(&mut self, other: &Self, choice: bool) {
        cmov_pod_bytes(self, other, choice);
    }

    fn cxchg(&mut self, other: &mut Self, choice: bool) {
        cxchg_pod_bytes(self, other, choice);
    }
}

/// Trusted, canonical inputs to one future protected page append.
///
/// This is constructed only from the public canonical projection stream,
/// outside the protected transform. It deliberately carries no prior page,
/// occupancy snapshot, or expected bytes. The transform must derive all of
/// those from the value returned by the protected read.
#[cfg(feature = "rostl-experimental")]
#[derive(Clone, Copy)]
struct FixedPageAppendRequest {
    identity: [u8; PERSISTENT_FIXED_UTXO_PAGE_HEADER_BYTES - 4],
    event: PersistentUtxoEvent,
}

#[cfg(feature = "rostl-experimental")]
impl FixedPageAppendRequest {
    fn new_offline(
        kind: FixedUtxoPageKind,
        identity: FixedUtxoPageIdentity,
        event: UtxoEvent,
        derive_owner_key: &impl Fn(UtxoScriptClass, [u8; 20]) -> AddressKey,
    ) -> Result<Self, FixedUtxoPageError> {
        FixedUtxoPage::real(kind, identity, &[event], derive_owner_key)?;
        Ok(Self {
            identity: encode_fixed_page_identity(&identity),
            event: PersistentUtxoEvent::from_business(&event),
        })
    }
}

#[cfg(feature = "rostl-experimental")]
impl fmt::Debug for FixedPageAppendRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FixedPageAppendRequest { ..REDACTED.. }")
    }
}

#[cfg(feature = "rostl-experimental")]
#[derive(Clone, Copy)]
struct BasePageAppendRequest(FixedPageAppendRequest);

#[cfg(feature = "rostl-experimental")]
impl BasePageAppendRequest {
    fn new_offline(
        identity: FixedUtxoPageIdentity,
        event: UtxoEvent,
        derive_owner_key: &impl Fn(UtxoScriptClass, [u8; 20]) -> AddressKey,
    ) -> Result<Self, FixedUtxoPageError> {
        FixedPageAppendRequest::new_offline(
            FixedUtxoPageKind::Base,
            identity,
            event,
            derive_owner_key,
        )
        .map(Self)
    }
}

#[cfg(feature = "rostl-experimental")]
#[derive(Clone, Copy)]
struct AddPageAppendRequest(FixedPageAppendRequest);

#[cfg(feature = "rostl-experimental")]
impl AddPageAppendRequest {
    fn new_offline(
        identity: FixedUtxoPageIdentity,
        event: UtxoEvent,
        derive_owner_key: &impl Fn(UtxoScriptClass, [u8; 20]) -> AddressKey,
    ) -> Result<Self, FixedUtxoPageError> {
        FixedPageAppendRequest::new_offline(
            FixedUtxoPageKind::Add,
            identity,
            event,
            derive_owner_key,
        )
        .map(Self)
    }
}

#[cfg(feature = "rostl-experimental")]
#[derive(Clone, Copy)]
struct SpendPageAppendRequest(FixedPageAppendRequest);

#[cfg(feature = "rostl-experimental")]
impl SpendPageAppendRequest {
    fn new_offline(
        identity: FixedUtxoPageIdentity,
        event: UtxoEvent,
        derive_owner_key: &impl Fn(UtxoScriptClass, [u8; 20]) -> AddressKey,
    ) -> Result<Self, FixedUtxoPageError> {
        FixedPageAppendRequest::new_offline(
            FixedUtxoPageKind::Spend,
            identity,
            event,
            derive_owner_key,
        )
        .map(Self)
    }
}

/// Raw result of one fixed-work page transition.
///
/// `valid` is secret-derived and must not select whether the future protected
/// write occurs. The two-access owner will always write `replacement`, then
/// classify this bit and fail the generation closed after the full schedule.
/// A found count-zero value is deliberately invalid: canonical dummy pages are
/// cover/padding records, never the stored value of a real logical page key.
/// Only an ORAM-level miss may create that logical page.
#[cfg(feature = "rostl-experimental")]
#[derive(Clone, Copy)]
struct FixedPageAppendTransition<T> {
    replacement: T,
    valid: bool,
}

/// Appends to a base page with one fixed 16-slot schedule.
///
/// `#[inline(never)]` keeps this exact record-class transform addressable for
/// `check-oram-page-codegen`. The transform remains pure and is not wired into
/// an ORAM access.
#[cfg(feature = "rostl-experimental")]
#[inline(never)]
fn fixed_base_page_append(
    prior: PersistentBaseUtxoPage16,
    found: bool,
    request: BasePageAppendRequest,
) -> FixedPageAppendTransition<PersistentBaseUtxoPage16> {
    let transition = fixed_page_append(
        prior.0,
        found,
        request.0,
        FixedUtxoPageKind::Base.to_byte(),
        UtxoEventKind::Created.to_byte(),
        UTXO_EVENT_FLAG_MINED,
    );
    FixedPageAppendTransition {
        replacement: PersistentBaseUtxoPage16(transition.replacement),
        valid: transition.valid,
    }
}

/// Appends to an add page with one fixed 16-slot schedule.
#[cfg(feature = "rostl-experimental")]
#[inline(never)]
fn fixed_add_page_append(
    prior: PersistentAddUtxoPage16,
    found: bool,
    request: AddPageAppendRequest,
) -> FixedPageAppendTransition<PersistentAddUtxoPage16> {
    let transition = fixed_page_append(
        prior.0,
        found,
        request.0,
        FixedUtxoPageKind::Add.to_byte(),
        UtxoEventKind::Created.to_byte(),
        UTXO_EVENT_FLAG_MINED,
    );
    FixedPageAppendTransition {
        replacement: PersistentAddUtxoPage16(transition.replacement),
        valid: transition.valid,
    }
}

/// Appends to a spend page with one fixed 16-slot schedule.
#[cfg(feature = "rostl-experimental")]
#[inline(never)]
fn fixed_spend_page_append(
    prior: PersistentSpendUtxoPage16,
    found: bool,
    request: SpendPageAppendRequest,
) -> FixedPageAppendTransition<PersistentSpendUtxoPage16> {
    let transition = fixed_page_append(
        prior.0,
        found,
        request.0,
        FixedUtxoPageKind::Spend.to_byte(),
        UtxoEventKind::Spent.to_byte(),
        UTXO_EVENT_FLAG_MINED | UTXO_EVENT_FLAG_SPENT,
    );
    FixedPageAppendTransition {
        replacement: PersistentSpendUtxoPage16(transition.replacement),
        valid: transition.valid,
    }
}

/// Retains the three fixed-page transforms for `check-oram-page-codegen`.
///
/// The opaque function-pointer tuple keeps each `#[inline(never)]` wrapper
/// addressable in the linked timing binary without executing a transform. This
/// is only a Linux release-codegen retention anchor; it does not wire the
/// transforms into the ORAM backend.
#[cfg(all(
    feature = "rostl-experimental",
    target_os = "linux",
    target_arch = "x86_64"
))]
pub(super) fn retain_fixed_page_append_codegen() {
    let base: fn(
        PersistentBaseUtxoPage16,
        bool,
        BasePageAppendRequest,
    ) -> FixedPageAppendTransition<PersistentBaseUtxoPage16> = fixed_base_page_append;
    let add: fn(
        PersistentAddUtxoPage16,
        bool,
        AddPageAppendRequest,
    ) -> FixedPageAppendTransition<PersistentAddUtxoPage16> = fixed_add_page_append;
    let spend: fn(
        PersistentSpendUtxoPage16,
        bool,
        SpendPageAppendRequest,
    ) -> FixedPageAppendTransition<PersistentSpendUtxoPage16> = fixed_spend_page_append;
    std::hint::black_box((base, add, spend));
}

#[cfg(feature = "rostl-experimental")]
#[allow(clippy::needless_bitwise_bool)]
#[inline(always)]
fn fixed_page_append(
    prior: PersistentFixedUtxoPage,
    found: bool,
    request: FixedPageAppendRequest,
    expected_page_kind: u8,
    expected_event_kind: u8,
    expected_event_flags: u8,
) -> FixedPageAppendTransition<PersistentFixedUtxoPage> {
    let mut dummy = PersistentFixedUtxoPage::default();
    dummy.0[0] = FIXED_UTXO_PAGE_FORMAT_VERSION;
    dummy.0[1] = expected_page_kind;

    let mut candidate = prior;
    candidate.cmov(&dummy, !found);
    let occupied_before = candidate.0[2];

    for (candidate_byte, identity_byte) in candidate.0[4..PERSISTENT_FIXED_UTXO_PAGE_HEADER_BYTES]
        .iter_mut()
        .zip(request.identity.iter())
    {
        candidate_byte.cmov(identity_byte, !found);
    }
    for slot in 0..FIXED_UTXO_PAGE_ENTRIES {
        let selected = occupied_before == slot as u8;
        let start = PERSISTENT_FIXED_UTXO_PAGE_HEADER_BYTES + (slot * PERSISTENT_UTXO_EVENT_BYTES);
        for byte in 0..PERSISTENT_UTXO_EVENT_BYTES {
            candidate.0[start + byte].cmov(&request.event.0[byte], selected);
        }
    }
    candidate.0[2] = occupied_before.wrapping_add(1);

    let source_was_real_or_missing = !found | (occupied_before != 0);
    let valid = source_was_real_or_missing
        & fixed_page_candidate_is_valid(
            &candidate.0,
            &request,
            expected_page_kind,
            expected_event_kind,
            expected_event_flags,
        );
    let mut replacement = prior;
    replacement.cmov(&candidate, valid);
    FixedPageAppendTransition { replacement, valid }
}

#[cfg(feature = "rostl-experimental")]
#[allow(clippy::needless_bitwise_bool)]
#[inline(always)]
fn fixed_page_candidate_is_valid(
    candidate: &[u8; PERSISTENT_FIXED_UTXO_PAGE_BYTES],
    request: &FixedPageAppendRequest,
    expected_page_kind: u8,
    expected_event_kind: u8,
    expected_event_flags: u8,
) -> bool {
    let occupied = candidate[2];
    let request_script_class = request.event.0[2];
    let mut valid = (candidate[0] == FIXED_UTXO_PAGE_FORMAT_VERSION)
        & (candidate[1] == expected_page_kind)
        & (occupied != 0)
        & (occupied <= FIXED_UTXO_PAGE_ENTRIES as u8)
        & (candidate[3] == 0)
        & ((request_script_class == UtxoScriptClass::PayToPublicKeyHash.to_byte())
            | (request_script_class == UtxoScriptClass::PayToScriptHash.to_byte()));

    for (candidate_byte, identity_byte) in candidate[4..PERSISTENT_FIXED_UTXO_PAGE_HEADER_BYTES]
        .iter()
        .zip(request.identity.iter())
    {
        valid &= candidate_byte == identity_byte;
    }

    let lower_height = fixed_page_u32(candidate, 48);
    let upper_height = fixed_page_u32(candidate, 52);
    let mut generation_nonzero = false;
    for byte in &candidate[36..44] {
        generation_nonzero |= *byte != 0;
    }
    valid &= generation_nonzero & (lower_height <= upper_height);
    for slot in 0..FIXED_UTXO_PAGE_ENTRIES {
        let slot_is_occupied = (slot as u8) < occupied;
        let start = PERSISTENT_FIXED_UTXO_PAGE_HEADER_BYTES + (slot * PERSISTENT_UTXO_EVENT_BYTES);
        let mut zero = true;
        for byte in 0..PERSISTENT_UTXO_EVENT_BYTES {
            zero &= candidate[start + byte] == 0;
        }

        let mut owner_matches = candidate[start + 2] == request_script_class;
        for byte in 0..20 {
            owner_matches &= candidate[start + 52 + byte] == request.event.0[52 + byte];
        }
        let height = fixed_page_u32(candidate, start + 48);
        let event_is_valid = (candidate[start] == UTXO_EVENT_FORMAT_VERSION)
            & (candidate[start + 1] == expected_event_kind)
            & (candidate[start + 3] == expected_event_flags)
            & owner_matches
            & (height >= lower_height)
            & (height <= upper_height);
        valid &= slot_is_occupied | zero;
        valid &= !slot_is_occupied | event_is_valid;
    }

    for current in 1..FIXED_UTXO_PAGE_ENTRIES {
        let current_is_occupied = (current as u8) < occupied;
        let previous_start =
            PERSISTENT_FIXED_UTXO_PAGE_HEADER_BYTES + ((current - 1) * PERSISTENT_UTXO_EVENT_BYTES);
        let current_start =
            PERSISTENT_FIXED_UTXO_PAGE_HEADER_BYTES + (current * PERSISTENT_UTXO_EVENT_BYTES);
        valid &= !current_is_occupied
            | fixed_page_event_ordered(candidate, previous_start, current_start);
    }

    for left in 0..FIXED_UTXO_PAGE_ENTRIES {
        let left_is_occupied = (left as u8) < occupied;
        let left_start =
            PERSISTENT_FIXED_UTXO_PAGE_HEADER_BYTES + (left * PERSISTENT_UTXO_EVENT_BYTES);
        for right in (left + 1)..FIXED_UTXO_PAGE_ENTRIES {
            let both_occupied = left_is_occupied & ((right as u8) < occupied);
            let right_start =
                PERSISTENT_FIXED_UTXO_PAGE_HEADER_BYTES + (right * PERSISTENT_UTXO_EVENT_BYTES);
            valid &= !both_occupied | !fixed_page_same_outpoint(candidate, left_start, right_start);
        }
    }
    valid
}

#[cfg(feature = "rostl-experimental")]
#[inline(always)]
fn fixed_page_u32(bytes: &[u8; PERSISTENT_FIXED_UTXO_PAGE_BYTES], start: usize) -> u32 {
    u32::from_le_bytes([
        bytes[start],
        bytes[start + 1],
        bytes[start + 2],
        bytes[start + 3],
    ])
}

#[cfg(feature = "rostl-experimental")]
#[allow(clippy::needless_bitwise_bool)]
#[inline(always)]
fn fixed_page_event_ordered(
    bytes: &[u8; PERSISTENT_FIXED_UTXO_PAGE_BYTES],
    previous: usize,
    current: usize,
) -> bool {
    let previous_height = fixed_page_u32(bytes, previous + 48);
    let current_height = fixed_page_u32(bytes, current + 48);
    let (txid_less, txid_equal) = fixed_page_txid_relation(bytes, previous + 4, current + 4);
    (previous_height < current_height)
        | ((previous_height == current_height)
            & (txid_less
                | (txid_equal
                    & (fixed_page_u32(bytes, previous + 36)
                        <= fixed_page_u32(bytes, current + 36)))))
}

#[cfg(feature = "rostl-experimental")]
#[allow(clippy::needless_bitwise_bool)]
#[inline(always)]
fn fixed_page_txid_relation(
    bytes: &[u8; PERSISTENT_FIXED_UTXO_PAGE_BYTES],
    left: usize,
    right: usize,
) -> (bool, bool) {
    let mut less = false;
    let mut equal = true;
    for byte in 0..TXID_BYTES {
        less |= equal & (bytes[left + byte] < bytes[right + byte]);
        equal &= bytes[left + byte] == bytes[right + byte];
    }
    (less, equal)
}

#[cfg(feature = "rostl-experimental")]
#[inline(always)]
fn fixed_page_same_outpoint(
    bytes: &[u8; PERSISTENT_FIXED_UTXO_PAGE_BYTES],
    left: usize,
    right: usize,
) -> bool {
    let mut equal = fixed_page_u32(bytes, left + 36) == fixed_page_u32(bytes, right + 36);
    for byte in 0..TXID_BYTES {
        equal &= bytes[left + 4 + byte] == bytes[right + 4 + byte];
    }
    equal
}

/// Invalid bytes in one selected fixed hybrid page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PersistentFixedUtxoPageError {
    UnsupportedVersion {
        actual: u8,
    },
    InvalidPageKind {
        actual: u8,
    },
    WrongPageKind {
        expected: u8,
        actual: u8,
    },
    NonzeroReservedByte {
        actual: u8,
    },
    OccupancyOutOfRange {
        actual: u8,
        capacity: u8,
    },
    NoncanonicalDummy,
    InvalidIdentity(FixedUtxoPageIdentityError),
    UnexpectedIdentity,
    InvalidEvent {
        index: usize,
        error: PersistentUtxoEventError,
    },
    NoncanonicalPadding,
    InvalidPage(FixedUtxoPageError),
}

impl fmt::Display for PersistentFixedUtxoPageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedVersion { actual } => {
                write!(f, "unsupported persistent fixed UTXO page version {actual}")
            }
            Self::InvalidPageKind { actual } => {
                write!(f, "invalid persistent fixed UTXO page kind {actual}")
            }
            Self::WrongPageKind { expected, actual } => write!(
                f,
                "persistent fixed UTXO page kind {actual} does not match table kind {expected}"
            ),
            Self::NonzeroReservedByte { actual } => write!(
                f,
                "persistent fixed UTXO page reserved byte is nonzero: {actual}"
            ),
            Self::OccupancyOutOfRange { actual, capacity } => write!(
                f,
                "persistent fixed UTXO page occupancy {actual} exceeds {capacity}"
            ),
            Self::NoncanonicalDummy => {
                f.write_str("persistent fixed UTXO page dummy has nonzero payload")
            }
            Self::InvalidIdentity(error) => {
                write!(f, "persistent fixed UTXO page identity is invalid: {error}")
            }
            Self::UnexpectedIdentity => {
                f.write_str("persistent fixed UTXO page identity does not match its manifest")
            }
            Self::InvalidEvent { index, error } => write!(
                f,
                "persistent fixed UTXO page entry {index} is invalid: {error}"
            ),
            Self::NoncanonicalPadding => {
                f.write_str("persistent fixed UTXO page has nonzero padding")
            }
            Self::InvalidPage(error) => {
                write!(
                    f,
                    "persistent fixed UTXO page semantics are invalid: {error}"
                )
            }
        }
    }
}

impl std::error::Error for PersistentFixedUtxoPageError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidIdentity(error) => Some(error),
            Self::InvalidEvent { error, .. } => Some(error),
            Self::InvalidPage(error) => Some(error),
            Self::UnsupportedVersion { .. }
            | Self::InvalidPageKind { .. }
            | Self::WrongPageKind { .. }
            | Self::NonzeroReservedByte { .. }
            | Self::OccupancyOutOfRange { .. }
            | Self::NoncanonicalDummy
            | Self::UnexpectedIdentity
            | Self::NoncanonicalPadding => None,
        }
    }
}

/// One immutable cell in a future protected address directory.
///
/// The stored slot is self-described identity, never a truncated address
/// digest. This record layer validates its encoding only. A future protected
/// layout must authenticate the stored slot and address key against the
/// logical key used to read the cell before using it. Empty cells carry no
/// address-bearing payload.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct AddressDirectory {
    occupied: bool,
    directory_slot: u32,
    address_key: AddressKey,
}

impl AddressDirectory {
    pub(super) const fn dummy() -> Self {
        Self {
            occupied: false,
            directory_slot: 0,
            address_key: AddressKey::new([0; ADDRESS_KEY_BYTES]),
        }
    }

    pub(super) const fn real(directory_slot: u32, address_key: AddressKey) -> Self {
        Self {
            occupied: true,
            directory_slot,
            address_key,
        }
    }

    pub(super) const fn is_occupied(&self) -> bool {
        self.occupied
    }

    pub(super) const fn directory_slot(&self) -> u32 {
        self.directory_slot
    }

    pub(super) const fn address_key(&self) -> &AddressKey {
        &self.address_key
    }
}

impl fmt::Debug for AddressDirectory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AddressDirectory { ..REDACTED.. }")
    }
}

/// The publication-time answer to the finalized/recent join for one record.
///
/// Both bits are a function of `(record, its owner, the published recent
/// snapshot)` — public per-generation data — so storing them beside the record
/// leaks nothing a query did not already imply, and makes the per-query join
/// `O(1)` instead of a re-scan of the whole snapshot. The unannotated state is
/// distinct from `Annotated { survives: false, valid: false }`: it means no pass
/// has run for the current generation, which a consumer must not read as a
/// join answer.
///
/// Computing the annotation is deliberately out of scope here. This type is the
/// storage contract the computation will write through.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(super) enum RecordAnnotation {
    #[default]
    Unannotated,
    Annotated {
        survives: bool,
        valid: bool,
    },
}

impl RecordAnnotation {
    /// Encodes the annotation into its address-cell flag bits.
    const fn flag_bits(self) -> u8 {
        match self {
            Self::Unannotated => 0,
            Self::Annotated { survives, valid } => {
                let mut bits = ADDRESS_CELL_FLAG_ANNOTATED;
                if survives {
                    bits |= ADDRESS_CELL_FLAG_SURVIVES;
                }
                if valid {
                    bits |= ADDRESS_CELL_FLAG_VALID;
                }
                bits
            }
        }
    }

    /// Decodes the annotation from already header-validated flag bits.
    ///
    /// The survives/valid bits are meaningless without the annotated bit, so a
    /// cell that sets either of them alone is noncanonical rather than
    /// silently unannotated.
    const fn from_flag_bits(flags: u8) -> Result<Self, PersistentAddressEventPageError> {
        let annotated = flags & ADDRESS_CELL_FLAG_ANNOTATED != 0;
        let survives = flags & ADDRESS_CELL_FLAG_SURVIVES != 0;
        let valid = flags & ADDRESS_CELL_FLAG_VALID != 0;
        if !annotated {
            if survives || valid {
                return Err(PersistentAddressEventPageError::NoncanonicalAnnotation);
            }
            return Ok(Self::Unannotated);
        }
        Ok(Self::Annotated { survives, valid })
    }
}

/// One immutable event-table cell.
///
/// One event per cell is the compatibility baseline for the current append-only
/// candidate. Filling a partially occupied multi-event page would require an
/// upsert, which is unsafe with the current adapter. This record layer does not
/// authenticate the stored directory slot or event ordinal against a logical
/// read key, nor the event script against a directory address key. The future
/// layout must validate all three bindings before using the event.
///
/// The annotation is the one mutable field. It is deliberately excluded from
/// [`PartialEq`] — see the hand-written impl below — so replay identity keeps
/// its append-only meaning.
#[derive(Clone, Copy, Eq)]
pub(super) struct AddressEventPage {
    event: Option<UtxoEvent>,
    directory_slot: u32,
    event_ordinal: u32,
    annotation: RecordAnnotation,
}

/// Compares two pages by their replay identity only.
///
/// The append path decides `AppendDisposition::ExactReplay` and its
/// at-most-one-duplicate uniqueness check from record identity. The annotation
/// is derived per generation and rewritten in place, so including it would make
/// a re-annotated record stop matching its own replay and silently change what
/// a replay is. Byte-exact comparison still exists where it is needed: the
/// persistent encoding keeps its derived `PartialEq`, and the store's
/// compare-and-set reads every byte.
impl PartialEq for AddressEventPage {
    fn eq(&self, other: &Self) -> bool {
        self.event == other.event
            && self.directory_slot == other.directory_slot
            && self.event_ordinal == other.event_ordinal
    }
}

impl AddressEventPage {
    pub(super) const fn dummy() -> Self {
        Self {
            event: None,
            directory_slot: 0,
            event_ordinal: 0,
            annotation: RecordAnnotation::Unannotated,
        }
    }

    pub(super) fn real(
        directory_slot: u32,
        event_ordinal: u32,
        event: UtxoEvent,
    ) -> Result<Self, AddressEventPageError> {
        if !is_standard_address_event(&event) {
            return Err(AddressEventPageError::NonStandardEvent);
        }
        Ok(Self {
            event: Some(event),
            directory_slot,
            event_ordinal,
            annotation: RecordAnnotation::Unannotated,
        })
    }

    /// Returns this page carrying `annotation`.
    ///
    /// Only an occupied page can be annotated: a dummy cell has no record for
    /// the join to answer about, and an annotated dummy would not round-trip
    /// through the canonical all-zero payload check.
    pub(super) fn annotated(
        self,
        annotation: RecordAnnotation,
    ) -> Result<Self, AddressEventPageError> {
        if !self.is_occupied() {
            return Err(AddressEventPageError::AnnotatedDummy);
        }
        Ok(Self { annotation, ..self })
    }

    pub(super) const fn annotation(&self) -> RecordAnnotation {
        self.annotation
    }

    pub(super) const fn is_occupied(&self) -> bool {
        self.event.is_some()
    }

    pub(super) const fn directory_slot(&self) -> u32 {
        self.directory_slot
    }

    pub(super) const fn event_ordinal(&self) -> u32 {
        self.event_ordinal
    }

    pub(super) const fn event(&self) -> Option<&UtxoEvent> {
        self.event.as_ref()
    }
}

impl fmt::Debug for AddressEventPage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AddressEventPage { ..REDACTED.. }")
    }
}

fn is_standard_address_event(event: &UtxoEvent) -> bool {
    matches!(
        event.script_class(),
        UtxoScriptClass::PayToPublicKeyHash | UtxoScriptClass::PayToScriptHash
    )
}

/// A business event cannot enter the private address-event table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AddressEventPageError {
    NonStandardEvent,
    AnnotatedDummy,
}

impl fmt::Display for AddressEventPageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NonStandardEvent => {
                f.write_str("private address-event page requires a standard address event")
            }
            Self::AnnotatedDummy => {
                f.write_str("private address-event dummy cannot carry an annotation")
            }
        }
    }
}

impl std::error::Error for AddressEventPageError {}

/// Exact storage representation of [`AddressDirectory`].
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(
    feature = "rostl-experimental",
    derive(bytemuck::Pod, bytemuck::Zeroable)
)]
pub(super) struct PersistentAddressDirectory([u8; PERSISTENT_ADDRESS_DIRECTORY_BYTES]);

const _: [(); PERSISTENT_ADDRESS_DIRECTORY_BYTES] =
    [(); std::mem::size_of::<PersistentAddressDirectory>()];

impl PersistentAddressDirectory {
    pub(super) fn from_business(src: &AddressDirectory) -> Self {
        let mut bytes = [0; PERSISTENT_ADDRESS_DIRECTORY_BYTES];
        bytes[0] = ADDRESS_CELL_FORMAT_VERSION;
        if src.is_occupied() {
            bytes[1] = ADDRESS_CELL_FLAG_OCCUPIED;
            bytes[2..6].copy_from_slice(&src.directory_slot().to_le_bytes());
            bytes[6..38].copy_from_slice(src.address_key().as_bytes());
        }
        Self(bytes)
    }

    pub(super) fn into_business(self) -> Result<AddressDirectory, PersistentAddressDirectoryError> {
        let flags = decode_address_cell_header(&self.0, ADDRESS_DIRECTORY_CELL_FLAGS)
            .map_err(PersistentAddressDirectoryError::Header)?;
        if flags & ADDRESS_CELL_FLAG_OCCUPIED == 0 {
            if self.0[2..].iter().any(|byte| *byte != 0) {
                return Err(PersistentAddressDirectoryError::NoncanonicalDummy);
            }
            return Ok(AddressDirectory::dummy());
        }
        let mut directory_slot = [0; 4];
        directory_slot.copy_from_slice(&self.0[2..6]);
        let mut address_key = [0; ADDRESS_KEY_BYTES];
        address_key.copy_from_slice(&self.0[6..38]);
        Ok(AddressDirectory::real(
            u32::from_le_bytes(directory_slot),
            AddressKey::new(address_key),
        ))
    }
}

impl Default for PersistentAddressDirectory {
    /// Returns all-zero scratch storage, not a canonical persistent dummy.
    ///
    /// Callers may use this only as an ignored read buffer when the backend
    /// reports that no record was found. Deserializing it correctly fails the
    /// version check. Encode [`AddressDirectory::dummy`] for a real dummy cell.
    fn default() -> Self {
        Self([0; PERSISTENT_ADDRESS_DIRECTORY_BYTES])
    }
}

impl fmt::Debug for PersistentAddressDirectory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PersistentAddressDirectory([REDACTED])")
    }
}

#[cfg(feature = "rostl-experimental")]
impl rostl_primitives::traits::Cmov for PersistentAddressDirectory {
    fn cmov(&mut self, other: &Self, choice: bool) {
        cmov_pod_bytes(self, other, choice);
    }

    fn cxchg(&mut self, other: &mut Self, choice: bool) {
        cxchg_pod_bytes(self, other, choice);
    }
}

/// Exact storage representation of [`AddressEventPage`].
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(
    feature = "rostl-experimental",
    derive(bytemuck::Pod, bytemuck::Zeroable)
)]
pub(super) struct PersistentAddressEventPage([u8; PERSISTENT_ADDRESS_EVENT_PAGE_BYTES]);

const _: [(); PERSISTENT_ADDRESS_EVENT_PAGE_BYTES] =
    [(); std::mem::size_of::<PersistentAddressEventPage>()];

impl PersistentAddressEventPage {
    pub(super) fn from_business(src: &AddressEventPage) -> Self {
        let mut bytes = [0; PERSISTENT_ADDRESS_EVENT_PAGE_BYTES];
        bytes[0] = ADDRESS_CELL_FORMAT_VERSION;
        if let Some(event) = src.event() {
            // The annotation lives in spare flag bits rather than in new
            // payload bytes, so the record width — and with it the ORAM block
            // size every timing and sizing figure is measured against — is
            // unchanged.
            bytes[1] = ADDRESS_CELL_FLAG_OCCUPIED | src.annotation().flag_bits();
            bytes[2..6].copy_from_slice(&src.directory_slot().to_le_bytes());
            bytes[6..10].copy_from_slice(&src.event_ordinal().to_le_bytes());
            bytes[10..].copy_from_slice(&PersistentUtxoEvent::from_business(event).0);
        }
        Self(bytes)
    }

    pub(super) fn into_business(self) -> Result<AddressEventPage, PersistentAddressEventPageError> {
        let flags = decode_address_cell_header(&self.0, ADDRESS_EVENT_CELL_FLAGS)
            .map_err(PersistentAddressEventPageError::Header)?;
        let annotation = RecordAnnotation::from_flag_bits(flags)?;
        if flags & ADDRESS_CELL_FLAG_OCCUPIED == 0 {
            if annotation != RecordAnnotation::Unannotated {
                return Err(PersistentAddressEventPageError::NoncanonicalAnnotation);
            }
            if self.0[2..].iter().any(|byte| *byte != 0) {
                return Err(PersistentAddressEventPageError::NoncanonicalDummy);
            }
            return Ok(AddressEventPage::dummy());
        }
        let mut directory_slot = [0; 4];
        directory_slot.copy_from_slice(&self.0[2..6]);
        let mut event_ordinal = [0; 4];
        event_ordinal.copy_from_slice(&self.0[6..10]);
        let mut event = [0; PERSISTENT_UTXO_EVENT_BYTES];
        event.copy_from_slice(&self.0[10..]);
        let event = PersistentUtxoEvent(event)
            .into_business()
            .map_err(PersistentAddressEventPageError::InvalidEvent)?;
        let page = AddressEventPage::real(
            u32::from_le_bytes(directory_slot),
            u32::from_le_bytes(event_ordinal),
            event,
        )
        .map_err(map_address_event_page_error)?;
        match annotation {
            RecordAnnotation::Unannotated => Ok(page),
            annotation => page
                .annotated(annotation)
                .map_err(map_address_event_page_error),
        }
    }
}

const fn map_address_event_page_error(
    error: AddressEventPageError,
) -> PersistentAddressEventPageError {
    match error {
        AddressEventPageError::NonStandardEvent => {
            PersistentAddressEventPageError::NonStandardEvent
        }
        AddressEventPageError::AnnotatedDummy => {
            PersistentAddressEventPageError::NoncanonicalAnnotation
        }
    }
}

impl Default for PersistentAddressEventPage {
    /// Returns all-zero scratch storage, not a canonical persistent dummy.
    ///
    /// Callers may use this only as an ignored read buffer when the backend
    /// reports that no record was found. Deserializing it correctly fails the
    /// version check. Encode [`AddressEventPage::dummy`] for a real dummy cell.
    fn default() -> Self {
        Self([0; PERSISTENT_ADDRESS_EVENT_PAGE_BYTES])
    }
}

impl fmt::Debug for PersistentAddressEventPage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PersistentAddressEventPage([REDACTED])")
    }
}

#[cfg(feature = "rostl-experimental")]
impl rostl_primitives::traits::Cmov for PersistentAddressEventPage {
    fn cmov(&mut self, other: &Self, choice: bool) {
        cmov_pod_bytes(self, other, choice);
    }

    fn cxchg(&mut self, other: &mut Self, choice: bool) {
        cxchg_pod_bytes(self, other, choice);
    }
}

/// Validates the shared cell header and returns its flag byte.
///
/// `known_flags` is the caller's complete legal flag set: a directory cell has
/// only the occupancy bit, an event page also has the three annotation bits.
/// Any bit outside that set is rejected, so an unknown flag can never be
/// silently ignored by the cell kind that does not define it.
fn decode_address_cell_header(
    bytes: &[u8],
    known_flags: u8,
) -> Result<u8, PersistentAddressCellHeaderError> {
    if bytes[0] != ADDRESS_CELL_FORMAT_VERSION {
        return Err(PersistentAddressCellHeaderError::UnsupportedVersion { actual: bytes[0] });
    }
    if bytes[1] & !known_flags != 0 {
        return Err(PersistentAddressCellHeaderError::InvalidFlags { actual: bytes[1] });
    }
    Ok(bytes[1])
}

/// Invalid common header bytes in a protected address cell.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PersistentAddressCellHeaderError {
    UnsupportedVersion { actual: u8 },
    InvalidFlags { actual: u8 },
}

impl fmt::Display for PersistentAddressCellHeaderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedVersion { actual } => {
                write!(f, "unsupported persistent address-cell version {actual}")
            }
            Self::InvalidFlags { actual } => {
                write!(f, "invalid persistent address-cell flags {actual}")
            }
        }
    }
}

impl std::error::Error for PersistentAddressCellHeaderError {}

/// Invalid bytes in a protected directory cell.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PersistentAddressDirectoryError {
    Header(PersistentAddressCellHeaderError),
    NoncanonicalDummy,
}

impl fmt::Display for PersistentAddressDirectoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Header(error) => write!(f, "persistent address directory is invalid: {error}"),
            Self::NoncanonicalDummy => {
                f.write_str("persistent address-directory dummy has nonzero payload")
            }
        }
    }
}

impl std::error::Error for PersistentAddressDirectoryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Header(error) => Some(error),
            Self::NoncanonicalDummy => None,
        }
    }
}

/// Invalid bytes in a protected one-event page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PersistentAddressEventPageError {
    Header(PersistentAddressCellHeaderError),
    NoncanonicalDummy,
    NoncanonicalAnnotation,
    NonStandardEvent,
    InvalidEvent(PersistentUtxoEventError),
}

impl fmt::Display for PersistentAddressEventPageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Header(error) => write!(f, "persistent address-event page is invalid: {error}"),
            Self::NoncanonicalDummy => {
                f.write_str("persistent address-event dummy has nonzero payload")
            }
            Self::NoncanonicalAnnotation => {
                f.write_str("persistent address-event page has a noncanonical annotation")
            }
            Self::NonStandardEvent => {
                f.write_str("persistent address-event page contains a nonstandard event")
            }
            Self::InvalidEvent(error) => {
                write!(
                    f,
                    "persistent address-event page contains an invalid event: {error}"
                )
            }
        }
    }
}

impl std::error::Error for PersistentAddressEventPageError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Header(error) => Some(error),
            Self::InvalidEvent(error) => Some(error),
            Self::NoncanonicalDummy | Self::NoncanonicalAnnotation | Self::NonStandardEvent => None,
        }
    }
}

/// A private transparent-UTXO query prepared for profile-bounded execution.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct UtxoQuery {
    address_key: AddressKey,
    minimum_height: u32,
    domain_valid: bool,
}

impl UtxoQuery {
    /// Builds a valid query from a canonical address key.
    pub(super) const fn new(address_key: AddressKey, minimum_height: u32) -> Self {
        Self {
            address_key,
            minimum_height,
            domain_valid: true,
        }
    }

    /// Prepares untrusted key bytes without shortening the logical store schedule.
    ///
    /// A non-32-byte input is replaced with a fixed dummy key and marked invalid.
    /// The engine still executes the profile's complete read budget and reports
    /// [`QueryOutcome::InvalidDomain`] inside the protected result.
    pub(super) fn from_untrusted_address_key(bytes: &[u8], minimum_height: u32) -> Self {
        let mut fixed = [0; ADDRESS_KEY_BYTES];
        let domain_valid = bytes.len() == ADDRESS_KEY_BYTES;
        if domain_valid {
            fixed.copy_from_slice(bytes);
        }
        Self {
            address_key: AddressKey::new(fixed),
            minimum_height,
            domain_valid,
        }
    }

    /// Returns the address-derived key used for profile-bounded logical reads.
    pub(super) const fn address_key(&self) -> &AddressKey {
        &self.address_key
    }

    /// Returns the inclusive minimum mined height.
    pub(super) const fn minimum_height(&self) -> u32 {
        self.minimum_height
    }

    pub(super) const fn domain_valid(&self) -> bool {
        self.domain_valid
    }
}

impl fmt::Debug for UtxoQuery {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("UtxoQuery { ..REDACTED.. }")
    }
}

/// Protected outcome encoded inside a fixed response envelope.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct QueryOutcome(u8);

#[allow(non_upper_case_globals)]
impl QueryOutcome {
    /// All matching records fit in the configured result budget.
    pub(super) const Complete: Self = Self(0);
    /// More matching records existed than the profile permits returning.
    pub(super) const ResultBudgetExceeded: Self = Self(1);
    /// The protected request did not contain a valid address-key domain value.
    pub(super) const InvalidDomain: Self = Self(2);
    /// The store could not complete at least one logical read.
    pub(super) const StoreFailure: Self = Self(3);
    /// The protected projection has no ready checkpoint for this query round.
    pub(super) const ProjectionNotReady: Self = Self(4);
    /// The opaque continuation was invalid, expired, mismatched, or replayed.
    pub(super) const InvalidContinuation: Self = Self(5);

    /// Selects `replacement` when `mask` is all ones, otherwise keeps `self`.
    pub(super) const fn conditional_select(self, replacement: Self, mask: usize) -> Self {
        let byte_mask = mask as u8;
        Self((self.0 & !byte_mask) | (replacement.0 & byte_mask))
    }
}

impl fmt::Debug for QueryOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("QueryOutcome([REDACTED])")
    }
}

/// One fixed response slot, occupied by either a real UTXO or a dummy record.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct UtxoResultSlot {
    occupied: bool,
    utxo: TransparentUtxo,
}

impl UtxoResultSlot {
    const fn dummy() -> Self {
        Self {
            occupied: false,
            utxo: TransparentUtxo::dummy(),
        }
    }

    const fn real(utxo: TransparentUtxo) -> Self {
        Self {
            occupied: true,
            utxo,
        }
    }

    /// Returns whether this slot contains a real UTXO.
    pub(super) const fn is_occupied(&self) -> bool {
        self.occupied
    }

    /// Returns the fixed record for both real and dummy slots.
    pub(super) const fn padded_utxo(&self) -> &TransparentUtxo {
        &self.utxo
    }
}

impl fmt::Debug for UtxoResultSlot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("UtxoResultSlot { ..REDACTED.. }")
    }
}

/// A compile-time fixed response page.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct UtxoResultPage<const N: usize> {
    outcome: QueryOutcome,
    slots: [UtxoResultSlot; N],
}

impl<const N: usize> UtxoResultPage<N> {
    pub(super) const fn empty() -> Self {
        Self {
            outcome: QueryOutcome::Complete,
            slots: [UtxoResultSlot::dummy(); N],
        }
    }

    pub(super) fn set_outcome(&mut self, outcome: QueryOutcome) {
        self.outcome = outcome;
    }

    pub(super) fn set_slot(&mut self, index: usize, utxo: TransparentUtxo) {
        self.slots[index] = UtxoResultSlot::real(utxo);
    }

    /// Conditionally replaces one publicly indexed slot with a real record.
    pub(super) fn conditional_set_slot(
        &mut self,
        index: usize,
        utxo: TransparentUtxo,
        mask: usize,
    ) {
        let slot = &mut self.slots[index];
        slot.occupied = ((slot.occupied as usize & !mask) | (mask & 1)) != 0;
        slot.utxo = slot.utxo.conditional_select(utxo, mask);
    }

    /// Conditionally clears every response slot using a fixed sweep.
    pub(super) fn conditional_clear(&mut self, mask: usize) {
        for slot in &mut self.slots {
            slot.occupied = (slot.occupied as usize & !mask) != 0;
            slot.utxo = slot.utxo.conditional_select(TransparentUtxo::dummy(), mask);
        }
    }

    /// Returns the protected query outcome.
    pub(super) const fn outcome(&self) -> QueryOutcome {
        self.outcome
    }

    /// Returns every real and dummy result slot.
    pub(super) const fn slots(&self) -> &[UtxoResultSlot; N] {
        &self.slots
    }

    /// Returns whether every fixed slot is the canonical dummy value.
    pub(super) fn is_all_dummy(&self) -> bool {
        self.slots.iter().all(|slot| !slot.is_occupied())
    }

    /// Counts real records inside the protected page.
    #[cfg(test)]
    pub(super) fn real_count(&self) -> usize {
        self.slots.iter().filter(|slot| slot.occupied).count()
    }
}

impl<const N: usize> fmt::Debug for UtxoResultPage<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UtxoResultPage")
            .field("slots", &N)
            .finish_non_exhaustive()
    }
}

/// Storage-boundary representation of [`AddressKey`].
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct PersistentAddressKey([u8; ADDRESS_KEY_BYTES]);

impl PersistentAddressKey {
    pub(super) fn from_business(src: &AddressKey) -> Self {
        Self(*src.as_bytes())
    }

    pub(super) fn into_business(self) -> AddressKey {
        AddressKey::new(self.0)
    }
}

/// Storage-boundary representation of [`TransparentUtxo`].
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct PersistentTransparentUtxo {
    txid: [u8; TXID_BYTES],
    output_index: u32,
    value_zat: u64,
    height: u32,
    script_len: u8,
    script: [u8; TRANSPARENT_SCRIPT_CAPACITY],
}

impl PersistentTransparentUtxo {
    pub(super) fn from_business(src: &TransparentUtxo) -> Self {
        Self {
            txid: *src.txid(),
            output_index: src.output_index(),
            value_zat: src.value_zat(),
            height: src.height(),
            script_len: src.script_len() as u8,
            script: *src.padded_script(),
        }
    }

    pub(super) fn into_business(self) -> Result<TransparentUtxo, UtxoRecordError> {
        let script_len = usize::from(self.script_len);
        if script_len > TRANSPARENT_SCRIPT_CAPACITY {
            return Err(UtxoRecordError::ScriptTooLong {
                actual: script_len,
                capacity: TRANSPARENT_SCRIPT_CAPACITY,
            });
        }
        TransparentUtxo::new(
            self.txid,
            self.output_index,
            self.value_zat,
            self.height,
            &self.script[..script_len],
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_utxo(height: u32) -> TransparentUtxo {
        TransparentUtxo::new([0x11; TXID_BYTES], 3, 42_000, height, &[0x51; 25])
            .expect("sample transparent script fits the fixed record")
    }

    fn sample_created_event() -> UtxoEvent {
        UtxoEvent::created(
            [0x31; TXID_BYTES],
            7,
            42_000,
            123,
            UtxoScriptClass::PayToPublicKeyHash,
            [0x41; 20],
        )
    }

    fn sample_spent_event() -> UtxoEvent {
        UtxoEvent::spent(
            [0x32; TXID_BYTES],
            8,
            43_000,
            124,
            UtxoScriptClass::PayToScriptHash,
            [0x42; 20],
        )
    }

    fn fixed_page_owner_key(script_class: UtxoScriptClass, script_hash: [u8; 20]) -> AddressKey {
        use crate::layout::{
            derive_standard_address_key, LayoutNetwork, StandardAddress, StandardScriptKind,
        };

        let script_kind = match script_class {
            UtxoScriptClass::PayToPublicKeyHash => StandardScriptKind::PayToPublicKeyHash,
            UtxoScriptClass::PayToScriptHash => StandardScriptKind::PayToScriptHash,
            UtxoScriptClass::NonStandard => return AddressKey::new([0; ADDRESS_KEY_BYTES]),
        };
        derive_standard_address_key(
            LayoutNetwork::Regtest,
            7,
            StandardAddress::new(script_kind, script_hash),
        )
    }

    fn fixed_page_identity(lower_height: u32, upper_height: u32) -> FixedUtxoPageIdentity {
        FixedUtxoPageIdentity::new(
            fixed_page_owner_key(UtxoScriptClass::PayToPublicKeyHash, [0x92; 20]),
            0x0102_0304_0506_0708,
            0x1112_1314,
            lower_height,
            upper_height,
        )
        .expect("fixture generation is nonzero and its height range is ordered")
    }

    fn created_page_entries() -> [UtxoEvent; FIXED_UTXO_PAGE_ENTRIES] {
        std::array::from_fn(|index| {
            UtxoEvent::created(
                [(index + 1) as u8; TXID_BYTES],
                index as u32,
                50_000 + index as u64,
                100 + index as u32,
                UtxoScriptClass::PayToPublicKeyHash,
                [0x92; 20],
            )
        })
    }

    fn spent_page_entries() -> [UtxoEvent; FIXED_UTXO_PAGE_ENTRIES] {
        std::array::from_fn(|index| {
            UtxoEvent::spent(
                [(index + 1) as u8; TXID_BYTES],
                index as u32,
                50_000 + index as u64,
                100 + index as u32,
                UtxoScriptClass::PayToPublicKeyHash,
                [0x92; 20],
            )
        })
    }

    #[cfg(feature = "rostl-experimental")]
    fn persistent_fixed_page(
        kind: FixedUtxoPageKind,
        identity: FixedUtxoPageIdentity,
        entries: &[UtxoEvent],
    ) -> Result<PersistentFixedUtxoPage, FixedUtxoPageError> {
        FixedUtxoPage::real(kind, identity, entries, &fixed_page_owner_key)
            .map(|page| PersistentFixedUtxoPage::from_business_offline(&page))
    }

    #[cfg(feature = "rostl-experimental")]
    fn fixed_page_append_for_kind(
        kind: FixedUtxoPageKind,
        prior: PersistentFixedUtxoPage,
        found: bool,
        identity: FixedUtxoPageIdentity,
        event: UtxoEvent,
    ) -> Result<FixedPageAppendTransition<PersistentFixedUtxoPage>, FixedUtxoPageError> {
        let request =
            FixedPageAppendRequest::new_offline(kind, identity, event, &fixed_page_owner_key)?;
        let (expected_event_kind, expected_event_flags) = match kind {
            FixedUtxoPageKind::Base | FixedUtxoPageKind::Add => {
                (UtxoEventKind::Created.to_byte(), UTXO_EVENT_FLAG_MINED)
            }
            FixedUtxoPageKind::Spend => (
                UtxoEventKind::Spent.to_byte(),
                UTXO_EVENT_FLAG_MINED | UTXO_EVENT_FLAG_SPENT,
            ),
        };
        Ok(fixed_page_append(
            prior,
            found,
            request,
            kind.to_byte(),
            expected_event_kind,
            expected_event_flags,
        ))
    }

    #[cfg(feature = "rostl-experimental")]
    fn assert_invalid_fixed_page_append_preserves(
        kind: FixedUtxoPageKind,
        prior: PersistentFixedUtxoPage,
        identity: FixedUtxoPageIdentity,
        event: UtxoEvent,
    ) -> Result<(), FixedUtxoPageError> {
        let transition = fixed_page_append_for_kind(kind, prior, true, identity, event)?;
        assert!(!transition.valid);
        assert_eq!(transition.replacement, prior);
        Ok(())
    }

    #[cfg(feature = "rostl-experimental")]
    fn mutate_persistent_fixed_page(
        prior: PersistentFixedUtxoPage,
        mutation: impl FnOnce(&mut [u8; PERSISTENT_FIXED_UTXO_PAGE_BYTES]),
    ) -> PersistentFixedUtxoPage {
        let mut bytes = prior.0;
        mutation(&mut bytes);
        PersistentFixedUtxoPage(bytes)
    }

    fn created_event(
        txid_byte: u8,
        output_index: u32,
        value_zat: u64,
        height: u32,
        script_class: UtxoScriptClass,
        script_hash: [u8; 20],
    ) -> UtxoEvent {
        UtxoEvent::created(
            [txid_byte; TXID_BYTES],
            output_index,
            value_zat,
            height,
            script_class,
            script_hash,
        )
    }

    fn matching_spend(created: UtxoEvent, height: u32) -> UtxoEvent {
        UtxoEvent::spent(
            *created.txid(),
            created.output_index(),
            created.value_zat(),
            height,
            created.script_class(),
            *created.script_hash(),
        )
    }

    #[test]
    fn finalized_history_compacts_live_outputs_in_creation_order() {
        let first = created_event(
            0x11,
            0,
            11,
            100,
            UtxoScriptClass::PayToPublicKeyHash,
            [0xa1; 20],
        );
        let second = created_event(
            0x22,
            1,
            22,
            101,
            UtxoScriptClass::PayToScriptHash,
            [0xb2; 20],
        );
        let third = created_event(
            0x33,
            2,
            33,
            102,
            UtxoScriptClass::PayToPublicKeyHash,
            [0xa1; 20],
        );
        let history = [
            Some(first),
            Some(second),
            Some(matching_spend(first, 102)),
            Some(third),
            None,
            None,
        ];

        assert_eq!(
            finalized_live_utxo_at(&history, 0, 102),
            Ok(second.created_utxo())
        );
        assert_eq!(
            finalized_live_utxo_at(&history, 1, 102),
            Ok(third.created_utxo())
        );
        assert_eq!(finalized_live_utxo_at(&history, 2, 102), Ok(None));
    }

    /// The annotation pass writes to a *history ordinal*, but the query reads a
    /// *live slot*, and the two are not the same index: spent creations occupy
    /// history ordinals while contributing no live slot. Here live slot 1 is the
    /// event at ordinal 3, so a pass that annotated by live slot would write the
    /// wrong record.
    #[test]
    fn every_live_slot_names_the_history_ordinal_of_the_creation_behind_it() {
        let first = created_event(
            0x11,
            1,
            11,
            100,
            UtxoScriptClass::PayToPublicKeyHash,
            [0xa1; 20],
        );
        let second = created_event(
            0x22,
            2,
            22,
            101,
            UtxoScriptClass::PayToScriptHash,
            [0xb2; 20],
        );
        let third = created_event(
            0x33,
            2,
            33,
            102,
            UtxoScriptClass::PayToPublicKeyHash,
            [0xa1; 20],
        );
        let history = [
            Some(first),
            Some(second),
            Some(matching_spend(first, 102)),
            Some(third),
            None,
            None,
        ];

        let live = finalized_live_slots(&history, 102).expect("history is canonical");

        // The vector is the fixed history width, not the live count, so its
        // length reveals nothing about how many outputs the address holds.
        assert_eq!(live.len(), history.len());
        assert_eq!(live[0].map(FinalizedLiveSlot::ordinal), Some(1));
        assert_eq!(live[1].map(FinalizedLiveSlot::ordinal), Some(3));
        assert!(live[2..].iter().all(Option::is_none));
        assert_eq!(live[0].map(FinalizedLiveSlot::utxo), second.created_utxo());
        assert_eq!(live[1].map(FinalizedLiveSlot::utxo), third.created_utxo());
    }

    #[test]
    fn same_block_spend_removes_the_creation_and_padding_is_accepted() {
        let created = created_event(
            0x44,
            3,
            44,
            200,
            UtxoScriptClass::PayToScriptHash,
            [0xc3; 20],
        );
        let history = [Some(created), Some(matching_spend(created, 200)), None];

        assert_eq!(finalized_live_utxo_at(&history, 0, 200), Ok(None));
        assert_eq!(
            finalized_live_utxo_at(&[Some(created), None, None], 0, 200),
            Ok(created.created_utxo())
        );
    }

    #[test]
    fn finalized_history_rejects_every_malformed_sequence() {
        let created = created_event(
            0x55,
            4,
            55,
            300,
            UtxoScriptClass::PayToPublicKeyHash,
            [0xd4; 20],
        );
        let spend = matching_spend(created, 301);
        let mut mismatched_value = spend;
        mismatched_value.value_zat += 1;
        let mut early_spend = spend;
        early_spend.height = created.height - 1;
        let mut noncanonical_create = created;
        noncanonical_create.spent = true;
        let nonstandard = created_event(0x66, 5, 66, 302, UtxoScriptClass::NonStandard, [0xe5; 20]);

        let histories = [
            [None, Some(created), None],
            [Some(spend), None, None],
            [Some(created), Some(created), None],
            [Some(created), Some(spend), Some(spend)],
            [Some(created), Some(mismatched_value), None],
            [Some(created), Some(early_spend), None],
            [Some(noncanonical_create), None, None],
            [Some(nonstandard), None, None],
        ];
        for history in histories {
            assert_eq!(
                finalized_live_utxo_at(&history, 0, 302),
                Err(FinalizedEventHistoryError::Invalid)
            );
        }
        assert_eq!(
            finalized_live_utxo_at(&[Some(created)], 1, 300),
            Err(FinalizedEventHistoryError::Invalid)
        );

        let later = created_event(
            0x77,
            6,
            77,
            301,
            UtxoScriptClass::PayToPublicKeyHash,
            [0xd4; 20],
        );
        assert_eq!(
            finalized_live_utxo_at(&[Some(later), Some(created)], 0, 301),
            Err(FinalizedEventHistoryError::Invalid)
        );
        assert_eq!(
            finalized_live_utxo_at(&[Some(later), None], 0, 300),
            Err(FinalizedEventHistoryError::Invalid)
        );
    }

    #[test]
    fn address_key_round_trips_through_persistent_boundary() {
        let business = AddressKey::new([0x22; ADDRESS_KEY_BYTES]);
        let persistent = PersistentAddressKey::from_business(&business);
        assert_eq!(persistent.into_business(), business);
    }

    #[test]
    fn utxo_round_trips_through_persistent_boundary() -> Result<(), UtxoRecordError> {
        let business = sample_utxo(123);
        let persistent = PersistentTransparentUtxo::from_business(&business);
        assert_eq!(persistent.into_business()?, business);
        Ok(())
    }

    #[test]
    fn utxo_rejects_script_beyond_fixed_capacity() {
        let oversized = [0; TRANSPARENT_SCRIPT_CAPACITY + 1];
        assert_eq!(
            TransparentUtxo::new([0; TXID_BYTES], 0, 0, 0, &oversized),
            Err(UtxoRecordError::ScriptTooLong {
                actual: TRANSPARENT_SCRIPT_CAPACITY + 1,
                capacity: TRANSPARENT_SCRIPT_CAPACITY,
            })
        );
    }

    #[test]
    fn persistent_utxo_revalidates_script_length() {
        let mut persistent = PersistentTransparentUtxo::from_business(&sample_utxo(123));
        persistent.script_len = u8::MAX;
        assert_eq!(
            persistent.into_business(),
            Err(UtxoRecordError::ScriptTooLong {
                actual: usize::from(u8::MAX),
                capacity: TRANSPARENT_SCRIPT_CAPACITY,
            })
        );
    }

    #[test]
    fn fixed_event_round_trips_through_exact_persistent_bytes(
    ) -> Result<(), PersistentUtxoEventError> {
        for business in [sample_created_event(), sample_spent_event()] {
            let persistent = PersistentUtxoEvent::from_business(&business);

            assert_eq!(
                std::mem::size_of_val(&persistent),
                PERSISTENT_UTXO_EVENT_BYTES
            );
            assert_eq!(persistent.into_business()?, business);
        }
        Ok(())
    }

    #[test]
    fn named_event_constructors_set_the_only_permitted_finalized_states() {
        let created = sample_created_event();
        let spent = sample_spent_event();

        assert!(created.kind() == UtxoEventKind::Created);
        assert_eq!(created.txid(), &[0x31; TXID_BYTES]);
        assert_eq!(created.output_index(), 7);
        assert_eq!(created.value_zat(), 42_000);
        assert_eq!(created.height(), 123);
        assert!(created.script_class() == UtxoScriptClass::PayToPublicKeyHash);
        assert_eq!(created.script_hash(), &[0x41; 20]);
        assert_eq!(
            PersistentUtxoEvent::from_business(&created).0[3],
            UTXO_EVENT_FLAG_MINED
        );
        assert_eq!(
            PersistentUtxoEvent::from_business(&spent).0[3],
            UTXO_EVENT_FLAG_MINED | UTXO_EVENT_FLAG_SPENT
        );
    }

    #[test]
    fn fixed_event_revalidates_every_tag_and_flag() {
        let valid = PersistentUtxoEvent::from_business(&sample_created_event());
        for (index, actual, expected) in [
            (
                0,
                2,
                PersistentUtxoEventError::UnsupportedVersion { actual: 2 },
            ),
            (
                1,
                3,
                PersistentUtxoEventError::InvalidEventKind { actual: 3 },
            ),
            (
                2,
                3,
                PersistentUtxoEventError::InvalidScriptClass { actual: 3 },
            ),
            (3, 4, PersistentUtxoEventError::InvalidFlags { actual: 4 }),
        ] {
            let mut bytes = valid.0;
            bytes[index] = actual;
            assert_eq!(PersistentUtxoEvent(bytes).into_business(), Err(expected));
        }
    }

    #[test]
    fn fixed_event_rejects_every_illegal_known_kind_and_state_combination() {
        let valid = PersistentUtxoEvent::from_business(&sample_created_event());
        for (kind, flags, expected) in [
            (
                UtxoEventKind::Created.to_byte(),
                0,
                PersistentUtxoEventError::InvalidCreatedState {
                    mined: false,
                    spent: false,
                },
            ),
            (
                UtxoEventKind::Created.to_byte(),
                UTXO_EVENT_FLAG_SPENT,
                PersistentUtxoEventError::InvalidCreatedState {
                    mined: false,
                    spent: true,
                },
            ),
            (
                UtxoEventKind::Created.to_byte(),
                UTXO_EVENT_FLAG_MINED | UTXO_EVENT_FLAG_SPENT,
                PersistentUtxoEventError::InvalidCreatedState {
                    mined: true,
                    spent: true,
                },
            ),
            (
                UtxoEventKind::Spent.to_byte(),
                0,
                PersistentUtxoEventError::InvalidSpentState {
                    mined: false,
                    spent: false,
                },
            ),
            (
                UtxoEventKind::Spent.to_byte(),
                UTXO_EVENT_FLAG_MINED,
                PersistentUtxoEventError::InvalidSpentState {
                    mined: true,
                    spent: false,
                },
            ),
            (
                UtxoEventKind::Spent.to_byte(),
                UTXO_EVENT_FLAG_SPENT,
                PersistentUtxoEventError::InvalidSpentState {
                    mined: false,
                    spent: true,
                },
            ),
        ] {
            let mut bytes = valid.0;
            bytes[1] = kind;
            bytes[3] = flags;
            assert_eq!(PersistentUtxoEvent(bytes).into_business(), Err(expected));
        }
    }

    #[test]
    fn fixed_event_debug_output_is_redacted() {
        let business = sample_created_event();
        let persistent = PersistentUtxoEvent::from_business(&business);

        assert_eq!(format!("{business:?}"), "UtxoEvent { ..REDACTED.. }");
        assert_eq!(format!("{persistent:?}"), "PersistentUtxoEvent([REDACTED])");
    }

    #[test]
    fn fixed_page_records_have_exact_width_and_golden_header_offsets(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let identity = fixed_page_identity(100, 115);
        let created = created_page_entries();
        let spent = spent_page_entries();
        let base = BaseUtxoPage16::real(identity, &created[..1], &fixed_page_owner_key)?;
        let add = AddUtxoPage16::real(identity, &created[..1], &fixed_page_owner_key)?;
        let spend = SpendUtxoPage16::real(identity, &spent[..1], &fixed_page_owner_key)?;
        let persistent_base = PersistentBaseUtxoPage16::from_business_offline(&base);
        let persistent_add = PersistentAddUtxoPage16::from_business_offline(&add);
        let persistent_spend = PersistentSpendUtxoPage16::from_business_offline(&spend);

        for width in [
            std::mem::size_of_val(&persistent_base),
            std::mem::size_of_val(&persistent_add),
            std::mem::size_of_val(&persistent_spend),
        ] {
            assert_eq!(width, PERSISTENT_FIXED_UTXO_PAGE_BYTES);
            assert_eq!(width, 1_208);
        }

        let base_bytes = &(persistent_base.0).0;
        assert_eq!(base_bytes[0], FIXED_UTXO_PAGE_FORMAT_VERSION);
        assert_eq!(base_bytes[1], FixedUtxoPageKind::Base.to_byte());
        assert_eq!(base_bytes[2], 1);
        assert_eq!(base_bytes[3], 0);
        assert_eq!(&base_bytes[4..36], identity.address_key().as_bytes());
        assert_eq!(
            &base_bytes[36..44],
            &0x0102_0304_0506_0708_u64.to_le_bytes()
        );
        assert_eq!(&base_bytes[44..48], &0x1112_1314_u32.to_le_bytes());
        assert_eq!(&base_bytes[48..52], &100_u32.to_le_bytes());
        assert_eq!(&base_bytes[52..56], &115_u32.to_le_bytes());
        assert_eq!(
            &base_bytes[56..128],
            &PersistentUtxoEvent::from_business(&created[0]).0
        );
        assert!(base_bytes[128..].iter().all(|byte| *byte == 0));
        assert_eq!((persistent_add.0).0[1], FixedUtxoPageKind::Add.to_byte());
        assert_eq!(
            (persistent_spend.0).0[1],
            FixedUtxoPageKind::Spend.to_byte()
        );
        Ok(())
    }

    #[test]
    fn fixed_page_records_round_trip_one_full_and_dummy_pages(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let identity = fixed_page_identity(100, 115);
        let created = created_page_entries();
        let spent = spent_page_entries();
        let base = BaseUtxoPage16::real(identity, &created[..1], &fixed_page_owner_key)?;
        let add = AddUtxoPage16::real(identity, &created, &fixed_page_owner_key)?;
        let spend = SpendUtxoPage16::real(identity, &spent, &fixed_page_owner_key)?;

        assert_eq!(
            PersistentBaseUtxoPage16::from_business_offline(&base)
                .into_business_offline(identity, &fixed_page_owner_key)?,
            base
        );
        assert_eq!(
            PersistentAddUtxoPage16::from_business_offline(&add)
                .into_business_offline(identity, &fixed_page_owner_key)?,
            add
        );
        assert_eq!(
            PersistentSpendUtxoPage16::from_business_offline(&spend)
                .into_business_offline(identity, &fixed_page_owner_key)?,
            spend
        );

        let base_dummy = BaseUtxoPage16::dummy();
        let add_dummy = AddUtxoPage16::dummy();
        let spend_dummy = SpendUtxoPage16::dummy();
        assert!(PersistentBaseUtxoPage16::from_business_offline(&base_dummy)
            .into_business_offline(identity, &fixed_page_owner_key)?
            .0
            .is_dummy());
        assert!(PersistentAddUtxoPage16::from_business_offline(&add_dummy)
            .into_business_offline(identity, &fixed_page_owner_key)?
            .0
            .is_dummy());
        assert!(
            PersistentSpendUtxoPage16::from_business_offline(&spend_dummy)
                .into_business_offline(identity, &fixed_page_owner_key)?
                .0
                .is_dummy()
        );
        Ok(())
    }

    #[test]
    fn fixed_page_canonical_dummy_is_distinct_from_default_scratch() {
        let identity = fixed_page_identity(100, 115);
        let dummy = PersistentBaseUtxoPage16::from_business_offline(&BaseUtxoPage16::dummy());
        assert_eq!((dummy.0).0[0], FIXED_UTXO_PAGE_FORMAT_VERSION);
        assert_eq!((dummy.0).0[1], FixedUtxoPageKind::Base.to_byte());
        assert!((dummy.0).0[2..].iter().all(|byte| *byte == 0));
        assert_eq!(
            PersistentBaseUtxoPage16::default()
                .into_business_offline(identity, &fixed_page_owner_key),
            Err(PersistentFixedUtxoPageError::UnsupportedVersion { actual: 0 })
        );
        assert_eq!(
            PersistentAddUtxoPage16::default()
                .into_business_offline(identity, &fixed_page_owner_key),
            Err(PersistentFixedUtxoPageError::UnsupportedVersion { actual: 0 })
        );
        assert_eq!(
            PersistentSpendUtxoPage16::default()
                .into_business_offline(identity, &fixed_page_owner_key),
            Err(PersistentFixedUtxoPageError::UnsupportedVersion { actual: 0 })
        );
    }

    #[test]
    fn fixed_page_identity_rejects_zero_generation_and_inverted_range() {
        let key = AddressKey::new([0x91; ADDRESS_KEY_BYTES]);
        assert_eq!(
            FixedUtxoPageIdentity::new(key, 0, 1, 100, 115),
            Err(FixedUtxoPageIdentityError::ZeroGeneration)
        );
        assert_eq!(
            FixedUtxoPageIdentity::new(key, 1, 1, 116, 115),
            Err(FixedUtxoPageIdentityError::InvalidHeightRange {
                lower: 116,
                upper: 115,
            })
        );
    }

    #[test]
    fn fixed_page_requires_canonical_owner_key_and_total_event_order(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let identity = fixed_page_identity(100, 115);
        let mut created = created_page_entries();

        let wrong_identity =
            FixedUtxoPageIdentity::new(AddressKey::new([0xa5; 32]), 1, 0, 100, 115)?;
        assert_eq!(
            BaseUtxoPage16::real(wrong_identity, &created[..1], &fixed_page_owner_key),
            Err(FixedUtxoPageError::AddressKeyMismatch { index: 0 })
        );

        created[1].height = created[0].height;
        assert!(BaseUtxoPage16::real(identity, &created[..2], &fixed_page_owner_key).is_ok());
        assert_eq!(
            BaseUtxoPage16::real(identity, &[created[1], created[0]], &fixed_page_owner_key,),
            Err(FixedUtxoPageError::NoncanonicalOrder { index: 1 })
        );

        let first_output = created[0];
        let mut second_output = first_output;
        second_output.output_index += 1;
        assert!(BaseUtxoPage16::real(
            identity,
            &[first_output, second_output],
            &fixed_page_owner_key,
        )
        .is_ok());
        assert_eq!(
            BaseUtxoPage16::real(
                identity,
                &[second_output, first_output],
                &fixed_page_owner_key,
            ),
            Err(FixedUtxoPageError::NoncanonicalOrder { index: 1 })
        );
        Ok(())
    }

    #[test]
    fn fixed_page_offline_decode_requires_exact_manifest_identity(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let identity = fixed_page_identity(100, 115);
        let created = created_page_entries();
        let page = BaseUtxoPage16::real(identity, &created[..1], &fixed_page_owner_key)?;
        let persistent = PersistentBaseUtxoPage16::from_business_offline(&page);

        let unexpected_identities = [
            FixedUtxoPageIdentity::new(
                AddressKey::new([0xa5; 32]),
                identity.generation(),
                identity.page_ordinal(),
                identity.lower_height(),
                identity.upper_height(),
            )?,
            FixedUtxoPageIdentity::new(
                *identity.address_key(),
                identity.generation() + 1,
                identity.page_ordinal(),
                identity.lower_height(),
                identity.upper_height(),
            )?,
            FixedUtxoPageIdentity::new(
                *identity.address_key(),
                identity.generation(),
                identity.page_ordinal() + 1,
                identity.lower_height(),
                identity.upper_height(),
            )?,
            FixedUtxoPageIdentity::new(
                *identity.address_key(),
                identity.generation(),
                identity.page_ordinal(),
                identity.lower_height() - 1,
                identity.upper_height(),
            )?,
            FixedUtxoPageIdentity::new(
                *identity.address_key(),
                identity.generation(),
                identity.page_ordinal(),
                identity.lower_height(),
                identity.upper_height() + 1,
            )?,
        ];
        for unexpected in unexpected_identities {
            assert_eq!(
                persistent.into_business_offline(unexpected, &fixed_page_owner_key),
                Err(PersistentFixedUtxoPageError::UnexpectedIdentity)
            );
        }

        let dummy = PersistentBaseUtxoPage16::from_business_offline(&BaseUtxoPage16::dummy());
        assert!(dummy
            .into_business_offline(unexpected_identities[0], &fixed_page_owner_key)?
            .0
            .is_dummy());
        Ok(())
    }

    #[test]
    fn fixed_page_persistent_header_revalidates_every_field(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let created = created_page_entries();
        let identity = fixed_page_identity(100, 115);
        let page = BaseUtxoPage16::real(identity, &created, &fixed_page_owner_key)?;
        let valid = (PersistentBaseUtxoPage16::from_business_offline(&page).0).0;

        let mut wrong_version = valid;
        wrong_version[0] = 2;
        assert_eq!(
            PersistentBaseUtxoPage16(PersistentFixedUtxoPage(wrong_version))
                .into_business_offline(identity, &fixed_page_owner_key),
            Err(PersistentFixedUtxoPageError::UnsupportedVersion { actual: 2 })
        );

        let mut invalid_kind = valid;
        invalid_kind[1] = 4;
        assert_eq!(
            PersistentBaseUtxoPage16(PersistentFixedUtxoPage(invalid_kind))
                .into_business_offline(identity, &fixed_page_owner_key),
            Err(PersistentFixedUtxoPageError::InvalidPageKind { actual: 4 })
        );

        let mut wrong_kind = valid;
        wrong_kind[1] = FixedUtxoPageKind::Add.to_byte();
        assert_eq!(
            PersistentBaseUtxoPage16(PersistentFixedUtxoPage(wrong_kind))
                .into_business_offline(identity, &fixed_page_owner_key),
            Err(PersistentFixedUtxoPageError::WrongPageKind {
                expected: FixedUtxoPageKind::Base.to_byte(),
                actual: FixedUtxoPageKind::Add.to_byte(),
            })
        );

        let mut nonzero_reserved = valid;
        nonzero_reserved[3] = 1;
        assert_eq!(
            PersistentBaseUtxoPage16(PersistentFixedUtxoPage(nonzero_reserved))
                .into_business_offline(identity, &fixed_page_owner_key),
            Err(PersistentFixedUtxoPageError::NonzeroReservedByte { actual: 1 })
        );

        let mut invalid_count = valid;
        invalid_count[2] = (FIXED_UTXO_PAGE_ENTRIES + 1) as u8;
        assert_eq!(
            PersistentBaseUtxoPage16(PersistentFixedUtxoPage(invalid_count))
                .into_business_offline(identity, &fixed_page_owner_key),
            Err(PersistentFixedUtxoPageError::OccupancyOutOfRange {
                actual: (FIXED_UTXO_PAGE_ENTRIES + 1) as u8,
                capacity: FIXED_UTXO_PAGE_ENTRIES as u8,
            })
        );

        let mut zero_generation = valid;
        zero_generation[36..44].fill(0);
        assert_eq!(
            PersistentBaseUtxoPage16(PersistentFixedUtxoPage(zero_generation))
                .into_business_offline(identity, &fixed_page_owner_key),
            Err(PersistentFixedUtxoPageError::InvalidIdentity(
                FixedUtxoPageIdentityError::ZeroGeneration
            ))
        );

        let mut inverted_range = valid;
        inverted_range[48..52].copy_from_slice(&116_u32.to_le_bytes());
        assert_eq!(
            PersistentBaseUtxoPage16(PersistentFixedUtxoPage(inverted_range))
                .into_business_offline(identity, &fixed_page_owner_key),
            Err(PersistentFixedUtxoPageError::InvalidIdentity(
                FixedUtxoPageIdentityError::InvalidHeightRange {
                    lower: 116,
                    upper: 115,
                }
            ))
        );
        Ok(())
    }

    #[test]
    fn fixed_page_persistent_boundary_rejects_every_nonzero_padding_byte(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let identity = fixed_page_identity(100, 115);
        let dummy = (PersistentBaseUtxoPage16::from_business_offline(&BaseUtxoPage16::dummy()).0).0;
        for index in 4..PERSISTENT_FIXED_UTXO_PAGE_BYTES {
            let mut noncanonical = dummy;
            noncanonical[index] = 1;
            assert_eq!(
                PersistentBaseUtxoPage16(PersistentFixedUtxoPage(noncanonical))
                    .into_business_offline(identity, &fixed_page_owner_key),
                Err(PersistentFixedUtxoPageError::NoncanonicalDummy)
            );
        }

        let created = created_page_entries();
        let page = BaseUtxoPage16::real(identity, &created[..1], &fixed_page_owner_key)?;
        let valid = (PersistentBaseUtxoPage16::from_business_offline(&page).0).0;
        let padding_start = PERSISTENT_FIXED_UTXO_PAGE_HEADER_BYTES + PERSISTENT_UTXO_EVENT_BYTES;
        for index in padding_start..PERSISTENT_FIXED_UTXO_PAGE_BYTES {
            let mut noncanonical = valid;
            noncanonical[index] = 1;
            assert_eq!(
                PersistentBaseUtxoPage16(PersistentFixedUtxoPage(noncanonical))
                    .into_business_offline(identity, &fixed_page_owner_key),
                Err(PersistentFixedUtxoPageError::NoncanonicalPadding)
            );
        }
        Ok(())
    }

    #[test]
    fn fixed_page_persistent_boundary_revalidates_nested_event_and_page_semantics(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let created = created_page_entries();
        let spent = spent_page_entries();
        let identity = fixed_page_identity(100, 115);
        let page = BaseUtxoPage16::real(identity, &created[..2], &fixed_page_owner_key)?;
        let valid = (PersistentBaseUtxoPage16::from_business_offline(&page).0).0;

        let mut invalid_event = valid;
        invalid_event[PERSISTENT_FIXED_UTXO_PAGE_HEADER_BYTES] = 2;
        assert_eq!(
            PersistentBaseUtxoPage16(PersistentFixedUtxoPage(invalid_event))
                .into_business_offline(identity, &fixed_page_owner_key),
            Err(PersistentFixedUtxoPageError::InvalidEvent {
                index: 0,
                error: PersistentUtxoEventError::UnsupportedVersion { actual: 2 },
            })
        );

        let mut wrong_event_kind = valid;
        wrong_event_kind[PERSISTENT_FIXED_UTXO_PAGE_HEADER_BYTES
            ..PERSISTENT_FIXED_UTXO_PAGE_HEADER_BYTES + PERSISTENT_UTXO_EVENT_BYTES]
            .copy_from_slice(&PersistentUtxoEvent::from_business(&spent[0]).0);
        assert_eq!(
            PersistentBaseUtxoPage16(PersistentFixedUtxoPage(wrong_event_kind))
                .into_business_offline(identity, &fixed_page_owner_key),
            Err(PersistentFixedUtxoPageError::InvalidPage(
                FixedUtxoPageError::WrongEventKind {
                    index: 0,
                    expected: UtxoEventKind::Created.to_byte(),
                    actual: UtxoEventKind::Spent.to_byte(),
                }
            ))
        );

        let mut mixed_owner = created[1];
        mixed_owner.script_hash = [0x93; 20];
        let second_start = PERSISTENT_FIXED_UTXO_PAGE_HEADER_BYTES + PERSISTENT_UTXO_EVENT_BYTES;
        let mut mixed_page = valid;
        mixed_page[second_start..second_start + PERSISTENT_UTXO_EVENT_BYTES]
            .copy_from_slice(&PersistentUtxoEvent::from_business(&mixed_owner).0);
        assert_eq!(
            PersistentBaseUtxoPage16(PersistentFixedUtxoPage(mixed_page))
                .into_business_offline(identity, &fixed_page_owner_key),
            Err(PersistentFixedUtxoPageError::InvalidPage(
                FixedUtxoPageError::MixedAddress { index: 1 }
            ))
        );

        let mut wrong_owner_key = valid;
        for slot in 0..2 {
            let script_hash_start =
                PERSISTENT_FIXED_UTXO_PAGE_HEADER_BYTES + (slot * PERSISTENT_UTXO_EVENT_BYTES) + 52;
            wrong_owner_key[script_hash_start..script_hash_start + 20].fill(0x93);
        }
        assert_eq!(
            PersistentBaseUtxoPage16(PersistentFixedUtxoPage(wrong_owner_key))
                .into_business_offline(identity, &fixed_page_owner_key),
            Err(PersistentFixedUtxoPageError::InvalidPage(
                FixedUtxoPageError::AddressKeyMismatch { index: 0 }
            ))
        );

        let mut out_of_range = valid;
        out_of_range[PERSISTENT_FIXED_UTXO_PAGE_HEADER_BYTES + 48
            ..PERSISTENT_FIXED_UTXO_PAGE_HEADER_BYTES + 52]
            .copy_from_slice(&116_u32.to_le_bytes());
        assert_eq!(
            PersistentBaseUtxoPage16(PersistentFixedUtxoPage(out_of_range))
                .into_business_offline(identity, &fixed_page_owner_key),
            Err(PersistentFixedUtxoPageError::InvalidPage(
                FixedUtxoPageError::HeightOutOfRange { index: 0 }
            ))
        );

        let mut duplicate = valid;
        let first_event = valid[PERSISTENT_FIXED_UTXO_PAGE_HEADER_BYTES
            ..PERSISTENT_FIXED_UTXO_PAGE_HEADER_BYTES + PERSISTENT_UTXO_EVENT_BYTES]
            .to_owned();
        duplicate[second_start..second_start + PERSISTENT_UTXO_EVENT_BYTES]
            .copy_from_slice(&first_event);
        assert_eq!(
            PersistentBaseUtxoPage16(PersistentFixedUtxoPage(duplicate))
                .into_business_offline(identity, &fixed_page_owner_key),
            Err(PersistentFixedUtxoPageError::InvalidPage(
                FixedUtxoPageError::DuplicateOutpoint { index: 1 }
            ))
        );
        Ok(())
    }

    #[test]
    fn fixed_page_business_boundary_rejects_invalid_entry_sets() {
        let identity = fixed_page_identity(100, 115);
        let created = created_page_entries();
        let spent = spent_page_entries();

        assert_eq!(
            BaseUtxoPage16::real(identity, &[], &fixed_page_owner_key),
            Err(FixedUtxoPageError::EmptyRealPage)
        );
        assert_eq!(
            BaseUtxoPage16::real(
                identity,
                &[created[0]; FIXED_UTXO_PAGE_ENTRIES + 1],
                &fixed_page_owner_key,
            ),
            Err(FixedUtxoPageError::TooManyEntries {
                actual: FIXED_UTXO_PAGE_ENTRIES + 1,
                capacity: FIXED_UTXO_PAGE_ENTRIES,
            })
        );
        assert_eq!(
            BaseUtxoPage16::real(identity, &spent[..1], &fixed_page_owner_key),
            Err(FixedUtxoPageError::WrongEventKind {
                index: 0,
                expected: UtxoEventKind::Created.to_byte(),
                actual: UtxoEventKind::Spent.to_byte(),
            })
        );

        let mut nonstandard = created[0];
        nonstandard.script_class = UtxoScriptClass::NonStandard;
        assert_eq!(
            BaseUtxoPage16::real(identity, &[nonstandard], &fixed_page_owner_key),
            Err(FixedUtxoPageError::NonStandardEvent { index: 0 })
        );

        let mut another_owner = created[1];
        another_owner.script_hash = [0x93; 20];
        assert_eq!(
            BaseUtxoPage16::real(
                identity,
                &[created[0], another_owner],
                &fixed_page_owner_key,
            ),
            Err(FixedUtxoPageError::MixedAddress { index: 1 })
        );

        let mut out_of_range = created[0];
        out_of_range.height = 99;
        assert_eq!(
            BaseUtxoPage16::real(identity, &[out_of_range], &fixed_page_owner_key),
            Err(FixedUtxoPageError::HeightOutOfRange { index: 0 })
        );

        assert_eq!(
            BaseUtxoPage16::real(identity, &[created[1], created[0]], &fixed_page_owner_key,),
            Err(FixedUtxoPageError::NoncanonicalOrder { index: 1 })
        );
        assert_eq!(
            BaseUtxoPage16::real(identity, &[created[0], created[0]], &fixed_page_owner_key,),
            Err(FixedUtxoPageError::DuplicateOutpoint { index: 1 })
        );
    }

    #[test]
    fn fixed_page_debug_surfaces_are_redacted() {
        let identity = fixed_page_identity(100, 115);
        let created = created_page_entries();
        let spent = spent_page_entries();
        let base = BaseUtxoPage16::real(identity, &created[..1], &fixed_page_owner_key)
            .expect("fixture page is canonical");
        let add = AddUtxoPage16::real(identity, &created[..1], &fixed_page_owner_key)
            .expect("fixture page is canonical");
        let spend = SpendUtxoPage16::real(identity, &spent[..1], &fixed_page_owner_key)
            .expect("fixture page is canonical");

        assert_eq!(
            format!("{identity:?}"),
            "FixedUtxoPageIdentity { ..REDACTED.. }"
        );
        assert_eq!(format!("{base:?}"), "BaseUtxoPage16 { ..REDACTED.. }");
        assert_eq!(format!("{add:?}"), "AddUtxoPage16 { ..REDACTED.. }");
        assert_eq!(format!("{spend:?}"), "SpendUtxoPage16 { ..REDACTED.. }");
        assert_eq!(
            format!(
                "{:?}",
                PersistentBaseUtxoPage16::from_business_offline(&base)
            ),
            "PersistentBaseUtxoPage16([REDACTED])"
        );
        assert_eq!(
            format!("{:?}", PersistentAddUtxoPage16::from_business_offline(&add)),
            "PersistentAddUtxoPage16([REDACTED])"
        );
        assert_eq!(
            format!(
                "{:?}",
                PersistentSpendUtxoPage16::from_business_offline(&spend)
            ),
            "PersistentSpendUtxoPage16([REDACTED])"
        );
    }

    #[cfg(feature = "rostl-experimental")]
    #[test]
    fn fixed_page_append_wrappers_build_canonical_pages_on_miss(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let identity = fixed_page_identity(100, 115);
        let created = created_page_entries();
        let spent = spent_page_entries();

        let base_request =
            BasePageAppendRequest::new_offline(identity, created[0], &fixed_page_owner_key)?;
        let base = fixed_base_page_append(
            PersistentBaseUtxoPage16(PersistentFixedUtxoPage(
                [0xa5; PERSISTENT_FIXED_UTXO_PAGE_BYTES],
            )),
            false,
            base_request,
        );
        let expected_base = BaseUtxoPage16::real(identity, &created[..1], &fixed_page_owner_key)?;
        assert!(base.valid);
        assert_eq!(
            base.replacement,
            PersistentBaseUtxoPage16::from_business_offline(&expected_base)
        );
        assert_eq!(
            base.replacement
                .into_business_offline(identity, &fixed_page_owner_key)?,
            expected_base
        );

        let add_request =
            AddPageAppendRequest::new_offline(identity, created[0], &fixed_page_owner_key)?;
        let add = fixed_add_page_append(
            PersistentAddUtxoPage16(PersistentFixedUtxoPage(
                [0x5a; PERSISTENT_FIXED_UTXO_PAGE_BYTES],
            )),
            false,
            add_request,
        );
        let expected_add = AddUtxoPage16::real(identity, &created[..1], &fixed_page_owner_key)?;
        assert!(add.valid);
        assert_eq!(
            add.replacement,
            PersistentAddUtxoPage16::from_business_offline(&expected_add)
        );
        assert_eq!(
            add.replacement
                .into_business_offline(identity, &fixed_page_owner_key)?,
            expected_add
        );

        let spend_request =
            SpendPageAppendRequest::new_offline(identity, spent[0], &fixed_page_owner_key)?;
        let spend = fixed_spend_page_append(
            PersistentSpendUtxoPage16(PersistentFixedUtxoPage(
                [0x3c; PERSISTENT_FIXED_UTXO_PAGE_BYTES],
            )),
            false,
            spend_request,
        );
        let expected_spend = SpendUtxoPage16::real(identity, &spent[..1], &fixed_page_owner_key)?;
        assert!(spend.valid);
        assert_eq!(
            spend.replacement,
            PersistentSpendUtxoPage16::from_business_offline(&expected_spend)
        );
        assert_eq!(
            spend
                .replacement
                .into_business_offline(identity, &fixed_page_owner_key)?,
            expected_spend
        );
        Ok(())
    }

    #[cfg(feature = "rostl-experimental")]
    #[test]
    fn fixed_page_append_accepts_every_nonfull_occupancy_for_each_page_class(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let identity = fixed_page_identity(100, 115);
        let created = created_page_entries();
        let spent = spent_page_entries();

        for (kind, entries) in [
            (FixedUtxoPageKind::Base, created),
            (FixedUtxoPageKind::Add, created),
            (FixedUtxoPageKind::Spend, spent),
        ] {
            for occupied in 0..FIXED_UTXO_PAGE_ENTRIES {
                let found = occupied != 0;
                let prior = if found {
                    persistent_fixed_page(kind, identity, &entries[..occupied])?
                } else {
                    PersistentFixedUtxoPage([0xc3; PERSISTENT_FIXED_UTXO_PAGE_BYTES])
                };
                let transition =
                    fixed_page_append_for_kind(kind, prior, found, identity, entries[occupied])?;
                let expected = FixedUtxoPage::real(
                    kind,
                    identity,
                    &entries[..=occupied],
                    &fixed_page_owner_key,
                )?;
                let expected_persistent = PersistentFixedUtxoPage::from_business_offline(&expected);

                assert!(transition.valid);
                assert_eq!(transition.replacement, expected_persistent);
                assert_eq!(
                    transition.replacement.into_business_offline(
                        kind,
                        identity,
                        &fixed_page_owner_key
                    )?,
                    expected
                );
            }
        }
        Ok(())
    }

    #[cfg(feature = "rostl-experimental")]
    #[test]
    fn fixed_page_append_rejects_full_duplicate_out_of_order_and_dummy_sources(
    ) -> Result<(), FixedUtxoPageError> {
        let identity = fixed_page_identity(100, 115);
        let created = created_page_entries();

        let full = persistent_fixed_page(FixedUtxoPageKind::Base, identity, &created)?;
        let after_full = UtxoEvent::created(
            [0xff; TXID_BYTES],
            16,
            60_000,
            115,
            UtxoScriptClass::PayToPublicKeyHash,
            [0x92; 20],
        );
        assert_invalid_fixed_page_append_preserves(
            FixedUtxoPageKind::Base,
            full,
            identity,
            after_full,
        )?;

        let one = persistent_fixed_page(FixedUtxoPageKind::Base, identity, &created[..1])?;
        assert_invalid_fixed_page_append_preserves(
            FixedUtxoPageKind::Base,
            one,
            identity,
            created[0],
        )?;

        let later_only = persistent_fixed_page(FixedUtxoPageKind::Base, identity, &created[1..2])?;
        assert_invalid_fixed_page_append_preserves(
            FixedUtxoPageKind::Base,
            later_only,
            identity,
            created[0],
        )?;

        let dummy = PersistentFixedUtxoPage::from_business_offline(&FixedUtxoPage::dummy(
            FixedUtxoPageKind::Base,
        ));
        assert_invalid_fixed_page_append_preserves(
            FixedUtxoPageKind::Base,
            dummy,
            identity,
            created[0],
        )?;
        Ok(())
    }

    #[cfg(feature = "rostl-experimental")]
    #[test]
    fn fixed_page_append_rejects_and_preserves_every_malformed_prior_class(
    ) -> Result<(), FixedUtxoPageError> {
        let identity = fixed_page_identity(100, 115);
        let created = created_page_entries();
        let prior = persistent_fixed_page(FixedUtxoPageKind::Base, identity, &created[..2])?;
        let first_event = PERSISTENT_FIXED_UTXO_PAGE_HEADER_BYTES;
        let second_event = first_event + PERSISTENT_UTXO_EVENT_BYTES;
        let fourth_event = first_event + (3 * PERSISTENT_UTXO_EVENT_BYTES);

        let corruptions = [
            mutate_persistent_fixed_page(prior, |bytes| bytes[0] = 2),
            mutate_persistent_fixed_page(prior, |bytes| {
                bytes[1] = FixedUtxoPageKind::Add.to_byte();
            }),
            mutate_persistent_fixed_page(prior, |bytes| {
                bytes[2] = (FIXED_UTXO_PAGE_ENTRIES + 1) as u8;
            }),
            mutate_persistent_fixed_page(prior, |bytes| bytes[3] = 1),
            mutate_persistent_fixed_page(prior, |bytes| bytes[4] ^= 1),
            mutate_persistent_fixed_page(prior, |bytes| bytes[first_event] = 2),
            mutate_persistent_fixed_page(prior, |bytes| {
                bytes[first_event + 1] = UtxoEventKind::Spent.to_byte();
            }),
            mutate_persistent_fixed_page(prior, |bytes| bytes[first_event + 3] = 0),
            mutate_persistent_fixed_page(prior, |bytes| bytes[first_event + 52] ^= 1),
            mutate_persistent_fixed_page(prior, |bytes| {
                bytes[first_event + 48..first_event + 52].copy_from_slice(&116_u32.to_le_bytes());
            }),
            mutate_persistent_fixed_page(prior, |bytes| bytes[fourth_event] = 1),
            mutate_persistent_fixed_page(prior, |bytes| {
                bytes[PERSISTENT_FIXED_UTXO_PAGE_BYTES - 1] = 1;
            }),
            mutate_persistent_fixed_page(prior, |bytes| {
                bytes[first_event + 48..first_event + 52].copy_from_slice(&102_u32.to_le_bytes());
            }),
            mutate_persistent_fixed_page(prior, |bytes| {
                let first_txid_and_index = bytes[first_event + 4..first_event + 40].to_owned();
                bytes[second_event + 4..second_event + 40].copy_from_slice(&first_txid_and_index);
            }),
        ];

        for corrupted in corruptions {
            assert_invalid_fixed_page_append_preserves(
                FixedUtxoPageKind::Base,
                corrupted,
                identity,
                created[2],
            )?;
        }
        Ok(())
    }

    #[cfg(feature = "rostl-experimental")]
    #[test]
    fn fixed_page_append_request_boundary_rejects_uncanonical_inputs_and_redacts_debug() {
        let identity = fixed_page_identity(100, 115);
        let created = created_page_entries();
        let spent = spent_page_entries();

        let mut wrong_owner = created[0];
        wrong_owner.script_hash = [0x93; 20];
        assert!(matches!(
            BasePageAppendRequest::new_offline(identity, wrong_owner, &fixed_page_owner_key),
            Err(FixedUtxoPageError::AddressKeyMismatch { index: 0 })
        ));
        assert!(matches!(
            BasePageAppendRequest::new_offline(identity, spent[0], &fixed_page_owner_key),
            Err(FixedUtxoPageError::WrongEventKind { index: 0, .. })
        ));

        let nonstandard = UtxoEvent::created(
            [0x41; TXID_BYTES],
            1,
            50_000,
            100,
            UtxoScriptClass::NonStandard,
            [0x42; 20],
        );
        assert!(matches!(
            BasePageAppendRequest::new_offline(identity, nonstandard, &fixed_page_owner_key),
            Err(FixedUtxoPageError::NonStandardEvent { index: 0 })
        ));

        let request =
            BasePageAppendRequest::new_offline(identity, created[0], &fixed_page_owner_key)
                .expect("fixture request is canonical");
        assert_eq!(
            format!("{:?}", request.0),
            "FixedPageAppendRequest { ..REDACTED.. }"
        );
    }

    #[cfg(feature = "rostl-experimental")]
    #[test]
    fn fixed_page_append_revalidates_raw_request_identity_and_event_state(
    ) -> Result<(), FixedUtxoPageError> {
        let identity = fixed_page_identity(100, 115);
        let created = created_page_entries();
        let canonical = FixedPageAppendRequest::new_offline(
            FixedUtxoPageKind::Base,
            identity,
            created[0],
            &fixed_page_owner_key,
        )?;
        let prior = PersistentFixedUtxoPage([0x69; PERSISTENT_FIXED_UTXO_PAGE_BYTES]);

        let mut zero_generation = canonical;
        zero_generation.identity[32..40].fill(0);
        let mut inverted_range = canonical;
        inverted_range.identity[44..48].copy_from_slice(&116_u32.to_le_bytes());
        inverted_range.identity[48..52].copy_from_slice(&115_u32.to_le_bytes());
        let mut wrong_version = canonical;
        wrong_version.event.0[0] = 2;
        let mut wrong_class = canonical;
        wrong_class.event.0[2] = UtxoScriptClass::NonStandard.to_byte();
        let mut wrong_flags = canonical;
        wrong_flags.event.0[3] = 0;

        for request in [
            zero_generation,
            inverted_range,
            wrong_version,
            wrong_class,
            wrong_flags,
        ] {
            let transition = fixed_page_append(
                prior,
                false,
                request,
                FixedUtxoPageKind::Base.to_byte(),
                UtxoEventKind::Created.to_byte(),
                UTXO_EVENT_FLAG_MINED,
            );
            assert!(!transition.valid);
            assert_eq!(transition.replacement, prior);
        }
        Ok(())
    }

    #[cfg(feature = "rostl-experimental")]
    #[test]
    fn fixed_page_append_orders_equal_height_and_txid_by_numeric_output_index(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let identity = fixed_page_identity(100, 115);
        let first = UtxoEvent::created(
            [0x55; TXID_BYTES],
            7,
            50_000,
            100,
            UtxoScriptClass::PayToPublicKeyHash,
            [0x92; 20],
        );
        let prior = persistent_fixed_page(FixedUtxoPageKind::Base, identity, &[first])?;
        let above = UtxoEvent::created(
            [0x55; TXID_BYTES],
            8,
            50_001,
            100,
            UtxoScriptClass::PayToPublicKeyHash,
            [0x92; 20],
        );
        let accepted =
            fixed_page_append_for_kind(FixedUtxoPageKind::Base, prior, true, identity, above)?;
        let expected = FixedUtxoPage::real(
            FixedUtxoPageKind::Base,
            identity,
            &[first, above],
            &fixed_page_owner_key,
        )?;
        assert!(accepted.valid);
        assert_eq!(
            accepted.replacement,
            PersistentFixedUtxoPage::from_business_offline(&expected)
        );

        let below = UtxoEvent::created(
            [0x55; TXID_BYTES],
            6,
            49_999,
            100,
            UtxoScriptClass::PayToPublicKeyHash,
            [0x92; 20],
        );
        assert_invalid_fixed_page_append_preserves(
            FixedUtxoPageKind::Base,
            prior,
            identity,
            below,
        )?;
        Ok(())
    }

    #[cfg(feature = "rostl-experimental")]
    #[test]
    fn fixed_spend_page_append_rejects_wrong_flags_in_a_found_page(
    ) -> Result<(), FixedUtxoPageError> {
        let identity = fixed_page_identity(100, 115);
        let spent = spent_page_entries();
        let page = SpendUtxoPage16::real(identity, &spent[..2], &fixed_page_owner_key)?;
        let mut prior = PersistentSpendUtxoPage16::from_business_offline(&page);
        (prior.0).0[PERSISTENT_FIXED_UTXO_PAGE_HEADER_BYTES + 3] = UTXO_EVENT_FLAG_MINED;
        let request =
            SpendPageAppendRequest::new_offline(identity, spent[2], &fixed_page_owner_key)?;
        let transition = fixed_spend_page_append(prior, true, request);
        assert!(!transition.valid);
        assert_eq!(transition.replacement, prior);
        Ok(())
    }

    #[test]
    fn address_directory_round_trips_real_and_canonical_dummy_cells(
    ) -> Result<(), PersistentAddressDirectoryError> {
        let dummy = AddressDirectory::dummy();
        let real = AddressDirectory::real(17, AddressKey::new([0x5a; ADDRESS_KEY_BYTES]));
        let zero_identity = AddressDirectory::real(0, AddressKey::new([0; ADDRESS_KEY_BYTES]));
        let max_slot = AddressDirectory::real(u32::MAX, AddressKey::new([0xa5; ADDRESS_KEY_BYTES]));

        for business in [dummy, real, zero_identity, max_slot] {
            let persistent = PersistentAddressDirectory::from_business(&business);
            assert_eq!(
                std::mem::size_of_val(&persistent),
                PERSISTENT_ADDRESS_DIRECTORY_BYTES
            );
            assert_eq!(persistent.into_business()?, business);
        }
        assert!(zero_identity.is_occupied());

        let dummy_bytes = PersistentAddressDirectory::from_business(&dummy).0;
        assert_eq!(dummy_bytes[0], ADDRESS_CELL_FORMAT_VERSION);
        assert!(dummy_bytes[1..].iter().all(|byte| *byte == 0));
        let real_bytes = PersistentAddressDirectory::from_business(&real).0;
        assert_eq!(real_bytes[1], ADDRESS_CELL_FLAG_OCCUPIED);
        assert_eq!(&real_bytes[2..6], &17_u32.to_le_bytes());
        assert_eq!(&real_bytes[6..], &[0x5a; ADDRESS_KEY_BYTES]);
        Ok(())
    }

    #[test]
    fn address_directory_revalidates_header_and_every_dummy_payload_byte() {
        let valid_dummy = PersistentAddressDirectory::from_business(&AddressDirectory::dummy());
        let mut wrong_version = valid_dummy.0;
        wrong_version[0] = 2;
        assert_eq!(
            PersistentAddressDirectory(wrong_version).into_business(),
            Err(PersistentAddressDirectoryError::Header(
                PersistentAddressCellHeaderError::UnsupportedVersion { actual: 2 }
            ))
        );
        let mut wrong_flags = valid_dummy.0;
        wrong_flags[1] = 2;
        assert_eq!(
            PersistentAddressDirectory(wrong_flags).into_business(),
            Err(PersistentAddressDirectoryError::Header(
                PersistentAddressCellHeaderError::InvalidFlags { actual: 2 }
            ))
        );
        for index in 2..PERSISTENT_ADDRESS_DIRECTORY_BYTES {
            let mut noncanonical = valid_dummy.0;
            noncanonical[index] = 1;
            assert_eq!(
                PersistentAddressDirectory(noncanonical).into_business(),
                Err(PersistentAddressDirectoryError::NoncanonicalDummy)
            );
        }
    }

    #[test]
    fn all_zero_address_cell_scratch_is_not_a_canonical_dummy() {
        assert_eq!(
            PersistentAddressDirectory::default().into_business(),
            Err(PersistentAddressDirectoryError::Header(
                PersistentAddressCellHeaderError::UnsupportedVersion { actual: 0 }
            ))
        );
        assert_eq!(
            PersistentAddressEventPage::default().into_business(),
            Err(PersistentAddressEventPageError::Header(
                PersistentAddressCellHeaderError::UnsupportedVersion { actual: 0 }
            ))
        );
    }

    #[test]
    fn one_event_page_round_trips_standard_events_and_canonical_dummy(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let dummy = AddressEventPage::dummy();
        assert!(!dummy.is_occupied());
        let pages = [
            AddressEventPage::real(9, 0, sample_created_event())?,
            AddressEventPage::real(9, 1, sample_spent_event())?,
            AddressEventPage::real(u32::MAX, u32::MAX, sample_created_event())?,
        ];
        for page in pages {
            let persistent = PersistentAddressEventPage::from_business(&page);
            assert_eq!(
                std::mem::size_of_val(&persistent),
                PERSISTENT_ADDRESS_EVENT_PAGE_BYTES
            );
            assert_eq!(persistent.into_business()?, page);
        }

        let dummy_bytes = PersistentAddressEventPage::from_business(&dummy).0;
        assert_eq!(dummy_bytes[0], ADDRESS_CELL_FORMAT_VERSION);
        assert!(dummy_bytes[1..].iter().all(|byte| *byte == 0));
        let real_bytes = PersistentAddressEventPage::from_business(&pages[0]).0;
        assert_eq!(real_bytes[1], ADDRESS_CELL_FLAG_OCCUPIED);
        assert_eq!(&real_bytes[2..6], &9_u32.to_le_bytes());
        assert_eq!(&real_bytes[6..10], &0_u32.to_le_bytes());
        assert_eq!(
            &real_bytes[10..],
            &PersistentUtxoEvent::from_business(&sample_created_event()).0
        );
        Ok(())
    }

    #[test]
    fn one_event_page_rejects_nonstandard_business_events() {
        let event = UtxoEvent::created(
            [0x71; TXID_BYTES],
            2,
            50_000,
            200,
            UtxoScriptClass::NonStandard,
            [0x72; 20],
        );
        assert_eq!(
            AddressEventPage::real(3, 4, event),
            Err(AddressEventPageError::NonStandardEvent)
        );
    }

    #[test]
    fn one_event_page_revalidates_header_and_every_dummy_payload_byte() {
        let valid_dummy = PersistentAddressEventPage::from_business(&AddressEventPage::dummy());
        let mut wrong_version = valid_dummy.0;
        wrong_version[0] = 2;
        assert_eq!(
            PersistentAddressEventPage(wrong_version).into_business(),
            Err(PersistentAddressEventPageError::Header(
                PersistentAddressCellHeaderError::UnsupportedVersion { actual: 2 }
            ))
        );
        // Bit 4 and above are outside the event page's complete flag set.
        let mut wrong_flags = valid_dummy.0;
        wrong_flags[1] = 1 << 4;
        assert_eq!(
            PersistentAddressEventPage(wrong_flags).into_business(),
            Err(PersistentAddressEventPageError::Header(
                PersistentAddressCellHeaderError::InvalidFlags { actual: 1 << 4 }
            ))
        );
        // The annotation bits are inside that set but meaningless on a dummy.
        for annotation_bits in [
            ADDRESS_CELL_FLAG_ANNOTATED,
            ADDRESS_CELL_FLAG_SURVIVES,
            ADDRESS_CELL_FLAG_VALID,
        ] {
            let mut annotated_dummy = valid_dummy.0;
            annotated_dummy[1] = annotation_bits;
            assert_eq!(
                PersistentAddressEventPage(annotated_dummy).into_business(),
                Err(PersistentAddressEventPageError::NoncanonicalAnnotation)
            );
        }
        for index in 2..PERSISTENT_ADDRESS_EVENT_PAGE_BYTES {
            let mut noncanonical = valid_dummy.0;
            noncanonical[index] = 1;
            assert_eq!(
                PersistentAddressEventPage(noncanonical).into_business(),
                Err(PersistentAddressEventPageError::NoncanonicalDummy)
            );
        }
    }

    /// The annotation is the one mutable field on a stored record, and the one
    /// field replay identity must not see. Both halves are asserted here: the
    /// bytes change, and the business comparison does not.
    #[test]
    fn annotation_round_trips_without_entering_replay_identity() {
        let page =
            AddressEventPage::real(7, 2, sample_created_event()).expect("sample event is standard");
        assert_eq!(page.annotation(), RecordAnnotation::Unannotated);

        for annotation in [
            RecordAnnotation::Annotated {
                survives: false,
                valid: false,
            },
            RecordAnnotation::Annotated {
                survives: true,
                valid: false,
            },
            RecordAnnotation::Annotated {
                survives: false,
                valid: true,
            },
            RecordAnnotation::Annotated {
                survives: true,
                valid: true,
            },
        ] {
            let annotated = page.annotated(annotation).expect("occupied page annotates");
            assert_eq!(annotated.annotation(), annotation);
            // Replay identity ignores it.
            assert_eq!(annotated, page);
            // The stored bytes do not.
            let persistent = PersistentAddressEventPage::from_business(&annotated);
            assert_ne!(persistent, PersistentAddressEventPage::from_business(&page));
            // Only the flag byte moves: the record width, and with it the ORAM
            // block size, is unchanged.
            assert_eq!(
                persistent.0[2..],
                PersistentAddressEventPage::from_business(&page).0[2..]
            );
            let decoded = persistent.into_business().expect("annotated page decodes");
            assert_eq!(decoded.annotation(), annotation);
            assert_eq!(decoded, annotated);
        }
    }

    #[test]
    fn a_dummy_page_refuses_an_annotation() {
        assert_eq!(
            AddressEventPage::dummy().annotated(RecordAnnotation::Annotated {
                survives: true,
                valid: true,
            }),
            Err(AddressEventPageError::AnnotatedDummy)
        );
    }

    /// The survives/valid bits are meaningless without the annotated bit, so a
    /// record that sets one alone is corruption rather than an unannotated
    /// record with stray bits.
    #[test]
    fn annotation_bits_without_the_annotated_bit_are_rejected() {
        let page =
            AddressEventPage::real(1, 0, sample_created_event()).expect("sample event is standard");
        let encoded = PersistentAddressEventPage::from_business(&page);
        for stray in [ADDRESS_CELL_FLAG_SURVIVES, ADDRESS_CELL_FLAG_VALID] {
            let mut bytes = encoded.0;
            bytes[1] |= stray;
            assert_eq!(
                PersistentAddressEventPage(bytes).into_business(),
                Err(PersistentAddressEventPageError::NoncanonicalAnnotation)
            );
        }
    }

    /// A directory cell has no annotation, so the bits an event page defines
    /// must not be silently accepted there.
    #[test]
    fn a_directory_cell_rejects_the_event_annotation_bits() {
        let encoded = PersistentAddressDirectory::from_business(&AddressDirectory::real(
            3,
            AddressKey::new([0x44; ADDRESS_KEY_BYTES]),
        ));
        let mut bytes = encoded.0;
        bytes[1] |= ADDRESS_CELL_FLAG_ANNOTATED;
        assert_eq!(
            PersistentAddressDirectory(bytes).into_business(),
            Err(PersistentAddressDirectoryError::Header(
                PersistentAddressCellHeaderError::InvalidFlags {
                    actual: ADDRESS_CELL_FLAG_OCCUPIED | ADDRESS_CELL_FLAG_ANNOTATED
                }
            ))
        );
    }

    #[test]
    fn one_event_page_revalidates_nested_events_and_standard_class() {
        let page =
            AddressEventPage::real(4, 5, sample_created_event()).expect("sample event is standard");
        let valid = PersistentAddressEventPage::from_business(&page);
        let mut invalid_event = valid.0;
        invalid_event[10] = 2;
        assert_eq!(
            PersistentAddressEventPage(invalid_event).into_business(),
            Err(PersistentAddressEventPageError::InvalidEvent(
                PersistentUtxoEventError::UnsupportedVersion { actual: 2 }
            ))
        );

        let mut zero_event = valid.0;
        zero_event[10..].fill(0);
        assert_eq!(
            PersistentAddressEventPage(zero_event).into_business(),
            Err(PersistentAddressEventPageError::InvalidEvent(
                PersistentUtxoEventError::UnsupportedVersion { actual: 0 }
            ))
        );

        let nonstandard = UtxoEvent::created(
            [0x81; TXID_BYTES],
            6,
            60_000,
            300,
            UtxoScriptClass::NonStandard,
            [0x82; 20],
        );
        let mut nonstandard_page = valid.0;
        nonstandard_page[10..].copy_from_slice(&PersistentUtxoEvent::from_business(&nonstandard).0);
        assert_eq!(
            PersistentAddressEventPage(nonstandard_page).into_business(),
            Err(PersistentAddressEventPageError::NonStandardEvent)
        );
    }

    #[cfg(feature = "rostl-experimental")]
    #[test]
    fn address_records_satisfy_pod_and_cmov_constraints_and_semantics() {
        fn assert_semantics<T>(left: T, right: T)
        where
            T: bytemuck::Pod + rostl_primitives::traits::Cmov + Copy + PartialEq + fmt::Debug,
        {
            let mut destination = left;
            destination.cmov(&right, false);
            assert_eq!(destination, left);
            destination.cmov(&right, true);
            assert_eq!(destination, right);

            let mut exchange_left = left;
            let mut exchange_right = right;
            exchange_left.cxchg(&mut exchange_right, false);
            assert_eq!((exchange_left, exchange_right), (left, right));
            exchange_left.cxchg(&mut exchange_right, true);
            assert_eq!((exchange_left, exchange_right), (right, left));
        }

        assert_semantics(
            PersistentUtxoEvent::from_business(&sample_created_event()),
            PersistentUtxoEvent::from_business(&sample_spent_event()),
        );
        let identity = fixed_page_identity(100, 115);
        let created = created_page_entries();
        let spent = spent_page_entries();
        assert_semantics(
            PersistentBaseUtxoPage16::from_business_offline(&BaseUtxoPage16::dummy()),
            PersistentBaseUtxoPage16::from_business_offline(
                &BaseUtxoPage16::real(identity, &created, &fixed_page_owner_key)
                    .expect("fixture base page is canonical"),
            ),
        );
        assert_semantics(
            PersistentAddUtxoPage16::from_business_offline(&AddUtxoPage16::dummy()),
            PersistentAddUtxoPage16::from_business_offline(
                &AddUtxoPage16::real(identity, &created, &fixed_page_owner_key)
                    .expect("fixture add page is canonical"),
            ),
        );
        assert_semantics(
            PersistentSpendUtxoPage16::from_business_offline(&SpendUtxoPage16::dummy()),
            PersistentSpendUtxoPage16::from_business_offline(
                &SpendUtxoPage16::real(identity, &spent, &fixed_page_owner_key)
                    .expect("fixture spend page is canonical"),
            ),
        );
        assert_semantics(
            PersistentAddressDirectory::from_business(&AddressDirectory::dummy()),
            PersistentAddressDirectory::from_business(&AddressDirectory::real(
                u32::MAX,
                AddressKey::new([0x70; ADDRESS_KEY_BYTES]),
            )),
        );
        assert_semantics(
            PersistentAddressEventPage::from_business(&AddressEventPage::dummy()),
            PersistentAddressEventPage::from_business(
                &AddressEventPage::real(u32::MAX, u32::MAX, sample_created_event())
                    .expect("sample event is standard"),
            ),
        );
    }

    #[test]
    fn address_cell_debug_surfaces_are_redacted() {
        let directory = AddressDirectory::real(0x5151, AddressKey::new([0x52; 32]));
        let page = AddressEventPage::real(0x5151, 0x5353, sample_created_event())
            .expect("sample event is standard");
        let persistent_directory = PersistentAddressDirectory::from_business(&directory);
        let persistent_page = PersistentAddressEventPage::from_business(&page);

        assert_eq!(
            format!("{directory:?}"),
            "AddressDirectory { ..REDACTED.. }"
        );
        assert_eq!(format!("{page:?}"), "AddressEventPage { ..REDACTED.. }");
        assert_eq!(
            format!("{persistent_directory:?}"),
            "PersistentAddressDirectory([REDACTED])"
        );
        assert_eq!(
            format!("{persistent_page:?}"),
            "PersistentAddressEventPage([REDACTED])"
        );
        for formatted in [
            format!("{directory:?}"),
            format!("{page:?}"),
            format!("{persistent_directory:?}"),
            format!("{persistent_page:?}"),
        ] {
            assert!(!formatted.contains("5151"));
            assert!(!formatted.contains("5353"));
            assert!(!formatted.contains("5252"));
        }
    }

    #[test]
    fn untrusted_invalid_key_becomes_fixed_dummy_query() {
        let query = UtxoQuery::from_untrusted_address_key(&[0x44; 31], 10);
        assert!(!query.domain_valid());
        assert_eq!(
            query.address_key(),
            &AddressKey::new([0; ADDRESS_KEY_BYTES])
        );
        assert_eq!(format!("{query:?}"), "UtxoQuery { ..REDACTED.. }");
    }

    #[test]
    fn result_page_has_compile_time_fixed_shape() {
        let mut page = UtxoResultPage::<3>::empty();
        page.set_slot(0, sample_utxo(10));
        assert_eq!(page.slots().len(), 3);
        assert_eq!(page.real_count(), 1);
        assert!(page.slots()[0].is_occupied());
        assert_eq!(page.slots()[0].padded_utxo(), &sample_utxo(10));
        assert!(!page.slots()[1].is_occupied());
    }

    #[test]
    fn protected_outcomes_have_constant_debug_output() {
        let outcomes = [
            QueryOutcome::Complete,
            QueryOutcome::ResultBudgetExceeded,
            QueryOutcome::InvalidDomain,
            QueryOutcome::StoreFailure,
            QueryOutcome::ProjectionNotReady,
            QueryOutcome::InvalidContinuation,
        ];
        for outcome in outcomes {
            assert_eq!(format!("{outcome:?}"), "QueryOutcome([REDACTED])");
        }
    }

    #[test]
    fn sensitive_records_have_redacted_debug_output() {
        let key = AddressKey::new([0x22; ADDRESS_KEY_BYTES]);
        let query = UtxoQuery::new(key, 7);
        let utxo = sample_utxo(10);
        let slot = UtxoResultSlot::real(utxo);
        let mut page = UtxoResultPage::<1>::empty();
        page.set_slot(0, utxo);

        assert_eq!(format!("{key:?}"), "AddressKey([REDACTED; 32])");
        assert_eq!(format!("{query:?}"), "UtxoQuery { ..REDACTED.. }");
        assert_eq!(format!("{utxo:?}"), "TransparentUtxo { ..REDACTED.. }");
        assert_eq!(format!("{slot:?}"), "UtxoResultSlot { ..REDACTED.. }");
        assert_eq!(format!("{page:?}"), "UtxoResultPage { slots: 1, .. }");
    }
}
