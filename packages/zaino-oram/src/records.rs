use std::fmt;

/// Byte length of an address-derived ORAM key.
pub(super) const ADDRESS_KEY_BYTES: usize = 32;

/// Byte length of a Zcash transaction identifier.
pub(super) const TXID_BYTES: usize = 32;

/// Fixed storage reserved for a supported transparent locking script.
///
/// The research corpus gate must confirm that every script accepted by the
/// private transparent-address API fits this bound. Unsupported shapes fail
/// closed instead of entering a variable-length fallback.
const TRANSPARENT_SCRIPT_CAPACITY: usize = 34;

/// Exact byte width of the append-only event candidate exercised by the
/// experimental ORAM adapter.
pub(super) const PERSISTENT_UTXO_EVENT_BYTES: usize = 72;

const UTXO_EVENT_FORMAT_VERSION: u8 = 1;
const UTXO_EVENT_FLAG_MINED: u8 = 1 << 0;
const UTXO_EVENT_FLAG_SPENT: u8 = 1 << 1;
const UTXO_EVENT_KNOWN_FLAGS: u8 = UTXO_EVENT_FLAG_MINED | UTXO_EVENT_FLAG_SPENT;

/// A domain-separated digest of a canonical transparent locking script.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub(super) struct AddressKey([u8; ADDRESS_KEY_BYTES]);

impl AddressKey {
    /// Builds an address key from an already domain-separated digest.
    pub(super) const fn new(bytes: [u8; ADDRESS_KEY_BYTES]) -> Self {
        Self(bytes)
    }

    /// Returns the fixed digest bytes.
    const fn as_bytes(&self) -> &[u8; ADDRESS_KEY_BYTES] {
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
    const fn txid(&self) -> &[u8; TXID_BYTES] {
        &self.txid
    }

    /// Returns the transparent output index.
    const fn output_index(&self) -> u32 {
        self.output_index
    }

    /// Returns the output value in zatoshis.
    const fn value_zat(&self) -> u64 {
        self.value_zat
    }

    /// Returns the mined height.
    pub(super) const fn height(&self) -> u32 {
        self.height
    }

    /// Returns the occupied locking-script byte length.
    const fn script_len(&self) -> usize {
        self.script_len as usize
    }

    /// Returns every real and padded locking-script byte.
    const fn padded_script(&self) -> &[u8; TRANSPARENT_SCRIPT_CAPACITY] {
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

    const fn value_zat(&self) -> u64 {
        self.value_zat
    }

    const fn height(&self) -> u32 {
        self.height
    }

    const fn script_class(&self) -> UtxoScriptClass {
        self.script_class
    }

    const fn script_hash(&self) -> &[u8; 20] {
        &self.script_hash
    }
}

impl fmt::Debug for UtxoEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("UtxoEvent { ..REDACTED.. }")
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

    #[cfg(all(
        feature = "rostl-experimental",
        target_os = "linux",
        target_arch = "x86_64"
    ))]
    pub(super) const fn zeroed() -> Self {
        Self([0; PERSISTENT_UTXO_EVENT_BYTES])
    }
}

impl Default for PersistentUtxoEvent {
    fn default() -> Self {
        Self([0; PERSISTENT_UTXO_EVENT_BYTES])
    }
}

#[cfg(feature = "rostl-experimental")]
impl rostl_primitives::traits::Cmov for PersistentUtxoEvent {
    fn cmov(&mut self, other: &Self, choice: bool) {
        for (destination, source) in self.0.iter_mut().zip(other.0.iter()) {
            rostl_primitives::traits::Cmov::cmov(destination, source, choice);
        }
    }

    fn cxchg(&mut self, other: &mut Self, choice: bool) {
        for (left, right) in self.0.iter_mut().zip(other.0.iter_mut()) {
            rostl_primitives::traits::Cmov::cxchg(left, right, choice);
        }
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
pub(super) enum QueryOutcome {
    /// All matching records fit in the configured result budget.
    Complete,
    /// More matching records existed than the profile permits returning.
    ResultBudgetExceeded,
    /// The protected request did not contain a valid address-key domain value.
    InvalidDomain,
    /// The store could not complete at least one logical read.
    StoreFailure,
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
    const fn is_occupied(&self) -> bool {
        self.occupied
    }

    /// Returns the fixed record for both real and dummy slots.
    const fn padded_utxo(&self) -> &TransparentUtxo {
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

    /// Returns the protected query outcome.
    pub(super) const fn outcome(&self) -> QueryOutcome {
        self.outcome
    }

    /// Returns every real and dummy result slot.
    pub(super) const fn slots(&self) -> &[UtxoResultSlot; N] {
        &self.slots
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
