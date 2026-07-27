#[cfg(test)]
use std::fmt;

use crate::records::{AddressKey, TransparentUtxo};
#[cfg(test)]
use crate::records::{PersistentAddressKey, PersistentTransparentUtxo, UtxoRecordError};

/// One fixed-shape logical store result.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct StoreSlot {
    occupied: bool,
    record: TransparentUtxo,
}

impl StoreSlot {
    pub(super) fn dummy() -> Self {
        Self {
            occupied: false,
            record: TransparentUtxo::dummy(),
        }
    }

    pub(super) fn occupied(record: TransparentUtxo) -> Self {
        Self {
            occupied: true,
            record,
        }
    }

    pub(super) const fn is_occupied(&self) -> bool {
        self.occupied
    }

    pub(super) const fn record(&self) -> &TransparentUtxo {
        &self.record
    }
}

/// Logical store operations required by the query-schedule model.
///
/// Implementing this trait does not make a store oblivious. A production
/// adapter must independently guarantee that each call has an acceptable,
/// query-independent physical access distribution and recovery behavior.
pub(super) trait ObliviousStore {
    /// Store-specific read failure.
    type Error;

    /// Returns the complete number of logical slots addressable for one key.
    fn slots_per_key(&self) -> usize;

    /// Reads one fixed logical slot for an address-derived key.
    fn read_slot(
        &mut self,
        address_key: &AddressKey,
        slot: usize,
    ) -> Result<StoreSlot, Self::Error>;
}

#[cfg(test)]
#[derive(Clone, Copy, PartialEq, Eq)]
struct StoredEntry {
    address_key: PersistentAddressKey,
    slot: usize,
    utxo: PersistentTransparentUtxo,
}

/// A deterministic plaintext store for unit tests and offline research.
///
/// This implementation scans ordinary memory and is explicitly not an ORAM.
/// It exists only to exercise logical query schedules, fixed shapes, boundary
/// conversions, completeness bounds, and error handling.
#[cfg(test)]
pub(super) struct PlaintextMockStore {
    entries: Vec<StoredEntry>,
    slots_per_key: usize,
    entry_capacity: usize,
    read_slots: Vec<usize>,
    fail_on_read: Option<usize>,
}

#[cfg(test)]
impl PlaintextMockStore {
    /// Builds an empty plaintext mock with fixed per-key slots and capacity.
    pub(super) fn new(slots_per_key: usize, entry_capacity: usize) -> Self {
        Self {
            entries: Vec::with_capacity(entry_capacity),
            slots_per_key,
            entry_capacity,
            read_slots: Vec::new(),
            fail_on_read: None,
        }
    }

    /// Configures one one-based logical read number to fail.
    pub(super) fn with_failure_on_read(mut self, read_number: usize) -> Self {
        self.fail_on_read = Some(read_number);
        self
    }

    /// Inserts one address slot into the bounded plaintext mock.
    pub(super) fn insert(
        &mut self,
        address_key: &AddressKey,
        slot: usize,
        utxo: &TransparentUtxo,
    ) -> Result<(), PlaintextMockStoreError> {
        if slot >= self.slots_per_key {
            return Err(PlaintextMockStoreError::SlotOutOfRange {
                slot,
                slots_per_key: self.slots_per_key,
            });
        }
        if self
            .entries
            .iter()
            .any(|entry| entry.address_key.into_business() == *address_key && entry.slot == slot)
        {
            return Err(PlaintextMockStoreError::DuplicateSlot { slot });
        }
        if self.entries.len() == self.entry_capacity {
            return Err(PlaintextMockStoreError::CapacityExceeded {
                capacity: self.entry_capacity,
            });
        }
        self.entries.push(StoredEntry {
            address_key: PersistentAddressKey::from_business(address_key),
            slot,
            utxo: PersistentTransparentUtxo::from_business(utxo),
        });
        Ok(())
    }

    /// Returns the exact public slot ordinals requested from the mock.
    pub(super) fn read_slots(&self) -> &[usize] {
        &self.read_slots
    }
}

#[cfg(test)]
impl fmt::Debug for PlaintextMockStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PlaintextMockStore")
            .field("slots_per_key", &self.slots_per_key)
            .field("entry_capacity", &self.entry_capacity)
            .field("entries", &self.entries.len())
            .field("reads", &self.read_slots.len())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
impl ObliviousStore for PlaintextMockStore {
    type Error = PlaintextMockStoreError;

    fn slots_per_key(&self) -> usize {
        self.slots_per_key
    }

    fn read_slot(
        &mut self,
        address_key: &AddressKey,
        slot: usize,
    ) -> Result<StoreSlot, Self::Error> {
        self.read_slots.push(slot);
        if self.fail_on_read == Some(self.read_slots.len()) {
            return Err(PlaintextMockStoreError::InjectedReadFailure {
                read_number: self.read_slots.len(),
            });
        }

        // Scan the complete public entry set even after a match. This mock is
        // still plaintext and branchy, but query keys do not change scan length.
        let mut selected = None;
        for entry in &self.entries {
            if entry.address_key.into_business() == *address_key && entry.slot == slot {
                selected = Some(entry.utxo);
            }
        }
        match selected {
            Some(persistent) => persistent
                .into_business()
                .map(StoreSlot::occupied)
                .map_err(PlaintextMockStoreError::CorruptRecord),
            None => Ok(StoreSlot::dummy()),
        }
    }
}

/// A deterministic plaintext-mock operation failed.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PlaintextMockStoreError {
    /// An insertion would exceed the mock's fixed entry capacity.
    CapacityExceeded {
        /// Configured entry capacity.
        capacity: usize,
    },
    /// An address already has a record at this logical slot.
    DuplicateSlot {
        /// Duplicate logical slot.
        slot: usize,
    },
    /// An insertion lies outside the complete per-key slot domain.
    SlotOutOfRange {
        /// Rejected logical slot.
        slot: usize,
        /// Configured complete per-key slot count.
        slots_per_key: usize,
    },
    /// A test-requested read failure was reached.
    InjectedReadFailure {
        /// One-based read number that failed.
        read_number: usize,
    },
    /// A stored fixed record failed persistence-boundary validation.
    CorruptRecord(UtxoRecordError),
}

#[cfg(test)]
impl fmt::Display for PlaintextMockStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CapacityExceeded { capacity } => {
                write!(f, "plaintext mock capacity {capacity} exceeded")
            }
            Self::DuplicateSlot { slot } => {
                write!(f, "plaintext mock slot {slot} already exists for this key")
            }
            Self::SlotOutOfRange {
                slot,
                slots_per_key,
            } => write!(
                f,
                "plaintext mock slot {slot} is outside the {slots_per_key}-slot key domain"
            ),
            Self::InjectedReadFailure { read_number } => {
                write!(f, "plaintext mock injected failure at read {read_number}")
            }
            Self::CorruptRecord(error) => {
                write!(f, "plaintext mock record is invalid: {error}")
            }
        }
    }
}

#[cfg(test)]
impl std::error::Error for PlaintextMockStoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::CorruptRecord(error) => Some(error),
            Self::CapacityExceeded { .. }
            | Self::DuplicateSlot { .. }
            | Self::SlotOutOfRange { .. }
            | Self::InjectedReadFailure { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::records::{ADDRESS_KEY_BYTES, TXID_BYTES};

    fn sample_utxo() -> TransparentUtxo {
        TransparentUtxo::new([0x22; TXID_BYTES], 1, 500, 99, &[0x51; 25])
            .expect("sample transparent script fits the fixed record")
    }

    #[test]
    fn plaintext_mock_reads_fixed_slot_shape() -> Result<(), Box<dyn std::error::Error>> {
        let key = AddressKey::new([0x11; ADDRESS_KEY_BYTES]);
        let utxo = sample_utxo();
        let mut store = PlaintextMockStore::new(2, 1);
        store.insert(&key, 0, &utxo)?;
        let occupied = store.read_slot(&key, 0)?;
        let dummy = store.read_slot(&key, 1)?;
        assert!(occupied.is_occupied());
        assert_eq!(occupied.record(), &utxo);
        assert!(!dummy.is_occupied());
        assert_eq!(dummy.record(), &TransparentUtxo::dummy());
        assert_eq!(store.read_slots(), &[0, 1]);
        Ok(())
    }

    #[test]
    fn plaintext_mock_enforces_capacity_unique_and_complete_slot_domain(
    ) -> Result<(), PlaintextMockStoreError> {
        let key = AddressKey::new([0x11; ADDRESS_KEY_BYTES]);
        let other_key = AddressKey::new([0x33; ADDRESS_KEY_BYTES]);
        let utxo = sample_utxo();
        let mut store = PlaintextMockStore::new(2, 1);
        store.insert(&key, 0, &utxo)?;
        assert_eq!(
            store.insert(&key, 0, &utxo),
            Err(PlaintextMockStoreError::DuplicateSlot { slot: 0 })
        );
        assert_eq!(
            store.insert(&other_key, 0, &utxo),
            Err(PlaintextMockStoreError::CapacityExceeded { capacity: 1 })
        );
        assert_eq!(
            store.insert(&key, 2, &utxo),
            Err(PlaintextMockStoreError::SlotOutOfRange {
                slot: 2,
                slots_per_key: 2,
            })
        );
        Ok(())
    }
}
