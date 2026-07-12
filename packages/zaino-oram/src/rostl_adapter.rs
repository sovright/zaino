//! Offline-only adapter proving the fixed event candidate satisfies `rostl`.

use std::fmt;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use rand::Rng as _;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use rostl_oram::{
    circuit_oram::CircuitORAM, prelude::PositionType, recursive_oram::RecursivePositionMap,
};
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use std::panic::{catch_unwind, AssertUnwindSafe};

#[cfg(any(test, all(target_os = "linux", target_arch = "x86_64")))]
use crate::records::PersistentUtxoEvent;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use crate::records::PersistentUtxoEventError;

/// Volatile research adapter for the exact fixed event candidate.
///
/// This is deliberately not an [`crate::store::ObliviousStore`] backend: the
/// upstream crate has no durable storage/recovery contract and exposes panic
/// failure paths. It exists only to compile and exercise the candidate record
/// against the pinned API on the intended target.
pub(super) struct RostlCandidateStore {
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    oram: CircuitORAM<PersistentUtxoEvent>,
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    position_map: RecursivePositionMap,
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    capacity: usize,
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    failed_closed: bool,
}

impl RostlCandidateStore {
    pub(super) fn new(capacity: usize) -> Result<Self, RostlAdapterError> {
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        {
            if !(2..=u32::MAX as usize).contains(&capacity) {
                return Err(RostlAdapterError::InvalidCapacity { capacity });
            }
            catch_upstream(|| Self {
                oram: CircuitORAM::new(capacity),
                position_map: RecursivePositionMap::new(capacity),
                capacity,
                failed_closed: false,
            })
            .map_err(|()| RostlAdapterError::UpstreamPanic)
        }

        #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
        {
            let _ = capacity;
            Err(RostlAdapterError::UnsupportedPlatform)
        }
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    pub(super) fn insert(
        &mut self,
        key: usize,
        value: PersistentUtxoEvent,
    ) -> Result<(), RostlAdapterError> {
        self.validate_operation(key)?;
        let new_position = self.sample_new_position();
        let result = catch_upstream(|| {
            let old_position = self.position_map.access_position(key, new_position);
            self.oram
                .write_or_insert(old_position, new_position, key, value)
        });
        let found = self.finish_upstream(result)?;
        if found {
            self.failed_closed = true;
            return Err(RostlAdapterError::DuplicateKey);
        }
        Ok(())
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    pub(super) fn read(
        &mut self,
        key: usize,
    ) -> Result<Option<PersistentUtxoEvent>, RostlAdapterError> {
        self.validate_operation(key)?;
        let new_position = self.sample_new_position();
        let mut value = PersistentUtxoEvent::zeroed();
        let result = catch_upstream(|| {
            let old_position = self.position_map.access_position(key, new_position);
            self.oram.read(old_position, new_position, key, &mut value)
        });
        let found = self.finish_upstream(result)?;
        if !found {
            return Ok(None);
        }
        if let Err(error) = value.into_business() {
            self.failed_closed = true;
            return Err(RostlAdapterError::InvalidRecord(error));
        }
        Ok(Some(value))
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    fn validate_operation(&self, key: usize) -> Result<(), RostlAdapterError> {
        if self.failed_closed {
            return Err(RostlAdapterError::FailedClosed);
        }
        if key >= self.capacity {
            return Err(RostlAdapterError::KeyOutsideCapacity {
                capacity: self.capacity,
            });
        }
        Ok(())
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    fn sample_new_position(&self) -> PositionType {
        // CircuitORAM requires every remap position to be sampled uniformly.
        // This mirrors the pinned upstream experiment. A future TDX design must
        // separately bind and review its in-workload entropy source.
        rand::rng().random_range(0..self.capacity as PositionType)
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    fn finish_upstream<T>(&mut self, result: Result<T, ()>) -> Result<T, RostlAdapterError> {
        match result {
            Ok(value) => Ok(value),
            Err(()) => {
                self.failed_closed = true;
                Err(RostlAdapterError::UpstreamPanic)
            }
        }
    }
}

impl fmt::Debug for RostlCandidateStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RostlCandidateStore { ..REDACTED.. }")
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn catch_upstream<T>(operation: impl FnOnce() -> T) -> Result<T, ()> {
    catch_unwind(AssertUnwindSafe(operation)).map_err(|_| ())
}

/// Fail-closed outcome from the volatile upstream experiment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RostlAdapterError {
    #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
    UnsupportedPlatform,
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    InvalidCapacity { capacity: usize },
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    KeyOutsideCapacity { capacity: usize },
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    DuplicateKey,
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    InvalidRecord(PersistentUtxoEventError),
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    UpstreamPanic,
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    FailedClosed,
}

impl fmt::Display for RostlAdapterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
            Self::UnsupportedPlatform => f.write_str(
                "rostl experiment is unavailable: privacy qualification requires Linux x86_64",
            ),
            #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
            Self::InvalidCapacity { capacity } => write!(
                f,
                "rostl experiment capacity {capacity} is outside 2..=u32::MAX"
            ),
            #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
            Self::KeyOutsideCapacity { capacity } => {
                write!(f, "rostl experiment key is outside capacity {capacity}")
            }
            #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
            Self::DuplicateKey => {
                f.write_str("rostl append-only experiment rejected a duplicate key")
            }
            #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
            Self::InvalidRecord(error) => {
                write!(
                    f,
                    "rostl experiment returned an invalid fixed record: {error}"
                )
            }
            #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
            Self::UpstreamPanic => {
                f.write_str("rostl experiment panicked; candidate state must be discarded")
            }
            #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
            Self::FailedClosed => f.write_str("rostl experiment is failed closed"),
        }
    }
}

impl std::error::Error for RostlAdapterError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
            Self::InvalidRecord(error) => Some(error),
            #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
            Self::UnsupportedPlatform => None,
            #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
            Self::InvalidCapacity { .. } => None,
            #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
            Self::KeyOutsideCapacity { .. } => None,
            #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
            Self::DuplicateKey => None,
            #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
            Self::UpstreamPanic => None,
            #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
            Self::FailedClosed => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    use crate::records::{UtxoEvent, UtxoScriptClass, TXID_BYTES};

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    fn fixed_event() -> PersistentUtxoEvent {
        PersistentUtxoEvent::from_business(&UtxoEvent::created(
            [0x51; TXID_BYTES],
            2,
            30_000,
            100,
            UtxoScriptClass::PayToScriptHash,
            [0x61; 20],
        ))
    }

    #[test]
    fn candidate_satisfies_pod_and_cmov_constraints() {
        fn assert_constraints<T: bytemuck::Pod + rostl_primitives::traits::Cmov>() {}

        assert_constraints::<PersistentUtxoEvent>();
    }

    #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
    #[test]
    fn unsupported_targets_fail_before_constructing_upstream_state() {
        assert!(matches!(
            RostlCandidateStore::new(8),
            Err(RostlAdapterError::UnsupportedPlatform)
        ));
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn linux_x86_64_candidate_round_trips_and_rejects_duplicates() -> Result<(), RostlAdapterError>
    {
        fn assert_send<T: Send>() {}

        assert_send::<RostlCandidateStore>();
        let mut store = RostlCandidateStore::new(8)?;
        let event = fixed_event();

        store.insert(3, event)?;
        assert_eq!(store.read(3)?, Some(event));
        assert_eq!(store.insert(3, event), Err(RostlAdapterError::DuplicateKey));
        assert_eq!(store.read(3), Err(RostlAdapterError::FailedClosed));
        Ok(())
    }
}
