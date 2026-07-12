use std::{fmt, marker::PhantomData};

use crate::envelope::FixedEnvelope;

/// A compiled privacy budget for one fixed query class.
///
/// No production profile is provided yet. The label is diagnostic only:
/// attestation must bind this complete structure and its exact compiled page
/// and envelope shapes, so a reused label cannot silently weaken the budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct PrivacyProfile {
    label: &'static str,
    store_reads: usize,
    response_slots: usize,
    envelope_bytes: usize,
    cover_rounds: usize,
}

impl PrivacyProfile {
    /// Validates and builds a compiled privacy profile.
    pub(super) const fn new(
        label: &'static str,
        store_reads: usize,
        response_slots: usize,
        envelope_bytes: usize,
        cover_rounds: usize,
    ) -> Result<Self, PrivacyProfileError> {
        if label.is_empty() {
            return Err(PrivacyProfileError::EmptyLabel);
        }
        if store_reads == 0 {
            return Err(PrivacyProfileError::ZeroStoreReads);
        }
        if response_slots == 0 {
            return Err(PrivacyProfileError::ZeroResponseSlots);
        }
        if envelope_bytes == 0 {
            return Err(PrivacyProfileError::ZeroEnvelopeBytes);
        }
        if cover_rounds == 0 {
            return Err(PrivacyProfileError::ZeroCoverRounds);
        }
        Ok(Self {
            label,
            store_reads,
            response_slots,
            envelope_bytes,
            cover_rounds,
        })
    }

    /// Returns the human-readable, non-authoritative profile label.
    const fn label(&self) -> &'static str {
        self.label
    }

    /// Returns the logical store calls performed by every query.
    pub(super) const fn store_reads(&self) -> usize {
        self.store_reads
    }

    /// Returns the exact number of fixed response slots.
    pub(super) const fn response_slots(&self) -> usize {
        self.response_slots
    }

    /// Returns the exact protected-envelope byte length.
    const fn envelope_bytes(&self) -> usize {
        self.envelope_bytes
    }

    /// Returns the required query/cover round count.
    const fn cover_rounds(&self) -> usize {
        self.cover_rounds
    }

    const fn validate_response_slots<const N: usize>(&self) -> Result<(), PrivacyProfileError> {
        if self.response_slots != N {
            return Err(PrivacyProfileError::ResponseShapeMismatch {
                required: self.response_slots,
                available: N,
            });
        }
        Ok(())
    }

    const fn validate_envelope_bytes<const N: usize>(&self) -> Result<(), PrivacyProfileError> {
        if self.envelope_bytes != N {
            return Err(PrivacyProfileError::EnvelopeShapeMismatch {
                required: self.envelope_bytes,
                available: N,
            });
        }
        Ok(())
    }
}

/// A compiled privacy profile is internally inconsistent with its fixed shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PrivacyProfileError {
    /// Profile labels must be nonempty.
    EmptyLabel,
    /// Every query must perform at least one store read.
    ZeroStoreReads,
    /// Every response must reserve at least one result slot.
    ZeroResponseSlots,
    /// Every protected envelope must contain at least one byte.
    ZeroEnvelopeBytes,
    /// Every profile must declare at least one query/cover round.
    ZeroCoverRounds,
    /// The page's compile-time slot count differs from the profile.
    ResponseShapeMismatch {
        /// Slots required by the profile.
        required: usize,
        /// Slots available in the compiled page.
        available: usize,
    },
    /// The envelope's compile-time length differs from the profile.
    EnvelopeShapeMismatch {
        /// Bytes required by the profile.
        required: usize,
        /// Bytes available in the compiled envelope.
        available: usize,
    },
    /// The store's complete per-key slot domain differs from the read budget.
    StoreShapeMismatch {
        /// Slots the profile promises to read.
        required: usize,
        /// Slots exposed by the store.
        available: usize,
    },
}

impl fmt::Display for PrivacyProfileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyLabel => write!(f, "privacy profile label is empty"),
            Self::ZeroStoreReads => write!(f, "privacy profile has zero store reads"),
            Self::ZeroResponseSlots => write!(f, "privacy profile has zero response slots"),
            Self::ZeroEnvelopeBytes => write!(f, "privacy profile has zero envelope bytes"),
            Self::ZeroCoverRounds => write!(f, "privacy profile has zero cover rounds"),
            Self::ResponseShapeMismatch {
                required,
                available,
            } => write!(
                f,
                "privacy profile requires exactly {required} result slots; compiled page has {available}"
            ),
            Self::EnvelopeShapeMismatch {
                required,
                available,
            } => write!(
                f,
                "privacy profile requires {required} envelope bytes; compiled envelope has {available}"
            ),
            Self::StoreShapeMismatch {
                required,
                available,
            } => write!(
                f,
                "privacy profile requires a complete {required}-slot store domain; store has {available}"
            ),
        }
    }
}

impl std::error::Error for PrivacyProfileError {}

/// A profile sealed to exact compile-time page and envelope shapes.
pub(super) struct CompiledQueryShape<const RESPONSE_SLOTS: usize, const ENVELOPE_BYTES: usize> {
    profile: PrivacyProfile,
    envelope_shape: PhantomData<FixedEnvelope<ENVELOPE_BYTES>>,
}

impl<const RESPONSE_SLOTS: usize, const ENVELOPE_BYTES: usize>
    CompiledQueryShape<RESPONSE_SLOTS, ENVELOPE_BYTES>
{
    /// Validates and seals the profile to exact compile-time shapes.
    pub(super) const fn new(profile: PrivacyProfile) -> Result<Self, PrivacyProfileError> {
        match profile.validate_response_slots::<RESPONSE_SLOTS>() {
            Ok(()) => {}
            Err(error) => return Err(error),
        }
        match profile.validate_envelope_bytes::<ENVELOPE_BYTES>() {
            Ok(()) => Ok(Self {
                profile,
                envelope_shape: PhantomData,
            }),
            Err(error) => Err(error),
        }
    }

    pub(super) const fn profile(&self) -> &PrivacyProfile {
        &self.profile
    }

    const fn empty_envelope(&self) -> FixedEnvelope<ENVELOPE_BYTES> {
        FixedEnvelope::zeroed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROFILE: PrivacyProfile = PrivacyProfile {
        label: "test-v1",
        store_reads: 4,
        response_slots: 2,
        envelope_bytes: 128,
        cover_rounds: 3,
    };

    #[test]
    fn profile_exposes_complete_compiled_budget() {
        assert_eq!(PROFILE.label(), "test-v1");
        assert_eq!(PROFILE.store_reads(), 4);
        assert_eq!(PROFILE.response_slots(), 2);
        assert_eq!(PROFILE.envelope_bytes(), 128);
        assert_eq!(PROFILE.cover_rounds(), 3);
    }

    #[test]
    fn profile_rejects_zero_budgets() {
        assert_eq!(
            PrivacyProfile::new("test", 0, 1, 1, 1),
            Err(PrivacyProfileError::ZeroStoreReads)
        );
        assert_eq!(
            PrivacyProfile::new("test", 1, 0, 1, 1),
            Err(PrivacyProfileError::ZeroResponseSlots)
        );
        assert_eq!(
            PrivacyProfile::new("test", 1, 1, 0, 1),
            Err(PrivacyProfileError::ZeroEnvelopeBytes)
        );
        assert_eq!(
            PrivacyProfile::new("test", 1, 1, 1, 0),
            Err(PrivacyProfileError::ZeroCoverRounds)
        );
    }

    #[test]
    fn compiled_shape_rejects_every_mismatch() {
        assert!(matches!(
            CompiledQueryShape::<1, 128>::new(PROFILE),
            Err(PrivacyProfileError::ResponseShapeMismatch {
                required: 2,
                available: 1,
            })
        ));
        assert!(matches!(
            CompiledQueryShape::<3, 128>::new(PROFILE),
            Err(PrivacyProfileError::ResponseShapeMismatch {
                required: 2,
                available: 3,
            })
        ));
        assert!(matches!(
            CompiledQueryShape::<2, 127>::new(PROFILE),
            Err(PrivacyProfileError::EnvelopeShapeMismatch {
                required: 128,
                available: 127,
            })
        ));
    }

    #[test]
    fn compiled_shape_couples_page_envelope_and_cover_profile() {
        let shape = CompiledQueryShape::<2, 128>::new(PROFILE)
            .expect("test profile exactly matches its compiled shapes");
        assert_eq!(shape.profile().cover_rounds(), 3);
        assert_eq!(shape.empty_envelope().as_bytes().len(), 128);
    }
}
