use std::{fmt, marker::PhantomData};

use blake2::{Blake2s256, Digest};

use crate::{envelope::FixedEnvelope, trace::QueryAccessBudget};

pub(super) const PROFILE_ID_BYTES: usize = 16;
const PROFILE_ID_DOMAIN: &[u8] = b"zaino-oram/privacy-profile/v1";
const UNARY_FIXED_ENVELOPE_TAG: u8 = 1;

/// A compiled privacy budget for one fixed query class.
///
/// No production profile is provided yet. The fixed identifier is derived from
/// every authoritative budget dimension; the label remains diagnostic only.
/// Attestation must bind this complete structure and its exact compiled page
/// and envelope shapes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct PrivacyProfile {
    profile_id: [u8; PROFILE_ID_BYTES],
    label: &'static str,
    access_budget: QueryAccessBudget,
    response_slots: usize,
    cover_rounds: usize,
}

impl PrivacyProfile {
    /// Validates and builds a compiled privacy profile.
    pub(super) fn new(
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
        let access_budget =
            QueryAccessBudget::read_only_unary_fixed_envelope(store_reads, envelope_bytes);
        let profile_id = derive_profile_id(&access_budget, response_slots, cover_rounds)?;
        Ok(Self {
            profile_id,
            label,
            access_budget,
            response_slots,
            cover_rounds,
        })
    }

    /// Returns the fixed identifier bound into protected request state.
    pub(super) const fn profile_id(&self) -> &[u8; PROFILE_ID_BYTES] {
        &self.profile_id
    }

    /// Returns the human-readable, non-authoritative profile label.
    const fn label(&self) -> &'static str {
        self.label
    }

    /// Returns the logical store calls performed by every query.
    pub(super) const fn store_reads(&self) -> usize {
        self.access_budget.store_reads()
    }

    /// Returns the complete modeled logical-access budget.
    pub(super) const fn access_budget(&self) -> QueryAccessBudget {
        self.access_budget
    }

    /// Returns the exact number of fixed response slots.
    pub(super) const fn response_slots(&self) -> usize {
        self.response_slots
    }

    /// Returns the exact protected-envelope byte length.
    const fn envelope_bytes(&self) -> usize {
        self.access_budget.request_bytes()
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
        if self.envelope_bytes() != N {
            return Err(PrivacyProfileError::EnvelopeShapeMismatch {
                required: self.envelope_bytes(),
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
    /// A profile dimension cannot fit the canonical 64-bit identifier format.
    DimensionTooLarge,
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
            Self::DimensionTooLarge => {
                f.write_str("privacy profile dimension exceeds canonical identifier width")
            }
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

/// Derives the public profile identifier from the complete authoritative
/// logical budget. The diagnostic label is deliberately excluded.
fn derive_profile_id(
    access_budget: &QueryAccessBudget,
    response_slots: usize,
    cover_rounds: usize,
) -> Result<[u8; PROFILE_ID_BYTES], PrivacyProfileError> {
    let mut hasher = Blake2s256::new();
    Digest::update(&mut hasher, PROFILE_ID_DOMAIN);
    for dimension in [
        access_budget.store_reads(),
        access_budget.store_writes(),
        access_budget.allocations(),
        access_budget.source_calls(),
        access_budget.request_frames(),
        access_budget.response_frames(),
        access_budget.request_bytes(),
        access_budget.response_bytes(),
        response_slots,
        cover_rounds,
    ] {
        update_profile_dimension(&mut hasher, dimension)?;
    }
    Digest::update(&mut hasher, [UNARY_FIXED_ENVELOPE_TAG]);
    let digest = Digest::finalize(hasher);
    let mut profile_id = [0; PROFILE_ID_BYTES];
    profile_id.copy_from_slice(&digest[..PROFILE_ID_BYTES]);
    Ok(profile_id)
}

fn update_profile_dimension(
    hasher: &mut Blake2s256,
    dimension: usize,
) -> Result<(), PrivacyProfileError> {
    let dimension = u64::try_from(dimension).map_err(|_| PrivacyProfileError::DimensionTooLarge)?;
    Digest::update(hasher, dimension.to_be_bytes());
    Ok(())
}

/// Returns whether every byte equals the canonical zero sentinel.
pub(super) const fn all_zero<const N: usize>(bytes: &[u8; N]) -> bool {
    let mut index = 0;
    while index < N {
        if bytes[index] != 0 {
            return false;
        }
        index += 1;
    }
    true
}

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
    use crate::trace::CompletionShape;

    fn profile() -> PrivacyProfile {
        PrivacyProfile::new("test-v1", 4, 2, 128, 3)
            .expect("test profile has nonzero authoritative dimensions")
    }

    #[test]
    fn profile_exposes_complete_compiled_budget() {
        let profile = profile();
        assert_eq!(profile.label(), "test-v1");
        assert_eq!(profile.store_reads(), 4);
        assert_eq!(profile.access_budget().store_writes(), 0);
        assert_eq!(profile.access_budget().allocations(), 0);
        assert_eq!(profile.access_budget().source_calls(), 0);
        assert_eq!(profile.access_budget().request_frames(), 1);
        assert_eq!(profile.access_budget().response_frames(), 1);
        assert_eq!(profile.access_budget().request_bytes(), 128);
        assert_eq!(profile.access_budget().response_bytes(), 128);
        assert_eq!(
            profile.access_budget().completion(),
            CompletionShape::UnaryFixedEnvelope
        );
        assert_eq!(profile.response_slots(), 2);
        assert_eq!(profile.envelope_bytes(), 128);
        assert_eq!(profile.cover_rounds(), 3);
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
    fn profile_identifier_binds_every_authoritative_dimension_but_not_label() {
        let baseline = profile();
        assert_eq!(
            baseline.profile_id(),
            &[96, 146, 31, 125, 196, 142, 21, 149, 166, 20, 67, 106, 34, 169, 176, 109,]
        );
        let relabeled = PrivacyProfile::new("renamed", 4, 2, 128, 3)
            .expect("relabeled test profile remains valid");
        assert_eq!(baseline.profile_id(), relabeled.profile_id());

        for changed in [
            PrivacyProfile::new("test-v1", 5, 2, 128, 3),
            PrivacyProfile::new("test-v1", 4, 3, 128, 3),
            PrivacyProfile::new("test-v1", 4, 2, 129, 3),
            PrivacyProfile::new("test-v1", 4, 2, 128, 4),
        ] {
            let changed = changed.expect("changed authoritative dimension remains nonzero");
            assert_ne!(baseline.profile_id(), changed.profile_id());
        }
    }

    #[test]
    fn compiled_shape_rejects_every_mismatch() {
        assert!(matches!(
            CompiledQueryShape::<1, 128>::new(profile()),
            Err(PrivacyProfileError::ResponseShapeMismatch {
                required: 2,
                available: 1,
            })
        ));
        assert!(matches!(
            CompiledQueryShape::<3, 128>::new(profile()),
            Err(PrivacyProfileError::ResponseShapeMismatch {
                required: 2,
                available: 3,
            })
        ));
        assert!(matches!(
            CompiledQueryShape::<2, 127>::new(profile()),
            Err(PrivacyProfileError::EnvelopeShapeMismatch {
                required: 128,
                available: 127,
            })
        ));
    }

    #[test]
    fn compiled_shape_couples_page_envelope_and_cover_profile() {
        let shape = CompiledQueryShape::<2, 128>::new(profile())
            .expect("test profile exactly matches its compiled shapes");
        assert_eq!(shape.profile().cover_rounds(), 3);
        assert_eq!(shape.empty_envelope().as_bytes().len(), 128);
    }
}
