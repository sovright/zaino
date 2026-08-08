use std::{fmt, marker::PhantomData, num::NonZeroU64};

use blake2::{Blake2s256, Digest};

use crate::{
    envelope::FixedEnvelope,
    trace::{QueryAccessBudget, RUNTIME_SCHEDULE_VERSION},
};

pub(super) const PROFILE_ID_BYTES: usize = 16;
const PROFILE_ID_DOMAIN: &[u8] = b"zaino-oram/privacy-profile/v6";
const UNARY_FIXED_ENVELOPE_TAG: u8 = 1;
const SINGLE_WORKER_FIFO_TAG: u8 = 1;
const REJECT_AT_CAPACITY_TAG: u8 = 1;
const REPLAY_TRANSACTION_CAPACITY_TRANSACTIONS_TAG: u8 = 1;
const REPLAY_EXPIRY_BUCKET_WIDTH_SECONDS_TAG: u8 = 2;
const REPLAY_GARBAGE_COLLECTION_INTERVAL_SECONDS_TAG: u8 = 3;
const SINGLE_WORKER_EXECUTION_LIMIT: usize = 1;

/// Fixed public scheduling and overload behavior for one private profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ConcurrencyPolicy {
    queue_limit: usize,
    max_in_flight: usize,
}

impl ConcurrencyPolicy {
    fn single_worker_fifo(queue_limit: usize) -> Result<Self, PrivacyProfileError> {
        if queue_limit == 0 {
            return Err(PrivacyProfileError::ZeroConcurrencyQueueLimit);
        }
        let max_in_flight = SINGLE_WORKER_EXECUTION_LIMIT
            .checked_add(queue_limit)
            .ok_or(PrivacyProfileError::DimensionTooLarge)?;
        Ok(Self {
            queue_limit,
            max_in_flight,
        })
    }

    const fn execution_limit(&self) -> usize {
        SINGLE_WORKER_EXECUTION_LIMIT
    }

    const fn queue_limit(&self) -> usize {
        self.queue_limit
    }

    const fn max_in_flight(&self) -> usize {
        self.max_in_flight
    }

    const fn scheduling_tag(&self) -> u8 {
        SINGLE_WORKER_FIFO_TAG
    }

    const fn overload_tag(&self) -> u8 {
        REJECT_AT_CAPACITY_TAG
    }
}

/// Fixed public replay bounds compiled into one privacy profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct CompiledReplayPolicy {
    transaction_capacity: NonZeroU64,
    expiry_bucket_width_seconds: NonZeroU64,
    garbage_collection_interval_seconds: NonZeroU64,
}

impl CompiledReplayPolicy {
    fn new(
        transaction_capacity: u64,
        expiry_bucket_width_seconds: u64,
        garbage_collection_interval_seconds: u64,
    ) -> Result<Self, PrivacyProfileError> {
        let transaction_capacity = NonZeroU64::new(transaction_capacity)
            .ok_or(PrivacyProfileError::ZeroReplayTransactionCapacity)?;
        let expiry_bucket_width_seconds = NonZeroU64::new(expiry_bucket_width_seconds)
            .ok_or(PrivacyProfileError::ZeroReplayExpiryBucketWidth)?;
        let garbage_collection_interval_seconds =
            NonZeroU64::new(garbage_collection_interval_seconds)
                .ok_or(PrivacyProfileError::ZeroReplayGarbageCollectionInterval)?;
        Ok(Self {
            transaction_capacity,
            expiry_bucket_width_seconds,
            garbage_collection_interval_seconds,
        })
    }

    /// Returns the maximum total committed replay transactions.
    pub(super) const fn transaction_capacity(&self) -> u64 {
        self.transaction_capacity.get()
    }

    /// Returns the public replay-expiry bucket width.
    pub(super) const fn expiry_bucket_width(&self) -> NonZeroU64 {
        self.expiry_bucket_width_seconds
    }

    /// Returns the public replay-expiry bucket width in seconds.
    pub(super) const fn expiry_bucket_width_seconds(&self) -> u64 {
        self.expiry_bucket_width().get()
    }

    /// Returns the fixed proactive garbage-collection interval.
    pub(super) const fn garbage_collection_interval_seconds(&self) -> u64 {
        self.garbage_collection_interval_seconds.get()
    }
}

/// Unvalidated authoritative inputs for one compiled profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PrivacyProfileDefinition {
    label: &'static str,
    store_reads: usize,
    padded_input_slots: usize,
    recent_snapshot_scan_slots: usize,
    response_slots: usize,
    envelope_bytes: usize,
    cover_rounds: usize,
    continuation_ttl_seconds: u64,
    timeout_bucket_millis: u64,
    concurrency_queue_limit: usize,
    replay_transaction_capacity: u64,
    replay_expiry_bucket_width_seconds: u64,
    replay_garbage_collection_interval_seconds: u64,
}

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
    padded_input_slots: usize,
    response_slots: usize,
    cover_rounds: usize,
    continuation_ttl_seconds: u64,
    timeout_bucket_millis: u64,
    concurrency_policy: ConcurrencyPolicy,
    replay_policy: CompiledReplayPolicy,
}

impl PrivacyProfile {
    /// Validates and builds a compiled privacy profile.
    fn new(definition: PrivacyProfileDefinition) -> Result<Self, PrivacyProfileError> {
        if definition.label.is_empty() {
            return Err(PrivacyProfileError::EmptyLabel);
        }
        if definition.store_reads == 0 {
            return Err(PrivacyProfileError::ZeroStoreReads);
        }
        if definition.padded_input_slots == 0 {
            return Err(PrivacyProfileError::ZeroPaddedInputSlots);
        }
        if definition.response_slots == 0 {
            return Err(PrivacyProfileError::ZeroResponseSlots);
        }
        if definition.envelope_bytes == 0 {
            return Err(PrivacyProfileError::ZeroEnvelopeBytes);
        }
        if definition.cover_rounds == 0 {
            return Err(PrivacyProfileError::ZeroCoverRounds);
        }
        if definition.continuation_ttl_seconds == 0 {
            return Err(PrivacyProfileError::ZeroContinuationTtl);
        }
        if definition.timeout_bucket_millis == 0 {
            return Err(PrivacyProfileError::ZeroTimeoutBucket);
        }
        let replay_policy = CompiledReplayPolicy::new(
            definition.replay_transaction_capacity,
            definition.replay_expiry_bucket_width_seconds,
            definition.replay_garbage_collection_interval_seconds,
        )?;
        let concurrency_policy =
            ConcurrencyPolicy::single_worker_fifo(definition.concurrency_queue_limit)?;
        let access_budget = QueryAccessBudget::read_only_unary_fixed_envelope(
            definition.store_reads,
            definition.recent_snapshot_scan_slots,
            definition.envelope_bytes,
        );
        definition
            .store_reads
            .checked_add(definition.recent_snapshot_scan_slots)
            .ok_or(PrivacyProfileError::DimensionTooLarge)?;
        let mut profile = Self {
            profile_id: [0; PROFILE_ID_BYTES],
            label: definition.label,
            access_budget,
            padded_input_slots: definition.padded_input_slots,
            response_slots: definition.response_slots,
            cover_rounds: definition.cover_rounds,
            continuation_ttl_seconds: definition.continuation_ttl_seconds,
            timeout_bucket_millis: definition.timeout_bucket_millis,
            concurrency_policy,
            replay_policy,
        };
        profile.profile_id = derive_profile_id(&profile)?;
        Ok(profile)
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

    /// Returns the combined finalized-store then recent-snapshot cursor domain.
    pub(super) fn combined_scan_slots(&self) -> Result<usize, PrivacyProfileError> {
        self.store_reads()
            .checked_add(self.access_budget.recent_snapshot_reads())
            .ok_or(PrivacyProfileError::DimensionTooLarge)
    }

    /// Returns the exact padded request-input count.
    const fn padded_input_slots(&self) -> usize {
        self.padded_input_slots
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

    /// Returns the fixed absolute-lifetime budget for continuation tokens.
    pub(super) const fn continuation_ttl_seconds(&self) -> u64 {
        self.continuation_ttl_seconds
    }

    /// Returns the fixed public request timeout bucket.
    const fn timeout_bucket_millis(&self) -> u64 {
        self.timeout_bucket_millis
    }

    /// Returns the fixed public scheduling and overload policy.
    const fn concurrency_policy(&self) -> ConcurrencyPolicy {
        self.concurrency_policy
    }

    /// Returns the fixed public replay bounds compiled into this profile.
    pub(super) const fn replay_policy(&self) -> CompiledReplayPolicy {
        self.replay_policy
    }

    /// Recompiles this fixture with explicit test-only replay bounds.
    #[cfg(test)]
    pub(super) fn with_test_replay_policy(
        mut self,
        transaction_capacity: u64,
        expiry_bucket_width_seconds: u64,
        garbage_collection_interval_seconds: u64,
    ) -> Result<Self, PrivacyProfileError> {
        let replay_policy = CompiledReplayPolicy::new(
            transaction_capacity,
            expiry_bucket_width_seconds,
            garbage_collection_interval_seconds,
        )?;
        self.replay_policy = replay_policy;
        self.profile_id = derive_profile_id(&self)?;
        Ok(self)
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

    /// Validates the compiled recent-snapshot source width against the profile.
    pub(super) const fn validate_recent_snapshot_slots<const N: usize>(
        &self,
    ) -> Result<(), PrivacyProfileError> {
        let required = self.access_budget.recent_snapshot_reads();
        if required != N {
            return Err(PrivacyProfileError::RecentSnapshotShapeMismatch {
                required,
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
    /// Every request must reserve at least one padded input slot.
    ZeroPaddedInputSlots,
    /// Every response must reserve at least one result slot.
    ZeroResponseSlots,
    /// Every protected envelope must contain at least one byte.
    ZeroEnvelopeBytes,
    /// Every profile must declare at least one query/cover round.
    ZeroCoverRounds,
    /// Every profile must fix a nonzero continuation lifetime bucket.
    ZeroContinuationTtl,
    /// Every profile must publish a nonzero timeout bucket.
    ZeroTimeoutBucket,
    /// The replay journal must permit at least one committed transaction.
    ZeroReplayTransactionCapacity,
    /// Replay expiry buckets must have a nonzero public width.
    ZeroReplayExpiryBucketWidth,
    /// Proactive replay garbage collection must have a nonzero interval.
    ZeroReplayGarbageCollectionInterval,
    /// The single-worker FIFO policy must reserve at least one queue slot.
    ZeroConcurrencyQueueLimit,
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
    /// The compiled recent-snapshot domain differs from the profile budget.
    RecentSnapshotShapeMismatch {
        /// Slots the profile promises to scan.
        required: usize,
        /// Slots exposed by the compiled source.
        available: usize,
    },
}

impl fmt::Display for PrivacyProfileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyLabel => write!(f, "privacy profile label is empty"),
            Self::ZeroStoreReads => write!(f, "privacy profile has zero store reads"),
            Self::ZeroPaddedInputSlots => {
                f.write_str("privacy profile has zero padded input slots")
            }
            Self::ZeroResponseSlots => write!(f, "privacy profile has zero response slots"),
            Self::ZeroEnvelopeBytes => write!(f, "privacy profile has zero envelope bytes"),
            Self::ZeroCoverRounds => write!(f, "privacy profile has zero cover rounds"),
            Self::ZeroContinuationTtl => {
                f.write_str("privacy profile has zero continuation lifetime")
            }
            Self::ZeroTimeoutBucket => f.write_str("privacy profile has zero timeout bucket"),
            Self::ZeroReplayTransactionCapacity => {
                f.write_str("privacy profile has zero replay transaction capacity")
            }
            Self::ZeroReplayExpiryBucketWidth => {
                f.write_str("privacy profile has zero replay expiry-bucket width")
            }
            Self::ZeroReplayGarbageCollectionInterval => {
                f.write_str("privacy profile has zero replay garbage-collection interval")
            }
            Self::ZeroConcurrencyQueueLimit => {
                f.write_str("privacy profile has zero concurrency queue capacity")
            }
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
            Self::RecentSnapshotShapeMismatch {
                required,
                available,
            } => write!(
                f,
                "privacy profile requires a complete {required}-slot recent snapshot; source has {available}"
            ),
        }
    }
}

impl std::error::Error for PrivacyProfileError {}

/// Derives the public profile identifier from the complete authoritative
/// logical budget. The diagnostic label is deliberately excluded.
fn derive_profile_id(
    profile: &PrivacyProfile,
) -> Result<[u8; PROFILE_ID_BYTES], PrivacyProfileError> {
    let mut hasher = Blake2s256::new();
    Digest::update(&mut hasher, PROFILE_ID_DOMAIN);
    for dimension in [
        profile.access_budget.store_reads(),
        profile.access_budget.store_writes(),
        profile.access_budget.allocations(),
        profile.access_budget.source_calls(),
        profile.access_budget.recent_snapshot_reads(),
        profile.access_budget.replay_reads(),
        profile.access_budget.replay_writes(),
        profile.access_budget.request_frames(),
        profile.access_budget.response_frames(),
        profile.access_budget.request_bytes(),
        profile.access_budget.response_bytes(),
        profile.access_budget.runtime_phases(),
        profile.padded_input_slots,
        profile.response_slots,
        profile.cover_rounds,
        profile.concurrency_policy.execution_limit(),
        profile.concurrency_policy.queue_limit(),
        profile.concurrency_policy.max_in_flight(),
    ] {
        update_profile_dimension(&mut hasher, dimension)?;
    }
    Digest::update(&mut hasher, RUNTIME_SCHEDULE_VERSION.to_be_bytes());
    Digest::update(&mut hasher, profile.continuation_ttl_seconds.to_be_bytes());
    Digest::update(&mut hasher, profile.timeout_bucket_millis.to_be_bytes());
    Digest::update(&mut hasher, [UNARY_FIXED_ENVELOPE_TAG]);
    Digest::update(&mut hasher, [profile.concurrency_policy.scheduling_tag()]);
    Digest::update(&mut hasher, [profile.concurrency_policy.overload_tag()]);
    update_profile_u64_dimension(
        &mut hasher,
        REPLAY_TRANSACTION_CAPACITY_TRANSACTIONS_TAG,
        profile.replay_policy.transaction_capacity(),
    );
    update_profile_u64_dimension(
        &mut hasher,
        REPLAY_EXPIRY_BUCKET_WIDTH_SECONDS_TAG,
        profile.replay_policy.expiry_bucket_width_seconds(),
    );
    update_profile_u64_dimension(
        &mut hasher,
        REPLAY_GARBAGE_COLLECTION_INTERVAL_SECONDS_TAG,
        profile.replay_policy.garbage_collection_interval_seconds(),
    );
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

fn update_profile_u64_dimension(hasher: &mut Blake2s256, semantic_unit_tag: u8, dimension: u64) {
    Digest::update(hasher, [semantic_unit_tag]);
    Digest::update(hasher, dimension.to_be_bytes());
}

/// Fixed per-request scan depth and response width for the mainnet profile.
///
/// One number governs both: scanning deeper than the envelope can return is
/// wasted work, and returning more than was scanned is impossible. Its value is
/// derived from the Gate 1 Mainnet capture at height 3,425,046
/// (`docs/evidence/oram/gate1/hybrid-mainnet-2316644-h3425046-v1/`), whose
/// live-UTXO histogram covers all 9,193,009 distinct standard addresses:
///
/// - 90.81% hold no live UTXO at all and complete in one round trip trivially.
/// - Among the 844,678 that hold any, the median is 1 and the 90th percentile
///   is 36. At 256 slots, 98.85% of them complete in one round trip, as do
///   99.89% of all addresses.
/// - The maximum is 262,983, held by one address whose profile is an exchange
///   rather than a user. Sizing the fixed work to it would charge every request
///   roughly 16 times this scan for a population 7,000 times smaller than the
///   90th percentile, so it is deliberately left to paginate.
///
/// Cost follows from the same capture's insertion-equivalent curve in
/// `cost_model`: roughly 55 ms of scan work per request against the finalized
/// table, and the same again against the recent-snapshot window. Those figures
/// are extrapolated beyond the measured 2^10..2^14 range and time a complete
/// insertion rather than a single read, so they screen a design point rather
/// than establish an SLO.
pub(super) const MAINNET_QUERY_SLOTS: usize = 256;

/// Probe counts fixed by the compiled layout, mirrored from `cost_model`.
const MAINNET_DIRECTORY_PROBES: usize = 4;
const MAINNET_EVENT_PROBES: usize = 4;

/// Logical store calls per query: one directory probe set plus one probe set
/// per scanned slot.
const MAINNET_STORE_READS: usize =
    MAINNET_DIRECTORY_PROBES + MAINNET_EVENT_PROBES * MAINNET_QUERY_SLOTS;

/// Fixed protected envelope width.
///
/// The response body needs 21,742 bytes at 256 slots (`RESULT_SLOT_BYTES` is
/// 84, plus the header, outcome, flags, continuation token, and session
/// binding) and the envelope adds 40 bytes of nonce and authentication. The
/// remainder is zero padding the codec already requires, kept as headroom for
/// layout growth that would otherwise force a profile identifier change.
pub(super) const MAINNET_ENVELOPE_BYTES: usize = 24_576;

/// Total committed replay transactions before the journal must be rotated.
///
/// The journal is append-only and reclaims nothing, so this is an operational
/// deadline rather than a steady-state limit: roughly two years at one request
/// per second.
const MAINNET_REPLAY_TRANSACTION_CAPACITY: u64 = 1 << 26;

/// The compiled mainnet transparent UTXO-history profile.
///
/// Every dimension below is authoritative: each one is hashed into the profile
/// identifier that the security lease, replay namespace, and every envelope's
/// associated data bind to. Changing any of them is a new profile, not a
/// reconfiguration of this one.
pub(super) fn mainnet_utxo_history_profile() -> Result<PrivacyProfile, PrivacyProfileError> {
    PrivacyProfile::new(PrivacyProfileDefinition {
        label: "zaino.private.mainnet.utxo-history.v1",
        store_reads: MAINNET_STORE_READS,
        padded_input_slots: 1,
        // UNMEASURED. Set to match the finalized width by symmetry, not from
        // evidence. The Gate 1 capture records only `max_per_address_delta_events`
        // per rebuild interval (153,037 at 288 blocks), which is the same outlier
        // address the finalized width deliberately ignores, and no per-address
        // delta histogram exists: `GenerationSummary` collapses to maxima before
        // the report is written. Grounding this needs that histogram threaded
        // through generation accumulation and a rescan. Until then this is the
        // one dimension of the identifier below not backed by a measurement.
        recent_snapshot_scan_slots: MAINNET_QUERY_SLOTS,
        response_slots: MAINNET_QUERY_SLOTS,
        envelope_bytes: MAINNET_ENVELOPE_BYTES,
        // One real round and one cover round.
        cover_rounds: 2,
        // The largest address paginates over roughly a thousand requests; an
        // hour keeps that walk inside a single continuation lifetime.
        continuation_ttl_seconds: 3_600,
        // Above the roughly 110 ms of worst-case scan work, so the observable
        // bucket does not vary with the work actually performed.
        timeout_bucket_millis: 250,
        concurrency_queue_limit: 64,
        replay_transaction_capacity: MAINNET_REPLAY_TRANSACTION_CAPACITY,
        replay_expiry_bucket_width_seconds: 600,
        replay_garbage_collection_interval_seconds: 600,
    })
}

#[cfg(test)]
const TEST_REPLAY_TRANSACTION_CAPACITY: u64 = 32;
#[cfg(test)]
const TEST_REPLAY_EXPIRY_BUCKET_WIDTH_SECONDS: u64 = 60;
#[cfg(test)]
const TEST_REPLAY_GARBAGE_COLLECTION_INTERVAL_SECONDS: u64 = 300;

/// Builds an explicitly listener-free test profile with no recent-snapshot
/// integration. The zero scan budget is bound into the identifier and must not
/// be reused for a production profile. A later slice replaces it with a fixed
/// nonzero ordinal scan backed by an injected snapshot fixture.
#[cfg(test)]
pub(super) fn test_profile_without_recent_snapshot(
    label: &'static str,
    store_reads: usize,
    response_slots: usize,
    envelope_bytes: usize,
    cover_rounds: usize,
    continuation_ttl_seconds: u64,
) -> Result<PrivacyProfile, PrivacyProfileError> {
    test_profile(
        label,
        store_reads,
        0,
        response_slots,
        envelope_bytes,
        cover_rounds,
        continuation_ttl_seconds,
    )
}

/// Builds an explicitly listener-free test profile with a fixed
/// recent-snapshot scan budget supplied by the caller.
#[cfg(test)]
pub(super) fn test_profile_with_recent_snapshot(
    label: &'static str,
    store_reads: usize,
    recent_snapshot_scan_slots: usize,
    response_slots: usize,
    envelope_bytes: usize,
    cover_rounds: usize,
    continuation_ttl_seconds: u64,
) -> Result<PrivacyProfile, PrivacyProfileError> {
    test_profile(
        label,
        store_reads,
        recent_snapshot_scan_slots,
        response_slots,
        envelope_bytes,
        cover_rounds,
        continuation_ttl_seconds,
    )
}

#[cfg(test)]
fn test_profile(
    label: &'static str,
    store_reads: usize,
    recent_snapshot_scan_slots: usize,
    response_slots: usize,
    envelope_bytes: usize,
    cover_rounds: usize,
    continuation_ttl_seconds: u64,
) -> Result<PrivacyProfile, PrivacyProfileError> {
    PrivacyProfile::new(PrivacyProfileDefinition {
        label,
        store_reads,
        padded_input_slots: 1,
        recent_snapshot_scan_slots,
        response_slots,
        envelope_bytes,
        cover_rounds,
        continuation_ttl_seconds,
        timeout_bucket_millis: 1_000,
        concurrency_queue_limit: 1,
        replay_transaction_capacity: TEST_REPLAY_TRANSACTION_CAPACITY,
        replay_expiry_bucket_width_seconds: TEST_REPLAY_EXPIRY_BUCKET_WIDTH_SECONDS,
        replay_garbage_collection_interval_seconds: TEST_REPLAY_GARBAGE_COLLECTION_INTERVAL_SECONDS,
    })
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
#[derive(Clone, Copy)]
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

    fn definition() -> PrivacyProfileDefinition {
        PrivacyProfileDefinition {
            label: "test-v1",
            store_reads: 4,
            padded_input_slots: 2,
            recent_snapshot_scan_slots: 0,
            response_slots: 2,
            envelope_bytes: 128,
            cover_rounds: 3,
            continuation_ttl_seconds: 60,
            timeout_bucket_millis: 1_000,
            concurrency_queue_limit: 2,
            replay_transaction_capacity: TEST_REPLAY_TRANSACTION_CAPACITY,
            replay_expiry_bucket_width_seconds: TEST_REPLAY_EXPIRY_BUCKET_WIDTH_SECONDS,
            replay_garbage_collection_interval_seconds:
                TEST_REPLAY_GARBAGE_COLLECTION_INTERVAL_SECONDS,
        }
    }

    fn profile() -> PrivacyProfile {
        PrivacyProfile::new(definition())
            .expect("test profile has nonzero authoritative dimensions")
    }

    fn assert_definition_changes_id(baseline: &PrivacyProfile, changed: PrivacyProfileDefinition) {
        let changed =
            PrivacyProfile::new(changed).expect("changed authoritative dimension remains valid");
        assert_ne!(baseline.profile_id(), changed.profile_id());
    }

    #[test]
    fn profile_exposes_complete_compiled_budget() {
        let profile = profile();
        assert_eq!(profile.label(), "test-v1");
        assert_eq!(profile.store_reads(), 4);
        assert_eq!(profile.combined_scan_slots(), Ok(4));
        assert_eq!(profile.access_budget().store_writes(), 0);
        assert_eq!(profile.access_budget().allocations(), 0);
        assert_eq!(profile.access_budget().source_calls(), 0);
        assert_eq!(profile.access_budget().recent_snapshot_reads(), 0);
        assert_eq!(profile.access_budget().replay_reads(), 1);
        assert_eq!(profile.access_budget().replay_writes(), 1);
        assert_eq!(profile.access_budget().request_frames(), 1);
        assert_eq!(profile.access_budget().response_frames(), 1);
        assert_eq!(profile.access_budget().request_bytes(), 128);
        assert_eq!(profile.access_budget().response_bytes(), 128);
        assert_eq!(
            profile.access_budget().completion(),
            CompletionShape::UnaryFixedEnvelope
        );
        assert_eq!(profile.padded_input_slots(), 2);
        assert_eq!(profile.response_slots(), 2);
        assert_eq!(profile.envelope_bytes(), 128);
        assert_eq!(profile.cover_rounds(), 3);
        assert_eq!(profile.continuation_ttl_seconds(), 60);
        assert_eq!(profile.timeout_bucket_millis(), 1_000);
        let concurrency = profile.concurrency_policy();
        assert_eq!(concurrency.execution_limit(), 1);
        assert_eq!(concurrency.queue_limit(), 2);
        assert_eq!(concurrency.max_in_flight(), 3);
        assert_eq!(concurrency.scheduling_tag(), SINGLE_WORKER_FIFO_TAG);
        assert_eq!(concurrency.overload_tag(), REJECT_AT_CAPACITY_TAG);
        let replay = profile.replay_policy();
        assert_eq!(
            replay.transaction_capacity(),
            TEST_REPLAY_TRANSACTION_CAPACITY
        );
        assert_eq!(
            replay.expiry_bucket_width_seconds(),
            TEST_REPLAY_EXPIRY_BUCKET_WIDTH_SECONDS
        );
        assert_eq!(
            replay.expiry_bucket_width().get(),
            TEST_REPLAY_EXPIRY_BUCKET_WIDTH_SECONDS
        );
        assert_eq!(
            replay.garbage_collection_interval_seconds(),
            TEST_REPLAY_GARBAGE_COLLECTION_INTERVAL_SECONDS
        );
    }

    #[test]
    fn profile_rejects_zero_required_budgets() {
        let mut changed = definition();
        changed.label = "";
        assert_eq!(
            PrivacyProfile::new(changed),
            Err(PrivacyProfileError::EmptyLabel)
        );

        let mut changed = definition();
        changed.store_reads = 0;
        assert_eq!(
            PrivacyProfile::new(changed),
            Err(PrivacyProfileError::ZeroStoreReads)
        );

        let mut changed = definition();
        changed.padded_input_slots = 0;
        assert_eq!(
            PrivacyProfile::new(changed),
            Err(PrivacyProfileError::ZeroPaddedInputSlots)
        );

        let mut changed = definition();
        changed.response_slots = 0;
        assert_eq!(
            PrivacyProfile::new(changed),
            Err(PrivacyProfileError::ZeroResponseSlots)
        );

        let mut changed = definition();
        changed.envelope_bytes = 0;
        assert_eq!(
            PrivacyProfile::new(changed),
            Err(PrivacyProfileError::ZeroEnvelopeBytes)
        );

        let mut changed = definition();
        changed.cover_rounds = 0;
        assert_eq!(
            PrivacyProfile::new(changed),
            Err(PrivacyProfileError::ZeroCoverRounds)
        );

        let mut changed = definition();
        changed.continuation_ttl_seconds = 0;
        assert_eq!(
            PrivacyProfile::new(changed),
            Err(PrivacyProfileError::ZeroContinuationTtl)
        );

        let mut changed = definition();
        changed.timeout_bucket_millis = 0;
        assert_eq!(
            PrivacyProfile::new(changed),
            Err(PrivacyProfileError::ZeroTimeoutBucket)
        );

        let mut changed = definition();
        changed.replay_transaction_capacity = 0;
        assert_eq!(
            PrivacyProfile::new(changed),
            Err(PrivacyProfileError::ZeroReplayTransactionCapacity)
        );

        let mut changed = definition();
        changed.replay_expiry_bucket_width_seconds = 0;
        assert_eq!(
            PrivacyProfile::new(changed),
            Err(PrivacyProfileError::ZeroReplayExpiryBucketWidth)
        );

        let mut changed = definition();
        changed.replay_garbage_collection_interval_seconds = 0;
        assert_eq!(
            PrivacyProfile::new(changed),
            Err(PrivacyProfileError::ZeroReplayGarbageCollectionInterval)
        );

        let mut changed = definition();
        changed.concurrency_queue_limit = 0;
        assert_eq!(
            PrivacyProfile::new(changed),
            Err(PrivacyProfileError::ZeroConcurrencyQueueLimit)
        );

        let mut changed = definition();
        changed.concurrency_queue_limit = usize::MAX;
        assert_eq!(
            PrivacyProfile::new(changed),
            Err(PrivacyProfileError::DimensionTooLarge)
        );

        let mut changed = definition();
        changed.store_reads = usize::MAX;
        changed.recent_snapshot_scan_slots = 1;
        assert_eq!(
            PrivacyProfile::new(changed),
            Err(PrivacyProfileError::DimensionTooLarge)
        );
    }

    #[test]
    fn profile_identifier_binds_every_authoritative_dimension_but_not_label() {
        let baseline = profile();
        assert_eq!(
            baseline.profile_id(),
            &[242, 71, 113, 71, 227, 192, 130, 40, 112, 11, 108, 206, 85, 56, 119, 181,]
        );
        let mut relabeled = definition();
        relabeled.label = "renamed";
        let relabeled =
            PrivacyProfile::new(relabeled).expect("relabeled test profile remains valid");
        assert_eq!(baseline.profile_id(), relabeled.profile_id());

        let mut changed = definition();
        changed.store_reads = 5;
        assert_definition_changes_id(&baseline, changed);

        let mut changed = definition();
        changed.padded_input_slots = 3;
        assert_definition_changes_id(&baseline, changed);

        let mut changed = definition();
        changed.recent_snapshot_scan_slots = 1;
        assert_definition_changes_id(&baseline, changed);

        let mut changed = definition();
        changed.response_slots = 3;
        assert_definition_changes_id(&baseline, changed);

        let mut changed = definition();
        changed.envelope_bytes = 129;
        assert_definition_changes_id(&baseline, changed);

        let mut changed = definition();
        changed.cover_rounds = 4;
        assert_definition_changes_id(&baseline, changed);

        let mut changed = definition();
        changed.continuation_ttl_seconds = 61;
        assert_definition_changes_id(&baseline, changed);

        let mut changed = definition();
        changed.timeout_bucket_millis = 1_001;
        assert_definition_changes_id(&baseline, changed);

        let mut changed = definition();
        changed.replay_transaction_capacity += 1;
        assert_definition_changes_id(&baseline, changed);

        let mut changed = definition();
        changed.replay_expiry_bucket_width_seconds += 1;
        assert_definition_changes_id(&baseline, changed);

        let mut changed = definition();
        changed.replay_garbage_collection_interval_seconds += 1;
        assert_definition_changes_id(&baseline, changed);

        let mut changed = definition();
        changed.concurrency_queue_limit = 3;
        assert_definition_changes_id(&baseline, changed);
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
        assert_eq!(
            profile().validate_recent_snapshot_slots::<1>(),
            Err(PrivacyProfileError::RecentSnapshotShapeMismatch {
                required: 0,
                available: 1,
            })
        );
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

    #[test]
    fn mainnet_profile_compiles_to_its_declared_shape() -> Result<(), Box<dyn std::error::Error>> {
        let profile = mainnet_utxo_history_profile()?;

        assert_eq!(profile.response_slots(), MAINNET_QUERY_SLOTS);
        assert_eq!(profile.envelope_bytes(), MAINNET_ENVELOPE_BYTES);
        assert_eq!(profile.store_reads(), 1_028);
        profile.validate_recent_snapshot_slots::<MAINNET_QUERY_SLOTS>()?;

        let shape =
            CompiledQueryShape::<MAINNET_QUERY_SLOTS, MAINNET_ENVELOPE_BYTES>::new(profile)?;
        assert_eq!(
            shape.empty_envelope().as_bytes().len(),
            MAINNET_ENVELOPE_BYTES
        );
        Ok(())
    }

    /// The identifier binds every authoritative dimension, so a changed
    /// parameter silently invalidates every lease, replay namespace, and sealed
    /// envelope minted under the old one. Pinning the bytes makes that a test
    /// failure rather than a production mismatch.
    #[test]
    fn mainnet_profile_identifier_is_pinned() -> Result<(), PrivacyProfileError> {
        const MAINNET_PROFILE_ID: [u8; PROFILE_ID_BYTES] = [
            0x67, 0x4f, 0xfb, 0xb1, 0x66, 0x9b, 0xe6, 0xfe, 0x65, 0xa1, 0xaa, 0x5d, 0x01, 0xf6,
            0xcb, 0x93,
        ];
        let profile = mainnet_utxo_history_profile()?;

        assert_eq!(profile.profile_id(), &MAINNET_PROFILE_ID);
        Ok(())
    }

    /// The scan depth is one number because scanning deeper than the envelope
    /// can return is wasted work. This pins the two together.
    #[test]
    fn mainnet_scan_depth_matches_the_response_width() -> Result<(), PrivacyProfileError> {
        let profile = mainnet_utxo_history_profile()?;

        assert_eq!(
            profile.store_reads(),
            MAINNET_DIRECTORY_PROBES + MAINNET_EVENT_PROBES * profile.response_slots()
        );
        Ok(())
    }
}
