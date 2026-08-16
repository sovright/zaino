//! Fixed-probe planning, record binding, and exclusive-command model.
//!
//! The parent module is a pure planner: it models two separate sparse tables,
//! validates every fixed probe observation before producing a match or an
//! insertion capability, and keeps layout identity separate from persistent
//! record encoding. Its vacancies and occupancy counts remain caller-supplied
//! model inputs. The private child command core joins that planner to two typed
//! backend interfaces under one synchronous owner and terminal-latches an
//! uncertain generation. Neither layer authenticates record contents, persists
//! the secret seed, proves crash atomicity, or establishes physical
//! obliviousness. A higher-layer authenticated public projection manifest does
//! not change those properties or make either table resumable after restart.

use std::{fmt, num::NonZeroU64};

use blake2::{
    digest::{Key, KeyInit, Mac},
    Blake2s256, Blake2sMac256, Digest,
};

use crate::records::{
    finalized_live_utxo_at, AddressDirectory, AddressEventPage, AddressKey,
    FinalizedEventHistoryError, PersistentAddressDirectory, PersistentAddressEventPage,
    RecordAnnotation, TransparentUtxo, UtxoEvent, UtxoScriptClass, ADDRESS_KEY_BYTES,
};

mod atomic_store;

#[cfg(feature = "rostl-experimental")]
pub(crate) use atomic_store::{rostl_insert_timing_probe, validate_rostl_insert_timing_shape};
#[cfg(feature = "corpus-zaino")]
pub(super) use atomic_store::{
    shutdown_atomic_worker, spawn_qualification_worker, spawn_typed_rostl_worker,
    AtomicQualificationAppendDisposition, AtomicQualificationAppendResult,
    AtomicQualificationCommandError, AtomicQualificationSnapshot, AtomicQueueCapacity,
    AtomicQueueCapacityError, AtomicWorker, AtomicWorkerBuildError, QualificationMemoryTable,
};
#[cfg(all(test, feature = "corpus-zaino"))]
pub(super) use atomic_store::{BackendFailure, UniqueTable};

const LAYOUT_FORMAT_VERSION: u8 = 1;
const ADDRESS_KEY_DOMAIN: &[u8] = b"zaino-oram-address-key-v1";
const PROBE_DOMAIN: &[u8] = b"zaino-oram-fixed-probe-v1";
const PROFILE_BINDING_DOMAIN: &[u8] = b"zaino-oram-layout-binding-v1";
const MINIMUM_TABLE_CAPACITY: u64 = 2;
const MAXIMUM_TABLE_CAPACITY: u64 = 1_u64 << 31;
const MAXIMUM_PROBE_COUNT: usize = 64;
#[cfg(feature = "corpus-zaino")]
const MAXIMUM_RUNTIME_PROBE_COUNT: usize = 16;

/// Network domain included in canonical address keys and probe plans.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum LayoutNetwork {
    Mainnet,
    Testnet,
    Regtest,
}

impl LayoutNetwork {
    const fn tag(self) -> u8 {
        match self {
            Self::Mainnet => 1,
            Self::Testnet => 2,
            Self::Regtest => 3,
        }
    }
}

/// Standard transparent address identity before canonical key derivation.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub(super) struct StandardAddress {
    kind: StandardScriptKind,
    hash: [u8; 20],
}

impl StandardAddress {
    pub(super) const fn new(kind: StandardScriptKind, hash: [u8; 20]) -> Self {
        Self { kind, hash }
    }

    fn from_event(event: &UtxoEvent) -> Result<Self, LayoutCorruption> {
        let kind = match event.script_class() {
            UtxoScriptClass::PayToPublicKeyHash => StandardScriptKind::PayToPublicKeyHash,
            UtxoScriptClass::PayToScriptHash => StandardScriptKind::PayToScriptHash,
            UtxoScriptClass::NonStandard => return Err(LayoutCorruption::InvalidEventOwner),
        };
        Ok(Self::new(kind, *event.script_hash()))
    }
}

impl fmt::Debug for StandardAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("StandardAddress([REDACTED])")
    }
}

/// Supported standard transparent locking-script class.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub(super) enum StandardScriptKind {
    PayToPublicKeyHash,
    PayToScriptHash,
}

impl StandardScriptKind {
    const fn tag(self) -> u8 {
        match self {
            Self::PayToPublicKeyHash => 1,
            Self::PayToScriptHash => 2,
        }
    }
}

/// Derives the canonical layout key for one standard transparent address.
pub(super) fn derive_standard_address_key(
    network: LayoutNetwork,
    schema_version: u32,
    address: StandardAddress,
) -> AddressKey {
    let mut hasher = Blake2s256::new();
    Digest::update(&mut hasher, ADDRESS_KEY_DOMAIN);
    Digest::update(&mut hasher, [LAYOUT_FORMAT_VERSION]);
    Digest::update(&mut hasher, [network.tag()]);
    Digest::update(&mut hasher, schema_version.to_le_bytes());
    Digest::update(&mut hasher, [address.kind.tag()]);
    Digest::update(&mut hasher, address.hash);
    let digest = Digest::finalize(hasher);
    let mut bytes = [0; ADDRESS_KEY_BYTES];
    bytes.copy_from_slice(&digest);
    AddressKey::new(bytes)
}

/// Secret probe seed injected by a future lifecycle owner.
struct ProbeSeed([u8; 32]);

impl ProbeSeed {
    fn new(bytes: [u8; 32]) -> Result<Self, LayoutConfigError> {
        if bytes
            .iter()
            .copied()
            .fold(0_u8, |combined, byte| combined | byte)
            == 0
        {
            return Err(LayoutConfigError::ZeroProbeSeed);
        }
        Ok(Self(bytes))
    }
}

impl fmt::Debug for ProbeSeed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ProbeSeed([REDACTED])")
    }
}

/// Immutable identity shared by both protected tables in one generation.
pub(super) struct LayoutIdentity {
    network: LayoutNetwork,
    schema_version: u32,
    key_epoch: NonZeroU64,
    generation: NonZeroU64,
    seed: ProbeSeed,
}

impl LayoutIdentity {
    pub(super) fn new(
        network: LayoutNetwork,
        schema_version: u32,
        key_epoch: u64,
        generation: u64,
        seed: [u8; 32],
    ) -> Result<Self, LayoutConfigError> {
        if schema_version == 0 {
            return Err(LayoutConfigError::ZeroSchemaVersion);
        }
        Ok(Self {
            network,
            schema_version,
            key_epoch: NonZeroU64::new(key_epoch).ok_or(LayoutConfigError::ZeroKeyEpoch)?,
            generation: NonZeroU64::new(generation)
                .ok_or(LayoutConfigError::ZeroLayoutGeneration)?,
            seed: ProbeSeed::new(seed)?,
        })
    }
}

impl fmt::Debug for LayoutIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LayoutIdentity { ..REDACTED.. }")
    }
}

/// Protected table kind. This is public profile information, not an identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum TableKind {
    Directory,
    Event,
}

impl TableKind {
    const fn tag(self) -> u8 {
        match self {
            Self::Directory => 1,
            Self::Event => 2,
        }
    }
}

/// Validated fixed allocation and admission boundary shared with sizing.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct TableAllocation {
    capacity: u32,
    admission_limit: u32,
}

impl TableAllocation {
    fn new(
        kind: TableKind,
        capacity: u64,
        admission_limit: u64,
    ) -> Result<Self, LayoutConfigError> {
        let capacity = validate_table_capacity(kind, capacity)?;
        let admission_limit = validate_admission_limit(kind, capacity, admission_limit)?;
        Ok(Self {
            capacity,
            admission_limit,
        })
    }

    pub(super) const fn capacity(self) -> u32 {
        self.capacity
    }

    pub(super) const fn admission_limit(self) -> u32 {
        self.admission_limit
    }
}

fn validate_table_capacity(kind: TableKind, capacity: u64) -> Result<u32, LayoutConfigError> {
    if capacity < MINIMUM_TABLE_CAPACITY {
        return Err(LayoutConfigError::CapacityBelowMinimum { table: kind });
    }
    if capacity > MAXIMUM_TABLE_CAPACITY {
        return Err(LayoutConfigError::CapacityOutsideSlotDomain { table: kind });
    }
    if !capacity.is_power_of_two() {
        return Err(LayoutConfigError::CapacityNotPowerOfTwo { table: kind });
    }
    u32::try_from(capacity)
        .map_err(|_| LayoutConfigError::CapacityOutsideSlotDomain { table: kind })
}

fn validate_admission_limit(
    kind: TableKind,
    capacity: u32,
    admission_limit: u64,
) -> Result<u32, LayoutConfigError> {
    if admission_limit == 0 {
        return Err(LayoutConfigError::ZeroAdmissionLimit { table: kind });
    }
    if admission_limit >= u64::from(capacity) {
        return Err(LayoutConfigError::AdmissionLimitOutsideTable { table: kind });
    }
    u32::try_from(admission_limit)
        .map_err(|_| LayoutConfigError::AdmissionLimitOutsideTable { table: kind })
}

impl fmt::Debug for TableAllocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TableAllocation { public_shape: true, .. }")
    }
}

/// Validated allocation shared by the pure planner and capacity model.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct FixedLayoutAllocation {
    directory: TableAllocation,
    event: TableAllocation,
    max_events_per_address: u32,
}

impl FixedLayoutAllocation {
    pub(super) fn new(
        directory_capacity: u64,
        directory_admission_limit: u64,
        event_capacity: u64,
        event_admission_limit: u64,
        max_events_per_address: u64,
    ) -> Result<Self, LayoutConfigError> {
        let directory = TableAllocation::new(
            TableKind::Directory,
            directory_capacity,
            directory_admission_limit,
        )?;
        let event = TableAllocation::new(TableKind::Event, event_capacity, event_admission_limit)?;
        Self::from_allocations(directory, event, max_events_per_address)
    }

    fn from_allocations(
        directory: TableAllocation,
        event: TableAllocation,
        max_events_per_address: u64,
    ) -> Result<Self, LayoutConfigError> {
        let max_events_per_address =
            validate_max_events_per_address(event.admission_limit(), max_events_per_address)?;
        Ok(Self {
            directory,
            event,
            max_events_per_address,
        })
    }

    pub(super) const fn directory(self) -> TableAllocation {
        self.directory
    }

    pub(super) const fn event(self) -> TableAllocation {
        self.event
    }

    pub(super) const fn max_events_per_address(self) -> u32 {
        self.max_events_per_address
    }
}

impl fmt::Debug for FixedLayoutAllocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FixedLayoutAllocation { public_shape: true, .. }")
    }
}

/// Capacity, admission, and fixed-probe shape shared by typed table configs.
#[derive(Clone, Copy, PartialEq, Eq)]
struct TableShape {
    capacity: u32,
    admission_limit: u32,
    probe_count: u32,
}

impl TableShape {
    fn new(
        kind: TableKind,
        capacity: u64,
        admission_limit: u64,
        probe_count: usize,
    ) -> Result<Self, LayoutConfigError> {
        if probe_count == 0 {
            return Err(LayoutConfigError::ZeroProbeCount { table: kind });
        }
        if probe_count > MAXIMUM_PROBE_COUNT {
            return Err(LayoutConfigError::ProbeCountAboveResearchLimit { table: kind });
        }
        let capacity = validate_table_capacity(kind, capacity)?;
        if u64::try_from(probe_count).map_or(true, |count| count > u64::from(capacity)) {
            return Err(LayoutConfigError::ProbeCountExceedsCapacity { table: kind });
        }
        let admission_limit = validate_admission_limit(kind, capacity, admission_limit)?;
        let probe_count = u32::try_from(probe_count)
            .map_err(|_| LayoutConfigError::ProbeCountAboveResearchLimit { table: kind })?;
        Ok(Self {
            capacity,
            admission_limit,
            probe_count,
        })
    }

    const fn mask(self) -> u32 {
        self.capacity - 1
    }

    const fn allocation(self) -> TableAllocation {
        TableAllocation {
            capacity: self.capacity,
            admission_limit: self.admission_limit,
        }
    }
}

impl fmt::Debug for TableShape {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TableShape { public_shape: true, .. }")
    }
}

/// Directory-table configuration that cannot be swapped with the event table.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct DirectoryTableConfiguration<const PROBES: usize>(TableShape);

impl<const PROBES: usize> DirectoryTableConfiguration<PROBES> {
    pub(super) fn new(capacity: u64, admission_limit: u64) -> Result<Self, LayoutConfigError> {
        TableShape::new(TableKind::Directory, capacity, admission_limit, PROBES).map(Self)
    }
}

impl<const PROBES: usize> fmt::Debug for DirectoryTableConfiguration<PROBES> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DirectoryTableConfiguration { public_shape: true, .. }")
    }
}

/// Event-table configuration that cannot be swapped with the directory table.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct EventTableConfiguration<const PROBES: usize>(TableShape);

impl<const PROBES: usize> EventTableConfiguration<PROBES> {
    pub(super) fn new(capacity: u64, admission_limit: u64) -> Result<Self, LayoutConfigError> {
        TableShape::new(TableKind::Event, capacity, admission_limit, PROBES).map(Self)
    }
}

impl<const PROBES: usize> fmt::Debug for EventTableConfiguration<PROBES> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EventTableConfiguration { public_shape: true, .. }")
    }
}

/// Invalid public layout configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum LayoutConfigError {
    ZeroSchemaVersion,
    ZeroKeyEpoch,
    ZeroLayoutGeneration,
    ZeroProbeSeed,
    ZeroProbeCount { table: TableKind },
    ProbeCountAboveResearchLimit { table: TableKind },
    RuntimeProbeCountAboveQualificationLimit { table: TableKind },
    CapacityBelowMinimum { table: TableKind },
    CapacityOutsideSlotDomain { table: TableKind },
    CapacityNotPowerOfTwo { table: TableKind },
    ProbeCountExceedsCapacity { table: TableKind },
    ZeroAdmissionLimit { table: TableKind },
    AdmissionLimitOutsideTable { table: TableKind },
    ZeroEventsPerAddress,
    EventsPerAddressOutsideDomain,
    EventsPerAddressExceedsAdmission,
}

impl fmt::Display for LayoutConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroSchemaVersion => f.write_str("layout schema version must be nonzero"),
            Self::ZeroKeyEpoch => f.write_str("layout key epoch must be nonzero"),
            Self::ZeroLayoutGeneration => f.write_str("layout generation must be nonzero"),
            Self::ZeroProbeSeed => f.write_str("layout probe seed must not be all zero"),
            Self::ZeroProbeCount { table } => {
                write!(f, "{table:?} table probe count must be nonzero")
            }
            Self::ProbeCountAboveResearchLimit { table } => write!(
                f,
                "{table:?} table probe count exceeds the research safety bound"
            ),
            Self::RuntimeProbeCountAboveQualificationLimit { table } => write!(
                f,
                "{table:?} table runtime probe count exceeds the qualification limit"
            ),
            Self::CapacityBelowMinimum { table } => {
                write!(f, "{table:?} table capacity is below the backend minimum")
            }
            Self::CapacityOutsideSlotDomain { table } => {
                write!(f, "{table:?} table capacity is outside the slot domain")
            }
            Self::CapacityNotPowerOfTwo { table } => {
                write!(f, "{table:?} table capacity is not a power of two")
            }
            Self::ProbeCountExceedsCapacity { table } => {
                write!(f, "{table:?} table probe count exceeds capacity")
            }
            Self::ZeroAdmissionLimit { table } => {
                write!(f, "{table:?} table admission limit must be nonzero")
            }
            Self::AdmissionLimitOutsideTable { table } => {
                write!(f, "{table:?} table admission limit must be below capacity")
            }
            Self::ZeroEventsPerAddress => {
                f.write_str("layout events-per-address limit must be nonzero")
            }
            Self::EventsPerAddressOutsideDomain => {
                f.write_str("layout events-per-address limit is outside the ordinal domain")
            }
            Self::EventsPerAddressExceedsAdmission => f.write_str(
                "layout events-per-address limit exceeds event-table admission capacity",
            ),
        }
    }
}

impl std::error::Error for LayoutConfigError {}

fn validate_max_events_per_address(
    event_admission_limit: u32,
    max_events_per_address: u64,
) -> Result<u32, LayoutConfigError> {
    if max_events_per_address == 0 {
        return Err(LayoutConfigError::ZeroEventsPerAddress);
    }
    let max_events_per_address = u32::try_from(max_events_per_address)
        .map_err(|_| LayoutConfigError::EventsPerAddressOutsideDomain)?;
    if max_events_per_address > event_admission_limit {
        return Err(LayoutConfigError::EventsPerAddressExceedsAdmission);
    }
    Ok(max_events_per_address)
}

/// Identifier-free failure to prepare a logical probe plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum LayoutPlanError {
    EventOrdinalOutOfRange,
    DirectoryProfileMismatch,
    DirectoryIndexOutsideProbeSet,
    ProbePlanProfileMismatch,
    BackendIndexOutsideHostDomain,
}

impl fmt::Display for LayoutPlanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EventOrdinalOutOfRange => {
                f.write_str("event ordinal is outside the compiled layout profile")
            }
            Self::DirectoryProfileMismatch => {
                f.write_str("directory witness belongs to a different layout profile")
            }
            Self::DirectoryIndexOutsideProbeSet => {
                f.write_str("directory index is outside the keyed probe set")
            }
            Self::ProbePlanProfileMismatch => {
                f.write_str("probe plan belongs to a different layout profile")
            }
            Self::BackendIndexOutsideHostDomain => {
                f.write_str("logical table slot is outside the host index domain")
            }
        }
    }
}

impl std::error::Error for LayoutPlanError {}

/// Identifier-free corruption found after completing a fixed probe scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LayoutCorruption {
    ProbePlanProfileMismatch,
    InvalidDirectoryRecord,
    FoundDirectoryDummy,
    DirectoryPhysicalSlotMismatch,
    DirectoryProbeOwnershipMismatch,
    DuplicateDirectoryIdentity,
    InvalidEventRecord,
    FoundEventDummy,
    EventDirectoryIdentityOutOfRange,
    EventOrdinalOutOfRange,
    EventProbeOwnershipMismatch,
    DuplicateEventIdentity,
    InvalidEventOwner,
    EventOwnerMismatch,
}

impl fmt::Display for LayoutCorruption {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ProbePlanProfileMismatch => {
                f.write_str("probe plan belongs to a different layout profile")
            }
            Self::InvalidDirectoryRecord => f.write_str("directory record is invalid"),
            Self::FoundDirectoryDummy => {
                f.write_str("found directory dummy is corruption, not vacant capacity")
            }
            Self::DirectoryPhysicalSlotMismatch => {
                f.write_str("directory record is bound to a different physical slot")
            }
            Self::DirectoryProbeOwnershipMismatch => {
                f.write_str("directory record does not own its physical probe slot")
            }
            Self::DuplicateDirectoryIdentity => {
                f.write_str("directory probe set contains a duplicate logical identity")
            }
            Self::InvalidEventRecord => f.write_str("event record is invalid"),
            Self::FoundEventDummy => {
                f.write_str("found event dummy is corruption, not vacant capacity")
            }
            Self::EventDirectoryIdentityOutOfRange => {
                f.write_str("event record refers to an invalid directory identity")
            }
            Self::EventOrdinalOutOfRange => {
                f.write_str("event record ordinal is outside the layout profile")
            }
            Self::EventProbeOwnershipMismatch => {
                f.write_str("event record does not own its physical probe slot")
            }
            Self::DuplicateEventIdentity => {
                f.write_str("event probe set contains a duplicate logical identity")
            }
            Self::InvalidEventOwner => {
                f.write_str("event record has no canonical standard-address owner")
            }
            Self::EventOwnerMismatch => {
                f.write_str("event record owner does not match its bound directory")
            }
        }
    }
}

impl std::error::Error for LayoutCorruption {}

/// Identifier-free refusal to prepare an immutable insertion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MutationPlanError {
    AlreadyPresent { table: TableKind },
    ProbeSetFull { table: TableKind },
    VacancyProfileMismatch { table: TableKind },
    PreparedProfileMismatch { table: TableKind },
    BackendIndexOutsideHostDomain { table: TableKind },
    CoverPlanNotInsertable,
    AdmissionLimitReached { table: TableKind },
    EventOwnerMismatch,
    AbsentRecord { table: TableKind },
}

impl fmt::Display for MutationPlanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyPresent { table } => {
                write!(f, "{table:?} table already contains the logical identity")
            }
            Self::ProbeSetFull { table } => {
                write!(f, "{table:?} table fixed probe set has no vacant slot")
            }
            Self::VacancyProfileMismatch { table } => {
                write!(
                    f,
                    "{table:?} table vacancy belongs to another layout profile"
                )
            }
            Self::PreparedProfileMismatch { table } => {
                write!(
                    f,
                    "prepared {table:?} insert belongs to another layout profile"
                )
            }
            Self::BackendIndexOutsideHostDomain { table } => {
                write!(
                    f,
                    "prepared {table:?} insert is outside the host index domain"
                )
            }
            Self::CoverPlanNotInsertable => {
                f.write_str("cover event probe plans cannot prepare insertions")
            }
            Self::AdmissionLimitReached { table } => {
                write!(f, "{table:?} table reached its configured admission limit")
            }
            Self::EventOwnerMismatch => {
                f.write_str("event owner does not match the prepared directory identity")
            }
            Self::AbsentRecord { table } => {
                write!(f, "{table:?} table has no record to update in place")
            }
        }
    }
}

impl std::error::Error for MutationPlanError {}

/// One physical directory-table slot.
#[derive(Clone, Copy, PartialEq, Eq)]
struct DirectorySlot(u32);

impl DirectorySlot {
    fn backend_index(self) -> Result<usize, LayoutPlanError> {
        usize::try_from(self.0).map_err(|_| LayoutPlanError::BackendIndexOutsideHostDomain)
    }
}

impl fmt::Debug for DirectorySlot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DirectorySlot([REDACTED])")
    }
}

/// One physical event-table slot.
#[derive(Clone, Copy, PartialEq, Eq)]
struct EventTableSlot(u32);

impl EventTableSlot {
    fn backend_index(self) -> Result<usize, LayoutPlanError> {
        usize::try_from(self.0).map_err(|_| LayoutPlanError::BackendIndexOutsideHostDomain)
    }
}

impl fmt::Debug for EventTableSlot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EventTableSlot([REDACTED])")
    }
}

/// Canonical per-address append ordinal.
#[derive(Clone, Copy, PartialEq, Eq)]
struct EventOrdinal(u32);

impl fmt::Debug for EventOrdinal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EventOrdinal([REDACTED])")
    }
}

/// Fixed directory probe plan derived inside one layout profile.
struct DirectoryProbePlan<const PROBES: usize> {
    profile_binding: [u8; 32],
    address_key: AddressKey,
    slots: [DirectorySlot; PROBES],
}

impl<const PROBES: usize> fmt::Debug for DirectoryProbePlan<PROBES> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DirectoryProbePlan { ..REDACTED.. }")
    }
}

/// A directory match whose full key and physical slot were validated.
#[derive(Clone, Copy, PartialEq, Eq)]
struct BoundDirectory {
    profile_binding: [u8; 32],
    slot: DirectorySlot,
    address_key: AddressKey,
}

impl fmt::Debug for BoundDirectory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BoundDirectory { ..REDACTED.. }")
    }
}

/// A clean directory vacancy retained only while one append is preflighted.
#[derive(Clone, Copy, PartialEq, Eq)]
struct ProspectiveDirectory {
    profile_binding: [u8; 32],
    slot: DirectorySlot,
    address_key: AddressKey,
}

impl fmt::Debug for ProspectiveDirectory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ProspectiveDirectory { ..REDACTED.. }")
    }
}

/// Fixed event probe plan for one bound directory and append ordinal.
struct EventProbePlan<const PROBES: usize> {
    profile_binding: [u8; 32],
    directory_identity: u32,
    ordinal: EventOrdinal,
    expected_address_key: AddressKey,
    accept_match: bool,
    slots: [EventTableSlot; PROBES],
}

impl<const PROBES: usize> fmt::Debug for EventProbePlan<PROBES> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EventProbePlan { ..REDACTED.. }")
    }
}

/// One exact backend observation. Only a backend miss is vacant.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ProbeRead<T> {
    Miss,
    Found(T),
}

impl<T> fmt::Debug for ProbeRead<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ProbeRead([REDACTED])")
    }
}

/// Successful directory scan after every fixed probe was validated.
enum DirectoryScan {
    Found(BoundDirectory),
    Vacant(DirectoryVacancy),
    Full,
}

impl fmt::Debug for DirectoryScan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DirectoryScan { ..REDACTED.. }")
    }
}

/// Successful event scan after every fixed probe was validated.
enum EventScan {
    Found(BoundEventPage),
    Vacant(EventVacancy),
    Full,
}

/// Opaque witness that one caller-supplied complete clean event scan matched.
///
/// It carries the physical slot the match came from, which is what an in-place
/// annotation needs and an insertion does not: an insert claims a vacancy, an
/// annotation rewrites the exact occupied cell it just read.
#[derive(Clone, Copy)]
struct BoundEventPage {
    profile_binding: [u8; 32],
    page: AddressEventPage,
    slot: EventTableSlot,
}

impl BoundEventPage {
    const fn page(&self) -> &AddressEventPage {
        &self.page
    }
}

impl fmt::Debug for BoundEventPage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BoundEventPage { ..REDACTED.. }")
    }
}

impl fmt::Debug for EventScan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EventScan { ..REDACTED.. }")
    }
}

/// Opaque witness from one caller-supplied complete clean directory scan.
struct DirectoryVacancy {
    profile_binding: [u8; 32],
    address_key: AddressKey,
    slot: DirectorySlot,
}

impl fmt::Debug for DirectoryVacancy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DirectoryVacancy { ..REDACTED.. }")
    }
}

/// Opaque witness from one caller-supplied complete clean event scan.
struct EventVacancy {
    profile_binding: [u8; 32],
    expected_address_key: AddressKey,
    directory_identity: u32,
    ordinal: EventOrdinal,
    slot: EventTableSlot,
    insertable: bool,
}

impl fmt::Debug for EventVacancy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EventVacancy { ..REDACTED.. }")
    }
}

/// Immutable directory insertion prepared without touching a backend.
struct PreparedDirectoryInsert {
    profile_binding: [u8; 32],
    slot: DirectorySlot,
    value: PersistentAddressDirectory,
}

impl fmt::Debug for PreparedDirectoryInsert {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PreparedDirectoryInsert { ..REDACTED.. }")
    }
}

/// In-place event annotation prepared without touching a backend.
///
/// It carries both the exact prior bytes the scan observed and the replacement,
/// so the backend write is a compare-and-set rather than a blind overwrite. The
/// two encodings differ only in the annotation flag bits.
struct PreparedEventAnnotation {
    profile_binding: [u8; 32],
    slot: EventTableSlot,
    expected_prior: PersistentAddressEventPage,
    value: PersistentAddressEventPage,
}

impl fmt::Debug for PreparedEventAnnotation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PreparedEventAnnotation { ..REDACTED.. }")
    }
}

/// Immutable event insertion prepared without touching a backend.
struct PreparedEventInsert {
    profile_binding: [u8; 32],
    slot: EventTableSlot,
    value: PersistentAddressEventPage,
}

impl fmt::Debug for PreparedEventInsert {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PreparedEventInsert { ..REDACTED.. }")
    }
}

/// Aggregate fixed validation work retained only inside the pure model.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct ScanWork {
    observations: usize,
    owner_probe_slots: usize,
    identity_bindings: usize,
    duplicate_comparisons: usize,
}

struct ScanOutcome<T> {
    result: Result<T, LayoutCorruption>,
    work: ScanWork,
}

/// Fixed-capacity backend indices for one runtime qualification probe.
#[cfg(feature = "corpus-zaino")]
pub(super) struct RuntimeProbeIndices {
    indices: [usize; MAXIMUM_RUNTIME_PROBE_COUNT],
    len: usize,
}

#[cfg(feature = "corpus-zaino")]
impl RuntimeProbeIndices {
    pub(super) fn as_slice(&self) -> &[usize] {
        &self.indices[..self.len]
    }
}

/// Directory probes retaining the authority to bind one selected probe slot.
#[cfg(feature = "corpus-zaino")]
pub(super) struct RuntimeDirectoryProbeIndices(RuntimeProbeIndices);

#[cfg(feature = "corpus-zaino")]
impl RuntimeDirectoryProbeIndices {
    pub(super) fn as_slice(&self) -> &[usize] {
        self.0.as_slice()
    }

    pub(super) fn bind(
        &self,
        directory_index: usize,
    ) -> Result<RuntimeBoundDirectorySlot, LayoutPlanError> {
        if !self.as_slice().contains(&directory_index) {
            return Err(LayoutPlanError::DirectoryIndexOutsideProbeSet);
        }
        let slot = u32::try_from(directory_index)
            .map_err(|_| LayoutPlanError::BackendIndexOutsideHostDomain)?;
        Ok(RuntimeBoundDirectorySlot(slot))
    }
}

/// Directory slot whose membership in an address probe set was checked once.
#[cfg(feature = "corpus-zaino")]
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct RuntimeBoundDirectorySlot(u32);

/// Runtime-shaped keyed planner used only by corpus qualification analysis.
#[cfg(feature = "corpus-zaino")]
pub(super) struct RuntimeProbeLayout {
    identity: LayoutIdentity,
    directory: TableShape,
    event: TableShape,
    max_events_per_address: u32,
}

#[cfg(feature = "corpus-zaino")]
impl RuntimeProbeLayout {
    pub(super) fn new(
        identity: LayoutIdentity,
        allocation: FixedLayoutAllocation,
        directory_probe_count: usize,
        event_probe_count: usize,
    ) -> Result<Self, LayoutConfigError> {
        validate_runtime_probe_count(TableKind::Directory, directory_probe_count)?;
        validate_runtime_probe_count(TableKind::Event, event_probe_count)?;
        let directory_allocation = allocation.directory();
        let event_allocation = allocation.event();
        Ok(Self {
            identity,
            directory: TableShape::new(
                TableKind::Directory,
                u64::from(directory_allocation.capacity()),
                u64::from(directory_allocation.admission_limit()),
                directory_probe_count,
            )?,
            event: TableShape::new(
                TableKind::Event,
                u64::from(event_allocation.capacity()),
                u64::from(event_allocation.admission_limit()),
                event_probe_count,
            )?,
            max_events_per_address: allocation.max_events_per_address(),
        })
    }

    pub(super) fn directory_probe_indices(
        &self,
        address: StandardAddress,
    ) -> Result<RuntimeDirectoryProbeIndices, LayoutPlanError> {
        let address_key = derive_standard_address_key(
            self.identity.network,
            self.identity.schema_version,
            address,
        );
        self.probe_indices(TableKind::Directory, address_key.as_bytes())
            .map(RuntimeDirectoryProbeIndices)
    }

    pub(super) fn event_probe_indices(
        &self,
        directory: RuntimeBoundDirectorySlot,
        ordinal: u64,
    ) -> Result<RuntimeProbeIndices, LayoutPlanError> {
        let ordinal =
            u32::try_from(ordinal).map_err(|_| LayoutPlanError::EventOrdinalOutOfRange)?;
        if ordinal >= self.max_events_per_address {
            return Err(LayoutPlanError::EventOrdinalOutOfRange);
        }
        let mut logical_identity = [0; 8];
        logical_identity[..4].copy_from_slice(&directory.0.to_le_bytes());
        logical_identity[4..].copy_from_slice(&ordinal.to_le_bytes());
        self.probe_indices(TableKind::Event, &logical_identity)
    }

    fn probe_indices(
        &self,
        table: TableKind,
        logical_identity: &[u8],
    ) -> Result<RuntimeProbeIndices, LayoutPlanError> {
        let configuration = table_shape(self.directory, self.event, table);
        let mut sequence = probe_sequence(
            &self.identity,
            self.directory,
            self.event,
            self.max_events_per_address,
            table,
            logical_identity,
        );
        let len = usize::try_from(configuration.probe_count)
            .map_err(|_| LayoutPlanError::BackendIndexOutsideHostDomain)?;
        let mut indices = [0; MAXIMUM_RUNTIME_PROBE_COUNT];
        for destination in indices.iter_mut().take(len) {
            *destination = usize::try_from(sequence.next_slot())
                .map_err(|_| LayoutPlanError::BackendIndexOutsideHostDomain)?;
        }
        Ok(RuntimeProbeIndices { indices, len })
    }
}

#[cfg(feature = "corpus-zaino")]
fn validate_runtime_probe_count(
    table: TableKind,
    probe_count: usize,
) -> Result<(), LayoutConfigError> {
    if probe_count > MAXIMUM_RUNTIME_PROBE_COUNT {
        return Err(LayoutConfigError::RuntimeProbeCountAboveQualificationLimit { table });
    }
    Ok(())
}

/// Pure keyed planner for a two-table immutable layout generation.
pub(super) struct FixedProbeLayout<const DIRECTORY_PROBES: usize, const EVENT_PROBES: usize> {
    identity: LayoutIdentity,
    directory: DirectoryTableConfiguration<DIRECTORY_PROBES>,
    event: EventTableConfiguration<EVENT_PROBES>,
    max_events_per_address: u32,
    profile_binding: [u8; 32],
}

impl<const DIRECTORY_PROBES: usize, const EVENT_PROBES: usize>
    FixedProbeLayout<DIRECTORY_PROBES, EVENT_PROBES>
{
    pub(super) fn new(
        identity: LayoutIdentity,
        directory: DirectoryTableConfiguration<DIRECTORY_PROBES>,
        event: EventTableConfiguration<EVENT_PROBES>,
        max_events_per_address: u64,
    ) -> Result<Self, LayoutConfigError> {
        let allocation = FixedLayoutAllocation::from_allocations(
            directory.0.allocation(),
            event.0.allocation(),
            max_events_per_address,
        )?;
        let max_events_per_address = allocation.max_events_per_address();
        let mut layout = Self {
            identity,
            directory,
            event,
            max_events_per_address,
            profile_binding: [0; 32],
        };
        layout.profile_binding = layout.profile_binding();
        Ok(layout)
    }

    #[cfg(feature = "corpus-zaino")]
    pub(super) const fn network(&self) -> LayoutNetwork {
        self.identity.network
    }

    #[cfg(feature = "corpus-zaino")]
    pub(super) const fn schema_version(&self) -> u32 {
        self.identity.schema_version
    }

    #[cfg(feature = "corpus-zaino")]
    pub(super) const fn key_epoch(&self) -> u64 {
        self.identity.key_epoch.get()
    }

    #[cfg(feature = "corpus-zaino")]
    pub(super) const fn directory_admission_limit(&self) -> u32 {
        self.directory.0.admission_limit
    }

    #[cfg(feature = "corpus-zaino")]
    pub(super) const fn event_admission_limit(&self) -> u32 {
        self.event.0.admission_limit
    }

    #[cfg(feature = "corpus-zaino")]
    pub(super) const fn max_events_per_address(&self) -> u32 {
        self.max_events_per_address
    }

    fn address_key(&self, address: StandardAddress) -> AddressKey {
        derive_standard_address_key(self.identity.network, self.identity.schema_version, address)
    }

    fn directory_plan(&self, address: StandardAddress) -> DirectoryProbePlan<DIRECTORY_PROBES> {
        let address_key = self.address_key(address);
        self.directory_plan_for_key(&address_key)
    }

    fn directory_plan_for_key(
        &self,
        address_key: &AddressKey,
    ) -> DirectoryProbePlan<DIRECTORY_PROBES> {
        let slots = self
            .probe_slots::<DIRECTORY_PROBES>(TableKind::Directory, address_key.as_bytes())
            .map(DirectorySlot);
        DirectoryProbePlan {
            profile_binding: self.profile_binding,
            address_key: *address_key,
            slots,
        }
    }

    fn directory_backend_indices(
        &self,
        plan: &DirectoryProbePlan<DIRECTORY_PROBES>,
    ) -> Result<[usize; DIRECTORY_PROBES], LayoutPlanError> {
        if !fixed_bytes_equal(&plan.profile_binding, &self.profile_binding) {
            return Err(LayoutPlanError::ProbePlanProfileMismatch);
        }
        let mut indices = [0; DIRECTORY_PROBES];
        for (destination, slot) in indices.iter_mut().zip(plan.slots) {
            *destination = slot.backend_index()?;
        }
        Ok(indices)
    }

    #[cfg(feature = "corpus-zaino")]
    pub(super) fn qualification_directory_probe_indices(
        &self,
        address: StandardAddress,
    ) -> Result<[usize; DIRECTORY_PROBES], ()> {
        self.directory_backend_indices(&self.directory_plan(address))
            .map_err(|_| ())
    }

    #[cfg(feature = "corpus-zaino")]
    pub(super) fn qualification_event_probe_indices(
        &self,
        address: StandardAddress,
        directory_index: usize,
        ordinal: u64,
    ) -> Result<[usize; EVENT_PROBES], ()> {
        let directory_slot = DirectorySlot(u32::try_from(directory_index).map_err(|_| ())?);
        let directory_plan = self.directory_plan(address);
        if !directory_plan.slots.contains(&directory_slot) {
            return Err(());
        }
        let directory = BoundDirectory {
            profile_binding: directory_plan.profile_binding,
            slot: directory_slot,
            address_key: directory_plan.address_key,
        };
        let event_plan = self.event_plan(&directory, ordinal).map_err(|_| ())?;
        self.event_backend_indices(&event_plan).map_err(|_| ())
    }

    fn event_plan(
        &self,
        directory: &BoundDirectory,
        ordinal: u64,
    ) -> Result<EventProbePlan<EVENT_PROBES>, LayoutPlanError> {
        if !fixed_bytes_equal(&directory.profile_binding, &self.profile_binding) {
            return Err(LayoutPlanError::DirectoryProfileMismatch);
        }
        self.event_plan_for_identity(
            directory.profile_binding,
            directory.slot,
            directory.address_key,
            ordinal,
            true,
        )
    }

    fn prospective_directory(
        &self,
        vacancy: &DirectoryVacancy,
    ) -> Result<ProspectiveDirectory, LayoutPlanError> {
        if !fixed_bytes_equal(&vacancy.profile_binding, &self.profile_binding) {
            return Err(LayoutPlanError::DirectoryProfileMismatch);
        }
        Ok(ProspectiveDirectory {
            profile_binding: vacancy.profile_binding,
            slot: vacancy.slot,
            address_key: vacancy.address_key,
        })
    }

    fn prospective_event_plan(
        &self,
        directory: &ProspectiveDirectory,
        ordinal: u64,
    ) -> Result<EventProbePlan<EVENT_PROBES>, LayoutPlanError> {
        if !fixed_bytes_equal(&directory.profile_binding, &self.profile_binding) {
            return Err(LayoutPlanError::DirectoryProfileMismatch);
        }
        self.event_plan_for_identity(
            directory.profile_binding,
            directory.slot,
            directory.address_key,
            ordinal,
            true,
        )
    }

    fn cover_event_plan(
        &self,
        ordinal: u64,
    ) -> Result<EventProbePlan<EVENT_PROBES>, LayoutPlanError> {
        self.event_plan_for_identity(
            self.profile_binding,
            DirectorySlot(self.directory.0.capacity),
            self.synthetic_address_key(),
            ordinal,
            false,
        )
    }

    fn event_backend_indices(
        &self,
        plan: &EventProbePlan<EVENT_PROBES>,
    ) -> Result<[usize; EVENT_PROBES], LayoutPlanError> {
        if !fixed_bytes_equal(&plan.profile_binding, &self.profile_binding) {
            return Err(LayoutPlanError::ProbePlanProfileMismatch);
        }
        let mut indices = [0; EVENT_PROBES];
        for (destination, slot) in indices.iter_mut().zip(plan.slots) {
            *destination = slot.backend_index()?;
        }
        Ok(indices)
    }

    fn event_plan_for_identity(
        &self,
        profile_binding: [u8; 32],
        directory_slot: DirectorySlot,
        expected_address_key: AddressKey,
        ordinal: u64,
        accept_match: bool,
    ) -> Result<EventProbePlan<EVENT_PROBES>, LayoutPlanError> {
        let ordinal = self.event_ordinal(ordinal)?;
        let directory_identity = directory_slot.0;
        Ok(EventProbePlan {
            profile_binding,
            directory_identity,
            ordinal,
            expected_address_key,
            accept_match,
            slots: self
                .event_probe_slots(directory_identity, ordinal)
                .map(EventTableSlot),
        })
    }

    fn scan_directory(
        &self,
        plan: &DirectoryProbePlan<DIRECTORY_PROBES>,
        reads: [ProbeRead<PersistentAddressDirectory>; DIRECTORY_PROBES],
    ) -> Result<DirectoryScan, LayoutCorruption> {
        self.scan_directory_inner(plan, reads).result
    }

    fn scan_directory_inner(
        &self,
        plan: &DirectoryProbePlan<DIRECTORY_PROBES>,
        reads: [ProbeRead<PersistentAddressDirectory>; DIRECTORY_PROBES],
    ) -> ScanOutcome<DirectoryScan> {
        let mut corruption = None;
        if !fixed_bytes_equal(&plan.profile_binding, &self.profile_binding) {
            latch(&mut corruption, LayoutCorruption::ProbePlanProfileMismatch);
        }
        let mut decoded = [None; DIRECTORY_PROBES];
        let mut first_miss = None;
        let mut matched = None;
        let mut work = ScanWork::default();

        for (index, (physical_slot, read)) in plan.slots.iter().copied().zip(reads).enumerate() {
            work.observations += 1;
            let mut owner_key = self.synthetic_address_key();
            match read {
                ProbeRead::Miss => {
                    if first_miss.is_none() {
                        first_miss = Some(physical_slot);
                    }
                }
                ProbeRead::Found(persistent) => match persistent.into_business() {
                    Ok(record) if record.is_occupied() => {
                        owner_key = *record.address_key();
                        if record.directory_slot() != physical_slot.0 {
                            latch(
                                &mut corruption,
                                LayoutCorruption::DirectoryPhysicalSlotMismatch,
                            );
                        }
                        decoded[index] = Some(record);
                    }
                    Ok(_) => latch(&mut corruption, LayoutCorruption::FoundDirectoryDummy),
                    Err(_) => latch(&mut corruption, LayoutCorruption::InvalidDirectoryRecord),
                },
            }

            let owner_slots =
                self.probe_slots::<DIRECTORY_PROBES>(TableKind::Directory, owner_key.as_bytes());
            let mut owns_physical_slot = false;
            for candidate in owner_slots {
                work.owner_probe_slots += 1;
                owns_physical_slot |= candidate == physical_slot.0;
            }
            if decoded[index].is_some() && !owns_physical_slot {
                latch(
                    &mut corruption,
                    LayoutCorruption::DirectoryProbeOwnershipMismatch,
                );
            }
            let matches_query =
                fixed_bytes_equal(owner_key.as_bytes(), plan.address_key.as_bytes());
            work.identity_bindings += 1;
            if decoded[index].is_some() && matches_query && matched.is_none() {
                matched = Some(BoundDirectory {
                    profile_binding: self.profile_binding,
                    slot: physical_slot,
                    address_key: owner_key,
                });
            }
        }

        let duplicate_synthetic_key = self.synthetic_address_key();
        for left in 0..DIRECTORY_PROBES {
            for right in 0..DIRECTORY_PROBES {
                work.duplicate_comparisons += 1;
                let left_key =
                    decoded[left].map_or(duplicate_synthetic_key, |record| *record.address_key());
                let right_key =
                    decoded[right].map_or(duplicate_synthetic_key, |record| *record.address_key());
                let same_identity = fixed_bytes_equal(left_key.as_bytes(), right_key.as_bytes());
                let both_real = decoded[left].is_some() & decoded[right].is_some();
                if (left < right) & both_real & same_identity {
                    latch(
                        &mut corruption,
                        LayoutCorruption::DuplicateDirectoryIdentity,
                    );
                }
            }
        }

        let result = match corruption {
            Some(error) => Err(error),
            None => Ok(match matched {
                Some(directory) => DirectoryScan::Found(directory),
                None => match first_miss {
                    Some(slot) => DirectoryScan::Vacant(DirectoryVacancy {
                        profile_binding: self.profile_binding,
                        address_key: plan.address_key,
                        slot,
                    }),
                    None => DirectoryScan::Full,
                },
            }),
        };
        ScanOutcome { result, work }
    }

    fn scan_event(
        &self,
        plan: &EventProbePlan<EVENT_PROBES>,
        reads: [ProbeRead<PersistentAddressEventPage>; EVENT_PROBES],
    ) -> Result<EventScan, LayoutCorruption> {
        self.scan_event_inner(plan, reads).result
    }

    fn scan_event_inner(
        &self,
        plan: &EventProbePlan<EVENT_PROBES>,
        reads: [ProbeRead<PersistentAddressEventPage>; EVENT_PROBES],
    ) -> ScanOutcome<EventScan> {
        let mut corruption = None;
        if !fixed_bytes_equal(&plan.profile_binding, &self.profile_binding) {
            latch(&mut corruption, LayoutCorruption::ProbePlanProfileMismatch);
        }
        let mut decoded = [None; EVENT_PROBES];
        let mut first_miss = None;
        let mut matched = None;
        let mut work = ScanWork::default();

        for (index, (physical_slot, read)) in plan.slots.iter().copied().zip(reads).enumerate() {
            work.observations += 1;
            let mut owner_directory = self.directory.0.capacity;
            let mut owner_ordinal = EventOrdinal(0);
            let mut owner_address =
                StandardAddress::new(StandardScriptKind::PayToPublicKeyHash, [0; 20]);
            match read {
                ProbeRead::Miss => {
                    if first_miss.is_none() {
                        first_miss = Some(physical_slot);
                    }
                }
                ProbeRead::Found(persistent) => match persistent.into_business() {
                    Ok(record) if record.is_occupied() => {
                        owner_directory = record.directory_slot();
                        owner_ordinal = EventOrdinal(record.event_ordinal());
                        if owner_directory >= self.directory.0.capacity {
                            latch(
                                &mut corruption,
                                LayoutCorruption::EventDirectoryIdentityOutOfRange,
                            );
                        }
                        if owner_ordinal.0 >= self.max_events_per_address {
                            latch(&mut corruption, LayoutCorruption::EventOrdinalOutOfRange);
                        }
                        if let Some(event) = record.event() {
                            match StandardAddress::from_event(event) {
                                Ok(owner) => owner_address = owner,
                                Err(error) => latch(&mut corruption, error),
                            }
                        } else {
                            latch(&mut corruption, LayoutCorruption::FoundEventDummy);
                        }
                        decoded[index] = Some(record);
                    }
                    Ok(_) => latch(&mut corruption, LayoutCorruption::FoundEventDummy),
                    Err(_) => latch(&mut corruption, LayoutCorruption::InvalidEventRecord),
                },
            }

            let owner_slots = self
                .event_probe_slots(owner_directory, owner_ordinal)
                .map(EventTableSlot);
            let mut owns_physical_slot = false;
            for candidate in owner_slots {
                work.owner_probe_slots += 1;
                owns_physical_slot |= candidate == physical_slot;
            }
            if decoded[index].is_some() && !owns_physical_slot {
                latch(
                    &mut corruption,
                    LayoutCorruption::EventProbeOwnershipMismatch,
                );
            }
            let exact_identity =
                (owner_directory == plan.directory_identity) & (owner_ordinal == plan.ordinal);
            let owner_key = self.address_key(owner_address);
            let owner_matches =
                fixed_bytes_equal(owner_key.as_bytes(), plan.expected_address_key.as_bytes());
            work.identity_bindings += 1;
            if decoded[index].is_some() && exact_identity {
                if !plan.accept_match {
                    latch(
                        &mut corruption,
                        LayoutCorruption::EventDirectoryIdentityOutOfRange,
                    );
                } else if !owner_matches {
                    latch(&mut corruption, LayoutCorruption::EventOwnerMismatch);
                } else if matched.is_none() {
                    matched = decoded[index].map(|page| (page, physical_slot));
                }
            }
        }

        for left in 0..EVENT_PROBES {
            for right in 0..EVENT_PROBES {
                work.duplicate_comparisons += 1;
                let left_directory = decoded[left]
                    .map_or(self.directory.0.capacity, |record| record.directory_slot());
                let right_directory = decoded[right]
                    .map_or(self.directory.0.capacity, |record| record.directory_slot());
                let left_ordinal = decoded[left].map_or(0, |record| record.event_ordinal());
                let right_ordinal = decoded[right].map_or(0, |record| record.event_ordinal());
                let same_identity = ((left_directory ^ right_directory) == 0)
                    & ((left_ordinal ^ right_ordinal) == 0);
                let both_real = decoded[left].is_some() & decoded[right].is_some();
                if (left < right) & both_real & same_identity {
                    latch(&mut corruption, LayoutCorruption::DuplicateEventIdentity);
                }
            }
        }

        let result = match corruption {
            Some(error) => Err(error),
            None => Ok(match matched {
                Some((page, slot)) => EventScan::Found(BoundEventPage {
                    profile_binding: self.profile_binding,
                    page,
                    slot,
                }),
                None => match first_miss {
                    Some(slot) => EventScan::Vacant(EventVacancy {
                        profile_binding: self.profile_binding,
                        expected_address_key: plan.expected_address_key,
                        directory_identity: plan.directory_identity,
                        ordinal: plan.ordinal,
                        slot,
                        insertable: plan.accept_match,
                    }),
                    None => EventScan::Full,
                },
            }),
        };
        ScanOutcome { result, work }
    }

    fn prepare_directory_insert(
        &self,
        scan: DirectoryScan,
        occupied_records: u64,
    ) -> Result<PreparedDirectoryInsert, MutationPlanError> {
        match scan {
            DirectoryScan::Found(_) => Err(MutationPlanError::AlreadyPresent {
                table: TableKind::Directory,
            }),
            DirectoryScan::Full => Err(MutationPlanError::ProbeSetFull {
                table: TableKind::Directory,
            }),
            DirectoryScan::Vacant(vacancy) => {
                if occupied_records >= u64::from(self.directory.0.admission_limit) {
                    return Err(MutationPlanError::AdmissionLimitReached {
                        table: TableKind::Directory,
                    });
                }
                if !fixed_bytes_equal(&vacancy.profile_binding, &self.profile_binding) {
                    return Err(MutationPlanError::VacancyProfileMismatch {
                        table: TableKind::Directory,
                    });
                }
                let record = AddressDirectory::real(vacancy.slot.0, vacancy.address_key);
                Ok(PreparedDirectoryInsert {
                    profile_binding: self.profile_binding,
                    slot: vacancy.slot,
                    value: PersistentAddressDirectory::from_business(&record),
                })
            }
        }
    }

    fn prepare_event_insert(
        &self,
        scan: EventScan,
        event: UtxoEvent,
        occupied_records: u64,
    ) -> Result<PreparedEventInsert, MutationPlanError> {
        match scan {
            EventScan::Found(_) => Err(MutationPlanError::AlreadyPresent {
                table: TableKind::Event,
            }),
            EventScan::Full => Err(MutationPlanError::ProbeSetFull {
                table: TableKind::Event,
            }),
            EventScan::Vacant(vacancy) => {
                if !vacancy.insertable {
                    return Err(MutationPlanError::CoverPlanNotInsertable);
                }
                if occupied_records >= u64::from(self.event.0.admission_limit) {
                    return Err(MutationPlanError::AdmissionLimitReached {
                        table: TableKind::Event,
                    });
                }
                if !fixed_bytes_equal(&vacancy.profile_binding, &self.profile_binding) {
                    return Err(MutationPlanError::VacancyProfileMismatch {
                        table: TableKind::Event,
                    });
                }
                let owner = StandardAddress::from_event(&event)
                    .map_err(|_| MutationPlanError::EventOwnerMismatch)?;
                let owner_key = self.address_key(owner);
                if !fixed_bytes_equal(
                    owner_key.as_bytes(),
                    vacancy.expected_address_key.as_bytes(),
                ) {
                    return Err(MutationPlanError::EventOwnerMismatch);
                }
                let record =
                    AddressEventPage::real(vacancy.directory_identity, vacancy.ordinal.0, event)
                        .map_err(|_| MutationPlanError::EventOwnerMismatch)?;
                Ok(PreparedEventInsert {
                    profile_binding: self.profile_binding,
                    slot: vacancy.slot,
                    value: PersistentAddressEventPage::from_business(&record),
                })
            }
        }
    }

    /// Prepares the in-place annotation of one already-scanned occupied cell.
    ///
    /// An annotation never creates, moves, or removes a record, so there is no
    /// admission check here: occupancy is unchanged by construction. A scan
    /// that did not match is a caller error rather than an insertion
    /// opportunity — the annotation pass only ever rewrites records it read.
    fn prepare_event_annotation(
        &self,
        scan: EventScan,
        annotation: RecordAnnotation,
    ) -> Result<PreparedEventAnnotation, MutationPlanError> {
        match scan {
            EventScan::Vacant(_) | EventScan::Full => Err(MutationPlanError::AbsentRecord {
                table: TableKind::Event,
            }),
            EventScan::Found(bound) => {
                if !fixed_bytes_equal(&bound.profile_binding, &self.profile_binding) {
                    return Err(MutationPlanError::VacancyProfileMismatch {
                        table: TableKind::Event,
                    });
                }
                let annotated = bound
                    .page
                    .annotated(annotation)
                    .map_err(|_| MutationPlanError::EventOwnerMismatch)?;
                Ok(PreparedEventAnnotation {
                    profile_binding: self.profile_binding,
                    slot: bound.slot,
                    expected_prior: PersistentAddressEventPage::from_business(&bound.page),
                    value: PersistentAddressEventPage::from_business(&annotated),
                })
            }
        }
    }

    fn backend_event_annotation(
        &self,
        prepared: PreparedEventAnnotation,
    ) -> Result<
        (
            usize,
            PersistentAddressEventPage,
            PersistentAddressEventPage,
        ),
        MutationPlanError,
    > {
        if !fixed_bytes_equal(&prepared.profile_binding, &self.profile_binding) {
            return Err(MutationPlanError::PreparedProfileMismatch {
                table: TableKind::Event,
            });
        }
        let index = prepared.slot.backend_index().map_err(|_| {
            MutationPlanError::BackendIndexOutsideHostDomain {
                table: TableKind::Event,
            }
        })?;
        Ok((index, prepared.expected_prior, prepared.value))
    }

    fn backend_directory_insert(
        &self,
        prepared: PreparedDirectoryInsert,
    ) -> Result<(usize, PersistentAddressDirectory), MutationPlanError> {
        if !fixed_bytes_equal(&prepared.profile_binding, &self.profile_binding) {
            return Err(MutationPlanError::PreparedProfileMismatch {
                table: TableKind::Directory,
            });
        }
        let index = prepared.slot.backend_index().map_err(|_| {
            MutationPlanError::BackendIndexOutsideHostDomain {
                table: TableKind::Directory,
            }
        })?;
        Ok((index, prepared.value))
    }

    fn backend_event_insert(
        &self,
        prepared: PreparedEventInsert,
    ) -> Result<(usize, PersistentAddressEventPage), MutationPlanError> {
        if !fixed_bytes_equal(&prepared.profile_binding, &self.profile_binding) {
            return Err(MutationPlanError::PreparedProfileMismatch {
                table: TableKind::Event,
            });
        }
        let index = prepared.slot.backend_index().map_err(|_| {
            MutationPlanError::BackendIndexOutsideHostDomain {
                table: TableKind::Event,
            }
        })?;
        Ok((index, prepared.value))
    }

    fn event_ordinal(&self, ordinal: u64) -> Result<EventOrdinal, LayoutPlanError> {
        let ordinal =
            u32::try_from(ordinal).map_err(|_| LayoutPlanError::EventOrdinalOutOfRange)?;
        if ordinal >= self.max_events_per_address {
            return Err(LayoutPlanError::EventOrdinalOutOfRange);
        }
        Ok(EventOrdinal(ordinal))
    }

    fn event_probe_slots(
        &self,
        directory_identity: u32,
        ordinal: EventOrdinal,
    ) -> [u32; EVENT_PROBES] {
        let mut identity = [0; 8];
        identity[..4].copy_from_slice(&directory_identity.to_le_bytes());
        identity[4..].copy_from_slice(&ordinal.0.to_le_bytes());
        self.probe_slots::<EVENT_PROBES>(TableKind::Event, &identity)
    }

    fn probe_slots<const PROBES: usize>(
        &self,
        table: TableKind,
        logical_identity: &[u8],
    ) -> [u32; PROBES] {
        let mut sequence = probe_sequence(
            &self.identity,
            self.directory.0,
            self.event.0,
            self.max_events_per_address,
            table,
            logical_identity,
        );
        std::array::from_fn(|_| sequence.next_slot())
    }

    fn probe_digest(&self, table: TableKind, logical_identity: &[u8]) -> [u8; 32] {
        probe_digest(
            &self.identity,
            self.directory.0,
            self.event.0,
            self.max_events_per_address,
            table,
            logical_identity,
        )
    }

    fn profile_binding(&self) -> [u8; 32] {
        profile_binding(
            &self.identity,
            self.directory.0,
            self.event.0,
            self.max_events_per_address,
        )
    }

    fn synthetic_address_key(&self) -> AddressKey {
        self.address_key(StandardAddress::new(
            StandardScriptKind::PayToPublicKeyHash,
            [0; 20],
        ))
    }
}

struct ProbeSequence {
    next: u32,
    step: u32,
    mask: u32,
}

impl ProbeSequence {
    fn next_slot(&mut self) -> u32 {
        let current = self.next;
        self.next = self.next.wrapping_add(self.step) & self.mask;
        current
    }
}

fn probe_sequence(
    identity: &LayoutIdentity,
    directory: TableShape,
    event: TableShape,
    max_events_per_address: u32,
    table: TableKind,
    logical_identity: &[u8],
) -> ProbeSequence {
    let configuration = table_shape(directory, event, table);
    let digest = probe_digest(
        identity,
        directory,
        event,
        max_events_per_address,
        table,
        logical_identity,
    );
    let start =
        u32::from_le_bytes([digest[0], digest[1], digest[2], digest[3]]) & configuration.mask();
    let step = (u32::from_le_bytes([digest[4], digest[5], digest[6], digest[7]])
        & configuration.mask())
        | 1;
    ProbeSequence {
        next: start,
        step,
        mask: configuration.mask(),
    }
}

fn probe_digest(
    identity: &LayoutIdentity,
    directory: TableShape,
    event: TableShape,
    max_events_per_address: u32,
    table: TableKind,
    logical_identity: &[u8],
) -> [u8; 32] {
    let mut mac = probe_mac(identity);
    Mac::update(&mut mac, PROBE_DOMAIN);
    update_profile_mac(&mut mac, identity, directory, event, max_events_per_address);
    Mac::update(&mut mac, &[table.tag()]);
    Mac::update(&mut mac, logical_identity);
    let digest = Mac::finalize(mac).into_bytes();
    let mut bytes = [0; 32];
    bytes.copy_from_slice(&digest);
    bytes
}

fn profile_binding(
    identity: &LayoutIdentity,
    directory: TableShape,
    event: TableShape,
    max_events_per_address: u32,
) -> [u8; 32] {
    let mut mac = probe_mac(identity);
    Mac::update(&mut mac, PROFILE_BINDING_DOMAIN);
    update_profile_mac(&mut mac, identity, directory, event, max_events_per_address);
    let digest = Mac::finalize(mac).into_bytes();
    let mut bytes = [0; 32];
    bytes.copy_from_slice(&digest);
    bytes
}

fn update_profile_mac(
    mac: &mut Blake2sMac256,
    identity: &LayoutIdentity,
    directory: TableShape,
    event: TableShape,
    max_events_per_address: u32,
) {
    Mac::update(mac, &[LAYOUT_FORMAT_VERSION]);
    Mac::update(mac, &[identity.network.tag()]);
    Mac::update(mac, &identity.schema_version.to_le_bytes());
    Mac::update(mac, &identity.key_epoch.get().to_le_bytes());
    Mac::update(mac, &identity.generation.get().to_le_bytes());
    update_table_mac(mac, TableKind::Directory, directory);
    update_table_mac(mac, TableKind::Event, event);
    Mac::update(mac, &max_events_per_address.to_le_bytes());
}

fn probe_mac(identity: &LayoutIdentity) -> Blake2sMac256 {
    let key = Key::<Blake2sMac256>::from(identity.seed.0);
    <Blake2sMac256 as KeyInit>::new(&key)
}

fn update_table_mac(mac: &mut Blake2sMac256, kind: TableKind, table: TableShape) {
    Mac::update(mac, &[kind.tag()]);
    Mac::update(mac, &table.capacity.to_le_bytes());
    Mac::update(mac, &table.admission_limit.to_le_bytes());
    Mac::update(mac, &table.probe_count.to_le_bytes());
}

const fn table_shape(directory: TableShape, event: TableShape, table: TableKind) -> TableShape {
    match table {
        TableKind::Directory => directory,
        TableKind::Event => event,
    }
}

impl<const DIRECTORY_PROBES: usize, const EVENT_PROBES: usize> fmt::Debug
    for FixedProbeLayout<DIRECTORY_PROBES, EVENT_PROBES>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FixedProbeLayout { ..REDACTED.. }")
    }
}

fn fixed_bytes_equal<const N: usize>(left: &[u8; N], right: &[u8; N]) -> bool {
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

fn latch<T: Copy>(destination: &mut Option<T>, error: T) {
    if destination.is_none() {
        *destination = Some(error);
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::records::TXID_BYTES;

    const DIRECTORY_PROBES: usize = 4;
    const EVENT_PROBES: usize = 4;
    type TestLayout = FixedProbeLayout<DIRECTORY_PROBES, EVENT_PROBES>;

    fn layout() -> Result<TestLayout, LayoutConfigError> {
        layout_with(LayoutNetwork::Mainnet, 1, 7, 11, [0x5a; 32], 8, 6, 16, 12)
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "test helper exposes every immutable layout-domain input"
    )]
    fn layout_with(
        network: LayoutNetwork,
        schema_version: u32,
        key_epoch: u64,
        generation: u64,
        seed: [u8; 32],
        directory_capacity: u64,
        directory_admission: u64,
        event_capacity: u64,
        event_admission: u64,
    ) -> Result<TestLayout, LayoutConfigError> {
        FixedProbeLayout::new(
            LayoutIdentity::new(network, schema_version, key_epoch, generation, seed)?,
            DirectoryTableConfiguration::<DIRECTORY_PROBES>::new(
                directory_capacity,
                directory_admission,
            )?,
            EventTableConfiguration::<EVENT_PROBES>::new(event_capacity, event_admission)?,
            8,
        )
    }

    #[test]
    fn planner_and_sizing_share_one_validated_allocation_shape() -> Result<(), LayoutConfigError> {
        let allocation = FixedLayoutAllocation::new(8, 6, 16, 12, 8)?;
        let layout = layout()?;

        assert_eq!(allocation.directory(), layout.directory.0.allocation());
        assert_eq!(allocation.event(), layout.event.0.allocation());
        assert_eq!(allocation.max_events_per_address(), 8);
        assert_eq!(layout.max_events_per_address, 8);
        Ok(())
    }

    #[cfg(feature = "corpus-zaino")]
    fn assert_runtime_probe_parity<const PROBES: usize>() -> Result<(), Box<dyn std::error::Error>>
    {
        let fixed = FixedProbeLayout::<PROBES, PROBES>::new(
            LayoutIdentity::new(LayoutNetwork::Mainnet, 1, 7, 11, [0x5a; 32])?,
            DirectoryTableConfiguration::<PROBES>::new(32, 28)?,
            EventTableConfiguration::<PROBES>::new(64, 56)?,
            8,
        )?;
        let runtime = RuntimeProbeLayout::new(
            LayoutIdentity::new(LayoutNetwork::Mainnet, 1, 7, 11, [0x5a; 32])?,
            FixedLayoutAllocation::new(32, 28, 64, 56, 8)?,
            PROBES,
            PROBES,
        )?;

        for address in [p2pkh(0x11), p2sh(0x22), p2pkh(0xff)] {
            let expected_directory = fixed
                .qualification_directory_probe_indices(address)
                .expect("valid fixed qualification directory plan");
            let actual_directory = runtime.directory_probe_indices(address)?;
            assert_eq!(actual_directory.as_slice(), expected_directory.as_slice());

            for directory_index in expected_directory {
                let bound_directory = actual_directory.bind(directory_index)?;
                for ordinal in [0, 3, 7] {
                    let expected_event = fixed
                        .qualification_event_probe_indices(address, directory_index, ordinal)
                        .expect("valid fixed qualification event plan");
                    let actual_event = runtime.event_probe_indices(bound_directory, ordinal)?;
                    assert_eq!(actual_event.as_slice(), expected_event.as_slice());
                }
            }
        }
        Ok(())
    }

    #[cfg(feature = "corpus-zaino")]
    #[test]
    fn runtime_probes_match_fixed_qualification_helpers_at_supported_counts(
    ) -> Result<(), Box<dyn std::error::Error>> {
        assert_runtime_probe_parity::<4>()?;
        assert_runtime_probe_parity::<8>()?;
        assert_runtime_probe_parity::<16>()?;
        Ok(())
    }

    #[cfg(feature = "corpus-zaino")]
    #[test]
    fn runtime_directory_binding_rejects_non_probe_slots() -> Result<(), Box<dyn std::error::Error>>
    {
        let runtime = RuntimeProbeLayout::new(
            LayoutIdentity::new(LayoutNetwork::Mainnet, 1, 7, 11, [0x5a; 32])?,
            FixedLayoutAllocation::new(32, 28, 64, 56, 8)?,
            4,
            4,
        )?;
        let probes = runtime.directory_probe_indices(p2pkh(0x42))?;

        assert!(matches!(
            probes.bind(usize::MAX),
            Err(LayoutPlanError::DirectoryIndexOutsideProbeSet)
        ));
        Ok(())
    }

    #[cfg(feature = "corpus-zaino")]
    #[test]
    fn runtime_probe_count_is_bounded_by_fixed_representation(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let result = RuntimeProbeLayout::new(
            LayoutIdentity::new(LayoutNetwork::Mainnet, 1, 7, 11, [0x5a; 32])?,
            FixedLayoutAllocation::new(32, 28, 64, 56, 8)?,
            MAXIMUM_RUNTIME_PROBE_COUNT + 1,
            4,
        );

        assert!(matches!(
            result,
            Err(
                LayoutConfigError::RuntimeProbeCountAboveQualificationLimit {
                    table: TableKind::Directory
                }
            )
        ));
        Ok(())
    }

    #[test]
    fn key_addressed_directory_plan_matches_the_standard_address_plan(
    ) -> Result<(), LayoutConfigError> {
        let layout = layout()?;
        let address = p2sh(0x2a);
        let address_plan = layout.directory_plan(address);
        let key_plan = layout.directory_plan_for_key(&address_plan.address_key);

        assert_eq!(key_plan.profile_binding, address_plan.profile_binding);
        assert_eq!(key_plan.address_key, address_plan.address_key);
        assert_eq!(key_plan.slots, address_plan.slots);
        Ok(())
    }

    const fn p2pkh(byte: u8) -> StandardAddress {
        StandardAddress::new(StandardScriptKind::PayToPublicKeyHash, [byte; 20])
    }

    const fn p2sh(byte: u8) -> StandardAddress {
        StandardAddress::new(StandardScriptKind::PayToScriptHash, [byte; 20])
    }

    fn event(address: StandardAddress, txid_byte: u8) -> UtxoEvent {
        let script_class = match address.kind {
            StandardScriptKind::PayToPublicKeyHash => UtxoScriptClass::PayToPublicKeyHash,
            StandardScriptKind::PayToScriptHash => UtxoScriptClass::PayToScriptHash,
        };
        UtxoEvent::created(
            [txid_byte; TXID_BYTES],
            1,
            50_000,
            100,
            script_class,
            address.hash,
        )
    }

    fn bound_directory(
        layout: &TestLayout,
        address: StandardAddress,
        probe_index: usize,
    ) -> BoundDirectory {
        let plan = layout.directory_plan(address);
        let mut reads = [ProbeRead::Miss; DIRECTORY_PROBES];
        let record = AddressDirectory::real(plan.slots[probe_index].0, plan.address_key);
        reads[probe_index] = ProbeRead::Found(PersistentAddressDirectory::from_business(&record));
        match layout
            .scan_directory(&plan, reads)
            .expect("valid directory fixture must scan")
        {
            DirectoryScan::Found(directory) => directory,
            DirectoryScan::Vacant(_) | DirectoryScan::Full => {
                panic!("valid directory fixture must bind")
            }
        }
    }

    fn directory_collision_for_slot(
        layout: &TestLayout,
        physical_slot: DirectorySlot,
        excluded: &[AddressKey],
    ) -> PersistentAddressDirectory {
        for candidate in 1_u16..=u16::MAX {
            let mut hash = [0; 20];
            hash[..2].copy_from_slice(&candidate.to_le_bytes());
            let plan = layout.directory_plan(StandardAddress::new(
                StandardScriptKind::PayToScriptHash,
                hash,
            ));
            if !excluded.contains(&plan.address_key) && plan.slots.contains(&physical_slot) {
                return PersistentAddressDirectory::from_business(&AddressDirectory::real(
                    physical_slot.0,
                    plan.address_key,
                ));
            }
        }
        panic!("small deterministic table must have a collision fixture")
    }

    fn directory_nonowner_for_slot(
        layout: &TestLayout,
        physical_slot: DirectorySlot,
    ) -> PersistentAddressDirectory {
        for candidate in 1_u16..=u16::MAX {
            let mut hash = [0; 20];
            hash[..2].copy_from_slice(&candidate.to_le_bytes());
            let plan = layout.directory_plan(StandardAddress::new(
                StandardScriptKind::PayToPublicKeyHash,
                hash,
            ));
            if !plan.slots.contains(&physical_slot) {
                return PersistentAddressDirectory::from_business(&AddressDirectory::real(
                    physical_slot.0,
                    plan.address_key,
                ));
            }
        }
        panic!("small deterministic table must have a non-owner fixture")
    }

    fn event_collision_for_slot(
        layout: &TestLayout,
        physical_slot: EventTableSlot,
        excluded_directory: u32,
        excluded_ordinal: EventOrdinal,
    ) -> PersistentAddressEventPage {
        for directory_identity in 0..layout.directory.0.capacity {
            for ordinal in 0..layout.max_events_per_address {
                if directory_identity == excluded_directory && ordinal == excluded_ordinal.0 {
                    continue;
                }
                let event_ordinal = EventOrdinal(ordinal);
                if layout
                    .event_probe_slots(directory_identity, event_ordinal)
                    .map(EventTableSlot)
                    .contains(&physical_slot)
                {
                    let page = AddressEventPage::real(
                        directory_identity,
                        ordinal,
                        event(p2pkh(0x39), 0x40),
                    )
                    .expect("test collision event is standard");
                    return PersistentAddressEventPage::from_business(&page);
                }
            }
        }
        panic!("small deterministic event table must have a collision fixture")
    }

    fn event_nonowner_for_slot(
        layout: &TestLayout,
        physical_slot: EventTableSlot,
    ) -> PersistentAddressEventPage {
        for directory_identity in 0..layout.directory.0.capacity {
            for ordinal in 0..layout.max_events_per_address {
                let event_ordinal = EventOrdinal(ordinal);
                if !layout
                    .event_probe_slots(directory_identity, event_ordinal)
                    .map(EventTableSlot)
                    .contains(&physical_slot)
                {
                    let page = AddressEventPage::real(
                        directory_identity,
                        ordinal,
                        event(p2sh(0x51), 0x52),
                    )
                    .expect("test non-owner event is standard");
                    return PersistentAddressEventPage::from_business(&page);
                }
            }
        }
        panic!("small deterministic event table must have a non-owner fixture")
    }

    #[test]
    fn address_keys_and_probe_sequences_have_golden_domain_separated_vectors(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let layout = layout()?;
        let p2pkh_key = layout.address_key(p2pkh(0x11));
        let p2sh_key = layout.address_key(p2sh(0x11));
        assert_eq!(
            *p2pkh_key.as_bytes(),
            [
                154, 115, 127, 200, 219, 7, 24, 80, 230, 144, 97, 0, 65, 148, 244, 95, 110, 1, 246,
                100, 16, 192, 213, 112, 59, 120, 105, 245, 137, 93, 145, 233,
            ]
        );
        assert_ne!(p2pkh_key, p2sh_key);
        assert_eq!(
            *p2sh_key.as_bytes(),
            [
                17, 210, 43, 236, 226, 148, 5, 184, 105, 85, 88, 146, 177, 218, 69, 69, 134, 104,
                230, 186, 40, 195, 1, 64, 103, 93, 224, 49, 34, 242, 165, 93,
            ]
        );

        let directory = layout.directory_plan(p2pkh(0x11));
        assert_eq!(directory.slots.map(|slot| slot.0), [7, 2, 5, 0]);
        let bound = bound_directory(&layout, p2pkh(0x11), 0);
        let event = layout.event_plan(&bound, 3)?;
        assert_eq!(event.slots.map(|slot| slot.0), [13, 4, 11, 2]);
        let event_identity = |directory_identity: u32, ordinal: u32| {
            let mut identity = [0; 8];
            identity[..4].copy_from_slice(&directory_identity.to_le_bytes());
            identity[4..].copy_from_slice(&ordinal.to_le_bytes());
            identity
        };
        assert_ne!(
            layout.probe_digest(
                TableKind::Event,
                &event_identity(bound.slot.0, event.ordinal.0)
            ),
            layout.probe_digest(
                TableKind::Event,
                &event_identity(bound.slot.0, event.ordinal.0 - 1)
            )
        );
        assert_ne!(
            layout.probe_digest(
                TableKind::Event,
                &event_identity(bound.slot.0, event.ordinal.0)
            ),
            layout.probe_digest(
                TableKind::Event,
                &event_identity(
                    bound.slot.0.wrapping_add(1) & layout.directory.0.mask(),
                    event.ordinal.0
                )
            )
        );

        let testnet = layout_with(LayoutNetwork::Testnet, 1, 7, 11, [0x5a; 32], 8, 6, 16, 12)?;
        let testnet_key = testnet.address_key(StandardAddress::new(
            StandardScriptKind::PayToPublicKeyHash,
            [0x11; 20],
        ));
        assert_eq!(
            *testnet_key.as_bytes(),
            [
                49, 76, 69, 50, 208, 138, 195, 33, 18, 37, 47, 17, 227, 246, 235, 176, 38, 156, 62,
                20, 44, 186, 214, 177, 208, 12, 239, 210, 250, 54, 1, 85,
            ]
        );
        assert_ne!(p2pkh_key, testnet_key);
        assert_ne!(
            layout.probe_digest(TableKind::Directory, p2pkh_key.as_bytes()),
            layout.probe_digest(TableKind::Event, p2pkh_key.as_bytes())
        );
        Ok(())
    }

    #[test]
    fn complete_identity_and_profile_changes_are_domain_separated() -> Result<(), LayoutConfigError>
    {
        let base = layout()?;
        let mut last_byte_changed = p2pkh(0x22);
        last_byte_changed.hash[19] ^= 1;
        let original = base.directory_plan(p2pkh(0x22));
        let changed = base.directory_plan(last_byte_changed);
        assert_ne!(original.address_key, changed.address_key);
        assert_ne!(
            base.probe_digest(TableKind::Directory, original.address_key.as_bytes()),
            base.probe_digest(TableKind::Directory, changed.address_key.as_bytes())
        );

        let variants = [
            layout_with(LayoutNetwork::Regtest, 1, 7, 11, [0x5a; 32], 8, 6, 16, 12)?,
            layout_with(LayoutNetwork::Mainnet, 2, 7, 11, [0x5a; 32], 8, 6, 16, 12)?,
            layout_with(LayoutNetwork::Mainnet, 1, 8, 11, [0x5a; 32], 8, 6, 16, 12)?,
            layout_with(LayoutNetwork::Mainnet, 1, 7, 12, [0x5a; 32], 8, 6, 16, 12)?,
            layout_with(LayoutNetwork::Mainnet, 1, 7, 11, [0x5b; 32], 8, 6, 16, 12)?,
            layout_with(LayoutNetwork::Mainnet, 1, 7, 11, [0x5a; 32], 16, 6, 16, 12)?,
            layout_with(LayoutNetwork::Mainnet, 1, 7, 11, [0x5a; 32], 8, 5, 16, 12)?,
            layout_with(LayoutNetwork::Mainnet, 1, 7, 11, [0x5a; 32], 8, 6, 32, 12)?,
            layout_with(LayoutNetwork::Mainnet, 1, 7, 11, [0x5a; 32], 8, 6, 16, 11)?,
        ];
        for variant in variants {
            assert_ne!(base.profile_binding, variant.profile_binding);
        }

        type ThreeDirectoryProbes = FixedProbeLayout<3, EVENT_PROBES>;
        let changed_probe_count = ThreeDirectoryProbes::new(
            LayoutIdentity::new(LayoutNetwork::Mainnet, 1, 7, 11, [0x5a; 32])?,
            DirectoryTableConfiguration::<3>::new(8, 6)?,
            EventTableConfiguration::<EVENT_PROBES>::new(16, 12)?,
            8,
        )?;
        assert_ne!(base.profile_binding, changed_probe_count.profile_binding);

        type ThreeEventProbes = FixedProbeLayout<DIRECTORY_PROBES, 3>;
        let changed_event_probe_count = ThreeEventProbes::new(
            LayoutIdentity::new(LayoutNetwork::Mainnet, 1, 7, 11, [0x5a; 32])?,
            DirectoryTableConfiguration::<DIRECTORY_PROBES>::new(8, 6)?,
            EventTableConfiguration::<3>::new(16, 12)?,
            8,
        )?;
        assert_ne!(
            base.profile_binding,
            changed_event_probe_count.profile_binding
        );

        let changed_max_events = TestLayout::new(
            LayoutIdentity::new(LayoutNetwork::Mainnet, 1, 7, 11, [0x5a; 32])?,
            DirectoryTableConfiguration::<DIRECTORY_PROBES>::new(8, 6)?,
            EventTableConfiguration::<EVENT_PROBES>::new(16, 12)?,
            7,
        )?;
        assert_ne!(base.profile_binding, changed_max_events.profile_binding);
        Ok(())
    }

    #[test]
    fn probes_are_distinct_and_in_range_through_the_complete_small_domain(
    ) -> Result<(), LayoutConfigError> {
        type FullProbeLayout = FixedProbeLayout<8, 8>;
        let layout = FullProbeLayout::new(
            LayoutIdentity::new(LayoutNetwork::Mainnet, 1, 1, 1, [0x21; 32])?,
            DirectoryTableConfiguration::<8>::new(8, 7)?,
            EventTableConfiguration::<8>::new(8, 7)?,
            7,
        )?;
        let directory = layout.directory_plan(p2pkh(0x33));
        assert_eq!(
            directory
                .slots
                .iter()
                .map(|slot| slot.0)
                .collect::<BTreeSet<_>>()
                .len(),
            8
        );
        assert!(directory.slots.iter().all(|slot| slot.0 < 8));
        let bound = BoundDirectory {
            profile_binding: layout.profile_binding,
            slot: directory.slots[0],
            address_key: directory.address_key,
        };
        let event = layout
            .event_plan(&bound, 6)
            .expect("ordinal below the profile maximum is valid");
        assert_eq!(
            event
                .slots
                .iter()
                .map(|slot| slot.0)
                .collect::<BTreeSet<_>>()
                .len(),
            8
        );
        assert!(event.slots.iter().all(|slot| slot.0 < 8));
        Ok(())
    }

    #[test]
    fn every_layout_configuration_bound_fails_typed() -> Result<(), LayoutConfigError> {
        assert!(matches!(
            LayoutIdentity::new(LayoutNetwork::Mainnet, 0, 1, 1, [1; 32]),
            Err(LayoutConfigError::ZeroSchemaVersion)
        ));
        assert!(matches!(
            LayoutIdentity::new(LayoutNetwork::Mainnet, 1, 0, 1, [1; 32]),
            Err(LayoutConfigError::ZeroKeyEpoch)
        ));
        assert!(matches!(
            LayoutIdentity::new(LayoutNetwork::Mainnet, 1, 1, 0, [1; 32]),
            Err(LayoutConfigError::ZeroLayoutGeneration)
        ));
        assert!(matches!(
            LayoutIdentity::new(LayoutNetwork::Mainnet, 1, 1, 1, [0; 32]),
            Err(LayoutConfigError::ZeroProbeSeed)
        ));
        assert_eq!(
            DirectoryTableConfiguration::<0>::new(8, 6),
            Err(LayoutConfigError::ZeroProbeCount {
                table: TableKind::Directory
            })
        );
        assert_eq!(
            DirectoryTableConfiguration::<65>::new(128, 64),
            Err(LayoutConfigError::ProbeCountAboveResearchLimit {
                table: TableKind::Directory
            })
        );
        assert_eq!(
            EventTableConfiguration::<4>::new(1, 1),
            Err(LayoutConfigError::CapacityBelowMinimum {
                table: TableKind::Event
            })
        );
        assert_eq!(
            EventTableConfiguration::<4>::new(6, 4),
            Err(LayoutConfigError::CapacityNotPowerOfTwo {
                table: TableKind::Event
            })
        );
        assert_eq!(
            EventTableConfiguration::<4>::new(MAXIMUM_TABLE_CAPACITY + 1, 4),
            Err(LayoutConfigError::CapacityOutsideSlotDomain {
                table: TableKind::Event
            })
        );
        assert_eq!(
            DirectoryTableConfiguration::<8>::new(4, 3),
            Err(LayoutConfigError::ProbeCountExceedsCapacity {
                table: TableKind::Directory
            })
        );
        assert_eq!(
            DirectoryTableConfiguration::<4>::new(8, 0),
            Err(LayoutConfigError::ZeroAdmissionLimit {
                table: TableKind::Directory
            })
        );
        assert_eq!(
            DirectoryTableConfiguration::<4>::new(8, 8),
            Err(LayoutConfigError::AdmissionLimitOutsideTable {
                table: TableKind::Directory
            })
        );

        let identity = LayoutIdentity::new(LayoutNetwork::Mainnet, 1, 1, 1, [1; 32])?;
        assert!(matches!(
            FixedProbeLayout::<4, 4>::new(
                identity,
                DirectoryTableConfiguration::<4>::new(8, 6)?,
                EventTableConfiguration::<4>::new(16, 12)?,
                0,
            ),
            Err(LayoutConfigError::ZeroEventsPerAddress)
        ));
        assert!(matches!(
            layout()?.event_plan(&bound_directory(&layout()?, p2pkh(1), 0), 8),
            Err(LayoutPlanError::EventOrdinalOutOfRange)
        ));
        Ok(())
    }

    #[test]
    fn minimum_and_maximum_supported_table_shapes_are_accepted(
    ) -> Result<(), Box<dyn std::error::Error>> {
        type EdgeLayout = FixedProbeLayout<1, MAXIMUM_PROBE_COUNT>;
        let layout = EdgeLayout::new(
            LayoutIdentity::new(LayoutNetwork::Mainnet, 1, 1, 1, [0x19; 32])?,
            DirectoryTableConfiguration::<1>::new(2, 1)?,
            EventTableConfiguration::<MAXIMUM_PROBE_COUNT>::new(
                MAXIMUM_TABLE_CAPACITY,
                MAXIMUM_TABLE_CAPACITY - 1,
            )?,
            1,
        )?;
        let directory = layout.directory_plan(p2pkh(0x1a));
        assert_eq!(directory.slots.len(), 1);
        assert!(directory.slots[0].0 < 2);
        let bound = BoundDirectory {
            profile_binding: layout.profile_binding,
            slot: directory.slots[0],
            address_key: directory.address_key,
        };
        let event = layout.event_plan(&bound, 0)?;
        assert_eq!(event.slots.len(), MAXIMUM_PROBE_COUNT);
        assert_eq!(
            event
                .slots
                .iter()
                .map(|slot| slot.0)
                .collect::<BTreeSet<_>>()
                .len(),
            MAXIMUM_PROBE_COUNT
        );
        assert!(event
            .slots
            .iter()
            .all(|slot| u64::from(slot.0) < MAXIMUM_TABLE_CAPACITY));
        Ok(())
    }

    #[test]
    fn foreign_plans_and_vacancies_fail_closed_before_reuse(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let original = layout()?;
        let replacement = layout_with(LayoutNetwork::Mainnet, 1, 7, 12, [0x5a; 32], 8, 6, 16, 12)?;
        let plan = original.directory_plan(p2pkh(0x1b));
        assert!(matches!(
            replacement.directory_backend_indices(&plan),
            Err(LayoutPlanError::ProbePlanProfileMismatch)
        ));
        assert!(matches!(
            replacement.scan_directory(&plan, [ProbeRead::Miss; DIRECTORY_PROBES]),
            Err(LayoutCorruption::ProbePlanProfileMismatch)
        ));

        let vacancy = original.scan_directory(&plan, [ProbeRead::Miss; DIRECTORY_PROBES])?;
        let prospective = match &vacancy {
            DirectoryScan::Vacant(vacancy) => original.prospective_directory(vacancy)?,
            DirectoryScan::Found(_) | DirectoryScan::Full => {
                panic!("all-miss directory scan must produce a vacancy")
            }
        };
        let event_plan = original.prospective_event_plan(&prospective, 0)?;
        assert!(matches!(
            replacement.event_backend_indices(&event_plan),
            Err(LayoutPlanError::ProbePlanProfileMismatch)
        ));
        assert!(matches!(
            replacement.prepare_directory_insert(vacancy, 0),
            Err(MutationPlanError::VacancyProfileMismatch {
                table: TableKind::Directory
            })
        ));
        Ok(())
    }

    #[test]
    fn directory_scan_accepts_collision_and_late_match_then_prevents_duplicate_insert(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let layout = layout()?;
        let plan = layout.directory_plan(p2pkh(0x61));
        let mut reads = [ProbeRead::Miss; DIRECTORY_PROBES];
        reads[0] = ProbeRead::Found(directory_collision_for_slot(
            &layout,
            plan.slots[0],
            &[plan.address_key],
        ));
        let match_record = AddressDirectory::real(plan.slots[3].0, plan.address_key);
        reads[3] = ProbeRead::Found(PersistentAddressDirectory::from_business(&match_record));

        let scan = layout.scan_directory(&plan, reads)?;
        let bound = match scan {
            DirectoryScan::Found(bound) => bound,
            DirectoryScan::Vacant(_) | DirectoryScan::Full => {
                panic!("late exact identity must bind")
            }
        };
        assert_eq!(bound.slot, plan.slots[3]);
        assert_eq!(
            bound.slot.backend_index()?,
            usize::try_from(plan.slots[3].0).expect("u32 test slot fits the host index")
        );
        assert!(matches!(
            layout.prepare_directory_insert(DirectoryScan::Found(bound), 0),
            Err(MutationPlanError::AlreadyPresent {
                table: TableKind::Directory
            })
        ));
        Ok(())
    }

    #[test]
    fn directory_scan_latches_late_corruption_and_completes_fixed_work(
    ) -> Result<(), LayoutConfigError> {
        let layout = layout()?;
        let plan = layout.directory_plan(p2pkh(0x62));
        let mut reads = [ProbeRead::Miss; DIRECTORY_PROBES];
        reads[0] = ProbeRead::Found(PersistentAddressDirectory::from_business(
            &AddressDirectory::real(plan.slots[0].0, plan.address_key),
        ));
        reads[DIRECTORY_PROBES - 1] = ProbeRead::Found(PersistentAddressDirectory::from_business(
            &AddressDirectory::dummy(),
        ));

        let outcome = layout.scan_directory_inner(&plan, reads);
        assert!(matches!(
            outcome.result,
            Err(LayoutCorruption::FoundDirectoryDummy)
        ));
        assert_eq!(
            outcome.work,
            ScanWork {
                observations: DIRECTORY_PROBES,
                owner_probe_slots: DIRECTORY_PROBES * DIRECTORY_PROBES,
                identity_bindings: DIRECTORY_PROBES,
                duplicate_comparisons: DIRECTORY_PROBES * DIRECTORY_PROBES,
            }
        );
        Ok(())
    }

    #[test]
    fn directory_scan_work_is_identical_for_miss_match_and_duplicate(
    ) -> Result<(), LayoutConfigError> {
        let layout = layout()?;
        let plan = layout.directory_plan(p2pkh(0x65));
        let miss = layout.scan_directory_inner(&plan, [ProbeRead::Miss; DIRECTORY_PROBES]);

        let persistent = |slot: DirectorySlot| {
            ProbeRead::Found(PersistentAddressDirectory::from_business(
                &AddressDirectory::real(slot.0, plan.address_key),
            ))
        };
        let mut matching = [ProbeRead::Miss; DIRECTORY_PROBES];
        matching[DIRECTORY_PROBES - 1] = persistent(plan.slots[DIRECTORY_PROBES - 1]);
        let matching = layout.scan_directory_inner(&plan, matching);

        let mut duplicate = [ProbeRead::Miss; DIRECTORY_PROBES];
        duplicate[0] = persistent(plan.slots[0]);
        duplicate[1] = persistent(plan.slots[1]);
        let duplicate = layout.scan_directory_inner(&plan, duplicate);

        assert_eq!(miss.work, matching.work);
        assert_eq!(miss.work, duplicate.work);
        assert!(miss.result.is_ok());
        assert!(matching.result.is_ok());
        assert!(matches!(
            duplicate.result,
            Err(LayoutCorruption::DuplicateDirectoryIdentity)
        ));
        Ok(())
    }

    #[test]
    fn directory_scan_rejects_invalid_dummy_slot_placement_and_duplicates(
    ) -> Result<(), LayoutConfigError> {
        let layout = layout()?;
        let plan = layout.directory_plan(p2pkh(0x63));

        let mut invalid = [ProbeRead::Miss; DIRECTORY_PROBES];
        invalid[0] = ProbeRead::Found(PersistentAddressDirectory::default());
        assert!(matches!(
            layout.scan_directory(&plan, invalid),
            Err(LayoutCorruption::InvalidDirectoryRecord)
        ));

        let mut wrong_slot = [ProbeRead::Miss; DIRECTORY_PROBES];
        wrong_slot[0] = ProbeRead::Found(PersistentAddressDirectory::from_business(
            &AddressDirectory::real(plan.slots[1].0, plan.address_key),
        ));
        assert!(matches!(
            layout.scan_directory(&plan, wrong_slot),
            Err(LayoutCorruption::DirectoryPhysicalSlotMismatch)
        ));

        let mut nonowner = [ProbeRead::Miss; DIRECTORY_PROBES];
        nonowner[0] = ProbeRead::Found(directory_nonowner_for_slot(&layout, plan.slots[0]));
        assert!(matches!(
            layout.scan_directory(&plan, nonowner),
            Err(LayoutCorruption::DirectoryProbeOwnershipMismatch)
        ));

        let mut duplicate = [ProbeRead::Miss; DIRECTORY_PROBES];
        duplicate[0] = ProbeRead::Found(PersistentAddressDirectory::from_business(
            &AddressDirectory::real(plan.slots[0].0, plan.address_key),
        ));
        duplicate[1] = ProbeRead::Found(PersistentAddressDirectory::from_business(
            &AddressDirectory::real(plan.slots[1].0, plan.address_key),
        ));
        assert!(matches!(
            layout.scan_directory(&plan, duplicate),
            Err(LayoutCorruption::DuplicateDirectoryIdentity)
        ));
        Ok(())
    }

    #[test]
    fn complete_clean_directory_scan_selects_first_miss_or_reports_probe_set_full(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let layout = layout()?;
        let plan = layout.directory_plan(p2pkh(0x64));
        let scan = layout.scan_directory(&plan, [ProbeRead::Miss; DIRECTORY_PROBES])?;
        let prepared = layout.prepare_directory_insert(scan, 0)?;
        let (backend_index, persistent) = layout.backend_directory_insert(prepared)?;
        assert_eq!(
            backend_index,
            usize::try_from(plan.slots[0].0).expect("u32 test slot fits the host index")
        );
        let record = persistent.into_business()?;
        assert_eq!(record.directory_slot(), plan.slots[0].0);
        assert_eq!(record.address_key(), &plan.address_key);

        let stale_scan = layout.scan_directory(&plan, [ProbeRead::Miss; DIRECTORY_PROBES])?;
        let stale_prepared = layout.prepare_directory_insert(stale_scan, 0)?;
        let replacement = layout_with(LayoutNetwork::Mainnet, 1, 7, 12, [0x5a; 32], 8, 6, 16, 12)?;
        assert!(matches!(
            replacement.backend_directory_insert(stale_prepared),
            Err(MutationPlanError::PreparedProfileMismatch {
                table: TableKind::Directory
            })
        ));

        let admission_scan = layout.scan_directory(&plan, [ProbeRead::Miss; DIRECTORY_PROBES])?;
        assert!(matches!(
            layout.prepare_directory_insert(admission_scan, 6),
            Err(MutationPlanError::AdmissionLimitReached {
                table: TableKind::Directory
            })
        ));

        let mut excluded = vec![plan.address_key];
        let mut full = [ProbeRead::Miss; DIRECTORY_PROBES];
        for (index, physical_slot) in plan.slots.iter().copied().enumerate() {
            let collision = directory_collision_for_slot(&layout, physical_slot, &excluded);
            let collision_record = collision
                .into_business()
                .expect("collision helper produces a valid record");
            excluded.push(*collision_record.address_key());
            full[index] = ProbeRead::Found(collision);
        }
        let scan = layout.scan_directory(&plan, full)?;
        assert!(matches!(scan, DirectoryScan::Full));
        assert!(matches!(
            layout.prepare_directory_insert(scan, 0),
            Err(MutationPlanError::ProbeSetFull {
                table: TableKind::Directory
            })
        ));
        Ok(())
    }

    #[test]
    fn event_scan_accepts_valid_collision_and_late_owner_bound_match(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let layout = layout()?;
        let address = p2sh(0x71);
        let bound = bound_directory(&layout, address, 1);
        let plan = layout.event_plan(&bound, 2)?;
        let mut reads = [ProbeRead::Miss; EVENT_PROBES];
        reads[0] = ProbeRead::Found(event_collision_for_slot(
            &layout,
            plan.slots[0],
            plan.directory_identity,
            plan.ordinal,
        ));
        let matching_event = event(address, 0x72);
        let matching_page =
            AddressEventPage::real(plan.directory_identity, plan.ordinal.0, matching_event)?;
        reads[3] = ProbeRead::Found(PersistentAddressEventPage::from_business(&matching_page));

        match layout.scan_event(&plan, reads)? {
            EventScan::Found(bound) => assert_eq!(bound.page().event(), Some(&matching_event)),
            EventScan::Vacant(_) | EventScan::Full => panic!("late event match must bind"),
        }
        assert_eq!(
            plan.slots[3].backend_index()?,
            usize::try_from(plan.slots[3].0).expect("u32 test slot fits the host index")
        );
        Ok(())
    }

    #[test]
    fn event_scan_rejects_owner_placement_dummy_invalid_and_duplicate_records(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let layout = layout()?;
        let address = p2pkh(0x73);
        let bound = bound_directory(&layout, address, 0);
        let plan = layout.event_plan(&bound, 1)?;

        let wrong_owner_page = AddressEventPage::real(
            plan.directory_identity,
            plan.ordinal.0,
            event(p2pkh(0x74), 0x75),
        )?;
        let mut wrong_owner = [ProbeRead::Miss; EVENT_PROBES];
        wrong_owner[0] =
            ProbeRead::Found(PersistentAddressEventPage::from_business(&wrong_owner_page));
        assert!(matches!(
            layout.scan_event(&plan, wrong_owner),
            Err(LayoutCorruption::EventOwnerMismatch)
        ));

        let mut dummy = [ProbeRead::Miss; EVENT_PROBES];
        dummy[0] = ProbeRead::Found(PersistentAddressEventPage::from_business(
            &AddressEventPage::dummy(),
        ));
        assert!(matches!(
            layout.scan_event(&plan, dummy),
            Err(LayoutCorruption::FoundEventDummy)
        ));

        let mut invalid = [ProbeRead::Miss; EVENT_PROBES];
        invalid[0] = ProbeRead::Found(PersistentAddressEventPage::default());
        assert!(matches!(
            layout.scan_event(&plan, invalid),
            Err(LayoutCorruption::InvalidEventRecord)
        ));

        let mut nonowner = [ProbeRead::Miss; EVENT_PROBES];
        nonowner[0] = ProbeRead::Found(event_nonowner_for_slot(&layout, plan.slots[0]));
        assert!(matches!(
            layout.scan_event(&plan, nonowner),
            Err(LayoutCorruption::EventProbeOwnershipMismatch)
        ));

        let out_of_range_directory =
            AddressEventPage::real(layout.directory.0.capacity, 0, event(address, 0x75))?;
        let mut invalid_directory = [ProbeRead::Miss; EVENT_PROBES];
        invalid_directory[0] = ProbeRead::Found(PersistentAddressEventPage::from_business(
            &out_of_range_directory,
        ));
        assert!(matches!(
            layout.scan_event(&plan, invalid_directory),
            Err(LayoutCorruption::EventDirectoryIdentityOutOfRange)
        ));

        let out_of_range_ordinal =
            AddressEventPage::real(0, layout.max_events_per_address, event(address, 0x75))?;
        let mut invalid_ordinal = [ProbeRead::Miss; EVENT_PROBES];
        invalid_ordinal[0] = ProbeRead::Found(PersistentAddressEventPage::from_business(
            &out_of_range_ordinal,
        ));
        assert!(matches!(
            layout.scan_event(&plan, invalid_ordinal),
            Err(LayoutCorruption::EventOrdinalOutOfRange)
        ));

        let matching_page = AddressEventPage::real(
            plan.directory_identity,
            plan.ordinal.0,
            event(address, 0x76),
        )?;
        let persistent = PersistentAddressEventPage::from_business(&matching_page);
        let mut duplicate = [ProbeRead::Miss; EVENT_PROBES];
        duplicate[0] = ProbeRead::Found(persistent);
        duplicate[1] = ProbeRead::Found(persistent);
        assert!(matches!(
            layout.scan_event(&plan, duplicate),
            Err(LayoutCorruption::DuplicateEventIdentity)
        ));
        Ok(())
    }

    #[test]
    fn event_scan_completes_fixed_work_before_reporting_late_corruption(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let layout = layout()?;
        let address = p2pkh(0x77);
        let bound = bound_directory(&layout, address, 0);
        let plan = layout.event_plan(&bound, 0)?;
        let matching = AddressEventPage::real(
            plan.directory_identity,
            plan.ordinal.0,
            event(address, 0x78),
        )?;
        let mut reads = [ProbeRead::Miss; EVENT_PROBES];
        reads[0] = ProbeRead::Found(PersistentAddressEventPage::from_business(&matching));
        reads[EVENT_PROBES - 1] = ProbeRead::Found(PersistentAddressEventPage::from_business(
            &AddressEventPage::dummy(),
        ));

        let outcome = layout.scan_event_inner(&plan, reads);
        assert!(matches!(
            outcome.result,
            Err(LayoutCorruption::FoundEventDummy)
        ));
        assert_eq!(
            outcome.work,
            ScanWork {
                observations: EVENT_PROBES,
                owner_probe_slots: EVENT_PROBES * EVENT_PROBES,
                identity_bindings: EVENT_PROBES,
                duplicate_comparisons: EVENT_PROBES * EVENT_PROBES,
            }
        );
        Ok(())
    }

    #[test]
    fn event_scan_work_is_identical_for_miss_match_and_duplicate(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let layout = layout()?;
        let address = p2pkh(0x7e);
        let bound = bound_directory(&layout, address, 0);
        let plan = layout.event_plan(&bound, 0)?;
        let miss = layout.scan_event_inner(&plan, [ProbeRead::Miss; EVENT_PROBES]);

        let page = AddressEventPage::real(
            plan.directory_identity,
            plan.ordinal.0,
            event(address, 0x7f),
        )?;
        let persistent = ProbeRead::Found(PersistentAddressEventPage::from_business(&page));
        let mut matching = [ProbeRead::Miss; EVENT_PROBES];
        matching[EVENT_PROBES - 1] = persistent;
        let matching = layout.scan_event_inner(&plan, matching);

        let mut duplicate = [ProbeRead::Miss; EVENT_PROBES];
        duplicate[0] = persistent;
        duplicate[1] = persistent;
        let duplicate = layout.scan_event_inner(&plan, duplicate);

        assert_eq!(miss.work, matching.work);
        assert_eq!(miss.work, duplicate.work);
        assert!(miss.result.is_ok());
        assert!(matching.result.is_ok());
        assert!(matches!(
            duplicate.result,
            Err(LayoutCorruption::DuplicateEventIdentity)
        ));
        Ok(())
    }

    #[test]
    fn complete_clean_event_scan_prepares_only_owner_bound_noncover_insert(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let layout = layout()?;
        let address = p2sh(0x79);
        let bound = bound_directory(&layout, address, 2);
        let plan = layout.event_plan(&bound, 3)?;
        let scan = layout.scan_event(&plan, [ProbeRead::Miss; EVENT_PROBES])?;
        let inserted_event = event(address, 0x7a);
        let prepared = layout.prepare_event_insert(scan, inserted_event, 0)?;
        let (backend_index, persistent) = layout.backend_event_insert(prepared)?;
        assert_eq!(
            backend_index,
            usize::try_from(plan.slots[0].0).expect("u32 test slot fits the host index")
        );
        let page = persistent.into_business()?;
        assert_eq!(page.directory_slot(), bound.slot.0);
        assert_eq!(page.event_ordinal(), 3);
        assert_eq!(page.event(), Some(&inserted_event));

        let stale_plan = layout.event_plan(&bound, 4)?;
        let stale_scan = layout.scan_event(&stale_plan, [ProbeRead::Miss; EVENT_PROBES])?;
        let stale_prepared = layout.prepare_event_insert(stale_scan, event(address, 0x7b), 0)?;
        let replacement = layout_with(LayoutNetwork::Mainnet, 1, 7, 12, [0x5a; 32], 8, 6, 16, 12)?;
        assert!(matches!(
            replacement.event_plan(&bound, 0),
            Err(LayoutPlanError::DirectoryProfileMismatch)
        ));
        assert!(matches!(
            replacement.backend_event_insert(stale_prepared),
            Err(MutationPlanError::PreparedProfileMismatch {
                table: TableKind::Event
            })
        ));

        let admission_plan = layout.event_plan(&bound, 5)?;
        let admission_scan = layout.scan_event(&admission_plan, [ProbeRead::Miss; EVENT_PROBES])?;
        assert!(matches!(
            layout.prepare_event_insert(admission_scan, event(address, 0x7b), 12),
            Err(MutationPlanError::AdmissionLimitReached {
                table: TableKind::Event
            })
        ));

        let wrong_plan = layout.event_plan(&bound, 6)?;
        let wrong_scan = layout.scan_event(&wrong_plan, [ProbeRead::Miss; EVENT_PROBES])?;
        assert!(matches!(
            layout.prepare_event_insert(wrong_scan, event(p2sh(0x7b), 0x7c), 0),
            Err(MutationPlanError::EventOwnerMismatch)
        ));

        let cover = layout.cover_event_plan(0)?;
        let cover_scan = layout.scan_event(&cover, [ProbeRead::Miss; EVENT_PROBES])?;
        assert!(matches!(
            layout.prepare_event_insert(cover_scan, event(p2pkh(0), 0x7d), 0),
            Err(MutationPlanError::CoverPlanNotInsertable)
        ));
        Ok(())
    }

    #[test]
    fn sensitive_layout_debug_and_errors_are_identifier_free(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let layout = layout()?;
        let plan = layout.directory_plan(p2pkh(0xab));
        let scan = layout.scan_directory(&plan, [ProbeRead::Miss; DIRECTORY_PROBES])?;
        let formatted = [
            format!("{layout:?}"),
            format!("{:?}", layout.identity),
            format!("{:?}", layout.identity.seed),
            format!("{plan:?}"),
            format!("{scan:?}"),
            format!("{:?}", LayoutCorruption::EventOwnerMismatch),
        ];
        for value in formatted {
            assert!(!value.contains("5a5a"));
            assert!(!value.contains("abab"));
            assert!(!value.contains(&plan.slots[0].0.to_string()));
        }
        assert_eq!(format!("{:?}", plan.slots[0]), "DirectorySlot([REDACTED])");
        assert_eq!(
            format!("{:?}", EventOrdinal(0x5151)),
            "EventOrdinal([REDACTED])"
        );
        Ok(())
    }
}
