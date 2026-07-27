use std::{
    collections::{BTreeMap, HashMap},
    fmt,
    mem::size_of,
};

use serde::{Deserialize, Serialize};

use crate::{
    records::{
        AddressKey, PersistentAddressDirectory, PersistentAddressEventPage,
        PersistentTransparentUtxo, PersistentUtxoEvent, TransparentUtxo,
    },
    sizing::{SizingError, SizingParameters, StorageEstimate},
    store::StoreSlot,
};

const BASIS_POINTS_DENOMINATOR: u64 = 10_000;
const HOTTEST_TAIL_SLOTS: usize = 16;
const MAX_GROWTH_YEARS: u16 = 100;

/// Standard transparent script classes plus the lossy non-standard category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(super) enum CorpusScriptClass {
    PayToPublicKeyHash,
    PayToScriptHash,
    NonStandard,
}

impl CorpusScriptClass {
    const fn index(self) -> usize {
        match self {
            Self::PayToPublicKeyHash => 0,
            Self::PayToScriptHash => 1,
            Self::NonStandard => 2,
        }
    }
}

/// Exact identity of a standard transparent address inside the offline scan.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub(super) struct CorpusAddress {
    script_hash: [u8; 20],
    script_class: CorpusScriptClass,
}

impl CorpusAddress {
    pub(super) const fn new(
        script_hash: [u8; 20],
        script_class: CorpusScriptClass,
    ) -> Option<Self> {
        match script_class {
            CorpusScriptClass::PayToPublicKeyHash | CorpusScriptClass::PayToScriptHash => {
                Some(Self {
                    script_hash,
                    script_class,
                })
            }
            CorpusScriptClass::NonStandard => None,
        }
    }

    const fn script_class(self) -> CorpusScriptClass {
        self.script_class
    }
}

impl fmt::Debug for CorpusAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CorpusAddress([REDACTED])")
    }
}

/// Transparent outpoint identity retained only while accumulating aggregates.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub(super) struct CorpusOutpoint {
    txid: [u8; 32],
    output_index: u32,
}

impl CorpusOutpoint {
    pub(super) const fn new(txid: [u8; 32], output_index: u32) -> Self {
        Self { txid, output_index }
    }
}

impl fmt::Debug for CorpusOutpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CorpusOutpoint([REDACTED])")
    }
}

/// One transparent event consumed by the aggregate-only scanner.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum CorpusEvent {
    Created {
        outpoint: CorpusOutpoint,
        address: Option<CorpusAddress>,
        script_class: CorpusScriptClass,
    },
    Spent {
        previous: CorpusOutpoint,
    },
}

impl fmt::Debug for CorpusEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CorpusEvent { ..REDACTED.. }")
    }
}

#[derive(Clone, Copy, Default, PartialEq, Eq)]
struct AddressStats {
    events: u64,
    outputs: u64,
    spends: u64,
    live_utxos: u64,
    peak_live_utxos: u64,
}

#[derive(Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScriptClassTotals {
    outputs: u64,
    spends: u64,
    live_utxos: u64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum LiveOutputOwner {
    Standard(CorpusAddress),
    NonStandard,
}

/// Stateful, genesis-forward accumulator whose emitted measurement contains only
/// identifier-free aggregate values.
pub(super) struct CorpusAccumulator {
    blocks: u64,
    transactions: u64,
    outputs: u64,
    spends: u64,
    addresses: HashMap<CorpusAddress, AddressStats>,
    live_outputs: HashMap<CorpusOutpoint, LiveOutputOwner>,
    script_totals: [ScriptClassTotals; 3],
}

impl CorpusAccumulator {
    /// Starts an exact scan with no pre-existing UTXOs. Callers must feed the
    /// canonical chain from genesis; an unknown spent outpoint fails closed.
    pub(super) fn from_genesis() -> Self {
        Self {
            blocks: 0,
            transactions: 0,
            outputs: 0,
            spends: 0,
            addresses: HashMap::new(),
            live_outputs: HashMap::new(),
            script_totals: [ScriptClassTotals::default(); 3],
        }
    }

    /// Records one public block boundary and its transaction count.
    pub(super) fn record_block(&mut self, transactions: u64) -> Result<(), CorpusError> {
        let next_blocks = checked_add(self.blocks, 1, CounterQuantity::Blocks)?;
        let next_transactions = checked_add(
            self.transactions,
            transactions,
            CounterQuantity::Transactions,
        )?;
        self.blocks = next_blocks;
        self.transactions = next_transactions;
        Ok(())
    }

    /// Applies one event without emitting or formatting its identifiers.
    pub(super) fn apply(&mut self, event: CorpusEvent) -> Result<(), CorpusError> {
        match event {
            CorpusEvent::Created {
                outpoint,
                address,
                script_class,
            } => self.apply_created(outpoint, address, script_class),
            CorpusEvent::Spent { previous } => self.apply_spent(previous),
        }
    }

    fn apply_created(
        &mut self,
        outpoint: CorpusOutpoint,
        address: Option<CorpusAddress>,
        script_class: CorpusScriptClass,
    ) -> Result<(), CorpusError> {
        if self.live_outputs.contains_key(&outpoint) {
            return Err(CorpusError::DuplicateCreatedOutpoint);
        }
        if address.is_some_and(|address| address.script_class() != script_class)
            || (address.is_none() && script_class != CorpusScriptClass::NonStandard)
        {
            return Err(CorpusError::AddressClassMismatch);
        }

        let next_outputs = checked_add(self.outputs, 1, CounterQuantity::Outputs)?;
        let script_index = script_class.index();
        let mut next_script_totals = self.script_totals[script_index];
        next_script_totals.outputs = checked_add(
            next_script_totals.outputs,
            1,
            CounterQuantity::ScriptOutputs,
        )?;
        next_script_totals.live_utxos = checked_add(
            next_script_totals.live_utxos,
            1,
            CounterQuantity::ScriptLiveUtxos,
        )?;

        let owner = match address {
            Some(address) => {
                let current = self.addresses.get(&address).copied().unwrap_or_default();
                let next = AddressStats {
                    events: checked_add(current.events, 1, CounterQuantity::AddressEvents)?,
                    outputs: checked_add(current.outputs, 1, CounterQuantity::AddressOutputs)?,
                    spends: current.spends,
                    live_utxos: checked_add(
                        current.live_utxos,
                        1,
                        CounterQuantity::AddressLiveUtxos,
                    )?,
                    peak_live_utxos: current.peak_live_utxos.max(checked_add(
                        current.live_utxos,
                        1,
                        CounterQuantity::AddressPeakLiveUtxos,
                    )?),
                };
                self.addresses.insert(address, next);
                LiveOutputOwner::Standard(address)
            }
            None => LiveOutputOwner::NonStandard,
        };

        self.outputs = next_outputs;
        self.script_totals[script_index] = next_script_totals;
        self.live_outputs.insert(outpoint, owner);
        Ok(())
    }

    fn apply_spent(&mut self, previous: CorpusOutpoint) -> Result<(), CorpusError> {
        let owner = self
            .live_outputs
            .get(&previous)
            .copied()
            .ok_or(CorpusError::UnknownSpentOutpoint)?;
        let script_class = match owner {
            LiveOutputOwner::Standard(address) => address.script_class(),
            LiveOutputOwner::NonStandard => CorpusScriptClass::NonStandard,
        };
        let script_index = script_class.index();
        let mut next_script_totals = self.script_totals[script_index];
        next_script_totals.spends =
            checked_add(next_script_totals.spends, 1, CounterQuantity::ScriptSpends)?;
        next_script_totals.live_utxos = next_script_totals
            .live_utxos
            .checked_sub(1)
            .ok_or(CorpusError::LiveUtxoUnderflow)?;
        let next_spends = checked_add(self.spends, 1, CounterQuantity::Spends)?;

        if let LiveOutputOwner::Standard(address) = owner {
            let current = self
                .addresses
                .get(&address)
                .copied()
                .ok_or(CorpusError::MissingAddressState)?;
            let next = AddressStats {
                events: checked_add(current.events, 1, CounterQuantity::AddressEvents)?,
                outputs: current.outputs,
                spends: checked_add(current.spends, 1, CounterQuantity::AddressSpends)?,
                live_utxos: current
                    .live_utxos
                    .checked_sub(1)
                    .ok_or(CorpusError::LiveUtxoUnderflow)?,
                peak_live_utxos: current.peak_live_utxos,
            };
            self.addresses.insert(address, next);
        }

        self.spends = next_spends;
        self.script_totals[script_index] = next_script_totals;
        self.live_outputs.remove(&previous);
        Ok(())
    }

    /// Consumes all identifier-bearing state and produces aggregate measurements.
    pub(super) fn finish(self) -> Result<CorpusMeasurement, CorpusError> {
        let mut events_per_address = BTreeMap::new();
        let mut live_utxos_per_address = BTreeMap::new();
        let mut peak_live_utxos_per_address = BTreeMap::new();
        let mut address_state_counts = BTreeMap::new();
        let mut event_counts = Vec::with_capacity(self.addresses.len());
        let mut live_counts = Vec::with_capacity(self.addresses.len());
        let mut peak_counts = Vec::with_capacity(self.addresses.len());

        for stats in self.addresses.values() {
            increment_histogram(&mut events_per_address, stats.events)?;
            increment_histogram(&mut live_utxos_per_address, stats.live_utxos)?;
            increment_histogram(&mut peak_live_utxos_per_address, stats.peak_live_utxos)?;
            increment_address_state(&mut address_state_counts, *stats)?;
            event_counts.push(stats.events);
            live_counts.push(stats.live_utxos);
            peak_counts.push(stats.peak_live_utxos);
        }

        event_counts.sort_unstable();
        live_counts.sort_unstable();
        peak_counts.sort_unstable();
        let event_distribution = DistributionSummary::from_sorted(&event_counts);
        let live_distribution = DistributionSummary::from_sorted(&live_counts);
        let peak_live_distribution = DistributionSummary::from_sorted(&peak_counts);
        let hottest_event_counts = hottest_tail(&event_counts);

        let distinct_standard_addresses =
            u64::try_from(self.addresses.len()).map_err(|_| CorpusError::CounterOverflow {
                quantity: CounterQuantity::DistinctAddresses,
            })?;
        let live_standard_utxos = self.script_totals[0]
            .live_utxos
            .checked_add(self.script_totals[1].live_utxos)
            .ok_or(CorpusError::CounterOverflow {
                quantity: CounterQuantity::StandardLiveUtxos,
            })?;
        let live_nonstandard_utxos = self.script_totals[2].live_utxos;
        Ok(CorpusMeasurement {
            blocks: self.blocks,
            transactions: self.transactions,
            outputs: self.outputs,
            spends: self.spends,
            distinct_standard_addresses,
            live_standard_utxos,
            live_nonstandard_utxos,
            script_totals: self.script_totals,
            events_per_address,
            live_utxos_per_address,
            peak_live_utxos_per_address,
            address_state_histogram: address_state_counts
                .into_iter()
                .map(
                    |((events, live_utxos, peak_live_utxos), address_count)| AddressStateBucket {
                        events,
                        live_utxos,
                        peak_live_utxos,
                        address_count,
                    },
                )
                .collect(),
            event_distribution,
            live_distribution,
            peak_live_distribution,
            hottest_event_counts,
            record_sizes: CandidateRecordSizes::compiled(),
        })
    }
}

/// Conservative proportional-growth assumption for capacity planning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct GrowthAssumption {
    horizon_years: u16,
    annual_growth_bps: u64,
}

impl GrowthAssumption {
    pub(super) const fn new(
        horizon_years: u16,
        annual_growth_bps: u64,
    ) -> Result<Self, CorpusError> {
        if horizon_years > MAX_GROWTH_YEARS {
            return Err(CorpusError::GrowthHorizonTooLarge {
                requested: horizon_years,
                maximum: MAX_GROWTH_YEARS,
            });
        }
        Ok(Self {
            horizon_years,
            annual_growth_bps,
        })
    }
}

/// Aggregate quantiles without retaining the address at any rank.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DistributionSummary {
    p50: u64,
    p90: u64,
    p99: u64,
    p999: u64,
    maximum: u64,
}

impl DistributionSummary {
    fn from_sorted(sorted: &[u64]) -> Self {
        Self {
            p50: nearest_rank(sorted, 5_000),
            p90: nearest_rank(sorted, 9_000),
            p99: nearest_rank(sorted, 9_900),
            p999: nearest_rank(sorted, 9_990),
            maximum: sorted.last().copied().unwrap_or(0),
        }
    }
}

/// Compiled record widths included in every corpus measurement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CandidateRecordSizes {
    address_key_bytes: u64,
    business_utxo_bytes: u64,
    persistent_utxo_bytes: u64,
    persistent_event_bytes: u64,
    logical_store_slot_bytes: u64,
    directory_cell_bytes: u64,
    event_cell_bytes: u64,
}

/// One identifier-free joint address-state bucket retained for exact validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AddressStateBucket {
    events: u64,
    live_utxos: u64,
    peak_live_utxos: u64,
    address_count: u64,
}

impl CandidateRecordSizes {
    fn compiled() -> Self {
        Self {
            address_key_bytes: size_of::<AddressKey>() as u64,
            business_utxo_bytes: size_of::<TransparentUtxo>() as u64,
            persistent_utxo_bytes: size_of::<PersistentTransparentUtxo>() as u64,
            persistent_event_bytes: size_of::<PersistentUtxoEvent>() as u64,
            logical_store_slot_bytes: size_of::<StoreSlot>() as u64,
            directory_cell_bytes: size_of::<PersistentAddressDirectory>() as u64,
            event_cell_bytes: size_of::<PersistentAddressEventPage>() as u64,
        }
    }
}

/// One identifier-free current or projected storage point.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct CorpusProjection {
    year: u16,
    standard_addresses: u64,
    estimate: StorageEstimate,
}

impl fmt::Debug for CorpusProjection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CorpusProjection { aggregates_only: true, .. }")
    }
}

#[cfg(feature = "corpus-zaino")]
impl CorpusProjection {
    pub(super) const fn year(&self) -> u16 {
        self.year
    }

    pub(super) const fn estimate(&self) -> &StorageEstimate {
        &self.estimate
    }
}

/// Aggregate-only output of a complete genesis-forward corpus scan.
///
/// This type cannot expose address, transaction, or outpoint identifiers: it
/// owns only observed counts, distributions, and compiled record widths.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CorpusMeasurement {
    blocks: u64,
    transactions: u64,
    outputs: u64,
    spends: u64,
    distinct_standard_addresses: u64,
    live_standard_utxos: u64,
    live_nonstandard_utxos: u64,
    script_totals: [ScriptClassTotals; 3],
    #[serde(with = "histogram_serde")]
    events_per_address: BTreeMap<u64, u64>,
    #[serde(with = "histogram_serde")]
    live_utxos_per_address: BTreeMap<u64, u64>,
    #[serde(with = "histogram_serde")]
    peak_live_utxos_per_address: BTreeMap<u64, u64>,
    address_state_histogram: Vec<AddressStateBucket>,
    event_distribution: DistributionSummary,
    live_distribution: DistributionSummary,
    peak_live_distribution: DistributionSummary,
    hottest_event_counts: [u64; HOTTEST_TAIL_SLOTS],
    record_sizes: CandidateRecordSizes,
}

impl CorpusMeasurement {
    #[cfg(feature = "corpus-zaino")]
    pub(super) const fn block_count(&self) -> u64 {
        self.blocks
    }

    #[cfg(feature = "corpus-zaino")]
    pub(super) const fn output_count(&self) -> u64 {
        self.outputs
    }

    pub(super) const fn distinct_standard_addresses(&self) -> u64 {
        self.distinct_standard_addresses
    }

    pub(super) const fn live_standard_utxos(&self) -> u64 {
        self.live_standard_utxos
    }

    pub(super) const fn live_nonstandard_utxos(&self) -> u64 {
        self.live_nonstandard_utxos
    }

    pub(super) const fn events_per_address(&self) -> &BTreeMap<u64, u64> {
        &self.events_per_address
    }

    const fn live_utxos_per_address(&self) -> &BTreeMap<u64, u64> {
        &self.live_utxos_per_address
    }

    pub(super) fn validate(&self) -> Result<(), CorpusError> {
        validate_measurement(self)
    }

    pub(super) fn qualify(
        &self,
        growth: GrowthAssumption,
        sizing: SizingParameters,
    ) -> Result<CorpusSizingQualification, CorpusError> {
        self.validate()?;
        let projections = build_projections(
            &self.events_per_address,
            growth,
            sizing,
            self.distinct_standard_addresses,
        )?;
        Ok(CorpusSizingQualification { projections })
    }
}

impl fmt::Debug for CorpusMeasurement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CorpusMeasurement { aggregates_only: true, .. }")
    }
}

impl fmt::Display for CorpusMeasurement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "schema=oram-corpus-measurement-v1\naggregate_only=true\nblocks={}\ntransactions={}\noutputs={}\nspends={}\ndistinct_standard_addresses={}\nlive_standard_utxos={}\nlive_nonstandard_utxos={}\n",
            self.blocks,
            self.transactions,
            self.outputs,
            self.spends,
            self.distinct_standard_addresses,
            self.live_standard_utxos,
            self.live_nonstandard_utxos,
        )?;
        write_script_totals(f, &self.script_totals)?;
        write_histogram(f, "events_per_address", &self.events_per_address)?;
        write_histogram(f, "live_utxos_per_address", &self.live_utxos_per_address)?;
        write_histogram(
            f,
            "peak_live_utxos_per_address",
            &self.peak_live_utxos_per_address,
        )?;
        write_address_state_histogram(f, &self.address_state_histogram)?;
        write_distribution(f, "event_distribution", self.event_distribution)?;
        write_distribution(f, "live_distribution", self.live_distribution)?;
        write_distribution(f, "peak_live_distribution", self.peak_live_distribution)?;
        write_array(f, "hottest_event_counts", &self.hottest_event_counts)?;
        writeln!(
            f,
            "record_sizes=address_key:{},business_utxo:{},persistent_utxo:{},persistent_event:{},logical_store_slot:{},directory_cell:{},event_cell:{}",
            self.record_sizes.address_key_bytes,
            self.record_sizes.business_utxo_bytes,
            self.record_sizes.persistent_utxo_bytes,
            self.record_sizes.persistent_event_bytes,
            self.record_sizes.logical_store_slot_bytes,
            self.record_sizes.directory_cell_bytes,
            self.record_sizes.event_cell_bytes,
        )?;
        Ok(())
    }
}

/// Operator-selected sizing assumptions and projections derived from one measurement.
pub(super) struct CorpusSizingQualification {
    projections: Vec<CorpusProjection>,
}

impl CorpusSizingQualification {
    pub(super) fn projections(&self) -> &[CorpusProjection] {
        &self.projections
    }
}

impl fmt::Debug for CorpusSizingQualification {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CorpusSizingQualification { aggregates_only: true, .. }")
    }
}

/// Aggregate scan or projection failure with no identifier-bearing fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CorpusError {
    DuplicateCreatedOutpoint,
    UnknownSpentOutpoint,
    AddressClassMismatch,
    MissingAddressState,
    LiveUtxoUnderflow,
    CounterOverflow { quantity: CounterQuantity },
    GrowthHorizonTooLarge { requested: u16, maximum: u16 },
    InvalidMeasurement { invariant: MeasurementInvariant },
    Sizing(SizingError),
}

impl fmt::Display for CorpusError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateCreatedOutpoint => {
                f.write_str("corpus contains a duplicate live created outpoint")
            }
            Self::UnknownSpentOutpoint => f.write_str(
                "corpus spend references an unknown outpoint; scan must start at genesis or use a complete seed",
            ),
            Self::AddressClassMismatch => {
                f.write_str("corpus event address and script classifications disagree")
            }
            Self::MissingAddressState => {
                f.write_str("corpus live output has no matching aggregate address state")
            }
            Self::LiveUtxoUnderflow => f.write_str("corpus live UTXO aggregate underflowed"),
            Self::CounterOverflow { quantity } => {
                write!(f, "corpus {} exceeds u64 capacity", quantity.description())
            }
            Self::GrowthHorizonTooLarge { requested, maximum } => write!(
                f,
                "growth horizon {requested} years exceeds the supported maximum {maximum}"
            ),
            Self::InvalidMeasurement { invariant } => {
                write!(f, "corpus measurement invariant failed: {invariant}")
            }
            Self::Sizing(error) => write!(f, "corpus sizing failed: {error}"),
        }
    }
}

impl std::error::Error for CorpusError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Sizing(error) => Some(error),
            Self::DuplicateCreatedOutpoint
            | Self::UnknownSpentOutpoint
            | Self::AddressClassMismatch
            | Self::MissingAddressState
            | Self::LiveUtxoUnderflow
            | Self::CounterOverflow { .. }
            | Self::GrowthHorizonTooLarge { .. }
            | Self::InvalidMeasurement { .. } => None,
        }
    }
}

/// Identifier-free semantic check for a persisted aggregate measurement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum MeasurementInvariant {
    HistogramShape,
    AddressStateHistogram,
    EventHistogramAddressCount,
    LiveHistogramAddressCount,
    PeakHistogramAddressCount,
    StandardLiveUtxos,
    ScriptTotals,
    ScriptClassBalance,
    OutputSpendBalance,
    StandardEventCount,
    EventDistribution,
    LiveDistribution,
    PeakDistribution,
    HottestEventCounts,
    AddressMarginals,
    RecordSizes,
}

impl fmt::Display for MeasurementInvariant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let description = match self {
            Self::HistogramShape => "histogram shape",
            Self::AddressStateHistogram => "joint address-state histogram",
            Self::EventHistogramAddressCount => "event histogram address count",
            Self::LiveHistogramAddressCount => "live histogram address count",
            Self::PeakHistogramAddressCount => "peak histogram address count",
            Self::StandardLiveUtxos => "standard live UTXO count",
            Self::ScriptTotals => "script totals",
            Self::ScriptClassBalance => "script-class output and spend balance",
            Self::OutputSpendBalance => "output and spend balance",
            Self::StandardEventCount => "standard event count",
            Self::EventDistribution => "event distribution",
            Self::LiveDistribution => "live distribution",
            Self::PeakDistribution => "peak distribution",
            Self::HottestEventCounts => "hottest event counts",
            Self::AddressMarginals => "per-address event, peak, and live marginals",
            Self::RecordSizes => "compiled record sizes",
        };
        f.write_str(description)
    }
}

/// Aggregate counter whose checked update overflowed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CounterQuantity {
    Blocks,
    Transactions,
    Outputs,
    Spends,
    ScriptOutputs,
    ScriptSpends,
    ScriptLiveUtxos,
    AddressEvents,
    AddressOutputs,
    AddressSpends,
    AddressLiveUtxos,
    AddressPeakLiveUtxos,
    DistinctAddresses,
    StandardLiveUtxos,
    HistogramBucket,
    ProjectedAddresses,
}

impl CounterQuantity {
    const fn description(self) -> &'static str {
        match self {
            Self::Blocks => "block count",
            Self::Transactions => "transaction count",
            Self::Outputs => "output count",
            Self::Spends => "spend count",
            Self::ScriptOutputs => "script-class output count",
            Self::ScriptSpends => "script-class spend count",
            Self::ScriptLiveUtxos => "script-class live UTXO count",
            Self::AddressEvents => "per-address event count",
            Self::AddressOutputs => "per-address output count",
            Self::AddressSpends => "per-address spend count",
            Self::AddressLiveUtxos => "per-address live UTXO count",
            Self::AddressPeakLiveUtxos => "per-address peak live UTXO count",
            Self::DistinctAddresses => "distinct-address count",
            Self::StandardLiveUtxos => "standard live UTXO count",
            Self::HistogramBucket => "histogram bucket count",
            Self::ProjectedAddresses => "projected address count",
        }
    }
}

fn checked_add(left: u64, right: u64, quantity: CounterQuantity) -> Result<u64, CorpusError> {
    left.checked_add(right)
        .ok_or(CorpusError::CounterOverflow { quantity })
}

fn increment_histogram(histogram: &mut BTreeMap<u64, u64>, value: u64) -> Result<(), CorpusError> {
    let current = histogram.get(&value).copied().unwrap_or(0);
    let next = checked_add(current, 1, CounterQuantity::HistogramBucket)?;
    histogram.insert(value, next);
    Ok(())
}

fn increment_address_state(
    histogram: &mut BTreeMap<(u64, u64, u64), u64>,
    stats: AddressStats,
) -> Result<(), CorpusError> {
    let state = (stats.events, stats.live_utxos, stats.peak_live_utxos);
    let current = histogram.get(&state).copied().unwrap_or(0);
    let next = checked_add(current, 1, CounterQuantity::HistogramBucket)?;
    histogram.insert(state, next);
    Ok(())
}

fn nearest_rank(sorted: &[u64], percentile_bps: u64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let length = sorted.len() as u128;
    let rank = (length * u128::from(percentile_bps))
        .div_ceil(u128::from(BASIS_POINTS_DENOMINATOR))
        .max(1);
    let index = usize::try_from(rank - 1)
        .unwrap_or(sorted.len() - 1)
        .min(sorted.len() - 1);
    sorted[index]
}

fn hottest_tail(sorted: &[u64]) -> [u64; HOTTEST_TAIL_SLOTS] {
    let mut tail = [0; HOTTEST_TAIL_SLOTS];
    for (target, value) in tail.iter_mut().zip(sorted.iter().rev()) {
        *target = *value;
    }
    tail
}

fn validate_measurement(measurement: &CorpusMeasurement) -> Result<(), CorpusError> {
    if !histogram_shape_is_valid(&measurement.events_per_address, false)
        || !histogram_shape_is_valid(&measurement.live_utxos_per_address, true)
        || !histogram_shape_is_valid(&measurement.peak_live_utxos_per_address, false)
    {
        return invalid_measurement(MeasurementInvariant::HistogramShape);
    }
    let Some([joint_events, joint_live, joint_peak]) =
        joint_address_state_marginals(&measurement.address_state_histogram)
    else {
        return invalid_measurement(MeasurementInvariant::AddressStateHistogram);
    };
    if joint_events != measurement.events_per_address
        || joint_live != measurement.live_utxos_per_address
        || joint_peak != measurement.peak_live_utxos_per_address
    {
        return invalid_measurement(MeasurementInvariant::AddressStateHistogram);
    }

    let address_count = u128::from(measurement.distinct_standard_addresses);
    if histogram_count(&measurement.events_per_address) != Some(address_count) {
        return invalid_measurement(MeasurementInvariant::EventHistogramAddressCount);
    }
    if histogram_count(&measurement.live_utxos_per_address) != Some(address_count) {
        return invalid_measurement(MeasurementInvariant::LiveHistogramAddressCount);
    }
    if histogram_count(&measurement.peak_live_utxos_per_address) != Some(address_count) {
        return invalid_measurement(MeasurementInvariant::PeakHistogramAddressCount);
    }
    if histogram_weighted_sum(&measurement.live_utxos_per_address)
        != Some(u128::from(measurement.live_standard_utxos))
    {
        return invalid_measurement(MeasurementInvariant::StandardLiveUtxos);
    }

    let output_total = measurement
        .script_totals
        .iter()
        .map(|totals| u128::from(totals.outputs))
        .sum::<u128>();
    let spend_total = measurement
        .script_totals
        .iter()
        .map(|totals| u128::from(totals.spends))
        .sum::<u128>();
    let standard_live = u128::from(measurement.script_totals[0].live_utxos)
        + u128::from(measurement.script_totals[1].live_utxos);
    if output_total != u128::from(measurement.outputs)
        || spend_total != u128::from(measurement.spends)
        || standard_live != u128::from(measurement.live_standard_utxos)
        || measurement.script_totals[2].live_utxos != measurement.live_nonstandard_utxos
    {
        return invalid_measurement(MeasurementInvariant::ScriptTotals);
    }
    if measurement
        .script_totals
        .iter()
        .any(|totals| totals.outputs.checked_sub(totals.spends) != Some(totals.live_utxos))
    {
        return invalid_measurement(MeasurementInvariant::ScriptClassBalance);
    }

    let live_total = u128::from(measurement.live_standard_utxos)
        + u128::from(measurement.live_nonstandard_utxos);
    if output_total.checked_sub(spend_total) != Some(live_total) {
        return invalid_measurement(MeasurementInvariant::OutputSpendBalance);
    }

    let standard_events = measurement.script_totals[..2]
        .iter()
        .map(|totals| u128::from(totals.outputs) + u128::from(totals.spends))
        .sum::<u128>();
    if histogram_weighted_sum(&measurement.events_per_address) != Some(standard_events) {
        return invalid_measurement(MeasurementInvariant::StandardEventCount);
    }
    if distribution_from_histogram(&measurement.events_per_address)
        != measurement.event_distribution
    {
        return invalid_measurement(MeasurementInvariant::EventDistribution);
    }
    if distribution_from_histogram(&measurement.live_utxos_per_address)
        != measurement.live_distribution
    {
        return invalid_measurement(MeasurementInvariant::LiveDistribution);
    }
    if distribution_from_histogram(&measurement.peak_live_utxos_per_address)
        != measurement.peak_live_distribution
    {
        return invalid_measurement(MeasurementInvariant::PeakDistribution);
    }
    if hottest_tail_from_histogram(&measurement.events_per_address)
        != measurement.hottest_event_counts
    {
        return invalid_measurement(MeasurementInvariant::HottestEventCounts);
    }
    let peak_sum = histogram_weighted_sum(&measurement.peak_live_utxos_per_address);
    let standard_outputs = measurement.script_totals[..2]
        .iter()
        .map(|totals| u128::from(totals.outputs))
        .sum::<u128>();
    if !histogram_values_are_bounded(
        &measurement.live_utxos_per_address,
        &measurement.peak_live_utxos_per_address,
    ) || !histogram_values_are_bounded(
        &measurement.peak_live_utxos_per_address,
        &measurement.events_per_address,
    ) || peak_sum.is_none_or(|peak_sum| peak_sum > standard_outputs)
        || histogram_parity_counts(&measurement.events_per_address)
            != histogram_parity_counts(&measurement.live_utxos_per_address)
    {
        return invalid_measurement(MeasurementInvariant::AddressMarginals);
    }
    if measurement.record_sizes != CandidateRecordSizes::compiled() {
        return invalid_measurement(MeasurementInvariant::RecordSizes);
    }
    Ok(())
}

fn joint_address_state_marginals(
    buckets: &[AddressStateBucket],
) -> Option<[BTreeMap<u64, u64>; 3]> {
    let mut marginals = std::array::from_fn(|_| BTreeMap::new());
    let mut previous = None;
    for bucket in buckets {
        let state = (bucket.events, bucket.live_utxos, bucket.peak_live_utxos);
        let valid_state = bucket.address_count != 0
            && bucket.events != 0
            && bucket.peak_live_utxos != 0
            && bucket.events >= bucket.live_utxos
            && (bucket.events - bucket.live_utxos) % 2 == 0
            && bucket.live_utxos <= bucket.peak_live_utxos
            && u128::from(bucket.peak_live_utxos) * 2
                <= u128::from(bucket.events) + u128::from(bucket.live_utxos)
            && previous.is_none_or(|previous| state > previous);
        if !valid_state {
            return None;
        }
        previous = Some(state);
        for (histogram, value) in
            marginals
                .iter_mut()
                .zip([bucket.events, bucket.live_utxos, bucket.peak_live_utxos])
        {
            let next = histogram
                .get(&value)
                .copied()
                .unwrap_or(0_u64)
                .checked_add(bucket.address_count)?;
            histogram.insert(value, next);
        }
    }
    Some(marginals)
}

fn histogram_shape_is_valid(histogram: &BTreeMap<u64, u64>, zero_value_allowed: bool) -> bool {
    histogram
        .iter()
        .all(|(value, count)| *count != 0 && (zero_value_allowed || *value != 0))
}

/// Returns whether two equally-sized marginal populations can be paired so
/// every value in `lower` is less than or equal to its value in `upper`.
fn histogram_values_are_bounded(lower: &BTreeMap<u64, u64>, upper: &BTreeMap<u64, u64>) -> bool {
    if histogram_count(lower) != histogram_count(upper) {
        return false;
    }

    let mut lower_cumulative = 0_u128;
    let mut upper_cumulative = 0_u128;
    let mut values = lower
        .keys()
        .chain(upper.keys())
        .copied()
        .collect::<Vec<_>>();
    values.sort_unstable();
    values.dedup();
    for value in values {
        lower_cumulative += u128::from(lower.get(&value).copied().unwrap_or(0));
        upper_cumulative += u128::from(upper.get(&value).copied().unwrap_or(0));
        if lower_cumulative < upper_cumulative {
            return false;
        }
    }
    true
}

fn invalid_measurement(invariant: MeasurementInvariant) -> Result<(), CorpusError> {
    Err(CorpusError::InvalidMeasurement { invariant })
}

fn histogram_count(histogram: &BTreeMap<u64, u64>) -> Option<u128> {
    histogram
        .values()
        .try_fold(0_u128, |total, count| total.checked_add(u128::from(*count)))
}

mod histogram_serde {
    use std::collections::BTreeMap;

    use serde::{
        de::Error as _, ser::SerializeSeq as _, Deserialize, Deserializer, Serialize, Serializer,
    };

    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct HistogramBucket {
        value: u64,
        count: u64,
    }

    pub(super) fn serialize<S>(
        histogram: &BTreeMap<u64, u64>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut sequence = serializer.serialize_seq(Some(histogram.len()))?;
        for (&value, &count) in histogram {
            sequence.serialize_element(&HistogramBucket { value, count })?;
        }
        sequence.end()
    }

    pub(super) fn deserialize<'de, D>(deserializer: D) -> Result<BTreeMap<u64, u64>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let buckets = Vec::<HistogramBucket>::deserialize(deserializer)?;
        let mut histogram = BTreeMap::new();
        let mut previous = None;
        for bucket in buckets {
            if bucket.count == 0 {
                return Err(D::Error::custom("histogram bucket count must be nonzero"));
            }
            if previous.is_some_and(|value| bucket.value <= value) {
                return Err(D::Error::custom(
                    "histogram bucket values must be strictly increasing",
                ));
            }
            previous = Some(bucket.value);
            histogram.insert(bucket.value, bucket.count);
        }
        Ok(histogram)
    }
}

fn histogram_weighted_sum(histogram: &BTreeMap<u64, u64>) -> Option<u128> {
    histogram.iter().try_fold(0_u128, |total, (value, count)| {
        let contribution = u128::from(*value).checked_mul(u128::from(*count))?;
        total.checked_add(contribution)
    })
}

fn histogram_parity_counts(histogram: &BTreeMap<u64, u64>) -> [u128; 2] {
    let mut counts = [0_u128; 2];
    for (value, count) in histogram {
        counts[usize::from(value % 2 != 0)] += u128::from(*count);
    }
    counts
}

fn distribution_from_histogram(histogram: &BTreeMap<u64, u64>) -> DistributionSummary {
    let total = histogram_count(histogram).unwrap_or(0);
    DistributionSummary {
        p50: nearest_rank_from_histogram(histogram, total, 5_000),
        p90: nearest_rank_from_histogram(histogram, total, 9_000),
        p99: nearest_rank_from_histogram(histogram, total, 9_900),
        p999: nearest_rank_from_histogram(histogram, total, 9_990),
        maximum: histogram
            .iter()
            .rev()
            .find_map(|(value, count)| (*count != 0).then_some(*value))
            .unwrap_or(0),
    }
}

fn nearest_rank_from_histogram(
    histogram: &BTreeMap<u64, u64>,
    total: u128,
    percentile_bps: u64,
) -> u64 {
    if total == 0 {
        return 0;
    }
    let rank = total
        .saturating_mul(u128::from(percentile_bps))
        .div_ceil(u128::from(BASIS_POINTS_DENOMINATOR))
        .max(1);
    let mut cumulative = 0_u128;
    for (value, count) in histogram {
        cumulative = cumulative.saturating_add(u128::from(*count));
        if cumulative >= rank {
            return *value;
        }
    }
    0
}

fn hottest_tail_from_histogram(histogram: &BTreeMap<u64, u64>) -> [u64; HOTTEST_TAIL_SLOTS] {
    let mut tail = [0; HOTTEST_TAIL_SLOTS];
    let mut index = 0_usize;
    for (value, count) in histogram.iter().rev() {
        let available = HOTTEST_TAIL_SLOTS.saturating_sub(index);
        let copies = u64::try_from(available).map_or(*count, |available| (*count).min(available));
        for _ in 0..copies {
            tail[index] = *value;
            index += 1;
        }
        if index == HOTTEST_TAIL_SLOTS {
            break;
        }
    }
    tail
}

fn build_projections(
    baseline_histogram: &BTreeMap<u64, u64>,
    growth: GrowthAssumption,
    sizing: SizingParameters,
    baseline_addresses: u64,
) -> Result<Vec<CorpusProjection>, CorpusError> {
    let mut projections = Vec::with_capacity(usize::from(growth.horizon_years) + 1);
    let mut histogram = baseline_histogram.clone();
    let mut address_count = baseline_addresses;

    for year in 0..=growth.horizon_years {
        let estimate = sizing
            .estimate(address_count, &histogram)
            .map_err(CorpusError::Sizing)?;
        projections.push(CorpusProjection {
            year,
            standard_addresses: address_count,
            estimate,
        });
        if year != growth.horizon_years {
            histogram = grow_histogram(&histogram, growth.annual_growth_bps)?;
            address_count = histogram.values().try_fold(0_u64, |total, count| {
                checked_add(total, *count, CounterQuantity::ProjectedAddresses)
            })?;
        }
    }
    Ok(projections)
}

fn grow_histogram(
    histogram: &BTreeMap<u64, u64>,
    annual_growth_bps: u64,
) -> Result<BTreeMap<u64, u64>, CorpusError> {
    histogram
        .iter()
        .map(|(&event_count, &address_count)| {
            let growth = u128::from(address_count)
                .checked_mul(u128::from(annual_growth_bps))
                .ok_or(CorpusError::CounterOverflow {
                    quantity: CounterQuantity::ProjectedAddresses,
                })?
                .div_ceil(u128::from(BASIS_POINTS_DENOMINATOR));
            let growth = u64::try_from(growth).map_err(|_| CorpusError::CounterOverflow {
                quantity: CounterQuantity::ProjectedAddresses,
            })?;
            let projected =
                checked_add(address_count, growth, CounterQuantity::ProjectedAddresses)?;
            Ok((event_count, projected))
        })
        .collect()
}

fn write_script_totals(f: &mut fmt::Formatter<'_>, totals: &[ScriptClassTotals; 3]) -> fmt::Result {
    for (name, totals) in ["p2pkh", "p2sh", "nonstandard"].into_iter().zip(totals) {
        writeln!(
            f,
            "script_class={name},outputs:{},spends:{},live_utxos:{}",
            totals.outputs, totals.spends, totals.live_utxos
        )?;
    }
    Ok(())
}

fn write_histogram(
    f: &mut fmt::Formatter<'_>,
    name: &str,
    histogram: &BTreeMap<u64, u64>,
) -> fmt::Result {
    write!(f, "{name}=")?;
    for (index, (value, count)) in histogram.iter().enumerate() {
        if index != 0 {
            f.write_str(",")?;
        }
        write!(f, "{value}:{count}")?;
    }
    f.write_str("\n")
}

fn write_address_state_histogram(
    f: &mut fmt::Formatter<'_>,
    buckets: &[AddressStateBucket],
) -> fmt::Result {
    f.write_str("address_state_histogram=")?;
    for (index, bucket) in buckets.iter().enumerate() {
        if index != 0 {
            f.write_str(",")?;
        }
        write!(
            f,
            "{}:{}:{}:{}",
            bucket.events, bucket.live_utxos, bucket.peak_live_utxos, bucket.address_count
        )?;
    }
    f.write_str("\n")
}

fn write_distribution(
    f: &mut fmt::Formatter<'_>,
    name: &str,
    distribution: DistributionSummary,
) -> fmt::Result {
    writeln!(
        f,
        "{name}=p50:{},p90:{},p99:{},p999:{},max:{}",
        distribution.p50,
        distribution.p90,
        distribution.p99,
        distribution.p999,
        distribution.maximum,
    )
}

fn write_array(f: &mut fmt::Formatter<'_>, name: &str, values: &[u64]) -> fmt::Result {
    write!(f, "{name}=")?;
    for (index, value) in values.iter().enumerate() {
        if index != 0 {
            f.write_str(",")?;
        }
        write!(f, "{value}")?;
    }
    f.write_str("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn address(byte: u8, class: CorpusScriptClass) -> CorpusAddress {
        CorpusAddress::new([byte; 20], class)
            .expect("standard test script class has an address identity")
    }

    fn outpoint(byte: u8, output_index: u32) -> CorpusOutpoint {
        CorpusOutpoint::new([byte; 32], output_index)
    }

    fn sizing() -> Result<SizingParameters, SizingError> {
        SizingParameters::new(8, 6, 16, 12, 8, 4, 20_000, 1_000_000, 3_000)
    }

    fn growth() -> Result<GrowthAssumption, CorpusError> {
        GrowthAssumption::new(2, 1_000)
    }

    #[test]
    fn growth_keeps_fixed_allocation_and_exposes_admission_crossings() -> Result<(), CorpusError> {
        let sizing = SizingParameters::new(8, 5, 16, 10, 3, 4, 10_000, 10_000, 0)
            .map_err(CorpusError::Sizing)?;
        let projections = build_projections(
            &BTreeMap::from([(1, 3)]),
            GrowthAssumption::new(2, 10_000)?,
            sizing,
            3,
        )?;

        assert_eq!(projections.len(), 3);
        assert!(projections[0].estimate.fits_modeled_constraints());
        assert!(!projections[1].estimate.fits_directory_admission());
        assert!(projections[1].estimate.fits_event_admission());
        assert!(!projections[2].estimate.fits_event_admission());
        assert_eq!(projections[0].estimate.maximum_events_per_address(), 1);
        assert_eq!(projections[2].estimate.maximum_events_per_address(), 1);
        assert!(projections.windows(2).all(|pair| {
            pair[0].estimate.allocated_table_bytes() == pair[1].estimate.allocated_table_bytes()
                && pair[0].estimate.logical_position_map_bytes()
                    == pair[1].estimate.logical_position_map_bytes()
                && pair[0].estimate.backend_expanded_bytes()
                    == pair[1].estimate.backend_expanded_bytes()
        }));
        Ok(())
    }

    #[test]
    fn create_and_spend_produce_exact_identifier_free_aggregates(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let first = outpoint(0x11, 0);
        let second = outpoint(0x22, 1);
        let p2pkh = address(0xaa, CorpusScriptClass::PayToPublicKeyHash);
        let p2sh = address(0xbb, CorpusScriptClass::PayToScriptHash);
        let mut accumulator = CorpusAccumulator::from_genesis();
        accumulator.record_block(2)?;
        accumulator.apply(CorpusEvent::Created {
            outpoint: first,
            address: Some(p2pkh),
            script_class: CorpusScriptClass::PayToPublicKeyHash,
        })?;
        accumulator.apply(CorpusEvent::Created {
            outpoint: second,
            address: Some(p2sh),
            script_class: CorpusScriptClass::PayToScriptHash,
        })?;
        accumulator.apply(CorpusEvent::Spent { previous: first })?;

        let report = accumulator.finish()?;
        report.validate()?;
        assert_eq!(report.distinct_standard_addresses(), 2);
        assert_eq!(report.live_standard_utxos(), 1);
        assert_eq!(
            report.events_per_address(),
            &BTreeMap::from([(1, 1), (2, 1)])
        );
        assert_eq!(
            report.live_utxos_per_address(),
            &BTreeMap::from([(0, 1), (1, 1)])
        );
        let qualification = report.qualify(growth()?, sizing()?)?;
        assert_eq!(qualification.projections().len(), 3);

        let output = report.to_string();
        assert_eq!(
            output,
            concat!(
                "schema=oram-corpus-measurement-v1\n",
                "aggregate_only=true\n",
                "blocks=1\n",
                "transactions=2\n",
                "outputs=2\n",
                "spends=1\n",
                "distinct_standard_addresses=2\n",
                "live_standard_utxos=1\n",
                "live_nonstandard_utxos=0\n",
                "script_class=p2pkh,outputs:1,spends:1,live_utxos:0\n",
                "script_class=p2sh,outputs:1,spends:0,live_utxos:1\n",
                "script_class=nonstandard,outputs:0,spends:0,live_utxos:0\n",
                "events_per_address=1:1,2:1\n",
                "live_utxos_per_address=0:1,1:1\n",
                "peak_live_utxos_per_address=1:2\n",
                "address_state_histogram=1:1:1:1,2:0:1:1\n",
                "event_distribution=p50:1,p90:2,p99:2,p999:2,max:2\n",
                "live_distribution=p50:0,p90:1,p99:1,p999:1,max:1\n",
                "peak_live_distribution=p50:1,p90:1,p99:1,p999:1,max:1\n",
                "hottest_event_counts=2,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0\n",
                "record_sizes=address_key:32,business_utxo:88,persistent_utxo:88,persistent_event:72,logical_store_slot:96,directory_cell:38,event_cell:82\n",
            )
        );
        assert!(!output.contains("growth_assumption"));
        assert!(!output.contains("tdx_memory_bytes"));
        assert!(!output.contains("projection="));
        assert!(!output.contains("11111111"));
        assert!(!output.contains("22222222"));
        assert!(!output.contains("aaaaaaaa"));
        assert!(!output.contains("bbbbbbbb"));
        Ok(())
    }

    #[test]
    fn nonstandard_outputs_are_counted_without_address_identity(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let previous = outpoint(0x33, 0);
        let mut accumulator = CorpusAccumulator::from_genesis();
        accumulator.record_block(1)?;
        accumulator.apply(CorpusEvent::Created {
            outpoint: previous,
            address: None,
            script_class: CorpusScriptClass::NonStandard,
        })?;
        let report = accumulator.finish()?;

        assert_eq!(report.distinct_standard_addresses(), 0);
        assert_eq!(report.live_standard_utxos(), 0);
        assert_eq!(report.live_nonstandard_utxos(), 1);
        assert_eq!(report.events_per_address(), &BTreeMap::new());
        Ok(())
    }

    #[test]
    fn duplicate_unknown_and_mismatched_events_fail_closed() -> Result<(), CorpusError> {
        let previous = outpoint(0x44, 0);
        let p2pkh = address(0xcc, CorpusScriptClass::PayToPublicKeyHash);
        let mut accumulator = CorpusAccumulator::from_genesis();
        assert_eq!(
            accumulator.apply(CorpusEvent::Spent { previous }),
            Err(CorpusError::UnknownSpentOutpoint)
        );
        accumulator.apply(CorpusEvent::Created {
            outpoint: previous,
            address: Some(p2pkh),
            script_class: CorpusScriptClass::PayToPublicKeyHash,
        })?;
        assert_eq!(
            accumulator.apply(CorpusEvent::Created {
                outpoint: previous,
                address: Some(p2pkh),
                script_class: CorpusScriptClass::PayToPublicKeyHash,
            }),
            Err(CorpusError::DuplicateCreatedOutpoint)
        );
        assert_eq!(
            CorpusAccumulator::from_genesis().apply(CorpusEvent::Created {
                outpoint: outpoint(0x55, 0),
                address: Some(p2pkh),
                script_class: CorpusScriptClass::PayToScriptHash,
            }),
            Err(CorpusError::AddressClassMismatch)
        );
        Ok(())
    }

    #[test]
    fn report_and_identifier_types_have_redacted_debug_output(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let previous = outpoint(0x66, 0);
        let address = address(0xdd, CorpusScriptClass::PayToPublicKeyHash);
        assert_eq!(format!("{previous:?}"), "CorpusOutpoint([REDACTED])");
        assert_eq!(format!("{address:?}"), "CorpusAddress([REDACTED])");
        assert_eq!(
            format!(
                "{:?}",
                CorpusEvent::Created {
                    outpoint: previous,
                    address: Some(address),
                    script_class: CorpusScriptClass::PayToPublicKeyHash,
                }
            ),
            "CorpusEvent { ..REDACTED.. }"
        );

        let mut accumulator = CorpusAccumulator::from_genesis();
        accumulator.apply(CorpusEvent::Created {
            outpoint: previous,
            address: Some(address),
            script_class: CorpusScriptClass::PayToPublicKeyHash,
        })?;
        let report = accumulator.finish()?;
        assert_eq!(
            format!("{report:?}"),
            "CorpusMeasurement { aggregates_only: true, .. }"
        );
        Ok(())
    }

    #[test]
    fn measurement_json_round_trip_is_deterministic_and_validated(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let previous = outpoint(0x77, 0);
        let address = address(0xee, CorpusScriptClass::PayToPublicKeyHash);
        let mut accumulator = CorpusAccumulator::from_genesis();
        accumulator.record_block(1)?;
        accumulator.apply(CorpusEvent::Created {
            outpoint: previous,
            address: Some(address),
            script_class: CorpusScriptClass::PayToPublicKeyHash,
        })?;
        let measurement = accumulator.finish()?;

        let json = serde_json::to_string(&measurement)?;
        let decoded: CorpusMeasurement = serde_json::from_str(&json)?;
        decoded.validate()?;

        assert_eq!(decoded, measurement);
        assert_eq!(serde_json::to_string(&decoded)?, json);
        assert!(json.contains("\"events_per_address\":[{\"value\":1,\"count\":1}]"));

        let duplicate_bucket = json.replace(
            "\"events_per_address\":[{\"value\":1,\"count\":1}]",
            "\"events_per_address\":[{\"value\":1,\"count\":1},{\"value\":1,\"count\":1}]",
        );
        assert!(serde_json::from_str::<CorpusMeasurement>(&duplicate_bucket).is_err());
        Ok(())
    }

    #[test]
    fn validation_rejects_per_class_balance_and_impossible_marginals(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let previous = outpoint(0x88, 0);
        let second = outpoint(0x89, 0);
        let address = address(0xff, CorpusScriptClass::PayToPublicKeyHash);
        let mut accumulator = CorpusAccumulator::from_genesis();
        accumulator.record_block(1)?;
        accumulator.apply(CorpusEvent::Created {
            outpoint: previous,
            address: Some(address),
            script_class: CorpusScriptClass::PayToPublicKeyHash,
        })?;
        accumulator.apply(CorpusEvent::Created {
            outpoint: second,
            address: Some(address),
            script_class: CorpusScriptClass::PayToPublicKeyHash,
        })?;
        accumulator.apply(CorpusEvent::Spent { previous })?;
        let measurement = accumulator.finish()?;

        let mut invalid_balance = measurement.clone();
        invalid_balance.script_totals[0].live_utxos = 0;
        invalid_balance.script_totals[1].live_utxos = 1;
        assert!(matches!(
            invalid_balance.validate(),
            Err(CorpusError::InvalidMeasurement {
                invariant: MeasurementInvariant::ScriptClassBalance,
            })
        ));

        let mut impossible_marginals = measurement;
        impossible_marginals.peak_live_utxos_per_address = BTreeMap::from([(3, 1)]);
        impossible_marginals.address_state_histogram = vec![AddressStateBucket {
            events: 3,
            live_utxos: 1,
            peak_live_utxos: 3,
            address_count: 1,
        }];
        impossible_marginals.peak_live_distribution =
            distribution_from_histogram(&impossible_marginals.peak_live_utxos_per_address);
        assert!(matches!(
            impossible_marginals.validate(),
            Err(CorpusError::InvalidMeasurement {
                invariant: MeasurementInvariant::AddressStateHistogram,
            })
        ));
        assert_ne!(
            histogram_parity_counts(&BTreeMap::from([(1, 2)])),
            histogram_parity_counts(&BTreeMap::from([(0, 1), (2, 1)])),
        );
        Ok(())
    }

    #[test]
    fn nearest_rank_and_growth_are_deterministic_and_bounded() -> Result<(), CorpusError> {
        let sorted = [1, 2, 3, 4, 100];
        let summary = DistributionSummary::from_sorted(&sorted);
        assert_eq!(summary.p50, 3);
        assert_eq!(summary.p90, 100);
        assert_eq!(summary.maximum, 100);
        assert_eq!(
            GrowthAssumption::new(MAX_GROWTH_YEARS + 1, 0),
            Err(CorpusError::GrowthHorizonTooLarge {
                requested: MAX_GROWTH_YEARS + 1,
                maximum: MAX_GROWTH_YEARS,
            })
        );
        let projected = grow_histogram(&BTreeMap::from([(2, 10)]), 1_000)?;
        assert_eq!(projected, BTreeMap::from([(2, 11)]));
        Ok(())
    }
}
