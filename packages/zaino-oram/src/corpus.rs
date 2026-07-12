use std::{
    collections::{BTreeMap, HashMap},
    fmt,
    mem::size_of,
};

use crate::{
    records::{AddressKey, PersistentTransparentUtxo, TransparentUtxo},
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

#[derive(Clone, Copy, Default, PartialEq, Eq)]
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

/// Stateful, genesis-forward accumulator whose emitted report contains only
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

    /// Consumes all identifier-bearing state and produces an aggregate report.
    pub(super) fn finish(
        self,
        growth: GrowthAssumption,
        sizing: SizingParameters,
    ) -> Result<CorpusReport, CorpusError> {
        let mut events_per_address = BTreeMap::new();
        let mut live_utxos_per_address = BTreeMap::new();
        let mut peak_live_utxos_per_address = BTreeMap::new();
        let mut event_counts = Vec::with_capacity(self.addresses.len());
        let mut live_counts = Vec::with_capacity(self.addresses.len());
        let mut peak_counts = Vec::with_capacity(self.addresses.len());

        for stats in self.addresses.values() {
            increment_histogram(&mut events_per_address, stats.events)?;
            increment_histogram(&mut live_utxos_per_address, stats.live_utxos)?;
            increment_histogram(&mut peak_live_utxos_per_address, stats.peak_live_utxos)?;
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
        let projections = build_projections(
            &events_per_address,
            growth,
            sizing,
            distinct_standard_addresses,
        )?;

        Ok(CorpusReport {
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
            event_distribution,
            live_distribution,
            peak_live_distribution,
            hottest_event_counts,
            record_sizes: CandidateRecordSizes::compiled(sizing.event_record_bytes()),
            growth,
            sizing,
            projections,
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
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
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

/// Compiled and configured record widths included in every corpus report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CandidateRecordSizes {
    address_key_bytes: u64,
    business_utxo_bytes: u64,
    persistent_utxo_bytes: u64,
    logical_store_slot_bytes: u64,
    configured_event_record_bytes: u64,
}

impl CandidateRecordSizes {
    fn compiled(configured_event_record_bytes: u64) -> Self {
        Self {
            address_key_bytes: size_of::<AddressKey>() as u64,
            business_utxo_bytes: size_of::<TransparentUtxo>() as u64,
            persistent_utxo_bytes: size_of::<PersistentTransparentUtxo>() as u64,
            logical_store_slot_bytes: size_of::<StoreSlot>() as u64,
            configured_event_record_bytes,
        }
    }
}

/// One identifier-free current or projected storage point.
#[derive(Clone, Copy, PartialEq, Eq)]
struct CorpusProjection {
    year: u16,
    standard_addresses: u64,
    estimate: StorageEstimate,
}

impl fmt::Debug for CorpusProjection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CorpusProjection { aggregates_only: true, .. }")
    }
}

/// Aggregate-only output of a complete genesis-forward corpus scan.
///
/// This type cannot expose address, transaction, or outpoint identifiers: it
/// owns only counts, distributions, record widths, and modeled projections.
pub(super) struct CorpusReport {
    blocks: u64,
    transactions: u64,
    outputs: u64,
    spends: u64,
    distinct_standard_addresses: u64,
    live_standard_utxos: u64,
    live_nonstandard_utxos: u64,
    script_totals: [ScriptClassTotals; 3],
    events_per_address: BTreeMap<u64, u64>,
    live_utxos_per_address: BTreeMap<u64, u64>,
    peak_live_utxos_per_address: BTreeMap<u64, u64>,
    event_distribution: DistributionSummary,
    live_distribution: DistributionSummary,
    peak_live_distribution: DistributionSummary,
    hottest_event_counts: [u64; HOTTEST_TAIL_SLOTS],
    record_sizes: CandidateRecordSizes,
    growth: GrowthAssumption,
    sizing: SizingParameters,
    projections: Vec<CorpusProjection>,
}

impl CorpusReport {
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

    fn projections(&self) -> &[CorpusProjection] {
        &self.projections
    }
}

impl fmt::Debug for CorpusReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CorpusReport { aggregates_only: true, .. }")
    }
}

impl fmt::Display for CorpusReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "schema=oram-corpus-v1\naggregate_only=true\nblocks={}\ntransactions={}\noutputs={}\nspends={}\ndistinct_standard_addresses={}\nlive_standard_utxos={}\nlive_nonstandard_utxos={}\n",
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
        write_distribution(f, "event_distribution", self.event_distribution)?;
        write_distribution(f, "live_distribution", self.live_distribution)?;
        write_distribution(f, "peak_live_distribution", self.peak_live_distribution)?;
        write_array(f, "hottest_event_counts", &self.hottest_event_counts)?;
        writeln!(
            f,
            "record_sizes=address_key:{},business_utxo:{},persistent_utxo:{},logical_store_slot:{},configured_event:{}",
            self.record_sizes.address_key_bytes,
            self.record_sizes.business_utxo_bytes,
            self.record_sizes.persistent_utxo_bytes,
            self.record_sizes.logical_store_slot_bytes,
            self.record_sizes.configured_event_record_bytes,
        )?;
        writeln!(
            f,
            "growth_assumption=horizon_years:{},annual_growth_bps:{}",
            self.growth.horizon_years, self.growth.annual_growth_bps,
        )?;
        write!(f, "{}", self.sizing)?;
        for projection in &self.projections {
            writeln!(
                f,
                "projection=year:{},standard_addresses:{},events:{},pages:{},modeled_bytes:{},usable_memory_bytes:{},fits_memory:{}",
                projection.year,
                projection.standard_addresses,
                projection.estimate.event_count(),
                projection.estimate.page_count(),
                projection.estimate.backend_expanded_bytes(),
                projection.estimate.usable_memory_bytes(),
                projection.estimate.fits_memory(),
            )?;
        }
        Ok(())
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
            | Self::GrowthHorizonTooLarge { .. } => None,
        }
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
        SizingParameters::new(2, 16, 32, 4, 20_000, 1_000_000, 3_000)
    }

    fn growth() -> Result<GrowthAssumption, CorpusError> {
        GrowthAssumption::new(2, 1_000)
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

        let report = accumulator.finish(growth()?, sizing()?)?;
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
        assert_eq!(report.projections().len(), 3);

        let output = report.to_string();
        assert!(output.contains("aggregate_only=true"));
        assert!(output.contains("hottest_event_counts=2,1"));
        assert!(output.contains(
            "sizing_parameters=events_per_page:2,event_record_bytes:72,page_overhead_bytes:16,directory_entry_bytes:32,position_map_entry_bytes:4,backend_expansion_bps:20000,tdx_memory_bytes:1000000,required_headroom_bps:3000"
        ));
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
        let report = accumulator.finish(GrowthAssumption::new(0, 0)?, sizing()?)?;

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
        let report = accumulator.finish(GrowthAssumption::new(0, 0)?, sizing()?)?;
        assert_eq!(
            format!("{report:?}"),
            "CorpusReport { aggregates_only: true, .. }"
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
