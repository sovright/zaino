use std::fmt;

use serde::{Deserialize, Serialize};
use zaino_state::{
    extract_transparent_events, IndexedBlock, ScriptType, TransparentBlockEvent,
    TransparentEventError,
};

use crate::{
    canonical_chain::{
        CanonicalBlockCursor, CanonicalChainError, CanonicalNetwork, PublicChainCheckpoint,
    },
    corpus::{
        CorpusAccumulator, CorpusAddress, CorpusError, CorpusEvent, CorpusMeasurement,
        CorpusOutpoint, CorpusScriptClass, CorpusSizingQualification, GrowthAssumption,
    },
    sizing::{SizingParameters, StorageEstimate},
};

/// Aggregate measurement paired with its public canonical-chain checkpoint.
pub(super) struct ZainoCorpusMeasurement {
    checkpoint: PublicChainCheckpoint,
    aggregate: CorpusMeasurement,
}

impl fmt::Debug for ZainoCorpusMeasurement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ZainoCorpusMeasurement { public_checkpoint: true, aggregates_only: true, .. }")
    }
}

impl fmt::Display for ZainoCorpusMeasurement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "network={}", self.checkpoint.network())?;
        writeln!(f, "final_height={}", self.checkpoint.height())?;
        writeln!(
            f,
            "final_hash={}",
            self.checkpoint.block_hash().to_rpc_hex()
        )?;
        write!(f, "{}", self.aggregate)
    }
}

/// Validated growth and sizing inputs applied to a captured mainnet measurement.
///
/// Every value is supplied explicitly by the operator. This research API does
/// not guess privacy-profile or target-TDX constants.
#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
pub struct MainnetSizingModel {
    growth_horizon_years: u16,
    annual_growth_bps: u64,
    directory_capacity: u64,
    directory_admission_limit: u64,
    event_capacity: u64,
    event_admission_limit: u64,
    max_events_per_address: u64,
    position_map_entry_bytes: u64,
    backend_expansion_bps: u64,
    tdx_memory_bytes: u64,
    required_headroom_bps: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MainnetSizingModelDto {
    growth_horizon_years: u16,
    annual_growth_bps: u64,
    directory_capacity: u64,
    directory_admission_limit: u64,
    event_capacity: u64,
    event_admission_limit: u64,
    max_events_per_address: u64,
    position_map_entry_bytes: u64,
    backend_expansion_bps: u64,
    tdx_memory_bytes: u64,
    required_headroom_bps: u64,
}

impl MainnetSizingModel {
    /// Validates the complete aggregate growth and logical-storage model.
    #[expect(
        clippy::too_many_arguments,
        reason = "the sizing model validates every operator-selected capacity dimension together"
    )]
    pub fn new(
        growth_horizon_years: u16,
        annual_growth_bps: u64,
        directory_capacity: u64,
        directory_admission_limit: u64,
        event_capacity: u64,
        event_admission_limit: u64,
        max_events_per_address: u64,
        position_map_entry_bytes: u64,
        backend_expansion_bps: u64,
        tdx_memory_bytes: u64,
        required_headroom_bps: u64,
    ) -> Result<Self, MainnetCorpusError> {
        let model = Self {
            growth_horizon_years,
            annual_growth_bps,
            directory_capacity,
            directory_admission_limit,
            event_capacity,
            event_admission_limit,
            max_events_per_address,
            position_map_entry_bytes,
            backend_expansion_bps,
            tdx_memory_bytes,
            required_headroom_bps,
        };
        model.parts()?;
        Ok(model)
    }

    /// Revalidates every operator-selected model input.
    pub fn validate(&self) -> Result<(), MainnetCorpusError> {
        self.parts().map(|_| ())
    }

    /// Returns the configured directory-table capacity.
    pub const fn directory_capacity(&self) -> u64 {
        self.directory_capacity
    }

    /// Returns the configured directory-table admission limit.
    pub const fn directory_admission_limit(&self) -> u64 {
        self.directory_admission_limit
    }

    /// Returns the configured event-table capacity.
    pub const fn event_capacity(&self) -> u64 {
        self.event_capacity
    }

    /// Returns the configured event-table admission limit.
    pub const fn event_admission_limit(&self) -> u64 {
        self.event_admission_limit
    }

    /// Returns the configured per-address event limit.
    pub const fn max_events_per_address(&self) -> u64 {
        self.max_events_per_address
    }

    fn parts(&self) -> Result<(GrowthAssumption, SizingParameters), MainnetCorpusError> {
        let growth = GrowthAssumption::new(self.growth_horizon_years, self.annual_growth_bps)
            .map_err(ZainoCorpusError::Aggregate)?;
        let sizing = SizingParameters::new(
            self.directory_capacity,
            self.directory_admission_limit,
            self.event_capacity,
            self.event_admission_limit,
            self.max_events_per_address,
            self.position_map_entry_bytes,
            self.backend_expansion_bps,
            self.tdx_memory_bytes,
            self.required_headroom_bps,
        )
        .map_err(CorpusError::Sizing)
        .map_err(ZainoCorpusError::Aggregate)?;
        Ok((growth, sizing))
    }

    fn directory_admission_bps(&self) -> u128 {
        u128::from(self.directory_admission_limit) * 10_000 / u128::from(self.directory_capacity)
    }

    fn event_admission_bps(&self) -> u128 {
        u128::from(self.event_admission_limit) * 10_000 / u128::from(self.event_capacity)
    }
}

impl<'de> Deserialize<'de> for MainnetSizingModel {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let dto = MainnetSizingModelDto::deserialize(deserializer)?;
        Self::new(
            dto.growth_horizon_years,
            dto.annual_growth_bps,
            dto.directory_capacity,
            dto.directory_admission_limit,
            dto.event_capacity,
            dto.event_admission_limit,
            dto.max_events_per_address,
            dto.position_map_entry_bytes,
            dto.backend_expansion_bps,
            dto.tdx_memory_bytes,
            dto.required_headroom_bps,
        )
        .map_err(serde::de::Error::custom)
    }
}

impl fmt::Debug for MainnetSizingModel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MainnetSizingModel { aggregate_parameters: true, .. }")
    }
}

/// Incremental, genesis-forward mainnet scanner for the non-published corpus
/// runner.
///
/// The scanner does not retain blocks. It necessarily retains public-chain
/// address and outpoint identities while resolving spends, then consumes that
/// state into an identifier-free [`MainnetCorpusMeasurement`].
pub struct MainnetCorpusScanner {
    inner: ZainoCorpusScanner,
}

impl MainnetCorpusScanner {
    /// Starts an empty scanner bound to the canonical mainnet genesis hash.
    pub fn new() -> Self {
        Self {
            inner: ZainoCorpusScanner::new(CanonicalNetwork::Mainnet),
        }
    }

    /// Applies one canonical indexed block without retaining the block.
    pub fn push(&mut self, block: &IndexedBlock) -> Result<(), MainnetCorpusError> {
        self.inner.push(block).map_err(Into::into)
    }

    /// Consumes all identifier-bearing scan state and returns aggregates only.
    pub fn finish(self) -> Result<MainnetCorpusMeasurement, MainnetCorpusError> {
        self.inner
            .finish()
            .map(MainnetCorpusMeasurement::from_zaino)
            .map_err(Into::into)
    }
}

impl fmt::Debug for MainnetCorpusScanner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MainnetCorpusScanner { identifiers: [REDACTED], .. }")
    }
}

impl Default for MainnetCorpusScanner {
    fn default() -> Self {
        Self::new()
    }
}

/// Primitive public checkpoint stored with every mainnet corpus measurement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MainnetCorpusCheckpoint {
    network: String,
    height: u32,
    hash: String,
}

impl MainnetCorpusCheckpoint {
    fn from_public(checkpoint: PublicChainCheckpoint) -> Self {
        Self {
            network: checkpoint.network().to_string(),
            height: checkpoint.height(),
            hash: checkpoint.block_hash().to_rpc_hex(),
        }
    }

    /// Returns the fixed public mainnet height.
    pub const fn height(&self) -> u32 {
        self.height
    }

    /// Returns the lowercase RPC-order block hash.
    pub fn hash(&self) -> &str {
        &self.hash
    }

    fn is_valid(&self) -> bool {
        self.network == "mainnet"
            && self.hash.len() == 64
            && self
                .hash
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    }
}

/// Identifier-free measured aggregates bound to a public mainnet checkpoint.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct MainnetCorpusMeasurement {
    checkpoint: MainnetCorpusCheckpoint,
    aggregate: CorpusMeasurement,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MainnetCorpusMeasurementDto {
    checkpoint: MainnetCorpusCheckpoint,
    aggregate: CorpusMeasurement,
}

impl<'de> Deserialize<'de> for MainnetCorpusMeasurement {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let dto = MainnetCorpusMeasurementDto::deserialize(deserializer)?;
        let measurement = Self {
            checkpoint: dto.checkpoint,
            aggregate: dto.aggregate,
        };
        measurement.validate().map_err(serde::de::Error::custom)?;
        Ok(measurement)
    }
}

impl MainnetCorpusMeasurement {
    fn from_zaino(inner: ZainoCorpusMeasurement) -> Self {
        Self {
            checkpoint: MainnetCorpusCheckpoint::from_public(inner.checkpoint),
            aggregate: inner.aggregate,
        }
    }

    /// Returns the verified public checkpoint for this measurement.
    pub const fn checkpoint(&self) -> &MainnetCorpusCheckpoint {
        &self.checkpoint
    }

    pub(super) const fn output_count(&self) -> u64 {
        self.aggregate.output_count()
    }

    /// Revalidates every redundant aggregate field after deserialization.
    pub fn validate(&self) -> Result<(), MainnetCorpusError> {
        let expected_blocks = u64::from(self.checkpoint.height) + 1;
        let genesis_hash_is_valid = self.checkpoint.height != 0
            || self.checkpoint.hash == CanonicalNetwork::Mainnet.genesis_hash().to_rpc_hex();
        if !self.checkpoint.is_valid()
            || !genesis_hash_is_valid
            || self.aggregate.block_count() != expected_blocks
        {
            return Err(ZainoCorpusError::InvalidMainnetMeasurement.into());
        }
        self.aggregate
            .validate()
            .map_err(ZainoCorpusError::Aggregate)
            .map_err(Into::into)
    }

    /// Applies explicit operator sizing assumptions without rescanning the chain.
    pub fn apply_model(
        &self,
        model: &MainnetSizingModel,
    ) -> Result<MainnetSizingQualification, MainnetCorpusError> {
        self.validate()?;
        let (growth, sizing) = model.parts()?;
        let aggregate = self
            .aggregate
            .qualify(growth, sizing)
            .map_err(ZainoCorpusError::Aggregate)?;
        Ok(MainnetSizingQualification::new(
            self.checkpoint.clone(),
            *model,
            sizing,
            &aggregate,
        ))
    }
}

impl fmt::Debug for MainnetCorpusMeasurement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(
            "MainnetCorpusMeasurement { public_checkpoint: true, aggregates_only: true, .. }",
        )
    }
}

impl fmt::Display for MainnetCorpusMeasurement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "network={}", self.checkpoint.network)?;
        writeln!(f, "final_height={}", self.checkpoint.height)?;
        writeln!(f, "final_hash={}", self.checkpoint.hash)?;
        self.aggregate.fmt(f)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum LoadBasisPointRounding {
    Floor,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MainnetSizingEvidence {
    insertion_bound: bool,
    backend_calibrated: bool,
    rss_measured: bool,
    load_bps_rounding: LoadBasisPointRounding,
    load_bps_capped: bool,
}

impl MainnetSizingEvidence {
    const fn modeled_only() -> Self {
        Self {
            insertion_bound: false,
            backend_calibrated: false,
            rss_measured: false,
            load_bps_rounding: LoadBasisPointRounding::Floor,
            load_bps_capped: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MainnetSizingRecordBytes {
    directory_cell_bytes: u64,
    event_cell_bytes: u64,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MainnetSizingProjection {
    year: u16,
    standard_addresses: u64,
    events: u64,
    max_events_per_address: u64,
    #[serde(with = "u128_decimal")]
    directory_load_bps: u128,
    #[serde(with = "u128_decimal")]
    event_load_bps: u128,
    allocated_directory_bytes: u64,
    allocated_event_bytes: u64,
    allocated_table_bytes: u64,
    logical_position_map_bytes: u64,
    logical_total_bytes: u64,
    backend_expanded_bytes: u64,
    usable_memory_bytes: u64,
    fits_directory_admission: bool,
    fits_event_admission: bool,
    fits_address_event_limit: bool,
    fits_configured_limits: bool,
    fits_modeled_memory: bool,
    fits_modeled_constraints: bool,
}

impl MainnetSizingProjection {
    fn from_estimate(year: u16, estimate: &StorageEstimate) -> Self {
        Self {
            year,
            standard_addresses: estimate.address_count(),
            events: estimate.event_count(),
            max_events_per_address: estimate.maximum_events_per_address(),
            directory_load_bps: estimate.directory_load_bps(),
            event_load_bps: estimate.event_load_bps(),
            allocated_directory_bytes: estimate.allocated_directory_bytes(),
            allocated_event_bytes: estimate.allocated_event_bytes(),
            allocated_table_bytes: estimate.allocated_table_bytes(),
            logical_position_map_bytes: estimate.logical_position_map_bytes(),
            logical_total_bytes: estimate.logical_total_bytes(),
            backend_expanded_bytes: estimate.backend_expanded_bytes(),
            usable_memory_bytes: estimate.usable_memory_bytes(),
            fits_directory_admission: estimate.fits_directory_admission(),
            fits_event_admission: estimate.fits_event_admission(),
            fits_address_event_limit: estimate.fits_address_event_limit(),
            fits_configured_limits: estimate.fits_configured_limits(),
            fits_modeled_memory: estimate.fits_modeled_memory(),
            fits_modeled_constraints: estimate.fits_modeled_constraints(),
        }
    }
}

impl fmt::Debug for MainnetSizingProjection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MainnetSizingProjection { aggregates_only: true, .. }")
    }
}

/// Identifier-free sizing qualification derived from a measured mainnet corpus.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct MainnetSizingQualification {
    checkpoint: MainnetCorpusCheckpoint,
    model: MainnetSizingModel,
    compiled_record_bytes: MainnetSizingRecordBytes,
    evidence: MainnetSizingEvidence,
    projections: Vec<MainnetSizingProjection>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MainnetSizingQualificationDto {
    checkpoint: MainnetCorpusCheckpoint,
    model: MainnetSizingModel,
    compiled_record_bytes: MainnetSizingRecordBytes,
    evidence: MainnetSizingEvidence,
    projections: Vec<MainnetSizingProjection>,
}

impl MainnetSizingQualification {
    fn new(
        checkpoint: MainnetCorpusCheckpoint,
        model: MainnetSizingModel,
        sizing: SizingParameters,
        aggregate: &CorpusSizingQualification,
    ) -> Self {
        Self {
            checkpoint,
            model,
            compiled_record_bytes: MainnetSizingRecordBytes {
                directory_cell_bytes: sizing.directory_record_bytes(),
                event_cell_bytes: sizing.event_record_bytes(),
            },
            evidence: MainnetSizingEvidence::modeled_only(),
            projections: aggregate
                .projections()
                .iter()
                .map(|projection| {
                    MainnetSizingProjection::from_estimate(projection.year(), projection.estimate())
                })
                .collect(),
        }
    }

    /// Returns the measured checkpoint used for this sizing qualification.
    pub const fn checkpoint(&self) -> &MainnetCorpusCheckpoint {
        &self.checkpoint
    }

    /// Returns the explicit model applied to the captured measurement.
    pub const fn model(&self) -> &MainnetSizingModel {
        &self.model
    }

    pub(super) fn captured_corpus_fits_configured_limits(&self) -> bool {
        self.projections
            .first()
            .is_some_and(|projection| projection.year == 0 && projection.fits_configured_limits)
    }

    /// Revalidates the model, compiled widths, projection arithmetic, and
    /// identifier-free evidence flags after deserialization.
    ///
    /// This is structural validation only. Use [`Self::validate_against`] to
    /// prove that the rows were derived from a particular measurement.
    pub fn validate(&self) -> Result<(), MainnetCorpusError> {
        if !self.checkpoint.is_valid()
            || (self.checkpoint.height == 0
                && self.checkpoint.hash != CanonicalNetwork::Mainnet.genesis_hash().to_rpc_hex())
            || self.evidence != MainnetSizingEvidence::modeled_only()
        {
            return Err(ZainoCorpusError::InvalidMainnetSizingQualification.into());
        }
        let (_, sizing) = self.model.parts()?;
        if self.compiled_record_bytes
            != (MainnetSizingRecordBytes {
                directory_cell_bytes: sizing.directory_record_bytes(),
                event_cell_bytes: sizing.event_record_bytes(),
            })
            || self.projections.len() != usize::from(self.model.growth_horizon_years) + 1
        {
            return Err(ZainoCorpusError::InvalidMainnetSizingQualification.into());
        }

        let mut previous = None;
        for (index, projection) in self.projections.iter().enumerate() {
            let year = u16::try_from(index)
                .map_err(|_| ZainoCorpusError::InvalidMainnetSizingQualification)?;
            let expected = sizing
                .estimate_aggregates(
                    projection.standard_addresses,
                    projection.events,
                    projection.max_events_per_address,
                )
                .map_err(CorpusError::Sizing)
                .map_err(ZainoCorpusError::Aggregate)?;
            if projection.year != year
                || *projection != MainnetSizingProjection::from_estimate(year, &expected)
                || previous.is_some_and(|previous: &MainnetSizingProjection| {
                    projection.standard_addresses < previous.standard_addresses
                        || projection.events < previous.events
                        || projection.max_events_per_address != previous.max_events_per_address
                })
            {
                return Err(ZainoCorpusError::InvalidMainnetSizingQualification.into());
            }
            previous = Some(projection);
        }
        Ok(())
    }

    /// Recomputes this qualification from `measurement` and requires an exact
    /// match, including its checkpoint, model, evidence, and every projection.
    pub fn validate_against(
        &self,
        measurement: &MainnetCorpusMeasurement,
    ) -> Result<(), MainnetCorpusError> {
        self.validate()?;
        let expected = measurement.apply_model(&self.model)?;
        if *self == expected {
            Ok(())
        } else {
            Err(ZainoCorpusError::InvalidMainnetSizingQualification.into())
        }
    }
}

impl<'de> Deserialize<'de> for MainnetSizingQualification {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let dto = MainnetSizingQualificationDto::deserialize(deserializer)?;
        let qualification = Self {
            checkpoint: dto.checkpoint,
            model: dto.model,
            compiled_record_bytes: dto.compiled_record_bytes,
            evidence: dto.evidence,
            projections: dto.projections,
        };
        qualification.validate().map_err(serde::de::Error::custom)?;
        Ok(qualification)
    }
}

impl fmt::Debug for MainnetSizingQualification {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(
            "MainnetSizingQualification { public_checkpoint: true, aggregates_only: true, .. }",
        )
    }
}

impl fmt::Display for MainnetSizingQualification {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "network={}", self.checkpoint.network)?;
        writeln!(f, "final_height={}", self.checkpoint.height)?;
        writeln!(f, "final_hash={}", self.checkpoint.hash)?;
        writeln!(f, "schema=oram-corpus-sizing-v1")?;
        writeln!(
            f,
            "growth_assumption=horizon_years:{},annual_growth_bps:{}",
            self.model.growth_horizon_years, self.model.annual_growth_bps,
        )?;
        writeln!(
            f,
            "sizing_parameters=directory_capacity:{},directory_admission_limit:{},directory_admission_bps:{},directory_record_bytes:{},event_capacity:{},event_admission_limit:{},event_admission_bps:{},event_record_bytes:{},max_events_per_address:{},position_map_entry_bytes:{},backend_expansion_bps:{},tdx_memory_bytes:{},required_headroom_bps:{}",
            self.model.directory_capacity,
            self.model.directory_admission_limit,
            self.model.directory_admission_bps(),
            self.compiled_record_bytes.directory_cell_bytes,
            self.model.event_capacity,
            self.model.event_admission_limit,
            self.model.event_admission_bps(),
            self.compiled_record_bytes.event_cell_bytes,
            self.model.max_events_per_address,
            self.model.position_map_entry_bytes,
            self.model.backend_expansion_bps,
            self.model.tdx_memory_bytes,
            self.model.required_headroom_bps,
        )?;
        writeln!(
            f,
            "sizing_evidence=insertion_bound:false,backend_calibrated:false,rss_measured:false,load_bps_rounding:floor,load_bps_capped:false"
        )?;
        for projection in &self.projections {
            writeln!(
                f,
                "projection=year:{},standard_addresses:{},events:{},max_events_per_address:{},directory_load_bps:{},event_load_bps:{},allocated_directory_bytes:{},allocated_event_bytes:{},allocated_table_bytes:{},logical_position_map_bytes:{},logical_total_bytes:{},backend_expanded_bytes:{},usable_memory_bytes:{},fits_directory_admission:{},fits_event_admission:{},fits_address_event_limit:{},fits_configured_limits:{},fits_modeled_memory:{},fits_modeled_constraints:{}",
                projection.year,
                projection.standard_addresses,
                projection.events,
                projection.max_events_per_address,
                projection.directory_load_bps,
                projection.event_load_bps,
                projection.allocated_directory_bytes,
                projection.allocated_event_bytes,
                projection.allocated_table_bytes,
                projection.logical_position_map_bytes,
                projection.logical_total_bytes,
                projection.backend_expanded_bytes,
                projection.usable_memory_bytes,
                projection.fits_directory_admission,
                projection.fits_event_admission,
                projection.fits_address_event_limit,
                projection.fits_configured_limits,
                projection.fits_modeled_memory,
                projection.fits_modeled_constraints,
            )?;
        }
        Ok(())
    }
}

mod u128_decimal {
    use serde::{de::Error as _, Deserialize, Deserializer, Serializer};

    pub(super) fn serialize<S>(value: &u128, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&value.to_string())
    }

    pub(super) fn deserialize<'de, D>(deserializer: D) -> Result<u128, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        let value = encoded.parse::<u128>().map_err(D::Error::custom)?;
        if value.to_string() != encoded {
            return Err(D::Error::custom(
                "u128 decimal strings must use canonical unsigned encoding",
            ));
        }
        Ok(value)
    }
}

/// Redacted failure from mainnet model validation or corpus accumulation.
#[derive(Debug)]
pub struct MainnetCorpusError {
    inner: ZainoCorpusError,
}

impl From<ZainoCorpusError> for MainnetCorpusError {
    fn from(inner: ZainoCorpusError) -> Self {
        Self { inner }
    }
}

impl fmt::Display for MainnetCorpusError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.inner.fmt(f)
    }
}

impl std::error::Error for MainnetCorpusError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.inner)
    }
}

/// Scans canonical indexed blocks from genesis and emits only aggregate data.
///
/// The in-memory accumulator necessarily holds public-chain identifiers while
/// resolving spends. Its returned measurement owns no address, transaction, or
/// outpoint identity. A scan that starts after genesis fails on the first
/// unresolved previous outpoint unless a future complete seed API is used.
pub(super) fn scan_indexed_blocks<'a>(
    blocks: impl IntoIterator<Item = &'a IndexedBlock>,
    network: CanonicalNetwork,
) -> Result<ZainoCorpusMeasurement, ZainoCorpusError> {
    let mut scanner = ZainoCorpusScanner::new(network);
    for block in blocks {
        scanner.push(block)?;
    }
    scanner.finish()
}

/// Incremental adapter from canonical Zaino blocks to aggregate corpus state.
///
/// The adapter never retains an [`IndexedBlock`]. It retains only the previous
/// public checkpoint plus the identifier-bearing maps required to resolve
/// transparent spends. Those maps are consumed into an aggregate-only measurement
/// by [`Self::finish`].
struct ZainoCorpusScanner {
    cursor: CanonicalBlockCursor,
    accumulator: Option<CorpusAccumulator>,
}

impl ZainoCorpusScanner {
    fn new(network: CanonicalNetwork) -> Self {
        Self {
            cursor: CanonicalBlockCursor::new(network),
            accumulator: Some(CorpusAccumulator::from_genesis()),
        }
    }

    /// Validates and applies one canonical block without retaining it.
    ///
    /// Extraction and provenance failures happen before aggregate mutation and
    /// may be retried with corrected input. Once aggregate mutation begins, any
    /// failure consumes the accumulator and permanently poisons the scanner so
    /// partially applied state cannot be reused.
    fn push(&mut self, block: &IndexedBlock) -> Result<(), ZainoCorpusError> {
        if self.accumulator.is_none() {
            return Err(ZainoCorpusError::ScannerPoisoned);
        }

        let candidate = self
            .cursor
            .validate_next(block)
            .map_err(ZainoCorpusError::CanonicalChain)?;
        let height = candidate.checkpoint().height();
        let transaction_count = u64::try_from(block.transactions().len())
            .map_err(|_| ZainoCorpusError::TransactionCountOverflow { height })?;
        let events = extract_transparent_events(block).map_err(ZainoCorpusError::Extraction)?;

        let mut accumulator = self
            .accumulator
            .take()
            .ok_or(ZainoCorpusError::ScannerPoisoned)?;
        accumulator
            .record_block(transaction_count)
            .map_err(ZainoCorpusError::Aggregate)?;
        for event in events {
            apply_transparent_event(&mut accumulator, event)?;
        }

        let (cursor, _) = self
            .cursor
            .stage_advance(candidate)
            .map_err(ZainoCorpusError::CanonicalChain)?;
        self.accumulator = Some(accumulator);
        self.cursor = cursor;
        Ok(())
    }

    fn finish(self) -> Result<ZainoCorpusMeasurement, ZainoCorpusError> {
        let accumulator = self.accumulator.ok_or(ZainoCorpusError::ScannerPoisoned)?;
        let checkpoint = self
            .cursor
            .checkpoint()
            .ok_or(ZainoCorpusError::EmptyChain)?;
        let aggregate = accumulator.finish().map_err(ZainoCorpusError::Aggregate)?;
        Ok(ZainoCorpusMeasurement {
            checkpoint,
            aggregate,
        })
    }
}

fn apply_transparent_event(
    accumulator: &mut CorpusAccumulator,
    event: TransparentBlockEvent,
) -> Result<(), ZainoCorpusError> {
    let event = match event {
        TransparentBlockEvent::Created {
            outpoint,
            address,
            script_class,
            ..
        } => CorpusEvent::Created {
            outpoint: CorpusOutpoint::new(*outpoint.prev_txid(), outpoint.prev_index()),
            address: address.and_then(|address| {
                CorpusAddress::new(*address.hash(), map_script_class(script_class))
            }),
            script_class: map_script_class(script_class),
        },
        TransparentBlockEvent::Spent { previous, .. } => CorpusEvent::Spent {
            previous: CorpusOutpoint::new(*previous.prev_txid(), previous.prev_index()),
        },
    };
    accumulator
        .apply(event)
        .map_err(ZainoCorpusError::Aggregate)
}

const fn map_script_class(script_class: ScriptType) -> CorpusScriptClass {
    match script_class {
        ScriptType::P2PKH => CorpusScriptClass::PayToPublicKeyHash,
        ScriptType::P2SH => CorpusScriptClass::PayToScriptHash,
        ScriptType::NonStandard => CorpusScriptClass::NonStandard,
    }
}

/// Indexed-block extraction or aggregate scan failure with redacted identity.
#[derive(Debug)]
pub(super) enum ZainoCorpusError {
    EmptyChain,
    /// Aggregate mutation failed and the partial scanner state was discarded.
    ScannerPoisoned,
    InvalidMainnetMeasurement,
    InvalidMainnetSizingQualification,
    CanonicalChain(CanonicalChainError),
    /// One block contains more transactions than an aggregate `u64` can count.
    TransactionCountOverflow {
        /// Public block height containing the rejected count.
        height: u32,
    },
    /// Pure compact-event extraction rejected a fixed-domain value.
    Extraction(TransparentEventError),
    /// Aggregate accumulation or sizing failed.
    Aggregate(CorpusError),
}

impl fmt::Display for ZainoCorpusError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyChain => {
                f.write_str("corpus scan requires a nonempty genesis-forward chain")
            }
            Self::ScannerPoisoned => {
                f.write_str("corpus scanner cannot continue after an aggregate mutation failure")
            }
            Self::InvalidMainnetMeasurement => {
                f.write_str("mainnet corpus measurement failed semantic validation")
            }
            Self::InvalidMainnetSizingQualification => {
                f.write_str("mainnet corpus sizing qualification failed semantic validation")
            }
            Self::CanonicalChain(error) => {
                write!(f, "corpus canonical-chain validation failed: {error}")
            }
            Self::TransactionCountOverflow { height } => write!(
                f,
                "transaction count at public height {height} exceeds u64 capacity"
            ),
            Self::Extraction(error) => write!(f, "transparent event extraction failed: {error}"),
            Self::Aggregate(error) => write!(f, "aggregate corpus scan failed: {error}"),
        }
    }
}

impl std::error::Error for ZainoCorpusError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::CanonicalChain(error) => Some(error),
            Self::Extraction(error) => Some(error),
            Self::Aggregate(error) => Some(error),
            Self::EmptyChain
            | Self::ScannerPoisoned
            | Self::InvalidMainnetMeasurement
            | Self::InvalidMainnetSizingQualification
            | Self::TransactionCountOverflow { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use zaino_state::{AddrScript, IndexedBlock, Outpoint, ScriptType, TxInCompact, TxLocation};

    use crate::zaino_fixtures::{indexed_block, output, transaction};

    fn model(annual_growth_bps: u64) -> Result<MainnetSizingModel, MainnetCorpusError> {
        MainnetSizingModel::new(
            2,
            annual_growth_bps,
            8,
            6,
            16,
            12,
            8,
            4,
            20_000,
            1_000_000,
            3_000,
        )
    }

    fn mainnet_measurement() -> Result<MainnetCorpusMeasurement, Box<dyn std::error::Error>> {
        let mut accumulator = CorpusAccumulator::from_genesis();
        accumulator.record_block(1)?;
        accumulator.apply(CorpusEvent::Created {
            outpoint: CorpusOutpoint::new([0x44; 32], 0),
            address: CorpusAddress::new([0x55; 20], CorpusScriptClass::PayToPublicKeyHash),
            script_class: CorpusScriptClass::PayToPublicKeyHash,
        })?;
        Ok(MainnetCorpusMeasurement {
            checkpoint: MainnetCorpusCheckpoint {
                network: "mainnet".to_owned(),
                height: 0,
                hash: CanonicalNetwork::Mainnet.genesis_hash().to_rpc_hex(),
            },
            aggregate: accumulator.finish()?,
        })
    }

    fn fixture_genesis() -> Result<IndexedBlock, Box<dyn std::error::Error>> {
        let created_txid = [0x11; 32];
        let created = transaction(
            0,
            created_txid,
            vec![TxInCompact::null_prevout()],
            vec![
                output(50, [0xa1; 20], ScriptType::P2PKH)?,
                output(75, [0xb2; 20], ScriptType::NonStandard)?,
            ],
        );
        let same_block_spend = transaction(
            1,
            [0x22; 32],
            vec![TxInCompact::new(created_txid, 0)],
            vec![output(40, [0xc3; 20], ScriptType::P2SH)?],
        );
        indexed_block(
            0,
            CanonicalNetwork::Regtest.genesis_hash().0,
            [0; 32],
            vec![created, same_block_spend],
        )
    }

    fn fixture_second_block() -> Result<IndexedBlock, Box<dyn std::error::Error>> {
        let spend_and_create = transaction(
            0,
            [0x33; 32],
            vec![TxInCompact::new([0x22; 32], 0)],
            vec![output(30, [0xd4; 20], ScriptType::P2PKH)?],
        );
        indexed_block(
            1,
            [0x92; 32],
            CanonicalNetwork::Regtest.genesis_hash().0,
            vec![spend_and_create],
        )
    }

    #[test]
    fn network_labels_bind_canonical_genesis_hashes() {
        assert_eq!(
            CanonicalNetwork::Mainnet.genesis_hash().to_rpc_hex(),
            "00040fe8ec8471911baa1db1266ea15dd06b4a8a5c453883c000b031973dce08"
        );
        assert_eq!(
            CanonicalNetwork::Testnet.genesis_hash().to_rpc_hex(),
            "05a60a92d99d85997cce3b87616c089f6124d7342af37106edc76126334a2c38"
        );
        assert_eq!(
            CanonicalNetwork::Regtest.genesis_hash().to_rpc_hex(),
            "029f11d80ef9765602235e1bc9727e3eb6ba20839319f761fee920d63401e327"
        );
    }

    #[test]
    fn empty_scan_is_rejected_before_emitting_a_report() -> Result<(), Box<dyn std::error::Error>> {
        let result = scan_indexed_blocks(
            std::iter::empty::<&IndexedBlock>(),
            CanonicalNetwork::Mainnet,
        );

        assert!(matches!(result, Err(ZainoCorpusError::EmptyChain)));
        Ok(())
    }

    #[test]
    fn nonempty_canonical_fixture_runs_extraction_adapter_and_aggregate_report(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let genesis = fixture_genesis()?;
        let report = scan_indexed_blocks([&genesis], CanonicalNetwork::Regtest)?;
        let output = report.to_string();

        assert!(output.contains("network=regtest"));
        assert!(output.contains("final_height=0"));
        assert!(output.contains("blocks=1"));
        assert!(output.contains("transactions=2"));
        assert!(output.contains("outputs=3"));
        assert!(output.contains("spends=1"));
        assert_eq!(report.aggregate.distinct_standard_addresses(), 2);
        assert_eq!(report.aggregate.live_standard_utxos(), 1);
        assert_eq!(report.aggregate.live_nonstandard_utxos(), 1);
        assert_eq!(
            report.aggregate.events_per_address(),
            &BTreeMap::from([(1, 1), (2, 1)])
        );
        Ok(())
    }

    #[test]
    fn incremental_scanner_matches_iterator_helper_without_retaining_blocks(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let genesis = fixture_genesis()?;
        let second = fixture_second_block()?;
        let network = CanonicalNetwork::Regtest;
        let mut scanner = ZainoCorpusScanner::new(network);

        scanner.push(&genesis)?;
        scanner.push(&second)?;
        let incremental = scanner.finish()?;
        let iterator = scan_indexed_blocks([&genesis, &second], network)?;

        assert_eq!(incremental.to_string(), iterator.to_string());
        assert!(incremental.to_string().contains("final_height=1"));
        Ok(())
    }

    #[test]
    fn aggregate_mutation_failure_permanently_poisons_incremental_scanner(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let unknown_spend = transaction(
            0,
            [0x44; 32],
            vec![TxInCompact::new([0xff; 32], 0)],
            Vec::new(),
        );
        let invalid_genesis = indexed_block(
            0,
            CanonicalNetwork::Regtest.genesis_hash().0,
            [0; 32],
            vec![unknown_spend],
        )?;
        let mut scanner = ZainoCorpusScanner::new(CanonicalNetwork::Regtest);

        assert!(matches!(
            scanner.push(&invalid_genesis),
            Err(ZainoCorpusError::Aggregate(
                CorpusError::UnknownSpentOutpoint
            ))
        ));
        assert!(matches!(
            scanner.push(&invalid_genesis),
            Err(ZainoCorpusError::ScannerPoisoned)
        ));
        assert!(matches!(
            scanner.finish(),
            Err(ZainoCorpusError::ScannerPoisoned)
        ));
        Ok(())
    }

    #[test]
    fn chain_provenance_rejects_wrong_genesis_and_noncontiguous_parent(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let genesis = fixture_genesis()?;
        let wrong_genesis = scan_indexed_blocks([&genesis], CanonicalNetwork::Mainnet);
        assert!(matches!(
            wrong_genesis,
            Err(ZainoCorpusError::CanonicalChain(
                CanonicalChainError::GenesisHashMismatch
            ))
        ));

        let wrong_parent = indexed_block(1, [0x92; 32], [0xee; 32], Vec::new())?;
        let discontinuous =
            scan_indexed_blocks([&genesis, &wrong_parent], CanonicalNetwork::Regtest);
        assert!(matches!(
            discontinuous,
            Err(ZainoCorpusError::CanonicalChain(
                CanonicalChainError::ParentHashMismatch { height: 1 }
            ))
        ));
        Ok(())
    }

    #[test]
    fn provenance_rejection_can_retry_the_corrected_block() -> Result<(), Box<dyn std::error::Error>>
    {
        let wrong_genesis = indexed_block(0, [0xee; 32], [0; 32], Vec::new())?;
        let genesis = fixture_genesis()?;
        let mut scanner = ZainoCorpusScanner::new(CanonicalNetwork::Regtest);

        assert!(matches!(
            scanner.push(&wrong_genesis),
            Err(ZainoCorpusError::CanonicalChain(
                CanonicalChainError::GenesisHashMismatch,
            ))
        ));
        scanner.push(&genesis)?;
        assert!(scanner.finish()?.to_string().contains("final_height=0"));
        Ok(())
    }

    #[test]
    fn adapter_preserves_standard_and_nonstandard_aggregate_semantics(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let standard_outpoint = Outpoint::new([0x11; 32], 0);
        let nonstandard_outpoint = Outpoint::new([0x22; 32], 1);
        let mut accumulator = CorpusAccumulator::from_genesis();
        apply_transparent_event(
            &mut accumulator,
            TransparentBlockEvent::Created {
                location: TxLocation::new(1, 0),
                output_index: 0,
                outpoint: standard_outpoint,
                address: Some(AddrScript::new([0xaa; 20], ScriptType::P2PKH as u8)),
                value_zat: 50,
                script_class: ScriptType::P2PKH,
            },
        )?;
        apply_transparent_event(
            &mut accumulator,
            TransparentBlockEvent::Created {
                location: TxLocation::new(1, 0),
                output_index: 1,
                outpoint: nonstandard_outpoint,
                address: None,
                value_zat: 75,
                script_class: ScriptType::NonStandard,
            },
        )?;
        apply_transparent_event(
            &mut accumulator,
            TransparentBlockEvent::Spent {
                location: TxLocation::new(2, 0),
                input_index: 0,
                previous: standard_outpoint,
            },
        )?;

        let report = accumulator.finish()?;
        assert_eq!(report.distinct_standard_addresses(), 1);
        assert_eq!(report.live_standard_utxos(), 0);
        assert_eq!(report.live_nonstandard_utxos(), 1);
        assert_eq!(report.events_per_address(), &BTreeMap::from([(2, 1)]));
        Ok(())
    }

    #[test]
    fn public_measurement_round_trips_and_rejects_checkpoint_mismatches(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let measurement = mainnet_measurement()?;
        measurement.validate()?;

        let json = serde_json::to_vec(&measurement)?;
        let decoded: MainnetCorpusMeasurement = serde_json::from_slice(&json)?;
        decoded.validate()?;
        assert_eq!(decoded, measurement);

        let mut wrong_height = measurement.clone();
        wrong_height.checkpoint.height = 1;
        assert!(wrong_height.validate().is_err());
        assert!(
            serde_json::from_slice::<MainnetCorpusMeasurement>(&serde_json::to_vec(&wrong_height)?)
                .is_err()
        );

        let mut wrong_genesis = measurement;
        wrong_genesis.checkpoint.hash = "11".repeat(32);
        assert!(wrong_genesis.validate().is_err());
        assert!(
            serde_json::from_slice::<MainnetCorpusMeasurement>(&serde_json::to_vec(
                &wrong_genesis
            )?)
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn one_measurement_supports_multiple_offline_sizing_models(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let measurement = mainnet_measurement()?;
        let baseline_model = model(0)?;
        let baseline = measurement.apply_model(&baseline_model)?;
        let growth = measurement.apply_model(&model(1_000)?)?;

        assert_eq!(baseline.checkpoint(), measurement.checkpoint());
        assert_eq!(growth.checkpoint(), measurement.checkpoint());
        assert_ne!(baseline.to_string(), growth.to_string());
        assert!(baseline
            .to_string()
            .contains("schema=oram-corpus-sizing-v1\n"));

        let model_json = serde_json::to_vec(&baseline_model)?;
        assert_eq!(
            serde_json::from_slice::<MainnetSizingModel>(&model_json)?,
            baseline_model
        );
        let qualification_json = serde_json::to_vec(&baseline)?;
        let decoded: MainnetSizingQualification = serde_json::from_slice(&qualification_json)?;
        decoded.validate()?;
        assert_eq!(decoded, baseline);
        Ok(())
    }

    #[test]
    fn sizing_deserialization_rejects_invalid_models_and_derived_rows(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let measurement = mainnet_measurement()?;
        let qualification = measurement.apply_model(&model(1_000)?)?;

        let mut invalid_model = serde_json::to_value(model(0)?)?;
        invalid_model["directory_capacity"] = serde_json::json!(3);
        assert!(serde_json::from_value::<MainnetSizingModel>(invalid_model).is_err());

        let mut unknown_model_field = serde_json::to_value(model(0)?)?;
        unknown_model_field["unknown"] = serde_json::json!(1);
        assert!(serde_json::from_value::<MainnetSizingModel>(unknown_model_field).is_err());

        let mut missing_model_field = serde_json::to_value(model(0)?)?;
        let Some(model_fields) = missing_model_field.as_object_mut() else {
            panic!("serialized sizing model must be a JSON object");
        };
        model_fields.remove("event_capacity");
        assert!(serde_json::from_value::<MainnetSizingModel>(missing_model_field).is_err());

        let mut invalid_evidence = serde_json::to_value(&qualification)?;
        invalid_evidence["evidence"]["rss_measured"] = serde_json::json!(true);
        assert!(serde_json::from_value::<MainnetSizingQualification>(invalid_evidence).is_err());

        let mut invalid_projection = serde_json::to_value(&qualification)?;
        invalid_projection["projections"][0]["allocated_table_bytes"] = serde_json::json!(1);
        assert!(serde_json::from_value::<MainnetSizingQualification>(invalid_projection).is_err());

        let mut noncanonical_load = serde_json::to_value(&qualification)?;
        noncanonical_load["projections"][0]["directory_load_bps"] = serde_json::json!("0000");
        assert!(serde_json::from_value::<MainnetSizingQualification>(noncanonical_load).is_err());
        Ok(())
    }

    #[test]
    fn source_bound_validation_rejects_structurally_valid_fabricated_growth_rows(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let measurement = mainnet_measurement()?;
        let qualification = measurement.apply_model(&model(1_000)?)?;
        let mut fabricated = serde_json::to_value(&qualification)?;
        let Some(projections) = fabricated["projections"].as_array_mut() else {
            panic!("serialized sizing qualification must contain projection rows");
        };
        let year_zero = projections[0].clone();
        for (year, projection) in projections.iter_mut().enumerate().skip(1) {
            *projection = year_zero.clone();
            projection["year"] = serde_json::json!(year);
        }

        let fabricated: MainnetSizingQualification = serde_json::from_value(fabricated)?;
        fabricated.validate()?;
        assert!(fabricated.validate_against(&measurement).is_err());
        Ok(())
    }

    #[test]
    fn sizing_validation_covers_zero_horizon_shape_and_growth_overflow(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let measurement = mainnet_measurement()?;
        let zero_horizon =
            MainnetSizingModel::new(0, 1_000, 8, 6, 16, 12, 8, 4, 20_000, 1_000_000, 3_000)?;
        let qualification = measurement.apply_model(&zero_horizon)?;
        assert_eq!(qualification.projections.len(), 1);
        assert_eq!(qualification.projections[0].year, 0);

        let mut wrong_year = serde_json::to_value(&qualification)?;
        wrong_year["projections"][0]["year"] = serde_json::json!(1);
        assert!(serde_json::from_value::<MainnetSizingQualification>(wrong_year).is_err());

        let mut missing_projection = serde_json::to_value(&qualification)?;
        let Some(projections) = missing_projection["projections"].as_array_mut() else {
            panic!("serialized sizing qualification must contain a projection array");
        };
        projections.clear();
        assert!(serde_json::from_value::<MainnetSizingQualification>(missing_projection).is_err());

        let overflow_model =
            MainnetSizingModel::new(2, u64::MAX, 8, 6, 16, 12, 8, 4, 20_000, 1_000_000, 3_000)?;
        assert!(measurement.apply_model(&overflow_model).is_err());
        Ok(())
    }
}
