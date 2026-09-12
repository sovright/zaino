//! Exact native geometry preflight for the recovered historical two-table model.

use std::{fmt, mem::size_of};

use rostl_oram::circuit_oram::{Block, Bucket, S, Z};
use serde::{Deserialize, Serialize};

use crate::{
    records::{PersistentAddressDirectory, PersistentAddressEventPage},
    MainnetCorpusMeasurement, MainnetSizingQualification,
};

const MEASUREMENT_DIGEST: &str = "aba46f64da0113d9b0e93209ab4a8a98626d6d5bc7973444c8bf766a1922b127";
const MODEL_DIGEST: &str = "8ff797d7a57f6e07c0d4de5049178ef11568edd5c0c98e10bf30fd42ba50b58a";
const QUALIFICATION_DIGEST: &str =
    "7c16856d25d363e9409a05408f6c6e4b6c668236e2851abcb1eb47763cd0b0f2";
const DIRECTORY_CAPACITY: u64 = 1 << 24;
const EVENT_CAPACITY: u64 = 1 << 29;
const NOMINAL_HOST_BYTES: u64 = 176 * 1_073_741_824;
const MAX_WHOLE_PROCESS_RSS_BYTES: u64 = 132_284_992_716;
const ROSTL_REVISION: &str = "8c3a12d2febf17b024f2e949428b3bc526d74172";

/// Error returned before any historical allocation can begin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HistoricalGeometryError {
    /// Compiled target is not the pinned Linux x86_64 geometry target.
    UnsupportedPlatform,
    /// Capture, sizing, or retained digest lineage did not match exactly.
    InputRejected,
    /// Checked native-layout arithmetic overflowed.
    ArithmeticOverflow,
    /// The historical allocation cannot fit its fixed host model.
    PreallocationNoGo,
}

impl fmt::Display for HistoricalGeometryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::UnsupportedPlatform => {
                "historical native geometry requires Linux x86_64 with 64-bit pointers"
            }
            Self::InputRejected => "historical allocation lineage or model was rejected",
            Self::ArithmeticOverflow => "historical native geometry arithmetic overflowed",
            Self::PreallocationNoGo => {
                "historical event-tree lower bound exceeds the fixed 176-GiB host"
            }
        })
    }
}

impl std::error::Error for HistoricalGeometryError {}

/// Source-bound native-layout result for the historical two-table model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalTwoTableGeometry {
    schema: String,
    rostl_revision: String,
    measurement_blake2s256: String,
    sizing_model_blake2s256: String,
    qualification_blake2s256: String,
    target_arch: String,
    pointer_width_bits: u32,
    directory_capacity: u64,
    event_capacity: u64,
    directory_record_bytes: u64,
    event_record_bytes: u64,
    directory_block_bytes: u64,
    event_block_bytes: u64,
    directory_bucket_bytes: u64,
    event_bucket_bytes: u64,
    blocks_per_bucket: u64,
    stash_base_blocks: u64,
    directory_height: u32,
    event_height: u32,
    directory_tree_nodes: u64,
    event_tree_nodes: u64,
    directory_tree_bytes: u64,
    event_tree_bytes: u64,
    event_tree_padding_free_lower_bound_bytes: u64,
    directory_stash_bytes: u64,
    event_stash_bytes: u64,
    two_main_trees_and_stashes_bytes: u64,
    nominal_host_bytes: u64,
    max_whole_process_rss_bytes: u64,
    preallocation_no_go: bool,
    evidence_scope: String,
}

impl HistoricalTwoTableGeometry {
    /// Checks the exact historical model and trusted digest labels, then computes geometry.
    ///
    /// This business-layer constructor does not read artifacts or authenticate
    /// the digest strings. The daemon artifact owner must validate those files
    /// before calling it and must rederive the report during read-back.
    pub fn derive(
        measurement: &MainnetCorpusMeasurement,
        sizing: &MainnetSizingQualification,
        measurement_blake2s256: &str,
        sizing_model_blake2s256: &str,
        qualification_blake2s256: &str,
    ) -> Result<Self, HistoricalGeometryError> {
        if !cfg!(all(
            target_os = "linux",
            target_arch = "x86_64",
            target_pointer_width = "64"
        )) {
            return Err(HistoricalGeometryError::UnsupportedPlatform);
        }
        measurement
            .validate()
            .map_err(|_| HistoricalGeometryError::InputRejected)?;
        sizing
            .validate_against(measurement)
            .map_err(|_| HistoricalGeometryError::InputRejected)?;
        let model = sizing.model();
        if measurement_blake2s256 != MEASUREMENT_DIGEST
            || sizing_model_blake2s256 != MODEL_DIGEST
            || qualification_blake2s256 != QUALIFICATION_DIGEST
            || !sizing.is_exact_historical_176_gib_model()
            || model.directory_capacity() != DIRECTORY_CAPACITY
            || model.event_capacity() != EVENT_CAPACITY
            || size_of::<PersistentAddressDirectory>() != 38
            || size_of::<PersistentAddressEventPage>() != 82
        {
            return Err(HistoricalGeometryError::InputRejected);
        }
        let directory = table_geometry::<PersistentAddressDirectory>(DIRECTORY_CAPACITY)?;
        let event = table_geometry::<PersistentAddressEventPage>(EVENT_CAPACITY)?;
        let combined = directory
            .tree_bytes
            .checked_add(directory.stash_bytes)
            .and_then(|bytes| bytes.checked_add(event.tree_bytes))
            .and_then(|bytes| bytes.checked_add(event.stash_bytes))
            .ok_or(HistoricalGeometryError::ArithmeticOverflow)?;
        let event_tree_padding_free_lower_bound_bytes = event
            .tree_nodes
            .checked_mul(82 + 4 + 8)
            .and_then(|bytes| bytes.checked_mul(Z as u64))
            .ok_or(HistoricalGeometryError::ArithmeticOverflow)?;
        Ok(Self {
            schema: "zaino-oram-historical-two-table-native-geometry-v1".to_owned(),
            rostl_revision: ROSTL_REVISION.to_owned(),
            measurement_blake2s256: measurement_blake2s256.to_owned(),
            sizing_model_blake2s256: sizing_model_blake2s256.to_owned(),
            qualification_blake2s256: qualification_blake2s256.to_owned(),
            target_arch: std::env::consts::ARCH.to_owned(),
            pointer_width_bits: usize::BITS,
            directory_capacity: DIRECTORY_CAPACITY,
            event_capacity: EVENT_CAPACITY,
            directory_record_bytes: size_of::<PersistentAddressDirectory>() as u64,
            event_record_bytes: size_of::<PersistentAddressEventPage>() as u64,
            directory_block_bytes: directory.block_bytes,
            event_block_bytes: event.block_bytes,
            directory_bucket_bytes: directory.bucket_bytes,
            event_bucket_bytes: event.bucket_bytes,
            blocks_per_bucket: Z as u64,
            stash_base_blocks: S as u64,
            directory_height: directory.height,
            event_height: event.height,
            directory_tree_nodes: directory.tree_nodes,
            event_tree_nodes: event.tree_nodes,
            directory_tree_bytes: directory.tree_bytes,
            event_tree_bytes: event.tree_bytes,
            event_tree_padding_free_lower_bound_bytes,
            directory_stash_bytes: directory.stash_bytes,
            event_stash_bytes: event.stash_bytes,
            two_main_trees_and_stashes_bytes: combined,
            nominal_host_bytes: NOMINAL_HOST_BYTES,
            max_whole_process_rss_bytes: MAX_WHOLE_PROCESS_RSS_BYTES,
            preallocation_no_go: event.tree_bytes > NOMINAL_HOST_BYTES,
            evidence_scope: "computed-native-layout-lower-bound;excludes-recursive-position-maps,allocator,service,growth,generation-overlap,recovery,rss,tdx,hybrid".to_owned(),
        })
    }
}

impl fmt::Display for HistoricalTwoTableGeometry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "schema={}", self.schema)?;
        writeln!(
            f,
            "source=measurement:{},model:{},qualification:{},rostl:{}",
            self.measurement_blake2s256,
            self.sizing_model_blake2s256,
            self.qualification_blake2s256,
            self.rostl_revision
        )?;
        writeln!(
            f,
            "native=arch:{},pointer_bits:{},directory_record:{},event_record:{},directory_block:{},event_block:{},directory_bucket:{},event_bucket:{}",
            self.target_arch,
            self.pointer_width_bits,
            self.directory_record_bytes,
            self.event_record_bytes,
            self.directory_block_bytes,
            self.event_block_bytes,
            self.directory_bucket_bytes,
            self.event_bucket_bytes
        )?;
        writeln!(
            f,
            "event_tree=capacity:{},height:{},nodes:{},compiled_bytes:{},padding_free_lower_bound_bytes:{}",
            self.event_capacity,
            self.event_height,
            self.event_tree_nodes,
            self.event_tree_bytes,
            self.event_tree_padding_free_lower_bound_bytes
        )?;
        writeln!(
            f,
            "result=nominal_host_bytes:{},max_whole_process_rss_bytes:{},preallocation_no_go:{}",
            self.nominal_host_bytes, self.max_whole_process_rss_bytes, self.preallocation_no_go
        )?;
        writeln!(f, "evidence_scope={}", self.evidence_scope)
    }
}

struct TableGeometry {
    height: u32,
    tree_nodes: u64,
    block_bytes: u64,
    bucket_bytes: u64,
    tree_bytes: u64,
    stash_bytes: u64,
}

fn table_geometry<T>(capacity: u64) -> Result<TableGeometry, HistoricalGeometryError>
where
    T: bytemuck::Pod + rostl_primitives::traits::Cmov,
{
    if capacity <= 1 || !capacity.is_power_of_two() {
        return Err(HistoricalGeometryError::InputRejected);
    }
    let height = capacity.ilog2() + 1;
    let tree_nodes = 1_u64
        .checked_shl(height)
        .and_then(|nodes| nodes.checked_sub(1))
        .ok_or(HistoricalGeometryError::ArithmeticOverflow)?;
    let block_bytes = size_of::<Block<T>>() as u64;
    let bucket_bytes = size_of::<Bucket<T>>() as u64;
    let tree_bytes = tree_nodes
        .checked_mul(bucket_bytes)
        .ok_or(HistoricalGeometryError::ArithmeticOverflow)?;
    let stash_blocks = (S as u64)
        .checked_add(
            u64::from(height)
                .checked_mul(Z as u64)
                .ok_or(HistoricalGeometryError::ArithmeticOverflow)?,
        )
        .ok_or(HistoricalGeometryError::ArithmeticOverflow)?;
    let stash_bytes = stash_blocks
        .checked_mul(block_bytes)
        .ok_or(HistoricalGeometryError::ArithmeticOverflow)?;
    Ok(TableGeometry {
        height,
        tree_nodes,
        block_bytes,
        bucket_bytes,
        tree_bytes,
        stash_bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rostl_oram::circuit_oram::CircuitORAM;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn small_real_oram_matches_the_geometry_formula() -> TestResult {
        let geometry = table_geometry::<u64>(8)?;
        let actual = CircuitORAM::<u64>::new(8);
        assert_eq!(geometry.height as usize, actual.h);
        assert_eq!(geometry.height as usize, actual.tree.height);
        assert_eq!(geometry.tree_nodes, 15);
        assert_eq!(actual.stash.len(), S + actual.h * Z);
        Ok(())
    }

    #[test]
    fn historical_event_tree_is_a_preallocation_no_go() -> TestResult {
        let event = table_geometry::<PersistentAddressEventPage>(EVENT_CAPACITY)?;
        assert_eq!(size_of::<PersistentAddressEventPage>(), 82);
        if cfg!(all(target_arch = "x86_64", target_pointer_width = "64")) {
            assert_eq!(event.block_bytes, 104);
            assert_eq!(event.bucket_bytes, 208);
            assert_eq!(event.height, 30);
            assert_eq!(event.tree_nodes, 1_073_741_823);
            assert_eq!(event.tree_bytes, 223_338_299_184);
            assert_eq!(event.tree_nodes * (82 + 4 + 8) * Z as u64, 201_863_462_724);
            assert!(event.tree_bytes > NOMINAL_HOST_BYTES);
        }
        Ok(())
    }

    #[test]
    fn geometry_rejects_non_power_of_two_capacity() {
        assert_eq!(
            table_geometry::<u64>(3).err(),
            Some(HistoricalGeometryError::InputRejected)
        );
    }
}
