//! Checked retained-memory lower bounds for the selected fixed-page tables.
//!
//! This module binds the selected source-derived page demands to the exact
//! record and in-memory geometry of pinned `rostl` revision
//! `8c3a12d2febf17b024f2e949428b3bc526d74172`. It models the three independent
//! base/add/spend page tables on the intended Linux x86-64 target. The result is
//! a retained allocation floor, not an RSS estimate: allocator metadata,
//! transient construction allocations, directory state, generation overlap,
//! rebuild workspace, process memory, growth, and failure probability remain
//! outside the model.

use std::{fmt, mem::size_of};

use bytemuck::{Pod, Zeroable};
use rostl_oram::circuit_oram::{Block, Bucket, CircuitORAM, S, Z};
use rostl_primitives::traits::Cmov;

use crate::{
    hybrid_sizing::SourceBoundHybridSizingReport,
    records::{PersistentAddUtxoPage16, PersistentBaseUtxoPage16, PersistentSpendUtxoPage16},
};

pub(super) const SELECTED_PAGE_ENTRIES: u64 = 16;
pub(super) const SELECTED_GENERATION_INTERVAL_BLOCKS: u32 = 288;

const ROSTL_REVISION: &str = "8c3a12d2febf17b024f2e949428b3bc526d74172";
const IMMUTABLE_BASE_SPARE_RECORDS: u64 = 1;
const MUTABLE_DELTA_SPARE_RECORDS: u64 = 2;
const TARGET_POINTER_BYTES: usize = 8;
const POSITION_MAP_LEVEL_ZERO_BUCKETS: usize = 128;
const POSITION_MAP_FAN_OUT_BYTES: usize = 64;
const POSITION_BYTES: usize = size_of::<u32>();
const POSITION_MAP_FAN_OUT: usize = POSITION_MAP_FAN_OUT_BYTES / POSITION_BYTES;
const POSITION_MAP_LINEAR_ENTRIES: usize = POSITION_MAP_LEVEL_ZERO_BUCKETS * POSITION_MAP_FAN_OUT;

// `RostlTable<T>` contains the main CircuitORAM, RecursivePositionMap, capacity,
// public occupancy, terminal latch, and PhantomData. The nested Linux test in
// `worker/rostl.rs` checks this target-layout constant against the real type.
pub(super) const TARGET_ROSTL_TABLE_OBJECT_BYTES: u64 = 168;

#[repr(transparent)]
#[derive(Debug, Clone, Copy, Default, Zeroable, Pod)]
struct PositionMapNode([u32; POSITION_MAP_FAN_OUT]);

impl Cmov for PositionMapNode {
    fn cmov(&mut self, other: &Self, choice: bool) {
        for (current, replacement) in self.0.iter_mut().zip(other.0.iter()) {
            current.cmov(replacement, choice);
        }
    }

    fn cxchg(&mut self, other: &mut Self, choice: bool) {
        for (current, replacement) in self.0.iter_mut().zip(other.0.iter_mut()) {
            current.cxchg(replacement, choice);
        }
    }
}

const _: [(); 64] = [(); size_of::<PositionMapNode>()];
const _: [(); 1_208] = [(); size_of::<PersistentBaseUtxoPage16>()];
const _: [(); 1_208] = [(); size_of::<PersistentAddUtxoPage16>()];
const _: [(); 1_208] = [(); size_of::<PersistentSpendUtxoPage16>()];
const _: [(); 1_224] = [(); size_of::<Block<PersistentBaseUtxoPage16>>()];
const _: [(); 2_448] = [(); size_of::<Bucket<PersistentBaseUtxoPage16>>()];
const _: [(); 80] = [(); size_of::<Block<PositionMapNode>>()];
const _: [(); 160] = [(); size_of::<Bucket<PositionMapNode>>()];
const _: [(); 80] = [(); size_of::<CircuitORAM<PositionMapNode>>()];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct SelectedFixedPageDemands {
    pub(super) base_pages: u64,
    pub(super) add_pages: u64,
    pub(super) spend_pages: u64,
    pub(super) fixed_page_reads: u64,
}

/// Checked retained allocation floor for one fixed-page `rostl` table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FixedPageTableCapacityLowerBound {
    logical_records: u64,
    minimum_records: u64,
    rounded_capacity: u64,
    capacity_slack: u64,
    tree_height: u32,
    tree_buckets: u64,
    stash_blocks: u64,
    main_oram_bytes: u64,
    position_map_linear_nodes: u64,
    position_map_recursive_levels: u32,
    position_map_bytes: u64,
    table_object_bytes: u64,
    retained_bytes: u64,
}

impl FixedPageTableCapacityLowerBound {
    /// Returns the selected source-derived logical records.
    pub const fn logical_records(&self) -> u64 {
        self.logical_records
    }

    /// Returns logical records plus the table's mandatory reserve.
    pub const fn minimum_records(&self) -> u64 {
        self.minimum_records
    }

    /// Returns the minimum power-of-two capacity accepted by Zaino's adapter.
    pub const fn rounded_capacity(&self) -> u64 {
        self.rounded_capacity
    }

    /// Returns retained object and buffer bytes, excluding allocator overhead.
    pub const fn retained_bytes(&self) -> u64 {
        self.retained_bytes
    }
}

/// Source-bound retained allocation floor for the selected page-table tuple.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FixedPageCapacityLowerBound {
    fixed_page_reads: u64,
    record_bytes: u64,
    block_bytes: u64,
    bucket_bytes: u64,
    base: FixedPageTableCapacityLowerBound,
    add: FixedPageTableCapacityLowerBound,
    spend: FixedPageTableCapacityLowerBound,
    retained_bytes: u64,
}

impl FixedPageCapacityLowerBound {
    /// Returns the conservative fixed page-read lower bound per request.
    pub const fn fixed_page_reads(&self) -> u64 {
        self.fixed_page_reads
    }

    /// Returns the immutable-base table floor.
    pub const fn base(&self) -> &FixedPageTableCapacityLowerBound {
        &self.base
    }

    /// Returns the active-add table floor.
    pub const fn add(&self) -> &FixedPageTableCapacityLowerBound {
        &self.add
    }

    /// Returns the active-spend table floor.
    pub const fn spend(&self) -> &FixedPageTableCapacityLowerBound {
        &self.spend
    }

    /// Returns the retained floor across the three independent page tables.
    pub const fn retained_bytes(&self) -> u64 {
        self.retained_bytes
    }
}

impl fmt::Display for FixedPageCapacityLowerBound {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            formatter,
            "profile=fixed-page-16-generation-288-capacity-lower-bound-v1"
        )?;
        writeln!(formatter, "rostl_revision={ROSTL_REVISION}")?;
        writeln!(formatter, "target_abi=x86_64-unknown-linux-gnu")?;
        writeln!(
            formatter,
            "shape=entries_per_page:{SELECTED_PAGE_ENTRIES},generation_interval_blocks:{SELECTED_GENERATION_INTERVAL_BLOCKS},immutable_base_spare_records:{IMMUTABLE_BASE_SPARE_RECORDS},mutable_delta_spare_records:{MUTABLE_DELTA_SPARE_RECORDS},record_bytes:{},block_bytes:{},bucket_bytes:{}",
            self.record_bytes, self.block_bytes, self.bucket_bytes
        )?;
        write_table(formatter, "base", &self.base)?;
        write_table(formatter, "add", &self.add)?;
        write_table(formatter, "spend", &self.spend)?;
        writeln!(
            formatter,
            "lower_bound=fixed_page_reads:{},retained_bytes:{}",
            self.fixed_page_reads, self.retained_bytes
        )?;
        write!(
            formatter,
            "nonclaims=allocator-overhead,construction-peak,directory-state,growth,generation-overlap,rebuild-workspace,process-rss,stash-failure,latency,target-headroom,tdx-qualification,gate1-go"
        )
    }
}

fn write_table(
    formatter: &mut fmt::Formatter<'_>,
    name: &str,
    table: &FixedPageTableCapacityLowerBound,
) -> fmt::Result {
    writeln!(
        formatter,
        "table={name},logical_records:{},minimum_records:{},rounded_capacity:{},capacity_slack:{},tree_height:{},tree_buckets:{},stash_blocks:{},main_oram_bytes:{},position_map_linear_nodes:{},position_map_recursive_levels:{},position_map_bytes:{},table_object_bytes:{},retained_bytes:{}",
        table.logical_records,
        table.minimum_records,
        table.rounded_capacity,
        table.capacity_slack,
        table.tree_height,
        table.tree_buckets,
        table.stash_blocks,
        table.main_oram_bytes,
        table.position_map_linear_nodes,
        table.position_map_recursive_levels,
        table.position_map_bytes,
        table.table_object_bytes,
        table.retained_bytes
    )
}

/// A fixed-page capacity lower bound could not be derived safely.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FixedPageCapacityError {
    /// The source-bound hybrid-sizing report failed semantic validation.
    InvalidSizingReport,
    /// A checked size or capacity calculation overflowed.
    ArithmeticOverflow,
    /// The selected requirement cannot be represented by the pinned adapter.
    UnsupportedCapacity,
    /// The compiler target does not match the modeled 64-bit ABI.
    UnsupportedTargetLayout,
}

impl fmt::Display for FixedPageCapacityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSizingReport => {
                formatter.write_str("source-bound hybrid-sizing report is invalid")
            }
            Self::ArithmeticOverflow => {
                formatter.write_str("fixed-page capacity calculation overflowed")
            }
            Self::UnsupportedCapacity => {
                formatter.write_str("fixed-page requirement exceeds pinned rostl capacity")
            }
            Self::UnsupportedTargetLayout => formatter
                .write_str("fixed-page capacity model requires an x86_64-unknown-linux-gnu target"),
        }
    }
}

impl std::error::Error for FixedPageCapacityError {}

/// Derives the selected fixed-page tables' retained allocation floor.
pub fn derive_fixed_page_capacity_lower_bound(
    report: &SourceBoundHybridSizingReport,
) -> Result<FixedPageCapacityLowerBound, FixedPageCapacityError> {
    ensure_target_layout()?;
    let demands = report
        .selected_fixed_page_demands()
        .map_err(|_| FixedPageCapacityError::InvalidSizingReport)?;
    derive_from_demands(demands)
}

fn ensure_target_layout() -> Result<(), FixedPageCapacityError> {
    if !cfg!(all(target_os = "linux", target_arch = "x86_64"))
        || size_of::<usize>() != TARGET_POINTER_BYTES
    {
        return Err(FixedPageCapacityError::UnsupportedTargetLayout);
    }
    Ok(())
}

fn derive_from_demands(
    demands: SelectedFixedPageDemands,
) -> Result<FixedPageCapacityLowerBound, FixedPageCapacityError> {
    let base =
        derive_table::<PersistentBaseUtxoPage16>(demands.base_pages, IMMUTABLE_BASE_SPARE_RECORDS)?;
    let add =
        derive_table::<PersistentAddUtxoPage16>(demands.add_pages, MUTABLE_DELTA_SPARE_RECORDS)?;
    let spend = derive_table::<PersistentSpendUtxoPage16>(
        demands.spend_pages,
        MUTABLE_DELTA_SPARE_RECORDS,
    )?;
    let retained_bytes = base
        .retained_bytes
        .checked_add(add.retained_bytes)
        .and_then(|total| total.checked_add(spend.retained_bytes))
        .ok_or(FixedPageCapacityError::ArithmeticOverflow)?;

    Ok(FixedPageCapacityLowerBound {
        fixed_page_reads: demands.fixed_page_reads,
        record_bytes: size_as_u64::<PersistentBaseUtxoPage16>()?,
        block_bytes: size_as_u64::<Block<PersistentBaseUtxoPage16>>()?,
        bucket_bytes: size_as_u64::<Bucket<PersistentBaseUtxoPage16>>()?,
        base,
        add,
        spend,
        retained_bytes,
    })
}

fn derive_table<T>(
    logical_records: u64,
    spare_records: u64,
) -> Result<FixedPageTableCapacityLowerBound, FixedPageCapacityError>
where
    T: Cmov + Pod + Default + Clone + fmt::Debug,
{
    let minimum_records = logical_records
        .checked_add(spare_records)
        .ok_or(FixedPageCapacityError::ArithmeticOverflow)?;
    let requested_capacity = usize::try_from(minimum_records)
        .map_err(|_| FixedPageCapacityError::UnsupportedCapacity)?;
    let rounded_capacity = requested_capacity
        .max(2)
        .checked_next_power_of_two()
        .ok_or(FixedPageCapacityError::UnsupportedCapacity)?;
    if rounded_capacity > u32::MAX as usize {
        return Err(FixedPageCapacityError::UnsupportedCapacity);
    }

    let main = circuit_geometry::<T>(rounded_capacity)?;
    let position_map = position_map_geometry(rounded_capacity)?;
    let retained_bytes = main
        .retained_bytes
        .checked_add(position_map.retained_bytes)
        .and_then(|total| total.checked_add(TARGET_ROSTL_TABLE_OBJECT_BYTES))
        .ok_or(FixedPageCapacityError::ArithmeticOverflow)?;
    let rounded_capacity =
        u64::try_from(rounded_capacity).map_err(|_| FixedPageCapacityError::ArithmeticOverflow)?;
    let capacity_slack = rounded_capacity
        .checked_sub(minimum_records)
        .ok_or(FixedPageCapacityError::ArithmeticOverflow)?;

    Ok(FixedPageTableCapacityLowerBound {
        logical_records,
        minimum_records,
        rounded_capacity,
        capacity_slack,
        tree_height: main.height,
        tree_buckets: main.tree_buckets,
        stash_blocks: main.stash_blocks,
        main_oram_bytes: main.retained_bytes,
        position_map_linear_nodes: position_map.linear_nodes,
        position_map_recursive_levels: position_map.recursive_levels,
        position_map_bytes: position_map.retained_bytes,
        table_object_bytes: TARGET_ROSTL_TABLE_OBJECT_BYTES,
        retained_bytes,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CircuitGeometry {
    height: u32,
    tree_buckets: u64,
    stash_blocks: u64,
    retained_bytes: u64,
}

fn circuit_geometry<T>(capacity: usize) -> Result<CircuitGeometry, FixedPageCapacityError>
where
    T: Cmov + Pod,
{
    if capacity < 2 || !capacity.is_power_of_two() {
        return Err(FixedPageCapacityError::UnsupportedCapacity);
    }
    let height = capacity
        .ilog2()
        .checked_add(1)
        .ok_or(FixedPageCapacityError::ArithmeticOverflow)?;
    let capacity =
        u64::try_from(capacity).map_err(|_| FixedPageCapacityError::ArithmeticOverflow)?;
    let tree_buckets = capacity
        .checked_mul(2)
        .and_then(|buckets| buckets.checked_sub(1))
        .ok_or(FixedPageCapacityError::ArithmeticOverflow)?;
    let stash_blocks = u64::try_from(S)
        .map_err(|_| FixedPageCapacityError::ArithmeticOverflow)?
        .checked_add(
            u64::from(height)
                .checked_mul(
                    u64::try_from(Z).map_err(|_| FixedPageCapacityError::ArithmeticOverflow)?,
                )
                .ok_or(FixedPageCapacityError::ArithmeticOverflow)?,
        )
        .ok_or(FixedPageCapacityError::ArithmeticOverflow)?;
    let tree_bytes = tree_buckets
        .checked_mul(size_as_u64::<Bucket<T>>()?)
        .ok_or(FixedPageCapacityError::ArithmeticOverflow)?;
    let stash_bytes = stash_blocks
        .checked_mul(size_as_u64::<Block<T>>()?)
        .ok_or(FixedPageCapacityError::ArithmeticOverflow)?;
    let retained_bytes = tree_bytes
        .checked_add(stash_bytes)
        .ok_or(FixedPageCapacityError::ArithmeticOverflow)?;

    Ok(CircuitGeometry {
        height,
        tree_buckets,
        stash_blocks,
        retained_bytes,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PositionMapGeometry {
    linear_nodes: u64,
    recursive_levels: u32,
    retained_bytes: u64,
}

fn position_map_geometry(capacity: usize) -> Result<PositionMapGeometry, FixedPageCapacityError> {
    let linear_nodes = capacity
        .div_ceil(POSITION_MAP_FAN_OUT)
        .min(POSITION_MAP_LEVEL_ZERO_BUCKETS);
    let linear_bytes = size_of::<PositionMapNode>()
        .checked_mul(linear_nodes)
        .ok_or(FixedPageCapacityError::ArithmeticOverflow)?;
    let mut retained_bytes =
        u64::try_from(linear_bytes).map_err(|_| FixedPageCapacityError::ArithmeticOverflow)?;
    let mut recursive_levels = 0_u32;
    let mut covered_positions = POSITION_MAP_LINEAR_ENTRIES.min(capacity);

    while covered_positions < capacity {
        let level = circuit_geometry::<PositionMapNode>(covered_positions)?;
        retained_bytes = retained_bytes
            .checked_add(level.retained_bytes)
            .and_then(|bytes| {
                bytes.checked_add(u64::try_from(size_of::<CircuitORAM<PositionMapNode>>()).ok()?)
            })
            .ok_or(FixedPageCapacityError::ArithmeticOverflow)?;
        recursive_levels = recursive_levels
            .checked_add(1)
            .ok_or(FixedPageCapacityError::ArithmeticOverflow)?;
        covered_positions = covered_positions
            .checked_mul(POSITION_MAP_FAN_OUT)
            .ok_or(FixedPageCapacityError::ArithmeticOverflow)?;
    }

    Ok(PositionMapGeometry {
        linear_nodes: u64::try_from(linear_nodes)
            .map_err(|_| FixedPageCapacityError::ArithmeticOverflow)?,
        recursive_levels,
        retained_bytes,
    })
}

fn size_as_u64<T>() -> Result<u64, FixedPageCapacityError> {
    u64::try_from(size_of::<T>()).map_err(|_| FixedPageCapacityError::ArithmeticOverflow)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selected_mainnet_demands_have_exact_pinned_rostl_floor() -> Result<(), FixedPageCapacityError>
    {
        let lower_bound = derive_from_demands(SelectedFixedPageDemands {
            base_pages: 2_388_477,
            add_pages: 69_233,
            spend_pages: 92_186,
            fixed_page_reads: 27_159,
        })?;

        assert_eq!(lower_bound.base.minimum_records, 2_388_478);
        assert_eq!(lower_bound.base.rounded_capacity, 4_194_304);
        assert_eq!(lower_bound.base.capacity_slack, 1_805_826);
        assert_eq!(lower_bound.base.main_oram_bytes, 20_535_390_720);
        assert_eq!(lower_bound.base.position_map_bytes, 178_933_712);
        assert_eq!(lower_bound.base.retained_bytes, 20_714_324_600);

        assert_eq!(lower_bound.add.minimum_records, 69_235);
        assert_eq!(lower_bound.add.rounded_capacity, 131_072);
        assert_eq!(lower_bound.add.capacity_slack, 61_837);
        assert_eq!(lower_bound.add.main_oram_bytes, 641_794_608);
        assert_eq!(lower_bound.add.position_map_bytes, 11_156_832);
        assert_eq!(lower_bound.add.retained_bytes, 652_951_608);

        assert_eq!(lower_bound.spend.minimum_records, 92_188);
        assert_eq!(lower_bound.spend.rounded_capacity, 131_072);
        assert_eq!(lower_bound.spend.capacity_slack, 38_884);
        assert_eq!(lower_bound.spend.retained_bytes, 652_951_608);
        assert_eq!(lower_bound.retained_bytes, 22_020_227_816);
        Ok(())
    }

    #[test]
    fn position_map_levels_match_pinned_production_recursion() -> Result<(), FixedPageCapacityError>
    {
        let base = position_map_geometry(4_194_304)?;
        assert_eq!(base.linear_nodes, 128);
        assert_eq!(base.recursive_levels, 3);
        assert_eq!(base.retained_bytes, 178_933_712);

        let delta = position_map_geometry(131_072)?;
        assert_eq!(delta.linear_nodes, 128);
        assert_eq!(delta.recursive_levels, 2);
        assert_eq!(delta.retained_bytes, 11_156_832);
        Ok(())
    }

    #[test]
    fn capacity_rounding_rejects_unrepresentable_requirement() {
        assert_eq!(
            derive_table::<PersistentBaseUtxoPage16>(u64::from(u32::MAX), 1),
            Err(FixedPageCapacityError::UnsupportedCapacity)
        );
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn intended_target_layout_is_accepted() {
        assert_eq!(ensure_target_layout(), Ok(()));
    }

    #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
    #[test]
    fn non_linux_x86_64_target_layout_is_rejected() {
        assert_eq!(
            ensure_target_layout(),
            Err(FixedPageCapacityError::UnsupportedTargetLayout)
        );
    }

    #[test]
    fn mutable_tables_keep_the_upsert_reserve_at_power_of_two_edges(
    ) -> Result<(), FixedPageCapacityError> {
        let lower_bound = derive_from_demands(SelectedFixedPageDemands {
            base_pages: 1,
            add_pages: 1,
            spend_pages: 1,
            fixed_page_reads: 3,
        })?;

        assert_eq!(lower_bound.base.minimum_records, 2);
        assert_eq!(lower_bound.base.rounded_capacity, 2);
        assert_eq!(lower_bound.add.minimum_records, 3);
        assert_eq!(lower_bound.add.rounded_capacity, 4);
        assert_eq!(lower_bound.spend.minimum_records, 3);
        assert_eq!(lower_bound.spend.rounded_capacity, 4);
        Ok(())
    }

    #[test]
    fn display_names_every_excluded_rss_component() -> Result<(), FixedPageCapacityError> {
        let lower_bound = derive_from_demands(SelectedFixedPageDemands {
            base_pages: 2,
            add_pages: 2,
            spend_pages: 2,
            fixed_page_reads: 3,
        })?;
        let rendered = lower_bound.to_string();
        assert!(rendered.contains("rostl_revision=8c3a12d2"));
        assert!(rendered.contains("nonclaims=allocator-overhead"));
        assert!(rendered.contains("target-headroom"));
        assert!(rendered.contains("gate1-go"));
        Ok(())
    }
}
