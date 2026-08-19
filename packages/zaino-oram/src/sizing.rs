use std::{collections::BTreeMap, fmt};

use crate::{
    layout::{FixedLayoutAllocation, LayoutConfigError},
    records::{PersistentAddressDirectory, PersistentAddressEventPage},
};

const BASIS_POINTS_DENOMINATOR: u64 = 10_000;

/// Validated inputs for a deterministic two-table storage-capacity estimate.
///
/// Every estimate charges the complete allocated directory and event tables,
/// including unused slots, rather than only currently occupied records. The
/// modeled backend expansion is still an operator-supplied approximation; this
/// is not measured RSS, allocator, stash, recursive-map, or working-memory
/// evidence.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct SizingParameters {
    layout: FixedLayoutAllocation,
    directory_record_bytes: u64,
    event_record_bytes: u64,
    position_map_entry_bytes: u64,
    backend_expansion_bps: u64,
    tdx_memory_bytes: u64,
    required_headroom_bps: u64,
}

impl SizingParameters {
    /// Validates a fixed two-table allocation using the compiled record widths.
    #[expect(
        clippy::too_many_arguments,
        reason = "the private model validates every fixed-layout sizing dimension together"
    )]
    pub(super) fn new(
        directory_capacity: u64,
        directory_admission_limit: u64,
        event_capacity: u64,
        event_admission_limit: u64,
        max_events_per_address: u64,
        position_map_entry_bytes: u64,
        backend_expansion_bps: u64,
        tdx_memory_bytes: u64,
        required_headroom_bps: u64,
    ) -> Result<Self, SizingError> {
        Self::new_with_record_bytes(
            directory_capacity,
            directory_admission_limit,
            std::mem::size_of::<PersistentAddressDirectory>() as u64,
            event_capacity,
            event_admission_limit,
            std::mem::size_of::<PersistentAddressEventPage>() as u64,
            max_events_per_address,
            position_map_entry_bytes,
            backend_expansion_bps,
            tdx_memory_bytes,
            required_headroom_bps,
        )
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "the arithmetic-test seam validates every sizing dimension together"
    )]
    fn new_with_record_bytes(
        directory_capacity: u64,
        directory_admission_limit: u64,
        directory_record_bytes: u64,
        event_capacity: u64,
        event_admission_limit: u64,
        event_record_bytes: u64,
        max_events_per_address: u64,
        position_map_entry_bytes: u64,
        backend_expansion_bps: u64,
        tdx_memory_bytes: u64,
        required_headroom_bps: u64,
    ) -> Result<Self, SizingError> {
        let layout = FixedLayoutAllocation::new(
            directory_capacity,
            directory_admission_limit,
            event_capacity,
            event_admission_limit,
            max_events_per_address,
        )
        .map_err(SizingError::InvalidLayoutConfiguration)?;

        if directory_record_bytes == 0 {
            return Err(SizingError::ZeroDirectoryRecordBytes);
        }
        if event_record_bytes == 0 {
            return Err(SizingError::ZeroEventRecordBytes);
        }
        if position_map_entry_bytes == 0 {
            return Err(SizingError::ZeroPositionMapEntryBytes);
        }
        if backend_expansion_bps < BASIS_POINTS_DENOMINATOR {
            return Err(SizingError::BackendExpansionBelowMinimum {
                actual_bps: backend_expansion_bps,
            });
        }
        if required_headroom_bps >= BASIS_POINTS_DENOMINATOR {
            return Err(SizingError::RequiredHeadroomOutOfRange {
                actual_bps: required_headroom_bps,
            });
        }

        Ok(Self {
            layout,
            directory_record_bytes,
            event_record_bytes,
            position_map_entry_bytes,
            backend_expansion_bps,
            tdx_memory_bytes,
            required_headroom_bps,
        })
    }

    /// Estimates one current or projected aggregate corpus against the fixed
    /// allocation.
    ///
    /// Admission failures are retained as explicit booleans instead of
    /// changing allocated bytes. This lets the offline report show that a
    /// candidate profile is too small without pretending that the backend can
    /// grow or fall back dynamically.
    pub(super) fn estimate(
        &self,
        address_count: u64,
        event_count_histogram: &BTreeMap<u64, u64>,
    ) -> Result<StorageEstimate, SizingError> {
        let mut histogram_address_count = 0_u64;
        let mut event_count = 0_u64;
        let mut maximum_events_per_address = 0_u64;

        for (&events_per_address, &addresses_in_bucket) in event_count_histogram {
            histogram_address_count = checked_add(
                histogram_address_count,
                addresses_in_bucket,
                OverflowQuantity::HistogramAddressCount,
            )?;
            let bucket_events = checked_mul(
                events_per_address,
                addresses_in_bucket,
                OverflowQuantity::EventCount,
            )?;
            event_count = checked_add(event_count, bucket_events, OverflowQuantity::EventCount)?;
            if addresses_in_bucket != 0 {
                maximum_events_per_address = maximum_events_per_address.max(events_per_address);
            }
        }

        if histogram_address_count != address_count {
            return Err(SizingError::HistogramAddressCountMismatch {
                declared: address_count,
                histogram: histogram_address_count,
            });
        }

        self.estimate_aggregates(address_count, event_count, maximum_events_per_address)
    }

    /// Recomputes every deterministic estimate field from identifier-free
    /// aggregate counts. This is also the validation seam for persisted sizing
    /// rows; the histogram-based entry point above remains the source of those
    /// counts during model application.
    pub(super) fn estimate_aggregates(
        &self,
        address_count: u64,
        event_count: u64,
        maximum_events_per_address: u64,
    ) -> Result<StorageEstimate, SizingError> {
        let allocated_directory_bytes = checked_mul(
            u64::from(self.layout.directory().capacity()),
            self.directory_record_bytes,
            OverflowQuantity::AllocatedDirectoryBytes,
        )?;
        let allocated_event_bytes = checked_mul(
            u64::from(self.layout.event().capacity()),
            self.event_record_bytes,
            OverflowQuantity::AllocatedEventBytes,
        )?;
        let allocated_table_bytes = checked_add(
            allocated_directory_bytes,
            allocated_event_bytes,
            OverflowQuantity::AllocatedTableBytes,
        )?;
        let position_map_entries = checked_add(
            u64::from(self.layout.directory().capacity()),
            u64::from(self.layout.event().capacity()),
            OverflowQuantity::PositionMapEntries,
        )?;
        let logical_position_map_bytes = checked_mul(
            position_map_entries,
            self.position_map_entry_bytes,
            OverflowQuantity::LogicalPositionMapBytes,
        )?;
        let logical_total_bytes = checked_add(
            allocated_table_bytes,
            logical_position_map_bytes,
            OverflowQuantity::LogicalTotalBytes,
        )?;
        let backend_expanded_bytes =
            apply_backend_expansion(logical_total_bytes, self.backend_expansion_bps)?;
        let usable_memory_bytes =
            usable_memory_after_headroom(self.tdx_memory_bytes, self.required_headroom_bps)?;

        let fits_directory_admission =
            address_count <= u64::from(self.layout.directory().admission_limit());
        let fits_event_admission = event_count <= u64::from(self.layout.event().admission_limit());
        let fits_address_event_limit =
            maximum_events_per_address <= u64::from(self.layout.max_events_per_address());
        let fits_configured_limits =
            fits_directory_admission && fits_event_admission && fits_address_event_limit;
        let fits_modeled_memory = backend_expanded_bytes <= usable_memory_bytes;
        let directory_load_bps =
            load_basis_points(address_count, self.layout.directory().capacity());
        let event_load_bps = load_basis_points(event_count, self.layout.event().capacity());

        Ok(StorageEstimate {
            address_count,
            event_count,
            maximum_events_per_address,
            allocated_directory_bytes,
            allocated_event_bytes,
            allocated_table_bytes,
            logical_position_map_bytes,
            logical_total_bytes,
            backend_expanded_bytes,
            usable_memory_bytes,
            directory_load_bps,
            event_load_bps,
            fits_directory_admission,
            fits_event_admission,
            fits_address_event_limit,
            fits_configured_limits,
            fits_modeled_memory,
            fits_modeled_constraints: fits_configured_limits && fits_modeled_memory,
        })
    }

    pub(super) const fn directory_record_bytes(&self) -> u64 {
        self.directory_record_bytes
    }

    pub(super) const fn event_record_bytes(&self) -> u64 {
        self.event_record_bytes
    }
}

impl fmt::Debug for SizingParameters {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SizingParameters { ..REDACTED.. }")
    }
}

/// Deterministic capacity results for one aggregate corpus histogram.
///
/// The allocation byte counts are fixed by the selected profile. Corpus
/// occupancy changes only the admission flags. All values remain model outputs,
/// not measured process-memory observations.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct StorageEstimate {
    address_count: u64,
    event_count: u64,
    maximum_events_per_address: u64,
    allocated_directory_bytes: u64,
    allocated_event_bytes: u64,
    allocated_table_bytes: u64,
    logical_position_map_bytes: u64,
    logical_total_bytes: u64,
    backend_expanded_bytes: u64,
    usable_memory_bytes: u64,
    directory_load_bps: u128,
    event_load_bps: u128,
    fits_directory_admission: bool,
    fits_event_admission: bool,
    fits_address_event_limit: bool,
    fits_configured_limits: bool,
    fits_modeled_memory: bool,
    fits_modeled_constraints: bool,
}

impl StorageEstimate {
    pub(super) const fn address_count(&self) -> u64 {
        self.address_count
    }

    pub(super) const fn event_count(&self) -> u64 {
        self.event_count
    }

    pub(super) const fn maximum_events_per_address(&self) -> u64 {
        self.maximum_events_per_address
    }

    pub(super) const fn allocated_directory_bytes(&self) -> u64 {
        self.allocated_directory_bytes
    }

    pub(super) const fn allocated_event_bytes(&self) -> u64 {
        self.allocated_event_bytes
    }

    pub(super) const fn allocated_table_bytes(&self) -> u64 {
        self.allocated_table_bytes
    }

    pub(super) const fn logical_position_map_bytes(&self) -> u64 {
        self.logical_position_map_bytes
    }

    pub(super) const fn logical_total_bytes(&self) -> u64 {
        self.logical_total_bytes
    }

    pub(super) const fn backend_expanded_bytes(&self) -> u64 {
        self.backend_expanded_bytes
    }

    pub(super) const fn usable_memory_bytes(&self) -> u64 {
        self.usable_memory_bytes
    }

    pub(super) const fn directory_load_bps(&self) -> u128 {
        self.directory_load_bps
    }

    pub(super) const fn event_load_bps(&self) -> u128 {
        self.event_load_bps
    }

    pub(super) const fn fits_directory_admission(&self) -> bool {
        self.fits_directory_admission
    }

    pub(super) const fn fits_event_admission(&self) -> bool {
        self.fits_event_admission
    }

    pub(super) const fn fits_address_event_limit(&self) -> bool {
        self.fits_address_event_limit
    }

    pub(super) const fn fits_configured_limits(&self) -> bool {
        self.fits_configured_limits
    }

    pub(super) const fn fits_modeled_memory(&self) -> bool {
        self.fits_modeled_memory
    }

    pub(super) const fn fits_modeled_constraints(&self) -> bool {
        self.fits_modeled_constraints
    }
}

impl fmt::Debug for StorageEstimate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("StorageEstimate { ..REDACTED.. }")
    }
}

/// A sizing parameter or checked aggregate calculation was invalid.
///
/// Error fields contain only configured or aggregate public sizing values; no
/// address key or per-address identity is retained.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SizingError {
    InvalidLayoutConfiguration(LayoutConfigError),
    ZeroDirectoryRecordBytes,
    ZeroEventRecordBytes,
    ZeroPositionMapEntryBytes,
    BackendExpansionBelowMinimum { actual_bps: u64 },
    RequiredHeadroomOutOfRange { actual_bps: u64 },
    HistogramAddressCountMismatch { declared: u64, histogram: u64 },
    ArithmeticOverflow { quantity: OverflowQuantity },
}

impl fmt::Display for SizingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLayoutConfiguration(error) => {
                write!(f, "invalid fixed-layout sizing configuration: {error}")
            }
            Self::ZeroDirectoryRecordBytes => {
                f.write_str("directory record bytes must be nonzero")
            }
            Self::ZeroEventRecordBytes => f.write_str("event record bytes must be nonzero"),
            Self::ZeroPositionMapEntryBytes => {
                f.write_str("position-map entry bytes must be nonzero")
            }
            Self::BackendExpansionBelowMinimum { actual_bps } => write!(
                f,
                "backend expansion must be at least {BASIS_POINTS_DENOMINATOR} basis points; received {actual_bps}"
            ),
            Self::RequiredHeadroomOutOfRange { actual_bps } => write!(
                f,
                "required headroom must be below {BASIS_POINTS_DENOMINATOR} basis points; received {actual_bps}"
            ),
            Self::HistogramAddressCountMismatch {
                declared,
                histogram,
            } => write!(
                f,
                "declared address count {declared} differs from histogram count {histogram}"
            ),
            Self::ArithmeticOverflow { quantity } => {
                write!(f, "{} exceeds u64 capacity", quantity.description())
            }
        }
    }
}

impl std::error::Error for SizingError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidLayoutConfiguration(error) => Some(error),
            Self::ZeroDirectoryRecordBytes
            | Self::ZeroEventRecordBytes
            | Self::ZeroPositionMapEntryBytes
            | Self::BackendExpansionBelowMinimum { .. }
            | Self::RequiredHeadroomOutOfRange { .. }
            | Self::HistogramAddressCountMismatch { .. }
            | Self::ArithmeticOverflow { .. } => None,
        }
    }
}

/// Aggregate whose checked calculation overflowed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum OverflowQuantity {
    HistogramAddressCount,
    EventCount,
    AllocatedDirectoryBytes,
    AllocatedEventBytes,
    AllocatedTableBytes,
    PositionMapEntries,
    LogicalPositionMapBytes,
    LogicalTotalBytes,
    BackendExpandedBytes,
    UsableMemoryBytes,
}

impl OverflowQuantity {
    const fn description(self) -> &'static str {
        match self {
            Self::HistogramAddressCount => "histogram address count",
            Self::EventCount => "event count",
            Self::AllocatedDirectoryBytes => "allocated directory bytes",
            Self::AllocatedEventBytes => "allocated event bytes",
            Self::AllocatedTableBytes => "allocated table bytes",
            Self::PositionMapEntries => "position-map entry count",
            Self::LogicalPositionMapBytes => "logical position-map bytes",
            Self::LogicalTotalBytes => "logical total bytes",
            Self::BackendExpandedBytes => "backend-expanded bytes",
            Self::UsableMemoryBytes => "usable memory bytes",
        }
    }
}

fn checked_add(left: u64, right: u64, quantity: OverflowQuantity) -> Result<u64, SizingError> {
    left.checked_add(right)
        .ok_or(SizingError::ArithmeticOverflow { quantity })
}

fn checked_mul(left: u64, right: u64, quantity: OverflowQuantity) -> Result<u64, SizingError> {
    left.checked_mul(right)
        .ok_or(SizingError::ArithmeticOverflow { quantity })
}

fn load_basis_points(occupied: u64, capacity: u32) -> u128 {
    u128::from(occupied) * u128::from(BASIS_POINTS_DENOMINATOR) / u128::from(capacity)
}

fn apply_backend_expansion(logical_bytes: u64, expansion_bps: u64) -> Result<u64, SizingError> {
    let expanded_product = u128::from(logical_bytes)
        .checked_mul(u128::from(expansion_bps))
        .ok_or(SizingError::ArithmeticOverflow {
            quantity: OverflowQuantity::BackendExpandedBytes,
        })?;
    let expanded_bytes = expanded_product.div_ceil(u128::from(BASIS_POINTS_DENOMINATOR));
    u64::try_from(expanded_bytes).map_err(|_| SizingError::ArithmeticOverflow {
        quantity: OverflowQuantity::BackendExpandedBytes,
    })
}

fn usable_memory_after_headroom(
    tdx_memory_bytes: u64,
    required_headroom_bps: u64,
) -> Result<u64, SizingError> {
    let usable_bps = BASIS_POINTS_DENOMINATOR
        .checked_sub(required_headroom_bps)
        .ok_or(SizingError::ArithmeticOverflow {
            quantity: OverflowQuantity::UsableMemoryBytes,
        })?;
    let usable_product = u128::from(tdx_memory_bytes)
        .checked_mul(u128::from(usable_bps))
        .ok_or(SizingError::ArithmeticOverflow {
            quantity: OverflowQuantity::UsableMemoryBytes,
        })?;
    let usable_bytes = usable_product / u128::from(BASIS_POINTS_DENOMINATOR);
    u64::try_from(usable_bytes).map_err(|_| SizingError::ArithmeticOverflow {
        quantity: OverflowQuantity::UsableMemoryBytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layout::TableKind;

    fn parameters(
        tdx_memory_bytes: u64,
        required_headroom_bps: u64,
    ) -> Result<SizingParameters, SizingError> {
        SizingParameters::new(
            8,
            5,
            16,
            12,
            8,
            2,
            12_500,
            tdx_memory_bytes,
            required_headroom_bps,
        )
    }

    #[test]
    fn normal_math_charges_every_allocated_component_and_headroom() -> Result<(), SizingError> {
        let parameters = parameters(3_000, 3_000)?;
        let histogram = BTreeMap::from([(0, 1), (1, 2), (4, 1), (5, 1)]);

        let estimate = parameters.estimate(5, &histogram)?;

        assert_eq!(estimate.address_count(), 5);
        assert_eq!(estimate.event_count(), 11);
        assert_eq!(estimate.maximum_events_per_address(), 5);
        assert_eq!(estimate.allocated_directory_bytes(), 304);
        assert_eq!(estimate.allocated_event_bytes(), 1_312);
        assert_eq!(estimate.allocated_table_bytes(), 1_616);
        assert_eq!(estimate.logical_position_map_bytes(), 48);
        assert_eq!(estimate.logical_total_bytes(), 1_664);
        assert_eq!(estimate.backend_expanded_bytes(), 2_080);
        assert_eq!(estimate.usable_memory_bytes(), 2_100);
        assert_eq!(estimate.directory_load_bps(), 6_250);
        assert_eq!(estimate.event_load_bps(), 6_875);
        assert!(estimate.fits_directory_admission());
        assert!(estimate.fits_event_admission());
        assert!(estimate.fits_address_event_limit());
        assert!(estimate.fits_configured_limits());
        assert!(estimate.fits_modeled_memory());
        assert!(estimate.fits_modeled_constraints());
        Ok(())
    }

    #[test]
    fn production_parameters_use_compiled_table_record_widths() -> Result<(), SizingError> {
        let parameters = parameters(3_000, 3_000)?;

        assert_eq!(
            parameters.directory_record_bytes(),
            std::mem::size_of::<PersistentAddressDirectory>() as u64
        );
        assert_eq!(
            parameters.event_record_bytes(),
            std::mem::size_of::<PersistentAddressEventPage>() as u64
        );
        Ok(())
    }

    #[test]
    fn occupancy_never_reduces_the_fixed_allocation() -> Result<(), SizingError> {
        let parameters = parameters(3_000, 3_000)?;
        let empty = parameters.estimate(5, &BTreeMap::from([(0, 5)]))?;
        let occupied = parameters.estimate(5, &BTreeMap::from([(1, 2), (4, 2), (8, 1)]))?;

        assert_eq!(empty.event_count(), 0);
        assert_eq!(occupied.event_count(), 18);
        assert_eq!(
            empty.allocated_table_bytes(),
            occupied.allocated_table_bytes()
        );
        assert_eq!(
            empty.logical_position_map_bytes(),
            occupied.logical_position_map_bytes()
        );
        assert_eq!(
            empty.backend_expanded_bytes(),
            occupied.backend_expanded_bytes()
        );
        Ok(())
    }

    #[test]
    fn invalid_parameters_reuse_layout_validation_and_fail_typed() {
        let valid = (8, 5, 16, 12, 8, 2, 10_000, 1_000, 0);
        assert_eq!(
            SizingParameters::new(
                1, valid.1, valid.2, valid.3, valid.4, valid.5, valid.6, valid.7, valid.8
            ),
            Err(SizingError::InvalidLayoutConfiguration(
                LayoutConfigError::CapacityBelowMinimum {
                    table: TableKind::Directory,
                }
            ))
        );
        assert_eq!(
            SizingParameters::new(
                valid.0, 8, valid.2, valid.3, valid.4, valid.5, valid.6, valid.7, valid.8
            ),
            Err(SizingError::InvalidLayoutConfiguration(
                LayoutConfigError::AdmissionLimitOutsideTable {
                    table: TableKind::Directory,
                }
            ))
        );
        assert_eq!(
            SizingParameters::new(
                valid.0, valid.1, 3, valid.3, valid.4, valid.5, valid.6, valid.7, valid.8
            ),
            Err(SizingError::InvalidLayoutConfiguration(
                LayoutConfigError::CapacityNotPowerOfTwo {
                    table: TableKind::Event,
                }
            ))
        );
        assert_eq!(
            SizingParameters::new(
                valid.0, valid.1, valid.2, valid.3, 0, valid.5, valid.6, valid.7, valid.8
            ),
            Err(SizingError::InvalidLayoutConfiguration(
                LayoutConfigError::ZeroEventsPerAddress
            ))
        );
        assert_eq!(
            SizingParameters::new(
                valid.0, valid.1, valid.2, valid.3, 13, valid.5, valid.6, valid.7, valid.8
            ),
            Err(SizingError::InvalidLayoutConfiguration(
                LayoutConfigError::EventsPerAddressExceedsAdmission
            ))
        );
        assert_eq!(
            SizingParameters::new(
                valid.0, valid.1, valid.2, valid.3, valid.4, 0, valid.6, valid.7, valid.8
            ),
            Err(SizingError::ZeroPositionMapEntryBytes)
        );
        assert_eq!(
            SizingParameters::new(
                valid.0, valid.1, valid.2, valid.3, valid.4, valid.5, 9_999, valid.7, valid.8
            ),
            Err(SizingError::BackendExpansionBelowMinimum { actual_bps: 9_999 })
        );
        assert_eq!(
            SizingParameters::new(
                valid.0, valid.1, valid.2, valid.3, valid.4, valid.5, valid.6, valid.7, 10_000
            ),
            Err(SizingError::RequiredHeadroomOutOfRange { actual_bps: 10_000 })
        );
    }

    #[test]
    fn record_width_test_seam_rejects_zero_widths() {
        let parameters = |directory_record_bytes, event_record_bytes| {
            SizingParameters::new_with_record_bytes(
                8,
                5,
                directory_record_bytes,
                16,
                12,
                event_record_bytes,
                8,
                2,
                10_000,
                1_000,
                0,
            )
        };

        assert_eq!(parameters(0, 1), Err(SizingError::ZeroDirectoryRecordBytes));
        assert_eq!(parameters(1, 0), Err(SizingError::ZeroEventRecordBytes));
    }

    #[test]
    fn admission_and_hot_address_failures_are_reported_independently() -> Result<(), SizingError> {
        let parameters = SizingParameters::new(8, 4, 16, 8, 3, 1, 10_000, 10_000, 0)?;
        let directory_full = parameters.estimate(5, &BTreeMap::from([(1, 5)]))?;
        let event_full = parameters.estimate(3, &BTreeMap::from([(3, 3)]))?;
        let hot_address = parameters.estimate(1, &BTreeMap::from([(4, 1)]))?;
        let fitting = parameters.estimate(4, &BTreeMap::from([(1, 2), (3, 2)]))?;

        assert!(!directory_full.fits_directory_admission());
        assert!(directory_full.fits_event_admission());
        assert!(directory_full.fits_address_event_limit());

        assert!(event_full.fits_directory_admission());
        assert!(!event_full.fits_event_admission());
        assert!(event_full.fits_address_event_limit());

        assert!(hot_address.fits_directory_admission());
        assert!(hot_address.fits_event_admission());
        assert!(!hot_address.fits_address_event_limit());

        assert!(fitting.fits_configured_limits());
        assert!(fitting.fits_modeled_constraints());
        assert_eq!(fitting.directory_load_bps(), 5_000);
        assert_eq!(fitting.event_load_bps(), 5_000);
        Ok(())
    }

    #[test]
    fn zero_count_histogram_buckets_do_not_inflate_the_hot_address_limit() -> Result<(), SizingError>
    {
        let parameters = SizingParameters::new(8, 4, 16, 8, 3, 1, 10_000, 10_000, 0)?;
        let estimate = parameters.estimate(2, &BTreeMap::from([(1, 2), (u64::MAX, 0)]))?;

        assert_eq!(estimate.maximum_events_per_address(), 1);
        assert!(estimate.fits_address_event_limit());
        Ok(())
    }

    #[test]
    fn histogram_must_account_for_declared_addresses() -> Result<(), SizingError> {
        let parameters = parameters(3_000, 3_000)?;

        assert_eq!(
            parameters.estimate(4, &BTreeMap::from([(0, 2), (1, 1)])),
            Err(SizingError::HistogramAddressCountMismatch {
                declared: 4,
                histogram: 3,
            })
        );
        Ok(())
    }

    #[test]
    fn fit_uses_backend_expansion_and_headroom_adjusted_memory() -> Result<(), SizingError> {
        let fitting = SizingParameters::new(2, 1, 4, 2, 1, 1, 20_000, 1_172, 3_000)?;
        let too_small = SizingParameters::new(2, 1, 4, 2, 1, 1, 20_000, 1_171, 3_000)?;
        let histogram = BTreeMap::from([(1, 1)]);

        let fitting_estimate = fitting.estimate(1, &histogram)?;
        let too_small_estimate = too_small.estimate(1, &histogram)?;

        assert_eq!(fitting_estimate.logical_total_bytes(), 410);
        assert_eq!(fitting_estimate.backend_expanded_bytes(), 820);
        assert_eq!(fitting_estimate.usable_memory_bytes(), 820);
        assert!(fitting_estimate.fits_modeled_memory());
        assert!(fitting_estimate.fits_modeled_constraints());
        assert_eq!(too_small_estimate.usable_memory_bytes(), 819);
        assert!(!too_small_estimate.fits_modeled_memory());
        assert!(!too_small_estimate.fits_modeled_constraints());
        Ok(())
    }

    #[test]
    fn every_unbounded_calculation_reports_overflow() -> Result<(), SizingError> {
        let unit = SizingParameters::new(2, 1, 4, 2, 1, 1, 10_000, u64::MAX, 0)?;
        assert_eq!(
            unit.estimate(u64::MAX, &BTreeMap::from([(0, u64::MAX), (1, 1)]),),
            Err(SizingError::ArithmeticOverflow {
                quantity: OverflowQuantity::HistogramAddressCount,
            })
        );
        assert_eq!(
            unit.estimate(2, &BTreeMap::from([(u64::MAX, 2)])),
            Err(SizingError::ArithmeticOverflow {
                quantity: OverflowQuantity::EventCount,
            })
        );

        let directory_bytes = SizingParameters::new_with_record_bytes(
            2,
            1,
            u64::MAX,
            4,
            2,
            1,
            1,
            1,
            10_000,
            u64::MAX,
            0,
        )?;
        assert_eq!(
            directory_bytes.estimate(1, &BTreeMap::from([(1, 1)])),
            Err(SizingError::ArithmeticOverflow {
                quantity: OverflowQuantity::AllocatedDirectoryBytes,
            })
        );

        let event_bytes = SizingParameters::new_with_record_bytes(
            2,
            1,
            1,
            4,
            2,
            u64::MAX,
            1,
            1,
            10_000,
            u64::MAX,
            0,
        )?;
        assert_eq!(
            event_bytes.estimate(1, &BTreeMap::from([(1, 1)])),
            Err(SizingError::ArithmeticOverflow {
                quantity: OverflowQuantity::AllocatedEventBytes,
            })
        );

        let near_maximum_record_width = (u64::MAX - 100) / 2;
        let allocated_table = SizingParameters::new_with_record_bytes(
            2,
            1,
            near_maximum_record_width,
            4,
            2,
            100,
            1,
            1,
            10_000,
            u64::MAX,
            0,
        )?;
        assert_eq!(
            allocated_table.estimate(1, &BTreeMap::from([(1, 1)])),
            Err(SizingError::ArithmeticOverflow {
                quantity: OverflowQuantity::AllocatedTableBytes,
            })
        );

        let position_map = SizingParameters::new(2, 1, 4, 2, 1, u64::MAX, 10_000, u64::MAX, 0)?;
        assert_eq!(
            position_map.estimate(1, &BTreeMap::from([(1, 1)])),
            Err(SizingError::ArithmeticOverflow {
                quantity: OverflowQuantity::LogicalPositionMapBytes,
            })
        );

        let near_maximum_width = (u64::MAX - 100) / 6;
        let logical_total =
            SizingParameters::new(2, 1, 4, 2, 1, near_maximum_width, 10_000, u64::MAX, 0)?;
        assert_eq!(
            logical_total.estimate(1, &BTreeMap::from([(1, 1)])),
            Err(SizingError::ArithmeticOverflow {
                quantity: OverflowQuantity::LogicalTotalBytes,
            })
        );

        let maximum_capacity = 1_u64 << 31;
        let backend_expanded = SizingParameters::new(
            maximum_capacity,
            maximum_capacity - 1,
            maximum_capacity,
            maximum_capacity - 2,
            1,
            1,
            u64::MAX,
            u64::MAX,
            0,
        )?;
        assert_eq!(
            backend_expanded.estimate(0, &BTreeMap::new()),
            Err(SizingError::ArithmeticOverflow {
                quantity: OverflowQuantity::BackendExpandedBytes,
            })
        );
        Ok(())
    }

    #[test]
    fn debug_redacts_internal_sizing_values() -> Result<(), SizingError> {
        let parameters = parameters(3_000, 3_000)?;
        let estimate = parameters.estimate(1, &BTreeMap::from([(1, 1)]))?;

        assert_eq!(
            format!("{parameters:?}"),
            "SizingParameters { ..REDACTED.. }"
        );
        assert_eq!(format!("{estimate:?}"), "StorageEstimate { ..REDACTED.. }");
        Ok(())
    }
}
