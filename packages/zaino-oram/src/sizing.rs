use std::{collections::BTreeMap, fmt};

use crate::records::PERSISTENT_UTXO_EVENT_BYTES;

const BASIS_POINTS_DENOMINATOR: u64 = 10_000;

/// Validated inputs for a deterministic storage-capacity estimate.
///
/// This model computes logical and backend-expanded byte counts. It does not
/// represent measured RSS, allocator overhead, runtime working memory, or host
/// swapping behavior; those remain hardware benchmark gates.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct SizingParameters {
    events_per_page: u64,
    event_record_bytes: u64,
    page_overhead_bytes: u64,
    directory_entry_bytes: u64,
    position_map_entry_bytes: u64,
    backend_expansion_bps: u64,
    tdx_memory_bytes: u64,
    required_headroom_bps: u64,
}

impl SizingParameters {
    /// Validates every parameter that would otherwise make the estimate
    /// undefined or understate backend storage. The event width is always
    /// derived from the compiled persistent candidate record.
    pub(super) const fn new(
        events_per_page: u64,
        page_overhead_bytes: u64,
        directory_entry_bytes: u64,
        position_map_entry_bytes: u64,
        backend_expansion_bps: u64,
        tdx_memory_bytes: u64,
        required_headroom_bps: u64,
    ) -> Result<Self, SizingError> {
        Self::new_with_event_record_bytes(
            events_per_page,
            PERSISTENT_UTXO_EVENT_BYTES as u64,
            page_overhead_bytes,
            directory_entry_bytes,
            position_map_entry_bytes,
            backend_expansion_bps,
            tdx_memory_bytes,
            required_headroom_bps,
        )
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "the private arithmetic-test seam validates every sizing dimension together"
    )]
    const fn new_with_event_record_bytes(
        events_per_page: u64,
        event_record_bytes: u64,
        page_overhead_bytes: u64,
        directory_entry_bytes: u64,
        position_map_entry_bytes: u64,
        backend_expansion_bps: u64,
        tdx_memory_bytes: u64,
        required_headroom_bps: u64,
    ) -> Result<Self, SizingError> {
        if events_per_page == 0 {
            return Err(SizingError::ZeroEventsPerPage);
        }
        if event_record_bytes == 0 {
            return Err(SizingError::ZeroEventRecordBytes);
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
            events_per_page,
            event_record_bytes,
            page_overhead_bytes,
            directory_entry_bytes,
            position_map_entry_bytes,
            backend_expansion_bps,
            tdx_memory_bytes,
            required_headroom_bps,
        })
    }

    /// Estimates storage from an aggregate histogram mapping events per address
    /// to the number of addresses in that bucket.
    ///
    /// Page counts are rounded up independently for each address bucket, so
    /// unused capacity in one address's final page is never assigned to another
    /// address. A zero-event address occupies a directory entry but no event
    /// page.
    pub(super) fn estimate(
        &self,
        address_count: u64,
        event_count_histogram: &BTreeMap<u64, u64>,
    ) -> Result<StorageEstimate, SizingError> {
        let mut histogram_address_count = 0_u64;
        let mut event_count = 0_u64;
        let mut page_count = 0_u64;

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

            let pages_per_address = events_per_address.div_ceil(self.events_per_page);
            let bucket_pages = checked_mul(
                pages_per_address,
                addresses_in_bucket,
                OverflowQuantity::PageCount,
            )?;
            page_count = checked_add(page_count, bucket_pages, OverflowQuantity::PageCount)?;
        }

        if histogram_address_count != address_count {
            return Err(SizingError::HistogramAddressCountMismatch {
                declared: address_count,
                histogram: histogram_address_count,
            });
        }

        let logical_event_bytes = checked_mul(
            event_count,
            self.event_record_bytes,
            OverflowQuantity::LogicalEventBytes,
        )?;
        let event_capacity_bytes_per_page = checked_mul(
            self.events_per_page,
            self.event_record_bytes,
            OverflowQuantity::LogicalPageBytes,
        )?;
        let fixed_page_bytes = checked_add(
            event_capacity_bytes_per_page,
            self.page_overhead_bytes,
            OverflowQuantity::LogicalPageBytes,
        )?;
        let logical_page_bytes = checked_mul(
            page_count,
            fixed_page_bytes,
            OverflowQuantity::LogicalPageBytes,
        )?;
        let logical_directory_bytes = checked_mul(
            address_count,
            self.directory_entry_bytes,
            OverflowQuantity::LogicalDirectoryBytes,
        )?;
        // Both address-directory lookup and event-page lookup are protected.
        // Counting only event pages would either understate the recursive map
        // or imply a plaintext directory keyed by the private address.
        let directory_position_map_bytes = checked_mul(
            address_count,
            self.position_map_entry_bytes,
            OverflowQuantity::LogicalPositionMapBytes,
        )?;
        let page_position_map_bytes = checked_mul(
            page_count,
            self.position_map_entry_bytes,
            OverflowQuantity::LogicalPositionMapBytes,
        )?;
        let logical_position_map_bytes = checked_add(
            directory_position_map_bytes,
            page_position_map_bytes,
            OverflowQuantity::LogicalPositionMapBytes,
        )?;
        let logical_total_bytes = checked_sum(
            [
                logical_page_bytes,
                logical_directory_bytes,
                logical_position_map_bytes,
            ],
            OverflowQuantity::LogicalTotalBytes,
        )?;
        let backend_expanded_bytes =
            apply_backend_expansion(logical_total_bytes, self.backend_expansion_bps)?;
        let usable_memory_bytes =
            usable_memory_after_headroom(self.tdx_memory_bytes, self.required_headroom_bps)?;

        Ok(StorageEstimate {
            address_count,
            event_count,
            page_count,
            logical_event_bytes,
            logical_page_bytes,
            logical_directory_bytes,
            logical_position_map_bytes,
            logical_total_bytes,
            backend_expanded_bytes,
            usable_memory_bytes,
            fits_memory: backend_expanded_bytes <= usable_memory_bytes,
        })
    }

    /// Returns the configured persisted event width used by reports.
    pub(super) const fn event_record_bytes(&self) -> u64 {
        self.event_record_bytes
    }
}

impl fmt::Debug for SizingParameters {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SizingParameters { ..REDACTED.. }")
    }
}

impl fmt::Display for SizingParameters {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "sizing_parameters=events_per_page:{},event_record_bytes:{},page_overhead_bytes:{},directory_entry_bytes:{},position_map_entry_bytes:{},backend_expansion_bps:{},tdx_memory_bytes:{},required_headroom_bps:{}",
            self.events_per_page,
            self.event_record_bytes,
            self.page_overhead_bytes,
            self.directory_entry_bytes,
            self.position_map_entry_bytes,
            self.backend_expansion_bps,
            self.tdx_memory_bytes,
            self.required_headroom_bps,
        )
    }
}

/// Deterministic byte and capacity results for one aggregate corpus histogram.
///
/// The values are model outputs, not measured process-memory observations.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct StorageEstimate {
    address_count: u64,
    event_count: u64,
    page_count: u64,
    logical_event_bytes: u64,
    logical_page_bytes: u64,
    logical_directory_bytes: u64,
    logical_position_map_bytes: u64,
    logical_total_bytes: u64,
    backend_expanded_bytes: u64,
    usable_memory_bytes: u64,
    fits_memory: bool,
}

impl StorageEstimate {
    /// Returns the declared number of address-directory entries.
    const fn address_count(&self) -> u64 {
        self.address_count
    }

    /// Returns the checked total number of events represented by the histogram.
    pub(super) const fn event_count(&self) -> u64 {
        self.event_count
    }

    /// Returns the sum of independently rounded-up per-address page counts.
    pub(super) const fn page_count(&self) -> u64 {
        self.page_count
    }

    /// Returns bytes occupied by logical event records.
    const fn logical_event_bytes(&self) -> u64 {
        self.logical_event_bytes
    }

    /// Returns bytes reserved by fixed-capacity pages, including dummy slots
    /// and page overhead.
    const fn logical_page_bytes(&self) -> u64 {
        self.logical_page_bytes
    }

    /// Returns bytes occupied by address-directory entries.
    const fn logical_directory_bytes(&self) -> u64 {
        self.logical_directory_bytes
    }

    /// Returns bytes occupied by address-directory and event-page position-map
    /// entries.
    const fn logical_position_map_bytes(&self) -> u64 {
        self.logical_position_map_bytes
    }

    /// Returns the sum of all logical storage components.
    const fn logical_total_bytes(&self) -> u64 {
        self.logical_total_bytes
    }

    /// Returns the logical total after upward-rounded backend expansion.
    pub(super) const fn backend_expanded_bytes(&self) -> u64 {
        self.backend_expanded_bytes
    }

    /// Returns configured TDX memory after reserving the required headroom.
    pub(super) const fn usable_memory_bytes(&self) -> u64 {
        self.usable_memory_bytes
    }

    /// Returns whether modeled backend bytes fit within usable configured
    /// memory. This is not evidence that measured RSS satisfies the same bound.
    pub(super) const fn fits_memory(&self) -> bool {
        self.fits_memory
    }
}

impl fmt::Debug for StorageEstimate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("StorageEstimate { ..REDACTED.. }")
    }
}

/// A sizing parameter or checked capacity calculation was invalid.
///
/// Error fields contain only configured or aggregate public sizing values; no
/// address key or per-address identity is retained.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SizingError {
    /// A page cannot hold zero events.
    ZeroEventsPerPage,
    /// A persisted event record cannot occupy zero bytes.
    ZeroEventRecordBytes,
    /// Backend expansion would understate logical bytes.
    BackendExpansionBelowMinimum {
        /// Rejected expansion factor in basis points.
        actual_bps: u64,
    },
    /// Required headroom must leave a nonempty basis-point range for usable
    /// memory.
    RequiredHeadroomOutOfRange {
        /// Rejected headroom in basis points.
        actual_bps: u64,
    },
    /// Histogram bucket address counts do not equal the declared address count.
    HistogramAddressCountMismatch {
        /// Address count supplied independently by the scanner.
        declared: u64,
        /// Sum of address counts in every histogram bucket.
        histogram: u64,
    },
    /// A named aggregate or byte calculation exceeded `u64`.
    ArithmeticOverflow {
        /// Calculation that could not be represented.
        quantity: OverflowQuantity,
    },
}

impl fmt::Display for SizingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroEventsPerPage => write!(f, "events per page must be nonzero"),
            Self::ZeroEventRecordBytes => write!(f, "event record bytes must be nonzero"),
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

impl std::error::Error for SizingError {}

/// Aggregate whose checked calculation overflowed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum OverflowQuantity {
    /// Sum of address counts represented by histogram buckets.
    HistogramAddressCount,
    /// Total events represented by the histogram.
    EventCount,
    /// Total independently allocated event pages.
    PageCount,
    /// Bytes occupied by event records.
    LogicalEventBytes,
    /// Bytes occupied by page overhead.
    LogicalPageBytes,
    /// Bytes occupied by directory entries.
    LogicalDirectoryBytes,
    /// Bytes occupied by position-map entries.
    LogicalPositionMapBytes,
    /// Sum of logical storage components.
    LogicalTotalBytes,
    /// Logical bytes after backend expansion.
    BackendExpandedBytes,
    /// Configured memory remaining after required headroom.
    UsableMemoryBytes,
}

impl OverflowQuantity {
    const fn description(self) -> &'static str {
        match self {
            Self::HistogramAddressCount => "histogram address count",
            Self::EventCount => "event count",
            Self::PageCount => "page count",
            Self::LogicalEventBytes => "logical event bytes",
            Self::LogicalPageBytes => "logical page bytes",
            Self::LogicalDirectoryBytes => "logical directory bytes",
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

fn checked_sum<const N: usize>(
    values: [u64; N],
    quantity: OverflowQuantity,
) -> Result<u64, SizingError> {
    values
        .into_iter()
        .try_fold(0_u64, |total, value| checked_add(total, value, quantity))
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

    #[expect(
        clippy::too_many_arguments,
        reason = "test helper mirrors the validated sizing schema"
    )]
    fn parameters(
        events_per_page: u64,
        event_record_bytes: u64,
        page_overhead_bytes: u64,
        directory_entry_bytes: u64,
        position_map_entry_bytes: u64,
        backend_expansion_bps: u64,
        tdx_memory_bytes: u64,
        required_headroom_bps: u64,
    ) -> Result<SizingParameters, SizingError> {
        SizingParameters::new_with_event_record_bytes(
            events_per_page,
            event_record_bytes,
            page_overhead_bytes,
            directory_entry_bytes,
            position_map_entry_bytes,
            backend_expansion_bps,
            tdx_memory_bytes,
            required_headroom_bps,
        )
    }

    #[test]
    fn normal_math_accounts_for_every_component_and_headroom() -> Result<(), SizingError> {
        let parameters = parameters(4, 10, 6, 8, 2, 12_500, 1_000, 3_000)?;
        let histogram = BTreeMap::from([(0, 1), (1, 2), (4, 1), (5, 1)]);

        let estimate = parameters.estimate(5, &histogram)?;

        assert_eq!(estimate.address_count(), 5);
        assert_eq!(estimate.event_count(), 11);
        assert_eq!(estimate.page_count(), 5);
        assert_eq!(estimate.logical_event_bytes(), 110);
        assert_eq!(estimate.logical_page_bytes(), 230);
        assert_eq!(estimate.logical_directory_bytes(), 40);
        assert_eq!(estimate.logical_position_map_bytes(), 20);
        assert_eq!(estimate.logical_total_bytes(), 290);
        assert_eq!(estimate.backend_expanded_bytes(), 363);
        assert_eq!(estimate.usable_memory_bytes(), 700);
        assert!(estimate.fits_memory());
        Ok(())
    }

    #[test]
    fn production_parameters_use_the_compiled_event_width() -> Result<(), SizingError> {
        let parameters = SizingParameters::new(4, 6, 8, 2, 12_500, 10_000, 3_000)?;

        assert_eq!(
            parameters.event_record_bytes(),
            PERSISTENT_UTXO_EVENT_BYTES as u64
        );
        Ok(())
    }

    #[test]
    fn zero_event_addresses_use_directory_but_no_pages() -> Result<(), SizingError> {
        let parameters = parameters(4, 10, 6, 8, 2, 10_000, 1_000, 0)?;
        let histogram = BTreeMap::from([(0, 3), (1, 2)]);

        let estimate = parameters.estimate(5, &histogram)?;

        assert_eq!(estimate.event_count(), 2);
        assert_eq!(estimate.page_count(), 2);
        assert_eq!(estimate.logical_event_bytes(), 20);
        assert_eq!(estimate.logical_page_bytes(), 92);
        assert_eq!(estimate.logical_directory_bytes(), 40);
        assert_eq!(estimate.logical_position_map_bytes(), 14);
        assert_eq!(estimate.logical_total_bytes(), 146);
        Ok(())
    }

    #[test]
    fn invalid_parameters_are_rejected() {
        assert_eq!(
            parameters(0, 1, 0, 0, 0, 10_000, 1, 0),
            Err(SizingError::ZeroEventsPerPage)
        );
        assert_eq!(
            parameters(1, 0, 0, 0, 0, 10_000, 1, 0),
            Err(SizingError::ZeroEventRecordBytes)
        );
        assert_eq!(
            parameters(1, 1, 0, 0, 0, 9_999, 1, 0),
            Err(SizingError::BackendExpansionBelowMinimum { actual_bps: 9_999 })
        );
        assert_eq!(
            parameters(1, 1, 0, 0, 0, 10_000, 1, 10_000),
            Err(SizingError::RequiredHeadroomOutOfRange { actual_bps: 10_000 })
        );
        assert_eq!(
            parameters(1, 1, 0, 0, 0, 10_000, 1, u64::MAX),
            Err(SizingError::RequiredHeadroomOutOfRange {
                actual_bps: u64::MAX,
            })
        );
    }

    #[test]
    fn page_ceil_is_applied_per_address() -> Result<(), SizingError> {
        let parameters = parameters(4, 1, 0, 0, 0, 10_000, u64::MAX, 0)?;
        let histogram = BTreeMap::from([(1, 1), (4, 1), (5, 1), (8, 1), (9, 1)]);

        let estimate = parameters.estimate(5, &histogram)?;

        assert_eq!(estimate.event_count(), 27);
        assert_eq!(estimate.page_count(), 9);
        Ok(())
    }

    #[test]
    fn histogram_must_account_for_declared_addresses() -> Result<(), SizingError> {
        let parameters = parameters(1, 1, 0, 0, 0, 10_000, 1, 0)?;
        let histogram = BTreeMap::from([(0, 2), (1, 1)]);

        assert_eq!(
            parameters.estimate(4, &histogram),
            Err(SizingError::HistogramAddressCountMismatch {
                declared: 4,
                histogram: 3,
            })
        );
        Ok(())
    }

    #[test]
    fn fit_uses_backend_expansion_and_headroom_adjusted_memory() -> Result<(), SizingError> {
        let histogram = BTreeMap::from([(1, 190)]);
        let fitting = parameters(1, 1, 0, 0, 0, 12_500, 340, 3_000)?;
        let too_small = parameters(1, 1, 0, 0, 0, 12_500, 339, 3_000)?;

        let fitting_estimate = fitting.estimate(190, &histogram)?;
        let too_small_estimate = too_small.estimate(190, &histogram)?;

        assert_eq!(fitting_estimate.backend_expanded_bytes(), 238);
        assert_eq!(fitting_estimate.usable_memory_bytes(), 238);
        assert!(fitting_estimate.fits_memory());
        assert_eq!(too_small_estimate.usable_memory_bytes(), 237);
        assert!(!too_small_estimate.fits_memory());
        Ok(())
    }

    #[test]
    fn every_unbounded_calculation_reports_overflow() -> Result<(), SizingError> {
        let unit = parameters(1, 1, 0, 0, 0, 10_000, u64::MAX, 0)?;
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

        let event_bytes = parameters(u64::MAX, 2, 0, 0, 0, 10_000, u64::MAX, 0)?;
        assert_eq!(
            event_bytes.estimate(1, &BTreeMap::from([(u64::MAX, 1)])),
            Err(SizingError::ArithmeticOverflow {
                quantity: OverflowQuantity::LogicalEventBytes,
            })
        );

        let page_bytes = parameters(1, 1, 2, 0, 0, 10_000, u64::MAX, 0)?;
        assert_eq!(
            page_bytes.estimate(u64::MAX, &BTreeMap::from([(1, u64::MAX)])),
            Err(SizingError::ArithmeticOverflow {
                quantity: OverflowQuantity::LogicalPageBytes,
            })
        );

        let directory_bytes = parameters(1, 1, 0, 2, 0, 10_000, u64::MAX, 0)?;
        assert_eq!(
            directory_bytes.estimate(u64::MAX, &BTreeMap::from([(0, u64::MAX)])),
            Err(SizingError::ArithmeticOverflow {
                quantity: OverflowQuantity::LogicalDirectoryBytes,
            })
        );

        let position_map_bytes = parameters(1, 1, 0, 0, 2, 10_000, u64::MAX, 0)?;
        assert_eq!(
            position_map_bytes.estimate(u64::MAX, &BTreeMap::from([(1, u64::MAX)])),
            Err(SizingError::ArithmeticOverflow {
                quantity: OverflowQuantity::LogicalPositionMapBytes,
            })
        );

        let logical_total = parameters(1, 1, 0, 1, 0, 10_000, u64::MAX, 0)?;
        assert_eq!(
            logical_total.estimate(u64::MAX, &BTreeMap::from([(1, u64::MAX)])),
            Err(SizingError::ArithmeticOverflow {
                quantity: OverflowQuantity::LogicalTotalBytes,
            })
        );

        let backend_expanded = parameters(1, 1, 0, 0, 0, 10_001, u64::MAX, 0)?;
        assert_eq!(
            backend_expanded.estimate(u64::MAX, &BTreeMap::from([(1, u64::MAX)])),
            Err(SizingError::ArithmeticOverflow {
                quantity: OverflowQuantity::BackendExpandedBytes,
            })
        );
        Ok(())
    }

    #[test]
    fn debug_redacts_while_display_records_the_public_model() -> Result<(), SizingError> {
        let parameters = parameters(4, 10, 6, 8, 2, 12_500, 1_000, 3_000)?;
        let estimate = parameters.estimate(1, &BTreeMap::from([(1, 1)]))?;

        assert_eq!(
            format!("{parameters:?}"),
            "SizingParameters { ..REDACTED.. }"
        );
        assert_eq!(format!("{estimate:?}"), "StorageEstimate { ..REDACTED.. }");
        assert_eq!(
            parameters.to_string(),
            "sizing_parameters=events_per_page:4,event_record_bytes:10,page_overhead_bytes:6,directory_entry_bytes:8,position_map_entry_bytes:2,backend_expansion_bps:12500,tdx_memory_bytes:1000,required_headroom_bps:3000\n"
        );
        Ok(())
    }
}
