//! Coherent Zaino capture, conversion, and recent-generation publication.
//!
//! This private build-stage controller publishes one atomic serving epoch only
//! after binding an owner-issued finalized store generation and identity, the
//! owner-assigned recent generation, opaque source boundary, and release-time
//! currentness capability. Its caller must still serialize refresh against
//! committed-finalized publication and retain the release guard through the
//! eventual transport boundary.

use std::{fmt, future::Future};

use zaino_state::chain_index::{
    types::{BlockIndex, FinalizedOutpointState},
    CanonicalTransparentProjectionBoundary, CanonicalTransparentProjectionInput,
    CanonicalTransparentProjectionInputError, ZebraNetwork,
};
use zaino_state::{BlockchainSource, NodeBackedChainIndexSubscriber, Outpoint};

use super::{
    FinalizedServingStore, RecentSnapshotPublicationError, RecentSnapshotPublicationOwner,
    RecentSnapshotUpdateTicket, ServingEpochBoundary, ServingEpochCurrentness, ServingEpochLease,
    ServingEpochObservation, ServingEpochPublicationOwner, ServingEpochUnavailable,
};
use crate::{
    canonical_chain::{CanonicalNetwork, PublicChainCheckpoint},
    recent_snapshot::{
        zaino::{
            convert_canonical_recent_snapshot, ConvertedRecentSnapshot,
            FinalizedOutpointClassification, FinalizedOutpointSnapshot,
            FinalizedOutpointSnapshotError,
        },
        RecentSnapshotIdentity,
    },
};

/// Builds and publishes recent snapshots from one live chain-index subscriber.
///
/// This type is intentionally private until the service layer supplies the
/// process-wide owner and transport integration. Within one instance it is the
/// only path from a coherent Zaino capture to an owner-assigned generation and
/// its atomic serving-epoch publication.
struct RecentSnapshotRefreshController<const N: usize, S, C> {
    owner: RecentSnapshotPublicationOwner<N>,
    serving_epoch: ServingEpochPublicationOwner<N, CanonicalTransparentProjectionBoundary, S, C>,
    network: CanonicalNetwork,
    schema_version: u32,
    projection_epoch: u64,
    key_epoch: u64,
}

impl<const N: usize, S, C> RecentSnapshotRefreshController<N, S, C>
where
    S: FinalizedServingStore,
    C: ServingEpochCurrentness<CanonicalTransparentProjectionBoundary>,
{
    fn new(
        network: CanonicalNetwork,
        schema_version: u32,
        projection_epoch: u64,
        key_epoch: u64,
    ) -> Result<Self, RecentSnapshotRefreshError> {
        if schema_version == 0 || projection_epoch == 0 {
            return Err(RecentSnapshotRefreshError::InvalidConfiguration);
        }

        Ok(Self {
            owner: RecentSnapshotPublicationOwner::new(),
            serving_epoch: ServingEpochPublicationOwner::new(),
            network,
            schema_version,
            projection_epoch,
            key_epoch,
        })
    }

    /// Owns the cancellation boundary so tests can hold capture pending
    /// without constructing a live database-backed subscriber.
    async fn refresh_from_capture<Capture, Current, Bind>(
        &mut self,
        committed_finalized: PublicChainCheckpoint,
        finalized_store: S,
        capture: Capture,
        current: Current,
        bind_currentness: Bind,
    ) -> Result<(), RecentSnapshotRefreshError>
    where
        Capture: Future<
            Output = Result<
                CanonicalTransparentProjectionInput,
                CanonicalTransparentProjectionInputError,
            >,
        >,
        Current: FnOnce(&CanonicalTransparentProjectionBoundary) -> Result<bool, ()>,
        Bind: FnOnce(RecentSnapshotIdentity, &CanonicalTransparentProjectionBoundary) -> C,
    {
        // Invalidate before the only await point. If this future is cancelled
        // during capture, no prior generation remains eligible for service.
        self.invalidate_before_capture();
        let input = match capture.await {
            Ok(input) => input,
            Err(_) => return Err(RecentSnapshotRefreshError::CaptureUnavailable),
        };

        if !captured_input_matches_committed(&input, self.network, committed_finalized) {
            return Err(RecentSnapshotRefreshError::InputRejected);
        }

        let recent_tip = input.recent().tip();
        let identity = serving_identity(
            self.network,
            committed_finalized.height(),
            committed_finalized.block_hash().bytes_in_display_order(),
            self.schema_version,
            self.projection_epoch,
            self.key_epoch,
        );
        let captured_boundary = input.boundary().clone();

        self.rebuild_candidate(
            identity,
            u32::from(recent_tip.height),
            recent_tip.hash.bytes_in_display_order(),
            || {
                let finalized = CapturedFinalizedOutpoints {
                    input: &input,
                    identity,
                };
                convert_canonical_recent_snapshot::<N, _>(input.recent(), &finalized)
                    .map_err(|_| ())
            },
            || {
                // This narrows the capture-to-activation window only. The
                // serving-epoch owner must recheck the paired boundary when a
                // response is released, because the source can advance after
                // this observation.
                current(&captured_boundary)
            },
        )?;

        // Publication of the atomic epoch is deliberately the final step. A
        // response can pin only after the recent generation, finalized
        // identity, and opaque source revision are bound in one Arc.
        let recent = self
            .owner
            .pin()
            .ok_or(RecentSnapshotRefreshError::PublicationRejected)?;
        let currentness = bind_currentness(identity, &captured_boundary);
        if let Err(error) = self.serving_epoch.publish(
            recent,
            identity,
            captured_boundary,
            finalized_store,
            currentness,
        ) {
            self.owner.clear_publication();
            return Err(map_publication_error(error));
        }
        Ok(())
    }

    /// Executes every post-capture step synchronously and consumes every ticket
    /// on failure. The closures keep tests independent of live database setup.
    fn rebuild_candidate<Build, Current>(
        &mut self,
        identity: RecentSnapshotIdentity,
        recent_tip_height: u32,
        recent_tip_hash_display: [u8; 32],
        build: Build,
        current: Current,
    ) -> Result<(), RecentSnapshotRefreshError>
    where
        Build: FnOnce() -> Result<ConvertedRecentSnapshot<N>, ()>,
        Current: FnOnce() -> Result<bool, ()>,
    {
        self.serving_epoch.clear();
        let ticket = self
            .owner
            .begin_update(identity, recent_tip_height, recent_tip_hash_display)
            .map_err(map_publication_error)?;

        let converted = match build() {
            Ok(converted) => converted,
            Err(()) => {
                self.consume_failed_update(ticket)?;
                return Err(RecentSnapshotRefreshError::BuildRejected);
            }
        };

        match current() {
            Ok(true) => {}
            Ok(false) => {
                self.consume_failed_update(ticket)?;
                return Err(RecentSnapshotRefreshError::SourceAdvanced);
            }
            Err(()) => {
                self.consume_failed_update(ticket)?;
                return Err(RecentSnapshotRefreshError::FreshnessUnavailable);
            }
        }

        self.owner
            .activate_converted(ticket, converted)
            .map_err(map_publication_error)
    }

    fn consume_failed_update(
        &mut self,
        ticket: RecentSnapshotUpdateTicket,
    ) -> Result<(), RecentSnapshotRefreshError> {
        self.owner
            .fail_update(ticket)
            .map_err(map_publication_error)
    }

    fn invalidate_before_capture(&mut self) {
        self.serving_epoch.clear();
        self.owner.clear_publication();
    }

    fn pin_serving_epoch(
        &self,
    ) -> Option<ServingEpochLease<N, CanonicalTransparentProjectionBoundary, S, C>> {
        self.serving_epoch.pin()
    }
}

impl<const N: usize, S, Source>
    RecentSnapshotRefreshController<N, S, CanonicalServingEpochCurrentness<Source>>
where
    S: FinalizedServingStore,
    Source: BlockchainSource,
{
    /// Captures asynchronously, requires one owner-issued finalized projection
    /// generation, then completes the ticketed update without another await.
    ///
    /// The caller must hold whatever exclusion protects that generation and its
    /// committed checkpoint through this call. The final source recheck rejects
    /// drift visible during the build; the bound observer repeats the check when
    /// runtime is ready to release a response.
    async fn refresh(
        &mut self,
        subscriber: &NodeBackedChainIndexSubscriber<Source>,
        committed_finalized: PublicChainCheckpoint,
        finalized_store: S,
    ) -> Result<(), RecentSnapshotRefreshError> {
        let currentness_subscriber = subscriber.clone();
        let network = self.network;
        let schema_version = self.schema_version;
        let projection_epoch = self.projection_epoch;
        let key_epoch = self.key_epoch;
        self.refresh_from_capture(
            committed_finalized,
            finalized_store,
            subscriber.capture_canonical_transparent_projection_input(),
            |captured| {
                subscriber
                    .current_canonical_transparent_projection_boundary()
                    .map(|current| captured.same_capture(&current))
                    .map_err(|_| ())
            },
            move |identity, boundary| {
                CanonicalServingEpochCurrentness::new(
                    currentness_subscriber,
                    network,
                    schema_version,
                    projection_epoch,
                    key_epoch,
                    identity,
                    boundary.clone(),
                )
            },
        )
        .await
    }
}

struct CanonicalServingEpochCurrentness<Source: BlockchainSource> {
    subscriber: NodeBackedChainIndexSubscriber<Source>,
    network: CanonicalNetwork,
    schema_version: u32,
    projection_epoch: u64,
    key_epoch: u64,
    bound_identity: RecentSnapshotIdentity,
    bound_boundary: CanonicalTransparentProjectionBoundary,
}

impl<Source: BlockchainSource> CanonicalServingEpochCurrentness<Source> {
    const fn new(
        subscriber: NodeBackedChainIndexSubscriber<Source>,
        network: CanonicalNetwork,
        schema_version: u32,
        projection_epoch: u64,
        key_epoch: u64,
        bound_identity: RecentSnapshotIdentity,
        bound_boundary: CanonicalTransparentProjectionBoundary,
    ) -> Self {
        Self {
            subscriber,
            network,
            schema_version,
            projection_epoch,
            key_epoch,
            bound_identity,
            bound_boundary,
        }
    }
}

impl<Source: BlockchainSource> ServingEpochCurrentness<CanonicalTransparentProjectionBoundary>
    for CanonicalServingEpochCurrentness<Source>
{
    fn binding(
        &self,
    ) -> Option<(
        RecentSnapshotIdentity,
        &CanonicalTransparentProjectionBoundary,
    )> {
        Some((self.bound_identity, &self.bound_boundary))
    }

    fn observe(
        &mut self,
    ) -> Result<
        ServingEpochObservation<CanonicalTransparentProjectionBoundary>,
        ServingEpochUnavailable,
    > {
        let boundary = self
            .subscriber
            .current_canonical_transparent_projection_boundary()
            .map_err(|_| ServingEpochUnavailable)?;
        if !network_matches(self.network, boundary.network()) {
            return Err(ServingEpochUnavailable);
        }
        let finalized = boundary.finalized();
        let identity = serving_identity(
            self.network,
            u32::from(finalized.height),
            finalized.hash.bytes_in_display_order(),
            self.schema_version,
            self.projection_epoch,
            self.key_epoch,
        );
        Ok(ServingEpochObservation::new(identity, boundary))
    }
}

impl ServingEpochBoundary for CanonicalTransparentProjectionBoundary {
    fn same_capture(&self, other: &Self) -> bool {
        CanonicalTransparentProjectionBoundary::same_capture(self, other)
    }
}

impl<const N: usize, S, C> fmt::Debug for RecentSnapshotRefreshController<N, S, C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RecentSnapshotRefreshController { ..REDACTED.. }")
    }
}

struct CapturedFinalizedOutpoints<'a> {
    input: &'a CanonicalTransparentProjectionInput,
    identity: RecentSnapshotIdentity,
}

impl FinalizedOutpointSnapshot for CapturedFinalizedOutpoints<'_> {
    fn identity(&self) -> RecentSnapshotIdentity {
        self.identity
    }

    fn classify(
        &self,
        outpoint: &Outpoint,
    ) -> Result<FinalizedOutpointClassification, FinalizedOutpointSnapshotError> {
        require_finalized_outpoint_state(self.input.classify_finalized_outpoint(outpoint))
    }
}

fn require_finalized_outpoint_state(
    state: Option<FinalizedOutpointState>,
) -> Result<FinalizedOutpointClassification, FinalizedOutpointSnapshotError> {
    state
        .map(map_finalized_outpoint_state)
        .ok_or(FinalizedOutpointSnapshotError)
}

fn captured_input_matches_committed(
    input: &CanonicalTransparentProjectionInput,
    expected_network: CanonicalNetwork,
    committed: PublicChainCheckpoint,
) -> bool {
    let checkpoint = input.finalized_checkpoint();
    finalized_checkpoint_matches_committed(input.network(), checkpoint, expected_network, committed)
        && network_matches(expected_network, input.boundary().network())
        && input.recent().finalized() == checkpoint
        && input.boundary().finalized() == checkpoint
        && input.boundary().tip() == input.recent().tip()
}

fn finalized_checkpoint_matches_committed(
    captured_network: &ZebraNetwork,
    checkpoint: BlockIndex,
    expected_network: CanonicalNetwork,
    committed: PublicChainCheckpoint,
) -> bool {
    committed.network() == expected_network
        && network_matches(expected_network, captured_network)
        && u32::from(checkpoint.height) == committed.height()
        && checkpoint.hash == *committed.block_hash()
}

fn map_finalized_outpoint_state(state: FinalizedOutpointState) -> FinalizedOutpointClassification {
    match state {
        FinalizedOutpointState::NeverSeen => FinalizedOutpointClassification::NeverSeen,
        FinalizedOutpointState::Spent => FinalizedOutpointClassification::Spent,
        FinalizedOutpointState::LiveStandard {
            address,
            value_zat,
            created_height,
        } => FinalizedOutpointClassification::LiveStandard {
            address,
            value_zat,
            created_height: u32::from(created_height),
        },
        FinalizedOutpointState::LiveNonStandard { created_height } => {
            FinalizedOutpointClassification::LiveNonStandard {
                created_height: u32::from(created_height),
            }
        }
    }
}

fn network_matches(expected: CanonicalNetwork, captured: &ZebraNetwork) -> bool {
    match expected {
        CanonicalNetwork::Mainnet => matches!(captured, ZebraNetwork::Mainnet),
        CanonicalNetwork::Testnet => {
            matches!(captured, ZebraNetwork::Testnet(_)) && !captured.is_regtest()
        }
        CanonicalNetwork::Regtest => captured.is_regtest(),
    }
}

const fn serving_identity(
    network: CanonicalNetwork,
    finalized_height: u32,
    finalized_hash_display: [u8; 32],
    schema_version: u32,
    projection_epoch: u64,
    key_epoch: u64,
) -> RecentSnapshotIdentity {
    RecentSnapshotIdentity::new(
        recent_network_tag(network),
        finalized_height,
        finalized_hash_display,
        schema_version,
        projection_epoch,
        key_epoch,
    )
}

const fn recent_network_tag(network: CanonicalNetwork) -> u8 {
    match network {
        CanonicalNetwork::Mainnet => 0,
        CanonicalNetwork::Testnet => 1,
        CanonicalNetwork::Regtest => 2,
    }
}

/// Coarsened controller failure without outpoint or checkpoint identifiers.
#[derive(Clone, Copy, PartialEq, Eq)]
enum RecentSnapshotRefreshError {
    InvalidConfiguration,
    CaptureUnavailable,
    InputRejected,
    BuildRejected,
    SourceAdvanced,
    FreshnessUnavailable,
    RebuildRequired,
    PublicationRejected,
}

impl fmt::Debug for RecentSnapshotRefreshError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RecentSnapshotRefreshError { ..REDACTED.. }")
    }
}

impl fmt::Display for RecentSnapshotRefreshError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfiguration => f.write_str("recent snapshot configuration rejected"),
            Self::CaptureUnavailable => f.write_str("recent snapshot capture unavailable"),
            Self::InputRejected => f.write_str("recent snapshot input rejected"),
            Self::BuildRejected => f.write_str("recent snapshot build rejected"),
            Self::SourceAdvanced => f.write_str("recent snapshot source advanced during build"),
            Self::FreshnessUnavailable => f.write_str("recent snapshot freshness unavailable"),
            Self::RebuildRequired => f.write_str("recent snapshot rebuild required"),
            Self::PublicationRejected => f.write_str("recent snapshot publication rejected"),
        }
    }
}

impl std::error::Error for RecentSnapshotRefreshError {}

const fn map_publication_error(
    error: RecentSnapshotPublicationError,
) -> RecentSnapshotRefreshError {
    match error {
        RecentSnapshotPublicationError::RebuildRequired => {
            RecentSnapshotRefreshError::RebuildRequired
        }
        RecentSnapshotPublicationError::InvalidUpdate
        | RecentSnapshotPublicationError::ActivationRejected => {
            RecentSnapshotRefreshError::PublicationRejected
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        recent_snapshot::RecentSnapshotSlot,
        records::AddressKey,
        store::{ObliviousStore, StoreSlot},
    };
    use zaino_state::{AddrScript, BlockHash, Height, ScriptType};

    const FINALIZED_HASH: [u8; 32] = [0x11; 32];
    const ADVANCED_FINALIZED_HASH: [u8; 32] = [0x12; 32];
    const TIP_HASH_A: [u8; 32] = [0x21; 32];
    const TIP_HASH_B: [u8; 32] = [0x22; 32];
    const SLOT_COUNT: usize = 2;

    type TestController =
        RecentSnapshotRefreshController<SLOT_COUNT, TestFinalizedStore, TestCurrentness>;
    type LiveController = RecentSnapshotRefreshController<
        SLOT_COUNT,
        TestFinalizedStore,
        CanonicalServingEpochCurrentness<zaino_state::ValidatorConnector>,
    >;

    struct TestFinalizedStore {
        identity: RecentSnapshotIdentity,
    }

    impl ObliviousStore for TestFinalizedStore {
        type Error = ();

        fn slots_per_key(&self) -> usize {
            4
        }

        fn read_slot(
            &mut self,
            _address_key: &AddressKey,
            _slot: usize,
        ) -> Result<StoreSlot, Self::Error> {
            Ok(StoreSlot::dummy())
        }
    }

    impl FinalizedServingStore for TestFinalizedStore {
        fn serving_identity(&self) -> RecentSnapshotIdentity {
            self.identity
        }
    }

    struct TestCurrentness;

    impl ServingEpochCurrentness<CanonicalTransparentProjectionBoundary> for TestCurrentness {
        fn binding(
            &self,
        ) -> Option<(
            RecentSnapshotIdentity,
            &CanonicalTransparentProjectionBoundary,
        )> {
            None
        }

        fn observe(
            &mut self,
        ) -> Result<
            ServingEpochObservation<CanonicalTransparentProjectionBoundary>,
            ServingEpochUnavailable,
        > {
            Err(ServingEpochUnavailable)
        }
    }

    fn identity(height: u32, hash: [u8; 32]) -> RecentSnapshotIdentity {
        RecentSnapshotIdentity::new(0, height, hash, 1, 7, 9)
    }

    fn committed_finalized() -> PublicChainCheckpoint {
        PublicChainCheckpoint::new(CanonicalNetwork::Mainnet, 100, BlockHash(FINALIZED_HASH))
    }

    fn candidate(
        finalized: RecentSnapshotIdentity,
        tip_height: u32,
        tip_hash: [u8; 32],
    ) -> ConvertedRecentSnapshot<SLOT_COUNT> {
        ConvertedRecentSnapshot::from_parts_for_tests(
            finalized,
            tip_height,
            tip_hash,
            [RecentSnapshotSlot::dummy(); SLOT_COUNT],
        )
    }

    fn controller() -> Result<TestController, RecentSnapshotRefreshError> {
        RecentSnapshotRefreshController::new(CanonicalNetwork::Mainnet, 1, 7, 9)
    }

    fn finalized_store() -> TestFinalizedStore {
        TestFinalizedStore {
            identity: identity(100, FINALIZED_HASH),
        }
    }

    fn rebuild(
        controller: &mut TestController,
        finalized: RecentSnapshotIdentity,
    ) -> Result<(), RecentSnapshotRefreshError> {
        controller.rebuild_candidate(
            finalized,
            102,
            TIP_HASH_A,
            || Ok(candidate(finalized, 102, TIP_HASH_A)),
            || Ok(true),
        )
    }

    fn active_generation(controller: &TestController) -> Result<u64, RecentSnapshotRefreshError> {
        controller
            .owner
            .pin()
            .map(|lease| lease.snapshot().lineage().generation())
            .ok_or(RecentSnapshotRefreshError::PublicationRejected)
    }

    #[test]
    fn validates_lifecycle_configuration() {
        assert!(matches!(
            TestController::new(CanonicalNetwork::Mainnet, 0, 7, 9,),
            Err(RecentSnapshotRefreshError::InvalidConfiguration)
        ));
        assert!(matches!(
            TestController::new(CanonicalNetwork::Mainnet, 1, 0, 9,),
            Err(RecentSnapshotRefreshError::InvalidConfiguration)
        ));
    }

    #[test]
    fn live_entrypoint_typechecks() {
        let _refresh = LiveController::refresh;
        let _pin = LiveController::pin_serving_epoch;
    }

    #[test]
    fn activates_only_after_freshness_recheck() -> Result<(), RecentSnapshotRefreshError> {
        let finalized = identity(100, FINALIZED_HASH);
        let mut controller = controller()?;

        rebuild(&mut controller, finalized)?;

        assert_eq!(active_generation(&controller)?, 1);
        let lease = controller
            .owner
            .pin()
            .ok_or(RecentSnapshotRefreshError::PublicationRejected)?;
        assert!(lease.is_current());
        Ok(())
    }

    #[test]
    fn failed_build_consumes_generation() -> Result<(), RecentSnapshotRefreshError> {
        let finalized = identity(100, FINALIZED_HASH);
        let mut controller = controller()?;

        assert_eq!(
            controller.rebuild_candidate(finalized, 102, TIP_HASH_A, || Err(()), || Ok(true)),
            Err(RecentSnapshotRefreshError::BuildRejected)
        );
        assert!(controller.owner.pin().is_none());
        assert!(controller.pin_serving_epoch().is_none());
        assert!(controller.owner.outstanding.is_none());

        rebuild(&mut controller, finalized)?;
        assert_eq!(active_generation(&controller)?, 2);
        Ok(())
    }

    #[test]
    fn stale_or_unavailable_freshness_fails_closed() -> Result<(), RecentSnapshotRefreshError> {
        let finalized = identity(100, FINALIZED_HASH);
        let mut controller = controller()?;

        assert_eq!(
            controller.rebuild_candidate(
                finalized,
                102,
                TIP_HASH_A,
                || Ok(candidate(finalized, 102, TIP_HASH_A)),
                || Ok(false),
            ),
            Err(RecentSnapshotRefreshError::SourceAdvanced)
        );
        assert_eq!(
            controller.rebuild_candidate(
                finalized,
                102,
                TIP_HASH_A,
                || Ok(candidate(finalized, 102, TIP_HASH_A)),
                || Err(()),
            ),
            Err(RecentSnapshotRefreshError::FreshnessUnavailable)
        );
        assert!(controller.owner.pin().is_none());
        assert!(controller.owner.outstanding.is_none());

        rebuild(&mut controller, finalized)?;
        assert_eq!(active_generation(&controller)?, 3);
        Ok(())
    }

    #[tokio::test]
    async fn cancellation_during_capture_invalidates_without_consuming_a_generation(
    ) -> Result<(), RecentSnapshotRefreshError> {
        let finalized = identity(100, FINALIZED_HASH);
        let mut controller = controller()?;
        rebuild(&mut controller, finalized)?;

        {
            let capture = std::future::pending::<
                Result<
                    CanonicalTransparentProjectionInput,
                    CanonicalTransparentProjectionInputError,
                >,
            >();
            let refresh = controller.refresh_from_capture(
                committed_finalized(),
                finalized_store(),
                capture,
                |_| Ok(true),
                |_, _| TestCurrentness,
            );
            tokio::pin!(refresh);
            tokio::select! {
                biased;
                result = &mut refresh => panic!("pending capture completed unexpectedly: {result:?}"),
                _ = async {} => {}
            }
        }

        assert!(controller.owner.pin().is_none());
        assert!(controller.owner.outstanding.is_none());

        rebuild(&mut controller, finalized)?;
        assert_eq!(active_generation(&controller)?, 2);
        Ok(())
    }

    #[test]
    fn finalized_rollback_requires_rebuild() -> Result<(), RecentSnapshotRefreshError> {
        let finalized = identity(100, FINALIZED_HASH);
        let mut controller = controller()?;
        rebuild(&mut controller, finalized)?;

        assert_eq!(
            controller.rebuild_candidate(
                identity(99, ADVANCED_FINALIZED_HASH),
                101,
                TIP_HASH_B,
                || Ok(candidate(finalized, 102, TIP_HASH_A)),
                || Ok(true),
            ),
            Err(RecentSnapshotRefreshError::RebuildRequired)
        );
        assert!(controller.owner.pin().is_none());
        assert!(controller.owner.outstanding.is_none());
        Ok(())
    }

    #[test]
    fn finalized_state_mapping_preserves_all_classes() {
        let address = AddrScript::new([0x45; 20], ScriptType::P2PKH as u8);
        let created_height =
            Height::try_from(77_u32).expect("fixture height is inside the supported chain range");

        assert!(matches!(
            map_finalized_outpoint_state(FinalizedOutpointState::NeverSeen),
            FinalizedOutpointClassification::NeverSeen
        ));
        assert!(matches!(
            map_finalized_outpoint_state(FinalizedOutpointState::Spent),
            FinalizedOutpointClassification::Spent
        ));
        assert!(matches!(
            map_finalized_outpoint_state(FinalizedOutpointState::LiveStandard {
                address,
                value_zat: 91,
                created_height,
            }),
            FinalizedOutpointClassification::LiveStandard {
                address: mapped_address,
                value_zat: 91,
                created_height: 77,
            } if mapped_address == address
        ));
        assert!(matches!(
            map_finalized_outpoint_state(FinalizedOutpointState::LiveNonStandard {
                created_height,
            }),
            FinalizedOutpointClassification::LiveNonStandard { created_height: 77 }
        ));
        assert!(require_finalized_outpoint_state(None).is_err());
    }

    #[test]
    fn network_and_committed_checkpoint_mapping_is_exact_and_redacted() {
        assert_eq!(recent_network_tag(CanonicalNetwork::Mainnet), 0);
        assert_eq!(recent_network_tag(CanonicalNetwork::Testnet), 1);
        assert_eq!(recent_network_tag(CanonicalNetwork::Regtest), 2);
        let checkpoint = BlockIndex {
            height: Height::try_from(100_u32)
                .expect("fixture height is inside the supported chain range"),
            hash: BlockHash(FINALIZED_HASH),
        };
        let committed = committed_finalized();
        let mainnet = ZebraNetwork::Mainnet;
        assert!(network_matches(CanonicalNetwork::Mainnet, &mainnet));
        assert!(!network_matches(CanonicalNetwork::Testnet, &mainnet));
        assert!(!network_matches(CanonicalNetwork::Regtest, &mainnet));
        assert!(finalized_checkpoint_matches_committed(
            &mainnet,
            checkpoint,
            CanonicalNetwork::Mainnet,
            committed,
        ));
        for (expected, candidate, published) in [
            (CanonicalNetwork::Testnet, checkpoint, committed),
            (
                CanonicalNetwork::Mainnet,
                checkpoint,
                PublicChainCheckpoint::new(
                    CanonicalNetwork::Testnet,
                    100,
                    BlockHash(FINALIZED_HASH),
                ),
            ),
            (
                CanonicalNetwork::Mainnet,
                BlockIndex {
                    height: Height::try_from(99_u32)
                        .expect("fixture height is inside the supported chain range"),
                    hash: BlockHash(FINALIZED_HASH),
                },
                committed,
            ),
            (
                CanonicalNetwork::Mainnet,
                BlockIndex {
                    height: checkpoint.height,
                    hash: BlockHash(ADVANCED_FINALIZED_HASH),
                },
                committed,
            ),
        ] {
            assert!(!finalized_checkpoint_matches_committed(
                &mainnet, candidate, expected, published,
            ));
        }
        assert_eq!(
            format!("{:?}", RecentSnapshotRefreshError::BuildRejected),
            "RecentSnapshotRefreshError { ..REDACTED.. }"
        );
        assert_eq!(
            format!("{:?}", controller().expect("valid fixture configuration")),
            "RecentSnapshotRefreshController { ..REDACTED.. }"
        );
    }
}
