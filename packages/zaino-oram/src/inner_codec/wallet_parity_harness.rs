//! Test-support seam that lets a test form a **real** private query.
//!
//! # This is not, and cannot become, a production API
//!
//! A real wallet cannot do what this module does, and the reason is not that
//! the client code has not been written yet. Two values a request must carry
//! are never published by the protocol:
//!
//! 1. **`session_binding`** — 32 bytes minted per security lease from OS
//!    entropy ([`super::security_owner::SecurityLeaseIdentity::mint`]). It is
//!    bound into the AEAD protection context *and* written into the request
//!    body, where [`super::PrivateQueryCodec::decode_request_with_nonce`]
//!    validates it. It appears in no `.proto` file and in no wire message.
//! 2. **The serving checkpoint** — network, height, block hash, schema
//!    version, projection epoch, and key epoch. A request whose checkpoint
//!    differs from the runtime's serving checkpoint is answered
//!    `ProjectionNotReady`. `BootstrapResponse` publishes only `key_epoch`.
//!
//! This module hands both out *from the composed runtime's own internals*.
//! Publishing them on the wire is a real option, but it is a security decision
//! that needs its own ADR; until that decision is made there is no
//! client-constructible request, and therefore no way to check that the private
//! query path returns correct answers. This harness closes that correctness gap
//! without making the security decision.
//!
//! Because a value obtained this way can only come from inside the server
//! process, nothing here can be mistaken for something a deployed wallet could
//! call: [`wallet_parity_harness`] returns the wallet material *and* the
//! serving runtime from one call, so possessing a [`WalletSession`] already
//! means possessing the server.
//!
//! # What is real here
//!
//! Everything cryptographic. The envelopes are sealed and opened by
//! [`super::xchacha20::XChaCha20EnvelopeProtector`] — the same
//! XChaCha20-Poly1305 protector the runtime holds — through the same
//! [`super::PrivateQueryCodec`]. There is no stand-in transform anywhere in
//! this module. The replay guard is the real crash-durable replay journal.
//!
//! # What is not real here
//!
//! The projection underneath is built on the **in-memory qualification
//! backend**, not the typed ORAM backend, so this harness establishes *answer
//! correctness only* and makes no obliviousness claim whatsoever.
//! [`super::private_service::FinalizedProjectionBuilder`] refuses that backend
//! on purpose, and this module deliberately does not go through it. The serving
//! epoch is published directly rather than captured from a live chain
//! subscriber.

use std::path::PathBuf;

use zaino_state::{AddrScript, IndexedBlock};
use zeroize::Zeroizing;

use super::{
    private_service::{
        PrivateNetwork as ServiceNetwork, PrivateProjectionShape, ReleasableSessionKeys,
        SessionBootstrap,
    },
    runtime::PrivateQueryRuntime,
    security_owner::{
        xchacha20_security_lease, OsEntropy, OwnedRoundMaterialSource, RoundEntropy,
        SecurityLeaseIdentity, SystemRoundClock,
    },
    xchacha20::XChaCha20EnvelopeProtector,
    PrivateQueryCheckpoint, PrivateQueryCodec, PrivateQueryRequest, ENVELOPE_NONCE_BYTES,
    SESSION_BINDING_BYTES,
};
use crate::{
    continuation_token::ContinuationToken,
    envelope::FixedEnvelope,
    layout::{derive_standard_address_key, StandardAddress, StandardScriptKind},
    private_runtime::{FixedEnvelopeRuntime, PendingFixedEnvelope, PrivateQueryUnavailable},
    profile::{
        mainnet_utxo_history_profile, CompiledQueryShape, MAINNET_ENVELOPE_BYTES,
        MAINNET_QUERY_SLOTS,
    },
    projection_owner::{FinalizedProjectionServingStore, OfflineProjectionOwner},
    recent_snapshot::{
        serving_epoch_for_tests, FinalizedServingStore, FrozenRecentSnapshot,
        RecentSnapshotIdentity, RecentSnapshotLineage, RecentSnapshotSlot, ServingEpochBoundary,
        ServingEpochCurrentness, ServingEpochObservation, ServingEpochUnavailable,
    },
    records::{QueryOutcome, TransparentUtxo, UtxoQuery, ADDRESS_KEY_BYTES},
    xchacha20::KEY_BYTES,
};

/// Exact envelope width every harness request and response carries.
pub const PARITY_ENVELOPE_BYTES: usize = MAINNET_ENVELOPE_BYTES;

/// The compiled profile admits a single in-flight command.
const QUEUE_CAPACITY: usize = 1;

/// Why a harness could not be built or a wallet round could not be formed.
///
/// Deliberately not coarsened the way the serving surface's failures are: this
/// type never reaches a client, and a test that cannot tell "the projection
/// refused this block" from "the envelope did not authenticate" is a test that
/// cannot be debugged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParityHarnessError {
    /// The compiled mainnet profile or its shape did not validate.
    Profile,
    /// The requested projection shape was rejected before any chain work.
    ProjectionShape,
    /// A projection worker could not be allocated on the memory backend.
    ProjectionBackend,
    /// A canonical block was rejected, or no block was applied at all.
    ProjectionChain,
    /// The completed projection could not be sealed into a serving store.
    ProjectionSeal,
    /// The operating-system generator refused to produce key or nonce bytes.
    Entropy,
    /// The crash-durable replay journal could not be opened.
    ReplayJournal,
    /// The runtime refused to activate the published serving epoch.
    ServingEpoch,
    /// A request could not be sealed under the session's protection context.
    Seal,
    /// A response envelope did not authenticate or did not parse.
    Open,
    /// The runtime refused the round.
    Refused,
}

impl std::fmt::Display for ParityHarnessError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Profile => "compiled profile did not validate",
            Self::ProjectionShape => "projection shape was rejected",
            Self::ProjectionBackend => "projection worker could not be allocated",
            Self::ProjectionChain => "canonical block was rejected",
            Self::ProjectionSeal => "projection could not be sealed for serving",
            Self::Entropy => "operating-system generator refused",
            Self::ReplayJournal => "replay journal could not be opened",
            Self::ServingEpoch => "serving epoch was refused",
            Self::Seal => "request could not be sealed",
            Self::Open => "response could not be opened",
            Self::Refused => "runtime refused the round",
        })
    }
}

impl std::error::Error for ParityHarnessError {}

/// One transparent UTXO as a wallet reads it out of an opened response.
///
/// Plain owned data rather than the crate's fixed record: a caller comparing
/// against an ordinary source has its own representation, and the point of this
/// type is to be trivially comparable with one.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct WalletUtxo {
    /// Transaction identifier in Zaino's internal byte order.
    pub txid: [u8; 32],
    /// Transparent output index.
    pub output_index: u32,
    /// Output value in zatoshis.
    pub value_zat: u64,
    /// Mined block height.
    pub height: u32,
    /// Exact transparent locking script.
    pub script: Vec<u8>,
}

impl WalletUtxo {
    fn from_record(utxo: &TransparentUtxo) -> Self {
        let script_len = utxo.script_len();
        let padded = utxo.padded_script();
        Self {
            txid: *utxo.txid(),
            output_index: utxo.output_index(),
            value_zat: utxo.value_zat(),
            height: utxo.height(),
            script: padded.get(..script_len).unwrap_or_default().to_vec(),
        }
    }

    /// Orders a set canonically so two sources can be compared as sequences.
    fn canonical_key(&self) -> ([u8; 32], u32) {
        (self.txid, self.output_index)
    }
}

/// The outcome byte a wallet reads out of an opened response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalletOutcome {
    /// Every matching record fit in the profile's result budget.
    Complete,
    /// More matching records existed than the profile permits returning.
    ResultBudgetExceeded,
    /// The request carried no valid address-key domain value.
    InvalidDomain,
    /// The store could not complete at least one logical read.
    StoreFailure,
    /// No ready projection answered this round.
    ProjectionNotReady,
    /// The continuation was invalid, expired, mismatched, or replayed.
    InvalidContinuation,
}

impl WalletOutcome {
    fn from_outcome(outcome: QueryOutcome) -> Option<Self> {
        Some(match outcome {
            QueryOutcome::Complete => Self::Complete,
            QueryOutcome::ResultBudgetExceeded => Self::ResultBudgetExceeded,
            QueryOutcome::InvalidDomain => Self::InvalidDomain,
            QueryOutcome::StoreFailure => Self::StoreFailure,
            QueryOutcome::ProjectionNotReady => Self::ProjectionNotReady,
            QueryOutcome::InvalidContinuation => Self::InvalidContinuation,
            _ => return None,
        })
    }
}

/// An opaque continuation a wallet echoes back to fetch the next page.
///
/// Opaque on purpose: the token is sealed under the runtime's token key, which
/// [`super::private_service::ReleasableSessionKeys`] deliberately withholds, so
/// a wallet can only replay one it was handed.
#[derive(Clone)]
pub struct WalletContinuation(ContinuationToken);

impl std::fmt::Debug for WalletContinuation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("WalletContinuation { ..REDACTED.. }")
    }
}

/// One decoded response page.
#[derive(Debug, Clone)]
pub struct WalletPage {
    /// Protected outcome the runtime reported.
    pub outcome: WalletOutcome,
    /// Every occupied result slot, in slot order.
    pub utxos: Vec<WalletUtxo>,
    /// Whether a further page remains.
    pub has_more: bool,
    /// The continuation to echo back when `has_more` is set.
    pub continuation: Option<WalletContinuation>,
}

/// Reports the first way `returned` differs from `expected` as a set of UTXOs.
///
/// Order-insensitive by construction: both sides are sorted on
/// `(txid, output_index)` first, because neither the private page's slot order
/// nor an ordinary source's row order is part of either contract. Returning a
/// description rather than a bool keeps a failing parity assertion debuggable
/// without the caller reimplementing the diff.
///
/// Platform-independent and free of every runtime type, so it is unit-testable
/// wherever this crate compiles.
pub fn parity_mismatch(returned: &[WalletUtxo], expected: &[WalletUtxo]) -> Option<String> {
    let mut returned = returned.to_vec();
    let mut expected = expected.to_vec();
    returned.sort_by_key(WalletUtxo::canonical_key);
    expected.sort_by_key(WalletUtxo::canonical_key);
    if returned.len() != expected.len() {
        return Some(format!(
            "returned {} utxos, ordinary source has {}",
            returned.len(),
            expected.len()
        ));
    }
    for (index, (returned, expected)) in returned.iter().zip(expected.iter()).enumerate() {
        if returned != expected {
            return Some(format!(
                "utxo {index} differs: returned {returned:?}, ordinary {expected:?}"
            ));
        }
    }
    None
}

/// The wallet half of one harness session.
///
/// Holds exactly what a wallet would hold if the two unpublished values were
/// published: the two releasable keys (inside a real protector), the session
/// binding, and the serving checkpoint. It holds no store, no token key, and no
/// journal.
pub struct WalletSession {
    codec: PrivateQueryCodec<MAINNET_QUERY_SLOTS, MAINNET_ENVELOPE_BYTES>,
    protector: XChaCha20EnvelopeProtector,
    checkpoint: PrivateQueryCheckpoint,
    network: crate::layout::LayoutNetwork,
    schema_version: u32,
}

impl std::fmt::Debug for WalletSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("WalletSession { ..REDACTED.. }")
    }
}

impl WalletSession {
    /// Derives the canonical address key this deployment indexes `address` under.
    fn address_key_bytes(&self, address: &AddrScript) -> Option<[u8; ADDRESS_KEY_BYTES]> {
        let kind = match address.script_type() {
            0x00 => StandardScriptKind::PayToPublicKeyHash,
            0x01 => StandardScriptKind::PayToScriptHash,
            _ => return None,
        };
        Some(
            *derive_standard_address_key(
                self.network,
                self.schema_version,
                StandardAddress::new(kind, *address.hash()),
            )
            .as_bytes(),
        )
    }

    /// Seals one real query for `address` at or above `minimum_height`.
    pub fn seal_query(
        &self,
        address: &AddrScript,
        minimum_height: u32,
        continuation: Option<&WalletContinuation>,
    ) -> Result<[u8; PARITY_ENVELOPE_BYTES], ParityHarnessError> {
        let key = self
            .address_key_bytes(address)
            .ok_or(ParityHarnessError::Seal)?;
        self.seal_untrusted_query(&key, minimum_height, continuation)
    }

    /// Seals a query from raw address-key bytes, valid domain or not.
    ///
    /// A wallet with a corrupt or wrong-width key produces exactly this
    /// envelope, and it is the only way to drive the `InvalidDomain` outcome
    /// through the real codec.
    pub fn seal_untrusted_query(
        &self,
        address_key_bytes: &[u8],
        minimum_height: u32,
        continuation: Option<&WalletContinuation>,
    ) -> Result<[u8; PARITY_ENVELOPE_BYTES], ParityHarnessError> {
        let query = UtxoQuery::from_untrusted_address_key(address_key_bytes, minimum_height);
        let request = PrivateQueryRequest::new(
            self.checkpoint,
            query,
            continuation.map(|token| token.0.clone()),
        );
        let mut nonce = [0; ENVELOPE_NONCE_BYTES];
        OsEntropy
            .fill(&mut nonce)
            .map_err(|_| ParityHarnessError::Entropy)?;
        self.codec
            .encode_request(&request, nonce, &self.protector)
            .map(|envelope| *envelope.as_bytes())
            .map_err(|_| ParityHarnessError::Seal)
    }

    /// Opens one response envelope under the session's response key.
    pub fn open_response(
        &self,
        envelope: &[u8; PARITY_ENVELOPE_BYTES],
    ) -> Result<WalletPage, ParityHarnessError> {
        let response = self
            .codec
            .decode_response(&FixedEnvelope::from_array(*envelope), &self.protector)
            .map_err(|_| ParityHarnessError::Open)?;
        let (page, has_more, continuation) = response.into_wallet_parts();
        let outcome =
            WalletOutcome::from_outcome(page.outcome()).ok_or(ParityHarnessError::Open)?;
        let utxos = page
            .slots()
            .iter()
            .filter(|slot| slot.is_occupied())
            .map(|slot| WalletUtxo::from_record(slot.padded_utxo()))
            .collect();
        Ok(WalletPage {
            outcome,
            utxos,
            has_more,
            continuation: continuation.map(WalletContinuation),
        })
    }
}

/// One released response envelope.
pub struct ParityPendingResponse {
    envelope: [u8; PARITY_ENVELOPE_BYTES],
}

impl PendingFixedEnvelope<PARITY_ENVELOPE_BYTES> for ParityPendingResponse {
    fn try_release_bytes(&self) -> Result<&[u8; PARITY_ENVELOPE_BYTES], PrivateQueryUnavailable> {
        Ok(&self.envelope)
    }
}

impl std::fmt::Debug for ParityPendingResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ParityPendingResponse { ..REDACTED.. }")
    }
}

/// The serving half of one harness, plus the seam that hands out the two
/// unpublished values.
pub trait WalletParityRuntime: FixedEnvelopeRuntime<PARITY_ENVELOPE_BYTES> {
    /// Returns the wallet material for the runtime's current serving epoch.
    ///
    /// Re-derived per call rather than cached: [`Self::republish`] moves the
    /// serving checkpoint, and a session held across that boundary is exactly
    /// the stale-checkpoint case a test needs to be able to drive.
    fn wallet_session(&self) -> Result<WalletSession, ParityHarnessError>;

    /// Returns the bootstrap material a listener publishes for this harness.
    ///
    /// Exactly the surface a deployed runtime publishes -- key epoch, the two
    /// releasable keys, and the compiled profile identifier -- and nothing
    /// more. It is *insufficient* to form a request, which is the whole reason
    /// this module exists; [`Self::wallet_session`] is where the two
    /// unpublished values come from.
    fn session_bootstrap(&self) -> Result<SessionBootstrap, ParityHarnessError>;

    /// Replaces the serving generation with one built from `blocks`.
    ///
    /// This is the harness's stand-in for a refresh, and only for the epoch
    /// swap: it publishes the new generation directly instead of capturing it
    /// from a live subscriber, because the capture type a subscriber produces
    /// has no constructor outside a live chain index.
    fn republish(&mut self, blocks: &[IndexedBlock]) -> Result<(), ParityHarnessError>;
}

/// Freshness observer for a generation published without a live source.
///
/// Answers "still current" from the identity it was published with, because
/// there is no source that could have advanced: the harness owns the whole
/// chain it built the generation from.
struct StaticCurrentness {
    identity: RecentSnapshotIdentity,
    boundary: StaticBoundary,
}

impl ServingEpochCurrentness<StaticBoundary> for StaticCurrentness {
    fn binding(&self) -> Option<(RecentSnapshotIdentity, &StaticBoundary)> {
        Some((self.identity, &self.boundary))
    }

    fn observe(
        &mut self,
    ) -> Result<ServingEpochObservation<StaticBoundary>, ServingEpochUnavailable> {
        Ok(ServingEpochObservation::new(
            self.identity,
            self.boundary.clone(),
        ))
    }
}

/// One capture revision, distinguished by allocation exactly as the live
/// boundary is.
#[derive(Clone)]
struct StaticBoundary {
    revision: std::sync::Arc<()>,
}

impl StaticBoundary {
    fn new() -> Self {
        Self {
            revision: std::sync::Arc::new(()),
        }
    }
}

impl ServingEpochBoundary for StaticBoundary {
    fn same_capture(&self, other: &Self) -> bool {
        std::sync::Arc::ptr_eq(&self.revision, &other.revision)
    }
}

type HarnessRuntime<E, T, R, N> = PrivateQueryRuntime<
    FinalizedProjectionServingStore,
    E,
    T,
    R,
    N,
    StaticCurrentness,
    StaticBoundary,
    MAINNET_QUERY_SLOTS,
    MAINNET_ENVELOPE_BYTES,
    MAINNET_QUERY_SLOTS,
>;

struct Harness<E, T, R, N> {
    runtime: HarnessRuntime<E, T, R, N>,
    shape: PrivateProjectionShape,
    session_binding: [u8; SESSION_BINDING_BYTES],
    request_key: [u8; KEY_BYTES],
    response_key: [u8; KEY_BYTES],
}

impl<E, T, R, N> std::fmt::Debug for Harness<E, T, R, N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Harness { ..REDACTED.. }")
    }
}

/// Builds one finalized serving generation over the in-memory qualification
/// backend.
///
/// Not [`super::private_service::FinalizedProjectionBuilder`], and the
/// difference is the whole obliviousness claim: that builder fails closed
/// without the typed ORAM backend, and this one deliberately uses the
/// non-oblivious memory tables so a correctness check can run on any host.
fn memory_backed_serving_store(
    shape: &PrivateProjectionShape,
    blocks: &[IndexedBlock],
) -> Result<FinalizedProjectionServingStore, ParityHarnessError> {
    let directory_capacity = usize::try_from(shape.directory_capacity)
        .map_err(|_| ParityHarnessError::ProjectionShape)?;
    let event_capacity =
        usize::try_from(shape.event_capacity).map_err(|_| ParityHarnessError::ProjectionShape)?;
    let mut owner = OfflineProjectionOwner::new_on_qualification_memory(
        shape
            .projection_config()
            .map_err(|_| ParityHarnessError::ProjectionShape)?,
        shape
            .layout()
            .map_err(|_| ParityHarnessError::ProjectionShape)?,
        directory_capacity,
        event_capacity,
        QUEUE_CAPACITY,
    )
    .map_err(|_| ParityHarnessError::ProjectionBackend)?;

    let mut target = None;
    for block in blocks {
        target = Some(
            owner
                .apply_finalized(block)
                .map_err(|_| ParityHarnessError::ProjectionChain)?,
        );
    }
    let target = target.ok_or(ParityHarnessError::ProjectionChain)?;
    if owner
        .finish(target)
        .map_err(|_| ParityHarnessError::ProjectionSeal)?
        != target
    {
        return Err(ParityHarnessError::ProjectionSeal);
    }
    owner
        .into_serving_store()
        .map_err(|_| ParityHarnessError::ProjectionSeal)
}

/// Publishes one serving epoch over `store` with an empty recent snapshot.
///
/// Empty is correct rather than convenient: the harness treats every supplied
/// block as finalized, so there is no non-finalized state for the recent
/// snapshot to carry.
fn published_serving_epoch(
    mut store: FinalizedProjectionServingStore,
) -> Result<
    crate::recent_snapshot::ServingEpochLease<
        MAINNET_QUERY_SLOTS,
        StaticBoundary,
        FinalizedProjectionServingStore,
        StaticCurrentness,
    >,
    ParityHarnessError,
> {
    let identity = store.serving_identity();
    let lineage = RecentSnapshotLineage::from_parts_for_tests(
        1,
        identity,
        identity.finalized_height(),
        *identity.finalized_hash_display(),
    )
    .map_err(|_| ParityHarnessError::ServingEpoch)?;
    let snapshot = FrozenRecentSnapshot::from_parts_for_tests(
        lineage,
        [RecentSnapshotSlot::dummy(); MAINNET_QUERY_SLOTS],
    );
    // Run the real annotation pass before publishing. The query reads stored
    // annotations and never recomputes the join (ADR 0902), so an unannotated
    // record would answer `ProjectionNotReady` rather than its UTXOs. Every
    // address this projection appended to is the pass's visit set: there is no
    // previous generation to correct, and the snapshot is empty.
    let visit = store.appended_addresses().clone();
    let slots = *snapshot.scan().slots();
    store
        .annotate_generation(&visit, &|owner, record| {
            Some(crate::engine::annotate_record(owner, record, &slots))
        })
        .map_err(|_| ParityHarnessError::ServingEpoch)?;

    let boundary = StaticBoundary::new();
    let currentness = StaticCurrentness {
        identity: snapshot.identity(),
        boundary: boundary.clone(),
    };
    Ok(serving_epoch_for_tests(
        snapshot,
        boundary,
        store,
        currentness,
    ))
}

fn draw_key() -> Result<[u8; KEY_BYTES], ParityHarnessError> {
    let mut bytes = [0; KEY_BYTES];
    OsEntropy
        .fill(&mut bytes)
        .map_err(|_| ParityHarnessError::Entropy)?;
    Ok(bytes)
}

/// Composes one harness: a real serving runtime over `blocks`, plus the wallet
/// material for it.
///
/// `replay_journal_root` receives the deployment's real crash-durable replay
/// journal; nothing about the replay path is simulated.
pub fn wallet_parity_harness(
    shape: &PrivateProjectionShape,
    blocks: &[IndexedBlock],
    replay_journal_root: PathBuf,
    service_namespace_id: [u8; 16],
    owner_generation: u64,
) -> Result<
    impl WalletParityRuntime<PendingResponse: Send + 'static> + Send + 'static,
    ParityHarnessError,
> {
    let profile = mainnet_utxo_history_profile().map_err(|_| ParityHarnessError::Profile)?;
    let compiled = CompiledQueryShape::<MAINNET_QUERY_SLOTS, MAINNET_ENVELOPE_BYTES>::new(profile)
        .map_err(|_| ParityHarnessError::Profile)?;

    let request_key = draw_key()?;
    let response_key = draw_key()?;
    let token_key = draw_key()?;
    let journal_key = draw_key()?;

    let deployment = super::composition::RuntimeDeployment {
        service_namespace_id,
        owner_generation,
        key_epoch: shape.key_epoch,
        replay_journal_root,
    };
    let replay_guard =
        super::composition::open_replay_journal(&deployment, &profile, Zeroizing::new(journal_key))
            .map_err(|_| ParityHarnessError::ReplayJournal)?;
    let identity = SecurityLeaseIdentity::mint(
        shape.key_epoch,
        service_namespace_id,
        owner_generation,
        &mut OsEntropy,
    )
    .map_err(|_| ParityHarnessError::Entropy)?;
    let lease = xchacha20_security_lease(
        compiled,
        identity,
        Zeroizing::new(request_key),
        Zeroizing::new(response_key),
        Zeroizing::new(token_key),
        replay_guard,
        OwnedRoundMaterialSource::new(OsEntropy, SystemRoundClock),
    );
    let session_binding = lease.session_binding();

    let store = memory_backed_serving_store(shape, blocks)?;
    let serving_epoch = published_serving_epoch(store)?;
    let runtime = HarnessRuntime::from_finalized_serving_epoch(serving_epoch, compiled, lease)
        .map_err(|_| ParityHarnessError::ServingEpoch)?;

    Ok(Harness {
        runtime,
        shape: *shape,
        session_binding,
        request_key,
        response_key,
    })
}

impl<E, T, R, N> FixedEnvelopeRuntime<PARITY_ENVELOPE_BYTES> for Harness<E, T, R, N>
where
    E: super::EnvelopeProtector,
    T: crate::continuation_token::ContinuationTokenProtector,
    R: crate::continuation_token::ContinuationReplayGuard,
    N: super::security_owner::RoundMaterialSource,
{
    type PendingResponse = ParityPendingResponse;

    fn query_page(
        &mut self,
        request: [u8; PARITY_ENVELOPE_BYTES],
    ) -> Result<Self::PendingResponse, PrivateQueryUnavailable> {
        let round = self
            .runtime
            .handle(&FixedEnvelope::from_array(request))
            .map_err(|_| PrivateQueryUnavailable)?;
        Ok(ParityPendingResponse {
            envelope: *round.envelope().as_bytes(),
        })
    }
}

impl<E, T, R, N> WalletParityRuntime for Harness<E, T, R, N>
where
    E: super::EnvelopeProtector,
    T: crate::continuation_token::ContinuationTokenProtector,
    R: crate::continuation_token::ContinuationReplayGuard,
    N: super::security_owner::RoundMaterialSource,
{
    fn wallet_session(&self) -> Result<WalletSession, ParityHarnessError> {
        let profile = mainnet_utxo_history_profile().map_err(|_| ParityHarnessError::Profile)?;
        let compiled =
            CompiledQueryShape::<MAINNET_QUERY_SLOTS, MAINNET_ENVELOPE_BYTES>::new(profile)
                .map_err(|_| ParityHarnessError::Profile)?;
        let codec = PrivateQueryCodec::new(&compiled, self.session_binding)
            .map_err(|_| ParityHarnessError::Profile)?;
        Ok(WalletSession {
            codec,
            protector: XChaCha20EnvelopeProtector::new(
                Zeroizing::new(self.request_key),
                Zeroizing::new(self.response_key),
            ),
            checkpoint: self
                .runtime
                .serving_checkpoint()
                .ok_or(ParityHarnessError::ServingEpoch)?,
            network: layout_network(self.shape.network),
            schema_version: self.shape.schema_version,
        })
    }

    fn session_bootstrap(&self) -> Result<SessionBootstrap, ParityHarnessError> {
        let profile = mainnet_utxo_history_profile().map_err(|_| ParityHarnessError::Profile)?;
        Ok(SessionBootstrap {
            key_epoch: self.shape.key_epoch,
            keys: ReleasableSessionKeys {
                request_key: self.request_key,
                response_key: self.response_key,
            },
            profile_label: profile.label(),
            profile_id: *profile.profile_id(),
        })
    }

    fn republish(&mut self, blocks: &[IndexedBlock]) -> Result<(), ParityHarnessError> {
        let store = memory_backed_serving_store(&self.shape, blocks)?;
        let serving_epoch = published_serving_epoch(store)?;
        self.runtime
            .activate_finalized_serving_epoch(serving_epoch)
            .map_err(|_| ParityHarnessError::ServingEpoch)
    }
}

const fn layout_network(network: ServiceNetwork) -> crate::layout::LayoutNetwork {
    match network {
        ServiceNetwork::Mainnet => crate::layout::LayoutNetwork::Mainnet,
        ServiceNetwork::Testnet => crate::layout::LayoutNetwork::Testnet,
        ServiceNetwork::Regtest => crate::layout::LayoutNetwork::Regtest,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inner_codec::runtime::recent_snapshot_identity;

    fn utxo(txid: u8, output_index: u32) -> WalletUtxo {
        WalletUtxo {
            txid: [txid; 32],
            output_index,
            value_zat: 1_000,
            height: 7,
            script: vec![0x76, 0xa9],
        }
    }

    #[test]
    fn parity_ignores_order_but_not_content() {
        let left = vec![utxo(1, 0), utxo(2, 1)];
        let reordered = vec![utxo(2, 1), utxo(1, 0)];

        assert_eq!(parity_mismatch(&left, &reordered), None);

        let mut altered = left.clone();
        altered[0].value_zat = 999;
        assert!(parity_mismatch(&left, &altered).is_some());
    }

    #[test]
    fn parity_reports_a_cardinality_difference_first() {
        let mismatch = parity_mismatch(&[utxo(1, 0)], &[])
            .expect("a one-sided set is not equal to the empty set");

        assert!(mismatch.contains("returned 1 utxos, ordinary source has 0"));
    }

    #[test]
    fn an_empty_comparison_matches() {
        assert_eq!(parity_mismatch(&[], &[]), None);
    }

    /// The harness publishes a serving epoch from the store's own identity and
    /// the runtime derives its codec checkpoint back out of that identity. If
    /// those two derivations ever disagree, every query answers
    /// `ProjectionNotReady` with nothing to point at, so the round trip is
    /// asserted directly.
    #[test]
    fn the_published_identity_and_the_codec_checkpoint_agree() {
        let identity = RecentSnapshotIdentity::new(2, 41, [0x7c; 32], 1, 9, 3);

        let checkpoint = PrivateQueryCheckpoint::try_from_serving_identity(identity)
            .expect("a regtest identity names a known network");

        assert!(recent_snapshot_identity(&checkpoint) == identity);
    }
}

#[cfg(all(test, feature = "shadow-parity"))]
mod parity_tests {
    use zaino_state::{
        extract_transparent_events,
        test_dependencies::{load_ordinary_utxo_shadow_fixture, OrdinaryUtxoShadowFixture},
        TransparentBlockEvent,
    };

    use super::*;
    use crate::inner_codec::private_service::{private_mainnet_store_reads, PrivateNetwork};

    type ParityResult<T> = Result<T, Box<dyn std::error::Error>>;

    /// A regtest shape wide enough for exactly one compiled mainnet query.
    ///
    /// `max_events_per_address` is not a knob: [`crate::engine`] refuses a
    /// store whose per-key slot count is anything other than the profile's
    /// store-read count, so it is the compiled figure or nothing.
    fn parity_shape() -> Result<PrivateProjectionShape, ParityHarnessError> {
        Ok(PrivateProjectionShape {
            network: PrivateNetwork::Regtest,
            schema_version: 1,
            key_epoch: 7,
            projection_epoch: 11,
            max_seen_outputs: 4_096,
            max_live_outputs: 4_096,
            directory_admission: 64,
            event_admission: 4_096,
            max_events_per_address: private_mainnet_store_reads()
                .map_err(|_| ParityHarnessError::Profile)?,
            directory_capacity: 256,
            event_capacity: 8_192,
        })
    }

    /// Every fixture case's ordinary answer, in this crate's wallet shape.
    fn ordinary_expectation(
        case: &zaino_state::test_dependencies::OrdinaryUtxoShadowCase,
    ) -> Vec<WalletUtxo> {
        case.ordinary_utxos()
            .iter()
            .map(|utxo| WalletUtxo {
                txid: *utxo.txid(),
                output_index: utxo.output_index(),
                value_zat: utxo.value_zat(),
                height: utxo.height(),
                script: utxo.script().to_vec(),
            })
            .collect()
    }

    /// Seals one query, drives it through the runtime, and opens the answer.
    fn round<H>(
        harness: &mut H,
        request: [u8; PARITY_ENVELOPE_BYTES],
        session: &WalletSession,
    ) -> ParityResult<WalletPage>
    where
        H: WalletParityRuntime,
    {
        let pending = harness
            .query_page(request)
            .map_err(|_| ParityHarnessError::Refused)?;
        let bytes = *pending
            .try_release_bytes()
            .map_err(|_| ParityHarnessError::Refused)?;
        Ok(session.open_response(&bytes)?)
    }

    /// The number of transparent outputs the fixture chain spends.
    ///
    /// Asserted rather than assumed: "a spent output is excluded" is only
    /// covered by the parity comparison if the chain actually spends one.
    fn spent_output_count(fixture: &OrdinaryUtxoShadowFixture) -> ParityResult<usize> {
        let mut spent = 0;
        for block in fixture.indexed_blocks() {
            for event in extract_transparent_events(block)? {
                if matches!(event, TransparentBlockEvent::Spent { .. }) {
                    spent += 1;
                }
            }
        }
        Ok(spent)
    }

    /// The whole point of this module: a request sealed with the real codec and
    /// the real XChaCha20 protector, answered by the real engine, must decode
    /// to exactly what an ordinary Zaino source reports for the same address at
    /// the same checkpoint.
    ///
    /// This establishes answer correctness only. The projection underneath is
    /// the in-memory qualification backend, so nothing here bears on
    /// obliviousness, and the epoch is published rather than captured from a
    /// live chain, so nothing here bears on freshness.
    #[tokio::test]
    async fn a_sealed_private_query_matches_the_ordinary_source() -> ParityResult<()> {
        let fixture = load_ordinary_utxo_shadow_fixture().await?;
        let journal = tempfile::TempDir::new()?;
        let mut harness = wallet_parity_harness(
            &parity_shape()?,
            fixture.indexed_blocks(),
            journal.path().join("replay"),
            [0x5a; 16],
            1,
        )?;
        let session = harness.wallet_session()?;

        assert!(
            spent_output_count(&fixture)? > 0,
            "a fixture with no spend cannot show that a spent output is excluded"
        );

        let mut empty_cases = 0;
        let mut single_utxo_cases = 0;
        let mut multi_utxo_cases = 0;
        for case in fixture.cases() {
            let request = session.seal_query(case.address_script(), 0, None)?;
            let page = round(&mut harness, request, &session)?;

            assert_eq!(
                page.outcome,
                WalletOutcome::Complete,
                "{} did not complete",
                case.name()
            );
            // Terminal pagination: every fixture answer fits one page.
            assert!(!page.has_more, "{} reported a further page", case.name());
            assert!(page.continuation.is_none());

            let expected = ordinary_expectation(case);
            assert_eq!(
                parity_mismatch(&page.utxos, &expected),
                None,
                "{} differs from the ordinary source",
                case.name()
            );

            match expected.len() {
                0 => empty_cases += 1,
                1 => single_utxo_cases += 1,
                _ => multi_utxo_cases += 1,
            }
        }

        assert!(empty_cases > 0, "the empty-result case is not covered");
        assert!(single_utxo_cases > 0, "the single-UTXO case is not covered");
        assert!(
            multi_utxo_cases > 0,
            "the multiple-UTXO case is not covered"
        );
        Ok(())
    }

    /// A request whose address key is not 32 bytes must come back
    /// `InvalidDomain` with an empty page, not as a transport failure: the
    /// profile's complete read budget still runs, so a malformed key costs a
    /// well-formed client exactly what a well-formed one costs.
    #[tokio::test]
    async fn a_malformed_address_key_is_answered_invalid_domain() -> ParityResult<()> {
        let fixture = load_ordinary_utxo_shadow_fixture().await?;
        let journal = tempfile::TempDir::new()?;
        let mut harness = wallet_parity_harness(
            &parity_shape()?,
            fixture.indexed_blocks(),
            journal.path().join("replay"),
            [0x5b; 16],
            1,
        )?;
        let session = harness.wallet_session()?;

        let request = session.seal_untrusted_query(&[0x11; 31], 0, None)?;
        let page = round(&mut harness, request, &session)?;

        assert_eq!(page.outcome, WalletOutcome::InvalidDomain);
        assert!(page.utxos.is_empty());
        assert!(!page.has_more);
        Ok(())
    }

    /// A byte-identical envelope replayed against the same runtime is refused,
    /// and refused *inside* the protected response rather than at the
    /// transport: the round still runs its full read budget and comes back
    /// `ProjectionNotReady` with an empty page.
    ///
    /// That outcome name is deliberately the same one a stale checkpoint gets.
    /// A duplicate and an unready projection are indistinguishable to a client
    /// by design, so this test's value is showing that a duplicate reaches that
    /// arm at all -- the replay journal underneath is the real crash-durable
    /// one, not a double.
    #[tokio::test]
    async fn a_byte_identical_request_is_refused_on_replay() -> ParityResult<()> {
        let fixture = load_ordinary_utxo_shadow_fixture().await?;
        let journal = tempfile::TempDir::new()?;
        let mut harness = wallet_parity_harness(
            &parity_shape()?,
            fixture.indexed_blocks(),
            journal.path().join("replay"),
            [0x5c; 16],
            1,
        )?;
        let session = harness.wallet_session()?;
        let case = fixture
            .cases()
            .first()
            .ok_or("the fixture publishes at least one case")?;

        let request = session.seal_query(case.address_script(), 0, None)?;
        let first = round(&mut harness, request, &session)?;
        assert_eq!(first.outcome, WalletOutcome::Complete);

        let replayed = round(&mut harness, request, &session)?;

        assert_eq!(replayed.outcome, WalletOutcome::ProjectionNotReady);
        assert!(replayed.utxos.is_empty());
        assert!(!replayed.has_more);
        Ok(())
    }

    /// Answers must stay correct across a generation swap, and a request sealed
    /// against the retired checkpoint must not be answered from the new one.
    ///
    /// The swap is `republish`, not `refresh`: the harness has no live
    /// subscriber, and the capture type a subscriber produces has no
    /// constructor outside a live chain index.
    #[tokio::test]
    async fn answers_stay_correct_across_a_generation_swap() -> ParityResult<()> {
        let fixture = load_ordinary_utxo_shadow_fixture().await?;
        let blocks = fixture.indexed_blocks();
        let prefix = blocks
            .get(
                ..blocks
                    .len()
                    .checked_sub(1)
                    .ok_or("fixture chain is empty")?,
            )
            .ok_or("fixture chain has a proper prefix")?;
        let journal = tempfile::TempDir::new()?;
        let mut harness = wallet_parity_harness(
            &parity_shape()?,
            prefix,
            journal.path().join("replay"),
            [0x5d; 16],
            1,
        )?;
        let stale_session = harness.wallet_session()?;
        let case = fixture
            .cases()
            .first()
            .ok_or("the fixture publishes at least one case")?;
        let stale_request = stale_session.seal_query(case.address_script(), 0, None)?;

        harness.republish(blocks)?;

        // The retired checkpoint is still a well-formed, authentic envelope --
        // it opens -- and is answered as having no ready projection.
        let stale = round(&mut harness, stale_request, &stale_session)?;
        assert_eq!(stale.outcome, WalletOutcome::ProjectionNotReady);
        assert!(stale.utxos.is_empty());

        let session = harness.wallet_session()?;
        for case in fixture.cases() {
            let request = session.seal_query(case.address_script(), 0, None)?;
            let page = round(&mut harness, request, &session)?;

            assert_eq!(page.outcome, WalletOutcome::Complete);
            assert_eq!(
                parity_mismatch(&page.utxos, &ordinary_expectation(case)),
                None,
                "{} differs from the ordinary source after the swap",
                case.name()
            );
        }
        Ok(())
    }

    /// Documents, executably, why the continuing-pagination case is not driven
    /// here: the compiled profile returns 256 slots per page and no fixture
    /// address owns that many live outputs, so `has_more` is unreachable with
    /// this corpus. If a wider fixture ever lands, this fails and the
    /// continuation case becomes writable.
    #[tokio::test]
    async fn no_fixture_address_can_reach_a_second_page() -> ParityResult<()> {
        let fixture = load_ordinary_utxo_shadow_fixture().await?;

        let widest = fixture
            .cases()
            .iter()
            .map(|case| case.ordinary_utxos().len())
            .max()
            .unwrap_or_default();

        assert!(
            widest <= MAINNET_QUERY_SLOTS,
            "a fixture address now exceeds one page; the continuation case is writable"
        );
        Ok(())
    }
}
