//! Client-side codec over an authenticated, validated bootstrap context.

use zaino_state::AddrScript;
use zeroize::Zeroizing;

use super::{
    private_service::{
        ClientSessionBootstrap, PrivateNetwork as ServiceNetwork, PRIVATE_CLIENT_CONTEXT_VERSION,
    },
    security_owner::{OsEntropy, RoundEntropy},
    xchacha20::XChaCha20EnvelopeProtector,
    PrivateNetwork, PrivateQueryCheckpoint, PrivateQueryCodec, PrivateQueryRequest,
    ENVELOPE_NONCE_BYTES,
};
use crate::{
    envelope::FixedEnvelope,
    layout::{derive_standard_address_key, LayoutNetwork, StandardAddress, StandardScriptKind},
    profile::{
        mainnet_utxo_history_profile, CompiledQueryShape, MAINNET_ENVELOPE_BYTES,
        MAINNET_QUERY_SLOTS,
    },
    records::{QueryOutcome, TransparentUtxo, UtxoQuery},
};

/// Why authenticated bootstrap material could not form or operate a client codec.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MainnetClientCodecError {
    /// The bootstrap context version, profile, or fixed codec shape was rejected.
    Context,
    /// The address was outside the supported transparent domains.
    Address,
    /// The operating system did not provide a request nonce.
    Entropy,
    /// A request could not be encoded or protected.
    Seal,
    /// A response did not authenticate or decode.
    Open,
}

impl std::fmt::Display for MainnetClientCodecError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("mainnet private client codec refused the operation")
    }
}

impl std::error::Error for MainnetClientCodecError {}

/// One transparent output decoded from an authenticated response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MainnetClientUtxo {
    /// Transaction identifier in Zaino internal byte order.
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

impl MainnetClientUtxo {
    fn from_record(record: &TransparentUtxo) -> Self {
        Self {
            txid: *record.txid(),
            output_index: record.output_index(),
            value_zat: record.value_zat(),
            height: record.height(),
            script: record.padded_script()[..record.script_len()].to_vec(),
        }
    }
}

/// Protected response outcome visible to a wallet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MainnetClientOutcome {
    /// Every matching record fit.
    Complete,
    /// The result budget was exceeded.
    ResultBudgetExceeded,
    /// The address domain was invalid.
    InvalidDomain,
    /// An oblivious store read failed.
    StoreFailure,
    /// The request checkpoint was not the current serving checkpoint.
    ProjectionNotReady,
    /// A continuation was invalid or replayed.
    InvalidContinuation,
}

impl MainnetClientOutcome {
    fn from_query(outcome: QueryOutcome) -> Result<Self, MainnetClientCodecError> {
        match outcome {
            QueryOutcome::Complete => Ok(Self::Complete),
            QueryOutcome::ResultBudgetExceeded => Ok(Self::ResultBudgetExceeded),
            QueryOutcome::InvalidDomain => Ok(Self::InvalidDomain),
            QueryOutcome::StoreFailure => Ok(Self::StoreFailure),
            QueryOutcome::ProjectionNotReady => Ok(Self::ProjectionNotReady),
            QueryOutcome::InvalidContinuation => Ok(Self::InvalidContinuation),
            _ => Err(MainnetClientCodecError::Open),
        }
    }
}

/// One decoded authenticated response page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MainnetClientPage {
    /// Protected result classification.
    pub outcome: MainnetClientOutcome,
    /// Occupied UTXO result slots.
    pub utxos: Vec<MainnetClientUtxo>,
    /// Whether the response indicates another page.
    pub has_more: bool,
}

/// A fixed-profile codec built only from a complete bootstrap snapshot.
pub struct MainnetClientSession {
    codec: PrivateQueryCodec<MAINNET_QUERY_SLOTS, MAINNET_ENVELOPE_BYTES>,
    protector: XChaCha20EnvelopeProtector,
    checkpoint: PrivateQueryCheckpoint,
    network: LayoutNetwork,
    schema_version: u32,
}

impl std::fmt::Debug for MainnetClientSession {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("MainnetClientSession { ..REDACTED.. }")
    }
}

impl MainnetClientSession {
    /// Builds a codec from fixed-width context already authenticated by the caller.
    ///
    /// The caller must first authenticate the TLS peer and accept its evidence and
    /// bootstrap policy. This method validates codec/profile format only.
    #[allow(clippy::too_many_arguments)]
    pub fn try_from_authenticated_context(
        keys: crate::inner_codec::private_service::ReleasableSessionKeys,
        session_binding: [u8; 32],
        profile_id: [u8; 16],
        network: ServiceNetwork,
        serving_finalized_checkpoint_height: u32,
        serving_finalized_checkpoint_block_hash_display: [u8; 32],
        schema_version: u32,
        projection_epoch: u64,
        key_epoch: u64,
    ) -> Result<Self, MainnetClientCodecError> {
        let bootstrap = ClientSessionBootstrap::from_authenticated_parts(
            keys,
            session_binding,
            profile_id,
            "authenticated-client-context",
            network,
            serving_finalized_checkpoint_height,
            serving_finalized_checkpoint_block_hash_display,
            schema_version,
            projection_epoch,
            key_epoch,
        );
        Self::try_from_authenticated_bootstrap(&bootstrap)
    }

    /// Builds a codec from bootstrap material already authenticated by the caller.
    ///
    /// This validates format and profile coherence. It does not authenticate the
    /// source of `bootstrap`; the client evidence/TLS gate owns that decision.
    pub fn try_from_authenticated_bootstrap(
        bootstrap: &ClientSessionBootstrap,
    ) -> Result<Self, MainnetClientCodecError> {
        if bootstrap.context_version() != PRIVATE_CLIENT_CONTEXT_VERSION
            || bootstrap.schema_version() == 0
            || bootstrap.projection_epoch() == 0
            || bootstrap.key_epoch() == 0
        {
            return Err(MainnetClientCodecError::Context);
        }
        let profile =
            mainnet_utxo_history_profile().map_err(|_| MainnetClientCodecError::Context)?;
        if bootstrap.profile_id() != profile.profile_id() {
            return Err(MainnetClientCodecError::Context);
        }
        let compiled =
            CompiledQueryShape::<MAINNET_QUERY_SLOTS, MAINNET_ENVELOPE_BYTES>::new(profile)
                .map_err(|_| MainnetClientCodecError::Context)?;
        let codec = PrivateQueryCodec::new(&compiled, *bootstrap.session_binding())
            .map_err(|_| MainnetClientCodecError::Context)?;
        let (network, layout_network) = match bootstrap.network() {
            ServiceNetwork::Mainnet => (PrivateNetwork::Mainnet, LayoutNetwork::Mainnet),
            ServiceNetwork::Testnet => (PrivateNetwork::Testnet, LayoutNetwork::Testnet),
            ServiceNetwork::Regtest => (PrivateNetwork::Regtest, LayoutNetwork::Regtest),
        };
        let checkpoint = PrivateQueryCheckpoint::new(
            network,
            bootstrap.serving_finalized_checkpoint_height(),
            *bootstrap.serving_finalized_checkpoint_block_hash_display(),
            bootstrap.schema_version(),
            bootstrap.projection_epoch(),
            bootstrap.key_epoch(),
        );
        Ok(Self {
            codec,
            protector: XChaCha20EnvelopeProtector::new(
                Zeroizing::new(bootstrap.keys().request_key),
                Zeroizing::new(bootstrap.keys().response_key),
            ),
            checkpoint,
            network: layout_network,
            schema_version: bootstrap.schema_version(),
        })
    }

    /// Seals one first-page standard-address query.
    pub fn seal_query(
        &self,
        address: &AddrScript,
        minimum_height: u32,
    ) -> Result<[u8; MAINNET_ENVELOPE_BYTES], MainnetClientCodecError> {
        let kind = match address.script_type() {
            0x00 => StandardScriptKind::PayToPublicKeyHash,
            0x01 => StandardScriptKind::PayToScriptHash,
            _ => return Err(MainnetClientCodecError::Address),
        };
        let key = derive_standard_address_key(
            self.network,
            self.schema_version,
            StandardAddress::new(kind, *address.hash()),
        );
        let request = PrivateQueryRequest::new(
            self.checkpoint,
            UtxoQuery::from_untrusted_address_key(key.as_bytes(), minimum_height),
            None,
        );
        let mut nonce = [0; ENVELOPE_NONCE_BYTES];
        OsEntropy
            .fill(&mut nonce)
            .map_err(|_| MainnetClientCodecError::Entropy)?;
        self.codec
            .encode_request(&request, nonce, &self.protector)
            .map(|envelope| *envelope.as_bytes())
            .map_err(|_| MainnetClientCodecError::Seal)
    }

    /// Authenticates one response and refuses pages that require continuation.
    pub fn open_single_page_response(
        &self,
        envelope: [u8; MAINNET_ENVELOPE_BYTES],
    ) -> Result<MainnetClientPage, MainnetClientCodecError> {
        let response = self
            .codec
            .decode_response(&FixedEnvelope::from_array(envelope), &self.protector)
            .map_err(|_| MainnetClientCodecError::Open)?;
        let (page, has_more, _continuation) = response
            .into_wallet_parts_for_checkpoint(self.checkpoint)
            .map_err(|_| MainnetClientCodecError::Open)?;
        if has_more {
            return Err(MainnetClientCodecError::Open);
        }
        let utxos = page
            .slots()
            .iter()
            .filter(|slot| slot.is_occupied())
            .map(|slot| MainnetClientUtxo::from_record(slot.padded_utxo()))
            .collect();
        Ok(MainnetClientPage {
            outcome: MainnetClientOutcome::from_query(page.outcome())?,
            utxos,
            has_more,
        })
    }
}
