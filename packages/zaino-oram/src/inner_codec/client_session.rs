//! Client-side codec over an authenticated, validated bootstrap context.

use rand::TryRngCore as _;
use zeroize::Zeroizing;

use super::{
    xchacha20::XChaCha20EnvelopeProtector, PrivateNetwork, PrivateQueryCheckpoint,
    PrivateQueryCodec, PrivateQueryRequest, ENVELOPE_NONCE_BYTES,
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

/// The two client-held envelope keys released by an authenticated bootstrap.
pub struct MainnetClientKeys {
    request: Zeroizing<[u8; 32]>,
    response: Zeroizing<[u8; 32]>,
}

impl MainnetClientKeys {
    /// Takes ownership of fixed-width request and response keys.
    pub fn new(request: [u8; 32], response: [u8; 32]) -> Self {
        Self {
            request: Zeroizing::new(request),
            response: Zeroizing::new(response),
        }
    }
}

impl std::fmt::Debug for MainnetClientKeys {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("MainnetClientKeys { ..REDACTED.. }")
    }
}

/// Closed network domain encoded in a protected client checkpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MainnetClientNetwork {
    /// Zcash mainnet.
    Mainnet,
    /// The public Zcash test network.
    Testnet,
    /// A local regression-test network.
    Regtest,
}

/// Closed standard transparent-address input accepted by the client codec.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct MainnetStandardAddress {
    kind: StandardScriptKind,
    hash: [u8; 20],
}

impl std::fmt::Debug for MainnetStandardAddress {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("MainnetStandardAddress { .. }")
    }
}

impl MainnetStandardAddress {
    /// Constructs a pay-to-public-key-hash address identity.
    pub const fn pay_to_public_key_hash(hash: [u8; 20]) -> Self {
        Self {
            kind: StandardScriptKind::PayToPublicKeyHash,
            hash,
        }
    }
    /// Constructs a pay-to-script-hash address identity.
    pub const fn pay_to_script_hash(hash: [u8; 20]) -> Self {
        Self {
            kind: StandardScriptKind::PayToScriptHash,
            hash,
        }
    }
}

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
        keys: MainnetClientKeys,
        session_binding: [u8; 32],
        profile_id: [u8; 16],
        network: MainnetClientNetwork,
        serving_finalized_checkpoint_height: u32,
        serving_finalized_checkpoint_block_hash_display: [u8; 32],
        schema_version: u32,
        projection_epoch: u64,
        key_epoch: u64,
    ) -> Result<Self, MainnetClientCodecError> {
        if schema_version == 0 || projection_epoch == 0 || key_epoch == 0 {
            return Err(MainnetClientCodecError::Context);
        }
        let profile =
            mainnet_utxo_history_profile().map_err(|_| MainnetClientCodecError::Context)?;
        if profile_id != *profile.profile_id() {
            return Err(MainnetClientCodecError::Context);
        }
        let compiled =
            CompiledQueryShape::<MAINNET_QUERY_SLOTS, MAINNET_ENVELOPE_BYTES>::new(profile)
                .map_err(|_| MainnetClientCodecError::Context)?;
        let codec = PrivateQueryCodec::new(&compiled, session_binding)
            .map_err(|_| MainnetClientCodecError::Context)?;
        let (network, layout_network) = match network {
            MainnetClientNetwork::Mainnet => (PrivateNetwork::Mainnet, LayoutNetwork::Mainnet),
            MainnetClientNetwork::Testnet => (PrivateNetwork::Testnet, LayoutNetwork::Testnet),
            MainnetClientNetwork::Regtest => (PrivateNetwork::Regtest, LayoutNetwork::Regtest),
        };
        Ok(Self {
            codec,
            protector: XChaCha20EnvelopeProtector::new(keys.request, keys.response),
            checkpoint: PrivateQueryCheckpoint::new(
                network,
                serving_finalized_checkpoint_height,
                serving_finalized_checkpoint_block_hash_display,
                schema_version,
                projection_epoch,
                key_epoch,
            ),
            network: layout_network,
            schema_version,
        })
    }

    /// Builds a codec from bootstrap material already authenticated by the caller.
    ///
    /// This validates format and profile coherence. It does not authenticate the
    /// source of `bootstrap`; the client evidence/TLS gate owns that decision.
    #[cfg(feature = "corpus-zaino")]
    pub fn try_from_authenticated_bootstrap(
        bootstrap: &super::private_service::ClientSessionBootstrap,
    ) -> Result<Self, MainnetClientCodecError> {
        if bootstrap.context_version() != crate::PRIVATE_CLIENT_CONTEXT_VERSION {
            return Err(MainnetClientCodecError::Context);
        }
        let network = match bootstrap.network() {
            super::private_service::PrivateNetwork::Mainnet => MainnetClientNetwork::Mainnet,
            super::private_service::PrivateNetwork::Testnet => MainnetClientNetwork::Testnet,
            super::private_service::PrivateNetwork::Regtest => MainnetClientNetwork::Regtest,
        };
        Self::try_from_authenticated_context(
            MainnetClientKeys::new(bootstrap.keys().request_key, bootstrap.keys().response_key),
            *bootstrap.session_binding(),
            *bootstrap.profile_id(),
            network,
            bootstrap.serving_finalized_checkpoint_height(),
            *bootstrap.serving_finalized_checkpoint_block_hash_display(),
            bootstrap.schema_version(),
            bootstrap.projection_epoch(),
            bootstrap.key_epoch(),
        )
    }

    /// Seals one first-page standard-address query.
    pub fn seal_standard_address_query(
        &self,
        address: MainnetStandardAddress,
        minimum_height: u32,
    ) -> Result<[u8; MAINNET_ENVELOPE_BYTES], MainnetClientCodecError> {
        let key = derive_standard_address_key(
            self.network,
            self.schema_version,
            StandardAddress::new(address.kind, address.hash),
        );
        let request = PrivateQueryRequest::new(
            self.checkpoint,
            UtxoQuery::from_untrusted_address_key(key.as_bytes(), minimum_height),
            None,
        );
        let mut nonce = [0; ENVELOPE_NONCE_BYTES];
        rand::rngs::OsRng
            .try_fill_bytes(&mut nonce)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn closed_standard_address_domains_preserve_key_derivation() {
        let p2pkh = MainnetStandardAddress::pay_to_public_key_hash([0x11; 20]);
        let p2sh = MainnetStandardAddress::pay_to_script_hash([0x11; 20]);
        let p2pkh_key = derive_standard_address_key(
            LayoutNetwork::Mainnet,
            6,
            StandardAddress::new(p2pkh.kind, p2pkh.hash),
        );
        let p2sh_key = derive_standard_address_key(
            LayoutNetwork::Mainnet,
            6,
            StandardAddress::new(p2sh.kind, p2sh.hash),
        );
        assert_eq!(
            *p2pkh_key.as_bytes(),
            [
                107, 156, 81, 112, 218, 94, 137, 171, 208, 18, 94, 192, 243, 196, 99, 45, 247, 141,
                56, 96, 26, 148, 50, 69, 175, 9, 86, 147, 126, 220, 155, 202
            ]
        );
        assert_eq!(
            *p2sh_key.as_bytes(),
            [
                136, 197, 75, 37, 219, 40, 224, 23, 234, 45, 15, 155, 222, 200, 105, 253, 253, 86,
                79, 167, 46, 63, 135, 160, 200, 88, 38, 140, 142, 200, 57, 105
            ]
        );
    }

    #[test]
    fn client_keys_debug_is_redacted() {
        let keys = MainnetClientKeys::new([0x11; 32], [0x22; 32]);
        let debug = format!("{keys:?}");
        assert_eq!(debug, "MainnetClientKeys { ..REDACTED.. }");
        assert!(!debug.contains("17"));
        assert!(!debug.contains("34"));
    }
}
