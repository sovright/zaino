//! Strict wire validation for the codec bootstrap carried on the accepted TLS stream.

use crate::private_proto;

const CONTEXT_VERSION: u32 = 1;
const KEY_BYTES: usize = 32;
const BINDING_BYTES: usize = 32;
const PROFILE_BYTES: usize = 16;
const HASH_BYTES: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootstrapNetwork {
    Mainnet,
    Testnet,
    Regtest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootstrapWireError {
    ContextVersion,
    Width(&'static str),
    Network,
    EnvelopeBytes,
    LegacyAttestation,
    SchemaVersion,
    ProjectionEpoch,
    KeyEpoch,
    EvidenceMismatch(&'static str),
}

impl std::fmt::Display for BootstrapWireError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "private bootstrap refused: {self:?}")
    }
}

impl std::error::Error for BootstrapWireError {}

/// Codec material validated from the canonical bootstrap wire message.
///
/// This validates encoding and its overlap with already accepted evidence. The
/// caller still owns TLS peer authentication and evidence acceptance.
#[derive(Clone, PartialEq, Eq)]
pub struct ValidatedBootstrap {
    request_key: [u8; KEY_BYTES],
    response_key: [u8; KEY_BYTES],
    session_binding: [u8; BINDING_BYTES],
    profile_id: [u8; PROFILE_BYTES],
    network: BootstrapNetwork,
    serving_finalized_checkpoint_height: u32,
    serving_finalized_checkpoint_block_hash_display: [u8; HASH_BYTES],
    schema_version: u32,
    projection_epoch: u64,
    key_epoch: u64,
}

impl std::fmt::Debug for ValidatedBootstrap {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ValidatedBootstrap { ..REDACTED.. }")
    }
}

impl ValidatedBootstrap {
    /// Validates external bootstrap bytes and cross-checks quoted overlapping fields.
    pub fn try_from_wire(
        wire: &private_proto::BootstrapResponse,
        accepted_evidence: &private_proto::EvidenceResponse,
        expected_network: BootstrapNetwork,
    ) -> Result<Self, BootstrapWireError> {
        if wire.context_version != CONTEXT_VERSION {
            return Err(BootstrapWireError::ContextVersion);
        }
        if wire.envelope_bytes != zaino_oram::PRIVATE_MAINNET_ENVELOPE_BYTES as u32 {
            return Err(BootstrapWireError::EnvelopeBytes);
        }
        if !wire.attestation.is_empty() {
            return Err(BootstrapWireError::LegacyAttestation);
        }
        if wire.schema_version == 0 {
            return Err(BootstrapWireError::SchemaVersion);
        }
        if wire.projection_epoch == 0 {
            return Err(BootstrapWireError::ProjectionEpoch);
        }
        if wire.key_epoch == 0 {
            return Err(BootstrapWireError::KeyEpoch);
        }
        let request_key = fixed("request_key", &wire.request_key)?;
        let response_key = fixed("response_key", &wire.response_key)?;
        let session_binding = fixed("session_binding", &wire.session_binding)?;
        let profile_id = fixed("profile_id", &wire.profile_id)?;
        let serving_finalized_checkpoint_block_hash_display = fixed(
            "serving_finalized_checkpoint_block_hash_display",
            &wire.serving_finalized_checkpoint_block_hash_display,
        )?;
        if profile_id.as_slice() != accepted_evidence.profile_id {
            return Err(BootstrapWireError::EvidenceMismatch("profile_id"));
        }
        if wire.schema_version != accepted_evidence.schema_version {
            return Err(BootstrapWireError::EvidenceMismatch("schema_version"));
        }
        if wire.key_epoch != accepted_evidence.key_epoch {
            return Err(BootstrapWireError::EvidenceMismatch("key_epoch"));
        }
        let network = match private_proto::PrivateNetwork::try_from(wire.network) {
            Ok(private_proto::PrivateNetwork::Mainnet) => BootstrapNetwork::Mainnet,
            Ok(private_proto::PrivateNetwork::Testnet) => BootstrapNetwork::Testnet,
            Ok(private_proto::PrivateNetwork::Regtest) => BootstrapNetwork::Regtest,
            Ok(private_proto::PrivateNetwork::Unspecified) | Err(_) => {
                return Err(BootstrapWireError::Network);
            }
        };
        if network != expected_network {
            return Err(BootstrapWireError::EvidenceMismatch("network"));
        }
        if wire.serving_finalized_checkpoint_height != accepted_evidence.checkpoint_height {
            return Err(BootstrapWireError::EvidenceMismatch("checkpoint_height"));
        }
        let mut accepted_hash_display: [u8; HASH_BYTES] = fixed(
            "accepted_checkpoint_block_hash",
            &accepted_evidence.checkpoint_block_hash,
        )?;
        accepted_hash_display.reverse();
        if serving_finalized_checkpoint_block_hash_display != accepted_hash_display {
            return Err(BootstrapWireError::EvidenceMismatch(
                "checkpoint_block_hash",
            ));
        }
        Ok(Self {
            request_key,
            response_key,
            session_binding,
            profile_id,
            network,
            serving_finalized_checkpoint_height: wire.serving_finalized_checkpoint_height,
            serving_finalized_checkpoint_block_hash_display,
            schema_version: wire.schema_version,
            projection_epoch: wire.projection_epoch,
            key_epoch: wire.key_epoch,
        })
    }

    pub const fn request_key(&self) -> &[u8; KEY_BYTES] {
        &self.request_key
    }
    pub const fn response_key(&self) -> &[u8; KEY_BYTES] {
        &self.response_key
    }
    pub const fn session_binding(&self) -> &[u8; BINDING_BYTES] {
        &self.session_binding
    }
    pub const fn profile_id(&self) -> &[u8; PROFILE_BYTES] {
        &self.profile_id
    }
    pub const fn network(&self) -> BootstrapNetwork {
        self.network
    }
    pub const fn serving_finalized_checkpoint_height(&self) -> u32 {
        self.serving_finalized_checkpoint_height
    }
    pub const fn serving_finalized_checkpoint_block_hash_display(&self) -> &[u8; HASH_BYTES] {
        &self.serving_finalized_checkpoint_block_hash_display
    }
    pub const fn schema_version(&self) -> u32 {
        self.schema_version
    }
    pub const fn projection_epoch(&self) -> u64 {
        self.projection_epoch
    }
    pub const fn key_epoch(&self) -> u64 {
        self.key_epoch
    }

    /// Consumes validated material into the production first-page query codec.
    ///
    /// Validation does not establish trust by itself; call this only after the
    /// same TLS peer's evidence and this bootstrap message have been accepted.
    pub fn into_mainnet_client_session(
        self,
    ) -> Result<zaino_oram::MainnetClientSession, zaino_oram::MainnetClientCodecError> {
        let network = match self.network {
            BootstrapNetwork::Mainnet => zaino_oram::PrivateNetwork::Mainnet,
            BootstrapNetwork::Testnet => zaino_oram::PrivateNetwork::Testnet,
            BootstrapNetwork::Regtest => zaino_oram::PrivateNetwork::Regtest,
        };
        zaino_oram::MainnetClientSession::try_from_authenticated_context(
            zaino_oram::ReleasableSessionKeys {
                request_key: self.request_key,
                response_key: self.response_key,
            },
            self.session_binding,
            self.profile_id,
            network,
            self.serving_finalized_checkpoint_height,
            self.serving_finalized_checkpoint_block_hash_display,
            self.schema_version,
            self.projection_epoch,
            self.key_epoch,
        )
    }
}

fn fixed<const N: usize>(name: &'static str, value: &[u8]) -> Result<[u8; N], BootstrapWireError> {
    value
        .try_into()
        .map_err(|_| BootstrapWireError::Width(name))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wire() -> private_proto::BootstrapResponse {
        private_proto::BootstrapResponse {
            key_epoch: 7,
            request_key: vec![1; KEY_BYTES],
            response_key: vec![2; KEY_BYTES],
            profile_label: "diagnostic-only".into(),
            envelope_bytes: zaino_oram::PRIVATE_MAINNET_ENVELOPE_BYTES as u32,
            attestation: Vec::new(),
            profile_id: vec![3; PROFILE_BYTES],
            context_version: CONTEXT_VERSION,
            session_binding: vec![4; BINDING_BYTES],
            network: private_proto::PrivateNetwork::Mainnet.into(),
            serving_finalized_checkpoint_height: 9,
            serving_finalized_checkpoint_block_hash_display: (0_u8..32).rev().collect(),
            schema_version: 6,
            projection_epoch: 8,
        }
    }

    fn evidence() -> private_proto::EvidenceResponse {
        private_proto::EvidenceResponse {
            profile_id: vec![3; PROFILE_BYTES],
            schema_version: 6,
            key_epoch: 7,
            checkpoint_height: 9,
            checkpoint_block_hash: (0_u8..32).collect(),
            ..Default::default()
        }
    }

    #[test]
    fn canonical_bootstrap_validates() -> Result<(), BootstrapWireError> {
        let parsed =
            ValidatedBootstrap::try_from_wire(&wire(), &evidence(), BootstrapNetwork::Mainnet)?;
        assert_eq!(parsed.network(), BootstrapNetwork::Mainnet);
        assert_eq!(parsed.serving_finalized_checkpoint_height(), 9);
        assert_eq!(
            parsed.serving_finalized_checkpoint_block_hash_display(),
            &std::array::from_fn(|index| 31 - index as u8)
        );
        assert_eq!(format!("{parsed:?}"), "ValidatedBootstrap { ..REDACTED.. }");
        Ok(())
    }

    #[test]
    fn validated_wire_material_builds_the_production_codec(
    ) -> Result<(), Box<dyn std::error::Error>> {
        const MAINNET_PROFILE_ID: [u8; PROFILE_BYTES] = [
            0x67, 0x4f, 0xfb, 0xb1, 0x66, 0x9b, 0xe6, 0xfe, 0x65, 0xa1, 0xaa, 0x5d, 0x01, 0xf6,
            0xcb, 0x93,
        ];
        let mut candidate = wire();
        candidate.profile_id = MAINNET_PROFILE_ID.to_vec();
        let mut accepted = evidence();
        accepted.profile_id = MAINNET_PROFILE_ID.to_vec();
        ValidatedBootstrap::try_from_wire(&candidate, &accepted, BootstrapNetwork::Mainnet)?
            .into_mainnet_client_session()?;
        Ok(())
    }

    #[test]
    fn every_external_boundary_is_refused() {
        type MutationCase = (
            fn(&mut private_proto::BootstrapResponse),
            BootstrapWireError,
        );
        let cases: &[MutationCase] = &[
            (
                |w| w.context_version = 0,
                BootstrapWireError::ContextVersion,
            ),
            (
                |w| w.request_key.clear(),
                BootstrapWireError::Width("request_key"),
            ),
            (
                |w| w.response_key.push(0),
                BootstrapWireError::Width("response_key"),
            ),
            (
                |w| w.session_binding.clear(),
                BootstrapWireError::Width("session_binding"),
            ),
            (
                |w| w.profile_id.clear(),
                BootstrapWireError::Width("profile_id"),
            ),
            (
                |w| w.serving_finalized_checkpoint_block_hash_display.clear(),
                BootstrapWireError::Width("serving_finalized_checkpoint_block_hash_display"),
            ),
            (|w| w.network = 0, BootstrapWireError::Network),
            (|w| w.network = 99, BootstrapWireError::Network),
            (|w| w.envelope_bytes = 1, BootstrapWireError::EnvelopeBytes),
            (
                |w| w.attestation.push(1),
                BootstrapWireError::LegacyAttestation,
            ),
            (|w| w.schema_version = 0, BootstrapWireError::SchemaVersion),
            (
                |w| w.projection_epoch = 0,
                BootstrapWireError::ProjectionEpoch,
            ),
            (|w| w.key_epoch = 0, BootstrapWireError::KeyEpoch),
        ];
        for (mutate, expected) in cases {
            let mut candidate = wire();
            mutate(&mut candidate);
            assert_eq!(
                ValidatedBootstrap::try_from_wire(
                    &candidate,
                    &evidence(),
                    BootstrapNetwork::Mainnet,
                ),
                Err(*expected)
            );
        }
        let mut candidate = wire();
        candidate.envelope_bytes = 4_096;
        assert_eq!(
            ValidatedBootstrap::try_from_wire(&candidate, &evidence(), BootstrapNetwork::Mainnet,),
            Err(BootstrapWireError::EnvelopeBytes)
        );
        let mut candidate = wire();
        candidate.profile_id.fill(4);
        assert_eq!(
            ValidatedBootstrap::try_from_wire(&candidate, &evidence(), BootstrapNetwork::Mainnet,),
            Err(BootstrapWireError::EvidenceMismatch("profile_id"))
        );
        assert_eq!(
            ValidatedBootstrap::try_from_wire(
                &wire(),
                &private_proto::EvidenceResponse {
                    schema_version: 5,
                    ..evidence()
                },
                BootstrapNetwork::Mainnet,
            ),
            Err(BootstrapWireError::EvidenceMismatch("schema_version"))
        );
        assert_eq!(
            ValidatedBootstrap::try_from_wire(
                &wire(),
                &private_proto::EvidenceResponse {
                    key_epoch: 9,
                    ..evidence()
                },
                BootstrapNetwork::Mainnet,
            ),
            Err(BootstrapWireError::EvidenceMismatch("key_epoch"))
        );
        assert_eq!(
            ValidatedBootstrap::try_from_wire(&wire(), &evidence(), BootstrapNetwork::Testnet,),
            Err(BootstrapWireError::EvidenceMismatch("network"))
        );
        let mut accepted = evidence();
        accepted.checkpoint_height += 1;
        assert_eq!(
            ValidatedBootstrap::try_from_wire(&wire(), &accepted, BootstrapNetwork::Mainnet),
            Err(BootstrapWireError::EvidenceMismatch("checkpoint_height"))
        );
        let mut accepted = evidence();
        accepted.checkpoint_block_hash[0] = 4;
        assert_eq!(
            ValidatedBootstrap::try_from_wire(&wire(), &accepted, BootstrapNetwork::Mainnet),
            Err(BootstrapWireError::EvidenceMismatch(
                "checkpoint_block_hash"
            ))
        );
    }
}
