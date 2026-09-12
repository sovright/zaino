//! Listener-free construction of one raw TDX evidence response.
//!
//! This module binds a caller challenge to the live ephemeral listener key and
//! workload-owned public identities. It acquires raw evidence only. Quote
//! verification, TCB policy, peer proof-of-possession, and challenge replay
//! rejection belong to the client verifier and are not claimed here.

use std::fmt;

use sha2::{Digest, Sha512};
use zaino_oram::PRIVATE_PROFILE_ID_BYTES;

use super::tls::{PrivateTlsError, PrivateTlsIdentity};

mod configfs;

#[allow(unused_imports)]
pub(crate) use configfs::{ConfigFsQuoteError, ConfigFsTsmQuoteProvider};

pub(crate) const ATTESTATION_CHALLENGE_BYTES: usize = 64;
pub(crate) const ATTESTATION_DIGEST_BYTES: usize = 32;
pub(crate) const REPORT_DATA_BYTES: usize = 64;
pub(crate) const MAX_RAW_QUOTE_BYTES: usize = 16 * 1024;

const TRANSCRIPT_VERSION: u16 = 1;
const TRANSCRIPT_DOMAIN: [u8; 32] = *b"zaino-tdx-report-data-v1\0\0\0\0\0\0\0\0";

/// The verifier's sole contribution to an evidence request.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct AttestationChallenge([u8; ATTESTATION_CHALLENGE_BYTES]);

impl AttestationChallenge {
    #[cfg(test)]
    pub(crate) const fn new(bytes: [u8; ATTESTATION_CHALLENGE_BYTES]) -> Self {
        Self(bytes)
    }

    pub(crate) fn try_from_wire(
        request: crate::private_proto::EvidenceRequest,
    ) -> Result<Self, InvalidAttestationChallenge> {
        request
            .challenge
            .try_into()
            .map(Self)
            .map_err(|_| InvalidAttestationChallenge)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct InvalidAttestationChallenge;

impl fmt::Debug for AttestationChallenge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AttestationChallenge { ..REDACTED.. }")
    }
}

/// Public workload identities supplied by their in-process owners.
///
/// The checkpoint is the committed public chain height and block hash. It is
/// not an authenticated ORAM-state root and does not establish rollback
/// protection for service state.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct AttestationWorkloadBinding {
    binary_sha256: [u8; ATTESTATION_DIGEST_BYTES],
    effective_config_sha256: [u8; ATTESTATION_DIGEST_BYTES],
    profile_id: [u8; PRIVATE_PROFILE_ID_BYTES],
    schema_version: u32,
    key_epoch: u64,
    checkpoint_height: u32,
    checkpoint_block_hash: [u8; ATTESTATION_DIGEST_BYTES],
}

impl AttestationWorkloadBinding {
    pub(crate) const fn new(
        binary_sha256: [u8; ATTESTATION_DIGEST_BYTES],
        effective_config_sha256: [u8; ATTESTATION_DIGEST_BYTES],
        profile_id: [u8; PRIVATE_PROFILE_ID_BYTES],
        schema_version: u32,
        key_epoch: u64,
        checkpoint_height: u32,
        checkpoint_block_hash: [u8; ATTESTATION_DIGEST_BYTES],
    ) -> Self {
        Self {
            binary_sha256,
            effective_config_sha256,
            profile_id,
            schema_version,
            key_epoch,
            checkpoint_height,
            checkpoint_block_hash,
        }
    }
}

impl fmt::Debug for AttestationWorkloadBinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AttestationWorkloadBinding { ..REDACTED.. }")
    }
}

/// Raw quote plus the fixed public values a verifier must recompute.
pub(crate) struct RawAttestationEvidence {
    pub(crate) transcript_version: u16,
    pub(crate) challenge: [u8; ATTESTATION_CHALLENGE_BYTES],
    pub(crate) tls_spki_sha256: [u8; ATTESTATION_DIGEST_BYTES],
    pub(crate) workload: AttestationWorkloadBinding,
    pub(crate) raw_quote: Vec<u8>,
}

impl fmt::Debug for RawAttestationEvidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RawAttestationEvidence")
            .field("transcript_version", &self.transcript_version)
            .field("quote_bytes", &self.raw_quote.len())
            .finish_non_exhaustive()
    }
}

impl RawAttestationEvidence {
    /// Converts the unverified evidence and its public recomputation inputs.
    pub(crate) fn to_wire(&self) -> crate::private_proto::EvidenceResponse {
        crate::private_proto::EvidenceResponse {
            transcript_version: u32::from(self.transcript_version),
            challenge: self.challenge.to_vec(),
            tls_spki_sha256: self.tls_spki_sha256.to_vec(),
            binary_sha256: self.workload.binary_sha256.to_vec(),
            effective_config_sha256: self.workload.effective_config_sha256.to_vec(),
            profile_id: self.workload.profile_id.to_vec(),
            schema_version: self.workload.schema_version,
            key_epoch: self.workload.key_epoch,
            checkpoint_height: self.workload.checkpoint_height,
            checkpoint_block_hash: self.workload.checkpoint_block_hash.to_vec(),
            raw_quote: self.raw_quote.clone(),
        }
    }
}

/// Acquires a provider-specific raw quote for one exact REPORT_DATA value.
pub(crate) trait RawQuoteProvider {
    type Error;

    fn quote(&mut self, report_data: [u8; REPORT_DATA_BYTES]) -> Result<Vec<u8>, Self::Error>;
}

/// Immutable evidence context captured from the exact TLS listener identity.
#[derive(Clone, Copy)]
pub(crate) struct RawEvidenceIssuer {
    tls_spki_sha256: [u8; ATTESTATION_DIGEST_BYTES],
    workload: AttestationWorkloadBinding,
}

impl RawEvidenceIssuer {
    pub(crate) fn new(
        tls: &PrivateTlsIdentity,
        workload: AttestationWorkloadBinding,
    ) -> Result<Self, PrivateTlsError> {
        Ok(Self {
            tls_spki_sha256: tls.ephemeral_spki_sha256()?,
            workload,
        })
    }

    pub(crate) fn issue<P>(
        &self,
        challenge: AttestationChallenge,
        provider: &mut P,
    ) -> Result<RawAttestationEvidence, AttestationEvidenceError<P::Error>>
    where
        P: RawQuoteProvider,
    {
        let report_data = derive_report_data(challenge, self.tls_spki_sha256, self.workload);
        let raw_quote = provider
            .quote(report_data)
            .map_err(AttestationEvidenceError::Quote)?;
        if raw_quote.is_empty() || raw_quote.len() > MAX_RAW_QUOTE_BYTES {
            return Err(AttestationEvidenceError::InvalidQuoteLength);
        }
        Ok(RawAttestationEvidence {
            transcript_version: TRANSCRIPT_VERSION,
            challenge: challenge.0,
            tls_spki_sha256: self.tls_spki_sha256,
            workload: self.workload,
            raw_quote,
        })
    }
}

#[derive(Debug)]
pub(crate) enum AttestationEvidenceError<E> {
    #[cfg(test)]
    Tls(PrivateTlsError),
    Quote(E),
    InvalidQuoteLength,
}

/// Builds one listener-free raw evidence response for a live listener key.
#[cfg(test)]
fn acquire_raw_evidence<P>(
    challenge: AttestationChallenge,
    tls: &PrivateTlsIdentity,
    workload: AttestationWorkloadBinding,
    provider: &mut P,
) -> Result<RawAttestationEvidence, AttestationEvidenceError<P::Error>>
where
    P: RawQuoteProvider,
{
    RawEvidenceIssuer::new(tls, workload)
        .map_err(AttestationEvidenceError::Tls)?
        .issue(challenge, provider)
}

fn derive_report_data(
    challenge: AttestationChallenge,
    tls_spki_sha256: [u8; ATTESTATION_DIGEST_BYTES],
    workload: AttestationWorkloadBinding,
) -> [u8; REPORT_DATA_BYTES] {
    let mut transcript = Sha512::new();
    transcript.update(TRANSCRIPT_DOMAIN);
    transcript.update(TRANSCRIPT_VERSION.to_be_bytes());
    transcript.update(challenge.0);
    transcript.update(tls_spki_sha256);
    transcript.update(workload.binary_sha256);
    transcript.update(workload.effective_config_sha256);
    transcript.update(workload.profile_id);
    transcript.update(workload.schema_version.to_be_bytes());
    transcript.update(workload.key_epoch.to_be_bytes());
    transcript.update(workload.checkpoint_height.to_be_bytes());
    transcript.update(workload.checkpoint_block_hash);
    transcript.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    struct RecordingProvider {
        report_data: Option<[u8; REPORT_DATA_BYTES]>,
    }

    struct FailingProvider;

    impl RawQuoteProvider for FailingProvider {
        type Error = &'static str;

        fn quote(&mut self, _: [u8; REPORT_DATA_BYTES]) -> Result<Vec<u8>, Self::Error> {
            Err("fixture failure")
        }
    }

    struct SizedProvider(usize);

    impl RawQuoteProvider for SizedProvider {
        type Error = ();

        fn quote(&mut self, _: [u8; REPORT_DATA_BYTES]) -> Result<Vec<u8>, Self::Error> {
            Ok(vec![0; self.0])
        }
    }

    impl RawQuoteProvider for RecordingProvider {
        type Error = ();

        fn quote(&mut self, report_data: [u8; REPORT_DATA_BYTES]) -> Result<Vec<u8>, Self::Error> {
            self.report_data = Some(report_data);
            Ok(vec![0xa5; 64])
        }
    }

    fn workload() -> AttestationWorkloadBinding {
        AttestationWorkloadBinding::new([1; 32], [2; 32], [3; 16], 4, 5, 6, [7; 32])
    }

    #[test]
    fn transcript_is_fixed_and_every_binding_changes_report_data() {
        let base = derive_report_data(AttestationChallenge::new([0; 64]), [7; 32], workload());
        assert_eq!(
            hex::encode(base),
            "451d3a488285fb8a44d6f069e90b5c797596b00bdfb86ed415876699a33a790c0c9ee20acc2e0a78cb37249ca55480960b47c9b9ab9674bd399e2fcbdb54642f"
        );

        let mut cases = Vec::new();
        cases.push(derive_report_data(
            AttestationChallenge::new([1; 64]),
            [7; 32],
            workload(),
        ));
        cases.push(derive_report_data(
            AttestationChallenge::new([0; 64]),
            [8; 32],
            workload(),
        ));
        let mut changed = workload();
        changed.binary_sha256[0] ^= 1;
        cases.push(derive_report_data(
            AttestationChallenge::new([0; 64]),
            [7; 32],
            changed,
        ));
        changed = workload();
        changed.effective_config_sha256[0] ^= 1;
        cases.push(derive_report_data(
            AttestationChallenge::new([0; 64]),
            [7; 32],
            changed,
        ));
        changed = workload();
        changed.profile_id[0] ^= 1;
        cases.push(derive_report_data(
            AttestationChallenge::new([0; 64]),
            [7; 32],
            changed,
        ));
        changed = workload();
        changed.schema_version += 1;
        cases.push(derive_report_data(
            AttestationChallenge::new([0; 64]),
            [7; 32],
            changed,
        ));
        changed = workload();
        changed.key_epoch += 1;
        cases.push(derive_report_data(
            AttestationChallenge::new([0; 64]),
            [7; 32],
            changed,
        ));
        changed = workload();
        changed.checkpoint_height += 1;
        cases.push(derive_report_data(
            AttestationChallenge::new([0; 64]),
            [7; 32],
            changed,
        ));
        changed = workload();
        changed.checkpoint_block_hash[0] ^= 1;
        cases.push(derive_report_data(
            AttestationChallenge::new([0; 64]),
            [7; 32],
            changed,
        ));
        assert!(cases.into_iter().all(|candidate| candidate != base));
    }

    #[test]
    fn evidence_borrows_the_live_ephemeral_identity() {
        let tls = PrivateTlsIdentity::generate_ephemeral()
            .expect("ephemeral TLS fixture identity is generated");
        let mut provider = RecordingProvider { report_data: None };
        let evidence = acquire_raw_evidence(
            AttestationChallenge::new([9; 64]),
            &tls,
            workload(),
            &mut provider,
        )
        .expect("recording quote provider succeeds");
        assert_eq!(
            evidence.tls_spki_sha256,
            tls.ephemeral_spki_sha256()
                .expect("fixture identity is ephemeral")
        );
        assert_eq!(evidence.raw_quote.len(), 64);
        assert!(provider.report_data.is_some());
    }

    #[test]
    fn persisted_identity_is_rejected_before_quote_acquisition() {
        let deployment = tempfile::TempDir::new().expect("temporary identity directory is created");
        let tls = PrivateTlsIdentity::load_or_generate(deployment.path())
            .expect("persisted TLS fixture identity is generated");
        let mut provider = RecordingProvider { report_data: None };
        let result = acquire_raw_evidence(
            AttestationChallenge::new([9; 64]),
            &tls,
            workload(),
            &mut provider,
        );
        assert!(matches!(
            result,
            Err(AttestationEvidenceError::Tls(
                PrivateTlsError::AttestationRequiresEphemeralIdentity
            ))
        ));
        assert!(provider.report_data.is_none());
    }

    #[test]
    fn quote_failures_and_invalid_lengths_are_rejected() {
        let tls = PrivateTlsIdentity::generate_ephemeral()
            .expect("ephemeral TLS fixture identity is generated");
        let challenge = AttestationChallenge::new([0; 64]);
        assert!(matches!(
            acquire_raw_evidence(challenge, &tls, workload(), &mut FailingProvider),
            Err(AttestationEvidenceError::Quote("fixture failure"))
        ));
        for length in [0, MAX_RAW_QUOTE_BYTES + 1] {
            assert!(matches!(
                acquire_raw_evidence(challenge, &tls, workload(), &mut SizedProvider(length)),
                Err(AttestationEvidenceError::InvalidQuoteLength)
            ));
        }
    }

    #[test]
    fn challenge_wire_conversion_requires_exact_width() {
        let valid = AttestationChallenge::try_from_wire(crate::private_proto::EvidenceRequest {
            challenge: vec![0x5a; ATTESTATION_CHALLENGE_BYTES],
        })
        .expect("64-byte challenge is valid");
        assert_eq!(valid.0, [0x5a; ATTESTATION_CHALLENGE_BYTES]);

        for length in [
            ATTESTATION_CHALLENGE_BYTES - 1,
            ATTESTATION_CHALLENGE_BYTES + 1,
        ] {
            assert_eq!(
                AttestationChallenge::try_from_wire(crate::private_proto::EvidenceRequest {
                    challenge: vec![0; length],
                }),
                Err(InvalidAttestationChallenge)
            );
        }
    }
}
