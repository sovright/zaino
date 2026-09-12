//! Closed wire format and transcript for the no-secrets TDX boot diagnostic.

use sha2::{Digest, Sha512};
use std::fmt;

pub mod wire {
    tonic::include_proto!("zaino.boot_spike.v1");
}

pub const TRANSCRIPT_VERSION: u32 = 1;
pub const CHALLENGE_BYTES: usize = 64;
pub const DIGEST_BYTES: usize = 32;
pub const LEASE_BYTES: usize = 32;
pub const REPORT_DATA_BYTES: usize = 64;
pub const MAX_QUOTE_BYTES: usize = 16 * 1024;
pub const MAX_CCEL_TABLE_BYTES: usize = 4 * 1024;
pub const MAX_CCEL_LOG_BYTES: usize = 1024 * 1024;
pub const MAX_RESPONSE_BYTES: usize =
    MAX_QUOTE_BYTES + MAX_CCEL_TABLE_BYTES + MAX_CCEL_LOG_BYTES + 4096;
const TRANSCRIPT_DOMAIN: &[u8] = b"ZAINO-BOOT-SPIKE-EVIDENCE-V1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolError {
    Width(&'static str),
    Empty(&'static str),
    Version,
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "boot diagnostic protocol refused: {self:?}")
    }
}
impl std::error::Error for ProtocolError {}

pub fn report_data(
    challenge: [u8; CHALLENGE_BYTES],
    server_spki_sha256: [u8; DIGEST_BYTES],
    boot_lease_id: [u8; LEASE_BYTES],
) -> [u8; REPORT_DATA_BYTES] {
    let mut preimage = Vec::with_capacity(196);
    append(&mut preimage, TRANSCRIPT_DOMAIN);
    append(&mut preimage, &challenge);
    append(&mut preimage, &server_spki_sha256);
    append(&mut preimage, &boot_lease_id);
    Sha512::digest(preimage).into()
}

#[derive(Clone, Copy)]
pub struct Challenge([u8; CHALLENGE_BYTES]);

impl Challenge {
    pub fn try_from_wire(request: wire::EvidenceRequest) -> Result<Self, ProtocolError> {
        Ok(Self(exact("challenge", request.challenge)?))
    }

    pub fn into_bytes(self) -> [u8; CHALLENGE_BYTES] {
        self.0
    }
}

pub struct ValidatedEvidence {
    boot_lease_id: [u8; LEASE_BYTES],
    quote_v4: Vec<u8>,
    ccel_table: Vec<u8>,
    ccel_log: Vec<u8>,
}

impl ValidatedEvidence {
    pub fn try_from_wire(response: wire::EvidenceResponse) -> Result<Self, ProtocolError> {
        if response.transcript_version != TRANSCRIPT_VERSION {
            return Err(ProtocolError::Version);
        }
        Ok(Self {
            boot_lease_id: exact("boot_lease_id", response.boot_lease_id)?,
            quote_v4: bounded("quote_v4", response.quote_v4, MAX_QUOTE_BYTES)?,
            ccel_table: bounded("ccel_table", response.ccel_table, MAX_CCEL_TABLE_BYTES)?,
            ccel_log: bounded("ccel_log", response.ccel_log, MAX_CCEL_LOG_BYTES)?,
        })
    }

    pub fn boot_lease_id(&self) -> [u8; LEASE_BYTES] {
        self.boot_lease_id
    }

    pub fn quote_v4(&self) -> &[u8] {
        &self.quote_v4
    }

    pub fn ccel_table(&self) -> &[u8] {
        &self.ccel_table
    }

    pub fn ccel_log(&self) -> &[u8] {
        &self.ccel_log
    }
}

fn append(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&(value.len() as u16).to_be_bytes());
    output.extend_from_slice(value);
}
fn exact<const N: usize>(name: &'static str, value: Vec<u8>) -> Result<[u8; N], ProtocolError> {
    value.try_into().map_err(|_| ProtocolError::Width(name))
}
fn bounded(name: &'static str, value: Vec<u8>, limit: usize) -> Result<Vec<u8>, ProtocolError> {
    if value.is_empty() {
        Err(ProtocolError::Empty(name))
    } else if value.len() > limit {
        Err(ProtocolError::Width(name))
    } else {
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn transcript_changes_for_each_owner_input() {
        let base = report_data([1; 64], [2; 32], [3; 32]);
        assert_ne!(base, report_data([0; 64], [2; 32], [3; 32]));
        assert_ne!(base, report_data([1; 64], [0; 32], [3; 32]));
        assert_ne!(base, report_data([1; 64], [2; 32], [0; 32]));
    }

    #[test]
    fn canonical_transcript_golden() {
        assert_eq!(
            report_data([1; 64], [2; 32], [3; 32]),
            [
                0x15, 0x38, 0x65, 0x6a, 0xce, 0xe1, 0x7e, 0x3f, 0x78, 0x32, 0xbc, 0x22, 0xa3, 0x50,
                0x1d, 0xaa, 0x93, 0x4d, 0xab, 0x4c, 0xd0, 0xc2, 0xdd, 0xd2, 0x92, 0xed, 0x1b, 0x6f,
                0xc3, 0xf2, 0x54, 0xa6, 0x55, 0xde, 0x9a, 0x06, 0x85, 0x5b, 0x33, 0x89, 0xa4, 0x75,
                0xf4, 0x73, 0xb3, 0x0b, 0x21, 0xb3, 0x90, 0xc8, 0xce, 0x93, 0x6a, 0x3e, 0x2e, 0xc9,
                0x29, 0x99, 0x8e, 0x9f, 0x00, 0xd0, 0x8b, 0xae,
            ]
        );
    }

    #[test]
    fn wire_boundaries_reject_missing_and_oversized_fields() {
        assert_eq!(
            Challenge::try_from_wire(wire::EvidenceRequest {
                challenge: vec![0; 63]
            })
            .err(),
            Some(ProtocolError::Width("challenge"))
        );
        let valid = wire::EvidenceResponse {
            transcript_version: 1,
            boot_lease_id: vec![1; 32],
            quote_v4: vec![1],
            ccel_table: vec![1],
            ccel_log: vec![1],
        };
        assert!(ValidatedEvidence::try_from_wire(valid.clone()).is_ok());
        let mut invalid = valid.clone();
        invalid.transcript_version = 2;
        assert_eq!(
            ValidatedEvidence::try_from_wire(invalid).err(),
            Some(ProtocolError::Version)
        );
        let mut invalid = valid.clone();
        invalid.quote_v4.clear();
        assert_eq!(
            ValidatedEvidence::try_from_wire(invalid).err(),
            Some(ProtocolError::Empty("quote_v4"))
        );
        let mut invalid = valid;
        invalid.ccel_log = vec![0; MAX_CCEL_LOG_BYTES + 1];
        assert_eq!(
            ValidatedEvidence::try_from_wire(invalid).err(),
            Some(ProtocolError::Width("ccel_log"))
        );
    }
}
