//! Shared XChaCha20-Poly1305 operations for crate-internal protectors.

use std::fmt;

use chacha20poly1305::{
    aead::{AeadInPlace, KeyInit},
    Key, Tag, XChaCha20Poly1305, XNonce,
};
use zeroize::Zeroizing;

use crate::protection::{AuthenticationDecision, ProtectionUnavailable};

pub(super) const KEY_BYTES: usize = 32;
pub(super) const NONCE_BYTES: usize = 24;
pub(super) const AUTHENTICATION_BYTES: usize = 16;
pub(super) const ENVELOPE_ASSOCIATED_DATA_DOMAIN: &[u8] = b"zaino.private.v1/aead/envelope/v1";
pub(super) const CONTINUATION_ASSOCIATED_DATA_DOMAIN: &[u8] =
    b"zaino.private.v1/aead/continuation/v1";

const CHACHA_BLOCK_BYTES: usize = 64;
const MAX_CHACHA_BLOCKS: usize = u32::MAX as usize;

/// One separately owned XChaCha20-Poly1305 role-key object.
///
/// The dependency zeroizes its retained key on drop. Requiring `Zeroizing`
/// here also clears the constructor's input after the cipher copies it into
/// its private storage.
pub(super) struct XChaCha20ProtectionKey {
    cipher: XChaCha20Poly1305,
}

impl XChaCha20ProtectionKey {
    pub(super) fn new(key: Zeroizing<[u8; KEY_BYTES]>) -> Self {
        let cipher = XChaCha20Poly1305::new(Key::from_slice(key.as_ref()));
        Self { cipher }
    }

    pub(super) fn seal(
        &self,
        associated_data: &[u8],
        nonce: &[u8; NONCE_BYTES],
        body: &mut [u8],
    ) -> Result<[u8; AUTHENTICATION_BYTES], ProtectionUnavailable> {
        if !input_lengths_supported(associated_data.len(), body.len()) {
            return Err(ProtectionUnavailable);
        }

        self.cipher
            .encrypt_in_place_detached(XNonce::from_slice(nonce), associated_data, body)
            .map(Into::into)
            .map_err(|_| ProtectionUnavailable)
    }

    pub(super) fn open(
        &self,
        associated_data: &[u8],
        nonce: &[u8; NONCE_BYTES],
        body: &mut [u8],
        authentication: &[u8; AUTHENTICATION_BYTES],
    ) -> Result<AuthenticationDecision, ProtectionUnavailable> {
        if !input_lengths_supported(associated_data.len(), body.len()) {
            return Err(ProtectionUnavailable);
        }

        match self.cipher.decrypt_in_place_detached(
            XNonce::from_slice(nonce),
            associated_data,
            body,
            Tag::from_slice(authentication),
        ) {
            Ok(()) => Ok(AuthenticationDecision::Accepted),
            Err(_) => Ok(AuthenticationDecision::Rejected),
        }
    }
}

impl fmt::Debug for XChaCha20ProtectionKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("XChaCha20ProtectionKey { ..REDACTED.. }")
    }
}

fn input_lengths_supported(associated_data_bytes: usize, body_bytes: usize) -> bool {
    u64::try_from(associated_data_bytes).is_ok()
        && u64::try_from(body_bytes).is_ok()
        && body_bytes / CHACHA_BLOCK_BYTES < MAX_CHACHA_BLOCKS
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; KEY_BYTES] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];
    const NONCE: [u8; NONCE_BYTES] = [
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e,
        0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    ];
    const ASSOCIATED_DATA: [u8; 12] = *b"zaino-aad-v1";
    const PLAINTEXT: [u8; 32] = [
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e,
        0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d,
        0x5e, 0x5f,
    ];

    fn protection_key() -> XChaCha20ProtectionKey {
        XChaCha20ProtectionKey::new(Zeroizing::new(KEY))
    }

    #[test]
    fn fixed_vector_round_trips() {
        let key = protection_key();
        let mut body = PLAINTEXT;
        let authentication = key
            .seal(&ASSOCIATED_DATA, &NONCE, &mut body)
            .expect("fixed vector seals");

        // Cross-checked with Go x/crypto/chacha20poly1305 v0.47.0 and pinned so
        // wrapper or dependency drift is visible.
        let expected_body = [
            0x5d, 0x18, 0x0f, 0x88, 0x3f, 0x72, 0x52, 0xcc, 0x70, 0xf7, 0x1a, 0xf6, 0x04, 0x0a,
            0x4f, 0x9e, 0x6d, 0x04, 0x83, 0x6f, 0x8b, 0xc6, 0x50, 0xe2, 0xb9, 0x38, 0x06, 0x72,
            0x53, 0x64, 0xb4, 0x5d,
        ];
        let expected_authentication = [
            0x39, 0x21, 0x61, 0x65, 0x43, 0xed, 0x7a, 0xb9, 0xf5, 0x85, 0xce, 0x48, 0xad, 0xbb,
            0xbf, 0x64,
        ];
        assert_eq!(body, expected_body);
        assert_eq!(authentication, expected_authentication);

        assert_eq!(
            key.open(&ASSOCIATED_DATA, &NONCE, &mut body, &authentication),
            Ok(AuthenticationDecision::Accepted)
        );
        assert_eq!(body, PLAINTEXT);
    }

    #[test]
    fn every_protected_input_mutation_rejects_without_exposing_plaintext() {
        let key = protection_key();
        let mut ciphertext = PLAINTEXT;
        let authentication = key
            .seal(&ASSOCIATED_DATA, &NONCE, &mut ciphertext)
            .expect("mutation fixture seals");

        for index in 0..ciphertext.len() {
            let mut candidate = ciphertext;
            candidate[index] ^= 1;
            let rejected_ciphertext = candidate;
            assert_eq!(
                key.open(&ASSOCIATED_DATA, &NONCE, &mut candidate, &authentication,),
                Ok(AuthenticationDecision::Rejected)
            );
            assert_eq!(candidate, rejected_ciphertext);
        }

        for index in 0..authentication.len() {
            let mut candidate_authentication = authentication;
            candidate_authentication[index] ^= 1;
            let mut candidate = ciphertext;
            assert_eq!(
                key.open(
                    &ASSOCIATED_DATA,
                    &NONCE,
                    &mut candidate,
                    &candidate_authentication,
                ),
                Ok(AuthenticationDecision::Rejected)
            );
            assert_eq!(candidate, ciphertext);
        }

        for index in 0..NONCE.len() {
            let mut candidate_nonce = NONCE;
            candidate_nonce[index] ^= 1;
            let mut candidate = ciphertext;
            assert_eq!(
                key.open(
                    &ASSOCIATED_DATA,
                    &candidate_nonce,
                    &mut candidate,
                    &authentication,
                ),
                Ok(AuthenticationDecision::Rejected)
            );
            assert_eq!(candidate, ciphertext);
        }

        for index in 0..ASSOCIATED_DATA.len() {
            let mut candidate_associated_data = ASSOCIATED_DATA;
            candidate_associated_data[index] ^= 1;
            let mut candidate = ciphertext;
            assert_eq!(
                key.open(
                    &candidate_associated_data,
                    &NONCE,
                    &mut candidate,
                    &authentication,
                ),
                Ok(AuthenticationDecision::Rejected)
            );
            assert_eq!(candidate, ciphertext);
        }
    }

    #[test]
    fn wrong_key_rejects_without_exposing_plaintext() {
        let key = protection_key();
        let mut ciphertext = PLAINTEXT;
        let authentication = key
            .seal(&ASSOCIATED_DATA, &NONCE, &mut ciphertext)
            .expect("wrong-key fixture seals");
        let wrong_key = XChaCha20ProtectionKey::new(Zeroizing::new([0xa5; KEY_BYTES]));
        let rejected_ciphertext = ciphertext;

        assert_eq!(
            wrong_key.open(&ASSOCIATED_DATA, &NONCE, &mut ciphertext, &authentication,),
            Ok(AuthenticationDecision::Rejected)
        );
        assert_eq!(ciphertext, rejected_ciphertext);
    }

    #[test]
    fn envelope_and_continuation_domains_reject_cross_role_open() {
        let key = protection_key();
        let envelope_associated_data = test_associated_data(ENVELOPE_ASSOCIATED_DATA_DOMAIN, 51);
        let continuation_associated_data =
            test_associated_data(CONTINUATION_ASSOCIATED_DATA_DOMAIN, 89);
        let mut envelope_ciphertext = PLAINTEXT;
        let envelope_authentication = key
            .seal(&envelope_associated_data, &NONCE, &mut envelope_ciphertext)
            .expect("envelope-domain fixture seals");
        let rejected_envelope_ciphertext = envelope_ciphertext;

        assert_eq!(
            key.open(
                &continuation_associated_data,
                &NONCE,
                &mut envelope_ciphertext,
                &envelope_authentication,
            ),
            Ok(AuthenticationDecision::Rejected)
        );
        assert_eq!(envelope_ciphertext, rejected_envelope_ciphertext);

        let mut continuation_ciphertext = PLAINTEXT;
        let continuation_authentication = key
            .seal(
                &continuation_associated_data,
                &NONCE,
                &mut continuation_ciphertext,
            )
            .expect("continuation-domain fixture seals");
        let rejected_continuation_ciphertext = continuation_ciphertext;

        assert_eq!(
            key.open(
                &envelope_associated_data,
                &NONCE,
                &mut continuation_ciphertext,
                &continuation_authentication,
            ),
            Ok(AuthenticationDecision::Rejected)
        );
        assert_eq!(continuation_ciphertext, rejected_continuation_ciphertext);
    }

    fn test_associated_data(domain: &[u8], context_bytes: usize) -> Vec<u8> {
        let mut associated_data = domain.to_vec();
        associated_data.resize(domain.len() + context_bytes, 0x91);
        associated_data
    }
}
