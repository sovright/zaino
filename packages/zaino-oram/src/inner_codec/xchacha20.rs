//! XChaCha20-Poly1305 protection for complete private-query envelopes.

use std::fmt;

use zeroize::Zeroizing;

use super::{
    EnvelopeDirection, EnvelopeProtectionContext, EnvelopeProtector, ENVELOPE_AUTHENTICATION_BYTES,
    ENVELOPE_NONCE_BYTES, PROFILE_ID_BYTES, SESSION_BINDING_BYTES, U16_BYTES,
};
use crate::{
    protection::{AuthenticationDecision, ProtectionUnavailable},
    xchacha20::{
        XChaCha20ProtectionKey, AUTHENTICATION_BYTES, ENVELOPE_ASSOCIATED_DATA_DOMAIN, KEY_BYTES,
        NONCE_BYTES,
    },
};

const ENVELOPE_CONTEXT_BYTES: usize = U16_BYTES + 1 + PROFILE_ID_BYTES + SESSION_BINDING_BYTES;
const ENVELOPE_ASSOCIATED_DATA_BYTES: usize =
    ENVELOPE_ASSOCIATED_DATA_DOMAIN.len() + ENVELOPE_CONTEXT_BYTES;

const _: [(); ENVELOPE_NONCE_BYTES] = [(); NONCE_BYTES];
const _: [(); ENVELOPE_AUTHENTICATION_BYTES] = [(); AUTHENTICATION_BYTES];

/// Separately owned request and response envelope role-key objects.
struct XChaCha20EnvelopeProtector {
    request_key: XChaCha20ProtectionKey,
    response_key: XChaCha20ProtectionKey,
}

impl XChaCha20EnvelopeProtector {
    fn new(
        request_key: Zeroizing<[u8; KEY_BYTES]>,
        response_key: Zeroizing<[u8; KEY_BYTES]>,
    ) -> Self {
        Self {
            request_key: XChaCha20ProtectionKey::new(request_key),
            response_key: XChaCha20ProtectionKey::new(response_key),
        }
    }

    const fn key(&self, direction: EnvelopeDirection) -> &XChaCha20ProtectionKey {
        match direction {
            EnvelopeDirection::Request => &self.request_key,
            EnvelopeDirection::Response => &self.response_key,
        }
    }
}

impl EnvelopeProtector for XChaCha20EnvelopeProtector {
    fn seal(
        &self,
        context: &EnvelopeProtectionContext,
        nonce: &[u8; ENVELOPE_NONCE_BYTES],
        body: &mut [u8],
    ) -> Result<[u8; ENVELOPE_AUTHENTICATION_BYTES], ProtectionUnavailable> {
        self.key(context.direction)
            .seal(&associated_data(context), nonce, body)
    }

    fn open(
        &self,
        context: &EnvelopeProtectionContext,
        nonce: &[u8; ENVELOPE_NONCE_BYTES],
        body: &mut [u8],
        authentication: &[u8; ENVELOPE_AUTHENTICATION_BYTES],
    ) -> Result<AuthenticationDecision, ProtectionUnavailable> {
        self.key(context.direction)
            .open(&associated_data(context), nonce, body, authentication)
    }
}

impl fmt::Debug for XChaCha20EnvelopeProtector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("XChaCha20EnvelopeProtector { ..REDACTED.. }")
    }
}

fn associated_data(context: &EnvelopeProtectionContext) -> [u8; ENVELOPE_ASSOCIATED_DATA_BYTES] {
    let mut bytes = [0; ENVELOPE_ASSOCIATED_DATA_BYTES];
    let mut cursor = ENVELOPE_ASSOCIATED_DATA_DOMAIN.len();
    bytes[..cursor].copy_from_slice(ENVELOPE_ASSOCIATED_DATA_DOMAIN);

    let format_version_end = cursor + U16_BYTES;
    bytes[cursor..format_version_end].copy_from_slice(&context.format_version.to_be_bytes());
    cursor = format_version_end;

    bytes[cursor] = context.direction.tag();
    cursor += 1;

    let profile_id_end = cursor + PROFILE_ID_BYTES;
    bytes[cursor..profile_id_end].copy_from_slice(&context.profile_id);
    cursor = profile_id_end;

    bytes[cursor..].copy_from_slice(&context.session_binding);
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    const REQUEST_KEY: [u8; KEY_BYTES] = [0x11; KEY_BYTES];
    const RESPONSE_KEY: [u8; KEY_BYTES] = [0x22; KEY_BYTES];
    const NONCE: [u8; ENVELOPE_NONCE_BYTES] = [0x33; ENVELOPE_NONCE_BYTES];
    const PROFILE_ID: [u8; PROFILE_ID_BYTES] = [0x44; PROFILE_ID_BYTES];
    const SESSION_BINDING: [u8; SESSION_BINDING_BYTES] = [0x55; SESSION_BINDING_BYTES];
    const PLAINTEXT: [u8; 32] = [0x66; 32];
    const REQUEST_CIPHERTEXT: [u8; PLAINTEXT.len()] = [
        0xdc, 0xc2, 0x11, 0xef, 0x1e, 0x0d, 0x65, 0x51, 0xe4, 0xf2, 0x4e, 0xc2, 0xa8, 0x8b, 0x98,
        0xb0, 0xed, 0x21, 0x1a, 0x98, 0x2a, 0xd5, 0x12, 0xea, 0x8d, 0x02, 0xf0, 0x1c, 0xf6, 0x71,
        0x99, 0x27,
    ];
    const REQUEST_AUTHENTICATION: [u8; ENVELOPE_AUTHENTICATION_BYTES] = [
        0x85, 0xbf, 0xb0, 0x77, 0xf5, 0x07, 0xda, 0x0e, 0x8e, 0xd5, 0x15, 0xa8, 0xb4, 0x47, 0x51,
        0xa9,
    ];
    const RESPONSE_CIPHERTEXT: [u8; PLAINTEXT.len()] = [
        0xf4, 0x9c, 0x42, 0x0b, 0xa3, 0xa2, 0x03, 0xe0, 0xc6, 0x7e, 0x6f, 0xcd, 0x38, 0x80, 0xcd,
        0x41, 0x4b, 0x06, 0x67, 0x6f, 0x3b, 0x98, 0x38, 0xd7, 0x6a, 0xb7, 0x88, 0x61, 0x08, 0xe6,
        0xf8, 0x0f,
    ];
    const RESPONSE_AUTHENTICATION: [u8; ENVELOPE_AUTHENTICATION_BYTES] = [
        0xd0, 0xa2, 0x52, 0x74, 0x84, 0x52, 0xfb, 0x9c, 0xb8, 0x70, 0xec, 0xa5, 0x62, 0xd0, 0x84,
        0xb1,
    ];

    fn protector() -> XChaCha20EnvelopeProtector {
        protector_with_keys(REQUEST_KEY, RESPONSE_KEY)
    }

    fn protector_with_keys(
        request_key: [u8; KEY_BYTES],
        response_key: [u8; KEY_BYTES],
    ) -> XChaCha20EnvelopeProtector {
        XChaCha20EnvelopeProtector::new(Zeroizing::new(request_key), Zeroizing::new(response_key))
    }

    const fn context(direction: EnvelopeDirection) -> EnvelopeProtectionContext {
        EnvelopeProtectionContext {
            format_version: 1,
            direction,
            profile_id: PROFILE_ID,
            session_binding: SESSION_BINDING,
        }
    }

    #[test]
    fn associated_data_is_canonical_and_complete() {
        let context = context(EnvelopeDirection::Request);
        let bytes = associated_data(&context);
        let mut cursor = ENVELOPE_ASSOCIATED_DATA_DOMAIN.len();

        assert_eq!(&bytes[..cursor], ENVELOPE_ASSOCIATED_DATA_DOMAIN);
        assert_eq!(&bytes[cursor..cursor + U16_BYTES], &[0, 1]);
        cursor += U16_BYTES;
        assert_eq!(bytes[cursor], EnvelopeDirection::Request.tag());
        cursor += 1;
        assert_eq!(&bytes[cursor..cursor + PROFILE_ID_BYTES], &PROFILE_ID);
        cursor += PROFILE_ID_BYTES;
        assert_eq!(&bytes[cursor..], &SESSION_BINDING);
    }

    #[test]
    fn request_and_response_role_keys_round_trip() {
        let protector = protector();
        let request_context = context(EnvelopeDirection::Request);
        let response_context = context(EnvelopeDirection::Response);
        let mut request_body = PLAINTEXT;
        let request_authentication = protector
            .seal(&request_context, &NONCE, &mut request_body)
            .expect("request envelope seals");
        let sealed_request_body = request_body;
        assert_eq!(request_body, REQUEST_CIPHERTEXT);
        assert_eq!(request_authentication, REQUEST_AUTHENTICATION);

        let mut wrong_domain_body = request_body;
        assert_eq!(
            protector.open(
                &response_context,
                &NONCE,
                &mut wrong_domain_body,
                &request_authentication,
            ),
            Ok(AuthenticationDecision::Rejected)
        );
        assert_eq!(wrong_domain_body, request_body);

        assert_eq!(
            protector.open(
                &request_context,
                &NONCE,
                &mut request_body,
                &request_authentication,
            ),
            Ok(AuthenticationDecision::Accepted)
        );
        assert_eq!(request_body, PLAINTEXT);

        let mut response_body = PLAINTEXT;
        let response_authentication = protector
            .seal(&response_context, &NONCE, &mut response_body)
            .expect("response envelope seals");
        assert_eq!(response_body, RESPONSE_CIPHERTEXT);
        assert_eq!(response_authentication, RESPONSE_AUTHENTICATION);
        assert_ne!(response_body, sealed_request_body);
        assert_ne!(response_authentication, request_authentication);
        assert_eq!(
            protector.open(
                &response_context,
                &NONCE,
                &mut response_body,
                &response_authentication,
            ),
            Ok(AuthenticationDecision::Accepted)
        );
        assert_eq!(response_body, PLAINTEXT);
    }

    #[test]
    fn direction_is_authenticated_even_when_role_key_bytes_match() {
        let protector = protector_with_keys(REQUEST_KEY, REQUEST_KEY);
        let request_context = context(EnvelopeDirection::Request);
        let response_context = context(EnvelopeDirection::Response);
        let mut ciphertext = PLAINTEXT;
        let authentication = protector
            .seal(&request_context, &NONCE, &mut ciphertext)
            .expect("equal-key direction fixture seals");
        let rejected_ciphertext = ciphertext;

        assert_eq!(
            protector.open(&response_context, &NONCE, &mut ciphertext, &authentication,),
            Ok(AuthenticationDecision::Rejected)
        );
        assert_eq!(ciphertext, rejected_ciphertext);
    }

    #[test]
    fn every_context_field_is_authenticated() {
        let protector = protector();
        let original_context = context(EnvelopeDirection::Request);
        let plaintext = [0x77; 29];
        let mut ciphertext = plaintext;
        let authentication = protector
            .seal(&original_context, &NONCE, &mut ciphertext)
            .expect("context fixture seals");

        let mut changed_version = original_context;
        changed_version.format_version += 1;
        let mut changed_profile = original_context;
        changed_profile.profile_id[0] ^= 1;
        let mut changed_session = original_context;
        changed_session.session_binding[0] ^= 1;

        for changed_context in [changed_version, changed_profile, changed_session] {
            let mut candidate = ciphertext;
            assert_eq!(
                protector.open(&changed_context, &NONCE, &mut candidate, &authentication,),
                Ok(AuthenticationDecision::Rejected)
            );
            assert_eq!(candidate, ciphertext);
        }
    }
}
