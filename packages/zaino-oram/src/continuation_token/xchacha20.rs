//! XChaCha20-Poly1305 protection for fixed continuation tokens.

use std::fmt;

use zeroize::Zeroizing;

use super::{
    ContinuationProtectionContext, ContinuationTokenProtector, AUTHENTICATION_BYTES,
    CONTINUATION_CONTEXT_BYTES, NONCE_BYTES, PROTECTED_BODY_BYTES,
};
use crate::{
    protection::{AuthenticationDecision, ProtectionUnavailable},
    xchacha20::{
        XChaCha20ProtectionKey, AUTHENTICATION_BYTES as XCHACHA_AUTHENTICATION_BYTES,
        CONTINUATION_ASSOCIATED_DATA_DOMAIN, KEY_BYTES, NONCE_BYTES as XCHACHA_NONCE_BYTES,
    },
};

const CONTINUATION_ASSOCIATED_DATA_BYTES: usize =
    CONTINUATION_ASSOCIATED_DATA_DOMAIN.len() + CONTINUATION_CONTEXT_BYTES;

const _: [(); NONCE_BYTES] = [(); XCHACHA_NONCE_BYTES];
const _: [(); AUTHENTICATION_BYTES] = [(); XCHACHA_AUTHENTICATION_BYTES];

pub(super) fn token_protector(key: Zeroizing<[u8; KEY_BYTES]>) -> impl ContinuationTokenProtector {
    XChaCha20ContinuationTokenProtector::new(key)
}

/// Separately owned continuation-token role-key object.
struct XChaCha20ContinuationTokenProtector {
    key: XChaCha20ProtectionKey,
}

impl XChaCha20ContinuationTokenProtector {
    fn new(key: Zeroizing<[u8; KEY_BYTES]>) -> Self {
        Self {
            key: XChaCha20ProtectionKey::new(key),
        }
    }
}

impl ContinuationTokenProtector for XChaCha20ContinuationTokenProtector {
    fn seal(
        &self,
        context: &ContinuationProtectionContext,
        nonce: &[u8; NONCE_BYTES],
        body: &mut [u8; PROTECTED_BODY_BYTES],
    ) -> Result<[u8; AUTHENTICATION_BYTES], ProtectionUnavailable> {
        self.key
            .seal(&associated_data(context), nonce, body.as_mut_slice())
    }

    fn open(
        &self,
        context: &ContinuationProtectionContext,
        nonce: &[u8; NONCE_BYTES],
        body: &mut [u8; PROTECTED_BODY_BYTES],
        authentication: &[u8; AUTHENTICATION_BYTES],
    ) -> Result<AuthenticationDecision, ProtectionUnavailable> {
        self.key.open(
            &associated_data(context),
            nonce,
            body.as_mut_slice(),
            authentication,
        )
    }
}

impl fmt::Debug for XChaCha20ContinuationTokenProtector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("XChaCha20ContinuationTokenProtector { ..REDACTED.. }")
    }
}

fn associated_data(
    context: &ContinuationProtectionContext,
) -> [u8; CONTINUATION_ASSOCIATED_DATA_BYTES] {
    let mut bytes = [0; CONTINUATION_ASSOCIATED_DATA_BYTES];
    let context_start = CONTINUATION_ASSOCIATED_DATA_DOMAIN.len();
    bytes[..context_start].copy_from_slice(CONTINUATION_ASSOCIATED_DATA_DOMAIN);
    bytes[context_start..].copy_from_slice(context.as_bytes());
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; KEY_BYTES] = [0x81; KEY_BYTES];
    const NONCE: [u8; NONCE_BYTES] = [0x82; NONCE_BYTES];
    const CONTEXT: [u8; CONTINUATION_CONTEXT_BYTES] = [0x83; CONTINUATION_CONTEXT_BYTES];
    const PLAINTEXT: [u8; PROTECTED_BODY_BYTES] = [0x84; PROTECTED_BODY_BYTES];
    const CIPHERTEXT: [u8; PROTECTED_BODY_BYTES] = [
        0xae, 0x84, 0x2d, 0xbc, 0xab, 0x2a, 0x1f, 0x74, 0x72, 0x22, 0xca, 0xa8, 0x5e, 0x51, 0xe0,
        0x43, 0x1f, 0xa3, 0xfe, 0x33, 0xcf, 0xdc, 0x39, 0x7b, 0x11, 0x48, 0x25, 0x27, 0x82, 0xcf,
        0xee, 0x7f, 0xe6, 0xa5, 0xd0, 0x79, 0x06, 0xa5, 0x19, 0x76, 0xe0, 0x75, 0xb0, 0xf6, 0xa4,
        0x01, 0x9c, 0x38, 0x8b, 0xbe, 0x3f, 0xdf, 0x37, 0x9c, 0xb0, 0x46, 0x60, 0xec, 0xe6, 0x31,
        0x9e, 0x48, 0x49, 0x8c, 0x96, 0x62, 0x37, 0x46, 0xc5, 0xa4, 0x83, 0x1f, 0xa6, 0xda, 0xe1,
        0xfc, 0xb3, 0x63, 0x89, 0x8b, 0x56, 0x7a, 0xe3, 0xb2, 0xc6, 0x5d, 0x59, 0x4b,
    ];
    const AUTHENTICATION: [u8; AUTHENTICATION_BYTES] = [
        0x7e, 0x47, 0x4c, 0xc5, 0xe2, 0x44, 0xf3, 0x4c, 0x56, 0x2a, 0xe8, 0x78, 0x64, 0x8b, 0x2b,
        0x2d,
    ];

    fn protector() -> XChaCha20ContinuationTokenProtector {
        XChaCha20ContinuationTokenProtector::new(Zeroizing::new(KEY))
    }

    #[test]
    fn associated_data_is_canonical_and_complete() {
        let context = ContinuationProtectionContext::new(CONTEXT);
        let bytes = associated_data(&context);
        let context_start = CONTINUATION_ASSOCIATED_DATA_DOMAIN.len();

        assert_eq!(&bytes[..context_start], CONTINUATION_ASSOCIATED_DATA_DOMAIN);
        assert_eq!(&bytes[context_start..], &CONTEXT);
    }

    #[test]
    fn continuation_round_trip_authenticates_context() {
        let protector = protector();
        let context = ContinuationProtectionContext::new(CONTEXT);
        let mut ciphertext = PLAINTEXT;
        let authentication = protector
            .seal(&context, &NONCE, &mut ciphertext)
            .expect("continuation body seals");
        assert_eq!(ciphertext, CIPHERTEXT);
        assert_eq!(authentication, AUTHENTICATION);

        for index in 0..CONTEXT.len() {
            let mut changed_context_bytes = CONTEXT;
            changed_context_bytes[index] ^= 1;
            let changed_context = ContinuationProtectionContext::new(changed_context_bytes);
            let mut rejected_body = ciphertext;
            assert_eq!(
                protector.open(
                    &changed_context,
                    &NONCE,
                    &mut rejected_body,
                    &authentication,
                ),
                Ok(AuthenticationDecision::Rejected)
            );
            assert_eq!(rejected_body, ciphertext);
        }

        assert_eq!(
            protector.open(&context, &NONCE, &mut ciphertext, &authentication),
            Ok(AuthenticationDecision::Accepted)
        );
        assert_eq!(ciphertext, PLAINTEXT);
    }
}
