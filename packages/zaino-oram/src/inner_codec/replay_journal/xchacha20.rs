//! XChaCha20-Poly1305 protection for replay-journal records at rest.

use std::fmt;

use rand::TryRngCore as _;
use zeroize::Zeroizing;

use super::{
    read_array, ReplayJournalProtectionContext, ReplayJournalRecordKind,
    ReplayJournalRecordProtector, DIGEST_BYTES, PROTECTION_OVERHEAD_BYTES, U16_BYTES,
};
use crate::{
    protection::{AuthenticationDecision, ProtectionUnavailable},
    xchacha20::{
        XChaCha20ProtectionKey, AUTHENTICATION_BYTES, KEY_BYTES, NONCE_BYTES,
        REPLAY_JOURNAL_ASSOCIATED_DATA_DOMAIN,
    },
};

/// Offset of the sealed body within one protected record.
const CIPHERTEXT_START: usize = NONCE_BYTES + AUTHENTICATION_BYTES;

const RECORD_CONTEXT_BYTES: usize = U16_BYTES + 1 + DIGEST_BYTES;
const RECORD_ASSOCIATED_DATA_BYTES: usize =
    REPLAY_JOURNAL_ASSOCIATED_DATA_DOMAIN.len() + RECORD_CONTEXT_BYTES;

/// The journal's fixed record overhead has to be exactly one nonce plus one tag.
const _: () = assert!(PROTECTION_OVERHEAD_BYTES == CIPHERTEXT_START);

/// Supplies one unpredictable nonce per sealed journal record.
///
/// Injected rather than drawn inline so the exhaustion and repetition paths
/// stay testable: a real generator cannot be made to fail or repeat on demand,
/// and both are exactly the paths that must fail closed.
pub(in crate::inner_codec) trait JournalRecordNonces {
    fn next_nonce(&self) -> Result<[u8; NONCE_BYTES], ProtectionUnavailable>;
}

/// Draws record nonces from the operating system generator.
pub(in crate::inner_codec) struct OsJournalRecordNonces;

impl JournalRecordNonces for OsJournalRecordNonces {
    fn next_nonce(&self) -> Result<[u8; NONCE_BYTES], ProtectionUnavailable> {
        let mut nonce = [0; NONCE_BYTES];
        rand::rngs::OsRng
            .try_fill_bytes(&mut nonce)
            .map_err(|_| ProtectionUnavailable)?;
        Ok(nonce)
    }
}

/// Composes the production record protector over one journal record key.
pub(in crate::inner_codec) fn record_protector<N>(
    record_key: Zeroizing<[u8; KEY_BYTES]>,
    nonces: N,
) -> impl ReplayJournalRecordProtector
where
    N: JournalRecordNonces,
{
    XChaCha20ReplayJournalRecordProtector {
        key: XChaCha20ProtectionKey::new(record_key),
        nonces,
    }
}

/// One journal record key paired with the nonce source that keeps it safe.
struct XChaCha20ReplayJournalRecordProtector<N> {
    key: XChaCha20ProtectionKey,
    nonces: N,
}

impl<N> ReplayJournalRecordProtector for XChaCha20ReplayJournalRecordProtector<N>
where
    N: JournalRecordNonces,
{
    fn seal(
        &self,
        context: &ReplayJournalProtectionContext,
        kind: ReplayJournalRecordKind,
        plaintext: &[u8],
        protected: &mut [u8],
    ) -> Result<(), ProtectionUnavailable> {
        if protected.len() != plaintext.len() + PROTECTION_OVERHEAD_BYTES {
            return Err(ProtectionUnavailable);
        }
        let nonce = self.nonces.next_nonce()?;
        let (header, body) = protected.split_at_mut(CIPHERTEXT_START);
        body.copy_from_slice(plaintext);
        // The header stays zeroed until the body seals, so an interrupted seal
        // leaves a record that cannot authenticate rather than a partial one.
        let authentication = self
            .key
            .seal(&associated_data(context, kind), &nonce, body)?;
        header[..NONCE_BYTES].copy_from_slice(&nonce);
        header[NONCE_BYTES..].copy_from_slice(&authentication);
        Ok(())
    }

    fn open(
        &self,
        context: &ReplayJournalProtectionContext,
        kind: ReplayJournalRecordKind,
        protected: &[u8],
        plaintext: &mut [u8],
    ) -> Result<AuthenticationDecision, ProtectionUnavailable> {
        if protected.len() != plaintext.len() + PROTECTION_OVERHEAD_BYTES {
            return Err(ProtectionUnavailable);
        }
        let nonce = read_array::<NONCE_BYTES>(protected, 0);
        let authentication = read_array::<AUTHENTICATION_BYTES>(protected, NONCE_BYTES);
        plaintext.copy_from_slice(&protected[CIPHERTEXT_START..]);
        let decision = self.key.open(
            &associated_data(context, kind),
            &nonce,
            plaintext,
            &authentication,
        )?;
        if decision == AuthenticationDecision::Rejected {
            // A rejected record leaves the caller's buffer holding ciphertext;
            // clear it so no unauthenticated bytes survive the call.
            plaintext.fill(0);
        }
        Ok(decision)
    }
}

impl<N> fmt::Debug for XChaCha20ReplayJournalRecordProtector<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("XChaCha20ReplayJournalRecordProtector { ..REDACTED.. }")
    }
}

fn associated_data(
    context: &ReplayJournalProtectionContext,
    kind: ReplayJournalRecordKind,
) -> [u8; RECORD_ASSOCIATED_DATA_BYTES] {
    let mut bytes = [0; RECORD_ASSOCIATED_DATA_BYTES];
    let mut cursor = REPLAY_JOURNAL_ASSOCIATED_DATA_DOMAIN.len();
    bytes[..cursor].copy_from_slice(REPLAY_JOURNAL_ASSOCIATED_DATA_DOMAIN);

    let format_version_end = cursor + U16_BYTES;
    bytes[cursor..format_version_end].copy_from_slice(&kind.format_version().to_be_bytes());
    cursor = format_version_end;

    bytes[cursor] = kind.tag();
    cursor += 1;

    bytes[cursor..].copy_from_slice(context.as_bytes());
    bytes
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;

    const KEY: [u8; KEY_BYTES] = [0x31; KEY_BYTES];
    const BODY_BYTES: usize = 24;
    const PLAINTEXT: [u8; BODY_BYTES] = [0x5c; BODY_BYTES];
    const KINDS: [ReplayJournalRecordKind; 2] = [
        ReplayJournalRecordKind::CurrentStateV3,
        ReplayJournalRecordKind::ImmutableEntryV2,
    ];

    /// Hands out distinct, predictable nonces and can be made to fail on demand.
    pub(super) struct CountingNonces {
        next: Cell<u8>,
        available: Cell<bool>,
    }

    impl CountingNonces {
        pub(super) const fn new() -> Self {
            Self {
                next: Cell::new(1),
                available: Cell::new(true),
            }
        }
    }

    impl JournalRecordNonces for CountingNonces {
        fn next_nonce(&self) -> Result<[u8; NONCE_BYTES], ProtectionUnavailable> {
            if !self.available.get() {
                return Err(ProtectionUnavailable);
            }
            let value = self.next.get();
            self.next.set(value.wrapping_add(1));
            Ok([value; NONCE_BYTES])
        }
    }

    fn protector() -> impl ReplayJournalRecordProtector {
        record_protector(Zeroizing::new(KEY), CountingNonces::new())
    }

    const fn context(binding: u8) -> ReplayJournalProtectionContext {
        ReplayJournalProtectionContext::new([binding; DIGEST_BYTES])
    }

    fn seal(
        protector: &impl ReplayJournalRecordProtector,
        context: &ReplayJournalProtectionContext,
        kind: ReplayJournalRecordKind,
    ) -> [u8; BODY_BYTES + PROTECTION_OVERHEAD_BYTES] {
        let mut protected = [0; BODY_BYTES + PROTECTION_OVERHEAD_BYTES];
        protector
            .seal(context, kind, &PLAINTEXT, &mut protected)
            .expect("fixture record seals");
        protected
    }

    #[test]
    fn every_record_kind_round_trips_under_its_own_context() {
        let protector = protector();
        let context = context(0x9a);

        for kind in KINDS {
            let protected = seal(&protector, &context, kind);
            let mut recovered = [0; BODY_BYTES];

            assert_eq!(
                protector.open(&context, kind, &protected, &mut recovered),
                Ok(AuthenticationDecision::Accepted)
            );
            assert_eq!(recovered, PLAINTEXT);
            assert_ne!(protected[CIPHERTEXT_START..], PLAINTEXT);
        }
    }

    #[test]
    fn record_kind_and_context_are_authenticated() {
        let protector = protector();
        let sealing_context = context(0x9a);
        let protected = seal(
            &protector,
            &sealing_context,
            ReplayJournalRecordKind::CurrentStateV3,
        );
        let other_context = context(0x9b);

        for (context, kind) in [
            (&other_context, ReplayJournalRecordKind::CurrentStateV3),
            (&sealing_context, ReplayJournalRecordKind::ImmutableEntryV2),
        ] {
            let mut recovered = [0xff; BODY_BYTES];

            assert_eq!(
                protector.open(context, kind, &protected, &mut recovered),
                Ok(AuthenticationDecision::Rejected)
            );
            assert_eq!(recovered, [0; BODY_BYTES]);
        }
    }

    #[test]
    fn every_protected_byte_is_authenticated_without_exposing_plaintext() {
        let protector = protector();
        let context = context(0x9a);
        let kind = ReplayJournalRecordKind::CurrentStateV3;
        let protected = seal(&protector, &context, kind);

        for index in 0..protected.len() {
            let mut candidate = protected;
            candidate[index] ^= 1;
            let mut recovered = [0xff; BODY_BYTES];

            assert_eq!(
                protector.open(&context, kind, &candidate, &mut recovered),
                Ok(AuthenticationDecision::Rejected)
            );
            assert_eq!(recovered, [0; BODY_BYTES]);
        }
    }

    #[test]
    fn each_seal_draws_a_fresh_nonce() {
        let protector = protector();
        let context = context(0x9a);
        let kind = ReplayJournalRecordKind::CurrentStateV3;

        let first = seal(&protector, &context, kind);
        let second = seal(&protector, &context, kind);

        assert_ne!(first[..NONCE_BYTES], second[..NONCE_BYTES]);
        assert_ne!(first[CIPHERTEXT_START..], second[CIPHERTEXT_START..]);
    }

    #[test]
    fn an_unavailable_nonce_source_fails_the_seal_closed() {
        let nonces = CountingNonces::new();
        nonces.available.set(false);
        let protector = record_protector(Zeroizing::new(KEY), nonces);
        let mut protected = [0; BODY_BYTES + PROTECTION_OVERHEAD_BYTES];

        assert_eq!(
            protector.seal(
                &context(0x9a),
                ReplayJournalRecordKind::CurrentStateV3,
                &PLAINTEXT,
                &mut protected,
            ),
            Err(ProtectionUnavailable)
        );
        assert_eq!(protected, [0; BODY_BYTES + PROTECTION_OVERHEAD_BYTES]);
    }

    #[test]
    fn mismatched_buffer_lengths_are_rejected_before_any_key_use() {
        let protector = protector();
        let context = context(0x9a);
        let kind = ReplayJournalRecordKind::CurrentStateV3;
        let mut short = [0; BODY_BYTES + PROTECTION_OVERHEAD_BYTES - 1];

        assert_eq!(
            protector.seal(&context, kind, &PLAINTEXT, &mut short),
            Err(ProtectionUnavailable)
        );

        let protected = seal(&protector, &context, kind);
        let mut wide = [0; BODY_BYTES + 1];

        assert_eq!(
            protector.open(&context, kind, &protected, &mut wide),
            Err(ProtectionUnavailable)
        );
    }

    #[test]
    fn the_operating_system_source_yields_distinct_nonces() {
        let first = OsJournalRecordNonces
            .next_nonce()
            .expect("operating system nonce is available");
        let second = OsJournalRecordNonces
            .next_nonce()
            .expect("operating system nonce is available");

        assert_ne!(first, second);
        assert_ne!(first, [0; NONCE_BYTES]);
    }

    #[test]
    fn the_record_domain_is_distinct_from_the_envelope_and_continuation_domains() {
        assert_ne!(
            REPLAY_JOURNAL_ASSOCIATED_DATA_DOMAIN,
            crate::xchacha20::ENVELOPE_ASSOCIATED_DATA_DOMAIN
        );
        assert_ne!(
            REPLAY_JOURNAL_ASSOCIATED_DATA_DOMAIN,
            crate::xchacha20::CONTINUATION_ASSOCIATED_DATA_DOMAIN
        );
    }
}

/// Property tests over the record protector's whole input space.
///
/// The hand-written tests above pin one body width and one corruption pattern.
/// These explore arbitrary widths, kinds, contexts, and nonce sequences,
/// because the journal's records are fixed-width but its bodies are not, and
/// the boundaries between them are where a length or offset error would hide.
#[cfg(test)]
mod properties {
    use proptest::prelude::*;

    use super::{tests::CountingNonces, *};

    /// Bodies from empty to wider than one ChaCha block, so the stream cipher's
    /// block boundary is inside the explored range rather than beside it.
    fn body() -> impl Strategy<Value = Vec<u8>> {
        proptest::collection::vec(any::<u8>(), 0..=200)
    }

    fn kind() -> impl Strategy<Value = ReplayJournalRecordKind> {
        prop_oneof![
            Just(ReplayJournalRecordKind::CurrentStateV3),
            Just(ReplayJournalRecordKind::ImmutableEntryV2),
        ]
    }

    proptest! {
        #[test]
        fn any_body_round_trips_under_its_own_context(
            body in body(),
            binding in any::<[u8; DIGEST_BYTES]>(),
            kind in kind(),
        ) {
            let protector = record_protector(Zeroizing::new([0x31; KEY_BYTES]), CountingNonces::new());
            let context = ReplayJournalProtectionContext::new(binding);
            let mut protected = vec![0; body.len() + PROTECTION_OVERHEAD_BYTES];

            protector.seal(&context, kind, &body, &mut protected)?;
            let mut recovered = vec![0; body.len()];

            prop_assert_eq!(
                protector.open(&context, kind, &protected, &mut recovered)?,
                AuthenticationDecision::Accepted
            );
            prop_assert_eq!(recovered, body);
        }

        #[test]
        fn any_single_byte_change_is_rejected_without_exposing_plaintext(
            body in proptest::collection::vec(any::<u8>(), 1..=120),
            binding in any::<[u8; DIGEST_BYTES]>(),
            kind in kind(),
            index in any::<prop::sample::Index>(),
            flip in 1_u8..=255,
        ) {
            let protector = record_protector(Zeroizing::new([0x31; KEY_BYTES]), CountingNonces::new());
            let context = ReplayJournalProtectionContext::new(binding);
            let mut protected = vec![0; body.len() + PROTECTION_OVERHEAD_BYTES];
            protector.seal(&context, kind, &body, &mut protected)?;

            let index = index.index(protected.len());
            protected[index] ^= flip;
            let mut recovered = vec![0xff; body.len()];

            prop_assert_eq!(
                protector.open(&context, kind, &protected, &mut recovered)?,
                AuthenticationDecision::Rejected
            );
            prop_assert!(recovered.iter().all(|byte| *byte == 0));
        }

        /// A record sealed under one context or kind must never open under a
        /// different one, whatever the body.
        #[test]
        fn no_body_opens_under_a_foreign_context_or_kind(
            body in body(),
            sealing in any::<[u8; DIGEST_BYTES]>(),
            opening in any::<[u8; DIGEST_BYTES]>(),
            kind in kind(),
        ) {
            prop_assume!(sealing != opening);
            let protector = record_protector(Zeroizing::new([0x31; KEY_BYTES]), CountingNonces::new());
            let mut protected = vec![0; body.len() + PROTECTION_OVERHEAD_BYTES];
            protector.seal(
                &ReplayJournalProtectionContext::new(sealing),
                kind,
                &body,
                &mut protected,
            )?;

            let other_kind = match kind {
                ReplayJournalRecordKind::CurrentStateV3 => {
                    ReplayJournalRecordKind::ImmutableEntryV2
                }
                ReplayJournalRecordKind::ImmutableEntryV2 => {
                    ReplayJournalRecordKind::CurrentStateV3
                }
            };
            let foreign = [
                (ReplayJournalProtectionContext::new(opening), kind),
                (ReplayJournalProtectionContext::new(sealing), other_kind),
            ];

            for (context, kind) in foreign {
                let mut recovered = vec![0xff; body.len()];
                prop_assert_eq!(
                    protector.open(&context, kind, &protected, &mut recovered)?,
                    AuthenticationDecision::Rejected
                );
                prop_assert!(recovered.iter().all(|byte| *byte == 0));
            }
        }

        /// Any buffer pair whose widths disagree with the fixed overhead must be
        /// refused before the key is used at all.
        #[test]
        fn mismatched_widths_are_always_refused(
            body in body(),
            skew in 1_usize..=8,
            binding in any::<[u8; DIGEST_BYTES]>(),
            kind in kind(),
        ) {
            let protector = record_protector(Zeroizing::new([0x31; KEY_BYTES]), CountingNonces::new());
            let context = ReplayJournalProtectionContext::new(binding);
            let mut wrong = vec![0; body.len() + PROTECTION_OVERHEAD_BYTES + skew];

            prop_assert_eq!(
                protector.seal(&context, kind, &body, &mut wrong),
                Err(ProtectionUnavailable)
            );
        }
    }
}
