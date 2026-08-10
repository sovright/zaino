//! Adaptation between the private wire contract and an ORAM handler.

use std::fmt;
use zaino_oram::FixedEnvelopeRuntime;
#[cfg(test)]
use zaino_oram::{PendingFixedEnvelope, PrivateQueryUnavailable};

use crate::private_proto;

mod listener;
mod tls;
mod tonic_body;

pub(crate) use listener::PrivateQueryListener;
pub(crate) use tls::{require_no_stranded_identity, PrivateTlsIdentity};

/// Exact application envelope after validation at the private wire boundary.
struct ValidatedFixedEnvelope<const N: usize> {
    bytes: [u8; N],
}

impl<const N: usize> ValidatedFixedEnvelope<N> {
    /// Validates a decoded protobuf message before it reaches the private engine.
    pub fn try_from_wire(wire: private_proto::FixedEnvelope) -> Result<Self, WireEnvelopeError> {
        if N == 0 {
            return Err(WireEnvelopeError::EmptyProfile);
        }
        let actual = wire.envelope.len();
        let bytes = wire
            .envelope
            .try_into()
            .map_err(|_| WireEnvelopeError::WrongLength {
                expected: N,
                actual,
            })?;
        Ok(Self { bytes })
    }

    /// Encodes one already exact business response as the private protobuf
    /// type, stamped with the epoch it was sealed under.
    pub fn to_wire(&self, key_epoch: u64) -> private_proto::FixedEnvelope {
        private_proto::FixedEnvelope {
            envelope: self.bytes.to_vec(),
            key_epoch,
        }
    }

    const fn from_array(bytes: [u8; N]) -> Self {
        Self { bytes }
    }
}

impl<const N: usize> fmt::Debug for ValidatedFixedEnvelope<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ValidatedFixedEnvelope")
            .field("len", &N)
            .finish_non_exhaustive()
    }
}

/// Typed rejection at the protobuf-to-business boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WireEnvelopeError {
    /// A private profile cannot select an empty application envelope.
    EmptyProfile,
    /// The decoded bytes field did not match the selected profile size.
    WrongLength {
        /// Required application-envelope length.
        expected: usize,
        /// Decoded application-envelope length.
        actual: usize,
    },
}

impl fmt::Display for WireEnvelopeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyProfile => f.write_str("private wire envelope profile cannot be empty"),
            Self::WrongLength { expected, actual } => {
                write!(
                    f,
                    "private wire envelope requires {expected} bytes; received {actual}"
                )
            }
        }
    }
}

impl std::error::Error for WireEnvelopeError {}

/// One protobuf response that still owns the runtime port's pending value.
///
/// This type deliberately offers no production extraction method. The lazy
/// Tonic encoder consumes the whole value at its first outbound body poll;
/// cancellation drops it without borrowing the response bytes.
struct PendingQueryPage<P, const N: usize> {
    pending_response: P,
}

impl<P, const N: usize> fmt::Debug for PendingQueryPage<P, N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PendingQueryPage { ..REDACTED.. }")
    }
}

/// Synchronous, listener-free private-query adapter.
struct PrivateServiceAdapter<H, const N: usize> {
    handler: H,
}

impl<H, const N: usize> PrivateServiceAdapter<H, N>
where
    H: FixedEnvelopeRuntime<N>,
{
    const fn new(handler: H) -> Self {
        Self { handler }
    }

    fn query_page(
        &mut self,
        request: private_proto::FixedEnvelope,
    ) -> Result<PendingQueryPage<H::PendingResponse, N>, PrivateServiceError> {
        let request = ValidatedFixedEnvelope::<N>::try_from_wire(request)
            .map_err(coarsen_private_service_error)?;
        let pending_response = self
            .handler
            .query_page(request.bytes)
            .map_err(coarsen_private_service_error)?;
        Ok(PendingQueryPage { pending_response })
    }
}

impl<H, const N: usize> fmt::Debug for PrivateServiceAdapter<H, N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PrivateServiceAdapter { ..REDACTED.. }")
    }
}

fn coarsen_private_service_error<T>(_: T) -> PrivateServiceError {
    PrivateServiceError
}

/// Uniform adapter failure without request, profile, or runtime details.
#[derive(Clone, Copy, PartialEq, Eq)]
struct PrivateServiceError;

impl fmt::Debug for PrivateServiceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PrivateServiceError { ..REDACTED.. }")
    }
}

impl fmt::Display for PrivateServiceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("private query unavailable")
    }
}

impl std::error::Error for PrivateServiceError {}

#[cfg(test)]
mod tests {
    use std::sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    };

    use prost::Message;

    use super::*;

    const ENVELOPE_BYTES: usize = 4;

    struct MockPendingResponse {
        response: [u8; ENVELOPE_BYTES],
        busy: Arc<AtomicBool>,
    }

    impl PendingFixedEnvelope<ENVELOPE_BYTES> for MockPendingResponse {
        fn try_release_bytes(&self) -> Result<&[u8; ENVELOPE_BYTES], PrivateQueryUnavailable> {
            Ok(&self.response)
        }
    }

    impl Drop for MockPendingResponse {
        fn drop(&mut self) {
            self.busy.store(false, Ordering::SeqCst);
        }
    }

    struct MockHandler {
        busy: Arc<AtomicBool>,
        calls: Arc<AtomicUsize>,
        response: [u8; ENVELOPE_BYTES],
    }

    impl FixedEnvelopeRuntime<ENVELOPE_BYTES> for MockHandler {
        type PendingResponse = MockPendingResponse;

        fn query_page(
            &mut self,
            _request: [u8; ENVELOPE_BYTES],
        ) -> Result<Self::PendingResponse, PrivateQueryUnavailable> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.busy.swap(true, Ordering::SeqCst) {
                return Err(PrivateQueryUnavailable);
            }
            Ok(MockPendingResponse {
                response: self.response,
                busy: Arc::clone(&self.busy),
            })
        }
    }

    fn mock_adapter(
        response: [u8; ENVELOPE_BYTES],
    ) -> (
        PrivateServiceAdapter<MockHandler, ENVELOPE_BYTES>,
        Arc<AtomicUsize>,
    ) {
        let calls = Arc::new(AtomicUsize::new(0));
        let handler = MockHandler {
            busy: Arc::new(AtomicBool::new(false)),
            calls: Arc::clone(&calls),
            response,
        };
        (PrivateServiceAdapter::new(handler), calls)
    }

    fn wire(bytes: &[u8]) -> private_proto::FixedEnvelope {
        private_proto::FixedEnvelope {
            envelope: bytes.to_vec(),
            key_epoch: 0,
        }
    }

    #[test]
    fn schema_and_generated_query_route_are_golden() {
        assert_eq!(
            include_str!("../proto/private.proto"),
            concat!(
                "syntax = \"proto3\";\n",
                "\n",
                "package zaino.private.v1;\n",
                "\n",
                "// One fixed-size protected application envelope.\n",
                "message FixedEnvelope {\n",
                "  bytes envelope = 1;\n",
                "  // The key epoch this envelope was sealed under. Cleartext on purpose: it is\n",
                "  // per-generation and identical for every client, so it reveals nothing, and\n",
                "  // sealing it inside would make a retired key indistinguishable from any\n",
                "  // other refusal — leaving a wallet no way to learn it must re-bootstrap.\n",
                "  uint64 key_epoch = 2;\n",
                "}\n",
                "\n",
                "// Empty: bootstrap takes no client input. A field here would be an input to\n",
                "// authenticate before the client holds any key material, which is exactly the\n",
                "// surface this design avoids.\n",
                "message BootstrapRequest {}\n",
                "\n",
                "// Everything a wallet needs to seal a query, and nothing else.\n",
                "message BootstrapResponse {\n",
                "  // Identifies the key generation these keys belong to. Sent back in cleartext\n",
                "  // on every QueryPage so a retired key is actionable rather than opaque.\n",
                "  uint64 key_epoch = 1;\n",
                "  // Seals request envelopes.\n",
                "  bytes request_key = 2;\n",
                "  // Opens response envelopes.\n",
                "  bytes response_key = 3;\n",
                "  // Human-readable name of the compiled privacy profile, for logs and support.\n",
                "  //\n",
                "  // Diagnostic, NOT authoritative: do not pin on it. The authoritative profile\n",
                "  // identifier is a digest over every logical budget dimension and is already\n",
                "  // bound into protected request state, so a query sealed against the wrong\n",
                "  // profile fails to open regardless of what this string says. It is named\n",
                "  // `profile_label` rather than `profile_id` precisely so it cannot be mistaken\n",
                "  // for that identifier.\n",
                "  string profile_label = 4;\n",
                "  // Exact envelope size class, so a wallet pads correctly without guessing.\n",
                "  uint32 envelope_bytes = 5;\n",
                "  // Reserved for a TDX quote binding the TLS identity to the measured binary.\n",
                "  // Present and empty in this release; ADR 0010 defers verification, and\n",
                "  // keeping the field means adding it later is not a breaking wire change.\n",
                "  bytes attestation = 6;\n",
                "}\n",
                "\n",
                "// Independent private-query surface. This is not the legacy lightwallet API.\n",
                "service PrivateCompactTxStreamer {\n",
                "  rpc QueryPage(FixedEnvelope) returns (FixedEnvelope);\n",
                "  rpc BootstrapSession(BootstrapRequest) returns (BootstrapResponse);\n",
                "}\n",
            )
        );
        assert!(include_str!("private_proto.rs")
            .contains("\"/zaino.private.v1.PrivateCompactTxStreamer/QueryPage\""));
        assert!(include_str!("private_proto.rs")
            .contains("\"/zaino.private.v1.PrivateCompactTxStreamer/BootstrapSession\""));
    }

    #[test]
    fn wire_conversion_is_exact_and_has_a_golden_encoding() -> Result<(), Box<dyn std::error::Error>>
    {
        let validated =
            ValidatedFixedEnvelope::<ENVELOPE_BYTES>::try_from_wire(wire(&[1, 2, 3, 4]))?;
        let encoded = validated.to_wire(0).encode_to_vec();
        assert_eq!(encoded, [0x0a, 0x04, 1, 2, 3, 4]);

        let decoded = private_proto::FixedEnvelope::decode(encoded.as_slice())?;
        assert_eq!(decoded.envelope, [1, 2, 3, 4]);
        assert_eq!(
            private_proto::private_compact_tx_streamer_server::SERVICE_NAME,
            "zaino.private.v1.PrivateCompactTxStreamer"
        );
        Ok(())
    }

    #[test]
    fn non_exact_wire_lengths_are_rejected_before_handler_invocation() {
        let (mut adapter, calls) = mock_adapter([9; ENVELOPE_BYTES]);

        for bytes in [&[][..], &[1, 2, 3][..], &[1, 2, 3, 4, 5][..]] {
            assert!(matches!(
                adapter.query_page(wire(bytes)),
                Err(PrivateServiceError)
            ));
        }
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn empty_profile_is_rejected_even_for_an_empty_wire_field() {
        assert!(matches!(
            ValidatedFixedEnvelope::<0>::try_from_wire(wire(&[])),
            Err(WireEnvelopeError::EmptyProfile)
        ));
    }

    #[test]
    fn pending_result_retains_exclusive_admission_until_drop(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (mut adapter, calls) = mock_adapter([9, 8, 7, 6]);
        let first = adapter.query_page(wire(&[1, 2, 3, 4]))?;

        assert!(matches!(
            adapter.query_page(wire(&[4, 3, 2, 1])),
            Err(PrivateServiceError)
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 2);

        drop(first);
        let _second = adapter.query_page(wire(&[4, 3, 2, 1]))?;
        assert_eq!(calls.load(Ordering::SeqCst), 3);
        Ok(())
    }

    #[test]
    fn wire_and_handler_failures_share_one_redacted_error() {
        let (mut adapter, _) = mock_adapter([9; ENVELOPE_BYTES]);
        let pending = adapter
            .query_page(wire(&[1, 2, 3, 4]))
            .expect("exact mock request produces one pending response");
        let handler_error = adapter
            .query_page(wire(&[1, 2, 3, 4]))
            .expect_err("pending mock response keeps admission closed");
        let wire_error = adapter
            .query_page(wire(&[1, 2, 3]))
            .expect_err("short request is rejected at the wire boundary");

        assert_eq!(handler_error, wire_error);
        assert_eq!(handler_error.to_string(), "private query unavailable");
        assert_eq!(
            format!("{handler_error:?}"),
            "PrivateServiceError { ..REDACTED.. }"
        );
        assert_eq!(format!("{pending:?}"), "PendingQueryPage { ..REDACTED.. }");
    }

    #[test]
    fn adapter_and_validated_envelope_debug_are_redacted() -> Result<(), Box<dyn std::error::Error>>
    {
        let (adapter, _) = mock_adapter([9; ENVELOPE_BYTES]);
        let envelope =
            ValidatedFixedEnvelope::<ENVELOPE_BYTES>::try_from_wire(wire(&[1, 2, 3, 4]))?;

        assert_eq!(
            format!("{adapter:?}"),
            "PrivateServiceAdapter { ..REDACTED.. }"
        );
        assert_eq!(
            format!("{envelope:?}"),
            "ValidatedFixedEnvelope { len: 4, .. }"
        );
        assert!(!format!("{envelope:?}").contains("1, 2, 3, 4"));
        Ok(())
    }
}
