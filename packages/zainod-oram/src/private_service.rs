//! Listener-free adaptation between the private wire contract and an ORAM handler.

#![cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the listener-free adapter lands before its guarded Tonic body consumer"
    )
)]

use std::fmt;

use crate::private_proto;

/// Crate-private port for one exact listener-free runtime round.
trait FixedEnvelopeRuntime<const N: usize> {
    /// Pending runtime response retained until the adapter result is dropped.
    type PendingResponse: PendingFixedEnvelope<N>;

    /// Handles one already validated request envelope.
    fn query_page(&mut self, request: [u8; N])
        -> Result<Self::PendingResponse, RuntimeUnavailable>;
}

/// Borrows response bytes while the crate-private pending value remains owned.
trait PendingFixedEnvelope<const N: usize> {
    /// Returns one exact response envelope without consuming the pending value.
    fn envelope_bytes(&self) -> &[u8; N];
}

/// Coarsened runtime-port rejection used only inside this adapter module.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RuntimeUnavailable;

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

    /// Encodes one already exact business response as the private protobuf type.
    pub fn to_wire(&self) -> private_proto::FixedEnvelope {
        private_proto::FixedEnvelope {
            envelope: self.bytes.to_vec(),
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
/// This type deliberately offers no production extraction method. The guarded
/// response-body slice must consume the whole value and retain it through body
/// completion or cancellation.
struct PendingQueryPage<P> {
    wire_response: private_proto::FixedEnvelope,
    _pending_response: P,
}

impl<P> fmt::Debug for PendingQueryPage<P> {
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
    ) -> Result<PendingQueryPage<H::PendingResponse>, PrivateServiceError> {
        let request = ValidatedFixedEnvelope::<N>::try_from_wire(request)
            .map_err(coarsen_private_service_error)?;
        let pending_response = self
            .handler
            .query_page(request.bytes)
            .map_err(coarsen_private_service_error)?;
        let response = ValidatedFixedEnvelope::from_array(*pending_response.envelope_bytes());
        Ok(PendingQueryPage {
            wire_response: response.to_wire(),
            _pending_response: pending_response,
        })
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
    use std::{cell::Cell, rc::Rc};

    use prost::Message;

    use super::*;

    const ENVELOPE_BYTES: usize = 4;

    struct MockPendingResponse {
        response: [u8; ENVELOPE_BYTES],
        busy: Rc<Cell<bool>>,
    }

    impl PendingFixedEnvelope<ENVELOPE_BYTES> for MockPendingResponse {
        fn envelope_bytes(&self) -> &[u8; ENVELOPE_BYTES] {
            &self.response
        }
    }

    impl Drop for MockPendingResponse {
        fn drop(&mut self) {
            self.busy.set(false);
        }
    }

    struct MockHandler {
        busy: Rc<Cell<bool>>,
        calls: Rc<Cell<usize>>,
        response: [u8; ENVELOPE_BYTES],
    }

    impl FixedEnvelopeRuntime<ENVELOPE_BYTES> for MockHandler {
        type PendingResponse = MockPendingResponse;

        fn query_page(
            &mut self,
            _request: [u8; ENVELOPE_BYTES],
        ) -> Result<Self::PendingResponse, RuntimeUnavailable> {
            self.calls.set(self.calls.get() + 1);
            if self.busy.replace(true) {
                return Err(RuntimeUnavailable);
            }
            Ok(MockPendingResponse {
                response: self.response,
                busy: Rc::clone(&self.busy),
            })
        }
    }

    fn mock_adapter(
        response: [u8; ENVELOPE_BYTES],
    ) -> (
        PrivateServiceAdapter<MockHandler, ENVELOPE_BYTES>,
        Rc<Cell<usize>>,
    ) {
        let calls = Rc::new(Cell::new(0));
        let handler = MockHandler {
            busy: Rc::new(Cell::new(false)),
            calls: Rc::clone(&calls),
            response,
        };
        (PrivateServiceAdapter::new(handler), calls)
    }

    fn wire(bytes: &[u8]) -> private_proto::FixedEnvelope {
        private_proto::FixedEnvelope {
            envelope: bytes.to_vec(),
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
                "}\n",
                "\n",
                "// Independent private-query surface. This is not the legacy lightwallet API.\n",
                "service PrivateCompactTxStreamer {\n",
                "  rpc QueryPage(FixedEnvelope) returns (FixedEnvelope);\n",
                "}\n",
            )
        );
        assert!(include_str!("private_proto.rs")
            .contains("\"/zaino.private.v1.PrivateCompactTxStreamer/QueryPage\""));
    }

    #[test]
    fn wire_conversion_is_exact_and_has_a_golden_encoding() -> Result<(), Box<dyn std::error::Error>>
    {
        let validated =
            ValidatedFixedEnvelope::<ENVELOPE_BYTES>::try_from_wire(wire(&[1, 2, 3, 4]))?;
        let encoded = validated.to_wire().encode_to_vec();
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
        assert_eq!(calls.get(), 0);
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
        assert_eq!(first.wire_response.envelope, [9, 8, 7, 6]);

        assert!(matches!(
            adapter.query_page(wire(&[4, 3, 2, 1])),
            Err(PrivateServiceError)
        ));
        assert_eq!(calls.get(), 2);

        drop(first);
        let second = adapter.query_page(wire(&[4, 3, 2, 1]))?;
        assert_eq!(second.wire_response.envelope, [9, 8, 7, 6]);
        assert_eq!(calls.get(), 3);
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
