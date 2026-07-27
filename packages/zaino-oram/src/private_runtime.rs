//! Minimal fixed-envelope boundary shared by a private runtime and its server.

use std::fmt;

/// Executes one fixed-envelope private-query round.
///
/// Implementations retain any round-scoped release authority in
/// [`PendingResponse`](Self::PendingResponse). Returning a pending response
/// does not itself authorize its bytes for transport.
pub trait FixedEnvelopeRuntime<const N: usize> {
    /// Pending response that owns the round until it is released or dropped.
    type PendingResponse: PendingFixedEnvelope<N>;

    /// Handles one exact fixed-length request envelope.
    fn query_page(
        &mut self,
        request: [u8; N],
    ) -> Result<Self::PendingResponse, PrivateQueryUnavailable>;
}

/// A fixed-envelope response whose bytes remain guarded until release time.
pub trait PendingFixedEnvelope<const N: usize> {
    /// Rechecks release authority and borrows the exact response envelope.
    ///
    /// Callers must keep the pending response alive for the returned borrow.
    fn try_release_bytes(&self) -> Result<&[u8; N], PrivateQueryUnavailable>;
}

/// Uniform rejection at the private runtime boundary.
///
/// The zero-sized value deliberately carries no request, profile, or runtime
/// details across the shared facade.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PrivateQueryUnavailable;

impl fmt::Debug for PrivateQueryUnavailable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PrivateQueryUnavailable { ..REDACTED.. }")
    }
}

impl fmt::Display for PrivateQueryUnavailable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("private query unavailable")
    }
}

impl std::error::Error for PrivateQueryUnavailable {}

#[cfg(test)]
mod tests {
    use super::PrivateQueryUnavailable;

    #[test]
    fn unavailable_error_is_zero_sized_and_redacted() {
        let error = PrivateQueryUnavailable;

        assert_eq!(std::mem::size_of::<PrivateQueryUnavailable>(), 0);
        assert_eq!(error.to_string(), "private query unavailable");
        assert_eq!(
            format!("{error:?}"),
            "PrivateQueryUnavailable { ..REDACTED.. }"
        );
    }
}
