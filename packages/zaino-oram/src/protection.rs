//! Shared failure vocabulary for crate-internal protection providers.

use std::fmt;

/// The result of authenticating one protected body.
///
/// Rejection represents attacker-controlled invalid input. Provider outages
/// use [`ProtectionUnavailable`] so the runtime can latch unhealthy without
/// treating an operational failure as an authentication result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AuthenticationDecision {
    /// Authentication succeeded and the provider may expose plaintext.
    Accepted,
    /// Authentication failed and the provider did not expose plaintext.
    Rejected,
}

/// A protection provider could not complete an operation.
///
/// The unit shape deliberately discards backend details at the codec boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ProtectionUnavailable;

impl fmt::Display for ProtectionUnavailable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("private protection is unavailable")
    }
}

impl std::error::Error for ProtectionUnavailable {}
