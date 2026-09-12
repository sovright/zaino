//! State-independent constants shared by the private runtime and client codec.

/// Exact application-envelope width every mainnet-shaped request and response carries.
pub const PRIVATE_MAINNET_ENVELOPE_BYTES: usize = crate::profile::MAINNET_ENVELOPE_BYTES;

/// Version of the complete client codec context published after refresh.
pub const PRIVATE_CLIENT_CONTEXT_VERSION: u32 = 1;
