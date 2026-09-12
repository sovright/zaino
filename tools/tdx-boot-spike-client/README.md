# TDX boot-spike diagnostic client

This unpublished client owns one non-resuming TLS 1.3 connection and performs
one fresh-challenge evidence transaction. It derives the actual peer SPKI from
the retained stream, validates the canonical wire response, constructs the
fixed boot-spike REPORT_DATA transcript, and invokes a locally pinned Go helper
in strict QuoteV4 plus CCEL digest-replay mode.

The verifier executable, reviewed policy template, and their SHA-256 digests
are independent client inputs. The client never derives trusted measurements
from received evidence. One absolute deadline covers connection, RPC, and the
helper subprocess budget; cancellation or any RPC error terminally closes the
owned socket. The client host and immutable helper installation are trusted.

Success emits `tdx_boot_spike_quote_ccel_diagnostic_v1`, correlated to the
challenge, actual peer SPKI, boot lease, and exact quote, policy, CCEL table,
and CCEL log bytes. This scope is deliberately rejected by the retained Zaino
client and grants no workload or private-query admission.
