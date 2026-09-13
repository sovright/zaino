# TDX boot-spike evidence agent

This unpublished diagnostic agent serves one bounded evidence RPC over an
ephemeral TLS 1.3 identity. It derives REPORT_DATA from its own TLS SPKI, the
client's 64-byte challenge, and a boot-local lease identifier, then returns the
TDX ConfigFS QuoteV4 plus the fixed CCEL table and log paths.

The shipped binary has no injectable quote provider and accepts only loopback,
private, or link-local listeners. ConfigFS work is serialized; a timed-out
blocking worker retains the permit until it exits. TLS uses AWS-LC, TLS 1.3,
HTTP/2 ALPN, no resumption, bounded handshakes, headers, streams, messages, and
requests.

Startup refuses inherited descriptors outside stdio and verifies the
inheritable, permitted, effective, bounding, and ambient capability sets are
empty before binding. The synchronized filter traps `perf_event_open`; this is
a guest syscall boundary and does not establish host PMU isolation.

This is diagnostic plumbing. It does not establish an accepted guest image,
semantic measured-boot coverage, rollback protection, or Zaino query admission.
Access to ConfigFS and CCEL after the intended guest capability drop remains a
real C3 TDX boot-spike gate.
