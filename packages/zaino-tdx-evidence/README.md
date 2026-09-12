# Zaino TDX evidence

This unpublished crate contains the bounded Linux ConfigFS TSM QuoteV4
collector shared by the private-service adapter and the boot diagnostic agent.
It checks the `tdx_guest` provider, advances generation exactly once, writes
REPORT_DATA through the existing `inblob`, reads a bounded `outblob`, and
cleans its unique request directory. It performs collection only; quote,
collateral, policy, and CCEL verification belong to the client-side verifier.
