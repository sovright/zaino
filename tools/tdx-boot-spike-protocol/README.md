# TDX boot-spike protocol

This unpublished schema crate is the single wire and transcript authority for
the no-secrets boot diagnostic. It validates fixed field widths and bounded
quote, CCEL table, CCEL log, and aggregate response sizes. Its validated value
has private fields and conveys parsed bytes only; it is not a verification
receipt or admission capability.
