# The minimal private API set is three operations, and balance is not one of them

## Status

proposed

First record in the fork-reserved range (see [README](README.md)). Extends
[0007](0007-private-query-service-and-leakage-model.md), which named the first
private operation but not the set a wallet actually needs. Scoped by
[0010](0010-interim-honest-but-curious-deployment-posture.md).

## Context and decision

ADR 0007 says "the first operation is transparent-address UTXO lookup" and that
additional methods get no privacy claim until their whole storage, source, wire
and continuation paths satisfy the same leakage model. It deliberately did not
say what the eventual set is. That has left the private surface sized, costed
and reasoned about as though one operation were the target, when a wallet
cannot function on one.

To ground this in behaviour rather than intuition, the calls the end-to-end
wallet flows in `live-tests/e2e` actually make, grouped by what the call
reveals:

| call | e2e call sites | keyed on |
| --- | --- | --- |
| `get_address_utxos` (+ stream) | 36 | address |
| `get_address_balance` / `get_taddress_balance` | 25 | address |
| `get_address_tx_ids` / `get_taddress_txids` | 26 | address |
| `get_raw_transaction` | 18 | txid |
| `get_treestate`, `get_subtrees_by_index` | 28 | height |
| `get_info`, `get_mempool_info`, mempool streams | 45 | nothing secret |

Call-site counts in a test suite are a proxy for what a wallet does, not a
measurement of it. They are used here only to establish *which* operations a
wallet reaches for, not how often.

We decide:

1. **The minimal private set is three operations**, not one:

   - **address → UTXOs.** Implemented as `QueryPage`.
   - **address → txids.** Not implemented. UTXOs are unspent-only, so history
     and spend detection cannot be derived from them.
   - **txid → transaction.** Not implemented. Without it, the previous
     operation returns identifiers a wallet cannot use without leaking which
     one it cared about.

2. **Balance is derived, never served.** It is the sum of the UTXO result and
   is computable by the client. Serving it privately would be a third
   address-keyed projection answering a question the wallet can already answer.
   This is a decision to design an operation *out*, and the 25 e2e call sites
   for balance should not be read as demand for a private balance method.

3. **Shielded sync stays on the ordinary surface and needs no ORAM.** The
   wallet fetches a block range and trial-decrypts locally, so the server
   learns the range and not which notes are the client's. That property is
   already provided by the existing lightwalletd design. Building shielded
   privacy on this machinery would spend the cost of ORAM to buy something the
   protocol already has.

4. **Height-keyed and public operations stay on the ordinary surface**:
   tree state, subtree roots, chain info, mempool. They are either identical
   across clients or reveal nothing about which client asked.

5. **Transaction submission is out of scope for this ADR** and is not solved by
   ORAM. Its exposure is linkability of a submitter to a broadcast
   transaction, not an access pattern over stored state. It needs its own
   treatment.

## Consequences

- **The privacy machinery covers one third of the minimal set.** Everything
  built so far — the fixed envelope, the data-independent engine, the release
  schedule, the replay journal, key establishment — serves one operation.
- **The remaining two are not free, and the second is keyed differently.**
  address → txids is another address-keyed projection with its own width and
  sizing problem. txid → transaction cannot use the current projection at all:
  it is address-keyed and cannot answer a txid-keyed question, so it needs a
  separate index with its own capacity, publication and qualification story.
- **Mainnet sizing was scoped to one projection.** The unservable-width finding
  in `docs/notes/recent-snapshot-scan-width.md` concerns the address→UTXO
  projection alone. A usable wallet needs at least two, so the cost question is
  larger than that note currently frames it.
- **The current surface cannot support a wallet even if the unpublished
  protocol values were published tomorrow.** A client with UTXOs but no
  transaction history and no way to fetch a transaction can display a balance
  and little else.
- Deciding balance is derived removes an operation that call-site counts would
  otherwise have justified building.

## Considered options

- **Keep the set implicit and add operations as they are asked for.**
  Rejected: it produced the current position, where cost and width were
  reasoned about as if one operation were the target. Naming the set is what
  makes the remaining cost visible.
- **Declare address → UTXOs sufficient and treat the rest as future work.**
  Rejected as misleading rather than wrong. It is a defensible engineering
  order, but stated as a target it implies a wallet could be built on it, and
  one cannot.
- **Include balance as a served private operation.** Rejected: derivable
  client-side from an operation already served, so it would add an
  address-keyed projection for no capability.
- **Extend the set to shielded operations.** Rejected: shielded sync is
  already private under the existing download-and-trial-decrypt design.
- **Include transaction submission.** Rejected here, not dismissed: its
  exposure is unlinkability rather than access pattern, so folding it into an
  ORAM-scoped decision would obscure that it needs a different mechanism.

## Revisiting

This set is minimal for a transparent-capable wallet under 0010's posture. It
does not attempt to be sufficient for every wallet feature, and it says nothing
about which operations become necessary if the deployment moves toward 0007's
adversary, where metadata this ADR treats as public may need reconsidering.
