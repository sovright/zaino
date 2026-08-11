# Private query release schedule: measurement and policy

Records the measurement behind the fixed release schedule on the private
query surface, and the overrun policy chosen from it. Companion to ADR 0007
(which names the `timeout_bucket` as the mechanism) and ADR 0010 (which keeps
network observers in scope even though the operator is not).

## The gap this closes

Before this change the private surface was uniform in every dimension except
one. A fixed-width envelope, one request per connection, per-route decode
caps, a single uniform refusal for every protected outcome but a deliberate
`StaleKeyEpoch`, and a data-independent engine — and then the response went
out the moment computation and queueing happened to finish. A wallet's query
was still separable by how long the answer took.

## What was measured

Two halves, because no single harness can drive both. The engine half needs
`zaino-oram`'s in-crate test seams; the transport half needs a real TLS
listener.

### Engine and runtime half

`zaino-oram`, `inner_codec::runtime::tests::measure_per_outcome_round_latency`
(`#[ignore]`; run with `--ignored --nocapture`). Times one complete protected
round — envelope open, continuation open, replay claim, masked store sweep,
recent-snapshot scan, response seal — on a fresh runtime per sample, 128
samples per outcome after 16 warm-up rounds, at a 512-slot per-address store
width.

| outcome | min µs | median µs | p95 µs | max µs |
| --- | --- | --- | --- | --- |
| hit | 22 | 22 | 22 | 57 |
| miss | 24 | 24 | 40 | 71 |
| empty | 24 | 24 | 24 | 100 |
| cap-hit (pagination continuing) | 23 | 25 | 46 | 128 |
| pagination terminal | 23 | 25 | 27 | 105 |
| invalid domain | 21 | 24 | 39 | 120 |
| protection failure | 21 | 21 | 21 | 23 |

Read honestly, this says three things.

1. The **spread across outcomes is small but not zero**. Medians run 21–25 µs.
   `hit` sits ~2 µs (about 9%) below `miss`, and `protection failure` sits
   consistently lowest because the withheld response seal is one operation the
   other outcomes perform. The engine's sweep is data-independent by
   construction; these numbers do not contradict that, but they also do not
   demonstrate it. A stopwatch at this resolution cannot separate a real
   data-dependence from allocator and cache effects.
2. The **tails dwarf the medians**. Maxima reach 128 µs against a 22 µs median
   — a five-fold excursion that no outcome is exempt from, and that this layer
   does not control. It is allocator, scheduler, and cache behaviour.
3. Both numbers are **three orders of magnitude below the compiled bucket**
   (250 ms for the mainnet profile). The schedule swallows the whole
   distribution with enormous margin.

Scope limit, stated plainly: this is the mock-store test profile, not mainnet
dimensions. The compiled mainnet profile's recent-snapshot scan is already
documented as `Unserviceable` (see `recent-snapshot-scan-width.md`), so a
mainnet-shaped round cannot be timed today by anyone. These numbers size the
schedule against the engine shape that exists; they are not a mainnet
latency claim.

### Transport half

`zainod-oram`,
`private_service::listener::tests::measure_per_outcome_wire_latency`
(`#[ignore]`). One real TLS connection per outcome, 32 sequential unary calls
on it, timed client-side around the call alone — decode, cap, routing,
adapter, encoding, framing and the TLS write, with a constant-work handler
double so the transport is the only variable.

**Before the schedule** (measured by driving the same harness with a
zero-width bucket, which is exactly the un-gated behaviour):

| outcome | min µs | median µs | p95 µs | max µs |
| --- | --- | --- | --- | --- |
| answered | 180 | 1448 | 1503 | 1962 |
| wrong length | 1388 | 1423 | 1478 | 1527 |
| over decode cap | 178 | 1452 | 1518 | 1551 |
| stale key epoch | 206 | 1458 | 1591 | 1598 |
| unknown route | 1427 | 1455 | 1624 | 1686 |

**After the schedule**, at a 50 ms test bucket:

| outcome | min µs | median µs | p95 µs | max µs |
| --- | --- | --- | --- | --- |
| answered | 51291 | 52554 | 53331 | 53425 |
| wrong length | 51480 | 52473 | 53251 | 53391 |
| over decode cap | 51188 | 53598 | 54254 | 56054 |
| stale key epoch | 51593 | 53455 | 54089 | 54123 |
| unknown route | 51415 | 53442 | 54001 | 54053 |

Every outcome now completes at the bucket plus a transport constant of
1.2–6.0 ms. The residual 1.1 ms spread between outcome medians is the same
transport noise present in the before table (medians 1423–1458 µs there), not
a signal the schedule failed to cover: it is the cost of the write itself,
which happens after the release gate by necessity — the gate cannot be placed
after a write it is meant to schedule.

## The schedule

- **Reference point.** The instant the round is admitted to the
  single-admission handler, i.e. entry to
  `PrivateTonicBodyAdapter::query_page`, reached identically by every
  protected outcome on that route. Queue time ahead of admission is
  deliberately outside the window: it is a function of concurrent load, which
  ADR 0007's profile already permits observing, and folding it in would make
  one client's deadline depend on another client's query.
- **Width.** The compiled profile's existing `timeout_bucket_millis`, read
  through `private_mainnet_timeout_bucket_millis()`. Not a new constant: the
  authoritative width is bound into the profile identifier a wallet pins, and
  a second copy could disagree with it.
- **Coverage.** The query route and the unroutable-request arm. `BootstrapSession`
  stays exempt, as it is exempt from the rest of the shape discipline: its
  answer is identical for every caller, takes no client input, and is served
  without the admission lock.

## Overrun policy: fail closed

**Chosen: fail closed.** A round that exceeds the bucket is cancelled and
answered with the uniform refusal, written *at* the deadline rather than
after it.

The alternative — release late — leaks precisely the queries that were
expensive, which is the leak the schedule exists to close. Adopting it would
mean building the whole mechanism and then leaving open the one channel it
was built to shut. It is not offered.

Failing closed costs an answer, and that is the honest price. Two things make
it acceptable here. First, the refusal is the *same* refusal every other
protected failure produces, so an overrun collapses into an observable class
that already exists rather than creating a new one. Second, the compiled
bucket is set above worst-case modelled work (250 ms against roughly 110 ms of
scan), so an overrun means the deployment is provisioned below its own
compiled budget — an operator's condition, not a property of the query. ADR
0007 already states that denial of service is not prevented.

Cancellation is safe by construction: a pending response that never reaches an
outbound body poll releases its admission and never borrows its bytes, the
same property that makes an abandoned connection safe.

**Operator visibility.** `ReleaseSchedule::overruns()` is a running count, and
each overrun prints
`private_query_release_overrun=<count>,bucket_millis:<width>` to stderr. Both
values are public and deployment-wide; neither is derived from a query.

## Equalising work, not only time

The schedule equalises *when* a response is written. It does not by itself
equalise the work behind it, and a request refused at the wire boundary would
otherwise reach its deadline having asked the runtime for nothing while an
answered one paid a full round. So every uniform refusal now buys a cover
round (`PrivateServiceAdapter::cover_round`) on an all-zero envelope, which
the runtime cannot open and therefore answers with its complete fixed round.
The `StaleKeyEpoch` arm is the exception and stays one: it is refused ahead of
the handler on purpose, it is already distinguishable by status, and spending
a round on a request under a retired key would neither hide anything nor be
owed to anyone.

## What the tests establish, and what they cannot

Establish:

- On a paused clock, the schedule's arithmetic is exact: an answered query, a
  wrong-length envelope and an over-cap body are released at the same instant,
  to the tick (`every_protected_outcome_is_released_on_the_same_deadline`).
- Overrunning work is cancelled at the deadline, answered with the uniform
  refusal, counted, and never borrows its response bytes
  (`an_overrunning_round_fails_closed_at_the_deadline`).
- The three ways a protected request can be refused — wrong length, over the
  decode cap, overrun — are identical header for header and frame for frame,
  not merely identical in status
  (`every_uniform_refusal_is_header_and_frame_identical`). The same test shows
  an answered query and a stale-epoch refusal *are* distinguishable from them,
  so the equality is not vacuous.
- `StaleKeyEpoch` keeps its own status and everyone else's release instant, and
  is still refused ahead of the handler.
- Over real TLS and real routing, both an answered query and a probe of an
  unknown route wait out the bucket
  (`a_served_query_and_a_probed_route_both_wait_out_the_bucket`).

Cannot:

- **A timing test cannot prove the absence of a timing leak.** These tests show
  that the paths under test release on schedule. They say nothing about
  channels below this layer.
- The exact-deadline claims hold on a *mocked* clock. The wire test asserts
  only a lower bound, deliberately: an upper bound would be an assertion that
  the machine is not busy, which is not a property of this code.
- The engine measurement is on the mock-store test profile at a 512-slot
  width. It does not speak for mainnet dimensions, which cannot be measured
  today.
- The measured per-outcome medians are not identical (21–25 µs). That is
  consistent with data-independence plus noise, and it is not evidence *of*
  data-independence. The engine's structural argument — masked full sweeps,
  non-short-circuiting predicates, byte-scanning comparisons — remains the
  claim; this measurement neither strengthens nor weakens it.

## Variance this layer does not control

- **Allocator and cache.** The engine tails (128 µs against a 22 µs median) are
  five-fold excursions that no outcome is exempt from and that no schedule at
  this layer can attribute to a query.
- **The TLS write path.** The gate releases the response; hyper writes it. The
  1.2–6.0 ms transport constant, and its ~1 ms spread, sit after the gate by
  necessity.
- **Response encoding.** The lazy encoder deliberately releases the pending
  value at the first outbound body poll, which is after the gate. That work is
  a fixed-width copy and is data-independent by shape, but it is outside the
  scheduled window and this note does not claim otherwise.
- **The ORAM backend.** Nothing here constrains what a real engine does
  underneath the current mock store.

None of these is papered over by the schedule. The schedule's claim is
bounded and specific: the *release instant* of a protected response no longer
depends on the outcome that produced it.
