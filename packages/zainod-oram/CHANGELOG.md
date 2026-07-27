# Changelog

## Unreleased

- Add an explicit, bounded `corpus capture --fetch-concurrency` option that
  keeps indexed-block reads in flight while reducing them strictly in height
  order; the conservative default remains sequential.
- Add a crate-private, mock-backed custom Tonic codec and body adapter that
  retains a non-`Clone` pending response without an eager byte copy, performs
  its fallible currentness check at the first outbound body poll, emits the
  exact fixed-envelope DATA frame on success, and suppresses stale responses as
  one uniform `Unavailable` trailer shape with no DATA. Dropping an unpolled
  body releases the pending response without checking or borrowing its bytes.
  This does not integrate the real process owner or prove socket-write,
  transport-completion, peer-delivery, listener, or production privacy
  properties.
- Add a default-off `private-service` feature with an independent
  `zaino.private.v1.PrivateCompactTxStreamer/QueryPage` schema, committed
  generated Rust source, exact outer-envelope length validation through named
  wire methods, and a crate-private listener-free adapter tested against a mock
  runtime port. Its non-`Clone` result retains the port's pending response. The
  generated Tonic trait is not implemented; no concrete owner routing,
  currentness at socket write, listener, attestation, or production privacy
  claim is added.
- Add listener-free `corpus capture` over one indexed non-finalized mainnet
  snapshot, with optional explicit height/hash selection and atomic,
  read-back-verified measurement artifacts.
- Separate observed corpus measurements from growth, capacity, backend, memory,
  and TDX sizing assumptions so one capture can be qualified offline under
  multiple models.
- Add fully offline `corpus size` with eleven required model inputs, validated
  capture consumption, deterministic typed qualification/provenance digests,
  source-bound qualification recomputation, bounded no-follow artifact reads,
  and dirfd-relative crash-durable no-clobber three-file publication.
- Add a read-only `corpus validate-sizing` command that reopens an existing
  sizing directory alongside its separately validated source capture, repeats
  bounded no-follow validation, and requires the recomputed qualification to
  remain bound to that capture. It creates no artifact, accepts no runtime or
  workload tuning, and makes no backend, worker, load, performance, hardware,
  or mainnet claim.
- Add a default-off `typed-qualification` feature with a listener-free
  `qualification run` command for the fixed typed-worker correctness scenario.
  Successful runs atomically publish a read-back-verified three-file JSON,
  text, and digest-bound provenance artifact; the command exposes no listener,
  runtime-service hook, latency/RSS measurement, or physical-trace claim. The
  unsigned self-reported bundle explicitly carries no source, lockfile,
  toolchain, binary, CI-run, or execution-attestation binding.
- Add `qualification stress --profile smoke-v1 --output-dir <NEW_DIR>` under
  the same default-off feature. The command offers no numeric workload or
  backend tuning knobs and publishes a distinct, aggregate-only,
  read-back-verified stress report, text rendering, and unsigned self-reported
  provenance bundle. `SmokeV1` is a deterministic CI correctness/fail-closed
  exercise, not a benchmark, target-load run, billion-operation soak,
  latency/RSS/stash/queue-load or physical-trace measurement,
  persistence/recovery or hardware qualification, node-year failure bound, or
  mainnet gate.
- Add `qualification stress --profile full-map-saturation-v1 --output-dir
  <NEW_DIR>` as a separate deterministic admitted-map boundary qualification.
  It publishes its own schema and three-file artifact after independent
  directory-boundary and event-boundary workers reach their exact logical
  admission limits and fail closed on the next append. It is not physical
  capacity, random target-load, performance, persistence/recovery, target
  CPU/TDX, or mainnet-gate evidence.
- Add `qualification target-load --profile builder-foundation-v1
  --capture-dir <CAPTURE_DIR> --sizing-dir <SIZING_DIR> --output-dir <NEW_DIR>`
  as a listener-free source-bound builder experiment. The command accepts no
  capacity, operation-count, concurrency, seed, backend, queue, or service
  configuration knobs. It revalidates the complete capture/sizing pair, runs
  the fixed 256-command `BuilderFoundationV1` workload inside its bounded table
  envelope, and publishes exactly `target-load.json`, `target-load.txt`, and a
  digest-bound `provenance.json` after staged read-back verification on Linux
  x86_64. The publisher rejects output nested under either validated source and
  rebinds staged JSON to both inputs. The unsigned artifact records typed-worker
  call latency, mixed-phase wall-clock completion rates, process-wide RSS plus
  process-lifetime HWM, lifecycle queue
  counters, logical probe collisions, and explicit `backend-unobservable`
  stash/physical-access markers. It is generic-builder research evidence only,
  not target hardware/TDX, persistence/recovery, a `10^9`-operation soak,
  full-mainnet capacity, attestation, physical-obliviousness, or mainnet
  readiness.
