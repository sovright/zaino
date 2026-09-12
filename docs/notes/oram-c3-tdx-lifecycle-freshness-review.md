# C3 TDX lifecycle, cloning, entropy, and time review

Date: 2026-09-12. This is a design review for the selected Google Compute
Engine `c3-standard-*` Intel TDX target. It does not approve a guest image,
derive a measurement policy from the diagnostic quote, or authorize cloud
changes.

## Findings

The selected C3 TDX platform has no supported full-memory suspend/resume path.
Google's suspend documentation explicitly excludes Confidential VMs, while
ordinary suspend would otherwise copy guest memory and device/application
state to persistent storage. Therefore `instances.suspend` cannot be the
operator's mechanism for cloning or resuming this C3 TD.
[Suspend/resume limitations](https://docs.cloud.google.com/compute/docs/instances/suspend-resume-instance)

C3 Intel TDX also has no supported live migration. Google's current support
table lists `c3-standard-*` with Intel TDX and live migration “Not supported.”
The maintenance documentation says this target instead receives a seven-day
notice, terminates for host maintenance, and can restart afterward depending
on `automaticRestart`. The production manifest should retain
`onHostMaintenance=TERMINATE` and `automaticRestart=false`; a maintenance event
then ends the security lease.
[Confidential VM supported configurations](https://docs.cloud.google.com/confidential-computing/confidential-vm/docs/supported-configurations),
[Confidential VM maintenance behavior](https://docs.cloud.google.com/confidential-computing/confidential-vm/docs/troubleshoot-live-migration)

The QuoteV4 `TD_ATTRIBUTES` field is the cryptographic control for Intel's TD
migration mechanism. Intel defines bit 0 as DEBUG, which gives the host VMM
access to VCPU state and private memory, and bit 29 as MIGRATABLE. Intel's
migration design requires MIGRATABLE at TD initialization and a bound Migration
TD before private state can be exported and imported. The existing closed Go
policy correctly enables both debug and migratable rejection and checks the
exact verifier-owned `td_attributes`; those checks must remain mandatory.
[Intel TDX ABI, ATTRIBUTES table](https://cdrdv2-public.intel.com/839195/intel-tdx-module-1.5-abi-spec-348551002.pdf),
[Intel TDX migration architecture](https://cdrdv2-public.intel.com/733578/intel-tdx-module-1.5-td-migration-spec-348550002.pdf)

Those quote bits do not constrain Compute Engine disk operations or instance
configuration. An operator can stop a VM, snapshot or image a persistent disk,
create another VM from disk-derived bytes, change metadata/network/scheduling,
or restore older public-chain/ORAM state. A machine image stores VM
configuration, metadata, permissions, and disk data; it is a clone/backup
format, not a protected memory-resume format. Standard disk snapshots and
custom images likewise copy disk state. A clone boots as a new TD with a new
memory-encryption context, but can present rolled-back durable bytes unless the
workload detects them.
[Machine images](https://docs.cloud.google.com/compute/docs/machine-images),
[Custom image creation](https://docs.cloud.google.com/compute/docs/images/create-custom)

Consequently, debug-free plus non-migratable attestation proves that the
attested TD is not using Intel off-TD debug or the Intel migration protocol. It
does not prove unique instantiation, first boot, absence of disk cloning,
current cloud policy, current time, current chain state, or non-rollback. Image
ID, boot-disk ID/provenance, service account, metadata, firewall, NIC,
scheduling, restart policy, and snapshot provenance remain mutable Google API
assertions. They are useful fail-closed preflight facts but are not QuoteV4
measurements or client cryptographic evidence.

## Entropy and key lifetime

Every boot must create a new security lease. The guest must generate its TLS
private key, session binding, token/replay keys, and nonce state only after the
Linux CSPRNG is initialized, using blocking `getrandom(2)`/the Rust OS RNG and
checking the exact returned width. Linux documents that default `getrandom`
blocks until the urandom pool is initialized and recommends requests of at most
256 bytes; the required 32- and 64-byte values fit that contract.
[getrandom(2)](https://man7.org/linux/man-pages/man2/getrandom.2.html)

The accepted image must have no persisted application RNG seed, TLS key,
session key, replay key, or continuation authority and no swap/hibernation
image. Kernel entropy initialization and successful key generation are startup
gates before the listener opens. A duplicate boot from identical disk bytes
must produce different TLS public keys and lease identifiers. Statistical
health tests can detect obvious integration breakage but cannot prove entropy;
the release must also document the enabled kernel entropy inputs on the exact
C3 guest. Linux warns that raw hardware-RNG output is not itself fitness-tested,
so `/dev/hwrng` alone is not an adequate application key source.
[Linux hardware RNG documentation](https://docs.kernel.org/6.11/admin-guide/hw_random.html)

Because C3 Confidential VMs cannot suspend, no supported Google operation
should resume an in-memory CSPRNG or guest key. Stop/start, reset, maintenance
termination, process crash, and clean reboot must all destroy the lease and
require a fresh key, challenge, quote, bootstrap, and client connection. Disk
state may survive these operations and must never be allowed to resurrect
lease secrets.

## Time and freshness

Guest wall clock and monotonic progress are not established by the quote. The
host supplies virtual devices and controls scheduling; neither DEBUG=0 nor
MIGRATABLE=0 turns guest time into a trusted external clock. The verifier's
existing local `time.Now()` and current Intel collateral/revocation checks are
therefore the authority for quote-collateral freshness and must keep their
no-override production path.

A fresh client-generated 64-byte challenge bound into REPORT_DATA proves that
the accepted TD produced this evidence for this attempt. It does not prove
first boot, unique instance, current durable state, or a recent finalized
checkpoint. The client must independently enforce a verifier-owned minimum
checkpoint/network policy and compare it with the owner-derived bootstrap on
the same retained TLS stream. Query admission must expire with that one stream;
no reconnect or retry may reuse the challenge or receipt.

Any server-side continuation expiry, replay reclamation, or long-lived key
epoch that depends on elapsed real time still needs an external freshness
authority. A signed expiry checked only by the guest does not solve host pause
or clock rollback. The trusted client/verifier must enforce expiry before each
authorization, or the guest must obtain a fresh online witness bound to the
retained session/TLS SPKI and accepted policy. A bounded next design is a
client/verifier-signed lease containing a fresh random lease ID,
issuance/expiry under the verifier clock, accepted
binary/config/profile/schema/key epoch, and minimum finalized checkpoint. The
guest accepts it only after attestation on the retained stream and keeps it in
memory, while the external authority remains responsible for its freshness.
This does not solve persistent rollback by itself; durable
security-relevant state needs a monotonic witness or an authenticated external
state owner. Until then, rebuild ORAM from public canonical chain data on every
boot and make all replay/token authority lease-local.

## Required changes and gates

1. Keep the Go verifier's exact `TD_ATTRIBUTES`, DEBUG rejection,
   MIGRATABLE rejection, QuoteV4, Intel root, revocation, and both-UpToDate TCB
   checks. Add explicit unit coverage that setting bit 29 is refused before a
   receipt is emitted if that exact mutation is not already covered.
2. Extend the deployment preflight policy to require
   `onHostMaintenance=TERMINATE`, `automaticRestart=false`, no spot/preemption
   restart semantics, no instance suspend state, and a boot disk created only
   from the reviewed numeric image ID. Reject `sourceSnapshot`,
   `sourceInstantSnapshot`, machine-image provenance, extra disks, and changed
   resource policies. Record these as cloud assertions, never inside the quote
   receipt.
3. Use IAM and organization policy to deny operators the suspend/resume,
   snapshot, image-from-running-disk, machine-image, clone, and automatic
   restart paths where Google exposes such controls. This reduces accidental
   rollback surface but does not replace client verification against a
   malicious project administrator.
4. At guest startup, reject any hibernation/resume image or swap, wait for the
   kernel CSPRNG, generate all lease keys in memory, rebuild the serving state,
   and open the listener only after integrity, entropy, quote-provider, and
   checkpoint gates pass. Zeroize/drop lease keys on orderly shutdown; treat
   crash/termination as destruction rather than recovery.
5. Add negative lifecycle experiments on a no-secrets accepted-image candidate:
   `instances.suspend` must be unsupported; stop/start and reset must yield a
   new TLS SPKI; a fresh client must reject old evidence/receipts, sessions, and
   tokens. The evidence RPC may quote any correctly sized public challenge and
   is not responsible for retaining every prior client nonce. Disk snapshot/custom
   image/machine-image clones must not reuse keys and must fail external
   checkpoint/lease freshness when rolled back; a simulated host-maintenance
   event must terminate without automatic restart.
6. Run repeated clean boots from the same immutable image and require unique
   lease keys while the verifier-owned MRTD/RTMR policy remains stable. Test
   early-boot entropy failure by keeping the query listener closed. For time
   rollback, an expired or missing external witness must make the trusted
   client refuse admission or new authorization; the guest closes only when
   its implemented external-freshness gate fails. An external lease cannot
   force a host-paused TD to erase already issued keys or stop local
   computation. Test stale collateral only through the existing fixed-time
   test seam; production continues to use the trusted client clock.

There is no supported full-memory resume or live-migration feature to qualify
for this selected C3 TDX configuration today. Disk cloning and rollback remain
available control-plane threats, so external freshness and boot-local key
lifetimes are still required before encrypted research queries carry a private
Zaino claim.
