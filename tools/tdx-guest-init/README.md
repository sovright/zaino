# TDX guest init

This unpublished Linux-only binary is the compiled ELF `rdinit` for the
no-secrets C3 boot spike. The release build must use the pinned static
`x86_64-unknown-linux-musl` target. Shell scripts and a general-purpose init
system are absent from the guest.

The release builder supplies three mandatory compile-time values:

- `ZAINO_EXPECTED_CMDLINE_SHA256`: SHA-256 of the exact bytes Linux exposes at
  `/proc/cmdline` for the signed UKI command line, including its exposed
  trailing newline, complete `dm-mod.create` verity table, and IPv4 DHCP;
- `ZAINO_EXPECTED_DM_UUID`: the exact resulting dm-verity UUID;
- `ZAINO_EXPECTED_ROOT_BYTES`: the exact logical size of the verified mapping.

PID 1 mounts devtmpfs, proc, sysfs, and ConfigFS, establishes `/dev/null` as
file descriptors 0/1/2, checks those release values, mounts `/dev/dm-0`
read-only, and reads every logical byte through the verified mapping. Any
geometry, identity, or read error stops boot. It waits for blocking OS
randomness, mounts bounded noexec tmpfs at `/run` and `/tmp`, removes the old
initramfs contents, performs the kernel-documented switch-root sequence, and
executes only `/usr/lib/zaino/tdx-evidence-agent` on the discovered private
IPv4 address.

The evidence agent becomes PID 1 and permits no process creation after its
seccomp policy is installed. `SIGCHLD` is ignored to reap any unexpected
inherited child; the agent explicitly handles `SIGTERM` and `SIGINT` with a
bounded graceful listener shutdown. Real boot must still prove C3 networking,
mount behavior, and post-capability-drop ConfigFS plus CCEL access; local parser
and sweep tests do not establish those properties.
