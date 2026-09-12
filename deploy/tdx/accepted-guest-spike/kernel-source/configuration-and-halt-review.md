# Requested configuration and TDX halt source review

This is a requested configuration and source review, not a generated kernel,
effective configuration, boot result, or accepted guest. The selected source
is the three-file `linux-gcp-6.17` package authenticated by
`custom-kernel-source.json`. The build must apply the complete package patch;
reviewing upstream files alone does not replace that extraction step.

## Configuration contract

The requested fragment is `../custom-kernel.config`. In a fresh build directory,
use the selected kernel's Kconfig machinery, with no host `.config` or inherited
Kconfig environment:

```console
KCONFIG_ALLCONFIG=/inputs/custom-kernel.config make ARCH=x86 O=/build allnoconfig
make ARCH=x86 O=/build olddefconfig
```

The build front door must provide the pinned compiler/tools and fixed build
environment. These commands describe the Kconfig interface, not a complete
build invocation. `allnoconfig` starts with optional features disabled and
applies the explicit requested settings through dependency resolution. It
avoids inheriting desktop drivers, tracing, module loading, or networking
services from a distribution configuration. The resulting `.config` is the
authority for compilation and must be retained and reviewed.

All NVMe, GVE, TDX report, ConfigFS, SHA-256, and dm-verity support is requested
built-in. `CONFIG_MODULES=n` excludes loadable modules and their signing-key
closure. x86-64, UEFI, ACPI, APIC/MSI, paravirtualization, TDX, and DMA bounce
buffer support are explicit prerequisites. Four CPUs match the bounded
`c3-standard-4` experiment; this is not the large-memory mainnet profile.

The requested userland supports the evidence service's ELF executable, threads,
bounded asynchronous networking, filesystem mounts, and later confinement.
DHCP is public network setup, not a metadata credential consumer. The fixed
UKI command line and actual service/mount policy still need implementation and
review. No shell, guest administration service, swap, dump, raw-memory export,
module loading, kexec, or sleep path is introduced by this fragment. Actual
absence must be checked after dependency resolution and in the final image.

The build must reject a requested enabled value that dependency resolution
drops or changes. It must check the static kernel policy against the effective
configuration, not just this fragment, and preserve any refusal for review.
Kconfig can omit disabled hidden symbols: do not append comments to the output
to make a textual prohibition check pass. Any such mismatch requires explicit
review of the generated configuration and Kconfig semantics.

`CONFIG_IKCONFIG=y` requests embedding the effective configuration in the
kernel. After compilation, extract it using this source tree's
`scripts/extract-ikconfig` and require agreement with the retained effective
configuration. This establishes configuration consistency for the build; it
does not authenticate arbitrary caller-supplied binaries. Independent builds,
artifact hashing, offline signing, and the final boot verification remain
separate requirements.

## Native init and confinement prerequisites

`CONFIG_BINFMT_SCRIPT=n` and `CONFIG_TTY=n` are intentional. A stock
initramfs-tools shell `/init` cannot execute with this kernel. The single UKI
must instead carry a separately reviewed compiled ELF init/PID1 program.
It must mount devtmpfs, proc, sysfs, and ConfigFS explicitly: the selected
kernel's `DEVTMPFS_MOUNT` option does not perform that mount during initramfs
boot. It must also establish safe file descriptors 0/1/2 without a terminal,
activate and fully read the verity-protected root, establish its final root
and writable tmpfs paths, and confirm network readiness before dropping
capabilities and opening the listener. The evidence-agent foundation alone
does not implement this boot lifecycle.

The requested guest networking is IPv4-only. Do not configure an IPv6-only
listener or verifier route. With `CONFIG_BPF_SYSCALL=n`, confinement cannot
claim enforcement of systemd's `IPAddressDeny/Allow`, `SocketBindAllow/Deny`,
or `RestrictFileSystems` settings; those depend on BPF support. A reviewed
native init/service policy must enforce its actual filesystem, syscall, and
capability restrictions and test evidence access afterward. See the
[systemd v255 kernel requirements](https://raw.githubusercontent.com/systemd/systemd/v255/README)
and the kernel's [initramfs responsibilities](https://www.kernel.org/doc/html/latest/filesystems/ramfs-rootfs-initramfs.html).

## Halt-path observations

The authenticated original archive contains
`linux-6.17/arch/x86/coco/tdx/tdx.c`, SHA-256:

```text
0fd48e3de84d3c2e0fe0562e4dd12518bb0c59542fde59026de955bb2b551481
```

Source inspection found these behaviors:

- The halt hypercall passes an explicit `irq_disabled` argument in register
  `r12`. The #VE handler obtains it from `irqs_disabled()`; `tdx_halt` passes
  `false` before the safe-halt wrapper re-enables local interrupts.
- The #VE halt handler refuses emulation when interrupts are enabled, avoiding
  consumption of a wake event before requesting the blocking hypercall.
- The safe-halt path performs the TDX halt call before re-enabling interrupts.
- TDX initialization replaces the paravirtual halt and safe-halt operations;
  the x86 idle selection also chooses the TDX-aware halt routine for a TDX guest.

The authenticated Ubuntu diff does not modify `arch/x86/coco/tdx/tdx.c`.
It does modify `arch/x86/kernel/process.c` and `arch/x86/include/asm/tdx.h`;
their inspected hunks concern thread flags and TDX/SME cache handling for kexec,
not the idle-selection or guest halt paths above. The effective extracted
source must be checked again before compiling; no pattern-matching script
should turn these observations into a general correctness assertion.

These observations address the known unsafe interrupt/halt ordering motivating
the boot plan's halt check. They do not establish complete CPU-side-channel
coverage, a complete kernel-vulnerability audit, successful C3 wake behavior,
or evidence availability after the guest drops capabilities. Those require the
reviewed compiled artifact and actual bounded boot tests.
