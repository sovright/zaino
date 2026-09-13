# ConfigFS report permissions after capability drop

This is a source-only audit of the selected Linux 6.17 input, not a successful
quote, guest-boot, seccomp, or attestation-admission test. It supports retaining
the planned empty capability sets: the inspected report path does not require
restoring a capability merely to use its ordinary owner permissions.

## Evidence and inference

The inference assumes the agent retains filesystem UID 0 in the initial user
namespace, ConfigFS was mounted before capability drop, the intended report
directory is accessible and writable, and no later LSM or syscall policy denies
the operation. UID 0 alone does not bypass all checks once capabilities are
empty; the owner permission bits below are what support this path.

- `fs/inode.c` initializes new inode ownership to UID/GID 0.
  `fs/configfs/inode.c` retains that default unless persistent attributes were
  changed. `configfs_create_dir` in `fs/configfs/dir.c` creates directories with
  owner read/write/execute permissions (0755).
- `acl_permission_check` in `fs/namei.c` compares the mapped inode owner with
  the caller's filesystem UID and checks the owner mode bits. This branch does
  not require a DAC override capability when those bits already allow access.
- `drivers/virt/coco/guest/report.c` declares `inblob` using
  `CONFIGFS_BIN_ATTR_WO` (0200), and `outblob` using `CONFIGFS_BIN_ATTR_RO`
  (0444). The macros are in `include/linux/configfs.h`.
- The inspected ConfigFS open path requires the applicable permission bits and
  a registered read/write callback. The TSM item creation, input write, and
  output read callbacks contain no added capability check. Provider existence,
  valid input, generation state, and provider success still constrain requests.

This does not justify retaining mount, administration, DAC override, or device
capabilities in the agent. Mount setup belongs before the drop. It also does
not establish that a non-root UID could use unchanged root-owned directories
and the 0200 input file.

## Exact source scope

The original archive has SHA-256
`a5623ec5af79da8807e1467e43a1888461c7a445fb1e17533fe45f0fdf4394e3`.
The actual builder applies the authenticated Ubuntu distro diff before its
reviewed kernel backport. The distro diff SHA-256 is
`ab102e6505a4bfcf4a6393358ba2a562a140860dc9c477f535ee4c61e84a518b`.
Its `fs/namei.c` hunks alter protected-link defaults and mount-crossing checks,
not the owner-permission branch. It contains no hunks for the other files in
the table. These are the inspected original-tree file hashes; the namei hash
is explicitly before the distro diff, not the builder's final file hash.

| Original-tree file | SHA-256 |
| --- | --- |
| `drivers/virt/coco/guest/report.c` | `950424dcbf28508080e4de4bfaee36be4f0eca5162ffd8de13620f742f83c48d` |
| `fs/configfs/inode.c` | `bea5f2d941ef5484619ecb21cabd03611853b981769111af553d226de0fb4c53` |
| `fs/configfs/file.c` | `c5337c5744ae48c7dd46fa9cfece31261bbbced824ffe247ed3167b0a71592ca` |
| `fs/configfs/dir.c` | `ee0ca4734762407994273f165e93731f8d5e5245f58472b5c0d016d9d0bf6c3e` |
| `include/linux/configfs.h` | `40514b5e1a7bc3197b3ce2559920ba6a8afa775bdcbe7f498760e3c15010f8da` |
| `fs/namei.c` | `a812c54a4cdf887c4fdf40dc56c4aa319434fe297c253320707835647e88adc2` |
| `fs/inode.c` | `0b8944a2513a2dbaa654bd91df226a43f192057f057a702e69b66d347f864665` |

## Remaining runtime gate

In the exact rebuilt guest, record filesystem ownership/modes and all five
empty capability sets, then generate and independently verify fresh quotes
after the final TSYNC filter and mount policy are installed. Exercise repeated
requests and cleanup through the fixed worker, and verify CCEL access and
challenge/TLS binding on the same accepted connection. A listener-only Linux
confinement test does not cover these hardware paths. The separate quote-buffer
kernel backport and two-builder gate remain required; file permissions cannot
repair unsafe provider handling of shared VMM data.
