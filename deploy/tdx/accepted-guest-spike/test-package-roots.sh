#!/usr/bin/env bash
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
scratch=$(mktemp -d)
trap 'rm -rf -- "$scratch"' EXIT
bash "$root/verify-package-roots.sh" > "$scratch/positive.log"
refuse() {
  local name=$1 filter=$2
  jq "$filter" "$root/package-roots.json" > "$scratch/$name.json"
  if bash "$root/verify-package-roots.sh" "$scratch/$name.json" > "$scratch/$name.log" 2>&1; then
    echo "unexpected package-root acceptance: $name" >&2
    exit 1
  fi
}
refuse mutable-snapshot '.snapshot = "https://snapshot.ubuntu.com/ubuntu/latest/"'
refuse builder-tag '.selected_builder_base_image = "docker.io/library/ubuntu:24.04"'
refuse wrong-architecture '.architecture = "arm64"'
refuse wrong-resolver '.resolver_apt_version = "latest"'
refuse duplicate-root '.builder_tool_roots += [.guest_roots[0]]'
refuse unpinned-root '.guest_roots[0] = "linux-image-gcp"'
refuse broadened-scope '.scope = "image_admission_complete"'
echo 'Package roots: positive control and 7 negative cases passed.'
