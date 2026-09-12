#!/usr/bin/env bash
# Validate the reviewed package-root request without resolving or downloading.
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
selection="$root/upstream-selection.json"
roots="${1:-$root/package-roots.json}"
fail() { echo "package roots refused: $*" >&2; exit 1; }
[[ $# -le 1 ]] || fail 'usage: verify-package-roots.sh [package-roots.json]'
[[ -f "$roots" && ! -L "$roots" ]] || fail 'missing regular package roots'
jq -e --arg image "$(jq -r '.builder_base.image' "$selection")" --arg snapshot "$(jq -r '.package_snapshot.base_url' "$selection")" '
  .schema == "zaino-boot-spike-package-roots-v1" and
  .selected_builder_base_image == $image and .snapshot == $snapshot and .architecture == "amd64" and
  .resolver_apt_version == "2.8.3" and
  (.guest_roots | length > 0 and all(.[]; test("^[a-z0-9][a-z0-9+.-]*=[^[:space:]]+$"))) and
  (.builder_tool_roots | length > 0 and all(.[]; test("^[a-z0-9][a-z0-9+.-]*=[^[:space:]]+$"))) and
  ((.guest_roots + .builder_tool_roots) | length == (unique | length)) and
  .scope == "resolver_roots_only;kernel_suitability_and_image_admission_unverified"
' "$roots" >/dev/null || fail 'invalid package roots'
bash "$root/verify-upstream-selection.sh" >/dev/null
echo 'Verified package roots. No package closure or kernel suitability is implied.'
