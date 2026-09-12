#!/usr/bin/env bash
set -euo pipefail
source_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
scratch=$(mktemp -d)
trap 'rm -rf -- "$scratch"' EXIT
bash "$source_dir/verify-upstream-selection.sh" > "$scratch/positive.log" 2>&1
refuse_lock_edit() {
  local name=$1 filter=$2 case_dir
  case_dir="$scratch/$name"
  cp -R "$source_dir" "$case_dir"
  jq "$filter" "$case_dir/upstream-selection.json" > "$case_dir/edited.json"
  mv "$case_dir/edited.json" "$case_dir/upstream-selection.json"
  if bash "$case_dir/verify-upstream-selection.sh" > "$scratch/$name.log" 2>&1; then
    echo "unexpected acceptance: $name" >&2
    exit 1
  fi
}
refuse_lock_edit duplicate-evidence '.retained_evidence[0] = .retained_evidence[1]'
refuse_lock_edit wrong-platform '.builder_base.platform = "linux/arm64"'
refuse_lock_edit wrong-manifest-length '.builder_base.manifest_bytes += 1'
refuse_lock_edit complete-claim '.build_inputs_complete = true'
refuse_lock_edit package-closure-claim '.package_snapshot.package_closure_resolved = true'
refuse_lock_edit mutable-rootfs '.rootfs.url = "https://cloud-images.ubuntu.com/noble/current/root.tar.xz"'

for name in SHA256SUMS noble-updates.InRelease; do
  case_dir="$scratch/signature-$name"
  cp -R "$source_dir" "$case_dir"
  # Change signed content, then repair its outer hash and length. A refusal
  # must still come from the signature, rather than merely the file checksum.
  if [[ $name == SHA256SUMS ]]; then
    printf '\nmodified signed manifest\n' >> "$case_dir/upstream/$name"
  else
    awk '{ if ($0 == "Origin: Ubuntu") print "Origin: Altered"; else print }' \
      "$case_dir/upstream/$name" > "$case_dir/altered"
    mv "$case_dir/altered" "$case_dir/upstream/$name"
  fi
  digest=$(openssl dgst -sha256 -r "$case_dir/upstream/$name")
  digest=${digest%% *}
  bytes=$(wc -c < "$case_dir/upstream/$name" | tr -d ' ')
  jq --arg file "upstream/$name" --arg digest "$digest" --argjson bytes "$bytes" \
    '(.retained_evidence[] | select(.file == $file)) |= (.sha256 = $digest | .bytes = $bytes)' \
    "$case_dir/upstream-selection.json" > "$case_dir/edited.json"
  mv "$case_dir/edited.json" "$case_dir/upstream-selection.json"
  if bash "$case_dir/verify-upstream-selection.sh" > "$scratch/signature-$name.log" 2>&1; then
    echo "unexpected signed-content acceptance: $name" >&2
    exit 1
  fi
  grep -q 'BAD signature' "$scratch/signature-$name.log"
done
echo 'Upstream selection: positive control and 8 negative cases passed.'
