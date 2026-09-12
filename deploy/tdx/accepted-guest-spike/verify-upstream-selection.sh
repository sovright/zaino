#!/usr/bin/env bash
# Checks the partial upstream lock only; never authorizes a guest build or boot.
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
lock="$root/upstream-selection.json"
fail() { echo "upstream selection refused: $*" >&2; exit 1; }
hash() {
  local result
  result=$(openssl dgst -sha256 -r "$1")
  printf '%s\n' "${result%% *}"
}
[[ $# -le 1 ]] || fail 'usage: verify-upstream-selection.sh [downloaded-rootfs]'
[[ -f "$lock" && ! -L "$lock" ]] || fail 'missing regular lock'
jq -e '
  .schema == "zaino-boot-spike-upstream-selection-v1" and
  .scope == "partial_upstream_selection_only" and
  .build_inputs_complete == false and
  ([.retained_evidence[].file] | sort) == ([
    "upstream/SHA256SUMS", "upstream/SHA256SUMS.gpg",
    "upstream/cloud-image-signing-key.asc", "upstream/builder-index.json",
    "upstream/builder-amd64-manifest.json", "upstream/noble.InRelease",
    "upstream/noble-updates.InRelease", "upstream/noble-security.InRelease",
    "upstream/ubuntu-archive-keyring.gpg"
  ] | sort) and
  (.rootfs.sha256 | test("^[0-9a-f]{64}$")) and
  (.rootfs.bytes | type == "number" and . == floor and . > 0 and . <= 1073741824) and
  .rootfs.url == "https://cloud-images.ubuntu.com/releases/noble/release-20260826/ubuntu-24.04-server-cloudimg-amd64-root.tar.xz" and
  .builder_base.platform == "linux/amd64" and
  (.builder_base.manifest_bytes | type == "number" and . == floor and . > 0 and . <= 1048576) and
  .package_snapshot.base_url == "https://snapshot.ubuntu.com/ubuntu/20260911T000000Z/" and
  .package_snapshot.suites == ["noble", "noble-updates", "noble-security"] and
  .package_snapshot.metadata_signature_verified == true and
  .package_snapshot.package_closure_resolved == false and
  all(.retained_evidence[];
    (.file | test("^upstream/[A-Za-z0-9.-]+$")) and
    (.sha256 | test("^[0-9a-f]{64}$")) and
    (.bytes | type == "number" and . > 0 and . <= 1048576))
' "$lock" >/dev/null || fail 'invalid partial-lock schema'
while IFS=$'\t' read -r file bytes digest; do
  path="$root/$file"
  [[ -f "$path" && ! -L "$path" ]] || fail "missing regular evidence: $file"
  [[ $(wc -c < "$path" | tr -d ' ') == "$bytes" ]] || fail "evidence length: $file"
  [[ $(hash "$path") == "$digest" ]] || fail "evidence digest: $file"
done < <(jq -r '.retained_evidence[] | [.file, .bytes, .sha256] | @tsv' "$lock")

key_fingerprint=D2EB44626FDDC30B513D5BB71A5D6C4C7DB87C81
[[ $(jq -r '.rootfs.signing_fingerprint' "$lock") == "$key_fingerprint" ]] || fail 'unreviewed signing key'
scratch=$(mktemp -d)
trap 'rm -rf -- "$scratch"' EXIT
chmod 700 "$scratch"
gpg --homedir "$scratch" --batch --dearmor --output "$scratch/keyring.gpg" "$root/upstream/cloud-image-signing-key.asc"
gpgv --homedir "$scratch" --status-fd 1 --keyring "$scratch/keyring.gpg" \
  "$root/upstream/SHA256SUMS.gpg" "$root/upstream/SHA256SUMS" > "$scratch/status"
awk -v expected="$key_fingerprint" '$2 == "VALIDSIG" && $3 == expected { valid++ } END { exit valid != 1 }' "$scratch/status" || fail 'manifest signer'
expected_root=$(jq -r '.rootfs.sha256' "$lock")
awk -v expected="$expected_root" '$1 == expected && $2 == "*ubuntu-24.04-server-cloudimg-amd64-root.tar.xz" { valid++ } END { exit valid != 1 }' "$root/upstream/SHA256SUMS" || fail 'rootfs not bound by signed manifest'
archive_fingerprint=F6ECB3762474EDA9D21B7022871920D1991BC93C
[[ $(jq -r '.package_snapshot.signing_fingerprint' "$lock") == "$archive_fingerprint" ]] || fail 'unreviewed archive key'
for suite in noble noble-updates noble-security; do
  gpgv --homedir "$scratch" --status-fd 1 --keyring "$root/upstream/ubuntu-archive-keyring.gpg" \
    "$root/upstream/$suite.InRelease" > "$scratch/status"
  awk -v expected="$archive_fingerprint" '$2 == "VALIDSIG" && $3 == expected { valid++ } END { exit valid != 1 }' "$scratch/status" || fail "archive signer: $suite"
done
index_digest="sha256:$(hash "$root/upstream/builder-index.json")"
child_digest="sha256:$(hash "$root/upstream/builder-amd64-manifest.json")"
[[ $(jq -r '.builder_base.index_digest' "$lock") == "$index_digest" ]] || fail 'builder index digest'
[[ $(jq -r '.builder_base.image' "$lock") == "docker.io/library/ubuntu@$child_digest" ]] || fail 'builder image digest'
child_bytes=$(wc -c < "$root/upstream/builder-amd64-manifest.json" | tr -d ' ')
[[ $(jq -r '.builder_base.manifest_bytes' "$lock") == "$child_bytes" ]] || fail 'builder manifest length'
jq -e --arg digest "$child_digest" --argjson bytes "$child_bytes" '[.manifests[] | select(.platform.os == "linux" and .platform.architecture == "amd64")] | length == 1 and .[0].digest == $digest and .[0].size == $bytes' "$root/upstream/builder-index.json" >/dev/null || fail 'builder platform selection'
[[ $(jq -r '.config.digest' "$root/upstream/builder-amd64-manifest.json") == $(jq -r '.builder_base.config_digest' "$lock") ]] || fail 'builder config binding'
if [[ $# == 1 ]]; then
  [[ -f "$1" && ! -L "$1" ]] || fail 'rootfs is not a regular file'
  [[ $(wc -c < "$1" | tr -d ' ') == $(jq -r '.rootfs.bytes' "$lock") ]] || fail 'rootfs length'
  [[ $(hash "$1") == "$expected_root" ]] || fail 'rootfs digest'
fi
echo 'Verified partial upstream selection. Build inputs remain incomplete; no build or boot is authorized by this check.'
