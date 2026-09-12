#!/usr/bin/env bash
# Offline verification of a resolved closure against retained signed indexes.
set -euo pipefail
export LC_ALL=C
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
fail() { echo "package closure refused: $*" >&2; exit 1; }
[[ $# -ge 1 && $# -le 2 ]] || fail 'usage: verify-package-closure.sh CLOSURE_DIRECTORY [PACKAGE_ROOTS_JSON]'
roots="${2:-$root/package-roots.json}"
closure=$(cd -- "$1" && pwd -P) || fail 'missing closure directory'
lock="$closure/package-lock.json"
packages="$closure/packages"
indexes="$closure/indexes"
[[ -f "$lock" && ! -L "$lock" && -d "$packages" && ! -L "$packages" && -d "$indexes" && ! -L "$indexes" ]] || fail 'invalid closure layout'
for tool in awk basename cmp dpkg-deb find gpgv jq sha256sum sort stat xz; do command -v "$tool" >/dev/null || fail "missing tool: $tool"; done
bash "$root/verify-package-roots.sh" "$roots" >/dev/null
lock_bytes=$(stat -c %s "$lock")
[[ "$lock_bytes" -gt 0 && "$lock_bytes" -le 65536 ]] || fail 'lock byte budget'
root_entries=$(find "$closure" -mindepth 1 -maxdepth 1 -print | sort)
[[ "$root_entries" == "$(printf '%s\n' "$indexes" "$lock" "$packages" | sort)" ]] || fail 'unexpected closure root entry'
roots_sha=$(sha256sum -- "$roots" | awk '{print $1}')
jq -e --arg builder "$(jq -r '.selected_builder_base_image' "$roots")" --arg snapshot "$(jq -r '.snapshot' "$roots")" --arg apt "$(jq -r '.resolver_apt_version' "$roots")" --arg roots "$roots_sha" '
  .schema == "zaino-boot-spike-package-closure-v1" and
  .selected_builder_base_image == $builder and .snapshot == $snapshot and .architecture == "amd64" and
  .apt_version == $apt and .package_roots_sha256 == $roots and
  .scope == "downloaded-package-closure-only;selected-builder-base-not-executed;resolver-host-not-hermetic;kernel-suitability-and-image-admission-unverified" and
  (.packages | length > 0 and length <= 512) and all(.packages[];
    (.name | test("^[a-z0-9][a-z0-9+.-]*$")) and (.version | type == "string" and length > 0) and
    (.architecture == "amd64" or .architecture == "all") and
    (.filename | test("^pool/([A-Za-z0-9+._-]+/){3}[A-Za-z0-9+._~-]+\\.deb$")) and (.filename | contains("..") | not) and
    (.bytes | type == "number" and . == floor and . > 0 and . <= 536870912) and
    (.sha256 | test("^[0-9a-f]{64}$")) and
    (.signed_index_origins | length > 0 and length == (unique | length) and all(.[]; test("^noble(-updates|-security)?/(main|universe)$")))) and
  ([.packages[] | [.name,.version,.architecture] | join("\t")] | length == (unique | length)) and
  ([.packages[].filename | split("/")[-1]] | length == (unique | length)) and
  ([.packages[].bytes] | add <= 1073741824)
' "$lock" >/dev/null || fail 'invalid package lock'
while IFS= read -r requested; do
  name=${requested%%=*}
  version=${requested#*=}
  count=$(jq --arg name "$name" --arg version "$version" '[.packages[] | select(.name == $name and .version == $version)] | length' "$lock")
  [[ "$count" == 1 ]] || fail "missing or duplicate requested root: $requested"
done < <(jq -r '.guest_roots[], .builder_tool_roots[]' "$roots")

release_value() {
  local release=$1 wanted=$2
  awk -v wanted="$wanted" '
    /^SHA256:/ { inside=1; next }
    /^[A-Z][A-Za-z0-9-]*:/ { inside=0 }
    inside && $3 == wanted { print $1 "\t" $2; found++ }
    END { if (found != 1) exit 1 }
  ' "$release"
}
proof_entries=$(find "$indexes" -mindepth 1 -maxdepth 1 -print | sort)
expected_proofs=$(for suite in noble noble-updates noble-security; do for component in main universe; do printf '%s/%s-%s-Packages.xz\n' "$indexes" "$suite" "$component"; done; done | sort)
[[ "$proof_entries" == "$expected_proofs" ]] || fail 'signed index proof set'
signed_rows=$(mktemp)
expected_files=$(mktemp)
actual_files=$(mktemp)
trap 'rm -f -- "$signed_rows" "$expected_files" "$actual_files"' EXIT
: > "$signed_rows"
for suite in noble noble-updates noble-security; do
  for component in main universe; do
    proof="$indexes/$suite-$component-Packages.xz"
    [[ -f "$proof" && ! -L "$proof" ]] || fail "nonregular signed index proof: $suite/$component"
    relative="$component/binary-amd64/Packages.xz"
    entry=$(release_value "$root/upstream/$suite.InRelease" "$relative") || fail "missing signed index: $suite/$relative"
    digest=${entry%%$'\t'*}; bytes=${entry#*$'\t'}
    [[ $(stat -c %s "$proof") == "$bytes" && $(sha256sum -- "$proof" | awk '{print $1}') == "$digest" ]] || fail "signed index proof: $suite/$component"
    xz --decompress --stdout -- "$proof" | awk -v suite="$suite" -v component="$component" 'BEGIN { RS=""; FS="\n"; OFS="\t" }
      {
        package=version=arch=filename=size=sha="";
        for (i=1; i<=NF; i++) {
          if ($i ~ /^Package: /) package=substr($i,10);
          else if ($i ~ /^Version: /) version=substr($i,10);
          else if ($i ~ /^Architecture: /) arch=substr($i,15);
          else if ($i ~ /^Filename: /) filename=substr($i,11);
          else if ($i ~ /^Size: /) size=substr($i,7);
          else if ($i ~ /^SHA256: /) sha=substr($i,9);
        }
        if (package != "" && version != "" && (arch == "amd64" || arch == "all") && filename != "" && size != "" && sha != "")
          print package,version,arch,filename,size,sha,suite "/" component;
      }' >> "$signed_rows"
  done
done

jq -r '.packages[].filename | split("/")[-1]' "$lock" | sort > "$expected_files"
find "$packages" -mindepth 1 -maxdepth 1 -print | while IFS= read -r entry; do
  [[ -f "$entry" && ! -L "$entry" ]] || fail "nonregular package entry: $entry"
  basename "$entry"
done | sort > "$actual_files"
cmp -s "$expected_files" "$actual_files" || fail 'package file set differs from lock'
while IFS=$'\t' read -r name version arch filename bytes digest; do
  origins=$(jq -r --arg filename "$filename" '.packages[] | select(.filename == $filename) | .signed_index_origins[]' "$lock" | sort)
  signed=$(awk -F '\t' -v name="$name" -v version="$version" -v arch="$arch" -v filename="$filename" -v bytes="$bytes" -v digest="$digest" '
    $1==name && $2==version && $3==arch && $4==filename && $5==bytes && $6==digest { print $7 }
  ' "$signed_rows" | sort -u)
  [[ -n "$signed" && "$origins" == "$signed" ]] || fail "package is not bound by claimed signed indexes: $filename"
  file="$packages/${filename##*/}"
  [[ $(stat -c %s "$file") == "$bytes" ]] || fail "package length: $filename"
  [[ $(sha256sum -- "$file" | awk '{print $1}') == "$digest" ]] || fail "package digest: $filename"
  [[ $(dpkg-deb -f "$file" Package) == "$name" && $(dpkg-deb -f "$file" Version) == "$version" && $(dpkg-deb -f "$file" Architecture) == "$arch" ]] || fail "package control fields: $filename"
done < <(jq -r '.packages[] | [.name,.version,.architecture,.filename,.bytes,.sha256] | @tsv' "$lock")
echo 'Verified downloaded package closure against retained signed indexes. Kernel suitability and image admission remain unverified.'
