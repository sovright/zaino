#!/usr/bin/env bash
# Resolve and download a frozen Ubuntu package closure without installing it.
set -euo pipefail
export LC_ALL=C
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
roots="${2:-$root/package-roots.json}"
fail() { echo "package closure refused: $*" >&2; exit 1; }
[[ $# -ge 1 && $# -le 2 ]] || fail 'usage: resolve-package-closure.sh NEW_OUTPUT_DIRECTORY [PACKAGE_ROOTS_JSON]'
[[ $(uname -s) == Linux && $(uname -m) == x86_64 ]] || fail 'requires Linux x86_64'
for tool in apt-get awk curl cut dpkg-deb gpgv head jq paste sha256sum sort stat timeout xz; do command -v "$tool" >/dev/null || fail "missing tool: $tool"; done
if [[ ${ZAINO_PACKAGE_CLOSURE_DEADLINE_GUARD:-} != 1 ]]; then
  export ZAINO_PACKAGE_CLOSURE_DEADLINE_GUARD=1
  exec timeout --signal=TERM --kill-after=10s 1800s bash "$root/resolve-package-closure.sh" "$@"
fi
apt_version=$(apt-get --version | awk 'NR == 1 { print $2 }')
expected_apt_version=$(jq -r '.resolver_apt_version' "$roots")
[[ "$apt_version" == "$expected_apt_version" ]] || fail "unexpected apt resolver version: $apt_version"
requested_out=$1
[[ ! -e "$requested_out" ]] || fail 'output already exists'
out_parent=$(cd -- "$(dirname -- "$requested_out")" && pwd -P)
out_name=$(basename -- "$requested_out")
[[ "$out_name" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || fail 'unsafe output name'
final_out="$out_parent/$out_name"
bash "$root/verify-package-roots.sh" "$roots" >/dev/null

out="$final_out.partial.$$"
mkdir -m 700 -- "$out"
published=false
cleanup() { if [[ $published != true ]]; then rm -rf -- "$out"; fi; }
trap cleanup EXIT
trap 'exit 130' INT TERM
mkdir -m 700 -- "$out/apt" "$out/apt/etc" "$out/apt/etc/apt.conf.d" "$out/apt/etc/sources.list.d" "$out/apt/etc/preferences.d" "$out/apt/lists" "$out/apt/cache" "$out/indexes" "$out/packages"
mkdir -m 700 -- "$out/apt/lists/partial" "$out/apt/cache/partial"
: > "$out/apt/status"
: > "$out/apt/etc/preferences"
snapshot=$(jq -r '.snapshot' "$roots")
snapshot_path=${snapshot#https://snapshot.ubuntu.com/}
[[ "$snapshot_path" != "$snapshot" && "$snapshot_path" =~ ^ubuntu/[0-9]{8}T[0-9]{6}Z/$ ]] || fail 'mutable or foreign snapshot URL'

cat > "$out/apt/etc/apt.conf" <<EOF
#clear APT::Architectures;
APT::Architecture "amd64";
APT::Architectures { "amd64"; };
APT::Install-Recommends "false";
APT::Install-Suggests "false";
APT::Get::Assume-Yes "true";
Acquire::Languages "none";
Acquire::Retries "0";
Acquire::http::Proxy "false";
Acquire::https::Proxy "false";
Dir::State::status "$out/apt/status";
Dir::State::lists "$out/apt/lists";
Dir::Cache::archives "$out/apt/cache";
Dir::Etc "$out/apt/etc";
Dir::Etc::sourcelist "sources.list";
Dir::Etc::sourceparts "sources.list.d";
Dir::Etc::preferences "preferences";
Dir::Etc::preferencesparts "preferences.d";
Dir::Etc::main "apt.conf";
Dir::Etc::parts "apt.conf.d";
#clear DPkg::Pre-Install-Pkgs;
#clear DPkg::Post-Invoke;
#clear APT::Update::Post-Invoke;
EOF
cat > "$out/apt/etc/sources.list" <<EOF
deb [arch=amd64 signed-by=$root/upstream/ubuntu-archive-keyring.gpg] ${snapshot} noble main universe
deb [arch=amd64 signed-by=$root/upstream/ubuntu-archive-keyring.gpg] ${snapshot} noble-updates main universe
deb [arch=amd64 signed-by=$root/upstream/ubuntu-archive-keyring.gpg] ${snapshot} noble-security main universe
EOF

hash_file() { sha256sum -- "$1" | awk '{print $1}'; }
decode_uri_path() {
  local input=$1 output='' prefix rest hex remainder byte
  while [[ "$input" == *%* ]]; do
    prefix=${input%%\%*}
    rest=${input#*%}
    [[ "$rest" =~ ^([0-9A-Fa-f]{2})(.*)$ ]] || fail 'malformed resolver URI escape'
    hex=${BASH_REMATCH[1]}
    remainder=${BASH_REMATCH[2]}
    printf -v byte '%b' "\\x$hex"
    [[ "$byte" =~ ^[A-Za-z0-9+._~:-]$ ]] || fail 'unsafe resolver URI escape'
    output+="$prefix$byte"
    input=$remainder
  done
  printf '%s%s\n' "$output" "$input"
}
release_value() {
  local release=$1 wanted=$2
  awk -v wanted="$wanted" '
    /^SHA256:/ { inside=1; next }
    /^[A-Z][A-Za-z0-9-]*:/ { inside=0 }
    inside && $3 == wanted { print $1 "\t" $2; found++ }
    END { if (found != 1) exit 1 }
  ' "$release"
}

total_index_bytes=0
all_packages="$out/indexes/all-Packages"
: > "$all_packages"
for suite in noble noble-updates noble-security; do
  release="$root/upstream/$suite.InRelease"
  prefix="snapshot.ubuntu.com_${snapshot_path//\//_}dists_${suite}"
  cp -- "$release" "$out/apt/lists/${prefix}_InRelease"
  for component in main universe; do
    relative="$component/binary-amd64/Packages.xz"
    entry=$(release_value "$release" "$relative") || fail "missing signed index: $suite/$relative"
    digest=${entry%%$'\t'*}; bytes=${entry#*$'\t'}
    [[ "$digest" =~ ^[0-9a-f]{64}$ && "$bytes" =~ ^[0-9]+$ && "$bytes" -le 67108864 ]] || fail "invalid signed index metadata: $suite/$relative"
    total_index_bytes=$((total_index_bytes + bytes))
    (( total_index_bytes <= 268435456 )) || fail 'index byte budget exceeded'
    index="$out/indexes/$suite-$component-Packages.xz"
    curl --fail --silent --show-error --location --proto '=https' --max-time 120 --max-filesize 67108864 --output "$index" "${snapshot}dists/$suite/$relative"
    [[ $(stat -c %s "$index") == "$bytes" && $(hash_file "$index") == "$digest" ]] || fail "signed index mismatch: $suite/$relative"
    unpacked=$(xz --robot --list "$index" | awk -F '\t' '$1 == "totals" { print $5 }')
    [[ "$unpacked" =~ ^[0-9]+$ && "$unpacked" -le 268435456 ]] || fail "unpacked index budget: $suite/$relative"
    list="$out/apt/lists/${prefix}_${component}_binary-amd64_Packages"
    xz --decompress --stdout -- "$index" > "$list"
    awk -v suite="$suite" -v component="$component" 'BEGIN { RS="" } NF { print $0 "\nX-Zaino-Suite: " suite "\nX-Zaino-Component: " component "\n" }' "$list" >> "$all_packages"
  done
done

awk 'BEGIN { RS=""; FS="\n"; OFS="\t" }
  {
    package=version=arch=filename=size=sha=suite=component="";
    for (i=1; i<=NF; i++) {
      if ($i ~ /^Package: /) package=substr($i,10);
      else if ($i ~ /^Version: /) version=substr($i,10);
      else if ($i ~ /^Architecture: /) arch=substr($i,15);
      else if ($i ~ /^Filename: /) filename=substr($i,11);
      else if ($i ~ /^Size: /) size=substr($i,7);
      else if ($i ~ /^SHA256: /) sha=substr($i,9);
      else if ($i ~ /^X-Zaino-Suite: /) suite=substr($i,16);
      else if ($i ~ /^X-Zaino-Component: /) component=substr($i,20);
    }
    if (package != "" && version != "" && (arch == "amd64" || arch == "all") && filename != "" && size != "" && sha != "")
      print package,version,arch,filename,size,sha,suite,component;
  }' "$all_packages" | sort -u > "$out/package-index.tsv"
awk -F '\t' '
  $4 !~ /^pool\/([A-Za-z0-9+._-]+\/){3}[A-Za-z0-9+._~-]+\.deb$/ ||
  $4 ~ /\.\./ || $4 ~ /[?#]/ || $5 !~ /^[0-9]+$/ || $6 !~ /^[0-9a-f]{64}$/ { bad=1 }
  { key=$1 FS $2 FS $3; value=$5 FS $6; if (seen[key] && seen[key] != value) bad=1; seen[key]=value }
  END { exit bad }
' "$out/package-index.tsv" || fail 'unsafe or conflicting package index entry'

export APT_CONFIG="$out/apt/etc/apt.conf"
unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY all_proxy no_proxy NO_PROXY
mapfile -t requested < <(jq -r '.guest_roots[], .builder_tool_roots[]' "$roots")
apt-get --print-uris --download-only --no-install-recommends install "${requested[@]}" > "$out/apt-uris.txt"
awk 'NF >= 4 && $1 ~ /^\047https:/ {
  uri=$1; sub(/^\047/,"",uri); sub(/\047$/,"",uri);
  print uri "\t" $2 "\t" $3 "\t" $4
}' "$out/apt-uris.txt" > "$out/selected-uris.tsv"
[[ -s "$out/selected-uris.tsv" ]] || fail 'resolver selected no packages'

total_deb_bytes=0
: > "$out/selected-packages.tsv"
while IFS=$'\t' read -r uri apt_name apt_bytes _; do
  [[ "$uri" == "$snapshot"* && "$uri" != *'?'* && "$uri" != *'#'* ]] || fail 'resolver selected foreign URI'
  relative_encoded=${uri#"$snapshot"}
  [[ "$relative_encoded" != "$uri" ]] || fail 'resolver selected foreign URI'
  relative=$(decode_uri_path "$relative_encoded")
  [[ "$relative" =~ ^pool/[A-Za-z0-9+._~:/-]+\.deb$ && "$relative" != *'..'* ]] || fail 'resolver selected unsafe path'
  rows=$(awk -F '\t' -v path="$relative" '$4 == path { print }' "$out/package-index.tsv")
  [[ -n "$rows" ]] || fail "package path absent from signed indexes: $relative"
  unique_tuple_count=$(printf '%s\n' "$rows" | cut -f1-6 | sort -u | awk 'NF { n++ } END { print n+0 }')
  [[ "$unique_tuple_count" == 1 ]] || fail "conflicting signed package entries: $relative"
  IFS=$'\t' read -r package version arch _ bytes digest _ _ <<< "$(printf '%s\n' "$rows" | sort | head -1)"
  origins=$(printf '%s\n' "$rows" | awk -F '\t' '{ print $7 "/" $8 }' | sort -u | paste -sd, -)
  [[ "$apt_bytes" == "$bytes" ]] || fail "resolver size mismatch: $relative"
  [[ "$bytes" =~ ^[0-9]+$ && "$bytes" -gt 0 && "$bytes" -le 536870912 ]] || fail "package byte budget: $relative"
  total_deb_bytes=$((total_deb_bytes + bytes)); (( total_deb_bytes <= 1073741824 )) || fail 'package byte budget exceeded'
  [[ "$apt_name" != */* && "$apt_name" != *..* && "$apt_name" =~ ^[A-Za-z0-9][A-Za-z0-9%+._~:-]*\.deb$ ]] || fail 'unsafe resolver output name'
  destination="$out/packages/${relative##*/}"
  [[ ! -e "$destination" ]] || fail "package basename collision: ${relative##*/}"
  curl --fail --silent --show-error --location --proto '=https' --max-time 600 --max-filesize 536870912 --output "$destination" "$uri"
  [[ $(stat -c %s "$destination") == "$bytes" && $(hash_file "$destination") == "$digest" ]] || fail "package bytes mismatch: $relative"
  [[ $(dpkg-deb -f "$destination" Package) == "$package" && $(dpkg-deb -f "$destination" Version) == "$version" && $(dpkg-deb -f "$destination" Architecture) == "$arch" ]] || fail "package control mismatch: $relative"
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$package" "$version" "$arch" "$relative" "$bytes" "$digest" "$origins" >> "$out/selected-packages.tsv"
done < "$out/selected-uris.tsv"

sort -u "$out/selected-packages.tsv" -o "$out/selected-packages.tsv"
jq -n --arg builder "$(jq -r '.selected_builder_base_image' "$roots")" --arg snapshot "$snapshot" --arg apt "$apt_version" \
  --arg roots_sha256 "$(hash_file "$roots")" --rawfile rows "$out/selected-packages.tsv" '
  {schema:"zaino-boot-spike-package-closure-v1", selected_builder_base_image:$builder, snapshot:$snapshot,
   architecture:"amd64", apt_version:$apt, package_roots_sha256:$roots_sha256,
   scope:"downloaded-package-closure-only;selected-builder-base-not-executed;resolver-host-not-hermetic;kernel-suitability-and-image-admission-unverified",
   packages:($rows | split("\n") | map(select(length>0) | split("\t") |
     {name:.[0],version:.[1],architecture:.[2],filename:.[3],bytes:(.[4]|tonumber),sha256:.[5],signed_index_origins:(.[6]|split(","))}))} |
  .packages |= sort_by(.name,.version,.architecture,.filename)
' > "$out/package-lock.json"
rm -rf -- "$out/apt" "$out/apt-uris.txt" "$out/selected-uris.tsv" "$out/package-index.tsv" "$out/selected-packages.tsv" "$all_packages"
chmod -R go-rwx -- "$out"
mv --no-clobber --no-target-directory -- "$out" "$final_out"
[[ -d "$final_out" && ! -e "$out" ]] || fail 'atomic publication collision'
published=true
echo "Resolved a frozen download-only package closure. Kernel suitability and image admission remain unverified."
