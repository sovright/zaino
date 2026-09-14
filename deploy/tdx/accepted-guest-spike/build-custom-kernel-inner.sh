#!/usr/bin/env bash
# Run only inside the selected network-disabled builder container.
set -euo pipefail
export LC_ALL=C.UTF-8 TZ=UTC
fail() { echo "custom kernel build refused: $*" >&2; exit 1; }
[[ $# == 8 ]] || fail 'internal usage: SOURCES CLOSURE LOCAL_REPO EXPECTED_PACKAGES FRAGMENT PATCHES OUTPUT RUN_LABEL'
sources=$1 closure=$2 local_repo=$3 expected_packages=$4 fragment=$5 patches=$6 output=$7 run_label=$8
[[ "$run_label" =~ ^run-[12]$ ]] || fail 'invalid run label'
for path in "$sources" "$closure" "$local_repo" "$expected_packages" "$fragment" "$patches"; do [[ -e "$path" && ! -L "$path" ]] || fail 'missing regular build input'; done
[[ ! -e "$output" ]] || fail 'output already exists'
output_owner=$(stat -c '%u:%g' "$(dirname -- "$output")")
[[ "$output_owner" =~ ^[0-9]+:[0-9]+$ ]] || fail 'invalid output owner'
mkdir -m 700 -- "$output"
# The disposable container runs as root to install the offline tool closure.
# Hand its bounded output mount back to the unprivileged runner on every
# controlled exit so failure evidence and cleanup remain possible.
handoff_output() {
  local status=$?
  trap - EXIT
  if ! chown -R -h -- "$output_owner" "$output"; then
    echo 'custom kernel build refused: output ownership handoff failed' >&2
    [[ $status != 0 ]] || status=1
  fi
  exit "$status"
}
trap handoff_output EXIT

# The host authenticated every deb before constructing this local repository.
# A private APT configuration permits only the readonly file source, preserving
# the complete Pre-Depends transaction without external downloads.
apt_root=/tmp/zaino-kernel-apt
mkdir -p "$apt_root/etc/apt.conf.d" "$apt_root/etc/sources.list.d" "$apt_root/etc/preferences.d" "$apt_root/lists/partial" "$apt_root/cache/archives/partial"
: > "$apt_root/etc/preferences"
cat > "$apt_root/etc/sources.list" <<EOF
deb [trusted=yes] file:/inputs/repo ./
EOF
cat > "$apt_root/etc/apt.conf" <<EOF
APT::Architecture "amd64";
APT::Install-Recommends "false";
APT::Install-Suggests "false";
Acquire::Languages "none";
Acquire::Retries "0";
Acquire::http::Proxy "false";
Acquire::https::Proxy "false";
Dir::State::status "/var/lib/dpkg/status";
Dir::State::lists "$apt_root/lists";
Dir::Cache::archives "$apt_root/cache/archives";
Dir::Etc "$apt_root/etc";
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
export APT_CONFIG="$apt_root/etc/apt.conf"
unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY all_proxy no_proxy NO_PROXY
[[ $(apt-get --version | awk 'NR == 1 { print $2 }') == 2.8.3 ]] || fail 'unexpected apt version'
apt-get update
mapfile -t install_requests < <(awk -F '\t' '{print $1 "=" $2}' "$expected_packages")
[[ ${#install_requests[@]} -gt 0 ]] || fail 'empty tool closure'
DEBIAN_FRONTEND=noninteractive apt-get --assume-yes --no-remove --no-install-recommends install "${install_requests[@]}"
[[ -z $(dpkg --audit) ]] || fail 'dpkg audit reports an incomplete installation'
while IFS=$'\t' read -r package version architecture; do
  [[ $(dpkg-query -W -f='${Version}\t${Architecture}\n' "$package") == "$version"$'\t'"$architecture" ]] || fail "installed package mismatch: $package"
done < "$expected_packages"
[[ $(dpkg-query -W -f='${Version}' dpkg-dev) == 1.22.6ubuntu6.6 ]] || fail 'unexpected dpkg-source version'
[[ $(gcc-13 -dumpfullversion) == 13.3.0 ]] || fail 'unexpected gcc version'
[[ $(make --version | awk 'NR==1 {print $3}') == 4.3 ]] || fail 'unexpected make version'
[[ $(ld --version | awk 'NR==1 {print $NF}') == 2.42 ]] || fail 'unexpected linker version'

dsc=$(find "$sources" -mindepth 1 -maxdepth 1 -type f -name '*.dsc' -print)
[[ $(printf '%s\n' "$dsc" | awk 'NF {n++} END {print n+0}') == 1 ]] || fail 'expected exactly one dsc'
src="$output/source"
dpkg-source --no-check -x "$dsc" "$src"
lock_sha=$(sha256sum -- /builder/kernel-patches.json); [[ ${lock_sha%% *} == fa4aa401443c303077fc1a434bb82c5fe558f44b5a62f4ca3d6534f649c2289a ]] || fail 'mounted patch lock digest changed'
backport_sha=$(sha256sum -- "$patches/0003-tdx-getquote-linux-6.17-backport.patch"); [[ ${backport_sha%% *} == ab420f4663f504a61f33d054a350a88dd9dae8e35431c5fcdd800f025ee88bf8 ]] || fail 'mounted backport digest changed'
driver="$src/drivers/virt/coco/tdx-guest/tdx-guest.c"
driver_sha=$(sha256sum -- "$driver"); [[ ${driver_sha%% *} == 06d50d736be3f708dd78654884b296b379736529f0a1cb73f7753e3f9e4fa078 ]] || fail 'unexpected pre-patch TDX quote driver'
patch --batch --fuzz=0 -p1 -d "$src" < "$patches/0003-tdx-getquote-linux-6.17-backport.patch"
driver_sha=$(sha256sum -- "$driver"); [[ ${driver_sha%% *} == ac7a2fed535b553fbd112bca77d42f7d734fa23e72341ce7437b853d311f582a ]] || fail 'unexpected post-patch TDX quote driver'
bash /builder/verify-tdx-quote-hardening.sh "$driver" >/dev/null
build="$output/build"
mkdir -m 700 -- "$build"
export SOURCE_DATE_EPOCH=1789084800
export KBUILD_BUILD_TIMESTAMP='Fri Sep 11 00:00:00 UTC 2026'
export KBUILD_BUILD_USER=zaino KBUILD_BUILD_HOST=accepted-guest-builder KBUILD_BUILD_VERSION=1
export KCONFIG_NOTIMESTAMP=1
export KCFLAGS="-ffile-prefix-map=$src=/usr/src/zaino-kernel -fdebug-prefix-map=$src=/usr/src/zaino-kernel"
export KCPPFLAGS="$KCFLAGS"
KCONFIG_ALLCONFIG="$fragment" make -C "$src" O="$build" ARCH=x86 CC=gcc-13 HOSTCC=gcc-13 allnoconfig
make -C "$src" O="$build" ARCH=x86 CC=gcc-13 HOSTCC=gcc-13 olddefconfig

cp -- "$build/.config" "$output/effective-config.candidate"
bash /builder/verify-effective-config.sh --requested-only "$build/.config" "$fragment"
make -C "$src" O="$build" ARCH=x86 CC=gcc-13 HOSTCC=gcc-13 -j2 bzImage vmlinux
[[ -f "$build/arch/x86/boot/bzImage" && -f "$build/vmlinux" && -f "$build/System.map" ]] || fail 'missing kernel output'
bash "$src/scripts/extract-ikconfig" "$build/arch/x86/boot/bzImage" > "$output/embedded.config"
cmp -s "$build/.config" "$output/embedded.config" || fail 'compiled IKCONFIG differs from effective config'
mkdir -m 700 -- "$output/artifacts"
cp -- "$build/.config" "$output/artifacts/config"
cp -- "$output/embedded.config" "$output/artifacts/embedded.config"
cp -- "$build/arch/x86/boot/bzImage" "$output/artifacts/bzImage"
cp -- "$build/vmlinux" "$output/artifacts/vmlinux"
cp -- "$build/System.map" "$output/artifacts/System.map"
cp -- /builder/kernel-patches.json "$output/artifacts/kernel-patches.json"
for name in System.map bzImage config embedded.config kernel-patches.json vmlinux; do
  artifact="$output/artifacts/$name"
  digest=$(sha256sum -- "$artifact"); printf '%s  %s\n' "${digest%% *}" "${artifact##*/}"
done | LC_ALL=C sort > "$output/artifacts/SHA256SUMS"
printf 'apt=%s\ndpkg-source=%s\ngcc=%s\nmake=%s\nld=%s\n' \
  "$(apt-get --version | awk 'NR == 1 { print $2 }')" \
  "$(dpkg-query -W -f='${Version}' dpkg-dev)" "$(gcc-13 -dumpfullversion)" \
  "$(make --version | awk 'NR==1 {print $3}')" "$(ld --version | awk 'NR==1 {print $NF}')" > "$output/tool-versions.txt"
rm -rf -- "$src" "$build"
rm -f -- "$output/effective-config.candidate" "$output/embedded.config"
