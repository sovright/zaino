#!/usr/bin/env bash
# Run only inside the selected network-disabled builder container.
set -euo pipefail
export LC_ALL=C.UTF-8 TZ=UTC
fail() { echo "custom kernel build refused: $*" >&2; exit 1; }
[[ $# == 6 ]] || fail 'internal usage: SOURCES CLOSURE EXPECTED_PACKAGES FRAGMENT OUTPUT RUN_LABEL'
sources=$1 closure=$2 expected_packages=$3 fragment=$4 output=$5 run_label=$6
[[ "$run_label" =~ ^run-[12]$ ]] || fail 'invalid run label'
for path in "$sources" "$closure" "$expected_packages" "$fragment"; do [[ -e "$path" && ! -L "$path" ]] || fail 'missing regular build input'; done
[[ ! -e "$output" ]] || fail 'output already exists'
mkdir -m 700 -- "$output"

# The closure is authenticated by the host before entry. dpkg consumes only
# these retained bytes without downloads or network. A failed maintainer script
# or configuration is fatal.
mapfile -t debs < <(find "$closure/packages" -mindepth 1 -maxdepth 1 -type f -name '*.deb' -print | LC_ALL=C sort)
[[ ${#debs[@]} -gt 0 ]] || fail 'empty tool closure'
# Freeze the observed gawk Pre-Depends edge and satisfy it before the ordinary
# dpkg transaction. dpkg remains responsible for every other relation and fails
# normally if the pinned base does not satisfy it.
prerequisite=''
gawk_archive=''
for deb in "${debs[@]}"; do
  package=$(dpkg-deb -f "$deb" Package)
  if [[ "$package" == gawk ]]; then
    [[ -z "$gawk_archive" ]] || fail 'duplicate gawk archive'
    gawk_archive=$deb
  elif [[ "$package" == libmpfr6 ]]; then
    [[ -z "$prerequisite" ]] || fail 'duplicate libmpfr6 prerequisite'
    prerequisite=$deb
  fi
done
[[ -n "$gawk_archive" ]] || fail 'missing gawk archive'
[[ $(dpkg-deb -f "$gawk_archive" Version) == 1:5.2.1-2ubuntu0.1 && $(dpkg-deb -f "$gawk_archive" Architecture) == amd64 && $(dpkg-deb -f "$gawk_archive" Pre-Depends) == 'libmpfr6 (>= 3.1.3)' ]] || fail 'unexpected gawk Pre-Depends identity'
[[ -n "$prerequisite" ]] || fail 'missing libmpfr6 prerequisite'
[[ $(dpkg-deb -f "$prerequisite" Version) == 4.2.1-1build1.1 && $(dpkg-deb -f "$prerequisite" Architecture) == amd64 ]] || fail 'unexpected libmpfr6 prerequisite identity'
[[ $(awk -F '\t' '$1=="libmpfr6" && $2=="4.2.1-1build1.1" && $3=="amd64" {n++} END {print n+0}' "$expected_packages") == 1 ]] || fail 'libmpfr6 prerequisite absent from authenticated closure lock'
DEBIAN_FRONTEND=noninteractive dpkg --unpack "$prerequisite"
DEBIAN_FRONTEND=noninteractive dpkg --configure libmpfr6:amd64
DEBIAN_FRONTEND=noninteractive dpkg --unpack "${debs[@]}"
DEBIAN_FRONTEND=noninteractive dpkg --configure -a
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
for name in System.map bzImage config embedded.config vmlinux; do
  artifact="$output/artifacts/$name"
  digest=$(sha256sum -- "$artifact"); printf '%s  %s\n' "${digest%% *}" "${artifact##*/}"
done | LC_ALL=C sort > "$output/artifacts/SHA256SUMS"
printf 'apt=%s\ndpkg-source=%s\ngcc=%s\nmake=%s\nld=%s\n' \
  "$(apt-get --version | awk 'NR == 1 { print $2 }')" \
  "$(dpkg-query -W -f='${Version}' dpkg-dev)" "$(gcc-13 -dumpfullversion)" \
  "$(make --version | awk 'NR==1 {print $3}')" "$(ld --version | awk 'NR==1 {print $NF}')" > "$output/tool-versions.txt"
rm -rf -- "$src" "$build"
rm -f -- "$output/effective-config.candidate" "$output/embedded.config"
