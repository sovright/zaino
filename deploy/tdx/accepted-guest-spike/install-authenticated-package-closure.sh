#!/usr/bin/env bash
# Install a host-authenticated deb closure from its readonly local file repository.
set -euo pipefail
fail() { echo "offline package installation refused: $*" >&2; exit 1; }
[[ $# == 3 ]] || fail 'usage: install-authenticated-package-closure.sh LOCAL_REPO EXPECTED_PACKAGES PRIVATE_APT_ROOT'
repo=$1 expected=$2 apt_root=$3
[[ -d "$repo" && ! -L "$repo" && -f "$repo/Packages" ]] || fail 'local repository rejected'
[[ -f "$expected" && ! -L "$expected" ]] || fail 'expected package list rejected'
mkdir -p "$apt_root/etc/apt.conf.d" "$apt_root/etc/sources.list.d" "$apt_root/etc/preferences.d" "$apt_root/lists/partial" "$apt_root/cache/archives/partial"
: > "$apt_root/etc/preferences"
printf '%s\n' 'deb [trusted=yes] file:/inputs/repo ./' > "$apt_root/etc/sources.list"
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
mapfile -t requests < <(awk -F '\t' 'NF==3 {print $1 "=" $2}' "$expected")
[[ ${#requests[@]} -gt 0 ]] || fail 'empty package closure'
DEBIAN_FRONTEND=noninteractive apt-get --assume-yes --no-remove --no-install-recommends install "${requests[@]}"
[[ -z $(dpkg --audit) ]] || fail 'dpkg audit reports an incomplete installation'
while IFS=$'\t' read -r package version architecture; do
  [[ $(dpkg-query -W -f='${Version}\t${Architecture}\n' "$package") == "$version"$'\t'"$architecture" ]] || fail "installed package mismatch: $package"
done < "$expected"
