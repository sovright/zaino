#!/usr/bin/env bash
# Build the evidence agent in the selected network-disabled builder.
set -euo pipefail
export LC_ALL=C.UTF-8 TZ=UTC SOURCE_DATE_EPOCH=1789084800
fail() { echo "offline workload build refused: $*" >&2; exit 1; }
[[ $# == 8 ]] || fail 'internal usage: REPO SOURCE LOCAL_REPO EXPECTED RUST_ARCHIVES OUTPUT RUN_LABEL OWNER'
repo=$1 source_input=$2 local_repo=$3 expected=$4 rust_archives=$5 output=$6 run_label=$7 output_owner=$8
[[ "$run_label" =~ ^run-[12]$ && "$output_owner" =~ ^[0-9]+:[0-9]+$ ]] || fail 'invalid build identity'
[[ ! -e "$output" ]] || fail 'output already exists'; mkdir -m 700 "$output"
handoff() { local s=$?; trap - EXIT; chown -R -h -- "$output_owner" "$output" || { echo 'offline workload build refused: output ownership handoff failed' >&2; [[ $s != 0 ]] || s=1; }; exit "$s"; }
trap handoff EXIT
bash /builder/install-packages.sh "$local_repo" "$expected" /tmp/zaino-workload-apt
[[ $(gcc-13 -dumpfullversion) == 13.3.0 ]] || fail 'unexpected gcc version'
[[ $(musl-gcc -dumpmachine) == x86_64-linux-gnu ]] || fail 'unexpected musl compiler target'

mkdir -m 755 /opt/rust
for archive in "$rust_archives"/*.tar.xz; do
  top=$(tar -tf "$archive" | awk -F/ 'NR==1 {print $1}')
  [[ "$top" =~ ^(cargo|rustc|rust-std)-1\.96\.0-x86_64-unknown-linux-(gnu|musl)$ ]] || fail 'unexpected Rust archive layout'
  tar -xJf "$archive" -C /tmp
  bash "/tmp/$top/install.sh" --prefix=/opt/rust --disable-ldconfig
  rm -rf -- "/tmp/$top"
done
export PATH=/opt/rust/bin:/usr/bin:/bin CARGO_HOME=/tmp/cargo-home RUSTUP_HOME=/nonexistent
unset RUSTC RUSTFLAGS CARGO_ENCODED_RUSTFLAGS CARGO_TARGET_DIR CC CFLAGS CXX CXXFLAGS
rustv=$(rustc -vV); cargov=$(cargo -Vv)
grep -Fx 'release: 1.96.0' <<<"$rustv" >/dev/null || fail 'rustc release mismatch'
grep -Fx 'commit-hash: ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96' <<<"$rustv" >/dev/null || fail 'rustc commit mismatch'
grep -Fx 'host: x86_64-unknown-linux-gnu' <<<"$rustv" >/dev/null || fail 'rustc host mismatch'
grep -F 'cargo 1.96.0' <<<"$cargov" >/dev/null || fail 'cargo version mismatch'
mkdir -m 700 "$CARGO_HOME" /tmp/target
cp "$source_input/config.toml" "$CARGO_HOME/config.toml"
export CARGO_TARGET_DIR=/tmp/target CARGO_INCREMENTAL=0
export RUSTFLAGS="-C debuginfo=0 -C strip=symbols -C link-arg=-Wl,-Map=/tmp/evidence-agent.link-map --remap-path-prefix=$repo=/usr/src/zaino --remap-path-prefix=/tmp/target=/usr/src/zaino-target"
cargo build --manifest-path "$repo/Cargo.toml" --locked --frozen --offline --release -p tdx-evidence-agent
agent=/tmp/target/release/tdx-evidence-agent
[[ -f "$agent" && ! -L "$agent" ]] || fail 'missing evidence agent'
readelf -h "$agent" | grep -Eq 'Type:[[:space:]]+DYN' || fail 'evidence agent is not PIE'
interp=$(readelf -l "$agent" | awk -F': ' '/Requesting program interpreter/ {gsub(/\]/,"",$2); print $2}')
[[ "$interp" == /lib64/ld-linux-x86-64.so.2 ]] || fail 'unexpected evidence agent interpreter'
mkdir -m 700 "$output/artifacts" "$output/runtime-libs"
cp "$agent" "$output/artifacts/tdx-evidence-agent"
cp /tmp/evidence-agent.link-map "$output/evidence-agent.link-map"
ldd "$agent" > "$output/runtime-closure.txt"
grep -Eq 'not found|libssl|libcrypto' "$output/runtime-closure.txt" && fail 'runtime closure rejected'
awk '/=> \// {print $3} /^\// {print $1}' "$output/runtime-closure.txt" | LC_ALL=C sort -u > /tmp/runtime-paths
printf '%s\n' "$interp" >> /tmp/runtime-paths
LC_ALL=C sort -u -o /tmp/runtime-paths /tmp/runtime-paths
while IFS= read -r library; do
  [[ "$library" == /* && -f "$library" ]] || fail 'runtime library rejected'
  destination="$output/runtime-libs$library"; mkdir -p "$(dirname "$destination")"; cp -L -- "$library" "$destination"
done < /tmp/runtime-paths
while IFS= read -r library; do destination="$output/runtime-libs$library"; digest=$(sha256sum "$destination"); printf '%s\t%s\t%s\n' "$(stat -c %a "$destination")" "${digest%% *}" "$library"; done < /tmp/runtime-paths > "$output/canonical-runtime-closure.tsv"
printf '%s\n%s\n' "$rustv" "$cargov" > "$output/rust-tool-versions.txt"
printf 'gcc=%s\nmusl-gcc=%s\nld=%s\n' "$(gcc-13 -dumpfullversion)" "$(musl-gcc -dumpfullversion)" "$(ld --version | awk 'NR==1{print $NF}')" > "$output/native-tool-versions.txt"
printf '%s\n' 'init_artifact=deferred_until_rootfs_verity_cmdline_binding' > "$output/init-status.txt"
(cd "$output" && find artifacts runtime-libs -type f -print; printf '%s\n' canonical-runtime-closure.tsv rust-tool-versions.txt native-tool-versions.txt init-status.txt) | LC_ALL=C sort | while read -r file; do digest=$(sha256sum "$output/$file"); printf '%s  %s\n' "${digest%% *}" "$file"; done > "$output/SHA256SUMS"
