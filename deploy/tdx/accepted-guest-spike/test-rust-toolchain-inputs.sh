#!/usr/bin/env bash
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
[[ $# -le 1 ]] || exit 1
temporary=$(mktemp -d)
trap 'rm -rf -- "$temporary"' EXIT
chmod 700 "$temporary"
cp "$root/verify-rust-toolchain-inputs.sh" "$temporary/"
cp -R "$root/rust-toolchain-inputs" "$temporary/"
reset_lock() { cp "$root/rust-toolchain-inputs.json" "$temporary/rust-toolchain-inputs.json"; }
reject() {
  if bash "$temporary/verify-rust-toolchain-inputs.sh" "$@" > "$temporary/result" 2>&1; then
    echo 'invalid Rust input accepted' >&2
    exit 1
  fi
}
reset_lock
bash "$temporary/verify-rust-toolchain-inputs.sh"
for mutation in \
  '.version = "stable"' \
  '.builder_execution_verified = true' \
  '.components[0].file = "../cargo.tar.xz"' \
  '.components[0].url = "https://example.com/cargo.tar.xz"' \
  '.components[1] = .components[0]' \
  '.components[0].sha256 = ("0" * 64)' \
  '.manifest.bytes += 1' \
  '.unexpected = true'; do
  jq "$mutation" "$root/rust-toolchain-inputs.json" > "$temporary/rust-toolchain-inputs.json"
  reject
done
reset_lock
printf '\n' >> "$temporary/rust-toolchain-inputs/channel-rust-1.96.0.toml"
reject
rm "$temporary/rust-toolchain-inputs/channel-rust-1.96.0.toml"
ln -s "$root/rust-toolchain-inputs/channel-rust-1.96.0.toml" "$temporary/rust-toolchain-inputs/channel-rust-1.96.0.toml"
reject
rm "$temporary/rust-toolchain-inputs/channel-rust-1.96.0.toml"
cp "$root/rust-toolchain-inputs/channel-rust-1.96.0.toml" "$temporary/rust-toolchain-inputs/"
if [[ $# == 1 ]]; then
  bash "$temporary/verify-rust-toolchain-inputs.sh" "$1"
  mkdir "$temporary/archives"
  cp "$1/"*.tar.xz "$temporary/archives/"
  touch "$temporary/archives/.unexpected"
  reject "$temporary/archives"
  rm "$temporary/archives/.unexpected"
  cargo="$temporary/archives/cargo-1.96.0-x86_64-unknown-linux-gnu.tar.xz"
  rm "$cargo"
  ln -s "$1/cargo-1.96.0-x86_64-unknown-linux-gnu.tar.xz" "$cargo"
  reject "$temporary/archives"
  rm "$cargo"
  cp "$1/cargo-1.96.0-x86_64-unknown-linux-gnu.tar.xz" "$cargo"
  printf X | dd of="$cargo" bs=1 count=1 conv=notrunc 2>/dev/null
  reject "$temporary/archives"
  echo 'Rust archive checks passed: actual positive and three refusal cases'
fi
echo 'Rust metadata checks passed: positive and ten refusal cases'
