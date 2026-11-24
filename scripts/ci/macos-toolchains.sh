#!/usr/bin/env bash
# Installs what the macOS build needs besides Xcode and the Metal toolchain (B9-CI), each pinned,
# each skipped when already there (a persistent self-hosted runner keeps them between runs):
#
#   macos-toolchains.sh <tools dir>
#
# - rustup (1.29.3, rustup-init checked against its pinned SHA-256) when there is none, then the
#   Rust toolchain rust-toolchain.toml names (profile minimal plus the file's components);
# - rzup built from the hemilabs/risc0 rev Cargo.toml pins (the same rzup library risc0-build
#   links to find the guest toolchain; cargo install --locked with the fork's Cargo.lock), then the
#   RISC Zero Rust guest toolchain 1.97.0 (RZUP_RUST_VERSION; what the benchmark guests were built and
#   measured with: RELEASE-DEPS.md) through it. rzup checks the toolchain archive's SHA-256 against
#   RISC Zero's manifest;
# - protoc 36.2 (risc0-groth16's circom-witnesscalc build script), the official
#   protoc-36.2-osx-aarch_64.zip checked against its pinned SHA-256, unpacked into <tools dir>.
# In a GitHub Actions step it adds ~/.cargo/bin to GITHUB_PATH and PROTOC to GITHUB_ENV; elsewhere it
# prints the two lines to export. Versions are printed at the end.
set -euo pipefail
tools=${1:?usage: $0 <tools dir>}
ci=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$ci/../.." && pwd)
mkdir -p "$tools"; tools=$(cd "$tools" && pwd)
die() { echo "::error::macos-toolchains: $*" >&2; exit 1; }
sha() { shasum -a 256 "$1" | cut -d' ' -f1; }
fetch() { # <url> <sha256> <file>
  curl -fsSL --connect-timeout 30 --speed-limit 102400 --speed-time 60 --retry 5 --retry-delay 5 \
    --retry-all-errors -o "$3" "$1" || die "download failed: $1"
  [ "$(sha "$3")" = "$2" ] || die "$1: SHA-256 $(sha "$3"), want $2"
}

RUSTUP_VERSION=1.29.3
RUSTUP_SHA256=63752a1919a3a4793173ec70f8f212621a7ce38ba6a246095984482f4de20f9f
PROTOC_VERSION=36.2
PROTOC_SHA256=9cd98a532c5c5e0c4161314de0225de27e4c8a323917b6ea7b1b714d3ae23466
RZUP_RUST_VERSION=${RZUP_RUST_VERSION:-1.97.0}
RISC0_REV=$(sed -n 's/^risc0-zkvm = { git = "https:\/\/github.com\/hemilabs\/risc0", rev = "\([0-9a-f]*\)" }.*/\1/p' "$repo/Cargo.toml")
[ -n "$RISC0_REV" ] || die "no hemilabs/risc0 rev in Cargo.toml"

cargo_home=${CARGO_HOME:-$HOME/.cargo}
export PATH="$cargo_home/bin:$PATH"

echo "== rustup"
if ! command -v rustup >/dev/null 2>&1; then
  fetch "https://static.rust-lang.org/rustup/archive/$RUSTUP_VERSION/aarch64-apple-darwin/rustup-init" \
    "$RUSTUP_SHA256" "$tools/rustup-init"
  chmod +x "$tools/rustup-init"
  "$tools/rustup-init" -y --no-modify-path --profile minimal --default-toolchain none
  rm -f "$tools/rustup-init"
fi
rustup --version 2>/dev/null
echo "== Rust toolchain of rust-toolchain.toml"
# Named explicitly (channel and components from the file): a runner's older rustup (before 1.28)
# does not take a bare `rustup toolchain install`.
channel=$(sed -n 's/^channel = "\(.*\)"/\1/p' "$repo/rust-toolchain.toml")
components=$(sed -n 's/^components = \[\(.*\)\]/\1/p' "$repo/rust-toolchain.toml" | tr -d '" ')
[ -n "$channel" ] || die "no channel in rust-toolchain.toml"
rustup toolchain install "$channel" --profile minimal ${components:+--component "$components"}
(cd "$repo" && rustc -vV && cargo -V)

echo "== RISC Zero guest toolchain $RZUP_RUST_VERSION"
risc0_home=${RISC0_HOME:-$HOME/.risc0}
rzup_bin=$risc0_home/bin/rzup
want_rzup="rzup @ hemilabs/risc0 $RISC0_REV"
if [ "$(cat "$risc0_home/bin/.rzup-source" 2>/dev/null)" != "$want_rzup" ] || [ ! -x "$rzup_bin" ]; then
  # A throwaway target dir, deleted afterwards (disk), and only the features the CLI needs (no AWS SDK).
  # (From the repository, so rust-toolchain.toml picks the compiler.)
  (cd "$repo" && CARGO_TARGET_DIR="$tools/rzup-target" cargo install \
    --locked --git https://github.com/hemilabs/risc0 --rev "$RISC0_REV" \
    --no-default-features --features cli,install --root "$risc0_home" --force rzup)
  rm -rf "$tools/rzup-target"
  echo "$want_rzup" > "$risc0_home/bin/.rzup-source"
fi
"$rzup_bin" --version
if ! ls -d "$risc0_home/toolchains/v$RZUP_RUST_VERSION-rust-aarch64-apple-darwin/bin" >/dev/null 2>&1; then
  "$rzup_bin" install rust "$RZUP_RUST_VERSION"
fi
"$rzup_bin" default rust "$RZUP_RUST_VERSION"
"$risc0_home/toolchains/v$RZUP_RUST_VERSION-rust-aarch64-apple-darwin/bin/rustc" --version \
  || die "the RISC Zero Rust toolchain $RZUP_RUST_VERSION does not run"
"$rzup_bin" show 2>/dev/null || true

echo "== protoc $PROTOC_VERSION"
protoc=$tools/protoc-$PROTOC_VERSION/bin/protoc
if [ ! -x "$protoc" ]; then
  fetch "https://github.com/protocolbuffers/protobuf/releases/download/v$PROTOC_VERSION/protoc-$PROTOC_VERSION-osx-aarch_64.zip" \
    "$PROTOC_SHA256" "$tools/protoc.zip"
  rm -rf "$tools/protoc-$PROTOC_VERSION"
  mkdir -p "$tools/protoc-$PROTOC_VERSION"
  unzip -q "$tools/protoc.zip" -d "$tools/protoc-$PROTOC_VERSION"
  rm -f "$tools/protoc.zip"
fi
"$protoc" --version

if [ -n "${GITHUB_PATH:-}" ]; then
  echo "$cargo_home/bin" >> "$GITHUB_PATH"
  echo "PROTOC=$protoc" >> "$GITHUB_ENV"
else
  echo "export PATH=\"$cargo_home/bin:\$PATH\" PROTOC=\"$protoc\""
fi
