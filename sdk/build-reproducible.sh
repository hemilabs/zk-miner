#!/bin/sh
# Builds the SDK workspace's modules reproducibly: locked dependencies, the pinned toolchain
# (rust-toolchain.toml), the pinned target features (.cargo/config.toml), and every host path
# remapped, so the bytes (and the builderId = sha256 of them) do not depend on where the source,
# the toolchain or the cargo registry live. Extra arguments go to cargo, e.g. `-p latest-block`.
# The modules land in target/wasm32-unknown-unknown/release/.
set -eu
cd "$(dirname "$0")"
sysroot=$(rustc --print sysroot)
commit=$(rustc -vV | sed -n 's/^commit-hash: //p')
cargo_home=${CARGO_HOME:-$HOME/.cargo}
# Added to (not replacing) the target's rustflags in .cargo/config.toml. RUSTFLAGS would replace
# them, so it must be unset.
unset RUSTFLAGS CARGO_ENCODED_RUSTFLAGS CARGO_BUILD_RUSTFLAGS
export CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUSTFLAGS="\
--remap-path-prefix=$sysroot/lib/rustlib/src/rust=/rustc/$commit \
--remap-path-prefix=$cargo_home=/cargo \
--remap-path-prefix=$PWD=/sdk"
exec cargo build --locked --release --target wasm32-unknown-unknown "$@"
