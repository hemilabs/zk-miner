#!/bin/sh
# Source this file from the miner repository; no global installation is required.
MACOS_MINER_DIR=${HEMI_MINER_DIR:-$(pwd)}
if [ ! -f "$MACOS_MINER_DIR/crates/zkminer-prove-risc0/Cargo.toml" ]; then
    echo 'Source env.sh from the miner root, or set HEMI_MINER_DIR explicitly.' >&2
    return 1
fi
export CARGO_HOME="$MACOS_MINER_DIR/target/macos/toolchain/cargo"
export RUSTUP_HOME="$MACOS_MINER_DIR/target/macos/toolchain/rustup"
export RISC0_HOME="$MACOS_MINER_DIR/target/macos/toolchain/risc0"
export PATH="$CARGO_HOME/bin:$PATH"
export CARGO_BUILD_JOBS=6
export RAYON_NUM_THREADS="${ZKMINER_RISC0_CPU_THREADS:-${RAYON_NUM_THREADS:-18}}"
