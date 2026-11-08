#!/bin/sh
set -eu
HEMI_MINER_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
export HEMI_MINER_DIR
. "$HEMI_MINER_DIR/scripts/macos/env.sh"
cd "$HEMI_MINER_DIR"
project="$HEMI_MINER_DIR/target/macos/unchanged-verifier"
mkdir -p "$project/src"
cp tools/macos-proof/Cargo.toml "$project/Cargo.toml"
cp tools/macos-proof/src/main.rs "$project/src/main.rs"
# This standalone lock retains the root lock's external package versions and pinned Git source.
cp tools/macos-proof/Verifier.Cargo.lock "$project/Cargo.lock"
# No --config and no `prove`: original Git engine and no local patches.
python3 scripts/macos/proof_provenance.py snapshot verifier
cargo +1.93.0 build --locked --release --manifest-path "$project/Cargo.toml" \
    --target-dir "$HEMI_MINER_DIR/target/macos/verifier"
cargo +1.93.0 metadata --locked --filter-platform aarch64-apple-darwin \
    --manifest-path "$project/Cargo.toml" --format-version 1 \
    > target/macos/verifier-metadata.json
python3 scripts/macos/check-source.py target/macos/verifier-metadata.json --unchanged-verifier

python3 scripts/macos/proof_provenance.py seal verifier
