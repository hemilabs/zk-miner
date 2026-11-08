#!/bin/sh
# Build only the isolated differential harness; never installs Xcode/components.
set -eu
engine=${1:?usage: build-metal.sh ENGINE_DIR REVIEWED_ENGINE_SHA}
revision=${2:?pass the full reviewed engine commit SHA}
HEMI_MINER_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
export HEMI_MINER_DIR
. "$HEMI_MINER_DIR/scripts/macos/env.sh"
cd "$HEMI_MINER_DIR"
[ "$(uname -m)" = arm64 ] && [ "$(uname -s)" = Darwin ] || { echo 'Apple Silicon macOS required' >&2; exit 1; }
python3 scripts/macos/local-engine.py "$engine" target/macos/metal-engine.toml --revision "$revision"
python3 scripts/macos/metal_provenance.py snapshot "$engine"
cargo +1.93.0 build --locked --release --manifest-path tools/macos-metal/Cargo.toml \
    --config target/macos/metal-engine.toml --target-dir target/macos/metal
cargo +1.93.0 metadata --locked --filter-platform aarch64-apple-darwin \
    --manifest-path tools/macos-metal/Cargo.toml --config target/macos/metal-engine.toml \
    --format-version 1 > target/macos/metal-metadata.json
python3 scripts/macos/check-source.py target/macos/metal-metadata.json --engine "$engine" --metal-runtime
cargo +1.93.0 tree --locked --target aarch64-apple-darwin --edges features \
    --manifest-path tools/macos-metal/Cargo.toml --config target/macos/metal-engine.toml \
    > target/macos/metal-tree.txt

python3 scripts/macos/metal_provenance.py seal "$engine"
