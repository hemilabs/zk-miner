#!/bin/sh
# Run the WP4 non-macOS feature paths in the cached, network-isolated Colima VM.
set -eu

MINER=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
ENGINE=/Users/dbur/dev/risc0
COMMIT=bca7044c5480d0efddcb2a035dd569035d0c8cde
DIRECTORY="$MINER/target/macos/phase2/wp4-linux"

test "$(git -C "$ENGINE" rev-parse HEAD)" = "$COMMIT"
test -z "$(git -C "$ENGINE" status --porcelain)"
mkdir -p "$DIRECTORY/source"
git -C "$ENGINE" archive "$COMMIT" | tar -xf - -C "$DIRECTORY/source"
if [ ! -d "$DIRECTORY/target" ]; then
    cp -cR "$MINER/target/macos/phase2/wp5-linux/target" "$DIRECTORY/target"
fi

run_check() {
    name=$1
    package=$2
    features=$3
    docker run --rm --network none \
        -v "$DIRECTORY/source:/work/risc0" \
        -v "$DIRECTORY/target:/work/target" \
        -v "$MINER/target/macos/toolchain/cargo:/work/cargo" \
        -v "$MINER/target/macos/phase2/wp05-linux/recursion_zkr.zip:/work/recursion_zkr.zip:ro" \
        -e CARGO_HOME=/work/cargo -e CARGO_TARGET_DIR=/work/target \
        -e CARGO_NET_OFFLINE=true -e RUSTUP_TOOLCHAIN=1.93.1 \
        -e RECURSION_SRC_PATH=/work/recursion_zkr.zip \
        -w /work/risc0 rust:1.93-trixie \
        sh -c "rustc --version && cargo check --offline --locked -p $package --features $features" \
        > "$DIRECTORY/$name.log" 2>&1
}

run_check recursion risc0-circuit-recursion prove,metal
run_check rv32im risc0-circuit-rv32im prove
run_check zkvm risc0-zkvm prove,metal-recursion
python3 "$MINER/scripts/macos/phase2-collect-wp4-linux.py"
