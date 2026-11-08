#!/bin/sh
# Source-bound WP8-lite correctness and lifecycle checks after the paired campaign.
set -eu

MINER=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
ENGINE=/Users/dbur/dev/risc0
COMMIT=6521f87c2daf873c54d011a33d48fee8097db924
PHASE="$MINER/target/macos/phase2"
cd "$MINER"
. "$MINER/scripts/macos/env.sh"
export CARGO_NET_OFFLINE=true ZKMINER_MACOS_HOST_RESERVE_GIB=8
export PROTOC="$MINER/target/macos/bootstrap/protoc-36.2/bin/protoc"
export RECURSION_SRC_PATH="$MINER/target/macos/worker-native-rv32im-metal/release/build/risc0-circuit-recursion-dfe0b3f83c486430/out/recursion_zkr.zip"

for po2 in 14 18 20; do
    python3 scripts/macos/test-native-worker.py --engine "$ENGINE" \
        --worker-kind native-rv32im-metal --segment-hal metal --segment-check-cpu \
        --recursion-hal metal --workload segment-boundary --iterations 8 \
        --po2 "$po2" --repeat 1 --proof-only --rayon-threads 18 \
        --go-threads 18 --timeout-seconds 1800 \
        > "$PHASE/wp8lite-real-po2-$po2.log" 2>&1
done

python3 scripts/macos/test-native-worker.py --engine "$ENGINE" \
    --worker-kind native-rv32im-metal --segment-hal metal --recursion-hal metal \
    --workload segment-boundary --iterations 8 --po2 14 --repeat 20 \
    --rayon-threads 18 --go-threads 18 --timeout-seconds 1800 \
    --failure-timeout-seconds 28 > "$PHASE/wp8lite-lifecycle.log" 2>&1

python3 scripts/macos/test-native-worker.py --engine "$ENGINE" \
    --worker-kind native-rv32im-metal --segment-hal metal --recursion-hal metal \
    --workload segment-boundary --iterations 8 --po2 14 --repeat 1 \
    --proof-only --limit-controls > "$PHASE/wp8lite-limit-controls.log" 2>&1

python3 scripts/macos/phase2-test-wp8lite-parent-death.py \
    > "$PHASE/wp8lite-parent-death.log" 2>&1

python3 scripts/macos/build-worker.py --mode cpu --tests --engine "$ENGINE" \
    --config "$PHASE/wp8lite-engine.toml" --revision "$COMMIT" \
    > "$PHASE/wp8lite-cpu-build.log" 2>&1

sh scripts/macos/phase2-run-wp8lite-linux.sh \
    > "$PHASE/wp8lite-linux.log" 2>&1
python3 scripts/macos/phase2-collect-wp8lite-validation.py
