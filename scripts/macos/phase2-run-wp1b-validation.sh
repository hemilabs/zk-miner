#!/bin/sh
# Source-bound WP1b correctness ladder after the paired campaign.
set -eu

MINER=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
ENGINE=/Users/dbur/dev/risc0
COMMIT=7222459e351a81ecb55ac75f8804edc4c51e08d9
PHASE="$MINER/target/macos/phase2"
cd "$MINER"
. "$MINER/scripts/macos/env.sh"
export CARGO_NET_OFFLINE=true ZKMINER_MACOS_HOST_RESERVE_GIB=8

python3 "$ENGINE/risc0/circuit/rv32im-sys/kernels/cuda/evalfast/regen.py" --check \
    > "$PHASE/wp1b-final-generator-check.log" 2>&1

for po2 in 14 18 20; do
    python3 scripts/macos/test-native-worker.py --engine "$ENGINE" \
        --worker-kind native-rv32im-metal --segment-hal metal --segment-check-cpu \
        --recursion-hal metal --workload segment-boundary --iterations 8 \
        --po2 "$po2" --repeat 1 --proof-only --rayon-threads 18 \
        --go-threads 18 --timeout-seconds 1800 \
        > "$PHASE/wp1b-final-real-po2-$po2.log" 2>&1
done

python3 scripts/macos/test-native-worker.py --engine "$ENGINE" \
    --worker-kind native-rv32im-metal --segment-hal metal --recursion-hal metal \
    --workload segment-boundary --iterations 8 --po2 14 --repeat 20 \
    --rayon-threads 18 --go-threads 18 --timeout-seconds 1800 \
    --failure-timeout-seconds 20 > "$PHASE/wp1b-final-lifecycle.log" 2>&1

RISC0_RV32IM_TAIL_SPLIT=1 python3 scripts/macos/test-native-worker.py \
    --engine "$ENGINE" --worker-kind native-rv32im-metal --segment-hal metal \
    --segment-check-cpu --recursion-hal metal --workload segment-boundary \
    --iterations 8 --po2 14 --repeat 1 --proof-only \
    --rayon-threads 18 --go-threads 18 --timeout-seconds 1800 \
    > "$PHASE/wp1b-final-fallback-proof.log" 2>&1

python3 scripts/macos/test-native-worker.py --engine "$ENGINE" \
    --worker-kind native-rv32im-metal --segment-hal metal --recursion-hal metal \
    --workload segment-boundary --iterations 8 --po2 14 --repeat 1 \
    --proof-only --limit-controls > "$PHASE/wp1b-final-limit-controls.log" 2>&1

python3 scripts/macos/build-worker.py --mode cpu --tests --engine "$ENGINE" \
    --config "$PHASE/wp1b-engine.toml" --revision "$COMMIT" \
    > "$PHASE/wp1b-final-cpu-build.log" 2>&1

sh scripts/macos/phase2-run-wp1b-linux.sh \
    > "$PHASE/wp1b-final-linux.log" 2>&1
python3 scripts/macos/phase2-collect-wp1b-validation.py
