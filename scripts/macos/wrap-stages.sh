#!/bin/bash
# Serial stage timing for feasibility only; the production entrypoint overlaps
# witness generation and key loading through a FIFO. Nanoseconds use VM wall
# time; the host runner records an independent monotonic end-to-end duration.
set -euo pipefail
ulimit -s 16384
start=$(date +%s%N)
stark_verify /mnt/input.json /mnt/witness.wtns
witness_end=$(date +%s%N)
prover /app/stark_verify.cs /app/stark_verify_final.pk.dmp /mnt/witness.wtns /mnt/proof.json
prover_end=$(date +%s%N)
printf '{"witness_ns":%s,"prover_including_load_ns":%s,"serial_total_ns":%s}\n' \
    "$((witness_end - start))" "$((prover_end - witness_end))" "$((prover_end - start))" \
    > /mnt/stages.json
