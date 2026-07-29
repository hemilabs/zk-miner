#!/bin/bash
# Infinite job submitter for the Hemi testnet HemiProve market. Rotates through
# several small RISC Zero guest types, submitting one job per iteration from the
# submitter account. Each job is a small single-segment proof (fast + safe).
#
#   examples/testnet_submitter.sh            # loop forever, ~45s between jobs
#   SUBMIT_INTERVAL=20 examples/testnet_submitter.sh
set -u

RPC="${RPC_URL:-https://testnet.rpc.hemi.network/rpc}"
SUBMITTER_KEY="${SUBMITTER_KEY:?export SUBMITTER_KEY before running - never commit it}"
export HEMI_PROVE=0x889B967eD85246271122b50d1A2bda1f250683c8
export HEMI_TOKEN=0x0E6CeC5992A0c5B748F67Ec990D750AbaD7098e2
export NUM_JOBS=1
INTERVAL="${SUBMIT_INTERVAL:-45}"

# This forge-script submitter needs the HemiProve Foundry project, which is NOT
# part of this repository (it lives in the contracts repo). Point CONTRACTS_DIR at
# a checkout of it, or use examples/testnet_submitter_cast.sh, which needs only
# `cast` and targets the current market.
CONTRACTS_DIR="${CONTRACTS_DIR:-}"
if [ -z "$CONTRACTS_DIR" ] || [ ! -d "$CONTRACTS_DIR" ]; then
  echo "error: set CONTRACTS_DIR to a HemiProve Foundry checkout (contains foundry.toml)." >&2
  echo "       Alternatively use examples/testnet_submitter_cast.sh (cast-only)." >&2
  exit 1
fi
cd "$CONTRACTS_DIR"

# guest -> true RISC Zero image id (== on-chain programId, must match the ELF the
# miner has cached at ~/.zkminer/elfs/<imageId>.elf)
declare -A IMG=(
  [fibonacci]=0x620aba66e236b019e3aef2cf2d211c889f2f5d56728ee3fd51d0c9c95f32ec0b
  [sha256-chain]=0xa4cc66ecc531f3c8ba667fc16e72688daac0d1a03a0e4f6d8429e417886ba087
  [chacha-mix]=0x871da5ff38dca76a5addc5fed50ccde44cdd8c41f250fe32c4f5e391c8f359e9
  [ecdsa-verify]=0xd52f2cdde3da68ba0c4ef5880b2f5c19d179f6ba2afca125696e18ee6f0f2186
)
# small single-segment inputs (u32 iteration count) -> ~5-15s proofs
declare -A N=( [fibonacci]=5000 [sha256-chain]=200 [chacha-mix]=500 [ecdsa-verify]=1 )
types=(fibonacci sha256-chain chacha-mix ecdsa-verify)

le32() { printf '0x%02x%02x%02x%02x' $(( $1 & 0xff )) $(( ($1>>8)&0xff )) $(( ($1>>16)&0xff )) $(( ($1>>24)&0xff )); }

echo "$(date +%T) submitter loop starting (interval ${INTERVAL}s, ${#types[@]} job types)"
i=0
while true; do
  t=${types[$((i % ${#types[@]}))]}
  if PROGRAM_ID=${IMG[$t]} INPUT_DATA=$(le32 "${N[$t]}") \
       timeout 120 forge script script/SubmitJobsReal.s.sol:SubmitJobsReal \
       --rpc-url "$RPC" --broadcast --private-key "$SUBMITTER_KEY" \
       --legacy --gas-price 3000000000 >/dev/null 2>&1; then
    echo "$(date +%T) submitted #$i  $t (n=${N[$t]})"
  else
    echo "$(date +%T) submit #$i  $t FAILED (will continue)"
  fi
  i=$((i + 1))
  sleep "$INTERVAL"
done
