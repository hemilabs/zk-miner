#!/bin/bash
# Submit calibrated chacha-mix proving jobs to the local HemiProve devnet.
#
#   submit_examples.sh [name ...]
#
# Names: xs (~30s), s (~1min), m (~2.5min), l (~5min). No args = all four.
# Repeat a name to submit multiple copies (e.g. concurrency tests).
#
# Requires: devnet up + addresses in scratchpad/devnet2_addrs.env, the chacha-mix
# ELF cached at ~/.zkminer/elfs/<PROGRAM_ID>.elf, and the miner already polling.
set -euo pipefail

REPO="${REPO:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
ADDRS="${ZKMINER_DEVNET_ADDRS:?set ZKMINER_DEVNET_ADDRS to the devnet address env file}"
RPC="${RPC_URL:-http://127.0.0.1:8545}"
# anvil account 0 (requester / job submitter)
REQUESTER_KEY="${REQUESTER_KEY:-0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80}"

# name -> chacha-mix iteration count (see examples/README.md for the calibration)
declare -A N=( [xs]=16000 [s]=34000 [m]=90000 [l]=182000 )

[ -f "$ADDRS" ] || { echo "addresses file not found: $ADDRS" >&2; exit 1; }
# shellcheck disable=SC1090
source "$ADDRS"   # HEMI_PROVE, HEMI_TOKEN, PROGRAM_ID
: "${HEMI_PROVE:?}" "${HEMI_TOKEN:?}" "${PROGRAM_ID:?}"

names=("$@"); [ ${#names[@]} -eq 0 ] && names=(xs s m l)

# little-endian u32 encoding of the iteration count (the guest reads a u32)
le32() { printf '0x%02x%02x%02x%02x' $(( $1 & 0xff )) $(( ($1>>8)&0xff )) $(( ($1>>16)&0xff )) $(( ($1>>24)&0xff )); }

# The HemiProve Foundry project is not part of this repository; point
# CONTRACTS_DIR at a checkout of the contracts repo.
CONTRACTS_DIR="${CONTRACTS_DIR:-}"
if [ -z "$CONTRACTS_DIR" ] || [ ! -d "$CONTRACTS_DIR" ]; then
  echo "error: set CONTRACTS_DIR to a HemiProve Foundry checkout." >&2
  exit 1
fi
cd "$CONTRACTS_DIR"
export HEMI_PROVE HEMI_TOKEN PROGRAM_ID NUM_JOBS=1
for name in "${names[@]}"; do
  n="${N[$name]:-}"
  [ -z "$n" ] && { echo "unknown example '$name' (use: xs s m l)" >&2; exit 1; }
  job=$(INPUT_DATA=$(le32 "$n") forge script script/SubmitJobsReal.s.sol:SubmitJobsReal \
        --rpc-url "$RPC" --broadcast --private-key "$REQUESTER_KEY" 2>/dev/null \
        | grep -A1 'jobId:' | tail -1 | tr -d ' ')
  printf 'submitted %-2s  n=%-7s  input=%s  job=%s\n' "$name" "$n" "$(le32 "$n")" "${job:0:14}"
done
