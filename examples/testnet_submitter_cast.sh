#!/bin/bash
# Cast-based job submitter for the Hemi testnet HemiProve market (2026-07-14 deploy).
# Submits the correct 9-field JobDescriptor via `submitJob` directly with `cast`
# (the forge-script submitter compiled against stale 8-field source and reverts).
# Rotates through several cached RISC Zero guests; each job is a small single-
# segment proof the local miner claims + proves + fulfills.
#
#   examples/testnet_submitter_cast.sh              # loop forever, ~45s between jobs
#   SUBMIT_INTERVAL=20 examples/testnet_submitter_cast.sh
set -u

RPC="${RPC_URL:-https://testnet.rpc.hemi.network/rpc}"
SUBMITTER_KEY="${SUBMITTER_KEY:?export SUBMITTER_KEY before running - never commit it}"
HEMI_PROVE="0x9ce16C8e61BFe6f1a86965f3B22C48562E82Cf76"
HEMI_TOKEN="0xe5040F6917C942efDE65AC47d8019095fD6DdDEc"
PSID=$(cast keccak "risczero.v1")   # RISC0 proofSystemId (adapter registered under this)
INTERVAL="${SUBMIT_INTERVAL:-45}"
# EIP-1559: 2 gwei max-fee + 2 gwei priority tip (testnet prioritises tipped txs;
# legacy txs can stall). Override with MAX_FEE_WEI / PRIORITY_WEI.
# --gas-limit skips this testnet's flaky eth_estimateGas (which intermittently reverts
# a perfectly valid submitJob); submitJob writes the 27-field Job struct + auction, ~600k.
GP="--gas-price ${MAX_FEE_WEI:-2000000000} --priority-gas-price ${PRIORITY_WEI:-2000000000} --gas-limit ${GAS_LIMIT:-1000000}"
Z32="0x0000000000000000000000000000000000000000000000000000000000000000"
Z20="0x0000000000000000000000000000000000000000"

# guest -> RISC Zero image id (== on-chain programId; ELF cached at ~/.zkminer/elfs/<id>.elf)
declare -A IMG=(
  [fibonacci]=0x620aba66e236b019e3aef2cf2d211c889f2f5d56728ee3fd51d0c9c95f32ec0b
  [sha256-chain]=0xa4cc66ecc531f3c8ba667fc16e72688daac0d1a03a0e4f6d8429e417886ba087
  [chacha-mix]=0x871da5ff38dca76a5addc5fed50ccde44cdd8c41f250fe32c4f5e391c8f359e9
  [ecdsa-verify]=0xd52f2cdde3da68ba0c4ef5880b2f5c19d179f6ba2afca125696e18ee6f0f2186
)
declare -A N=( [fibonacci]=5000 [sha256-chain]=200 [chacha-mix]=500 [ecdsa-verify]=1 )
types=(fibonacci sha256-chain chacha-mix ecdsa-verify)

# little-endian u32 hex (guest reads inputData as a u32 iteration count)
le32() { printf '0x%02x%02x%02x%02x' $(( $1 & 0xff )) $(( ($1>>8)&0xff )) $(( ($1>>16)&0xff )) $(( ($1>>24)&0xff )); }

# One-time: approve the router to pull the per-job HEMI deposit (maxPrice).
echo "$(date +%T) approving HEMI -> HemiProve ..."
cast send --rpc-url "$RPC" --private-key "$SUBMITTER_KEY" $GP "$HEMI_TOKEN" \
  'approve(address,uint256)' "$HEMI_PROVE" 1000000000000000000000000 >/dev/null 2>&1 \
  && echo "  approved" || echo "  approve failed (already approved?)"

# AuctionConfig: minPrice 50 HEMI, maxPrice 100 HEMI, 30s ramp, 2h timeout, no collateral/cycle/bid.
AUCTION="(50000000000000000000,100000000000000000000,30,0,7200,0,0,0,0,false,false)"
CYCLE="(0,0,0,0,0,0,0,0)"
BID="(0,0,0,0,0)"

echo "$(date +%T) submitter loop starting (interval ${INTERVAL}s, ${#types[@]} job types)"
i=0
while true; do
  t=${types[$((i % ${#types[@]}))]}
  prog=${IMG[$t]}
  input=$(le32 "${N[$t]}")
  desc="($prog,$PSID,$Z20,$Z20,$Z32,$input,0x,0x,$Z32)"
  if cast send --async --rpc-url "$RPC" --private-key "$SUBMITTER_KEY" $GP "$HEMI_PROVE" \
       'submitJob((bytes32,bytes32,address,address,bytes32,bytes,bytes,bytes,bytes32),(uint96,uint96,uint40,uint8,uint40,uint96,uint96,uint40,uint32,bool,bool),(uint64,uint96,uint8,uint16,uint16,uint16,uint16,uint16),(uint40,uint40,uint40,uint96,uint8))(bytes32)' \
       "$desc" "$AUCTION" "$CYCLE" "$BID" >/dev/null 2>&1; then
    echo "$(date +%T) submitted #$i  $t (n=${N[$t]})"
  else
    echo "$(date +%T) submit #$i  $t FAILED (will continue)"
  fi
  i=$((i + 1))
  sleep "$INTERVAL"
done
