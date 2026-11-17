#!/bin/sh
# Refetches the real-chain fixtures the tests read. The tests never run it: the JSON it writes is
# committed, so the tests are offline and the vectors fixed. Each file holds the raw JSON-RPC results
# for one block, as a node returned them, so every test decodes and re-encodes them independently:
#
#   block           eth_getBlockByNumber(n, false)
#   parent          eth_getBlockByHash(block.parentHash, false)
#   proofs[]        {address, slots, proof: eth_getProof(address, slots, n)}
#   receipts        eth_getBlockReceipts(n)              (unless SKIP_RECEIPTS=1)
#   rawTransactions eth_getRawTransactionByBlockNumberAndIndex(n, i) for every i
#   headers[]       {number, block: eth_getBlockByNumber(number, false)} for older header variants
#
# Usage: [BLOCK=0x…] fetch.sh OUT.json RPC RAW_RPC "ADDRESS[:SLOT,SLOT…] …" ["OLD_BLOCK …"]
#   RAW_RPC serves eth_getRawTransactionByBlockNumberAndIndex (some public RPCs filter it).
# Needs curl and jq.
set -eu

out=$1
rpc_url=$2
raw_url=$3
accounts=$4
old_blocks=${5:-}

call() { # URL METHOD PARAMS-JSON; public endpoints rate-limit, so up to five attempts
    for attempt in 1 2 3 4 5; do
        if curl -sf --max-time 120 -H 'content-type: application/json' \
            -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$2\",\"params\":$3}" "$1" | jq -ce '.result'; then
            return 0
        fi
        sleep "$attempt"
    done
    echo "fetch.sh: $2 on $1 failed" >&2
    return 1
}

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

chain=$(call "$rpc_url" eth_chainId '[]' | jq -r .)
block=$(call "$rpc_url" eth_getBlockByNumber "[\"${BLOCK:-finalized}\",false]")
number=$(printf '%s' "$block" | jq -r .number)
hash=$(printf '%s' "$block" | jq -r .hash)
parent_hash=$(printf '%s' "$block" | jq -r .parentHash)
printf '%s' "$block" >"$tmp/block.json"
call "$rpc_url" eth_getBlockByHash "[\"$parent_hash\",false]" >"$tmp/parent.json"

echo '[]' >"$tmp/proofs.json"
for spec in $accounts; do
    address=${spec%%:*}
    slots='[]'
    if [ "$spec" != "$address" ]; then
        slots=$(printf '%s' "${spec#*:}" | jq -Rc 'split(",")')
    fi
    call "$rpc_url" eth_getProof "[\"$address\",$slots,\"$number\"]" >"$tmp/proof.json"
    jq -c --arg a "$address" --argjson s "$slots" --slurpfile p "$tmp/proof.json" \
        '. + [{address: $a, slots: $s, proof: $p[0]}]' "$tmp/proofs.json" >"$tmp/proofs.next"
    mv "$tmp/proofs.next" "$tmp/proofs.json"
done

if [ "${SKIP_RECEIPTS:-0}" = 1 ]; then
    echo null >"$tmp/receipts.json"
else
    call "$rpc_url" eth_getBlockReceipts "[\"$number\"]" >"$tmp/receipts.json"
fi

count=$(printf '%s' "$block" | jq '.transactions | length')
echo '[]' >"$tmp/raw.json"
i=0
while [ "$i" -lt "$count" ]; do
    raw=$(call "$raw_url" eth_getRawTransactionByBlockNumberAndIndex "[\"$number\",\"$(printf '0x%x' "$i")\"]")
    jq -c --argjson r "$raw" '. + [$r]' "$tmp/raw.json" >"$tmp/raw.next"
    mv "$tmp/raw.next" "$tmp/raw.json"
    i=$((i + 1))
done

echo '[]' >"$tmp/headers.json"
for n in $old_blocks; do
    call "$rpc_url" eth_getBlockByNumber "[\"$(printf '0x%x' "$n")\",false]" >"$tmp/old.json"
    jq -c --argjson n "$n" --slurpfile b "$tmp/old.json" '. + [{number: $n, block: $b[0]}]' "$tmp/headers.json" \
        >"$tmp/headers.next"
    mv "$tmp/headers.next" "$tmp/headers.json"
done

jq -n --arg chain "$chain" --arg number "$number" --arg hash "$hash" \
    --slurpfile block "$tmp/block.json" --slurpfile parent "$tmp/parent.json" \
    --slurpfile proofs "$tmp/proofs.json" --slurpfile receipts "$tmp/receipts.json" \
    --slurpfile raw "$tmp/raw.json" --slurpfile headers "$tmp/headers.json" \
    '{chainId: $chain, number: $number, hash: $hash, block: $block[0], parent: $parent[0], proofs: $proofs[0],
      receipts: $receipts[0], rawTransactions: $raw[0], headers: $headers[0]}' >"$out"
echo "$out: chain $chain block $number ($hash), $count transactions"
