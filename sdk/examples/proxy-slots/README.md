# proxy-slots builder

The reference witness builder (type 1, ABI v1) of zkminer `docs/witness-construction-jobs.md`
§12.2, for the guest in `../../../reference/proxy-slots/` (whose README documents the statement,
the journal, the binding and `W`).

`builderParams` = `abi.encode(uint64 chainId, bytes32 B, address C, bytes32 R, uint64 k)`;
capability 0 must be `evm-rpc/v1` for `chainId`, method set `state-read`, provisioned with proofs at
least as deep as the head is past `B` (`maxProofAge`: many public nodes serve `eth_getProof` only
near the tip: two public Base endpoints refused `eth_getProof` at the finalized block on 2026-11-17).

What it fetches (4 requests, all pinned to `{"blockHash": B}` where the method takes a block):

1. `eth_getBlockByHash(B, false)`: the header, RLP-encoded with the prelude's encoder; refused unless
   it hashes to `B`.
2. `eth_getStorageAt(C, 0x3608…2bbc, B)`: the implementation `I`, a hint.
3. `eth_getProof(C, [0x3608…2bbc, slots of R for I…], B)`: the slot set from the guest's own rule.
4. `eth_getProof(I, [], B)`.

It writes the scheme-1 `W` with the guest's own codec, each proof's kind as the proof shows it (an
empty-trie proof served as `["0x80"]` normalised to `[]`), after running the guest's statement over
it: a node that lies fails the builder, with the reason in the log, instead of the guest.

Nothing it receives is trusted, and nothing it does needs to be: the guest re-derives `I` and the
slot set and verifies every proof against the pinned `B`.

## Building

```sh
cd sdk
./build-reproducible.sh -p proxy-slots-builder   # alone: see the SDK README on feature unification
sha256sum target/wasm32-unknown-unknown/release/proxy_slots_builder.wasm
```

`c39381f5d49e24e4eaa7340e3db2a7931321d16c04261b21e4fb25ae71fd37f6` (99,093 bytes) on the pinned
toolchain, from two clean target dirs and from a copy of the tree elsewhere. It shares the prelude
and the statement with the guest through the SDK's `reference` symlink, which keeps their source
paths under the SDK directory, where the build's path remapping rewrites them (see the SDK README,
"Shared code").

Limits it needs: 4 fetches; responses of a few tens of KB per proof on a large chain; the module
has 17 initial memory pages (1.06 MiB), so `maxBuilderMemoryBytes` of 16 MiB leaves ample heap;
`W` is about 3 KB on anvil and 17–26 KB on Ethereum, Base and Hemi for `k` of 3 to 6.

## Tested

`reference/proxy-slots/methods/tests/anvil_e2e.rs` runs it in the real runner binary behind the
real broker binary (both sandboxed, developer mode) against a proxy on anvil, then proves over its
`W` on the risc0 executor.
