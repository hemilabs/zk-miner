# hemiprove-eth-prelude

The reference guest library for HemiProve `eth-block` (scheme 1) witness jobs: the code a risc0
guest links to check a witness `W` it does not trust, and the codec a witness builder uses to write
it. Design: zkminer `docs/witness-construction-jobs.md` §8 (soundness for guest and prelude
authors) and §12 (the worked example).

**Status: not audited.** Plan §21.1 item 4 holds: no mainnet serving of jobs whose guests link this
crate until it is.

`no_std` with `alloc`; one dependency (`tiny-keccak`, software keccak). The same code runs in a
risc0 guest (`riscv32im-risc0-zkvm-elf`), a wasm32 builder and on the host; feature `std` adds
`std::error::Error` impls.

| module | what it checks |
|---|---|
| `rlp` | Canonical RLP only: no single byte below `0x80` wrapped as a string, no long form for short payloads, no leading zeros in lengths or integers, nothing past an item or after the top-level item. One encoding per value. |
| `header` | Headers with 15 (Berlin), 16 (London), 17 (Shanghai), 20 (Cancun) or 21 (Prague) fields, Ethereum and OP Stack (Base and Hemi carry all 21 since Isthmus). Every field its exact size; any other field count refused, so a fork that appends a field fails closed until a release knows it. `decode_with_hash`: the header hashes to the expected block hash. |
| `mpt` | Merkle-Patricia proofs, inclusion and exclusion. The root node hashes to the root; every later node is reached through a 32-byte hash in its parent, hashes to it and is at least 32 bytes; embedded children are lists under 32 bytes, walked in place; branches have an empty value and at least two children; hex-prefix paths have a zero pad nibble; extensions are non-empty and lead to a branch; leaves have non-empty values; the walk ends at an empty child, a leaf or a diverging extension and **every proof node is used exactly once**; the empty trie has exactly one proof, no nodes. |
| `state` | Accounts (`[nonce, balance, storageRoot, codeHash]`) and storage slots (RLP inside the leaf string: a non-zero integer of at most 32 bytes, no leading zeros, left-padded). An absent account is proven by exclusion and reads as nonce 0, balance 0, storage root `EMPTY_ROOT` (so every slot reads 0, and only the empty proof is accepted under it), no code. `extcodehash`: `EXTCODEHASH` semantics, 0 when absent or empty under EIP-161 (nonce 0, balance 0, no code, whatever its storage: an account a genesis allocation or a devnet's state edit left in the trie), `keccak("")` for any other account without code. |
| `receipt` | EIP-2718 receipts: legacy, 0x01–0x04 and the OP deposit type 0x7E with `depositNonce` (Regolith) and `depositReceiptVersion` (Canyon); status 0, 1 or a pre-Byzantium post-state root; at most four topics; `logs_bloom` and `bloom_matches`. The receipts trie is keyed by `rlp(txIndex)`. |
| `tx` | EIP-2718 transactions: legacy (27/28 or EIP-155 `v`), 0x01, 0x02, 0x03 (recipient and at least one blob), 0x04 (recipient and at least one authorization), 0x7E deposits; the transaction hash. **No sender recovery** (see the gaps). |
| `anchor` | Plan §8.5's anchor 1 (the header hashes to a pinned hash) and anchor 2 (walk `parentHash` back from a pinned later block, numbers decreasing by one). |
| `guard` | `Pinned`, `Authenticated`, `constant!`, `indices`, `JournalWriter`, `split_prefixed`: below. |
| `scheme1` | The scheme-1 `W` format, its strict codec, the guest's `Reader`, and the structural mutations requester tooling applies. |

## The guards (plan §8.3, "commit what you checked")

A guest built on `scheme1::Reader` can put into its journal, and use as a trie key or a selection,
only:

- **`Pinned<T>`**: a journal-header word read from `W` (`Reader::pin_*`). The binding pins the
  header, so a pinned value is the requester's whatever `W` claims. Not `Clone`; committed by
  `JournalWriter::commit_pinned`, which takes the words in header order, each once.
- **`Authenticated<T>`**: a value a verifier produced (`Reader::block_header`, `parent_header`,
  `account`, `storage`, `receipt`, `transaction`, and the module-level `prove_*` functions), a
  pinned value (`Pinned::authenticated`), a guest constant (`constant!(T = expr)`, which only
  compiles for a constant expression of an `AuthValue` type: byte arrays, integers, `bool` and this
  crate's own types, nothing with interior mutability), a counter below an authenticated count
  (`indices`), or a function of those (`map`, `derive`, `zip`, `try_map`, `into_items`). The
  derivations take plain `fn` pointers, so a closure that captures a value from `W` does not
  compile into one.

Neither type has a public constructor from a runtime value. Verifiers take their keys as
`Authenticated` values, so a trie key cannot come from `W`; `JournalWriter::output` takes only
`Authenticated` values of a `ToWord` type, after the whole header. `AuthValue` and `ToWord` are
sealed: a guest cannot add a type that could be changed after the fact or write what it likes. The
doc tests of `guard` (`compile_fail`) pin each of these. `Reader::finish(journal)` returns the journal bytes only when every
header word was committed and every header, account, storage, receipt and transaction proof in `W`
was read; the guest commits them with one `env::commit_slice`. A failure anywhere is an `Err` the
guest turns into a panic: no journal, no proof (plan §8.2).

`Reader::new` is the prelude's entry check (plan §8.3, "wrong prelude"): `W` must start with the
magic `HPW`, scheme 1 and format version 1, and its header word 0 must be the scheme id 1, or
nothing is read.

What the types do not stop: a `fn` pointer does not capture, but it can still read a `static`, a
`thread_local!` or a `Cell` the guest filled from `W` or from a host input, and a guest can
deliberately call `map` with a function returning a constant it made up, or use `Pinned::word`
bytes as data. The guest lints refuse `static`, `thread_local`, `Cell` and `RefCell` (with the host
inputs) in a guest's sources (`reference/proxy-slots/methods/tests/guest_lints.rs`). The types make
accidents hard, not malice; an audit of the guest still reads every derivation.

## The scheme-1 witness (`scheme1`)

```text
W        = "HPW" ‖ scheme (u8 = 1) ‖ version (u8 = 1)
           ‖ nWords (u16, 1..=1022) ‖ nWords × word (32)   journal-header words; word 0 = 1
           ‖ nHeaders (u32) ‖ nHeaders × bytes              RLP headers
           ‖ nAccounts (u32) ‖ nAccounts × account
           ‖ nReceipts (u32) ‖ nReceipts × proof
           ‖ nTxs (u32) ‖ nTxs × proof
account  = proof ‖ nSlots (u32) ‖ nSlots × proof           account proof, then its storage proofs
proof    = kind (u8: 0 inclusion, 1 exclusion) ‖ nNodes (u32) ‖ nNodes × bytes
bytes    = len (u32, ≥ 1) ‖ len bytes
```

Big-endian integers, nothing after the last section: a `W` that decodes re-encodes to the same
bytes. `W` carries **no keys and no values**: the guest computes every trie key from pinned or
authenticated values and takes every value from a verified leaf. Its only claims are the header
words (pinned by the binding) and each proof's kind (checked against what the proof shows). Items
are consumed in the order the guest asks for them; each statement documents its order.

### For requester tooling

`Witness::decode`/`encode` (borrowing; `into_owned` detaches), `is_scheme1`, and:

- `Mutation`: one structural change: a header-word, header or node byte flipped; a header replaced
  (the parent, the next block's, another chain's) or dropped; a node dropped or inserted; a proof's kind
  flipped; a proof replaced, swapped with another, dropped or duplicated; bytes appended or the
  encoding truncated. `ProofRef` names a proof (`Account(a)`, `Storage { account, slot }`,
  `Receipt(i)`, `Transaction(i)`).
- `Witness::mutate(&Mutation) -> Vec<u8>`: the mutated `W`'s encoding.
- `Witness::standard_mutations(ByteSelection)`: plan §21.1's per-scheme set that needs nothing from
  outside `W` (add `ReplaceHeader` with the parent's or the next block's header from the chain).
  It lists every mutation at once; zkminer's `simulate --adversarial` makes the same set lazily
  (`ByteSelection::positions` is public for that).
- `judge(honest_journal, mutated_journal_or_none, pinned_len) -> Verdict`: `Rejected`,
  `Identical`, `BindingRejects` (the pinned prefix and header differ, so the binding refuses it), or
  `Unsound` (same pinned bytes, different outputs: a bug in the guest or the prelude).

## Tests

```sh
cargo test -p hemiprove-eth-prelude
```

- Unit tests next to each module, cross-checked against alloy-rlp, alloy-trie (random tries with
  hashed and raw keys, so extensions and embedded nodes occur) and alloy-consensus (every header
  variant, every receipt and transaction type).
- `tests/real_chains.rs`: Ethereum mainnet, Base and Hemi blocks fetched by
  `tests/fixtures/fetch.sh` (raw JSON-RPC results, committed): every header (and Ethereum's Berlin,
  London, Shanghai and Cancun layouts) hashes to its block; every account and storage proof
  verifies, present and absent; receipts and transactions rebuild their block's roots, deposits
  included; every byte flip of a real account and storage proof is rejected.
- `tests/no_panics.rs`: arbitrary and mutated inputs through every decoder: no panic, and whatever
  is accepted re-encodes to the bytes read.

## Known gaps

- **Sender recovery** for signed transactions (secp256k1 under the pinned chain id, per type, low-s)
  is not implemented. A statement that names a sender must not use this crate's `tx` until it is;
  deposits' `from` is set by L1 derivation, not a signature.
- **Anchor 3** (consensus verification in the guest) is not implemented.
- **No trie builder**: a builder that needs a receipts-trie proof must build the trie itself from
  `eth_getBlockReceipts` (the prelude encodes the receipts).
- **Software keccak** only: the risc0 keccak accelerator would cut cycles on large witnesses but
  adds keccak proof requests; about 180 cycles per byte of `W` today.
- Header layouts past Prague are refused until a release adds them.
