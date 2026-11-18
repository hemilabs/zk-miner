# proxy-slots: the reference statement, guest and builder of plan §12

"At block `B`, proxy `C`'s EIP-1967 implementation is `I` (code hash `H`), and the `k` slots rule
`R` names hold `V1..Vk`." zkminer `docs/witness-construction-jobs.md` §12.

| path | what |
|---|---|
| `statement/` | `hemiprove-proxy-slots`: the statement as one function, `run(input) -> journal`, plus the requester's helpers. `no_std`; shared by the guest, the builder and tooling. |
| `guest/` | the risc0 guest: reads its input, runs the statement, commits the journal with one `commit_slice` or panics. Its own workspace and lockfile, like every guest in this repository, on risc0-zkvm 3.1.0 (see "The risc0 version"). |
| `methods/` | builds the guests with risc0-build; the executor, end-to-end, lint, keccak-batch and `simulate --adversarial` tests; `examples/export-guest.rs` writes a guest's program binary and prints its image id. |
| `lint-control/` | a guest that does everything the lints forbid, so the lint checks are shown to catch it. Never deployed. |
| `hostdep/` | a test guest whose journal depends on host inputs (`sys_rand`, the keccak po2) or echoes `W`, for `simulate --adversarial`'s tests, and runs keccak through the batcher. Never deployed. |
| `keccak-3-0/` | a control still on risc0-zkvm 3.0.5, which the miner must refuse (see "The risc0 version"). Never deployed. |
| `check-guest-lints.sh` | clippy with `guest/clippy.toml` for the zkVM target. |
| `../../sdk/examples/proxy-slots/` | the builder (type 1, wasm32). |

## The statement

**The journal** (a journal-prefix job, plan §7.2):

| offset | bytes | |
|---|---|---|
| 0 | 64 | `abi.encode(jobId, prover)`, copied from the input |
| 64 | 160 | **header**, pinned: `schemeId = 1`, `B`, `C` (left-padded), `R`, `k` (≤ 255) |
| 224 | 32 | `I`: the low 20 bytes of `C`'s slot `0x3608…2bbc`, as the proxy itself reads it |
| 256 | 32 | `H`: `EXTCODEHASH(I)` (0 if `I` has no account or one that is empty under EIP-161, `keccak("")` if it has no code) |
| 288 | 64 × k | `(slot, value)` in rule order; an unset slot reads 0 |

**The binding:** `journalFields = 0xffffffff ‖ 0x000000a0 ‖ 0…` (the prefix marker, then 160 bytes at
offset 0 of the statement); `expectedJournalHash = keccak256(header)`. `Statement::journal_fields`,
`header`, `expected_journal_hash` compute them from the requester's own parameters; zkminer's
`binding::journal_fields_for_header(160, true)` and `expected_journal_hash` give the same, and
`binding::mutation_check` passes (the end-to-end test checks all three).

**The rule `R`**: byte 0 is the rule id, bytes 1..32 a 248-bit parameter `p`:

- `0x01` consecutive: `C`'s slots `p … p + k − 1`;
- `0x02` mapping by implementation: the `k` words of `mapping(address => T)` at slot `p` under key
  `I`, i.e. `keccak256(pad32(I) ‖ pad32(p)) + j`. The slot set exists only once `I` is proven.

Any other id fails.

**`builderParams`** = `abi.encode(uint64 chainId, bytes32 B, address C, bytes32 R, uint64 k)`
(`Statement::builder_params`). Plan §12.1 writes `abi.encode(8453, B, C)`; the builder also needs
`R` and `k`, which it writes into `W`'s header words. `builderParams` bind nothing: the header does.

**`W`** (scheme 1, `hemiprove_eth_prelude::scheme1`): the five header words; headers `[header(B)]`
(anchor 1: `B` is pinned); accounts `C` (storage proofs: the EIP-1967 slot, then the `k` rule slots
in order) and `I` (none); no receipts or transactions.

**What the guest proves, step by step** (`statement/src/lib.rs`, `run`): the prefix is split off;
`Reader::new` checks magic, scheme, version and word 0; exactly five header words; each pinned and
committed in order (`B` raw, `C` an address word, `R` a known rule, `k` ≤ 255); the header hashes
to `B`; `C`'s account proof under the header's state root; the EIP-1967 slot's proof under `C`'s
storage root; `I` from it; `I`'s account proof; the slot set from the pinned `R` and `k` and the
proven `I`; each slot's proof under `C`'s storage root; `finish`: nothing in `W` unread.

## What a requester must audit

The binding pins the header; everything else rests on the guest being what it claims (plan §8.3,
"the scheme id is advisory"). Before relying on a proof:

1. **The guest and its image id.** `guest/src/main.rs` (50 lines), `statement/src/lib.rs` (`run` and
   the rule), and the prelude's README. Publish the image id of a reproducible build (risc0-build's
   Docker build); a local build embeds the checkout's paths, so its id differs from machine to
   machine. Build it with risc0-zkvm 3.1.0, as below.
2. **The parameters.** `B` must be canonical when you submit (take it from Base's `finalized` head,
   at least `safe`); `C`, `R` and `k` are what you mean. The binding then fixes the answer's
   question.
3. **The binding.** `journalFields` and `expectedJournalHash` from `Statement`, never from a
   prover's journal; the journal-prefix marker set.
4. **Outputs you rely on.** `I` is the truncation the proxy uses; `H` follows `EXTCODEHASH`; a slot
   that reads 0 may be unset or set to 0 (the trie cannot tell).
5. **Not the builder.** The builder is untrusted by design: a wrong `W` fails in the guest during
   simulation (no lock), or answers a header the binding refuses.

The guards guarantee (prelude README): every journal word after the header is a value the prelude
verified against the pinned `B`, every trie key is computed from pinned or proven values, and the
guest never finishes with unread witness data. They do not guarantee that `B` is canonical or that
the statement is the one you wanted.

## The risc0 version

The guest (and the lint control and `hostdep`) is built with risc0-zkvm 3.1.0, what the miner proves
with and the deployed verifier (risc0-ethereum v3.1.0) accepts, pinned exactly (`=3.1.0`) with the
two crates whose control roots a guest's keccak assumptions name, risc0-circuit-recursion and
risc0-circuit-keccak 4.1.0: risc0-zkvm requires them only by caret, so a `cargo update` could move
them. The guest crates of crates.io's 3.1.0 are the fork's the miner pins (its differences are on
the host side).

It matters for any guest that hashes with keccak through risc0's accelerator (the batcher): two or
more batches are rooted under risc0-circuit-recursion's `ALLOWED_CONTROL_ROOT`, and a guest built
with risc0-zkvm 3.0 names 4.0's (`0xa54dc85a…`), which the 3.1 prover cannot resolve. Such a guest
executes cleanly and fails every proof ("no receipt available for unresolved assumption"); the miner
refuses it before any claim, and `zkminer simulate` says why: "the guest was built with risc0-zkvm
older than 3.1 … Rebuild the guest with risc0-zkvm 3.1.0". One batch (about 655 permutations at the
miner's keccak po2, 17) is assumed under the keccak circuit's root, which both share. This guest
hashes in software (the prelude's keccak), so it was never affected; `keccak-3-0` and `hostdep` show
both sides (`methods/tests/keccak_batches.rs`, and `simulate_adversarial.rs`'s
`a_guest_built_with_risc0_3_0_is_refused_by_name`).

## The guest lints (plan §21.1 item 4)

No host input may reach the journal or a selection: no default-seeded `HashMap`/`HashSet`
(`sys_rand` seeds them), `env::exit`/`pause`, environment, arguments, cycle count, `sys_rand`, the
raw keccak permutation's status (it shows the host's keccak po2), a file descriptor other than
stdin, or any syscall made around the platform's wrappers (the raw `syscall_*_nr` entry points,
`asm!`). And no `static`, `thread_local!`, `Cell` or `RefCell`: a derivation the guards accept
captures nothing, but could read one of those.

- `guest/clippy.toml` denies what clippy can see; `./check-guest-lints.sh` runs clippy for the zkVM
  target with the risc0 toolchain, and checks that the lint control's violations are reported.
- `methods/tests/guest_lints.rs` checks the built ELF, which covers every crate the guest links:
  an `ecall` only inside the platform's wrappers (`sys_*`, `syscall_*`) and risc0's keccak batcher,
  and the raw entry points called only by those wrappers; `sys_rand` only from risc0's `env::init`
  (the memory-image entropy every risc0 guest draws, which never reaches the journal); `sys_keccak`
  only from the batcher; nothing calling `sys_getenv`, `sys_argv`, `sys_argc`, `sys_cycle_count`,
  `env::exit` or `env::pause`; the syscall name strings (`nr::SYS_*`) referenced only by their
  wrappers, and `SYS_GETENV`, `SYS_ARGV`, `SYS_ARGC`, `SYS_CYCLE_COUNT` by nothing; no hash-map seed
  linked. It also scans the sources of the guest, the statement and the prelude for the banned names,
  the `syscall_`/`SYS_` prefixes, `asm!`, `send_recv`, `FdReader`, `static`, `thread_local`, `Cell`,
  `RefCell` and a `sys_read` of any fd but `fileno::STDIN`. Both are shown to catch the lint control,
  which also reaches every host input around the names (a reviewer's bypass guest, folded in).
- What no lint sees: a host input the guest reads by an `ecall` inside one of the platform's own
  wrappers it is allowed to call, if the platform changed what that wrapper does. Pin the platform
  crate, and `simulate --adversarial` reruns the guest under two `sys_rand` seeds (the rule's and a
  random one), two po2s and two keccak po2s.

The guest is `no_std`, so the standard hash maps, `std::env` and `std::process::exit` do not exist
for it at all.

## Running it

```sh
# The statement: synthetic states, real Ethereum/Base/Hemi proxies, mutations, fuzzing.
cargo test -p hemiprove-proxy-slots
# The guest: lints, and the risc0 executor (CPU) on real chains.
cargo test -p hemiprove-proxy-slots-methods --test guest_lints --test executor
./reference/proxy-slots/check-guest-lints.sh
# End to end on anvil: real broker and runner binaries, sandboxed (needs a delegated cgroup).
systemd-run --user --scope -q -p Delegate=yes -- env ZKMINER_SANDBOX_TESTS_REQUIRED=1 \
    cargo test -p hemiprove-proxy-slots-methods --test anvil_e2e
# Keccak batches by risc0 version: the executor's claims, then real CPU proofs (ignored, slow).
cargo test -p hemiprove-proxy-slots-methods --test keccak_batches
cargo test -p hemiprove-proxy-slots-methods --test keccak_batches -- --ignored --test-threads=1
```

On the miner, claimed and proven, on a local fork of 743111 with a second anvil as the `evm-rpc`
chain: `serves_the_proxy_slots_witness_job` (CPU) and `serves_the_proxy_slots_witness_job_on_a_gpu`
in `crates/zkminer-cli/tests/localnet.rs` (see its witness section).

Cycles on the risc0 3.1 executor (padded to segments of 2^20): Ethereum (k = 3, `W` 17 KB) 3.1 M,
Base (k = 6, `W` 26 KB) 4.7 M, Hemi (k = 6, `W` 18 KB) 3.2 M, anvil (`W` 3 KB) 1.0 M; about 180
cycles per byte of `W`. Size `maxGuestCycles` from `zkminer simulate`. Keep `k` near 20 or below for
the fulfil to stay under the default DA cap.
