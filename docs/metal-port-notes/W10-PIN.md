# W10-PIN: pin zk-miner to the risc0 fork after W10-GATE

Branch `item/W10-PIN`, base `metal-3.1` @ `8153340` (W10-INT merged: GitHub main `c030355` in the macOS
beta). W10-BENCH and W10-DOC were not merged in phase 2, so this base does not contain them. Wave 10 (merge wave): no performance
work. Scratch, logs and scripts: `/Users/user/zkminer/scratch/w10/W10-PIN/` (`bench/`, `localnet/`,
`rcpt/`, `scripts/`, `bin/`).

## Result

- **Pin:** hemilabs/risc0 `zkminer/metal-3.1` @ **`37b434755ce77dd1354d957a7b61912aa4359423`**. This is
  the risc0 checkout after the Wave 10 phase-2 merge, `Merge metal/W10-GATE` (`404ae8dcf`). The previous
  pin was `28b4bef33`, W10-R0's merge.
- **Lock:** the 17 `[patch.crates-io]` revs and the 18 `source = "git+…"` lines in `Cargo.lock` were
  moved, in the B9-DEP form. Nothing else in the lock changed: the fork's diff `28b4bef33..37b434755`
  touches no `Cargo.toml` or `Cargo.lock`. `cargo metadata --locked` resolves through the refreshed
  mirror, and `--locked` builds pass.
- **zkrs crates:** still crates.io `=4.1.0`. The fork's LFS pointers at `37b434755` name oids
  `53388c58…26c2` (lift) and `202fd7e7…187f` (control). The crates.io tarballs in the cargo registry
  hash to the same values (`shasum -a 256`). Neither crate directory changed in the diff.
- **No code change:** zk-miner calls none of the APIs W10-GATE touched (`git grep get_zkr`: no hits
  outside the notes). The restored upstream `get_zkr(&str, usize) -> Result<Program>` is not called. The
  new `get_zkr_shared` is only used inside the fork.
- **Docs:**
  - `RELEASE-DEPS.md` gives the new pin. Its section "What the Metal fork changes on the other
    platforms" now says "nothing by default" and has a table built from W10-GATE's: per change, the
    Metal default, the default elsewhere (= release-3.1) and the opt-in knob.
  - The `Cargo.toml` comments give the new rev and mention W10-GATE.
  - `docs/release/BETA_RC.md` gets a pointer: its checklist shas are RC2's, and the RC must be redone on
    the current pin.
  - Older notes (B9-*, BETA-FIX, W10-INT) are records of their time and keep their revs.
- **Performance:** unchanged. The interleaved A/B is inside A-vs-A at the default, 8 GiB and 4 GiB
  budgets. The full `--benchmark` is within noise of RC2 and of A measured in the same session.
- **Gates:** every gate in the brief passed. The exception is the best-effort Linux cross-check, which
  could not finish for the whole workspace (details below).
- `origin/main` is still an ancestor of the branch.

## Steps

1. Refreshed the mirror:
   `git -C …/scratch/w9/mirror/risc0.git fetch /Users/user/zkminer/deps/risc0-3.1 '+refs/heads/*:refs/heads/*'`
   moved `zkminer/metal-3.1` from `28b4bef33` to `37b434755`.
2. Replaced the full sha in `Cargo.toml` and `Cargo.lock`: 17 + 18 occurrences.
3. Ran `cargo metadata --locked` through the mirror (the brief's `GIT_CONFIG_*` env): rc 0. Cargo
   fetched `37b434755` from the mirror, and the lock was not rewritten.
4. Checked the LFS oids and edited the docs (above).

## Profile / A/B (before keeping the pin)

The zk-miner code is the same on both arms. Only the risc0 rev differs, and its Metal-reachable changes
are W10-GATE's (the keccak syscall and the `get_zkr_shared` call path).

- **A** = `metal-3.1` `8153340` (risc0 `28b4bef33`): detached worktree `scratch/w10/W10-PIN/zkA`,
  binary `bin/W_A`, 184,536,672 B.
- **B** = this branch (risc0 `37b434755`): binary `bin/W_B`, 184,562,656 B.

Both arms are a plain `cargo build --locked --release -p zkminer-prove-risc0 --features metal --bin
zkminer-prove-risc0-metal` through the mirror, in one target dir. Each run is `BENCH_ONLY=memory-merkle
--benchmark` under `/usr/bin/time -l`, 7 interleaved pairs (A B A B …) per budget, in one `gpu-run` lock
per budget (`scripts/ab_mm.sh`, `scripts/sum_mm.py`). Every run returned rc 0, verified its receipt and
proved the same cycle count as its pair.

| budget (cycles) | A STARK median [min-max] | B STARK median [min-max] | B-A per pair: median [min, max], pairs > 0 | A-vs-A (consecutive A runs) | wrap A / B | peak footprint A / B (GiB) | load |
|---|---|---|---|---|---|---|---|
| default (7,340,032) | 8.430 [8.400-8.490] s, 870.8K c/s | 8.420 [8.420-8.440] s, 871.2K c/s | -0.01 [-0.05, +0.03] s, 1/7 | [-0.06, +0.03] | 1.590 / 1.590 s | 13.01 / 13.01 | 1.0-4.3 |
| 8 GiB (7,864,320) | 10.420 [10.370-10.460] s, 754.5K c/s | 10.430 [10.400-10.490] s, 754.1K c/s | +0.01 [-0.03, +0.11] s, 4/7 | [-0.05, +0.07] | 1.730 / 1.730 s | 7.75 / 7.75 | 0.6-2.0 |
| 4 GiB (8,388,608) | 14.220 [14.190-14.270] s, 589.8K c/s | 14.210 [14.190-14.270] s, 590.4K c/s | -0.01 [-0.07, +0.06] s, 3/7 | [-0.05, +0.04] | 1.730 / 1.720 s | 5.40 / 5.41 | 1.0-2.9 |

**No change** at any budget: every median difference is inside the A-vs-A spread. These are the same
numbers W10-GATE measured on its own A/B (default 8.44 s, 4 GiB 14.07 s on its build).

- **BASELINES '3.1' comparison:** memory-merkle there was ~767K c/s at 8 GiB and ~603K c/s at 4 GiB.
  Here both arms are ~1.6 % / 2.1 % lower than that. Arm A, the merged beta without this pin, shows the
  same offset.
- **Why the offset:** it is not this item. Since W10-INT, `BENCH_ONLY` runs the warm-up and pick a
  segment po2 by budget (W10-INT open issue 6). The cycle counts differ by budget for that reason.
- **Peaks:** not raised at either budget (the table, plus the full run below).

### Full `--benchmark` (default budget)

One full `--benchmark` per arm, B first, under `scripts/full1.sh` and `scripts/sum_full.py`.

| | B (this pin) | A (8153340 / 28b4bef33), same session | RC2 |
|---|---|---|---|
| 5 programs STARK | 170.54 s, 905.5K c/s | 171.06 s, 902.7K c/s | |
| with fibonacci | **170.82 s, 904.2K c/s** | 171.34 s, 901.4K c/s | 169.92 s, 909.0K c/s |
| Groth16 wraps | 1.59-1.60 s | 1.59-1.60 s | |
| peak footprint | 14.73 GB | 14.70 GB | baseline 14.69 GB |
| wall | 253.9 s | 254.6 s | |

- The zkop-mix proofs on B took 4.88 s and 68.12 s.
- B is +0.5 % over RC2's 169.92 s and 0.3 % faster than A in the same session. That is within noise,
  and it matches W10-INT's 171.05 s on the same code.

### `zkminer benchmark` through the CLI

- **Setup:** sandbox `HOME=scratch/w10/W10-PIN/home`, so the user's saved benchmark is untouched;
  `zkminer init`, then worker `W_B` installed in `home/.zkminer/provers`.
- **Result:** rc 0 in 335 s, 2.72 MzkOP/s, the same as W10-INT.
  - The 5 programs and the zkop-mix score ran through the dispatcher.
  - Device row: po2 20, 891.5K c/s, Groth16 1.6 s.
  - Per program: sha256-chain 50.91 s, ecdsa-verify 71.08 s, bigint-mul 30.78 s, memory-merkle 8.35 s,
    chacha-mix 9.73 s, zkop-mix 68.22 s.
- **Logs:** `cli-init.log`, `cli-bench.log`.

## Correctness and gates (all foreground; logs in `scratch/w10/W10-PIN/`)

| gate | result |
|---|---|
| `cargo metadata --locked` through the mirror | rc 0; lock unchanged (`metadata.log`) |
| release worker + CLI through the mirror (`CARGO_NET_GIT_FETCH_WITH_CLI=true GIT_CONFIG_COUNT=2 … make -f Makefile.mac RISC0_SRC=git mac-build-worker`) | rc 0. Makefile prints `risc0 from hemilabs/risc0 @ 37b434755…`, and every risc0 crate compiled from `rev=37b434755…`. Worker 184,562,656 B, CLI 15,949,312 B. The tree stays clean (`mac-build-worker.log`) |
| `cargo test --workspace --exclude zkminer-prove-sp1 --exclude zkminer-prover`, ×2 (heavy lock) | **497 passed, 0 failed, 18 ignored**, both runs (`ws-1.log`, `ws-2.log`). The same count as W10-INT |
| `cargo test -p zkminer-prove-risc0 --features metal`, ×2 | **66 passed, 4 ignored**, both runs (`pr0-{1,2}.log`) |
| Metal IPC tests (`--release --features metal --test metal_worker -- --ignored --test-threads=1`) | **4/4** in 96.7 s (`mw.log`): warm-up + prove, a first prove without warm-up, the 4 GiB keccak-then-Groth16 sequence with key releases, and the M9 run of 20 proofs in one worker |
| `cargo test -p zkminer-prover --features testing --tests` (`ZKVM_ALLOW_SKIP=1`), ×2 | **384 passed, 21 ignored**, both runs: lib **292 passed / 1 ignored**, `worker_lifecycle` **27 passed / 3 ignored** (`prover-{1,2}.log`) |
| localnet suite (743111 fork, `crates/zkminer-cli/tests/localnet.rs --ignored`, real Metal worker = this build), ×2 | **9/9 runnable, both passes** (`localnet/pass{1,2}_*.log`, `scripts/localnet_pass.sh`): replayed receipt (106-107 s), `mines_the_claimable_jobs` (150-155 s), adapter disabled, 3.0 selector refused (no matching verifier), lock held through a pause (280-311 s), router paused, skewed clock, simulate (123 s), watch-only (245-246 s). Not run, by design (as in W10-INT): `serves_a_tui_miner` and `serves_jobs_to_simulate` (they serve a miner run by hand), and `mines_on_every_gpu` (SP1/CUDA) |
| receipts, stock crates.io 3.1.0 verifier (`scratch/w9/rc2/bin/stock-verify31`) | Source: B's `ZKMINER_BENCH_RECEIPT_DIR` Groth16 receipts (fibonacci and memory-merkle) at the default budget and at 4 GiB. Result: **4/4 STOCK 3.1 VERIFY: OK** (`rcpt/`). A 3.0 fibonacci Groth16 receipt (W10-GATE's `r30`) is **REJECTED**, plain (parameters digest 73c457ba…) and `--relabel-as-31` (proof invalid) |
| bit-exactness vs the CPU | Not re-run here: no kernel or prover code is in zk-miner's diff. W10-GATE ran the fork's Metal suites twice at this rev, its metallibs are byte-identical, and it ran the 30/30 stock matrix |
| `BENCH_ONLY=memory-merkle --benchmark` at default / 8 / 4 GiB | the A/B above, 21 B runs, all verified |
| full `--benchmark` | above: 170.82 s / 904.2K c/s (RC2 169.92 s / 909.0K) |
| `zkminer benchmark` (CLI) | above: rc 0, 2.72 MzkOP/s |
| `scripts/ci/test-assemble-macos.sh` (sdk = this build; kit = RC2's kit binaries, de-quarantined copies) | **44 passed, 0 failed** (`test-assemble.log`) |
| best-effort `cargo check --target x86_64-unknown-linux-gnu` (W10-R0's stand-in `fakecc` and fake nvcc/hipcc/icpx; nothing compiled for a GPU, nothing linked) | `-p zkminer-prove-risc0 --bins` with `--features cpu`, `cuda`, `rocm` and `intel`: **ok** for all four, risc0 checked at `rev=37b434755` (`xcheck-pr0-*.log`). `--workspace --exclude zkminer-prove-sp1`: **fails in `openssl-sys`'s build script** (no Linux OpenSSL headers or sysroot on this Mac; W10-INT hit the same wall at ckzg/openssl). Not a pin issue (`xcheck-ws.log`) |
| `git merge-base --is-ancestor origin/main HEAD` | holds |

## Tried and rejected

- **The first `test-assemble-macos.sh` run hung, and was killed after ~10 min.** It ran the RC2 kit
  binaries from `scratch/w9/rc2/home/Downloads/…`, which carry the `com.apple.quarantine` attribute (the
  RC's simulated Safari download).
  - `--metal-arch` sat at `_dyld_start` (`metal-arch-hang.sample`): Gatekeeper's first-launch assessment
    of an unsigned quarantined binary was waiting on a GUI prompt.
  - The rerun used copies with the attribute removed (`kit/`, same sha256 as the kit's files) and
    passed 44/44 in 140 s. The log of the killed run is kept as `test-assemble-quarantined-killed.log`.
  - This is expected for an unsigned beta, and the kit's install path handles it: RC2 tested
    `install.sh`. A dialog from the killed run may still be open on this Mac's screen.

## Budgets and memory

Peak memory is unchanged at every budget measured (default, 8 GiB, 4 GiB, and the full benchmark; the
tables above). No new knob: W10-GATE's knobs are listed in RELEASE-DEPS.md.

## Open issues

1. **Push `zkminer/metal-3.1` @ `37b434755` to hemilabs/risc0 unchanged** before anyone off this Mac
   builds. `https://github.com/hemilabs/risc0` has no such commit until then. If the branch is rebased
   or amended, the 17 revs in `Cargo.toml` and the 18 lock lines must follow.
2. **Linux and Windows are still not built or run.** W10-GATE makes the fork behave like release-3.1 off
   Metal by default, and the Linux type-checks above pass for the prover crate. A real CUDA/ROCm/Intel CI
   build and run is still needed before tagging from main.
3. **W10-BENCH and W10-DOC are not on this base.** Neither touches `Cargo.toml` or `Cargo.lock`, so
   the pin stands. But W10-DOC rewrites parts of `RELEASE-DEPS.md` (+31/-28 against `metal-3.1`), so
   expect a text conflict there. Keep this item's pin, its W10-GATE section and its first paragraph,
   plus W10-DOC's other edits.
4. The RC round must be repeated on this pin (BETA_RC.md now says so).
