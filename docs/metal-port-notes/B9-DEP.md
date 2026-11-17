# B9-DEP: zk-miner builds without a local risc0 checkout

Branch `item/B9-DEP` (worktree `/Users/user/zkminer/zk-miner-3.1-wt-B9-DEP`), from `item/B9-CHAIN`
`e3fd6cf`. Scratch, logs and scripts are in `/Users/user/zkminer/scratch/w9/B9-DEP/`: `logs/`,
`bench/`, `scripts/` (`ci-env.sh` is the clean-runner environment, `ab.sh`, `ab-pairs.sh` and
`summarize.py` are the A/B). `RELEASE-DEPS.md` at the top of the repository is the user-facing
summary.

**Pin:** hemilabs/risc0 branch **`zkminer/metal-3.1`** @ **`d94ef65015f4753c5496ad7302f15c44513370f3`**.
That is `/Users/user/zkminer/deps/risc0-3.1` HEAD after the phase-1 merges: B9-SEC `abea7c97c`,
B9-G1 `afb524d8e`, B9-4G `d94ef6501`. The tools unit merged nothing, and B9-FX stays unmerged. The
branch is not on GitHub yet (`git ls-remote` on 2026-11-17: the public repository has
`release-3.1` @ `5beab26b5`, `zkminer/release-3.1-fixes` and others, but not this commit). It has to be
pushed unchanged under that name, or the rev must be updated (RELEASE-DEPS.md).

No Metal kernel, risc0 file or proving source changed. R17 (`ir_scan.py`, `run_stress.sh`) does not
apply. `/Users/user/zkminer/deps/risc0-3.1` was not edited: only a mirror was cloned from it and a stock
verifier built from it, into scratch. No risc0-side patch is required, so
`scratch/w9/B9-DEP/risc0-patches/` is empty.

## What changed

| file | change |
|---|---|
| `Cargo.toml` | The 17 `[patch.crates-io]` risc0 lines are now `{ git = "https://github.com/hemilabs/risc0", rev = "d94ef650…" }` instead of `{ path = "../deps/risc0-3.1/…" }`. A new `[patch."https://github.com/hemilabs/risc0"]` takes `risc0-circuit-recursion-zkrs` and `-control-zkrs` from crates.io `=4.1.0`. The 3.0-era pin paragraph is marked as history. |
| `Cargo.lock` | +22 lines, 0 removed: 18 `source = "git+…?rev=d94ef650…#d94ef650…"` lines (the 17 crates + `rzup`), and `source`/`checksum` for the two zkrs crates. Nothing else moved (`cargo metadata --locked` passes). |
| `.cargo/risc0-local.toml` | New. The old path patches as a `--config` file for plain cargo. It is not `config.toml`, so it is never loaded implicitly. |
| `Makefile.mac` | `RISC0_SRC=git\|local\|auto` (default auto: local when `$(RISC0_DIR)` holds a checkout). Local mode adds `--config 'patch.crates-io.<crate>.path="<RISC0_DIR>/…"'` (absolute, so any checkout location works) and swaps in a derived local lock for the recipe (see below). `RISC0_LOCAL_LOCKED=0` drops `--locked`. `env.sh` is now optional (warns and uses PATH/xcrun). `mac-prereqs` reports the mode, checks protoc, honours `RISC0_HOME`, and warns when a local checkout is not at the pinned rev or is dirty. `mac-build-aot`/`mac-install-worker` get the risc0 tree from the mode (git: a verified copy of cargo's checkout). The fork's suites (`mac-test-risc0-*`) say clearly that they need a checkout. |
| `RELEASE-DEPS.md` | New: pins, clean-runner commands, local mode, mirror testing. |

Revert knob: `RISC0_SRC=local` (or `cargo --config .cargo/risc0-local.toml`) builds exactly what the
path patches built before. The derived lock is byte-identical to the old committed `Cargo.lock`
apart from the two `[[patch.unused]]` zkrs entries that cargo adds.

## (a) Git LFS: the zkrs crates

Evidence that it is a real problem:

- `git lfs ls-files` in the fork lists `risc0/circuit/recursion-zkrs/src/zkrs.tar.xz` (oid
  `53388c58…`), `recursion-control-zkrs/src/zkrs.tar.xz` (`202fd7e7…`) and
  `groth16_proof/groth16/stark_verify.circom`.
- In the fresh build, cargo's checkout
  (`cargo-home/git/checkouts/risc0-2889eb738d2534f6/d94ef65/risc0/circuit/recursion-zkrs/src/zkrs.tar.xz`)
  is the 132-byte pointer: `version https://git-lfs.github.com/spec/v1 / oid sha256:53388c58… /
  size 7868920`. The same holds for the control crate.
- Negative control: building the fork's own `risc0-circuit-recursion-zkrs` from that checkout
  (`logs/negative-zkrs-from-git.log`) fails with "panicked at risc0/circuit/recursion-zkrs/build.rs:47:
  src/zkrs.tar.xz is a git-lfs pointer, not the tarball. Run `git lfs pull`, or depend on this crate
  from crates.io."

Evidence that crates.io 4.1.0 is the same content (downloads in `scratch/w9/B9-DEP/zkrs/`):

| | crate sha256 (= index `cksum`) | `src/zkrs.tar.xz` sha256 | fork LFS oid / file sha256 |
|---|---|---|---|
| risc0-circuit-recursion-zkrs 4.1.0 | `667665b4fafafeb5b589aaf2cc825ec688bdb2b6cddad5ce9d28001d5366fb5d` | `53388c58fc04788baac51db69283bedc0c4293480d0455e400313dfc4dd226c2` | `53388c58…26c2` (equal) |
| risc0-circuit-recursion-control-zkrs 4.1.0 | `bc7f8b264ea4dea2909c2dea39fd1952b835d4688a45ac7b0eed07c642df1667` | `202fd7e78e4fc900da18bee048164bfe4ee428d95aa33a0d61a9c002dba9187f` | `202fd7e7…187f` (equal) |

`diff -r` of each crate's `src/` against the fork shows no difference, and the same holds for
`build.rs`. The fork's crates have the same version (4.1.0) and the same dependencies (phf 0.13;
liblzma 0.4 static+parallel, tar 0.4). `Cargo.lock` records the two checksums above. The fresh build
compiled `risc0-circuit-recursion-zkrs v4.1.0` and `-control-zkrs v4.1.0` from the registry and every
other risc0 crate from the git rev (`logs/fresh-build-3.log`, `-4.log`).

`stark_verify.circom` is read only by risc0's `xtask setup_groth16`, not by any build script.

Tried and rejected: `[replace]` (cargo refuses `[replace]` together with `[patch]`) and path-patching
the zkrs crates to a vendored copy (it would add 11 MB of tarballs to this repository for nothing
that crates.io does not already give, checksum-pinned). One pitfall cost time, so it is recorded here:
the new `[patch."…/risc0"]` table has to come *after* the SP1 lines. If it is placed before them, TOML
makes the SP1 entries part of it, and `cargo` then silently re-resolves the SP1 crates to crates.io
6.9/6.10 (~1800 changed lock lines).

## (b) Build inputs outside the crate directories

A git dependency is a checkout of the whole repository at the rev (it has no submodules), so
`../`-relative reads in the -sys build scripts work as they do in a local checkout. What must hold is
that every such input is *tracked*. `git status --short --ignored` in the fork (excluding `target/`)
lists only `tools/stock_verify31/produce/Cargo.lock`, which no build reads. The Metal shared headers,
`cuda2metal.h` and `sppark_compat.h`, are `include_str!`ed into `risc0-build-kernel`. The fresh build
compiled all five Metal libraries from the git checkout with an empty kernel cache: a fresh `HOME`,
and `home/Library/Caches/com.risczero.RISC-Zero.risc0` grew from nothing to 77 MB. The embedded
metallibs are byte-identical to the local-path build's (below). `tools/metal_aot`, the AOT archive
tooling, is not a build input. `mac-build-aot` takes it from the risc0 tree (next section).

**AOT in git mode.** `build-metal-aot.sh` builds risc0's dump tests in the risc0 workspace.
`risc0-circuit-keccak` depends on `risc0-circuit-recursion`, so these builds hit the zkrs LFS
pointers in cargo's checkout (`logs/aot-dump-build.log`: the same build.rs refusal). In git mode the
Makefile therefore copies cargo's checkout to `target/aot-risc0-<rev>`. It replaces the two pointers
with the crates.io tarballs that the build already uses, after checking each tarball's sha256 against
its pointer's oid, and hands that copy to the script as `RISC0_DIR`. Cargo's checkout is not modified.
Tested in the fresh clone (`logs/aot-git.log`, run under `gpu-run --light`): 11 archives, 165 MiB,
82 s for applegpu_g17s, and the script's own check passed (every dump metallib equals one the worker
embeds).

## (c) What env.sh provided, on a clean runner

`env.sh` provides four things. Here is each one, and what a runner with Xcode uses instead.

| env.sh | needed by the zk-miner build? | on a runner |
|---|---|---|
| Metal compiler on PATH (mounted toolchain dmg) | yes (all -sys crates) | `xcodebuild -downloadComponent MetalToolchain`, then `xcrun --sdk macosx metal` |
| `~/.risc0/bin` (rzup) on PATH | no: risc0-build finds the toolchain through `RISC0_HOME`/`~/.risc0` | `curl -L https://risczero.com/install \| bash; rzup install rust 1.97.0` |
| `AR_riscv32im_risc0_zkvm_elf` (C++ guest archiver) | **no** (only the fork's own C++ guests) | nothing |
| Homebrew llvm on PATH | no | nothing |
| (not in env.sh) protoc | **yes**: `circom-witnesscalc` (risc0-groth16) | `brew install protobuf` or `PROTOC=` |
| (not in env.sh) git-lfs | no (see (a)) | nothing |

How this was shown: the fresh build ran with `env -i` (`scripts/ci-env.sh`), which sets:

- `HOME` and `CARGO_HOME`, both empty directories under scratch;
- `PATH` = rustup proxies + the Metal toolchain + `/usr/bin:/bin:/usr/sbin:/sbin` only;
- `RUSTUP_HOME=~/.rustup`, `RISC0_HOME=~/.risc0` (the installed 1.97.0 Rust guest toolchain);
- `PROTOC` (Homebrew's, after the first try failed without it: `logs/fresh-build-3.log`);
- no `AR_riscv32im…`;
- `make -f Makefile.mac RISC0_SRC=git ENV_SH=/nonexistent`.

The guest ELFs come from risc0-build at build time, as before. Checking them in (no guest toolchain
on CI) would change `crates/zkminer-prove-risc0/build.rs`, which this item does not own (open issue).

The C++ toolchain warning in `mac-prereqs` stays a warning.

## The mirror build (the item's acceptance test)

- Mirror: `git clone --mirror /Users/user/zkminer/deps/risc0-3.1 /Users/user/zkminer/scratch/w9/mirror/risc0.git`
  (`zkminer/metal-3.1` = `d94ef650…`; a mirror has no LFS objects, like cargo's checkout).
- Fresh clone of this branch (`scratch/w9/B9-DEP/fresh`), fresh `CARGO_HOME` and `HOME`.
- Two corrections to the brief's command:
  1. **`insteadOf` prefix trap.** `url.file:///…/risc0.git.insteadOf https://github.com/hemilabs/risc0`
     also rewrites `https://github.com/hemilabs/risc0-sppark` (prefix match): "fatal:
     '/…/mirror/risc0.git-sppark' does not appear to be a git repository" (`logs/fresh-build-2.log`).
     A second, longer rule mapping `https://github.com/hemilabs/risc0-sppark` to itself fixes it
     (`GIT_CONFIG_COUNT=2`, in RELEASE-DEPS.md).
  2. The worker needs `--features metal`, so the build ran as Makefile.mac does: two `cargo build
     --locked --release` calls (worker with `--features metal --bin zkminer-prove-risc0-metal`, then
     `-p zkminer-cli`).
- One cache was seeded: the first attempt's `hemilabs/sp1` fetch (344 MB) was cut off by the
  network ("fetch-pack: unexpected disconnect") before the slice ended. I copied cargo's existing
  sp1 git db into the fresh `CARGO_HOME`. Every risc0 object came from the mirror, and everything
  else came from the network.
- Result: `rc=0`, `Finished release`. About 13 min of wall time from an empty `CARGO_HOME` (downloads
  included) at `-j 6`, in two 570 s slices (`logs/fresh-build-3.log`, `-4.log`). The release binary was
  `target/release/zkminer-prove-risc0-metal`, 184,156,176 B, and the `zkminer` CLI was 15,768,208 B.

## Same behaviour as the local-path build

Reference A: `make -f Makefile.mac RISC0_SRC=local mac-build-worker` in the worktree, on the same
risc0 commit `d94ef6501` via path. Its binary was 184,089,696 B. Afterwards `Cargo.lock` was byte for
byte the committed lock, and the tree was clean. B: the fresh git build above.

- **Kernels:** the five embedded metallibs have the same digests in A and B (`build-metal-aot.sh
  --worker-digests`: `0f98bbd2…`, `4f52e454…`, `518b8340…`, `6537b10c…`, `a99c1267…`;
  `logs/digests-{local,git}.txt`).
- **Size difference** (66 KB): path strings (cargo-home/git/checkouts/… vs deps/risc0-3.1) in panic
  locations.
- **Guest image ids differ**: memory-merkle `05bd9ebe…5169` in A, which is also the 3.0/3.1 id of
  P31-19, and `49b4b5a1…a331` in B. The cause is the guest build, not the git switch. The guest ELFs
  embed `$HOME/.cargo/registry/src/…` paths, because risc0-build strips every `CARGO*` variable from
  the guest cargo, and B's `HOME` was the fresh one (`strings` of the two `fibonacci.bin`). Nothing
  compares these ids to a constant (`grep` of `crates/`). Both builds' receipts verify with their own
  ids.

**Interleaved A/B**, memory-merkle `--benchmark` (7,340,032 cycles):

- `scripts/ab.sh` ran one `gpu-run` per pair, A then B.
- Pairs: 8 at full budget (`--no-budget`), 7 at 8 GiB, 7 at 4 GiB (`RISC0_METAL_MAX_WORKING_SET_BYTES`
  via `gpu-run --budget`).
- Two warm-up pairs were run first and discarded.
- Each cell is median [min..max]; `bench/summary.txt` has the full output.

| budget | po2 | STARK A | STARK B | c/s A | c/s B | wrap A / B | process peak A / B (MiB) | GPU seg / wrap peak A / B (MiB) | load avg A / B |
|---|---|---|---|---|---|---|---|---|---|
| full | 20 | 8.355 [8.30..8.40] | 8.350 [8.33..8.38] | 878,608 | 879,066 | 1.59 / 1.59 | 12,592 / 12,591 | 9437 / 5635 both | 2.24 / 2.21 |
| 8 GiB | 19 | 10.24 [10.23..10.27] | 10.23 [10.20..10.26] | 768,100 | 768,613 | 1.74 / 1.75 | 6,986 / 6,986 | 4738 / 5635 both | 3.45 / 3.50 |
| 4 GiB | 18 | 13.94 [13.91..13.97] | 13.94 [13.91..13.96] | 601,553 | 601,871 | 1.73 / 1.73 | 4,700 / 4,700 | 2404 / 3944 both | 2.96 / 2.57 |

The A–B differences (≤ 0.06 %) are inside each side's own spread, so there is **no change**. The
numbers match BASELINES '3.1': memory-merkle ~767K c/s at 8 GiB and ~603K at 4 GiB, wrap 1.57-1.59 s.
Peak memory did not change at either budget.

## Correctness gates

| gate | result |
|---|---|
| stock crates.io 3.1.0 verifier (`tools/stock_verify31`, built unmodified `--locked` into `scratch/w9/B9-DEP/target-stock`; build.rs checks all 10 risc0 packages are crates.io) on every A/B receipt | **44/44 `STOCK 3.1 VERIFY: OK`** (22 A + 22 B; full, 8 GiB, 4 GiB), selector `e71e6620`, control root `e6feef13…` (`bench/stock_verify.log`) |
| git build: worker unit tests (`cargo test --locked --release -p zkminer-prove-risc0 --features metal --bin zkminer-prove-risc0-metal`, gpu-run heavy) | 64 passed, **twice** |
| git build: `cargo test --locked --release -p zkminer-cli --bin zkminer` | 142 passed, **twice** (includes `the_3_1_verifier_pin_slot_matches_the_linked_risc0`) |
| git build: `metal_worker -- --ignored` (release, one test per gpu-run) | 4/4 passed: warm-up + prove over IPC, first prove without warm-up, M9 10 proofs (65.7 s), tight worker after keccak (with `ZKMINER_B9_KECCAK_ELF`, see open issues) |
| git mode `mac-build-aot` | OK, 11 archives (above) |
| local mode `mac-build-worker` | OK, lock restored, tree clean |
| awk-derived local lock vs the lock cargo writes for `--config .cargo/risc0-local.toml` | byte-identical (`cmp`) |
| `Cargo.lock` vs path-mode lock | +22 lines only. `cargo metadata --locked` passes in git mode |
| 3.0 receipts rejected | not re-run: no prover source changed, and A and B prove identically. B9-4G's matrix at this risc0 rev rejects 30/30 |

No timing or test ran outside `gpu-run`. Builds ran outside the lock, then tests under it.
Afterwards I deleted the fresh clone's `target/`, the fresh `CARGO_HOME` and `HOME`, and
`target-stock`. Logs, receipts and scripts are kept.

## Knobs

- `RISC0_SRC=git|local|auto` (Makefile.mac, default auto).
- `RISC0_DIR` (local checkout, default `../deps/risc0-3.1`).
- `RISC0_LOCAL_LOCKED=0` (local mode without `--locked`).
- `cargo --config .cargo/risc0-local.toml` (plain cargo; rewrites `Cargo.lock`).

## Open issues

1. **Push `zkminer/metal-3.1` @ `d94ef6501` to hemilabs/risc0 unchanged** (user action). Until then
   no machine without the mirror can build this branch, CI included.
2. **The Metal compiler on CI differs from the validated one.** All Metal validation (R17 audits,
   stress, A/B) used Metal toolchain 27B47 (`Apple metal version 32023.922`, SDK 27.2). A macOS 26
   runner's Xcode 26 compiler is an older build. Its metallibs will differ, and with them the AOT
   archive digests. R17 is a compiler/GPU codegen defect class. Before shipping a CI-built worker,
   run the R17 audit and stress (`tools/metal_audit`), or at least the unit suites and a
   `--benchmark`, with that binary on Apple Silicon hardware, or pin the runner's Xcode to the
   validated toolchain.
3. **Guest toolchain at build time.** The 13 benchmark guests are compiled by risc0-build, so CI
   needs `rzup install rust 1.97.0`. Their image ids depend on the build host's `$HOME` (above).
   Checking the ELFs in, or a remap-path-prefix in the guests' `[package.metadata.risc0]
   rustc-flags`, would make them reproducible and remove the toolchain from CI. That needs edits
   to `crates/zkminer-prove-risc0/build.rs` and the guest manifests (not owned by this item).
4. **`metal_worker::a_tight_worker_wraps_after_keccak_and_releases_the_key_between_jobs`** reads its
   keccak guest from `../../../deps/risc0-3.1/target/riscv-guest/…/multi_test.bin`, a fork test build.
   Without a checkout it fails unless `ZKMINER_B9_KECCAK_ELF` is set. It is `#[ignore]` and needs a
   GPU, so it does not affect a build-only CI.
5. **README** (not owned) still describes the macOS build as needing `../deps/risc0-3.1` and
   `env.sh`. Point it at RELEASE-DEPS.md.
6. risc0-build-kernel's "no Metal compiler" hint names `/Users/user/zkminer/env.sh` (risc0 side,
   cosmetic). On a runner the fix is the `xcodebuild -downloadComponent MetalToolchain` step above.
7. The Linux/Windows workflows on this branch (`Dockerfile.build`, `build-windows.yml`) now also
   build risc0 from this rev and the crates.io zkrs. The old path patch broke them outright, but
   they were not built or tested here.
