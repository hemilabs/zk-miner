# macOS beta, release candidate 3 (integrated branch: GitHub main + the macOS beta, RISC Zero 3.1)

2026-11-19. This is the first release-candidate round of Wave 10 (the merge wave). It checks the
**integrated** `metal-3.1`, which now contains GitHub zk-miner `main`, and is pinned to a risc0 fork
rev that contains upstream hemilabs/risc0 `release-3.1`. The kit was built the way the CI job builds
it, then installed and used as a new user would. It ships **unsigned**: no Developer ID and no
notarization. Evidence and scripts are in `/Users/user/zkminer/scratch/w10/rc1/` (`ci/`, `logs/`,
`out/`, `live/`, `scripts/`).

RC1 (commit `ca07773`, kit `54296dc6…`) and RC2 (commit `6e7a1c1`, kit `02e5ca12…`) are in this file's
history. They checked the pre-merge beta (risc0 `d94ef6501`). RC3 replaces them.

**Verdict (updated after step 0, 2026-11-19).**
- RC3 found one failing check: when the worker died at start-up, or its warm-up failed, `zkminer
  benchmark` printed a table of *simulated* numbers and exited 0.
- **Step 0 is done** (section 3.6 and "Step 0" below). W10-BENCH, W10-DOC and the BETA-FIX
  startup-error fix are merged (`f9f535b`). The kit was rebuilt from `f9f535b`, and both forced
  failures now exit 1 with `BENCHMARK FAILED`, the worker's error and no table, while a working
  `zkminer benchmark` exits 0 with real numbers.
- The candidate is now the `f9f535b` kit below. Sections 1-5 below are RC3's record of `8b448a0`;
  only the zk-miner CLI-side code, the worker's benchmark exit codes and docs changed since (no risc0,
  kernel, metallib or compiler change).

## The candidate

**After step 0:** `zkminer-0.1.0-macos-arm64.tar.gz`, 121,308,198 bytes (192 MB unpacked), **sha256
`5153fac0e4ba59388133771ffd8c6dd47e85fa1a3dbbec4cdd9b51aaa624b49e`**, in
`/Users/user/zkminer/scratch/w10/BETA-FIX/dist/`. BUILDINFO commit
`f9f535b800f8652072f3164a3372a209712130f6` (`commit_dirty=no`), risc0 `37b434755…`, min_macos 26.0,
compiler 32023.922 validated, no archives, the same 5 metallib digests. RC3's kit (below) is superseded.

| | |
|---|---|
| kit | `zkminer-0.1.0-macos-arm64.tar.gz`, 121,281,859 bytes (192 MB unpacked) |
| **sha256** | **`d0099a51dc6186ea0092e51798168e00702bcdb913ccc6b2e5ffbbad6238eb6d`** |
| where | `/Users/user/zkminer/scratch/w10/rc1/dist/` (the tarball and its `SHA256SUMS`) |
| zk-miner | `metal-3.1` @ `8b448a08b665e8ba53e01be74e36e3eb8dbfe878` (`BUILDINFO commit`, `commit_dirty=no`) |
| risc0 | hemilabs/risc0 `zkminer/metal-3.1` @ `37b434755ce77dd1354d957a7b61912aa4359423` (`BUILDINFO risc0_rev`, `risc0_src=git`) |
| minimum macOS | 26.0: binaries minos 26.0, metallibs target 26.0 (`check-macos-release.sh`: "a self-contained arm64 kit for macOS 26.0 and later") |
| Metal compiler | `Apple metal version 32023.922 (metalfe-32023.922.4)` (27B47, pinned, `metal_compiler_validated=yes`), SDK 27.2 |
| offline archives | none (`aot_arches=`; CI builds with `AOT_ARCHES=none`) |
| Groth16 component | not bundled; v0.2.0, sha256 `173354ab…57e5`, fetched by the worker or `install.sh --with-groth16` |
| worker metallib digests | `261571a7…`, `62805de6…`, `c934c282…`, `cf978db9…`, `f42fd572…`: the same 5 as RC1, RC2 and B9-M26 |

- The commit that adds this file changes only `docs/release/BETA_RC.md`, which is not an input of the
  kit.
- A kit built by CI for a tag differs in its `BUILDINFO commit`, and so in its sha256. On the runner's
  Xcode 26 SDK, `metal_sdk` and the metallib digests also change (B9-M26, B9-CI).

## 0. Integration facts (all hold)

| fact | check | result |
|---|---|---|
| pushing `metal-3.1` to `main` is a fast-forward | `git merge-base --is-ancestor origin/main metal-3.1` | **yes**. `origin/main` = `c030355`; `metal-3.1` is 66 commits ahead and 0 behind |
| the pin contains upstream `release-3.1` | `git -C deps/risc0-3.1 merge-base --is-ancestor origin/release-3.1 37b434755` | **yes** (`origin/release-3.1` = `5beab26b5`) |
| the pin is the fork's HEAD | `deps/risc0-3.1` HEAD | **`37b434755`** (`Merge metal/W10-GATE`), clean tree. Its tree equals W10-GATE's `404ae8dcf` |
| `Cargo.toml` / `Cargo.lock` | grep | 17 `[patch]` revs and 18 lock `source` lines = `37b434755…`. No other hemilabs/risc0 rev. sppark stays `5f68eb3e…` |
| the mirror has it | `scratch/w9/mirror/risc0.git` fetched from `deps/risc0-3.1` | `zkminer/metal-3.1` = `37b434755…` |
| non-Metal code = release-3.1 in effect | W10-GATE (`deps/risc0-3.1/docs/metal-port/notes/W10-GATE.md`) and RELEASE-DEPS.md's table | every fork change off Metal is gated to its release-3.1 default. Not re-checked here, and no Linux or Windows build was run (open issue 2) |
| workflows | `actionlint` 1.7.12 (with shellcheck) on all 5 workflows | clean once the self-hosted labels (`zkminer-gpu`, `zk-runner-mac-new`) are declared in a config. Without that config the only finding is `release.yml:168` "label zkminer-gpu is unknown", which comes from main. `scripts/ci/test-workflow-expressions.py`: 425 passed |

## 1. CI build (`build-macos.yml`, all three jobs, run locally)

**How it was run.** B9-CI's harness (`ci/sim.py`, with only its paths changed) ran every step of
`.github/workflows/build-macos.yml` at `8b448a0`, in order, exactly as written:
- a fresh clone of `metal-3.1`, inside a 14 GB APFS disk image (`hdiutil`, 13.79 GB usable; detached
  and deleted afterwards);
- a fresh `HOME` and `CARGO_HOME` inside the image, and `CARGO_BUILD_JOBS=5`;
- the hemilabs/risc0 URL sent to the mirror (`CARGO_NET_GIT_FETCH_WITH_CLI=true` and RELEASE-DEPS.md's
  two `GIT_CONFIG_*` rules).

The workflow file is byte-identical to RC2's.

| job / step | rc | wall | disk (of 13.79 GB) |
|---|---|---|---|
| build: Metal toolchain (27B47, pinned) | 0 | 18 s | |
| build: Rust, rzup guest toolchain, protoc | 0 | 60 s | |
| build: Metal worker and CLI (`ASSEMBLE_BUILD_ONLY=1 assemble-macos.sh`) | 0 | 314 s | peak used 12.57 GB, **min free 1.22 GB** (RC2: 2.05 GB) |
| build: delete intermediates | 0 | 3 s | 12.55 -> 4.83 GB |
| build: package and check (`check-macos-kit.py` ok with 0 archives; `test-check-macos-kit.sh` **16/16**) | 0 | 60 s | |
| cpu-tests: tests that need no GPU (2 suites, **62 + 131 passed**; `test-metal-tc` 18/18) | 0 | 283 s | min free 2.07 GB |
| metal-probe: install, probe, Groth16 download (158 s), one fibonacci proof (verified, wrap 1.75 s) | 0 | 165 s | min free 3.18 GB |

- **Disk margin.** The integrated build needs 0.83 GB more disk than RC2 (main's crates), which leaves
  1.22 GB free at the build job's peak on a 14 GB runner (open issue 4).
- **Checks on the uploaded kit.** `check-macos-release.sh` on the tarball: rc 0. `check-macos-kit.py
  --version 0.1.0 --commit 8b448a0… --require-validated`: ok.

## 2. Install as a new user (sandbox HOME, quarantined download)

**Setup.** Sandbox `HOME=scratch/w10/rc1/home`, entered through `env -i` with the system `PATH` plus
`~/.zkminer` (the README's `export PATH`). The tarball was put in `~/Downloads` and marked as a Safari
download (`com.apple.quarantine 0083;…;Safari;…`).

The kit README (`packaging/macos/README.md`), followed literally:
- **Checksums.** `shasum -a 256` of the tarball equals its `SHA256SUMS` line. `shasum -a 256 -c` of the
  kit's own `SHA256SUMS`: OK for all 9 files.
- **Unpack.** `tar -xzf` passes the quarantine flag to every file, and `spctl --assess` rejects
  `zkminer`.
- **`./install.sh --with-groth16`:** rc 0 in 80 s.
  - It checked the kit (commit `8b448a08b665`) and installed both binaries without the quarantine flag
    (`xattr -l` is empty).
  - It said the kit has no offline archives, so the first start compiles the pipelines, and
    downloaded and installed Groth16 v0.2.0 (5.4 GB).
  - Its "Next" list: `init`, `benchmark`, `run`, and where `BUILDINFO` is.
- **`zkminer help`:** ok.
- **`zkminer init`:** rc 0. It wrote `config.toml` for 743111: router `0xD931…Ed58`, token
  `0x4695…36cc`.
- **`zkminer benchmark`:** rc 0, real numbers (section 3.6).
- **`tools/macos-smoke.sh` from the kit:** `RESULT: ok (exit 0)`.
- **`./install.sh --warm`:** rc 0, warm-up 2 s.
- **`./install.sh --uninstall`:** removed the CLI and the worker. It left `config.toml`, `~/.risc0` and
  the pipeline cache, as documented.

**Where the docs are wrong or unclear.** These are RC2's items. None was fixed, because W10-DOC (which
fixes most of them) is stacked on the unmerged W10-BENCH. None blocks an install.
1. **`docs/macos-beta.md` describes a kit that is not the release kit** (maintainer doc).
   - "Build the kit" defaults to `AOT_ARCHES=applegpu_g17s`.
   - "Offline archives" says the kit "ships a `macos27` set".
   - The "CI" section is the pre-B9-CI sketch ("The workflow files are not part of this item",
     `--no-aot`).
   - `RELEASE-DEPS.md`'s runner recipe still uses `xcodebuild -downloadComponent`.
2. **`release.yml`'s notes say `sha256sum -c SHA256SUMS`.** On a Mac that only downloaded the macOS
   tarball, this exits 1 because the other platforms' files are missing. Use `--ignore-missing`.
3. **Gatekeeper in a terminal without a GUI session** (not retested). Over SSH, a quarantined binary
   hangs with no output. The README describes only the desktop dialog.
4. **`zkminer init` step 3 says "Stake it (via the Wallet screen)"**, but `zkminer stake` exists. The
   README's "Then:" stops at `zkminer run`, which needs a key, gas, tHEMI and a stake first.
5. **`zkminer benchmark` on a Mac:**
   - It takes 261 s on the M5 Max (main's warm-up plus zkop-mix scoring), and the README gives no
     duration.
   - It prints Linux and NVIDIA advice: `nvidia-smi did not answer`, "CPU power monitoring
     unavailable. To enable, run: sudo chmod o+r /dev/cpu/0/msr".
   - New since the merge: "GPU power unavailable for the proving cards — device rows will carry the
     300W fallback, which feeds the profitability model directly". The profitability figure for a Mac
     therefore assumes 300 W (open issue 6).
   - It re-logs the worker's INFO lines at WARN.
   - Its failure path is in section 3.6.
6. The README's first-start figure is "60.3 s measured". This RC measured 57.8 s, which is consistent.

## 3. The installed worker on this Mac (M5 Max, 36 GB, macOS 27.2.1)

All GPU runs went through `gpu-run` (heavy). Each used the sandbox's installed
`~/.zkminer/provers/zkminer-prove-risc0-metal` with `env -i`, so budgets were passed explicitly as
`RISC0_METAL_MAX_WORKING_SET_BYTES`. Load average was 0.5-3.5, and no other GPU work ran.

### 3.1 Full `--benchmark`, default budget (one run)

| program | cycles | STARK | c/s | wrap |
|---|---|---|---|---|
| fibonacci (main's discarded warm-up) | 32,768 | 0.28 s | | 1.61 s |
| sha256-chain | 46,137,344 | 50.97 s | 905K | 1.59 s |
| ecdsa-verify | 65,011,712 | 71.77 s | 906K | 1.58 s |
| bigint-mul | 27,525,120 | 30.73 s | 896K | 1.60 s |
| memory-merkle | 7,340,032 | 8.33 s | 881K | 1.59 s |
| chacha-mix | 8,404,992 | 9.80 s | 857K | 1.59 s |
| **all six** | 154,451,968 | **171.88 s, 898.6K c/s** | | |
| zkop-mix scoring (main; no wrap) | 4,194,304 + 61,865,984 | 4.98 + 68.73 s | | |

- **Against RC2** (169.92 s, 909.0K c/s): **+1.15 %**. **Against BASELINES '3.1'** (169.56 s): **+1.37 %**.
  Both are below the 1.5 % threshold.
- The same code measured 170.82 s in W10-PIN and 170.66-171.06 s in W10-INT. W10-INT's like-for-like
  A/B of the full suite (old vs merged binary, same session) showed no change. The run started at a
  load of 3.4, just after the cold-start compile.
- **Peak footprint 14.72 GB** (baseline 14.69, RC2 14.68). Wraps 1.58-1.61 s. Wall 268 s, which now
  includes the warm-up and the zkop-mix proofs.

### 3.2 Interleaved A/B, `BENCH_ONLY=memory-merkle --benchmark`, 5 pairs per budget

- A = the reference 3.1 worker in `~/.zkminer/provers` (sha256 `9161605e…`, as in RC2). B = the
  installed kit worker.
- The order was A B A B …, one `gpu-run` per arm, in one session.

| budget | A STARK median [min-max] | B STARK median [min-max] | B-A per pair, median [range] | A-vs-A spread | wrap A / B | peak footprint A / B |
|---|---|---|---|---|---|---|
| default (po2 20) | 8.38 [8.37-8.41] s | 8.43 [8.42-8.43] s | +0.04 [+0.02, +0.06] s | 0.04 s | 1.59 / 1.58-1.59 s | 13.19 / 13.95-13.96 GB |
| 8 GiB (po2 19) | 10.38 [10.29-10.41] s | 10.44 [10.40-10.50] s | +0.06 [+0.01, +0.16] s | 0.12 s | 1.74 / 1.72-1.73 s | 7.32 / 8.31 GB |
| 4 GiB (po2 18) | 14.07 [14.07-14.18] s | 14.22 [14.22-14.27] s | +0.15 [+0.04, +0.16] s | 0.11 s | 1.73-1.74 / 1.71-1.72 s | 5.01-5.05 / 5.78-5.79 GB |

- **The arms are not like for like.** Since the merge, B's `BENCH_ONLY` first proves main's discarded
  fibonacci warm-up, with its Groth16 wrap. A's memory-merkle is its process's first proof. This
  matches W10-INT's open issue 6 and its `BENCH_ONLY` A/B (+0.05 / +0.08 s, +0.8-1.0 GB). That item's
  like-for-like full-suite A/B showed every program unchanged.
- **Default and 8 GiB:** inside the A-vs-A spread.
- **4 GiB:** +1.1 %, slightly above the spread (0.15 vs 0.11 s). It is the same order effect, measured
  larger here than in W10-INT. It does not show in the full-suite numbers (W10-INT 4 GiB full suite:
  291.83 vs 291.67 s).
- **The higher B peaks** are the warm-up's wrap and stay inside each budget's plan. 8.31 GB = 7.74 GiB.
- **Against BASELINES** (8 GiB ~767K c/s, 4 GiB ~603K c/s): `c/s` is not comparable, because po2 now
  changes the memory-merkle cycle count. RC2's own runs were 10.23 s / 13.93 s; A here is 10.38 / 14.07 s.
- 15 A-arm receipts and all B receipts verified (section 3.5).

### 3.3 Budgets, sequences, hosts

- **memory-merkle at 8 GiB** (po2 19, 7,864,320 cycles), 3 runs: STARK 10.39 / 10.40 / 10.41 s,
  755-757K c/s, wrap 1.72 s. Peak footprint 7.60-8.31 GB. W10-PIN measured 10.43 s.
- **memory-merkle at 4 GiB** (po2 18, 8,388,608 cycles), 3 runs: STARK 14.18 / 14.22 / 14.23 s,
  590-591K c/s, wrap 1.71-1.72 s. Peak footprint 5.79 GB. W10-PIN measured 14.21 s.
- **4 GiB, Groth16 after keccak.** The test
  `a_tight_worker_wraps_after_keccak_and_releases_the_key_between_jobs` was built from this commit and
  pointed at the installed worker (`ZKMINER_B9_WORKER`, keccak guest from `deps/risc0-3.1`). It ran
  twice:
  - rc 0 both times. The warm-up, fibonacci, keccak, memory-merkle and fibonacci were all wrapped
    (256-byte seals).
  - 5 of 5 key releases per run, each "3882.3 MiB freed (prover layout split_h + tw_lent)".
  - keccak took 4.95 s and 4.93 s.
- **20 sequential jobs in one worker at 4 GiB.** Test `m9_proofs_in_one_worker`: installed worker,
  Warmup first, fibonacci 4,587,520 cycles, 9.55-9.72 s each.
  - Idle footprint after proof 1: 4834 MiB. Proofs 2-20: 4387-4781 MiB. The last one, 4764 MiB, is
    below the first.
  - Lifetime peak 6206 MiB (RC2 6208), 21 key releases. **No footprint growth.**
- **Simulated 16 GB host.** Settings: `ZKMINER_METAL_HOST_RAM_BYTES=16 GiB`, HAL limit 10.67 GiB,
  `ZKMINER_CUDA_VRAM_BYTES=8 GiB`. The worker planned 8 GiB at po2 19.
  - memory-merkle: 10.31 s, wrap 1.73 s, footprint 8.37 GB.
  - **Full suite: 206.49 s** (six programs; W10-INT 206.49 s), plus zkop-mix 6.10 + 86.47 s. Every
    program was wrapped (1.73-1.74 s) and verified.
  - **Peak footprint 9.39 GB.** RC2 measured 9.34 GB. W10-INT's no-wrap release keeps the scoring proof
    from raising it to 10.99 GB. This is inside a 16 GB Mac's 11.5 GiB allowance.
- These are all simulated budgets on this Mac. No real 16 GB Mac has been measured.

### 3.4 First start

`BENCH_ONLY=fibonacci --benchmark` (now the warm-up alone), timed as process wall:

| case | wall | pipelines |
|---|---|---|
| **cold first start** (first run in the new HOME, `MTL_SHADER_CACHE_SIZE=0`, no archives) | **57.8 s** | built in 55.5 s (cold): rv32im+zkp 55.4, recursion 31.3, keccak 20.5, groth16 31.3 (in parallel); zkp 72 PSOs 17.7 s, rv32im 13 PSOs 37.8 s |
| second start (runtime archive kept) | 2.48 s | 72 + 13 hits |
| third start, cold OS shader cache | 2.54 s | 72 + 13 hits |

- The macOS 26 fallback (a `macos26`-keyed archive set misses cleanly, then everything compiles) was
  shown in RC2 with the same 5 metallib digests, and was not repeated.

### 3.5 Correctness

- **Stock crates.io risc0-zkvm 3.1.0 verifier** (`tools/stock_verify31`, RC2's build; selector
  `e71e6620`).
  - **74 of 74** Groth16 receipts pass `STOCK 3.1 VERIFY: OK`. They come from the full suite, every
    memory-merkle run at the default, 8 and 4 GiB budgets, the A/B (including 15 A-arm receipts), the 16
    GB host and the three starts. By program: fibonacci 27, memory-merkle 39, and the other four 2 each.
  - **Receipt types.** The worker returns Groth16 receipts only. Composite and succinct receipts stay
    inside it, and it verifies them there (zkop-mix's no-wrap path, the keccak and M9 tests).
  - For this risc0 tree (`37b434755` = W10-GATE's `404ae8dcf`, the same tree), W10-GATE's
    `run_matrix.sh` judged composite, succinct and Groth16 receipts at the default, 8 and 4 GiB
    budgets: **30/30 OK**.
- **3.0 receipts are rejected.** B9-M26's 30 receipts from the 3.0 producer (composite, succinct and
  Groth16; fibonacci, merkle, keccak, compose; default, 8 and 4 GiB) are all **REJECTED**, plain and
  with `--relabel-as-31`: **60 of 60**.
- **CLI end to end on a local chain.** Test binary `crates/zkminer-cli/tests/localnet.rs`, built from
  this commit, with `ZKMINER_LOCALNET_ZKMINER` set to the installed CLI and
  `ZKMINER_LOCALNET_RISC0_WORKER` to the installed worker. Anvil forked live 743111.
  - **`mines_the_claimable_jobs`** (`ZKMINER_LOCALNET_MINE=1`): **rc 0 in 137 s.** 4 claimable risc0
    jobs (Full, Fields, NoneForUs, FullForAnother) were each claimed, proved on Metal with a Groth16 wrap,
    fulfilled, and paid 4.95 tHEMI (5 tHEMI minus the 1 % fee). The 8 non-claimable jobs were not
    claimed.
  - **`refuses_to_claim_without_a_matching_verifier`** (the 3.0 selector): rc 0, 53 s.
  - **`fulfils_with_a_replayed_receipt`** (mock worker): rc 0, 107 s.
- **B9-CHAIN live read-only checks** against `https://testnet.rpc.hemi.network/rpc`, head 7248536:
  - **handoff section 13 tests 1-4** (`live/checks.log`):
    - chain 743111;
    - the router, staking, registry and token wiring;
    - `getAdapter` for the three ids: status 1, ratio 15,000, min stake 1e20, fee 100;
    - the risc0 verifier: `SELECTOR 0xe71e6620`, `VERSION "3.1.0"`;
    - live `getProofNonce`;
    - 345 `JobSubmitted` logs.
  - **`live_743111`, built from this commit: 4/4.**
    - `the_live_deployment_verifies`: `verify_deployment` passes on "Hemi testnet (743111,
      2026-11-16)".
    - `the_proof_nonce_matches_the_live_router`.
    - `every_live_job_descriptor_decodes`: 345 logs.
    - `the_abandoned_stack_is_refused_live`.
  - **`abi_pins`: 3/3.** The cross-check against a hemiprove-contracts checkout
    (`ZKMINER_CONTRACTS_REPO`) was not run, because no checkout is on this Mac.
  - **The decisive check** (`scripts/verify_live.sh`, `eth_call` only), with this kit's fibonacci and
    memory-merkle receipts:
    - `Registry.verifyProof` and the native verifier both accept them.
    - A flipped seal nibble and a journal one byte too long revert `0x439cc0cd`.
    - The 3.0 fixture (`73c457ba`) and a 3.1 seal relabelled `73c457ba` revert with the
      selector-mismatch error `0xb8b38d4c`.

### 3.6 `zkminer benchmark` through the CLI

- **Working worker:** `zkminer benchmark` in the sandbox gives **rc 0 in 261 s, with real numbers.**
  - 2.71 MzkOP/s.
  - Device row: po2 20, 892.6K c/s, Groth16 1.6 s.
  - Per program: sha256-chain 50.97 s, ecdsa-verify 71.27 s, bigint-mul 30.63 s, memory-merkle 8.32 s,
    chacha-mix 9.72 s, zkop-mix 68.36 s.
  - It cached nothing simulated.
- **Forced worker failure (RC3, `8b448a0`): FAIL.** Each case used its own HOME with the same config
  and CLI:

| case | expected | got |
|---|---|---|
| the worker exits 3 at start-up (a script printing "forced failure") | non-zero exit, the worker's error, no table | **rc 0**. Header "Workers: none — install prover binaries in ~/.zkminer/provers (CPU/simulated only)". The table is all **`simulated`** (e.g. chacha-mix 23,734,729,494 c/s), followed by "-0.00 MzkOP/s". The log has "Benchmark failed for risc0:metal:0: Backoff: waiting 4.78s before respawning" |
| the real worker, warm-up fails (`RISC0_METAL_MAX_WORKING_SET_BYTES=1 GiB`: "Metal working-set budget exceeded") | the same | **rc 0**. Header "Workers: risc0:metal:0", then the same simulated table, and "ERROR Benchmark failed for risc0:metal:0: Worker risc0 process died (EOF)" |

- This is RC2's section 2 item 5 and open issue 6. The fix is W10-BENCH:
  - non-zero exit and no simulated table;
  - the slot's last spawn or handshake error goes into the failure line and the header;
  - a `benchmark_cli.rs` test.
- W10-BENCH was not merged. Its last review reproduced the remaining defect, and the branch and its
  worktree are kept for the next round.
- Nothing from the failed runs reached the config, so `zkminer run` would not use those numbers. Even
  so, a user is told the benchmark worked. This blocked the tag.

**Step 0 (kit from `f9f535b`, sandbox `HOME`, quarantined download; logs in
`scratch/w10/BETA-FIX/out/rc5-*`, details in `docs/metal-port-notes/BETA-FIX.md`):**

| case | result |
|---|---|
| the worker exits 3 at start-up | **rc 1**, no table. Header `Workers: risc0:metal:0 (failed to start; see below)`. `BENCHMARK FAILED: nothing was measured or saved.` and `risc0:metal:0 (Apple M5 Max): could not start: Handshake ... process died (EOF) (the worker's last output: forced failure) ...`, the smoke and quarantine advice. No `benchmarks.json` |
| the real worker, `RISC0_METAL_MAX_WORKING_SET_BYTES=1 GiB` | **rc 1**, no table. `Worker risc0 process died (EOF) (the worker's last output: Metal working-set budget exceeded: ...)`. No `benchmarks.json` |
| working `zkminer benchmark` | **rc 0** in 271.5 s: 2.72 MzkOP/s, device row po2 20, 891.6K c/s, Groth16 1.6 s |
| install (README steps), `init`, `help`, `macos-smoke.sh`, `install.sh --warm`, `--uninstall` | all rc 0; `spctl` rejects the quarantined download, the installed copies are unquarantined |
| `check-macos-release.sh`, `check-macos-kit.py --require-validated`, `test-check-macos-kit.sh` (16/16), `test-assemble-macos.sh` (44/44) | ok |
| full worker `--benchmark` (installed worker, default budget) | six programs **171.41 s, 901.1K c/s** (+1.09 % vs 169.56 s; RC3 171.88 s), wraps 1.59-1.60 s, peak footprint 14.73 GB |
| stock crates.io 3.1.0 verifier on its 6 Groth16 receipts | **6/6 OK**; a receipt against another image id is rejected |

### 3.7 Not run here

Each item says why:
- A real macOS 26 Mac, a real 16 GB Mac, and GPU families other than `applegpu_g17s`: none is
  available.
- The R17 audit, the stress run and the fork's Metal suites: there is no kernel or risc0 change since
  W10-GATE's gates, which ran on this tree. The 5 metallib digests are unchanged, and so is the
  compiler (27B47).
- A Linux or Windows build of the integrated branch: there is no such host. CI on `main` will be the
  first one (open issue 2).
- The macOS 26 AOT fallback and the 3.0 producer: unchanged inputs, covered by RC2 and B9-M26.
- Live-chain transactions: forbidden here (see the checklist).

## 4. macOS 26: what is validated

Unchanged since RC2. No kernel, metallib or compiler change has gone in since.
- **B9-M26 on this Mac:** 26.0-target AIR 2.8 kernels, `ir_scan` A=0 S=0, stress clean, suites ×2,
  stock-verifier matrix, A/B, API audit.
- **Two macOS 26.6.2 VM sessions** (`scratch/w9/B9-M26/vm/out-gui/RESULTS.md`, `…/out-rc1/RESULTS.md`)
  passed:
  - install, quarantine and `spctl`;
  - `install.sh`, the Groth16 download, `init`;
  - the clear missing-key error, the 8 GiB / po2 19 plan, and loading of all 5 metallibs.
- The VMs' paravirtual GPU is inconclusive for proving. It is how the benchmark failure in section 3.6
  was found.
- **Still required:** a real Apple Silicon Mac on macOS 26 with at least 16 GB (checklist step 6).

## 5. Open issues

1. **Closed by step 0:** W10-BENCH and W10-DOC are merged with the BETA-FIX startup-error fix
   (`f9f535b`, via `item/W10-BFIX`; no conflicts). Section 2's doc items 1-5 are W10-DOC's fixes.
2. **Linux (CUDA, ROCm, Intel) and Windows have not been built against the fork pin.**
   - W10-GATE makes every fork change behave like `release-3.1` off Metal by default, and the prover
     crate type-checks for Linux.
   - Main's CI will be the first real build: after the push, watch `build-docker.yml`,
     `build-windows.yml` and `e2e.yml` on `main`.
3. **Neither repository has these commits on GitHub yet.** `https://github.com/hemilabs/risc0` has no
   `37b434755` until step 1 of the checklist.
4. **Disk on the 14 GB runner.** The build job's minimum free space fell from 2.05 GB (RC2) to 1.22 GB.
   Main's crates are the likely cause.
   - Watch `macos-disk.sh "after the build"` on the real runner.
   - If it fails, prune more before packaging or give the runner more disk.
5. **The 4 GiB `BENCH_ONLY` A/B is +1.1 %** (section 3.2): the warm-up-order effect, and not a change
   in the suite.
6. **Mac messages in `zkminer benchmark`** (from main):
   - the 300 W GPU power fallback "feeds the profitability model directly";
   - the `nvidia-smi` and `/dev/cpu/0/msr` warnings.

   A Mac's profitability estimate therefore uses 300 W, not a measured or Apple-typical figure. This
   needs a decision or a fix.
7. **Carried over from RC2:**
   - every Mac has a ~1-minute first start (no AOT archives);
   - B9-CI's runner items (nothing has run on the real runner; its SDK changes the metallib digests;
     the `xcode` toolchain mode is untested);
   - B9-FX (the fixture symlink guard) is unmerged;
   - `worker --benchmark` exits 0 when a program fails (documented in the README);
   - no kit-aware missing-Groth16 message;
   - the unpinned `Jimver/cuda-toolkit` tag in `build-windows.yml`;
   - the release notes' checksum command;
   - the `w7` dispatcher table and debug-only knobs (B9-G1, B9-ZK).
8. Not measured: a real 16 GB Mac (including its cold first start on an M1-M4), other GPU families, a
   real macOS 26 runtime, and `build-macos.yml` on the real runner.

## 6. User checklist

Nothing below was executed. The local checkouts' push URLs are disabled on purpose, so each command
names its URL.

0. **Done (2026-11-19, `f9f535b`; section 3.6 "Step 0").** Before pushing: merge W10-BENCH, then
   W10-DOC, then repeat the short RC. This changes the zk-miner sha, not the risc0 pin.
   - Rebuild the kit with `build-macos.yml`'s steps (`scripts/ci/assemble-macos.sh`, `AOT_ARCHES=none`).
   - Re-run the checks for what changed:
     - section 3.6, both forced failures: non-zero exit, the worker's error, no table;
     - `zkminer benchmark` with a working worker: rc 0;
     - the kit README steps (section 2);
     - `check-macos-release.sh`;
     - one full `--benchmark`;
     - the stock verifier on its receipts.
   - Then update this file's sha256 and commit.

1. **Push the risc0 fork unchanged.** `Cargo.lock` pins this exact sha:

   ```sh
   cd /Users/user/zkminer/deps/risc0-3.1
   git rev-parse zkminer/metal-3.1      # must print 37b434755ce77dd1354d957a7b61912aa4359423
   git push git@github.com:hemilabs/risc0.git 37b434755ce77dd1354d957a7b61912aa4359423:refs/heads/zkminer/metal-3.1
   git ls-remote https://github.com/hemilabs/risc0 refs/heads/zkminer/metal-3.1   # must print 37b434755…
   ```

2. **Push zk-miner.** `main` (`c030355`) is an ancestor of `metal-3.1`, so this is a fast-forward:

   ```sh
   cd /Users/user/zkminer/zk-miner-3.1
   git fetch https://github.com/hemilabs/zk-miner main && git merge-base --is-ancestor FETCH_HEAD metal-3.1 && echo fast-forward
   git log --oneline -1 metal-3.1        # this file's commit (or the one after step 0)
   git push git@github.com:hemilabs/zk-miner.git metal-3.1:refs/heads/metal-3.1     # keep the branch
   git push git@github.com:hemilabs/zk-miner.git metal-3.1:main                     # fast-forward main
   ```

   If `main` is protected, open a PR and merge it with a merge that keeps the history. A squash or
   rebase merge changes the shas and breaks the fast-forward relationship.

   ```sh
   gh pr create --repo hemilabs/zk-miner --base main --head metal-3.1 --title "macOS (Metal) beta on RISC Zero 3.1"
   ```

3. **Repository variable** (optional). The workflow falls back to `zk-runner-mac-new`, so set the
   variable only for a different runner label. Never register this Mac as a runner.

   ```sh
   gh variable set ZKMINER_MACOS_RUNNER --repo hemilabs/zk-miner --body zk-runner-mac-new
   ```

4. **CI on the real runners.**
   - The push to `main` triggers `build-macos.yml`, `build-docker.yml` and `e2e.yml` (by path). Run
     `build-windows.yml` by hand.
   - `build-macos.yml` needs build, cpu-tests and metal-probe to pass (metal-probe is informational).
     Compare its kit's `BUILDINFO` with "The candidate": `min_macos=26.0`, `metal_compiler … 32023.922`,
     `risc0_rev 37b434755…`, no archives. Watch the build job's disk line (open issue 4).
   - The Linux and Windows builds are the first builds of the fork pin there (open issue 2).

   ```sh
   gh workflow run build-macos.yml   --repo hemilabs/zk-miner --ref main -f metal_toolchain=pinned
   gh workflow run build-windows.yml --repo hemilabs/zk-miner --ref main
   gh run list --repo hemilabs/zk-miner --branch main --limit 10
   ```

5. **HemiProve deployment of 2026-11-16 on 743111** (handoff `/Users/user/zkminer/zkminer-handoff-743111.md`).
   - Main's own update (`deployment.rs`, ABIs re-vendored from hemiprove-contracts `3bc441d`) is now the
     code path. `3bc441d` equals B9-CHAIN's `8e1808b` except for `LICENSE`.
   - This RC re-ran, against the live chain, read-only:
     - handoff tests 1-4;
     - `live_743111` 4/4;
     - `abi_pins` 3/3;
     - `Registry.verifyProof` with this kit's receipts.
   - On a fork it re-ran test 6 (section 3.5).
   - After the governance handoff, check that `zkminer run` still passes its deployment checks. If you
     have a hemiprove-contracts checkout at `3bc441d`, also run
     `ZKMINER_CONTRACTS_REPO=<checkout> cargo test -p zkminer-chain --lib`.

6. **macOS 26 on real hardware (user decision: supported).**
   - **Before tagging**, on a real Apple Silicon Mac with macOS 26 and at least 16 GB: ideally a 16 GB
     M1-M4, plus other GPU families (an M1/M2 `applegpu_g13*`/`g14*` and an M3/M4 `g15*`/`g16*`) if you
     can.
   - In the extracted CI kit:

     ```sh
     shasum -a 256 zkminer-0.1.0-macos-arm64.tar.gz      # against the CI run's SHA256SUMS
     tar -xzf zkminer-0.1.0-macos-arm64.tar.gz && cd zkminer-0.1.0-macos-arm64
     ./install.sh --with-groth16
     tools/macos-smoke.sh                                # scripts/ci/macos-smoke.sh in the repository
     ~/.zkminer/provers/zkminer-prove-risc0-metal --metal-arch
     ~/.zkminer/provers/zkminer-prove-risc0-metal --benchmark
     ~/.zkminer/zkminer init && ~/.zkminer/zkminer benchmark
     ```

   - Expect the first start to compile the pipelines for a minute or more. Then expect every program
     "verified", the smoke script's `RESULT: ok`, and `zkminer benchmark` exiting 0 with real numbers.
   - Keep the logs, and note the chip, RAM, macOS build and first-start time.

7. **Funded-key acceptance tests** (handoff section 13), live on 743111:
   - Use a staked prover key, with tHEMI from the HemiProve team: at least 100 per lock, and 1,000 for
     custom-verifier jobs. You also need testnet ETH. Keep the transaction hashes.
   - Tests for the Mac beta: **5, 6, 10, 11, 13, 14, 15, 16, 17, 18, 19**.
     - Schedule 19 (the pause drill) with the team.
     - For 14, expect `InsufficientFreeStake`, not `Panic(0x01)` (B9-CHAIN).
   - Not applicable to this build: **7, 8, 9, 12** (SP1 nonce marker, PLONK, `claimAndFulfillAssigned`).

8. **Cut v0.1.0** once steps 0-7 are done.
   - `release.yml` requires the tag to equal `[workspace.package].version` (`0.1.0`).
   - It builds Linux, Windows and the macOS kit (`build-macos.yml`, pinned 27B47) from the tagged
     commit.
   - Fix the release notes' checksum line first (`--ignore-missing`). Recommended.
   - Run a dry run on `main` first (it publishes nothing), check its assets, then tag:

   ```sh
   gh workflow run release.yml --repo hemilabs/zk-miner --ref main -f dry_run=true -f gpu_validation=true
   gh run watch --repo hemilabs/zk-miner        # all jobs green; download and inspect the assets
   git -C <checkout of main> tag -a v0.1.0 -m "zk-miner 0.1.0 (macOS beta: Apple Silicon, RISC Zero 3.1; unsigned)"
   git -C <checkout of main> push git@github.com:hemilabs/zk-miner.git v0.1.0
   ```

   Compare the release's macOS kit `BUILDINFO` with this RC. Its sha256 will differ (commit, SDK).
