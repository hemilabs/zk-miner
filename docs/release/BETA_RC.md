# macOS beta, release candidate 2 (RISC Zero 3.1 on Apple Silicon)

2026-11-18. This is the second release-candidate check of the zk-miner macOS (Metal) beta kit, after the
BETA-FIX round (`docs/metal-port-notes/BETA-FIX.md`). The kit was built the way the CI job builds it, then
installed and used as a new user would. It ships **unsigned**: no Developer ID and no notarization.
Evidence and scripts are in `/Users/user/zkminer/scratch/w9/rc2/` (`ci/`, `logs/`, `out/`). Release
candidate 1 (kit `54296dc6…`, commit `39978cd`) is in this file's history (commit `ca07773`); RC2 replaces
it, and nothing in RC1's results changed except where this file says so.

> **Superseded pin (Wave 10).** This file records RC2 as built. Since then GitHub main was merged in
> (W10-INT) and the risc0 pin moved to `zkminer/metal-3.1` @ `37b434755ce77dd1354d957a7b61912aa4359423`
> (W10-PIN, `docs/metal-port-notes/W10-PIN.md`; RELEASE-DEPS.md has the current pin). The shas in the
> checklist below (section 6) are RC2's: use the current ones, and redo the RC on them, before pushing.

## The candidate

| | |
|---|---|
| kit | `zkminer-0.1.0-macos-arm64.tar.gz`, 121,021,779 bytes (191 MB unpacked) |
| **sha256** | **`02e5ca12e34e83a4fc5ea96d8c9d3ab7a6aa8c838aa3aee345020823388cdc9e`** |
| where | `/Users/user/zkminer/scratch/w9/rc2/dist/` (the tarball and its `SHA256SUMS`) |
| zk-miner | `metal-3.1` @ `304f4865049939f7226d852549ba45ac4d1ac0d5` (`BUILDINFO commit`, `commit_dirty=no`) |
| risc0 | hemilabs/risc0 `zkminer/metal-3.1` @ `d94ef65015f4753c5496ad7302f15c44513370f3` (`BUILDINFO risc0_rev`, `risc0_src=git`) |
| minimum macOS | 26.0: binaries minos 26.0, metallibs target 26.0 (`check-macos-release.sh`: "a self-contained arm64 kit for macOS 26.0 and later") |
| Metal compiler | `Apple metal version 32023.922 (metalfe-32023.922.4)` (27B47, pinned, `metal_compiler_validated=yes`), SDK 27.2 |
| offline archives | none (`aot_arches=`; the CI build uses `AOT_ARCHES=none`). The README says so, and `check-macos-kit.py` enforces it |
| Groth16 component | not bundled; v0.2.0, sha256 `173354ab…57e5`, fetched by the worker or `install.sh --with-groth16` |

The commit that adds this file changes only `docs/release/BETA_RC.md`, which is not an input of the kit.
A kit built by CI for a tag still differs in its `BUILDINFO commit`, and so in its tarball sha256. On the
runner's Xcode 26 SDK, `metal_sdk` and the metallib digests also change (B9-M26, B9-CI).

The worker's 5 metallib digests (`tools/build-metal-aot.sh --worker-digests`) are the same as RC1's and
B9-M26's: `261571a7…`, `62805de6…`, `c934c282…`, `cf978db9…`, `f42fd572…`. No Rust, kernel or risc0 change
went in between RC1 and RC2; the only changes are docs, `install.sh`'s "Next" line and the kit checks.

## 1. Mirror, pin and CI build

- **Mirror and pin.** I fetched `scratch/w9/mirror/risc0.git` from `deps/risc0-3.1`. Its
  `zkminer/metal-3.1` is `d94ef6501`, which is:
  - the `deps/risc0-3.1` HEAD (`Merge metal/B9-4G`, clean tree);
  - the rev that zk-miner's `Cargo.toml` (8 `[patch]` entries) and `Cargo.lock` pin.

  The brief names `84df3e8c0`. That is the tools unit's head after merge 1. Merges 2 and 3 (recursion
  `045ff92b6`, groth16 `d94ef6501`) moved HEAD on after it, so `d94ef6501` is the right pin.
- **The CI jobs.** B9-CI's harness (`ci/sim.py`, the BETA-FIX copy with only its paths changed) ran every
  step of `.github/workflows/build-macos.yml` at `304f486`, in order, exactly as written:
  - all three jobs: build, cpu-tests and metal-probe;
  - a fresh clone of `metal-3.1`, inside a 14 GB APFS disk image (`hdiutil`, 13.79 GB usable; detached
    and deleted afterwards);
  - a fresh `HOME` and `CARGO_HOME` inside the image, `CARGO_BUILD_JOBS=5`;
  - the hemilabs/risc0 URL sent to the mirror with `CARGO_NET_GIT_FETCH_WITH_CLI=true` and a
    `GIT_CONFIG_*` `insteadOf` rule.

  The brief's single rule also rewrites `hemilabs/risc0-sppark`, because git matches URL prefixes, and
  then the sppark fetch fails (RC1 `ci/logs/attempt1/`). The run therefore added RELEASE-DEPS.md's
  second, identity rule for sppark. This matters only for local CI replays with a mirror.

| job / step | rc | wall | disk (of 13.79 GB) |
|---|---|---|---|
| build: Metal toolchain (27B47, pinned) | 0 | 18 s | |
| build: Rust, rzup guest toolchain, protoc | 0 | 54 s | |
| build: Metal worker and CLI (`ASSEMBLE_BUILD_ONLY=1 assemble-macos.sh`) | 0 | 293 s | peak used 11.74 GB, **min free 2.05 GB** |
| build: delete intermediates | 0 | 2 s | 11.72 -> 4.84 GB |
| build: package and check (`check-macos-kit.py` ok with 0 archives; `test-check-macos-kit.sh` **16/16**, including the new 2l, 2m and 2n) | 0 | 61 s | |
| cpu-tests: tests that need no GPU (2 suites, 60 + 128 passed; `test-metal-tc` 18/18) | 0 | 262 s | min free 2.88 GB |
| metal-probe: install, probe, Groth16 download (49 s), one fibonacci proof (verified, wrap 1.74 s) | 0 | 57 s | min free 3.20 GB |

The kit from the build job's upload is the candidate above. `check-macos-release.sh` on the tarball: rc 0,
"macOS 26.0 and later". `check-macos-kit.py --version 0.1.0 --commit 304f486… --require-validated`: ok.

## 2. Install as a new user (sandbox HOME, quarantined download)

- **Setup.** The sandbox is `HOME=scratch/w9/rc2/home`, entered through `env -i` with the system `PATH`
  plus `~/.zkminer` (the README's `export PATH`). The tarball was copied to `~/Downloads` and marked as a
  Safari download (`com.apple.quarantine 0083;…;Safari;…`).
- **Steps**, from the kit README (`packaging/macos/README.md`), literally:
  - `shasum -a 256` of the tarball equals the line in the release's `SHA256SUMS`, and `shasum -c` of the
    kit's own `SHA256SUMS` is OK for every file;
  - `tar -xzf`: the quarantine flag reaches every extracted file, and `spctl` rejects `zkminer`;
  - `./install.sh --with-groth16`: rc 0 in 74 s. It checked the kit and installed both binaries without
    the quarantine flag (`xattr -l` is empty). It said "this kit has no offline Metal archives; the
    first start compiles the GPU pipelines". It downloaded and installed Groth16 v0.2.0 (5.4 GB on disk).
    Its "Next" list: `zkminer init` ("first install only"), `zkminer benchmark`, `zkminer run`, and
    where the version is (`BUILDINFO`).
- **CLI checks.**
  - `zkminer help`: ok.
  - `zkminer init`: rc 0. It wrote `config.toml` for 743111 (router `0xD931…Ed58`, token `0x4695…36cc`).
  - `zkminer benchmark`: rc 0 in 201 s, cycle-weighted 904.8K c/s, Groth16 median 1.59 s.
  - `tools/macos-smoke.sh` from the kit after the install: `RESULT: ok`, `STOCK 3.1 VERIFY: OK`.
  - `./install.sh --warm`: rc 0, warm-up 2 s.
  - `./install.sh --uninstall`: removed the CLI and the worker. It left the config, `risc0-sys-rand.key`,
    `~/.risc0` and the pipeline cache, as documented.

**Where the docs are wrong or unclear.** None of these blocks the beta.

RC1's items 1 (the README described offline archives) and 5 (README disk size) are fixed: the README now
matches this kit (no archives, "about a minute" first start, 0.2 GB), and the 60 s it gives matches the
59.7 s measured below. Still open:

1. **`docs/macos-beta.md` describes a kit that is not the release kit** (RC1 item 2, B9-CI open issue 5).
   - "Build the kit" defaults to `AOT_ARCHES=applegpu_g17s`. Such a kit now fails `check-macos-kit.py`
     until the README's archive text is restored (documented in `assemble-macos.sh`).
   - "Offline archives: which families" says "The kit ships a `macos27` set". The release kit ships none.
   - Its "CI" section is still the pre-B9-CI sketch: "The workflow files are not part of this item",
     `--no-aot` and `macos-smoke.sh --no-proof`. The workflow uses `macos-metal-toolchain.sh`.
   - RELEASE-DEPS.md's runner recipe still uses `xcodebuild -downloadComponent`.
   - Fix: point both at `docs/ci-macos.md`. These are maintainer docs, not user docs.
2. **Release notes: `sha256sum -c SHA256SUMS` fails on a Mac** (new).
   - Where: `release.yml`'s notes say "Verify with `sha256sum -c SHA256SUMS`".
   - The problem: a Mac user downloads only the macOS tarball, and the release's `SHA256SUMS` also lists
     the Linux and Windows files. macOS's `/sbin/sha256sum` then prints "No such file or directory" and
     exits 1, even though the tarball's own line is OK (reproduced).
   - Fix: say `sha256sum -c --ignore-missing SHA256SUMS` (or `shasum -a 256 -c --ignore-missing`). The kit
     README's manual comparison is correct.
3. **Gatekeeper in a terminal without a GUI session** (RC1 item 3, not retested). A quarantined binary run
   directly over SSH hangs with no output. The README describes only the desktop dialog.
4. **`zkminer init` step 3 says "Stake it (via the Wallet screen)", but `zkminer stake` exists** (RC1
   item 4). The README's "Then:" stops at `zkminer run`, which needs a key, gas, tHEMI and a stake first.
5. **`zkminer benchmark` on a Mac.**
   - It takes 201 s on the M5 Max (several times longer on a base chip), and the README gives no duration.
   - It prints Linux-only advice: "CPU power monitoring unavailable. To enable, run:
     sudo chmod o+r /dev/cpu/0/msr".
   - It re-logs worker INFO lines at WARN.
   - **When the GPU warm-up fails** (seen in the main session's macOS 26 VM run with RC1's kit,
     `scratch/w9/B9-M26/vm/out-rc1/RESULTS.md`), it logs the error, then prints a *simulated* benchmark
     table (e.g. 3,009,039,154 c/s) and exits 0. Nothing is cached, so `zkminer run` does not use those
     numbers, but the user is told the benchmark worked. It should exit non-zero (code change; open
     issue 6).

## 3. The installed worker on this Mac (M5 Max, 36 GB, macOS 27.2.1)

All GPU runs went through `gpu-run` (heavy). Each used the sandbox's installed
`~/.zkminer/provers/zkminer-prove-risc0-metal` with `env -i`, so budgets were passed explicitly as
`RISC0_METAL_MAX_WORKING_SET_BYTES`.

**Machine state.** During my first three runs another session's macOS VM (Virtualization.framework,
paravirtual GPU) was compiling Metal pipelines: load average 6-7 and two busy `MTLCompilerService`s. Those
runs are kept as `out/*-vmbusy` and are not used below. Every run below came after the VM had exited, at a
load average of 0.9-3.3.

### Full `--benchmark`, default budget (one run)

| program | cycles | STARK | c/s | wrap |
|---|---|---|---|---|
| fibonacci | 32,768 | 0.29 s | | 1.63 s |
| sha256-chain | 46,137,344 | 50.56 s | 912K | 1.63 s |
| ecdsa-verify | 65,011,712 | 70.62 s | 921K | 1.59 s |
| bigint-mul | 27,525,120 | 30.50 s | 903K | 1.59 s |
| memory-merkle | 7,340,032 | 8.27 s | 888K | 1.58 s |
| chacha-mix | 8,404,992 | 9.68 s | 868K | 1.59 s |
| **all** | 154,451,968 | **169.92 s, 909.0K c/s** | | |

- **Against BASELINES '3.1'** (169.56 s, 910.9K c/s): **+0.21 %**, below the 1.5 % threshold. RC1 measured
  +0.73 %.
- Peak footprint **14.68 GB** (baseline 14.69). Wraps 1.58-1.63 s (baseline 1.57-1.59 s warm).
- Every program was wrapped and verified.
- The threshold did not require an A/B. I ran one anyway, because it is cheap.

### Interleaved A/B, memory-merkle `--benchmark`

- A = the reference 3.1 worker in `~/.zkminer/provers` (sha256 `9161605e…`).
- B = the installed kit worker.
- Order A B A B …, one `gpu-run` per arm, in one session, load 1.2-2.8.

| budget | pairs | A STARK median [min-max] | B STARK median [min-max] | B-A per pair, median [range] | wrap A / B | peak footprint A / B |
|---|---|---|---|---|---|---|
| default (po2 20) | 5 | 8.37 [8.36-8.39] s | 8.37 [8.34-8.38] s | -0.01 [-0.04, +0.01] s | 1.59 / 1.59 s | 13.19 / 13.16-13.20 GB |
| 4 GiB (po2 18) | 5 | 14.04 [13.98-14.06] s | 14.05 [14.01-14.08] s | +0.02 [-0.01, +0.03] s | 1.73 / 1.72 s | 5.01-5.02 / 4.92-4.94 GB |

**No change.** Both differences are inside the A-vs-A spread (0.03 s and 0.08 s).

### Budgets, sequences, hosts

- **memory-merkle at 8 GiB** (po2 19), 3 runs: STARK 10.23 / 10.24 / 10.25 s, 767-769K c/s (BASELINES
  ~767K), wrap 1.74 s. Peak footprint 7.24-7.31 GB.
- **memory-merkle at 4 GiB** (po2 18), 3 runs: STARK 13.91 / 13.93 / 13.94 s, 602-603K c/s (BASELINES
  ~603K), wrap 1.72-1.73 s. Peak footprint 4.91 GB.
- **4 GiB, Groth16 after keccak.** I pointed the test
  `a_tight_worker_wraps_after_keccak_and_releases_the_key_between_jobs` at the installed worker
  (`ZKMINER_B9_WORKER`) and ran it twice, with the sandbox HOME:
  - rc 0 both times. The warm-up, fibonacci, keccak, memory-merkle and fibonacci all wrapped (256-byte
    seals).
  - 5 of 5 key releases per run, each "3882.3 MiB freed (prover layout split_h + tw_lent)".
  - The keccak job took 4.99 s and 4.93 s.
- **20 sequential jobs in one worker at 4 GiB.** Test `m9_proofs_in_one_worker` with the installed worker,
  Warmup first, fibonacci 4,587,520 cycles, 9.49-9.67 s each:
  - idle footprint after proof 1: 4836 MiB. Proofs 2-20: 4410-4768 MiB, and the last one (4703 MiB) is
    below the first.
  - lifetime peak 6208 MiB (RC1 6191), 21 key releases. **No footprint growth.**
- **Simulated 16 GB host.** Settings: `ZKMINER_METAL_HOST_RAM_BYTES=16 GiB`, HAL limit 10.67 GiB,
  `ZKMINER_CUDA_VRAM_BYTES=8 GiB`. The worker planned 8 GiB at po2 19.
  - memory-merkle: 10.21 s, wrap 1.74 s, footprint 7.30 GB.
  - **Full suite: 203.8 s (787K c/s)**, every program wrapped and verified. **Peak footprint 9.34 GB**
    (RC1 9.47), which is inside a 16 GB Mac's 11.5 GiB allowance.
- These are all simulated budgets on this Mac. No real 16 GB Mac has been measured.

### First start and the macOS 26 fallback

`BENCH_ONLY=fibonacci --benchmark`, timed as process wall:

| case | wall | pipelines |
|---|---|---|
| **cold first start** (first run in the new HOME after the install, `MTL_SHADER_CACHE_SIZE=0`, no archives) | **59.7 s** | built in 57.3 s: rv32im+zkp 57.3, recursion 27.1, keccak 27.1, groth16 27.0 (in parallel); zkp 72 PSOs 27.1 s, rv32im 13 PSOs 30.3 s |
| the same while the VM was compiling (`out/firststart-cold-vmbusy`) | 73.4 s | built in 68.6 s |
| second start (runtime archive kept) | 2.44 s | 72 + 13 hits |
| second start, cold OS shader cache | 2.49 s | 72 + 13 hits |
| control: an archive set with this worker's digests, key `macos27` (`RISC0_METAL_AOT_DIR`, empty `RISC0_METAL_ARCHIVE_DIR`, cold OS cache) | 2.52 s | every pipeline from the offline files |
| **macOS 26 fallback: the same set with key `macos26`** (what a macOS 27 runtime never opens, the mirror image of macOS 26 facing a `macos27` set) | **47.0 s** | "no offline archive …-<os26B131\|macos27>-*" for all 6 units, a clean miss, then all compiled; no WARN or ERROR |

- The two sets are RC1's (`scratch/w9/rc1/aot/`), taken from B9-M26's final kit. Their 5 digests equal
  this kit's.
- Every one of these runs verified its proof, and every receipt passes the stock verifier.
- The miner's Warmup timeout (60 min) and its Metal benchmark deadline leave room for a one-minute first
  start.

### Correctness

- **Stock crates.io risc0-zkvm 3.1.0 verifier** (`tools/stock_verify31`, RC1's `--locked` build: same
  source, same risc0 rev; selector `e71e6620`).
  - **37 of 37** Groth16 receipts made by the installed kit worker pass `STOCK 3.1 VERIFY: OK`, plus the
    smoke script's one. They come from:
    - the six-program suite at the default budget and at 16 GB;
    - memory-merkle at the default budget, 8 and 4 GiB, and the A/B B arms;
    - the first, second and third starts, and both AOT cases.
  - The 10 A-arm receipts of the reference worker pass too.
  - The worker returns Groth16 receipts only; composite and succinct receipts stay inside it. Wave 8's
    matrix covers those types for this risc0 rev (B9-M26 `matrix/`).
- **3.0 receipts are rejected.** I used 30 receipts from B9-M26's 3.0 producer: composite, succinct and
  Groth16; fibonacci, merkle, keccak and compose; at default, 8 and 4 GiB. All are REJECTED, both plain
  and with `--relabel-as-31` (**60 of 60**).
- **CLI end to end on a local chain.** Foundry from `/Users/user/zkminer/bin`. I ran the `localnet` test
  `mines_the_claimable_jobs` (`ZKMINER_LOCALNET_MINE=1`) with `ZKMINER_LOCALNET_ZKMINER` set to the
  installed CLI and `ZKMINER_LOCALNET_RISC0_WORKER` to the installed worker. Anvil forked live 743111.
  - **rc 0 in 180 s.** 4 claimable risc0 jobs (Full, Fields, NoneForUs, FullForAnother) were each claimed,
    proved on Metal with a Groth16 wrap, fulfilled, and paid 4.95 tHEMI (the 5 tHEMI price minus the 1 %
    fee).
  - The 8 non-claimable jobs were not claimed: two wrong journals, one exclusive for another prover, one
    "None" job assigned to another prover, high collateral, a prefix marker, an unreachable ELF and a
    decoy ELF.
- `RISC0_METAL_REC_SEAL_CHECK` (the P31-SEC finding) is fixed in this rev (B9-SEC: a 256-bit OS seed per
  proof). The kit README and `docs/macos-beta.md` list it as debug-only.

### Not run here

Each item says why:

- A real macOS 26 Mac and a real 16 GB Mac: none is available.
- GPU families other than `applegpu_g17s`: there is only this Mac.
- The R17 audit and stress: no kernel changed since B9-M26. The 5 metallib digests are identical, and the
  compiler is the same 27B47.
- The fork's Metal unit suites: the risc0 rev is unchanged since its merge gates.
- Live-chain transactions: forbidden here. See the user checklist below.

## 4. macOS 26: what is validated

- **B9-M26 on this Mac (macOS 27.2.1).**
  - The 26.0-target kernels are AIR 2.8. `ir_scan.py` gives `A=0 S=0`, equal to the 27.0 scan, and
    `run_stress.sh` is clean.
  - The Metal suites pass twice. The stock verifier accepts every 3.1 receipt at default, 8 and 4 GiB, and
    rejects every 3.0 one.
  - The A/B against the 27.0 kit shows no change.
  - The API audit found nothing newer than macOS 15.
  - The `macos26` AOT key is not validated, so the kit ships no archives at all. This RC confirms the
    clean fallback above.
- **macOS 26 VMs** (main session; guest macOS 26.6.2, 25G83, paravirtual GPU).
  - Session 1 (B9-M26 kit, 8 GB; `scratch/w9/B9-M26/vm/out-gui/RESULTS.md`): the checksum, quarantine,
    `spctl`, `install.sh` (8 GB refused, `--force`), the Groth16 download, `--metal-arch` and the loading
    of all 5 metallibs passed.
  - Session 2 (RC1 kit, 16 GB; `…/vm/out-rc1/RESULTS.md`): the checksum, the quarantined kit, the smoke
    script's exit 8 before the install, `install.sh --with-groth16` with no `--force`, `zkminer init`, a
    clear missing-key error from `zkminer run`, and an 8 GiB / po2 19 plan all passed.
  - **Inconclusive on GPU:** the paravirtual GPU fails some pipeline compiles and resets (20-23 resets).
    This says nothing about real hardware. It exposed the simulated-benchmark finding (section 2, item 5).
- **Still required:** a real Apple Silicon Mac on macOS 26 with at least 16 GB (checklist step 5).

## 5. Open issues

1. **`metal-3.1` is not on top of zk-miner `main`.**
   - GitHub `main` is still `c030355` (checked today with `git ls-remote`). As RC1 found, it has 88
     commits that `metal-3.1` lacks, and a trial merge conflicts in 15 files, including the risc0 pin.
   - **An integration item is needed** (merge, re-pin, then this RC again) before a tag from `main` can
     ship the Mac kit.
2. **The risc0 fork lacks hemilabs/risc0 `release-3.1`'s last two commits.** `release-3.1` is still
   `5beab26b` (ROCm-only HIP files, no Metal code).
   - One Cargo patch serves every platform, so `zkminer/metal-3.1` needs a merge of `release-3.1` before
     `main` can pin it.
   - That changes the rev, which means a re-pin and a rebuild.
   - Neither `zkminer/metal-3.1` nor zk-miner `metal-3.1` is on GitHub yet.
3. **Every Mac has a ~1-minute first start**, because CI kits have no AOT archives. The README now says
   so. Shipping archives is a user decision: the kit would then need the README's archive text back.
4. **B9-CI's open issues remain:**
   - nothing has run on the real runner;
   - its SDK changes the metallib digests;
   - the `xcode` toolchain mode is untested;
   - the maintainer docs are stale (section 2, item 1).
5. B9-FX (the fixture generator's symlink guard) was not merged: unresolved, and a real bug in
   `fixtures/generate_segments.sh`. It does not touch the kit.
6. **Not done in BETA-FIX** (code changes):
   - a non-zero exit from `zkminer benchmark` when its warm-up fails (it now prints a simulated table and
     exits 0), and from `worker --benchmark` when nothing verified;
   - a kit-aware missing-Groth16 message in the worker;
   - Mac-appropriate power messages in `zkminer benchmark`;
   - hashing an already-installed Groth16 component;
   - an ephemeral runner for release builds;
   - the unpinned `Jimver/cuda-toolkit` tag in `build-windows.yml`;
   - the release notes' checksum command (section 2, item 2).
7. B9-G1 / B9-ZK:
   - the beta keeps the `w7` dispatcher table, so no `MallocLargeCache=0`;
   - nothing guards against `RISC0_METAL=0`, `RISC0_METAL_SKIP=groth16` or
     `RISC0_GROTH16_METAL_PROVER=docker` routing the wrap to Docker. These are documented as debug-only.
8. Not measured: a real 16 GB Mac (including its cold first start on an M1-M4), other GPU families, a real
   macOS 26 runtime, and `build-macos.yml` on the real runner.

## 6. User checklist

Nothing below was executed. The push URLs of the local checkouts are disabled on purpose, so each command
names its URL. The shas are the ones this RC used. If any of them changes (open issues 1 and 2), redo
the RC on the new ones.

1. **Push the risc0 fork unchanged.** `Cargo.lock` pins this exact sha:

   ```sh
   cd /Users/user/zkminer/deps/risc0-3.1
   git push git@github.com:hemilabs/risc0.git d94ef65015f4753c5496ad7302f15c44513370f3:refs/heads/zkminer/metal-3.1
   git ls-remote https://github.com/hemilabs/risc0 refs/heads/zkminer/metal-3.1   # must print d94ef6501…
   ```

2. **Push the zk-miner branch** (`metal-3.1`: the commit that adds this file, on top of `304f486`), then
   open a PR into `main`. It is not a fast-forward (open issue 1).

   ```sh
   cd /Users/user/zkminer/zk-miner-3.1
   git log --oneline -2 metal-3.1        # this RC2 commit, then 304f486
   git push git@github.com:hemilabs/zk-miner.git metal-3.1:refs/heads/metal-3.1
   gh pr create --repo hemilabs/zk-miner --base main --head metal-3.1 --title "macOS (Metal) beta on RISC Zero 3.1"
   ```

3. **Repository variable** (optional). The workflow falls back to `zk-runner-mac-new`, so set the variable
   only for another runner label. Never register this Mac as a runner.

   ```sh
   gh variable set ZKMINER_MACOS_RUNNER --repo hemilabs/zk-miner --body zk-runner-mac-new
   ```

   Then run `build-macos.yml` by hand on the branch, and check that build, cpu-tests and metal-probe pass
   on the real runner. Compare its kit's `BUILDINFO` with section "The candidate": `min_macos=26.0`,
   `metal_compiler … 32023.922`, `risc0_rev d94ef6501…`, no archives.

   ```sh
   gh workflow run build-macos.yml --repo hemilabs/zk-miner --ref metal-3.1 -f metal_toolchain=pinned
   ```

4. **HemiProve redeploy of 2026-11-16 on 743111** (handoff `/Users/user/zkminer/zkminer-handoff-743111.md`).
   - **What B9-CHAIN verified read-only:**
     - handoff section 13 tests 1-4 (chain id and codehashes, `getAdapter` for the three ids, nonce
       derivation against `getProofNonce`, descriptor decode);
     - `verify_deployment` and `verify_proof_system` against the live chain;
     - the risc0 3.1 verifier: `SELECTOR() 0xe71e6620`, "3.1.0", source equal to risc0-ethereum v3.1.0;
     - Metal 3.1 receipts accepted by `Registry.verifyProof`; tampered and 3.0 seals rejected;
     - the pins and the 23 ABIs equal hemi-prove-contracts `8e1808b` (`the_pins_match_the_contracts_repo`).
   - On an anvil fork B9-CHAIN also covered tests 5, 6, 10, 11, 13, 14, 15 and 16. This RC re-ran test 6
     on a fork with the installed RC2 kit (section 3).
   - Day 1 (the governance handoff, due by 2026-11-18 10:13 UTC) changes no address or interface. After
     it, check that `zkminer run` still passes its deployment checks.
5. **macOS 26 (user decision: supported).**
   - B9-M26 validated the 26.0-target kernels on this Mac. Two macOS 26.6.2 VM sessions passed launch,
     install, init and Metal library loading (section 4).
   - **Before tagging**, on a real macOS 26 Apple Silicon Mac with at least 16 GB, run
     `scripts/ci/macos-smoke.sh` (in the kit: `tools/macos-smoke.sh`) and the installed worker's
     `--benchmark`. In the extracted kit:

     ```sh
     ./install.sh --with-groth16
     tools/macos-smoke.sh                                # scripts/ci/macos-smoke.sh in the repository
     ~/.zkminer/provers/zkminer-prove-risc0-metal --benchmark
     ```

   - Expect the first start to compile the pipelines for a minute or more, then every program
     "verified" and the smoke script's `RESULT: ok`. Keep the logs, and note the first-start time and
     the chip.
6. **Funded-key acceptance tests** (handoff section 13), live on 743111:
   - Use a staked prover key, with tHEMI from the HemiProve team: at least 100 per lock, and 1,000 for
     custom-verifier jobs. You also need testnet ETH. Keep the transaction hashes.
   - Tests for the Mac beta: **5, 6, 10, 11, 13, 14, 15, 16, 17, 18, 19**.
     - Schedule 19 (the pause drill) with the team.
     - For 14, expect `InsufficientFreeStake`, not `Panic(0x01)` (B9-CHAIN).
   - Not applicable to this build: 7, 8, 9 and 12 (SP1 nonce-marker / PLONK / `claimAndFulfillAssigned`).
7. **Cut the tag** once all of this is done:
   - steps 1-6;
   - open issues 1 and 2 resolved: `main` holds the integrated code on a re-pinned fork, and an RC round
     re-validated it (stock-verifier matrix, A/B, user round);
   - the release notes' checksum line fixed (section 2, item 2). Recommended.

   `release.yml` requires the tag to equal `[workspace.package].version` (now `0.1.0`). It builds Linux,
   Windows and the macOS kit (`build-macos.yml`, pinned 27B47) from the tagged commit. Run a dry run
   first, then tag:

   ```sh
   gh workflow run release.yml --repo hemilabs/zk-miner --ref main -f dry_run=true
   git -C <checkout of the integrated main> tag -a v0.1.0 -m "zk-miner 0.1.0 (macOS beta: Apple Silicon, RISC Zero 3.1; unsigned)"
   git -C <checkout of the integrated main> push git@github.com:hemilabs/zk-miner.git v0.1.0
   ```

   Compare the CI kit's `BUILDINFO` with this RC. Its sha256 will differ (commit, SDK).
