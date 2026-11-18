# macOS beta, release candidate 1 (RISC Zero 3.1 on Apple Silicon)

2026-11-18. This is the release-candidate check of the zk-miner macOS (Metal) beta kit. The kit was built the
way the CI job builds it, then installed and used as a new user would. It ships **unsigned**: no Developer ID
and no notarization. Evidence and scripts are in `/Users/user/zkminer/scratch/w9/rc1/` (`ci/`, `logs/`, `out/`).

## The candidate

| | |
|---|---|
| kit | `zkminer-0.1.0-macos-arm64.tar.gz`, 121,021,606 bytes |
| **sha256** | **`54296dc61014b786cfb5349a63c16e41c471f8798dcf8706d78b4c16d0863e6c`** |
| where | `/Users/user/zkminer/scratch/w9/rc1/dist/` (the tarball and its `SHA256SUMS`) |
| zk-miner | `metal-3.1` @ `39978cd121b2e38835704d26c0c9dd42ee0c54fe` (`BUILDINFO commit`, `commit_dirty=no`) |
| risc0 | hemilabs/risc0 `zkminer/metal-3.1` @ `d94ef65015f4753c5496ad7302f15c44513370f3` (`BUILDINFO risc0_rev`, `risc0_src=git`) |
| minimum macOS | 26.0: binaries minos 26.0, metallibs target 26.0 (`check-macos-release.sh`: "a self-contained arm64 kit for macOS 26.0 and later") |
| Metal compiler | `Apple metal version 32023.922 (metalfe-32023.922.4)` (27B47, pinned, `metal_compiler_validated=yes`), SDK 27.2 |
| offline archives | none (`aot_arches=`; the CI build uses `AOT_ARCHES=none`) |
| Groth16 component | not bundled; v0.2.0, sha256 `173354ab…57e5`, fetched by the worker or `install.sh --with-groth16` |

The commit that adds this file changes only `docs/release/BETA_RC.md`, which is not an input of the kit.
A kit built by CI for a tag therefore has the same code, but a different `BUILDINFO commit`, and so a different
tarball sha256. On the runner's Xcode 26 SDK, `metal_sdk` and the metallib digests also change (B9-M26, B9-CI).

## 1. Mirror, pin and CI build

- **Mirror and pin.** The mirror `scratch/w9/mirror/risc0.git` was fetched from `deps/risc0-3.1`. Its
  `zkminer/metal-3.1` is `d94ef6501`, which is:
  - the `deps/risc0-3.1` HEAD (`Merge metal/B9-4G`, clean tree);
  - the rev that zk-miner's `Cargo.toml` and `Cargo.lock` pin.

  The brief's `84df3e8c0` is the tools unit's head after merge 1. Merges 2 and 3 (recursion `045ff92b6`,
  groth16 `d94ef6501`) moved HEAD on after it.
- **The CI jobs.** `ci/sim.py` (B9-CI's harness) ran every step of `.github/workflows/build-macos.yml` at
  `39978cd`, in order, exactly as written:
  - all three jobs: build, cpu-tests and metal-probe;
  - a fresh clone of `metal-3.1`, inside a 14 GB APFS disk image (`hdiutil`, 13.79 GB usable; detached and
    deleted afterwards);
  - a fresh `HOME`/`CARGO_HOME` inside the image, `CARGO_BUILD_JOBS=5`;
  - the hemilabs/risc0 URL sent to the mirror through `GIT_CONFIG_*` `insteadOf`.

  Note on the `insteadOf` rule: the brief's single rule also rewrites `hemilabs/risc0-sppark`, because git
  matches prefixes, so the first run failed fetching sppark (`ci/logs/attempt1/`). The run used
  RELEASE-DEPS.md's second, identity rule for sppark. This affects only local CI replays with a mirror.

| job / step | rc | wall | disk (of 13.79 GB) |
|---|---|---|---|
| build: Metal toolchain (27B47, pinned) | 0 | 14 s | |
| build: Rust, rzup guest toolchain 1.97.0, protoc | 0 | 56 s | |
| build: Metal worker and CLI (`ASSEMBLE_BUILD_ONLY=1 assemble-macos.sh`) | 0 | 294 s | peak used 11.75 GB, **min free 2.04 GB** |
| build: delete intermediates | 0 | 2 s | 11.72 -> 4.84 GB |
| build: package and check (`check-macos-kit.py`, `test-check-macos-kit.sh` 13/13) | 0 | 48 s | |
| cpu-tests: tests that need no GPU (2 suites, 60 + 128 passed; `test-metal-tc` 18/18) | 0 | 262 s | min free 2.90 GB |
| metal-probe: install, probe, Groth16 download (54 s), one fibonacci proof | 0 | 62 s | min free 3.20 GB |

The kit from the build job's upload is the candidate above.

## 2. Install as a new user (sandbox HOME, quarantined download)

- **Setup.** The sandbox is `HOME=scratch/w9/rc1/home`, entered through `env -i` with the system `PATH` plus
  `~/.zkminer`. The tarball was copied to `~/Downloads` and marked as a Safari download
  (`com.apple.quarantine 0083;…;Safari;…`).
- **Steps.** I followed the README (`packaging/macos/README.md`, which ships in the kit) literally:
  - `shasum -c SHA256SUMS`: OK;
  - `tar -xzf`: the quarantine flag reaches every extracted file; `spctl`: rejected;
  - **a direct run of `./zkminer --help` blocked with no output** until I killed it (rc 143). This was a
    shell with no GUI session, so it was presumably waiting on Gatekeeper's dialog;
  - `./install.sh --with-groth16`: rc 0 in 88 s. It checked the kit, installed both binaries and removed
    their quarantine flag (`xattr -l` is empty). It said "this kit has no offline Metal archives; the first
    start compiles the GPU pipelines". It downloaded and installed Groth16 v0.2.0 (2.4 GB, 5.4 GB on disk).
    Its "Next" list: `zkminer init`, `zkminer benchmark`, `zkminer run`.
- **CLI checks.**
  - `zkminer help`: ok.
  - `zkminer init`: rc 0. It wrote `config.toml` for 743111: router `0xD931…Ed58`, token `0x4695…36cc`,
    `scan_from_block` 7226094.
  - `zkminer benchmark`: rc 0 in 187 s (table below).
  - `tools/macos-smoke.sh`, run from the kit after the install: `RESULT: ok`, `STOCK 3.1 VERIFY: OK`.
  - `./install.sh --warm`: rc 0, warm-up 2 s.
  - `./install.sh --uninstall`: removed the CLI and the worker, and left the config, keys and `~/.risc0` as
    documented.

**Where the docs are wrong or unclear** (none blocks the beta; items 1 and 2 should be fixed before the tag):

1. **README "First start and the offline archives" does not match a CI-built kit.**
   - What it says: "GPU family `applegpu_g17s` on macOS 27: the kit ships pre-compiled archives. The first
     start then takes about 2.3 s." Install step 5 and the Files table also describe `metal-aot/` archives
     (`manifest.jsonl`, `SHA256SUMS`).
   - What happens: the release path (release.yml -> build-macos.yml) builds with `AOT_ARCHES=none`. The kit's
     `metal-aot/` is empty, and the first start on an M5 Max on macOS 27 took **60.3 s** (`install.sh` says so
     correctly).
   - Fix: either correct the README for the CI kit, or ship a kit assembled on a Mac with the g17s set
     (`docs/macos-beta.md` "Build the kit"; B9-CI open issue 3). This is a user decision.
2. **`docs/macos-beta.md` describes a different kit from the one a tag ships.**
   - "Build the kit" describes the Mac-built kit (default `AOT_ARCHES=applegpu_g17s`, 209 MB).
   - Its "CI" section is still the pre-B9-CI sketch: "The workflow files are not part of this item", and
     `fetch-metal-toolchain.sh` instead of `macos-metal-toolchain.sh`.
   - RELEASE-DEPS.md's runner recipe still uses `xcodebuild -downloadComponent` (B9-CI open issue 5).
   - Both should point at `docs/ci-macos.md`.
3. **Gatekeeper in a terminal without a GUI session.**
   - Running a quarantined binary directly produces no message: the command just hangs.
   - The README describes only the desktop dialog. Over SSH, B9-M26's VM was not blocked at all.
   - Suggest one line: "if a program from the kit hangs without output, macOS is waiting for you to approve
     it; use `install.sh` or `xattr -d`".
4. **README "Then:" stops too early.** It goes `init`, `benchmark`, `run`. `zkminer run` needs a key, gas,
   tHEMI and a stake first. `zkminer init` prints these steps, but its step 3 says "Stake it (via the Wallet
   screen)", while `zkminer stake` exists. The README should point at init's "Next steps".
5. **README Disk.** It says "about 0.5 GB for the kit", but the CI kit is 121 MB packed and 191 MB unpacked.
   This is harmless.
6. **`zkminer benchmark` takes time and its output is noisy.**
   - It runs the full six-program suite: 187 s on the M5 Max, and the README gives no duration, so expect
     several times longer on a base chip.
   - Without a TTY its log has ANSI colour codes.
   - It re-logs the worker's INFO lines at WARN (`WARN [worker:risc0] … INFO … Shutdown requested`).
     This is cosmetic.

## 3. The installed worker on this Mac (M5 Max, 36 GB, macOS 27.2.1)

All GPU runs went through `gpu-run`. Each used the installed `~/.zkminer/provers/zkminer-prove-risc0-metal`
of the sandbox, with `env -i`, so budgets were passed explicitly as `RISC0_METAL_MAX_WORKING_SET_BYTES`.

### Full `--benchmark`, default budget (one run, load 4.8)

| program | cycles | STARK | c/s | wrap |
|---|---|---|---|---|
| fibonacci | 32,768 | 0.28 s | | 1.62 s |
| sha256-chain | 46,137,344 | 50.58 s | 912K | 1.60 s |
| ecdsa-verify | 65,011,712 | 71.15 s | 914K | 1.60 s |
| bigint-mul | 27,525,120 | 30.73 s | 896K | 1.60 s |
| memory-merkle | 7,340,032 | 8.34 s | 880K | 1.61 s |
| chacha-mix | 8,404,992 | 9.72 s | 864K | 1.60 s |
| **all** | 154,451,968 | **170.80 s, 904.3K c/s** | | |

- **Against BASELINES '3.1'** (169.56 s, 910.9K c/s): **+0.73 %**, below the 1.5 % threshold.
- Peak footprint 14.68 GB (baseline 14.69). Wraps 1.60-1.62 s (baseline first wrap 1.58-1.60 s).
- `zkminer benchmark` (the CLI, through the dispatcher) gave 171.23 s, 902.0K c/s cycle-weighted, and a
  Groth16 median of 1.59 s.
- Every program was wrapped and verified.

### Interleaved A/B, memory-merkle `--benchmark` (A = the reference 3.1 worker in `~/.zkminer/provers`, sha256 `9161605e…`; B = the installed kit worker)

The single budget runs came out 0.9-1.6 % below BASELINES at 8 and 4 GiB. Single runs: 8 GiB 10.31 / 10.38 /
10.38 s (757-762K c/s, peak 7.25-7.31 GB); 4 GiB 14.05 / 14.10 / 14.14 s (593-597K c/s, peak 4.91-4.93 GB).
I therefore ran an interleaved A/B, A B A B …, one `gpu-run` per arm, in one session, load 1.1-4.2:

| budget | pairs | A STARK median [min-max] | B STARK median [min-max] | B-A per pair, median | wrap A / B | peak footprint A / B |
|---|---|---|---|---|---|---|
| default (po2 20) | 5 | 8.41 [8.41-8.45] s | 8.41 [8.40-8.42] s | -0.01 s | 1.60 / 1.60 s | 13.19 / 13.19 GB |
| 8 GiB (po2 19) | 7 | 10.37 [10.36-10.39] s | 10.36 [10.35-10.40] s | -0.01 s | 1.75 / 1.75 s | 7.32 / 7.28-7.31 GB |
| 4 GiB (po2 18) | 7 | 14.11 [14.10-14.15] s | 14.10 [14.08-14.12] s | -0.02 s | 1.75 / 1.74 s | 5.01 / 4.91 GB |

**No change at any budget.** Every difference is inside the A-vs-A spread. The reference worker is ~1.4 %
slower than BASELINES' day too, so the gap is this session's machine state, not the kit.

### Budgets, sequences, hosts

- **4 GiB, Groth16 after keccak.** Test `a_tight_worker_wraps_after_keccak_and_releases_the_key_between_jobs`
  pointed at the installed worker (`ZKMINER_B9_WORKER`), 2 runs:
  - the warm-up and then fibonacci, keccak, memory-merkle and fibonacci all wrap (256-byte seals);
  - 5/5 key releases per run, each "3882.3 MiB freed (prover layout split_h + tw_lent)";
  - the keccak job takes 4.95-4.96 s. The P31-14 / BASELINES 3.1.5 refusal is fixed (B9-4G).
- **20 sequential jobs in one worker at 4 GiB** (`m9_proofs_in_one_worker`, installed worker, Warmup first,
  fibonacci 4,587,520 cycles, 9.52-9.72 s each):
  - **shipped default** (dispatcher table `w7`, so no `MallocLargeCache=0`): the idle footprint after each
    proof is 4821, 4779, …, 4716 MiB. Proofs 2-20 stay within 4552-4782 MiB, and the last is below the first.
    The settled level 1 s after each proof is 3178-3703 MiB, with no trend. Lifetime peak 6191 MiB.
    21 key releases. **No footprint growth.**
  - with `MallocLargeCache=0` (the `r2` table's spawn): idle 2811 -> 2802-2804 MiB, lifetime peak 4143 MiB.
- **Simulated 16 GB host.** Settings: `ZKMINER_METAL_HOST_RAM_BYTES=16 GiB`, HAL limit 10.67 GiB,
  `ZKMINER_CUDA_VRAM_BYTES=8 GiB`. The worker planned 8 GiB at po2 19.
  - memory-merkle: 10.27 s (BASELINES 10.19), wrap 1.75 s, footprint 7.37 GB (7.38).
  - **Full suite: 206.2 s (778K c/s)**, every program wrapped and verified. **Peak footprint 9.47 GB**, which
    is within a 16 GB Mac's 11.5 GiB allowance (16 GiB minus the 4.5 GiB reserve). This is new data: BASELINES
    has no full suite at 16 GB.
- **Simulated budget runs**: all of the 8 / 4 GiB runs above are simulated budgets on this Mac. No real 16 GB
  Mac has been measured.

### First start and the macOS 26 fallback

`BENCH_ONLY=fibonacci --benchmark`, timed as process wall:

| case | wall | pipelines |
|---|---|---|
| **cold first start** (first run in the new HOME, `MTL_SHADER_CACHE_SIZE=0`, no archives) | **60.3 s** | built in 57.9 s: rv32im+zkp 57.9, recursion 16.6, keccak 32.0, groth16 31.9 (in parallel); zkp 72 PSOs 16.6 s, rv32im 13 PSOs 41.3 s |
| second start (runtime archive kept) | 2.52 s | 72 + 13 hits |
| second start, cold OS shader cache | 2.52 s | 72 + 13 hits |
| control: an archive set with this worker's digests, key `macos27` (`RISC0_METAL_AOT_DIR`, empty runtime dir, cold OS cache) | 2.52 s | every unit served from the offline files |
| **macOS 26 fallback: the same set with key `macos26`** (what a macOS 27 runtime never opens, the mirror image of macOS 26 facing the `macos27` set) | **57.9 s** | "no offline archive …-<os26B131\|macos27>-*" for every unit, a clean miss, all compiled; no WARN/ERROR |

- The set came from B9-M26's final kit, whose 5 metallib digests equal this kit's (`--worker-digests`).
- Every run verified its proof, and every receipt passes the stock verifier.
- The miner's Warmup timeout (60 min) and its Metal benchmark deadline leave room for the one-minute first start.

### Correctness

- **Stock crates.io risc0-zkvm 3.1.0 verifier.** I built `tools/stock_verify31` `--locked` (all 10 risc0
  packages from crates.io; selector `e71e6620`).
  - **44 of 44** Groth16 receipts made by the installed kit worker pass `STOCK 3.1 VERIFY: OK`: the six-program
    suite, fibonacci first starts, memory-merkle at default / 8 / 4 GiB, the A/B B arms and the 16 GB runs.
  - The 20 A-arm receipts of the reference worker pass too.
  - The worker emits Groth16 receipts only: composite and succinct receipts stay inside it. Wave 8's matrix
    covers those types for the same risc0 rev (B9-M26 `matrix/`).
- **3.0 receipts are rejected:** 30 receipts from B9-M26's 3.0 producer (composite, succinct and Groth16;
  fibonacci, merkle, keccak, compose; default, 8 and 4 GiB) are REJECTED, both plain and with
  `--relabel-as-31` (60 of 60).
- **CLI end to end on a local chain.**
  - Setup: Foundry 1.5.1 (`/Users/user/zkminer/bin`); `localnet` test `mines_the_claimable_jobs` with
    `ZKMINER_LOCALNET_ZKMINER` set to the installed CLI and `ZKMINER_LOCALNET_RISC0_WORKER` to the installed
    worker (the run dir links to both). Anvil forked live 743111 at 7234420.
  - **rc 0 in 159 s.** 4 claimable risc0 jobs were each claimed alone, proved on Metal (Groth16 wrap),
    fulfilled, and paid 4.95 tHEMI (5 tHEMI price minus the 1 % fee).
  - The 7 non-claimable jobs were not claimed: wrong journals, exclusive for another prover, high collateral,
    prefix marker, an unreachable ELF and a decoy ELF.
- `check-macos-release.sh` on the tarball: rc 0, minimum macOS 26.0.
- `RISC0_METAL_REC_SEAL_CHECK` (the P31-SEC finding) is fixed in this rev: B9-SEC, merge `abea7c97c`. It uses
  a 256-bit OS seed per proof.

### Not run here

Each item says why:

- A real macOS 26 Mac, and a real 16 GB Mac: none is available.
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
  - The `macos26` AOT key is not validated, so the kit ships no `macos26` set. This RC confirms the fallback
    above.
- **macOS 26 VM check** (2026-11-18, main session; `scratch/w9/B9-M26/vm/out-gui/RESULTS.md`).
  - Setup: guest `cirruslabs/macos-tahoe-base` @ `sha256:65c3133a…`, macOS 26.6.2 (25G83), VirtualMac2,1,
    4 CPUs, 8 GB. Kit: the B9-M26 dist (commit 2dea3b6, min_macos 26.0, compiler 32023.922, AOT `macos27`
    only).
  - **Passed:**
    - the checksum, `tar` and the quarantined kit files;
    - the binaries launch (no dyld, missing-symbol or availability failure);
    - `spctl` rejects the unsigned binary once Gatekeeper is on. SSH sessions bypass the launch prompt, so the
      desktop "Open Anyway" path is untested;
    - `install.sh` refuses the 8 GB VM with a clear message. `--force` installs, skips the `macos27` archives on
      macOS 26 and says the first start compiles;
    - `install.sh --with-groth16` downloads v0.2.0 (2.4 GB, sha256 checked) in 68 s;
    - `--metal-arch` works. The worker refuses below 16 GB with a clear message;
    - `macos-smoke.sh` identifies "Apple Paravirtual device" (families apple1-5, 5.33 GiB) and exits 4;
    - macOS 26 Metal loads all 5 embedded metallibs (AIR 2.8 / MSL 3.2).
  - **Inconclusive (VM limit):**
    - a standalone loader that builds every compute pipeline gets 345/345 on the host;
    - in the guest it got 213/345 and then 115/273, failing non-deterministically ("Compilation failed")
      with 23 AppleParavirtGPU GPU resets. The paravirtual GPU resets under this load, which says nothing
      about real hardware.
  - **Still required:** a real Apple Silicon Mac on macOS 26 with at least 16 GB (checklist step 5).
- The main session runs a second VM session with this RC's kit (`scratch/w9/rc1/dist/`) after this report.

## 5. Open issues

1. **`metal-3.1` is not on top of zk-miner `main`.**
   - GitHub `main` (`c030355`, 2026-11-17) has 88 commits that `metal-3.1` lacks: a parallel 2026-11-16
     deployment pin, "public risc0 seed is protocol 13", the SP1 12 GB tier, splash and benchmark changes.
     `metal-3.1` has 54 that `main` lacks.
   - A trial merge (scratch clone, aborted) conflicts in 15 files: `Cargo.toml`/`Cargo.lock` (the risc0 pin),
     `deployment.rs`, `run.rs`, `localnet.rs`, `config.rs`, `groth16_component.rs`, the worker's `main.rs`,
     `prover-protocol/types.rs`, `benchmark.rs`, `discovery.rs`, `dispatcher.rs`, `memory.rs`, `README.md` and
     `VENDORED_FROM.txt`.
   - **This needs an integration item** (merge, then this RC again) before a tag from `main` can ship the Mac
     kit.
2. **The risc0 fork lacks hemilabs/risc0 `release-3.1`'s last two commits.** `main` pins
   `5beab26b` = `a85ef303b`, "rv32im ROCm: regenerate the evalfast eval_check for the 3.1 circuit": 4 HIP
   files, no Metal code. One Cargo patch serves every platform, so before `main` can pin the Metal fork,
   `zkminer/metal-3.1` needs a merge of `release-3.1`. That changes the rev, which needs a re-pin and a rebuild.
3. CI kits have no AOT archives, so every Mac takes a ~1-minute first start (docs item 1).
4. B9-CI's open issues remain:
   - nothing has run on the real runner;
   - its SDK changes the metallib digests;
   - the `xcode` toolchain mode is untested.
5. B9-FX (fixture generator symlink guard) was not merged: unresolved, a real bug in
   `fixtures/generate_segments.sh`. It does not touch the kit.
6. B9-G1 / B9-ZK:
   - the beta keeps the `w7` table, so no `MallocLargeCache=0` (footprint as measured above);
   - nothing guards against `RISC0_METAL=0`, `RISC0_METAL_SKIP=groth16` or `RISC0_GROTH16_METAL_PROVER=docker`
     routing the wrap to Docker (B9-CHAIN open issue 4).
7. Not measured: a real 16 GB Mac, other GPU families, a real macOS 26 runtime.

## 6. User checklist

Nothing below was executed. The push URLs of the local checkouts are disabled on purpose, so each command
names its URL.

1. **Push the risc0 fork unchanged.** `Cargo.lock` pins this exact sha; if it changes, re-pin and redo this RC:

   ```sh
   cd /Users/user/zkminer/deps/risc0-3.1
   git push git@github.com:hemilabs/risc0.git d94ef65015f4753c5496ad7302f15c44513370f3:refs/heads/zkminer/metal-3.1
   git ls-remote https://github.com/hemilabs/risc0 refs/heads/zkminer/metal-3.1   # must print d94ef6501…
   ```

2. **Push the zk-miner branch** (this commit on `metal-3.1`) and open a PR into `main`. It is not a
   fast-forward: see open issue 1.

   ```sh
   cd /Users/user/zkminer/zk-miner-3.1
   git push git@github.com:hemilabs/zk-miner.git metal-3.1:refs/heads/metal-3.1
   gh pr create --repo hemilabs/zk-miner --base main --head metal-3.1 --title "macOS (Metal) beta on RISC Zero 3.1"
   ```

3. **Repository variable** (optional). The workflow falls back to `zk-runner-mac-new`; set the variable
   only for another runner label. Never register this Mac as a runner.

   ```sh
   gh variable set ZKMINER_MACOS_RUNNER --repo hemilabs/zk-miner --body zk-runner-mac-new
   ```

   Then run `build-macos.yml` by hand on the branch, and check that build, cpu-tests and metal-probe pass on
   the real runner:

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
     - after review, the pins and the 23 ABIs equal hemi-prove-contracts `8e1808b`
       (`the_pins_match_the_contracts_repo`).
   - On an anvil fork it also covered tests 5, 6, 10, 11, 13, 14, 15 and 16. This RC re-ran test 6 on a fork
     with the installed kit.
   - Day 1 (governance handoff by 2026-11-18 10:13 UTC) changes no code. After it, check that `zkminer run`
     still passes its deployment checks.
5. **macOS 26 (user decision: supported).**
   - B9-M26 validated the 26.0-target kernels on this Mac, and the VM check passed launch, install and Metal
     library loading on macOS 26.6.2 (section 4).
   - **Before tagging**, on a real macOS 26 Apple Silicon Mac with at least 16 GB, in the extracted kit:

     ```sh
     ./install.sh --with-groth16
     tools/macos-smoke.sh               # scripts/ci/macos-smoke.sh in the repository
     ~/.zkminer/provers/zkminer-prove-risc0-metal --benchmark
     ```

   - Expect the first start to compile the pipelines for about a minute, then every program "verified".
     Keep the logs.
6. **Funded-key acceptance tests** (handoff section 13), live on 743111:
   - Use a staked prover key: tHEMI from the HemiProve team, at least 100 per lock (1,000 for custom-verifier
     jobs), plus testnet ETH. Keep the transaction hashes.
   - Tests for the Mac beta: **5, 6, 10, 11, 13, 14, 15, 16, 17, 18, 19**:
     - 19 (the pause drill) is scheduled with the team;
     - for 14, expect `InsufficientFreeStake`, not `Panic(0x01)` (B9-CHAIN).
   - Not applicable to this build: 7, 8, 9 and 12 (SP1 nonce-marker / PLONK / `claimAndFulfillAssigned`).
7. **Cut the tag**, once these are done:
   - steps 1-6;
   - open issue 1 resolved: `main` holds the integrated code, re-validated by an RC round;
   - the README fixes of section 2 (items 1-2) in.

   `release.yml` requires the tag to equal `[workspace.package].version` (now `0.1.0`), and builds Linux,
   Windows and the macOS kit (`build-macos.yml`, pinned 27B47) from the tagged commit:

   ```sh
   git -C <checkout of the integrated main> tag -a v0.1.0 -m "zk-miner 0.1.0 (macOS beta: Apple Silicon, RISC Zero 3.1; unsigned)"
   git -C <checkout of the integrated main> push git@github.com:hemilabs/zk-miner.git v0.1.0
   ```

   A dry run first: `gh workflow run release.yml --repo hemilabs/zk-miner --ref main -f dry_run=true`. Then
   compare the CI kit's `BUILDINFO` (`metal_compiler … 32023.922`, `min_macos=26.0`, `risc0_rev`) with this
   RC. The sha256 differs (commit, SDK).
