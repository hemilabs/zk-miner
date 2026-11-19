# BETA-FIX: the macOS beta's blocking doc finding (no offline archives in the kit)

2026-11-18. Branch `metal-3.1`. Scratch, logs and the rebuilt kit: `/Users/user/zkminer/scratch/w9/BETA-FIX/`.

## The finding

The final beta review had one blocking finding, from the new-user lens. The security and release lenses
had none. The P31-SEC 64-bit-seed finding was already fixed by B9-SEC, which is an ancestor of the pinned
risc0 `d94ef6501`.

- **What the docs said.** `packaging/macos/README.md` (shipped as the kit's README.md) and the top-level
  README.md said:
  - the kit ships offline GPU pipeline archives for `applegpu_g17s` on macOS 27;
  - the first start takes about 2.3 s;
  - the kit takes about 0.5 GB.
- **What the kit has.** Every kit CI builds uses `AOT_ARCHES=none`, the RC1 kit included:
  - `metal-aot/` is empty and BUILDINFO has `aot_arches=`;
  - every Mac compiles its pipelines at the first start (60.3 s on the M5 Max in RC1);
  - the kit is 121 MB packed and 191 MB unpacked.

## Reproduction first

`check-macos-kit.py` now checks that the kit's README describes the kit:

- A kit without `metal-aot/*.binarchive` must contain "This kit has no offline GPU pipeline archives".
  A kit with archives must not.
- "About <x> GB for the kit" must be within a factor of 2 of the unpacked size.

Results:

- **RC1 tarball, before the doc fix.** 2 failures: the missing statement, and "About 0.5 GB for the kit"
  against 0.20 GB unpacked (`logs/repro-rc1-check.log`). `test-check-macos-kit.sh` fails case 1
  (`logs/repro-rc1-testcheck.log`).
- **The RC1 kit with only README.md and install.sh replaced** (re-summed and re-packed):
  `test-check-macos-kit.sh` 16/16 (`logs/readmeonly-testcheck.log`). It adds three new cases:
  - 2l: a README claiming archives the kit lacks;
  - 2n: a README saying "none" over a kit with one (a synthetic GPU-CPU-type Mach-O header);
  - 2m: a wrong size.

## Commits

1. `d03f8d1` **macOS kit docs: no offline archives in the beta; the kit check enforces it.**
   - Kit README:
     - install step 5 and `--no-aot` have no effect in this beta;
     - the new "First start" section: no archives, so every Mac compiles once, about a minute on an
       M5 Max and longer on M1-M4, then about 2.5 s from the cache;
     - disk: 0.2 GB for the kit plus 5.4 GB for Groth16, with 7.8 GB free during its download;
     - `metal-aot/` is marked empty in the Files table.
   - Top-level README: the same facts.
   - The checker and its test, as described above.
   - assemble-macos.sh, docs/macos-beta.md and docs/ci-macos.md: a kit with archives needs the README's
     archive text back first.
2. `b4707dd` **Cheap non-blocking items from the same review.**
   - Tarball provenance: download from the GitHub release over HTTPS and compare the tarball's SHA-256
     with the release's SHA256SUMS before unpacking. The kit's own SHA256SUMS only catches damage.
   - `zkminer init` is needed on the first install only. This is in both READMEs and in install.sh's
     Next list; init without `--force` keeps an existing config.
   - Kit README:
     - the worker's `--benchmark` exits 0 even when a program fails, so judge it by its "verified" lines
       or by `tools/macos-smoke.sh`;
     - the "rzup install risc0-groth16" hint maps to `./install.sh --with-groth16`;
     - the first-use Groth16 download is silent until it is done.
   - docs/macos-beta.md: the debug-only release-build knobs (`RISC0_METAL_REC_CAPTURE`,
     `RISC0_SKIP_VERIFY`, `RISC0_METAL_REC_SEAL_CHECK`, the stock fallbacks) and what each one affects.

No Rust, kernel or risc0 change was made, so the risc0 pin (`d94ef6501`), RELEASE-DEPS.md and performance
are unchanged and need no A/B. No hot path was touched.

## Gates re-run: the kit rebuilt as CI builds it

RC1's `ci/sim.py` was copied to `scratch/w9/BETA-FIX/ci`. It ran build-macos.yml's `build` and
`metal-probe` jobs at `b4707dd`, in a 14 GB APFS image, with a fresh HOME, `CARGO_BUILD_JOBS=5` and the
risc0 mirror at `d94ef6501`.

| step | rc | wall | min free (of 13.79 GB) |
|---|---|---|---|
| Metal toolchain (pinned 27B47) | 0 | 18 s | 12.83 GB |
| Rust, rzup guest toolchain, protoc | 0 | 57 s | 10.22 GB |
| build worker + CLI (`ASSEMBLE_BUILD_ONLY=1`) | 0 | 295 s | 2.05 GB |
| package + `check-macos-release.sh` + `check-macos-kit.py` + `test-check-macos-kit.sh` | 0 | 61 s | 5.09 GB |
| metal-probe: install, probe, Groth16 download, one fibonacci proof | 0 | 59 s | 3.25 GB |

The rebuilt kit:

- **Tarball.** `zkminer-0.1.0-macos-arm64.tar.gz`, 121,022,512 bytes, sha256
  `70852f6048f8361207a2f5ed1e2086730d9dfb6131069652b23aaa7e75d4aa6f`, in
  `scratch/w9/BETA-FIX/ci/artifacts/dist-macos/`.
- **BUILDINFO.** `commit=b4707dd`, `commit_dirty=no`, `risc0_rev=d94ef6501`,
  `metal_compiler_validated=yes`, `aot_arches=`.
- **check-macos-kit.py.** ok: "10 files, 2 programs, 0 GPU binary archives".
- **test-check-macos-kit.sh.** 16 passed, 0 failed.
- **check-macos-release.sh.** ok, macOS 26.0 and later.
- **Probe.** install.sh said "this kit has no offline Metal archives; the first start compiles the GPU
  pipelines". The fibonacci Groth16 proof verified, `RESULT: ok (exit 0)`.

The cpu-tests job was not re-run: no Rust code or test input changed.

## Open issues

- **RC1 and this kit are evidence only.** The tag has to be built from an integrated main, after the risc0
  fork merges hemilabs `release-3.1` and is re-pinned (RC open issues 1 and 2). Repeat the RC round on that
  commit.
- **Not done here.** These are listed in the review and the RC:
  - a non-zero `--benchmark` exit when no program verified;
  - a kit-aware missing-component message in the worker itself;
  - Linux-only MSR advice and a Mac power default in `zkminer benchmark`;
  - hashing an already-installed Groth16 zkey once;
  - an ephemeral runner for release builds;
  - the stale "Build the kit" and "CI" sections of docs/macos-beta.md and RELEASE-DEPS.md's runner recipe
    (B9-CI open issue 5);
  - RC docs items 3 (a quarantined binary hangs silently over SSH) and 4 (`zkminer run` needs the key,
    gas and stake steps that `init` prints);
  - the unpinned `Jimver/cuda-toolkit` tag in build-windows.yml.
- **Untested hardware.** A real macOS 26 Mac, a real 16 GB base Mac (M1-M4) and its cold first-start time
  are still unmeasured. build-macos.yml has never run on the real `zk-runner-mac-new`.

# Wave 10: the integrated branch's last blocker (W10-BENCH, W10-DOC and the startup error)

Round 1 of Wave 10's final review (integration, security and user lenses) had one blocking finding,
the same in all three: on `metal-3.1` @ `8ec11d6` (RC3), when the Metal worker died at start-up or its
warm-up failed, `zkminer benchmark` printed a table of simulated numbers and exited 0. The fix,
W10-BENCH, was unmerged because its round-3 review left one defect: a worker that never started was
reported with the dispatcher's respawn backoff ("Backoff: waiting 4.77s before respawning ...") under
the header "Workers: none — install prover binaries", and W10-DOC was stacked on it.

Branch `item/W10-BFIX` (from `item/W10-DOC` @ `06a2277`, worktree `zk-miner-3.1-wt-W10-DOC`), merged
into `metal-3.1` as `f9f535b`. Logs: `/Users/user/zkminer/scratch/w10/BETA-FIX/`.

## Reproduction first

- The round-3 reviewer's homes (`h_crash`: a worker script that prints a `dyld:` line and exits 134;
  `h_garbage`: one that writes non-protocol bytes) on W10-BENCH's code: exit 1 and no table (already
  right), but the failure line was the backoff text and the header said "Workers: none".
- Two new `benchmark_cli.rs` tests written first, with those scripts as the installed
  `zkminer-prove-risc0-metal`: both failed on the header (`before-tests.log`).
- RC4's forced failure with the real worker and a 1 GiB budget then showed a second, smaller gap: the
  failure line said only "Worker risc0 process died (EOF)", and the reason ("Metal working-set budget
  exceeded ...") was only in the log above it. A third test (`a_worker_that_dies_in_its_warm_up_is_quoted`)
  failed against the code without the fix, also when the panic handler's `RUST_BACKTRACE` note is the
  last line.

## Commits (on `item/W10-BFIX`)

| commit | what |
|---|---|
| `968b9bd` | `WorkerHandle` keeps the worker's last stderr line (sanitized; recorded also when forwarding is suppressed in the TUI) and a failed handshake quotes it. `WorkerSlot::last_spawn_error` holds the last failed spawn/respawn error; a benchmark of a slot that never came up reports `could not start: <that error>`, with the benchmark's own attempt (the backoff) only as context. `WorkerPool::not_started()`; the CLI header names those slots (`risc0:metal:0 (failed to start; see below)` or `(declined; see below)`) and says "none" only when no worker was found. A Metal slot that could not start adds quarantine advice (re-run `install.sh`, `xattr -l`). The kit README's Troubleshooting describes the new header |
| `befd019` | README.md: `--benchmark` takes about 4.2 min (254 s), `zkminer benchmark` 4.4-5.2 min (262-314 s), not "about 4.5 minutes". The W10-DOC note's `check-macos-kit.py` / `test-check-macos-kit.sh` commands give the full commit hash (`--commit` is compared verbatim with BUILDINFO) |
| `09db910` | `git merge --no-ff metal-3.1` (W10-PIN's pin 37b434755 and RC3's record); no conflicts |
| `1e5265a` | `WorkerDied` (EOF from a running worker) carries the worker's last stderr line, capped at 300 characters, read after at most 300 ms for stderr to drain; the type is unchanged for downcasting and the message keeps its "process died (EOF)" prefix. The panic handler's `note: run with RUST_BACKTRACE` line is never recorded |

`f9f535b` merges the branch into `metal-3.1` (`--no-ff`). `origin/main` (`c030355`) is an ancestor. The
risc0 pin is unchanged (37b434755), so the fork, the mirror and RELEASE-DEPS.md are unchanged.

The worker binary does not depend on `zkminer-prover` (only as a dev-dependency), so none of these
commits changes proving. Its code is W10-BENCH's (exit codes, `ZKMINER_TEST_FORCE_FAIL`), which W10-BENCH
A/B'd, on the W10-PIN pin.

## Gates (final tree `1e5265a` = `f9f535b`)

| gate | result |
|---|---|
| `cargo test -p zkminer-prover --features testing --tests` (`ZKVM_ALLOW_SKIP=1`), x2 | 405 passed / 21 ignored, both (lib 300 incl. 3 new; `worker_lifecycle` 37/3) |
| `cargo test --workspace --exclude zkminer-prove-sp1 --exclude zkminer-prover`, x2 | 512 passed / 18 ignored, both. `benchmark_cli` 8/8 (3 new), `first_run_cli` 3/3 |
| `cargo test -p zkminer-prove-risc0 --features metal`, x2 | 69 passed / 4 ignored, both |
| the reviewer's `h_crash` / `h_garbage` with the CLI | rc 1, header `Workers: risc0:metal:0 (failed to start; see below)`, failure line `could not start: Handshake ... process died (EOF) (the worker's last output: dyld: Library not loaded)` / `... frame too large ...`, quarantine advice (`p_crash.*`, `p_garbage.*`) |
| release worker + CLI through the mirror (`make -f Makefile.mac RISC0_SRC=git mac-build-worker`) | rc 0 |
| kit from `f9f535b` (`AOT_ARCHES=none assemble-macos.sh`, git mode through the mirror) | `zkminer-0.1.0-macos-arm64.tar.gz` 121,308,198 B, sha256 `5153fac0e4ba59388133771ffd8c6dd47e85fa1a3dbbec4cdd9b51aaa624b49e`, 192 MB unpacked. BUILDINFO commit `f9f535b…` clean, risc0_rev `37b434755…`, min_macos 26.0, compiler 32023.922 validated, no archives. Metallib digests: the same 5 as RC1-RC3 |
| `check-macos-kit.py --require-validated --version 0.1.0 --commit f9f535b800f8652072f3164a3372a209712130f6` | ok |
| `test-check-macos-kit.sh <kit> f9f535b8…` (full hash) | 16/16 |
| `check-macos-release.sh <kit>` | ok |
| `test-assemble-macos.sh` (sdk build + the kit's binaries) | 44/44 |

## RC step 0 on the kit (sandbox HOME, quarantined Safari download, `env -i`)

- `shasum -a 256 -c --ignore-missing SHA256SUMS`: OK; the kit's own SHA256SUMS: 9/9 OK; `spctl`
  rejects the quarantined `zkminer`. `./install.sh --with-groth16`: rc 0 in 122 s; installed copies have
  no quarantine mark. `zkminer help` and `zkminer init` (names `zkminer stake 100`): rc 0.
- **Worker exits 3 at start-up** ("forced failure" on stderr): **rc 1**, no table, header
  `Workers: risc0:metal:0 (failed to start; see below)`, `BENCHMARK FAILED: nothing was measured or
  saved.`, failure line `could not start: ... process died (EOF) (the worker's last output: forced
  failure) (then, when the benchmark tried it: Backoff: ...)`, smoke and quarantine advice. No
  `benchmarks.json` (`out/rc5-fail-crash.*`).
- **Real worker, `RISC0_METAL_MAX_WORKING_SET_BYTES=1 GiB`**: **rc 1**, no table, `BENCHMARK FAILED`,
  failure line `Worker risc0 process died (EOF) (the worker's last output: Metal working-set budget
  exceeded: ...)`. No `benchmarks.json` (`out/rc5-fail-budget.*`).
- **Working `zkminer benchmark`**: **rc 0**, 271.5 s wall, real numbers: 2.72 MzkOP/s, device row po2
  20, 891.6K c/s, Groth16 1.6 s; sha256-chain 50.77 s, ecdsa-verify 71.29 s, bigint-mul 30.72 s,
  memory-merkle 8.36 s, chacha-mix 9.73 s, zkop-mix 68.26 s. Load 1.75 -> 0.79 (`out/rc5-bench.*`).
- `tools/macos-smoke.sh`: `RESULT: ok (exit 0)`. `./install.sh --warm`: rc 0, warm-up 3 s.
  `./install.sh --uninstall`: rc 0, as documented.
- **Full worker `--benchmark`** (installed kit worker, default budget, `ZKMINER_BENCH_RECEIPT_DIR`):
  rc 0. fibonacci 0.28, sha256-chain 50.96, ecdsa-verify 71.35, bigint-mul 30.70, memory-merkle 8.37,
  chacha-mix 9.75 s: **six programs 171.41 s, 901.1K c/s**; zkop-mix 68.37 s. Wraps 1.59-1.60 s. Peak
  footprint 14.73 GB. Wall 254.8 s, load 1.85 -> 0.42. Against BASELINES '3.1' 169.56 s: **+1.09 %**;
  RC2 169.92 s: +0.88 %; RC3 171.88 s: -0.27 %. Below the 1.5 % threshold; single run, no code on the
  proving path changed since RC3.
- **Stock crates.io 3.1.0 verifier** (`scratch/w10/rc1/bin/stock-verify31`, selector `e71e6620`): the
  6 Groth16 receipts of that run: **6/6 `STOCK 3.1 VERIFY: OK`**; fibonacci's receipt against another
  image id: REJECTED (claim digest mismatch).

Budgets: none of these commits touches the worker, so the 4 and 8 GiB figures of RC3 / W10-PIN stand;
the 1 GiB forced failure above is the only budgeted run here.

## Knobs

None new. The messages are behaviour of the failure path only. `ZKMINER_TEST_FORCE_FAIL` (W10-BENCH)
is unchanged.

## Open issues

1. A worker file that is present but not executable (`h_noexec` in the round-3 review) is not
   discovered, so `zkminer benchmark` runs the SIMULATED path (labelled, exit 0, nothing saved). Not a
   kit path: `install.sh` sets the mode. Not changed.
2. The quoted last stderr line is the worker's (or, for a guest, its stdout, which is dup2'd onto
   stderr): sanitized and capped at 300 characters, it only appears in local errors and logs.
3. W10-BENCH's open issues stand (TUI drops a run where one card fails and another measures, simulated
   `--json` exit 0, `benchmark_targets()` ignores Metal, the 150 ms `proc` test bound under load).
4. RC3's open issues 2-8 are unchanged (Linux/Windows builds against the pin, runner disk, 300 W
   GPU power fallback on a Mac, real 16 GB / macOS 26 hardware).
