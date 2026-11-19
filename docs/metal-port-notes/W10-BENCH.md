# W10-BENCH: a failed benchmark is a failure, never a simulated table

Branch `item/W10-BENCH`, worktree `/Users/user/zkminer/zk-miner-3.1-wt-W10-BENCH`, from `item/W10-INT` @
`29488c2` (GitHub main merged into the beta, risc0 pin `28b4bef33`). Logs and scripts are in
`/Users/user/zkminer/scratch/w10/W10-BENCH/` (`repro/`, `real/`, `ab*/`, `tests/`, `scripts/`).

## The finding, reproduced on the integrated code first

In the macOS 26 VM (`scratch/w9/B9-M26/vm/out-rc1/RESULTS.md`) the Metal worker's warm-up failed. `zkminer benchmark`
logged `ERROR Benchmark failed for risc0:metal:0: warm-up ... failed`, then `No prover backend enabled — running
simulated benchmarks`, printed a table of simulated rows (3,009,039,154 c/s) and exited 0.

Main's benchmark rework did not change this path. I reproduced it on this Mac with `item/W10-INT` unchanged and the
mock worker standing in as `~/.zkminer/provers/zkminer-prove-risc0-metal` (sandbox `HOME`, no GPU involved):

| forced failure | before (W10-INT code) |
|---|---|
| warm-up crashes (`MOCK_CRASH_ON=warmup`) | `Benchmark failed for risc0:metal:0: Worker risc0 process died (EOF)`, then the simulated table (chacha-mix 7,678,047,716 c/s), `-0.00 MzkOP/s`, **rc 0** (`repro/before-crash-warmup.log`) |
| warm-up answers with the VM's error (new `MOCK_FAIL_ON=warmup`) | the VM's exact log lines, simulated table, `-0.00 MzkOP/s`, **rc 0** (`repro/before-fail-warmup.log`) |

The cause is `benchmark::run_benchmark`. `WorkerPool::benchmark_all_with_device_info` / `benchmark_all_streaming` only
logged a failed slot and returned the slots that measured, so an empty list meant both "every worker failed" and "no
worker". `run_benchmark` then fell back to `run_simulated_benchmarks()` whenever the list was empty.

Where a failed or simulated run could be cached or used for pricing (`zkminer run`'s profitability model reads the
cache via `load_cached_benchmark`):

| path | before |
|---|---|
| `zkminer benchmark` | saves only with `--calibrate`. With a failed worker it saved the simulated suite (`save_benchmark` had no check) |
| TUI full benchmark (`[b]` on the Benchmark screen, `run_full_benchmark`) | **saved the suite unconditionally** and set it as `benchmark_results`, which a simulated suite reached. The evaluator only skips jobs for a simulated suite when `job.throughput <= 0` |
| TUI streaming benchmark (startup, per-device) | already refused a suite with no GPU rows. A partial run replaced every GPU row, including the failed card's |
| `spawn_streaming_benchmark` in `run.rs` and `mock.rs` | saved unconditionally. Dead code: no caller (rustc's `never used` warnings); removed |
| `load_cached_benchmark` | loaded a simulated suite if one was on disk |

## What changed

| where | change |
|---|---|
| `dispatcher.rs` | `benchmark_all_with_device_info` and `benchmark_all_streaming` return a `BenchmarkRun { results, failures }`. Each `SlotBenchmarkFailure` has the slot key, the GPU name and tag, and the error with its causes. A slot that answers with no rows is also a failure (`NO_BENCHMARK_ROWS`). New `has_any_worker()`: a proving slot or a measure worker. |
| `benchmark.rs` | `BenchmarkSuite.failures` (`serde(skip)`: never cached). `run_benchmark` simulates **only when no compiled-in backend and no worker exists**; with workers present an empty run is a failure (`note_unexplained_empty_run`, e.g. only measure workers started). A simulated run has `zkops = 0`. `not_cacheable()` (failed, simulated, or measured nothing) is checked by `save_benchmark_to`, the one gate every save goes through. `load_cached_benchmark_from` ignores a simulated cache. `describe_failures` and `benchmark_failure_advice` give per-worker lines and what to try (Metal: `tools/macos-smoke.sh` and Troubleshooting in the kit README; others: the worker's `--benchmark` by hand). The "no device rows" GPU-power warning no longer fires when nothing proved. |
| CLI `commands/benchmark.rs` | On failure: no table (or, when other workers measured, their real rows only), then `BENCHMARK FAILED: nothing was measured or saved.`, a line per worker with its error, the advice, and **exit 1** (`Error: the benchmark failed on risc0:metal:0`). `--calibrate` does not calibrate or save a failed or simulated run. `--json` prints nothing on stdout on a total failure. A simulated run (no worker at all) prints `SIMULATED` on every line and in the table header, and no zkOP/s score. It still exits 0, because that is not a failure. |
| TUI `app.rs` | A failed run (full or streaming) is logged as `Benchmark FAILED: previous results kept, nothing saved`, plus the per-worker lines and advice (`report_unusable_benchmark`). It is not merged, saved or shown. The full benchmark's simulated suite is no longer saved or set as the results. |
| CPU power line | `sudo chmod o+r /dev/cpu/0/msr` is Linux-only. macOS logs at INFO: `CPU power is not measured on macOS; the cost model uses the configured system_power_watts and its default CPU draw`. Other platforms get a one-line INFO. |
| worker `--benchmark` (`zkminer-prove-risc0`) | `run_benchmarks` returns the rows and the names of the programs that did not prove and verify, including the discarded warm-up and the zkOP/s scoring proof. The table prints as before, then `BENCHMARK FAILED: <names> did not prove and verify` and **exit 1**. `BENCH_ONLY=fibonacci` (the smoke test and `install.sh --warm`) exits 1 when its one proof fails. |
| test aid `ZKMINER_TEST_FORCE_FAIL=<step>[,...]` (worker) | `warmup` fails the IPC `Warmup` and the `--benchmark` warm-up. A program name fails that program. Nothing is proved for a forced step. Nothing reads it on the job path (`Prove`). This is how the real forced-failure run below works without breaking the GPU. |
| mock worker | `MOCK_FAIL_ON=warmup|benchmark` answers with an `Error` (the worker stays up), with `MOCK_FAIL_MESSAGE`. |
| `packaging/macos/install.sh` | `--warm` used `set -e`, so with the new exit code a failed warm-up proof would have aborted silently. It now prints a WARNING naming `tools/macos-smoke.sh` and Troubleshooting. The install itself is already complete at that point. |
| `packaging/macos/README.md` | the "exits with status 0 even when a program fails" sentence is replaced. New **Troubleshooting** section: `BENCHMARK FAILED` (what it means, the smoke script and its exit codes, the worker's own lines, re-run after a macOS update), a `SIMULATED` table, a failed `--warm`. |

Revert knobs: none. These are correctness fixes, not optimizations, and nothing on the proving path changed (below).

## After

| run | result |
|---|---|
| mock, warm-up error, `zkminer benchmark` (`repro/after-fail-warmup.log`) | no table, `BENCHMARK FAILED: nothing was measured or saved.`, `risc0:metal:0 (Apple M5 Max): warm-up of risc0:metal:0 failed: warm-up failed: ... stepAccumA: Compilation failed`, the macos-smoke.sh advice, **rc 1**, no `benchmarks.json` |
| **real worker** (this branch's release build), `ZKMINER_TEST_FORCE_FAIL=warmup zkminer benchmark` (`real/forced-warmup.log`) | the same output with `forced failure (ZKMINER_TEST_FORCE_FAIL=warmup)`, **rc 1**, no table |
| **real worker, real `zkminer benchmark`** (`real/real-cli.log`, sandbox `HOME` with the user's Groth16 component and pipeline cache) | **rc 0**, warm-up, the 5 programs and the zkop-mix score through the dispatcher: **2.65 MzkOP/s** (risc0 0.88M c/s), STARK sha256-chain 51.30 / ecdsa-verify 71.58 / bigint-mul 30.65 / memory-merkle 8.68 / chacha-mix 10.00 s (sum 172.21 s), zkop-mix 70.01 s, Groth16 1.61-1.64 s, wall 265 s. Load average was 4.5 at the start and 18.2 at the end: another session's work. W10-INT measured 2.72 MzkOP/s at load 0.6-3.4. The A/B below shows that the code did not cause the difference. |
| no worker at all (`repro/after-none.out`) | rc 0. `SIMULATED BENCHMARK: no prover worker was found...`, every row prefixed `SIMULATED`, no MzkOP/s line, nothing saved |
| worker `BENCH_ONLY=memory-merkle ZKMINER_TEST_FORCE_FAIL=memory-merkle --benchmark` | the warm-up proves; then `BENCHMARK FAILED: memory-merkle did not prove and verify`, **rc 1** |
| worker `BENCH_ONLY=fibonacci ZKMINER_TEST_FORCE_FAIL=warmup --benchmark` | `BENCHMARK FAILED: fibonacci (warm-up) did not prove and verify`, **rc 1** |
| worker `BENCH_ONLY=fibonacci --benchmark` (and all 23 B runs of the A/B below) | rc 0, `fibonacci: 32768 cycles — ... verified` (the smoke script's regex still matches) |
| `CPU power` line on this Mac | `INFO CPU power is not measured on macOS; ...` (was `WARN ... sudo chmod o+r /dev/cpu/0/msr`) |

## Performance: no change (interleaved A/B)

The worker change (one environment read per benchmark program, before its stopwatch, and one in `Warmup`) is not on
the job path, and no kernel or risc0 code changed, so R17 (`ir_scan.py`, `run_stress.sh`) does not apply. To check it
anyway I ran an A/B of `BENCH_ONLY=memory-merkle --benchmark` (warm-up + memory-merkle, `/usr/bin/time -l`), with
A = W10-INT's release worker (`zk-miner-3.1-wt-W10-INT/target/release`, `72b4000` code) and B = this branch. The order
was A B A B ..., each run alone under `gpu-run --no-budget` (`scripts/ab_mm.sh`). Load average was 17-25 throughout
(other sessions), so absolute times are ~3-5 % above W10-INT's low-load figures. The A-vs-B comparison is what counts:

| budget | pairs | A STARK median [min-max] | B STARK median [min-max] | A / B peak footprint (median) |
|---|---|---|---|---|
| default (po2 20) | 9 | 8.69 [8.63-8.83] s | 8.68 [8.44-8.74] s | 13.98 / 13.98 GB |
| 8 GiB (po2 19) | 7 | 10.83 [10.75-10.95] s | 10.84 [10.51-10.89] s | 8.34 / 8.33 GB |
| 4 GiB (po2 18) | 7 | 14.93 [14.80-15.09] s | 14.93 [14.75-15.14] s | 5.81 / 5.83 GB |

Every difference is inside the A-vs-A spread, so the result is no change. Peak memory is unchanged at both simulated
budgets. All 46 runs exited 0.

## Correctness and gates (logs in `tests/`)

| gate | result |
|---|---|
| `cargo test -p zkminer-prover --features testing --tests` (`ZKVM_ALLOW_SKIP=1`, default parallel harness), ×2 | 392 passed, both runs: lib **296** (W10-INT 292: +4 `failure_cache_tests`), `worker_lifecycle` **30 passed / 3 ignored** (+3: a failed warm-up on both paths, a benchmark error or an empty answer, an empty pool), new `benchmark_failure` 1/1 (`run_benchmark`, `run_benchmark_gpu_only`, `run_benchmark_gpu_only_streaming` with the global pool's worker failing: a failed suite, never simulated, zkops 0, advice present, refused by the cache), the rest as W10-INT |
| `cargo test --workspace --exclude zkminer-prove-sp1 --exclude zkminer-prover`, ×2 | **502 passed / 18 ignored** both runs (W10-INT 497: +3 CLI `benchmark_cli`, +2 TUI `unusable_benchmark_tests`) |
| CLI-level test `crates/zkminer-cli/tests/benchmark_cli.rs` (in the run above) | the real `zkminer` binary, sandbox `HOME`, run from its own directory (discovery also searches the CLI's directory, and `target/debug` holds a real Metal worker). Mock Metal worker with a failing warm-up: rc ≠ 0, no `Program`/`c/s`/`zkOP/s`/`simulated` on stdout, the worker, its error and the macos-smoke.sh advice on stderr, also with `--calibrate`, and `--json` prints nothing. Mock CPU worker: the same with the generic advice. No worker: every table line says SIMULATED, no MzkOP/s, nothing saved with `--calibrate` |
| `cargo test -p zkminer-prove-risc0 --features metal`, ×2 | **68 passed** (W10-INT 66: +2 `bench_exit_tests`, the knob and a run whose every step fails, which reports each step, warm-up and zkop-mix included, without touching the GPU), 4 ignored |
| Metal IPC tests (`--release --test metal_worker --ignored`, one per lock) | 4/4: warm-up + prove 5.4 s, first prove without warm-up 7.2 s, the 4 GiB keccak-then-Groth16 sequence 17.9 s, 20 sequential proofs 66.4 s |
| receipt | this branch's worker, `BENCH_ONLY=fibonacci ZKMINER_BENCH_RECEIPT_DIR`: **STOCK 3.1 VERIFY: OK** (crates.io 3.1.0 `stock-verify31`, selector e71e6620). No proving code changed, so the CPU bit-exactness and 3.0-rejection evidence of W10-INT stands |
| `scripts/ci/test-assemble-macos.sh <release worker> <release CLI>` (sdk mode) | 17/17. The kit-mode cases (W10-INT's 44 used RC2's kit binaries) were not run, because they need a kit build. The installer's `--warm` change is covered by `bash -n` and shellcheck (no new findings; the file's existing warnings are unchanged) |
| release build `make -f Makefile.mac RISC0_SRC=git mac-build-worker` (through the local risc0 mirror, RELEASE-DEPS.md) | rc 0, worker 184,537,232 B, CLI 15,969,360 B |
| rustfmt / clippy | the changed lines are rustfmt-clean (only the files' existing deviations remain; `cargo fmt` on the workspace rewrites unrelated files, so it was not used). Clippy reports nothing new on the changed lines |

During one early run of the CLI test, the sandbox did not isolate discovery: it found cargo's real
`target/debug/zkminer-prove-risc0-metal` next to the CLI, and that worker warmed up under the test's `--light` lock
(2 GiB budget), where its Groth16 key load was refused. That run was harmless. The test now runs a copy of the CLI
from the sandbox.

## Budgets

The proving path did not change, and peak memory is unchanged at the default, 8 GiB and 4 GiB budgets (table above).
The CLI's failure path allocates nothing.

## Open issues

1. **A slot whose zkOP/s scoring proof fails is not a failure in the CLI.** Its program rows are real, so it is
   reported as a successful run with `0.00 MzkOP/s` for that GPU ("no zkOP/s score" is logged). The worker's own
   `--benchmark` counts it as a failure (exit 1). If the score must always exist, `run_benchmark_requests` could
   return an error for it. I left this out of scope: the dispatcher's behaviour here is main's.
2. **A partial run in the TUI is now dropped whole** (one card failed, another measured): nothing is merged or saved,
   and the previous results stay, so a fixed card needs a new full run. Before this change, the measured card's rows
   replaced every GPU row and the failed card lost its saved row.
3. `docs/release/BETA_RC.md` still lists these as open findings (section 2 item 5, lines 118-122 and 295-296). The RC
   round of this wave should record them as fixed by this item.
4. `cfg(target_os = "linux")` / Windows branches (the RAPL line) compile only for macOS here, as in W10-INT open
   issue 2. A Linux and Windows CI build is still needed.
5. Simulated mode still exits 0: there is no worker to blame. Every line says SIMULATED. Change it if the release
   wants `zkminer benchmark` to fail on a machine with no prover at all.
