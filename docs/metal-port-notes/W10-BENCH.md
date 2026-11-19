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

## Fix round 1 (review findings)

Logs: `/Users/user/zkminer/scratch/w10/W10-BENCH/r1-*`.

### Finding A: a declined or unstartable sibling failed every benchmark

`discover_and_spawn` keeps a slot whose worker DECLINED (`sp1 unavailable: libcudart.so.12 not found`) or could not
start, with no handle. Neither benchmark loop skipped it. Its `benchmark_slot` re-declined or hit the respawn backoff,
and since the first round that error was a `SlotBenchmarkFailure`. So on a multi-backend rig `zkminer benchmark
--calibrate` exited 1, the TUI's streaming benchmark never saved the working card's rows, and `benchmark_targets` kept
listing the declined slot, which re-ran the startup benchmark on every start.

Fix (`dispatcher.rs`):
- `BenchmarkRun.not_benchmarked`: slots that were down when the run started and stayed down. A declined slot is not
  tried at all (it is never respawned, so trying only re-declines) and is recorded with its decline reason. A slot
  with no worker is still tried, because a respawn may bring it up. If it is still down afterwards, its error goes
  here rather than into `failures`.
- `BenchmarkRun::finish`: when no slot measured, these become the run's failures with their own reasons, so a lone
  Metal worker that never started still fails the benchmark.
- `benchmark_targets` leaves out declined slots (`try_lock`, so it never waits on a proof).
- The streaming queue does not announce declined slots.
- `BenchmarkSuite.not_benchmarked` (`serde(skip)`): the CLI prints `WARNING: <slot> was not benchmarked: <reason>`,
  and the TUI logs it at Warn. The run is saved as usual.

### Findings B and C: a short suite was a successful, cached benchmark

`run_benchmark_requests` returned whatever rows came back. A worker leaves out a program that fails to prove and
verify, and a failed zkop-mix score was only logged. So the reviewer's repro on the real worker,
`ZKMINER_TEST_FORCE_FAIL=sha256-chain,ecdsa-verify,bigint-mul,chacha-mix,zkop-mix zkminer benchmark`, printed a
normal table and exited 0, and `--calibrate` or the TUI would have saved it. I checked this before the fix: mutation
runs with the round-1 logic disabled fail all 5 new tests (`mutation.log` in the log directory).

Fix: `missing_benchmark_rows(backend, entries)` lists every program of `benchmark_suite(backend)` that has no row,
plus `zkop-mix` on risc0 and SP1 (the zkVMs a score is defined for; OpenVM's stub worker never returns one). The SP1
cycle-mismatch case drops the score row, so it is covered too. When anything is missing, `BenchmarkRun::record`
keeps the rows in `results` (so the CLI can show them) and adds a failure:
`the benchmark is incomplete: no result for programs: ... (the worker's own log lines above say why)`. The suite is
then `failed()`. The CLI shows the rows under `BENCHMARK FAILED: the results above are incomplete; nothing was saved
or used for pricing.` and exits 1. `save_benchmark_to` refuses the suite, and the streaming `Finished` event reports
`succeeded: false`. `zkminer benchmark` and the worker's own `--benchmark` now agree: both exit 1 when any program or
the score fails. This closes the first round's open issue 1.

Both loops now share `BenchmarkRun::record`, which replaced the two copies of the outcome match.

### Non-blocking items also done

- `benchmark_cli.rs` skips with `SKIPPED: no mock worker at ...` when the mock is not built, rather than failing.
- Worker `--benchmark` with a `BENCH_ONLY` that names nothing (`memroy-merkle`) exits **2** before any GPU work, and
  lists the valid names. Before, it ran the warm-up, printed an empty table and exited 0.
- When `ZKMINER_TEST_FORCE_FAIL` is set, `--benchmark` warns at start. The knob is documented in
  `docs/macos-beta.md` (debug-only environment variables). In IPC mode the failure text names it.
- The synthetic `workers` failure (only measure workers came up) carries the `metal` tag on macOS, so it gives the
  macos-smoke.sh advice.
- `format_mzkops(-0.0)` prints `0.00`, not `-0.00`.

New test aids: in the mock worker, `MOCK_BENCH_ROWS=all` returns one row per requested program and
`MOCK_BENCH_DROP=<names>` leaves some out. `WorkerPool::insert_test_down_worker` registers a declined or unstartable
slot (`testing` feature only).

### Round-1 tests

| test | checks |
|---|---|
| `worker_lifecycle::a_complete_suite_is_a_clean_run` | control: every program + score, both entry points, no failure |
| `worker_lifecycle::a_short_suite_is_the_slots_failure` | 4 programs + score dropped / only memory-merkle dropped / only zkop-mix dropped: rows kept, one failure naming each missing name, streaming `Finished{succeeded:false}` |
| `worker_lifecycle::a_declined_or_unstartable_sibling_does_not_fail_a_working_card` | a working metal mock + declined `sp1:cuda:0` + unstartable `openvm:cuda:1`: no failure, both in `not_benchmarked` (decline reason kept), `benchmark_targets` drops the sp1 slot and keeps the openvm one |
| `worker_lifecycle::only_down_slots_fail_the_run` | a lone declined slot is the run's failure, with its reason |
| new `benchmark_partial` (own binary: global pool) | `run_benchmark`, `run_benchmark_gpu_only`, `run_benchmark_gpu_only_streaming` with a short suite + declined sibling: failed, memory-merkle row kept, zkop-mix named, sibling only in `not_benchmarked`, cache refuses it |
| new `benchmark_declined_sibling` (own binary) | a working card beside a declined one: not failed, device rows present, `not_cacheable() == None`, saved |
| CLI `a_short_metal_suite_fails_the_benchmark_and_saves_nothing` | the real CLI binary with a short mock suite under `--calibrate`: rc ≠ 0, BENCHMARK FAILED / incomplete, missing names, memory-merkle row shown, no `benchmarks.json` |
| CLI `a_complete_metal_suite_is_a_normal_benchmark` | control: rc 0, table with MzkOP/s, no SIMULATED, no failure |
| worker `bench_exit_tests::bench_only_names_are_checked` | valid names accepted (case-insensitive), typos refused |

### Round-1 gates

| gate | result |
|---|---|
| `ZKVM_ALLOW_SKIP=1 gpu-run -- cargo test --locked -p zkminer-prover --features testing --tests`, ×2 | **398 passed / 0 failed / 21 ignored**, both runs. Lib 296; `worker_lifecycle` 34 passed / 3 ignored (+4); `benchmark_failure`, `benchmark_partial` and `benchmark_declined_sibling` 1/1 each |
| `gpu-run -- cargo test --locked --workspace --exclude zkminer-prove-sp1 --exclude zkminer-prover`, ×2 | **504 passed / 18 ignored**, both runs (+2 CLI tests) |
| `gpu-run -- cargo test --locked -p zkminer-prove-risc0 --features metal`, ×2 | **69 passed**, 4 ignored, both runs (+1) |
| release build (`make -f Makefile.mac RISC0_SRC=git JOBS=6 mac-build-worker`) | rc 0, worker 184,537,568 B, CLI 16,005,168 B |
| **real `zkminer benchmark`** (release CLI + worker, sandbox `HOME` `rhome`, gpu-run on the real `HOME`) | **rc 0**, 2.67 MzkOP/s (risc0 0.89M c/s), STARK 52.18 / 72.65 / 31.13 / 8.52 / 10.04 s (sum 174.52 s), zkop-mix 69.60 s, Groth16 1.77-1.81 s. Load average 14.5 at the start and 3.2 at the end, from other sessions' work. This is a functional gate, not a speed claim. This round changed no proving code: dispatcher bookkeeping after the rows arrive, and an argument check in the worker before any GPU work. The first round's interleaved A/B covers the worker binary. (`r1-real.out`) |
| **real worker, reviewer's partial repro**, `ZKMINER_TEST_FORCE_FAIL=sha256-chain,ecdsa-verify,bigint-mul,chacha-mix,zkop-mix zkminer benchmark --calibrate` | **rc 1**. The memory-merkle row (8.53 s) is shown under `BENCHMARK FAILED: the results above are incomplete; nothing was saved or used for pricing.`, then `risc0:metal:0 (Apple M5 Max): the benchmark is incomplete: no result for programs: sha256-chain, ecdsa-verify, bigint-mul, chacha-mix, zkop-mix ...` and the macos-smoke.sh advice. No `benchmarks.json`. `0.00 MzkOP/s` (was `-0.00`). (`r1-partial.*`; before the fix this gave rc 0 and a normal table, per the reviewer's `scratch/w10/W10-BENCH-rev1/partial.log`) |
| real worker, `ZKMINER_TEST_FORCE_FAIL=warmup zkminer benchmark` | **rc 1**, no table, BENCHMARK FAILED with the worker, its error and the advice (`r1-warm.*`) |
| worker `BENCH_ONLY=memroy-merkle --benchmark` | **rc 2**, `BENCH_ONLY=memroy-merkle names no benchmark program; use one of: fibonacci, sha256-chain, ...` |
| worker `BENCH_ONLY=fibonacci --benchmark` | rc 0, `fibonacci: 32768 cycles — ... verified` |
| `scripts/ci/test-assemble-macos.sh <release worker> <release CLI>` | 17/17 (sdk mode) |
| clippy / rustfmt | nothing new on the changed lines. A `cargo fmt` run touched unrelated files; those changes were reverted and only this item's hunks were kept |

Lock hygiene: the first round's sandbox `rhome` contained `zkminer/.gpulock`, which means at least one first-round
gpu-run was started with `HOME` set to the sandbox and so took a private lock. I removed that directory. Every
round-1 command ran gpu-run with the real `HOME`, and set the sandbox `HOME` only for the child (`env HOME=...`).

## Fix round 2 (review findings)

### Finding: a failed GPU worker was a warning when a CPU worker or the OpenVM stub measured

Round 1's `was_down` rule made a slot that was down at the start (crash or backoff, not a decline) "not
benchmarked" whenever ANY other slot returned rows. Two shapes the reviewer reproduced with mock workers
(`scratch/w10/W10-BENCH-review2/probe{1,2}.log`) were then clean runs: exit 0, a normal table, cached under
`--calibrate`, priced by `zkminer run`:

1. `risc0:metal:0` (or `risc0:cuda:0`) down, plus a `risc0:generic` CPU worker. `gpu_backends` counted only GPU slots
   with a running worker, so the CPU worker was benchmarked in the GPU's place, and the GPU's error was a warning.
2. `risc0:cuda:0` down, plus the OpenVM worker (shipped in the Linux release layout by `assemble-release.sh` and
   `unpack-provers.sh`). `zkminer-prove-openvm` cannot prove (every `Prove` is an error); its `Benchmark` answer times
   a busy loop and labels the rows `openvm`. `is_simulated()` only knows the `simulated` label, and
   `missing_benchmark_rows` exempts OpenVM from `zkop-mix`, so a host whose only real prover failed to start showed,
   cached and priced simulated OpenVM numbers: the item's original defect by another route.

Fixed at the root, in `dispatcher::BenchmarkRun` (both loops share it):

* A down, non-declined slot's error is held until `finish()`. It becomes "not benchmarked" only if a GPU slot
  (cuda/rocm/intel/metal) of the SAME backend measured a complete suite (one card of a multi-card rig is down).
  Otherwise it is a failure. A CPU `generic` worker, another backend, or a same-backend GPU whose own suite came
  back short never covers for it. This also makes a down slot of another backend (for example `sp1:cuda:0` that
  crashed at start beside a working risc0 card) a failure again, as in `cd6143a`. A slot that DECLINED at startup
  is still only reported (round 1, Finding A): it said it cannot prove here.
* `gpu_backends`, the rule that skips a backend's CPU worker when it has a GPU worker, now counts GPU slots that are
  down but not declined, too. They are still tried (a respawn may bring them up), and if they stay down the run fails,
  so benchmarking the CPU worker would only add a very long CPU risc0 run to a failed benchmark. A declined GPU slot
  still lets the CPU worker run: the host does prove on the CPU then.
* New `simulated_benchmark_reason(backend, entries)`: a backend in `SIMULATED_BENCHMARK_BACKENDS` (OpenVM) or any row
  labelled `simulated`. Such a slot is never run (OpenVM: skipped like a declined slot, not announced in the
  streaming queue) or, if rows labelled `simulated` come back, its rows are discarded. Either way it goes into
  `not_benchmarked` with `not measured (SIMULATED): ...`. Nothing from it reaches `results`, so nothing is shown,
  cached or priced (`average_throughput`, `device_benchmarks`), and it never counts as a slot that measured: with
  nothing else measured, `finish()` makes it the run's failure. The streaming `Finished` event says
  `succeeded: false` for it.
* `benchmark_targets()` leaves OpenVM slots out. Their rows can never be saved, so counting them made every TUI start
  re-run the startup benchmark.

I did not change the OpenVM worker's labels. The dispatcher decides by backend, so an old or third-party stub
cannot get around it. When OpenVM proving is implemented, remove it from `SIMULATED_BENCHMARK_BACKENDS`.

Behaviour changes to record for the RC round:
* On a multi-backend Linux rig, a worker of another backend that crashes at start now fails `zkminer benchmark`
  (exit 1, nothing cached). This is the `cd6143a` behaviour. Round 1 had made it a warning. A worker that declined is
  still a warning.
* A Linux host with only the OpenVM stub and no working prover now fails the benchmark with the SIMULATED reason.
  Before, it showed and cached OpenVM's busy-loop numbers.
* SP1 (reviewer's note): `run_benchmark_requests` drops SP1's `zkop-mix` row when its cycle count is not
  `ZKOP_MIX_SP1_CYCLES`, and since round 1 the missing row fails the whole SP1 benchmark. That error says
  `no result for programs: zkop-mix (the worker's own log lines above say why)`, and the WARN line above it gives the
  cycle mismatch.

Also (reviewer's non-blocking note): in `packaging/macos/README.md` Troubleshooting, "Nothing was measured, and
nothing was saved" now reads: rows printed under `the results above are incomplete` did prove, and nothing was saved
or used for pricing.

### Round-2 tests (each fails with the round-2 logic disabled)

Mutation run (`scratch/w10/W10-BENCH/r2/mutation.log`): `finish()` always files a down slot as not benchmarked,
`simulated_benchmark_reason` always returns `None`, and `gpu_backends` uses the old `handle.is_some()`. With these
mutations, all 5 new tests fail. The updated round-1 test still passes, as it should, because it covers the
declined and same-backend cases.

| test | shape |
|---|---|
| `worker_lifecycle::a_down_gpu_slot_is_not_covered_by_a_cpu_worker` | reviewer's probe 1: `risc0:generic` mock with all rows, plus a down `risc0:metal:0`, then a down `risc0:cuda:0`. Both loops: the GPU slot is in `failures` and the CPU worker is not benchmarked |
| `worker_lifecycle::openvm_stub_rows_are_never_measurements` | reviewer's probe 2: an `openvm:generic` mock with all rows, plus a down `risc0:cuda:0`. No results, and both are failures (OpenVM's says SIMULATED). Beside a working Metal card: a clean run, OpenVM not announced, not run and not a target |
| `worker_lifecycle::a_down_slot_of_another_backend_fails_the_run` | a working Metal card plus a down `sp1:cuda:0`: a failure |
| `dispatcher::benchmark_run_tests::only_a_same_backend_gpu_covers_for_a_down_slot` | bookkeeping only: CPU stand-in and other backend give a failure; a same-backend GPU, in either order, gives not benchmarked; a same-backend GPU with a short suite gives two failures |
| `dispatcher::benchmark_run_tests::simulated_rows_are_never_results` | rows labelled `simulated` never become a result; alone they are a failure; an OpenVM slot covers for no down OpenVM slot |
| `worker_lifecycle::a_declined_or_unstartable_sibling_does_not_fail_a_working_card` (updated) | the unstartable sibling is now `risc0:cuda:1` (same backend as the working card). An unstartable sibling of another backend is the new test above |

### Round-2 gates (logs in `scratch/w10/W10-BENCH/r2/`)

| gate | result |
|---|---|
| `ZKVM_ALLOW_SKIP=1 gpu-run -- cargo test --locked -p zkminer-prover --features testing --tests` x2 | both rc 0: **403 passed**, 0 failed, 21 ignored (+5 new) (`prover-{1,2}.log`) |
| `gpu-run -- cargo test --locked --workspace --exclude zkminer-prove-sp1 --exclude zkminer-prover` x2 | both rc 0: 504 passed / 18 ignored (`ws-{1,2}.log`) |
| `gpu-run -- cargo test --locked -p zkminer-prove-risc0 --features metal` x2 | both rc 0: 69 passed / 4 ignored (`r0metal-{1,2}.log`) |
| `make -f Makefile.mac RISC0_SRC=git JOBS=6 mac-build-worker` | rc 0. Worker 184,537,568 B (unchanged; no worker code changed this round), CLI 16,007,104 B |
| **real `zkminer benchmark`** (release CLI + worker, sandbox `HOME`) | **rc 0**: 2.70 MzkOP/s (risc0 0.90M c/s). STARK 51.21 / 72.01 / 30.90 / 8.38 / 9.77 s (sum 172.27 s), zkop-mix 68.82 s, Groth16 1.73-1.74 s. Load average 11.7 at the start, 1.0 at the end. A functional gate, not a speed claim (`real.out`) |
| real worker, `ZKMINER_TEST_FORCE_FAIL=warmup zkminer benchmark --calibrate` | **rc 1** with no table: `BENCHMARK FAILED: nothing was measured or saved.`, the worker, its error and the macos-smoke.sh advice. No `benchmarks.json` (`warm.*`) |
| real worker, reviewer's partial repro (`ZKMINER_TEST_FORCE_FAIL=sha256-chain,ecdsa-verify,bigint-mul,chacha-mix,zkop-mix ... --calibrate`) | **rc 1**: only the memory-merkle row, under `BENCHMARK FAILED: the results above are incomplete; nothing was saved or used for pricing.`, followed by the missing programs. No `benchmarks.json` (`partial.*`) |
| rustfmt / clippy | nothing new on the changed lines (the files' existing rustfmt drift was left alone) |

### Round-2 A/B (the reviewer's lens, re-run to completion)

A is the base `item/W10-INT` `29488c2` release worker (built by the reviewer in
`scratch/w10/W10-BENCH-verify/base`). B is this branch's release worker. Each run is
`BENCH_ONLY=memory-merkle RUST_LOG=info RISC0_METAL_ARCHIVE_GC=0 /usr/bin/time -l <worker> --benchmark`, alone under
`gpu-run --no-budget`, in the order A B A B ... (`r2/ab/ab_pair.sh`). All runs exited 0.

| budget | pairs | A STARK median [min-max] | B STARK median [min-max] | A / B peak footprint median [range] | load |
|---|---|---|---|---|---|
| default (po2 20) | 8 | 8.63 [8.47-8.82] s | 8.69 [8.46-8.86] s | 13.972 [13.967-14.614] / 13.971 [13.963-13.978] GB | 6.2-17.1 |
| 4 GiB (po2 18) | 8 | 14.20 [14.15-14.24] s | 14.23 [14.17-14.29] s | 5.796 [5.795-5.797] / 5.817 [5.808-5.839] GB | 1.0-5.3 |

The time differences are within the A-vs-A spread, so there is no change. At 4 GiB, B's peak footprint was 21 MB
(0.36 %) higher in AB order. The worker's own breakdown puts it before the first proof ("start" 4178 vs 4164 MiB).
GPU memory was identical (segments 2404, recursion 2199, wrap 3944 MiB). To see whether it follows the binary, I ran 4
more pairs in BA order (`r2/ab/BA-4294967296`). The second run of each pair was the higher one again: B 4163-4164 MiB
and A 4178-4181 MiB at start, with peaks of B 5.796-5.830 and A 5.810-5.830 GB. So the difference is an order effect
of back-to-back runs, not the code: peak memory is unchanged at both budgets. This round changed no worker code. The
worker diff against the base is round 1's: a `BENCH_ONLY` name check and a warning, both before any GPU work.

## Open issues

1. ~~A slot whose zkOP/s scoring proof fails is not a failure in the CLI.~~ Fixed in round 1: a missing score (or any
   missing suite program) fails the run, and nothing is cached.
2. **A run where one card fails and another measures is dropped whole in the TUI**: nothing is merged or saved, and
   the previous results stay, so a fixed card needs a new full run. A card that was down from the start (declined,
   or never started) no longer counts as failed (round 1): only a card whose worker ran and failed drops the run.
3. `docs/release/BETA_RC.md` still lists these as open findings (section 2 item 5, lines 118-122 and 295-296). This
   wave's RC round should record them as fixed by this item (`cd6143a`, `95009c1` and the round-2 commit), along with
   the round-2 behaviour changes listed above.
4. `cfg(target_os = "linux")` / Windows branches (the RAPL line) compile only for macOS here, as in W10-INT open
   issue 2. A Linux and Windows CI build is still needed.
5. Simulated mode still exits 0: there is no worker to blame. Every line says SIMULATED. Its `--json` output marks it
   only with `prover_backend: "simulated"` and `zkops: 0`, and `failures` is not serialized: a `--json` consumer of a
   failed partial run sees the rows, and only the exit code says it failed.
6. A slot that was down at the start, then came up and failed (for example a respawned worker whose warm-up
   fails and which is retired again), counts as "not benchmarked" rather than failed. Since round 2 that happens only
   when a GPU of its own backend measured a complete suite, as with a second card on a multi-card rig. With a single
   worker (every Mac) it is still the run's failure.
10. OpenVM is excluded from benchmarks by backend (`SIMULATED_BENCHMARK_BACKENDS`) until its worker can prove.
    Implementing OpenVM proving must remove it there, or OpenVM will never be benchmarked or priced.
11. `benchmark_targets()` matches only cuda/rocm/intel, so the TUI's startup "re-benchmark when a card has no saved
    row" logic does not see a Metal card (reviewer's note; not introduced here). Worth checking in the RC round.
12. The reviewer's base worktree `scratch/w10/W10-BENCH-verify/base` (detached at `29488c2`, a worktree of the main
    checkout) was used as A in the round-2 A/B. I left it in place: removing it means `git worktree remove` on the main
    checkout's metadata, which is not this item's to edit.
7. `ZKMINER_TEST_FORCE_FAIL` is still read by the release worker, on the warm-up and benchmark paths only. It is
   documented, and `--benchmark` warns when it is set. It is not behind a cfg: the real forced-failure gate needs it in
   the release build.
8. `crates/zkminer-cli/tests/benchmark_cli.rs` needs `target/debug/mock-worker`, which
   `cargo build -p zkminer-prover --features testing --bin mock-worker` builds (it now skips with a message when the
   mock is missing). CI should build the mock explicitly if it runs these tests. The workflows run `--lib --bins`
   today.
9. Not this item: `zkminer-prover-protocol proc::tests::a_healthy_child_is_fast_and_successful` has a 150 ms bound
   that fails under load, and its panic poisons the test lock for 7 sibling tests (reviewer's observation). It did
   not recur in this round's runs. It is a W10-INT follow-up (PLAN 8.7).
