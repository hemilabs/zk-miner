# Executed validation — 2026-10-31

Gate 1 passed: genuine complete CPU-path proofs, including final Groth16,
accepted by an independently built unchanged Hemi verifier. Gate 2 passed:
real miner WorkerPool discovery/IPC/admission, multiple complete proofs,
wrapping timeout/cleanup, restart and shutdown. This is a bounded experimental
local slice with an emulated wrapping helper. Subsequent hybrid harness and
native-worker milestones are recorded below. Full Gate 3 stability/performance
and network acceptance remain open. The whole specification is not complete.

The earlier sections retain their milestone-specific results and failures; later
sections supersede historical statements about Metal availability.

## Source/build evidence

The source/hardware audit was written before broad implementation. Original
Hemi and upstream checkouts remain clean and unchanged. The implementation
engine worktree uses the exact miner pin; upstream HEAD was never substituted.
The original CPU check failed because `xcrun metal` was invoked on a machine
without the Metal compiler (`target/macos/check-original.log`). Explicit
Metal feature propagation fixed this; CPU check/build then succeeded.

Actual successful build commands (from the miner root after sourcing env.sh):

```sh
cargo +1.93.0 build --release --features prove --manifest-path tools/macos-proof/Cargo.toml --config target/macos/local-engine.toml --target-dir target/macos/cpu
python3 scripts/macos/build-guest.py fibonacci --config target/macos/local-engine.toml
python3 scripts/macos/build-guest.py sha256-chain --config target/macos/local-engine.toml
python3 scripts/macos/build-guest.py segment-boundary --config target/macos/local-engine.toml --reset-lock
sh scripts/macos/build-verifier.sh
python3 scripts/macos/build-worker.py --config target/macos/local-engine.toml --engine /Users/dbur/.codex/worktrees/hemi-macos-cpu/risc0
cargo +1.93.0 build --locked --release -p zkminer-cli --bin zkminer --target-dir target/macos/miner
```

`file` identifies harness, worker, miner and verifier as Mach-O arm64.
Source metadata verifies 17 local worker engine packages and 10 unchanged
Git verifier packages. Feature trees are in `target/macos/{worker,verifier}-tree.txt`.
The worker build saves its local lock and restores the root Git lock; its only
root lock additions are existing libc/risc0-binfmt dependencies, with
no version upgrades. Verifier tests use original circuit/verifier parameters.
`zkminer --help` is the only CLI operation used after the native miner build.
A final rebuild initially used the wrong package name `-p zkminer` and failed;
the actual package is `zkminer-cli`, binary `zkminer`.

## Genuine proof attempts

Every attempt, including failures, is recorded in `target/macos/runs/results.jsonl`.
Full artifacts include intermediate receipts, complete receipt/seal/journal,
proof/verification JSON and stage logs. Independent expected journals are
computed from arithmetic/hash inputs, not copied from generated receipts.

| Run prefix | Workload / po2 | Outcome |
|---|---|---|
| d5c3df7d | Fibonacci / 18, raw ELF | Failed: malformed ProgramBinary; fixed by packing authentic ELF + pinned V1COMPAT kernel |
| facaf950 | Fibonacci(20) / 18 | Complete Groth16, independent positive and 3 negative checks passed |
| 9cc541fc | Fibonacci(20) / 18 | Second consecutive complete proof, same independent checks passed |
| d811a606 | SHA-256-chain(10) / 18 | Complete Groth16, independent checks passed |
| 03aeaeb7 | Segment boundary / 14 | Verified 22-segment composite, then missing `lift_rv32im_v2_13.zkr`; incomplete proof, failed |
| f2bd8b66 | Segment boundary / 18 | Complete independently valid Groth16, but only one segment; failed multi-segment coverage |
| a519537b | Segment boundary / 16 | Five segments, complete Groth16, independent positive and 3 negative checks passed; 241.9996 seconds |

Fibonacci image ID:
`6f8159836d1511443408b77a590c2920fce31042249e71551bf998e7c7ea1466`;
expected journal `6d1a000000000000`. All successful independent checks reject
wrong image, altered journal and corrupted seal. SHA-256 expected journal:
`43f66f29297b60a3a6a09f54f383bf01a44d6c3baa727796983637a32fcb0583`.
The pinned recursion archive supplies lift sizes 14..24, not 13. No circuit,
key, archive or verifier substitution was made to bypass that limitation.

Smoke commands executed:

```sh
python3 scripts/macos/smoke.py --context colima-hemi-macos-cpu --repeat 2 --workload fibonacci
python3 scripts/macos/smoke.py --context colima-hemi-macos-cpu --repeat 1 --workload sha256-chain
python3 scripts/macos/smoke.py --context colima-hemi-macos-cpu --repeat 1 --workload segment-boundary --po2 14
python3 scripts/macos/smoke.py --context colima-hemi-macos-cpu --repeat 1 --workload segment-boundary --po2 18
python3 scripts/macos/smoke.py --context colima-hemi-macos-cpu --repeat 1 --workload segment-boundary --po2 16
```

## Real worker acceptance

The environment/command is reproduced in SETUP.md. Executed explicitly:
`cargo +1.93.0 test --locked -p zkminer-prover --test macos_worker -- --ignored --nocapture`.
Result: **1 passed, 0 failed, 0 ignored**, 744.21 seconds. Evidence directory
`target/macos/worker-acceptance-2`, log `target/macos/test-worker-acceptance-2.log`.
Four actual raw worker Groth16 outputs were independently verified, including
all three tamper checks each time. No mocked prover participates in this test.

Observed: forced Metal rejected; missing helper context rejected; capabilities
report canonical risc0, no GPU and two supported fixtures; protocol mismatch
rejected; real Execute returns cycles; invalid guest fails; three consecutive
Prove requests succeed; the 70-second deadline kills a request after a real
helper appears; no helper survives; the next request restarts and succeeds;
shutdown leaves no helper. One conservative memory-driven worker recycle
occurred before the third successful request. This is three consecutive
successful requests, not three proofs in a single uninterrupted worker process.
Proof times were 164.478, 159.875, 167.932 and 164.781 seconds.

The first acceptance attempt failed during startup because free-only memory
accounting ignored the filesystem cache. The corrected conservative estimate
is documented in DESIGN.md. That failure log is retained. During the passing
suite, process cleanup still used the conservative fallback when `/proc` was
absent; subsequent native proc_listpids cleanup was separately compiled and
tested with real owned processes. The passing full suite is not represented
as a run of those later process-enumeration edits.

## Focused checks and failures retained

Executed commands and latest results:

* `cargo +1.93.0 test --locked -p zkminer-prover-protocol --lib -- --test-threads=1`:
  31 passed, 0 ignored. Includes framing/roundtrips, EOF/oversize checks and
  bounded child-process execution. Linux-only ETXTBSY runtime test is compiled
  only on Linux; it is not a proof or a passed macOS test. Darwin errno mapping
  now tests 35 as EAGAIN and rejects 11 (EDEADLK) as transient.
* `cargo +1.93.0 test --locked -p zkminer-prover --lib worker::tests`:
  14 passed, 0 ignored; live descendant detection/kill, zombie/reap semantics,
  process-group ownership guards and synthetic proc regression fixtures.
* `cargo +1.93.0 test --locked -p zkminer-prover --lib memory::tests`:
  12 passed, 0 ignored; actual host observations plus admission arithmetic.
* `cargo +1.93.0 test --locked -p zkminer-prover --lib macos::tests`:
  2 passed, 0 ignored; native resource/PID identity and owned descendant cleanup.
* Acceptance guard experiments reject dev mode, Bonsai, skipped build/kernel
  settings and an upstream HEAD supplied to the local-source generator.
  See `evidence/guard-tests.json`.

Earlier focused runs failed on Linux zombie-group assumptions, Linux script
ETXTBSY behavior, reserve-specific test constants and a 150 ms new-script
execution timing assertion; poisoned test mutexes caused follow-on failures.
The timing test now invokes the installed shell directly with the same bound;
newly written script startup was the unrelated latency. Native enumeration
also exposed an exit race where BSD info disappears before a process leaves
the group; it now conservatively retains that enumerated member. All those
logs remain under `target/macos/test-*.log`; no failed proving is averaged away.

## Remaining gates at the initial CPU milestone (historical)

Metal compilation, kernel execution, CPU/Metal differential comparisons,
Metal-buffer lifetime/error tests, controlled five-run-per-mode benchmarking,
20-request extended stability, and Keccak-specific workload coverage are not
run. CPU benchmark/calibration marketplace ranking is not established. Full
CUDA/ROCm builds/runtime tests are not available on this Mac; platform guards
preserve their source paths but do not substitute for Linux CI. Contract-adapter
or deployed verifier acceptance, wallets, network jobs and transactions are
not run or authorized. The next Metal prerequisite is a compatible compiler;
the next stability prerequisite is the extended sequential suite with current
resource/lifecycle code, preserving every failure.

Final real-worker preflight check:
`cargo +1.93.0 test --locked -p zkminer-prover --test macos_worker native_worker_mode_preflight -- --ignored --nocapture`
passed (1 passed, 0 ignored; full proof test filtered out). This tests auto CPU
fallback, invalid mode and dev-mode rejection using the final process cleanup
and Darwin errno code. It is a preflight/lifecycle check, not another proof.

## Review artifacts

`evidence/validation.json` contains all seven harness attempts, four worker
proof verifications, hardware/guest provenance, helper artifact hashes and final
binary/lockfile/metadata hashes. `evidence/measurements.csv` is the timing ledger.
`evidence/hemi-engine.patch` is the separate six-file engine diff. The complete
miner diff, including new files, is saved locally as `target/macos/miner.patch`;
it is uncommitted and is not embedded recursively in the evidence bundle.
Raw receipts, seals and full logs remain under `target/macos` (about 10 GiB
including all toolchains/builds). Initial provenance remains in baseline.json.
Final binary hashes describe the final rebuild, not a claim that the earlier
full acceptance suite used later platform-test fixes. At the initial CPU milestone, source changes were still uncommitted.

## Metal continuation

CPU checkpoints and follow-up work are now committed on new local branches at
the user's request; no push. See METAL.md for the first actual GPU differential
milestone: 222 cases / 404 completed commands, retained failures, exact source/
binary binding, and a new complete CPU-only Groth16 regression proof. This does
not enable a hybrid worker or satisfy complete-proof Gate 3.


## Integrated Metal Merkle-fold milestone (2026-10-31)

The hybrid acceptance binary explicitly selects
`LocalProver::new_metal(..., 512 * 1024)` on engine
`0d5b41e8e44876c1e8b5a8a671aabc154e33106c`. It consumes Metal-produced
Poseidon2 Merkle-fold outputs in real segment proving. Witness generation,
leaf hashing, transforms, constraint evaluation, FRI arithmetic, recursion and
identity remain CPU; final Groth16 uses the same local emulated Linux/amd64
helper. At that harness milestone the worker's Metal mode was still disabled; the
native-worker continuation below supersedes that status.

The engine adds a default-preserving CPU HAL strategy, an opt-in bounded fold
bridge, explicit local prover selection and per-segment completed-work reports.
The Intel shadow verifier retains an explicit default CPU HAL type. No circuit,
constant, key, verifier parameter, proof format, pinned engine or dependency
version changed. The new hybrid lock uses only versions already in the root
lock. Upstream and the supplied Hemi checkout remain clean and unchanged.

Source-bound differential run `767200b6ed0c46058d177bee61fe6354` passed
**235 cases / 451 completed GPU commands**, including 13 bridge cases / 47
commands. New cases cover chunk boundaries/tails at 512 KiB and 4 KiB, sliced
buffers with sentinels, full-tree in-place reuse and tracked allocations returning
to baseline. Constructor budgets outside 4 KiB..16 MiB are rejected. These are
correctness checks, not performance measurements. The retained kernel source
hash remains `2fc1eb3c8a00e4fb40f5055dbaef08074e4c16cbc4e06b89de2bfe1e57d1bcd0`.

Eight acceptance-control unit tests pass, covering incomplete/mislabeled GPU
evidence, binary/source/lock/metadata changes and the exact hybrid feature chain.
Their synthetic fixtures are **not** proof-generation evidence. The source guards
also passed on actual CPU, primitive Metal, hybrid and unchanged-verifier build
metadata. CPU metadata excludes Metal; hybrid metadata requires zkvm and RV32IM
`metal-hybrid` plus ZKP `metal-runtime`.

Commands actually executed (from the miner root, with the task-local env):

```sh
sh scripts/macos/build-hybrid.sh /Users/dbur/.codex/worktrees/hemi-macos-cpu/risc0 0d5b41e8e44876c1e8b5a8a671aabc154e33106c
sh scripts/macos/build-verifier.sh
sh scripts/macos/build-metal.sh /Users/dbur/.codex/worktrees/hemi-macos-cpu/risc0 0d5b41e8e44876c1e8b5a8a671aabc154e33106c
python3 scripts/macos/test-metal.py --engine /Users/dbur/.codex/worktrees/hemi-macos-cpu/risc0 --mode all
python3 scripts/macos/test-proof-controls.py
python3 scripts/macos/smoke.py --context colima-hemi-macos-cpu --mode metal --engine /Users/dbur/.codex/worktrees/hemi-macos-cpu/risc0 --workload fibonacci --po2 18 --repeat 2
```

The independent verifier's cryptographic implementation is unchanged Git
`f8dcbdf8124a3f1528146bb01d539c55545cbb3d`, without local engine overrides or
proving features. Its reviewed standalone lock preserves external versions and
permits a fresh `--locked` build. Every proof attempt archives the exact verifier
binary/source/lock/metadata seal; hybrid attempts archive their engine/harness
seal too. The runner rejects changed artifacts and requires all three negative
checks in addition to positive final Groth16 verification.

Build/audit failures retained: an initial unfiltered offline metadata request
attempted to resolve uncached `android_system_properties`; adding the actual
macOS platform filter resolved it without downloading/updating packages. An
engine-workspace unit-test command could not resolve uncached `maybe-async` and
is not counted as passed; the isolated harnesses built and exercised the code.
Two in-progress hybrid builds compiled but were correctly refused a provenance
seal because reviewed code/HEAD changed during their build. A stable committed
rebuild was sealed before any accepted proof. One synthetic control test first
failed on macOS `/var` versus `/private/var` canonicalization, then passed after
its fixture was canonicalized. None of these attempts is treated as a proof.

Review found and fixed command-buffer lifetime accumulation, a concurrent local
request diagnostic race, Intel shadow-call type inference and fresh-verifier
lock seeding. No invalid GPU memory access or hardware fault was injected. Linux/
CUDA/Intel runtime tests are unavailable on this Mac; the Intel fix is source
reviewed, not a claim of running Intel hardware.


### Complete accepted outcomes

| Run | Mode / workload | Segments | GPU completions | Wall seconds |
|---|---|---:|---:|---:|
| `d4e86941bd7b464f9954aa24ea1b2375` | metal / fibonacci | 1 | 194 | 168.439 |
| `1ad9ae716a73463584b840fcf268bac4` | metal / fibonacci | 1 | 194 | 166.856 |
| `0551842728b9449ab3d85de41a3668f8` | metal / segment-boundary | 5 | 1269 | 237.822 |
| `08b5cca54b024b9ca9d3400f41b23b1b` | cpu / fibonacci | 1 | 0 | 165.581 |

All four runs produced real final Groth16 receipts with 256-byte raw seals and
passed the unchanged pinned verifier plus wrong-image, modified-journal and
corrupted-seal rejection. Both hybrid Fibonacci runs exactly matched the CPU
regression's program/input hashes, image, journal, po2 and cycle/segment stats;
randomized receipt bytes were not compared. Every one of the five boundary
segments recorded positive Metal work, totaling 1,269 completed commands.

The final hybrid manifest whitespace cleanup rebuilt an executable identical
to all three accepted hybrid runs. The final unchanged verifier also rechecked
all three receipts after its manifest cleanup. Historical per-attempt build
seals remain intact. The CPU all-features build exposes only `prove`, and its
actual metadata excludes Metal. Fresh temporary verifier metadata resolves
with `--locked --offline`, preserving the unchanged Git engine.

Additional executed acceptance commands:

```sh
python3 scripts/macos/smoke.py --context colima-hemi-macos-cpu --mode metal --engine /Users/dbur/.codex/worktrees/hemi-macos-cpu/risc0 --workload segment-boundary --po2 16 --repeat 1
python3 scripts/macos/smoke.py --context colima-hemi-macos-cpu --mode cpu --workload fibonacci --po2 18 --repeat 1
cargo +1.93.0 build --locked --release --manifest-path tools/macos-proof/Cargo.toml --all-features --config target/macos/local-engine.toml --target-dir target/macos/cpu
```

`evidence/hybrid-validation.json` binds exact commands, source/build manifests,
receipt/seal/journal hashes and verifier evidence. `hybrid-measurements.csv`
contains these smoke timings; `hybrid-bridge-cases.json` records bridge equality
cases; `hemi-hybrid.patch` is the separately recorded engine diff since the
primitive checkpoint. Raw attempts remain under `target/macos/runs`. No failed
proof attempt occurred in this milestone; all earlier failures are retained.

That milestone's next step was native-worker integration, now recorded below.
Full Gate 3 stability/performance and network acceptance remain open.


## Native hybrid worker milestone (2026-10-31)

The native worker now selects the validated segment Merkle-fold stage through
its existing WorkerPool/generic slot. CPU and Metal builds are separate; one
implementation handles `cpu|metal|auto`. A bounded real GPU differential probe
precedes Metal capability reporting. Forced Metal cannot fall back; auto records
a startup fallback reason. Explicit CPU avoids both the probe and GPU proving.
Per-request evidence records actual GPU completions before recursion/wrapping
and binds final image, journal and seal. No protocol fields changed.

Miner changes start at `3b2720110c1721a53d19c09a6ff2a16235aeb9be`; reviewed
uncommitted source hashes are bound in each worker/test build seal. Engine HEAD
is unchanged `0d5b41e8e44876c1e8b5a8a671aabc154e33106c`. The original Git pin
and independent verifier remain `f8dcbdf8124a3f1528146bb01d539c55545cbb3d`.
Cargo.lock adds only four existing dependency edges to the worker, with no
version/source-pin updates. The root manifest deliberately does not request a
feature absent from the original pin; the local build explicitly enables the
reviewed SDK feature using exact local overrides.

Executed builds and focused checks, with `scripts/macos/env.sh` sourced:

```sh
python3 scripts/macos/build-worker.py --mode metal --engine /Users/dbur/.codex/worktrees/hemi-macos-cpu/risc0 --config target/macos/local-engine.toml --revision 0d5b41e8e44876c1e8b5a8a671aabc154e33106c
python3 scripts/macos/build-worker.py --mode cpu --engine /Users/dbur/.codex/worktrees/hemi-macos-cpu/risc0 --config target/macos/local-engine.toml --revision 0d5b41e8e44876c1e8b5a8a671aabc154e33106c
cargo +1.93.0 test -p zkminer-prove-risc0 --bin zkminer-prove-risc0 --features macos-metal,risc0-zkvm/metal-hybrid --release --config target/macos/local-engine.toml --target-dir target/macos/worker-metal macos::tests -- --nocapture
python3 scripts/macos/test-worker.py --engine /Users/dbur/.codex/worktrees/hemi-macos-cpu/risc0 --worker-kind metal --mode metal --context colima-hemi-macos-cpu --repeat 3
```

Both final worker builds passed actual source checks and were sealed. The two
mode/deadline unit tests passed; the temporary local-source lock was audited
and the original Git root lock restored. Runtime probe equality passed at
4096, 4097, 524288, 16777216-byte budgets (129, 129, 2, 1 completed GPU commands);
4095 and 16777217 reject. Probe evidence is `/private/tmp/hemi-native-metal-probe.json`.
A changed temporary worker binary and wrong upstream checkout were rejected by
provenance guards. These controls are not proof-generation evidence.

Native Metal run `f8ff5abb2cef4a19bb02e24fbcb318d0` passed **2 tests, 0 failed,
0 ignored**, 777.73 seconds. Four real complete Groth16 outputs and three
negative checks per output passed the unchanged verifier. The first three
requests stayed in PID 8653; each recorded 194 completed GPU dispatches. The
production supervisor cancelled PID 8653 during a running owned helper; a
separate 70-second watchdog killed PID 12543 (observed elapsed 71.723s). Both
interrupted requests had 194 completed Metal dispatches and verified succinct
receipts before wrapping. They count as expected failures, never proof successes.
After owned helpers were removed, PID 13430 produced another verified proof and
shutdown left no worker/helper. Proof seconds: 163.997,159.590,159.140,164.465.

The suite also executes real mode selection/capability and warmup checks,
invalid mode/dev/skip-verification/budget startup rejection, protocol mismatch,
missing-helper rejection, real execution and invalid-guest failure. The runner
requires exact watchdog/cancellation logs for the observed worker PIDs; a generic
error or early crash cannot satisfy those cases. It binds acceptance source and
executable before and after the run, requires saved verified proof artifacts,
and cannot count an ignored or empty test run as successful proving.

Optional non-Mac check actually attempted:

```sh
cargo +1.93.0 metadata --locked --offline --manifest-path crates/zkminer-prove-risc0/Cargo.toml --features cuda --filter-platform x86_64-unknown-linux-gnu --format-version 1
```

It exited 101 because `approx v0.5.1` was not cached. No packages were updated or
downloaded to bypass this; log `target/macos/native-worker-linux-cuda-metadata.log`.
Non-Mac guards were reviewed, but Linux/CUDA/ROCm build/runtime validation is not
claimed. The first Metal build was rebuilt after separating the parent-death
cleanup deadline from shorter startup probes; only the final seal is used for
accepted native proofs. No failed proof attempt is concealed by this rebuild.

### Completed mode matrix and evidence

The following additional commands were actually executed sequentially:

```sh
python3 scripts/macos/test-worker.py --engine /Users/dbur/.codex/worktrees/hemi-macos-cpu/risc0 --worker-kind cpu --mode auto --context colima-hemi-macos-cpu --proof-only --repeat 1
python3 scripts/macos/test-worker.py --engine /Users/dbur/.codex/worktrees/hemi-macos-cpu/risc0 --worker-kind metal --mode cpu --context colima-hemi-macos-cpu --proof-only --repeat 1
python3 scripts/macos/test-worker.py --engine /Users/dbur/.codex/worktrees/hemi-macos-cpu/risc0 --worker-kind metal --mode auto --context colima-hemi-macos-cpu --proof-only --repeat 1
```

| Run | Build / requested → observed | Verified proofs | Proof seconds | GPU commands per proof |
|---|---|---:|---|---:|
| `f8ff5abb2cef4a19bb02e24fbcb318d0` | metal / metal → metal |4|163.997,159.590,159.140,164.465|194|
| `2b17330c44b84da099de8089a72032aa` | cpu / auto → cpu |1|164.497|0|
| `0a20964eec5f4643b0805f52e49a4d44` | metal / cpu → cpu |1|164.718|0|
| `ac9cf5773bf34427925ab5f29ce18ac5` | metal / auto → metal |1|164.798|194|

All four source-bound attempts passed, with two actual tests and zero ignored
per run. Seven complete real Groth16 outputs passed independent verification
and 21 total tamper rejections. The CPU-only auto run records the explicit
reason `worker was compiled without the macos-metal feature`; the Metal build's
explicit CPU mode produces no GPU proving work, and auto selects validated
Metal. Expected public outputs, program/input hashes, image and cycle/segment
stats agree across modes; proof bytes are not required to match.

`evidence/native-worker-validation.json` preserves all four run reports, exact
commands/build seals, independent verification, artifact hashes, expected-failure
ledger and optional Linux metadata failure. `native-worker-measurements.csv`
retains every successful and deliberately interrupted request with timing/memory
limits. Raw artifacts remain in `target/macos/worker-runs/<id>`. The complete
miner diff is saved as `target/macos/native-worker-metal.patch`; engine diff for
this continuation is empty. Separate prior engine diffs remain committed.

The dedicated VM was stopped after `docker --context colima-hemi-macos-cpu ps -a`
showed no remaining containers. No privileged installation or global toolchain
change was needed. No push or network mining was performed.

This is bounded native hybrid correctness/lifecycle acceptance. Extended
20-request stability, native-worker hash/multi-segment/memory-pressure coverage,
GPU hardware-fault recovery, driver allocation/growth measurements, benchmark/
calibration IPC execution and controlled five-measured-runs-per-mode performance
remain unrun. Prior harness hash/multi-segment coverage is retained separately.
Exact contract-adapter and deployed/network verification remain unrun. None of
these limits is bypassed by a build, mocked test or skipped test.


## Completed workload and stability milestone

This continuation starts from miner `b871d7ed0f0de83d99cc3e5674bfba95c3f04d7f`
and preserves both sealed worker binaries and engine
`0d5b41e8e44876c1e8b5a8a671aabc154e33106c`. Production worker, protocol, engine,
root manifest and dependency lock are unchanged. The changes are acceptance
code, evidence collection and documentation. The new Rust test compiled; actual
proving results below remain distinct from compilation and code review.

`test-worker.py` now accepts `--workload`, optional `--po2`, and optional
`--admission-pressure`. Inputs and journals are computed independently for
Fibonacci(20), SHA-256-chain(10), and boundary input(1,8); the boundary defaults
to po2 16 and requires at least five proved segments. Selected packed guest,
user ELF, source/build provenance and input are checked before/after the run.
Imported validation modules are included in the test source seal. Every
successful record must match the actual requested staging budget.

Twenty-request acceptance means twenty ordered independently verified requests
in one WorkerPool, with no hidden failure or retry. Unique worker/request pairs,
consistent deterministic cycle/segment stats and all negative verifier checks
are mandatory. PID changes and longest same-process streak are reported
separately; production memory guards and worker recycling remain enabled.

Each successful request records RSS before/during proving and after independent
verification plus a one-second settling interval. Process start identity and
parent/process-group ownership are checked before and after each observation.
Unavailable/recycled identities are explicit, never assigned zero memory.
Host available/total memory uses the existing production observation functions.
These samples exclude the helper VM from worker RSS and do not measure Metal
driver allocation peaks; global available memory already reflects VM effects.

The pressure case uses actual production reservation guards in bounded 1 GiB
accounting increments. It does not allocate the corresponding pages. A typed
HostMemoryShortage with attempted=false, unchanged sidecar count, no helper,
and zero reservations after release are required. A real full proof after
release is mandatory. Physical host-memory exhaustion and the 32 GiB RSS-kill
branch are not induced by this test.

First new result: SHA run `71387ac25ac74d4395278a3459680152` passed two actual
tests, zero ignored, in 192.21s. It refused dispatch with 107 GiB logically held,
then released all reservations and produced a genuine SHA-256 Groth16 proof
in 171.639s with 593 completed Metal commands. All three unchanged-verifier
negative checks passed. Peak sampled request RSS was 2,449,637,376 bytes;
post-verification idle RSS was 929,841,152 bytes. This is one sample, not a
performance comparison or proof of allocation stability.

Collector validation retained one tooling failure: the initial summary refused
two zero outer RSS samples from this successful run as invalid. The collector
now preserves them as unavailable_nonpositive_rss with phase/time and unknown
cause; they are excluded from positive sample counts and memory metrics. The
identity-checked Rust resource record and positive samples remain independently
validated. Recollection passed with 1 complete proof, 3 negative rejections and
1 expected admission refusal; no proof result was changed or regenerated.

Five-segment run `3c0b5d8179934bafb482174615a05d22` passed a complete proof
in 237.596s with 1,269 GPU completions across all five segments; all negative
checks passed. Sampled request peak was 2,756,018,176 bytes; settled idle was
1,551,286,272 bytes. Fibonacci run `d93743621b584487accb84c7df1833c6` passed
at the exact minimum 4,096-byte staging budget in 168.982s, recording 16,680
completed GPU commands and positive/negative unchanged-verifier acceptance.
Its sampled peak and idle were 1,975,173,120 bytes. Each run executed two tests
with zero ignored; these are full proofs, not only kernel comparisons.

Twenty consecutive independently verified requests passed in 3341.356s (55.69 minutes),
with zero failed requests. Normal memory-driven recycling used 16 proving processes; the
longest same-PID streak was 2. Proof seconds ranged 157.222–166.442, median 164.845.
Sampled request peaks ranged 1,970,487,296–1,996,292,096 bytes. All twenty outputs
passed 60 tamper rejections and recorded 3,880 completed GPU commands.

Run `28bdd9ca009a4f6eacda4e11df402aed` executed two actual tests, zero ignored,
in 3340.69s. All four runs together produced 23 independently accepted complete
Groth16 outputs and 69 tamper rejections, with 8 tests passed and zero ignored.
No unexpected proof failure was averaged away. Four process-identity groups
contain two successful requests; the others contain one. This establishes
consecutive WorkerPool request acceptance with normal recycling, not twenty
proofs in one uninterrupted process or leak-free long-lived operation.

Commands actually executed, after sourcing the task-local environment:

```sh
python3 scripts/macos/test-worker.py --engine /Users/dbur/.codex/worktrees/hemi-macos-cpu/risc0 --worker-kind metal --mode metal --context colima-hemi-macos-cpu --proof-only --repeat 1 --workload sha256-chain --admission-pressure
python3 scripts/macos/test-worker.py --engine /Users/dbur/.codex/worktrees/hemi-macos-cpu/risc0 --worker-kind metal --mode metal --context colima-hemi-macos-cpu --proof-only --repeat 1 --workload segment-boundary --po2 16
python3 scripts/macos/test-worker.py --engine /Users/dbur/.codex/worktrees/hemi-macos-cpu/risc0 --worker-kind metal --mode metal --context colima-hemi-macos-cpu --proof-only --repeat 1 --workload fibonacci --staging-bytes 4096
python3 scripts/macos/test-worker.py --engine /Users/dbur/.codex/worktrees/hemi-macos-cpu/risc0 --worker-kind metal --mode metal --context colima-hemi-macos-cpu --proof-only --repeat 20 --workload fibonacci --timeout 7200
python3 scripts/macos/summarize-worker.py --runs 71387ac25ac74d4395278a3459680152 3c0b5d8179934bafb482174615a05d22 d93743621b584487accb84c7df1833c6 28bdd9ca009a4f6eacda4e11df402aed --output docs/macos/evidence/worker-stability-validation.json --csv docs/macos/evidence/worker-stability-measurements.csv
python3 scripts/macos/test-worker-summary-controls.py --output docs/macos/evidence/worker-stability-controls.json
```

The final collector additionally exposed one-ULP timing differences introduced
by JSON number round-tripping through Rust. It now allows only finite,
nonnegative, at-most-one-ULP differences in `total_ms` and `stage_ms` values,
records each difference and retains both raw hashes. All proof hashes, public
identities, stage counters and other fields remain exact. Larger timing changes
and changed proof identities are rejected by dedicated collector controls;
those controls are not additional proof-generation successes. The runnable
`test-worker-summary-controls.py` passed all 12 guards with zero proofs generated
or verified; its exact command and outcomes are in
`evidence/worker-stability-controls.json`. Both collector
refusals are retained in this record; no raw accepted artifact was edited.

`evidence/worker-stability-validation.json` binds the four finalized reports,
source/build seals, every ledger status, raw proof/resource artifact hashes,
per-identity memory summaries and collector limitations.
`worker-stability-measurements.csv` retains chronological requests/refusal events
using LF endings. Raw logs, receipts and observations remain under the four
`target/macos/worker-runs/<id>` directories. The separate miner diff is
`target/macos/worker-stability-miner.patch`; this continuation's engine diff is
empty. CPU/Metal worker and unchanged-verifier seals are rechecked before commit.

The dedicated helper VM was stopped after confirming no containers remained.
Production worker/engine/CPU source and root dependency lock did not change.
Non-Mac runtime coverage is not claimed. Controlled benchmarks, benchmark IPC,
physical memory-pressure/RSS-kill recovery, longer same-process allocation
stability, GPU faults, exact contract-adapter and network acceptance remain open.
No wallet, marketplace, privileged installation or push was used.


## Controlled CPU/Metal benchmark attempt (2026-10-31 local)

Local instrumentation commit `461965e` adds only acceptance timing, an
orchestrator and a small read-only Foundation telemetry helper. Production
worker/protocol/engine code, pinned graph, CPU binary and verifier are unchanged.
The collector and evidence commit follows separately; no push or installation.

Commands actually executed from the miner checkout (task-local env sourced):

```sh
colima start hemi-macos-cpu --cpu 6 --memory 32 --disk 80 --activate=false --ssh-config=false --template=false --mount /Users/dbur/dev/zk-miner/target/macos:w --vz-rosetta
xcrun clang -O2 -Wall -Wextra -Werror -fobjc-arc -mmacosx-version-min=12.0 -framework Foundation scripts/macos/benchmark-thermal.m -o target/macos/benchmark-tools/thermal
cargo +1.93.0 test --locked -p zkminer-prover --test macos_worker --no-run --message-format=json --target-dir target/macos/worker-acceptance-build > target/macos/worker-timing-compile.jsonl 2> target/macos/worker-timing-compile.stderr
python3 -B scripts/macos/benchmark-worker.py --engine /Users/dbur/.codex/worktrees/hemi-macos-cpu/risc0 --context colima-hemi-macos-cpu --samples 5
python3 scripts/macos/test-benchmark-summary-controls.py --benchmark target/macos/benchmarks/f8b460c76d594ae88e6430ab29e1aa27 --output docs/macos/evidence/benchmark-summary-controls.json
python3 scripts/macos/summarize-benchmark.py --benchmark target/macos/benchmarks/f8b460c76d594ae88e6430ab29e1aa27 --output docs/macos/evidence/benchmark-attempt-1.json --csv docs/macos/evidence/benchmark-attempt-1.csv
```

The runner actually launched these two commands, each through the real
WorkerPool acceptance binary with `--ignored --nocapture --test-threads=1`:

```sh
python3 scripts/macos/test-worker.py --engine /Users/dbur/.codex/worktrees/hemi-macos-cpu/risc0 --worker-kind metal --mode cpu --context colima-hemi-macos-cpu --proof-only --repeat 1 --workload fibonacci --po2 18 --staging-bytes 524288 --timeout 900
python3 scripts/macos/test-worker.py --engine /Users/dbur/.codex/worktrees/hemi-macos-cpu/risc0 --worker-kind metal --mode metal --context colima-hemi-macos-cpu --proof-only --repeat 1 --workload fibonacci --po2 18 --staging-bytes 524288 --timeout 900
```

Campaign `f8b460c76d594ae88e6430ab29e1aa27` stopped after CPU warmup success and
Metal warmup refusal. CPU run `257de3edef294d10b2f03edda0048d95`: 2 actual tests
passed, 0 failed/ignored; one complete Groth16 proof accepted by the unchanged
verifier, all three tamper cases rejected, zero proving GPU commands. Worker
164.432s, exact supervisor prove call 164.731s, external positive+negative
verification 39.937ms. Full trial 185.088s includes preflight/build/measurement.

Metal run `dc005b12db1d44a5a98dad07ecb7ed01`: 1 actual preflight test passed,
1 proof test failed, 0 ignored. The real admission guard rejected a proof before
execution because available memory was below 22 GiB; the pre-call observation
was 23,597,678,592 bytes. The request ledger retains the typed refusal message,
resource observations and recycled preflight PID. No Metal proof or helper was
started. This is an unexpected campaign failure, not an expected negative test
or a completed proof. All ten measured trials are explicitly unattempted.
No comparative statistics, automatic retries or discarded failed measurements.

The new collector guards passed 13/13, zero proofs generated or verified. They
exercise schedule/order, duplicates, stopped campaigns, known statistics with
warmup exclusion, invalid timings, real timing/PID binding and ambiguous wrapping
logs. They do not stand in for genuine proving. Archived JSON/CSV retain the
failure, raw telemetry and source/binary/artifact hashes. Runtime Metal warmup
preflight passed, but no complete Metal proof was generated in this attempt.

All timing boundaries and thermal/background limitations are in BENCHMARKS.md.
The owner was asked to free roughly 4–8 GiB from unused applications. The native
16 GiB reserve, six-GiB proof estimate, 32 GiB worker watchdog and helper limits
remain unchanged; no unrelated process was terminated. The next step is a new
full campaign when host headroom permits. No non-Mac runtime, benchmark IPC,
contract adapter or network acceptance test was added or claimed.

Final checks: CPU/Metal/verifier build seals still match their prior values;
44 raw acceptance artifact hashes and nine benchmark artifact hashes rechecked.
Cargo.toml/Cargo.lock and both Hemi engine checkouts/upstream remain unchanged.
After `docker --context colima-hemi-macos-cpu ps -a --format '{{.Names}}'` and
owned PID checks showed no leftovers, `colima stop hemi-macos-cpu` completed.
`colima list --json` confirmed dedicated Stopped, original default Running.
Separate diffs: `target/macos/benchmark-miner.patch` from `244a3a1` and empty
`target/macos/benchmark-engine.patch`. `git diff --check` passed.


## Completed controlled comparison (2026-11-01)

Host headroom recovered, and the full frozen campaign was rerun from miner
`a3342fb80ec2fcfba909f921e381c6636fefb731`, with unchanged engine `0d5b41e8…`,
CPU/Metal/verifier binaries and dependency pins. No production code changes.
Campaign `f57fcc0ff71d4d6391605cb761c0a1a6` completed 12/12 genuine Groth16 proofs
(two warmups plus five alternating measured pairs), 36 unchanged-verifier tamper
rejections, and 24 native tests passed / 0 failed / 0 ignored. No timeout, retry,
admission failure or unattempted slot occurred. The previous failed campaign
remains in `benchmark-attempt-1*` and is not pooled into these statistics.

Commands actually executed after sourcing `scripts/macos/env.sh`:

```sh
colima start hemi-macos-cpu --cpu 6 --memory 32 --disk 80 --activate=false --ssh-config=false --template=false --mount /Users/dbur/dev/zk-miner/target/macos:w --vz-rosetta
python3 -B scripts/macos/benchmark-worker.py --engine /Users/dbur/.codex/worktrees/hemi-macos-cpu/risc0 --context colima-hemi-macos-cpu --samples 5
python3 -B scripts/macos/summarize-benchmark.py --benchmark target/macos/benchmarks/f57fcc0ff71d4d6391605cb761c0a1a6 --output docs/macos/evidence/benchmark-comparison.json --csv docs/macos/evidence/benchmark-comparison.csv
python3 -B scripts/macos/test-benchmark-summary-controls.py --benchmark target/macos/benchmarks/f57fcc0ff71d4d6391605cb761c0a1a6 --output docs/macos/evidence/benchmark-comparison-controls.json
docker --context colima-hemi-macos-cpu ps -a --format '{{.Names}}'
colima stop hemi-macos-cpu
```

The exact twelve child commands, build commands, immutable settings, source hashes
and full runner logs are recorded in the campaign plan/trial ledger and aggregate.
Each child explicitly ran the real ignored prerequisite tests via `--ignored
--nocapture --test-threads=1`; zero tests were skipped in their results. The 13
reporting guards passed against this new campaign and count as zero proof tests.
Every successful proof has the expected image, input, journal, segment/cycle stats,
256-byte Groth16 seal, independent verification and all three tamper rejections.
Metal executed 194 declared GPU commands per proof (970 measured / 1,164 total);
CPU proofs report no Metal stage. No CPU fallback was substituted for Metal.

| Phase | Mode | Sample | Run |
|---|---|---:|---|
| warmup | cpu | 0 | `b6c24a414d924cf08a7849c104fcf796` |
| warmup | metal | 0 | `f4bdaa744bf743aa9baca3eae782a20f` |
| measured | cpu | 1 | `a453c5b947b44ba6bd81c37d43e146b1` |
| measured | metal | 1 | `0a5153d093d644ad924af2039de61679` |
| measured | cpu | 2 | `cc2c45ce278745d9bcb12a565d1cbdd6` |
| measured | metal | 2 | `6211939bd55245639a5b63c5581de90a` |
| measured | cpu | 3 | `b42f75b123bd436e9fc817ee1ce92152` |
| measured | metal | 3 | `6ce67a6b36c645aaaf3d089e691a005f` |
| measured | cpu | 4 | `66298ac457ab481a86b2dd2ed650d828` |
| measured | metal | 4 | `4d66e70064e249b4b9d72cf934406f44` |
| measured | cpu | 5 | `69d0a38fed684292a6d0eacf5bfa6b91` |
| measured | metal | 5 | `6d56d3f4a4034d03b88abc0d4977e041` |

BENCHMARKS.md gives the timing table and interpretation: no observed speedup on
this small fixture; worker medians CPU165.582s / Metal165.823s. Controlled settings
and complete proofs do not remove background-load or small-sample uncertainty.
The external evidence audit rechecked 336 acceptance files plus 29 benchmark
archive files, the planned source inputs, binary/metadata/lock seals, all timings
and counts. Six one-ULP diagnostic timing serialization differences remain
explicitly recorded under the existing rule; no raw evidence was rewritten.

A post-run SDK counter check (`xcrun clang -Wall -Wextra -Werror
/private/tmp/hemi-memory-check.c -o /private/tmp/hemi-memory-check`, then native
counters / `vm_stat` / native counters) explained lower ad hoc memory readings:
Mach free_count includes speculative pages, while the quick vm_stat formula
omitted the separately printed speculative count. The exact check source,
compile argv and observations are in `benchmark-memory-counter-check.json`.
This corrects reporting only; production admission, resource observations and
worker binaries were not changed. The authoritative campaign minimum available
memory was 25.122 GiB; the quick conversational values were conservative proxies.

No leftover helper containers or proving workers were observed. Dedicated VM
stopped; default VM remained running. Separate continuation diffs are
`target/macos/benchmark-comparison-miner.patch` from `a3342fb` and empty
`target/macos/benchmark-comparison-engine.patch`. Larger-workload performance,
physical-memory/RSS-kill/GPU fault recovery, benchmark/calibration IPC, non-Mac
runtime, exact contract adapter and network acceptance remain unrun here.
No installation, wallet/network job, transaction or push occurred.
