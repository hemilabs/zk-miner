# W12-REBASE: the macOS beta, the ON37 integration and the macOS network guard on current main

The owner asked for all work in both repositories to be rebased onto the current default branches:
hemilabs/zk-miner `main` @ `6dbf4c5` (#37 merged exactly at `7b021f6`, then #39, #40, #43) and
hemilabs/risc0 `release-3.1` @ `eb847a1af` (the old base `5beab26b5` plus #42). Everything below is on
**new local branches**. No existing branch was moved and nothing was pushed. Logs, scripts and SHA
maps are in `/Users/user/zkminer/scratch/w12/REBASE/`.

| repo | new branch | base | old tip | new tip |
|---|---|---|---|---|
| risc0 | `rebase/metal-3.1` (worktree `deps/risc0-3.1-rebased`) | `release-3.1` `eb847a1af` | `zkminer/metal-3.1` `37b434755` | `81ee699e3` |
| zk-miner | `rebase/metal-3.1` (this branch; worktree `zk-miner-wt-rebase-metal`) | `main` `6dbf4c5` | `item/W11-ON37` `2e584ca` | the pin commit after this note |
| zk-miner | `rebase/netguard-mac` (worktree `zk-miner-wt-rebase-netguard`) | `main` `6dbf4c5` | `item/W11-NETGUARD-MAC` `1d49b92` | `a4869c9` |
| zk-miner | `rebase/metal-3.1-full` (worktree `zk-miner-wt-rebase-full`) | this branch | (2) + (3) | see the scratch summary |

## Why history-preserving, not linear

Neither Metal line is a simple stack of commits on its base. The risc0 branch has 461 non-merge commits
and 125 merges since `5beab26b5`. Most of them are the 3.0-era Metal port on a 3.0.4 base, which came into 3.1
through one synthetic merge (17 conflicts with a hand-picked merge base, about 158 without). The
zk-miner branch has 62 non-merge commits and 23 merges, written against older mains and integrated
by merges (W10-INT: 15 conflicts). Applied one at a time onto `6dbf4c5`, 52 of those 62 commits
conflict. So linearising would redo those integrations commit by commit, and the intermediate
states could not be tested.

Both repositories were therefore rebased with `--rebase-merges` semantics in the default
`no-rebase-cousins` mode. A commit that does not descend from the old base keeps its parent and its
SHA. Only the commits on the ancestry path from the old base are re-created. Each re-created merge
gets the original merge's tree plus the upstream delta, not a fresh re-resolution. A plain
`git rebase --rebase-merges` of the risc0 branch (862 todo steps, almost all fast-forwards) stopped in
a git-lfs checkout of the 3.0.4 tree. So the five risc0 commits were replayed with the same
semantics by `scratch/w12/REBASE/risc0-replay.sh`. A side effect is that both zk-miner Metal
branches still contain the pushed `metal-3.1` `6ca46df` as an ancestor.

## risc0: `rebase/metal-3.1` @ `81ee699e3`

| old | new | commit |
|---|---|---|
| `520dbaf97` | `eb52b365f` | Merge upstream release-3.1 (W10-R0): second parent `5beab26b5` -> `eb847a1af`; clean (auto-merged `recursion-sys/build.rs`) |
| `f720616c0` | `fd4fa2425` | docs: W10-R0 note |
| `28b4bef33` | `5739724db` | Merge metal/W10-R0 |
| `404ae8dcf` | `35d0efc05` | W10-GATE |
| `37b434755` | `81ee699e3` | Merge metal/W10-GATE (tip) |

The other 581 commits are unchanged. Acceptance:
- The tip tree `66f7770fa` is byte-identical to the tree of `git merge-tree eb847a1af 37b434755`. That
  merge is clean.
- Each re-created commit differs from its original only in `risc0/circuit/recursion-sys/build.rs`.
  `git diff 37b434755 81ee699e3` is #42's change exactly, at an offset of 12 lines.
- `git range-diff 5beab26b5..37b434755 eb847a1af..81ee699e3` shows 461 of 461 commits `=`.
  `git cherry` reports none missing.
- Authors and dates are kept. The committer is Max Sanchez.

## zk-miner `rebase/metal-3.1` (this branch)

| old | new | commit |
|---|---|---|
| `6ca46df` and all its ancestors | unchanged | `metal-3.1` as pushed, including the TEMPORARY CI skip `86f48b0`, untouched |
| `3b68fcc` (Merge PR #37 into the beta) | `0560612` | Merge main `6dbf4c5` into the beta: parents `6ca46df`, `6dbf4c5` |
| `09ad96f` | `7bc44f9` | risc0 segments: on macOS, remove a gone worker's segment directory |
| `2e584ca` | `bb85838` | docs: W11-ON37 note |
| — | this note, then the pin commit | |

`0560612`'s tree is `3b68fcc`'s tree plus main's delta `7b021f6..6dbf4c5` (#39, #40, #43). This keeps
every ON37 resolution and every ON37 semantic fix, including the protocol renumbering. #37 keeps 14-16
and the beta's additions are protocol **17**; #39/#40/#43 do not touch the protocol crate. It also keeps
`libc` for macOS in zkminer-cli, the simulate.rs fix and the codec, metal_worker, witness, sp1 and
benchmark edits. As a cross-check, `git merge 6dbf4c5` from `6ca46df` replayed 8 of ON37's 9
resolutions from rerere identically. Outside the three files below, the only differences were
exactly the six files where `3b68fcc` carried semantic edits beyond its conflict hunks. That is why the
replay takes `3b68fcc`'s tree rather than a fresh merge.

### Conflicts of #39/#40/#43 with the beta (3 files, 7 hunks)

| file | hunk | resolution |
|---|---|---|
| `zkminer-prover/src/dispatcher.rs` | top-level functions: the Metal recycle, respawn and growth-net functions (M9/W7-M10) vs #39's `first_slot_that_succeeds` | both, Metal's first |
| | `benchmark` and `benchmark_streaming` watchdogs (2 hunks): Metal's per-slot deadline `self.benchmark_timeout_for(key)` (M6, scaled for Apple GPU cores and po2) vs #43's per-step `WatchdogClock` + `ProvingWatchdog::with_clock` on `self.benchmark_timeout` | `let clock = WatchdogClock::new(); self.benchmark_timeout_for(key).map(\|t\| ProvingWatchdog::with_clock(..., clock.clone()))`: both |
| | `run_benchmark_requests` calls (2 hunks): the beta's following `slot.note_used(UseKind::Other)` vs #43's new `&\|\| clock.touch()` argument | #43's call, then `slot.note_used(UseKind::Other)` |
| `zkminer-cli/src/commands/run.rs` | tests: P31-19/B9-ZK selector tests vs #43's `job_card_order` / `card_finishes_in_time` tests | both |
| `zkminer-prover/src/bin/mock_worker.rs` | Benchmark reply: W10-BENCH's `MOCK_FAIL_ON` / `MOCK_BENCH_ROWS` answer vs #43's `MOCK_BENCHMARK_SECS` sleep | the sleep, then W10-BENCH's answer |

Semantic effects:
- **The benchmark deadline is now per step on Macs too.** #43 made `benchmark_timeout` bound each step
  of a benchmark (warm-up, each program, each scoring proof) rather than the whole suite.
  `metal_benchmark_timeout` was sized for the whole suite: 109,200 GPU-core-seconds / cores, at least
  the configured 1800 s. As a per-step bound it is therefore more generous than before. That is safe,
  because the deadline only stops a hung worker, but a hung step on a small Mac is now caught later.
  Re-tune it after the beta if wanted.
- **#43's per-card job admission** keys on benchmark device ids (`WorkerPool::benchmark_device_id`). A
  Metal slot `risc0:metal:0` maps through the generic `gpu_device_id("metal", "0")`, so a Mac's single
  GPU is just one eligible card. No Metal-specific change is needed.
- #43's witness binaries in the release (`build-docker.yml` `dist-witness`, `assemble-release.sh`,
  `unpack-provers.sh`) are Linux-only. The macOS kit (`assemble-macos.sh`) is unchanged, because a Mac
  miner serves no witness jobs (W11-ON37). The new `dist-witness` matrix row sits under the TEMPORARY
  `metal-3.1` skip of `build-docker.yml`'s job, like every other row.
- On macOS, #43 adds 6 dead-code warnings: `witness/policy.rs` card planning and
  `discovery::parse_i915_mem_regions`, both of which only Linux uses. These are not errors, and not
  from this merge.

Acceptance: `git merge-tree origin/main item/W11-ON37` conflicts in the same three files with the
same hunk counts (1, 1, 5). Outside those conflict regions, its tree is byte-identical to `bb85838`'s
tree. `tools/check_conflict_only.py` checked this file by file (`zk-d2-tree-compare.log`). The tip
differs from `bb85838` only by this note and the pin commit. `git range-diff
origin/main..item/W11-ON37 origin/main..bb85838` shows 62 of 62 non-merge commits `=`.

### The risc0 pin (final commit)

`Cargo.toml` (17 `[patch.crates-io]` revs and the pin comments), `Cargo.lock` (18 `source` lines) and
`RELEASE-DEPS.md` move from `37b434755` to `81ee699e3df4a08e9950f3374571ddeb250e6009`. The two zkrs
tarballs (LFS) are unchanged. **The rev does not resolve until `81ee699e3` is on hemilabs/risc0.**
`docs/release/BETA_RC.md` still records the RC3 kit on `37b434755` (historical) and is not edited.

Local builds: Makefile.mac's default `RISC0_DIR` is `deps/risc0-3.1`, and `RISC0_SRC=auto` uses it.
That checkout is on the OLD branch (`37b434755`). Pass
`RISC0_DIR=/Users/user/zkminer/deps/risc0-3.1-rebased` (or `RISC0_SRC=git` after the push) to build
the pinned tree.

## zk-miner `rebase/netguard-mac` @ `a4869c9`

`git rebase --onto origin/main 7b021f6 item/W11-NETGUARD-MAC` (a new branch, linear, 113 commits).
There were no conflicts. The tip tree `371046e2f` is byte-identical to the clean `git merge-tree
origin/main item/W11-NETGUARD-MAC`. `range-diff` shows 113 of 113 `=`. The SHA map is
`scratch/w12/REBASE/zk-d3-sha-map.txt`.

## zk-miner `rebase/metal-3.1-full`

This is the 113 netguard commits rebased linearly on top of this branch. A macOS beta needs them,
because ON37 alone refuses every public connection on macOS. There were no conflicts. `2056902`
("zkminer-cli: libc on every Unix, so the miner builds on macOS") becomes empty and is dropped: it is
the same `libc` change ON37's merge already made in `crates/zkminer-cli/Cargo.toml`. That leaves 112
commits. The tip tree equals the clean `git merge-tree` of this branch and `rebase/netguard-mac`.

## Push order (owner; nothing here pushes)

1. **risc0 first**: `81ee699e3` to hemilabs/risc0. As `zkminer/metal-3.1` this is a force-push over
   `37b434755`; a new branch name avoids that. The old SHA stays reachable from the pushed zk-miner
   `metal-3.1` pin until that moves.
2. zk-miner `rebase/metal-3.1` (or `rebase/metal-3.1-full` for the beta with the macOS netguard). It is
   a fast-forward of the pushed `metal-3.1` `6ca46df`, but **not** of the pushed `item/W11-ON37` /
   `item/W11-NETGUARD-MAC`, which would need force-pushes if they are reused.
3. Before merging to main: revert the TEMPORARY CI skip (`86f48b0`) once manual platform testing is
   done.

## Pushed (2026-11-21)

- risc0 `rebase/metal-3.1` @ `81ee699e3` is on hemilabs/risc0 as the new branch **`zkminer/metal-3.1-v2`**
  (no force-push; `zkminer/metal-3.1` @ `37b434755` is unchanged). The zk-miner pin now resolves.
- The temporary PR-CI skip covers every pushed beta branch: `metal-3.1`, `metal-3.1-v2` and
  `netguard-mac-v2` (build-docker, e2e, build-macos build/cpu-tests and thus metal-probe, and
  netguard-linux). risc0's workflows run only on pull requests, so a push runs nothing there.
- `the_image_is_risc0_groth16s_pinned_by_digest` is ignored on macOS (it needs the Linux dependency
  graph offline; it failed the macOS cpu-tests job, pre-existing since #37).
