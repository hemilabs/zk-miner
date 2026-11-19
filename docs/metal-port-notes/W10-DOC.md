# W10-DOC: the beta's remaining user-facing issues (messages and docs)

Branch `item/W10-DOC`, worktree `/Users/user/zkminer/zk-miner-3.1-wt-W10-DOC`, from `item/W10-BENCH` @
`bcb0376` (GitHub main merged into the beta, risc0 pin `28b4bef33`, then W10-BENCH). Logs are in
`/Users/user/zkminer/scratch/w10/W10-DOC/`. The commit `4d421db` has the code and docs; this note is
in its own commit after it, so the kit below records `4d421db` as its commit.

No proving code, kernel or hot path changed, so the R17 audit, the interleaved A/B and the budget runs
do not apply. Nothing has a revert knob, because these are message and doc fixes. The one measurement
taken is a `zkminer benchmark` from the built kit, to check the duration the docs give (below).

## Before: what was reproduced

| issue (source) | reproduction | log |
|---|---|---|
| `zkminer init` step 3: "Stake it (via the Wallet screen)" although `zkminer stake` exists (RC1 item 4, RC2 docs item 4) | W10-BENCH's release CLI on a fresh `HOME`: the old text | `before/init.out` |
| `zkminer init --network mainnet` printed "Pre-configured for Hemi Testnet (chain ID 743111)" (found here) | same CLI | (in this session's output) |
| `zkminer run` on a fresh install printed `Error reading the log directory/files: No such file or directory (os error 2)` before `ZKMINER_PRIVATE_KEY not set` (the macOS 26 VM, `scratch/w9/B9-M26/vm/out-rc1/run.log`) | same CLI, fresh `HOME`, `init`, then `run` with no key: both lines, rc 1 | `before/run.err` |
| `sha256sum -c SHA256SUMS` in the release notes fails on a Mac with only the kit (RC2 docs item 2) | a `SHA256SUMS` with a missing line: `/sbin/sha256sum -c` rc 1, `shasum -a 256 -c` rc 1; with `--ignore-missing` both rc 0; a tampered file rc 1 for both. **macOS's `/sbin/sha256sum -c --ignore-missing` returns 0 when no listed file exists**; `shasum -a 256 -c --ignore-missing` says `no file was verified` and returns 1 | `sumtest/` |
| A quarantined binary over SSH hangs with no output (RC1 item 3, "not retested") | this session runs over SSH (`launchctl managername` = `Background`, `SSH_CONNECTION` set), Gatekeeper assessments on. An ad hoc signed one-line C program with `com.apple.quarantine` printed nothing until `alarm 40` killed it (rc 142); `spctl -a -t exec` says `rejected`. The **kit's own `zkminer help`**, extracted from a quarantined tarball, printed nothing for 25 s (rc 142). SIGINT with its default disposition ends it (exit 130), so Ctrl-C works. `tools/macos-smoke.sh` on that kit exits 8 without launching anything | `gk/`, `qkit/` |
| `--generate-key` | the kit README said "`zkminer init` (and a key with `--generate-key`)"; `init.rs` prints "--generate-key is not yet implemented" | code |
| Component sizes (RC2's 5.4 / 7.8 GB) | `~/.risc0/extensions/v0.2.0-risc0-groth16`: 5,812,781,917 bytes (`du -sk` 5,676,552 KiB = 5.41 GiB). The archive is 2,406,044,780 bytes. Both `groth16_component.rs` and `install.sh` keep the archive until the unpack is complete, so the peak is 8.22 GB. "5.4 GB" was GiB and "7.8 GB" mixed 2.4 GB with 5.4 GiB | code, `du` |
| `install.sh --help` for `--prefix`: "another prefix needs a [workers] search_dirs entry" | no such setting. The config has `[prover] worker_search_paths` (`zkminer-config`), which discovery searches before `~/.zkminer/provers` | code |

## What changed

**Code (zkminer-cli):**

| file | change |
|---|---|
| `src/commands/init.rs` | `summary(network)` builds the text. Testnet: the deployment lines, then 5 steps, each with its command. (1) `export ZKMINER_PRIVATE_KEY=…`, a key of your own (zkminer makes none). (2) Testnet ETH (the team or a Hemi testnet faucet) and tHEMI from the HemiProve team, minted only by its owner, with at least 100 tHEMI of stake per job held at once. (3) `zkminer stake 100`, with the first claim one block after the first stake. (4) `zkminer status`. (5) `zkminer run`. These are the handoff's facts (sections 4 and 12: minCollateral 100 tHEMI, `StakingBlockDelayNotMet`, owner-minted tHEMI). Mainnet: the chain and RPC, and that `[contracts]` must be filled in; it is no longer called testnet. Two unit tests |
| `src/main.rs` | TUI mode creates `~/.zkminer/logs` before `tracing_appender::rolling::Builder::build`. The builder (tracing-appender 0.2.4, `prune_old_logs`) reads the directory before its writer creates it, and printed the error with `eprintln!`. If the creation fails, the builder still reports its own error |
| `tests/first_run_cli.rs` (new) | the built CLI with a fresh `HOME` and no key. `init` names the stake, status and run commands, and a second `init` keeps the config. `init --network mainnet` does not say Testnet. The first `run` (TUI mode) prints no log-directory error, stops at the key error and leaves `~/.zkminer/logs`. No network, GPU or process-wide state is involved (each test has its own `HOME`), so it needs no test lock. **All 3 fail on the previous code** (`cli-test-negative.log`) |

**Docs and packaging:**

| file | change, and what it was checked against |
|---|---|
| `docs/macos-beta.md` "Build the kit" | The release kit has no archives. CI builds it (`build-macos.yml` job `build`: `ASSEMBLE_BUILD_ONLY=1`, prune, `ASSEMBLE_SKIP_BUILD=1 AOT_ARCHES=none`, `check-macos-kit.py`, `test-check-macos-kit.sh`; read from the workflow). The local command is `AOT_ARCHES=none scripts/ci/assemble-macos.sh`, then `check-macos-kit.py`. The script's default `applegpu_g17s` gives a kit that `check-macos-kit.py` fails (`NO_ARCHIVES_TEXT`; `test-check-macos-kit.sh` case 2n). Step 3 and the `AOT_ARCHES` row say so. The wall time is this item's build. The layout lists `tools/macos-smoke.sh` and an empty `metal-aot/` |
| `docs/macos-beta.md` "Offline archives" | It opens with "the release kit ships none", why CI cannot build a set, and that shipping one is a user decision that needs the README text. "The kit ships a `macos27` set" now says "a kit with archives has …" |
| `docs/macos-beta.md` "CI" | The pre-B9-CI sketch (`--no-aot`, `macos-smoke.sh --no-proof`, "the workflow files are not part of this item") is replaced. Now: the three jobs, the runner expression, the release wiring and the pins table (offline archives: none; the `xcode` input). It points at `docs/ci-macos.md`. The smoke exit codes gain 9. The runner caveats are shortened and point at the measured disk budget |
| `docs/macos-beta.md` "Groth16", "quarantine" | Exact sizes and the 8.2 GB peak (code above). The SSH hang, with this session's reproduction |
| `RELEASE-DEPS.md` "Building on a clean macOS machine (CI)" | `xcodebuild -downloadComponent` / `brew install protobuf` is replaced by the three scripts CI runs: `macos-metal-toolchain.sh … pinned` (27B47, printing its export line outside a workflow), `macos-toolchains.sh` (rustup 1.29.3, rzup from the pinned rev, guest toolchain 1.97.0, protoc 36.2) and `AOT_ARCHES=none assemble-macos.sh`. Each was checked against the script's header and code. The compiler note says that assemble refuses other compilers unless `METAL_COMPILER_UNVALIDATED=1`, and that the release refuses such a kit (`assemble-release.sh` `--require-validated`) |
| `docs/ci-macos.md` | The component is 5.8 GB = 5.4 GiB. A kit with archives needs the README text back. The release notes' checksum line |
| `.github/workflows/release.yml` (notes only) | Verify with `sha256sum -c --ignore-missing SHA256SUMS` on Linux and `shasum -a 256 -c --ignore-missing SHA256SUMS` on a Mac (shasum, because macOS's sha256sum passes an empty match), "each file must print OK"; on Windows, `(Get-FileHash zkminer.exe).Hash` |
| `packaging/macos/README.md` (the kit README) | The checksum command is the `-c --ignore-missing` one, with the expected `OK` line and what `no file was verified` means. "Then:" covers init, the key, `zkminer stake 100`, `zkminer status`, the benchmark (optional) and `run`. There are notes on the key (no `--generate-key`), tHEMI and gas from the HemiProve team (100 tHEMI per job in flight, one block after the first stake), and the benchmark's duration: 262-314 s on the M5 Max (this item's run and W10-INT's). The Disk row and the Groth16 section give 5.8 GB (5.4G in `du -h`) and about 8.3 GB free. Gatekeeper has an "Over SSH" bullet: it hangs and prints nothing, Ctrl-C, install.sh or `xattr -d`, smoke exit 8. "About 0.2 GB for the kit" and "This kit has no offline GPU pipeline archives" are unchanged (`check-macos-kit.py` checks both against the kit) |
| `packaging/macos/install.sh` | `--prefix` help: `[prover] worker_search_paths = ["DIR/provers"]` in `~/.zkminer/config.toml`. The component is 5.8 GB. Uninstall names `~/.zkminer/config.toml`, the config's real path whatever the prefix. The "Next" list gains the key, tHEMI and stake line. `bash -n` passes, and shellcheck's findings are identical to the file before (`sc-old.txt` = `sc-new.txt`) |
| `README.md` macOS section | The risc0 fork is pinned by git rev (it said "takes from `../deps/risc0-3.1`"), with `RISC0_SRC=local` for a checkout. The kit sizes and the checksum command. The quick start goes init, key, `stake 100`, run. A line on the SSH hang. A note on the Metal compiler: release kits use 27B47 through `fetch-metal-toolchain.sh`, and Xcode 26's component is another, unvalidated build. "The full six-program `--benchmark`" becomes main's suite: the fibonacci warm-up and five programs, 154.5M cycles in 169.6-171.1 s of STARK, wraps of 1.57-1.60 s, then zkop-mix scoring (4.2M and 61.9M cycles, 73 s), 254 s wall (W10-INT `bench/full-def/Bfinal.log`). Known limitations had "about 3 minutes" and now say about 4.5 minutes (254 s; 262-314 s for `zkminer benchmark`) |
| `README.md` elsewhere (item 7) | The per-card po2 rules name `gpu-metal0`, and a Mac takes its Metal tier (`risc0_slot_job_po2`: 19 on 16 GB, 20 from 24 GB). "Layout" said risc0 and SP1 were "referenced by moving branch heads". Both are rev-pinned in `Cargo.toml` now, as sppark is. The rest of main's README (the Windows sections, zkOP/s scoring, the simulate and watch-only text) does not contradict the macOS sections. Main's "GPU power … 300 W default" still holds: `FALLBACK_GPU_WATTS` |

Main's other changes were checked. The benchmark rework is now described. Windows appears only in main's
own sections and the release notes, where nothing conflicts with the Mac text. zkOP/s scoring is
reported by `zkminer benchmark` on the Mac (2.72 MzkOP/s below).

## The kit and the gates

A kit built through the mirror, from `4d421db`, clean: `AOT_ARCHES=none scripts/ci/assemble-macos.sh`
(git mode through `file:///…/scratch/w9/mirror/risc0.git`, which holds `28b4bef33`; `scripts/genv.sh`).
The CLI (69 s) and the worker (194 s) were built first with `assemble-macos.sh`'s own environment
(`ASSEMBLE_ENV_OUT`), to stay under the tool's 10-minute limit. Then `assemble-macos.sh` took 71 s
(36 s for the final run).

- `zkminer-0.1.0-macos-arm64.tar.gz`, sha256 `05a9da05586bdb97db17b6b53122b1d3e95bd66487b0c8e64360849083b9b5ce`.
  It is 121,305,777 B packed and 192 MB unpacked, with 10 files and no archives.
- `BUILDINFO`: commit `4d421db…` (`commit_dirty=no`), `risc0_rev=28b4bef33…`, `risc0_src=git`, `min_macos=26.0`,
  compiler 32023.922, `metal_compiler_validated=yes`, empty `aot_arches`.

| gate | result |
|---|---|
| `check-macos-release.sh <kit>` (also run inside assemble) | ok: minos 26.0, 7 metallibs for 26.0, compiler 32023.922, no archives, Groth16 not bundled |
| `check-macos-kit.py --require-validated --version 0.1.0 --commit 4d421dbd2c0edfcc74ad7ca9afb3d8e22f610442 <kit>` | ok (README archive sentence and "About 0.2 GB" accepted against 192 MB) |
| `scripts/ci/test-check-macos-kit.sh <kit> 4d421dbd2c0edfcc74ad7ca9afb3d8e22f610442` | 16 passed, 0 failed (incl. 2m wrong README size, 2n README vs archives) |
| `scripts/ci/test-assemble-macos.sh <sdk worker> <sdk CLI> <kit worker> <kit CLI>` (sdk = W10-BENCH's plain release build, minos 11.0; kit = this kit's binaries; `gpu-run --light`, cases 8 and 12 run `--metal-arch`) | 44 passed, 0 failed (140 s) |
| `scripts/ci/lint-workflows.sh` (actionlint 1.7.12, shellcheck 0.11.0, repo config) | ok; expression tests 425/425 |
| `cargo test -p zkminer-cli` (mock worker built), twice, under `gpu-run --light` | 150 unit, `benchmark_cli` 5, `first_run_cli` 3, `localnet` 1 (+12 ignored): all pass both runs |
| the same `first_run_cli` against the previous `init.rs`/`main.rs` | 3 of 3 fail (the negative control) |
| install from the kit into a sandbox `HOME`, `zkminer init`, `zkminer benchmark` (`gpu-run --no-budget`, load 1.3-1.7; the user's Groth16 component and pipeline cache linked in) | `install.sh` rc 0. The new "Next" list and `init` text are shown. The benchmark gave rc 0 and **2.72 MzkOP/s**, with STARK sha256-chain 51.00, ecdsa-verify 71.01, bigint-mul 30.68, memory-merkle 8.32 and chacha-mix 9.71 s (sum 170.72 s), zkop-mix 68.21 s and Groth16 1.60 s. Wall **261.8 s**. That is W10-INT's speed and well within BASELINES '3.1' |

## Open issues

1. **macOS 26's `shasum`** was not run (no macOS 26 host). The command is Perl's `shasum` (Digest::SHA),
   which supports `--ignore-missing` on macOS 27.2 here. The macOS 26 VM in the user checklist should
   run the README's line once.
2. **`scripts/ci/macos-smoke.sh`'s exit-8 comment** says macOS "kills such an unsigned binary". Over
   SSH it hangs instead (above). The script never launches it, so its behaviour is right. The comment
   is in `scripts/ci`, which this item does not own.
3. **The desktop Gatekeeper path** ("Not Opened", Open Anyway) is still untested. This session has no
   GUI, and no dialog was observed.
4. **`zkminer init --generate-key`** is still not implemented. The docs no longer promise it. A key has
   to come from elsewhere (`cast wallet new` if Foundry is installed), and the docs do not name a
   tool.
5. **`assemble-macos.sh`'s `AOT_ARCHES` default** is still `applegpu_g17s`, which gives a kit that
   `check-macos-kit.py` rejects. The docs now say to pass `none`. Changing the default is a
   `scripts/ci` change for its owner.
6. `docs/release/BETA_RC.md` is the Wave 9 record and was left as it was. The next RC round should
   use this kit's commit or later.
