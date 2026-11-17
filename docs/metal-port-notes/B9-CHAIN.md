# B9-CHAIN: zk-miner on the 2026-11-16 HemiProve deployment (risc0 3.1 verifier)

Branch `item/B9-CHAIN` (worktree `/Users/user/zkminer/zk-miner-3.1-wt-B9-CHAIN`), from `item/B9-ZK`
`79f0679`. The risc0 crates resolve through the `[patch.crates-io]` paths to
`/Users/user/zkminer/deps/risc0-3.1` (not edited). The release builds use `--locked`, and `Cargo.lock`
is unchanged. Scratch, logs and scripts are in `/Users/user/zkminer/scratch/w9/B9-CHAIN/`:

- `live/`: the read-only RPC checks;
- `explorer/`: verified sources and ABIs;
- `rcpt/`: the Metal receipts;
- `anvil/`: the scripted scenarios;
- `localnet/`: the suite's logs;
- `gates/`: the test gates;
- `scripts/`: every script used.

No Metal kernel, risc0 file or proving path changed. R17 (`ir_scan.py`, `run_stress.sh`) therefore
does not apply, and no performance A/B was needed: the worker binary is built from unchanged
sources. On the miner's side, the only runtime additions are one `eth_call` per proof-system
verification and a 260-byte length check on each risc0 seal.

## The authority problem (read first)

**The contracts repository could not be read.** Neither
`github.com/max-sanchez/hemi-prove-contracts` nor `hemilabs/hemiprove-contracts` is reachable from
this host:

- `git clone` fails because the keychain credential helper is not allowed to prompt (-25308);
- `gh` holds an invalid token;
- anonymous HTTPS returns 404 (both repos are private);
- the ssh agent socket refuses connections;
- no local copy exists.

So `script/lib/ReleaseCorePins.sol`, `VerifierPins.sol`, the `abi/*.abi.json` files, the deployment
record, `INTERACTION_GUIDE.md` and `CHANGELOG_ABI.md` at `8e1808b` were **not** available. I used
these sources instead, each cross-checked:

1. **Code pins.** I computed them with zkminer's own pin method (`keccak_self_zeroed`,
   `keccak_offsets_zeroed`) from the live 743111 code at block 7234324.
   - The method is validated: run on the **abandoned** 2026-10-29 stack's live code, it reproduces
     the c8333aa `AuditedCorePins.sol` values byte for byte. That covers the router implementation
     `fe19d149…` and all five old facets (`96787200…`, `5c181365…`, `f7dd82f1…`, `60675be0…`,
     `500035cd…`).
   - Unchanged since 2026-10-29: the ERC1967 proxy, both adapters' code (RISC Zero `dc362a20…`,
     SP1 `99d18017…`, with the same immutable offsets) and the SP1 v6.1.0 Groth16 verifier
     (`6e1a354c…`).
   - New:
     - the router, Staking, Registry and ProgramRegistry implementations (all compiled with solc
       0.8.38);
     - the five facets;
     - the risc0 3.1 verifier, `26e455ef…` (raw keccak, 4,611 B).
   - **These are trust-on-first-use pins for the new code.** They catch any later upgrade or swap.
     They do not prove the code is the audited 8e1808b code. One command checks them against the
     repo: `ZKMINER_CONTRACTS_REPO=<checkout at 8e1808b> cargo test -p zkminer-chain --lib
     the_pins_match_the_contracts_repo`. It requires every pin value to appear in
     `ReleaseCorePins.sol` or `VerifierPins.sol`. **Run it before the beta ships.**
2. **The risc0 3.1 verifier** is established independently of the pin files:
   - its explorer-verified source equals risc0-ethereum tag v3.1.0 (`ff30da77`, cloned from the
     public repo) once comments are stripped. The only differences are the SafeCast import path and
     one reformatted function signature in `StructHash.sol`. The vendored headers quote the upstream
     sha256 of each file, and those match the clone;
   - its constructor arguments equal v3.1.0's `ControlID.sol` (`CONTROL_ROOT e6feef13…551d`,
     `BN254_CONTROL_ID 0ac2eaf9…81de`);
   - live, `SELECTOR()` is `0xe71e6620` and `VERSION()` is "3.1.0".
3. **ABIs** come from the explorer's verified sources (testnet.explorer.hemi.xyz; every deployed
   contract is verified).
   - I canonicalised them into forge's `abi/*.abi.json` layout with a script that reproduces the 8
     unchanged c8333aa files byte for byte from their explorer ABIs.
   - The router union follows the rule (first occurrence wins, in the order HemiProve, Core,
     Fulfill, FulfillCycle, Aux, AuxGov) that reproduces the c8333aa `HemiProveRouter.abi.json` byte
     for byte.
   - `hemiprove-abi/VENDORED_FROM.txt` states all of this.

## Summary

| sub-track | result |
|---|---|
| (1) zkminer-chain deployment | `KnownDeployment` is now the 2026-11-16 stack: router `0xD931…Ed58`, Staking `0xF349…2e2D`, Registry `0xA80D…f10F`, ProgramRegistry `0xeBB9…695D`, tHEMI `0x4695…36cc` (unchanged, codehash `536084d8…` unchanged), `scan_from_block` 7226094. New core, facet and verifier pins (see above). `RISC0_V3_1_GROTH16_VERIFIER = Some(26e455ef…)`. 3.0 seals are refused (`risc0_v3_0_refused`): no 3.0 verifier pin is accepted any more. The 2026-10-29 stack and the old free-mint tHEMI are refused as ABANDONED (`ABANDONED_743111`, `abandoned_stack_refusal`), even under `ZKMINER_ALLOW_UNKNOWN_DEPLOYMENT=1`. New: a startup `eth_call` of `Registry.verifyProof` with a known-good Metal 3.1 receipt (`risc0_preflight`, knob `ZKMINER_SKIP_RISC0_RECEIPT_PREFLIGHT=1`). New: `binding::proof_nonce`. |
| (1) ABIs | `hemiprove-abi/` regenerated: 9 files changed (see "ABI changes"). `tests/abi_pins.rs` recomputes every selector, topic and error from the JSON. It checks every call, event and error of every binding zkminer-chain uses against the ABI of the contract it targets, and the handoff's Appendix A, section 9 and Appendix C tables against the ABI. `zkminer-contracts` keeps its own output-tuple pins (6/6 pass). `INTERACTION_GUIDE.md` and `CHANGELOG_ABI.md` could **not** be updated to 8e1808b (open issue 1). |
| (2) risc0 toolchain | The fork matches the handoff: risc0-zkvm 3.1.0, risc0-groth16 3.0.6, risc0-circuit-recursion 4.1.0 (`Cargo.lock` and `deps/risc0-3.1` manifests). zk-miner does not link risc0-ethereum-contracts; its `risc0_onchain_seal` (`run.rs`) is byte-identical in construction to v3.1.0 `encode_seal` (`selector = verifier_parameters[..4]`, then the 256-byte seal), giving 260 B starting `e71e6620`. Docker on macOS: see "Docker on macOS". |
| (3) live read-only checks | Handoff section 13 tests 1-4 pass. zkminer's own `verify_deployment` and `verify_proof_system` pass against the live chain. **Decisive check passes:** Metal 3.1 receipts (fibonacci, memory-merkle) verify through `Registry.verifyProof` and the native verifier; tampered seals, wrong journals and 3.0 seals fail. |
| (4) Foundry + localnet | Foundry v1.5.1 darwin-arm64 is in `/Users/user/zkminer/bin` (sha256 matches GitHub's published digest). The localnet suite forks the live 8e1808b deployment: **9/9 runnable tests pass, twice**, including a full RISC Zero Groth16 job proved by the Metal worker with payouts checked. A scripted anvil run covers handoff tests 5, 6, 10, 11, 13, 14, 15 and 16. |
| (5) checklist | See "Handoff section 5 and sections 9-11". Implemented: the risc0 seal length and prefix pre-check, the receipt preflight, the abandoned-stack refusal, and the watch-only verdict fix. The rest is listed. |

## (3) Live read-only checks (2026-11-17, `https://testnet.rpc.hemi.network/rpc`, User-Agent `zkminer-test` / `zkminer/<ver>`)

Logs: `live/checks.log`, `live/codes.log`, `live/verify_live.log`, `live/zkminer_live_tests2.log`.
Only `eth_call`, `eth_getCode`, `eth_getStorageAt` and `eth_getLogs` were used. Nothing was signed or
sent, and no key was used.

- **Test 1.**
  - Chain id 743111.
  - Wiring: `router.staking/registry/hemiToken` and `Staking.hemiToken` name the section 2
    addresses.
  - Neither the router nor the Registry is paused.
  - The token is "Test HEMI" / tHEMI, 18 decimals, owner `0x1efd…33ff`.
  - Codehashes: the four proxies are `46a010df…` (ERC1967Proxy); the implementations and adapters
    are as listed above. The deployment record was not available to compare against (see the
    authority section).
- **Test 2.**
  - `getAdapter` returns `(adapter, 1, 0, 0x0, 15000, 1e20, 100, 0)` for each of
    `risczero.groth16.v1` → `0x9181…5dE2`, `sp1.groth16.v1` → `0x4bc0…B702` and `sp1.plonk.v1` →
    `0x7d2E…2F35`.
  - Native verifiers:
    - RISC Zero `0x9b85…F852`: `SELECTOR` `0xe71e6620`, `VERSION` "3.1.0";
    - SP1 Groth16 `0x517b…3E8F`: `VERIFIER_HASH` `0x4388a21c…e696`, "v6.1.0";
    - SP1 PLONK `0xf1E2…E19c`: `VERIFIER_HASH` `0x5a093a2f…7fac`, "v6.1.0".
  - `risczero.v1` and `openvm.halo2.v1` are unregistered.
- **Test 3.**
  - `binding::proof_nonce` reproduces the section 8 vector offline: B `57ea0cc5…`, limbs
    `[0x18d1097b, 0x28ce9cf6, 0x1e4353ab, 0x166b4653]`, nonce `0x31a212f6a33a73d8f21a9d5966b4653`.
  - It also matches the live router's `getProofNonce` for 4 fresh random (jobId, prover) pairs per
    run (`live_743111::the_proof_nonce_matches_the_live_router`) and for 3 captured vectors (unit
    test).
  - With router `0xD931…` the derivation matches. With the abandoned `0xE1a4…` it does not (live
    `0xE1a4…getProofNonce` returns a different nonce for the same input). This settles the section 8
    inconsistency.
- **Test 4.**
  - 15 `JobSubmitted` logs since block 7226094.
  - Every descriptor decodes from its submit tx calldata, and `compute_descriptor_hash` equals the
    log's `descriptorHash`: 15/15 (`every_live_job_descriptor_decodes`).
  - They cover risc0 FULL, FIELDS and journal-prefix jobs, SP1 Groth16 with the nonce marker, and
    SP1 PLONK.
- **zkminer `verify_deployment`** (`live_743111::the_live_deployment_verifies`, a watch-only
  client):
  - it passes, and so do `verify_proof_system(risczero.groth16.v1, e71e6620)` (with the receipt
    preflight) and `verify_proof_system(sp1.groth16.v1, 4388a21c)`;
  - `verify_proof_system(risczero.groth16.v1, 73c457ba)` is refused with the 3.0 message;
  - a config naming the abandoned router is refused with the ABANDONED message.
- **Decisive end-to-end check** (`scripts/verify_live.sh`):
  - Receipts: made fresh by this worktree's release Metal worker (`BENCH_ONLY=<p> --benchmark`,
    `ZKMINER_BENCH_RECEIPT_DIR`, default budget; logs in `rcpt/`).
  - Each receipt was then verified by `dump31`, a tool built only from crates.io risc0-zkvm 3.1.0
    (no path dependencies), which also extracts the journal and the 260-byte seal.

| receipt | `Registry.verifyProof(0xf8fe…60c5, imageId, journal, seal, "")` | native `verify(seal, imageId, sha256(journal))` |
|---|---|---|
| fibonacci 3.1 Metal (image `245dd297…`, journal `4b60c05cc74d590b`) | **ok** (returns 0) | **ok** |
| memory-merkle 3.1 Metal (image `05bd9ebe…`) | **ok** | **ok** |
| either, one seal nibble flipped | reverts `VerificationFailed()` `0x439cc0cd` | same |
| either, journal + 1 byte | reverts `0x439cc0cd` | same |
| risc0 3.0 receipt (the c8333aa contract-suite fixture, `73c457ba`) | reverts `SelectorMismatch(0x73c457ba, 0xe71e6620)` `0xb8b38d4c` | same |
| the 3.1 proof relabelled `73c457ba` | reverts `SelectorMismatch` | same |

## (4) Foundry and the localnet suite

- **Foundry v1.5.1.**
  - `foundry_v1.5.1_darwin_arm64.tar.gz` from github.com/foundry-rs/foundry/releases.
  - Its sha256 `b3bf1752be066e0877911721e0624058171c88fc5616e228937fe4620b41c40d` equals the digest
    GitHub publishes for the asset (releases API).
  - The attestation (`attestations/15443976`) could not be verified: the attestation API needs
    authentication.
  - `forge`, `cast`, `anvil` and `chisel` are in `/Users/user/zkminer/bin` (commit `b0a9dd9c`).
- **The suite's own design forks the live deployment** (`anvil --fork-url` 743111). It therefore runs
  exactly the 8e1808b code that is deployed, rather than a local deploy from the repo's script, which
  was unavailable.
- Changes to `crates/zkminer-cli/tests/localnet.rs`:
  - `FORK_BLOCK` moved to 7_234_420;
  - the replayed receipt is now the Metal worker's risc0 3.1 fibonacci receipt (it was the
    contract suite's 3.0 receipt), with no selector override;
  - `refuses_to_claim_without_a_matching_verifier` is now the 3.0 negative: a miner configured with
    `0x73c457ba` refuses every risc0 claim. Its log shows `risc0 3.0 Groth16 seals (SELECTOR
    0x73c457ba) are refused`;
  - `check_settlement` asserts every `JobFulfilled` pays settledPrice + speedBonus − 1% fee.

| test | pass 1 | pass 2 |
|---|---|---|
| `fulfils_with_a_replayed_receipt` (mock worker replays the Metal receipt; real claims and fulfils) | ok 109 s | ok 106 s |
| `mines_the_claimable_jobs` (**real Metal worker**, `ZKMINER_LOCALNET_MINE=1`, gpu-run heavy) | ok 159 s | ok 160 s |
| `watch_only_reports_every_job` (Metal worker) | ok 246 s | ok 246 s |
| `simulate_reports_every_job` | ok 50 s | ok 50 s |
| `holds_its_lock_through_a_pause` | ok 307 s | ok 310 s |
| `holds_off_while_the_router_is_paused` | ok 110 s | ok 113 s |
| `refuses_to_claim_while_its_adapter_is_disabled` | ok 54 s | ok 55 s |
| `refuses_to_claim_without_a_matching_verifier` | ok 53 s | ok 54 s |
| `refuses_to_claim_on_a_skewed_clock` | ok 108 s | ok 108 s |
| `serves_a_tui_miner`, `serves_jobs_to_simulate` | not run: by design they serve a localnet to a miner run by hand | |
| `mines_on_every_gpu` | not run: needs the SP1 server and every GPU worker | |

**The full RISC Zero Groth16 job** (`mines_the_claimable_jobs`):

- Jobs: four claimable risc0 jobs (FULL, FIELDS, NONE-for-us, FULL-assigned-to-another with no
  window), submitted on the fork.
- Each one is claimed alone; the lock is confirmed by `jobs().prover` before the proof. The test
  checks that each claim is mined in an earlier block than its fulfil.
- Each is proved by the Metal worker. The kept run directory shows 5 Metal Groth16 key releases
  (warm-up plus 4 jobs) and no Docker.
- Each is fulfilled. Every `JobFulfilled` pays 4.95 tHEMI on a 5 tHEMI price: settledPrice
  5e18 + speedBonus 0 − fee 5e16.
- No collateral is left locked, the stake is whole, and the prover's nonce moved by exactly 2 per
  job.
- The seven non-claimable cases are never claimed: wrong journals, exclusivity, collateral over the
  stake, the prefix marker, an unreachable ELF and a decoy ELF.

**watch-only fix.** `watch_only_reports_every_job` failed at first: no WOULD CLAIM verdict ever came.

- Cause (found with `-v`): the claim gate "Not claiming risc0 jobs until its one-time setup is done"
  (`run.rs`) holds every job until the backend's warm-up has run. A watch-only run never starts the
  warm-up (`spawn_sp1_warmup` is skipped when watching), so on a Metal host the verdict never came.
- Fix: the gate is skipped when `watch_only()` is set (it proves nothing).
- This changes no sending path. The gate dates from phase 1; it is not a 3.1 regression.

### Handoff section 13 tests 5-18 (scripted anvil run, `scripts/anvil_scenarios.sh`, log `anvil/scenarios.log`; fork of 743111 at 7234420, every sender impersonated, the Metal fibonacci receipt)

| # | result |
|---|---|
| 5 | Stake and claim in one block (automine off): the stake succeeds; the claim reverts `0x27e761d2` StakingBlockDelayNotMet; `getAvailableCollateral` = 100e18. |
| 6 | Covered twice: the localnet mining test, and here (claim alone, `jobs().prover` = prover, free stake 0 while locked, fulfil, `JobFulfilled` payout 4.95e18 = 5e18 − 1%, free stake back to 100e18). |
| 7, 8, 9, 12 | Not applicable to this build. zkminer serves no SP1 nonce-marker or PLONK jobs and refuses prefix-marker jobs (watch verdict "its binding marker is not supported by this build"). It never uses `claimAndFulfillAssigned`. |
| 10 | Speed premium 2 tHEMI: `previewSpeedBonus` at the fulfil's timestamp = 1666666666666666666 = `JobFulfilled.speedBonus`. |
| 11 | A wrong journal: `eth_call` reverts JournalMismatch `0x91d07f1e`; `releaseJob` succeeds with `JobReleased.penaltyAmount` 5e18 (5% of 100 tHEMI); a re-claim reverts ReleaseCooldownActive `0x71e53069`. zkminer classifies these as ProofDefect and Wait (`revert.rs` test `reverts_captured_from_the_8e1808b_deployment_…`). In normal mining, zkminer's pre-claim measurement refuses a wrong-journal job before claiming (localnet `FullWrongJournal` / `FieldsWrongJournal`). |
| 13 | A 4.5M-gas fulfil reverts `0xa95674c8` InsufficientGasForFullSettlement; a resend at 5.7M succeeds (classified Gas). zkminer's floor is `fulfill_gas_formula` (≥ 5.6M) with a default of 10M (`client.rs` `DEFAULT_FULFILL_GAS_LIMIT`), so it never sends 4.5M. |
| 14 | A second lock on a 100 tHEMI stake: the deployed Staking reverts **InsufficientFreeStake** `0x31ebd6fd`, **not** `Panic(0x01)` as the handoff says. zkminer classifies both as StakeShort and logs STAKE-SHORT. |
| 15 | A floor of price + 1 reverts ClaimBelowFloor `0xc8cea62a` (Wait; the high-water mark is kept, `jobs.rs` `claim_floor_with_high_water`). |
| 16 | 300-s job: `slashAndReopen` at slashOpensAt − 1 reverts "Not expired yet"; the late prover's fulfil reverts "Past deadline" (classified Late: never resent); `slashAndReopen` at slashOpensAt succeeds. |
| 17 | Not scripted. zkminer's unit and integration tests (`nonce_retry_ladder`, `nonce_gap_detection`, `client.rs` `hemi_fees`) cover both fee fields and the 12.5% same-nonce bump. |
| 18 | Not scripted. Recovery from the chain is `run.rs` `recover_claimed_jobs`; `holds_its_lock_through_a_pause` covers the hold side. |
| 19 | The pause drill on testnet needs the team. On the fork it is covered by `holds_its_lock_through_a_pause` (lock kept, no release, fulfilled after the lift). |

## Docker on macOS

risc0's `risc0-groth16` with `--features metal` routes `shrink_wrap` to the Metal prover
(`deps/risc0-3.1/risc0/groth16/src/prove/mod.rs`). It falls back to Docker only when one of these
holds:

- `risc0_zkp::hal::metal::enabled("groth16")` is false (`RISC0_METAL=0` or `RISC0_METAL_SKIP=groth16`);
- `RISC0_GROTH16_METAL_PROVER=docker` is set;
- `metal_supported()` fails.

The mac build always uses `--features metal` (`Makefile.mac`). Every wrap in this item's runs was
Metal (benchmark logs, and 5 releases logged in the localnet mining run). The README now says not to
set those variables. zk-miner itself has no guard against them (`crates/zkminer-prove-risc0`, outside
this item): open issue 4.

## Handoff section 5 and sections 9-11, against zkminer

Status: done = implemented; n/a = not applicable to what this build serves; missing = not
implemented.

**This deployment (2026-11-16)**

- **done**: new addresses: `deployment.rs` `HEMI_TESTNET_743111` (`:222`), `init.rs`. The 2026-10-29
  stack is refused: `abandoned_stack_refusal` (`:249`).
- **done**: risc0-zkvm 3.1.0. `verify_proof_system` reads `nativeVerifier().SELECTOR()` and
  requires the build's `e71e6620` (`deployment.rs:643`). 3.0 is refused.
- **done (new)**: `Registry.verifyProof` `eth_call` on one of our own receipts before the first risc0
  claim: `risc0_receipt_preflight` (`deployment.rs:667`), on every risc0 proof-system verification.
- **done**: log scans start at 7226094: `scan_from_block`, `monitor.rs:167`.

**2026-10-29**

- **done**: new tHEMI.
- **done**: chain id check (`client.rs:430`) and code pins (`verify_deployment`, `deployment.rs:361`).

**2026-10-28**

- **done**: the new ids (`auction.rs:71`).
- **done**: FULL hash with the job's own id (`binding.rs:69`).
- **done**: renamed adapter ABIs.
- **n/a**: the SP1 filter on both ids, and the PLONK prefix and length checks. This build serves
  `sp1.groth16.v1` only.
- **done**: SP1 Groth16 prefix and length check before the fulfil (`run.rs:10079`).
- **done (new)**: risc0 260-B and `e71e6620` pre-check before the fulfil (`run.rs:10096`).

**2026-10-26**

- **done**: JournalPrefixMismatch and ProofNonceMismatch classified as release-worthy
  (`revert.rs:169`).
- **missing, safe**: the prefix marker is refused at measurement (`run.rs:8312`); nonce-marker jobs
  are refused (`binding.rs:119`). `binding::proof_nonce` now exists for a future pre-check.
- **missing, optional**: `claimAndFulfillAssigned`.
- **done**: the union clock views and effective deadlines from `getJobStatusView`.

**2026-10-17**

- **done**: `claimJob(bytes32,uint96,uint96)` with exact floors and a per-job high-water mark
  (`jobs.rs:236`).
- **done**: ClaimBelowFloor = Wait.
- **done**: CANARY when settledPrice < floor (`jobs.rs:1494`).
- **done**: JobStatusView with 22 members (zkminer-contracts pins).
- **n/a**: bids (zkminer does not bid).

**2026-10-15**

- **done**: PROVER_GRACE windows (`auction.rs:41`).

**2026-10-13**

- **done**: the 10-field descriptor and its hash (`descriptor.rs:397`).
- **done**: decode of `submitJob`, `submitJobSimple`, `submitJobDefault` and `submitJobBatch`
  (`descriptor.rs:351`).
- **done**: journal cap (`jobs.rs:19`).

**Section 9**

- **done**: claim and fulfil revert classification (`revert.rs`). VerifierCallFailed re-reads
  `Registry.paused` and the adapter status before any release (`run.rs:10277`).
- **done**: Late is never resent.
- **done**: RPC errors without revert data never release.
- Note: the deployed Staking reverts InsufficientFreeStake where the handoff says `Panic(0x01)`.
  Both are handled.

**Section 10**

- **done**: broadcast rule: claim alone; the lock is confirmed by re-reading `jobs().prover` at or
  after the receipt's block (`jobs.rs:884`, `run.rs` "lock_block"); no multicall.
- **done**: one sender per key: `flock` on `~/.zkminer/miner.lock` (`run.rs:449`). It is host-local
  only, as for the daemons.
- **done**: both fee fields; tip = max(2 × `eth_maxPriorityFeePerGas`, 0.01 gwei); maxFee =
  2 × base + tip (`client.rs:297`, `:1189`); ≥ 12.5% same-nonce bumps; a key-wide fee ceiling
  (`chain.fee_ceiling_gwei`).
- **done**: fulfil gas limit from the repo formula (`jobs.rs:174`); never forge-script sized.
- **done**: fulfil payload cap of 128 KiB (`run.rs:1292`).
- **missing**: the 131,072-B signed-tx size check (zkminer caps the payload, not the signed size).
- **missing**: the DA-size estimate (`GasPriceOracle.getL1GasUsed`) before claiming. A follow-up.
- **missing, optional**: late-lock rescue with `slashAndClaim`.
- **done**: alert classes (`PAGE:`, STAKE-SHORT, CANARY, FUNDS-SHORT).
- **missing**: the daemons' exact LOCK-LATE, LOCK-LOST, PENDING-UNMINED and RPC-DOWN names.
- Memory and hardware: SP1 sizing is not this item's.

**Section 11**

- **done**: keep locks through pauses (localnet pause tests); `releaseJob` is never sent because of
  a pause (`run.rs:11838`).
- **done**: deadlines re-read through the clock views. This covers DeadlineExtended implicitly.
- **missing**: no watch on the timelock's `OperationProposed` / `RevokeGuardianProposed` or the
  Registry's `VerifierSwitchProposed`.
- **missing**: no `gracePauseRelease` exit.

## ABI changes, 8e1808b vs the vendored c8333aa (from the explorer's verified ABIs)

- **Router facets and HemiProve:** `jobLaxCallbackMode(bytes32)` was removed (zkminer never used
  it). `HemiProveAuxGov` also lost `markFormerBurnDestination(address)` and gained error
  `ZeroEwmaKey(bytes32,bytes32)`. `HemiProveRouter.abi.json` changed accordingly. Every selector,
  event and error zkminer uses is unchanged (`abi_pins`, zkminer-contracts pins).
- **ProgramRegistry:**
  - removed: `initializeV2`, the event `ProgramAdminTransferred_v2`, and the errors `BondOverflow`,
    `NotInitialized` and `FieldNameTooLong(uint8)`;
  - added: `cancelRegistrantTransfer`, `getPendingRegistrantExpiry`, the events
    `ProgramAdminTransferred`, `CommitmentConsumed` and `ProgramKeyReservationCancelled`, and the
    errors `FieldNameTooLong(uint256)`, `InvalidFieldSize`, `ProgramNotDeprecated`,
    `RegistrantTransferExpired`, `ReservedFlagBits`, `TrailingSchemaBytes` and `ZeroRefProgramId`.
  - zkminer's `IProgramRegistry` calls (`getProgram`, `getStorageURIs`, `isRegistered`,
    `getBuildHashes`, `getResourceEstimate`, `getIOSchema`, `registerProgram`) are all still present,
    and localnet registers and reads programs through them.
- **BatchCycleCommittee:** reworked (17 entries removed, 5 added). zkminer does not use it.
- **Unchanged byte for byte:** Staking, Registry, the three adapters, ProofResultStore,
  GovernanceTimelock and GuardianPauseRelay.

## Handoff inconsistencies (for the user)

1. **Section 8 (SP1 nonce)** says `router` is `0xE1a492Dc…470e`. The live router is
   `0xD931725d…Ed58`, and the live `getProofNonce` matches the derivation with `0xD931…`, not with
   `0xE1a4…` (`binding::proof_nonce` tests, `live/checks.log`).
2. **Appendix A** says "All at the router `0xE1a492Dc…470e`", gives Staking as `0x44b2DDCf…A66E`
   and Registry as `0x77fDb1DC…BBc6`. Those are the abandoned 2026-10-29 addresses. The live ones are
   `0xD931…Ed58`, `0xF349…2e2D` and `0xA80D…f10F` (section 2, and the router's own `staking()` /
   `registry()`).
3. **Sections 4, 9 and 13 test 14** say too little free stake reverts `Panic(0x01)`. The deployed
   Staking reverts `InsufficientFreeStake(address,uint128,uint128)` `0x31ebd6fd` (anvil fork of the
   live code, `anvil/scenarios.log`).
4. **Section 5** says "the Groth16 wrap needs an x86 host with Docker". Not for zkminer on Apple
   Silicon: the wrap is native Metal (risc0-groth16 `metal` feature).
5. **Section 5 lists no ABI change for 2026-11-16.** 8e1808b does change the ABI (`jobLaxCallbackMode`
   removed, AuxGov, ProgramRegistry and BatchCycleCommittee reworked; see "ABI changes"). None of
   these affect a prover's calls.
6. **Section 1/2** point to "the deployment record" for codehashes. It is not in the handoff and
   could not be fetched, so the live codehashes are recorded in `live/codes.log` and in the pins.

## Correctness gates

| gate | result |
|---|---|
| `cargo test -p zkminer-chain` (lib + integration) ×2 | lib 157 passed, 1 ignored; `abi_pins` 3/3; `nonce_*`, `stake_tx_shape` pass; `live_743111` 4 ignored (run separately: 4/4 against the live chain, twice) |
| `cargo test -p zkminer-prover --lib` ×2 (gpu-run) | 291 passed, 1 ignored, both |
| `cargo test -p zkminer-prover --features testing --test worker_lifecycle` ×2 (gpu-run) | 27 passed, 3 ignored, both |
| localnet suite ×2 | 9/9 runnable pass, both (table above) |
| `cargo test -p zkminer-cli --bin zkminer` | 142 passed |
| `cargo test -p zkminer-contracts` | 6 passed |
| release build `--locked` (worker `--features metal`, `zkminer-cli`) | clean; pre-existing warnings only |
| Metal receipts, stock crates.io 3.1.0 verifier (`dump31`, `Receipt::verify`) | fibonacci and memory-merkle OK |
| on-chain: Metal receipts accepted, 3.0 rejected | yes (table in section 3) |

Budgets: no budgeted runs were needed. Nothing in the prover changed, and the receipts and localnet
runs used gpu-run's default 16 GiB. B9-ZK's 4 and 8 GiB runs stand.

Knobs added:

- `ZKMINER_SKIP_RISC0_RECEIPT_PREFLIGHT=1` skips the verifyProof `eth_call`.
- `ZKMINER_CONTRACTS_REPO=<path>` makes the repo pin cross-check test run.

Knobs kept: `ZKMINER_SKIP_CODE_PINS=1` and `ZKMINER_ALLOW_UNKNOWN_DEPLOYMENT=1`. The latter no longer
admits an abandoned stack.

## Files

- `crates/zkminer-chain/src/deployment.rs`: deployment, pins, abandoned refusal, 3.0 refusal,
  receipt preflight, tests.
- `src/binding.rs`: `proof_nonce` and its tests.
- `src/revert.rs`: classification test on the captured 8e1808b reverts.
- `tests/abi_pins.rs` (new), `tests/live_743111.rs` (new, ignored).
- `hemiprove-abi/`: 9 ABIs and `VENDORED_FROM.txt`.
- `README.md`: the risc0 3.1 verifier section, Configure, the localnet and examples notes.
- Outside the listed ownership, kept minimal and needed for the gates or the checklist:
  - `crates/zkminer-cli/tests/localnet.rs` (new fixture, fork block, 3.0 negative, payout check);
  - `crates/zkminer-cli/src/commands/run.rs` (risc0 seal pre-check; the watch-only warm-up gate);
  - `crates/zkminer-cli/src/commands/init.rs` and `crates/zkminer-config/src/config.rs` (comments);
  - `examples/testnet_submitter*.sh` (marked STALE).

## Open issues

1. **Cross-check against the repo.** Run `ZKMINER_CONTRACTS_REPO=<8e1808b checkout> cargo test -p
   zkminer-chain --lib the_pins_match_the_contracts_repo`. Then re-vendor `abi/*.abi.json`,
   `INTERACTION_GUIDE.md` and `CHANGELOG_ABI.md` from the repo (the ABIs should come out identical;
   the two .md files are still c8333aa). This needs GitHub access, which this host lacks.
2. The new core, facet and verifier pins are trust-on-first-use from 2026-11-17 until issue 1 is
   done. The deployer key still owns the stack until Day 1 (2026-11-18 10:13 UTC). Day 1 changes no
   code (governance only), so the pins should survive it; zkminer refuses anything else and pages.
3. Missing and not small:
   - the DA-size estimate (`GasPriceOracle.getL1GasUsed`) and the 131,072-B signed-size check;
   - `claimAndFulfillAssigned`;
   - `slashAndClaim` late rescue;
   - watching the timelock and Registry governance events;
   - the `gracePauseRelease` exit;
   - SP1 PLONK, nonce-marker and prefix-marker support.
4. No zk-miner guard stops a mac worker from running with `RISC0_METAL=0`,
   `RISC0_METAL_SKIP=groth16` or `RISC0_GROTH16_METAL_PROVER=docker`, which would route the wrap to
   Docker. Suggest: the Metal worker refuses to start (or its warm-up fails) when Groth16 would not
   be Metal (`crates/zkminer-prove-risc0`, not this item's).
5. `examples/testnet_submitter*.sh` target an abandoned stack and the old descriptor and id. They are
   marked STALE and not fixed.
6. The Foundry attestation was not verified (it needs an authenticated `gh attestation verify`). The
   asset's sha256 matches GitHub's published digest.
7. Handoff section 13 tests 17 and 18 were not scripted end to end, and test 19 (pause drill) needs
   the team. Tests 7, 8, 9 and 12 do not apply to this build.


## Contracts-repo verification (2026-11-17, after review)

With GitHub access restored, the pins and ABIs were checked against max-sanchez/hemi-prove-contracts @ 8e1808b (same files as hemilabs/hemiprove-contracts @ 3bc441d apart from LICENSE): `the_pins_match_the_contracts_repo` passes, each pin maps to its matching constant in ReleaseCorePins.sol / VerifierPins.sol, all 23 vendored ABI JSON files equal the repo's, and INTERACTION_GUIDE.md, CHANGELOG_ABI.md and README.md were re-vendored. The trust-on-first-use caveat above is closed.
