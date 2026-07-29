# ABI Changelog — 2026-07-07 vs. any prior Hemi testnet deploy

This document lists every **wire-format** change since the last time your indexer / frontend / prover daemon regenerated its ABIs. Read this before repointing at the new deploy. Anything not listed here has stable signatures.

Categories: 🔴 **breaking** (client rebuild required), 🟡 **new** (opt-in, additive), ⚪ **cosmetic** (documentation, gas).

---

## 🔴 Breaking

### `HemiProve.initialize` — 14 params → 15 params

Added `burnDestination` as the 15th positional arg (was previously deployed via a separate `setBurnDestination` call). Deploy scripts already handle this; frontend/indexer only relevant if they simulate initialize.

### `updateFacets` / `proposeUpdateFacets` — 6 args → 9 args

`extraImpls[]` and `extraSelectors[][]` added for FulfillCycle + AuxGov extra-facet support (HIGH-10 / HIGH-18). If your ops tooling calls these, regenerate the ABI.

### Struct field additions

Any indexer decoding these structs via a static ABI must rebuild:

| Struct | Old fields | New fields | Notes |
|---|---:|---:|---|
| `CycleConfig` | 5 | **8** | Adds `overshootBps`, `undershootPenaltyBps`, `resolverRewardBps` for tolerance-band saturation |
| `PendingCycleSettlement` | 8 | **11** | Adds cycle-committee fields |
| `AuctionConfig` | 10 | **11** | Adds `laxCallbackMode` (FIX-14; caller opts prover out of callback-OOG slashing) |

### `PrivateInputCallback.commitments` getter signature changed

Was: `commitments(bytes32 jobId) view returns (bytes32)`
Now: `commitments(bytes32 jobId, address submitter) view returns (bytes32)`

**Selector changes.** Anyone reading commitments must pass both keys. Store commit is now keyed on `msg.sender`, verify against `context.caller` at proof-check time. Closes mempool front-run DoS (FIX-8).

### `HemiProveFulfill.claimAndFulfillJob` and `submitAndFulfillJob` — **REMOVED**

The two atomic fastpath selectors are gone entirely (FIX-P1a-tail / Residual #2 delete path). Deploy scripts do not register them. Any tooling that called them must switch to the standard two-step flow:
- `submitJob` → `claimJob` → `fulfillJob`
- `submitJob` → `fulfillJobHashed` (if you want the hashed-descriptor gas optimization)

### `HemiProveRegistry.setEwmaExcluded` and `setMaxEwmaBootstrapPrice` — governance-only

Previously `excludeFromEwma` was a caller-supplied `AuctionConfig` field (HIGH-2). Now it's forced by governance via `setEwmaExcluded(bytes32 proofSystemId, bytes32 programId, bool excluded)`. Caller-set field is silently overwritten. Frontend: hide the checkbox.

### Removed events (5)

These were never actually emitted on any live deploy — pure ABI slimming. Safe to drop from event decoders:

- `JobBatchFulfilled`
- `BatchSettlementFailed`
- `GraceBidReleased`
- `CycleCommitExceeded`
- `OperatorCapBelowLocked`

**Kept for ABI compat**: `SlashClaimFulfillPartialRevert` (retained per FIX-12 memo; no longer emitted but signature preserved).

### Removed custom errors (12)

Pure ABI slimming; none were reachable. Drop from selector→error-name decoder tables:

- `InsufficientCollateral`, `InvalidBidConfig`, `MixedProofSystems`, `CustomVerifierCannotBatch`
- `DelegatedReleaseLimitExceeded`, `DelegatedReleaseTotalLimitExceeded`
- `SignatureExpired`, `OperatorFrozen`, `NotPaused`
- `CycleCollateralTooSmall`, `InvalidCycleAttestationMode`, `InvalidParameterBounds`

### Removed staking APIs

`stakeForDelegated` and `requestUnstakeDelegated` on `HemiProveStaking` were dead code and are gone. Prover self-staking only. Selectors will 404.

### `deprecateAdapter` signature

Now requires **two** args: `deprecateAdapter(bytes32 proofSystemId, bytes32 successorId)`. Old single-arg version reverts.

### `rescueBalance` semantics

New requirement: `to == from`. Rescue can only send balance back to the address that owns it. `rescueBalance(to, otherAddr)` reverts with `"to must equal from"`.

---

## 🟡 New (additive; safe to ignore initially)

### `event FeeRateSnapshotted(bytes32 indexed jobId, uint16 feeRateBps)`

Emitted in the same tx as `JobSubmitted`. Pin this per-jobId for accurate fee accounting off-chain — the protocol fee at fulfill will use *this* rate, not the current `Registry.feeRateBps` (FIX-X13A2-F1 sandwich fix). Indexers should join `JobSubmitted` and `FeeRateSnapshotted` on `jobId`.

### `_effectiveFeeRateBpsAt(bytes32 jobId, bytes32 proofSystemId)` — internal view helper

Not called externally, but if you build a future atomic facet, use this helper (in `HemiProveBase`) instead of re-implementing the snapshot decode. Prevents regression on the sandwich fix.

### Governance timelock introduced for these setters

The following setters now go through a 48h `TimelockController`-style propose/execute flow (FIX-15b), so calling them directly reverts unless the timelock has already scheduled the change:

- `HemiProveStaking.setAuthorizedHemiProve`
- Registry / BCC / ProgramRegistry UUPS `upgradeToAndCall`
- `HemiProveAuxGov.setBatchCycleCommittee`

Off-chain must submit via `proposeXxx` then wait 48h then `finalizeXxx`. Ownership-transfer scripts document this in `DEPLOY_RUNBOOK.md`.

### New `HemiProveAuxGov` selectors

R2-FIX-1 added two selectors to bring AuxGov from 28 to 30 selectors:
- `setEwmaExcluded(bytes32 proofSystemId, bytes32 programId, bool excluded)`
- `setMaxEwmaBootstrapPrice(uint96 maxPrice)`

### `getEffectiveFeeRateBps(bytes32 jobId, bytes32 proofSystemId)` — public equivalent

Not added yet; if you need the snapshot fee off-chain, decode from `FeeRateSnapshotted` event.

### Job field: `_releasePenaltyBpsAtSubmit[jobId]` and `_feeRateBpsAtSubmit[jobId]`

Both are `internal` mappings with `+1` offset encoding (slot 0 = pre-fix job, fall back to live rate). Not directly readable but the derived event (`FeeRateSnapshotted`) exposes the value.

---

## ⚪ Cosmetic / behavioral

### `_forfeitBid` now bumps `reopenCount`, stamps `lastReopenTimestamp`, resets `competitiveBidStartTime[jobId]`

Off-chain grief-detection heuristics that track "auction restart via forfeit" now see `reopenCount++` for every forfeit. Bounded by `MAX_REOPEN_COUNT = 10` per M9. Fresh side-effect: cancelJob's `MIN_REOPEN_CANCEL_DELAY = 24h` clock now applies to forfeit cycles too (capped at 9×24h = 216h before the cap-bypass kicks in and cancel goes through immediately).

### `HemiProveStaking.applyReleasePenalty` / `forfeitCollateral` / `distributeSlash` now `nonReentrant`

Defense-in-depth. Dormant against current hookless HEMI ERC20; only observable if a future ERC777-style token migration or malicious `burnDestination` calls back into Staking. No behavior change on happy path.

### EWMA warmup (samples #2-#5 use 150% ceiling instead of 400%)

Reduces early-lifecycle price ratchet. Advisory only (`suggestPriceRange` view). Any indexer that recomputes EWMA off-chain needs to mirror the `sampleCount < EWMA_WARMUP_SAMPLES (5)` branch.

### `gracePauseRelease` now uses MIN of pause timestamps when both paused

Previously used MAX (later timestamp). Now uses MIN (earlier). Effect: countdown to release can only advance, never regress, when both registry and local pause are active. Off-chain callers computing "when can I gracePauseRelease" should switch to `min(registry.pauseTimestamp(), hemiProve.localPauseTimestamp())`.

### ProgramRegistry: 3 non-paginated getters removed

- `getProgramVersions(bytes32 programKey)` — use `getProgramVersionsPaginated(programKey, 0, type(uint256).max)`
- `getVersionImages(bytes32 versionId)` — use `getVersionImagesPaginated(...)`
- `getApplicationPrograms(bytes32 applicationId)` — use `getApplicationProgramsPaginated(...)`

Also removed: `getEffectiveIOSchemaHash(imageId, kind)` — compute `keccak256(getEffectiveIOSchema(imageId, kind))` client-side.

### ProgramRegistry: 10 `public constant` → `internal constant` (auto-getters removed)

`MAX_NAME_LENGTH`, `MAX_DESCRIPTION_LENGTH`, `MAX_SCHEMA_URI_LENGTH`, `MAX_URI_LENGTH`, `MAX_SCHEMA_SIZE`, `SCHEMA_KIND_INPUT`, `MAX_BATCH_SIZE`, `MIN_COMMIT_BOND`, `COMMIT_REVEAL_DELAY`, `COMMIT_EXPIRY`.

Kept public: `MAX_URIS_PER_PROGRAM`, `MAX_REGISTRATION_FEE`. Frontend should hardcode the removed values from source (they haven't changed) or query them one-time from a source snapshot.

### Deploy profile metadata strip

`FOUNDRY_PROFILE=deploy` sets `bytecode_hash = "none"` and `cbor_metadata = false`. Runtime bytecode is ~53 bytes shorter but Etherscan / Sourcify auto-verification degrades to partial match. Manual source verification (upload flattened source + settings) still works.

### `ProgramRegistryHelpers` external library added

New standalone library at 945 B. `ProgramRegistry` DELEGATECALLs into it for `injectEncodingMode` + `paginateMemory`. Deploy scripts auto-link via Forge's `new X()` pattern. If you deploy `ProgramRegistry` via raw bytecode blob (bypassing Forge's linker), you MUST manually patch the `__$hash$__` placeholder — Z1A9 finding.

---

## Not changed (stable signatures — no rebuild needed)

- `submitJob(descriptor, auction, cycle, bid) → bytes32`
- `claimJob(bytes32)`
- `fulfillJob(bytes32, descriptor, publicValues, proof)`
- `fulfillJobHashed(bytes32, hashedDesc, callbackExtraData, extraVerifierData, publicValues, proof)`
- `slashAndReopen(bytes32)`, `slashAndClaim(bytes32)`, `releaseJob(bytes32)`, `cancelJob(bytes32)`
- `stake(prover, uint128)`, `requestUnstake(uint128)`, `withdrawUnstaked()`
- `getProverStake(address)`, `getProverStats(address)`
- All `AdapterEntry` fields unchanged
- All `BidState`, `ProverStake`, `ProverStats` field orderings preserved
- `Job` struct still 27 packed fields across 8 storage slots — critical for storage-layout upgrade safety

---

## Recommended off-chain rebuild checklist

1. **Regenerate ABIs** from the JSON files in this `/abi/` directory. Merge the 5 facet ABIs into a single "router ABI" attached to the `HEMIPROVE` address (see `HemiProveRouter.abi.json`).
2. **Update struct decoders** for `CycleConfig`, `PendingCycleSettlement`, `AuctionConfig` (5→8, 8→11, 10→11 fields respectively).
3. **Add `FeeRateSnapshotted` handler** to the event pipeline; join with `JobSubmitted` on jobId.
4. **Remove decoders** for the 5 removed events + 12 removed errors (safe; they never fired).
5. **Update `deprecateAdapter` calls** to the 2-arg form.
6. **Update `rescueBalance` calls** to `to == from`.
7. **Remove any `claimAndFulfillJob` / `submitAndFulfillJob` calls** — switch to the standard 3-step flow.
8. **Skip `stakeForDelegated` / `requestUnstakeDelegated`** — provers self-stake only.
9. **Set explicit `gasLimit >= 5_000_000` on all `fulfillJob` transactions** — see INTERACTION_GUIDE.md §9.
10. **Cache the descriptor struct** at submit time; pass the *identical* struct at fulfill time (hash-checked).

---

*Generated 2026-07-07 after session close. Live devnet cycles verified with real Groth16 proof. See MEMORY.md and SESSION_HANDOFF.md for full session history.*
