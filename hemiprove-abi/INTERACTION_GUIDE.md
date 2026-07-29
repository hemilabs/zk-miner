# HemiProve — Contract Interaction Guide

Self-contained reference for `zkui` (job-submission frontend/CLI) and `zkminer` (prover daemon) integrations.

**Target chain**: any EVM. Anvil (31337), Hemi testnet (743111), Hemi mainnet (43111).
**Solidity**: 0.8.28. **Proxy pattern**: UUPS + diamond-lite router. **Reentrancy guard**: shared TSTORE (Cancun).

---

## 1. Address layout after deployment

Every deploy produces these addresses (extract from `broadcast/DeployTestnet.s.sol/<chainId>/run-latest.json`):

| Symbol | What it is | Direct calls to it? |
|---|---|---|
| `HEMI_TOKEN` | ERC-20 payment token | yes (approve, balanceOf) |
| `REGISTRY` | Adapter registry (UUPS proxy) | reads only; owner setters via router |
| `STAKING` | Prover collateral vault (UUPS proxy) | **yes** — `stake`, `requestUnstake`, `withdrawUnstaked` |
| `HEMIPROVE` | **The router** (UUPS proxy) | **yes for everything else** |
| `PROGRAM_REGISTRY` | Advisory program hierarchy (UUPS proxy) | optional; not required for submit/fulfill |
| `BCC` | Batch cycle committee (UUPS proxy) | committee mode only |
| `RISC0_ADAPTER` / `SP1_ADAPTER` | Verifier adapters | read-only |
| `PROOF_RESULT_STORE` | Off-chain journal cache | read-only |

Facet impls (Core / Fulfill / FulfillCycle / Aux / AuxGov) exist but are **only** reachable via `HEMIPROVE` delegatecall. Never send tx to a facet impl directly.

---

## 2. The two lifecycles

### Prover onboarding (once per prover address)

```solidity
// 1. Acquire HEMI (faucet, mint, buy)
IERC20(HEMI_TOKEN).approve(STAKING, stakeAmount);

// 2. Stake
IHemiProveStaking(STAKING).stake(proverAddress, uint128(stakeAmount));

// 3. Wait MIN_STAKING_AGE = 1 hour real time
//    (unless anvil: cast rpc evm_increaseTime 3700; cast rpc evm_mine)
```

**Important**: `stake(prover, amount)` takes the prover address explicitly. Any account can call it, but `msg.sender` funds the tokens. In practice the prover self-stakes.

### Job lifecycle (per job)

```
caller: submitJob(descriptor, auction, cycle, bid) → jobId
prover: claimJob(jobId)   (locks collateral, sets deadline)
prover: fulfillJob(jobId, descriptor, publicValues, proof)
         → JobFulfilled + HEMI transfer to prover
```

Alternate exits: `slashAndReopen(jobId)` (any keeper, after deadline), `releaseJob(jobId)` (prover, voluntary), `cancelJob(jobId)` (caller only).

---

## 3. `submitJob` — the payload

Signature (Core facet, called via router):

```solidity
function submitJob(
    JobDescriptor calldata descriptor,
    AuctionConfig   calldata auction,
    CycleConfig     calldata cycle,
    CompetitiveBidConfig calldata bid
) external whenNotPaused nonReentrant returns (bytes32 jobId);
```

### `JobDescriptor` (8 fields — see `src/libraries/Types.sol`)

```solidity
struct JobDescriptor {
    bytes32 programId;         // e.g., RISC Zero imageId
    bytes32 proofSystemId;     // keccak256("risczero.v1") or keccak256("sp1.v1")
    address callbackContract;  // address(0) = no callback, else must implement IHemiProveCallback
    address assignedProver;    // address(0) = any prover; else only that address may claim
    bytes32 tag;               // arbitrary metadata (e.g., off-chain job hash)
    bytes   inputData;         // abi-encoded input for the callback (opaque to protocol)
    bytes   callbackExtraData; // extra bytes forwarded to callback
    bytes   extraVerifierData; // adapter-specific data (e.g., CUSTOM_VERIFIER address+ctor args)
}
```

Well-known `proofSystemId` constants (see `src/libraries/Constants.sol`):
- `RISC_ZERO_V1 = keccak256("risczero.v1")` = `0xe78e7460b61c60a2e4c61b929873b09e221b4c874388e613da921a41eaaeb602`
- `SP1_V1 = keccak256("sp1.v1")` = `0x138d8f8d44b49258e0776fa8268f760a61913d981da657b843ce72f9a9f40b74`
- `CUSTOM_VERIFIER = keccak256("CUSTOM")` — job-supplied verifier via `extraVerifierData`

### `AuctionConfig` (11 fields)

```solidity
struct AuctionConfig {
    uint96  minPrice;              // in HEMI wei; min == max means fixed price
    uint96  maxPrice;              // upper bound; must be >= minPrice
    uint40  rampUpPeriod;          // seconds from submit to full price
    uint8   curveType;             // 0=Linear, 1=Quadratic (setter cap; higher reverts)
    uint40  fulfillmentTimeout;    // seconds prover has after claim to submit proof
    uint96  lockCollateralBps;     // bps of settledPrice locked as prover collateral (0..50000 per governance)
    uint96  speedPremium;          // extra HEMI paid if fulfilled fast; deposited by caller
    uint40  exclusivityDuration;   // seconds only assignedProver may claim (0 if unassigned)
    uint32  callbackGasLimit;      // gas budget for callback (min 50k, max 5M per governance)
    bool    excludeFromEwma;       // caller opt-out of EWMA update (governance-only override)
    bool    laxCallbackMode;       // if true, callback OOG/revert doesn't slash prover
}
```

For a simple fixed-price test job: `minPrice == maxPrice`, `rampUpPeriod = 0`, `curveType = 0`, `fulfillmentTimeout = 3600`, everything else 0 or false. Deposit = `maxPrice + speedPremium`.

### `CycleConfig` (8 fields; all zero for "no cycles")

Used when the adapter reports actual cycle count and settlement uses it (RISC Zero's PoVW, custom verifiers). Leave zeroed for basic Groth16-only flows.

### `CompetitiveBidConfig` (5 fields; all zero for "no auction")

Enables Dutch-auction bidding where provers underbid each other. Leave zeroed for direct claim.

### Deposit accounting

At submit time, HemiProve pulls from `msg.sender`: `depositedAmount = maxPrice + speedPremium + cycleCollateral`. **Caller must have `approve`d the router first.**

Returns `bytes32 jobId = keccak256(caller, jobIndex, chainId)`. Grab it from the return value or from `event JobSubmitted(bytes32 indexed jobId, ...)`.

### FeeRateSnapshotted event

Emitted alongside `JobSubmitted`: `event FeeRateSnapshotted(bytes32 indexed jobId, uint16 feeRateBps)`. This is the **pinned** fee rate — the protocol fee at fulfill will always use this value, regardless of any governance changes between submit and fulfill (FIX-X13A2-F1 sandwich fix). Off-chain indexers should record it per-job.

---

## 4. `claimJob` — prover locks

```solidity
function claimJob(bytes32 jobId) external whenNotPaused nonReentrant;
```

- Reverts if job is not `Open`, or if `depositTimestamp + MIN_STAKING_AGE > block.timestamp` (1-hour maturity).
- Reverts if `descriptor.assignedProver != address(0) && msg.sender != assignedProver` during `exclusivityDuration`.
- Reverts if job's competitive bidding is active.
- Reverts if `job.reopenCount >= MAX_REOPEN_COUNT (10)` (M9 backstop).
- Locks `settledPrice * lockCollateralBps / 10000` from the prover's stake as `lockedCollateral`.
- Sets `lockDeadline = block.timestamp + fulfillmentTimeout` (post-ramp-up).
- Emits `JobClaimed(jobId, prover, operator, settledPrice, bonusAmount, lockDeadline)`.

`settledPrice` at claim time = whatever the auction curve says right now. For fixed-price (`min == max`) it's constant.

---

## 5. `fulfillJob` — settle with a proof

```solidity
function fulfillJob(
    bytes32 jobId,
    JobDescriptor calldata descriptor,   // MUST match the descriptor at submit (hash-checked)
    bytes calldata publicValues,          // the Groth16 journal / SP1 public values
    bytes calldata proofBytes             // the Groth16 seal
) external whenNotPaused nonReentrant;
```

Preconditions:
- Job status must be `Locked`.
- `msg.sender == job.prover`.
- `block.timestamp <= job.lockDeadline`.
- `keccak256(abi.encode(descriptor)) == job.descriptorHash` (submit-time snapshot).

The adapter is looked up by `descriptor.proofSystemId`, then adapter's `verify(publicValues, proofBytes, ProofContext{jobId, prover, ...})` is called. If verification fails, the tx reverts (prover keeps collateral but no payout; can retry within deadline).

Payout math (all in HEMI wei):
```
protocolFee    = settledPrice * feeRateSnap / 10000        // feeRateSnap pinned at submit
proverPayout   = settledPrice - protocolFee + speedBonus + cycleBonus
callerRefund   = depositedAmount - settledPrice - speedBonus - cycleFromDeposit + cycleRefund
// Conservation: proverPayout + callerRefund + protocolFee == deposit + bonus
```

Post-fulfill: `job.status = Fulfilled`, `lockedCollateral` released back to prover's `totalStaked`, protocol fee routed to `protocolFeeRecipient`, prover stats incremented, EWMA updated (unless `excludeFromEwma`).

Emits: `JobFulfilled(jobId, prover, caller, settledPrice, bonusAmount, proverPayout, callerRefund, protocolFee, speedBonus, actualCycles, publicValues)`.

### Callback (optional)

If `descriptor.callbackContract != address(0)`, HemiProve calls back to `IHemiProveCallback.handleProofResult(...)` with `callbackGasLimit`. Callback return semantics:
- Return `bool(true)` → acceptance, standard payout.
- Return `bool(false)`, revert, empty return → rejection. On the 4th rejection HemiProve **force-accepts** and pays out anyway (with a 50/50 split penalty on the rejecting caller). Non-canonical bool `uint256(2)` also treated as acceptance (assembly decode).

---

## 6. Slash / release / cancel

```solidity
// Any keeper, after job.lockDeadline + TIMESTAMP_SLACK expires
function slashAndReopen(bytes32 jobId) external whenNotPaused nonReentrant;

// Prover voluntarily gives up the lock (flat 5% penalty on lockedCollateral)
function releaseJob(bytes32 jobId) external nonReentrant;

// Caller only; refunds remaining deposit
function cancelJob(bytes32 jobId) external whenNotPaused nonReentrant;
```

Slash split: keeper gets `max(2% * slashedAmount, MIN_KEEPER_REWARD = 0.5 HEMI)`, ~65% burned, rest added to job's `bonusAmount` (paid to next successful prover).

`slashAndClaim(jobId)` is **atomic** slash + reclaim by the keeper themselves (they immediately claim the reopened slot). FIX-12 ensures the whole thing reverts if the claim fails.

Cancel: if job is `Locked` past deadline, `cancelJob` auto-slashes first, then defers cancellation to the caller for a follow-up call once slashed. If `reopenCount < MAX_REOPEN_COUNT`, an additional `MIN_REOPEN_CANCEL_DELAY = 24h` gate applies (bypassed once cap is hit).

---

## 7. Reading state

Common `view` calls (all on the router):

```solidity
function jobs(bytes32 jobId) external view returns (Job memory);   // 27 packed fields
function getJobStatusView(bytes32 jobId) external view returns (JobStatusView memory);
function nextJobIndex() external view returns (uint256);
function accumulatedProtocolFees() external view returns (uint256);
function priceHistories(bytes32 proofSystemId, bytes32 programId) external view returns (PriceHistory);
function suggestPriceRange(bytes32 proofSystemId, bytes32 programId) external view returns (uint96 min, uint96 max, bool stale);
```

`JobStatusView` is the recommended read for UIs — it unpacks the fields you actually need without the 27-tuple destructure.

On Staking:
```solidity
function getProverStake(address prover) external view returns (ProverStake memory);
function getProverStats(address prover) external view returns (ProverStats memory);
function totalStakedGlobal() external view returns (uint256);
```

---

## 8. Events for indexers

Priority events (fire on happy path):
- `JobSubmitted(jobId, proofSystemId, caller, programId, descriptorHash, depositedAmount, minPrice, maxPrice, fulfillmentTimeout, trust)`
- `FeeRateSnapshotted(jobId, feeRateBps)` — same tx as JobSubmitted
- `JobClaimed(jobId, prover, operator, settledPrice, bonusAmount, lockDeadline)`
- `JobFulfilled(jobId, prover, caller, settledPrice, bonusAmount, proverPayout, callerRefund, protocolFee, speedBonus, actualCycles, publicValues)`
- `PriceUpdated(proofSystemId, programId, settledPrice, newEwma, sampleCount)` — advisory

Fault events:
- `JobReopened(jobId, slashedProver, slashCaller, slashedAmount, keeperReward, burnedAmount, newBonusAmount, reopenCount, ...)`
- `JobReleased(jobId, prover, penaltyAmount, newBonusAmount, timeHeld, operator)`
- `JobCancelled(jobId, caller, refundAmount, bonusIncluded)`

All events are on the **router address**, not the facets. Filter by `HEMIPROVE`.

---

## 9. Gas budgets (session-measured, testnet expected)

| Op | Median gas | Max gas |
|---|---:|---:|
| `submitJob` | 287k | 352k |
| `claimJob` | 112k | 115k |
| `fulfillJob` (mock verifier) | ~365k | ~560k |
| `fulfillJob` (real Groth16) | ~530-630k | ~3.7M worst case |
| `slashAndReopen` | 195k | 233k |
| `releaseJob` | 147k | 169k |
| `cancelJob` | 57k | 206k |
| `submitJobBatch` @ MAX_BATCH_SIZE=10 | 234k/job | 2.34M total |

**Foundry gas-estimator caveat**: forge-script's estimator under-provisions the `fulfillJob` gas-preflight check (`gasleft() < CUSTOM_VERIFIER_GAS_LIMIT*2 + SETTLEMENT_GAS_BUFFER + 100k` ≈ 4.6M). Off-chain submitters MUST set explicit `gasLimit: 5_000_000` (or higher for verifier-heavy paths) on the fulfill tx.

---

## 10. Devnet quickstart

```bash
# Terminal 1
anvil --port 8545 --chain-id 31337 --block-time 1

# Terminal 2
cd <hemiprove-contracts-checkout>
FOUNDRY_PROFILE=deploy USE_MOCK_VERIFIERS=true forge script script/DeployTestnet.s.sol \
    --rpc-url http://localhost:8545 --broadcast \
    --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80

# Addresses in broadcast/DeployTestnet.s.sol/31337/run-latest.json
```

Full cycle in bash: see `docs/DEVNET.md`.

---

## 11. Testnet checklist (Hemi 743111)

- Deploy real `HEMI` token OR set `HEMI_TOKEN` env to a pre-existing testnet HEMI.
- Set `OWNER`, `PROTOCOL_FEE_RECIPIENT`, `BURN_DESTINATION` (revert-on-missing per FIX-4).
- Drop `USE_MOCK_VERIFIERS` — deploys real `RiscZeroGroth16Verifier` + `SP1VerifierGroth16` from `src/vendors/`.
- Chain-id guard (FIX-3) enforces `chainid == 743111 || 31337`.
- Post-deploy: transfer ownership to your operator wallet.
- Commit `.storage-layout/*.json` baselines to git so CI catches drift on future PRs.

---

## 12. Common pitfalls

- **Approving the wrong contract**: HEMI approve for `submitJob` goes to `HEMIPROVE` (router); HEMI approve for `stake` goes to `STAKING`. Two different `approve` calls needed.
- **Descriptor hash mismatch on fulfill**: pass the *exact same* descriptor struct at fulfill — any byte diff in `inputData` / `extraVerifierData` reverts. Cache it off-chain.
- **`MIN_STAKING_AGE = 1 hour`**: brand-new prover cannot claim for 1h after their first stake. Slash-to-zero + re-stake resets the timer.
- **`fulfillJob` gas**: see §9. Under-provisioned tx reverts with `InsufficientGasForFullSettlement()`.
- **Cycle collateral overflow**: `cycleCollateral + maxPrice + speedPremium` must fit in `uint96`. Very large jobs may need to be split.

---

*Generated 2026-07-07 after session close. Grade: A. Devnet-verified with real Groth16 proof. Ready for Hemi testnet 743111.*
