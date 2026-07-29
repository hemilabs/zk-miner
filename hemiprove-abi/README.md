# HemiProve ABIs — v2026-07-07

Generated from `FOUNDRY_PROFILE=deploy forge build` after all P0/P1/P1a/P1a-tail/P1b fixes shipped this session. Test suite: 4243/4243 green.

## Files

| ABI | For | Notes |
|---|---|---|
| `HemiProveRouter.abi.json` | **`HemiProve` proxy address** — the router | Union of all 5 facet ABIs + router internals. **Use this** for any call to the deployed HemiProve proxy. |
| `HemiProve.abi.json` | Router-only surface | Just `initialize`, `updateFacets`, `pause`, `unpause`, `owner`, etc. |
| `HemiProveCore.abi.json` | Core facet (delegatecalled) | `submitJob`, `submitJobBatch`, `claimJob`, `topUpDeposit`, `withdraw`. Never call the impl address directly. |
| `HemiProveFulfill.abi.json` | Fulfill facet | `fulfillJob`, `fulfillJobHashed`, `releaseJob`, `slashAndReopen`, `slashAndClaim`. |
| `HemiProveFulfillCycle.abi.json` | FulfillCycle facet | Cycle-mode settlement + committee resolution. |
| `HemiProveAux.abi.json` | Aux facet | Bidding, delegation, cancel, grace release, view helpers. |
| `HemiProveAuxGov.abi.json` | AuxGov facet | 30 owner-only setters. |
| `HemiProveStaking.abi.json` | **`HemiProveStaking` proxy** | `stake`, `requestUnstake`, `withdrawUnstaked`, `getProverStake`, `getProverStats`. |
| `HemiProveRegistry.abi.json` | **`HemiProveRegistry` proxy** | Adapter registry (`getAdapter`, `isBlacklisted`, pause, `minFeeRateBps`). |
| `ProgramRegistry.abi.json` | **`ProgramRegistry` proxy** | Advisory program hierarchy (V5). |
| `BatchCycleCommittee.abi.json` | **`BatchCycleCommittee` proxy** | Committee-mode cycle attestation. |
| `RiscZeroVerifierAdapter.abi.json` | Deployed adapter contract | Reads: `proofSystemId`, `nativeVerifier`. |
| `SP1VerifierAdapter.abi.json` | Deployed adapter contract | Same. |
| `ProofResultStore.abi.json` | Off-chain proof result cache | `getVerifiedResult(jobId)`. |
| `MockERC20.abi.json` | Test HEMI token | `mint`, `approve`, `balanceOf` — testnet only. |
| `MockRiscZeroVerifier.abi.json` / `MockSP1Verifier.abi.json` | Mock verifiers | Accepts any proof bytes. Devnet only. |
| `IHemiProveCallback.abi.json` | Interface consumers implement | Single-selector interface for consumer contracts. |
| `HashChainConsumer.abi.json` | Reference consumer contract | See `src/demo/HashChainConsumer.sol`. |

## What "the router" means

`HemiProve` is a diamond-lite router at a single stable address. It holds all storage and `delegatecall`s to 5 facet impls based on selector. You **always** send transactions to the router address — never to a facet impl. The merged `HemiProveRouter.abi.json` is what your web3 client should attach to that address.

## See also

- `INTERACTION_GUIDE.md` — end-to-end walkthrough of submit → claim → fulfill
- `CHANGELOG_ABI.md` — what changed vs. any prior testnet deploy
