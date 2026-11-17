# ABI Changelog

## Initial release

This release is the first deployment of the HemiProve contracts. Its interface is the set of ABI files in this
directory (`scripts/gen-abi.sh` generates them from the deploy-profile build, and CI's `scripts/gen-abi.sh --check`
holds them to the commit; `README.md` maps each file to the contract address it belongs to). How to use that
interface is `INTERACTION_GUIDE.md`: submitting, claiming and fulfilling jobs, the events and views, and the rules for
callbacks, committee bots and indexers. The storage layouts of the upgradeable contracts are in `../.storage-layout/`.

## How changes are recorded

Every change of a deployed contract's interface or observable behaviour gets a dated entry in this file, newest
first, written when the change is made and before it is deployed:

- **Category.** 🔴 **breaking** (clients must rebuild: a selector, event, error, struct or enum changes, or a function
  keeps its signature but changes what it does), 🟡 **new** (additive and opt-in), ⚪ **no wire change** (gas,
  documentation, scripts and tooling).
- **What changed**, per contract: the functions, events and errors added, removed or changed, with their full
  signatures, and any change of meaning under an unchanged signature.
- **Enums.** The ABI files carry enums as `uint8`, so `scripts/gen-abi.sh --check` cannot see a member change. An
  entry spells out every enum member it adds, under the enum rule of `INTERACTION_GUIDE.md` §7 ("Router enums are
  append-only").
- **Storage, bytecode and pins**: the storage-layout change of each upgradeable contract, and the runtime pins that
  move (`../script/lib/ReleaseCorePins.sol`, `RELEASE_BCC_RUNTIME_KECCAK` and `RELEASE_RELAY_RUNTIME_KECCAK` in
  `../DEPLOY_RUNBOOK.md`, `../script/lib/VerifierPins.sol`).
- **Downstream impact**: what callers, provers, committee members, indexers and operators must do.

The procedures that make a change (`../DEPLOY_RUNBOOK.md`: "G5: ABI artifact regeneration & re-publish", "Router
upgrade and facet update", "Future upgrades of the BCC") end with the entry in this file.
