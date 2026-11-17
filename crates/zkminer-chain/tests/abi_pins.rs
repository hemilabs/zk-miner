//! Every selector, event topic and error selector zkminer's chain code can send or decode, recomputed
//! from the ABI JSON checked into `hemiprove-abi/` (regenerated for the 2026-11-16 deployment, contracts
//! repo `8e1808b`), plus the handoff's Appendix A and C tables (handoff 2026-11-16) against the same
//! JSON. A binding whose selector or topic is not in the deployed ABI fails here instead of reverting
//! (or decoding nothing) on the chain.

use alloy::json_abi::JsonAbi;
use alloy::primitives::{keccak256, B256};
use std::collections::BTreeSet;
use zkminer_contracts::bindings::{
    IHemiProveAux, IHemiProveCore, IHemiProveErrors, IHemiProveFulfill, IHemiProveRegistry,
    IHemiProveStaking, IProgramRegistry, IRiscZeroSelectable, ISP1NativeVerifier, ITestnetToken,
    IVerifierAdapter, IERC20,
};

fn abi(name: &str) -> JsonAbi {
    let path = format!("{}/../../hemiprove-abi/{name}", env!("CARGO_MANIFEST_DIR"));
    let s = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    serde_json::from_str(&s).unwrap_or_else(|e| panic!("parse {path}: {e}"))
}

/// The ABI's function, event and error selectors, each recomputed here as keccak256 of the
/// canonical signature the JSON describes (not read from anywhere else).
struct Sels {
    functions: BTreeSet<[u8; 4]>,
    events: BTreeSet<B256>,
    errors: BTreeSet<[u8; 4]>,
    names: Vec<([u8; 4], String)>,
}

fn sels(files: &[&str]) -> Sels {
    let mut s = Sels {
        functions: BTreeSet::new(),
        events: BTreeSet::new(),
        errors: BTreeSet::new(),
        names: Vec::new(),
    };
    for f in files {
        let a = abi(f);
        for func in a.functions() {
            let sig = func.signature();
            let sel: [u8; 4] = keccak256(sig.as_bytes())[..4].try_into().unwrap();
            assert_eq!(sel, func.selector().0, "{f}: {sig}");
            s.functions.insert(sel);
            s.names.push((sel, func.name.clone()));
        }
        for ev in a.events() {
            let topic = keccak256(ev.signature().as_bytes());
            assert_eq!(topic, ev.selector(), "{f}: {}", ev.signature());
            s.events.insert(topic);
        }
        for er in a.errors() {
            let sel: [u8; 4] = keccak256(er.signature().as_bytes())[..4]
                .try_into()
                .unwrap();
            s.errors.insert(sel);
            s.names.push((sel, er.name.clone()));
        }
    }
    s
}

fn hex4(s: &[u8; 4]) -> String {
    alloy::hex::encode(s)
}

fn assert_all_in<T: Ord + std::fmt::Debug>(what: &str, have: &[T], abi: &BTreeSet<T>) {
    let missing: Vec<&T> = have.iter().filter(|x| !abi.contains(x)).collect();
    assert!(
        missing.is_empty(),
        "{what}: not in the deployed ABI: {missing:?}"
    );
}

/// Every call, event and error of every binding zkminer-chain uses is in the ABI of the contract it
/// is sent to.
#[test]
fn every_binding_is_in_the_deployed_abi() {
    let router = sels(&["HemiProveRouter.abi.json"]);
    assert_all_in(
        "IHemiProveCore calls",
        IHemiProveCore::IHemiProveCoreCalls::SELECTORS,
        &router.functions,
    );
    assert_all_in(
        "IHemiProveCore events",
        IHemiProveCore::IHemiProveCoreEvents::SELECTORS
            .iter()
            .map(|b| B256::from(*b))
            .collect::<Vec<_>>()
            .as_slice(),
        &router.events,
    );
    assert_all_in(
        "IHemiProveFulfill calls",
        IHemiProveFulfill::IHemiProveFulfillCalls::SELECTORS,
        &router.functions,
    );
    assert_all_in(
        "IHemiProveFulfill events",
        IHemiProveFulfill::IHemiProveFulfillEvents::SELECTORS
            .iter()
            .map(|b| B256::from(*b))
            .collect::<Vec<_>>()
            .as_slice(),
        &router.events,
    );
    assert_all_in(
        "IHemiProveAux calls",
        IHemiProveAux::IHemiProveAuxCalls::SELECTORS,
        &router.functions,
    );
    // The errors a router call can revert with: its own and Staking's (bubbled from the stake lock).
    let mut revertable = router.errors.clone();
    revertable.extend(sels(&["HemiProveStaking.abi.json"]).errors);
    assert_all_in(
        "IHemiProveErrors",
        IHemiProveErrors::IHemiProveErrorsErrors::SELECTORS,
        &revertable,
    );

    let staking = sels(&["HemiProveStaking.abi.json"]);
    assert_all_in(
        "IHemiProveStaking calls",
        IHemiProveStaking::IHemiProveStakingCalls::SELECTORS,
        &staking.functions,
    );
    assert_all_in(
        "IHemiProveStaking events",
        IHemiProveStaking::IHemiProveStakingEvents::SELECTORS
            .iter()
            .map(|b| B256::from(*b))
            .collect::<Vec<_>>()
            .as_slice(),
        &staking.events,
    );

    let registry = sels(&["HemiProveRegistry.abi.json"]);
    assert_all_in(
        "IHemiProveRegistry calls",
        IHemiProveRegistry::IHemiProveRegistryCalls::SELECTORS,
        &registry.functions,
    );
    assert_all_in(
        "IHemiProveRegistry events",
        IHemiProveRegistry::IHemiProveRegistryEvents::SELECTORS
            .iter()
            .map(|b| B256::from(*b))
            .collect::<Vec<_>>()
            .as_slice(),
        &registry.events,
    );

    let programs = sels(&["ProgramRegistry.abi.json"]);
    assert_all_in(
        "IProgramRegistry calls",
        IProgramRegistry::IProgramRegistryCalls::SELECTORS,
        &programs.functions,
    );

    // Both deployed adapters of the proof systems zkminer serves.
    for f in [
        "RiscZeroGroth16VerifierAdapter.abi.json",
        "SP1Groth16VerifierAdapter.abi.json",
    ] {
        assert_all_in(
            f,
            IVerifierAdapter::IVerifierAdapterCalls::SELECTORS,
            &sels(&[f]).functions,
        );
    }
    // The native verifiers have no ABI in hemiprove-abi (the mocks lack these getters): the handoff's
    // Appendix A selectors, which are keccak256 of the signatures (recomputed here).
    for (sig, want) in [("SELECTOR()", "053c238d")] {
        assert_eq!(alloy::hex::encode(&keccak256(sig)[..4]), want, "{sig}");
        assert!(IRiscZeroSelectable::IRiscZeroSelectableCalls::SELECTORS
            .iter()
            .any(|s| hex4(s) == want));
    }
    for (sig, want) in [("VERIFIER_HASH()", "2a510436"), ("VERSION()", "ffa1ad74")] {
        assert_eq!(alloy::hex::encode(&keccak256(sig)[..4]), want, "{sig}");
        assert!(ISP1NativeVerifier::ISP1NativeVerifierCalls::SELECTORS
            .iter()
            .any(|s| hex4(s) == want));
    }
    let token = sels(&["MockERC20.abi.json"]);
    assert_all_in("IERC20", IERC20::IERC20Calls::SELECTORS, &token.functions);
    assert_all_in(
        "ITestnetToken",
        ITestnetToken::ITestnetTokenCalls::SELECTORS,
        &token.functions,
    );
}

/// The handoff's Appendix A (calls with selectors) and section 9 (errors), checked against the ABI:
/// each selector exists there under the name the handoff gives.
#[test]
fn the_handoffs_selector_tables_match_the_abi() {
    let router = sels(&["HemiProveRouter.abi.json"]);
    let staking = sels(&["HemiProveStaking.abi.json"]);
    let registry = sels(&["HemiProveRegistry.abi.json"]);
    let adapter = sels(&["RiscZeroGroth16VerifierAdapter.abi.json"]);
    let check = |s: &Sels, name: &str, sel: &str| {
        let want: [u8; 4] = alloy::hex::decode(sel).unwrap().try_into().unwrap();
        assert!(
            s.names.iter().any(|(x, n)| *x == want && n == name),
            "handoff {name} 0x{sel} is not in the ABI (ABI has {name} as {:?})",
            s.names
                .iter()
                .filter(|(_, n)| n == name)
                .map(|(x, _)| hex4(x))
                .collect::<Vec<_>>()
        );
    };
    for (name, sel) in [
        ("claimJob", "b2f51925"),
        ("claimJobDelegated", "363e6708"),
        ("claimJobBatch", "f100ca00"),
        ("claimAndFulfillAssigned", "ce6eda56"),
        ("fulfillJob", "f925a173"),
        ("fulfillJobHashed", "80f765f2"),
        ("fulfillJobBatch", "ae956f27"),
        ("releaseJob", "3268974c"),
        ("slashAndReopen", "69e249b2"),
        ("slashAndClaim", "5cb21b7e"),
        ("gracePauseRelease", "d15a988f"),
        ("graceRelease", "cb2cef2c"),
        ("graceReleaseWithDescriptor", "bc68cd4c"),
        ("submitBid", "1598b3af"),
        ("settleBid", "f7b5fd4b"),
        ("refundBid", "427163dc"),
        ("cancelJob", "5fae1450"),
        ("cancelJobBatch", "c61d3477"),
        ("cancelStaleJob", "14e79edf"),
        ("withdraw", "3ccfd60b"),
        ("multicall", "ac9650d8"),
        ("authorizeOperator", "f69d1702"),
        ("submitJob", "c773d0f8"),
        ("submitJobSimple", "6c6064e0"),
        ("submitJobDefault", "26abbec5"),
        ("submitJobBatch", "d820b15d"),
        ("getPremiumCap", "41b0a464"),
        ("getProofNonce", "8162527d"),
        ("getJobStatusView", "bc4971c6"),
        ("jobs", "38ed7cfc"),
        ("getJobExtras", "ec6eb4ec"),
        ("getJobSnapshots", "c06e305c"),
        ("previewSpeedBonus", "b9e3f446"),
        ("getCurrentPrice", "161e444e"),
        ("getBidState", "dc0b8385"),
        ("bidStates", "08acc217"),
        ("suggestPriceRange", "f80297c3"),
        ("clockOf", "093e7cea"),
        ("jobProofSystems", "52017a5b"),
        ("paused", "5c975abb"),
        ("isPendingSettlement", "21bd3a5a"),
        ("totalPaidToProvers", "81c61d70"),
        ("extendLocksForDowntime", "13b4e19a"),
        // Section 9 errors.
        ("EnforcedPause", "d93c0665"),
        ("NotReserved", "33529975"),
        ("JobNotOpen", "913b0f2e"),
        ("JobNotFound", "c182b72d"),
        ("MaxReopenCountReached", "767dde6d"),
        ("BiddingActive", "6626e9e0"),
        ("ReleaseCooldownActive", "71e53069"),
        ("AdapterDisabled", "00fee884"),
        ("AdapterNotActive", "a5d9e794"),
        ("RegistryPaused", "98179f9d"),
        ("BlacklistedVerifier", "5b0b12c4"),
        ("InsufficientStake", "2c4d60f4"),
        ("StakingBlockDelayNotMet", "27e761d2"),
        ("ExclusivityActive", "c8999ec4"),
        ("ClaimBelowFloor", "c8cea62a"),
        ("CollateralOverflow", "b52efcbc"),
        ("JobNotLocked", "cbf9359f"),
        ("NotJobProver", "06c503ca"),
        ("InvalidDescriptorHash", "892dccc4"),
        ("JournalTooLarge", "7617f2d9"),
        ("JournalPrefixMismatch", "912b2e79"),
        ("ProofNonceMismatch", "07f69e19"),
        ("JournalMismatch", "91d07f1e"),
        ("InsufficientGasForFullSettlement", "a95674c8"),
        ("VerifierCallFailed", "beee77b7"),
        ("InsufficientGasForSettlement", "3fe65886"),
        ("PendingSettlement", "81d44e54"),
        ("InvalidJournalBinding", "7725587f"),
        ("GracePauseDelayNotMet", "63f4a133"),
        ("JobExpiredBeforePause", "807791cf"),
    ] {
        check(&router, name, sel);
    }
    for (name, sel) in [
        ("stake", "19f8d5b4"),
        ("requestUnstake", "866be1e1"),
        ("cancelUnstake", "4ab17969"),
        ("withdrawUnstaked", "847fdd12"),
        ("getAvailableCollateral", "bb69bc71"),
        ("getProverStake", "f966de02"),
        ("lastProverActivityAt", "7d2882c4"),
        ("getProverStats", "a27d4363"),
        ("InsufficientFreeStake", "31ebd6fd"),
        ("PendingUnstakeConflict", "30aba57c"),
        ("UnstakeNotReady", "a7baf362"),
    ] {
        check(&staking, name, sel);
    }
    for (name, sel) in [
        ("getAdapter", "8272e138"),
        ("verifyProof", "d1140f23"),
        ("paused", "5c975abb"),
        ("isBlacklisted", "fe575a87"),
    ] {
        check(&registry, name, sel);
    }
    for (name, sel) in [
        ("verifyProof", "26012f8b"),
        ("nativeVerifier", "c0766e15"),
        ("name", "06fdde03"),
        ("version", "54fd4d50"),
    ] {
        check(&adapter, name, sel);
    }
}

/// The handoff's Appendix C topic0 values against the ABI's events (router, Registry, Staking).
#[test]
fn the_handoffs_event_topics_match_the_abi() {
    let all = sels(&[
        "HemiProveRouter.abi.json",
        "HemiProveRegistry.abi.json",
        "HemiProveStaking.abi.json",
        "GovernanceTimelock.abi.json",
    ]);
    for t in [
        "83de06bf8caab89fc798ea0f0b6a2bfb28a5c5dfe80823a65647257f79e056c4", // JobSubmitted
        "2a2076ef2997fcf3e18c875d9d6683de597cb3b55d2618a00ae8bdf82e0925d6", // FeeRateSnapshotted
        "bf66ab8560d6c673268edaa5f026552e18c9daae77671c60ec8a48b9124eacce", // JobClaimed
        "95b524b4340b3913501beb2eacce9adbd1d8e71c90e28d946242398f5108eba9", // JobFulfilled
        "0e1631d55dd343cd752f268eea06a770a214a6eaf6a964ff8c62928c65b06058", // JobReleased
        "b3f566b59599afea0fd4457a07f1016b3fc6fe8adbf6b1658623902300cce013", // JobReopened
        "a96b38c2858070b5eb59b3be21c9261ebf35b64c358634f372d7e2b1e17b4e88", // JobCancelled
        "65f0363d842e32b88958dae49d91e5c6b9879e5e5a53e2c3abf3cfd1ddaf3b69", // GracePauseReleased
        "3e6472c66deeb36058861de4d8f8a063ae88c0a67e9cc7635926b58fa7c934fe", // GraceReleased
        "26dd31e9da4fd4440349e9fdc0035e4bdb47f8bfea598736ea9c912bc3481861", // BidSubmitted
        "ed306c5ba4d03e47578fcf9c60fc0d30d7db546449ffef77df29d6297d3db7a5", // BidOutbid
        "9c4ff9a81ebb4c848f09ffeef24cd60ca059212de8be8929b834b73143a17a37", // BidSettled
        "66580e28a405d30f35de25ced868d414063f0acdefeee0301b3724a7faf92e1c", // BidInvalidated
        "5bbba0771213771d401f500f44abebf21d5e6ebf757b46e5b7d37bfb27966326", // CallbackFailed
        "2746af9b8767deb62448a737e1d245198643d69a32e4ecd4cfa98b642a318d2b", // PayoutCredited
        "fc76162e1785e8ff15f973877e05433f8cfcca9007f3ee4eb75ef5c4caae457a", // DeadlineExtended
        "09650061ad6409ba8b9e5f518a646a188d6e78eaa88e76309b25f6db158dc1bc", // DeadlineExtensionSkipped
        "bcb509fb90c1f44c4960c313a98f9ddf69851164e385d4f6014d9ca2147448bd", // PriceUpdated
        "62e78cea01bee320cd4e420270b5ea74000d11b0c9f74754ebdbfc544b05a258", // Paused
        "5db9ee0a495bf2e6ff9c91a7834c1ba4fdd244a5e8aa4e537bd38aeae4b073aa", // Unpaused
        "5c53b373468f58c1f41013435580c0c9094f7913b67d7d01e31348846a6fa250", // PauseClockSet
        "fba0d2decda885c7a86d561ee06d1713480fc8f6605ccbfb9ac0a1c76d6e4feb", // UnionClockSet
        "691740e60fe0b6990ef5806368c611c4883693b76a7f6e2d607642b936c1f0fb", // KeyClockSet
        "0f90bfe484b8325de512166fcc74cd0a81a8091f1583b3e41c42f088862b22bc", // GuardianEmergencyPaused
        "523c6fb0f9d698019e054d5298c06afd6c3bb1d0fc95cb7a143c76c0e83212c7", // AdapterDisabledEvent
        "b52e0162241016eaf503d3072ef90cbc134ccf8c8752c77dd3b749bc7bd00417", // AdapterReactivated
        "1c9253fa521fa0820e38d5573a20d4641eea44110b106acd7f2632d490ea3fe0", // AdapterDeprecatedEvent
        "84afcc6e44e253e434cd117417a5bb8a531472ad1eff36214ba20cc6eecbacf4", // AdapterUndeprecated
        "d0a6c4b5741cf081e7309ddc0ef50005b1f507b1bb0df255004a80a2c49d2da7", // AdapterRegistered
        "ebc2c2449c45feca1f5a58df6a21866b31ee407646ada6ae8d99e9486acdfdca", // VerifierSwitchProposed
        "b846e4f6fa5782d61ee6b347539ef2fd3c26519737f0b10a757edd9a9bbc486b", // VerifierBlacklisted
        "a116801e71e6d5e5c3104719e162b93a183f33192b5b557c3ba039b91764ecc0", // VerifierUnblacklisted
        "d574252a9a3e0695389b03fe1db43ebed53f96351bae0b745347e70d2a90aedf", // Staked
        "7a4dcebd452a49d8776b9371d6db59c8c3cdf115ea72e8ef3074f569ac3c19ee", // StakeReduced
        "66b845f815c6c12d9eb7218a0d51f8927cd95b6dee2cd82e1650473c9adb9c0b", // UnstakeRequested
        "cbb6c3e09e8f6e1911d5ec14534108c3107c00ecba117ebc32d735ddd6e67c29", // UnstakeCancelled
        "46a85bb068360778f28161eb8ac970939d29cc684f100323a8e5f120adc45ff1", // Withdrawn
        "92f23b0e7e2d96954631ddfc65c3ab771f6bf07744394129b84643fff11bf2d9", // ProverActivityMarked
        "e610c18aae915f6e0656674c3fa01124cd1ba3be0caf73399dd6891a75b17c95", // OperationProposed
        "eab8572377c094c845a96c340f2b1bed37f8830acfedd0c8132177fcdd6737d3", // RevokeGuardianProposed
    ] {
        let topic: B256 = format!("0x{t}").parse().unwrap();
        assert!(
            all.events.contains(&topic),
            "handoff topic0 {t} is not an event of the ABI"
        );
    }
}
