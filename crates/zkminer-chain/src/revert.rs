//! Typed classification of HemiProve reverts (handoff §9).
//!
//! The router names every failure with a typed custom error, so the 4-byte selector — not the
//! message text — is the signal. Each class drives a different action, and getting it wrong costs
//! stake: releasing on a pause or a gas shortfall pays the 5% penalty for nothing (the clock is
//! credited during a pause) and, after a reverted fulfil has already published our unbound seal,
//! reopens the job for anyone to settle with OUR proof; keeping a lock whose proof is defective
//! instead walks it into a 100% slash.

use alloy::primitives::{Bytes, U256};
use alloy::sol_types::{Panic, Revert, SolError, SolInterface};
use zkminer_contracts::bindings::IHemiProveErrors::IHemiProveErrorsErrors as E;

/// A decoded revert payload.
#[derive(Debug)]
pub enum Decoded {
    /// A HemiProve / Staking custom error.
    Hemi(E),
    /// `Panic(uint256)` — code 0x01 on a claim means free stake is below the job's collateral.
    Panic(U256),
    /// `Error(string)` — the router's `require` messages ("Past deadline", "At or past deadline",
    /// "Not expired yet", "Unknown selector").
    Message(String),
    /// A 4-byte selector we do not know.
    Unknown([u8; 4]),
    /// A revert with no data (e.g. an SP1 verifier fed a too-short seal, or OOG).
    Empty,
}

/// Decode raw revert data.
pub fn decode(data: &[u8]) -> Decoded {
    if data.is_empty() {
        return Decoded::Empty;
    }
    if let Ok(e) = E::abi_decode(data) {
        return Decoded::Hemi(e);
    }
    if data.len() >= 4 && data[..4] == Panic::SELECTOR {
        if let Ok(p) = Panic::abi_decode(data) {
            return Decoded::Panic(p.code);
        }
    }
    if data.len() >= 4 && data[..4] == Revert::SELECTOR {
        if let Ok(r) = Revert::abi_decode(data) {
            return Decoded::Message(r.reason);
        }
    }
    let mut sel = [0u8; 4];
    let n = data.len().min(4);
    sel[..n].copy_from_slice(&data[..n]);
    Decoded::Unknown(sel)
}

/// Revert data carried by an alloy contract error (an `eth_call` or a send rejected by a
/// preflighting node), when the node reported an execution revert.
pub fn revert_data_of(e: &alloy::contract::Error) -> Option<Bytes> {
    e.as_revert_data()
}

impl Decoded {
    /// Short, log-safe name (no submitter-controlled text beyond a bounded `Error(string)`).
    pub fn name(&self) -> String {
        match self {
            Decoded::Hemi(e) => format!("{e:?}")
                .split(['(', ' ', '{'])
                .next()
                .unwrap_or("HemiError")
                .to_string(),
            Decoded::Panic(c) => format!("Panic(0x{c:x})"),
            Decoded::Message(m) => {
                format!("Error(\"{}\")", crate::programs::sanitize_log(m))
            }
            Decoded::Unknown(s) => format!("unknown selector 0x{}", alloy::hex::encode(s)),
            Decoded::Empty => "revert without data".to_string(),
        }
    }
}

/// What a failed (or pre-checked) CLAIM means for the job — handoff §9 claim table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimClass {
    /// The router or the job's Registry is paused: claim nothing now; the job stays a candidate.
    Paused,
    /// Temporarily unclaimable for this job: the price/premium fell below our floor
    /// (`ClaimBelowFloor`), a live bid, our own release cooldown, a not-yet-elapsed staking block
    /// delay, an exclusivity window, or a Disabled adapter. Retry later; NEVER lower the floor.
    Wait,
    /// Our free stake cannot cover the job's collateral (`Panic(0x01)`, `PendingUnstakeConflict`,
    /// `InsufficientStake`): stop claiming until a settlement frees stake.
    StakeShort,
    /// Permanently unclaimable by us: not Open, gone, at 10 reopens, an unregistered adapter, not
    /// reserved to us, a collateral overflow. Drop the job.
    Gone,
    /// Anything else (incl. a revert without data): skip this job for now and alert.
    Unknown,
}

/// Classify a claim revert (`claimJob` quote or a mined/sent `claimJob`).
pub fn classify_claim(d: &Decoded) -> ClaimClass {
    match d {
        Decoded::Hemi(e) => match e {
            E::EnforcedPause(_) | E::RegistryPaused(_) => ClaimClass::Paused,
            // `JobNotFound` fires only for a job with no descriptor hash (status checks come first), and
            // we only ever claim a job we SAW submitted: this is a replica behind the submit block.
            E::JobNotFound(_)
            | E::ClaimBelowFloor(_)
            | E::BiddingActive(_)
            | E::CompetitiveBiddingActive(_)
            | E::ReleaseCooldownActive(_)
            | E::StakingBlockDelayNotMet(_)
            | E::ExclusivityActive(_)
            | E::AdapterDisabled(_)
            | E::DelegatedClaimCooldownActive(_) => ClaimClass::Wait,
            E::InsufficientStake(_)
            | E::PendingUnstakeConflict(_)
            | E::InsufficientFreeStake(_)
            | E::OperatorCollateralCapExceeded(_) => ClaimClass::StakeShort,
            E::JobNotOpen(_)
            | E::MaxReopenCountReached(_)
            | E::AdapterNotActive(_)
            | E::NotReserved(_)
            | E::CollateralOverflow(_)
            | E::JobAlreadyTerminal(_)
            | E::BlacklistedVerifier(_)
            | E::CustomVerifierHasNoCode(_)
            | E::NotAuthorizedOperator(_) => ClaimClass::Gone,
            _ => ClaimClass::Unknown,
        },
        // Panic(0x01) is the staking contract's free-stake assert.
        Decoded::Panic(code) if *code == U256::from(1u8) => ClaimClass::StakeShort,
        // "Unknown selector": the router does not route this call (a stale binding).
        _ => ClaimClass::Unknown,
    }
}

/// What a failed FULFIL (or release) means for the lock — handoff §9 "What to do about a fulfil
/// revert". The order of the variants is the order of the actions' severity, not of the router's
/// checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FulfilClass {
    /// Our proof (or our descriptor copy) is defective: `JournalMismatch`, `JournalTooLarge`,
    /// `InvalidDescriptorHash`, `JournalPrefixMismatch`, `ProofNonceMismatch`. Fix it if we can
    /// before D+G, else release (5% beats a 100% slash).
    ProofDefect,
    /// `VerifierCallFailed`: release ONLY if neither `Registry.paused()` nor a non-Active adapter
    /// status explains it (re-read at the same block); otherwise keep.
    VerifierFailed,
    /// A temporary protocol state — a router/Registry pause, a Disabled adapter, a blacklisted
    /// verifier, a pending settlement, a grace-exit hint: KEEP the lock (time is credited while the
    /// state lasts) and retry after the lift. Never release on these.
    Keep,
    /// `InsufficientGasForFullSettlement` / `InsufficientGasForSettlement`: resend with more gas.
    Gas,
    /// The lock is no longer ours / the job is settled (`JobNotLocked`, `NotJobProver`,
    /// `JobNotFound`, `JobAlreadyTerminal`): stop publishing; re-read the job.
    Stale,
    /// "Past deadline" / "At or past deadline": past D+G. Never resend — a late fulfil only
    /// publishes the proof.
    Late,
    /// No classifiable revert (unknown selector, a revert without data, or a transport error):
    /// keep the lock and alert; never release on it alone.
    Unknown,
}

/// Classify a fulfil / release revert.
pub fn classify_fulfil(d: &Decoded) -> FulfilClass {
    match d {
        Decoded::Hemi(e) => match e {
            E::JournalMismatch(_)
            | E::JournalTooLarge(_)
            | E::InvalidDescriptorHash(_)
            | E::JournalPrefixMismatch(_)
            | E::ProofNonceMismatch(_) => FulfilClass::ProofDefect,
            E::VerifierCallFailed(_) => FulfilClass::VerifierFailed,
            E::EnforcedPause(_)
            | E::RegistryPaused(_)
            | E::AdapterDisabled(_)
            | E::BlacklistedVerifier(_)
            | E::PendingSettlement(_)
            | E::UseGraceRelease(_)
            | E::UseGraceReleaseWithDescriptor(_)
            | E::RegistryPausedUseGracePauseRelease(_)
            | E::SystemPausedUseGracePauseRelease(_)
            | E::JobExpiredBeforePause(_)
            | E::ReentrancyGuardReentrantCall(_) => FulfilClass::Keep,
            E::InsufficientGasForFullSettlement(_) | E::InsufficientGasForSettlement(_) => {
                FulfilClass::Gas
            }
            E::JobNotLocked(_) | E::NotJobProver(_) | E::JobNotFound(_) | E::JobAlreadyTerminal(_) => {
                FulfilClass::Stale
            }
            _ => FulfilClass::Unknown,
        },
        Decoded::Message(m) if is_late_message(m) => FulfilClass::Late,
        _ => FulfilClass::Unknown,
    }
}

/// The router's past-the-window `require` messages (fulfil: "Past deadline"; release: "At or past
/// deadline").
pub fn is_late_message(m: &str) -> bool {
    m == "Past deadline" || m == "At or past deadline"
}

/// A claim that did not lock, with its typed class. Carried inside `anyhow::Error` so existing
/// `Result` plumbing is unchanged; callers `downcast_ref::<ClaimFailure>()` to act on the class.
#[derive(Debug, Clone)]
pub struct ClaimFailure {
    pub class: ClaimClass,
    /// Log-safe description (decoded error name or a sanitized message).
    pub reason: String,
    /// True when the failure is AUTHORITATIVE that no lock of ours exists — set only once an
    /// ownership read pinned at or after [`Self::block`] confirmed it (a refusal alone never proves
    /// it: `JobNotOpen` / `EnforcedPause` do not say who holds the job, and an earlier broadcast of
    /// ours may have locked it). False for ambiguous failures — those keep the claim breadcrumb so
    /// the lifecycle can check ownership on-chain.
    pub definitely_not_locked: bool,
    /// The mined block the refusal was evaluated at (the quote's block, or a mined revert's), when
    /// known: an ownership re-read must be pinned at or after it.
    pub block: Option<u64>,
}

impl std::fmt::Display for ClaimFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "claim refused ({:?}): {}", self.class, self.reason)
    }
}
impl std::error::Error for ClaimFailure {}

/// A claim attempt that failed BEFORE anything was broadcast (a quote read, a nonce reservation, an
/// exhausted fee cap on the first send): no tx exists and nothing is known about the job. Temporary:
/// drop the fresh breadcrumb and retry the job after a back-off.
#[derive(Debug, Clone)]
pub struct ClaimNotSent(pub String);

impl std::fmt::Display for ClaimNotSent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "claim not sent: {}", self.0)
    }
}
impl std::error::Error for ClaimNotSent {}

/// A fulfil that did not settle, with its typed class (see [`ClaimFailure`] for the pattern).
#[derive(Debug, Clone)]
pub struct FulfilFailure {
    pub class: FulfilClass,
    /// The decoded error's name (e.g. "JournalMismatch") when the revert data decoded to a typed
    /// HemiProve error, else empty. Lets a caller act on ONE error within a class.
    pub error_name: String,
    pub reason: String,
    /// True if the fulfil calldata (our seal + journal) has been PUBLISHED — a send reached the
    /// mempool or a tx mined. A release after a published, unbound seal reopens the job for anyone to
    /// settle with our proof, so the lifecycle weighs this before releasing.
    pub published: bool,
}

impl std::fmt::Display for FulfilFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "fulfil failed ({:?}): {}", self.class, self.reason)
    }
}
impl std::error::Error for FulfilFailure {}

#[cfg(test)]
mod tests {
    use super::*;
    use zkminer_contracts::bindings::IHemiProveErrors as H;

    fn enc<T: SolError>(e: T) -> Vec<u8> {
        e.abi_encode()
    }

    #[test]
    fn claim_reverts_classify_per_the_handoff_table() {
        let b = alloy::primitives::B256::ZERO;
        let a = alloy::primitives::Address::ZERO;
        let c = |d: Vec<u8>| classify_claim(&decode(&d));
        assert_eq!(c(enc(H::EnforcedPause {})), ClaimClass::Paused);
        assert_eq!(c(enc(H::RegistryPaused { jobId: b })), ClaimClass::Paused);
        assert_eq!(
            c(enc(H::ClaimBelowFloor {
                jobId: b,
                price: Default::default(),
                priceFloor: Default::default(),
                premiumCap: U256::ZERO,
                premiumFloor: Default::default()
            })),
            ClaimClass::Wait
        );
        assert_eq!(c(enc(H::BiddingActive { jobId: b })), ClaimClass::Wait);
        assert_eq!(
            c(enc(H::ReleaseCooldownActive { jobId: b, prover: a, cooldownEnd: U256::ZERO })),
            ClaimClass::Wait
        );
        assert_eq!(
            c(enc(H::StakingBlockDelayNotMet { prover: a, depositBlock: Default::default() })),
            ClaimClass::Wait
        );
        assert_eq!(c(enc(H::JobNotOpen { jobId: b })), ClaimClass::Gone);
        assert_eq!(
            c(enc(H::MaxReopenCountReached { jobId: b, reopenCount: 10 })),
            ClaimClass::Gone
        );
        assert_eq!(c(enc(H::PendingUnstakeConflict { prover: a })), ClaimClass::StakeShort);
        // Panic(0x01) is a stake shortfall (acceptance test 14), not a crash.
        let panic1 = Panic { code: U256::from(1u8) }.abi_encode();
        assert_eq!(c(panic1), ClaimClass::StakeShort);
        // An unrouted selector ("Unknown selector") is not a known class.
        let unknown = Revert { reason: "Unknown selector".into() }.abi_encode();
        assert_eq!(c(unknown), ClaimClass::Unknown);
        assert_eq!(c(vec![]), ClaimClass::Unknown);
    }

    #[test]
    fn fulfil_reverts_classify_per_the_handoff_table() {
        let b = alloy::primitives::B256::ZERO;
        let a = alloy::primitives::Address::ZERO;
        let f = |d: Vec<u8>| classify_fulfil(&decode(&d));
        assert_eq!(f(enc(H::JournalMismatch { expected: b, actual: b })), FulfilClass::ProofDefect);
        assert_eq!(
            f(enc(H::InvalidDescriptorHash { expected: b, actual: b })),
            FulfilClass::ProofDefect
        );
        assert_eq!(
            f(enc(H::JournalPrefixMismatch { jobId: b, prover: a })),
            FulfilClass::ProofDefect
        );
        assert_eq!(f(enc(H::VerifierCallFailed {})), FulfilClass::VerifierFailed);
        // A pause / disable / pending settlement is KEEP — never a release (handoff §9, §11).
        assert_eq!(f(enc(H::EnforcedPause {})), FulfilClass::Keep);
        assert_eq!(f(enc(H::RegistryPaused { jobId: b })), FulfilClass::Keep);
        assert_eq!(f(enc(H::AdapterDisabled { proofSystemId: b })), FulfilClass::Keep);
        assert_eq!(f(enc(H::PendingSettlement { jobId: b })), FulfilClass::Keep);
        assert_eq!(f(enc(H::InsufficientGasForFullSettlement {})), FulfilClass::Gas);
        assert_eq!(f(enc(H::JobNotLocked { jobId: b })), FulfilClass::Stale);
        assert_eq!(f(enc(H::NotJobProver { jobId: b, prover: a })), FulfilClass::Stale);
        let late = Revert { reason: "Past deadline".into() }.abi_encode();
        assert_eq!(f(late), FulfilClass::Late);
        let late_release = Revert { reason: "At or past deadline".into() }.abi_encode();
        assert_eq!(f(late_release), FulfilClass::Late);
        // No data / an unknown selector is never a release reason.
        assert_eq!(f(vec![]), FulfilClass::Unknown);
        assert_eq!(f(vec![0xde, 0xad, 0xbe, 0xef]), FulfilClass::Unknown);
    }

    #[test]
    fn typed_failures_downcast_through_anyhow() {
        let e: anyhow::Error = ClaimFailure {
            class: ClaimClass::Wait,
            reason: "ClaimBelowFloor".into(),
            definitely_not_locked: true,
            block: None,
        }
        .into();
        assert_eq!(e.downcast_ref::<ClaimFailure>().unwrap().class, ClaimClass::Wait);
        let e: anyhow::Error = FulfilFailure {
            class: FulfilClass::Keep,
            error_name: "EnforcedPause".into(),
            reason: "EnforcedPause".into(),
            published: true,
        }
        .into();
        assert_eq!(e.downcast_ref::<FulfilFailure>().unwrap().class, FulfilClass::Keep);
        // A context-wrapped typed failure still downcasts (anyhow keeps the source chain).
        let wrapped = e.context("fulfil step");
        assert!(wrapped.downcast_ref::<FulfilFailure>().is_some());
    }

    #[test]
    fn names_are_log_safe() {
        let m = Revert { reason: "\x1b[31mevil\nline".into() }.abi_encode();
        let n = decode(&m).name();
        assert!(!n.contains('\x1b') && !n.contains('\n'), "{n:?}");
    }
    /// Revert data the 2026-11-16 deployment (contracts 8e1808b) actually returned on an anvil fork of
    /// 743111 (B9-CHAIN, handoff §13 tests 5, 11, 13, 14, 15, 16), classified as §9 says.
    #[test]
    fn reverts_captured_from_the_8e1808b_deployment_classify_per_the_handoff() {
        let h = |s: &str| alloy::hex::decode(s).unwrap();
        // Test 15: a floor above the live price.
        assert_eq!(classify_claim(&decode(&h("c8cea62ae2d513a674d664cc0afb24b6cfa01afcf9e605732656f866f32261746ffe8a850000000000000000000000000000000000000000000000004563918244f400000000000000000000000000000000000000000000000000004563918244f4000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"))), ClaimClass::Wait);
        // Test 14: a second lock on a 100 tHEMI stake. The deployed Staking reverts
        // InsufficientFreeStake (the handoff says Panic(0x01); both classify as a stake shortfall).
        assert_eq!(classify_claim(&decode(&h("31ebd6fd00000000000000000000000000000000000000000000000000000000000b1b1b0000000000000000000000000000000000000000000000056bc75e2d631000000000000000000000000000000000000000000000000000000000000000000000"))), ClaimClass::StakeShort);
        // Test 11: a wrong journal, then a re-claim within the hour after the release.
        assert_eq!(classify_fulfil(&decode(&h("91d07f1e46792eb908089e8f5ddf0a9de9c3b18821890a7e6768174f386e087d14d84acce0282a96835f3797bd5d8a75086ca83e889f44cceec733c4b3bbedd6178c02f2"))), FulfilClass::ProofDefect);
        assert_eq!(classify_claim(&decode(&h("71e53069aa53ee5de601392698f77cab214a82788216791b4e9dc9b9839ca5e6a499a1e400000000000000000000000000000000000000000000000000000000000b1b1b000000000000000000000000000000000000000000000000000000006afc6b65"))), ClaimClass::Wait);
        // Test 13: the 4.5M-gas fulfil (the selector alone, as the trace returned it).
        assert_eq!(classify_fulfil(&decode(&h("a95674c8"))), FulfilClass::Gas);
        // Test 16: a fulfil after D + G reverts Error("Past deadline").
        let past = alloy::sol_types::Revert::from("Past deadline").abi_encode();
        assert_eq!(classify_fulfil(&decode(&past)), FulfilClass::Late);
        // Test 5: a claim in the block of the first stake (selector 0x27e761d2, as traced).
        let delay = enc(zkminer_contracts::bindings::IHemiProveErrors::StakingBlockDelayNotMet {
            prover: alloy::primitives::Address::ZERO,
            depositBlock: Default::default(),
        });
        assert_eq!(alloy::hex::encode(&delay[..4]), "27e761d2");
        assert_eq!(classify_claim(&decode(&delay)), ClaimClass::Wait);
    }

}
