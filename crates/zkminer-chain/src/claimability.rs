//! The static gate's claimability read (witness-construction-jobs §5.3 "Claimable").
//!
//! One `eth_call` of `claimJob(jobId, 0, 0)` from the staked prover at a mined block covers
//! exclusivity, a live bid round, the release cooldown, the reopen limit, pauses, the adapter's state
//! and stake; its return value is the price a claim included now settles at. `getPremiumCap(jobId)`
//! is read at the same block, so the answer is a [`ClaimQuote`] exactly as
//! [`ChainClient::quote_claim`] gives it, for any prover (a watch-only client asks as the prover it
//! watches). A refusal is decoded from the revert data into a typed [`NotClaimable`].

use alloy::eips::BlockId;
use alloy::primitives::aliases::U96;
use alloy::primitives::{Address, B256, U256};
use alloy::providers::Provider;
use zkminer_contracts::bindings::IHemiProveErrors::IHemiProveErrorsErrors as E;
use zkminer_contracts::bindings::{IHemiProveAux, IHemiProveCore};

use crate::client::ChainClient;
use crate::jobs::ClaimQuote;
use crate::revert::{ClaimClass, Decoded};

/// Why a job is not claimable by a prover right now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NotClaimable {
    /// Inside another prover's exclusivity window (or a NONE job assigned to another prover).
    Exclusivity { assigned_prover: Address },
    /// Reserved to its caller's assigned prover, which is not this one (`NotReserved`).
    NotReserved,
    /// A competitive bid round is live (`BiddingActive`, `CompetitiveBiddingActive`).
    BidRound,
    /// This prover released the job and its cooldown runs until `until` (unix seconds;
    /// `ReleaseCooldownActive`), or a delegated claim's cooldown (`DelegatedClaimCooldownActive`).
    Cooldown { until: u64 },
    /// The job was reopened `MAX_REOPEN_COUNT` times (`MaxReopenCountReached`).
    ReopenLimit { reopen_count: u8 },
    /// The router is paused (`EnforcedPause`).
    Paused,
    /// The Registry is paused (`RegistryPaused`).
    RegistryPaused,
    /// The job's adapter is Disabled (`AdapterDisabled`).
    AdapterDisabled { proof_system_id: B256 },
    /// The job's adapter is not Active (unregistered, or deprecated past its window;
    /// `AdapterNotActive`).
    AdapterNotActive { proof_system_id: B256 },
    /// Stake: below the job's collateral (`InsufficientStake`, `InsufficientFreeStake`, the staking
    /// contract's `Panic(0x01)`), a pending unstake in the way (`PendingUnstakeConflict`), or a stake
    /// too fresh to claim with (`StakingBlockDelayNotMet`). `required`/`available` when the revert
    /// carries them.
    Stake {
        reason: String,
        required: Option<u128>,
        available: Option<u128>,
    },
    /// The job is not Open (held, settled or cancelled; `JobNotOpen`, `JobAlreadyTerminal`).
    NotOpen,
    /// The job is unknown at the read's block (`JobNotFound`: a replica behind its submit).
    NotFound,
    /// Any other refusal, with the claim table's class and the decoded name.
    Other { class: ClaimClass, name: String },
    /// The read itself failed (transport): nothing is known.
    Unreadable(String),
}

impl std::fmt::Display for NotClaimable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NotClaimable::Exclusivity { assigned_prover } => {
                write!(f, "exclusive to {assigned_prover}")
            }
            NotClaimable::NotReserved => f.write_str("reserved to another prover"),
            NotClaimable::BidRound => f.write_str("a bid round is live"),
            NotClaimable::Cooldown { until } => write!(f, "claim cooldown until {until}"),
            NotClaimable::ReopenLimit { reopen_count } => {
                write!(f, "reopened {reopen_count} times (the limit)")
            }
            NotClaimable::Paused => f.write_str("the router is paused"),
            NotClaimable::RegistryPaused => f.write_str("the Registry is paused"),
            NotClaimable::AdapterDisabled { proof_system_id } => {
                write!(f, "adapter {proof_system_id} is Disabled")
            }
            NotClaimable::AdapterNotActive { proof_system_id } => {
                write!(f, "adapter {proof_system_id} is not Active")
            }
            NotClaimable::Stake {
                reason,
                required,
                available,
            } => write!(
                f,
                "stake: {reason} (required {required:?}, available {available:?})"
            ),
            NotClaimable::NotOpen => f.write_str("the job is not Open"),
            NotClaimable::NotFound => f.write_str("the job is unknown at this block"),
            NotClaimable::Other { class, name } => write!(f, "{name} ({class:?})"),
            NotClaimable::Unreadable(why) => write!(f, "claimability unreadable: {why}"),
        }
    }
}

impl std::error::Error for NotClaimable {}

impl NotClaimable {
    /// The claim table's class of this refusal (`revert::classify_claim`'s answer).
    pub fn class(&self) -> ClaimClass {
        match self {
            NotClaimable::Paused | NotClaimable::RegistryPaused => ClaimClass::Paused,
            NotClaimable::Exclusivity { .. }
            | NotClaimable::BidRound
            | NotClaimable::Cooldown { .. }
            | NotClaimable::AdapterDisabled { .. }
            | NotClaimable::NotFound => ClaimClass::Wait,
            NotClaimable::Stake { reason, .. } if reason == "StakingBlockDelayNotMet" => {
                ClaimClass::Wait
            }
            NotClaimable::Stake { .. } => ClaimClass::StakeShort,
            NotClaimable::NotReserved
            | NotClaimable::ReopenLimit { .. }
            | NotClaimable::AdapterNotActive { .. }
            | NotClaimable::NotOpen => ClaimClass::Gone,
            NotClaimable::Other { class, .. } => *class,
            NotClaimable::Unreadable(_) => ClaimClass::Unknown,
        }
    }

    /// The typed reason a claim revert carries (`claimJob`'s revert data, decoded).
    pub fn from_revert(d: &Decoded) -> Self {
        match d {
            Decoded::Hemi(e) => match e {
                E::ExclusivityActive(x) => NotClaimable::Exclusivity {
                    assigned_prover: x.assignedProver,
                },
                E::NotReserved(_) => NotClaimable::NotReserved,
                E::BiddingActive(_) | E::CompetitiveBiddingActive(_) => NotClaimable::BidRound,
                E::ReleaseCooldownActive(x) => NotClaimable::Cooldown {
                    until: x.cooldownEnd.saturating_to::<u64>(),
                },
                E::DelegatedClaimCooldownActive(x) => NotClaimable::Cooldown {
                    until: x.cooldownEnd.to::<u64>(),
                },
                E::MaxReopenCountReached(x) => NotClaimable::ReopenLimit {
                    reopen_count: x.reopenCount,
                },
                E::EnforcedPause(_) => NotClaimable::Paused,
                E::RegistryPaused(_) => NotClaimable::RegistryPaused,
                E::AdapterDisabled(x) => NotClaimable::AdapterDisabled {
                    proof_system_id: x.proofSystemId,
                },
                E::AdapterNotActive(x) => NotClaimable::AdapterNotActive {
                    proof_system_id: x.proofSystemId,
                },
                E::InsufficientStake(x) => NotClaimable::Stake {
                    reason: "InsufficientStake".into(),
                    required: Some(x.required),
                    available: Some(x.actual),
                },
                E::InsufficientFreeStake(x) => NotClaimable::Stake {
                    reason: "InsufficientFreeStake".into(),
                    required: Some(x.requested),
                    available: Some(x.available),
                },
                E::PendingUnstakeConflict(_) => NotClaimable::Stake {
                    reason: "PendingUnstakeConflict".into(),
                    required: None,
                    available: None,
                },
                E::StakingBlockDelayNotMet(_) => NotClaimable::Stake {
                    reason: "StakingBlockDelayNotMet".into(),
                    required: None,
                    available: None,
                },
                E::NoStake(_) => NotClaimable::Stake {
                    reason: "NoStake".into(),
                    required: None,
                    available: Some(0),
                },
                E::OperatorCollateralCapExceeded(x) => NotClaimable::Stake {
                    reason: "OperatorCollateralCapExceeded".into(),
                    required: Some(x.requested),
                    available: Some(x.cap),
                },
                E::JobNotOpen(_) | E::JobAlreadyTerminal(_) => NotClaimable::NotOpen,
                E::JobNotFound(_) => NotClaimable::NotFound,
                _ => NotClaimable::Other {
                    class: crate::revert::classify_claim(d),
                    name: d.name(),
                },
            },
            // The staking contract's free-stake assert.
            Decoded::Panic(code) if *code == U256::from(1u8) => NotClaimable::Stake {
                reason: "Panic(0x01): free stake below the job's collateral".into(),
                required: None,
                available: None,
            },
            other => NotClaimable::Other {
                class: crate::revert::classify_claim(other),
                name: other.name(),
            },
        }
    }
}

impl ChainClient {
    /// The static gate's claimability read (§5.3): an `eth_call` of `claimJob(jobId, 0, 0)` FROM
    /// `prover` at one mined block, and `getPremiumCap(jobId)` at the same block. `Ok` is the quote
    /// a claim sent now would use as its floors; `Err` the typed reason it would be refused.
    pub async fn claimability(
        &self,
        job_id: B256,
        prover: Address,
    ) -> Result<ClaimQuote, NotClaimable> {
        let block = self
            .provider
            .get_block_number()
            .await
            .map_err(|e| NotClaimable::Unreadable(format!("block number: {e:#}")))?;
        let at = BlockId::number(block);
        let core = IHemiProveCore::new(self.hemi_prove, &*self.provider);
        let price = match core
            .claimJob(job_id, U96::ZERO, U96::ZERO)
            .from(prover)
            .block(at)
            .call()
            .await
        {
            Ok(p) => p.to::<u128>(),
            Err(e) => {
                return Err(match crate::revert::revert_data_of(&e) {
                    Some(data) => NotClaimable::from_revert(&crate::revert::decode(&data)),
                    None => NotClaimable::Unreadable(crate::programs::sanitize_log(&format!(
                        "claimJob eth_call: {e:#}"
                    ))),
                })
            }
        };
        let cap = IHemiProveAux::new(self.hemi_prove, &*self.provider)
            .getPremiumCap(job_id)
            .block(at)
            .call()
            .await
            .map_err(|e| NotClaimable::Unreadable(format!("getPremiumCap: {e:#}")))?;
        Ok(ClaimQuote {
            block,
            price_floor: price,
            premium_floor: cap.min(U256::from(U96::MAX)).to::<u128>(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::sol_types::{Panic, Revert, SolError};
    use zkminer_contracts::bindings::IHemiProveErrors as H;

    fn nc<T: SolError>(e: T) -> NotClaimable {
        NotClaimable::from_revert(&crate::revert::decode(&e.abi_encode()))
    }

    #[test]
    fn every_static_gate_reason_decodes_typed() {
        let b = B256::repeat_byte(7);
        let a = Address::repeat_byte(9);
        assert_eq!(
            nc(H::ExclusivityActive {
                jobId: b,
                assignedProver: a
            }),
            NotClaimable::Exclusivity { assigned_prover: a }
        );
        assert_eq!(nc(H::NotReserved { jobId: b }), NotClaimable::NotReserved);
        assert_eq!(nc(H::BiddingActive { jobId: b }), NotClaimable::BidRound);
        assert_eq!(
            nc(H::CompetitiveBiddingActive { jobId: b }),
            NotClaimable::BidRound
        );
        assert_eq!(
            nc(H::ReleaseCooldownActive {
                jobId: b,
                prover: a,
                cooldownEnd: U256::from(1_800_000_000u64)
            }),
            NotClaimable::Cooldown {
                until: 1_800_000_000
            }
        );
        assert_eq!(
            nc(H::MaxReopenCountReached {
                jobId: b,
                reopenCount: 10
            }),
            NotClaimable::ReopenLimit { reopen_count: 10 }
        );
        assert_eq!(nc(H::EnforcedPause {}), NotClaimable::Paused);
        assert_eq!(
            nc(H::RegistryPaused { jobId: b }),
            NotClaimable::RegistryPaused
        );
        assert_eq!(
            nc(H::AdapterDisabled { proofSystemId: b }),
            NotClaimable::AdapterDisabled { proof_system_id: b }
        );
        assert_eq!(
            nc(H::InsufficientStake {
                prover: a,
                required: 150,
                actual: 100
            }),
            NotClaimable::Stake {
                reason: "InsufficientStake".into(),
                required: Some(150),
                available: Some(100)
            }
        );
        let delay = nc(H::StakingBlockDelayNotMet {
            prover: a,
            depositBlock: Default::default(),
        });
        assert_eq!(delay.class(), ClaimClass::Wait);
        assert_eq!(
            nc(H::PendingUnstakeConflict { prover: a }).class(),
            ClaimClass::StakeShort
        );
        assert_eq!(nc(H::JobNotOpen { jobId: b }), NotClaimable::NotOpen);
        let panic1 = NotClaimable::from_revert(&crate::revert::decode(
            &Panic {
                code: U256::from(1u8),
            }
            .abi_encode(),
        ));
        assert_eq!(panic1.class(), ClaimClass::StakeShort);
        // Anything else keeps its claim-table class and name.
        let unrouted = NotClaimable::from_revert(&crate::revert::decode(
            &Revert {
                reason: "Unknown selector".into(),
            }
            .abi_encode(),
        ));
        assert!(matches!(
            unrouted,
            NotClaimable::Other {
                class: ClaimClass::Unknown,
                ..
            }
        ));
    }

    #[test]
    fn classes_agree_with_the_claim_table() {
        // For every typed reason, `class()` must be what `classify_claim` says of the same revert.
        let b = B256::repeat_byte(7);
        let a = Address::repeat_byte(9);
        let cases: Vec<Vec<u8>> = vec![
            H::ExclusivityActive {
                jobId: b,
                assignedProver: a,
            }
            .abi_encode(),
            H::NotReserved { jobId: b }.abi_encode(),
            H::BiddingActive { jobId: b }.abi_encode(),
            H::ReleaseCooldownActive {
                jobId: b,
                prover: a,
                cooldownEnd: U256::ZERO,
            }
            .abi_encode(),
            H::MaxReopenCountReached {
                jobId: b,
                reopenCount: 10,
            }
            .abi_encode(),
            H::EnforcedPause {}.abi_encode(),
            H::RegistryPaused { jobId: b }.abi_encode(),
            H::AdapterDisabled { proofSystemId: b }.abi_encode(),
            H::AdapterNotActive { proofSystemId: b }.abi_encode(),
            H::InsufficientStake {
                prover: a,
                required: 1,
                actual: 0,
            }
            .abi_encode(),
            H::PendingUnstakeConflict { prover: a }.abi_encode(),
            H::StakingBlockDelayNotMet {
                prover: a,
                depositBlock: Default::default(),
            }
            .abi_encode(),
            H::JobNotOpen { jobId: b }.abi_encode(),
            H::JobNotFound { jobId: b }.abi_encode(),
            Panic {
                code: U256::from(1u8),
            }
            .abi_encode(),
        ];
        for data in cases {
            let d = crate::revert::decode(&data);
            assert_eq!(
                NotClaimable::from_revert(&d).class(),
                crate::revert::classify_claim(&d),
                "{}",
                d.name()
            );
        }
    }
}
