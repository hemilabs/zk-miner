//! What the chain's own events say about a prover's stake and its locks (review 7 LD-1, LD-3): the
//! slash latch reads them to tell a stake fall this miner caused (a release penalty, a withdrawal)
//! from a slash, and a lock that ended past its deadline by a release from one that was slashed.
//!
//! - `StakeReduced(prover, amount, newTotal, newPendingUnstake, slashed)` on the staking contract:
//!   every reduction of a prover's stake other than a withdrawal, `slashed` saying which were slashes.
//! - `Withdrawn(prover, amount, newTotal)` on the staking contract: `withdrawUnstaked`.
//! - `JobReleased(jobId, prover, ..)`, `GraceReleased`, `GracePauseReleased` and
//!   `JobReopened(jobId, slashedProver, ..)` on the router: how a lock left its prover.
//!
//! Reads are chunked like the locked-job scan ([`ChainClient::get_logs_chunked`]).

use std::time::Duration;

use alloy::primitives::{Address, B256};
use alloy::providers::Provider;
use alloy::rpc::types::{Filter, Log};
use alloy::sol_types::SolEvent;
use anyhow::{bail, Result};

use zkminer_contracts::bindings::{IHemiProveFulfill, IHemiProveStaking};

use crate::client::ChainClient;

/// The widest block range one `eth_getLogs` asks for.
pub const LOG_CHUNK: u64 = 9000;

/// Tries per chunk before a read fails.
const CHUNK_TRIES: u32 = 3;

/// What a prover's stake events over a block range add up to.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StakeMoves {
    /// `StakeReduced` with `slashed == false`: release penalties and the like.
    pub reduced: u128,
    /// `Withdrawn`: unstaked stake taken out.
    pub withdrawn: u128,
    /// `StakeReduced` with `slashed == true`, as `(block, amount)`.
    pub slashes: Vec<(u64, u128)>,
}

impl StakeMoves {
    /// The stake these events took out without a slash.
    pub fn explained(&self) -> u128 {
        self.reduced.saturating_add(self.withdrawn)
    }
}

/// How a lock of ours left us, by the router's events.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockExit {
    /// `JobReleased` naming us, at this penalty (wei).
    Released { penalty: u128 },
    /// `GraceReleased` or `GracePauseReleased` naming us: no penalty.
    GraceReleased,
    /// `JobReopened` with us as the slashed prover, at this amount.
    Slashed { amount: u128 },
}

fn decode<E: SolEvent>(log: &Log) -> Option<E> {
    E::decode_log_data(log.data()).ok()
}

/// Sum the stake events of `prover` among `logs` from `staking`. Logs from another address, of
/// another prover, removed by a reorg, or that do not decode are left out.
pub fn stake_moves_of(logs: &[Log], staking: Address, prover: Address) -> StakeMoves {
    let mut m = StakeMoves::default();
    for log in logs {
        if log.removed || log.address() != staking {
            continue;
        }
        match log.topics().first().copied() {
            Some(t) if t == IHemiProveStaking::StakeReduced::SIGNATURE_HASH => {
                if let Some(e) = decode::<IHemiProveStaking::StakeReduced>(log) {
                    if e.prover != prover {
                        continue;
                    }
                    if e.slashed {
                        m.slashes.push((log.block_number.unwrap_or(0), e.amount));
                    } else {
                        m.reduced = m.reduced.saturating_add(e.amount);
                    }
                }
            }
            Some(t) if t == IHemiProveStaking::Withdrawn::SIGNATURE_HASH => {
                if let Some(e) = decode::<IHemiProveStaking::Withdrawn>(log) {
                    if e.prover == prover {
                        m.withdrawn = m.withdrawn.saturating_add(e.amount);
                    }
                }
            }
            _ => {}
        }
    }
    m
}

/// The exits of `prover`'s lock on `job_id` among `logs` from `router`, in log order.
pub fn lock_exits_of(
    logs: &[Log],
    router: Address,
    job_id: B256,
    prover: Address,
) -> Vec<LockExit> {
    let mut out = Vec::new();
    for log in logs {
        if log.removed || log.address() != router {
            continue;
        }
        let exit = match log.topics().first().copied() {
            Some(t) if t == IHemiProveFulfill::JobReleased::SIGNATURE_HASH => {
                decode::<IHemiProveFulfill::JobReleased>(log)
                    .filter(|e| e.jobId == job_id && e.prover == prover)
                    .map(|e| LockExit::Released {
                        penalty: u128::try_from(e.penaltyAmount).unwrap_or(u128::MAX),
                    })
            }
            Some(t) if t == IHemiProveFulfill::GraceReleased::SIGNATURE_HASH => {
                decode::<IHemiProveFulfill::GraceReleased>(log)
                    .filter(|e| e.jobId == job_id && e.prover == prover)
                    .map(|_| LockExit::GraceReleased)
            }
            Some(t) if t == IHemiProveFulfill::GracePauseReleased::SIGNATURE_HASH => {
                decode::<IHemiProveFulfill::GracePauseReleased>(log)
                    .filter(|e| e.jobId == job_id && e.prover == prover)
                    .map(|_| LockExit::GraceReleased)
            }
            Some(t) if t == IHemiProveFulfill::JobReopened::SIGNATURE_HASH => {
                decode::<IHemiProveFulfill::JobReopened>(log)
                    .filter(|e| e.jobId == job_id && e.slashedProver == prover)
                    .map(|e| LockExit::Slashed {
                        amount: e.slashedAmount,
                    })
            }
            _ => None,
        };
        out.extend(exit);
    }
    out
}

impl ChainClient {
    /// Every log matching `filter` (its address and topics; its block range is replaced) in
    /// `[from, to]`, read [`LOG_CHUNK`] blocks at a time, each chunk tried up to three times. `what`
    /// names the read in the warnings and the error.
    pub async fn get_logs_chunked(
        &self,
        filter: &Filter,
        from: u64,
        to: u64,
        what: &str,
    ) -> Result<Vec<Log>> {
        let mut out = Vec::new();
        let mut start = from;
        while start <= to {
            let end = start.saturating_add(LOG_CHUNK).min(to);
            let f = filter.clone().from_block(start).to_block(end);
            let mut tries = 0;
            let logs = loop {
                tries += 1;
                match self.provider.get_logs(&f).await {
                    Ok(l) => break l,
                    Err(e) if tries < CHUNK_TRIES => {
                        tracing::warn!(
                            "{what}: get_logs {start}..={end} failed (try {tries}/{CHUNK_TRIES}): {e:#}"
                        );
                        tokio::time::sleep(Duration::from_secs(2 * tries as u64)).await;
                    }
                    Err(e) => {
                        bail!("{what} {start}..={end} failed {CHUNK_TRIES}x: {e:#}")
                    }
                }
            };
            out.extend(logs);
            start = end.saturating_add(1);
        }
        Ok(out)
    }

    /// This prover's stake events in `(after, to]`.
    pub async fn stake_moves_in(&self, after: u64, to: u64) -> Result<StakeMoves> {
        let filter = Filter::new()
            .address(self.hemi_prove_staking)
            .event_signature(vec![
                IHemiProveStaking::StakeReduced::SIGNATURE_HASH,
                IHemiProveStaking::Withdrawn::SIGNATURE_HASH,
            ])
            .topic1(self.address.into_word());
        let logs = self
            .get_logs_chunked(&filter, after.saturating_add(1), to, "stake events")
            .await?;
        Ok(stake_moves_of(&logs, self.hemi_prove_staking, self.address))
    }

    /// How this prover's lock on `job_id` left it, by the router's events in `[from, to]`.
    pub async fn lock_exits_in(&self, job_id: B256, from: u64, to: u64) -> Result<Vec<LockExit>> {
        let filter = Filter::new()
            .address(self.hemi_prove)
            .event_signature(vec![
                IHemiProveFulfill::JobReleased::SIGNATURE_HASH,
                IHemiProveFulfill::GraceReleased::SIGNATURE_HASH,
                IHemiProveFulfill::GracePauseReleased::SIGNATURE_HASH,
                IHemiProveFulfill::JobReopened::SIGNATURE_HASH,
            ])
            .topic1(job_id);
        let logs = self
            .get_logs_chunked(&filter, from, to, "lock exit events")
            .await?;
        Ok(lock_exits_of(&logs, self.hemi_prove, job_id, self.address))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::{Log as PrimLog, U256};

    const STAKING: Address = Address::repeat_byte(0x5a);
    const ROUTER: Address = Address::repeat_byte(0xa1);
    const ME: Address = Address::repeat_byte(0x11);
    const OTHER: Address = Address::repeat_byte(0x22);
    const H: u128 = 1_000_000_000_000_000_000;

    fn rpc_log<E: SolEvent>(address: Address, ev: &E, block: u64) -> Log {
        Log {
            inner: PrimLog {
                address,
                data: ev.encode_log_data(),
            },
            block_number: Some(block),
            ..Default::default()
        }
    }

    fn reduced(prover: Address, amount: u128, slashed: bool) -> IHemiProveStaking::StakeReduced {
        IHemiProveStaking::StakeReduced {
            prover,
            amount,
            newTotal: 0,
            newPendingUnstake: 0,
            slashed,
        }
    }

    #[test]
    fn stake_events_sum_by_kind_and_skip_others() {
        let logs = vec![
            rpc_log(STAKING, &reduced(ME, 5 * H, false), 10),
            rpc_log(STAKING, &reduced(ME, 7 * H, false), 11),
            rpc_log(STAKING, &reduced(ME, 50 * H, true), 12),
            rpc_log(
                STAKING,
                &IHemiProveStaking::Withdrawn {
                    prover: ME,
                    amount: 100 * H,
                    newTotal: 0,
                },
                13,
            ),
            // Another prover, another contract, a reorged log: none count.
            rpc_log(STAKING, &reduced(OTHER, 9 * H, true), 14),
            rpc_log(ROUTER, &reduced(ME, 9 * H, true), 15),
            Log {
                removed: true,
                ..rpc_log(STAKING, &reduced(ME, 9 * H, true), 16)
            },
        ];
        let m = stake_moves_of(&logs, STAKING, ME);
        assert_eq!(m.reduced, 12 * H);
        assert_eq!(m.withdrawn, 100 * H);
        assert_eq!(m.slashes, vec![(12, 50 * H)]);
        assert_eq!(m.explained(), 112 * H);
    }

    #[test]
    fn lock_exits_name_a_release_a_grace_release_and_a_slash_of_ours_only() {
        let job = B256::repeat_byte(0x0b);
        let other_job = B256::repeat_byte(0x0c);
        let released = |prover, job_id| IHemiProveFulfill::JobReleased {
            jobId: job_id,
            prover,
            penaltyAmount: U256::from(5 * H),
            newBonusAmount: Default::default(),
            timeHeld: U256::ZERO,
            operator: prover,
        };
        let logs = vec![
            rpc_log(ROUTER, &released(OTHER, job), 10),
            rpc_log(ROUTER, &released(ME, other_job), 11),
            rpc_log(ROUTER, &released(ME, job), 12),
            rpc_log(
                ROUTER,
                &IHemiProveFulfill::GracePauseReleased {
                    jobId: job,
                    prover: ME,
                    releasedCollateral: 100 * H,
                    operator: ME,
                },
                13,
            ),
            rpc_log(
                ROUTER,
                &IHemiProveFulfill::JobReopened {
                    jobId: job,
                    slashedProver: ME,
                    slashCaller: OTHER,
                    slashedAmount: 100 * H,
                    keeperReward: U256::ZERO,
                    burnedAmount: U256::ZERO,
                    newBonusAmount: Default::default(),
                    reopenCount: 1,
                    newRampUpStart: Default::default(),
                    elapsedAtLock: Default::default(),
                    operator: OTHER,
                },
                14,
            ),
            // The right event from the wrong contract does not count.
            rpc_log(STAKING, &released(ME, job), 15),
        ];
        assert_eq!(
            lock_exits_of(&logs, ROUTER, job, ME),
            vec![
                LockExit::Released { penalty: 5 * H },
                LockExit::GraceReleased,
                LockExit::Slashed { amount: 100 * H },
            ]
        );
        assert!(lock_exits_of(&logs, ROUTER, job, Address::repeat_byte(0x33)).is_empty());
    }
}
