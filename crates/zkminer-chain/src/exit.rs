//! Leaving: request, cancel and withdraw an unstake, and withdraw payouts the router credited.
//!
//! Staking's exit is two steps: `requestUnstake(amount)` commits free stake to leave, and
//! `withdrawUnstaked()` pays it out once the request is [`UNSTAKE_COOLDOWN_SECS`] old and the prover
//! has had no settlement (fulfil, release, slash, bid refund, grace) for
//! [`POST_ACTIVITY_COOLDOWN_SECS`]. `cancelUnstake()` counts a pending request back as stake. The
//! router pays a job's prover by transfer, or credits `withdrawableBalances` when it cannot, and
//! `withdraw()` sends the credited balance.
//!
//! Every transaction here is checked first with an `eth_call` from the prover's own address. A
//! refusal comes back as a [`ExitRefused`] in words ("ready at …", "only 12.50 HEMI is free") and
//! nothing is sent: the contract's own checks are the authority on when an exit is allowed, so the
//! timings below are only for display.

use alloy::primitives::{Address, U256};
use alloy::providers::Provider;
use anyhow::{Context, Result};

use crate::client::ChainClient;
use crate::revert::{decode, revert_data_of, Decoded};
use crate::tx::TX_RECEIPT_TIMEOUT;
use zkminer_contracts::bindings::IHemiProveErrors::IHemiProveErrorsErrors as E;
use zkminer_contracts::bindings::{IHemiProveCore, IHemiProveStaking};

/// Staking's `UNSTAKE_COOLDOWN`: how long a request waits before it can be withdrawn.
pub const UNSTAKE_COOLDOWN_SECS: u64 = 7 * 86_400;
/// Staking's `MIN_POST_ACTIVITY_COOLDOWN`: no withdrawal for this long after a settlement.
pub const POST_ACTIVITY_COOLDOWN_SECS: u64 = 3_600;

/// Where this prover stands on the way out, as read now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExitState {
    pub total_staked: u128,
    pub locked_collateral: u128,
    /// Stake neither locked in a job nor committed to an unstake: what a new request can take.
    pub available_collateral: u128,
    /// The pending unstake request, 0 when there is none.
    pub pending_unstake: u128,
    /// When the pending request was made (unix seconds), 0 when there is none.
    pub unstake_requested_at: u64,
    /// The prover's last settlement (unix seconds), 0 when it has none or it could not be read.
    pub last_activity_at: u64,
    /// Payouts the router holds for this account (`withdrawableBalances`); `None` when the read
    /// failed (an older router without the getter, or an RPC error).
    pub withdrawable_payouts: Option<U256>,
    /// The latest block's timestamp: the clock the contract's cooldowns run on, which can differ
    /// from this host's (this host's clock when the block could not be read).
    pub chain_time: u64,
}

impl ExitState {
    /// Earliest time the pending unstake can be withdrawn: the request's cooldown and the
    /// post-settlement cooldown, whichever ends later. `None` with nothing pending.
    pub fn unstake_ready_at(&self) -> Option<u64> {
        (self.pending_unstake > 0).then(|| {
            let matured = self
                .unstake_requested_at
                .saturating_add(UNSTAKE_COOLDOWN_SECS);
            let settled = if self.last_activity_at == 0 {
                0
            } else {
                self.last_activity_at
                    .saturating_add(POST_ACTIVITY_COOLDOWN_SECS)
            };
            matured.max(settled)
        })
    }
}

/// The contract would refuse this exit transaction: why, in words. Nothing was sent.
#[derive(Debug, Clone)]
pub struct ExitRefused {
    pub what: &'static str,
    pub reason: String,
}

impl std::fmt::Display for ExitRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} would be refused: {} (nothing sent)",
            self.what, self.reason
        )
    }
}
impl std::error::Error for ExitRefused {}

/// The transaction was sent but its receipt was not seen in time. It may still mine: check
/// `zkminer status` before sending it again.
#[derive(Debug, Clone)]
pub struct ExitUnobserved {
    pub what: &'static str,
    pub tx_hash: alloy::primitives::TxHash,
}

impl std::fmt::Display for ExitUnobserved {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} sent as {:?}, but its receipt was not seen in time. It MAY STILL BE PENDING: check \
             `zkminer status` before sending it again",
            self.what, self.tx_hash
        )
    }
}
impl std::error::Error for ExitUnobserved {}

/// HEMI with 2 decimals, for refusal text.
fn hemi(wei: u128) -> String {
    const ONE: u128 = 1_000_000_000_000_000_000;
    format!("{}.{:02} HEMI", wei / ONE, (wei % ONE) / (ONE / 100))
}

/// A unix time as "2026-11-22 14:03 UTC".
pub fn fmt_unix(ts: u64) -> String {
    chrono::DateTime::from_timestamp(ts as i64, 0)
        .map(|t| t.format("%Y-%m-%d %H:%M UTC").to_string())
        .unwrap_or_else(|| ts.to_string())
}

/// Why the contract refused an exit transaction, for the operator.
pub fn explain_exit_revert(d: &Decoded) -> String {
    match d {
        Decoded::Hemi(E::NoPendingUnstake(_)) => "there is no pending unstake".into(),
        Decoded::Hemi(E::UnstakeNotReady(e)) => format!(
            "the unstake is still cooling down; it can be withdrawn from {}",
            fmt_unix(e.readyAt.to::<u64>())
        ),
        Decoded::Hemi(E::PostActivityCooldownActive(e)) => format!(
            "withdrawals wait an hour after this prover's last fulfil, release or slash; try again \
             from {}",
            fmt_unix(e.unlockAt.to::<u64>())
        ),
        Decoded::Hemi(E::PendingUnstakeConflict(_)) => {
            "an unstake is already pending: withdraw it \
             when it is ready (`zkminer withdraw`), or cancel it first (`zkminer unstake --cancel`)"
                .into()
        }
        Decoded::Hemi(E::InsufficientFreeStake(e)) => format!(
            "only {} of the stake is free (asked for {}); the rest is locked in jobs or already \
             pending",
            hemi(e.available),
            hemi(e.requested)
        ),
        Decoded::Hemi(E::NoStake(_)) => "this account has no stake".into(),
        Decoded::Hemi(E::ZeroAmount(_)) => "the amount must be more than zero".into(),
        Decoded::Hemi(E::MaxTotalStakedExceeded(_)) => "the staking cap has no room to count the \
             request back as stake; it stays pending until it can be withdrawn"
            .into(),
        Decoded::Hemi(E::EnforcedPause(_)) => "the contract is paused".into(),
        Decoded::Message(m) => format!("\"{}\"", crate::programs::sanitize_log(m)),
        other => other.name(),
    }
}

/// One of the exit transactions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitTx {
    /// `requestUnstake(amount)`: start the cooldown on `amount` (wei) of free stake.
    RequestUnstake(u128),
    /// `cancelUnstake()`: count the pending request back as stake.
    CancelUnstake,
    /// `withdrawUnstaked()`: pay out a matured unstake to this account.
    WithdrawUnstaked,
    /// The router's `withdraw()`: send this account its credited payouts.
    WithdrawPayouts,
}

impl ExitTx {
    pub fn name(self) -> &'static str {
        match self {
            ExitTx::RequestUnstake(_) => "requestUnstake",
            ExitTx::CancelUnstake => "cancelUnstake",
            ExitTx::WithdrawUnstaked => "withdrawUnstaked",
            ExitTx::WithdrawPayouts => "withdraw (payouts)",
        }
    }
}

/// `eth_call` a built call from our own address: a revert becomes an [`ExitRefused`] in words.
macro_rules! precheck {
    ($client:expr, $what:expr, $build:expr) => {{
        // Against the latest block. (Not `pending`: op-geth answers it as latest unless told
        // otherwise, and some RPCs refuse it; an exit of ours still in the mempool is caught by
        // the command's mempool check instead.)
        match $build.from($client.address).call().await {
            Ok(_) => Ok(()),
            Err(e) => match revert_data_of(&e) {
                Some(data) => Err(anyhow::Error::new(ExitRefused {
                    what: $what,
                    reason: explain_exit_revert(&decode(&data)),
                })),
                None => Err(anyhow::Error::new(e))
                    .with_context(|| format!("{}: pre-check failed", $what)),
            },
        }
    }};
}

/// Send a built call on the shared nonce allocator, with the Hemi fee floors, and wait for its
/// receipt — the same sequence as `stake`. A macro: each call builder is its own type.
macro_rules! send {
    ($client:expr, $what:expr, $build:expr) => {{
        let client: &ChainClient = $client;
        let what: &'static str = $what;
        let nonce = client.reserve_nonce().await?;
        let (tip, max_fee) = client.base_fees().await;
        let tx = $build
            .nonce(nonce)
            .max_priority_fee_per_gas(tip)
            .max_fee_per_gas(max_fee);
        let sent = {
            let _guard = client.tx_lock.lock().await;
            tx.send().await
        };
        let pending = match sent {
            Ok(p) => {
                // As in `stake`: the node took this nonce, so retire any stale abort record and
                // record our fee for a later same-nonce replacement to lift over.
                client.note_nonce_in_use(nonce);
                client.note_broadcast_fee(nonce, tip, max_fee, max_fee);
                p
            }
            Err(e) => {
                client.abort_nonce(nonce);
                client.resync_nonce().await.ok();
                return Err(e).with_context(|| format!("failed to send {what}"));
            }
        };
        let tx_hash = *pending.tx_hash();
        tracing::info!("{what} tx sent: {tx_hash:?}, waiting for receipt...");
        match crate::tx::await_receipt(&*client.provider, tx_hash, TX_RECEIPT_TIMEOUT).await {
            Some(receipt) => {
                client.commit_nonce(nonce);
                if !receipt.status() {
                    anyhow::bail!("{what} transaction {tx_hash:?} reverted");
                }
                Ok(tx_hash)
            }
            None => {
                // Not aborted: the node accepted it and it may still mine (see `stake`).
                client.resync_nonce().await.ok();
                Err(anyhow::Error::new(ExitUnobserved { what, tx_hash }))
            }
        }
    }};
}

impl ChainClient {
    /// Read where `prover` stands on the way out. Only the stake itself must be read: the rest is
    /// for display (the contract's own checks decide what is allowed), so a failed read of it does
    /// not stop an exit.
    pub async fn get_exit_state(&self, prover: Address) -> Result<ExitState> {
        let staking = IHemiProveStaking::new(self.hemi_prove_staking, &*self.provider);
        let router = IHemiProveCore::new(self.hemi_prove, &*self.provider);
        let stake = staking
            .getProverStake(prover)
            .call()
            .await
            .context("Failed to get prover stake")?;
        let available = staking
            .getAvailableCollateral(prover)
            .call()
            .await
            .context("Failed to get available collateral")?;
        let last_activity = staking
            .lastProverActivityAt(prover)
            .call()
            .await
            .map(|t| t.to::<u64>())
            .unwrap_or(0);
        let payouts = router.withdrawableBalances(prover).call().await.ok();
        let chain_time = match self
            .provider
            .get_block_by_number(alloy::eips::BlockNumberOrTag::Latest)
            .await
        {
            Ok(Some(b)) => b.header.timestamp,
            _ => crate::client::chain_now(),
        };
        Ok(ExitState {
            total_staked: stake.totalStaked,
            locked_collateral: stake.lockedCollateral,
            available_collateral: available,
            pending_unstake: stake.unstakeAmount,
            unstake_requested_at: stake.unstakeRequestTime.to::<u64>(),
            last_activity_at: last_activity,
            withdrawable_payouts: payouts,
            chain_time,
        })
    }

    /// Whether the contract would accept `tx` from this account now. `Err(ExitRefused)` says why
    /// not; nothing is sent either way.
    pub async fn precheck_exit(&self, tx: ExitTx) -> Result<()> {
        let staking = IHemiProveStaking::new(self.hemi_prove_staking, &*self.provider);
        let router = IHemiProveCore::new(self.hemi_prove, &*self.provider);
        let what = tx.name();
        match tx {
            ExitTx::RequestUnstake(amount) => precheck!(self, what, staking.requestUnstake(amount)),
            ExitTx::CancelUnstake => precheck!(self, what, staking.cancelUnstake()),
            ExitTx::WithdrawUnstaked => precheck!(self, what, staking.withdrawUnstaked()),
            ExitTx::WithdrawPayouts => precheck!(self, what, router.withdraw()),
        }
    }

    /// Pre-check `tx` (see [`Self::precheck_exit`]), then send it and wait for its receipt.
    pub async fn send_exit(&self, tx: ExitTx) -> Result<alloy::primitives::TxHash> {
        self.precheck_exit(tx).await?;
        let staking = IHemiProveStaking::new(self.hemi_prove_staking, &*self.provider);
        let router = IHemiProveCore::new(self.hemi_prove, &*self.provider);
        let what = tx.name();
        match tx {
            ExitTx::RequestUnstake(amount) => send!(self, what, staking.requestUnstake(amount)),
            ExitTx::CancelUnstake => send!(self, what, staking.cancelUnstake()),
            ExitTx::WithdrawUnstaked => send!(self, what, staking.withdrawUnstaked()),
            ExitTx::WithdrawPayouts => send!(self, what, router.withdraw()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::aliases::U40;
    use zkminer_contracts::bindings::IHemiProveErrors;

    fn state(pending: u128, requested: u64, activity: u64) -> ExitState {
        ExitState {
            total_staked: 0,
            locked_collateral: 0,
            available_collateral: 0,
            pending_unstake: pending,
            unstake_requested_at: requested,
            last_activity_at: activity,
            withdrawable_payouts: Some(U256::ZERO),
            chain_time: 0,
        }
    }

    #[test]
    fn an_unstake_is_ready_after_both_cooldowns() {
        assert_eq!(state(0, 0, 0).unstake_ready_at(), None, "nothing pending");
        // Never settled anything: the request's 7 days alone.
        assert_eq!(
            state(5, 1_000, 0).unstake_ready_at(),
            Some(1_000 + UNSTAKE_COOLDOWN_SECS)
        );
        // Settled long before: still the 7 days.
        assert_eq!(
            state(5, 1_000_000, 10).unstake_ready_at(),
            Some(1_000_000 + UNSTAKE_COOLDOWN_SECS)
        );
        // Settled an instant before the request matures: an hour after that settlement.
        let req = 1_000_000;
        let act = req + UNSTAKE_COOLDOWN_SECS - 1;
        assert_eq!(
            state(5, req, act).unstake_ready_at(),
            Some(act + POST_ACTIVITY_COOLDOWN_SECS)
        );
    }

    #[test]
    fn refusals_are_explained_in_words() {
        let prover = Address::repeat_byte(1);
        let ready = 1_800_000_000u64;
        let d = Decoded::Hemi(E::UnstakeNotReady(IHemiProveErrors::UnstakeNotReady {
            prover,
            readyAt: U40::from(ready),
        }));
        let why = explain_exit_revert(&d);
        assert!(why.contains(&fmt_unix(ready)), "{why}");
        let d = Decoded::Hemi(E::InsufficientFreeStake(
            IHemiProveErrors::InsufficientFreeStake {
                prover,
                requested: 150 * 10u128.pow(18),
                available: 12_500_000_000_000_000_000,
            },
        ));
        let why = explain_exit_revert(&d);
        assert!(
            why.contains("12.50 HEMI") && why.contains("150.00 HEMI"),
            "{why}"
        );
        let d = Decoded::Hemi(E::PendingUnstakeConflict(
            IHemiProveErrors::PendingUnstakeConflict { prover },
        ));
        assert!(explain_exit_revert(&d).contains("unstake --cancel"));
        assert_eq!(fmt_unix(0), "1970-01-01 00:00 UTC");
    }
}
