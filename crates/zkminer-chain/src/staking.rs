use alloy::primitives::{Address, U256};
use anyhow::{Context, Result};

use crate::tx::TX_RECEIPT_TIMEOUT;
use zkminer_contracts::bindings::{IHemiProveStaking, ITestnetToken, IERC20};

use crate::client::ChainClient;

/// Hemi testnet chain ID — gate testnet-only operations like public mint().
pub const TESTNET_CHAIN_ID: u64 = 743111;

/// Staking information for a prover.
#[derive(Debug, Clone)]
pub struct StakeInfo {
    pub total_staked: u128,
    pub locked_collateral: u128,
    pub available_collateral: u128,
    pub unstake_amount: u128,
    pub unstake_request_time: u64,
    /// Block number the current stake was deposited at (was a unix timestamp
    /// before contract FIX-V1A3, 2026-07-08). Claim eligibility is
    /// `block.number > deposit_block`; there is no wall-clock staking-age gate.
    pub deposit_block: u64,
}

/// Prover performance statistics.
#[derive(Debug, Clone)]
pub struct ProverStatistics {
    pub jobs_fulfilled: u64,
    pub jobs_slashed: u64,
    pub jobs_released: u64,
    pub total_earned: u128,
    pub first_fulfillment_at: u64,
    pub last_fulfillment_at: u64,
}

impl ChainClient {
    /// Get staking info for a prover.
    pub async fn get_stake_info(&self, prover: Address) -> Result<StakeInfo> {
        let staking = IHemiProveStaking::new(self.hemi_prove_staking, &*self.provider);

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

        Ok(StakeInfo {
            total_staked: stake.totalStaked,
            locked_collateral: stake.lockedCollateral,
            available_collateral: available,
            unstake_amount: stake.unstakeAmount,
            unstake_request_time: stake.unstakeRequestTime.to::<u64>(),
            deposit_block: stake.depositBlock.to::<u64>(),
        })
    }

    /// Get prover statistics.
    pub async fn get_prover_stats(&self, prover: Address) -> Result<ProverStatistics> {
        let staking = IHemiProveStaking::new(self.hemi_prove_staking, &*self.provider);

        let stats = staking
            .getProverStats(prover)
            .call()
            .await
            .context("Failed to get prover stats")?;

        Ok(ProverStatistics {
            jobs_fulfilled: stats.jobsFulfilled,
            jobs_slashed: stats.jobsSlashed,
            jobs_released: stats.jobsReleased,
            total_earned: stats.totalEarned.to::<u128>(),
            first_fulfillment_at: stats.firstFulfillmentAt.to::<u64>(),
            last_fulfillment_at: stats.lastFulfillmentAt.to::<u64>(),
        })
    }

    /// Get HEMI token balance.
    pub async fn get_hemi_balance(&self, account: Address) -> Result<U256> {
        let token = IERC20::new(self.hemi_token, &*self.provider);
        let balance = token
            .balanceOf(account)
            .call()
            .await
            .context("Failed to get HEMI balance")?;
        Ok(balance)
    }

    /// Get HEMI token allowance for the staking contract.
    pub async fn get_hemi_allowance(&self, owner: Address, spender: Address) -> Result<U256> {
        let token = IERC20::new(self.hemi_token, &*self.provider);
        let allowance = token
            .allowance(owner, spender)
            .call()
            .await
            .context("Failed to get HEMI allowance")?;
        Ok(allowance)
    }

    /// Approve HEMI token spending for the staking contract.
    pub async fn approve_hemi_token(&self, spender: Address, amount: U256) -> Result<()> {
        // [#48] Route through the nonce allocator with an EXPLICIT nonce so this shares one
        // nonce sequence with the job txs. Without this, staking goes through alloy's
        // independent NonceFiller and can occupy a nonce the allocator hands to a concurrent
        // lifecycle task (a re-stake during live proving), where the keep+escalate path would
        // then displace one tx with the other — the exact sibling-displacement the allocator
        // exists to prevent.
        let token = IERC20::new(self.hemi_token, &*self.provider);
        let nonce = self.reserve_nonce().await?;
        let tx = token.approve(spender, amount).nonce(nonce);
        let send_result = {
            let _guard = self.tx_lock.lock().await;
            tx.send().await
        };
        let pending = match send_result {
            Ok(p) => {
                // Retire any stale abort record: the node ACCEPTED this send, so the nonce
                // is legitimately in use. These paths share the job allocator but cannot
                // record a fee (alloy's filler owns the pair), so without this a nonce
                // recycled by a job give-up and then taken by a stake keeps its record, and
                // the ungated watchdog evicts the live stake with a >=4x self-transfer.
                self.note_nonce_in_use(nonce);
                p
            }
            Err(e) => {
                self.abort_nonce(nonce);
                // [review must-fix] An errored send may still have reached the node; if
                // the tx later mines, the aborted nonce sits in `freed` and would be
                // re-issued -> permanent "nonce too low" collision (the setup wizard has
                // no concurrent job task to trigger the self-heal). resync prunes freed
                // below the mined frontier; harmless no-op otherwise. Mirrors the
                // job-path abort→resync pattern. (Match moved outside the tx_lock so the
                // resync read never holds up concurrent senders.)
                self.resync_nonce().await.ok();
                return Err(e).context("Failed to send approve tx");
            }
        };
        let tx_hash = *pending.tx_hash();
        tracing::info!("approve tx sent: {:?}, waiting for receipt...", tx_hash);
        // [RPC #1] Poll for the receipt (no heartbeat watcher). None (no receipt within
        // budget, incl. transient RPC/429) → resync + bail, WITHOUT recycling the nonce.
        // See [R4-A] below: the node accepted this send, so the tx may still be resident.
        let receipt =
            match crate::tx::await_receipt(&*self.provider, tx_hash, TX_RECEIPT_TIMEOUT).await {
                Some(r) => r,
                None => {
                    // [R4-A] Do NOT abort here. The node ACCEPTED this send — only the RECEIPT
                    // was not observed — so the tx may well still be resident. `abort` inserts
                    // into `freed` AND writes an abort record, and the `resync` below cannot undo
                    // either: the stake is unmined, so the mined frontier IS this nonce and
                    // `freed.retain(f >= chain_nonce)` keeps it. That is branch (B)'s literal
                    // trigger, and the watchdog consumes branch (B) ungated — ~45-105s later it
                    // bids max(4x base, 2 gwei) with no floor to lift over (staking records no
                    // fee) and replaces the live stake with a 0-value self-transfer. Nothing
                    // retries: the caller's StakeUnobserved arm deliberately neither re-sends nor
                    // revokes, precisely because "the stake tx may still be in the mempool".
                    //
                    // Leaving the nonce reserved-but-unresolved is now safe: if the tx really was
                    // dropped, [A4]'s branch (A) finds the hole off the node's pending count as
                    // soon as anything is reserved above it, and a restart re-anchors at that same
                    // pending count. Do NOT substitute `note_unresolved` — it writes the abort
                    // record, which is the other half of branch (B)'s disjunction.
                    // [review must-fix] The broadcast tx may mine AFTER the budget; without a
                    // resync the aborted nonce would be re-issued from `freed` → permanent
                    // "nonce too low" collision with no job task around to self-heal.
                    self.resync_nonce().await.ok();
                    anyhow::bail!("approve receipt not confirmed (tx {tx_hash:?})");
                }
            };
        // Mined (success or revert) consumed the nonce.
        self.commit_nonce(nonce);
        if !receipt.status() {
            anyhow::bail!("Approve transaction reverted");
        }
        tracing::info!(
            "HEMI token approval confirmed: {:?}",
            receipt.transaction_hash
        );
        Ok(())
    }

    /// Stake HEMI tokens for a prover.
    pub async fn stake(&self, amount: u128) -> Result<()> {
        let staking = IHemiProveStaking::new(self.hemi_prove_staking, &*self.provider);
        let nonce = self.reserve_nonce().await?; // [#48] explicit nonce via the shared allocator
        let tx = staking.stake(self.address, amount).nonce(nonce);
        let send_result = {
            let _guard = self.tx_lock.lock().await;
            tx.send().await
        };
        let pending = match send_result {
            Ok(p) => {
                // Retire any stale abort record: the node ACCEPTED this send, so the nonce
                // is legitimately in use. These paths share the job allocator but cannot
                // record a fee (alloy's filler owns the pair), so without this a nonce
                // recycled by a job give-up and then taken by a stake keeps its record, and
                // the ungated watchdog evicts the live stake with a >=4x self-transfer.
                self.note_nonce_in_use(nonce);
                p
            }
            // [review must-fix] abort→resync: see approve_hemi_token for rationale.
            Err(e) => {
                self.abort_nonce(nonce);
                self.resync_nonce().await.ok();
                return Err(e).context("Failed to send stake tx");
            }
        };
        let tx_hash = *pending.tx_hash();
        tracing::info!("stake tx sent: {:?}, waiting for receipt...", tx_hash);
        // [RPC #1] Poll for the receipt (no heartbeat watcher); None → resync + bail, and
        // deliberately NO abort — see [R4-A] below.
        let receipt =
            match crate::tx::await_receipt(&*self.provider, tx_hash, TX_RECEIPT_TIMEOUT).await {
                Some(r) => r,
                None => {
                    // [R4-A] Do NOT abort here. The node ACCEPTED this send — only the RECEIPT
                    // was not observed — so the tx may well still be resident. `abort` inserts
                    // into `freed` AND writes an abort record, and the `resync` below cannot undo
                    // either: the stake is unmined, so the mined frontier IS this nonce and
                    // `freed.retain(f >= chain_nonce)` keeps it. That is branch (B)'s literal
                    // trigger, and the watchdog consumes branch (B) ungated — ~45-105s later it
                    // bids max(4x base, 2 gwei) with no floor to lift over (staking records no
                    // fee) and replaces the live stake with a 0-value self-transfer. Nothing
                    // retries: the caller's StakeUnobserved arm deliberately neither re-sends nor
                    // revokes, precisely because "the stake tx may still be in the mempool".
                    //
                    // Leaving the nonce reserved-but-unresolved is now safe: if the tx really was
                    // dropped, [A4]'s branch (A) finds the hole off the node's pending count as
                    // soon as anything is reserved above it, and a restart re-anchors at that same
                    // pending count. Do NOT substitute `note_unresolved` — it writes the abort
                    // record, which is the other half of branch (B)'s disjunction.
                    self.resync_nonce().await.ok(); // [review must-fix] late-mine self-heal
                                                    // Typed, not a string: the caller MUST be able to tell "not observed" from
                                                    // "definitely failed". await_receipt returns None after absorbing RPC errors
                                                    // and 429s (see tx.rs), so the dominant cause is a tx STILL PENDING, not one
                                                    // that failed. Everything the caller would do to clean up — revoke, retry —
                                                    // is destructive against a live tx.
                    return Err(anyhow::Error::new(StakeUnobserved { tx_hash }));
                }
            };
        self.commit_nonce(nonce);
        if !receipt.status() {
            anyhow::bail!("Stake transaction reverted");
        }
        tracing::info!("Staked {} HEMI: {:?}", amount, receipt.transaction_hash);
        Ok(())
    }

    /// Revoke a previously granted allowance by setting it to zero.
    ///
    /// Use this to clean up a dangling approval from a failed approve+stake flow.
    pub async fn revoke_approval(&self, spender: Address) -> Result<()> {
        self.approve_hemi_token(spender, U256::ZERO).await
    }

    /// Mint testnet HEMI tokens. Only callable on the configured Hemi testnet
    /// (chain_id == 743111); refuses on mainnet to avoid wasting gas on a
    /// mint() function that does not exist there.
    pub async fn mint_testnet_tokens(&self, amount: u128) -> Result<()> {
        if self.chain_id != TESTNET_CHAIN_ID {
            anyhow::bail!(
                "Testnet mint is only allowed on Hemi testnet (chain_id {}); this client is connected to chain_id {}",
                TESTNET_CHAIN_ID,
                self.chain_id,
            );
        }
        let token = ITestnetToken::new(self.hemi_token, &*self.provider);
        let nonce = self.reserve_nonce().await?; // [#48] explicit nonce via the shared allocator
        let tx = token.mint(self.address, U256::from(amount)).nonce(nonce);
        let send_result = {
            let _guard = self.tx_lock.lock().await;
            tx.send().await
        };
        let pending = match send_result {
            Ok(p) => {
                // Retire any stale abort record: the node ACCEPTED this send, so the nonce
                // is legitimately in use. These paths share the job allocator but cannot
                // record a fee (alloy's filler owns the pair), so without this a nonce
                // recycled by a job give-up and then taken by a stake keeps its record, and
                // the ungated watchdog evicts the live stake with a >=4x self-transfer.
                self.note_nonce_in_use(nonce);
                p
            }
            // [review must-fix] abort→resync: see approve_hemi_token for rationale.
            Err(e) => {
                self.abort_nonce(nonce);
                self.resync_nonce().await.ok();
                return Err(e).context("Failed to send mint tx — is this a testnet?");
            }
        };
        let tx_hash = *pending.tx_hash();
        tracing::info!("mint tx sent: {:?}, waiting for receipt...", tx_hash);
        // [RPC #1] Poll for the receipt (no heartbeat watcher); None → resync + bail, and
        // deliberately NO abort — see [R4-A] below.
        let receipt =
            match crate::tx::await_receipt(&*self.provider, tx_hash, TX_RECEIPT_TIMEOUT).await {
                Some(r) => r,
                None => {
                    // [R4-A] Do NOT abort here. The node ACCEPTED this send — only the RECEIPT
                    // was not observed — so the tx may well still be resident. `abort` inserts
                    // into `freed` AND writes an abort record, and the `resync` below cannot undo
                    // either: the stake is unmined, so the mined frontier IS this nonce and
                    // `freed.retain(f >= chain_nonce)` keeps it. That is branch (B)'s literal
                    // trigger, and the watchdog consumes branch (B) ungated — ~45-105s later it
                    // bids max(4x base, 2 gwei) with no floor to lift over (staking records no
                    // fee) and replaces the live stake with a 0-value self-transfer. Nothing
                    // retries: the caller's StakeUnobserved arm deliberately neither re-sends nor
                    // revokes, precisely because "the stake tx may still be in the mempool".
                    //
                    // Leaving the nonce reserved-but-unresolved is now safe: if the tx really was
                    // dropped, [A4]'s branch (A) finds the hole off the node's pending count as
                    // soon as anything is reserved above it, and a restart re-anchors at that same
                    // pending count. Do NOT substitute `note_unresolved` — it writes the abort
                    // record, which is the other half of branch (B)'s disjunction.
                    self.resync_nonce().await.ok(); // [review must-fix] late-mine self-heal
                    anyhow::bail!("mint receipt not confirmed (tx {tx_hash:?})");
                }
            };
        self.commit_nonce(nonce);
        if !receipt.status() {
            anyhow::bail!("Mint transaction reverted — token may not have public mint()");
        }
        tracing::info!("Minted {} tHEMI: {:?}", amount, receipt.transaction_hash);
        Ok(())
    }

    /// Convenience: approve + stake in a single call.
    ///
    /// Validates the HEMI balance first (approve on its own does not require
    /// balance, but stake reverts in transferFrom — this avoids a dangling
    /// allowance from a guaranteed-to-fail stake). If stake fails after approve
    /// succeeded, attempts to revoke the residual allowance and reports both
    /// errors so the user isn't left with an invisible standing approval.
    pub async fn approve_and_stake(&self, amount: u128) -> Result<()> {
        let amount_u256 = U256::from(amount);

        // Snapshot the staked total so a failed-looking stake can be checked against
        // on-chain truth below. See the Err arm for why this matters.
        let staked_before = self
            .get_stake_info(self.address)
            .await
            .ok()
            .map(|s| s.total_staked);

        // Pre-flight: must have enough HEMI for the stake itself to succeed.
        let balance = self
            .get_hemi_balance(self.address)
            .await
            .context("Failed to read HEMI balance before staking")?;
        if balance < amount_u256 {
            anyhow::bail!(
                "Insufficient HEMI balance: have {}, need {} (no approval sent)",
                balance,
                amount_u256,
            );
        }

        let current_allowance = self
            .get_hemi_allowance(self.address, self.hemi_prove_staking)
            .await?;
        let did_approve_here = if current_allowance < amount_u256 {
            tracing::info!("Approving {} HEMI for staking contract...", amount);
            self.approve_hemi_token(self.hemi_prove_staking, amount_u256)
                .await?;
            true
        } else {
            false
        };

        match self.stake(amount).await {
            Ok(()) => Ok(()),
            Err(stake_err) => {
                // `await_receipt` returns None for "not observed" — an RPC hiccup or a 429 —
                // NOT for "did not land"; tx.rs tells callers to poll on-chain STATE before
                // acting on it. Every job path does; this one did not. Reporting a stake that
                // landed as a failure is worse than a bare error: nothing stops the operator
                // re-running, and a second stake is locked behind a delayed unstake.
                if let Some(before) = staked_before {
                    if let Ok(after) = self.get_stake_info(self.address).await {
                        if after.total_staked >= before.saturating_add(amount) {
                            tracing::warn!(
                                "stake receipt was not observed, but on-chain staked total rose \
                                 {} -> {} — the stake DID land. Not retrying, not revoking.",
                                before,
                                after.total_staked,
                            );
                            return Ok(());
                        }
                    }
                }
                // The stake tx may still be in the mempool. Revoking now would be actively
                // harmful, and not only because the allowance is still needed: [R4-A] leaves
                // the stake's nonce N reserved-but-UNRESOLVED — deliberately not in `freed` —
                // so the revoke would reserve a FRESH nonce above N and queue behind it. It
                // cannot mine until the stake does, and if the stake was in fact dropped it
                // never mines at all, leaving a second unresolved nonce stacked on the first.
                // A dangling one-stake allowance is far cheaper than evicting the stake.
                //
                // (This previously described a `freed`-reissue race at N. That mechanism was
                // real before [R4-A] removed the abort; the conclusion held, the reason did
                // not. Fourth comment in this file found asserting the pre-[R4-A] behaviour.)
                if stake_err.downcast_ref::<StakeUnobserved>().is_some() {
                    if did_approve_here {
                        tracing::warn!(
                            "Leaving the {} HEMI allowance in place: the stake tx was not \
                             observed and may still be pending. Revoking now could evict it.",
                            amount,
                        );
                    }
                    return Err(stake_err);
                }
                if !did_approve_here {
                    return Err(stake_err);
                }
                // approve landed but stake definitively failed — revoke the residual allowance.
                tracing::error!(
                    "stake() failed after approve() succeeded; attempting to revoke allowance to avoid dangling approval"
                );
                match self.revoke_approval(self.hemi_prove_staking).await {
                    Ok(()) => Err(stake_err.context(
                        "Stake failed; previously-granted allowance was revoked",
                    )),
                    Err(revoke_err) => Err(stake_err.context(format!(
                        "Stake failed AND revoke of residual allowance failed: {revoke_err:#}. Manually set allowance to 0 via approve({}, 0).",
                        self.hemi_prove_staking
                    ))),
                }
            }
        }
    }
}

/// The stake tx was accepted by the node but no receipt was observed within the timeout.
///
/// This is NOT "the stake failed" — it is "we do not know". `tx::await_receipt` returns
/// None after swallowing transient RPC errors and 429s, so the likeliest state is a tx
/// still sitting in the mempool. Callers must treat it as unresolved: do not revoke, do
/// not re-broadcast, and do not tell the operator that no funds moved.
#[derive(Debug)]
pub struct StakeUnobserved {
    pub tx_hash: alloy::primitives::TxHash,
}

impl std::fmt::Display for StakeUnobserved {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "stake receipt not confirmed (tx {:?}) — it MAY STILL BE PENDING; check the \
             staked total on-chain before retrying",
            self.tx_hash
        )
    }
}

impl std::error::Error for StakeUnobserved {}

// ─────────────────────────────────────────────────────────────────────────────
// Collateral headroom — "can I actually feed all my GPUs?"
// ─────────────────────────────────────────────────────────────────────────────

/// Render a wei amount as HEMI with 2 decimals, rounded UP.
///
/// Lives here, beside the `Headroom` that produces the shortfall, because THREE call sites
/// paste this exact string into `zkminer stake`: the headless log, the TUI log pane, and the
/// dashboard verdict. Two hand-maintained copies of the same sentence is how the log copy
/// once told operators to `stake 1` when they were 4.25 short; two copies of the ROUNDING
/// would be the same class of bug, and silent — a floored copy renders S as S-e, and staking
/// S-e leaves the slot unfundable with the warning repeating at "short ~0.00".
pub fn fmt_hemi_ceil(wei: u128) -> String {
    const ONE_HEMI_WEI: u128 = 1_000_000_000_000_000_000;
    let unit = ONE_HEMI_WEI / 100;
    let cents = wei / unit + u128::from(!wei.is_multiple_of(unit));
    format!("{}.{:02}", cents / 100, cents % 100)
}

/// How many proving slots the operator's collateral can currently fund.
///
/// WHY THIS EXISTS: a miner can lose ~50% of throughput indefinitely with no warning.
/// Observed live 2026-08-08 — 2 GPUs, `max_concurrent_proofs=2`, but `in_flight` never
/// exceeded 1/2 because available collateral was 295.75 HEMI against the 300.00 needed for
/// two concurrent claims. Short by 4.25 HEMI, with 444,804 HEMI sitting in the wallet. The
/// miner logged 2,851 DEBUG skips and ZERO warnings, because the warning was gated on
/// "claimed nothing this tick" and so only ever detected TOTAL starvation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Headroom {
    /// Slots we can fund right now: those already running, plus what the free collateral buys.
    pub fundable: usize,
    /// Slots we WANT to fund — `min(max_concurrent_proofs, detected proving GPUs)`.
    pub wanted: usize,
    /// HEMI needed to fund ONE more slot. Zero when not short.
    pub shortfall: u128,
}

impl Headroom {
    /// True when collateral — not the market, not a dead worker — is what is idling a GPU.
    /// Callers MUST additionally require that a job was actually blocked for collateral,
    /// or this cries wolf on an empty market.
    pub fn is_starved(&self) -> bool {
        self.fundable < self.wanted
    }
}

/// Compute headroom from the **on-chain** available figure.
///
/// `available` MUST be `StakeInfo::available_collateral` **less anything reserved since that
/// snapshot was taken**, and `funded` MUST count the SAME set. Pairing a tick-start
/// `available` with a post-claim `funded` counts this tick's claims twice and inflates
/// `fundable` by exactly the number of claims made — which silently cancels a one-slot
/// shortfall, i.e. precisely the 2026-08-08 incident. It is NOT the brain's tick residual
/// either (that is the D17 double-count in the other direction).
/// Measured against the live contract: `locked` already includes live in-flight locks
/// (`in_flight 2/2` → locked = baseline + 2 x per_claim), so `available` already nets them.
/// The brain additionally subtracts `Σ(in_flight)` on purpose — the documented "D17"
/// fail-safe at `run.rs:1938-1958` — which double-counts by up to one reservation. Feeding
/// that residual in here would inherit the double-count and over-warn.
///
/// `per_claim` is an UPPER bound (the auction gate reserves at `max_price`), so `fundable`
/// is conservative and `shortfall` is a ceiling. Say so when reporting it.
///
/// `anything_affordable`: false when the tick could not fund even one claim. Without this,
/// a tiny `per_claim` fallback makes `fundable` clamp to `wanted` and silently re-hides
/// TOTAL starvation — the one case the old predicate did catch.
pub fn collateral_headroom(
    available: u128,
    per_claim: u128,
    funded: usize,
    wanted: usize,
    anything_affordable: bool,
) -> Headroom {
    if per_claim == 0 {
        // No basis to judge; report "not starved" rather than invent a verdict.
        return Headroom {
            fundable: wanted,
            wanted,
            shortfall: 0,
        };
    }
    let extra = if anything_affordable {
        (available / per_claim) as usize
    } else {
        0
    };
    let fundable = funded.saturating_add(extra).min(wanted);
    // Deficit for ONE more slot, on the non-saturating on-chain figure. Deliberately NOT
    // `wanted * per_claim - available`, which re-charges for slots already funded: in the
    // incident that reads 154.25 instead of 4.25 — a 36x over-recommendation into a contract
    // whose exit is delayed.
    // Marginal cost of the NEXT slot. `per_claim - available` is only correct while
    // `available < per_claim`; once `available >= per_claim` it saturates to 0 and the
    // message becomes "short ~0.00 HEMI … stake more", which is self-contradictory and
    // unactionable. Reachable on a 4-slot rig with available=250, per_claim=100: two slots
    // fundable, true cost of the third is 50, old formula said 0.
    // The remainder form is correct in both regimes and yields `per_claim` on an exact
    // multiple, which is right — a full further claim must be funded.
    let shortfall = if fundable >= wanted {
        0
    } else if !anything_affordable {
        // The veto says this tick could not fund even ONE claim, so `available % per_claim`
        // is demonstrably not spendable toward the next slot — crediting it understates the
        // ask, and following the understated advice makes the number go UP on the next tick:
        //   (195, per_claim 50, affordable=false) -> "short 5.00"
        //   stake 5 -> (200, ...)                 -> "short 50.00"
        // Two stop/stake/restart cycles, wrong both times. A full claim is the honest ask.
        // (The incident replay passes either way only by coincidence: there Σ(in_flight) was
        // exactly 1 x per_claim, so the remainder happened to equal the residual.)
        per_claim
    } else {
        // Marginal cost of the NEXT slot, correct in both regimes; yields `per_claim` on an
        // exact multiple, which is right — a full further claim must be funded.
        per_claim - (available % per_claim)
    };
    Headroom {
        fundable,
        wanted,
        shortfall,
    }
}

#[cfg(test)]
mod headroom_tests {

    /// Obeying the advice must BUY something: either it funds another slot, or the ask does
    /// not grow. Both together failing is the defect — with the tick veto set, `shortfall`
    /// credited `available % per_claim` toward a slot the veto had just declared unfundable,
    /// so "short 5.00" became "short 50.00" after staking 5 with NO slot gained. Two
    /// stop/stake/restart cycles, wrong number both times.
    ///
    /// Note the ask legitimately GROWS when progress was made: at available 250 / per_claim
    /// 100 / wanted 4, staking the advised 50 buys the third slot and the fourth then costs a
    /// full 100. That is the advice working, not failing — which is why the assertion is
    /// "progress OR no increase" and not the tempting "never increases".
    #[test]
    fn following_the_advice_never_increases_the_shortfall() {
        const HEMI: u128 = 1_000_000_000_000_000_000;
        for (available, per_claim, funded, wanted, affordable) in [
            (195 * HEMI, 50 * HEMI, 1, 2, false), // the reported case
            (295 * HEMI, 10 * HEMI, 0, 2, false), // total starvation, tiny per_claim
            (145 * HEMI, 150 * HEMI, 1, 2, true), // the 2026-08-08 incident
            (250 * HEMI, 100 * HEMI, 0, 4, true), // multi-slot, remainder regime
            (0, 50 * HEMI, 0, 2, false),
        ] {
            let h = collateral_headroom(available, per_claim, funded, wanted, affordable);
            if !h.is_starved() {
                continue;
            }
            assert!(h.shortfall > 0, "starved but asked for nothing: {h:?}");
            // Stake exactly what we were told, then re-evaluate on the same basis.
            let after = collateral_headroom(
                available + h.shortfall,
                per_claim,
                funded,
                wanted,
                affordable,
            );
            let progressed = after.fundable > h.fundable;
            assert!(
                progressed || after.shortfall <= h.shortfall,
                "advice bought nothing AND raised the ask: {} -> {} with fundable stuck at {} \
                 (available {available}, per_claim {per_claim}, affordable {affordable})",
                h.shortfall,
                after.shortfall,
                h.fundable,
            );
        }
    }
    use super::*;
    const H: u128 = 1_000_000_000_000_000_000; // 1 HEMI

    /// The live incident, replayed. Must report 1-of-2 and a 4.25 HEMI shortfall.
    #[test]
    fn replays_the_2026_08_08_incident() {
        // 1 job live; on-chain available already nets its 150 lock.
        let h = collateral_headroom(145_750 * H / 1000, 150 * H, 1, 2, true);
        assert_eq!(h.fundable, 1, "second slot is not fundable");
        assert_eq!(h.wanted, 2);
        assert!(h.is_starved());
        assert_eq!(h.shortfall, 4_250 * H / 1000, "must be 4.25, not 154.25");
    }

    /// The call site pairs a TICK-START `available` with a POST-claim `funded`. Netting out
    /// this tick's reservations is what makes the two describe the same instant; without it
    /// `fundable` is inflated by the number of claims made and a one-slot shortfall — the
    /// 2026-08-08 incident — is silently cancelled.
    #[test]
    fn tick_start_available_must_be_net_of_this_ticks_claims() {
        let avail_tick_start = 295_750 * H / 1000;
        let per_claim = 150 * H;
        // WRONG pairing (what the first implementation did): reports healthy.
        let wrong = collateral_headroom(avail_tick_start, per_claim, 1, 2, true);
        assert!(
            !wrong.is_starved(),
            "documents the bug: silent on the incident tick"
        );
        // RIGHT pairing: available net of the claim just made.
        let right = collateral_headroom(avail_tick_start - per_claim, per_claim, 1, 2, true);
        assert!(right.is_starved(), "must detect the incident");
        assert_eq!(right.shortfall, 4_250 * H / 1000);
    }

    /// `shortfall` is the MARGINAL cost of the next slot in BOTH regimes. The old
    /// `per_claim - available` saturated to 0 whenever available >= per_claim, producing
    /// "short ~0.00 HEMI ... stake more".
    #[test]
    fn shortfall_is_marginal_even_when_available_exceeds_one_claim() {
        let h = collateral_headroom(250 * H, 100 * H, 0, 4, true);
        assert_eq!(h.fundable, 2);
        assert!(h.is_starved());
        assert_eq!(h.shortfall, 50 * H, "cost of the 3rd slot, not 0");
    }

    /// A rich wallet that declined on profit/risk must NOT be told to stake.
    #[test]
    fn rich_wallet_declining_on_profit_is_not_a_stake_problem() {
        // any_affordable=true because collateral was fine; the skips were for other reasons.
        let h = collateral_headroom(10_000 * H, 150 * H, 0, 2, true);
        assert!(
            !h.is_starved(),
            "plenty of collateral: not a staking problem"
        );
    }

    #[test]
    fn healthy_when_collateral_suffices() {
        let h = collateral_headroom(795 * H, 150 * H, 0, 2, true);
        assert_eq!((h.fundable, h.shortfall), (2, 0));
        assert!(!h.is_starved());
    }

    /// Regression for the fallback that re-hid TOTAL starvation: with a tiny `per_claim`
    /// the division would clamp `fundable` to `wanted` and report healthy.
    #[test]
    fn total_starvation_is_not_masked_by_a_tiny_per_claim() {
        let h = collateral_headroom(295 * H, 10 * H, 0, 2, /* anything_affordable */ false);
        assert_eq!(
            h.fundable, 0,
            "nothing was affordable, so nothing is fundable"
        );
        assert!(h.is_starved());
    }

    #[test]
    fn never_divides_by_zero_and_never_exceeds_wanted() {
        assert!(!collateral_headroom(0, 0, 0, 2, true).is_starved());
        let h = collateral_headroom(10_000 * H, 1 * H, 1, 2, true);
        assert_eq!(h.fundable, 2, "clamped to wanted");
    }

    #[test]
    fn zero_wanted_is_never_starved() {
        assert!(!collateral_headroom(0, 150 * H, 0, 0, true).is_starved());
    }
}
