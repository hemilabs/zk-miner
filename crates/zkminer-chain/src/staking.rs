use alloy::primitives::{Address, U256};
use anyhow::{Context, Result};

use crate::tx::TX_RECEIPT_TIMEOUT;
use zkminer_contracts::bindings::{IHemiProveStaking, IERC20, ITestnetToken};

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

        let stake = staking.getProverStake(prover).call().await
            .context("Failed to get prover stake")?;
        let available = staking.getAvailableCollateral(prover).call().await
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

        let stats = staking.getProverStats(prover).call().await
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
        let balance = token.balanceOf(account).call().await
            .context("Failed to get HEMI balance")?;
        Ok(balance)
    }

    /// Get HEMI token allowance for the staking contract.
    pub async fn get_hemi_allowance(&self, owner: Address, spender: Address) -> Result<U256> {
        let token = IERC20::new(self.hemi_token, &*self.provider);
        let allowance = token.allowance(owner, spender).call().await
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
            Ok(p) => p,
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
        // budget, incl. transient RPC/429) → abort the nonce + bail, exactly as the old
        // timeout/RPC-error arms did (a one-shot staking tx is never re-broadcast).
        let receipt = match crate::tx::await_receipt(&*self.provider, tx_hash, TX_RECEIPT_TIMEOUT).await {
            Some(r) => r,
            None => {
                self.abort_nonce(nonce);
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
        tracing::info!("HEMI token approval confirmed: {:?}", receipt.transaction_hash);
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
            Ok(p) => p,
            // [review must-fix] abort→resync: see approve_hemi_token for rationale.
            Err(e) => {
                self.abort_nonce(nonce);
                self.resync_nonce().await.ok();
                return Err(e).context("Failed to send stake tx");
            }
        };
        let tx_hash = *pending.tx_hash();
        tracing::info!("stake tx sent: {:?}, waiting for receipt...", tx_hash);
        // [RPC #1] Poll for the receipt (no heartbeat watcher); None → abort + resync + bail.
        let receipt = match crate::tx::await_receipt(&*self.provider, tx_hash, TX_RECEIPT_TIMEOUT).await {
            Some(r) => r,
            None => {
                self.abort_nonce(nonce);
                self.resync_nonce().await.ok(); // [review must-fix] late-mine self-heal
                anyhow::bail!("stake receipt not confirmed (tx {tx_hash:?})");
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
            Ok(p) => p,
            // [review must-fix] abort→resync: see approve_hemi_token for rationale.
            Err(e) => {
                self.abort_nonce(nonce);
                self.resync_nonce().await.ok();
                return Err(e).context("Failed to send mint tx — is this a testnet?");
            }
        };
        let tx_hash = *pending.tx_hash();
        tracing::info!("mint tx sent: {:?}, waiting for receipt...", tx_hash);
        // [RPC #1] Poll for the receipt (no heartbeat watcher); None → abort + resync + bail.
        let receipt = match crate::tx::await_receipt(&*self.provider, tx_hash, TX_RECEIPT_TIMEOUT).await {
            Some(r) => r,
            None => {
                self.abort_nonce(nonce);
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

        // Pre-flight: must have enough HEMI for the stake itself to succeed.
        let balance = self
            .get_hemi_balance(self.address)
            .await
            .context("Failed to read HEMI balance before staking")?;
        if balance < amount_u256 {
            anyhow::bail!(
                "Insufficient HEMI balance: have {}, need {} (no approval sent)",
                balance, amount_u256,
            );
        }

        let current_allowance = self.get_hemi_allowance(self.address, self.hemi_prove_staking).await?;
        let did_approve_here = if current_allowance < amount_u256 {
            tracing::info!("Approving {} HEMI for staking contract...", amount);
            self.approve_hemi_token(self.hemi_prove_staking, amount_u256).await?;
            true
        } else {
            false
        };

        match self.stake(amount).await {
            Ok(()) => Ok(()),
            Err(stake_err) => {
                if !did_approve_here {
                    return Err(stake_err);
                }
                // approve landed but stake failed — try to revoke the residual allowance.
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
