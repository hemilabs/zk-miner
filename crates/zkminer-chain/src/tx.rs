//! Transaction management utilities.

use alloy::primitives::{B256, U256};
use alloy::providers::Provider;
use alloy::rpc::types::TransactionReceipt;
use anyhow::Result;
use std::time::{Duration, Instant};

/// Default timeout for waiting for a transaction receipt (120 seconds).
pub const TX_RECEIPT_TIMEOUT: Duration = Duration::from_secs(120);

/// Base interval between receipt polls in [`await_receipt`].
const RECEIPT_POLL_BASE: Duration = Duration::from_secs(6);

/// Wait for a transaction's receipt by POLLING `eth_getTransactionReceipt`, without ever
/// registering alloy's `PendingTransaction` watcher.
///
/// Why this exists: calling `pending.get_receipt()` registers a watcher that unpauses a
/// *process-wide* heartbeat which fires `eth_blockNumber` every ~7s **plus a back-to-back
/// `eth_getBlockByNumber` for every chain block** for as long as ANY tx is pending — the
/// single burstiest RPC shape the miner produces. Polling one `eth_getTransactionReceipt`
/// on a ~6s jittered timer instead removes that heartbeat entirely and issues far fewer,
/// non-bursty requests (and they ride the outer throttle).
///
/// Semantics — deliberately two-state, folding the old `get_receipt()` tri-state:
///   * `Some(receipt)` — the tx mined (caller inspects `receipt.status()` exactly as
///     before for the `commit_nonce` / mined-revert branch).
///   * `None` — the budget elapsed without a receipt. This absorbs BOTH the old timeout
///     arm AND the old `Ok(Err(rpc))` arm: a transient RPC/429 error is swallowed and
///     retried inside the budget rather than surfacing as an immediate same-nonce
///     re-broadcast. Callers must treat `None` as "poll on-chain STATE before
///     re-broadcasting" — which is strictly safer and never amplifies a rate-limit storm.
///
/// Sleeps BEFORE the first poll (a just-sent tx is never mined instantly). The jitter is
/// derived from the tx hash (no `rand` dependency) so N concurrent lifecycles' polls do
/// not align into the same second. Worst-case added receipt latency is one poll interval
/// (~6-8s) against 120s+ budgets and hour-scale deadlines.
pub async fn await_receipt<P: Provider>(
    provider: &P,
    tx_hash: B256,
    budget: Duration,
) -> Option<TransactionReceipt> {
    let deadline = Instant::now() + budget;
    // 0..~2s deterministic per-tx jitter (two hash bytes XORed so cadence collisions
    // need a 2-byte coincidence, not just a shared first byte).
    let jitter =
        Duration::from_millis((tx_hash.0[0] ^ tx_hash.0[31]) as u64 * 2000 / 255);
    loop {
        let now = Instant::now();
        if now >= deadline {
            return None;
        }
        let wait = (RECEIPT_POLL_BASE + jitter).min(deadline.saturating_duration_since(now));
        tokio::time::sleep(wait).await;
        // [review must-fix] Clamp the poll ITSELF to the remaining budget. The old
        // tokio::time::timeout(budget, get_receipt()) hard-cancelled the whole wait at
        // the budget; without this clamp the final in-flight poll could run up to the
        // 45s transport timeout PAST a deadline-derived budget (fulfill's recv_budget /
        // the batch WALL_CAP), overrunning the guarantee callers rely on. Mirrors the
        // clamp the sibling state-poll reads already apply.
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return None;
        }
        match tokio::time::timeout(remaining, provider.get_transaction_receipt(tx_hash)).await {
            Ok(Ok(Some(receipt))) => return Some(receipt),
            Ok(Ok(None)) => continue, // not mined yet
            Ok(Err(_)) => continue,   // transient RPC/429 — retry within budget, never surface
            Err(_) => return None,    // budget exhausted mid-call — honor the hard bound
        }
    }
}

/// Configuration for transaction submission.
#[derive(Debug, Clone)]
pub struct TxConfig {
    /// Maximum number of retries on transient failures.
    pub max_retries: u32,
    /// Base delay between retries (exponential backoff).
    pub retry_delay: Duration,
    /// Gas price multiplier (1.0 = default, 1.2 = 20% premium).
    pub gas_price_multiplier: f64,
    /// Maximum gas price willing to pay (in wei).
    pub max_gas_price: Option<U256>,
}

impl Default for TxConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            retry_delay: Duration::from_secs(2),
            gas_price_multiplier: 1.1,
            max_gas_price: None,
        }
    }
}

/// Wait for a transaction with exponential backoff retry on failure.
pub async fn retry_with_backoff<F, Fut, T>(
    config: &TxConfig,
    operation_name: &str,
    f: F,
) -> Result<T>
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = Result<T>>,
{
    let mut last_error = None;

    for attempt in 0..=config.max_retries {
        match f().await {
            Ok(result) => return Ok(result),
            Err(e) => {
                let delay = config.retry_delay * 2u32.pow(attempt);
                tracing::warn!(
                    "{} attempt {} failed: {}. Retrying in {:?}",
                    operation_name,
                    attempt + 1,
                    e,
                    delay
                );
                last_error = Some(e);
                if attempt < config.max_retries {
                    tokio::time::sleep(delay).await;
                }
            }
        }
    }

    Err(last_error.unwrap_or_else(|| anyhow::anyhow!("{} failed after retries", operation_name)))
}
