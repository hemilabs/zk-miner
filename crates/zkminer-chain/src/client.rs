use alloy::{
    network::EthereumWallet,
    primitives::Address,
    providers::{Provider, ProviderBuilder, RootProvider, fillers::{
        BlobGasFiller, ChainIdFiller, FillProvider, GasFiller, JoinFill, NonceFiller,
        WalletFiller,
    }, Identity},
    signers::local::PrivateKeySigner,
};
use anyhow::{Context, Result};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use zkminer_config::ZkMinerConfig;

/// Concrete provider type returned by ProviderBuilder::new().wallet().connect_http().
pub type HttpProvider = FillProvider<
    JoinFill<
        JoinFill<
            Identity,
            JoinFill<GasFiller, JoinFill<BlobGasFiller, JoinFill<NonceFiller, ChainIdFiller>>>,
        >,
        WalletFiller<EthereumWallet>,
    >,
    RootProvider,
>;

/// Default explicit gas limit for `fulfillJob` txs (INTERACTION_GUIDE §9). The
/// router's registry-adapter settlement preflight needs `gasleft() >= 4.6M`
/// (`CUSTOM_VERIFIER_GAS_LIMIT*2 + 500k + 100k`) INSIDE the diamond; the 63/64
/// rule across the router's delegatecall layers eats a 5M outer limit below
/// that (confirmed on Hemi testnet: 5M → InsufficientGasForFullSettlement).
/// 10M leaves ample headroom; unused gas is refunded, so this only sets a cap.
pub const DEFAULT_FULFILL_GAS_LIMIT: u64 = 10_000_000;

/// The main chain client wrapping alloy provider + signer.
#[derive(Clone)]
pub struct ChainClient {
    pub provider: Arc<HttpProvider>,
    pub signer: PrivateKeySigner,
    pub address: Address,
    pub chain_id: u64,
    pub hemi_prove: Address,
    pub hemi_prove_staking: Address,
    pub hemi_prove_registry: Address,
    pub hemi_token: Address,
    pub program_registry: Option<Address>,
    /// Legacy gas price (wei) forced on all txs, or None for automatic pricing.
    pub gas_price: Option<u128>,
    /// Explicit gas LIMIT for fulfillJob txs. The router's on-chain preflight
    /// (`gasleft() < CUSTOM_VERIFIER_GAS_LIMIT*2 + SETTLEMENT_GAS_BUFFER + 100k`
    /// ≈ 4.6M) reverts `InsufficientGasForFullSettlement()` if the tx is
    /// under-provisioned — and eth_estimateGas under-provisions this check.
    /// Default 5_000_000 per INTERACTION_GUIDE §9; bump for verifier-heavy paths.
    pub fulfill_gas_limit: u64,
    /// Serializes nonce assignment across concurrent tx submissions from this
    /// account, so two in-flight jobs never grab the same nonce. Held only around
    /// nonce-fetch + send (not the receipt wait), so proofs still run in parallel.
    pub tx_lock: Arc<tokio::sync::Mutex<()>>,
    /// Latest chain head, refreshed by the job monitor each poll (~5s). Shared
    /// across clones so other tasks read it instead of each making their own
    /// `eth_blockNumber` call. 0 = not yet populated.
    head_block: Arc<AtomicU64>,
    /// Single-signer nonce allocator: hands DISTINCT nonces to concurrent tx tasks (so a
    /// re-broadcast can only displace the task's OWN stuck tx, never a sibling's healthy
    /// one), recycles aborted-reservation gaps, and re-syncs on external nonce jumps. See
    /// [`crate::nonce`]. Shared across clones.
    nonce_mgr: Arc<crate::nonce::NonceManager>,
    /// Explicit fulfill→release nonce handoff (keyed by jobId). When `fulfill_job` gives
    /// up with its tx likely still pending at nonce N, it STASHES N here; `release_job`
    /// for the same job takes N and re-broadcasts `releaseJob` at that exact nonce to
    /// DISPLACE the stuck fulfill (with the distinct-nonce allocator, `release` would
    /// otherwise get a fresh nonce and queue behind the stuck fulfill → strand).
    abandoned_fulfill_nonces:
        Arc<std::sync::Mutex<std::collections::HashMap<alloy::primitives::B256, u64>>>,
    /// Cache of ProgramRegistry metadata keyed by programId. Registered program
    /// metadata is immutable, so once fetched we never re-query the registry for
    /// the same program. Shared across clones.
    pub(crate) program_info_cache: Arc<
        std::sync::Mutex<
            std::collections::HashMap<alloy::primitives::B256, crate::programs::ProgramInfo>,
        >,
    >,
    /// Counts every JSON-RPC request sent to the endpoint (total + rolling minute).
    rpc_meter: Arc<crate::rpc_meter::RpcMeter>,
    /// [RPC #2] jobId → submitting tx hash, written by the monitor as it parses
    /// JobSubmitted logs (the log already carries `transaction_hash`, so populating
    /// this costs ZERO extra requests). Read by the descriptor fast path
    /// ([`crate::descriptor::fetch_job_descriptor_checked`]) to replace the
    /// 500k-block `eth_getLogs` scan with one `eth_getTransactionByHash`. Sound
    /// because exactly ONE JobSubmitted is ever emitted per jobId (jobId is derived
    /// from a monotonic index and reopen does not re-emit), so the cached tx IS the
    /// tx the scan would find. FIFO-bounded; a miss just uses the scan fallback.
    submit_tx_cache: Arc<std::sync::Mutex<SubmitTxCache>>,
}

/// FIFO-bounded jobId → submit-tx-hash map (see `ChainClient::submit_tx_cache`).
#[derive(Debug, Default)]
pub(crate) struct SubmitTxCache {
    map: std::collections::HashMap<alloy::primitives::B256, alloy::primitives::B256>,
    order: std::collections::VecDeque<alloy::primitives::B256>,
}

/// Bound on the submit-tx cache. Large enough to cover every job a long-running
/// miner could plausibly still need a descriptor for (open candidates + in-flight +
/// recovery window); old entries evict FIFO and simply fall back to the log scan.
const SUBMIT_TX_CACHE_CAP: usize = 2048;

impl SubmitTxCache {
    fn insert(&mut self, job_id: alloy::primitives::B256, tx_hash: alloy::primitives::B256) {
        if self.map.insert(job_id, tx_hash).is_none() {
            self.order.push_back(job_id);
            while self.order.len() > SUBMIT_TX_CACHE_CAP {
                if let Some(old) = self.order.pop_front() {
                    self.map.remove(&old);
                }
            }
        }
    }
}

/// Result of [`ChainClient::get_refresh_batch`]. Each field is `None` if its
/// sub-call in the multicall failed, so a single reverting read never discards the
/// other reads (they share one block snapshot). A total RPC failure is surfaced as
/// `Err` from `get_refresh_batch` instead.
#[derive(Debug, Default, Clone)]
pub struct RefreshData {
    pub head: Option<u64>,
    pub eth_balance: Option<alloy::primitives::U256>,
    pub hemi_balance: Option<alloy::primitives::U256>,
    pub stake: Option<crate::staking::StakeInfo>,
    /// Prover lifetime stats. Included so startup hydration and the periodic refresh both
    /// get it in the SAME multicall (no separate getProverStats round-trip).
    pub stats: Option<crate::staking::ProverStatistics>,
}

impl ChainClient {
    /// Create a new ChainClient from config + signer.
    pub async fn new(config: &ZkMinerConfig, signer: PrivateKeySigner) -> Result<Self> {
        let address = signer.address();
        let wallet = EthereumWallet::from(signer.clone());

        let rpc_url = config.chain.rpc_url.parse().context("Invalid RPC URL")?;

        // Install an RPC meter layer so we can report request volume (it counts
        // every JSON-RPC call, including alloy-internal receipt/gas/nonce calls).
        let rpc_meter = crate::rpc_meter::RpcMeter::new();
        // [D4] Transport-level timeouts so NO RPC await can hang forever. A
        // black-holing endpoint (TCP accepted, no HTTP response — the documented
        // flaky-testnet failure) would otherwise wedge any await indefinitely: the
        // post-claim lockDeadline read, the serial startup-recovery loop, the batch
        // reconcile read. Any of those hanging strands collateral past its deadline to
        // a keeper slash with no in-session recovery. A per-request ceiling bounds
        // every call at the transport layer, beneath every caller, so a stalled
        // endpoint fails fast (Err, handled by the existing retry/poll paths) instead
        // of blocking forever. 45s is well above a healthy call yet finite.
        let http_client = alloy::transports::http::reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(45))
            .connect_timeout(std::time::Duration::from_secs(10))
            .build()
            .context("Failed to build HTTP client with timeouts")?;
        let http = alloy::transports::http::Http::with_client(http_client, rpc_url);
        // [RPC-1/2] Two burst-shaping measures against the public endpoint's ~5 req/s
        // per-second cap (which tripped at only ~70 req/min sustained because concurrent
        // lifecycles + the monitor/refresh loops fired in the same second):
        //  - ThrottleLayer (OUTERMOST, MeterLayer innermost so genuine 429s still reach
        //    the meter) paces dispatch to <=4/s, structurally preventing same-second
        //    spikes regardless of concurrency. Steady state (~1-2/s) is untouched.
        //  - with_poll_interval(12s) widens alloy's watcher heartbeat cadence. NOTE: on
        //    the `run` path this is now DEFENSE-IN-DEPTH ONLY — no code registers the
        //    watcher anymore (every receipt wait goes through crate::tx::await_receipt,
        //    which polls eth_getTransactionReceipt directly and never unpauses the
        //    heartbeat). The interval still governs any future/one-off get_receipt()
        //    caller (e.g. the sp1_demo command). Do NOT reintroduce get_receipt() in the
        //    miner paths believing this interval makes it cheap — use await_receipt.
        let rpc_client = alloy::rpc::client::ClientBuilder::default()
            .layer(crate::rpc_meter::ThrottleLayer::new(4))
            .layer(crate::rpc_meter::MeterLayer::new(rpc_meter.clone()))
            .transport(http, false)
            .with_poll_interval(std::time::Duration::from_secs(12));
        let provider = ProviderBuilder::new()
            .wallet(wallet)
            .connect_client(rpc_client);

        let hemi_prove: Address = config
            .contracts
            .hemi_prove
            .parse()
            .context("Invalid hemi_prove address")?;
        let hemi_prove_staking: Address = config
            .contracts
            .hemi_prove_staking
            .parse()
            .context("Invalid hemi_prove_staking address")?;
        let hemi_prove_registry: Address = config
            .contracts
            .hemi_prove_registry
            .parse()
            .context("Invalid hemi_prove_registry address")?;
        let hemi_token: Address = config
            .contracts
            .hemi_token
            .parse()
            .context("Invalid hemi_token address")?;

        let program_registry: Option<Address> = if config.contracts.program_registry.is_empty() {
            None
        } else {
            Some(
                config
                    .contracts
                    .program_registry
                    .parse()
                    .context("Invalid program_registry address")?,
            )
        };

        // Verify the RPC's chain_id matches what the config claims. Prevents
        // silent misconfiguration (e.g., testnet config pointed at mainnet RPC)
        // which would cause EIP-712 signatures to fail on-chain and wasted gas
        // on testnet-only guards like mint_testnet_tokens.
        let rpc_chain_id = provider
            .get_chain_id()
            .await
            .context("Failed to query RPC chain_id at startup")?;
        if rpc_chain_id != config.chain.chain_id {
            anyhow::bail!(
                "Chain ID mismatch: config says {}, RPC reports {}. \
                 Update config.chain.chain_id or point rpc_url at the correct network.",
                config.chain.chain_id, rpc_chain_id,
            );
        }

        let gas_price = config
            .chain
            .gas_price_gwei
            .map(|g| (g * 1e9).round() as u128);

        let fulfill_gas_limit = config.chain.fulfill_gas_limit.unwrap_or(DEFAULT_FULFILL_GAS_LIMIT);

        Ok(Self {
            provider: Arc::new(provider),
            signer,
            address,
            chain_id: config.chain.chain_id,
            hemi_prove,
            hemi_prove_staking,
            hemi_prove_registry,
            hemi_token,
            program_registry,
            gas_price,
            fulfill_gas_limit,
            tx_lock: Arc::new(tokio::sync::Mutex::new(())),
            head_block: Arc::new(AtomicU64::new(0)),
            program_info_cache: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            submit_tx_cache: Arc::new(std::sync::Mutex::new(SubmitTxCache::default())),
            nonce_mgr: Arc::new(crate::nonce::NonceManager::new()),
            abandoned_fulfill_nonces: Arc::new(std::sync::Mutex::new(Default::default())),
            rpc_meter,
        })
    }

    /// Shared RPC request meter (total + rolling-minute counts).
    pub fn rpc_meter(&self) -> Arc<crate::rpc_meter::RpcMeter> {
        self.rpc_meter.clone()
    }

    /// Reserve a DISTINCT nonce for one tx operation. Each concurrent lifecycle task gets
    /// its own nonce (a recycled gap first, else the next fresh one), so no two tasks
    /// share a nonce and a re-broadcast can only displace the task's OWN stuck predecessor.
    /// The caller owns the returned nonce across its retry loop and must, on completion,
    /// call exactly one of [`commit_nonce`](Self::commit_nonce) (mined),
    /// [`abort_nonce`](Self::abort_nonce) (definitively did not land — recycle the gap),
    /// or hand it to `release_job` (fulfill→release displacement).
    pub async fn reserve_nonce(&self) -> Result<u64> {
        // Fast path: already synced.
        if let Some(n) = self.nonce_mgr.try_reserve() {
            return Ok(n);
        }
        // Unsynced → fetch the chain nonce and anchor. Loop to resolve a race where a
        // concurrent task anchors first (then our anchor returns None → retry try_reserve).
        loop {
            let chain = self
                .provider
                .get_transaction_count(self.address)
                .pending()
                .await
                .context("Failed to fetch nonce")?;
            if let Some(n) = self.nonce_mgr.anchor_if_unsynced(chain) {
                return Ok(n);
            }
            if let Some(n) = self.nonce_mgr.try_reserve() {
                return Ok(n);
            }
        }
    }

    /// Record that `used` was accepted on-chain, so it is never reissued and the allocator
    /// stays ahead of it.
    pub fn commit_nonce(&self, used: u64) {
        self.nonce_mgr.commit(used);
    }

    /// A reserved nonce whose tx definitively did NOT land — recycle it so the next
    /// reservation refills the gap (keeping the on-chain sequence gap-free). Do NOT call
    /// for a tx that may still be pending; hand such a nonce to `release_job` instead.
    pub fn abort_nonce(&self, nonce: u64) {
        self.nonce_mgr.abort(nonce);
    }

    /// After a "nonce too low"/"too high" (an external tx — e.g. a stake/mint that
    /// bypasses this allocator — advanced the account), re-fetch the chain nonce and
    /// advance the allocator past it. Only ever raises `next`; never reissues an in-flight
    /// nonce. Returns the (possibly-updated) chain nonce.
    pub async fn resync_nonce(&self) -> Result<u64> {
        // [nonce-review] Use the MINED frontier (`.latest()`), NOT `.pending()`. resync
        // prunes recycled gaps below the frontier, and only a MINED nonce proves the gap
        // below it is truly consumed. `.pending()` counts still-in-mempool txs, so a
        // genuine recycled gap (abort() deliberately recycles a possibly-pending nonce)
        // could be pruned from `freed` while its tx is merely pending; if that tx is then
        // evicted, the nonce becomes a permanent on-chain gap `freed` no longer holds →
        // the whole signer wedges. The mined frontier can only advance monotonically as
        // txs actually mine, so pruning against it never forgets a live gap.
        let chain = self
            .provider
            .get_transaction_count(self.address)
            .await
            .context("Failed to re-sync nonce")?;
        self.nonce_mgr.resync(chain);
        Ok(chain)
    }

    /// Detect and heal a nonce GAP that has wedged the signer. [nonce-review round 4] A
    /// hole at the mined frontier — an evicted external tx (e.g. a stake/mint from another
    /// process or the alloy NonceFiller bypass, #48), or a below-`next` abort-gap that no
    /// organic reserve has refilled — leaves our higher-nonce txs queued forever (the
    /// sequential-nonce rule) with NO error surfaced, and neither `resync` (only raises
    /// next) nor `reserve` (only hands out freed/next) can fill it. This sends a 0-value
    /// self-transfer at the mined-frontier nonce so the queued txs cascade and mine.
    ///
    /// Returns `Ok(true)` if it filled a gap. GUARD: the caller MUST only invoke this after
    /// confirming the wedge has PERSISTED (a freshly reserved-but-unsent nonce would else be
    /// mistaken for a gap and collided with); a legit unsent reservation is sent within a
    /// tick, so a wedge that survives ~90s is a real hole.
    /// Cheap wedge detector: returns `Some(mined)` (the hole to fill) if the signer is
    /// wedged behind a gap — we reserved beyond `mined+1` (so `mined` is a real hole, not a
    /// single unsent reservation) yet nothing is executable (`pending == mined`) — else
    /// `None`. The caller should require this to PERSIST (same gap across ≥2 checks) before
    /// healing, so a transient reserved-but-unsent nonce is never mistaken for a hole.
    pub async fn nonce_gap_frontier(&self) -> Result<Option<u64>> {
        let next = match self.nonce_mgr.peek_next() {
            Some(n) => n,
            None => return Ok(None),
        };
        let mined = self
            .provider
            .get_transaction_count(self.address)
            .await
            .context("gap-check: mined nonce")?;
        // [RPC quick-win] Reordered to avoid the second getTransactionCount(.pending())
        // whenever it can't change the answer — provably equivalent to the original
        // `(next > mined) && (external_hole || owned_stuck)` where
        // `external_hole = next > mined+1 && pending <= mined`, `owned_stuck = is_freed(mined)`.
        // No gap is possible unless we've reserved past the mined frontier.
        if next <= mined {
            return Ok(None);
        }
        // (B) an ABORTED-but-stuck nonce we OWN (`freed` holds `mined`): our own tx there may
        //     be pending-but-unminable at a low fee, blocking a higher deadline-critical tx —
        //     safe to fill/displace because it's ours. Determinable from local state alone.
        if self.nonce_mgr.is_freed(mined) {
            return Ok(Some(mined));
        }
        // (A) an EXTERNAL hole needs `next > mined+1` (a real hole, not one unsent reservation)
        //     AND nothing executable (`pending <= mined`). Only now is the pending read needed.
        if next > mined + 1 {
            let pending = self
                .provider
                .get_transaction_count(self.address)
                .pending()
                .await
                .context("gap-check: pending nonce")?;
            if pending <= mined {
                return Ok(Some(mined));
            }
        }
        Ok(None)
    }

    pub async fn heal_nonce_gap(&self) -> Result<bool> {
        let mined = match self.nonce_gap_frontier().await? {
            Some(m) => m,
            None => return Ok(false),
        };
        let next = self.nonce_mgr.peek_next().unwrap_or(mined);
        // [nonce-review round 5] EXCLUSIVELY claim the nonce out of the allocator BEFORE
        // broadcasting, so a concurrent reserve can't hand the same nonce to a job task and
        // double-issue it (the fill/displace tx would otherwise collide). Idempotent.
        self.nonce_mgr.claim_gap(mined);
        tracing::warn!(
            "nonce {mined} wedging the signer (next={next}) — filling/displacing with a self-transfer"
        );
        let (base_tip, base_max_fee) = self.base_fees().await;
        // Use a HIGH fee: the hole may be blocked by our own stuck LOW-fee tx (an aborted
        // batch tx during a base-fee spike), which can only be displaced by a strictly
        // higher fee. Overpaying on a rare recovery tx is well worth unwedging the signer.
        let tip = base_tip.saturating_mul(4).max(2_000_000_000); // >= 2 gwei
        let max_fee = base_max_fee.saturating_mul(4).max(tip);
        let tx = alloy::rpc::types::TransactionRequest::default()
            .to(self.address)
            .value(alloy::primitives::U256::ZERO)
            .nonce(mined)
            .gas_limit(21_000)
            .max_priority_fee_per_gas(tip)
            .max_fee_per_gas(max_fee);
        let send = {
            let _guard = self.tx_lock.lock().await;
            self.provider.send_transaction(tx).await
        };
        let pending_tx = match send {
            Ok(p) => p,
            Err(e) => {
                // Send failed → the tx never entered the mempool, so the nonce we claimed
                // would leak as a hole; recycle it so a future reserve/heal refills it.
                self.nonce_mgr.abort(mined);
                return Err(anyhow::anyhow!("heal: send self-transfer failed: {e:#}"));
            }
        };
        let tx_hash = *pending_tx.tx_hash();
        // [RPC #1] Poll for the receipt (no heartbeat watcher). Some+status = unwedged;
        // anything else (no receipt within budget, or a mined revert) → retry next tick.
        // [review] Budget capped at 30s, NOT TX_RECEIPT_TIMEOUT: heal is awaited directly
        // in the brain's 5s scheduler loop (unlike every other site, which runs in a
        // spawned lifecycle task), so a long wait here stalls claim dispatch. On None the
        // watchdog simply re-probes next tick — if the fill tx mined meanwhile the gap is
        // gone; if not, the retry re-sends at the same claimed nonce with a higher fee.
        const HEAL_RECEIPT_BUDGET: std::time::Duration = std::time::Duration::from_secs(30);
        match crate::tx::await_receipt(&*self.provider, tx_hash, HEAL_RECEIPT_BUDGET).await {
            Some(r) if r.status() => {
                tracing::info!("nonce gap at {mined} filled (tx {:?}) — signer unwedged", r.transaction_hash);
                self.resync_nonce().await.ok(); // advance the allocator past the filled nonce
                Ok(true)
            }
            other => {
                tracing::warn!("nonce gap-fill at {mined} (tx {tx_hash:?}) not confirmed ({other:?}); will retry");
                Ok(false)
            }
        }
    }

    /// Stash the abandoned fulfill nonce for `job_id` so `release_job` can displace the
    /// stuck fulfill at the SAME nonce. Called by `fulfill_job` on give-up.
    pub fn stash_abandoned_nonce(&self, job_id: alloy::primitives::B256, nonce: u64) {
        self.abandoned_fulfill_nonces
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(job_id, nonce);
    }

    /// Take (and clear) the abandoned fulfill nonce stashed for `job_id`, if any.
    pub fn take_abandoned_nonce(&self, job_id: alloy::primitives::B256) -> Option<u64> {
        self.abandoned_fulfill_nonces
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&job_id)
    }

    /// Base EIP-1559 fees used to SEED per-attempt fee escalation on tx re-broadcasts.
    /// Returns `(base_priority_fee, base_max_fee)` in wei.
    ///
    /// This is the linchpin for replacing a stuck same-nonce tx: with default config
    /// (`gas_price` unset), the tx builders leave fees to the provider's auto-fill,
    /// which re-broadcasts at ~the same price and is rejected "replacement underpriced"
    /// forever. Callers escalate these per attempt so a re-broadcast reliably out-bids
    /// (and thus displaces) a stuck predecessor. A configured fixed `gas_price` takes
    /// precedence (legacy behavior). On estimation failure returns `(0, 0)` — callers
    /// treat that as "don't override", degrading to the provider's auto-fill.
    pub async fn base_fees(&self) -> (u128, u128) {
        if let Some(gp) = self.gas_price {
            return (gp, gp);
        }
        match self.provider.estimate_eip1559_fees().await {
            Ok(est) if est.max_fee_per_gas > 0 => {
                (est.max_priority_fee_per_gas, est.max_fee_per_gas)
            }
            other => {
                // [H2(c)] NEVER return (0,0). Fee escalation is gated on `base_max_fee > 0`,
                // so a zero base disables ALL escalation → a re-broadcast can never clear a
                // node's +12.5% replacement floor → a stuck tx (fulfill/release/claim) loops
                // "replacement underpriced" forever and strands. Seed a nonzero floor from
                // the live eth_gasPrice (or a hard 1 gwei minimum) so escalation always works.
                if let Err(e) = &other {
                    tracing::debug!("EIP-1559 fee estimate failed: {e:#}; falling back to eth_gasPrice");
                }
                let gp = self.provider.get_gas_price().await.unwrap_or(0);
                let floor = (gp).max(1_000_000_000u128); // >= 1 gwei
                (floor, floor)
            }
        }
    }

    /// Force a full re-anchor to chain on the next reserve (last resort). Prefer
    /// [`resync_nonce`](Self::resync_nonce) / [`abort_nonce`](Self::abort_nonce), which
    /// keep concurrent in-flight reservations valid; a blunt invalidate clears the gap
    /// set and can wedge higher nonces behind an un-refilled gap.
    pub fn invalidate_nonce(&self) {
        self.nonce_mgr.invalidate();
    }

    /// Record the latest chain head (called by the monitor each poll).
    pub fn set_head_block(&self, block: u64) {
        self.head_block.store(block, Ordering::Relaxed);
    }

    /// [RPC #2] Record the submitting tx hash for a job (from the monitor's
    /// JobSubmitted log — free, the log carries it). FIFO-bounded internally.
    pub fn note_submit_tx(
        &self,
        job_id: alloy::primitives::B256,
        tx_hash: alloy::primitives::B256,
    ) {
        self.submit_tx_cache
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(job_id, tx_hash);
    }

    /// [RPC #2] The cached submitting tx hash for a job, if the monitor saw its
    /// JobSubmitted log (live poll or startup backfill). `None` → use the scan path.
    pub fn submit_tx_for(
        &self,
        job_id: alloy::primitives::B256,
    ) -> Option<alloy::primitives::B256> {
        self.submit_tx_cache
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .map
            .get(&job_id)
            .copied()
    }

    /// Latest known chain head without an RPC call, falling back to a live query
    /// only if the monitor hasn't populated it yet. At most ~one poll-interval
    /// stale, which is fine for lookback windows and display.
    pub async fn head_block_cached(&self) -> Result<u64> {
        let cached = self.head_block.load(Ordering::Relaxed);
        if cached != 0 {
            return Ok(cached);
        }
        let block = self.get_block_number().await?;
        self.head_block.store(block, Ordering::Relaxed);
        Ok(block)
    }

    /// Get ETH balance of the prover wallet.
    pub async fn get_eth_balance(&self) -> Result<alloy::primitives::U256> {
        let balance = self
            .provider
            .get_balance(self.address)
            .await
            .context("Failed to get ETH balance")?;
        Ok(balance)
    }

    /// Get current block number.
    pub async fn get_block_number(&self) -> Result<u64> {
        let block = self
            .provider
            .get_block_number()
            .await
            .context("Failed to get block number")?;
        Ok(block)
    }

    /// Fetch head block + ETH balance + HEMI balance + prover stake + available
    /// collateral in ONE RPC request via Multicall3 (all from one consistent block
    /// snapshot). Replaces 5 separate calls on every refresh tick. Also updates the
    /// shared head-block cache.
    pub async fn get_refresh_batch(&self) -> Result<RefreshData> {
        use alloy::providers::MulticallItem;
        use zkminer_contracts::bindings::{IERC20, IHemiProveStaking};
        let token = IERC20::new(self.hemi_token, &*self.provider);
        let staking = IHemiProveStaking::new(self.hemi_prove_staking, &*self.provider);
        // [review must-fix] Each contract view is added with allowFailure=TRUE. alloy's
        // `.add()` builds a CallItem with `allow_failure: false` by DEFAULT, and aggregate3
        // reverts WHOLESALE if any allowFailure=false sub-call reverts — so without this the
        // per-field degrade below is a lie: one reverting view would sink block+balances+
        // stake+stats together, on EVERY tick. That is reachable today, not hypothetical:
        // getAvailableCollateral does a checked subtraction that reverts when
        // locked+unstake > total. With allowFailure=false that would make the whole refresh
        // Err forever → stake_info never hydrates → the collateral gate reads 0 → claiming
        // permanently blocked (and the "the refresh loop will re-hydrate" fail-safe fails too).
        // The two native helpers (block number / ETH balance) are Multicall3 built-ins and
        // cannot revert, so they stay as-is.
        let (blk, eth, hemi, stake, avail, stats) = self
            .provider
            .multicall()
            .get_block_number()
            .get_eth_balance(self.address)
            .add_call(token.balanceOf(self.address).into_call(true))
            .add_call(staking.getProverStake(self.address).into_call(true))
            .add_call(staking.getAvailableCollateral(self.address).into_call(true))
            .add_call(staking.getProverStats(self.address).into_call(true))
            .aggregate3()
            .await
            .context("refresh multicall")?;

        // Degrade per field: a reverting sub-call only drops its own value (guaranteed by the
        // allowFailure=true above), so the rest of the snapshot still applies (block/balances
        // survive a stake read failure, etc.). Only a total RPC failure (the `?`) skips the tick.
        let head = blk.ok().map(|b| b.to::<u64>());
        if let Some(h) = head {
            self.set_head_block(h);
        }
        // Stake needs BOTH the stake struct and available-collateral reads.
        let stake = match (stake, avail) {
            (Ok(s), Ok(avail)) => Some(crate::staking::StakeInfo {
                total_staked: s.totalStaked,
                locked_collateral: s.lockedCollateral,
                available_collateral: avail,
                unstake_amount: s.unstakeAmount,
                unstake_request_time: s.unstakeRequestTime.to::<u64>(),
                deposit_block: s.depositBlock.to::<u64>(),
            }),
            _ => None,
        };
        // Prover stats degrade independently (a revert here never drops the rest).
        let stats = stats.ok().map(|st| crate::staking::ProverStatistics {
            jobs_fulfilled: st.jobsFulfilled,
            jobs_slashed: st.jobsSlashed,
            jobs_released: st.jobsReleased,
            total_earned: st.totalEarned.to::<u128>(),
            first_fulfillment_at: st.firstFulfillmentAt.to::<u64>(),
            last_fulfillment_at: st.lastFulfillmentAt.to::<u64>(),
        });
        Ok(RefreshData {
            head,
            eth_balance: eth.ok(),
            hemi_balance: hemi.ok(),
            stake,
            stats,
        })
    }
}
