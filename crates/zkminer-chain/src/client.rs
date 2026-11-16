use alloy::{
    network::EthereumWallet,
    primitives::Address,
    providers::{
        fillers::{
            BlobGasFiller, ChainIdFiller, FillProvider, GasFiller, JoinFill, NonceFiller,
            WalletFiller,
        },
        Identity, Provider, ProviderBuilder, RootProvider,
    },
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
    /// A FLOOR: every fulfil sends at least `jobs::fulfill_gas_formula` for the job.
    pub fulfill_gas_limit: u64,
    /// First block of every HemiProve log scan — the deployment's `fromBlock` (no HemiProve log
    /// exists below it). 0 = no floor.
    pub scan_from_block: u64,
    /// Key-wide fee ceiling (wei) for the fulfil and release ladders (handoff §10; config
    /// `chain.fee_ceiling_gwei`). The per-nonce ratchet cap for those two paths is the larger of
    /// this and `8 x` the nonce's seed.
    pub fee_ceiling: u128,
    /// A watch-only client (see [`Self::new_watch_only`]): its transport refuses every send.
    watch_only: bool,
    /// Unix seconds of the last send the node refused for insufficient ETH (0 = none). Read by the
    /// brain's claim gate: a key that cannot fund a fulfil must not take on new locks.
    funds_short_at: Arc<AtomicU64>,
    /// The `maxFeePerGas` the last [`Self::base_fees`] quoted (wei, saturated to u64; 0 = none yet).
    /// Lets the claim gate size a fulfil's ETH need without an RPC of its own.
    last_max_fee: Arc<AtomicU64>,
    /// The base fee of the last header read for fees (wei, saturated; 0 = none yet): the fallback when
    /// a header read fails, instead of a fixed figure ~1e6 x the live base fee.
    last_base_fee: Arc<AtomicU64>,
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
    /// This key's hashed fulfils as the DA throttle rules track them (witness-construction-jobs
    /// §5.5): each accepted fulfil's estimated DA bytes and first-acceptance head, and the large
    /// fulfils replaced by a self-transfer awaiting a re-send. Shared across clones.
    da_book: Arc<std::sync::Mutex<crate::da::DaSendBook>>,
    /// Short-TTL cache of ProgramRegistry metadata keyed by programId. Shared across clones.
    pub(crate) program_info_cache: Arc<std::sync::Mutex<ProgramInfoCache>>,
    /// Counts every JSON-RPC request sent to the endpoint (total + rolling minute).
    rpc_meter: Arc<crate::rpc_meter::RpcMeter>,
    /// jobId → submitting tx hash, written by the monitor as it parses
    /// JobSubmitted logs (the log already carries `transaction_hash`, so populating
    /// this costs ZERO extra requests). Read by the descriptor fast path
    /// ([`crate::descriptor::fetch_job_descriptor_checked`]) to replace the
    /// 500k-block `eth_getLogs` scan with one `eth_getTransactionByHash`. Sound
    /// because exactly ONE JobSubmitted is ever emitted per jobId (jobId is derived
    /// from a monotonic index and reopen does not re-emit), so the cached tx IS the
    /// tx the scan would find. FIFO-bounded; a miss just uses the scan fallback.
    submit_tx_cache: Arc<std::sync::Mutex<SubmitTxCache>>,
    /// Downloads programs' ELFs through the network guard, under the config's `[dev]` and
    /// `[egress]` settings (see [`crate::programs::ElfFetcher`]). Shared across clones.
    elf_fetcher: crate::programs::ElfFetcher,
}

/// FIFO-bounded programId → ProgramInfo cache (see `ChainClient::program_info_cache`) with a TTL:
/// registered metadata can change (URIs, build hashes, status), so entries are re-read after
/// `PROGRAM_INFO_TTL`. The bound stops a submitter who registers unboundedly many distinct programIds
/// from growing the long-lived client's heap without limit.
#[derive(Default)]
pub(crate) struct ProgramInfoCache {
    map: std::collections::HashMap<
        alloy::primitives::B256,
        (crate::programs::ProgramInfo, std::time::Instant),
    >,
    order: std::collections::VecDeque<alloy::primitives::B256>,
}

/// Bound on the program-info cache: comfortably covers the distinct programs a miner works with,
/// while capping heap growth under a flood of distinct submitter-chosen programIds.
const PROGRAM_INFO_CACHE_CAP: usize = 4096;
/// How long a cached program-info entry is trusted before it is re-read.
const PROGRAM_INFO_TTL: std::time::Duration = std::time::Duration::from_secs(600);

impl ProgramInfoCache {
    pub(crate) fn get(&self, id: &alloy::primitives::B256) -> Option<crate::programs::ProgramInfo> {
        self.map
            .get(id)
            .filter(|(_, at)| at.elapsed() < PROGRAM_INFO_TTL)
            .map(|(info, _)| info.clone())
    }

    pub(crate) fn insert(
        &mut self,
        id: alloy::primitives::B256,
        info: crate::programs::ProgramInfo,
    ) {
        if self.map.insert(id, (info, std::time::Instant::now())).is_none() {
            self.order.push_back(id);
            while self.order.len() > PROGRAM_INFO_CACHE_CAP {
                if let Some(old) = self.order.pop_front() {
                    self.map.remove(&old);
                }
            }
        }
    }
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

/// How long an abort stays usable as wedge evidence. Must comfortably exceed the watchdog's
/// persistence gate (2 sightings ~60s apart) or the sticky signal would expire before it can
/// be acted on. Safe to be generous: `commit`/`resync` drop the record as soon as the nonce
/// mines, so it only survives while genuinely unmined.
const ABORT_MEMORY: std::time::Duration = std::time::Duration::from_secs(600);

/// Default confirmation wait for a gap fill, used by the live-process watchdog. The shutdown
/// path passes its own remaining budget instead — see `heal_claimed_gap_at`.
const HEAL_RECEIPT_BUDGET: std::time::Duration = std::time::Duration::from_secs(30);

/// Result of a heal on the VETTED (shutdown) path.
///
/// Three outcomes, not two. Collapsing `RefusedNotOurs` into "not confirmed" made the
/// shutdown loop stop walking: a refusal PROVES the nominated nonce has a live owner who will
/// plug it, so the hole ABOVE it is now the blocker and the loop should continue — whereas an
/// unconfirmed fill means retrying is pointless and the remaining budget is better left to
/// recovery on the next start.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnedHealOutcome {
    /// The hole is plugged (mined, or in the mempool for an above-frontier fill).
    Filled,
    /// Sent but not confirmed. Stop; the next start re-drives it.
    Unconfirmed,
    /// A live owner took the nonce after the gate approved it. Keep walking.
    RefusedNotOurs,
}

/// The best chain-time observation so far: the block timestamp that implies the LATEST chain time
/// now, and the monotonic instant it was read. Every on-chain window (fulfil <= D+G, release < D+G)
/// is judged by `block.timestamp`, not by this host's clock. A header from a lagging or
/// load-balanced replica implies an EARLIER chain time and is ignored (only a header that moves the
/// estimate forward replaces it), so one stale sample can never push the deadline guards late.
static CHAIN_CLOCK: std::sync::Mutex<Option<(u64, std::time::Instant)>> = std::sync::Mutex::new(None);

/// The chain time implied by the best observation, if any.
fn observed_chain_now() -> Option<u64> {
    let g = CHAIN_CLOCK.lock().unwrap_or_else(|p| p.into_inner());
    g.map(|(ts, at)| ts.saturating_add(at.elapsed().as_secs()))
}

/// The latest header read (its timestamp, and when it was read), whatever it implies: the chain's
/// clock as the endpoint reports it now. Unlike [`CHAIN_CLOCK`] it can move back, so a chain that
/// falls behind (a stall, catch-up blocks with past timestamps) shows in [`chain_clock_skew_secs`].
static LAST_HEADER: std::sync::Mutex<Option<(u64, std::time::Instant)>> =
    std::sync::Mutex::new(None);

/// Record a freshly-read block timestamp (kept only if it implies a later chain time than the
/// current estimate — see [`CHAIN_CLOCK`]).
pub fn note_chain_time(block_timestamp: u64) {
    *LAST_HEADER.lock().unwrap_or_else(|p| p.into_inner()) =
        Some((block_timestamp, std::time::Instant::now()));
    let mut g = CHAIN_CLOCK.lock().unwrap_or_else(|p| p.into_inner());
    let current = g.map(|(ts, at)| ts.saturating_add(at.elapsed().as_secs()));
    if current.is_none_or(|c| block_timestamp > c) {
        *g = Some((block_timestamp, std::time::Instant::now()));
    }
}

fn wall_now() -> u64 {
    chrono::Utc::now().timestamp().max(0) as u64
}

/// The current chain time, estimated from ABOVE: `max(wall clock, best observed header + elapsed)`.
/// Use it for every decision to STOP or START something before an on-chain deadline (stop proving,
/// stop fulfilling, start releasing): over-estimating the time there only gives up a little early,
/// while under-estimating it lands a release after D+G (a 100% slash) or publishes a late seal.
pub fn chain_now() -> u64 {
    let wall = wall_now();
    observed_chain_now().map_or(wall, |c| c.max(wall))
}

/// The current chain time, estimated from BELOW: `min(wall clock, best observed header + elapsed)`.
/// Use it only to decide that a deadline has ALREADY passed (skip a release that "would revert",
/// drop a breadcrumb as dead): there an over-estimate abandons a lock that could still be saved.
pub fn chain_now_floor() -> u64 {
    let wall = wall_now();
    observed_chain_now().map_or(wall, |c| c.min(wall))
}

/// The chain's clock minus this host's, in seconds, from the latest header read (`None` before the
/// first): its timestamp, plus the time since it was read, against the wall clock. Negative: the
/// host clock runs ahead of the chain's. A header read before a host suspend reads as skewed by the
/// suspend's length (`Instant` does not count it), so re-read one before acting on a large value.
pub fn chain_clock_skew_secs() -> Option<i64> {
    let g = LAST_HEADER.lock().unwrap_or_else(|p| p.into_inner());
    g.map(|(ts, at)| ts.saturating_add(at.elapsed().as_secs()) as i64 - wall_now() as i64)
}

/// Default key-wide fee ceiling for the fulfil and release ladders (handoff §10 example: 15-50
/// HEMI jobs with 100 HEMI collateral at 50,000 HEMI/ETH -> ~3.6-4.7 gwei).
pub const DEFAULT_FEE_CEILING_GWEI: f64 = 4.0;

/// How long one "insufficient funds" send refusal keeps the claim gate shut (re-armed by every
/// further refusal; cleared early once the balance covers a fulfil again).
pub const FUNDS_SHORT_HOLD_SECS: u64 = 600;

/// Hemi orders transactions by tip, and a 1-wei tip is accepted by the RPC but never mined (handoff
/// §1, §10). Every send states BOTH fee fields with at least this tip.
pub const MIN_PRIORITY_FEE_WEI: u128 = 10_000_000; // 0.01 gwei

/// The fee rule every zkminer send starts from (the reference daemons'): tip =
/// `max(2 x eth_maxPriorityFeePerGas, 0.01 gwei)` and maxFee = `2 x baseFee + tip`. Per-attempt
/// escalation and the per-nonce replacement floor build on these.
pub fn hemi_fees(base_fee: u128, suggested_tip: u128) -> (u128, u128) {
    let tip = suggested_tip.saturating_mul(2).max(MIN_PRIORITY_FEE_WEI);
    let max_fee = base_fee.saturating_mul(2).saturating_add(tip);
    (tip, max_fee)
}

impl ChainClient {
    /// Create a new ChainClient from config + signer.
    pub async fn new(config: &ZkMinerConfig, signer: PrivateKeySigner) -> Result<Self> {
        let address = signer.address();
        Self::connect(config, signer, address, false).await
    }

    /// A client that reads the chain as `address` and can send nothing.
    ///
    /// It holds no key of the operator's: it signs with a throwaway key, and its transport refuses
    /// every request that would broadcast a transaction or have the node sign one (see
    /// [`crate::send_guard`]). Calls that depend on the sender (the claim quote) name `address`
    /// explicitly, so they answer as they would for that prover.
    pub async fn new_watch_only(config: &ZkMinerConfig, address: Address) -> Result<Self> {
        Self::connect(config, PrivateKeySigner::random(), address, true).await
    }

    /// Whether this client was built by [`Self::new_watch_only`].
    pub fn is_watch_only(&self) -> bool {
        self.watch_only
    }

    /// The guarded ELF downloader every program fetch goes through.
    pub fn elf_fetcher(&self) -> &crate::programs::ElfFetcher {
        &self.elf_fetcher
    }

    async fn connect(
        config: &ZkMinerConfig,
        signer: PrivateKeySigner,
        address: Address,
        watch_only: bool,
    ) -> Result<Self> {
        // First: a config that would let requesters reach this host's private network on a
        // production chain is refused before anything connects anywhere.
        config.validate_network()?;
        let elf_fetcher = crate::programs::ElfFetcher::from_config(config)?;
        let wallet = EthereumWallet::from(signer.clone());

        let rpc_url = config.chain.rpc_url.parse().context("Invalid RPC URL")?;

        // Install an RPC meter layer so we can report request volume (it counts
        // every JSON-RPC call, including alloy-internal receipt/gas/nonce calls).
        let rpc_meter = crate::rpc_meter::RpcMeter::new();
        // Transport-level timeouts so NO RPC await can hang forever. A
        // black-holing endpoint (TCP accepted, no HTTP response — the documented
        // flaky-testnet failure) would otherwise wedge any await indefinitely: the
        // post-claim lockDeadline read, the serial startup-recovery loop, the batch
        // reconcile read. Any of those hanging strands collateral past its deadline to
        // a keeper slash with no in-session recovery. A per-request ceiling bounds
        // every call at the transport layer, beneath every caller, so a stalled
        // endpoint fails fast (Err, handled by the existing retry/poll paths) instead
        // of blocking forever. 45s is well above a healthy call yet finite.
        let http_client = alloy::transports::http::reqwest::Client::builder()
            // An explicit User-Agent: the public Hemi RPC answers HTTP 403 to some client UAs (a
            // blocklist, e.g. Python-urllib); identify ourselves rather than ride a library default.
            .user_agent(concat!("zkminer/", env!("CARGO_PKG_VERSION")))
            .timeout(std::time::Duration::from_secs(45))
            .connect_timeout(std::time::Duration::from_secs(10))
            .build()
            .context("Failed to build HTTP client with timeouts")?;
        let http = alloy::transports::http::Http::with_client(http_client, rpc_url);
        // Two burst-shaping measures against the public endpoint's ~5 req/s
        // per-second cap (which tripped at only ~70 req/min sustained because concurrent
        // lifecycles + the monitor/refresh loops fired in the same second):
        //  - ThrottleLayer (OUTERMOST, MeterLayer innermost so genuine 429s still reach
        //    the meter) paces dispatch to <=4/s, structurally preventing same-second
        //    spikes regardless of concurrency. Steady state (~1-2/s) is untouched.
        //    Queued requests are served by priority lane (design §17.6): held-lock reads and
        //    sends, then lock transactions, then pre-claim reads (capped at 25% of the rate),
        //    then everything else. A request takes the lane of its `rpc_meter::with_lane`
        //    scope; unscoped requests are all `Lane::Default`, i.e. the single FIFO limiter.
        //  - with_poll_interval(12s) widens alloy's watcher heartbeat cadence. NOTE: on
        //    the `run` path this is now DEFENSE-IN-DEPTH ONLY — no code registers the
        //    watcher anymore (every receipt wait goes through crate::tx::await_receipt,
        //    which polls eth_getTransactionReceipt directly and never unpauses the
        //    heartbeat). The interval still governs any future/one-off get_receipt()
        //    caller (e.g. the sp1_demo command). Do NOT reintroduce get_receipt() in the
        //    miner paths believing this interval makes it cheap — use await_receipt.
        // The send guard goes OUTERMOST, so a refused send is neither paced nor counted.
        let rpc_client = alloy::rpc::client::ClientBuilder::default()
            .layer(crate::send_guard::SendGuardLayer::new(watch_only))
            .layer(crate::rpc_meter::ThrottleLayer::with_lanes(
                config
                    .chain
                    .max_requests_per_sec
                    .unwrap_or(if watch_only { 1 } else { 4 }),
                crate::rpc_meter::LaneConfig::default(),
            ))
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

        // Unset: the known deployment's for this chain (programs' ELF sources come only from it, and
        // the deployment check requires the live one), else none.
        let program_registry: Option<Address> = if config.contracts.program_registry.is_empty() {
            crate::deployment::known_deployment(config.chain.chain_id).map(|k| k.program_registry)
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
                config.chain.chain_id,
                rpc_chain_id,
            );
        }

        let gas_price = config
            .chain
            .gas_price_gwei
            .map(|g| (g * 1e9).round() as u128);

        let fulfill_gas_limit = config
            .chain
            .fulfill_gas_limit
            .unwrap_or(DEFAULT_FULFILL_GAS_LIMIT);
        let scan_from_block = config.chain.scan_from_block.unwrap_or_else(|| {
            crate::deployment::known_deployment(config.chain.chain_id)
                .map(|k| k.scan_from_block)
                .unwrap_or(0)
        });
        // Never below a fixed gas price the operator configured.
        let fee_ceiling = ((config.chain.fee_ceiling_gwei.unwrap_or(DEFAULT_FEE_CEILING_GWEI) * 1e9)
            .round()
            .max(1.0) as u128)
            .max(gas_price.unwrap_or(0));

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
            scan_from_block,
            fee_ceiling,
            watch_only,
            funds_short_at: Arc::new(AtomicU64::new(0)),
            last_max_fee: Arc::new(AtomicU64::new(0)),
            last_base_fee: Arc::new(AtomicU64::new(0)),
            tx_lock: Arc::new(tokio::sync::Mutex::new(())),
            head_block: Arc::new(AtomicU64::new(0)),
            program_info_cache: Arc::new(std::sync::Mutex::new(ProgramInfoCache::default())),
            submit_tx_cache: Arc::new(std::sync::Mutex::new(SubmitTxCache::default())),
            elf_fetcher,
            nonce_mgr: Arc::new(crate::nonce::NonceManager::new()),
            abandoned_fulfill_nonces: Arc::new(std::sync::Mutex::new(Default::default())),
            da_book: Arc::new(std::sync::Mutex::new(Default::default())),
            rpc_meter,
        })
    }

    /// Shared RPC request meter (total + rolling-minute counts).
    pub fn rpc_meter(&self) -> Arc<crate::rpc_meter::RpcMeter> {
        self.rpc_meter.clone()
    }

    /// Record that the node refused one of our sends for insufficient ETH (see
    /// [`Self::funds_short`]). Pages once per hold window.
    pub fn note_funds_short(&self) {
        let now = wall_now();
        let prev = self.funds_short_at.swap(now, Ordering::Relaxed);
        if prev == 0 || now.saturating_sub(prev) >= FUNDS_SHORT_HOLD_SECS {
            tracing::error!(
                "PAGE: FUNDS-SHORT — the node refused a send from {} for insufficient ETH; no new \
                 claims until the balance covers a fulfil (fund the key for fulfil gas limit x fee \
                 ceiling per pending fulfil)",
                self.address
            );
        }
    }

    /// True while a recent send was refused for insufficient ETH.
    pub fn funds_short(&self) -> bool {
        let t = self.funds_short_at.load(Ordering::Relaxed);
        t != 0 && wall_now().saturating_sub(t) < FUNDS_SHORT_HOLD_SECS
    }

    /// Clear the funds-short hold (the brain re-read the balance and it covers a fulfil again).
    pub fn clear_funds_short(&self) {
        self.funds_short_at.store(0, Ordering::Relaxed);
    }

    /// After anchoring at the PENDING count on a fresh start: anything in `[mined, pending)` is a tx a
    /// previous run left in the mempool, with no owner in this process and no record here. If it is
    /// stuck (out-bid by a block-filler, under a raised base fee), every later fulfil and release
    /// queues behind it unmined, and nothing would ever bid at that nonce. Record the abandonment
    /// evidence the gap watchdog acts on: a tx that mines in the next block or two is pruned before the
    /// watchdog's persistence gate passes, and one that does not is displaced.
    async fn note_inherited_pending(&self, pending: u64) {
        const MAX_INHERITED: u64 = 64;
        let Ok(mined) = self.provider.get_transaction_count(self.address).await else {
            return;
        };
        for n in mined..pending.min(mined.saturating_add(MAX_INHERITED)) {
            tracing::warn!("nonce {n} was left pending by a previous run — displaced if it stays stuck");
            self.nonce_mgr.note_unresolved(n);
        }
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
                self.note_inherited_pending(chain).await;
                return Ok(n);
            }
            if let Some(n) = self.nonce_mgr.try_reserve() {
                return Ok(n);
            }
        }
    }

    /// Whether `nonce` is currently a recycled gap. Exposed for tests that must assert an
    /// accepted-but-unconfirmed send did NOT recycle its nonce.
    pub fn nonce_is_freed(&self, nonce: u64) -> bool {
        self.nonce_mgr.is_freed(nonce)
    }

    /// The next FRESH nonce the allocator would hand out, if synced. Exposed for the
    /// nonce-gap tests, which must position the allocator relative to the chain frontier.
    pub fn peek_nonce(&self) -> Option<u64> {
        self.nonce_mgr.peek_next()
    }

    /// Record that `used` was accepted on-chain, so it is never reissued and the allocator
    /// stays ahead of it.
    pub fn commit_nonce(&self, used: u64) {
        self.nonce_mgr.commit(used);
    }

    /// Record a fee we successfully BROADCAST at `nonce`, so a later send at the same
    /// nonce is forced above it. See `NonceManager::note_broadcast` for the wedge this
    /// prevents. Call ONLY after the node accepted the tx.
    pub fn note_broadcast_fee(&self, nonce: u64, tip: u128, max_fee: u128, seed_max_fee: u128) {
        self.nonce_mgr
            .note_broadcast(nonce, tip, max_fee, seed_max_fee);
    }

    /// Mark `nonce` as legitimately in use by an accepted send that records no fee (the
    /// staking paths; alloy's gas filler owns their fee pair). See `NonceManager::note_sent`.
    pub fn note_nonce_in_use(&self, nonce: u64) {
        self.nonce_mgr.note_sent(nonce);
    }

    /// Highest `(tip, max_fee)` broadcast at `nonce`, if any (see `note_broadcast_fee`).
    pub fn nonce_fee_floor(&self, nonce: u64) -> Option<(u128, u128)> {
        self.nonce_mgr.fee_floor(nonce)
    }

    /// Leave abort evidence at `nonce` without offering it back to reservers.
    pub fn note_nonce_unresolved(&self, nonce: u64) {
        self.nonce_mgr.note_unresolved(nonce);
    }

    /// Record that we cannot outbid the tx resident at `nonce`.
    pub fn note_nonce_undisplaceable(&self, nonce: u64) {
        self.nonce_mgr.note_undisplaceable(nonce);
    }

    /// True while the signer is jammed by an undisplaceable nonce: nothing at or above
    /// it can mine, so taking on new collateral would bond work we cannot release.
    pub fn signer_is_jammed(&self) -> bool {
        self.nonce_mgr.is_jammed()
    }

    /// Drop a jam record once chain truth confirms the frontier has passed it.
    pub fn clear_jammed_nonce(&self, nonce: u64) {
        self.nonce_mgr.clear_undisplaceable(nonce);
    }

    /// Re-confirm a jam that chain truth says is still real, restarting its TTL.
    pub fn refresh_jammed_nonce(&self, nonce: u64) {
        self.nonce_mgr.refresh_undisplaceable(nonce);
    }

    /// Lowest nonce currently believed undisplaceable, for diagnostics.
    pub fn jammed_nonce(&self) -> Option<u64> {
        self.nonce_mgr.jammed_nonce()
    }

    /// Fee-floor state at `nonce`, including whether the ratchet cap leaves room for
    /// a strictly-higher replacement. See [`crate::nonce::NonceManager::fee_floor_state`].
    pub fn nonce_fee_floor_state(&self, nonce: u64) -> Option<crate::nonce::FeeFloorState> {
        self.nonce_mgr.fee_floor_state(nonce)
    }

    /// Recycle a reserved nonce as a gap, so the next reservation refills it and the
    /// on-chain sequence stays gap-free.
    ///
    /// Prefer calling this only when the tx definitively did NOT land. The tx-layer give-up
    /// paths nonetheless abort even when it MIGHT still be pending, because for THEM a
    /// reserved-but-unresolved nonce is a gap nothing will refill.
    ///
    /// Be precise about what "self-heals" means, because it differs by state. If the tx has
    /// MINED, a reuser gets "nonce too low" and resyncs — harmless. If it is still POOLED,
    /// the reuser instead gets "replacement transaction underpriced"/"already known", which
    /// `is_same_nonce_pending` matches FIRST, so it keeps the nonce and escalates until it
    /// EVICTS our live tx. That is a real cost, not a self-heal, and it is why the exceptions
    /// below exist rather than being mere style.
    ///
    /// The exceptions are documented at their call sites: the staking receipt-timeout arms
    /// must NOT abort — leaving the nonce reserved-but-unresolved is safe there, because the
    /// gap detector finds such a hole off the node's pending count — and a stuck fulfill's
    /// nonce is HANDED to `release_job` via the stash rather than recycled, so the release
    /// can displace it at that exact nonce.
    pub fn abort_nonce(&self, nonce: u64) {
        self.nonce_mgr.abort(nonce);
    }

    /// True if one of our txs is EXECUTABLE at the mined frontier, i.e. `pending > mined`.
    ///
    /// `nonce_gap_frontier`'s branch (B) (`is_freed` /
    /// `recently_aborted`) deliberately does NO pending check — it exists to DISPLACE a stuck
    /// low-fee tx of ours, which is right for the brain's watchdog but wrong for a caller
    /// that is about to exit: the tx-layer give-up paths abort a nonce whose tx they actually
    /// BROADCAST, so healing there replaces a still-mineable `releaseJob` with a 0-value
    /// self-transfer and nothing survives to re-send it. Callers that cannot re-send must
    /// gate on this: when something is executable at the frontier there is no wedge at all
    /// (the queue cascades once it mines).
    pub async fn frontier_has_executable_tx(&self) -> Result<bool> {
        let mined = self
            .provider
            .get_transaction_count(self.address)
            .await
            .context("frontier check: mined nonce")?;
        self.frontier_has_executable_tx_at(mined).await
    }

    /// As above, but against a frontier the caller already observed.
    ///
    /// `mined` MUST be the frontier the nomination was derived from. Re-reading it here
    /// recreates the two-frontier split `nonce_gap_frontier_with_mined` exists to eliminate —
    /// and only in the PERMISSIVE direction: a fresher `mined` can only flip `pending > mined`
    /// from true to false, which makes the sole guard on the destructive arm say "nothing
    /// executable" and return early, skipping the fall-through that would have found the
    /// genuine hole above. `hole_we_own` does not re-validate, and `is_freed` stays true for
    /// an already-mined nonce when its owner gave up (no commit, no resync on that path), so
    /// the healer signs at a consumed nonce, gets "nonce too low", and the walk breaks.
    async fn frontier_has_executable_tx_at(&self, mined: u64) -> Result<bool> {
        let pending = self
            .provider
            .get_transaction_count(self.address)
            .pending()
            .await
            .context("frontier check: pending nonce")?;
        // Fail CLOSED on an impossible read. `pending < mined` cannot happen on a coherent
        // node, so it means a lagging replica answered — and this is the SOLE guard on the
        // destructive `hole == mined` arm. Its sibling `pending_hole` clamps the identical
        // read; treating a stale read as "nothing executable" would let the healer evict our
        // own live releaseJob seconds before process::exit.
        if pending < mined {
            return Ok(true);
        }
        Ok(pending > mined)
    }

    /// After a "nonce too low"/"too high" (an external tx — e.g. a stake/mint that
    /// bypasses this allocator — advanced the account), re-fetch the chain nonce and
    /// advance the allocator past it. Only ever raises `next`; never reissues an in-flight
    /// nonce. Returns the (possibly-updated) chain nonce.
    pub async fn resync_nonce(&self) -> Result<u64> {
        // Use the MINED frontier (`.latest()`), NOT `.pending()`. resync
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

    /// The lowest nonce with no EXECUTABLE tx, if we have handed out anything strictly above
    /// it. Shared by the detector's branch (A) and by `nonce_gap_safe_to_fill`'s fallback.
    ///
    /// `> pending + 1`: we must have reserved a nonce ABOVE the hole, which is what proves
    /// something is actually blocked behind it. Without it, one reserved-but-unsent nonce
    /// reads as a hole.
    async fn pending_hole(&self, mined: u64) -> Result<Option<u64>> {
        let next = match self.nonce_mgr.peek_next() {
            Some(n) => n,
            None => return Ok(None),
        };
        if next <= mined + 1 {
            return Ok(None); // nothing handed out past the frontier: no pending read needed
        }
        // `.max(mined)` because pending can never legitimately trail mined; a load-balanced
        // RPC serving a stale pending read must not fabricate a low hole.
        let pending = self
            .provider
            .get_transaction_count(self.address)
            .pending()
            .await
            .context("gap-check: pending nonce")?
            .max(mined);
        Ok((next > pending + 1).then_some(pending))
    }

    /// Detect and heal a nonce GAP that has wedged the signer. A hole at the mined frontier
    /// — an evicted external tx (e.g. a stake/mint from another process or the alloy
    /// NonceFiller bypass), or a below-`next` abort-gap that no
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
        Ok(self.nonce_gap_frontier_with_mined().await?.0)
    }

    /// As [`nonce_gap_frontier`], but also returns the mined frontier it observed.
    ///
    /// The gate used to take its own `getTransactionCount(latest)`, so it could decide against
    /// a DIFFERENT frontier than the one that produced the nomination. Both directions were
    /// live: if the chain advanced (`hole < mined`) the nomination is already consumed and
    /// bidding there is rejected "nonce too low", which returns Err and breaks the multi-hole
    /// walk before it reaches the real hole; if the read regressed (a lagging replica),
    /// `hole > mined` became spuriously true and skipped the frontier defence entirely.
    /// Sharing one read makes `hole >= mined` hold BY CONSTRUCTION — branch (B) yields
    /// `mined`, and `pending_hole` returns `pending.max(mined)` — so the unhandled case
    /// ceases to exist rather than being patched. It also removes an RPC from the gate.
    ///
    /// [`nonce_gap_frontier`]: ChainClient::nonce_gap_frontier
    async fn nonce_gap_frontier_with_mined(&self) -> Result<(Option<u64>, u64)> {
        let mined = self
            .provider
            .get_transaction_count(self.address)
            .await
            .context("gap-check: mined nonce")?;
        let next = match self.nonce_mgr.peek_next() {
            Some(n) => n,
            None => return Ok((None, mined)),
        };
        // Reordered to avoid the second getTransactionCount(.pending())
        // whenever it can't change the answer — provably equivalent to the original
        // `(next > mined) && (external_hole || owned_stuck)` where
        // `external_hole = next > mined+1 && pending <= mined`, `owned_stuck = is_freed(mined)`.
        // No gap is possible unless we've reserved past the mined frontier.
        if next <= mined {
            return Ok((None, mined));
        }
        // (B) an ABORTED-but-stuck nonce we OWN (`freed` holds `mined`): our own tx there may
        //     be pending-but-unminable at a low fee, blocking a higher deadline-critical tx —
        //     safe to fill/displace because it's ours. Determinable from local state alone.
        //     `is_freed` alone FLICKERS: `reserve_locked` pops the nonce out of `freed` the
        //     moment it is re-handed-out, and a failing retry loop aborts/re-reserves the same
        //     nonce many times a second, so a once-a-minute sample nearly always misses it.
        //     A real one-nonce wedge can therefore stay invisible for many minutes.
        //     `recently_aborted` is the same evidence class (we abandoned a tx
        //     there) but sticky, and it is pruned the moment the nonce mines.
        if self.nonce_mgr.is_freed(mined) || self.nonce_mgr.recently_aborted(mined, ABORT_MEMORY) {
            return Ok((Some(mined), mined));
        }
        // (A) A hole ANYWHERE at or above the mined frontier — not just AT it.
        //
        // The node's pending count IS the lowest hole: `eth_getTransactionCount(pending)` is
        // the first nonce with no EXECUTABLE tx, and txs above a hole sit in the queued pool
        // without advancing it. So with mined=100, txs at 100 and 101, a hole at 102 and
        // queued txs at 103-104, `pending` is exactly 102.
        //
        // This branch used to demand `pending <= mined`, i.e. it could only ever nominate the
        // MINED frontier. A hole above it was structurally invisible: `pending > mined` failed
        // that test, and branch (B) looks for local evidence at `mined`, where a leaked
        // reservation leaves none. Detection was deferred until every nonce below the hole
        // mined — and never happened at all if one of them was itself stuck. Meanwhile every
        // tx above it is queued and unmineable, which for a releaseJob means its collateral
        // rides to the lock deadline and is lost.
        //
        // When `pending == mined` this is exactly the old `next > mined + 1` test, so the
        // previous behaviour is preserved verbatim.
        if let Some(h) = self.pending_hole(mined).await? {
            return Ok((Some(h), mined));
        }
        Ok((None, mined))
    }

    /// The hole to heal, but ONLY if filling it cannot displace an executable transaction.
    ///
    /// For the shutdown/abandon path, which must never replace one of its own still-mineable
    /// `releaseJob` txs with a 0-value self-transfer: heal bids >= 4x base, the release ladder
    /// tops out far below that, and the process exits immediately afterwards with nothing
    /// alive to re-send — stranding exactly the nearest-deadline job it was trying to save.
    ///
    /// That path previously gated on `frontier_has_executable_tx()` alone, i.e. "if anything
    /// is executable at the mined frontier, do not heal". That is too coarse now that a
    /// hole ABOVE the frontier is detectable, and it excluded the very case the abandon path
    /// exists for: a skipped release leaves a hole BELOW the releaseJob txs it did broadcast,
    /// so the frontier IS busy (its own release is executable there) while the hole sits
    /// above it, queueing every release behind it until their lock deadlines pass.
    ///
    /// A hole strictly above the mined frontier is safe by construction: `pending` is the
    /// first nonce with no EXECUTABLE tx, so there is nothing there to displace.
    pub async fn nonce_gap_safe_to_fill(&self) -> Result<Option<u64>> {
        let (hole, mined) = match self.nonce_gap_frontier_with_mined().await? {
            (Some(h), m) => (h, m),
            (None, _) => return Ok(None),
        };
        if hole > mined {
            return Ok(self.hole_we_own(hole));
        }
        // hole == mined. "Nothing executable at the frontier" is NECESSARY but not
        // SUFFICIENT: during the abandon burst it is true BY CONSTRUCTION — every nonce is
        // pre-reserved before any task sends — so with the allocator level with chain
        // (mined=100, pending=100, next=103, all three still in pre-flight) this arm used to
        // return 100, the NEAREST-DEADLINE job's live nonce, and hand it a >=4x self-transfer
        // seconds before process::exit. Demand the same ownership evidence as the
        // above-frontier arm.
        // Guarded by TWO things, and deliberately not a third.
        //
        // (1) `frontier_has_executable_tx` — now fail-closed on an impossible read.
        // (2) `hole_we_own`'s `is_freed(hole)` — first-person proof we abandoned it AND that
        //     nobody has taken it since.
        //
        // An earlier version also demanded `fee_floor(mined).is_none()`, on the reasoning that
        // a broadcast at a not-yet-mined nonce means something of ours is live there. That is
        // a non-sequitur — not-mined does not imply still-pooled; a tx can be EVICTED, which
        // this file names as the canonical cause of a hole — and `fee_floor` is immortal at a
        // nonce that never mines (`commit` is its only pruner; `resync` skips it). As a
        // short-circuiting conjunct it was a permanent unilateral veto that skipped both
        // guards above.
        //
        // Relaxing it to `|| recently_aborted(..)` did not help either: `freed.insert` happens
        // ONLY inside `abort`, which writes the abort record in the same critical section, and
        // every acquisition path removes the nonce from `freed`. So `is_freed(N)` already
        // IMPLIES a matching abort record, and the disjunct could only ever change the answer
        // when that record had aged past ABORT_MEMORY or been TTL-swept — i.e. exactly when it
        // wrongly refused. It bought nothing and cost a clock artifact; it is gone.
        if !self.frontier_has_executable_tx_at(mined).await? {
            return Ok(self.hole_we_own(hole));
        }
        // Do NOT stop here. Branch (B) runs FIRST in the detector and its evidence
        // (`recently_aborted`) is sticky for 600s and survives re-reservation, so a stale
        // abort record at `mined` makes it nominate `mined` and mask a genuine hole above
        // — on precisely the shutdown path this function exists for. Fall through and ask
        // for the pending-based hole directly.
        match self.pending_hole(mined).await? {
            Some(h) if h > mined => Ok(self.hole_we_own(h)),
            _ => Ok(None),
        }
    }

    /// Ownership gate for filling ANY hole on the shutdown path.
    ///
    /// "Nothing executable at `pending`" does NOT mean "nobody owns it". The abandon
    /// path pre-reserves a nonce for EVERY doomed job in one burst (`run.rs`, before any task
    /// sends), and each task then makes several throttled RPCs at a 4 req/s global cap before
    /// its first broadcast; the join budget can expire with those tasks still live, since the
    /// timeout does not abort them. Such a nonce looks exactly like a hole.
    ///
    /// Filling it is not a harmless no-op — it is destructive. Heal bids >= 4x base, while
    /// the (pre-ceiling) release ladder topped out at attempt 10, i.e.
    /// 1.15^9 ~= 3.52x base. HISTORICALLY the release path called `escalated_fees` directly
    /// without `fees_over_floor`, so it could never lift over the heal's recorded fee: all 5
    /// attempts were rejected "replacement underpriced" and the releaseJob never reached the
    /// wire, silently. All four job paths now DO lift over the floor, so a heal-vs-release
    /// collision is recoverable rather than terminal — but the gate is still right, because
    /// recoverable is not free: it costs attempts from a deadline-critical budget, and the
    /// shutdown path exits with nothing alive to spend them.
    ///
    /// So require first-person evidence that the nonce is ours and ABANDONED: an abort record
    /// at the hole itself. Every skip arm in the abandon path recycles its nonce via
    /// `abort_nonce`, so this is true in that abandon scenario and false for a live
    /// unsent reservation.
    ///
    /// This is NOT the rejected "no recorded broadcast" heuristic: that inferred absence of a
    /// tx from absence of a fee record (unsound — the staking path records nothing). This is
    /// the PRESENCE of a first-person abort record, the same evidence class branch (B) uses.
    ///
    /// It does re-blind the shutdown path to a pure panic-leak, which is the right trade: the
    /// watchdog owns that shape (persistence-gated, process still alive), whereas here we exit
    /// immediately with nothing left to re-send a release we just destroyed.
    fn hole_we_own(&self, hole: u64) -> Option<u64> {
        // `is_freed` ONLY — deliberately NOT `recently_aborted`.
        //
        // `aborted_at` is designed to survive re-reservation (nonce.rs `or_insert`), and
        // `reserve_locked` reissues the LOWEST freed nonce FIRST. During the abandon burst
        // those two combine badly: the nonce carrying a fresh abort record is typically the
        // one just handed to the NEAREST-DEADLINE job, so the sticky arm reads a live
        // pre-flight release as "abandoned" and fills it — the exact destruction this gate
        // exists to prevent, via the evidence meant to authorise it.
        //
        // `is_freed` is the same evidence class but is invalidated by precisely the event
        // that makes filling destructive: a new owner taking the nonce.
        //
        // Branch (B) keeps `recently_aborted`: it needs the flicker-proofing (a periodic
        // sample can otherwise miss a one-nonce wedge) and it runs on the live watchdog,
        // where a wrong answer is re-sendable now that every send path reads and writes the
        // per-nonce fee floor.
        //
        // Branch (B) is NOT separately gated by `frontier_has_executable_tx`: that gate
        // exists only in THIS function, which the watchdog never calls. Branch (B) is
        // consumed ungated. What actually bounds it is
        // `note_broadcast` clearing `aborted_at` on an accepted send, so a re-reserved nonce
        // stops looking abandoned the moment it is legitimately in use.
        if self.nonce_mgr.is_freed(hole) {
            return Some(hole);
        }
        // Also ours, and provably unowned: a nonce left UNRESOLVED by a fee-cap give-up is
        // in neither `freed` nor reachable by `reserve_locked`, so unlike the sticky
        // `aborted_at` record it cannot name a live pre-flight release taken by a sibling.
        // Without this the bail arms are a skip arm that does not recycle, and this gate
        // declines the resulting hole as "not ours" -- stranding every queued releaseJob
        // above it during the drain.
        if self.nonce_mgr.is_unresolved(hole) {
            return Some(hole);
        }
        tracing::info!(
            "nonce {hole} looks like a hole but we hold neither a recycled-gap nor an \
             unresolved record for it — it may be a \
             live unsent reservation; not filling it during shutdown"
        );
        None
    }

    pub async fn heal_nonce_gap(&self) -> Result<bool> {
        match self.nonce_gap_frontier().await? {
            Some(h) => self.heal_nonce_gap_at(h).await,
            None => Ok(false),
        }
    }

    /// Fill/displace EXACTLY `hole`.
    ///
    /// Any caller that VETTED a nonce MUST use this rather than [`heal_nonce_gap`].
    ///
    /// This split is not cosmetic. `heal_nonce_gap` re-derives its target from the UNGATED
    /// `nonce_gap_frontier`, whose branch (B) is checked FIRST and nominates `mined` on a
    /// sticky `recently_aborted` record. `nonce_gap_safe_to_fill` deliberately DISAGREES
    /// with that — the fall-through is the whole point, and
    /// `a_stale_abort_record_at_the_frontier_does_not_mask_a_hole_above_it` pins a state
    /// where the two return different nonces. So a caller that gated and then called the
    /// argument-less form filled precisely the nonce its gate had refused: on the shutdown
    /// path, the executable `releaseJob` at the frontier, at >=4x base, with `process::exit`
    /// a few lines later and nothing alive to re-send it. Every safety property the gate
    /// reasons about was unenforced at the only place a transaction is signed.
    ///
    /// [`heal_nonce_gap`]: ChainClient::heal_nonce_gap
    /// Like [`heal_nonce_gap_at`], but ONLY if the nonce is still a gap we own at the moment
    /// of the claim.
    ///
    /// For the shutdown path, where the safety gate and the broadcast are separated by at
    /// least one throttled RPC round-trip (`base_fees`). In that window a sibling task can
    /// take the nonce — `reserve_locked` hands out the lowest freed first, which is precisely
    /// the nonce the gate approved — broadcast an immediately-executable releaseJob on it, and
    /// have its accepted send clear the abort record. The healer would then evict it and exit,
    /// stranding that job's collateral until its lock deadline. `claim_gap`'s return value is
    /// the atomic check-and-take that closes the window.
    ///
    /// The watchdog deliberately uses the unchecked form: branch (A) leak-holes and
    /// `note_unresolved` holes are legitimately NOT in `freed`.
    ///
    /// [`heal_nonce_gap_at`]: ChainClient::heal_nonce_gap_at
    pub async fn heal_owned_nonce_gap_at(
        &self,
        hole: u64,
        receipt_budget: std::time::Duration,
    ) -> Result<OwnedHealOutcome> {
        // `claim_gap` is `freed.remove()`, so it is FALSE for a nonce left UNRESOLVED by a
        // fee-cap give-up -- those are deliberately kept out of `freed` so no reserver can
        // take them. Treating that as "someone else owns it" would make the hole
        // permanently unfillable during the drain, which is the opposite of the truth: an
        // unresolved nonce provably has no second owner.
        let claimed = self.nonce_mgr.claim_gap(hole);
        if !claimed && !self.nonce_mgr.is_unresolved(hole) {
            tracing::info!(
                "nonce {hole} was re-reserved between the safety gate and the fill — not \
                 displacing; whoever took it owns it now"
            );
            return Ok(OwnedHealOutcome::RefusedNotOurs);
        }
        // `claim_gap` returned true above, so we definitively own this one.
        Ok(
            match self.heal_claimed_gap_at(hole, true, receipt_budget).await? {
                true => OwnedHealOutcome::Filled,
                false => OwnedHealOutcome::Unconfirmed,
            },
        )
    }

    pub async fn heal_nonce_gap_at(&self, hole: u64) -> Result<bool> {
        let owned = self.nonce_mgr.claim_gap(hole);
        // The watchdog runs in a live process with no deadline pressure, so it keeps the
        // original budget and this path is byte-for-byte unchanged.
        self.heal_claimed_gap_at(hole, owned, HEAL_RECEIPT_BUDGET)
            .await
    }

    /// The fill itself. The caller has already claimed `hole` out of the allocator.
    ///
    /// `owned` is `claim_gap`'s verdict: whether the nonce was still a recycled gap of ours.
    /// It is routinely FALSE on the watchdog path — branch (A) holes are found off the node's
    /// pending count and are never in `freed`, and `note_unresolved` holes are deliberately
    /// kept out of it — so the send-error cleanup must not assume otherwise.
    /// `receipt_budget` bounds the confirmation wait. It is a PARAMETER because the shutdown
    /// caller has its own, smaller deadline: a hard-coded 30s inside that caller's 20s budget
    /// is not a race but an arithmetic certainty — the first frontier pass always overruns and
    /// always fails the next top-of-loop check, making the whole multi-hole walk single-shot
    /// in exactly the shape it was written for, and pushing the shutdown past the supervisor's
    /// kill so the worker reap and the exit-75 verdict never run.
    async fn heal_claimed_gap_at(
        &self,
        hole: u64,
        owned: bool,
        receipt_budget: std::time::Duration,
    ) -> Result<bool> {
        // `hole` is the lowest nonce with no executable tx. It is USUALLY the MINED
        // frontier, but need not be: a hole above the frontier blocks everything above it
        // just as effectively, and is the case the detector was previously blind to.
        let next = self.nonce_mgr.peek_next().unwrap_or(hole);
        tracing::warn!(
            "nonce {hole} wedging the signer (next={next}) — filling/displacing with a self-transfer"
        );
        let (base_tip, base_max_fee) = self.base_fees().await;
        // Use a HIGH fee: the hole may be blocked by our own stuck LOW-fee tx (an aborted
        // batch tx during a base-fee spike), which can only be displaced by a strictly
        // higher fee. Overpaying on a rare recovery tx is well worth unwedging the signer.
        let tip = base_tip.saturating_mul(4).max(2_000_000_000); // >= 2 gwei
        let max_fee = base_max_fee.saturating_mul(4).max(tip);
        // The externally-priced bid, BEFORE the floor lift below. This anchors the ratchet
        // cap; using the lifted value would let a floor-derived bid raise its own ceiling.
        let seed_max_fee = max_fee;
        // The blocker may be OUR OWN tx broadcast at this nonce above 4x base (the retry
        // ladder can reach that). A flat 4x would then be rejected "replacement
        // underpriced" and heal would fail silently every tick.
        //
        // Lift over the UNCAPPED high-water. Reading the CAPPED floor here is what made
        // this heal a guaranteed loser: the job paths' exhausted steady state settles at
        // ~1.0415x cap, so a bid of over(cap) = 1.125x cap is only +8.0% over the
        // resident -- under geth's +10% replacement threshold, so every attempt is
        // rejected "replacement transaction underpriced" and the nonce stays wedged
        // indefinitely.
        //
        // BOUNDED. This heal writes its OWN lifted bid back as the new high-water
        // (`note_broadcast` below) while `seed_max_fee` stays frozen at 4x base, so the
        // cap stops moving and each heal would otherwise lift over the previous heal:
        // a self-referential ratchet compounding x9/8 every 60s. Firing every 60s over
        // hours, it would reach ~1 ETH of priority fee on a single
        // 21k self-transfer and then freeze the high-water above what the signer can
        // afford -- leaving the nonce unreservable, undetectable and unhealable, i.e. the
        // permanent signer wedge the cap exists to prevent.
        //
        // So: lift over the UNCAPPED high-water (reading the CAPPED floor is what made
        // this heal a guaranteed loser), but clamp to a hard ceiling.
        // Clamp BOTH members so `tip <= max_fee` is preserved.
        let over = |v: u128| v.saturating_add((v / 8).max(1));
        let mut ceiling_reached = false;
        let (tip, max_fee) = match self.nonce_mgr.fee_floor_state(hole) {
            Some(st) => {
                // The fulfil and release ladders climb to the key-wide fee ceiling, so a heal must be
                // able to out-bid a resident up there too.
                let ceiling = over(over(st.cap.max(self.fee_ceiling)));
                let (bt, bm) = st.broadcast;
                let want_max = max_fee.max(over(bm)).min(ceiling).max(max_fee);
                let want_tip = tip.max(over(bt)).min(ceiling).max(tip).min(want_max);
                // A merely-larger bid is NOT enough: nodes require a MARGIN over the
                // resident (geth 10%, some 12.5%). Once the clamp binds, the bid keeps
                // creeping toward the ceiling while the resident creeps with it, and the
                // ratio decays below the threshold -- at which point every send is
                // rejected "replacement underpriced" again. That is the same under-margin
                // failure in a bounded disguise, and `want_max <= bm` does not catch it: with a
                // 64 gwei cap the third heal bids 81.000 against a 74.193 resident, which
                // is larger but only +9.18%.
                //
                // `over()` IS the 12.5% margin used everywhere else here, so require it.
                if want_max < over(bm) {
                    ceiling_reached = true;
                }
                (want_tip, want_max)
            }
            None => (tip, max_fee),
        };
        if ceiling_reached {
            // Before refusing, ASK THE CHAIN whether a resident still exists here.
            //
            // `ceiling_reached` is derived from local memory only. On a fixed-gas config
            // every input to it is frozen, so once it is true it can never become false
            // on its own -- and if our own heal transactions were accepted and then LOST
            // from the mempool (eviction over a multi-hour wedge, an RPC node restart, a
            // load-balanced replica), the nonce is EMPTY and a plain 4x-base bid would be
            // accepted instantly. Refusing there is terminal until a process restart, and
            // the operator message would say the exact opposite of the truth: eviction is
            // what makes it permanent, not what resolves it.
            let pending = self
                .provider
                .get_transaction_count(self.address)
                .pending()
                .await
                .unwrap_or(u64::MAX);
            if pending <= hole {
                // No executable tx at `hole`: the ladder is stale. Reset it so the next
                // heal starts cheap, and fall through to send at the un-lifted 4x base.
                tracing::warn!(
                    "heal at nonce {hole}: ceiling reached but the chain shows NO resident \
                     (pending={pending}) — our earlier heal was evicted. Resetting the fee \
                     ladder and retrying at base."
                );
                self.nonce_mgr.reset_fee_floor(hole);
                return Box::pin(self.heal_claimed_gap_at(hole, owned, receipt_budget)).await;
            }
            let st = self.nonce_fee_floor_state(hole);
            tracing::error!(
                "HEAL_CEILING_REACHED at nonce {hole}: cannot out-bid the resident within \
                 the heal ceiling (broadcast={:?} cap={:?}, pending={pending}) — refusing \
                 to send rather than spending on a transaction the node will reject. \
                 Re-arming the claim gate; the resident must mine, or be replaced by an \
                 operator-sent transaction at this nonce with a higher fee.",
                st.map(|s| s.broadcast.1),
                st.map(|s| s.cap),
            );
            self.nonce_mgr.note_undisplaceable(hole);
            return Err(anyhow::anyhow!("heal: ceiling reached at nonce {hole}"));
        }
        tracing::warn!(
            "heal bid at nonce {hole}: tip={tip} max_fee={max_fee} \
             (21k self-transfer costs ~{} wei)",
            max_fee.saturating_mul(21_000)
        );
        let tx = alloy::rpc::types::TransactionRequest::default()
            .to(self.address)
            .value(alloy::primitives::U256::ZERO)
            .nonce(hole)
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
                // Send failed → the tx never entered the mempool, so the nonce would leak as
                // a hole. Recycle it ONLY if we actually took it out of `freed`.
                //
                // Unconditional `abort` here inserted into `freed` a nonce a sibling task may
                // own — `claim_gap` had already returned false — and `reserve_locked` hands the
                // lowest freed out FIRST, so the next reserver would be issued a nonce with a
                // live tx on it and `fees_over_floor` would let it out-bid and evict that tx.
                // That breaks the allocator's founding invariant (two tasks never share a
                // nonce), which is what makes same-nonce keep-and-escalate safe everywhere
                // else. `note_unresolved` keeps the gap VISIBLE to the detector next tick
                // without offering it to a reserver.
                if owned {
                    self.nonce_mgr.abort(hole);
                } else {
                    self.nonce_mgr.note_unresolved(hole);
                }
                return Err(anyhow::anyhow!("heal: send self-transfer failed: {e:#}"));
            }
        };
        // Successive heals must out-bid the previous heal at this nonce, not repeat it.
        self.nonce_mgr
            .note_broadcast(hole, tip, max_fee, seed_max_fee);
        let tx_hash = *pending_tx.tx_hash();
        // A fill ABOVE the mined frontier CANNOT mine until every nonce below it does,
        // so waiting for its receipt is a guaranteed 30s burn for an answer we already know.
        // That matters on the shutdown path, where this now runs (it did not before) and the
        // budget is already 45s join + reap against a 90s supervisor kill — burning 30s here
        // can strand the worker reap and the exit-75 verdict. The hole is plugged the moment
        // the tx is in the mempool, which is exactly what the pending count reports.
        // A failed read must NOT default to "the hole is the frontier": `unwrap_or(hole)`
        // made `hole > mined_now` false for EVERY hole, hard-coding the one branch this
        // check exists to skip. One transient 429 — and this is roughly the ninth
        // getTransactionCount of a shutdown burst under a 4 req/s throttle — then cost a
        // 30s receipt wait for a tx that provably cannot mine, returned Ok(false), and broke
        // the multi-hole loop, after the hole had in fact been plugged.
        let above_frontier = match self.provider.get_transaction_count(self.address).await {
            Ok(m) => hole > m,
            Err(e) => {
                tracing::debug!(
                    "heal: post-send frontier read failed ({e:#}); using the mempool probe"
                );
                true
            }
        };
        if above_frontier {
            let plugged = self
                .provider
                .get_transaction_count(self.address)
                .pending()
                .await
                .is_ok_and(|p| p > hole);
            if plugged {
                tracing::info!(
                    "nonce hole at {hole} plugged in the mempool (tx {tx_hash:?}); it mines \
                     once the nonces below it clear"
                );
                return Ok(true);
            }
            self.nonce_mgr.note_unresolved(hole);
            tracing::warn!(
                "nonce gap-fill at {hole} (tx {tx_hash:?}) did not enter the mempool; will retry"
            );
            return Ok(false);
        }
        // Poll for the receipt (no heartbeat watcher). Some+status = unwedged;
        // anything else (no receipt within budget, or a mined revert) → retry next tick.
        // Budget capped at 30s, NOT TX_RECEIPT_TIMEOUT: heal is awaited directly
        // in the brain's 5s scheduler loop (unlike every other site, which runs in a
        // spawned lifecycle task), so a long wait here stalls claim dispatch. On None the
        // watchdog simply re-probes next tick — if the fill tx mined meanwhile the gap is
        // gone; if not, the retry re-sends at the same claimed nonce with a higher fee.
        match crate::tx::await_receipt(&*self.provider, tx_hash, receipt_budget).await {
            Some(r) if r.status() => {
                tracing::info!(
                    "nonce gap at {hole} filled (tx {:?}) — signer unwedged",
                    r.transaction_hash
                );
                self.resync_nonce().await.ok(); // advance the allocator past the filled nonce
                Ok(true)
            }
            other => {
                // Reached only for a fill AT the mined frontier (the above-frontier case
                // returned early). Such a tx is immediately executable, so no receipt inside
                // the budget really is a failure to confirm.
                // Leave evidence so the next tick can still SEE the gap. `claim_gap` above
                // took it out of `freed`, and `next` is only `hole + 1`, so without this
                // neither detector branch fires and the promised retry never happens.
                // Deliberately NOT `abort` — the fill tx may still be live and recycling the
                // nonce into `freed` would let a sibling task collide with it.
                self.nonce_mgr.note_unresolved(hole);
                tracing::warn!("nonce gap-fill at {hole} (tx {tx_hash:?}) not confirmed ({other:?}); will retry");
                Ok(false)
            }
        }
    }

    /// Stash the abandoned fulfill nonce for `job_id` so `release_job` can displace the
    /// stuck fulfill at the SAME nonce. Called by `fulfill_job` on give-up.
    pub fn stash_abandoned_nonce(&self, job_id: alloy::primitives::B256, nonce: u64) {
        let displaced = self
            .abandoned_fulfill_nonces
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(job_id, nonce);
        // `insert` returns whatever it overwrote. `release_job_with_nonce` is the only
        // consumer, and it takes ONE nonce per job_id — so a silently discarded predecessor
        // would be in no set at all: not stashed, not in `freed`, no abort record. That is
        // precisely the invisible-hole shape the gap detector was rewritten to catch, and it
        // would wedge every higher nonce until the watchdog found it. Recycle it instead.
        if let Some(old) = displaced {
            if old != nonce {
                tracing::warn!(
                    "second abandoned-nonce stash for job {job_id:?} displaced nonce {old} \
                     (new {nonce}) — recycling the displaced one so it cannot become a hole"
                );
                self.abort_nonce(old);
            }
        }
    }

    /// Take (and clear) the abandoned fulfill nonce stashed for `job_id`, if any.
    pub fn take_abandoned_nonce(&self, job_id: alloy::primitives::B256) -> Option<u64> {
        self.abandoned_fulfill_nonces
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&job_id)
    }

    /// Whether a fulfil nonce is stashed for `job_id` (without taking it).
    pub fn has_abandoned_nonce(&self, job_id: alloy::primitives::B256) -> bool {
        self.abandoned_fulfill_nonces
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .contains_key(&job_id)
    }

    // ── The DA nonce rule (witness-construction-jobs §5.5) ──────────────────────────────────
    //
    // Hemi's sequencer leaves a transaction above the batcher's per-transaction DA cap out of its
    // blocks, and every later nonce of its sender with it. So a LARGE fulfil goes out only as this
    // key's highest pending nonce, and one that stays unmined is replaced at its nonce by a minimal
    // self-transfer so later nonces proceed (`jobs::fulfill_job_hashed` drives this; `crate::da`
    // holds the decisions and the detector).

    /// This key's DA bookkeeping (see [`crate::da::DaSendBook`]). Never hold the guard across an
    /// `.await`.
    pub fn da_book(&self) -> std::sync::MutexGuard<'_, crate::da::DaSendBook> {
        self.da_book.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Whether `nonce` is the highest nonce this process has handed out: no transaction of ours can
    /// be pending above it. Call it under [`Self::tx_lock`] right before the send — a sibling that
    /// reserves later sends after us, behind the lock.
    pub fn nonce_is_highest_reserved(&self, nonce: u64) -> bool {
        self.nonce_mgr.peek_next() == Some(nonce.saturating_add(1))
    }

    /// Use up a nonce this task reserved but must not spend on a large fulfil (siblings already hold
    /// nonces above it, so a large fulfil there would not be the highest pending one): a 0-value,
    /// 21,000-gas self-transfer at the ordinary fees, lifted over anything already broadcast at it.
    /// About 100 estimated DA bytes, so the throttle never holds it, and the siblings above proceed.
    /// The nonce is spent on success; on a refused send it is recycled.
    pub async fn fill_reserved_nonce(&self, nonce: u64) -> Result<alloy::primitives::B256> {
        let (base_tip, base_max_fee) = self.base_fees().await;
        let over = |v: u128| v.saturating_add((v / 8).max(1));
        let (tip, max_fee) = match self.nonce_mgr.fee_floor_state(nonce) {
            Some(st) => (
                base_tip.max(over(st.broadcast.0)),
                base_max_fee.max(over(st.broadcast.1)),
            ),
            None => (base_tip, base_max_fee),
        };
        let max_fee = max_fee.max(tip);
        let tx = alloy::rpc::types::TransactionRequest::default()
            .to(self.address)
            .value(alloy::primitives::U256::ZERO)
            .nonce(nonce)
            .gas_limit(21_000)
            .max_priority_fee_per_gas(tip)
            .max_fee_per_gas(max_fee);
        let sent = {
            let _guard = self.tx_lock.lock().await;
            self.provider.send_transaction(tx).await
        };
        match sent {
            Ok(p) => {
                self.nonce_mgr.note_broadcast(nonce, tip, max_fee, base_max_fee);
                tracing::info!(
                    "DA nonce rule: nonce {nonce} sits below other reserved nonces — spent it on a \
                     self-transfer ({:?}) so the large fulfil goes out as the highest pending nonce",
                    p.tx_hash()
                );
                Ok(*p.tx_hash())
            }
            Err(e) => {
                self.nonce_mgr.abort(nonce);
                anyhow::bail!("DA nonce rule: filler self-transfer at nonce {nonce} refused: {e:#}")
            }
        }
    }

    /// Replace OUR pending transaction at `nonce` (a large fulfil the DA throttle may be filtering)
    /// by a minimal self-transfer at a bumped fee, so every later nonce of this key proceeds. This is
    /// the gap healer's fill ([`Self::heal_nonce_gap_at`]): a 21,000-gas self-transfer lifted 12.5%
    /// over the highest fee broadcast at the nonce, within the heal ceiling. `Ok(true)` once it is
    /// mined (or plugged in the mempool, above the frontier); `Ok(false)` if sent but unconfirmed
    /// (the nonce stays visible to the gap watchdog); `Err` if the send was refused (e.g. "nonce too
    /// low": the transaction mined first) or no out-bid is possible within the heal ceiling (the
    /// nonce is then marked undisplaceable, which shuts the claim gate via
    /// [`Self::signer_is_jammed`]).
    pub async fn replace_with_self_transfer(&self, nonce: u64) -> Result<bool> {
        tracing::warn!(
            "DA nonce rule: replacing our unmined transaction at nonce {nonce} with a self-transfer"
        );
        self.heal_nonce_gap_at(nonce).await
    }

    /// Base EIP-1559 fees used to SEED per-attempt fee escalation on tx re-broadcasts.
    /// Returns `(base_priority_fee, base_max_fee)` in wei.
    ///
    /// This is the linchpin for replacing a stuck same-nonce tx: with default config
    /// (`gas_price` unset), the tx builders leave fees to the provider's auto-fill,
    /// which re-broadcasts at ~the same price and is rejected "replacement underpriced"
    /// forever. Callers escalate these per attempt so a re-broadcast reliably out-bids
    /// (and thus displaces) a stuck predecessor. A configured fixed `gas_price` takes
    /// precedence (legacy behavior).
    ///
    /// NEVER returns `(0, 0)` from estimation failure: a zero base
    /// disables every `base_max_fee > 0` escalation gate, so a stuck tx could never clear a
    /// node's replacement threshold. The fallback is the last header's base fee, else
    /// `eth_gasPrice`; `hemi_fees` keeps the tip at >= 0.01 gwei either way.
    /// (A configured `gas_price` of 0 would still short-circuit to `(0, 0)`; config
    /// validation rejects that.)
    pub async fn base_fees(&self) -> (u128, u128) {
        let (tip, max_fee, from_header) = self.base_fees_uncached().await;
        // Only a quote from a real header: the claim gate reads this figure, and a fallback quote (a
        // failed header read) must not be what it keeps closing on.
        if from_header {
            self.last_max_fee
                .store(max_fee.min(u64::MAX as u128) as u64, Ordering::Relaxed);
        }
        (tip, max_fee)
    }

    /// The `maxFeePerGas` the last [`Self::base_fees`] quoted (0 before the first quote).
    pub fn last_max_fee(&self) -> u128 {
        self.last_max_fee.load(Ordering::Relaxed) as u128
    }

    async fn base_fees_uncached(&self) -> (u128, u128, bool) {
        // The latest block's base fee (fallback: the last header's, else eth_gasPrice — see below).
        let mut from_header = true;
        let base = match self
            .provider
            .get_block_by_number(alloy::eips::BlockNumberOrTag::Latest)
            .await
        {
            Ok(Some(b)) => {
                note_chain_time(b.header.timestamp);
                let base = b.header.base_fee_per_gas.map(u128::from).unwrap_or(0);
                self.last_base_fee
                    .store(base.min(u64::MAX as u128) as u64, Ordering::Relaxed);
                base
            }
            other => {
                if let Err(e) = &other {
                    tracing::debug!("latest block read for fees failed: {e:#}; falling back to eth_gasPrice");
                }
                from_header = false;
                // The last header's base fee, else eth_gasPrice as quoted. Never a fixed 1-gwei floor:
                // that is ~1e6 x Hemi's live base fee, and a maxFee seeded from it froze the fulfil
                // ladder. `hemi_fees` keeps the pair non-zero (tip >= 0.01 gwei).
                match self.last_base_fee.load(Ordering::Relaxed) {
                    0 => self.provider.get_gas_price().await.unwrap_or(0),
                    b => b as u128,
                }
            }
        };
        if let Some(gp) = self.gas_price {
            // A configured fixed price is honoured, but never below the Hemi floors.
            let (tip, max_fee) = hemi_fees(base, 0);
            let tip = gp.max(tip);
            return (
                tip,
                gp.max(max_fee).max(base.saturating_mul(2).saturating_add(tip)),
                from_header,
            );
        }
        let suggested = match self.provider.get_max_priority_fee_per_gas().await {
            Ok(v) => v,
            Err(e) => {
                tracing::debug!("eth_maxPriorityFeePerGas failed: {e:#}; using the tip floor");
                0
            }
        };
        // The suggestion is 1.1 x the median tip of the last block once it is near capacity, so a
        // block-filler can set it (up to op-geth's 500 gwei): never let it push the start price past
        // the key-wide ceiling.
        let (tip, max_fee) = hemi_fees(base, suggested.min(self.fee_ceiling / 2));
        (tip, max_fee, from_header)
    }

    /// Read the latest block header and record its timestamp (see [`chain_now`]). Best-effort: a
    /// failed read keeps the previous skew.
    pub async fn refresh_chain_time(&self) {
        if let Ok(Some(b)) = self
            .provider
            .get_block_by_number(alloy::eips::BlockNumberOrTag::Latest)
            .await
        {
            note_chain_time(b.header.timestamp);
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

    /// Record the submitting tx hash for a job (from the monitor's
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

    /// The cached submitting tx hash for a job, if the monitor saw its
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
        use zkminer_contracts::bindings::{IHemiProveStaking, IERC20};
        let token = IERC20::new(self.hemi_token, &*self.provider);
        let staking = IHemiProveStaking::new(self.hemi_prove_staking, &*self.provider);
        // Each contract view is added with allowFailure=TRUE. alloy's
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
                // aggregate3 runs every sub-call at one block, the head read beside them.
                read_block: head,
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

#[cfg(test)]
mod fee_rule_tests {
    use super::{hemi_fees, MIN_PRIORITY_FEE_WEI};

    #[test]
    fn tip_never_drops_below_the_hemi_floor() {
        // A quiet chain suggests a 1-wei (or zero) tip, which is accepted but never mined.
        assert_eq!(hemi_fees(254, 0).0, MIN_PRIORITY_FEE_WEI);
        assert_eq!(hemi_fees(254, 1).0, MIN_PRIORITY_FEE_WEI);
        // Above the floor, twice the node's suggestion.
        assert_eq!(hemi_fees(254, 1_000_000_000).0, 2_000_000_000);
    }

    #[test]
    fn max_fee_covers_two_base_fees_plus_the_tip() {
        let (tip, max_fee) = hemi_fees(254, 1_000_000);
        assert_eq!(max_fee, 2 * 254 + tip);
        assert!(max_fee >= tip, "maxFee >= tip, or the node refuses the tx");
        // Saturates instead of overflowing on absurd inputs.
        let (t, m) = hemi_fees(u128::MAX, u128::MAX);
        assert_eq!((t, m), (u128::MAX, u128::MAX));
    }
}

#[cfg(test)]
mod chain_clock_tests {
    use super::*;

    /// One test owns the process-wide clock (tests run concurrently; splitting this would race).
    #[test]
    fn a_lagging_header_never_moves_the_chain_clock_back() {
        let wall = wall_now();
        // A fresh header 3 s "ahead" of this host (a host clock running slow).
        note_chain_time(wall + 3);
        let after_fresh = chain_now();
        assert!(after_fresh >= wall + 3, "the upper estimate follows a header ahead of the wall clock");
        assert!(chain_now_floor() <= wall_now(), "the lower estimate never exceeds the wall clock");
        // A lagging replica's header, 300 s behind: ignored.
        note_chain_time(wall.saturating_sub(300));
        assert!(
            chain_now() >= after_fresh,
            "a stale header must not pull the deadline guards' clock back"
        );
        // The upper estimate is never below the wall clock.
        assert!(chain_now() >= wall_now().min(chain_now()));
        assert!(chain_now() >= wall);
    }
}
