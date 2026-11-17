//! Hemi's DA throttle, as a fulfil meets it (witness-construction-jobs §5.5, §13.5; the contracts'
//! `DEPLOY_RUNBOOK.md` residual 15 and `scripts/check-l2-lag.sh`).
//!
//! Hemi's sequencer leaves out of its blocks every transaction whose estimated DA size is above the
//! batcher's per-transaction cap, whatever it tips, and every later nonce of its sender with it. The
//! estimate is the Fjord one: `GasPriceOracle.getL1GasUsed(unsigned tx) / 16`, which is
//! `max(100, -42.5856 + 0.8365 x (FastLZ(unsigned tx) + 68))` bytes — the figure a mined receipt
//! carries as `l1GasUsed / 16`. This module holds:
//!
//! - the estimate ([`estimated_da_bytes`], [`estimate_fulfil_da_bytes`]);
//! - the throttle curve ([`live_tx_cap`]) and the claim gate's cap policy ([`DaCapPolicy`],
//!   [`DaCapPolicy::fulfil_fits`]);
//! - the backlog reading of §13.5 ([`BacklogReader`]), with its RPC cost bounded;
//! - the DA nonce rule's decisions ([`NonceRuleConfig`]) and the bookkeeping of this key's fulfils
//!   ([`DaSendBook`], held by [`ChainClient`]);
//! - the detector for pending-but-unmined transactions and the safe-head lag
//!   ([`ChainClient::observe_pending`], [`ChainClient::safe_head_lag`]).
//!
//! **The curve.** op-batcher's defaults (hemilabs/optimism 45182b8, `quadratic_strategy.go`), as the
//! contracts' runbook and `check-l2-lag.sh` state them: no per-transaction cap while the unposted
//! backlog `B` is at or below 3.2 MB; above it, with `i = min(1, (B - 3.2 MB) / 9.6 MB)^2`, the cap
//! is `20,000 - i x 19,850` (truncated to an integer), so 20,000 from the first throttled update,
//! 150 from 12.8 MB on. MB here is 10^6 bytes, as op-batcher's thresholds. §5.5's "20,000 estimated
//! bytes, falling to 150 at 12.8 MB" is this curve; the interpolation is QUADRATIC in the backlog,
//! not linear (at 8 MB the cap is 15,037, not 10,075).
//!
//! **The reading is a lower bound.** The batcher also counts channels it closed but L1 has not made
//! safe, in compressed bytes: up to 1.159 x this module's estimate for incompressible fill
//! (`check-l2-lag.sh`, `DA_BACKLOG_ACTION_BYTES`). Every cap decision here therefore evaluates the
//! curve at `1.159 x` the measured backlog ([`batcher_view`]).

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use alloy::consensus::{SignableTransaction, TxEip1559};
use alloy::eips::BlockNumberOrTag;
use alloy::primitives::{Address, Bytes, TxKind, B256, U256};
use alloy::providers::Provider;
use anyhow::{Context, Result};
use zkminer_contracts::bindings::{IGasPriceOracle, GAS_PRICE_ORACLE};

use crate::client::ChainClient;
use crate::jobs::HashedFulfil;

// ── constants ─────────────────────────────────────────────────────────────────

/// A fulfil above this many estimated DA bytes is LARGE for the DA nonce rule (§5.5: "the standard
/// size, about 600 estimated bytes"; standard risc0 and SP1 fulfils measure 455-583).
pub const STANDARD_FULFIL_DA_BYTES: u64 = 600;
/// The claim gate's default operator cap on the exact fulfil's estimated DA bytes (§19
/// `fulfil_da_cap_bytes`).
pub const DEFAULT_FULFIL_DA_CAP_BYTES: u64 = 2_048;
/// The most an operator may raise that cap to: the lower no-stall equilibrium cap the deploy runbook
/// derives (8,540 at a 10.49 MB equilibrium backlog), rounded down.
pub const MAX_FULFIL_DA_CAP_BYTES: u64 = 8_500;
/// Above this measured backlog the claim gate uses the live per-transaction cap or skips (§19
/// `da_backlog_hold_bytes`; the guardian pages at this level and pauses the router at 2.75 MB).
pub const DEFAULT_DA_BACKLOG_HOLD_BYTES: u64 = 2_500_000;
/// op-batcher's lower throttle threshold: no per-transaction cap at or below it.
pub const THROTTLE_LOWER_BYTES: u64 = 3_200_000;
/// op-batcher's upper throttle threshold: the cap is at its floor from here on.
pub const THROTTLE_UPPER_BYTES: u64 = 12_800_000;
/// The per-transaction cap at the first throttled update.
pub const THROTTLE_TX_CAP_HIGH: u64 = 20_000;
/// The per-transaction cap at full intensity.
pub const THROTTLE_TX_CAP_LOW: u64 = 150;
/// The batcher's view of the backlog is up to this much (per mille) of the receipts' estimate.
pub const BATCHER_OVERCOUNT_PERMILLE: u64 = 1_159;
/// The safe-head lag (`ts(latest) - ts(safe)`) above which an unmined large fulfil is replaced
/// (§5.5) — the reference daemons' `SAFE-LAG` page level.
pub const SAFE_LAG_REPLACE_SECS: u64 = 600;
/// Blocks an accepted large fulfil may stay unmined before it is replaced (the daemons'
/// `PENDING_PAGE_BLOCKS`).
pub const DEFAULT_UNMINED_BLOCKS: u64 = 10;
/// After a replacement, how many blocks to wait before re-sending when the throttle cannot be read
/// (or the lag stays high) — so ignorance never holds a fulfil to its deadline.
pub const DEFAULT_RESEND_BACKOFF_BLOCKS: u64 = 50;
/// The most unposted blocks a backlog reading scans (30 min of 12-s blocks, three times the
/// `SAFE-LAG` page). A longer lag reads as unknown, which every decision treats as above threshold.
pub const DEFAULT_BACKLOG_MAX_BLOCKS: u64 = 150;
/// The Fjord estimate's floor (`MIN_TRANSACTION_SIZE`).
pub const MIN_ESTIMATED_DA_BYTES: u64 = 100;
/// A RISC Zero Groth16 seal: the 4-byte verifier selector, then the 256-byte proof.
pub const RISC0_GROTH16_SEAL_LEN: usize = 260;
/// `FulfilFailure::error_name` of a fulfil held (or replaced) by the DA throttle rules: KEEP the lock
/// and call the fulfil again later; it re-sends once the throttle clears.
pub const DA_THROTTLE_HOLD_NAME: &str = "DaThrottleHold";

/// Receipt types with no DA footprint (op-geth `IsZeroDAFootprintTx`): deposits (0x7e), Hemi's PoP
/// payouts (0x7d) and BTC-attributes deposits (0x7c).
const SYSTEM_TX_TYPES: [u64; 3] = [0x7c, 0x7d, 0x7e];
/// Users' transaction types, which carry `l1GasUsed` on an OP Stack (Fjord) node.
const USER_TX_TYPES: [u64; 4] = [0x0, 0x1, 0x2, 0x4];

// ── the curve and the cap policy ──────────────────────────────────────────────

/// The per-transaction cap op-batcher's defaults push at a backlog of `backlog` bytes (as the
/// batcher counts it), or `None` (no cap) at or below 3.2 MB. See the module docs for the curve.
pub fn live_tx_cap(backlog: u64) -> Option<u64> {
    if backlog <= THROTTLE_LOWER_BYTES {
        return None;
    }
    let span = u128::from(THROTTLE_UPPER_BYTES - THROTTLE_LOWER_BYTES);
    let excess = u128::from(backlog - THROTTLE_LOWER_BYTES).min(span);
    let drop = u128::from(THROTTLE_TX_CAP_HIGH - THROTTLE_TX_CAP_LOW);
    // floor(HIGH - (excess / span)^2 x drop), exactly, in integers.
    let num = u128::from(THROTTLE_TX_CAP_HIGH) * span * span - excess * excess * drop;
    Some((num / (span * span)) as u64)
}

/// The batcher's possible view of a measured backlog (see the module docs).
pub fn batcher_view(measured: u64) -> u64 {
    measured.saturating_mul(BATCHER_OVERCOUNT_PERMILLE) / 1_000
}

/// A backlog reading's verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backlog {
    /// The whole unposted window was read: this many estimated bytes (this key's unmined fulfils
    /// included).
    Known(u64),
    /// Only part of it was read: at least this many.
    AtLeast(u64),
    /// Unreadable: the lag exceeds the scan cap, the endpoint is not an OP Stack Fjord node, or a
    /// read failed.
    Unknown,
}

impl Backlog {
    /// Whether the throttle would filter a transaction of `estimated` bytes: `Some(true)` provably
    /// (a known reading, or a partial one whose lower bound already caps below it), `Some(false)`
    /// provably not (a known reading), `None` unknown.
    pub fn would_filter(self, estimated: u64) -> Option<bool> {
        match self {
            Backlog::Known(b) => Some(live_tx_cap(batcher_view(b)).is_some_and(|c| estimated > c)),
            // The cap only falls as the backlog grows: the cap at a lower bound bounds it from above.
            Backlog::AtLeast(b) => live_tx_cap(batcher_view(b))
                .is_some_and(|c| estimated > c)
                .then_some(true),
            Backlog::Unknown => None,
        }
    }
}

/// What the claim gate does above the hold level (§5.5 "uses the live per-transaction cap or skips").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AboveHold {
    /// Keep the fulfil under the smaller of the operator cap and the live cap.
    LiveCap,
    /// Skip every witness job while the backlog is above the hold level.
    Skip,
}

/// The claim gate's DA policy (§5.2 step 7, §5.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DaCapPolicy {
    cap_bytes: u64,
    /// Above this measured backlog, [`Self::above_hold`] applies.
    pub hold_backlog_bytes: u64,
    pub above_hold: AboveHold,
}

impl Default for DaCapPolicy {
    fn default() -> Self {
        Self {
            cap_bytes: DEFAULT_FULFIL_DA_CAP_BYTES,
            hold_backlog_bytes: DEFAULT_DA_BACKLOG_HOLD_BYTES,
            above_hold: AboveHold::LiveCap,
        }
    }
}

/// Why the claim gate's DA check refused a job.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkipReason {
    /// The exact fulfil is above the operator cap.
    OverOperatorCap { estimated: u64, cap: u64 },
    /// The backlog is above the hold level and the live cap (at the batcher's view) is below the
    /// fulfil.
    OverLiveCap {
        estimated: u64,
        live_cap: u64,
        backlog: u64,
    },
    /// The backlog is above the hold level and the policy skips there.
    AboveHold { backlog: u64 },
    /// The backlog could not be read: treated as above the hold level, at the worst-case cap.
    BacklogUnknown { estimated: u64, worst_case_cap: u64 },
}

/// [`DaCapPolicy::fulfil_fits`]'s answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// The fulfil fits; `cap` is the effective cap it was held to.
    Fits {
        cap: u64,
    },
    Skip(SkipReason),
}

impl Decision {
    pub fn fits(&self) -> bool {
        matches!(self, Decision::Fits { .. })
    }
}

impl DaCapPolicy {
    /// A policy with operator cap `cap_bytes` (1 to [`MAX_FULFIL_DA_CAP_BYTES`]).
    pub fn new(cap_bytes: u64) -> Result<Self> {
        anyhow::ensure!(
            (1..=MAX_FULFIL_DA_CAP_BYTES).contains(&cap_bytes),
            "fulfil_da_cap_bytes {cap_bytes} is outside 1..={MAX_FULFIL_DA_CAP_BYTES} (the runbook's \
             lower no-stall equilibrium cap)"
        );
        Ok(Self {
            cap_bytes,
            ..Self::default()
        })
    }

    pub fn cap_bytes(&self) -> u64 {
        self.cap_bytes
    }

    /// The claim gate's DA check: whether a fulfil of `estimated_bytes` (the EXACT fulfil: real
    /// journal, `callbackExtraData`, `extraVerifierData`, seal) may be taken on at `backlog`.
    ///
    /// Always under the operator cap. While the backlog is above the hold level, also under the live
    /// cap at the batcher's view (or skipped, per [`AboveHold`]). An unknown or partial reading is
    /// "above threshold" at the worst case, the 150-byte floor: no proof-carrying fulfil fits then.
    pub fn fulfil_fits(&self, estimated_bytes: u64, backlog: Backlog) -> Decision {
        if estimated_bytes > self.cap_bytes {
            return Decision::Skip(SkipReason::OverOperatorCap {
                estimated: estimated_bytes,
                cap: self.cap_bytes,
            });
        }
        let measured = match backlog {
            Backlog::Known(b) => b,
            Backlog::AtLeast(_) | Backlog::Unknown => {
                if self.above_hold == AboveHold::Skip || estimated_bytes > THROTTLE_TX_CAP_LOW {
                    return Decision::Skip(SkipReason::BacklogUnknown {
                        estimated: estimated_bytes,
                        worst_case_cap: THROTTLE_TX_CAP_LOW,
                    });
                }
                return Decision::Fits {
                    cap: THROTTLE_TX_CAP_LOW,
                };
            }
        };
        if measured <= self.hold_backlog_bytes {
            return Decision::Fits {
                cap: self.cap_bytes,
            };
        }
        if self.above_hold == AboveHold::Skip {
            return Decision::Skip(SkipReason::AboveHold { backlog: measured });
        }
        match live_tx_cap(batcher_view(measured)) {
            Some(live) if estimated_bytes > live => Decision::Skip(SkipReason::OverLiveCap {
                estimated: estimated_bytes,
                live_cap: live,
                backlog: measured,
            }),
            Some(live) => Decision::Fits {
                cap: live.min(self.cap_bytes),
            },
            None => Decision::Fits {
                cap: self.cap_bytes,
            },
        }
    }
}

// ── the estimate ──────────────────────────────────────────────────────────────

/// The unsigned EIP-1559 transaction's RLP, as `GasPriceOracle.getL1GasUsed` takes it: the EIP-2718
/// signing payload `0x02 || rlp([chainId, nonce, tip, maxFee, gas, to, 0, input, []])`. The oracle
/// adds 68 bytes for the signature itself.
pub fn unsigned_eip1559_tx(
    chain_id: u64,
    nonce: u64,
    gas_limit: u64,
    max_fee_per_gas: u128,
    max_priority_fee_per_gas: u128,
    to: Address,
    input: Bytes,
) -> Vec<u8> {
    TxEip1559 {
        chain_id,
        nonce,
        gas_limit,
        max_fee_per_gas,
        max_priority_fee_per_gas,
        to: TxKind::Call(to),
        value: U256::ZERO,
        access_list: Default::default(),
        input,
    }
    .encoded_for_signing()
}

/// The fulfil transaction for an estimate, with every field the miner may still change (nonce, gas
/// limit, the fee ladder's fields) at a value at least as long in RLP as any it will send: the
/// estimate never comes out below the transaction actually sent. The calldata is exact.
pub fn conservative_fulfil_tx(chain_id: u64, router: Address, calldata: Bytes) -> Vec<u8> {
    unsigned_eip1559_tx(
        chain_id,
        u64::from(u32::MAX),
        u64::from(u32::MAX),
        u128::from(u64::MAX),
        u128::from(u64::MAX),
        router,
        calldata,
    )
}

/// `GasPriceOracle.getL1GasUsed(unsigned_tx) / 16`: the estimated DA size the sequencer's cap
/// compares (Fjord; the oracle adds the 68-byte signature). `unsigned_tx` is
/// [`unsigned_eip1559_tx`]'s encoding. One `eth_call`, at the latest block.
pub async fn estimated_da_bytes(client: &ChainClient, unsigned_tx: &[u8]) -> Result<u64> {
    let gpo = IGasPriceOracle::new(GAS_PRICE_ORACLE, &*client.provider);
    let used: U256 = gpo
        .getL1GasUsed(Bytes::copy_from_slice(unsigned_tx))
        .call()
        .await
        .context("GasPriceOracle.getL1GasUsed")?;
    Ok((used / U256::from(16u8)).saturating_to::<u64>())
}

/// An upper bound on `getL1GasUsed / 16` for an unsigned transaction of `unsigned_tx_len` bytes,
/// with no RPC: FastLZ (level 1) emits incompressible input as literal runs of at most 32 bytes,
/// one header byte each, so its output is at most `len + ceil(len / 32)` (plus a few bytes of
/// slack); the Fjord regression is then applied to that plus the 68-byte signature allowance.
/// (The oracle's own `getL1FeeUpperBound` uses `len / 255`, a 99.99th-percentile bound for real
/// transactions, which a seal-heavy payload exceeds.) The fallback when the oracle cannot be read.
pub fn da_bytes_upper_bound(unsigned_tx_len: usize) -> u64 {
    let n = unsigned_tx_len as u128;
    let flz = n + n.div_ceil(32) + 16;
    let scaled = 836_500u128 * (flz + 68);
    let est = (scaled.saturating_sub(42_585_600) / 1_000_000) as u64;
    est.max(MIN_ESTIMATED_DA_BYTES)
}

/// The seal to estimate a fulfil with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SealSpec {
    /// The real seal.
    Exact(Bytes),
    /// A seal not yet proven: `len` bytes of pseudo-random filler. A seal is incompressible, so the
    /// filler must be too — zeros would compress to almost nothing and under-estimate by about
    /// `len` bytes.
    Placeholder { len: usize },
}

impl SealSpec {
    /// A RISC Zero Groth16 seal's placeholder.
    pub fn risc0_groth16() -> Self {
        SealSpec::Placeholder {
            len: RISC0_GROTH16_SEAL_LEN,
        }
    }

    pub fn bytes(&self) -> Bytes {
        match self {
            SealSpec::Exact(b) => b.clone(),
            SealSpec::Placeholder { len } => incompressible(*len, b"zkminer/da/seal-placeholder"),
        }
    }
}

/// `len` pseudo-random bytes (a keccak stream): FastLZ finds no match in them.
pub fn incompressible(len: usize, seed: &[u8]) -> Bytes {
    let mut out = Vec::with_capacity(len + 32);
    let mut state = alloy::primitives::keccak256(seed);
    while out.len() < len {
        state = alloy::primitives::keccak256(state);
        out.extend_from_slice(state.as_slice());
    }
    out.truncate(len);
    out.into()
}

/// An estimate of one exact fulfil.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FulfilDaEstimate {
    /// `getL1GasUsed / 16` of the conservative transaction.
    pub estimated_bytes: u64,
    /// The `fulfillJobHashed` calldata's length (selector included): the gas formula's input.
    pub calldata_len: usize,
    /// The unsigned transaction's length.
    pub unsigned_tx_len: usize,
}

impl FulfilDaEstimate {
    /// LARGE for the DA nonce rule (above [`STANDARD_FULFIL_DA_BYTES`]).
    pub fn is_large(&self) -> bool {
        self.estimated_bytes > STANDARD_FULFIL_DA_BYTES
    }
}

/// The estimated DA bytes of the exact `fulfillJobHashed` transaction the miner would send for
/// `job_id`: `fulfil`'s hashed descriptor, `callbackExtraData` and `extraVerifierData`, the real
/// `journal`, and `seal` (or a placeholder of its length). Fields the miner may still change are
/// taken at their longest ([`conservative_fulfil_tx`]). One `eth_call`.
pub async fn estimate_fulfil_da_bytes(
    client: &ChainClient,
    job_id: B256,
    fulfil: &HashedFulfil,
    journal: &[u8],
    seal: &SealSpec,
) -> Result<FulfilDaEstimate> {
    let calldata = crate::jobs::fulfill_job_hashed_calldata(job_id, fulfil, journal, &seal.bytes());
    let calldata_len = calldata.len();
    let tx = conservative_fulfil_tx(client.chain_id, client.hemi_prove, calldata);
    Ok(FulfilDaEstimate {
        estimated_bytes: estimated_da_bytes(client, &tx).await?,
        calldata_len,
        unsigned_tx_len: tx.len(),
    })
}

// ── the backlog reading (§13.5) ───────────────────────────────────────────────

/// The scan's bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BacklogConfig {
    /// Read at most this many unposted blocks; more reads as [`Backlog::Unknown`].
    pub max_blocks: u64,
}

impl Default for BacklogConfig {
    fn default() -> Self {
        Self {
            max_blocks: DEFAULT_BACKLOG_MAX_BLOCKS,
        }
    }
}

/// One backlog reading: §13.5's "sum of `l1GasUsed / 16` over user transactions in (safe head,
/// head]", plus this key's unmined fulfil estimates, with the safe-head lag of the same two headers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BacklogReading {
    pub head: Option<u64>,
    pub head_timestamp: Option<u64>,
    pub safe: Option<u64>,
    pub safe_timestamp: Option<u64>,
    /// `ts(latest) - ts(safe)` (`None` if a header read failed).
    pub safe_lag_secs: Option<u64>,
    /// The chain part of the sum, when the whole window was read.
    pub chain_bytes: Option<u64>,
    /// This key's unmined fulfil estimates ([`DaSendBook::unmined_bytes`]).
    pub own_unmined_bytes: u64,
    pub backlog: Backlog,
    /// Blocks whose receipts this reading fetched (the rest came from the cache).
    pub blocks_fetched: u64,
    /// Why the backlog is not [`Backlog::Known`], if it is not.
    pub note: Option<String>,
}

impl BacklogReading {
    /// A reading with a given verdict and lag, for an operator override or a test (see
    /// [`BacklogSource::Fixed`]).
    pub fn fixed(backlog: Backlog, safe_lag_secs: Option<u64>) -> Self {
        Self {
            head: None,
            head_timestamp: None,
            safe: None,
            safe_timestamp: None,
            safe_lag_secs,
            chain_bytes: match backlog {
                Backlog::Known(b) => Some(b),
                _ => None,
            },
            own_unmined_bytes: 0,
            backlog,
            blocks_fetched: 0,
            note: None,
        }
    }
}

/// What one block contributes to the backlog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockDa {
    /// From the receipts' `blockHash` (`None` for a block without receipts).
    pub hash: Option<B256>,
    pub bytes: u64,
    /// Why this block cannot be counted, if it cannot.
    pub unreadable: Option<String>,
}

/// Reads the backlog, caching each unposted block's contribution by number and hash, so a reading
/// fetches only the blocks it has not seen: two headers (head, safe), the receipts of each new block,
/// and one header to check that the new blocks extend the cached ones. A head whose hash changed, or
/// new blocks that do not extend the cache, drop the cache (a reorg). Readers are serialized, so
/// concurrent callers never fetch the same block twice.
pub struct BacklogReader {
    cfg: BacklogConfig,
    cache: tokio::sync::Mutex<BTreeMap<u64, BlockDa>>,
}

impl Default for BacklogReader {
    fn default() -> Self {
        Self::new(BacklogConfig::default())
    }
}

impl BacklogReader {
    pub fn new(cfg: BacklogConfig) -> Self {
        Self {
            cfg,
            cache: tokio::sync::Mutex::new(BTreeMap::new()),
        }
    }

    pub fn config(&self) -> BacklogConfig {
        self.cfg
    }

    /// One reading. Never fails: whatever cannot be read leaves the backlog [`Backlog::Unknown`]
    /// (with a [`BacklogReading::note`]), and a failed header read leaves the lag `None`.
    pub async fn read(&self, client: &ChainClient) -> BacklogReading {
        let own = client.da_book().unmined_bytes();
        let mut r = BacklogReading::fixed(Backlog::Unknown, None);
        r.own_unmined_bytes = own;
        let unknown = |mut r: BacklogReading, why: String| {
            r.backlog = Backlog::Unknown;
            r.chain_bytes = None;
            r.note = Some(why);
            r
        };
        let lag = match client.safe_head_lag().await {
            Ok(l) => l,
            Err(e) => return unknown(r, format!("head/safe read failed: {e:#}")),
        };
        r.head = Some(lag.head);
        r.head_timestamp = Some(lag.head_timestamp);
        r.safe = Some(lag.safe);
        r.safe_timestamp = Some(lag.safe_timestamp);
        r.safe_lag_secs = Some(lag.lag_secs());
        if lag.safe > lag.head {
            return unknown(
                r,
                format!("safe block {} above the head {}", lag.safe, lag.head),
            );
        }
        let window = lag.head - lag.safe;
        if window > self.cfg.max_blocks {
            return unknown(
                r,
                format!(
                    "{window} unposted blocks exceed the scan cap of {}: above threshold",
                    self.cfg.max_blocks
                ),
            );
        }
        let mut cache = self.cache.lock().await;
        // Posted blocks no longer count; a changed head is a reorg.
        cache.retain(|n, _| *n > lag.safe);
        if cache
            .get(&lag.head)
            .and_then(|b| b.hash)
            .is_some_and(|h| h != lag.head_hash)
        {
            cache.clear();
        }
        let mut missing: Vec<u64> = (lag.safe + 1..=lag.head)
            .filter(|n| !cache.contains_key(n))
            .collect();
        // The new blocks must extend the cached ones.
        if let Some(&first) = missing.first() {
            let below = first
                .checked_sub(1)
                .and_then(|p| cache.get(&p))
                .and_then(|b| b.hash);
            if let Some(cached) = below {
                match client
                    .provider
                    .get_block_by_number(BlockNumberOrTag::Number(first))
                    .await
                {
                    Ok(Some(b)) if b.header.parent_hash == cached => {}
                    Ok(Some(_)) => {
                        cache.clear();
                        missing = (lag.safe + 1..=lag.head).collect();
                    }
                    Ok(None) => return unknown(r, format!("block {first} not served")),
                    Err(e) => return unknown(r, format!("block {first} read failed: {e:#}")),
                }
            }
        }
        for n in missing {
            let receipts: serde_json::Value = match client
                .provider
                .raw_request("eth_getBlockReceipts".into(), (format!("0x{n:x}"),))
                .await
            {
                Ok(v) => v,
                Err(e) => return unknown(r, format!("eth_getBlockReceipts({n}) failed: {e:#}")),
            };
            r.blocks_fetched += 1;
            let Some(list) = receipts.as_array() else {
                return unknown(r, format!("eth_getBlockReceipts({n}) returned no list"));
            };
            cache.insert(n, block_da(list, n));
        }
        // A head that moved under the scan.
        if cache
            .get(&lag.head)
            .and_then(|b| b.hash)
            .is_some_and(|h| h != lag.head_hash)
        {
            cache.clear();
            return unknown(
                r,
                format!("block {} changed during the scan (a reorg)", lag.head),
            );
        }
        let mut sum: u64 = 0;
        for n in lag.safe + 1..=lag.head {
            match cache.get(&n) {
                Some(b) => {
                    if let Some(why) = &b.unreadable {
                        return unknown(r, why.clone());
                    }
                    sum = sum.saturating_add(b.bytes);
                }
                None => return unknown(r, format!("block {n} missing from the scan")),
            }
        }
        r.chain_bytes = Some(sum);
        r.backlog = Backlog::Known(sum.saturating_add(own));
        r
    }
}

/// Parse a JSON-RPC quantity (`"0x..."`).
fn qty(v: &serde_json::Value) -> Option<u64> {
    let s = v.as_str()?.strip_prefix("0x")?;
    u64::from_str_radix(s, 16).ok()
}

/// One block's DA bytes from its receipts, as `check-l2-lag.sh` counts them: system types skipped
/// whatever their fields; a user type without `l1GasUsed` makes the block unreadable (the endpoint is
/// not an OP Stack Fjord node); another type counts when it carries `l1GasUsed`.
pub fn block_da(receipts: &[serde_json::Value], number: u64) -> BlockDa {
    let mut out = BlockDa {
        hash: None,
        bytes: 0,
        unreadable: None,
    };
    for rc in receipts {
        let hash = rc
            .get("blockHash")
            .and_then(|h| h.as_str())
            .and_then(|h| h.parse::<B256>().ok());
        if out.hash.is_none() {
            out.hash = hash;
        }
        if rc.get("blockNumber").and_then(qty) != Some(number)
            || (hash.is_some() && hash != out.hash)
        {
            out.unreadable = Some(format!("block {number}: a receipt of another block"));
            return out;
        }
        let ty = rc.get("type").map_or(Some(0), qty);
        let Some(ty) = ty else {
            out.unreadable = Some(format!("block {number}: a receipt with a malformed type"));
            return out;
        };
        if SYSTEM_TX_TYPES.contains(&ty) {
            continue;
        }
        match rc.get("l1GasUsed").filter(|v| !v.is_null()) {
            Some(g) => match qty(g) {
                Some(g) => out.bytes = out.bytes.saturating_add(g / 16),
                None => {
                    out.unreadable = Some(format!("block {number}: a malformed l1GasUsed"));
                    return out;
                }
            },
            None if USER_TX_TYPES.contains(&ty) => {
                out.unreadable = Some(format!(
                    "block {number}: a type-{ty:#x} receipt without l1GasUsed (not an OP Stack Fjord \
                     node: the backlog cannot be estimated)"
                ));
                return out;
            }
            None => {} // an unknown type without l1GasUsed: no DA footprint we can count
        }
    }
    out
}

/// Where the fulfil path gets its backlog readings.
#[derive(Clone)]
pub enum BacklogSource {
    /// Read the chain (§13.5).
    Reader(Arc<BacklogReader>),
    /// A fixed reading: an operator override on a node that cannot serve the reading, or a test.
    Fixed(BacklogReading),
}

impl BacklogSource {
    pub async fn read(&self, client: &ChainClient) -> BacklogReading {
        match self {
            BacklogSource::Reader(r) => r.read(client).await,
            BacklogSource::Fixed(r) => r.clone(),
        }
    }
}

// ── the DA nonce rule ─────────────────────────────────────────────────────────

/// The DA nonce rule (§5.5): a LARGE fulfil (above [`STANDARD_FULFIL_DA_BYTES`]) is sent only as
/// this key's highest pending nonce; if it stays unmined while the head advances, or the safe-head
/// lag passes 600 s, it is replaced at its nonce by a minimal self-transfer so later nonces proceed,
/// and re-sent when the throttle clears.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NonceRuleConfig {
    /// Blocks an accepted large fulfil may stay unmined before it is replaced.
    pub unmined_blocks: u64,
    /// Above this safe-head lag, an unmined large fulfil that has missed a block is replaced at once.
    pub safe_lag_secs: u64,
    /// After a replacement, re-send once this many blocks passed even if the throttle cannot be read
    /// (or the lag stays high): ignorance must not hold a fulfil to its deadline.
    pub resend_backoff_blocks: u64,
    /// Replace on the head-advance trigger only if the throttle could be what holds the fulfil (the
    /// reading is unknown, or its live cap is below the fulfil). A fulfil held out by ordinary
    /// blockspace competition keeps its fee ladder: replacing it would restart the ladder at the
    /// bottom, and make holding it out cheap (INTERACTION_GUIDE §6).
    pub require_da_evidence: bool,
}

impl Default for NonceRuleConfig {
    fn default() -> Self {
        Self {
            unmined_blocks: DEFAULT_UNMINED_BLOCKS,
            safe_lag_secs: SAFE_LAG_REPLACE_SECS,
            resend_backoff_blocks: DEFAULT_RESEND_BACKOFF_BLOCKS,
            require_da_evidence: true,
        }
    }
}

/// What the detector saw (see [`ChainClient::observe_pending`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PendingObservation {
    /// The head block number.
    pub head: u64,
    /// This key's MINED transaction count at the head: a nonce below it is consumed.
    pub mined_count: u64,
    /// `ts(latest) - ts(safe)`, if the safe header was read.
    pub safe_lag_secs: Option<u64>,
}

/// Why a large fulfil is replaced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StuckReason {
    /// Unmined while the head advanced this many blocks since its first acceptance.
    HeadAdvanced { blocks: u64 },
    /// Unmined across a block while the safe-head lag is this high.
    SafeLag { secs: u64, blocks: u64 },
}

impl std::fmt::Display for StuckReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StuckReason::HeadAdvanced { blocks } => {
                write!(f, "unmined while the head advanced {blocks} blocks")
            }
            StuckReason::SafeLag { secs, blocks } => write!(
                f,
                "unmined for {blocks} block(s) with the safe-head lag at {secs} s"
            ),
        }
    }
}

/// The detector's verdict on one accepted large fulfil.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StuckVerdict {
    /// Its nonce is consumed (by it, or by a replacement).
    Mined,
    /// Still unmined, not yet replaceable.
    Waiting { blocks_unmined: u64 },
    /// Replace it at its nonce.
    Replace(StuckReason),
}

/// A send gate's answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Gate {
    Send,
    Hold(String),
}

impl NonceRuleConfig {
    /// The verdict on the fulfil at `nonce`, first accepted at head `first_head`, given `obs` and
    /// `filter` — [`Backlog::would_filter`] of a fresh reading (`None`: unknown, which counts as
    /// evidence). The caller may pass anything for `filter` while the head-advance threshold is not
    /// reached: it is read only past it.
    pub fn verdict(
        &self,
        nonce: u64,
        first_head: u64,
        obs: PendingObservation,
        filter: Option<bool>,
    ) -> StuckVerdict {
        if obs.mined_count > nonce {
            return StuckVerdict::Mined;
        }
        let blocks = obs.head.saturating_sub(first_head);
        if let Some(secs) = obs.safe_lag_secs {
            if blocks >= 1 && secs > self.safe_lag_secs {
                return StuckVerdict::Replace(StuckReason::SafeLag { secs, blocks });
            }
        }
        if blocks >= self.unmined_blocks.max(1)
            && (!self.require_da_evidence || filter != Some(false))
        {
            return StuckVerdict::Replace(StuckReason::HeadAdvanced { blocks });
        }
        StuckVerdict::Waiting {
            blocks_unmined: blocks,
        }
    }

    /// Before the FIRST send of a large fulfil: hold only on positive evidence that the throttle
    /// would filter it. An unknown reading never holds a fulfil (the detector bounds what a filtered
    /// one costs; holding on ignorance could hold it to its deadline).
    pub fn presend(&self, estimated: u64, backlog: Backlog) -> Gate {
        match backlog.would_filter(estimated) {
            Some(true) => Gate::Hold(format!(
                "the live DA cap is below this fulfil's {estimated} estimated bytes ({backlog:?})"
            )),
            _ => Gate::Send,
        }
    }

    /// After a replacement at head `replaced_at`: re-send once the throttle provably clears (a known
    /// reading that fits and a safe-head lag at or under the limit); hold while it provably filters;
    /// otherwise re-send after [`Self::resend_backoff_blocks`].
    pub fn resend(
        &self,
        replaced_at: u64,
        head: u64,
        estimated: u64,
        backlog: Backlog,
        safe_lag_secs: Option<u64>,
    ) -> Gate {
        match backlog.would_filter(estimated) {
            Some(true) => {
                return Gate::Hold(format!(
                    "the live DA cap is still below this fulfil's {estimated} estimated bytes \
                     ({backlog:?})"
                ))
            }
            Some(false) if safe_lag_secs.is_some_and(|s| s <= self.safe_lag_secs) => {
                return Gate::Send
            }
            _ => {}
        }
        let waited = head.saturating_sub(replaced_at);
        if waited >= self.resend_backoff_blocks {
            Gate::Send
        } else {
            Gate::Hold(format!(
                "throttle not provably clear ({backlog:?}, safe-head lag {safe_lag_secs:?} s): \
                 {waited}/{} blocks of back-off since the replacement",
                self.resend_backoff_blocks
            ))
        }
    }
}

// ── this key's fulfils ────────────────────────────────────────────────────────

/// One accepted fulfil at a nonce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DaSend {
    pub job_id: B256,
    pub nonce: u64,
    pub estimated_bytes: u64,
    /// The head when the node first accepted a fulfil at this nonce (re-publishes keep it).
    pub first_accepted_head: u64,
}

impl DaSend {
    pub fn is_large(&self) -> bool {
        self.estimated_bytes > STANDARD_FULFIL_DA_BYTES
    }
}

/// A large fulfil replaced by a self-transfer, waiting to be re-sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Replaced {
    pub nonce: u64,
    /// The head the replacement was decided at.
    pub head: u64,
    pub estimated_bytes: u64,
}

/// This key's hashed fulfils as the DA rules track them (held by [`ChainClient`], shared across its
/// clones). Small: one entry per fulfil in flight.
#[derive(Debug, Default)]
pub struct DaSendBook {
    sends: BTreeMap<u64, DaSend>,
    replaced: HashMap<B256, Replaced>,
}

impl DaSendBook {
    /// Record an accepted fulfil at `nonce`, keeping the first acceptance's head across re-publishes.
    pub fn note_accepted(
        &mut self,
        job_id: B256,
        nonce: u64,
        estimated_bytes: u64,
        head: u64,
    ) -> DaSend {
        let e = self.sends.entry(nonce).or_insert(DaSend {
            job_id,
            nonce,
            estimated_bytes,
            first_accepted_head: head,
        });
        if e.job_id != job_id {
            // The nonce now carries another job's fulfil: a fresh acceptance.
            *e = DaSend {
                job_id,
                nonce,
                estimated_bytes,
                first_accepted_head: head,
            };
        }
        e.estimated_bytes = e.estimated_bytes.max(estimated_bytes);
        *e
    }

    /// Whether an accepted fulfil is recorded at `nonce`.
    pub fn get(&self, nonce: u64) -> Option<DaSend> {
        self.sends.get(&nonce).copied()
    }

    pub fn forget(&mut self, nonce: u64) {
        self.sends.remove(&nonce);
    }

    /// Forget every send of `job_id` (settled, or the lock is gone).
    pub fn forget_job(&mut self, job_id: B256) {
        self.sends.retain(|_, s| s.job_id != job_id);
        self.replaced.remove(&job_id);
    }

    /// Drop sends whose nonce is consumed (below the mined count).
    pub fn prune_mined(&mut self, mined_count: u64) {
        self.sends.retain(|n, _| *n >= mined_count);
    }

    /// This key's unmined fulfil estimates, for the backlog reading.
    pub fn unmined_bytes(&self) -> u64 {
        self.sends
            .values()
            .fold(0u64, |acc, s| acc.saturating_add(s.estimated_bytes))
    }

    /// The lowest large fulfil still unmined, if any — a claim gate may hold new claims behind it
    /// (they would queue behind a fulfil the throttle may be filtering).
    pub fn large_pending(&self) -> Option<DaSend> {
        self.sends.values().find(|s| s.is_large()).copied()
    }

    pub fn note_replaced(&mut self, job_id: B256, r: Replaced) {
        self.sends.remove(&r.nonce);
        self.replaced.insert(job_id, r);
    }

    pub fn replaced(&self, job_id: B256) -> Option<Replaced> {
        self.replaced.get(&job_id).copied()
    }

    pub fn clear_replaced(&mut self, job_id: B256) {
        self.replaced.remove(&job_id);
    }
}

// ── the detector ──────────────────────────────────────────────────────────────

/// The head and the safe head, read one after the other on the same endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SafeHeadLag {
    pub head: u64,
    pub head_timestamp: u64,
    pub head_hash: B256,
    pub safe: u64,
    pub safe_timestamp: u64,
}

impl SafeHeadLag {
    /// `ts(latest) - ts(safe)`: the reading `check-l2-lag.sh`, `check-lift-tx.sh` and the reference
    /// daemons share.
    pub fn lag_secs(&self) -> u64 {
        self.head_timestamp.saturating_sub(self.safe_timestamp)
    }
}

impl ChainClient {
    /// The safe-head lag (two header reads). Also records the head's chain time.
    pub async fn safe_head_lag(&self) -> Result<SafeHeadLag> {
        let head = self
            .provider
            .get_block_by_number(BlockNumberOrTag::Latest)
            .await
            .context("latest block")?
            .context("no latest block")?;
        crate::client::note_chain_time(head.header.timestamp);
        let safe = self
            .provider
            .get_block_by_number(BlockNumberOrTag::Safe)
            .await
            .context("safe block")?
            .context("the endpoint serves no safe block")?;
        Ok(SafeHeadLag {
            head: head.header.number,
            head_timestamp: head.header.timestamp,
            head_hash: head.header.hash,
            safe: safe.header.number,
            safe_timestamp: safe.header.timestamp,
        })
    }

    /// The detector's reading for pending-but-unmined transactions: the head, this key's mined count
    /// AT that head, and the safe-head lag. A nonce below `mined_count` is consumed; a nonce at or
    /// above it that was accepted at head `h` has been unmined for `head - h` blocks. Also prunes
    /// consumed nonces from the [`DaSendBook`]. Three reads.
    pub async fn observe_pending(&self) -> Result<PendingObservation> {
        let lag = self.safe_head_lag().await;
        let head = match &lag {
            Ok(l) => l.head,
            Err(_) => self
                .provider
                .get_block_number()
                .await
                .context("block number")?,
        };
        let mined_count = self
            .provider
            .get_transaction_count(self.address)
            .block_id(alloy::eips::BlockId::number(head))
            .await
            .context("mined transaction count")?;
        self.da_book().prune_mined(mined_count);
        Ok(PendingObservation {
            head,
            mined_count,
            safe_lag_secs: lag.ok().map(|l| l.lag_secs()),
        })
    }

    /// Whether the node holds `tx_hash` unmined: known (`eth_getTransactionByHash` answers) and in no
    /// block. `false` for a mined, dropped or replaced transaction.
    pub async fn tx_pending_in_pool(&self, tx_hash: B256) -> Result<bool> {
        let tx = self
            .provider
            .get_transaction_by_hash(tx_hash)
            .await
            .context("eth_getTransactionByHash")?;
        Ok(tx.is_some_and(|t| t.block_number.is_none()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn the_curve_matches_the_runbook() {
        // No cap at or below 3.2 MB.
        assert_eq!(live_tx_cap(0), None);
        assert_eq!(live_tx_cap(3_200_000), None);
        // 20,000 from the first throttled update.
        assert_eq!(live_tx_cap(3_200_001), Some(19_999));
        assert_eq!(live_tx_cap(3_210_000), Some(19_999));
        // Quadratic: a quarter of the drop at the midpoint, not half.
        assert_eq!(live_tx_cap(8_000_000), Some(20_000 - 19_850 / 4 - 1));
        // 150 from 12.8 MB on.
        assert_eq!(live_tx_cap(12_800_000), Some(150));
        assert_eq!(live_tx_cap(u64::MAX), Some(150));
        // The runbook's equilibrium points: 6.78 MB -> 17,240, 10.49 MB -> 8,540 (its rounding).
        let at = |b: u64| live_tx_cap(b).unwrap() as i64;
        assert!((at(6_780_000) - 17_240).abs() <= 2, "{}", at(6_780_000));
        assert!((at(10_490_000) - 8_540).abs() <= 25, "{}", at(10_490_000));
        // Non-increasing everywhere.
        let mut last = u64::MAX;
        for b in (3_200_001..13_000_000).step_by(37_013) {
            let c = live_tx_cap(b).unwrap();
            assert!(c <= last);
            last = c;
        }
        // The same figures check-l2-lag.sh prints (float arithmetic, int()).
        for b in [3_300_000u64, 5_000_000, 9_999_999, 12_000_000] {
            let lin = ((b - 3_200_000) as f64 / 9_600_000.0).min(1.0);
            let want = (20_000.0 - lin * lin * 19_850.0) as u64;
            let got = live_tx_cap(b).unwrap();
            assert!(got.abs_diff(want) <= 1, "{b}: {got} vs {want}");
        }
    }

    #[test]
    fn the_batcher_view_is_the_conservative_one() {
        assert_eq!(batcher_view(1_000_000), 1_159_000);
        // 2.75 MB measured is the 3.2 MB threshold as the batcher may count it.
        assert!(live_tx_cap(batcher_view(2_750_000)).is_none());
        assert!(live_tx_cap(batcher_view(2_770_000)).is_some());
        assert_eq!(batcher_view(u64::MAX), u64::MAX / 1_000);
    }

    #[test]
    fn the_cap_policy() {
        let p = DaCapPolicy::default();
        assert_eq!(p.cap_bytes(), 2_048);
        // Under the hold level: the operator cap only.
        assert_eq!(
            p.fulfil_fits(2_048, Backlog::Known(0)),
            Decision::Fits { cap: 2_048 }
        );
        assert_eq!(
            p.fulfil_fits(2_049, Backlog::Known(0)),
            Decision::Skip(SkipReason::OverOperatorCap {
                estimated: 2_049,
                cap: 2_048
            })
        );
        assert!(p.fulfil_fits(2_048, Backlog::Known(2_500_000)).fits());
        // Above it but below the throttle at the batcher's view: still the operator cap.
        assert_eq!(
            p.fulfil_fits(2_000, Backlog::Known(2_600_000)),
            Decision::Fits { cap: 2_048 }
        );
        // Deep in the throttle: the live cap.
        let b = 10_865_000; // batcher view 12.59 MB -> cap 998
        let live = live_tx_cap(batcher_view(b)).unwrap();
        assert!(live < 2_048 && live > 600, "{live}");
        assert_eq!(
            p.fulfil_fits(600, Backlog::Known(b)),
            Decision::Fits {
                cap: 2_048.min(live)
            }
        );
        let big = DaCapPolicy::new(8_500).unwrap();
        assert_eq!(
            big.fulfil_fits(live + 1, Backlog::Known(b)),
            Decision::Skip(SkipReason::OverLiveCap {
                estimated: live + 1,
                live_cap: live,
                backlog: b
            })
        );
        // Unknown or partial: above threshold at the worst case.
        for bl in [Backlog::Unknown, Backlog::AtLeast(0)] {
            assert_eq!(
                p.fulfil_fits(455, bl),
                Decision::Skip(SkipReason::BacklogUnknown {
                    estimated: 455,
                    worst_case_cap: 150
                })
            );
            assert!(p.fulfil_fits(150, bl).fits());
        }
        // The skip mode.
        let skip = DaCapPolicy {
            above_hold: AboveHold::Skip,
            ..DaCapPolicy::default()
        };
        assert_eq!(
            skip.fulfil_fits(455, Backlog::Known(2_600_000)),
            Decision::Skip(SkipReason::AboveHold { backlog: 2_600_000 })
        );
        assert!(skip.fulfil_fits(455, Backlog::Known(2_400_000)).fits());
        // Configuration bounds.
        assert!(DaCapPolicy::new(8_501).is_err());
        assert!(DaCapPolicy::new(0).is_err());
        assert_eq!(DaCapPolicy::new(8_500).unwrap().cap_bytes(), 8_500);
    }

    #[test]
    fn would_filter_only_on_proof() {
        assert_eq!(Backlog::Known(0).would_filter(50_000), Some(false));
        assert_eq!(Backlog::Known(12_000_000).would_filter(600), Some(true));
        assert_eq!(Backlog::Known(12_000_000).would_filter(150), Some(false));
        // A lower bound proves a filter, never its absence.
        assert_eq!(Backlog::AtLeast(12_000_000).would_filter(600), Some(true));
        assert_eq!(Backlog::AtLeast(0).would_filter(600), None);
        assert_eq!(Backlog::Unknown.would_filter(600), None);
    }

    fn obs(head: u64, mined: u64, lag: Option<u64>) -> PendingObservation {
        PendingObservation {
            head,
            mined_count: mined,
            safe_lag_secs: lag,
        }
    }

    #[test]
    fn the_stuck_verdict() {
        let c = NonceRuleConfig::default();
        // Mined (or replaced and mined): nothing to do.
        assert_eq!(
            c.verdict(7, 100, obs(200, 8, Some(9_999)), None),
            StuckVerdict::Mined
        );
        // Waiting under the block threshold.
        assert_eq!(
            c.verdict(7, 100, obs(109, 7, Some(30)), None),
            StuckVerdict::Waiting { blocks_unmined: 9 }
        );
        // The head advanced 10 blocks with the throttle possibly the cause.
        assert_eq!(
            c.verdict(7, 100, obs(110, 7, Some(30)), None),
            StuckVerdict::Replace(StuckReason::HeadAdvanced { blocks: 10 })
        );
        assert_eq!(
            c.verdict(7, 100, obs(110, 7, Some(30)), Some(true)),
            StuckVerdict::Replace(StuckReason::HeadAdvanced { blocks: 10 })
        );
        // ...but a known reading that cannot filter it: blockspace competition, keep the ladder.
        assert_eq!(
            c.verdict(7, 100, obs(140, 7, Some(30)), Some(false)),
            StuckVerdict::Waiting { blocks_unmined: 40 }
        );
        let literal = NonceRuleConfig {
            require_da_evidence: false,
            ..c
        };
        assert!(matches!(
            literal.verdict(7, 100, obs(110, 7, Some(30)), Some(false)),
            StuckVerdict::Replace(_)
        ));
        // The safe-head lag: at once, once the fulfil has missed a block.
        assert_eq!(
            c.verdict(7, 100, obs(100, 7, Some(601)), Some(false)),
            StuckVerdict::Waiting { blocks_unmined: 0 }
        );
        assert_eq!(
            c.verdict(7, 100, obs(101, 7, Some(601)), Some(false)),
            StuckVerdict::Replace(StuckReason::SafeLag {
                secs: 601,
                blocks: 1
            })
        );
        assert_eq!(
            c.verdict(7, 100, obs(101, 7, Some(600)), Some(false)),
            StuckVerdict::Waiting { blocks_unmined: 1 }
        );
        // A head read from a replica behind the acceptance never underflows.
        assert_eq!(
            c.verdict(7, 100, obs(90, 7, None), None),
            StuckVerdict::Waiting { blocks_unmined: 0 }
        );
    }

    #[test]
    fn the_send_gates() {
        let c = NonceRuleConfig::default();
        // First send: hold only on proof.
        assert_eq!(c.presend(1_200, Backlog::Unknown), Gate::Send);
        assert_eq!(c.presend(1_200, Backlog::Known(0)), Gate::Send);
        assert!(matches!(
            c.presend(1_200, Backlog::Known(12_000_000)),
            Gate::Hold(_)
        ));
        assert!(matches!(
            c.presend(1_200, Backlog::AtLeast(12_000_000)),
            Gate::Hold(_)
        ));
        // Re-send: at once when provably clear...
        assert_eq!(
            c.resend(100, 101, 1_200, Backlog::Known(0), Some(30)),
            Gate::Send
        );
        // ...never while provably filtered, however long...
        assert!(matches!(
            c.resend(100, 10_000, 1_200, Backlog::Known(12_000_000), Some(30)),
            Gate::Hold(_)
        ));
        // ...and after the back-off when unknown or the lag is high.
        assert!(matches!(
            c.resend(100, 149, 1_200, Backlog::Unknown, Some(30)),
            Gate::Hold(_)
        ));
        assert_eq!(
            c.resend(100, 150, 1_200, Backlog::Unknown, Some(30)),
            Gate::Send
        );
        assert!(matches!(
            c.resend(100, 120, 1_200, Backlog::Known(0), Some(900)),
            Gate::Hold(_)
        ));
        assert!(matches!(
            c.resend(100, 120, 1_200, Backlog::Known(0), None),
            Gate::Hold(_)
        ));
        assert_eq!(
            c.resend(100, 150, 1_200, Backlog::Known(0), Some(900)),
            Gate::Send
        );
    }

    #[test]
    fn the_send_book() {
        let mut b = DaSendBook::default();
        let j1 = B256::repeat_byte(1);
        let j2 = B256::repeat_byte(2);
        let s = b.note_accepted(j1, 7, 1_200, 100);
        assert!(s.is_large());
        // A re-publish keeps the first acceptance.
        assert_eq!(b.note_accepted(j1, 7, 1_190, 105).first_accepted_head, 100);
        assert_eq!(b.get(7).unwrap().estimated_bytes, 1_200);
        b.note_accepted(j2, 8, 500, 106);
        assert_eq!(b.unmined_bytes(), 1_700);
        assert_eq!(b.large_pending().map(|s| s.nonce), Some(7));
        // Another job at the same nonce is a fresh acceptance.
        assert_eq!(b.note_accepted(j2, 7, 300, 110).first_accepted_head, 110);
        assert_eq!(b.large_pending(), None);
        b.note_accepted(j1, 9, 1_000, 111);
        b.prune_mined(8);
        assert_eq!(b.get(7), None);
        assert!(b.get(8).is_some() && b.get(9).is_some());
        b.note_replaced(
            j1,
            Replaced {
                nonce: 9,
                head: 120,
                estimated_bytes: 1_000,
            },
        );
        assert_eq!(b.get(9), None);
        assert_eq!(b.replaced(j1).map(|r| r.head), Some(120));
        b.forget_job(j1);
        assert_eq!(b.replaced(j1), None);
        b.forget_job(j2);
        assert_eq!(b.unmined_bytes(), 0);
    }

    #[test]
    fn block_da_counts_user_receipts_like_check_l2_lag() {
        let h = format!("{:#x}", B256::repeat_byte(0xab));
        let rc = |ty: &str, l1: Option<u64>| {
            let mut v = json!({"type": ty, "blockNumber": "0x10", "blockHash": h});
            if let Some(g) = l1 {
                v["l1GasUsed"] = json!(format!("0x{g:x}"));
            }
            v
        };
        // Deposits, PoP payouts and BTC-attributes deposits are skipped; users counted /16.
        let b = block_da(
            &[
                rc("0x7e", None),
                rc("0x7c", None),
                rc("0x7d", Some(9_999)),
                rc("0x2", Some(1_600)),
                rc("0x0", Some(3_215)),
            ],
            16,
        );
        assert_eq!(b.unreadable, None);
        assert_eq!(b.bytes, 100 + 200);
        assert_eq!(b.hash, Some(B256::repeat_byte(0xab)));
        // A user receipt without l1GasUsed: not an OP Stack Fjord node.
        let b = block_da(&[rc("0x7e", None), rc("0x2", None)], 16);
        assert!(b.unreadable.unwrap().contains("not an OP Stack"));
        // An unknown type counts when it carries l1GasUsed, and is ignored otherwise.
        assert_eq!(block_da(&[rc("0x63", Some(320))], 16).bytes, 20);
        assert_eq!(block_da(&[rc("0x63", None)], 16).bytes, 0);
        // A receipt of another block.
        assert!(block_da(&[rc("0x2", Some(1_600))], 17).unreadable.is_some());
        // An empty block.
        assert_eq!(
            block_da(&[], 16),
            BlockDa {
                hash: None,
                bytes: 0,
                unreadable: None
            }
        );
    }

    #[test]
    fn the_unsigned_tx_is_the_signing_payload() {
        let to = Address::repeat_byte(0x11);
        let tx = unsigned_eip1559_tx(743111, 5, 21_000, 2, 1, to, Bytes::from_static(&[0xaa]));
        assert_eq!(tx[0], 0x02, "EIP-2718 type byte");
        // It is what a signer hashes.
        let t = TxEip1559 {
            chain_id: 743111,
            nonce: 5,
            gas_limit: 21_000,
            max_fee_per_gas: 2,
            max_priority_fee_per_gas: 1,
            to: TxKind::Call(to),
            value: U256::ZERO,
            access_list: Default::default(),
            input: Bytes::from_static(&[0xaa]),
        };
        assert_eq!(alloy::primitives::keccak256(&tx), t.signature_hash());
        // The conservative fields are at least as long as any real ones.
        let cd = Bytes::from(vec![0x55; 300]);
        let real = unsigned_eip1559_tx(
            743111,
            70_000,
            12_000_000,
            4_000_000_000_000,
            4_000_000_000,
            to,
            cd.clone(),
        );
        assert!(conservative_fulfil_tx(743111, to, cd).len() >= real.len());
    }

    #[test]
    fn the_upper_bound_covers_the_oracles_figures() {
        // `cast call` on the 743111 fork: getL1GasUsed of 200 and 2,000 random bytes, and of empty
        // input (the 100-byte floor).
        assert!(da_bytes_upper_bound(200) >= 2_999 / 16);
        assert!(da_bytes_upper_bound(2_000) >= 27_839 / 16);
        assert_eq!(da_bytes_upper_bound(0), 100);
        // ...and it is not wildly loose: within 2% + 20 bytes of the 2,000-byte figure.
        assert!(da_bytes_upper_bound(2_000) <= 27_839 / 16 * 102 / 100 + 20);
    }

    #[test]
    fn placeholders_are_incompressible_and_sized() {
        let s = SealSpec::risc0_groth16().bytes();
        assert_eq!(s.len(), 260);
        // No long runs or repeats a compressor could use: every 8-byte window distinct.
        let mut seen = std::collections::HashSet::new();
        assert!(s.windows(8).all(|w| seen.insert(w.to_vec())));
        assert_eq!(
            SealSpec::Exact(Bytes::from_static(b"x")).bytes(),
            Bytes::from_static(b"x")
        );
        assert_eq!(incompressible(0, b"s").len(), 0);
        assert_eq!(incompressible(33, b"s").len(), 33);
    }
}
