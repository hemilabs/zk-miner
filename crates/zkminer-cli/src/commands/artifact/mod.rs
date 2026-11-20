//! `zkminer artifact publish <file> --kind builder|elf --rpc-url <url> --chain-id <id>`
//! (docs/witness-construction-jobs.md §13.5): stores an artifact on the HemiProve chain as contract
//! code, in the `hemi-code` format of §13.2, under every MUST of §13.5:
//!
//! - **Input check:** `--kind` must match the bytes ([`plan::check_input`]) before anything is sent.
//! - **Key** ([`keys`]): an encrypted keystore, its password from the terminal or `--password-fd`;
//!   never the miner's key file, never the environment or argv; refused when it is the configured
//!   prover, staked as a prover, authorized as a prover's operator (under the prover's current
//!   `proverAuthNonce`), or has pending transactions it did not send (all read from the chain
//!   before anything is sent).
//! - **RPC:** `--rpc-url` (or `--rpc-url-file`, or `ZKMINER_PUBLISH_RPC_URL`: argv is visible to
//!   every local user, and the URL may carry a provider key) required, refused when it is `[chain]
//!   rpc_url` while a miner holds its instance lock; every request through the network guard
//!   ([`rpc`]); `https://` outside developer mode; a limiter of its own; no configuration needed (a
//!   configuration's `[dev]` section is what makes a local node reachable).
//! - **The RPC is trusted** for the pacing readings (heads, safe head, backlog, pause state) and the
//!   key checks (stake, operator logs, pending nonces): a lying one could open the gate early. So
//!   the local clock paces sends too ([`send_floor`]: at least the chain's block time between two
//!   sends whatever the RPC reports), and `--verify-rpc-url` names a second provider that must show
//!   each deployment in the same block, with the same code, before the next chunk is signed, and
//!   must read the artifact back too.
//! - **Cost preview** before sending ([`plan::CostPreview`]), confirmed on the terminal or by `--yes`.
//! - **Pacing:** one chunk in flight, at most one send per block and per [`send_floor`] of wall
//!   clock, and only while the DA backlog plus this publisher's unmined estimates is under 250 KB,
//!   the safe-head lag at most 300 s, the router not paused and the head at most 60 s old
//!   ([`plan::pace`]).
//! - **Chunk size and fees:** each chunk sized so `getL1GasUsed / 16` of its transaction is at most
//!   19,500, against a transaction whose every variable field is at its longest; both fee fields
//!   explicit, the tip the inclusion floor measured from recent blocks; a chunk unmined for
//!   [`STUCK_BLOCKS`] blocks while the gate is open is replaced at its nonce with bumped fees (at most
//!   [`MAX_REPLACEMENTS`] times, the tip and the max fee capped), and only an above-threshold backlog
//!   means waiting instead. Past the count or the caps it waits, while the pool holds the
//!   transaction: one the pool dropped is sent again as it was (at most [`MAX_RESENDS`] times), and
//!   the publish stops with an error when that is refused.
//! - **Deploy and verify:** chunks first, the manifest last, addresses from receipts; every
//!   receipt's status checked, a failed creation (out of gas) redeployed at a new nonce; then the
//!   wait until every deploying block is at or below `safe` with its hash unchanged, the §13.4 fetch
//!   of the locator at the safe head (pinned by hash, with the miner's own manifest, chunk and
//!   assembly checks), and only then the result.
//! - **Resume:** with `--progress FILE` each mined deployment is recorded, and so is each
//!   transaction before it is sent (synced to disk); a later run of the same artifact to the same
//!   chain reuses the recorded chunks whose code is on chain, and the transaction sent before the
//!   stop when it created the next deployment, sending only the rest (one still pending stops it
//!   until it settles). Without it, a run that stopped part-way is simply run again: it sends every
//!   chunk anew (paced the same, paid again), and the chunks of the first run stay on chain unused.

pub mod keys;
pub mod plan;
mod progress;
pub mod rpc;

use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use alloy::consensus::{SignableTransaction, TxEip1559, TxEnvelope};
use alloy::eips::eip2718::Encodable2718;
use alloy::network::TxSignerSync;
use alloy::primitives::{keccak256, Address, B256, U256};
use alloy::signers::local::PrivateKeySigner;
use alloy::sol_types::{SolCall, SolEvent};
use anyhow::{bail, Context, Result};
use serde::Serialize;
use serde_json::{json, Value};
use zkminer_config::ZkMinerConfig;
use zkminer_netguard::{NetMode, NetPolicy};
use zkminer_witness::locator::HemiCodeLocator;
use zkminer_witness::manifest::{chunk_body, manifest_runtime_code, parse_manifest, Assembler, MAX_CODE_BYTES};

use plan::{Kind, PaceInputs};
use progress::Progress;
use rpc::{data, qty, NodeError, Rpc};

alloy::sol! {
    /// What publishing reads of the HemiProve contracts and the OP Stack predeploy.
    interface IPublishReads {
        function paused() external view returns (bool);
        function staking() external view returns (address);
        function operatorAuthorizations(address prover, address operator) external view returns (uint256 permissionBitmap, uint256 authorizationNonce, uint128 maxLockedCollateral);
        function proverAuthNonce(address prover) external view returns (uint256);
        event OperatorAuthorized(address indexed prover, address indexed operator, uint256 permissions, uint128 maxLockedCollateral);
        function getProverStake(address prover) external view returns (uint128 totalStaked, uint128 lockedCollateral, uint128 unstakeAmount, uint40 unstakeRequestTime, uint40 depositBlock);
        function getL1GasUsed(bytes memory _data) external view returns (uint256);
        function getL1Fee(bytes memory _data) external view returns (uint256);
    }
}

/// Blocks a sent chunk may stay unmined, with the gate open, before it is replaced at its nonce.
pub const STUCK_BLOCKS: u64 = 3;
/// Replacements raise the tip to at most this multiple of the floor (and [`MIN_TIP_CAP_WEI`]): a
/// chunk that stays unmined for another reason (a node that dropped it, a stall) must never turn
/// into an open-ended fee escalation.
const TIP_CAP_MULTIPLE: u128 = 64;
const MIN_TIP_CAP_WEI: u128 = 1_000_000_000;
/// No send carries a max fee above this multiple of the base fee when publishing began, plus the
/// tip cap: past it (a base fee that rose that far) the publisher waits.
const BASE_FEE_CAP_MULTIPLE: u128 = 8;
/// Replacements sent (or refused) at one nonce, at most; then the publisher only waits.
pub const MAX_REPLACEMENTS: u32 = 16;
/// How many times a transaction the pool dropped, past the replacements, is sent again as it was.
pub const MAX_RESENDS: u32 = 3;
/// Hemi's block time (mainnet and testnet): the least time between two sends there.
const HEMI_BLOCK_TIME: Duration = Duration::from_secs(12);
/// The least time between two sends outside developer mode on any chain.
const MIN_SEND_FLOOR: Duration = Duration::from_secs(1);
/// Blocks a chain's block time is measured over.
const BLOCK_TIME_SAMPLE: u64 = 64;
/// How long `--verify-rpc-url` may take to show a deployment the publisher's RPC reported.
const VERIFY_TIMEOUT: Duration = Duration::from_secs(600);
/// `artifact publish` reads its RPC URL from this variable when no flag names one.
pub const RPC_URL_ENV: &str = "ZKMINER_PUBLISH_RPC_URL";
/// A creation that failed (out of gas) is redeployed at a new nonce at most this many times.
const MAX_REDEPLOYS: u32 = 3;
/// The gas limit's margin over `eth_estimateGas`.
const GAS_MARGIN_PERCENT: u64 = 10;
/// Recent blocks the tip floor is measured over.
const TIP_BLOCKS: u64 = 20;
/// The most unposted blocks the backlog scan reads; more reads as unknown (above threshold).
const MAX_BACKLOG_BLOCKS: u64 = 150;
/// `eth_getLogs` range per request for the operator check.
const LOG_RANGE: u64 = 10_000;
/// Chunk reads per JSON-RPC batch in the verification fetch (§13.4).
const FETCH_BATCH: usize = 256;
/// How often the publisher polls while it waits for a receipt, the gate or the safe head.
const POLL: Duration = Duration::from_secs(1);

/// `zkminer artifact publish`'s options.
#[derive(Debug)]
pub struct PublishOptions {
    pub file: PathBuf,
    pub kind: Kind,
    pub rpc_url: String,
    /// A second RPC of the same chain (another provider) every deployment is checked against.
    pub verify_rpc_url: Option<String>,
    pub chain_id: u64,
    pub keystore: PathBuf,
    /// `--password-fd`, taken by [`keys::take_password_fd`] at the start of `main`; else the
    /// terminal.
    pub password_fd: Option<OwnedFd>,
    /// The HemiProve router (default: the known deployment's on `chain_id`).
    pub router: Option<Address>,
    /// The first block of the operator check's log scan (default: the known deployment's).
    pub from_block: Option<u64>,
    /// Override the measured inclusion floor.
    pub tip_wei: Option<u128>,
    pub max_requests_per_sec: u32,
    /// The least wall-clock time between two sends ([`send_floor`]).
    pub block_time_ms: Option<u64>,
    /// Where mined deployments are recorded, and reused from ([`progress`]).
    pub progress: Option<PathBuf>,
    pub yes: bool,
    pub json: bool,
}

/// An RPC URL from argv, else from `file` (its first line), else from the environment variable
/// `env`; `None` when none names one. A URL may carry a provider key, which argv shows to every
/// local user (`/proc/<pid>/cmdline`); a file or this process's environment does not.
pub fn rpc_url_from(arg: Option<String>, file: Option<&Path>, env: Option<&str>) -> Result<Option<String>> {
    if let Some(url) = arg {
        return Ok(Some(url));
    }
    if let Some(f) = file {
        let mut text = String::new();
        std::io::Read::read_to_string(
            &mut std::io::Read::take(std::fs::File::open(f).with_context(|| format!("reading {}", f.display()))?, 64 << 10),
            &mut text,
        )
        .with_context(|| format!("reading {}", f.display()))?;
        let line = text.lines().next().unwrap_or("").trim();
        if line.is_empty() {
            bail!("{} holds no URL on its first line", f.display());
        }
        return Ok(Some(line.to_string()));
    }
    if let Some(name) = env {
        if let Some(v) = std::env::var_os(name) {
            let v = v.into_string().map_err(|_| anyhow::anyhow!("{name} is not UTF-8"))?;
            if !v.trim().is_empty() {
                return Ok(Some(v.trim().to_string()));
            }
        }
    }
    Ok(None)
}

/// One mined deployment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Deployed {
    pub address: Address,
    pub tx_hash: B256,
    pub nonce: u64,
    pub block_number: u64,
    pub block_hash: B256,
    pub body_bytes: usize,
    /// `gasUsed × effectiveGasPrice` plus the receipt's `l1Fee` when it carries one.
    pub cost_wei: String,
    /// Replacements sent at its nonce before it mined.
    pub replacements: u32,
    /// Failed creations (out of gas) before this one.
    pub redeploys: u32,
    /// Deployed by an earlier run (`--progress`) and found on chain with this code: not sent again.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub reused: bool,
}

/// The published artifact, printed only after the §13.4 fetch read it back.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Published {
    pub locator: String,
    pub sha256: B256,
    pub keccak256: B256,
    pub length: usize,
    pub chunks: Vec<Deployed>,
    pub manifest: Deployed,
    pub total_cost_wei: String,
    /// For `--kind builder`: the envelope's `builderId`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub builder_id: Option<B256>,
    /// For `--kind elf`: `addStorageURI(programId, 3, locator, keccak256(elf))` (§13.6).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub add_storage_uri: Option<String>,
    pub warnings: Vec<String>,
}

/// Faults in the send path, for tests only (an out-of-gas creation, a send dropped from the pool):
/// outside tests the type is empty and no code reads it.
#[cfg(not(test))]
#[derive(Debug, Default, Clone)]
pub struct Faults;

/// Faults in the send path, for tests only (an out-of-gas creation, a send dropped from the pool).
#[cfg(test)]
#[derive(Debug, Default, Clone)]
pub struct Faults {
    /// The first creation is sent with this gas limit.
    pub first_gas_limit: Option<u64>,
    /// The first send is removed from the node's pool (`anvil_dropTransaction`) right after it is
    /// accepted, so it never mines.
    pub drop_first_send: bool,
    /// The run stops (an error) once this many deployments mined, before the next send: a run that
    /// died part-way.
    pub stop_after: Option<usize>,
    /// How long `--verify-rpc-url` may take (default [`VERIFY_TIMEOUT`]).
    pub verify_timeout: Option<Duration>,
    /// The run's tip and fee caps are its first send's: no replacement can raise them.
    pub no_fee_room: bool,
    /// This many sends again of a dropped transaction are themselves dropped from the pool.
    pub drop_resends: u32,
    /// The run stops (an error) right after its first send, before the receipt: a run killed with a
    /// transaction in flight.
    pub stop_after_send: bool,
}

/// A block header as the publisher reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Header {
    number: u64,
    hash: B256,
    timestamp: u64,
    base_fee: u128,
}

/// The chain as the publisher reads and writes it.
struct Chain {
    rpc: Rpc,
    chain_id: u64,
}

fn addr_param(a: Address) -> Value {
    json!(format!("{a:#x}"))
}

fn hexs(b: &[u8]) -> Value {
    json!(format!("0x{}", alloy::hex::encode(b)))
}

impl Chain {
    async fn header(&self, tag: Value) -> Result<Option<Header>> {
        let v = self.rpc.call("eth_getBlockByNumber", json!([tag, false])).await?;
        if v.is_null() {
            return Ok(None);
        }
        Ok(Some(Header {
            number: qty(&v["number"])? as u64,
            hash: v["hash"].as_str().context("a block without a hash")?.parse()?,
            timestamp: qty(&v["timestamp"])? as u64,
            base_fee: v.get("baseFeePerGas").filter(|b| !b.is_null()).map(qty).transpose()?.unwrap_or(0),
        }))
    }

    async fn head(&self) -> Result<Header> {
        self.header(json!("latest")).await?.context("the node has no latest block")
    }

    /// The safe head (`finalized` on a node without `safe`).
    async fn safe(&self) -> Result<Header> {
        match self.header(json!("safe")).await {
            Ok(Some(h)) => Ok(h),
            _ => self.header(json!("finalized")).await?.context("the node serves neither a safe nor a finalized head"),
        }
    }

    async fn block_at(&self, n: u64) -> Result<Option<Header>> {
        self.header(json!(format!("0x{n:x}"))).await
    }

    /// The mean block time over the last [`BLOCK_TIME_SAMPLE`] blocks, from their timestamps (as
    /// this RPC reports them); `None` without enough blocks.
    async fn measured_block_time(&self, head: &Header) -> Result<Option<Duration>> {
        let from = head.number.saturating_sub(BLOCK_TIME_SAMPLE);
        if from == head.number {
            return Ok(None);
        }
        let Some(first) = self.block_at(from).await? else { return Ok(None) };
        let span_ms = head.timestamp.saturating_sub(first.timestamp).saturating_mul(1000);
        Ok(Some(Duration::from_millis(span_ms / (head.number - from))))
    }

    async fn nonce(&self, a: Address, tag: &str) -> Result<u64> {
        Ok(qty(&self.rpc.call("eth_getTransactionCount", json!([addr_param(a), tag])).await?)? as u64)
    }

    async fn balance(&self, a: Address) -> Result<U256> {
        let v = self.rpc.call("eth_getBalance", json!([addr_param(a), "latest"])).await?;
        Ok(U256::from_str_radix(v.as_str().unwrap_or("0x0").trim_start_matches("0x"), 16)?)
    }

    async fn eth_call(&self, to: Address, input: Vec<u8>) -> Result<Vec<u8>> {
        data(&self.rpc.call("eth_call", json!([{"to": addr_param(to), "data": hexs(&input)}, "latest"])).await?)
    }

    async fn code(&self, a: Address, at: Value) -> Result<Vec<u8>> {
        data(&self.rpc.call("eth_getCode", json!([addr_param(a), at])).await?)
    }

    async fn router_paused(&self, router: Address) -> Result<bool> {
        let out = self.eth_call(router, IPublishReads::pausedCall {}.abi_encode()).await?;
        Ok(IPublishReads::pausedCall::abi_decode_returns(&out)?)
    }

    /// `GasPriceOracle.getL1GasUsed(tx) / 16`, `None` when the chain has no oracle (a local node).
    async fn l1_gas_bytes(&self, unsigned_tx: &[u8]) -> Option<u64> {
        let input = IPublishReads::getL1GasUsedCall { _data: unsigned_tx.to_vec().into() }.abi_encode();
        let out = self.eth_call(zkminer_contracts::bindings::GAS_PRICE_ORACLE, input).await.ok()?;
        let used = IPublishReads::getL1GasUsedCall::abi_decode_returns(&out).ok()?;
        Some((used / U256::from(16u8)).saturating_to::<u64>())
    }

    /// `GasPriceOracle.getL1Fee(tx)`, `None` without the oracle.
    async fn l1_fee(&self, unsigned_tx: &[u8]) -> Option<U256> {
        let input = IPublishReads::getL1FeeCall { _data: unsigned_tx.to_vec().into() }.abi_encode();
        let out = self.eth_call(zkminer_contracts::bindings::GAS_PRICE_ORACLE, input).await.ok()?;
        IPublishReads::getL1FeeCall::abi_decode_returns(&out).ok()
    }

    /// A creation's DA estimate: the oracle's, else the RPC-free upper bound.
    async fn da_bytes(&self, unsigned_tx: &[u8]) -> (u64, bool) {
        match self.l1_gas_bytes(unsigned_tx).await {
            Some(b) => (b, true),
            None => (zkminer_chain::da::da_bytes_upper_bound(unsigned_tx.len()), false),
        }
    }

    async fn estimate_gas(&self, from: Address, input: &[u8]) -> Result<u64> {
        Ok(qty(&self.rpc.call("eth_estimateGas", json!([{"from": addr_param(from), "data": hexs(input)}])).await?)? as u64)
    }

    async fn receipt(&self, tx: B256) -> Result<Option<Value>> {
        let v = self.rpc.call("eth_getTransactionReceipt", json!([format!("{tx:#x}")])).await?;
        Ok((!v.is_null()).then_some(v))
    }

    /// The lowest effective tip of the user transactions in the last [`TIP_BLOCKS`] blocks.
    async fn measured_tip_floor(&self, head: &Header) -> Result<Option<u128>> {
        let mut tips = Vec::new();
        for n in head.number.saturating_sub(TIP_BLOCKS - 1)..=head.number {
            let b = self.rpc.call("eth_getBlockByNumber", json!([format!("0x{n:x}"), true])).await?;
            let base = b.get("baseFeePerGas").filter(|v| !v.is_null()).map(qty).transpose()?.unwrap_or(0);
            for tx in b.get("transactions").and_then(Value::as_array).into_iter().flatten() {
                let ty = tx.get("type").map(qty).transpose()?.unwrap_or(0);
                if ty >= 0x7c {
                    continue; // deposits and Hemi's system transactions carry no tip
                }
                let opt = |k: &str| tx.get(k).filter(|v| !v.is_null()).map(qty).transpose();
                if let Some(t) = plan::effective_tip(base, opt("maxFeePerGas")?, opt("maxPriorityFeePerGas")?, opt("gasPrice")?) {
                    tips.push(t);
                }
            }
        }
        Ok(plan::tip_floor(tips))
    }

    /// The sum of `l1GasUsed / 16` over user transactions in (safe, head], as the contracts'
    /// `check-l2-lag.sh` measures it (`zkminer_chain::da::block_da` per block); `None` when it
    /// cannot be read (not an OP Stack node, too many unposted blocks, a block changed).
    async fn backlog(&self, head: &Header, safe: &Header) -> Result<Option<u64>> {
        if safe.number > head.number || head.number - safe.number > MAX_BACKLOG_BLOCKS {
            return Ok(None);
        }
        let mut sum = 0u64;
        for n in safe.number + 1..=head.number {
            let receipts = self.rpc.call("eth_getBlockReceipts", json!([format!("0x{n:x}")])).await?;
            let Some(list) = receipts.as_array() else { return Ok(None) };
            let b = zkminer_chain::da::block_da(list, n);
            if b.unreadable.is_some() {
                return Ok(None);
            }
            sum = sum.saturating_add(b.bytes);
        }
        Ok(Some(sum))
    }
}

/// How the backlog is read: from the chain, or `[dev] da_backlog_bytes` on a local test network
/// (whose receipts carry no `l1GasUsed`), as the miner reads it.
#[derive(Debug, Clone, Copy)]
enum BacklogSource {
    Chain,
    Fixed(u64),
}

/// The least wall-clock time between two sends: `configured` (`--block-time-ms`) if given, else
/// the chain's `known` block time, else the `measured` one. In developer mode that is all (a local
/// node may mine on demand, so it may be zero). Elsewhere it is never below [`MIN_SEND_FLOOR`] nor
/// a known chain's block time, whatever the RPC reports: a lying or intercepted RPC that reports a
/// new head every few milliseconds still gets at most one chunk per block time, as an honest
/// chain would.
pub fn send_floor(configured: Option<Duration>, known: Option<Duration>, measured: Option<Duration>, dev: bool) -> Result<Duration> {
    if dev {
        return Ok(configured.or(known).or(measured).unwrap_or(Duration::ZERO));
    }
    let least = known.unwrap_or(MIN_SEND_FLOOR).max(MIN_SEND_FLOOR);
    match configured {
        Some(c) if c < least => bail!(
            "--block-time-ms {} is below {} ms, the least time between sends here (the chain's block time, and at least 1 s \
             outside developer mode)",
            c.as_millis(),
            least.as_millis()
        ),
        Some(c) => Ok(c),
        None => Ok(measured.unwrap_or(least).max(least)),
    }
}

/// A chain's block time when zkminer knows it (Hemi mainnet and testnet), not from any RPC.
fn known_block_time(chain_id: u64) -> Option<Duration> {
    zkminer_config::DEPLOYED_CHAIN_IDS.contains(&chain_id).then_some(HEMI_BLOCK_TIME)
}

/// Whether a replacement at `(tip, max_fee)` raises both fields of the pooled `(prev_tip,
/// prev_max_fee)` by at least the tenth nodes require.
fn raises_both(prev_tip: u128, prev_max_fee: u128, tip: u128, max_fee: u128) -> bool {
    tip > prev_tip
        && max_fee > prev_max_fee
        && tip.saturating_mul(10) >= prev_tip.saturating_mul(11)
        && max_fee.saturating_mul(10) >= prev_max_fee.saturating_mul(11)
        && max_fee >= tip
}

/// Whether a refused send's error says the node already holds that very transaction (a send whose
/// answer was lost, sent again): it is in the pool all the same.
fn already_pooled(e: &anyhow::Error) -> bool {
    e.chain().filter_map(|c| c.downcast_ref::<NodeError>()).any(|n| {
        let m = n.message.to_ascii_lowercase();
        m.contains("already known") || m.contains("known transaction") || m.contains("already imported")
    })
}

/// One publication's state.
struct Publisher {
    chain: Chain,
    /// `--verify-rpc-url`: every deployment must show there too before the next send.
    verify: Option<Chain>,
    signer: PrivateKeySigner,
    router: Address,
    backlog: BacklogSource,
    tip: u128,
    /// The highest tip a replacement may carry ([`TIP_CAP_MULTIPLE`] × the floor, at least 1 gwei).
    tip_cap: u128,
    /// The highest max fee any send carries ([`BASE_FEE_CAP_MULTIPLE`] × the starting base fee +
    /// the tip cap).
    fee_cap: u128,
    /// The next nonce this publisher sends at.
    nonce: u64,
    /// The head number of the last send (at most one send per block).
    last_send_head: Option<u64>,
    /// The least wall-clock time between two sends ([`send_floor`]), and when the last one went.
    send_floor: Duration,
    last_send_at: Option<Instant>,
    /// `--progress`: each mined deployment is recorded here.
    progress: Option<Progress>,
    /// Deployments mined in this run.
    mined: usize,
    quiet: bool,
    #[cfg_attr(not(test), allow(dead_code))]
    faults: Faults,
}

impl Publisher {
    fn say(&self, msg: impl AsRef<str>) {
        if !self.quiet {
            eprintln!("{}", msg.as_ref());
        }
    }

    /// The pacing gate's inputs now.
    async fn gate(&self, own_unmined: u64) -> Result<(Header, Result<(), String>)> {
        let head = self.chain.head().await?;
        let safe = self.chain.safe().await?;
        let now = chrono::Utc::now().timestamp().max(0) as u64;
        let backlog = match self.backlog {
            BacklogSource::Fixed(b) => Some(b),
            BacklogSource::Chain => self.chain.backlog(&head, &safe).await?,
        };
        let inputs = PaceInputs {
            backlog_bytes: backlog,
            own_unmined_bytes: own_unmined,
            safe_lag_secs: head.timestamp.checked_sub(safe.timestamp),
            router_paused: self.chain.router_paused(self.router).await.ok(),
            head_age_secs: Some(now.saturating_sub(head.timestamp)),
        };
        Ok((head, plan::pace(&inputs)))
    }

    /// What is left of the wall-clock floor since the last send.
    fn floor_left(&self) -> Duration {
        self.last_send_at.map_or(Duration::ZERO, |t| self.send_floor.saturating_sub(t.elapsed()))
    }

    /// Waits until the gate opens on a block after the last send's, at least [`send_floor`] after
    /// it by the local clock, with the base fee under the fee cap.
    async fn wait_to_send(&mut self) -> Result<Header> {
        let mut said = Instant::now() - Duration::from_secs(3600);
        loop {
            let (head, mut verdict) = self.gate(0).await?;
            if verdict.is_ok() && head.base_fee.saturating_add(self.tip) > self.fee_cap {
                verdict = Err(format!("the base fee is {} wei, above this run's fee cap ({} wei)", head.base_fee, self.fee_cap));
            }
            let new_block = self.last_send_head.is_none_or(|n| head.number > n);
            match verdict {
                Ok(()) if new_block => {
                    let left = self.floor_left();
                    if left.is_zero() {
                        return Ok(head);
                    }
                    tokio::time::sleep(left).await;
                    continue;
                }
                Ok(()) => {}
                Err(why) if said.elapsed() >= Duration::from_secs(60) => {
                    self.say(format!("waiting to send: {why}"));
                    said = Instant::now();
                }
                Err(_) => {}
            }
            tokio::time::sleep(POLL).await;
        }
    }

    /// `--verify-rpc-url`: waits until the second RPC shows `d`'s transaction mined, successful, in
    /// the same block as the publisher's RPC reports (followed through a reorg), with `runtime` at
    /// its address there; fails after [`VERIFY_TIMEOUT`] (nothing more is signed).
    async fn confirm_on_verify(&self, d: &mut Deployed, runtime: &[u8], label: &str) -> Result<()> {
        let Some(v) = &self.verify else { return Ok(()) };
        #[cfg(test)]
        let timeout = self.faults.verify_timeout.unwrap_or(VERIFY_TIMEOUT);
        #[cfg(not(test))]
        let timeout = VERIFY_TIMEOUT;
        let start = Instant::now();
        let mut said = Instant::now();
        loop {
            if let Some(r) = v.receipt(d.tx_hash).await? {
                let block: Option<B256> = r["blockHash"].as_str().and_then(|h| h.parse().ok());
                let address: Option<Address> = r["contractAddress"].as_str().and_then(|a| a.parse().ok());
                if qty(&r["status"]).unwrap_or(0) == 1 && block == Some(d.block_hash) && address == Some(d.address) {
                    let code = v.code(d.address, json!({"blockHash": format!("{:#x}", d.block_hash)})).await?;
                    if code == runtime {
                        return Ok(());
                    }
                    bail!(
                        "{label}: the second RPC ({}) shows other code at {}: the RPCs disagree; nothing more is sent",
                        v.rpc.host(),
                        d.address
                    );
                }
            }
            // The publisher's RPC may have followed a reorg meanwhile.
            if let Some(r) = self.chain.receipt(d.tx_hash).await? {
                if qty(&r["status"]).unwrap_or(0) == 1 {
                    d.block_number = qty(&r["blockNumber"])? as u64;
                    d.block_hash = r["blockHash"].as_str().context("a receipt without a block hash")?.parse()?;
                }
            }
            if start.elapsed() >= timeout {
                bail!(
                    "{label}: the second RPC ({}) does not show {} in block {} after {} s: the publisher's RPC may be \
                     lying or intercepted; nothing more is sent",
                    v.rpc.host(),
                    d.tx_hash,
                    d.block_hash,
                    timeout.as_secs()
                );
            }
            if said.elapsed() >= Duration::from_secs(30) {
                self.say(format!("{label}: waiting for the second RPC ({}) to show {}", v.rpc.host(), d.tx_hash));
                said = Instant::now();
            }
            tokio::time::sleep(POLL).await;
        }
    }

    /// Records a mined deployment in `--progress`, if given.
    fn record(&mut self, d: &Deployed, range: Option<std::ops::Range<usize>>) -> Result<()> {
        if let Some(p) = &mut self.progress {
            match range {
                Some(r) => p.push_chunk(r, d),
                None => p.set_manifest(d),
            }
            p.save()?;
        }
        Ok(())
    }

    /// No transaction of this key is pending that this publisher did not send.
    async fn check_no_foreign_pending(&self) -> Result<()> {
        let pending = self.chain.nonce(self.signer.address(), "pending").await?;
        if pending > self.nonce {
            bail!(
                "{} has pending transactions this publisher did not send (pending nonce {pending}, expected {}): \
                 use a key of its own, and let it settle (§13.5)",
                self.signer.address(),
                self.nonce
            );
        }
        Ok(())
    }

    fn sign(&self, tx: TxEip1559) -> Result<(B256, Vec<u8>)> {
        let mut tx = tx;
        let sig = self.signer.sign_transaction_sync(&mut tx).context("signing")?;
        let env = TxEnvelope::from(tx.into_signed(sig));
        Ok((*env.tx_hash(), env.encoded_2718()))
    }

    async fn send_raw(&self, raw: &[u8]) -> Result<B256, anyhow::Error> {
        let v = self.chain.rpc.call("eth_sendRawTransaction", json!([hexs(raw)])).await?;
        Ok(v.as_str().context("no tx hash")?.parse()?)
    }

    /// Records in `--progress`, before it is sent, a transaction at `nonce` for `target` (a chunk's
    /// range, or the manifest).
    fn note_send(&mut self, target: &Option<std::ops::Range<usize>>, nonce: u64, hash: B256) -> Result<()> {
        if let Some(p) = &mut self.progress {
            p.note_send(target.clone(), nonce, self.signer.address().create(nonce), hash);
            p.save()?;
        }
        Ok(())
    }

    /// Deploys `runtime` verbatim (one chunk, `target` its range, or the manifest), sizing nothing:
    /// the caller sized it.
    async fn deploy(&mut self, runtime: &[u8], label: &str, target: Option<std::ops::Range<usize>>) -> Result<Deployed> {
        #[cfg(test)]
        if self.faults.stop_after.is_some_and(|n| self.mined >= n) {
            bail!("stopped by the test after {} deployment(s)", self.mined);
        }
        let input = zkminer_witness::manifest::creation_code(runtime);
        let mut redeploys = 0u32;
        let mut gas_floor = 0u64;
        loop {
            let head = self.wait_to_send().await?;
            self.check_no_foreign_pending().await?;
            let estimate = self.chain.estimate_gas(self.signer.address(), &input).await.context("eth_estimateGas")?;
            #[allow(unused_mut)]
            let mut gas = (estimate + estimate * GAS_MARGIN_PERCENT / 100 + 10_000).max(gas_floor);
            #[cfg(test)]
            if let Some(g) = self.faults.first_gas_limit.take() {
                gas = g;
            }
            // The fees of the transaction the pool holds at this nonce: a refused replacement
            // leaves them as they were.
            let (mut tip, mut max_fee) = plan::fees(head.base_fee, self.tip);
            max_fee = max_fee.min(self.fee_cap);
            let nonce = self.nonce;
            let mut hashes = Vec::new();
            let mut replacements = 0u32;
            let mut attempts = 0u32;
            let (hash, raw) = self.sign(plan::unsigned_creation(self.chain.chain_id, nonce, gas, max_fee, tip, input.clone()))?;
            self.note_send(&target, nonce, hash)?;
            self.last_send_at = Some(Instant::now());
            self.send_raw(&raw).await.with_context(|| format!("sending {label}"))?;
            hashes.push(hash);
            // What the pool holds at this nonce: sent again as it is if the pool drops it.
            let mut pooled_raw = raw;
            let mut resends = 0u32;
            self.last_send_head = Some(head.number);
            self.say(format!("{label}: sent {hash} at nonce {nonce} (gas {gas}, tip {tip} wei, max fee {max_fee} wei)"));
            #[cfg(test)]
            if std::mem::take(&mut self.faults.drop_first_send) {
                let _ = self.chain.rpc.call("anvil_dropTransaction", json!([format!("{hash:#x}")])).await;
            }
            #[cfg(test)]
            if std::mem::take(&mut self.faults.stop_after_send) {
                bail!("stopped by the test after sending {hash}");
            }
            // The receipt of any transaction sent at this nonce; a replacement while the gate is open.
            let mut sent_at = head.number;
            let mut used_without_receipt = 0u32;
            let mut capped_said = Instant::now() - Duration::from_secs(3600);
            let receipt = loop {
                let mut found = None;
                for h in &hashes {
                    if let Some(r) = self.chain.receipt(*h).await? {
                        found = Some((*h, r));
                        break;
                    }
                }
                if let Some(f) = found {
                    break f;
                }
                let (now, verdict) = self.gate(0).await?;
                if now.number >= sent_at + STUCK_BLOCKS && verdict.is_ok() && self.floor_left().is_zero() {
                    // Never an open-ended fee escalation: past the caps or the count, only waiting
                    // is left.
                    let (next_tip, next_max) = plan::bump(tip, max_fee, now.base_fee, self.tip);
                    let (next_tip, next_max) = (next_tip.min(self.tip_cap), next_max.min(self.fee_cap));
                    if self.chain.nonce(self.signer.address(), "latest").await? > nonce {
                        // The nonce is used: by one of ours, whose receipt the node shows shortly, or
                        // by a transaction this publisher never sent.
                        used_without_receipt += 1;
                        if used_without_receipt > 10 {
                            bail!("{label}: nonce {nonce} was used by a transaction this publisher did not send");
                        }
                    } else if attempts >= MAX_REPLACEMENTS || !raises_both(tip, max_fee, next_tip, next_max) {
                        // Only waiting is left, while the pool holds the transaction. One it dropped
                        // (nothing pending at this nonce) is sent again as it was, a few times;
                        // refused, the publish stops rather than wait for what is not coming.
                        if self.chain.nonce(self.signer.address(), "pending").await? <= nonce {
                            resends += 1;
                            if resends > MAX_RESENDS {
                                bail!(
                                    "{label}: the pool dropped the transaction at nonce {nonce} again after {MAX_RESENDS} \
                                     sends of it (tip {tip} wei, max fee {max_fee} wei, at this run's caps or after \
                                     {attempts} replacement(s)); nothing more is sent: publish again later (with \
                                     --progress, what is mined is kept)"
                                );
                            }
                            match self.send_raw(&pooled_raw).await {
                                Ok(_) => {}
                                Err(e) if already_pooled(&e) => {}
                                Err(e) => bail!(
                                    "{label}: the pool dropped the transaction at nonce {nonce} (tip {tip} wei, max fee \
                                     {max_fee} wei, at this run's caps or after {attempts} replacement(s)) and refused it \
                                     again ({e:#}); nothing more is sent: publish again later (with --progress, what is \
                                     mined is kept)"
                                ),
                            }
                            self.last_send_at = Some(Instant::now());
                            self.last_send_head = Some(now.number);
                            self.say(format!(
                                "{label}: the pool dropped its transaction at nonce {nonce}; sent it again ({resends}/{MAX_RESENDS})"
                            ));
                            #[cfg(test)]
                            if self.faults.drop_resends > 0 {
                                self.faults.drop_resends -= 1;
                                for h in &hashes {
                                    let _ = self.chain.rpc.call("anvil_dropTransaction", json!([format!("{h:#x}")])).await;
                                }
                            }
                        } else if capped_said.elapsed() >= Duration::from_secs(60) {
                            self.say(format!(
                                "{label}: unmined after {attempts} replacement(s), at the caps (tip {} wei, max fee {} wei) or the \
                                 count ({MAX_REPLACEMENTS}); waiting (stop with Ctrl-C and publish again)",
                                self.tip_cap, self.fee_cap
                            ));
                            capped_said = Instant::now();
                        }
                        sent_at = now.number;
                    } else {
                        let (h2, raw2) =
                            self.sign(plan::unsigned_creation(self.chain.chain_id, nonce, gas, next_max, next_tip, input.clone()))?;
                        self.note_send(&target, nonce, h2)?;
                        self.last_send_at = Some(Instant::now());
                        attempts += 1;
                        // Watched for a receipt either way: a send whose answer was lost may be pooled.
                        hashes.push(h2);
                        match self.send_raw(&raw2).await {
                            Ok(_) => pooled_raw = raw2,
                            Err(e) if already_pooled(&e) => pooled_raw = raw2,
                            Err(e) => {
                                self.say(format!(
                                    "{label}: a replacement was refused ({e:#}); the pool keeps tip {tip} wei, max fee {max_fee} wei"
                                ));
                                sent_at = now.number;
                                self.last_send_head = Some(now.number);
                                tokio::time::sleep(POLL).await;
                                continue;
                            }
                        }
                        (tip, max_fee) = (next_tip, next_max);
                        replacements += 1;
                        self.say(format!(
                            "{label}: unmined after {} blocks with the gate open; replaced at nonce {nonce} by {h2} \
                             (tip {tip} wei, max fee {max_fee} wei)",
                            now.number - sent_at
                        ));
                        sent_at = now.number;
                        self.last_send_head = Some(now.number);
                    }
                }
                tokio::time::sleep(POLL).await;
            };
            let (tx_hash, r) = receipt;
            self.nonce = nonce + 1;
            let status = qty(&r["status"]).unwrap_or(0);
            let block_number = qty(&r["blockNumber"])? as u64;
            let block_hash: B256 = r["blockHash"].as_str().context("a receipt without a block hash")?.parse()?;
            let gas_used = qty(&r["gasUsed"])?;
            let price = r.get("effectiveGasPrice").map(qty).transpose()?.unwrap_or(0);
            let l1 = r.get("l1Fee").filter(|v| !v.is_null()).map(qty).transpose()?.unwrap_or(0);
            if status != 1 {
                // An out-of-gas creation spends the nonce and leaves the address empty: redeploy.
                redeploys += 1;
                if redeploys > MAX_REDEPLOYS {
                    bail!("{label}: {redeploys} creations failed; stopping");
                }
                gas_floor = gas.saturating_mul(2);
                self.say(format!("{label}: {tx_hash} failed in block {block_number} (status {status}); redeploying at a new nonce with gas ≥ {gas_floor}"));
                continue;
            }
            let address: Address = r["contractAddress"].as_str().context("a creation receipt without contractAddress")?.parse()?;
            let mut d = Deployed {
                address,
                tx_hash,
                nonce,
                block_number,
                block_hash,
                body_bytes: runtime.len().saturating_sub(1),
                cost_wei: (gas_used.saturating_mul(price).saturating_add(l1)).to_string(),
                replacements,
                redeploys,
                reused: false,
            };
            self.confirm_on_verify(&mut d, runtime, label).await?;
            self.mined += 1;
            return Ok(d);
        }
    }

    /// Waits until every deployment's block is at or below the safe head with its hash unchanged.
    async fn wait_safe(&self, deployed: &mut [Deployed]) -> Result<()> {
        let mut said = Instant::now() - Duration::from_secs(3600);
        loop {
            // Read again each time: a reorg may have moved a deployment to a later block.
            let last = deployed.iter().map(|d| d.block_number).max().unwrap_or(0);
            let safe = self.chain.safe().await?;
            if safe.number >= last {
                let mut moved = false;
                for d in deployed.iter_mut() {
                    let at = self.chain.block_at(d.block_number).await?;
                    if at.map(|h| h.hash) != Some(d.block_hash) {
                        // Reorged: its receipt says where it is now (or that it is gone, for now).
                        moved = true;
                        match self.chain.receipt(d.tx_hash).await? {
                            Some(r) if qty(&r["status"]).unwrap_or(0) == 1 => {
                                d.block_number = qty(&r["blockNumber"])? as u64;
                                d.block_hash = r["blockHash"].as_str().context("no block hash")?.parse()?;
                            }
                            _ => bail!(
                                "{} ({}) is no longer in the chain after a reorg: publish again (nothing printed is usable)",
                                d.address,
                                d.tx_hash
                            ),
                        }
                    }
                }
                if !moved {
                    return Ok(());
                }
            } else if said.elapsed() >= Duration::from_secs(30) {
                self.say(format!("waiting for the safe head ({}) to reach block {last}", safe.number));
                said = Instant::now();
            }
            tokio::time::sleep(POLL).await;
        }
    }
}

/// The §13.4 fetch of `manifest` at the safe head, pinned by its hash: the manifest checked with
/// `parse_manifest` (its sha256 must be `sha256`), the chunks read in batches of at most 256, each
/// checked with `chunk_body` and assembled by the `Assembler` (count, length, sha256). Returns the
/// assembled bytes.
async fn fetch_at_safe(chain: &Chain, manifest: Address, sha256: [u8; 32], max_bytes: u64) -> Result<Vec<u8>> {
    let safe = chain.safe().await?;
    let at = json!({"blockHash": format!("{:#x}", safe.hash)});
    let code = chain.code(manifest, at.clone()).await?;
    if code.len() > MAX_CODE_BYTES {
        bail!("the manifest's code is longer than {MAX_CODE_BYTES} bytes");
    }
    let m = parse_manifest(&code, manifest, max_bytes, Some(&sha256)).map_err(|e| anyhow::anyhow!("the manifest at the safe head: {e}"))?;
    let mut asm = Assembler::new(&m, Vec::with_capacity(m.length as usize));
    for batch in m.chunks.chunks(FETCH_BATCH) {
        let calls: Vec<(&str, Value)> = batch.iter().map(|a| ("eth_getCode", json!([addr_param(*a), at.clone()]))).collect();
        for (a, r) in batch.iter().zip(chain.rpc.batch(&calls).await?) {
            let code = data(&r.map_err(|e: NodeError| anyhow::anyhow!("chunk {a}: {e}"))?)?;
            if code.len() > MAX_CODE_BYTES {
                bail!("chunk {a}: code longer than {MAX_CODE_BYTES} bytes");
            }
            let body = chunk_body(&code).map_err(|e| anyhow::anyhow!("chunk {a}: {e}"))?;
            asm.push(body).map_err(|e| anyhow::anyhow!("chunk {a}: {e}"))?;
        }
    }
    asm.finish().map_err(|e| anyhow::anyhow!("assembling the artifact: {e}"))
}

/// Whether a running miner holds `~/.zkminer/miner.lock` (never created here).
fn miner_running() -> bool {
    let Some(path) = dirs::home_dir().map(|h| h.join(".zkminer").join("miner.lock")) else { return false };
    let Ok(f) = std::fs::OpenOptions::new().write(true).open(&path) else { return false };
    matches!(f.try_lock(), Err(std::fs::TryLockError::WouldBlock))
}

/// The network policy publishing runs under: developer mode only when the configuration enables it
/// for this very chain (`[dev] private_network` with `[dev] chain_id` and `[chain] chain_id` equal
/// to `--chain-id`), else public.
fn policy_for(config: &ZkMinerConfig, chain_id: u64) -> Result<NetPolicy> {
    let mode = if config.net_mode() == NetMode::DevPrivate && config.chain.chain_id == chain_id {
        eprintln!("{}: the RPC may be on loopback or the local network", zkminer_netguard::DEV_MODE_BANNER);
        NetMode::DevPrivate
    } else {
        NetMode::Public
    };
    NetPolicy::with_options(mode, config.egress_deny()?, config.egress_facts_options()?)
        .context("reading this host's network interfaces and routes (the network guard needs them)")
}

/// The keys and the chain's view of them (§13.5 "Key"): not staked, not an operator, nothing
/// pending it did not send.
async fn check_key(chain: &Chain, router: Address, from_block: u64, who: Address) -> Result<()> {
    let staking = {
        let out = chain.eth_call(router, IPublishReads::stakingCall {}.abi_encode()).await.context("router.staking()")?;
        IPublishReads::stakingCall::abi_decode_returns(&out).context("router.staking()")?
    };
    let out = chain
        .eth_call(staking, IPublishReads::getProverStakeCall { prover: who }.abi_encode())
        .await
        .context("staking.getProverStake")?;
    let s = IPublishReads::getProverStakeCall::abi_decode_returns(&out).context("staking.getProverStake")?;
    if s.totalStaked != 0 || s.lockedCollateral != 0 || s.unstakeAmount != 0 {
        bail!("{who} is staked as a prover: publish with a key of its own (a stuck chunk would stall its fulfils, §13.5)");
    }
    // Every prover that ever authorized this address as an operator, and whether that still holds.
    let head = chain.head().await?.number;
    let topic0 = IPublishReads::OperatorAuthorized::SIGNATURE_HASH;
    let topic2 = B256::left_padding_from(who.as_slice());
    let mut provers = std::collections::BTreeSet::new();
    let mut from = from_block;
    while from <= head {
        let to = (from + LOG_RANGE - 1).min(head);
        let logs = chain
            .rpc
            .call(
                "eth_getLogs",
                json!([{"address": addr_param(router), "fromBlock": format!("0x{from:x}"), "toBlock": format!("0x{to:x}"),
                        "topics": [format!("{topic0:#x}"), Value::Null, format!("{topic2:#x}")]}]),
            )
            .await
            .context("the operator check's log scan")?;
        for l in logs.as_array().into_iter().flatten() {
            if let Some(p) = l["topics"].get(1).and_then(Value::as_str).and_then(|t| t.parse::<B256>().ok()) {
                provers.insert(Address::from_slice(&p.0[12..]));
            }
        }
        from = to + 1;
    }
    for p in provers {
        let out = chain
            .eth_call(router, IPublishReads::operatorAuthorizationsCall { prover: p, operator: who }.abi_encode())
            .await
            .context("router.operatorAuthorizations")?;
        let a = IPublishReads::operatorAuthorizationsCall::abi_decode_returns(&out).context("router.operatorAuthorizations")?;
        if a.permissionBitmap == U256::ZERO {
            continue;
        }
        // An authorization counts while its nonce is the prover's current one: `revokeAllOperators`
        // moves the prover's on, and the old authorization never holds again (a new one is a new
        // `OperatorAuthorized`). A frozen operator is still refused: the prover may unfreeze it.
        let out = chain
            .eth_call(router, IPublishReads::proverAuthNonceCall { prover: p }.abi_encode())
            .await
            .context("router.proverAuthNonce")?;
        let current = IPublishReads::proverAuthNonceCall::abi_decode_returns(&out).context("router.proverAuthNonce")?;
        if a.authorizationNonce == current {
            bail!("{who} is authorized as prover {p}'s operator: publish with a key of its own (§13.5)");
        }
    }
    Ok(())
}

/// Splits `bytes[from..]` into chunks whose creation transactions each estimate at most 19,500 DA
/// bytes (ranges into `bytes`). The caller checks the whole plan.
async fn plan_chunks(chain: &Chain, bytes: &[u8], from: usize, first: usize) -> Result<(Vec<std::ops::Range<usize>>, bool)> {
    let mut out = Vec::new();
    let mut at = from;
    let mut oracle = true;
    while at < bytes.len() {
        let mut size = first.min(bytes.len() - at);
        for _ in 0..16 {
            let tx = plan::conservative_creation(chain.chain_id, plan::chunk_creation(&bytes[at..at + size]));
            let (est, by_oracle) = chain.da_bytes(&tx).await;
            oracle &= by_oracle;
            if est <= plan::MAX_CHUNK_DA_BYTES {
                break;
            }
            size = plan::shrink(size, est);
        }
        out.push(at..at + size);
        at += size;
    }
    Ok((out, oracle))
}

/// `zkminer artifact publish`.
#[allow(clippy::default_constructed_unit_structs)] // `Faults` has fields in test builds
pub async fn publish(config_path: Option<&Path>, opts: PublishOptions) -> Result<()> {
    let config = ZkMinerConfig::load(config_path)?;
    config.validate_network()?;
    publish_with(&config, opts, Faults::default()).await.map(|_| ())
}

/// [`publish`] with a configuration in hand (and, in tests, faults to inject).
pub async fn publish_with(config: &ZkMinerConfig, mut opts: PublishOptions, faults: Faults) -> Result<Published> {
    // 1. The input, before anything else.
    let bytes = std::fs::read(&opts.file).with_context(|| format!("reading {}", opts.file.display()))?;
    plan::check_input(&bytes, opts.kind)?;
    let sha256 = zkminer_witness::manifest::sha256(&bytes);
    let mut warnings = Vec::new();
    if opts.kind == Kind::Builder && bytes.len() as u64 > plan::DEFAULT_MAX_BUILDER_BYTES {
        warnings.push(format!(
            "{} bytes is above the published default max_builder_bytes ({}): miners on the default skip it",
            bytes.len(),
            plan::DEFAULT_MAX_BUILDER_BYTES
        ));
    }
    if opts.kind == Kind::Elf {
        warnings.push("Phase-1 miners ignore hemi-code ELF entries (§13.6)".into());
    }

    // 2. The RPC, through the guard.
    if config.chain.rpc_url == opts.rpc_url && miner_running() {
        bail!("--rpc-url is the miner's [chain] rpc_url and a miner is running: publish through another endpoint (§13.5)");
    }
    let policy = policy_for(config, opts.chain_id)?;
    let dev = policy.mode() == NetMode::DevPrivate;
    let rpc = Rpc::new(&policy, &opts.rpc_url, opts.max_requests_per_sec)?;
    let chain = Chain { rpc, chain_id: opts.chain_id };
    let reported = qty(&chain.rpc.call("eth_chainId", json!([])).await?)? as u64;
    if reported != opts.chain_id {
        bail!("the RPC at {} serves chain {reported}, not --chain-id {}", chain.rpc.host(), opts.chain_id);
    }
    let verify = match &opts.verify_rpc_url {
        Some(url) => {
            let v = Chain { rpc: Rpc::new(&policy, url, opts.max_requests_per_sec)?, chain_id: opts.chain_id };
            if v.rpc.host() == chain.rpc.host() {
                warnings.push("--verify-rpc-url names the same host as --rpc-url: it checks little".into());
            }
            let id = qty(&v.rpc.call("eth_chainId", json!([])).await?)? as u64;
            if id != opts.chain_id {
                bail!("the second RPC at {} serves chain {id}, not --chain-id {}", v.rpc.host(), opts.chain_id);
            }
            Some(v)
        }
        None => None,
    };
    let known = zkminer_chain::deployment::known_deployment(opts.chain_id);
    let router = match (opts.router, known) {
        (Some(r), _) => r,
        (None, Some(k)) => k.router,
        (None, None) => bail!("no known HemiProve deployment on chain {}: name its router with --router", opts.chain_id),
    };
    if chain.code(router, json!("latest")).await?.is_empty() {
        bail!("no contract at the router {router} on chain {}", opts.chain_id);
    }
    let from_block = opts.from_block.or(known.map(|k| k.scan_from_block)).unwrap_or(0);
    // The local clock's floor between sends, whatever the RPC reports.
    let head = chain.head().await?;
    let send_floor = send_floor(
        opts.block_time_ms.map(Duration::from_millis),
        known_block_time(opts.chain_id),
        chain.measured_block_time(&head).await.ok().flatten(),
        dev,
    )?;
    // `[dev] da_backlog_bytes` stands in for the backlog only in developer mode, and on a chain with
    // a deployment only against a node on loopback (a local fork).
    let backlog = match config.dev_da_backlog_bytes_for(&opts.rpc_url) {
        Some(b) if dev => BacklogSource::Fixed(b),
        _ => BacklogSource::Chain,
    };

    // 3. The key, refused before anything is sent.
    let signer = keys::load(
        &opts.keystore,
        match opts.password_fd.take() {
            Some(fd) => keys::PasswordSource::Fd(fd),
            None => keys::PasswordSource::Tty,
        },
        config,
    )?;
    let me = signer.address();
    check_key(&chain, router, from_block, me).await?;
    // 4. What an earlier run left (`--progress`), the plan and the cost preview.
    let mut progress = match &opts.progress {
        Some(path) => Some(Progress::open(path, opts.chain_id, B256::from(sha256), bytes.len())?),
        None => None,
    };
    let latest = chain.nonce(me, "latest").await?;
    let pending = chain.nonce(me, "pending").await?;
    if pending != latest {
        // The transaction an earlier run sent before it stopped, still in the pool: checked once it
        // settles, never sent around.
        if let Some((nonce, hashes)) =
            progress.as_ref().and_then(|p| p.pending_send()).filter(|(n, _)| (latest..pending).contains(n))
        {
            let hashes: Vec<String> = hashes.iter().map(|h| format!("{h:#x}")).collect();
            bail!(
                "the transaction the stopped run sent at nonce {nonce} ({}) is still pending: let it mine or drop, then \
                 publish again (it is checked before anything is sent)",
                hashes.join(", ")
            );
        }
        bail!(
            "{me} has {} pending transaction(s) it did not send here: let them settle, or use a key of its own (§13.5)",
            pending - latest
        );
    }
    let (mut deployed, reused_manifest) = match &progress {
        Some(p) => p.reusable(&chain, &bytes).await?,
        None => (Vec::new(), None),
    };
    let reused_to = deployed.last().map_or(0, |d: &(std::ops::Range<usize>, Deployed)| d.0.end);
    if let Some(p) = &mut progress {
        // Only what was found on chain stays recorded (a transaction left pending included, when
        // it created what it was for): the rest is sent again.
        p.keep(&deployed, reused_manifest.as_ref());
        p.save()?;
    }
    if !deployed.is_empty() {
        let s = format!(
            "reusing {} chunk(s) ({} bytes){} from {}",
            deployed.len(),
            reused_to,
            if reused_manifest.is_some() { " and the manifest" } else { "" },
            opts.progress.as_deref().map(|p| p.display().to_string()).unwrap_or_default()
        );
        if opts.json {
            warnings.push(s);
        } else {
            eprintln!("{s}");
        }
    }
    let (chunks, oracle) = plan_chunks(&chain, &bytes, reused_to, opts.kind_chunk_bytes()).await?;
    plan::check_plan(deployed.len() + chunks.len(), bytes.len())?;
    if !oracle {
        warnings.push("no GasPriceOracle on this chain: chunks were sized against the RPC-free upper bound".into());
    }
    let tip = match opts.tip_wei {
        Some(t) => t,
        None => match chain.measured_tip_floor(&head).await? {
            Some(t) => t,
            None => qty(&chain.rpc.call("eth_maxPriorityFeePerGas", json!([])).await?)?.max(1),
        },
    };
    #[allow(unused_mut)]
    let mut tip_cap = tip.saturating_mul(TIP_CAP_MULTIPLE).max(MIN_TIP_CAP_WEI);
    #[allow(unused_mut)]
    let mut fee_cap = head.base_fee.saturating_mul(BASE_FEE_CAP_MULTIPLE).saturating_add(tip_cap);
    let (_, max_fee) = plan::fees(head.base_fee, tip);
    #[cfg(test)]
    if faults.no_fee_room {
        (tip_cap, fee_cap) = (tip, max_fee);
    }
    let largest = chunks.iter().map(|c| c.len()).max().unwrap_or(0);
    let gas_largest = match chunks.iter().find(|c| c.len() == largest) {
        Some(c) => chain.estimate_gas(me, &plan::chunk_creation(&bytes[c.clone()])).await?,
        None => 0,
    };
    let all_chunks = deployed.len() + chunks.len();
    let manifest_gas = if reused_manifest.is_some() {
        0
    } else {
        chain
            .estimate_gas(
                me,
                &zkminer_witness::manifest::creation_code(&manifest_runtime_code(
                    bytes.len() as u64,
                    &sha256,
                    &vec![Address::ZERO; all_chunks],
                )),
            )
            .await?
    };
    let l2_gas = gas_largest.saturating_mul(chunks.len() as u64).saturating_add(manifest_gas);
    let mut l1_total: Option<U256> = Some(U256::ZERO);
    let mut l1_largest = U256::ZERO;
    for c in &chunks {
        let tx = plan::conservative_creation(opts.chain_id, plan::chunk_creation(&bytes[c.clone()]));
        match (chain.l1_fee(&tx).await, l1_total) {
            (Some(f), Some(t)) => {
                l1_total = Some(t + f);
                l1_largest = l1_largest.max(f);
            }
            _ => l1_total = None,
        }
    }
    let gas_limit = gas_largest.max(manifest_gas);
    let gas_limit = gas_limit + gas_limit * GAS_MARGIN_PERCENT / 100 + 10_000;
    let in_flight = U256::from(gas_limit) * U256::from(max_fee) + l1_largest;
    let balance = chain.balance(me).await?;
    let preview = plan::CostPreview {
        length: bytes.len(),
        chunks: chunks.len(),
        largest_chunk: largest,
        base_fee_wei: head.base_fee.to_string(),
        tip_wei: tip.to_string(),
        max_fee_wei: max_fee.to_string(),
        l2_gas,
        l2_fee_wei: (U256::from(l2_gas) * U256::from(head.base_fee + tip)).to_string(),
        l1_fee_wei: l1_total.map(|t| t.to_string()),
        in_flight_balance_wei: in_flight.to_string(),
        balance_wei: balance.to_string(),
    };
    if opts.json {
        eprintln!("{}", serde_json::to_string(&preview)?);
    } else {
        eprintln!("{preview}");
        eprintln!("  pacing:     at least {} ms between sends (the local clock)", send_floor.as_millis());
    }
    if balance < in_flight {
        bail!("{me} holds {balance} wei; one chunk in flight needs {in_flight} wei");
    }
    if !opts.yes {
        confirm("Publication is permanent and public. Send?")?;
    }

    // 5. Send: the chunks, then the manifest.
    let mut p = Publisher {
        chain,
        verify,
        signer,
        router,
        backlog,
        tip,
        tip_cap,
        fee_cap,
        nonce: latest,
        last_send_head: None,
        send_floor,
        last_send_at: None,
        progress,
        mined: 0,
        quiet: opts.json,
        faults,
    };
    for c in &chunks {
        let runtime = zkminer_witness::manifest::chunk_runtime_code(&bytes[c.clone()]);
        let d = p.deploy(&runtime, &format!("chunk {}/{}", deployed.len() + 1, all_chunks), Some(c.clone())).await?;
        p.record(&d, Some(c.clone()))?;
        deployed.push((c.clone(), d));
    }
    let mut deployed: Vec<Deployed> = deployed.into_iter().map(|(_, d)| d).collect();
    let addresses: Vec<Address> = deployed.iter().map(|d| d.address).collect();
    let manifest_runtime = manifest_runtime_code(bytes.len() as u64, &sha256, &addresses);
    let manifest = match reused_manifest {
        Some(m) => m,
        None => {
            let m = p.deploy(&manifest_runtime, "manifest", None).await?;
            p.record(&m, None)?;
            m
        }
    };
    deployed.push(manifest);

    // 6. Safe, then the §13.4 fetch (on the second RPC too), then the result.
    p.say("all deployed; waiting until every deploying block is at or below the safe head");
    p.wait_safe(&mut deployed).await?;
    let manifest = deployed.pop().expect("the manifest");
    let fetched = fetch_at_safe(&p.chain, manifest.address, sha256, u64::MAX).await?;
    if fetched != bytes {
        bail!("the artifact read back at the safe head is not the file");
    }
    if let Some(v) = &p.verify {
        let fetched = fetch_at_safe(v, manifest.address, sha256, u64::MAX).await.context("the read-back on the second RPC")?;
        if fetched != bytes {
            bail!("the artifact read back at the second RPC's safe head is not the file");
        }
    }
    let locator = HemiCodeLocator { chain_id: opts.chain_id, manifest: manifest.address }.to_uri();
    let total: U256 = deployed
        .iter()
        .chain(std::iter::once(&manifest))
        .filter(|d| !d.reused)
        .map(|d| d.cost_wei.parse::<U256>().unwrap_or_default())
        .fold(U256::ZERO, |a, b| a + b);
    let keccak = keccak256(&bytes);
    let published = Published {
        locator: locator.clone(),
        sha256: B256::from(sha256),
        keccak256: keccak,
        length: bytes.len(),
        chunks: deployed,
        manifest,
        total_cost_wei: total.to_string(),
        builder_id: (opts.kind == Kind::Builder).then_some(B256::from(sha256)),
        add_storage_uri: (opts.kind == Kind::Elf)
            .then(|| format!("addStorageURI(<programId>, 3, \"{locator}\", {keccak:#x})")),
        warnings,
    };
    if opts.json {
        println!("{}", serde_json::to_string_pretty(&published)?);
    } else {
        print_published(&published);
    }
    Ok(published)
}

impl PublishOptions {
    fn kind_chunk_bytes(&self) -> usize {
        plan::DEFAULT_CHUNK_BYTES
    }
}

fn print_published(p: &Published) {
    println!("locator:   {}", p.locator);
    println!("sha256:    {}", p.sha256);
    println!("length:    {}", p.length);
    println!("chunks:    {}", p.chunks.len());
    for c in &p.chunks {
        println!("  {} ({} bytes, block {}{})", c.address, c.body_bytes, c.block_number, if c.reused { ", reused" } else { "" });
    }
    println!("manifest:  {} (block {})", p.manifest.address, p.manifest.block_number);
    println!("cost:      {} wei", p.total_cost_wei);
    if let Some(id) = p.builder_id {
        println!("builderId: {id}");
    }
    if let Some(a) = &p.add_storage_uri {
        println!("register:  {a}");
    }
    for w in &p.warnings {
        println!("warning:   {w}");
    }
    println!("Read back at the safe head with the miner's checks. Submit the job only now.");
}

fn confirm(question: &str) -> Result<()> {
    use std::io::{BufRead, Write};
    let mut tty = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .context("no terminal to confirm on: pass --yes after reading the preview")?;
    write!(tty, "{question} [y/N] ")?;
    tty.flush()?;
    let mut line = String::new();
    std::io::BufReader::new(&tty).read_line(&mut line)?;
    if !matches!(line.trim(), "y" | "Y" | "yes") {
        bail!("not sent");
    }
    Ok(())
}

#[cfg(test)]
mod anvil_tests;
#[cfg(test)]
mod test_contracts;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_send_floor_is_the_block_time_whatever_the_rpc_reports() {
        let ms = Duration::from_millis;
        let hemi = known_block_time(743111);
        assert_eq!(hemi, Some(ms(12_000)));
        assert_eq!(known_block_time(43111), hemi);
        assert_eq!(known_block_time(31337), None);
        // Public mode on Hemi: a lying RPC's 100 ms blocks change nothing; a slower chain slows it.
        assert_eq!(send_floor(None, hemi, Some(ms(100)), false).unwrap(), ms(12_000));
        assert_eq!(send_floor(None, hemi, None, false).unwrap(), ms(12_000));
        assert_eq!(send_floor(None, hemi, Some(ms(20_000)), false).unwrap(), ms(20_000));
        assert!(send_floor(Some(ms(2_000)), hemi, None, false).unwrap_err().to_string().contains("12000 ms"));
        assert_eq!(send_floor(Some(ms(15_000)), hemi, None, false).unwrap(), ms(15_000));
        // Public mode elsewhere: never below a second.
        assert_eq!(send_floor(None, None, Some(Duration::ZERO), false).unwrap(), ms(1_000));
        assert_eq!(send_floor(None, None, None, false).unwrap(), ms(1_000));
        assert_eq!(send_floor(None, None, Some(ms(2_500)), false).unwrap(), ms(2_500));
        assert!(send_floor(Some(Duration::ZERO), None, None, false).is_err());
        // Developer mode: what is configured, known or measured, zero included.
        assert_eq!(send_floor(Some(Duration::ZERO), hemi, None, true).unwrap(), Duration::ZERO);
        assert_eq!(send_floor(None, hemi, Some(ms(100)), true).unwrap(), ms(12_000));
        assert_eq!(send_floor(None, None, Some(ms(100)), true).unwrap(), ms(100));
        assert_eq!(send_floor(None, None, None, true).unwrap(), Duration::ZERO);
    }

    #[test]
    fn a_replacement_must_raise_both_fees_by_a_tenth() {
        assert!(raises_both(10, 2_010, 12, 2_262));
        assert!(!raises_both(10, 2_010, 10, 2_262), "the tip did not rise");
        assert!(!raises_both(10, 2_010, 12, 2_100), "the max fee rose by less than a tenth");
        assert!(!raises_both(100, 2_000, 1_000, 900), "max fee below the tip");
        // Capped: bump then clamp to the caps leaves nothing to send.
        let (t, m) = plan::bump(64, 200, 50, 1);
        assert!(!raises_both(64, 200, t.min(64), m.min(200)));
        assert!(!raises_both(u128::MAX, u128::MAX, u128::MAX, u128::MAX));
    }

    #[test]
    fn a_pooled_duplicate_is_recognized_through_context() {
        let e = anyhow::Error::new(NodeError { code: -32000, message: "already known".into() }).context("eth_sendRawTransaction");
        assert!(already_pooled(&e));
        let e = anyhow::Error::new(NodeError { code: -32000, message: "replacement transaction underpriced".into() }).context("x");
        assert!(!already_pooled(&e));
        assert!(!already_pooled(&anyhow::anyhow!("already known (but not from the node)")));
    }

    #[test]
    fn the_rpc_url_comes_from_argv_a_file_or_the_environment() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("url");
        std::fs::write(&f, "https://rpc.example.com/v1/s3cr3t\nignored\n").unwrap();
        assert_eq!(rpc_url_from(Some("https://a".into()), Some(&f), None).unwrap().as_deref(), Some("https://a"));
        assert_eq!(rpc_url_from(None, Some(&f), None).unwrap().as_deref(), Some("https://rpc.example.com/v1/s3cr3t"));
        std::fs::write(&f, "\n").unwrap();
        assert!(rpc_url_from(None, Some(&f), None).is_err());
        assert!(rpc_url_from(None, Some(&dir.path().join("missing")), None).is_err());
        // A variable no test sets.
        assert_eq!(rpc_url_from(None, None, Some("ZKMINER_TEST_NO_SUCH_RPC_URL_VARIABLE")).unwrap(), None);
        assert_eq!(rpc_url_from(None, None, None).unwrap(), None);
    }

    /// Every chain with a known deployment is one the stricter rules (`[dev] da_backlog_bytes`, the
    /// send floor) apply to.
    #[test]
    fn known_deployments_are_deployed_chains() {
        for id in [1u64, 43111, 743111, 31337, 11155111] {
            if zkminer_chain::deployment::known_deployment(id).is_some() {
                assert!(zkminer_config::DEPLOYED_CHAIN_IDS.contains(&id), "{id}");
            }
        }
        for id in zkminer_config::PRODUCTION_CHAIN_IDS {
            assert!(zkminer_config::DEPLOYED_CHAIN_IDS.contains(id), "{id}");
        }
    }
}
