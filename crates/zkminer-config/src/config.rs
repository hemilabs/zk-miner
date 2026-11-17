use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Top-level configuration for zkminer.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ZkMinerConfig {
    #[serde(default)]
    pub chain: ChainConfig,
    #[serde(default)]
    pub contracts: ContractAddresses,
    #[serde(default)]
    pub wallet: WalletConfig,
    #[serde(default)]
    pub prover: ProverConfig,
    /// Witness-construction jobs (docs/witness-construction-jobs.md §19); off by default.
    #[serde(default)]
    pub witness: crate::witness::WitnessConfig,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retention: Option<crate::witness::RetentionConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub broker: Option<crate::witness::BrokerSection>,
    /// Developer settings: never for a miner on a market. Not written when off.
    #[serde(default, skip_serializing_if = "DevConfig::is_off")]
    pub dev: DevConfig,
    /// The network guard's operator settings. Not written when empty.
    #[serde(default, skip_serializing_if = "EgressConfig::is_empty")]
    pub egress: EgressConfig,
}

/// `[dev]`: developer settings. Unknown keys are refused, so a misspelt switch fails loudly instead
/// of leaving the guard in a state nobody chose.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DevConfig {
    /// Lets connections a requester causes (a program's ELF download URLs and their redirects)
    /// reach non-public destinations: loopback, the LAN, link-local, the host's own addresses.
    /// For local test networks and test scripts only, which serve programs from this machine.
    /// The ONLY way to turn the network guard off: there is no environment variable or flag.
    /// Needs [`Self::chain_id`] equal to `[chain] chain_id` (which the RPC confirms at startup);
    /// refused on Hemi mainnet (43111) whatever it says; announced by a warning at every start.
    /// Default false.
    #[serde(default)]
    pub private_network: bool,
    /// The test network `private_network` is meant for: it takes effect only on a config whose
    /// `[chain] chain_id` is this id. A config copied to another network (or a production
    /// deployment under a new chain id) then refuses to start instead of opening the guard there.
    /// Default: unset (and `private_network = true` without it is refused).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain_id: Option<u64>,
    /// A fixed DA backlog reading, in estimated bytes, for witness-job claim gates and fulfils
    /// (docs/witness-construction-jobs.md §5.5) and `zkminer artifact publish`, in place of reading
    /// the chain. For a local test network whose node serves no `l1GasUsed` in its receipts
    /// (anvil), where the reading is otherwise always unknown and every witness job is held. Only
    /// on a chain with no HemiProve deployment ([`DEPLOYED_CHAIN_IDS`]), or on a deployment's chain
    /// id when the RPC is on loopback (a local fork of it): never against the real testnet, whose
    /// shared router the backlog rule protects, and never on Hemi mainnet. Default: unset (read the
    /// chain).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub da_backlog_bytes: Option<u64>,
}

impl DevConfig {
    fn is_off(&self) -> bool {
        !self.private_network && self.chain_id.is_none() && self.da_backlog_bytes.is_none()
    }
}

/// `[egress]`: the network guard's operator settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EgressConfig {
    /// Extra CIDRs no requester-caused connection may reach (`"203.0.113.7/32"`, `"2001:db8::/32"`,
    /// or a bare address): the addresses of the rest of your fleet, your VPC's ranges, and this
    /// host's public address behind NAT if discovering it fails or is off. The host's own
    /// addresses, the networks it is connected to or routes off its default route, its IPv6 site
    /// and its DNS servers are refused already.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deny_cidrs: Vec<String>,
    /// The site around each of this host's own global IPv6 addresses that is refused: its
    /// enclosing /N, 16..=64 (default 32: what an organisation — a campus, a company — usually
    /// holds, whose other networks hold its other machines). The default also refuses the rest of
    /// this host's own ISP's /32 over IPv6 (a name there that also has an IPv4 address still
    /// connects over IPv4); set it longer (48, 56) if that is in the way and your site is no wider.
    #[serde(
        default = "default_ipv6_site_prefix_len",
        skip_serializing_if = "is_default_ipv6_site_prefix_len"
    )]
    pub ipv6_site_prefix_len: u8,
    /// The site around each global IPv4 address on one of this host's interfaces that is
    /// refused: its enclosing /N, 8..=32 (default 16). A host numbered from public IPv4 space sits
    /// in a network (a campus, a data centre) whose other subnets the default gateway reaches.
    #[serde(
        default = "default_ipv4_site_prefix_len",
        skip_serializing_if = "is_default_ipv4_site_prefix_len"
    )]
    pub ipv4_site_prefix_len: u8,
    /// Learn this host's public addresses behind NAT (asking fixed reflectors — Google's and
    /// Cloudflare's DNS ones, and Cloudflare's over HTTPS — which address the query came from)
    /// and refuse them. Default true. While a family this host routes has no known public
    /// address, requester connections over it are refused; off, `public_addresses` must name one
    /// per family.
    #[serde(default = "default_true", skip_serializing_if = "is_true")]
    pub discover_public_addresses: bool,
    /// This host's public addresses (behind NAT, its router's; on an IPv6-only host behind NAT64,
    /// the translator's IPv4 address), as you know them: refused as its own, and a family named
    /// here counts as known when discovery cannot reach the reflectors (DNS filtered or
    /// intercepted, HTTPS to 1.1.1.1 blocked).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub public_addresses: Vec<String>,
    /// The ranges of your own network that this host reaches by the same route as the internet
    /// (a campus's or data centre's public ranges, your VPC's, what a full-tunnel VPN leads to):
    /// refused like `deny_cidrs`. Required (`[]` if there are none) on a host with a global IPv4
    /// address on an interface or an uplink that is not plainly physical (a tunnel, a VPN's `ppp`,
    /// a default route in a table other than `main`, …): judged at startup and again whenever the
    /// host's network changes, and while it is required and unset, no requester-caused
    /// connection is made.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub internal_ranges: Option<Vec<String>>,
    /// The hop limit of the probe sent right before every requester-caused connection: a
    /// destination that answers within this many hops is this host's own network and is refused.
    /// 2..=16, default 2.
    #[serde(
        default = "default_near_hop_limit",
        skip_serializing_if = "is_default_near_hop_limit"
    )]
    pub near_hop_limit: u8,
    /// The DNS-over-HTTPS resolvers requester host names are resolved with (never the system
    /// resolver), as `https://` URLs whose host is a public IP literal
    /// (`"https://9.9.9.9/dns-query"`). Default: Cloudflare's, Google's and Quad9's, built in.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub doh_resolvers: Vec<String>,
    /// NAT64 network-specific prefixes this host's translator uses (RFC 6052: a /32, /40, /48,
    /// /56, /64 or /96 of IPv6, e.g. `"2001:db8:64::/96"`). An address under one carries an IPv4
    /// address the translator connects to from its own IPv4 side, so it is judged by that IPv4
    /// address: a private or metadata address there is refused. The prefix a DNS64 resolver uses
    /// is learned at startup by asking this host's DNS servers for `ipv4only.arpa` (RFC 7050);
    /// name it here when that cannot work. The well-known `64:ff9b::/96` needs no entry.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub nat64_prefixes: Vec<String>,
}

fn default_ipv6_site_prefix_len() -> u8 {
    zkminer_netguard::DEFAULT_IPV6_SITE_PREFIX_LEN
}

fn is_default_ipv6_site_prefix_len(n: &u8) -> bool {
    *n == zkminer_netguard::DEFAULT_IPV6_SITE_PREFIX_LEN
}

fn default_ipv4_site_prefix_len() -> u8 {
    zkminer_netguard::DEFAULT_IPV4_SITE_PREFIX_LEN
}

fn is_default_ipv4_site_prefix_len(n: &u8) -> bool {
    *n == zkminer_netguard::DEFAULT_IPV4_SITE_PREFIX_LEN
}

fn default_near_hop_limit() -> u8 {
    zkminer_netguard::DEFAULT_NEAR_HOP_LIMIT
}

fn is_default_near_hop_limit(n: &u8) -> bool {
    *n == zkminer_netguard::DEFAULT_NEAR_HOP_LIMIT
}

fn default_true() -> bool {
    true
}

fn is_true(b: &bool) -> bool {
    *b
}

impl Default for EgressConfig {
    fn default() -> Self {
        EgressConfig {
            deny_cidrs: Vec::new(),
            ipv6_site_prefix_len: default_ipv6_site_prefix_len(),
            ipv4_site_prefix_len: default_ipv4_site_prefix_len(),
            discover_public_addresses: true,
            public_addresses: Vec::new(),
            internal_ranges: None,
            near_hop_limit: default_near_hop_limit(),
            doh_resolvers: Vec::new(),
            nat64_prefixes: Vec::new(),
        }
    }
}

impl EgressConfig {
    fn is_empty(&self) -> bool {
        *self == EgressConfig::default()
    }
}

/// `[egress] <key>` CIDRs (or bare addresses), parsed; host bits must be zero.
fn parse_cidrs(key: &str, v: &[String]) -> Result<Vec<zkminer_netguard::Prefix>> {
    v.iter()
        .map(|s| {
            s.parse::<zkminer_netguard::Prefix>()
                .map_err(|e| anyhow::anyhow!("egress.{key}: {e}"))
        })
        .collect()
}

/// Chain ids zkminer treats as production markets, where `[dev] private_network` is refused
/// (Hemi mainnet), whether the switch reaches netguard's mode, and what every start says while it
/// is on. Defined in zkminer-netguard, so the witness broker refuses exactly the same chains.
pub use zkminer_netguard::{is_production_chain, DEV_MODE_BANNER, PRODUCTION_CHAIN_IDS};

/// Chains with a HemiProve deployment (or one meant for them): Hemi mainnet and Hemi testnet. A
/// test setting that stands in for a chain reading (`[dev] da_backlog_bytes`) applies on these
/// only against a node on loopback. `zkminer_chain::deployment::known_deployment` lists a subset.
pub const DEPLOYED_CHAIN_IDS: &[u64] = &[43111, 743111];

/// Whether `url`'s host is a loopback address written as one (`127.0.0.0/8`, `::1`, an
/// IPv4-mapped loopback) or `localhost`: the address every connection to it is pinned to is this
/// host's own. A name that merely resolves to loopback today is not enough.
pub fn rpc_on_loopback(url: &str) -> bool {
    let Ok(u) = zkminer_netguard::Url::parse(url) else {
        return false;
    };
    let Some(host) = u.host_str() else {
        return false;
    };
    let bare = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    match bare.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(a)) => a.is_loopback(),
        Ok(std::net::IpAddr::V6(a)) => {
            a.is_loopback() || a.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback())
        }
        Err(_) => bare.trim_end_matches('.').eq_ignore_ascii_case("localhost"),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainConfig {
    #[serde(default = "default_rpc_url")]
    pub rpc_url: String,
    #[serde(default)]
    pub ws_url: Option<String>,
    #[serde(default = "default_chain_id")]
    pub chain_id: u64,
    /// Legacy gas price in gwei applied to all miner txs. Some chains have a tiny
    /// base fee where the default EIP-1559 filler under-prices txs and they stall;
    /// set e.g. 1.0 to force 1 gwei. None = use the provider's automatic pricing.
    #[serde(default)]
    pub gas_price_gwei: Option<f64>,
    /// On-chain staking maturity (seconds) for this deployment, used only for the
    /// maturity countdown/readiness display. It's a Solidity compile-time constant
    /// with no getter, so it can't be read from the chain; set it to match the
    /// deployment (e.g. 60). None = use the built-in default (3600).
    #[serde(default)]
    pub min_staking_age_secs: Option<u64>,
    /// How many blocks back to scan on startup for jobs this miner locked but
    /// never fulfilled (crash/restart recovery). None = built-in default (108,150: a lock can
    /// live a 7-day window plus grace, a downtime extension and pause credit — keep it that long).
    #[serde(default)]
    pub recovery_lookback_blocks: Option<u64>,
    /// How many blocks to rewind the job monitor's start block, so it also claims
    /// jobs that were already Open when the miner started (not just newly-submitted
    /// ones). None = built-in default: back to `scan_from_block` (5000 on a chain with no known
    /// deployment); 0 = forward-only.
    #[serde(default)]
    pub monitor_backfill_blocks: Option<u64>,
    /// Job monitor poll interval in seconds. Lower = jobs seen sooner (better in a
    /// competitive market); higher = fewer eth_blockNumber/eth_getLogs calls (good
    /// on a rate-limited RPC). None = built-in default (10, ~chain block time).
    #[serde(default)]
    pub monitor_poll_secs: Option<u64>,
    /// Minimum gas limit for `fulfillJob` txs. zkminer always sends at least the repo's formula
    /// (`4.6M + callbackGasLimit + 250k + 16 x calldata + 8 x journal + 500k`, ~5.6M for a 1 KB
    /// adapter job): the router refuses to start verifying below `4.6M + callbackGasLimit` and
    /// reverts `InsufficientGasForFullSettlement()`. 5,000,000 is TOO LOW. None = built-in default
    /// (10,000,000, above every valid job's formula).
    #[serde(default)]
    pub fulfill_gas_limit: Option<u64>,
    /// Key-wide ceiling (gwei) for the fulfil and release fee ladders (handoff §10): an unmined
    /// fulfil is re-published at the same nonce with both fees raised >= 12.5% up to this ceiling.
    /// Size it from what the cheapest lock this key takes is worth: `(price + lockedCollateral) x
    /// ETH-per-HEMI / ~643k gas` (about 3.6-4.7 gwei for 15-50 HEMI jobs at 50,000 HEMI/ETH). A low
    /// ceiling makes holding our fulfil out of blocks cheap; fund the key for `fulfil gas limit x
    /// ceiling` per pending fulfil. None = built-in default (4 gwei).
    #[serde(default)]
    pub fee_ceiling_gwei: Option<f64>,
    /// First block of every HemiProve log scan (job discovery, lock recovery, descriptor
    /// reconstruction): the deployment's `fromBlock`. None = the known deployment's value for this
    /// chain (743111: 7226094), else no floor.
    #[serde(default)]
    pub scan_from_block: Option<u64>,
    /// Whether to claim journal-bound jobs: a non-zero `expectedJournalHash` (FULL or FIELDS
    /// binding), which is every open-market job. A fulfil whose journal does not satisfy the binding
    /// reverts `JournalMismatch` after the lock, so such a job is claimed only when the journal its
    /// (program, input) measured satisfies the binding, and the proof's journal is checked again
    /// before the fulfil. None = built-in default (TRUE). `false` claims only NONE jobs assigned to
    /// this prover.
    #[serde(default)]
    pub claim_predicate_jobs: Option<bool>,
    /// Ceiling on JSON-RPC requests per second to `rpc_url`, so a burst cannot trip the endpoint's
    /// per-IP rate limit. None = built-in default: 4, or 1 for `run --watch-only`, which shares the
    /// limit with any miner on the same host and IP.
    #[serde(default)]
    pub max_requests_per_sec: Option<u32>,
    /// Share of the chain limiter that pre-claim reads may use (witness plan §17.6). None = 0.25.
    #[serde(default)]
    pub preclaim_read_share: Option<f64>,
}

fn default_rpc_url() -> String {
    "https://rpc.hemi.network".to_string()
}

fn default_chain_id() -> u64 {
    43111 // Hemi mainnet
}

impl Default for ChainConfig {
    fn default() -> Self {
        Self {
            rpc_url: default_rpc_url(),
            ws_url: None,
            chain_id: default_chain_id(),
            gas_price_gwei: None,
            min_staking_age_secs: None,
            recovery_lookback_blocks: None,
            monitor_backfill_blocks: None,
            monitor_poll_secs: None,
            fulfill_gas_limit: None,
            fee_ceiling_gwei: None,
            scan_from_block: None,
            claim_predicate_jobs: None,
            max_requests_per_sec: None,
            preclaim_read_share: None,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ContractAddresses {
    /// HemiProve router proxy (diamond) — all Core/Fulfill/Aux calls target this.
    #[serde(default)]
    pub hemi_prove: String,
    /// HemiProveStaking contract address.
    #[serde(default)]
    pub hemi_prove_staking: String,
    /// HemiProveRegistry contract address.
    #[serde(default)]
    pub hemi_prove_registry: String,
    /// HEMI token (ERC20) address.
    #[serde(default)]
    pub hemi_token: String,
    /// ProgramRegistry contract address: where programs' ELF sources are read from. Unset: the known
    /// deployment's for the chain. On a known chain it must be the live one.
    #[serde(default)]
    pub program_registry: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletConfig {
    /// Key source: "env", "keystore", "file"
    #[serde(default = "default_key_source")]
    pub key_source: String,
    /// Environment variable name for private key (when key_source = "env")
    #[serde(default = "default_key_env_var")]
    pub key_env_var: String,
    /// Path to keystore file (when key_source = "keystore")
    #[serde(default)]
    pub keystore_path: Option<String>,
    /// Path to plaintext key file (when key_source = "file")
    #[serde(default)]
    pub key_file_path: Option<String>,
}

fn default_key_source() -> String {
    "env".to_string()
}

fn default_key_env_var() -> String {
    "ZKMINER_PRIVATE_KEY".to_string()
}

impl Default for WalletConfig {
    fn default() -> Self {
        Self {
            key_source: default_key_source(),
            key_env_var: default_key_env_var(),
            keystore_path: None,
            key_file_path: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProverConfig {
    #[serde(default = "default_max_concurrent")]
    pub max_concurrent_proofs: usize,
    /// Seconds of work to keep queued AHEAD on each GPU, so a finishing device always has its
    /// next job already locked instead of idling for a claim round-trip (~15-30s).
    ///
    /// `0` (the default) disables look-ahead entirely and preserves the historical behaviour
    /// exactly: one job per GPU, claimed only when that GPU is idle.
    ///
    /// This does NOT override deadline safety. A queued job is admitted only if it can finish
    /// from the start time it would actually get — `max_concurrent_proofs` still caps how many
    /// proofs run at once, and collateral still gates every claim. Raising it past a few
    /// minutes mostly locks more collateral for little gain, since the idle window it removes
    /// is bounded by the claim round-trip.
    #[serde(default)]
    pub queue_horizon_secs: u64,
    /// Minimum acceptable profit rate in HEMI/day.
    /// A proof taking T hours must net at least (threshold × T/24) HEMI after electricity costs.
    #[serde(default = "default_min_profit")]
    pub min_profit_threshold: f64,
    /// Multiplier for estimated proving time to set safety margin before deadline.
    #[serde(default = "default_deadline_safety")]
    pub deadline_safety_margin: f64,
    /// "auto", "aggressive", "conservative"
    #[serde(default = "default_strategy")]
    pub strategy: String,
    /// Electricity cost in USD/kWh for cost modeling.
    #[serde(default = "default_electricity_cost")]
    pub electricity_cost_kwh: f64,
    /// Base system power overhead in watts (motherboard, fans, drives, PSU losses) —
    /// everything EXCEPT the CPU package and the GPUs, which are measured.
    ///
    /// Added to measured CPU and GPU power by
    /// `zkminer_strategy::cost_model::system_watts_for_suite`. It was not added by anything
    /// until then: the production path passed this value into `CostParams` as the whole
    /// machine's draw, so a two-GPU box costed its electricity at 75 W against ~872 W
    /// measured at the wall. Raise it if your board/drives/PSU losses exceed ~75 W; do NOT
    /// raise it to cover the GPUs.
    #[serde(default = "default_system_watts")]
    pub system_power_watts: f64,
    /// Token price in USD for profitability calculation.
    #[serde(default = "default_token_price")]
    pub token_price_usd: f64,
    /// Estimated gas cost in USD for claim + fulfill transactions.
    #[serde(default = "default_gas_cost")]
    pub gas_cost_usd: f64,
    /// Maximum time (seconds) for a single proof. Worker is killed after this.
    /// 0 = no timeout (not recommended for production).
    #[serde(default = "default_proving_timeout")]
    pub proving_timeout_secs: u64,
    /// Maximum time (seconds) for the entire benchmark suite on one worker.
    /// Worker is killed after this. 0 = no timeout.
    #[serde(default = "default_benchmark_timeout")]
    pub benchmark_timeout_secs: u64,
    /// Additional directories to search for prover worker binaries.
    #[serde(default)]
    pub worker_search_paths: Vec<String>,
    /// Explicit paths to worker binaries, keyed by backend name.
    /// e.g. { "risc0" = "/opt/zkminer/bin/zkminer-prove-risc0" }
    #[serde(default)]
    pub worker_binaries: HashMap<String, String>,
    /// Override for the RISC Zero groth16 seal selector (4-byte hex, e.g.
    /// "0xe71e6620"). The miner prepends this to each seal for on-chain
    /// verification; it must equal the target chain's verifier `SELECTOR` for
    /// the risc0 version in use. Defaults to the risc0 v3.1.x value when unset.
    #[serde(default)]
    pub risc0_groth16_selector: Option<String>,
    /// The segment size (po2) a card measures and proves risc0 jobs at, keyed by its benchmark device
    /// id (`gpu0`, `gpu1`, … for NVIDIA cards, `gpu-rocm0`, … for AMD; the log lists them), e.g.
    /// `{ gpu1 = 19 }`: for a card the default (20, or nothing under 14 GiB of VRAM) or its
    /// calibration doesn't suit. Held to 16..=22. The Settings screen's Advanced rows override it for
    /// the session. Not written when empty, so `zkminer init` leaves no empty table at the end of the
    /// file for a later line to land in.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub risc0_job_po2: HashMap<String, u8>,
    /// If true, the brain will proceed with a synthetic conservative
    /// benchmark profile when no cached benchmark is available, rather
    /// than waiting for the user to run `[b]` on the Benchmark screen.
    /// Intended for operators who know their hardware and want the brain
    /// to start claiming jobs immediately on fresh installs.
    #[serde(default = "default_skip_benchmark_gate")]
    pub skip_benchmark_gate: bool,
}

fn default_skip_benchmark_gate() -> bool {
    true
}

fn default_max_concurrent() -> usize {
    // 0 = auto: resolved at startup to the number of detected proving GPUs (one job
    // per GPU). A positive value pins the concurrency limit explicitly.
    0
}
fn default_min_profit() -> f64 {
    10.0 // 10 HEMI/day
}
fn default_deadline_safety() -> f64 {
    1.5
}
fn default_strategy() -> String {
    "auto".to_string()
}
fn default_electricity_cost() -> f64 {
    0.12
}
fn default_system_watts() -> f64 {
    // Board, fans, drives and PSU conversion loss on a desktop/workstation, with CPU and
    // GPU excluded because those are measured and added separately. The remaining
    // inaccuracy is that PSU loss scales with load rather than being fixed, which this
    // understates at full tilt — within tens of watts, not the order of magnitude that the
    // missing CPU+GPU terms cost.
    75.0
}
fn default_proving_timeout() -> u64 {
    // Watchdog cap for a WEDGED GPU (kernel that never returns). 10 min comfortably
    // covers the slowest realistic single proof on these cards (~150M cycles at
    // ~1.25M cps ≈ 2 min + Groth16), while catching a wedge far sooner than the old
    // 30 min. Committed-cycle jobs are scaled tighter still (see run.rs). Lower this
    // for a small-job-only workload if you want wedges caught faster.
    600
}
fn default_benchmark_timeout() -> u64 {
    // The suite plus the zkOP/s proofs is about 10 minutes on an Arc A770's RISC Zero worker.
    BENCHMARK_TIMEOUT_DEFAULT_SECS
}

const BENCHMARK_TIMEOUT_DEFAULT_SECS: u64 = 1800;
/// The default before the zkOP/s proofs were added, which `zkminer init` wrote into config files.
const BENCHMARK_TIMEOUT_OLD_DEFAULT_SECS: u64 = 600;

impl ProverConfig {
    /// The per-worker benchmark deadline, or `None` for no deadline.
    ///
    /// A config still carrying the old default gets the new one: that value was never a choice, and
    /// the worker would be killed partway through scoring a slower card.
    pub fn benchmark_timeout(&self) -> Option<std::time::Duration> {
        match self.benchmark_timeout_secs {
            0 => None,
            BENCHMARK_TIMEOUT_OLD_DEFAULT_SECS => Some(std::time::Duration::from_secs(
                BENCHMARK_TIMEOUT_DEFAULT_SECS,
            )),
            secs => Some(std::time::Duration::from_secs(secs)),
        }
    }
}
fn default_token_price() -> f64 {
    0.80
}
fn default_gas_cost() -> f64 {
    0.01 // ~0.0005 ETH at ~$20/ETH (Hemi gas is cheap)
}

impl Default for ProverConfig {
    fn default() -> Self {
        Self {
            max_concurrent_proofs: default_max_concurrent(),
            queue_horizon_secs: 0, // look-ahead off by default: preserves one-job-per-GPU
            min_profit_threshold: default_min_profit(),
            deadline_safety_margin: default_deadline_safety(),
            strategy: default_strategy(),
            electricity_cost_kwh: default_electricity_cost(),
            system_power_watts: default_system_watts(),
            token_price_usd: default_token_price(),
            gas_cost_usd: default_gas_cost(),
            proving_timeout_secs: default_proving_timeout(),
            benchmark_timeout_secs: default_benchmark_timeout(),
            worker_search_paths: Vec::new(),
            worker_binaries: HashMap::new(),
            risc0_groth16_selector: None,
            risc0_job_po2: HashMap::new(),
            skip_benchmark_gate: default_skip_benchmark_gate(),
        }
    }
}

impl ZkMinerConfig {
    /// Returns the default config directory: `~/.zkminer/`
    pub fn default_dir() -> PathBuf {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".zkminer")
    }

    /// Returns the default config file path: `~/.zkminer/config.toml`
    pub fn default_path() -> PathBuf {
        Self::default_dir().join("config.toml")
    }

    /// Load config from the given path, or default path if None.
    pub fn load(path: Option<&Path>) -> Result<Self> {
        let path = path.map(PathBuf::from).unwrap_or_else(Self::default_path);

        if !path.exists() {
            tracing::info!(
                "Config file not found at {}, using defaults",
                path.display()
            );
            return Ok(Self::default());
        }

        let content = std::fs::read_to_string(&path)
            .with_context(|| format!("Failed to read config from {}", path.display()))?;

        toml::from_str(&content)
            .with_context(|| format!("Failed to parse config from {}", path.display()))
    }

    /// Save config to the given path, creating directories as needed.
    pub fn save(&self, path: Option<&Path>) -> Result<()> {
        let path = path.map(PathBuf::from).unwrap_or_else(Self::default_path);

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).with_context(|| {
                format!("Failed to create config directory {}", parent.display())
            })?;
        }

        let content = toml::to_string_pretty(self).context("Failed to serialize config")?;

        std::fs::write(&path, content)
            .with_context(|| format!("Failed to write config to {}", path.display()))?;

        // Restrict config file permissions on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(&path, perms).ok();
        }

        Ok(())
    }

    /// The network guard's mode for connections a requester causes: [`NetMode::DevPrivate`] only
    /// with `[dev] private_network = true` and `[dev] chain_id` equal to `[chain] chain_id`, on a
    /// chain that is not a production market. Otherwise this is [`NetMode::Public`] whatever the
    /// config says ([`Self::validate_for_chain`] refuses such a config outright; this holds even
    /// where validation was skipped).
    ///
    /// [`NetMode::DevPrivate`]: zkminer_netguard::NetMode::DevPrivate
    /// [`NetMode::Public`]: zkminer_netguard::NetMode::Public
    pub fn net_mode(&self) -> zkminer_netguard::NetMode {
        if self.dev.private_network
            && self.dev.chain_id == Some(self.chain.chain_id)
            && !is_production_chain(self.chain.chain_id)
        {
            zkminer_netguard::NetMode::DevPrivate
        } else {
            zkminer_netguard::NetMode::Public
        }
    }

    /// `[egress] deny_cidrs` and `internal_ranges`, parsed: what every requester-caused
    /// connection is refused besides the host's own facts. Host bits must be zero (`10.0.0.1/8`
    /// is an error).
    pub fn egress_deny(&self) -> Result<Vec<zkminer_netguard::Prefix>> {
        let mut deny = parse_cidrs("deny_cidrs", &self.egress.deny_cidrs)?;
        for p in self.egress_internal_ranges()?.into_iter().flatten() {
            if !deny.contains(&p) {
                deny.push(p);
            }
        }
        Ok(deny)
    }

    /// `[egress] internal_ranges`, parsed (`None` when the key is absent).
    pub fn egress_internal_ranges(&self) -> Result<Option<Vec<zkminer_netguard::Prefix>>> {
        self.egress
            .internal_ranges
            .as_ref()
            .map(|v| parse_cidrs("internal_ranges", v))
            .transpose()
    }

    /// `[egress] public_addresses`, parsed: bare addresses, each a public internet address.
    pub fn egress_public_addresses(&self) -> Result<Vec<std::net::IpAddr>> {
        self.egress
            .public_addresses
            .iter()
            .map(|s| {
                let ip: std::net::IpAddr = s.trim().parse().map_err(|_| {
                    anyhow::anyhow!("egress.public_addresses: {s:?} is not an IP address")
                })?;
                if !zkminer_netguard::is_global(ip) {
                    anyhow::bail!("egress.public_addresses: {ip} is not a public internet address");
                }
                Ok(ip)
            })
            .collect()
    }

    /// `[egress] doh_resolvers`, parsed ([`zkminer_netguard::DohServer::parse`]).
    pub fn egress_doh_resolvers(&self) -> Result<Vec<zkminer_netguard::DohServer>> {
        self.egress
            .doh_resolvers
            .iter()
            .map(|s| {
                zkminer_netguard::DohServer::parse(s)
                    .map_err(|e| anyhow::anyhow!("egress.doh_resolvers: {e}"))
            })
            .collect()
    }

    /// `[egress] nat64_prefixes`, parsed: IPv6 prefixes of an RFC 6052 length (/32, /40, /48,
    /// /56, /64, /96), host bits zero.
    pub fn egress_nat64_prefixes(&self) -> Result<Vec<zkminer_netguard::Prefix>> {
        self.egress
            .nat64_prefixes
            .iter()
            .map(|s| {
                let p = s
                    .parse::<zkminer_netguard::Prefix>()
                    .map_err(|e| anyhow::anyhow!("egress.nat64_prefixes: {e}"))?;
                zkminer_netguard::nat64::check_prefix(p)
                    .map_err(|e| anyhow::anyhow!("egress.nat64_prefixes: {e}"))
            })
            .collect()
    }

    /// The options the network guard runs with (`[egress]` `ipv6_site_prefix_len`,
    /// `ipv4_site_prefix_len`, `discover_public_addresses`, `public_addresses`,
    /// `internal_ranges`, `near_hop_limit`, `doh_resolvers`). Refuses a length or limit outside
    /// its range and a malformed or non-public entry.
    ///
    /// Also puts `[egress] nat64_prefixes` in force, process-wide
    /// ([`zkminer_netguard::nat64::set_configured`]): the network guard's address predicate reads
    /// them wherever it runs in this process, and every component that judges requester-caused
    /// connections (the ELF fetch, the witness broker's host facts) builds its options here.
    pub fn egress_facts_options(&self) -> Result<zkminer_netguard::FactsOptions> {
        let o = zkminer_netguard::FactsOptions {
            ipv6_site_prefix_len: self.egress.ipv6_site_prefix_len,
            ipv4_site_prefix_len: self.egress.ipv4_site_prefix_len,
            discover_public_addresses: self.egress.discover_public_addresses,
            public_addresses: self.egress_public_addresses()?,
            internal_ranges: self.egress_internal_ranges()?,
            near_hop_limit: self.egress.near_hop_limit,
            doh_resolvers: self.egress_doh_resolvers()?,
        };
        o.validate()
            .map_err(|e| anyhow::anyhow!("egress.{e}"))?;
        zkminer_netguard::nat64::set_configured(&self.egress_nat64_prefixes()?)
            .map_err(|e| anyhow::anyhow!("egress.nat64_prefixes: {e}"))?;
        Ok(o)
    }

    /// [`DEV_MODE_BANNER`] while developer mode is in force, else `None`.
    pub fn dev_mode_banner(&self) -> Option<&'static str> {
        (self.net_mode() == zkminer_netguard::NetMode::DevPrivate).then_some(DEV_MODE_BANNER)
    }

    /// Refuses `[dev] private_network` on a production chain or without a matching `[dev]
    /// chain_id`, and a malformed `[egress]` (CIDRs, addresses, resolvers, lengths and limits out
    /// of range: [`Self::egress_facts_options`], `nat64_prefixes`). What needs the host's facts
    /// (`internal_ranges` required, `public_addresses` with discovery off) is checked when the
    /// network guard starts.
    pub fn validate_network(&self) -> Result<()> {
        if self.dev.private_network && is_production_chain(self.chain.chain_id) {
            anyhow::bail!(
                "[dev] private_network = true is refused on chain {} (a production market): it lets \
                 requesters reach this host's private network. Remove it, or point the config at a \
                 test network",
                self.chain.chain_id
            );
        }
        if self.dev.private_network {
            match self.dev.chain_id {
                None => anyhow::bail!(
                    "[dev] private_network = true also needs `chain_id = {}` in [dev], naming the \
                     test network it is meant for (this config's [chain] chain_id): developer mode \
                     lets requesters reach this host's private network, so it takes effect only on \
                     the network it names",
                    self.chain.chain_id
                ),
                Some(id) if id != self.chain.chain_id => anyhow::bail!(
                    "[dev] chain_id = {id} does not match [chain] chain_id = {}: [dev] \
                     private_network = true is meant for chain {id} only. Point the config at that \
                     network, or remove [dev] private_network",
                    self.chain.chain_id
                ),
                Some(_) => {}
            }
        }
        if self.dev.da_backlog_bytes.is_some() && is_production_chain(self.chain.chain_id) {
            anyhow::bail!(
                "[dev] da_backlog_bytes is refused on chain {} (a production market): the DA \
                 backlog must be read from the chain there",
                self.chain.chain_id
            );
        }
        if self.dev.da_backlog_bytes.is_some()
            && DEPLOYED_CHAIN_IDS.contains(&self.chain.chain_id)
            && !rpc_on_loopback(&self.chain.rpc_url)
        {
            anyhow::bail!(
                "[dev] da_backlog_bytes is refused on chain {} unless [chain] rpc_url is a loopback \
                 address (a local fork): the HemiProve router there is shared, and its DA backlog \
                 must be read from the chain",
                self.chain.chain_id
            );
        }
        self.egress_deny()?;
        self.egress_facts_options()?;
        Ok(())
    }

    /// `[dev] da_backlog_bytes` for the miner's own reads (`[chain] rpc_url`): see
    /// [`Self::dev_da_backlog_bytes_for`].
    pub fn dev_da_backlog_bytes(&self) -> Option<u64> {
        self.dev_da_backlog_bytes_for(&self.chain.rpc_url)
    }

    /// `[dev] da_backlog_bytes` for backlog reads through `rpc_url`: never on a production chain,
    /// and on a chain with a HemiProve deployment only when `rpc_url` is on loopback
    /// ([`rpc_on_loopback`]); validation refuses the configurations it ignores.
    pub fn dev_da_backlog_bytes_for(&self, rpc_url: &str) -> Option<u64> {
        let id = self.chain.chain_id;
        self.dev.da_backlog_bytes.filter(|_| {
            !is_production_chain(id)
                && (!DEPLOYED_CHAIN_IDS.contains(&id) || rpc_on_loopback(rpc_url))
        })
    }

    /// Validate that required fields are set for production use.
    pub fn validate_for_chain(&self) -> Result<()> {
        // First, so no other error can hide it.
        self.validate_network()?;
        // `gas_price_gwei` reaches the client as `(g * 1e9).round() as u128`, which saturates
        // a negative or NaN to 0 — and `base_fees` short-circuits `Some(0)` to `(0, 0)` BEFORE
        // the floor. Every escalation path is gated on `base_max_fee > 0`, so a zero
        // here silently disables the whole fee ladder AND the per-nonce ratchet: a stuck tx can
        // then never clear a node's +12.5% replacement threshold and strands. Reject it here
        // rather than let it degrade a live money path in silence.
        if let Some(g) = self.chain.gas_price_gwei {
            // Mirror the CLIENT's conversion exactly — `(g * 1e9).round() as u128` — rather
            // than testing `g > 0.0`. Any `0 < g < 5e-10` is positive and finite yet rounds to
            // ZERO wei, so the naive check passed it straight through to the failure this
            // validation exists to prevent.
            let wei = (g * 1e9).round();
            if !g.is_finite() || g <= 0.0 || wei < 1.0 {
                anyhow::bail!(
                    "chain.gas_price_gwei must be a positive finite number of at least 1 wei \
                     (got {g}, which rounds to {} wei); omit it to use automatic EIP-1559 \
                     estimation",
                    wei.max(0.0) as u128
                );
            }
        }
        if let Some(c) = self.chain.fee_ceiling_gwei {
            if !c.is_finite() || !(0.01..=10_000.0).contains(&c) {
                anyhow::bail!(
                    "chain.fee_ceiling_gwei must be between 0.01 and 10000 gwei (got {c}); omit it \
                     for the built-in default"
                );
            }
        }
        if self.contracts.hemi_prove.is_empty() {
            anyhow::bail!(
                "hemi_prove address not set. Run `zkminer init` and edit ~/.zkminer/config.toml"
            );
        }
        if self.contracts.hemi_token.is_empty() {
            anyhow::bail!(
                "hemi_token address not set. Run `zkminer init` and edit ~/.zkminer/config.toml"
            );
        }
        if self.prover.token_price_usd <= 0.0 {
            anyhow::bail!(
                "token_price_usd must be positive (used as divisor in profitability calculation)"
            );
        }
        // max_concurrent_proofs == 0 is valid and means "auto" (resolved at startup
        // to the detected proving-GPU count); any positive value pins it explicitly.
        Ok(())
    }
}

#[cfg(test)]
mod validation_tests {
    use super::*;

    /// A positive, finite gwei value can still round to ZERO wei.
    ///
    /// The client converts with `(g * 1e9).round() as u128`, so any `0 < g < 5e-10` becomes
    /// `Some(0)` — and `base_fees` short-circuits that to `(0, 0)` BEFORE its own floor,
    /// disabling every `base_max_fee > 0` escalation gate and the whole per-nonce ratchet.
    /// A bare `g > 0.0` check passes it straight through to the failure this validation
    /// exists to prevent, so the validation must mirror the client's expression.
    #[test]
    fn a_sub_wei_gas_price_is_rejected() {
        for g in [4e-10_f64, 1e-10, 1e-12] {
            let mut c = ZkMinerConfig::default();
            c.chain.gas_price_gwei = Some(g);
            let err = c
                .validate_for_chain()
                .expect_err(&format!(
                    "gas_price_gwei={g} rounds to 0 wei and must be rejected"
                ))
                .to_string();
            assert!(
                err.contains("at least 1 wei"),
                "wrong rejection reason for {g}: {err}"
            );
        }
    }

    fn parse(toml_text: &str) -> Result<ZkMinerConfig> {
        Ok(toml::from_str(toml_text)?)
    }

    #[test]
    fn dev_mode_is_off_by_default_and_unwritten() {
        let c = ZkMinerConfig::default();
        assert!(!c.dev.private_network);
        assert_eq!(c.net_mode(), zkminer_netguard::NetMode::Public);
        assert_eq!(c.dev_mode_banner(), None);
        let text = toml::to_string_pretty(&c).unwrap();
        assert!(
            !text.contains("[dev]") && !text.contains("[egress]"),
            "{text}"
        );
        let c = parse("[chain]\nchain_id = 743111\n").unwrap();
        assert_eq!(c.net_mode(), zkminer_netguard::NetMode::Public);
    }

    #[test]
    fn dev_mode_is_refused_on_mainnet() {
        for text in [
            // Explicitly mainnet, and by default (43111 is the default chain id).
            "[chain]\nchain_id = 43111\n[dev]\nprivate_network = true\n",
            "[dev]\nprivate_network = true\n",
        ] {
            let c = parse(text).unwrap();
            let err = c.validate_for_chain().expect_err(text).to_string();
            assert!(
                err.contains("private_network") && err.contains("43111"),
                "{err}"
            );
            // And even where validation is skipped, the mode stays public on mainnet.
            assert_eq!(c.net_mode(), zkminer_netguard::NetMode::Public, "{text}");
            assert_eq!(c.dev_mode_banner(), None);
        }
        assert!(is_production_chain(43111) && !is_production_chain(743111));
    }

    #[test]
    fn dev_mode_on_a_test_network_is_announced() {
        let c = parse("[chain]\nchain_id = 743111\n[dev]\nprivate_network = true\nchain_id = 743111\n")
            .unwrap();
        assert!(c.validate_network().is_ok());
        assert_eq!(c.net_mode(), zkminer_netguard::NetMode::DevPrivate);
        let banner = c.dev_mode_banner().expect("a banner");
        assert_eq!(banner, DEV_MODE_BANNER);
        assert!(banner.starts_with("DEV MODE: private network access enabled"));
        assert!(banner.contains("never run on a public market"));
        // It round-trips through the file, which is how the localnet test turns it on.
        let text = toml::to_string_pretty(&c).unwrap();
        assert!(
            text.contains("[dev]\nprivate_network = true\nchain_id = 743111"),
            "{text}"
        );
        assert_eq!(
            parse(&text).unwrap().net_mode(),
            zkminer_netguard::NetMode::DevPrivate
        );
    }

    /// Developer mode names the test network it is for: without `[dev] chain_id`, or with one
    /// that is not the config's chain, the config is refused and the mode stays public (a
    /// production deployment under a chain id zkminer does not know as one included).
    #[test]
    fn dev_mode_needs_the_chain_id_it_is_meant_for() {
        for (text, why) in [
            (
                "[chain]\nchain_id = 743111\n[dev]\nprivate_network = true\n",
                "chain_id = 743111",
            ),
            (
                "[chain]\nchain_id = 743111\n[dev]\nprivate_network = true\nchain_id = 31337\n",
                "does not match",
            ),
            (
                "[chain]\nchain_id = 999\n[dev]\nprivate_network = true\nchain_id = 743111\n",
                "does not match",
            ),
        ] {
            let c = parse(text).unwrap();
            let err = c.validate_network().expect_err(text).to_string();
            assert!(err.contains(why), "{text}: {err}");
            assert_eq!(c.net_mode(), zkminer_netguard::NetMode::Public, "{text}");
            assert_eq!(c.dev_mode_banner(), None, "{text}");
        }
        // Mainnet stays refused even when the ids agree.
        let c = parse("[chain]\nchain_id = 43111\n[dev]\nprivate_network = true\nchain_id = 43111\n")
            .unwrap();
        assert!(c.validate_network().unwrap_err().to_string().contains("43111"));
        assert_eq!(c.net_mode(), zkminer_netguard::NetMode::Public);
        // A chain id alone changes nothing.
        let c = parse("[chain]\nchain_id = 31337\n[dev]\nchain_id = 31337\n").unwrap();
        assert!(c.validate_network().is_ok());
        assert_eq!(c.net_mode(), zkminer_netguard::NetMode::Public);
        let c = parse("[chain]\nchain_id = 31337\n[dev]\nprivate_network = true\nchain_id = 31337\n")
            .unwrap();
        assert!(c.validate_network().is_ok());
        assert_eq!(c.net_mode(), zkminer_netguard::NetMode::DevPrivate);
    }

    #[test]
    fn a_fixed_da_backlog_is_a_test_network_setting() {
        let c = parse("[chain]\nchain_id = 743111\nrpc_url = \"http://127.0.0.1:8545\"\n[dev]\nda_backlog_bytes = 0\n").unwrap();
        assert!(c.validate_network().is_ok());
        assert_eq!(c.dev_da_backlog_bytes(), Some(0));
        // Alone, it does not turn on private-network access.
        assert_eq!(c.net_mode(), zkminer_netguard::NetMode::Public);
        let text = toml::to_string_pretty(&c).unwrap();
        assert!(text.contains("da_backlog_bytes = 0"), "{text}");
        for mainnet in ["[dev]\nda_backlog_bytes = 5\n", "[chain]\nchain_id = 43111\n[dev]\nda_backlog_bytes = 5\n"] {
            let c = parse(mainnet).unwrap();
            let err = c.validate_for_chain().expect_err(mainnet).to_string();
            assert!(err.contains("da_backlog_bytes"), "{err}");
            assert_eq!(c.dev_da_backlog_bytes(), None, "never honoured on mainnet");
        }
        // Unset by default, and not written.
        let c = parse("[chain]\nchain_id = 743111\n").unwrap();
        assert_eq!(c.dev_da_backlog_bytes(), None);
        assert!(!toml::to_string_pretty(&c).unwrap().contains("[dev]"));
    }

    #[test]
    fn a_fixed_da_backlog_reaches_a_deployments_chain_only_on_loopback() {
        // The real testnet (the default URL, or any public one): refused, and never honoured.
        for url in [
            "",
            "rpc_url = \"https://testnet.rpc.hemi.network/rpc\"\n",
            "rpc_url = \"http://10.0.0.5:8545\"\n",
        ] {
            let text = format!("[chain]\nchain_id = 743111\n{url}[dev]\nda_backlog_bytes = 0\n");
            let c = parse(&text).unwrap();
            let err = c.validate_network().expect_err(&text).to_string();
            assert!(err.contains("loopback"), "{err}");
            assert_eq!(c.dev_da_backlog_bytes(), None, "{text}");
        }
        // A local fork of it: honoured.
        let c = parse("[chain]\nchain_id = 743111\nrpc_url = \"http://[::1]:8545\"\n[dev]\nda_backlog_bytes = 7\n").unwrap();
        assert!(c.validate_network().is_ok());
        assert_eq!(c.dev_da_backlog_bytes(), Some(7));
        // ... but not for reads through another RPC.
        assert_eq!(
            c.dev_da_backlog_bytes_for("https://testnet.rpc.hemi.network/rpc"),
            None
        );
        assert_eq!(c.dev_da_backlog_bytes_for("http://127.0.0.1:9545"), Some(7));
        // A chain with no deployment: honoured whatever the RPC.
        let c = parse("[chain]\nchain_id = 31337\nrpc_url = \"https://rpc.example.com\"\n[dev]\nda_backlog_bytes = 3\n").unwrap();
        assert!(c.validate_network().is_ok());
        assert_eq!(c.dev_da_backlog_bytes(), Some(3));
        assert_eq!(
            c.dev_da_backlog_bytes_for("https://rpc.example.com"),
            Some(3)
        );
        // Mainnet: never, loopback or not.
        let c = parse("[chain]\nchain_id = 43111\nrpc_url = \"http://127.0.0.1:8545\"\n[dev]\nda_backlog_bytes = 3\n").unwrap();
        assert!(c.validate_network().is_err());
        assert_eq!(c.dev_da_backlog_bytes(), None);
    }

    #[test]
    fn loopback_rpcs_are_loopback_addresses_as_written() {
        for url in [
            "http://127.0.0.1:8545",
            "http://127.9.9.9",
            "https://[::1]:8545/rpc",
            "http://[::ffff:127.0.0.1]:8545",
            "http://localhost:8545",
            "http://LOCALHOST.:8545",
        ] {
            assert!(rpc_on_loopback(url), "{url}");
        }
        for url in [
            "http://10.0.0.1:8545",
            "http://127.0.0.1.nip.io:8545",
            "http://localhost.example.com",
            "http://[64:ff9b::7f00:1]:8545",
            "http://0.0.0.0:8545",
            "https://testnet.rpc.hemi.network/rpc",
            "not a url",
            "",
        ] {
            assert!(!rpc_on_loopback(url), "{url}");
        }
    }

    #[test]
    fn unknown_keys_in_dev_and_egress_are_refused() {
        for text in [
            "[dev]\nprivate_netwrok = true\n",
            "[dev]\nprivate_network = true\nallow_everything = true\n",
            "[dev]\nprivate_network = \"true\"\n",
            "[egress]\ndeny_cidr = [\"10.0.0.0/8\"]\n",
        ] {
            assert!(parse(text).is_err(), "{text}");
        }
    }

    #[test]
    fn egress_deny_cidrs_parse_strictly() {
        let c = parse(
            "[chain]\nchain_id = 743111\n[egress]\ndeny_cidrs = [\"203.0.113.7/32\", \"2001:db8::/32\", \"198.51.100.4\"]\n",
        )
        .unwrap();
        let deny = c.egress_deny().unwrap();
        assert_eq!(
            deny.iter().map(|p| p.to_string()).collect::<Vec<_>>(),
            ["203.0.113.7/32", "2001:db8::/32", "198.51.100.4/32"]
        );
        assert!(c.validate_network().is_ok());
        for bad in ["10.0.0.1/8", "not-an-ip", "10.0.0.0/33", ""] {
            let c = parse(&format!(
                "[chain]\nchain_id = 743111\n[egress]\ndeny_cidrs = [\"{bad}\"]\n"
            ))
            .unwrap();
            let err = c.validate_network().expect_err(bad).to_string();
            assert!(err.contains("egress.deny_cidrs"), "{err}");
        }
    }

    /// Review r1 (fetch F1b/F1c): `[egress] ipv6_site_prefix_len` (16..=64, default 32) and
    /// `discover_public_addresses` (default true) reach netguard's facts options, and are not
    /// written while they hold their defaults.
    #[test]
    fn egress_site_prefix_and_discovery_options() {
        let c = parse("[chain]\nchain_id = 743111\n").unwrap();
        assert_eq!(
            c.egress_facts_options().unwrap(),
            zkminer_netguard::FactsOptions::default()
        );
        assert_eq!(c.egress.ipv6_site_prefix_len, 32);
        assert_eq!(c.egress.ipv4_site_prefix_len, 16);
        assert_eq!(c.egress.near_hop_limit, 2);
        assert!(c.egress.discover_public_addresses);
        assert_eq!(c.egress.internal_ranges, None);
        let c = parse(
            "[chain]\nchain_id = 743111\n[egress]\nipv6_site_prefix_len = 56\ndiscover_public_addresses = false\n",
        )
        .unwrap();
        let o = c.egress_facts_options().unwrap();
        assert_eq!(o.ipv6_site_prefix_len, 56);
        assert!(!o.discover_public_addresses);
        assert!(c.validate_network().is_ok());
        let text = toml::to_string_pretty(&c).unwrap();
        assert!(text.contains("ipv6_site_prefix_len = 56"), "{text}");
        assert!(text.contains("discover_public_addresses = false"), "{text}");
        assert_eq!(parse(&text).unwrap().egress, c.egress);
        for (len, ok) in [(15, false), (16, true), (32, true), (48, true), (56, true), (64, true), (65, false), (0, false)] {
            let c = parse(&format!(
                "[chain]\nchain_id = 743111\n[egress]\nipv6_site_prefix_len = {len}\n"
            ))
            .unwrap();
            assert_eq!(c.validate_network().is_ok(), ok, "{len}");
            if !ok {
                let err = c.validate_network().unwrap_err().to_string();
                assert!(err.contains("ipv6_site_prefix_len"), "{err}");
            }
        }
        assert!(parse("[egress]\nipv6_site_prefix_len = 300\n").is_err());
    }

    /// The `[egress]` keys the guard's host checks run with: the IPv4 site, the stated public
    /// addresses, the internal ranges (refused like deny CIDRs; absent and empty differ), the
    /// near-hop limit and the DNS-over-HTTPS resolvers, each parsed strictly and round-tripped.
    #[test]
    fn egress_host_keys_parse_strictly() {
        let c = parse(
            "[chain]\nchain_id = 743111\n[egress]\nipv4_site_prefix_len = 12\n\
             public_addresses = [\"81.2.69.160\", \"2a02:8070::5\"]\n\
             internal_ranges = [\"128.112.0.0/16\", \"2620:c4::/32\"]\nnear_hop_limit = 3\n\
             doh_resolvers = [\"https://9.9.9.9/dns-query\", \"https://[2620:fe::fe]\"]\n",
        )
        .unwrap();
        assert!(c.validate_network().is_ok());
        let o = c.egress_facts_options().unwrap();
        assert_eq!(o.ipv4_site_prefix_len, 12);
        assert_eq!(
            o.public_addresses,
            vec![
                "81.2.69.160".parse::<std::net::IpAddr>().unwrap(),
                "2a02:8070::5".parse().unwrap()
            ]
        );
        assert_eq!(
            o.internal_ranges,
            Some(vec![
                "128.112.0.0/16".parse().unwrap(),
                "2620:c4::/32".parse().unwrap()
            ])
        );
        assert_eq!(o.near_hop_limit, 3);
        assert_eq!(o.doh_resolvers.len(), 2);
        assert_eq!(o.doh_resolvers[1].addr, "[2620:fe::fe]:443".parse().unwrap());
        // Internal ranges are refused like deny CIDRs.
        let deny = c.egress_deny().unwrap();
        assert!(deny.contains(&"128.112.0.0/16".parse().unwrap()));
        let text = toml::to_string_pretty(&c).unwrap();
        assert_eq!(parse(&text).unwrap().egress, c.egress);
        // `internal_ranges = []` is a statement; its absence is none.
        let empty = parse("[chain]\nchain_id = 743111\n[egress]\ninternal_ranges = []\n").unwrap();
        assert_eq!(empty.egress_facts_options().unwrap().internal_ranges, Some(vec![]));
        let text = toml::to_string_pretty(&empty).unwrap();
        assert!(text.contains("internal_ranges = []"), "{text}");
        for bad in [
            "ipv4_site_prefix_len = 7\n",
            "ipv4_site_prefix_len = 33\n",
            "near_hop_limit = 1\n",
            "near_hop_limit = 17\n",
            "public_addresses = [\"192.168.1.1\"]\n",
            "public_addresses = [\"81.2.69.0/24\"]\n",
            "internal_ranges = [\"10.0.0.1/8\"]\n",
            "doh_resolvers = [\"https://dns.google/dns-query\"]\n",
            "doh_resolvers = [\"https://192.168.1.1/dns-query\"]\n",
            "doh_resolvers = [\"http://9.9.9.9/dns-query\"]\n",
        ] {
            let c = parse(&format!("[chain]\nchain_id = 743111\n[egress]\n{bad}")).unwrap();
            assert!(c.validate_network().is_err(), "{bad}");
        }
    }

    /// Review r2 R2-NG-4: `[egress] nat64_prefixes` parses strictly (RFC 6052 lengths, host bits
    /// zero), round-trips, and is not written while empty.
    #[test]
    fn egress_nat64_prefixes() {
        let c = parse("[chain]\nchain_id = 743111\n").unwrap();
        assert!(c.egress_nat64_prefixes().unwrap().is_empty());
        assert!(!toml::to_string_pretty(&c)
            .unwrap()
            .contains("nat64_prefixes"));
        let c = parse(
            "[chain]\nchain_id = 743111\n[egress]\nnat64_prefixes = [\"2001:db8:64::/96\", \"2001:db8:122:344::/64\"]\n",
        )
        .unwrap();
        assert_eq!(
            c.egress_nat64_prefixes().unwrap(),
            vec![
                "2001:db8:64::/96".parse().unwrap(),
                "2001:db8:122:344::/64".parse().unwrap()
            ]
        );
        assert!(c.validate_network().is_ok());
        let text = toml::to_string_pretty(&c).unwrap();
        assert_eq!(parse(&text).unwrap().egress, c.egress);
        for bad in [
            "10.0.0.0/8",
            "2001:db8::/33",
            "2001:db8::1/96",
            "2001:db8::/128",
            "nope",
        ] {
            let c = parse(&format!(
                "[chain]\nchain_id = 743111\n[egress]\nnat64_prefixes = [\"{bad}\"]\n"
            ))
            .unwrap();
            let err = c.validate_network().expect_err(bad).to_string();
            assert!(err.contains("egress.nat64_prefixes"), "{bad}: {err}");
            assert!(c.egress_facts_options().is_err(), "{bad}");
        }
    }

    /// The guard must not reject a genuine value — it is easy to write one that rejects all.
    #[test]
    fn a_normal_gas_price_passes_the_wei_guard() {
        for g in [1.0_f64, 1.5, 0.001] {
            let mut c = ZkMinerConfig::default();
            c.chain.gas_price_gwei = Some(g);
            if let Err(e) = c.validate_for_chain() {
                assert!(
                    !e.to_string().contains("at least 1 wei"),
                    "rejected a valid {g} gwei: {e}"
                );
            }
        }
    }
}
