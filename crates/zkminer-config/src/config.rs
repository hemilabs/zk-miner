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
    /// never fulfilled (crash/restart recovery). None = built-in default (50000).
    #[serde(default)]
    pub recovery_lookback_blocks: Option<u64>,
    /// How many blocks to rewind the job monitor's start block, so it also claims
    /// jobs that were already Open when the miner started (not just newly-submitted
    /// ones). None = built-in default (5000); 0 = forward-only.
    #[serde(default)]
    pub monitor_backfill_blocks: Option<u64>,
    /// Job monitor poll interval in seconds. Lower = jobs seen sooner (better in a
    /// competitive market); higher = fewer eth_blockNumber/eth_getLogs calls (good
    /// on a rate-limited RPC). None = built-in default (10, ~chain block time).
    #[serde(default)]
    pub monitor_poll_secs: Option<u64>,
    /// Explicit gas limit for `fulfillJob` txs. The router's settlement-gas
    /// preflight (~4.6M) reverts `InsufficientGasForFullSettlement()` if the tx
    /// is under-provisioned, and eth_estimateGas under-provisions it. None =
    /// built-in default (5_000_000). Bump for verifier-heavy proof systems.
    #[serde(default)]
    pub fulfill_gas_limit: Option<u64>,
    /// Whether to claim jobs that carry a non-zero `expectedJournalHash`
    /// (Phase-2 "journal predicate"). Fulfilling such a job with a proof whose
    /// public values don't satisfy the predicate reverts `JournalMismatch`
    /// AFTER the lock — risking a collateral slash on timeout — because zkminer
    /// does not yet simulate the predicate before claiming. None = built-in
    /// default (TRUE: claim them, for testnet testing). Set `false` to skip
    /// predicate jobs entirely once you've decided the final policy.
    #[serde(default)]
    pub claim_predicate_jobs: Option<bool>,
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
            claim_predicate_jobs: None,
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
    /// ProgramRegistry contract address (advisory ELF/program metadata).
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
    /// Base system power overhead in watts (motherboard, fans, drives, PSU losses).
    /// Added to measured CPU and GPU power for cost estimation.
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
    /// "0x73c457ba"). The miner prepends this to each seal for on-chain
    /// verification; it must equal the target chain's verifier `SELECTOR` for
    /// the risc0 version in use. Defaults to the risc0 v3.0.x value when unset.
    #[serde(default)]
    pub risc0_groth16_selector: Option<String>,
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
    600 // 10 minutes
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
        let path = path
            .map(PathBuf::from)
            .unwrap_or_else(Self::default_path);

        if !path.exists() {
            tracing::info!("Config file not found at {}, using defaults", path.display());
            return Ok(Self::default());
        }

        let content = std::fs::read_to_string(&path)
            .with_context(|| format!("Failed to read config from {}", path.display()))?;

        toml::from_str(&content)
            .with_context(|| format!("Failed to parse config from {}", path.display()))
    }

    /// Save config to the given path, creating directories as needed.
    pub fn save(&self, path: Option<&Path>) -> Result<()> {
        let path = path
            .map(PathBuf::from)
            .unwrap_or_else(Self::default_path);

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create config directory {}", parent.display()))?;
        }

        let content = toml::to_string_pretty(self)
            .context("Failed to serialize config")?;

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

    /// Validate that required fields are set for production use.
    pub fn validate_for_chain(&self) -> Result<()> {
        // `gas_price_gwei` reaches the client as `(g * 1e9).round() as u128`, which saturates
        // a negative or NaN to 0 — and `base_fees` short-circuits `Some(0)` to `(0, 0)` BEFORE
        // the [H2(c)] floor. Every escalation path is gated on `base_max_fee > 0`, so a zero
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
            anyhow::bail!("token_price_usd must be positive (used as divisor in profitability calculation)");
        }
        // max_concurrent_proofs == 0 is valid and means "auto" (resolved at startup
        // to the detected proving-GPU count); any positive value pins it explicitly.
        Ok(())
    }
}

#[cfg(test)]
mod validation_tests {
    use super::*;

    /// [cheap-5 / round-1 LOW-1] A positive, finite gwei value can still round to ZERO wei.
    ///
    /// The client converts with `(g * 1e9).round() as u128`, so any `0 < g < 5e-10` becomes
    /// `Some(0)` — and `base_fees` short-circuits that to `(0, 0)` BEFORE its own floor,
    /// disabling every `base_max_fee > 0` escalation gate and the whole per-nonce ratchet.
    /// A bare `g > 0.0` check passed it straight through to the failure this validation
    /// exists to prevent, so the validation must mirror the client's expression.
    #[test]
    fn a_sub_wei_gas_price_is_rejected() {
        for g in [4e-10_f64, 1e-10, 1e-12] {
            let mut c = ZkMinerConfig::default();
            c.chain.gas_price_gwei = Some(g);
            let err = c
                .validate_for_chain()
                .expect_err(&format!("gas_price_gwei={g} rounds to 0 wei and must be rejected"))
                .to_string();
            assert!(err.contains("at least 1 wei"), "wrong rejection reason for {g}: {err}");
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
