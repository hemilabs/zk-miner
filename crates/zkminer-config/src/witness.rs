//! The `[witness]`, `[retention]` and `[broker]` sections (docs/witness-construction-jobs.md §19).
//!
//! These sections reject unknown keys. Endpoints, provider keys, the artifact endpoint and the
//! capability configurations live in the broker's own config file (`[broker] config`), which only the
//! broker reads: the miner never holds a provider key.

use std::path::PathBuf;

use alloy_primitives::Address;
use serde::{Deserialize, Serialize};
use zkminer_witness::envelope::{
    DEFAULT_MAX_WITNESS_BYTES, HARD_MAX_BUILDER_MEMORY_BYTES, HARD_MAX_BUILDER_SECONDS, HARD_MAX_WITNESS_BYTES,
    MAX_REQUEST_BYTES,
};

/// The most estimated DA bytes an operator may allow a fulfil (the lower no-stall equilibrium cap).
pub const MAX_FULFIL_DA_CAP_BYTES: u64 = 8_500;
/// The longest an exchange rate may be configured to stay valid.
pub const MAX_RATE_VALIDITY_SECS: i64 = 31 * 24 * 3600;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SandboxModeConfig {
    /// Namespaces, a separate uid and an nftables floor (needs `zkminer witness setup` as root).
    #[default]
    System,
    /// Landlock + seccomp + delegated cgroup under the miner's uid; no kernel egress floor.
    Rootless,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum BuilderPolicy {
    #[default]
    Any,
    /// Only builder ids signed in the builder registry (Phase 2).
    Attested,
}

/// Clamps for the builder-side limits a job declares (§7.1); the code's hard ceilings still apply.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct BuilderClamps {
    pub fuel: u64,
    pub memory_bytes: u64,
    pub seconds: u32,
    pub fetches: u32,
    pub fetch_bytes: u64,
    pub request_bytes: u32,
    pub response_bytes: u32,
}

impl Default for BuilderClamps {
    fn default() -> Self {
        Self {
            fuel: 20_000_000_000,
            memory_bytes: 512 << 20,
            seconds: 120,
            fetches: 1_024,
            fetch_bytes: 256 << 20,
            request_bytes: MAX_REQUEST_BYTES,
            response_bytes: 32 << 20,
        }
    }
}

/// Clamps for probation callers (§17.3; open admission only).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ProbationClamps {
    pub max_artifact_bytes: u64,
    pub seconds: u32,
}

impl Default for ProbationClamps {
    fn default() -> Self {
        Self { max_artifact_bytes: 1 << 20, seconds: 30 }
    }
}

/// Operator unit prices for the simulation cost in the reservation (§17.2), in HEMI.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnitPrices {
    pub cpu_second_hemi: f64,
    pub gib_hour_retained_hemi: f64,
    pub provider_overage_unit_hemi: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct WitnessConfig {
    pub enabled: bool,
    pub sandbox_mode: SandboxModeConfig,
    /// Allowlisted callers (the Phase-1 admission mode).
    pub callers: Vec<Address>,
    /// Serve non-allowlisted callers through the lanes of §17.3 (Phase 2; refused for now).
    pub open_admission: bool,
    pub builders: BuilderPolicy,
    pub max_witness_bytes: u64,
    /// Host maximum for `maxGuestCycles`; derived from the enabled cards when unset.
    pub max_guest_cycles: Option<u64>,
    pub builder_clamps: BuilderClamps,
    pub probation_clamps: ProbationClamps,
    pub fulfil_da_cap_bytes: u64,
    pub da_backlog_hold_bytes: u64,
    /// HEMI per ETH, operator-set; never read from an on-chain pool (§17.2).
    pub hemi_per_eth: Option<f64>,
    /// RFC 3339 expiry of `hemi_per_eth`, at most 31 days ahead.
    pub hemi_per_eth_expires: Option<String>,
    pub k: f64,
    pub unit_prices: Option<UnitPrices>,
    pub credit_c: f64,
    pub copy_rate_threshold: f64,
    /// Non-secret; lets `artifact publish` refuse the prover key.
    pub prover_address: Option<Address>,
    /// The builder runner binary (default: `zkminer-witness-builder` next to the zkminer binary).
    pub builder_binary: Option<PathBuf>,
    /// The CPU risc0 worker used for the sandboxed execute (default: `zkminer-prove-risc0-cpu` next
    /// to the zkminer binary).
    pub execute_binary: Option<PathBuf>,
    /// Memory cap for one sandboxed execute (risc0's executor peaks at several GiB).
    pub execute_memory_bytes: u64,
}

impl Default for WitnessConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            sandbox_mode: SandboxModeConfig::System,
            callers: Vec::new(),
            open_admission: false,
            builders: BuilderPolicy::Any,
            max_witness_bytes: DEFAULT_MAX_WITNESS_BYTES,
            max_guest_cycles: None,
            builder_clamps: BuilderClamps::default(),
            probation_clamps: ProbationClamps::default(),
            fulfil_da_cap_bytes: 2_048,
            da_backlog_hold_bytes: 2_500_000,
            hemi_per_eth: None,
            hemi_per_eth_expires: None,
            k: 1.5,
            unit_prices: None,
            credit_c: 0.05,
            copy_rate_threshold: 0.5,
            prover_address: None,
            builder_binary: None,
            execute_binary: None,
            execute_memory_bytes: 10 << 30,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetentionConfig {
    /// The store root (its own filesystem recommended); created by `zkminer witness init-store`.
    pub dir: PathBuf,
    /// The store's UUID, printed by `zkminer witness init-store`. Required: a store is never created
    /// implicitly, so an unmounted disk reads as unavailable rather than empty (§15.2).
    pub store_uuid: String,
    #[serde(default = "default_quota")]
    pub quota_bytes: u64,
    #[serde(default = "default_quota_inodes")]
    pub quota_inodes: u64,
    #[serde(default = "default_per_caller")]
    pub per_caller_bytes: u64,
    /// Free space kept on the store's filesystem, in percent of its size.
    #[serde(default = "default_free_floor_pct")]
    pub free_floor_pct: f64,
    /// Segment scratch for proving (non-tmpfs, distinct from the store and the lock journal).
    pub segment_dir: PathBuf,
    #[serde(default)]
    pub require_dedicated_mount: bool,
    #[serde(default)]
    pub allow_any_filesystem: bool,
}

fn default_quota() -> u64 {
    20 << 30
}
fn default_quota_inodes() -> u64 {
    1_000_000
}
fn default_per_caller() -> u64 {
    2 << 30
}
fn default_free_floor_pct() -> f64 {
    5.0
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerSection {
    /// The broker's config file: endpoints, roles, provider keys, the artifact endpoint, egress and
    /// DNS settings. Only the broker reads it.
    pub config: PathBuf,
    /// The broker binary (default: `zkminer-witness-broker` next to the zkminer binary).
    #[serde(default)]
    pub binary: Option<PathBuf>,
    #[serde(default = "default_broker_memory")]
    pub memory_bytes: u64,
}

fn default_broker_memory() -> u64 {
    1 << 30
}

/// Validation failures of the witness sections; every problem is reported, not just the first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WitnessConfigErrors(pub Vec<String>);

impl std::fmt::Display for WitnessConfigErrors {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid witness configuration: {}", self.0.join("; "))
    }
}

impl std::error::Error for WitnessConfigErrors {}

/// Checks the witness sections. Always checks ranges; when `enabled`, also requires everything
/// witness serving needs (§10.3: a retention store, a broker, an unexpired rate, unit prices).
/// `now_unix` is the current time in seconds.
pub fn validate(
    w: &WitnessConfig,
    retention: Option<&RetentionConfig>,
    broker: Option<&BrokerSection>,
    now_unix: i64,
) -> Result<(), WitnessConfigErrors> {
    let mut e = Vec::new();
    if w.max_witness_bytes == 0 || w.max_witness_bytes > HARD_MAX_WITNESS_BYTES {
        e.push(format!("witness.max_witness_bytes must be in 1..={HARD_MAX_WITNESS_BYTES}"));
    }
    let c = &w.builder_clamps;
    if c.memory_bytes > HARD_MAX_BUILDER_MEMORY_BYTES {
        e.push(format!("witness.builder_clamps.memory_bytes above the hard ceiling {HARD_MAX_BUILDER_MEMORY_BYTES}"));
    }
    if c.seconds > HARD_MAX_BUILDER_SECONDS {
        e.push(format!("witness.builder_clamps.seconds above the hard ceiling {HARD_MAX_BUILDER_SECONDS}"));
    }
    if c.request_bytes > MAX_REQUEST_BYTES {
        e.push(format!("witness.builder_clamps.request_bytes above {MAX_REQUEST_BYTES}"));
    }
    if w.fulfil_da_cap_bytes == 0 || w.fulfil_da_cap_bytes > MAX_FULFIL_DA_CAP_BYTES {
        e.push(format!("witness.fulfil_da_cap_bytes must be in 1..={MAX_FULFIL_DA_CAP_BYTES}"));
    }
    if !(w.k.is_finite() && w.k > 0.0) {
        e.push("witness.k must be positive".into());
    }
    if !(w.credit_c.is_finite() && w.credit_c > 0.0 && w.credit_c <= 1.0) {
        e.push("witness.credit_c must be in (0, 1]".into());
    }
    if !(w.copy_rate_threshold.is_finite() && (0.0..=1.0).contains(&w.copy_rate_threshold)) {
        e.push("witness.copy_rate_threshold must be in [0, 1]".into());
    }
    if w.open_admission {
        e.push("witness.open_admission is not available in this release (allowlist mode only)".into());
    }
    if w.builders == BuilderPolicy::Attested {
        e.push("witness.builders = \"attested\" is not available in this release".into());
    }
    if let Some(r) = retention {
        if !(r.free_floor_pct.is_finite() && (0.0..100.0).contains(&r.free_floor_pct)) {
            e.push("retention.free_floor_pct must be in [0, 100)".into());
        }
        if r.per_caller_bytes > r.quota_bytes {
            e.push("retention.per_caller_bytes above retention.quota_bytes".into());
        }
        if r.segment_dir.starts_with(&r.dir) || r.dir.starts_with(&r.segment_dir) {
            e.push("retention.segment_dir must be distinct from retention.dir".into());
        }
    }
    if w.enabled {
        if retention.is_none() {
            e.push("witness serving needs a [retention] section".into());
        }
        if broker.is_none() {
            e.push("witness serving needs a [broker] section".into());
        }
        if w.callers.is_empty() {
            e.push("witness.callers is empty: allowlist mode would serve no one".into());
        }
        if w.unit_prices.is_none() {
            e.push("witness serving needs witness.unit_prices".into());
        }
        if let Some(p) = &w.unit_prices {
            for (name, v) in [
                ("cpu_second_hemi", p.cpu_second_hemi),
                ("gib_hour_retained_hemi", p.gib_hour_retained_hemi),
                ("provider_overage_unit_hemi", p.provider_overage_unit_hemi),
            ] {
                if !(v.is_finite() && v >= 0.0) {
                    e.push(format!("witness.unit_prices.{name} must be a non-negative number"));
                }
            }
        }
        match (w.hemi_per_eth, w.hemi_per_eth_expires.as_deref()) {
            (Some(r), Some(exp)) => {
                if !(r.is_finite() && r > 0.0) {
                    e.push("witness.hemi_per_eth must be positive".into());
                }
                match rate_expiry(exp) {
                    Ok(t) if t <= now_unix => e.push("witness.hemi_per_eth_expires has passed".into()),
                    Ok(t) if t - now_unix > MAX_RATE_VALIDITY_SECS => {
                        e.push("witness.hemi_per_eth_expires is more than 31 days ahead".into())
                    }
                    Ok(_) => {}
                    Err(m) => e.push(m),
                }
            }
            _ => e.push("witness serving needs witness.hemi_per_eth and witness.hemi_per_eth_expires".into()),
        }
    }
    if e.is_empty() {
        Ok(())
    } else {
        Err(WitnessConfigErrors(e))
    }
}

/// Parses `hemi_per_eth_expires` (RFC 3339) to unix seconds.
pub fn rate_expiry(s: &str) -> Result<i64, String> {
    chrono::DateTime::parse_from_rfc3339(s)
        .map(|t| t.timestamp())
        .map_err(|_| "witness.hemi_per_eth_expires is not an RFC 3339 timestamp".to_string())
}

/// One line per effective setting, for the startup log (§19). No secrets live in these sections.
pub fn effective_summary(w: &WitnessConfig, retention: Option<&RetentionConfig>, broker: Option<&BrokerSection>) -> String {
    let c = &w.builder_clamps;
    let mut s = format!(
        "witness: enabled={} sandbox_mode={:?} callers={} open_admission={} builders={:?} max_witness_bytes={} \
         max_guest_cycles={} clamps(fuel={} memory={} seconds={} fetches={} fetch_bytes={} request={} response={}) \
         fulfil_da_cap_bytes={} da_backlog_hold_bytes={} hemi_per_eth={} expires={} k={} credit_c={} \
         copy_rate_threshold={} execute_memory_bytes={}",
        w.enabled,
        w.sandbox_mode,
        w.callers.len(),
        w.open_admission,
        w.builders,
        w.max_witness_bytes,
        w.max_guest_cycles.map_or("host-derived".to_string(), |v| v.to_string()),
        c.fuel,
        c.memory_bytes,
        c.seconds,
        c.fetches,
        c.fetch_bytes,
        c.request_bytes,
        c.response_bytes,
        w.fulfil_da_cap_bytes,
        w.da_backlog_hold_bytes,
        w.hemi_per_eth.map_or("unset".to_string(), |v| v.to_string()),
        w.hemi_per_eth_expires.as_deref().unwrap_or("unset"),
        w.k,
        w.credit_c,
        w.copy_rate_threshold,
        w.execute_memory_bytes,
    );
    if let Some(r) = retention {
        s.push_str(&format!(
            "; retention: dir={} store_uuid={} quota_bytes={} quota_inodes={} per_caller_bytes={} free_floor_pct={} \
             segment_dir={} require_dedicated_mount={} allow_any_filesystem={}",
            r.dir.display(),
            r.store_uuid,
            r.quota_bytes,
            r.quota_inodes,
            r.per_caller_bytes,
            r.free_floor_pct,
            r.segment_dir.display(),
            r.require_dedicated_mount,
            r.allow_any_filesystem
        ));
    }
    if let Some(b) = broker {
        s.push_str(&format!("; broker: config={} memory_bytes={}", b.config.display(), b.memory_bytes));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_800_000_000;

    fn enabled() -> (WitnessConfig, RetentionConfig, BrokerSection) {
        let w = WitnessConfig {
            enabled: true,
            callers: vec![Address::repeat_byte(1)],
            hemi_per_eth: Some(30_000.0),
            hemi_per_eth_expires: Some(
                chrono::DateTime::from_timestamp(NOW + 7 * 86_400, 0).unwrap().to_rfc3339(),
            ),
            unit_prices: Some(UnitPrices {
                cpu_second_hemi: 0.001,
                gib_hour_retained_hemi: 0.01,
                provider_overage_unit_hemi: 0.0001,
            }),
            ..Default::default()
        };
        let r = RetentionConfig {
            dir: "/srv/retention".into(),
            store_uuid: "00000000-0000-0000-0000-000000000000".into(),
            quota_bytes: default_quota(),
            quota_inodes: default_quota_inodes(),
            per_caller_bytes: default_per_caller(),
            free_floor_pct: 5.0,
            segment_dir: "/srv/segments".into(),
            require_dedicated_mount: false,
            allow_any_filesystem: false,
        };
        let b = BrokerSection { config: "/etc/zkminer/broker.toml".into(), binary: None, memory_bytes: 1 << 30 };
        (w, r, b)
    }

    #[test]
    fn defaults_are_disabled_and_valid() {
        let w = WitnessConfig::default();
        assert!(!w.enabled);
        assert_eq!(w.max_witness_bytes, 32 << 20);
        assert_eq!(validate(&w, None, None, NOW), Ok(()));
    }

    #[test]
    fn enabled_needs_everything() {
        let (w, r, b) = enabled();
        assert_eq!(validate(&w, Some(&r), Some(&b), NOW), Ok(()));
        let errs = validate(&WitnessConfig { enabled: true, ..Default::default() }, None, None, NOW).unwrap_err();
        for needle in ["[retention]", "[broker]", "callers", "unit_prices", "hemi_per_eth"] {
            assert!(errs.0.iter().any(|m| m.contains(needle)), "{needle}: {errs}");
        }
    }

    #[test]
    fn rate_expiry_bounds() {
        let (mut w, r, b) = enabled();
        w.hemi_per_eth_expires = Some(chrono::DateTime::from_timestamp(NOW - 1, 0).unwrap().to_rfc3339());
        assert!(validate(&w, Some(&r), Some(&b), NOW).unwrap_err().to_string().contains("passed"));
        w.hemi_per_eth_expires = Some(chrono::DateTime::from_timestamp(NOW + 32 * 86_400, 0).unwrap().to_rfc3339());
        assert!(validate(&w, Some(&r), Some(&b), NOW).unwrap_err().to_string().contains("31 days"));
        w.hemi_per_eth_expires = Some("next tuesday".into());
        assert!(validate(&w, Some(&r), Some(&b), NOW).unwrap_err().to_string().contains("RFC 3339"));
    }

    #[test]
    fn ranges_and_phase_2_options_are_refused() {
        let (mut w, mut r, b) = enabled();
        w.fulfil_da_cap_bytes = 9_000;
        w.max_witness_bytes = HARD_MAX_WITNESS_BYTES + 1;
        w.builder_clamps.seconds = 301;
        w.open_admission = true;
        w.builders = BuilderPolicy::Attested;
        r.segment_dir = "/srv/retention/segments".into();
        let errs = validate(&w, Some(&r), Some(&b), NOW).unwrap_err();
        assert_eq!(errs.0.len(), 6, "{errs}");
    }

    #[test]
    fn unknown_keys_are_rejected() {
        let ok: Result<WitnessConfig, _> = toml::from_str("enabled = false\nsandbox_mode = \"rootless\"\n");
        assert_eq!(ok.unwrap().sandbox_mode, SandboxModeConfig::Rootless);
        let bad: Result<WitnessConfig, _> = toml::from_str("enabled = false\nenable = true\n");
        assert!(bad.is_err());
        let bad: Result<WitnessConfig, _> = toml::from_str("[builder_clamps]\nfuels = 1\n");
        assert!(bad.is_err());
        let bad: Result<RetentionConfig, _> =
            toml::from_str("dir = \"/a\"\nstore_uuid = \"x\"\nsegment_dir = \"/b\"\nquota = 1\n");
        assert!(bad.is_err());
    }

    #[test]
    fn summary_names_every_section() {
        let (w, r, b) = enabled();
        let s = effective_summary(&w, Some(&r), Some(&b));
        assert!(s.contains("enabled=true") && s.contains("retention: dir=/srv/retention") && s.contains("broker: config="));
    }
}
