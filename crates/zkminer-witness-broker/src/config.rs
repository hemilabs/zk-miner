//! The broker's configuration (plan §11.1, §19): TOML with unknown keys refused in every table, and
//! provider keys read from files only (never the environment or argv).
//!
//! ```toml
//! # The miner's `chain.rpc_url` host (or the URL itself): an endpoint on this host is refused (§11.1).
//! chain_rpc_host = "rpc.hemi.network"
//! spool_dir = "/var/lib/zkminer-broker/spool"   # absolute; blob/v1 bodies are spooled here
//! spool_quota_bytes = 1073741824                 # all spooled bodies at once
//!
//! [budget]
//! inflight_bytes = 268435456   # the global in-flight byte budget
//! held_lock_share = 0.25       # the share of it (and of each endpoint's concurrency) reserved for held locks
//!
//! [cache]
//! rpc_max_bytes = 67108864
//! rpc_max_entries = 65536
//! artifact_max_bytes = 268435456
//! artifact_max_entries = 256
//! bad_manifest_max_entries = 65536
//!
//! [egress]
//! deny_cidrs = ["203.0.113.7/32"]   # the host's and the fleet's public and NAT addresses
//!
//! [dns]
//! servers = ["9.9.9.9", "[2620:fe::fe]:53"]   # default: the nameservers of /etc/resolv.conf
//! reresolve_secs = 300                         # how long a host name's answer is pinned
//!
//! [timeouts]
//! connect_secs = 5
//! request_secs = 30
//! fetch_secs = 60
//! partial_frame_secs = 10
//! artifact_fetch_secs = 300
//! charge_decision_secs = 30
//!
//! [[evm_rpc]]
//! alias = "base-own"
//! url = "https://base.example.net/v2/{key}"     # the key is substituted into the path...
//! chain_id = 8453
//! archive = true
//! max_proof_age = 100000
//! method_sets = ["state-read"]
//! key_file = "/etc/zkminer-broker/base.key"
//! # key_header = "x-api-key"                    # ...or sent in this header instead
//! cidrs = ["198.51.100.0/24"]                   # optional: the role entry (default: below)
//! max_concurrency = 8
//! max_requests_per_sec = 50                     # optional pacing
//! max_units_per_minute = 6000                   # optional operator budget (status 2 when spent)
//!
//! [[blob_mirror]]
//! alias = "mirror-a"
//! url_template = "https://mirror.example/blobs/{sha256}"
//!
//! [artifacts]
//! alias = "hemi-own"
//! url = "http://10.0.0.5:8545"
//! chain_id = 743111
//! max_requests_per_sec = 2
//! max_builder_bytes = 4194304
//! cidrs = ["10.0.0.5/32"]
//!
//! [artifacts.mirror]
//! alias = "artifact-mirror"
//! url_template = "https://mirror.example/artifacts/{type}/{id}"
//! ```
//!
//! # Role entries: IP literals, `cidrs` and host names
//!
//! Each endpoint's role entry (the addresses the network floor admits for it, plan §14.2) is, in
//! order of precedence:
//!
//! 1. its explicit `cidrs`: the operator's word, private addresses included. Whatever a host name
//!    resolves to is used only if it falls inside them;
//! 2. the IP literal of its URL (a host route);
//! 3. otherwise, what its host name resolves to — **only the global addresses** outside the deny
//!    CIDRs, the connected prefixes and the host's own addresses. A DNS answer is not the operator's
//!    word (a split-horizon zone, a stale record or a spoofed answer can name anything), so a local
//!    or LAN node (loopback, RFC 1918, ULA, link-local, a neighbour on a connected prefix) is
//!    configured by IP literal or explicit `cidrs`, never by name alone. Names resolve through the
//!    broker's own stub resolver ([`crate::dns`]: `[dns] servers`, never `/etc/hosts`), at startup
//!    and again every `reresolve_secs`; each answer replaces the pinned addresses.
//!
//! The self-test counts only `cidrs` and IP literals as configured, and fails when a role prefix
//! that is not a host route (/32, /128) covers loopback, the metadata service, an RFC 1918 probe,
//! one of the host's own addresses or a connected prefix: configure local nodes as host routes.
//!
//! A key travels only over `https`, or over `http` to an IP literal that is loopback or inside the
//! endpoint's own `cidrs` (a node on the operator's own wire).

use std::collections::{BTreeSet, HashMap, HashSet};
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use reqwest::header::{HeaderName, HeaderValue};
use serde::Deserialize;
use url::Url;
use zeroize::Zeroizing;
use zkminer_witness::envelope::MethodSet;

use crate::egress::{Prefix, Role};

pub const MAX_CONFIG_FILE_BYTES: u64 = 1 << 20;
pub const MAX_KEY_BYTES: u64 = 4096;
const MAX_ALIAS_BYTES: usize = 64;

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("reading {path}: {source}")]
    Io { path: PathBuf, source: std::io::Error },
    #[error("config does not parse: {0}")]
    Parse(String),
    #[error("{0}")]
    Invalid(String),
}

fn invalid<T>(msg: impl Into<String>) -> Result<T, ConfigError> {
    Err(ConfigError::Invalid(msg.into()))
}

// ---------------------------------------------------------------------------------------------
// The file schema.

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileConfig {
    chain_rpc_host: String,
    spool_dir: PathBuf,
    #[serde(default = "d_spool_quota")]
    spool_quota_bytes: u64,
    #[serde(default)]
    budget: BudgetConfig,
    #[serde(default)]
    cache: CacheConfig,
    #[serde(default)]
    egress: EgressFile,
    #[serde(default)]
    dns: DnsFile,
    #[serde(default)]
    timeouts: TimeoutConfig,
    #[serde(default)]
    evm_rpc: Vec<EvmRpcFile>,
    #[serde(default)]
    blob_mirror: Vec<MirrorFile>,
    artifacts: Option<ArtifactsFile>,
}

/// `[budget]`: the global in-flight byte budget and the share reserved for held-lock work.
#[derive(Debug, Clone, Copy, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetConfig {
    #[serde(default = "d_inflight")]
    pub inflight_bytes: u64,
    #[serde(default = "d_share")]
    pub held_lock_share: f64,
}

impl Default for BudgetConfig {
    fn default() -> Self {
        Self { inflight_bytes: d_inflight(), held_lock_share: d_share() }
    }
}

/// `[cache]`: byte and entry caps of each type-tagged cache (LRU).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CacheConfig {
    #[serde(default = "d_rpc_bytes")]
    pub rpc_max_bytes: u64,
    #[serde(default = "d_rpc_entries")]
    pub rpc_max_entries: usize,
    #[serde(default = "d_artifact_bytes")]
    pub artifact_max_bytes: u64,
    #[serde(default = "d_artifact_entries")]
    pub artifact_max_entries: usize,
    #[serde(default = "d_bad_entries")]
    pub bad_manifest_max_entries: usize,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            rpc_max_bytes: d_rpc_bytes(),
            rpc_max_entries: d_rpc_entries(),
            artifact_max_bytes: d_artifact_bytes(),
            artifact_max_entries: d_artifact_entries(),
            bad_manifest_max_entries: d_bad_entries(),
        }
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct EgressFile {
    #[serde(default)]
    deny_cidrs: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DnsFile {
    #[serde(default)]
    servers: Vec<String>,
    #[serde(default = "d_reresolve")]
    reresolve_secs: u64,
}

impl Default for DnsFile {
    fn default() -> Self {
        Self { servers: Vec::new(), reresolve_secs: d_reresolve() }
    }
}

/// `[dns]`: the broker's own resolver for endpoint host names (see [`crate::dns`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsConfig {
    /// Explicit servers; empty = the nameservers of `/etc/resolv.conf` (read before the sandbox,
    /// into [`HostFacts::dns_servers`]).
    pub servers: Vec<SocketAddr>,
    /// How long a host name's answer stays pinned before it is resolved again.
    pub reresolve: Duration,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self { servers: Vec::new(), reresolve: Duration::from_secs(d_reresolve()) }
    }
}

/// `[timeouts]`, in seconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TimeoutConfig {
    #[serde(default = "d_connect")]
    pub connect_secs: u64,
    /// One HTTP request to an endpoint.
    #[serde(default = "d_request")]
    pub request_secs: u64,
    /// One builder fetch, failover included (then status 2).
    #[serde(default = "d_fetch")]
    pub fetch_secs: u64,
    /// The rest of a frame once its first byte arrived, and writing a result frame.
    #[serde(default = "d_partial")]
    pub partial_frame_secs: u64,
    /// One `FetchArtifact`, all reads included.
    #[serde(default = "d_artifact_fetch")]
    pub artifact_fetch_secs: u64,
    /// How long a fetch waits for the miner's `ChargeDecision`.
    #[serde(default = "d_charge")]
    pub charge_decision_secs: u64,
}

impl Default for TimeoutConfig {
    fn default() -> Self {
        Self {
            connect_secs: d_connect(),
            request_secs: d_request(),
            fetch_secs: d_fetch(),
            partial_frame_secs: d_partial(),
            artifact_fetch_secs: d_artifact_fetch(),
            charge_decision_secs: d_charge(),
        }
    }
}

impl TimeoutConfig {
    pub fn connect(&self) -> Duration {
        Duration::from_secs(self.connect_secs)
    }
    pub fn request(&self) -> Duration {
        Duration::from_secs(self.request_secs)
    }
    pub fn fetch(&self) -> Duration {
        Duration::from_secs(self.fetch_secs)
    }
    pub fn partial_frame(&self) -> Duration {
        Duration::from_secs(self.partial_frame_secs)
    }
    pub fn artifact_fetch(&self) -> Duration {
        Duration::from_secs(self.artifact_fetch_secs)
    }
    pub fn charge_decision(&self) -> Duration {
        Duration::from_secs(self.charge_decision_secs)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EvmRpcFile {
    alias: String,
    url: String,
    chain_id: u64,
    #[serde(default)]
    archive: bool,
    #[serde(default)]
    max_proof_age: u64,
    method_sets: Vec<String>,
    key_file: Option<PathBuf>,
    key_header: Option<String>,
    #[serde(default)]
    cidrs: Vec<String>,
    #[serde(default = "d_concurrency")]
    max_concurrency: u32,
    max_requests_per_sec: Option<u32>,
    max_units_per_minute: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MirrorFile {
    alias: String,
    url_template: String,
    #[serde(default)]
    cidrs: Vec<String>,
    #[serde(default = "d_concurrency")]
    max_concurrency: u32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArtifactsFile {
    alias: String,
    url: String,
    chain_id: u64,
    #[serde(default = "d_artifact_rps")]
    max_requests_per_sec: u32,
    #[serde(default = "d_max_builder_bytes")]
    max_builder_bytes: u64,
    key_file: Option<PathBuf>,
    key_header: Option<String>,
    #[serde(default)]
    cidrs: Vec<String>,
    #[serde(default = "d_concurrency")]
    max_concurrency: u32,
    mirror: Option<MirrorFile>,
}

fn d_spool_quota() -> u64 {
    1 << 30
}
fn d_inflight() -> u64 {
    256 << 20
}
fn d_share() -> f64 {
    0.25
}
fn d_rpc_bytes() -> u64 {
    64 << 20
}
fn d_rpc_entries() -> usize {
    65_536
}
fn d_artifact_bytes() -> u64 {
    256 << 20
}
fn d_artifact_entries() -> usize {
    256
}
fn d_bad_entries() -> usize {
    65_536
}
fn d_connect() -> u64 {
    5
}
fn d_request() -> u64 {
    30
}
fn d_fetch() -> u64 {
    60
}
fn d_partial() -> u64 {
    10
}
fn d_artifact_fetch() -> u64 {
    300
}
fn d_charge() -> u64 {
    30
}
fn d_concurrency() -> u32 {
    8
}
fn d_artifact_rps() -> u32 {
    2
}
fn d_max_builder_bytes() -> u64 {
    4 << 20
}
fn d_reresolve() -> u64 {
    300
}

// ---------------------------------------------------------------------------------------------
// The validated configuration.

/// A provider key: zeroed on drop, never printed.
#[derive(Clone)]
pub struct Secret(Zeroizing<String>);

impl Secret {
    pub(crate) fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<secret>")
    }
}

/// One operator endpoint: its role, alias, URL (with any key in place, so never logged), key header,
/// host, port and role-entry prefixes.
#[derive(Clone)]
pub struct EndpointSpec {
    pub role: Role,
    pub alias: String,
    /// The request URL (JSON-RPC endpoints, key substituted) or URL template (mirrors).
    url: Zeroizing<String>,
    /// `(name, value)` of the key header, the value marked sensitive.
    pub(crate) key_header: Option<(HeaderName, HeaderValue)>,
    /// Whether a key travels with requests (in the path or a header).
    pub key_bearing: bool,
    /// Lowercase host name, or the textual IP of an IP-literal host.
    pub host: String,
    /// The host's address when the URL names an IP literal (no resolution).
    pub literal: Option<IpAddr>,
    pub port: u16,
    /// Explicit role-entry prefixes; empty = the addresses the host resolves to.
    pub cidrs: Vec<Prefix>,
    pub max_concurrency: u32,
    pub max_requests_per_sec: Option<u32>,
    pub max_units_per_minute: Option<u64>,
}

impl fmt::Debug for EndpointSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EndpointSpec").field("role", &self.role).field("alias", &self.alias).finish_non_exhaustive()
    }
}

impl EndpointSpec {
    /// The request URL. Never log it: it may carry a key.
    pub(crate) fn url(&self) -> &str {
        &self.url
    }

    /// The template with each `{name}` replaced (values are broker-built: hex or decimal).
    pub(crate) fn url_with(&self, replacements: &[(&str, &str)]) -> String {
        let mut s = self.url.to_string();
        for (name, value) in replacements {
            s = s.replace(&format!("{{{name}}}"), value);
        }
        s
    }
}

#[derive(Debug, Clone)]
pub struct EvmRpcEndpoint {
    pub spec: EndpointSpec,
    pub chain_id: u64,
    pub archive: bool,
    /// The deepest `head − block` at which it serves `eth_getProof`.
    pub max_proof_age: u64,
    pub method_sets: Vec<MethodSet>,
}

#[derive(Debug, Clone)]
pub struct ArtifactsSpec {
    pub spec: EndpointSpec,
    pub chain_id: u64,
    pub max_builder_bytes: u64,
    /// The operator artifact mirror (`{type}`, `{id}`).
    pub mirror: Option<EndpointSpec>,
}

/// Facts about the host the sandboxed broker cannot read itself: the DNS servers, what each
/// endpoint host resolved to at startup, the connected prefixes and the host's own addresses.
/// `main` reads them before `restrict_self`; [`crate::serve`] reads them itself when they are
/// absent (tests).
#[derive(Debug, Clone, Default)]
pub struct HostFacts {
    /// Endpoint alias → resolved addresses, unfiltered (empty when resolution failed; retried
    /// lazily). The floor filters them ([`crate::net::build_policy`]).
    pub resolved: HashMap<String, Vec<IpAddr>>,
    pub connected: Vec<Prefix>,
    pub own_addresses: Vec<IpAddr>,
    /// The servers host names are resolved with: `[dns] servers`, else `/etc/resolv.conf`'s.
    pub dns_servers: Vec<SocketAddr>,
}

#[derive(Debug, Clone)]
pub struct BrokerConfig {
    pub chain_rpc_host: String,
    pub spool_dir: PathBuf,
    pub spool_quota_bytes: u64,
    pub budget: BudgetConfig,
    pub cache: CacheConfig,
    pub deny: Vec<Prefix>,
    pub dns: DnsConfig,
    pub timeouts: TimeoutConfig,
    pub evm_rpc: Vec<EvmRpcEndpoint>,
    pub blob_mirrors: Vec<EndpointSpec>,
    pub artifacts: Option<ArtifactsSpec>,
    pub host: Option<HostFacts>,
}

impl BrokerConfig {
    /// Reads and validates the config file and every key file it names (relative key paths are
    /// taken from the config file's directory).
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let io = |source| ConfigError::Io { path: path.to_path_buf(), source };
        let meta = std::fs::metadata(path).map_err(io)?;
        if meta.len() > MAX_CONFIG_FILE_BYTES {
            return invalid("config file larger than 1 MiB");
        }
        let text = std::fs::read_to_string(path).map_err(io)?;
        let base = path.parent().unwrap_or(Path::new("/"));
        Self::from_toml(&text, base)
    }

    /// Parses and validates a config, reading key files relative to `base_dir`.
    pub fn from_toml(text: &str, base_dir: &Path) -> Result<Self, ConfigError> {
        let file: FileConfig = toml::from_str(text).map_err(|e| ConfigError::Parse(e.message().to_string()))?;
        validate(file, base_dir)
    }

    /// Every endpoint, in a fixed order: evm-rpc, blob mirrors, the artifact endpoint, its mirror.
    pub fn endpoints(&self) -> impl Iterator<Item = &EndpointSpec> {
        self.evm_rpc
            .iter()
            .map(|e| &e.spec)
            .chain(self.blob_mirrors.iter())
            .chain(self.artifacts.iter().flat_map(|a| std::iter::once(&a.spec).chain(a.mirror.iter())))
    }

    /// The TCP ports the broker connects to (its sandbox profile): every endpoint's port, and —
    /// when an endpoint is named by host name, so the resolver runs — the DNS servers' ports (53,
    /// unless `[dns] servers` names another), since [`crate::dns`] queries over TCP.
    ///
    /// Landlock admits a port to *any* host. That the broker dials only the configured endpoints
    /// on theirs is the network floor's work ([`crate::net`]), and only the resolver's servers on
    /// theirs is [`crate::dns`]'s: the server list is fixed at startup, from `[dns] servers` or
    /// `/etc/resolv.conf`, and no other code connects to it.
    pub fn tcp_connect_ports(&self) -> Vec<u16> {
        let mut ports: BTreeSet<u16> = self.endpoints().map(|e| e.port).collect();
        if self.endpoints().any(|e| e.literal.is_none()) {
            ports.extend(self.dns_server_ports());
        }
        ports.into_iter().collect()
    }

    /// The ports of the servers the resolver will use: the host facts' (read before the sandbox),
    /// else `[dns] servers`, else the DNS port (`/etc/resolv.conf` names addresses only).
    fn dns_server_ports(&self) -> Vec<u16> {
        match &self.host {
            Some(h) => h.dns_servers.iter().map(|s| s.port()).collect(),
            None if !self.dns.servers.is_empty() => self.dns.servers.iter().map(|s| s.port()).collect(),
            None => vec![crate::dns::DNS_PORT],
        }
    }

    /// The bytes reserved for held-lock work.
    pub fn held_lock_reserved_bytes(&self) -> u64 {
        ((self.budget.inflight_bytes as f64) * self.budget.held_lock_share) as u64
    }

    /// What the operator configured each endpoint's role entry as, by alias: its explicit `cidrs`,
    /// else its IP literal's host route, else nothing (a host name: DNS-derived, never counted as
    /// configured by the self-test).
    pub fn configured_prefixes(&self) -> HashMap<String, Vec<Prefix>> {
        self.endpoints()
            .map(|e| {
                let p = if !e.cidrs.is_empty() {
                    e.cidrs.clone()
                } else {
                    e.literal.map(host_prefix).into_iter().collect()
                };
                (e.alias.clone(), p)
            })
            .collect()
    }
}

fn validate(f: FileConfig, base: &Path) -> Result<BrokerConfig, ConfigError> {
    let chain_rpc_host = normalize_host_input(&f.chain_rpc_host)
        .ok_or_else(|| ConfigError::Invalid("chain_rpc_host is not a host or URL".into()))?;
    if !f.spool_dir.is_absolute() {
        return invalid("spool_dir must be an absolute path");
    }
    if f.spool_quota_bytes == 0 {
        return invalid("spool_quota_bytes must be positive");
    }
    if f.budget.inflight_bytes < (1 << 20) {
        return invalid("budget.inflight_bytes must be at least 1 MiB");
    }
    if !(f.budget.held_lock_share > 0.0 && f.budget.held_lock_share < 1.0) {
        return invalid("budget.held_lock_share must be in (0, 1)");
    }
    let c = &f.cache;
    if c.rpc_max_entries == 0 || c.artifact_max_entries == 0 || c.bad_manifest_max_entries == 0 {
        return invalid("cache entry caps must be positive");
    }
    let t = &f.timeouts;
    if [t.connect_secs, t.request_secs, t.fetch_secs, t.partial_frame_secs, t.artifact_fetch_secs, t.charge_decision_secs]
        .contains(&0)
    {
        return invalid("timeouts must be positive");
    }
    let deny = f
        .egress
        .deny_cidrs
        .iter()
        .map(|s| parse_cidr(s).map_err(|e| ConfigError::Invalid(format!("egress.deny_cidrs: {e}"))))
        .collect::<Result<Vec<_>, _>>()?;
    if f.dns.reresolve_secs == 0 {
        return invalid("dns.reresolve_secs must be positive");
    }
    let dns = DnsConfig {
        servers: f
            .dns
            .servers
            .iter()
            .map(|s| crate::dns::parse_server(s).map_err(|e| ConfigError::Invalid(format!("dns.servers: {e}"))))
            .collect::<Result<Vec<_>, _>>()?,
        reresolve: Duration::from_secs(f.dns.reresolve_secs),
    };

    let mut aliases = HashSet::new();
    let mut check_alias = |alias: &str| -> Result<(), ConfigError> {
        if alias.is_empty()
            || alias.len() > MAX_ALIAS_BYTES
            || !alias.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        {
            return invalid(format!("alias {alias:?}: 1-64 characters of [A-Za-z0-9._-]"));
        }
        if !aliases.insert(alias.to_string()) {
            return invalid(format!("alias {alias:?} is used twice"));
        }
        Ok(())
    };

    let mut evm_rpc = Vec::new();
    for e in f.evm_rpc {
        check_alias(&e.alias)?;
        if e.chain_id == 0 {
            return invalid(format!("{}: chain_id must be positive", e.alias));
        }
        if e.method_sets.is_empty() {
            return invalid(format!("{}: method_sets is empty", e.alias));
        }
        let mut method_sets = Vec::new();
        for m in &e.method_sets {
            let set = match m.as_str() {
                "state-read" => MethodSet::StateRead,
                "state-trace" => MethodSet::StateTrace,
                _ => return invalid(format!("{}: unknown method set {m:?}", e.alias)),
            };
            if method_sets.contains(&set) {
                return invalid(format!("{}: method set {m:?} listed twice", e.alias));
            }
            method_sets.push(set);
        }
        let spec = rpc_endpoint(
            Role::EvmRpc,
            &e.alias,
            &e.url,
            e.key_file.as_deref(),
            e.key_header.as_deref(),
            &e.cidrs,
            e.max_concurrency,
            e.max_requests_per_sec,
            e.max_units_per_minute,
            base,
        )?;
        evm_rpc.push(EvmRpcEndpoint {
            spec,
            chain_id: e.chain_id,
            archive: e.archive,
            max_proof_age: e.max_proof_age,
            method_sets,
        });
    }

    let mut blob_mirrors = Vec::new();
    for m in f.blob_mirror {
        check_alias(&m.alias)?;
        blob_mirrors.push(mirror_endpoint(Role::BlobMirror, &m, &["sha256"])?);
    }

    let artifacts = match f.artifacts {
        None => None,
        Some(a) => {
            check_alias(&a.alias)?;
            if a.chain_id == 0 {
                return invalid("artifacts.chain_id must be positive");
            }
            if a.max_requests_per_sec == 0 {
                return invalid("artifacts.max_requests_per_sec must be positive");
            }
            if a.max_builder_bytes == 0 {
                return invalid("artifacts.max_builder_bytes must be positive");
            }
            let spec = rpc_endpoint(
                Role::Artifact,
                &a.alias,
                &a.url,
                a.key_file.as_deref(),
                a.key_header.as_deref(),
                &a.cidrs,
                a.max_concurrency,
                Some(a.max_requests_per_sec),
                None,
                base,
            )?;
            let mirror = match &a.mirror {
                None => None,
                Some(m) => {
                    check_alias(&m.alias)?;
                    Some(mirror_endpoint(Role::ArtifactMirror, m, &["type", "id"])?)
                }
            };
            Some(ArtifactsSpec { spec, chain_id: a.chain_id, max_builder_bytes: a.max_builder_bytes, mirror })
        }
    };

    let cfg = BrokerConfig {
        chain_rpc_host,
        spool_dir: f.spool_dir,
        spool_quota_bytes: f.spool_quota_bytes,
        budget: f.budget,
        cache: f.cache,
        deny,
        dns,
        timeouts: f.timeouts,
        evm_rpc,
        blob_mirrors,
        artifacts,
        host: None,
    };
    // §11.1: never an endpoint on the miner's chain-RPC host.
    for e in cfg.endpoints() {
        if e.host == cfg.chain_rpc_host {
            return invalid(format!("{}: its host is chain_rpc_host (the miner's chain RPC); use a separate endpoint", e.alias));
        }
    }
    Ok(cfg)
}

/// A JSON-RPC endpoint (`evm-rpc/v1` or the artifact endpoint): a URL with an optional key, in the
/// path (`{key}`) or in a header.
#[allow(clippy::too_many_arguments)]
fn rpc_endpoint(
    role: Role,
    alias: &str,
    url: &str,
    key_file: Option<&Path>,
    key_header: Option<&str>,
    cidrs: &[String],
    max_concurrency: u32,
    max_requests_per_sec: Option<u32>,
    max_units_per_minute: Option<u64>,
    base: &Path,
) -> Result<EndpointSpec, ConfigError> {
    const TOKEN: &str = "zkminerkeyslot";
    let slots = url.matches("{key}").count();
    if slots > 1 {
        return invalid(format!("{alias}: {{key}} appears more than once in url"));
    }
    let probe = url.replace("{key}", TOKEN);
    if probe.contains(['{', '}']) {
        return invalid(format!("{alias}: url has a placeholder other than {{key}}"));
    }
    let parsed = check_url(alias, &probe)?;
    if slots == 1 && (!parsed.path().contains(TOKEN) || parsed.query().is_some_and(|q| q.contains(TOKEN))) {
        return invalid(format!("{alias}: {{key}} must be in the URL path"));
    }
    let key = match key_file {
        None => {
            if slots == 1 || key_header.is_some() {
                return invalid(format!("{alias}: {{key}} or key_header needs key_file"));
            }
            None
        }
        Some(p) => {
            if (slots == 1) == key_header.is_some() {
                return invalid(format!("{alias}: key_file needs exactly one of {{key}} in the url path or key_header"));
            }
            let path = if p.is_absolute() { p.to_path_buf() } else { base.join(p) };
            Some(read_key(alias, &path)?)
        }
    };
    let mut final_url = Zeroizing::new(url.to_string());
    let mut header = None;
    if let Some(key) = &key {
        if slots == 1 {
            if !key.expose().bytes().all(|b| b.is_ascii_alphanumeric() || b"._~-".contains(&b)) {
                return invalid(format!("{alias}: a key substituted into the path must be [A-Za-z0-9._~-]"));
            }
            final_url = Zeroizing::new(url.replace("{key}", key.expose()));
        } else {
            let name = key_header.unwrap_or_default().to_ascii_lowercase();
            let name = HeaderName::from_bytes(name.as_bytes())
                .map_err(|_| ConfigError::Invalid(format!("{alias}: key_header is not a header name")))?;
            if ["host", "content-length", "content-type", "transfer-encoding", "connection", "referer"]
                .contains(&name.as_str())
            {
                return invalid(format!("{alias}: key_header may not be {}", name.as_str()));
            }
            let mut value = HeaderValue::from_str(key.expose())
                .map_err(|_| ConfigError::Invalid(format!("{alias}: the key is not a valid header value")))?;
            value.set_sensitive(true);
            header = Some((name, value));
        }
    }
    let (host, literal, port) = host_port(&parsed);
    if max_concurrency == 0 || max_concurrency > 1024 {
        return invalid(format!("{alias}: max_concurrency must be in 1..=1024"));
    }
    if max_requests_per_sec == Some(0) || max_units_per_minute == Some(0) {
        return invalid(format!("{alias}: rate limits must be positive"));
    }
    let cidrs = parse_cidrs(alias, cidrs)?;
    // A key never crosses a network in clear text: http only to a loopback IP literal or one inside
    // the endpoint's own explicit cidrs (a node on the operator's own wire); never to a host name.
    if key.is_some() && parsed.scheme() == "http" {
        let local = literal.is_some_and(|ip| {
            crate::egress::canonical_ip(ip).is_loopback() || cidrs.iter().any(|p| p.contains(ip))
        });
        if !local {
            return invalid(format!(
                "{alias}: a key is sent only over https (or http to a loopback IP literal or one inside the endpoint's cidrs)"
            ));
        }
    }
    Ok(EndpointSpec {
        role,
        alias: alias.to_string(),
        url: final_url,
        key_header: header,
        key_bearing: key.is_some(),
        host,
        literal,
        port,
        cidrs,
        max_concurrency,
        max_requests_per_sec,
        max_units_per_minute,
    })
}

/// A mirror: a URL template whose `placeholders` each appear exactly once, in the path.
fn mirror_endpoint(role: Role, m: &MirrorFile, placeholders: &[&str]) -> Result<EndpointSpec, ConfigError> {
    let alias = m.alias.as_str();
    let mut probe = m.url_template.clone();
    for p in placeholders {
        let slot = format!("{{{p}}}");
        if m.url_template.matches(&slot).count() != 1 {
            return invalid(format!("{alias}: url_template must contain {slot} exactly once"));
        }
        probe = probe.replace(&slot, &format!("zkminerslot{p}"));
    }
    if probe.contains(['{', '}']) {
        return invalid(format!("{alias}: url_template has an unknown placeholder"));
    }
    let parsed = check_url(alias, &probe)?;
    for p in placeholders {
        let token = format!("zkminerslot{p}");
        if !parsed.path().contains(&token) || parsed.query().is_some_and(|q| q.contains(&token)) {
            return invalid(format!("{alias}: {{{p}}} must be in the URL path"));
        }
    }
    if m.max_concurrency == 0 || m.max_concurrency > 1024 {
        return invalid(format!("{alias}: max_concurrency must be in 1..=1024"));
    }
    let (host, literal, port) = host_port(&parsed);
    Ok(EndpointSpec {
        role,
        alias: alias.to_string(),
        url: Zeroizing::new(m.url_template.clone()),
        key_header: None,
        key_bearing: false,
        host,
        literal,
        port,
        cidrs: parse_cidrs(alias, &m.cidrs)?,
        max_concurrency: m.max_concurrency,
        max_requests_per_sec: None,
        max_units_per_minute: None,
    })
}

fn check_url(alias: &str, s: &str) -> Result<Url, ConfigError> {
    let u = Url::parse(s).map_err(|_| ConfigError::Invalid(format!("{alias}: url does not parse")))?;
    if !matches!(u.scheme(), "http" | "https") {
        return invalid(format!("{alias}: url scheme must be http or https"));
    }
    if u.host().is_none() {
        return invalid(format!("{alias}: url has no host"));
    }
    if !u.username().is_empty() || u.password().is_some() {
        return invalid(format!("{alias}: url may not carry userinfo (use key_file)"));
    }
    if u.fragment().is_some() {
        return invalid(format!("{alias}: url may not have a fragment"));
    }
    Ok(u)
}

fn host_port(u: &Url) -> (String, Option<IpAddr>, u16) {
    let port = u.port_or_known_default().unwrap_or(443);
    match u.host() {
        Some(url::Host::Ipv4(ip)) => (ip.to_string(), Some(IpAddr::V4(ip)), port),
        Some(url::Host::Ipv6(ip)) => (ip.to_string(), Some(IpAddr::V6(ip)), port),
        Some(url::Host::Domain(d)) => (d.trim_end_matches('.').to_ascii_lowercase(), None, port),
        None => (String::new(), None, port),
    }
}

/// `chain_rpc_host` as a host, `host:port` or URL, normalized like an endpoint host.
fn normalize_host_input(s: &str) -> Option<String> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    let u = if s.contains("://") { Url::parse(s).ok()? } else { Url::parse(&format!("http://{s}")).ok()? };
    u.host()?;
    Some(host_port(&u).0)
}

fn read_key(alias: &str, path: &Path) -> Result<Secret, ConfigError> {
    let io = |source| ConfigError::Io { path: path.to_path_buf(), source };
    let meta = std::fs::metadata(path).map_err(io)?;
    if !meta.is_file() {
        return invalid(format!("{alias}: key_file is not a regular file"));
    }
    if meta.permissions().mode() & 0o007 != 0 {
        return invalid(format!("{alias}: key_file is accessible by others (chmod o-rwx)"));
    }
    if meta.len() > MAX_KEY_BYTES {
        return invalid(format!("{alias}: key_file is larger than {MAX_KEY_BYTES} bytes"));
    }
    let raw = Zeroizing::new(std::fs::read(path).map_err(io)?);
    let text = std::str::from_utf8(&raw).map_err(|_| ConfigError::Invalid(format!("{alias}: key_file is not text")))?;
    let key = text.trim();
    if key.is_empty() {
        return invalid(format!("{alias}: key_file is empty"));
    }
    if !key.bytes().all(|b| b == b' ' || b.is_ascii_graphic()) {
        return invalid(format!("{alias}: key_file holds control or non-ASCII characters"));
    }
    Ok(Secret(Zeroizing::new(key.to_string())))
}

fn parse_cidrs(alias: &str, cidrs: &[String]) -> Result<Vec<Prefix>, ConfigError> {
    cidrs
        .iter()
        .map(|s| parse_cidr(s).map_err(|e| ConfigError::Invalid(format!("{alias}: cidrs: {e}"))))
        .collect()
}

/// `a.b.c.d/len`, `v6/len`, or a bare address (a host prefix). Host bits must be zero.
pub fn parse_cidr(s: &str) -> Result<Prefix, String> {
    let (addr, len) = match s.split_once('/') {
        Some((a, l)) => {
            let addr: IpAddr = a.parse().map_err(|_| format!("{s:?} is not an address"))?;
            if l.is_empty() || l.len() > 3 || !l.bytes().all(|b| b.is_ascii_digit()) {
                return Err(format!("{s:?} has a malformed prefix length"));
            }
            (addr, l.parse::<u8>().map_err(|_| format!("{s:?} has a malformed prefix length"))?)
        }
        None => {
            let addr: IpAddr = s.parse().map_err(|_| format!("{s:?} is not an address"))?;
            (addr, if addr.is_ipv4() { 32 } else { 128 })
        }
    };
    let max = if addr.is_ipv4() { 32 } else { 128 };
    if len > max {
        return Err(format!("{s:?}: prefix length above {max}"));
    }
    if mask(addr, len) != addr {
        return Err(format!("{s:?} has host bits set"));
    }
    Ok(Prefix { addr, len })
}

/// The host prefix of `ip`.
pub fn host_prefix(ip: IpAddr) -> Prefix {
    Prefix { addr: ip, len: if ip.is_ipv4() { 32 } else { 128 } }
}

/// `ip` with every bit past `len` cleared.
pub(crate) fn mask(ip: IpAddr, len: u8) -> IpAddr {
    match ip {
        IpAddr::V4(v4) => {
            let bits = u32::from(v4);
            let m = if len == 0 { 0 } else { u32::MAX << (32 - u32::from(len.min(32))) };
            IpAddr::V4((bits & m).into())
        }
        IpAddr::V6(v6) => {
            let bits = u128::from(v6);
            let m = if len == 0 { 0 } else { u128::MAX << (128 - u32::from(len.min(128))) };
            IpAddr::V6((bits & m).into())
        }
    }
}

/// Whether `p` contains `ip` (same family only). The broker's own check for configuration facts
/// (the self-test's "explicitly configured" rule); admission itself is [`crate::egress`]'s.
pub(crate) fn prefix_contains(p: &Prefix, ip: IpAddr) -> bool {
    p.addr.is_ipv4() == ip.is_ipv4() && mask(ip, p.len) == mask(p.addr, p.len)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn write_key(dir: &Path, name: &str, key: &str, mode: u32) -> PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, key).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
        p
    }

    fn example(dir: &Path) -> String {
        write_key(dir, "base.key", "abcDEF123._~-\n", 0o600);
        write_key(dir, "hdr.key", "Bearer s3cret\n", 0o640);
        format!(
            r#"
chain_rpc_host = "https://rpc.hemi.network/some/path"
spool_dir = "{spool}"
spool_quota_bytes = 1048576

[budget]
inflight_bytes = 268435456
held_lock_share = 0.25

[cache]
rpc_max_bytes = 1000
rpc_max_entries = 10

[egress]
deny_cidrs = ["203.0.113.7/32", "2001:db8::/32"]

[[evm_rpc]]
alias = "base-own"
url = "https://base.example.net/v2/{{key}}"
chain_id = 8453
archive = true
max_proof_age = 100000
method_sets = ["state-read"]
key_file = "base.key"
cidrs = ["198.51.100.0/24"]
max_requests_per_sec = 50
max_units_per_minute = 6000

[[evm_rpc]]
alias = "base-hdr"
url = "http://127.0.0.1:8545"
chain_id = 8453
method_sets = ["state-read", "state-trace"]
key_file = "{dir}/hdr.key"
key_header = "Authorization"

[[blob_mirror]]
alias = "mirror-a"
url_template = "https://mirror.example/blobs/{{sha256}}"

[artifacts]
alias = "hemi-own"
url = "http://10.0.0.5:8545"
chain_id = 743111
cidrs = ["10.0.0.5"]

[artifacts.mirror]
alias = "artifact-mirror"
url_template = "https://mirror.example/artifacts/{{type}}/{{id}}"
"#,
            spool = dir.join("spool").display(),
            dir = dir.display()
        )
    }

    #[test]
    fn example_parses() {
        let dir = tempfile::tempdir().unwrap();
        let c = BrokerConfig::from_toml(&example(dir.path()), dir.path()).unwrap();
        assert_eq!(c.chain_rpc_host, "rpc.hemi.network");
        assert_eq!(c.deny.len(), 2);
        assert_eq!(c.cache.rpc_max_entries, 10);
        assert_eq!(c.cache.artifact_max_entries, 256, "defaults fill the rest of a table");
        let e = &c.evm_rpc[0];
        assert_eq!(e.spec.url(), "https://base.example.net/v2/abcDEF123._~-");
        assert!(e.spec.key_bearing && e.spec.key_header.is_none());
        assert_eq!(e.spec.port, 443);
        assert_eq!(e.spec.cidrs, vec![parse_cidr("198.51.100.0/24").unwrap()]);
        assert_eq!(format!("{:?}", e.spec), "EndpointSpec { role: EvmRpc, alias: \"base-own\", .. }");
        let h = &c.evm_rpc[1];
        let (name, value) = h.spec.key_header.as_ref().unwrap();
        assert_eq!(name.as_str(), "authorization");
        assert_eq!(value.to_str().unwrap(), "Bearer s3cret");
        assert!(value.is_sensitive());
        assert_eq!(h.spec.literal, Some("127.0.0.1".parse().unwrap()));
        assert_eq!(h.method_sets, vec![MethodSet::StateRead, MethodSet::StateTrace]);
        let a = c.artifacts.as_ref().unwrap();
        assert_eq!((a.chain_id, a.max_builder_bytes, a.spec.max_requests_per_sec), (743111, 4 << 20, Some(2)));
        assert_eq!(a.spec.cidrs, vec![host_prefix("10.0.0.5".parse().unwrap())]);
        let m = a.mirror.as_ref().unwrap();
        assert_eq!(m.url_with(&[("type", "1"), ("id", "ab")]), "https://mirror.example/artifacts/1/ab");
        assert_eq!(c.blob_mirrors[0].url_with(&[("sha256", "ff")]), "https://mirror.example/blobs/ff");
        // Host-name endpoints: the resolver's port (TCP DNS) too.
        assert_eq!(c.tcp_connect_ports(), vec![53, 443, 8545]);
        assert_eq!(c.held_lock_reserved_bytes(), 64 << 20);
    }

    fn minimal(extra: &str) -> String {
        format!("chain_rpc_host = \"rpc.hemi.network\"\nspool_dir = \"/tmp/spool\"\n{extra}")
    }

    fn err(text: &str, dir: &Path) -> String {
        match BrokerConfig::from_toml(text, dir) {
            Ok(_) => panic!("accepted:\n{text}"),
            Err(e) => e.to_string(),
        }
    }

    #[test]
    fn unknown_keys_are_refused_in_every_table() {
        let dir = tempfile::tempdir().unwrap();
        let ep = "[[evm_rpc]]\nalias = \"a\"\nurl = \"https://x.example\"\nchain_id = 1\nmethod_sets = [\"state-read\"]\n";
        for bad in [
            minimal("bogus = 1"),
            minimal("[budget]\ninflight = 1"),
            minimal("[cache]\nmax = 1"),
            minimal("[egress]\nallow = []"),
            minimal("[timeouts]\nidle_secs = 1"),
            minimal(&format!("{ep}rate = 1")),
            minimal("[[blob_mirror]]\nalias = \"m\"\nurl_template = \"https://m.example/{sha256}\"\nkey_file = \"k\""),
            minimal("[artifacts]\nalias = \"a\"\nurl = \"https://a.example\"\nchain_id = 1\nrpc_url = \"x\""),
            minimal("[artifacts]\nalias = \"a\"\nurl = \"https://a.example\"\nchain_id = 1\n[artifacts.mirror]\nalias = \"m\"\nurl_template = \"https://m.example/{type}/{id}\"\nx = 1"),
        ] {
            assert!(err(&bad, dir.path()).contains("unknown field"), "{bad}");
        }
        assert!(BrokerConfig::from_toml(&minimal(ep), dir.path()).is_ok());
    }

    #[test]
    fn the_chain_rpc_host_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        for (host, url) in [
            ("rpc.hemi.network", "https://RPC.hemi.network./x"),
            ("https://rpc.hemi.network:8545/key", "http://rpc.hemi.network:1/"),
            ("10.1.2.3:8545", "http://10.1.2.3:9000"),
            ("[2001:db8::1]", "http://[2001:db8:0::1]/"),
        ] {
            let text = format!(
                "chain_rpc_host = \"{host}\"\nspool_dir = \"/s\"\n[artifacts]\nalias = \"a\"\nurl = \"{url}\"\nchain_id = 1\n"
            );
            assert!(err(&text, dir.path()).contains("chain_rpc_host"), "{host} vs {url}");
        }
        let text = minimal("[[blob_mirror]]\nalias = \"m\"\nurl_template = \"https://rpc.hemi.network/b/{sha256}\"\n");
        assert!(err(&text, dir.path()).contains("chain_rpc_host"));
    }

    #[test]
    fn keys_come_from_files_and_go_only_where_configured() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        write_key(d, "ok.key", "k1", 0o600);
        write_key(d, "world.key", "k1", 0o604);
        write_key(d, "bad.key", "a/b", 0o600);
        write_key(d, "empty.key", "\n", 0o600);
        let ep = |url: &str, extra: &str| {
            minimal(&format!(
                "[[evm_rpc]]\nalias = \"a\"\nurl = \"{url}\"\nchain_id = 1\nmethod_sets = [\"state-read\"]\n{extra}"
            ))
        };
        assert!(err(&ep("https://x.example/{key}", ""), d).contains("needs key_file"));
        assert!(err(&ep("https://x.example/", "key_header = \"x-api-key\""), d).contains("needs key_file"));
        assert!(err(&ep("https://x.example/", "key_file = \"ok.key\""), d).contains("exactly one"));
        assert!(err(&ep("https://x.example/{key}", "key_file = \"ok.key\"\nkey_header = \"x\""), d).contains("exactly one"));
        assert!(err(&ep("https://x.example/?k={key}", "key_file = \"ok.key\""), d).contains("path"));
        assert!(err(&ep("https://{key}.example/", "key_file = \"ok.key\""), d).contains("path"));
        assert!(err(&ep("https://x.example/{key}/{key}", "key_file = \"ok.key\""), d).contains("more than once"));
        assert!(err(&ep("https://x.example/{key}", "key_file = \"world.key\""), d).contains("others"));
        assert!(err(&ep("https://x.example/{key}", "key_file = \"bad.key\""), d).contains("[A-Za-z0-9._~-]"));
        assert!(err(&ep("https://x.example/{key}", "key_file = \"empty.key\""), d).contains("empty"));
        assert!(err(&ep("https://x.example/{key}", "key_file = \"missing.key\""), d).contains("missing.key"));
        assert!(err(&ep("https://x.example/", "key_file = \"ok.key\"\nkey_header = \"host\""), d).contains("may not be"));
        assert!(err(&ep("https://u:p@x.example/", ""), d).contains("userinfo"));
        assert!(err(&ep("ftp://x.example/", ""), d).contains("scheme"));
        assert!(err(&ep("https://x.example/{api}", ""), d).contains("placeholder"));
        let c = BrokerConfig::from_toml(&ep("https://x.example/a/{key}", "key_file = \"ok.key\""), d).unwrap();
        assert_eq!(c.evm_rpc[0].spec.url(), "https://x.example/a/k1");
        // Keys never reach Debug output.
        assert!(!format!("{c:?}").contains("k1"));
    }

    #[test]
    fn values_are_range_checked() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        let ep = |extra: &str| {
            minimal(&format!(
                "[[evm_rpc]]\nalias = \"a\"\nurl = \"https://x.example\"\nchain_id = 1\nmethod_sets = [\"state-read\"]\n{extra}"
            ))
        };
        assert!(err(&ep("cidrs = [\"10.0.0.1/8\"]"), d).contains("host bits"));
        assert!(err(&ep("cidrs = [\"10.0.0.0/33\"]"), d).contains("above 32"));
        assert!(err(&ep("cidrs = [\"10.0.0.0/+8\"]"), d).contains("malformed"));
        assert!(err(&ep("max_concurrency = 0"), d).contains("max_concurrency"));
        assert!(err(&minimal("[[evm_rpc]]\nalias = \"a\"\nurl = \"https://x.example\"\nchain_id = 1\nmethod_sets = [\"state-write\"]"), d).contains("unknown method set"));
        assert!(err(&minimal("[[evm_rpc]]\nalias = \"a\"\nurl = \"https://x.example\"\nchain_id = 1\nmethod_sets = []"), d).contains("empty"));
        assert!(err(&minimal("[budget]\nheld_lock_share = 1.0"), d).contains("held_lock_share"));
        assert!(err(&minimal("[budget]\ninflight_bytes = 10"), d).contains("1 MiB"));
        assert!(err(&minimal("[timeouts]\nfetch_secs = 0"), d).contains("positive"));
        assert!(err(&minimal("[[blob_mirror]]\nalias = \"m\"\nurl_template = \"https://m.example/blobs\""), d).contains("{sha256}"));
        assert!(err(&minimal("[[blob_mirror]]\nalias = \"m\"\nurl_template = \"https://m.example/?h={sha256}\""), d).contains("path"));
        assert!(err(&minimal("[[blob_mirror]]\nalias = \"a b\"\nurl_template = \"https://m.example/{sha256}\""), d).contains("alias"));
        let twice = minimal("[[blob_mirror]]\nalias = \"m\"\nurl_template = \"https://m.example/{sha256}\"\n[[blob_mirror]]\nalias = \"m\"\nurl_template = \"https://n.example/{sha256}\"");
        assert!(err(&twice, d).contains("twice"));
        assert!(err("chain_rpc_host = \"x\"\nspool_dir = \"rel\"", d).contains("absolute"));
        assert!(err(&minimal("[artifacts]\nalias = \"a\"\nurl = \"https://a.example\"\nchain_id = 1\n[artifacts.mirror]\nalias = \"m\"\nurl_template = \"https://m.example/{id}\""), d).contains("{type}"));
    }

    #[test]
    fn keys_cross_the_network_only_over_https() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        write_key(d, "k", "k1", 0o600);
        let ep = |url: &str, extra: &str| {
            minimal(&format!(
                "[[evm_rpc]]\nalias = \"a\"\nurl = \"{url}\"\nchain_id = 1\nmethod_sets = [\"state-read\"]\nkey_file = \"k\"\n{extra}"
            ))
        };
        let hdr = "key_header = \"x-api-key\"";
        for (url, extra) in [
            ("http://node.example/v2/{key}", ""),
            ("http://node.example/", hdr),
            ("http://localhost:8545/", hdr),
            ("http://10.0.0.5:8545/", hdr),
            ("http://10.0.0.5:8545/", "key_header = \"x-api-key\"\ncidrs = [\"10.0.1.0/24\"]"),
            ("http://node.example/", "key_header = \"x-api-key\"\ncidrs = [\"10.0.0.5/32\"]"),
        ] {
            assert!(err(&ep(url, extra), d).contains("only over https"), "{url} {extra}");
        }
        for (url, extra) in [
            ("https://node.example/v2/{key}", ""),
            ("http://127.0.0.1:8545/v2/{key}", ""),
            ("http://[::1]:8545/", hdr),
            ("http://10.0.0.5:8545/", "key_header = \"x-api-key\"\ncidrs = [\"10.0.0.5/32\"]"),
        ] {
            assert!(BrokerConfig::from_toml(&ep(url, extra), d).is_ok(), "{url} {extra}");
        }
        // Without a key, http to a host name is the operator's choice.
        let open = minimal("[[evm_rpc]]\nalias = \"a\"\nurl = \"http://node.example/\"\nchain_id = 1\nmethod_sets = [\"state-read\"]\n");
        assert!(BrokerConfig::from_toml(&open, d).is_ok());
    }

    #[test]
    fn the_dns_table() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        let c = BrokerConfig::from_toml(&minimal(""), d).unwrap();
        assert_eq!(c.dns, DnsConfig::default());
        assert_eq!(c.dns.reresolve, Duration::from_secs(300));
        let c = BrokerConfig::from_toml(
            &minimal("[dns]\nservers = [\"9.9.9.9\", \"127.0.0.1:5353\", \"[2620:fe::fe]:53\"]\nreresolve_secs = 60"),
            d,
        )
        .unwrap();
        assert_eq!(
            c.dns.servers,
            vec!["9.9.9.9:53".parse().unwrap(), "127.0.0.1:5353".parse().unwrap(), "[2620:fe::fe]:53".parse().unwrap()]
        );
        assert_eq!(c.dns.reresolve, Duration::from_secs(60));
        assert!(err(&minimal("[dns]\nservers = [\"dns.example\"]"), d).contains("dns.servers"));
        assert!(err(&minimal("[dns]\nreresolve_secs = 0"), d).contains("positive"));
        assert!(err(&minimal("[dns]\nsearch = []"), d).contains("unknown field"));
    }

    #[test]
    fn configured_prefixes_are_cidrs_or_literals_only() {
        let dir = tempfile::tempdir().unwrap();
        let text = minimal(
            "[[evm_rpc]]\nalias = \"named\"\nurl = \"https://node.example\"\nchain_id = 1\nmethod_sets = [\"state-read\"]\n\
             [[evm_rpc]]\nalias = \"lit\"\nurl = \"http://10.0.0.5:8545\"\nchain_id = 1\nmethod_sets = [\"state-read\"]\n\
             [[evm_rpc]]\nalias = \"both\"\nurl = \"https://node2.example\"\nchain_id = 1\nmethod_sets = [\"state-read\"]\ncidrs = [\"192.168.4.0/24\"]\n",
        );
        let c = BrokerConfig::from_toml(&text, dir.path()).unwrap();
        let p = c.configured_prefixes();
        assert_eq!(p["named"], vec![]);
        assert_eq!(p["lit"], vec![host_prefix("10.0.0.5".parse().unwrap())]);
        assert_eq!(p["both"], vec![parse_cidr("192.168.4.0/24").unwrap()]);
    }

    /// The resolver queries over TCP, so its servers' ports join the sandbox's connect ports —
    /// only when some endpoint is named by host name.
    #[test]
    fn tcp_connect_ports_include_the_resolver_only_when_names_resolve() {
        let dir = tempfile::tempdir().unwrap();
        let named = "[[evm_rpc]]\nalias = \"named\"\nurl = \"https://node.example\"\nchain_id = 1\nmethod_sets = [\"state-read\"]\n";
        let literal = "[[evm_rpc]]\nalias = \"lit\"\nurl = \"http://10.0.0.5:8545\"\nchain_id = 1\nmethod_sets = [\"state-read\"]\n";
        let ports = |extra: &str| BrokerConfig::from_toml(&minimal(extra), dir.path()).unwrap().tcp_connect_ports();
        assert_eq!(ports(literal), vec![8545]);
        assert_eq!(ports(&format!("{named}{literal}")), vec![53, 443, 8545]);
        assert_eq!(
            ports(&format!("[dns]\nservers = [\"127.0.0.1:5353\", \"9.9.9.9\"]\n{named}")),
            vec![53, 443, 5353]
        );
        assert_eq!(ports(&format!("[dns]\nservers = [\"127.0.0.1:5353\"]\n{literal}")), vec![8545]);
        // Once the host facts are read (main does so before the sandbox), their servers count.
        let mut c = BrokerConfig::from_toml(&minimal(named), dir.path()).unwrap();
        c.host = Some(HostFacts { dns_servers: vec!["127.0.0.53:53".parse().unwrap()], ..Default::default() });
        assert_eq!(c.tcp_connect_ports(), vec![53, 443]);
        c.host = Some(HostFacts { dns_servers: vec!["127.0.0.1:40053".parse().unwrap()], ..Default::default() });
        assert_eq!(c.tcp_connect_ports(), vec![443, 40053]);
        c.host = Some(HostFacts::default());
        assert_eq!(c.tcp_connect_ports(), vec![443], "no server, no DNS port");
    }

    #[test]
    fn cidr_helpers() {
        let p = parse_cidr("192.168.0.0/16").unwrap();
        assert!(prefix_contains(&p, "192.168.4.5".parse().unwrap()));
        assert!(!prefix_contains(&p, "192.169.0.1".parse().unwrap()));
        assert!(!prefix_contains(&p, "::ffff:192.168.0.1".parse().unwrap()), "families never mix");
        let all = parse_cidr("0.0.0.0/0").unwrap();
        assert!(prefix_contains(&all, "8.8.8.8".parse().unwrap()));
        let v6 = parse_cidr("fd00::/8").unwrap();
        assert!(prefix_contains(&v6, "fd12::1".parse().unwrap()));
        assert_eq!(parse_cidr("::1").unwrap(), host_prefix("::1".parse().unwrap()));
    }
}
