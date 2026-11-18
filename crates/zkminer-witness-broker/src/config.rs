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
//! deny_cidrs = ["203.0.113.7/32"]   # the fleet's addresses, the VPC's ranges
//! ipv6_site_prefix_len = 32         # the site refused around each own IPv6 address (16..=64)
//! discover_public_addresses = true  # learn the NAT public addresses from fixed reflectors
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
//! head_fresh_secs = 6                           # a head this recent is at the chain's (default 36)
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
//!    configured by IP literal or explicit `cidrs`, never by name alone. Names are resolved by the
//!    miner's connector ([`crate::connector`]) with the stub resolver of [`crate::dns`] (`[dns]
//!    servers`, never `/etc/hosts`), on first use and again once `reresolve_secs` old; each answer
//!    replaces the pinned addresses. The broker itself resolves nothing.
//!
//! # Public mode and developer mode
//!
//! The broker runs in the miner's network mode, never one of its own: [`NetMode::Public`] unless
//! the miner was configured with `[dev] private_network = true`, in which case the miner starts it
//! with `--dev-private-network` ([`NetMode::DevPrivate`]). This file has no key for it (a `dev` or
//! `private_network` key is an unknown field).
//!
//! In **public mode** the configuration is refused when it loads if any endpoint (each `evm_rpc`,
//! each `blob_mirror`, `artifacts` and its `mirror`):
//!
//! - has explicit `cidrs`, or an IP-literal URL host, that is not **entirely** global (netguard's
//!   [`zkminer_netguard::prefix_is_global`]: `0.0.0.0/0`, `::/0`, `8.0.0.0/6` and
//!   `::ffff:0:0/96` hold private space and are refused), or that overlaps the deny CIDRs or a DNS
//!   server's address; and, once the host's facts are read ([`BrokerConfig::validate_host`]),
//!   that holds one of the host's own addresses or overlaps one of its connected prefixes;
//! - has a URL host name that fails netguard's host-name hygiene ([`zkminer_netguard::check_host_name`]:
//!   `localhost`, `.local`, `.internal`, `.lan`, `.test`, single-label names, …).
//!
//! A host name's answers become its role entry only where netguard's public floor admits them, in
//! both modes ([`crate::egress::EgressPolicy::dns_admissible`]). The DNS servers (`[dns] servers`,
//! else `/etc/resolv.conf`'s) are operator infrastructure the resolver dials, not a destination:
//! a loopback stub such as `127.0.0.53` stays allowed in public mode, and every DNS server address
//! joins the deny CIDRs, so no fetch connects to one.
//!
//! In **developer mode** explicitly configured role entries (`cidrs`, IP literals) may be private
//! and host names skip the hygiene rules, so a local test network serves. It is refused when any
//! `evm_rpc` or `artifacts` `chain_id` is a production chain (Hemi mainnet, 43111).
//!
//! The self-test counts only `cidrs` and IP literals as configured (in developer mode), and fails
//! when a role prefix that is not a host route (/32, /128) covers loopback, the metadata service,
//! an RFC 1918 probe, one of the host's own addresses or a connected prefix: configure local nodes
//! as host routes. In public mode it also fails when any role prefix is not public.
//!
//! The host's facts are netguard's ([`zkminer_netguard::HostFacts::gather_with`] with `[egress]
//! ipv6_site_prefix_len` and `discover_public_addresses`): own addresses with the public NAT ones,
//! connected prefixes with on-link routes, the IPv6 site, routes off the default path, and the DNS
//! servers of `/etc/resolv.conf` and systemd-resolved's upstream file, all refused in public mode
//! ([`HostFacts`]).
//!
//! An endpoint with both an IP-literal URL host and explicit `cidrs` must have the literal inside
//! the cidrs (in either mode), and in public mode the literal's host route is held to the same
//! public checks as the cidrs.
//!
//! A key travels only over `https` in public mode. In developer mode it may also travel over
//! `http` to an IP literal that is not global and is loopback or inside the endpoint's own
//! `cidrs` (a node on the operator's own wire).
//!
//! # Who loads this file
//!
//! Both processes: the miner ([`BrokerConfig::load_for_connector`], for its connector, without
//! reading key files) and the broker ([`BrokerConfig::load`]). The broker's copy serves its URLs,
//! keys and in-process checks; every connection is admitted by the miner's copy alone
//! ([`crate::connector`]), so a broker that read another file, or lies about this one, can still
//! only name the endpoints the miner loaded.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use http::header::{HeaderName, HeaderValue};
use serde::Deserialize;
use url::Url;
use zeroize::Zeroizing;
use zkminer_witness::envelope::MethodSet;

use crate::egress::{NetMode, Prefix, Role};

pub const MAX_CONFIG_FILE_BYTES: u64 = 1 << 20;
/// The default `max_concurrency` of every endpoint.
pub const DEFAULT_MAX_CONCURRENCY: u32 = 8;
/// The default `[artifacts] max_requests_per_sec`.
pub const DEFAULT_ARTIFACT_REQUESTS_PER_SEC: u32 = 2;
/// The default `[[evm_rpc]] head_fresh_secs`: three block times of a 12-second chain.
pub const DEFAULT_HEAD_FRESH_SECS: u64 = 36;
/// The largest `head_fresh_secs` accepted: an hour-old head is no evidence of a healthy node.
pub const MAX_HEAD_FRESH_SECS: u64 = 3600;
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
    /// Default [`zkminer_netguard::DEFAULT_IPV6_SITE_PREFIX_LEN`].
    #[serde(default)]
    ipv6_site_prefix_len: Option<u8>,
    /// Default true.
    #[serde(default)]
    discover_public_addresses: Option<bool>,
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

/// `[dns]`: the resolver the miner's connector uses for endpoint host names (see [`crate::dns`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsConfig {
    /// Explicit servers; empty = the nameservers of `/etc/resolv.conf` (read by the connector when
    /// it starts, and by the broker before its sandbox, into [`HostFacts::dns_servers`], to deny
    /// them as destinations).
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
    #[serde(default = "d_head_fresh")]
    head_fresh_secs: u64,
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
    DEFAULT_MAX_CONCURRENCY
}
/// Three block times of a 12-second chain (Ethereum, Hemi).
fn d_head_fresh() -> u64 {
    DEFAULT_HEAD_FRESH_SECS
}
fn d_artifact_rps() -> u32 {
    DEFAULT_ARTIFACT_REQUESTS_PER_SEC
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
    /// How recent its latest block's timestamp must be for the node to count as at the chain's head
    /// (`head_fresh_secs`, a few of the chain's block times): such a node that lacks a block or state
    /// shows the request names something not on the chain (`rpc_serve`).
    pub head_fresh: Duration,
}

#[derive(Debug, Clone)]
pub struct ArtifactsSpec {
    pub spec: EndpointSpec,
    pub chain_id: u64,
    pub max_builder_bytes: u64,
    /// The operator artifact mirror (`{type}`, `{id}`).
    pub mirror: Option<EndpointSpec>,
}

/// Facts about the host the sandboxed broker cannot read itself, for its own (second-layer) floor:
/// the DNS servers, the prefixes the host's facts refuse and the host's own addresses. `main`
/// reads them before `restrict_self`; [`crate::serve`] reads them itself when they are absent
/// (tests). The broker resolves no names: the miner's connector does ([`crate::connector`]).
#[derive(Debug, Clone, Default)]
pub struct HostFacts {
    /// Every prefix netguard's facts refuse ([`zkminer_netguard::HostFacts::refused_prefixes`]):
    /// connected prefixes (interfaces and on-link routes), the IPv6 site, routes off the default
    /// path and the host's DNS servers.
    pub connected: Vec<Prefix>,
    /// The host's own addresses, its public (NAT) addresses included.
    pub own_addresses: Vec<IpAddr>,
    /// The servers the connector resolves host names with: `[dns] servers`, else
    /// `/etc/resolv.conf`'s. Denied as destinations.
    pub dns_servers: Vec<SocketAddr>,
    /// Every DNS server the host itself uses (`/etc/resolv.conf`, systemd-resolved's upstream
    /// servers behind its stub): denied like `dns_servers`.
    pub resolvers: Vec<IpAddr>,
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
    /// The miner's network mode (never from this file): see the module doc.
    pub net_mode: NetMode,
    /// How the host's facts are gathered (`[egress] ipv6_site_prefix_len`,
    /// `discover_public_addresses`).
    pub facts_options: zkminer_netguard::FactsOptions,
}

impl BrokerConfig {
    /// Reads and validates the config file and every key file it names (relative key paths are
    /// taken from the config file's directory).
    pub fn load(path: &Path, net_mode: NetMode) -> Result<Self, ConfigError> {
        let (text, base) = read_file(path)?;
        Self::from_toml(&text, base, net_mode)
    }

    /// Parses and validates a config in `net_mode`, reading key files relative to `base_dir`.
    pub fn from_toml(text: &str, base_dir: &Path, net_mode: NetMode) -> Result<Self, ConfigError> {
        let file: FileConfig = toml::from_str(text).map_err(|e| ConfigError::Parse(e.message().to_string()))?;
        validate(file, base_dir, net_mode, Keys::Read)
    }

    /// The miner's load, for its connector ([`crate::connector::Connector::for_miner`]): the same
    /// parse and the same validation in the miner's `net_mode` — every endpoint, role entry and
    /// public-mode check — except that no key file is read (the miner never holds a provider key;
    /// a key's presence still counts, so a key over `http` is refused as in [`Self::load`]). The
    /// connector takes only what it needs from the result (roles, hosts, literals, ports, cidrs,
    /// limits, `[dns]`, `[egress]`, timeouts) and never anything from the broker.
    pub fn load_for_connector(path: &Path, net_mode: NetMode) -> Result<Self, ConfigError> {
        let (text, base) = read_file(path)?;
        Self::from_toml_for_connector(&text, base, net_mode)
    }

    /// [`Self::load_for_connector`] from text.
    pub fn from_toml_for_connector(text: &str, base_dir: &Path, net_mode: NetMode) -> Result<Self, ConfigError> {
        let file: FileConfig = toml::from_str(text).map_err(|e| ConfigError::Parse(e.message().to_string()))?;
        validate(file, base_dir, net_mode, Keys::Skip)
    }

    /// The prefixes an endpoint's role entry is configured as: its explicit `cidrs`, else its IP
    /// literal's host route, else none (a host name: DNS-derived, judged at every answer).
    pub fn role_prefixes(e: &EndpointSpec) -> Vec<Prefix> {
        if !e.cidrs.is_empty() {
            e.cidrs.clone()
        } else {
            e.literal.map(Prefix::host).into_iter().collect()
        }
    }

    /// The deny CIDRs the floor enforces: the operator's, plus a host route for every DNS server
    /// the resolver dials (`dns_servers`), so no fetch connects to one.
    pub fn effective_deny(&self, dns_servers: &[SocketAddr]) -> Vec<Prefix> {
        let mut deny = self.deny.clone();
        for s in dns_servers {
            let p = Prefix::host(s.ip());
            if !deny.contains(&p) {
                deny.push(p);
            }
        }
        deny
    }

    /// [`Self::effective_deny`] with the host's facts: every server the broker's resolver dials and
    /// every DNS server the host itself uses ([`HostFacts::resolvers`]).
    pub fn effective_deny_for(&self, host: &HostFacts) -> Vec<Prefix> {
        let mut deny = self.effective_deny(&host.dns_servers);
        for r in &host.resolvers {
            let p = Prefix::host(*r);
            if !deny.contains(&p) {
                deny.push(p);
            }
        }
        deny
    }

    /// In public mode, refuses a role entry that holds one of the host's own addresses or overlaps
    /// one of the prefixes its facts refuse, the deny CIDRs or a DNS server (the checks the config
    /// file alone cannot make). Nothing in developer mode.
    pub fn validate_host(&self, host: &HostFacts) -> Result<(), ConfigError> {
        if self.net_mode != NetMode::Public {
            return Ok(());
        }
        let facts = zkminer_netguard::HostFacts::new(host.connected.clone(), host.own_addresses.clone());
        check_roles_public(self, &facts, &self.effective_deny_for(host))
    }

    /// Every endpoint, in a fixed order: evm-rpc, blob mirrors, the artifact endpoint, its mirror.
    pub fn endpoints(&self) -> impl Iterator<Item = &EndpointSpec> {
        self.evm_rpc
            .iter()
            .map(|e| &e.spec)
            .chain(self.blob_mirrors.iter())
            .chain(self.artifacts.iter().flat_map(|a| std::iter::once(&a.spec).chain(a.mirror.iter())))
    }

    /// The bytes reserved for held-lock work.
    pub fn held_lock_reserved_bytes(&self) -> u64 {
        ((self.budget.inflight_bytes as f64) * self.budget.held_lock_share) as u64
    }

    /// What the operator configured each endpoint's role entry as, by alias: its explicit `cidrs`,
    /// else its IP literal's host route, else nothing (a host name: DNS-derived, never counted as
    /// configured by the self-test).
    pub fn configured_prefixes(&self) -> HashMap<String, Vec<Prefix>> {
        self.endpoints().map(|e| (e.alias.clone(), Self::role_prefixes(e))).collect()
    }
}

/// Public mode: every endpoint's host name passes netguard's hygiene and every configured role
/// prefix passes [`zkminer_netguard::admit_prefix`] against `facts` and `deny`.
fn check_roles_public(cfg: &BrokerConfig, facts: &zkminer_netguard::HostFacts, deny: &[Prefix]) -> Result<(), ConfigError> {
    for e in cfg.endpoints() {
        if e.literal.is_none() {
            zkminer_netguard::check_host_name(&e.host).map_err(|why| {
                ConfigError::Invalid(format!(
                    "{}: {} (outside developer mode an endpoint is named only by a public host name)",
                    e.alias,
                    zkminer_netguard::Denied::Host { host: e.host.clone(), why }
                ))
            })?;
        }
        // The role entry, and an IP-literal host's own host route even when explicit cidrs are the
        // role entry (review r1 broker F4: a loopback literal with global cidrs loaded).
        for p in BrokerConfig::role_prefixes(e).into_iter().chain(e.literal.map(Prefix::host)) {
            zkminer_netguard::admit_prefix(NetMode::Public, p, facts, deny).map_err(|d| {
                ConfigError::Invalid(format!(
                    "{}: role entry {p}: {d} (outside developer mode an endpoint must be on the public internet)",
                    e.alias
                ))
            })?;
        }
    }
    Ok(())
}

/// Whether key files are read ([`BrokerConfig::load`], the broker) or only their presence counts
/// ([`BrokerConfig::load_for_connector`], the miner).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Keys {
    Read,
    Skip,
}

fn read_file(path: &Path) -> Result<(String, &Path), ConfigError> {
    let io = |source| ConfigError::Io { path: path.to_path_buf(), source };
    let meta = std::fs::metadata(path).map_err(io)?;
    if meta.len() > MAX_CONFIG_FILE_BYTES {
        return invalid("config file larger than 1 MiB");
    }
    let text = std::fs::read_to_string(path).map_err(io)?;
    Ok((text, path.parent().unwrap_or(Path::new("/"))))
}

fn validate(f: FileConfig, base: &Path, net_mode: NetMode, keys: Keys) -> Result<BrokerConfig, ConfigError> {
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
    let facts_options = zkminer_netguard::FactsOptions {
        ipv6_site_prefix_len: f.egress.ipv6_site_prefix_len.unwrap_or(zkminer_netguard::DEFAULT_IPV6_SITE_PREFIX_LEN),
        discover_public_addresses: f.egress.discover_public_addresses.unwrap_or(true),
        ..zkminer_netguard::FactsOptions::default()
    };
    facts_options.validate().map_err(|e| ConfigError::Invalid(format!("egress.{e}")))?;
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
            net_mode,
            keys,
        )?;
        if !(1..=MAX_HEAD_FRESH_SECS).contains(&e.head_fresh_secs) {
            return invalid(format!(
                "{}: head_fresh_secs must be within 1..={MAX_HEAD_FRESH_SECS}",
                e.alias
            ));
        }
        evm_rpc.push(EvmRpcEndpoint {
            spec,
            chain_id: e.chain_id,
            archive: e.archive,
            max_proof_age: e.max_proof_age,
            method_sets,
            head_fresh: Duration::from_secs(e.head_fresh_secs),
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
                net_mode,
                keys,
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
        net_mode,
        facts_options,
    };
    // §11.1: never an endpoint on the miner's chain-RPC host.
    for e in cfg.endpoints() {
        if e.host == cfg.chain_rpc_host {
            return invalid(format!("{}: its host is chain_rpc_host (the miner's chain RPC); use a separate endpoint", e.alias));
        }
        // An IP literal outside its own explicit cidrs could never be connected to (the cidrs are
        // the role entry), and in public mode its own address would escape the checks.
        if let Some(ip) = e.literal {
            if !e.cidrs.is_empty() && !e.cidrs.iter().any(|p| p.contains(ip)) {
                return invalid(format!("{}: the URL's IP literal {ip} is outside the endpoint's cidrs", e.alias));
            }
        }
    }
    match net_mode {
        NetMode::Public => {
            // The host's own facts are checked once read (`validate_host`); the file's deny CIDRs
            // and explicit DNS servers now.
            check_roles_public(&cfg, &zkminer_netguard::HostFacts::empty(), &cfg.effective_deny(&cfg.dns.servers))?;
        }
        NetMode::DevPrivate => {
            let chains = cfg.evm_rpc.iter().map(|e| e.chain_id).chain(cfg.artifacts.iter().map(|a| a.chain_id));
            if let Some(id) = chains.into_iter().find(|id| zkminer_netguard::is_production_chain(*id)) {
                return invalid(format!(
                    "developer mode (--dev-private-network, from the miner's [dev] private_network) is refused: \
                     an endpoint serves chain {id}, a production chain"
                ));
            }
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
    net_mode: NetMode,
    keys: Keys,
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
            match keys {
                Keys::Read => Some(read_key(alias, &path)?),
                // A stand-in that passes every check a real key must (the broker reads the real
                // one and checks it again).
                Keys::Skip => Some(Secret(Zeroizing::new("zkminer-unread-key".to_string()))),
            }
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
    // A key never crosses a network in clear text. In public mode every endpoint is on the public
    // internet, so a key travels only over https (review r1 broker F5: a global literal inside its
    // own cidrs took a key over http). In developer mode, http also to a loopback IP literal or one
    // inside the endpoint's own explicit cidrs (a node on the operator's own wire); never to a
    // host name.
    if key.is_some() && parsed.scheme() == "http" {
        if net_mode == NetMode::Public {
            return invalid(format!("{alias}: a key is sent only over https outside developer mode"));
        }
        // Review r2 B3: on the operator's own wire means not global, whatever the cidrs say
        // (`0.0.0.0/0` or a public /32 would otherwise send the key in clear to the internet).
        let local = literal.is_some_and(|ip| {
            let c = crate::egress::canonical_ip(ip);
            !zkminer_netguard::is_global(ip) && (c.is_loopback() || cidrs.iter().any(|p| p.contains(ip)))
        });
        if !local {
            return invalid(format!(
                "{alias}: a key is sent only over https (or http to a loopback IP literal, or a non-global one inside the endpoint's cidrs)"
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

/// The host the broker's `chain_rpc_host` names for a chain RPC URL (or host): normalized like an
/// endpoint host, so the miner can hold the file's value to its own `[chain] rpc_url`.
pub fn chain_rpc_host_of(url: &str) -> Option<String> {
    normalize_host_input(url)
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
/// netguard's parser ([`Prefix`]'s `FromStr`).
pub fn parse_cidr(s: &str) -> Result<Prefix, String> {
    s.parse::<Prefix>().map_err(|e| e.to_string())
}

/// The host prefix of `ip`.
pub fn host_prefix(ip: IpAddr) -> Prefix {
    Prefix::host(ip)
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

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Most tests parse configs with private test addresses: developer mode.
    fn dev_toml(text: &str, dir: &Path) -> Result<BrokerConfig, ConfigError> {
        BrokerConfig::from_toml(text, dir, NetMode::DevPrivate)
    }

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
head_fresh_secs = 6
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
        let c = dev_toml(&example(dir.path()), dir.path()).unwrap();
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
        // A head this recent is at the chain's: the entry's own, else three 12-second blocks.
        assert_eq!(
            (e.head_fresh, h.head_fresh),
            (Duration::from_secs(6), Duration::from_secs(36))
        );
        let ep = "[[evm_rpc]]\nalias = \"a\"\nurl = \"https://x.example\"\nchain_id = 1\nmethod_sets = [\"state-read\"]\n";
        for bad in ["0", "3601"] {
            assert!(err(
                &minimal(&format!("{ep}head_fresh_secs = {bad}")),
                dir.path()
            )
            .contains("head_fresh_secs"));
        }
        let a = c.artifacts.as_ref().unwrap();
        assert_eq!((a.chain_id, a.max_builder_bytes, a.spec.max_requests_per_sec), (743111, 4 << 20, Some(2)));
        assert_eq!(a.spec.cidrs, vec![host_prefix("10.0.0.5".parse().unwrap())]);
        let m = a.mirror.as_ref().unwrap();
        assert_eq!(m.url_with(&[("type", "1"), ("id", "ab")]), "https://mirror.example/artifacts/1/ab");
        assert_eq!(c.blob_mirrors[0].url_with(&[("sha256", "ff")]), "https://mirror.example/blobs/ff");
        assert_eq!(c.held_lock_reserved_bytes(), 64 << 20);
    }

    fn minimal(extra: &str) -> String {
        format!("chain_rpc_host = \"rpc.hemi.network\"\nspool_dir = \"/tmp/spool\"\n{extra}")
    }

    fn err(text: &str, dir: &Path) -> String {
        match dev_toml(text, dir) {
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
        assert!(dev_toml(&minimal(ep), dir.path()).is_ok());
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
        let c = dev_toml(&ep("https://x.example/a/{key}", "key_file = \"ok.key\""), d).unwrap();
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
        assert!(err(&ep("cidrs = [\"10.0.0.0/33\"]"), d).contains("above"));
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
            // Review r2 B3: a global literal is never the operator's own wire, whatever its cidrs.
            ("http://1.1.1.1:8545/v1/{key}", "cidrs = [\"0.0.0.0/0\"]"),
            ("http://1.1.1.1:8545/v1/{key}", "cidrs = [\"1.1.1.1/32\"]"),
            ("http://[2606:4700:4700::1111]:8545/v1/{key}", "cidrs = [\"::/0\"]"),
            ("http://[::ffff:1.1.1.1]:8545/", "key_header = \"x-api-key\"\ncidrs = [\"::ffff:0:0/96\"]"),
        ] {
            assert!(err(&ep(url, extra), d).contains("only over https"), "{url} {extra}");
        }
        for (url, extra) in [
            ("https://node.example/v2/{key}", ""),
            ("http://127.0.0.1:8545/v2/{key}", ""),
            ("http://[::1]:8545/", hdr),
            ("http://10.0.0.5:8545/", "key_header = \"x-api-key\"\ncidrs = [\"10.0.0.5/32\"]"),
        ] {
            assert!(dev_toml(&ep(url, extra), d).is_ok(), "{url} {extra}");
        }
        // Without a key, http to a host name is the operator's choice.
        let open = minimal("[[evm_rpc]]\nalias = \"a\"\nurl = \"http://node.example/\"\nchain_id = 1\nmethod_sets = [\"state-read\"]\n");
        assert!(dev_toml(&open, d).is_ok());
    }

    #[test]
    fn the_dns_table() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        let c = dev_toml(&minimal(""), d).unwrap();
        assert_eq!(c.dns, DnsConfig::default());
        assert_eq!(c.dns.reresolve, Duration::from_secs(300));
        let c = dev_toml(
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
        let c = dev_toml(&text, dir.path()).unwrap();
        let p = c.configured_prefixes();
        assert_eq!(p["named"], vec![]);
        assert_eq!(p["lit"], vec![host_prefix("10.0.0.5".parse().unwrap())]);
        assert_eq!(p["both"], vec![parse_cidr("192.168.4.0/24").unwrap()]);
    }

    /// The miner's load reads no key file (a missing one included) but applies every other rule,
    /// a key's presence too: the same endpoints in the same order as the broker's load.
    #[test]
    fn the_connectors_load_reads_no_key() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        let text = example(d);
        let full = dev_toml(&text, d).unwrap();
        std::fs::remove_file(d.join("base.key")).unwrap();
        std::fs::remove_file(d.join("hdr.key")).unwrap();
        assert!(dev_toml(&text, d).is_err(), "the broker's load reads the keys");
        let miner = BrokerConfig::from_toml_for_connector(&text, d, NetMode::DevPrivate).unwrap();
        let ids = |c: &BrokerConfig| c.endpoints().map(|e| (e.role, e.alias.clone(), e.host.clone(), e.port, e.cidrs.clone())).collect::<Vec<_>>();
        assert_eq!(ids(&miner), ids(&full));
        assert!(miner.evm_rpc.iter().all(|e| !e.spec.url().contains("abcDEF")), "no key in the miner's copy");
        // A key over http is refused in public mode even when the key is not read.
        let http = minimal("[[evm_rpc]]\nalias = \"a\"\nurl = \"http://node.example.com/v2/{key}\"\nchain_id = 1\nmethod_sets = [\"state-read\"]\nkey_file = \"nope\"\n");
        let e = BrokerConfig::from_toml_for_connector(&http, d, NetMode::Public).unwrap_err().to_string();
        assert!(e.contains("only over https"), "{e}");
    }

    fn public_err(text: &str) -> String {
        let dir = tempfile::tempdir().unwrap();
        match BrokerConfig::from_toml(text, dir.path(), NetMode::Public) {
            Ok(_) => panic!("accepted in public mode:\n{text}"),
            Err(e) => e.to_string(),
        }
    }

    /// Every role's endpoint, as the TOML that configures it with `url` and `extra` lines.
    fn role_tables(url: &str, extra: &str) -> [(&'static str, String); 4] {
        // A mirror's template needs its placeholders in the path.
        let mirror_url = |slots: &str| format!("{}/{slots}", url.trim_end_matches('/'));
        [
            ("evm_rpc", format!("[[evm_rpc]]\nalias = \"a\"\nurl = \"{url}\"\nchain_id = 1\nmethod_sets = [\"state-read\"]\n{extra}\n")),
            ("blob_mirror", format!("[[blob_mirror]]\nalias = \"a\"\nurl_template = \"{}\"\n{extra}\n", mirror_url("{sha256}"))),
            ("artifacts", format!("[artifacts]\nalias = \"a\"\nurl = \"{url}\"\nchain_id = 1\n{extra}\n")),
            (
                "artifacts.mirror",
                format!(
                    "[artifacts]\nalias = \"p\"\nurl = \"https://artifacts.example.com\"\nchain_id = 1\n[artifacts.mirror]\nalias = \"a\"\nurl_template = \"{}\"\n{extra}\n",
                    mirror_url("{type}/{id}")
                ),
            ),
        ]
    }

    /// Public mode refuses, for every role, a configured address or CIDR that is not entirely
    /// global and a host name that fails netguard's hygiene; developer mode accepts the same.
    #[test]
    fn public_mode_refuses_non_public_role_entries_for_every_role() {
        let refused = [
            // IP-literal hosts.
            ("http://127.0.0.1:8545", "", "not on the public internet"),
            ("http://10.0.0.5:8545", "", "not on the public internet"),
            ("http://169.254.169.254", "", "not on the public internet"),
            ("http://[::1]:8545", "", "not on the public internet"),
            ("http://[::ffff:127.0.0.1]:8545", "", "not on the public internet"),
            ("http://[fd00:ec2::254]", "", "not on the public internet"),
            ("http://[64:ff9b::a00:5]", "", "not on the public internet"),
            ("http://192.0.2.10", "", "not on the public internet"),
            // Explicit cidrs: whole prefixes, judged entirely.
            ("https://node.example.com", "cidrs = [\"0.0.0.0/0\"]", "not on the public internet"),
            ("https://node.example.com", "cidrs = [\"::/0\"]", "not on the public internet"),
            ("https://node.example.com", "cidrs = [\"172.0.0.0/8\"]", "not on the public internet"), // holds 172.16/12
            ("https://node.example.com", "cidrs = [\"100.0.0.0/8\"]", "not on the public internet"), // holds CGNAT
            ("https://node.example.com", "cidrs = [\"8.0.0.0/6\"]", "not on the public internet"),   // holds 10/8
            ("https://node.example.com", "cidrs = [\"::ffff:0:0/96\"]", "not on the public internet"),
            ("https://node.example.com", "cidrs = [\"1.1.1.0/24\", \"10.0.0.5/32\"]", "10.0.0.5/32"),
            ("http://127.0.0.1:8545", "cidrs = [\"127.0.0.0/8\"]", "not on the public internet"),
            // Host names.
            ("http://localhost:8545", "", "single label"),
            ("http://node:8545", "", "single label"),
            ("http://node.local:8545", "", ".local"),
            ("http://metadata.google.internal", "", ".internal"),
            ("http://nas.lan:8545", "", ".lan"),
            ("http://anvil.test:8545", "", ".test"),
            ("http://kubernetes.default.svc", "", ".svc"),
            ("http://foo.localhost", "", ".localhost"),
        ];
        for (url, extra, why) in refused {
            for (role, table) in role_tables(url, extra) {
                let text = minimal(&table);
                let e = public_err(&text);
                assert!(e.contains(why) && e.contains("a:"), "{role} {url} {extra}: {e}");
                let dir = tempfile::tempdir().unwrap();
                let c = BrokerConfig::from_toml(&text, dir.path(), NetMode::DevPrivate)
                    .unwrap_or_else(|e| panic!("developer mode refused {role} {url} {extra}: {e}"));
                assert_eq!(c.net_mode, NetMode::DevPrivate);
            }
        }
        // Public endpoints pass in public mode.
        for (url, extra) in [
            ("https://node.example.com", ""),
            ("https://1.1.1.1", ""),
            ("https://[2606:4700:4700::1111]", ""),
            ("https://node.example.com", "cidrs = [\"1.1.1.0/24\", \"2606:4700::/32\"]"),
            ("https://node.example.com", "cidrs = [\"8.0.0.0/7\"]"),
            ("https://node.example.com", "cidrs = [\"64:ff9b::808:800/120\"]"),
        ] {
            for (role, table) in role_tables(url, extra) {
                let dir = tempfile::tempdir().unwrap();
                let c = BrokerConfig::from_toml(&minimal(&table), dir.path(), NetMode::Public)
                    .unwrap_or_else(|e| panic!("public mode refused {role} {url} {extra}: {e}"));
                assert_eq!(c.net_mode, NetMode::Public);
            }
        }
    }

    /// The deny CIDRs and the DNS servers are no destination: a role entry overlapping either is
    /// refused in public mode, and a loopback DNS stub is itself allowed.
    #[test]
    fn public_mode_refuses_role_entries_on_denied_or_dns_server_addresses() {
        let ep = |extra: &str| {
            format!("[[evm_rpc]]\nalias = \"a\"\nurl = \"https://node.example.com\"\nchain_id = 1\nmethod_sets = [\"state-read\"]\n{extra}\n")
        };
        let e = public_err(&minimal(&format!("[egress]\ndeny_cidrs = [\"1.1.0.0/16\"]\n{}", ep("cidrs = [\"1.1.1.0/24\"]"))));
        assert!(e.contains("deny CIDR 1.1.0.0/16"), "{e}");
        let e = public_err(&minimal(&format!("[dns]\nservers = [\"1.1.1.1\"]\n{}", ep("cidrs = [\"1.1.1.0/24\"]"))));
        assert!(e.contains("deny CIDR 1.1.1.1/32"), "{e}");
        let e = public_err(&minimal(&format!("[dns]\nservers = [\"[2606:4700:4700::1111]:53\"]\n{}", ep("cidrs = [\"2606:4700::/32\"]"))));
        assert!(e.contains("2606:4700:4700::1111/128"), "{e}");
        let dir = tempfile::tempdir().unwrap();
        let c = BrokerConfig::from_toml(&minimal(&format!("[dns]\nservers = [\"127.0.0.53\"]\n{}", ep(""))), dir.path(), NetMode::Public)
            .expect("a loopback DNS stub is operator infrastructure, not a destination");
        assert_eq!(c.effective_deny(&c.dns.servers), vec![parse_cidr("127.0.0.53/32").unwrap()]);
    }

    /// Once the host's facts are known: a role entry holding an own address or overlapping a
    /// connected prefix (or a DNS server from `/etc/resolv.conf`) is refused in public mode only.
    #[test]
    fn public_mode_refuses_role_entries_on_the_hosts_own_networks() {
        let text = minimal(
            "[[evm_rpc]]\nalias = \"wide\"\nurl = \"https://node.example.com\"\nchain_id = 1\nmethod_sets = [\"state-read\"]\ncidrs = [\"9.9.0.0/16\"]\n\
             [[blob_mirror]]\nalias = \"lit\"\nurl_template = \"https://1.1.1.1/{sha256}\"\n",
        );
        let dir = tempfile::tempdir().unwrap();
        let c = BrokerConfig::from_toml(&text, dir.path(), NetMode::Public).unwrap();
        let host = |connected: &[&str], own: &[&str], dns: &[&str]| HostFacts {
            connected: connected.iter().map(|s| parse_cidr(s).unwrap()).collect(),
            own_addresses: own.iter().map(|s| s.parse().unwrap()).collect(),
            dns_servers: dns.iter().map(|s| s.parse().unwrap()).collect(),
            resolvers: Vec::new(),
        };
        assert!(c.validate_host(&host(&["127.0.0.0/8", "192.168.1.0/24"], &["127.0.0.1", "192.168.1.10"], &["127.0.0.53:53"])).is_ok());
        for (h, why) in [
            (host(&["9.9.9.0/24"], &[], &[]), "a network this host is connected to"),
            (host(&["9.0.0.0/8"], &[], &[]), "a network this host is connected to"),
            (host(&[], &["9.9.200.1"], &[]), "this host's own address"),
            (host(&[], &["1.1.1.1"], &[]), "this host's own address"),
            (host(&[], &[], &["1.1.1.1:53"]), "deny CIDR 1.1.1.1/32"),
            (host(&["::ffff:9.9.9.0/120"], &[], &[]), "connected"),
        ] {
            let e = c.validate_host(&h).expect_err(why).to_string();
            assert!(e.contains(why), "{e}");
        }
        let dev = BrokerConfig::from_toml(&text, dir.path(), NetMode::DevPrivate).unwrap();
        assert!(dev.validate_host(&host(&["9.9.9.0/24"], &["1.1.1.1"], &["1.1.1.1:53"])).is_ok());
    }

    /// Review r1 broker F4 (PoC t1): with explicit `cidrs`, an IP-literal URL host was never
    /// checked, so a loopback literal with global cidrs loaded in public mode. The literal must be
    /// inside the cidrs (either mode), and in public mode its host route is judged too.
    #[test]
    fn an_ip_literal_must_be_inside_its_cidrs_and_public() {
        let dir = tempfile::tempdir().unwrap();
        let ep = |url: &str, cidrs: &str| {
            minimal(&format!(
                "[[evm_rpc]]\nalias = \"x\"\nurl = \"{url}\"\nchain_id = 8453\nmethod_sets = [\"state-read\"]\ncidrs = [{cidrs}]\n"
            ))
        };
        for (url, cidrs) in [
            ("http://127.0.0.1:36749/", "\"1.1.1.0/24\""),
            ("http://[::1]:8545/", "\"2606:4700:4700::/48\""),
            ("http://1.0.0.1:8545/", "\"1.1.1.0/24\""),
        ] {
            for mode in [NetMode::Public, NetMode::DevPrivate] {
                let e = BrokerConfig::from_toml(&ep(url, cidrs), dir.path(), mode).expect_err(url).to_string();
                assert!(e.contains("outside the endpoint's cidrs"), "{mode:?} {url}: {e}");
            }
        }
        // A literal inside its cidrs, in any spelling, loads.
        for (url, cidrs) in [("http://1.1.1.1:8545/", "\"1.1.1.0/24\""), ("http://[::ffff:1.1.1.1]:8545/", "\"1.1.1.0/24\"")] {
            let c = BrokerConfig::from_toml(&ep(url, cidrs), dir.path(), NetMode::Public).unwrap();
            // ...and once the host owns that address, the literal's host route is refused too.
            let host = HostFacts { own_addresses: vec!["1.1.1.1".parse().unwrap()], ..Default::default() };
            let e = c.validate_host(&host).expect_err(url).to_string();
            assert!(e.contains("this host's own address"), "{e}");
        }
    }

    /// Review r1 broker F5 (PoC t2): in public mode a key travels only over https, even to a
    /// global IP literal inside the endpoint's own cidrs.
    #[test]
    fn public_mode_sends_keys_only_over_https() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        write_key(d, "k", "SECRETKEY123", 0o600);
        for (url, extra) in [
            ("http://1.1.1.1:8545/v1/{key}", "cidrs = [\"1.1.1.1/32\"]"),
            ("http://1.1.1.1:8545/", "key_header = \"x-api-key\"\ncidrs = [\"1.1.1.0/24\"]"),
        ] {
            let text = minimal(&format!(
                "[[evm_rpc]]\nalias = \"p\"\nurl = \"{url}\"\nchain_id = 8453\nmethod_sets = [\"state-read\"]\nkey_file = \"k\"\n{extra}\n"
            ));
            let e = BrokerConfig::from_toml(&text, d, NetMode::Public).expect_err(url).to_string();
            assert!(e.contains("only over https outside developer mode"), "{e}");
            // Review r2 B3: a global literal is not the operator's own wire in developer mode
            // either.
            let e = BrokerConfig::from_toml(&text, d, NetMode::DevPrivate).expect_err(url).to_string();
            assert!(e.contains("only over https"), "{e}");
            let https = text.replace("http://", "https://");
            let c = BrokerConfig::from_toml(&https, d, NetMode::Public).unwrap();
            assert!(c.evm_rpc[0].spec.key_bearing);
        }
    }

    /// Review r1 (fetch F1b, F1c, I1): `[egress] ipv6_site_prefix_len` and
    /// `discover_public_addresses` reach the facts options; a DNS server the host itself uses
    /// (systemd-resolved's upstream ones) is denied like the resolver's own.
    #[test]
    fn egress_facts_options_and_host_resolvers() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        let c = dev_toml(&minimal(""), d).unwrap();
        assert_eq!(c.facts_options, zkminer_netguard::FactsOptions::default());
        let c = dev_toml(&minimal("[egress]\nipv6_site_prefix_len = 56\ndiscover_public_addresses = false"), d).unwrap();
        assert_eq!(c.facts_options.ipv6_site_prefix_len, 56);
        assert!(!c.facts_options.discover_public_addresses);
        for bad in ["15", "65", "0"] {
            let e = err(&minimal(&format!("[egress]\nipv6_site_prefix_len = {bad}")), d);
            assert!(e.contains("ipv6_site_prefix_len"), "{e}");
        }
        let text = minimal("[[blob_mirror]]\nalias = \"m\"\nurl_template = \"https://9.9.9.9/{sha256}\"\n");
        let c = BrokerConfig::from_toml(&text, d, NetMode::Public).unwrap();
        let host = HostFacts { resolvers: vec!["9.9.9.9".parse().unwrap()], ..Default::default() };
        assert!(c.effective_deny_for(&host).contains(&parse_cidr("9.9.9.9/32").unwrap()));
        let e = c.validate_host(&host).unwrap_err().to_string();
        assert!(e.contains("deny CIDR 9.9.9.9/32"), "{e}");
    }

    /// The mode comes only from the miner: the file has no key for it.
    #[test]
    fn the_file_has_no_developer_mode_key() {
        for text in [
            minimal("dev = true"),
            minimal("private_network = true"),
            minimal("dev_private_network = true"),
            minimal("[dev]\nprivate_network = true"),
            minimal("[egress]\nprivate_network = true"),
        ] {
            for mode in [NetMode::Public, NetMode::DevPrivate] {
                let dir = tempfile::tempdir().unwrap();
                let e = BrokerConfig::from_toml(&text, dir.path(), mode).expect_err(&text).to_string();
                assert!(e.contains("unknown field"), "{text}: {e}");
            }
        }
    }

    /// Developer mode is refused when any endpoint serves a production chain (Hemi mainnet).
    #[test]
    fn developer_mode_is_refused_with_a_mainnet_endpoint() {
        let dir = tempfile::tempdir().unwrap();
        for text in [
            minimal("[[evm_rpc]]\nalias = \"a\"\nurl = \"http://127.0.0.1:8545\"\nchain_id = 43111\nmethod_sets = [\"state-read\"]\n"),
            minimal("[[evm_rpc]]\nalias = \"a\"\nurl = \"http://127.0.0.1:8545\"\nchain_id = 1\nmethod_sets = [\"state-read\"]\n[[evm_rpc]]\nalias = \"b\"\nurl = \"https://rpc.example.com\"\nchain_id = 43111\nmethod_sets = [\"state-read\"]\n"),
            minimal("[artifacts]\nalias = \"a\"\nurl = \"http://127.0.0.1:8545\"\nchain_id = 43111\n"),
        ] {
            let e = BrokerConfig::from_toml(&text, dir.path(), NetMode::DevPrivate).expect_err(&text).to_string();
            assert!(e.contains("developer mode") && e.contains("43111"), "{e}");
        }
        // A mainnet endpoint is fine in public mode, on the public internet.
        let ok = minimal("[[evm_rpc]]\nalias = \"a\"\nurl = \"https://rpc.example.com\"\nchain_id = 43111\nmethod_sets = [\"state-read\"]\n");
        assert!(BrokerConfig::from_toml(&ok, dir.path(), NetMode::Public).is_ok());
    }

    #[test]
    fn cidr_helpers() {
        let p = parse_cidr("192.168.0.0/16").unwrap();
        assert!(p.contains("192.168.4.5".parse().unwrap()));
        assert!(!p.contains("192.169.0.1".parse().unwrap()));
        assert!(p.contains("::ffff:192.168.0.1".parse().unwrap()), "a mapped address is its IPv4 address");
        let all = parse_cidr("0.0.0.0/0").unwrap();
        assert!(all.contains("8.8.8.8".parse().unwrap()));
        let v6 = parse_cidr("fd00::/8").unwrap();
        assert!(v6.contains("fd12::1".parse().unwrap()));
        assert_eq!(parse_cidr("::1").unwrap(), host_prefix("::1".parse().unwrap()));
    }
}
