//! The egress wiring (plan §14.2): one reqwest client per operator endpoint, whose DNS resolver
//! returns only addresses the network floor admits for that endpoint's role and alias, pinned for
//! the request. No proxy, no redirects, no `Referer`, no decompression, a constant User-Agent;
//! endpoints are logged by alias and errors pass through `redact_urls(sanitize_log(…))`.
//!
//! Hosts are resolved once: at startup, before the sandbox (see [`crate::config::HostFacts`]). A
//! host that did not resolve then is retried lazily, at most every [`RERESOLVE_EVERY`], through
//! the system resolver (`getaddrinfo`, which the sandbox allows); an endpoint without explicit
//! CIDRs then gets those addresses as its role entry. IP-literal hosts never reach a resolver (hyper
//! connects to them directly), so [`Endpoint`] checks the floor itself before every request.

use std::error::Error as _;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use reqwest::header::CONTENT_TYPE;

use crate::config::{host_prefix, EndpointSpec, TimeoutConfig};
use crate::egress::{Admit, EgressPolicy, Prefix, Role, RoleEntry};
use crate::hooks::EgressHooks;
use crate::lanes::{Lanes, Pacer, TokenBucket};

/// The shared, refreshable policy.
pub type PolicyHandle = Arc<RwLock<EgressPolicy>>;

/// How often an unresolved host is retried.
pub const RERESOLVE_EVERY: Duration = Duration::from_secs(10);

const USER_AGENT: &str = "zkminer-witness-broker";

/// Builds the policy: one role entry per endpoint (its configured CIDRs, else the addresses its
/// host resolved to), the operator deny CIDRs and the connected prefixes.
pub fn build_policy<'a>(
    endpoints: impl Iterator<Item = &'a EndpointSpec>,
    resolved: &std::collections::HashMap<String, Vec<IpAddr>>,
    deny: Vec<Prefix>,
    connected: Vec<Prefix>,
) -> EgressPolicy {
    let roles = endpoints
        .map(|e| RoleEntry {
            role: e.role,
            alias: e.alias.clone(),
            prefixes: if e.cidrs.is_empty() {
                resolved.get(&e.alias).map(|ips| ips.iter().map(|ip| host_prefix(*ip)).collect()).unwrap_or_default()
            } else {
                e.cidrs.clone()
            },
            port: e.port,
        })
        .collect();
    EgressPolicy { roles, deny, connected }
}

/// Why a request to an endpoint failed. Messages are already redacted.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EndpointError {
    #[error("no address the egress floor admits")]
    Egress,
    #[error("transport: {0}")]
    Transport(String),
    #[error("timed out")]
    Timeout,
    #[error("HTTP status {0}")]
    Status(u16),
    #[error("response larger than its cap")]
    TooLarge,
    #[error("local: {0}")]
    Local(String),
}

struct Shared {
    role: Role,
    alias: String,
    host: String,
    port: u16,
    literal: bool,
    explicit_cidrs: bool,
    addrs: Mutex<(Vec<IpAddr>, Option<Instant>)>,
    policy: PolicyHandle,
    egress: Arc<dyn EgressHooks>,
}

impl Shared {
    fn admitted(&self) -> Vec<SocketAddr> {
        let addrs = self.addrs.lock().unwrap_or_else(|p| p.into_inner()).0.clone();
        let policy = self.policy.read().unwrap_or_else(|p| p.into_inner());
        addrs
            .into_iter()
            .map(|ip| SocketAddr::new(ip, self.port))
            .filter(|sa| matches!(self.egress.admit(&policy, Some((self.role, &self.alias)), *sa), Admit::Role))
            .collect()
    }

    /// Resolves a host that has no addresses yet (rate limited).
    async fn ensure_resolved(&self) {
        if self.literal {
            return;
        }
        {
            let mut g = self.addrs.lock().unwrap_or_else(|p| p.into_inner());
            if !g.0.is_empty() || g.1.is_some_and(|t| t.elapsed() < RERESOLVE_EVERY) {
                return;
            }
            g.1 = Some(Instant::now());
        }
        let ips: Vec<IpAddr> = match tokio::net::lookup_host((self.host.as_str(), self.port)).await {
            Ok(it) => dedup(it.map(|sa| sa.ip())),
            Err(e) => {
                tracing::warn!(endpoint = %self.alias, error = %self.egress.redact(&e.to_string()), "endpoint host does not resolve");
                return;
            }
        };
        if ips.is_empty() {
            return;
        }
        if !self.explicit_cidrs {
            let mut p = self.policy.write().unwrap_or_else(|p| p.into_inner());
            if let Some(entry) = p.roles.iter_mut().find(|r| r.role == self.role && r.alias == self.alias) {
                entry.prefixes = ips.iter().map(|ip| host_prefix(*ip)).collect();
            }
        }
        self.addrs.lock().unwrap_or_else(|p| p.into_inner()).0 = ips;
    }
}

fn dedup(it: impl Iterator<Item = IpAddr>) -> Vec<IpAddr> {
    let mut v: Vec<IpAddr> = Vec::new();
    for ip in it {
        if !v.contains(&ip) {
            v.push(ip);
        }
    }
    v
}

/// Resolves `host` at startup with the blocking system resolver (before the sandbox).
pub fn resolve_blocking(spec: &EndpointSpec) -> Vec<IpAddr> {
    if let Some(ip) = spec.literal {
        return vec![ip];
    }
    use std::net::ToSocketAddrs;
    match (spec.host.as_str(), spec.port).to_socket_addrs() {
        Ok(it) => dedup(it.map(|sa| sa.ip())),
        Err(_) => Vec::new(),
    }
}

struct PinnedResolver(Arc<Shared>);

impl Resolve for PinnedResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let shared = self.0.clone();
        let name = name.as_str().trim_end_matches('.').to_ascii_lowercase();
        Box::pin(async move {
            if name != shared.host {
                return Err("resolver asked for a host that is not its endpoint's".into());
            }
            shared.ensure_resolved().await;
            let addrs = shared.admitted();
            if addrs.is_empty() {
                return Err("no address the egress floor admits".into());
            }
            Ok(Box::new(addrs.into_iter()) as Addrs)
        })
    }
}

/// One operator endpoint: its client, floor check, concurrency lanes, pacing and operator budget.
pub struct Endpoint {
    pub spec: EndpointSpec,
    shared: Arc<Shared>,
    client: reqwest::Client,
    pub concurrency: Lanes,
    pacer: Option<Pacer>,
    budget: Option<TokenBucket>,
}

impl std::fmt::Debug for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Endpoint").field("alias", &self.spec.alias).finish_non_exhaustive()
    }
}

impl Endpoint {
    /// Needs a tokio runtime (the pacer's dispatcher).
    pub fn new(
        spec: EndpointSpec,
        resolved: Vec<IpAddr>,
        policy: PolicyHandle,
        egress: Arc<dyn EgressHooks>,
        t: &TimeoutConfig,
    ) -> Result<Arc<Self>, reqwest::Error> {
        let shared = Arc::new(Shared {
            role: spec.role,
            alias: spec.alias.clone(),
            host: spec.host.clone(),
            port: spec.port,
            literal: spec.literal.is_some(),
            explicit_cidrs: !spec.cidrs.is_empty(),
            addrs: Mutex::new((spec.literal.map(|ip| vec![ip]).unwrap_or(resolved), None)),
            policy,
            egress,
        });
        let client = reqwest::Client::builder()
            .dns_resolver(Arc::new(PinnedResolver(shared.clone())))
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .referer(false)
            .connect_timeout(t.connect())
            .timeout(t.request())
            .user_agent(USER_AGENT)
            .pool_idle_timeout(Duration::from_secs(30))
            .pool_max_idle_per_host(spec.max_concurrency as usize)
            .build()?;
        Ok(Arc::new(Self {
            concurrency: Lanes::concurrency(spec.max_concurrency),
            pacer: spec.max_requests_per_sec.map(Pacer::new),
            budget: spec.max_units_per_minute.map(TokenBucket::per_minute),
            spec,
            shared,
            client,
        }))
    }

    pub fn alias(&self) -> &str {
        &self.spec.alias
    }

    /// Spends `units` of the operator budget (always true without one).
    pub fn try_spend(&self, units: u64) -> bool {
        self.budget.as_ref().is_none_or(|b| b.try_take(units))
    }

    /// The endpoint's addresses the floor admits now.
    pub fn admitted(&self) -> Vec<SocketAddr> {
        self.shared.admitted()
    }

    async fn gate(&self, held: bool) -> Result<crate::lanes::LanePermit, EndpointError> {
        self.shared.ensure_resolved().await;
        if self.shared.admitted().is_empty() {
            return Err(EndpointError::Egress);
        }
        if let Some(p) = &self.pacer {
            p.acquire(held).await;
        }
        Ok(self.concurrency.acquire(held, 1).await)
    }

    /// POSTs a JSON body to the endpoint URL; the 2xx response body, at most `cap` bytes.
    pub async fn post_json(&self, held: bool, body: Vec<u8>, cap: u64) -> Result<Vec<u8>, EndpointError> {
        let _slot = self.gate(held).await?;
        let mut req = self.client.post(self.spec.url()).header(CONTENT_TYPE, "application/json").body(body);
        if let Some((name, value)) = &self.spec.key_header {
            req = req.header(name.clone(), value.clone());
        }
        let resp = req.send().await.map_err(|e| self.transport(e))?;
        let mut out = Vec::new();
        self.read_body(resp, cap, &mut |chunk| {
            out.extend_from_slice(chunk);
            Ok(())
        })
        .await?;
        Ok(out)
    }

    /// GETs `url` (built by the broker from this endpoint's template) and streams the 2xx body,
    /// at most `cap` bytes, into `sink`. Returns the body length.
    pub async fn get_into(
        &self,
        url: &str,
        held: bool,
        cap: u64,
        sink: &mut (dyn FnMut(&[u8]) -> io::Result<()> + Send),
    ) -> Result<u64, EndpointError> {
        let _slot = self.gate(held).await?;
        let resp = self.client.get(url).send().await.map_err(|e| self.transport(e))?;
        self.read_body(resp, cap, sink).await
    }

    async fn read_body(
        &self,
        mut resp: reqwest::Response,
        cap: u64,
        sink: &mut (dyn FnMut(&[u8]) -> io::Result<()> + Send),
    ) -> Result<u64, EndpointError> {
        let status = resp.status();
        if !status.is_success() {
            return Err(EndpointError::Status(status.as_u16()));
        }
        if resp.content_length().is_some_and(|l| l > cap) {
            return Err(EndpointError::TooLarge);
        }
        let mut total = 0u64;
        while let Some(chunk) = resp.chunk().await.map_err(|e| self.transport(e))? {
            total += chunk.len() as u64;
            if total > cap {
                return Err(EndpointError::TooLarge);
            }
            sink(&chunk).map_err(|e| EndpointError::Local(e.to_string()))?;
        }
        Ok(total)
    }

    fn transport(&self, e: reqwest::Error) -> EndpointError {
        if e.is_timeout() {
            return EndpointError::Timeout;
        }
        let e = e.without_url();
        let mut s = e.to_string();
        let mut src = e.source();
        while let Some(x) = src {
            s.push_str(": ");
            s.push_str(&x.to_string());
            src = x.source();
        }
        EndpointError::Transport(self.shared.egress.redact(&s))
    }

    /// Logs a failure by alias, with the redacted error.
    pub fn log_failure(&self, what: &str, e: &EndpointError) {
        tracing::warn!(endpoint = %self.spec.alias, error = %self.shared.egress.redact(&e.to_string()), "{what}");
    }

    pub fn redact(&self, s: &str) -> String {
        self.shared.egress.redact(s)
    }
}
