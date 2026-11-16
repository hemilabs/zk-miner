//! The egress wiring (plan §14.2): one reqwest client per operator endpoint, whose DNS resolver
//! returns only addresses the network floor admits for that endpoint's role and alias, pinned for
//! the request. No proxy, no redirects, no `Referer`, no decompression, a constant User-Agent;
//! endpoints are logged by alias and errors pass through `redact_urls(sanitize_log(…))`.
//!
//! Host names are resolved with the broker's own stub resolver ([`crate::dns`]; never
//! `getaddrinfo`, `/etc/hosts` or NSS): at startup, before the sandbox (see
//! [`crate::config::HostFacts`]), then again once the answer is `[dns] reresolve_secs` old (in the
//! background while the old answer serves; inline, retried at most every
//! [`RETRY_UNRESOLVED_EVERY`], while there is none). Each answer replaces the pinned addresses. For
//! an endpoint without explicit `cidrs` the answer is also its role entry, **filtered**: only
//! global addresses outside the deny CIDRs, the connected prefixes and the host's own addresses
//! ([`EgressPolicy::dns_admissible`], netguard's public floor in either mode), re-checked whenever
//! the miner refreshes the prefixes. With explicit `cidrs`, the role entry is the cidrs and an
//! answer outside them is never connected to. IP-literal hosts never reach a resolver (hyper
//! connects to them directly), so [`Endpoint`] checks the floor itself before every request. In
//! public mode every address is also held to netguard's public floor at connect time
//! ([`EgressPolicy::admit`]).

use std::error::Error as _;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use reqwest::header::CONTENT_TYPE;

use crate::config::{host_prefix, EndpointSpec, TimeoutConfig};
use crate::dns::Resolver;
use crate::egress::{Admit, EgressPolicy, NetMode, Prefix, Role, RoleEntry};
use crate::hooks::EgressHooks;
use crate::lanes::{LanePermit, Lanes, Pacer, TokenBucket, WaitFlag};

/// The shared, refreshable policy (with the host's connected prefixes and own addresses).
pub type PolicyHandle = Arc<RwLock<EgressPolicy>>;

/// How often a host name without any admitted address is resolved again.
pub const RETRY_UNRESOLVED_EVERY: Duration = Duration::from_secs(10);

const USER_AGENT: &str = "zkminer-witness-broker";

fn read<T>(l: &RwLock<T>) -> std::sync::RwLockReadGuard<'_, T> {
    l.read().unwrap_or_else(|p| p.into_inner())
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

/// Builds the policy in `mode`: one role entry per endpoint — its explicit CIDRs, else its IP
/// literal, else the addresses its host name resolved to that [`EgressPolicy::dns_admissible`]
/// admits — the deny CIDRs (the operator's and the DNS servers', see
/// [`crate::config::BrokerConfig::effective_deny`]), the connected prefixes and own addresses.
pub fn build_policy<'a>(
    mode: NetMode,
    endpoints: impl Iterator<Item = &'a EndpointSpec>,
    resolved: &std::collections::HashMap<String, Vec<IpAddr>>,
    deny: Vec<Prefix>,
    connected: Vec<Prefix>,
    own: &[IpAddr],
) -> EgressPolicy {
    let mut policy =
        EgressPolicy { mode, roles: Vec::new(), deny, facts: zkminer_netguard::HostFacts::new(connected, own.to_vec()) };
    let roles = endpoints
        .map(|e| RoleEntry {
            role: e.role,
            alias: e.alias.clone(),
            prefixes: if !e.cidrs.is_empty() {
                e.cidrs.clone()
            } else if let Some(ip) = e.literal {
                vec![host_prefix(ip)]
            } else {
                resolved
                    .get(&e.alias)
                    .map(|ips| ips.iter().filter(|ip| policy.dns_admissible(**ip)).map(|ip| host_prefix(*ip)).collect())
                    .unwrap_or_default()
            },
            port: e.port,
        })
        .collect();
    policy.roles = roles;
    policy
}

/// Why a request to an endpoint failed. Messages are already redacted.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EndpointError {
    #[error("no address the egress floor admits")]
    Egress,
    /// Connecting failed (refused, reset, unreachable, a connect timeout, TLS) or the connection
    /// broke: the operator's side.
    #[error("transport: {0}")]
    Transport(String),
    /// The endpoint took longer than `request_secs` to answer the request once it was sent, or to
    /// stream its body: the request's own cost, as far as the broker can tell.
    #[error("timed out")]
    Timeout,
    #[error("HTTP status {0}")]
    Status(u16),
    #[error("response larger than its cap")]
    TooLarge,
    #[error("local: {0}")]
    Local(String),
}

impl EndpointError {
    /// Whether the failure is the operator's (plan §11.2, §16): transport, a non-2xx other than
    /// 404, no admitted address, a local resource. A timeout after the request was sent, a 404 and a
    /// body above the job's cap are not: a builder can cause each of them on demand.
    pub fn operator_side(&self) -> bool {
        match self {
            EndpointError::Egress | EndpointError::Transport(_) | EndpointError::Local(_) => true,
            EndpointError::Status(s) => *s != 404,
            EndpointError::Timeout | EndpointError::TooLarge => false,
        }
    }
}

struct Pins {
    addrs: Vec<IpAddr>,
    /// When the last answer arrived.
    resolved_at: Option<Instant>,
    /// When the last resolution started.
    attempted_at: Option<Instant>,
    refreshing: bool,
}

struct Shared {
    role: Role,
    alias: String,
    host: String,
    port: u16,
    literal: bool,
    explicit_cidrs: bool,
    pins: Mutex<Pins>,
    policy: PolicyHandle,
    egress: Arc<dyn EgressHooks>,
    dns: Arc<Resolver>,
    reresolve: Duration,
}

impl Shared {
    fn admitted(&self) -> Vec<SocketAddr> {
        let addrs = lock(&self.pins).addrs.clone();
        let policy = read(&self.policy);
        addrs
            .into_iter()
            .map(|ip| SocketAddr::new(ip, self.port))
            .filter(|sa| matches!(policy.admit(Some((self.role, &self.alias)), *sa), Admit::Role))
            .collect()
    }

    /// Re-resolves the host name when its answer is stale: in the background while it still has
    /// addresses, inline (rate limited) when it has none.
    async fn ensure_resolved(self: &Arc<Self>) {
        if self.literal {
            return;
        }
        let inline = {
            let mut p = lock(&self.pins);
            let stale = p.resolved_at.is_none_or(|t| t.elapsed() >= self.reresolve) || p.addrs.is_empty();
            let may_try = p.attempted_at.is_none_or(|t| t.elapsed() >= RETRY_UNRESOLVED_EVERY);
            if !stale || !may_try || p.refreshing {
                return;
            }
            p.refreshing = true;
            p.attempted_at = Some(Instant::now());
            p.addrs.is_empty()
        };
        if inline {
            self.refresh().await;
        } else {
            let me = self.clone();
            tokio::spawn(async move { me.refresh().await });
        }
    }

    async fn refresh(&self) {
        struct Done<'a>(&'a Mutex<Pins>);
        impl Drop for Done<'_> {
            fn drop(&mut self) {
                lock(self.0).refreshing = false;
            }
        }
        let _done = Done(&self.pins);
        match self.dns.resolve(&self.host).await {
            Ok(ips) => self.install(ips, true),
            Err(e) => {
                tracing::warn!(endpoint = %self.alias, error = %e, "endpoint host name does not resolve; keeping the pinned addresses")
            }
        }
    }

    /// Pins `ips` (filtered for a host name without explicit cidrs, which also become its role
    /// entry). `fresh`: a new answer (else a re-check of the pinned one).
    fn install(&self, ips: Vec<IpAddr>, fresh: bool) {
        let kept: Vec<IpAddr> = if self.explicit_cidrs {
            ips.clone()
        } else {
            let policy = read(&self.policy);
            ips.iter().copied().filter(|ip| policy.dns_admissible(*ip)).collect()
        };
        if kept.len() < ips.len() {
            tracing::warn!(
                endpoint = %self.alias,
                refused = ips.len() - kept.len(),
                "the host name resolves to addresses a DNS-derived role entry may not hold (not global, denied, \
                 connected or the host's own); configure a local node by IP literal or cidrs"
            );
        }
        if !self.explicit_cidrs {
            let mut policy = self.policy.write().unwrap_or_else(|p| p.into_inner());
            if let Some(e) = policy.roles.iter_mut().find(|r| r.role == self.role && r.alias == self.alias) {
                e.prefixes = kept.iter().map(|ip| host_prefix(*ip)).collect();
            }
        }
        let mut p = lock(&self.pins);
        p.addrs = kept;
        if fresh {
            p.resolved_at = Some(Instant::now());
        }
    }
}

/// Resolves `spec`'s host at startup with the broker's resolver, blocking (before the sandbox).
/// Unfiltered: [`build_policy`] decides what may become a role entry.
pub fn resolve_blocking(spec: &EndpointSpec, resolver: &Resolver) -> Vec<IpAddr> {
    if let Some(ip) = spec.literal {
        return vec![ip];
    }
    resolver.resolve_blocking(&spec.host).unwrap_or_default()
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

/// The hardened client settings every endpoint uses (also used by tests to show what they change).
pub fn client_builder(t: &TimeoutConfig, max_idle: usize) -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .referer(false)
        .connect_timeout(t.connect())
        .timeout(t.request())
        .user_agent(USER_AGENT)
        .pool_idle_timeout(Duration::from_secs(30))
        .pool_max_idle_per_host(max_idle)
}

/// What an [`Endpoint`] is built from besides its spec.
pub struct EndpointEnv {
    pub policy: PolicyHandle,
    pub egress: Arc<dyn EgressHooks>,
    pub dns: Arc<Resolver>,
    pub reresolve: Duration,
    /// The share of the operator budget only held-lock work may spend.
    pub held_lock_share: f64,
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

/// A 2xx response body being read under its cap, holding the endpoint's concurrency slot.
pub struct BodyReader<'a> {
    ep: &'a Endpoint,
    resp: reqwest::Response,
    cap: u64,
    total: u64,
    _slot: LanePermit,
}

impl BodyReader<'_> {
    /// Appends the next chunk to `buf`; `false` at the end of the body.
    pub async fn next_into(&mut self, buf: &mut Vec<u8>) -> Result<bool, EndpointError> {
        match self.resp.chunk().await.map_err(|e| self.ep.transport(e))? {
            None => Ok(false),
            Some(chunk) => {
                self.total += chunk.len() as u64;
                if self.total > self.cap {
                    return Err(EndpointError::TooLarge);
                }
                buf.extend_from_slice(&chunk);
                Ok(true)
            }
        }
    }

    /// Bytes read so far.
    pub fn total(&self) -> u64 {
        self.total
    }
}

impl Endpoint {
    /// Needs a tokio runtime (the pacer's dispatcher).
    pub fn new(spec: EndpointSpec, resolved: Vec<IpAddr>, env: &EndpointEnv, t: &TimeoutConfig) -> Result<Arc<Self>, reqwest::Error> {
        let addrs = spec.literal.map(|ip| vec![ip]).unwrap_or(resolved);
        let resolved_at = (!addrs.is_empty()).then(Instant::now);
        let shared = Arc::new(Shared {
            role: spec.role,
            alias: spec.alias.clone(),
            host: spec.host.clone(),
            port: spec.port,
            literal: spec.literal.is_some(),
            explicit_cidrs: !spec.cidrs.is_empty(),
            pins: Mutex::new(Pins { addrs: Vec::new(), resolved_at, attempted_at: None, refreshing: false }),
            policy: env.policy.clone(),
            egress: env.egress.clone(),
            dns: env.dns.clone(),
            reresolve: env.reresolve,
        });
        if shared.literal {
            lock(&shared.pins).addrs = addrs;
        } else {
            // The startup answer, through the same filter as every later one (the role entry
            // `build_policy` made from it is rewritten identically).
            shared.install(addrs, false);
        }
        let client = client_builder(t, spec.max_concurrency as usize)
            .dns_resolver(Arc::new(PinnedResolver(shared.clone())))
            .build()?;
        Ok(Arc::new(Self {
            concurrency: Lanes::concurrency(spec.max_concurrency),
            pacer: spec.max_requests_per_sec.map(Pacer::new),
            budget: spec.max_units_per_minute.map(|u| TokenBucket::per_minute(u, env.held_lock_share)),
            spec,
            shared,
            client,
        }))
    }

    pub fn alias(&self) -> &str {
        &self.spec.alias
    }

    /// Spends `units` of the operator budget (always true without one). Work that holds no lock
    /// may not take the held-lock share of it.
    pub fn try_spend(&self, units: u64, held: bool) -> bool {
        self.budget.as_ref().is_none_or(|b| b.try_take(units, held))
    }

    /// The endpoint's addresses the floor admits now.
    pub fn admitted(&self) -> Vec<SocketAddr> {
        self.shared.admitted()
    }

    /// Re-applies the DNS filter to a host name's pinned answer (after the connected prefixes or
    /// own addresses changed).
    pub fn refilter(&self) {
        if !self.shared.literal && !self.shared.explicit_cidrs {
            let addrs = lock(&self.shared.pins).addrs.clone();
            self.shared.install(addrs, false);
        }
    }

    async fn gate(&self, held: bool, wait: &WaitFlag) -> Result<LanePermit, EndpointError> {
        self.shared.ensure_resolved().await;
        if self.shared.admitted().is_empty() {
            return Err(EndpointError::Egress);
        }
        wait.during(async {
            if let Some(p) = &self.pacer {
                p.acquire(held).await;
            }
            Ok(self.concurrency.acquire(held, 1).await)
        })
        .await
    }

    /// POSTs a JSON body to the endpoint URL; the 2xx response body, at most `cap` bytes. `wait` is
    /// marked while the request waits for the pacer or a concurrency slot.
    pub async fn post_json(&self, held: bool, body: Vec<u8>, cap: u64, wait: &WaitFlag) -> Result<Vec<u8>, EndpointError> {
        let slot = self.gate(held, wait).await?;
        let mut req = self.client.post(self.spec.url()).header(CONTENT_TYPE, "application/json").body(body);
        if let Some((name, value)) = &self.spec.key_header {
            req = req.header(name.clone(), value.clone());
        }
        let resp = req.send().await.map_err(|e| self.transport(e))?;
        let mut r = self.reader(resp, cap, slot)?;
        let mut out = Vec::new();
        while r.next_into(&mut out).await? {}
        Ok(out)
    }

    /// GETs `url` (built by the broker from this endpoint's template); the 2xx body is read from
    /// the returned reader, at most `cap` bytes.
    pub async fn get(&self, url: &str, held: bool, cap: u64, wait: &WaitFlag) -> Result<BodyReader<'_>, EndpointError> {
        let slot = self.gate(held, wait).await?;
        let resp = self.client.get(url).send().await.map_err(|e| self.transport(e))?;
        self.reader(resp, cap, slot)
    }

    fn reader(&self, resp: reqwest::Response, cap: u64, slot: LanePermit) -> Result<BodyReader<'_>, EndpointError> {
        let status = resp.status();
        if !status.is_success() {
            return Err(EndpointError::Status(status.as_u16()));
        }
        if resp.content_length().is_some_and(|l| l > cap) {
            return Err(EndpointError::TooLarge);
        }
        Ok(BodyReader { ep: self, resp, cap, total: 0, _slot: slot })
    }

    fn transport(&self, e: reqwest::Error) -> EndpointError {
        // A connect timeout is the endpoint's (it is unreachable); a timeout once the request was
        // sent is the request's.
        if e.is_timeout() && !e.is_connect() {
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The hardened builder really suppresses `Referer`: with redirects re-enabled on top of it
    /// (only here), the redirect target gets no `Referer`, while a stock client sends one.
    #[tokio::test]
    async fn the_client_settings_send_no_referer_even_when_following() {
        use crate::testkit::{TestResponse, TestServer};
        let target = TestServer::start(|_| TestResponse::ok(b"ok".to_vec())).await;
        let loc = format!("{}/next", target.url());
        let redirecting = TestServer::start(move |_| TestResponse::status(307).with_header("Location", &loc)).await;
        let ours = client_builder(&TimeoutConfig::default(), 1).redirect(reqwest::redirect::Policy::limited(1)).build().unwrap();
        assert_eq!(ours.get(redirecting.url()).send().await.unwrap().status(), 200);
        let stock = reqwest::Client::builder().no_proxy().redirect(reqwest::redirect::Policy::limited(1)).build().unwrap();
        assert_eq!(stock.get(redirecting.url()).send().await.unwrap().status(), 200);
        let reqs = target.requests.lock().unwrap().clone();
        assert_eq!(reqs.len(), 2);
        assert_eq!(reqs[0].header("referer"), None, "our settings");
        assert!(reqs[1].header("referer").is_some(), "control: a stock client sends Referer on a redirect");
    }

    #[test]
    fn operator_side_errors() {
        for (e, op) in [
            (EndpointError::Egress, true),
            (EndpointError::Transport("x".into()), true),
            (EndpointError::Local("x".into()), true),
            (EndpointError::Status(429), true),
            (EndpointError::Status(500), true),
            (EndpointError::Status(307), true),
            (EndpointError::Status(404), false),
            (EndpointError::Timeout, false),
            (EndpointError::TooLarge, false),
        ] {
            assert_eq!(e.operator_side(), op, "{e:?}");
        }
    }
}
