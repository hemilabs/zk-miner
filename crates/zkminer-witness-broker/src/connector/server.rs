//! The miner's side of the connector (see the module doc of [`crate::connector`]).
//!
//! [`Connector`] holds what the miner loaded itself: the endpoints of the broker configuration
//! (role, alias, host, IP literal, port, `cidrs`, `max_concurrency` — no URL, no key), the network
//! mode from the miner's own `net_mode()`, the DNS servers, and netguard's public floor as a
//! [`NetPolicy`] over the miner's host facts with every deny CIDR (the broker file's, the miner's
//! `[egress] deny_cidrs`, the DNS servers). [`Connector::serve`] runs one broker session on the
//! miner's end of the socketpair.

use std::collections::{HashSet, VecDeque};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::Interest;
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::{mpsc, Semaphore};
use tokio::task::JoinSet;
use tokio::time::Instant;
use zkminer_netguard::{canonical_ip, NetMode, NetPolicy, Prefix};
use zkminer_witness::ipc::SelfTestCheck;

use super::{
    request_budget, Malformed, Request, Response, Status, MAX_INFLIGHT, MAX_MISUSE, MISUSE_WINDOW, RATE_BURST,
    RATE_PER_SEC, REQUEST_LEN, RESOLVE_BUDGET, RESPONSE_LEN,
};
use crate::config::BrokerConfig;
use crate::dns::{Resolver, QUERY_TIMEOUT};
use crate::egress::Role;
use crate::fdpass::{recvmsg_once, retry_eintr, sendmsg_once};

/// How often a host name without any admitted address is resolved again.
pub const RETRY_UNRESOLVED_EVERY: Duration = Duration::from_secs(10);
/// Most of the floor's blocking checks (`vet_path`, `recheck_connected`) running at once (review
/// round 4): a blocking check holds its turn until it ends, so a broker cannot pile up blocking
/// threads by asking faster than checks finish. Since review round 5 (probe-1) a check runs
/// within the request's deadline and gives up at it, so an abandoned one ends with it.
pub const MAX_CHECKS_AT_ONCE: usize = 4;

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

/// One operator endpoint, as the miner loaded it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectorEndpoint {
    pub role: Role,
    pub alias: String,
    /// Lowercase host name, or the textual IP of an IP-literal host.
    pub host: String,
    pub literal: Option<IpAddr>,
    pub port: u16,
    /// The explicit role entry; empty = the host's IP literal, or its admitted DNS answer.
    pub cidrs: Vec<Prefix>,
    pub max_concurrency: u32,
}

impl ConnectorEndpoint {
    /// Whether the role entry comes from DNS (a host name without `cidrs`): its answers must pass
    /// the public floor in either mode.
    fn dns_derived(&self) -> bool {
        self.literal.is_none() && self.cidrs.is_empty()
    }
}

/// The endpoints of `cfg`, in [`BrokerConfig::endpoints`] order (their indices are the protocol's).
pub fn endpoints_of(cfg: &BrokerConfig) -> Vec<ConnectorEndpoint> {
    cfg.endpoints()
        .map(|e| ConnectorEndpoint {
            role: e.role,
            alias: e.alias.clone(),
            host: e.host.clone(),
            literal: e.literal,
            port: e.port,
            cidrs: e.cidrs.clone(),
            max_concurrency: e.max_concurrency,
        })
        .collect()
}

struct Pins {
    addrs: Vec<IpAddr>,
    resolved_at: Option<Instant>,
    attempted_at: Option<Instant>,
    refreshing: bool,
}

struct EndpointState {
    ep: ConnectorEndpoint,
    /// Connection attempts in flight to this endpoint.
    slots: Semaphore,
    pins: Mutex<Pins>,
}

/// Why an address is not admitted for an endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// Outside the endpoint's `cidrs`, not its IP literal, or not in its current DNS answer.
    NotInRoleEntry,
    /// netguard's public floor (not global, the host's own or connected, a deny CIDR, a DNS
    /// server, off the default route).
    Floor(zkminer_netguard::Denied),
}

/// Why a session cut the broker off.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CutOff {
    Malformed(Malformed),
    /// The broker sent a file descriptor.
    FdAttached,
    /// More than [`MAX_INFLIGHT`] requests in flight (a request is in flight until its answer is
    /// handed to the socket).
    Flood,
    /// A request id that is still in flight.
    DuplicateId,
    /// More than [`MAX_MISUSE`] requests for a missing index or the wrong role or port within
    /// [`MISUSE_WINDOW`].
    Misuse,
    /// An answer could not be written for longer than the request budget: the broker stopped
    /// reading its answers (and would leave their sockets with the miner).
    AnswersStalled,
    /// Writing an answer failed while the broker kept its sending side open: it shut its reading
    /// side, so answers (and their sockets) can no longer reach it.
    AnswersRefused,
}

impl std::fmt::Display for CutOff {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CutOff::Malformed(m) => write!(f, "{m}"),
            CutOff::FdAttached => f.write_str("it sent a file descriptor"),
            CutOff::Flood => write!(f, "more than {MAX_INFLIGHT} requests in flight"),
            CutOff::DuplicateId => f.write_str("a request id still in flight"),
            CutOff::Misuse => write!(f, "more than {MAX_MISUSE} requests for endpoints it does not have within {MISUSE_WINDOW:?}"),
            CutOff::AnswersStalled => f.write_str("it stopped reading its answers"),
            CutOff::AnswersRefused => f.write_str("it shut the reading side of its connector socket"),
        }
    }
}

/// How a session ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionEnd {
    /// The broker closed its end (or the socket failed).
    Closed,
    /// The broker broke the protocol; the socket was closed on it.
    CutOff(CutOff),
}

/// Counters, for logs and tests.
#[derive(Debug, Default)]
pub struct ConnectorStats {
    pub requests: AtomicU64,
    pub connected: AtomicU64,
    pub refused: AtomicU64,
    /// TCP connect attempts made (each admitted address tried).
    pub attempts: AtomicU64,
}

struct Bucket {
    tokens: f64,
    at: Instant,
}

/// The miner's connector. Cheap to share; one [`Connector::serve`] per broker session.
pub struct Connector {
    mode: NetMode,
    endpoints: Vec<Arc<EndpointState>>,
    /// netguard's public floor (always [`NetMode::Public`]), with every deny CIDR.
    floor: NetPolicy,
    resolver: Resolver,
    reresolve: Duration,
    connect_timeout: Duration,
    bucket: Mutex<Bucket>,
    /// Turns for the floor's blocking checks ([`MAX_CHECKS_AT_ONCE`]).
    checks: Arc<Semaphore>,
    pub stats: ConnectorStats,
}

impl std::fmt::Debug for Connector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Connector").field("mode", &self.mode).field("endpoints", &self.endpoints.len()).finish_non_exhaustive()
    }
}

impl Connector {
    /// The miner's connector for `cfg` — the broker file **as the miner loaded it**, in the
    /// miner's network mode ([`BrokerConfig::load_for_connector`]) — with the miner's `[egress]`
    /// `deny_cidrs` and options (its IPv4 site, stated public addresses, internal ranges and
    /// near-hop limit). The floor's facts are gathered with the stricter of the miner's and the
    /// file's `[egress]` options (the shorter IPv6 site, discovery if either asks) and re-read as
    /// netguard does. The DNS servers are `[dns] servers`, else `/etc/resolv.conf`'s, read now.
    pub fn for_miner(
        cfg: &BrokerConfig,
        miner_deny: &[Prefix],
        miner_facts: zkminer_netguard::FactsOptions,
    ) -> io::Result<Arc<Self>> {
        let dns_servers = if cfg.dns.servers.is_empty() { crate::dns::system_servers() } else { cfg.dns.servers.clone() };
        let options = zkminer_netguard::FactsOptions {
            ipv6_site_prefix_len: miner_facts.ipv6_site_prefix_len.min(cfg.facts_options.ipv6_site_prefix_len),
            discover_public_addresses: miner_facts.discover_public_addresses || cfg.facts_options.discover_public_addresses,
            ..miner_facts
        };
        let floor = NetPolicy::with_options(NetMode::Public, Self::deny_for(cfg, miner_deny, &dns_servers), options)?;
        Self::with_floor(cfg, dns_servers, floor)
    }

    /// Every deny CIDR the floor holds: the broker file's, the miner's, and a host route per DNS
    /// server the resolver dials.
    pub fn deny_for(cfg: &BrokerConfig, miner_deny: &[Prefix], dns_servers: &[SocketAddr]) -> Vec<Prefix> {
        let mut deny = cfg.effective_deny(dns_servers);
        for p in miner_deny {
            if !deny.contains(p) {
                deny.push(*p);
            }
        }
        deny
    }

    /// A connector over an explicit public-mode `floor` (tests inject host facts this way).
    pub fn with_floor(cfg: &BrokerConfig, dns_servers: Vec<SocketAddr>, floor: NetPolicy) -> io::Result<Arc<Self>> {
        if floor.mode() != NetMode::Public {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "the connector's floor must be netguard's public floor"));
        }
        let endpoints = endpoints_of(cfg)
            .into_iter()
            .map(|ep| {
                Arc::new(EndpointState {
                    slots: Semaphore::new(ep.max_concurrency.max(1) as usize),
                    pins: Mutex::new(Pins { addrs: Vec::new(), resolved_at: None, attempted_at: None, refreshing: false }),
                    ep,
                })
            })
            .collect();
        Ok(Arc::new(Connector {
            mode: cfg.net_mode,
            endpoints,
            floor,
            resolver: Resolver::new(dns_servers, QUERY_TIMEOUT),
            reresolve: cfg.dns.reresolve,
            connect_timeout: cfg.timeouts.connect(),
            bucket: Mutex::new(Bucket { tokens: f64::from(RATE_BURST), at: Instant::now() }),
            checks: Arc::new(Semaphore::new(MAX_CHECKS_AT_ONCE)),
            stats: ConnectorStats::default(),
        }))
    }

    pub fn mode(&self) -> NetMode {
        self.mode
    }

    /// The endpoints, in index order.
    pub fn endpoints(&self) -> impl Iterator<Item = &ConnectorEndpoint> {
        self.endpoints.iter().map(|e| &e.ep)
    }

    /// The DNS servers its resolver dials.
    pub fn dns_servers(&self) -> &[SocketAddr] {
        self.resolver.servers()
    }

    /// Resolves every host-name endpoint in the background (the first connection then finds an
    /// answer). Needs a tokio runtime.
    pub fn warm_up(self: &Arc<Self>) {
        for (i, st) in self.endpoints.iter().enumerate() {
            if st.ep.literal.is_none() {
                let me = self.clone();
                tokio::spawn(async move { me.ensure_resolved(i).await });
            }
        }
    }

    // -----------------------------------------------------------------------------------------
    // Admission.

    /// Whether `ip` is admitted for endpoint `index`: in its role entry (explicit `cidrs`, else its
    /// IP literal, else its current DNS answer), and — in public mode, or for a DNS-derived
    /// address in either mode — through netguard's public floor. May block (the floor re-reads
    /// the host's facts when they are stale): call it off the runtime's worker threads.
    pub fn admit(&self, index: usize, ip: IpAddr) -> Result<(), Refusal> {
        let st = self.endpoints.get(index).ok_or(Refusal::NotInRoleEntry)?;
        let c = canonical_ip(ip);
        let in_role = if !st.ep.cidrs.is_empty() {
            st.ep.cidrs.iter().any(|p| p.contains(ip))
        } else if let Some(lit) = st.ep.literal {
            canonical_ip(lit) == c
        } else {
            lock(&st.pins).addrs.iter().any(|a| canonical_ip(*a) == c)
        };
        if !in_role {
            return Err(Refusal::NotInRoleEntry);
        }
        if self.mode == NetMode::Public || st.ep.dns_derived() {
            self.floor.admit(ip).map_err(Refusal::Floor)?;
        }
        Ok(())
    }

    /// What a DNS answer for endpoint `st` may pin: inside its `cidrs` when it has them (the
    /// operator's word), else only what the public floor admits.
    fn answer_admissible(&self, st: &EndpointState, ip: IpAddr) -> bool {
        if !st.ep.cidrs.is_empty() {
            st.ep.cidrs.iter().any(|p| p.contains(ip))
        } else {
            self.floor.admit(ip).is_ok()
        }
    }

    async fn ensure_resolved(self: &Arc<Self>, index: usize) {
        let st = &self.endpoints[index];
        if st.ep.literal.is_some() {
            return;
        }
        let inline = {
            let mut p = lock(&st.pins);
            let stale = p.resolved_at.is_none_or(|t| t.elapsed() >= self.reresolve) || p.addrs.is_empty();
            // Without an answer, retried at most every RETRY_UNRESOLVED_EVERY; a stale answer is
            // refreshed once it is `reresolve` old (and a failed refresh retried no sooner).
            let retry_after = if p.addrs.is_empty() { RETRY_UNRESOLVED_EVERY } else { self.reresolve.min(RETRY_UNRESOLVED_EVERY) };
            let may_try = p.attempted_at.is_none_or(|t| t.elapsed() >= retry_after);
            if !stale || !may_try || p.refreshing {
                return;
            }
            p.refreshing = true;
            p.attempted_at = Some(Instant::now());
            p.addrs.is_empty()
        };
        if inline {
            self.refresh(index).await;
        } else {
            let me = self.clone();
            tokio::spawn(async move { me.refresh(index).await });
        }
    }

    async fn refresh(self: &Arc<Self>, index: usize) {
        struct Done<'a>(&'a Mutex<Pins>);
        impl Drop for Done<'_> {
            fn drop(&mut self) {
                lock(self.0).refreshing = false;
            }
        }
        let st = self.endpoints[index].clone();
        let _done = Done(&st.pins);
        let answer = tokio::time::timeout(RESOLVE_BUDGET, self.resolver.resolve(&st.ep.host)).await;
        let ips = match answer {
            Ok(Ok(ips)) => ips,
            Ok(Err(e)) => {
                tracing::warn!(endpoint = %st.ep.alias, error = %e, "connector: endpoint host name does not resolve; keeping the pinned addresses");
                return;
            }
            Err(_) => {
                tracing::warn!(endpoint = %st.ep.alias, "connector: endpoint host name did not resolve in time; keeping the pinned addresses");
                return;
            }
        };
        let me = self.clone();
        let st2 = st.clone();
        let kept = tokio::task::spawn_blocking(move || {
            ips.iter().copied().filter(|ip| me.answer_admissible(&st2, *ip)).collect::<Vec<_>>()
        })
        .await
        .unwrap_or_default();
        let mut p = lock(&st.pins);
        if kept.is_empty() {
            tracing::warn!(
                endpoint = %st.ep.alias,
                "connector: the host name resolves to no address its role entry admits (not global, denied, connected or \
                 the host's own; configure a local node by IP literal or cidrs, in developer mode)"
            );
        }
        p.addrs = kept;
        p.resolved_at = Some(Instant::now());
    }

    // -----------------------------------------------------------------------------------------
    // Serving.

    /// Waits for a token of the connection bucket until `deadline`.
    async fn take_token(&self, deadline: Instant) -> bool {
        loop {
            let wait = {
                let mut b = lock(&self.bucket);
                let now = Instant::now();
                let refill = now.duration_since(b.at).as_secs_f64() * f64::from(RATE_PER_SEC);
                b.tokens = (b.tokens + refill).min(f64::from(RATE_BURST));
                b.at = now;
                if b.tokens >= 1.0 {
                    b.tokens -= 1.0;
                    return true;
                }
                Duration::from_secs_f64((1.0 - b.tokens) / f64::from(RATE_PER_SEC))
            };
            let until = Instant::now() + wait.max(Duration::from_millis(5));
            if until > deadline {
                return false;
            }
            tokio::time::sleep_until(until).await;
        }
    }

    /// Serves one well-formed request for an existing endpoint (index, role and port checked).
    async fn connect_for(self: Arc<Self>, index: usize, id: u64) -> (Response, Option<OwnedFd>) {
        let deadline = Instant::now() + request_budget(self.connect_timeout);
        let st = self.endpoints[index].clone();
        if !self.take_token(deadline).await {
            return (Response::refused(id, Status::RateLimited), None);
        }
        let Ok(Ok(_slot)) = tokio::time::timeout_at(deadline, st.slots.acquire()).await else {
            return (Response::refused(id, Status::RateLimited), None);
        };
        let candidates = match st.ep.literal {
            Some(ip) => vec![ip],
            None => {
                let _ = tokio::time::timeout_at(deadline, self.ensure_resolved(index)).await;
                lock(&st.pins).addrs.clone()
            }
        };
        let me = self.clone();
        let admitted = tokio::task::spawn_blocking(move || {
            candidates
                .into_iter()
                .filter(|ip| match me.admit(index, *ip) {
                    Ok(()) => true,
                    Err(r) => {
                        tracing::warn!(endpoint = %me.endpoints[index].ep.alias, address = %ip, refusal = ?r, "connector: address refused");
                        false
                    }
                })
                .collect::<Vec<_>>()
        })
        .await;
        let admitted = match admitted {
            Ok(a) => a,
            Err(_) => return (Response::refused(id, Status::Internal), None),
        };
        if admitted.is_empty() {
            return (Response::refused(id, Status::NotAdmitted), None);
        }
        // Review round 5, probe-1: each address's check runs within the request's time (the
        // near-hop decision takes up to seconds when the probe goes unanswered: three attempts
        // and a pause, then a check connection), not within its share of the connect time,
        // which only bounds the TCP connect; and the check is given that deadline, so one the
        // connector stops waiting for stops too and gives back its turn and its probe slot.
        let n = admitted.len() as u32;
        let mut connect_left = self.connect_timeout;
        for (i, ip) in admitted.into_iter().enumerate() {
            if Instant::now() >= deadline {
                break;
            }
            let addr = SocketAddr::new(ip, st.ep.port);
            // Right before connecting, wherever the floor applies: the kernel's route with the
            // port, and the near-hop probe (a destination within a few hops is this host's own
            // network); and the source address the kernel picks for it, which the connection must
            // leave from once made (below).
            let mut vetted = None;
            if self.mode == NetMode::Public || st.ep.dns_derived() {
                let floor = self.floor.clone();
                let Ok(Ok(turn)) = tokio::time::timeout_at(deadline, self.checks.clone().acquire_owned()).await else {
                    tracing::debug!(endpoint = %st.ep.alias, address = %addr, "connector: no turn for the check before connecting");
                    continue;
                };
                // The turn is held by the blocking check until it ends, which is by the deadline.
                let until = deadline.into_std();
                let check = move || {
                    let _turn = turn;
                    floor.vet_path_until(addr, addr, until)
                };
                match tokio::time::timeout_at(deadline + CHECK_SLACK, tokio::task::spawn_blocking(check)).await {
                    Ok(Ok(Ok(v))) => vetted = Some(v),
                    Ok(Ok(Err(d))) => {
                        tracing::warn!(endpoint = %st.ep.alias, address = %addr, refusal = %d, "connector: address refused right before connecting");
                        continue;
                    }
                    Ok(Err(_)) | Err(_) => {
                        tracing::debug!(endpoint = %st.ep.alias, address = %addr, "connector: the check before connecting did not finish");
                        continue;
                    }
                }
            }
            let now = Instant::now();
            let share = (connect_left / (n - i as u32)).min(deadline.saturating_duration_since(now));
            self.stats.attempts.fetch_add(1, Ordering::Relaxed);
            // From the source the check vetted (the kernel's for a TCP connection: review round
            // 4, cross-3), so the connection leaves from it.
            let source = vetted.as_ref().and_then(|v: &zkminer_netguard::Vetted| v.source);
            let connected = tokio::time::timeout(share, connect_tcp(addr, source)).await;
            connect_left = connect_left.saturating_sub(now.elapsed());
            match connected {
                Ok(Ok(fd)) => {
                    // Once made, before the broker gets it: the connection's own addresses must be
                    // the vetted ones and the route still admitted, the kernel asked afresh (a route
                    // or VPN that changed between the check and the connection: review round 2,
                    // bypass-3, the Linux application). Otherwise it is closed here.
                    if let Some(v) = vetted {
                        let stream = std::net::TcpStream::from(fd);
                        let addrs = stream.local_addr().and_then(|l| Ok((l, stream.peer_addr()?)));
                        let fd = OwnedFd::from(stream);
                        let Ok((local, peer)) = addrs else {
                            tracing::warn!(endpoint = %st.ep.alias, address = %addr, "connector: the connection's addresses could not be read; closed");
                            continue;
                        };
                        let floor = self.floor.clone();
                        let Ok(Ok(turn)) = tokio::time::timeout_at(deadline, self.checks.clone().acquire_owned()).await else {
                            tracing::debug!(endpoint = %st.ep.alias, address = %addr, "connector: no turn for the check once connected; closed");
                            continue;
                        };
                        let recheck = move || {
                            let _turn = turn;
                            floor.recheck_connected(&v, local, peer)
                        };
                        match tokio::task::spawn_blocking(recheck).await {
                            Ok(Ok(())) => {}
                            Ok(Err(d)) => {
                                tracing::warn!(endpoint = %st.ep.alias, address = %addr, refusal = %d, "connector: connection refused once made; closed");
                                drop(fd);
                                continue;
                            }
                            Err(_) => {
                                tracing::debug!(endpoint = %st.ep.alias, address = %addr, "connector: the check once connected did not finish");
                                continue;
                            }
                        }
                        return (Response { id, status: Status::Connected, peer: Some(addr) }, Some(fd));
                    }
                    return (Response { id, status: Status::Connected, peer: Some(addr) }, Some(fd));
                }
                Ok(Err(e)) => tracing::debug!(endpoint = %st.ep.alias, address = %addr, error = %e, "connector: connect failed"),
                Err(_) => tracing::debug!(endpoint = %st.ep.alias, address = %addr, "connector: connect timed out"),
            }
        }
        (Response::refused(id, Status::Unreachable), None)
    }

    /// Serves one broker session on the miner's end `sock` of the connector socketpair, until the
    /// broker closes it or is cut off (the socket is then closed on it, and a page logged). Either
    /// way, requests still being served are aborted before it returns. Needs a tokio runtime.
    pub async fn serve(self: Arc<Self>, sock: std::os::unix::net::UnixStream) -> SessionEnd {
        self.serve_session(sock, true).await
    }

    async fn serve_session(self: Arc<Self>, sock: std::os::unix::net::UnixStream, page: bool) -> SessionEnd {
        let sock = match sock.set_nonblocking(true).and_then(|()| tokio::net::UnixStream::from_std(sock)) {
            Ok(s) => Arc::new(s),
            Err(e) => {
                tracing::error!(error = %e, "connector: the socket");
                return SessionEnd::Closed;
            }
        };
        // Answers written but not yet read wait in the broker's receive queue, charged to this
        // end's send buffer: at the kernel's minimum it holds a few frames, so a broker that does
        // not read cannot park the sockets of many answers there either.
        if let Err(e) = shrink_send_buffer(&sock) {
            tracing::warn!(error = %e, "connector: shrinking the socket's send buffer");
        }
        // Every request id stays in flight until its answer is handed to the socket, so requests
        // being served, answers queued and the answer being written are all within
        // MAX_INFLIGHT (+ the one being written): a broker that stops reading reaches the bound
        // (a flood) or stalls the writer (both cut it off) instead of piling sockets up here.
        let in_flight: Arc<Mutex<HashSet<u64>>> = Arc::default();
        // One slot per id in flight at most (reserved when the request is admitted), so the queue
        // is never full while the bound holds.
        let (tx, rx) = mpsc::channel::<Answer>(MAX_INFLIGHT);
        let stall = request_budget(self.connect_timeout);
        let mut writer = tokio::spawn(write_answers(sock.clone(), rx, in_flight.clone(), stall));
        let mut writer_end: Option<Result<WriterEnd, tokio::task::JoinError>> = None;
        // Once the writer is gone (a failed write), when: from then on requests are still judged
        // as ever but nothing is connected or answered, and the broker's end must reach
        // end-of-file within EXITED_WITHIN (it exited) or it is cut off.
        let mut writer_gone_at: Option<Instant> = None;
        // The requests being served: aborted when the session ends, so nothing is connected for
        // a broker that is gone or cut off.
        let mut tasks = JoinSet::new();
        let mut misuse: VecDeque<Instant> = VecDeque::new();
        let mut frames = FrameReader::default();
        let end = loop {
            while tasks.try_join_next().is_some() {}
            let read = match writer_gone_at {
                None => {
                    // Reading first: a broker that exited is at end-of-file here before a failed
                    // write is looked at.
                    tokio::select! {
                        biased;
                        r = frames.read(&sock) => r,
                        w = &mut writer => {
                            if matches!(w, Ok(WriterEnd::Stalled)) {
                                break SessionEnd::CutOff(CutOff::AnswersStalled);
                            }
                            if let Ok(WriterEnd::Failed(e)) = &w {
                                tracing::debug!(error = %e, "connector: writing an answer failed");
                            }
                            writer_end = Some(w);
                            writer_gone_at = Some(Instant::now());
                            continue;
                        }
                    }
                }
                Some(at) => match tokio::time::timeout_at(at + EXITED_WITHIN, frames.read(&sock)).await {
                    Ok(r) => r,
                    // Still sending, no longer taking answers: it shut its reading side.
                    Err(_) => break SessionEnd::CutOff(CutOff::AnswersRefused),
                },
            };
            let frame = match read {
                Ok(Some(f)) => f,
                Ok(None) => break SessionEnd::Closed,
                Err(ReadError::FdAttached) => break SessionEnd::CutOff(CutOff::FdAttached),
                Err(ReadError::Io(e)) => {
                    tracing::debug!(error = %e, "connector: reading a request failed");
                    break SessionEnd::Closed;
                }
            };
            let req = match Request::decode(&frame) {
                Ok(r) => r,
                Err(m) => break SessionEnd::CutOff(CutOff::Malformed(m)),
            };
            self.stats.requests.fetch_add(1, Ordering::Relaxed);
            {
                let mut f = lock(&in_flight);
                if f.contains(&req.id) {
                    break SessionEnd::CutOff(CutOff::DuplicateId);
                }
                if f.len() >= MAX_INFLIGHT {
                    break SessionEnd::CutOff(CutOff::Flood);
                }
                f.insert(req.id);
            }
            // The answer's slot, before anything is done for the request (none once the writer is
            // gone: the request is judged, never served).
            let slot = match writer_gone_at {
                Some(_) => None,
                None => match tx.clone().try_reserve_owned() {
                    Ok(p) => Some(p),
                    Err(TrySendError::Full(_)) => break SessionEnd::CutOff(CutOff::Flood),
                    Err(TrySendError::Closed(_)) => {
                        writer_gone_at = Some(Instant::now());
                        None
                    }
                },
            };
            let index = usize::try_from(req.endpoint).ok().filter(|i| *i < self.endpoints.len());
            let refusal = match index {
                None => Some(Status::NoSuchEndpoint),
                Some(i) if self.endpoints[i].ep.role != req.role || self.endpoints[i].ep.port != req.port => Some(Status::Mismatch),
                Some(_) => None,
            };
            if let Some(status) = refusal {
                let now = Instant::now();
                misuse.push_back(now);
                while misuse.front().is_some_and(|t| now.duration_since(*t) > MISUSE_WINDOW) {
                    misuse.pop_front();
                }
                tracing::warn!(id = req.id, endpoint = req.endpoint, ?status, "connector: the broker asked for an endpoint it does not have");
                self.stats.refused.fetch_add(1, Ordering::Relaxed);
                // The bound before the answer: past it the broker is cut off whether or not it
                // still reads.
                if misuse.len() > MAX_MISUSE {
                    break SessionEnd::CutOff(CutOff::Misuse);
                }
                if let Some(slot) = slot {
                    slot.send((Response::refused(req.id, status), None));
                }
                continue;
            }
            let Some(slot) = slot else { continue };
            let me = self.clone();
            let index = index.unwrap_or_default();
            tasks.spawn(async move {
                let (resp, fd) = me.clone().connect_for(index, req.id).await;
                if resp.status == Status::Connected {
                    me.stats.connected.fetch_add(1, Ordering::Relaxed);
                } else {
                    me.stats.refused.fetch_add(1, Ordering::Relaxed);
                }
                slot.send((resp, fd));
            });
        };
        drop(tx);
        if let SessionEnd::CutOff(_) = &end {
            // Closed on the broker at once, before anything else: whatever else still holds the
            // socket, and whatever answers (sockets connected earlier included) are still queued
            // for the writer, nothing more reaches the broker.
            // SAFETY: shutdown of a socket this task owns.
            unsafe { libc::shutdown(sock.as_raw_fd(), libc::SHUT_RDWR) };
            writer.abort();
        }
        // Requests still being served are aborted (a socket one already made is closed, never
        // delivered), and gone before the session's end is reported.
        tasks.shutdown().await;
        if writer_gone_at.is_some() && writer_end.is_none() && matches!(end, SessionEnd::Closed) {
            writer_end = Some((&mut writer).await);
        }
        if let Some(Err(e)) = &writer_end {
            tracing::error!(error = %e, "connector: the answer writer failed");
        }
        match &end {
            SessionEnd::CutOff(why) => {
                if page {
                    tracing::error!("PAGE: WITNESS-BROKER-CUT-OFF: the connector closed the broker's socket: {why}");
                } else {
                    tracing::debug!("connector self-test session cut off as expected: {why}");
                }
            }
            SessionEnd::Closed => {
                // What is already queued is still written (each answer within the stall bound).
                if writer_end.is_none() {
                    let _ = writer.await;
                }
            }
        }
        // The last reference to the socket goes with this task (the writer's is gone): the broker
        // sees end-of-file.
        drop(sock);
        end
    }

    // -----------------------------------------------------------------------------------------
    // The self-test (checked in the miner).

    /// The connector's own checks: it refuses an address outside every endpoint's configured role
    /// entry or DNS answer, (public mode) every private probe for every endpoint, an index past
    /// the configuration, and a malformed request (which ends a test session with a cut-off).
    pub async fn self_test(self: &Arc<Self>) -> Vec<(SelfTestCheck, bool)> {
        let me = self.clone();
        let admission = tokio::task::spawn_blocking(move || {
            let facts = me.floor.facts();
            let mut private: Vec<IpAddr> = PRIVATE_PROBES.iter().map(|s| s.parse().expect("constant address")).collect();
            private.extend(facts.own_addresses().iter().copied());
            for p in facts.connected() {
                private.push(p.addr);
                if let Some(first) = first_host(p) {
                    private.push(first);
                }
            }
            let mut unconfigured_ok = true;
            let mut private_ok = true;
            for (i, st) in me.endpoints.iter().enumerate() {
                let pinned = lock(&st.pins).addrs.clone();
                for probe in STRANGER_PROBES.iter().map(|s| s.parse::<IpAddr>().expect("constant address")) {
                    let configured = st.ep.cidrs.iter().any(|p| p.contains(probe))
                        || st.ep.literal.is_some_and(|l| canonical_ip(l) == canonical_ip(probe))
                        || (st.ep.literal.is_none() && st.ep.cidrs.is_empty() && pinned.contains(&probe));
                    if !configured && me.admit(i, probe).is_ok() {
                        tracing::error!(endpoint = %st.ep.alias, address = %probe, "PAGE: connector self-test: an address outside the role entry is admitted");
                        unconfigured_ok = false;
                    }
                }
                if me.mode == NetMode::Public {
                    for probe in &private {
                        if me.admit(i, *probe).is_ok() {
                            tracing::error!(endpoint = %st.ep.alias, address = %probe, "PAGE: connector self-test: a private address is admitted in public mode");
                            private_ok = false;
                        }
                    }
                }
            }
            (unconfigured_ok, private_ok)
        })
        .await;
        let (unconfigured_ok, private_ok) = admission.unwrap_or((false, false));
        let (bad_index_ok, malformed_ok) = self.session_self_test().await;
        let mut checks = vec![
            (SelfTestCheck::ConnectorRefusesUnconfigured, unconfigured_ok),
            (SelfTestCheck::ConnectorRefusesBadIndex, bad_index_ok),
            (SelfTestCheck::ConnectorRefusesMalformed, malformed_ok),
        ];
        if self.mode == NetMode::Public {
            checks.push((SelfTestCheck::ConnectorRefusesPrivate, private_ok));
        }
        checks
    }

    /// A throwaway session: an index past the configuration is answered `NoSuchEndpoint`, then a
    /// malformed frame ends the session with a cut-off and the socket is closed.
    async fn session_self_test(self: &Arc<Self>) -> (bool, bool) {
        let Ok((ours, theirs)) = std::os::unix::net::UnixStream::pair() else { return (false, false) };
        let session = tokio::spawn(self.clone().serve_session(ours, false));
        let run = async {
            theirs.set_nonblocking(true).ok()?;
            let mut s = tokio::net::UnixStream::from_std(theirs).ok()?;
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let bad = Request { id: 1, endpoint: u32::MAX, role: Role::EvmRpc, port: 443 };
            s.write_all(&bad.encode()).await.ok()?;
            let mut b = [0u8; RESPONSE_LEN];
            s.read_exact(&mut b).await.ok()?;
            let bad_index = Response::decode(&b).ok() == Some(Response::refused(1, Status::NoSuchEndpoint));
            s.write_all(&[0x5a; REQUEST_LEN]).await.ok()?;
            let closed = matches!(s.read(&mut b).await, Ok(0));
            Some((bad_index, closed))
        };
        let (bad_index, closed) = tokio::time::timeout(Duration::from_secs(5), run).await.ok().flatten().unwrap_or((false, false));
        let end = tokio::time::timeout(Duration::from_secs(5), session).await;
        let cut = matches!(end, Ok(Ok(SessionEnd::CutOff(CutOff::Malformed(_)))));
        (bad_index, closed && cut)
    }
}

/// Probes that no endpoint may admit in public mode (besides the host's own addresses and its
/// connected prefixes).
const PRIVATE_PROBES: &[&str] =
    &["127.0.0.1", "::1", "169.254.169.254", "fd00:ec2::254", "10.0.0.1", "172.16.0.1", "192.168.1.1", "100.100.100.200"];
/// Global addresses no endpoint may admit unless its role entry or DNS answer holds them.
const STRANGER_PROBES: &[&str] = &["8.8.8.8", "1.1.1.1", "9.9.9.9", "2001:4860:4860::8888", "2606:4700:4700::1111"];

fn first_host(p: &Prefix) -> Option<IpAddr> {
    let net = crate::config::mask(p.addr, p.len);
    match net {
        IpAddr::V4(v) if p.len < 32 => Some(IpAddr::V4((u32::from(v) + 1).into())),
        IpAddr::V6(v) if p.len < 128 => Some(IpAddr::V6((u128::from(v) + 1).into())),
        _ => None,
    }
}

/// How long past the request's deadline the connector waits for a check that was given it
/// (the check gives up at the deadline; this covers its last step).
const CHECK_SLACK: Duration = Duration::from_millis(500);

/// A fresh TCP connection to `addr` (`socket` + `connect`, bound to `source` when given), as an
/// owned fd. An IPv4-mapped address is connected to as its IPv4 address, on an IPv4 socket
/// (review round 5, bypass-5: an IPv6 socket bound to the IPv4 source the check vetted failed
/// with `EINVAL`), as the guarded client's hops do.
async fn connect_tcp(addr: SocketAddr, source: Option<IpAddr>) -> io::Result<OwnedFd> {
    let addr = match addr.ip() {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(addr, |v4| SocketAddr::new(IpAddr::V4(v4), addr.port())),
        IpAddr::V4(_) => addr,
    };
    let sock = if addr.is_ipv4() { tokio::net::TcpSocket::new_v4()? } else { tokio::net::TcpSocket::new_v6()? };
    if let Some(src) = source {
        sock.bind(SocketAddr::new(src, 0))?;
    }
    let stream = sock.connect(addr).await?;
    Ok(OwnedFd::from(stream.into_std()?))
}

/// One answer and the socket it carries.
type Answer = (Response, Option<OwnedFd>);

/// Why the answer writer stopped.
#[derive(Debug)]
enum WriterEnd {
    /// Every sender is gone and the queue is written: the session is over.
    Done,
    /// One answer could not be written within the stall bound: the broker is not reading.
    Stalled,
    /// A write failed: the broker shut its reading side, or its end is closed.
    Failed(io::Error),
}

/// Writes the session's answers in order. An id leaves the in-flight set when its answer is
/// handed to the socket (before the write: the broker may read it and send its next request
/// before this task runs again). Each answer must be written within `stall`.
async fn write_answers(
    sock: Arc<tokio::net::UnixStream>,
    mut rx: mpsc::Receiver<Answer>,
    in_flight: Arc<Mutex<HashSet<u64>>>,
    stall: Duration,
) -> WriterEnd {
    while let Some((resp, fd)) = rx.recv().await {
        lock(&in_flight).remove(&resp.id);
        match tokio::time::timeout(stall, write_response(&sock, &resp.encode(), fd.as_ref())).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => return WriterEnd::Failed(e),
            Err(_) => return WriterEnd::Stalled,
        }
        // `fd` closes here: the broker's copy travels in the kernel's queue.
    }
    WriterEnd::Done
}

/// How soon after a failed answer write the requests of a broker that exited reach end-of-file.
const EXITED_WITHIN: Duration = Duration::from_secs(1);

/// Sets the socket's send buffer to the kernel's minimum (`SO_SNDBUF` 1 is raised to it).
fn shrink_send_buffer(sock: &tokio::net::UnixStream) -> io::Result<()> {
    let one: libc::c_int = 1;
    // SAFETY: setsockopt with an int of the stated length on a socket this session owns.
    let r = unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_SNDBUF,
            (&one as *const libc::c_int).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if r == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

enum ReadError {
    FdAttached,
    Io(io::Error),
}

/// Reads request frames, keeping a partial frame between calls: [`FrameReader::read`] is
/// cancel-safe (the session races it against its answer writer and a deadline; bytes already read
/// are never lost, so the stream never falls out of frame).
#[derive(Default)]
struct FrameReader {
    buf: [u8; REQUEST_LEN],
    off: usize,
}

impl FrameReader {
    /// Reads exactly one request frame; `None` at a clean end of stream. Ancillary data is
    /// received (so a file descriptor is noticed and closed) and is a protocol violation; a stream
    /// that ends inside a frame is a closed socket.
    async fn read(&mut self, sock: &tokio::net::UnixStream) -> Result<Option<[u8; REQUEST_LEN]>, ReadError> {
        while self.off < REQUEST_LEN {
            let mut fds = Vec::new();
            let off = self.off;
            let buf = &mut self.buf;
            // The only await: a cancellation there has consumed nothing; once `recvmsg` returned,
            // its bytes are counted below before anything else can run.
            let n = sock
                .async_io(Interest::READABLE, || retry_eintr(|| recvmsg_once(sock.as_raw_fd(), &mut buf[off..], &mut fds)))
                .await;
            if !fds.is_empty() {
                return Err(ReadError::FdAttached);
            }
            match n {
                Ok(0) if self.off == 0 => return Ok(None),
                Ok(0) => return Err(ReadError::Io(io::ErrorKind::UnexpectedEof.into())),
                Ok(n) => self.off += n,
                Err(e) if e.kind() == io::ErrorKind::InvalidData => return Err(ReadError::FdAttached),
                Err(e) => return Err(ReadError::Io(e)),
            }
        }
        self.off = 0;
        Ok(Some(self.buf))
    }
}

/// Writes one response frame, with `fd` attached to its first byte.
async fn write_response(sock: &tokio::net::UnixStream, frame: &[u8; RESPONSE_LEN], fd: Option<&OwnedFd>) -> io::Result<()> {
    let raw = sock.as_raw_fd();
    let mut off = 0;
    while off < frame.len() {
        let attach = if off == 0 { fd.map(|f| f.as_raw_fd()) } else { None };
        let n = sock.async_io(Interest::WRITABLE, || retry_eintr(|| sendmsg_once(raw, &frame[off..], attach))).await?;
        if n == 0 {
            return Err(io::ErrorKind::WriteZero.into());
        }
        off += n;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
