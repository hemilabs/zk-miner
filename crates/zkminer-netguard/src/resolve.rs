//! The guarded resolver: every connection to a name goes only to addresses the policy admitted,
//! from one resolution, with nothing left for the HTTP client to resolve again. (The guarded
//! client asks it itself, once per hop, and pins the hop to what it answers; it also implements
//! reqwest's DNS hook.) In public mode its lookup is netguard's DNS-over-HTTPS
//! ([`crate::doh::DohLookup`]), never the system resolver.
//!
//! For each connection reqwest asks [`GuardedResolver`] for the name's addresses (an IP-literal host
//! never reaches a resolver, which is why [`crate::check_url`] judges literals itself). The resolver
//! checks the name's hygiene (public mode), looks it up once through its [`Lookup`], passes every
//! answer through [`NetPolicy::admit`], and hands reqwest **only the admitted addresses**, with port
//! 0 (which the connector replaces by the URL's port). If none is admitted the connection fails with
//! [`Denied::NoAdmittedAddress`]. reqwest connects to exactly what it was handed, so a name whose
//! answers change between lookups (DNS rebinding, a TTL-0 record) cannot move the connection: the
//! address judged is the address connected to.

use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use crate::host::check_host_name;
use crate::policy::{Denied, NetMode, NetPolicy};

/// The future a [`Lookup`] returns.
pub type LookupFuture = Pin<Box<dyn Future<Output = io::Result<Vec<IpAddr>>> + Send>>;

/// Where answers come from: the system resolver in production ([`SystemLookup`]); a fake in tests,
/// so public and private answers can be staged for any name.
pub trait Lookup: Send + Sync + 'static {
    fn lookup(&self, host: &str) -> LookupFuture;
}

/// How long one system lookup may take.
pub const DNS_TIMEOUT: Duration = Duration::from_secs(5);

/// Lookups in flight at once, process-wide (see [`SystemLookup`]).
pub const MAX_CONCURRENT_LOOKUPS: usize = 16;

static LOOKUPS: OnceLock<tokio::sync::Semaphore> = OnceLock::new();

/// The system resolver (getaddrinfo), on tokio's blocking pool, bounded by [`DNS_TIMEOUT`].
///
/// **Absolute names only.** A name is looked up as written plus a trailing dot ([`absolute_name`]),
/// so the resolver's `search` list (and `domain`, `LOCALDOMAIN`) and its `ndots` rule never apply:
/// otherwise a requester's `secrets.corp` that has no public answer would be tried as
/// `secrets.corp.<the operator's search domain>` and answered from the operator's own zone, and with
/// `ndots:5` even `example.com` is tried under the search domain first. Requester names with a
/// trailing dot are still refused by the hygiene rules ([`crate::check_host_name`]); the dot is
/// added here, after them. IP literals are passed unchanged.
///
/// getaddrinfo cannot be cancelled: a lookup that times out keeps its pool thread until the OS
/// resolver gives up (tens of seconds for a black-holed nameserver). A requester who points many
/// names at a server that never answers could otherwise start lookups faster than they drain and
/// exhaust the blocking pool, stalling everything else on it. So at most
/// [`MAX_CONCURRENT_LOOKUPS`] are in flight at once, process-wide; each holds its permit for at
/// most the timeout, which caps the start rate and keeps the abandoned threads a small multiple of
/// the bound.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemLookup;

impl Lookup for SystemLookup {
    fn lookup(&self, host: &str) -> LookupFuture {
        let host = host.to_owned();
        Box::pin(async move {
            let _permit = LOOKUPS
                .get_or_init(|| tokio::sync::Semaphore::new(MAX_CONCURRENT_LOOKUPS))
                .acquire()
                .await
                .ok();
            let name = absolute_name(&host);
            let answer = tokio::time::timeout(
                DNS_TIMEOUT,
                tokio::task::spawn_blocking(move || {
                    (name.as_str(), 0)
                        .to_socket_addrs()
                        .map(|it| it.map(|a| a.ip()).collect::<Vec<_>>())
                }),
            )
            .await;
            match answer {
                Err(_) => Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("resolving {:?} timed out", crate::printable(&host, 128)),
                )),
                Ok(Err(join)) => Err(io::Error::other(join)),
                Ok(Ok(r)) => r,
            }
        })
    }
}

/// The name [`SystemLookup`] hands getaddrinfo for `host`: `host.` (absolute, so no search list or
/// `ndots` applies), or `host` itself when it already ends with a dot or is an IP literal.
pub fn absolute_name(host: &str) -> String {
    if host.ends_with('.') || host.parse::<IpAddr>().is_ok() {
        host.to_owned()
    } else {
        format!("{host}.")
    }
}

/// Most addresses handed to reqwest for one connection.
const MAX_ADDRS: usize = 8;

/// A test seam: the address actually connected to for an admitted one.
#[cfg(any(test, feature = "test-util"))]
pub type ConnectMap = Arc<dyn Fn(IpAddr) -> IpAddr + Send + Sync>;

/// reqwest's resolver for requester-caused connections (see the module doc).
#[derive(Clone)]
pub struct GuardedResolver {
    policy: NetPolicy,
    lookup: Arc<dyn Lookup>,
    #[cfg(any(test, feature = "test-util"))]
    connect_map: Option<ConnectMap>,
}

impl std::fmt::Debug for GuardedResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GuardedResolver")
            .field("mode", &self.policy.mode())
            .finish_non_exhaustive()
    }
}

impl GuardedResolver {
    pub fn new(policy: NetPolicy, lookup: Arc<dyn Lookup>) -> Self {
        GuardedResolver {
            policy,
            lookup,
            #[cfg(any(test, feature = "test-util"))]
            connect_map: None,
        }
    }

    /// A resolver that connects to `map(ip)` for each admitted `ip`: a server on loopback can then
    /// stand in for a public address in a public-mode test. Test builds only.
    #[cfg(any(test, feature = "test-util"))]
    pub fn with_connect_map(mut self, map: ConnectMap) -> Self {
        self.connect_map = Some(map);
        self
    }

    pub fn policy(&self) -> &NetPolicy {
        &self.policy
    }

    /// The admitted addresses of `host`, in answer order, deduplicated, at most 8: what a connection
    /// to it may use. Errors when the name fails hygiene (public mode), the lookup fails, or no
    /// answer is admitted.
    pub async fn resolve_admitted(&self, host: &str) -> Result<Vec<IpAddr>, ResolveError> {
        // A literal never reaches reqwest's resolver; one that does is judged as an address all the
        // same, and nothing is looked up.
        let answers = match host.parse::<IpAddr>() {
            Ok(ip) => vec![ip],
            Err(_) => {
                if self.policy.mode() == NetMode::Public {
                    check_host_name(host).map_err(|why| {
                        ResolveError::Denied(Denied::Host {
                            host: crate::printable(host, 128),
                            why,
                        })
                    })?;
                }
                self.lookup
                    .lookup(host)
                    .await
                    .map_err(ResolveError::Lookup)?
            }
        };
        // `admit` blocks (a facts re-read, a route query per destination: netlink, the routing
        // socket, the configuration daemon), so it runs on the blocking pool, never on a runtime
        // worker (review round 2, cross-3; the Linux application).
        let policy = self.policy.clone();
        let (admitted, refused) = tokio::task::spawn_blocking(move || {
            let mut admitted: Vec<IpAddr> = Vec::new();
            let mut refused = Vec::new();
            for ip in answers {
                match policy.admit(ip) {
                    Ok(()) if !admitted.contains(&ip) => admitted.push(ip),
                    Ok(()) => {}
                    Err(d) => {
                        if refused.len() < MAX_ADDRS {
                            refused.push(d);
                        }
                    }
                }
            }
            (admitted, refused)
        })
        .await
        .map_err(|e| ResolveError::Lookup(io::Error::other(e)))?;
        let mut admitted = admitted;
        if admitted.is_empty() {
            return Err(ResolveError::Denied(Denied::NoAdmittedAddress {
                host: crate::printable(host, 128),
                refused,
            }));
        }
        if !refused.is_empty() {
            tracing::debug!(
                "network guard: {} of {:?}'s answers refused, connecting only to the rest",
                refused.len(),
                crate::printable(host, 128)
            );
        }
        admitted.truncate(MAX_ADDRS);
        Ok(admitted)
    }

    /// The address connected to for the admitted `ip`: `ip` itself (in test builds, what the
    /// connect map says).
    pub(crate) fn connect_ip(&self, ip: IpAddr) -> IpAddr {
        #[cfg(any(test, feature = "test-util"))]
        let ip = match &self.connect_map {
            Some(map) => map(ip),
            None => ip,
        };
        ip
    }

    fn connect_addr(&self, ip: IpAddr) -> SocketAddr {
        SocketAddr::new(self.connect_ip(ip), 0)
    }
}

/// Why a name gave no address to connect to.
#[derive(Debug)]
pub enum ResolveError {
    /// The guard refused the name or every address it resolved to.
    Denied(Denied),
    /// The lookup itself failed (no such name, a timeout).
    Lookup(io::Error),
}

impl std::fmt::Display for ResolveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResolveError::Denied(d) => std::fmt::Display::fmt(d, f),
            ResolveError::Lookup(e) => write!(f, "DNS lookup failed: {e}"),
        }
    }
}

impl std::error::Error for ResolveError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ResolveError::Denied(d) => Some(d),
            ResolveError::Lookup(e) => Some(e),
        }
    }
}

impl reqwest::dns::Resolve for GuardedResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let this = self.clone();
        Box::pin(async move {
            let ips = this.resolve_admitted(name.as_str()).await?;
            let addrs: Vec<SocketAddr> = ips.into_iter().map(|ip| this.connect_addr(ip)).collect();
            Ok(Box::new(addrs.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::facts::HostFacts;
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// A lookup that answers from a table and records every name it was asked.
    #[derive(Default, Clone)]
    pub(crate) struct FakeLookup {
        pub(crate) answers: Arc<Mutex<HashMap<String, Vec<IpAddr>>>>,
        pub(crate) asked: Arc<Mutex<Vec<String>>>,
    }

    impl FakeLookup {
        pub(crate) fn with(entries: &[(&str, &[&str])]) -> Self {
            let f = FakeLookup::default();
            for (name, ips) in entries {
                f.answers.lock().unwrap().insert(
                    (*name).to_string(),
                    ips.iter().map(|s| s.parse().unwrap()).collect(),
                );
            }
            f
        }
    }

    impl Lookup for FakeLookup {
        fn lookup(&self, host: &str) -> LookupFuture {
            self.asked.lock().unwrap().push(host.to_string());
            let r = self
                .answers
                .lock()
                .unwrap()
                .get(host)
                .cloned()
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no such name"));
            Box::pin(async move { r })
        }
    }

    pub(crate) fn public_policy() -> NetPolicy {
        NetPolicy::with_facts(
            NetMode::Public,
            HostFacts::new(
                vec![
                    "9.9.9.0/24".parse().unwrap(),
                    "127.0.0.0/8".parse().unwrap(),
                ],
                vec!["9.9.9.10".parse().unwrap(), "127.0.0.1".parse().unwrap()],
            ),
            vec!["8.8.4.4/32".parse().unwrap()],
        )
    }

    fn ips(v: &[&str]) -> Vec<IpAddr> {
        v.iter().map(|s| s.parse().unwrap()).collect()
    }

    fn fake() -> FakeLookup {
        FakeLookup::with(&[
            (
                "public.example.com",
                &["93.184.216.34", "2606:2800:220:1::1"],
            ),
            ("private.example.com", &["10.0.0.1"]),
            ("loopback.example.com", &["127.0.0.1", "::1"]),
            (
                "metadata.example.com",
                &["169.254.169.254", "fd00:ec2::254"],
            ),
            (
                "mixed.example.com",
                &["127.0.0.1", "93.184.216.34", "10.1.2.3", "93.184.216.34"],
            ),
            ("nat64.example.com", &["64:ff9b::a9fe:a9fe"]),
            ("hairpin.example.com", &["9.9.9.10"]),
            ("neighbour.example.com", &["9.9.9.20"]),
            ("denied.example.com", &["8.8.4.4"]),
            ("empty.example.com", &[]),
            ("localhost", &["127.0.0.1"]),
        ])
    }

    #[tokio::test]
    async fn only_admitted_answers_are_returned() {
        let f = fake();
        let r = GuardedResolver::new(public_policy(), Arc::new(f.clone()));
        assert_eq!(
            r.resolve_admitted("public.example.com").await.unwrap(),
            ips(&["93.184.216.34", "2606:2800:220:1::1"])
        );
        // A rebinding-style answer set: the private addresses are dropped, the public one kept once.
        assert_eq!(
            r.resolve_admitted("mixed.example.com").await.unwrap(),
            ips(&["93.184.216.34"])
        );
    }

    #[tokio::test]
    async fn names_with_no_admitted_answer_fail_with_the_reasons() {
        let r = GuardedResolver::new(public_policy(), Arc::new(fake()));
        for host in [
            "private.example.com",
            "loopback.example.com",
            "metadata.example.com",
            "nat64.example.com",
            "hairpin.example.com",
            "neighbour.example.com",
            "denied.example.com",
            "empty.example.com",
        ] {
            match r.resolve_admitted(host).await {
                Err(ResolveError::Denied(Denied::NoAdmittedAddress { host: h, refused })) => {
                    assert_eq!(h, host);
                    if host != "empty.example.com" {
                        assert!(!refused.is_empty(), "{host}");
                    }
                }
                other => panic!("{host}: {other:?}"),
            }
        }
    }

    #[tokio::test]
    async fn local_names_are_refused_before_any_lookup_in_public_mode() {
        let f = fake();
        let r = GuardedResolver::new(public_policy(), Arc::new(f.clone()));
        for host in [
            "localhost",
            "foo.localhost",
            "metadata.google.internal",
            "nas.lan",
            "x.local.",
        ] {
            assert!(
                matches!(
                    r.resolve_admitted(host).await,
                    Err(ResolveError::Denied(Denied::Host { .. }))
                ),
                "{host}"
            );
        }
        assert!(
            f.asked.lock().unwrap().is_empty(),
            "{:?}",
            f.asked.lock().unwrap()
        );
        // A literal is judged as an address without a lookup.
        assert!(matches!(
            r.resolve_admitted("127.0.0.1").await,
            Err(ResolveError::Denied(Denied::NoAdmittedAddress { .. }))
        ));
        assert_eq!(
            r.resolve_admitted("1.1.1.1").await.unwrap(),
            ips(&["1.1.1.1"])
        );
        assert!(f.asked.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn lookup_failures_are_not_denials() {
        let r = GuardedResolver::new(public_policy(), Arc::new(fake()));
        assert!(matches!(
            r.resolve_admitted("nxdomain.example.com").await,
            Err(ResolveError::Lookup(_))
        ));
    }

    #[tokio::test]
    async fn dev_mode_returns_every_answer() {
        let dev = NetPolicy::with_facts(NetMode::DevPrivate, HostFacts::empty(), Vec::new());
        let r = GuardedResolver::new(dev, Arc::new(fake()));
        assert_eq!(
            r.resolve_admitted("localhost").await.unwrap(),
            ips(&["127.0.0.1"])
        );
        assert_eq!(
            r.resolve_admitted("mixed.example.com").await.unwrap(),
            ips(&["127.0.0.1", "93.184.216.34", "10.1.2.3"])
        );
    }

    /// What reqwest is handed: the admitted addresses with port 0, nothing else.
    #[tokio::test]
    async fn reqwest_gets_only_the_admitted_addresses_with_port_zero() {
        use reqwest::dns::Resolve;
        let r = GuardedResolver::new(public_policy(), Arc::new(fake()));
        let addrs: Vec<SocketAddr> = r
            .resolve("mixed.example.com".parse().unwrap())
            .await
            .unwrap()
            .collect();
        assert_eq!(
            addrs,
            vec!["93.184.216.34:0".parse::<SocketAddr>().unwrap()]
        );
        let e = match r.resolve("loopback.example.com".parse().unwrap()).await {
            Err(e) => e,
            Ok(a) => panic!("resolved to {:?}", a.collect::<Vec<_>>()),
        };
        assert!(
            e.to_string().contains("refused by the network guard"),
            "{e}"
        );
    }

    #[test]
    fn the_system_lookup_asks_for_absolute_names() {
        assert_eq!(absolute_name("example.com"), "example.com.");
        assert_eq!(absolute_name("secrets.corp"), "secrets.corp.");
        assert_eq!(absolute_name("localhost"), "localhost.");
        assert_eq!(absolute_name("example.com."), "example.com.");
        assert_eq!(absolute_name("192.0.2.1"), "192.0.2.1");
        assert_eq!(absolute_name("2001:db8::1"), "2001:db8::1");
    }

    #[tokio::test]
    async fn the_system_lookup_resolves_literals_and_the_resolver_judges_them() {
        // No network needed: getaddrinfo answers a literal itself.
        let r = GuardedResolver::new(public_policy(), Arc::new(SystemLookup));
        let got = SystemLookup.lookup("192.0.2.1").await.unwrap();
        assert_eq!(got, ips(&["192.0.2.1"]));
        assert!(r.resolve_admitted("192.0.2.1").await.is_err());
    }

    /// A route oracle that takes `delay` per answer (a slow facts re-read or route query).
    #[derive(Debug)]
    struct SlowOracle(Duration);

    impl crate::routes::RouteOracle for SlowOracle {
        fn route_to(
            &self,
            _: IpAddr,
            _: Option<u16>,
        ) -> std::io::Result<crate::routes::KernelAnswer> {
            std::thread::sleep(self.0);
            Ok(crate::routes::KernelAnswer::NoRoute)
        }
    }

    /// Review round 2, cross-3 (the Linux application): `admit` blocks (facts re-reads, route
    /// queries), so the resolver's admit loop runs on the blocking pool. On a single-threaded
    /// runtime, a ticker keeps ticking while three answers take 300 ms each to judge; were the
    /// loop on the runtime's thread, the ticker would not tick until it ended.
    #[tokio::test(flavor = "current_thread")]
    async fn the_admit_loop_runs_off_the_runtime() {
        let facts = HostFacts::new(Vec::new(), Vec::new())
            .with_route_oracle(Arc::new(SlowOracle(Duration::from_millis(300))));
        let policy = NetPolicy::with_facts(NetMode::Public, facts, Vec::new());
        let lookup = FakeLookup::with(&[("slow.example.com", &["1.1.1.1", "8.8.8.8", "9.9.9.9"])]);
        let r = GuardedResolver::new(policy, Arc::new(lookup));
        let ticks = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let t = ticks.clone();
        let ticker = tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_millis(10)).await;
                t.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
        });
        let start = std::time::Instant::now();
        assert!(r.resolve_admitted("slow.example.com").await.is_err());
        let took = start.elapsed();
        ticker.abort();
        let n = ticks.load(std::sync::atomic::Ordering::SeqCst);
        assert!(took >= Duration::from_millis(900), "{took:?}");
        // About 90 at 10 ms; well over half of them, whatever the scheduler's jitter.
        assert!(n >= 30, "the ticker ticked {n} times in {took:?}");
    }
}
