//! The one admission decision ([`admit`]) and the policy value callers hold ([`NetPolicy`]).

use std::fmt;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use crate::facts::{EgressPath, FactsOptions, HostFacts};
use crate::host::HostDenied;
use crate::ip::{canonical_ip, is_global, prefix_is_global, Prefix};
use crate::nearhop::{NearProbe, TtlProbe, Verdict};

/// Whether connections a requester causes may reach non-public destinations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum NetMode {
    /// The only mode a miner on a market runs in: a requester-caused connection goes only to a
    /// globally routable address that is not the host's own, not on a prefix the host is connected
    /// to, and not in the operator's deny CIDRs; requester host names pass the hygiene rules.
    #[default]
    Public,
    /// Developer mode (`[dev] private_network = true`): every destination is admitted, loopback and
    /// the LAN included, so a local test network can serve programs. Never on a public market.
    DevPrivate,
}

pub use crate::routes::RouteKind;

/// Why a destination or URL was refused. The `Display` of each says so in the guard's own words
/// (`refused by the network guard: …`), and prints only what is safe to log: addresses, prefixes,
/// and requester text escaped and bounded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Denied {
    /// Not globally routable unicast ([`crate::is_global`]).
    NotGlobal(IpAddr),
    /// One of the host's own addresses.
    OwnAddress(IpAddr),
    /// On a prefix one of the host's interfaces is connected to.
    ConnectedPrefix { ip: IpAddr, prefix: Prefix },
    /// In the site around one of the host's own global IPv6 addresses (`[egress]
    /// ipv6_site_prefix_len`), or around a global IPv4 address on one of its interfaces
    /// (`[egress] ipv4_site_prefix_len`).
    SitePrefix { ip: IpAddr, prefix: Prefix },
    /// One of the DNS servers the host uses.
    DnsServer(IpAddr),
    /// Its best route is not the default path ([`crate::routes`]).
    OffDefaultRoute {
        ip: IpAddr,
        route: Prefix,
        kind: RouteKind,
    },
    /// In one of the operator's deny CIDRs.
    DenyCidr { ip: IpAddr, prefix: Prefix },
    /// The URL is malformed or uses something refused (see [`UrlDenied`]).
    Url(UrlDenied),
    /// The URL's host name failed the hygiene rules.
    Host { host: String, why: HostDenied },
    /// The name resolved, but to no admitted address.
    NoAdmittedAddress { host: String, refused: Vec<Denied> },
    /// The kernel could not be asked how the destination is routed.
    RouteQueryFailed { ip: IpAddr, why: String },
    /// A prefix (an operator's role entry) holds an address that is not global.
    PrefixNotGlobal(Prefix),
    /// A prefix holds one of the host's own addresses.
    PrefixHoldsOwnAddress { prefix: Prefix, ip: IpAddr },
    /// A prefix overlaps a network the host is connected to.
    PrefixOverlapsConnected { prefix: Prefix, connected: Prefix },
    /// A prefix overlaps the site around one of the host's own addresses.
    PrefixOverlapsSite { prefix: Prefix, site: Prefix },
    /// A prefix holds one of the DNS servers the host uses.
    PrefixHoldsDnsServer { prefix: Prefix, ip: IpAddr },
    /// A prefix overlaps a route that does not take the default path, a route that delivers to
    /// this host, or a destination a policy rule sends to another table.
    PrefixOverlapsRoute { prefix: Prefix, route: Prefix },
    /// A prefix overlaps one of the operator's deny CIDRs.
    PrefixOverlapsDeny { prefix: Prefix, deny: Prefix },
    /// This host's public address on the path a connection to `ip` takes is not known (see
    /// [`HostFacts::unknown_paths`]): it could be this host or its router, reached by hairpin.
    PublicAddressUnknown { ip: IpAddr, path: EgressPath },
    /// The host's facts now need `[egress] internal_ranges` (a tunnel became the uplink, a global
    /// IPv4 address appeared: [`HostFacts::needs_internal_ranges`]), which the configuration does
    /// not state: every connection is refused until it does, or the condition clears.
    InternalRangesUnstated { ip: IpAddr, why: String },
    /// The destination answered within `hops` hops of this host ([`crate::nearhop`]), or the
    /// probe that asks failed: `what` says which.
    NearHop {
        addr: SocketAddr,
        hops: u8,
        what: String,
    },
    /// macOS: this host's facts could not be read again (`why`, naming what failed) and are
    /// older than [`FACTS_TTL`] and a grace of 2 s: every requester connection is refused
    /// until they can be read (review round 2, bypass-1).
    #[cfg(target_os = "macos")]
    FactsUnreadable { ip: IpAddr, why: String },
    /// macOS: an IPv6 destination while this host, with IPv6 and no IPv4 route, has just joined a
    /// network whose NAT64 prefix is still being learned ([`crate::nat64`]): an address under
    /// that prefix can carry a private IPv4 address (review round 3, bypass-1).
    #[cfg(target_os = "macos")]
    Nat64Unsettled(IpAddr),
}

/// What is wrong with a URL, apart from where it points.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UrlDenied {
    /// Longer than [`crate::MAX_URL_LEN`].
    TooLong,
    /// A byte outside printable ASCII, a space, or a backslash.
    BadCharacter,
    /// Not `http` or `https`.
    Scheme(String),
    /// User information (`user:pass@`) in the authority.
    UserInfo,
    /// No host, or a malformed authority.
    BadAuthority,
    /// A malformed or zero port.
    BadPort,
    /// An IPv6 literal with a zone id (`[fe80::1%eth0]`).
    ZoneId,
    /// The URL parser read it differently from the strict reading (scheme, host or port).
    Ambiguous,
    /// The URL did not parse.
    Unparseable,
}

impl fmt::Display for UrlDenied {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UrlDenied::TooLong => write!(f, "the URL is longer than {} bytes", crate::MAX_URL_LEN),
            UrlDenied::BadCharacter => {
                f.write_str("the URL has a byte outside printable ASCII, a space, or a backslash")
            }
            UrlDenied::Scheme(s) => write!(
                f,
                "the URL's scheme is {:?}, not http or https",
                crate::printable(s, 16)
            ),
            UrlDenied::UserInfo => f.write_str("the URL carries user information"),
            UrlDenied::BadAuthority => f.write_str("the URL has no host or a malformed authority"),
            UrlDenied::BadPort => f.write_str("the URL's port is malformed or zero"),
            UrlDenied::ZoneId => f.write_str("the URL's IPv6 literal has a zone id"),
            UrlDenied::Ambiguous => {
                f.write_str("the URL parser reads the URL differently from its strict reading")
            }
            UrlDenied::Unparseable => f.write_str("the URL does not parse"),
        }
    }
}

impl fmt::Display for Denied {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("refused by the network guard: ")?;
        self.reason(f)
    }
}

impl Denied {
    fn reason(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Denied::NotGlobal(ip) => write!(f, "{ip} is not a public internet address"),
            Denied::OwnAddress(ip) => write!(f, "{ip} is this host's own address"),
            Denied::ConnectedPrefix { ip, prefix } => {
                write!(
                    f,
                    "{ip} is on {prefix}, a network this host is connected to"
                )
            }
            Denied::SitePrefix { ip, prefix } => write!(
                f,
                "{ip} is in {prefix}, the site around one of this host's own addresses"
            ),
            Denied::DnsServer(ip) => write!(f, "{ip} is a DNS server this host uses"),
            Denied::OffDefaultRoute { ip, route, kind } => match kind {
                RouteKind::OnLink => write!(
                    f,
                    "{ip} is routed on-link by {route}, not by the default route"
                ),
                RouteKind::OtherGateway => write!(
                    f,
                    "{ip} is routed by {route} through a gateway other than the default route's"
                ),
                RouteKind::Local => write!(
                    f,
                    "{ip} is delivered to this host itself (its local route {route})"
                ),
                RouteKind::NoRoute => write!(f, "{ip} has no route on this host"),
                RouteKind::PolicyRule => write!(
                    f,
                    "{ip} is routed by {route}, which a policy-routing rule (ip rule) sends to \
                     another routing table than the default route's"
                ),
            },
            Denied::DenyCidr { ip, prefix } => {
                write!(f, "{ip} is in the operator's deny CIDR {prefix}")
            }
            Denied::RouteQueryFailed { ip, why } => {
                write!(f, "could not ask the kernel how {ip} is routed ({why})")
            }
            Denied::Url(why) => fmt::Display::fmt(why, f),
            Denied::Host { host, why } => write!(f, "host {host:?}: {why}"),
            Denied::PrefixNotGlobal(p) => {
                write!(f, "{p} holds addresses that are not on the public internet")
            }
            Denied::PrefixHoldsOwnAddress { prefix, ip } => {
                write!(f, "{prefix} holds {ip}, this host's own address")
            }
            Denied::PrefixOverlapsConnected { prefix, connected } => {
                write!(
                    f,
                    "{prefix} overlaps {connected}, a network this host is connected to"
                )
            }
            Denied::PrefixOverlapsDeny { prefix, deny } => {
                write!(f, "{prefix} overlaps the operator's deny CIDR {deny}")
            }
            Denied::PrefixOverlapsSite { prefix, site } => write!(
                f,
                "{prefix} overlaps {site}, the site around one of this host's own addresses"
            ),
            Denied::PrefixHoldsDnsServer { prefix, ip } => {
                write!(f, "{prefix} holds {ip}, a DNS server this host uses")
            }
            Denied::PrefixOverlapsRoute { prefix, route } => write!(
                f,
                "{prefix} overlaps {route}, which this host routes other than by its default \
                 route (another gateway, on-link, to itself, or by a policy rule)"
            ),
            Denied::PublicAddressUnknown { ip, path } => {
                if *path == EgressPath::Nat64 {
                    write!(
                        f,
                        "{ip} is reached through a NAT64 translator whose own IPv4 address this \
                         host has not learned (it could hairpin to the translator or this host); \
                         {}",
                        path.advice()
                    )
                } else {
                    write!(
                        f,
                        "{ip} is reached over {path}, and this host's public {path} address is \
                         not known (it could be this host or its router, reached by hairpin); {}",
                        path.advice()
                    )
                }
            }
            Denied::InternalRangesUnstated { ip, why } => write!(
                f,
                "{ip} is not connected to: {why}, so this host now needs `internal_ranges = \
                 [\"<cidr>\", ...]` in [egress] (the ranges of your own network that route reaches; \
                 `[]` if there are none), which the config does not state. Every connection is \
                 refused until it does"
            ),
            #[cfg(target_os = "macos")]
            Denied::FactsUnreadable { ip, why } => write!(
                f,
                "{ip} cannot be judged: this host's network facts (interfaces, routes, DNS \
                 servers) could not be read again for more than {}s ({why}), so every \
                 requester-caused connection is refused until they can be",
                (FACTS_TTL + REFRESH_GRACE).as_secs()
            ),
            #[cfg(target_os = "macos")]
            Denied::Nat64Unsettled(ip) => write!(
                f,
                "{ip} cannot be judged yet: this host, with IPv6 and no IPv4 route, is on a new \
                 network whose NAT64 prefix is still being learned (RFC 7050, at most {}s), and an \
                 IPv6 address under that prefix can carry a private IPv4 address",
                crate::nat64::DISCOVERY_TIMEOUT.as_secs()
            ),
            Denied::NearHop { addr, hops, what } => write!(
                f,
                "{addr} is within {hops} hops of this host, on its own network (a probe limited \
                 to {hops} hops: {what})"
            ),
            Denied::NoAdmittedAddress { host, refused } => {
                write!(f, "{host:?} resolves to no admitted address (")?;
                for (i, d) in refused.iter().enumerate() {
                    if i > 0 {
                        f.write_str("; ")?;
                    }
                    d.reason(f)?;
                }
                f.write_str(")")
            }
        }
    }
}

impl std::error::Error for Denied {}

impl Denied {
    /// Whether the refusal rests on the host's facts (which may have changed since they were
    /// read), rather than on the address alone or the operator's deny CIDRs.
    pub fn depends_on_facts(&self) -> bool {
        #[cfg(target_os = "macos")]
        if matches!(
            self,
            Denied::FactsUnreadable { .. } | Denied::Nat64Unsettled(_)
        ) {
            return true;
        }
        matches!(
            self,
            Denied::OwnAddress(_)
                | Denied::ConnectedPrefix { .. }
                | Denied::SitePrefix { .. }
                | Denied::DnsServer(_)
                | Denied::OffDefaultRoute { .. }
                | Denied::RouteQueryFailed { .. }
                | Denied::PublicAddressUnknown { .. }
                | Denied::InternalRangesUnstated { .. }
        )
    }
}

/// The single admission decision for one destination address of a connection a requester caused.
///
/// [`NetMode::DevPrivate`] admits everything. [`NetMode::Public`] admits `ip` only if it is globally
/// routable ([`crate::is_global`], judged on `ip` as given) and, judged on its [`canonical_ip`] (so
/// an IPv4-mapped, SIIT or NAT64 spelling of an address is that address), it is none of the host's
/// own addresses (its public NAT addresses included), on none of its connected prefixes (on-link
/// routes included), in none of its IPv6 site prefixes, none of the DNS servers it uses, in none of
/// `extra_deny`, its best route (as given, and as its canonical address) is the default path
/// ([`crate::routes::RouteTable::off_default_path`]), and — for facts read from this host — the
/// kernel, asked how it would route a connection to `ip`, answers with the default path
/// ([`crate::routes::RouteTable::judge`]; one netlink round trip per destination and facts
/// snapshot). Last, the host's public address on the path the connection takes must be known
/// ([`HostFacts::unknown_paths`]), and the facts must not need `[egress] internal_ranges` the
/// configuration does not state ([`HostFacts::config_gaps`]).
pub fn admit(
    mode: NetMode,
    ip: IpAddr,
    facts: &HostFacts,
    extra_deny: &[Prefix],
) -> Result<(), Denied> {
    admit_inner(mode, ip, None, facts, extra_deny)
}

/// [`admit`] for a connection to `addr`, its port included: the kernel is asked how it routes a
/// connection to that address and destination port (a rule may select by port).
pub fn admit_to(
    mode: NetMode,
    addr: SocketAddr,
    facts: &HostFacts,
    extra_deny: &[Prefix],
) -> Result<(), Denied> {
    admit_inner(mode, addr.ip(), Some(addr.port()), facts, extra_deny)
}

fn admit_inner(
    mode: NetMode,
    ip: IpAddr,
    dport: Option<u16>,
    facts: &HostFacts,
    extra_deny: &[Prefix],
) -> Result<(), Denied> {
    if mode == NetMode::DevPrivate {
        return Ok(());
    }
    #[cfg(target_os = "macos")]
    if let Some(why) = facts.unreadable() {
        return Err(Denied::FactsUnreadable {
            ip,
            why: why.to_string(),
        });
    }
    #[cfg(target_os = "macos")]
    if ip.is_ipv6() && facts.nat64_unsettled() {
        return Err(Denied::Nat64Unsettled(ip));
    }
    if !is_global(ip) {
        return Err(Denied::NotGlobal(ip));
    }
    let c = canonical_ip(ip);
    // Review r2 R2-NG-5: `contains` gets the address as given, and compares it both as written
    // and in canonical form; handed the canonical form, a prefix written in another spelling (a
    // deny of `64:ff9b::/64`) never saw the address as written (`64:ff9b::808:808`).
    let same = |o: &IpAddr| *o == ip || canonical_ip(*o) == c;
    if facts.own_addresses().iter().any(same) {
        return Err(Denied::OwnAddress(ip));
    }
    if let Some(p) = facts.connected().iter().find(|p| p.contains(ip)) {
        return Err(Denied::ConnectedPrefix { ip, prefix: *p });
    }
    if let Some(p) = facts.site_prefixes().iter().find(|p| p.contains(ip)) {
        return Err(Denied::SitePrefix { ip, prefix: *p });
    }
    if facts.resolvers().iter().any(same) {
        return Err(Denied::DnsServer(ip));
    }
    if let Some(p) = extra_deny.iter().find(|p| p.contains(ip)) {
        return Err(Denied::DenyCidr { ip, prefix: *p });
    }
    let routes = facts.routes();
    if let Some(r) = routes
        .off_default_path(ip)
        .or_else(|| (c != ip).then(|| routes.off_default_path(c)).flatten())
    {
        return Err(Denied::OffDefaultRoute {
            ip,
            route: r.prefix,
            kind: r.kind,
        });
    }
    // Review r2 R2-NG-3: the kernel applies the policy rules exactly; the tables above are the
    // prefix model, which a destination rule into a default-only table slipped past.
    facts.kernel_verdict(ip, dport)?;
    facts
        .path_known(ip)
        .map_err(|path| Denied::PublicAddressUnknown { ip, path })?;
    // Re-judged with every snapshot: a tunnel that became the uplink after startup is refused
    // like one there at startup.
    let gaps = facts.config_gaps();
    if !gaps.is_empty() {
        return Err(Denied::InternalRangesUnstated {
            ip,
            why: crate::printable(&gaps.join("; "), 400),
        });
    }
    Ok(())
}

/// [`admit`] for every address of a prefix at once (an operator's role entry, which admits
/// connections to any address inside it): in [`NetMode::Public`] the whole prefix must be global
/// ([`crate::ip::prefix_is_global`]), hold none of the host's own addresses and none of its DNS
/// servers, and overlap none of its connected prefixes, its site prefixes, its routes off the
/// default path and none of `extra_deny`, each compared in canonical form
/// ([`Prefix::canonical_prefix`]). [`NetMode::DevPrivate`] admits every prefix.
pub fn admit_prefix(
    mode: NetMode,
    prefix: Prefix,
    facts: &HostFacts,
    extra_deny: &[Prefix],
) -> Result<(), Denied> {
    if mode == NetMode::DevPrivate {
        return Ok(());
    }
    let prefix = Prefix::new(prefix.addr, prefix.len);
    if !prefix_is_global(prefix) {
        return Err(Denied::PrefixNotGlobal(prefix));
    }
    if let Some(ip) = facts
        .own_addresses()
        .iter()
        .find(|o| prefix.overlaps(&Prefix::host(**o)))
    {
        return Err(Denied::PrefixHoldsOwnAddress { prefix, ip: *ip });
    }
    if let Some(c) = facts.connected().iter().find(|c| prefix.overlaps(c)) {
        return Err(Denied::PrefixOverlapsConnected {
            prefix,
            connected: *c,
        });
    }
    if let Some(s) = facts.site_prefixes().iter().find(|s| prefix.overlaps(s)) {
        return Err(Denied::PrefixOverlapsSite { prefix, site: *s });
    }
    if let Some(ip) = facts
        .resolvers()
        .iter()
        .find(|r| prefix.overlaps(&Prefix::host(**r)))
    {
        return Err(Denied::PrefixHoldsDnsServer { prefix, ip: *ip });
    }
    if let Some(d) = extra_deny.iter().find(|d| prefix.overlaps(d)) {
        return Err(Denied::PrefixOverlapsDeny { prefix, deny: *d });
    }
    if let Some(r) = facts
        .routes()
        .off_default_prefixes()
        .into_iter()
        .find(|r| prefix.overlaps(r))
    {
        return Err(Denied::PrefixOverlapsRoute { prefix, route: r });
    }
    Ok(())
}

/// How long gathered host facts are trusted before they are read again (interfaces, routes and
/// `resolv.conf` are cheap to read; the public addresses have their own cache,
/// [`crate::public::DISCOVERY_TTL`]).
pub const FACTS_TTL: Duration = Duration::from_secs(1);

/// A refusal that rests on the host's facts re-reads them first, unless they are younger than
/// this: a host that just changed networks is judged on its new facts.
pub const FORCED_REFRESH_MIN_AGE: Duration = Duration::from_millis(100);

/// macOS: how long after [`FACTS_TTL`] facts whose refresh failed are still judged with (review
/// round 2, bypass-1): a failure that clears within it (a resolver file being rewritten) refuses
/// nothing; one that lasts longer refuses every requester connection
/// ([`Denied::FactsUnreadable`]) until the facts can be read again.
#[cfg(target_os = "macos")]
pub const REFRESH_GRACE: Duration = Duration::from_secs(2);

/// macOS: how long a caller that finds the facts being re-read waits for that re-read (review
/// round 3, 12(b)); a normal re-read takes tens of milliseconds.
#[cfg(target_os = "macos")]
pub const REFRESH_WAIT: Duration = Duration::from_millis(500);

/// The host facts a policy judges with: gathered and re-read once older than [`FACTS_TTL`] (or
/// on a facts-dependent refusal, [`FORCED_REFRESH_MIN_AGE`]), or fixed by the caller.
#[derive(Debug)]
struct FactsCell {
    current: RwLock<Arc<HostFacts>>,
    refresh: bool,
    options: FactsOptions,
    /// The paths last warned about as unknown ([`HostFacts::unknown_paths`]).
    warned: std::sync::Mutex<Vec<EgressPath>>,
    /// The configuration gaps last warned about ([`HostFacts::config_gaps`]).
    warned_gaps: std::sync::Mutex<Vec<String>>,
    /// macOS: held while the facts are re-read (one re-read at a time: review round 2, cross-3),
    /// with the last re-read's failure, if it failed.
    #[cfg(target_os = "macos")]
    refreshing: std::sync::Mutex<Option<RefreshFailure>>,
    /// macOS: when the re-read under way started, if one is (see [`Self::lock_refresh`]).
    #[cfg(target_os = "macos")]
    refresh_started: std::sync::Mutex<Option<std::time::Instant>>,
    /// macOS tests: a failure to stage in place of the next re-reads, and their count.
    #[cfg(all(test, target_os = "macos"))]
    seam: RefreshSeam,
}

/// macOS: the last re-read of the facts failed.
#[cfg(target_os = "macos")]
#[derive(Debug)]
struct RefreshFailure {
    /// When it was tried.
    at: std::time::Instant,
    /// Why it failed.
    why: String,
}

#[cfg(all(test, target_os = "macos"))]
#[derive(Debug, Default)]
struct RefreshSeam {
    fail: std::sync::Mutex<Option<String>>,
    delay: std::sync::Mutex<Duration>,
    gathers: std::sync::atomic::AtomicUsize,
}

impl FactsCell {
    fn get(&self) -> Arc<HostFacts> {
        self.get_fresher_than(FACTS_TTL)
    }

    /// macOS: the facts, re-read first if they are older than `max_age` (and the cell refreshes),
    /// one re-read at a time: a caller that finds one under way waits for it and takes its facts.
    /// A re-read that fails (an `/etc/resolver` file that cannot be read, a configuration daemon
    /// that does not answer: review round 2, bypass-1) leaves the last good facts in force,
    /// without their cached kernel verdicts, for [`REFRESH_GRACE`] past [`FACTS_TTL`]; after
    /// that, and until a re-read succeeds, the facts in force refuse every requester connection
    /// ([`Denied::FactsUnreadable`], naming the failure). A failed re-read is tried again on a
    /// later call, at most every [`FORCED_REFRESH_MIN_AGE`]. A caller waits for a re-read under way
    /// at most [`REFRESH_WAIT`] ([`Self::lock_refresh`]).
    #[cfg(target_os = "macos")]
    fn get_fresher_than(&self, max_age: Duration) -> Arc<HostFacts> {
        let read = || {
            self.current
                .read()
                .unwrap_or_else(|e| e.into_inner())
                .clone()
        };
        let current = read();
        if !self.refresh || current.gathered_at().elapsed() < max_age {
            return current;
        }
        let mut failure = match self.lock_refresh() {
            Ok(failure) => failure,
            Err(facts) => return facts,
        };
        // Re-read by another caller while this one waited.
        let current = read();
        if current.gathered_at().elapsed() < max_age {
            return current;
        }
        let retry = failure
            .as_ref()
            .is_none_or(|f| f.at.elapsed() >= FORCED_REFRESH_MIN_AGE);
        if retry {
            let started = |at| {
                *self
                    .refresh_started
                    .lock()
                    .unwrap_or_else(|e| e.into_inner()) = at
            };
            started(Some(std::time::Instant::now()));
            let gathered = self.gather();
            started(None);
            match gathered {
                Ok(fresh) => {
                    let fresh = Arc::new(fresh);
                    if let Some(f) = failure.take() {
                        tracing::info!(
                            "network guard: this host's network facts are read again (after: \
                             {}); connections are judged again",
                            f.why
                        );
                    }
                    self.warn_unknown(&fresh);
                    *self.current.write().unwrap_or_else(|e| e.into_inner()) = fresh.clone();
                    return fresh;
                }
                Err(e) => {
                    let why = crate::printable(&e.to_string(), 300);
                    if failure.as_ref().is_none_or(|f| f.why != why) {
                        tracing::warn!(
                            "network guard: re-reading this host's network facts failed: {why}. \
                             Unless that clears within {}s, every requester-caused connection is \
                             refused until it does",
                            REFRESH_GRACE.as_secs()
                        );
                    }
                    *failure = Some(RefreshFailure {
                        at: std::time::Instant::now(),
                        why,
                    });
                    // What the kernel answered for the old facts is asked again.
                    let kept = Arc::new(current.without_verdicts());
                    *self.current.write().unwrap_or_else(|e| e.into_inner()) = kept;
                }
            }
        }
        let current = read();
        let Some(f) = failure.as_ref() else {
            return current;
        };
        if current.unreadable().is_some()
            || current.gathered_at().elapsed() < FACTS_TTL + REFRESH_GRACE
        {
            return current;
        }
        tracing::error!(
            "network guard: this host's network facts could not be read again for more than {}s \
             ({}): refusing every requester-caused connection until they can be",
            (FACTS_TTL + REFRESH_GRACE).as_secs(),
            f.why
        );
        let refusing = Arc::new(current.refusing(f.why.clone()));
        *self.current.write().unwrap_or_else(|e| e.into_inner()) = refusing.clone();
        refusing
    }

    /// macOS: the re-read lock, waited for until the re-read under way is [`REFRESH_WAIT`] old
    /// (review round 3, 12(b)). A re-read that takes longer (a configuration daemon that answers
    /// just within its 2 s, or not at all) holds only the caller that runs it: the others get,
    /// without waiting further, the
    /// facts in force while those are within [`FACTS_TTL`] + [`REFRESH_GRACE`], and after that
    /// those facts made to refuse every requester connection, saying why
    /// ([`Denied::FactsUnreadable`]).
    #[cfg(target_os = "macos")]
    fn lock_refresh(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, Option<RefreshFailure>>, Arc<HostFacts>> {
        let first = std::time::Instant::now();
        loop {
            match self.refreshing.try_lock() {
                Ok(g) => return Ok(g),
                Err(std::sync::TryLockError::Poisoned(e)) => return Ok(e.into_inner()),
                Err(std::sync::TryLockError::WouldBlock) => {}
            }
            let since = self
                .refresh_started
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .unwrap_or(first);
            if since.elapsed() >= REFRESH_WAIT {
                break;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        let current = self
            .current
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        if current.unreadable().is_some()
            || current.gathered_at().elapsed() < FACTS_TTL + REFRESH_GRACE
        {
            return Err(current);
        }
        Err(Arc::new(current.refusing(format!(
            "a re-read of them has not finished within {}s",
            (FACTS_TTL + REFRESH_GRACE).as_secs()
        ))))
    }

    /// macOS: one re-read of the facts (tests stage a failure, a delay, and count them).
    #[cfg(target_os = "macos")]
    fn gather(&self) -> io::Result<HostFacts> {
        #[cfg(test)]
        {
            use std::sync::atomic::Ordering;
            self.seam.gathers.fetch_add(1, Ordering::SeqCst);
            let delay = *self.seam.delay.lock().unwrap();
            std::thread::sleep(delay);
            if let Some(why) = self.seam.fail.lock().unwrap().clone() {
                return Err(io::Error::other(why));
            }
        }
        HostFacts::gather_with(&self.options)
    }

    /// The facts, re-read first if they are older than `max_age` (and the cell refreshes).
    #[cfg(not(target_os = "macos"))]
    fn get_fresher_than(&self, max_age: Duration) -> Arc<HostFacts> {
        let current = self
            .current
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        if !self.refresh || current.gathered_at().elapsed() < max_age {
            return current;
        }
        match HostFacts::gather_with(&self.options) {
            Ok(fresh) => {
                let fresh = Arc::new(fresh);
                self.warn_unknown(&fresh);
                *self.current.write().unwrap_or_else(|e| e.into_inner()) = fresh.clone();
                fresh
            }
            Err(e) => {
                // The last good facts stay in force (an interface read that fails says nothing about
                // the interfaces), and the next call tries again.
                tracing::warn!("network guard: re-reading this host's interfaces failed: {e}");
                current
            }
        }
    }
}

/// Refuses, at startup in public mode, what the guard cannot run safely or usefully with, saying
/// what to change:
///
/// - a host with a global IPv4 interface address or a default route through a tunnel, unless
///   `[egress] internal_ranges` is set ([`HostFacts::needs_internal_ranges`]);
/// - public-address discovery turned off while `[egress] public_addresses` names no address of a
///   family the host routes;
/// - local routes that hold every public address the host routes
///   ([`crate::RouteTable::local_refuses_everything`]).
fn usable(facts: &HostFacts, options: &FactsOptions) -> io::Result<()> {
    let invalid = |m: String| io::Error::new(io::ErrorKind::InvalidInput, m);
    if options.internal_ranges.is_none() {
        let why = facts.needs_internal_ranges();
        if !why.is_empty() {
            return Err(invalid(format!(
                "{}. Other hosts of a network like that are reached by the same route as the \
                 internet, and the network guard cannot tell them apart from it. Add \
                 `internal_ranges = [\"<cidr>\", ...]` to [egress] in the config, listing every \
                 range of your own network (campus, data centre or VPC ranges, what the tunnel \
                 leads to); they are refused like deny_cidrs. `internal_ranges = []` states that \
                 there are none",
                why.join("; ")
            )));
        }
    }
    if !options.discover_public_addresses {
        for v6 in [false, true] {
            let named = options.public_addresses.iter().any(|a| a.is_ipv6() == v6);
            if facts.routes().routes_family(v6) && !named {
                let fam = if v6 { "IPv6" } else { "IPv4" };
                return Err(invalid(format!(
                    "[egress] discover_public_addresses = false, but [egress] public_addresses \
                     names no {fam} address and this host routes {fam}: the network guard must \
                     know this host's public {fam} address to refuse it. Add `public_addresses = \
                     [\"<this host's public {fam} address>\"]` to [egress], or turn discovery \
                     back on"
                )));
            }
        }
    }
    let Some(local) = facts.routes().local_refuses_everything() else {
        return Ok(());
    };
    let list: Vec<String> = local.iter().map(Prefix::to_string).collect();
    Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        format!(
            "this host's local routes ({}) deliver every public address to this host itself, so \
             the network guard would refuse every destination. A transparent proxy's catch-all \
             belongs in a routing table only a fwmark rule consults, as `local 0.0.0.0/0` / \
             `local ::/0` (which the guard leaves alone)",
            list.join(", ")
        ),
    ))
}

impl FactsCell {
    /// Says loudly, when it changes, which paths no connection may go out over because this
    /// host's public address on them is not known, and what to set.
    fn warn_unknown(&self, facts: &HostFacts) {
        let now = facts.unknown_paths();
        let mut last = self.warned.lock().unwrap_or_else(|e| e.into_inner());
        if *last == now {
            return;
        }
        for path in &now {
            tracing::warn!(
                "network guard: this host's public {path} address is not known, so every \
                 requester-caused connection over {path} is refused (it could reach this host or \
                 its router by hairpin). To fix: {}",
                path.advice()
            );
        }
        if now.is_empty() && !last.is_empty() {
            tracing::info!("network guard: this host's public addresses are known again");
        }
        *last = now;
        drop(last);
        let gaps = facts.config_gaps();
        let mut last = self.warned_gaps.lock().unwrap_or_else(|e| e.into_inner());
        if *last == gaps {
            return;
        }
        if !gaps.is_empty() {
            tracing::warn!(
                "network guard: {}. This host now needs `internal_ranges = [\"<cidr>\", ...]` in \
                 [egress] (the ranges of your own network that route reaches; `[]` if there are \
                 none), which the config does not state: every requester-caused connection is \
                 refused until it does, or this clears",
                gaps.join("; ")
            );
        } else {
            tracing::info!(
                "network guard: this host no longer needs [egress] internal_ranges; connections \
                 are admitted again"
            );
        }
        *last = gaps;
    }
}

/// A network policy: the mode, the host's facts, and the operator's extra deny CIDRs. Cheap to clone
/// (shared state). Every requester-caused connection is judged by one: [`NetPolicy::admit`] for an
/// address, [`NetPolicy::check_url`] for a URL, [`NetPolicy::vet_connection`] right before a
/// connection is made, and the guarded resolver and client built from it.
#[derive(Debug, Clone)]
pub struct NetPolicy {
    mode: NetMode,
    facts: Arc<FactsCell>,
    deny: Arc<[Prefix]>,
    probe: Arc<dyn NearProbe>,
}

impl NetPolicy {
    /// A policy over this host's own facts with the default options ([`FactsOptions::default`]);
    /// see [`Self::with_options`].
    pub fn new(mode: NetMode, deny: Vec<Prefix>) -> io::Result<Self> {
        Self::with_options(mode, deny, FactsOptions::default())
    }

    /// A policy over this host's own facts, gathered now with `options` (in [`NetMode::Public`])
    /// and re-read once older than [`FACTS_TTL`], or before a refusal that rests on them; `deny`
    /// and `options`' `internal_ranges` are refused. Fails if the interfaces or the routing table
    /// cannot be read, `options` is invalid, or (public mode) the guard cannot run on this host
    /// as configured (`usable`: a global IPv4 interface address or a tunnel uplink without
    /// `[egress] internal_ranges`, discovery off without `[egress] public_addresses`, local routes
    /// that hold every address): a public-mode policy that does not know the host cannot refuse
    /// it. Warns about every path whose public address is not known.
    pub fn with_options(
        mode: NetMode,
        mut deny: Vec<Prefix>,
        options: FactsOptions,
    ) -> io::Result<Self> {
        options
            .validate()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        for p in options.internal_ranges.iter().flatten() {
            if !deny.contains(p) {
                deny.push(*p);
            }
        }
        let (facts, refresh) = match mode {
            NetMode::Public => (HostFacts::gather_with(&options)?, true),
            NetMode::DevPrivate => (HostFacts::empty(), false),
        };
        if mode == NetMode::Public {
            usable(&facts, &options)?;
        }
        let policy = Self::build(mode, facts, refresh, deny, options);
        if mode == NetMode::Public {
            policy.facts.warn_unknown(&policy.facts.get());
        }
        Ok(policy)
    }

    /// A policy over fixed facts, never re-read: for tests, and for a caller that refreshes the
    /// facts itself (and builds a new policy when they change).
    pub fn with_facts(mode: NetMode, facts: HostFacts, deny: Vec<Prefix>) -> Self {
        Self::build(mode, facts, false, deny, FactsOptions::default())
    }

    fn build(
        mode: NetMode,
        facts: HostFacts,
        refresh: bool,
        deny: Vec<Prefix>,
        options: FactsOptions,
    ) -> Self {
        NetPolicy {
            mode,
            facts: Arc::new(FactsCell {
                current: RwLock::new(Arc::new(facts)),
                refresh,
                options,
                warned: std::sync::Mutex::new(Vec::new()),
                warned_gaps: std::sync::Mutex::new(Vec::new()),
                #[cfg(target_os = "macos")]
                refreshing: std::sync::Mutex::new(None),
                #[cfg(target_os = "macos")]
                refresh_started: std::sync::Mutex::new(None),
                #[cfg(all(test, target_os = "macos"))]
                seam: RefreshSeam::default(),
            }),
            deny: deny.into(),
            probe: Arc::new(TtlProbe),
        }
    }

    /// This policy with `probe` in place of the real near-hop probe: a test, where a server on
    /// loopback stands in for a public address, says what the probe would have found. Test builds
    /// only (the `test-util` feature, which only `[dev-dependencies]` enable).
    #[cfg(any(test, feature = "test-util"))]
    pub fn with_near_probe(mut self, probe: Arc<dyn NearProbe>) -> Self {
        self.probe = probe;
        self
    }

    pub fn mode(&self) -> NetMode {
        self.mode
    }

    /// The operator's extra deny CIDRs.
    pub fn deny(&self) -> &[Prefix] {
        &self.deny
    }

    /// The host facts in force (re-read first if stale).
    pub fn facts(&self) -> Arc<HostFacts> {
        self.facts.get()
    }

    /// The options the facts are gathered with.
    pub fn options(&self) -> FactsOptions {
        self.facts.options.clone()
    }

    /// The hop limit of the near-hop probe (`[egress] near_hop_limit`).
    pub fn near_hop_limit(&self) -> u8 {
        self.facts.options.near_hop_limit
    }

    /// [`admit`] under this policy. A refusal that rests on the host's facts is judged again on
    /// facts read now (unless they are younger than [`FORCED_REFRESH_MIN_AGE`]).
    pub fn admit(&self, ip: IpAddr) -> Result<(), Denied> {
        if self.mode == NetMode::DevPrivate {
            return Ok(());
        }
        match admit(self.mode, ip, &self.facts(), &self.deny) {
            Err(d) if d.depends_on_facts() && self.facts.refresh => {
                let fresh = self.facts.get_fresher_than(FORCED_REFRESH_MIN_AGE);
                admit(self.mode, ip, &fresh, &self.deny)
            }
            r => r,
        }
    }

    /// [`admit_to`] under this policy (a refusal that rests on the facts is judged again on facts
    /// read now, as [`Self::admit`] does).
    pub fn admit_to(&self, addr: SocketAddr) -> Result<(), Denied> {
        if self.mode == NetMode::DevPrivate {
            return Ok(());
        }
        match admit_to(self.mode, addr, &self.facts(), &self.deny) {
            Err(d) if d.depends_on_facts() && self.facts.refresh => {
                let fresh = self.facts.get_fresher_than(FORCED_REFRESH_MIN_AGE);
                admit_to(self.mode, addr, &fresh, &self.deny)
            }
            r => r,
        }
    }

    /// The last check before a connection to `addr` is made, right before it (public mode;
    /// developer mode admits everything): [`Self::admit_to`], then the near-hop probe
    /// ([`crate::nearhop::decide`]): refused when the destination answers within `[egress]
    /// near_hop_limit` hops — to the probe, or, when the probe had no answer, to a check
    /// connection's hop-limited FIN — or the probe fails. Blocking (up to the probe's timeout, plus
    /// a check connection when it had no answer): call it off an async runtime's worker threads.
    pub fn vet_connection(&self, addr: SocketAddr) -> Result<(), Denied> {
        if self.mode == NetMode::DevPrivate {
            return Ok(());
        }
        self.admit_to(addr)?;
        // An IPv4-mapped address is connected to as its IPv4 address: probe that.
        let target = match addr.ip() {
            IpAddr::V6(v6) => v6
                .to_ipv4_mapped()
                .map_or(addr, |v4| SocketAddr::new(IpAddr::V4(v4), addr.port())),
            IpAddr::V4(_) => addr,
        };
        let hops = self.near_hop_limit();
        match crate::nearhop::decide(&*self.probe, target, hops) {
            Verdict::Far => Ok(()),
            Verdict::Near(how) => Err(Denied::NearHop {
                addr,
                hops,
                what: format!("it {how}"),
            }),
            Verdict::Failed(why) => Err(Denied::NearHop {
                addr,
                hops,
                what: format!("the probe failed: {why}"),
            }),
            Verdict::Undecided => Err(Denied::NearHop {
                addr,
                hops,
                what: "no answer either way".into(),
            }),
        }
    }

    /// [`crate::check_url`] under this policy.
    pub fn check_url(&self, raw: &str) -> Result<url::Url, Denied> {
        crate::url::check_url(self, raw)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn pfx(s: &str) -> Prefix {
        s.parse().unwrap()
    }

    fn facts() -> HostFacts {
        HostFacts::new(
            vec![
                pfx("127.0.0.0/8"),
                pfx("192.168.1.0/24"),
                pfx("9.9.9.0/24"),          // a public subnet the host sits on
                pfx("2606:4700:aaaa::/64"), // the host's global /64 (on-link neighbours)
                pfx("fe80::/64"),
            ],
            vec![
                ip("127.0.0.1"),
                ip("192.168.1.10"),
                ip("9.9.9.10"),
                ip("2606:4700:aaaa::10"),
                ip("203.0.113.9"), // not global, but its own address all the same
                ip("2a01:4f8:1::77"), // a global address with a host route only
            ],
        )
    }

    #[test]
    fn public_mode_admits_only_public_strangers() {
        let f = facts();
        let deny = [pfx("8.8.4.4/32"), pfx("2a02:1234::/32")];
        let a = |s: &str| admit(NetMode::Public, ip(s), &f, &deny);
        for s in [
            "1.1.1.1",
            "2606:4700:4700::1111",
            "64:ff9b::101:101",
            "::ffff:1.1.1.1",
            "9.9.10.1",
        ] {
            assert_eq!(a(s), Ok(()), "{s}");
        }
        assert_eq!(a("127.0.0.1"), Err(Denied::NotGlobal(ip("127.0.0.1"))));
        assert_eq!(a("10.0.0.1"), Err(Denied::NotGlobal(ip("10.0.0.1"))));
        assert_eq!(
            a("169.254.169.254"),
            Err(Denied::NotGlobal(ip("169.254.169.254")))
        );
        assert_eq!(
            a("::ffff:192.168.1.1"),
            Err(Denied::NotGlobal(ip("::ffff:192.168.1.1")))
        );
        assert_eq!(
            a("fd00:ec2::254"),
            Err(Denied::NotGlobal(ip("fd00:ec2::254")))
        );
        // Hairpin: the host's own global addresses, in any spelling.
        assert_eq!(
            a("2a01:4f8:1::77"),
            Err(Denied::OwnAddress(ip("2a01:4f8:1::77")))
        );
        assert_eq!(a("9.9.9.10"), Err(Denied::OwnAddress(ip("9.9.9.10"))));
        assert_eq!(
            a("64:ff9b::909:90a"),
            Err(Denied::OwnAddress(ip("64:ff9b::909:90a")))
        );
        assert_eq!(
            a("::ffff:9.9.9.10"),
            Err(Denied::OwnAddress(ip("::ffff:9.9.9.10")))
        );
        // On-link neighbours with global addresses.
        assert_eq!(
            a("9.9.9.11"),
            Err(Denied::ConnectedPrefix {
                ip: ip("9.9.9.11"),
                prefix: pfx("9.9.9.0/24")
            })
        );
        assert_eq!(
            a("2606:4700:aaaa::1"),
            Err(Denied::ConnectedPrefix {
                ip: ip("2606:4700:aaaa::1"),
                prefix: pfx("2606:4700:aaaa::/64")
            })
        );
        assert_eq!(
            a("64:ff9b::909:901"),
            Err(Denied::ConnectedPrefix {
                ip: ip("64:ff9b::909:901"),
                prefix: pfx("9.9.9.0/24")
            })
        );
        // The operator's deny CIDRs (a NAT'd public address).
        assert_eq!(
            a("8.8.4.4"),
            Err(Denied::DenyCidr {
                ip: ip("8.8.4.4"),
                prefix: pfx("8.8.4.4/32")
            })
        );
        assert_eq!(
            a("::ffff:0:808:404"),
            Err(Denied::DenyCidr {
                ip: ip("::ffff:0:808:404"),
                prefix: pfx("8.8.4.4/32")
            })
        );
        assert_eq!(
            a("2a02:1234::5"),
            Err(Denied::DenyCidr {
                ip: ip("2a02:1234::5"),
                prefix: pfx("2a02:1234::/32")
            })
        );
    }

    /// Review r1 broker F6 (PoC t6): a deny CIDR written in an embedded-IPv4 form (NAT64, SIIT,
    /// IPv4-compatible) denied the prefix at load (`admit_prefix`) but not the address at connect
    /// time (`admit`), which compared only the IPv4-mapped spelling. Both refuse it now, in every
    /// spelling of the address.
    /// Review r2 R2-NG-5 (PoC `contains_overlaps_admit_prefix_consistency`), inverted: a deny CIDR
    /// shorter than /96 that holds an embedded-IPv4 /96 (`64:ff9b::/64`) refuses the addresses it
    /// holds as written; the prefix check agrees.
    #[test]
    fn a_deny_cidr_holds_what_it_holds_as_written() {
        let f = HostFacts::empty();
        let d = [pfx("64:ff9b::/64")];
        assert_eq!(
            admit(NetMode::Public, ip("64:ff9b::808:808"), &f, &d),
            Err(Denied::DenyCidr {
                ip: ip("64:ff9b::808:808"),
                prefix: pfx("64:ff9b::/64")
            })
        );
        assert!(matches!(
            admit_prefix(NetMode::Public, pfx("64:ff9b::808:800/120"), &f, &d),
            Err(Denied::PrefixOverlapsDeny { .. })
        ));
        // The same in the host's own prefixes and addresses, and the DNS servers.
        let f = HostFacts::new(vec![pfx("64:ff9b::/64")], vec![ip("64:ff9b::101:101")]);
        assert!(matches!(
            admit(NetMode::Public, ip("64:ff9b::909:909"), &f, &[]),
            Err(Denied::ConnectedPrefix { .. })
        ));
        assert!(matches!(
            admit(NetMode::Public, ip("1.1.1.1"), &f, &[]),
            Err(Denied::OwnAddress(_))
        ));
        assert!(matches!(
            admit_prefix(NetMode::Public, pfx("64:ff9b::909:900/120"), &f, &[]),
            Err(Denied::PrefixOverlapsConnected { .. })
        ));
        // Elsewhere, still admitted.
        assert_eq!(
            admit(NetMode::Public, ip("8.8.8.8"), &HostFacts::empty(), &d),
            Ok(())
        );
    }

    #[test]
    fn deny_cidrs_in_any_embedded_form_deny_at_connect_time() {
        let f = HostFacts::empty();
        for deny in [
            "64:ff9b::808:808/128",
            "::ffff:0:808:808/128",
            "::808:808/128",
            "::ffff:8.8.8.8/128",
            "64:ff9b::808:800/120",
        ] {
            let d = [pfx(deny)];
            for a in [
                "8.8.8.8",
                "::ffff:8.8.8.8",
                "::ffff:0:808:808",
                "64:ff9b::808:808",
            ] {
                assert!(
                    matches!(
                        admit(NetMode::Public, ip(a), &f, &d),
                        Err(Denied::DenyCidr { .. })
                    ),
                    "deny {deny}: {a}"
                );
            }
            assert!(matches!(
                admit_prefix(NetMode::Public, pfx("8.8.8.8/32"), &f, &d),
                Err(Denied::PrefixOverlapsDeny { .. })
            ));
            assert_eq!(admit(NetMode::Public, ip("1.1.1.1"), &f, &d), Ok(()));
        }
        // A connected prefix or an own address in NAT64 form is the IPv4 one, too.
        let f = HostFacts::new(vec![pfx("64:ff9b::909:900/120")], vec![]);
        assert!(matches!(
            admit(NetMode::Public, ip("9.9.9.20"), &f, &[]),
            Err(Denied::ConnectedPrefix { .. })
        ));
    }

    /// No discovery: the host's public addresses as the operator states them.
    fn offline() -> FactsOptions {
        FactsOptions {
            discover_public_addresses: false,
            public_addresses: vec![ip("198.51.99.7"), ip("2a02:db8:99::7")],
            ..FactsOptions::default()
        }
    }

    /// Review r1 (fetch F1 / broker F1 / PoC t3), with an injected routing table: a DHCPv6 host
    /// (/128 address, on-link /64 route), a VPN's pushed route, a Docker bridge and DHCP host
    /// routes via the home router.
    #[test]
    fn routes_sites_and_resolvers_are_refused() {
        use crate::facts::RawFacts;
        use crate::routes::Route;
        let raw = RawFacts {
            interface_prefixes: vec![
                pfx("2606:4700:1::5/128"),
                pfx("192.168.1.0/24"),
                pfx("172.17.0.0/16"),
            ],
            interface_addresses: vec![ip("2606:4700:1::5"), ip("192.168.1.33"), ip("172.17.0.1")],
            routes: vec![
                Route::on_link(pfx("2606:4700:1::/64"), 2),
                Route::via(pfx("::/0"), ip("fe80::1"), 2),
                Route::via(pfx("0.0.0.0/0"), ip("192.168.1.1"), 2),
                Route::via(pfx("1.1.1.1/32"), ip("192.168.1.1"), 2),
                Route::via(pfx("172.233.157.223/32"), ip("192.168.1.1"), 2),
                Route::on_link(pfx("172.17.0.0/16"), 3),
                Route::on_link(pfx("10.8.0.0/24"), 7),
                Route::via(pfx("45.60.1.0/24"), ip("10.8.0.1"), 7),
                Route::on_link(pfx("185.199.108.0/24"), 9), // WireGuard AllowedIPs, public
            ],
            resolvers: vec![ip("127.0.0.53"), ip("2606:a300:c::7d"), ip("9.9.9.9")],
            public_addresses: vec![ip("168.1.2.57")],
            ..RawFacts::default()
        };
        let f = HostFacts::assemble(raw, &offline());
        let a = |s: &str| admit(NetMode::Public, ip(s), &f, &[]);
        // The DHCPv6 neighbour in the on-link /64 (the PoC's connect went through).
        assert!(matches!(
            a("2606:4700:1::6"),
            Err(Denied::ConnectedPrefix { .. })
        ));
        // Elsewhere in the delegated /56: the site.
        assert!(matches!(
            a("2606:4700:1:5::1"),
            Err(Denied::SitePrefix { .. })
        ));
        assert_eq!(a("2606:4701::1"), Ok(()));
        // The NAT public address (learned) is the host's own.
        assert!(matches!(a("168.1.2.57"), Err(Denied::OwnAddress(_))));
        // The upstream DNS servers behind the stub.
        assert!(matches!(a("2606:a300:c::7d"), Err(Denied::DnsServer(_))));
        assert!(matches!(a("9.9.9.9"), Err(Denied::DnsServer(_))));
        assert!(matches!(a("::ffff:9.9.9.9"), Err(Denied::DnsServer(_))));
        // A VPN's pushed public range, and a public WireGuard network.
        assert_eq!(
            a("45.60.1.20"),
            Err(Denied::OffDefaultRoute {
                ip: ip("45.60.1.20"),
                route: pfx("45.60.1.0/24"),
                kind: RouteKind::OtherGateway
            })
        );
        assert!(matches!(
            a("185.199.108.5"),
            Err(Denied::ConnectedPrefix { .. })
        ));
        assert!(matches!(
            a("64:ff9b::2d3c:114"),
            Err(Denied::OffDefaultRoute { .. })
        ));
        // DHCP host routes via the default router are the default path.
        assert_eq!(a("172.233.157.223"), Ok(()));
        assert_eq!(a("8.8.8.8"), Ok(()));
        // Whole prefixes too.
        let ap = |s: &str| admit_prefix(NetMode::Public, pfx(s), &f, &[]);
        assert!(matches!(
            ap("2606:4700:1:0:8000::/65"),
            Err(Denied::PrefixOverlapsConnected { .. })
        ));
        assert!(matches!(
            ap("2606:4700:1:8::/64"),
            Err(Denied::PrefixOverlapsSite { .. })
        ));
        assert!(matches!(
            ap("9.9.9.0/24"),
            Err(Denied::PrefixHoldsDnsServer { .. })
        ));
        assert!(matches!(
            ap("45.60.1.128/25"),
            Err(Denied::PrefixOverlapsRoute { .. })
        ));
        assert!(matches!(
            ap("168.1.2.0/24"),
            Err(Denied::PrefixHoldsOwnAddress { .. })
        ));
        assert_eq!(ap("8.8.8.0/24"), Ok(()));
        for d in [
            Denied::SitePrefix {
                ip: ip("2606:4700:1:5::1"),
                prefix: pfx("2606:4700:1::/56"),
            },
            Denied::DnsServer(ip("9.9.9.9")),
            Denied::OffDefaultRoute {
                ip: ip("45.60.1.20"),
                route: pfx("45.60.1.0/24"),
                kind: RouteKind::OnLink,
            },
        ] {
            assert!(d.depends_on_facts());
            assert!(d.to_string().starts_with("refused by the network guard: "));
        }
        assert!(!Denied::NotGlobal(ip("10.0.0.1")).depends_on_facts());
        assert!(!Denied::DenyCidr {
            ip: ip("8.8.8.8"),
            prefix: pfx("8.8.8.8/32")
        }
        .depends_on_facts());
    }

    /// Review r2 R2-NG-3 (PoC `destination_policy_rule_into_a_vpn_table_is_admitted`), inverted:
    /// with `ip rule add to 52.95.0.0/16 lookup 100` and a default in table 100 (through a VPN
    /// gateway, or a gateway-less WireGuard one), the address and the prefix are refused.
    #[test]
    fn a_destination_rule_into_a_vpn_table_is_refused() {
        use crate::facts::RawFacts;
        use crate::routes::{Route, Rule};
        for vpn in [
            Route::via(pfx("0.0.0.0/0"), ip("10.8.0.1"), 7).in_table(100),
            Route::on_link(pfx("0.0.0.0/0"), 9).in_table(100),
        ] {
            let mut rules = Rule::stock(false);
            rules.insert(0, Rule::to(pfx("52.95.0.0/16"), 100));
            let f = HostFacts::assemble(
                RawFacts {
                    interface_prefixes: vec![pfx("192.168.1.0/24"), pfx("10.8.0.0/24")],
                    interface_addresses: vec![ip("192.168.1.33"), ip("10.8.0.6")],
                    routes: vec![
                        Route::via(pfx("0.0.0.0/0"), ip("192.168.1.1"), 2),
                        Route::on_link(pfx("192.168.1.0/24"), 2),
                        Route::on_link(pfx("10.8.0.0/24"), 7),
                        vpn,
                    ],
                    rules,
                    ..RawFacts::default()
                },
                &offline(),
            );
            let e = admit(NetMode::Public, ip("52.95.1.1"), &f, &[]).unwrap_err();
            assert_eq!(
                e,
                Denied::OffDefaultRoute {
                    ip: ip("52.95.1.1"),
                    route: pfx("52.95.0.0/16"),
                    kind: RouteKind::PolicyRule
                }
            );
            assert!(e.to_string().contains("policy-routing rule"), "{e}");
            assert!(e.depends_on_facts());
            assert!(matches!(
                admit(NetMode::Public, ip("64:ff9b::345f:101"), &f, &[]),
                Err(Denied::OffDefaultRoute { .. })
            ));
            assert!(matches!(
                admit_prefix(NetMode::Public, pfx("52.95.0.0/16"), &f, &[]),
                Err(Denied::PrefixOverlapsRoute { .. })
            ));
            assert!(f.refused_prefixes().contains(&pfx("52.95.0.0/16")));
            assert_eq!(admit(NetMode::Public, ip("8.8.8.8"), &f, &[]), Ok(()));
        }
    }

    /// Staged kernel answers, counted.
    #[derive(Debug, Default)]
    struct Staged {
        answers: std::collections::HashMap<IpAddr, Option<Vec<crate::routes::Route>>>,
        asked: std::sync::Mutex<Vec<IpAddr>>,
    }

    impl crate::routes::RouteOracle for Staged {
        fn route_to(&self, dst: IpAddr, _: Option<u16>) -> io::Result<crate::routes::KernelAnswer> {
            self.asked.lock().unwrap().push(dst);
            self.answers
                .get(&dst)
                .cloned()
                .map(crate::routes::KernelAnswer::from)
                .ok_or_else(|| io::Error::other("no staged answer"))
        }
    }

    /// Review r2 R2-NG-3, the per-connection side: the kernel, asked per destination, applies the
    /// rules the prefix model cannot see (here the rule is not in the dump at all), and its
    /// answer is judged: only a unicast route through an uplink, or a default-like route of an
    /// ordinary table, is admitted. Asked once per destination and facts snapshot.
    #[test]
    fn the_kernels_answer_per_destination_is_judged() {
        use crate::facts::RawFacts;
        use crate::routes::{Route, RouteType, Rule};
        let main_default = Route::via(pfx("0.0.0.0/0"), ip("192.168.1.1"), 2);
        let mut rules = Rule::stock(false);
        rules.insert(
            0,
            Rule {
                invert: true,
                matches: crate::routes::RuleMatch::Never, // not fwmark 0xca6c
                ..Rule::lookup(false, 51820)
            },
        );
        let raw = RawFacts {
            interface_prefixes: vec![pfx("192.168.1.0/24"), pfx("10.8.0.0/24")],
            interface_addresses: vec![ip("192.168.1.33"), ip("10.8.0.6")],
            routes: vec![
                main_default,
                Route::on_link(pfx("192.168.1.0/24"), 2),
                Route::on_link(pfx("10.8.0.0/24"), 7),
                Route::via(pfx("0.0.0.0/0"), ip("10.8.0.1"), 7).in_table(100),
            ],
            rules,
            ..RawFacts::default()
        };
        let mut staged = Staged::default();
        let mut stage = |a: &str, answer: Option<Vec<Route>>| {
            staged.answers.insert(ip(a), answer);
        };
        stage("8.8.8.8", Some(vec![main_default]));
        // `to 52.95.0.0/16 lookup 100`, added after the dump: the kernel answers table 100.
        stage(
            "52.95.1.1",
            Some(vec![
                Route::via(pfx("0.0.0.0/0"), ip("10.8.0.1"), 7).in_table(100)
            ]),
        );
        // An AnyIP range the dump missed.
        stage(
            "185.199.108.10",
            Some(vec![Route::local(pfx("185.199.108.0/24"), 1).in_table(255)]),
        );
        // ECMP: one path through the uplink, one through the VPN.
        stage(
            "9.9.1.1",
            Some(vec![
                Route::via(pfx("9.9.0.0/16"), ip("192.168.1.1"), 2),
                Route::via(pfx("9.9.0.0/16"), ip("10.8.0.1"), 7),
            ]),
        );
        // OpenVPN def1 in main: a split default.
        stage(
            "93.184.216.34",
            Some(vec![Route::via(pfx("0.0.0.0/1"), ip("10.8.0.1"), 7)]),
        );
        // wg-quick's table, which `not fwmark` makes ordinary.
        stage(
            "1.0.0.1",
            Some(vec![Route::on_link(pfx("0.0.0.0/0"), 9).in_table(51820)]),
        );
        // A DHCP option 121 host route via the router; an on-link one.
        stage(
            "172.233.157.223",
            Some(vec![Route::via(
                pfx("172.233.157.223/32"),
                ip("192.168.1.1"),
                2,
            )]),
        );
        stage(
            "45.60.1.20",
            Some(vec![Route::on_link(pfx("45.60.1.0/24"), 8)]),
        );
        // No route; an unknown nexthop.
        stage("203.0.114.9", None);
        stage(
            "198.18.0.0",
            Some(vec![Route {
                hop: crate::routes::Hop::Unknown,
                ..Route::on_link(pfx("100.0.0.0/8"), 2)
            }]),
        );
        let staged = Arc::new(staged);
        let f = HostFacts::assemble(raw, &offline()).with_route_oracle(staged.clone());
        let a = |s: &str| admit(NetMode::Public, ip(s), &f, &[]);
        assert_eq!(a("8.8.8.8"), Ok(()));
        assert_eq!(
            a("52.95.1.1"),
            Err(Denied::OffDefaultRoute {
                ip: ip("52.95.1.1"),
                route: pfx("0.0.0.0/0"),
                kind: RouteKind::PolicyRule
            })
        );
        assert_eq!(
            a("185.199.108.10"),
            Err(Denied::OffDefaultRoute {
                ip: ip("185.199.108.10"),
                route: pfx("185.199.108.0/24"),
                kind: RouteKind::Local
            })
        );
        assert_eq!(
            a("9.9.1.1"),
            Err(Denied::OffDefaultRoute {
                ip: ip("9.9.1.1"),
                route: pfx("9.9.0.0/16"),
                kind: RouteKind::OtherGateway
            })
        );
        #[cfg(not(target_os = "macos"))]
        assert_eq!(a("93.184.216.34"), Ok(()));
        #[cfg(not(target_os = "macos"))]
        assert_eq!(a("1.0.0.1"), Ok(()));
        // macOS (review round 3, bypass-3): a default-like answer must be one of these facts'
        // default routes; the split default via the VPN and wg-quick's table on interface 9 are
        // not (`a_new_uplink_is_refused_until_the_facts_hold_it`).
        #[cfg(target_os = "macos")]
        for (dst, kind) in [
            ("93.184.216.34", RouteKind::OtherGateway),
            ("1.0.0.1", RouteKind::OnLink),
        ] {
            let e = a(dst).unwrap_err();
            assert!(
                matches!(e, Denied::OffDefaultRoute { kind: k, .. } if k == kind),
                "{dst}: {e:?}"
            );
            assert!(e.depends_on_facts());
        }
        assert_eq!(a("172.233.157.223"), Ok(()));
        assert!(matches!(
            a("45.60.1.20"),
            Err(Denied::OffDefaultRoute {
                kind: RouteKind::OnLink,
                ..
            })
        ));
        let e = a("203.0.114.9").unwrap_err();
        assert_eq!(
            e,
            Denied::OffDefaultRoute {
                ip: ip("203.0.114.9"),
                route: pfx("203.0.114.9/32"),
                kind: RouteKind::NoRoute
            }
        );
        assert!(e.to_string().contains("no route"), "{e}");
        assert!(matches!(
            a("198.18.0.0"),
            Err(Denied::NotGlobal(_)) // judged before the kernel is asked
        ));
        // A query that fails refuses, and says so.
        let e = a("4.4.4.4").unwrap_err();
        assert!(matches!(e, Denied::RouteQueryFailed { .. }), "{e:?}");
        assert!(e.depends_on_facts());
        assert!(e.to_string().contains("could not ask the kernel"), "{e}");
        // An IPv4-mapped address is asked as its IPv4 address; each destination once.
        assert_eq!(a("::ffff:8.8.8.8"), Ok(()));
        assert_eq!(a("8.8.8.8"), Ok(()));
        let asked = staged.asked.lock().unwrap().clone();
        assert_eq!(
            asked.iter().filter(|d| **d == ip("8.8.8.8")).count(),
            1,
            "{asked:?}"
        );
        assert!(!asked.contains(&ip("::ffff:8.8.8.8")));
        assert!(!asked.contains(&ip("198.18.0.0")), "refused before asking");
        // Developer mode asks nothing.
        assert_eq!(admit(NetMode::DevPrivate, ip("52.95.1.1"), &f, &[]), Ok(()));
        let _ = RouteType::Local;
    }

    /// macOS, review round 3, bypass-3 (the reviewer's `r3_a_new_uplink_passes_the_kernel_check_
    /// of_old_facts`): the kernel's default-like answer is admitted only when these facts hold
    /// that default route (its family, hop and interface). A full-tunnel VPN that came up after
    /// the facts were read (`0/1` on a `utun`, or its own default via its peer) and a second
    /// network's default are refused as off the default path, a refusal that rests on the facts
    /// (the policy reads them again and judges once more); the facts' own default, a clone through
    /// their uplink, and the same VPN once the facts hold it are admitted.
    #[cfg(target_os = "macos")]
    #[test]
    fn a_new_uplink_is_refused_until_the_facts_hold_it() {
        use crate::facts::RawFacts;
        use crate::routes::Route;
        let raw = |extra: Vec<Route>| RawFacts {
            interface_prefixes: vec![pfx("192.168.1.0/24")],
            interface_addresses: vec![ip("192.168.1.33")],
            routes: [
                vec![
                    Route::via(pfx("0.0.0.0/0"), ip("192.168.1.1"), 14),
                    Route::on_link(pfx("192.168.1.0/24"), 14),
                ],
                extra,
            ]
            .concat(),
            ..RawFacts::default()
        };
        let mut staged = Staged::default();
        let answers = [
            (
                "8.8.8.8",
                Route::via(pfx("0.0.0.0/0"), ip("192.168.1.1"), 14),
            ),
            (
                "1.1.1.1",
                Route::via(pfx("1.1.1.1/32"), ip("192.168.1.1"), 14),
            ),
            ("9.9.9.9", Route::on_link(pfx("0.0.0.0/1"), 20)),
            ("4.2.2.2", Route::via(pfx("0.0.0.0/0"), ip("10.8.0.1"), 20)),
            (
                "4.2.2.3",
                Route::via(pfx("0.0.0.0/0"), ip("192.168.50.1"), 15),
            ),
            // The facts' gateway, out of another interface; another gateway on the facts'
            // interface.
            (
                "4.2.2.4",
                Route::via(pfx("0.0.0.0/0"), ip("192.168.1.1"), 15),
            ),
            (
                "4.2.2.5",
                Route::via(pfx("0.0.0.0/0"), ip("192.168.1.254"), 14),
            ),
            // A link route of the other family on the VPN's interface.
            ("2606:4700::6810:84e5", Route::on_link(pfx("::/1"), 20)),
        ];
        for (d, r) in &answers {
            staged.answers.insert(ip(d), Some(vec![*r]));
        }
        let staged = Arc::new(staged);
        let old =
            HostFacts::assemble(raw(Vec::new()), &offline()).with_route_oracle(staged.clone());
        let a = |f: &HostFacts, s: &str| admit(NetMode::Public, ip(s), f, &[]);
        assert_eq!(a(&old, "8.8.8.8"), Ok(()));
        assert_eq!(a(&old, "1.1.1.1"), Ok(()));
        for (d, kind) in [
            ("9.9.9.9", RouteKind::OnLink),
            ("4.2.2.2", RouteKind::OtherGateway),
            ("4.2.2.3", RouteKind::OtherGateway),
            ("4.2.2.4", RouteKind::OtherGateway),
            ("4.2.2.5", RouteKind::OtherGateway),
        ] {
            let e = a(&old, d).unwrap_err();
            assert!(
                matches!(e, Denied::OffDefaultRoute { kind: k, .. } if k == kind),
                "{d}: {e:?}"
            );
            assert!(e.depends_on_facts(), "{d}");
        }
        // Once the facts hold the VPN's routes (read after it came up), its answers are admitted.
        let new = HostFacts::assemble(
            raw(vec![
                Route::on_link(pfx("0.0.0.0/1"), 20),
                Route::via(pfx("0.0.0.0/0"), ip("10.8.0.1"), 20),
            ]),
            &FactsOptions {
                internal_ranges: Some(Vec::new()),
                ..offline()
            },
        )
        .with_route_oracle(staged);
        assert_eq!(a(&new, "9.9.9.9"), Ok(()));
        assert_eq!(a(&new, "4.2.2.2"), Ok(()));
        assert!(a(&new, "4.2.2.3").is_err());
        // The VPN's `0/1` is IPv4's: an IPv6 `::/1` on the same interface is not held.
        assert!(matches!(
            a(&new, "2606:4700::6810:84e5"),
            Err(Denied::OffDefaultRoute {
                kind: RouteKind::OnLink,
                ..
            })
        ));
    }

    /// macOS, review round 3, bypass-1 (the reviewer's `r3_an_unlearned_nsp_carries_private_
    /// ipv4_as_global`): on a host with IPv6 and no IPv4 route, `<NSP>::<private IPv4>` under a
    /// network-specific NAT64 prefix not learned yet is an ordinary global IPv6 address. While the
    /// new uplink's discovery round has not finished, every IPv6 destination is refused, and the
    /// refusal rests on the facts; once the prefix is learned, what it carries is judged.
    #[cfg(target_os = "macos")]
    #[test]
    fn ipv6_is_refused_while_a_new_uplinks_nat64_prefix_is_learned() {
        use crate::facts::RawFacts;
        use crate::routes::Route;
        let nsp = pfx("2a0b:7e40:64::/96");
        let under =
            |v4: [u8; 4]| IpAddr::V6(crate::nat64::synthesize(nsp, std::net::Ipv4Addr::from(v4)));
        let facts = |unsettled: bool| {
            HostFacts::assemble(
                RawFacts {
                    interface_prefixes: vec![pfx("2a02:db8:99::/64")],
                    interface_addresses: vec![ip("2a02:db8:99::7")],
                    routes: vec![Route::via(pfx("::/0"), ip("fe80::1"), 4)],
                    nat64_unsettled: unsettled,
                    ..RawFacts::default()
                },
                &FactsOptions {
                    public_addresses: vec![ip("2a02:db8:99::7")],
                    ..offline()
                },
            )
        };
        let targets = [
            [10, 0, 0, 1],
            [192, 168, 1, 1],
            [169, 254, 169, 254],
            [127, 0, 0, 1],
        ];
        let pending = facts(true);
        for v4 in targets {
            let e = admit(NetMode::Public, under(v4), &pending, &[]).unwrap_err();
            assert_eq!(e, Denied::Nat64Unsettled(under(v4)));
            assert!(e.depends_on_facts());
            assert!(
                e.to_string()
                    .contains("NAT64 prefix is still being learned"),
                "{e}"
            );
        }
        let e = admit(NetMode::Public, ip("2606:4700:4700::1111"), &pending, &[]).unwrap_err();
        assert!(matches!(e, Denied::Nat64Unsettled(_)), "{e:?}");
        // Settled, and the prefix learned: refused as the IPv4 address it carries.
        crate::nat64::add_learned(&[nsp]);
        let settled = facts(false);
        for v4 in targets {
            let d = admit(NetMode::Public, under(v4), &settled, &[]);
            assert_eq!(d, Err(Denied::NotGlobal(under(v4))));
        }
        assert_eq!(
            admit(NetMode::Public, ip("2606:4700:4700::1111"), &settled, &[]),
            Ok(())
        );
    }

    /// Review r1 fetch F1 (PoC `facts`), inverted, on this host's real facts: neighbours in the
    /// /56 around the host's global IPv6 addresses, the DNS servers it uses (systemd-resolved's
    /// upstream ones included), and the public addresses the reflectors report are all refused.
    #[test]
    fn this_hosts_site_resolvers_and_public_addresses_are_refused() {
        let p = NetPolicy::new(NetMode::Public, Vec::new()).expect("read the host");
        let f = p.facts();
        // A site comes from an interface address or a public address both reflectors confirmed.
        let confirmed = crate::public::learned().confirmed;
        for own in f.own_addresses() {
            assert!(p.admit(*own).is_err(), "{own}");
            let on_interface = f
                .connected()
                .iter()
                .any(|c| c.contains(*own) && c.len < 128);
            if let IpAddr::V6(v6) = own {
                if is_global(*own) && (on_interface || confirmed.contains(own)) {
                    // Another /64 of the same /56.
                    let other = IpAddr::V6(std::net::Ipv6Addr::from(
                        (u128::from(*v6) ^ (0x7f << 64)) | 1,
                    ));
                    assert!(p.admit(other).is_err(), "{other} is in {own}'s /56");
                }
            }
        }
        for r in crate::system_resolvers() {
            assert!(p.admit(r).is_err(), "DNS server {r}");
        }
        for a in crate::public::public_addresses() {
            assert!(f.own_addresses().contains(&a), "{a}");
            assert!(p.admit(a).is_err(), "public address {a}");
        }
        assert_eq!(
            p.admit(ip("1.0.0.1")).is_ok(),
            !f.resolvers().contains(&ip("1.0.0.1")),
            "{:?}",
            p.admit(ip("1.0.0.1"))
        );
    }

    /// Review r1 (fetch F1d): facts are re-read once a second, and before a refusal that rests on
    /// them.
    #[test]
    fn gathered_facts_are_re_read() {
        let p = NetPolicy::with_options(NetMode::Public, Vec::new(), offline()).unwrap();
        assert_eq!(FACTS_TTL, Duration::from_secs(1));
        let first = p.facts().gathered_at();
        std::thread::sleep(FORCED_REFRESH_MIN_AGE + Duration::from_millis(50));
        // A refusal on the facts (loopback is an own address, but is_global refuses it first; use
        // an own global address if there is one, else a connected-prefix neighbour).
        let own = p
            .facts()
            .own_addresses()
            .iter()
            .copied()
            .find(|a| is_global(*a));
        if let Some(own) = own {
            assert!(p.admit(own).is_err());
            assert!(
                p.facts().gathered_at() > first,
                "the refusal re-read the facts"
            );
        }
        std::thread::sleep(FACTS_TTL);
        assert!(p.facts().gathered_at() > first);
        // Fixed facts are never re-read; bad options are refused.
        let fixed = NetPolicy::with_facts(NetMode::Public, facts(), Vec::new());
        let t = fixed.facts().gathered_at();
        std::thread::sleep(Duration::from_millis(5));
        assert_eq!(fixed.facts().gathered_at(), t);
        let bad = FactsOptions {
            ipv6_site_prefix_len: 15,
            ..offline()
        };
        assert!(NetPolicy::with_options(NetMode::Public, Vec::new(), bad).is_err());
    }

    /// Review round 2, bypass-1 (macOS): a re-read of the facts that keeps failing (here a
    /// staged `/etc/resolver` error) refuses every requester connection once the facts are older
    /// than `FACTS_TTL` and `REFRESH_GRACE`, naming the failure; within that time the last good
    /// facts are judged with (without their cached kernel verdicts); and once a re-read succeeds
    /// again, connections are admitted again. Before this change the first facts stayed in force
    /// for as long as the failure lasted (`r2-bypass/frozen-facts.log`).
    #[cfg(target_os = "macos")]
    #[test]
    fn a_failing_refresh_refuses_after_its_grace_and_recovers() {
        use std::time::Instant;
        let p = NetPolicy::with_options(NetMode::Public, Vec::new(), offline()).unwrap();
        let public = ip("8.8.4.4");
        if let Err(e) = p.admit(public) {
            crate::skipped(format!("{public} is not admitted on this host: {e}"));
            return;
        }
        let start = p.facts().gathered_at();
        assert!(p.facts().cached_verdicts() > 0);
        let why =
            "the DNS resolver file /etc/resolver/corp.example: Permission denied (os error 13)";
        *p.facts.seam.fail.lock().unwrap() = Some(why.into());
        // Within the grace: judged with the last good facts.
        std::thread::sleep(FACTS_TTL + Duration::from_millis(200));
        let f = p.facts();
        assert_eq!(f.gathered_at(), start);
        assert!(f.unreadable().is_none());
        // The kernel's verdicts for the old facts were dropped: asked again.
        assert_eq!(f.cached_verdicts(), 0);
        assert_eq!(p.admit(public), Ok(()));
        // Past it: refused, naming the failure, and so is every other destination.
        while start.elapsed() < FACTS_TTL + REFRESH_GRACE + Duration::from_millis(50) {
            std::thread::sleep(Duration::from_millis(50));
        }
        let t = Instant::now();
        let d = p.admit(public).unwrap_err();
        assert!(t.elapsed() < Duration::from_secs(1));
        assert!(
            matches!(&d, Denied::FactsUnreadable { why: w, .. } if w.contains("corp.example")),
            "{d:?}"
        );
        assert!(d.to_string().contains("corp.example"), "{d}");
        assert!(d.depends_on_facts());
        for other in ["1.1.1.1", "2606:4700:4700::1111"] {
            assert!(
                matches!(p.admit(ip(other)), Err(Denied::FactsUnreadable { .. })),
                "{other}"
            );
        }
        assert!(matches!(
            p.admit_to("8.8.4.4:443".parse().unwrap()),
            Err(Denied::FactsUnreadable { .. })
        ));
        assert!(matches!(
            p.vet_connection("8.8.4.4:443".parse().unwrap()),
            Err(Denied::FactsUnreadable { .. })
        ));
        // A caller judging with the facts in force (the witness broker's floor) refuses too.
        assert!(matches!(
            admit(NetMode::Public, public, &p.facts(), &[]),
            Err(Denied::FactsUnreadable { .. })
        ));
        // And the operator's warnings can say why (review round 3, cross-6).
        assert!(p
            .facts()
            .unreadable_reason()
            .is_some_and(|w| w.contains("corp.example")));
        // The condition clears: the next call reads the facts again and admits.
        *p.facts.seam.fail.lock().unwrap() = None;
        std::thread::sleep(FORCED_REFRESH_MIN_AGE);
        assert_eq!(p.admit(public), Ok(()));
        assert!(p.facts().unreadable().is_none());
        assert!(p.facts().unreadable_reason().is_none());
        assert!(p.facts().gathered_at() > start);
    }

    /// Review round 2, cross-3 (macOS): stale facts are re-read once however many callers find
    /// them stale at the same time; the others wait for that re-read and take its facts.
    #[cfg(target_os = "macos")]
    #[test]
    fn stale_facts_are_re_read_once_for_every_caller() {
        use std::sync::atomic::Ordering;
        let p = NetPolicy::with_options(NetMode::Public, Vec::new(), offline()).unwrap();
        *p.facts.seam.delay.lock().unwrap() = Duration::from_millis(300);
        std::thread::sleep(FACTS_TTL + Duration::from_millis(50));
        let before = p.facts.seam.gathers.load(Ordering::SeqCst);
        let barrier = Arc::new(std::sync::Barrier::new(16));
        let threads: Vec<_> = (0..16)
            .map(|_| {
                let (p, b) = (p.clone(), barrier.clone());
                std::thread::spawn(move || {
                    b.wait();
                    p.facts().gathered_at()
                })
            })
            .collect();
        let got: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
        assert_eq!(p.facts.seam.gathers.load(Ordering::SeqCst) - before, 1);
        assert!(got.iter().all(|g| *g == got[0]));
    }

    /// Review round 3, 12(b): a re-read that takes longer than [`REFRESH_WAIT`] (a configuration
    /// daemon answering just after its 2 s, again and again) holds only the caller that runs it.
    /// The others wait for it at most [`REFRESH_WAIT`], then judge with the facts in force while
    /// they are within their grace, and are refused at once after it (round 2 held each of them
    /// for the whole re-read, every time).
    #[cfg(target_os = "macos")]
    #[test]
    fn a_slow_refresh_holds_only_the_caller_that_runs_it() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::time::Instant;
        let p = NetPolicy::with_options(NetMode::Public, Vec::new(), offline()).unwrap();
        let public = ip("8.8.4.4");
        if let Err(e) = p.admit(public) {
            crate::skipped(format!("{public} is not admitted on this host: {e}"));
            return;
        }
        // Longer than the grace, so callers come past it while the first re-read still runs.
        *p.facts.seam.delay.lock().unwrap() = Duration::from_millis(3500);
        *p.facts.seam.fail.lock().unwrap() = Some("staged: configd answered late".into());
        let before = p.facts.seam.gathers.load(Ordering::SeqCst);
        let start = Instant::now();
        static SLOW: AtomicUsize = AtomicUsize::new(0);
        static ADMITTED_LATE: AtomicUsize = AtomicUsize::new(0);
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let p = p.clone();
                std::thread::spawn(move || {
                    let mut calls = 0;
                    while start.elapsed() < Duration::from_secs(7) {
                        let t = Instant::now();
                        let f = p.facts();
                        let r = p.admit(public);
                        if t.elapsed() > REFRESH_WAIT + Duration::from_millis(400) {
                            SLOW.fetch_add(1, Ordering::SeqCst);
                        }
                        if r.is_ok()
                            && f.gathered_at().elapsed()
                                > FACTS_TTL + REFRESH_GRACE + Duration::from_millis(300)
                        {
                            ADMITTED_LATE.fetch_add(1, Ordering::SeqCst);
                        }
                        calls += 1;
                        std::thread::sleep(Duration::from_millis(20));
                    }
                    calls
                })
            })
            .collect();
        let calls: usize = threads.into_iter().map(|t| t.join().unwrap()).sum();
        let gathers = p.facts.seam.gathers.load(Ordering::SeqCst) - before;
        let slow = SLOW.load(Ordering::SeqCst);
        eprintln!("{calls} calls, {gathers} re-reads, {slow} calls slower than the wait");
        // Each re-read holds the caller that runs it (and admit's forced re-read can be a
        // second); every other caller is answered within the wait.
        assert!(
            slow <= 2 * gathers,
            "{slow} slow calls for {gathers} re-reads"
        );
        assert!(calls > 100, "{calls}");
        assert_eq!(ADMITTED_LATE.load(Ordering::SeqCst), 0);
        // And past the grace, refused.
        assert!(matches!(
            p.admit(public),
            Err(Denied::FactsUnreadable { .. })
        ));
    }

    /// Review r2 R2-NG-1: local routes that hold every public address the host routes stop a
    /// public-mode policy at startup, saying why, instead of refusing every fetch.
    #[test]
    fn local_routes_that_hold_everything_refuse_to_start() {
        use crate::facts::RawFacts;
        use crate::routes::Route;
        let facts = |routes| {
            HostFacts::assemble(
                RawFacts {
                    routes,
                    ..RawFacts::default()
                },
                &offline(),
            )
        };
        let default = Route::via(pfx("0.0.0.0/0"), ip("192.168.1.1"), 2);
        let e = usable(
            &facts(vec![
                default,
                Route::local(pfx("0.0.0.0/1"), 1),
                Route::local(pfx("128.0.0.0/1"), 1),
            ]),
            &offline(),
        )
        .unwrap_err();
        assert!(
            e.to_string().contains("0.0.0.0/1, 128.0.0.0/1")
                && e.to_string().contains("every destination"),
            "{e}"
        );
        // One half: refused where it holds, and the policy starts.
        let f = facts(vec![default, Route::local(pfx("0.0.0.0/1"), 1)]);
        assert!(usable(&f, &offline()).is_ok());
        assert!(admit(NetMode::Public, ip("8.8.8.8"), &f, &[]).is_err());
        assert_eq!(admit(NetMode::Public, ip("200.1.1.1"), &f, &[]), Ok(()));
        // A TPROXY catch-all is left alone.
        let f = facts(vec![default, Route::local(pfx("0.0.0.0/0"), 1)]);
        assert!(usable(&f, &offline()).is_ok());
        assert_eq!(admit(NetMode::Public, ip("8.8.8.8"), &f, &[]), Ok(()));
    }

    #[test]
    fn dev_mode_admits_everything() {
        let f = facts();
        let deny = [pfx("0.0.0.0/0"), pfx("::/0")];
        for s in [
            "127.0.0.1",
            "10.0.0.1",
            "169.254.169.254",
            "::1",
            "9.9.9.10",
            "8.8.8.8",
            "fe80::1",
        ] {
            assert_eq!(admit(NetMode::DevPrivate, ip(s), &f, &deny), Ok(()), "{s}");
        }
        let p = NetPolicy::with_facts(NetMode::DevPrivate, f, deny.to_vec());
        assert_eq!(p.admit(ip("127.0.0.1")), Ok(()));
    }

    #[test]
    fn a_policy_over_fixed_facts_judges_with_them() {
        let p = NetPolicy::with_facts(NetMode::Public, facts(), vec![pfx("8.8.4.0/24")]);
        assert_eq!(p.mode(), NetMode::Public);
        assert_eq!(p.admit(ip("1.1.1.1")), Ok(()));
        assert!(matches!(
            p.admit(ip("9.9.9.10")),
            Err(Denied::OwnAddress(_))
        ));
        assert!(matches!(
            p.admit(ip("8.8.4.8")),
            Err(Denied::DenyCidr { .. })
        ));
        assert_eq!(p.deny(), &[pfx("8.8.4.0/24")]);
    }

    #[test]
    fn a_gathered_public_policy_refuses_this_hosts_own_addresses() {
        let p = NetPolicy::new(NetMode::Public, Vec::new()).expect("read the interfaces");
        for a in p.facts().own_addresses() {
            assert!(p.admit(*a).is_err(), "{a} is this host's");
        }
    }

    #[test]
    fn whole_prefixes_are_admitted_only_when_public_and_apart_from_the_host() {
        let f = facts();
        let deny = [pfx("8.8.4.4/32"), pfx("2a02:1234::/32")];
        let a = |s: &str| admit_prefix(NetMode::Public, pfx(s), &f, &deny);
        for s in [
            "1.1.1.0/24",
            "1.1.1.1/32",
            "2606:4700:4700::/48",
            "64:ff9b::101:100/120",
            "8.8.8.0/24",
        ] {
            assert_eq!(a(s), Ok(()), "{s}");
        }
        for (s, why) in [
            ("0.0.0.0/0", "not on the public internet"),
            ("::/0", "not on the public internet"),
            ("8.0.0.0/6", "not on the public internet"), // holds 10.0.0.0/8
            ("127.0.0.1/32", "not on the public internet"),
            ("::ffff:127.0.0.1/128", "not on the public internet"),
            ("10.0.0.5/32", "not on the public internet"),
            ("2a01:4f8:1::77/128", "this host's own address"),
            ("2a01:4f8::/32", "this host's own address"),
            ("9.9.9.16/28", "a network this host is connected to"),
            ("9.0.0.0/8", "this host's own address"),
            (
                "2606:4700:aaaa:0:8000::/65",
                "a network this host is connected to",
            ),
            ("2606:4700:aaaa::/48", "this host's own address"),
            ("8.8.4.0/24", "deny CIDR"),
            ("::ffff:8.8.4.4/128", "deny CIDR"),
            ("2a02:1234:5::/48", "deny CIDR"),
        ] {
            let e = a(s).expect_err(s).to_string();
            assert!(e.contains(why), "{s}: {e}");
        }
        assert_eq!(
            admit_prefix(NetMode::DevPrivate, pfx("0.0.0.0/0"), &f, &deny),
            Ok(())
        );
    }

    #[test]
    fn denials_say_what_and_why_in_the_guards_words() {
        let d = Denied::NoAdmittedAddress {
            host: "elf.example.com".into(),
            refused: vec![
                Denied::NotGlobal(ip("127.0.0.1")),
                Denied::OwnAddress(ip("9.9.9.10")),
            ],
        };
        assert_eq!(
            d.to_string(),
            "refused by the network guard: \"elf.example.com\" resolves to no admitted address \
             (127.0.0.1 is not a public internet address; 9.9.9.10 is this host's own address)"
        );
        assert_eq!(
            Denied::Url(UrlDenied::Scheme("file".into())).to_string(),
            "refused by the network guard: the URL's scheme is \"file\", not http or https"
        );
    }
}
