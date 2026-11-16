//! The one admission decision ([`admit`]) and the policy value callers hold ([`NetPolicy`]).

use std::fmt;
use std::io;
use std::net::IpAddr;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use crate::facts::{FactsOptions, HostFacts};
use crate::host::HostDenied;
use crate::ip::{canonical_ip, is_global, prefix_is_global, Prefix};

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
    /// ipv6_site_prefix_len`).
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
    /// A prefix overlaps the site around one of the host's own IPv6 addresses.
    PrefixOverlapsSite { prefix: Prefix, site: Prefix },
    /// A prefix holds one of the DNS servers the host uses.
    PrefixHoldsDnsServer { prefix: Prefix, ip: IpAddr },
    /// A prefix overlaps a route that does not take the default path.
    PrefixOverlapsRoute { prefix: Prefix, route: Prefix },
    /// A prefix overlaps one of the operator's deny CIDRs.
    PrefixOverlapsDeny { prefix: Prefix, deny: Prefix },
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
                "{ip} is in {prefix}, the site around this host's own IPv6 address"
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
                "{prefix} overlaps {site}, the site around this host's own IPv6 address"
            ),
            Denied::PrefixHoldsDnsServer { prefix, ip } => {
                write!(f, "{prefix} holds {ip}, a DNS server this host uses")
            }
            Denied::PrefixOverlapsRoute { prefix, route } => write!(
                f,
                "{prefix} overlaps {route}, a route of this host that is not its default route"
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
        matches!(
            self,
            Denied::OwnAddress(_)
                | Denied::ConnectedPrefix { .. }
                | Denied::SitePrefix { .. }
                | Denied::DnsServer(_)
                | Denied::OffDefaultRoute { .. }
                | Denied::RouteQueryFailed { .. }
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
/// snapshot).
pub fn admit(
    mode: NetMode,
    ip: IpAddr,
    facts: &HostFacts,
    extra_deny: &[Prefix],
) -> Result<(), Denied> {
    if mode == NetMode::DevPrivate {
        return Ok(());
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
    facts.kernel_verdict(ip)
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

/// The host facts a policy judges with: gathered and re-read once older than [`FACTS_TTL`] (or
/// on a facts-dependent refusal, [`FORCED_REFRESH_MIN_AGE`]), or fixed by the caller.
#[derive(Debug)]
struct FactsCell {
    current: RwLock<Arc<HostFacts>>,
    refresh: bool,
    options: FactsOptions,
}

impl FactsCell {
    fn get(&self) -> Arc<HostFacts> {
        self.get_fresher_than(FACTS_TTL)
    }

    /// The facts, re-read first if they are older than `max_age` (and the cell refreshes).
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

/// Refuses, at startup, facts under which every destination would be refused, with why (the
/// host's local routes hold every public address it routes: [`crate::RouteTable::local_refuses_everything`]).
fn usable(facts: &HostFacts) -> io::Result<()> {
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

/// A network policy: the mode, the host's facts, and the operator's extra deny CIDRs. Cheap to clone
/// (shared state). Every requester-caused connection is judged by one: [`NetPolicy::admit`] for an
/// address, [`NetPolicy::check_url`] for a URL, and the guarded resolver and client built from it.
#[derive(Debug, Clone)]
pub struct NetPolicy {
    mode: NetMode,
    facts: Arc<FactsCell>,
    deny: Arc<[Prefix]>,
}

impl NetPolicy {
    /// A policy over this host's own facts with the default options ([`FactsOptions::default`]);
    /// see [`Self::with_options`].
    pub fn new(mode: NetMode, deny: Vec<Prefix>) -> io::Result<Self> {
        Self::with_options(mode, deny, FactsOptions::default())
    }

    /// A policy over this host's own facts, gathered now with `options` (in [`NetMode::Public`])
    /// and re-read once older than [`FACTS_TTL`], or before a refusal that rests on them. Fails if
    /// the interfaces or the routing table cannot be read, or `options` is invalid: a public-mode
    /// policy that does not know the host cannot refuse it.
    pub fn with_options(
        mode: NetMode,
        deny: Vec<Prefix>,
        options: FactsOptions,
    ) -> io::Result<Self> {
        options
            .validate()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let (facts, refresh) = match mode {
            NetMode::Public => (HostFacts::gather_with(&options)?, true),
            NetMode::DevPrivate => (HostFacts::empty(), false),
        };
        if mode == NetMode::Public {
            usable(&facts)?;
        }
        Ok(Self::build(mode, facts, refresh, deny, options))
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
            }),
            deny: deny.into(),
        }
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
        self.facts.options
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

    fn offline() -> FactsOptions {
        FactsOptions {
            discover_public_addresses: false,
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
        assert_eq!(a("2606:4700:1:100::1"), Ok(()));
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
        fn route_to(&self, dst: IpAddr) -> io::Result<Option<Vec<crate::routes::Route>>> {
            self.asked.lock().unwrap().push(dst);
            self.answers
                .get(&dst)
                .cloned()
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
        assert_eq!(a("93.184.216.34"), Ok(()));
        assert_eq!(a("1.0.0.1"), Ok(()));
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
            !f.resolvers().contains(&ip("1.0.0.1"))
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
            ipv6_site_prefix_len: 40,
            ..offline()
        };
        assert!(NetPolicy::with_options(NetMode::Public, Vec::new(), bad).is_err());
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
        let e = usable(&facts(vec![
            default,
            Route::local(pfx("0.0.0.0/1"), 1),
            Route::local(pfx("128.0.0.0/1"), 1),
        ]))
        .unwrap_err();
        assert!(
            e.to_string().contains("0.0.0.0/1, 128.0.0.0/1")
                && e.to_string().contains("every destination"),
            "{e}"
        );
        // One half: refused where it holds, and the policy starts.
        let f = facts(vec![default, Route::local(pfx("0.0.0.0/1"), 1)]);
        assert!(usable(&f).is_ok());
        assert!(admit(NetMode::Public, ip("8.8.8.8"), &f, &[]).is_err());
        assert_eq!(admit(NetMode::Public, ip("200.1.1.1"), &f, &[]), Ok(()));
        // A TPROXY catch-all is left alone.
        let f = facts(vec![default, Route::local(pfx("0.0.0.0/0"), 1)]);
        assert!(usable(&f).is_ok());
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
