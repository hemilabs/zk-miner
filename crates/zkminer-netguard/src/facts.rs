//! What the host itself is on the network: its own addresses, the prefixes it is connected to,
//! the site around its IPv6 addresses, the DNS servers it uses, and its routing table.
//!
//! A global address can still be the host itself (its public address, reached by hairpin through
//! the router) or a neighbour (a NAS or a BMC with a global IPv6 address in the miner's /64, a
//! server on the same public subnet, a host behind a VPN route). A connection a requester causes
//! is refused to all of them ([`crate::admit`]). The facts, gathered by [`HostFacts::gather_with`]:
//!
//! - **own addresses:** every interface address, plus the public addresses the host has behind NAT,
//!   learned from fixed reflectors ([`crate::public`]; `discover_public_addresses`);
//! - **connected prefixes:** every interface address under its netmask, the peer of a
//!   point-to-point link, and every on-link route (no gateway, not on loopback, not a default
//!   route): a DHCPv6 address is a /128 whose /64 is only a route ([`crate::routes`]);
//! - **site prefixes:** the enclosing /`ipv6_site_prefix_len` (default /32) of every own global
//!   IPv6 address. A home or office is delegated a /56 or a /48, an organisation holds up to a
//!   /32, and numbers its other networks from it, none of which the host's own /64 shows (the
//!   default also refuses the rest of the host's own ISP's /32 over IPv6); and the enclosing
//!   /`ipv4_site_prefix_len`
//!   (default /16) of every global IPv4 address on an interface (a campus or data centre numbered
//!   from public space reaches its other subnets through the default gateway);
//! - **public-address knowledge:** per family the host routes, whether its public address is
//!   known (learned reliably or configured); a family whose is not refuses every connection
//!   ([`HostFacts::unknown_paths`]);
//! - **uplinks that are not plainly physical and global IPv4 interface addresses**, which make a
//!   public-mode host need `[egress] internal_ranges` ([`HostFacts::needs_internal_ranges`]):
//!   re-judged with every snapshot ([`HostFacts::config_gaps`]);
//! - **DNS servers:** the `nameserver`s of `/etc/resolv.conf` and of systemd-resolved's
//!   `/run/systemd/resolve/resolv.conf` (the upstream servers behind its `127.0.0.53` stub), which
//!   may answer only their own customers;
//! - **the routing table and the policy-routing rules**, for the best-route rule: a destination
//!   whose best route is not the default path is refused, and so is one a `local`, `broadcast` or
//!   `anycast` route delivers to this host (an AnyIP range) or a destination rule sends to another
//!   table ([`crate::routes::RouteTable::off_default_path`]); and the kernel itself, asked per
//!   destination how it would route a connection ([`crate::routes::RouteTable::judge`]).
//!
//! - **NAT64 prefixes**, configured or learned ([`crate::nat64`]): process-wide, read by the
//!   address predicate itself.
//!
//! A miner in a container sees the container's network, not the host's: run it with host
//! networking, or list the host's networks in `[egress] deny_cidrs`.

use std::collections::HashMap;
use std::io;
use std::net::IpAddr;
use std::ops::RangeInclusive;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use crate::ip::{is_global, Prefix};
use crate::policy::Denied;
use crate::routes::{Route, RouteOracle, RouteRefusal, RouteTable, Rule};

/// The default `[egress] ipv6_site_prefix_len`: a /32, what an organisation (a campus, a
/// company, an ISP's own customers' allocation) usually holds. It also refuses the rest of the
/// miner's own ISP's /32 over IPv6; a dual-stack name there still connects over IPv4.
pub const DEFAULT_IPV6_SITE_PREFIX_LEN: u8 = 32;
/// The lengths `[egress] ipv6_site_prefix_len` may take.
pub const IPV6_SITE_PREFIX_LENS: RangeInclusive<u8> = 16..=64;
/// The default `[egress] ipv4_site_prefix_len`.
pub const DEFAULT_IPV4_SITE_PREFIX_LEN: u8 = 16;
/// The lengths `[egress] ipv4_site_prefix_len` may take.
pub const IPV4_SITE_PREFIX_LENS: RangeInclusive<u8> = 8..=32;
/// The default `[egress] near_hop_limit` ([`crate::nearhop`]).
pub const DEFAULT_NEAR_HOP_LIMIT: u8 = 2;
/// The values `[egress] near_hop_limit` may take.
pub const NEAR_HOP_LIMITS: RangeInclusive<u8> = 2..=16;

/// The operator's `[egress]` settings the guard runs with: how the host's facts are gathered,
/// what the operator says about its network, and how connections are checked before they are
/// made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FactsOptions {
    /// The site around each of the host's own global IPv6 addresses that is refused
    /// ([`IPV6_SITE_PREFIX_LENS`], default [`DEFAULT_IPV6_SITE_PREFIX_LEN`]).
    pub ipv6_site_prefix_len: u8,
    /// The site around each global IPv4 address on one of the host's interfaces that is refused
    /// ([`IPV4_SITE_PREFIX_LENS`], default [`DEFAULT_IPV4_SITE_PREFIX_LEN`]).
    pub ipv4_site_prefix_len: u8,
    /// Whether to learn the host's public (NAT) addresses from fixed reflectors
    /// ([`crate::public`]). Default true.
    pub discover_public_addresses: bool,
    /// The host's public addresses as the operator states them (`[egress] public_addresses`):
    /// refused as its own, and a family named here counts as known whether or not discovery
    /// works (see [`HostFacts::unknown_paths`]).
    pub public_addresses: Vec<IpAddr>,
    /// The ranges of the operator's own network that the internet path also reaches
    /// (`[egress] internal_ranges`), refused like deny CIDRs. `None` when the operator has not
    /// said; `Some(vec![])` is the statement that there are none. A host with a global IPv4
    /// interface address or a default route through a tunnel needs it to start
    /// ([`HostFacts::needs_internal_ranges`]).
    pub internal_ranges: Option<Vec<Prefix>>,
    /// The hop limit of the probe sent before every connection under the floor
    /// ([`crate::nearhop`]; [`NEAR_HOP_LIMITS`], default [`DEFAULT_NEAR_HOP_LIMIT`]).
    pub near_hop_limit: u8,
    /// The DNS-over-HTTPS resolvers requester names are resolved with in public mode; empty: the
    /// compiled-in ones ([`crate::doh::DEFAULT_SERVERS`]).
    pub doh_resolvers: Vec<crate::doh::DohServer>,
}

impl Default for FactsOptions {
    fn default() -> Self {
        FactsOptions {
            ipv6_site_prefix_len: DEFAULT_IPV6_SITE_PREFIX_LEN,
            ipv4_site_prefix_len: DEFAULT_IPV4_SITE_PREFIX_LEN,
            discover_public_addresses: true,
            public_addresses: Vec::new(),
            internal_ranges: None,
            near_hop_limit: DEFAULT_NEAR_HOP_LIMIT,
            doh_resolvers: Vec::new(),
        }
    }
}

impl FactsOptions {
    /// Refuses a site prefix length or hop limit outside its range, a stated public address
    /// that is not global, and a DNS-over-HTTPS resolver that is not.
    pub fn validate(&self) -> Result<(), String> {
        let range = |name: &str, v: u8, r: &RangeInclusive<u8>| {
            if r.contains(&v) {
                Ok(())
            } else {
                Err(format!(
                    "{name} = {v} is outside {}..={}",
                    r.start(),
                    r.end()
                ))
            }
        };
        range(
            "ipv6_site_prefix_len",
            self.ipv6_site_prefix_len,
            &IPV6_SITE_PREFIX_LENS,
        )?;
        range(
            "ipv4_site_prefix_len",
            self.ipv4_site_prefix_len,
            &IPV4_SITE_PREFIX_LENS,
        )?;
        range("near_hop_limit", self.near_hop_limit, &NEAR_HOP_LIMITS)?;
        if let Some(a) = self.public_addresses.iter().find(|a| !is_global(**a)) {
            return Err(format!(
                "public_addresses: {a} is not a public internet address"
            ));
        }
        for d in &self.doh_resolvers {
            d.check()?;
        }
        Ok(())
    }
}

/// The path a connection to a destination leaves this host by, for the public-address check
/// ([`HostFacts::unknown_paths`]): native IPv4, native IPv6, or IPv4 through a NAT64 translator
/// (an IPv6 address that carries an IPv4 one).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum EgressPath {
    Ipv4,
    Ipv6,
    /// To the IPv4 address an IPv6 address carries, through the translator of its NAT64
    /// prefix (or a SIIT translator), from that translator's own IPv4 address.
    Nat64,
}

impl std::fmt::Display for EgressPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            EgressPath::Ipv4 => "IPv4",
            EgressPath::Ipv6 => "IPv6",
            EgressPath::Nat64 => "IPv4 through NAT64",
        })
    }
}

impl EgressPath {
    /// The path a connection to `ip` takes: IPv4 for an IPv4 address or an IPv4-mapped one
    /// (which a dual-stack socket connects as IPv4), NAT64 for another IPv6 spelling of an IPv4
    /// address, else IPv6.
    pub fn of(ip: IpAddr) -> EgressPath {
        match ip {
            IpAddr::V4(_) => EgressPath::Ipv4,
            IpAddr::V6(a) if a.to_ipv4_mapped().is_some() => EgressPath::Ipv4,
            IpAddr::V6(_) if crate::canonical_ip(ip).is_ipv4() => EgressPath::Nat64,
            IpAddr::V6(_) => EgressPath::Ipv6,
        }
    }

    /// What the operator can set so connections over this path go out again.
    pub fn advice(&self) -> &'static str {
        match self {
            EgressPath::Ipv4 => {
                "set `public_addresses = [\"<this host's public IPv4 address>\"]` in [egress] (or \
                 let outbound DNS to 216.239.32.10 and 1.1.1.1, or HTTPS to 1.1.1.1, through)"
            }
            EgressPath::Ipv6 => {
                "set `public_addresses = [\"<this host's public IPv6 address>\"]` in [egress] (or \
                 let outbound DNS to 2001:4860:4802:32::a and 2606:4700:4700::1111, or HTTPS to \
                 2606:4700:4700::1111, through)"
            }
            EgressPath::Nat64 => {
                "on an IPv6-only host, set `public_addresses = [\"<the NAT64 translator's public \
                 IPv4 address>\"]` in [egress] (or let the reflectors be reached through the \
                 translator); a host with IPv4 of its own never connects through NAT64"
            }
        }
    }
}

/// What the facts know about the host's public addresses per path (see
/// [`HostFacts::unknown_paths`]).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct EgressState {
    /// [IPv4, IPv6]: the host has a default route of the family.
    routed: [bool; 2],
    /// [IPv4, IPv6]: a public address of the family was learned reliably or is configured.
    known: [bool; 2],
    /// The NAT64 prefixes through which this host's IPv4 public address was learned.
    nat64: Vec<Prefix>,
    /// An IPv4 public address is configured (it stands for the NAT64 path too).
    v4_configured: bool,
}

/// What the system said, before it is judged: the injectable input of [`HostFacts::assemble`]
/// (tests stage a DHCPv6 host or a VPN with it, no root needed).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RawFacts {
    /// Every interface address under its netmask, and point-to-point peers.
    pub interface_prefixes: Vec<Prefix>,
    /// Every interface address.
    pub interface_addresses: Vec<IpAddr>,
    /// Every unicast, `local`, `broadcast` and `anycast` route of every table.
    pub routes: Vec<Route>,
    /// The policy-routing rules, read for this process (none: a stock host's, [`Rule::stock`]).
    pub rules: Vec<Rule>,
    /// The DNS servers the host uses.
    pub resolvers: Vec<IpAddr>,
    /// The host's public addresses as reflectors see them (refused as its own).
    pub public_addresses: Vec<IpAddr>,
    /// The public addresses discovery learned reliably ([`crate::public::Learned::confirmed`]:
    /// the TLS reflector's answer, or two DNS reflectors' alike): only these (and the interface
    /// addresses) give an IPv6 site, and a family with one counts as known.
    pub public_confirmed: Vec<IpAddr>,
    /// The NAT64 prefixes through which an IPv4 public address was learned reliably.
    pub public_via_nat64: Vec<Prefix>,
    /// Every network interface, with its kind.
    pub links: Vec<crate::routes::Link>,
    /// The interfaces the kernel sends internet traffic out of (its answer for a fixed public
    /// address of each family).
    pub internet_interfaces: Vec<u32>,
    /// Every nexthop object (for default routes through one, whose interface the route dump does
    /// not show).
    pub nexthops: Vec<crate::routes::Nexthop>,
    /// How many PPPoE sessions the host has (`/proc/net/pppoe`): a `ppp` uplink is an ordinary
    /// PPPoE uplink only when every `ppp` interface can be one of them.
    pub pppoe_sessions: usize,
}

/// A snapshot of the host's facts (see the module doc).
#[derive(Debug, Clone)]
pub struct HostFacts {
    connected: Vec<Prefix>,
    own: Vec<IpAddr>,
    site: Vec<Prefix>,
    resolvers: Vec<IpAddr>,
    routes: RouteTable,
    gathered_at: Instant,
    /// Asked per destination by [`crate::admit`] ([`Self::with_route_oracle`]); the kernel for
    /// facts read from this host.
    oracle: Option<Arc<dyn RouteOracle>>,
    /// The oracle's verdicts, per destination and port, for as long as these facts are in force.
    verdicts: Arc<Mutex<Verdicts>>,
    /// What is known about the host's public addresses, for facts read from a host (`None` for
    /// facts given by the caller, which say nothing about it).
    egress: Option<EgressState>,
    /// Why the host's uplinks are not plainly physical (see [`Self::needs_internal_ranges`]).
    uplink_reasons: Vec<String>,
    /// The global IPv4 addresses on the host's interfaces.
    global_v4_interfaces: Vec<IpAddr>,
    /// Whether `[egress] internal_ranges` is stated (facts given by the caller: true).
    internal_ranges_stated: bool,
    /// macOS: why these facts can no longer be judged with (a refresh failed and they outlived
    /// their time): every requester connection is refused ([`crate::Denied::FactsUnreadable`]).
    #[cfg(target_os = "macos")]
    unreadable: Option<String>,
}

/// Why the kernel's answer refused a destination ([`HostFacts::kernel_verdict`]).
#[derive(Debug, Clone, PartialEq, Eq)]
enum KernelRefusal {
    Route(RouteRefusal),
    QueryFailed(String),
}

/// The route oracle's verdicts, per destination and destination port.
type Verdicts = HashMap<(IpAddr, Option<u16>), Result<(), KernelRefusal>>;

/// Most per-destination verdicts one facts snapshot keeps (it lives about a second).
const MAX_VERDICTS: usize = 4096;

fn sorted<T: Ord>(mut v: Vec<T>) -> Vec<T> {
    v.sort();
    v.dedup();
    v
}

/// Why the uplinks of `routes` are not plainly physical (see [`HostFacts::needs_internal_ranges`]):
/// every default route of an ordinary table, by its interface (or its nexthop object's), and the
/// interfaces in `internet` (the kernel's own answer for internet traffic).
fn uplink_reasons(
    routes: &RouteTable,
    links: &[crate::routes::Link],
    nexthops: &[crate::routes::Nexthop],
    internet: &[u32],
    pppoe_sessions: usize,
) -> Vec<String> {
    use crate::routes::{RT_TABLE_DEFAULT, RT_TABLE_MAIN};
    let mut why = Vec::new();
    let mut uplinks: Vec<u32> = internet.to_vec();
    for r in routes.routes().iter().filter(|r| r.is_default_like()) {
        if r.table != RT_TABLE_MAIN && r.table != RT_TABLE_DEFAULT {
            why.push(format!(
                "routing table {} holds the default route {}, and a policy rule sends every \
                 connection to that table (a VPN's or a policy-based IPsec's, such as \
                 strongSwan's table 220)",
                r.table, r.prefix
            ));
        }
        if r.ifindex != 0 {
            uplinks.push(r.ifindex);
        } else if r.nexthop != 0 {
            match crate::routes::nexthop_interfaces(nexthops, r.nexthop) {
                Some(ifs) => uplinks.extend(ifs),
                None => why.push(format!(
                    "the default route {} goes through nexthop object {}, whose interface cannot \
                     be read",
                    r.prefix, r.nexthop
                )),
            }
        } else {
            why.push(format!("the default route {} names no interface", r.prefix));
        }
    }
    uplinks.sort();
    uplinks.dedup();
    if links.is_empty() {
        // Facts given without an interface list (a host's always has `lo`): nothing to judge
        // the interfaces by.
        why.sort();
        why.dedup();
        return why;
    }
    let ppp_links = links.iter().filter(|l| l.is_ppp()).count();
    for i in uplinks {
        let Some(l) = links.iter().find(|l| l.index == i) else {
            why.push(format!(
                "this host's default route goes out of interface {i}, which the interface list \
                 does not show"
            ));
            continue;
        };
        if l.is_physical() {
            continue;
        }
        if l.is_ppp() {
            if ppp_links <= pppoe_sessions {
                continue; // a PPPoE uplink
            }
            why.push(format!(
                "this host's default route goes out of {}, a ppp link that is not a PPPoE \
                 session (a VPN: L2TP, PPTP, SSTP, openfortivpn)",
                l.name
            ));
            continue;
        }
        let kind = l.kind.as_deref().unwrap_or_default();
        why.push(if l.is_tunnel() {
            format!(
                "this host's default route goes out of {}, a {kind} tunnel",
                l.name
            )
        } else {
            format!(
                "this host's default route goes out of {}, an interface of kind {kind}, which \
                 the network guard does not know to be physical",
                l.name
            )
        });
    }
    why.sort();
    why.dedup();
    why
}

/// A value that changes when the host's uplink does: its default routes (prefix, gateway,
/// interface, table; not a nexthop object's id, which a router advertisement can renew without
/// changing anything) and the interfaces the kernel sends internet traffic out of.
/// Public addresses confirmed under another uplink are not this one's
/// ([`crate::public::learned_on`]).
fn uplink_signature(routes: &RouteTable, internet: &[u32]) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    for r in routes.routes().iter().filter(|r| r.is_default_like()) {
        (r.prefix, r.hop, r.ifindex, r.table).hash(&mut h);
    }
    internet.hash(&mut h);
    h.finish()
}

/// macOS: the kernel's answer `answer`, which `routes` (these facts' table) admitted, must leave by
/// a default path these facts hold (review round 3, bypass-3). [`RouteTable::judge`] admits any
/// default-like route of an ordinary table whatever its gateway and interface, so an uplink that
/// came up after the facts were read (a full-tunnel VPN's `0/1` on a `utun`, a second network's
/// default) was admitted until the facts were read again, up to [`crate::FACTS_TTL`] later (and
/// `REFRESH_GRACE` more while re-reads fail), and only those facts would have seen it
/// (`[egress] internal_ranges`, the uplink signature). So each route of the answer that is
/// default-like must be one of their default-like routes: the same family, hop and interface (a
/// route through one of their uplinks is: an uplink is a `/0` route's gateway and interface).
/// Otherwise it is refused as off the default path
/// (the gateway's or the link's kind), which rests on the facts: the policy reads them again and
/// judges once more.
#[cfg(target_os = "macos")]
fn default_path_known(
    routes: &RouteTable,
    answer: &crate::routes::KernelAnswer,
) -> Result<(), crate::routes::RouteRefusal> {
    use crate::routes::{Hop, KernelAnswer, RouteKind, RouteRefusal};
    let KernelAnswer::Entry(entry) = answer else {
        // No route and a split answer are refused by the judge already.
        return Ok(());
    };
    for r in entry {
        let held = routes.routes().iter().any(|d| {
            d.is_default_like()
                && d.prefix.addr.is_ipv6() == r.prefix.addr.is_ipv6()
                && d.hop == r.hop
                && d.ifindex == r.ifindex
        });
        if r.is_default_like() && !held {
            return Err(RouteRefusal {
                prefix: r.prefix,
                kind: if r.hop == Hop::OnLink {
                    RouteKind::OnLink
                } else {
                    RouteKind::OtherGateway
                },
            });
        }
    }
    Ok(())
}

/// macOS: [`uplink_signature`] (`base`) and the network each service is on, as the configuration
/// daemon identifies it (`NetworkSignature`: the router's address and hardware address for IPv4,
/// the prefix and the router's hardware address for IPv6; [`macos_dns::network_signatures`]).
/// Two networks whose routers have the same address on the same interface (two home networks
/// behind 192.168.1.1) have the same routes, so `base` alone cannot tell them apart, and a public
/// address confirmed on the first would stay confirmed on the second for up to
/// [`crate::public::DISCOVERY_TTL`]; their routers' hardware addresses differ (review round 2,
/// bypass-2). The kernel's neighbour table cannot stand in: an unprivileged process sees no ARP
/// entries and every NDP entry's hardware address as `02:00:00:00:00:00`
/// (`fix-r2/llinfo-unprivileged.log`).
#[cfg(target_os = "macos")]
fn macos_uplink_signature(base: u64, networks: &[String]) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    base.hash(&mut h);
    sorted(networks.to_vec()).hash(&mut h);
    h.finish()
}

/// The enclosing /`len` of every global IPv6 address in `own` (`len` clamped to
/// [`IPV6_SITE_PREFIX_LENS`]).
pub fn site_prefixes(own: &[IpAddr], len: u8) -> Vec<Prefix> {
    let len = len.clamp(*IPV6_SITE_PREFIX_LENS.start(), *IPV6_SITE_PREFIX_LENS.end());
    sorted(
        own.iter()
            .filter(|a| a.is_ipv6() && is_global(**a) && crate::canonical_ip(**a) == **a)
            .map(|a| Prefix::new(*a, len))
            .collect(),
    )
}

/// The enclosing /`len` of every global IPv4 address in `interface_addresses` (`len` clamped to
/// [`IPV4_SITE_PREFIX_LENS`]): a host numbered from global IPv4 space sits in a network (a
/// campus, a data centre) whose other subnets are reached through the default gateway.
pub fn ipv4_site_prefixes(interface_addresses: &[IpAddr], len: u8) -> Vec<Prefix> {
    let len = len.clamp(*IPV4_SITE_PREFIX_LENS.start(), *IPV4_SITE_PREFIX_LENS.end());
    sorted(
        interface_addresses
            .iter()
            .filter(|a| a.is_ipv4() && is_global(**a))
            .map(|a| Prefix::new(*a, len))
            .collect(),
    )
}

impl HostFacts {
    /// Facts given by the caller: connected prefixes and own addresses only (no site prefixes,
    /// DNS servers or routes). Tests, and the witness broker, which is told the facts.
    pub fn new(connected: Vec<Prefix>, own: Vec<IpAddr>) -> Self {
        HostFacts {
            connected: sorted(connected),
            own: sorted(own),
            site: Vec::new(),
            resolvers: Vec::new(),
            routes: RouteTable::default(),
            gathered_at: Instant::now(),
            oracle: None,
            verdicts: Arc::default(),
            egress: None,
            uplink_reasons: Vec::new(),
            global_v4_interfaces: Vec::new(),
            internal_ranges_stated: true,
            #[cfg(target_os = "macos")]
            unreadable: None,
        }
    }

    /// No addresses and no prefixes.
    pub fn empty() -> Self {
        Self::new(Vec::new(), Vec::new())
    }

    /// The facts `raw` amounts to under `opts` (see the module doc).
    pub fn assemble(raw: RawFacts, opts: &FactsOptions) -> Self {
        let routes = RouteTable::with_rules(raw.routes, raw.rules);
        let mut connected = raw.interface_prefixes;
        connected.extend(routes.on_link_prefixes());
        // Review r2 R2-NG-7: a public address one reflector alone reported (or a forger) is
        // refused as an own address, but gives no site: that would refuse a /48-/56 of whoever
        // the forged address belongs to.
        let configured: Vec<IpAddr> = opts
            .public_addresses
            .iter()
            .copied()
            .filter(|a| is_global(*a))
            .collect();
        let mut site_from = raw.interface_addresses.clone();
        site_from.extend(raw.public_confirmed.iter().filter(|a| is_global(**a)));
        site_from.extend(&configured);
        let mut site = site_prefixes(&site_from, opts.ipv6_site_prefix_len);
        site.extend(ipv4_site_prefixes(
            &raw.interface_addresses,
            opts.ipv4_site_prefix_len,
        ));
        let global_v4_interfaces = sorted(
            raw.interface_addresses
                .iter()
                .copied()
                .filter(|a| a.is_ipv4() && is_global(*a))
                .collect(),
        );
        // A public address of a family is known when discovery learned one reliably or the
        // operator stated one; only then may a connection go out over that family.
        let known_of = |v6: bool| {
            raw.public_confirmed
                .iter()
                .chain(&configured)
                .any(|a| a.is_ipv6() == v6 && is_global(*a))
        };
        let egress = EgressState {
            routed: [routes.routes_family(false), routes.routes_family(true)],
            known: [known_of(false), known_of(true)],
            nat64: sorted(raw.public_via_nat64.clone()),
            v4_configured: configured.iter().any(IpAddr::is_ipv4),
        };
        let uplink_reasons = uplink_reasons(
            &routes,
            &raw.links,
            &raw.nexthops,
            &raw.internet_interfaces,
            raw.pppoe_sessions,
        );
        let mut own = raw.interface_addresses;
        own.extend(
            raw.public_addresses
                .into_iter()
                .chain(raw.public_confirmed)
                .chain(configured)
                .filter(|a| is_global(*a)),
        );
        let own = sorted(own);
        HostFacts {
            connected: sorted(connected),
            site: sorted(site),
            own,
            resolvers: sorted(raw.resolvers),
            routes,
            gathered_at: Instant::now(),
            oracle: None,
            verdicts: Arc::default(),
            egress: Some(egress),
            uplink_reasons,
            global_v4_interfaces,
            internal_ranges_stated: opts.internal_ranges.is_some(),
            #[cfg(target_os = "macos")]
            unreadable: None,
        }
    }

    /// How many kernel verdicts these facts hold (macOS tests).
    #[cfg(all(test, target_os = "macos"))]
    pub(crate) fn cached_verdicts(&self) -> usize {
        self.verdicts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .len()
    }

    /// macOS: why these facts may not be judged with, if so (see [`Self::refusing`]).
    #[cfg(target_os = "macos")]
    pub(crate) fn unreadable(&self) -> Option<&str> {
        self.unreadable.as_deref()
    }

    /// macOS: these facts without the kernel's cached verdicts (a refresh failed: what the kernel
    /// answered for them is asked again).
    #[cfg(target_os = "macos")]
    pub(crate) fn without_verdicts(&self) -> Self {
        HostFacts {
            verdicts: Arc::default(),
            ..self.clone()
        }
    }

    /// macOS: these facts, which may no longer be judged with: `why` they could not be read
    /// again. [`crate::admit`] refuses every destination with them.
    #[cfg(target_os = "macos")]
    pub(crate) fn refusing(&self, why: String) -> Self {
        HostFacts {
            unreadable: Some(why),
            ..self.without_verdicts()
        }
    }

    /// The paths over which no connection may go out because this host's public address on them
    /// is not known: a family the host routes whose public address discovery has not learned
    /// (or learned only from one DNS reflector) and `[egress] public_addresses` does not name.
    /// Behind NAT a destination at that unknown address would reach this host or its router by
    /// hairpin, so the family is refused until it is known. On an IPv6-only host the NAT64 path
    /// is listed until the translator's IPv4 address is learned through a NAT64 prefix (or an
    /// IPv4 address is configured). (On a host with IPv4 of its own the NAT64 path is always
    /// refused, [`Self::path_known`], and not listed: nothing needs setting.) Empty for facts
    /// given by the caller ([`Self::new`]).
    pub fn unknown_paths(&self) -> Vec<EgressPath> {
        let Some(e) = &self.egress else {
            return Vec::new();
        };
        let mut v = Vec::new();
        if e.routed[0] && !e.known[0] {
            v.push(EgressPath::Ipv4);
        }
        if e.routed[1] && !e.known[1] {
            v.push(EgressPath::Ipv6);
        }
        if e.routed[1] && !e.routed[0] && !e.v4_configured && e.nat64.is_empty() {
            v.push(EgressPath::Nat64);
        }
        v
    }

    /// Whether a connection to `ip` may go out on its path ([`Self::unknown_paths`]): `Err` with
    /// the path when it may not.
    pub(crate) fn path_known(&self, ip: IpAddr) -> Result<(), EgressPath> {
        let Some(e) = &self.egress else {
            return Ok(());
        };
        let path = EgressPath::of(ip);
        let v6 = path != EgressPath::Ipv4;
        if e.routed[usize::from(v6)] && !e.known[usize::from(v6)] {
            return Err(if v6 {
                EgressPath::Ipv6
            } else {
                EgressPath::Ipv4
            });
        }
        if path == EgressPath::Nat64 {
            // A host with IPv4 of its own never needs a translator; on an IPv6-only host the
            // translator's IPv4 address must be known, through this address's prefix.
            let through = match ip {
                IpAddr::V6(a) => crate::nat64::prefix_of(a),
                IpAddr::V4(_) => None,
            };
            let learned = through.is_some_and(|p| e.nat64.contains(&p));
            if e.routed[0] || !(learned || e.v4_configured) {
                return Err(EgressPath::Nat64);
            }
        }
        Ok(())
    }

    /// Why this host needs `[egress] internal_ranges` in public mode: each global IPv4 address on
    /// its interfaces (its network is numbered from public space, and its other subnets are
    /// reached through the default gateway), and each way its uplink is not plainly physical
    /// (the far side's own hosts would look like the internet): a default route out of an
    /// interface whose kind is not known to be physical ([`crate::routes::PHYSICAL_KINDS`]: a
    /// tunnel, a `ppp` link that is not PPPoE, a kind the guard does not know), a default route in
    /// an ordinary routing table other than `main` and `default` (a VPN's, a policy-based IPsec's
    /// table 220), or one through a nexthop object or an interface that cannot be resolved.
    /// Empty when nothing holds.
    pub fn needs_internal_ranges(&self) -> Vec<String> {
        let mut why: Vec<String> = self
            .global_v4_interfaces
            .iter()
            .map(|a| format!("this host has the global IPv4 address {a} on an interface"))
            .collect();
        why.extend(self.uplink_reasons.iter().cloned());
        why
    }

    /// What these facts need that the configuration does not state: the reasons of
    /// [`Self::needs_internal_ranges`] when `[egress] internal_ranges` is not set. Re-read with
    /// the facts, so a tunnel that comes up (or a global IPv4 address that appears) after the miner
    /// started refuses every connection until the operator states the ranges ([`crate::admit`]:
    /// [`crate::Denied::InternalRangesUnstated`]); empty when nothing is missing.
    pub fn config_gaps(&self) -> Vec<String> {
        if self.internal_ranges_stated {
            Vec::new()
        } else {
            self.needs_internal_ranges()
        }
    }

    /// These facts, with `oracle` asked how each destination is routed ([`crate::admit`] refuses
    /// what [`RouteTable::judge`] refuses of its answer). [`Self::gather_with`] sets the kernel
    /// itself ([`crate::KernelRoutes`]); tests stage answers.
    pub fn with_route_oracle(mut self, oracle: Arc<dyn RouteOracle>) -> Self {
        self.oracle = Some(oracle);
        self.verdicts = Arc::default();
        self
    }

    /// The oracle asked per destination, if any.
    pub fn route_oracle(&self) -> Option<&Arc<dyn RouteOracle>> {
        self.oracle.as_ref()
    }

    /// The route oracle's verdict on a connection to `ip` (on destination port `dport` when
    /// given; admitted when there is no oracle): asked once per destination and port for as long
    /// as these facts are in force (a snapshot lives about a second, [`crate::FACTS_TTL`]). An
    /// IPv4-mapped address is asked as its IPv4 address, which is how a dual-stack socket
    /// connects to it.
    pub(crate) fn kernel_verdict(&self, ip: IpAddr, dport: Option<u16>) -> Result<(), Denied> {
        let Some(oracle) = &self.oracle else {
            return Ok(());
        };
        let dst = match ip {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
            v4 => v4,
        };
        let cached = self
            .verdicts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&(dst, dport))
            .cloned();
        let verdict = match cached {
            Some(v) => v,
            None => {
                let v = match oracle.route_to(dst, dport) {
                    #[cfg(target_os = "macos")]
                    Ok(answer) => self
                        .routes
                        .judge_answer(&answer)
                        .and_then(|()| default_path_known(&self.routes, &answer))
                        .map_err(KernelRefusal::Route),
                    #[cfg(not(target_os = "macos"))]
                    Ok(answer) => self
                        .routes
                        .judge_answer(&answer)
                        .map_err(KernelRefusal::Route),
                    Err(e) => Err(KernelRefusal::QueryFailed(e.to_string())),
                };
                let mut cache = self.verdicts.lock().unwrap_or_else(|e| e.into_inner());
                if cache.len() >= MAX_VERDICTS {
                    cache.clear();
                }
                cache.insert((dst, dport), v.clone());
                v
            }
        };
        verdict.map_err(|k| match k {
            KernelRefusal::Route(r) => Denied::OffDefaultRoute {
                ip,
                route: if r.kind == crate::routes::RouteKind::NoRoute {
                    Prefix::host(dst)
                } else {
                    r.prefix
                },
                kind: r.kind,
            },
            KernelRefusal::QueryFailed(why) => Denied::RouteQueryFailed {
                ip,
                why: crate::printable(&why, 200),
            },
        })
    }

    /// Reads the host's facts with the default options ([`FactsOptions::default`]).
    pub fn gather() -> io::Result<Self> {
        Self::gather_with(&FactsOptions::default())
    }

    /// Reads every interface (each address is one of its own, and its network — the address under
    /// its netmask or on-link prefix length — a connected prefix, plus the peer of a
    /// point-to-point link as a host route; an address without a netmask counts as a host route; a
    /// non-contiguous netmask counts its leading ones, which only widens the prefix), the routing
    /// tables and rules, the DNS servers, (if `opts` says so) the public addresses, and the NAT64
    /// prefixes the DNS servers reveal ([`crate::nat64`]), then [`Self::assemble`]s them, with the
    /// kernel as the route oracle. Fails if the interfaces or the routing table cannot be read (on
    /// macOS, or the DNS configuration: see [`system_resolvers`]): a public-mode policy that does
    /// not know them cannot refuse what they name.
    pub fn gather_with(opts: &FactsOptions) -> io::Result<Self> {
        let (interface_prefixes, interface_addresses, loopback) = sys::interfaces()?;
        // The NAT64 prefixes the host's DNS64 reveals (process-wide; the first call asks).
        crate::nat64::ensure_discovered();
        let (routes, rules) = crate::routes::read_routing(&loopback)?;
        let links = crate::routes::read_links()?;
        let nexthops = if routes.iter().any(|r| r.nexthop != 0) {
            crate::routes::read_nexthops()?
        } else {
            Vec::new()
        };
        let internet_interfaces = crate::routes::internet_interfaces();
        let public = if opts.discover_public_addresses {
            // Addresses confirmed under another uplink (a new default gateway, a VPN that came
            // up) are not this one's: discovery runs again, and meanwhile they are not known.
            let table = RouteTable::with_rules(routes.clone(), rules.clone());
            #[cfg(target_os = "macos")]
            let uplink_signature = {
                // macOS: the routes' signature and the networks the configuration daemon says
                // the services are on (`uplink_signature` in here is the function above).
                let networks = macos_dns::network_signatures()?;
                move |t: &RouteTable, i: &[u32]| {
                    macos_uplink_signature(uplink_signature(t, i), &networks)
                }
            };
            crate::public::learned_on(uplink_signature(&table, &internet_interfaces))
        } else {
            crate::public::Learned::default()
        };
        Ok(Self::assemble(
            RawFacts {
                interface_prefixes,
                interface_addresses,
                routes,
                rules,
                resolvers: read_system_resolvers()?,
                public_addresses: public.addresses,
                public_confirmed: public.confirmed,
                public_via_nat64: public.via_nat64,
                links,
                internet_interfaces,
                nexthops,
                pppoe_sessions: crate::routes::pppoe_sessions(),
            },
            opts,
        )
        .with_route_oracle(Arc::new(crate::routes::KernelRoutes)))
    }

    /// The connected prefixes (interfaces and on-link routes), sorted.
    pub fn connected(&self) -> &[Prefix] {
        &self.connected
    }

    /// The host's own addresses (interfaces and public addresses), sorted.
    pub fn own_addresses(&self) -> &[IpAddr] {
        &self.own
    }

    /// The site prefixes around the own global IPv6 addresses, sorted.
    pub fn site_prefixes(&self) -> &[Prefix] {
        &self.site
    }

    /// The DNS servers the host uses, sorted.
    pub fn resolvers(&self) -> &[IpAddr] {
        &self.resolvers
    }

    /// The routing table.
    pub fn routes(&self) -> &RouteTable {
        &self.routes
    }

    /// Every prefix these facts refuse, flattened for a consumer that knows only connected prefixes
    /// and own addresses (the sandboxed witness broker, which cannot read the host itself): the
    /// connected and site prefixes, the prefixes of every route off the default path, of every
    /// route that delivers to this host and of every destination rule into another table, a host
    /// route for every DNS server, and what the NAT64 network-specific prefixes in force imply
    /// ([`crate::nat64::embedded_refusals`]).
    pub fn refused_prefixes(&self) -> Vec<Prefix> {
        let mut v = self.connected.clone();
        v.extend_from_slice(&self.site);
        v.extend(self.routes.off_default_prefixes());
        v.extend(self.resolvers.iter().map(|r| Prefix::host(*r)));
        // Under each NAT64 network-specific prefix in force, the IPv4 ranges refused here and
        // the non-global ones, embedded (the consumer may not know the prefix).
        let mut v4: Vec<Prefix> = v
            .iter()
            .map(Prefix::canonical_prefix)
            .filter(|p| p.addr.is_ipv4())
            .collect();
        v4.extend(
            self.own
                .iter()
                .map(|a| Prefix::host(crate::canonical_ip(*a)))
                .filter(|p| p.addr.is_ipv4()),
        );
        v.extend(crate::nat64::embedded_refusals(&v4));
        sorted(v)
    }

    /// When these facts were read.
    pub fn gathered_at(&self) -> Instant {
        self.gathered_at
    }
}

/// Files whose `nameserver` lines name DNS servers this host uses: the resolver's own, and the
/// upstream servers behind a local stub (systemd-resolved's, NetworkManager's).
pub const RESOLV_CONF_PATHS: &[&str] = &[
    "/etc/resolv.conf",
    "/run/systemd/resolve/resolv.conf",
    "/run/NetworkManager/no-stub-resolv.conf",
];

/// Every `nameserver` address in a `resolv.conf` (all of them, not glibc's first three; an IPv6
/// zone id is dropped).
pub fn parse_nameservers(text: &str) -> Vec<IpAddr> {
    text.lines()
        .filter_map(|l| {
            let mut words = l.split_whitespace();
            (words.next()? == "nameserver").then_some(())?;
            let w = words.next()?;
            w.split('%').next()?.parse::<IpAddr>().ok()
        })
        .collect()
}

/// The DNS servers of every file in [`RESOLV_CONF_PATHS`] that exists, sorted.
#[cfg(not(target_os = "macos"))]
pub fn system_resolvers() -> Vec<IpAddr> {
    sorted(
        RESOLV_CONF_PATHS
            .iter()
            .filter_map(|p| std::fs::read_to_string(p).ok())
            .flat_map(|t| parse_nameservers(&t))
            .collect(),
    )
}

/// The DNS servers for the facts: [`system_resolvers`], which cannot fail here.
#[cfg(not(target_os = "macos"))]
fn read_system_resolvers() -> io::Result<Vec<IpAddr>> {
    Ok(system_resolvers())
}

/// macOS: the DNS servers of every file in [`RESOLV_CONF_PATHS`] that exists, of every
/// per-domain resolver file in `/etc/resolver` (resolver(5)), and of every resolver the
/// configuration daemon knows (`scutil --dns`: a secondary interface's DHCP or RDNSS servers, a
/// VPN's supplemental and split-DNS resolvers, scoped resolvers), sorted; empty when they cannot
/// be read (the facts read then fails: [`HostFacts::gather_with`]). See `facts::macos_dns`.
#[cfg(target_os = "macos")]
pub fn system_resolvers() -> Vec<IpAddr> {
    read_system_resolvers().unwrap_or_default()
}

#[cfg(target_os = "macos")]
fn read_system_resolvers() -> io::Result<Vec<IpAddr>> {
    macos_dns::read().map(sorted)
}

/// macOS: where the DNS servers are read from, and how (review rounds 1 and 2).
///
/// - **Files**: `/etc/resolv.conf` (configd writes it from the primary resolvers) and every
///   regular file in `/etc/resolver`. Read as bytes, at most [`macos_dns::MAX_FILE`] (a bigger
///   file fails the read), invalid UTF-8 replaced (a stray byte in a comment does not hide the
///   file's servers). Each file is opened non-blocking and `fstat`ed: what is not a regular file
///   (a FIFO, a device, a directory) is skipped without being read. A file or directory that does
///   not exist has none; a symbolic link that loops (`ELOOP`) is skipped with a warning (the
///   configuration daemon, which reads these files for `scutil --dns`, cannot open it either, so
///   it names no resolver); any other error (a file this user may not read, such as a root-only
///   one the daemon reads as root: its servers would otherwise go unrefused) fails the read, its
///   message naming the file.
/// - **`nameserver` lines** (any case, leading blanks allowed): the word after it read by every
///   parser macOS uses for one: `getaddrinfo(AI_NUMERICHOST)` (libresolv, configd), which reads
///   `203.0.113.053` as decimal, `inet_aton` (`203.0.113.053` octal, `3405803829`, `0xcb007135`,
///   `10.1`), and the plain form with a zone dropped; every address any of them gives counts.
/// - **The configuration daemon** (SCDynamicStore): the `ServerAddresses` of every
///   `State:/Network/Service/<id>/DNS` key, of `State:/Network/Global/DNS`, and of every
///   `Setup:/Network/Service/<id>/DNS` key (the DNS servers set by hand for a service, which the
///   daemon gives a secondary service's scoped resolver without writing them to any `State:`
///   key; review round 2; a service that is not active adds servers that are refused needlessly,
///   never fewer). A session that cannot be opened, a key list that cannot be read, a value that
///   is not what configd writes (a dictionary whose `ServerAddresses` is an array of numeric
///   addresses), or a daemon that does not answer within [`macos_dns::CONFIGD_TIMEOUT`] fails the
///   read. Each request to the daemon is made on a thread of its own and waited for at most
///   [`macos_dns::CONFIGD_TIMEOUT`]: SCDynamicStore has no timeout of its own, and a stuck request
///   must not hold the facts read (and every connection waiting on it) for ever. Requests are not
///   serialised (callers that come at once each ask on their own thread); while four timed-out
///   requests have not returned, the next fails at once ([`macos_dns::Bounded`]).
/// - **Not read**: the resolver configuration the daemon publishes for the system's resolver
///   (`dns_configuration_copy`, what `scutil --dns` prints). Its layout is in configd's private
///   `dnsinfo.h`, not in the SDK, and it is a tree of raw pointers whose layout is no ABI promise:
///   misreading it is undefined behaviour, so no sound reader can be written against it. Its
///   sources (the keys above and `/etc/resolver`) are read instead; the real-host test checks
///   that every server `scutil --dns` lists is among them.
#[cfg(target_os = "macos")]
pub(crate) mod macos_dns {
    use std::ffi::CString;
    use std::io::{self, Read};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::os::unix::fs::OpenOptionsExt;
    use std::path::Path;

    use core_foundation::array::CFArray;
    use core_foundation::base::TCFType;
    use core_foundation::dictionary::CFDictionary;
    use core_foundation::propertylist::CFPropertyList;
    use core_foundation::string::CFString;
    use system_configuration::dynamic_store::SCDynamicStoreBuilder;

    /// The largest resolver file read; a resolver file is a few lines.
    pub(crate) const MAX_FILE: u64 = 1 << 20;

    /// Every DNS server macOS knows of (see the module doc), unsorted.
    pub(crate) fn read() -> io::Result<Vec<IpAddr>> {
        read_with(
            super::RESOLV_CONF_PATHS.iter().map(Path::new),
            Path::new("/etc/resolver"),
            configd_all,
        )
    }

    /// [`read`] from these files, this resolver directory, and this view of the configuration
    /// daemon (`(State: servers, Setup: servers)`).
    pub(crate) fn read_with<'a>(
        files: impl IntoIterator<Item = &'a Path>,
        resolver: &Path,
        configd: impl FnOnce() -> io::Result<(Vec<IpAddr>, Vec<IpAddr>)>,
    ) -> io::Result<Vec<IpAddr>> {
        let mut texts = Vec::new();
        for p in files {
            texts.extend(read_file(p)?);
        }
        texts.extend(resolver_dir(resolver)?);
        let mut v: Vec<IpAddr> = texts.iter().flat_map(|t| parse(t)).collect();
        let (state, setup) = configd()?;
        v.extend(state);
        v.extend(setup);
        Ok(v)
    }

    /// A resolver file's text: `None` when it does not exist or is not a regular file.
    pub(crate) fn read_file(path: &Path) -> io::Result<Option<String>> {
        // Non-blocking, so that a FIFO put in its place is not waited on before it is seen to be
        // one.
        let f = match std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(path)
        {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) if e.raw_os_error() == Some(libc::ELOOP) => {
                warn_once(path, &e);
                return Ok(None);
            }
            Err(e) => {
                return Err(io::Error::new(
                    e.kind(),
                    format!("the DNS resolver file {}: {e}", path.display()),
                ))
            }
        };
        if !f.metadata()?.is_file() {
            return Ok(None);
        }
        let mut b = Vec::new();
        f.take(MAX_FILE + 1).read_to_end(&mut b)?;
        if b.len() as u64 > MAX_FILE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "the DNS resolver file {} is larger than {MAX_FILE} bytes",
                    path.display()
                ),
            ));
        }
        Ok(Some(String::from_utf8_lossy(&b).into_owned()))
    }

    /// The text of every regular file in a resolver directory; none when it does not exist.
    pub(crate) fn resolver_dir(dir: &Path) -> io::Result<Vec<String>> {
        let entries = match std::fs::read_dir(dir) {
            Ok(d) => d,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => {
                return Err(io::Error::new(
                    e.kind(),
                    format!("the DNS resolver directory {}: {e}", dir.display()),
                ))
            }
        };
        let mut out = Vec::new();
        for e in entries {
            out.extend(read_file(&e?.path())?);
        }
        Ok(out)
    }

    /// Warns once per path about a resolver file that is skipped.
    fn warn_once(path: &Path, e: &io::Error) {
        static WARNED: std::sync::Mutex<Vec<std::path::PathBuf>> =
            std::sync::Mutex::new(Vec::new());
        let mut w = WARNED.lock().unwrap_or_else(|e| e.into_inner());
        if !w.iter().any(|p| p == path) && w.len() < 64 {
            w.push(path.to_path_buf());
            tracing::warn!(
                "network guard: skipping the DNS resolver file {}: {e} (the system cannot open \
                 it either, so it names no resolver)",
                path.display()
            );
        }
    }

    /// The servers of a resolver file's `nameserver` lines (see the module doc).
    pub(crate) fn parse(text: &str) -> Vec<IpAddr> {
        text.lines()
            .filter_map(|l| {
                let mut words = l.split_whitespace();
                words
                    .next()?
                    .eq_ignore_ascii_case("nameserver")
                    .then_some(())?;
                words.next()
            })
            .flat_map(numeric)
            .collect()
    }

    extern "C" {
        // <arpa/inet.h>; the libc crate does not bind it.
        fn inet_aton(cp: *const libc::c_char, inp: *mut libc::in_addr) -> libc::c_int;
    }

    /// Every address a numeric host string names to any of macOS's parsers (see the module doc),
    /// sorted, without duplicates; empty when none reads it.
    pub(crate) fn numeric(word: &str) -> Vec<IpAddr> {
        // What C reads of it: up to a NUL.
        let word = word.split('\0').next().unwrap_or_default();
        let mut v = Vec::new();
        if word.is_empty() {
            return v;
        }
        if let Some(Ok(a)) = word.split('%').next().map(str::parse::<IpAddr>) {
            v.push(a);
        }
        let Ok(c) = CString::new(word) else {
            return v;
        };
        // SAFETY: a zeroed in_addr is valid; `c` is NUL-terminated.
        let mut a: libc::in_addr = unsafe { std::mem::zeroed() };
        if unsafe { inet_aton(c.as_ptr(), &mut a) } != 0 {
            v.push(IpAddr::V4(Ipv4Addr::from(u32::from_be(a.s_addr))));
        }
        // SAFETY: a zeroed addrinfo is valid hints (no pointers set).
        let mut hints: libc::addrinfo = unsafe { std::mem::zeroed() };
        hints.ai_flags = libc::AI_NUMERICHOST;
        hints.ai_family = libc::AF_UNSPEC;
        hints.ai_socktype = libc::SOCK_DGRAM;
        let mut res: *mut libc::addrinfo = std::ptr::null_mut();
        // SAFETY: `c` is NUL-terminated, `hints` valid, `res` receives a list freed below.
        if unsafe { libc::getaddrinfo(c.as_ptr(), std::ptr::null(), &hints, &mut res) } == 0 {
            let mut cur = res;
            while !cur.is_null() {
                // SAFETY: a node of the list getaddrinfo returned, alive until freeaddrinfo.
                let ai = unsafe { &*cur };
                cur = ai.ai_next;
                if ai.ai_addr.is_null() {
                    continue;
                }
                let len = ai.ai_addrlen as usize;
                // SAFETY: `ai_addr` holds `ai_addrlen` bytes.
                let sa = unsafe { std::slice::from_raw_parts(ai.ai_addr.cast::<u8>(), len) };
                match ai.ai_family {
                    libc::AF_INET => {
                        let o = std::mem::offset_of!(libc::sockaddr_in, sin_addr);
                        if let Some(b) = sa.get(o..o + 4) {
                            let b: [u8; 4] = b.try_into().unwrap_or_default();
                            v.push(IpAddr::V4(Ipv4Addr::from(b)));
                        }
                    }
                    libc::AF_INET6 => {
                        let o = std::mem::offset_of!(libc::sockaddr_in6, sin6_addr);
                        if let Some(b) = sa.get(o..o + 16) {
                            let b: [u8; 16] = b.try_into().unwrap_or_default();
                            v.push(IpAddr::V6(Ipv6Addr::from(b)));
                        }
                    }
                    _ => {}
                }
            }
            // SAFETY: `res` came from a successful getaddrinfo and is freed once.
            unsafe { libc::freeaddrinfo(res) };
        }
        v.sort();
        v.dedup();
        v
    }

    fn malformed(what: &str) -> io::Error {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("the system configuration holds a value it would not write at {what}"),
        )
    }

    /// The configuration daemon's DNS keys read for their servers (patterns of
    /// `SCDynamicStoreCopyKeyList`): the active services' and the global resolvers.
    pub(crate) const STATE_DNS_KEYS: &[&str] = &[
        "State:/Network/Service/[^/]+/DNS",
        "State:/Network/Global/DNS",
    ];

    /// The DNS servers set by hand for each service (review round 2).
    pub(crate) const SETUP_DNS_KEYS: &[&str] = &["Setup:/Network/Service/[^/]+/DNS"];

    /// How long the configuration daemon may take to answer (see the module doc).
    pub(crate) const CONFIGD_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

    /// The keys whose `NetworkSignature` identifies the network a service is on.
    pub(crate) const NETWORK_KEYS: &[&str] = &["State:/Network/Service/[^/]+/IPv[46]"];

    /// The configuration daemon's identity of the network each active service is on: every
    /// `NetworkSignature` of a [`NETWORK_KEYS`] key, as `key=signature` (a key without one, a VPN
    /// service's, has none); a signature that is not a string fails the read (see
    /// [`super::macos_uplink_signature`]).
    pub(crate) fn network_signatures() -> io::Result<Vec<String>> {
        ASKING.run(CONFIGD_TIMEOUT, || {
            let store = session()?;
            signatures_of(keys(&store, NETWORK_KEYS)?.into_iter().map(|k| {
                let v = store.get(k.as_str());
                (k, v)
            }))
        })
    }

    /// The `key=signature` of each value that has one, by key (`None`: the key is gone): an
    /// error naming the key for a value configd would not write ([`network_signature`]).
    pub(crate) fn signatures_of(
        values: impl IntoIterator<Item = (String, Option<CFPropertyList>)>,
    ) -> io::Result<Vec<String>> {
        let mut out = Vec::new();
        for (key, value) in values {
            let Some(value) = value else {
                continue;
            };
            if let Some(sig) = network_signature(&value).ok_or_else(|| malformed(&key))? {
                out.push(format!("{key}={sig}"));
            }
        }
        Ok(out)
    }

    /// A service's `NetworkSignature`: `Some(None)` without one, `None` for a value configd would
    /// not write (not a dictionary, or a signature that is not a string).
    pub(crate) fn network_signature(value: &CFPropertyList) -> Option<Option<String>> {
        let dict = value.downcast::<CFDictionary>()?;
        let key = CFString::from_static_string("NetworkSignature");
        let Some(sig) = dict.find(key.as_CFTypeRef()) else {
            return Some(None);
        };
        // SAFETY: a value of a property-list dictionary is a property list, retained here.
        let sig = unsafe { CFPropertyList::wrap_under_get_rule(*sig) }.downcast::<CFString>()?;
        Some(Some(sig.to_string()))
    }

    /// Calls to the configuration daemon: at most four outstanding (see [`Bounded`]).
    static ASKING: Bounded = Bounded::new("the system configuration daemon", 4);

    fn session() -> io::Result<system_configuration::dynamic_store::SCDynamicStore> {
        SCDynamicStoreBuilder::new("zkminer-netguard")
            .build()
            .ok_or_else(|| io::Error::other("could not reach the system configuration daemon"))
    }

    fn keys(
        store: &system_configuration::dynamic_store::SCDynamicStore,
        patterns: &[&str],
    ) -> io::Result<Vec<String>> {
        let mut keys = Vec::new();
        for pattern in patterns {
            let list = store
                .get_keys(*pattern)
                .ok_or_else(|| io::Error::other("could not list the system's network settings"))?;
            keys.extend(list.iter().map(|k| k.to_string()));
        }
        Ok(keys)
    }

    /// The servers of the daemon's [`STATE_DNS_KEYS`] (see the module doc).
    #[cfg(test)]
    pub(crate) fn configd() -> io::Result<Vec<IpAddr>> {
        configd_all().map(|(state, _)| state)
    }

    /// The servers of the daemon's [`STATE_DNS_KEYS`] and of its [`SETUP_DNS_KEYS`], from one
    /// session, asked on a thread of its own within [`CONFIGD_TIMEOUT`].
    pub(crate) fn configd_all() -> io::Result<(Vec<IpAddr>, Vec<IpAddr>)> {
        ASKING.run(CONFIGD_TIMEOUT, || {
            let store = session()?;
            let servers = |patterns: &[&str]| -> io::Result<Vec<IpAddr>> {
                // A key gone since it was listed (a service went down) has no servers any more.
                servers_of(keys(&store, patterns)?.into_iter().map(|k| {
                    let v = store.get(k.as_str());
                    (k, v)
                }))
            };
            Ok((servers(STATE_DNS_KEYS)?, servers(SETUP_DNS_KEYS)?))
        })
    }

    /// The servers of the daemon's DNS values, by key (`None`: the key is gone): an error naming
    /// the key for a value configd would not write ([`server_addresses`]).
    pub(crate) fn servers_of(
        values: impl IntoIterator<Item = (String, Option<CFPropertyList>)>,
    ) -> io::Result<Vec<IpAddr>> {
        let mut out = Vec::new();
        for (key, value) in values {
            let Some(value) = value else {
                continue;
            };
            out.extend(server_addresses(&value).ok_or_else(|| malformed(&key))?);
        }
        Ok(out)
    }

    /// The addresses of a DNS dictionary's `ServerAddresses` (none without one); `None` when the
    /// value is not a dictionary, `ServerAddresses` is not an array of strings, or a string names
    /// no address.
    pub(crate) fn server_addresses(value: &CFPropertyList) -> Option<Vec<IpAddr>> {
        let dict = value.downcast::<CFDictionary>()?;
        let key = CFString::from_static_string("ServerAddresses");
        let Some(list) = dict.find(key.as_CFTypeRef()) else {
            return Some(Vec::new());
        };
        // SAFETY: a value of a property-list dictionary is a property list, retained here.
        let list = unsafe { CFPropertyList::wrap_under_get_rule(*list) }.downcast::<CFArray>()?;
        let mut out = Vec::new();
        for item in list.iter() {
            // SAFETY: an element of a property-list array is a property list, retained here.
            let s = unsafe { CFPropertyList::wrap_under_get_rule(*item) }.downcast::<CFString>()?;
            let a = numeric(&s.to_string());
            if a.is_empty() {
                return None;
            }
            out.extend(a);
        }
        Some(out)
    }

    /// A call that may block for ever (a request to a daemon), made on a thread of its own and
    /// waited for at most a timeout. A call that timed out is abandoned (its thread finishes on
    /// its own, if ever); while `max` abandoned calls have not returned, the next call fails at
    /// once rather than leave another thread behind (review round 2, cross-3). Calls that have
    /// not timed out are not limited: callers that come at once (the facts re-read, which runs
    /// one at a time, and public-address and NAT64 discovery, which read the DNS servers on
    /// threads of their own) each run on a thread of their own, concurrently. The count of
    /// abandoned calls can be one too high for a moment (a call that returned just as it timed
    /// out), which refuses sooner, never later.
    pub(crate) struct Bounded {
        what: &'static str,
        max: usize,
        abandoned: std::sync::atomic::AtomicUsize,
    }

    impl Bounded {
        pub(crate) const fn new(what: &'static str, max: usize) -> Self {
            Bounded {
                what,
                max,
                abandoned: std::sync::atomic::AtomicUsize::new(0),
            }
        }

        /// How many abandoned calls have not returned (tests).
        #[cfg(test)]
        pub(crate) fn abandoned_now(&self) -> usize {
            self.abandoned.load(std::sync::atomic::Ordering::Acquire)
        }

        /// `f`'s result, or an error when it takes longer than `timeout` or `max` abandoned calls
        /// have not returned yet.
        pub(crate) fn run<T: Send + 'static>(
            &'static self,
            timeout: std::time::Duration,
            f: impl FnOnce() -> io::Result<T> + Send + 'static,
        ) -> io::Result<T> {
            use std::sync::atomic::{AtomicU8, Ordering};
            use std::sync::Arc;
            const RUNNING: u8 = 0;
            const ABANDONED: u8 = 1;
            const DONE: u8 = 2;
            if self.abandoned.load(Ordering::Acquire) >= self.max {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("{} has not answered earlier requests", self.what),
                ));
            }
            let state = Arc::new(AtomicU8::new(RUNNING));
            let (tx, rx) = std::sync::mpsc::sync_channel(1);
            let theirs = state.clone();
            std::thread::Builder::new()
                .name("netguard-configd".into())
                .spawn(move || {
                    let r = f();
                    let _ = tx.send(r);
                    if theirs
                        .compare_exchange(RUNNING, DONE, Ordering::AcqRel, Ordering::Acquire)
                        .is_err()
                    {
                        // Abandoned by its caller: no longer outstanding.
                        self.abandoned.fetch_sub(1, Ordering::AcqRel);
                    }
                })?;
            match rx.recv_timeout(timeout) {
                Ok(r) => r,
                Err(_) => {
                    // Counted before it is marked abandoned, so the thread, which uncounts it once
                    // it finds it abandoned, never uncounts it first (the count wrapped below zero
                    // for a moment and refused calls with none outstanding: review round 3,
                    // bypass-4).
                    self.abandoned.fetch_add(1, Ordering::AcqRel);
                    if state
                        .compare_exchange(RUNNING, ABANDONED, Ordering::AcqRel, Ordering::Acquire)
                        .is_ok()
                    {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            format!("{} did not answer within {timeout:?}", self.what),
                        ));
                    }
                    // It returned just now: not abandoned after all.
                    self.abandoned.fetch_sub(1, Ordering::AcqRel);
                    rx.recv()
                        .unwrap_or_else(|_| Err(io::Error::other("the call was lost")))
                }
            }
        }
    }
}

#[cfg(unix)]
mod sys {
    use std::io;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use crate::ip::Prefix;

    /// `(connected prefixes, own addresses, loopback interface indexes)`.
    pub(super) fn interfaces() -> io::Result<(Vec<Prefix>, Vec<IpAddr>, Vec<u32>)> {
        struct List(*mut libc::ifaddrs);
        impl Drop for List {
            fn drop(&mut self) {
                if !self.0.is_null() {
                    // SAFETY: the pointer came from a successful getifaddrs and is freed exactly
                    // once.
                    unsafe { libc::freeifaddrs(self.0) };
                }
            }
        }
        let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
        // SAFETY: getifaddrs writes a list head (or null) into `head`; `List` frees it.
        if unsafe { libc::getifaddrs(&mut head) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let list = List(head);
        let mut connected = Vec::new();
        let mut own = Vec::new();
        let mut loopback = Vec::new();
        let mut cur = list.0;
        while !cur.is_null() {
            // SAFETY: `cur` is a non-null node of the list getifaddrs returned, alive until `list`
            // drops.
            let ifa = unsafe { &*cur };
            cur = ifa.ifa_next;
            if ifa.ifa_flags & (libc::IFF_LOOPBACK as libc::c_uint) != 0 && !ifa.ifa_name.is_null()
            {
                // SAFETY: a live node's name is a NUL-terminated string.
                let index = unsafe { libc::if_nametoindex(ifa.ifa_name) };
                if index != 0 && !loopback.contains(&index) {
                    loopback.push(index);
                }
            }
            // SAFETY: the sockaddr pointers of a live ifaddrs node are null or valid for their
            // family.
            let Some(addr) = (unsafe { sockaddr_ip(ifa.ifa_addr) }) else {
                continue;
            };
            let width = if addr.is_ipv4() { 32 } else { 128 };
            // SAFETY: as above; the netmask is read in the address's family.
            let len = unsafe { sockaddr_mask(ifa.ifa_netmask, addr.is_ipv4()) }.unwrap_or(width);
            own.push(addr);
            connected.push(Prefix::new(addr, len));
            if ifa.ifa_flags & (libc::IFF_POINTOPOINT as libc::c_uint) != 0 {
                // SAFETY: on a point-to-point interface the union holds the destination address.
                if let Some(peer) = unsafe { sockaddr_ip(peer_ptr(ifa)) } {
                    connected.push(Prefix::host(peer));
                }
            }
        }
        Ok((connected, own, loopback))
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn peer_ptr(ifa: &libc::ifaddrs) -> *const libc::sockaddr {
        ifa.ifa_ifu
    }

    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    fn peer_ptr(ifa: &libc::ifaddrs) -> *const libc::sockaddr {
        ifa.ifa_dstaddr
    }

    /// # Safety
    /// `sa` is null or points to a sockaddr valid for its `sa_family`.
    #[cfg(not(target_os = "macos"))]
    unsafe fn sockaddr_ip(sa: *const libc::sockaddr) -> Option<IpAddr> {
        if sa.is_null() {
            return None;
        }
        match i32::from((*sa).sa_family) {
            libc::AF_INET => {
                let sin = &*(sa as *const libc::sockaddr_in);
                Some(IpAddr::V4(Ipv4Addr::from(u32::from_be(
                    sin.sin_addr.s_addr,
                ))))
            }
            libc::AF_INET6 => {
                let sin6 = &*(sa as *const libc::sockaddr_in6);
                Some(IpAddr::V6(Ipv6Addr::from(sin6.sin6_addr.s6_addr)))
            }
            _ => None,
        }
    }

    /// macOS: the address of an IP sockaddr, read within its `sa_len` bytes (`getifaddrs` copies
    /// each sockaddr by its `sa_len`, and gives a `utun`'s destination address `sa_len` 0); an IP
    /// sockaddr too short for its address names none (review round 1, parse-4).
    ///
    /// # Safety
    /// `sa` is null or points to a sockaddr valid for its `sa_len` bytes.
    #[cfg(target_os = "macos")]
    pub(super) unsafe fn sockaddr_ip(sa: *const libc::sockaddr) -> Option<IpAddr> {
        use std::mem::offset_of;
        if sa.is_null() {
            return None;
        }
        let b = std::slice::from_raw_parts(sa.cast::<u8>(), usize::from((*sa).sa_len));
        match i32::from(*b.get(1)?) {
            libc::AF_INET => {
                let o = offset_of!(libc::sockaddr_in, sin_addr);
                let a: [u8; 4] = b.get(o..o + 4)?.try_into().ok()?;
                Some(IpAddr::V4(Ipv4Addr::from(a)))
            }
            libc::AF_INET6 => {
                let o = offset_of!(libc::sockaddr_in6, sin6_addr);
                let a: [u8; 16] = b.get(o..o + 16)?.try_into().ok()?;
                Some(IpAddr::V6(Ipv6Addr::from(a)))
            }
            _ => None,
        }
    }

    /// The prefix length of a netmask, read in the address's family (some systems leave the
    /// netmask's own `sa_family` zero).
    ///
    /// # Safety
    /// `sa` is null or points to a sockaddr_in (`v4`) or sockaddr_in6.
    #[cfg(not(target_os = "macos"))]
    unsafe fn sockaddr_mask(sa: *const libc::sockaddr, v4: bool) -> Option<u8> {
        if sa.is_null() {
            return None;
        }
        if v4 {
            let sin = &*(sa as *const libc::sockaddr_in);
            Some(u32::from_be(sin.sin_addr.s_addr).leading_ones() as u8)
        } else {
            let sin6 = &*(sa as *const libc::sockaddr_in6);
            Some(u128::from_be_bytes(sin6.sin6_addr.s6_addr).leading_ones() as u8)
        }
    }

    /// macOS: the prefix length of a netmask, read in the address's family up to its `sa_len`.
    /// The kernel trims a netmask's trailing zero bytes (`sa_len` 7 for 255.255.255.0, 0 for an
    /// all-zero mask) and `getifaddrs` copies `sa_len` bytes, so what lies past them is not the
    /// mask's (the next sockaddr's, or past the list): those bytes read as zero.
    ///
    /// # Safety
    /// `sa` is null or points to a sockaddr valid for its `sa_len` bytes.
    #[cfg(target_os = "macos")]
    pub(super) unsafe fn sockaddr_mask(sa: *const libc::sockaddr, v4: bool) -> Option<u8> {
        use std::mem::offset_of;
        if sa.is_null() {
            return None;
        }
        let bytes = std::slice::from_raw_parts(sa.cast::<u8>(), usize::from((*sa).sa_len));
        let (off, width) = if v4 {
            (offset_of!(libc::sockaddr_in, sin_addr), 4)
        } else {
            (offset_of!(libc::sockaddr_in6, sin6_addr), 16)
        };
        let mut m = [0u8; 16];
        for (i, b) in m[..width].iter_mut().enumerate() {
            *b = bytes.get(off + i).copied().unwrap_or(0);
        }
        Some(if v4 {
            u32::from_be_bytes([m[0], m[1], m[2], m[3]]).leading_ones() as u8
        } else {
            u128::from_be_bytes(m).leading_ones() as u8
        })
    }
}

#[cfg(windows)]
mod sys {
    use std::io;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use windows_sys::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_SUCCESS};
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetAdaptersAddresses, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER,
        GAA_FLAG_SKIP_MULTICAST, IP_ADAPTER_ADDRESSES_LH,
    };
    use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC, SOCKET_ADDRESS};

    use crate::ip::Prefix;

    /// Every unicast address of every adapter, with its on-link prefix length (no loopback
    /// indexes: routes are not read on Windows).
    pub(super) fn interfaces() -> io::Result<(Vec<Prefix>, Vec<IpAddr>, Vec<u32>)> {
        let flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
        // The documented way: start at 15 KB and grow to what the call asks for, a few times
        // (adapters can appear between calls).
        let mut size: u32 = 15 * 1024;
        let mut buf: Vec<u64> = Vec::new();
        let mut done = false;
        for _ in 0..4 {
            // u64 elements: the list must be 8-byte aligned.
            buf = vec![0u64; (size as usize).div_ceil(8)];
            // SAFETY: `buf` holds at least `size` writable bytes, suitably aligned.
            let rc = unsafe {
                GetAdaptersAddresses(
                    u32::from(AF_UNSPEC),
                    flags,
                    std::ptr::null(),
                    buf.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>(),
                    &mut size,
                )
            };
            if rc == ERROR_SUCCESS {
                done = true;
                break;
            }
            if rc != ERROR_BUFFER_OVERFLOW {
                return Err(io::Error::from_raw_os_error(rc as i32));
            }
        }
        if !done {
            return Err(io::Error::other(
                "GetAdaptersAddresses kept asking for a larger buffer",
            ));
        }
        let mut connected = Vec::new();
        let mut own = Vec::new();
        let mut adapter = buf.as_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
        while !adapter.is_null() {
            // SAFETY: a node of the list GetAdaptersAddresses wrote into `buf`, alive while `buf`
            // is.
            let a = unsafe { &*adapter };
            let mut unicast = a.FirstUnicastAddress;
            while !unicast.is_null() {
                // SAFETY: as above.
                let u = unsafe { &*unicast };
                // SAFETY: the address of a live unicast node.
                if let Some(ip) = unsafe { socket_address_ip(&u.Address) } {
                    own.push(ip);
                    connected.push(Prefix::new(ip, u.OnLinkPrefixLength));
                }
                unicast = u.Next;
            }
            adapter = a.Next;
        }
        Ok((connected, own, Vec::new()))
    }

    /// The IP of a SOCKET_ADDRESS, read from its bytes (family at 0; IPv4 at 4..8; IPv6 at 8..24).
    ///
    /// # Safety
    /// `sa.lpSockaddr` is null or points to `sa.iSockaddrLength` readable bytes.
    unsafe fn socket_address_ip(sa: &SOCKET_ADDRESS) -> Option<IpAddr> {
        if sa.lpSockaddr.is_null() || sa.iSockaddrLength < 2 {
            return None;
        }
        let bytes =
            std::slice::from_raw_parts(sa.lpSockaddr.cast::<u8>(), sa.iSockaddrLength as usize);
        let family = u16::from_ne_bytes([bytes[0], bytes[1]]);
        if family == AF_INET && bytes.len() >= 8 {
            let o: [u8; 4] = bytes[4..8].try_into().ok()?;
            Some(IpAddr::V4(Ipv4Addr::from(o)))
        } else if family == AF_INET6 && bytes.len() >= 24 {
            let o: [u8; 16] = bytes[8..24].try_into().ok()?;
            Some(IpAddr::V6(Ipv6Addr::from(o)))
        } else {
            None
        }
    }
}

#[cfg(not(any(unix, windows)))]
mod sys {
    use std::io;
    use std::net::IpAddr;

    use crate::ip::Prefix;

    pub(super) fn interfaces() -> io::Result<(Vec<Prefix>, Vec<IpAddr>, Vec<u32>)> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "reading the host's interfaces is not supported on this platform",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn offline() -> FactsOptions {
        FactsOptions {
            discover_public_addresses: false,
            ..FactsOptions::default()
        }
    }

    #[test]
    fn gathered_facts_are_well_formed() {
        let f = HostFacts::gather_with(&offline()).expect("read the interfaces");
        for p in f.connected() {
            let w = if p.addr.is_ipv4() { 32 } else { 128 };
            assert!(p.len <= w, "{p:?}");
            assert_eq!(Prefix::new(p.addr, p.len), *p, "{p:?} is a network address");
        }
        // Every own address is inside a connected prefix (its own network).
        for a in f.own_addresses() {
            assert!(f.connected().iter().any(|p| p.contains(*a)), "{a}");
        }
        // Loopback, where the namespace has it up, is both.
        if f.own_addresses().contains(&"127.0.0.1".parse().unwrap()) {
            assert!(f
                .connected()
                .iter()
                .any(|p| p.contains("127.0.0.1".parse().unwrap())));
        }
        let mut sorted = f.connected().to_vec();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted, f.connected());
        // The routing table read too, and every on-link route is a connected prefix.
        for p in f.routes().on_link_prefixes() {
            assert!(f.connected().contains(&p), "{p}");
        }
        assert_eq!(f.resolvers(), system_resolvers().as_slice());
    }

    fn p(s: &str) -> Prefix {
        s.parse().unwrap()
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    /// Review r1 (fetch F1, broker F1 / PoC t3): a DHCPv6 address is a /128, and the on-link /64
    /// is a route; an IPv4 /32 address has its subnet as a route. Both are connected prefixes now.
    #[test]
    fn on_link_routes_are_connected_prefixes() {
        let raw = RawFacts {
            interface_prefixes: vec![p("2606:4700:1::5/128"), p("203.0.113.9/32")],
            interface_addresses: vec![ip("2606:4700:1::5"), ip("203.0.113.9")],
            routes: vec![
                Route::on_link(p("2606:4700:1::/64"), 2),
                Route::on_link(p("203.0.113.0/24"), 2),
                Route::via(p("::/0"), ip("fe80::1"), 2),
                Route::via(p("0.0.0.0/0"), ip("203.0.113.1"), 2),
            ],
            ..RawFacts::default()
        };
        let f = HostFacts::assemble(raw, &offline());
        assert!(f.connected().contains(&p("2606:4700:1::/64")));
        assert!(f.connected().contains(&p("203.0.113.0/24")));
        assert!(!f.connected().iter().any(|c| c.len == 0));
    }

    #[test]
    fn site_prefixes_enclose_own_global_ipv6_addresses() {
        let raw = RawFacts {
            interface_addresses: vec![
                ip("2606:a300:9024:184:be24:11ff:fe33:f724"),
                ip("fe80::1"),
                ip("192.168.1.33"),
                ip("::1"),
            ],
            public_addresses: vec![ip("2a01:4f8:1:2::9"), ip("10.0.0.1")],
            public_confirmed: vec![ip("2a01:4f8:1:2::9")],
            ..RawFacts::default()
        };
        // The default: a /32, what an organisation usually holds.
        let f = HostFacts::assemble(raw.clone(), &offline());
        assert_eq!(
            f.site_prefixes(),
            &[p("2606:a300::/32"), p("2a01:4f8::/32")]
        );
        // A public address is an own address; a non-global "public" answer is dropped.
        assert!(f.own_addresses().contains(&ip("2a01:4f8:1:2::9")));
        assert!(!f.own_addresses().contains(&ip("10.0.0.1")));
        let f56 = HostFacts::assemble(
            raw.clone(),
            &FactsOptions {
                ipv6_site_prefix_len: 56,
                ..offline()
            },
        );
        assert_eq!(
            f56.site_prefixes(),
            &[p("2606:a300:9024:100::/56"), p("2a01:4f8:1::/56")]
        );
        let f48 = HostFacts::assemble(
            raw.clone(),
            &FactsOptions {
                ipv6_site_prefix_len: 48,
                ..offline()
            },
        );
        assert_eq!(
            f48.site_prefixes(),
            &[p("2606:a300:9024::/48"), p("2a01:4f8:1::/48")]
        );
        let f16 = HostFacts::assemble(
            raw,
            &FactsOptions {
                ipv6_site_prefix_len: 16,
                ..offline()
            },
        );
        assert_eq!(f16.site_prefixes(), &[p("2606::/16"), p("2a01::/16")]);
        assert_eq!(
            site_prefixes(&[ip("2606:a300::1")], 99),
            vec![p("2606:a300::/64")]
        );
        assert!(FactsOptions::default().validate().is_ok());
        for bad in [15u8, 65, 0, 128] {
            let o = FactsOptions {
                ipv6_site_prefix_len: bad,
                ..offline()
            };
            assert!(o.validate().is_err(), "{bad}");
        }
    }

    /// Review r2 R2-NG-7 (PoC `a_forged_v6_reflector_answer_refuses_a_site`), inverted: one
    /// reflector's answer (or a forged one) is refused as an own address, and gives no site, so
    /// the rest of that /48 and an operator's role entry in it stay admitted. An answer both
    /// reflectors gave, or one inside an interface address's site, gives its site.
    #[test]
    fn an_unconfirmed_public_answer_refuses_one_address_not_a_site() {
        use crate::{admit, admit_prefix, NetMode};
        let forged = ip("2606:4700:4700::64");
        let raw = RawFacts {
            interface_addresses: vec![ip("192.168.1.33")],
            interface_prefixes: vec![p("192.168.1.0/24")],
            public_addresses: vec![forged],
            ..Default::default()
        };
        let opts = FactsOptions {
            discover_public_addresses: false,
            ipv6_site_prefix_len: 48,
            ..FactsOptions::default()
        };
        let f = HostFacts::assemble(raw.clone(), &opts);
        assert!(f.site_prefixes().is_empty(), "{:?}", f.site_prefixes());
        assert!(admit(NetMode::Public, forged, &f, &[]).is_err());
        assert_eq!(
            admit(NetMode::Public, ip("2606:4700:4700::1111"), &f, &[]),
            Ok(())
        );
        assert_eq!(
            admit_prefix(NetMode::Public, p("2606:4700:4700:1::/64"), &f, &[]),
            Ok(())
        );
        // Confirmed by both reflectors: the site is refused.
        let f = HostFacts::assemble(
            RawFacts {
                public_confirmed: vec![forged],
                ..raw.clone()
            },
            &opts,
        );
        assert_eq!(f.site_prefixes(), &[p("2606:4700:4700::/48")]);
        // In an interface address's site: that site, from the interface address.
        let f = HostFacts::assemble(
            RawFacts {
                interface_addresses: vec![ip("2606:4700:4700:9::2")],
                ..raw
            },
            &opts,
        );
        assert_eq!(f.site_prefixes(), &[p("2606:4700:4700::/48")]);
    }

    #[test]
    fn nameservers_parse_from_every_resolv_conf_line() {
        let text =
            "# comment\nnameserver 1.1.1.1\nnameserver 9.9.9.9\n  nameserver   2606:a300:c::7d\n\
                    nameserver 2606:a300:c::7e\nnameserver fe80::1%eth0\nsearch .\noptions edns0\n\
                    nameserver bogus\n";
        assert_eq!(
            parse_nameservers(text),
            vec![
                ip("1.1.1.1"),
                ip("9.9.9.9"),
                ip("2606:a300:c::7d"),
                ip("2606:a300:c::7e"),
                ip("fe80::1")
            ]
        );
    }

    /// parse-4: an IP sockaddr is read within its `sa_len`: one too short for its address (here
    /// `sa_len` 4 with an address's bytes after it, another sockaddr's) names none; whole ones
    /// read as before.
    #[cfg(target_os = "macos")]
    #[test]
    fn ip_sockaddrs_are_read_within_their_length() {
        let v4 = |len: u8| {
            let mut b = [0u8; 16];
            b[0] = len;
            b[1] = libc::AF_INET as u8;
            b[4..8].copy_from_slice(&[203, 0, 113, 9]);
            // SAFETY: `b` holds 16 bytes, at least `len`.
            unsafe { sys::sockaddr_ip(b.as_ptr().cast()) }
        };
        assert_eq!(v4(16), Some(ip("203.0.113.9")));
        assert_eq!(v4(8), Some(ip("203.0.113.9")));
        for len in [0, 1, 2, 4, 7] {
            assert_eq!(v4(len), None, "sa_len {len}");
        }
        let v6 = |len: u8| {
            let mut b = [0u8; 28];
            b[0] = len;
            b[1] = libc::AF_INET6 as u8;
            b[8..24].copy_from_slice(
                &"2001:db8::9"
                    .parse::<std::net::Ipv6Addr>()
                    .unwrap()
                    .octets(),
            );
            // SAFETY: `b` holds 28 bytes, at least `len`.
            unsafe { sys::sockaddr_ip(b.as_ptr().cast()) }
        };
        assert_eq!(v6(28), Some(ip("2001:db8::9")));
        assert_eq!(v6(24), Some(ip("2001:db8::9")));
        for len in [0, 8, 16, 23] {
            assert_eq!(v6(len), None, "sa_len {len}");
        }
        // SAFETY: null is allowed.
        assert_eq!(unsafe { sys::sockaddr_ip(std::ptr::null()) }, None);
    }

    /// parse-2: nameserver words as macOS's parsers read them, every reading counted; what none
    /// reads names nothing.
    #[cfg(target_os = "macos")]
    #[test]
    fn macos_reads_nameservers_as_its_resolvers_do() {
        use super::macos_dns::{numeric, parse};
        let ips = |v: &[&str]| v.iter().map(|a| ip(a)).collect::<Vec<_>>();
        // getaddrinfo reads 053 as decimal, inet_aton as octal: both count.
        assert_eq!(
            numeric("203.0.113.053"),
            ips(&["203.0.113.43", "203.0.113.53"])
        );
        assert_eq!(numeric("3405803829"), ips(&["203.0.113.53"]));
        assert_eq!(numeric("0xcb007135"), ips(&["203.0.113.53"]));
        assert_eq!(numeric("10.1"), ips(&["10.0.0.1"]));
        assert_eq!(numeric("0x7f.1"), ips(&["127.0.0.1"]));
        assert_eq!(numeric("fe80::1%en0"), ips(&["fe80::1"]));
        assert_eq!(numeric("fe80::1%nosuchif9"), ips(&["fe80::1"]));
        assert_eq!(numeric("::ffff:1.2.3.4"), ips(&["::ffff:1.2.3.4"]));
        assert_eq!(numeric("1.2.3.4\0junk"), ips(&["1.2.3.4"]));
        for none in [
            "",
            "bogus",
            "[2001:db8::1]",
            "203.0.113.53.53",
            "203.0.113.53:53",
            "1.2.3.4x",
            "\0",
        ] {
            assert_eq!(numeric(none), Vec::<IpAddr>::new(), "{none:?}");
        }
        let text = "# caf\u{fffd}\nnameserver 203.0.113.053\n  NameServer\t3405803829 # c\n\
                    nameserver\nnameserver bogus\nsearch x\nnameserver 2001:db8::53\n";
        assert_eq!(
            parse(text),
            ips(&[
                "203.0.113.43",
                "203.0.113.53",
                "203.0.113.53",
                "2001:db8::53"
            ])
        );
        // Everything the resolv.conf parser reads, this one reads too.
        let linux = "# comment\nnameserver 1.1.1.1\n  nameserver   2606:a300:c::7d\n\
                     nameserver fe80::1%eth0\nnameserver bogus\n";
        for a in parse_nameservers(linux) {
            assert!(parse(linux).contains(&a), "{a}");
        }
    }

    /// parse-2: resolver files are read as bytes (a non-UTF-8 byte does not hide a file's
    /// servers), up to a size; what is not a regular file is skipped without blocking; a missing
    /// file or directory has none; any other error fails the read.
    #[cfg(target_os = "macos")]
    #[test]
    fn macos_resolver_files_are_read_strictly() {
        use super::macos_dns::{parse, read_file, resolver_dir, MAX_FILE};
        let dir = std::env::temp_dir().join(format!("zkminer-resolver-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        std::fs::write(
            dir.join("example.com"),
            b"# caf\xe9\nnameserver 203.0.113.53\n",
        )
        .unwrap();
        std::fs::write(dir.join("other"), b"nameserver 0xcb007136\n").unwrap();
        let fifo = std::ffi::CString::new(dir.join("fifo").to_str().unwrap()).unwrap();
        // SAFETY: a NUL-terminated path.
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        let mut got: Vec<IpAddr> = resolver_dir(&dir)
            .unwrap()
            .iter()
            .flat_map(|t| parse(t))
            .collect();
        got.sort();
        assert_eq!(got, vec![ip("203.0.113.53"), ip("203.0.113.54")]);
        assert_eq!(read_file(&dir.join("fifo")).unwrap(), None);
        assert_eq!(read_file(&dir.join("sub")).unwrap(), None);
        assert_eq!(read_file(&dir.join("absent")).unwrap(), None);
        assert_eq!(
            resolver_dir(&dir.join("absent")).unwrap(),
            Vec::<String>::new()
        );
        // Not a directory, or not readable: an error, not "no files".
        assert!(resolver_dir(&dir.join("other")).is_err());
        std::fs::write(dir.join("big"), vec![b'#'; MAX_FILE as usize + 1]).unwrap();
        assert!(read_file(&dir.join("big")).is_err());
        assert!(resolver_dir(&dir).is_err());
        std::fs::remove_file(dir.join("big")).unwrap();
        std::fs::write(dir.join("locked"), b"nameserver 203.0.113.55\n").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.join("locked"), std::fs::Permissions::from_mode(0o000))
            .unwrap();
        assert!(read_file(&dir.join("locked")).is_err());
        assert!(resolver_dir(&dir).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// bypass-1: every DNS server `scutil --dns` lists (the configuration daemon's resolvers,
    /// scoped and supplemental ones included) is one of the system's DNS servers, and every
    /// server the daemon's DNS keys name is one `scutil --dns` lists.
    #[cfg(target_os = "macos")]
    #[test]
    fn macos_dns_servers_are_the_configuration_daemons() {
        let out = std::process::Command::new("/usr/sbin/scutil")
            .arg("--dns")
            .output()
            .expect("scutil --dns");
        let text = String::from_utf8_lossy(&out.stdout);
        let listed: Vec<IpAddr> = text
            .lines()
            .filter_map(|l| {
                let (k, v) = l.split_once(':')?;
                k.trim().starts_with("nameserver[").then(|| v.trim())
            })
            .flat_map(super::macos_dns::numeric)
            .collect();
        let configd = super::macos_dns::configd().expect("the configuration daemon");
        let all = system_resolvers();
        assert_eq!(all, read_system_resolvers().unwrap());
        for a in &listed {
            assert!(all.contains(a), "{a} (scutil --dns) not in {all:?}");
        }
        for a in &configd {
            assert!(
                listed.contains(a),
                "{a} (configd) not in scutil --dns: {listed:?}"
            );
            assert!(all.contains(a), "{a} (configd) not in {all:?}");
        }
        // Review round 2: the servers set by hand for any service, and every /etc/resolver
        // file's, are the system's too.
        let (state, setup) = super::macos_dns::configd_all().unwrap();
        assert_eq!(state, configd);
        for a in &setup {
            assert!(all.contains(a), "{a} (Setup:) not in {all:?}");
        }
        let files: Vec<IpAddr> =
            super::macos_dns::resolver_dir(std::path::Path::new("/etc/resolver"))
                .unwrap()
                .iter()
                .flat_map(|t| super::macos_dns::parse(t))
                .collect();
        for a in &files {
            assert!(all.contains(a), "{a} (/etc/resolver) not in {all:?}");
        }
        eprintln!("Setup: servers {setup:?}; /etc/resolver servers {files:?}");
        assert_eq!(
            listed.is_empty(),
            configd.is_empty(),
            "{listed:?} {configd:?}"
        );
        eprintln!(
            "scutil --dns: {} server entries; configd keys: {configd:?}; all: {all:?}",
            listed.len()
        );
    }

    /// Review round 2 (cross-1, cross-2): every source counts: the files, the resolver
    /// directory, the daemon's `State:` servers and its `Setup:` servers; a failure of any one
    /// fails the read.
    #[cfg(target_os = "macos")]
    #[test]
    fn macos_dns_servers_come_from_every_source() {
        use super::macos_dns::read_with;
        use std::path::Path;
        let dir = std::env::temp_dir().join(format!("zkminer-dns-src-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("resolver")).unwrap();
        std::fs::write(dir.join("resolv.conf"), "nameserver 192.0.2.1\n").unwrap();
        std::fs::write(dir.join("resolver/corp.example"), "nameserver 192.0.2.2\n").unwrap();
        let conf = dir.join("resolv.conf");
        let files = [conf.as_path(), Path::new("/nonexistent/resolv.conf")];
        let configd = || Ok((vec![ip("192.0.2.3")], vec![ip("192.0.2.4")]));
        let mut got = read_with(files, &dir.join("resolver"), configd).unwrap();
        got.sort();
        assert_eq!(
            got,
            vec![
                ip("192.0.2.1"),
                ip("192.0.2.2"),
                ip("192.0.2.3"),
                ip("192.0.2.4")
            ]
        );
        let down = || {
            Err(io::Error::other(
                "could not reach the system configuration daemon",
            ))
        };
        assert!(read_with(files, &dir.join("resolver"), down).is_err());
        // A symbolic link that loops is skipped (the system cannot open it either); the rest of
        // the directory is still read.
        std::os::unix::fs::symlink(dir.join("resolver/b"), dir.join("resolver/a")).unwrap();
        std::os::unix::fs::symlink(dir.join("resolver/a"), dir.join("resolver/b")).unwrap();
        let got = read_with(files, &dir.join("resolver"), configd).unwrap();
        assert!(got.contains(&ip("192.0.2.2")), "{got:?}");
        // A file this user may not read fails the read, naming it.
        use std::os::unix::fs::PermissionsExt;
        let locked = dir.join("resolver/locked.example");
        std::fs::write(&locked, "nameserver 192.0.2.5\n").unwrap();
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
        let e = read_with(files, &dir.join("resolver"), configd).unwrap_err();
        assert!(e.to_string().contains("locked.example"), "{e}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// cross-2: the daemon's values are read strictly: only a dictionary whose `ServerAddresses`
    /// is an array of strings that each name an address gives servers (none without the key); a
    /// value that is not one fails the read, naming its key; a key gone since it was listed has
    /// none.
    #[cfg(target_os = "macos")]
    #[test]
    fn configd_values_are_read_strictly() {
        use super::macos_dns::{server_addresses, servers_of};
        use core_foundation::array::CFArray;
        use core_foundation::base::{CFType, TCFType};
        use core_foundation::dictionary::CFDictionary;
        use core_foundation::number::CFNumber;
        use core_foundation::propertylist::{CFPropertyList, CFPropertyListSubClass};
        use core_foundation::string::CFString;
        let key = CFString::from_static_string("ServerAddresses");
        let dict = |v: CFType| -> CFPropertyList {
            CFDictionary::from_CFType_pairs(&[(key.as_CFType(), v)])
                .to_untyped()
                .to_CFPropertyList()
        };
        let strings = |v: &[&str]| -> CFType {
            let items: Vec<CFType> = v.iter().map(|s| CFString::new(s).as_CFType()).collect();
            CFArray::from_CFTypes(&items).as_CFType()
        };
        assert_eq!(
            server_addresses(&dict(strings(&["192.0.2.53", "fe80::1%en0", "0xc0000235"]))),
            Some(vec![ip("192.0.2.53"), ip("fe80::1"), ip("192.0.2.53")])
        );
        // No ServerAddresses: no servers.
        let other = CFString::from_static_string("SearchDomains");
        let no_key =
            CFDictionary::from_CFType_pairs(&[(other.as_CFType(), strings(&["x.example"]))])
                .to_untyped()
                .to_CFPropertyList();
        assert_eq!(server_addresses(&no_key), Some(Vec::new()));
        // Not a dictionary; ServerAddresses a string; an array holding a number; a number; a
        // string that names no address; an empty string.
        let array = CFArray::from_CFTypes(&[CFString::new("192.0.2.53").as_CFType()])
            .to_untyped()
            .to_CFPropertyList();
        let mixed = CFArray::from_CFTypes(&[
            CFString::new("192.0.2.53").as_CFType(),
            CFNumber::from(53i32).as_CFType(),
        ])
        .as_CFType();
        for bad in [
            array,
            dict(CFString::new("192.0.2.53").as_CFType()),
            dict(mixed),
            dict(CFNumber::from(53i32).as_CFType()),
            dict(strings(&["not-an-ip"])),
            dict(strings(&["192.0.2.53", ""])),
        ] {
            assert_eq!(server_addresses(&bad), None);
        }
        let good = dict(strings(&["192.0.2.53"]));
        assert_eq!(
            servers_of([
                ("State:/Network/Global/DNS".to_string(), Some(good.clone())),
                ("State:/Network/Service/gone/DNS".to_string(), None),
            ])
            .unwrap(),
            vec![ip("192.0.2.53")]
        );
        let e = servers_of([
            ("State:/Network/Global/DNS".to_string(), Some(good)),
            (
                "Setup:/Network/Service/x/DNS".to_string(),
                Some(dict(strings(&["not-an-ip"]))),
            ),
        ])
        .unwrap_err();
        assert!(
            e.to_string().contains("Setup:/Network/Service/x/DNS"),
            "{e}"
        );
    }

    /// cross-2: every DNS key this host's configuration daemon holds for a service or globally is
    /// one the read lists (the multicast, private-relay and mDNSResponder keys hold no unicast
    /// servers), and every value read is one configd wrote.
    #[cfg(target_os = "macos")]
    #[test]
    fn this_hosts_dns_keys_are_all_read() {
        use super::macos_dns::{SETUP_DNS_KEYS, STATE_DNS_KEYS};
        use system_configuration::dynamic_store::SCDynamicStoreBuilder;
        let store = SCDynamicStoreBuilder::new("zkminer-netguard-test")
            .build()
            .unwrap();
        let keys = |patterns: &[&str]| -> Vec<String> {
            let mut v: Vec<String> = patterns
                .iter()
                .flat_map(|p| {
                    store
                        .get_keys(*p)
                        .unwrap()
                        .iter()
                        .map(|k| k.to_string())
                        .collect::<Vec<_>>()
                })
                .collect();
            v.sort();
            v
        };
        let read = keys(&[STATE_DNS_KEYS, SETUP_DNS_KEYS].concat());
        let every: Vec<String> = keys(&["(State|Setup):/Network/.*/DNS"])
            .into_iter()
            .filter(|k| !k.ends_with("/MulticastDNS") && !k.ends_with("/PrivateDNS"))
            .collect();
        eprintln!("this host's DNS keys: {every:?}");
        assert_eq!(read, every);
        assert!(every.contains(&"State:/Network/Global/DNS".to_string()) || every.is_empty());
    }

    /// bypass-2 (macOS): two networks whose routers have the same address on the same interface
    /// have the same routes and the same `uplink_signature`; the configuration daemon's network
    /// identities (the routers' hardware addresses) tell them apart, so a public address
    /// confirmed on one is not confirmed on the other. The same network read twice, its services
    /// listed in another order, is the same uplink.
    #[cfg(target_os = "macos")]
    #[test]
    fn two_networks_behind_the_same_router_address_are_two_uplinks_on_macos() {
        let gw = ip("192.168.1.1");
        let home = RouteTable::new(vec![
            Route::via(p("0.0.0.0/0"), gw, 14),
            Route::on_link(p("192.168.1.0/24"), 14),
        ]);
        let cafe = RouteTable::new(vec![
            Route::via(p("0.0.0.0/0"), gw, 14),
            Route::on_link(p("192.168.1.0/24"), 14),
            Route::on_link(p("192.168.1.1/32"), 14),
        ]);
        let (a, b) = (
            uplink_signature(&home, &[14]),
            uplink_signature(&cafe, &[14]),
        );
        assert_eq!(a, b, "the routes alone cannot tell them apart");
        let sig = |mac: &str| {
            vec![
                format!("State:/Network/Service/S/IPv4=IPv4.Router=192.168.1.1;IPv4.RouterHardwareAddress={mac}"),
                format!("State:/Network/Service/S/IPv6=IPv6.Prefix=2001:db8:1::/64;IPv6.RouterHardwareAddress={mac}"),
            ]
        };
        let at_home = macos_uplink_signature(a, &sig("a4:2b:b0:00:00:01"));
        let at_cafe = macos_uplink_signature(b, &sig("3c:84:6a:00:00:02"));
        assert_ne!(at_home, at_cafe);
        let mut reordered = sig("a4:2b:b0:00:00:01");
        reordered.reverse();
        assert_eq!(macos_uplink_signature(a, &reordered), at_home);
        assert_ne!(macos_uplink_signature(a, &[]), at_home);
        // This host: the daemon identifies the network of every service with an IPv4 router.
        let networks = macos_dns::network_signatures().unwrap();
        eprintln!("{} network signatures", networks.len());
        let (routes, _) = crate::routes::read_routing(&[]).unwrap();
        if routes.iter().any(|r| {
            r.prefix.len == 0 && r.prefix.addr.is_ipv4() && r.table == crate::routes::RT_TABLE_MAIN
        }) {
            assert!(
                networks.iter().any(|n| n.contains("IPv4.Router=")),
                "no IPv4 network signature"
            );
        }
    }

    /// bypass-2: a service's `NetworkSignature` is read strictly.
    #[cfg(target_os = "macos")]
    #[test]
    fn network_signatures_are_read_strictly() {
        use super::macos_dns::{network_signature, signatures_of};
        use core_foundation::base::TCFType;
        use core_foundation::dictionary::CFDictionary;
        use core_foundation::number::CFNumber;
        use core_foundation::propertylist::CFPropertyListSubClass;
        use core_foundation::string::CFString;
        let key = CFString::from_static_string("NetworkSignature");
        let with = |v: core_foundation::base::CFType| {
            CFDictionary::from_CFType_pairs(&[(key.as_CFType(), v)])
                .to_untyped()
                .to_CFPropertyList()
        };
        assert_eq!(
            network_signature(&with(CFString::new("IPv4.Router=192.0.2.1").as_CFType())),
            Some(Some("IPv4.Router=192.0.2.1".to_string()))
        );
        assert_eq!(
            network_signature(&with(CFNumber::from(1i32).as_CFType())),
            None
        );
        let other = CFDictionary::from_CFType_pairs(&[(
            CFString::new("Router").as_CFType(),
            CFString::new("192.0.2.1").as_CFType(),
        )])
        .to_untyped()
        .to_CFPropertyList();
        assert_eq!(network_signature(&other), Some(None));
        assert_eq!(
            network_signature(&CFString::new("x").to_CFPropertyList()),
            None
        );
        let k = |s: &str| s.to_string();
        let good = with(CFString::new("IPv4.Router=192.0.2.1").as_CFType());
        assert_eq!(
            signatures_of([
                (k("State:/Network/Service/a/IPv4"), Some(good.clone())),
                (k("State:/Network/Service/b/IPv4"), Some(other)),
                (k("State:/Network/Service/c/IPv6"), None),
            ])
            .unwrap(),
            vec![k("State:/Network/Service/a/IPv4=IPv4.Router=192.0.2.1")]
        );
        let e = signatures_of([
            (k("State:/Network/Service/a/IPv4"), Some(good)),
            (
                k("State:/Network/Service/d/IPv6"),
                Some(with(CFNumber::from(1i32).as_CFType())),
            ),
        ])
        .unwrap_err();
        assert!(e.to_string().contains("Service/d/IPv6"), "{e}");
    }

    /// parse-4 / cross-2: a netmask is read within its `sa_len`: the kernel trims
    /// 255.255.255.0 to `sa_len` 7, and what follows (here 0xff bytes, another sockaddr's) is
    /// not the mask's.
    #[cfg(target_os = "macos")]
    #[test]
    fn netmasks_are_read_within_their_length() {
        let mask = |b: &[u8], v4: bool| {
            let mut buf = [0xffu8; 32];
            buf[..b.len()].copy_from_slice(b);
            // SAFETY: `buf` holds 32 bytes, more than any `sa_len` here.
            unsafe { sys::sockaddr_mask(buf.as_ptr().cast(), v4) }
        };
        assert_eq!(mask(&[7, 0, 0, 0, 0xff, 0xff, 0xff], true), Some(24));
        assert_eq!(mask(&[5, 0, 0, 0, 0xff], true), Some(8));
        assert_eq!(mask(&[0], true), Some(0));
        assert_eq!(mask(&[8, 0, 0, 0, 0xff, 0xff, 0xff, 0xff], true), Some(32));
        let mut v6 = vec![16, 0, 0, 0, 0, 0, 0, 0];
        v6.extend([0xff; 8]);
        assert_eq!(mask(&v6, false), Some(64));
        // SAFETY: null is allowed.
        assert_eq!(unsafe { sys::sockaddr_mask(std::ptr::null(), true) }, None);
    }

    /// cross-2: without the configuration daemon (a sandbox that denies its Mach service) the
    /// DNS servers cannot be read, so the facts read fails, and a public-mode policy cannot be
    /// built: fail closed. Runs this test binary again under `sandbox-exec`.
    #[cfg(target_os = "macos")]
    #[test]
    fn the_facts_read_fails_without_the_configuration_daemon() {
        if std::env::var_os("ZKMINER_TEST_NO_CONFIGD").is_some() {
            let c = super::macos_dns::configd();
            let g = HostFacts::gather_with(&offline());
            let p = crate::NetPolicy::with_options(crate::NetMode::Public, Vec::new(), offline());
            println!(
                "RESULT configd {:?}; gather {:?}; policy {:?}",
                c.as_ref().err(),
                g.as_ref().err(),
                p.as_ref().err()
            );
            assert!(c.is_err() && g.is_err() && p.is_err());
            println!("RESULT all failed");
            return;
        }
        let sandbox = std::path::Path::new("/usr/bin/sandbox-exec");
        if !sandbox.exists() {
            crate::skipped("no sandbox-exec");
            return;
        }
        let out = std::process::Command::new(sandbox)
            .args([
                "-p",
                "(version 1)(allow default)(deny mach-lookup (global-name \"com.apple.SystemConfiguration.configd\"))",
            ])
            .arg(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "facts::tests::the_facts_read_fails_without_the_configuration_daemon",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("ZKMINER_TEST_NO_CONFIGD", "1")
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&out.stdout);
        eprintln!("{text}{}", String::from_utf8_lossy(&out.stderr));
        assert!(
            out.status.success() && text.contains("RESULT all failed"),
            "{text}"
        );
    }

    /// cross-3: a call to the configuration daemon is bounded: one that does not return within
    /// its timeout fails, the next fails at once while it is still stuck (here one stuck call is
    /// the most; the daemon's allows four), and once it returns calls are made again. Calls that
    /// return in time may run at once, any number of them.
    #[cfg(target_os = "macos")]
    #[test]
    fn a_stuck_configuration_daemon_fails_the_read_in_time() {
        use super::macos_dns::Bounded;
        use std::time::{Duration, Instant};
        static B: Bounded = Bounded::new("the test daemon", 1);
        assert_eq!(B.run(Duration::from_secs(1), || Ok(7)).unwrap(), 7);
        let t = Instant::now();
        let e = B
            .run(Duration::from_millis(200), || {
                std::thread::sleep(Duration::from_millis(800));
                Ok(1)
            })
            .unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::TimedOut);
        assert!(
            t.elapsed() < Duration::from_millis(600),
            "{:?}",
            t.elapsed()
        );
        let e = B.run(Duration::from_secs(1), || Ok(2)).unwrap_err();
        assert!(e.to_string().contains("earlier requests"), "{e}");
        std::thread::sleep(Duration::from_millis(900));
        assert_eq!(B.run(Duration::from_secs(1), || Ok(3)).unwrap(), 3);
        assert!(B
            .run(Duration::from_secs(1), || Err::<(), _>(io::Error::other(
                "x"
            )))
            .is_err());
        assert_eq!(B.run(Duration::from_secs(1), || Ok(4)).unwrap(), 4);
        let many: Vec<_> = (0..16)
            .map(|i| {
                std::thread::spawn(move || {
                    B.run(Duration::from_secs(2), move || {
                        std::thread::sleep(Duration::from_millis(100));
                        Ok(i)
                    })
                })
            })
            .collect();
        for (i, t) in many.into_iter().enumerate() {
            assert_eq!(t.join().unwrap().unwrap(), i);
        }
    }

    /// Review round 3, bypass-4: calls that return right at their timeout, from several threads
    /// at once, never make the count of abandoned calls wrap below zero (round 2 counted a call
    /// after marking it abandoned, so its thread could uncount it first), and never refuse a call
    /// while fewer than the cap are outstanding.
    #[cfg(target_os = "macos")]
    #[test]
    fn abandoned_calls_are_counted_before_they_can_return() {
        use super::macos_dns::Bounded;
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        use std::time::{Duration, Instant};
        static B: Bounded = Bounded::new("the test daemon", 64);
        static STOP: AtomicBool = AtomicBool::new(false);
        static HIGHEST: AtomicUsize = AtomicUsize::new(0);
        static REFUSED: AtomicUsize = AtomicUsize::new(0);
        let watch = std::thread::spawn(|| {
            while !STOP.load(Ordering::Relaxed) {
                HIGHEST.fetch_max(B.abandoned_now(), Ordering::Relaxed);
            }
        });
        let racers: Vec<_> = (0..16)
            .map(|_| {
                std::thread::spawn(|| {
                    let mut timed_out = 0usize;
                    let end = Instant::now() + Duration::from_secs(3);
                    while Instant::now() < end {
                        // A call that ends right at its timeout, so the race is often close.
                        match B.run(Duration::from_micros(300), || {
                            std::thread::sleep(Duration::from_micros(300));
                            Ok(())
                        }) {
                            Err(e) if e.to_string().contains("earlier requests") => {
                                REFUSED.fetch_add(1, Ordering::Relaxed);
                            }
                            Err(_) => timed_out += 1,
                            Ok(()) => {}
                        }
                    }
                    timed_out
                })
            })
            .collect();
        let timed_out: usize = racers.into_iter().map(|r| r.join().unwrap()).sum();
        STOP.store(true, Ordering::Relaxed);
        watch.join().unwrap();
        let highest = HIGHEST.load(Ordering::Relaxed);
        eprintln!(
            "{timed_out} calls timed out; the most abandoned at once: {highest}; refused: {}",
            REFUSED.load(Ordering::Relaxed)
        );
        assert!(timed_out > 100, "the race was not run: {timed_out}");
        // Sixteen callers can have at most sixteen calls abandoned at once (plus one counted while
        // it returns); a wrapped count is near usize::MAX.
        assert!(highest <= 32, "the count wrapped: {highest}");
        assert_eq!(REFUSED.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn refused_prefixes_flatten_everything_the_facts_refuse() {
        let raw = RawFacts {
            interface_prefixes: vec![p("192.168.1.0/24")],
            interface_addresses: vec![ip("192.168.1.33"), ip("2606:a300:9024:184::5")],
            routes: vec![
                Route::via(p("0.0.0.0/0"), ip("192.168.1.1"), 2),
                Route::via(p("198.51.100.0/24"), ip("10.8.0.1"), 7),
                Route::on_link(p("2606:a300:9024:184::/64"), 2),
            ],
            resolvers: vec![ip("9.9.9.9")],
            ..RawFacts::default()
        };
        let f = HostFacts::assemble(raw, &offline());
        assert_eq!(
            f.refused_prefixes(),
            vec![
                p("9.9.9.9/32"),
                p("192.168.1.0/24"),
                p("198.51.100.0/24"),
                p("2606:a300::/32"),
                p("2606:a300:9024:184::/64"),
            ]
        );
    }
}
