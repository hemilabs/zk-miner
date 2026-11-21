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
    /// [IPv4, IPv6]: the family's address is being learned again after an uplink change
    /// ([`RawFacts::public_relearning`]).
    relearning: [bool; 2],
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
    /// [IPv4, IPv6]: the family's public address was confirmed on another uplink and is being
    /// learned again on this one ([`crate::public::Learned::relearning`]).
    pub public_relearning: [bool; 2],
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
    /// The host has IPv6 and no IPv4 route, and NAT64 prefix discovery for the uplink it is on
    /// now has not finished ([`crate::nat64`]): every IPv6 destination is refused until it has
    /// (review round 3, bypass-1; every platform since the Linux application).
    pub nat64_unsettled: bool,
    /// A NAT64 prefix named on the uplink in use could not be held, or was named by a source
    /// that is not believed: why ([`crate::nat64::unheld`]; every IPv6 destination is refused on
    /// any host meanwhile: review round 5, cross-1).
    pub nat64_unheld: Option<String>,
    /// [IPv4, IPv6]: a default gateway of the family whose link-layer address was known has no
    /// neighbour entry now, and did not resolve when asked (Linux, review round 6, bypass-2 =
    /// cross-5: the first reads after a move over a link that went down, to a network numbered
    /// like the old, read as the old network). The family's connections are refused meanwhile,
    /// as while its public address is learned again.
    pub gateway_unresolved: [bool; 2],
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
    /// Why these facts can no longer be judged with (a refresh failed and they outlived their
    /// time): every requester connection is refused ([`crate::Denied::FactsUnreadable`]).
    unreadable: Option<String>,
    /// [`RawFacts::nat64_unsettled`].
    nat64_unsettled: bool,
    /// [`RawFacts::nat64_unheld`].
    nat64_unheld: Option<String>,
    /// The uplink signature NAT64 discovery runs on for facts read from this host, whose unheld
    /// marks are read live ([`Self::nat64_unheld`]).
    nat64_uplink: Option<u64>,
    /// The nexthop objects (Linux), for the default routes through one ([`default_path_known`]).
    nexthops: Vec<crate::routes::Nexthop>,
}

/// Why the kernel's answer refused a destination ([`HostFacts::kernel_verdict_from`]).
#[derive(Debug, Clone, PartialEq, Eq)]
enum KernelRefusal {
    Route(RouteRefusal),
    QueryFailed(String),
}

/// The route oracle's verdicts, per destination and destination port.
type Verdicts = HashMap<(IpAddr, Option<u16>, Option<IpAddr>), Result<(), KernelRefusal>>;

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

/// The kernel's answer `answer`, which `routes` (these facts' table) admitted, must leave by a
/// default path these facts hold (review round 3, bypass-3; on every platform since the Linux
/// application). [`RouteTable::judge`] admits any
/// default-like route of an ordinary table whatever its gateway and interface, so an uplink that
/// came up after the facts were read (a full-tunnel VPN's `0/1` on a `utun`, a second network's
/// default) was admitted until the facts were read again, up to [`crate::FACTS_TTL`] later (and
/// `REFRESH_GRACE` more while re-reads fail), and only those facts would have seen it
/// (`[egress] internal_ranges`, the uplink signature). So each route of the answer that is
/// default-like must be one of their default-like routes: the same family, hop and interface (a
/// route through one of their uplinks is: an uplink is a `/0` route's gateway and interface).
/// Otherwise it is refused as off the default path
/// (the gateway's or the link's kind), which rests on the facts: the policy reads them again and
/// judges once more. On Linux a default route through a nexthop object reads with its hop
/// [`crate::routes::Hop::Unknown`] in the dump; the kernel's answer for it carries the same, so
/// such a route is held as long as the facts hold it on that interface.
///
/// Review round 4, cross-4: a route through a nexthop object (`RTA_NH_ID`) must go through the
/// same object as the facts' default route, and that object must resolve in the facts' nexthop
/// dump (`nexthops`): with `nexthop_compat_mode` 0 the routes show no gateway and no interface,
/// so hop and interface alone held any default-like route through any object.
fn default_path_known(
    routes: &RouteTable,
    nexthops: &[crate::routes::Nexthop],
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
                && d.nexthop == r.nexthop
                && (d.nexthop == 0
                    || crate::routes::nexthop_interfaces(nexthops, d.nexthop).is_some())
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

/// NAT64 prefix discovery for the uplink `signature` of `table`, started when it is due
/// ([`crate::nat64::ensure_discovered_on`]); whether IPv6 destinations are refused meanwhile (a
/// host with IPv6 and no IPv4 route whose uplink's round has not finished: review round 3,
/// bypass-1; on every platform since the Linux application).
/// Review round 4 (bypass-1): the uplink's IPv6 default gateways are the routers whose PREF64
/// is heard, and a prefix named there that the guard could not hold
/// ([`crate::nat64::unheld`]) refuses IPv6 destinations on any host (it is a sign of a hostile
/// network, or of a network the guard cannot judge).
fn nat64_unsettled_on(
    table: &RouteTable,
    nexthops: &[crate::routes::Nexthop],
    signature: u64,
    clat: bool,
) -> (bool, Option<String>) {
    let up = crate::nat64::Uplink {
        signature,
        routed: [table.routes_family(false), table.routes_family(true)],
        clat,
    };
    let gateways: Vec<(std::net::Ipv6Addr, u32)> = default_gateways(table, nexthops)
        .into_iter()
        .filter_map(|(gw, ifindex)| match gw {
            IpAddr::V6(gw) => Some((gw, ifindex)),
            IpAddr::V4(_) => None,
        })
        .collect();
    crate::nat64::on_uplink(signature, &gateways);
    let settled = crate::nat64::ensure_discovered_on(up);
    (up.refuses_ipv6(settled), crate::nat64::unheld(signature))
}

/// The interfaces the IPv4 default routes leave from: a route's own, or its nexthop object's
/// devices (review round 6, the CLAT suspicion: a default through a nexthop object, ifindex 0,
/// never matched the CLAT name test). Sorted.
pub(crate) fn v4_default_links(
    table: &RouteTable,
    links: &[crate::routes::Link],
    nexthops: &[crate::routes::Nexthop],
) -> Vec<crate::routes::Link> {
    let mut ifs: Vec<u32> = Vec::new();
    for r in table.routes().iter().filter(|r| r.prefix.addr.is_ipv4() && r.is_default_like()) {
        if r.ifindex != 0 {
            ifs.push(r.ifindex);
        } else if r.nexthop != 0 {
            ifs.extend(crate::routes::nexthop_interfaces(nexthops, r.nexthop).unwrap_or_default());
        }
    }
    sorted(
        links
            .iter()
            .filter(|l| ifs.contains(&l.index))
            .cloned()
            .collect(),
    )
}

/// Whether an IPv4 default leaves from an interface a CLAT could be (a `tun` device, or one
/// named like `clat*`, `v4-*`, `tun*`): this host may reach IPv4 only through NAT64.
pub(crate) fn tunnelled_ipv4(v4_links: &[crate::routes::Link]) -> bool {
    v4_links.iter().any(|l| {
        l.kind.as_deref() == Some("tun")
            || ["clat", "v4-", "tun"].iter().any(|p| l.name.starts_with(p))
    })
}

/// Review round 6 (the CLAT suspicion): a host whose IPv4 default goes through a CLAT-like
/// interface the guard does not recognise as one (`clat`: no 192.0.0.0/29 address, no CLAT
/// name), or does, and that knows no NAT64 prefix (none configured, none learned) is warned,
/// once: a CLAT that translates under a network-specific prefix the DNS servers and routers do
/// not reveal would make `<NSP>::10.0.0.1` look like a public address.
fn warn_tunnelled_ipv4_without_nat64(v4_links: &[crate::routes::Link], clat: bool) {
    static WARNED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    if (clat || tunnelled_ipv4(v4_links))
        && crate::nat64::in_force().is_empty()
        && !WARNED.swap(true, std::sync::atomic::Ordering::Relaxed)
    {
        let names: Vec<&str> = v4_links.iter().map(|l| l.name.as_str()).collect();
        tracing::warn!(
            "network guard: this host's IPv4 default route goes through {} (a tunnel or a CLAT, \
             464XLAT) and no NAT64 prefix is known (none configured, none learned from DNS64 or \
             router advertisements). If that interface is a CLAT, name the network's NAT64 \
             prefix in [egress] nat64_prefixes: an address under it can carry a private IPv4 \
             address",
            names.join(", ")
        );
    }
}

/// The signature of the uplink this host is on now ([`uplink_signature`], and what tells two
/// networks behind the same router address apart): macOS adds the configuration daemon's
/// network signatures ([`macos_uplink_signature`]), Linux the addressing of the uplink's
/// interfaces ([`uplink_addressing`]) and the default gateways' link-layer addresses
/// ([`MacHistory::signature`]); elsewhere the routes alone. Public-address discovery and NAT64
/// discovery both run per signature.
#[cfg(target_os = "macos")]
fn host_uplink_signature(
    table: &RouteTable,
    internet: &[u32],
    _addresses: &[IpAddr],
    _nexthops: &[crate::routes::Nexthop],
) -> io::Result<UplinkId> {
    let networks = macos_dns::network_signatures()?;
    Ok(UplinkId::both(macos_uplink_signature(
        uplink_signature(table, internet),
        &networks,
    )))
}

/// The uplink as each family sees it (review round 6, cross-4): its signature per family
/// (`[IPv4, IPv6]`: public-address discovery runs per family, NAT64 discovery on the IPv6 one),
/// and per family whether a default gateway whose link-layer address was known shows none now
/// (Linux, review round 6, bypass-2 = cross-5: the neighbour table emptied by a link that went
/// down; that family's connections are refused until it resolves again, which the read asks for).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct UplinkId {
    pub families: [u64; 2],
    pub unresolved: [bool; 2],
}

impl UplinkId {
    /// One signature for both families, nothing unresolved.
    #[allow(dead_code)] // macOS and elsewhere
    pub(crate) fn both(signature: u64) -> Self {
        UplinkId {
            families: [signature; 2],
            unresolved: [false; 2],
        }
    }

}

/// See the macOS one. A neighbour table that cannot be read (a dump that is denied, unsupported
/// or keeps being interrupted: review round 4) does not fail the facts read: every gateway's
/// link-layer address is then unknown ([`MacHistory::signature`]: the last known one stands, and
/// with none known the routes and the uplink's addressing decide, warned about once: review
/// round 5, parse-4). Review round 6 (bypass-2 = cross-5): a gateway whose address was known and
/// that has no entry now is asked for one (a datagram to it makes the kernel resolve it) and
/// the table read again, for up to [`RESOLVE_WAIT`]; one still without is unresolved.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn host_uplink_signature(
    table: &RouteTable,
    internet: &[u32],
    addresses: &[IpAddr],
    nexthops: &[crate::routes::Nexthop],
) -> io::Result<UplinkId> {
    static HISTORY: std::sync::Mutex<MacHistory> = std::sync::Mutex::new(MacHistory::new());
    let carriers = crate::routes::carrier_changes();
    let mut history = HISTORY.lock().unwrap_or_else(|e| e.into_inner());
    let read = |h: &mut MacHistory| {
        let neighbours = crate::routes::read_neighbours();
        #[cfg(test)]
        {
            *LAST_NEIGHBOURS_READ.lock().unwrap_or_else(|e| e.into_inner()) =
                neighbours.as_ref().map(|n| gateway_identities(table, nexthops, n)).ok();
        }
        linux_signature(h, table, internet, addresses, nexthops, neighbours, &carriers, Instant::now())
    };
    let mut id = read(&mut history);
    if id.unresolved.contains(&true) {
        let t = Instant::now();
        for (gw, ifindex) in default_gateways(table, nexthops) {
            ask_for_neighbour(gw, ifindex);
        }
        while id.unresolved.contains(&true) && t.elapsed() < RESOLVE_WAIT {
            std::thread::sleep(std::time::Duration::from_millis(25));
            id = read(&mut history);
        }
    }
    Ok(id)
}

/// What the last facts read found of the gateways in the neighbour table (tests: cross-7 V02).
#[cfg(all(test, any(target_os = "linux", target_os = "android")))]
pub(crate) static LAST_NEIGHBOURS_READ: std::sync::Mutex<Option<Vec<GatewayIdentity>>> =
    std::sync::Mutex::new(None);

/// A default gateway, its interface, and its link-layer address if the table holds one.
#[cfg(all(test, any(target_os = "linux", target_os = "android")))]
type GatewayIdentity = (IpAddr, u32, Option<Vec<u8>>);

/// How long a facts read waits for a gateway whose entry went missing to resolve again.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub(crate) const RESOLVE_WAIT: std::time::Duration = std::time::Duration::from_millis(300);

/// Linux: one empty UDP datagram to gateway `gw` (port 9, discard) out of interface `ifindex`, so
/// that the kernel resolves its link-layer address (ARP, NDP); nothing waits for an answer.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn ask_for_neighbour(gw: IpAddr, ifindex: u32) {
    let (bind, to): (std::net::SocketAddr, std::net::SocketAddr) = match gw {
        IpAddr::V4(a) => ((std::net::Ipv4Addr::UNSPECIFIED, 0).into(), (a, 9).into()),
        IpAddr::V6(a) => (
            (std::net::Ipv6Addr::UNSPECIFIED, 0).into(),
            std::net::SocketAddrV6::new(a, 9, 0, if a.is_unicast_link_local() { ifindex } else { 0 }).into(),
        ),
    };
    if let Ok(sock) = std::net::UdpSocket::bind(bind) {
        let _ = sock.send_to(&[], to);
    }
}

/// Linux: [`host_uplink_signature`] with the neighbour table read as `neighbours` (an error
/// counts as no entry, warned about once), at `now`: the routes ([`uplink_signature`]), the
/// addressing of the uplink's interfaces ([`uplink_addressing`]), the /64s of the host's global
/// IPv6 addresses and the uplink's interfaces' carrier changes (`carriers`: review round 6,
/// bypass-2 = cross-5, the L=0 suspicion) are the base; the gateways' link-layer addresses tell
/// networks of the same base apart ([`MacHistory::signature`]).
#[cfg(any(test, target_os = "linux", target_os = "android"))]
#[allow(clippy::too_many_arguments)]
fn linux_signature(
    history: &mut MacHistory,
    table: &RouteTable,
    internet: &[u32],
    addresses: &[IpAddr],
    nexthops: &[crate::routes::Nexthop],
    neighbours: io::Result<Vec<crate::routes::Neighbour>>,
    carriers: &[(u32, u32)],
    now: Instant,
) -> UplinkId {
    use std::hash::{Hash, Hasher};
    static WARNED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    let readable = neighbours.is_ok();
    let neighbours = neighbours.unwrap_or_else(|e| {
        if !WARNED.swap(true, std::sync::atomic::Ordering::Relaxed) {
            tracing::warn!(
                "network guard: the neighbour table (RTM_GETNEIGH) could not be read ({e}); the \
                 default gateways' link-layer addresses are taken as unknown"
            );
        }
        Vec::new()
    });
    let gateways = gateway_identities(table, nexthops, &neighbours);
    let addressing = uplink_addressing(table, internet, addresses, &gateways);
    let mut uplinks: Vec<u32> = addressing.iter().map(|a| a.1).collect();
    uplinks.extend(gateways.iter().map(|g| g.1));
    uplinks.extend(internet);
    let mut carrier: Vec<(u32, u32)> =
        carriers.iter().copied().filter(|(i, _)| uplinks.contains(i)).collect();
    carrier.sort();
    carrier.dedup();
    let mut v6_64s: Vec<IpAddr> = addresses
        .iter()
        .filter(|a| a.is_ipv6() && is_global(**a))
        .map(|a| crate::ip::mask(*a, 64))
        .collect();
    v6_64s.sort();
    v6_64s.dedup();
    let mut h = std::collections::hash_map::DefaultHasher::new();
    uplink_signature(table, internet).hash(&mut h);
    addressing.hash(&mut h);
    v6_64s.hash(&mut h);
    carrier.hash(&mut h);
    history.signature(h.finish(), &gateways, readable, now)
}

/// See the macOS one.
#[cfg(not(any(target_os = "linux", target_os = "android", target_os = "macos")))]
fn host_uplink_signature(
    table: &RouteTable,
    internet: &[u32],
    _addresses: &[IpAddr],
    _nexthops: &[crate::routes::Nexthop],
) -> io::Result<UplinkId> {
    Ok(UplinkId::both(uplink_signature(table, internet)))
}

/// The default routes' gateways, each with its interface: a route's own (`Hop::Via` on an
/// interface), or, for a route through a nexthop object, its gateways
/// ([`crate::routes::nexthop_gateways`]; review round 5, cross-4: with `nexthop_compat_mode` 0
/// the dump shows no gateway, and the uplink's gateways were missing from its identities and
/// from the routers whose PREF64 is heard). Sorted.
pub(crate) fn default_gateways(
    routes: &RouteTable,
    nexthops: &[crate::routes::Nexthop],
) -> Vec<(IpAddr, u32)> {
    use crate::routes::Hop;
    let mut v: Vec<(IpAddr, u32)> = Vec::new();
    for r in routes.routes().iter().filter(|r| r.is_default_like()) {
        match r.hop {
            Hop::Via(gw) if r.ifindex != 0 => v.push((gw, r.ifindex)),
            _ if r.nexthop != 0 => v.extend(crate::routes::nexthop_gateways(nexthops, r.nexthop)),
            _ => {}
        }
    }
    v.sort();
    v.dedup();
    v
}

/// Linux: what the uplink's interfaces are numbered with (review round 5, bypass-1): the
/// prefixes of the on-link routes out of them (every IPv4 one, the global IPv6 ones: a
/// network's SLAAC or DHCPv6 prefix; never `fe80::/64`, the same everywhere), and the host's IPv4
/// addresses within those IPv4 prefixes. Two networks whose routers have the same address on the
/// same interface differ here unless they also number their hosts alike (two home networks on
/// 192.168.1.0/24 handing out the same address: the gateways' link-layer addresses then tell
/// them apart, [`MacHistory::signature`]); and these do not depend on the neighbour table. The
/// uplink's interfaces: those of its default routes and gateways and `internet`. Sorted.
#[cfg(any(test, target_os = "linux", target_os = "android"))]
pub(crate) fn uplink_addressing(
    table: &RouteTable,
    internet: &[u32],
    addresses: &[IpAddr],
    gateways: &[(IpAddr, u32, Option<Vec<u8>>)],
) -> Vec<(Prefix, u32, Option<IpAddr>)> {
    use crate::routes::{Hop, RouteType};
    let mut uplinks: Vec<u32> = internet.to_vec();
    uplinks.extend(gateways.iter().map(|g| g.1));
    uplinks.extend(
        table
            .routes()
            .iter()
            .filter(|r| r.is_default_like() && r.ifindex != 0)
            .map(|r| r.ifindex),
    );
    let mut v: Vec<(Prefix, u32, Option<IpAddr>)> = Vec::new();
    for r in table.routes() {
        if r.hop != Hop::OnLink
            || r.loopback
            || r.is_default_like()
            || r.kind != RouteType::Unicast
            || !uplinks.contains(&r.ifindex)
        {
            continue;
        }
        if r.prefix.addr.is_ipv6() {
            if is_global(r.prefix.addr) {
                v.push((r.prefix, r.ifindex, None));
            }
            continue;
        }
        let inside: Vec<IpAddr> = addresses
            .iter()
            .copied()
            .filter(|a| a.is_ipv4() && crate::ip::mask(*a, r.prefix.len) == r.prefix.addr)
            .collect();
        if inside.is_empty() {
            v.push((r.prefix, r.ifindex, None));
        }
        v.extend(inside.into_iter().map(|a| (r.prefix, r.ifindex, Some(a))));
    }
    v.sort();
    v.dedup();
    v
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

/// Linux: the link-layer address of each default gateway, from the neighbour table: for every
/// default gateway ([`default_gateways`], a nexthop object's included), `(gateway, interface,
/// its link-layer address)`, the address `None` when the table holds no usable entry for that
/// gateway on that interface (incomplete, failed, garbage-collected, never resolved yet).
/// Sorted.
#[cfg(any(test, target_os = "linux", target_os = "android"))]
pub(crate) fn gateway_identities(
    routes: &RouteTable,
    nexthops: &[crate::routes::Nexthop],
    neighbours: &[crate::routes::Neighbour],
) -> Vec<(IpAddr, u32, Option<Vec<u8>>)> {
    default_gateways(routes, nexthops)
        .into_iter()
        .map(|(gw, ifindex)| {
            let lladdr = neighbours
                .iter()
                .find(|n| n.ifindex == ifindex && n.addr == gw)
                .and_then(|n| n.lladdr.clone());
            (gw, ifindex, lladdr)
        })
        .collect()
}

/// Linux: how many reads in a row, and how long, a default gateway must show another
/// link-layer address than the one known before it counts as another network
/// ([`MacHistory::signature`]).
#[cfg(any(test, target_os = "linux", target_os = "android"))]
pub(crate) const MAC_CHANGE_READS: u32 = 3;
#[cfg(any(test, target_os = "linux", target_os = "android"))]
pub(crate) const MAC_CHANGE_HOLD: std::time::Duration = std::time::Duration::from_secs(2);

/// Linux: the default gateways' link-layer addresses as the facts reads have seen them, per
/// base (the routes and the uplink's addressing; the last few), for [`MacHistory::signature`].
#[cfg(any(test, target_os = "linux", target_os = "android"))]
#[derive(Debug, Default)]
pub(crate) struct MacHistory {
    bases: Vec<MacsOf>,
}

/// One gateway's link-layer address (a gateway: its address and interface).
#[cfg(any(test, target_os = "linux", target_os = "android"))]
type GatewayMac = ((IpAddr, u32), Vec<u8>);

#[cfg(any(test, target_os = "linux", target_os = "android"))]
#[derive(Debug)]
struct MacsOf {
    base: u64,
    /// Per gateway: the link-layer address known for it (the first seen, or the last that held).
    known: Vec<GatewayMac>,
    /// Per gateway whose known address changed (and held): the address it changed to. Part of
    /// the signature (an address first seen is not: it changes nothing).
    changed: Vec<GatewayMac>,
    /// Per gateway now showing another address than the known one: the latest it showed, since
    /// when it has shown other addresses, and on how many reads.
    #[allow(clippy::type_complexity)]
    candidate: Vec<((IpAddr, u32), Vec<u8>, Instant, u32)>,
}

#[cfg(any(test, target_os = "linux", target_os = "android"))]
impl MacHistory {
    pub(crate) const fn new() -> Self {
        MacHistory { bases: Vec::new() }
    }

    /// Linux: the uplink signature for `base` (the routes and the uplink's addressing) and the
    /// default gateways' link-layer addresses ([`gateway_identities`]). Two networks whose
    /// routers have the same address on the same interface and whose hosts are numbered alike
    /// (two home networks behind 192.168.1.1) have the same base; their routers' link-layer
    /// addresses differ (review round 2, bypass-2; Linux reads them unprivileged, unlike macOS).
    ///
    /// Review round 4 (cross-2): an entry that goes missing (`ip neigh flush`, a `FAILED` or
    /// garbage-collected entry, a neighbour table that cannot be read) changes nothing; an
    /// address first seen where none was known is that gateway's (no change).
    ///
    /// Review round 5 (bypass-1): another address than the known one is another network at once
    /// (the signature hashes it): until round 5 the old network's signature stood until the new
    /// address had held for [`MAC_CHANGE_READS`] reads and [`MAC_CHANGE_HOLD`], and a host that
    /// flipped the entry between two addresses kept it standing, so on a new network the old
    /// one's public addresses and NAT64 state counted (macOS changes at once). The debounce now
    /// only decides when the new address becomes the known one (so that a later flush or the old
    /// address keep the new network); the old address showing again before that is the old
    /// network again, and only it resets the debounce (a flapper or a spoof makes the guard
    /// learn again: it fails closed). Review round 5 (parse-4): with no address known, the base
    /// alone decides (stable; before, every such read was an uplink of its own, which refused
    /// every connection for want of a public address, for good).
    ///
    /// Review round 6 (cross-4, bypass-2 = cross-5): per family, the family of each gateway's
    /// own address deciding (a spoofed IPv4 gateway's address no longer makes IPv6 learn again).
    /// A family whose gateway shows another address than the known one is in one unsettled
    /// state, whatever and however many other addresses it shows (so a spoofer that changes the
    /// address every read makes one uplink, not one a read; and the known address showing again
    /// is the known network again); a candidate holds only when the same address shows on
    /// [`MAC_CHANGE_READS`] reads in a row over [`MAC_CHANGE_HOLD`]. A known gateway with no
    /// entry in a table that was read (`readable`) is unresolved (the caller asks for it and
    /// refuses that family meanwhile); a table that cannot be read changes nothing.
    pub(crate) fn signature(
        &mut self,
        base: u64,
        gateways: &[(IpAddr, u32, Option<Vec<u8>>)],
        readable: bool,
        now: Instant,
    ) -> UplinkId {
        use std::hash::{Hash, Hasher};
        static UNKNOWN_WARNED: std::sync::atomic::AtomicBool =
            std::sync::atomic::AtomicBool::new(false);
        let i = match self.bases.iter().position(|m| m.base == base) {
            Some(i) => i,
            None => {
                if self.bases.len() >= 8 {
                    self.bases.remove(0);
                }
                self.bases.push(MacsOf {
                    base,
                    known: Vec::new(),
                    changed: Vec::new(),
                    candidate: Vec::new(),
                });
                self.bases.len() - 1
            }
        };
        let m = &mut self.bases[i];
        let mut unresolved = [false; 2];
        for (gw, ifindex, seen) in gateways {
            let key = (*gw, *ifindex);
            let fam = usize::from(gw.is_ipv6());
            let Some(seen) = seen else {
                if readable && m.known.iter().any(|(k, _)| *k == key) {
                    unresolved[fam] = true;
                }
                continue;
            };
            match m.known.iter_mut().find(|(k, _)| *k == key) {
                None => m.known.push((key, seen.clone())),
                Some((_, known)) if known == seen => m.candidate.retain(|c| c.0 != key),
                Some((_, known)) => {
                    let c = match m.candidate.iter_mut().find(|c| c.0 == key) {
                        Some(c) if c.1 == *seen => {
                            c.3 += 1;
                            c
                        }
                        Some(c) => {
                            // Another address again: the same unsettled state, counted afresh.
                            c.1 = seen.clone();
                            c.2 = now;
                            c.3 = 1;
                            c
                        }
                        None => {
                            m.candidate.push((key, seen.clone(), now, 1));
                            tracing::info!(
                                "network guard: default gateway {gw} shows another link-layer \
                                 address; another network until it shows the known one again: \
                                 its public addresses and NAT64 prefixes are learned again"
                            );
                            m.candidate.last_mut().expect("just pushed")
                        }
                    };
                    if c.3 >= MAC_CHANGE_READS && now.saturating_duration_since(c.2) >= MAC_CHANGE_HOLD
                    {
                        tracing::info!(
                            "network guard: default gateway {gw}'s link-layer address changed and \
                             held; it is the known one from now on"
                        );
                        *known = seen.clone();
                        m.changed.retain(|(k, _)| *k != key);
                        m.changed.push((key, seen.clone()));
                        m.candidate.retain(|c| c.0 != key);
                    }
                }
            }
        }
        let ids: Vec<(IpAddr, u32)> = gateways.iter().map(|(g, i, _)| (*g, *i)).collect();
        if !ids.is_empty()
            && !ids.iter().any(|k| m.known.iter().any(|(kk, _)| kk == k))
            && !UNKNOWN_WARNED.swap(true, std::sync::atomic::Ordering::Relaxed)
        {
            tracing::warn!(
                "network guard: no default gateway's link-layer address is in the neighbour table; \
                 two networks behind the same gateway address are told apart by their routes and \
                 addressing alone until one is"
            );
        }
        let families = [false, true].map(|v6| {
            let of_family = |k: &(IpAddr, u32)| ids.contains(k) && k.0.is_ipv6() == v6;
            // What tells this network from another of the same base: the family's gateways'
            // addresses that changed (and held), and whether one shows another address now
            // (unsettled: the known address it left, not the one it shows).
            let mut macs: Vec<GatewayMac> =
                m.changed.iter().filter(|(k, _)| of_family(k)).cloned().collect();
            macs.sort();
            let mut unsettled: Vec<GatewayMac> = m
                .candidate
                .iter()
                .filter(|c| of_family(&c.0))
                .filter_map(|c| m.known.iter().find(|(k, _)| *k == c.0).cloned())
                .collect();
            unsettled.sort();
            let mut h = std::collections::hash_map::DefaultHasher::new();
            base.hash(&mut h);
            ids.hash(&mut h);
            macs.hash(&mut h);
            if !unsettled.is_empty() {
                "unsettled".hash(&mut h);
                unsettled.hash(&mut h);
            }
            h.finish()
        });
        UplinkId {
            families,
            unresolved,
        }
    }
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
            unreadable: None,
            nat64_unsettled: false,
            nat64_unheld: None,
            nat64_uplink: None,
            nexthops: Vec::new(),
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
            relearning: [0, 1].map(|i| raw.public_relearning[i] || raw.gateway_unresolved[i]),
        };
        let egress = EgressState {
            known: [0, 1].map(|i| egress.known[i] && !raw.gateway_unresolved[i]),
            ..egress
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
            unreadable: None,
            nat64_unsettled: raw.nat64_unsettled,
            nat64_unheld: raw.nat64_unheld,
            nat64_uplink: None,
            nexthops: raw.nexthops,
        }
    }

    /// How many kernel verdicts these facts hold (tests).
    #[cfg(test)]
    pub(crate) fn cached_verdicts(&self) -> usize {
        self.verdicts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .len()
    }

    /// Why these facts refuse every requester connection, if they do: their re-read kept failing
    /// past its grace (`Denied::FactsUnreadable`, naming the failure; review round 3, cross-6: for
    /// the operator's warnings). On every platform since the Linux application.
    pub fn unreadable_reason(&self) -> Option<&str> {
        self.unreadable.as_deref()
    }

    /// Why these facts may not be judged with, if so (see [`Self::refusing`]).
    pub(crate) fn unreadable(&self) -> Option<&str> {
        self.unreadable.as_deref()
    }

    /// Whether NAT64 prefix discovery for the uplink is unsettled on a host with IPv6 and no IPv4
    /// route ([`RawFacts::nat64_unsettled`]).
    pub(crate) fn nat64_unsettled(&self) -> bool {
        self.nat64_unsettled
    }

    /// Why a NAT64 prefix named on the uplink could not be held ([`RawFacts::nat64_unheld`]),
    /// or, for facts read from this host, is not held now (review round 6, the parse lens's
    /// suspicion: a mark a router advertisement made between two facts reads counted only from
    /// the next one; it is read live from [`crate::nat64::unheld`]).
    pub(crate) fn nat64_unheld(&self) -> Option<String> {
        self.nat64_unheld
            .clone()
            .or_else(|| self.nat64_uplink.and_then(crate::nat64::unheld))
    }

    /// These facts, read on NAT64 uplink `signature` (whose unheld marks are read live; tests).
    #[cfg(test)]
    pub(crate) fn on_nat64_uplink(mut self, signature: u64) -> Self {
        self.nat64_uplink = Some(signature);
        self
    }

    /// These facts, read on uplink `id`.
    pub(crate) fn on_uplink(mut self, id: UplinkId) -> Self {
        self.nat64_uplink = Some(id.families[1]);
        self
    }

    /// These facts without the kernel's cached verdicts (a refresh failed: what the kernel
    /// answered for them is asked again).
    pub(crate) fn without_verdicts(&self) -> Self {
        HostFacts {
            verdicts: Arc::default(),
            ..self.clone()
        }
    }

    /// These facts, which may no longer be judged with: `why` they could not be read again.
    /// [`crate::admit`] refuses every destination with them.
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

    /// Whether `path`'s public address is unknown only because the host just moved to another
    /// uplink and it is being learned again there (review round 4, cross-2): nothing to set.
    pub fn relearning(&self, path: EgressPath) -> bool {
        self.egress
            .as_ref()
            .is_some_and(|e| e.relearning[usize::from(path == EgressPath::Ipv6)])
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

    /// [`Self::kernel_verdict_from`] with no source (the macOS tests).
    #[cfg(all(test, target_os = "macos"))]
    pub(crate) fn kernel_verdict(&self, ip: IpAddr, dport: Option<u16>) -> Result<(), Denied> {
        self.kernel_verdict_from(ip, dport, None)
    }

    /// The source address the kernel would choose for a TCP connection to `dst` (on `dport`),
    /// when the route oracle can say ([`RouteOracle::source_for`]).
    pub(crate) fn kernel_source(&self, dst: IpAddr, dport: Option<u16>) -> Option<IpAddr> {
        self.oracle
            .as_ref()
            .and_then(|o| o.source_for(dst, dport).ok().flatten())
    }

    /// The route oracle's verdict on a connection to `ip` (on destination port `dport` when
    /// given; from source `src` when given, a socket bound to it, asked with
    /// [`RouteOracle::route_from`]; admitted when there is no oracle): asked once per destination,
    /// port and source for as long as these facts are in force (a snapshot lives about a second,
    /// [`crate::FACTS_TTL`]). An IPv4-mapped address is asked as its IPv4 address, which is how
    /// a dual-stack socket connects to it.
    pub(crate) fn kernel_verdict_from(
        &self,
        ip: IpAddr,
        dport: Option<u16>,
        src: Option<IpAddr>,
    ) -> Result<(), Denied> {
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
            .get(&(dst, dport, src))
            .cloned();
        let verdict = match cached {
            Some(v) => v,
            None => {
                let answer = match src {
                    Some(src) => oracle.route_from(src, dst, dport),
                    None => oracle.route_to(dst, dport),
                };
                let v = match answer {
                    Ok(answer) => self
                        .routes
                        .judge_answer(&answer)
                        .and_then(|()| default_path_known(&self.routes, &self.nexthops, &answer))
                        .map_err(KernelRefusal::Route),
                    Err(e) => Err(KernelRefusal::QueryFailed(e.to_string())),
                };
                let mut cache = self.verdicts.lock().unwrap_or_else(|e| e.into_inner());
                if cache.len() >= MAX_VERDICTS {
                    cache.clear();
                }
                cache.insert((dst, dport, src), v.clone());
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
        let (routes, rules) = crate::routes::read_routing(&loopback)?;
        let links = crate::routes::read_links()?;
        let nexthops = if routes.iter().any(|r| r.nexthop != 0) {
            crate::routes::read_nexthops()?
        } else {
            Vec::new()
        };
        let internet_interfaces = crate::routes::internet_interfaces();
        let table = RouteTable::with_rules(routes.clone(), rules.clone());
        let uplink = host_uplink_signature(
            &table,
            &internet_interfaces,
            &interface_addresses,
            &nexthops,
        )?;
        // NAT64 is the IPv6 side's (review round 6, cross-4).
        let signature = uplink.families[1];
        // The NAT64 prefixes, learned again whenever the uplink changes (review round 3,
        // bypass-1; every platform since the Linux application); IPv6 destinations are refused
        // on a host with IPv6 and no IPv4 route until the new uplink's round has finished.
        // Review round 5, bypass-4: a host whose IPv4 goes out through a CLAT is IPv6-only.
        let v4_links = v4_default_links(&table, &links, &nexthops);
        let v4_default_interfaces: Vec<String> = v4_links.iter().map(|l| l.name.clone()).collect();
        let clat = crate::nat64::clat_in_use(&interface_addresses, &v4_default_interfaces);
        warn_tunnelled_ipv4_without_nat64(&v4_links, clat);
        let (nat64_unsettled, nat64_unheld) =
            nat64_unsettled_on(&table, &nexthops, signature, clat);
        let public = if opts.discover_public_addresses {
            // Addresses confirmed under another uplink (a new default gateway, a VPN that came
            // up) are not this one's: discovery runs again, and meanwhile they are not known.
            crate::public::learned_on_families(uplink.families)
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
                public_relearning: public.relearning,
                links,
                internet_interfaces,
                nexthops,
                pppoe_sessions: crate::routes::pppoe_sessions(),
                nat64_unsettled,
                nat64_unheld,
                gateway_unresolved: uplink.unresolved,
            },
            opts,
        )
        .with_route_oracle(Arc::new(crate::routes::KernelRoutes))
        .on_uplink(uplink))
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

/// The DNS servers for the facts and NAT64 discovery: [`system_resolvers`], which cannot fail here.
#[cfg(not(target_os = "macos"))]
pub(crate) fn read_system_resolvers() -> io::Result<Vec<IpAddr>> {
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

/// macOS: the DNS servers for the facts and for discovery ([`system_resolvers`]'s, or why they
/// cannot be read).
#[cfg(target_os = "macos")]
pub(crate) fn read_system_resolvers() -> io::Result<Vec<IpAddr>> {
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

    /// The key holding the system's active DNS configuration (the primary service's resolvers).
    pub(crate) const GLOBAL_DNS_KEY: &str = "State:/Network/Global/DNS";

    /// The active DNS servers, in the order the configuration daemon gives them (the resolvers
    /// the system asks first): [`GLOBAL_DNS_KEY`]'s `ServerAddresses`; none without the key.
    /// NAT64 discovery asks them first (review round 3, bypass-2).
    pub(crate) fn global_servers() -> io::Result<Vec<IpAddr>> {
        ASKING.run(CONFIGD_TIMEOUT, || {
            let store = session()?;
            servers_of(
                store
                    .get(GLOBAL_DNS_KEY)
                    .map(|v| (GLOBAL_DNS_KEY.to_string(), Some(v))),
            )
        })
    }

    /// The configuration daemon's per-interface NAT64 state (its PLAT discovery, RFC 7050, and
    /// the prefixes a router announces, RFC 8781): one key per interface.
    pub(crate) const NAT64_KEYS: &[&str] = &["State:/Network/Interface/[^/]+/NAT64"];

    /// The NAT64 prefixes the configuration daemon publishes for this host's interfaces
    /// ([`NAT64_KEYS`], read by [`nat64_prefixes_of`]); review round 3, bypass-1.
    pub(crate) fn nat64_prefixes() -> io::Result<Vec<crate::ip::Prefix>> {
        ASKING.run(CONFIGD_TIMEOUT, || {
            let store = session()?;
            Ok(nat64_prefixes_of(
                keys(&store, NAT64_KEYS)?
                    .into_iter()
                    .filter_map(|k| store.get(k.as_str())),
            ))
        })
    }

    /// The IPv6 prefixes of an RFC 6052 length ([`crate::nat64::NSP_LENS`]) written as strings
    /// (`2001:db8:64::/96`) anywhere among the values of NAT64 dictionaries, alone or in an
    /// array. configd writes its prefix list under a key of its private schema
    /// (`kSCPropNetNAT64PrefixList`), next to discovery times; reading every string value rather
    /// than one key name keeps a renamed key from hiding a prefix, and what is not such a prefix
    /// is ignored (a learned prefix only refuses more). On this Mac the key holds only
    /// `PLATDiscoveryStartTime` and `PLATDiscoveryCompletionTime` (no NAT64 here).
    pub(crate) fn nat64_prefixes_of(
        values: impl IntoIterator<Item = CFPropertyList>,
    ) -> Vec<crate::ip::Prefix> {
        let prefix = |v: &CFPropertyList| -> Option<crate::ip::Prefix> {
            let s = v.downcast::<CFString>()?.to_string();
            let p: crate::ip::Prefix = s.trim().parse().ok()?;
            (p.addr.is_ipv6() && crate::nat64::NSP_LENS.contains(&p.len)).then_some(p)
        };
        let mut out = Vec::new();
        for value in values {
            let Some(dict) = value.downcast::<CFDictionary>() else {
                continue;
            };
            let (_, items) = dict.get_keys_and_values();
            for item in items {
                // SAFETY: a value of a property-list dictionary is a property list, retained here.
                let item = unsafe { CFPropertyList::wrap_under_get_rule(item) };
                if let Some(p) = prefix(&item) {
                    out.push(p);
                } else if let Some(list) = item.downcast::<CFArray>() {
                    for e in list.iter() {
                        // SAFETY: an element of a property-list array is a property list.
                        let e = unsafe { CFPropertyList::wrap_under_get_rule(*e) };
                        out.extend(prefix(&e));
                    }
                }
            }
        }
        out.sort();
        out.dedup();
        out
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
    /// value is not a dictionary or `ServerAddresses` is not an array of strings. A string that
    /// names no address (empty, a host name) is skipped with a warning (review round 3, 12(a)):
    /// configd builds the system's resolvers from these strings with `_SC_string_to_sockaddr`
    /// (`inet_aton`, then `inet_pton` for IPv6) and skips one that does not parse, so it names no
    /// server the system asks; [`numeric`] reads every form those parsers read (and more), so no
    /// server configd would use is skipped here. Round 2 failed the whole facts read for one.
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
            let s = s.to_string();
            let a = numeric(&s);
            if a.is_empty() {
                warn_unparsed(&s);
            }
            out.extend(a);
        }
        Some(out)
    }

    /// Warns once per entry about a `ServerAddresses` string that names no address.
    fn warn_unparsed(entry: &str) {
        static WARNED: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());
        let entry = crate::printable(entry, 80);
        let mut w = WARNED.lock().unwrap_or_else(|e| e.into_inner());
        if !w.contains(&entry) && w.len() < 64 {
            tracing::warn!(
                "network guard: skipping the DNS server {entry:?} of the system configuration: it \
                 names no address (the system skips it too, so it names no resolver)"
            );
            w.push(entry);
        }
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
        ] {
            assert_eq!(server_addresses(&bad), None);
        }
        // Review round 3, 12(a): a string that names no address is skipped (configd skips it
        // too), with a warning; the others are read.
        assert_eq!(
            server_addresses(&dict(strings(&["not-an-ip"]))),
            Some(Vec::new())
        );
        assert_eq!(
            server_addresses(&dict(strings(&["192.0.2.53", "", " ", "dns.example"]))),
            Some(vec![ip("192.0.2.53")])
        );
        let good = dict(strings(&["192.0.2.53"]));
        assert_eq!(
            servers_of([
                ("State:/Network/Global/DNS".to_string(), Some(good.clone())),
                ("State:/Network/Service/gone/DNS".to_string(), None),
            ])
            .unwrap(),
            vec![ip("192.0.2.53")]
        );
        assert_eq!(
            servers_of([
                ("State:/Network/Global/DNS".to_string(), Some(good.clone())),
                (
                    "Setup:/Network/Service/x/DNS".to_string(),
                    Some(dict(strings(&["not-an-ip"]))),
                ),
            ])
            .unwrap(),
            vec![ip("192.0.2.53")]
        );
        let e = servers_of([
            ("State:/Network/Global/DNS".to_string(), Some(good)),
            (
                "Setup:/Network/Service/x/DNS".to_string(),
                Some(dict(CFNumber::from(53i32).as_CFType())),
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

    /// Review round 2, bypass-2, the Linux application, review round 4 (cross-2, bypass-3) and
    /// review round 5 (bypass-1, parse-4): two networks behind the same router address on the
    /// same interface differ by the router's link-layer address in the neighbour table, at once;
    /// the same router read twice is the same uplink; an entry that goes missing, or first
    /// appears, changes nothing; another address is another uplink until the known one shows
    /// again (a flapper never keeps the old one's); once it held it is the known one; with no
    /// address ever known the routes and addressing decide, stably. Pure (every platform).
    #[test]
    fn two_networks_behind_the_same_router_address_are_two_uplinks_on_linux() {
        use crate::routes::Neighbour;
        use std::time::Duration;
        let gw = ip("192.168.1.1");
        let gw6 = ip("fe80::1");
        let table = RouteTable::new(vec![
            Route::via(p("0.0.0.0/0"), gw, 2),
            Route::via(p("::/0"), gw6, 2),
            Route::on_link(p("192.168.1.0/24"), 2),
        ]);
        let addrs = [ip("192.168.1.33")];
        let n = |addr: IpAddr, ifindex: u32, ll: Option<&[u8]>| Neighbour {
            ifindex,
            addr,
            lladdr: ll.map(<[u8]>::to_vec),
        };
        let home = [0xa4, 0x2b, 0xb0, 0, 0, 1];
        let cafe = [0x3c, 0x84, 0x6a, 0, 0, 2];
        let spoof = [0x02, 0, 0, 0, 0, 0x99];
        let t0 = Instant::now();
        let at = |ms: u64| t0 + Duration::from_millis(ms);
        let at_home = [n(gw, 2, Some(&home)), n(gw6, 2, Some(&home))];
        let at_cafe = [n(gw, 2, Some(&cafe)), n(gw6, 2, Some(&cafe))];
        let at_spoof = [n(gw, 2, Some(&spoof)), n(gw6, 2, Some(&spoof))];
        let flushed: [Neighbour; 0] = [];
        let sig = |h: &mut MacHistory, ns: &[Neighbour], t: u64| {
            linux_signature(h, &table, &[2], &addrs, &[], Ok(ns.to_vec()), &[], at(t)).families
        };
        let mut h = MacHistory::new();
        let home_sig = sig(&mut h, &at_home, 0);
        // Known gateways: stable, whatever the order of the table.
        assert_eq!(sig(&mut h, &at_home, 100), home_sig);
        let mut reordered = at_home.to_vec();
        reordered.reverse();
        assert_eq!(sig(&mut h, &reordered, 200), home_sig);
        // cross-2: a flushed table, a FAILED entry, an entry that comes back: the same uplink.
        assert_eq!(sig(&mut h, &flushed, 300), home_sig);
        assert_eq!(sig(&mut h, &[n(gw, 2, None), n(gw6, 2, None)], 400), home_sig);
        assert_eq!(sig(&mut h, &[n(gw, 2, Some(&home))], 500), home_sig);
        assert_eq!(sig(&mut h, &at_home, 600), home_sig);
        // bypass-1: another address is another uplink at once; a flush meanwhile keeps it; the
        // known one showing again is home again.
        let cafe_sig = sig(&mut h, &at_cafe, 700);
        assert_ne!(cafe_sig, home_sig);
        assert_eq!(sig(&mut h, &flushed, 800), cafe_sig);
        assert_eq!(sig(&mut h, &at_home, 900), home_sig);
        // An on-link host flipping the gateway's entry between two addresses (neither known)
        // never gets the home signature, read after read.
        for k in 0..60u64 {
            let ns: &[Neighbour] = if k % 2 == 0 { &at_spoof } else { &at_cafe };
            assert_ne!(sig(&mut h, ns, 1_000 + 1_000 * k), home_sig, "{k}");
        }
        // Review round 6, cross-4: the flips are one unsettled state (one uplink, not one a
        // read), and none held (two addresses in turn never show the same one on 3 reads in a
        // row): the known one showing again is home again.
        let last = sig(&mut h, &at_cafe, 70_000);
        assert_eq!(last, cafe_sig, "one unsettled state");
        assert_eq!(sig(&mut h, &flushed, 70_100), last);
        assert_eq!(sig(&mut h, &at_home, 70_200), home_sig);
        // A real move (no carrier change: one would change the base): the café's address from
        // the first read on (unsettled), and once it held (3 reads in a row, 2 s) the café's own;
        // a flush keeps it.
        let mut h = MacHistory::new();
        assert_eq!(sig(&mut h, &at_home, 0), home_sig);
        let unsettled = sig(&mut h, &at_cafe, 1_000);
        assert_ne!(unsettled, home_sig);
        assert_eq!(sig(&mut h, &at_cafe, 2_000), unsettled);
        let moved = sig(&mut h, &at_cafe, 3_000);
        assert_ne!(moved, home_sig);
        assert_eq!(sig(&mut h, &at_cafe, 5_000), moved);
        assert_eq!(sig(&mut h, &flushed, 6_000), moved);
        // A spoofed address seen once before the café's: the same unsettled state, and the
        // café's once it held (the latest address counts, not the first other one: cross-3).
        let mut h3 = MacHistory::new();
        sig(&mut h3, &at_home, 0);
        assert_eq!(sig(&mut h3, &at_spoof, 1_000), unsettled);
        assert_eq!(sig(&mut h3, &at_cafe, 1_500), unsettled);
        sig(&mut h3, &at_cafe, 2_500);
        assert_eq!(sig(&mut h3, &at_cafe, 3_600), moved);
        // Three reads of another address within 2 s do not make it the known one: home again.
        let mut h4 = MacHistory::new();
        sig(&mut h4, &at_home, 0);
        for t in [100, 200, 300] {
            sig(&mut h4, &at_cafe, t);
        }
        assert_eq!(sig(&mut h4, &at_home, 400), home_sig, "not held for 2 s");
        // Back home: another change again (never the café's, never a merge).
        let back = sig(&mut h, &at_home, 7_000);
        assert_ne!(back, moved);
        // An entry on another interface, or for another address, is not the gateway's.
        let elsewhere = [
            n(gw, 3, Some(&cafe)),
            n(ip("192.168.1.2"), 2, Some(&cafe)),
            n(gw6, 2, Some(&home)),
        ];
        assert_eq!(
            gateway_identities(&table, &[], &elsewhere),
            vec![(gw, 2, None), (gw6, 2, Some(home.to_vec()))]
        );
        // parse-4: no gateway's address ever known (or the table cannot be read): one stable
        // signature, the first known one changes nothing, and it holds.
        let denied = || Err(io::Error::from_raw_os_error(13));
        let mut fresh = MacHistory::new();
        let a = sig(&mut fresh, &flushed, 0);
        assert_eq!(sig(&mut fresh, &[n(gw, 2, None)], 10), a);
        assert_eq!(
            linux_signature(&mut fresh, &table, &[2], &addrs, &[], denied(), &[], at(15)).families,
            a
        );
        assert_eq!(sig(&mut fresh, &[n(gw, 2, Some(&home)), n(gw6, 2, None)], 20), a);
        assert_eq!(sig(&mut fresh, &at_home, 30), a, "the IPv6 gateway's entry appeared");
        assert_eq!(a, home_sig, "the same network as the first history's");
        // The table that cannot be read: the known address stands.
        assert_eq!(
            linux_signature(&mut h, &table, &[2], &addrs, &[], denied(), &[], at(16_000)).families,
            back
        );
        // A device without link-layer addresses (NOARP, an empty one) is a stable identity.
        let tun = RouteTable::new(vec![Route::via(p("0.0.0.0/0"), ip("10.8.0.1"), 9)]);
        let ids = gateway_identities(&tun, &[], &[n(ip("10.8.0.1"), 9, Some(&[]))]);
        assert_eq!(ids, vec![(ip("10.8.0.1"), 9, Some(Vec::new()))]);
        let mut h2 = MacHistory::new();
        assert_eq!(h2.signature(1, &ids, true, t0), h2.signature(1, &ids, true, at(5)));
        // No gateway at all (an on-link default): nothing to look up, the routes decide.
        let onlink = RouteTable::new(vec![Route::on_link(p("0.0.0.0/0"), 9)]);
        assert!(gateway_identities(&onlink, &[], &[]).is_empty());
        assert_eq!(h2.signature(7, &[], true, t0), h2.signature(7, &[], true, at(5)));
        // Other bases are other uplinks.
        assert_ne!(h2.signature(7, &[], true, t0), h2.signature(8, &[], true, t0));
    }

    /// Review round 5 (bypass-1, parse-4): the uplink's addressing is part of the Linux
    /// signature: two IPv6-only networks behind `fe80::1` differ by their global prefix, two
    /// IPv4 ones behind 192.168.1.1 by their subnet or the address handed out, with no
    /// neighbour entry at all; a link-local prefix, another interface's routes, an IPv6
    /// address that changes within the prefix (privacy addresses) and a route that is not
    /// on-link change nothing.
    #[test]
    fn r5_the_uplinks_addressing_tells_networks_apart_on_linux() {
        use std::time::Duration;
        let t0 = Instant::now();
        let sig = |routes: Vec<Route>, addrs: &[&str]| {
            let table = RouteTable::new(routes);
            let addrs: Vec<IpAddr> = addrs.iter().map(|a| ip(a)).collect();
            let mut h = MacHistory::new();
            linux_signature(&mut h, &table, &[3], &addrs, &[], Ok(Vec::new()), &[], t0)
        };
        let v6 = |prefix: &str| {
            vec![
                Route::via(p("::/0"), ip("fe80::1"), 3),
                Route::on_link(p(prefix), 3),
                Route::on_link(p("fe80::/64"), 3),
            ]
        };
        let home = sig(v6("2a01:4f8:a:1::/64"), &["2a01:4f8:a:1::5"]);
        assert_ne!(home, sig(v6("2a01:4f8:b:1::/64"), &["2a01:4f8:b:1::5"]));
        assert_eq!(home, sig(v6("2a01:4f8:a:1::/64"), &["2a01:4f8:a:1::77"]));
        let mut other_if = v6("2a01:4f8:a:1::/64");
        other_if.push(Route::on_link(p("2a01:4f8:dead::/64"), 9));
        other_if.push(Route::on_link(p("fe80::/64"), 4));
        assert_eq!(home, sig(other_if, &["2a01:4f8:a:1::5"]));
        // The uplink's link-local prefix is the same on every network: not hashed.
        let mut no_ll = v6("2a01:4f8:a:1::/64");
        no_ll.retain(|r| r.prefix != p("fe80::/64"));
        assert_eq!(home, sig(no_ll, &["2a01:4f8:a:1::5"]));
        let v4 = |subnet: &str| {
            vec![
                Route::via(p("0.0.0.0/0"), ip("192.168.1.1"), 3),
                Route::on_link(p(subnet), 3),
                Route::via(p("10.9.0.0/16"), ip("192.168.1.254"), 3),
            ]
        };
        let a = sig(v4("192.168.1.0/24"), &["192.168.1.33"]);
        assert_ne!(a, sig(v4("192.168.1.0/24"), &["192.168.1.34"]));
        assert_ne!(a, sig(v4("192.168.0.0/23"), &["192.168.1.33"]));
        assert_eq!(a, sig(v4("192.168.1.0/24"), &["192.168.1.33", "172.17.0.1"]));
        let _ = Duration::ZERO;
    }

    /// Review round 5, cross-4: with `nexthop_compat_mode` 0 a default route through a nexthop
    /// object shows no gateway; its gateways come from the nexthop dump (a group's members'),
    /// so they are the uplink's identities and the routers whose PREF64 is heard.
    #[test]
    fn r5_a_nexthop_objects_gateways_are_the_uplinks() {
        use crate::routes::{Hop, Neighbour, Nexthop};
        let mut r4 = Route::via(p("0.0.0.0/0"), ip("192.168.1.1"), 0);
        r4.hop = Hop::Unknown;
        r4.nexthop = 10;
        let mut r6 = Route::via(p("::/0"), ip("fe80::1"), 0);
        r6.hop = Hop::Unknown;
        r6.nexthop = 20;
        let table = RouteTable::new(vec![r4, r6]);
        let nh = |id: u32, oif: u32, gw: Option<&str>, group: Vec<u32>| Nexthop {
            id,
            oif,
            gateway: gw.map(ip),
            group,
            blackhole: false,
        };
        let nexthops = vec![
            nh(10, 2, Some("192.168.1.1"), vec![]),
            nh(21, 2, Some("fe80::1"), vec![]),
            nh(22, 5, Some("fe80::2"), vec![]),
            nh(20, 0, None, vec![21, 22]),
            // A nexthop with a gateway and no device names no uplink gateway (cross-3).
            nh(23, 0, Some("fe80::3"), vec![]),
            nh(24, 0, None, vec![23]),
        ];
        assert!(crate::routes::nexthop_gateways(&nexthops, 24).is_empty());
        assert!(crate::routes::nexthop_gateways(&nexthops, 23).is_empty());
        assert_eq!(
            default_gateways(&table, &nexthops),
            vec![(ip("192.168.1.1"), 2), (ip("fe80::1"), 2), (ip("fe80::2"), 5)]
        );
        assert!(default_gateways(&table, &[]).is_empty());
        // cross-3 (`facts.rs:488`): a route that is not default-like names no uplink gateway (nor
        // a router whose PREF64 is heard).
        let mixed = RouteTable::new(vec![
            Route::via(p("::/0"), ip("fe80::1"), 2),
            Route::via(p("2a01:4f8::/32"), ip("fe80::9"), 2),
            Route::via(p("10.9.0.0/16"), ip("192.168.1.254"), 2),
        ]);
        assert_eq!(default_gateways(&mixed, &[]), vec![(ip("fe80::1"), 2)]);
        let mac = [1u8, 2, 3, 4, 5, 6];
        let ids = gateway_identities(
            &table,
            &nexthops,
            &[Neighbour {
                ifindex: 2,
                addr: ip("192.168.1.1"),
                lladdr: Some(mac.to_vec()),
            }],
        );
        assert_eq!(ids[0], (ip("192.168.1.1"), 2, Some(mac.to_vec())));
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

    /// Review round 3, bypass-1 (every platform since the Linux application): the facts of a host with IPv6 and no IPv4 route that has
    /// just joined a network (an uplink signature not seen before) refuse IPv6 until that
    /// network's NAT64 round has finished, and so, since review round 5 (bypass-4), do those of
    /// a host whose IPv4 goes out through a CLAT; a dual-stack host's never do.
    #[test]
    fn a_new_ipv6_only_uplink_is_unsettled_until_its_round_ends() {
        use crate::routes::Route;
        use std::time::Duration;
        use std::hash::{BuildHasher, Hasher};
        let fresh = || {
            std::collections::hash_map::RandomState::new()
                .build_hasher()
                .finish()
        };
        let v6_only = RouteTable::new(vec![Route::via(p("::/0"), ip("fe80::1"), 4)]);
        let dual = RouteTable::new(vec![
            Route::via(p("::/0"), ip("fe80::1"), 4),
            Route::via(p("0.0.0.0/0"), ip("192.0.2.1"), 4),
        ]);
        // The process's first round runs on the caller's thread; the next uplinks' in the
        // background. Review round 5, bypass-4: a host whose IPv4 goes through a CLAT is an
        // IPv6-only one.
        nat64_unsettled_on(&dual, &[], fresh(), false);
        assert!(nat64_unsettled_on(&v6_only, &[], fresh(), false).0);
        assert!(!nat64_unsettled_on(&dual, &[], fresh(), false).0);
        let behind_clat = fresh();
        assert!(nat64_unsettled_on(&dual, &[], behind_clat, true).0);
        let t = Instant::now();
        while nat64_unsettled_on(&dual, &[], behind_clat, true).0 && t.elapsed() < Duration::from_secs(10) {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(!nat64_unsettled_on(&dual, &[], behind_clat, true).0, "settled once its round ended");
        // Review round 4, bypass-1: a prefix named on the uplink that could not be held refuses
        // IPv6 there, on a dual-stack host too.
        let held = fresh();
        nat64_unsettled_on(&dual, &[], held, false);
        crate::nat64::unheld_after_round(held, "test: one source named too many");
        let (_, why) = nat64_unsettled_on(&dual, &[], held, false);
        assert!(why.is_some_and(|w| w.ends_with("test: one source named too many")));
        assert!(nat64_unsettled_on(&dual, &[], fresh(), false).1.is_none());
    }

    /// Review round 4, cross-4: with nexthop objects (`nexthop_compat_mode` 0: the dump shows no
    /// gateway and no interface), a default-like route of the kernel's answer is held only when
    /// it goes through the same nexthop object as one of the facts' default routes, and that
    /// object resolves in the facts' nexthop dump; any other (a `0.0.0.0/1 nhid 30` via a LAN box
    /// that came up after the facts were read) is off the default path.
    #[test]
    fn r4_a_nexthop_object_default_is_held_only_through_the_same_object() {
        use crate::routes::{Hop, KernelAnswer, Nexthop};
        let nh = |prefix: &str, id: u32| Route {
            hop: Hop::Unknown,
            ifindex: 0,
            nexthop: id,
            ..Route::via(p(prefix), ip("192.0.2.1"), 0)
        };
        let routes = RouteTable::new(vec![nh("0.0.0.0/0", 10)]);
        let nexthops = vec![
            Nexthop {
                id: 10,
                oif: 2,
                gateway: None,
                group: vec![],
                blackhole: false,
            },
            Nexthop {
                id: 30,
                oif: 2,
                gateway: None,
                group: vec![],
                blackhole: false,
            },
        ];
        let answer = |r: Route| KernelAnswer::Entry(vec![r]);
        assert_eq!(default_path_known(&routes, &nexthops, &answer(nh("0.0.0.0/0", 10))), Ok(()));
        let e = default_path_known(&routes, &nexthops, &answer(nh("0.0.0.0/1", 30)));
        assert!(e.is_err(), "another nexthop object held: {e:?}");
        // The facts' object that does not resolve in their dump: not held either.
        assert!(default_path_known(&routes, &[], &answer(nh("0.0.0.0/0", 10))).is_err());
        // A route with a gateway shown (compat mode 1 shows both) still needs the same object.
        let shown = |id| Route {
            nexthop: id,
            ..Route::via(p("0.0.0.0/0"), ip("192.168.1.1"), 2)
        };
        let compat1 = RouteTable::new(vec![shown(10)]);
        assert_eq!(default_path_known(&compat1, &nexthops, &answer(shown(10))), Ok(()));
        assert!(default_path_known(&compat1, &nexthops, &answer(shown(30))).is_err());
        // Plain routes as before.
        let plain = RouteTable::new(vec![Route::via(p("0.0.0.0/0"), ip("192.168.1.1"), 2)]);
        assert_eq!(
            default_path_known(&plain, &[], &answer(Route::via(p("0.0.0.0/1"), ip("192.168.1.1"), 2))),
            Ok(())
        );
        assert!(default_path_known(&plain, &[], &answer(Route::via(p("0.0.0.0/1"), ip("192.168.1.9"), 2))).is_err());
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

/// Review round 6: the Linux uplink identity (bypass-2 = cross-5, cross-4, the L=0 suspicion,
/// cross-7 F21/F24/V02/V05) and the CLAT warning.
#[cfg(test)]
mod r6_tests {
    use super::*;
    use crate::routes::{Link, Neighbour, Nexthop, Route, RouteType};
    use std::time::Duration;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }
    fn p(s: &str) -> Prefix {
        s.parse().unwrap()
    }
    fn n(addr: IpAddr, ll: Option<&[u8]>) -> Neighbour {
        Neighbour { ifindex: 2, addr, lladdr: ll.map(<[u8]>::to_vec) }
    }

    const HOME: [u8; 6] = [0xa4, 0x2b, 0xb0, 0, 0, 1];
    const CAFE: [u8; 6] = [0x3c, 0x84, 0x6a, 0, 0, 2];

    fn table() -> RouteTable {
        RouteTable::new(vec![
            Route::via(p("0.0.0.0/0"), ip("192.168.1.1"), 2),
            Route::via(p("::/0"), ip("fe80::1"), 2),
            Route::on_link(p("192.168.1.0/24"), 2),
        ])
    }

    fn sig(h: &mut MacHistory, ns: Vec<Neighbour>, carriers: &[(u32, u32)], ms: u64, t0: Instant) -> UplinkId {
        linux_signature(h, &table(), &[2], &[ip("192.168.1.100")], &[], Ok(ns), carriers, t0 + Duration::from_millis(ms))
    }

    /// bypass-2 = cross-5 (`r6_the_first_reads_after_a_move_are_the_old_network`,
    /// `r6cross_a_move_with_a_flushed_neighbour_table_is_the_old_network`): after a move over a
    /// link that went down to a network numbered alike, the first reads (the neighbour table
    /// emptied) were the old network's. Now: the carrier change is part of the base (another
    /// uplink at once); and with no carrier change seen, a gateway whose address was known and
    /// has no entry is unresolved (that family refused) until it resolves, to the old address
    /// (the old network, nothing refused any more) or another (unsettled).
    #[test]
    fn r6_a_move_with_a_flushed_neighbour_table_is_never_the_old_network() {
        let t0 = Instant::now();
        let gw = ip("192.168.1.1");
        let mut h = MacHistory::new();
        let home = sig(&mut h, vec![n(gw, Some(&HOME))], &[(2, 4)], 0, t0);
        assert_eq!(home.unresolved, [false, false]);
        // The link bounced: another base, another uplink, whatever the table holds.
        let bounced = sig(&mut h, vec![], &[(2, 6)], 5_000, t0);
        assert_ne!(bounced.families[0], home.families[0]);
        // No carrier change seen (a dump without the attribute, or a flush): unresolved.
        let mut h = MacHistory::new();
        let home = sig(&mut h, vec![n(gw, Some(&HOME))], &[], 0, t0);
        let flushed = sig(&mut h, vec![], &[], 5_000, t0);
        assert_eq!(flushed.families, home.families);
        assert_eq!(flushed.unresolved, [true, false]);
        let cafe = sig(&mut h, vec![n(gw, Some(&CAFE))], &[], 5_300, t0);
        assert_ne!(cafe.families[0], home.families[0]);
        assert_eq!(cafe.families[1], home.families[1], "IPv6's gateway did not change");
        assert_eq!(cafe.unresolved, [false, false]);
        // An ordinary flush with no move: refused only until the entry resolves again.
        let mut h = MacHistory::new();
        let home = sig(&mut h, vec![n(gw, Some(&HOME))], &[], 0, t0);
        assert!(sig(&mut h, vec![n(gw, None)], &[], 1_000, t0).unresolved[0]);
        assert_eq!(sig(&mut h, vec![n(gw, Some(&HOME))], &[], 1_050, t0), home);
        // A table that cannot be read refuses nothing (review round 5, parse-4).
        let denied = linux_signature(&mut h, &table(), &[2], &[ip("192.168.1.100")], &[], Err(io::Error::from_raw_os_error(13)), &[], t0);
        assert_eq!(denied, home);
        // What the facts make of it: the family is refused as relearning, the other is not.
        let f = HostFacts::assemble(
            RawFacts {
                routes: table().routes().to_vec(),
                gateway_unresolved: [true, false],
                ..RawFacts::default()
            },
            &FactsOptions { public_addresses: vec![ip("9.9.9.7"), ip("2a02:db8::7")], ..FactsOptions::default() },
        );
        assert!(f.path_known(ip("1.1.1.1")).is_err() && f.relearning(EgressPath::Ipv4));
        assert!(f.path_known(ip("2606:4700:4700::1111")).is_ok());
    }

    /// The L=0 suspicion: two IPv6 networks behind fe80::1 whose prefixes are announced without
    /// the on-link flag (no on-link route) differ by the /64 of the host's global address; an
    /// address that changes within the /64 (privacy addresses) changes nothing.
    #[test]
    fn r6_the_hosts_ipv6_64s_are_part_of_the_base() {
        let t0 = Instant::now();
        let table = RouteTable::new(vec![Route::via(p("::/0"), ip("fe80::1"), 3)]);
        let sig = |addrs: &[&str]| {
            let a: Vec<IpAddr> = addrs.iter().map(|s| ip(s)).collect();
            linux_signature(&mut MacHistory::new(), &table, &[3], &a, &[], Ok(vec![]), &[], t0).families
        };
        assert_ne!(sig(&["2a01:4f8:a:1::5"]), sig(&["2a01:4f8:b:1::5"]));
        assert_eq!(sig(&["2a01:4f8:a:1::5"]), sig(&["2a01:4f8:a:1:1234::77"]));
        assert_eq!(sig(&["2a01:4f8:a:1::5"]), sig(&["2a01:4f8:a:1::5", "fe80::5", "fd00::5"]));
    }

    /// cross-4 (live `r6-cross/vm-r6-flap.log`: a new spoofed IPv4 gateway MAC every second
    /// refused both families, 100%): on random sequences of reads (the real address, a
    /// spoofer's new one each time, flushes), IPv6's signature never changes for the IPv4
    /// gateway's address; whenever the known address shows, the signature is home's; and the
    /// IPv4 signatures seen are home's and one unsettled state, unless one address held (the
    /// same address on 3 reads in a row over 2 s), which then counts once.
    #[test]
    fn r6_a_spoofer_of_the_ipv4_gateway_makes_one_unsettled_state() {
        let gw = ip("192.168.1.1");
        let gw6 = ip("fe80::1");
        for seed in 1..=50u64 {
            let mut x = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
            let mut rnd = move |n: u64| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                x % n
            };
            let t0 = Instant::now();
            let mut h = MacHistory::new();
            let v6 = n(gw6, Some(&[0xaa, 0, 0, 0, 0, 1]));
            let home = sig(&mut h, vec![n(gw, Some(&HOME)), v6.clone()], &[], 0, t0);
            let mut seen = vec![home.families[0]];
            let mut ms = 0;
            let (mut last_mac, mut run) = (HOME.to_vec(), 0u32);
            for _ in 0..300 {
                ms += 200 + rnd(1_000);
                let (ns, mac) = match rnd(4) {
                    0 => (vec![n(gw, Some(&HOME)), v6.clone()], Some(HOME.to_vec())),
                    1 => (vec![v6.clone()], None),
                    _ => {
                        let m = vec![0x02, 0, 0, 0, (rnd(250) + 1) as u8, rnd(250) as u8];
                        (vec![n(gw, Some(&m)), v6.clone()], Some(m))
                    }
                };
                let id = sig(&mut h, ns, &[], ms, t0);
                assert_eq!(id.families[1], home.families[1], "seed {seed}: IPv6 moved with the IPv4 gateway");
                if mac.as_deref() == Some(&HOME[..]) {
                    assert_eq!(id.families[0], home.families[0], "seed {seed}");
                }
                if let Some(m) = mac {
                    run = if m[..] == HOME[..] { 0 } else if m == last_mac { run + 1 } else { 1 };
                    last_mac = m;
                }
                if !seen.contains(&id.families[0]) {
                    seen.push(id.families[0]);
                }
                assert!(run < MAC_CHANGE_READS, "seed {seed}: a random address repeated");
            }
            assert!(seen.len() <= 2, "seed {seed}: {} IPv4 uplinks from one spoofer", seen.len());
        }
    }

    /// cross-7 F21: the history keeps several bases: back on a base whose gateway's address was
    /// known, another address there is another network (were only the latest base kept, it
    /// would be first seen: no change).
    #[test]
    fn r6_the_mac_history_keeps_several_bases() {
        let t0 = Instant::now();
        let gw = ip("192.168.1.1");
        let mut h = MacHistory::new();
        let home = sig(&mut h, vec![n(gw, Some(&HOME))], &[], 0, t0);
        let other = linux_signature(&mut h, &RouteTable::new(vec![Route::via(p("0.0.0.0/0"), ip("10.0.0.1"), 2)]), &[2], &[ip("10.0.0.5")], &[], Ok(vec![n(ip("10.0.0.1"), Some(&CAFE))]), &[], t0);
        assert_ne!(other.families, home.families);
        let back = sig(&mut h, vec![n(gw, Some(&CAFE))], &[], 1_000, t0);
        assert_ne!(back.families[0], home.families[0]);
    }

    /// cross-7 F24: only unicast on-link routes are the uplink's addressing (a broadcast or local
    /// route on the uplink changes nothing).
    #[test]
    fn r6_only_unicast_on_link_routes_are_addressing() {
        let mut bcast = Route::on_link(p("192.168.1.255/32"), 2);
        bcast.kind = RouteType::Broadcast;
        let mut with = table().routes().to_vec();
        with.push(bcast);
        let a = uplink_addressing(&table(), &[2], &[ip("192.168.1.100")], &[]);
        let b = uplink_addressing(&RouteTable::new(with), &[2], &[ip("192.168.1.100")], &[]);
        assert_eq!(a, b);
    }

    /// cross-7 V05 and the CLAT suspicion: the IPv4 default's interfaces, a nexthop object's
    /// included (ifindex 0), are what the CLAT test and the warning see.
    #[test]
    fn r6_the_ipv4_defaults_interfaces_include_a_nexthop_objects() {
        let mut r = Route::via(p("0.0.0.0/0"), ip("192.0.0.1"), 0);
        r.nexthop = 7;
        let table = RouteTable::new(vec![r, Route::via(p("::/0"), ip("fe80::1"), 2)]);
        let links = vec![
            Link { index: 2, name: "wlan0".into(), kind: None },
            Link { index: 9, name: "v4-wlan0".into(), kind: Some("tun".into()) },
        ];
        let nexthops = vec![Nexthop { id: 7, oif: 9, gateway: None, group: vec![], blackhole: false }];
        let v4 = v4_default_links(&table, &links, &nexthops);
        assert_eq!(v4.iter().map(|l| l.name.as_str()).collect::<Vec<_>>(), ["v4-wlan0"]);
        let names: Vec<String> = v4.iter().map(|l| l.name.clone()).collect();
        assert!(crate::nat64::clat_in_use(&[], &names));
        assert!(tunnelled_ipv4(&v4));
        let plain = RouteTable::new(vec![Route::via(p("0.0.0.0/0"), ip("192.168.1.1"), 2)]);
        assert!(!tunnelled_ipv4(&v4_default_links(&plain, &links, &[])));
        let utun = vec![Link { index: 2, name: "utun3".into(), kind: Some("tun".into()) }];
        assert!(tunnelled_ipv4(&v4_default_links(&plain, &utun, &[])));
        for name in ["clat", "v4-rmnet0", "tun0"] {
            let l = vec![Link { index: 2, name: name.into(), kind: None }];
            assert!(tunnelled_ipv4(&v4_default_links(&plain, &l, &[])), "{name}");
        }
        let eth = vec![Link { index: 2, name: "eth0".into(), kind: None }];
        assert!(!tunnelled_ipv4(&v4_default_links(&plain, &eth, &[])));
    }

    /// Review round 6 (fix-r6 mutation L02, Linux, live): asking for a neighbour makes the kernel
    /// resolve it (an entry appears, at least incomplete), unprivileged. An address of the IPv4
    /// default gateway's subnet that no entry holds: one ARP request.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn r6_asking_for_a_neighbour_makes_the_kernel_resolve_it() {
        let f = HostFacts::gather_with(&FactsOptions { discover_public_addresses: false, ..FactsOptions::default() }).unwrap();
        let Some((gw, ifindex)) = default_gateways(f.routes(), &[]).into_iter().find(|(g, _)| g.is_ipv4()) else {
            crate::skipped("no IPv4 default gateway here");
            return;
        };
        let IpAddr::V4(g) = gw else { unreachable!() };
        let table = crate::routes::read_neighbours().unwrap();
        let Some(probe) = (1..255u8)
            .rev()
            .map(|last| IpAddr::from([g.octets()[0], g.octets()[1], g.octets()[2], last]))
            .find(|a| *a != gw && !table.iter().any(|n| n.addr == *a) && !f.own_addresses().contains(a))
        else {
            crate::skipped("no free address in the gateway's /24");
            return;
        };
        ask_for_neighbour(probe, ifindex);
        let t = Instant::now();
        while t.elapsed() < RESOLVE_WAIT {
            if crate::routes::read_neighbours().unwrap().iter().any(|n| n.addr == probe) {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        panic!("no neighbour entry for {probe} after asking");
    }

    /// cross-7 V02 (Linux, live): the facts read the neighbour table (a host with an IPv4
    /// default gateway has its entry, the read asking for it when missing).
    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn r6_the_facts_read_the_neighbour_table() {
        let f = HostFacts::gather_with(&FactsOptions { discover_public_addresses: false, ..FactsOptions::default() }).unwrap();
        let gws = default_gateways(f.routes(), &[]);
        if !gws.iter().any(|(g, _)| g.is_ipv4()) {
            crate::skipped("no IPv4 default gateway here".to_string());
            return;
        }
        let ids = LAST_NEIGHBOURS_READ.lock().unwrap().clone().expect("the table was read");
        assert!(ids.iter().any(|(g, _, mac)| g.is_ipv4() && mac.is_some()), "{ids:?}");
    }
}
