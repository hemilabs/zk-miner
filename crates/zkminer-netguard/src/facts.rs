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
//! - **site prefixes:** the enclosing /`ipv6_site_prefix_len` (default /48) of every own global
//!   IPv6 address. A home or office is delegated a /56 or a /48 and numbers its other networks
//!   from it, none of which the host's own /64 shows; and the enclosing /`ipv4_site_prefix_len`
//!   (default /16) of every global IPv4 address on an interface (a campus or data centre numbered
//!   from public space reaches its other subnets through the default gateway);
//! - **public-address knowledge:** per family the host routes, whether its public address is
//!   known (learned reliably or configured); a family whose is not refuses every connection
//!   ([`HostFacts::unknown_paths`]);
//! - **tunnel uplinks and global IPv4 interface addresses**, which make a public-mode start need
//!   `[egress] internal_ranges` ([`HostFacts::needs_internal_ranges`]);
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

/// The default `[egress] ipv6_site_prefix_len`: a /48, the most a site is usually delegated.
pub const DEFAULT_IPV6_SITE_PREFIX_LEN: u8 = 48;
/// The lengths `[egress] ipv6_site_prefix_len` may take.
pub const IPV6_SITE_PREFIX_LENS: RangeInclusive<u8> = 32..=64;
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
    /// The interfaces the kernel sends internet traffic out of (for default routes through a
    /// nexthop object, whose interface the route dump does not show).
    pub internet_interfaces: Vec<u32>,
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
    /// `(name, kind)` of every tunnel interface a default route goes out of.
    tunnel_uplinks: Vec<(String, String)>,
    /// The global IPv4 addresses on the host's interfaces.
    global_v4_interfaces: Vec<IpAddr>,
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
            tunnel_uplinks: Vec::new(),
            global_v4_interfaces: Vec::new(),
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
        // The interfaces internet traffic leaves by: those of the default routes, and the
        // kernel's answer where a route names a nexthop object instead.
        let mut uplink_ifs = routes.default_interfaces();
        uplink_ifs.retain(|i| *i != 0);
        uplink_ifs.extend(&raw.internet_interfaces);
        let tunnel_uplinks = sorted(
            raw.links
                .iter()
                .filter(|l| uplink_ifs.contains(&l.index) && l.is_tunnel())
                .map(|l| (l.name.clone(), l.kind.clone().unwrap_or_default()))
                .collect(),
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
            tunnel_uplinks,
            global_v4_interfaces,
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

    /// Why this host may not start in public mode without `[egress] internal_ranges`: each
    /// global IPv4 address on its interfaces (its network is numbered from public space, and its
    /// other subnets are reached through the default gateway), and each tunnel a default route
    /// goes out of (the far side's own hosts look like the internet). Empty when neither holds.
    pub fn needs_internal_ranges(&self) -> Vec<String> {
        let mut why: Vec<String> = self
            .global_v4_interfaces
            .iter()
            .map(|a| format!("this host has the global IPv4 address {a} on an interface"))
            .collect();
        why.extend(self.tunnel_uplinks.iter().map(|(name, kind)| {
            format!("this host's default route goes out of {name}, a {kind} tunnel")
        }));
        why
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
    /// kernel as the route oracle. Fails if the interfaces or the routing table cannot be read: a
    /// public-mode policy that does not know them cannot refuse what they name.
    pub fn gather_with(opts: &FactsOptions) -> io::Result<Self> {
        let (interface_prefixes, interface_addresses, loopback) = sys::interfaces()?;
        // The NAT64 prefixes the host's DNS64 reveals (process-wide; the first call asks).
        crate::nat64::ensure_discovered();
        let (routes, rules) = crate::routes::read_routing(&loopback)?;
        let links = crate::routes::read_links()?;
        let public = if opts.discover_public_addresses {
            crate::public::learned()
        } else {
            crate::public::Learned::default()
        };
        Ok(Self::assemble(
            RawFacts {
                interface_prefixes,
                interface_addresses,
                routes,
                rules,
                resolvers: system_resolvers(),
                public_addresses: public.addresses,
                public_confirmed: public.confirmed,
                public_via_nat64: public.via_nat64,
                links,
                internet_interfaces: crate::routes::internet_interfaces(),
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
pub fn system_resolvers() -> Vec<IpAddr> {
    sorted(
        RESOLV_CONF_PATHS
            .iter()
            .filter_map(|p| std::fs::read_to_string(p).ok())
            .flat_map(|t| parse_nameservers(&t))
            .collect(),
    )
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

    /// The prefix length of a netmask, read in the address's family (some systems leave the
    /// netmask's own `sa_family` zero).
    ///
    /// # Safety
    /// `sa` is null or points to a sockaddr_in (`v4`) or sockaddr_in6.
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
        // The default: a /48, the most a site is usually delegated.
        let f = HostFacts::assemble(raw.clone(), &offline());
        assert_eq!(
            f.site_prefixes(),
            &[p("2606:a300:9024::/48"), p("2a01:4f8:1::/48")]
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
        let f32 = HostFacts::assemble(
            raw,
            &FactsOptions {
                ipv6_site_prefix_len: 32,
                ..offline()
            },
        );
        assert_eq!(
            f32.site_prefixes(),
            &[p("2606:a300::/32"), p("2a01:4f8::/32")]
        );
        assert_eq!(
            site_prefixes(&[ip("2606:a300::1")], 99),
            vec![p("2606:a300::/64")]
        );
        assert!(FactsOptions::default().validate().is_ok());
        for bad in [31u8, 65, 0, 128] {
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
                p("2606:a300:9024::/48"),
                p("2606:a300:9024:184::/64"),
            ]
        );
    }
}
