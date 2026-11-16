//! The host's routing table, and the best-route rule (review r1, fetch F1 / broker F1).
//!
//! An interface's netmask does not say everything the host is directly attached to. A DHCPv6
//! address is a /128 while the router advertises its /64 as on-link (a route, `proto ra`); an IPv4
//! address can be a /32 with the subnet installed as a route; a VPN, WireGuard, Tailscale or Docker
//! network is a route on its own interface, sometimes to global addresses. So the facts include
//! every unicast route of every routing table (netlink `RTM_GETROUTE`, which needs no privileges)
//! with its table, the routes that deliver to the host itself, and the policy-routing rules, and
//! two rules come from the routes:
//!
//! - **on-link routes are connected prefixes:** a unicast route with no gateway, not on a loopback
//!   interface and not a default route names a network the host reaches directly
//!   ([`RouteTable::on_link_prefixes`]);
//! - **the best route must be the default path** ([`RouteTable::off_default_path`]): for a
//!   destination, the routes whose prefix holds it with the longest prefix length (the kernel's
//!   longest-prefix match) must all take the default path, else the destination is refused. A
//!   route takes the default path when it is a default route — `0.0.0.0/0`, `::/0`, or a
//!   "split default" no longer than /[`DEFAULT_LIKE_MAX_LEN`] (`0.0.0.0/1` + `128.0.0.0/1`,
//!   `2000::/4`, …: how full-tunnel VPNs override the default without replacing it), whether it has
//!   a gateway or not (a PPPoE or WireGuard uplink is a gateway-less default route) — or when it
//!   goes through the gateway, on the interface, of a true default route (`/0`): a DHCP option 121
//!   route to a DNS or NTP server via the home router reaches nothing the default route does not.
//!   Anything else — an on-link route, a route on a loopback interface, a route through another
//!   gateway (a VPN's pushed routes, a static route into a DMZ), a route through a nexthop object
//!   whose gateway the dump does not show — is refused.
//!
//! **Policy routing** (review r2, R2-NG-2 / R2-NG-3). The facts include the policy-routing rules
//! (netlink `RTM_GETRULE`, unprivileged), and each is read for this process's own outgoing
//! connections ([`Rule::matches`]): firewall mark 0, this process's uid, input interface `lo`,
//! no output interface, TOS 0, TCP. A rule's selectors either always match those connections,
//! never do, or depend on the connection (`from`, ports, flow labels, or a selector this code
//! does not know). Then:
//!
//! - **ordinary tables** are those a rule with no destination selector that always matches
//!   sends every connection to (`local`, `main` and `default` on a stock host; a wg-quick or
//!   Mullvad `not fwmark … lookup …` table too). Only their default routes are default routes:
//!   the **uplinks** — `(gateway, interface)` of their `/0` routes, which make another route
//!   through the same gateway default-path — come from them alone, and a default-like route of
//!   any other table (a VPN table's `default via 10.8.0.1`, which only a selector sends traffic
//!   to) is neither a default route nor an uplink;
//! - **destination rules** (`to 52.95.0.0/16 lookup 100`) that send a prefix to a table that is
//!   not ordinary refuse that whole prefix ([`RouteKind::PolicyRule`]), whatever the table holds;
//! - every other route of every table is merged, as before: a specific route of any table that
//!   does not take the default path refuses its destinations, even where no rule would consult
//!   that table. A table only a source (`from`) or port rule reaches has its default route left
//!   out: such a table is used for connections whose source the ordinary tables already chose
//!   (a VPN's own address, so its routes are already off the default path), or for some ports
//!   only; see SECURITY.md's known limits.
//!
//! This prefix model is what a consumer that knows only prefixes gets (the witness broker, an
//! operator's role entry: [`RouteTable::off_default_prefixes`]). A connection's own address is
//! also put to the kernel, which applies the rules exactly ([`crate::admit`]).
//!
//! A destination no route holds is admitted by this model (the kernel will not connect to it
//! either).
//!
//! **Routes that deliver to this host** (review r2, R2-NG-1): `local`, `broadcast` and `anycast`
//! routes, of every table, refuse every address they hold, like the host's own addresses
//! ([`RouteKind::Local`]). The kernel delivers such an address to the host itself, so an AnyIP
//! range (`ip route add local 185.199.108.0/24 dev lo`, as freebind, anycast and IPv6-proxy hosts
//! install) is this host, though no interface carries it. A `local` route of length `/0` is the
//! exception: it is how a transparent proxy (TPROXY) catches marked traffic, in a table only a
//! `fwmark` rule consults, and refusing every address for it would stop the miner outright. Any
//! other length refuses what it holds, `/1` to `/4` included; when those leave no public address
//! of any family the host routes, [`RouteTable::local_refuses_everything`] says so, and a
//! public-mode policy refuses to start with that explanation rather than refuse every fetch.
//!
//! Only Linux (and Android) routing tables are read; elsewhere the table is empty and only the
//! interfaces' own prefixes are known (put further ranges in `[egress] deny_cidrs`).

use std::net::IpAddr;

use crate::ip::{mask, Prefix};

/// The longest prefix length that still counts as a default route: a "split default" that covers
/// at least 1/16 of its family's address space (OpenVPN's `def1`: `0.0.0.0/1` and `128.0.0.0/1`;
/// its IPv6 equivalent: `::/3`, `2000::/4`, `3000::/4`).
pub const DEFAULT_LIKE_MAX_LEN: u8 = 4;

/// Where a route sends packets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Hop {
    /// Directly to the destination on the interface (no gateway): an on-link route.
    OnLink,
    /// Through this gateway.
    Via(IpAddr),
    /// Through a nexthop object whose gateway the dump does not show.
    Unknown,
}

/// What a route does with the packets it holds (`rtm_type`). Routes of any other type
/// (`blackhole`, `unreachable`, `prohibit`, `throw`, `multicast`, …) reach nothing and are not
/// read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub enum RouteType {
    /// Forwarded to a gateway or a neighbour.
    #[default]
    Unicast,
    /// Delivered to this host itself: its own addresses, and AnyIP ranges.
    Local,
    /// A broadcast address, delivered to this host (and its link).
    Broadcast,
    /// An anycast address this host answers (IPv6 subnet-router anycast).
    Anycast,
}

/// The `default` routing table's id.
pub const RT_TABLE_DEFAULT: u32 = 253;
/// The `main` routing table's id.
pub const RT_TABLE_MAIN: u32 = 254;
/// The `local` routing table's id.
pub const RT_TABLE_LOCAL: u32 = 255;

/// One route of any routing table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Route {
    /// The destination (`0.0.0.0/0` or `::/0` for a default route).
    pub prefix: Prefix,
    pub hop: Hop,
    /// The outgoing interface's index (0 when the route names none).
    pub ifindex: u32,
    /// Whether the outgoing interface is a loopback interface.
    pub loopback: bool,
    /// [`RouteType::Unicast`] for the routes built by [`Route::on_link`] and [`Route::via`].
    pub kind: RouteType,
    /// The routing table ([`RT_TABLE_MAIN`] for the routes the constructors build).
    pub table: u32,
}

impl Route {
    /// An on-link route on interface `ifindex` (tests, and callers with their own source).
    pub fn on_link(prefix: Prefix, ifindex: u32) -> Self {
        Route {
            prefix: Prefix::new(prefix.addr, prefix.len),
            hop: Hop::OnLink,
            ifindex,
            loopback: false,
            kind: RouteType::Unicast,
            table: RT_TABLE_MAIN,
        }
    }

    /// A route through `gateway` on interface `ifindex`.
    pub fn via(prefix: Prefix, gateway: IpAddr, ifindex: u32) -> Self {
        Route {
            prefix: Prefix::new(prefix.addr, prefix.len),
            hop: Hop::Via(gateway),
            ifindex,
            loopback: false,
            kind: RouteType::Unicast,
            table: RT_TABLE_MAIN,
        }
    }

    /// A `local` route on interface `ifindex`: every address in `prefix` is this host's
    /// (`ip route add local 185.199.108.0/24 dev lo`).
    pub fn local(prefix: Prefix, ifindex: u32) -> Self {
        Route {
            kind: RouteType::Local,
            ..Route::on_link(prefix, ifindex)
        }
    }

    /// The route, in routing table `table`.
    pub fn in_table(self, table: u32) -> Self {
        Route { table, ..self }
    }

    /// Whether the route delivers to this host itself (`local`, `broadcast`, `anycast`).
    pub fn delivers_locally(&self) -> bool {
        self.kind != RouteType::Unicast
    }

    /// Whether the route counts as a default route (`/0`, or a split default up to
    /// /[`DEFAULT_LIKE_MAX_LEN`]).
    pub fn is_default_like(&self) -> bool {
        self.prefix.len <= DEFAULT_LIKE_MAX_LEN
    }

    /// Whether `ip` is in the route's prefix, read as written (a routing table is per family).
    fn holds(&self, ip: IpAddr) -> bool {
        self.prefix.addr.is_ipv4() == ip.is_ipv4() && mask(ip, self.prefix.len) == self.prefix.addr
    }
}

/// Why the routing table refuses a destination ([`RouteRefusal`], and
/// [`crate::Denied::OffDefaultRoute`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteKind {
    /// No gateway: a network the host reaches directly.
    OnLink,
    /// Through a gateway that is not a default route's.
    OtherGateway,
    /// Delivered to this host itself by a `local`, `broadcast` or `anycast` route.
    Local,
    /// A policy-routing rule (`ip rule`) sends it to a routing table other than the default
    /// route's.
    PolicyRule,
    /// The kernel has no route for it (unreachable, prohibited, blackholed).
    NoRoute,
}

/// How a policy-routing rule's selectors, its destination (`to`) aside, read this process's own
/// outgoing connections (see the module doc).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum RuleMatch {
    /// Every connection.
    Always,
    /// None.
    Never,
    /// Some, depending on the connection: a source address (`from`), ports, a flow label, or a
    /// selector this code does not know.
    Sometimes,
}

impl RuleMatch {
    fn and(self, other: RuleMatch) -> RuleMatch {
        use RuleMatch::*;
        match (self, other) {
            (Never, _) | (_, Never) => Never,
            (Always, Always) => Always,
            _ => Sometimes,
        }
    }

    fn not(self) -> RuleMatch {
        match self {
            RuleMatch::Always => RuleMatch::Never,
            RuleMatch::Never => RuleMatch::Always,
            RuleMatch::Sometimes => RuleMatch::Sometimes,
        }
    }
}

/// What a policy-routing rule does with the connections it selects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum RuleAction {
    /// Look the destination up in this table (`lookup N`).
    Lookup(u32),
    /// Jump to a later rule (`goto`).
    Goto,
    /// Anything else (`nop`, `blackhole`, `unreachable`, `prohibit`): reaches nothing.
    Other,
}

/// One policy-routing rule (`ip rule`), read for this process's own connections.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Rule {
    /// An IPv6 rule (rules are per family).
    pub v6: bool,
    pub priority: u32,
    pub action: RuleAction,
    /// The destination selector (`to`); `None` selects every destination.
    pub to: Option<Prefix>,
    /// `not`: the rule applies where its selectors do not match.
    pub invert: bool,
    /// Its other selectors, read for this process's connections.
    pub matches: RuleMatch,
}

impl Rule {
    /// `from all lookup table` (tests, and callers with their own source).
    pub fn lookup(v6: bool, table: u32) -> Self {
        Rule {
            v6,
            priority: 0,
            action: RuleAction::Lookup(table),
            to: None,
            invert: false,
            matches: RuleMatch::Always,
        }
    }

    /// `to prefix lookup table`.
    pub fn to(prefix: Prefix, table: u32) -> Self {
        Rule {
            to: Some(Prefix::new(prefix.addr, prefix.len)),
            ..Rule::lookup(prefix.addr.is_ipv6(), table)
        }
    }

    /// A stock host's rules for a family: `local`, `main`, `default`.
    pub fn stock(v6: bool) -> Vec<Rule> {
        [RT_TABLE_LOCAL, RT_TABLE_MAIN, RT_TABLE_DEFAULT]
            .into_iter()
            .map(|t| Rule::lookup(v6, t))
            .collect()
    }

    /// Whether it selects this process's connections to destinations outside `to` (all
    /// destinations when it has no `to`).
    fn outside(&self) -> RuleMatch {
        match (self.to.is_some(), self.invert) {
            (false, false) => self.matches,
            (false, true) => self.matches.not(),
            (true, false) => RuleMatch::Never,
            (true, true) => RuleMatch::Always,
        }
    }

    /// Whether it selects this process's connections to destinations inside `to`.
    fn inside(&self) -> RuleMatch {
        if self.invert {
            self.matches.not()
        } else {
            self.matches
        }
    }
}

/// The route that refuses a destination, and why ([`RouteTable::off_default_path`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouteRefusal {
    /// The refusing route's prefix.
    pub prefix: Prefix,
    pub kind: RouteKind,
}

impl RouteRefusal {
    fn of(r: &Route) -> Self {
        let kind = if r.delivers_locally() {
            RouteKind::Local
        } else if r.hop == Hop::OnLink {
            RouteKind::OnLink
        } else {
            RouteKind::OtherGateway
        };
        RouteRefusal {
            prefix: r.prefix,
            kind,
        }
    }
}

/// The routing table, with the default path worked out (see the module doc).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RouteTable {
    /// The unicast routes, less the default-like routes of tables that are not ordinary.
    routes: Vec<Route>,
    /// The routes that deliver to this host (`local`, `broadcast`, `anycast`), `/0` left out.
    local: Vec<Route>,
    /// `(IPv6, table)` of every ordinary table (see the module doc).
    ordinary: Vec<(bool, u32)>,
    /// The destinations rules send to a table that is not ordinary: `(to, table)`, table 0 for a
    /// `goto`.
    steered: Vec<(Prefix, u32)>,
    /// `(gateway, interface)` of every `/0` route of an ordinary table that has a gateway.
    uplinks: Vec<(IpAddr, u32)>,
}

impl RouteTable {
    /// The table of a stock host: every route's table is consulted as `local`, `main` and
    /// `default` are ([`Rule::stock`]).
    pub fn new(routes: Vec<Route>) -> Self {
        Self::with_rules(routes, Vec::new())
    }

    /// The table under policy-routing `rules` (a family without any gets [`Rule::stock`]).
    pub fn with_rules(routes: Vec<Route>, rules: Vec<Rule>) -> Self {
        let mut ordinary = Vec::new();
        for v6 in [false, true] {
            let family: Vec<&Rule> = rules.iter().filter(|r| r.v6 == v6).collect();
            if family.is_empty() {
                ordinary.extend([RT_TABLE_LOCAL, RT_TABLE_MAIN, RT_TABLE_DEFAULT].map(|t| (v6, t)));
            }
            for r in family {
                if let (RuleAction::Lookup(t), RuleMatch::Always) = (r.action, r.outside()) {
                    ordinary.push((v6, t));
                }
            }
        }
        ordinary.sort();
        ordinary.dedup();
        let mut steered: Vec<(Prefix, u32)> = rules
            .iter()
            .filter(|r| r.inside() != RuleMatch::Never)
            .filter_map(|r| {
                let to = r.to?;
                match r.action {
                    RuleAction::Lookup(t) if ordinary.contains(&(r.v6, t)) => None,
                    RuleAction::Lookup(t) => Some((to, t)),
                    RuleAction::Goto => Some((to, 0)),
                    RuleAction::Other => None,
                }
            })
            .collect();
        steered.sort();
        steered.dedup();
        let is_ordinary = |r: &Route| ordinary.contains(&(r.prefix.addr.is_ipv6(), r.table));
        let (mut local, mut routes): (Vec<Route>, Vec<Route>) = routes
            .into_iter()
            .map(|mut r| {
                r.prefix = Prefix::new(r.prefix.addr, r.prefix.len);
                r
            })
            .partition(Route::delivers_locally);
        // A `local default` is a transparent proxy's catch-all (see the module doc).
        local.retain(|r| r.prefix.len > 0);
        local.sort();
        local.dedup();
        // Review r2 R2-NG-2: a default route of a table only a selector reaches is no default
        // route, and its gateway no uplink.
        routes.retain(|r| !r.is_default_like() || is_ordinary(r));
        routes.sort();
        routes.dedup();
        let mut uplinks: Vec<(IpAddr, u32)> = routes
            .iter()
            .filter(|r| r.prefix.len == 0 && is_ordinary(r))
            .filter_map(|r| match r.hop {
                Hop::Via(gw) => Some((gw, r.ifindex)),
                _ => None,
            })
            .collect();
        uplinks.sort();
        uplinks.dedup();
        RouteTable {
            routes,
            local,
            ordinary,
            steered,
            uplinks,
        }
    }

    /// Whether `table` of the family is ordinary: a rule with no destination selector sends
    /// every connection of this process to it (see the module doc).
    pub fn is_ordinary(&self, v6: bool, table: u32) -> bool {
        self.ordinary.contains(&(v6, table))
    }

    /// `(gateway, interface)` of every `/0` route of an ordinary table that has a gateway.
    pub fn uplinks(&self) -> &[(IpAddr, u32)] {
        &self.uplinks
    }

    /// The destinations rules send to a table that is not ordinary (`to` prefix, table; 0 for a
    /// `goto`).
    pub fn steered(&self) -> &[(Prefix, u32)] {
        &self.steered
    }

    /// Every unicast route, sorted.
    pub fn routes(&self) -> &[Route] {
        &self.routes
    }

    /// Every route that delivers to this host (`local`, `broadcast`, `anycast`; not `/0`), sorted.
    pub fn local_routes(&self) -> &[Route] {
        &self.local
    }

    /// Whether `r` takes the default path: it is a default route (or a split default) of an
    /// ordinary table, or it goes through the gateway, on the interface, of a true default route
    /// of one (an uplink).
    pub fn via_default_path(&self, r: &Route) -> bool {
        if r.is_default_like() && self.is_ordinary(r.prefix.addr.is_ipv6(), r.table) {
            return true;
        }
        match r.hop {
            Hop::Via(gw) => self.uplinks.contains(&(gw, r.ifindex)),
            Hop::OnLink | Hop::Unknown => false,
        }
    }

    /// The route that refuses `ip`: a route that delivers it to this host, else, among the
    /// unicast routes holding `ip` with the longest prefix length (the kernel's choice, up to
    /// policy routing), the first that does not take the default path. `None` when every one of
    /// them does, or when no route holds `ip`.
    pub fn off_default_path(&self, ip: IpAddr) -> Option<RouteRefusal> {
        if let Some(r) = self.local.iter().find(|r| r.holds(ip)) {
            return Some(RouteRefusal::of(r));
        }
        if let Some((to, _)) = self
            .steered
            .iter()
            .find(|(to, _)| to.addr.is_ipv4() == ip.is_ipv4() && mask(ip, to.len) == to.addr)
        {
            return Some(RouteRefusal {
                prefix: *to,
                kind: RouteKind::PolicyRule,
            });
        }
        let best = self
            .routes
            .iter()
            .filter(|r| r.holds(ip))
            .map(|r| r.prefix.len)
            .max()?;
        self.routes
            .iter()
            .filter(|r| r.prefix.len == best && r.holds(ip))
            .find(|r| !self.via_default_path(r))
            .map(RouteRefusal::of)
    }

    /// The prefixes of the on-link routes: no gateway, not on a loopback interface, not a default
    /// route. Connected prefixes the interfaces' netmasks may not show.
    pub fn on_link_prefixes(&self) -> Vec<Prefix> {
        let mut v: Vec<Prefix> = self
            .routes
            .iter()
            .filter(|r| r.hop == Hop::OnLink && !r.loopback && !r.is_default_like())
            .map(|r| r.prefix)
            .collect();
        v.sort();
        v.dedup();
        v
    }

    /// The prefixes of every route that does not take the default path (on-link routes, routes on
    /// a loopback interface, routes through another gateway, routes that deliver to this host)
    /// and of every destination rule into a table that is not ordinary: what a consumer that
    /// knows only prefixes must refuse to refuse what [`Self::off_default_path`] refuses. Wider
    /// than the rule itself where a more specific default-path route sits inside one of them.
    pub fn off_default_prefixes(&self) -> Vec<Prefix> {
        let mut v: Vec<Prefix> = self
            .routes
            .iter()
            .filter(|r| !self.via_default_path(r))
            .chain(&self.local)
            .map(|r| r.prefix)
            .chain(self.steered.iter().map(|(to, _)| *to))
            .collect();
        v.sort();
        v.dedup();
        v
    }

    /// When the routes that deliver to this host hold every public address of every family the
    /// host has a default route for (a `local 0.0.0.0/1` + `local 128.0.0.0/1` pair, say), those
    /// routes: a policy over this table would refuse every destination. `None` otherwise, and
    /// when the host has no default route at all.
    pub fn local_refuses_everything(&self) -> Option<Vec<Prefix>> {
        let mut families = 0;
        for v6 in [false, true] {
            if !self.routes.iter().any(|r| {
                r.prefix.addr.is_ipv6() == v6 && r.prefix.len == 0 && self.is_ordinary(v6, r.table)
            }) {
                continue;
            }
            families += 1;
            let space = if v6 {
                Prefix::new(
                    IpAddr::V6(std::net::Ipv6Addr::new(0x2000, 0, 0, 0, 0, 0, 0, 0)),
                    3,
                )
            } else {
                Prefix::new(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0)
            };
            let local: Vec<Prefix> = self.local.iter().map(|r| r.prefix).collect();
            if !covered(space, &local) {
                return None;
            }
        }
        (families > 0).then(|| self.local.iter().map(|r| r.prefix).collect())
    }
}

/// Whether the prefixes in `set` together hold every address of `p` (each family on its own).
fn covered(p: Prefix, set: &[Prefix]) -> bool {
    let same = |q: &Prefix| q.addr.is_ipv4() == p.addr.is_ipv4();
    if set
        .iter()
        .any(|q| same(q) && q.len <= p.len && mask(p.addr, q.len) == q.addr)
    {
        return true;
    }
    let width = if p.addr.is_ipv4() { 32 } else { 128 };
    // Nothing smaller inside `p`: not covered.
    if p.len >= width
        || !set
            .iter()
            .any(|q| same(q) && q.len > p.len && mask(q.addr, p.len) == p.addr)
    {
        return false;
    }
    let upper = match p.addr {
        IpAddr::V4(a) => IpAddr::V4(std::net::Ipv4Addr::from(
            u32::from(a) | (1u32 << (31 - u32::from(p.len))),
        )),
        IpAddr::V6(a) => IpAddr::V6(std::net::Ipv6Addr::from(
            u128::from(a) | (1u128 << (127 - u32::from(p.len))),
        )),
    };
    covered(Prefix::new(p.addr, p.len + 1), set) && covered(Prefix::new(upper, p.len + 1), set)
}

/// Where [`crate::admit`] learns how the kernel routes one destination (see
/// [`RouteTable::judge`]): the kernel itself ([`KernelRoutes`]) for facts read from this host, a
/// fake in tests.
pub trait RouteOracle: Send + Sync + std::fmt::Debug {
    /// The routing entry the kernel would use for a connection from this process to `dst` —
    /// one [`Route`] per nexthop, all with the entry's prefix, table and type — or `Ok(None)`
    /// when it has no route.
    fn route_to(&self, dst: IpAddr) -> std::io::Result<Option<Vec<Route>>>;
}

/// The kernel, asked over netlink per destination (Linux; elsewhere every query fails, and a
/// policy over gathered facts refuses everything: routes are only read on Linux anyway).
///
/// One `RTM_GETROUTE` per destination, non-dump, with the destination, this process's uid and
/// TCP, and `RTM_F_FIB_MATCH`: the kernel runs its policy rules and answers with the routing
/// entry it matched (prefix, table, type, every nexthop). No privileges needed. It is what a
/// connection's first route lookup sees: the firewall mark is 0, the source not yet chosen, the
/// ports not given.
#[derive(Debug, Clone, Copy, Default)]
pub struct KernelRoutes;

impl RouteOracle for KernelRoutes {
    fn route_to(&self, dst: IpAddr) -> std::io::Result<Option<Vec<Route>>> {
        sys::query(dst)
    }
}

impl RouteTable {
    /// Judges the kernel's answer for one destination ([`RouteOracle::route_to`]; an empty
    /// answer is no route): admitted only for a unicast route whose every nexthop is an uplink
    /// (the gateway and interface of an ordinary table's default route), or that is itself a
    /// default-like route of an ordinary table. Anything else is refused: a route that delivers
    /// to this host, no route, a default-like route of a table only a rule's selector reaches
    /// ([`RouteKind::PolicyRule`]), an on-link route, a route through another gateway or through
    /// a nexthop object whose gateway the answer does not show.
    pub fn judge(&self, answer: &[Route]) -> Result<(), RouteRefusal> {
        let Some(first) = answer.first() else {
            return Err(RouteRefusal {
                prefix: Prefix::new(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0),
                kind: RouteKind::NoRoute,
            });
        };
        if let Some(r) = answer.iter().find(|r| r.delivers_locally()) {
            return Err(RouteRefusal::of(r));
        }
        let through_uplinks = answer.iter().all(|r| match r.hop {
            Hop::Via(gw) => self.uplinks.contains(&(gw, r.ifindex)),
            Hop::OnLink | Hop::Unknown => false,
        });
        if through_uplinks {
            return Ok(());
        }
        if first.is_default_like() {
            return if self.is_ordinary(first.prefix.addr.is_ipv6(), first.table) {
                Ok(())
            } else {
                Err(RouteRefusal {
                    prefix: first.prefix,
                    kind: RouteKind::PolicyRule,
                })
            };
        }
        let off = answer
            .iter()
            .find(|r| !matches!(r.hop, Hop::Via(gw) if self.uplinks.contains(&(gw, r.ifindex))))
            .unwrap_or(first);
        Err(RouteRefusal::of(off))
    }
}

/// Reads every unicast, `local`, `broadcast` and `anycast` route of every table, and every
/// policy-routing rule, IPv4 and IPv6. `loopback` is the set of loopback interface indexes (from
/// the interface list).
pub(crate) fn read_routing(loopback: &[u32]) -> std::io::Result<(Vec<Route>, Vec<Rule>)> {
    let (mut routes, rules) = sys::dump()?;
    for r in &mut routes {
        r.loopback = r.ifindex != 0 && loopback.contains(&r.ifindex);
    }
    Ok((routes, rules))
}

#[cfg(any(target_os = "linux", target_os = "android"))]
mod sys {
    //! Netlink `RTM_GETROUTE` and `RTM_GETRULE` dumps, per family. Unprivileged; every table.

    use std::io;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    use super::{Hop, Route, RouteType, Rule, RuleAction, RuleMatch};
    use crate::ip::Prefix;

    const NLMSG_HDRLEN: usize = 16;
    const RTMSG_LEN: usize = 12;
    const NLMSG_ERROR: u16 = 2;
    const NLMSG_DONE: u16 = 3;
    const RTM_NEWROUTE: u16 = 24;
    const RTM_GETROUTE: u16 = 26;
    const NLM_F_REQUEST: u16 = 1;
    const NLM_F_DUMP: u16 = 0x300;
    const RTN_UNICAST: u8 = 1;
    const RTN_LOCAL: u8 = 2;
    const RTN_BROADCAST: u8 = 3;
    const RTN_ANYCAST: u8 = 4;
    const RTM_F_CLONED: u32 = 0x200;
    const RTA_DST: u16 = 1;
    const RTA_OIF: u16 = 4;
    const RTA_GATEWAY: u16 = 5;
    const RTA_MULTIPATH: u16 = 9;
    const RTA_VIA: u16 = 18;
    const RTA_TABLE: u16 = 15;
    const RTA_UID: u16 = 25;
    const RTA_IP_PROTO: u16 = 27;
    const RTA_NH_ID: u16 = 30;
    const RTM_F_FIB_MATCH: u32 = 0x2000;
    const RTM_NEWRULE: u16 = 32;
    const RTM_GETRULE: u16 = 34;
    const FR_ACT_TO_TBL: u8 = 1;
    const FR_ACT_GOTO: u8 = 2;
    const FIB_RULE_INVERT: u32 = 0x2;
    const FIB_RULE_IIF_DETACHED: u32 = 0x8;
    const FRA_DST: u16 = 1;
    const FRA_SRC: u16 = 2;
    const FRA_IIFNAME: u16 = 3;
    const FRA_GOTO: u16 = 4;
    const FRA_PRIORITY: u16 = 6;
    const FRA_FWMARK: u16 = 10;
    const FRA_FLOW: u16 = 11;
    const FRA_TUN_ID: u16 = 12;
    const FRA_SUPPRESS_IFGROUP: u16 = 13;
    const FRA_SUPPRESS_PREFIXLEN: u16 = 14;
    const FRA_TABLE: u16 = 15;
    const FRA_FWMASK: u16 = 16;
    const FRA_OIFNAME: u16 = 17;
    const FRA_PAD: u16 = 18;
    const FRA_L3MDEV: u16 = 19;
    const FRA_UID_RANGE: u16 = 20;
    const FRA_PROTOCOL: u16 = 21;
    const FRA_IP_PROTO: u16 = 22;
    const FRA_SPORT_RANGE: u16 = 23;
    const FRA_DPORT_RANGE: u16 = 24;
    /// The most a dump message can be (the kernel caps dump skbs at 32 KiB).
    const RECV_BUF: usize = 64 * 1024;
    /// A ceiling on the routes read, against a runaway dump.
    const MAX_ROUTES: usize = 1 << 20;

    /// Times a dump the kernel flags as interrupted (`NLM_F_DUMP_INTR`: the table changed while it
    /// was read) is started again before the read fails.
    const DUMP_ATTEMPTS: usize = 5;
    /// `nlmsghdr.nlmsg_flags`: the dump was interrupted by a change and may be inconsistent.
    const NLM_F_DUMP_INTR: u16 = 0x10;

    /// Who is asking: what the rules are read for (see the module doc).
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(super) struct Flow {
        /// This process's uid.
        pub uid: u32,
        /// The name of the loopback interface (`lo`), the input interface of every locally
        /// generated packet's route lookup.
        pub loopback: Option<String>,
    }

    impl Flow {
        fn current() -> Self {
            let mut name = [0 as libc::c_char; libc::IF_NAMESIZE];
            // SAFETY: `name` holds IF_NAMESIZE bytes, as if_indextoname requires; the loopback
            // device is ifindex 1 (LOOPBACK_IFINDEX) in every network namespace.
            let p = unsafe { libc::if_indextoname(1, name.as_mut_ptr()) };
            let loopback = (!p.is_null()).then(|| {
                // SAFETY: on success the buffer holds a NUL-terminated name.
                unsafe { std::ffi::CStr::from_ptr(name.as_ptr()) }
                    .to_string_lossy()
                    .into_owned()
            });
            Flow {
                // SAFETY: getuid cannot fail.
                uid: unsafe { libc::getuid() },
                loopback,
            }
        }
    }

    /// Every route and every rule, IPv4 and IPv6.
    pub(super) fn dump() -> io::Result<(Vec<Route>, Vec<Rule>)> {
        let flow = Flow::current();
        let mut routes = Vec::new();
        let mut rules = Vec::new();
        for family in [libc::AF_INET as u8, libc::AF_INET6 as u8] {
            routes.extend(dump_consistent(
                RTM_GETROUTE,
                RTM_NEWROUTE,
                family,
                parse_route,
            )?);
            match dump_consistent(
                RTM_GETRULE,
                RTM_NEWRULE,
                family,
                |p: &[u8], out: &mut Vec<Rule>| parse_rule(p, &flow, out),
            ) {
                Ok(r) => rules.extend(r),
                // A kernel built without policy routing (CONFIG_FIB_RULES) has no rule dump and
                // only the stock tables: no rules reads as the stock ones.
                Err(e) if e.raw_os_error() == Some(libc::EOPNOTSUPP) => {}
                Err(e) => return Err(e),
            }
        }
        Ok((routes, rules))
    }

    /// One family's routes (or rules) from a dump the kernel neither aborted nor flagged as
    /// interrupted, retried up to [`DUMP_ATTEMPTS`] times; a table that keeps changing fails the
    /// read (the caller then keeps its last good facts, or refuses to start).
    fn dump_consistent<T>(
        request: u16,
        reply: u16,
        family: u8,
        parse: impl Fn(&[u8], &mut Vec<T>) -> io::Result<()>,
    ) -> io::Result<Vec<T>> {
        for _ in 0..DUMP_ATTEMPTS {
            let mut out = Vec::new();
            match dump_family(request, reply, family, &parse, &mut out) {
                Ok(()) => return Ok(out),
                Err(e) if is_interrupted(&e) => continue,
                Err(e) => return Err(e),
            }
        }
        Err(io::Error::other(format!(
            "the routing table changed during each of {DUMP_ATTEMPTS} reads (NLM_F_DUMP_INTR); \
             a partial table is not used"
        )))
    }

    /// The error [`parse_dump`] returns for a dump flagged `NLM_F_DUMP_INTR`.
    fn interrupted() -> io::Error {
        io::Error::new(io::ErrorKind::Interrupted, DumpInterrupted)
    }

    fn is_interrupted(e: &io::Error) -> bool {
        e.get_ref().is_some_and(|i| i.is::<DumpInterrupted>())
    }

    #[derive(Debug)]
    struct DumpInterrupted;

    impl std::fmt::Display for DumpInterrupted {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("the netlink dump was interrupted by a change (NLM_F_DUMP_INTR)")
        }
    }

    impl std::error::Error for DumpInterrupted {}

    fn align4(n: usize) -> usize {
        (n + 3) & !3
    }

    /// A route netlink socket, unbound (the kernel assigns its port id on the first send).
    pub(super) fn socket() -> io::Result<OwnedFd> {
        // SAFETY: plain socket(2); the fd is owned by the OwnedFd from here on.
        let fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                libc::NETLINK_ROUTE,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `fd` was just created and is owned here alone.
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }

    /// Sends `req` to the kernel on `sock`.
    pub(super) fn send(sock: &OwnedFd, req: &[u8]) -> io::Result<()> {
        // SAFETY: a zeroed sockaddr_nl is the kernel's address (nl_pid 0, no groups).
        let mut kernel: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        kernel.nl_family = libc::AF_NETLINK as libc::sa_family_t;
        // SAFETY: `req` and `kernel` are valid for the lengths given.
        let sent = unsafe {
            libc::sendto(
                sock.as_raw_fd(),
                req.as_ptr().cast(),
                req.len(),
                0,
                (&kernel as *const libc::sockaddr_nl).cast(),
                std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if sent < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// One datagram from the kernel into `buf` (others' are skipped), its length.
    pub(super) fn recv(sock: &OwnedFd, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            // SAFETY: a zeroed sockaddr_nl is valid to be overwritten by recvfrom.
            let mut from: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
            let mut from_len = std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t;
            // SAFETY: `buf` and `from` are valid for the lengths given.
            let n = unsafe {
                libc::recvfrom(
                    sock.as_raw_fd(),
                    buf.as_mut_ptr().cast(),
                    buf.len(),
                    0,
                    (&mut from as *mut libc::sockaddr_nl).cast(),
                    &mut from_len,
                )
            };
            if n < 0 {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(e);
            }
            if from.nl_pid != 0 {
                // Not from the kernel.
                continue;
            }
            return Ok(n as usize);
        }
    }

    /// A netlink message: header, then `body`.
    pub(super) fn message(ty: u16, flags: u16, seq: u32, body: &[u8]) -> Vec<u8> {
        let mut req = Vec::with_capacity(NLMSG_HDRLEN + body.len());
        req.extend_from_slice(&((NLMSG_HDRLEN + body.len()) as u32).to_ne_bytes());
        req.extend_from_slice(&ty.to_ne_bytes());
        req.extend_from_slice(&flags.to_ne_bytes());
        req.extend_from_slice(&seq.to_ne_bytes());
        req.extend_from_slice(&0u32.to_ne_bytes());
        req.extend_from_slice(body);
        req
    }

    fn dump_family<T>(
        request: u16,
        reply: u16,
        family: u8,
        parse: &impl Fn(&[u8], &mut Vec<T>) -> io::Result<()>,
        out: &mut Vec<T>,
    ) -> io::Result<()> {
        let sock = socket()?;
        let seq: u32 = 1;
        // `struct rtmsg` and `struct fib_rule_hdr` are both 12 bytes, family first.
        let mut hdr = [0u8; RTMSG_LEN];
        hdr[0] = family;
        send(
            &sock,
            &message(request, NLM_F_REQUEST | NLM_F_DUMP, seq, &hdr),
        )?;
        let mut buf = vec![0u8; RECV_BUF];
        loop {
            let n = recv(&sock, &mut buf)?;
            if parse_dump(&buf[..n], seq, reply, &mut |p| parse(p, out))? {
                return Ok(());
            }
            if out.len() > MAX_ROUTES {
                return Err(io::Error::other("the routing table dump never ended"));
            }
        }
    }

    fn malformed() -> io::Error {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "malformed netlink route message",
        )
    }

    fn u16_at(b: &[u8], i: usize) -> Option<u16> {
        Some(u16::from_ne_bytes(b.get(i..i + 2)?.try_into().ok()?))
    }

    fn u32_at(b: &[u8], i: usize) -> Option<u32> {
        Some(u32::from_ne_bytes(b.get(i..i + 4)?.try_into().ok()?))
    }

    /// Parses one datagram of a dump, handing each `reply` message's payload to `on`; `true`
    /// once the dump is done.
    ///
    /// Fails closed (review r2, R2-NG-8): an `NLMSG_DONE` that carries a negative errno (the kernel
    /// aborted the dump, `dump_done_errno`) is that error, and a message flagged `NLM_F_DUMP_INTR`
    /// (the table changed while it was dumped, so routes may be missing) fails the dump at once
    /// with an error [`dump_consistent`] retries; neither is ever taken as a complete table.
    pub(super) fn parse_dump(
        mut b: &[u8],
        seq: u32,
        reply: u16,
        on: &mut dyn FnMut(&[u8]) -> io::Result<()>,
    ) -> io::Result<bool> {
        while b.len() >= NLMSG_HDRLEN {
            let len = u32_at(b, 0).ok_or_else(malformed)? as usize;
            let ty = u16_at(b, 4).ok_or_else(malformed)?;
            let flags = u16_at(b, 6).ok_or_else(malformed)?;
            let mseq = u32_at(b, 8).ok_or_else(malformed)?;
            if len < NLMSG_HDRLEN || len > b.len() {
                return Err(malformed());
            }
            let payload = &b[NLMSG_HDRLEN..len];
            if mseq == seq {
                if flags & NLM_F_DUMP_INTR != 0 {
                    return Err(interrupted());
                }
                match ty {
                    NLMSG_DONE => {
                        // `int error`: 0, or the negative errno of an aborted dump.
                        let code = u32_at(payload, 0).map_or(0, |c| c as i32);
                        if code < 0 {
                            return Err(io::Error::from_raw_os_error(-code));
                        }
                        return Ok(true);
                    }
                    NLMSG_ERROR => {
                        let code = u32_at(payload, 0).ok_or_else(malformed)? as i32;
                        if code != 0 {
                            return Err(io::Error::from_raw_os_error(-code));
                        }
                        return Ok(true);
                    }
                    t if t == reply => on(payload)?,
                    _ => {}
                }
            }
            b = &b[align4(len).min(b.len())..];
        }
        Ok(false)
    }

    /// [`parse_dump`] for a route dump.
    #[cfg(test)]
    pub(super) fn parse_messages(b: &[u8], seq: u32, out: &mut Vec<Route>) -> io::Result<bool> {
        parse_dump(b, seq, RTM_NEWROUTE, &mut |p| parse_route(p, out))
    }

    /// [`parse_dump`] for a rule dump, read for `flow`.
    #[cfg(test)]
    pub(super) fn parse_rule_messages(
        b: &[u8],
        seq: u32,
        flow: &Flow,
        out: &mut Vec<Rule>,
    ) -> io::Result<bool> {
        parse_dump(b, seq, RTM_NEWRULE, &mut |p| parse_rule(p, flow, out))
    }

    /// One `RTM_NEWRULE`: `struct fib_rule_hdr { u8 family, dst_len, src_len, tos, table, res1,
    /// res2, action; u32 flags; }` and its `FRA_*` attributes, read for `flow` (see the module
    /// doc). A selector this code does not know reads as [`RuleMatch::Sometimes`].
    fn parse_rule(p: &[u8], flow: &Flow, out: &mut Vec<Rule>) -> io::Result<()> {
        if p.len() < RTMSG_LEN {
            return Err(malformed());
        }
        let (family, dst_len, src_len, tos, action) = (p[0], p[1], p[2], p[3], p[7]);
        let flags = u32_at(p, 8).ok_or_else(malformed)?;
        let v6 = match i32::from(family) {
            libc::AF_INET => false,
            libc::AF_INET6 => true,
            _ => return Ok(()),
        };
        let mut table = u32::from(p[4]);
        let mut priority = 0;
        let mut to = None;
        let mut m = RuleMatch::Always;
        let mut mark: Option<u32> = None;
        let mut mark_mask: Option<u32> = None;
        for (ty, data) in attrs(&p[RTMSG_LEN..])? {
            let x = match ty {
                FRA_DST => {
                    to = Some(Prefix::new(
                        addr(family, data).ok_or_else(malformed)?,
                        dst_len,
                    ));
                    RuleMatch::Always
                }
                // The source is chosen per destination, after the first lookup.
                FRA_SRC if src_len > 0 => RuleMatch::Sometimes,
                FRA_SRC => RuleMatch::Always,
                FRA_IIFNAME => {
                    let name = data.split(|b| *b == 0).next().unwrap_or_default();
                    let lo = flow.loopback.as_deref().map(str::as_bytes);
                    if flags & FIB_RULE_IIF_DETACHED == 0 && lo == Some(name) {
                        RuleMatch::Always
                    } else {
                        RuleMatch::Never
                    }
                }
                // A connection that is not bound to a device has no output interface.
                FRA_OIFNAME => RuleMatch::Never,
                FRA_PRIORITY => {
                    priority = u32_at(data, 0).ok_or_else(malformed)?;
                    RuleMatch::Always
                }
                FRA_FWMARK => {
                    mark = Some(u32_at(data, 0).ok_or_else(malformed)?);
                    RuleMatch::Always
                }
                FRA_FWMASK => {
                    mark_mask = Some(u32_at(data, 0).ok_or_else(malformed)?);
                    RuleMatch::Always
                }
                FRA_TABLE => {
                    table = u32_at(data, 0).ok_or_else(malformed)?;
                    RuleMatch::Always
                }
                FRA_TUN_ID if data.iter().any(|b| *b != 0) => RuleMatch::Never,
                // Only a socket bound into a VRF matches an l3mdev rule.
                FRA_L3MDEV if data.first().is_some_and(|b| *b != 0) => RuleMatch::Never,
                FRA_UID_RANGE => {
                    let start = u32_at(data, 0).ok_or_else(malformed)?;
                    let end = u32_at(data, 4).ok_or_else(malformed)?;
                    if (start..=end).contains(&flow.uid) {
                        RuleMatch::Always
                    } else {
                        RuleMatch::Never
                    }
                }
                FRA_IP_PROTO => match data.first() {
                    Some(&p) if i32::from(p) == libc::IPPROTO_TCP => RuleMatch::Always,
                    Some(_) => RuleMatch::Never,
                    None => return Err(malformed()),
                },
                FRA_SPORT_RANGE | FRA_DPORT_RANGE => RuleMatch::Sometimes,
                // Not selectors: where to go, or bookkeeping.
                FRA_GOTO
                | FRA_FLOW
                | FRA_SUPPRESS_IFGROUP
                | FRA_SUPPRESS_PREFIXLEN
                | FRA_PROTOCOL
                | FRA_PAD
                | FRA_TUN_ID
                | FRA_L3MDEV => RuleMatch::Always,
                _ => RuleMatch::Sometimes,
            };
            m = m.and(x);
        }
        if dst_len > 0 && to.is_none() {
            return Err(malformed());
        }
        if tos != 0 {
            // This process's connections are TOS 0.
            m = m.and(RuleMatch::Never);
        }
        if mark.is_some() || mark_mask.is_some() {
            // The kernel dumps FRA_FWMASK only when it is not all ones; this process's packets
            // carry mark 0.
            let mark = mark.unwrap_or(0);
            let mask = mark_mask.unwrap_or(u32::MAX);
            m = m.and(if mark & mask != 0 {
                RuleMatch::Never
            } else {
                RuleMatch::Always
            });
        }
        let action = match action {
            FR_ACT_TO_TBL => RuleAction::Lookup(table),
            FR_ACT_GOTO => RuleAction::Goto,
            _ => RuleAction::Other,
        };
        out.push(Rule {
            v6,
            priority,
            action,
            to,
            invert: flags & FIB_RULE_INVERT != 0,
            matches: m,
        });
        Ok(())
    }

    fn addr(family: u8, data: &[u8]) -> Option<IpAddr> {
        match (i32::from(family), data.len()) {
            (libc::AF_INET, 4) => Some(IpAddr::V4(Ipv4Addr::new(
                data[0], data[1], data[2], data[3],
            ))),
            (libc::AF_INET6, 16) => {
                Some(IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(data).ok()?)))
            }
            _ => None,
        }
    }

    /// `RTA_VIA`: `struct rtvia { __kernel_sa_family_t rtvia_family; __u8 rtvia_addr[]; }`.
    fn via(data: &[u8]) -> Option<IpAddr> {
        let fam = u16_at(data, 0)?;
        addr(fam as u8, data.get(2..)?)
    }

    /// The attributes in `b`, as `(type, data)`.
    fn attrs(mut b: &[u8]) -> io::Result<Vec<(u16, &[u8])>> {
        let mut v = Vec::new();
        while b.len() >= 4 {
            let len = usize::from(u16_at(b, 0).ok_or_else(malformed)?);
            let ty = u16_at(b, 2).ok_or_else(malformed)? & 0x3fff; // strip NLA_F_NESTED/BYTEORDER
            if len < 4 || len > b.len() {
                return Err(malformed());
            }
            v.push((ty, &b[4..len]));
            b = &b[align4(len).min(b.len())..];
        }
        Ok(v)
    }

    /// How long the kernel may take to answer one route query.
    const QUERY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

    /// The route the kernel would take for a connection from this process to `dst`: a
    /// non-dump `RTM_GETROUTE` with `RTA_DST`, `RTA_UID` (this process's uid) and `RTA_IP_PROTO`
    /// (TCP), and `RTM_F_FIB_MATCH`, so the answer is the matching routing entry itself — its
    /// prefix, table, type and every nexthop — as the rules (`ip rule`) select it. Unprivileged.
    /// `Ok(None)` when the kernel has no route (unreachable, prohibited).
    pub(super) fn query(dst: IpAddr) -> io::Result<Option<Vec<Route>>> {
        let sock = socket()?;
        let tv = libc::timeval {
            tv_sec: QUERY_TIMEOUT.as_secs() as libc::time_t,
            tv_usec: 0,
        };
        // SAFETY: `tv` is a valid timeval for SO_RCVTIMEO.
        if unsafe {
            libc::setsockopt(
                sock.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                (&tv as *const libc::timeval).cast(),
                std::mem::size_of::<libc::timeval>() as libc::socklen_t,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        let (family, width, octets): (u8, u8, Vec<u8>) = match dst {
            IpAddr::V4(a) => (libc::AF_INET as u8, 32, a.octets().to_vec()),
            IpAddr::V6(a) => (libc::AF_INET6 as u8, 128, a.octets().to_vec()),
        };
        let mut body = vec![0u8; RTMSG_LEN];
        body[0] = family;
        body[1] = width;
        body[8..12].copy_from_slice(&RTM_F_FIB_MATCH.to_ne_bytes());
        // SAFETY: getuid cannot fail.
        let uid = unsafe { libc::getuid() };
        for (ty, data) in [
            (RTA_DST, octets),
            (RTA_UID, uid.to_ne_bytes().to_vec()),
            (RTA_IP_PROTO, vec![libc::IPPROTO_TCP as u8]),
        ] {
            body.extend_from_slice(&((4 + data.len()) as u16).to_ne_bytes());
            body.extend_from_slice(&ty.to_ne_bytes());
            body.extend_from_slice(&data);
            body.resize(align4(body.len()), 0);
        }
        let seq = 1;
        send(&sock, &message(RTM_GETROUTE, NLM_F_REQUEST, seq, &body))?;
        let mut buf = vec![0u8; RECV_BUF];
        loop {
            let n = recv(&sock, &mut buf)?;
            if let Some(answer) = parse_answer(&buf[..n], seq)? {
                return Ok(answer);
            }
        }
    }

    /// The answer to [`query`] in one datagram: `Some(Some(routes))` for a route,
    /// `Some(None)` for none, `None` when the datagram does not answer it.
    pub(super) fn parse_answer(mut b: &[u8], seq: u32) -> io::Result<Option<Option<Vec<Route>>>> {
        while b.len() >= NLMSG_HDRLEN {
            let len = u32_at(b, 0).ok_or_else(malformed)? as usize;
            let ty = u16_at(b, 4).ok_or_else(malformed)?;
            let mseq = u32_at(b, 8).ok_or_else(malformed)?;
            if len < NLMSG_HDRLEN || len > b.len() {
                return Err(malformed());
            }
            let payload = &b[NLMSG_HDRLEN..len];
            if mseq == seq {
                match ty {
                    NLMSG_ERROR => {
                        let code = u32_at(payload, 0).ok_or_else(malformed)? as i32;
                        return match -code {
                            0 => Err(malformed()),
                            libc::ENETUNREACH | libc::EHOSTUNREACH | libc::EACCES => Ok(Some(None)),
                            e => Err(io::Error::from_raw_os_error(e)),
                        };
                    }
                    RTM_NEWROUTE => {
                        let mut out = Vec::new();
                        parse_route_entry(payload, &mut out)?;
                        return Ok(Some((!out.is_empty()).then_some(out)));
                    }
                    _ => {}
                }
            }
            b = &b[align4(len).min(b.len())..];
        }
        Ok(None)
    }

    /// One `RTM_NEWROUTE` of a dump into `out` (routes the kernel cached, `RTM_F_CLONED`, and
    /// routes that reach nothing are skipped).
    fn parse_route(p: &[u8], out: &mut Vec<Route>) -> io::Result<()> {
        let flags = u32_at(p, 8).ok_or_else(malformed)?;
        if flags & RTM_F_CLONED != 0 {
            return Ok(());
        }
        parse_route_entry(p, out)
    }

    /// One `RTM_NEWROUTE` into `out`, one [`Route`] per nexthop; nothing for a route of a type
    /// that reaches nothing (`blackhole`, `unreachable`, `prohibit`, `throw`, `multicast`, …).
    fn parse_route_entry(p: &[u8], out: &mut Vec<Route>) -> io::Result<()> {
        if p.len() < RTMSG_LEN {
            return Err(malformed());
        }
        let (family, dst_len, rtype) = (p[0], p[1], p[7]);
        let kind = match rtype {
            RTN_UNICAST => RouteType::Unicast,
            // Review r2 R2-NG-1: these deliver to this host; they were dropped, so an AnyIP
            // range (`local 185.199.108.0/24 dev lo`) was admitted.
            RTN_LOCAL => RouteType::Local,
            RTN_BROADCAST => RouteType::Broadcast,
            RTN_ANYCAST => RouteType::Anycast,
            _ => return Ok(()),
        };
        let mut table = u32::from(p[4]);
        let mut dst = None;
        let mut gateway = None;
        let mut oif = 0u32;
        let mut nh_object = false;
        let mut multipath: Vec<(Hop, u32)> = Vec::new();
        for (ty, data) in attrs(&p[RTMSG_LEN..])? {
            match ty {
                RTA_DST => dst = addr(family, data),
                RTA_GATEWAY => gateway = addr(family, data),
                RTA_VIA => gateway = via(data),
                RTA_OIF => oif = u32_at(data, 0).unwrap_or(0),
                RTA_TABLE => table = u32_at(data, 0).ok_or_else(malformed)?,
                RTA_NH_ID => nh_object = true,
                RTA_MULTIPATH => {
                    // struct rtnexthop { u16 len; u8 flags; u8 hops; i32 ifindex; } + attributes.
                    let mut m = data;
                    while m.len() >= 8 {
                        let len = usize::from(u16_at(m, 0).ok_or_else(malformed)?);
                        if len < 8 || len > m.len() {
                            return Err(malformed());
                        }
                        let ifindex = u32_at(m, 4).ok_or_else(malformed)?;
                        let mut gw = None;
                        for (t, d) in attrs(&m[8..len])? {
                            match t {
                                RTA_GATEWAY => gw = addr(family, d),
                                RTA_VIA => gw = via(d),
                                _ => {}
                            }
                        }
                        multipath.push((gw.map_or(Hop::OnLink, Hop::Via), ifindex));
                        m = &m[align4(len).min(m.len())..];
                    }
                }
                _ => {}
            }
        }
        let unspecified = if i32::from(family) == libc::AF_INET {
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        } else if i32::from(family) == libc::AF_INET6 {
            IpAddr::V6(Ipv6Addr::UNSPECIFIED)
        } else {
            return Ok(());
        };
        let prefix = Prefix::new(dst.unwrap_or(unspecified), dst_len);
        let mut push = |hop: Hop, ifindex: u32| {
            out.push(Route {
                prefix,
                hop,
                ifindex,
                loopback: false,
                kind,
                table,
            })
        };
        if !multipath.is_empty() {
            for (hop, ifindex) in multipath {
                push(hop, ifindex);
            }
        } else {
            let hop = match (gateway, nh_object) {
                (Some(gw), _) => Hop::Via(gw),
                (None, true) => Hop::Unknown,
                (None, false) => Hop::OnLink,
            };
            push(hop, oif);
        }
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn attr(ty: u16, data: &[u8]) -> Vec<u8> {
            let mut v = Vec::new();
            v.extend_from_slice(&((4 + data.len()) as u16).to_ne_bytes());
            v.extend_from_slice(&ty.to_ne_bytes());
            v.extend_from_slice(data);
            while v.len() % 4 != 0 {
                v.push(0);
            }
            v
        }

        fn msg(ty: u16, seq: u32, payload: &[u8]) -> Vec<u8> {
            let mut v = Vec::new();
            v.extend_from_slice(&((NLMSG_HDRLEN + payload.len()) as u32).to_ne_bytes());
            v.extend_from_slice(&ty.to_ne_bytes());
            v.extend_from_slice(&2u16.to_ne_bytes()); // NLM_F_MULTI
            v.extend_from_slice(&seq.to_ne_bytes());
            v.extend_from_slice(&0u32.to_ne_bytes());
            v.extend_from_slice(payload);
            v
        }

        fn rt(family: u8, dst_len: u8, rtype: u8, attrs: &[Vec<u8>]) -> Vec<u8> {
            let mut v = vec![family, dst_len, 0, 0, 254, 3, 0, rtype, 0, 0, 0, 0];
            for a in attrs {
                v.extend_from_slice(a);
            }
            v
        }

        #[test]
        fn route_messages_parse() {
            let v4 = libc::AF_INET as u8;
            let v6 = libc::AF_INET6 as u8;
            let mut dgram = Vec::new();
            // default via 192.168.1.1 dev 2
            dgram.extend(msg(
                RTM_NEWROUTE,
                1,
                &rt(
                    v4,
                    0,
                    RTN_UNICAST,
                    &[
                        attr(RTA_GATEWAY, &[192, 168, 1, 1]),
                        attr(RTA_OIF, &2u32.to_ne_bytes()),
                    ],
                ),
            ));
            // 172.17.0.0/16 dev 3 (on-link)
            dgram.extend(msg(
                RTM_NEWROUTE,
                1,
                &rt(
                    v4,
                    16,
                    RTN_UNICAST,
                    &[
                        attr(RTA_DST, &[172, 17, 0, 0]),
                        attr(RTA_OIF, &3u32.to_ne_bytes()),
                    ],
                ),
            ));
            // local 192.168.1.33 (type local): kept, as a route that delivers to this host
            dgram.extend(msg(
                RTM_NEWROUTE,
                1,
                &rt(v4, 32, RTN_LOCAL, &[attr(RTA_DST, &[192, 168, 1, 33])]),
            ));
            // blackhole 10.66.0.0/16 (type 6): reaches nothing, skipped
            dgram.extend(msg(
                RTM_NEWROUTE,
                1,
                &rt(v4, 16, 6, &[attr(RTA_DST, &[10, 66, 0, 0])]),
            ));
            // 2606:4700:1::/64 dev 2 (on-link, proto ra)
            let mut d6 = [0u8; 16];
            d6[..6].copy_from_slice(&[0x26, 0x06, 0x47, 0x00, 0, 1]);
            dgram.extend(msg(
                RTM_NEWROUTE,
                1,
                &rt(
                    v6,
                    64,
                    RTN_UNICAST,
                    &[attr(RTA_DST, &d6), attr(RTA_OIF, &2u32.to_ne_bytes())],
                ),
            ));
            // ::/0 through a nexthop object (no gateway shown)
            dgram.extend(msg(
                RTM_NEWROUTE,
                1,
                &rt(v6, 0, RTN_UNICAST, &[attr(RTA_NH_ID, &7u32.to_ne_bytes())]),
            ));
            // 10.9.0.0/16 multipath: via 10.0.0.1 dev 4, on-link dev 5
            let mut nh1 = Vec::new();
            let gw = attr(RTA_GATEWAY, &[10, 0, 0, 1]);
            nh1.extend_from_slice(&((8 + gw.len()) as u16).to_ne_bytes());
            nh1.extend_from_slice(&[0, 0]);
            nh1.extend_from_slice(&4u32.to_ne_bytes());
            nh1.extend(gw);
            nh1.extend_from_slice(&8u16.to_ne_bytes());
            nh1.extend_from_slice(&[0, 0]);
            nh1.extend_from_slice(&5u32.to_ne_bytes());
            dgram.extend(msg(
                RTM_NEWROUTE,
                1,
                &rt(
                    v4,
                    16,
                    RTN_UNICAST,
                    &[attr(RTA_DST, &[10, 9, 0, 0]), attr(RTA_MULTIPATH, &nh1)],
                ),
            ));
            // Another sequence number: ignored.
            dgram.extend(msg(
                RTM_NEWROUTE,
                9,
                &rt(v4, 8, RTN_UNICAST, &[attr(RTA_DST, &[11, 0, 0, 0])]),
            ));
            let mut out = Vec::new();
            assert!(!parse_messages(&dgram, 1, &mut out).unwrap());
            let p = |s: &str| s.parse::<Prefix>().unwrap();
            let ip = |s: &str| s.parse::<IpAddr>().unwrap();
            assert_eq!(
                out,
                vec![
                    Route {
                        prefix: p("0.0.0.0/0"),
                        hop: Hop::Via(ip("192.168.1.1")),
                        ifindex: 2,
                        loopback: false,
                        kind: RouteType::Unicast,
                        table: 254,
                    },
                    Route {
                        prefix: p("172.17.0.0/16"),
                        hop: Hop::OnLink,
                        ifindex: 3,
                        loopback: false,
                        kind: RouteType::Unicast,
                        table: 254,
                    },
                    Route {
                        prefix: p("192.168.1.33/32"),
                        hop: Hop::OnLink,
                        ifindex: 0,
                        loopback: false,
                        kind: RouteType::Local,
                        table: 254,
                    },
                    Route {
                        prefix: p("2606:4700:1::/64"),
                        hop: Hop::OnLink,
                        ifindex: 2,
                        loopback: false,
                        kind: RouteType::Unicast,
                        table: 254,
                    },
                    Route {
                        prefix: p("::/0"),
                        hop: Hop::Unknown,
                        ifindex: 0,
                        loopback: false,
                        kind: RouteType::Unicast,
                        table: 254,
                    },
                    Route {
                        prefix: p("10.9.0.0/16"),
                        hop: Hop::Via(ip("10.0.0.1")),
                        ifindex: 4,
                        loopback: false,
                        kind: RouteType::Unicast,
                        table: 254,
                    },
                    Route {
                        prefix: p("10.9.0.0/16"),
                        hop: Hop::OnLink,
                        ifindex: 5,
                        loopback: false,
                        kind: RouteType::Unicast,
                        table: 254,
                    },
                ]
            );
            assert!(parse_messages(&msg(NLMSG_DONE, 1, &[0; 4]), 1, &mut out).unwrap());
            let err = msg(NLMSG_ERROR, 1, &(-libc::EPERM).to_ne_bytes());
            assert_eq!(
                parse_messages(&err, 1, &mut out)
                    .unwrap_err()
                    .raw_os_error(),
                Some(libc::EPERM)
            );
            // A length past the datagram is malformed.
            let mut bad = msg(RTM_NEWROUTE, 1, &rt(v4, 0, RTN_UNICAST, &[]));
            bad[0] = 200;
            assert!(parse_messages(&bad, 1, &mut out).is_err());
        }

        /// Review r2 R2-NG-8 (PoC `an_aborted_or_interrupted_dump_counts_as_complete`), inverted:
        /// an `NLMSG_DONE` carrying a negative errno is that error, and a message flagged
        /// `NLM_F_DUMP_INTR` fails the dump (to be retried) instead of counting as complete.
        #[test]
        fn an_aborted_or_interrupted_dump_is_an_error() {
            let v4 = libc::AF_INET as u8;
            let default = msg(
                RTM_NEWROUTE,
                1,
                &rt(
                    v4,
                    0,
                    RTN_UNICAST,
                    &[
                        attr(RTA_GATEWAY, &[192, 168, 1, 1]),
                        attr(RTA_OIF, &2u32.to_ne_bytes()),
                    ],
                ),
            );
            let mut d = default.clone();
            d.extend(msg(NLMSG_DONE, 1, &(-libc::EINTR).to_ne_bytes()));
            let mut out = Vec::new();
            let e = parse_messages(&d, 1, &mut out).unwrap_err();
            assert_eq!(e.raw_os_error(), Some(libc::EINTR), "{e}");
            assert!(!is_interrupted(&e));
            // NLM_F_DUMP_INTR on a route message: the dump is refused, and marked for a retry.
            let mut m = msg(
                RTM_NEWROUTE,
                1,
                &rt(
                    v4,
                    16,
                    RTN_UNICAST,
                    &[
                        attr(RTA_DST, &[52, 95, 0, 0]),
                        attr(RTA_OIF, &7u32.to_ne_bytes()),
                    ],
                ),
            );
            m[6..8].copy_from_slice(&(2u16 | NLM_F_DUMP_INTR).to_ne_bytes());
            let e = parse_messages(&m, 1, &mut Vec::new()).unwrap_err();
            assert!(is_interrupted(&e), "{e}");
            // On the DONE message too.
            let mut d = default.clone();
            let mut done = msg(NLMSG_DONE, 1, &[0; 4]);
            done[6..8].copy_from_slice(&(2u16 | NLM_F_DUMP_INTR).to_ne_bytes());
            d.extend(done);
            assert!(is_interrupted(
                &parse_messages(&d, 1, &mut Vec::new()).unwrap_err()
            ));
            // A clean DONE (error 0, or no payload at all) still ends the dump.
            let mut d = default;
            d.extend(msg(NLMSG_DONE, 1, &[]));
            assert!(parse_messages(&d, 1, &mut Vec::new()).unwrap());
        }

        /// Review r2 R2-NG-1 (PoC `anyip_local_routes_are_dropped_and_admitted`), inverted: AnyIP
        /// routes (`ip route add local 185.199.108.0/24 dev lo`, and its IPv6 form) are read, and
        /// every address they hold is refused, by `admit` and in the broker's flattened view.
        #[test]
        fn anyip_local_routes_are_read_and_refused() {
            use crate::{admit, FactsOptions, HostFacts, NetMode, RawFacts};
            const RT_TABLE_LOCAL: u8 = 255;
            let local_rt = |family: u8, dst_len: u8, attrs: &[Vec<u8>]| {
                let mut v = rt(family, dst_len, RTN_LOCAL, attrs);
                v[4] = RT_TABLE_LOCAL;
                v[6] = 254; // scope host
                v
            };
            let v4 = libc::AF_INET as u8;
            let v6 = libc::AF_INET6 as u8;
            let (lo, eth) = (1u32, 2u32);
            let mut d = Vec::new();
            d.extend(msg(
                RTM_NEWROUTE,
                1,
                &rt(
                    v4,
                    0,
                    RTN_UNICAST,
                    &[
                        attr(RTA_GATEWAY, &[192, 168, 1, 1]),
                        attr(RTA_OIF, &eth.to_ne_bytes()),
                    ],
                ),
            ));
            d.extend(msg(
                RTM_NEWROUTE,
                1,
                &rt(
                    v4,
                    24,
                    RTN_UNICAST,
                    &[
                        attr(RTA_DST, &[192, 168, 1, 0]),
                        attr(RTA_OIF, &eth.to_ne_bytes()),
                    ],
                ),
            ));
            d.extend(msg(
                RTM_NEWROUTE,
                1,
                &local_rt(
                    v4,
                    24,
                    &[
                        attr(RTA_DST, &[185, 199, 108, 0]),
                        attr(RTA_OIF, &lo.to_ne_bytes()),
                    ],
                ),
            ));
            let mut fe80 = [0u8; 16];
            fe80[..2].copy_from_slice(&[0xfe, 0x80]);
            fe80[15] = 1;
            d.extend(msg(
                RTM_NEWROUTE,
                1,
                &rt(
                    v6,
                    0,
                    RTN_UNICAST,
                    &[attr(RTA_GATEWAY, &fe80), attr(RTA_OIF, &eth.to_ne_bytes())],
                ),
            ));
            let mut any6 = [0u8; 16];
            any6[..6].copy_from_slice(&[0x2a, 0x01, 0x04, 0xf9, 0xaa, 0xaa]);
            d.extend(msg(
                RTM_NEWROUTE,
                1,
                &local_rt(
                    v6,
                    48,
                    &[attr(RTA_DST, &any6), attr(RTA_OIF, &lo.to_ne_bytes())],
                ),
            ));
            // A TPROXY catch-all: `local default dev lo table 100`.
            let mut tproxy = local_rt(v4, 0, &[attr(RTA_OIF, &lo.to_ne_bytes())]);
            tproxy[4] = 100;
            d.extend(msg(RTM_NEWROUTE, 1, &tproxy));
            let mut routes = Vec::new();
            assert!(!parse_messages(&d, 1, &mut routes).unwrap());
            let p = |s: &str| s.parse::<Prefix>().unwrap();
            let ip = |s: &str| s.parse::<IpAddr>().unwrap();
            for (prefix, kind) in [
                ("185.199.108.0/24", RouteType::Local),
                ("2a01:4f9:aaaa::/48", RouteType::Local),
                ("0.0.0.0/0", RouteType::Local),
            ] {
                assert!(
                    routes
                        .iter()
                        .any(|r| r.prefix == p(prefix) && r.kind == kind),
                    "{prefix} read: {routes:#?}"
                );
            }
            let facts = HostFacts::assemble(
                RawFacts {
                    interface_prefixes: vec![
                        p("127.0.0.0/8"),
                        p("192.168.1.0/24"),
                        p("::1/128"),
                        p("2a01:4f8:c17:1234::/64"),
                    ],
                    interface_addresses: vec![
                        ip("127.0.0.1"),
                        ip("192.168.1.33"),
                        ip("::1"),
                        ip("2a01:4f8:c17:1234::2"),
                    ],
                    routes,
                    resolvers: vec![ip("127.0.0.53")],
                    ..RawFacts::default()
                },
                &FactsOptions {
                    discover_public_addresses: false,
                    ..FactsOptions::default()
                },
            );
            for a in [
                "185.199.108.10",
                "2a01:4f9:aaaa::1",
                "2a01:4f9:aaaa:1234::5",
                "::ffff:185.199.108.10",
            ] {
                let r = admit(NetMode::Public, ip(a), &facts, &[]);
                assert!(
                    matches!(
                        r,
                        Err(crate::Denied::OffDefaultRoute {
                            kind: super::super::RouteKind::Local,
                            ..
                        })
                    ),
                    "{a}: {r:?}"
                );
                assert!(r
                    .unwrap_err()
                    .to_string()
                    .contains("delivered to this host"));
                assert!(
                    facts.refused_prefixes().iter().any(|q| q.contains(ip(a))),
                    "{a} in the flattened view"
                );
                assert!(
                    crate::admit_prefix(NetMode::Public, Prefix::host(ip(a)), &facts, &[]).is_err()
                );
            }
            // The TPROXY `/0` is left alone: the internet stays reachable.
            for a in ["8.8.8.8", "185.199.109.1", "2a01:4f9:aaab::1"] {
                assert_eq!(admit(NetMode::Public, ip(a), &facts, &[]), Ok(()), "{a}");
            }
        }

        /// A `struct fib_rule_hdr` and its attributes.
        fn rule(family: u8, dst_len: u8, action: u8, flags: u32, attrs: &[Vec<u8>]) -> Vec<u8> {
            let mut v = vec![family, dst_len, 0, 0, 0, 0, 0, action];
            v.extend_from_slice(&flags.to_ne_bytes());
            for a in attrs {
                v.extend_from_slice(a);
            }
            v
        }

        /// Rules are read for this process's own connections: mark 0, its uid, input interface
        /// `lo`, no output interface, TOS 0, TCP; a source, port or unknown selector depends on the
        /// connection. Then the ordinary tables and the steered destinations follow.
        #[test]
        fn rule_messages_parse_for_this_processs_connections() {
            let v4 = libc::AF_INET as u8;
            let flow = Flow {
                uid: 1000,
                loopback: Some("lo".into()),
            };
            let table = |t: u32| attr(FRA_TABLE, &t.to_ne_bytes());
            let prio = |n: u32| attr(FRA_PRIORITY, &n.to_ne_bytes());
            let name = |s: &str| {
                let mut b = s.as_bytes().to_vec();
                b.push(0);
                b
            };
            /// A rule message and what it reads as: action, `to`, inverted, match.
            type Case = (Vec<u8>, RuleAction, Option<&'static str>, bool, RuleMatch);
            let cases: Vec<Case> = vec![
                // 0: from all lookup local
                (
                    rule(
                        v4,
                        0,
                        FR_ACT_TO_TBL,
                        0,
                        &[table(255), attr(FRA_PROTOCOL, &[2])],
                    ),
                    RuleAction::Lookup(255),
                    None,
                    false,
                    RuleMatch::Always,
                ),
                // 100: to 52.95.0.0/16 lookup 100
                (
                    rule(
                        v4,
                        16,
                        FR_ACT_TO_TBL,
                        0,
                        &[prio(100), attr(FRA_DST, &[52, 95, 0, 0]), table(100)],
                    ),
                    RuleAction::Lookup(100),
                    Some("52.95.0.0/16"),
                    false,
                    RuleMatch::Always,
                ),
                // 200: from 10.8.0.6 lookup 101
                (
                    {
                        let mut r = rule(
                            v4,
                            0,
                            FR_ACT_TO_TBL,
                            0,
                            &[attr(FRA_SRC, &[10, 8, 0, 6]), table(101)],
                        );
                        r[2] = 32;
                        r
                    },
                    RuleAction::Lookup(101),
                    None,
                    false,
                    RuleMatch::Sometimes,
                ),
                // not from all fwmark 0xca6c lookup 51820 (wg-quick)
                (
                    rule(
                        v4,
                        0,
                        FR_ACT_TO_TBL,
                        FIB_RULE_INVERT,
                        &[attr(FRA_FWMARK, &0xca6cu32.to_ne_bytes()), table(51820)],
                    ),
                    RuleAction::Lookup(51820),
                    None,
                    true,
                    RuleMatch::Never,
                ),
                // fwmark 0x80000/0xff0000 lookup 102 (Tailscale's own packets)
                (
                    rule(
                        v4,
                        0,
                        FR_ACT_TO_TBL,
                        0,
                        &[
                            attr(FRA_FWMARK, &0x80000u32.to_ne_bytes()),
                            attr(FRA_FWMASK, &0xff0000u32.to_ne_bytes()),
                            table(102),
                        ],
                    ),
                    RuleAction::Lookup(102),
                    None,
                    false,
                    RuleMatch::Never,
                ),
                // uidrange 1000-1000 lookup 103: this uid
                (
                    rule(
                        v4,
                        0,
                        FR_ACT_TO_TBL,
                        0,
                        &[
                            attr(
                                FRA_UID_RANGE,
                                &[1000u32.to_ne_bytes(), 1000u32.to_ne_bytes()].concat(),
                            ),
                            table(103),
                        ],
                    ),
                    RuleAction::Lookup(103),
                    None,
                    false,
                    RuleMatch::Always,
                ),
                // uidrange 0-999 lookup 104: not this uid
                (
                    rule(
                        v4,
                        0,
                        FR_ACT_TO_TBL,
                        0,
                        &[
                            attr(
                                FRA_UID_RANGE,
                                &[0u32.to_ne_bytes(), 999u32.to_ne_bytes()].concat(),
                            ),
                            table(104),
                        ],
                    ),
                    RuleAction::Lookup(104),
                    None,
                    false,
                    RuleMatch::Never,
                ),
                // iif lo lookup 105: locally generated traffic
                (
                    rule(
                        v4,
                        0,
                        FR_ACT_TO_TBL,
                        0,
                        &[attr(FRA_IIFNAME, &name("lo")), table(105)],
                    ),
                    RuleAction::Lookup(105),
                    None,
                    false,
                    RuleMatch::Always,
                ),
                // iif eth0 lookup 106: forwarded traffic only
                (
                    rule(
                        v4,
                        0,
                        FR_ACT_TO_TBL,
                        0,
                        &[attr(FRA_IIFNAME, &name("eth0")), table(106)],
                    ),
                    RuleAction::Lookup(106),
                    None,
                    false,
                    RuleMatch::Never,
                ),
                // oif wg0 lookup 107: device-bound sockets only
                (
                    rule(
                        v4,
                        0,
                        FR_ACT_TO_TBL,
                        0,
                        &[attr(FRA_OIFNAME, &name("wg0")), table(107)],
                    ),
                    RuleAction::Lookup(107),
                    None,
                    false,
                    RuleMatch::Never,
                ),
                // ipproto udp lookup 108 / ipproto tcp lookup 109
                (
                    rule(
                        v4,
                        0,
                        FR_ACT_TO_TBL,
                        0,
                        &[attr(FRA_IP_PROTO, &[17]), table(108)],
                    ),
                    RuleAction::Lookup(108),
                    None,
                    false,
                    RuleMatch::Never,
                ),
                (
                    rule(
                        v4,
                        0,
                        FR_ACT_TO_TBL,
                        0,
                        &[attr(FRA_IP_PROTO, &[6]), table(109)],
                    ),
                    RuleAction::Lookup(109),
                    None,
                    false,
                    RuleMatch::Always,
                ),
                // dport 443 lookup 110: some connections
                (
                    rule(
                        v4,
                        0,
                        FR_ACT_TO_TBL,
                        0,
                        &[
                            attr(
                                FRA_DPORT_RANGE,
                                &[443u16.to_ne_bytes(), 443u16.to_ne_bytes()].concat(),
                            ),
                            table(110),
                        ],
                    ),
                    RuleAction::Lookup(110),
                    None,
                    false,
                    RuleMatch::Sometimes,
                ),
                // tos 0x10 lookup 111
                (
                    {
                        let mut r = rule(v4, 0, FR_ACT_TO_TBL, 0, &[table(111)]);
                        r[3] = 0x10;
                        r
                    },
                    RuleAction::Lookup(111),
                    None,
                    false,
                    RuleMatch::Never,
                ),
                // A selector this code does not know (attribute 99): it may select.
                (
                    rule(
                        v4,
                        0,
                        FR_ACT_TO_TBL,
                        0,
                        &[attr(99, &[1, 2, 3, 4]), table(112)],
                    ),
                    RuleAction::Lookup(112),
                    None,
                    false,
                    RuleMatch::Sometimes,
                ),
                // to 10.0.0.0/8 blackhole
                (
                    rule(v4, 8, 6, 0, &[attr(FRA_DST, &[10, 0, 0, 0])]),
                    RuleAction::Other,
                    Some("10.0.0.0/8"),
                    false,
                    RuleMatch::Always,
                ),
            ];
            let mut dgram = Vec::new();
            for (body, ..) in &cases {
                dgram.extend(msg(RTM_NEWRULE, 1, body));
            }
            dgram.extend(msg(NLMSG_DONE, 1, &[0; 4]));
            let mut rules = Vec::new();
            assert!(parse_rule_messages(&dgram, 1, &flow, &mut rules).unwrap());
            assert_eq!(rules.len(), cases.len());
            for (r, (_, action, to, invert, matches)) in rules.iter().zip(&cases) {
                assert_eq!(r.action, *action, "{r:?}");
                assert_eq!(r.to, to.map(|t| t.parse().unwrap()), "{r:?}");
                assert_eq!(r.invert, *invert, "{r:?}");
                assert_eq!(r.matches, *matches, "{r:?}");
                assert!(!r.v6);
            }
            assert_eq!(rules[1].priority, 100);
            let t = super::super::RouteTable::with_rules(Vec::new(), rules.clone());
            for (table, ordinary) in [
                (255, true),
                (254, false), // no `lookup main` among these rules
                (100, false),
                (101, false),
                (51820, true), // `not fwmark` matches mark 0
                (102, false),
                (103, true),
                (104, false),
                (105, true),
                (106, false),
                (107, false),
                (108, false),
                (109, true),
                (110, false),
                (111, false),
                (112, false),
            ] {
                assert_eq!(t.is_ordinary(false, table), ordinary, "table {table}");
            }
            assert_eq!(t.steered(), &[("52.95.0.0/16".parse().unwrap(), 100)]);
            // Another uid: the uid rules swap.
            let mut other = Vec::new();
            let root = Flow { uid: 0, ..flow };
            assert!(parse_rule_messages(&dgram, 1, &root, &mut other).unwrap());
            assert_eq!(other[5].matches, RuleMatch::Never);
            assert_eq!(other[6].matches, RuleMatch::Always);
            // A destination length without a destination is malformed.
            let bad = msg(RTM_NEWRULE, 1, &rule(v4, 16, FR_ACT_TO_TBL, 0, &[table(5)]));
            assert!(parse_rule_messages(&bad, 1, &root, &mut Vec::new()).is_err());
        }

        /// A route's table comes from `RTA_TABLE` (tables above 255 do not fit `rtm_table`).
        #[test]
        fn route_tables_parse() {
            let v4 = libc::AF_INET as u8;
            let mut body = rt(
                v4,
                0,
                RTN_UNICAST,
                &[
                    attr(RTA_GATEWAY, &[10, 8, 0, 1]),
                    attr(RTA_OIF, &7u32.to_ne_bytes()),
                    attr(RTA_TABLE, &51820u32.to_ne_bytes()),
                ],
            );
            body[4] = 252; // RT_TABLE_COMPAT
            let mut out = Vec::new();
            assert!(!parse_messages(&msg(RTM_NEWROUTE, 1, &body), 1, &mut out).unwrap());
            assert_eq!(out[0].table, 51820);
            let body = rt(v4, 0, RTN_UNICAST, &[attr(RTA_OIF, &7u32.to_ne_bytes())]);
            let mut out = Vec::new();
            parse_messages(&msg(RTM_NEWROUTE, 1, &body), 1, &mut out).unwrap();
            assert_eq!(out[0].table, 254);
        }

        /// Review r2 R2-NG-3, on this host's real routing (read-only): the kernel answers per
        /// destination, and on a host whose rules are the stock ones its verdicts agree with the
        /// prefix model's: own addresses deliver locally, on-link neighbours are on-link, public
        /// addresses take the default path.
        #[test]
        fn this_hosts_kernel_answers_agree_with_its_tables() {
            use super::super::{RouteKind, RouteTable};
            let (routes, rules) = dump().unwrap();
            let t = RouteTable::with_rules(routes.clone(), rules.clone());
            let stock = rules.iter().all(|r| {
                r.to.is_none()
                    && r.matches == RuleMatch::Always
                    && !r.invert
                    && matches!(r.action, RuleAction::Lookup(253..=255))
            });
            let ip = |s: &str| s.parse::<IpAddr>().unwrap();
            let mut checked = 0;
            for v6 in [false, true] {
                let has_default = t
                    .routes()
                    .iter()
                    .any(|r| r.prefix.addr.is_ipv6() == v6 && r.prefix.len == 0);
                let public = if v6 {
                    ip("2606:4700:4700::1111")
                } else {
                    ip("8.8.8.8")
                };
                let answer = query(public).expect("route query");
                if has_default {
                    let a = answer.expect("a route to the internet");
                    assert_eq!(t.judge(&a), Ok(()), "{public}: {a:?}");
                    checked += 1;
                } else {
                    assert!(t.judge(answer.as_deref().unwrap_or_default()).is_err());
                }
            }
            // This host's own addresses: delivered locally (link-local ones need a scope).
            for r in t.local_routes() {
                let a = r.prefix.addr;
                if r.kind != RouteType::Local
                    || matches!(a, IpAddr::V6(v) if v.segments()[0] & 0xffc0 == 0xfe80)
                {
                    continue;
                }
                let answer = query(a).unwrap().expect("a local route");
                assert_eq!(
                    t.judge(&answer).map_err(|r| r.kind),
                    Err(RouteKind::Local),
                    "{a}: {answer:?}"
                );
                checked += 1;
            }
            // A neighbour on each on-link route (not the host itself, not a broadcast address).
            for prefix in t.on_link_prefixes() {
                let width = if prefix.addr.is_ipv4() { 32 } else { 128 };
                if prefix.len + 3 > width
                    || matches!(prefix.addr, IpAddr::V6(v) if v.segments()[0] & 0xffc0 == 0xfe80)
                {
                    continue;
                }
                let n = match prefix.addr {
                    IpAddr::V4(a) => IpAddr::V4(Ipv4Addr::from(u32::from(a) | 6)),
                    IpAddr::V6(a) => IpAddr::V6(Ipv6Addr::from(u128::from(a) | 6)),
                };
                if t.local_routes().iter().any(|r| r.holds(n)) {
                    continue;
                }
                let answer = query(n).unwrap().expect("an on-link route");
                let kernel = t.judge(&answer).map_err(|r| r.kind);
                assert_eq!(kernel, Err(RouteKind::OnLink), "{n}: {answer:?}");
                if stock {
                    assert_eq!(
                        t.off_default_path(n).map(|r| r.kind),
                        Some(RouteKind::OnLink)
                    );
                }
                checked += 1;
            }
            eprintln!("{checked} kernel answers checked against the tables");
            assert!(checked >= 2, "checked {checked}");
        }

        /// The answer to a route query: an entry, no route (`ENETUNREACH`), a type that reaches
        /// nothing, another sequence number (not ours), a failure.
        #[test]
        fn route_answers_parse() {
            let v4 = libc::AF_INET as u8;
            let mut entry = rt(
                v4,
                1,
                RTN_UNICAST,
                &[
                    attr(RTA_GATEWAY, &[10, 8, 0, 1]),
                    attr(RTA_OIF, &7u32.to_ne_bytes()),
                ],
            );
            entry[8..12].copy_from_slice(&RTM_F_CLONED.to_ne_bytes()); // kept in an answer
            let got = parse_answer(&msg(RTM_NEWROUTE, 1, &entry), 1).unwrap();
            let routes = got.unwrap().unwrap();
            assert_eq!(routes.len(), 1);
            assert_eq!(routes[0].prefix, "0.0.0.0/1".parse().unwrap());
            assert_eq!(
                parse_answer(&msg(NLMSG_ERROR, 1, &(-libc::ENETUNREACH).to_ne_bytes()), 1).unwrap(),
                Some(None)
            );
            let blackhole = rt(v4, 8, 6, &[attr(RTA_DST, &[10, 0, 0, 0])]);
            assert_eq!(
                parse_answer(&msg(RTM_NEWROUTE, 1, &blackhole), 1).unwrap(),
                Some(None)
            );
            assert_eq!(
                parse_answer(&msg(RTM_NEWROUTE, 2, &entry), 1).unwrap(),
                None
            );
            let e =
                parse_answer(&msg(NLMSG_ERROR, 1, &(-libc::ENOBUFS).to_ne_bytes()), 1).unwrap_err();
            assert_eq!(e.raw_os_error(), Some(libc::ENOBUFS));
        }

        /// This host's own tables and rules read, and have what every running Linux host has:
        /// `main` consulted for every connection.
        #[test]
        fn this_hosts_routes_and_rules_read() {
            let (routes, rules) = dump().expect("netlink route and rule dumps");
            assert!(routes.len() < MAX_ROUTES);
            for r in &routes {
                assert_eq!(Prefix::new(r.prefix.addr, r.prefix.len), r.prefix, "{r:?}");
            }
            assert!(!rules.is_empty(), "every host has a `lookup main` rule");
            let t = super::super::RouteTable::with_rules(routes, rules.clone());
            assert!(t.is_ordinary(false, 254), "{rules:#?}");
            if rules.iter().any(|r| r.v6) {
                assert!(t.is_ordinary(true, 254), "{rules:#?}");
            }
            assert_eq!(Flow::current().uid, unsafe { libc::getuid() });
            assert_eq!(Flow::current().loopback.as_deref(), Some("lo"));
        }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
mod sys {
    pub(super) fn dump() -> std::io::Result<(Vec<super::Route>, Vec<super::Rule>)> {
        Ok((Vec::new(), Vec::new()))
    }

    pub(super) fn query(_: std::net::IpAddr) -> std::io::Result<Option<Vec<super::Route>>> {
        Err(std::io::ErrorKind::Unsupported.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> Prefix {
        s.parse().unwrap()
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    /// A home host: DHCP default via the router, the LAN on-link, Docker's bridge, DHCP option 121
    /// host routes via the router, and IPv6 from router advertisements.
    fn home() -> RouteTable {
        RouteTable::new(vec![
            Route::via(p("0.0.0.0/0"), ip("192.168.1.1"), 2),
            Route::via(p("1.1.1.1/32"), ip("192.168.1.1"), 2),
            Route::via(p("172.233.157.223/32"), ip("192.168.1.1"), 2),
            Route::on_link(p("192.168.1.0/24"), 2),
            Route::on_link(p("192.168.1.1/32"), 2),
            Route::on_link(p("172.17.0.0/16"), 3),
            Route::on_link(p("2606:a300:9024:184::/64"), 2),
            Route::on_link(p("fe80::/64"), 2),
            Route::via(p("::/0"), ip("fe80::1"), 2),
        ])
    }

    #[test]
    fn the_default_path_is_admitted_and_everything_else_refused() {
        let t = home();
        for a in [
            "8.8.8.8",
            "1.1.1.1",
            "172.233.157.223",
            "2606:4700::1",
            "2606:a300:9024:185::1",
        ] {
            assert_eq!(t.off_default_path(ip(a)), None, "{a}");
        }
        for (a, route) in [
            ("192.168.1.7", "192.168.1.0/24"),
            ("172.17.0.2", "172.17.0.0/16"),
            ("2606:a300:9024:184::99", "2606:a300:9024:184::/64"),
        ] {
            assert_eq!(
                t.off_default_path(ip(a)).map(|r| r.prefix),
                Some(p(route)),
                "{a}"
            );
        }
        assert_eq!(
            t.on_link_prefixes(),
            vec![
                p("172.17.0.0/16"),
                p("192.168.1.0/24"),
                p("192.168.1.1/32"),
                p("2606:a300:9024:184::/64"),
                p("fe80::/64"),
            ]
        );
        assert_eq!(t.off_default_prefixes(), t.on_link_prefixes());
    }

    /// The reviewers' case: a DHCPv6 host has a /128 address; its /64 is only a route.
    #[test]
    fn a_dhcpv6_host_routes_its_on_link_64() {
        let t = RouteTable::new(vec![
            Route::on_link(p("2606:4700:1::/64"), 2),
            Route::via(p("::/0"), ip("fe80::1"), 2),
        ]);
        assert_eq!(t.on_link_prefixes(), vec![p("2606:4700:1::/64")]);
        assert!(t.off_default_path(ip("2606:4700:1::6")).is_some());
        assert!(t.off_default_path(ip("2606:4700:2::6")).is_none());
    }

    /// An IPv4 /32 address with its subnet as a route (cloud images, some DHCP clients).
    #[test]
    fn a_slash_32_host_routes_its_subnet() {
        let t = RouteTable::new(vec![
            Route::on_link(p("203.0.113.0/24"), 2),
            Route::via(p("0.0.0.0/0"), ip("203.0.113.1"), 2),
        ]);
        assert!(t.off_default_path(ip("203.0.113.50")).is_some());
        assert_eq!(t.on_link_prefixes(), vec![p("203.0.113.0/24")]);
    }

    /// VPNs: a split tunnel's pushed routes (through the VPN's gateway, or on its interface) are
    /// refused, a full tunnel's split default is the default path, and so is the VPN server's own
    /// host route via the LAN router.
    #[test]
    fn vpn_routes_are_refused_and_full_tunnels_are_the_default_path() {
        let t = RouteTable::new(vec![
            Route::via(p("0.0.0.0/0"), ip("192.168.1.1"), 2),
            Route::on_link(p("10.8.0.0/24"), 7),
            Route::via(p("198.51.100.0/24"), ip("10.8.0.1"), 7), // a company's public range
            Route::on_link(p("100.64.0.0/10"), 8),               // Tailscale
            Route::on_link(p("203.0.113.0/24"), 9),              // WireGuard AllowedIPs
            Route::via(p("0.0.0.0/1"), ip("10.8.0.1"), 7),       // OpenVPN def1
            Route::via(p("128.0.0.0/1"), ip("10.8.0.1"), 7),
            Route::via(p("192.0.2.10/32"), ip("192.168.1.1"), 2), // the VPN server, via the LAN
            Route::via(p("2000::/4"), ip("fd00::1"), 7),
        ]);
        for (a, refused) in [
            ("198.51.100.20", true),
            ("203.0.113.5", true),
            ("100.100.100.100", true),
            ("8.8.8.8", false),   // the /1 split default
            ("200.1.1.1", false), // the other half
            ("192.0.2.10", false),
            ("2606:4700::1", false),
        ] {
            assert_eq!(t.off_default_path(ip(a)).is_some(), refused, "{a}");
        }
        assert!(t.off_default_prefixes().contains(&p("198.51.100.0/24")));
        assert!(!t.off_default_prefixes().contains(&p("0.0.0.0/1")));
        assert!(!t.on_link_prefixes().contains(&p("198.51.100.0/24")));
    }

    /// A gateway-less default route (PPPoE, a WireGuard full tunnel) is the default path; so is a
    /// split default without a gateway. A route on a loopback interface is not, and is not a
    /// connected prefix either.
    #[test]
    fn gateway_less_defaults_and_loopback_routes() {
        let mut lo = Route::on_link(p("198.18.0.0/15"), 1);
        lo.loopback = true;
        let t = RouteTable::new(vec![
            Route::on_link(p("0.0.0.0/0"), 5),
            Route::on_link(p("::/3"), 5),
            lo,
        ]);
        assert!(t.off_default_path(ip("8.8.8.8")).is_none());
        assert!(t.off_default_path(ip("2606:4700::1")).is_none());
        assert!(t.off_default_path(ip("198.18.0.1")).is_some());
        assert!(t.on_link_prefixes().is_empty());
        assert_eq!(t.off_default_prefixes(), vec![p("198.18.0.0/15")]);
    }

    /// Ties at the best length: one off-path route among them refuses. A nexthop object whose
    /// gateway is not shown is not the default path; a default through one still is.
    #[test]
    fn ties_and_unknown_gateways() {
        let t = RouteTable::new(vec![
            Route::via(p("0.0.0.0/0"), ip("192.168.1.1"), 2),
            Route::via(p("9.9.0.0/16"), ip("192.168.1.1"), 2),
            Route::on_link(p("9.9.0.0/16"), 4),
            Route {
                hop: Hop::Unknown,
                ..Route::on_link(p("8.8.0.0/16"), 2)
            },
            Route {
                hop: Hop::Unknown,
                ..Route::on_link(p("::/0"), 2)
            },
        ]);
        assert!(t.off_default_path(ip("9.9.1.1")).is_some());
        assert!(t.off_default_path(ip("8.8.8.8")).is_some());
        assert!(t.off_default_path(ip("2606:4700::1")).is_none());
        // A route through the default gateway on another interface is not the default path.
        let t = RouteTable::new(vec![
            Route::via(p("0.0.0.0/0"), ip("192.168.1.1"), 2),
            Route::via(p("9.9.0.0/16"), ip("192.168.1.1"), 3),
        ]);
        assert!(t.off_default_path(ip("9.9.1.1")).is_some());
        // Nothing holds it: no route, no refusal.
        assert!(RouteTable::default()
            .off_default_path(ip("8.8.8.8"))
            .is_none());
    }

    /// Review r2 R2-NG-2 (PoC `a_default_in_another_table_launders_routes_through_its_gateway`),
    /// inverted: a `/0` in a table only a selector reaches (or none) is no default route, and its
    /// gateway no uplink, so a VPN-pushed route through that gateway in `main` stays refused.
    #[test]
    fn a_default_in_another_table_launders_nothing() {
        let base = vec![
            Route::via(p("0.0.0.0/0"), ip("192.168.1.1"), 2),
            Route::on_link(p("10.8.0.0/24"), 7),
            Route::via(p("52.95.0.0/16"), ip("10.8.0.1"), 7),
        ];
        let vpn_default = Route::via(p("0.0.0.0/0"), ip("10.8.0.1"), 7).in_table(100);
        let mut with = base.clone();
        with.push(vpn_default);
        let from_vpn = Rule {
            matches: RuleMatch::Sometimes, // `from 10.8.0.6`
            ..Rule::lookup(false, 100)
        };
        let mut rules = Rule::stock(false);
        rules.insert(0, from_vpn);
        for t in [
            RouteTable::new(with.clone()), // table 100 named by no rule
            RouteTable::with_rules(with.clone(), rules),
        ] {
            assert_eq!(t.uplinks(), &[(ip("192.168.1.1"), 2)]);
            let r = t.off_default_path(ip("52.95.1.1"));
            assert_eq!(
                r,
                Some(RouteRefusal {
                    prefix: p("52.95.0.0/16"),
                    kind: RouteKind::OtherGateway
                })
            );
            assert!(t.off_default_prefixes().contains(&p("52.95.0.0/16")));
            // The rest of the internet is still the main default.
            assert_eq!(t.off_default_path(ip("8.8.8.8")), None);
            assert!(!t.off_default_prefixes().iter().any(|q| q.len == 0));
        }
        // The same default in an ordinary table (a full tunnel) is an uplink, as before.
        let mut rules = Rule::stock(false);
        rules.insert(0, Rule::lookup(false, 100));
        let t = RouteTable::with_rules(with, rules);
        assert!(t.uplinks().contains(&(ip("10.8.0.1"), 7)));
        assert_eq!(t.off_default_path(ip("52.95.1.1")), None);
    }

    /// Review r2 R2-NG-3 (PoC `destination_policy_rule_into_a_vpn_table_is_admitted`), inverted,
    /// in the prefix model: `ip rule add to 52.95.0.0/16 lookup 100` with a default in table 100
    /// refuses all of 52.95.0.0/16, with a gateway or without (WireGuard).
    #[test]
    fn destination_rules_into_another_table_refuse_their_prefix() {
        let mut rules = Rule::stock(false);
        rules.insert(0, Rule::to(p("52.95.0.0/16"), 100));
        for vpn in [
            Route::via(p("0.0.0.0/0"), ip("10.8.0.1"), 7).in_table(100),
            Route::on_link(p("0.0.0.0/0"), 9).in_table(100), // default dev wg0
        ] {
            let t = RouteTable::with_rules(
                vec![
                    Route::via(p("0.0.0.0/0"), ip("192.168.1.1"), 2),
                    Route::on_link(p("192.168.1.0/24"), 2),
                    vpn,
                ],
                rules.clone(),
            );
            assert_eq!(
                t.off_default_path(ip("52.95.1.1")),
                Some(RouteRefusal {
                    prefix: p("52.95.0.0/16"),
                    kind: RouteKind::PolicyRule
                })
            );
            assert!(t.off_default_prefixes().contains(&p("52.95.0.0/16")));
            assert_eq!(t.off_default_path(ip("52.96.0.1")), None);
        }
        // A destination rule into an ordinary table (an allow-list back into `main`) refuses
        // nothing; an inverted one makes its table ordinary.
        let mut rules = Rule::stock(false);
        rules.insert(0, Rule::to(p("192.168.0.0/16"), RT_TABLE_MAIN));
        rules.insert(
            0,
            Rule {
                invert: true,
                ..Rule::to(p("192.168.0.0/16"), 51820)
            },
        );
        let t = RouteTable::with_rules(
            vec![
                Route::via(p("0.0.0.0/0"), ip("192.168.1.1"), 2),
                Route::on_link(p("0.0.0.0/0"), 9).in_table(51820),
            ],
            rules,
        );
        assert!(t.steered().is_empty());
        assert!(t.is_ordinary(false, 51820));
        assert_eq!(t.off_default_path(ip("8.8.8.8")), None);
        // A rule that never selects this process's connections steers nothing.
        let mut rules = Rule::stock(false);
        rules.insert(
            0,
            Rule {
                matches: RuleMatch::Never, // `to 52.95.0.0/16 fwmark 0x1 lookup 100`
                ..Rule::to(p("52.95.0.0/16"), 100)
            },
        );
        assert!(RouteTable::with_rules(Vec::new(), rules)
            .steered()
            .is_empty());
    }

    /// wg-quick's full tunnel: `not fwmark 0xca6c lookup 51820` (which this process's mark-0
    /// connections match) and `lookup main suppress_prefixlength 0`. Table 51820's gateway-less
    /// default is the default path; the LAN stays refused.
    #[test]
    fn a_wg_quick_full_tunnel_is_the_default_path() {
        let rules = vec![
            Rule::lookup(false, RT_TABLE_LOCAL),
            Rule::lookup(false, RT_TABLE_MAIN), // suppress_prefixlength 0
            Rule {
                invert: true,
                matches: RuleMatch::Never, // fwmark 0xca6c
                ..Rule::lookup(false, 51820)
            },
            Rule::lookup(false, RT_TABLE_MAIN),
        ];
        let t = RouteTable::with_rules(
            vec![
                Route::via(p("0.0.0.0/0"), ip("192.168.1.1"), 2),
                Route::on_link(p("192.168.1.0/24"), 2),
                Route::on_link(p("0.0.0.0/0"), 9).in_table(51820),
            ],
            rules,
        );
        assert_eq!(t.off_default_path(ip("8.8.8.8")), None);
        assert!(t.off_default_path(ip("192.168.1.7")).is_some());
    }

    /// Review r2 R2-NG-1: a route that delivers to this host refuses what it holds, whatever its
    /// length (`/1` included) and table, except a `/0` (a TPROXY catch-all). Local routes that
    /// leave no public address of a routed family are reported, so a policy can refuse to start.
    #[test]
    fn local_routes_refuse_and_short_ones_are_reported() {
        let default4 = Route::via(p("0.0.0.0/0"), ip("192.168.1.1"), 2);
        let default6 = Route::via(p("::/0"), ip("fe80::1"), 2);
        let bcast = Route {
            kind: RouteType::Broadcast,
            ..Route::on_link(p("203.0.114.255/32"), 2)
        };
        let any6 = Route {
            kind: RouteType::Anycast,
            ..Route::on_link(p("2606:a300:9024:184::/128"), 2)
        };
        let t = RouteTable::new(vec![
            default4,
            default6,
            Route::local(p("0.0.0.0/0"), 1),
            Route::local(p("0.0.0.0/1"), 1),
            bcast,
            any6,
        ]);
        for (a, refused) in [
            ("8.8.8.8", true),              // the /1
            ("200.1.1.1", false),           // outside it; the /0 is left alone
            ("203.0.114.255", true),        // broadcast
            ("203.0.114.254", false),       // next to it
            ("2606:a300:9024:184::", true), // subnet-router anycast
            ("2606:a300:9024:184::1", false),
        ] {
            let r = t.off_default_path(ip(a));
            assert_eq!(r.is_some(), refused, "{a}: {r:?}");
            if let Some(r) = r {
                assert_eq!(r.kind, RouteKind::Local, "{a}");
            }
        }
        assert_eq!(
            t.off_default_prefixes(),
            vec![
                p("0.0.0.0/1"),
                p("203.0.114.255/32"),
                p("2606:a300:9024:184::/128")
            ]
        );
        assert_eq!(t.local_refuses_everything(), None);
        // Both IPv4 halves: nothing public is left over IPv4, and IPv6 has no default route.
        let t = RouteTable::new(vec![
            default4,
            Route::local(p("0.0.0.0/1"), 1),
            Route::local(p("128.0.0.0/1"), 1),
        ]);
        assert_eq!(
            t.local_refuses_everything(),
            Some(vec![p("0.0.0.0/1"), p("128.0.0.0/1")])
        );
        // IPv6 still routes: not everything.
        let mut with6 = t.routes().to_vec();
        with6.extend(t.local_routes());
        with6.push(default6);
        assert_eq!(
            RouteTable::new(with6.clone()).local_refuses_everything(),
            None
        );
        // Unless 2000::/3 is covered too (by two /4s).
        with6.push(Route::local(p("2000::/4"), 1));
        with6.push(Route::local(p("3000::/4"), 1));
        assert!(RouteTable::new(with6).local_refuses_everything().is_some());
        // No default route at all: nothing to report.
        assert_eq!(
            RouteTable::new(vec![Route::local(p("0.0.0.0/1"), 1)]).local_refuses_everything(),
            None
        );
    }
}
