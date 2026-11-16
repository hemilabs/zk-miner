//! The host's routing table, and the best-route rule (review r1, fetch F1 / broker F1).
//!
//! An interface's netmask does not say everything the host is directly attached to. A DHCPv6
//! address is a /128 while the router advertises its /64 as on-link (a route, `proto ra`); an IPv4
//! address can be a /32 with the subnet installed as a route; a VPN, WireGuard, Tailscale or Docker
//! network is a route on its own interface, sometimes to global addresses. So the facts include
//! every unicast route of every routing table (netlink `RTM_GETROUTE`, which needs no privileges),
//! and two rules come from it:
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
//! Routes of every table are merged, so policy routing (`ip rule`) is not modelled: a specific
//! route in any table refuses its destinations, even where a rule would never consult that table.
//! That errs towards refusing. A destination no route holds is admitted (the kernel will not
//! connect to it either).
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
    /// The unicast routes.
    routes: Vec<Route>,
    /// The routes that deliver to this host (`local`, `broadcast`, `anycast`), `/0` left out.
    local: Vec<Route>,
    /// `(gateway, interface)` of every true default route (`/0`) that has a gateway.
    uplinks: Vec<(IpAddr, u32)>,
}

impl RouteTable {
    pub fn new(routes: Vec<Route>) -> Self {
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
        routes.sort();
        routes.dedup();
        let mut uplinks: Vec<(IpAddr, u32)> = routes
            .iter()
            .filter(|r| r.prefix.len == 0)
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
            uplinks,
        }
    }

    /// Every unicast route, sorted.
    pub fn routes(&self) -> &[Route] {
        &self.routes
    }

    /// Every route that delivers to this host (`local`, `broadcast`, `anycast`; not `/0`), sorted.
    pub fn local_routes(&self) -> &[Route] {
        &self.local
    }

    /// Whether `r` takes the default path: it is a default route (or a split default), or it goes
    /// through the gateway, on the interface, of a true default route.
    pub fn via_default_path(&self, r: &Route) -> bool {
        if r.is_default_like() {
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
    /// a loopback interface, routes through another gateway, routes that deliver to this host):
    /// what a consumer that knows only prefixes must refuse to refuse what
    /// [`Self::off_default_path`] refuses. Wider than the rule itself where a more specific
    /// default-path route sits inside one of them.
    pub fn off_default_prefixes(&self) -> Vec<Prefix> {
        let mut v: Vec<Prefix> = self
            .routes
            .iter()
            .filter(|r| !self.via_default_path(r))
            .chain(&self.local)
            .map(|r| r.prefix)
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
            if !self
                .routes
                .iter()
                .any(|r| r.prefix.addr.is_ipv6() == v6 && r.prefix.len == 0)
            {
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

/// Reads every unicast, `local`, `broadcast` and `anycast` route of every table, IPv4 and IPv6.
/// `loopback` is the set of loopback interface indexes (from the interface list).
pub(crate) fn read_routes(loopback: &[u32]) -> std::io::Result<Vec<Route>> {
    let mut routes = sys::dump()?;
    for r in &mut routes {
        r.loopback = r.ifindex != 0 && loopback.contains(&r.ifindex);
    }
    Ok(routes)
}

#[cfg(any(target_os = "linux", target_os = "android"))]
mod sys {
    //! A netlink `RTM_GETROUTE` dump, per family. Unprivileged; every table.

    use std::io;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    use super::{Hop, Route, RouteType};
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
    const RTA_NH_ID: u16 = 30;
    /// The most a dump message can be (the kernel caps dump skbs at 32 KiB).
    const RECV_BUF: usize = 64 * 1024;
    /// A ceiling on the routes read, against a runaway dump.
    const MAX_ROUTES: usize = 1 << 20;

    /// Times a dump the kernel flags as interrupted (`NLM_F_DUMP_INTR`: the table changed while it
    /// was read) is started again before the read fails.
    const DUMP_ATTEMPTS: usize = 5;
    /// `nlmsghdr.nlmsg_flags`: the dump was interrupted by a change and may be inconsistent.
    const NLM_F_DUMP_INTR: u16 = 0x10;

    pub(super) fn dump() -> io::Result<Vec<Route>> {
        let mut out = Vec::new();
        for family in [libc::AF_INET, libc::AF_INET6] {
            out.extend(dump_consistent(family as u8)?);
        }
        Ok(out)
    }

    /// One family's routes from a dump the kernel neither aborted nor flagged as interrupted,
    /// retried up to [`DUMP_ATTEMPTS`] times; a table that keeps changing fails the read (the
    /// caller then keeps its last good facts, or refuses to start).
    fn dump_consistent(family: u8) -> io::Result<Vec<Route>> {
        for _ in 0..DUMP_ATTEMPTS {
            let mut out = Vec::new();
            match dump_family(family, &mut out) {
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

    /// The error [`parse_messages`] returns for a dump flagged `NLM_F_DUMP_INTR`.
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

    fn dump_family(family: u8, out: &mut Vec<Route>) -> io::Result<()> {
        // SAFETY: plain socket(2); the fd is owned by `sock` from here on.
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
        let sock = unsafe { OwnedFd::from_raw_fd(fd) };
        let seq: u32 = 1;
        let mut req = Vec::with_capacity(NLMSG_HDRLEN + RTMSG_LEN);
        req.extend_from_slice(&((NLMSG_HDRLEN + RTMSG_LEN) as u32).to_ne_bytes());
        req.extend_from_slice(&RTM_GETROUTE.to_ne_bytes());
        req.extend_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
        req.extend_from_slice(&seq.to_ne_bytes());
        req.extend_from_slice(&0u32.to_ne_bytes());
        let mut rtmsg = [0u8; RTMSG_LEN];
        rtmsg[0] = family;
        req.extend_from_slice(&rtmsg);
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
        let mut buf = vec![0u8; RECV_BUF];
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
            if parse_messages(&buf[..n as usize], seq, out)? {
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

    /// Parses one datagram of the dump into `out`; `true` once the dump is done.
    ///
    /// Fails closed (review r2, R2-NG-8): an `NLMSG_DONE` that carries a negative errno (the kernel
    /// aborted the dump, `dump_done_errno`) is that error, and a message flagged `NLM_F_DUMP_INTR`
    /// (the table changed while it was dumped, so routes may be missing) fails the dump at once
    /// with an error [`dump_consistent`] retries; neither is ever taken as a complete table.
    pub(super) fn parse_messages(mut b: &[u8], seq: u32, out: &mut Vec<Route>) -> io::Result<bool> {
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
                    RTM_NEWROUTE => parse_route(payload, out)?,
                    _ => {}
                }
            }
            b = &b[align4(len).min(b.len())..];
        }
        Ok(false)
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

    fn parse_route(p: &[u8], out: &mut Vec<Route>) -> io::Result<()> {
        if p.len() < RTMSG_LEN {
            return Err(malformed());
        }
        let (family, dst_len, rtype) = (p[0], p[1], p[7]);
        let flags = u32_at(p, 8).ok_or_else(malformed)?;
        let kind = match rtype {
            RTN_UNICAST => RouteType::Unicast,
            // Review r2 R2-NG-1: these deliver to this host; they were dropped, so an AnyIP
            // range (`local 185.199.108.0/24 dev lo`) was admitted.
            RTN_LOCAL => RouteType::Local,
            RTN_BROADCAST => RouteType::Broadcast,
            RTN_ANYCAST => RouteType::Anycast,
            _ => return Ok(()),
        };
        if flags & RTM_F_CLONED != 0 {
            return Ok(());
        }
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
                    },
                    Route {
                        prefix: p("172.17.0.0/16"),
                        hop: Hop::OnLink,
                        ifindex: 3,
                        loopback: false,
                        kind: RouteType::Unicast,
                    },
                    Route {
                        prefix: p("192.168.1.33/32"),
                        hop: Hop::OnLink,
                        ifindex: 0,
                        loopback: false,
                        kind: RouteType::Local,
                    },
                    Route {
                        prefix: p("2606:4700:1::/64"),
                        hop: Hop::OnLink,
                        ifindex: 2,
                        loopback: false,
                        kind: RouteType::Unicast,
                    },
                    Route {
                        prefix: p("::/0"),
                        hop: Hop::Unknown,
                        ifindex: 0,
                        loopback: false,
                        kind: RouteType::Unicast,
                    },
                    Route {
                        prefix: p("10.9.0.0/16"),
                        hop: Hop::Via(ip("10.0.0.1")),
                        ifindex: 4,
                        loopback: false,
                        kind: RouteType::Unicast,
                    },
                    Route {
                        prefix: p("10.9.0.0/16"),
                        hop: Hop::OnLink,
                        ifindex: 5,
                        loopback: false,
                        kind: RouteType::Unicast,
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

        /// This host's own table reads, and has what every running Linux host has.
        #[test]
        fn this_hosts_routes_read() {
            let routes = dump().expect("netlink route dump");
            assert!(routes.len() < MAX_ROUTES);
            for r in &routes {
                assert_eq!(Prefix::new(r.prefix.addr, r.prefix.len), r.prefix, "{r:?}");
            }
        }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
mod sys {
    pub(super) fn dump() -> std::io::Result<Vec<super::Route>> {
        Ok(Vec::new())
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
