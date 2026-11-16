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
//! - **site prefixes:** the enclosing /`ipv6_site_prefix_len` (default /56) of every own global
//!   IPv6 address. A home or office is delegated a /56 (or a /48) and numbers its other networks
//!   from it, none of which the host's own /64 shows;
//! - **DNS servers:** the `nameserver`s of `/etc/resolv.conf` and of systemd-resolved's
//!   `/run/systemd/resolve/resolv.conf` (the upstream servers behind its `127.0.0.53` stub), which
//!   may answer only their own customers;
//! - **the routing table and the policy-routing rules**, for the best-route rule: a destination
//!   whose best route is not the default path is refused, and so is one a `local`, `broadcast` or
//!   `anycast` route delivers to this host (an AnyIP range) or a destination rule sends to another
//!   table ([`crate::routes::RouteTable::off_default_path`]); and the kernel itself, asked per
//!   destination how it would route a connection ([`crate::routes::RouteTable::judge`]).
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

/// The default `[egress] ipv6_site_prefix_len`.
pub const DEFAULT_IPV6_SITE_PREFIX_LEN: u8 = 56;
/// The lengths `[egress] ipv6_site_prefix_len` may take.
pub const IPV6_SITE_PREFIX_LENS: RangeInclusive<u8> = 48..=64;

/// The operator's settings for gathering host facts (`[egress]`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FactsOptions {
    /// The site around each of the host's own global IPv6 addresses that is refused
    /// ([`IPV6_SITE_PREFIX_LENS`], default [`DEFAULT_IPV6_SITE_PREFIX_LEN`]).
    pub ipv6_site_prefix_len: u8,
    /// Whether to learn the host's public (NAT) addresses from fixed reflectors
    /// ([`crate::public`]). Default true.
    pub discover_public_addresses: bool,
}

impl Default for FactsOptions {
    fn default() -> Self {
        FactsOptions {
            ipv6_site_prefix_len: DEFAULT_IPV6_SITE_PREFIX_LEN,
            discover_public_addresses: true,
        }
    }
}

impl FactsOptions {
    /// Refuses a site prefix length outside [`IPV6_SITE_PREFIX_LENS`].
    pub fn validate(&self) -> Result<(), String> {
        if IPV6_SITE_PREFIX_LENS.contains(&self.ipv6_site_prefix_len) {
            Ok(())
        } else {
            Err(format!(
                "ipv6_site_prefix_len = {} is outside {}..={}",
                self.ipv6_site_prefix_len,
                IPV6_SITE_PREFIX_LENS.start(),
                IPV6_SITE_PREFIX_LENS.end()
            ))
        }
    }
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
    /// The host's public addresses as reflectors see them.
    pub public_addresses: Vec<IpAddr>,
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
    /// The oracle's verdicts, per destination, for as long as these facts are in force.
    verdicts: Arc<Mutex<HashMap<IpAddr, Result<(), KernelRefusal>>>>,
}

/// Why the kernel's answer refused a destination ([`HostFacts::kernel_verdict`]).
#[derive(Debug, Clone, PartialEq, Eq)]
enum KernelRefusal {
    Route(RouteRefusal),
    QueryFailed(String),
}

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
        let mut own = raw.interface_addresses;
        own.extend(raw.public_addresses.into_iter().filter(|a| is_global(*a)));
        let own = sorted(own);
        HostFacts {
            connected: sorted(connected),
            site: site_prefixes(&own, opts.ipv6_site_prefix_len),
            own,
            resolvers: sorted(raw.resolvers),
            routes,
            gathered_at: Instant::now(),
            oracle: None,
            verdicts: Arc::default(),
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

    /// The route oracle's verdict on a connection to `ip` (admitted when there is no oracle):
    /// asked once per destination for as long as these facts are in force (a snapshot lives
    /// about a second, [`crate::FACTS_TTL`]). An IPv4-mapped address is asked as its IPv4
    /// address, which is how a dual-stack socket connects to it.
    pub(crate) fn kernel_verdict(&self, ip: IpAddr) -> Result<(), Denied> {
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
            .get(&dst)
            .cloned();
        let verdict = match cached {
            Some(v) => v,
            None => {
                let v = match oracle.route_to(dst) {
                    Ok(answer) => self
                        .routes
                        .judge(answer.as_deref().unwrap_or_default())
                        .map_err(KernelRefusal::Route),
                    Err(e) => Err(KernelRefusal::QueryFailed(e.to_string())),
                };
                let mut cache = self.verdicts.lock().unwrap_or_else(|e| e.into_inner());
                if cache.len() >= MAX_VERDICTS {
                    cache.clear();
                }
                cache.insert(dst, v.clone());
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
    /// table, the DNS servers, and (if `opts` says so) the public addresses, then
    /// [`Self::assemble`]s them. Fails if the interfaces or the routing table cannot be read: a
    /// public-mode policy that does not know them cannot refuse what they name.
    pub fn gather_with(opts: &FactsOptions) -> io::Result<Self> {
        let (interface_prefixes, interface_addresses, loopback) = sys::interfaces()?;
        let (routes, rules) = crate::routes::read_routing(&loopback)?;
        let public_addresses = if opts.discover_public_addresses {
            crate::public::public_addresses()
        } else {
            Vec::new()
        };
        Ok(Self::assemble(
            RawFacts {
                interface_prefixes,
                interface_addresses,
                routes,
                rules,
                resolvers: system_resolvers(),
                public_addresses,
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
    /// connected and site prefixes, the prefixes of every route off the default path, and a host
    /// route for every DNS server.
    pub fn refused_prefixes(&self) -> Vec<Prefix> {
        let mut v = self.connected.clone();
        v.extend_from_slice(&self.site);
        v.extend(self.routes.off_default_prefixes());
        v.extend(self.resolvers.iter().map(|r| Prefix::host(*r)));
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
            ..RawFacts::default()
        };
        let f = HostFacts::assemble(raw.clone(), &offline());
        assert_eq!(
            f.site_prefixes(),
            &[p("2606:a300:9024:100::/56"), p("2a01:4f8:1::/56")]
        );
        // A public address is an own address; a non-global "public" answer is dropped.
        assert!(f.own_addresses().contains(&ip("2a01:4f8:1:2::9")));
        assert!(!f.own_addresses().contains(&ip("10.0.0.1")));
        let f48 = HostFacts::assemble(
            raw,
            &FactsOptions {
                ipv6_site_prefix_len: 48,
                ..offline()
            },
        );
        assert_eq!(
            f48.site_prefixes(),
            &[p("2606:a300:9024::/48"), p("2a01:4f8:1::/48")]
        );
        assert_eq!(
            site_prefixes(&[ip("2606:a300::1")], 99),
            vec![p("2606:a300::/64")]
        );
        assert!(FactsOptions::default().validate().is_ok());
        for bad in [47u8, 65, 0, 128] {
            let o = FactsOptions {
                ipv6_site_prefix_len: bad,
                ..offline()
            };
            assert!(o.validate().is_err(), "{bad}");
        }
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
                p("2606:a300:9024:100::/56"),
                p("2606:a300:9024:184::/64"),
            ]
        );
    }
}
