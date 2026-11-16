//! The global-address predicate ([`is_global`]) and IP prefixes ([`Prefix`]).
//!
//! Allow-only-globally-routable, strictly stronger than the blocklist zkminer's ELF fetch used before
//! this crate (`ip_is_blocked`; every address that blocklist refuses, this refuses, and a test keeps
//! the blocklist verbatim as an oracle):
//!
//! - **IPv4:** everything except the ranges in `V4_NOT_GLOBAL` (this network, RFC 1918, CGNAT,
//!   loopback, link-local and metadata, `192.0.0/24`, the three TEST-NETs, the 6to4 relay anycast,
//!   the AMT relay anycast `192.52.193.0/24`, the AS112 sinks `192.31.196.0/24` and
//!   `192.175.48.0/24`, benchmarking, multicast, `240/4` with the broadcast address, and Azure's
//!   `168.63.129.16`). All of `192.0.0.0/24` is refused, including the two /32s IANA marks globally
//!   reachable (`192.0.0.9` PCP anycast, `192.0.0.10` TURN anycast): no program store lives there,
//!   and the blocklist refuses them. The AMT and AS112 blocks, which IANA also marks globally
//!   reachable, are refused for the reason `2001:1::/32` is (below): anycast services answered by
//!   the nearest instance, which may be a box on the operator's own network.
//! - **IPv6:** only `2000::/3` is global unicast (every RIR allocation is inside it), so everything
//!   else (`::/128`, `::1`, `100::/64`, `5f00::/16`, `fc00::/7` with `fd00:ec2::254`, `fe80::/10`,
//!   `fec0::/10`, `ff00::/8`, and all of `64:ff9b::/32` except the well-known NAT64 /96) is refused,
//!   after these forms are judged by the IPv4 address they embed: IPv4-mapped `::ffff:a.b.c.d`, SIIT
//!   `::ffff:0:a.b.c.d`, and NAT64 `64:ff9b::a.b.c.d` (how a host on an IPv6-only network with DNS64
//!   reaches a store that has only IPv4). Refused **outright, whatever they embed**: IPv4-compatible
//!   `::a.b.c.d` (deprecated by RFC 4291; no host is reached at one, and a host with an automatic
//!   `sit` tunnel carries it to its IPv4 address), 6to4 `2002::/16` and Teredo `2001::/32` (both
//!   deprecated relay prefixes), and the local-use NAT64 `64:ff9b:1::/48` (outside `2000::/3`).
//!   Inside `2000::/3`, also refused: `2001:db8::/32` and `3fff::/20` (documentation), and **all of
//!   the IETF protocol block `2001::/23`**, IANA's globally reachable assignments in it included.
//!   `2001:1::/32` holds three anycast addresses (`2001:1::1` PCP, `2001:1::2` TURN, `2001:1::3`
//!   DNS-SD SRP); `2001:3::/32` is AMT's relay discovery prefix (RFC 7450), an anycast prefix a
//!   gateway uses to reach the nearest relay; `2001:4:112::/48` is AS112-v6 (RFC 7535), anycast DNS
//!   sinks anyone may run locally. An anycast service answers from whichever instance is nearest,
//!   which on a network that runs one (a PCP-capable router, a site's TURN relay, SRP registrar,
//!   AMT relay or AS112 node) is a local box, and no program store lives there (review r2: AMT
//!   had been admitted, against the `2001:1::/32` decision). ORCHIDv2 `2001:20::/28` and the DRIP
//!   entity tags `2001:30::/28` (RFC 9374, ORCHIDv2-formatted) are identifiers, not routable
//!   locators, and the blocklist refuses ORCHIDv2.
//!
//! Ported from the witness broker's egress predicate (`zkminer-witness-broker/src/egress.rs` @
//! bd9aabf), which a review already hardened; the one change is the IPv4-compatible form, refused
//! outright here where the broker judged it by its IPv4 address.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

/// An IPv4 or IPv6 prefix (a CIDR).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Prefix {
    pub addr: IpAddr,
    pub len: u8,
}

impl Prefix {
    /// The prefix `addr/len` with the host bits cleared and `len` clamped to the family's width.
    pub fn new(addr: IpAddr, len: u8) -> Self {
        let len = len.min(width(addr));
        Prefix {
            addr: mask(addr, len),
            len,
        }
    }

    /// The host route of `ip` (a /32 or /128).
    pub fn host(ip: IpAddr) -> Self {
        Prefix {
            addr: ip,
            len: width(ip),
        }
    }

    /// Whether `ip` falls in the prefix. Host bits of `addr` are ignored; a `len` beyond the family's
    /// width is clamped to it (a host route).
    ///
    /// Compared in the canonical space on both sides: the prefix as [`Self::canonical_prefix`]
    /// against the address as [`canonical_ip`], so every embedded-IPv4 spelling (mapped
    /// `::ffff:a.b.c.d`, compatible `::a.b.c.d`, SIIT `::ffff:0:a.b.c.d`, the well-known NAT64
    /// `64:ff9b::a.b.c.d`) of an address or a network is that IPv4 address or network:
    /// `::ffff:10.0.0.5` and `64:ff9b::a00:5` are in `10.0.0.0/8`, and a deny CIDR written
    /// `64:ff9b::808:808/128` holds `8.8.8.8`. A prefix also holds what it holds as written (so
    /// `::1/128` holds `::1`, which [`canonical_ip`] leaves alone). Families never match each other
    /// otherwise.
    pub fn contains(&self, ip: IpAddr) -> bool {
        in_prefix(Prefix::new(self.addr, self.len), ip)
            || in_prefix(self.canonical_prefix(), canonical_ip(ip))
    }

    /// Whether the prefix names one address (a /32 or /128 once an embedded-IPv4 prefix is read as
    /// its IPv4 prefix, [`Self::canonical_prefix`]; `::ffff:0:0/96` is `0.0.0.0/0`, not a host
    /// route).
    pub fn is_host_route(&self) -> bool {
        let p = self.canonical_prefix();
        p.len == width(p.addr)
    }

    /// The prefix as the address space it reaches: an IPv6 prefix of length 96 or more inside one of
    /// the embedded-IPv4 /96s [`canonical_ip`] reads (mapped, compatible, SIIT, the well-known
    /// NAT64) is the IPv4 prefix it embeds; any other is itself, with host bits cleared. Like
    /// [`canonical_ip`], `::/128` and `::1/128` stay themselves.
    pub fn canonical_prefix(&self) -> Prefix {
        let p = Prefix::new(self.addr, self.len);
        if let (IpAddr::V6(v6), true) = (p.addr, p.len >= 96) {
            let x = u128::from(v6);
            if p.len == 128 && x <= 1 {
                return p;
            }
            if EMBEDDED_V4_BASES.contains(&(x >> 32)) {
                return Prefix::new(
                    IpAddr::V4(Ipv4Addr::from(u128::from(v6) as u32)),
                    p.len - 96,
                );
            }
        }
        p
    }

    /// Whether the two prefixes share an address, as written or each read as
    /// [`Self::canonical_prefix`] (so `::ffff:10.0.0.0/104` and `64:ff9b::a00:0/104` overlap
    /// `10.0.0.0/8`, and `64:ff9b::/64` overlaps `64:ff9b::808:800/120`, which it holds as
    /// written). Families never overlap otherwise.
    pub fn overlaps(&self, other: &Prefix) -> bool {
        let raw = |a: Prefix, b: Prefix| {
            a.addr.is_ipv4() == b.addr.is_ipv4() && {
                let len = a.len.min(b.len);
                mask(a.addr, len) == mask(b.addr, len)
            }
        };
        raw(
            Prefix::new(self.addr, self.len),
            Prefix::new(other.addr, other.len),
        ) || raw(self.canonical_prefix(), other.canonical_prefix())
    }
}

/// The high 96 bits of the IPv6 /96s that embed an IPv4 address [`canonical_ip`] reads: compatible
/// `::/96`, mapped `::ffff:0:0/96`, SIIT `::ffff:0:0:0/96` and the well-known NAT64 `64:ff9b::/96`.
const EMBEDDED_V4_BASES: [u128; 4] = [0, 0xffff, 0xffff_0000, 0x0064_ff9b_0000_0000_0000_0000];

impl fmt::Display for Prefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.len)
    }
}

/// Why a CIDR string did not parse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrefixParseError(String);

impl fmt::Display for PrefixParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for PrefixParseError {}

impl FromStr for Prefix {
    type Err = PrefixParseError;

    /// `a.b.c.d/len`, `v6/len`, or a bare address (a host route). Host bits must be zero, so a typo
    /// like `10.0.0.1/8` is an error rather than a silently wider prefix.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let err = |why: &str| PrefixParseError(format!("{:?} {why}", crate::printable(s, 64)));
        let (addr, len) = match s.split_once('/') {
            Some((a, l)) => {
                let addr: IpAddr = a.parse().map_err(|_| err("is not an address"))?;
                if l.is_empty() || l.len() > 3 || !l.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(err("has a malformed prefix length"));
                }
                let len: u8 = l
                    .parse()
                    .map_err(|_| err("has a malformed prefix length"))?;
                (addr, len)
            }
            None => {
                let addr: IpAddr = s.parse().map_err(|_| err("is not an address"))?;
                (addr, width(addr))
            }
        };
        if len > width(addr) {
            return Err(err("has a prefix length above its family's width"));
        }
        if mask(addr, len) != addr {
            return Err(err("has host bits set"));
        }
        Ok(Prefix { addr, len })
    }
}

/// `ip` is in the (normalized) prefix `p`, compared as written: same family, same network bits.
fn in_prefix(p: Prefix, ip: IpAddr) -> bool {
    p.addr.is_ipv4() == ip.is_ipv4() && mask(ip, p.len) == p.addr
}

fn width(ip: IpAddr) -> u8 {
    if ip.is_ipv4() {
        32
    } else {
        128
    }
}

/// `ip` with every bit past `len` cleared.
pub(crate) fn mask(ip: IpAddr, len: u8) -> IpAddr {
    match ip {
        IpAddr::V4(a) => IpAddr::V4(Ipv4Addr::from(u32::from(a) & mask32(len))),
        IpAddr::V6(a) => IpAddr::V6(Ipv6Addr::from(u128::from(a) & mask128(len))),
    }
}

/// `ip` with every embedded-IPv4 form replaced by that IPv4 address (mapped `::ffff:a.b.c.d`,
/// compatible `::a.b.c.d`, SIIT `::ffff:0:a.b.c.d`, the well-known NAT64 `64:ff9b::a.b.c.d`), so deny
/// CIDRs, connected prefixes and the host's own addresses match whichever spelling a connection
/// uses. Used for those comparisons only: [`is_global`] judges the original address.
pub fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => embedded_v4(v6).map_or(ip, IpAddr::V4),
        v4 => v4,
    }
}

fn mask32(len: u8) -> u32 {
    match len {
        0 => 0,
        l => u32::MAX << (32 - u32::from(l.min(32))),
    }
}

fn mask128(len: u8) -> u128 {
    match len {
        0 => 0,
        l => u128::MAX << (128 - u32::from(l.min(128))),
    }
}

/// IPv4 ranges that are not globally routable (or that the old blocklist refused), as (network,
/// length).
const V4_NOT_GLOBAL: &[([u8; 4], u8)] = &[
    ([0, 0, 0, 0], 8),        // "this network" (incl. 0.0.0.0)
    ([10, 0, 0, 0], 8),       // RFC 1918
    ([100, 64, 0, 0], 10),    // shared address space (CGNAT; Alibaba's 100.100.100.200 metadata)
    ([127, 0, 0, 0], 8),      // loopback
    ([169, 254, 0, 0], 16),   // link-local, incl. the 169.254.169.254 metadata endpoint
    ([172, 16, 0, 0], 12),    // RFC 1918
    ([192, 0, 0, 0], 24),     // IETF protocol assignments, all of it (see the module doc)
    ([192, 0, 2, 0], 24),     // TEST-NET-1
    ([192, 88, 99, 0], 24),   // 6to4 relay anycast (deprecated)
    ([192, 168, 0, 0], 16),   // RFC 1918
    ([198, 18, 0, 0], 15),    // benchmarking
    ([198, 51, 100, 0], 24),  // TEST-NET-2
    ([203, 0, 113, 0], 24),   // TEST-NET-3
    ([224, 0, 0, 0], 4),      // multicast
    ([240, 0, 0, 0], 4),      // reserved, incl. 255.255.255.255
    ([168, 63, 129, 16], 32), // Azure's platform endpoint (wireserver / DNS / DHCP)
    ([192, 52, 193, 0], 24),  // AMT relay anycast (IANA global; refused, see the module doc)
    ([192, 31, 196, 0], 24),  // AS112-v4 anycast (likewise)
    ([192, 175, 48, 0], 24),  // AS112 direct delegation anycast (likewise)
];

/// Inside `2000::/3`: ranges refused outright, as (network, length).
const V6_NOT_GLOBAL: &[(u128, u8)] = &[
    (0x2001_0db8 << 96, 32), // documentation
    (0x2002 << 112, 16),     // 6to4, whatever it embeds
    (0x3fff << 112, 20),     // documentation (RFC 9637)
    (0x2001_0000 << 96, 23), // IETF protocol assignments (incl. Teredo, AMT, AS112-v6): all
];

fn in4(a: u32, net: [u8; 4], len: u8) -> bool {
    let m = mask32(len);
    a & m == u32::from_be_bytes(net) & m
}

fn in6(a: u128, net: u128, len: u8) -> bool {
    let m = mask128(len);
    a & m == net & m
}

fn v4_is_global(a: Ipv4Addr) -> bool {
    let x = u32::from(a);
    !V4_NOT_GLOBAL.iter().any(|&(net, len)| in4(x, net, len))
}

/// The IPv4 address an IPv6 address embeds, in the forms [`canonical_ip`] reads: mapped, compatible
/// (not `::`/`::1`), SIIT and the well-known NAT64 /96.
fn embedded_v4(a: Ipv6Addr) -> Option<Ipv4Addr> {
    let x = u128::from(a);
    let low = Ipv4Addr::from(x as u32);
    match x >> 32 {
        0xffff => Some(low),                          // ::ffff:a.b.c.d mapped
        0 if x > 1 => Some(low),                      // ::a.b.c.d compatible
        0xffff_0000 => Some(low),                     // ::ffff:0:a.b.c.d SIIT
        0x0064_ff9b_0000_0000_0000_0000 => Some(low), // 64:ff9b::a.b.c.d NAT64
        _ => None,
    }
}

fn v6_is_global(a: Ipv6Addr) -> bool {
    let x = u128::from(a);
    // IPv4-compatible (and `::`, `::1`): refused whatever it embeds (see the module doc).
    if x >> 32 == 0 {
        return false;
    }
    if let Some(v4) = embedded_v4(a) {
        return v4_is_global(v4);
    }
    if !in6(x, 0x2000 << 112, 3) {
        return false;
    }
    !V6_NOT_GLOBAL.iter().any(|&(net, len)| in6(x, net, len))
}

/// Allow-only-globally-routable unicast: see the module doc for the exact ranges and choices.
pub fn is_global(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4_is_global(v4),
        IpAddr::V6(v6) => v6_is_global(v6),
    }
}

/// Whether **every** address in `p` is global ([`is_global`]): `0.0.0.0/0`, `::/0`, `8.0.0.0/6`
/// (which holds `10.0.0.0/8`) and `::ffff:0:0/96` (every IPv4 address, mapped) are not.
///
/// Exact, from the same tables as [`is_global`]: those tables decide by membership in a fixed set
/// of prefixes (the "boundaries"), so a prefix that strictly contains none of them is classified
/// the same throughout and is judged by its first address; one that does is split in two halves,
/// each judged the same way. The recursion only descends towards boundaries, so it is bounded by
/// their number times the address width.
pub fn prefix_is_global(p: Prefix) -> bool {
    let p = Prefix::new(p.addr, p.len);
    let width = if p.addr.is_ipv4() { 32 } else { 128 };
    let split = p.len < width
        && boundaries().iter().any(|b| {
            b.addr.is_ipv4() == p.addr.is_ipv4() && b.len > p.len && mask(b.addr, p.len) == p.addr
        });
    if !split {
        return is_global(p.addr);
    }
    let lower = Prefix::new(p.addr, p.len + 1);
    let upper = Prefix::new(
        match p.addr {
            IpAddr::V4(a) => IpAddr::V4(Ipv4Addr::from(
                u32::from(a) | (1u32 << (31 - u32::from(p.len))),
            )),
            IpAddr::V6(a) => IpAddr::V6(Ipv6Addr::from(
                u128::from(a) | (1u128 << (127 - u32::from(p.len))),
            )),
        },
        p.len + 1,
    );
    prefix_is_global(lower) && prefix_is_global(upper)
}

/// Every prefix whose membership [`is_global`] depends on (see [`prefix_is_global`]).
fn boundaries() -> &'static [Prefix] {
    static B: std::sync::OnceLock<Vec<Prefix>> = std::sync::OnceLock::new();
    B.get_or_init(|| {
        let v4 = |net: [u8; 4], len: u8| Prefix::new(IpAddr::V4(Ipv4Addr::from(net)), len);
        let v6 = |net: u128, len: u8| Prefix::new(IpAddr::V6(Ipv6Addr::from(net)), len);
        let mut b: Vec<Prefix> = V4_NOT_GLOBAL.iter().map(|&(n, l)| v4(n, l)).collect();
        b.push(v6(0x2000 << 112, 3));
        b.extend(V6_NOT_GLOBAL.iter().map(|&(n, l)| v6(n, l)));
        for base in EMBEDDED_V4_BASES {
            b.push(v6(base << 32, 96));
            // Inside a /96 judged by its IPv4 address, the IPv4 table's boundaries, embedded.
            if base != 0 {
                b.extend(
                    V4_NOT_GLOBAL.iter().map(|&(n, l)| {
                        v6((base << 32) | u128::from(u32::from_be_bytes(n)), 96 + l)
                    }),
                );
            }
        }
        b
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn pfx(s: &str) -> Prefix {
        let (a, l) = s.split_once('/').unwrap();
        Prefix {
            addr: ip(a),
            len: l.parse().unwrap(),
        }
    }

    /// zkminer-chain's `embedded_ipv4` and `ip_is_blocked` as they stood before this crate replaced
    /// them (crates/zkminer-chain/src/programs.rs @ ca2ef82), verbatim: the oracle the new predicate
    /// must be strictly stronger than.
    pub(crate) mod legacy {
        use std::net::{IpAddr, Ipv4Addr};

        fn embedded_ipv4(v6: std::net::Ipv6Addr) -> Option<std::net::Ipv4Addr> {
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return Some(mapped);
            }
            let seg = v6.segments();
            let v4_from = |hi: u16, lo: u16| {
                let a = hi.to_be_bytes();
                let b = lo.to_be_bytes();
                Ipv4Addr::new(a[0], a[1], b[0], b[1])
            };
            if seg[0..6].iter().all(|&s| s == 0) && !(seg[6] == 0 && (seg[7] == 0 || seg[7] == 1)) {
                return Some(v4_from(seg[6], seg[7]));
            }
            if seg[0..4].iter().all(|&s| s == 0) && seg[4] == 0xffff && seg[5] == 0 {
                return Some(v4_from(seg[6], seg[7]));
            }
            if seg[0] == 0x0064 && seg[1] == 0xff9b && seg[2..6].iter().all(|&s| s == 0) {
                return Some(v4_from(seg[6], seg[7]));
            }
            if seg[0] == 0x2002 {
                return Some(v4_from(seg[1], seg[2]));
            }
            if seg[0] == 0x2001 && seg[1] == 0x0000 {
                return Some(v4_from(!seg[6], !seg[7]));
            }
            None
        }

        pub fn ip_is_blocked(ip: &IpAddr) -> bool {
            match ip {
                IpAddr::V4(v4) => {
                    let o = v4.octets();
                    v4.is_loopback()
                        || v4.is_private()
                        || v4.is_link_local()
                        || v4.is_broadcast()
                        || v4.is_multicast()
                        || v4.is_documentation()
                        || v4.is_unspecified()
                        || o[0] == 0
                        || (o[0] == 100 && (o[1] & 0xc0) == 64)
                        || o[0] >= 240
                        || (o[0] == 198 && (o[1] == 18 || o[1] == 19))
                        || (o[0] == 192 && o[1] == 0 && o[2] == 0)
                        || (o[0] == 192 && o[1] == 88 && o[2] == 99)
                        || o == [168, 63, 129, 16]
                }
                IpAddr::V6(v6) => {
                    if embedded_ipv4(*v6).is_some_and(|v4| ip_is_blocked(&IpAddr::V4(v4))) {
                        return true;
                    }
                    let seg = v6.segments();
                    v6.is_loopback()
                        || v6.is_unspecified()
                        || v6.is_multicast()
                        || (seg[0] & 0xfe00) == 0xfc00
                        || (seg[0] & 0xffc0) == 0xfe80
                        || (seg[0] & 0xffc0) == 0xfec0
                        || (seg[0] == 0x0064
                            && seg[1] == 0xff9b
                            && seg[2..6].iter().any(|&s| s != 0))
                        || seg[0] == 0x2002
                        || (seg[0] == 0x2001 && seg[1] == 0x0000)
                        || (seg[0] == 0x2001 && seg[1] == 0x0db8)
                        || (seg[0] == 0x2001 && (seg[1] & 0xfff0) == 0x0020)
                }
            }
        }
    }

    /// Every case the witness spec's §14.1 names (what the blocklist covers, and the gaps it misses),
    /// plus the rest of the not-global set.
    pub(crate) const REFUSED: &[&str] = &[
        // §14.1: what ip_is_blocked already refused.
        "fd00:ec2::254",          // AWS IMDS over IPv6 (ULA)
        "fc00::1",                // ULA
        "fdff:ffff::1",           // ULA
        "::ffff:127.0.0.1",       // mapped loopback
        "::ffff:169.254.169.254", // mapped metadata
        "::ffff:10.0.0.1",        // mapped RFC 1918
        "::a9fe:a9fe",            // compatible metadata
        "::a00:1",                // compatible 10.0.0.1
        "::ffff:0:a9fe:a9fe",     // SIIT metadata
        "::ffff:0:a00:1",         // SIIT 10.0.0.1
        "64:ff9b::a9fe:a9fe",     // NAT64 metadata
        "64:ff9b::a00:1",         // NAT64 10.0.0.1
        "64:ff9b::7f00:1",        // NAT64 loopback
        "2002:a9fe:a9fe::",       // 6to4 metadata
        "2002:808:808::",         // 6to4, whatever it embeds
        "2001::f5ff:fffe",        // Teredo with client 10.0.0.1
        "2001:0:808:808::1",      // Teredo, whatever it embeds
        "100.64.0.1",             // CGNAT
        "100.100.100.200",        // Alibaba Cloud metadata (CGNAT)
        "100.127.255.255",        // CGNAT
        "0.0.0.0",                // 0/8
        "0.1.2.3",                // 0/8
        "198.18.0.1",             // benchmarking
        "198.19.255.255",         // benchmarking
        "192.0.2.1",              // TEST-NET-1
        "198.51.100.1",           // TEST-NET-2
        "203.0.113.255",          // TEST-NET-3
        "2001:db8::1",            // IPv6 documentation
        "224.0.0.1",              // multicast
        "239.255.255.250",        // multicast
        "ff02::1",                // IPv6 multicast
        "ff0e::1",                // IPv6 global-scope multicast
        "240.0.0.1",              // 240/4
        "255.255.255.255",        // broadcast
        "192.0.0.1",              // 192.0.0/24
        "192.0.0.9",              // PCP anycast (IANA global; refused, see the module doc)
        "192.0.0.10",             // TURN anycast (likewise)
        "192.0.0.170",            // NAT64 discovery
        "192.88.99.1",            // 6to4 relay anycast
        "fec0::1",                // site-local
        "168.63.129.16",          // Azure platform endpoint
        "64:ff9b:1::808:808",     // local-use NAT64 (RFC 8215)
        "2001:20::1",             // ORCHIDv2 (refused, see the module doc)
        "2001:2f:ffff::1",        // ORCHIDv2
        // §14.1 gaps: what the blocklist missed.
        "100::1", // discard-only
        "100::ffff:ffff:ffff:ffff",
        "2001:2::1", // benchmarking
        "2001:2:0:ffff::1",
        "3fff::1", // documentation (RFC 9637)
        "3fff:fff:ffff::1",
        "5f00::1", // SRv6 SIDs
        // IPv4-compatible, whatever it embeds (the blocklist judged it by its IPv4 address).
        "::808:808",
        "::101:101",
        // The rest of the not-global set.
        "10.0.0.1",
        "10.255.255.255",
        "127.0.0.1",
        "127.255.255.254",
        "169.254.169.254", // cloud metadata
        "169.254.0.1",
        "172.16.0.1",
        "172.31.255.255",
        "192.168.1.1",
        "::",
        "::1",
        "fe80::1",
        "febf::1",
        "2001:10::1", // deprecated ORCHID
        "2001:1::",   // all of 2001:1::/32, its three IANA anycast addresses included
        "2001:1::1",  // PCP anycast: answered by the nearest instance, often a local router
        "2001:1::2",  // TURN anycast
        "2001:1::3",  // DNS-SD SRP anycast
        "2001:1::4",
        "2001:4:113::1", // next to AS112-v6
        "2001:40::1",    // unassigned in 2001::/23
        "2001:1ff::1",   // the top of 2001::/23
        // Review r2: IANA-global anycast blocks, refused like 2001:1::/32; DRIP like ORCHIDv2.
        "2001:3::1", // AMT relay discovery anycast
        "2001:3:ffff::1",
        "2001:4:112::1", // AS112-v6
        "2001:4:112:ffff::1",
        "2001:30::1", // DRIP DETs
        "2001:3f:ffff::1",
        "192.52.193.1", // AMT (IPv4)
        "192.31.196.1", // AS112-v4
        "192.175.48.1", // AS112 direct delegation
        "::ffff:192.52.193.1",
        "4000::1", // outside 2000::/3
        "1fff::1",
        "::ffff:0.0.0.0",
        "::2", // compatible 0.0.0.2
    ];

    pub(crate) const ADMITTED: &[&str] = &[
        "8.8.8.8",
        "1.1.1.1",
        "93.184.216.34",
        "100.63.255.255", // just below CGNAT
        "100.128.0.0",    // just above CGNAT
        "172.15.255.255",
        "172.32.0.0",
        "169.253.255.255",
        "169.255.0.0",
        "192.0.1.0",
        "192.0.3.0",
        "192.88.98.255",
        "192.88.100.0",
        "198.17.255.255",
        "198.20.0.0",
        "198.51.99.255",
        "203.0.112.255",
        "203.0.114.0",
        "223.255.255.255", // just below multicast
        "168.63.129.15",
        "168.63.129.17",
        "192.31.195.255", // next to AS112-v4
        "192.31.197.0",
        "192.52.192.255", // next to AMT
        "192.52.194.0",
        "192.175.47.255", // next to AS112 direct delegation
        "192.175.49.0",
        "2606:4700:4700::1111",
        "2a00:1450:4001::1",
        "2001:200::1", // just above 2001::/23
        "2001:db7:ffff::1",
        "2001:db9::1",
        "2003::1",
        "3ffe::1",
        "3fff:1000::1",   // just above 3fff::/20
        "::ffff:8.8.8.8", // embedded forms of a public address
        "::ffff:0:808:808",
        "64:ff9b::808:808",
    ];

    #[test]
    fn every_section_14_1_case_and_the_not_global_set_is_refused() {
        for s in REFUSED {
            assert!(!is_global(ip(s)), "{s} must not be global");
        }
    }

    #[test]
    fn public_addresses_and_neighbours_of_the_ranges_are_admitted() {
        for s in ADMITTED {
            assert!(is_global(ip(s)), "{s} must be global");
        }
    }

    #[test]
    fn strictly_stronger_than_the_legacy_blocklist_on_the_tables() {
        for s in REFUSED.iter().chain(ADMITTED) {
            let a = ip(s);
            if legacy::ip_is_blocked(&a) {
                assert!(
                    !is_global(a),
                    "{s}: blocked by ip_is_blocked but global here"
                );
            }
        }
        // And the gaps really are gaps of the old list (so the test above is not vacuous for them).
        for s in [
            "100::1",
            "2001:2::1",
            "3fff::1",
            "5f00::1",
            "4000::1",
            "::808:808",
        ] {
            assert!(!legacy::ip_is_blocked(&ip(s)) && !is_global(ip(s)), "{s}");
        }
    }

    /// Interesting IPv6 /32 heads: every special range and its neighbours.
    const V6_HEADS: &[u32] = &[
        0x0000_0000,
        0x0000_ffff,
        0x0064_ff9b,
        0x0064_ff9a,
        0x0100_0000,
        0x2001_0000,
        0x2001_0001,
        0x2001_0002,
        0x2001_0003,
        0x2001_0004,
        0x2001_0010,
        0x2001_0020,
        0x2001_002f,
        0x2001_0030,
        0x2001_01ff,
        0x2001_0200,
        0x2001_0db8,
        0x2002_0000,
        0x2002_ffff,
        0x3fff_0000,
        0x3fff_1000,
        0x5f00_0000,
        0xfc00_0000,
        0xfd00_0ec2,
        0xfe80_0000,
        0xfec0_0000,
        0xff02_0000,
        0x2606_4700,
    ];

    fn v4_strategy() -> impl Strategy<Value = Ipv4Addr> {
        prop_oneof![
            any::<u32>().prop_map(Ipv4Addr::from),
            // Biased to the special /8s and their neighbours.
            (
                prop::sample::select(vec![
                    0u8, 10, 100, 127, 168, 169, 172, 192, 198, 203, 223, 224, 239, 240, 255
                ]),
                any::<u8>(),
                any::<u8>(),
                any::<u8>()
            )
                .prop_map(|(a, b, c, d)| Ipv4Addr::new(a, b, c, d)),
        ]
    }

    fn v6_strategy() -> impl Strategy<Value = Ipv6Addr> {
        prop_oneof![
            any::<u128>().prop_map(Ipv6Addr::from),
            (
                prop::sample::select(V6_HEADS.to_vec()),
                any::<u128>(),
                0u32..96
            )
                .prop_map(|(h, r, zeros)| {
                    // A head, then random bits with a random run of high zero bits (so the embedded
                    // forms, which need zeros in the middle, are hit).
                    let tail = (r >> 32) >> zeros.min(95);
                    Ipv6Addr::from((u128::from(h) << 96) | tail)
                }),
            (
                v4_strategy(),
                prop::sample::select(vec![
                    0u128,
                    0xffff,
                    0xffff_0000,
                    0x0064_ff9b_0000_0000_0000_0000
                ])
            )
                .prop_map(|(v4, hi)| Ipv6Addr::from((hi << 32) | u128::from(u32::from(v4)))),
        ]
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: 20_000, ..ProptestConfig::default() })]

        #[test]
        fn legacy_blocked_implies_not_global_v4(a in v4_strategy()) {
            let a = IpAddr::V4(a);
            prop_assert!(!(legacy::ip_is_blocked(&a) && is_global(a)), "{a}");
        }

        #[test]
        fn legacy_blocked_implies_not_global_v6(a in v6_strategy()) {
            let a = IpAddr::V6(a);
            prop_assert!(!(legacy::ip_is_blocked(&a) && is_global(a)), "{a}");
        }

        #[test]
        fn embedded_forms_follow_their_v4(v4 in v4_strategy()) {
            let x = u128::from(u32::from(v4));
            for hi in [0xffffu128, 0xffff_0000, 0x0064_ff9b_0000_0000_0000_0000] {
                let a = Ipv6Addr::from((hi << 32) | x);
                prop_assert_eq!(is_global(IpAddr::V6(a)), is_global(IpAddr::V4(v4)), "{}", a);
            }
            // The compatible form never is.
            prop_assert!(!is_global(IpAddr::V6(Ipv6Addr::from(x))));
        }

        #[test]
        fn a_prefix_parses_back_from_its_display(a in any::<u128>(), len in 0u8..=128) {
            let p = Prefix::new(IpAddr::V6(Ipv6Addr::from(a)), len);
            prop_assert_eq!(p.to_string().parse::<Prefix>(), Ok(p));
        }
    }

    #[test]
    fn prefix_contains() {
        let p = pfx("10.0.0.0/8");
        assert!(p.contains(ip("10.1.2.3")));
        assert!(
            p.contains(ip("::ffff:10.1.2.3")),
            "a mapped address is its v4"
        );
        assert!(!p.contains(ip("11.0.0.0")));
        assert!(
            p.contains(ip("::a01:203")),
            "a compatible address is its v4"
        );
        assert!(
            p.contains(ip("::ffff:0:a01:203")),
            "an SIIT address is its v4"
        );
        assert!(
            p.contains(ip("64:ff9b::a01:203")),
            "a NAT64 address is its v4"
        );
        assert!(
            !p.contains(ip("64:ff9b:1::a01:203")),
            "a local-use NAT64 is not"
        );
        assert!(
            pfx("10.9.9.9/8").contains(ip("10.0.0.1")),
            "host bits of the prefix are ignored"
        );
        assert!(pfx("0.0.0.0/0").contains(ip("1.2.3.4")));
        assert!(
            !pfx("0.0.0.0/0").contains(ip("2001:db8::1")),
            "families never mix"
        );
        assert!(!pfx("::/0").contains(ip("1.2.3.4")));
        assert!(pfx("::/0").contains(ip("2001:db8::1")));
        assert!(pfx("1.2.3.4/32").contains(ip("1.2.3.4")));
        assert!(!pfx("1.2.3.4/32").contains(ip("1.2.3.5")));
        assert!(
            pfx("1.2.3.4/40").contains(ip("1.2.3.4")),
            "len is clamped to a host route"
        );
        assert!(!pfx("1.2.3.4/40").contains(ip("1.2.3.5")));
        assert!(pfx("2001:db8:1::/48").contains(ip("2001:db8:1:ffff::1")));
        assert!(!pfx("2001:db8:1::/48").contains(ip("2001:db8:2::1")));
        assert!(pfx("2001:db8::1/200").contains(ip("2001:db8::1")));
        assert!(!pfx("2001:db8::1/200").contains(ip("2001:db8::2")));
        assert!(
            pfx("::ffff:10.0.0.0/104").contains(ip("10.255.0.1")),
            "a mapped prefix is its v4"
        );
        assert!(!pfx("::ffff:10.0.0.0/104").contains(ip("11.0.0.1")));
        assert!(pfx("2001:db8::/31").contains(ip("2001:db9::1")));
        // Review r1 broker F6: a prefix written in any embedded form holds the IPv4 addresses it
        // embeds, in every spelling (it was the mapped form only).
        for p in [
            "64:ff9b::808:808/128",
            "::ffff:0:808:808/128",
            "::808:808/128",
            "::ffff:8.8.8.8/128",
            "8.8.8.8/32",
        ] {
            for a in [
                "8.8.8.8",
                "::ffff:8.8.8.8",
                "::ffff:0:808:808",
                "64:ff9b::808:808",
                "::808:808",
            ] {
                assert!(pfx(p).contains(ip(a)), "{p} holds {a}");
            }
            assert!(!pfx(p).contains(ip("8.8.4.4")), "{p}");
        }
        assert!(pfx("64:ff9b::a00:0/104").contains(ip("10.1.2.3")));
        // What canonical_ip leaves alone is held as written.
        assert!(pfx("::1/128").contains(ip("::1")));
        assert!(pfx("::/128").contains(ip("::")));
        assert!(!pfx("::1/128").contains(ip("0.0.0.1")));
    }

    #[test]
    fn host_routes() {
        for (s, host) in [
            ("1.2.3.4/32", true),
            ("1.2.3.0/24", false),
            ("0.0.0.0/0", false),
            ("::1/128", true),
            ("::/0", false),
            ("::ffff:127.0.0.1/128", true),
            ("::ffff:127.0.0.0/104", false),
            ("::ffff:0.0.0.0/96", false),
        ] {
            assert_eq!(pfx(s).is_host_route(), host, "{s}");
        }
        assert_eq!(Prefix::host(ip("10.0.0.1")), pfx("10.0.0.1/32"));
        assert_eq!(Prefix::new(ip("10.1.2.3"), 8), pfx("10.0.0.0/8"));
        assert_eq!(Prefix::new(ip("10.1.2.3"), 99), pfx("10.1.2.3/32"));
    }

    #[test]
    fn cidr_strings_parse_strictly() {
        assert_eq!("10.0.0.0/8".parse(), Ok(pfx("10.0.0.0/8")));
        assert_eq!("203.0.113.7".parse(), Ok(pfx("203.0.113.7/32")));
        assert_eq!("2001:db8::/32".parse(), Ok(pfx("2001:db8::/32")));
        assert_eq!("2001:db8::1".parse(), Ok(pfx("2001:db8::1/128")));
        assert_eq!("0.0.0.0/0".parse(), Ok(pfx("0.0.0.0/0")));
        for bad in [
            "10.0.0.1/8", // host bits
            "10.0.0.0/33",
            "::/129",
            "10.0.0.0/",
            "10.0.0.0/-1",
            "10.0.0.0/+8",
            "10.0.0.0/0008",
            "10.0.0.0/8/8",
            "10.0.0/8",
            "010.0.0.0/8",
            "example.com/32",
            "",
            " 10.0.0.0/8",
            "fe80::1%eth0/128",
        ] {
            assert!(bad.parse::<Prefix>().is_err(), "{bad:?} parsed");
        }
    }

    #[test]
    fn whole_prefixes_are_global_only_when_every_address_is() {
        for (s, global) in [
            ("0.0.0.0/0", false),
            ("::/0", false),
            ("0.0.0.0/1", false),
            ("128.0.0.0/1", false), // holds 169.254/16, 172.16/12, 192.168/16, multicast
            ("8.0.0.0/7", true),    // 8.0.0.0 - 9.255.255.255
            ("8.0.0.0/6", false),   // holds 10.0.0.0/8
            ("10.0.0.0/7", false),  // 10/8 and 11/8
            ("11.0.0.0/8", true),
            ("100.0.0.0/8", false), // holds CGNAT 100.64/10
            ("100.0.0.0/10", true), // just below it
            ("192.0.0.0/23", false),
            ("192.0.4.0/22", true),
            ("1.1.1.1/32", true),
            ("127.0.0.1/32", false),
            ("2000::/3", false), // holds 2001:db8::/32, 2002::/16, …
            ("2a00::/8", true),
            ("2001::/16", false),
            ("2001:200::/23", true),
            ("2001:3::/32", false), // AMT anycast: refused (review r2)
            ("2001:4:112::/48", false),
            ("192.52.193.0/24", false),
            ("192.52.192.0/24", true),
            ("2001:2::/48", false),
            ("2001:1::/120", false), // the three anycast /128s and their neighbours
            ("2001:1::1/128", false),
            ("2001:1::/32", false),
            ("::ffff:0:0/96", false),       // every IPv4 address, mapped
            ("::ffff:8.8.8.0/120", true),   // a public /24, mapped
            ("64:ff9b::/96", false),        // NAT64 of every IPv4 address
            ("64:ff9b::808:800/120", true), // NAT64 of a public /24
            ("64:ff9b::a00:0/104", false),  // NAT64 of 10/8
            ("::/96", false),               // IPv4-compatible, refused whatever it embeds
            ("::808:800/120", false),
            ("fc00::/7", false),
            ("4000::/2", false),
        ] {
            assert_eq!(prefix_is_global(pfx(s)), global, "{s}");
        }
    }

    #[test]
    fn prefixes_overlap_in_their_canonical_space() {
        for (a, b, overlap) in [
            ("10.0.0.0/8", "10.1.0.0/16", true),
            ("10.1.0.0/16", "10.0.0.0/8", true),
            ("10.0.0.0/8", "11.0.0.0/8", false),
            ("0.0.0.0/0", "203.0.113.7/32", true),
            ("::ffff:10.0.0.0/104", "10.9.0.0/16", true),
            ("64:ff9b::a00:0/104", "10.9.9.9/32", true),
            ("::ffff:0:a00:0/104", "10.0.0.0/8", true),
            ("64:ff9b::808:808/128", "8.8.8.8/32", true),
            ("2001:db8::/32", "2001:db8:1::/48", true),
            ("2001:db8::/32", "2001:db9::/32", false),
            ("::/0", "10.0.0.0/8", false), // families never mix outside the embedded /96s
            ("2606:4700::/32", "8.8.8.8/32", false),
            // Review r2 R2-NG-5: as written, too.
            ("64:ff9b::/64", "64:ff9b::808:800/120", true),
            ("64:ff9b::808:800/120", "64:ff9b::/64", true),
            ("64:ff9b::/64", "8.8.8.0/24", false),
        ] {
            assert_eq!(pfx(a).overlaps(&pfx(b)), overlap, "{a} {b}");
        }
        assert_eq!(
            pfx("::ffff:10.0.0.0/104").canonical_prefix(),
            pfx("10.0.0.0/8")
        );
        assert_eq!(
            pfx("2001:db8::1/32").canonical_prefix(),
            pfx("2001:db8::/32")
        );
    }

    fn prefix_strategy() -> impl Strategy<Value = Prefix> {
        prop_oneof![
            (v4_strategy(), 0u8..=32).prop_map(|(a, l)| Prefix::new(IpAddr::V4(a), l)),
            (v6_strategy(), 0u8..=128).prop_map(|(a, l)| Prefix::new(IpAddr::V6(a), l)),
            // Long prefixes, where the interesting boundaries are.
            (v6_strategy(), 90u8..=128).prop_map(|(a, l)| Prefix::new(IpAddr::V6(a), l)),
            (v4_strategy(), 4u8..=32).prop_map(|(a, l)| Prefix::new(IpAddr::V4(a), l)),
        ]
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: 5_000, ..ProptestConfig::default() })]

        /// A prefix judged entirely global holds no non-global address (sampled: its ends and
        /// random addresses inside it); one judged not entirely global is either a non-global
        /// address's prefix or has a non-global address inside, found by descending to it.
        #[test]
        fn prefix_is_global_agrees_with_is_global(p in prefix_strategy(), r in any::<u128>(), s in any::<u128>()) {
            let inside = |x: u128| match p.addr {
                IpAddr::V4(a) => {
                    let host = if p.len == 32 { 0 } else { (x as u32) & (u32::MAX >> p.len) };
                    IpAddr::V4(Ipv4Addr::from(u32::from(a) | host))
                }
                IpAddr::V6(a) => {
                    let host = if p.len == 128 { 0 } else { x & (u128::MAX >> p.len) };
                    IpAddr::V6(Ipv6Addr::from(u128::from(a) | host))
                }
            };
            if prefix_is_global(p) {
                for x in [0, u128::MAX, r, s] {
                    prop_assert!(is_global(inside(x)), "{} judged global, {} inside is not", p, inside(x));
                }
            } else {
                // Some non-global address exists: descend into a non-global half until a host route.
                let mut q = p;
                let width = if q.addr.is_ipv4() { 32 } else { 128 };
                while q.len < width {
                    let lower = Prefix::new(q.addr, q.len + 1);
                    let upper = Prefix::new(
                        match q.addr {
                            IpAddr::V4(a) => IpAddr::V4(Ipv4Addr::from(u32::from(a) | (1u32 << (31 - u32::from(q.len))))),
                            IpAddr::V6(a) => IpAddr::V6(Ipv6Addr::from(u128::from(a) | (1u128 << (127 - u32::from(q.len))))),
                        },
                        q.len + 1,
                    );
                    q = if !prefix_is_global(lower) { lower } else { upper };
                }
                prop_assert!(!is_global(q.addr), "{} judged not global, but descended to global {}", p, q.addr);
            }
        }
    }

    #[test]
    fn canonical_ip_reads_every_embedded_form() {
        assert_eq!(canonical_ip(ip("64:ff9b::a00:1")), ip("10.0.0.1"));
        assert_eq!(canonical_ip(ip("::ffff:0:a00:1")), ip("10.0.0.1"));
        assert_eq!(canonical_ip(ip("::ffff:10.0.0.1")), ip("10.0.0.1"));
        assert_eq!(canonical_ip(ip("::a00:1")), ip("10.0.0.1"));
        assert_eq!(canonical_ip(ip("::1")), ip("::1"));
        assert_eq!(canonical_ip(ip("::")), ip("::"));
        assert_eq!(canonical_ip(ip("2001:db8::1")), ip("2001:db8::1"));
    }
}
