//! The broker's in-app network floor (plan §14.2) and log redaction (§11.4). Pure functions: the
//! broker's HTTP client asks [`EgressPolicy::admit`] for every address it is about to connect to.
//!
//! INTERFACE CONTRACT (fixed for milestone 2; the bodies are implemented on max/witness-broker-rpc).
//!
//! # The global-address predicate ([`is_global`])
//!
//! Allow-only-globally-routable, strictly stronger than `zkminer-chain`'s `ip_is_blocked` (every
//! address that blocklist refuses, this refuses; a test ports the blocklist verbatim as an oracle):
//!
//! - **IPv4:** everything except the ranges in `V4_NOT_GLOBAL` (this network, RFC 1918, CGNAT,
//!   loopback, link-local and metadata, `192.0.0/24`, the three TEST-NETs, the 6to4 relay anycast,
//!   benchmarking, multicast, `240/4` with the broadcast address, and Azure's `168.63.129.16`). All of
//!   `192.0.0.0/24` is refused, including the two /32s IANA marks globally reachable (`192.0.0.9` PCP
//!   anycast, `192.0.0.10` TURN anycast): no RPC endpoint or artifact host lives there, and the
//!   blocklist refuses them.
//! - **IPv6:** only `2000::/3` is global unicast (every RIR allocation is inside it), so everything
//!   else (`::/128`, `::1`, `100::/64`, `5f00::/16`, `fc00::/7` with `fd00:ec2::254`, `fe80::/10`,
//!   `fec0::/10`, `ff00::/8`, and all of `64:ff9b::/32` except the well-known NAT64 /96) is refused,
//!   after these forms are judged by the IPv4 address they embed: IPv4-mapped `::ffff:a.b.c.d`,
//!   IPv4-compatible `::a.b.c.d` (not `::` or `::1`), SIIT `::ffff:0:a.b.c.d`, and NAT64
//!   `64:ff9b::a.b.c.d`. Inside `2000::/3`, refused: `2001:db8::/32`, `3fff::/20` (documentation),
//!   `2002::/16` (6to4) and Teredo `2001::/32` **outright, whatever they embed** (both deprecated relay
//!   prefixes; the blocklist refuses them outright, so judging the embedded IPv4 would be weaker), the
//!   local-use NAT64 `64:ff9b:1::/48` likewise (it is outside `2000::/3`), and `2001::/23` except
//!   IANA's globally reachable assignments in it: `2001:1::1`, `2001:1::2`, `2001:1::3` (PCP, TURN and
//!   DNS-SD SRP anycast), `2001:3::/32` (AMT), `2001:4:112::/48` (AS112-v6) and `2001:30::/28` (DRIP
//!   DETs). ORCHIDv2 `2001:20::/28`, globally reachable per IANA, stays refused: its identifiers are
//!   not routable locators, and the blocklist refuses it.
//!
//! # Redaction ([`redact_urls`])
//!
//! Text is split into tokens at whitespace and quotes (`"`, `'`, `` ` ``). In each token, replaced
//! by `<url>` from where it starts to the end of the token:
//!
//! 1. `scheme://…`: the scheme is the run of `[A-Za-z0-9+.-]` before `://` (empty is allowed);
//! 2. bare endpoints, starting at the token's start or after `=`, `(`, `[`, `,`, `;` or `@`:
//!    `user[:pass]@host…` (which also catches e-mail addresses); `host[:port]/path` or
//!    `host[:port]?a=b` where host is a dotted DNS name with an alphabetic TLD, an IPv4 literal,
//!    `localhost` or a bracketed IPv6 literal; and `ipv4:port`, `localhost:port`, `[ipv6]:port`. Not
//!    caught, on purpose: `name.tld:port` without a path (`lib.rs:42` would be a false positive), a
//!    bare IPv4 or IPv6 address, and `a.b.c.d/nn` (a CIDR);
//! 3. any token with a query (`?` or `&`) carrying a credential-like parameter (`key=`, `apikey=`,
//!    `api_key=`, `api-key=`, `token=`, `access_token=`, `auth=`, `secret=`, `password=`, `pass=`,
//!    `sig=`, `signature=`, case-insensitive): the whole token.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// What an endpoint is for. Role entries are admitted only for their own role, in a set that
/// connections derived from requester data never match.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Role {
    EvmRpc,
    Artifact,
    BlobMirror,
    ArtifactMirror,
}

/// An IPv4 or IPv6 prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Prefix {
    pub addr: IpAddr,
    pub len: u8,
}

impl Prefix {
    /// Whether `ip` falls in the prefix. Host bits of `addr` are ignored; a `len` beyond the family's
    /// width is clamped to it (a host route). IPv4-mapped IPv6 is the IPv4 address it maps, on both
    /// sides: `::ffff:10.0.0.5` is in `10.0.0.0/8`, and `::ffff:10.0.0.0/104` is `10.0.0.0/8`.
    /// Families never match each other otherwise.
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.canonical(), ip.to_canonical()) {
            ((IpAddr::V4(net), len), IpAddr::V4(a)) => {
                let m = mask32(len);
                u32::from(net) & m == u32::from(a) & m
            }
            ((IpAddr::V6(net), len), IpAddr::V6(a)) => {
                let m = mask128(len);
                u128::from(net) & m == u128::from(a) & m
            }
            _ => false,
        }
    }

    /// The prefix with an IPv4-mapped IPv6 network (len ≥ 96) turned into its IPv4 prefix, and `len`
    /// clamped to the family's width.
    fn canonical(&self) -> (IpAddr, u8) {
        match self.addr {
            IpAddr::V4(v4) => (IpAddr::V4(v4), self.len.min(32)),
            IpAddr::V6(v6) => {
                let len = self.len.min(128);
                match v6.to_ipv4_mapped() {
                    Some(v4) if len >= 96 => (IpAddr::V4(v4), len - 96),
                    _ => (IpAddr::V6(v6), len),
                }
            }
        }
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

/// One admitted operator endpoint: a role, an alias, the prefixes its connected address must fall in,
/// and its port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleEntry {
    pub role: Role,
    pub alias: String,
    pub prefixes: Vec<Prefix>,
    pub port: u16,
}

/// IPv4 ranges that are not globally routable (or that the blocklist refuses), as (network, length).
const V4_NOT_GLOBAL: &[([u8; 4], u8)] = &[
    ([0, 0, 0, 0], 8),        // "this network" (incl. 0.0.0.0)
    ([10, 0, 0, 0], 8),       // RFC 1918
    ([100, 64, 0, 0], 10),    // shared address space (CGNAT)
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
];

/// Inside `2000::/3`: ranges refused outright, as (network, length).
const V6_NOT_GLOBAL: &[(u128, u8)] = &[
    (0x2001_0db8 << 96, 32), // documentation
    (0x2002 << 112, 16),     // 6to4, whatever it embeds
    (0x3fff << 112, 20),     // documentation (RFC 9637)
    (0x2001_0000 << 96, 23), // IETF protocol assignments (incl. Teredo), less the exceptions
];

/// IANA's globally reachable assignments inside `2001::/23` that are admitted (not ORCHIDv2).
const V6_IANA_GLOBAL_EXCEPTIONS: &[(u128, u8)] = &[
    ((0x2001_0001 << 96) | 1, 128), // PCP anycast
    ((0x2001_0001 << 96) | 2, 128), // TURN anycast
    ((0x2001_0001 << 96) | 3, 128), // DNS-SD SRP anycast
    (0x2001_0003 << 96, 32),        // AMT
    (0x2001_0004_0112 << 80, 48),   // AS112-v6
    (0x2001_0030 << 96, 28),        // DRIP DETs
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

/// The IPv4 address an IPv6 address embeds, for the forms that are judged by it: mapped, compatible
/// (not `::`/`::1`), SIIT and the well-known NAT64 /96. 6to4 and Teredo are refused outright instead.
fn judged_embedded_v4(a: Ipv6Addr) -> Option<Ipv4Addr> {
    let x = u128::from(a);
    let low = Ipv4Addr::from(x as u32);
    let hi96 = x >> 32;
    match hi96 {
        0xffff => Some(low),                          // ::ffff:a.b.c.d mapped
        0 if x > 1 => Some(low),                      // ::a.b.c.d compatible
        0xffff_0000 => Some(low),                     // ::ffff:0:a.b.c.d SIIT
        0x0064_ff9b_0000_0000_0000_0000 => Some(low), // 64:ff9b::a.b.c.d NAT64
        _ => None,
    }
}

fn v6_is_global(a: Ipv6Addr) -> bool {
    if let Some(v4) = judged_embedded_v4(a) {
        return v4_is_global(v4);
    }
    let x = u128::from(a);
    if !in6(x, 0x2000 << 112, 3) {
        return false;
    }
    if V6_IANA_GLOBAL_EXCEPTIONS
        .iter()
        .any(|&(net, len)| in6(x, net, len))
    {
        return true;
    }
    !V6_NOT_GLOBAL.iter().any(|&(net, len)| in6(x, net, len))
}

/// Allow-only-globally-routable (`is_global` semantics, plus every embedded-IPv4 form judged by its
/// IPv4 address, and the blocklist of `zkminer-chain`'s `ip_is_blocked`). See the module doc for the
/// exact ranges and choices.
pub fn is_global(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4_is_global(v4),
        IpAddr::V6(v6) => v6_is_global(v6),
    }
}

/// The decision for one connection attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admit {
    /// Admitted by its role entry.
    Role,
    /// Admitted as a global address that is not denied (Phase 2 requester URLs only).
    Global,
    Denied(DenyReason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenyReason {
    NotGlobal,
    DenyCidr,
    ConnectedPrefix,
    NoRoleEntry,
    WrongPort,
}

/// The only port a requester-derived connection may use.
pub const REQUESTER_PORT: u16 = 443;

/// The policy: role entries, operator deny CIDRs (the host's and fleet's public and NAT addresses),
/// and the connected prefixes of every interface (refreshed by the caller on change).
#[derive(Debug, Clone, Default)]
pub struct EgressPolicy {
    pub roles: Vec<RoleEntry>,
    pub deny: Vec<Prefix>,
    pub connected: Vec<Prefix>,
}

impl EgressPolicy {
    /// For an operator endpoint (`alias` of `role`): admitted only if `addr` matches that entry's
    /// prefixes and port. For requester-derived connections (`role == None`, Phase 2): admitted only
    /// if global, port 443, and not in `deny` or `connected`.
    ///
    /// A role entry admits its own role and alias only, private addresses included (operators run
    /// local nodes), and is not subject to `deny` or `connected`. When no entry of that role and alias
    /// has a prefix containing the address the answer is `NoRoleEntry`; when one does but on another
    /// port, `WrongPort`. Requester-derived checks run in the order global, deny, connected, port.
    pub fn admit(&self, role: Option<(Role, &str)>, addr: SocketAddr) -> Admit {
        let ip = addr.ip().to_canonical();
        match role {
            Some((role, alias)) => {
                let mut wrong_port = false;
                for e in self
                    .roles
                    .iter()
                    .filter(|e| e.role == role && e.alias == alias)
                {
                    if e.prefixes.iter().any(|p| p.contains(ip)) {
                        if e.port == addr.port() {
                            return Admit::Role;
                        }
                        wrong_port = true;
                    }
                }
                Admit::Denied(if wrong_port {
                    DenyReason::WrongPort
                } else {
                    DenyReason::NoRoleEntry
                })
            }
            None => {
                if !is_global(ip) {
                    Admit::Denied(DenyReason::NotGlobal)
                } else if self.deny.iter().any(|p| p.contains(ip)) {
                    Admit::Denied(DenyReason::DenyCidr)
                } else if self.connected.iter().any(|p| p.contains(ip)) {
                    Admit::Denied(DenyReason::ConnectedPrefix)
                } else if addr.port() != REQUESTER_PORT {
                    Admit::Denied(DenyReason::WrongPort)
                } else {
                    Admit::Global
                }
            }
        }
    }
}

/// The connected prefixes of every interface (getifaddrs): each address with its netmask as a
/// network prefix (a missing netmask is a host route; a non-contiguous one counts its leading ones,
/// which only widens it), plus the peer address of a point-to-point link as a host route. Sorted and
/// deduplicated.
pub fn connected_prefixes() -> io::Result<Vec<Prefix>> {
    struct List(*mut libc::ifaddrs);
    impl Drop for List {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: the pointer came from a successful getifaddrs and is freed exactly once.
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
    let mut out = Vec::new();
    let mut cur = list.0;
    while !cur.is_null() {
        // SAFETY: `cur` is a non-null node of the list getifaddrs returned, alive until `list` drops.
        let ifa = unsafe { &*cur };
        cur = ifa.ifa_next;
        // SAFETY: the sockaddr pointers of a live ifaddrs node are null or valid for their family.
        let Some(addr) = (unsafe { sockaddr_ip(ifa.ifa_addr) }) else {
            continue;
        };
        let width = if addr.is_ipv4() { 32 } else { 128 };
        // SAFETY: as above; the netmask is read in the address's family.
        let len = match unsafe { sockaddr_mask(ifa.ifa_netmask, addr.is_ipv4()) } {
            Some(len) => len,
            None => width,
        };
        out.push(network(addr, len));
        if ifa.ifa_flags & (libc::IFF_POINTOPOINT as libc::c_uint) != 0 {
            // SAFETY: on a point-to-point interface the union holds the destination address.
            if let Some(peer) = unsafe { sockaddr_ip(peer_ptr(ifa)) } {
                let w = if peer.is_ipv4() { 32 } else { 128 };
                out.push(Prefix { addr: peer, len: w });
            }
        }
    }
    out.sort_by_key(|p| (p.addr, p.len));
    out.dedup();
    Ok(out)
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn peer_ptr(ifa: &libc::ifaddrs) -> *const libc::sockaddr {
    ifa.ifa_ifu
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn peer_ptr(ifa: &libc::ifaddrs) -> *const libc::sockaddr {
    ifa.ifa_dstaddr
}

fn network(addr: IpAddr, len: u8) -> Prefix {
    let addr = match addr {
        IpAddr::V4(a) => IpAddr::V4(Ipv4Addr::from(u32::from(a) & mask32(len))),
        IpAddr::V6(a) => IpAddr::V6(Ipv6Addr::from(u128::from(a) & mask128(len))),
    };
    Prefix { addr, len }
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

/// The prefix length of a netmask, read in the address's family (some systems leave the netmask's own
/// `sa_family` zero).
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

/// Replaces every URL (scheme://…) in `s` with `<url>`; endpoints are logged by alias only. Also bare
/// endpoints and credential-bearing queries: see the module doc for exactly what is caught.
pub fn redact_urls(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while !rest.is_empty() {
        let tok_end = rest.find(is_token_break).unwrap_or(rest.len());
        let (tok, tail) = rest.split_at(tok_end);
        match redact_start(tok) {
            Some(start) => {
                out.push_str(&tok[..start]);
                out.push_str("<url>");
            }
            None => out.push_str(tok),
        }
        // Copy the run of break characters as is.
        let brk_end = tail
            .find(|c: char| !is_token_break(c))
            .unwrap_or(tail.len());
        out.push_str(&tail[..brk_end]);
        rest = &tail[brk_end..];
    }
    out
}

fn is_token_break(c: char) -> bool {
    c.is_whitespace() || matches!(c, '"' | '\'' | '`')
}

/// Where in `tok` a URL-like part starts (it runs to the token's end), if anywhere.
fn redact_start(tok: &str) -> Option<usize> {
    let b = tok.as_bytes();
    // 1. scheme://
    if let Some(sep) = tok.find("://") {
        let mut start = sep;
        while start > 0 && is_scheme_byte(b[start - 1]) {
            start -= 1;
        }
        return Some(start);
    }
    // 3. a credential-bearing query anywhere in the token: all of it.
    if has_secret_query(tok) {
        return Some(0);
    }
    // 2. bare endpoints, at the start or after a separator.
    let starts = std::iter::once(0).chain(
        b.iter()
            .enumerate()
            .filter(|&(_, &c)| matches!(c, b'=' | b'(' | b'[' | b',' | b';' | b'@'))
            .map(|(i, &c)| if c == b'[' { i } else { i + 1 }),
    );
    for start in starts {
        if start < b.len() && is_bare_endpoint(&tok[start..]) {
            return Some(start);
        }
    }
    None
}

fn is_scheme_byte(c: u8) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, b'+' | b'.' | b'-')
}

const SECRET_PARAMS: &[&str] = &[
    "key",
    "apikey",
    "api_key",
    "api-key",
    "token",
    "access_token",
    "auth",
    "secret",
    "password",
    "pass",
    "sig",
    "signature",
];

fn has_secret_query(tok: &str) -> bool {
    let lower = tok.to_ascii_lowercase();
    let b = lower.as_bytes();
    b.iter().enumerate().any(|(i, &c)| {
        (c == b'?' || c == b'&')
            && SECRET_PARAMS.iter().any(|p| {
                let rest = &b[i + 1..];
                rest.len() > p.len() && rest.starts_with(p.as_bytes()) && rest[p.len()] == b'='
            })
    })
}

/// `user[:pass]@host…`, `host[:port]/…`, `host[:port]?…`, `ipv4:port`, `localhost:port`,
/// `[ipv6]:port`.
fn is_bare_endpoint(c: &str) -> bool {
    // Userinfo: something@host, where the part before @ has no '/' and the host is a real host.
    if let Some(at) = c.find('@') {
        let (user, host) = (&c[..at], &c[at + 1..]);
        if !user.is_empty() && !user.contains('/') && host_end(host).is_some() {
            return true;
        }
    }
    let Some((kind, end)) = host_end(c) else {
        return false;
    };
    let rest = &c[end..];
    let (has_port, after) = match rest.strip_prefix(':') {
        Some(p) => {
            let digits = p.bytes().take_while(u8::is_ascii_digit).count();
            if digits == 0 {
                return false;
            }
            (true, &p[digits..])
        }
        None => (false, rest),
    };
    if let Some(path) = after.strip_prefix('/') {
        // `a.b.c.d/nn` with nothing else is a CIDR, not a URL.
        let cidr = kind == HostKind::V4
            && !has_port
            && !path.is_empty()
            && path.len() <= 3
            && path.bytes().all(|c| c.is_ascii_digit());
        return !cidr;
    }
    if after.starts_with('?') && after.contains('=') {
        return true;
    }
    has_port && after.is_empty() && kind != HostKind::Dns
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HostKind {
    Dns,
    V4,
    Local,
    V6,
}

/// If `c` starts with a host, its kind and the byte offset just past it.
fn host_end(c: &str) -> Option<(HostKind, usize)> {
    let b = c.as_bytes();
    if b.first() == Some(&b'[') {
        let close = c.find(']')?;
        let inner = &c[1..close];
        return inner
            .parse::<Ipv6Addr>()
            .ok()
            .map(|_| (HostKind::V6, close + 1));
    }
    let end = b
        .iter()
        .position(|&x| !(x.is_ascii_alphanumeric() || x == b'.' || x == b'-'))
        .unwrap_or(b.len());
    let host = &c[..end];
    if host.eq_ignore_ascii_case("localhost") {
        return Some((HostKind::Local, end));
    }
    if host.parse::<Ipv4Addr>().is_ok() {
        return Some((HostKind::V4, end));
    }
    let labels: Vec<&str> = host.split('.').collect();
    let tld = labels.last()?;
    let ok = labels.len() >= 2
        && labels
            .iter()
            .all(|l| !l.is_empty() && !l.starts_with('-') && !l.ends_with('-'))
        && tld.len() >= 2
        && tld.bytes().all(|x| x.is_ascii_alphabetic());
    ok.then_some((HostKind::Dns, end))
}

/// Turns untrusted bytes into a printable, bounded string: control characters and non-ASCII escaped,
/// at most `max` output bytes.
///
/// Printable ASCII passes through, `\` becomes `\\`, TAB/LF/CR become `\t`/`\n`/`\r`, and every other
/// byte (controls, DEL, each byte of non-ASCII or invalid UTF-8) becomes `\xNN`. The output is
/// printable ASCII only. When it would exceed `max`, it is cut at an escape boundary and ends with
/// `...` (if `max` ≥ 3), never longer than `max` bytes.
pub fn sanitize_log(bytes: &[u8], max: usize) -> String {
    const MARK: &str = "...";
    let mut out = String::with_capacity(max.min(bytes.len().saturating_mul(4)));
    // The longest prefix (at an escape boundary) that leaves room for the marker.
    let mut cut = 0usize;
    let room = max.saturating_sub(MARK.len());
    let mut esc = [0u8; 4];
    for &b in bytes {
        let e: &[u8] = match b {
            b'\\' => b"\\\\",
            b'\t' => b"\\t",
            b'\n' => b"\\n",
            b'\r' => b"\\r",
            0x20..=0x7e => {
                esc[0] = b;
                &esc[..1]
            }
            _ => {
                const HEX: &[u8; 16] = b"0123456789abcdef";
                esc = [
                    b'\\',
                    b'x',
                    HEX[usize::from(b >> 4)],
                    HEX[usize::from(b & 15)],
                ];
                &esc[..]
            }
        };
        if out.len() + e.len() > max {
            if max >= MARK.len() {
                out.truncate(cut);
                out.push_str(MARK);
            }
            return out;
        }
        // Every escape is printable ASCII, so this is valid UTF-8.
        out.extend(e.iter().map(|&x| x as char));
        if out.len() <= room {
            cut = out.len();
        }
    }
    out
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

    /// `zkminer-chain`'s `embedded_ipv4` and `ip_is_blocked`, verbatim (crates/zkminer-chain/src/
    /// programs.rs), as the oracle the new predicate must be strictly stronger than.
    mod legacy {
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

    /// Every case §14.1 names (what the blocklist covers, and the gaps it misses), plus the rest of
    /// the not-global set.
    const REFUSED: &[&str] = &[
        // §14.1: what ip_is_blocked already refuses.
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
        // §14.1 gaps: what the blocklist misses.
        "100::1", // discard-only
        "100::ffff:ffff:ffff:ffff",
        "2001:2::1", // benchmarking
        "2001:2:0:ffff::1",
        "3fff::1", // documentation (RFC 9637)
        "3fff:fff:ffff::1",
        "5f00::1", // SRv6 SIDs
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
        "2001:1::",   // in 2001:1::/48 but not one of the three anycast /128s
        "2001:1::4",
        "2001:4:113::1", // next to AS112-v6
        "2001:40::1",    // unassigned in 2001::/23
        "2001:1ff::1",   // the top of 2001::/23
        "4000::1",       // outside 2000::/3
        "1fff::1",
        "::ffff:0.0.0.0",
        "::2", // compatible 0.0.0.2 (0/8)
    ];

    const ADMITTED: &[&str] = &[
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
        "192.31.196.1", // AS112-v4 (IANA global)
        "192.52.193.1", // AMT (IANA global)
        "192.175.48.1", // AS112 direct delegation (IANA global)
        "2606:4700:4700::1111",
        "2a00:1450:4001::1",
        "2001:200::1", // just above 2001::/23
        "2001:db7:ffff::1",
        "2001:db9::1",
        "2003::1",
        "3ffe::1",
        "3fff:1000::1", // just above 3fff::/20
        "2001:1::1",    // IANA exceptions in 2001::/23
        "2001:1::2",
        "2001:1::3",
        "2001:3::1",
        "2001:3:ffff::1",
        "2001:4:112::1",
        "2001:4:112:ffff::1",
        "2001:30::1",
        "2001:3f:ffff::1",
        "::ffff:8.8.8.8", // embedded forms of a public address
        "::ffff:0:808:808",
        "64:ff9b::808:808",
        "::808:808",
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
        for s in ["100::1", "2001:2::1", "3fff::1", "5f00::1", "4000::1"] {
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
        }

        #[test]
        fn sanitize_log_is_bounded_and_printable(bytes in prop::collection::vec(any::<u8>(), 0..300), max in 0usize..400) {
            let s = sanitize_log(&bytes, max);
            prop_assert!(s.len() <= max);
            prop_assert!(s.bytes().all(|c| (0x20..0x7f).contains(&c)));
        }

        #[test]
        fn redact_urls_never_panics_and_hides_scheme_urls(pre in "[ -~]{0,20}", host in "[a-z]{1,10}\\.[a-z]{2,5}", path in "[!-~&&[^\"'`]]{0,30}", post in "[ -~]{0,20}") {
            let secret = format!("https://{host}/{path}");
            let s = format!("{pre} {secret} {post}");
            let r = redact_urls(&s);
            prop_assert!(!r.contains(&secret), "{} -> {}", s, r);
            let _ = redact_urls(&pre);
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
        assert!(!p.contains(ip("::a01:203")), "compatible is not mapped");
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
    }

    fn policy() -> EgressPolicy {
        EgressPolicy {
            roles: vec![
                RoleEntry {
                    role: Role::EvmRpc,
                    alias: "base-archive".into(),
                    prefixes: vec![pfx("10.1.0.0/16"), pfx("fd00::/64")],
                    port: 8545,
                },
                RoleEntry {
                    role: Role::Artifact,
                    alias: "hemi".into(),
                    prefixes: vec![pfx("203.0.113.7/32")],
                    port: 443,
                },
                RoleEntry {
                    role: Role::BlobMirror,
                    alias: "m1".into(),
                    prefixes: vec![pfx("8.8.4.0/24")],
                    port: 443,
                },
            ],
            deny: vec![pfx("8.8.4.4/32"), pfx("2a01:4f8::/32")],
            connected: vec![pfx("9.9.9.0/24"), pfx("2606:4700:aaaa::/48")],
        }
    }

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn admit_role_entries() {
        let p = policy();
        let rpc = Some((Role::EvmRpc, "base-archive"));
        // Private addresses are fine for a role entry.
        assert_eq!(p.admit(rpc, sa("10.1.2.3:8545")), Admit::Role);
        assert_eq!(p.admit(rpc, sa("[fd00::5]:8545")), Admit::Role);
        assert_eq!(p.admit(rpc, sa("[::ffff:10.1.2.3]:8545")), Admit::Role);
        assert_eq!(
            p.admit(rpc, sa("10.1.2.3:8546")),
            Admit::Denied(DenyReason::WrongPort)
        );
        assert_eq!(
            p.admit(rpc, sa("10.2.0.1:8545")),
            Admit::Denied(DenyReason::NoRoleEntry)
        );
        // Only its own role and alias.
        assert_eq!(
            p.admit(Some((Role::EvmRpc, "other")), sa("10.1.2.3:8545")),
            Admit::Denied(DenyReason::NoRoleEntry)
        );
        assert_eq!(
            p.admit(Some((Role::Artifact, "base-archive")), sa("10.1.2.3:8545")),
            Admit::Denied(DenyReason::NoRoleEntry)
        );
        assert_eq!(
            p.admit(Some((Role::ArtifactMirror, "hemi")), sa("203.0.113.7:443")),
            Admit::Denied(DenyReason::NoRoleEntry)
        );
        // A documentation address, but the operator configured it: admitted for its role.
        assert_eq!(
            p.admit(Some((Role::Artifact, "hemi")), sa("203.0.113.7:443")),
            Admit::Role
        );
        // A role entry is not subject to the deny list (the operator named it explicitly).
        assert_eq!(
            p.admit(Some((Role::BlobMirror, "m1")), sa("8.8.4.4:443")),
            Admit::Role
        );
    }

    #[test]
    fn admit_requester_derived() {
        let p = policy();
        assert_eq!(p.admit(None, sa("1.1.1.1:443")), Admit::Global);
        assert_eq!(
            p.admit(None, sa("[2606:4700:4700::1111]:443")),
            Admit::Global
        );
        assert_eq!(
            p.admit(None, sa("1.1.1.1:80")),
            Admit::Denied(DenyReason::WrongPort)
        );
        assert_eq!(
            p.admit(None, sa("10.1.2.3:443")),
            Admit::Denied(DenyReason::NotGlobal)
        );
        assert_eq!(
            p.admit(None, sa("[::ffff:10.1.2.3]:443")),
            Admit::Denied(DenyReason::NotGlobal)
        );
        assert_eq!(
            p.admit(None, sa("169.254.169.254:443")),
            Admit::Denied(DenyReason::NotGlobal)
        );
        assert_eq!(
            p.admit(None, sa("[fd00:ec2::254]:443")),
            Admit::Denied(DenyReason::NotGlobal)
        );
        assert_eq!(
            p.admit(None, sa("8.8.4.4:443")),
            Admit::Denied(DenyReason::DenyCidr)
        );
        assert_eq!(
            p.admit(None, sa("[::ffff:8.8.4.4]:443")),
            Admit::Denied(DenyReason::DenyCidr)
        );
        assert_eq!(
            p.admit(None, sa("[2a01:4f8::1]:443")),
            Admit::Denied(DenyReason::DenyCidr)
        );
        assert_eq!(
            p.admit(None, sa("9.9.9.9:443")),
            Admit::Denied(DenyReason::ConnectedPrefix)
        );
        assert_eq!(
            p.admit(None, sa("[2606:4700:aaaa::1]:443")),
            Admit::Denied(DenyReason::ConnectedPrefix)
        );
        // Requester-derived connections never come back as `Role`, even at a role entry's address.
        assert_eq!(p.admit(None, sa("8.8.4.8:443")), Admit::Global);
        assert_eq!(
            p.admit(None, sa("203.0.113.7:443")),
            Admit::Denied(DenyReason::NotGlobal)
        );
    }

    #[test]
    fn connected_prefixes_are_well_formed() {
        let ps = connected_prefixes().expect("getifaddrs");
        for p in &ps {
            let w = if p.addr.is_ipv4() { 32 } else { 128 };
            assert!(p.len <= w, "{p:?}");
            assert_eq!(network(p.addr, p.len), *p, "{p:?} is a network address");
        }
        // Loopback, where the namespace has it up, is a connected prefix.
        if ps.iter().any(|p| p.addr == ip("127.0.0.0")) {
            assert!(ps.iter().any(|p| p.contains(ip("127.0.0.1"))));
        }
        let mut sorted = ps.clone();
        sorted.sort_by_key(|p| (p.addr, p.len));
        sorted.dedup();
        assert_eq!(sorted, ps);
    }

    #[test]
    fn redact_urls_table() {
        for (input, want) in [
            (
                "GET https://mainnet.infura.io/v3/abcdef failed",
                "GET <url> failed",
            ),
            (
                "url=\"wss://x.example/ws?key=1\" next",
                "url=\"<url>\" next",
            ),
            ("endpoint=http://10.0.0.1:8545/ done", "endpoint=<url> done"),
            ("(https://a.b/c), more", "(<url> more"),
            ("://weird/abc", "<url>"),
            ("ipfs://bafy/x and git+ssh://h/r", "<url> and <url>"),
            ("'ftp://u:p@h/x'", "'<url>'"),
            ("eth-mainnet.g.alchemy.com/v2/KEY", "<url>"),
            ("rpc=eth-mainnet.g.alchemy.com/v2/KEY,", "rpc=<url>"),
            ("connect 10.0.0.1:8545 refused", "connect <url> refused"),
            ("connect localhost:8545 refused", "connect <url> refused"),
            ("connect [::1]:8545 refused", "connect <url> refused"),
            ("host=[fd00::1]:8545", "host=<url>"),
            ("user:pw@db.internal.example", "<url>"),
            ("node.example.org?apikey=xyz", "<url>"),
            ("/v1/rpc?token=abc", "<url>"),
            ("path?a=1&secret=2", "<url>"),
            ("Q?API_KEY=1", "<url>"),
            ("example.com/path", "<url>"),
            // Not URLs.
            ("crates/foo/src/lib.rs:42:5", "crates/foo/src/lib.rs:42:5"),
            ("at lib.rs:42", "at lib.rs:42"),
            (
                "denied 10.0.0.0/8 and 10.0.0.1",
                "denied 10.0.0.0/8 and 10.0.0.1",
            ),
            ("version v1.2.3/linux", "version v1.2.3/linux"),
            ("std::io::Error: oops", "std::io::Error: oops"),
            ("what is foo.rs?", "what is foo.rs?"),
            ("a?b", "a?b"),
            ("plain text, nothing here", "plain text, nothing here"),
            ("", ""),
            ("  leading\tand\ntrailing  ", "  leading\tand\ntrailing  "),
            ("ünïcode https://ü.example/é ok", "ünïcode <url> ok"),
        ] {
            assert_eq!(redact_urls(input), want, "{input:?}");
        }
    }

    #[test]
    fn sanitize_then_redact_hides_a_url_with_escaped_bytes() {
        let raw = b"error from https://key\x1b[0m.example/v3/SECRET\r\nforged line";
        let s = redact_urls(&sanitize_log(raw, 512));
        assert!(
            !s.contains("SECRET") && !s.contains('\n') && !s.contains('\x1b'),
            "{s}"
        );
        assert_eq!(s, "error from <url> line");
    }

    #[test]
    fn sanitize_log_table() {
        assert_eq!(sanitize_log(b"plain", 100), "plain");
        assert_eq!(
            sanitize_log(b"a\r\nb\x1b[31mc\td", 100),
            "a\\r\\nb\\x1b[31mc\\td"
        );
        assert_eq!(sanitize_log(b"back\\slash", 100), "back\\\\slash");
        assert_eq!(sanitize_log("café".as_bytes(), 100), "caf\\xc3\\xa9");
        assert_eq!(
            sanitize_log("\u{202e}".as_bytes(), 100),
            "\\xe2\\x80\\xae",
            "bidi override"
        );
        assert_eq!(
            sanitize_log(b"\xff\xfe\x00\x7f", 100),
            "\\xff\\xfe\\x00\\x7f"
        );
        // Bounds: exact fit, then one over (cut at an escape boundary, with the marker).
        assert_eq!(sanitize_log(b"abcdef", 6), "abcdef");
        assert_eq!(sanitize_log(b"abcdefg", 6), "abc...");
        assert_eq!(sanitize_log(b"ab\x01cdef", 7), "ab...");
        assert_eq!(sanitize_log(b"ab\x01", 6), "ab\\x01");
        assert_eq!(sanitize_log(b"abcdef", 2), "ab");
        assert_eq!(sanitize_log(b"\x01", 2), "");
        assert_eq!(sanitize_log(b"abcdef", 0), "");
        assert_eq!(sanitize_log(b"", 0), "");
    }
}
