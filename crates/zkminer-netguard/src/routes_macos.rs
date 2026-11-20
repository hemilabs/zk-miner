//! macOS: the routing table, per-destination route queries and the interface list, over the BSD
//! routing socket (`PF_ROUTE`) and its sysctl, unprivileged (`route -n get` and `netstat -rn` need
//! no root either). What the Linux netlink code reads, and how each maps (the evidence, commands
//! and captures: `docs/netguard-macos.md`):
//!
//! - **routes** ([`dump`]): `sysctl {CTL_NET, PF_ROUTE, 0, AF_UNSPEC, NET_RT_DUMP, 0}`, one
//!   `RTM_GET` message per route of both families. The kernel writes it under its routing lock, so
//!   the buffer is a consistent snapshot or the call fails (`ENOMEM` when the table grew between
//!   the size query and the read: read again, as Linux reads an interrupted dump again). Read as
//!   the netlink dump is: `RTF_GATEWAY` gives [`Hop::Via`] its gateway (one that is not an IP
//!   address of the route's family: [`Hop::Unknown`], refused); without it the route is on-link
//!   (its gateway is then a link-layer or interface address). `RTF_LOCAL` and `RTF_BROADCAST`
//!   routes deliver to this host ([`RouteType::Local`], [`RouteType::Broadcast`]). Routes that
//!   reach nothing (`RTF_REJECT`, `RTF_BLACKHOLE`, not `RTF_UP`) and multicast routes are not
//!   read, as Linux skips those types; nor are the kernel's clones (`RTF_WASCLONED`: ARP/NDP
//!   entries and per-destination copies of their parent route, what Linux's `RTM_F_CLONED` is),
//!   unless one delivers locally or an ICMP redirect changed it (`RTF_DYNAMIC`, `RTF_MODIFIED`).
//! - **policy rules: none; scoped routes instead.** macOS has no `ip rule`. It has
//!   interface-scoped routes (`RTF_IFSCOPE`, netstat's `I`): a scoped route is used only by a
//!   socket bound to its interface (and by the kernel's clones on the primary interface), never by
//!   an unbound connection's lookup. So each interface's scoped routes are read as a routing table
//!   of their own, [`SCOPED_TABLE`] + the interface index, which no rule sends this process's
//!   connections to, and the unscoped routes as table `main`; the rules [`dump`] returns
//!   (`lookup main` for each family) make `main` the one ordinary table. Exactly as for a Linux
//!   table only a selector reaches: a scoped default route (a system utun's or a second
//!   interface's `default … UGScI`) is no default route and its gateway no uplink, and any other
//!   scoped route that does not take the default path still refuses what it holds.
//! - **the kernel per destination** ([`query`]): an `RTM_GET` (sent as `RTM_GET_SILENT`, so the
//!   answer goes to this socket alone) for the destination on a fresh `PF_ROUTE` socket, with a
//!   sequence number drawn for it from the CSPRNG; the answer is the one datagram that is exactly
//!   an `RTM_GET` message with this process's `rtm_pid` and that `rtm_seq` (every routing socket
//!   also receives other routing messages, and writes the kernel refused, as written:
//!   [`parse_answer`]), answered with the route the kernel's lookup picks (a clone on the primary
//!   interface, the network's cloning route, or a default route). macOS's Network Extension
//!   policies (NECP: a per-app or include-all-networks VPN, a content filter) can send a socket
//!   elsewhere without any route saying so; the closest unprivileged view of them is a real socket.
//!   So for an answer the judge could admit (a route through a gateway, or a default-like route), a
//!   UDP socket is connected to the destination (no packet is sent) and the source address the
//!   kernel chose must be an address of the interface the route names; when it is not, the answer
//!   is [`KernelAnswer::Split`] (refused, as a Linux `from` rule that sends a connection somewhere
//!   its first lookup did not). `ESRCH` (no route) is [`KernelAnswer::NoRoute`].
//! - **interfaces** ([`links`]): `getifaddrs`' `AF_LINK` entries, the interface type
//!   (`sdl_type`, <net/if_types.h>) read as a Linux link kind ([`link_kind`]): Ethernet and Wi-Fi
//!   are physical (no kind), `utun` is `tun`, `ppp` is `ppp` (macOS has no `/proc/net/pppoe`, so
//!   a `ppp` uplink always needs `[egress] internal_ranges`), any type this code does not know is
//!   a kind the guard does not know to be physical.
//! - **nexthop objects:** none on macOS ([`nexthops`] is empty; every route has `nexthop` 0).
//!
//! Every message is parsed from bytes, never cast: lengths are checked before every read, a
//! message or sockaddr that does not fit is an error (the facts read fails, or the destination is
//! refused), and nothing malformed is ever read as a route.

use std::io;
use std::mem::{offset_of, size_of};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use super::{Hop, KernelAnswer, Link, Nexthop, Route, RouteType, Rule, RT_TABLE_MAIN};
use crate::ip::Prefix;

/// The routing table an interface's scoped routes (`RTF_IFSCOPE`) are read into: this plus the
/// interface index. Above every Linux table id a host uses, and never ordinary.
pub(crate) const SCOPED_TABLE: u32 = 0x8000_0000;

/// `sizeof(struct rt_msghdr)` (<net/route.h>): 92 bytes on macOS.
const HDR_LEN: usize = size_of::<libc::rt_msghdr>();
/// `RTAX_MAX` (<net/route.h>): the sockaddr slots a routing message can carry.
const RTAX_MAX: usize = libc::RTAX_MAX as usize;
/// The most a routing message can be: its header and `RTAX_MAX` sockaddrs of at most 255 bytes.
const RECV_BUF: usize = 4096;
/// A ceiling on the routes read, against a runaway dump.
const MAX_ROUTES: usize = 1 << 20;
/// Times the dump is read again when the table grew between the size query and the read.
const DUMP_ATTEMPTS: usize = 5;
/// How long the kernel may take to answer one route query.
const QUERY_TIMEOUT: Duration = Duration::from_secs(2);

// Interface types (<net/if_types.h>), which the libc crate does not define.
const IFT_OTHER: u8 = 0x1;
const IFT_ETHER: u8 = 0x6;
const IFT_PPP: u8 = 0x17;
const IFT_LOOP: u8 = 0x18;
const IFT_GIF: u8 = 0x37;
const IFT_STF: u8 = 0x39;
const IFT_IEEE80211: u8 = 0x47;
const IFT_L2VLAN: u8 = 0x87;
const IFT_IEEE8023ADLAG: u8 = 0x88;
const IFT_BRIDGE: u8 = 0xd1;

fn malformed() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "malformed routing socket message",
    )
}

/// The fields of a `struct rt_msghdr` (<net/route.h>) this code reads, at the offsets the libc
/// crate's definition has (`rtm_index` is followed by two bytes of padding).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Header {
    pub len: usize,
    pub version: u8,
    pub ty: u8,
    pub index: u16,
    pub flags: i32,
    pub addrs: i32,
    pub pid: i32,
    pub seq: i32,
    pub errno: i32,
}

fn u16_at(b: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_ne_bytes(b.get(i..i + 2)?.try_into().ok()?))
}

fn i32_at(b: &[u8], i: usize) -> Option<i32> {
    Some(i32::from_ne_bytes(b.get(i..i + 4)?.try_into().ok()?))
}

/// The header at the start of `b` (which must hold a whole header).
pub(super) fn header(b: &[u8]) -> io::Result<Header> {
    if b.len() < HDR_LEN {
        return Err(malformed());
    }
    let f = |o: usize| i32_at(b, o).ok_or_else(malformed);
    Ok(Header {
        len: usize::from(u16_at(b, offset_of!(libc::rt_msghdr, rtm_msglen)).ok_or_else(malformed)?),
        version: b[offset_of!(libc::rt_msghdr, rtm_version)],
        ty: b[offset_of!(libc::rt_msghdr, rtm_type)],
        index: u16_at(b, offset_of!(libc::rt_msghdr, rtm_index)).ok_or_else(malformed)?,
        flags: f(offset_of!(libc::rt_msghdr, rtm_flags))?,
        addrs: f(offset_of!(libc::rt_msghdr, rtm_addrs))?,
        pid: f(offset_of!(libc::rt_msghdr, rtm_pid))?,
        seq: f(offset_of!(libc::rt_msghdr, rtm_seq))?,
        errno: f(offset_of!(libc::rt_msghdr, rtm_errno))?,
    })
}

/// The sockaddrs after a message's header, by `RTAX_*` slot: one for each `RTA_*` bit set in
/// `addrs`, in bit order, each taking its `sa_len` rounded up to a multiple of 4 bytes, and 4 bytes
/// for a zero `sa_len` (`ROUNDUP32` in xnu's bsd/net/rtsock.c; what `route(8)`'s `ROUNDUP` reads).
/// A slot holds the sockaddr's `sa_len` bytes (none for a zero length: an all-zero netmask). A bit
/// beyond `RTAX_MAX`, or a sockaddr that runs past `b`, is an error.
pub(super) fn sockaddrs(mut b: &[u8], addrs: i32) -> io::Result<[Option<&[u8]>; RTAX_MAX]> {
    if (addrs as u32) >> RTAX_MAX != 0 {
        return Err(malformed());
    }
    let mut out = [None; RTAX_MAX];
    for (i, slot) in out.iter_mut().enumerate() {
        if addrs & (1 << i) == 0 {
            continue;
        }
        let len = usize::from(*b.first().ok_or_else(malformed)?);
        let step = if len == 0 { 4 } else { (len + 3) & !3 };
        if step > b.len() {
            return Err(malformed());
        }
        *slot = Some(&b[..len]);
        b = &b[step..];
    }
    Ok(out)
}

/// A KAME-style embedded scope (xnu keeps an interface-local or link-local address's interface
/// index in its second 16-bit word inside the kernel, and the routing socket shows it, as
/// `fe80:8::…` for `fe80::…%en0`): cleared, so the address reads as written.
fn clear_embedded_scope(a: &mut [u8; 16]) {
    let link_local_unicast = a[0] == 0xfe && a[1] & 0xc0 == 0x80;
    let scoped_multicast = a[0] == 0xff && matches!(a[1] & 0x0f, 0x1 | 0x2);
    if link_local_unicast || scoped_multicast {
        a[2] = 0;
        a[3] = 0;
    }
}

/// The IP address of a sockaddr slot (`sockaddr_in` / `sockaddr_in6`, <netinet/in.h>); `None` for
/// another family. An IP sockaddr too short for its address is an error.
fn sa_ip(sa: &[u8]) -> io::Result<Option<IpAddr>> {
    let Some(&family) = sa.get(1) else {
        return Ok(None);
    };
    match i32::from(family) {
        libc::AF_INET => {
            let o = offset_of!(libc::sockaddr_in, sin_addr);
            let a: [u8; 4] = sa
                .get(o..o + 4)
                .ok_or_else(malformed)?
                .try_into()
                .map_err(|_| malformed())?;
            Ok(Some(IpAddr::V4(Ipv4Addr::from(a))))
        }
        libc::AF_INET6 => {
            let o = offset_of!(libc::sockaddr_in6, sin6_addr);
            let mut a: [u8; 16] = sa
                .get(o..o + 16)
                .ok_or_else(malformed)?
                .try_into()
                .map_err(|_| malformed())?;
            clear_embedded_scope(&mut a);
            Ok(Some(IpAddr::V6(Ipv6Addr::from(a))))
        }
        _ => Ok(None),
    }
}

/// The prefix length of a netmask slot, read in the route's family. The kernel trims a mask's
/// trailing zero bytes (`sa_len` 7 for 255.255.255.0) and leaves its family byte unset, so the
/// address bytes are read at the family's offset up to `sa_len`, the rest zero. `None` for a
/// non-contiguous mask (`0.255.255.0`): no prefix length says which addresses such a route
/// holds, and counting its leading ones would read it as wider than it is (a /0, a default
/// route); the message is malformed.
fn mask_len(sa: &[u8], v4: bool) -> Option<u8> {
    let (off, width) = if v4 {
        (offset_of!(libc::sockaddr_in, sin_addr), 4)
    } else {
        (offset_of!(libc::sockaddr_in6, sin6_addr), 16)
    };
    let mut m = [0u8; 16];
    for (i, b) in m[..width].iter_mut().enumerate() {
        *b = sa.get(off + i).copied().unwrap_or(0);
    }
    let bits = u128::from_be_bytes(m);
    let len = bits.leading_ones();
    // Contiguous: nothing set after the leading ones.
    (bits.checked_shl(len).unwrap_or(0) == 0).then_some(len as u8)
}

/// One `RTM_GET` message's route (`body`: what follows its header). `None` for a route that reaches
/// nothing (not up, reject, blackhole), a multicast route, a route of another family, and (`dump`)
/// a clone that neither delivers locally nor was changed by a redirect. See the module doc.
pub(super) fn parse_route(h: &Header, body: &[u8], dump: bool) -> io::Result<Option<Route>> {
    let sas = sockaddrs(body, h.addrs)?;
    let dst = sas[libc::RTAX_DST as usize].ok_or_else(malformed)?;
    let Some(dst) = sa_ip(dst)? else {
        return Ok(None);
    };
    let gateway = match sas[libc::RTAX_GATEWAY as usize] {
        Some(g) => sa_ip(g)?,
        None => None,
    };
    let f = h.flags;
    if f & libc::RTF_UP == 0
        || f & (libc::RTF_REJECT | libc::RTF_BLACKHOLE | libc::RTF_MULTICAST) != 0
    {
        return Ok(None);
    }
    let kept_clone = libc::RTF_LOCAL | libc::RTF_BROADCAST | libc::RTF_DYNAMIC | libc::RTF_MODIFIED;
    if dump && f & libc::RTF_WASCLONED != 0 && f & kept_clone == 0 {
        return Ok(None);
    }
    let v4 = dst.is_ipv4();
    let width = if v4 { 32 } else { 128 };
    // A route without a netmask is a host route (BSD's radix tree keeps no mask for one).
    let len = match sas[libc::RTAX_NETMASK as usize] {
        Some(m) if f & libc::RTF_HOST == 0 => mask_len(m, v4).ok_or_else(malformed)?,
        _ => width,
    };
    let hop = if f & libc::RTF_GATEWAY != 0 {
        match gateway {
            Some(gw) if gw.is_ipv4() == v4 => Hop::Via(gw),
            _ => Hop::Unknown,
        }
    } else {
        Hop::OnLink
    };
    let kind = if f & libc::RTF_LOCAL != 0 {
        RouteType::Local
    } else if f & libc::RTF_BROADCAST != 0 {
        RouteType::Broadcast
    } else {
        RouteType::Unicast
    };
    let ifindex = u32::from(h.index);
    let table = if f & libc::RTF_IFSCOPE != 0 {
        SCOPED_TABLE + ifindex
    } else {
        RT_TABLE_MAIN
    };
    Ok(Some(Route {
        prefix: Prefix::new(dst, len),
        hop,
        ifindex,
        loopback: false,
        kind,
        table,
        nexthop: 0,
    }))
}

/// Every route of a `NET_RT_DUMP` buffer (see the module doc). A message that does not fit, of
/// another version or type, or with a malformed sockaddr fails the whole read.
pub(super) fn parse_dump(mut b: &[u8]) -> io::Result<Vec<Route>> {
    let mut out = Vec::new();
    while !b.is_empty() {
        let h = header(b)?;
        if i32::from(h.version) != libc::RTM_VERSION
            || i32::from(h.ty) != libc::RTM_GET
            || h.len < HDR_LEN
            || h.len > b.len()
        {
            return Err(malformed());
        }
        if let Some(r) = parse_route(&h, &b[HDR_LEN..h.len], true)? {
            out.push(r);
        }
        if out.len() > MAX_ROUTES {
            return Err(io::Error::other("the routing table dump never ended"));
        }
        b = &b[h.len..];
    }
    Ok(out)
}

/// The `NET_RT_DUMP` buffer: sized, then read, again when the table grew in between (`ENOMEM`).
fn sysctl_dump() -> io::Result<Vec<u8>> {
    let mut mib = [libc::CTL_NET, libc::PF_ROUTE, 0, 0, libc::NET_RT_DUMP, 0];
    for _ in 0..DUMP_ATTEMPTS {
        let mut need: libc::size_t = 0;
        // SAFETY: a size query: no output buffer, `need` receives the size; `mib` holds the 6
        // names given.
        let rc = unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                mib.len() as libc::c_uint,
                std::ptr::null_mut(),
                &mut need,
                std::ptr::null_mut(),
                0,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        // Room for routes added before the read.
        let cap = need + need / 4 + 4096;
        let mut buf = vec![0u8; cap];
        let mut got: libc::size_t = cap;
        // SAFETY: `buf` holds `got` writable bytes, which the kernel fills and says how many.
        let rc = unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                mib.len() as libc::c_uint,
                buf.as_mut_ptr().cast(),
                &mut got,
                std::ptr::null_mut(),
                0,
            )
        };
        if rc == 0 {
            if got > cap {
                return Err(malformed());
            }
            buf.truncate(got);
            return Ok(buf);
        }
        let e = io::Error::last_os_error();
        if e.raw_os_error() != Some(libc::ENOMEM) {
            return Err(e);
        }
    }
    Err(io::Error::other(format!(
        "the routing table grew during each of {DUMP_ATTEMPTS} reads; a partial table is not used"
    )))
}

/// Every route of both families, and the rules that make `main` (the unscoped routes) the one
/// ordinary table (see the module doc).
pub(super) fn dump() -> io::Result<(Vec<Route>, Vec<Rule>)> {
    let routes = parse_dump(&sysctl_dump()?)?;
    Ok((
        routes,
        vec![
            Rule::lookup(false, RT_TABLE_MAIN),
            Rule::lookup(true, RT_TABLE_MAIN),
        ],
    ))
}

/// A query's sequence number, drawn for it alone from the system's CSPRNG (`arc4random`), never
/// a counter: every routing socket can see other processes' routing messages, and a number that
/// follows the last one seen could be guessed (review round 2, parse-1).
fn next_seq() -> i32 {
    // SAFETY: arc4random takes no arguments and cannot fail.
    unsafe { libc::arc4random() as i32 }
}

/// `RTM_GET_SILENT` (xnu's private <net/route.h>, 0x11): an `RTM_GET` whose answer the kernel
/// sends to the asking socket alone (`sendonlytoself`), as type `RTM_GET`, instead of to every
/// routing socket, so no other process sees which destinations this process asks about, nor
/// its queries' pid and sequence numbers. Measured on macOS 27.2 (26B131):
/// `fix-r2/rtm-get-silent.log`. A kernel that does not know the type refuses the write (an
/// unknown type is `EPERM` for an unprivileged writer, as `fix-r2/forge-variants.log` shows),
/// and the query is then asked as a plain `RTM_GET` from then on.
const RTM_GET_SILENT: u8 = 0x11;

/// Set once a kernel refused `RTM_GET_SILENT`.
static SILENT_REFUSED: AtomicBool = AtomicBool::new(false);

/// A `PF_ROUTE` socket, close-on-exec, with a receive timeout.
fn route_socket() -> io::Result<OwnedFd> {
    // SAFETY: plain socket(2); the fd is owned by the OwnedFd from here on.
    let fd = unsafe { libc::socket(libc::PF_ROUTE, libc::SOCK_RAW, libc::AF_UNSPEC) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` was just created and is owned here alone.
    let sock = unsafe { OwnedFd::from_raw_fd(fd) };
    // SAFETY: F_SETFD on a valid fd (macOS has no SOCK_CLOEXEC).
    if unsafe { libc::fcntl(sock.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let tv = libc::timeval {
        tv_sec: QUERY_TIMEOUT.as_secs() as libc::time_t,
        tv_usec: 0,
    };
    // SAFETY: `tv` is a valid timeval for SO_RCVTIMEO, its size given.
    if unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            (&tv as *const libc::timeval).cast(),
            size_of::<libc::timeval>() as libc::socklen_t,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(sock)
}

/// An `RTM_GET` request for `dst`: the header, the destination (`RTA_DST`) and an empty
/// `sockaddr_dl` (`RTA_IFP`, so the answer names the interface), as `route -n get` sends it.
#[cfg(test)]
pub(super) fn request(dst: IpAddr, pid: i32, seq: i32) -> Vec<u8> {
    request_of(libc::RTM_GET as u8, dst, pid, seq)
}

/// An `RTM_GET` request (the type `ty`: `RTM_GET` or [`RTM_GET_SILENT`]) for `dst`: the
/// header, the destination (`RTA_DST`) and an empty `sockaddr_dl` (`RTA_IFP`, so the answer names
/// the interface), as `route -n get` sends it.
fn request_of(ty: u8, dst: IpAddr, pid: i32, seq: i32) -> Vec<u8> {
    let mut sa = match dst {
        IpAddr::V4(a) => {
            let mut s = vec![0u8; size_of::<libc::sockaddr_in>()];
            let o = offset_of!(libc::sockaddr_in, sin_addr);
            s[o..o + 4].copy_from_slice(&a.octets());
            s[1] = libc::AF_INET as u8;
            s
        }
        IpAddr::V6(a) => {
            let mut s = vec![0u8; size_of::<libc::sockaddr_in6>()];
            let o = offset_of!(libc::sockaddr_in6, sin6_addr);
            s[o..o + 16].copy_from_slice(&a.octets());
            s[1] = libc::AF_INET6 as u8;
            s
        }
    };
    sa[0] = sa.len() as u8;
    let mut dl = vec![0u8; size_of::<libc::sockaddr_dl>()];
    dl[0] = dl.len() as u8;
    dl[1] = libc::AF_LINK as u8;
    let mut m = vec![0u8; HDR_LEN];
    let len = (HDR_LEN + sa.len() + dl.len()) as u16;
    let put = |m: &mut Vec<u8>, o: usize, v: &[u8]| m[o..o + v.len()].copy_from_slice(v);
    put(
        &mut m,
        offset_of!(libc::rt_msghdr, rtm_msglen),
        &len.to_ne_bytes(),
    );
    m[offset_of!(libc::rt_msghdr, rtm_version)] = libc::RTM_VERSION as u8;
    m[offset_of!(libc::rt_msghdr, rtm_type)] = ty;
    put(
        &mut m,
        offset_of!(libc::rt_msghdr, rtm_flags),
        &(libc::RTF_UP | libc::RTF_HOST).to_ne_bytes(),
    );
    put(
        &mut m,
        offset_of!(libc::rt_msghdr, rtm_addrs),
        &(libc::RTA_DST | libc::RTA_IFP).to_ne_bytes(),
    );
    put(
        &mut m,
        offset_of!(libc::rt_msghdr, rtm_pid),
        &pid.to_ne_bytes(),
    );
    put(
        &mut m,
        offset_of!(libc::rt_msghdr, rtm_seq),
        &seq.to_ne_bytes(),
    );
    m.extend_from_slice(&sa);
    m.extend_from_slice(&dl);
    m
}

/// The answer to request (`pid`, `seq`) for `dst` in one datagram: `Some(Some(route))`,
/// `Some(None)` for no route (`ESRCH`, or a route that reaches nothing), `None` when the datagram
/// is not the kernel's answer to this request.
///
/// Only a datagram that is exactly one message (its length is its `rtm_msglen`), of type
/// `RTM_GET` and this version, whose `rtm_pid` and `rtm_seq` are this request's, is the answer
/// (review round 2, parse-1 and parse-2). Every other datagram is skipped, whatever it holds:
/// another process's or thread's message, a routing change, and above all a message the kernel
/// refused. xnu's `route_output` hands a write it refuses to every routing socket as written:
/// one whose length is not its `rtm_msglen` raw (pid and sequence number as the writer chose
/// them), and one refused before the kernel sets `rtm_pid` (another version: `EPROTONOSUPPORT`;
/// any type but `RTM_GET` from an unprivileged writer: `EPERM`) with its version or type kept.
/// Every write the kernel accepts as a request has `rtm_pid` set to the writer's (measured:
/// `fix-r2/forge-variants.log`, 23 kinds of write). So a datagram whose length matches its
/// header, of this version and type `RTM_GET`, with this process's pid, is a message the kernel
/// wrote for this process. The kernel copies its answer whole (`rtm_msglen` its length), so an
/// answer is never skipped for its length.
///
/// The answer is an error when it does not parse: malformed, an interface (`RTA_IFP`, the
/// `sockaddr_dl` the request asked for) that is not the header's `rtm_index` (xnu takes both
/// from the route's `rt_ifp`, so they always agree), or a route that does not hold `dst`.
pub(super) fn parse_answer(
    b: &[u8],
    pid: i32,
    seq: i32,
    dst: IpAddr,
) -> io::Result<Option<Option<Route>>> {
    if b.len() < HDR_LEN {
        return Ok(None);
    }
    let h = header(b)?;
    if h.len != b.len()
        || i32::from(h.version) != libc::RTM_VERSION
        || i32::from(h.ty) != libc::RTM_GET
        || h.pid != pid
        || h.seq != seq
    {
        return Ok(None);
    }
    if h.errno != 0 {
        return match h.errno {
            libc::ESRCH | libc::ENETUNREACH | libc::EHOSTUNREACH => Ok(Some(None)),
            e => Err(io::Error::from_raw_os_error(e)),
        };
    }
    let body = &b[HDR_LEN..h.len];
    if let Some(ifp) = sockaddrs(body, h.addrs)?[libc::RTAX_IFP as usize] {
        let index = u16_at(ifp, offset_of!(libc::sockaddr_dl, sdl_index));
        if ifp.get(1).map(|f| i32::from(*f)) != Some(libc::AF_LINK) || index != Some(h.index) {
            return Err(malformed());
        }
    }
    let Some(route) = parse_route(&h, body, false)? else {
        return Ok(Some(None));
    };
    if !route.holds(dst) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "the kernel answered a route query for {dst} with {}, which does not hold it",
                route.prefix
            ),
        ));
    }
    Ok(Some(Some(route)))
}

/// One `RTM_GET` for `dst` (see the module doc): the route, or `None` without one. Asked as
/// [`RTM_GET_SILENT`] unless the kernel refused that type before.
fn ask(dst: IpAddr) -> io::Result<Option<Route>> {
    ask_as(dst, next_seq())
}

/// [`ask`] with sequence number `seq` (tests fix it, to forge answers to it).
fn ask_as(dst: IpAddr, seq: i32) -> io::Result<Option<Route>> {
    let sock = route_socket()?;
    // SAFETY: getpid cannot fail.
    let pid = unsafe { libc::getpid() };
    let silent = !SILENT_REFUSED.load(Ordering::Relaxed);
    let ty = if silent {
        RTM_GET_SILENT
    } else {
        libc::RTM_GET as u8
    };
    let req = request_of(ty, dst, pid, seq);
    // SAFETY: `req` is valid for its length.
    let n = unsafe { libc::write(sock.as_raw_fd(), req.as_ptr().cast(), req.len()) };
    if n < 0 {
        let e = io::Error::last_os_error();
        if silent && matches!(e.raw_os_error(), Some(libc::EPERM) | Some(libc::EOPNOTSUPP)) {
            SILENT_REFUSED.store(true, Ordering::Relaxed);
            tracing::debug!("network guard: RTM_GET_SILENT refused ({e}); asking with RTM_GET");
            return ask_as(dst, next_seq());
        }
        return match e.raw_os_error() {
            Some(libc::ESRCH) | Some(libc::ENETUNREACH) | Some(libc::EHOSTUNREACH) => Ok(None),
            _ => Err(e),
        };
    }
    if n as usize != req.len() {
        return Err(io::Error::other("short write of a route query"));
    }
    let deadline = Instant::now() + QUERY_TIMEOUT;
    let mut buf = vec![0u8; RECV_BUF];
    loop {
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "the kernel did not answer a route query",
            ));
        }
        // SAFETY: `buf` is valid for its length.
        let n = unsafe { libc::recv(sock.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), 0) };
        if n < 0 {
            let e = io::Error::last_os_error();
            match e.kind() {
                io::ErrorKind::Interrupted => continue,
                io::ErrorKind::WouldBlock => {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "the kernel did not answer a route query",
                    ))
                }
                _ => return Err(e),
            }
        }
        if let Some(answer) = parse_answer(&buf[..n as usize], pid, seq, dst)? {
            return Ok(answer);
        }
    }
}

/// The interface index of each of this host's addresses (`getifaddrs`).
fn address_interfaces() -> io::Result<Vec<(IpAddr, u32)>> {
    let mut out = Vec::new();
    for_each_ifaddr(|ifa| {
        // SAFETY: a live node's address is null or a sockaddr of its sa_len bytes.
        if let Some(sa) = unsafe { sockaddr_bytes(ifa.ifa_addr) } {
            if let Ok(Some(a)) = sa_ip(sa) {
                // SAFETY: a live node's name is a NUL-terminated string.
                let index = unsafe { libc::if_nametoindex(ifa.ifa_name) };
                out.push((a, index));
            }
        }
    })?;
    Ok(out)
}

/// A UDP socket connected to `dst` on `dport` (443 when none is given; UDP `connect` sends
/// nothing); `None` when the kernel will not connect a socket there (unreachable).
fn udp_toward(dst: IpAddr, dport: Option<u16>) -> io::Result<Option<UdpSocket>> {
    let any: SocketAddr = match dst {
        IpAddr::V4(_) => (Ipv4Addr::UNSPECIFIED, 0).into(),
        IpAddr::V6(_) => (Ipv6Addr::UNSPECIFIED, 0).into(),
    };
    let sock = UdpSocket::bind(any)?;
    if let Err(e) = sock.connect(SocketAddr::new(dst, dport.unwrap_or(443))) {
        return match e.raw_os_error() {
            Some(libc::ENETUNREACH) | Some(libc::EHOSTUNREACH) => Ok(None),
            _ => Err(e),
        };
    }
    Ok(Some(sock))
}

/// The interfaces a connection to `dst` may leave by, as a real socket sees it: every interface
/// that holds the source address the kernel chooses when a UDP socket is connected to `dst` (no
/// packet is sent), sorted. `None` when the kernel will not connect a socket there (unreachable);
/// empty when the source address is on no interface.
fn socket_interfaces(dst: IpAddr, dport: Option<u16>) -> io::Result<Option<Vec<u32>>> {
    let Some(sock) = udp_toward(dst, dport)? else {
        return Ok(None);
    };
    let src = sock.local_addr()?.ip();
    let mut v: Vec<u32> = address_interfaces()?
        .into_iter()
        .filter(|(a, _)| *a == src)
        .map(|(_, i)| i)
        .collect();
    v.sort();
    v.dedup();
    Ok(Some(v))
}

/// How the kernel would route a connection from this process to `dst` (see the module doc).
pub(super) fn query(dst: IpAddr, dport: Option<u16>) -> io::Result<KernelAnswer> {
    // A connection to 0.0.0.0 or :: goes to this host (loopback), while `RTM_GET` answers it with
    // the default route: answered here as what it is, a destination on this host.
    if dst.is_unspecified() {
        return Ok(KernelAnswer::Entry(vec![Route {
            loopback: true,
            ..Route::local(Prefix::host(dst), 0)
        }]));
    }
    query_with(dst, dport, ask, socket_interfaces)
}

/// [`query`]'s steps for a destination that is not unspecified, with the kernel's route query
/// (`ask`) and the socket's view (`socket`, asked with the destination and port) given.
fn query_with(
    dst: IpAddr,
    dport: Option<u16>,
    ask: impl FnOnce(IpAddr) -> io::Result<Option<Route>>,
    socket: impl FnOnce(IpAddr, Option<u16>) -> io::Result<Option<Vec<u32>>>,
) -> io::Result<KernelAnswer> {
    decide(ask(dst)?, || socket(dst, dport))
}

/// The kernel's answer for one destination from its route (`None`: no route) and, asked only when
/// the judge could admit the route, the socket's view (`socket`: [`socket_interfaces`]). A route
/// the judge could admit is one through a gateway, or a default-like one, that does not deliver
/// to this host; an on-link route that is not default-like, and a route that delivers to this
/// host, are refused whatever the socket says, so it is not asked (under Local Network privacy a
/// UDP connect into the LAN can fail, and the refusal then still names the route). For one the
/// judge could admit: a socket the kernel will not connect is no route; a source address on no
/// interface, or on any interface but the route's, is [`KernelAnswer::Split`] (refused); a source
/// address only on the route's interface leaves the route's answer as it is.
pub(super) fn decide(
    route: Option<Route>,
    socket: impl FnOnce() -> io::Result<Option<Vec<u32>>>,
) -> io::Result<KernelAnswer> {
    let Some(route) = route else {
        return Ok(KernelAnswer::NoRoute);
    };
    let admissible = route.kind == RouteType::Unicast
        && (matches!(route.hop, Hop::Via(_)) || route.is_default_like());
    if !admissible {
        return Ok(KernelAnswer::Entry(vec![route]));
    }
    let Some(interfaces) = socket()? else {
        return Ok(KernelAnswer::NoRoute);
    };
    let elsewhere = match interfaces.iter().find(|i| **i != route.ifindex) {
        Some(i) => Some(*i),
        None if interfaces.is_empty() => Some(0),
        None => None,
    };
    Ok(match elsewhere {
        Some(i) => KernelAnswer::Split {
            first_table: SCOPED_TABLE + i,
            entry: vec![route],
        },
        None => KernelAnswer::Entry(vec![route]),
    })
}

/// The interface the kernel would send a connection to `dst` out of (the route's), `None` without
/// a route.
pub(super) fn output_interface(dst: IpAddr) -> io::Result<Option<u32>> {
    Ok(ask(dst)?.map(|r| r.ifindex).filter(|i| *i != 0))
}

/// Nexthop objects: none on macOS.
pub(super) fn nexthops() -> io::Result<Vec<Nexthop>> {
    Ok(Vec::new())
}

/// Calls `f` with every node of `getifaddrs`' list.
fn for_each_ifaddr(mut f: impl FnMut(&libc::ifaddrs)) -> io::Result<()> {
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
    let mut cur = list.0;
    while !cur.is_null() {
        // SAFETY: `cur` is a non-null node of the list getifaddrs returned, alive until `list`
        // drops.
        let ifa = unsafe { &*cur };
        cur = ifa.ifa_next;
        if !ifa.ifa_name.is_null() {
            f(ifa);
        }
    }
    Ok(())
}

/// The `sa_len` bytes of a sockaddr from `getifaddrs`, `None` for a null pointer.
///
/// # Safety
/// `sa` is null or points to a sockaddr whose first byte is its length, valid for that many bytes
/// (BSD's `sa_len`, which `getifaddrs` copies each sockaddr by).
unsafe fn sockaddr_bytes<'a>(sa: *const libc::sockaddr) -> Option<&'a [u8]> {
    if sa.is_null() {
        return None;
    }
    let len = usize::from((*sa).sa_len);
    Some(std::slice::from_raw_parts(sa.cast::<u8>(), len))
}

/// The names of Apple's own Ethernet-type and Wi-Fi interfaces (`IFT_ETHER`, `IFT_IEEE80211`):
/// `en` (Ethernet, Wi-Fi, Thunderbolt and USB adapters), `ap` (the Wi-Fi access point of Internet
/// Sharing), `awdl` and `llw` (Apple Wireless Direct Link, low-latency WLAN), `nan` (Wi-Fi Aware),
/// `anpi` (the internal Apple network interfaces of Apple-silicon Macs). Any other name of those
/// types (ZeroTier's `feth`, a virtual machine's `vmenet`, a third-party driver's) is a virtual
/// Ethernet the guard cannot tell from a tunnel, so it does not count as physical.
const PHYSICAL_NAMES: &[&str] = &["en", "ap", "awdl", "llw", "nan", "anpi"];

/// A macOS interface type and name read as a Linux link kind (see the module doc): `None` for a
/// physical interface (an Ethernet-type or Wi-Fi interface of a name in [`PHYSICAL_NAMES`], and
/// loopback), a kind in [`super::PHYSICAL_KINDS`] for a bridge, VLAN or link aggregate, `tun` for
/// a `utun`, `tap` for a `tap`, and otherwise a kind no list has (`ether-feth` for an
/// Ethernet-type interface of another name, `ipsec`, `gif`, `stf`, `iftype-N`), which the guard
/// does not count as physical.
pub(crate) fn link_kind(ift: u8, name: &str) -> Option<String> {
    let named = |p: &str| {
        name.strip_prefix(p)
            .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
    };
    let kind = match ift {
        IFT_LOOP => return None,
        IFT_ETHER | IFT_IEEE80211 => {
            if named("bridge") {
                "bridge"
            } else if named("vlan") {
                "vlan"
            } else if named("bond") {
                "bond"
            } else if named("tap") {
                "tap"
            } else if PHYSICAL_NAMES.iter().any(|p| named(p)) {
                return None;
            } else {
                let base = name.trim_end_matches(|c: char| c.is_ascii_digit());
                return Some(format!("ether-{}", crate::printable(base, 32)));
            }
        }
        IFT_BRIDGE => "bridge",
        IFT_L2VLAN => "vlan",
        IFT_IEEE8023ADLAG => "bond",
        IFT_PPP => "ppp",
        IFT_OTHER if named("utun") => "tun",
        IFT_OTHER if named("ipsec") => "ipsec",
        IFT_GIF => "gif",
        IFT_STF => "stf",
        other => return Some(format!("iftype-{other}")),
    };
    Some(kind.to_string())
}

/// Every network interface: index, name and kind from `getifaddrs`' `AF_LINK` entries
/// (`sockaddr_dl`, <net/if_dl.h>).
pub(super) fn links() -> io::Result<Vec<Link>> {
    let mut out = Vec::new();
    for_each_ifaddr(|ifa| {
        // SAFETY: a live node's address is null or a sockaddr of its sa_len bytes.
        let Some(sa) = (unsafe { sockaddr_bytes(ifa.ifa_addr) }) else {
            return;
        };
        if sa.get(1).map(|f| i32::from(*f)) != Some(libc::AF_LINK) {
            return;
        }
        let (Some(index), Some(&ift)) = (
            u16_at(sa, offset_of!(libc::sockaddr_dl, sdl_index)),
            sa.get(offset_of!(libc::sockaddr_dl, sdl_type)),
        ) else {
            return;
        };
        // SAFETY: a live node's name is a NUL-terminated string.
        let name = unsafe { std::ffi::CStr::from_ptr(ifa.ifa_name) }
            .to_string_lossy()
            .into_owned();
        let kind = link_kind(ift, &name);
        out.push(Link {
            index: u32::from(index),
            name,
            kind,
        });
    })?;
    out.sort();
    out.dedup();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::super::{RouteKind, RouteTable};
    use super::*;

    const FIXTURES: &str = include_str!("testdata/macos-routing.txt");

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// The captured `RTM_GET` replies, by destination.
    fn replies() -> Vec<(IpAddr, Vec<u8>)> {
        FIXTURES
            .lines()
            .filter_map(|l| l.strip_prefix("get "))
            .map(|l| {
                let (d, h) = l.split_once(' ').unwrap();
                (d.parse().unwrap(), hex(h))
            })
            .collect()
    }

    fn reply(dst: &str) -> (IpAddr, Vec<u8>) {
        let dst: IpAddr = dst.parse().unwrap();
        replies().into_iter().find(|(d, _)| *d == dst).unwrap()
    }

    /// The captured dump buffer.
    fn dump_fixture() -> Vec<u8> {
        hex(FIXTURES
            .lines()
            .find_map(|l| l.strip_prefix("dump "))
            .unwrap())
    }

    /// The answer a captured reply gives, read with its own pid and sequence number.
    fn answer(dst: &str) -> Option<Route> {
        let (d, b) = reply(dst);
        let h = header(&b).unwrap();
        parse_answer(&b, h.pid, h.seq, d).unwrap().unwrap()
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn p(s: &str) -> Prefix {
        s.parse().unwrap()
    }

    #[test]
    fn the_header_is_the_kernels() {
        assert_eq!(HDR_LEN, 92);
        assert_eq!(offset_of!(libc::rt_msghdr, rtm_flags), 8);
        assert_eq!(offset_of!(libc::rt_msghdr, rtm_errno), 24);
        assert_eq!(size_of::<libc::sockaddr_dl>(), 20);
        // A request as route(8) sends it: 92 + 16 + 20 bytes for IPv4, 92 + 28 + 20 for IPv6.
        let r = request(ip("1.1.1.1"), 7, 9);
        assert_eq!(r.len(), 128);
        let h = header(&r).unwrap();
        assert_eq!((h.len, h.version, h.ty, h.pid, h.seq), (128, 5, 4, 7, 9));
        assert_eq!(h.addrs, libc::RTA_DST | libc::RTA_IFP);
        let s = sockaddrs(&r[HDR_LEN..], h.addrs).unwrap();
        assert_eq!(sa_ip(s[0].unwrap()).unwrap(), Some(ip("1.1.1.1")));
        assert_eq!(s[4].unwrap()[1], libc::AF_LINK as u8);
        assert_eq!(request(ip("2606:4700:4700::1111"), 7, 9).len(), 140);
    }

    /// Every captured reply reads as `route -n get` showed it on the Mac it was captured on.
    #[test]
    fn captured_route_replies_parse() {
        let via = |d: &str, prefix: &str, gw: &str, ifindex: u32, table: u32| {
            let r = answer(d).unwrap();
            assert_eq!(
                (r.prefix, r.hop, r.ifindex, r.kind, r.table),
                (
                    p(prefix),
                    Hop::Via(ip(gw)),
                    ifindex,
                    RouteType::Unicast,
                    table
                ),
                "{d}"
            );
        };
        // The IPv4 default route (destination 0.0.0.0, a zero-length netmask), and a clone of it
        // on the primary interface (`HOST, WASCLONED, IFSCOPE`).
        via("8.8.4.4", "0.0.0.0/0", "192.168.1.1", 8, RT_TABLE_MAIN);
        via("1.1.1.1", "1.1.1.1/32", "192.168.1.1", 8, SCOPED_TABLE + 8);
        // The IPv6 default, through the router's link-local address (embedded scope cleared).
        via(
            "2606:4700:4700::1111",
            "::/0",
            "fe80::fe00:1",
            8,
            RT_TABLE_MAIN,
        );
        let on_link = |d: &str, prefix: &str, ifindex: u32| {
            let r = answer(d).unwrap();
            assert_eq!(
                (r.prefix, r.hop, r.ifindex, r.kind),
                (p(prefix), Hop::OnLink, ifindex, RouteType::Unicast),
                "{d}"
            );
            r
        };
        // The router itself (an ARP entry: no RTF_GATEWAY, a link-layer gateway), a LAN neighbour
        // (the cloning /24, its netmask trimmed to 7 bytes), an IPv6 neighbour (the /64), and
        // link-local (scoped to en0).
        on_link("192.168.1.1", "192.168.1.1/32", 8);
        on_link("192.168.1.50", "192.168.1.0/24", 8);
        on_link("2001:db8:9024:184::99", "2001:db8:9024:184::/64", 8);
        assert_eq!(on_link("fe80::1", "fe80::/64", 8).table, SCOPED_TABLE + 8);
        // This host: its addresses and loopback deliver locally, on lo0.
        for d in [
            "192.168.1.213",
            "127.0.0.1",
            "::1",
            "2001:db8:9024:184:2cd3:b59f:bfaa:3b77",
        ] {
            let r = answer(d).unwrap();
            assert_eq!(
                (r.prefix, r.kind, r.ifindex),
                (Prefix::host(ip(d)), RouteType::Local, 1),
                "{d}"
            );
        }
    }

    /// The captured dump: the defaults of both families on en0 are the uplinks; the four system
    /// utun interfaces' scoped IPv6 defaults are no default route and no uplink; the LAN, the
    /// router's host route and the IPv6 /64 are on-link; this host's IPv6 addresses deliver
    /// locally; multicast routes are not read.
    #[test]
    fn the_captured_dump_parses_into_the_default_path() {
        let routes = parse_dump(&dump_fixture()).unwrap();
        assert!(routes
            .iter()
            .all(|r| Prefix::new(r.prefix.addr, r.prefix.len) == r.prefix));
        assert!(!routes.iter().any(
            |r| matches!(r.prefix.addr, IpAddr::V4(a) if a.is_multicast())
                || matches!(r.prefix.addr, IpAddr::V6(a) if a.is_multicast())
        ));
        let scoped_defaults: Vec<u32> = routes
            .iter()
            .filter(|r| r.prefix.len == 0 && r.table != RT_TABLE_MAIN)
            .map(|r| r.ifindex)
            .collect();
        assert_eq!(scoped_defaults, vec![22, 23, 24, 25]);
        let t = RouteTable::with_rules(
            routes.clone(),
            vec![
                Rule::lookup(false, RT_TABLE_MAIN),
                Rule::lookup(true, RT_TABLE_MAIN),
            ],
        );
        assert_eq!(
            t.uplinks(),
            &[(ip("192.168.1.1"), 8), (ip("fe80::fe00:1"), 8)]
        );
        assert!(t.routes_family(false) && t.routes_family(true));
        assert_eq!(t.default_interfaces(), vec![8]);
        for public in ["8.8.8.8", "1.0.0.1", "2606:4700:4700::1111"] {
            assert_eq!(t.off_default_path(ip(public)), None, "{public}");
        }
        let kind = |a: &str| t.off_default_path(ip(a)).map(|r| r.kind);
        assert_eq!(kind("192.168.1.1"), Some(RouteKind::OnLink));
        assert_eq!(kind("192.168.1.77"), Some(RouteKind::OnLink));
        assert_eq!(kind("2001:db8:9024:184::77"), Some(RouteKind::OnLink));
        assert_eq!(kind("fe80::99"), Some(RouteKind::OnLink));
        assert_eq!(kind("127.0.0.2"), Some(RouteKind::OnLink));
        assert_eq!(
            kind("2001:db8:9024:184:2cd3:b59f:bfaa:3b77"),
            Some(RouteKind::Local)
        );
        assert_eq!(kind("::1"), Some(RouteKind::Local));
        assert!(t.on_link_prefixes().contains(&p("2001:db8:9024:184::/64")));
        assert!(t.on_link_prefixes().contains(&p("192.168.1.0/24")));
        // The kernel's answers, judged against this table.
        let judge = |d: &str| {
            t.judge_answer(&KernelAnswer::Entry(vec![answer(d).unwrap()]))
                .map_err(|r| r.kind)
        };
        assert_eq!(judge("8.8.4.4"), Ok(()));
        assert_eq!(judge("1.1.1.1"), Ok(()));
        assert_eq!(judge("2606:4700:4700::1111"), Ok(()));
        assert_eq!(judge("192.168.1.1"), Err(RouteKind::OnLink));
        assert_eq!(judge("192.168.1.50"), Err(RouteKind::OnLink));
        assert_eq!(judge("2001:db8:9024:184::99"), Err(RouteKind::OnLink));
        assert_eq!(judge("fe80::1"), Err(RouteKind::OnLink));
        assert_eq!(judge("192.168.1.213"), Err(RouteKind::Local));
        assert_eq!(judge("::1"), Err(RouteKind::Local));
    }

    /// A utun's scoped default (as a VPN that does not take over the default route leaves one),
    /// were the kernel to answer with it, is refused: no ordinary table holds it, and its gateway
    /// is no uplink.
    #[test]
    fn a_scoped_default_is_no_default_path() {
        let routes = parse_dump(&dump_fixture()).unwrap();
        let t = RouteTable::with_rules(
            routes.clone(),
            vec![
                Rule::lookup(false, RT_TABLE_MAIN),
                Rule::lookup(true, RT_TABLE_MAIN),
            ],
        );
        let utun = routes
            .iter()
            .find(|r| r.prefix.len == 0 && r.ifindex == 22)
            .unwrap();
        assert_eq!(utun.table, SCOPED_TABLE + 22);
        assert_eq!(
            t.judge_answer(&KernelAnswer::Entry(vec![*utun]))
                .map_err(|r| r.kind),
            Err(RouteKind::PolicyRule)
        );
        // And a socket that leaves by another interface than the route names is refused.
        let entry = vec![answer("8.8.4.4").unwrap()];
        assert_eq!(
            t.judge_answer(&KernelAnswer::Split {
                first_table: SCOPED_TABLE + 22,
                entry
            })
            .map_err(|r| r.kind),
            Err(RouteKind::PolicyRule)
        );
    }

    /// Another process's or thread's message is skipped; no route, a reject or blackhole route and
    /// a route that is not up are no route; a failure is an error; an answer that does not hold
    /// the destination is an error.
    #[test]
    fn answers_are_matched_and_judged_strictly() {
        let (d, b) = reply("8.8.4.4");
        let h = header(&b).unwrap();
        assert_eq!(parse_answer(&b, h.pid + 1, h.seq, d).unwrap(), None);
        assert_eq!(parse_answer(&b, h.pid, h.seq + 1, d).unwrap(), None);
        // Another message type (RTM_IFINFO) or version is not an answer, whatever its length.
        let mut other = b.clone();
        other[3] = 0xe;
        assert_eq!(parse_answer(&other, h.pid, h.seq, d).unwrap(), None);
        assert_eq!(
            parse_answer(&[0x14, 0, 5, 0xc], h.pid, h.seq, d).unwrap(),
            None
        );
        let with_flags = |set: i32, clear: i32| {
            let mut m = b.clone();
            let o = offset_of!(libc::rt_msghdr, rtm_flags);
            let f = (h.flags | set) & !clear;
            m[o..o + 4].copy_from_slice(&f.to_ne_bytes());
            parse_answer(&m, h.pid, h.seq, d).unwrap()
        };
        assert!(with_flags(0, 0).unwrap().is_some());
        assert_eq!(with_flags(libc::RTF_REJECT, 0), Some(None));
        assert_eq!(with_flags(libc::RTF_BLACKHOLE, 0), Some(None));
        assert_eq!(with_flags(0, libc::RTF_UP), Some(None));
        // A gateway flag on a route whose gateway is no IP address: through an unknown hop.
        let (rd, rb) = reply("192.168.1.1");
        let rh = header(&rb).unwrap();
        let mut m = rb.clone();
        let o = offset_of!(libc::rt_msghdr, rtm_flags);
        m[o..o + 4].copy_from_slice(&(rh.flags | libc::RTF_GATEWAY).to_ne_bytes());
        assert_eq!(
            parse_answer(&m, rh.pid, rh.seq, rd)
                .unwrap()
                .unwrap()
                .unwrap()
                .hop,
            Hop::Unknown
        );
        let with_errno = |e: i32| {
            let mut m = b.clone();
            let o = offset_of!(libc::rt_msghdr, rtm_errno);
            m[o..o + 4].copy_from_slice(&e.to_ne_bytes());
            parse_answer(&m, h.pid, h.seq, d)
        };
        assert_eq!(with_errno(libc::ESRCH).unwrap(), Some(None));
        assert!(with_errno(libc::EINVAL).is_err());
        // The default route does not hold the reply asked about if the question was another
        // family's address; a host route does not hold a neighbour.
        assert!(parse_answer(&b, h.pid, h.seq, ip("2606:4700:4700::1111")).is_err());
        let (cd, cb) = reply("1.1.1.1");
        let ch = header(&cb).unwrap();
        assert_eq!(cd, ip("1.1.1.1"));
        assert!(parse_answer(&cb, ch.pid, ch.seq, ip("1.1.1.2")).is_err());
    }

    /// The socket's view of an answer the judge could admit (cross-1): only a source address on
    /// the route's interface alone leaves the answer as it is; a source address on another
    /// interface, on several, or on none is a split (refused), a socket the kernel will not
    /// connect is no route, and a failure to ask is an error. On-link and local answers never ask
    /// the socket.
    #[test]
    fn the_socket_view_decides_an_admissible_answer() {
        let routes = parse_dump(&dump_fixture()).unwrap();
        let t = RouteTable::with_rules(
            routes,
            vec![
                Rule::lookup(false, RT_TABLE_MAIN),
                Rule::lookup(true, RT_TABLE_MAIN),
            ],
        );
        for d in ["8.8.4.4", "1.1.1.1", "2606:4700:4700::1111"] {
            let r = answer(d).unwrap();
            assert_eq!(r.ifindex, 8);
            let with = |s: Option<Vec<u32>>| decide(Some(r), || Ok(s)).unwrap();
            assert_eq!(with(Some(vec![8])), KernelAnswer::Entry(vec![r]), "{d}");
            assert_eq!(t.judge_answer(&with(Some(vec![8]))), Ok(()), "{d}");
            for (s, first) in [
                (vec![22], SCOPED_TABLE + 22),
                (vec![], SCOPED_TABLE),
                (vec![8, 22], SCOPED_TABLE + 22),
                (vec![1, 8], SCOPED_TABLE + 1),
            ] {
                let a = with(Some(s.clone()));
                assert_eq!(
                    a,
                    KernelAnswer::Split {
                        first_table: first,
                        entry: vec![r]
                    },
                    "{d} {s:?}"
                );
                assert_eq!(
                    t.judge_answer(&a).map_err(|r| r.kind),
                    Err(RouteKind::PolicyRule),
                    "{d} {s:?}"
                );
            }
            assert_eq!(with(None), KernelAnswer::NoRoute, "{d}");
            assert!(decide(Some(r), || Err(io::Error::other("no socket"))).is_err());
        }
        assert_eq!(
            decide(None, || panic!("asked the socket without a route")).unwrap(),
            KernelAnswer::NoRoute
        );
        for d in [
            "192.168.1.1",
            "192.168.1.50",
            "2001:db8:9024:184::99",
            "fe80::1",
            "192.168.1.213",
            "127.0.0.1",
            "::1",
            "2001:db8:9024:184:2cd3:b59f:bfaa:3b77",
        ] {
            let r = answer(d).unwrap();
            assert_eq!(
                decide(Some(r), || panic!("asked the socket for {d}")).unwrap(),
                KernelAnswer::Entry(vec![r]),
                "{d}"
            );
        }
        // A default route that delivers locally is refused without asking; an on-link split
        // default (a VPN's `0/1` on a utun) is default-like, so the socket is asked.
        let local = Route::local(p("0.0.0.0/0"), 1);
        assert_eq!(
            decide(Some(local), || panic!("asked")).unwrap(),
            KernelAnswer::Entry(vec![local])
        );
        let half = Route::on_link(p("0.0.0.0/1"), 30);
        assert_eq!(
            decide(Some(half), || Ok(Some(vec![8]))).unwrap(),
            KernelAnswer::Split {
                first_table: SCOPED_TABLE + 8,
                entry: vec![half]
            }
        );
    }

    /// parse-1 (c): queries are asked as `RTM_GET_SILENT` on this kernel, so another routing
    /// socket never sees their answers (nor their pid and sequence numbers).
    #[test]
    fn queries_are_answered_to_the_asking_socket_alone() {
        let watch = route_socket().unwrap();
        // SAFETY: F_SETFL on a valid fd.
        unsafe { libc::fcntl(watch.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) };
        // SAFETY: getpid cannot fail.
        let pid = unsafe { libc::getpid() };
        let seq = next_seq();
        for d in ["127.0.0.1", "8.8.4.4", "::1"] {
            assert!(ask_as(ip(d), seq).unwrap().is_some(), "{d}");
        }
        assert!(!SILENT_REFUSED.load(Ordering::Relaxed));
        std::thread::sleep(Duration::from_millis(50));
        let mut buf = vec![0u8; RECV_BUF];
        loop {
            // SAFETY: `buf` is valid for its length.
            let n = unsafe { libc::recv(watch.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), 0) };
            if n <= 0 {
                break;
            }
            let h = header(&buf[..n as usize]);
            assert!(
                !matches!(h, Ok(h) if h.pid == pid && h.seq == seq),
                "another socket saw this query's answer"
            );
        }
        // The request goes out as RTM_GET_SILENT, and the answer comes back as RTM_GET.
        assert_eq!(request_of(RTM_GET_SILENT, ip("1.1.1.1"), 1, 2)[3], 0x11);
    }

    /// A connection to 0.0.0.0 or :: goes to this host; `RTM_GET` answers the default route for
    /// them (as `route -n get 0.0.0.0` shows). The query answers them as local (bypass-2).
    #[test]
    fn the_unspecified_addresses_are_this_host() {
        let routes = parse_dump(&dump_fixture()).unwrap();
        let t = RouteTable::with_rules(
            routes,
            vec![
                Rule::lookup(false, RT_TABLE_MAIN),
                Rule::lookup(true, RT_TABLE_MAIN),
            ],
        );
        for d in ["0.0.0.0", "::"] {
            let a = query(ip(d), Some(443)).unwrap();
            assert!(
                matches!(&a, KernelAnswer::Entry(e) if e.len() == 1
                    && e[0].kind == RouteType::Local && e[0].prefix == Prefix::host(ip(d))),
                "{d}: {a:?}"
            );
            assert_eq!(
                t.judge_answer(&a).map_err(|r| r.kind),
                Err(RouteKind::Local),
                "{d}"
            );
            // What the kernel itself answers: the default route.
            let r = ask(ip(d)).unwrap();
            eprintln!("RTM_GET {d}: {r:?}");
        }
    }

    /// The reply's interface (`RTA_IFP`) must be the header's (hardening): every captured reply's
    /// is; one that names another interface, or is no link-layer sockaddr, is an error. And
    /// each query's sequence number is drawn on its own (review round 2, parse-1: a counter from
    /// a random start let a process that saw one answer guess the next query's).
    #[test]
    fn the_answers_interface_is_the_headers() {
        for (d, b) in replies() {
            let h = header(&b).unwrap();
            assert_ne!(h.addrs & libc::RTA_IFP, 0, "{d}");
            let sas = sockaddrs(&b[HDR_LEN..h.len], h.addrs).unwrap();
            let ifp = sas[libc::RTAX_IFP as usize].unwrap();
            let off = ifp.as_ptr() as usize - b.as_ptr() as usize;
            let at = off + offset_of!(libc::sockaddr_dl, sdl_index);
            assert_eq!(u16_at(&b, at), Some(h.index), "{d}");
            let mut m = b.clone();
            m[at..at + 2].copy_from_slice(&(h.index + 1).to_ne_bytes());
            assert!(parse_answer(&m, h.pid, h.seq, d).is_err(), "{d}");
            let mut m = b.clone();
            m[off + 1] = libc::AF_INET as u8;
            assert!(parse_answer(&m, h.pid, h.seq, d).is_err(), "{d}");
        }
        let seqs: Vec<i32> = (0..1000).map(|_| next_seq()).collect();
        let follows = seqs
            .windows(2)
            .filter(|w| w[1] == w[0].wrapping_add(1))
            .count();
        let mut distinct = seqs.clone();
        distinct.sort();
        distinct.dedup();
        assert!(
            follows <= 1,
            "{follows} of 999 sequence numbers follow the one before"
        );
        assert!(distinct.len() >= 998, "{} distinct of 1000", distinct.len());
    }

    /// Truncated or malformed input of every kind is never a route: a reply cut short anywhere,
    /// or whose message length is not the datagram's (past it, short of it, below a header), is
    /// no answer at all (review round 2, parse-1: xnu hands such a write, as written, to every
    /// routing socket, so it is never the kernel's answer; the query then waits for the real one
    /// and fails when none comes); a sockaddr that runs past the message, an address bit beyond
    /// `RTAX_MAX`, an IP sockaddr too short for its address, a reply without a destination are
    /// errors; so is a dump whose message lengths do not add up.
    #[test]
    fn malformed_and_truncated_input_is_an_error() {
        for (d, b) in replies() {
            let h = header(&b).unwrap();
            assert!(parse_answer(&b, h.pid, h.seq, d).is_ok(), "{d}");
            for cut in 0..b.len() {
                let r = parse_answer(&b[..cut], h.pid, h.seq, d);
                assert!(matches!(r, Ok(None)), "{d} cut at {cut}: {r:?}");
            }
            // The header claims more than was received, less, or less than a header; or the
            // datagram carries bytes past the message.
            for len in [b.len() + 4, b.len() - 4, HDR_LEN - 4, 0] {
                let mut m = b.clone();
                m[0..2].copy_from_slice(&(len as u16).to_ne_bytes());
                let r = parse_answer(&m, h.pid, h.seq, d);
                assert!(matches!(r, Ok(None)), "{d} len {len}: {r:?}");
            }
            let mut m = b.clone();
            m.extend([0; 4]);
            assert!(
                matches!(parse_answer(&m, h.pid, h.seq, d), Ok(None)),
                "{d} + 4"
            );
            // Sockaddrs claimed that are not there.
            let mut m = b.clone();
            let o = offset_of!(libc::rt_msghdr, rtm_addrs);
            m[o..o + 4].copy_from_slice(&(h.addrs | libc::RTA_BRD).to_ne_bytes());
            assert!(parse_answer(&m, h.pid, h.seq, d).is_err(), "{d} RTA_BRD");
            m[o..o + 4].copy_from_slice(&(h.addrs | 0x100).to_ne_bytes());
            assert!(parse_answer(&m, h.pid, h.seq, d).is_err(), "{d} bit 8");
            // No destination.
            m[o..o + 4].copy_from_slice(&(h.addrs & !libc::RTA_DST).to_ne_bytes());
            assert!(parse_answer(&m, h.pid, h.seq, d).is_err(), "{d} no RTA_DST");
            // A destination sockaddr too short for its address.
            let mut m = b.clone();
            m[HDR_LEN] = 6;
            assert!(parse_answer(&m, h.pid, h.seq, d).is_err(), "{d} short dst");
        }
        // The dump: cut anywhere inside a message, or a length that does not add up.
        let dump = dump_fixture();
        let n = parse_dump(&dump).unwrap().len();
        assert!(n > 20, "{n}");
        let first = header(&dump).unwrap().len;
        for cut in [
            1,
            4,
            HDR_LEN - 1,
            HDR_LEN,
            first - 1,
            first + 1,
            dump.len() - 1,
        ] {
            assert!(parse_dump(&dump[..cut]).is_err(), "dump cut at {cut}");
        }
        let mut m = dump.clone();
        m[0..2].copy_from_slice(&((first - 4) as u16).to_ne_bytes());
        assert!(parse_dump(&m).is_err());
        let mut m = dump.clone();
        m[2] = 4; // RTM_VERSION 4: another layout
        assert!(parse_dump(&m).is_err());
        let mut m = dump;
        m[3] = libc::RTM_ADD as u8;
        assert!(parse_dump(&m).is_err());
    }

    /// Netmasks the kernel trims, leaves empty or writes non-contiguous; embedded scopes.
    #[test]
    fn netmasks_and_scopes_read_as_the_kernel_means_them() {
        assert_eq!(mask_len(&[], true), Some(0));
        assert_eq!(
            mask_len(&[7, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff], true),
            Some(24)
        );
        assert_eq!(mask_len(&[5, 0xff, 0, 0, 0xff], true), Some(8));
        assert_eq!(
            mask_len(&[8, 0xff, 0, 0, 0xff, 0xff, 0xff, 0xfe], true),
            Some(31)
        );
        assert_eq!(
            mask_len(&[8, 0xff, 0, 0, 0xff, 0xff, 0xff, 0xff], true),
            Some(32)
        );
        // Non-contiguous masks are no prefix length (parse-1: 255.15.255.255 read as /8 before,
        // 0.255.255.0 as /0).
        assert_eq!(
            mask_len(&[8, 0xff, 0, 0, 0xff, 0x0f, 0xff, 0xff], true),
            None
        );
        assert_eq!(mask_len(&[8, 0xff, 0, 0, 0, 0xff, 0xff, 0], true), None);
        assert_eq!(mask_len(&[8, 0xff, 0, 0, 0xff, 0xff, 0xfd, 0], true), None);
        let mut v6 = vec![0x10, 0xff, 0, 0, 0, 0, 0, 0];
        v6.extend([0xff; 8]);
        assert_eq!(mask_len(&v6, false), Some(64));
        assert_eq!(mask_len(&[], false), Some(0));
        let mut v6 = vec![0x1c, 0xff, 0, 0, 0, 0, 0, 0];
        v6.extend([0xff; 8]);
        v6.extend([0, 0, 0, 0, 0, 0, 0, 1]);
        assert_eq!(mask_len(&v6, false), None);
        let mut a = [0xfe, 0x80, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        clear_embedded_scope(&mut a);
        assert_eq!(Ipv6Addr::from(a), "fe80::1".parse::<Ipv6Addr>().unwrap());
        let mut g = "2606:8::1".parse::<Ipv6Addr>().unwrap().octets();
        clear_embedded_scope(&mut g);
        assert_eq!(Ipv6Addr::from(g), "2606:8::1".parse::<Ipv6Addr>().unwrap());
    }

    /// parse-1: the captured replies and dump with a netmask made non-contiguous (the LAN /24's
    /// 255.255.255.0 as 0.255.255.0, or with a hole) are malformed, never a wider route: the
    /// reply is an error (the destination refused) and the dump fails (the facts read fails).
    #[test]
    fn a_non_contiguous_netmask_is_malformed() {
        // Where each message's netmask's address bytes start, in `b`.
        let mask_at = |b: &[u8], start: usize| {
            let h = header(&b[start..]).unwrap();
            let body = &b[start + HDR_LEN..start + h.len];
            sockaddrs(body, h.addrs).unwrap()[libc::RTAX_NETMASK as usize].map(|m| {
                let v4 = m.len() <= 8;
                (
                    m.as_ptr() as usize - b.as_ptr() as usize,
                    m.len(),
                    v4,
                    h.flags & libc::RTF_HOST != 0,
                )
            })
        };
        let (d, b) = reply("192.168.1.50");
        let h = header(&b).unwrap();
        let (at, len, _, _) = mask_at(&b, 0).unwrap();
        assert_eq!(len, 7);
        let a = offset_of!(libc::sockaddr_in, sin_addr);
        assert_eq!(&b[at + a..at + len], &[0xff, 0xff, 0xff]);
        assert_eq!(answer("192.168.1.50").unwrap().prefix, p("192.168.1.0/24"));
        for mask in [
            [0, 0xff, 0xff],
            [0xff, 0, 0xff],
            [0xff, 0xff, 0x7f],
            [0xfe, 0xff, 0xff],
        ] {
            let mut m = b.clone();
            m[at + a..at + len].copy_from_slice(&mask);
            let r = parse_answer(&m, h.pid, h.seq, d);
            assert!(r.is_err(), "{mask:02x?}: {r:?}");
        }
        // Every netmask of the dump, one at a time: its first address byte cleared where it was
        // set and followed by more mask bits.
        let dump = dump_fixture();
        let n = parse_dump(&dump).unwrap().len();
        let mut start = 0;
        let mut mutated = 0;
        while start < dump.len() {
            let h = header(&dump[start..]).unwrap();
            if let Some((at, len, _, host)) = mask_at(&dump, start) {
                let first = if len > 8 {
                    offset_of!(libc::sockaddr_in6, sin6_addr)
                } else {
                    a
                };
                let body = start + HDR_LEN..start + h.len;
                let read = parse_route(&h, &dump[body.clone()], true)
                    .unwrap()
                    .is_some();
                if read && !host && len > first + 1 && dump[at + first] == 0xff {
                    // A route the dump reads: it is malformed, and the whole dump refused.
                    let mut m = dump.clone();
                    m[at + first] = 0;
                    assert!(parse_route(&h, &m[body], true).is_err(), "at {start}");
                    assert!(parse_dump(&m).is_err(), "message at {start}");
                    mutated += 1;
                }
            }
            start += h.len;
        }
        eprintln!("{mutated} of the dump's {n} routes' netmasks made non-contiguous: each refused");
        assert!(mutated >= 3, "{mutated}");
    }

    #[test]
    fn interface_types_read_as_link_kinds() {
        assert_eq!(link_kind(IFT_ETHER, "en0"), None);
        assert_eq!(link_kind(IFT_LOOP, "lo0"), None);
        assert_eq!(link_kind(IFT_ETHER, "bridge0").as_deref(), Some("bridge"));
        assert_eq!(link_kind(IFT_ETHER, "tap3").as_deref(), Some("tap"));
        assert_eq!(link_kind(IFT_OTHER, "utun4").as_deref(), Some("tun"));
        assert_eq!(link_kind(IFT_OTHER, "ipsec0").as_deref(), Some("ipsec"));
        assert_eq!(link_kind(IFT_PPP, "ppp0").as_deref(), Some("ppp"));
        assert_eq!(link_kind(IFT_GIF, "gif0").as_deref(), Some("gif"));
        assert_eq!(link_kind(0xff, "pdp_ip0").as_deref(), Some("iftype-255"));
        assert_eq!(link_kind(IFT_OTHER, "other0").as_deref(), Some("iftype-1"));
        let link = |ift, name: &str| Link {
            index: 1,
            name: name.into(),
            kind: link_kind(ift, name),
        };
        assert!(link(IFT_ETHER, "en0").is_physical());
        assert!(link(IFT_ETHER, "bridge0").is_physical());
        assert!(link(IFT_OTHER, "utun0").is_tunnel());
        assert!(!link(IFT_OTHER, "utun0").is_physical());
        assert!(!link(IFT_OTHER, "ipsec0").is_physical());
        assert!(link(IFT_PPP, "ppp0").is_ppp());
        // parse-3: only Apple's own Ethernet-type and Wi-Fi names are physical; ZeroTier's
        // `feth`, a VM's `vmenet`, an unknown driver's interface are not (fail closed).
        for name in ["en0", "en12", "ap1", "awdl0", "llw0", "nan0", "anpi3"] {
            for ift in [IFT_ETHER, IFT_IEEE80211] {
                assert_eq!(link_kind(ift, name), None, "{name}");
            }
        }
        for (name, kind) in [
            ("feth0", "ether-feth"),
            ("feth1234", "ether-feth"),
            ("vmenet0", "ether-vmenet"),
            ("zt0", "ether-zt"),
            ("en", "ether-en"),
            ("enx0", "ether-enx"),
            ("eth0", "ether-eth"),
        ] {
            assert_eq!(link_kind(IFT_ETHER, name).as_deref(), Some(kind), "{name}");
            assert!(!link(IFT_ETHER, name).is_physical(), "{name}");
            assert!(!link(IFT_IEEE80211, name).is_physical(), "{name}");
        }
    }

    /// This host's real interfaces classify as their kinds: Apple's Ethernet, Wi-Fi and internal
    /// interfaces and loopback are physical, `bridgeN` a bridge, `utunN` a tunnel, `gif`/`stf`
    /// not physical; anything else found is printed with its kind.
    #[test]
    fn this_hosts_interfaces_read_as_their_kinds() {
        let links = links().unwrap();
        let base = |n: &str| n.trim_end_matches(|c: char| c.is_ascii_digit()).to_string();
        for l in &links {
            let want: Option<Option<&str>> = match base(&l.name).as_str() {
                "en" | "ap" | "awdl" | "llw" | "nan" | "anpi" | "lo" => Some(None),
                "bridge" => Some(Some("bridge")),
                "utun" => Some(Some("tun")),
                "gif" => Some(Some("gif")),
                "stf" => Some(Some("stf")),
                _ => None,
            };
            if let Some(want) = want {
                assert_eq!(l.kind.as_deref(), want, "{l:?}");
            }
            let physical = l.is_physical();
            assert_eq!(
                physical,
                matches!(l.kind.as_deref(), None | Some("bridge")),
                "{l:?}"
            );
            eprintln!(
                "{} (index {}): kind {:?}, physical {physical}",
                l.name, l.index, l.kind
            );
        }
        assert!(links.iter().any(|l| l.name == "lo0"));
    }

    /// This host's real table and kernel, read-only: the dump reads, the kernel answers every
    /// destination as the table says (public addresses take the default path, this host's own
    /// addresses deliver locally, on-link neighbours are on-link), and the interfaces read.
    #[test]
    fn this_hosts_kernel_answers_agree_with_its_table() {
        let (routes, rules) = dump().expect("the NET_RT_DUMP sysctl");
        let t = RouteTable::with_rules(routes, rules);
        let mut checked = 0;
        for v6 in [false, true] {
            let public = if v6 {
                ip("2606:4700:4700::1111")
            } else {
                ip("8.8.8.8")
            };
            let answer = query(public, Some(443)).expect("route query");
            if t.routes_family(v6) {
                assert!(
                    matches!(answer, KernelAnswer::Entry(_)),
                    "{public}: {answer:?}"
                );
                assert_eq!(t.judge_answer(&answer), Ok(()), "{public}: {answer:?}");
                assert_eq!(t.judge_answer(&query(public, None).unwrap()), Ok(()));
                assert_eq!(t.off_default_path(public), None);
                checked += 1;
            } else {
                assert!(t.judge_answer(&answer).is_err());
            }
        }
        for r in t.local_routes() {
            let a = r.prefix.addr;
            if r.kind != RouteType::Local
                || matches!(a, IpAddr::V6(v) if v.segments()[0] & 0xffc0 == 0xfe80)
            {
                continue;
            }
            let answer = query(a, Some(80)).unwrap();
            assert_eq!(
                t.judge_answer(&answer).map_err(|r| r.kind),
                Err(RouteKind::Local),
                "{a}: {answer:?}"
            );
            checked += 1;
        }
        for prefix in t.on_link_prefixes() {
            let width = if prefix.addr.is_ipv4() { 32 } else { 128 };
            if prefix.len + 3 > width
                || matches!(prefix.addr, IpAddr::V6(v) if v.segments()[0] & 0xffc0 == 0xfe80)
                || t.routes().iter().any(|r| r.prefix == prefix && r.loopback)
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
            let answer = query(n, Some(80)).unwrap();
            assert!(matches!(answer, KernelAnswer::Entry(_)), "{n}: {answer:?}");
            assert_eq!(
                t.judge_answer(&answer).map_err(|r| r.kind),
                Err(RouteKind::OnLink),
                "{n}: {answer:?}"
            );
            assert_eq!(
                t.off_default_path(n).map(|r| r.kind),
                Some(RouteKind::OnLink)
            );
            checked += 1;
        }
        eprintln!("{checked} kernel answers checked against the table");
        assert!(checked >= 2, "checked {checked}");
        let links = links().expect("getifaddrs");
        let lo = links.iter().find(|l| l.index == 1).expect("lo0");
        assert_eq!((lo.name.as_str(), lo.kind.as_deref()), ("lo0", None));
        for i in super::super::internet_interfaces() {
            assert!(links.iter().any(|l| l.index == i), "{i} in {links:?}");
        }
        assert!(nexthops().unwrap().is_empty());
    }

    /// This host's real sockets to public addresses of each family it routes leave by the
    /// interface the kernel's route names, and by no other (the check of [`decide`], on real
    /// answers).
    #[test]
    fn this_hosts_sockets_leave_by_the_routes_interface() {
        let (routes, rules) = dump().unwrap();
        let t = RouteTable::with_rules(routes, rules);
        let mut checked = 0;
        for d in [
            "8.8.8.8",
            "1.0.0.1",
            "2606:4700:4700::1111",
            "2001:4860:4860::8888",
        ] {
            let d = ip(d);
            if !t.routes_family(d.is_ipv6()) {
                crate::skipped(format!(
                    "{d}: no default route of its family ({})",
                    if d.is_ipv6() { "IPv6" } else { "IPv4" }
                ));
                continue;
            }
            let r = ask(d).unwrap().expect("a route");
            let s = socket_interfaces(d, Some(443)).unwrap().expect("a socket");
            assert_eq!(s, vec![r.ifindex], "{d}: {r:?}");
            // The connect may have made the kernel clone the route (a host route on the same
            // interface, through the same gateway) in between: the answer is still an entry there.
            let a = query(d, Some(443)).unwrap();
            assert!(
                matches!(&a, KernelAnswer::Entry(e) if e.iter().all(|e| e.ifindex == r.ifindex
                    && e.hop == r.hop)),
                "{d}: {a:?}"
            );
            assert_eq!(t.judge_answer(&a), Ok(()), "{d}: {a:?}");
            eprintln!("{d}: route and socket both on interface {}", r.ifindex);
            checked += 1;
        }
        assert!(checked >= 1, "no family routed");
    }

    /// The parser against `route -n get` (/sbin/route, unprivileged) for this host's own
    /// destinations, public ones, a LAN neighbour, a neighbour in a global on-link /64 and a
    /// link-local address: destination, mask (as the prefix length), gateway, interface and
    /// flags agree.
    #[test]
    fn this_hosts_answers_agree_with_route_get() {
        let (routes, _) = dump().unwrap();
        let gw = routes
            .iter()
            .find_map(|r| match (r.prefix.len, r.hop, r.table) {
                (0, Hop::Via(g @ IpAddr::V4(_)), RT_TABLE_MAIN) => Some(g),
                _ => None,
            });
        let mut dsts = vec![
            ip("1.0.0.1"),
            ip("8.8.4.4"),
            ip("127.0.0.1"),
            ip("::1"),
            ip("2606:4700:4700::1111"),
        ];
        dsts.extend(gw);
        // Neighbours: in the LAN that holds the IPv4 router, and in each global on-link /64 (review
        // round 1, cross-5); and link-local.
        let own: Vec<IpAddr> = address_interfaces()
            .unwrap()
            .into_iter()
            .map(|(a, _)| a)
            .collect();
        let mut neighbours = 0;
        for r in routes.iter().filter(|r| {
            r.hop == Hop::OnLink && r.kind == RouteType::Unicast && r.table == RT_TABLE_MAIN
        }) {
            let n = match r.prefix.addr {
                IpAddr::V4(a) if r.prefix.len <= 29 && gw.is_some_and(|g| r.holds(g)) => {
                    IpAddr::V4(Ipv4Addr::from(u32::from(a) | 0x4d))
                }
                IpAddr::V6(a) if r.prefix.len == 64 && crate::is_global(r.prefix.addr) => {
                    IpAddr::V6(Ipv6Addr::from(u128::from(a) | 0x5ee))
                }
                _ => continue,
            };
            if !own.contains(&n) && Some(n) != gw {
                dsts.push(n);
                neighbours += 1;
            }
        }
        if gw.is_some() {
            assert!(neighbours > 0, "no LAN neighbour in {routes:?}");
        }
        dsts.push(ip("fe80::1"));
        dsts.extend(
            address_interfaces()
                .unwrap()
                .into_iter()
                .map(|(a, _)| a)
                .filter(|a| !matches!(a, IpAddr::V6(v) if v.segments()[0] & 0xffc0 == 0xfe80)),
        );
        let names: Vec<(u32, String)> = links()
            .unwrap()
            .into_iter()
            .map(|l| (l.index, l.name))
            .collect();
        // One comparison; a clone the kernel makes in between (another test's connection to the
        // same destination) can change the answer, so a disagreement is asked again.
        let compare = |d: IpAddr| -> Result<String, String> {
            let family = if d.is_ipv4() { "-inet" } else { "-inet6" };
            // route(8) reads its routing socket until its own answer arrives, with no timeout;
            // a routing socket drops messages when its buffer is full, and then it waits for
            // ever. So it is given 5 s, and asked again (below) if killed.
            let mut child = std::process::Command::new("/sbin/route")
                .args(["-n", "get", family, &d.to_string()])
                .stdout(std::process::Stdio::piped())
                .spawn()
                .expect("route -n get");
            let started = Instant::now();
            while child.try_wait().unwrap().is_none() {
                if started.elapsed() > Duration::from_secs(5) {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(format!("{d}: route -n get did not answer in 5 s"));
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            let out = child.wait_with_output().unwrap();
            let text = String::from_utf8_lossy(&out.stdout).into_owned();
            let field = |k: &str| {
                text.lines()
                    .find_map(|l| l.trim().strip_prefix(&format!("{k}: ")))
                    .map(str::to_string)
            };
            let check = |ok: bool, what: &str| {
                if ok {
                    Ok(())
                } else {
                    Err(format!("{d}: {what} differs from route -n get: {text}"))
                }
            };
            let Some(r) = ask(d).unwrap() else {
                check(field("interface").is_none(), "no route")?;
                return Ok(format!("{d}: no route, as route -n get says"));
            };
            let iface = names.iter().find(|(i, _)| *i == r.ifindex).map(|(_, n)| n);
            check(field("interface").as_ref() == iface, "the interface")?;
            let flags = field("flags").unwrap_or_default();
            check(
                flags.contains("LOCAL") == (r.kind == RouteType::Local),
                "LOCAL",
            )?;
            check(
                flags.contains("GATEWAY") == matches!(r.hop, Hop::Via(_)),
                "GATEWAY",
            )?;
            check(
                flags.contains("IFSCOPE") == (r.table != RT_TABLE_MAIN),
                "IFSCOPE",
            )?;
            if let (Hop::Via(g), Some(shown)) = (r.hop, field("gateway")) {
                let shown: IpAddr = shown.split('%').next().unwrap().parse().unwrap();
                check(g == shown, "the gateway")?;
            }
            let dest = field("destination").unwrap_or_default();
            let dest: IpAddr = if dest == "default" {
                if d.is_ipv4() {
                    Ipv4Addr::UNSPECIFIED.into()
                } else {
                    Ipv6Addr::UNSPECIFIED.into()
                }
            } else {
                dest.split('%').next().unwrap().parse().unwrap()
            };
            check(r.prefix.addr == dest, "the destination")?;
            // The mask: none shown for a host route, `default` for a zero-length one.
            let width = if d.is_ipv4() { 32 } else { 128 };
            let shown_len = match field("mask").as_deref() {
                None => width,
                Some("default") => 0,
                Some(m) => match m.parse::<IpAddr>() {
                    Ok(IpAddr::V4(m)) => u32::from(m).leading_ones() as u8,
                    Ok(IpAddr::V6(m)) => u128::from(m).leading_ones() as u8,
                    Err(_) => return Err(format!("{d}: an unreadable mask in {text}")),
                },
            };
            check(r.prefix.len == shown_len, "the mask")?;
            Ok(format!("{d}: {r:?} agrees with route -n get"))
        };
        for d in dsts {
            let mut last = Err(String::new());
            for _ in 0..3 {
                last = compare(d);
                if last.is_ok() {
                    break;
                }
            }
            eprintln!("{}", last.unwrap_or_else(|e| panic!("{e}")));
        }
    }

    /// What an unprivileged process can make another routing socket receive with this process's
    /// pid and a query's sequence number (review round 2, parse-1; `fix-r2/forge-variants.log`
    /// has what xnu delivers for each write): the kernel's own answer to a query with another
    /// destination (the captured default route), written back by a forger with its length off by
    /// some bytes either way, its `rtm_msglen` 0, as an 8-byte stub, with another version, or as
    /// another message type (refused with `EPERM` before the kernel sets `rtm_pid`, so delivered
    /// with the forger's pid and `rtm_errno` set, or as written).
    fn forged_datagrams(pid: i32, seq: i32) -> Vec<(&'static str, Vec<u8>)> {
        let (_, mut b) = reply("8.8.4.4");
        let put = |m: &mut Vec<u8>, o: usize, v: &[u8]| m[o..o + v.len()].copy_from_slice(v);
        put(
            &mut b,
            offset_of!(libc::rt_msghdr, rtm_pid),
            &pid.to_ne_bytes(),
        );
        put(
            &mut b,
            offset_of!(libc::rt_msghdr, rtm_seq),
            &seq.to_ne_bytes(),
        );
        let len = b.len();
        let with_len = |m: &[u8], l: usize| {
            let mut m = m.to_vec();
            m[0..2].copy_from_slice(&(l as u16).to_ne_bytes());
            m
        };
        let mut out = vec![
            ("4 bytes past its length", [b.clone(), vec![0; 4]].concat()),
            (
                "163 bytes past its length",
                [b.clone(), vec![0; 163]].concat(),
            ),
            ("cut 40 bytes short", with_len(&b[..len - 40], len)),
            ("a length 40 bytes past", with_len(&b, len + 40)),
            ("rtm_msglen 0", with_len(&b, 0)),
            ("a header alone", with_len(&b[..HDR_LEN], len)),
            ("an 8-byte stub", vec![8, 0, 5, 4, 0, 0, 0, 0]),
        ];
        for (what, at, v) in [
            ("version 4", 2, 4u8),
            ("version 6", 2, 6),
            ("type RTM_ADD", 3, libc::RTM_ADD as u8),
            ("type RTM_CHANGE", 3, libc::RTM_CHANGE as u8),
            ("type 0x55", 3, 0x55),
            ("type RTM_GET_SILENT", 3, RTM_GET_SILENT),
        ] {
            let mut m = b.clone();
            m[at] = v;
            out.push((what, m.clone()));
            let mut refused = m;
            put(
                &mut refused,
                offset_of!(libc::rt_msghdr, rtm_errno),
                &libc::EPERM.to_ne_bytes(),
            );
            out.push((what, refused));
        }
        out
    }

    /// parse-1 and parse-2: no datagram a forger can have delivered is taken as the answer, nor
    /// fails the query: only the kernel's own answer, exactly as it wrote it, is.
    #[test]
    fn forged_and_refused_writes_are_no_answer() {
        let (pid, seq) = (4242, 77);
        for dst in ["192.168.1.50", "127.0.0.1", "10.0.0.1", "2001:db8::1"] {
            for (what, m) in forged_datagrams(pid, seq) {
                let r = parse_answer(&m, pid, seq, ip(dst));
                assert!(matches!(r, Ok(None)), "{dst}: {what}: {r:?}");
            }
        }
        // The reviewer's forgery (r2-parse/repro/review_r2.rs): a default route via
        // 192.168.1.1 on index 8 in a 132-byte write of a 128-byte message.
        let mut f = vec![0u8; 132];
        let put = |f: &mut Vec<u8>, o: usize, v: &[u8]| f[o..o + v.len()].copy_from_slice(v);
        put(&mut f, 0, &128u16.to_ne_bytes());
        f[2] = libc::RTM_VERSION as u8;
        f[3] = libc::RTM_GET as u8;
        put(
            &mut f,
            offset_of!(libc::rt_msghdr, rtm_index),
            &8u16.to_ne_bytes(),
        );
        put(
            &mut f,
            offset_of!(libc::rt_msghdr, rtm_flags),
            &(libc::RTF_UP | libc::RTF_GATEWAY).to_ne_bytes(),
        );
        put(
            &mut f,
            offset_of!(libc::rt_msghdr, rtm_addrs),
            &(libc::RTA_DST | libc::RTA_GATEWAY | libc::RTA_NETMASK).to_ne_bytes(),
        );
        put(
            &mut f,
            offset_of!(libc::rt_msghdr, rtm_pid),
            &pid.to_ne_bytes(),
        );
        put(
            &mut f,
            offset_of!(libc::rt_msghdr, rtm_seq),
            &seq.to_ne_bytes(),
        );
        f[92] = 16;
        f[93] = libc::AF_INET as u8;
        f[108] = 16;
        f[109] = libc::AF_INET as u8;
        f[112..116].copy_from_slice(&[192, 168, 1, 1]);
        assert!(matches!(
            parse_answer(&f, pid, seq, ip("192.168.1.50")),
            Ok(None)
        ));
        // Written at its own length, that message is a query the kernel answers with the
        // writer's pid; were it delivered with this process's pid, it would be read (and judged).
        assert!(parse_answer(&f[..128], pid, seq, ip("192.168.1.50"))
            .unwrap()
            .is_some());
        // The kernel's answer itself is taken.
        let (d, b) = reply("8.8.4.4");
        let h = header(&b).unwrap();
        assert!(parse_answer(&b, h.pid, h.seq, d)
            .unwrap()
            .unwrap()
            .is_some());
    }

    /// The forger [`forged_answers_are_never_taken`] runs in a child process (`ZKMINER_TEST_FORGE
    /// = "<pid> <seq> <seconds>"`): it writes every kind of [`forged_datagrams`] with that pid and
    /// sequence number, as fast as it can, and watches for answers with that pid to forge the
    /// next sequence numbers too. Does nothing without the variable.
    #[test]
    #[ignore = "the child process of forged_answers_are_never_taken"]
    fn route_forger() {
        let Some(arg) = std::env::var_os("ZKMINER_TEST_FORGE") else {
            return;
        };
        let arg = arg.into_string().unwrap();
        let v: Vec<i64> = arg.split(' ').map(|w| w.parse().unwrap()).collect();
        let (pid, seq, secs) = (v[0] as i32, v[1] as i32, v[2] as u64);
        let sock = route_socket().unwrap();
        // SAFETY: F_SETFL on a valid fd.
        unsafe { libc::fcntl(sock.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) };
        let mut forged = forged_datagrams(pid, seq);
        // Written at their own length, as a query: the kernel answers with this process's pid.
        forged.push(("an exact-length answer", reply("8.8.4.4").1));
        let end = Instant::now() + Duration::from_secs(secs);
        let (mut written, mut seen) = (0u64, 0u64);
        let mut buf = vec![0u8; RECV_BUF];
        while Instant::now() < end {
            loop {
                // SAFETY: `buf` is valid for its length.
                let n =
                    unsafe { libc::recv(sock.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), 0) };
                if n <= 0 {
                    break;
                }
                if let Ok(h) = header(&buf[..n as usize]) {
                    if h.pid == pid
                        && h.len == n as usize
                        && i32::from(h.ty) == libc::RTM_GET
                        && i32::from(h.version) == libc::RTM_VERSION
                    {
                        seen += 1;
                        for next in [h.seq, h.seq.wrapping_add(1)] {
                            forged.extend(forged_datagrams(pid, next));
                        }
                        forged.truncate(200);
                    }
                }
            }
            for (_, m) in &forged {
                // SAFETY: `m` is valid for its length.
                unsafe { libc::write(sock.as_raw_fd(), m.as_ptr().cast(), m.len()) };
                written += 1;
            }
        }
        eprintln!("forger: {written} writes; {seen} answers to pid {pid} seen");
    }

    /// parse-1, live: while another process writes every forged kind of answer with this
    /// process's pid and the query's own sequence number (fixed here, as if guessed), and with
    /// the next sequence numbers of any answer it sees, no forged answer is ever taken: every
    /// query for 127.0.0.1 is answered with its local route on lo0 (or fails), never the forged
    /// default route. The forger is effective: this process's routing socket receives its
    /// datagrams with this pid and sequence number.
    ///
    /// Ignored by default: the flood reaches every routing socket on the host, and a socket
    /// whose buffer it fills loses messages (`route -n get` in a test running alongside waited
    /// for its lost answer for ever). Run on its own: `cargo test -p zkminer-netguard --lib
    /// forged_answers_are_never_taken -- --ignored`.
    #[test]
    #[ignore = "floods every routing socket on the host; run on its own"]
    fn forged_answers_are_never_taken() {
        let dst = ip("127.0.0.1");
        let real = ask(dst).unwrap().unwrap();
        assert_eq!(
            (real.kind, real.prefix),
            (RouteType::Local, Prefix::host(dst))
        );
        // SAFETY: getpid cannot fail.
        let pid = unsafe { libc::getpid() };
        let seq = next_seq();
        let watch = route_socket().unwrap();
        // SAFETY: F_SETFL on a valid fd.
        unsafe { libc::fcntl(watch.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) };
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "routes::sys::tests::route_forger",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("ZKMINER_TEST_FORGE", format!("{pid} {seq} 4"))
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap();
        std::thread::sleep(Duration::from_millis(300));
        let (mut answered, mut failed, mut forged_seen) = (0u32, 0u32, 0u64);
        let mut last_err = String::new();
        let end = Instant::now() + Duration::from_secs(3);
        let mut buf = vec![0u8; RECV_BUF];
        let mut i = 0u32;
        while Instant::now() < end {
            i += 1;
            let r = if i.is_multiple_of(2) {
                ask_as(dst, seq)
            } else {
                ask(dst)
            };
            match r {
                Ok(Some(r)) => {
                    assert_eq!(
                        (r.kind, r.prefix, r.ifindex),
                        (real.kind, real.prefix, real.ifindex),
                        "a forged answer was taken: {r:?}"
                    );
                    answered += 1;
                }
                Ok(None) => panic!("no route to 127.0.0.1: a forged ESRCH was taken"),
                Err(e) => {
                    failed += 1;
                    last_err = e.to_string();
                }
            }
            loop {
                // SAFETY: `buf` is valid for its length.
                let n =
                    unsafe { libc::recv(watch.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), 0) };
                if n <= 0 {
                    break;
                }
                if let Ok(h) = header(&buf[..n as usize]) {
                    forged_seen += u64::from(h.pid == pid && h.seq == seq);
                }
            }
        }
        assert!(child.wait().unwrap().success());
        eprintln!(
            "{answered} queries answered by the kernel, {failed} failed (last: {last_err}); \
             {forged_seen} forged datagrams with this pid and sequence number seen"
        );
        assert!(
            forged_seen > 1000,
            "the forger was not effective: {forged_seen}"
        );
        assert!(answered > 100, "{answered} answered, {failed} failed");
    }

    /// cross-2: the destination port reaches the socket check (a Network Extension policy may
    /// select by port), and the socket is connected to that port (443 when none is given).
    #[test]
    fn the_destination_port_reaches_the_socket_check() {
        let r = answer("8.8.4.4").unwrap();
        for port in [Some(8443), Some(53), None] {
            let mut asked = None;
            let a = query_with(
                ip("8.8.4.4"),
                port,
                |d| {
                    assert_eq!(d, ip("8.8.4.4"));
                    Ok(Some(r))
                },
                |d, p| {
                    asked = Some((d, p));
                    Ok(Some(vec![8]))
                },
            )
            .unwrap();
            assert_eq!(a, KernelAnswer::Entry(vec![r]));
            assert_eq!(asked, Some((ip("8.8.4.4"), port)));
        }
        for (port, want) in [(Some(8443), 8443), (None, 443)] {
            if let Some(s) = udp_toward(ip("127.0.0.1"), port).unwrap() {
                assert_eq!(s.peer_addr().unwrap().port(), want);
            }
        }
    }

    /// cross-2 (M16): a plain clone in the dump (`RTF_WASCLONED`: an ARP entry, a per-destination
    /// copy of its parent route) is not read, as Linux skips `RTM_F_CLONED`; one a redirect
    /// changed (`RTF_DYNAMIC`, `RTF_MODIFIED`) or that delivers locally is.
    #[test]
    fn plain_clones_in_the_dump_are_not_read() {
        // The captured default route's message, made a host route for 10.99.0.1 through
        // 192.0.2.99 (no uplink), with `flags`.
        let clone = |flags: i32| {
            let (_, mut m) = reply("8.8.4.4");
            let h = header(&m).unwrap();
            let o = offset_of!(libc::rt_msghdr, rtm_flags);
            m[o..o + 4].copy_from_slice(&flags.to_ne_bytes());
            let a = offset_of!(libc::sockaddr_in, sin_addr);
            let (dst, gw) = {
                let sas = sockaddrs(&m[HDR_LEN..h.len], h.addrs).unwrap();
                let at = |i: usize| sas[i].unwrap().as_ptr() as usize - m.as_ptr() as usize;
                (at(libc::RTAX_DST as usize), at(libc::RTAX_GATEWAY as usize))
            };
            m[dst + a..dst + a + 4].copy_from_slice(&[10, 99, 0, 1]);
            m[gw + a..gw + a + 4].copy_from_slice(&[192, 0, 2, 99]);
            m
        };
        let base = libc::RTF_UP | libc::RTF_GATEWAY | libc::RTF_HOST | libc::RTF_WASCLONED;
        let host = Prefix::host(ip("10.99.0.1"));
        for (extra, kept) in [
            (0, false),
            (libc::RTF_DYNAMIC, true),
            (libc::RTF_MODIFIED, true),
            (libc::RTF_LOCAL, true),
        ] {
            let mut dump = dump_fixture();
            let n = parse_dump(&dump).unwrap().len();
            dump.extend(clone(base | extra));
            let routes = parse_dump(&dump).unwrap();
            let found = routes.iter().any(|r| r.prefix == host);
            assert_eq!(found, kept, "flags {:#x}", base | extra);
            assert_eq!(routes.len(), n + usize::from(kept));
            let t = RouteTable::with_rules(
                routes,
                vec![
                    Rule::lookup(false, RT_TABLE_MAIN),
                    Rule::lookup(true, RT_TABLE_MAIN),
                ],
            );
            assert_eq!(
                t.off_default_path(ip("10.99.0.1")).is_some(),
                kept,
                "flags {:#x}",
                base | extra
            );
        }
        // The same clone, asked for (an answer, not the dump), is read.
        let m = clone(base);
        let h = header(&m).unwrap();
        let r = parse_answer(&m, h.pid, h.seq, ip("10.99.0.1"))
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!((r.prefix, r.hop), (host, Hop::Via(ip("192.0.2.99"))));
    }
}
