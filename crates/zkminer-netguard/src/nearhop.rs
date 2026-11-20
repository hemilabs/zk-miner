//! The near-hop refusal: before every connection made under the floor in public mode, a probe
//! asks whether the destination answers within a few hops of this host, and a destination that
//! does is refused.
//!
//! Some destinations pass every address and route check and are still the operator's own
//! network: the home router's own global address (its WAN side, reached through the default
//! route like the internet, and on many routers zoned by input interface, so the LAN reaches its
//! admin page, DNS and UPnP on it), a NAT64 translator or NAT router that hairpins its own public
//! address, a cloud VPC neighbour or a campus host reached through the default gateway, the far
//! side of a tunnel. They have in common that they are near. So each connection is preceded by a
//! probe ([`TtlProbe`]): a fresh TCP socket whose packets may cross at most `[egress]
//! near_hop_limit` hops (`IP_TTL` / `IPV6_UNICAST_HOPS`, default 2: the first-hop router and what
//! sits directly behind it), connecting to the exact destination address and port, for at most
//! [`PROBE_TIMEOUT`]:
//!
//! - **connected**, or **refused** / **reset** (`ECONNREFUSED`, `ECONNRESET`): something within
//!   that many hops answered for the destination: refused ([`crate::Denied::NearHop`]);
//! - **host or network unreachable** (`EHOSTUNREACH`, `ENETUNREACH`: on Linux, how an ICMP "time
//!   exceeded" from the router where the probe ran out of hops ends a connect; on macOS too, as
//!   long as `net.inet.tcp.icmp_may_rst` is 1, its default, which drops a connection still in
//!   `SYN_SENT` on such an ICMP error): the destination is farther: the real connection is made,
//!   on a new socket with the default hop limit;
//! - **no answer in time**: no evidence either way (a path that filters ICMP, or a near host that
//!   drops SYNs for a while: a full accept queue, a SYN rate limit, a neighbour being resolved, a
//!   device waking up). So the destination is **checked once connected**
//!   ([`NearProbe::confirm`]): a check connection is made with the default hop limit (no data is
//!   ever written on it), and once it is established its hop limit is lowered to the probe's and
//!   it is half-closed: the FIN can reach the peer only if the peer is within the limit, and a
//!   peer that gets it acknowledges it. Acknowledged (or answered with a reset) within a few round
//!   trips: near, refused. Unacknowledged: far, and the real connection is made. The check
//!   connection failing to connect refuses too (the real one would fail the same way). Linux reads
//!   the FIN's fate from `TCP_INFO`, macOS from `TCP_CONNECTION_INFO`; elsewhere there is no check
//!   connection, and a probe without an answer refuses;
//! - **any other error** (a local firewall's `EPERM`/`EACCES`, `EADDRNOTAVAIL`, …): refused.
//!
//! The probe is closed without sending data (a reset if it connected). Unprivileged.
//!
//! **macOS.** A process that Local Network privacy has not been granted to gets `EHOSTUNREACH` at
//! once for a connection into a directly attached network, before any packet is sent (as does a
//! connection a Network Extension policy denies). The probe reads an unreachable that `connect`
//! itself reports, before the connection was in progress, as a failure (refused), not as far: no
//! packet was answered, so it says nothing of the distance. (An ICMP "time exceeded" can only
//! arrive after `connect` has returned `EINPROGRESS`; on this Mac every real one did, 2 ms or more
//! later, and every Local Network denial came from `connect` itself, in under 0.4 ms: see
//! docs/netguard-macos.md.) Such destinations are on-link, refused by the address and route
//! checks before any probe anyway, and the real connection would fail the same way.
//!
//! **What it cannot help:** a probe that connects, and a check connection, still reach a near
//! host (a SYN, a handshake, a FIN, a reset; never data) before the refusal; a near host that
//! drops the probe and also drops the check connection's FIN reads as far; a transparent proxy
//! within the limit answers for every destination, so every connection through it is refused; a
//! router that decrements no hop count is invisible to it.

use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::time::Duration;

/// How long a probe waits for an answer before it counts as no answer.
pub const PROBE_TIMEOUT: Duration = Duration::from_millis(1500);

/// How long the check connection ([`NearProbe::confirm`]) may take to connect.
pub const CONFIRM_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// How a probe ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeOutcome {
    /// The connection was established within the hop limit.
    Connected,
    /// `ECONNREFUSED`: something within the hop limit answered with a reset (or a port
    /// unreachable).
    Refused,
    /// `ECONNRESET`.
    Reset,
    /// `EHOSTUNREACH` / `ENETUNREACH`: the probe ran out of hops (an ICMP "time exceeded"), or
    /// nothing routes there.
    Unreachable,
    /// No answer within the probe's time.
    TimedOut,
    /// Any other error: what it was.
    Failed(String),
}

/// How the check connection ([`NearProbe::confirm`]) ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfirmOutcome {
    /// The peer acknowledged (or reset on) the hop-limited FIN: it is within the limit.
    Answered,
    /// Nothing answered the hop-limited FIN: the peer is farther.
    Unanswered,
    /// The check connection did not connect: why.
    ConnectFailed(String),
    /// Anything else went wrong: what.
    Failed(String),
}

/// What a probe's outcome means for the connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Farther than the hop limit: connect.
    Far,
    /// Answered within the hop limit (how): refuse.
    Near(&'static str),
    /// No answer to the probe: check once connected ([`NearProbe::confirm`]).
    Undecided,
    /// The probe failed (why): refuse.
    Failed(String),
}

impl ProbeOutcome {
    /// The outcome of a probe's connect.
    pub fn of(r: io::Result<()>) -> Self {
        match r {
            Ok(()) => ProbeOutcome::Connected,
            Err(e) => match e.raw_os_error() {
                #[cfg(unix)]
                Some(libc::ECONNREFUSED) => ProbeOutcome::Refused,
                #[cfg(unix)]
                Some(libc::ECONNRESET) => ProbeOutcome::Reset,
                #[cfg(unix)]
                Some(libc::EHOSTUNREACH) | Some(libc::ENETUNREACH) => ProbeOutcome::Unreachable,
                #[cfg(unix)]
                Some(libc::ETIMEDOUT) => ProbeOutcome::TimedOut,
                _ => match e.kind() {
                    io::ErrorKind::TimedOut => ProbeOutcome::TimedOut,
                    io::ErrorKind::ConnectionRefused => ProbeOutcome::Refused,
                    io::ErrorKind::ConnectionReset => ProbeOutcome::Reset,
                    io::ErrorKind::HostUnreachable | io::ErrorKind::NetworkUnreachable => {
                        ProbeOutcome::Unreachable
                    }
                    _ => ProbeOutcome::Failed(e.to_string()),
                },
            },
        }
    }

    /// What it means on its own (see the module doc): a timeout decides nothing.
    pub fn verdict(&self) -> Verdict {
        match self {
            ProbeOutcome::Connected => Verdict::Near("accepted a connection"),
            ProbeOutcome::Refused => Verdict::Near("refused a connection"),
            ProbeOutcome::Reset => Verdict::Near("reset a connection"),
            ProbeOutcome::Unreachable => Verdict::Far,
            ProbeOutcome::TimedOut => Verdict::Undecided,
            ProbeOutcome::Failed(why) => Verdict::Failed(crate::printable(why, 120)),
        }
    }
}

impl ConfirmOutcome {
    /// What it means for a destination the probe could not decide.
    pub fn verdict(&self) -> Verdict {
        match self {
            ConfirmOutcome::Answered => {
                Verdict::Near("answered once connected (it had not answered the probe)")
            }
            ConfirmOutcome::Unanswered => Verdict::Far,
            ConfirmOutcome::ConnectFailed(why) => Verdict::Failed(format!(
                "the probe had no answer and a check connection did not connect: {}",
                crate::printable(why, 120)
            )),
            ConfirmOutcome::Failed(why) => Verdict::Failed(crate::printable(why, 120)),
        }
    }
}

/// Sends the probe ([`TtlProbe`] for real; a fake in tests, where a loopback server stands in for
/// a public address).
pub trait NearProbe: Send + Sync + fmt::Debug {
    /// Connects to `addr` with packets that may cross at most `hops` hops, for at most `timeout`.
    /// Blocking.
    fn probe(&self, addr: SocketAddr, hops: u8, timeout: Duration) -> ProbeOutcome;

    /// For a destination the probe had no answer from: connects to `addr` with the default hop
    /// limit (within `timeout`), then lowers the hop limit to `hops` and half-closes, and sees
    /// whether the FIN is answered (see the module doc). Writes no data. Blocking.
    fn confirm(&self, addr: SocketAddr, hops: u8, timeout: Duration) -> ConfirmOutcome;
}

/// The near-hop decision for a connection to `addr` (see the module doc): the probe, and when it
/// had no answer, the check connection. Blocking (up to [`PROBE_TIMEOUT`], plus
/// [`CONFIRM_CONNECT_TIMEOUT`] and a few round trips when the probe had no answer).
pub fn decide(probe: &dyn NearProbe, addr: SocketAddr, hops: u8) -> Verdict {
    match probe.probe(addr, hops, PROBE_TIMEOUT).verdict() {
        Verdict::Undecided => match probe.confirm(addr, hops, CONFIRM_CONNECT_TIMEOUT).verdict() {
            // Never undecided twice.
            Verdict::Undecided => Verdict::Failed("no answer either way".into()),
            v => v,
        },
        v => v,
    }
}

/// The real probe: a fresh TCP socket with its hop limit set, connected without sending data.
#[derive(Debug, Clone, Copy, Default)]
pub struct TtlProbe;

impl NearProbe for TtlProbe {
    fn probe(&self, addr: SocketAddr, hops: u8, timeout: Duration) -> ProbeOutcome {
        ProbeOutcome::of(probe_once(addr, hops, timeout))
    }

    fn confirm(&self, addr: SocketAddr, hops: u8, timeout: Duration) -> ConfirmOutcome {
        confirm_once(addr, hops, timeout)
    }
}

/// A probe that answers the same every time, and records what it was asked: for tests, where a
/// server on loopback stands in for a public address (the real probe would find it near), or
/// where a near destination is staged. Test builds only (the `test-util` feature).
#[cfg(any(test, feature = "test-util"))]
#[derive(Debug)]
pub struct FixedProbe {
    pub outcome: ProbeOutcome,
    /// What the check connection finds, when the probe times out.
    pub confirmed: ConfirmOutcome,
    pub asked: std::sync::Mutex<Vec<(SocketAddr, u8)>>,
    /// The check connections asked for.
    pub confirms: std::sync::Mutex<Vec<(SocketAddr, u8)>>,
}

#[cfg(any(test, feature = "test-util"))]
impl FixedProbe {
    /// A probe that always finds the destination far (it runs out of hops).
    pub fn far() -> std::sync::Arc<Self> {
        Self::answering(ProbeOutcome::Unreachable)
    }

    /// A probe that always ends with `outcome` (and, if that is a timeout, whose check
    /// connection finds nothing).
    pub fn answering(outcome: ProbeOutcome) -> std::sync::Arc<Self> {
        Self::with(outcome, ConfirmOutcome::Unanswered)
    }

    /// A probe that ends with `outcome`, and whose check connection ends with `confirmed`.
    pub fn with(outcome: ProbeOutcome, confirmed: ConfirmOutcome) -> std::sync::Arc<Self> {
        std::sync::Arc::new(FixedProbe {
            outcome,
            confirmed,
            asked: std::sync::Mutex::new(Vec::new()),
            confirms: std::sync::Mutex::new(Vec::new()),
        })
    }
}

#[cfg(any(test, feature = "test-util"))]
impl NearProbe for FixedProbe {
    fn probe(&self, addr: SocketAddr, hops: u8, _: Duration) -> ProbeOutcome {
        self.asked
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push((addr, hops));
        self.outcome.clone()
    }

    fn confirm(&self, addr: SocketAddr, hops: u8, _: Duration) -> ConfirmOutcome {
        self.confirms
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push((addr, hops));
        self.confirmed.clone()
    }
}

fn new_socket(addr: SocketAddr) -> io::Result<socket2::Socket> {
    use socket2::{Domain, Protocol, Socket, Type};
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    Socket::new(domain, Type::STREAM, Some(Protocol::TCP))
}

fn set_hops(sock: &socket2::Socket, addr: SocketAddr, hops: u8) -> io::Result<()> {
    if addr.is_ipv4() {
        sock.set_ttl_v4(u32::from(hops))
    } else {
        sock.set_unicast_hops_v6(u32::from(hops))
    }
}

#[cfg(not(target_os = "macos"))]
fn probe_once(addr: SocketAddr, hops: u8, timeout: Duration) -> io::Result<()> {
    let sock = new_socket(addr)?;
    set_hops(&sock, addr, hops)?;
    let r = sock.connect_timeout(&addr.into(), timeout);
    // Closed with a reset, never a byte of data.
    let _ = sock.set_linger(Some(Duration::ZERO));
    drop(sock);
    r
}

/// macOS: the probe as elsewhere (`socket2::Socket::connect_timeout`'s steps), except that an
/// unreachable `connect` reports at once, before the connection is in progress, is a failure (see
/// the module doc).
#[cfg(target_os = "macos")]
fn probe_once(addr: SocketAddr, hops: u8, timeout: Duration) -> io::Result<()> {
    let addr = unmapped(addr);
    let sock = new_socket(addr)?;
    set_hops(&sock, addr, hops)?;
    sock.set_nonblocking(true)?;
    let r = match sock.connect(&addr.into()) {
        Ok(()) => Ok(()),
        Err(e) if e.raw_os_error() == Some(libc::EINPROGRESS) => poll_connected(&sock, timeout),
        Err(e) => Err(unreachable_at_once(e)),
    };
    // Closed with a reset, never a byte of data.
    let _ = sock.set_linger(Some(Duration::ZERO));
    drop(sock);
    r
}

/// macOS: an IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) as its IPv4 address, which is what a
/// connection to it reaches. An IPv6 socket connected to a mapped address sends IPv4 packets, and
/// `IPV6_UNICAST_HOPS` does not limit them (they leave with the default TTL, so the probe of a
/// far host connects and reads it as near: `r2-probe/mapped.log`); an IPv4 socket with `IP_TTL`
/// set limits them. Review round 2, probe-2 ([`crate::NetPolicy::vet_connection`] already
/// unmaps before it asks; the probe and the check connection no longer rely on it).
#[cfg(target_os = "macos")]
fn unmapped(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V6(a) => match a.ip().to_ipv4_mapped() {
            Some(v4) => SocketAddr::new(std::net::IpAddr::V4(v4), a.port()),
            None => addr,
        },
        v4 => v4,
    }
}

/// macOS: an error `connect` reported before the connection was in progress. An unreachable
/// (Local Network privacy, a Network Extension policy, no route) becomes a failure the probe does
/// not read as "farther"; any other error is left as it is.
#[cfg(target_os = "macos")]
fn unreachable_at_once(e: io::Error) -> io::Error {
    match e.raw_os_error() {
        Some(libc::EHOSTUNREACH) | Some(libc::ENETUNREACH) => io::Error::other(format!(
            "{e}, before any packet was answered (Local Network privacy, a Network Extension \
             policy, or no route)"
        )),
        _ => e,
    }
}

/// macOS: waits for a non-blocking connect in progress, as `socket2::Socket::connect_timeout`
/// does: connected, its error, or `TimedOut`.
#[cfg(target_os = "macos")]
fn poll_connected(sock: &socket2::Socket, timeout: Duration) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    let start = std::time::Instant::now();
    let mut p = libc::pollfd {
        fd: sock.as_raw_fd(),
        events: libc::POLLIN | libc::POLLOUT,
        revents: 0,
    };
    loop {
        let elapsed = start.elapsed();
        if elapsed >= timeout {
            return Err(io::ErrorKind::TimedOut.into());
        }
        let ms = (timeout - elapsed).as_millis().clamp(1, i32::MAX as u128) as libc::c_int;
        // SAFETY: `p` is one valid pollfd.
        match unsafe { libc::poll(&mut p, 1, ms) } {
            0 => return Err(io::ErrorKind::TimedOut.into()),
            n if n > 0 => {
                if p.revents & (libc::POLLHUP | libc::POLLERR) != 0 {
                    return match sock.take_error() {
                        Ok(Some(e)) | Err(e) => Err(e),
                        Ok(None) => Err(io::Error::other("no error set after POLLHUP")),
                    };
                }
                return match sock.take_error()? {
                    Some(e) => Err(e),
                    None => Ok(()),
                };
            }
            _ => {
                let e = io::Error::last_os_error();
                if e.kind() != io::ErrorKind::Interrupted {
                    return Err(e);
                }
            }
        }
    }
}

/// The check connection (see the module doc). Linux: the FIN's fate is read from `TCP_INFO`.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn confirm_once(addr: SocketAddr, hops: u8, timeout: Duration) -> ConfirmOutcome {
    use std::os::fd::AsRawFd;
    let sock = match new_socket(addr) {
        Ok(s) => s,
        Err(e) => return ConfirmOutcome::Failed(e.to_string()),
    };
    if let Err(e) = sock.connect_timeout(&addr.into(), timeout) {
        return ConfirmOutcome::ConnectFailed(e.to_string());
    }
    // From here on every packet of this socket — the FIN, its retransmissions, the closing
    // reset — may cross at most `hops` hops.
    let _ = sock.set_linger(Some(Duration::ZERO));
    if let Err(e) = set_hops(&sock, addr, hops) {
        return ConfirmOutcome::Failed(e.to_string());
    }
    let info = |fd: i32| -> io::Result<libc::tcp_info> {
        // SAFETY: a zeroed tcp_info is valid to be overwritten by getsockopt.
        let mut i: libc::tcp_info = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of::<libc::tcp_info>() as libc::socklen_t;
        // SAFETY: `i` and `len` are valid for the size given.
        let rc = unsafe {
            libc::getsockopt(
                fd,
                libc::IPPROTO_TCP,
                libc::TCP_INFO,
                (&mut i as *mut libc::tcp_info).cast(),
                &mut len,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(i)
    };
    let fd = sock.as_raw_fd();
    let rtt = match info(fd) {
        Ok(i) => Duration::from_micros(u64::from(i.tcpi_rtt)),
        Err(e) => return ConfirmOutcome::Failed(e.to_string()),
    };
    if let Err(e) = sock.shutdown(std::net::Shutdown::Write) {
        return ConfirmOutcome::Failed(e.to_string());
    }
    // A peer within the limit acknowledges the FIN within about a round trip (a delayed ACK at
    // most a couple of hundred milliseconds later).
    let wait = (rtt * 4 + Duration::from_millis(250))
        .clamp(Duration::from_millis(300), Duration::from_millis(1500));
    let deadline = std::time::Instant::now() + wait;
    const TCP_FIN_WAIT1: u8 = 4;
    loop {
        match info(fd) {
            // FIN_WAIT2, CLOSING, TIME_WAIT, CLOSE: the FIN was acknowledged, or the peer reset.
            Ok(i) if i.tcpi_state != TCP_FIN_WAIT1 => return ConfirmOutcome::Answered,
            Ok(_) => {}
            Err(e) => return ConfirmOutcome::Failed(e.to_string()),
        }
        // An ICMP "time exceeded" for the FIN shows as a soft error (`SO_ERROR` reports it):
        // positive evidence that the peer is farther. A reset shows in the state above.
        if let Ok(Some(e)) = sock.take_error() {
            if matches!(
                e.raw_os_error(),
                Some(libc::EHOSTUNREACH) | Some(libc::ENETUNREACH)
            ) {
                return ConfirmOutcome::Unanswered;
            }
        }
        if std::time::Instant::now() >= deadline {
            return ConfirmOutcome::Unanswered;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// The check connection (see the module doc). macOS: the FIN's fate is read from
/// `TCP_CONNECTION_INFO` (<netinet/tcp.h>, the public counterpart of Linux's `TCP_INFO`; its
/// states are <netinet/tcp_fsm.h>'s), as [`fin_step`] and [`fin_at_deadline`] read it. macOS
/// keeps an ICMP "time exceeded" for the FIN as a soft error it never reports (`SO_ERROR` stays
/// 0), so a far peer is found only by the deadline passing: the same verdict as on Linux, without
/// Linux's early answer.
#[cfg(target_os = "macos")]
fn confirm_once(addr: SocketAddr, hops: u8, timeout: Duration) -> ConfirmOutcome {
    use std::os::fd::AsRawFd;
    let addr = unmapped(addr);
    let sock = match new_socket(addr) {
        Ok(s) => s,
        Err(e) => return ConfirmOutcome::Failed(e.to_string()),
    };
    if let Err(e) = sock.connect_timeout(&addr.into(), timeout) {
        return ConfirmOutcome::ConnectFailed(e.to_string());
    }
    // From here on every packet of this socket — the FIN, its retransmissions, the closing
    // reset — may cross at most `hops` hops.
    let _ = sock.set_linger(Some(Duration::ZERO));
    if let Err(e) = set_hops(&sock, addr, hops) {
        return ConfirmOutcome::Failed(e.to_string());
    }
    let fd = sock.as_raw_fd();
    let rtt = match connection_info(fd) {
        // The peer closed or reset the connection before the FIN was sent: what follows could
        // not tell whether the FIN reached it (review round 2, probe-1).
        Ok(i) if i.state != TCPS_ESTABLISHED => {
            return ConfirmOutcome::Failed(peer_closed_first(i.state))
        }
        // Milliseconds; the smoothed round trip, or the last one before there is one.
        Ok(i) => Duration::from_millis(u64::from(i.srtt_ms.max(i.rttcur_ms))),
        Err(e) => return ConfirmOutcome::Failed(e.to_string()),
    };
    if let Err(e) = sock.shutdown(std::net::Shutdown::Write) {
        return ConfirmOutcome::Failed(e.to_string());
    }
    // A peer within the limit acknowledges the FIN within about a round trip (a delayed ACK at
    // most a couple of hundred milliseconds later).
    let wait = (rtt * 4 + Duration::from_millis(250))
        .clamp(Duration::from_millis(300), Duration::from_millis(1500));
    let deadline = std::time::Instant::now() + wait;
    loop {
        let state = match connection_info(fd) {
            Ok(i) => i.state,
            Err(e) => return ConfirmOutcome::Failed(e.to_string()),
        };
        if let Some(done) = fin_step(state) {
            return done;
        }
        if std::time::Instant::now() >= deadline {
            return fin_at_deadline(state);
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

// TCP states (<netinet/tcp_fsm.h>).
#[cfg(target_os = "macos")]
const TCPS_CLOSED: u8 = 0;
#[cfg(target_os = "macos")]
const TCPS_ESTABLISHED: u8 = 4;
#[cfg(target_os = "macos")]
const TCPS_CLOSE_WAIT: u8 = 5;
#[cfg(target_os = "macos")]
const TCPS_FIN_WAIT_1: u8 = 6;
#[cfg(target_os = "macos")]
const TCPS_CLOSING: u8 = 7;
#[cfg(target_os = "macos")]
const TCPS_LAST_ACK: u8 = 8;
#[cfg(target_os = "macos")]
const TCPS_FIN_WAIT_2: u8 = 9;
#[cfg(target_os = "macos")]
const TCPS_TIME_WAIT: u8 = 10;

/// macOS: why the check fails when the peer closed (`CLOSE_WAIT`, then `LAST_ACK` once this side
/// sends its FIN) or reset (`CLOSED`) the connection before its FIN was acknowledged.
#[cfg(target_os = "macos")]
fn peer_closed_first(state: u8) -> String {
    let how = match state {
        TCPS_CLOSE_WAIT | TCPS_LAST_ACK => "closed",
        TCPS_CLOSED => "reset",
        _ => return format!("the check connection is in TCP state {state}"),
    };
    format!(
        "the peer {how} the check connection before its hop-limited FIN was acknowledged, so \
         the check cannot tell how near it is"
    )
}

/// macOS: what the check connection's state, polled after its FIN was sent, decides (review
/// round 2, probe-1): `FIN_WAIT_2` or `TIME_WAIT` (only reached once the FIN was acknowledged;
/// `TIME_WAIT` also from `CLOSING`) is an answer, near; `FIN_WAIT_1` (the FIN not yet
/// acknowledged) and `CLOSING` (the peer's FIN crossed this side's, which is still not
/// acknowledged) decide nothing yet; a peer that closed or reset the connection on its own
/// (`LAST_ACK`, `CLOSE_WAIT`, `CLOSED`: no acknowledgement of the FIN) is a failure, refused but
/// not read as near, and never as far.
#[cfg(target_os = "macos")]
fn fin_step(state: u8) -> Option<ConfirmOutcome> {
    match state {
        TCPS_FIN_WAIT_2 | TCPS_TIME_WAIT => Some(ConfirmOutcome::Answered),
        TCPS_FIN_WAIT_1 | TCPS_CLOSING => None,
        other => Some(ConfirmOutcome::Failed(peer_closed_first(other))),
    }
}

/// macOS: the check connection's state when its deadline passes: still `FIN_WAIT_1` (the FIN
/// unacknowledged, the peer silent) is far; `CLOSING` (the peer closed on its own while the FIN
/// went unacknowledged) is a failure, never far.
#[cfg(target_os = "macos")]
fn fin_at_deadline(state: u8) -> ConfirmOutcome {
    match state {
        TCPS_FIN_WAIT_1 => ConfirmOutcome::Unanswered,
        other => ConfirmOutcome::Failed(peer_closed_first(match other {
            TCPS_CLOSING => TCPS_LAST_ACK,
            o => o,
        })),
    }
}

/// The fields of a `struct tcp_connection_info` (<netinet/tcp.h>) the check connection reads.
#[cfg(target_os = "macos")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ConnectionInfo {
    /// `tcpi_state`: a <netinet/tcp_fsm.h> state.
    state: u8,
    /// `tcpi_rttcur`, `tcpi_srtt`: the last and the smoothed round trip, in milliseconds.
    rttcur_ms: u32,
    srtt_ms: u32,
}

/// The bytes of a `tcp_connection_info` that must have been written for [`ConnectionInfo`] to be
/// read: up to the end of `tcpi_srtt` (48). The libc crate's struct is 176 bytes and the SDK's
/// 112 (the kernel writes 112: review round 1, probe-1), so only the fields within what the kernel
/// says it wrote are read, never the libc struct's tail; the offsets are the SDK's (`tcpi_state`
/// 0, `tcpi_rttcur` 40, `tcpi_srtt` 44), checked in the tests.
#[cfg(target_os = "macos")]
const CONNECTION_INFO_NEEDED: usize =
    std::mem::offset_of!(libc::tcp_connection_info, tcpi_srtt) + 4;

/// [`ConnectionInfo`] from a `tcp_connection_info` of which the kernel wrote `len` bytes; an
/// error when that does not reach `tcpi_srtt`'s end.
#[cfg(target_os = "macos")]
fn connection_info_fields(i: &libc::tcp_connection_info, len: usize) -> io::Result<ConnectionInfo> {
    if len < CONNECTION_INFO_NEEDED || len > std::mem::size_of::<libc::tcp_connection_info>() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "TCP_CONNECTION_INFO wrote {len} bytes, not the {CONNECTION_INFO_NEEDED} needed"
            ),
        ));
    }
    Ok(ConnectionInfo {
        state: i.tcpi_state,
        rttcur_ms: i.tcpi_rttcur,
        srtt_ms: i.tcpi_srtt,
    })
}

/// `getsockopt(TCP_CONNECTION_INFO)` on `fd`, read as [`connection_info_fields`] says.
#[cfg(target_os = "macos")]
fn connection_info(fd: i32) -> io::Result<ConnectionInfo> {
    // SAFETY: a zeroed tcp_connection_info (plain integers) is valid to be overwritten by
    // getsockopt.
    let mut i: libc::tcp_connection_info = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::tcp_connection_info>() as libc::socklen_t;
    // SAFETY: `i` and `len` are valid for the size given; the kernel writes at most `len` bytes.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_CONNECTION_INFO,
            (&mut i as *mut libc::tcp_connection_info).cast(),
            &mut len,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    connection_info_fields(&i, len as usize)
}

#[cfg(not(any(target_os = "linux", target_os = "android", target_os = "macos")))]
fn confirm_once(_: SocketAddr, _: u8, _: Duration) -> ConfirmOutcome {
    ConfirmOutcome::Failed("the check connection is supported on Linux only".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn outcomes_are_classified() {
        let os = |e: i32| ProbeOutcome::of(Err(io::Error::from_raw_os_error(e)));
        assert_eq!(
            ProbeOutcome::of(Ok(())).verdict(),
            Verdict::Near("accepted a connection")
        );
        assert_eq!(
            os(libc::ECONNREFUSED).verdict(),
            Verdict::Near("refused a connection")
        );
        assert_eq!(
            os(libc::ECONNRESET).verdict(),
            Verdict::Near("reset a connection")
        );
        assert_eq!(os(libc::EHOSTUNREACH).verdict(), Verdict::Far);
        assert_eq!(os(libc::ENETUNREACH).verdict(), Verdict::Far);
        // No answer decides nothing.
        assert_eq!(os(libc::ETIMEDOUT).verdict(), Verdict::Undecided);
        assert_eq!(
            ProbeOutcome::of(Err(io::ErrorKind::TimedOut.into())).verdict(),
            Verdict::Undecided
        );
        for e in [libc::EPERM, libc::EACCES, libc::EADDRNOTAVAIL, libc::EINVAL] {
            assert!(matches!(os(e).verdict(), Verdict::Failed(_)), "{e}");
        }
    }

    /// A probe without an answer is decided by the check connection: answered is near, unanswered
    /// far, not connecting refused; a probe with an answer needs no check connection.
    #[test]
    fn a_timed_out_probe_is_decided_by_the_check_connection() {
        let addr: SocketAddr = "93.184.216.34:443".parse().unwrap();
        for (confirmed, want) in [
            (
                ConfirmOutcome::Answered,
                Verdict::Near("answered once connected (it had not answered the probe)"),
            ),
            (ConfirmOutcome::Unanswered, Verdict::Far),
        ] {
            let p = FixedProbe::with(ProbeOutcome::TimedOut, confirmed);
            assert_eq!(decide(&*p, addr, 2), want);
            assert_eq!(*p.confirms.lock().unwrap(), vec![(addr, 2)]);
        }
        let p = FixedProbe::with(
            ProbeOutcome::TimedOut,
            ConfirmOutcome::ConnectFailed("timed out".into()),
        );
        assert!(matches!(decide(&*p, addr, 2), Verdict::Failed(_)));
        for outcome in [ProbeOutcome::Unreachable, ProbeOutcome::Connected] {
            let p = FixedProbe::with(outcome, ConfirmOutcome::Answered);
            decide(&*p, addr, 2);
            assert!(p.confirms.lock().unwrap().is_empty());
        }
    }

    /// A listener on loopback is zero hops away: the probe connects (near). A loopback port with
    /// nothing listening refuses (near).
    #[test]
    fn a_local_listener_is_near() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        assert_eq!(
            TtlProbe.probe(addr, 2, PROBE_TIMEOUT),
            ProbeOutcome::Connected
        );
        drop(l);
        assert_eq!(
            TtlProbe.probe(addr, 2, PROBE_TIMEOUT),
            ProbeOutcome::Refused
        );
    }

    /// A near listener that drops SYNs while its accept queue is full (backlog 0, one connection
    /// queued) gives the probe no answer; it drains its queue two seconds later and then answers
    /// a connection. The check connection connects then, and its hop-limited FIN is acknowledged:
    /// near, refused before any connection that carries data.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn a_near_listener_that_drops_syns_for_a_while_is_near() {
        use socket2::{Domain, Socket, Type};
        let l = Socket::new(Domain::IPV4, Type::STREAM, None).unwrap();
        l.bind(&"127.0.0.1:0".parse::<SocketAddr>().unwrap().into())
            .unwrap();
        l.listen(0).unwrap();
        let addr = l.local_addr().unwrap().as_socket().unwrap();
        let _first = std::net::TcpStream::connect(addr).unwrap();
        // The probe alone: no answer within its time.
        assert_eq!(
            TtlProbe.probe(addr, 2, PROBE_TIMEOUT),
            ProbeOutcome::TimedOut
        );
        let drain = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs(2));
            let accepted = l.accept();
            std::thread::sleep(Duration::from_secs(12));
            drop((l, accepted));
        });
        let t = std::time::Instant::now();
        let v = decide(&TtlProbe, addr, 2);
        assert_eq!(
            v,
            Verdict::Near("answered once connected (it had not answered the probe)"),
            "after {:?}",
            t.elapsed()
        );
        drop(drain);
    }

    /// macOS: a near listener whose probe had no answer. (macOS answers SYNs with SYN cookies
    /// when a listener's accept queue is full, so the Linux test's silent listener cannot be
    /// staged without root; the probe's silence is staged instead, and everything after it is
    /// real.) The check connection connects, its hop-limited FIN is acknowledged: near, refused.
    #[cfg(target_os = "macos")]
    #[test]
    fn a_near_listener_that_gave_the_probe_no_answer_is_near_on_macos() {
        #[derive(Debug)]
        struct Silent;
        impl NearProbe for Silent {
            fn probe(&self, _: SocketAddr, _: u8, _: Duration) -> ProbeOutcome {
                ProbeOutcome::TimedOut
            }
            fn confirm(&self, addr: SocketAddr, hops: u8, timeout: Duration) -> ConfirmOutcome {
                TtlProbe.confirm(addr, hops, timeout)
            }
        }
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let accept = std::thread::spawn(move || {
            let c = l.accept();
            std::thread::sleep(Duration::from_secs(2));
            drop(c);
        });
        assert_eq!(
            decide(&Silent, addr, 2),
            Verdict::Near("answered once connected (it had not answered the probe)")
        );
        accept.join().unwrap();
        // Nothing listening any more: the check connection does not connect, refused.
        assert!(matches!(decide(&Silent, addr, 2), Verdict::Failed(_)));
    }

    /// Hardening 13: on macOS an unreachable that `connect` reports at once (no packet answered:
    /// Local Network privacy, a Network Extension policy) is a failure, refused; one that arrives
    /// while the connection is in progress (an ICMP "time exceeded") is still far; other errors
    /// keep their meaning.
    #[cfg(target_os = "macos")]
    #[test]
    fn an_unreachable_at_once_is_no_answer_on_macos() {
        let at_once =
            |e: i32| ProbeOutcome::of(Err(unreachable_at_once(io::Error::from_raw_os_error(e))));
        for e in [libc::EHOSTUNREACH, libc::ENETUNREACH] {
            let o = at_once(e);
            assert!(
                matches!(&o, ProbeOutcome::Failed(w) if w.contains("before any packet")),
                "{o:?}"
            );
            assert!(matches!(o.verdict(), Verdict::Failed(_)));
        }
        assert_eq!(at_once(libc::ECONNREFUSED), ProbeOutcome::Refused);
        assert_eq!(
            ProbeOutcome::of(Err(io::Error::from_raw_os_error(libc::EHOSTUNREACH))),
            ProbeOutcome::Unreachable
        );
        // This host's router (on-link): without Local Network privacy granted the probe is denied
        // at once and refused; with it the router answers within the limit. Never far.
        let (routes, _) = crate::routes::read_routing(&[]).unwrap();
        if let Some(g) = routes.iter().find_map(|r| match (r.prefix.len, r.hop) {
            (0, crate::routes::Hop::Via(g @ std::net::IpAddr::V4(_))) => Some(g),
            _ => None,
        }) {
            let o = TtlProbe.probe(SocketAddr::new(g, 80), 2, PROBE_TIMEOUT);
            eprintln!("the router, port 80, hop limit 2: {o:?}");
            assert_ne!(o.verdict(), Verdict::Far, "{o:?}");
        } else {
            crate::skipped("the router probe: no IPv4 default route");
        }
    }

    /// probe-1: `TCP_CONNECTION_INFO` is read only within what the kernel wrote (112 bytes here,
    /// the SDK's struct, while the libc crate's is 176), and fails when that does not reach
    /// `tcpi_srtt`; the fields read are at the SDK's offsets.
    #[cfg(target_os = "macos")]
    #[test]
    fn connection_info_is_read_within_what_the_kernel_wrote() {
        use std::mem::offset_of;
        use std::os::fd::AsRawFd;
        assert_eq!(offset_of!(libc::tcp_connection_info, tcpi_state), 0);
        assert_eq!(offset_of!(libc::tcp_connection_info, tcpi_rttcur), 40);
        assert_eq!(offset_of!(libc::tcp_connection_info, tcpi_srtt), 44);
        assert_eq!(CONNECTION_INFO_NEEDED, 48);
        // SAFETY: plain integers.
        let mut i: libc::tcp_connection_info = unsafe { std::mem::zeroed() };
        i.tcpi_state = 4;
        i.tcpi_srtt = 7;
        let size = std::mem::size_of::<libc::tcp_connection_info>();
        for len in [48, 112, size] {
            assert_eq!(
                connection_info_fields(&i, len).unwrap(),
                ConnectionInfo {
                    state: 4,
                    rttcur_ms: 0,
                    srtt_ms: 7
                }
            );
        }
        for len in [0, 4, 40, 47, size + 1] {
            assert!(connection_info_fields(&i, len).is_err(), "{len}");
        }
        // The kernel's answer for a real connection.
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let c = std::net::TcpStream::connect(l.local_addr().unwrap()).unwrap();
        let mut len = size as libc::socklen_t;
        // SAFETY: `i` and `len` are valid for the size given.
        let rc = unsafe {
            libc::getsockopt(
                c.as_raw_fd(),
                libc::IPPROTO_TCP,
                libc::TCP_CONNECTION_INFO,
                (&mut i as *mut libc::tcp_connection_info).cast(),
                &mut len,
            )
        };
        assert_eq!(rc, 0);
        eprintln!("TCP_CONNECTION_INFO: the kernel wrote {len} of {size} bytes");
        assert!(len as usize >= CONNECTION_INFO_NEEDED, "{len}");
        // TCPS_ESTABLISHED.
        assert_eq!(connection_info(c.as_raw_fd()).unwrap().state, 4);
    }

    /// The check connection to a listener on loopback (zero hops) and to an IPv6 one: answered,
    /// near. Its hop-limited FIN reaches them and is acknowledged.
    #[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
    #[test]
    fn the_check_connection_finds_a_local_listener_near() {
        for bind in ["127.0.0.1:0", "[::1]:0"] {
            let Ok(l) = std::net::TcpListener::bind(bind) else {
                crate::skipped(format!("no {bind} here"));
                continue;
            };
            let addr = l.local_addr().unwrap();
            let accept = std::thread::spawn(move || {
                let c = l.accept();
                std::thread::sleep(Duration::from_secs(2));
                drop(c);
            });
            assert_eq!(
                TtlProbe.confirm(addr, 2, Duration::from_secs(5)),
                ConfirmOutcome::Answered,
                "{addr}"
            );
            accept.join().unwrap();
        }
    }

    /// The check connection against a far public host (Cloudflare's resolver): it connects, and
    /// its FIN limited to 2 hops dies on the way: unanswered, far. Skipped where unreachable.
    #[test]
    fn the_check_connection_finds_a_public_host_far() {
        let addr: SocketAddr = "1.1.1.1:443".parse().unwrap();
        match TtlProbe.confirm(addr, 2, Duration::from_secs(5)) {
            ConfirmOutcome::ConnectFailed(e) => {
                crate::skipped(format!("{addr} unreachable here: {e}"))
            }
            other => assert_eq!(other, ConfirmOutcome::Unanswered),
        }
    }

    /// probe-1: macOS reads only an acknowledgement of the check's FIN as an answer. A peer that
    /// closed or reset the connection on its own is a failure (refused), never near by mistake
    /// and never far; a FIN still unacknowledged at the deadline is far only if the peer stayed
    /// silent.
    #[cfg(target_os = "macos")]
    #[test]
    fn the_check_reads_only_an_acknowledged_fin_as_an_answer_on_macos() {
        assert_eq!(fin_step(TCPS_FIN_WAIT_2), Some(ConfirmOutcome::Answered));
        assert_eq!(fin_step(TCPS_TIME_WAIT), Some(ConfirmOutcome::Answered));
        assert_eq!(fin_step(TCPS_FIN_WAIT_1), None);
        assert_eq!(fin_step(TCPS_CLOSING), None);
        for (state, how) in [
            (TCPS_LAST_ACK, "closed"),
            (TCPS_CLOSE_WAIT, "closed"),
            (TCPS_CLOSED, "reset"),
            (TCPS_ESTABLISHED, "TCP state 4"),
        ] {
            let o = fin_step(state);
            assert!(
                matches!(&o, Some(ConfirmOutcome::Failed(w)) if w.contains(how)),
                "{state}: {o:?}"
            );
            assert!(matches!(o.unwrap().verdict(), Verdict::Failed(_)));
        }
        assert_eq!(fin_at_deadline(TCPS_FIN_WAIT_1), ConfirmOutcome::Unanswered);
        let o = fin_at_deadline(TCPS_CLOSING);
        assert!(
            matches!(&o, ConfirmOutcome::Failed(w) if w.contains("closed")),
            "{o:?}"
        );
        assert!(matches!(peer_closed_first(TCPS_CLOSE_WAIT), w if w.contains("closed")));
    }

    /// probe-1, live: a loopback peer that closes, or resets, each connection as soon as it
    /// accepts it is never found far, and is refused either way (near when the FIN was
    /// acknowledged before the peer's close, a failure when the peer closed first). And a far
    /// public peer that closes each connection at once (a NIST daytime server, port 13): its FIN
    /// crosses the check's, which dies two hops out; the check is a failure, refused but not
    /// near (before this change it was read as near). Skipped where that server is unreachable.
    #[cfg(target_os = "macos")]
    #[test]
    fn a_peer_that_closes_first_is_never_far_on_macos() {
        for (bind, reset) in [
            ("127.0.0.1:0", false),
            ("127.0.0.1:0", true),
            ("[::1]:0", false),
        ] {
            let Ok(l) = std::net::TcpListener::bind(bind) else {
                crate::skipped(format!("no {bind} here"));
                continue;
            };
            let addr = l.local_addr().unwrap();
            let server = std::thread::spawn(move || {
                for _ in 0..5 {
                    let Ok((c, _)) = l.accept() else { return };
                    if reset {
                        let _ = socket2::SockRef::from(&c).set_linger(Some(Duration::ZERO));
                    }
                    drop(c);
                }
            });
            for _ in 0..5 {
                let o = TtlProbe.confirm(addr, 2, Duration::from_secs(5));
                eprintln!("{addr} (reset {reset}): {o:?}");
                // Near when the FIN was acknowledged before the peer's close, a failure when the
                // peer closed first (or, under load, the connection was refused): never far.
                assert_ne!(o, ConfirmOutcome::Unanswered, "{addr}");
                assert_ne!(o.verdict(), Verdict::Far, "{addr}: {o:?}");
            }
            server.join().unwrap();
        }
        let far: SocketAddr = "129.6.15.28:13".parse().unwrap();
        let o = TtlProbe.confirm(far, 2, Duration::from_secs(5));
        eprintln!("{far}, hop limit 2: {o:?}");
        match o {
            ConfirmOutcome::ConnectFailed(e) => {
                crate::skipped(format!("{far} unreachable here: {e}"))
            }
            o => assert!(
                matches!(&o, ConfirmOutcome::Failed(w) if w.contains("closed")),
                "{far}: {o:?}"
            ),
        }
    }

    /// probe-2: the probe and the check connection connect to an IPv4-mapped address as its
    /// IPv4 address, so the hop limit holds (an IPv6 socket's hop limit does not limit the IPv4
    /// packets a mapped connection sends: the probe of a far host connected). Skipped where
    /// 1.1.1.1 is unreachable.
    #[cfg(target_os = "macos")]
    #[test]
    fn a_mapped_address_is_probed_as_its_ipv4_address_on_macos() {
        let v4: SocketAddr = "1.1.1.1:443".parse().unwrap();
        let mapped: SocketAddr = "[::ffff:1.1.1.1]:443".parse().unwrap();
        assert_eq!(unmapped(mapped), v4);
        assert_eq!(unmapped(v4), v4);
        let v6: SocketAddr = "[2606:4700:4700::1111]:443".parse().unwrap();
        assert_eq!(unmapped(v6), v6);
        // A listener on 127.0.0.1 is still reached through its mapped address.
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let local: SocketAddr = format!("[::ffff:127.0.0.1]:{}", l.local_addr().unwrap().port())
            .parse()
            .unwrap();
        assert_eq!(
            TtlProbe.probe(local, 2, PROBE_TIMEOUT),
            ProbeOutcome::Connected
        );
        drop(l);
        if TtlProbe.probe(v4, 64, PROBE_TIMEOUT) != ProbeOutcome::Connected {
            crate::skipped(format!("{v4} unreachable here"));
            return;
        }
        for _ in 0..3 {
            let o = TtlProbe.probe(mapped, 2, PROBE_TIMEOUT);
            eprintln!("{mapped}, hop limit 2: {o:?}");
            assert_ne!(o, ProbeOutcome::Connected, "the hop limit did not hold");
        }
        match TtlProbe.confirm(mapped, 2, Duration::from_secs(5)) {
            ConfirmOutcome::ConnectFailed(e) => {
                crate::skipped(format!("the check connection: {e}"))
            }
            c => assert_eq!(c, ConfirmOutcome::Unanswered, "{c:?}"),
        }
    }
}
