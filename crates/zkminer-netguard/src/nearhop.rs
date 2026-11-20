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

/// The probe, on every platform: asked at most twice within `timeout` ([`probe_twice`]), to
/// the destination as a connection reaches it ([`unmapped`]).
fn probe_once(addr: SocketAddr, hops: u8, timeout: Duration) -> io::Result<()> {
    let addr = unmapped(addr);
    probe_twice(timeout, |t| probe_attempt(addr, hops, t))
}

/// The probe asked at most twice within `timeout`: two thirds of it, then, after a timeout, the
/// rest (review round 3, probe-1; on every platform since the Linux application). A router that
/// rate-limits its ICMP drops some "time exceeded" answers (7.5% of the reviewer's probes on a
/// home path went unanswered: `r3-probe/sweep-h2.log`), and a probe without an answer leaves the
/// decision to the check connection, whose positive control refuses a peer that never
/// acknowledges a bare FIN (every AWS S3 front end), and which does not exist on Windows (a
/// probe without an answer is refused there). An answer comes within a round trip to the router,
/// milliseconds.
fn probe_twice(
    timeout: Duration,
    mut attempt: impl FnMut(Duration) -> io::Result<()>,
) -> io::Result<()> {
    let first = timeout * 2 / 3;
    match attempt(first) {
        Err(e) if e.kind() == io::ErrorKind::TimedOut => attempt(timeout - first),
        r => r,
    }
}

/// One probe (not macOS): `socket2::Socket::connect_timeout` with the hop limit set.
#[cfg(not(target_os = "macos"))]
fn probe_attempt(addr: SocketAddr, hops: u8, timeout: Duration) -> io::Result<()> {
    let sock = new_socket(addr)?;
    set_hops(&sock, addr, hops)?;
    let r = sock.connect_timeout(&addr.into(), timeout);
    // Closed with a reset, never a byte of data.
    let _ = sock.set_linger(Some(Duration::ZERO));
    drop(sock);
    r
}

/// macOS: one probe, `socket2::Socket::connect_timeout`'s steps run here so that an unreachable
/// `connect` reports at once, before the connection is in progress, is a failure (see the module
/// doc).
#[cfg(target_os = "macos")]
fn probe_attempt(addr: SocketAddr, hops: u8, timeout: Duration) -> io::Result<()> {
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

/// An IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) as its IPv4 address, which is what a
/// connection to it reaches. An IPv6 socket connected to a mapped address sends IPv4 packets, and
/// `IPV6_UNICAST_HOPS` need not limit them (on macOS they left with the default TTL, so the probe
/// of a far host connected and read it as near: `r2-probe/mapped.log`); an IPv4 socket with
/// `IP_TTL` set limits them. Review round 2, probe-2, on every platform since the Linux
/// application ([`crate::NetPolicy::vet_connection`] already unmaps before it asks; the probe and
/// the check connection no longer rely on it).
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
            n if n > 0 => return connect_result(p.revents, sock.take_error()),
            _ => {
                let e = io::Error::last_os_error();
                if e.kind() != io::ErrorKind::Interrupted {
                    return Err(e);
                }
            }
        }
    }
}

/// macOS: how a connect in progress ended, from `poll`'s `revents` and the socket's pending error
/// (`SO_ERROR`): that error; a hang-up or error event with no error set is a failure of its own
/// (never an unreachable, which would read as far: review round 3, cross-1); otherwise connected.
#[cfg(target_os = "macos")]
fn connect_result(revents: libc::c_short, error: io::Result<Option<io::Error>>) -> io::Result<()> {
    if revents & (libc::POLLHUP | libc::POLLERR) != 0 {
        return match error {
            Ok(Some(e)) | Err(e) => Err(e),
            Ok(None) => Err(io::Error::other("no error set after POLLHUP")),
        };
    }
    match error? {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

/// The check connection (see the module doc), on Linux, Android and macOS alike since the Linux
/// application: connected with the default hop limit, the hop limit lowered, half-closed, and the
/// FIN's fate read from the connection's TCP state ([`conn_info`]: Linux's `TCP_INFO`, macOS's
/// `TCP_CONNECTION_INFO`), as [`fin_step`] and [`fin_at_deadline`] read it, then, for a FIN
/// still unacknowledged at the deadline, the positive control ([`positive_control`]).
///
/// Only an acknowledgement counts as an answer (review round 2, probe-1): a peer that closed or
/// reset the connection first is a failed check, never near by mistake and never far. Before the
/// Linux application Linux read every state but `FIN_WAIT1` as near (a peer's own close
/// included), took an ICMP error for the FIN (`SO_ERROR`) as far at once, and had no positive
/// control. That ICMP early answer is gone: Linux keeps an ICMP error for an established socket
/// as a soft error `SO_ERROR` does not report unless `IP_RECVERR` is set, and a "far" from it
/// would skip the positive control; macOS never reported it either. So both platforms decide far
/// only by the deadline and the control.
#[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
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
    // The hop limit the connection was made with, restored for the positive control.
    let default_hops = match default_hops(&sock, addr) {
        Ok(h) => h,
        Err(e) => return ConfirmOutcome::Failed(e.to_string()),
    };
    // From here on every packet of this socket — the FIN, its retransmissions, the closing
    // reset — may cross at most `hops` hops (until the positive control).
    let _ = sock.set_linger(Some(Duration::ZERO));
    if let Err(e) = set_hops(&sock, addr, hops) {
        return ConfirmOutcome::Failed(e.to_string());
    }
    let fd = sock.as_raw_fd();
    let rtt = match conn_info(fd) {
        // The peer closed or reset the connection before the FIN was sent: what follows could
        // not tell whether the FIN reached it (review round 2, probe-1).
        Ok(i) if i.state != TcpState::Established => {
            return ConfirmOutcome::Failed(peer_closed_first(i.state))
        }
        Ok(i) => i.rtt,
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
        let state = match conn_info(fd) {
            Ok(i) => i.state,
            Err(e) => return ConfirmOutcome::Failed(e.to_string()),
        };
        if let Some(done) = fin_step(state) {
            return done;
        }
        if std::time::Instant::now() >= deadline {
            return match fin_at_deadline(state) {
                ConfirmOutcome::Unanswered => positive_control(&sock, addr, default_hops, rtt),
                other => other,
            };
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// The hop limit `sock` (to `addr`) has now, as it was connected: `IP_TTL`, or
/// `IPV6_UNICAST_HOPS` (macOS: -1, read as `u32::MAX`, the system's default; Linux answers the
/// hop limit in effect).
#[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
fn default_hops(sock: &socket2::Socket, addr: SocketAddr) -> io::Result<u32> {
    if addr.is_ipv4() {
        sock.ttl_v4()
    } else {
        sock.unicast_hops_v6()
    }
}

/// The check connection's positive control (review round 3, probe-1; Linux too since the Linux
/// application). Its FIN went unacknowledged within `hops` hops until the deadline, which reads as
/// far only if the peer acknowledges a FIN at all: a peer that never acknowledges a bare FIN
/// (every AWS S3 front end tested: `r3-probe/finack-s3.log`) would read as far at any distance.
/// So the hop limit the connection was made with (`default_hops`) is restored and the FIN's
/// retransmission (due within the retransmission timeout, `tcpi_rto`) is waited for:
/// acknowledged now, the peer answers a FIN that reaches it, and the one limited to `hops` did
/// not: far ([`fin_after_control`]); not acknowledged within the RTO, two round trips (`rtt`)
/// and 250 ms (clamped to 0.5–4 s), or the peer closed or reset the connection meanwhile: the
/// check cannot tell, refused ([`fin_after_control_deadline`]). Only an acknowledgement counts:
/// a reset may come from a timer of the peer's (an S3 front end resets an idle connection),
/// whatever reached it.
#[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
fn positive_control(
    sock: &socket2::Socket,
    addr: SocketAddr,
    default_hops: u32,
    rtt: Duration,
) -> ConfirmOutcome {
    use std::os::fd::AsRawFd;
    let restored = if addr.is_ipv4() {
        sock.set_ttl_v4(default_hops)
    } else {
        sock.set_unicast_hops_v6(default_hops)
    };
    if let Err(e) = restored {
        return ConfirmOutcome::Failed(e.to_string());
    }
    let rto = match conn_info(sock.as_raw_fd()) {
        Ok(i) => i.rto,
        Err(e) => return ConfirmOutcome::Failed(e.to_string()),
    };
    let wait = (rto + rtt * 2 + Duration::from_millis(250))
        .clamp(Duration::from_millis(500), Duration::from_secs(4));
    let deadline = std::time::Instant::now() + wait;
    loop {
        let state = match conn_info(sock.as_raw_fd()) {
            Ok(i) => i.state,
            Err(e) => return ConfirmOutcome::Failed(e.to_string()),
        };
        if let Some(done) = fin_after_control(state) {
            return done;
        }
        if std::time::Instant::now() >= deadline {
            return fin_after_control_deadline(state);
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// A TCP connection's state as the check connection reads it, whatever the platform's numbering
/// (Linux's <net/tcp_states.h>, [`TcpState::from_linux`]; macOS's <netinet/tcp_fsm.h>,
/// [`TcpState::from_macos`]).
#[cfg(any(test, target_os = "linux", target_os = "android", target_os = "macos"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TcpState {
    /// Closed: the peer reset the connection (Linux `TCP_CLOSE` with an error pending; macOS
    /// `TCPS_CLOSED`, which also follows an acknowledged `LAST_ACK` there).
    Closed,
    Established,
    /// The peer closed its side first.
    CloseWait,
    /// This side's FIN sent, not yet acknowledged.
    FinWait1,
    /// Both FINs sent, this side's not yet acknowledged.
    Closing,
    /// The peer closed first, then this side sent its FIN.
    LastAck,
    /// This side's FIN acknowledged.
    FinWait2,
    /// Both closed, this side's FIN acknowledged (Linux: `TCP_CLOSE` with no error pending).
    TimeWait,
    /// Any other state (the platform's number).
    Other(u8),
}

#[cfg(any(test, target_os = "linux", target_os = "android", target_os = "macos"))]
impl TcpState {
    /// Linux's `tcpi_state` (<net/tcp_states.h>: `TCP_ESTABLISHED` 1 … `TCP_CLOSING` 11), with
    /// the socket's pending error (`SO_ERROR`, read only for `TCP_CLOSE`).
    ///
    /// Linux never shows `TIME_WAIT` on the socket itself: a connection that reaches it (this
    /// side's FIN acknowledged and the peer's FIN received, from `FIN_WAIT2` or `CLOSING`) is
    /// handed to a timewait mini-socket and the socket the process holds is `TCP_CLOSE`
    /// (`tcp_time_wait` → `tcp_done`); so is one whose `LAST_ACK` was acknowledged. Both mean
    /// this side's FIN was acknowledged. A reset is `TCP_CLOSE` too, but with `sk_err` set
    /// (`tcp_reset`: `ECONNRESET`, `EPIPE` from `CLOSE_WAIT`), as is a connection the kernel gave
    /// up on (`ETIMEDOUT`) or another process aborted (`ECONNABORTED`). So `TCP_CLOSE` with no
    /// pending error reads as [`TcpState::TimeWait`] (the FIN acknowledged, the connection
    /// closed), and with one as [`TcpState::Closed`] (reset). Measured: the check connection to
    /// 1.1.1.1 whose restored FIN 1.1.1.1 acknowledged and answered with its own went straight
    /// from `FIN_WAIT1` to `TCP_CLOSE` with `SO_ERROR` 0 (`fix-linux/exp/finctl-1.1.1.1-vm.log`).
    #[cfg(any(all(test, unix), target_os = "linux", target_os = "android"))]
    pub(crate) fn from_linux_close(s: u8, so_error: i32) -> Self {
        match (s, so_error) {
            (7, 0) => TcpState::TimeWait,
            (7, _) => TcpState::Closed,
            (s, _) => TcpState::from_linux(s),
        }
    }

    /// Linux's `tcpi_state` (<net/tcp_states.h>: `TCP_ESTABLISHED` 1 … `TCP_CLOSING` 11), as
    /// numbered (`TCP_CLOSE` 7 is [`TcpState::Closed`]; see [`TcpState::from_linux_close`]).
    #[cfg(any(test, target_os = "linux", target_os = "android"))]
    pub(crate) fn from_linux(s: u8) -> Self {
        match s {
            1 => TcpState::Established,
            4 => TcpState::FinWait1,
            5 => TcpState::FinWait2,
            6 => TcpState::TimeWait,
            7 => TcpState::Closed,
            8 => TcpState::CloseWait,
            9 => TcpState::LastAck,
            11 => TcpState::Closing,
            o => TcpState::Other(o),
        }
    }

    /// macOS's `tcpi_state` (<netinet/tcp_fsm.h>: `TCPS_CLOSED` 0 … `TCPS_TIME_WAIT` 10).
    #[cfg(any(test, target_os = "macos"))]
    pub(crate) fn from_macos(s: u8) -> Self {
        match s {
            0 => TcpState::Closed,
            4 => TcpState::Established,
            5 => TcpState::CloseWait,
            6 => TcpState::FinWait1,
            7 => TcpState::Closing,
            8 => TcpState::LastAck,
            9 => TcpState::FinWait2,
            10 => TcpState::TimeWait,
            o => TcpState::Other(o),
        }
    }
}

/// What the check connection reads of a connection: its state, the round trip (smoothed, or the
/// last before there is one) and the retransmission timeout.
#[cfg(any(all(test, unix), target_os = "linux", target_os = "android", target_os = "macos"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ConnInfo {
    pub state: TcpState,
    pub rtt: Duration,
    pub rto: Duration,
}

/// What the check connection's state, polled after its FIN was sent, decides (review round 2,
/// probe-1; Linux too since the Linux application): `FIN_WAIT_2` or `TIME_WAIT` (only reached
/// once the FIN was acknowledged; `TIME_WAIT` also from `CLOSING`) is an answer, near;
/// `FIN_WAIT_1` (the FIN not yet acknowledged) and `CLOSING` (the peer's FIN crossed this side's,
/// which is still not acknowledged) decide nothing yet; a peer that closed or reset the connection
/// on its own (`LAST_ACK`, `CLOSE_WAIT`, `CLOSED`: no acknowledgement of the FIN) is a failure,
/// refused but not read as near, and never as far.
#[cfg(any(test, target_os = "linux", target_os = "android", target_os = "macos"))]
fn fin_step(state: TcpState) -> Option<ConfirmOutcome> {
    match state {
        TcpState::FinWait2 | TcpState::TimeWait => Some(ConfirmOutcome::Answered),
        TcpState::FinWait1 | TcpState::Closing => None,
        other => Some(ConfirmOutcome::Failed(peer_closed_first(other))),
    }
}

/// The check connection's state when its deadline passes: still `FIN_WAIT_1` (the FIN
/// unacknowledged, the peer silent) goes to the positive control; `CLOSING` (the peer closed on
/// its own while the FIN went unacknowledged) is a failure, never far.
#[cfg(any(test, target_os = "linux", target_os = "android", target_os = "macos"))]
fn fin_at_deadline(state: TcpState) -> ConfirmOutcome {
    match state {
        TcpState::FinWait1 => ConfirmOutcome::Unanswered,
        other => ConfirmOutcome::Failed(peer_closed_first(match other {
            TcpState::Closing => TcpState::LastAck,
            o => o,
        })),
    }
}

/// What the check connection's state decides once the default hop limit is restored
/// ([`positive_control`]): the FIN acknowledged (`FIN_WAIT_2`, `TIME_WAIT`) only now is far;
/// still unacknowledged (`FIN_WAIT_1`, `CLOSING`) decides nothing yet; the peer closed or reset
/// the connection: a failure.
#[cfg(any(test, target_os = "linux", target_os = "android", target_os = "macos"))]
fn fin_after_control(state: TcpState) -> Option<ConfirmOutcome> {
    match fin_step(state)? {
        ConfirmOutcome::Answered => Some(ConfirmOutcome::Unanswered),
        other => Some(other),
    }
}

/// The state when the positive control's time is up: a FIN acknowledged at no hop limit (or a
/// peer that closed on its own meanwhile) cannot tell how near the peer is: a failure, never far.
/// The message names the cause, so an operator who sees a store refused (an AWS S3 front end
/// never acknowledges a bare FIN) knows why.
#[cfg(any(test, target_os = "linux", target_os = "android", target_os = "macos"))]
fn fin_after_control_deadline(state: TcpState) -> ConfirmOutcome {
    match state {
        TcpState::FinWait1 => ConfirmOutcome::Failed(UNACKED_FIN.into()),
        other => ConfirmOutcome::Failed(peer_closed_first(match other {
            TcpState::Closing => TcpState::LastAck,
            o => o,
        })),
    }
}

/// Why a check whose FIN no hop limit got acknowledged fails ([`fin_after_control_deadline`]):
/// the cause within the 120 characters a refusal shows of it ([`ConfirmOutcome::verdict`]).
/// Before the Linux application the message ended "…, so the check cannot tell how near it is"
/// and was cut at 120 characters before naming anything.
#[cfg(any(test, target_os = "linux", target_os = "android", target_os = "macos"))]
const UNACKED_FIN: &str = "the peer acknowledged the check's FIN neither within the hop limit \
                           nor at the default one (AWS S3 never does)";

/// Why the check fails when the peer closed (`CLOSE_WAIT`, then `LAST_ACK` once this side sends
/// its FIN) or reset (`CLOSED`) the connection before its FIN was acknowledged.
#[cfg(any(test, target_os = "linux", target_os = "android", target_os = "macos"))]
fn peer_closed_first(state: TcpState) -> String {
    let how = match state {
        TcpState::CloseWait | TcpState::LastAck => "closed",
        TcpState::Closed => "reset",
        other => return format!("the check connection is in TCP state {other:?}"),
    };
    format!(
        "the peer {how} the check connection before its hop-limited FIN was acknowledged, so \
         the check cannot tell how near it is"
    )
}

/// Linux: the bytes of a `struct tcp_info` (<linux/tcp.h>) the check connection reads, at the
/// kernel's ABI offsets: `tcpi_state` (0, u8), `tcpi_rto` (8, µs), `tcpi_rtt` (68, µs, the
/// smoothed round trip). Every kernel since 2.6 writes at least these 104 bytes; the check needs
/// the 72 up to `tcpi_rtt`'s end, and reads nothing past what the kernel says it wrote. (Parsed
/// from bytes, not the libc crate's struct: Android's libc defines none, and the crate's layouts
/// differ between C libraries past these fields.)
#[cfg(any(all(test, unix), target_os = "linux", target_os = "android"))]
const TCP_INFO_NEEDED: usize = 72;

/// [`ConnInfo`] from the `len` bytes of a `tcp_info` the kernel wrote into `b` (`so_error`: the
/// socket's pending error, read when the state is `TCP_CLOSE`: [`TcpState::from_linux_close`]);
/// an error when that does not reach `tcpi_rtt`'s end.
#[cfg(any(all(test, unix), target_os = "linux", target_os = "android"))]
fn linux_conn_info(b: &[u8], len: usize, so_error: impl FnOnce() -> i32) -> io::Result<ConnInfo> {
    if len < TCP_INFO_NEEDED || len > b.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("TCP_INFO wrote {len} bytes, not the {TCP_INFO_NEEDED} needed"),
        ));
    }
    let u32_at = |o: usize| u32::from_ne_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]);
    let state = match b[0] {
        7 => TcpState::from_linux_close(7, so_error()),
        s => TcpState::from_linux(s),
    };
    Ok(ConnInfo {
        state,
        rto: Duration::from_micros(u64::from(u32_at(8))),
        rtt: Duration::from_micros(u64::from(u32_at(68))),
    })
}

/// Linux: `getsockopt(TCP_INFO)` on `fd`, read as [`linux_conn_info`] says.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn conn_info(fd: i32) -> io::Result<ConnInfo> {
    let mut b = [0u8; 256];
    let mut len = b.len() as libc::socklen_t;
    // SAFETY: `b` and `len` are valid for the size given; the kernel writes at most `len` bytes.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_INFO,
            b.as_mut_ptr().cast(),
            &mut len,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    // Read (and so cleared) only for TCP_CLOSE, which ends the check either way.
    let so_error = || {
        let mut e: libc::c_int = 0;
        let mut l = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        // SAFETY: `e` and `l` are valid for the size given.
        let rc = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_ERROR,
                (&mut e as *mut libc::c_int).cast(),
                &mut l,
            )
        };
        // A socket whose error cannot be read is not known to have closed cleanly.
        if rc != 0 {
            -1
        } else {
            e
        }
    };
    linux_conn_info(&b, len as usize, so_error)
}

/// macOS: `getsockopt(TCP_CONNECTION_INFO)` on `fd` ([`connection_info`]) as a [`ConnInfo`].
#[cfg(target_os = "macos")]
fn conn_info(fd: i32) -> io::Result<ConnInfo> {
    let i = connection_info(fd)?;
    Ok(ConnInfo {
        state: TcpState::from_macos(i.state),
        // Milliseconds; the smoothed round trip, or the last one before there is one.
        rtt: Duration::from_millis(u64::from(i.srtt_ms.max(i.rttcur_ms))),
        rto: Duration::from_millis(u64::from(i.rto_ms)),
    })
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
    /// `tcpi_rto`: the retransmission timeout, in milliseconds.
    rto_ms: u32,
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
        rto_ms: i.tcpi_rto,
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
    ConfirmOutcome::Failed("the check connection is supported on Linux and macOS only".into())
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
        assert_eq!(offset_of!(libc::tcp_connection_info, tcpi_rto), 12);
        assert_eq!(CONNECTION_INFO_NEEDED, 48);
        // SAFETY: plain integers.
        let mut i: libc::tcp_connection_info = unsafe { std::mem::zeroed() };
        i.tcpi_state = 4;
        i.tcpi_srtt = 7;
        i.tcpi_rto = 9;
        let size = std::mem::size_of::<libc::tcp_connection_info>();
        for len in [48, 112, size] {
            assert_eq!(
                connection_info_fields(&i, len).unwrap(),
                ConnectionInfo {
                    state: 4,
                    rttcur_ms: 0,
                    srtt_ms: 7,
                    rto_ms: 9
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

    /// probe-1 (macOS since review round 2, Linux since the Linux application): only an
    /// acknowledgement of the check's FIN is an answer. A peer that closed or reset the connection
    /// on its own is a failure (refused), never near by mistake and never far; a FIN still
    /// unacknowledged at the deadline goes to the positive control only if the peer stayed silent.
    /// Both platforms' state numbers read as the same states.
    #[test]
    fn the_check_reads_only_an_acknowledged_fin_as_an_answer() {
        use TcpState::*;
        assert_eq!(fin_step(FinWait2), Some(ConfirmOutcome::Answered));
        assert_eq!(fin_step(TimeWait), Some(ConfirmOutcome::Answered));
        assert_eq!(fin_step(FinWait1), None);
        assert_eq!(fin_step(Closing), None);
        for (state, how) in [
            (LastAck, "closed"),
            (CloseWait, "closed"),
            (Closed, "reset"),
            (Established, "TCP state Established"),
            (Other(10), "TCP state Other(10)"),
        ] {
            let o = fin_step(state);
            assert!(
                matches!(&o, Some(ConfirmOutcome::Failed(w)) if w.contains(how)),
                "{state:?}: {o:?}"
            );
            assert!(matches!(o.unwrap().verdict(), Verdict::Failed(_)));
        }
        assert_eq!(fin_at_deadline(FinWait1), ConfirmOutcome::Unanswered);
        let o = fin_at_deadline(Closing);
        assert!(
            matches!(&o, ConfirmOutcome::Failed(w) if w.contains("closed")),
            "{o:?}"
        );
        assert!(matches!(peer_closed_first(CloseWait), w if w.contains("closed")));
        // Linux's <net/tcp_states.h> and macOS's <netinet/tcp_fsm.h>.
        for (linux, macos, state) in [
            (1, 4, Established),
            (4, 6, FinWait1),
            (5, 9, FinWait2),
            (6, 10, TimeWait),
            (7, 0, Closed),
            (8, 5, CloseWait),
            (9, 8, LastAck),
            (11, 7, Closing),
        ] {
            assert_eq!(TcpState::from_linux(linux), state, "Linux {linux}");
            assert_eq!(TcpState::from_macos(macos), state, "macOS {macos}");
        }
        // Linux's SYN_SENT, SYN_RECV, LISTEN, NEW_SYN_RECV; macOS's LISTEN, SYN_SENT, SYN_RECEIVED.
        for s in [2, 3, 10, 12] {
            assert_eq!(TcpState::from_linux(s), Other(s));
        }
        for s in [1, 2, 3] {
            assert_eq!(TcpState::from_macos(s), Other(s));
        }
        // The old Linux reading (any state but FIN_WAIT1 near) is gone: a peer's own close,
        // as Linux numbers it, is a failure, not an answer.
        for linux in [7, 8, 9] {
            assert!(
                matches!(fin_step(TcpState::from_linux(linux)), Some(ConfirmOutcome::Failed(_))),
                "{linux}"
            );
        }
    }

    /// Linux: `TCP_INFO` is read from the bytes the kernel wrote, at the kernel ABI's offsets
    /// (`tcpi_state` 0, `tcpi_rto` 8, `tcpi_rtt` 68, microseconds), and fails when they do not
    /// reach `tcpi_rtt`'s end.
    #[cfg(unix)]
    #[test]
    fn linux_tcp_info_is_read_within_what_the_kernel_wrote() {
        let mut b = [0u8; 256];
        b[0] = 4;
        b[8..12].copy_from_slice(&204_000u32.to_ne_bytes());
        b[68..72].copy_from_slice(&1_500u32.to_ne_bytes());
        // A field between them that must not be read as either.
        b[64..68].copy_from_slice(&u32::MAX.to_ne_bytes());
        for len in [72, 104, 232, 256] {
            assert_eq!(
                linux_conn_info(&b, len, || unreachable!()).unwrap(),
                ConnInfo {
                    state: TcpState::FinWait1,
                    rto: Duration::from_millis(204),
                    rtt: Duration::from_micros(1_500),
                }
            );
        }
        for len in [0, 8, 68, 71, 257] {
            assert!(linux_conn_info(&b, len, || 0).is_err(), "{len}");
        }
        // TCP_CLOSE: the FIN acknowledged and the connection closed when no error is pending (a
        // TIME_WAIT Linux does not show), a reset when one is.
        b[0] = 7;
        assert_eq!(linux_conn_info(&b, 104, || 0).unwrap().state, TcpState::TimeWait);
        for e in [libc::ECONNRESET, libc::EPIPE, libc::ETIMEDOUT, -1] {
            assert_eq!(linux_conn_info(&b, 104, || e).unwrap().state, TcpState::Closed, "{e}");
        }
        b[0] = 4;
        assert_eq!(
            linux_conn_info(&b, 104, || panic!("read only for TCP_CLOSE")).unwrap().state,
            TcpState::FinWait1
        );
    }

    /// Linux: the offsets [`linux_conn_info`] reads are glibc's `struct tcp_info`'s, and the
    /// kernel's answer for a real connection is read: established, with a round trip and an RTO.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn linux_tcp_info_is_the_kernels() {
        use std::os::fd::AsRawFd;
        #[cfg(all(target_os = "linux", target_env = "gnu"))]
        {
            use std::mem::offset_of;
            assert_eq!(offset_of!(libc::tcp_info, tcpi_state), 0);
            assert_eq!(offset_of!(libc::tcp_info, tcpi_rto), 8);
            assert_eq!(offset_of!(libc::tcp_info, tcpi_rtt), 68);
            assert_eq!(offset_of!(libc::tcp_info, tcpi_rttvar), TCP_INFO_NEEDED);
        }
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let c = std::net::TcpStream::connect(l.local_addr().unwrap()).unwrap();
        let i = conn_info(c.as_raw_fd()).unwrap();
        eprintln!("TCP_INFO of a loopback connection: {i:?}");
        assert_eq!(i.state, TcpState::Established);
        assert!(i.rto >= Duration::from_millis(200), "{i:?}");
        assert!(i.rtt < Duration::from_secs(1), "{i:?}");
    }

    /// Review round 3, cross-1 (mutant X30): a connect whose `poll` reports a hang-up or an error
    /// with no error set is a failed probe, never an unreachable (far); a pending error is that
    /// error; neither is connected.
    #[cfg(target_os = "macos")]
    #[test]
    fn a_hang_up_without_an_error_is_a_failed_probe_on_macos() {
        for ev in [libc::POLLHUP, libc::POLLERR, libc::POLLHUP | libc::POLLOUT] {
            let r = connect_result(ev, Ok(None));
            let o = ProbeOutcome::of(r);
            assert!(matches!(o, ProbeOutcome::Failed(_)), "{ev}: {o:?}");
            assert!(matches!(o.verdict(), Verdict::Failed(_)));
        }
        let e = || io::Error::from_raw_os_error(libc::EHOSTUNREACH);
        assert_eq!(
            ProbeOutcome::of(connect_result(libc::POLLHUP, Ok(Some(e())))),
            ProbeOutcome::Unreachable
        );
        assert_eq!(
            ProbeOutcome::of(connect_result(libc::POLLOUT, Ok(Some(e())))),
            ProbeOutcome::Unreachable
        );
        assert_eq!(
            ProbeOutcome::of(connect_result(
                libc::POLLHUP,
                Err(io::Error::from_raw_os_error(libc::ECONNREFUSED))
            )),
            ProbeOutcome::Refused
        );
        assert_eq!(
            ProbeOutcome::of(connect_result(libc::POLLOUT, Ok(None))),
            ProbeOutcome::Connected
        );
    }

    /// Review round 3, cross-1 (mutant X37; the reviewer's `x37_test.rs`): the real probe's own
    /// timeout (`poll` returning 0) is no answer (a check connection follows), never unreachable
    /// (far). TEST-NET-1 is routed out the default route and answered by nothing. Skipped when
    /// the probe fails here (no default route).
    #[cfg(target_os = "macos")]
    #[test]
    fn a_silent_destination_is_no_answer_to_the_real_probe_on_macos() {
        let dst: SocketAddr = "192.0.2.1:443".parse().unwrap();
        let o = TtlProbe.probe(dst, 64, Duration::from_millis(400));
        eprintln!("{dst}: {o:?}");
        if matches!(o, ProbeOutcome::Failed(_)) {
            crate::skipped(format!("the probe of {dst} failed here: {o:?}"));
            return;
        }
        assert_eq!(o, ProbeOutcome::TimedOut);
        assert_eq!(o.verdict(), Verdict::Undecided);
    }

    /// Review round 3, probe-1 (every platform since the Linux application): a probe that timed
    /// out is asked once more within the same time (two thirds, then the rest); any other outcome
    /// of the first attempt stands.
    #[cfg(unix)]
    #[test]
    fn a_probe_that_timed_out_is_asked_again_once() {
        let timeout = Duration::from_millis(1500);
        let mut asked = Vec::new();
        let r = probe_twice(timeout, |t| {
            asked.push(t);
            Err(io::ErrorKind::TimedOut.into())
        });
        assert_eq!(r.unwrap_err().kind(), io::ErrorKind::TimedOut);
        assert_eq!(
            asked,
            [Duration::from_millis(1000), Duration::from_millis(500)]
        );
        let mut n = 0;
        let r = probe_twice(timeout, |_| {
            n += 1;
            if n == 1 {
                Err(io::ErrorKind::TimedOut.into())
            } else {
                Err(io::Error::from_raw_os_error(libc::EHOSTUNREACH))
            }
        });
        assert_eq!(ProbeOutcome::of(r), ProbeOutcome::Unreachable);
        for first in [
            Ok(()),
            Err(io::Error::from_raw_os_error(libc::EHOSTUNREACH)),
            Err(io::Error::from_raw_os_error(libc::ECONNREFUSED)),
        ] {
            let mut first = Some(first);
            let mut n = 0;
            let _ = probe_twice(timeout, |_| {
                n += 1;
                first.take().unwrap()
            });
            assert_eq!(n, 1);
        }
    }

    /// Review round 3, probe-1 (every platform with a check connection since the Linux
    /// application): a FIN unacknowledged within the hop limit is far only if the peer
    /// acknowledges it once the default hop limit is restored (the positive control); a FIN
    /// acknowledged at no hop limit, and a peer that closes or resets meanwhile, is a failure,
    /// never far, and the refusal names the cause (S3).
    #[test]
    fn a_fin_acknowledged_at_no_hop_limit_is_never_far() {
        use TcpState::*;
        for acked in [FinWait2, TimeWait] {
            assert_eq!(fin_after_control(acked), Some(ConfirmOutcome::Unanswered));
        }
        assert_eq!(fin_after_control(FinWait1), None);
        assert_eq!(fin_after_control(Closing), None);
        for state in [Closed, CloseWait, LastAck, Established] {
            assert!(
                matches!(fin_after_control(state), Some(ConfirmOutcome::Failed(_))),
                "{state:?}"
            );
        }
        for state in [FinWait1, Closing, Closed] {
            let o = fin_after_control_deadline(state);
            assert!(matches!(o, ConfirmOutcome::Failed(_)), "{state:?}: {o:?}");
            assert!(matches!(o.verdict(), Verdict::Failed(_)));
        }
        let o = fin_after_control_deadline(FinWait1);
        assert!(
            matches!(&o, ConfirmOutcome::Failed(w) if w.contains("neither within the hop limit nor") && w.contains("S3")),
            "{o:?}"
        );
        // What the operator reads: the refusal names the cause.
        let Verdict::Failed(why) = o.verdict() else {
            unreachable!()
        };
        let d = crate::Denied::NearHop {
            addr: "52.216.0.1:443".parse().unwrap(),
            hops: 2,
            what: format!("the probe failed: {why}"),
        };
        assert!(UNACKED_FIN.chars().count() <= 120);
        assert!(d.to_string().contains("(AWS S3 never does)"), "{d}");
    }

    /// Review round 3, probe-1, live: AWS S3's front ends never acknowledge a bare FIN, at any
    /// hop limit (`r3-probe/finack-s3.log`), so the check connection read them as far at any
    /// distance; with the positive control they are a failed check (refused when the probe had no
    /// answer: the cost, docs/netguard-macos.md). Skipped when S3 cannot be reached, or when it
    /// now acknowledges a bare FIN at the default hop limit.
    #[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
    #[test]
    fn a_peer_that_never_acknowledges_a_fin_is_not_far() {
        use std::net::ToSocketAddrs;
        use std::os::fd::AsRawFd;
        let Some(addr) = ("s3.amazonaws.com", 443)
            .to_socket_addrs()
            .ok()
            .and_then(|mut a| a.find(SocketAddr::is_ipv4))
        else {
            crate::skipped("s3.amazonaws.com does not resolve here");
            return;
        };
        // Does it acknowledge a bare FIN at the default hop limit within 2 s?
        let Ok(c) = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)) else {
            crate::skipped(format!("{addr} unreachable here"));
            return;
        };
        c.shutdown(std::net::Shutdown::Write).unwrap();
        let t = std::time::Instant::now();
        let mut acked = false;
        while t.elapsed() < Duration::from_secs(2) && !acked {
            acked = matches!(
                conn_info(c.as_raw_fd()).map(|i| i.state),
                Ok(TcpState::FinWait2 | TcpState::TimeWait)
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        drop(c);
        if acked {
            crate::skipped(format!("{addr} now acknowledges a bare FIN"));
            return;
        }
        let o = TtlProbe.confirm(addr, 2, Duration::from_secs(5));
        eprintln!("{addr}, hop limit 2: {o:?}");
        if let ConfirmOutcome::ConnectFailed(e) = &o {
            crate::skipped(format!("{addr} unreachable here: {e}"));
            return;
        }
        assert!(matches!(o, ConfirmOutcome::Failed(_)), "{o:?}");
        assert_ne!(o.verdict(), Verdict::Far);
    }

    /// probe-1, live: a loopback peer that closes, or resets, each connection as soon as it
    /// accepts it is never found far, and is refused either way (near when the FIN was
    /// acknowledged before the peer's close, a failure when the peer closed first). And a far
    /// public peer that closes each connection at once (a NIST daytime server, port 13): its FIN
    /// crosses the check's, which dies two hops out; the check is a failure, refused but not
    /// near (before this change it was read as near). Skipped where that server is unreachable.
    #[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
    #[test]
    fn a_peer_that_closes_first_is_never_far() {
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

    /// probe-2 (every platform since the Linux application): the probe and the check connection
    /// connect to an IPv4-mapped address as its IPv4 address, so the hop limit holds (on macOS an
    /// IPv6 socket's hop limit did not limit the IPv4 packets a mapped connection sends: the
    /// probe of a far host connected). Skipped where 1.1.1.1 is unreachable.
    #[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
    #[test]
    fn a_mapped_address_is_probed_as_its_ipv4_address() {
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
