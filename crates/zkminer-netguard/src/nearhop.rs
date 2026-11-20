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
//! once for a connection into a directly attached network, before any packet is sent. The probe
//! reads that as far, as it reads any unreachable; it changes nothing, because the real
//! connection fails the same way, and such destinations (on-link) are refused by the address and
//! route checks before any probe.
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

fn probe_once(addr: SocketAddr, hops: u8, timeout: Duration) -> io::Result<()> {
    let sock = new_socket(addr)?;
    set_hops(&sock, addr, hops)?;
    let r = sock.connect_timeout(&addr.into(), timeout);
    // Closed with a reset, never a byte of data.
    let _ = sock.set_linger(Some(Duration::ZERO));
    drop(sock);
    r
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
/// states are <netinet/tcp_fsm.h>'s). macOS keeps an ICMP "time exceeded" for the FIN as a soft
/// error it never reports (`SO_ERROR` stays 0), so a far peer is found only by the deadline
/// passing: the same verdict as on Linux, without Linux's early answer.
#[cfg(target_os = "macos")]
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
    let info = |fd: i32| -> io::Result<libc::tcp_connection_info> {
        // SAFETY: a zeroed tcp_connection_info (plain integers) is valid to be overwritten by
        // getsockopt.
        let mut i: libc::tcp_connection_info = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of::<libc::tcp_connection_info>() as libc::socklen_t;
        // SAFETY: `i` and `len` are valid for the size given.
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
        Ok(i)
    };
    let fd = sock.as_raw_fd();
    let rtt = match info(fd) {
        // Milliseconds; the smoothed round trip, or the last one before there is one.
        Ok(i) => Duration::from_millis(u64::from(i.tcpi_srtt.max(i.tcpi_rttcur))),
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
    const TCPS_FIN_WAIT_1: u8 = 6;
    loop {
        match info(fd) {
            // FIN_WAIT_2, CLOSING, TIME_WAIT, CLOSED: the FIN was acknowledged, or the peer reset.
            Ok(i) if i.tcpi_state != TCPS_FIN_WAIT_1 => return ConfirmOutcome::Answered,
            Ok(_) => {}
            Err(e) => return ConfirmOutcome::Failed(e.to_string()),
        }
        if std::time::Instant::now() >= deadline {
            return ConfirmOutcome::Unanswered;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
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

    /// The check connection to a listener on loopback (zero hops) and to an IPv6 one: answered,
    /// near. Its hop-limited FIN reaches them and is acknowledged.
    #[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
    #[test]
    fn the_check_connection_finds_a_local_listener_near() {
        for bind in ["127.0.0.1:0", "[::1]:0"] {
            let Ok(l) = std::net::TcpListener::bind(bind) else {
                eprintln!("SKIPPED: no {bind} here");
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
            ConfirmOutcome::ConnectFailed(e) => eprintln!("SKIPPED: {addr} unreachable here: {e}"),
            other => assert_eq!(other, ConfirmOutcome::Unanswered),
        }
    }
}
