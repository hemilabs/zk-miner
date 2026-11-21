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
//!   exceeded" from the router where the probe ran out of hops ends a connect): the destination
//!   is farther: the real connection is made, on a new socket with the default hop limit;
//! - **no answer in time**: no evidence either way (a path that filters ICMP, or a near host that
//!   drops SYNs for a while: a full accept queue, a SYN rate limit, a neighbour being resolved, a
//!   device waking up). So the destination is **checked once connected**
//!   ([`NearProbe::confirm`]): a check connection is made with the default hop limit (no data is
//!   ever written on it), and once it is established its hop limit is lowered to the probe's and
//!   it is half-closed: the FIN can reach the peer only if the peer is within the limit, and a
//!   peer that gets it acknowledges it. Acknowledged (or answered with a reset) within a few round
//!   trips: near, refused. Unacknowledged: far, and the real connection is made. The check
//!   connection failing to connect refuses too (the real one would fail the same way);
//! - **any other error** (a local firewall's `EPERM`/`EACCES`, `EADDRNOTAVAIL`, …): refused.
//!
//! The probe is closed without sending data (a reset if it connected). Unprivileged.
//!
//! **Windows** keeps retrying a SYN an ICMP error answered, so the probe sets
//! `TCP_FAIL_CONNECT_ON_ICMP_ERROR` and reads which ICMP message ended the connect
//! ([`ProbeOutcome::of_icmp`]: "time exceeded" is far). Where the message does not reach TCP
//! (as seen on Windows 11, likely withheld by the firewall) a far destination's probe times out,
//! and the check connection, which reads the FIN's fate from `SIO_TCP_INFO`, decides: every
//! connection then waits out [`PROBE_TIMEOUT`] first. Elsewhere than Linux and Windows the check
//! connection fails, so a probe without an answer refuses.
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
        #[cfg(windows)]
        {
            probe_windows(addr, hops, timeout)
        }
        #[cfg(not(windows))]
        {
            ProbeOutcome::of(probe_once(addr, hops, timeout))
        }
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

impl ProbeOutcome {
    /// What an ICMP error that ended a probe's connect says (Windows reports it apart from the
    /// error code, as `TCP_ICMP_ERROR_INFO`): "time exceeded" is the probe running out of hops
    /// (far); "port" or "protocol unreachable" comes from the destination itself (refused, as
    /// Linux reads it: `ECONNREFUSED`); any other "destination unreachable" is unreachable, as
    /// Linux's `EHOSTUNREACH` reads it. `None` for any other message.
    pub fn of_icmp(v6: bool, icmp_type: u8, code: u8) -> Option<Self> {
        match (v6, icmp_type, code) {
            (false, 11, _) | (true, 3, _) => Some(ProbeOutcome::Unreachable),
            (false, 3, 2 | 3) | (true, 1, 4) => Some(ProbeOutcome::Refused),
            (false, 3, _) | (true, 1, _) => Some(ProbeOutcome::Unreachable),
            _ => None,
        }
    }
}

#[cfg(not(windows))]
fn probe_once(addr: SocketAddr, hops: u8, timeout: Duration) -> io::Result<()> {
    let sock = new_socket(addr)?;
    set_hops(&sock, addr, hops)?;
    let r = sock.connect_timeout(&addr.into(), timeout);
    // Closed with a reset, never a byte of data.
    let _ = sock.set_linger(Some(Duration::ZERO));
    drop(sock);
    r
}

/// The probe on Windows, whose TCP keeps retrying a SYN an ICMP "time exceeded" answered unless
/// told otherwise: with `TCP_FAIL_CONNECT_ON_ICMP_ERROR` the connect ends on the ICMP error, and
/// `TCP_ICMP_ERROR_INFO` says which it was ([`ProbeOutcome::of_icmp`]). Where the ICMP error never
/// reaches TCP (the option unknown before Windows 10 1903, or the firewall withholding the
/// message, as seen on Windows 11) the probe times out instead, and the check connection
/// decides.
#[cfg(windows)]
fn probe_windows(addr: SocketAddr, hops: u8, timeout: Duration) -> ProbeOutcome {
    let sock = match new_socket(addr) {
        Ok(s) => s,
        Err(e) => return ProbeOutcome::of(Err(e)),
    };
    if let Err(e) = set_hops(&sock, addr, hops) {
        return ProbeOutcome::of(Err(e));
    }
    win::fail_connect_on_icmp(&sock);
    let r = sock.connect_timeout(&addr.into(), timeout);
    let icmp = if r.is_err() {
        win::icmp_error(&sock)
    } else {
        None
    };
    // Closed with a reset, never a byte of data.
    let _ = sock.set_linger(Some(Duration::ZERO));
    drop(sock);
    icmp.and_then(|(v6, t, c)| ProbeOutcome::of_icmp(v6, t, c))
        .unwrap_or_else(|| ProbeOutcome::of(r))
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

/// Where a check connection's FIN stands, by its TCP state (Windows `TCPSTATE`).
#[cfg(any(windows, test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FinState {
    /// Sent and not acknowledged yet (`FIN_WAIT_1`, `LAST_ACK`).
    Pending,
    /// Acknowledged, or the peer reset (`FIN_WAIT_2`, `CLOSING`, `TIME_WAIT`, `CLOSED`): as Linux
    /// reads every state past `FIN_WAIT_1`.
    Answered,
    /// Not sent (`ESTABLISHED`, `CLOSE_WAIT`, or a state a connected socket never has): no
    /// evidence either way.
    NotSent,
}

#[cfg(any(windows, test))]
fn windows_fin_state(state: i32) -> FinState {
    match state {
        5 | 10 => FinState::Pending,
        0 | 6 | 7 | 8 => FinState::Answered,
        _ => FinState::NotSent,
    }
}

/// The check connection (see the module doc). Windows: the FIN's fate is read from
/// `SIO_TCP_INFO` (Windows 10 1703 and later), as Linux reads it from `TCP_INFO`. A FIN still
/// unsent when the wait ends is no evidence: refused.
#[cfg(windows)]
fn confirm_once(addr: SocketAddr, hops: u8, timeout: Duration) -> ConfirmOutcome {
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
    let rtt = match win::tcp_info(&sock) {
        Ok(i) => Duration::from_micros(u64::from(i.RttUs)),
        Err(e) => return ConfirmOutcome::Failed(format!("SIO_TCP_INFO: {e}")),
    };
    if let Err(e) = sock.shutdown(std::net::Shutdown::Write) {
        return ConfirmOutcome::Failed(e.to_string());
    }
    let wait = (rtt * 4 + Duration::from_millis(250))
        .clamp(Duration::from_millis(300), Duration::from_millis(1500));
    let deadline = std::time::Instant::now() + wait;
    loop {
        let state = match win::tcp_info(&sock) {
            Ok(i) => windows_fin_state(i.State),
            // The peer reset the connection: as Linux reads `CLOSE`.
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted
                ) =>
            {
                FinState::Answered
            }
            Err(e) => return ConfirmOutcome::Failed(format!("SIO_TCP_INFO: {e}")),
        };
        if state == FinState::Answered {
            return ConfirmOutcome::Answered;
        }
        if std::time::Instant::now() >= deadline {
            return match state {
                FinState::Pending => ConfirmOutcome::Unanswered,
                _ => ConfirmOutcome::Failed("the check connection's FIN was not sent".into()),
            };
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[cfg(windows)]
mod win {
    //! Winsock calls the probe and the check connection make.

    use std::io;
    use std::os::windows::io::AsRawSocket;

    use windows_sys::Win32::Networking::WinSock::{
        getsockopt, setsockopt, TCP_INFO_v0, WSAGetLastError, ICMP_ERROR_INFO, IPPROTO_TCP,
        SIO_TCP_INFO, SOCKET, TCP_FAIL_CONNECT_ON_ICMP_ERROR, TCP_ICMP_ERROR_INFO,
    };

    // `WSAIoctl` as declared in winsock2.h (windows-sys gates it behind a feature this crate does
    // not enable, for its `OVERLAPPED` argument, which is always null here).
    #[link(name = "ws2_32")]
    extern "system" {
        fn WSAIoctl(
            s: SOCKET,
            code: u32,
            inbuf: *const core::ffi::c_void,
            inlen: u32,
            outbuf: *mut core::ffi::c_void,
            outlen: u32,
            returned: *mut u32,
            overlapped: *mut core::ffi::c_void,
            completion: *const core::ffi::c_void,
        ) -> i32;
    }

    fn last_error() -> io::Error {
        // SAFETY: no arguments; reads the calling thread's last Winsock error.
        io::Error::from_raw_os_error(unsafe { WSAGetLastError() })
    }

    /// Ends the socket's connect on an ICMP error (best effort: older Windows does not know the
    /// option, and the probe then times out instead).
    pub(super) fn fail_connect_on_icmp(sock: &socket2::Socket) {
        let on: u32 = 1;
        // SAFETY: a valid socket, and a DWORD option value of the size given.
        unsafe {
            setsockopt(
                sock.as_raw_socket() as SOCKET,
                IPPROTO_TCP,
                TCP_FAIL_CONNECT_ON_ICMP_ERROR,
                (&on as *const u32).cast(),
                std::mem::size_of::<u32>() as i32,
            )
        };
    }

    /// The ICMP error that ended the socket's connect, if one did: (IPv6, type, code).
    pub(super) fn icmp_error(sock: &socket2::Socket) -> Option<(bool, u8, u8)> {
        // SAFETY: plain data, overwritten by the call.
        let mut info: ICMP_ERROR_INFO = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of::<ICMP_ERROR_INFO>() as i32;
        // SAFETY: a valid socket, and `info` and `len` valid for the size given.
        let rc = unsafe {
            getsockopt(
                sock.as_raw_socket() as SOCKET,
                IPPROTO_TCP,
                TCP_ICMP_ERROR_INFO,
                (&mut info as *mut ICMP_ERROR_INFO).cast(),
                &mut len,
            )
        };
        if rc != 0 || len < std::mem::size_of::<ICMP_ERROR_INFO>() as i32 {
            return None;
        }
        match info.protocol {
            1 => Some((false, info.r#type, info.code)),
            58 => Some((true, info.r#type, info.code)),
            _ => None,
        }
    }

    /// `SIO_TCP_INFO`, version 0.
    pub(super) fn tcp_info(sock: &socket2::Socket) -> io::Result<TCP_INFO_v0> {
        let version: u32 = 0;
        // SAFETY: plain data, overwritten by the call.
        let mut info: TCP_INFO_v0 = unsafe { std::mem::zeroed() };
        let mut returned: u32 = 0;
        // SAFETY: a valid socket; the in and out buffers are valid for the sizes given; no
        // overlapped I/O.
        let rc = unsafe {
            WSAIoctl(
                sock.as_raw_socket() as SOCKET,
                SIO_TCP_INFO,
                (&version as *const u32).cast(),
                std::mem::size_of::<u32>() as u32,
                (&mut info as *mut TCP_INFO_v0).cast(),
                std::mem::size_of::<TCP_INFO_v0>() as u32,
                &mut returned,
                std::ptr::null_mut(),
                std::ptr::null(),
            )
        };
        if rc != 0 {
            return Err(last_error());
        }
        Ok(info)
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android", windows)))]
fn confirm_once(_: SocketAddr, _: u8, _: Duration) -> ConfirmOutcome {
    ConfirmOutcome::Failed("the check connection is supported on Linux and Windows only".into())
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

    #[cfg(windows)]
    #[test]
    fn windows_outcomes_are_classified() {
        // WSAECONNREFUSED, WSAECONNRESET, WSAEHOSTUNREACH, WSAENETUNREACH, WSAETIMEDOUT.
        let os = |e: i32| ProbeOutcome::of(Err(io::Error::from_raw_os_error(e)));
        assert_eq!(os(10061), ProbeOutcome::Refused);
        assert_eq!(os(10054), ProbeOutcome::Reset);
        assert_eq!(os(10065).verdict(), Verdict::Far);
        assert_eq!(os(10051).verdict(), Verdict::Far);
        assert_eq!(os(10060).verdict(), Verdict::Undecided);
        // WSAEACCES, WSAEADDRNOTAVAIL, WSAEINVAL.
        for e in [10013, 10049, 10022] {
            assert!(matches!(os(e).verdict(), Verdict::Failed(_)), "{e}");
        }
    }

    /// The ICMP message that ended a Windows probe's connect: time exceeded is far, port and
    /// protocol unreachable come from the destination (near), other unreachables are far as on
    /// Linux; anything else says nothing (the error code decides).
    #[test]
    fn icmp_errors_are_classified() {
        let of = ProbeOutcome::of_icmp;
        assert_eq!(of(false, 11, 0), Some(ProbeOutcome::Unreachable));
        assert_eq!(of(true, 3, 0), Some(ProbeOutcome::Unreachable));
        assert_eq!(of(false, 3, 3), Some(ProbeOutcome::Refused));
        assert_eq!(of(false, 3, 2), Some(ProbeOutcome::Refused));
        assert_eq!(of(true, 1, 4), Some(ProbeOutcome::Refused));
        assert_eq!(of(false, 3, 1), Some(ProbeOutcome::Unreachable));
        assert_eq!(of(false, 3, 13), Some(ProbeOutcome::Unreachable));
        assert_eq!(of(true, 1, 0), Some(ProbeOutcome::Unreachable));
        // Not errors that end a connect: an echo reply, a redirect, IPv6 "packet too big".
        assert_eq!(of(false, 0, 0), None);
        assert_eq!(of(false, 5, 1), None);
        assert_eq!(of(true, 2, 0), None);
        // A type is read in its own family: IPv4 type 11 is not IPv6 time exceeded.
        assert_eq!(of(true, 11, 0), None);
    }

    /// A Windows check connection's TCP state: only a FIN sent and unacknowledged reads as far
    /// (at the deadline); acknowledged or reset is near; a FIN never sent is neither.
    #[test]
    fn windows_fin_states() {
        assert_eq!(windows_fin_state(5), FinState::Pending); // FIN_WAIT_1
        assert_eq!(windows_fin_state(10), FinState::Pending); // LAST_ACK
        for s in [0, 6, 7, 8] {
            assert_eq!(windows_fin_state(s), FinState::Answered, "{s}");
        }
        for s in [1, 2, 3, 4, 9, 11, -1] {
            assert_eq!(windows_fin_state(s), FinState::NotSent, "{s}");
        }
    }

    /// The check connection against a listener on loopback (zero hops): its FIN is acknowledged,
    /// near.
    #[cfg(any(target_os = "linux", target_os = "android", windows))]
    #[test]
    fn the_check_connection_finds_a_local_listener_near() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let accept = std::thread::spawn(move || {
            let s = l.accept();
            std::thread::sleep(Duration::from_secs(3));
            drop(s);
        });
        assert_eq!(
            TtlProbe.confirm(addr, 2, Duration::from_secs(5)),
            ConfirmOutcome::Answered
        );
        accept.join().unwrap();
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
        let closed = TtlProbe.probe(addr, 2, PROBE_TIMEOUT);
        // Windows retries a connect a reset answered for about two seconds, so the probe may
        // time out; the check connection then fails to connect, which refuses too.
        #[cfg(windows)]
        if closed == ProbeOutcome::TimedOut {
            assert!(
                matches!(decide(&TtlProbe, addr, 2), Verdict::Failed(_)),
                "a closed local port"
            );
            return;
        }
        assert_eq!(closed, ProbeOutcome::Refused);
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
