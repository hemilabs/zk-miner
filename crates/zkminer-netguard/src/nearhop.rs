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
//!   ([`NearProbe::confirm`]): a check connection and a control connection are made with the
//!   default hop limit (no data is ever written on either); the check connection's hop limit is
//!   then lowered to the probe's for good and both are half-closed: the check's FIN can reach the
//!   peer only if the peer is within the limit, the control's always does, and a peer that gets a
//!   FIN acknowledges it. The check's FIN acknowledged, whenever: near, refused. Far only once the
//!   control's FIN was acknowledged and the check's was not for a few round trips, one
//!   retransmission and the control's time again (review round 4, probe-1); then the real
//!   connection is made. A control never acknowledged, a peer that closes or resets first, a check
//!   connection that fails to connect: refused (the real one would fail the same way). Linux reads
//!   the FINs' fate from `TCP_INFO`, macOS from `TCP_CONNECTION_INFO`; elsewhere there is no check
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
use std::time::{Duration, Instant};

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

    /// [`Self::probe`], given up on at `deadline` (a turn waited for, attempts, pauses: review
    /// round 5, probe-1). A probe that knows no deadline (a test's fake) ignores it.
    fn probe_until(
        &self,
        addr: SocketAddr,
        hops: u8,
        timeout: Duration,
        deadline: Instant,
    ) -> ProbeOutcome {
        let _ = deadline;
        self.probe(addr, hops, timeout)
    }

    /// Review round 6, probe-4: one more probe attempt, after `pause`, for a destination whose
    /// probe had no answer and whose check connection could not decide (every AWS S3 front end
    /// resets or never acknowledges it: a router's ICMP loss can outlast the probe's three
    /// attempts). A probe that knows no such attempt (a test's fake) has no answer.
    fn probe_last_until(
        &self,
        addr: SocketAddr,
        hops: u8,
        pause: Duration,
        deadline: Instant,
    ) -> ProbeOutcome {
        let _ = (addr, hops, pause, deadline);
        ProbeOutcome::TimedOut
    }

    /// [`Self::confirm`], given up on at `deadline` (a failure, never far).
    fn confirm_until(
        &self,
        addr: SocketAddr,
        hops: u8,
        timeout: Duration,
        deadline: Instant,
    ) -> ConfirmOutcome {
        let _ = deadline;
        self.confirm(addr, hops, timeout)
    }
}

/// The longest the near-hop decision takes when nothing bounds it ([`decide`]): the probe's
/// attempts and pause, two connects of the check connection and its wait, and turns waited for.
pub const DECIDE_BUDGET: Duration = Duration::from_secs(40);

/// The near-hop decision for a connection to `addr` (see the module doc): the probe, and when it
/// had no answer, the check connection. Blocking (up to [`PROBE_TIMEOUT`], plus
/// [`CONFIRM_CONNECT_TIMEOUT`] and a few round trips when the probe had no answer).
pub fn decide(probe: &dyn NearProbe, addr: SocketAddr, hops: u8) -> Verdict {
    decide_until(probe, addr, hops, Instant::now() + DECIDE_BUDGET)
}

/// [`decide`], given up on at `deadline` (review round 5, probe-1): a caller that stops waiting
/// (the broker's connector, a guarded request whose budget ran out) passes its own, so the work
/// it abandons stops too and gives back its turn ([`ProbeGate`]) instead of running on for
/// seconds. Out of time is a failure (refused), never far.
pub fn decide_until(probe: &dyn NearProbe, addr: SocketAddr, hops: u8, deadline: Instant) -> Verdict {
    let left = || deadline.saturating_duration_since(Instant::now());
    if left().is_zero() {
        return Verdict::Failed(OUT_OF_TIME.into());
    }
    match probe.probe_until(addr, hops, PROBE_TIMEOUT, deadline).verdict() {
        Verdict::Undecided => {
            if left().is_zero() {
                return Verdict::Failed(OUT_OF_TIME.into());
            }
            let timeout = CONFIRM_CONNECT_TIMEOUT.min(left());
            match probe.confirm_until(addr, hops, timeout, deadline).verdict() {
                // Never undecided twice.
                Verdict::Undecided => Verdict::Failed("no answer either way".into()),
                Verdict::Failed(why) => {
                    // Review round 6, probe-4: the probe once more, when the time allows it.
                    if left() < PROBE_LAST_PAUSE + PROBE_TIMEOUT {
                        return Verdict::Failed(why);
                    }
                    match probe
                        .probe_last_until(addr, hops, PROBE_LAST_PAUSE, deadline)
                        .verdict()
                    {
                        Verdict::Undecided => Verdict::Failed(why),
                        v => v,
                    }
                }
                v => v,
            }
        }
        v => v,
    }
}

/// How long the probe's last attempt waits ([`NearProbe::probe_last_until`]).
pub const PROBE_LAST_PAUSE: Duration = Duration::from_secs(2);

/// Why a decision out of time failed.
const OUT_OF_TIME: &str = "the time for the check ran out before it could tell how near it is";

/// The real probe: a fresh TCP socket with its hop limit set, connected without sending data.
#[derive(Debug, Clone, Copy, Default)]
pub struct TtlProbe;

impl NearProbe for TtlProbe {
    fn probe(&self, addr: SocketAddr, hops: u8, timeout: Duration) -> ProbeOutcome {
        self.probe_until(addr, hops, timeout, Instant::now() + DECIDE_BUDGET)
    }

    fn confirm(&self, addr: SocketAddr, hops: u8, timeout: Duration) -> ConfirmOutcome {
        self.confirm_until(addr, hops, timeout, Instant::now() + DECIDE_BUDGET)
    }

    fn probe_until(
        &self,
        addr: SocketAddr,
        hops: u8,
        timeout: Duration,
        deadline: Instant,
    ) -> ProbeOutcome {
        ProbeOutcome::of(probe_once(addr, hops, timeout, deadline))
    }

    fn confirm_until(
        &self,
        addr: SocketAddr,
        hops: u8,
        timeout: Duration,
        deadline: Instant,
    ) -> ConfirmOutcome {
        confirm_once(addr, hops, timeout, deadline)
    }

    fn probe_last_until(
        &self,
        addr: SocketAddr,
        hops: u8,
        pause: Duration,
        deadline: Instant,
    ) -> ProbeOutcome {
        std::thread::sleep(pause.min(deadline.saturating_duration_since(Instant::now())));
        ProbeOutcome::of(probe_turn(unmapped(addr), hops, PROBE_TIMEOUT * 2 / 3, deadline))
    }
}

/// How long a far verdict is remembered ([`remembered_far`]).
pub const FAR_TTL: Duration = Duration::from_secs(10);
/// Most far verdicts remembered.
const MAX_FAR: usize = 256;

/// A far verdict's key: the destination (address and port: a router can send one port elsewhere,
/// a transparent proxy), the hop limit, the facts the path was judged on (their routes, rules,
/// addresses and uplink signature: [`crate::HostFacts`]), and the probe.
pub(crate) type FarKey = (SocketAddr, u8, u64, usize);

/// The far verdicts of the last [`FAR_TTL`] (review round 6, probe-3: the pacer let 2 probes at
/// once and 3 a second through, process-wide, so 64 connections at once to four hosts left 28
/// refused after 17 s). Only far is remembered (near and failed never are), for one exact
/// destination and port, never a prefix: a /24 or /48 can hold both a far host and a near one
/// (an ISP's access router and its data centre), so a far verdict for one would admit the other.
/// Any change of the facts (a route, a rule, an address, the uplink) is another key.
static FAR: std::sync::Mutex<Vec<(FarKey, Instant)>> = std::sync::Mutex::new(Vec::new());

/// Whether `key` was found far within [`FAR_TTL`] of `now`.
pub(crate) fn remembered_far(key: FarKey, now: Instant) -> bool {
    let mut far = FAR.lock().unwrap_or_else(|e| e.into_inner());
    far.retain(|(_, at)| now.saturating_duration_since(*at) < FAR_TTL);
    far.iter().any(|(k, _)| *k == key)
}

/// The keys a decision is running for ([`decide_remembered`]).
static DECIDING: std::sync::Mutex<Vec<FarKey>> = std::sync::Mutex::new(Vec::new());
static DECIDED: std::sync::Condvar = std::sync::Condvar::new();

/// `decide` (the near-hop decision for `key`'s destination), unless a far verdict for `key` is
/// remembered ([`remembered_far`]); a far one is remembered. One decision runs per key at a
/// time: a caller that finds one running waits for it (until `deadline`), then takes its far
/// verdict, or decides itself (review round 6, probe-3: 64 connections at once to four hosts
/// each sent their own probes). `None` (facts given by the caller): `decide`, nothing remembered.
pub(crate) fn decide_remembered(
    key: Option<FarKey>,
    deadline: Instant,
    decide: impl FnOnce() -> Verdict,
) -> Verdict {
    let Some(key) = key else { return decide() };
    let mut g = DECIDING.lock().unwrap_or_else(|e| e.into_inner());
    loop {
        let now = Instant::now();
        if remembered_far(key, now) {
            return Verdict::Far;
        }
        if !g.contains(&key) {
            g.push(key);
            break;
        }
        let left = deadline.saturating_duration_since(now);
        if left.is_zero() {
            return Verdict::Failed(OUT_OF_TIME.into());
        }
        g = DECIDED
            .wait_timeout(g, left.min(TOKEN_INTERVAL))
            .unwrap_or_else(|e| e.into_inner())
            .0;
    }
    drop(g);
    /// Gives the key back however `decide` ends (a panic included).
    struct Done(FarKey);
    impl Drop for Done {
        fn drop(&mut self) {
            DECIDING
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .retain(|k| *k != self.0);
            DECIDED.notify_all();
        }
    }
    let done = Done(key);
    let v = decide();
    if v == Verdict::Far {
        remember_far(key, Instant::now());
    }
    drop(done);
    v
}

/// Remembers that `key` was found far at `now`.
pub(crate) fn remember_far(key: FarKey, now: Instant) {
    let mut far = FAR.lock().unwrap_or_else(|e| e.into_inner());
    far.retain(|(k, at)| *k != key && now.saturating_duration_since(*at) < FAR_TTL);
    if far.len() >= MAX_FAR {
        far.remove(0);
    }
    far.push((key, now));
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

/// The probe, on every platform: asked up to three times ([`probe_attempts`]), to the
/// destination as a connection reaches it ([`unmapped`]), at most [`PROBES_AT_ONCE`] probes in
/// the process at a time ([`ProbeGate`]).
fn probe_once(addr: SocketAddr, hops: u8, timeout: Duration, deadline: Instant) -> io::Result<()> {
    let addr = unmapped(addr);
    let left = || deadline.saturating_duration_since(Instant::now());
    probe_attempts(
        timeout,
        PROBE_PAUSE,
        left,
        |pause| std::thread::sleep(pause.min(left())),
        |t| probe_turn(addr, hops, t, deadline),
    )
}

/// One attempt of the probe, within `t` and the caller's `deadline` (review round 5, probe-1: a
/// turn waited for included; review round 6, parse-4 = probe-2, cross-7 N14: out of time, it
/// neither waits for a turn nor takes a token, and an attempt never runs past the deadline).
fn probe_turn(addr: SocketAddr, hops: u8, t: Duration, deadline: Instant) -> io::Result<()> {
    if deadline <= Instant::now() {
        return Err(io::ErrorKind::TimedOut.into());
    }
    let Some(_turn) = Turn::enter_for(addr, deadline) else {
        return Err(io::Error::other(NO_TURN));
    };
    let t = t.min(deadline.saturating_duration_since(Instant::now()));
    if t.is_zero() {
        return Err(io::ErrorKind::TimedOut.into());
    }
    probe_attempt(addr, hops, t)
}

/// Why a probe that got no turn before its deadline failed ([`ProbeGate::enter_until`]).
const NO_TURN: &str = "no turn to probe before the check's time ran out (too many probes at once)";

/// How long the probe pauses before its third attempt ([`probe_attempts`]): a router's ICMP rate
/// limit refills (Linux: one "time exceeded" a second per destination after a burst of six,
/// `icmp_ratelimit`).
pub const PROBE_PAUSE: Duration = Duration::from_secs(1);

/// The probe asked up to three times: two thirds of `timeout`, then, after a timeout, the rest;
/// then, after a further timeout, once more for two thirds of `timeout` after `pause` (review
/// round 3, probe-1; review round 4, probe-2). A router that rate-limits its ICMP drops some
/// "time exceeded" answers (7.5% of the reviewer's probes on a home path went unanswered:
/// `r3-probe/sweep-h2.log`; many more when 8 probes went at once: `r4-probe/exp`), and a probe
/// without an answer leaves the decision to the check connection, whose control connection
/// refuses a peer that never acknowledges a bare FIN (every AWS S3 front end), and which does
/// not exist on Windows (a probe without an answer is refused there). An answer comes within a
/// round trip to the router, milliseconds.
///
/// Review round 6 (parse-4 = probe-2): once the caller's time is out (`left`), no further attempt
/// is made.
fn probe_attempts(
    timeout: Duration,
    pause: Duration,
    left: impl Fn() -> Duration,
    sleep: impl FnOnce(Duration),
    mut attempt: impl FnMut(Duration) -> io::Result<()>,
) -> io::Result<()> {
    let first = timeout * 2 / 3;
    let timed_out = |r: &io::Result<()>| matches!(r, Err(e) if e.kind() == io::ErrorKind::TimedOut);
    let r = attempt(first);
    if !timed_out(&r) || left().is_zero() {
        return r;
    }
    let r = attempt(timeout - first);
    if !timed_out(&r) || left().is_zero() {
        return r;
    }
    sleep(pause);
    if left().is_zero() {
        return r;
    }
    attempt(first)
}

/// Most hop-limited probes in flight in the process at once (review round 4, probe-2): they go
/// through the same first hops, whose ICMP rate limit drops answers past a small burst.
pub const PROBES_AT_ONCE: usize = 2;

/// Most hop-limited probe SYNs sent in a burst, and how many a second after it (review round 5,
/// the probe lens's suspicion): [`PROBES_AT_ONCE`] bounds how many are in flight, not how many a
/// second, and a requester naming many far hosts could drain the first hops' ICMP rate limit
/// (Linux routers: about one "time exceeded" a second per destination after a burst of six), so
/// that ordinary probes went unanswered and fell to the check connection (which refuses every
/// AWS S3 front end). A turn waits for a token as it waits for a slot.
pub const PROBE_BURST: u32 = 6;
/// See [`PROBE_BURST`].
pub const PROBES_PER_SECOND: u32 = 3;

/// A token bucket of [`PROBE_BURST`] tokens, refilled at [`PROBES_PER_SECOND`]. Pure: tests drive
/// it with their own clock.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Pacer {
    tokens: f64,
    at: Option<Instant>,
}

impl Pacer {
    pub(crate) const fn new() -> Self {
        Pacer {
            tokens: PROBE_BURST as f64,
            at: None,
        }
    }

    /// The tokens there at `now` (fractional).
    pub(crate) fn available(&self, now: Instant) -> f64 {
        match self.at {
            Some(at) => (self.tokens
                + now.saturating_duration_since(at).as_secs_f64() * f64::from(PROBES_PER_SECOND))
            .min(f64::from(PROBE_BURST)),
            None => self.tokens,
        }
    }

    /// Takes a token at `now` (`Ok`), or says how long until one is there.
    pub(crate) fn take(&mut self, now: Instant) -> Result<(), Duration> {
        if let Some(at) = self.at {
            let refill = now.saturating_duration_since(at).as_secs_f64() * f64::from(PROBES_PER_SECOND);
            self.tokens = (self.tokens + refill).min(f64::from(PROBE_BURST));
        }
        self.at = Some(now);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            Ok(())
        } else {
            Err(Duration::from_secs_f64(
                (1.0 - self.tokens) / f64::from(PROBES_PER_SECOND),
            ))
        }
    }
}

/// A family's gate: turns in flight, the pacer, the callers waiting (their tickets, first come
/// first served) and the next ticket. A tuple so tests can stage it.
#[derive(Debug)]
pub(crate) struct GateState(usize, Pacer, std::collections::VecDeque<u64>, u64);

impl GateState {
    const fn new() -> Self {
        GateState(0, Pacer::new(), std::collections::VecDeque::new(), 0)
    }
}

/// The interval at which tokens come ([`PROBES_PER_SECOND`]): the longest a waiter sleeps before
/// it looks again (review round 6, parse-1: a wakeup handed to a waiter that then left was lost,
/// and another slept to its own deadline).
const TOKEN_INTERVAL: Duration = Duration::from_millis(1000 / PROBES_PER_SECOND as u64);

/// A turn to probe an IPv4 destination: at most [`PROBES_AT_ONCE`] are held at a time, and they
/// start at most as fast as [`Pacer`] allows; [`ProbeGate::enter_until`] waits for one until a
/// deadline. IPv6 destinations have a gate of their own ([`ProbeGateV6`]; review round 6,
/// probe-3: the first hops keep their ICMP and ICMPv6 rate limits apart, Linux's `icmp_ratelimit`
/// and `icmp/ratelimit`, and each family has its own default route, its own uplink).
struct ProbeGate;

/// A turn to probe an IPv6 destination (see [`ProbeGate`]).
struct ProbeGateV6;

static PROBES_IN_FLIGHT: std::sync::Mutex<GateState> = std::sync::Mutex::new(GateState::new());
static PROBE_TURN: std::sync::Condvar = std::sync::Condvar::new();
static PROBES_IN_FLIGHT_V6: std::sync::Mutex<GateState> = std::sync::Mutex::new(GateState::new());
static PROBE_TURN_V6: std::sync::Condvar = std::sync::Condvar::new();
/// How many times a turn waited for a token (tests).
#[cfg(test)]
static PACED: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// A turn of either family.
#[allow(dead_code)] // held for its Drop
enum Turn {
    V4(ProbeGate),
    V6(ProbeGateV6),
}

impl Turn {
    /// A turn for a probe of `addr`, waited for until `deadline`.
    fn enter_for(addr: SocketAddr, deadline: Instant) -> Option<Self> {
        if addr.is_ipv4() {
            ProbeGate::enter_until(deadline).map(Turn::V4)
        } else {
            ProbeGateV6::enter_until(deadline).map(Turn::V6)
        }
    }
}

/// Waits for a turn of the gate `m` (woken by `cv`) until `deadline` (review round 6, parse-1,
/// parse-4 = probe-2, probe-3): first come, first served (a ticket queue); none when the deadline
/// has passed, before a token is taken; none at once when the turns ahead need more tokens than
/// can come before the deadline (the caller sheds its load instead of waiting its whole budget
/// for a refusal); every change wakes every waiter, and none sleeps longer than
/// [`TOKEN_INTERVAL`], so a wakeup is never lost.
fn enter_gate(m: &std::sync::Mutex<GateState>, cv: &std::sync::Condvar, deadline: Instant) -> bool {
    if deadline <= Instant::now() {
        return false;
    }
    let mut g = m.lock().unwrap_or_else(|e| e.into_inner());
    let ticket = g.3;
    g.3 = g.3.wrapping_add(1);
    g.2.push_back(ticket);
    loop {
        let now = Instant::now();
        let left = deadline.saturating_duration_since(now);
        let mut wait = left.min(TOKEN_INTERVAL);
        let ahead = g.2.iter().position(|t| *t == ticket).unwrap_or(0);
        if ahead == 0 && g.0 < PROBES_AT_ONCE && !left.is_zero() {
            match g.1.take(now) {
                Ok(()) => {
                    g.0 += 1;
                    g.2.pop_front();
                    drop(g);
                    cv.notify_all();
                    return true;
                }
                Err(until_token) => {
                    #[cfg(test)]
                    PACED.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    wait = wait.min(until_token);
                }
            }
        }
        // At least one token for each turn ahead and this one: when they cannot come in time,
        // none will (unless one ahead gives up first: rare, and a refusal either way).
        let needed = (ahead + 1) as f64 - g.1.available(now);
        let expected = Duration::from_secs_f64(needed.max(0.0) / f64::from(PROBES_PER_SECOND));
        if left.is_zero() || expected > left {
            g.2.retain(|t| *t != ticket);
            drop(g);
            cv.notify_all();
            return false;
        }
        g = cv
            .wait_timeout(g, wait.max(Duration::from_millis(1)))
            .unwrap_or_else(|e| e.into_inner())
            .0;
    }
}

/// Gives a turn of the gate `m` back.
fn leave_gate(m: &std::sync::Mutex<GateState>, cv: &std::sync::Condvar) {
    let mut g = m.lock().unwrap_or_else(|e| e.into_inner());
    g.0 = g.0.saturating_sub(1);
    drop(g);
    cv.notify_all();
}

impl ProbeGate {
    /// A turn, waited for until `deadline` (review round 5: the wait had no bound, so a caller
    /// that gave up left a thread waiting for a turn, then probing for nobody); `None` when none
    /// came in time ([`enter_gate`]).
    fn enter_until(deadline: Instant) -> Option<Self> {
        enter_gate(&PROBES_IN_FLIGHT, &PROBE_TURN, deadline).then_some(ProbeGate)
    }

    /// Probes in flight now (tests).
    #[cfg(test)]
    fn in_flight() -> usize {
        PROBES_IN_FLIGHT.lock().unwrap_or_else(|e| e.into_inner()).0
    }
}

impl ProbeGateV6 {
    /// See [`ProbeGate::enter_until`].
    fn enter_until(deadline: Instant) -> Option<Self> {
        enter_gate(&PROBES_IN_FLIGHT_V6, &PROBE_TURN_V6, deadline).then_some(ProbeGateV6)
    }
}

impl Drop for ProbeGate {
    fn drop(&mut self) {
        leave_gate(&PROBES_IN_FLIGHT, &PROBE_TURN);
    }
}

impl Drop for ProbeGateV6 {
    fn drop(&mut self) {
        leave_gate(&PROBES_IN_FLIGHT_V6, &PROBE_TURN_V6);
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
/// application, redesigned in review round 4 (probe-1): two connections to the destination, both
/// made with the default hop limit. The **check** connection's hop limit is then lowered to
/// `hops` for the rest of its life (its FIN, every retransmission of it, its closing reset), and
/// it is half-closed; then the **control** connection is made, at the default hop limit, and
/// half-closed too. Both FINs' fates are read from the connections' TCP state ([`ConnReader`]:
/// Linux's `TCP_INFO`, macOS's `TCP_CONNECTION_INFO`) and decided by [`Check::step`]:
///
/// - the check's FIN acknowledged, at any time: near ([`ConfirmOutcome::Answered`]);
/// - far ([`ConfirmOutcome::Unanswered`]) only once the control's FIN was acknowledged (the peer
///   acknowledges a FIN that reaches it) and the check's has stayed unacknowledged for
///   [`Check::far_after`]: at least the window a near peer answers in (four round trips and
///   250 ms, at least 300 ms), one retransmission of the check's FIN (its RTO, two round trips and
///   250 ms), and the control's acknowledgement plus its round trip again (at least 250 ms) after
///   it (the check's FIN left first on the same path, so a near peer's answer to it would come
///   before the control's);
/// - the control's FIN unacknowledged within its RTO, two round trips and 250 ms (at least
///   500 ms), a peer that closes or resets either connection first, a wait past
///   [`MAX_CHECK_WAIT`]: a failure, never far.
///
/// Before review round 4 one connection did both: its hop limit was restored after a deadline
/// capped at 1.5 s (the "positive control"), and a late acknowledgement of the hop-limited FIN
/// (a near peer behind a congested queue, a delayed or lost ACK) then read as the control's
/// answer: far. Now the check connection's hop limit is never restored, and nothing it answers
/// can read as far.
///
/// Only an acknowledgement counts as an answer (review round 2, probe-1): a peer that closed or
/// reset the connection first is a failed check, never near by mistake and never far. ICMP
/// errors for the FIN are not read (Linux keeps them as soft errors `SO_ERROR` does not report
/// unless `IP_RECVERR` is set; macOS never reports them).
#[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
fn confirm_once(addr: SocketAddr, hops: u8, timeout: Duration, deadline: Instant) -> ConfirmOutcome {
    use std::os::fd::AsRawFd;
    let addr = unmapped(addr);
    let connect = || -> Result<socket2::Socket, ConfirmOutcome> {
        let sock = new_socket(addr).map_err(|e| ConfirmOutcome::Failed(e.to_string()))?;
        // Review round 5, probe-1: within the caller's time too.
        let timeout = timeout.min(deadline.saturating_duration_since(Instant::now()));
        if timeout.is_zero() {
            return Err(ConfirmOutcome::Failed(OUT_OF_TIME.into()));
        }
        sock.connect_timeout(&addr.into(), timeout)
            .map_err(|e| ConfirmOutcome::ConnectFailed(e.to_string()))?;
        // Closed with a reset, never a byte of data.
        let _ = sock.set_linger(Some(Duration::ZERO));
        Ok(sock)
    };
    let check = match connect() {
        Ok(s) => s,
        Err(o) => return o,
    };
    // From here on every packet of the check connection — the FIN, its retransmissions, the
    // closing reset — may cross at most `hops` hops.
    if let Err(e) = set_hops(&check, addr, hops) {
        return ConfirmOutcome::Failed(e.to_string());
    }
    let rc = ConnReader::new(check.as_raw_fd());
    let ic = match rc.info() {
        Ok(i) => i,
        Err(e) => return ConfirmOutcome::Failed(e.to_string()),
    };
    // The peer closed or reset the connection before the FIN was sent: what follows could not
    // tell whether the FIN reached it (review round 2, probe-1).
    if ic.state != TcpState::Established {
        return ConfirmOutcome::Failed(peer_closed_first(ic.state, Conn::Check));
    }
    // The hop-limited FIN first; then the control connection is made and its FIN sent. An
    // acknowledgement of the check's FIN that comes meanwhile is near at once.
    if let Err(e) = check.shutdown(std::net::Shutdown::Write) {
        return ConfirmOutcome::Failed(e.to_string());
    }
    let start = std::time::Instant::now();
    // Review round 6, probe-1: macOS reports the retransmission timeout only while its timer is
    // armed (0 on an idle connection, so the margin for a retransmitted FIN's acknowledgement
    // collapsed to ~50 ms): read again now that the FIN is out, and an RTO still unknown is
    // UNKNOWN_RTO.
    let rto = check_rto(ic.rto, rc.info().ok().map(|i| i.rto));
    #[cfg(test)]
    LAST_RTO.store(rto.as_millis() as u64, std::sync::atomic::Ordering::SeqCst);
    let mut decision = match Check::new(ic.rtt, rto) {
        Ok(d) => d,
        Err(o) => return o,
    };
    let check_state = || rc.info().map(|i| i.state);
    let near_already = |d: &mut Check| {
        let state = check_state();
        matches!(state, Ok(TcpState::FinWait2 | TcpState::TimeWait))
            .then(|| d.step(start.elapsed(), state, Ok(TcpState::FinWait1)))
            .flatten()
    };
    if let Some(done) = near_already(&mut decision) {
        return done;
    }
    let control = match connect() {
        Ok(s) => s,
        Err(o) => return near_already(&mut decision).unwrap_or(o),
    };
    let rk = ConnReader::new(control.as_raw_fd());
    match rk.info() {
        Ok(i) if i.state == TcpState::Established => {}
        Ok(i) => {
            return near_already(&mut decision).unwrap_or_else(|| {
                ConfirmOutcome::Failed(peer_closed_first(i.state, Conn::Control))
            })
        }
        Err(e) => return ConfirmOutcome::Failed(e.to_string()),
    }
    if let Err(e) = control.shutdown(std::net::Shutdown::Write) {
        return ConfirmOutcome::Failed(e.to_string());
    }
    decision.control_sent_at(start.elapsed());
    loop {
        let (c, k) = (check_state(), rk.info().map(|i| i.state));
        if let Some(done) = decision.step(start.elapsed(), c, k) {
            return done;
        }
        if Instant::now() >= deadline {
            return ConfirmOutcome::Failed(OUT_OF_TIME.into());
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// The retransmission timeout taken when the kernel reports none (review round 6, probe-1): RFC
/// 6298's initial RTO, more than any path the check can judge needs (Linux's minimum is 200 ms).
#[cfg(any(test, target_os = "linux", target_os = "android", target_os = "macos"))]
pub const UNKNOWN_RTO: Duration = Duration::from_secs(1);

/// The check connection's retransmission timeout: the larger of what the kernel reported before
/// and after the FIN was sent, [`UNKNOWN_RTO`] when both are zero (unknown, never "none").
#[cfg(any(test, target_os = "linux", target_os = "android", target_os = "macos"))]
fn check_rto(before: Duration, after: Option<Duration>) -> Duration {
    let rto = before.max(after.unwrap_or_default());
    if rto.is_zero() {
        UNKNOWN_RTO
    } else {
        rto
    }
}

/// The RTO the last check connection used, in milliseconds (tests).
#[cfg(test)]
static LAST_RTO: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// The longest the check connection may wait for the decision ([`Check`]); a path whose round
/// trip asks for longer is refused (`round trip too long`), never decided with a shorter wait.
#[cfg(any(test, target_os = "linux", target_os = "android", target_os = "macos"))]
pub const MAX_CHECK_WAIT: Duration = Duration::from_secs(10);

/// The two-connection check's decision ([`confirm_once`]), from the states read of the check
/// connection (its FIN limited to the probe's hops) and the control connection (its FIN at the
/// default hop limit), polled with the time since both FINs were sent. Pure: tests drive every
/// interleaving.
#[cfg(any(test, target_os = "linux", target_os = "android", target_os = "macos"))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Check {
    /// How long the check's FIN must stay unacknowledged at least before far: the window a
    /// near peer answers in, and one retransmission of the FIN.
    min_wait: Duration,
    /// How long the control's FIN may take to be acknowledged.
    control_wait: Duration,
    /// When the control's FIN was sent (after the check's: the control connection is made once
    /// the check's FIN is out).
    control_sent: Duration,
    /// When the control's FIN was acknowledged.
    control_acked: Option<Duration>,
}

#[cfg(any(test, target_os = "linux", target_os = "android", target_os = "macos"))]
impl Check {
    /// The margin past the control's acknowledgement (a delayed ACK, jitter).
    const MARGIN: Duration = Duration::from_millis(250);

    /// The check for a connection whose round trip is `rtt` and retransmission timeout `rto`;
    /// a failure when the waits they ask for pass [`MAX_CHECK_WAIT`].
    pub(crate) fn new(rtt: Duration, rto: Duration) -> Result<Self, ConfirmOutcome> {
        let window = (rtt * 4 + Self::MARGIN).max(Duration::from_millis(300));
        let retransmission = rto + rtt * 2 + Self::MARGIN;
        let min_wait = window.max(retransmission);
        let control_wait = retransmission.max(Duration::from_millis(500));
        if min_wait.max(control_wait) > MAX_CHECK_WAIT {
            return Err(too_slow(rtt, rto));
        }
        Ok(Check {
            min_wait,
            control_wait,
            control_sent: Duration::ZERO,
            control_acked: None,
        })
    }

    /// Notes that the control's FIN was sent `at` (after the check's).
    pub(crate) fn control_sent_at(&mut self, at: Duration) {
        self.control_sent = at;
    }

    /// How long after the check's FIN it may be read as unanswered, once the control's was
    /// acknowledged at `acked`: [`Self::min_wait`], and the control's round trip again plus the
    /// margin after that.
    pub(crate) fn far_after(&self, acked: Duration) -> Duration {
        let round_trip = acked.saturating_sub(self.control_sent);
        self.min_wait.max(acked + round_trip.max(Self::MARGIN))
    }

    /// One reading, `now` after the check's FIN: the check connection's state and the control's
    /// (or why they could not be read). `Some` when decided.
    pub(crate) fn step(
        &mut self,
        now: Duration,
        check: io::Result<TcpState>,
        control: io::Result<TcpState>,
    ) -> Option<ConfirmOutcome> {
        let check = match check {
            Ok(s) => s,
            Err(e) => return Some(ConfirmOutcome::Failed(e.to_string())),
        };
        // Any acknowledgement of the hop-limited FIN, whenever it comes: near.
        if let Some(done) = fin_step(check, Conn::Check) {
            return Some(done);
        }
        if self.control_acked.is_none() {
            match control.map(|c| fin_step(c, Conn::Control)) {
                Err(e) => {
                    return Some(ConfirmOutcome::Failed(format!(
                        "the control connection's state could not be read: {e}"
                    )))
                }
                Ok(Some(ConfirmOutcome::Answered)) => self.control_acked = Some(now),
                Ok(Some(other)) => return Some(other),
                Ok(None) => {}
            }
        }
        match self.control_acked {
            Some(acked) => {
                let far_after = self.far_after(acked);
                if far_after > MAX_CHECK_WAIT {
                    return Some(ConfirmOutcome::Failed(format!(
                        "the peer took {} ms to acknowledge the control's FIN, too long for the \
                         check to tell how near it is",
                        acked.saturating_sub(self.control_sent).as_millis()
                    )));
                }
                (now >= far_after).then(|| match check {
                    TcpState::FinWait1 => ConfirmOutcome::Unanswered,
                    // The peer's FIN crossed the check's, which is still unacknowledged: it
                    // closed on its own.
                    other => ConfirmOutcome::Failed(peer_closed_first(
                        match other {
                            TcpState::Closing => TcpState::LastAck,
                            o => o,
                        },
                        Conn::Check,
                    )),
                })
            }
            None => (now >= self.control_sent + self.control_wait)
                .then(|| ConfirmOutcome::Failed(UNACKED_FIN.into())),
        }
    }
}

/// Why a path is too slow for the check ([`Check::new`]).
#[cfg(any(test, target_os = "linux", target_os = "android", target_os = "macos"))]
fn too_slow(rtt: Duration, rto: Duration) -> ConfirmOutcome {
    ConfirmOutcome::Failed(format!(
        "its round trip ({} ms, retransmission timeout {} ms) is too long for the check to tell \
         how near it is",
        rtt.as_millis(),
        rto.as_millis()
    ))
}

/// Reads a connection's [`ConnInfo`] ([`conn_info`]), and remembers a reset (review round 4,
/// parse-2): on Linux a reset is `TCP_CLOSE` with an error pending, and reading the error
/// (`SO_ERROR`) clears it, so a later read of the same `TCP_CLOSE` would look like a completed
/// close (acknowledged). Once a read says [`TcpState::Closed`], every later one does.
#[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
struct ConnReader {
    fd: i32,
    closed: std::cell::Cell<Option<ConnInfo>>,
}

#[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
impl ConnReader {
    fn new(fd: i32) -> Self {
        ConnReader {
            fd,
            closed: std::cell::Cell::new(None),
        }
    }

    fn info(&self) -> io::Result<ConnInfo> {
        sticky_closed(&self.closed, || conn_info(self.fd))
    }
}

/// [`ConnReader::info`]'s rule: once `read` says [`TcpState::Closed`], `closed` keeps it.
#[cfg(any(all(test, unix), target_os = "linux", target_os = "android", target_os = "macos"))]
fn sticky_closed(
    closed: &std::cell::Cell<Option<ConnInfo>>,
    read: impl FnOnce() -> io::Result<ConnInfo>,
) -> io::Result<ConnInfo> {
    if let Some(i) = closed.get() {
        return Ok(i);
    }
    let i = read()?;
    if i.state == TcpState::Closed {
        closed.set(Some(i));
    }
    Ok(i)
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
fn fin_step(state: TcpState, which: Conn) -> Option<ConfirmOutcome> {
    match state {
        TcpState::FinWait2 | TcpState::TimeWait => Some(ConfirmOutcome::Answered),
        TcpState::FinWait1 | TcpState::Closing => None,
        other => Some(ConfirmOutcome::Failed(peer_closed_first(other, which))),
    }
}

/// Which of the check's two connections a state was read of (its failure names it: review round
/// 5, probe-2).
#[cfg(any(test, target_os = "linux", target_os = "android", target_os = "macos"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Conn {
    /// The hop-limited one.
    Check,
    /// The one at the default hop limit.
    Control,
}

/// Why a check whose control FIN, at the default hop limit, was never acknowledged fails
/// ([`Check::step`]): the cause within the 120 characters a refusal shows of it
/// ([`ConfirmOutcome::verdict`]).
#[cfg(any(test, target_os = "linux", target_os = "android", target_os = "macos"))]
const UNACKED_FIN: &str = "the peer acknowledged the check's FIN neither within the hop limit \
                           nor at the default one (AWS S3 never does)";

/// Why the check fails when the peer closed (`CLOSE_WAIT`, then `LAST_ACK` once this side sends
/// its FIN) or reset (`CLOSED`) the connection before its FIN was acknowledged.
#[cfg(any(test, target_os = "linux", target_os = "android", target_os = "macos"))]
fn peer_closed_first(state: TcpState, which: Conn) -> String {
    let (conn, fin) = match which {
        Conn::Check => ("check", "hop-limited FIN"),
        Conn::Control => ("control", "FIN"),
    };
    let how = match state {
        TcpState::CloseWait | TcpState::LastAck => "closed",
        TcpState::Closed => "reset",
        other => return format!("the {conn} connection is in TCP state {other:?}"),
    };
    // Within the 120 characters a refusal shows ([`ConfirmOutcome::verdict`]).
    format!("the peer {how} the {conn} connection before its {fin} was acknowledged: the check cannot tell how near it is")
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

/// Linux: the pending error `getsockopt(SO_ERROR)` returned `rc` and `e` for: a socket whose
/// error cannot be read (`rc != 0`) is not known to have closed cleanly, so it reads as an error
/// (-1), which makes its `TCP_CLOSE` a reset (review round 4, cross-6).
#[cfg(any(all(test, unix), target_os = "linux", target_os = "android"))]
fn so_error_read(rc: i32, e: i32) -> i32 {
    if rc != 0 {
        -1
    } else {
        e
    }
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
    // Read (and so cleared) only for TCP_CLOSE, which every caller takes as final: polled again,
    // a reset's TCP_CLOSE would read as acknowledged (its error already read).
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
        so_error_read(rc, e)
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
fn confirm_once(_: SocketAddr, _: u8, _: Duration, _: Instant) -> ConfirmOutcome {
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
    /// queued) gives the probe no answer; it drains its queue 4.5 seconds later and then answers
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
        // Drained once the probe has had all its attempts (1 s, 0.5 s, a 1 s pause, 1 s).
        let drain = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(4500));
            let accepted = l.accept();
            std::thread::sleep(Duration::from_secs(12));
            drop((l, accepted));
        });
        let t = std::time::Instant::now();
        let v = decide(&TtlProbe, addr, 2);
        // Near either way: the check connection's answer, or (review round 5: the probes are
        // paced, and other tests' probes can delay its attempts past the drain) the probe's own.
        assert!(
            matches!(
                v,
                Verdict::Near("answered once connected (it had not answered the probe)")
                    | Verdict::Near("accepted a connection")
            ),
            "{v:?} after {:?}",
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

    /// Linux, live: the kernel's `TCP_CLOSE` is read by its pending error. A connection whose FIN
    /// was acknowledged and that then got the peer's FIN (TIME_WAIT, which Linux does not show
    /// on the socket) reads as [`TcpState::TimeWait`]; one the peer reset reads as
    /// [`TcpState::Closed`]. Both on loopback, waited for until the socket leaves the states
    /// before.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn linux_a_reset_and_a_completed_close_read_apart() {
        use std::io::Read;
        use std::os::fd::AsRawFd;
        let settle = |c: &std::net::TcpStream, want: TcpState| {
            let t = std::time::Instant::now();
            loop {
                let i = conn_info(c.as_raw_fd()).unwrap();
                if i.state == want || t.elapsed() > Duration::from_secs(3) {
                    return i.state;
                }
                std::thread::sleep(Duration::from_millis(5));
            }
        };
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        // A completed close: this side's FIN acknowledged, the peer's FIN received.
        let c = std::net::TcpStream::connect(addr).unwrap();
        let (mut peer, _) = l.accept().unwrap();
        c.shutdown(std::net::Shutdown::Write).unwrap();
        let mut b = [0u8; 8];
        assert_eq!(peer.read(&mut b).unwrap(), 0);
        drop(peer);
        assert_eq!(settle(&c, TcpState::TimeWait), TcpState::TimeWait);
        // A reset: the peer closes with linger 0.
        let c = std::net::TcpStream::connect(addr).unwrap();
        let (peer, _) = l.accept().unwrap();
        socket2::SockRef::from(&peer).set_linger(Some(Duration::ZERO)).unwrap();
        drop(peer);
        assert_eq!(settle(&c, TcpState::Closed), TcpState::Closed);
    }

    /// The check connection to a listener on loopback (zero hops) and to an IPv6 one: answered,
    /// near. Its hop-limited FIN reaches them and is acknowledged.
    #[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
    #[test]
    fn the_check_connection_finds_a_local_listener_near() {
        for bind in ["127.0.0.1:0", "[::1]:0"] {
            let Ok(l) = std::net::TcpListener::bind(bind) else {
                let tag = if bind.starts_with('[') { "[ipv6] " } else { "" };
                crate::skipped(format!("{tag}no {bind} here"));
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
    /// on its own is a failure (refused), never near by mistake and never far (`Check::step`
    /// decides the rest). Both platforms' state numbers read as the same states.
    #[test]
    fn the_check_reads_only_an_acknowledged_fin_as_an_answer() {
        use TcpState::*;
        assert_eq!(fin_step(FinWait2, Conn::Check), Some(ConfirmOutcome::Answered));
        assert_eq!(fin_step(TimeWait, Conn::Check), Some(ConfirmOutcome::Answered));
        assert_eq!(fin_step(FinWait1, Conn::Check), None);
        assert_eq!(fin_step(Closing, Conn::Check), None);
        for (state, how) in [
            (LastAck, "closed"),
            (CloseWait, "closed"),
            (Closed, "reset"),
            (Established, "TCP state Established"),
            (Other(10), "TCP state Other(10)"),
        ] {
            let o = fin_step(state, Conn::Check);
            assert!(
                matches!(&o, Some(ConfirmOutcome::Failed(w)) if w.contains(how)),
                "{state:?}: {o:?}"
            );
            assert!(matches!(o.unwrap().verdict(), Verdict::Failed(_)));
        }
        assert!(matches!(peer_closed_first(CloseWait, Conn::Check), w if w.contains("closed")));
        // Review round 5, probe-2: a failure names the connection it was read of, within the
        // 120 characters a refusal shows.
        for which in [Conn::Check, Conn::Control] {
            for state in [LastAck, Closed] {
                let why = peer_closed_first(state, which);
                let name = if which == Conn::Check { "check connection" } else { "control connection" };
                assert!(why.contains(name), "{why}");
                assert!(why.chars().count() <= 120, "{} chars: {why}", why.chars().count());
                let Verdict::Failed(shown) = ConfirmOutcome::Failed(why.clone()).verdict() else {
                    panic!()
                };
                assert!(shown.contains(name) && shown.ends_with("how near it is"), "{shown}");
            }
        }
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
                matches!(fin_step(TcpState::from_linux(linux), Conn::Check), Some(ConfirmOutcome::Failed(_))),
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

    /// Review round 3, probe-1, and round 4, probe-2 (every platform): a probe that timed out
    /// is asked once more within the same time (two thirds, then the rest), and, timed out
    /// again, a third time after a pause (a router's ICMP rate limit refills); any other outcome
    /// of an attempt stands.
    #[cfg(unix)]
    #[test]
    fn a_probe_that_timed_out_is_asked_again() {
        let timeout = Duration::from_millis(1500);
        let pause = Duration::from_secs(1);
        let asked = std::cell::RefCell::new(Vec::new());
        let r = probe_attempts(
            timeout,
            pause,
            || Duration::from_secs(60),
            |p| asked.borrow_mut().push(format!("pause {}", p.as_millis())),
            |t| {
                asked.borrow_mut().push(format!("probe {}", t.as_millis()));
                Err(io::ErrorKind::TimedOut.into())
            },
        );
        assert_eq!(r.unwrap_err().kind(), io::ErrorKind::TimedOut);
        assert_eq!(
            *asked.borrow(),
            ["probe 1000", "probe 500", "pause 1000", "probe 1000"]
        );
        for answered_at in 1..=3 {
            let mut n = 0;
            let mut paused = false;
            let r = probe_attempts(timeout, pause, || Duration::from_secs(60), |_| paused = true, |_| {
                n += 1;
                if n < answered_at {
                    Err(io::ErrorKind::TimedOut.into())
                } else {
                    Err(io::Error::from_raw_os_error(libc::EHOSTUNREACH))
                }
            });
            assert_eq!(ProbeOutcome::of(r), ProbeOutcome::Unreachable);
            assert_eq!(n, answered_at);
            assert_eq!(paused, answered_at == 3);
        }
        for first in [
            Ok(()),
            Err(io::Error::from_raw_os_error(libc::EHOSTUNREACH)),
            Err(io::Error::from_raw_os_error(libc::ECONNREFUSED)),
        ] {
            let mut first = Some(first);
            let mut n = 0;
            let _ = probe_attempts(timeout, pause, || Duration::from_secs(60), |_| {}, |_| {
                n += 1;
                first.take().unwrap()
            });
            assert_eq!(n, 1);
        }
    }

    /// Review round 4, probe-2: at most [`PROBES_AT_ONCE`] probes are in flight in the process;
    /// eight callers at once take turns.
    #[test]
    fn probes_take_turns() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static MOST: AtomicUsize = AtomicUsize::new(0);
        let threads: Vec<_> = (0..8)
            .map(|_| {
                std::thread::spawn(|| {
                    let _turn = ProbeGate::enter_until(Instant::now() + Duration::from_secs(30))
                        .expect("a turn");
                    MOST.fetch_max(ProbeGate::in_flight(), Ordering::SeqCst);
                    std::thread::sleep(Duration::from_millis(30));
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }
        let most = MOST.load(Ordering::SeqCst);
        assert!((1..=PROBES_AT_ONCE).contains(&most), "{most}");
    }

    /// Review round 5 (probe-1, and the parse and probe lenses' suspicion): a turn is waited
    /// for only until the caller's deadline; a probe that gets none in time fails (refused,
    /// never far) without sending anything, so an abandoned check stops and gives its turn
    /// back; a decision already out of time asks nothing.
    #[test]
    fn r5_a_probe_waits_for_a_turn_only_until_its_deadline() {
        let far = Instant::now() + Duration::from_secs(30);
        let held: Vec<ProbeGate> = (0..PROBES_AT_ONCE)
            .map(|_| ProbeGate::enter_until(far).expect("a turn"))
            .collect();
        let t = Instant::now();
        assert!(ProbeGate::enter_until(t + Duration::from_millis(200)).is_none());
        // Review round 6: at its deadline at the latest (sooner when the turns ahead cannot all
        // come in time: it sheds).
        assert!(t.elapsed() < Duration::from_secs(2));
        // Nothing listens there: had the probe been sent, it would have been refused (near).
        let addr: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let t = Instant::now();
        let o = TtlProbe.probe_until(addr, 2, PROBE_TIMEOUT, t + Duration::from_millis(300));
        assert!(matches!(&o, ProbeOutcome::Failed(w) if w.contains("no turn")), "{o:?}");
        assert!(t.elapsed() < Duration::from_secs(2), "{:?}", t.elapsed());
        let v = decide_until(&TtlProbe, addr, 2, Instant::now() + Duration::from_millis(300));
        assert!(matches!(&v, Verdict::Failed(w) if w.contains("no turn")), "{v:?}");
        drop(held);
        assert!(ProbeGate::enter_until(Instant::now() + Duration::from_secs(5)).is_some());
        let probe = FixedProbe::far();
        let v = decide_until(&*probe, addr, 2, Instant::now() - Duration::from_millis(1));
        assert_eq!(v, Verdict::Failed(OUT_OF_TIME.into()));
        assert!(probe.asked.lock().unwrap().is_empty());
        let undecided = FixedProbe::answering(ProbeOutcome::TimedOut);
        assert_eq!(decide_until(&*undecided, addr, 2, far), Verdict::Far);
        assert_eq!(undecided.confirms.lock().unwrap().len(), 1);
    }

    /// Review round 5 (the probe lens's suspicion): probes start at most [`PROBE_BURST`] at once
    /// and [`PROBES_PER_SECOND`] after that, however many callers ask.
    #[test]
    fn r5_probes_are_paced() {
        let t0 = Instant::now();
        let mut p = Pacer::new();
        for _ in 0..PROBE_BURST {
            assert_eq!(p.take(t0), Ok(()));
        }
        let wait = p.take(t0).unwrap_err();
        let per = Duration::from_secs(1) / PROBES_PER_SECOND;
        assert!(wait <= per && wait + Duration::from_millis(5) >= per, "{wait:?}");
        assert_eq!(p.take(t0 + per + Duration::from_millis(1)), Ok(()));
        assert!(p.take(t0 + per + Duration::from_millis(2)).is_err());
        // A second's rest refills PROBES_PER_SECOND, never past the burst.
        let later = t0 + Duration::from_secs(60);
        let n = (0..100).take_while(|_| p.take(later).is_ok()).count();
        assert_eq!(n, PROBE_BURST as usize);
    }

    /// The gate paces: past a burst, turns wait for tokens (other tests' probes only take more).
    #[test]
    fn r5_the_gate_paces_past_a_burst() {
        let before = PACED.load(std::sync::atomic::Ordering::SeqCst);
        let t = Instant::now();
        for _ in 0..PROBE_BURST + 3 {
            drop(ProbeGate::enter_until(t + Duration::from_secs(30)).expect("a turn"));
        }
        assert!(PACED.load(std::sync::atomic::Ordering::SeqCst) > before, "no turn waited for a token");
    }

    /// Review round 4, probe-1: the two-connection check, every interleaving. An
    /// acknowledgement of the hop-limited FIN is near whenever it comes (before the control's,
    /// with it, after it, long after the window: the late ACK that read as far before); far only
    /// once the control's FIN was acknowledged and the check's stayed unacknowledged for
    /// `far_after`; the control unacknowledged (S3), a peer that closes or resets either
    /// connection, an unreadable state, a path too slow: failures, never far.
    #[test]
    fn r4_the_two_connection_check_never_reads_a_late_ack_as_far() {
        use TcpState::*;
        let ms = Duration::from_millis;
        let ok = |s: TcpState| -> io::Result<TcpState> { Ok(s) };
        // A 20 ms path, RTO 220 ms: min_wait = max(330, 220 + 40 + 250) = 510 ms.
        let fresh = || Check::new(ms(20), ms(220)).unwrap();
        assert_eq!(fresh().min_wait, ms(510));
        assert_eq!(fresh().control_wait, ms(510));
        // Drive a sequence of (time, check, control); the first decision.
        let run = |steps: &[(u64, TcpState, TcpState)]| {
            let mut c = fresh();
            for &(t, a, b) in steps {
                if let Some(o) = c.step(ms(t), ok(a), ok(b)) {
                    return Some((t, o));
                }
            }
            None
        };
        // Far: the control acknowledged at 20 ms, the check never.
        assert_eq!(
            run(&[(0, FinWait1, FinWait1), (20, FinWait1, FinWait2), (509, FinWait1, FinWait2), (510, FinWait1, FinWait2)]),
            Some((510, ConfirmOutcome::Unanswered))
        );
        // Near: the check acknowledged before the control, with it, after it, and late (after
        // the old 1.5 s window, once the control had long answered) — as long as no decision
        // was made, and the decision waits past the control's time again.
        for steps in [
            vec![(10, FinWait2, FinWait1)],
            vec![(20, FinWait2, FinWait2)],
            vec![(20, FinWait1, FinWait2), (30, TimeWait, FinWait2)],
            vec![(20, FinWait1, TimeWait), (400, FinWait2, Closed)],
        ] {
            assert_eq!(run(&steps).map(|(_, o)| o), Some(ConfirmOutcome::Answered), "{steps:?}");
        }
        // Bufferbloat: the control's ACK comes at 1.6 s (the RTT grew); the check's, as late,
        // at 1.65 s: near, not far (the old design restored the hop limit at 1.5 s).
        assert_eq!(
            run(&[(0, FinWait1, FinWait1), (1600, FinWait1, FinWait2), (1650, FinWait2, FinWait2)]),
            Some((1650, ConfirmOutcome::Answered))
        );
        let mut c = fresh();
        assert_eq!(c.step(ms(1600), ok(FinWait1), ok(FinWait2)), None);
        assert_eq!(c.far_after(ms(1600)), ms(3200));
        assert_eq!(c.step(ms(3199), ok(FinWait1), ok(FinWait1)), None, "the control stays acked");
        assert_eq!(c.step(ms(3200), ok(FinWait1), ok(Closed)), Some(ConfirmOutcome::Unanswered));
        // A lost ACK: the check's FIN retransmitted after its RTO (220 ms) is answered at
        // 245 ms, before min_wait.
        assert_eq!(
            run(&[(20, FinWait1, FinWait2), (244, FinWait1, FinWait2), (245, FinWait2, FinWait2)]),
            Some((245, ConfirmOutcome::Answered))
        );
        // The control connection made 100 ms after the check's FIN, acknowledged 20 ms after
        // its own: far only at max(510, 120 + 250).
        let mut c = fresh();
        assert_eq!(c.step(ms(50), ok(FinWait1), ok(FinWait1)), None);
        c.control_sent_at(ms(100));
        assert_eq!(c.step(ms(120), ok(FinWait1), ok(FinWait2)), None);
        assert_eq!(c.far_after(ms(120)), ms(510));
        assert_eq!(c.step(ms(510), ok(FinWait1), ok(FinWait2)), Some(ConfirmOutcome::Unanswered));
        // The control's round trip counts from its own FIN: sent at 400, acknowledged at 420.
        let mut c = fresh();
        c.control_sent_at(ms(400));
        assert_eq!(c.far_after(ms(420)), ms(670));
        let mut c = fresh();
        c.control_sent_at(ms(100));
        assert_eq!(c.step(ms(609), ok(FinWait1), ok(FinWait1)), None, "control_wait from its FIN");
        assert_eq!(c.step(ms(610), ok(FinWait1), ok(FinWait1)), Some(ConfirmOutcome::Failed(UNACKED_FIN.into())));
        // The control never acknowledged (S3): a failure at control_wait, never far.
        let o = run(&[(0, FinWait1, FinWait1), (509, FinWait1, FinWait1), (510, FinWait1, FinWait1)]);
        assert_eq!(o, Some((510, ConfirmOutcome::Failed(UNACKED_FIN.into()))));
        // A peer that resets or closes either connection first: a failure.
        for (a, b) in [(Closed, FinWait1), (LastAck, FinWait1), (CloseWait, FinWait1), (FinWait1, Closed), (FinWait1, LastAck), (Established, FinWait1)] {
            let o = run(&[(5, a, b)]);
            assert!(matches!(&o, Some((_, ConfirmOutcome::Failed(_)))), "{a:?} {b:?}: {o:?}");
        }
        // The peer's FIN crossed the check's (CLOSING) when the time is up: a failure.
        let o = run(&[(20, Closing, FinWait2), (510, Closing, FinWait2)]);
        assert!(matches!(&o, Some((510, ConfirmOutcome::Failed(w))) if w.contains("closed")), "{o:?}");
        // An unreadable state: a failure.
        let mut c = fresh();
        assert!(matches!(c.step(ms(1), Err(io::Error::other("x")), ok(FinWait1)), Some(ConfirmOutcome::Failed(_))));
        let mut c = fresh();
        assert!(matches!(c.step(ms(1), ok(FinWait1), Err(io::Error::other("x"))), Some(ConfirmOutcome::Failed(_))));
        // No cap shorter than the round trip: a 900 ms path waits 3.85 s; one too slow for
        // MAX_CHECK_WAIT, or a control acknowledged too late, is refused.
        let slow = Check::new(ms(900), ms(1100)).unwrap();
        assert_eq!(slow.min_wait, ms(3850));
        assert!(matches!(Check::new(ms(2600), ms(3000)), Err(ConfirmOutcome::Failed(w)) if w.contains("too long")));
        let mut c = fresh();
        assert!(matches!(c.step(ms(5100), ok(FinWait1), ok(FinWait2)), Some(ConfirmOutcome::Failed(w)) if w.contains("too long")));
        // Every failure is refused, not far.
        assert!(matches!(
            ConfirmOutcome::Failed(UNACKED_FIN.into()).verdict(),
            Verdict::Failed(_)
        ));
        assert!(UNACKED_FIN.chars().count() <= 120);
    }

    /// Review round 4, parse-2: a reset read once is a reset for good. On Linux the first read
    /// of a reset's `TCP_CLOSE` takes its error (`SO_ERROR`, cleared by reading); a second read
    /// would see `TCP_CLOSE` with no error, a completed close (acknowledged). Every read of the
    /// check goes through [`sticky_closed`].
    #[cfg(unix)]
    #[test]
    fn r4_a_reset_read_once_stays_a_reset() {
        let sk_err = std::cell::Cell::new(libc::ECONNRESET);
        let mut tcp_info = [0u8; 104];
        tcp_info[0] = 7; // TCP_CLOSE
        let closed = std::cell::Cell::new(None);
        let read = || {
            sticky_closed(&closed, || linux_conn_info(&tcp_info, 104, || sk_err.replace(0)))
                .unwrap()
                .state
        };
        assert_eq!(read(), TcpState::Closed);
        assert_eq!(read(), TcpState::Closed, "the second read of the same TCP_CLOSE");
        // Without it (the reviewers' race): the second read is a completed close.
        let bare = || linux_conn_info(&tcp_info, 104, || sk_err.replace(0)).unwrap().state;
        sk_err.set(libc::ECONNRESET);
        assert_eq!(bare(), TcpState::Closed);
        assert_eq!(bare(), TcpState::TimeWait);
        // cross-6: an SO_ERROR that cannot be read is a reset, never a completed close.
        assert_eq!(so_error_read(-1, 0), -1);
        assert_eq!(so_error_read(0, 0), 0);
        assert_eq!(so_error_read(0, libc::ECONNRESET), libc::ECONNRESET);
        assert_eq!(
            linux_conn_info(&tcp_info, 104, || so_error_read(-1, 0)).unwrap().state,
            TcpState::Closed
        );
        // And the check, fed the sticky reads, fails; never far, never near.
        let mut c = Check::new(Duration::from_millis(20), Duration::from_millis(220)).unwrap();
        assert!(matches!(
            c.step(Duration::from_millis(30), Ok(read()), Ok(TcpState::FinWait2)),
            Some(ConfirmOutcome::Failed(w)) if w.contains("reset")
        ));
    }

    /// Review round 3, probe-1, live: AWS S3's front ends never acknowledge a bare FIN, at any
    /// hop limit (`r3-probe/finack-s3.log`), so the check connection read them as far at any
    /// distance; with the control connection (review round 4: a second connection, no longer the
    /// check connection's own hop limit restored) they are a failed check (refused when the probe
    /// had no answer: the cost, docs/netguard-macos.md). Skipped when S3 cannot be reached, or when it
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
            match conn_info(c.as_raw_fd()).map(|i| i.state) {
                Ok(TcpState::FinWait2 | TcpState::TimeWait) => acked = true,
                // Reset (or unreadable): final. On Linux `SO_ERROR` is read, and cleared, with
                // the first `TCP_CLOSE`, so the state is never polled past it.
                Ok(TcpState::Closed) | Err(_) => break,
                Ok(_) => {}
            }
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
                let tag = if bind.starts_with('[') { "[ipv6] " } else { "" };
                crate::skipped(format!("{tag}no {bind} here"));
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


/// Review round 6: the probe gate (parse-1, parse-4 = probe-2, probe-3), the deadlines (cross-7
/// N11, N14), the last attempt (probe-4) and the far verdicts remembered (probe-3).
#[cfg(test)]
mod r6_tests {
    use super::*;
    use std::sync::{Arc, Condvar, Mutex};

    /// A gate of the test's own (the process's are shared with every other test).
    fn gate() -> &'static (Mutex<GateState>, Condvar) {
        Box::leak(Box::new((Mutex::new(GateState::new()), Condvar::new())))
    }

    fn stage(g: &(Mutex<GateState>, Condvar), in_flight: usize, tokens: f64) {
        let mut s = g.0.lock().unwrap();
        s.0 = in_flight;
        s.1 = Pacer { tokens, at: Some(Instant::now()) };
    }

    /// parse-1 (`r6_parse_a_freed_turn_is_not_lost`, 4/4 failed before): both turns held, no
    /// token; W1 (deadline 200 ms) then W2 (deadline 3 s) wait; a turn is freed at 100 ms. W1
    /// leaves at its deadline without a turn; W2 must get the freed one once a token is there
    /// (~333 ms), not sleep to its own deadline.
    #[test]
    fn r6_a_freed_turn_is_not_lost() {
        for _ in 0..4 {
            let g = gate();
            stage(g, PROBES_AT_ONCE, 0.0);
            let t0 = Instant::now();
            let waiter = |d: Duration| {
                std::thread::spawn(move || {
                    let got = enter_gate(&g.0, &g.1, t0 + d);
                    (got, t0.elapsed())
                })
            };
            let w1 = waiter(Duration::from_millis(200));
            std::thread::sleep(Duration::from_millis(20));
            let w2 = waiter(Duration::from_secs(3));
            std::thread::sleep(Duration::from_millis(80));
            leave_gate(&g.0, &g.1);
            let (r1, r2) = (w1.join().unwrap(), w2.join().unwrap());
            assert!(!r1.0, "{r1:?}");
            assert!(r2.0 && r2.1 < Duration::from_millis(1000), "W1 {r1:?}, W2 {r2:?}");
        }
    }

    /// parse-4 = probe-2 (`r6_parse_an_expired_caller_takes_no_token`,
    /// `r6_turn_after_deadline_takes_a_token`): a caller whose deadline has passed gets no turn
    /// and takes no token, and a probe out of time sends nothing.
    #[test]
    fn r6_an_expired_caller_takes_no_token() {
        let g = gate();
        stage(g, 0, f64::from(PROBE_BURST));
        let past = Instant::now() - Duration::from_millis(1);
        for _ in 0..4 {
            assert!(!enter_gate(&g.0, &g.1, past));
        }
        let s = g.0.lock().unwrap();
        assert!(s.1.tokens >= f64::from(PROBE_BURST) - 0.01 && s.0 == 0 && s.2.is_empty(), "{s:?}");
        drop(s);
        // Nothing listens there: had a probe been sent, it would have been refused at once.
        let addr: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let r = probe_turn(addr, 2, PROBE_TIMEOUT, past);
        assert_eq!(r.unwrap_err().kind(), io::ErrorKind::TimedOut);
        let asked = std::cell::Cell::new(0);
        let r = probe_attempts(PROBE_TIMEOUT, PROBE_PAUSE, || Duration::ZERO, |_| {}, |_| {
            asked.set(asked.get() + 1);
            Err(io::ErrorKind::TimedOut.into())
        });
        assert!(r.is_err());
        assert_eq!(asked.get(), 1, "out of time: no further attempt");
    }

    /// probe-3: first come, first served; a caller whose turn cannot come in time (the turns
    /// ahead need more tokens than come before its deadline) gives up at once.
    #[test]
    fn r6_turns_are_first_come_first_served_and_hopeless_waits_are_shed() {
        let g = gate();
        stage(g, PROBES_AT_ONCE, f64::from(PROBE_BURST));
        let order = Arc::new(Mutex::new(Vec::new()));
        let t0 = Instant::now();
        let hs: Vec<_> = (0..5)
            .map(|i| {
                let order = order.clone();
                let h = std::thread::spawn(move || {
                    assert!(enter_gate(&g.0, &g.1, t0 + Duration::from_secs(10)));
                    order.lock().unwrap().push(i);
                    leave_gate(&g.0, &g.1);
                });
                std::thread::sleep(Duration::from_millis(30));
                h
            })
            .collect();
        leave_gate(&g.0, &g.1);
        for h in hs {
            h.join().unwrap();
        }
        assert_eq!(*order.lock().unwrap(), vec![0, 1, 2, 3, 4]);
        // Six callers wait for tokens (none there); a seventh with half a second sheds at once.
        let g = gate();
        stage(g, 0, 0.0);
        let hs: Vec<_> = (0..6)
            .map(|_| {
                let h = std::thread::spawn(move || {
                    if enter_gate(&g.0, &g.1, Instant::now() + Duration::from_secs(10)) {
                        leave_gate(&g.0, &g.1);
                    }
                });
                std::thread::sleep(Duration::from_millis(5));
                h
            })
            .collect();
        let t = Instant::now();
        assert!(!enter_gate(&g.0, &g.1, t + Duration::from_millis(500)));
        assert!(t.elapsed() < Duration::from_millis(100), "{:?}", t.elapsed());
        for h in hs {
            h.join().unwrap();
        }
    }

    /// The gate's invariant, on random callers (random deadlines and hold times, arriving at
    /// random): never more than PROBES_AT_ONCE turns held; a turn is never given after its
    /// deadline; a caller that gets none returns by its deadline; nobody waits for a turn that
    /// is free with a token there (no lost wakeup: every caller whose deadline leaves room for
    /// every token ahead of it, and their holds, gets one); tokens stay within the burst.
    #[test]
    fn r6_the_gate_never_loses_a_turn_on_random_callers() {
        for seed in 1..=4u64 {
            let g = gate();
            let most = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let mut x = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
            let mut rnd = move |n: u64| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                x % n
            };
            let t0 = Instant::now();
            let hs: Vec<_> = (0..24)
                .map(|i| {
                    let deadline = Duration::from_millis(50 + rnd(4000));
                    let hold = Duration::from_millis(rnd(60));
                    let most = most.clone();
                    std::thread::sleep(Duration::from_millis(rnd(40)));
                    let arrived = t0.elapsed();
                    let h = std::thread::spawn(move || {
                        let start = Instant::now();
                        let got = enter_gate(&g.0, &g.1, start + deadline);
                        let took = start.elapsed();
                        if got {
                            let n = g.0.lock().unwrap().0;
                            most.fetch_max(n, std::sync::atomic::Ordering::SeqCst);
                            std::thread::sleep(hold);
                            leave_gate(&g.0, &g.1);
                        }
                        (i, arrived, deadline, got, took)
                    });
                    (h, deadline)
                })
                .collect();
            let mut results: Vec<_> = hs.into_iter().map(|(h, _)| h.join().unwrap()).collect();
            results.sort_by_key(|r| r.1);
            assert!(most.load(std::sync::atomic::Ordering::SeqCst) <= PROBES_AT_ONCE);
            // The burst covers the first PROBE_BURST; then PROBES_PER_SECOND; every hold is
            // short (60 ms), so the k-th arrival's turn can come by about (k - burst) / rate.
            for (k, (i, _, deadline, got, took)) in results.iter().enumerate() {
                if *got {
                    assert!(*took <= *deadline + Duration::from_millis(5), "seed {seed} #{i}: {took:?} > {deadline:?}");
                } else {
                    assert!(*took <= *deadline + Duration::from_millis(50), "seed {seed} #{i}: {took:?}");
                }
                let room = (k as f64 + 1.0 - f64::from(PROBE_BURST)).max(0.0) / f64::from(PROBES_PER_SECOND);
                if deadline.as_secs_f64() > room + 0.1 * k as f64 + 1.0 {
                    assert!(*got, "seed {seed} #{i} (arrival {k}): no turn within {deadline:?} ({results:?})");
                }
            }
            let s = g.0.lock().unwrap();
            assert!(s.0 == 0 && s.2.is_empty() && s.1.tokens <= f64::from(PROBE_BURST), "{s:?}");
        }
    }

    /// cross-7 N14: an attempt never runs past the caller's deadline (a listener whose accept
    /// queue is full drops SYNs: the attempt would wait its whole timeout).
    #[cfg(unix)]
    #[test]
    fn r6_a_probe_attempt_ends_at_the_deadline() {
        let sock = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None).unwrap();
        sock.bind(&"127.0.0.1:0".parse::<SocketAddr>().unwrap().into()).unwrap();
        sock.listen(0).unwrap();
        let addr = sock.local_addr().unwrap().as_socket().unwrap();
        let mut fill = Vec::new();
        for _ in 0..8 {
            let s = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None).unwrap();
            s.set_nonblocking(true).unwrap();
            let _ = s.connect(&addr.into());
            fill.push(s);
        }
        std::thread::sleep(Duration::from_millis(100));
        let t = Instant::now();
        let r = probe_turn(addr, 64, Duration::from_secs(2), t + Duration::from_millis(300));
        let took = t.elapsed();
        // A full queue on loopback: dropped SYNs, or (some kernels) an answer at once.
        if matches!(&r, Err(e) if e.kind() == io::ErrorKind::TimedOut) {
            assert!(took < Duration::from_millis(700), "{took:?}");
        } else {
            crate::skipped(format!("this kernel answered a full accept queue: {r:?}"));
        }
    }

    /// A probe that records what it was asked.
    #[derive(Debug)]
    struct Recording {
        confirm: ConfirmOutcome,
        last: ProbeOutcome,
        confirm_timeouts: Mutex<Vec<Duration>>,
        lasts: Mutex<usize>,
    }

    impl NearProbe for Recording {
        fn probe(&self, _: SocketAddr, _: u8, _: Duration) -> ProbeOutcome {
            ProbeOutcome::TimedOut
        }
        fn confirm(&self, _: SocketAddr, _: u8, timeout: Duration) -> ConfirmOutcome {
            self.confirm_timeouts.lock().unwrap().push(timeout);
            self.confirm.clone()
        }
        fn probe_last_until(&self, _: SocketAddr, _: u8, _: Duration, _: Instant) -> ProbeOutcome {
            *self.lasts.lock().unwrap() += 1;
            self.last.clone()
        }
    }

    fn recording(confirm: ConfirmOutcome, last: ProbeOutcome) -> Recording {
        Recording { confirm, last, confirm_timeouts: Mutex::new(Vec::new()), lasts: Mutex::new(0) }
    }

    /// probe-1 (`r6_macos_rto_zero_reads_a_retransmitted_near_ack_as_far`, live
    /// `r6-probe/exp/rto-macos.log`: macOS reads 0 before the FIN): an unknown RTO is never
    /// zero, so the far margin always covers a retransmission of the FIN (macOS and Linux alike).
    #[test]
    fn r6_the_check_never_uses_a_zero_rto() {
        let ms = Duration::from_millis;
        assert_eq!(check_rto(ms(0), Some(ms(242))), ms(242));
        assert_eq!(check_rto(ms(0), None), UNKNOWN_RTO);
        assert_eq!(check_rto(ms(0), Some(ms(0))), UNKNOWN_RTO);
        assert_eq!(check_rto(ms(300), Some(ms(200))), ms(300));
        // The reviewer's case: rtt 14 ms, the near peer's ACK of the retransmitted FIN at
        // ~rto + rtt; with the RTO read as 0 the check read far at ~306 ms.
        let c = Check::new(ms(14), check_rto(ms(0), None)).unwrap();
        assert!(c.far_after(ms(0)) > UNKNOWN_RTO + ms(14), "{c:?}");
    }

    /// probe-1, live: the RTO the check connection used is not zero (a local listener: near).
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn r6_the_live_check_uses_a_nonzero_rto() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let _keep = std::thread::spawn(move || {
            let held: Vec<_> = l.incoming().take(2).collect();
            std::thread::sleep(Duration::from_secs(3));
            drop(held);
        });
        let o = confirm_once(addr, 2, Duration::from_secs(2), Instant::now() + Duration::from_secs(10));
        assert_eq!(o, ConfirmOutcome::Answered, "{o:?}");
        assert!(LAST_RTO.load(std::sync::atomic::Ordering::SeqCst) > 0);
    }

    /// cross-7 N11: the check connection's connect is bounded by the caller's deadline.
    #[test]
    fn r6_the_check_connection_is_bounded_by_the_deadline() {
        let p = recording(ConfirmOutcome::Unanswered, ProbeOutcome::TimedOut);
        let addr: SocketAddr = "192.0.2.1:443".parse().unwrap();
        assert_eq!(decide_until(&p, addr, 2, Instant::now() + Duration::from_secs(1)), Verdict::Far);
        let t = p.confirm_timeouts.lock().unwrap();
        assert!(t.len() == 1 && t[0] <= Duration::from_secs(1), "{t:?}");
    }

    /// probe-4: a destination whose probe had no answer and whose check connection failed (every
    /// AWS S3 front end) is probed once more when the time allows; its answer decides.
    #[test]
    fn r6_a_failed_check_is_followed_by_one_more_probe() {
        let addr: SocketAddr = "192.0.2.1:443".parse().unwrap();
        let reset = ConfirmOutcome::Failed("the peer reset the control connection".into());
        let far = Instant::now() + Duration::from_secs(30);
        let p = recording(reset.clone(), ProbeOutcome::Unreachable);
        assert_eq!(decide_until(&p, addr, 2, far), Verdict::Far);
        assert_eq!(*p.lasts.lock().unwrap(), 1);
        let p = recording(reset.clone(), ProbeOutcome::Connected);
        assert!(matches!(decide_until(&p, addr, 2, far), Verdict::Near(_)));
        let p = recording(reset.clone(), ProbeOutcome::TimedOut);
        assert!(matches!(decide_until(&p, addr, 2, far), Verdict::Failed(w) if w.contains("reset")));
        // Not when the time left cannot hold it.
        let p = recording(reset, ProbeOutcome::Unreachable);
        let soon = Instant::now() + PROBE_LAST_PAUSE;
        assert!(matches!(decide_until(&p, addr, 2, soon), Verdict::Failed(_)));
        assert_eq!(*p.lasts.lock().unwrap(), 0);
        // A check that decided is never followed by it.
        let p = recording(ConfirmOutcome::Answered, ProbeOutcome::Unreachable);
        assert!(matches!(decide_until(&p, addr, 2, far), Verdict::Near(_)));
        assert_eq!(*p.lasts.lock().unwrap(), 0);
    }

    /// probe-3: callers deciding the same key at once wait for the one decision running; a
    /// verdict other than far is not shared (each decides again).
    #[test]
    fn r6_one_decision_runs_per_destination_at_a_time() {
        let key = ("203.0.113.77:443".parse().unwrap(), 2, 0xfa_0002u64, 9);
        let ran = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let hs: Vec<_> = (0..8)
            .map(|_| {
                let ran = ran.clone();
                std::thread::spawn(move || {
                    decide_remembered(Some(key), Instant::now() + Duration::from_secs(5), || {
                        ran.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        std::thread::sleep(Duration::from_millis(100));
                        Verdict::Far
                    })
                })
            })
            .collect();
        for h in hs {
            assert_eq!(h.join().unwrap(), Verdict::Far);
        }
        assert_eq!(ran.load(std::sync::atomic::Ordering::SeqCst), 1);
        let key = ("203.0.113.78:443".parse().unwrap(), 2, 0xfa_0002u64, 9);
        let ran = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let hs: Vec<_> = (0..4)
            .map(|_| {
                let ran = ran.clone();
                std::thread::spawn(move || {
                    decide_remembered(Some(key), Instant::now() + Duration::from_secs(5), || {
                        ran.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        Verdict::Near("answered".into())
                    })
                })
            })
            .collect();
        for h in hs {
            assert!(matches!(h.join().unwrap(), Verdict::Near(_)));
        }
        assert_eq!(ran.load(std::sync::atomic::Ordering::SeqCst), 4);
    }

    /// probe-3: a far verdict is remembered for FAR_TTL, for its exact destination and port, hop
    /// limit, facts and probe.
    #[test]
    fn r6_far_verdicts_are_remembered_only_for_the_same_destination_and_facts() {
        let a: SocketAddr = "198.51.100.7:443".parse().unwrap();
        let facts = 0xfa_0001u64;
        let t0 = Instant::now();
        let key = (a, 2, facts, 1);
        assert!(!remembered_far(key, t0));
        remember_far(key, t0);
        assert!(remembered_far(key, t0 + FAR_TTL - Duration::from_millis(1)));
        assert!(!remembered_far(key, t0 + FAR_TTL));
        remember_far(key, t0);
        for other in [
            ("198.51.100.8:443".parse().unwrap(), 2, facts, 1),
            ("198.51.100.7:80".parse().unwrap(), 2, facts, 1),
            (a, 3, facts, 1),
            (a, 2, facts, 2),
        ] {
            assert!(!remembered_far(other, t0), "{other:?}");
        }
        assert!(!remembered_far((a, 2, facts + 1, 1), t0), "other facts");
    }
}
