//! The near-hop refusal: before every connection made under the floor in public mode, the guard
//! asks whether the destination is within `[egress] near_hop_limit` hops of this host, and admits
//! it as far **only on positive evidence, never on silence** (the S3 review, 2026-11:
//! docs/netguard-hardening.md, "Near-hop rule: positive evidence").
//!
//! Some destinations pass every address and route check and are still the operator's own
//! network: the home router's own global address (its WAN side, reached through the default
//! route like the internet, and on many routers zoned by input interface, so the LAN reaches its
//! admin page, DNS and UPnP on it), a NAT64 translator or NAT router that hairpins its own public
//! address, a cloud VPC neighbour or a campus host reached through the default gateway, the far
//! side of a tunnel. They have in common that they are near.
//!
//! **The probes** ([`TtlProbe`]). Fresh TCP sockets connect to the exact destination address and
//! port with hop limits (`IP_TTL` / `IPV6_UNICAST_HOPS`) `N`, `N + 1` and `N + 2` at once, `N` the
//! limit (default 2: the first-hop router and what sits directly behind it), each from the source
//! address (and interface) the real connection will use; a second round follows about a second
//! later when the first decided nothing ([`ROUNDS`], [`ROUND_PAUSE`]). No data is ever written; a
//! probe that connected is closed with a reset. Unprivileged. What each probe saw
//! ([`ProbeOutcome`]):
//!
//! - **an answer from the destination** (connected, `ECONNREFUSED`, `ECONNRESET`);
//! - **an ICMP error the kernel matched to that probe** (its 4-tuple and initial sequence number),
//!   with its type, code and sender: Linux and Android set `IP_RECVERR` / `IPV6_RECVERR` and read
//!   the error queue (`MSG_ERRQUEUE`: `sock_extended_err`, `SO_EE_ORIGIN_ICMP(6)`, `ee_type`,
//!   `ee_code`, `SO_EE_OFFENDER`); macOS opens a `SOCK_DGRAM` `IPPROTO_ICMP(V6)` socket before the
//!   probes and takes a copy only when its quoted destination address and port, source address
//!   and port and sequence number (the probe's ISN, from the private `TCP_INFO` 0x200) are the
//!   probe's and the probe socket itself failed with `EHOSTUNREACH` / `ENETUNREACH`;
//! - an unreachable without a matched ICMP message, no answer at all, or a local failure.
//!
//! **The rule** ([`rule`]):
//!
//! - **near** (refused, [`crate::Denied::NearHop`]) when the destination answered any probe whose
//!   hop limit was `N` or less;
//! - **far** only when some probe with hop limit `t >= N` got an ICMP Time Exceeded, code 0
//!   (IPv4 11/0, ICMPv6 3/0), matched to it by the kernel, from a unicast, specified sender that
//!   is not the destination, and the destination answered no probe whose hop limit was `t` or
//!   less (an answer only at a hop limit above `N` with no Time Exceeded below it is refused);
//! - **everything else is refused** ([`crate::Denied::NearCheckFailed`]): silence, any
//!   Destination Unreachable, Time Exceeded code 1, a Time Exceeded sent by the destination
//!   itself, an unreachable without its ICMP message, inconsistent results, local errors, a
//!   platform without the ICMP plumbing (Windows today, which refuses every requester connection
//!   in public mode anyway).
//!
//! An answer always dominates an ICMP error queued for the same probe (Linux can queue an error
//! and still complete the connection: `sk_err_soft` while the socket is owned by the user).
//!
//! **The connection that follows** leaves as the probes did: from the same source address, by
//! the same interface where the platform can bind one (macOS `IP_BOUND_IF` / `IPV6_BOUND_IF`;
//! Linux sets `IP_UNICAST_IF` / `IPV6_UNICAST_IF`, which TCP does not follow there), and on Linux
//! with a fixed IPv6 flow label (`IPV6_AUTOFLOWLABEL` off on the probes and the connection), from
//! a new local port ([`crate::Vetted::socket`]). It does not reuse the far probe's port: a
//! stateful home or carrier-grade NAT keeps the probe's session and drops a second SYN on its
//! 4-tuple (measured: every IPv4 connection failed on this project's home path), so a
//! per-connection multi-WAN balancer that routes connections over unequal paths can send the
//! connection another way than the probe (the owner's decision; as before the S3 review). A far
//! verdict is not remembered for other connections.
//!
//! **What "within `N` hops" means, and what it assumes.** A hop is a router that decrements the hop
//! count; a Time Exceeded at hop limit `t` proves only that the probe's own path crossed `t`
//! decrementing routers before the destination. The far verdict holds under four assumptions:
//! (1) no party that sees the probe's SYN forges ICMP (root on a near host, an on-path or on-link
//! attacker: a hostile LAN gets no protection from this check, as from any distance test);
//! (2) routers send Time Exceeded only for packets they forward (RFC 1812 5.3.1), not for their
//! own addresses reached through policy routing or a VRF leak; (3) the real connection follows
//! the probe's path (the pin above; a stateless per-packet balancer, a transient loop or a route
//! change in between can still break it); (4) the kernel's matching of the ICMP error to the probe
//! (on macOS through a private `TCP_INFO` layout). A box that hides hops (double NAT behind the
//! ISP's router, a VM's NAT, a VPN, a userspace NAT64) moves the limit: `near_hop_limit` 2 then
//! does not reach the ISP's first box. Paths whose first hops send no Time Exceeded are refused,
//! every destination on them.
//!
//! **macOS.** A process that Local Network privacy has not been granted to gets `EHOSTUNREACH` at
//! once for a connection into a directly attached network, before any packet is sent (as does a
//! connection a Network Extension policy denies). An error `connect` itself reports, before the
//! connection was in progress, is a local failure, never evidence (see docs/netguard-macos.md).
//! A macOS host whose ICMP socket cannot be opened, or whose `TCP_INFO` cannot be read, refuses
//! every requester connection (said once at startup: [`warn_if_unsupported`]).
//!
//! **What it cannot help:** a probe that connects still reaches a near host (a SYN, a handshake,
//! a reset; never data) before the refusal; a transparent proxy within the limit answers for every
//! destination, so every connection through it is refused; a router that decrements no hop count
//! is invisible to it.

use std::fmt;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

/// How long one round of probes waits for its answers.
pub const PROBE_TIMEOUT: Duration = Duration::from_millis(1500);

/// How many rounds of probes a decision sends at most (the second only when the first decided
/// nothing).
pub const ROUNDS: u32 = 2;

/// The pause before the second round (a router's ICMP rate limit refills: Linux, one "time
/// exceeded" a second per destination after a burst of six).
pub const ROUND_PAUSE: Duration = Duration::from_secs(1);

/// The probes of a round go out at hop limits `N ..= N + EXTRA_HOPS` (a first router past the
/// limit that sends no Time Exceeded leaves the next one to).
pub const EXTRA_HOPS: u8 = 2;

/// The longest the near-hop decision takes when nothing bounds it ([`decide`]): two rounds, the
/// pause between them, and turns waited for.
pub const DECIDE_BUDGET: Duration = Duration::from_secs(8);

/// What one probe saw.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeOutcome {
    /// The destination accepted the connection.
    Connected,
    /// `ECONNREFUSED`: a reset (or an ICMP port unreachable, which is counted as an answer: it
    /// can only make the verdict nearer).
    Refused,
    /// `ECONNRESET`.
    Reset,
    /// An ICMP error the kernel matched to this probe and that ended it: its type and code (ICMP
    /// or ICMPv6, by the destination's family) and the address that sent it.
    Icmp { kind: u8, code: u8, from: IpAddr },
    /// `EHOSTUNREACH` / `ENETUNREACH` with no matched ICMP message to say why.
    Unreachable,
    /// No answer within the round's time.
    TimedOut,
    /// A local failure, or anything else (what it was).
    Failed(String),
}

impl ProbeOutcome {
    /// Whether the destination answered (connected, refused, reset).
    pub fn answered(&self) -> bool {
        matches!(
            self,
            ProbeOutcome::Connected | ProbeOutcome::Refused | ProbeOutcome::Reset
        )
    }

    /// How an answer is named in a refusal.
    fn how(&self) -> &'static str {
        match self {
            ProbeOutcome::Connected => "accepted a connection",
            ProbeOutcome::Refused => "refused a connection",
            _ => "reset a connection",
        }
    }
}

/// One probe: its hop limit, what it saw, and the address it left from (`None` only where a test
/// stages it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Obs {
    pub ttl: u8,
    pub outcome: ProbeOutcome,
    pub local: Option<SocketAddr>,
}

/// The evidence a far verdict rests on: the hop limit of the probe whose Time Exceeded it was,
/// the router that sent it, and the address and port that probe left from (which the real
/// connection binds: `None` only from a test's staged probe).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FarEvidence {
    pub ttl: u8,
    pub from: IpAddr,
    pub local: Option<SocketAddr>,
}

/// What the probes mean for the connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// The destination answered within the hop limit (how): refuse.
    Near(&'static str),
    /// A router past the hop limit said the probe ran out of hops: connect, pinned to the
    /// evidence's probe.
    Far(FarEvidence),
    /// No positive evidence either way (what the probes saw): refuse.
    NoEvidence(String),
    /// The probes failed or contradicted each other (why): refuse.
    Failed(String),
}

/// Where the probes (and then the real connection) leave from: the source address the kernel
/// chose for the destination, and the interface that holds it. `None`: the kernel's choice.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Pin {
    pub source: Option<IpAddr>,
    pub interface: Option<u32>,
}

/// ICMP Time Exceeded, code 0 ("hop limit exceeded in transit") for a destination of `dst`'s
/// family: IPv4 type 11, ICMPv6 type 3.
pub fn time_exceeded(dst: IpAddr) -> (u8, u8) {
    if dst.is_ipv6() {
        (3, 0)
    } else {
        (11, 0)
    }
}

/// Whether `from` can be the router a Time Exceeded for a probe of `dst` came from: the same
/// family, not `dst` itself, a specified unicast address (not multicast, broadcast, loopback, or
/// an IPv4-mapped IPv6 address).
fn router_sent(from: IpAddr, dst: IpAddr) -> bool {
    if from == dst || from.is_unspecified() || from.is_multicast() || from.is_loopback() {
        return false;
    }
    match (from, dst) {
        (IpAddr::V4(f), IpAddr::V4(_)) => !f.is_broadcast(),
        (IpAddr::V6(f), IpAddr::V6(_)) => f.to_ipv4_mapped().is_none(),
        _ => false,
    }
}

/// The decision on what the probes of every round saw (see the module doc). Pure.
pub fn rule(dst: IpAddr, hops: u8, obs: &[Obs]) -> Verdict {
    if let Some(o) = obs
        .iter()
        .filter(|o| o.ttl <= hops && o.outcome.answered())
        .min_by_key(|o| o.ttl)
    {
        return Verdict::Near(o.outcome.how());
    }
    let (te, te_code) = time_exceeded(dst);
    let evidence = obs
        .iter()
        .filter(|o| o.ttl >= hops)
        .filter_map(|o| match o.outcome {
            ProbeOutcome::Icmp { kind, code, from }
                if kind == te && code == te_code && router_sent(from, dst) =>
            {
                Some(FarEvidence {
                    ttl: o.ttl,
                    from,
                    local: o.local,
                })
            }
            _ => None,
        })
        .min_by_key(|e| e.ttl);
    let answered_at_or_below = |t: u8| obs.iter().any(|o| o.ttl <= t && o.outcome.answered());
    match evidence {
        Some(e) if !answered_at_or_below(e.ttl) => Verdict::Far(e),
        Some(e) => Verdict::Failed(format!(
            "inconsistent: it answered a probe of at most {} hops, which a router at {} said \
             ran out",
            e.ttl, e.from
        )),
        None => {
            if let Some(why) = obs.iter().find_map(|o| match &o.outcome {
                ProbeOutcome::Failed(why) => Some(why),
                _ => None,
            }) {
                return Verdict::Failed(format!("a probe failed: {}", crate::printable(why, 100)));
            }
            Verdict::NoEvidence(format!(
                "no router past {hops} hops said a probe ran out of hops (a time exceeded), and \
                 silence is not taken as far ({})",
                summary(obs)
            ))
        }
    }
}

/// What the probes saw, counted.
fn summary(obs: &[Obs]) -> String {
    let n = |f: &dyn Fn(&ProbeOutcome) -> bool| obs.iter().filter(|o| f(&o.outcome)).count();
    format!(
        "{} probes: no answer {}, answered beyond the limit {}, other ICMP {}, unreachable {}",
        obs.len(),
        n(&|s| *s == ProbeOutcome::TimedOut),
        n(&|s| s.answered()),
        n(&|s| matches!(s, ProbeOutcome::Icmp { .. })),
        n(&|s| *s == ProbeOutcome::Unreachable),
    )
}

/// Sends the probes ([`TtlProbe`] for real; a fake in tests, where a loopback server stands in for
/// a public address, or a router's answer is staged).
pub trait NearProbe: Send + Sync + fmt::Debug {
    /// Round `round` (0, 1, …) of probes to `addr` (an IPv4 address for an IPv4-mapped one) at
    /// hop limits `hops ..= hops + extra`, from `pin`, each waited for at most `wait` and never
    /// past `deadline`: what each saw, or why the round could not be sent. Blocking.
    #[allow(clippy::too_many_arguments)]
    fn round(
        &self,
        round: u32,
        addr: SocketAddr,
        hops: u8,
        extra: u8,
        pin: &Pin,
        wait: Duration,
        deadline: Instant,
    ) -> Result<Vec<Obs>, String>;

    /// The pause before a further round ([`ROUND_PAUSE`]; a test's fake need not wait).
    fn pause(&self) -> Duration {
        ROUND_PAUSE
    }
}

/// The near-hop decision for a connection to `addr` (see the module doc), from the kernel's
/// source. Blocking (up to [`DECIDE_BUDGET`]).
pub fn decide(probe: &dyn NearProbe, addr: SocketAddr, hops: u8) -> Verdict {
    decide_until(probe, addr, hops, &Pin::default(), Instant::now() + DECIDE_BUDGET)
}

/// [`decide`] from `pin`, given up on at `deadline` (review round 5, probe-1): a caller that stops
/// waiting (the broker's connector, a guarded request whose budget ran out) passes its own, so
/// the work it abandons stops too and gives back its turn ([`ProbeGate`]). Out of time is a
/// failure (refused), never far. Up to [`ROUNDS`] rounds, [`ROUND_PAUSE`] apart; the first that
/// decides near or far ends it.
pub fn decide_until(
    probe: &dyn NearProbe,
    addr: SocketAddr,
    hops: u8,
    pin: &Pin,
    deadline: Instant,
) -> Verdict {
    let addr = unmapped(addr);
    let left = || deadline.saturating_duration_since(Instant::now());
    let mut all: Vec<Obs> = Vec::new();
    for round in 0..ROUNDS {
        if round > 0 {
            std::thread::sleep(probe.pause().min(left()));
        }
        let wait = PROBE_TIMEOUT.min(left());
        if wait.is_zero() {
            if round == 0 {
                return Verdict::Failed(OUT_OF_TIME.into());
            }
            break;
        }
        match probe.round(round, addr, hops, EXTRA_HOPS, pin, wait, deadline) {
            Ok(obs) => all.extend(obs),
            Err(why) if round == 0 => return Verdict::Failed(crate::printable(&why, 160)),
            // A later round that could not be sent decides nothing more.
            Err(_) => break,
        }
        if let v @ (Verdict::Near(_) | Verdict::Far(_)) = rule(addr.ip(), hops, &all) {
            return v;
        }
    }
    rule(addr.ip(), hops, &all)
}

/// Why a decision out of time failed.
const OUT_OF_TIME: &str = "the time for the check ran out before it could tell how near it is";

/// The real probe: fresh TCP sockets with their hop limits set, connected without sending data,
/// their ICMP errors read (see the module doc). Each round takes one turn of the probe gate
/// ([`ProbeGate`]: one token for its three SYNs, since each router on the path expires at most
/// one of them).
#[derive(Debug, Clone, Copy, Default)]
pub struct TtlProbe;

impl NearProbe for TtlProbe {
    #[allow(clippy::too_many_arguments)]
    fn round(
        &self,
        _round: u32,
        addr: SocketAddr,
        hops: u8,
        extra: u8,
        pin: &Pin,
        wait: Duration,
        deadline: Instant,
    ) -> Result<Vec<Obs>, String> {
        let addr = unmapped(addr);
        if deadline <= Instant::now() {
            return Err(OUT_OF_TIME.into());
        }
        let Some(_turn) = Turn::enter_for(addr, deadline) else {
            return Err(NO_TURN.into());
        };
        #[cfg(test)]
        ROUNDS_SENT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let wait = wait.min(deadline.saturating_duration_since(Instant::now()));
        if wait.is_zero() {
            return Err(OUT_OF_TIME.into());
        }
        observe(addr, hops, extra, pin, wait)
    }
}

/// How many rounds the real probe sent (tests).
#[cfg(test)]
static ROUNDS_SENT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Why a round that got no turn before its deadline failed ([`ProbeGate::enter_until`]).
const NO_TURN: &str = "no turn to probe before the check's time ran out (too many probes at once)";

/// Says once, at startup in public mode, when this host cannot read the ICMP errors the rule needs
/// (every requester connection is then refused as no evidence).
pub fn warn_if_unsupported() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        if let Err(why) = supported() {
            tracing::warn!(
                "network guard: the near-hop check cannot read ICMP errors on this host ({why}): \
                 every requester connection will be refused"
            );
        }
    });
}

/// Whether this host can read what the rule needs (an ICMP socket on macOS, `TCP_INFO`; the
/// error queue on Linux), or why not.
pub fn supported() -> Result<(), String> {
    #[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
    {
        for v6 in [false, true] {
            let addr: SocketAddr = if v6 {
                "[2001:db8::1]:9".parse().unwrap()
            } else {
                "192.0.2.1:9".parse().unwrap()
            };
            let sock = new_socket(addr).map_err(|e| e.to_string())?;
            #[cfg(any(target_os = "linux", target_os = "android"))]
            set_recverr(&sock, addr).map_err(|e| format!("IP_RECVERR: {e}"))?;
            #[cfg(target_os = "macos")]
            {
                // An IPv6 ICMP socket where IPv6 is off is no loss: no IPv6 probe is sent then.
                if let Err(e) = icmp_socket(v6) {
                    if !v6 {
                        return Err(format!("an ICMP socket: {e}"));
                    }
                }
                if !v6 {
                    use std::os::fd::AsRawFd;
                    let mut b = [0u8; TCP_INFO_BUF];
                    tcp_info(sock.as_raw_fd(), &mut b).map_err(|e| format!("TCP_INFO: {e}"))?;
                }
            }
            drop(sock);
        }
        Ok(())
    }
    #[cfg(not(any(target_os = "linux", target_os = "android", target_os = "macos")))]
    {
        Err(UNSUPPORTED.into())
    }
}

/// A probe that answers the same every time, run through the real [`rule`], and records what it
/// was asked: for tests, where a server on loopback stands in for a public address (the real
/// probe would find it near), or where a near destination or a router's answer is staged. Test
/// builds only (the `test-util` feature).
#[cfg(any(test, feature = "test-util"))]
#[derive(Debug)]
pub struct FixedProbe {
    /// Per round (the last repeats): what each hop limit's probe saw; `None` for the staged Time
    /// Exceeded from [`FixedProbe::ROUTER_V4`] or [`FixedProbe::ROUTER_V6`].
    pub rounds: Vec<Vec<(u8, Option<ProbeOutcome>)>>,
    /// The address the evidence's probe left from, when staged.
    pub local: Option<SocketAddr>,
    /// The decisions asked for: destination and hop limit (once per decision).
    pub asked: std::sync::Mutex<Vec<(SocketAddr, u8)>>,
    /// The pins the decisions were given.
    pub pins: std::sync::Mutex<Vec<Pin>>,
}

#[cfg(any(test, feature = "test-util"))]
impl FixedProbe {
    /// The router a staged Time Exceeded comes from (TEST-NET-2 / the IPv6 documentation prefix).
    pub const ROUTER_V4: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(198, 51, 100, 1));
    pub const ROUTER_V6: IpAddr = IpAddr::V6(std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x99));

    /// A probe that always finds the destination far: a router past the limit sends a Time
    /// Exceeded for every probe.
    pub fn far() -> std::sync::Arc<Self> {
        Self::staged(vec![(0, None)], None)
    }

    /// [`Self::far`], its evidence's probe having left from `local`.
    pub fn far_from(local: SocketAddr) -> std::sync::Arc<Self> {
        Self::staged(vec![(0, None)], Some(local))
    }

    /// A probe each of whose probes ends with `outcome`, at every hop limit and in every round.
    pub fn answering(outcome: ProbeOutcome) -> std::sync::Arc<Self> {
        Self::staged(vec![(0, Some(outcome))], None)
    }

    /// One round staged, repeated: per hop limit offset from the limit (0 = `N`), what that probe
    /// saw (`None`: a router's Time Exceeded); a hop limit not listed is silent.
    pub fn staged(
        round: Vec<(u8, Option<ProbeOutcome>)>,
        local: Option<SocketAddr>,
    ) -> std::sync::Arc<Self> {
        Self::rounds(vec![round], local)
    }

    /// Several rounds staged (the last repeats).
    pub fn rounds(
        rounds: Vec<Vec<(u8, Option<ProbeOutcome>)>>,
        local: Option<SocketAddr>,
    ) -> std::sync::Arc<Self> {
        std::sync::Arc::new(FixedProbe {
            rounds,
            local,
            asked: std::sync::Mutex::new(Vec::new()),
            pins: std::sync::Mutex::new(Vec::new()),
        })
    }
}

#[cfg(any(test, feature = "test-util"))]
impl NearProbe for FixedProbe {
    #[allow(clippy::too_many_arguments)]
    fn round(
        &self,
        round: u32,
        addr: SocketAddr,
        hops: u8,
        extra: u8,
        pin: &Pin,
        _: Duration,
        _: Instant,
    ) -> Result<Vec<Obs>, String> {
        if round == 0 {
            self.asked
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push((addr, hops));
            self.pins.lock().unwrap_or_else(|e| e.into_inner()).push(*pin);
        }
        let staged = self
            .rounds
            .get(round as usize)
            .or(self.rounds.last())
            .cloned()
            .unwrap_or_default();
        let router = if addr.is_ipv6() {
            Self::ROUTER_V6
        } else {
            Self::ROUTER_V4
        };
        let (kind, code) = time_exceeded(addr.ip());
        Ok((0..=extra)
            .map(|k| {
                let outcome = match staged.iter().find(|(o, _)| *o == k) {
                    Some((_, Some(o))) => o.clone(),
                    Some((_, None)) => ProbeOutcome::Icmp {
                        kind,
                        code,
                        from: router,
                    },
                    None => ProbeOutcome::TimedOut,
                };
                Obs {
                    ttl: hops.saturating_add(k),
                    outcome,
                    local: self.local,
                }
            })
            .collect())
    }

    fn pause(&self) -> Duration {
        Duration::ZERO
    }
}

/// Most rounds of hop-limited probes in flight in the process at once (review round 4,
/// probe-2): they go through the same first hops, whose ICMP rate limit drops answers past a
/// small burst. A round is the three probes of one decision ([`EXTRA_HOPS`]); each router on the
/// path expires at most one of them (the probe at its own hop limit), so a round loads each
/// router's ICMP budget as one probe did before the S3 review.
pub const PROBES_AT_ONCE: usize = 2;

/// Most rounds started in a burst, and how many a second after it (review round 5, the probe
/// lens's suspicion): [`PROBES_AT_ONCE`] bounds how many are in flight, not how many a second,
/// and a requester naming many far hosts could drain the first hops' ICMP rate limit (Linux
/// routers: about one "time exceeded" a second per destination after a burst of six), so that
/// ordinary probes went unanswered (refused: no evidence). A round waits for a token as it waits
/// for a slot, and takes one token for its three probes.
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

/// The turns each thread took (tests: a round takes one).
#[cfg(test)]
static TURNS_TAKEN: std::sync::Mutex<Vec<(std::thread::ThreadId, usize)>> = std::sync::Mutex::new(Vec::new());

/// The turns this thread took (tests).
#[cfg(all(test, unix))]
fn turns_taken() -> usize {
    let me = std::thread::current().id();
    let t = TURNS_TAKEN.lock().unwrap_or_else(|e| e.into_inner());
    t.iter().find(|(id, _)| *id == me).map_or(0, |(_, n)| *n)
}

/// A turn of either family.
#[allow(dead_code)] // held for its Drop
enum Turn {
    V4(ProbeGate),
    V6(ProbeGateV6),
}

impl Turn {
    /// A turn for a probe of `addr`, waited for until `deadline`.
    fn enter_for(addr: SocketAddr, deadline: Instant) -> Option<Self> {
        let turn = if addr.is_ipv4() {
            ProbeGate::enter_until(deadline).map(Turn::V4)
        } else {
            ProbeGateV6::enter_until(deadline).map(Turn::V6)
        };
        #[cfg(test)]
        if turn.is_some() {
            let me = std::thread::current().id();
            let mut t = TURNS_TAKEN.lock().unwrap_or_else(|e| e.into_inner());
            match t.iter_mut().find(|(id, _)| *id == me) {
                Some((_, n)) => *n += 1,
                None => t.push((me, 1)),
            }
        }
        turn
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

/// [`enter_gate`], the turn made by `make` only once given (both families' gates: a turn made
/// and dropped unused would give back one never taken).
fn enter_gate_as<G>(
    m: &std::sync::Mutex<GateState>,
    cv: &std::sync::Condvar,
    deadline: Instant,
    make: impl FnOnce() -> G,
) -> Option<G> {
    enter_gate(m, cv, deadline).then(make)
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
    /// came in time ([`enter_gate`]). The turn is made only once given: before the S3 review
    /// `then_some(ProbeGate)` made one either way, and dropping the unused one gave back a turn
    /// never taken, so every caller that got none let one more probe in flight.
    fn enter_until(deadline: Instant) -> Option<Self> {
        enter_gate_as(&PROBES_IN_FLIGHT, &PROBE_TURN, deadline, || ProbeGate)
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
        enter_gate_as(&PROBES_IN_FLIGHT_V6, &PROBE_TURN_V6, deadline, || ProbeGateV6)
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

/// A fresh TCP socket of `addr`'s family.
pub(crate) fn new_socket(addr: SocketAddr) -> io::Result<socket2::Socket> {
    use socket2::{Domain, Protocol, Socket, Type};
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    Socket::new(domain, Type::STREAM, Some(Protocol::TCP))
}

#[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
fn set_hops(sock: &socket2::Socket, addr: SocketAddr, hops: u8) -> io::Result<()> {
    if addr.is_ipv4() {
        sock.set_ttl_v4(u32::from(hops))
    } else {
        sock.set_unicast_hops_v6(u32::from(hops))
    }
}

/// `setsockopt` of an `int` option.
#[cfg(unix)]
fn set_int(sock: &socket2::Socket, level: libc::c_int, opt: libc::c_int, v: libc::c_int) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    // SAFETY: a valid fd and a c_int option value of the size given.
    let rc = unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            level,
            opt,
            (&v as *const libc::c_int).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Linux: ICMP errors for the socket queued with their details (`IP_RECVERR` / `IPV6_RECVERR`).
#[cfg(any(target_os = "linux", target_os = "android"))]
fn set_recverr(sock: &socket2::Socket, addr: SocketAddr) -> io::Result<()> {
    if addr.is_ipv4() {
        set_int(sock, libc::IPPROTO_IP, libc::IP_RECVERR, 1)
    } else {
        set_int(sock, libc::IPPROTO_IPV6, libc::IPV6_RECVERR, 1)
    }
}

/// Pins a socket for `addr` as the probes and the real connection are pinned (see the module
/// doc): on Linux a fixed IPv6 flow label (`IPV6_AUTOFLOWLABEL` off: a balancer that hashes the
/// flow label sees the probe's and the connection's alike, and Linux does not rehash it on a
/// retransmission); `pin`'s interface (macOS `IP_BOUND_IF` / `IPV6_BOUND_IF`, Linux
/// `IP_UNICAST_IF` / `IPV6_UNICAST_IF`); bound to `pin`'s source and `port` (0: any).
pub(crate) fn pin_socket(
    sock: &socket2::Socket,
    addr: SocketAddr,
    pin: &Pin,
    port: u16,
) -> io::Result<()> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    if addr.is_ipv6() {
        set_int(sock, libc::IPPROTO_IPV6, libc::IPV6_AUTOFLOWLABEL, 0)?;
    }
    if let Some(i) = pin.interface {
        bind_interface(sock, addr, i)?;
    }
    if let Some(src) = pin.source {
        sock.bind(&SocketAddr::new(src, port).into())?;
    }
    Ok(())
}

/// Binds the socket's traffic to interface `index`.
#[cfg(target_os = "macos")]
fn bind_interface(sock: &socket2::Socket, addr: SocketAddr, index: u32) -> io::Result<()> {
    let i = index as libc::c_int;
    if addr.is_ipv4() {
        set_int(sock, libc::IPPROTO_IP, libc::IP_BOUND_IF, i)
    } else {
        set_int(sock, libc::IPPROTO_IPV6, libc::IPV6_BOUND_IF, i)
    }
}

/// Linux: `IP_UNICAST_IF` / `IPV6_UNICAST_IF` to interface `index` (both take it in network byte
/// order; the IPv6 one in host order was refused with `EADDRNOTAVAIL`, found on the Linux VM). It
/// steers UDP and raw sockets; measured on kernel 7.0, a TCP connect is routed as without it
/// (the unprivileged way to hold a TCP socket to an interface, `SO_BINDTODEVICE`, needs
/// `CAP_NET_RAW`), so on Linux the path pin is the source address and the port, and the check
/// once connected ([`crate::NetPolicy::recheck_connected`]).
#[cfg(any(target_os = "linux", target_os = "android"))]
fn bind_interface(sock: &socket2::Socket, addr: SocketAddr, index: u32) -> io::Result<()> {
    let index = index.to_be() as libc::c_int;
    if addr.is_ipv4() {
        set_int(sock, libc::IPPROTO_IP, libc::IP_UNICAST_IF, index)
    } else {
        set_int(sock, libc::IPPROTO_IPV6, libc::IPV6_UNICAST_IF, index)
    }
}

/// No interface pin here (no far verdict is ever given on such a platform).
#[cfg(not(any(target_os = "linux", target_os = "android", target_os = "macos")))]
fn bind_interface(_: &socket2::Socket, _: SocketAddr, _: u32) -> io::Result<()> {
    Ok(())
}

/// The interface that holds local address `ip` (`getifaddrs`), if any.
#[cfg(unix)]
pub(crate) fn interface_of(ip: IpAddr) -> io::Result<Option<u32>> {
    let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs writes a list it allocates, freed below.
    if unsafe { libc::getifaddrs(&mut ifap) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let mut found = None;
    let mut p = ifap;
    while !p.is_null() {
        // SAFETY: a node of the list getifaddrs returned.
        let ifa = unsafe { &*p };
        // SAFETY: ifa_addr is null or a sockaddr of its family.
        if !ifa.ifa_addr.is_null() && unsafe { sockaddr_ip(ifa.ifa_addr) } == Some(ip) {
            // SAFETY: ifa_name is the interface's NUL-terminated name.
            let i = unsafe { libc::if_nametoindex(ifa.ifa_name) };
            found = (i != 0).then_some(i);
            break;
        }
        p = ifa.ifa_next;
    }
    // SAFETY: the list getifaddrs returned, freed once.
    unsafe { libc::freeifaddrs(ifap) };
    Ok(found)
}

/// No interface lookup here.
#[cfg(not(unix))]
pub(crate) fn interface_of(_: IpAddr) -> io::Result<Option<u32>> {
    Ok(None)
}

/// The address of a `sockaddr_in` / `sockaddr_in6`.
///
/// # Safety
/// `sa` points to a sockaddr whose family says how long it is.
#[cfg(unix)]
unsafe fn sockaddr_ip(sa: *const libc::sockaddr) -> Option<IpAddr> {
    match i32::from((*sa).sa_family) {
        libc::AF_INET => {
            let a = &*(sa as *const libc::sockaddr_in);
            Some(IpAddr::from(u32::from_be(a.sin_addr.s_addr).to_be_bytes()))
        }
        libc::AF_INET6 => {
            let a = &*(sa as *const libc::sockaddr_in6);
            Some(IpAddr::from(a.sin6_addr.s6_addr))
        }
        _ => None,
    }
}

/// An IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) as its IPv4 address, which is what a
/// connection to it reaches. An IPv6 socket connected to a mapped address sends IPv4 packets, and
/// `IPV6_UNICAST_HOPS` need not limit them (on macOS they left with the default TTL, so the probe
/// of a far host connected and read it as near: `r2-probe/mapped.log`); an IPv4 socket with
/// `IP_TTL` set limits them. Review round 2, probe-2, on every platform since the Linux
/// application ([`crate::NetPolicy::vet_connection`] already unmaps before it asks).
fn unmapped(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V6(a) => match a.ip().to_ipv4_mapped() {
            Some(v4) => SocketAddr::new(std::net::IpAddr::V4(v4), a.port()),
            None => addr,
        },
        v4 => v4,
    }
}

/// What a probe saw, from how its own socket ended (`None`: not yet, at the round's end) and the
/// ICMP errors matched to it: an answer dominates any ICMP error (Linux can queue one and still
/// complete the connection: `sk_err_soft` while the socket is owned by the user; the S3 review's
/// skeptic); an unreachable is the ICMP error that caused it when one kind was matched (several
/// different ones: a failure), a plain unreachable when none was; an ICMP error the socket did not
/// end on is no evidence (no answer).
#[cfg(any(test, target_os = "linux", target_os = "android", target_os = "macos"))]
fn settle(end: Option<ProbeOutcome>, icmp: &[(u8, u8, IpAddr)]) -> ProbeOutcome {
    match end {
        None => ProbeOutcome::TimedOut,
        Some(ProbeOutcome::Unreachable) => match icmp.first() {
            Some(&first) if icmp.iter().all(|e| *e == first) => ProbeOutcome::Icmp {
                kind: first.0,
                code: first.1,
                from: first.2,
            },
            Some(_) => ProbeOutcome::Failed("different ICMP errors for one probe".into()),
            None => ProbeOutcome::Unreachable,
        },
        Some(o) => o,
    }
}

/// Whether what the probes of a round saw so far (`None`: not yet ended) already decides it, so
/// the round ends at once and the connection can follow its probe closely: an answer within the
/// limit (near), or a far verdict whose every probe at or below its hop limit has ended (no later
/// answer can contradict it: only an answer at or below that hop limit could).
#[cfg(any(test, target_os = "linux", target_os = "android", target_os = "macos"))]
fn decided(dst: IpAddr, hops: u8, seen: &[(u8, Option<ProbeOutcome>)]) -> bool {
    let ended: Vec<Obs> = seen
        .iter()
        .filter_map(|(ttl, o)| {
            o.clone().map(|outcome| Obs {
                ttl: *ttl,
                outcome,
                local: None,
            })
        })
        .collect();
    match rule(dst, hops, &ended) {
        Verdict::Near(_) => true,
        Verdict::Far(e) => seen.iter().all(|(t, o)| *t > e.ttl || o.is_some()),
        _ => false,
    }
}

/// How a probe's socket ended, from its pending error (`SO_ERROR`) when it has one.
#[cfg(unix)]
fn ended(e: &io::Error) -> ProbeOutcome {
    match e.raw_os_error() {
        Some(libc::ECONNREFUSED) => ProbeOutcome::Refused,
        Some(libc::ECONNRESET) => ProbeOutcome::Reset,
        Some(libc::EHOSTUNREACH) | Some(libc::ENETUNREACH) => ProbeOutcome::Unreachable,
        Some(libc::ETIMEDOUT) => ProbeOutcome::TimedOut,
        _ => ProbeOutcome::Failed(e.to_string()),
    }
}

/// An error `connect` reported at once, before the connection was in progress: a reset (on
/// loopback) is an answer; anything else (Local Network privacy, a Network Extension policy, no
/// route) is a local failure, never evidence: no packet was answered.
#[cfg(unix)]
fn at_once(e: io::Error) -> ProbeOutcome {
    match e.raw_os_error() {
        Some(libc::ECONNREFUSED) => ProbeOutcome::Refused,
        Some(libc::ECONNRESET) => ProbeOutcome::Reset,
        _ => ProbeOutcome::Failed(format!("{e}, before any packet was answered")),
    }
}

/// How a probe's socket ended once `poll` reported `revents` on it, from its pending error (read
/// first: `SO_ERROR`), whether it is connected, and how many error-queue entries were read: an
/// error is how it ended; connected is an answer; no error with an ICMP error queued is Linux's
/// soft error (the connection goes on: not ended, how it ends decides); neither is a failure.
#[cfg(unix)]
fn socket_end(
    error: io::Result<Option<io::Error>>,
    connected: bool,
    queued: usize,
    revents: libc::c_short,
) -> Option<ProbeOutcome> {
    match error {
        Err(e) => Some(ProbeOutcome::Failed(e.to_string())),
        Ok(Some(e)) => Some(ended(&e)),
        Ok(None) if connected => Some(ProbeOutcome::Connected),
        Ok(None) if queued > 0 => None,
        Ok(None) => Some(ProbeOutcome::Failed(format!(
            "the socket reported {revents:#x} with neither an error nor a connection"
        ))),
    }
}

/// One probe of a round.
#[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
struct Probe {
    sock: socket2::Socket,
    ttl: u8,
    local: SocketAddr,
    /// How its socket ended.
    end: Option<ProbeOutcome>,
    /// The ICMP errors matched to it: type, code, sender.
    icmp: Vec<(u8, u8, IpAddr)>,
    /// macOS: its initial sequence number, while in `SYN_SENT` when read.
    #[cfg(target_os = "macos")]
    isn: Option<u32>,
}

#[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
impl Probe {
    /// A probe to `addr` with hop limit `ttl`, from `pin`, its connect started.
    fn open(addr: SocketAddr, ttl: u8, pin: &Pin) -> io::Result<Self> {
        let sock = new_socket(addr)?;
        set_hops(&sock, addr, ttl)?;
        #[cfg(any(target_os = "linux", target_os = "android"))]
        set_recverr(&sock, addr)?;
        pin_socket(&sock, addr, pin, 0)?;
        sock.set_nonblocking(true)?;
        let end = match sock.connect(&addr.into()) {
            Ok(()) => Some(ProbeOutcome::Connected),
            Err(e) if e.raw_os_error() == Some(libc::EINPROGRESS) => None,
            Err(e) => Some(at_once(e)),
        };
        // Closed with a reset, never a byte of data.
        let _ = sock.set_linger(Some(Duration::ZERO));
        let local = sock
            .local_addr()?
            .as_socket()
            .ok_or_else(|| io::Error::other("the probe's own address is not an IP address"))?;
        #[cfg(target_os = "macos")]
        let isn = match end {
            None => {
                use std::os::fd::AsRawFd;
                let mut b = [0u8; TCP_INFO_BUF];
                let n = tcp_info(sock.as_raw_fd(), &mut b)?;
                isn_from(&b[..n])?
            }
            Some(_) => None,
        };
        Ok(Probe {
            sock,
            ttl,
            local,
            end,
            icmp: Vec::new(),
            #[cfg(target_os = "macos")]
            isn,
        })
    }

    /// The socket reported `revents`: how it ended, its queued ICMP errors read (Linux). Its
    /// pending error is read first: reading the error queue clears it (`sock_dequeue_err_skb`).
    fn ready(&mut self, revents: libc::c_short) {
        let error = self.sock.take_error();
        #[cfg(any(target_os = "linux", target_os = "android"))]
        let queued = self.read_errqueue();
        #[cfg(target_os = "macos")]
        let queued = 0;
        self.end = socket_end(error, self.sock.peer_addr().is_ok(), queued, revents);
    }

    /// Linux: every ICMP error queued for the probe (`MSG_ERRQUEUE`), kept when it is an ICMP
    /// message of the probe's family; how many entries were read.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn read_errqueue(&mut self) -> usize {
        use std::os::fd::AsRawFd;
        let v6 = self.local.is_ipv6();
        let mut n = 0;
        while n < 16 {
            let mut data = [0u8; 256];
            let mut cbuf = [0u64; 64];
            let mut iov = libc::iovec {
                iov_base: data.as_mut_ptr().cast(),
                iov_len: data.len(),
            };
            // SAFETY: a zeroed msghdr, then filled with valid buffers.
            let mut m: libc::msghdr = unsafe { std::mem::zeroed() };
            m.msg_iov = &mut iov;
            m.msg_iovlen = 1;
            m.msg_control = cbuf.as_mut_ptr().cast();
            m.msg_controllen = std::mem::size_of_val(&cbuf) as _;
            // SAFETY: as above; MSG_DONTWAIT: an empty queue is EAGAIN.
            let r = unsafe {
                libc::recvmsg(
                    self.sock.as_raw_fd(),
                    &mut m,
                    libc::MSG_ERRQUEUE | libc::MSG_DONTWAIT,
                )
            };
            if r < 0 {
                break;
            }
            n += 1;
            // SAFETY: the control buffer the kernel wrote, walked with the libc CMSG macros.
            if let Some(e) = unsafe { errqueue_entry(&m, v6) } {
                self.icmp.push(e);
            }
        }
        n
    }
}

/// Linux: the ICMP error of one error-queue message: type, code and sender (`SO_EE_OFFENDER`),
/// when its origin is ICMP (IPv4) or ICMPv6 (`v6`) and its control message holds the whole
/// `sock_extended_err` and offender.
///
/// # Safety
/// `m` is a msghdr `recvmsg` filled.
#[cfg(any(target_os = "linux", target_os = "android"))]
unsafe fn errqueue_entry(m: &libc::msghdr, v6: bool) -> Option<(u8, u8, IpAddr)> {
    let (level, kind, origin, addr_len) = if v6 {
        (
            libc::IPPROTO_IPV6,
            libc::IPV6_RECVERR,
            libc::SO_EE_ORIGIN_ICMP6,
            std::mem::size_of::<libc::sockaddr_in6>(),
        )
    } else {
        (
            libc::IPPROTO_IP,
            libc::IP_RECVERR,
            libc::SO_EE_ORIGIN_ICMP,
            std::mem::size_of::<libc::sockaddr_in>(),
        )
    };
    let need = libc::CMSG_LEN((std::mem::size_of::<libc::sock_extended_err>() + addr_len) as u32) as usize;
    let mut c = libc::CMSG_FIRSTHDR(m);
    while !c.is_null() {
        let h = &*c;
        if h.cmsg_level == level && h.cmsg_type == kind && h.cmsg_len as usize >= need {
            let e = &*(libc::CMSG_DATA(c) as *const libc::sock_extended_err);
            if e.ee_origin != origin {
                return None;
            }
            let off = (e as *const libc::sock_extended_err).add(1) as *const libc::sockaddr;
            let from = sockaddr_ip(off)?;
            return Some((e.ee_type, e.ee_code, from));
        }
        c = libc::CMSG_NXTHDR(m, c);
    }
    None
}

/// macOS: the private `TCP_INFO` option (xnu `tcp_private.h`), whose `struct tcp_info` holds
/// `tcpi_state` at 0 and `tcpi_snd_nxt` at 52.
#[cfg(target_os = "macos")]
const TCP_INFO_PRIVATE: libc::c_int = 0x200;
/// The bytes of it read: up to `tcpi_snd_nxt`'s end (this Mac's kernel writes 424).
#[cfg(any(test, target_os = "macos"))]
const TCP_INFO_NEEDED: usize = 56;
/// The buffer it is read into.
#[cfg(target_os = "macos")]
const TCP_INFO_BUF: usize = 1024;
/// xnu's `TCPS_SYN_SENT`.
#[cfg(any(test, target_os = "macos"))]
const TCPS_SYN_SENT: u8 = 2;

/// macOS: `getsockopt(IPPROTO_TCP, TCP_INFO 0x200)` on `fd` into `b`: how many bytes the kernel
/// wrote, an error when that does not reach `tcpi_snd_nxt`'s end.
#[cfg(target_os = "macos")]
fn tcp_info(fd: i32, b: &mut [u8; TCP_INFO_BUF]) -> io::Result<usize> {
    let mut len = b.len() as libc::socklen_t;
    // SAFETY: `b` and `len` are valid for the size given; the kernel writes at most `len` bytes.
    let rc = unsafe {
        libc::getsockopt(fd, libc::IPPROTO_TCP, TCP_INFO_PRIVATE, b.as_mut_ptr().cast(), &mut len)
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    let len = len as usize;
    if len < TCP_INFO_NEEDED || len > b.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("TCP_INFO wrote {len} bytes, not the {TCP_INFO_NEEDED} needed"),
        ));
    }
    Ok(len)
}

/// macOS: a probe's initial sequence number from the `TCP_INFO` bytes the kernel wrote
/// (`tcpi_snd_nxt - 1` while in `SYN_SENT`, when only the SYN has been sent); `None` when the
/// connection is no longer in `SYN_SENT` (it already ended: an ICMP error then cannot be matched
/// to it, and is no evidence); an error when the bytes are too few or the number is zero.
#[cfg(any(test, target_os = "macos"))]
fn isn_from(b: &[u8]) -> io::Result<Option<u32>> {
    if b.len() < TCP_INFO_NEEDED {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("TCP_INFO wrote {} bytes, not the {TCP_INFO_NEEDED} needed", b.len()),
        ));
    }
    if b[0] != TCPS_SYN_SENT {
        return Ok(None);
    }
    let snd_nxt = u32::from_ne_bytes([b[52], b[53], b[54], b[55]]);
    let isn = snd_nxt.wrapping_sub(1);
    if snd_nxt == 0 || isn == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "TCP_INFO gave the probe no initial sequence number",
        ));
    }
    Ok(Some(isn))
}

/// macOS: the round's probes' initial sequence numbers must differ (two equal ones could not tell
/// whose ICMP error is whose).
#[cfg(any(test, target_os = "macos"))]
fn distinct_isns(isns: &[Option<u32>]) -> Result<(), String> {
    let known: Vec<u32> = isns.iter().flatten().copied().collect();
    for (i, a) in known.iter().enumerate() {
        if known[i + 1..].contains(a) {
            return Err("two probes read the same initial sequence number".into());
        }
    }
    Ok(())
}

/// What an ICMP error quotes of the TCP segment it is about ([`icmp_quote`]).
#[cfg(any(test, target_os = "macos"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Quote {
    kind: u8,
    code: u8,
    src: IpAddr,
    sport: u16,
    seq: u32,
}

/// macOS: an ICMP datagram as the `SOCK_DGRAM` ICMP socket hands it over (IPv4 with its IP header,
/// ICMPv6 without), when it quotes a TCP segment to `dst` (its address and port): its type, code,
/// and the quoted segment's source address, source port and sequence number. Pure.
#[cfg(any(test, target_os = "macos"))]
fn icmp_quote(b: &[u8], dst: SocketAddr) -> Option<Quote> {
    let icmp = if dst.is_ipv6() {
        b
    } else {
        if b.first()? >> 4 != 4 {
            return None;
        }
        b.get(usize::from(b[0] & 15) * 4..)?
    };
    let (kind, code) = (*icmp.first()?, *icmp.get(1)?);
    let inner = icmp.get(8..)?;
    let (src, qdst, l4): (IpAddr, IpAddr, &[u8]) = if dst.is_ipv6() {
        if inner.len() < 48 || inner[0] >> 4 != 6 || inner[6] != 6 {
            return None;
        }
        let a = |o: usize| {
            let mut x = [0u8; 16];
            x.copy_from_slice(&inner[o..o + 16]);
            IpAddr::from(x)
        };
        (a(8), a(24), &inner[40..])
    } else {
        let ihl = usize::from(*inner.first()? & 15) * 4;
        if inner[0] >> 4 != 4 || ihl < 20 || inner.len() < ihl + 8 || inner[9] != 6 {
            return None;
        }
        (
            IpAddr::from([inner[12], inner[13], inner[14], inner[15]]),
            IpAddr::from([inner[16], inner[17], inner[18], inner[19]]),
            &inner[ihl..],
        )
    };
    let sport = u16::from_be_bytes([l4[0], l4[1]]);
    let dport = u16::from_be_bytes([l4[2], l4[3]]);
    let seq = u32::from_be_bytes([l4[4], l4[5], l4[6], l4[7]]);
    (qdst == dst.ip() && dport == dst.port()).then_some(Quote {
        kind,
        code,
        src,
        sport,
        seq,
    })
}

/// macOS: whether an ICMP error quoting `q` is about the probe that left from `local` with initial
/// sequence number `isn` (known only in `SYN_SENT`): its source port, its sequence number, and its
/// source address (unless the probe's is unspecified). Pure.
#[cfg(any(test, target_os = "macos"))]
fn quotes(q: &Quote, local: SocketAddr, isn: Option<u32>) -> bool {
    let src_ok = local.ip().is_unspecified() || local.ip() == q.src;
    local.port() == q.sport && isn == Some(q.seq) && src_ok
}

/// macOS: a `SOCK_DGRAM` `IPPROTO_ICMP` / `IPPROTO_ICMPV6` socket (unprivileged), non-blocking;
/// it gets a copy of every ICMP error this host receives.
#[cfg(target_os = "macos")]
fn icmp_socket(v6: bool) -> io::Result<std::os::fd::OwnedFd> {
    use std::os::fd::FromRawFd;
    let (family, proto) = if v6 {
        (libc::AF_INET6, libc::IPPROTO_ICMPV6)
    } else {
        (libc::AF_INET, libc::IPPROTO_ICMP)
    };
    // SAFETY: plain socket(2).
    let fd = unsafe { libc::socket(family, libc::SOCK_DGRAM, proto) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fd is a fresh socket this function owns.
    let owned = unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) };
    // SAFETY: fcntl on our fd.
    if unsafe { libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(owned)
}

/// macOS: every datagram waiting on the ICMP socket `fd`, each matched to the probe whose
/// destination, source address and port and initial sequence number it quotes.
#[cfg(target_os = "macos")]
fn read_icmp(fd: i32, dst: SocketAddr, probes: &mut [Probe]) {
    for _ in 0..64 {
        let mut b = [0u8; 2048];
        // SAFETY: zeroed storage, valid buffers of the sizes given.
        let mut from: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        let mut fl = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        // SAFETY: as above.
        let n = unsafe {
            libc::recvfrom(
                fd,
                b.as_mut_ptr().cast(),
                b.len(),
                0,
                (&mut from as *mut libc::sockaddr_storage).cast(),
                &mut fl,
            )
        };
        if n <= 0 {
            return;
        }
        let Some(q) = icmp_quote(&b[..n as usize], dst) else {
            continue;
        };
        // SAFETY: the kernel wrote a sockaddr of the socket's family into `from`.
        let Some(sender) = (unsafe { sockaddr_ip((&from as *const libc::sockaddr_storage).cast()) }) else {
            continue;
        };
        for p in probes.iter_mut() {
            if quotes(&q, p.local, p.isn) {
                p.icmp.push((q.kind, q.code, sender));
            }
        }
    }
}

/// One round (see the module doc): the probes at hop limits `hops ..= hops + extra`, at once,
/// waited for at most `wait`.
#[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
fn observe(
    addr: SocketAddr,
    hops: u8,
    extra: u8,
    pin: &Pin,
    wait: Duration,
) -> Result<Vec<Obs>, String> {
    use std::os::fd::AsRawFd;
    // Before any probe leaves: its copy of the answers.
    #[cfg(target_os = "macos")]
    let ic = icmp_socket(addr.is_ipv6())
        .map_err(|e| format!("an ICMP socket to read the probes' errors could not be opened: {e}"))?;
    let mut probes = Vec::new();
    for t in hops..=hops.saturating_add(extra) {
        probes.push(Probe::open(addr, t, pin).map_err(|e| format!("a probe could not be sent: {e}"))?);
    }
    #[cfg(target_os = "macos")]
    distinct_isns(&probes.iter().map(|p| p.isn).collect::<Vec<_>>())?;
    let end = Instant::now() + wait;
    loop {
        let left = end.saturating_duration_since(Instant::now());
        let seen: Vec<(u8, Option<ProbeOutcome>)> = probes
            .iter()
            .map(|p| (p.ttl, p.end.as_ref().map(|_| settle(p.end.clone(), &p.icmp))))
            .collect();
        if left.is_zero() || probes.iter().all(|p| p.end.is_some()) || decided(addr.ip(), hops, &seen) {
            break;
        }
        let mut pf: Vec<libc::pollfd> = probes
            .iter()
            .filter(|p| p.end.is_none())
            .map(|p| libc::pollfd {
                fd: p.sock.as_raw_fd(),
                events: libc::POLLOUT,
                revents: 0,
            })
            .collect();
        #[cfg(target_os = "macos")]
        pf.push(libc::pollfd {
            fd: ic.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        });
        let ms = left.as_millis().clamp(1, i32::MAX as u128) as libc::c_int;
        // SAFETY: a valid pollfd array of the length given.
        let n = unsafe { libc::poll(pf.as_mut_ptr(), pf.len() as libc::nfds_t, ms) };
        if n < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(format!("poll: {e}"));
        }
        for f in pf.iter().filter(|f| f.revents != 0) {
            #[cfg(target_os = "macos")]
            if f.fd == ic.as_raw_fd() {
                read_icmp(ic.as_raw_fd(), addr, &mut probes);
                continue;
            }
            if let Some(p) = probes.iter_mut().find(|p| p.sock.as_raw_fd() == f.fd) {
                p.ready(f.revents);
            }
        }
    }
    // xnu tells TCP of an ICMP error (tcp_ctlinput) before it copies it to the ICMP socket
    // (rip_input): a short drain.
    #[cfg(target_os = "macos")]
    {
        let until = Instant::now() + Duration::from_millis(30);
        while Instant::now() < until {
            let mut q = libc::pollfd {
                fd: ic.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: one valid pollfd.
            if unsafe { libc::poll(&mut q, 1, 10) } > 0 {
                read_icmp(ic.as_raw_fd(), addr, &mut probes);
            }
        }
    }
    Ok(probes
        .into_iter()
        .map(|p| Obs {
            ttl: p.ttl,
            outcome: settle(p.end, &p.icmp),
            local: Some(p.local),
        })
        .collect())
}

/// Why no destination is found far on this platform.
#[cfg(not(any(target_os = "linux", target_os = "android", target_os = "macos")))]
const UNSUPPORTED: &str = "this platform gives the near-hop check no way to read which router's \
                           ICMP error ended a probe (Windows: TCP_FAIL_CONNECT_ON_ICMP_ERROR and \
                           TCP_ICMP_ERROR_INFO are not yet verified), so no destination is found far";

/// Elsewhere (Windows): no round can be read; every decision refuses.
#[cfg(not(any(target_os = "linux", target_os = "android", target_os = "macos")))]
fn observe(_: SocketAddr, _: u8, _: u8, _: &Pin, _: Duration) -> Result<Vec<Obs>, String> {
    Err(UNSUPPORTED.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    const D4: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 1));
    const R4: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(198, 51, 100, 1));
    const D6: IpAddr = IpAddr::V6(std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
    const R6: IpAddr = IpAddr::V6(std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x99));

    fn o(ttl: u8, outcome: ProbeOutcome) -> Obs {
        Obs {
            ttl,
            outcome,
            local: None,
        }
    }

    fn icmp(ttl: u8, kind: u8, code: u8, from: IpAddr) -> Obs {
        o(ttl, ProbeOutcome::Icmp { kind, code, from })
    }

    fn te(ttl: u8) -> Obs {
        icmp(ttl, 11, 0, R4)
    }

    fn far_at(v: &Verdict) -> Option<u8> {
        match v {
            Verdict::Far(e) => Some(e.ttl),
            _ => None,
        }
    }

    fn refused(v: &Verdict) -> bool {
        matches!(v, Verdict::NoEvidence(_) | Verdict::Failed(_))
    }

    /// The rule (the S3 review's round-2 prototype cases and more): far only on a matched Time
    /// Exceeded code 0 from a router at `N` or more with no answer at or below its hop limit;
    /// near on any answer within `N`; everything else refused.
    #[test]
    fn the_rule_is_positive_evidence_only() {
        use ProbeOutcome::*;
        assert_eq!(far_at(&rule(D4, 2, &[te(2)])), Some(2));
        assert_eq!(far_at(&rule(D4, 2, &[o(2, TimedOut), te(3)])), Some(3));
        assert_eq!(far_at(&rule(D4, 2, &[te(2), o(5, Connected)])), Some(2), "an answer beyond");
        assert_eq!(far_at(&rule(D4, 2, &[o(2, TimedOut), te(3), o(4, Connected)])), Some(3));
        assert_eq!(rule(D4, 2, &[o(2, Connected), te(3)]), Verdict::Near("accepted a connection"));
        assert_eq!(rule(D4, 2, &[o(1, Refused)]), Verdict::Near("refused a connection"));
        assert_eq!(rule(D4, 2, &[o(2, Reset), te(2)]), Verdict::Near("reset a connection"));
        assert!(matches!(rule(D4, 2, &[o(2, TimedOut)]), Verdict::NoEvidence(_)), "silence");
        assert!(matches!(rule(D4, 2, &[]), Verdict::NoEvidence(_)), "nothing");
        assert!(refused(&rule(D4, 2, &[o(2, TimedOut), o(3, Connected)])), "an answer only beyond N");
        assert!(refused(&rule(D4, 2, &[icmp(2, 3, 1, R4)])), "destination unreachable");
        assert!(refused(&rule(D4, 2, &[icmp(2, 3, 13, R4)])), "administratively prohibited");
        assert!(refused(&rule(D4, 2, &[icmp(2, 11, 1, R4)])), "reassembly time exceeded");
        assert!(refused(&rule(D4, 2, &[icmp(2, 11, 0, D4)])), "time exceeded from D");
        assert!(refused(&rule(D4, 2, &[te(1)])), "below N");
        assert!(refused(&rule(D4, 2, &[o(2, Unreachable)])), "unreachable without its ICMP");
        assert!(matches!(rule(D4, 2, &[o(3, Connected), te(4)]), Verdict::Failed(w) if w.contains("inconsistent")));
        assert!(matches!(rule(D4, 2, &[o(2, Failed("EPERM".into()))]), Verdict::Failed(w) if w.contains("EPERM")));
        for bad in ["0.0.0.0", "224.0.0.1", "255.255.255.255", "127.0.0.1", "2001:db8::99"] {
            let from: IpAddr = bad.parse().unwrap();
            assert!(refused(&rule(D4, 2, &[icmp(2, 11, 0, from)])), "{bad}");
        }
        // IPv6: Time Exceeded is type 3; IPv4's type 11 is not.
        assert_eq!(far_at(&rule(D6, 2, &[icmp(2, 3, 0, R6)])), Some(2));
        assert!(refused(&rule(D6, 2, &[icmp(2, 11, 0, R6)])), "the IPv4 type on IPv6");
        assert!(refused(&rule(D6, 2, &[icmp(2, 1, 3, R6)])), "address unreachable");
        assert!(refused(&rule(D6, 2, &[icmp(2, 3, 0, D6)])), "from D");
        for bad in ["::", "ff02::1", "::1", "::ffff:198.51.100.1", "198.51.100.1"] {
            let from: IpAddr = bad.parse().unwrap();
            assert!(refused(&rule(D6, 2, &[icmp(2, 3, 0, from)])), "{bad}");
        }
        // Link-local routers are routers.
        assert!(far_at(&rule(D6, 1, &[icmp(1, 3, 0, "fe80::1".parse().unwrap())])).is_some());
    }

    /// The evidence is the lowest hop limit's Time Exceeded, with the address its probe left from.
    #[test]
    fn far_names_the_probe_it_rests_on() {
        let local: SocketAddr = "192.0.2.77:40000".parse().unwrap();
        let other: SocketAddr = "192.0.2.77:40001".parse().unwrap();
        let mut a = te(3);
        a.local = Some(other);
        let mut b = te(2);
        b.local = Some(local);
        assert_eq!(
            rule(D4, 2, &[a, b]),
            Verdict::Far(FarEvidence { ttl: 2, from: R4, local: Some(local) })
        );
    }

    fn any_ip() -> impl Strategy<Value = IpAddr> {
        prop_oneof![
            Just(D4),
            Just(R4),
            Just(D6),
            Just(R6),
            Just("0.0.0.0".parse().unwrap()),
            Just("224.0.0.9".parse().unwrap()),
            Just("255.255.255.255".parse().unwrap()),
            Just("127.0.0.1".parse().unwrap()),
            Just("::ffff:198.51.100.1".parse().unwrap()),
            Just("10.0.0.1".parse().unwrap()),
        ]
    }

    fn any_outcome() -> impl Strategy<Value = ProbeOutcome> {
        prop_oneof![
            Just(ProbeOutcome::Connected),
            Just(ProbeOutcome::Refused),
            Just(ProbeOutcome::Reset),
            Just(ProbeOutcome::Unreachable),
            Just(ProbeOutcome::TimedOut),
            Just(ProbeOutcome::Failed("x".into())),
            (prop_oneof![Just(0u8), Just(1), Just(3), Just(4), Just(11), Just(12)], 0u8..3, any_ip())
                .prop_map(|(kind, code, from)| ProbeOutcome::Icmp { kind, code, from }),
        ]
    }

    fn any_obs() -> impl Strategy<Value = Vec<Obs>> {
        prop::collection::vec((1u8..7, any_outcome()).prop_map(|(t, s)| o(t, s)), 0..9)
    }

    fn is_te0_from_router(ob: &Obs, dst: IpAddr) -> bool {
        let (k, c) = time_exceeded(dst);
        matches!(ob.outcome, ProbeOutcome::Icmp { kind, code, from } if kind == k && code == c && router_sent(from, dst))
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(4000))]

        /// No combination of observations without a Time Exceeded code 0 from a router is ever
        /// far.
        #[test]
        fn prop_nothing_but_a_time_exceeded_is_far(obs in any_obs(), v6 in any::<bool>(), hops in 1u8..4) {
            let d = if v6 { D6 } else { D4 };
            let obs: Vec<Obs> = obs.into_iter().filter(|ob| !is_te0_from_router(ob, d)).collect();
            prop_assert!(!matches!(rule(d, hops, &obs), Verdict::Far(_)));
        }

        /// Far's evidence is real: a Time Exceeded code 0 from a router (not D) at its hop limit,
        /// at `N` or more, with no answer at or below it; any answer within `N` is near.
        #[test]
        fn prop_far_is_sound(obs in any_obs(), v6 in any::<bool>(), hops in 1u8..4) {
            let d = if v6 { D6 } else { D4 };
            let v = rule(d, hops, &obs);
            let answered_within = obs.iter().any(|ob| ob.ttl <= hops && ob.outcome.answered());
            prop_assert_eq!(answered_within, matches!(v, Verdict::Near(_)));
            if let Verdict::Far(e) = v {
                prop_assert!(e.ttl >= hops && e.from != d && router_sent(e.from, d));
                prop_assert!(obs.iter().any(|ob| ob.ttl == e.ttl && is_te0_from_router(ob, d)));
                prop_assert!(!obs.iter().any(|ob| ob.ttl <= e.ttl && ob.outcome.answered()));
            }
        }

        /// An answer at a hop limit `<= t` always beats a Time Exceeded at `t`; one from D is never
        /// far.
        #[test]
        fn prop_an_answer_beats_a_time_exceeded_at_or_above_it(t in 2u8..6, below in 0u8..3, v6 in any::<bool>()) {
            let (d, r) = if v6 { (D6, R6) } else { (D4, R4) };
            let (k, c) = time_exceeded(d);
            let at = t.saturating_sub(below).max(1);
            let obs = [icmp(t, k, c, r), o(at, ProbeOutcome::Connected)];
            prop_assert!(!matches!(rule(d, 2, &obs), Verdict::Far(_)));
            prop_assert!(!matches!(rule(d, 2, &[icmp(t, k, c, d)]), Verdict::Far(_)));
        }
    }

    /// The sk_err_soft trap (the S3 review's skeptic): a probe whose connection completed (or was
    /// reset) is an answer, whatever ICMP errors were queued for it; an unreachable is its ICMP
    /// error only when one kind was matched; an ICMP error the socket did not end on is no
    /// evidence.
    #[test]
    fn an_answer_dominates_any_queued_icmp_error() {
        let tex = [(11u8, 0u8, R4)];
        for answer in [ProbeOutcome::Connected, ProbeOutcome::Refused, ProbeOutcome::Reset] {
            assert_eq!(settle(Some(answer.clone()), &tex), answer);
        }
        assert_eq!(
            settle(Some(ProbeOutcome::Unreachable), &tex),
            ProbeOutcome::Icmp { kind: 11, code: 0, from: R4 }
        );
        assert_eq!(settle(Some(ProbeOutcome::Unreachable), &[tex[0], tex[0]]), ProbeOutcome::Icmp { kind: 11, code: 0, from: R4 });
        assert!(matches!(settle(Some(ProbeOutcome::Unreachable), &[tex[0], (3, 1, R4)]), ProbeOutcome::Failed(_)));
        assert_eq!(settle(Some(ProbeOutcome::Unreachable), &[]), ProbeOutcome::Unreachable);
        assert_eq!(settle(None, &tex), ProbeOutcome::TimedOut, "a soft error alone");
        // And so through the rule: the queued Time Exceeded of a probe that connected is near.
        let obs = [o(2, settle(Some(ProbeOutcome::Connected), &tex)), te(3)];
        assert!(matches!(rule(D4, 2, &obs), Verdict::Near(_)));
    }

    /// A round ends as soon as it is decided: an answer within the limit, or a Time Exceeded
    /// whose lower probes have all ended; never while a probe at or below its hop limit could
    /// still be answered.
    #[test]
    fn a_round_ends_once_decided() {
        use ProbeOutcome::*;
        let tex = || Some(Icmp { kind: 11, code: 0, from: R4 });
        assert!(decided(D4, 2, &[(2, tex()), (3, None), (4, None)]), "TE at N");
        assert!(!decided(D4, 2, &[(2, None), (3, tex()), (4, None)]), "N may still answer");
        assert!(decided(D4, 2, &[(2, Some(TimedOut)), (3, tex()), (4, None)]));
        assert!(decided(D4, 2, &[(2, Some(Refused)), (3, None), (4, None)]), "near");
        assert!(!decided(D4, 2, &[(2, None), (3, Some(Connected)), (4, None)]), "an answer beyond N");
        assert!(!decided(D4, 2, &[(2, Some(Icmp { kind: 3, code: 1, from: R4 })), (3, None), (4, None)]));
        assert!(!decided(D4, 2, &[(2, None), (3, None), (4, None)]));
    }

    /// A probe's socket: its error is how it ended, connected is an answer (whatever was
    /// queued), and an ICMP error queued while the connection goes on (Linux's soft error) ends
    /// nothing; a hang-up with neither is a failure, never an unreachable.
    #[cfg(unix)]
    #[test]
    fn a_soft_icmp_error_ends_no_probe() {
        let e = |n: i32| Ok(Some(io::Error::from_raw_os_error(n)));
        assert_eq!(socket_end(e(libc::EHOSTUNREACH), false, 1, libc::POLLERR), Some(ProbeOutcome::Unreachable));
        assert_eq!(socket_end(e(libc::ECONNREFUSED), false, 0, libc::POLLERR), Some(ProbeOutcome::Refused));
        assert_eq!(socket_end(Ok(None), true, 1, libc::POLLOUT | libc::POLLERR), Some(ProbeOutcome::Connected));
        assert_eq!(socket_end(Ok(None), false, 1, libc::POLLERR), None, "soft error: not ended");
        assert!(matches!(socket_end(Ok(None), false, 0, libc::POLLHUP), Some(ProbeOutcome::Failed(_))));
        assert!(matches!(socket_end(Err(io::Error::other("x")), false, 0, 0), Some(ProbeOutcome::Failed(_))));
    }

    /// The decision's rounds, staged: the first that decides ends it; a second round follows one
    /// that decided nothing; out of time or a round that cannot be sent is refused, never far.
    #[test]
    fn the_rounds_decide_as_the_rule_says() {
        let addr: SocketAddr = "192.0.2.1:443".parse().unwrap();
        let far = Instant::now() + Duration::from_secs(30);
        let p = FixedProbe::far();
        assert_eq!(far_at(&decide_until(&*p, addr, 2, &Pin::default(), far)), Some(2));
        assert_eq!(*p.asked.lock().unwrap(), vec![(addr, 2)]);
        // Round 1 silent (the routers' ICMP rate limit), round 2 a Time Exceeded: far.
        let p = FixedProbe::rounds(vec![vec![], vec![(0, None)]], None);
        assert_eq!(far_at(&decide_until(&*p, addr, 2, &Pin::default(), far)), Some(2));
        // Round 1 silent, round 2 an answer within the limit: near.
        let p = FixedProbe::rounds(vec![vec![], vec![(0, Some(ProbeOutcome::Connected))]], None);
        assert!(matches!(decide_until(&*p, addr, 2, &Pin::default(), far), Verdict::Near(_)));
        // Round 1 a Time Exceeded at N + 1, round 2 an answer at N: decided after round 1.
        let p = FixedProbe::rounds(vec![vec![(1, None)], vec![(0, Some(ProbeOutcome::Connected))]], None);
        assert_eq!(far_at(&decide_until(&*p, addr, 2, &Pin::default(), far)), Some(3));
        // Silence twice: no evidence.
        let p = FixedProbe::answering(ProbeOutcome::TimedOut);
        assert!(matches!(decide_until(&*p, addr, 2, &Pin::default(), far), Verdict::NoEvidence(_)));
        // Out of time: asked nothing.
        let p = FixedProbe::far();
        let v = decide_until(&*p, addr, 2, &Pin::default(), Instant::now() - Duration::from_millis(1));
        assert_eq!(v, Verdict::Failed(OUT_OF_TIME.into()));
        assert!(p.asked.lock().unwrap().is_empty());
        // The pin is handed to the probe; an IPv4-mapped destination is probed as IPv4.
        let pin = Pin { source: Some("192.0.2.9".parse().unwrap()), interface: Some(7) };
        let p = FixedProbe::far();
        decide_until(&*p, "[::ffff:192.0.2.1]:443".parse().unwrap(), 2, &pin, far);
        assert_eq!(*p.pins.lock().unwrap(), vec![pin]);
        assert_eq!(p.asked.lock().unwrap()[0].0, addr);
    }

    /// A round that cannot be sent: the first refuses (its reason); a later one decides nothing
    /// more.
    #[test]
    fn a_round_that_cannot_be_sent_is_refused() {
        #[derive(Debug)]
        struct Broken(u32);
        impl NearProbe for Broken {
            #[allow(clippy::too_many_arguments)]
            fn round(&self, round: u32, _: SocketAddr, hops: u8, _: u8, _: &Pin, _: Duration, _: Instant) -> Result<Vec<Obs>, String> {
                if round >= self.0 {
                    Err("no ICMP socket".into())
                } else {
                    Ok(vec![o(hops, ProbeOutcome::TimedOut)])
                }
            }
            fn pause(&self) -> Duration {
                Duration::ZERO
            }
        }
        let addr: SocketAddr = "192.0.2.1:443".parse().unwrap();
        let far = Instant::now() + Duration::from_secs(30);
        assert!(matches!(decide_until(&Broken(0), addr, 2, &Pin::default(), far), Verdict::Failed(w) if w.contains("ICMP socket")));
        assert!(matches!(decide_until(&Broken(1), addr, 2, &Pin::default(), far), Verdict::NoEvidence(_)));
    }

    /// The S3 review's lab cases (rounds 1-3: `S3REV/r1-measure`, `r2-evidence/lab2.sh`,
    /// `r3-evidence`), as the observations they produced, through the decision. Topology: the
    /// miner, r1 (hop 1), the near host or r2 (hop 2), the far host or r3 (hop 3), far4 (hop 4);
    /// `N` = 2, probes at 2, 3, 4.
    #[test]
    fn the_lab_cases_decide_as_measured() {
        use ProbeOutcome::*;
        let addr: SocketAddr = "192.0.2.1:443".parse().unwrap();
        let far = Instant::now() + Duration::from_secs(30);
        let run = |round: Vec<(u8, Option<ProbeOutcome>)>| {
            decide_until(&*FixedProbe::staged(round, None), addr, 2, &Pin::default(), far)
        };
        let d = addr.ip();
        let ans = |k: u8| (k, Some(Connected));
        // BASE: the near host answers at 2; far and far4 get r2's (r3's) Time Exceeded.
        assert!(matches!(run(vec![ans(0), ans(1), ans(2)]), Verdict::Near(_)), "near");
        assert_eq!(far_at(&run(vec![(0, None), (1, None), ans(2)])), Some(2), "far4");
        assert_eq!(far_at(&run(vec![(0, None), ans(1), ans(2)])), Some(2), "far");
        // r2silent: r2 sends no Time Exceeded; the far host (hop 3) answers at 3 only: refused;
        // far4 gets r3's at 3: far.
        assert!(refused(&run(vec![ans(1), ans(2)])), "far, r2 silent");
        assert_eq!(far_at(&run(vec![(1, None), ans(2)])), Some(3), "far4, r2 silent");
        // silent: no router sends any: refused.
        assert!(refused(&run(vec![ans(2)])), "far4, all silent");
        // HMIN / HBPF / H2b / H4 / H8: the near host drops (or delays, or answers with a hop
        // limit of 1) every low-TTL SYN: silence, refused.
        assert!(refused(&run(vec![])), "IP_MINTTL, cBPF, TTL filters, delay");
        // H2 / H7: TTL < 2 dropped (on the host or by r1): answers only beyond N: refused.
        assert!(refused(&run(vec![ans(1), ans(2)])), "TTL filter, on-path drop");
        // H5 / H5b: low-TTL SYNs rejected with a Destination Unreachable (host, net, admin, port
        // unreachable: the last reads as refused, near).
        for (kind, code) in [(3u8, 1u8), (3, 0), (3, 13)] {
            assert!(refused(&run(vec![(0, Some(Icmp { kind, code, from: d })), ans(1)])), "{kind}/{code}");
            assert!(refused(&run(vec![(0, Some(Icmp { kind, code, from: R4 })), ans(1)])), "{kind}/{code} from r1");
        }
        // H6: r1 normalises every TTL to 64: answers everywhere, near.
        assert!(matches!(run(vec![ans(0), ans(1), ans(2)]), Verdict::Near(_)));
        // A2 / A3 / A4: a forged Time Exceeded from D, code 1, a Destination Unreachable: refused.
        assert!(refused(&run(vec![(0, Some(Icmp { kind: 11, code: 0, from: d }))])));
        assert!(refused(&run(vec![(0, Some(Icmp { kind: 11, code: 1, from: R4 }))])));
        assert!(refused(&run(vec![(0, Some(Icmp { kind: 3, code: 1, from: R4 }))])));
        // A5 / A6: wrong ISN or source port: the kernel matches nothing, silence: refused.
        assert!(refused(&run(vec![])));
        // A1c: a forged Time Exceeded racing the near host's SYN-ACK: whichever probe the answer
        // reached is near.
        assert!(matches!(run(vec![ans(0), (1, None)]), Verdict::Near(_)));
        // C1: a container behind DNAT on the near host: Linux rewrites the Time Exceeded's
        // source to D: refused.
        assert!(refused(&run(vec![(0, Some(Icmp { kind: 11, code: 0, from: d })), ans(1)])));
        // A1 / A7 (documented, assumption 1): a forger who sees the SYN (root on the near host,
        // a hostile LAN) and drops it, then forges a Time Exceeded from another address: far.
        assert_eq!(far_at(&run(vec![(0, None)])), Some(2), "forged: indistinguishable");
    }

    /// Induced loss (`loss_lab.sh`, r2 netem 50-90 %): a near host's answers lost leave silence or
    /// answers beyond the limit, never far; a far host's Time Exceeded lost in round 1 can come in
    /// round 2.
    #[test]
    fn loss_never_makes_a_near_host_far() {
        let addr: SocketAddr = "192.0.2.1:443".parse().unwrap();
        let far = Instant::now() + Duration::from_secs(30);
        let answered = |k: u8| (k, Some(ProbeOutcome::Connected));
        let near_rounds = [vec![], vec![answered(1)], vec![answered(2)], vec![answered(1), answered(2)]];
        for r1 in &near_rounds {
            for r2 in &near_rounds {
                let p = FixedProbe::rounds(vec![r1.clone(), r2.clone()], None);
                let v = decide_until(&*p, addr, 2, &Pin::default(), far);
                assert!(refused(&v), "{r1:?} {r2:?}: {v:?}");
            }
        }
        let p = FixedProbe::rounds(vec![vec![], vec![(1, None)]], None);
        assert_eq!(far_at(&decide_until(&*p, addr, 2, &Pin::default(), far)), Some(3));
    }

    /// A listener on loopback is zero hops away: the probes connect (near); a loopback port with
    /// nothing listening refuses (near). One round, one turn of the gate for its three probes.
    #[cfg(unix)]
    #[test]
    fn a_local_listener_is_near_in_one_round_of_one_turn() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let turns = turns_taken();
        assert_eq!(decide(&TtlProbe, addr, 2), Verdict::Near("accepted a connection"));
        assert_eq!(turns_taken(), turns + 1);
        let obs = TtlProbe
            .round(0, addr, 2, EXTRA_HOPS, &Pin::default(), PROBE_TIMEOUT, Instant::now() + DECIDE_BUDGET)
            .unwrap();
        assert_eq!(obs.iter().map(|o| o.ttl).collect::<Vec<_>>(), vec![2, 3, 4]);
        // The round ends once decided (the answer at 2): the others may still be pending.
        assert_eq!(obs[0].outcome, ProbeOutcome::Connected, "{obs:?}");
        assert!(obs.iter().all(|o| o.local.is_some()), "{obs:?}");
        assert_eq!(turns_taken(), turns + 2);
        drop(l);
        assert!(matches!(decide(&TtlProbe, addr, 2), Verdict::Near(w) if w.contains("refused")));
    }

    /// The probes leave from the pin's source (and the interface that holds it).
    #[cfg(unix)]
    #[test]
    fn the_probes_leave_from_the_pin() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let lo: IpAddr = "127.0.0.1".parse().unwrap();
        let interface = interface_of(lo).unwrap();
        assert!(interface.is_some(), "loopback's interface");
        let pin = Pin { source: Some(lo), interface };
        let obs = TtlProbe
            .round(0, addr, 2, 0, &pin, PROBE_TIMEOUT, Instant::now() + DECIDE_BUDGET)
            .unwrap();
        assert_eq!(obs[0].outcome, ProbeOutcome::Connected, "{obs:?}");
        assert_eq!(obs[0].local.unwrap().ip(), lo);
        // A source this host does not hold: the round cannot be sent (refused).
        let pin = Pin { source: Some("192.0.2.200".parse().unwrap()), interface: None };
        let e = TtlProbe
            .round(0, addr, 2, 0, &pin, PROBE_TIMEOUT, Instant::now() + DECIDE_BUDGET)
            .unwrap_err();
        assert!(e.contains("could not be sent"), "{e}");
        assert_eq!(interface_of("192.0.2.200".parse().unwrap()).unwrap(), None);
        // The interface is bound: a probe of a public address held to loopback's interface does
        // not leave by the default route on macOS (no route on lo0); on Linux the option is set
        // (an IPv6 one in the wrong byte order failed) but does not steer TCP.
        let public: SocketAddr = "192.0.2.1:443".parse().unwrap();
        let pin = Pin { source: None, interface };
        let r = TtlProbe.round(0, public, 64, 0, &pin, Duration::from_millis(300), Instant::now() + DECIDE_BUDGET);
        eprintln!("held to loopback's interface: {r:?}");
        #[cfg(target_os = "macos")]
        assert!(matches!(&r, Ok(o) if matches!(&o[0].outcome, ProbeOutcome::Failed(_))), "{r:?}");
        #[cfg(any(target_os = "linux", target_os = "android"))]
        assert!(r.is_ok(), "{r:?}");
        if let Some(i) = interface {
            let v6: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
            let sock = new_socket(v6).unwrap();
            pin_socket(&sock, v6, &Pin { source: None, interface: Some(i) }, 0).expect("the IPv6 interface pin");
        }
    }

    /// The real probe, on the real path: a probe of hop limit 1 (or 2: a VM's NAT sends none) to
    /// a public address runs out of hops at a router, whose Time Exceeded the kernel matches to it
    /// and names (Linux: the error queue; macOS: the ICMP socket and the ISN). Skipped where
    /// 1.1.1.1 has no route, or the first two routers send none.
    #[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
    #[test]
    fn the_router_that_ran_a_probe_out_is_named() {
        let dst: SocketAddr = "1.1.1.1:443".parse().unwrap();
        let mut seen = Vec::new();
        for hops in [1, 2, 1, 2] {
            match observe(dst, hops, 0, &Pin::default(), Duration::from_millis(1500)) {
                Ok(obs) => {
                    if let ProbeOutcome::Icmp { kind, code, from } = obs[0].outcome {
                        assert_eq!((kind, code), (11, 0), "{obs:?}");
                        assert!(router_sent(from, dst.ip()), "{from}");
                        assert!(obs[0].local.is_some_and(|l| l.port() != 0));
                        eprintln!("hop {hops} is {from}");
                        return;
                    }
                    seen.push(format!("{obs:?}"));
                }
                Err(e) => seen.push(e),
            }
            std::thread::sleep(Duration::from_millis(500));
        }
        crate::skipped(format!("no Time Exceeded from the first router here: {seen:?}"));
    }

    /// A destination nothing answers (TEST-NET-1, at a hop limit past every router): two rounds,
    /// a turn each, no evidence; never far, and within the deadline.
    #[cfg(unix)]
    #[test]
    fn a_silent_destination_is_no_evidence_after_two_rounds() {
        let dst: SocketAddr = "192.0.2.1:443".parse().unwrap();
        let turns = turns_taken();
        let t = Instant::now();
        // Other tests' probes share the gate: time enough for two turns however busy it is.
        let v = decide_until(&TtlProbe, dst, 64, &Pin::default(), t + Duration::from_secs(30));
        eprintln!("{dst} at 64 hops: {v:?} in {:?}", t.elapsed());
        if matches!(&v, Verdict::Failed(w) if w.contains("before any packet")) {
            crate::skipped(format!("no route to {dst} here: {v:?}"));
            return;
        }
        assert!(matches!(&v, Verdict::NoEvidence(w) if w.contains("6 probes")), "{v:?}");
        assert_eq!(turns_taken(), turns + 2);
        // A deadline that leaves no room for the second round ends the decision with the first's.
        let t = Instant::now();
        let v = decide_until(&TtlProbe, dst, 64, &Pin::default(), t + Duration::from_millis(1200));
        assert!(!matches!(v, Verdict::Far(_) | Verdict::Near(_)), "{v:?}");
        assert!(t.elapsed() < Duration::from_millis(1700), "{:?}", t.elapsed());
    }

    /// An IPv4-mapped destination is probed as its IPv4 address (review round 2, probe-2: an
    /// IPv6 socket's hop limit did not limit the IPv4 packets a mapped connection sends).
    #[cfg(unix)]
    #[test]
    fn a_mapped_address_is_probed_as_its_ipv4_address() {
        let v4: SocketAddr = "1.1.1.1:443".parse().unwrap();
        let mapped: SocketAddr = "[::ffff:1.1.1.1]:443".parse().unwrap();
        assert_eq!(unmapped(mapped), v4);
        assert_eq!(unmapped(v4), v4);
        let v6: SocketAddr = "[2606:4700:4700::1111]:443".parse().unwrap();
        assert_eq!(unmapped(v6), v6);
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let local: SocketAddr = format!("[::ffff:127.0.0.1]:{}", l.local_addr().unwrap().port())
            .parse()
            .unwrap();
        let obs = TtlProbe
            .round(0, local, 2, 0, &Pin::default(), PROBE_TIMEOUT, Instant::now() + DECIDE_BUDGET)
            .unwrap();
        assert!(obs[0].local.is_some_and(|a| a.is_ipv4()), "{obs:?}");
        assert!(matches!(decide(&TtlProbe, local, 2), Verdict::Near(_)));
    }

    /// Linux: an error-queue message is read as the ICMP error it holds only when its origin is
    /// ICMP of the probe's family and the control message holds the whole extended error and the
    /// offender's address.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn linux_an_error_queue_entry_is_read_only_when_whole() {
        let build = |origin: u8, v6: bool, short: bool| -> Option<(u8, u8, IpAddr)> {
            let mut cbuf = [0u64; 64];
            let (level, kind, alen) = if v6 {
                (libc::IPPROTO_IPV6, libc::IPV6_RECVERR, std::mem::size_of::<libc::sockaddr_in6>())
            } else {
                (libc::IPPROTO_IP, libc::IP_RECVERR, std::mem::size_of::<libc::sockaddr_in>())
            };
            let full = std::mem::size_of::<libc::sock_extended_err>() + alen;
            // SAFETY: a zeroed msghdr over our buffer; the CMSG macros stay within it.
            unsafe {
                let mut m: libc::msghdr = std::mem::zeroed();
                m.msg_control = cbuf.as_mut_ptr().cast();
                m.msg_controllen = libc::CMSG_SPACE(full as u32) as _;
                let c = libc::CMSG_FIRSTHDR(&m);
                (*c).cmsg_level = level;
                (*c).cmsg_type = kind;
                (*c).cmsg_len = libc::CMSG_LEN(if short { full as u32 - 4 } else { full as u32 }) as _;
                let e = libc::CMSG_DATA(c) as *mut libc::sock_extended_err;
                (*e).ee_origin = origin;
                (*e).ee_type = if v6 { 3 } else { 11 };
                (*e).ee_code = 0;
                let off = e.add(1) as *mut u8;
                if v6 {
                    let a = &mut *(off as *mut libc::sockaddr_in6);
                    a.sin6_family = libc::AF_INET6 as _;
                    a.sin6_addr.s6_addr = "2001:db8::99".parse::<std::net::Ipv6Addr>().unwrap().octets();
                } else {
                    let a = &mut *(off as *mut libc::sockaddr_in);
                    a.sin_family = libc::AF_INET as _;
                    a.sin_addr.s_addr = u32::from_ne_bytes([198, 51, 100, 1]);
                }
                errqueue_entry(&m, v6)
            }
        };
        assert_eq!(build(libc::SO_EE_ORIGIN_ICMP, false, false), Some((11, 0, R4)));
        assert_eq!(build(libc::SO_EE_ORIGIN_ICMP6, true, false), Some((3, 0, R6)));
        assert_eq!(build(libc::SO_EE_ORIGIN_LOCAL, false, false), None, "a local error");
        assert_eq!(build(libc::SO_EE_ORIGIN_ICMP6, false, false), None, "ICMPv6 on IPv4");
        assert_eq!(build(libc::SO_EE_ORIGIN_ICMP, false, true), None, "cut short");
    }

    /// macOS: the initial sequence number is read only from enough bytes, in `SYN_SENT`, and
    /// never zero; equal ones in a round refuse.
    #[test]
    fn the_isn_is_read_only_when_it_can_be() {
        let mut b = [0u8; 424];
        b[0] = TCPS_SYN_SENT;
        b[52..56].copy_from_slice(&1001u32.to_ne_bytes());
        assert_eq!(isn_from(&b).unwrap(), Some(1000));
        assert!(isn_from(&b[..TCP_INFO_NEEDED - 1]).is_err(), "too short");
        assert_eq!(isn_from(&b[..TCP_INFO_NEEDED]).unwrap(), Some(1000));
        b[52..56].copy_from_slice(&1u32.to_ne_bytes());
        assert!(isn_from(&b).is_err(), "zero");
        b[52..56].copy_from_slice(&0u32.to_ne_bytes());
        assert!(isn_from(&b).is_err(), "nothing sent");
        b[0] = 4;
        assert_eq!(isn_from(&b).unwrap(), None, "established: not in SYN_SENT");
        assert!(distinct_isns(&[Some(1), Some(2), None]).is_ok());
        assert!(distinct_isns(&[Some(1), None, Some(1)]).is_err());
    }

    /// An ICMP error as macOS's ICMP socket hands it over, IPv4 (with its IP header) and ICMPv6.
    #[allow(clippy::too_many_arguments)]
    fn datagram_v4(kind: u8, code: u8, src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, seq: u32, proto: u8) -> Vec<u8> {
        let mut b = vec![0x45, 0, 0, 56, 0, 0, 0, 0, 64, 1, 0, 0, 198, 51, 100, 1, 192, 0, 2, 9];
        b.extend([kind, code, 0, 0, 0, 0, 0, 0]);
        b.extend([0x45, 0, 0, 60, 0, 0, 0, 0, 1, proto, 0, 0]);
        b.extend(src);
        b.extend(dst);
        b.extend(sport.to_be_bytes());
        b.extend(dport.to_be_bytes());
        b.extend(seq.to_be_bytes());
        b
    }

    #[test]
    fn an_icmp_copy_is_matched_by_what_it_quotes() {
        let dst: SocketAddr = "192.0.2.1:443".parse().unwrap();
        let b = datagram_v4(11, 0, [192, 0, 2, 9], [192, 0, 2, 1], 40000, 443, 77, 6);
        assert_eq!(
            icmp_quote(&b, dst),
            Some(Quote { kind: 11, code: 0, src: "192.0.2.9".parse().unwrap(), sport: 40000, seq: 77 })
        );
        assert_eq!(icmp_quote(&datagram_v4(11, 0, [192, 0, 2, 9], [192, 0, 2, 2], 40000, 443, 77, 6), dst), None, "another destination");
        assert_eq!(icmp_quote(&datagram_v4(11, 0, [192, 0, 2, 9], [192, 0, 2, 1], 40000, 80, 77, 6), dst), None, "another port");
        assert_eq!(icmp_quote(&datagram_v4(11, 0, [192, 0, 2, 9], [192, 0, 2, 1], 40000, 443, 77, 17), dst), None, "not TCP");
        assert_eq!(icmp_quote(&b[..b.len() - 1], dst), None, "cut short");
        assert_eq!(icmp_quote(&[], dst), None);
        // ICMPv6: no outer header; the quoted IPv6 header's next header is TCP.
        let d6: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
        let mut v6 = vec![3u8, 0, 0, 0, 0, 0, 0, 0, 0x60, 0, 0, 0, 0, 20, 6, 1];
        v6.extend("2001:db8::9".parse::<std::net::Ipv6Addr>().unwrap().octets());
        v6.extend("2001:db8::1".parse::<std::net::Ipv6Addr>().unwrap().octets());
        v6.extend(40001u16.to_be_bytes());
        v6.extend(443u16.to_be_bytes());
        v6.extend(99u32.to_be_bytes());
        assert_eq!(
            icmp_quote(&v6, d6),
            Some(Quote { kind: 3, code: 0, src: "2001:db8::9".parse().unwrap(), sport: 40001, seq: 99 })
        );
        v6[14] = 17;
        assert_eq!(icmp_quote(&v6, d6), None, "not TCP");
        // Matched to the probe only by its source port, ISN and source address.
        let q = icmp_quote(&b, dst).unwrap();
        let local: SocketAddr = "192.0.2.9:40000".parse().unwrap();
        assert!(quotes(&q, local, Some(77)));
        assert!(!quotes(&q, local, Some(78)), "another ISN");
        assert!(!quotes(&q, local, None), "no ISN known");
        assert!(!quotes(&q, "192.0.2.9:40001".parse().unwrap(), Some(77)), "another port");
        assert!(!quotes(&q, "192.0.2.10:40000".parse().unwrap(), Some(77)), "another source");
        assert!(quotes(&q, "0.0.0.0:40000".parse().unwrap(), Some(77)), "unbound source");
    }

    /// macOS: a real probe in `SYN_SENT` has its initial sequence number read.
    #[cfg(target_os = "macos")]
    #[test]
    fn macos_a_probe_has_its_isn() {
        let dst: SocketAddr = "192.0.2.1:443".parse().unwrap();
        match Probe::open(dst, 2, &Pin::default()) {
            Ok(p) if p.end.is_none() => assert!(p.isn.is_some_and(|i| i != 0)),
            Ok(p) => crate::skipped(format!("the probe ended at once: {:?}", p.end)),
            Err(e) => crate::skipped(format!("no probe to {dst} here: {e}")),
        }
        assert_eq!(supported(), Ok(()));
    }

    /// macOS (hardening 13): an unreachable that `connect` reports at once (no packet answered:
    /// Local Network privacy, a Network Extension policy) is a local failure, never evidence; a
    /// reset is an answer. The router (on-link) is never far.
    #[cfg(unix)]
    #[test]
    fn an_unreachable_at_once_is_a_local_failure() {
        for e in [libc::EHOSTUNREACH, libc::ENETUNREACH, libc::EPERM] {
            assert!(matches!(at_once(io::Error::from_raw_os_error(e)), ProbeOutcome::Failed(w) if w.contains("before any packet")));
        }
        assert_eq!(at_once(io::Error::from_raw_os_error(libc::ECONNREFUSED)), ProbeOutcome::Refused);
        assert_eq!(ended(&io::Error::from_raw_os_error(libc::EHOSTUNREACH)), ProbeOutcome::Unreachable);
        assert_eq!(ended(&io::Error::from_raw_os_error(libc::ECONNRESET)), ProbeOutcome::Reset);
        assert!(matches!(ended(&io::Error::from_raw_os_error(libc::EACCES)), ProbeOutcome::Failed(_)));
        let (routes, _) = crate::routes::read_routing(&[]).unwrap();
        if let Some(g) = routes.iter().find_map(|r| match (r.prefix.len, r.hop) {
            (0, crate::routes::Hop::Via(g @ std::net::IpAddr::V4(_))) => Some(g),
            _ => None,
        }) {
            let v = decide(&TtlProbe, SocketAddr::new(g, 80), 2);
            eprintln!("the router, port 80, hop limit 2: {v:?}");
            assert!(!matches!(v, Verdict::Far(_)), "{v:?}");
        } else {
            crate::skipped("the router probe: no IPv4 default route");
        }
    }

    /// Review round 4, probe-2: at most [`PROBES_AT_ONCE`] rounds are in flight in the process;
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
    /// for only until the caller's deadline; a round that gets none in time fails (refused,
    /// never far) without sending anything, so an abandoned check stops and gives its turn
    /// back.
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
        // Nothing listens there: had the probes been sent, they would have been refused (near).
        let addr: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let t = Instant::now();
        let r = TtlProbe.round(0, addr, 2, 2, &Pin::default(), PROBE_TIMEOUT, t + Duration::from_millis(300));
        assert!(matches!(&r, Err(w) if w.contains("no turn")), "{r:?}");
        assert!(t.elapsed() < Duration::from_secs(2), "{:?}", t.elapsed());
        let v = decide_until(&TtlProbe, addr, 2, &Pin::default(), Instant::now() + Duration::from_millis(300));
        assert!(matches!(&v, Verdict::Failed(w) if w.contains("no turn")), "{v:?}");
        drop(held);
        assert!(ProbeGate::enter_until(Instant::now() + Duration::from_secs(5)).is_some());
    }

    /// The S3 review (found on the Linux VM): a caller that gets no turn gives none back. Before,
    /// each one did (`then_some(ProbeGate)` dropped a gate it never entered), so after two failed
    /// waits four rounds could be in flight.
    #[test]
    fn a_caller_without_a_turn_gives_none_back() {
        let far = Instant::now() + Duration::from_secs(30);
        let held: Vec<ProbeGateV6> = (0..PROBES_AT_ONCE)
            .map(|_| ProbeGateV6::enter_until(far).expect("a turn"))
            .collect();
        let in_flight = || PROBES_IN_FLIGHT_V6.lock().unwrap_or_else(|e| e.into_inner()).0;
        for _ in 0..3 {
            assert!(ProbeGateV6::enter_until(Instant::now() + Duration::from_millis(50)).is_none());
            assert!(in_flight() >= PROBES_AT_ONCE, "a turn given back that was never taken");
        }
        assert!(ProbeGateV6::enter_until(Instant::now() + Duration::from_millis(50)).is_none());
        drop(held);
    }

    /// Review round 5 (the probe lens's suspicion): rounds start at most [`PROBE_BURST`] at once
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
}

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
        let r = TtlProbe.round(0, addr, 2, 2, &Pin::default(), PROBE_TIMEOUT, past);
        assert!(matches!(&r, Err(w) if w == OUT_OF_TIME), "{r:?}");
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

    /// probe-3 (fix-r6 mutation N16): the families have gates of their own: IPv4's turns all held
    /// leave IPv6's free.
    #[test]
    fn r6_each_family_has_its_own_gate() {
        let far = Instant::now() + Duration::from_secs(30);
        let held: Vec<ProbeGate> = (0..PROBES_AT_ONCE).filter_map(|_| ProbeGate::enter_until(far)).collect();
        assert_eq!(held.len(), PROBES_AT_ONCE);
        let v6: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
        let t = Instant::now();
        let turn = Turn::enter_for(v6, t + Duration::from_secs(5));
        assert!(matches!(turn, Some(Turn::V6(_))) && t.elapsed() < Duration::from_secs(3));
        drop(held);
    }

    /// cross-7 N14: a round never runs past the time it is given (TEST-NET-1 at a hop limit past
    /// every router: answered by nobody).
    #[cfg(unix)]
    #[test]
    fn r6_a_round_ends_at_its_time() {
        let dst: SocketAddr = "192.0.2.1:9".parse().unwrap();
        let t = Instant::now();
        let r = TtlProbe.round(0, dst, 64, 2, &Pin::default(), Duration::from_millis(300), t + Duration::from_secs(5));
        let took = t.elapsed();
        match r {
            Ok(obs) if obs.iter().all(|o| o.outcome == ProbeOutcome::TimedOut) => {
                assert!(took < Duration::from_millis(700), "{took:?}")
            }
            other => crate::skipped(format!("{dst} is not silent here: {other:?}")),
        }
    }
}
