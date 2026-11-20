//! This host's public addresses as the internet sees them, learned from fixed reflectors (review
//! r1, fetch F1 / broker F1).
//!
//! Behind NAT the host's public IPv4 address (and, behind NAT66 or NPTv6, its public IPv6 address)
//! is on no interface, so a requester URL at it would hairpin through the router to this host or
//! to whatever the router forwards. So the host asks, at startup and again every
//! [`DISCOVERY_TTL`], fixed reflectors that answer with the address the query came from, per
//! address family:
//!
//! - `o-o.myaddr.l.google.com` `TXT`, one DNS query over UDP to Google's authoritative server
//!   `ns1.google.com` (`216.239.32.10`, `2001:4860:4802:32::a`) directly (through a recursive
//!   resolver it would name the resolver);
//! - `whoami.cloudflare` `CH TXT`, one DNS query over UDP to `1.1.1.1` / `2606:4700:4700::1111`;
//! - with the `client` feature, Cloudflare's `/cdn-cgi/trace` over HTTPS at `1.1.1.1` /
//!   `[2606:4700:4700::1111]` (an IP literal, so no name is looked up; the certificate is
//!   verified for that address with the compiled-in web roots): the one answer a box that
//!   intercepts or redirects DNS cannot forge, and one a network that filters DNS still lets
//!   through.
//!
//! The names and server addresses are compiled in: nothing a requester supplies chooses them, and
//! an answer only ever adds an address to refuse. **Every reflector** of a family is asked, and
//! every address any reports is refused (their union; when they disagree, a WARN says so). An
//! address is **confirmed** when the HTTPS reflector reports it, or when the two DNS reflectors
//! report it alike (a DNS answer equal to one of the host's own DNS servers does not count: an
//! intercepting resolver reports itself). Only a confirmed address (or one in an interface
//! address's own site) gives the IPv6 site around it ([`crate::FactsOptions`]'s
//! `ipv6_site_prefix_len`): an answer forged by one DNS reflector or by a box that redirects DNS to
//! itself can then make the miner refuse one more address, not a whole site of someone else's
//! (review r2, R2-NG-7). And only a confirmed address makes the family **known**: a family the
//! host routes whose public address is not known refuses every requester connection
//! ([`crate::HostFacts::unknown_paths`], fail closed) until one is, or until `[egress]
//! public_addresses` names one.
//!
//! **IPv6-only hosts behind NAT64.** When the host has no IPv4 route, an IPv4 address is reached
//! through a NAT64 translator, from the translator's own IPv4 address, which a URL at
//! `<prefix>::<that address>` would hairpin to. So with a NAT64 prefix in force (`[egress]
//! nat64_prefixes`, or learned from the host's DNS64: [`crate::nat64`]) the IPv4 reflectors are
//! asked at their addresses under it (what a DNS64 resolver would synthesize), and what they
//! report is the translator's address: refused as an own address, and confirmed as above it
//! opens IPv4 through that prefix ([`Learned::via_nat64`]).
//!
//! When every reflector fails for a family, a loud WARN says so (once per run of failures) and
//! names what to set. A family the host has no route for at all is skipped quietly: there is no
//! public address to learn, and no requester connection goes out over it either. `[egress]
//! discover_public_addresses = false` turns the queries off (and then `[egress] public_addresses`
//! must name the address of every family the host routes).
//!
//! The answers are cached process-wide. The first call runs discovery on the calling thread (at
//! most [`DISCOVERY_TIMEOUT`] and [`AGREEMENT_GRACE`]: every reflector is asked at once, from the
//! calling thread, which starts no other — the witness broker gathers its facts right before a
//! sandbox that refuses a second thread); a call that arrives while that first discovery runs
//! waits for it (at most [`FIRST_DISCOVERY_WAIT`], review r2 R2-NG-6: it got nothing before, and
//! facts gathered then missed the NAT address). Later calls return the cache and refresh it on a
//! background thread once it is older than [`DISCOVERY_TTL`] (after a failure, retried at most
//! every [`RETRY_AFTER_FAILURE`]). The last good answer of a family stays in force when a refresh
//! fails.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};

use crate::ip::Prefix;

/// How long one reflector query may take (the HTTPS one, on a slow link, a few round trips).
pub const DISCOVERY_TIMEOUT: Duration = Duration::from_secs(3);
/// Once one reflector of a family has answered, how much longer the others get (within
/// [`DISCOVERY_TIMEOUT`]).
pub const AGREEMENT_GRACE: Duration = Duration::from_millis(500);
/// How long a call waits for a first discovery another thread is running.
pub const FIRST_DISCOVERY_WAIT: Duration = Duration::from_secs(4);
/// How long learned public addresses are trusted before they are learned again.
pub const DISCOVERY_TTL: Duration = Duration::from_secs(300);
/// How soon a failed discovery is tried again (a family whose address is unknown refuses every
/// connection meanwhile).
pub const RETRY_AFTER_FAILURE: Duration = Duration::from_secs(15);
/// How long a confirmed public address counts as known without being confirmed again: two
/// discovery rounds. A family whose address no round has confirmed for this long is unknown again
/// (its connections refused) until one does.
pub const CONFIRMATION_LIFETIME: Duration = Duration::from_secs(600);
/// Most NAT64 prefixes the IPv4 reflectors are asked through.
const MAX_NAT64_PREFIXES: usize = 2;

/// A reflector: a fixed DNS server asked a fixed name, answering with the asker's address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reflector {
    pub name: &'static str,
    /// DNS class: 1 (`IN`) or 3 (`CH`).
    pub class: u16,
    pub server: IpAddr,
}

const CLASS_IN: u16 = 1;
const CLASS_CH: u16 = 3;
const TYPE_TXT: u16 = 16;

/// Every DNS reflector: two operators, each asked over IPv4 and over IPv6.
pub const REFLECTORS: &[Reflector] = &[
    Reflector {
        name: "o-o.myaddr.l.google.com",
        class: CLASS_IN,
        server: IpAddr::V4(Ipv4Addr::new(216, 239, 32, 10)),
    },
    Reflector {
        name: "o-o.myaddr.l.google.com",
        class: CLASS_IN,
        server: IpAddr::V6(Ipv6Addr::new(0x2001, 0x4860, 0x4802, 0x32, 0, 0, 0, 0xa)),
    },
    Reflector {
        name: "whoami.cloudflare",
        class: CLASS_CH,
        server: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
    },
    Reflector {
        name: "whoami.cloudflare",
        class: CLASS_CH,
        server: IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111)),
    },
];

/// The HTTPS reflector's servers (Cloudflare's `/cdn-cgi/trace`), one per family.
pub const TLS_REFLECTORS: &[IpAddr] = &[
    IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
    IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111)),
];

/// The name the HTTPS reflector's answers are counted under.
const TLS_NAME: &str = "https://1.1.1.1/cdn-cgi/trace";

/// What discovery learned: every public address a reflector reported, the confirmed ones, and
/// the NAT64 prefixes the IPv4 one was confirmed through.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Learned {
    /// Every reported address (refused as the host's own).
    pub addresses: Vec<IpAddr>,
    /// The confirmed ones (see the module doc): they make their family known and give their
    /// IPv6 site.
    pub confirmed: Vec<IpAddr>,
    /// The NAT64 prefixes through which an IPv4 address was confirmed (an IPv6-only host's).
    pub via_nat64: Vec<Prefix>,
    /// [IPv4, IPv6]: the family's address was confirmed on another uplink, recently, and is
    /// being learned again on this one ([`learned_on`]; review round 4, cross-2: such a refusal
    /// says so, not that `[egress] public_addresses` should be set).
    pub relearning: [bool; 2],
}

/// One family's last good answer.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct FamilyAnswer {
    addresses: Vec<IpAddr>,
    confirmed: Vec<IpAddr>,
    via_nat64: Vec<Prefix>,
}

#[derive(Debug)]
struct State {
    families: [FamilyAnswer; 2],
    /// Per family: when its answer was last confirmed (see [`CONFIRMATION_LIFETIME`]).
    confirmed_at: [Option<Instant>; 2],
    /// Per family: the uplink its answer was learned on ([`learned_on`]).
    uplink_of: [Option<u64>; 2],
    /// The uplink the latest caller of [`learned_on`] is on.
    uplink: Option<u64>,
    learned_at: Option<Instant>,
    attempted_at: Option<Instant>,
    running: bool,
    /// Whether the first discovery has finished (successfully or not).
    first_done: bool,
    /// Whether the current failure streak of a family has been warned about (once per streak).
    warned: [bool; 2],
}

static STATE: Mutex<State> = Mutex::new(State {
    families: [
        FamilyAnswer {
            addresses: Vec::new(),
            confirmed: Vec::new(),
            via_nat64: Vec::new(),
        },
        FamilyAnswer {
            addresses: Vec::new(),
            confirmed: Vec::new(),
            via_nat64: Vec::new(),
        },
    ],
    confirmed_at: [None, None],
    uplink_of: [None, None],
    uplink: None,
    learned_at: None,
    attempted_at: None,
    running: false,
    first_done: false,
    warned: [false; 2],
});

/// Signalled when the first discovery finishes.
static FIRST_DONE: Condvar = Condvar::new();

fn state() -> std::sync::MutexGuard<'static, State> {
    STATE.lock().unwrap_or_else(|e| e.into_inner())
}

/// This host's public addresses, every family's, from the process-wide cache; see the module doc
/// for when this blocks and when it refreshes.
pub fn public_addresses() -> Vec<IpAddr> {
    learned().addresses
}

/// This host's public addresses and the confirmed ones among them, from the process-wide cache;
/// see the module doc for when this blocks and when it refreshes. A confirmation older than
/// [`CONFIRMATION_LIFETIME`] no longer counts.
pub fn learned() -> Learned {
    learned_inner(None)
}

/// [`learned`] for a host on uplink `uplink` (a value that changes with its default routes:
/// [`crate::HostFacts`] computes it). When the uplink changes, discovery runs again at once, and
/// until it has, nothing learned on another uplink counts as confirmed: a new default gateway or a
/// VPN that came up can mean a new public address.
pub fn learned_on(uplink: u64) -> Learned {
    learned_inner(Some(uplink))
}

fn spawn_discovery(s: &mut State) {
    s.running = true;
    s.attempted_at = Some(Instant::now());
    let uplink = s.uplink;
    let spawned = std::thread::Builder::new()
        .name("netguard-public-addr".into())
        .spawn(move || learn(discover(), uplink));
    if spawned.is_err() {
        s.running = false;
    }
}

fn learned_inner(uplink: Option<u64>) -> Learned {
    let mut s = state();
    let changed = uplink.is_some() && uplink != s.uplink && s.uplink.is_some();
    if uplink.is_some() {
        if s.uplink.is_none() {
            // The first caller to name the uplink: what was learned before (by a caller that
            // named none) was learned on it, as far as anyone can tell.
            for u in s.uplink_of.iter_mut().filter(|u| u.is_none()) {
                *u = uplink;
            }
        }
        s.uplink = uplink;
    }
    if s.attempted_at.is_none() && !s.running {
        // The first call: discover on this thread.
        s.running = true;
        s.attempted_at = Some(Instant::now());
        let uplink = s.uplink;
        drop(s);
        learn(discover(), uplink);
        s = state();
    } else if !s.first_done {
        // Review r2 R2-NG-6: the first discovery is running on another thread; wait for it
        // rather than answer with nothing.
        let deadline = Instant::now() + FIRST_DISCOVERY_WAIT;
        while !s.first_done {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            s = FIRST_DONE
                .wait_timeout(s, left)
                .unwrap_or_else(|e| e.into_inner())
                .0;
        }
    } else if changed && !s.running {
        tracing::info!(
            "network guard: this host's uplink changed; learning its public addresses again"
        );
        spawn_discovery(&mut s);
    } else {
        let stale = s.learned_at.is_none_or(|t| t.elapsed() >= DISCOVERY_TTL);
        let may_retry = s
            .attempted_at
            .is_none_or(|t| t.elapsed() >= RETRY_AFTER_FAILURE);
        if stale && may_retry && !s.running {
            spawn_discovery(&mut s);
        }
    }
    let now = Instant::now();
    let mut out = Learned::default();
    for (i, f) in s.families.iter().enumerate() {
        out.addresses.extend(&f.addresses);
        if still_confirmed(s.confirmed_at[i], s.uplink_of[i], s.uplink, now) {
            out.confirmed.extend(&f.confirmed);
            out.via_nat64.extend(&f.via_nat64);
        } else {
            out.relearning[i] = relearning(s.confirmed_at[i], s.uplink_of[i], uplink, now);
        }
    }
    out
}

/// Whether a family whose confirmation does not count on `uplink` ([`still_confirmed`]) is being
/// learned again: confirmed within [`CONFIRMATION_LIFETIME`], on another uplink than the one the
/// caller names.
fn relearning(
    confirmed_at: Option<Instant>,
    learned_on: Option<u64>,
    uplink: Option<u64>,
    now: Instant,
) -> bool {
    uplink.is_some()
        && learned_on != uplink
        && still_confirmed(confirmed_at, None, None, now)
}

/// Whether a family's confirmation still counts at `now`: confirmed within
/// [`CONFIRMATION_LIFETIME`], on the uplink the host is on (when the caller says which).
fn still_confirmed(
    confirmed_at: Option<Instant>,
    learned_on: Option<u64>,
    uplink: Option<u64>,
    now: Instant,
) -> bool {
    let fresh =
        confirmed_at.is_some_and(|t| now.saturating_duration_since(t) < CONFIRMATION_LIFETIME);
    let same_uplink = uplink.is_none() || learned_on == uplink;
    fresh && same_uplink
}

/// What one round of discovery found for a family: what its reflectors reported, `None` when the
/// host has no route for the family at all (nothing to learn, and nothing a requester could reach
/// over it), or why every reflector failed.
type FamilyFound = Result<Option<FamilyAnswer>, String>;

fn learn((v4, v6): (FamilyFound, FamilyFound), uplink: Option<u64>) {
    let mut guard = state();
    let s = &mut *guard;
    s.running = false;
    s.first_done = true;
    // A round started before any caller named the uplink ran on the one named since.
    let uplink = uplink.or(s.uplink);
    let mut any = false;
    let now = Instant::now();
    for (i, (got, family)) in [(v4, "IPv4"), (v6, "IPv6")].into_iter().enumerate() {
        match got {
            Ok(Some(answer)) => {
                if s.families[i] != answer {
                    let list: Vec<String> =
                        answer.addresses.iter().map(|a| a.to_string()).collect();
                    tracing::info!(
                        "network guard: this host's public {family} address is {}; refusing it",
                        list.join(" and ")
                    );
                    if answer.confirmed.is_empty() {
                        tracing::warn!(
                            "network guard: no two reflectors confirm this host's public {family} \
                             address (and the HTTPS reflector did not answer), so it counts as \
                             not known and requester connections over {family} are refused. If \
                             outbound DNS or HTTPS to the reflectors is filtered or intercepted \
                             here, name this host's public {family} address in [egress] \
                             public_addresses"
                        );
                    }
                }
                s.confirmed_at[i] = (!answer.confirmed.is_empty()).then_some(now);
                s.uplink_of[i] = uplink;
                s.families[i] = answer;
                s.warned[i] = false;
                any = true;
            }
            Ok(None) => {
                tracing::debug!("network guard: no {family} route, so no public {family} address");
                s.uplink_of[i] = uplink;
                any = true;
            }
            Err(e) if !s.warned[i] => {
                s.warned[i] = true;
                tracing::warn!(
                    "network guard: could not learn this host's public {family} address ({e}). \
                     Until it is known, every requester connection over {family} is refused: \
                     behind NAT one at that address would reach this host or its router. Name it \
                     in [egress] public_addresses if the reflectors cannot be reached from here. \
                     The last address learned stays refused (and counts as known for at most \
                     {} s after it was confirmed); retrying in the background",
                    CONFIRMATION_LIFETIME.as_secs()
                );
            }
            Err(e) => tracing::debug!("network guard: public {family} address: {e}"),
        }
    }
    if any {
        s.learned_at = Some(Instant::now());
    }
    // The uplink changed while this round ran: its answers are the old uplink's; ask again.
    if uplink.is_some() && s.uplink.is_some() && uplink != s.uplink {
        spawn_discovery(s);
    }
    drop(guard);
    FIRST_DONE.notify_all();
}

/// Who reported an address: a DNS reflector (by name) or the HTTPS one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Source {
    Dns(&'static str),
    Tls,
}

/// One answer: its source, the NAT64 prefix it came through (an IPv4 reflector asked from an
/// IPv6-only host), and the address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Answer {
    source: Source,
    via: Option<Prefix>,
    ip: IpAddr,
}

/// One family's answers as a [`FamilyAnswer`]: the union; confirmed, what the HTTPS reflector
/// reported and what both DNS reflectors reported alike (a DNS answer that is one of `dns_servers`
/// left out of the agreement; and no DNS agreement at all through a path in `vetoed`, where the
/// HTTPS reflector's TCP connection was made but its TLS or its answer failed: something on the
/// path answers in its place, and could answer the DNS queries alike too); and the NAT64 prefixes
/// something was confirmed through. Warns when they disagree.
fn agree(
    family: &str,
    answers: &[Answer],
    dns_servers: &[IpAddr],
    vetoed: &[Option<Prefix>],
) -> FamilyAnswer {
    let mut addresses: Vec<IpAddr> = answers.iter().map(|a| a.ip).collect();
    addresses.sort();
    addresses.dedup();
    let mut confirmed = Vec::new();
    let mut via_nat64 = Vec::new();
    let mut groups: Vec<Option<Prefix>> = answers.iter().map(|a| a.via).collect();
    groups.sort();
    groups.dedup();
    for via in groups {
        let mut sure: Vec<IpAddr> = answers
            .iter()
            .filter(|a| a.via == via && a.source == Source::Tls)
            .map(|a| a.ip)
            .collect();
        let dns: Vec<&Answer> = answers
            .iter()
            .filter(|a| a.via == via && matches!(a.source, Source::Dns(_)))
            .filter(|a| !dns_servers.contains(&a.ip))
            .collect();
        let mut names: Vec<Source> = dns.iter().map(|a| a.source).collect();
        names.sort_by_key(|s| format!("{s:?}"));
        names.dedup();
        let mut dns_ips: Vec<IpAddr> = dns.iter().map(|a| a.ip).collect();
        dns_ips.sort();
        dns_ips.dedup();
        if names.len() >= 2 && dns_ips.len() == 1 && !vetoed.contains(&via) {
            sure.extend(dns_ips);
        }
        if !sure.is_empty() {
            if let Some(p) = via {
                via_nat64.push(p);
            }
        }
        confirmed.extend(sure);
    }
    confirmed.sort();
    confirmed.dedup();
    if addresses.len() > 1 {
        let list: Vec<String> = answers
            .iter()
            .map(|a| match a.source {
                Source::Dns(n) => format!("{n} says {}", a.ip),
                Source::Tls => format!("{TLS_NAME} says {}", a.ip),
            })
            .collect();
        tracing::warn!(
            "network guard: the public-address reflectors disagree about this host's {family} \
             address ({}); refusing every one, deriving no IPv6 site from an unconfirmed one. A \
             box that redirects DNS, or a multi-homed uplink, does this",
            list.join(", ")
        );
    }
    FamilyAnswer {
        addresses,
        confirmed,
        via_nat64,
    }
}

/// A query in flight.
enum Pending {
    Dns {
        sock: UdpSocket,
        id: u16,
        name: &'static str,
    },
    #[cfg(feature = "client")]
    Tls(Box<tls::TlsQuery>),
}

/// One query: in flight, for family `fam` (0 = IPv4, 1 = IPv6), through `via`.
struct Query {
    pending: Pending,
    fam: usize,
    via: Option<Prefix>,
    what: String,
}

/// Asks every reflector at once, on this thread (no helper thread: the witness broker gathers its
/// facts single-threaded, right before a sandbox that refuses a process with a second thread), and
/// takes every valid answer per family within [`DISCOVERY_TIMEOUT`] — a family's other reflectors
/// get [`AGREEMENT_GRACE`] once the first has answered. Without an IPv4 route, the IPv4
/// reflectors are asked through the NAT64 prefixes in force (see the module doc).
fn discover() -> (FamilyFound, FamilyFound) {
    let mut found: [Vec<Answer>; 2] = [Vec::new(), Vec::new()];
    let mut errors: [Vec<String>; 2] = [Vec::new(), Vec::new()];
    // A family is unroutable when every one of its sends failed at once for want of a route.
    let mut unroutable = [true, true];
    let mut queries: Vec<Query> = Vec::new();
    let unroutable_error = |e: &io::Error| {
        matches!(
            e.kind(),
            io::ErrorKind::NetworkUnreachable | io::ErrorKind::AddrNotAvailable
        )
    };
    // (server to connect to, the reflector's own address, family, through)
    let start = |queries: &mut Vec<Query>,
                 errors: &mut [Vec<String>; 2],
                 unroutable: &mut [bool; 2],
                 via: Option<Prefix>| {
        let at = |server: IpAddr| -> IpAddr {
            match (via, server) {
                (Some(p), IpAddr::V4(v4)) => IpAddr::V6(crate::nat64::synthesize(p, v4)),
                _ => server,
            }
        };
        for r in REFLECTORS
            .iter()
            .filter(|r| via.is_none() || r.server.is_ipv4())
        {
            let fam = usize::from(r.server.is_ipv6());
            let to = at(r.server);
            let what = format!("{} @{to}", r.name);
            match send_query_to(r, to) {
                Ok((sock, id)) => {
                    if via.is_none() {
                        unroutable[fam] = false;
                    }
                    queries.push(Query {
                        pending: Pending::Dns {
                            sock,
                            id,
                            name: r.name,
                        },
                        fam,
                        via,
                        what,
                    });
                }
                Err(e) => {
                    if via.is_none() {
                        unroutable[fam] &= unroutable_error(&e);
                    }
                    errors[fam].push(format!("{what}: {e}"));
                }
            }
        }
        #[cfg(feature = "client")]
        for server in TLS_REFLECTORS
            .iter()
            .filter(|s| via.is_none() || s.is_ipv4())
        {
            let fam = usize::from(server.is_ipv6());
            let to = at(*server);
            let what = format!("{TLS_NAME} @{to}");
            match tls::TlsQuery::start(SocketAddr::new(to, 443), *server) {
                Ok(q) => {
                    if via.is_none() {
                        unroutable[fam] = false;
                    }
                    queries.push(Query {
                        pending: Pending::Tls(Box::new(q)),
                        fam,
                        via,
                        what,
                    });
                }
                Err(e) => {
                    if via.is_none() {
                        unroutable[fam] &= unroutable_error(&e);
                    }
                    errors[fam].push(format!("{what}: {e}"));
                }
            }
        }
    };
    start(&mut queries, &mut errors, &mut unroutable, None);
    let mut nat64_asked = false;
    if unroutable[0] && !unroutable[1] {
        for p in crate::nat64::in_force()
            .into_iter()
            .take(MAX_NAT64_PREFIXES)
        {
            nat64_asked = true;
            start(&mut queries, &mut errors, &mut unroutable, Some(p));
        }
    }
    let deadline = Instant::now() + DISCOVERY_TIMEOUT;
    // Per family: when its first answer came.
    let mut first_answer: [Option<Instant>; 2] = [None, None];
    // Per family: the paths (native, or through a NAT64 prefix) where the HTTPS reflector's TCP
    // connection was made but TLS or its answer failed.
    let mut vetoed: [Vec<Option<Prefix>>; 2] = [Vec::new(), Vec::new()];
    let mut buf = [0u8; 1500];
    while !queries.is_empty() {
        let now = Instant::now();
        if now >= deadline {
            break;
        }
        let mut progressed = false;
        queries.retain_mut(|q| {
            let fam = q.fam;
            // The HTTPS reflector gets the whole time: on a slow link its handshake takes a few
            // round trips more than a DNS answer, and its failure vetoes the DNS agreement.
            if first_answer[fam].is_some_and(|t| now >= t + AGREEMENT_GRACE) && !is_tls(&q.pending)
            {
                errors[fam].push(format!("{}: no answer within the grace", q.what));
                return false;
            }
            // The address family the reflector reports: the asked family's, IPv4 through NAT64.
            let want_v6 = fam == 1;
            let got: Option<io::Result<IpAddr>> = match &mut q.pending {
                Pending::Dns { sock, id, .. } => loop {
                    match sock.recv(&mut buf) {
                        Ok(n) => match parse_answer(&buf[..n], *id, want_v6) {
                            Some(r) => break Some(r),
                            None => continue, // not an answer to this query
                        },
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => break None,
                        Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                        Err(e) => break Some(Err(e)),
                    }
                },
                #[cfg(feature = "client")]
                Pending::Tls(t) => t.poll(want_v6),
            };
            match got {
                None => true,
                Some(Ok(ip)) => {
                    let source = match &q.pending {
                        Pending::Dns { name, .. } => Source::Dns(name),
                        #[cfg(feature = "client")]
                        Pending::Tls(_) => Source::Tls,
                    };
                    found[fam].push(Answer {
                        source,
                        via: q.via,
                        ip,
                    });
                    first_answer[fam].get_or_insert(Instant::now());
                    progressed = true;
                    false
                }
                Some(Err(e)) => {
                    if tls_connected(&q.pending) {
                        vetoed[fam].push(q.via);
                    }
                    errors[fam].push(format!("{}: {e}", q.what));
                    false
                }
            }
        });
        if !progressed {
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    for q in &queries {
        if tls_connected(&q.pending) {
            vetoed[q.fam].push(q.via);
        }
        errors[q.fam].push(format!("{}: no answer within the timeout", q.what));
    }
    for (fam, v) in vetoed.iter().enumerate() {
        if !v.is_empty() {
            tracing::warn!(
                "network guard: the HTTPS reflector's connection for {} was made but TLS or its \
                 answer failed (something on the path answers in its place), so no DNS reflector \
                 answer confirms this host's public address over that path",
                if fam == 0 { "IPv4" } else { "IPv6" }
            );
        }
    }
    #[cfg(not(target_os = "macos"))]
    let dns_servers = crate::system_resolvers();
    #[cfg(target_os = "macos")]
    let dns_servers = dns_exclusion(crate::facts::read_system_resolvers(), &found, &mut vetoed);
    let result = |fam: usize, family: &str| -> FamilyFound {
        if !found[fam].is_empty() {
            Ok(Some(agree(family, &found[fam], &dns_servers, &vetoed[fam])))
        } else if unroutable[fam] && !(fam == 0 && nat64_asked) {
            Ok(None)
        } else {
            Err(errors[fam].join("; "))
        }
    };
    (result(0, "IPv4"), result(1, "IPv6"))
}

/// macOS (review round 3, cross-5): the DNS servers whose answers confirm nothing ([`agree`]),
/// from `servers`. When they cannot be read (`servers` is an error), no DNS reflector answer
/// confirms anything this round, since one could name a DNS server of this host (a site resolver
/// that answers for the reflectors' names): every path an answer of `found` came over is vetoed in
/// `vetoed`, as when the HTTPS reflector's TLS failed, so only the HTTPS reflector confirms.
/// (Round 2 read an unreadable DNS configuration as no servers at all.)
#[cfg(target_os = "macos")]
fn dns_exclusion(
    servers: io::Result<Vec<IpAddr>>,
    found: &[Vec<Answer>; 2],
    vetoed: &mut [Vec<Option<Prefix>>; 2],
) -> Vec<IpAddr> {
    match servers {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(
                "network guard: this host's DNS servers could not be read ({e}), so no DNS \
                 reflector answer confirms its public address this round (only the HTTPS \
                 reflector's)"
            );
            for (fam, answers) in found.iter().enumerate() {
                for a in answers {
                    if !vetoed[fam].contains(&a.via) {
                        vetoed[fam].push(a.via);
                    }
                }
            }
            Vec::new()
        }
    }
}

/// Whether `p` is an HTTPS reflector query.
fn is_tls(p: &Pending) -> bool {
    #[cfg(feature = "client")]
    if let Pending::Tls(_) = p {
        return true;
    }
    let _ = p;
    false
}

/// Whether `p` is an HTTPS reflector query whose TCP connection was made.
fn tls_connected(p: &Pending) -> bool {
    #[cfg(feature = "client")]
    if let Pending::Tls(t) = p {
        return t.connected();
    }
    let _ = p;
    false
}

/// A non-blocking UDP socket connected to `to` (`r`'s server, or its NAT64 synthesis), with `r`'s
/// query sent, and the query's id.
fn send_query_to(r: &Reflector, to: IpAddr) -> io::Result<(UdpSocket, u16)> {
    let local: SocketAddr = if to.is_ipv6() {
        (Ipv6Addr::UNSPECIFIED, 0).into()
    } else {
        (Ipv4Addr::UNSPECIFIED, 0).into()
    };
    let sock = UdpSocket::bind(local)?;
    sock.connect((to, 53))?;
    let id = query_id();
    sock.send(&build_query(id, r.name, r.class)?)?;
    sock.set_nonblocking(true)?;
    Ok((sock, id))
}

/// Cloudflare's `/cdn-cgi/trace` over HTTPS, without blocking: one query driven by
/// [`TlsQuery::poll`] from the discovery loop.
#[cfg(feature = "client")]
mod tls {
    use std::io::{self, Read, Write};
    use std::net::{IpAddr, SocketAddr, TcpStream};
    use std::sync::{Arc, OnceLock};

    /// The most of a response read.
    const MAX_RESPONSE: usize = 16 * 1024;

    fn config() -> io::Result<Arc<rustls::ClientConfig>> {
        static CONFIG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
        if let Some(c) = CONFIG.get() {
            return Ok(c.clone());
        }
        let roots =
            rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let c = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(io::Error::other)?
        .with_root_certificates(roots)
        .with_no_client_auth();
        Ok(CONFIG.get_or_init(|| Arc::new(c)).clone())
    }

    pub(super) struct TlsQuery {
        stream: TcpStream,
        conn: rustls::ClientConnection,
        connected: bool,
        response: Vec<u8>,
    }

    impl TlsQuery {
        /// Starts connecting to `to` (the reflector, or its NAT64 synthesis); the certificate must
        /// be valid for `server`, the reflector's own address.
        pub(super) fn start(to: SocketAddr, server: IpAddr) -> io::Result<Self> {
            use socket2::{Domain, Socket, Type};
            let domain = if to.is_ipv4() {
                Domain::IPV4
            } else {
                Domain::IPV6
            };
            let sock = Socket::new(domain, Type::STREAM, None)?;
            sock.set_nonblocking(true)?;
            match sock.connect(&to.into()) {
                Ok(()) => {}
                #[cfg(unix)]
                Err(e) if e.raw_os_error() == Some(libc::EINPROGRESS) => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(e),
            }
            let name = rustls::pki_types::ServerName::from(server);
            let mut conn =
                rustls::ClientConnection::new(config()?, name).map_err(io::Error::other)?;
            let host = match server {
                IpAddr::V4(a) => a.to_string(),
                IpAddr::V6(a) => format!("[{a}]"),
            };
            // Sent once the handshake is done (rustls buffers it).
            write!(
                conn.writer(),
                "GET /cdn-cgi/trace HTTP/1.0\r\nHost: {host}\r\nUser-Agent: {}\r\n\
                 Accept: text/plain\r\n\r\n",
                crate::USER_AGENT
            )?;
            Ok(TlsQuery {
                stream: sock.into(),
                conn,
                connected: false,
                response: Vec::new(),
            })
        }

        /// Whether its TCP connection was made.
        pub(super) fn connected(&self) -> bool {
            self.connected
        }

        /// Drives the query as far as it goes without blocking: `None` while it waits, else the
        /// global address of the wanted family the trace reports (`ip=`), or why there is none.
        pub(super) fn poll(&mut self, want_v6: bool) -> Option<io::Result<IpAddr>> {
            if !self.connected {
                match self.stream.peer_addr() {
                    Ok(_) => self.connected = true,
                    Err(_) => {
                        return match self.stream.take_error() {
                            Ok(Some(e)) | Err(e) => Some(Err(e)),
                            Ok(None) => None,
                        }
                    }
                }
            }
            let mut eof = false;
            loop {
                let mut progressed = false;
                while self.conn.wants_write() {
                    match self.conn.write_tls(&mut self.stream) {
                        Ok(_) => progressed = true,
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                        Err(e) => return Some(Err(e)),
                    }
                }
                if self.conn.wants_read() {
                    match self.conn.read_tls(&mut self.stream) {
                        Ok(0) => eof = true,
                        Ok(_) => {
                            progressed = true;
                            if let Err(e) = self.conn.process_new_packets() {
                                return Some(Err(io::Error::new(io::ErrorKind::InvalidData, e)));
                            }
                        }
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                        Err(e) => return Some(Err(e)),
                    }
                }
                let mut buf = [0u8; 4096];
                loop {
                    match self.conn.reader().read(&mut buf) {
                        Ok(0) => {
                            eof = true;
                            break;
                        }
                        Ok(n) => {
                            self.response.extend_from_slice(&buf[..n]);
                            progressed = true;
                        }
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                        Err(_) => {
                            eof = true;
                            break;
                        }
                    }
                }
                if let Some(ip) = trace_address(&self.response, want_v6) {
                    return Some(Ok(ip));
                }
                if self.response.len() > MAX_RESPONSE || eof {
                    return Some(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "no public address in the trace",
                    )));
                }
                if !progressed {
                    return None;
                }
            }
        }
    }

    /// The `ip=` line of a trace response's body, when it is complete and holds a global address
    /// of the wanted family.
    pub(super) fn trace_address(response: &[u8], want_v6: bool) -> Option<IpAddr> {
        let text = std::str::from_utf8(response).ok()?;
        let body = &text[text.find("\r\n\r\n")? + 4..];
        let line = body.lines().find_map(|l| l.strip_prefix("ip="))?;
        // Complete only once its newline arrived.
        body.contains(&format!("ip={line}\n")).then_some(())?;
        let ip: IpAddr = line.trim().parse().ok()?;
        (ip.is_ipv6() == want_v6 && crate::is_global(ip)).then_some(ip)
    }
}

/// One reflector query over UDP.
pub fn ask(r: &Reflector, timeout: Duration) -> io::Result<IpAddr> {
    let local: SocketAddr = if r.server.is_ipv6() {
        (Ipv6Addr::UNSPECIFIED, 0).into()
    } else {
        (Ipv4Addr::UNSPECIFIED, 0).into()
    };
    let sock = UdpSocket::bind(local)?;
    sock.connect((r.server, 53))?;
    sock.set_read_timeout(Some(timeout))?;
    sock.set_write_timeout(Some(timeout))?;
    let id = query_id();
    sock.send(&build_query(id, r.name, r.class)?)?;
    let deadline = Instant::now() + timeout;
    let mut buf = [0u8; 1500];
    loop {
        let n = sock.recv(&mut buf)?;
        match parse_answer(&buf[..n], id, r.server.is_ipv6()) {
            Some(Ok(ip)) => return Ok(ip),
            Some(Err(e)) => return Err(e),
            // Not an answer to this query: keep waiting, within the deadline.
            None => {
                let left = deadline.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    return Err(io::ErrorKind::TimedOut.into());
                }
                sock.set_read_timeout(Some(left))?;
            }
        }
    }
}

pub(crate) fn query_id() -> u16 {
    use std::hash::{BuildHasher, Hasher};
    // A per-process random key, and the clock: unpredictable enough for an id whose forgery can
    // only add an address to refuse.
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    h.write_u128(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos(),
    );
    h.finish() as u16
}

/// A query for `name` `TXT` in `class`, recursion not desired.
pub(crate) fn build_query(id: u16, name: &str, class: u16) -> io::Result<Vec<u8>> {
    build_query_with(id, name, TYPE_TXT, class, false)
}

/// A query for `name` of type `qtype` in `class`, recursion desired or not.
pub(crate) fn build_query_with(
    id: u16,
    name: &str,
    qtype: u16,
    class: u16,
    recursion_desired: bool,
) -> io::Result<Vec<u8>> {
    let mut q = Vec::with_capacity(12 + name.len() + 6);
    q.extend_from_slice(&id.to_be_bytes());
    // A standard query; RD as asked.
    q.extend_from_slice(&if recursion_desired { 0x0100u16 } else { 0 }.to_be_bytes());
    q.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    q.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    for label in name.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "bad name"));
        }
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0);
    q.extend_from_slice(&qtype.to_be_bytes());
    q.extend_from_slice(&class.to_be_bytes());
    Ok(q)
}

pub(crate) fn u16_at(m: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*m.get(i)?, *m.get(i + 1)?]))
}

/// The offset just past the (possibly compressed) name at `off`.
pub(crate) fn skip_name(m: &[u8], mut off: usize) -> Option<usize> {
    for _ in 0..128 {
        let len = *m.get(off)?;
        match len >> 6 {
            0 if len == 0 => return Some(off + 1),
            0 => off += 1 + usize::from(len),
            3 => return Some(off + 2),
            _ => return None,
        }
    }
    None
}

/// `None` when `m` is not an answer to query `id` (keep waiting); else the first global address
/// of the asked family in a `TXT` answer, or why there is none.
pub(crate) fn parse_answer(m: &[u8], id: u16, v6: bool) -> Option<io::Result<IpAddr>> {
    let bad = |why: &str| {
        Some(Err(io::Error::new(
            io::ErrorKind::InvalidData,
            why.to_owned(),
        )))
    };
    if u16_at(m, 0)? != id || u16_at(m, 2)? & 0x8000 == 0 || u16_at(m, 4)? != 1 {
        return None;
    }
    let rcode = u16_at(m, 2)? & 0xf;
    if rcode != 0 {
        return bad(&format!("rcode {rcode}"));
    }
    let an = u16_at(m, 6)?;
    let Some(mut off) = skip_name(m, 12).map(|o| o + 4) else {
        return bad("malformed question");
    };
    for _ in 0..an {
        let Some(o) = skip_name(m, off) else {
            return bad("malformed answer");
        };
        let (Some(rtype), Some(rdlen)) = (u16_at(m, o), u16_at(m, o + 8)) else {
            return bad("malformed answer");
        };
        let start = o + 10;
        let end = start + usize::from(rdlen);
        let Some(rdata) = m.get(start..end) else {
            return bad("malformed answer");
        };
        off = end;
        if rtype != TYPE_TXT {
            continue;
        }
        let mut i = 0;
        while i < rdata.len() {
            let l = usize::from(rdata[i]);
            let Some(text) = rdata.get(i + 1..i + 1 + l) else {
                return bad("malformed TXT");
            };
            i += 1 + l;
            let Ok(ip) = std::str::from_utf8(text).unwrap_or("").parse::<IpAddr>() else {
                continue;
            };
            if ip.is_ipv6() == v6 && crate::is_global(ip) {
                return Some(Ok(ip));
            }
        }
    }
    bad("no public address in the answer")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn answer(id: u16, rcode: u16, txt: &[&str]) -> Vec<u8> {
        let mut m = Vec::new();
        m.extend_from_slice(&id.to_be_bytes());
        m.extend_from_slice(&(0x8400 | rcode).to_be_bytes());
        m.extend_from_slice(&1u16.to_be_bytes());
        m.extend_from_slice(&(txt.len() as u16).to_be_bytes());
        m.extend_from_slice(&[0, 0, 0, 0]);
        m.extend(build_query(0, "o-o.myaddr.l.google.com", 1).unwrap()[12..].iter());
        for t in txt {
            m.extend_from_slice(&[0xc0, 12]);
            m.extend_from_slice(&TYPE_TXT.to_be_bytes());
            m.extend_from_slice(&1u16.to_be_bytes());
            m.extend_from_slice(&60u32.to_be_bytes());
            m.extend_from_slice(&((t.len() + 1) as u16).to_be_bytes());
            m.push(t.len() as u8);
            m.extend_from_slice(t.as_bytes());
        }
        m
    }

    #[test]
    fn queries_and_answers() {
        let q = build_query(0xbeef, "whoami.cloudflare", CLASS_CH).unwrap();
        assert_eq!(&q[..4], &[0xbe, 0xef, 0, 0]);
        assert_eq!(&q[12..], b"\x06whoami\x0acloudflare\x00\x00\x10\x00\x03");
        let a = |m: &[u8], v6| parse_answer(m, 7, v6).map(|r| r.map_err(|e| e.to_string()));
        assert_eq!(
            a(&answer(7, 0, &["203.0.114.9"]), false),
            Some(Ok("203.0.114.9".parse().unwrap()))
        );
        assert_eq!(
            a(
                &answer(7, 0, &["edns0-client-subnet 1.2.3.0/24", "2606:4700::9"]),
                true
            ),
            Some(Ok("2606:4700::9".parse().unwrap()))
        );
        // Another id: not ours, keep waiting.
        assert_eq!(a(&answer(8, 0, &["203.0.114.9"]), false), None);
        // A non-global or wrong-family answer is no answer.
        assert!(matches!(
            a(&answer(7, 0, &["10.0.0.1"]), false),
            Some(Err(_))
        ));
        assert!(matches!(
            a(&answer(7, 0, &["203.0.114.9"]), true),
            Some(Err(_))
        ));
        assert!(matches!(a(&answer(7, 2, &[]), false), Some(Err(_))));
        let mut cut = answer(7, 0, &["203.0.114.9"]);
        cut.truncate(cut.len() - 3);
        assert!(matches!(a(&cut, false), Some(Err(_))));
    }

    /// Every reflector at once, on this thread: each family's answers are global addresses of
    /// that family (or the family is unroutable here, or failed with reasons), within the timeout.
    #[test]
    fn discovery_asks_everything_at_once_on_this_thread() {
        let t = Instant::now();
        let (v4, v6) = discover();
        assert!(t.elapsed() < DISCOVERY_TIMEOUT + Duration::from_millis(500));
        for (got, six) in [(v4, false), (v6, true)] {
            match got {
                Ok(Some(a)) => {
                    assert!(!a.addresses.is_empty());
                    for ip in a.addresses.iter().chain(&a.confirmed) {
                        assert!(ip.is_ipv6() == six && crate::is_global(*ip), "{ip}");
                    }
                    assert!(a.confirmed.iter().all(|c| a.addresses.contains(c)));
                    eprintln!("{a:?}");
                }
                Ok(None) => eprintln!("no route for this family here"),
                Err(e) => assert!(!e.is_empty()),
            }
        }
    }

    fn dns(name: &'static str, ip: &str) -> Answer {
        Answer {
            source: Source::Dns(name),
            via: None,
            ip: ip.parse().unwrap(),
        }
    }

    fn tls(ip: &str) -> Answer {
        Answer {
            source: Source::Tls,
            via: None,
            ip: ip.parse().unwrap(),
        }
    }

    const G: &str = "o-o.myaddr.l.google.com";
    const C: &str = "whoami.cloudflare";

    /// Review r2 R2-NG-7: every reflector's answers are kept (their union), and an address is
    /// confirmed only when the HTTPS reflector reports it or both DNS reflectors report it alike.
    #[test]
    fn answers_are_united_and_confirmed_only_by_agreement_or_tls() {
        let a = |s: &str| s.parse::<IpAddr>().unwrap();
        let both = agree(
            "IPv6",
            &[dns(G, "2606:a300::5"), dns(C, "2606:a300::5")],
            &[],
            &[],
        );
        assert_eq!(both.addresses, vec![a("2606:a300::5")]);
        assert_eq!(both.confirmed, vec![a("2606:a300::5")]);
        let one = agree("IPv6", &[dns(C, "2606:4700:4700::64")], &[], &[]);
        assert_eq!(one.addresses, vec![a("2606:4700:4700::64")]);
        assert!(one.confirmed.is_empty());
        let split = agree(
            "IPv4",
            &[dns(G, "203.0.114.9"), dns(C, "198.51.99.7")],
            &[],
            &[],
        );
        assert_eq!(split.addresses, vec![a("198.51.99.7"), a("203.0.114.9")]);
        assert!(split.confirmed.is_empty());
        // The HTTPS reflector alone confirms; with a disagreeing DNS answer, both are refused and
        // only its answer is confirmed.
        let t = agree("IPv4", &[tls("81.2.69.160")], &[], &[]);
        assert_eq!(t.confirmed, vec![a("81.2.69.160")]);
        let t = agree(
            "IPv4",
            &[dns(G, "203.0.114.9"), tls("81.2.69.160")],
            &[],
            &[],
        );
        assert_eq!(t.addresses, vec![a("81.2.69.160"), a("203.0.114.9")]);
        assert_eq!(t.confirmed, vec![a("81.2.69.160")]);
    }

    /// A box that intercepts DNS answers for the reflectors with its resolver's address (one of
    /// this host's DNS servers): refused, but it confirms nothing, so the family stays unknown.
    #[test]
    fn a_dns_answer_naming_a_host_dns_server_confirms_nothing() {
        let a = |s: &str| s.parse::<IpAddr>().unwrap();
        let resolver = [a("203.0.114.53")];
        let r = agree(
            "IPv4",
            &[dns(G, "203.0.114.53"), dns(C, "203.0.114.53")],
            &resolver,
            &[],
        );
        assert_eq!(r.addresses, vec![a("203.0.114.53")]);
        assert!(r.confirmed.is_empty());
    }

    /// An IPv4 answer through a NAT64 prefix is confirmed by the same rules, and names the prefix.
    #[test]
    fn a_nat64_answer_names_its_prefix() {
        let a = |s: &str| s.parse::<IpAddr>().unwrap();
        let p: Prefix = "64:ff9b::/96".parse().unwrap();
        let via = |x: Answer| Answer { via: Some(p), ..x };
        let r = agree(
            "IPv4",
            &[via(dns(G, "81.2.69.160")), via(dns(C, "81.2.69.160"))],
            &[],
            &[],
        );
        assert_eq!(r.confirmed, vec![a("81.2.69.160")]);
        assert_eq!(r.via_nat64, vec![p]);
        let r = agree("IPv4", &[via(dns(G, "81.2.69.160"))], &[], &[]);
        assert!(r.confirmed.is_empty() && r.via_nat64.is_empty());
    }

    /// Against the real HTTPS reflector (its certificate checked for its IP address): an answer
    /// is this host's public address of that family. Skipped quietly where it is unreachable.
    #[cfg(feature = "client")]
    #[test]
    fn the_https_reflector_answers_when_reachable() {
        for server in TLS_REFLECTORS {
            let mut q = match tls::TlsQuery::start(SocketAddr::new(*server, 443), *server) {
                Ok(q) => q,
                Err(e) => {
                    eprintln!("{server} unreachable here: {e}");
                    continue;
                }
            };
            let deadline = Instant::now() + DISCOVERY_TIMEOUT;
            let got = loop {
                if let Some(r) = q.poll(server.is_ipv6()) {
                    break Some(r);
                }
                if Instant::now() >= deadline {
                    break None;
                }
                std::thread::sleep(Duration::from_millis(5));
            };
            match got {
                Some(Ok(ip)) => {
                    assert_eq!(ip.is_ipv6(), server.is_ipv6());
                    assert!(crate::is_global(ip));
                    eprintln!("{TLS_NAME} @{server}: {ip}");
                }
                other => eprintln!("{server}: {other:?}"),
            }
        }
        // A certificate that does not name the reflector's address is refused: 8.8.8.8 presents
        // Google's, which does not name 1.1.1.1.
        if let Ok(mut q) = tls::TlsQuery::start("8.8.8.8:443".parse().unwrap(), TLS_REFLECTORS[0]) {
            let deadline = Instant::now() + DISCOVERY_TIMEOUT;
            loop {
                match q.poll(false) {
                    Some(r) => {
                        assert!(r.is_err(), "{r:?}");
                        break;
                    }
                    None if Instant::now() >= deadline => break,
                    None => std::thread::sleep(Duration::from_millis(5)),
                }
            }
        }
    }

    /// Where the HTTPS reflector's TCP connection was made but TLS or its answer failed (a box on
    /// the path answering for 1.1.1.1 with a certificate this host does not trust), both DNS
    /// reflectors agreeing confirm nothing over that path: the same box could answer them alike.
    /// Other paths are unaffected.
    #[test]
    fn a_failed_https_reflector_vetoes_the_dns_agreement() {
        let a = |s: &str| s.parse::<IpAddr>().unwrap();
        let forged = [dns(G, "81.2.69.160"), dns(C, "81.2.69.160")];
        let r = agree("IPv4", &forged, &[], &[None]);
        assert_eq!(r.addresses, vec![a("81.2.69.160")], "still refused");
        assert!(r.confirmed.is_empty());
        let p: Prefix = "64:ff9b::/96".parse().unwrap();
        let through = |x: Answer| Answer { via: Some(p), ..x };
        let r = agree(
            "IPv4",
            &[through(forged[0]), through(forged[1])],
            &[],
            &[None],
        );
        assert_eq!(r.confirmed, vec![a("81.2.69.160")], "another path");
        assert_eq!(r.via_nat64, vec![p]);
        let r = agree(
            "IPv4",
            &[through(forged[0]), through(forged[1])],
            &[],
            &[Some(p)],
        );
        assert!(r.confirmed.is_empty() && r.via_nat64.is_empty());
    }

    /// macOS, review round 3, cross-5: a round in which this host's DNS servers cannot be read
    /// confirms nothing from DNS reflectors (any could name a DNS server of this host), only from
    /// the HTTPS reflector; when they can be read, an answer naming one of them is left out as
    /// before.
    #[cfg(target_os = "macos")]
    #[test]
    fn dns_answers_confirm_nothing_without_the_dns_servers() {
        let a = |s: &str| s.parse::<IpAddr>().unwrap();
        let p: Prefix = "64:ff9b::/96".parse().unwrap();
        let through = |x: Answer| Answer { via: Some(p), ..x };
        let v4 = vec![
            dns(G, "81.2.69.160"),
            dns(C, "81.2.69.160"),
            through(dns(G, "81.2.69.161")),
            through(dns(C, "81.2.69.161")),
        ];
        let found = [v4, vec![dns(G, "2001:db8::7"), dns(C, "2001:db8::7")]];
        let mut vetoed: [Vec<Option<Prefix>>; 2] = [Vec::new(), Vec::new()];
        let servers = dns_exclusion(Err(io::Error::other("staged")), &found, &mut vetoed);
        assert!(servers.is_empty());
        for (fam, family) in [(0, "IPv4"), (1, "IPv6")] {
            let r = agree(family, &found[fam], &servers, &vetoed[fam]);
            assert!(r.confirmed.is_empty(), "{family}: {r:?}");
            assert!(r.via_nat64.is_empty());
            assert!(!r.addresses.is_empty(), "still refused as this host's");
        }
        // The HTTPS reflector's answer still confirms.
        let with_tls = [found[0].clone(), vec![tls("81.2.69.160")]].concat();
        let r = agree("IPv4", &with_tls, &servers, &vetoed[0]);
        assert_eq!(r.confirmed, vec![a("81.2.69.160")]);
        // Read, the servers are left out of the agreement and nothing is vetoed.
        let mut vetoed: [Vec<Option<Prefix>>; 2] = [Vec::new(), Vec::new()];
        let servers = dns_exclusion(Ok(vec![a("81.2.69.160")]), &found, &mut vetoed);
        assert_eq!(vetoed, [Vec::new(), Vec::new()]);
        let r = agree("IPv4", &found[0], &servers, &vetoed[0]);
        assert_eq!(r.confirmed, vec![a("81.2.69.161")]);
    }

    /// A confirmation counts for [`CONFIRMATION_LIFETIME`], and only on the uplink it was made
    /// on.
    #[test]
    fn confirmations_expire_and_belong_to_their_uplink() {
        let now = Instant::now();
        let ago = |s: u64| now.checked_sub(Duration::from_secs(s));
        assert!(still_confirmed(ago(10), Some(1), Some(1), now));
        assert!(still_confirmed(ago(599), Some(1), Some(1), now));
        assert!(!still_confirmed(ago(600), Some(1), Some(1), now), "expired");
        assert!(
            !still_confirmed(None, Some(1), Some(1), now),
            "never confirmed"
        );
        assert!(
            !still_confirmed(ago(10), Some(1), Some(2), now),
            "another uplink"
        );
        assert!(
            !still_confirmed(ago(10), None, Some(2), now),
            "learned before the uplink was known"
        );
        assert!(
            still_confirmed(ago(10), Some(1), None, now),
            "a caller that names no uplink"
        );
        assert_eq!(CONFIRMATION_LIFETIME, DISCOVERY_TTL * 2);
        // Review round 4, cross-2: confirmed recently on another uplink is being learned again
        // (its refusal says so); expired, never confirmed, or a caller naming no uplink is not.
        assert!(relearning(ago(10), Some(1), Some(2), now));
        assert!(relearning(ago(10), None, Some(2), now));
        assert!(!relearning(ago(10), Some(2), Some(2), now));
        assert!(!relearning(ago(600), Some(1), Some(2), now));
        assert!(!relearning(None, Some(1), Some(2), now));
        assert!(!relearning(ago(10), Some(1), None, now));
    }

    /// An HTTPS reflector query that connects, to something that does not speak TLS for
    /// 1.1.1.1, fails, and says it had connected (which vetoes the DNS agreement).
    #[cfg(feature = "client")]
    #[test]
    fn an_https_reflector_answered_by_an_impostor_connects_and_fails() {
        use std::io::Write;
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut c, _) = l.accept().unwrap();
            let _ = c.write_all(b"HTTP/1.0 200 OK\r\n\r\nip=81.2.69.160\n");
            std::thread::sleep(Duration::from_millis(200));
        });
        let mut q = tls::TlsQuery::start(addr, TLS_REFLECTORS[0]).unwrap();
        let deadline = Instant::now() + DISCOVERY_TIMEOUT;
        let got = loop {
            if let Some(r) = q.poll(false) {
                break r;
            }
            assert!(Instant::now() < deadline, "no outcome");
            std::thread::sleep(Duration::from_millis(5));
        };
        assert!(got.is_err(), "{got:?}");
        assert!(q.connected());
        assert!(tls_connected(&Pending::Tls(Box::new(q))));
        server.join().unwrap();
    }

    /// The trace's `ip=` line, once complete, global and of the wanted family.
    #[cfg(feature = "client")]
    #[test]
    fn the_trace_reports_the_address() {
        let r = |body: &str| format!("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n{body}");
        let t = |s: &str, v6| tls::trace_address(r(s).as_bytes(), v6);
        assert_eq!(
            t("fl=1\nh=1.1.1.1\nip=81.2.69.160\nts=1\n", false),
            Some("81.2.69.160".parse().unwrap())
        );
        assert_eq!(t("fl=1\nip=81.2.69.1", false), None, "incomplete");
        assert_eq!(t("ip=10.0.0.1\n", false), None, "not global");
        assert_eq!(t("ip=81.2.69.160\n", true), None, "the other family");
        assert_eq!(
            t("ip=2606:a300::5\n", true),
            Some("2606:a300::5".parse().unwrap())
        );
        assert_eq!(
            tls::trace_address(b"ip=81.2.69.160\n", false),
            None,
            "no body"
        );
    }

    /// Review r2 R2-NG-6 (PoC `pubrace`), inverted: a call that arrives while the first discovery
    /// runs on another thread waits for it and gets its answer, instead of nothing.
    #[test]
    fn a_call_during_the_first_discovery_waits_for_it() {
        let first = std::thread::spawn(learned);
        std::thread::sleep(Duration::from_millis(2));
        let t = Instant::now();
        let second = learned();
        let waited = t.elapsed();
        let first = first.join().unwrap();
        assert!(waited < FIRST_DISCOVERY_WAIT + Duration::from_millis(500));
        assert_eq!(
            second, first,
            "the second caller sees the first discovery's answer"
        );
        assert!(state().first_done);
    }

    /// Against the real reflectors (public DNS): an answer is this host's public address of that
    /// family. Skipped quietly where the network is unreachable.
    #[test]
    fn the_reflectors_answer_when_reachable() {
        for r in REFLECTORS {
            match ask(r, DISCOVERY_TIMEOUT) {
                Ok(ip) => {
                    assert_eq!(ip.is_ipv6(), r.server.is_ipv6(), "{r:?}");
                    assert!(crate::is_global(ip), "{r:?}: {ip}");
                }
                Err(e) => eprintln!("{} @{} unreachable here: {e}", r.name, r.server),
            }
        }
    }
}
