//! NAT64 network-specific prefixes (review r2, R2-NG-4).
//!
//! Behind NAT64, an IPv6 address under the translator's prefix carries an IPv4 address (RFC 6052),
//! and a connection to it reaches that IPv4 address **from the translator's IPv4 side**: a private
//! address there is the translator's own network, cloud metadata is the translator's host's. The
//! well-known prefix `64:ff9b::/96` is read everywhere ([`crate::canonical_ip`]); a
//! **network-specific prefix** (NSP: any prefix of length 32, 40, 48, 56, 64 or 96 a network picks
//! for its translator, usually inside its own global space) is invisible without being told, so
//! `<NSP>::10.0.0.1` looked like any global address and was admitted.
//!
//! The guard now knows the NSPs that are in force for this host:
//!
//! - **configured** ones, `[egress] nat64_prefixes` ([`set_configured`]);
//! - **learned** ones (RFC 7050): an `AAAA` query for `ipv4only.arpa.` (a name with only `A`
//!   records, `192.0.0.170` and `192.0.0.171`), asked of the DNS servers the host uses
//!   ([`crate::system_resolvers`]); a DNS64 resolver synthesizes `AAAA` answers under its NSP, and
//!   the prefix is where one of those two addresses sits. Asked per uplink
//!   (`ensure_discovered_on`, review round 3, bypass-1; every platform since the Linux
//!   application): when the host's facts are first gathered (on the calling thread, at most
//!   [`DISCOVERY_TIMEOUT`], the servers in use first: `order_servers`), at once in the
//!   background whenever the uplink signature changes, every [`RETRY_UNSETTLED`] while a host
//!   with IPv6 and no IPv4 route has found nothing, and every [`DISCOVERY_TTL`]. Until the round
//!   for a new uplink has finished, such a host refuses IPv6 destinations
//!   ([`crate::Denied::Nat64Unsettled`]). Failure is not fatal and is logged once. An answer
//!   reveals a prefix only where both well-known addresses sit under it, at most
//!   [`MAX_PER_ANSWER`] per answer ([`nsps_of_answer`], RFC 7050 §3);
//! - **announced** ones (RFC 8781 PREF64): macOS from the configuration daemon's NAT64 state,
//!   Linux from the router advertisements the kernel processes (`pref64`), from an IPv6 default
//!   gateway alone, with their lifetimes, learned with each round.
//!
//! Review round 4 (bypass-1, parse-1, cross-1, parse-4): configured prefixes are always in force
//! (the old process-wide list of 16, sorted and truncated, let 16 learned ones crowd them out).
//! Learned ones are kept per uplink and per source, each source capped; a source that names more
//! than its cap, or a prefix that cannot be held, makes its uplink unsettled ([`unheld`]: IPv6
//! destinations are refused there, on any host). Every learned prefix is read as an NSP (a stale
//! one only refuses more) until another uplink's need its room ([`MAX_LEARNED`]); only the
//! configured ones and those learned on the uplink in use, still named and within their
//! lifetime, are synthesized with ([`in_force`]).
//!
//! Every address under one of them is read as the IPv4 address it carries, laid out as RFC 6052
//! says for the prefix's length (bits 64–71, the "u" octet, skipped): [`crate::is_global`] refuses
//! it unless that IPv4 address is global (and the u octet is zero, as RFC 6052 requires), and
//! [`crate::canonical_ip`] / [`crate::Prefix::canonical_prefix`] read it as that IPv4 address, so
//! the host's own addresses, its connected prefixes and the operator's deny CIDRs match it. This
//! only ever refuses more: an address under an NSP must also pass every check it would without
//! one.
//!
//! The registry is process-wide (an NSP is a property of the network the host is on); the witness
//! broker, which cannot be told it, learns it at its own startup and also gets the refusals it
//! implies as prefixes ([`embedded_refusals`], part of [`crate::HostFacts::refused_prefixes`]).

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, RwLock};
use std::time::{Duration, Instant};

use crate::ip::{nsp_embed, Prefix};

/// The prefix lengths RFC 6052 allows.
pub const NSP_LENS: [u8; 6] = [32, 40, 48, 56, 64, 96];

/// The well-known prefix, read everywhere already.
pub const WELL_KNOWN_PREFIX: Prefix = Prefix {
    addr: IpAddr::V6(Ipv6Addr::new(0x64, 0xff9b, 0, 0, 0, 0, 0, 0)),
    len: 96,
};

/// How long the discovery query may take.
pub const DISCOVERY_TIMEOUT: Duration = Duration::from_secs(2);
/// How often the NSPs are learned again.
pub const DISCOVERY_TTL: Duration = Duration::from_secs(300);
/// Most DNS servers asked at once.
const MAX_SERVERS: usize = 8;
/// Most configured NSPs (`[egress] nat64_prefixes`); every one is always in force.
pub const MAX_PREFIXES: usize = 16;
/// Most learned NSPs held, on every uplink together (review round 4, bypass-1). When a new one
/// does not fit, the least recently seen of another uplink's makes room; when none can, it is not
/// held and its uplink is unsettled ([`unheld`]).
pub const MAX_LEARNED: usize = 64;
/// Most learned NSPs held for one uplink.
pub const MAX_PER_UPLINK: usize = 32;
/// Most NSPs one DNS server's answer may reveal (RFC 7050 §3: a DNS64 synthesizes under one
/// prefix, two during a renumbering); an answer that reveals more is not believed.
pub const MAX_PER_ANSWER: usize = 2;
/// Most NSPs one router may announce (PREF64, RFC 8781), and the system's own NAT64 state may
/// name; more is not believed.
pub const MAX_PER_ROUTER: usize = 4;
/// The name RFC 7050 asks for.
pub const IPV4ONLY_ARPA: &str = "ipv4only.arpa";
/// Its two `A` records, the well-known addresses an NSP is found by.
pub const WELL_KNOWN_V4: [Ipv4Addr; 2] =
    [Ipv4Addr::new(192, 0, 0, 170), Ipv4Addr::new(192, 0, 0, 171)];

const TYPE_AAAA: u16 = 28;
const CLASS_IN: u16 = 1;

/// Where a learned NSP came from; each source has its own cap (review round 4, bypass-1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // Pref64 is Linux's, System macOS's.
pub(crate) enum Source {
    /// The RFC 7050 answer of this DNS server.
    Dns64(IpAddr),
    /// The PREF64 option (RFC 8781) of this router's advertisements, on this interface: only a
    /// default route's gateway, on that route's interface, is heard.
    Pref64 { router: Ipv6Addr, ifindex: u32 },
    /// The system's own NAT64 state (macOS: the configuration daemon's).
    System,
    /// Named by a test.
    #[cfg(test)]
    Given(u32),
}

impl Source {
    fn cap(self) -> usize {
        match self {
            Source::Dns64(_) => MAX_PER_ANSWER,
            Source::Pref64 { .. } => MAX_PER_ROUTER,
            Source::System => 2 * MAX_PER_ROUTER,
            #[cfg(test)]
            Source::Given(_) => MAX_PER_UPLINK,
        }
    }
}

impl std::fmt::Display for Source {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Source::Dns64(s) => write!(f, "the DNS server {s} (RFC 7050)"),
            Source::Pref64 { router, ifindex } => write!(
                f,
                "the router advertisements of {router} on interface {ifindex} (PREF64)"
            ),
            Source::System => f.write_str("the system's NAT64 state"),
            #[cfg(test)]
            Source::Given(n) => write!(f, "test source {n}"),
        }
    }
}

/// One learned NSP: on which uplink, from which source, when last named, until when its source
/// says it holds (a PREF64 lifetime), and whether it is still named (a source that stops naming
/// it, or names it with lifetime 0, withdraws it: it is no longer synthesized with, and stays
/// refused until another uplink's prefixes need its room; a stale prefix only refuses more).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Entry {
    prefix: Prefix,
    uplink: u64,
    source: Source,
    seen: Instant,
    until: Option<Instant>,
    active: bool,
}

#[derive(Debug, Default)]
struct Registry {
    configured: Vec<Prefix>,
    learned: Vec<Entry>,
    /// The uplink signature the host's facts were last read on, and its IPv6 default gateways
    /// (address, interface): the routers whose PREF64 is heard.
    on: Option<u64>,
    gateways: Vec<(Ipv6Addr, u32)>,
    /// Uplinks on which a prefix could not be held, and why (the latest few).
    unheld: Vec<(u64, String)>,
    /// The uplinks a round is running on, and whether anything was marked unheld there since it
    /// began ([`begin_round`], [`end_round`]).
    rounds: Vec<(u64, bool)>,
}

static REGISTRY: Mutex<Registry> = Mutex::new(Registry {
    configured: Vec::new(),
    learned: Vec::new(),
    on: None,
    gateways: Vec::new(),
    unheld: Vec::new(),
    rounds: Vec::new(),
});

fn registry() -> std::sync::MutexGuard<'static, Registry> {
    REGISTRY.lock().unwrap_or_else(|e| e.into_inner())
}

/// Configured ∪ learned (every uplink's, withdrawn ones included), the well-known prefix left
/// out: what the address predicate reads. Never truncated (review round 4, bypass-1: a sorted,
/// truncated list let 16 learned prefixes crowd the configured one out).
static CURRENT: RwLock<Option<Arc<[Prefix]>>> = RwLock::new(None);

fn publish(r: &Registry) {
    *CURRENT.write().unwrap_or_else(|e| e.into_inner()) = Some(all_of(r).into());
}

/// What [`publish`] makes current for `r`.
fn all_of(r: &Registry) -> Vec<Prefix> {
    let mut all: Vec<Prefix> = r
        .configured
        .iter()
        .copied()
        .chain(r.learned.iter().map(|e| e.prefix))
        .filter(|p| *p != WELL_KNOWN_PREFIX)
        .collect();
    all.sort();
    all.dedup();
    all
}

/// The NSPs in force, the well-known prefix left out (empty unless configured or learned).
pub(crate) fn current() -> Arc<[Prefix]> {
    CURRENT
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
        .unwrap_or_else(|| Arc::from(Vec::new()))
}

/// The NSPs the address predicate reads: configured and learned, the well-known prefix left out.
pub fn prefixes() -> Vec<Prefix> {
    current().to_vec()
}

/// The configured NSPs (`[egress] nat64_prefixes`).
pub fn configured() -> Vec<Prefix> {
    registry().configured.clone()
}

/// The learned NSPs (RFC 7050, PREF64, the system's), every uplink's, sorted.
pub fn learned() -> Vec<Prefix> {
    let mut v: Vec<Prefix> = registry().learned.iter().map(|e| e.prefix).collect();
    v.sort();
    v.dedup();
    v
}

/// Refuses a prefix that cannot be an NSP: IPv4, a length other than [`NSP_LENS`], host bits set.
pub fn check_prefix(p: Prefix) -> Result<Prefix, String> {
    if !p.addr.is_ipv6() {
        return Err(format!("{p} is not an IPv6 prefix"));
    }
    if !NSP_LENS.contains(&p.len) {
        return Err(format!(
            "{p}: a NAT64 prefix is a /32, /40, /48, /56, /64 or /96 (RFC 6052)"
        ));
    }
    if Prefix::new(p.addr, p.len) != p {
        return Err(format!("{p} has host bits set"));
    }
    Ok(p)
}

/// Sets the configured NSPs (`[egress] nat64_prefixes`), process-wide, replacing the last ones.
/// Every configured NSP is in force whatever is learned.
pub fn set_configured(prefixes: &[Prefix]) -> Result<(), String> {
    let mut v = prefixes
        .iter()
        .map(|p| check_prefix(*p))
        .collect::<Result<Vec<_>, _>>()?;
    if v.len() > MAX_PREFIXES {
        return Err(format!("at most {MAX_PREFIXES} NAT64 prefixes"));
    }
    v.sort();
    v.dedup();
    let mut r = registry();
    r.configured = v;
    publish(&r);
    Ok(())
}

/// Notes that the host's facts are read on uplink `signature`, whose IPv6 default gateways are
/// `gateways` (address, interface): learned prefixes are synthesized with on that uplink only,
/// and PREF64 is heard from those routers only.
pub(crate) fn on_uplink(signature: u64, gateways: &[(Ipv6Addr, u32)]) {
    let mut r = registry();
    r.on = Some(signature);
    r.gateways = gateways.to_vec();
}

/// Why a prefix named on uplink `signature` could not be held, if one could not: the uplink is
/// then unsettled ([`crate::Denied::Nat64Unsettled`]) until a round there holds everything.
pub(crate) fn unheld(signature: u64) -> Option<String> {
    registry()
        .unheld
        .iter()
        .find(|(s, _)| *s == signature)
        .map(|(_, why)| why.clone())
}

fn mark_unheld(r: &mut Registry, uplink: u64, why: String) {
    for (on, marked) in &mut r.rounds {
        if *on == uplink {
            *marked = true;
        }
    }
    if r.unheld.iter().any(|(s, w)| *s == uplink && *w == why) {
        return;
    }
    tracing::warn!(
        "network guard: {why}; IPv6 destinations are refused on this network until it clears \
         (an address under a NAT64 prefix the guard does not hold can carry a private IPv4 address)"
    );
    r.unheld.retain(|(s, _)| *s != uplink);
    r.unheld.push((uplink, why));
    if r.unheld.len() > 8 {
        r.unheld.remove(0);
    }
}

/// Marks `uplink` unsettled once its round has finished (tests).
#[cfg(test)]
pub(crate) fn unheld_after_round(uplink: u64, why: &str) {
    let t = Instant::now();
    while ON_UPLINK.lock().unwrap_or_else(|e| e.into_inner()).settled != Some(uplink)
        && t.elapsed() < Duration::from_secs(10)
    {
        std::thread::sleep(Duration::from_millis(10));
    }
    mark_unheld(&mut registry(), uplink, why.into());
}

/// Starts a round on `uplink`: what could not be held there before is asked again. Its mark
/// stays until the round ends ([`end_round`]): review round 5, bypass-3 (the mark was cleared
/// here, so for as long as the round ran, up to [`DISCOVERY_TIMEOUT`] every [`RETRY_UNSETTLED`],
/// an uplink whose DNS64 names too many prefixes was not unsettled, and an address under a
/// prefix it could not hold was admitted).
fn begin_round(uplink: u64) {
    round_begins(&mut registry(), uplink);
}

/// Ends the round on `uplink`: its mark is cleared only if nothing was marked there since it
/// began (by the round, or by a router advertisement heard meanwhile).
fn end_round(uplink: u64) {
    round_ends(&mut registry(), uplink);
}

/// [`begin_round`] on `r`.
fn round_begins(r: &mut Registry, uplink: u64) {
    r.rounds.retain(|(s, _)| *s != uplink);
    r.rounds.push((uplink, false));
    if r.rounds.len() > 8 {
        r.rounds.remove(0);
    }
}

/// [`end_round`] on `r`.
fn round_ends(r: &mut Registry, uplink: u64) {
    if let Some(i) = r.rounds.iter().position(|(s, _)| *s == uplink) {
        let (_, marked) = r.rounds.remove(i);
        if !marked {
            r.unheld.retain(|(s, _)| *s != uplink);
        }
    }
}

/// Learns what `source` names on `uplink` now (each prefix with the lifetime it is named with,
/// `None` for no limit; `Some(0)` withdraws it): what it named before and does not name now is
/// withdrawn. A source that names more than its cap ([`Source::cap`]), or a prefix that cannot be
/// held ([`MAX_LEARNED`], [`MAX_PER_UPLINK`]), makes the uplink unsettled ([`unheld`]); what fits is
/// held all the same (it only refuses more). Whether the prefixes changed (the caller then
/// publishes them: [`learn_in`]).
fn learn(
    r: &mut Registry,
    uplink: u64,
    source: Source,
    found: &[(Prefix, Option<Duration>)],
    now: Instant,
) -> bool {
    let mut named: Vec<(Prefix, Option<Duration>)> = Vec::new();
    for (p, life) in found {
        if check_prefix(*p).is_ok() && !named.iter().any(|(q, _)| q == p) {
            named.push((*p, *life));
        }
    }
    let mut changed = false;
    for e in r
        .learned
        .iter_mut()
        .filter(|e| e.uplink == uplink && e.source == source && e.active)
    {
        if !named.iter().any(|(p, _)| *p == e.prefix) {
            e.active = false;
            changed = true;
        }
    }
    if named.len() > source.cap() {
        mark_unheld(
            r,
            uplink,
            format!(
                "{source} named {} NAT64 prefixes, more than the {} the network guard believes of \
                 one source",
                named.len(),
                source.cap()
            ),
        );
        named.truncate(source.cap());
    }
    let mut new = Vec::new();
    for (p, life) in named {
        let active = life != Some(Duration::ZERO);
        let until = life.filter(|l| !l.is_zero()).map(|l| now + l);
        if let Some(e) = r
            .learned
            .iter_mut()
            .find(|e| e.uplink == uplink && e.source == source && e.prefix == p)
        {
            changed |= e.active != active || e.until != until;
            e.seen = now;
            e.until = until;
            e.active = active;
            continue;
        }
        if r.learned.iter().filter(|e| e.uplink == uplink).count() >= MAX_PER_UPLINK {
            mark_unheld(
                r,
                uplink,
                format!("{source} named NAT64 prefix {p}, past the {MAX_PER_UPLINK} the network guard holds for one network"),
            );
            continue;
        }
        if r.learned.len() >= MAX_LEARNED {
            // Room from another uplink's, the least recently seen first (never the uplink in use).
            let on = r.on;
            let victim = r
                .learned
                .iter()
                .enumerate()
                .filter(|(_, e)| e.uplink != uplink && Some(e.uplink) != on)
                .min_by_key(|(_, e)| e.seen)
                .map(|(i, _)| i);
            match victim {
                Some(i) => {
                    r.learned.remove(i);
                }
                None => {
                    mark_unheld(
                        r,
                        uplink,
                        format!("{source} named NAT64 prefix {p}, past the {MAX_LEARNED} the network guard holds"),
                    );
                    continue;
                }
            }
        }
        r.learned.push(Entry {
            prefix: p,
            uplink,
            source,
            seen: now,
            until,
            active,
        });
        if active {
            new.push(p.to_string());
        }
        changed = true;
    }
    if !new.is_empty() {
        tracing::info!(
            "network guard: {source} names NAT64 prefix {}; addresses under it are judged by the \
             IPv4 address they carry",
            new.join(", ")
        );
    }
    changed
}

/// [`learn`] on the process-wide registry `r` (locked), publishing what changed.
fn learn_in(r: &mut Registry, uplink: u64, source: Source, found: &[(Prefix, Option<Duration>)]) {
    if learn(r, uplink, source, found, Instant::now()) {
        publish(r);
    }
}

/// [`learn`] on the registry.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub(crate) fn learn_on(uplink: u64, source: Source, found: &[(Prefix, Option<Duration>)]) {
    learn_in(&mut registry(), uplink, source, found);
}

/// Learns `prefixes` on the uplink in use, each as a source of its own (tests).
#[cfg(test)]
pub(crate) fn add_learned(prefixes: &[Prefix]) {
    static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let mut r = registry();
    let uplink = r.on.unwrap_or(0);
    for p in prefixes {
        let n = N.fetch_add(1, Ordering::Relaxed);
        learn_in(&mut r, uplink, Source::Given(n), &[(*p, None)]);
    }
}

/// The NSPs revealed by one DNS server's answer for `ipv4only.arpa` (RFC 7050 §3): a prefix, of
/// an RFC 6052 length, under which the answer carries **both** `192.0.0.170` and `192.0.0.171`
/// (one address each, the u octet zero). An address carrying one alone (or a prefix only one of
/// them sits under) reveals nothing; an answer revealing more than [`MAX_PER_ANSWER`] is not
/// believed (`Err`, review round 4, bypass-1: one answer of 16 addresses filled the registry).
pub fn nsps_of_answer(answer: &[Ipv6Addr]) -> Result<Vec<Prefix>, String> {
    let mut seen: Vec<(Prefix, [bool; 2])> = Vec::new();
    for a in answer {
        for &len in &NSP_LENS {
            let (v4, u_zero) = crate::ip::nsp_extract(u128::from(*a), len);
            let Some(k) = WELL_KNOWN_V4.iter().position(|w| *w == v4) else {
                continue;
            };
            if !u_zero {
                continue;
            }
            let p = Prefix::new(IpAddr::V6(*a), len);
            match seen.iter_mut().find(|(q, _)| *q == p) {
                Some((_, has)) => has[k] = true,
                None => {
                    let mut has = [false; 2];
                    has[k] = true;
                    seen.push((p, has));
                }
            }
        }
    }
    let mut out: Vec<Prefix> = seen
        .into_iter()
        .filter(|(_, has)| has[0] && has[1])
        .map(|(p, _)| p)
        .collect();
    out.sort();
    if out.len() > MAX_PER_ANSWER {
        return Err(format!(
            "its answer for {IPV4ONLY_ARPA} reveals {} NAT64 prefixes, more than the \
             {MAX_PER_ANSWER} a DNS64 synthesizes under (RFC 7050 §3)",
            out.len()
        ));
    }
    Ok(out)
}

/// The NSP a DNS64 answer for `ipv4only.arpa` reveals: the prefix, of an RFC 6052 length, under
/// which the address carries `192.0.0.170` or `192.0.0.171` (the longest such length first, as
/// RFC 7050 §3 checks). `None` when it carries neither.
pub fn prefix_of_answer(a: Ipv6Addr) -> Option<Prefix> {
    NSP_LENS.iter().rev().find_map(|&len| {
        let (v4, u_zero) = crate::ip::nsp_extract(u128::from(a), len);
        (u_zero && WELL_KNOWN_V4.contains(&v4)).then(|| Prefix::new(IpAddr::V6(a), len))
    })
}

/// The NAT64 prefix `a` sits under: the well-known prefix, or the longest network-specific
/// prefix in force that holds it (`None` for any other address, an SIIT one included).
pub fn prefix_of(a: Ipv6Addr) -> Option<Prefix> {
    let ip = IpAddr::V6(a);
    if crate::ip::mask(ip, 96) == WELL_KNOWN_PREFIX.addr {
        return Some(WELL_KNOWN_PREFIX);
    }
    current()
        .iter()
        .filter(|n| n.addr.is_ipv6() && crate::ip::mask(ip, n.len) == n.addr)
        .max_by_key(|n| n.len)
        .copied()
}

/// `v4` as an address under the NAT64 prefix `nsp` (RFC 6052's layout for its length, the u
/// octet zero): what a DNS64 resolver would synthesize for it.
pub fn synthesize(nsp: Prefix, v4: Ipv4Addr) -> Ipv6Addr {
    match nsp_embed(nsp, Prefix::host(IpAddr::V4(v4))).addr {
        IpAddr::V6(a) => a,
        IpAddr::V4(_) => Ipv6Addr::UNSPECIFIED,
    }
}

/// The NAT64 prefixes in force for synthesizing addresses on the uplink the host's facts were
/// last read on: the configured ones, then the ones learned on that uplink that their source
/// still names and whose lifetime has not run out (the order a translator is preferred in), the
/// well-known prefix included when it is either. A prefix learned on another network, or
/// withdrawn, is never synthesized with (review round 4, parse-4); every one of them is still
/// refused as an NSP.
pub fn in_force() -> Vec<Prefix> {
    in_force_of(&registry(), Instant::now())
}

/// [`in_force`] for `r` at `now`.
fn in_force_of(r: &Registry, now: Instant) -> Vec<Prefix> {
    let mut v: Vec<Prefix> = Vec::new();
    let learned = r
        .learned
        .iter()
        .filter(|e| Some(e.uplink) == r.on && e.active && e.until.is_none_or(|u| now < u));
    for p in r
        .configured
        .iter()
        .copied()
        .chain(learned.map(|e| e.prefix))
    {
        if !v.contains(&p) {
            v.push(p);
        }
    }
    v
}

/// What [`crate::HostFacts::refused_prefixes`] adds for the NSPs in force, for a consumer that
/// knows only prefixes and may not know the NSPs (the witness broker): under each one, every
/// non-global IPv4 range and every one of `v4_refused` (the host's own IPv4 addresses and its
/// refused IPv4 prefixes), embedded with a zero u octet, and, under a /64, every address whose u
/// octet is not zero. Under a prefix shorter than /64 the u octet sits inside the embedded
/// address, so its nonzero half is no set of prefixes: the whole NSP is refused to such a
/// consumer.
pub fn embedded_refusals(v4_refused: &[Prefix]) -> Vec<Prefix> {
    let mut out = Vec::new();
    for n in current().iter() {
        if n.len < 64 {
            out.push(*n);
            continue;
        }
        if n.len == 64 {
            let IpAddr::V6(base) = n.addr else { continue };
            for i in 0..8u8 {
                // u octet bit i set, the bits before it clear.
                let x = u128::from(base) | (1u128 << (63 - u32::from(i)));
                out.push(Prefix::new(IpAddr::V6(Ipv6Addr::from(x)), 65 + i));
            }
        }
        for v4 in crate::ip::v4_not_global()
            .chain(v4_refused.iter().copied())
            .filter(|p| p.addr.is_ipv4())
        {
            out.push(nsp_embed(*n, v4));
        }
    }
    out.sort();
    out.dedup();
    out
}

/// The NSPs the host's DNS servers reveal for `ipv4only.arpa` (RFC 7050): every server is asked
/// at once (recursion desired), on this thread, within `timeout`. `Ok` with what was found (empty:
/// no DNS64) once any server answered; `Err` when none did.
pub fn discover(servers: &[IpAddr], timeout: Duration) -> Result<Vec<Prefix>, String> {
    let servers: Vec<SocketAddr> = servers.iter().map(|s| SocketAddr::new(*s, 53)).collect();
    discover_at(&servers, timeout)
}

/// [`discover`], asking each server at its own port.
pub fn discover_at(servers: &[SocketAddr], timeout: Duration) -> Result<Vec<Prefix>, String> {
    let (answers, mut errors) = ask_servers(servers, timeout);
    let mut found = Vec::new();
    let mut answered = false;
    for (server, a) in answers {
        match a {
            Ok(p) => {
                answered = true;
                found.extend(p);
            }
            Err(e) => errors.push(format!("{server}: {e}")),
        }
    }
    if answered {
        found.sort();
        found.dedup();
        Ok(found)
    } else if errors.is_empty() {
        Err("no DNS server to ask".into())
    } else {
        Err(errors.join("; "))
    }
}

/// Every server's answer: per server that answered, the NSPs its answer reveals
/// ([`nsps_of_answer`]: `Err` when it is not believed); and what failed (servers that could not
/// be asked, failed or did not answer within `timeout`).
#[allow(clippy::type_complexity)]
pub(crate) fn ask_servers(
    servers: &[SocketAddr],
    timeout: Duration,
) -> (Vec<(SocketAddr, Result<Vec<Prefix>, String>)>, Vec<String>) {
    struct Pending {
        sock: UdpSocket,
        id: u16,
        server: SocketAddr,
    }
    let mut errors = Vec::new();
    let mut pending = Vec::new();
    for &server in servers.iter().take(MAX_SERVERS) {
        let local: SocketAddr = if server.is_ipv6() {
            (Ipv6Addr::UNSPECIFIED, 0).into()
        } else {
            (Ipv4Addr::UNSPECIFIED, 0).into()
        };
        let sent = (|| -> io::Result<(UdpSocket, u16)> {
            let sock = UdpSocket::bind(local)?;
            sock.connect(server)?;
            let id = crate::public::query_id();
            let q = crate::public::build_query_with(id, IPV4ONLY_ARPA, TYPE_AAAA, CLASS_IN, true)?;
            sock.send(&q)?;
            sock.set_nonblocking(true)?;
            Ok((sock, id))
        })();
        match sent {
            Ok((sock, id)) => pending.push(Pending { sock, id, server }),
            Err(e) => errors.push(format!("{server}: {e}")),
        }
    }
    let deadline = Instant::now() + timeout;
    let mut answers = Vec::new();
    let mut buf = [0u8; 1500];
    while !pending.is_empty() && Instant::now() < deadline {
        let mut progressed = false;
        pending.retain(|p| loop {
            match p.sock.recv(&mut buf) {
                Ok(n) => match parse_aaaa(&buf[..n], p.id) {
                    None => continue,
                    Some(Ok(addrs)) => {
                        progressed = true;
                        answers.push((p.server, nsps_of_answer(&addrs)));
                        return false;
                    }
                    Some(Err(e)) => {
                        errors.push(format!("{}: {e}", p.server));
                        return false;
                    }
                },
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return true,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    errors.push(format!("{}: {e}", p.server));
                    return false;
                }
            }
        });
        if !progressed {
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    for p in &pending {
        errors.push(format!("{}: no answer within the timeout", p.server));
    }
    (answers, errors)
}

/// `None` when `m` is not an answer to query `id`; else its `AAAA` records (none for `NXDOMAIN`
/// or no data), or why it failed.
pub(crate) fn parse_aaaa(m: &[u8], id: u16) -> Option<Result<Vec<Ipv6Addr>, String>> {
    use crate::public::{skip_name, u16_at};
    if u16_at(m, 0)? != id || u16_at(m, 2)? & 0x8000 == 0 || u16_at(m, 4)? != 1 {
        return None;
    }
    let rcode = u16_at(m, 2)? & 0xf;
    match rcode {
        0 => {}
        3 => return Some(Ok(Vec::new())), // NXDOMAIN
        r => return Some(Err(format!("rcode {r}"))),
    }
    let an = u16_at(m, 6)?;
    let Some(mut off) = skip_name(m, 12).map(|o| o + 4) else {
        return Some(Err("malformed question".into()));
    };
    let mut out = Vec::new();
    for _ in 0..an {
        let Some(o) = skip_name(m, off) else {
            return Some(Err("malformed answer".into()));
        };
        let (Some(rtype), Some(rdlen)) = (u16_at(m, o), u16_at(m, o + 8)) else {
            return Some(Err("malformed answer".into()));
        };
        let start = o + 10;
        let end = start + usize::from(rdlen);
        let Some(rdata) = m.get(start..end) else {
            return Some(Err("malformed answer".into()));
        };
        off = end;
        if rtype == TYPE_AAAA {
            if let Ok(b) = <[u8; 16]>::try_from(rdata) {
                out.push(Ipv6Addr::from(b));
            }
        }
    }
    Some(Ok(out))
}

#[derive(Debug, Default)]
struct Discovery {
    attempted_at: Option<Instant>,
    running: bool,
    first_done: bool,
}

static DISCOVERY: Mutex<Discovery> = Mutex::new(Discovery {
    attempted_at: None,
    running: false,
    first_done: false,
});
static FIRST_DONE: Condvar = Condvar::new();
static WARNED: AtomicBool = AtomicBool::new(false);

/// Asks `servers` (port 53) for their NSPs and learns each answer on `uplink`, each server a
/// source of its own ([`learn`]); an answer that is not believed ([`nsps_of_answer`]) makes the
/// uplink unsettled. Whether any prefix was found; `Err` when no server answered.
fn ask_and_learn(uplink: u64, servers: &[IpAddr]) -> Result<bool, String> {
    let at: Vec<SocketAddr> = servers.iter().map(|s| SocketAddr::new(*s, 53)).collect();
    ask_and_learn_at(uplink, &at, DISCOVERY_TIMEOUT)
}

/// [`ask_and_learn`], asking each server at its own port.
fn ask_and_learn_at(uplink: u64, at: &[SocketAddr], timeout: Duration) -> Result<bool, String> {
    let (answers, errors) = ask_servers(at, timeout);
    if answers.is_empty() {
        return Err(if errors.is_empty() {
            "no DNS server to ask".into()
        } else {
            errors.join("; ")
        });
    }
    let mut found_any = false;
    let mut r = registry();
    for (server, a) in answers {
        let source = Source::Dns64(server.ip());
        match a {
            Ok(found) => {
                found_any |= !found.is_empty();
                let found: Vec<(Prefix, Option<Duration>)> =
                    found.into_iter().map(|p| (p, None)).collect();
                learn_in(&mut r, uplink, source, &found);
            }
            Err(e) => mark_unheld(&mut r, uplink, format!("{source}: {e}")),
        }
    }
    Ok(found_any)
}

/// Review round 5 (the bypass lens's suspicion): on an IPv6-only host (or one behind a CLAT), a
/// round in which the DNS servers answered and named no NAT64 prefix settles the uplink: its
/// IPv6 destinations are judged as ordinary addresses (a host that only has IPv6 is not refused
/// all of them for want of a translator). That is said once per uplink, not left silent: if the
/// network does translate under a prefix of its own that its DNS servers do not reveal, every
/// address under it carrying a private IPv4 address is admitted until it is configured.
fn warn_nothing_found(uplink: u64) {
    static LAST: Mutex<Option<u64>> = Mutex::new(None);
    let mut last = LAST.lock().unwrap_or_else(|e| e.into_inner());
    if *last == Some(uplink) {
        return;
    }
    *last = Some(uplink);
    tracing::warn!(
        "network guard: this host reaches IPv4 only through NAT64, if at all (IPv6 and no IPv4 \
         route, or IPv4 through a CLAT), and its DNS servers named no NAT64 prefix \
         ({IPV4ONLY_ARPA}, RFC 7050) nor did its router (PREF64); IPv6 destinations are judged as \
         ordinary addresses. If this network translates to IPv4 under a prefix of its own, name \
         it in [egress] nat64_prefixes (an address under it can carry a private IPv4 address); \
         asking again every {}s",
        RETRY_UNSETTLED.as_secs()
    );
}

fn warn_discovery(e: &str) {
    if !WARNED.swap(true, Ordering::Relaxed) {
        tracing::warn!(
            "network guard: could not ask this host's DNS servers for its NAT64 prefix \
             (RFC 7050, {IPV4ONLY_ARPA} AAAA: {e}). If this host reaches IPv4 through \
             NAT64 under a prefix of its own network, name it in [egress] \
             nat64_prefixes; retrying in the background"
        );
    } else {
        tracing::debug!("network guard: NAT64 prefix discovery: {e}");
    }
}

fn run_discovery() {
    let servers = crate::system_resolvers();
    let uplink = registry().on.unwrap_or(0);
    if let Err(e) = ask_and_learn(uplink, &servers) {
        warn_discovery(&e);
    }
    let mut d = DISCOVERY.lock().unwrap_or_else(|e| e.into_inner());
    d.running = false;
    d.first_done = true;
    drop(d);
    FIRST_DONE.notify_all();
}

/// Learns the NSPs, process-wide, when they are due: the first call asks on this thread (at most
/// [`DISCOVERY_TIMEOUT`]), a call during that first round waits for it, and later calls start a
/// background round once the last is [`DISCOVERY_TTL`] old. Not per uplink: the host's facts
/// use `ensure_discovered_on` since the Linux application (on macOS since review round 3); this
/// stays for callers that know no uplink.
pub fn ensure_discovered() {
    let mut d = DISCOVERY.lock().unwrap_or_else(|e| e.into_inner());
    if d.attempted_at.is_none() && !d.running {
        d.running = true;
        d.attempted_at = Some(Instant::now());
        drop(d);
        run_discovery();
    } else if !d.first_done {
        let deadline = Instant::now() + DISCOVERY_TIMEOUT + Duration::from_secs(1);
        while !d.first_done {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            d = FIRST_DONE
                .wait_timeout(d, left)
                .unwrap_or_else(|e| e.into_inner())
                .0;
        }
    } else if !d.running && d.attempted_at.is_none_or(|t| t.elapsed() >= DISCOVERY_TTL) {
        d.running = true;
        d.attempted_at = Some(Instant::now());
        if std::thread::Builder::new()
            .name("netguard-nat64".into())
            .spawn(run_discovery)
            .is_err()
        {
            d.running = false;
        }
    }
}

/// how soon a round that failed, or found no prefix, is asked again while the host has
/// IPv6 and no IPv4 route (where an unlearned prefix matters: review round 3, bypass-1).
pub const RETRY_UNSETTLED: Duration = Duration::from_secs(15);

/// the uplink discovery runs for: the facts' uplink signature (which changes with the
/// default routes, the internet interfaces and the networks the configuration daemon says the
/// services are on) and whether the host routes IPv4 and IPv6 (`[IPv4, IPv6]`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Uplink {
    pub signature: u64,
    pub routed: [bool; 2],
    /// The host's IPv4 goes out through a CLAT (464XLAT, RFC 6877: [`clat_in_use`]), which
    /// translates it to IPv6 through the network's NAT64: an IPv6-only network all the same.
    pub clat: bool,
}

impl Uplink {
    /// IPv6 and no IPv4 route, or IPv4 only through a CLAT: connections to IPv4 go through
    /// NAT64, if anywhere.
    pub fn ipv6_only(&self) -> bool {
        self.routed[1] && (!self.routed[0] || self.clat)
    }

    /// Whether a host on this uplink refuses IPv6 destinations while discovery is not `settled`
    /// ([`ensure_discovered_on`]): only an IPv6-only one ([`Self::ipv6_only`]). Review round 5,
    /// bypass-4: a host whose IPv4 default goes through a CLAT is an IPv6-only host behind NAT64
    /// that looked dual-stack, so `<NSP>::10.0.0.1` under a prefix not learned yet was admitted
    /// there; it now counts as IPv6-only. A dual-stack host is still not refused for it (its IPv4
    /// goes out natively; a NAT64 on a dual-stack network is rare, and refusing every IPv6
    /// destination there for each new uplink's round was judged not worth it: see
    /// docs/netguard-hardening.md, review round 5).
    pub fn refuses_ipv6(&self, settled: bool) -> bool {
        !settled && self.ipv6_only()
    }
}

/// Whether this host's IPv4 goes out through a CLAT (464XLAT, RFC 6877): an IPv4 address in the
/// IPv4 Service Continuity Prefix `192.0.0.0/29` (RFC 7335; Android's and macOS's CLAT, clatd),
/// or an IPv4 default route out of an interface a CLAT names (`clat*`, Android's `v4-*`). On
/// macOS the configuration daemon's CLAT also numbers its interface from `192.0.0.0/29`.
pub(crate) fn clat_in_use(
    addresses: &[IpAddr],
    v4_default_interfaces: &[String],
) -> bool {
    let service_continuity = Prefix::new(IpAddr::V4(Ipv4Addr::new(192, 0, 0, 0)), 29);
    addresses
        .iter()
        .any(|a| a.is_ipv4() && crate::ip::mask(*a, 29) == service_continuity.addr)
        || v4_default_interfaces
            .iter()
            .any(|n| n.starts_with("clat") || n.starts_with("v4-"))
}

/// discovery per uplink (see [`ensure_discovered_on`]).
#[derive(Debug)]
struct OnUplink {
    /// The uplink the latest caller is on.
    uplink: Option<Uplink>,
    /// The uplink signature of the latest round that finished on the uplink the host was on
    /// then.
    settled: Option<u64>,
    running: bool,
    first_done: bool,
    attempted_at: Option<Instant>,
    /// Whether the latest round failed, or found no prefix.
    found_nothing: bool,
}

/// signalled when the first round finishes.
static ON_UPLINK_DONE: Condvar = Condvar::new();

static ON_UPLINK: Mutex<OnUplink> = Mutex::new(OnUplink {
    uplink: None,
    settled: None,
    running: false,
    first_done: false,
    attempted_at: None,
    found_nothing: false,
});

/// what [`ensure_discovered_on`] does next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Next {
    /// Ask on this thread (the first round).
    AskHere,
    /// Wait for the first round, running on another thread.
    WaitFirst,
    /// Start a round in the background.
    AskInBackground,
    /// Nothing.
    Nothing,
}

/// the decision [`ensure_discovered_on`] makes for a caller on `up` at `now`, from the
/// state `d` (updated: the uplink, and a round marked running when one starts). A round starts
/// when none ran yet (on the caller's thread), when the uplink signature changed (review round
/// 3, bypass-1: a new network's prefix is learned at once, not up to [`DISCOVERY_TTL`] later),
/// when the last round is [`DISCOVERY_TTL`] old, and, on a host with IPv6 and no IPv4 route,
/// [`RETRY_UNSETTLED`] after a round that failed or found nothing, or that finished on another
/// uplink. One round runs at a time; a round that finishes after the uplink changed starts
/// another.
fn next_on(d: &mut OnUplink, up: Uplink, now: Instant) -> Next {
    let changed = d.uplink.is_some_and(|u| u.signature != up.signature);
    d.uplink = Some(up);
    if d.attempted_at.is_none() && !d.running {
        d.running = true;
        d.attempted_at = Some(now);
        return Next::AskHere;
    }
    if !d.first_done {
        return Next::WaitFirst;
    }
    if d.running {
        return Next::Nothing;
    }
    let since = d
        .attempted_at
        .map_or(Duration::MAX, |t| now.saturating_duration_since(t));
    let unsettled = d.found_nothing || d.settled != Some(up.signature);
    if changed
        || since >= DISCOVERY_TTL
        || (up.ipv6_only() && unsettled && since >= RETRY_UNSETTLED)
    {
        d.running = true;
        d.attempted_at = Some(now);
        return Next::AskInBackground;
    }
    Next::Nothing
}

/// the DNS servers a round asks, in order (review round 3, bypass-2): the active ones
/// first (`active`, the configuration daemon's global resolvers, in its order), then the rest of
/// `all`; when the host routes one family only, that family's servers alone (a server of an
/// unrouted family cannot be reached), so on a host with IPv6 and no IPv4 route a DNS64 that
/// answers only over IPv6 is never left behind IPv4 servers that cannot answer. At most
/// [`MAX_SERVERS`], cut after this ordering.
pub(crate) fn order_servers<A: Copy + PartialEq>(
    active: &[A],
    all: &[A],
    routed: [bool; 2],
    is_v6: impl Fn(&A) -> bool,
) -> Vec<A> {
    let reachable = |a: &A| routed == [false, false] || routed[usize::from(is_v6(a))];
    let mut out: Vec<A> = Vec::new();
    for a in active.iter().chain(all) {
        if reachable(a) && !out.contains(a) {
            out.push(*a);
        }
    }
    // IPv6 first on a host without an IPv4 route (when there is nothing to skip: no route at all).
    if !routed[0] {
        out.sort_by_key(|a| !is_v6(a));
    }
    out.truncate(MAX_SERVERS);
    out
}

/// one round on uplink `up`: the configuration daemon's NAT64 prefixes, then the RFC 7050
/// query to the servers [`order_servers`] picks. Its prefixes are learned; the state notes that
/// it finished, on which uplink, and whether it found any.
fn round_on(up: Uplink) {
    begin_round(up.signature);
    let mut found_any = false;
    match system_prefixes(up.signature) {
        Ok(sources) => {
            let mut r = registry();
            for (source, found) in sources {
                found_any |= found.iter().any(|(_, l)| *l != Some(Duration::ZERO));
                learn_in(&mut r, up.signature, source, &found);
            }
        }
        Err(e) => tracing::debug!("network guard: NAT64 prefixes the system knows: {e}"),
    }
    let servers = crate::facts::read_system_resolvers().and_then(|all| {
        let active = active_servers()?;
        Ok(order_servers(&active, &all, up.routed, IpAddr::is_ipv6))
    });
    let result = servers
        .map_err(|e| format!("this host's DNS servers could not be read: {e}"))
        .and_then(|s| ask_and_learn(up.signature, &s));
    match result {
        Ok(found) => found_any |= found,
        Err(e) => warn_discovery(&e),
    }
    end_round(up.signature);
    if up.ipv6_only() && !found_any && configured().is_empty() {
        warn_nothing_found(up.signature);
    }
    let mut d = ON_UPLINK.lock().unwrap_or_else(|e| e.into_inner());
    finished(&mut d, up, found_any);
    let again = d.running.then_some(d.uplink).flatten();
    drop(d);
    ON_UPLINK_DONE.notify_all();
    if let Some(next) = again {
        spawn_round(next);
    }
}

/// What the system itself names as NAT64 prefixes on uplink `uplink`, per source, each with the
/// lifetime it is named with, learned with each round: macOS, the configuration daemon's
/// per-interface NAT64 state (its PLAT discovery, RFC 7050, and the PREF64 option a router
/// announces, RFC 8781); Linux, the PREF64 options of the router advertisements the kernel
/// processed since the guard started listening, from the uplink's IPv6 default gateways alone
/// ([`pref64`]); elsewhere none.
#[cfg(target_os = "macos")]
#[allow(clippy::type_complexity)]
fn system_prefixes(_uplink: u64) -> io::Result<Vec<(Source, Vec<(Prefix, Option<Duration>)>)>> {
    let found = crate::facts::macos_dns::nat64_prefixes()?;
    Ok(vec![(
        Source::System,
        found.into_iter().map(|p| (p, None)).collect(),
    )])
}

/// See the macOS one.
#[cfg(any(target_os = "linux", target_os = "android"))]
#[allow(clippy::type_complexity)]
fn system_prefixes(uplink: u64) -> io::Result<Vec<(Source, Vec<(Prefix, Option<Duration>)>)>> {
    pref64::start();
    let gateways = {
        let r = registry();
        if r.on == Some(uplink) {
            r.gateways.clone()
        } else {
            Vec::new()
        }
    };
    Ok(pref64::from_gateways(uplink, &gateways, Instant::now()))
}

/// See the macOS one.
#[cfg(not(any(target_os = "linux", target_os = "android", target_os = "macos")))]
#[allow(clippy::type_complexity)]
fn system_prefixes(_uplink: u64) -> io::Result<Vec<(Source, Vec<(Prefix, Option<Duration>)>)>> {
    Ok(Vec::new())
}

/// The DNS servers in use, in the order the system asks them ([`order_servers`] asks them
/// first): macOS, the configuration daemon's global resolvers; elsewhere the `nameserver` lines
/// of [`crate::facts::RESOLV_CONF_PATHS`] in file order (`/etc/resolv.conf` first: glibc and
/// musl ask its servers in that order; a stub such as systemd-resolved's 127.0.0.53 forwards to
/// the upstream servers the later files name).
#[cfg(target_os = "macos")]
fn active_servers() -> io::Result<Vec<IpAddr>> {
    crate::facts::macos_dns::global_servers()
}

/// See the macOS one.
#[cfg(not(target_os = "macos"))]
fn active_servers() -> io::Result<Vec<IpAddr>> {
    Ok(crate::facts::RESOLV_CONF_PATHS
        .iter()
        .filter_map(|p| std::fs::read_to_string(p).ok())
        .flat_map(|t| crate::facts::parse_nameservers(&t))
        .collect())
}

/// Linux: the PREF64 option (RFC 8781) of router advertisements, as the kernel hands them to
/// userspace. The kernel passes an RA's "user options" (RDNSS, DNSSL, captive portal, PREF64:
/// `ndisc_is_useropt`, Linux 5.8 and later for PREF64) to the `RTNLGRP_ND_USEROPT` netlink
/// group as `RTM_NEWNDUSEROPT` messages, and any process may join that group (rtnetlink is
/// `NL_CFG_F_NONROOT_RECV`). There is no table to read: only advertisements that arrive while
/// the listener runs are seen (routers repeat them every few minutes, RFC 4861's
/// `MaxRtrAdvInterval` 600 s at most by default), so the first round on a new network may not
/// have it yet and RFC 7050 discovery still runs. Only advertisements the kernel processes are
/// seen: on a host where a userspace RA client handles them instead (systemd-networkd's own
/// `IPv6AcceptRA`, NetworkManager), the kernel's `accept_ra` is 0 and nothing arrives;
/// systemd-networkd keeps the PREF64 it saw to itself (`networkctl status`, its varlink and
/// D-Bus interfaces), NetworkManager likewise, and neither writes it anywhere an unprivileged
/// process could read without their APIs: not read (documented).
///
/// Review round 4 (bypass-1, cross-1): any host on the link can send a router advertisement, so
/// what is heard is kept per sender ([`Heard`]) and learned only from an IPv6 default route's
/// gateway, on that route's interface (the message's `NDUSEROPT_SRCADDR` and ifindex), at most
/// [`MAX_PER_ROUTER`] per router (more makes the uplink unsettled), with the lifetime the option
/// names (0 withdraws it: it is no longer synthesized with, and stays refused).
#[cfg(any(target_os = "linux", target_os = "android"))]
pub(crate) mod pref64 {
    use std::io;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::sync::Mutex;
    use std::time::Instant;

    use super::{Announced, Heard};

    /// `RTNLGRP_ND_USEROPT` (<linux/rtnetlink.h>).
    const RTNLGRP_ND_USEROPT: u32 = 20;
    const SOL_NETLINK: libc::c_int = 270;
    const NETLINK_ADD_MEMBERSHIP: libc::c_int = 1;

    /// Whether the listener was started, and what it heard.
    static STATE: Mutex<(bool, Heard)> = Mutex::new((false, Heard::new()));

    /// Starts the listener once per process, on a thread of its own; a listener that cannot
    /// start (no netlink, a kernel without the group) is logged once and not tried again.
    pub(crate) fn start() {
        let mut s = STATE.lock().unwrap_or_else(|e| e.into_inner());
        if s.0 {
            return;
        }
        s.0 = true;
        drop(s);
        let sock = match subscribe() {
            Ok(sock) => sock,
            Err(e) => {
                tracing::debug!(
                    "network guard: cannot listen for router advertisements' NAT64 prefixes \
                     (RTNLGRP_ND_USEROPT): {e}"
                );
                return;
            }
        };
        let spawned = std::thread::Builder::new()
            .name("netguard-pref64".into())
            .spawn(move || {
                let mut buf = vec![0u8; 64 * 1024];
                let e = listen(|| receive(&sock, &mut buf));
                tracing::debug!("network guard: the PREF64 listener stopped: {e}");
            });
        if let Err(e) = spawned {
            tracing::debug!("network guard: the PREF64 listener did not start: {e}");
        }
    }

    /// Whether the listener was started (tests).
    #[cfg(test)]
    pub(crate) fn started() -> bool {
        STATE.lock().unwrap_or_else(|e| e.into_inner()).0
    }

    /// Every PREF64 prefix heard so far, from any sender (tests).
    #[cfg(test)]
    pub(crate) fn seen() -> Vec<crate::ip::Prefix> {
        STATE.lock().unwrap_or_else(|e| e.into_inner()).1.prefixes()
    }

    /// What the gateways `gateways` announce now, per gateway ([`Heard::named_by`]).
    #[allow(clippy::type_complexity)]
    pub(crate) fn from_gateways(
        uplink: u64,
        gateways: &[(std::net::Ipv6Addr, u32)],
        now: Instant,
    ) -> Vec<(
        super::Source,
        Vec<(crate::ip::Prefix, Option<std::time::Duration>)>,
    )> {
        let mut s = STATE.lock().unwrap_or_else(|e| e.into_inner());
        s.1.on(Some(uplink));
        s.1.prune(now);
        s.1.named_by(gateways, now)
    }

    /// A route netlink socket in the `RTNLGRP_ND_USEROPT` group.
    pub(crate) fn subscribe() -> io::Result<OwnedFd> {
        // SAFETY: plain socket(2); the fd is owned by the OwnedFd from here on.
        let fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                libc::NETLINK_ROUTE,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `fd` was just created and is owned here alone.
        let sock = unsafe { OwnedFd::from_raw_fd(fd) };
        // SAFETY: a zeroed sockaddr_nl binds to a port the kernel picks, no groups yet.
        let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        addr.nl_family = libc::AF_NETLINK as libc::sa_family_t;
        // SAFETY: `addr` is valid for its size.
        let rc = unsafe {
            libc::bind(
                sock.as_raw_fd(),
                (&addr as *const libc::sockaddr_nl).cast(),
                std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        let group = RTNLGRP_ND_USEROPT;
        // SAFETY: `group` is a valid u32 for the size given.
        let rc = unsafe {
            libc::setsockopt(
                sock.as_raw_fd(),
                SOL_NETLINK,
                NETLINK_ADD_MEMBERSHIP,
                (&group as *const u32).cast(),
                std::mem::size_of::<u32>() as libc::socklen_t,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(sock)
    }

    /// Reads with `next` until it fails other than by `ENOBUFS` (the group's messages overflowed
    /// the socket; the next ones still come) or `EINTR`, hearing every PREF64 option; the error
    /// it stopped on.
    pub(crate) fn listen(mut next: impl FnMut() -> io::Result<Vec<Announced>>) -> io::Error {
        loop {
            match next() {
                Ok(found) if !found.is_empty() => hear(&found),
                Ok(_) => {}
                Err(e) if e.raw_os_error() == Some(libc::ENOBUFS) => {}
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return e,
            }
        }
    }

    /// The PREF64 options in the next datagram the kernel sends `sock` (blocking).
    pub(crate) fn receive(sock: &OwnedFd, buf: &mut [u8]) -> io::Result<Vec<Announced>> {
        // SAFETY: a zeroed sockaddr_nl is valid to be overwritten by recvfrom.
        let mut from: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        let mut from_len = std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t;
        // SAFETY: `buf` and `from` are valid for the lengths given.
        let n = unsafe {
            libc::recvfrom(
                sock.as_raw_fd(),
                buf.as_mut_ptr().cast(),
                buf.len(),
                0,
                (&mut from as *mut libc::sockaddr_nl).cast(),
                &mut from_len,
            )
        };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(super::pref64_from(from.nl_pid, &buf[..n as usize]))
    }

    /// Hears `found`; what a gateway of the uplink in use announced is learned at once.
    pub(crate) fn hear(found: &[Announced]) {
        let (on, gateways) = {
            let r = super::registry();
            (r.on, r.gateways.clone())
        };
        let now = Instant::now();
        let mut s = STATE.lock().unwrap_or_else(|e| e.into_inner());
        s.1.on(on);
        s.1.hear(found, &gateways, now);
        let from: Vec<(std::net::Ipv6Addr, u32)> = gateways
            .iter()
            .copied()
            .filter(|g| {
                found
                    .iter()
                    .any(|a| a.router == Some(g.0) && a.ifindex == g.1)
            })
            .collect();
        let learn = s.1.named_by(&from, now);
        drop(s);
        if let Some(on) = on {
            for (source, prefixes) in learn {
                super::learn_on(on, source, &prefixes);
            }
        }
    }
}

/// One PREF64 option (RFC 8781) of a router advertisement: its prefix, its lifetime, the
/// interface it came in on and the router that sent it (`NDUSEROPT_SRCADDR`; `None` when the
/// message did not say, which is never believed).
#[cfg(any(test, target_os = "linux", target_os = "android"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Announced {
    pub prefix: Prefix,
    pub lifetime: Duration,
    pub ifindex: u32,
    pub router: Option<Ipv6Addr>,
}

/// Most routers whose PREF64 options are kept; a new one takes the place of the least recently
/// heard that is not a default gateway.
#[cfg(any(test, target_os = "linux", target_os = "android"))]
const MAX_ROUTERS: usize = 16;

/// The PREF64 options heard, per router and interface, on each uplink: at most
/// [`MAX_PER_ROUTER`] + 1 live prefixes each (one more than is believed, so a router that names
/// more is seen to), from at most [`MAX_ROUTERS`] routers (review round 4, bypass-1: one sender of
/// 16 options filled the old process-wide list).
///
/// Review round 5 (cross-1, bypass-2, parse-2): a prefix withdrawn (lifetime 0) or whose
/// lifetime ran out is dropped here, so it is neither named nor counted against the cap any
/// more, and a newer one takes its room; the registry keeps it refused all the same ([`learn`]
/// withdraws what a source stops naming). Before, every prefix a gateway ever named stayed here
/// for the process's life: five renumberings, or one forged advertisement of five, left its
/// uplink unsettled for good. Review round 5 (parse-3): each entry is tied to the uplink it was
/// heard on ([`Self::on`]): another network's router of the same address on the same interface
/// (`fe80::1` is common) names nothing on this one.
#[cfg(any(test, target_os = "linux", target_os = "android"))]
#[derive(Debug, Default)]
pub(crate) struct Heard {
    /// (router, interface, prefix, lifetime, when heard, uplink heard on)
    entries: Vec<(Ipv6Addr, u32, Prefix, Duration, Instant, Option<u64>)>,
    /// The uplink what is heard now is heard on.
    uplink: Option<u64>,
}

#[cfg(any(test, target_os = "linux", target_os = "android"))]
impl Heard {
    pub(crate) const fn new() -> Self {
        Heard {
            entries: Vec::new(),
            uplink: None,
        }
    }

    /// Every prefix heard (tests).
    #[cfg(test)]
    pub(crate) fn prefixes(&self) -> Vec<Prefix> {
        let mut v: Vec<Prefix> = self.entries.iter().map(|e| e.2).collect();
        v.sort();
        v.dedup();
        v
    }

    /// Notes that what is heard from now on, and what [`Self::named_by`] reads, is on `uplink`.
    pub(crate) fn on(&mut self, uplink: Option<u64>) {
        self.uplink = uplink;
    }

    /// Drops every entry whose lifetime has run out at `now`.
    pub(crate) fn prune(&mut self, now: Instant) {
        self.entries
            .retain(|e| now.saturating_duration_since(e.4) < e.3);
    }

    /// Notes `found` at `now`, on the uplink in use ([`Self::on`]): a prefix announced with
    /// lifetime 0 is withdrawn (dropped); `gateways` are never pushed out by other routers.
    pub(crate) fn hear(&mut self, found: &[Announced], gateways: &[(Ipv6Addr, u32)], now: Instant) {
        self.prune(now);
        let uplink = self.uplink;
        for a in found {
            let Some(router) = a.router else { continue };
            let key = (router, a.ifindex, uplink);
            let of_key = |e: &(Ipv6Addr, u32, Prefix, Duration, Instant, Option<u64>)| {
                (e.0, e.1, e.5) == key
            };
            if a.lifetime.is_zero() {
                self.entries.retain(|e| !(of_key(e) && e.2 == a.prefix));
                continue;
            }
            if let Some(e) = self
                .entries
                .iter_mut()
                .find(|e| of_key(e) && e.2 == a.prefix)
            {
                e.3 = a.lifetime;
                e.4 = now;
                continue;
            }
            if self.entries.iter().filter(|e| of_key(e)).count() > MAX_PER_ROUTER {
                // Already one more live than is believed: the router is seen to name too many.
                continue;
            }
            let mut routers: Vec<(Ipv6Addr, u32, Option<u64>)> =
                self.entries.iter().map(|e| (e.0, e.1, e.5)).collect();
            routers.sort();
            routers.dedup();
            if !routers.contains(&key) && routers.len() >= MAX_ROUTERS {
                let last_heard = |r: &(Ipv6Addr, u32, Option<u64>)| {
                    self.entries
                        .iter()
                        .filter(|e| (e.0, e.1, e.5) == *r)
                        .map(|e| e.4)
                        .max()
                };
                let Some(victim) = routers
                    .iter()
                    .filter(|r| !(r.2 == uplink && gateways.contains(&(r.0, r.1))))
                    .min_by_key(|r| last_heard(r))
                    .copied()
                else {
                    continue;
                };
                self.entries.retain(|e| (e.0, e.1, e.5) != victim);
            }
            self.entries
                .push((router, a.ifindex, a.prefix, a.lifetime, now, uplink));
        }
    }

    /// What each of `gateways` announces at `now` on the uplink in use ([`Self::on`]): every
    /// prefix it named there whose lifetime has not run out, with what is left of it, as a
    /// source of its own (one with nothing live names nothing, which withdraws what it named
    /// before).
    #[allow(clippy::type_complexity)]
    pub(crate) fn named_by(
        &self,
        gateways: &[(Ipv6Addr, u32)],
        now: Instant,
    ) -> Vec<(Source, Vec<(Prefix, Option<Duration>)>)> {
        gateways
            .iter()
            .map(|&(router, ifindex)| {
                let named = self
                    .entries
                    .iter()
                    .filter(|e| e.0 == router && e.1 == ifindex && e.5 == self.uplink)
                    .filter_map(|e| {
                        let left = e.3.saturating_sub(now.saturating_duration_since(e.4));
                        (!left.is_zero()).then_some((e.2, Some(left)))
                    })
                    .collect();
                (Source::Pref64 { router, ifindex }, named)
            })
            .collect()
    }
}

/// `RTM_NEWNDUSEROPT` (<linux/rtnetlink.h>).
#[cfg(any(test, target_os = "linux", target_os = "android"))]
const RTM_NEWNDUSEROPT: u16 = 68;
/// The PREF64 option's type (RFC 8781 §4).
#[cfg(any(test, target_os = "linux", target_os = "android"))]
const ND_OPT_PREF64: u8 = 38;
/// `NDUSEROPT_SRCADDR` (<linux/rtnetlink.h>): the advertisement's source address, an attribute
/// after the options.
#[cfg(any(test, target_os = "linux", target_os = "android"))]
const NDUSEROPT_SRCADDR: u16 = 1;

/// The PREF64 options in a datagram from netlink port `nl_pid`: none unless it is the kernel's
/// (port 0), else [`pref64_of_datagram`].
#[cfg(any(test, target_os = "linux", target_os = "android"))]
pub(crate) fn pref64_from(nl_pid: u32, b: &[u8]) -> Vec<Announced> {
    if nl_pid != 0 {
        // Not from the kernel.
        return Vec::new();
    }
    pref64_of_datagram(b)
}

/// The PREF64 options (RFC 8781) in one datagram of `RTNLGRP_ND_USEROPT` messages: each
/// `RTM_NEWNDUSEROPT` message (`struct nduseroptmsg`, 16 bytes: family, pad, `nduseropt_opts_len`,
/// ifindex, ICMP type and code, pads; then the options, then attributes, `NDUSEROPT_SRCADDR` the
/// router's address) of an IPv6 router advertisement (ICMPv6 type 134, code 0), each ND option
/// within `nduseropt_opts_len` read by its length (8-byte units); a PREF64 option of length 2
/// gives its scaled lifetime (13 bits, in units of 8 s) and the 96 bits after it, cut to the
/// length its PLC names (0: /96, 1: /64, 2: /56, 3: /48, 4: /40, 5: /32; other PLCs are invalid
/// and skipped, as RFC 8781 §4 says). Anything malformed ends the reading of that message.
#[cfg(any(test, target_os = "linux", target_os = "android"))]
pub(crate) fn pref64_of_datagram(mut b: &[u8]) -> Vec<Announced> {
    let u16_at = |b: &[u8], i: usize| b.get(i..i + 2).map(|x| u16::from_ne_bytes([x[0], x[1]]));
    let u32_at = |b: &[u8], i: usize| {
        b.get(i..i + 4)
            .map(|x| u32::from_ne_bytes([x[0], x[1], x[2], x[3]]))
    };
    let mut out = Vec::new();
    while let (Some(len), Some(ty)) = (u32_at(b, 0), u16_at(b, 4)) {
        let len = len as usize;
        if len < 16 || len > b.len() {
            break;
        }
        let payload = &b[16..len];
        if ty == RTM_NEWNDUSEROPT && payload.len() >= 16 {
            let family = payload[0];
            let opts_len = usize::from(u16_at(payload, 2).unwrap_or(0));
            let ifindex = u32_at(payload, 4).unwrap_or(0);
            let (icmp_type, icmp_code) = (payload[8], payload[9]);
            if i32::from(family) == AF_INET6 && icmp_type == 134 && icmp_code == 0 {
                let router = router_of(payload.get(16 + opts_len..).unwrap_or(&[]));
                let mut opts = payload.get(16..16 + opts_len).unwrap_or(&[]);
                while opts.len() >= 2 {
                    let olen = usize::from(opts[1]) * 8;
                    if olen == 0 || olen > opts.len() {
                        break;
                    }
                    if opts[0] == ND_OPT_PREF64 && olen == 16 {
                        let word = u16::from_be_bytes([opts[2], opts[3]]);
                        let plen = match word & 0x7 {
                            0 => Some(96),
                            1 => Some(64),
                            2 => Some(56),
                            3 => Some(48),
                            4 => Some(40),
                            5 => Some(32),
                            _ => None,
                        };
                        if let Some(plen) = plen {
                            let mut a = [0u8; 16];
                            a[..12].copy_from_slice(&opts[4..16]);
                            out.push(Announced {
                                prefix: Prefix::new(IpAddr::V6(Ipv6Addr::from(a)), plen),
                                lifetime: Duration::from_secs(u64::from(word >> 3) * 8),
                                ifindex,
                                router,
                            });
                        }
                    }
                    opts = &opts[olen..];
                }
            }
        }
        b = &b[((len + 3) & !3).min(b.len())..];
    }
    out
}

/// The `NDUSEROPT_SRCADDR` attribute among the route attributes `b` (after a message's options).
#[cfg(any(test, target_os = "linux", target_os = "android"))]
fn router_of(mut b: &[u8]) -> Option<Ipv6Addr> {
    while b.len() >= 4 {
        let len = usize::from(u16::from_ne_bytes([b[0], b[1]]));
        let ty = u16::from_ne_bytes([b[2], b[3]]);
        if len < 4 || len > b.len() {
            return None;
        }
        if ty == NDUSEROPT_SRCADDR && len == 20 {
            let a: [u8; 16] = b[4..20].try_into().ok()?;
            return Some(Ipv6Addr::from(a));
        }
        b = &b[((len + 3) & !3).min(b.len())..];
    }
    None
}

/// `AF_INET6` as the kernel numbers it on Linux (10), for [`pref64_of_datagram`], which tests
/// read on every platform.
#[cfg(any(test, target_os = "linux", target_os = "android"))]
const AF_INET6: i32 = 10;

/// Notes in `d` that a round on `up` finished (`found_any`: it found a prefix); when the
/// uplink changed while it ran, a round on the new one is marked running (the caller starts it).
fn finished(d: &mut OnUplink, up: Uplink, found_any: bool) {
    d.running = false;
    d.first_done = true;
    d.found_nothing = !found_any;
    let now_on = d.uplink.unwrap_or(up);
    if now_on.signature == up.signature {
        d.settled = Some(up.signature);
    } else {
        d.running = true;
        d.attempted_at = Some(Instant::now());
    }
}

fn spawn_round(up: Uplink) {
    if std::thread::Builder::new()
        .name("netguard-nat64".into())
        .spawn(move || round_on(up))
        .is_err()
    {
        let mut d = ON_UPLINK.lock().unwrap_or_else(|e| e.into_inner());
        d.running = false;
    }
}

/// learns the NSPs for a host on uplink `up` when they are due ([`next_on`]): the first
/// call asks on this thread (at most [`DISCOVERY_TIMEOUT`]), a call during that first round waits
/// for it, later rounds run in the background. Whether discovery is settled for `up`: false while
/// the first round on a new uplink signature has not finished. The facts then refuse IPv6
/// destinations on a host with IPv6 and no IPv4 route ([`crate::Denied::Nat64Unsettled`]): until
/// the new network's prefix is known, an address under it can carry a private IPv4 address.
pub(crate) fn ensure_discovered_on(up: Uplink) -> bool {
    let mut d = ON_UPLINK.lock().unwrap_or_else(|e| e.into_inner());
    match next_on(&mut d, up, Instant::now()) {
        Next::AskHere => {
            drop(d);
            round_on(up);
            d = ON_UPLINK.lock().unwrap_or_else(|e| e.into_inner());
        }
        Next::WaitFirst => {
            let deadline = Instant::now() + DISCOVERY_TIMEOUT + Duration::from_secs(1);
            while !d.first_done {
                let left = deadline.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    break;
                }
                d = ON_UPLINK_DONE
                    .wait_timeout(d, left)
                    .unwrap_or_else(|e| e.into_inner())
                    .0;
            }
        }
        Next::AskInBackground => spawn_round(up),
        Next::Nothing => {}
    }
    d.settled == Some(up.signature)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip6(s: &str) -> Ipv6Addr {
        s.parse().unwrap()
    }

    fn p(s: &str) -> Prefix {
        s.parse().unwrap()
    }

    #[test]
    fn nsps_are_checked() {
        for ok in [
            "64:ff9b::/96",
            "2001:db8::/32",
            "2001:db8:100::/40",
            "2001:db8:122:344::/64",
        ] {
            assert_eq!(check_prefix(p(ok)), Ok(p(ok)), "{ok}");
        }
        for bad in ["2001:db8::/33", "2001:db8::/128", "10.0.0.0/8", "::/0"] {
            assert!(check_prefix(p(bad)).is_err(), "{bad}");
        }
    }

    /// RFC 7050: the NSP is where 192.0.0.170 or .171 sits in the synthesized answer, at each
    /// RFC 6052 length (RFC 6052 §2.4's layouts).
    #[test]
    fn the_prefix_is_where_the_well_known_address_sits() {
        for (answer, nsp) in [
            ("64:ff9b::c000:aa", "64:ff9b::/96"),
            ("2001:db8:122:344::192.0.0.171", "2001:db8:122:344::/96"),
            ("2001:db8:122:344:c0:0:aa00:0", "2001:db8:122:344::/64"),
            ("2001:db8:122:3c0:0:aa::", "2001:db8:122:300::/56"),
            ("2001:db8:122:c000:0:aa00::", "2001:db8:122::/48"),
            ("2001:db8:1c0:0:aa::", "2001:db8:100::/40"),
            ("2001:db8:c000:aa::", "2001:db8::/32"),
        ] {
            assert_eq!(prefix_of_answer(ip6(answer)), Some(p(nsp)), "{answer}");
        }
        assert_eq!(prefix_of_answer(ip6("2606:4700::1111")), None);
    }

    /// An address is under the well-known prefix, under a network-specific one in force, or
    /// under none; synthesizing an IPv4 address under a prefix and reading it back agree.
    #[test]
    fn the_prefix_an_address_is_under_and_synthesis() {
        assert_eq!(prefix_of(ip6("64:ff9b::101:101")), Some(WELL_KNOWN_PREFIX));
        assert_eq!(prefix_of(ip6("64:ff9b:1::101:101")), None);
        assert_eq!(prefix_of(ip6("::ffff:0:101:101")), None);
        assert_eq!(prefix_of(ip6("2606:4700::1111")), None);
        assert_eq!(
            synthesize(WELL_KNOWN_PREFIX, Ipv4Addr::new(1, 1, 1, 1)),
            ip6("64:ff9b::101:101")
        );
        for (nsp, v4, want) in [
            (
                "2001:db8:64::/96",
                "216.239.32.10",
                "2001:db8:64::d8ef:200a",
            ),
            (
                "2001:db8:122:344::/64",
                "192.0.0.170",
                "2001:db8:122:344:c0:0:aa00:0",
            ),
            ("2001:db8::/32", "192.0.0.170", "2001:db8:c000:aa::"),
        ] {
            let got = synthesize(p(nsp), v4.parse().unwrap());
            assert_eq!(got, ip6(want), "{nsp} {v4}");
        }
        assert_eq!(
            prefix_of_answer(synthesize(p("2001:db8::/32"), WELL_KNOWN_V4[0])),
            Some(p("2001:db8::/32"))
        );
    }

    #[test]
    fn aaaa_answers_parse() {
        let q =
            crate::public::build_query_with(7, IPV4ONLY_ARPA, TYPE_AAAA, CLASS_IN, true).unwrap();
        assert_eq!(&q[2..4], &[1, 0], "recursion desired");
        let mut m = q.clone();
        m[2] |= 0x80; // response
        m[6..8].copy_from_slice(&2u16.to_be_bytes());
        for a in ["64:ff9b::c000:aa", "64:ff9b::c000:ab"] {
            m.extend_from_slice(&[0xc0, 12]);
            m.extend_from_slice(&TYPE_AAAA.to_be_bytes());
            m.extend_from_slice(&CLASS_IN.to_be_bytes());
            m.extend_from_slice(&60u32.to_be_bytes());
            m.extend_from_slice(&16u16.to_be_bytes());
            m.extend_from_slice(&ip6(a).octets());
        }
        assert_eq!(
            parse_aaaa(&m, 7),
            Some(Ok(vec![ip6("64:ff9b::c000:aa"), ip6("64:ff9b::c000:ab")]))
        );
        assert_eq!(parse_aaaa(&m, 8), None);
        let mut nx = q.clone();
        nx[2] |= 0x80;
        nx[3] |= 3;
        assert_eq!(parse_aaaa(&nx, 7), Some(Ok(Vec::new())));
        let mut servfail = q;
        servfail[2] |= 0x80;
        servfail[3] |= 2;
        assert!(matches!(parse_aaaa(&servfail, 7), Some(Err(_))));
    }

    /// A DNS64 resolver (staged on loopback) that synthesizes under a network-specific prefix:
    /// discovery learns the prefix from where 192.0.0.170/171 sit.
    #[test]
    fn a_dns64_resolver_reveals_its_prefix() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = server.local_addr().unwrap();
        let answers = [ip6("2001:db8:64::c000:aa"), ip6("2001:db8:64::c000:ab")];
        let t = std::thread::spawn(move || {
            let mut buf = [0u8; 512];
            let (n, from) = server.recv_from(&mut buf).unwrap();
            let q = &buf[..n];
            assert_eq!(&q[2..4], &[1, 0], "recursion desired");
            let mut m = q.to_vec();
            m[2] = 0x81; // QR, RD
            m[3] = 0x80; // RA, NOERROR
            m[6..8].copy_from_slice(&(answers.len() as u16).to_be_bytes());
            for a in answers {
                m.extend_from_slice(&[0xc0, 12]);
                m.extend_from_slice(&TYPE_AAAA.to_be_bytes());
                m.extend_from_slice(&CLASS_IN.to_be_bytes());
                m.extend_from_slice(&60u32.to_be_bytes());
                m.extend_from_slice(&16u16.to_be_bytes());
                m.extend_from_slice(&a.octets());
            }
            server.send_to(&m, from).unwrap();
        });
        // A second server that never answers does not hold the answer up past the timeout.
        let silent = UdpSocket::bind("127.0.0.1:0").unwrap();
        let found = discover_at(
            &[addr, silent.local_addr().unwrap()],
            Duration::from_millis(500),
        )
        .unwrap();
        t.join().unwrap();
        assert_eq!(found, vec![p("2001:db8:64::/96")]);
        // Nobody answers: an error, with reasons.
        assert!(discover_at(&[silent.local_addr().unwrap()], Duration::from_millis(100)).is_err());
    }

    /// Against this host's own DNS servers: an answer (no DNS64 here: nothing, or the
    /// well-known prefix), or a failure with reasons; within the timeout.
    #[test]
    fn this_hosts_resolvers_answer_the_discovery_query() {
        let t = Instant::now();
        match discover(&crate::system_resolvers(), DISCOVERY_TIMEOUT) {
            Ok(found) => {
                for n in &found {
                    assert!(check_prefix(*n).is_ok(), "{n}");
                }
                eprintln!("NAT64 prefixes here: {found:?}");
            }
            Err(e) => crate::skipped(format!("no DNS server answered here: {e}")),
        }
        assert!(t.elapsed() < DISCOVERY_TIMEOUT + Duration::from_millis(500));
    }

    /// Review round 3, bypass-1 (every platform since the Linux application): a round starts
    /// when the uplink signature changes (not up to [`DISCOVERY_TTL`] later), and is asked again
    /// every [`RETRY_UNSETTLED`] while a host with IPv6 and no IPv4 route has found nothing; a
    /// dual-stack host waits for the TTL; one round runs at a time, and one that finishes after
    /// the uplink changed starts another.
    #[test]
    fn a_new_uplink_is_asked_for_its_prefix_at_once() {
        let t0 = Instant::now();
        let at = |s: u64| t0 + Duration::from_secs(s);
        let v6_only = |sig| Uplink {
            signature: sig,
            routed: [false, true],
            clat: false,
        };
        let dual = |sig| Uplink {
            signature: sig,
            routed: [true, true],
            clat: false,
        };
        let mut d = OnUplink {
            uplink: None,
            settled: None,
            running: false,
            first_done: false,
            attempted_at: None,
            found_nothing: false,
        };
        assert_eq!(next_on(&mut d, dual(1), at(0)), Next::AskHere);
        assert_eq!(next_on(&mut d, dual(1), at(0)), Next::WaitFirst);
        finished(&mut d, dual(1), true);
        assert_eq!(d.settled, Some(1));
        assert_eq!(next_on(&mut d, dual(1), at(10)), Next::Nothing);
        // The uplink changes: asked at once, unsettled until that round finishes.
        assert_eq!(next_on(&mut d, v6_only(2), at(11)), Next::AskInBackground);
        assert_ne!(d.settled, Some(2));
        assert_eq!(
            next_on(&mut d, v6_only(2), at(11)),
            Next::Nothing,
            "one at a time"
        );
        finished(&mut d, v6_only(2), false);
        assert_eq!(d.settled, Some(2));
        // Found nothing on an IPv6-only host: asked again after RETRY_UNSETTLED, not before.
        assert_eq!(next_on(&mut d, v6_only(2), at(20)), Next::Nothing);
        assert_eq!(next_on(&mut d, v6_only(2), at(27)), Next::AskInBackground);
        finished(&mut d, v6_only(2), false);
        // A dual-stack host that found nothing waits for the TTL.
        assert_eq!(next_on(&mut d, dual(2), at(28)), Next::Nothing);
        assert_eq!(next_on(&mut d, dual(2), at(27 + 299)), Next::Nothing);
        assert_eq!(
            next_on(&mut d, dual(2), at(27 + 300)),
            Next::AskInBackground
        );
        // The uplink changes while a round runs: that round settles nothing, and another runs.
        assert_eq!(next_on(&mut d, v6_only(3), at(400)), Next::Nothing);
        finished(&mut d, dual(2), true);
        assert!(d.running, "a round on the new uplink is due at once");
        assert_ne!(d.settled, Some(3));
        finished(&mut d, v6_only(3), true);
        assert_eq!(d.settled, Some(3));
        assert!(v6_only(3).ipv6_only() && !dual(3).ipv6_only());
        assert!(v6_only(3).refuses_ipv6(false) && !v6_only(3).refuses_ipv6(true));
        assert!(
            !dual(3).refuses_ipv6(false),
            "a dual-stack host is never refused for it"
        );
        // Review round 5, bypass-4: one behind a CLAT is an IPv6-only host (refused while
        // unsettled, asked again every RETRY_UNSETTLED).
        let clat = Uplink {
            clat: true,
            ..dual(3)
        };
        assert!(clat.ipv6_only() && clat.refuses_ipv6(false));
        assert_eq!(next_on(&mut d, clat, at(500)), Next::AskInBackground);
    }

    /// Review round 3, bypass-1, live (every platform since the Linux application): a new uplink
    /// signature is unsettled when it is first seen (its round runs in the background).
    #[test]
    fn a_new_uplink_signature_is_unsettled_at_first() {
        use std::hash::{BuildHasher, Hasher};
        ensure_discovered_on(Uplink {
            signature: 1,
            routed: [true, true],
            clat: false,
        });
        let fresh = std::collections::hash_map::RandomState::new()
            .build_hasher()
            .finish()
            | 7;
        assert!(!ensure_discovered_on(Uplink {
            signature: fresh,
            routed: [true, true],
            clat: false,
        }));
    }

    /// Review round 3, bypass-2 (every platform since the Linux application; the reviewer's
    /// `r3_nat64_discovery_asks_only_the_first_eight_sorted_servers`): eight IPv4 servers that
    /// never answer, sorted ahead of the network's DNS64 on IPv6, hid its prefix. On a host with
    /// IPv6 and no IPv4 route the IPv6 servers are asked (the IPv4 ones cannot be reached), and on
    /// any host the active servers come first, so the DNS64 is asked and its prefix found.
    #[test]
    fn the_active_and_routed_servers_are_asked_first() {
        let dns64 = UdpSocket::bind("[::1]:0").unwrap();
        let dns64_addr = dns64.local_addr().unwrap();
        dns64
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let h = std::thread::spawn(move || {
            let mut asked = 0;
            let mut b = [0u8; 512];
            while let Ok((n, from)) = dns64.recv_from(&mut b) {
                asked += 1;
                let mut r = b[..n].to_vec();
                r[2] = 0x81;
                r[3] = 0x80;
                r[6] = 0;
                r[7] = 2;
                for v4 in WELL_KNOWN_V4 {
                    r.extend_from_slice(&[0xc0, 0x0c, 0, 28, 0, 1, 0, 0, 0, 60, 0, 16]);
                    r.extend_from_slice(&synthesize(p("2a0b:7e40:64::/96"), v4).octets());
                }
                dns64.send_to(&r, from).unwrap();
            }
            asked
        });
        let silent: Vec<UdpSocket> = (0..8)
            .map(|_| UdpSocket::bind("127.0.0.1:0").unwrap())
            .collect();
        let mut all: Vec<SocketAddr> = silent.iter().map(|s| s.local_addr().unwrap()).collect();
        all.push(dns64_addr);
        all.sort();
        let v6 = |a: &SocketAddr| a.is_ipv6();
        // As round 2 asked them: the first eight of the sorted list, all silent.
        assert!(discover_at(&all, Duration::from_millis(500)).is_err());
        // IPv6 only: the DNS64 alone.
        let ordered = order_servers(&[], &all, [false, true], v6);
        assert_eq!(ordered, vec![dns64_addr]);
        let found = discover_at(&ordered, Duration::from_millis(800)).unwrap();
        assert_eq!(found, vec![p("2a0b:7e40:64::/96")]);
        // Dual-stack, the DNS64 active: asked first, and found.
        let ordered = order_servers(&[dns64_addr], &all, [true, true], v6);
        assert_eq!(ordered[0], dns64_addr);
        assert_eq!(ordered.len(), MAX_SERVERS);
        let found = discover_at(&ordered, Duration::from_millis(800)).unwrap();
        assert_eq!(found, vec![p("2a0b:7e40:64::/96")]);
        // Without a route at all, nothing is skipped; IPv6 first.
        assert_eq!(order_servers(&[], &all, [false, false], v6)[0], dns64_addr);
        // IPv4 only: the IPv6 server is skipped.
        assert!(!order_servers(&[], &all, [true, false], v6).contains(&dns64_addr));
        drop(silent);
        assert_eq!(h.join().unwrap(), 2);
    }

    /// macOS, review round 3, bypass-1: the configuration daemon's NAT64 prefixes are read from
    /// every string value of its per-interface NAT64 dictionaries (alone or in an array); what is
    /// not an IPv6 prefix of an RFC 6052 length is ignored. And this host's keys read.
    #[cfg(target_os = "macos")]
    #[test]
    fn the_configuration_daemons_nat64_prefixes_are_read() {
        use crate::facts::macos_dns::{nat64_prefixes, nat64_prefixes_of};
        use core_foundation::array::CFArray;
        use core_foundation::base::{CFType, TCFType};
        use core_foundation::date::CFDate;
        use core_foundation::dictionary::CFDictionary;
        use core_foundation::propertylist::CFPropertyListSubClass;
        use core_foundation::string::CFString;
        let s = |v: &str| CFString::new(v).as_CFType();
        let k = |v: &'static str| CFString::from_static_string(v).as_CFType();
        let dict = |pairs: &[(CFType, CFType)]| {
            CFDictionary::from_CFType_pairs(pairs)
                .to_untyped()
                .to_CFPropertyList()
        };
        let list = |v: &[&str]| {
            CFArray::from_CFTypes(&v.iter().map(|x| s(x)).collect::<Vec<_>>()).as_CFType()
        };
        let values = vec![
            dict(&[
                (
                    k("PrefixList"),
                    list(&["2001:db8:64::/96", "64:ff9b::/96 ", "x"]),
                ),
                (k("PLATDiscoveryStartTime"), CFDate::now().as_CFType()),
            ]),
            dict(&[(k("Other"), s("2001:db8:a::/48"))]),
            // Not RFC 6052 lengths, not IPv6, not a dictionary.
            dict(&[(k("PrefixList"), list(&["2001:db8:b::/80", "10.0.0.0/8"]))]),
            CFArray::from_CFTypes(&[s("2001:db8:c::/96")])
                .to_untyped()
                .to_CFPropertyList(),
        ];
        assert_eq!(
            nat64_prefixes_of(values),
            vec![
                p("64:ff9b::/96"),
                p("2001:db8:a::/48"),
                p("2001:db8:64::/96")
            ]
        );
        let here = nat64_prefixes().unwrap();
        eprintln!("this host's NAT64 prefixes (configd): {here:?}");
    }

    /// The Linux application of review round 3, bypass-2: off macOS the active servers are the
    /// `nameserver` lines in file order, `/etc/resolv.conf` first, so the server glibc asks
    /// first is asked first (the facts' list is sorted).
    #[test]
    fn resolv_conf_servers_keep_their_order() {
        let text = "nameserver 9.9.9.9\nnameserver 2001:db8::53\nnameserver 1.1.1.1\n";
        let active = crate::facts::parse_nameservers(text);
        let mut all = active.clone();
        all.sort();
        let ordered = order_servers(&active, &all, [true, true], IpAddr::is_ipv6);
        assert_eq!(ordered, active);
        assert_eq!(ordered[0], "9.9.9.9".parse::<IpAddr>().unwrap());
        // IPv6 only: the IPv6 server, ahead of everything it cannot reach.
        assert_eq!(
            order_servers(&active, &all, [false, true], IpAddr::is_ipv6),
            vec!["2001:db8::53".parse::<IpAddr>().unwrap()]
        );
    }

    /// Off macOS the servers asked first are every `nameserver` line of the resolv.conf files,
    /// in file order, `/etc/resolv.conf` first.
    #[cfg(not(target_os = "macos"))]
    #[test]
    fn the_active_servers_are_the_resolv_conf_files_in_order() {
        let want: Vec<IpAddr> = crate::facts::RESOLV_CONF_PATHS
            .iter()
            .filter_map(|p| std::fs::read_to_string(p).ok())
            .flat_map(|t| crate::facts::parse_nameservers(&t))
            .collect();
        if want.is_empty() {
            crate::skipped("no nameserver in this host's resolv.conf files");
            return;
        }
        assert_eq!(active_servers().unwrap(), want);
    }

    /// The Linux application (RFC 8781): `RTM_NEWNDUSEROPT` messages carrying a router
    /// advertisement's PREF64 option give its prefix, at the length its PLC names; other options,
    /// other ICMP types, invalid PLCs and malformed options give nothing.
    #[test]
    fn pref64_options_of_router_advertisements_are_read() {
        // One RTM_NEWNDUSEROPT: nlmsghdr, nduseroptmsg, the options, an NDUSEROPT_SRCADDR.
        let msg = |icmp_type: u8, opts: &[u8]| {
            let mut payload = vec![0u8; 16];
            payload[0] = AF_INET6 as u8;
            payload[2..4].copy_from_slice(&(opts.len() as u16).to_ne_bytes());
            payload[4..8].copy_from_slice(&2i32.to_ne_bytes());
            payload[8] = icmp_type;
            payload.extend_from_slice(opts);
            // NDUSEROPT_SRCADDR: the router's address, after the options.
            payload.extend_from_slice(&20u16.to_ne_bytes());
            payload.extend_from_slice(&1u16.to_ne_bytes());
            payload.extend_from_slice(&ip6("fe80::1").octets());
            let mut m = Vec::new();
            m.extend_from_slice(&((16 + payload.len()) as u32).to_ne_bytes());
            m.extend_from_slice(&RTM_NEWNDUSEROPT.to_ne_bytes());
            m.extend_from_slice(&[0u8; 10]);
            m.extend_from_slice(&payload);
            m
        };
        let pref64 = |prefix: &str, plc: u8, lifetime: u16| {
            let a = ip6(prefix).octets();
            let mut o = vec![ND_OPT_PREF64, 2];
            o.extend_from_slice(&((lifetime << 3) | u16::from(plc)).to_be_bytes());
            o.extend_from_slice(&a[..12]);
            o
        };
        for (prefix, plc, len) in [
            ("2a0b:7e40:64::", 0, 96),
            ("2001:db8:122:344::", 1, 64),
            ("2001:db8:122:300::", 2, 56),
            ("2001:db8:122::", 3, 48),
            ("2001:db8:100::", 4, 40),
            ("2001:db8::", 5, 32),
        ] {
            assert_eq!(
                pref64_of_datagram(&msg(134, &pref64(prefix, plc, 600))),
                vec![Announced {
                    prefix: p(&format!("{prefix}/{len}")),
                    lifetime: Duration::from_secs(600 * 8),
                    ifindex: 2,
                    router: Some(ip6("fe80::1")),
                }],
                "{prefix} PLC {plc}"
            );
        }
        // Lifetime 0 (the router withdraws it): read, with lifetime 0.
        let w = pref64_of_datagram(&msg(134, &pref64("64:ff9b::", 0, 0)));
        assert_eq!(
            w.iter().map(|a| (a.prefix, a.lifetime)).collect::<Vec<_>>(),
            vec![(WELL_KNOWN_PREFIX, Duration::ZERO)]
        );
        // Not from the kernel: nothing.
        for pid in [1, 4242, u32::MAX] {
            assert!(pref64_from(pid, &msg(134, &pref64("2001:db8::", 5, 600))).is_empty());
        }
        assert_eq!(
            pref64_from(0, &msg(134, &pref64("2001:db8::", 5, 600))).len(),
            1
        );
        // Behind an RDNSS option, and two messages in one datagram.
        let rdnss = [
            25u8, 3, 0, 0, 0, 0, 0, 60, 0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x53,
        ];
        let mut both = msg(
            134,
            &[&rdnss[..], &pref64("2a0b:7e40:64::", 0, 600)].concat(),
        );
        both.extend(msg(134, &pref64("2001:db8::", 5, 600)));
        assert_eq!(
            pref64_of_datagram(&both)
                .iter()
                .map(|a| a.prefix)
                .collect::<Vec<_>>(),
            vec![p("2a0b:7e40:64::/96"), p("2001:db8::/32")]
        );
        // PLC 6 and 7 are invalid; another ICMP type (a redirect's options); a PREF64 of the
        // wrong length; an option whose length runs past the options; a cut message.
        assert!(pref64_of_datagram(&msg(134, &pref64("2001:db8::", 6, 600))).is_empty());
        assert!(pref64_of_datagram(&msg(134, &pref64("2001:db8::", 7, 600))).is_empty());
        assert!(pref64_of_datagram(&msg(137, &pref64("2001:db8::", 5, 600))).is_empty());
        let mut long = pref64("2001:db8::", 5, 600);
        long[1] = 3;
        long.extend_from_slice(&[0u8; 8]);
        assert!(pref64_of_datagram(&msg(134, &long)).is_empty());
        let mut past = pref64("2001:db8::", 5, 600);
        past[1] = 9;
        assert!(pref64_of_datagram(&msg(134, &past)).is_empty());
        let whole = msg(134, &pref64("2001:db8::", 5, 600));
        for cut in [0, 4, 16, 31, whole.len() - 1] {
            assert!(pref64_of_datagram(&whole[..cut]).is_empty(), "{cut}");
        }
    }

    /// Linux: the PREF64 listener joins `RTNLGRP_ND_USEROPT` without privileges. With
    /// `ZKMINER_TEST_PREF64=<prefix>` (a router advertisement carrying that PREF64 staged on an
    /// interface whose `accept_ra` lets the kernel process it, as `fix-linux/exp/pref64-ra.sh`
    /// does), it also waits up to 30 s for that prefix to arrive and be learned.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn the_pref64_listener_joins_unprivileged() {
        let sock = pref64::subscribe().expect("RTNLGRP_ND_USEROPT is open to every process");
        // A NAT64 round asks the system's prefixes, which starts the listener.
        system_prefixes(0).unwrap();
        assert!(pref64::started());
        let Ok(want) = std::env::var("ZKMINER_TEST_PREF64") else {
            eprintln!(
                "subscribed; no staged router advertisement (ZKMINER_TEST_PREF64) to wait for"
            );
            return;
        };
        let want: Prefix = want.parse().expect("ZKMINER_TEST_PREF64 is a prefix");
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut buf = vec![0u8; 64 * 1024];
            loop {
                match pref64::receive(&sock, &mut buf) {
                    Ok(found) if !found.is_empty() => {
                        let _ = tx.send(found);
                    }
                    Ok(_) => {}
                    Err(e) => panic!("{e}"),
                }
            }
        });
        let found = rx
            .recv_timeout(Duration::from_secs(30))
            .expect("a PREF64 within 30 s");
        eprintln!("PREF64 received: {found:?}");
        assert!(found.iter().any(|a| a.prefix == want), "{found:?}");
        // And the listener the rounds start learns it.
        pref64::start();
        let t = Instant::now();
        while !pref64::seen().contains(&want) && t.elapsed() < Duration::from_secs(30) {
            std::thread::sleep(Duration::from_millis(100));
        }
        assert!(pref64::seen().contains(&want), "{:?}", pref64::seen());
        // Learned only when its sender is an IPv6 default gateway of the uplink in use, on that
        // route's interface (review round 4, bypass-1:
        // `r4_pref64_is_learned_from_the_default_gateway_alone`).
        eprintln!(
            "learned: {} (gateways of the uplink in use: {:?})",
            learned().contains(&want),
            registry().gateways
        );
    }
}

/// Review round 4: bypass-1 = parse-1 = cross-1 (configured NSPs crowded out by learned ones),
/// parse-4 (learned prefixes synthesized with on every uplink, for ever), cross-6 (the PREF64
/// listener's untested lines).
#[cfg(test)]
mod r4_tests {
    use super::*;

    fn ip6(s: &str) -> Ipv6Addr {
        s.parse().unwrap()
    }

    fn p(s: &str) -> Prefix {
        s.parse().unwrap()
    }

    fn junk(n: u16) -> Vec<Prefix> {
        (1..=n).map(|i| p(&format!("2000:0:{i:x}::/96"))).collect()
    }

    fn forever(v: &[Prefix]) -> Vec<(Prefix, Option<Duration>)> {
        v.iter().map(|p| (*p, None)).collect()
    }

    /// A fake DNS64 (a hostile DHCP-supplied resolver, the reviewers' `rogue_dns64`) answering
    /// `ipv4only.arpa AAAA` with `answers`.
    fn dns64(answers: Vec<Ipv6Addr>) -> (SocketAddr, std::thread::JoinHandle<()>) {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = server.local_addr().unwrap();
        let t = std::thread::spawn(move || {
            let mut buf = [0u8; 512];
            let (n, from) = server.recv_from(&mut buf).unwrap();
            let mut m = buf[..n].to_vec();
            m[2] = 0x81;
            m[3] = 0x80;
            m[6..8].copy_from_slice(&(answers.len() as u16).to_be_bytes());
            for a in answers {
                m.extend_from_slice(&[0xc0, 12, 0, 28, 0, 1, 0, 0, 0, 60, 0, 16]);
                m.extend_from_slice(&a.octets());
            }
            server.send_to(&m, from).unwrap();
        });
        (addr, t)
    }

    /// The reviewers' attack, on the process-wide registry: 16 learned prefixes (a rogue RA's
    /// PREF64 options, or a DNS64 answer) no longer push the configured NSP out of what the
    /// address predicate reads, and what DoH synthesizes with first (the configured NSP) is
    /// refused as the IPv4 address it carries.
    #[test]
    fn r4_learned_prefixes_never_crowd_out_the_configured_nsp() {
        let cfg = p("2a0b:7e40:64::/96");
        set_configured(&[cfg]).unwrap();
        let victim = IpAddr::V6(synthesize(cfg, Ipv4Addr::new(10, 0, 0, 1)));
        assert!(!crate::is_global(victim));
        add_learned(&junk(16));
        assert!(prefixes().contains(&cfg), "{:?}", prefixes());
        assert!(
            !crate::is_global(victim),
            "{victim} admitted after the flood"
        );
        let first = in_force()[0];
        assert_eq!(first, cfg, "the configured NSP is synthesized with first");
        let meta = IpAddr::V6(synthesize(first, Ipv4Addr::new(169, 254, 169, 254)));
        assert!(!crate::is_global(meta), "{meta} admitted");
        // A real NSP learned after the flood is still learned (no process-wide cap of 16).
        let real = p("2a0b:7e40:65::/96");
        add_learned(&[real]);
        assert!(learned().contains(&real));
        assert!(!crate::is_global(IpAddr::V6(synthesize(
            real,
            Ipv4Addr::new(10, 0, 0, 1)
        ))));
    }

    /// The registry's caps, on a registry of its own: configured prefixes are never truncated;
    /// one source names at most its cap (more makes the uplink unsettled, with a reason); one
    /// uplink holds at most [`MAX_PER_UPLINK`]; when [`MAX_LEARNED`] are held, another uplink's
    /// least recently seen makes room (never the uplink in use), and when none can, the new one
    /// is not held and its uplink is unsettled.
    #[test]
    fn r4_the_registry_holds_configured_prefixes_and_caps_each_source() {
        let t0 = Instant::now();
        let mut r = Registry {
            configured: junk(16),
            ..Registry::default()
        };
        let cfg = r.configured.clone();
        // A router that names 16: its first four held, the uplink unsettled.
        let router = Source::Pref64 {
            router: ip6("fe80::1"),
            ifindex: 2,
        };
        let flood: Vec<Prefix> = (1..=16u16)
            .map(|i| p(&format!("2001:db8:{i:x}::/96")))
            .collect();
        assert!(learn(&mut r, 1, router, &forever(&flood), t0));
        assert_eq!(r.learned.len(), MAX_PER_ROUTER);
        assert!(
            r.unheld
                .iter()
                .any(|(s, w)| *s == 1 && w.contains("named 16")),
            "{:?}",
            r.unheld
        );
        for c in &cfg {
            assert!(all_of(&r).contains(c), "configured {c} crowded out");
        }
        // A DNS server whose answer names three: two held (RFC 7050 §3), unsettled.
        let server = Source::Dns64("192.0.2.53".parse().unwrap());
        learn(&mut r, 2, server, &forever(&junk(3)), t0);
        assert_eq!(
            r.learned.iter().filter(|e| e.uplink == 2).count(),
            MAX_PER_ANSWER
        );
        assert!(r.unheld.iter().any(|(s, _)| *s == 2));
        // One uplink holds at most MAX_PER_UPLINK.
        let mut r = Registry::default();
        for i in 0..40u16 {
            learn(
                &mut r,
                7,
                Source::Given(u32::from(i)),
                &[(p(&format!("2001:db8:{i:x}::/96")), None)],
                t0,
            );
        }
        assert_eq!(r.learned.len(), MAX_PER_UPLINK);
        assert!(r
            .unheld
            .iter()
            .any(|(s, w)| *s == 7 && w.contains("for one network")));
        // MAX_LEARNED in all: the least recently seen of another uplink makes room.
        let mut r = Registry {
            on: Some(100),
            ..Registry::default()
        };
        let mut n = 0u32;
        for up in [100u64, 101] {
            for i in 0..32u16 {
                let at = t0 + Duration::from_secs(u64::from(n));
                n += 1;
                learn(
                    &mut r,
                    up,
                    Source::Given(n),
                    &[(p(&format!("2001:db8:{up}:{i:x}::/96")), None)],
                    at,
                );
            }
        }
        assert_eq!(r.learned.len(), MAX_LEARNED);
        let later = t0 + Duration::from_secs(1000);
        assert!(learn(
            &mut r,
            102,
            Source::Given(999),
            &[(p("2001:db8:ffff::/96"), None)],
            later
        ));
        assert_eq!(r.learned.len(), MAX_LEARNED);
        assert!(
            !all_of(&r).contains(&p("2001:db8:101:0::/96")),
            "uplink 101's oldest made room"
        );
        assert!(
            all_of(&r).contains(&p("2001:db8:100:0::/96")),
            "the uplink in use is kept"
        );
        assert!(r.unheld.is_empty(), "{:?}", r.unheld);
        // Nothing of another uplink left to drop: not held, unsettled.
        let mut r2 = Registry {
            on: Some(100),
            ..Registry::default()
        };
        for i in 0..32u16 {
            learn(
                &mut r2,
                100,
                Source::Given(u32::from(i)),
                &[(p(&format!("2001:db8:100:{i:x}::/96")), None)],
                t0,
            );
            learn(
                &mut r2,
                103,
                Source::Given(100 + u32::from(i)),
                &[(p(&format!("2001:db8:103:{i:x}::/96")), None)],
                t0,
            );
        }
        assert_eq!(r2.learned.len(), MAX_LEARNED);
        r2.on = Some(103);
        learn(
            &mut r2,
            104,
            Source::Given(500),
            &[(p("2001:db8:104::/96"), None)],
            later,
        );
        assert!(
            all_of(&r2).contains(&p("2001:db8:104::/96")),
            "uplink 100's made room"
        );
        assert!(
            all_of(&r2)
                .iter()
                .filter(|q| q.to_string().starts_with("2001:db8:103:"))
                .count()
                == 32
        );
    }

    /// parse-4: a learned prefix is synthesized with only on the uplink it was learned on, while
    /// its source names it and its lifetime runs; withdrawn (lifetime 0, or no longer named) or
    /// learned elsewhere, it is still refused (read as an NSP) but never synthesized with.
    #[test]
    fn r4_only_the_uplink_in_uses_live_prefixes_are_synthesized_with() {
        let t0 = Instant::now();
        let cfg = p("2001:db8:c0::/96");
        let mut r = Registry {
            configured: vec![cfg],
            on: Some(1),
            ..Registry::default()
        };
        let router = Source::Pref64 {
            router: ip6("fe80::1"),
            ifindex: 2,
        };
        let a = p("2001:db8:a::/96");
        let b = p("2001:db8:b::/96");
        learn(
            &mut r,
            1,
            router,
            &[(a, Some(Duration::from_secs(600)))],
            t0,
        );
        learn(
            &mut r,
            2,
            Source::Dns64("192.0.2.1".parse().unwrap()),
            &forever(&[b]),
            t0,
        );
        assert_eq!(in_force_of(&r, t0), vec![cfg, a]);
        assert!(all_of(&r).contains(&b));
        // Its lifetime ran out.
        assert_eq!(in_force_of(&r, t0 + Duration::from_secs(601)), vec![cfg]);
        // Roamed to uplink 2: its prefix, not uplink 1's.
        r.on = Some(2);
        assert_eq!(in_force_of(&r, t0), vec![cfg, b]);
        // The router withdraws (lifetime 0): never synthesized with, still refused.
        r.on = Some(1);
        learn(&mut r, 1, router, &[(a, Some(Duration::ZERO))], t0);
        assert_eq!(in_force_of(&r, t0), vec![cfg]);
        assert!(all_of(&r).contains(&a));
        // A DNS server that no longer names its prefix withdraws it the same way.
        r.on = Some(2);
        learn(
            &mut r,
            2,
            Source::Dns64("192.0.2.1".parse().unwrap()),
            &[],
            t0,
        );
        assert_eq!(in_force_of(&r, t0), vec![cfg]);
        assert!(all_of(&r).contains(&b));
    }

    /// RFC 7050 §3: an answer reveals a prefix only where both well-known addresses sit under
    /// it; one carrying a single one reveals nothing; more than two prefixes are not believed.
    #[test]
    fn r4_rfc7050_answers_are_validated() {
        let nsp = |i: u16, w: u8| {
            Ipv6Addr::new(0x2001, 0x0db8, i, 0, 0, 0, 0xc000, 0x00aa + u16::from(w))
        };
        assert_eq!(
            nsps_of_answer(&[nsp(1, 0), nsp(1, 1)]),
            Ok(vec![p("2001:db8:1::/96")])
        );
        assert_eq!(
            nsps_of_answer(&[nsp(1, 0)]),
            Ok(vec![]),
            "one address alone"
        );
        assert_eq!(
            nsps_of_answer(&[nsp(1, 0), nsp(2, 1)]),
            Ok(vec![]),
            "under two prefixes"
        );
        assert_eq!(
            nsps_of_answer(&[nsp(1, 0), nsp(1, 1), nsp(2, 0), nsp(2, 1)]),
            Ok(vec![p("2001:db8:1::/96"), p("2001:db8:2::/96")]),
            "a renumbering: two"
        );
        let three: Vec<Ipv6Addr> = (1..=3).flat_map(|i| [nsp(i, 0), nsp(i, 1)]).collect();
        assert!(nsps_of_answer(&three)
            .unwrap_err()
            .contains("3 NAT64 prefixes"));
        // The reviewers' answer: 16 addresses, each carrying 192.0.0.170 alone.
        let rogue: Vec<Ipv6Addr> = (0..16).map(|i| nsp(i, 0)).collect();
        assert_eq!(nsps_of_answer(&rogue), Ok(vec![]));
        // A /64 one (RFC 6052 layout, the u octet skipped).
        let a64 = synthesize(p("2001:db8:122:344::/64"), WELL_KNOWN_V4[0]);
        let b64 = synthesize(p("2001:db8:122:344::/64"), WELL_KNOWN_V4[1]);
        assert_eq!(
            nsps_of_answer(&[a64, b64]),
            Ok(vec![p("2001:db8:122:344::/64")])
        );
    }

    /// The reviewers' hostile DNS64, end to end: an answer of 16 addresses each carrying one
    /// well-known address teaches nothing; an answer revealing 16 validated prefixes is not
    /// believed, nothing of it is learned, and its uplink is unsettled (IPv6 refused there).
    #[test]
    fn r4_a_hostile_dns64_answer_is_not_believed() {
        use std::hash::{BuildHasher, Hasher};
        let fresh = || {
            std::collections::hash_map::RandomState::new()
                .build_hasher()
                .finish()
                | 1
        };
        let up = fresh();
        let single: Vec<Ipv6Addr> = (0..16u16)
            .map(|i| Ipv6Addr::new(0x2001, 0x0400, i, 0, 0, 0, 0xc000, 0x00aa))
            .collect();
        let (addr, t) = dns64(single);
        assert_eq!(
            ask_and_learn_at(up, &[addr], Duration::from_secs(2)),
            Ok(false)
        );
        t.join().unwrap();
        assert!(!learned()
            .iter()
            .any(|q| q.to_string().starts_with("2001:400:")));
        assert_eq!(unheld(up), None);
        let up = fresh();
        let validated: Vec<Ipv6Addr> = (0..16u16)
            .flat_map(|i| {
                [0xaa, 0xab].map(|w| Ipv6Addr::new(0x2001, 0x0401, i, 0, 0, 0, 0xc000, w))
            })
            .collect();
        let (addr, t) = dns64(validated);
        let _ = ask_and_learn_at(up, &[addr], Duration::from_secs(2));
        t.join().unwrap();
        assert!(!learned()
            .iter()
            .any(|q| q.to_string().starts_with("2001:401:")));
        let why = unheld(up).expect("unsettled");
        assert!(why.contains("16 NAT64 prefixes"), "{why}");
        // A new round on that uplink asks again; the mark stands until it ends (review round 5,
        // bypass-3), and goes if that round names nothing it cannot hold.
        begin_round(up);
        assert!(unheld(up).is_some());
        end_round(up);
        assert_eq!(unheld(up), None);
    }

    /// PREF64 is heard per router: only an IPv6 default gateway, on that route's interface, is
    /// learned from; a message without the router's address is not believed; a router naming
    /// more than [`MAX_PER_ROUTER`] is seen to; other routers never push a gateway out.
    #[test]
    fn r4_pref64_is_learned_from_the_default_gateway_alone() {
        let t0 = Instant::now();
        let ann = |prefix: &str, router: Option<&str>, ifindex: u32, life: u64| Announced {
            prefix: p(prefix),
            lifetime: Duration::from_secs(life),
            ifindex,
            router: router.map(ip6),
        };
        let gw = (ip6("fe80::1"), 2u32);
        let mut h = Heard::new();
        h.hear(
            &[
                ann("2001:db8:1::/96", Some("fe80::1"), 2, 600),
                ann("2001:db8:2::/96", Some("fe80::bad"), 2, 600),
                ann("2001:db8:3::/96", Some("fe80::1"), 3, 600),
                ann("2001:db8:4::/96", None, 2, 600),
            ],
            &[gw],
            t0,
        );
        let got = h.named_by(&[gw], t0 + Duration::from_secs(100));
        assert_eq!(
            got,
            vec![(
                Source::Pref64 {
                    router: gw.0,
                    ifindex: 2
                },
                vec![(p("2001:db8:1::/96"), Some(Duration::from_secs(500)))]
            )]
        );
        assert!(
            !h.prefixes().contains(&p("2001:db8:4::/96")),
            "no router address"
        );
        // A gateway that names 16: one more than believed is kept, so learning sees too many.
        let flood: Vec<Announced> = (0x10..0x20)
            .map(|i| ann(&format!("2001:db8:{i:x}::/96"), Some("fe80::1"), 2, 600))
            .collect();
        h.hear(&flood, &[gw], t0);
        let got = h.named_by(&[gw], t0);
        assert_eq!(got[0].1.len(), MAX_PER_ROUTER + 1);
        let mut r = Registry::default();
        learn(&mut r, 9, got[0].0, &got[0].1, t0);
        assert!(r.unheld.iter().any(|(s, _)| *s == 9));
        // 40 other routers never push the gateway out.
        for i in 0..40u16 {
            h.hear(
                &[ann(
                    "2001:db8:99::/96",
                    Some(&format!("fe80::{:x}", 0x100 + i)),
                    2,
                    600,
                )],
                &[gw],
                t0,
            );
        }
        assert_eq!(h.named_by(&[gw], t0)[0].1.len(), MAX_PER_ROUTER + 1);
        let routers: std::collections::BTreeSet<_> = h.entries.iter().map(|e| (e.0, e.1)).collect();
        assert!(routers.len() <= MAX_ROUTERS, "{}", routers.len());
        // A gateway that has said nothing names nothing (what it named before is withdrawn).
        let other = (ip6("fe80::2"), 2u32);
        assert_eq!(h.named_by(&[other], t0)[0].1, vec![]);
    }

    /// Review round 4 (cross-1), live (Linux): with `ZKMINER_TEST_ROGUE_RA=<ifindex>,<router>`
    /// (a host on that interface's link sending router advertisements with 16 PREF64 options
    /// each, every second, from link-local address `<router>`: `fix-r4/rogue-ra.sh`), the
    /// configured NSP stays in force throughout. While the sender is no default gateway nothing
    /// it names is learned; once it is the uplink's gateway, at most [`MAX_PER_ROUTER`] of its
    /// prefixes are held and the uplink is unsettled (IPv6 refused).
    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn r4_rogue_router_advertisements_never_evict_the_configured_nsp() {
        let Ok(v) = std::env::var("ZKMINER_TEST_ROGUE_RA") else {
            return;
        };
        let (ifindex, router) = v.split_once(',').expect("<ifindex>,<router>");
        let (ifindex, router): (u32, Ipv6Addr) = (ifindex.parse().unwrap(), router.parse().unwrap());
        let rogue = |q: &Prefix| q.to_string().starts_with("2001:470:6400:");
        let conf = p("2a01:4f8:ffff:64::/96");
        set_configured(&[conf]).unwrap();
        let inner = IpAddr::V6(synthesize(conf, Ipv4Addr::new(10, 0, 0, 1)));
        assert!(!crate::is_global(inner));
        // The sender is no gateway of the uplink in use.
        let (a, b) = (0x00a1_1ce0_u64, 0x00b0_b000_u64);
        on_uplink(a, &[]);
        pref64::start();
        let t = Instant::now();
        while !pref64::seen().iter().any(rogue) && t.elapsed() < Duration::from_secs(30) {
            std::thread::sleep(Duration::from_millis(200));
        }
        eprintln!("heard: {:?}", pref64::seen());
        assert!(pref64::seen().iter().any(rogue), "no advertisement heard");
        assert!(pref64::seen().iter().filter(|q| rogue(q)).count() <= MAX_PER_ROUTER + 1);
        assert!(!learned().iter().any(rogue), "learned from a router that is no gateway");
        assert!(prefixes().contains(&conf) && !crate::is_global(inner));
        // The sender is the uplink's default gateway: its next advertisement is learned, capped.
        on_uplink(b, &[(router, ifindex)]);
        let t = Instant::now();
        while unheld(b).is_none() && t.elapsed() < Duration::from_secs(30) {
            std::thread::sleep(Duration::from_millis(200));
        }
        eprintln!("learned: {:?}; unheld: {:?}", learned(), unheld(b));
        assert!(unheld(b).is_some_and(|w| w.contains("PREF64")), "{:?}", unheld(b));
        assert!(learned().iter().filter(|q| rogue(q)).count() <= MAX_PER_ROUTER);
        assert!(prefixes().contains(&conf) && !crate::is_global(inner));
        assert_eq!(in_force().first(), Some(&conf));
        set_configured(&[]).unwrap();
    }

    /// cross-6 (`nat64.rs:814`, `:843`): the listener survives `ENOBUFS` and `EINTR` (the next
    /// datagram is still heard) and stops on any other error; a datagram not from the kernel
    /// is ignored.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn r4_the_pref64_listener_survives_enobufs() {
        let mut steps: Vec<io::Result<Vec<Announced>>> = vec![
            Err(io::Error::from_raw_os_error(libc::ENOBUFS)),
            Err(io::Error::from_raw_os_error(libc::EINTR)),
            Ok(vec![Announced {
                prefix: p("2001:db8:5e::/96"),
                lifetime: Duration::from_secs(600),
                ifindex: 77,
                router: Some(ip6("fe80::77")),
            }]),
            Err(io::Error::from_raw_os_error(libc::EBADF)),
        ];
        steps.reverse();
        let e = pref64::listen(|| steps.pop().unwrap());
        assert_eq!(e.raw_os_error(), Some(libc::EBADF));
        assert!(pref64::seen().contains(&p("2001:db8:5e::/96")));
    }
}

/// Review round 5: the fixes' tests (findings named in each).
#[cfg(test)]
mod r5_tests {
    use super::*;

    fn ip6(s: &str) -> Ipv6Addr {
        s.parse().unwrap()
    }

    fn p(s: &str) -> Prefix {
        s.parse().unwrap()
    }

    fn ann(prefix: &str, router: Ipv6Addr, life: u64) -> Announced {
        Announced {
            prefix: p(prefix),
            lifetime: Duration::from_secs(life),
            ifindex: 2,
            router: Some(router),
        }
    }

    /// One round's PREF64 learning on `uplink` from what `h` heard of `gw`, at `now`, as
    /// `round_on` does it (the uplink's unheld mark cleared first).
    fn round(h: &Heard, r: &mut Registry, uplink: u64, gw: (Ipv6Addr, u32), now: Instant) {
        r.unheld.retain(|(s, _)| *s != uplink);
        for (source, named) in h.named_by(&[gw], now) {
            learn(r, uplink, source, &named, now);
        }
    }

    fn active(r: &Registry, q: &str) -> bool {
        r.learned.iter().any(|e| e.prefix == p(q) && e.active)
    }

    /// cross-1 = bypass-2 = parse-2: a gateway that renumbers its PREF64 (each old prefix
    /// withdrawn with lifetime 0, or left to run out) never names more than one live prefix, and
    /// its uplink is never unsettled for it: withdrawn and expired prefixes are neither named nor
    /// counted; the sixth one is heard and learned; every old one stays refused (held, inactive).
    #[test]
    fn r5_a_gateway_that_renumbers_its_pref64_never_unsettles_its_uplink() {
        let gw = (ip6("fe80::1"), 2u32);
        let t0 = Instant::now();
        for withdraw in [true, false] {
            let mut h = Heard::new();
            h.on(Some(7));
            let mut r = Registry {
                on: Some(7),
                ..Registry::default()
            };
            for i in 0..6u64 {
                let now = t0 + Duration::from_secs(3600 * i);
                let mut found = vec![ann(&format!("2001:db8:{:x}::/96", 0x100 + i), gw.0, 1800)];
                if withdraw && i > 0 {
                    found.push(ann(&format!("2001:db8:{:x}::/96", 0x100 + i - 1), gw.0, 0));
                }
                h.hear(&found, &[gw], now);
                round(&h, &mut r, 7, gw, now);
                assert!(r.unheld.is_empty(), "renumbering {i} (withdraw {withdraw}): {:?}", r.unheld);
                let named = &h.named_by(&[gw], now)[0].1;
                assert_eq!(named.len(), 1, "{named:?}");
            }
            let now = t0 + Duration::from_secs(3600 * 5);
            assert!(active(&r, "2001:db8:105::/96"));
            assert_eq!(in_force_of(&r, now), vec![p("2001:db8:105::/96")]);
            for i in 0..5 {
                let old = format!("2001:db8:{:x}::/96", 0x100 + i);
                assert!(!active(&r, &old) && all_of(&r).contains(&p(&old)), "{old}");
            }
        }
    }

    /// cross-1 (live: `r5-cross/vm-r5-spoof.log`): one forged advertisement from the gateway's
    /// address naming five prefixes unsettles the uplink while they live, and its refusal names
    /// the source; once they are withdrawn, or run out, the next round holds everything again,
    /// and the real gateway's next prefix (which the five had crowded out of what is heard) is
    /// learned.
    #[test]
    fn r5_one_forged_advertisement_unsettles_its_uplink_only_while_it_lives() {
        let gw = (ip6("fe80::1"), 2u32);
        let t0 = Instant::now();
        for withdrawn in [true, false] {
            let mut h = Heard::new();
            h.on(Some(9));
            let mut r = Registry {
                on: Some(9),
                ..Registry::default()
            };
            let forged: Vec<Announced> = (1..=5)
                .map(|i| ann(&format!("2001:db8:{i:x}::/96"), gw.0, 8))
                .collect();
            h.hear(&forged, &[gw], t0);
            round(&h, &mut r, 9, gw, t0);
            let why = &r.unheld.iter().find(|(s, _)| *s == 9).expect("unheld").1;
            assert!(
                why.contains("the router advertisements of fe80::1 on interface 2 (PREF64)")
                    && why.contains("named 5 NAT64 prefixes"),
                "{why}"
            );
            // While they live, the real gateway's prefix is not heard (one more than believed
            // is kept already).
            h.hear(&[ann("2001:db8:aaaa::/96", gw.0, 1800)], &[gw], t0 + Duration::from_secs(1));
            assert!(!h.prefixes().contains(&p("2001:db8:aaaa::/96")));
            let later = if withdrawn {
                let off: Vec<Announced> = (1..=5)
                    .map(|i| ann(&format!("2001:db8:{i:x}::/96"), gw.0, 0))
                    .collect();
                h.hear(&off, &[gw], t0 + Duration::from_secs(2));
                t0 + Duration::from_secs(2)
            } else {
                t0 + Duration::from_secs(9)
            };
            h.hear(&[ann("2001:db8:aaaa::/96", gw.0, 1800)], &[gw], later);
            round(&h, &mut r, 9, gw, later);
            assert!(r.unheld.is_empty(), "{:?}", r.unheld);
            assert!(active(&r, "2001:db8:aaaa::/96"));
            assert_eq!(in_force_of(&r, later), vec![p("2001:db8:aaaa::/96")]);
            // The forged ones stay refused.
            assert!(all_of(&r).contains(&p("2001:db8:1::/96")));
        }
    }

    /// bypass-4: a host whose IPv4 goes out through a CLAT (an address in 192.0.0.0/29, or an
    /// IPv4 default out of a `clat*` or `v4-*` interface) is IPv6-only for NAT64; any other is
    /// not.
    #[test]
    fn r5_a_clat_host_is_ipv6_only() {
        let a = |s: &str| -> IpAddr { s.parse().unwrap() };
        assert!(clat_in_use(&[a("192.168.1.5"), a("192.0.0.4")], &[]));
        assert!(clat_in_use(&[a("192.0.0.2")], &["en0".into()]));
        assert!(clat_in_use(&[], &["clat".into()]));
        assert!(clat_in_use(&[], &["v4-wlan0".into()]));
        assert!(!clat_in_use(&[a("192.0.0.8"), a("192.168.1.5")], &["eth0".into()]));
        assert!(!clat_in_use(&[a("2001:db8::1")], &["wlan0".into()]));
        let up = Uplink {
            signature: 1,
            routed: [true, true],
            clat: true,
        };
        assert!(up.ipv6_only() && up.refuses_ipv6(false) && !up.refuses_ipv6(true));
    }

    /// parse-3: what a router heard on one uplink announced is not named on another, even by a
    /// router of the same address on the same interface; back on the first uplink, it is again.
    #[test]
    fn r5_another_networks_pref64_is_not_named_on_this_one() {
        let gw = (ip6("fe80::1"), 2u32);
        let t0 = Instant::now();
        let mut h = Heard::new();
        h.on(Some(1));
        h.hear(&[ann("2001:db8:a::/96", gw.0, 1800)], &[gw], t0);
        let mut r = Registry {
            on: Some(1),
            ..Registry::default()
        };
        round(&h, &mut r, 1, gw, t0);
        assert_eq!(in_force_of(&r, t0), vec![p("2001:db8:a::/96")]);
        let t1 = t0 + Duration::from_secs(60);
        h.on(Some(2));
        r.on = Some(2);
        assert_eq!(h.named_by(&[gw], t1)[0].1, vec![]);
        round(&h, &mut r, 2, gw, t1);
        assert!(in_force_of(&r, t1).is_empty());
        h.hear(&[ann("2001:db8:b::/96", gw.0, 1800)], &[gw], t1);
        round(&h, &mut r, 2, gw, t1);
        assert_eq!(in_force_of(&r, t1), vec![p("2001:db8:b::/96")]);
        h.on(Some(1));
        assert_eq!(h.named_by(&[gw], t1)[0].1.len(), 1);
        assert_eq!(h.named_by(&[gw], t1)[0].1[0].0, p("2001:db8:a::/96"));
    }
}

/// Review round 5, bypass-3: an uplink's unheld mark is replaced when its round ends, never
/// cleared while the round runs.
#[cfg(test)]
mod r5_round_tests {
    use super::*;

    fn p(s: &str) -> Prefix {
        s.parse().unwrap()
    }

    /// A DNS64 on loopback answering each query after `delay`, with `answers[i]` for the i-th.
    fn slow_dns64(answers: Vec<Vec<Ipv6Addr>>, delay: Duration) -> (SocketAddr, std::thread::JoinHandle<()>) {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = server.local_addr().unwrap();
        let t = std::thread::spawn(move || {
            for a in answers {
                let mut buf = [0u8; 512];
                let (n, from) = server.recv_from(&mut buf).unwrap();
                std::thread::sleep(delay);
                let mut m = buf[..n].to_vec();
                m[2] = 0x81;
                m[3] = 0x80;
                m[6..8].copy_from_slice(&(a.len() as u16).to_be_bytes());
                for x in &a {
                    m.extend_from_slice(&[0xc0, 12, 0, 28, 0, 1, 0, 0, 0, 60, 0, 16]);
                    m.extend_from_slice(&x.octets());
                }
                server.send_to(&m, from).unwrap();
            }
        });
        (addr, t)
    }

    fn validated(nsps: &[&str]) -> Vec<Ipv6Addr> {
        nsps.iter()
            .flat_map(|n| [synthesize(p(n), WELL_KNOWN_V4[0]), synthesize(p(n), WELL_KNOWN_V4[1])])
            .collect()
    }

    /// The reviewer's `r5_unheld_is_cleared_for_the_length_of_a_round`, turned around: while a
    /// second round asks a DNS64 that over-names (three validated prefixes) and takes 1.5 s to
    /// answer, the uplink stays unsettled; it is still once that round ends; a round whose answer
    /// fits clears it when it ends, not before.
    #[test]
    fn r5_unheld_is_kept_while_a_round_runs_and_replaced_when_it_ends() {
        let uplink = 0x5eed_0105_u64;
        let three = validated(&["2a00:1450:1::/96", "2a00:1450:2::/96", "2a00:1450:3::/96"]);
        let one = validated(&["2a00:1450:4::/96"]);
        let (addr, srv) = slow_dns64(vec![three.clone(), three, one], Duration::from_millis(1500));
        let ask = move || {
            begin_round(uplink);
            let r = ask_and_learn_at(uplink, &[addr], Duration::from_secs(3));
            end_round(uplink);
            r
        };
        ask().unwrap();
        assert!(unheld(uplink).is_some());
        let victim = IpAddr::V6(synthesize(p("2a00:1450:3::/96"), Ipv4Addr::new(10, 0, 0, 1)));
        for expect_after in [true, false] {
            let t = std::thread::spawn(ask);
            std::thread::sleep(Duration::from_millis(500));
            assert!(unheld(uplink).is_some(), "the mark was cleared while the round ran");
            t.join().unwrap().unwrap();
            assert_eq!(unheld(uplink).is_some(), expect_after);
        }
        srv.join().unwrap();
        eprintln!("{victim} is_global = {}", crate::is_global(victim));
    }

    /// The rule on a registry: a mark made during the round (by the round, or by a router
    /// advertisement heard meanwhile) survives its end; a mark the round did not make again is
    /// replaced (cleared) when it ends; a round on another uplink leaves it alone.
    #[test]
    fn r5_a_rounds_marks_replace_the_old_ones_when_it_ends() {
        let mut r = Registry::default();
        mark_unheld(&mut r, 1, "old".into());
        round_begins(&mut r, 1);
        assert!(r.unheld.iter().any(|(s, _)| *s == 1));
        round_ends(&mut r, 1);
        assert!(r.unheld.is_empty());
        mark_unheld(&mut r, 1, "old".into());
        round_begins(&mut r, 1);
        mark_unheld(&mut r, 1, "old".into());
        round_ends(&mut r, 1);
        assert_eq!(r.unheld, vec![(1, "old".to_string())]);
        round_begins(&mut r, 2);
        round_ends(&mut r, 1);
        round_ends(&mut r, 2);
        assert_eq!(r.unheld, vec![(1, "old".to_string())]);
    }
}
