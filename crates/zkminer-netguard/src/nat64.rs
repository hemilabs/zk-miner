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
//!   the prefix is where one of those two addresses sits. Asked when the host's facts are first
//!   gathered (on the calling thread, at most [`DISCOVERY_TIMEOUT`], every server at once) and
//!   again every [`DISCOVERY_TTL`] in the background. Failure is not fatal and is logged once.
//!   A learned prefix stays learned for the life of the process (a stale one only refuses
//!   more).
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
/// Most NSPs held (configured and learned together).
pub const MAX_PREFIXES: usize = 16;
/// The name RFC 7050 asks for.
pub const IPV4ONLY_ARPA: &str = "ipv4only.arpa";
/// Its two `A` records, the well-known addresses an NSP is found by.
pub const WELL_KNOWN_V4: [Ipv4Addr; 2] =
    [Ipv4Addr::new(192, 0, 0, 170), Ipv4Addr::new(192, 0, 0, 171)];

const TYPE_AAAA: u16 = 28;
const CLASS_IN: u16 = 1;

#[derive(Debug, Default)]
struct Registry {
    configured: Vec<Prefix>,
    learned: Vec<Prefix>,
}

static REGISTRY: Mutex<Registry> = Mutex::new(Registry {
    configured: Vec::new(),
    learned: Vec::new(),
});

/// Configured ∪ learned, the well-known prefix left out: what the address predicate reads.
static CURRENT: RwLock<Option<Arc<[Prefix]>>> = RwLock::new(None);

fn publish(r: &Registry) {
    let mut all: Vec<Prefix> = r
        .configured
        .iter()
        .chain(&r.learned)
        .copied()
        .filter(|p| *p != WELL_KNOWN_PREFIX)
        .collect();
    all.sort();
    all.dedup();
    all.truncate(MAX_PREFIXES);
    *CURRENT.write().unwrap_or_else(|e| e.into_inner()) = Some(all.into());
}

/// The NSPs in force, the well-known prefix left out (empty unless configured or learned).
pub(crate) fn current() -> Arc<[Prefix]> {
    CURRENT
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
        .unwrap_or_else(|| Arc::from(Vec::new()))
}

/// The NSPs in force: configured and learned, the well-known prefix left out.
pub fn prefixes() -> Vec<Prefix> {
    current().to_vec()
}

/// The configured NSPs (`[egress] nat64_prefixes`).
pub fn configured() -> Vec<Prefix> {
    REGISTRY
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .configured
        .clone()
}

/// The learned NSPs (RFC 7050).
pub fn learned() -> Vec<Prefix> {
    REGISTRY
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .learned
        .clone()
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
    let mut r = REGISTRY.lock().unwrap_or_else(|e| e.into_inner());
    r.configured = v;
    publish(&r);
    Ok(())
}

/// Adds learned NSPs (kept for the life of the process).
pub(crate) fn add_learned(prefixes: &[Prefix]) {
    let mut r = REGISTRY.lock().unwrap_or_else(|e| e.into_inner());
    let before = r.learned.len();
    for p in prefixes {
        if check_prefix(*p).is_ok() && !r.learned.contains(p) && r.learned.len() < MAX_PREFIXES {
            r.learned.push(*p);
        }
    }
    if r.learned.len() != before {
        r.learned.sort();
        let new: Vec<String> = r.learned.iter().map(Prefix::to_string).collect();
        tracing::info!(
            "network guard: this host's DNS64 synthesizes under NAT64 prefix {}; addresses \
             under it are judged by the IPv4 address they carry",
            new.join(", ")
        );
        publish(&r);
    }
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

/// The NAT64 prefixes in force for synthesizing addresses: the configured ones, then the learned
/// ones, the well-known prefix included when it is either (the order a translator is preferred
/// in).
pub fn in_force() -> Vec<Prefix> {
    let r = REGISTRY.lock().unwrap_or_else(|e| e.into_inner());
    let mut v: Vec<Prefix> = Vec::new();
    for p in r.configured.iter().chain(&r.learned) {
        if !v.contains(p) {
            v.push(*p);
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
    let mut answered = false;
    let mut found = Vec::new();
    let mut buf = [0u8; 1500];
    while !pending.is_empty() && Instant::now() < deadline {
        let mut progressed = false;
        pending.retain(|p| loop {
            match p.sock.recv(&mut buf) {
                Ok(n) => match parse_aaaa(&buf[..n], p.id) {
                    None => continue,
                    Some(Ok(addrs)) => {
                        answered = true;
                        progressed = true;
                        found.extend(addrs.into_iter().filter_map(prefix_of_answer));
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

fn run_discovery() {
    let servers = crate::system_resolvers();
    let result = discover(&servers, DISCOVERY_TIMEOUT);
    match &result {
        Ok(found) => add_learned(found),
        Err(e) => {
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
    }
    let mut d = DISCOVERY.lock().unwrap_or_else(|e| e.into_inner());
    d.running = false;
    d.first_done = true;
    drop(d);
    FIRST_DONE.notify_all();
}

/// Learns the NSPs, process-wide, when they are due: the first call asks on this thread (at most
/// [`DISCOVERY_TIMEOUT`]), a call during that first round waits for it, and later calls start a
/// background round once the last is [`DISCOVERY_TTL`] old.
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

/// macOS: how soon a round that failed, or found no prefix, is asked again while the host has
/// IPv6 and no IPv4 route (where an unlearned prefix matters: review round 3, bypass-1).
#[cfg(target_os = "macos")]
pub const RETRY_UNSETTLED: Duration = Duration::from_secs(15);

/// macOS: the uplink discovery runs for: the facts' uplink signature (which changes with the
/// default routes, the internet interfaces and the networks the configuration daemon says the
/// services are on) and whether the host routes IPv4 and IPv6 (`[IPv4, IPv6]`).
#[cfg(target_os = "macos")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Uplink {
    pub signature: u64,
    pub routed: [bool; 2],
}

#[cfg(target_os = "macos")]
impl Uplink {
    /// IPv6 and no IPv4 route: connections to IPv4 go through NAT64, if anywhere.
    pub fn ipv6_only(&self) -> bool {
        self.routed[1] && !self.routed[0]
    }

    /// Whether a host on this uplink refuses IPv6 destinations while discovery is not `settled`
    /// ([`ensure_discovered_on`]): only with IPv6 and no IPv4 route. A dual-stack host is never
    /// refused for it (its IPv4 goes out natively; an address under a prefix not learned yet is
    /// an ordinary IPv6 address there).
    pub fn refuses_ipv6(&self, settled: bool) -> bool {
        !settled && self.ipv6_only()
    }
}

/// macOS: discovery per uplink (see [`ensure_discovered_on`]).
#[cfg(target_os = "macos")]
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

/// macOS: signalled when the first round finishes.
#[cfg(target_os = "macos")]
static ON_UPLINK_DONE: Condvar = Condvar::new();

#[cfg(target_os = "macos")]
static ON_UPLINK: Mutex<OnUplink> = Mutex::new(OnUplink {
    uplink: None,
    settled: None,
    running: false,
    first_done: false,
    attempted_at: None,
    found_nothing: false,
});

/// macOS: what [`ensure_discovered_on`] does next.
#[cfg(target_os = "macos")]
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

/// macOS: the decision [`ensure_discovered_on`] makes for a caller on `up` at `now`, from the
/// state `d` (updated: the uplink, and a round marked running when one starts). A round starts
/// when none ran yet (on the caller's thread), when the uplink signature changed (review round
/// 3, bypass-1: a new network's prefix is learned at once, not up to [`DISCOVERY_TTL`] later),
/// when the last round is [`DISCOVERY_TTL`] old, and, on a host with IPv6 and no IPv4 route,
/// [`RETRY_UNSETTLED`] after a round that failed or found nothing, or that finished on another
/// uplink. One round runs at a time; a round that finishes after the uplink changed starts
/// another.
#[cfg(target_os = "macos")]
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

/// macOS: the DNS servers a round asks, in order (review round 3, bypass-2): the active ones
/// first (`active`, the configuration daemon's global resolvers, in its order), then the rest of
/// `all`; when the host routes one family only, that family's servers alone (a server of an
/// unrouted family cannot be reached), so on a host with IPv6 and no IPv4 route a DNS64 that
/// answers only over IPv6 is never left behind IPv4 servers that cannot answer. At most
/// [`MAX_SERVERS`], cut after this ordering.
#[cfg(target_os = "macos")]
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

/// macOS: one round on uplink `up`: the configuration daemon's NAT64 prefixes, then the RFC 7050
/// query to the servers [`order_servers`] picks. Its prefixes are learned; the state notes that
/// it finished, on which uplink, and whether it found any.
#[cfg(target_os = "macos")]
fn round_on(up: Uplink) {
    let mut found_any = false;
    match crate::facts::macos_dns::nat64_prefixes() {
        Ok(found) => {
            found_any |= !found.is_empty();
            add_learned(&found);
        }
        Err(e) => tracing::debug!("network guard: NAT64 prefixes of the configuration daemon: {e}"),
    }
    let servers = crate::facts::read_system_resolvers().and_then(|all| {
        let active = crate::facts::macos_dns::global_servers()?;
        Ok(order_servers(&active, &all, up.routed, IpAddr::is_ipv6))
    });
    let result = servers
        .map_err(|e| format!("this host's DNS servers could not be read: {e}"))
        .and_then(|s| discover(&s, DISCOVERY_TIMEOUT));
    match &result {
        Ok(found) => {
            found_any |= !found.is_empty();
            add_learned(found);
        }
        Err(e) => {
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

/// macOS: notes in `d` that a round on `up` finished (`found_any`: it found a prefix); when the
/// uplink changed while it ran, a round on the new one is marked running (the caller starts it).
#[cfg(target_os = "macos")]
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

#[cfg(target_os = "macos")]
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

/// macOS: learns the NSPs for a host on uplink `up` when they are due ([`next_on`]): the first
/// call asks on this thread (at most [`DISCOVERY_TIMEOUT`]), a call during that first round waits
/// for it, later rounds run in the background. Whether discovery is settled for `up`: false while
/// the first round on a new uplink signature has not finished. The facts then refuse IPv6
/// destinations on a host with IPv6 and no IPv4 route ([`crate::Denied::Nat64Unsettled`]): until
/// the new network's prefix is known, an address under it can carry a private IPv4 address.
#[cfg(target_os = "macos")]
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

    /// macOS, review round 3, bypass-1: a round starts when the uplink signature changes (not up
    /// to [`DISCOVERY_TTL`] later), and is asked again every [`RETRY_UNSETTLED`] while a host with
    /// IPv6 and no IPv4 route has found nothing; a dual-stack host waits for the TTL; one round
    /// runs at a time, and one that finishes after the uplink changed starts another.
    #[cfg(target_os = "macos")]
    #[test]
    fn a_new_uplink_is_asked_for_its_prefix_at_once() {
        let t0 = Instant::now();
        let at = |s: u64| t0 + Duration::from_secs(s);
        let v6_only = |sig| Uplink {
            signature: sig,
            routed: [false, true],
        };
        let dual = |sig| Uplink {
            signature: sig,
            routed: [true, true],
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
    }

    /// macOS, review round 3, bypass-1, live: a new uplink signature is unsettled when it is first
    /// seen (its round runs in the background).
    #[cfg(target_os = "macos")]
    #[test]
    fn a_new_uplink_signature_is_unsettled_at_first() {
        ensure_discovered_on(Uplink {
            signature: 1,
            routed: [true, true],
        });
        // SAFETY: arc4random takes no arguments and cannot fail.
        let fresh = u64::from(unsafe { libc::arc4random() }) << 32 | 7;
        assert!(!ensure_discovered_on(Uplink {
            signature: fresh,
            routed: [true, true],
        }));
    }

    /// macOS, review round 3, bypass-2 (the reviewer's
    /// `r3_nat64_discovery_asks_only_the_first_eight_sorted_servers`): eight IPv4 servers that
    /// never answer, sorted ahead of the network's DNS64 on IPv6, hid its prefix. On a host with
    /// IPv6 and no IPv4 route the IPv6 servers are asked (the IPv4 ones cannot be reached), and on
    /// any host the active servers come first, so the DNS64 is asked and its prefix found.
    #[cfg(target_os = "macos")]
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
}
