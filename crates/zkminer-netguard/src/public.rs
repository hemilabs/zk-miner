//! This host's public addresses as the internet sees them, learned from fixed reflectors (review
//! r1, fetch F1 / broker F1).
//!
//! Behind NAT the host's public IPv4 address (and, behind NAT66 or NPTv6, its public IPv6 address)
//! is on no interface, so a requester URL at it would hairpin through the router to this host or
//! to whatever the router forwards. So the host asks, at startup and again every
//! [`DISCOVERY_TTL`]: one DNS query over UDP, per address family, to a **fixed** reflector that
//! answers with the address the query came from:
//!
//! - `o-o.myaddr.l.google.com` `TXT`, asked of Google's authoritative server `ns1.google.com`
//!   (`216.239.32.10`, `2001:4860:4802:32::a`) directly (through a recursive resolver it would name
//!   the resolver);
//! - else `whoami.cloudflare` `CH TXT`, asked of `1.1.1.1` / `2606:4700:4700::1111`.
//!
//! The names and server addresses are compiled in: nothing a requester supplies chooses them, and
//! an answer only ever adds an address to refuse. **Both reflectors** of a family are asked, and
//! every address either reports is refused (their union; when they disagree, a WARN says so). An
//! address both report alike is **confirmed**, and only a confirmed address (or one in an
//! interface address's own site) gives the IPv6 site around it ([`crate::FactsOptions`]'s
//! `ipv6_site_prefix_len`): an answer forged by one reflector or by a box that redirects DNS to
//! itself can then make the miner refuse one more address, not a whole /48–/56 of someone else's
//! (review r2, R2-NG-7). When every reflector fails for a family, a loud WARN says so (once per
//! run of failures) and the miner carries on with what its interfaces show: name the public
//! addresses in `[egress] deny_cidrs` then (or always, as a belt to these braces). A family the
//! host has no route for at all is skipped quietly: there is no public address to learn, and no
//! requester connection goes out over it either. `[egress] discover_public_addresses = false`
//! turns the queries off.
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

/// How long one reflector query may take.
pub const DISCOVERY_TIMEOUT: Duration = Duration::from_secs(2);
/// Once one reflector of a family has answered, how much longer the other gets (within
/// [`DISCOVERY_TIMEOUT`]).
pub const AGREEMENT_GRACE: Duration = Duration::from_millis(500);
/// How long a call waits for a first discovery another thread is running.
pub const FIRST_DISCOVERY_WAIT: Duration = Duration::from_secs(3);
/// How long learned public addresses are trusted before they are learned again.
pub const DISCOVERY_TTL: Duration = Duration::from_secs(300);
/// How soon a failed discovery is tried again.
pub const RETRY_AFTER_FAILURE: Duration = Duration::from_secs(60);

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

/// Every reflector: two operators, each asked over IPv4 and over IPv6.
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

/// What discovery learned: every public address a reflector reported, and those both reflectors
/// of their family reported alike.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Learned {
    /// Every reported address (refused as the host's own).
    pub addresses: Vec<IpAddr>,
    /// The confirmed ones (they also give their IPv6 site).
    pub confirmed: Vec<IpAddr>,
}

/// One family's last good answer.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct FamilyAnswer {
    addresses: Vec<IpAddr>,
    confirmed: Vec<IpAddr>,
}

#[derive(Debug)]
struct State {
    families: [FamilyAnswer; 2],
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
        },
        FamilyAnswer {
            addresses: Vec::new(),
            confirmed: Vec::new(),
        },
    ],
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
/// see the module doc for when this blocks and when it refreshes.
pub fn learned() -> Learned {
    let mut s = state();
    if s.attempted_at.is_none() && !s.running {
        // The first call: discover on this thread.
        s.running = true;
        s.attempted_at = Some(Instant::now());
        drop(s);
        learn(discover());
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
    } else {
        let stale = s.learned_at.is_none_or(|t| t.elapsed() >= DISCOVERY_TTL);
        let may_retry = s
            .attempted_at
            .is_none_or(|t| t.elapsed() >= RETRY_AFTER_FAILURE);
        if stale && may_retry && !s.running {
            s.running = true;
            s.attempted_at = Some(Instant::now());
            let spawned = std::thread::Builder::new()
                .name("netguard-public-addr".into())
                .spawn(|| learn(discover()));
            if spawned.is_err() {
                s.running = false;
            }
        }
    }
    let mut out = Learned::default();
    for f in &s.families {
        out.addresses.extend(&f.addresses);
        out.confirmed.extend(&f.confirmed);
    }
    out
}

/// What one round of discovery found for a family: what its reflectors reported, `None` when the
/// host has no route for the family at all (nothing to learn, and nothing a requester could reach
/// over it), or why every reflector failed.
type FamilyFound = Result<Option<FamilyAnswer>, String>;

fn learn((v4, v6): (FamilyFound, FamilyFound)) {
    let mut guard = state();
    let s = &mut *guard;
    s.running = false;
    s.first_done = true;
    let mut any = false;
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
                }
                s.families[i] = answer;
                s.warned[i] = false;
                any = true;
            }
            Ok(None) => {
                tracing::debug!("network guard: no {family} route, so no public {family} address");
                any = true;
            }
            Err(e) if !s.warned[i] => {
                s.warned[i] = true;
                tracing::warn!(
                    "network guard: could not learn this host's public {family} address ({e}). \
                     If it sits behind NAT, a requester's URL at that address would reach this \
                     host or its router: list it in [egress] deny_cidrs. The last address learned \
                     stays refused; retrying in the background"
                );
            }
            Err(e) => tracing::debug!("network guard: public {family} address: {e}"),
        }
    }
    if any {
        s.learned_at = Some(Instant::now());
    }
    drop(guard);
    FIRST_DONE.notify_all();
}

/// One family's answers, `(reflector name, address)`, as [`FamilyAnswer`]: the union, and what
/// every reflector that answered reported alike when at least two did. Warns when they disagree.
fn agree(family: &str, answers: &[(&'static str, IpAddr)]) -> FamilyAnswer {
    let mut addresses: Vec<IpAddr> = answers.iter().map(|(_, a)| *a).collect();
    addresses.sort();
    addresses.dedup();
    let mut names: Vec<&str> = answers.iter().map(|(n, _)| *n).collect();
    names.sort();
    names.dedup();
    let confirmed = if names.len() >= 2 && addresses.len() == 1 {
        addresses.clone()
    } else {
        Vec::new()
    };
    if addresses.len() > 1 {
        let list: Vec<String> = answers
            .iter()
            .map(|(n, a)| format!("{n} says {a}"))
            .collect();
        tracing::warn!(
            "network guard: the public-address reflectors disagree about this host's {family} \
             address ({}); refusing every one, deriving no IPv6 site from them. A box that \
             redirects DNS, or a multi-homed uplink, does this",
            list.join(", ")
        );
    }
    FamilyAnswer {
        addresses,
        confirmed,
    }
}

/// Asks every reflector at once, on this thread (no helper thread: the witness broker gathers its
/// facts single-threaded, right before a sandbox that refuses a process with a second thread), and
/// takes every valid answer per family within [`DISCOVERY_TIMEOUT`] — a family's other reflector
/// gets [`AGREEMENT_GRACE`] once the first has answered.
fn discover() -> (FamilyFound, FamilyFound) {
    struct Pending {
        sock: UdpSocket,
        id: u16,
        v6: bool,
        name: &'static str,
        what: String,
    }
    let mut found: [Vec<(&'static str, IpAddr)>; 2] = [Vec::new(), Vec::new()];
    let mut errors: [Vec<String>; 2] = [Vec::new(), Vec::new()];
    // A family is unroutable when every one of its sends failed at once for want of a route.
    let mut unroutable = [true, true];
    let mut pending = Vec::new();
    for r in REFLECTORS {
        let fam = usize::from(r.server.is_ipv6());
        let what = format!("{} @{}", r.name, r.server);
        match send_query(r) {
            Ok((sock, id)) => {
                unroutable[fam] = false;
                pending.push(Pending {
                    sock,
                    id,
                    v6: r.server.is_ipv6(),
                    name: r.name,
                    what,
                });
            }
            Err(e) => {
                unroutable[fam] &= matches!(
                    e.kind(),
                    io::ErrorKind::NetworkUnreachable | io::ErrorKind::AddrNotAvailable
                );
                errors[fam].push(format!("{what}: {e}"));
            }
        }
    }
    let deadline = Instant::now() + DISCOVERY_TIMEOUT;
    // Per family: when its first answer came.
    let mut first_answer: [Option<Instant>; 2] = [None, None];
    let mut buf = [0u8; 1500];
    while !pending.is_empty() {
        let now = Instant::now();
        if now >= deadline {
            break;
        }
        let mut progressed = false;
        pending.retain(|p| {
            let fam = usize::from(p.v6);
            if first_answer[fam].is_some_and(|t| now >= t + AGREEMENT_GRACE) {
                errors[fam].push(format!("{}: no answer within the grace", p.what));
                return false;
            }
            loop {
                match p.sock.recv(&mut buf) {
                    Ok(n) => match parse_answer(&buf[..n], p.id, p.v6) {
                        Some(Ok(ip)) => {
                            found[fam].push((p.name, ip));
                            first_answer[fam].get_or_insert(Instant::now());
                            progressed = true;
                            return false;
                        }
                        Some(Err(e)) => {
                            errors[fam].push(format!("{}: {e}", p.what));
                            return false;
                        }
                        None => continue, // not an answer to this query
                    },
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => return true,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(e) => {
                        errors[fam].push(format!("{}: {e}", p.what));
                        return false;
                    }
                }
            }
        });
        if !progressed {
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    for p in &pending {
        errors[usize::from(p.v6)].push(format!("{}: no answer within the timeout", p.what));
    }
    let result = |fam: usize, family: &str| -> FamilyFound {
        if !found[fam].is_empty() {
            Ok(Some(agree(family, &found[fam])))
        } else if unroutable[fam] {
            Ok(None)
        } else {
            Err(errors[fam].join("; "))
        }
    };
    (result(0, "IPv4"), result(1, "IPv6"))
}

/// A non-blocking UDP socket connected to `r`'s server, with its query sent, and the query's id.
fn send_query(r: &Reflector) -> io::Result<(UdpSocket, u16)> {
    let local: SocketAddr = if r.server.is_ipv6() {
        (Ipv6Addr::UNSPECIFIED, 0).into()
    } else {
        (Ipv4Addr::UNSPECIFIED, 0).into()
    };
    let sock = UdpSocket::bind(local)?;
    sock.connect((r.server, 53))?;
    let id = query_id();
    sock.send(&build_query(id, r.name, r.class)?)?;
    sock.set_nonblocking(true)?;
    Ok((sock, id))
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

    /// Review r2 R2-NG-7: both reflectors' answers are kept (their union), and an address is
    /// confirmed only when two reflectors report it alike.
    #[test]
    fn answers_are_united_and_confirmed_only_by_agreement() {
        let g = "o-o.myaddr.l.google.com";
        let c = "whoami.cloudflare";
        let a = |s: &str| s.parse::<IpAddr>().unwrap();
        let both = agree("IPv6", &[(g, a("2606:a300::5")), (c, a("2606:a300::5"))]);
        assert_eq!(both.addresses, vec![a("2606:a300::5")]);
        assert_eq!(both.confirmed, vec![a("2606:a300::5")]);
        let one = agree("IPv6", &[(c, a("2606:4700:4700::64"))]);
        assert_eq!(one.addresses, vec![a("2606:4700:4700::64")]);
        assert!(one.confirmed.is_empty());
        let split = agree("IPv4", &[(g, a("203.0.114.9")), (c, a("198.51.99.7"))]);
        assert_eq!(split.addresses, vec![a("198.51.99.7"), a("203.0.114.9")]);
        assert!(split.confirmed.is_empty());
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
