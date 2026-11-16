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
//! the answer only ever adds an address to refuse (a forged answer can make the miner refuse one
//! more public address, nothing else). When every reflector fails for a family, a loud WARN says
//! so (once per run of failures) and the miner carries on with what its interfaces show: name the
//! public addresses in `[egress] deny_cidrs` then (or always, as a belt to these braces). A family
//! the host has no route for at all is skipped quietly: there is no public address to learn, and
//! no requester connection goes out over it either. `[egress] discover_public_addresses = false`
//! turns the queries off.
//!
//! The answers are cached process-wide: the first call blocks (at most [`DISCOVERY_TIMEOUT`]:
//! every reflector is asked at once, from the calling thread, which starts no other — the witness
//! broker gathers its facts right before a sandbox that refuses a second thread), later calls
//! return the cache and refresh it on a background thread once it is older than [`DISCOVERY_TTL`]
//! (after a failure, retried at most every [`RETRY_AFTER_FAILURE`]). The last good answer of a
//! family stays in force when a refresh fails.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// How long one reflector query may take.
pub const DISCOVERY_TIMEOUT: Duration = Duration::from_secs(2);
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

/// Every reflector, in the order asked (per family, the first that answers wins).
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

#[derive(Debug, Default)]
struct State {
    v4: Option<IpAddr>,
    v6: Option<IpAddr>,
    learned_at: Option<Instant>,
    attempted_at: Option<Instant>,
    running: bool,
    /// Whether the current failure streak of a family has been warned about (once per streak).
    warned: [bool; 2],
}

static STATE: Mutex<State> = Mutex::new(State {
    v4: None,
    v6: None,
    learned_at: None,
    attempted_at: None,
    running: false,
    warned: [false; 2],
});

fn state() -> std::sync::MutexGuard<'static, State> {
    STATE.lock().unwrap_or_else(|e| e.into_inner())
}

/// This host's public addresses (at most one per family), from the process-wide cache; see the
/// module doc for when this blocks and when it refreshes.
pub fn public_addresses() -> Vec<IpAddr> {
    let first = {
        let mut s = state();
        let first = s.attempted_at.is_none() && !s.running;
        let stale = s.learned_at.is_none_or(|t| t.elapsed() >= DISCOVERY_TTL);
        let may_retry = s
            .attempted_at
            .is_none_or(|t| t.elapsed() >= RETRY_AFTER_FAILURE);
        if first {
            s.running = true;
        } else if stale && may_retry && !s.running {
            s.running = true;
            s.attempted_at = Some(Instant::now());
            let spawned = std::thread::Builder::new()
                .name("netguard-public-addr".into())
                .spawn(|| learn(discover()));
            if spawned.is_err() {
                s.running = false;
            }
        }
        first
    };
    if first {
        state().attempted_at = Some(Instant::now());
        learn(discover());
    }
    let s = state();
    s.v4.into_iter().chain(s.v6).collect()
}

/// What one round of discovery found for a family: its public address, `None` when the host has
/// no route for the family at all (nothing to learn, and nothing a requester could reach over it),
/// or why every reflector failed.
type FamilyFound = Result<Option<IpAddr>, String>;

fn learn((v4, v6): (FamilyFound, FamilyFound)) {
    let mut guard = state();
    let s = &mut *guard;
    s.running = false;
    let mut any = false;
    for (i, (slot, got, family)) in [(&mut s.v4, v4, "IPv4"), (&mut s.v6, v6, "IPv6")]
        .into_iter()
        .enumerate()
    {
        match got {
            Ok(Some(ip)) => {
                if *slot != Some(ip) {
                    tracing::info!(
                        "network guard: this host's public {family} address is {ip}; refusing it"
                    );
                }
                *slot = Some(ip);
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
}

/// Asks every reflector at once, on this thread (no helper thread: the witness broker gathers its
/// facts single-threaded, right before a sandbox that refuses a process with a second thread), and
/// takes the first valid answer per family within [`DISCOVERY_TIMEOUT`].
fn discover() -> (FamilyFound, FamilyFound) {
    struct Pending {
        sock: UdpSocket,
        id: u16,
        v6: bool,
        what: String,
    }
    let mut found: [Option<IpAddr>; 2] = [None, None];
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
    let mut buf = [0u8; 1500];
    while !pending.is_empty() && Instant::now() < deadline {
        let mut progressed = false;
        pending.retain(|p| {
            let fam = usize::from(p.v6);
            if found[fam].is_some() {
                return false;
            }
            loop {
                match p.sock.recv(&mut buf) {
                    Ok(n) => match parse_answer(&buf[..n], p.id, p.v6) {
                        Some(Ok(ip)) => {
                            found[fam] = Some(ip);
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
    let result = |fam: usize| -> FamilyFound {
        match found[fam] {
            Some(ip) => Ok(Some(ip)),
            None if unroutable[fam] => Ok(None),
            None => Err(errors[fam].join("; ")),
        }
    };
    (result(0), result(1))
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

fn query_id() -> u16 {
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
    let mut q = Vec::with_capacity(12 + name.len() + 6);
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&0u16.to_be_bytes()); // flags: a standard query, RD clear
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
    q.extend_from_slice(&TYPE_TXT.to_be_bytes());
    q.extend_from_slice(&class.to_be_bytes());
    Ok(q)
}

fn u16_at(m: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*m.get(i)?, *m.get(i + 1)?]))
}

/// The offset just past the (possibly compressed) name at `off`.
fn skip_name(m: &[u8], mut off: usize) -> Option<usize> {
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

    /// Every reflector at once, on this thread: each family's answer is a global address of that
    /// family (or the family is unroutable here, or failed with reasons), within the timeout.
    #[test]
    fn discovery_asks_everything_at_once_on_this_thread() {
        let t = Instant::now();
        let (v4, v6) = discover();
        assert!(t.elapsed() < DISCOVERY_TIMEOUT + Duration::from_millis(500));
        for (got, six) in [(v4, false), (v6, true)] {
            match got {
                Ok(Some(ip)) => assert!(ip.is_ipv6() == six && crate::is_global(ip), "{ip}"),
                Ok(None) => eprintln!("no route for this family here"),
                Err(e) => assert!(!e.is_empty()),
            }
        }
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
