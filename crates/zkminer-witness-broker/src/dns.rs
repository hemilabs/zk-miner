//! A minimal DNS stub resolver for operator endpoint host names (plan §14.7). It runs in the
//! **miner**, inside the connector ([`crate::connector`]): the sandboxed broker resolves nothing and
//! has no socket to resolve with (review r2 F5).
//!
//! It does not use the system resolver: `getaddrinfo` reads `/etc/hosts` and `/etc/nsswitch.conf`
//! and may load NSS modules (mDNS, LLMNR, split-horizon). Instead it asks the servers of `[dns]
//! servers` (default: the `nameserver` lines of `/etc/resolv.conf`, read when the connector starts)
//! directly, over **TCP** (RFC 1035 §4.2.2, RFC 7766):
//!
//! - one `A` and one `AAAA` query per resolution, recursion desired, EDNS(0) with no options (no
//!   client subnet);
//! - a fresh connection per query, made with `socket(SOCK_STREAM)` and `connect` only (no `bind`);
//!   each message carries its 2-byte length prefix; a random 16-bit id; the connection is closed
//!   after the one answer;
//! - every answer is validated: the id, `QR`, opcode 0, one question echoing ours exactly, record
//!   bounds, compression pointers that only point backwards; over our own connection an answer
//!   with another id or question is an error, as is one with `TC` set (TCP has no truncation: the
//!   length prefix carries answers up to 65,535 bytes); `NXDOMAIN` is an empty answer; other error
//!   codes move to the next server;
//! - only `A`/`AAAA` records of class `IN` owned by the queried name, or by a name a `CNAME` chain
//!   of at most 8 records (hops) from it leads to, are taken, whatever order the records come in;
//!   at most 32 addresses.
//!
//! **Names are absolute.** A query carries the endpoint's host name exactly as configured, in wire
//! form, which is always fully qualified: no `search` list, `domain` or `ndots` rule is ever
//! applied (that is a feature of the system stub, which is never called), so a name cannot be
//! answered from the operator's search domain. A trailing dot changes nothing.
//!
//! **Which hosts it dials.** Only the resolver's own server list, fixed when the connector starts:
//! nothing a job, a builder, the broker or an answer supplies ever becomes a server, and the names
//! it asks for are only the operator's endpoint host names. The connector rate-limits resolution
//! (an answer is refreshed once `reresolve_secs` old, an unresolved name retried at most every ten
//! seconds).
//!
//! What the answers are allowed to become is the connector's business: a DNS-derived address is
//! admitted only when it is global and outside the deny CIDRs, the connected prefixes and the
//! host's own addresses (netguard's public floor, in either mode). With `127.0.0.53`
//! (systemd-resolved, which also answers on TCP) as the server, that daemon's own `/etc/hosts`,
//! LLMNR and mDNS handling still applies; configure `[dns] servers` to a dedicated resolver to
//! avoid it.

use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// The DNS port.
pub const DNS_PORT: u16 = 53;
/// How long one query (connect, send, answer) may take with one server.
pub const QUERY_TIMEOUT: Duration = Duration::from_secs(2);
/// The most addresses taken from one answer.
pub const MAX_ADDRS: usize = 32;
/// The longest `CNAME` chain followed, in records.
const MAX_CNAME_HOPS: usize = 8;
/// The OPT record's payload size: meaningless over TCP, kept at the common safe value.
const EDNS_UDP_PAYLOAD: u16 = 1232;
/// How many times the server list is walked for one query.
const ROUNDS: usize = 2;

/// The record types the broker asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QType {
    A,
    Aaaa,
}

impl QType {
    fn code(self) -> u16 {
        match self {
            QType::A => 1,
            QType::Aaaa => 28,
        }
    }
}

const TYPE_CNAME: u16 = 5;
const TYPE_OPT: u16 = 41;
const CLASS_IN: u16 = 1;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DnsError {
    #[error("no DNS server is configured")]
    NoServers,
    #[error("not a valid DNS name")]
    BadName,
    #[error("socket: {0:?}")]
    Io(io::ErrorKind),
    #[error("no answer before the timeout")]
    Timeout,
    #[error("malformed answer")]
    Malformed,
    #[error("truncated answer (TC set)")]
    Truncated,
    #[error("the answer is not to our query (another id or question)")]
    NotOurs,
    #[error("server answered with rcode {0}")]
    Rcode(u8),
}

impl From<io::Error> for DnsError {
    fn from(e: io::Error) -> Self {
        DnsError::Io(e.kind())
    }
}

/// `name` in wire form (lowercase labels, root label last). Labels are 1–63 bytes of
/// `[a-z0-9_-]`; the whole name at most 255 bytes on the wire. A trailing dot is ignored.
pub fn encode_name(name: &str) -> Result<Vec<u8>, DnsError> {
    let name = name.strip_suffix('.').unwrap_or(name);
    if name.is_empty() {
        return Err(DnsError::BadName);
    }
    let mut out = Vec::with_capacity(name.len() + 2);
    for label in name.split('.') {
        let ok = !label.is_empty()
            && label.len() <= 63
            && label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
        if !ok {
            return Err(DnsError::BadName);
        }
        out.push(label.len() as u8);
        out.extend(label.bytes().map(|b| b.to_ascii_lowercase()));
    }
    out.push(0);
    if out.len() > 255 {
        return Err(DnsError::BadName);
    }
    Ok(out)
}

/// A query for `qname` (wire form, from [`encode_name`]) with id `id`: recursion desired, one
/// question, an EDNS(0) OPT record without options.
pub fn build_query(id: u16, qname: &[u8], qtype: QType) -> Vec<u8> {
    let mut q = Vec::with_capacity(12 + qname.len() + 4 + 11);
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&0x0100u16.to_be_bytes()); // RD
    q.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    q.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    q.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    q.extend_from_slice(&1u16.to_be_bytes()); // ARCOUNT (OPT)
    q.extend_from_slice(qname);
    q.extend_from_slice(&qtype.code().to_be_bytes());
    q.extend_from_slice(&CLASS_IN.to_be_bytes());
    // OPT: root name, type 41, class = UDP payload size, TTL 0 (no DO), no rdata.
    q.push(0);
    q.extend_from_slice(&TYPE_OPT.to_be_bytes());
    q.extend_from_slice(&EDNS_UDP_PAYLOAD.to_be_bytes());
    q.extend_from_slice(&0u32.to_be_bytes());
    q.extend_from_slice(&0u16.to_be_bytes());
    q
}

/// Why a message was not taken.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rejected {
    /// Not an answer to this query (another id or question).
    NotOurs,
    /// An answer to this query that is unusable: try the next server.
    Bad(DnsError),
}

fn u16_at(m: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*m.get(i)?, *m.get(i + 1)?]))
}

/// Reads a (possibly compressed) name at `off`: its lowercase wire form and the offset just past
/// it in the record. Pointers must point strictly backwards; at most 255 bytes and 128 labels.
fn read_name(m: &[u8], mut off: usize) -> Option<(Vec<u8>, usize)> {
    let mut out = Vec::new();
    let mut end = None;
    let mut labels = 0;
    loop {
        let len = *m.get(off)?;
        match len >> 6 {
            0 => {
                if len == 0 {
                    out.push(0);
                    return Some((out, end.unwrap_or(off + 1)));
                }
                let l = usize::from(len);
                let label = m.get(off + 1..off + 1 + l)?;
                out.push(len);
                out.extend(label.iter().map(u8::to_ascii_lowercase));
                if out.len() > 255 {
                    return None;
                }
                labels += 1;
                if labels > 128 {
                    return None;
                }
                off += 1 + l;
            }
            3 => {
                let ptr = usize::from(u16_at(m, off)? & 0x3fff);
                if ptr >= off {
                    return None;
                }
                end.get_or_insert(off + 2);
                off = ptr;
            }
            _ => return None,
        }
    }
}

struct Record {
    owner: Vec<u8>,
    rtype: u16,
    class: u16,
    rdata: (usize, usize),
}

/// Validates `msg` as the answer to query `id` for `qname`/`qtype` and returns the addresses it
/// gives for the name (empty for `NXDOMAIN` or no records).
pub fn parse_answer(msg: &[u8], id: u16, qname: &[u8], qtype: QType) -> Result<Vec<IpAddr>, Rejected> {
    let bad = |e| Err(Rejected::Bad(e));
    if msg.len() < 12 || u16_at(msg, 0) != Some(id) {
        return Err(Rejected::NotOurs);
    }
    let flags = u16_at(msg, 2).ok_or(Rejected::NotOurs)?;
    let qd = u16_at(msg, 4).ok_or(Rejected::NotOurs)?;
    if flags & 0x8000 == 0 || qd != 1 {
        return Err(Rejected::NotOurs);
    }
    // The question must echo ours exactly.
    let Some((name, mut off)) = read_name(msg, 12) else { return Err(Rejected::NotOurs) };
    if name != qname || u16_at(msg, off) != Some(qtype.code()) || u16_at(msg, off + 2) != Some(CLASS_IN) {
        return Err(Rejected::NotOurs);
    }
    off += 4;
    if (flags >> 11) & 0xf != 0 {
        return bad(DnsError::Malformed);
    }
    if flags & 0x0200 != 0 {
        return bad(DnsError::Truncated);
    }
    match (flags & 0xf) as u8 {
        0 => {}
        3 => return Ok(Vec::new()), // NXDOMAIN
        r => return bad(DnsError::Rcode(r)),
    }
    let an = usize::from(u16_at(msg, 6).ok_or(Rejected::Bad(DnsError::Malformed))?);
    let mut records = Vec::with_capacity(an.min(64));
    for _ in 0..an {
        let Some((owner, o)) = read_name(msg, off) else { return bad(DnsError::Malformed) };
        let (Some(rtype), Some(class), Some(rdlen)) = (u16_at(msg, o), u16_at(msg, o + 2), u16_at(msg, o + 8)) else {
            return bad(DnsError::Malformed);
        };
        let start = o + 10;
        let end = start + usize::from(rdlen);
        if end > msg.len() {
            return bad(DnsError::Malformed);
        }
        records.push(Record { owner, rtype, class, rdata: (start, end) });
        off = end;
    }
    // The names that stand for the query: it, and every CNAME target at most MAX_CNAME_HOPS
    // records from it. Each pass follows one hop, from the names the previous pass reached only
    // (`names[frontier]`), so a chain listed in order is not followed further in one pass.
    let mut names = vec![qname.to_vec()];
    let mut frontier = 0..1;
    for _ in 0..MAX_CNAME_HOPS {
        let reached = names.len();
        for r in records.iter().filter(|r| r.rtype == TYPE_CNAME && r.class == CLASS_IN) {
            if !names[frontier.clone()].contains(&r.owner) {
                continue;
            }
            let Some((target, end)) = read_name(msg, r.rdata.0) else { return bad(DnsError::Malformed) };
            if end != r.rdata.1 {
                return bad(DnsError::Malformed);
            }
            if !names.contains(&target) {
                names.push(target);
            }
        }
        if names.len() == reached {
            break;
        }
        frontier = reached..names.len();
    }
    let mut out = Vec::new();
    for r in records.iter().filter(|r| r.rtype == qtype.code() && r.class == CLASS_IN && names.contains(&r.owner)) {
        let data = &msg[r.rdata.0..r.rdata.1];
        let ip = match (qtype, data.len()) {
            (QType::A, 4) => IpAddr::V4(Ipv4Addr::new(data[0], data[1], data[2], data[3])),
            (QType::Aaaa, 16) => IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(data).expect("16 bytes"))),
            _ => return bad(DnsError::Malformed),
        };
        if !out.contains(&ip) {
            out.push(ip);
        }
        if out.len() == MAX_ADDRS {
            break;
        }
    }
    Ok(out)
}

/// `query` with its 2-byte length prefix (RFC 1035 §4.2.2).
fn framed(query: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(2 + query.len());
    m.extend_from_slice(&(query.len() as u16).to_be_bytes());
    m.extend_from_slice(query);
    m
}

/// What one TCP exchange's answer means for the query: over our own connection there is exactly
/// one message, so an answer to another query is an error too.
fn judge(answer: &[u8], id: u16, qname: &[u8], qtype: QType) -> Result<Vec<IpAddr>, DnsError> {
    match parse_answer(answer, id, qname, qtype) {
        Ok(v) => Ok(v),
        Err(Rejected::NotOurs) => Err(DnsError::NotOurs),
        Err(Rejected::Bad(e)) => Err(e),
    }
}

fn timed_out(e: &io::Error) -> bool {
    matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut)
}

fn random_id() -> u16 {
    let mut b = [0u8; 2];
    // SAFETY: getrandom into a 2-byte buffer.
    let n = unsafe { libc::getrandom(b.as_mut_ptr().cast(), 2, 0) };
    if n != 2 {
        // Not reached on Linux ≥ 3.17; the time is a poor but harmless fallback (the id is one of
        // several defences: the connected socket and the exact question are the others).
        let t = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
        return t.subsec_nanos() as u16;
    }
    u16::from_ne_bytes(b)
}

/// The resolver: an ordered list of servers and a per-query timeout.
#[derive(Debug, Clone)]
pub struct Resolver {
    servers: Vec<SocketAddr>,
    timeout: Duration,
}

impl Resolver {
    pub fn new(servers: Vec<SocketAddr>, timeout: Duration) -> Self {
        Self { servers, timeout }
    }

    pub fn servers(&self) -> &[SocketAddr] {
        &self.servers
    }

    /// `A` and `AAAA` for `host`, blocking (before the sandbox, single-threaded). An error only
    /// when neither query got a usable answer.
    pub fn resolve_blocking(&self, host: &str) -> Result<Vec<IpAddr>, DnsError> {
        let qname = encode_name(host)?;
        let a = self.query_blocking(&qname, QType::A);
        let aaaa = self.query_blocking(&qname, QType::Aaaa);
        combine(a, aaaa)
    }

    /// `A` and `AAAA` for `host` (concurrently).
    pub async fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, DnsError> {
        let qname = encode_name(host)?;
        let (a, aaaa) = tokio::join!(self.query(&qname, QType::A), self.query(&qname, QType::Aaaa));
        combine(a, aaaa)
    }

    fn query_blocking(&self, qname: &[u8], qtype: QType) -> Result<Vec<IpAddr>, DnsError> {
        let mut last = DnsError::NoServers;
        for _ in 0..ROUNDS {
            for &server in &self.servers {
                match self.ask_blocking(server, qname, qtype) {
                    Ok(v) => return Ok(v),
                    Err(e) => last = e,
                }
            }
        }
        Err(last)
    }

    /// One query to one server over a fresh TCP connection (`socket` + `connect`; std makes no
    /// `bind`), within the timeout.
    fn ask_blocking(&self, server: SocketAddr, qname: &[u8], qtype: QType) -> Result<Vec<IpAddr>, DnsError> {
        let deadline = Instant::now() + self.timeout;
        let left = || {
            let l = deadline.saturating_duration_since(Instant::now());
            if l.is_zero() {
                Err(DnsError::Timeout)
            } else {
                Ok(l)
            }
        };
        let to_dns = |e: io::Error| if timed_out(&e) { DnsError::Timeout } else { e.into() };
        let mut sock = TcpStream::connect_timeout(&server, left()?).map_err(to_dns)?;
        let id = random_id();
        sock.set_write_timeout(Some(left()?))?;
        sock.write_all(&framed(&build_query(id, qname, qtype))).map_err(to_dns)?;
        let mut len = [0u8; 2];
        sock.set_read_timeout(Some(left()?))?;
        sock.read_exact(&mut len).map_err(to_dns)?;
        let mut answer = vec![0u8; usize::from(u16::from_be_bytes(len))];
        sock.set_read_timeout(Some(left()?))?;
        sock.read_exact(&mut answer).map_err(to_dns)?;
        judge(&answer, id, qname, qtype)
    }

    async fn query(&self, qname: &[u8], qtype: QType) -> Result<Vec<IpAddr>, DnsError> {
        let mut last = DnsError::NoServers;
        for _ in 0..ROUNDS {
            for &server in &self.servers {
                match self.ask(server, qname, qtype).await {
                    Ok(v) => return Ok(v),
                    Err(e) => last = e,
                }
            }
        }
        Err(last)
    }

    /// One query to one server over a fresh TCP connection (tokio: `socket(SOCK_STREAM |
    /// SOCK_NONBLOCK | SOCK_CLOEXEC, 0)` + `connect`, no `bind`), within the timeout.
    async fn ask(&self, server: SocketAddr, qname: &[u8], qtype: QType) -> Result<Vec<IpAddr>, DnsError> {
        let id = random_id();
        let exchange = async {
            let mut sock = tokio::net::TcpStream::connect(server).await?;
            sock.write_all(&framed(&build_query(id, qname, qtype))).await?;
            let len = sock.read_u16().await?;
            let mut answer = vec![0u8; usize::from(len)];
            sock.read_exact(&mut answer).await?;
            judge(&answer, id, qname, qtype)
        };
        tokio::time::timeout(self.timeout, exchange).await.unwrap_or(Err(DnsError::Timeout))
    }
}

fn combine(a: Result<Vec<IpAddr>, DnsError>, aaaa: Result<Vec<IpAddr>, DnsError>) -> Result<Vec<IpAddr>, DnsError> {
    match (a, aaaa) {
        (Err(e), Err(_)) => Err(e),
        (a, aaaa) => {
            let mut v = a.unwrap_or_default();
            for ip in aaaa.unwrap_or_default() {
                if !v.contains(&ip) && v.len() < MAX_ADDRS {
                    v.push(ip);
                }
            }
            Ok(v)
        }
    }
}

/// `ip`, `ip:port` or `[v6]:port` (port 53 when absent).
pub fn parse_server(s: &str) -> Result<SocketAddr, String> {
    if let Ok(sa) = s.parse::<SocketAddr>() {
        return Ok(sa);
    }
    s.parse::<IpAddr>().map(|ip| SocketAddr::new(ip, DNS_PORT)).map_err(|_| format!("{s:?} is not an address or address:port"))
}

/// The `nameserver` lines of a `resolv.conf` (at most three, as glibc reads; scoped IPv6
/// addresses are skipped).
pub fn parse_resolv_conf(text: &str) -> Vec<SocketAddr> {
    text.lines()
        .filter_map(|l| {
            let mut words = l.split_whitespace();
            (words.next()? == "nameserver").then_some(())?;
            words.next()?.parse::<IpAddr>().ok()
        })
        .map(|ip| SocketAddr::new(ip, DNS_PORT))
        .take(3)
        .collect()
}

/// The system's servers (`/etc/resolv.conf`); read before the sandbox, which grants no files.
pub fn system_servers() -> Vec<SocketAddr> {
    std::fs::read_to_string("/etc/resolv.conf").map(|t| parse_resolv_conf(&t)).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn answer(id: u16, qname: &[u8], qtype: QType, rcode: u8, flags_extra: u16, records: &[Vec<u8>]) -> Vec<u8> {
        let mut m = Vec::new();
        m.extend_from_slice(&id.to_be_bytes());
        m.extend_from_slice(&(0x8180u16 | flags_extra | u16::from(rcode)).to_be_bytes());
        m.extend_from_slice(&1u16.to_be_bytes());
        m.extend_from_slice(&(records.len() as u16).to_be_bytes());
        m.extend_from_slice(&[0, 0, 0, 0]);
        m.extend_from_slice(qname);
        m.extend_from_slice(&qtype.code().to_be_bytes());
        m.extend_from_slice(&CLASS_IN.to_be_bytes());
        for r in records {
            m.extend_from_slice(r);
        }
        m
    }

    /// A record whose owner is the question name (a pointer to offset 12).
    fn rr(rtype: u16, data: &[u8]) -> Vec<u8> {
        let mut r = vec![0xc0, 12];
        r.extend_from_slice(&rtype.to_be_bytes());
        r.extend_from_slice(&CLASS_IN.to_be_bytes());
        r.extend_from_slice(&60u32.to_be_bytes());
        r.extend_from_slice(&(data.len() as u16).to_be_bytes());
        r.extend_from_slice(data);
        r
    }

    #[test]
    fn names_are_checked_and_lowercased() {
        assert_eq!(encode_name("RPC.Example.com.").unwrap(), b"\x03rpc\x07example\x03com\x00");
        assert_eq!(encode_name("localhost").unwrap(), b"\x09localhost\x00");
        for bad in ["", ".", "a..b", "a b.com", "ä.com", &"x".repeat(64), &format!("{}.com", "a.".repeat(130))] {
            assert_eq!(encode_name(bad), Err(DnsError::BadName), "{bad}");
        }
        let q = build_query(0xbeef, &encode_name("a.io").unwrap(), QType::Aaaa);
        assert_eq!(&q[..12], &[0xbe, 0xef, 1, 0, 0, 1, 0, 0, 0, 0, 0, 1]);
        assert_eq!(&q[12..22], b"\x01a\x02io\x00\x00\x1c\x00\x01");
        assert_eq!(&q[22..], &[0, 0, 41, 0x04, 0xd0, 0, 0, 0, 0, 0, 0]);
    }

    /// Review r1 fetch F2, for the broker's resolver: the wire name is the configured name, never
    /// a search-list expansion, with or without a trailing dot.
    #[test]
    fn queries_carry_the_absolute_name_only() {
        let q = build_query(1, &encode_name("secrets.zzz").unwrap(), QType::A);
        assert_eq!(&q[12..q.len() - 15], b"\x07secrets\x03zzz\x00");
        assert_eq!(encode_name("secrets.zzz.").unwrap(), encode_name("secrets.zzz").unwrap());
    }

    #[test]
    fn answers_are_validated() {
        let q = encode_name("rpc.example.com").unwrap();
        let ok = answer(7, &q, QType::A, 0, 0, &[rr(1, &[8, 8, 8, 8]), rr(1, &[1, 1, 1, 1]), rr(1, &[8, 8, 8, 8])]);
        assert_eq!(parse_answer(&ok, 7, &q, QType::A).unwrap(), vec![IpAddr::from([8, 8, 8, 8]), IpAddr::from([1, 1, 1, 1])]);
        // Another id, question or type: not ours.
        assert_eq!(parse_answer(&ok, 8, &q, QType::A), Err(Rejected::NotOurs));
        assert_eq!(parse_answer(&ok, 7, &encode_name("rpc.example.org").unwrap(), QType::A), Err(Rejected::NotOurs));
        assert_eq!(parse_answer(&ok, 7, &q, QType::Aaaa), Err(Rejected::NotOurs));
        let mut query = ok.clone();
        query[2] &= 0x7f; // QR clear: a query, not an answer
        assert_eq!(parse_answer(&query, 7, &q, QType::A), Err(Rejected::NotOurs));
        // NXDOMAIN is empty; SERVFAIL and truncation are errors.
        assert_eq!(parse_answer(&answer(7, &q, QType::A, 3, 0, &[]), 7, &q, QType::A).unwrap(), Vec::<IpAddr>::new());
        assert_eq!(parse_answer(&answer(7, &q, QType::A, 2, 0, &[]), 7, &q, QType::A), Err(Rejected::Bad(DnsError::Rcode(2))));
        assert_eq!(parse_answer(&answer(7, &q, QType::A, 0, 0x0200, &[]), 7, &q, QType::A), Err(Rejected::Bad(DnsError::Truncated)));
        // A record of the wrong size, or cut short.
        assert!(parse_answer(&answer(7, &q, QType::A, 0, 0, &[rr(1, &[1, 2, 3])]), 7, &q, QType::A).is_err());
        let mut cut = ok.clone();
        cut.truncate(cut.len() - 2);
        assert_eq!(parse_answer(&cut, 7, &q, QType::A), Err(Rejected::Bad(DnsError::Malformed)));
        // Records for another owner are ignored.
        let mut other = b"\x05other\x00".to_vec();
        other.extend_from_slice(&rr(1, &[9, 9, 9, 9])[2..]);
        assert_eq!(parse_answer(&answer(7, &q, QType::A, 0, 0, &[other]), 7, &q, QType::A).unwrap(), Vec::<IpAddr>::new());
    }

    #[test]
    fn cname_chains_are_followed_from_the_question_only() {
        let q = encode_name("rpc.example.com").unwrap();
        // rpc.example.com CNAME edge.cdn.net; edge.cdn.net A 8.8.4.4; stray.net A 9.9.9.9.
        let target = encode_name("edge.cdn.net").unwrap();
        let mut edge = target.clone();
        edge.extend_from_slice(&1u16.to_be_bytes());
        edge.extend_from_slice(&CLASS_IN.to_be_bytes());
        edge.extend_from_slice(&60u32.to_be_bytes());
        edge.extend_from_slice(&4u16.to_be_bytes());
        edge.extend_from_slice(&[8, 8, 4, 4]);
        let mut stray = encode_name("stray.net").unwrap();
        stray.extend_from_slice(&edge[target.len()..edge.len() - 4]);
        stray.extend_from_slice(&[9, 9, 9, 9]);
        let m = answer(1, &q, QType::A, 0, 0, &[rr(TYPE_CNAME, &target), edge, stray]);
        assert_eq!(parse_answer(&m, 1, &q, QType::A).unwrap(), vec![IpAddr::from([8, 8, 4, 4])]);
    }

    /// A record owned by `owner` (written out, no compression).
    fn owned(owner: &str, rtype: u16, data: &[u8]) -> Vec<u8> {
        let mut r = encode_name(owner).unwrap();
        r.extend_from_slice(&rr(rtype, data)[2..]);
        r
    }

    /// A chain of `hops` CNAME records from the question to a name with an A record, listed in
    /// order or reversed: followed up to MAX_CNAME_HOPS records, not one more, either way.
    #[test]
    fn cname_chains_are_limited_in_hops() {
        let q = encode_name("rpc.example.com").unwrap();
        let chain = |hops: usize, reversed: bool| {
            let name = |i: usize| if i == 0 { "rpc.example.com".to_string() } else { format!("c{i}.cdn.net") };
            let mut records: Vec<Vec<u8>> =
                (0..hops).map(|i| owned(&name(i), TYPE_CNAME, &encode_name(&name(i + 1)).unwrap())).collect();
            if reversed {
                records.reverse();
            }
            records.push(owned(&name(hops), 1, &[8, 8, 4, 4]));
            parse_answer(&answer(1, &q, QType::A, 0, 0, &records), 1, &q, QType::A).unwrap()
        };
        for reversed in [false, true] {
            for hops in 1..=MAX_CNAME_HOPS {
                assert_eq!(chain(hops, reversed), vec![IpAddr::from([8, 8, 4, 4])], "{hops} hops, reversed {reversed}");
            }
            for hops in [MAX_CNAME_HOPS + 1, MAX_CNAME_HOPS + 2, 20] {
                assert_eq!(chain(hops, reversed), Vec::<IpAddr>::new(), "{hops} hops, reversed {reversed}");
            }
        }
    }

    #[test]
    fn compression_pointers_never_loop() {
        let q = encode_name("a.io").unwrap();
        // An answer whose owner points at itself.
        let mut self_ptr = answer(1, &q, QType::A, 0, 0, &[]);
        self_ptr[7] = 1;
        let at = self_ptr.len() as u16;
        self_ptr.extend_from_slice(&(0xc000 | at).to_be_bytes());
        self_ptr.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 1, 2, 3, 4]);
        assert_eq!(parse_answer(&self_ptr, 1, &q, QType::A), Err(Rejected::Bad(DnsError::Malformed)));
    }

    #[test]
    fn server_strings_and_resolv_conf() {
        assert_eq!(parse_server("9.9.9.9").unwrap(), "9.9.9.9:53".parse().unwrap());
        assert_eq!(parse_server("127.0.0.1:5353").unwrap(), "127.0.0.1:5353".parse().unwrap());
        assert_eq!(parse_server("2620:fe::fe").unwrap(), "[2620:fe::fe]:53".parse().unwrap());
        assert_eq!(parse_server("[2620:fe::fe]:54").unwrap(), "[2620:fe::fe]:54".parse().unwrap());
        assert!(parse_server("dns.example").is_err());
        let conf = "# c\nnameserver 127.0.0.53\nsearch .\nnameserver fe80::1%eth0\n nameserver ::1\nnameserver 1.1.1.1\nnameserver 8.8.8.8\n";
        assert_eq!(
            parse_resolv_conf(conf),
            vec!["127.0.0.53:53".parse().unwrap(), "[::1]:53".parse().unwrap(), "1.1.1.1:53".parse().unwrap()]
        );
    }

    #[test]
    fn a_resolver_without_servers_fails() {
        let r = Resolver::new(vec![], QUERY_TIMEOUT);
        assert_eq!(r.resolve_blocking("a.io"), Err(DnsError::NoServers));
    }

    #[test]
    fn queries_are_length_prefixed() {
        let q = build_query(0xbeef, &encode_name("a.io").unwrap(), QType::A);
        let f = framed(&q);
        assert_eq!(u16::from_be_bytes([f[0], f[1]]) as usize, q.len());
        assert_eq!(&f[2..], &q[..]);
    }

    /// A TCP server that answers every query on a connection with `respond(query)` (framed), or
    /// stays silent when it returns `None`.
    async fn tcp_server(respond: impl Fn(&[u8]) -> Option<Vec<u8>> + Send + Sync + 'static) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let respond = std::sync::Arc::new(respond);
        let task = tokio::spawn(async move {
            loop {
                let Ok((mut s, _)) = l.accept().await else { return };
                let respond = respond.clone();
                tokio::spawn(async move {
                    let Ok(len) = s.read_u16().await else { return };
                    let mut q = vec![0u8; usize::from(len)];
                    if s.read_exact(&mut q).await.is_err() {
                        return;
                    }
                    match respond(&q) {
                        Some(a) => {
                            let _ = s.write_all(&framed(&a)).await;
                        }
                        None => tokio::time::sleep(Duration::from_secs(30)).await,
                    }
                });
            }
        });
        (addr, task)
    }

    /// The question of `query` and an answer to it with `records`.
    fn reply(query: &[u8], id_delta: u16, records: &[Vec<u8>]) -> Vec<u8> {
        let id = u16::from_be_bytes([query[0], query[1]]).wrapping_add(id_delta);
        let qname = read_name(query, 12).unwrap().0;
        let qtype = if u16_at(query, 12 + qname.len()) == Some(28) { QType::Aaaa } else { QType::A };
        answer(id, &qname, qtype, 0, 0, records)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn resolves_over_tcp_blocking_and_async() {
        let dns = crate::testkit::TestDns::start(&[("rpc.test", &["192.0.2.7", "2001:db8::7"])]).await;
        let r = Resolver::new(vec![dns.addr], QUERY_TIMEOUT);
        let want: Vec<IpAddr> = vec!["192.0.2.7".parse().unwrap(), "2001:db8::7".parse().unwrap()];
        assert_eq!(r.resolve("RPC.test.").await.unwrap(), want);
        let rb = r.clone();
        let got = tokio::task::spawn_blocking(move || rb.resolve_blocking("rpc.test")).await.unwrap();
        assert_eq!(got.unwrap(), want);
        assert_eq!(r.resolve("other.test").await.unwrap(), Vec::<IpAddr>::new(), "NXDOMAIN");
        assert_eq!(dns.queries(), 6);
    }

    /// Answers longer than any UDP payload arrive whole: TCP has no truncation.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn large_answers_arrive_whole() {
        let ips: Vec<String> = (0..100u16).map(|i| format!("2001:db8::{i:x}")).collect();
        let ips: Vec<&str> = ips.iter().map(String::as_str).collect();
        let dns = crate::testkit::TestDns::start(&[("big.test", &ips)]).await;
        let r = Resolver::new(vec![dns.addr], QUERY_TIMEOUT);
        let got = r.resolve("big.test").await.unwrap();
        assert_eq!(got.len(), MAX_ADDRS);
        assert_eq!(got[0], "2001:db8::".parse::<IpAddr>().unwrap());
    }

    /// Over our own connection, an answer to another query is an error (and the next server is
    /// asked); a silent server times out; a closed port moves on.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn misbehaving_servers() {
        let (wrong_id, _t1) = tcp_server(|q| Some(reply(q, 1, &[rr(1, &[8, 8, 8, 8])]))).await;
        let (silent, _t2) = tcp_server(|_| None).await;
        let (good, _t3) = tcp_server(|q| Some(reply(q, 0, &[rr(1, &[9, 9, 9, 9])]))).await;
        let closed = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap()
        };
        let q = encode_name("x.test").unwrap();
        let fast = Duration::from_millis(300);
        assert_eq!(Resolver::new(vec![wrong_id], fast).query(&q, QType::A).await, Err(DnsError::NotOurs));
        assert_eq!(Resolver::new(vec![silent], fast).query(&q, QType::A).await, Err(DnsError::Timeout));
        assert!(matches!(Resolver::new(vec![closed], fast).query(&q, QType::A).await, Err(DnsError::Io(_))));
        let r = Resolver::new(vec![closed, wrong_id, silent, good], fast);
        assert_eq!(r.query(&q, QType::A).await.unwrap(), vec![IpAddr::from([9, 9, 9, 9])]);
        let rb = Resolver::new(vec![wrong_id, good], fast);
        let qb = q.clone();
        let got = tokio::task::spawn_blocking(move || rb.query_blocking(&qb, QType::A)).await.unwrap();
        assert_eq!(got.unwrap(), vec![IpAddr::from([9, 9, 9, 9])]);
        let rs = Resolver::new(vec![silent], fast);
        let t0 = Instant::now();
        let got = tokio::task::spawn_blocking(move || rs.query_blocking(&q, QType::A)).await.unwrap();
        assert_eq!(got, Err(DnsError::Timeout));
        assert!(t0.elapsed() < Duration::from_secs(3), "{:?}", t0.elapsed());
    }

    proptest! {
        #[test]
        fn parse_answer_never_panics(mut bytes in prop::collection::vec(any::<u8>(), 0..300), keep_header in any::<bool>()) {
            let q = encode_name("a.io").unwrap();
            if keep_header && bytes.len() >= 22 {
                bytes[..2].copy_from_slice(&[0, 1]);
                bytes[2] |= 0x80;
                bytes[4..6].copy_from_slice(&[0, 1]);
                bytes[12..22].copy_from_slice(b"\x01a\x02io\x00\x00\x01\x00\x01");
            }
            let _ = parse_answer(&bytes, 1, &q, QType::A);
        }
    }
}
