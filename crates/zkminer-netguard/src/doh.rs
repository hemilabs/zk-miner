//! Requester names resolved with netguard's own DNS-over-HTTPS client, in public mode.
//!
//! The system resolver (getaddrinfo) answers from `/etc/hosts`, NSS modules (mDNS, LLMNR,
//! `myhostname`, LDAP …), and the local stub, which forwards to the LAN's, the company's or the
//! ISP's resolver: split-horizon zones answer internal names with internal (sometimes global)
//! addresses, and whether a name resolves is itself an oracle on the operator's network. So in
//! public mode no requester name — a storage URI's host, a redirect's, the fixed IPFS and Arweave
//! gateways' — goes there. [`DohLookup`] asks public resolvers over HTTPS, addressed by IP literal
//! (no name to resolve first), with rustls and the compiled-in web roots verifying the resolver's
//! certificate for that address:
//!
//! - **the resolvers** ([`DEFAULT_SERVERS`]): Cloudflare (`1.1.1.1`, `2606:4700:4700::1111`,
//!   `1.0.0.1`), Google (`8.8.8.8`, `2001:4860:4860::8888`, `8.8.4.4`) and Quad9 (`9.9.9.9`,
//!   `2620:fe::fe`), tried in that order until one answers; `[egress] doh_resolvers` replaces the
//!   list with the operator's (each an `https` URL whose host is a global IP literal);
//! - **the query**: `A` and `AAAA` at once, recursion desired, an EDNS0 Client Subnet option with
//!   source prefix 0 (RFC 7871: the resolver must not pass this host's subnet on to the name's
//!   servers), as `GET <path>?dns=<base64url>` (RFC 8484);
//! - **the answer**: a `200` of `application/dns-message`, at most 64 KiB, whose question is the
//!   one asked; the addresses of the name and of the `CNAME` chain it starts (no other record is
//!   read); `NXDOMAIN` is "no such name";
//! - **IPv6-only hosts**: when the host routes IPv6 but not IPv4 and a NAT64 prefix is in force
//!   (configured, or learned from the host's DNS64), a name with `A` records but no `AAAA` is given
//!   the addresses a DNS64 resolver would synthesize ([`crate::nat64::synthesize`]).
//!
//! Every answer then goes through the guarded resolver's checks, as before. A resolver the floor
//! refuses (the host's own network, a route off the default path) is skipped; one of the host's
//! own DNS servers, or one on a path whose public address is not known yet, is not (it is a fixed
//! resolver, not a requester's destination).
//!
//! Developer mode keeps the system resolver: a local test network names its hosts there.

// The wire format is used by the client half only (the `client` feature).
#![cfg_attr(not(feature = "client"), allow(dead_code))]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// A DNS-over-HTTPS resolver: an IP literal, a port and a path (`https://1.1.1.1/dns-query`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DohServer {
    pub addr: SocketAddr,
    pub path: String,
}

/// The resolvers asked when `[egress] doh_resolvers` names none, in order.
pub const DEFAULT_SERVERS: &[IpAddr] = &[
    IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
    IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111)),
    IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
    IpAddr::V6(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888)),
    IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)),
    IpAddr::V6(Ipv6Addr::new(0x2620, 0xfe, 0, 0, 0, 0, 0, 0xfe)),
    IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1)),
    IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4)),
];

/// The path of the default resolvers (RFC 8484's example, which all of them serve).
pub const DEFAULT_PATH: &str = "/dns-query";

/// [`DEFAULT_SERVERS`] as servers.
pub fn default_servers() -> Vec<DohServer> {
    DEFAULT_SERVERS
        .iter()
        .map(|ip| DohServer {
            addr: SocketAddr::new(*ip, 443),
            path: DEFAULT_PATH.into(),
        })
        .collect()
}

impl DohServer {
    /// Parses an `[egress] doh_resolvers` entry: `https://<IPv4>[:port][/path]` or
    /// `https://[<IPv6>][:port][/path]`, no user information, query or fragment; the path
    /// defaults to [`DEFAULT_PATH`]. The address must be global ([`Self::check`]).
    pub fn parse(s: &str) -> Result<Self, String> {
        let bad = |why: &str| Err(format!("{s:?}: {why}"));
        let Some(rest) = s.strip_prefix("https://") else {
            return bad("a DNS-over-HTTPS resolver is an https:// URL");
        };
        if !s.bytes().all(|b| (0x21..=0x7e).contains(&b)) || s.contains(['?', '#', '@', '\\']) {
            return bad("only an IP literal, a port and a path");
        }
        let (authority, path) = match rest.find('/') {
            Some(i) => rest.split_at(i),
            None => (rest, ""),
        };
        let (host, port) = if let Some(v6) = authority.strip_prefix('[') {
            let Some((h, after)) = v6.split_once(']') else {
                return bad("an unclosed IPv6 literal");
            };
            let port = match after {
                "" => None,
                p => match p.strip_prefix(':') {
                    Some(p) => Some(p),
                    None => return bad("a malformed authority"),
                },
            };
            match h.parse::<Ipv6Addr>() {
                Ok(a) => (IpAddr::V6(a), port),
                Err(_) => return bad("the host must be an IP literal"),
            }
        } else {
            let (h, port) = match authority.split_once(':') {
                Some((h, p)) => (h, Some(p)),
                None => (authority, None),
            };
            // Four decimal octets only (no `1.1`, `0x01010101`).
            match h.parse::<Ipv4Addr>() {
                Ok(a) if a.to_string() == h => (IpAddr::V4(a), port),
                _ => return bad("the host must be an IP literal (four decimal octets, or [IPv6])"),
            }
        };
        let port = match port {
            None => 443,
            Some(p) => match p.parse::<u16>() {
                Ok(n) if n != 0 && p.bytes().all(|b| b.is_ascii_digit()) => n,
                _ => return bad("a malformed or zero port"),
            },
        };
        let path = if path.is_empty() || path == "/" {
            DEFAULT_PATH.to_string()
        } else {
            path.to_string()
        };
        let d = DohServer {
            addr: SocketAddr::new(host, port),
            path,
        };
        d.check().map_err(|e| format!("{s:?}: {e}"))?;
        Ok(d)
    }

    /// Refuses a resolver whose address is not global or whose path is not a plain absolute path.
    pub fn check(&self) -> Result<(), String> {
        if !crate::is_global(self.addr.ip()) {
            return Err(format!(
                "the DNS-over-HTTPS resolver {} is not a public internet address",
                self.addr.ip()
            ));
        }
        if self.addr.port() == 0
            || !self.path.starts_with('/')
            || !self
                .path
                .bytes()
                .all(|b| (0x21..=0x7e).contains(&b) && !b"?#\\".contains(&b))
        {
            return Err(format!(
                "the DNS-over-HTTPS resolver {}{} has a zero port or a malformed path",
                self.addr, self.path
            ));
        }
        Ok(())
    }

    /// The URL it is asked at, without the query.
    pub fn url(&self) -> String {
        match self.addr {
            SocketAddr::V4(a) => format!("https://{}:{}{}", a.ip(), a.port(), self.path),
            SocketAddr::V6(a) => format!("https://[{}]:{}{}", a.ip(), a.port(), self.path),
        }
    }
}

pub(crate) const TYPE_A: u16 = 1;
pub(crate) const TYPE_CNAME: u16 = 5;
pub(crate) const TYPE_AAAA: u16 = 28;
const TYPE_OPT: u16 = 41;
const CLASS_IN: u16 = 1;
/// Most answer records read, and most addresses kept, per answer.
const MAX_RECORDS: usize = 64;
const MAX_ADDRESSES: usize = 32;
/// Most `CNAME` links a name's chain may have (a longer one is an error).
const MAX_CNAME_LINKS: usize = 16;

/// A DNS query for `name` (no trailing dot) of type `qtype`, id 0 (RFC 8484 §4.1), recursion
/// desired, with an EDNS0 OPT record carrying a Client Subnet option of source prefix 0.
pub(crate) fn build_query(name: &str, qtype: u16) -> Result<Vec<u8>, String> {
    if name.is_empty() || name.len() > 253 {
        return Err("a name of 1 to 253 bytes".into());
    }
    let mut q = Vec::with_capacity(name.len() + 40);
    q.extend_from_slice(&[0, 0, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 1]);
    for label in name.split('.') {
        if label.is_empty() || label.len() > 63 || !label.is_ascii() {
            return Err(format!(
                "a malformed label in {:?}",
                crate::printable(name, 64)
            ));
        }
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0);
    q.extend_from_slice(&qtype.to_be_bytes());
    q.extend_from_slice(&CLASS_IN.to_be_bytes());
    // OPT: root name, type 41, UDP payload 4096, no extended rcode or flags, one option:
    // Client Subnet (8), 4 bytes: family 1, source prefix 0, scope 0, no address.
    q.push(0);
    q.extend_from_slice(&TYPE_OPT.to_be_bytes());
    q.extend_from_slice(&4096u16.to_be_bytes());
    q.extend_from_slice(&[0, 0, 0, 0]);
    q.extend_from_slice(&8u16.to_be_bytes());
    q.extend_from_slice(&[0, 8, 0, 4, 0, 1, 0, 0]);
    Ok(q)
}

fn u16_at(m: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*m.get(i)?, *m.get(i + 1)?]))
}

/// The (possibly compressed) name at `off`, lowercased, without a trailing dot, and the offset
/// just past it where it starts.
pub(crate) fn read_name(m: &[u8], off: usize) -> Option<(String, usize)> {
    let mut name = String::new();
    let mut at = off;
    let mut end = None;
    for _ in 0..128 {
        let len = *m.get(at)?;
        match len >> 6 {
            0 if len == 0 => {
                return Some((name, end.unwrap_or(at + 1)));
            }
            0 => {
                let label = m.get(at + 1..at + 1 + usize::from(len))?;
                // A dot inside a label would read as a label boundary: another name's text.
                if label.contains(&b'.') {
                    return None;
                }
                if !name.is_empty() {
                    name.push('.');
                }
                if name.len() + label.len() > 253 {
                    return None;
                }
                for &b in label {
                    name.push(char::from(b.to_ascii_lowercase()));
                }
                at += 1 + usize::from(len);
            }
            3 => {
                let target = usize::from(u16_at(m, at)? & 0x3fff);
                end.get_or_insert(at + 2);
                if target >= at {
                    return None; // pointers go backwards only
                }
                at = target;
            }
            _ => return None,
        }
    }
    None
}

/// The addresses a response gives for `name` (lowercase, no trailing dot) and `qtype` (`A` or
/// `AAAA`): those of the name and of the `CNAME` chain it starts. `NXDOMAIN` is `Ok(None)`; any
/// other error code, a truncated or malformed message, or another question is an error.
pub(crate) fn parse_response(
    m: &[u8],
    name: &str,
    qtype: u16,
) -> Result<Option<Vec<IpAddr>>, String> {
    // The query's id is 0 (RFC 8484 §4.1): the answer's must be too.
    if u16_at(m, 0) != Some(0) {
        return Err("an answer to another query".into());
    }
    let flags = u16_at(m, 2).ok_or("a short answer")?;
    if flags & 0x8000 == 0 {
        return Err("not a response".into());
    }
    if flags & 0x0200 != 0 {
        return Err("a truncated response".into());
    }
    match flags & 0xf {
        0 => {}
        3 => return Ok(None),
        r => return Err(format!("rcode {r}")),
    }
    if u16_at(m, 4) != Some(1) {
        return Err("not one question".into());
    }
    let an = usize::from(u16_at(m, 6).ok_or("a short answer")?);
    let (qname, off) = read_name(m, 12).ok_or("a malformed question")?;
    if qname != name || u16_at(m, off) != Some(qtype) || u16_at(m, off + 2) != Some(CLASS_IN) {
        return Err("an answer to another question".into());
    }
    let mut off = off + 4;
    let mut records: Vec<(String, u16, usize, usize)> = Vec::new();
    for _ in 0..an.min(MAX_RECORDS) {
        let (owner, o) = read_name(m, off).ok_or("a malformed answer")?;
        let rtype = u16_at(m, o).ok_or("a malformed answer")?;
        let class = u16_at(m, o + 2).ok_or("a malformed answer")?;
        let rdlen = usize::from(u16_at(m, o + 8).ok_or("a malformed answer")?);
        let start = o + 10;
        if m.len() < start + rdlen {
            return Err("a malformed answer".into());
        }
        off = start + rdlen;
        if class == CLASS_IN {
            records.push((owner, rtype, start, rdlen));
        }
    }
    // The name, and every name a CNAME of a name already in the chain points to: at most
    // MAX_CNAME_LINKS links, however the records are ordered.
    let mut chain = vec![name.to_string()];
    loop {
        let mut grew = false;
        for (owner, rtype, start, _) in &records {
            if *rtype == TYPE_CNAME && chain.contains(owner) {
                let (target, _) = read_name(m, *start).ok_or("a malformed CNAME")?;
                if !chain.contains(&target) {
                    if chain.len() > MAX_CNAME_LINKS {
                        return Err(format!("a CNAME chain longer than {MAX_CNAME_LINKS} links"));
                    }
                    chain.push(target);
                    grew = true;
                }
            }
        }
        if !grew {
            break;
        }
    }
    let mut out = Vec::new();
    for (owner, rtype, start, rdlen) in &records {
        if *rtype != qtype || !chain.contains(owner) {
            continue;
        }
        let data = &m[*start..*start + *rdlen];
        let ip = match (qtype, data.len()) {
            (TYPE_A, 4) => IpAddr::V4(Ipv4Addr::new(data[0], data[1], data[2], data[3])),
            (TYPE_AAAA, 16) => {
                IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(data).map_err(|_| "?")?))
            }
            _ => return Err("an address record of the wrong length".into()),
        };
        if !out.contains(&ip) && out.len() < MAX_ADDRESSES {
            out.push(ip);
        }
    }
    Ok(Some(out))
}

/// `b` in unpadded base64url (RFC 4648 §5), as RFC 8484 sends a query in a URL.
pub(crate) fn base64url(b: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(b.len().div_ceil(3) * 4);
    for chunk in b.chunks(3) {
        let n = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        let chars = chunk.len() + 1;
        for i in 0..chars {
            out.push(char::from(A[((n >> (18 - 6 * i)) & 63) as usize]));
        }
    }
    out
}

#[cfg(feature = "client")]
pub use client::DohLookup;

#[cfg(feature = "client")]
mod client {
    use std::io;
    use std::net::IpAddr;
    use std::sync::Arc;
    use std::time::Duration;

    use super::{base64url, build_query, parse_response, DohServer, TYPE_A, TYPE_AAAA};
    use crate::policy::{Denied, NetPolicy};
    use crate::resolve::{Lookup, LookupFuture};

    /// How long one resolver may take for one name (both queries).
    pub const PER_SERVER_TIMEOUT: Duration = Duration::from_secs(3);
    /// How long one name may take, every resolver tried.
    pub const LOOKUP_TIMEOUT: Duration = Duration::from_secs(10);
    /// The largest answer read.
    const MAX_ANSWER_BYTES: usize = 64 * 1024;

    /// The DNS-over-HTTPS lookup of public mode (see the module doc).
    #[derive(Clone)]
    pub struct DohLookup {
        policy: NetPolicy,
        servers: Arc<[DohServer]>,
        client: reqwest::Client,
    }

    impl std::fmt::Debug for DohLookup {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("DohLookup")
                .field("servers", &self.servers)
                .finish_non_exhaustive()
        }
    }

    /// reqwest's resolver for the DoH client: it is only ever handed IP-literal URLs, so any name
    /// that reaches it is refused.
    struct NoNames;

    impl reqwest::dns::Resolve for NoNames {
        fn resolve(&self, _: reqwest::dns::Name) -> reqwest::dns::Resolving {
            Box::pin(async {
                Err::<reqwest::dns::Addrs, _>("the DNS-over-HTTPS client resolves no names".into())
            })
        }
    }

    impl DohLookup {
        /// Resolving through `policy`'s `[egress] doh_resolvers` (else [`super::DEFAULT_SERVERS`]),
        /// each checked against `policy` before it is asked.
        pub fn new(policy: &NetPolicy) -> Result<Self, reqwest::Error> {
            let configured = policy.options().doh_resolvers;
            let servers = if configured.is_empty() {
                super::default_servers()
            } else {
                configured
            };
            let client = reqwest::Client::builder()
                .dns_resolver(Arc::new(NoNames))
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .use_rustls_tls()
                .http1_only()
                .no_gzip()
                .no_brotli()
                .no_deflate()
                .no_zstd()
                .user_agent(crate::USER_AGENT)
                .referer(false)
                .connect_timeout(PER_SERVER_TIMEOUT)
                .timeout(PER_SERVER_TIMEOUT)
                .build()?;
            Ok(DohLookup {
                policy: policy.clone(),
                servers: servers.into(),
                client,
            })
        }

        /// The resolvers it asks, in order.
        pub fn servers(&self) -> &[DohServer] {
            &self.servers
        }

        /// Whether `server` may be asked: the floor admits its address, or refuses it only as one
        /// of the host's own DNS servers or for a path whose public address is not known yet.
        fn usable(&self, server: &DohServer) -> Result<(), Denied> {
            match self.policy.admit(server.addr.ip()) {
                Ok(()) | Err(Denied::DnsServer(_)) | Err(Denied::PublicAddressUnknown { .. }) => {
                    Ok(())
                }
                Err(d) => Err(d),
            }
        }

        async fn ask(
            &self,
            server: &DohServer,
            name: &str,
            qtype: u16,
        ) -> Result<Option<Vec<IpAddr>>, String> {
            let q = build_query(name, qtype)?;
            let url = format!("{}?dns={}", server.url(), base64url(&q));
            let mut r = self
                .client
                .get(url)
                .header(reqwest::header::ACCEPT, "application/dns-message")
                .send()
                .await
                .map_err(|e| e.without_url().to_string())?;
            if r.status() != reqwest::StatusCode::OK {
                return Err(format!("HTTP {}", r.status()));
            }
            let ct = r
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            if !ct.starts_with("application/dns-message") {
                return Err("not a DNS message".into());
            }
            let mut body = Vec::new();
            while let Some(chunk) = r.chunk().await.map_err(|e| e.without_url().to_string())? {
                if body.len() + chunk.len() > MAX_ANSWER_BYTES {
                    return Err("an answer over 64 KiB".into());
                }
                body.extend_from_slice(&chunk);
            }
            parse_response(&body, name, qtype)
        }

        /// `name`'s addresses from the first resolver that answers (see the module doc).
        pub async fn resolve(&self, name: &str) -> io::Result<Vec<IpAddr>> {
            let name = name.trim_end_matches('.').to_ascii_lowercase();
            let mut errors = Vec::new();
            for server in self.servers.iter() {
                if let Err(d) = self.usable(server) {
                    errors.push(format!("{}: {d}", server.addr));
                    continue;
                }
                let both = async {
                    tokio::join!(
                        self.ask(server, &name, TYPE_AAAA),
                        self.ask(server, &name, TYPE_A)
                    )
                };
                let (aaaa, a) = match tokio::time::timeout(PER_SERVER_TIMEOUT, both).await {
                    Ok(r) => r,
                    Err(_) => {
                        errors.push(format!("{}: no answer in time", server.addr));
                        continue;
                    }
                };
                let (aaaa, a) = match (aaaa, a) {
                    (Err(e6), Err(e4)) => {
                        errors.push(format!("{}: {e6}; {e4}", server.addr));
                        continue;
                    }
                    (aaaa, a) => (aaaa, a),
                };
                let failed = aaaa.is_err() || a.is_err();
                let (aaaa, a) = (
                    aaaa.ok().flatten().unwrap_or_default(),
                    a.ok().flatten().unwrap_or_default(),
                );
                let synthesized = self.synthesize(&aaaa, &a);
                let mut out = aaaa;
                out.extend(a);
                out.extend(synthesized);
                if out.is_empty() {
                    if failed {
                        errors.push(format!(
                            "{}: one query failed, the other found nothing",
                            server.addr
                        ));
                        continue;
                    }
                    // NXDOMAIN, or no address of either type.
                    return Err(io::Error::new(io::ErrorKind::NotFound, "no such name"));
                }
                return Ok(out);
            }
            Err(io::Error::other(format!(
                "no DNS-over-HTTPS resolver answered ({})",
                crate::printable(&errors.join("; "), 600)
            )))
        }

        /// On a host that routes IPv6 but not IPv4, with a NAT64 prefix in force: what a DNS64
        /// resolver would answer for `a` when the name has no `AAAA` (RFC 6147).
        fn synthesize(&self, aaaa: &[IpAddr], a: &[IpAddr]) -> Vec<IpAddr> {
            if !aaaa.is_empty() || a.is_empty() {
                return Vec::new();
            }
            let facts = self.policy.facts();
            if facts.routes().routes_family(false) || !facts.routes().routes_family(true) {
                return Vec::new();
            }
            let Some(nsp) = crate::nat64::in_force().into_iter().next() else {
                return Vec::new();
            };
            a.iter()
                .filter_map(|ip| match ip {
                    IpAddr::V4(v4) => Some(IpAddr::V6(crate::nat64::synthesize(nsp, *v4))),
                    IpAddr::V6(_) => None,
                })
                .collect()
        }
    }

    impl Lookup for DohLookup {
        fn lookup(&self, host: &str) -> LookupFuture {
            let this = self.clone();
            let host = host.to_owned();
            Box::pin(async move {
                match tokio::time::timeout(LOOKUP_TIMEOUT, this.resolve(&host)).await {
                    Ok(r) => r,
                    Err(_) => Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!("resolving {:?} timed out", crate::printable(&host, 128)),
                    )),
                }
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolver_urls_parse_strictly() {
        let d = DohServer::parse("https://1.1.1.1/dns-query").unwrap();
        assert_eq!(d.addr, "1.1.1.1:443".parse().unwrap());
        assert_eq!(d.path, "/dns-query");
        assert_eq!(d.url(), "https://1.1.1.1:443/dns-query");
        let d = DohServer::parse("https://[2620:fe::fe]:8443").unwrap();
        assert_eq!(d.addr, "[2620:fe::fe]:8443".parse().unwrap());
        assert_eq!(d.path, DEFAULT_PATH);
        assert_eq!(d.url(), "https://[2620:fe::fe]:8443/dns-query");
        assert_eq!(
            DohServer::parse("https://9.9.9.9/").unwrap().path,
            DEFAULT_PATH
        );
        for bad in [
            "http://1.1.1.1/dns-query",
            "https://dns.google/dns-query",
            "https://1.1/dns-query",
            "https://0x01010101/",
            "https://127.0.0.1/dns-query",
            "https://192.168.1.1/dns-query",
            "https://[fd00::1]/dns-query",
            "https://[::ffff:10.0.0.1]/",
            "https://1.1.1.1:0/",
            "https://1.1.1.1:99999/",
            "https://user@1.1.1.1/",
            "https://1.1.1.1/dns-query?x=1",
            "https://1.1.1.1/dns query",
            "https://[2606:4700::1111/",
            "https://1.1.1.1:+443/",
        ] {
            assert!(DohServer::parse(bad).is_err(), "{bad}");
        }
        assert_eq!(default_servers().len(), DEFAULT_SERVERS.len());
        for d in default_servers() {
            assert!(d.check().is_ok(), "{d:?}");
        }
    }

    #[test]
    fn base64url_is_rfc_4648_section_5_unpadded() {
        assert_eq!(base64url(b""), "");
        assert_eq!(base64url(b"f"), "Zg");
        assert_eq!(base64url(b"fo"), "Zm8");
        assert_eq!(base64url(b"foo"), "Zm9v");
        assert_eq!(base64url(b"foob"), "Zm9vYg");
        assert_eq!(base64url(&[0xfb, 0xff, 0xbf]), "-_-_");
        // RFC 8484 §4.1.1's example query, id 0, www.example.com A.
        let q = [
            0u8, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 3, 119, 119, 119, 7, 101, 120, 97, 109, 112, 108,
            101, 3, 99, 111, 109, 0, 0, 1, 0, 1,
        ];
        assert_eq!(
            base64url(&q),
            "AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB"
        );
    }

    /// A response to `q` with the answers `rrs` (owner, type, rdata), names uncompressed.
    fn response(q: &[u8], rcode: u8, rrs: &[(&str, u16, Vec<u8>)]) -> Vec<u8> {
        // The question section ends before the OPT record (19 bytes).
        let mut m = q[..q.len() - 19].to_vec();
        m[2] = 0x81;
        m[3] = 0x80 | rcode;
        m[6..8].copy_from_slice(&(rrs.len() as u16).to_be_bytes());
        m[10..12].copy_from_slice(&[0, 0]);
        for (owner, t, rdata) in rrs {
            for l in owner.split('.') {
                m.push(l.len() as u8);
                m.extend_from_slice(l.as_bytes());
            }
            m.push(0);
            m.extend_from_slice(&t.to_be_bytes());
            m.extend_from_slice(&1u16.to_be_bytes());
            m.extend_from_slice(&60u32.to_be_bytes());
            m.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
            m.extend_from_slice(rdata);
        }
        m
    }

    fn wire(name: &str) -> Vec<u8> {
        let mut v = Vec::new();
        for l in name.split('.') {
            v.push(l.len() as u8);
            v.extend_from_slice(l.as_bytes());
        }
        v.push(0);
        v
    }

    #[test]
    fn queries_carry_a_zero_client_subnet() {
        let q = build_query("elfs.example.com", TYPE_AAAA).unwrap();
        assert_eq!(&q[..12], &[0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 1]);
        assert_eq!(
            &q[q.len() - 23..],
            &[
                0, 28, 0, 1, // AAAA IN
                0, 0, 41, 16, 0, 0, 0, 0, 0, 0, 8, // OPT, 4096, rdlen 8
                0, 8, 0, 4, 0, 1, 0, 0, // Client Subnet: IPv4, source 0, scope 0
            ][..]
        );
        assert!(build_query("", TYPE_A).is_err());
        assert!(build_query("a..b", TYPE_A).is_err());
        assert!(build_query(&"a".repeat(64), TYPE_A).is_err());
    }

    /// A chain of at most 16 links is followed whatever the records' order; a longer one is an
    /// error. An owner name with a dot inside a label (its text the asked name's) is malformed. An
    /// answer whose id is not the query's 0 is not an answer to it.
    #[test]
    fn chains_are_bounded_by_links_and_labels_hold_no_dots() {
        let q = build_query("a.example.com", TYPE_A).unwrap();
        let link = |i: usize| format!("l{i}.example.net");
        let chain = |n: usize| {
            let mut rrs: Vec<(String, u16, Vec<u8>)> = Vec::new();
            rrs.push(("a.example.com".into(), TYPE_CNAME, wire(&link(1))));
            for i in 1..n {
                rrs.push((link(i), TYPE_CNAME, wire(&link(i + 1))));
            }
            rrs.push((link(n), TYPE_A, vec![9, 9, 9, 9]));
            rrs
        };
        fn as_refs(v: &[(String, u16, Vec<u8>)]) -> Vec<(&str, u16, Vec<u8>)> {
            v.iter()
                .map(|(o, t, d)| (o.as_str(), *t, d.clone()))
                .collect()
        }
        let ok = chain(16);
        assert_eq!(
            parse_response(&response(&q, 0, &as_refs(&ok)), "a.example.com", TYPE_A).unwrap(),
            Some(vec!["9.9.9.9".parse().unwrap()])
        );
        let mut reversed = ok.clone();
        reversed.reverse();
        assert!(parse_response(
            &response(&q, 0, &as_refs(&reversed)),
            "a.example.com",
            TYPE_A
        )
        .unwrap()
        .is_some_and(|v| v.len() == 1));
        let long = chain(17);
        assert!(
            parse_response(&response(&q, 0, &as_refs(&long)), "a.example.com", TYPE_A).is_err()
        );
        // `a.example.com` as one label of an owner name ("a\x2eexample", "com").
        let mut m = response(&q, 0, &[]);
        m[6..8].copy_from_slice(&1u16.to_be_bytes());
        m.extend_from_slice(&[9]);
        m.extend_from_slice(b"a.example");
        m.extend_from_slice(&[3]);
        m.extend_from_slice(b"com");
        m.push(0);
        m.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 6, 6, 6, 6]);
        assert!(parse_response(&m, "a.example.com", TYPE_A).is_err());
        let mut other_id = response(&q, 0, &as_refs(&ok));
        other_id[0..2].copy_from_slice(&0x1234u16.to_be_bytes());
        assert!(parse_response(&other_id, "a.example.com", TYPE_A).is_err());
    }

    /// The addresses of the name and its CNAME chain are read; records of other names (which a
    /// resolver would not send, and an answer must not smuggle) are not.
    #[test]
    fn answers_follow_the_cname_chain_and_nothing_else() {
        let q = build_query("elfs.example.com", TYPE_A).unwrap();
        let m = response(
            &q,
            0,
            &[
                ("ELFS.example.com", TYPE_CNAME, wire("cdn.example.net")),
                ("cdn.example.net", TYPE_CNAME, wire("edge.example.org")),
                ("edge.example.org", TYPE_A, vec![93, 184, 216, 34]),
                ("edge.example.org", TYPE_A, vec![93, 184, 216, 34]),
                ("other.example.org", TYPE_A, vec![10, 0, 0, 1]),
                ("edge.example.org", TYPE_AAAA, vec![0; 16]),
            ],
        );
        assert_eq!(
            parse_response(&m, "elfs.example.com", TYPE_A).unwrap(),
            Some(vec!["93.184.216.34".parse().unwrap()])
        );
        // NXDOMAIN; another error; another question; a truncated message.
        assert_eq!(
            parse_response(&response(&q, 3, &[]), "elfs.example.com", TYPE_A).unwrap(),
            None
        );
        assert!(parse_response(&response(&q, 2, &[]), "elfs.example.com", TYPE_A).is_err());
        assert!(parse_response(&m, "other.example.org", TYPE_A).is_err());
        assert!(parse_response(&m, "elfs.example.com", TYPE_AAAA).is_err());
        assert!(parse_response(&m[..m.len() - 3], "elfs.example.com", TYPE_A).is_err());
        let mut tc = m.clone();
        tc[2] |= 0x02;
        assert!(parse_response(&tc, "elfs.example.com", TYPE_A).is_err());
        // A compression pointer that loops (or points forward) is malformed.
        let mut lp = response(&q, 0, &[]);
        lp[6..8].copy_from_slice(&1u16.to_be_bytes());
        let here = lp.len() as u16;
        lp.extend_from_slice(&(0xc000 | here).to_be_bytes());
        lp.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 1, 2, 3, 4]);
        assert!(parse_response(&lp, "elfs.example.com", TYPE_A).is_err());
        // A pointer back to the question's name is the name.
        let mut ok = response(&q, 0, &[]);
        ok[6..8].copy_from_slice(&1u16.to_be_bytes());
        ok.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 1, 2, 3, 4]);
        assert_eq!(
            parse_response(&ok, "elfs.example.com", TYPE_A).unwrap(),
            Some(vec!["1.2.3.4".parse().unwrap()])
        );
    }
}
