//! The broker's network floor (plan §14.2) and log redaction (§11.4). Pure: the broker's HTTP
//! clients ask [`EgressPolicy::admit`] for every address they are about to connect to.
//!
//! # One predicate: zkminer-netguard's
//!
//! Whether an address or a prefix is on the public internet, the host's own addresses and connected
//! prefixes, and the embedded-IPv4 canonicalization are all [`zkminer_netguard`]'s (the same code as
//! the miner's ELF fetch): [`is_global`] (allow-only-globally-routable; IPv4-compatible, 6to4 and
//! Teredo refused outright; mapped, SIIT and well-known NAT64 judged by their IPv4 address),
//! [`zkminer_netguard::admit`] and [`zkminer_netguard::admit_prefix`]. This module only maps them
//! onto roles.
//!
//! # The floor
//!
//! - **Operator endpoints** (role entries: explicit `cidrs`, an IP literal's host route, or what a
//!   host name resolves to) are admitted only for their own role and alias, on their port. In
//!   [`NetMode::Public`] the address must also pass netguard's floor: global, not one of the host's
//!   own addresses, on none of its connected prefixes, in none of the deny CIDRs (the operator's,
//!   plus the DNS servers', see [`crate::config`]). The configuration refuses a role entry that
//!   would fail it when it loads; this check holds it at every connection, after a prefix refresh
//!   too. In [`NetMode::DevPrivate`] (only through the miner's `[dev] private_network`) an
//!   explicitly configured role entry may be private.
//! - **A host name's answers** become its role entry only through [`EgressPolicy::dns_admissible`],
//!   netguard's public floor **in both modes**: a DNS answer is not the operator's word.
//! - **Requester-derived connections** (Phase 2): netguard's public floor in both modes, then never
//!   an operator endpoint's address (`RoleOnly`), and only port 443.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

pub use zkminer_netguard::{canonical_ip, is_global, NetMode, Prefix};

/// What an endpoint is for. Role entries are admitted only for their own role, in a set that
/// connections derived from requester data never match.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Role {
    EvmRpc,
    Artifact,
    BlobMirror,
    ArtifactMirror,
}

/// One admitted operator endpoint: a role, an alias, the prefixes its connected address must fall in,
/// and its port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleEntry {
    pub role: Role,
    pub alias: String,
    pub prefixes: Vec<Prefix>,
    pub port: u16,
}

/// The decision for one connection attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admit {
    /// Admitted by its role entry.
    Role,
    /// Admitted as a global address that is not denied (Phase 2 requester URLs only).
    Global,
    Denied(DenyReason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenyReason {
    NotGlobal,
    DenyCidr,
    ConnectedPrefix,
    /// One of the host's own addresses.
    OwnAddress,
    NoRoleEntry,
    WrongPort,
    /// A requester-derived connection to an operator endpoint's address: those are reachable only
    /// through their role entries (plan §14.6).
    RoleOnly,
}

/// The only port a requester-derived connection may use.
pub const REQUESTER_PORT: u16 = 443;

/// The policy: the mode, role entries, deny CIDRs (the operator's and the DNS servers') and the
/// host's facts (connected prefixes and own addresses, refreshed by the miner).
#[derive(Debug, Clone)]
pub struct EgressPolicy {
    pub mode: NetMode,
    pub roles: Vec<RoleEntry>,
    pub deny: Vec<Prefix>,
    pub facts: zkminer_netguard::HostFacts,
}

impl Default for EgressPolicy {
    fn default() -> Self {
        Self {
            mode: NetMode::Public,
            roles: Vec::new(),
            deny: Vec::new(),
            facts: zkminer_netguard::HostFacts::empty(),
        }
    }
}

impl EgressPolicy {
    /// The host's connected prefixes.
    pub fn connected(&self) -> &[Prefix] {
        self.facts.connected()
    }

    /// The host's own addresses.
    pub fn own_addresses(&self) -> &[IpAddr] {
        self.facts.own_addresses()
    }

    /// netguard's public-mode floor for one address, as a [`DenyReason`].
    pub fn public_floor(&self, ip: IpAddr) -> Result<(), DenyReason> {
        use zkminer_netguard::Denied;
        zkminer_netguard::admit(NetMode::Public, ip, &self.facts, &self.deny).map_err(|d| match d {
            Denied::OwnAddress(_) => DenyReason::OwnAddress,
            Denied::ConnectedPrefix { .. } => DenyReason::ConnectedPrefix,
            Denied::DenyCidr { .. } => DenyReason::DenyCidr,
            _ => DenyReason::NotGlobal,
        })
    }

    /// For an operator endpoint (`alias` of `role`): admitted only if `addr` falls in that entry's
    /// prefixes, on its port, and (in [`NetMode::Public`]) passes [`Self::public_floor`]. When no
    /// entry of that role and alias has a prefix containing the address the answer is
    /// `NoRoleEntry`; when one does but on another port, `WrongPort`.
    ///
    /// For requester-derived connections (`role == None`, Phase 2): [`Self::public_floor`] in
    /// either mode, then never a role entry's address, and only port 443. Every comparison uses
    /// [`canonical_ip`] (a NAT64, SIIT, mapped or IPv4-compatible spelling of an address is that
    /// address).
    pub fn admit(&self, role: Option<(Role, &str)>, addr: SocketAddr) -> Admit {
        let ip = canonical_ip(addr.ip());
        match role {
            Some((role, alias)) => {
                let mut wrong_port = false;
                for e in self.roles.iter().filter(|e| e.role == role && e.alias == alias) {
                    if e.prefixes.iter().any(|p| p.contains(ip)) {
                        if e.port != addr.port() {
                            wrong_port = true;
                            continue;
                        }
                        if self.mode == NetMode::Public {
                            if let Err(r) = self.public_floor(addr.ip()) {
                                return Admit::Denied(r);
                            }
                        }
                        return Admit::Role;
                    }
                }
                Admit::Denied(if wrong_port {
                    DenyReason::WrongPort
                } else {
                    DenyReason::NoRoleEntry
                })
            }
            None => {
                if let Err(r) = self.public_floor(addr.ip()) {
                    Admit::Denied(r)
                } else if self.roles.iter().any(|e| e.prefixes.iter().any(|p| p.contains(ip))) {
                    Admit::Denied(DenyReason::RoleOnly)
                } else if addr.port() != REQUESTER_PORT {
                    Admit::Denied(DenyReason::WrongPort)
                } else {
                    Admit::Global
                }
            }
        }
    }

    /// Whether an address a DNS answer gave for an endpoint without explicit `cidrs` may become its
    /// role entry: netguard's public floor, **in both modes**. DNS answers are not the operator's
    /// word (`/etc/hosts`, a split-horizon zone or a spoofed answer can say anything), so a local or
    /// LAN node is configured by IP literal or explicit `cidrs` (and only in developer mode), never
    /// by name alone.
    pub fn dns_admissible(&self, ip: IpAddr) -> bool {
        self.public_floor(ip).is_ok()
    }

    /// In [`NetMode::Public`], the first role prefix that is not entirely global or reaches the
    /// host or a deny CIDR ([`zkminer_netguard::admit_prefix`]), with why; `None` when every one is
    /// public (always in [`NetMode::DevPrivate`]). The self-test's check of the effective role set.
    pub fn first_non_public_role(&self) -> Option<(String, zkminer_netguard::Denied)> {
        self.roles.iter().find_map(|e| {
            e.prefixes.iter().find_map(|p| {
                zkminer_netguard::admit_prefix(self.mode, *p, &self.facts, &self.deny)
                    .err()
                    .map(|d| (e.alias.clone(), d))
            })
        })
    }
}

/// netguard's facts about this host ([`zkminer_netguard::HostFacts::gather_with`]: interfaces,
/// routes, DNS servers, and the public addresses if `opts` says so). Only callable before the
/// sandbox is applied (netlink).
pub fn host_facts(opts: &zkminer_netguard::FactsOptions) -> std::io::Result<zkminer_netguard::HostFacts> {
    zkminer_netguard::HostFacts::gather_with(opts)
}

/// Every prefix this host's facts refuse ([`zkminer_netguard::HostFacts::refused_prefixes`]),
/// without public-address discovery.
pub fn connected_prefixes() -> std::io::Result<Vec<Prefix>> {
    let opts = zkminer_netguard::FactsOptions { discover_public_addresses: false, ..Default::default() };
    Ok(host_facts(&opts)?.refused_prefixes())
}

/// Replaces every URL (scheme://…) in `s` with `<url>`; endpoints are logged by alias only. Also bare
/// endpoints and credential-bearing queries: see the module doc for exactly what is caught.
pub fn redact_urls(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while !rest.is_empty() {
        let tok_end = rest.find(is_token_break).unwrap_or(rest.len());
        let (tok, tail) = rest.split_at(tok_end);
        match redact_start(tok) {
            Some(start) => {
                out.push_str(&tok[..start]);
                out.push_str("<url>");
            }
            None => out.push_str(tok),
        }
        // Copy the run of break characters as is.
        let brk_end = tail
            .find(|c: char| !is_token_break(c))
            .unwrap_or(tail.len());
        out.push_str(&tail[..brk_end]);
        rest = &tail[brk_end..];
    }
    out
}

fn is_token_break(c: char) -> bool {
    c.is_whitespace() || matches!(c, '"' | '\'' | '`')
}

/// Where in `tok` a URL-like part starts (it runs to the token's end), if anywhere.
fn redact_start(tok: &str) -> Option<usize> {
    let b = tok.as_bytes();
    // 1. scheme://
    if let Some(sep) = tok.find("://") {
        let mut start = sep;
        while start > 0 && is_scheme_byte(b[start - 1]) {
            start -= 1;
        }
        return Some(start);
    }
    // 3. a credential-bearing query anywhere in the token: all of it.
    if has_secret_query(tok) {
        return Some(0);
    }
    // 2. bare endpoints, at the start or after a separator.
    let starts = std::iter::once(0).chain(
        b.iter()
            .enumerate()
            .filter(|&(_, &c)| matches!(c, b'=' | b'(' | b'[' | b',' | b';' | b'@'))
            .map(|(i, &c)| if c == b'[' { i } else { i + 1 }),
    );
    for start in starts {
        if start < b.len() && is_bare_endpoint(&tok[start..]) {
            return Some(start);
        }
    }
    None
}

fn is_scheme_byte(c: u8) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, b'+' | b'.' | b'-')
}

const SECRET_PARAMS: &[&str] = &[
    "key",
    "apikey",
    "api_key",
    "api-key",
    "token",
    "access_token",
    "auth",
    "secret",
    "password",
    "pass",
    "sig",
    "signature",
];

fn has_secret_query(tok: &str) -> bool {
    let lower = tok.to_ascii_lowercase();
    let b = lower.as_bytes();
    b.iter().enumerate().any(|(i, &c)| {
        (c == b'?' || c == b'&')
            && SECRET_PARAMS.iter().any(|p| {
                let rest = &b[i + 1..];
                rest.len() > p.len() && rest.starts_with(p.as_bytes()) && rest[p.len()] == b'='
            })
    })
}

/// `user[:pass]@host…`, `host[:port]/…`, `host[:port]?…`, `ipv4:port`, `localhost:port`,
/// `[ipv6]:port`.
fn is_bare_endpoint(c: &str) -> bool {
    // Userinfo: something@host, where the part before @ has no '/' and the host is a real host.
    if let Some(at) = c.find('@') {
        let (user, host) = (&c[..at], &c[at + 1..]);
        if !user.is_empty() && !user.contains('/') && host_end(host).is_some() {
            return true;
        }
    }
    let Some((kind, end)) = host_end(c) else {
        return false;
    };
    let rest = &c[end..];
    let (has_port, after) = match rest.strip_prefix(':') {
        Some(p) => {
            let digits = p.bytes().take_while(u8::is_ascii_digit).count();
            if digits == 0 {
                return false;
            }
            (true, &p[digits..])
        }
        None => (false, rest),
    };
    if let Some(path) = after.strip_prefix('/') {
        // `a.b.c.d/nn` with nothing else is a CIDR, not a URL.
        let cidr = kind == HostKind::V4
            && !has_port
            && !path.is_empty()
            && path.len() <= 3
            && path.bytes().all(|c| c.is_ascii_digit());
        return !cidr;
    }
    if after.starts_with('?') && after.contains('=') {
        return true;
    }
    has_port && after.is_empty() && kind != HostKind::Dns
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HostKind {
    Dns,
    V4,
    Local,
    V6,
}

/// If `c` starts with a host, its kind and the byte offset just past it.
fn host_end(c: &str) -> Option<(HostKind, usize)> {
    let b = c.as_bytes();
    if b.first() == Some(&b'[') {
        let close = c.find(']')?;
        let inner = &c[1..close];
        return inner
            .parse::<Ipv6Addr>()
            .ok()
            .map(|_| (HostKind::V6, close + 1));
    }
    let end = b
        .iter()
        .position(|&x| !(x.is_ascii_alphanumeric() || x == b'.' || x == b'-'))
        .unwrap_or(b.len());
    let host = &c[..end];
    if host.eq_ignore_ascii_case("localhost") {
        return Some((HostKind::Local, end));
    }
    if host.parse::<Ipv4Addr>().is_ok() {
        return Some((HostKind::V4, end));
    }
    let labels: Vec<&str> = host.split('.').collect();
    let tld = labels.last()?;
    let ok = labels.len() >= 2
        && labels
            .iter()
            .all(|l| !l.is_empty() && !l.starts_with('-') && !l.ends_with('-'))
        && tld.len() >= 2
        && tld.bytes().all(|x| x.is_ascii_alphabetic());
    ok.then_some((HostKind::Dns, end))
}

/// Turns untrusted bytes into a printable, bounded string: control characters and non-ASCII escaped,
/// at most `max` output bytes.
///
/// Printable ASCII passes through, `\` becomes `\\`, TAB/LF/CR become `\t`/`\n`/`\r`, and every other
/// byte (controls, DEL, each byte of non-ASCII or invalid UTF-8) becomes `\xNN`. The output is
/// printable ASCII only. When it would exceed `max`, it is cut at an escape boundary and ends with
/// `...` (if `max` ≥ 3), never longer than `max` bytes.
pub fn sanitize_log(bytes: &[u8], max: usize) -> String {
    const MARK: &str = "...";
    let mut out = String::with_capacity(max.min(bytes.len().saturating_mul(4)));
    // The longest prefix (at an escape boundary) that leaves room for the marker.
    let mut cut = 0usize;
    let room = max.saturating_sub(MARK.len());
    let mut esc = [0u8; 4];
    for &b in bytes {
        let e: &[u8] = match b {
            b'\\' => b"\\\\",
            b'\t' => b"\\t",
            b'\n' => b"\\n",
            b'\r' => b"\\r",
            0x20..=0x7e => {
                esc[0] = b;
                &esc[..1]
            }
            _ => {
                const HEX: &[u8; 16] = b"0123456789abcdef";
                esc = [
                    b'\\',
                    b'x',
                    HEX[usize::from(b >> 4)],
                    HEX[usize::from(b & 15)],
                ];
                &esc[..]
            }
        };
        if out.len() + e.len() > max {
            if max >= MARK.len() {
                out.truncate(cut);
                out.push_str(MARK);
            }
            return out;
        }
        // Every escape is printable ASCII, so this is valid UTF-8.
        out.extend(e.iter().map(|&x| x as char));
        if out.len() <= room {
            cut = out.len();
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn pfx(s: &str) -> Prefix {
        s.parse().unwrap()
    }

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    fn policy(mode: NetMode) -> EgressPolicy {
        EgressPolicy {
            mode,
            roles: vec![
                RoleEntry {
                    role: Role::EvmRpc,
                    alias: "base-archive".into(),
                    prefixes: vec![pfx("10.1.0.0/16"), pfx("fd00::/64")],
                    port: 8545,
                },
                RoleEntry {
                    role: Role::Artifact,
                    alias: "hemi".into(),
                    prefixes: vec![pfx("203.0.113.7/32")],
                    port: 443,
                },
                RoleEntry { role: Role::BlobMirror, alias: "m1".into(), prefixes: vec![pfx("8.8.4.0/24")], port: 443 },
                RoleEntry { role: Role::EvmRpc, alias: "public".into(), prefixes: vec![pfx("1.0.0.0/24")], port: 443 },
            ],
            deny: vec![pfx("8.8.4.4/32"), pfx("2a01:4f8::/32")],
            facts: zkminer_netguard::HostFacts::new(
                vec![pfx("9.9.9.0/24"), pfx("2606:4700:aaaa::/48")],
                vec![ip("9.9.9.10"), ip("1.0.0.77")],
            ),
        }
    }

    /// Developer mode: an explicitly configured role entry is admitted for its own role and alias,
    /// private addresses included.
    #[test]
    fn dev_mode_admits_private_role_entries_for_their_role_only() {
        let p = policy(NetMode::DevPrivate);
        let rpc = Some((Role::EvmRpc, "base-archive"));
        assert_eq!(p.admit(rpc, sa("10.1.2.3:8545")), Admit::Role);
        assert_eq!(p.admit(rpc, sa("[fd00::5]:8545")), Admit::Role);
        assert_eq!(p.admit(rpc, sa("[::ffff:10.1.2.3]:8545")), Admit::Role);
        assert_eq!(p.admit(rpc, sa("10.1.2.3:8546")), Admit::Denied(DenyReason::WrongPort));
        assert_eq!(p.admit(rpc, sa("10.2.0.1:8545")), Admit::Denied(DenyReason::NoRoleEntry));
        // Only its own role and alias.
        assert_eq!(
            p.admit(Some((Role::EvmRpc, "other")), sa("10.1.2.3:8545")),
            Admit::Denied(DenyReason::NoRoleEntry)
        );
        assert_eq!(
            p.admit(Some((Role::Artifact, "base-archive")), sa("10.1.2.3:8545")),
            Admit::Denied(DenyReason::NoRoleEntry)
        );
        assert_eq!(
            p.admit(Some((Role::ArtifactMirror, "hemi")), sa("203.0.113.7:443")),
            Admit::Denied(DenyReason::NoRoleEntry)
        );
        assert_eq!(p.admit(Some((Role::Artifact, "hemi")), sa("203.0.113.7:443")), Admit::Role);
        assert_eq!(p.admit(Some((Role::BlobMirror, "m1")), sa("8.8.4.4:443")), Admit::Role);
    }

    /// Public mode: a role entry is admitted only where netguard's floor admits the address too,
    /// however the configuration got there.
    #[test]
    fn public_mode_holds_role_entries_to_the_public_floor() {
        let p = policy(NetMode::Public);
        let rpc = Some((Role::EvmRpc, "base-archive"));
        assert_eq!(p.admit(rpc, sa("10.1.2.3:8545")), Admit::Denied(DenyReason::NotGlobal));
        assert_eq!(p.admit(rpc, sa("[fd00::5]:8545")), Admit::Denied(DenyReason::NotGlobal));
        assert_eq!(p.admit(Some((Role::Artifact, "hemi")), sa("203.0.113.7:443")), Admit::Denied(DenyReason::NotGlobal));
        assert_eq!(p.admit(Some((Role::BlobMirror, "m1")), sa("8.8.4.4:443")), Admit::Denied(DenyReason::DenyCidr));
        assert_eq!(p.admit(Some((Role::BlobMirror, "m1")), sa("8.8.4.8:443")), Admit::Role);
        let public = Some((Role::EvmRpc, "public"));
        assert_eq!(p.admit(public, sa("1.0.0.1:443")), Admit::Role);
        assert_eq!(p.admit(public, sa("1.0.0.77:443")), Admit::Denied(DenyReason::OwnAddress));
        assert_eq!(p.admit(public, sa("[64:ff9b::100:1]:443")), Admit::Role, "NAT64 of a public address");
        assert_eq!(p.admit(public, sa("[::100:1]:443")), Admit::Denied(DenyReason::NotGlobal), "IPv4-compatible");
        // The role-set check names the first non-public entry.
        let (alias, why) = p.first_non_public_role().expect("10.1.0.0/16 is not public");
        assert_eq!(alias, "base-archive");
        assert!(why.to_string().contains("10.1.0.0/16"), "{why}");
        assert_eq!(policy(NetMode::DevPrivate).first_non_public_role(), None);
        let clean = EgressPolicy { roles: p.roles[3..].to_vec(), ..p.clone() };
        assert!(clean.first_non_public_role().is_some(), "1.0.0.0/24 holds the own address 1.0.0.77");
        let clean = EgressPolicy { facts: zkminer_netguard::HostFacts::empty(), ..clean };
        assert_eq!(clean.first_non_public_role(), None);
    }

    /// The requester path is netguard's public floor in either mode.
    #[test]
    fn admit_requester_derived() {
        for mode in [NetMode::Public, NetMode::DevPrivate] {
            let p = policy(mode);
            assert_eq!(p.admit(None, sa("1.1.1.1:443")), Admit::Global);
            assert_eq!(p.admit(None, sa("[2606:4700:4700::1111]:443")), Admit::Global);
            assert_eq!(p.admit(None, sa("1.1.1.1:80")), Admit::Denied(DenyReason::WrongPort));
            for s in ["10.1.2.3:443", "[::ffff:10.1.2.3]:443", "169.254.169.254:443", "[fd00:ec2::254]:443", "127.0.0.1:443", "[::808:808]:443"] {
                assert_eq!(p.admit(None, sa(s)), Admit::Denied(DenyReason::NotGlobal), "{s}");
            }
            assert_eq!(p.admit(None, sa("8.8.4.4:443")), Admit::Denied(DenyReason::DenyCidr));
            assert_eq!(p.admit(None, sa("[::ffff:8.8.4.4]:443")), Admit::Denied(DenyReason::DenyCidr));
            assert_eq!(p.admit(None, sa("[2a01:4f8::1]:443")), Admit::Denied(DenyReason::DenyCidr));
            assert_eq!(p.admit(None, sa("9.9.9.9:443")), Admit::Denied(DenyReason::ConnectedPrefix));
            assert_eq!(p.admit(None, sa("[2606:4700:aaaa::1]:443")), Admit::Denied(DenyReason::ConnectedPrefix));
            assert_eq!(p.admit(None, sa("9.9.9.10:443")), Admit::Denied(DenyReason::OwnAddress));
            // Requester-derived connections never reach a role entry's address.
            assert_eq!(p.admit(None, sa("8.8.4.8:443")), Admit::Denied(DenyReason::RoleOnly));
            assert_eq!(p.admit(None, sa("1.0.0.1:443")), Admit::Denied(DenyReason::RoleOnly));
            assert_eq!(p.admit(None, sa("203.0.113.7:443")), Admit::Denied(DenyReason::NotGlobal));
        }
    }

    /// Review F10 (the reviewer's PoC, inverted): the NAT64, SIIT and IPv4-compatible spellings of a
    /// denied, connected or operator address are that address on the requester path.
    #[test]
    fn embedded_forms_are_judged_as_their_v4_on_the_requester_path() {
        let p = EgressPolicy {
            mode: NetMode::Public,
            roles: vec![RoleEntry { role: Role::EvmRpc, alias: "n".into(), prefixes: vec![pfx("8.8.8.8/32")], port: 443 }],
            deny: vec![pfx("8.8.4.4/32")],
            facts: zkminer_netguard::HostFacts::new(vec![pfx("9.9.9.0/24")], vec![]),
        };
        for (s, why) in [
            ("8.8.4.4:443", DenyReason::DenyCidr),
            ("[::ffff:8.8.4.4]:443", DenyReason::DenyCidr),
            ("[64:ff9b::808:404]:443", DenyReason::DenyCidr),
            ("[::ffff:0:808:404]:443", DenyReason::DenyCidr),
            ("[::808:404]:443", DenyReason::NotGlobal), // IPv4-compatible: refused outright now
            ("9.9.9.9:443", DenyReason::ConnectedPrefix),
            ("[64:ff9b::909:909]:443", DenyReason::ConnectedPrefix),
            ("8.8.8.8:443", DenyReason::RoleOnly),
            ("[64:ff9b::808:808]:443", DenyReason::RoleOnly),
            ("[::ffff:0:808:808]:443", DenyReason::RoleOnly),
        ] {
            assert_eq!(p.admit(None, sa(s)), Admit::Denied(why), "{s}");
        }
        assert_eq!(p.admit(None, sa("[64:ff9b::101:101]:443")), Admit::Global, "an unrelated global v4 stays admitted");
    }

    /// DNS answers are held to the public floor in both modes.
    #[test]
    fn dns_admission_is_public_in_both_modes() {
        for mode in [NetMode::Public, NetMode::DevPrivate] {
            let p = EgressPolicy {
                facts: zkminer_netguard::HostFacts::new(vec![pfx("9.9.9.0/24")], vec![ip("2a00:1450:4001::77")]),
                ..policy(mode)
            };
            for s in ["8.8.8.8", "2606:4700:4700::1111", "64:ff9b::101:101"] {
                assert!(p.dns_admissible(ip(s)), "{s}");
            }
            for s in [
                "127.0.0.1",
                "::1",
                "10.1.2.3",
                "169.254.169.254",
                "fd00:ec2::254",
                "::ffff:127.0.0.1",
                "64:ff9b::7f00:1", // NAT64 loopback
                "::808:808",       // IPv4-compatible
                "8.8.4.4",         // deny
                "64:ff9b::808:404",
                "9.9.9.9",            // connected
                "2a00:1450:4001::77", // own
            ] {
                assert!(!p.dns_admissible(ip(s)), "{s} ({mode:?})");
            }
        }
    }

    #[test]
    fn this_hosts_connected_prefixes_come_from_netguard() {
        let ps = connected_prefixes().expect("getifaddrs");
        assert!(ps.iter().any(|p| p.contains(ip("127.0.0.1"))) || ps.is_empty());
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: 2_000, ..ProptestConfig::default() })]

        #[test]
        fn sanitize_log_is_bounded_and_printable(bytes in prop::collection::vec(any::<u8>(), 0..300), max in 0usize..400) {
            let s = sanitize_log(&bytes, max);
            prop_assert!(s.len() <= max);
            prop_assert!(s.bytes().all(|c| (0x20..0x7f).contains(&c)));
        }

        #[test]
        fn redact_urls_never_panics_and_hides_scheme_urls(pre in "[ -~]{0,20}", host in "[a-z]{1,10}\\.[a-z]{2,5}", path in "[!-~&&[^\"'`]]{0,30}", post in "[ -~]{0,20}") {
            let secret = format!("https://{host}/{path}");
            let s = format!("{pre} {secret} {post}");
            let r = redact_urls(&s);
            prop_assert!(!r.contains(&secret), "{} -> {}", s, r);
            let _ = redact_urls(&pre);
        }
    }

    #[test]
    fn redact_urls_table() {
        for (input, want) in [
            (
                "GET https://mainnet.infura.io/v3/abcdef failed",
                "GET <url> failed",
            ),
            (
                "url=\"wss://x.example/ws?key=1\" next",
                "url=\"<url>\" next",
            ),
            ("endpoint=http://10.0.0.1:8545/ done", "endpoint=<url> done"),
            ("(https://a.b/c), more", "(<url> more"),
            ("://weird/abc", "<url>"),
            ("ipfs://bafy/x and git+ssh://h/r", "<url> and <url>"),
            ("'ftp://u:p@h/x'", "'<url>'"),
            ("eth-mainnet.g.alchemy.com/v2/KEY", "<url>"),
            ("rpc=eth-mainnet.g.alchemy.com/v2/KEY,", "rpc=<url>"),
            ("connect 10.0.0.1:8545 refused", "connect <url> refused"),
            ("connect localhost:8545 refused", "connect <url> refused"),
            ("connect [::1]:8545 refused", "connect <url> refused"),
            ("host=[fd00::1]:8545", "host=<url>"),
            ("user:pw@db.internal.example", "<url>"),
            ("node.example.org?apikey=xyz", "<url>"),
            ("/v1/rpc?token=abc", "<url>"),
            ("path?a=1&secret=2", "<url>"),
            ("Q?API_KEY=1", "<url>"),
            ("example.com/path", "<url>"),
            // Not URLs.
            ("crates/foo/src/lib.rs:42:5", "crates/foo/src/lib.rs:42:5"),
            ("at lib.rs:42", "at lib.rs:42"),
            (
                "denied 10.0.0.0/8 and 10.0.0.1",
                "denied 10.0.0.0/8 and 10.0.0.1",
            ),
            ("version v1.2.3/linux", "version v1.2.3/linux"),
            ("std::io::Error: oops", "std::io::Error: oops"),
            ("what is foo.rs?", "what is foo.rs?"),
            ("a?b", "a?b"),
            ("plain text, nothing here", "plain text, nothing here"),
            ("", ""),
            ("  leading\tand\ntrailing  ", "  leading\tand\ntrailing  "),
            ("ünïcode https://ü.example/é ok", "ünïcode <url> ok"),
        ] {
            assert_eq!(redact_urls(input), want, "{input:?}");
        }
    }

    #[test]
    fn sanitize_then_redact_hides_a_url_with_escaped_bytes() {
        let raw = b"error from https://key\x1b[0m.example/v3/SECRET\r\nforged line";
        let s = redact_urls(&sanitize_log(raw, 512));
        assert!(
            !s.contains("SECRET") && !s.contains('\n') && !s.contains('\x1b'),
            "{s}"
        );
        assert_eq!(s, "error from <url> line");
    }

    #[test]
    fn sanitize_log_table() {
        assert_eq!(sanitize_log(b"plain", 100), "plain");
        assert_eq!(
            sanitize_log(b"a\r\nb\x1b[31mc\td", 100),
            "a\\r\\nb\\x1b[31mc\\td"
        );
        assert_eq!(sanitize_log(b"back\\slash", 100), "back\\\\slash");
        assert_eq!(sanitize_log("café".as_bytes(), 100), "caf\\xc3\\xa9");
        assert_eq!(
            sanitize_log("\u{202e}".as_bytes(), 100),
            "\\xe2\\x80\\xae",
            "bidi override"
        );
        assert_eq!(
            sanitize_log(b"\xff\xfe\x00\x7f", 100),
            "\\xff\\xfe\\x00\\x7f"
        );
        // Bounds: exact fit, then one over (cut at an escape boundary, with the marker).
        assert_eq!(sanitize_log(b"abcdef", 6), "abcdef");
        assert_eq!(sanitize_log(b"abcdefg", 6), "abc...");
        assert_eq!(sanitize_log(b"ab\x01cdef", 7), "ab...");
        assert_eq!(sanitize_log(b"ab\x01", 6), "ab\\x01");
        assert_eq!(sanitize_log(b"abcdef", 2), "ab");
        assert_eq!(sanitize_log(b"\x01", 2), "");
        assert_eq!(sanitize_log(b"abcdef", 0), "");
        assert_eq!(sanitize_log(b"", 0), "");
    }
}
