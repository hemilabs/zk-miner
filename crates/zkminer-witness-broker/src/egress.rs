//! The broker's in-app network floor (plan §14.2) and log redaction (§11.4). Pure functions: the
//! broker's HTTP client asks [`EgressPolicy::admit`] for every address it is about to connect to.
//!
//! INTERFACE CONTRACT (fixed for milestone 2; the bodies are implemented on max/witness-broker-rpc).

use std::net::{IpAddr, SocketAddr};

/// What an endpoint is for. Role entries are admitted only for their own role, in a set that
/// connections derived from requester data never match.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Role {
    EvmRpc,
    Artifact,
    BlobMirror,
    ArtifactMirror,
}

/// An IPv4 or IPv6 prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Prefix {
    pub addr: IpAddr,
    pub len: u8,
}

impl Prefix {
    pub fn contains(&self, ip: IpAddr) -> bool {
        let _ = ip;
        todo!("max/witness-broker-rpc")
    }
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

/// Allow-only-globally-routable (`is_global` semantics, plus every embedded-IPv4 form judged by its
/// IPv4 address, and the blocklist of `zkminer-chain`'s `ip_is_blocked`).
pub fn is_global(ip: IpAddr) -> bool {
    let _ = ip;
    todo!("max/witness-broker-rpc")
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
    NoRoleEntry,
    WrongPort,
}

/// The policy: role entries, operator deny CIDRs (the host's and fleet's public and NAT addresses),
/// and the connected prefixes of every interface (refreshed by the caller on change).
#[derive(Debug, Clone, Default)]
pub struct EgressPolicy {
    pub roles: Vec<RoleEntry>,
    pub deny: Vec<Prefix>,
    pub connected: Vec<Prefix>,
}

impl EgressPolicy {
    /// For an operator endpoint (`alias` of `role`): admitted only if `addr` matches that entry's
    /// prefixes and port. For requester-derived connections (`role == None`, Phase 2): admitted only
    /// if global, port 443, and not in `deny` or `connected`.
    pub fn admit(&self, role: Option<(Role, &str)>, addr: SocketAddr) -> Admit {
        let _ = (role, addr);
        todo!("max/witness-broker-rpc")
    }
}

/// The connected prefixes of every interface (getifaddrs).
pub fn connected_prefixes() -> std::io::Result<Vec<Prefix>> {
    todo!("max/witness-broker-rpc")
}

/// Replaces every URL (scheme://…) in `s` with `<url>`; endpoints are logged by alias only.
pub fn redact_urls(s: &str) -> String {
    let _ = s;
    todo!("max/witness-broker-rpc")
}

/// Turns untrusted bytes into a printable, bounded string: control characters and non-ASCII escaped,
/// at most `max` output bytes.
pub fn sanitize_log(bytes: &[u8], max: usize) -> String {
    let _ = (bytes, max);
    todo!("max/witness-broker-rpc")
}
