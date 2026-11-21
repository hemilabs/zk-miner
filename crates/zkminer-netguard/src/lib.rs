//! zkminer's network guard.
//!
//! **The guarantee:** nothing a requester controls (a program's storage URIs, a redirect, later a
//! witness builder's fetches) can make a miner connect to anything that is not on the public
//! internet: not loopback, not the LAN, not cloud metadata, not the miner's own public address by
//! hairpin, not an on-link neighbour, not a name only a local resolver answers. A malicious
//! requester could otherwise aim the miner at an internal service and have a guest commit what came
//! back to a public journal. The only way to reach private destinations is
//! [`NetMode::DevPrivate`], which zkminer's configuration turns on with `[dev] private_network =
//! true` and refuses on Hemi mainnet.
//!
//! The pieces, each usable alone:
//!
//! - [`is_global`]: allow-only-globally-routable unicast, every embedded-IPv4 form judged by its
//!   IPv4 address or refused ([`ip`] module doc for the ranges), NAT64 network-specific prefixes
//!   included ([`nat64`]: configured, or learned from the host's DNS64);
//! - [`check_host_name`]: host-name hygiene for requester names ([`INTERNAL_SUFFIXES`]);
//! - [`HostFacts`]: the host's own addresses (its public NAT addresses included, [`public`]),
//!   connected prefixes (interfaces and on-link routes), IPv6 site prefixes, DNS servers, and
//!   routing tables and policy rules ([`routes`]: a destination whose route is not the default
//!   path, or that a local route delivers to the host, is refused);
//! - [`admit`]: the single admission decision for an address, by [`NetMode`]; for facts read from
//!   this host it also asks the kernel how it would route the connection
//!   ([`RouteTable::judge`]);
//! - [`check_url`]: the gate for a requester URL (scheme, user information, a strict reading that
//!   the URL standard's parser must agree with, host hygiene, and IP literals through [`admit`]);
//! - [`NetPolicy`]: the mode, refreshing host facts and the operator's deny CIDRs, as one value;
//! - [`ipfs_gateway_url`] / [`arweave_gateway_url`]: content ids syntax-checked into gateway URLs;
//! - [`NetPolicy::vet_connection`] / [`NetPolicy::vet_path`]: the last check right before a
//!   connection, with its port: the kernel's route for it, and the near-hop decision
//!   ([`nearhop`]: a destination is admitted as far only on positive evidence, a router past the
//!   limit saying a probe ran out of hops, never on silence; the connection then leaves from that
//!   probe's address and port, [`Vetted::socket`]);
//! - with the `client` feature (default): [`GuardedResolver`], which hands a connection only
//!   admitted addresses from one lookup (no DNS rebinding), over DNS-over-HTTPS to fixed public
//!   resolvers in public mode ([`doh`]), and [`guarded_client`], an HTTP client that refuses
//!   unchecked URLs, vets and pins every hop's addresses, ignores proxies, follows redirects only
//!   by hand ([`GuardedClient::get_following_redirects`]), and decodes no compression.
//!
//! Without the `client` feature the crate needs only `url` (and libc or windows-sys for the
//! interfaces), for crates that only parse configuration.

pub mod content;
pub mod doh;
mod facts;
mod host;
pub mod ip;
pub mod nat64;
pub mod nearhop;
mod policy;
pub mod public;
pub mod routes;
mod url;

#[cfg(feature = "client")]
mod client;
#[cfg(feature = "client")]
mod resolve;

pub use crate::url::{check_url, MAX_URL_LEN};
pub use ::url::Url;
pub use content::{arweave_gateway_url, ipfs_gateway_url, ContentIdDenied};
pub use doh::DohServer;
pub use facts::{
    ipv4_site_prefixes, parse_nameservers, site_prefixes, system_resolvers, EgressPath,
    FactsOptions, HostFacts, RawFacts, DEFAULT_IPV4_SITE_PREFIX_LEN, DEFAULT_IPV6_SITE_PREFIX_LEN,
    DEFAULT_NEAR_HOP_LIMIT, IPV4_SITE_PREFIX_LENS, IPV6_SITE_PREFIX_LENS, NEAR_HOP_LIMITS,
    RESOLV_CONF_PATHS,
};
pub use host::{check_host_name, HostDenied, INTERNAL_SUFFIXES};
pub use ip::{canonical_ip, is_global, prefix_is_global, Prefix, PrefixParseError};
pub use nearhop::{FarEvidence, NearProbe, Pin, ProbeOutcome, TtlProbe, Verdict};
pub use policy::{
    admit, admit_prefix, admit_to, connected_as_vetted, Denied, NetMode, NetPolicy, RouteKind,
    UrlDenied, Vetted, FACTS_TTL, FORCED_REFRESH_MIN_AGE,
};
pub use routes::{
    Hop, KernelAnswer, KernelRoutes, Link, Route, RouteOracle, RouteRefusal, RouteTable, RouteType,
    Rule, RuleAction, RuleMatch, TUNNEL_KINDS,
};

/// Chain ids zkminer treats as production markets, where developer mode
/// ([`NetMode::DevPrivate`]) is refused: Hemi mainnet. The miner's config and the witness broker
/// both refuse it here.
pub const PRODUCTION_CHAIN_IDS: &[u64] = &[43111];

/// Whether `chain_id` is a production market (see [`PRODUCTION_CHAIN_IDS`]).
pub fn is_production_chain(chain_id: u64) -> bool {
    PRODUCTION_CHAIN_IDS.contains(&chain_id)
}

/// What zkminer and its witness broker say at every start while developer mode is in force.
pub const DEV_MODE_BANNER: &str =
    "DEV MODE: private network access enabled — never run on a public market";

#[cfg(feature = "client")]
pub use client::{
    guarded_client, guarded_client_with, ClientOptions, FetchError, GuardedClient, USER_AGENT,
};
#[cfg(feature = "client")]
pub use doh::DohLookup;
#[cfg(feature = "client")]
pub use resolve::{
    absolute_name, GuardedResolver, Lookup, LookupFuture, ResolveError, SystemLookup, DNS_TIMEOUT,
    MAX_CONCURRENT_LOOKUPS,
};

#[cfg(any(test, feature = "test-util"))]
pub use client::guarded_client_for_test;
#[cfg(any(test, feature = "test-util"))]
pub use nearhop::FixedProbe;
#[cfg(any(test, feature = "test-util"))]
pub use resolve::ConnectMap;

/// `s` made safe to log: printable ASCII kept, everything else escaped (`\n`, `\u{202e}`, …), cut
/// at `max` characters with `…`. Requester text (a host, a URL) goes through this before it reaches
/// an error message.
pub(crate) fn printable(s: &str, max: usize) -> String {
    let mut out = String::new();
    for (n, c) in s.chars().enumerate() {
        if n >= max {
            out.push('…');
            break;
        }
        if c.is_ascii_graphic() || c == ' ' {
            out.push(c);
        } else {
            out.extend(c.escape_default());
        }
    }
    out
}

/// Tests: a test that cannot check what it is for on this host (no route of a family, no network,
/// a missing tool) says so and passes; under `ZKMINER_CI_STRICT=1` (a CI host that must run every
/// test: review round 3, cross-2) it fails instead, unless `why` starts with a token in
/// brackets (`"[ipv6] no [::1] here"`) that `ZKMINER_CI_ALLOW_SKIP` (a comma-separated list of
/// tokens) names exactly (review round 4, cross-7: it matched any part of `why` before, so
/// `"IPv6"` allowed every skip whose text mentioned IPv6). A CI host without IPv6 allows `ipv6`.
#[cfg(test)]
pub(crate) fn skipped(why: impl std::fmt::Display) {
    let why = why.to_string();
    if skip_fails(
        std::env::var("ZKMINER_CI_STRICT").ok().as_deref(),
        std::env::var("ZKMINER_CI_ALLOW_SKIP").ok().as_deref(),
        &why,
    ) {
        panic!("SKIPPED under ZKMINER_CI_STRICT=1 (not in ZKMINER_CI_ALLOW_SKIP): {why}");
    }
    eprintln!("SKIPPED: {why}");
}

/// Whether a skip for `why` fails the test under `ZKMINER_CI_STRICT` (`strict`) and
/// `ZKMINER_CI_ALLOW_SKIP` (`allow`): see [`skipped`].
#[cfg(test)]
fn skip_fails(strict: Option<&str>, allow: Option<&str>, why: &str) -> bool {
    strict == Some("1") && !skip_allowed(allow.unwrap_or_default(), why)
}

/// Whether `why`'s token (`[token] …`) is one `allow` (comma-separated tokens) names.
#[cfg(test)]
fn skip_allowed(allow: &str, why: &str) -> bool {
    let Some(token) = why
        .strip_prefix('[')
        .and_then(|rest| rest.split_once(']'))
        .map(|(t, _)| t.trim())
    else {
        return false;
    };
    !token.is_empty() && allow.split(',').any(|a| a.trim() == token)
}

#[cfg(test)]
mod floor_tests;

#[cfg(all(test, target_os = "macos"))]
mod macos_tests;

#[cfg(test)]
mod tests {
    #[test]
    fn printable_escapes_and_bounds() {
        assert_eq!(super::printable("a.b-c", 10), "a.b-c");
        assert_eq!(super::printable("a\r\nb\x1b[0m", 50), "a\\r\\nb\\u{1b}[0m");
        assert_eq!(super::printable("x\u{202e}y", 50), "x\\u{202e}y");
        assert_eq!(super::printable("abcdef", 3), "abc…");
    }

    /// Review round 3, cross-2: under ZKMINER_CI_STRICT=1 a skip fails, unless
    /// ZKMINER_CI_ALLOW_SKIP names its reason's token exactly (round 4); without it, nothing fails.
    #[test]
    fn strict_ci_fails_skips_it_does_not_allow() {
        use super::skip_fails;
        let why = "[ipv6] 2606:4700:4700::1111: no default route of its family (IPv6)";
        assert!(!skip_fails(None, None, why));
        assert!(!skip_fails(Some("0"), None, why));
        assert!(skip_fails(Some("1"), None, why));
        assert!(skip_fails(Some("1"), Some(""), why));
        assert!(skip_fails(Some("1"), Some(" , sandbox"), why));
        assert!(!skip_fails(Some("1"), Some("sandbox, ipv6"), why));
        assert!(skip_fails(Some("1"), Some("ipv4"), why));
        // Review round 4, cross-7: an explicit token, not a part of the text.
        assert!(skip_fails(Some("1"), Some("IPv6"), why), "a token is matched exactly");
        assert!(skip_fails(Some("1"), Some("6"), why));
        let untagged = "52.217.141.232:443 sent no time exceeded (no IPv6 here either)";
        assert!(skip_fails(Some("1"), Some("ipv6,IPv6"), untagged));
        assert!(skip_fails(Some("1"), Some("ipv6"), "[] nothing"));
        assert!(skip_fails(Some("1"), Some("ipv6"), "[ipv6 no closing bracket"));
    }
}
