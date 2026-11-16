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
//!   IPv4 address or refused ([`ip`] module doc for the ranges);
//! - [`check_host_name`]: host-name hygiene for requester names ([`INTERNAL_SUFFIXES`]);
//! - [`HostFacts`]: the host's own addresses and connected prefixes, from its interfaces;
//! - [`admit`]: the single admission decision for an address, by [`NetMode`];
//! - [`check_url`]: the gate for a requester URL (scheme, user information, a strict reading that
//!   the URL standard's parser must agree with, host hygiene, and IP literals through [`admit`]);
//! - [`NetPolicy`]: the mode, refreshing host facts and the operator's deny CIDRs, as one value;
//! - [`ipfs_gateway_url`] / [`arweave_gateway_url`]: content ids syntax-checked into gateway URLs;
//! - with the `client` feature (default): [`GuardedResolver`], reqwest's DNS hook that hands the
//!   connector only admitted addresses from one lookup (no DNS rebinding), and [`guarded_client`],
//!   an HTTP client that refuses unchecked URLs, ignores proxies, follows redirects only by hand
//!   ([`GuardedClient::get_following_redirects`]), and decodes no compression.
//!
//! Without the `client` feature the crate needs only `url` (and libc or windows-sys for the
//! interfaces), for crates that only parse configuration.

pub mod content;
mod facts;
mod host;
pub mod ip;
mod policy;
mod url;

#[cfg(feature = "client")]
mod client;
#[cfg(feature = "client")]
mod resolve;

pub use crate::url::{check_url, MAX_URL_LEN};
pub use ::url::Url;
pub use content::{arweave_gateway_url, ipfs_gateway_url, ContentIdDenied};
pub use facts::HostFacts;
pub use host::{check_host_name, HostDenied, INTERNAL_SUFFIXES};
pub use ip::{canonical_ip, is_global, Prefix, PrefixParseError};
pub use policy::{admit, Denied, NetMode, NetPolicy, UrlDenied, FACTS_TTL};

#[cfg(feature = "client")]
pub use client::{
    guarded_client, guarded_client_with, ClientOptions, FetchError, GuardedClient, USER_AGENT,
};
#[cfg(feature = "client")]
pub use resolve::{
    GuardedResolver, Lookup, LookupFuture, ResolveError, SystemLookup, DNS_TIMEOUT,
    MAX_CONCURRENT_LOOKUPS,
};

#[cfg(any(test, feature = "test-util"))]
pub use client::guarded_client_for_test;
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

#[cfg(test)]
mod tests {
    #[test]
    fn printable_escapes_and_bounds() {
        assert_eq!(super::printable("a.b-c", 10), "a.b-c");
        assert_eq!(super::printable("a\r\nb\x1b[0m", 50), "a\\r\\nb\\u{1b}[0m");
        assert_eq!(super::printable("x\u{202e}y", 50), "x\\u{202e}y");
        assert_eq!(super::printable("abcdef", 3), "abc…");
    }
}
