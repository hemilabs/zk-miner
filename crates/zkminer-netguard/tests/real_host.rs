//! Review r2: on this host's real facts (interfaces, routes, policy rules, the kernel asked per
//! destination, public addresses, NAT64 discovery), the ELF path still admits ordinary public
//! hosts: the guarded resolver hands out addresses for the program-store names, and a real fetch
//! goes through the guarded client (redirects followed by hand).
//!
//! Needs public DNS and HTTPS; where the control lookup fails the test says so and passes.

use std::sync::Arc;
use std::time::Duration;

use zkminer_netguard::{guarded_client, GuardedResolver, Lookup, NetMode, NetPolicy, SystemLookup};

#[tokio::test]
async fn ordinary_public_hosts_are_admitted_on_this_host() {
    let names = [
        "ipfs.io",
        "arweave.net",
        "github.com",
        "objects.githubusercontent.com",
        "release-assets.githubusercontent.com",
    ];
    if let Err(e) = SystemLookup.lookup(names[0]).await {
        eprintln!("SKIPPED: no public DNS here ({e})");
        return;
    }
    let policy = NetPolicy::new(NetMode::Public, Vec::new()).expect("read this host");
    assert!(
        policy.facts().route_oracle().is_some(),
        "gathered facts ask the kernel per destination"
    );
    let resolver = GuardedResolver::new(policy.clone(), Arc::new(SystemLookup));
    for name in names {
        let all = SystemLookup.lookup(name).await.expect(name);
        let admitted = resolver.resolve_admitted(name).await;
        eprintln!("{name}: answers {all:?}, admitted {admitted:?}");
        let admitted = admitted.unwrap_or_else(|e| panic!("{name} refused on this host: {e}"));
        assert!(!admitted.is_empty());
        // Every IPv4 answer of a public name is admitted here (IPv6 too, where the host routes it).
        for a in all.iter().filter(|a| a.is_ipv4()) {
            assert!(
                admitted.contains(a),
                "{name}: {a} refused: {:?}",
                policy.admit(*a)
            );
        }
    }
    // A real fetch through the guarded client, as the ELF download makes it.
    let client = guarded_client(&policy).unwrap();
    let r = client
        .get_following_redirects("https://github.com/", 5, Duration::from_secs(30))
        .await
        .expect("a guarded GET of github.com");
    eprintln!("GET https://github.com/ -> {}", r.status());
    assert!(
        r.status().is_success() || r.status().is_redirection(),
        "{}",
        r.status()
    );
    // And the host itself is still refused, through the same client.
    for own in policy.facts().own_addresses() {
        let url = match own {
            std::net::IpAddr::V4(a) => format!("http://{a}/"),
            std::net::IpAddr::V6(a) => format!("http://[{a}]/"),
        };
        assert!(client.get(&url).is_err(), "{url}");
    }
}
