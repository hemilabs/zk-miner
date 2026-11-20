//! On this host's real facts (interfaces, routes, policy rules, the kernel asked per destination,
//! public addresses, NAT64 discovery), the ELF path still admits ordinary public hosts: names
//! resolve over DNS-over-HTTPS to the fixed public resolvers, every address is vetted right
//! before connecting (its route with the port, the near-hop probe), and a real fetch goes
//! through the guarded client (redirects followed by hand).
//!
//! Needs public DNS-over-HTTPS and HTTPS; where the control lookup fails the test says so and
//! passes.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use zkminer_netguard::nearhop::{decide, NearProbe, ProbeOutcome, Verdict, PROBE_TIMEOUT};
use zkminer_netguard::{
    guarded_client, DohLookup, GuardedResolver, Lookup, NetMode, NetPolicy, TtlProbe,
};

#[tokio::test]
async fn ordinary_public_hosts_are_admitted_on_this_host() {
    let names = [
        "ipfs.io",
        "arweave.net",
        "github.com",
        "objects.githubusercontent.com",
        "release-assets.githubusercontent.com",
    ];
    let policy = NetPolicy::new(NetMode::Public, Vec::new()).expect("read this host");
    assert!(
        policy.facts().route_oracle().is_some(),
        "gathered facts ask the kernel per destination"
    );
    let doh = DohLookup::new(&policy).unwrap();
    if let Err(e) = doh.lookup(names[0]).await {
        skipped(format!("no DNS-over-HTTPS here ({e})"));
        return;
    }
    eprintln!("unknown paths here: {:?}", policy.facts().unknown_paths());
    let resolver = GuardedResolver::new(policy.clone(), Arc::new(doh.clone()));
    for name in names {
        let all = doh.lookup(name).await.expect(name);
        let admitted = resolver.resolve_admitted(name).await;
        eprintln!("{name}: answers {all:?}, admitted {admitted:?}");
        let admitted = admitted.unwrap_or_else(|e| panic!("{name} refused on this host: {e}"));
        assert!(!admitted.is_empty());
        // Every IPv4 answer of a public name is admitted here (IPv6 too, where the host routes
        // it), and passes the check right before connecting. (Two lookups of a round-robin name
        // can differ, so each answer is judged on its own.)
        for a in all.iter().filter(|a| a.is_ipv4()) {
            assert_eq!(policy.admit(*a), Ok(()), "{name}: {a}");
        }
        let first = SocketAddr::new(admitted[0], 443);
        let vetted = tokio::task::spawn_blocking({
            let p = policy.clone();
            move || p.vet_connection(first)
        })
        .await
        .unwrap();
        assert_eq!(vetted, Ok(()), "{name}: {first}");
    }
    // An NXDOMAIN is no such name.
    let e = doh
        .lookup("zkminer-netguard-no-such-name-7f3a9c.example.com")
        .await
        .unwrap_err();
    assert_eq!(e.kind(), std::io::ErrorKind::NotFound, "{e}");
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
    // And the host itself is still refused, by the same client's checks.
    for own in policy.facts().own_addresses() {
        let url = match own {
            std::net::IpAddr::V4(a) => format!("http://{a}/"),
            std::net::IpAddr::V6(a) => format!("http://[{a}]/"),
        };
        assert!(client.policy().check_url(&url).is_err(), "{url}");
    }
}

/// The near-hop probe for real, against public anycast resolvers: a probe limited to 2 hops dies
/// on the way (far), one with the usual hop limit connects. Where a family has no route here the
/// probe fails at once as unreachable, which also reads as far. A router on the way may rate-limit
/// its time-exceeded answers, so the 2-hop probe alone can time out; the decision is the guard's,
/// which then makes its check connection.
#[test]
fn public_hosts_are_far_and_reachable() {
    for addr in ["1.1.1.1:443", "[2606:4700:4700::1111]:443"] {
        let addr: SocketAddr = addr.parse().unwrap();
        let near = TtlProbe.probe(addr, 2, PROBE_TIMEOUT);
        eprintln!("{addr} within 2 hops: {near:?}");
        let decided = decide(&TtlProbe, addr, 2);
        assert_eq!(
            decided,
            Verdict::Far,
            "{addr}: probe {near:?}, decided {decided:?}"
        );
        let full = TtlProbe.probe(addr, 64, PROBE_TIMEOUT);
        eprintln!("{addr} within 64 hops: {full:?}");
        if full != ProbeOutcome::Unreachable {
            assert_eq!(full, ProbeOutcome::Connected, "{addr}");
        }
    }
    // Through the policy, at a public anycast address this host does not use as its DNS server.
    let policy = NetPolicy::new(NetMode::Public, Vec::new()).expect("read this host");
    if policy.facts().unknown_paths().is_empty() {
        let addr = ["1.1.1.1:443", "1.0.0.1:443", "8.8.4.4:443", "9.9.9.9:443"]
            .iter()
            .map(|a| a.parse::<SocketAddr>().unwrap())
            .find(|a| policy.admit(a.ip()).is_ok())
            .expect("a public anycast address the floor admits");
        assert_eq!(policy.vet_connection(addr), Ok(()), "{addr}");
    }
}

/// A near target that is not this host, given by the operator as `ZKMINER_TEST_NEAR_TARGET`
/// (`addr:port`, e.g. the first-hop router's own global address on a closed port): the probe
/// finds it near (it answers within 2 hops), or reads it as far when it drops the probe silently
/// (a router whose firewall drops what it does not serve; the real connection would be dropped
/// too). One probe.
#[test]
#[ignore = "needs a near target named in ZKMINER_TEST_NEAR_TARGET"]
fn a_near_target_is_near() {
    let target: SocketAddr = std::env::var("ZKMINER_TEST_NEAR_TARGET")
        .expect("ZKMINER_TEST_NEAR_TARGET")
        .parse()
        .expect("addr:port");
    let t = std::time::Instant::now();
    let got = TtlProbe.probe(target, 2, PROBE_TIMEOUT);
    eprintln!("{target} within 2 hops: {got:?} in {:?}", t.elapsed());
    assert!(
        matches!(got.verdict(), Verdict::Near(_)) || got == ProbeOutcome::TimedOut,
        "{got:?}"
    );
}

/// Tests: a test that cannot check what it is for on this host (no route of a family, no network,
/// a missing tool) says so and passes; under `ZKMINER_CI_STRICT=1` (a CI host that must run every
/// test: review round 3, cross-2) it fails instead, unless `why` starts with a token in brackets
/// (`"[ipv6] …"`) that `ZKMINER_CI_ALLOW_SKIP` (comma-separated tokens) names exactly (review
/// round 4, cross-7).
fn skipped(why: impl std::fmt::Display) {
    let why = why.to_string();
    if std::env::var("ZKMINER_CI_STRICT").is_ok_and(|v| v == "1") {
        let allowed = std::env::var("ZKMINER_CI_ALLOW_SKIP").unwrap_or_default();
        let token = why
            .strip_prefix('[')
            .and_then(|r| r.split_once(']'))
            .map(|(t, _)| t.trim().to_string())
            .filter(|t| !t.is_empty());
        if !token.is_some_and(|t| allowed.split(',').any(|a| a.trim() == t)) {
            panic!("SKIPPED under ZKMINER_CI_STRICT=1 (not in ZKMINER_CI_ALLOW_SKIP): {why}");
        }
    }
    eprintln!("SKIPPED: {why}");
}
