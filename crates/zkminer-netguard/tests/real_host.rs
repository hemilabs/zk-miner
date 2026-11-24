//! On this host's real facts (interfaces, routes, policy rules, the kernel asked per destination,
//! public addresses, NAT64 discovery), the ELF path still admits ordinary public hosts: names
//! resolve over DNS-over-HTTPS to the fixed public resolvers, every address is vetted right
//! before connecting (its route with the port, the near-hop decision), and a real fetch goes
//! through the guarded client (redirects followed by hand).
//!
//! Needs public DNS-over-HTTPS and HTTPS; where the control lookup fails the test says so and
//! passes.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use zkminer_netguard::nearhop::{decide, Verdict};
use zkminer_netguard::{
    guarded_client, Denied, DohLookup, GuardedResolver, Lookup, NetMode, NetPolicy, TtlProbe,
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
    // Review r3 G1: the guard itself must let the resolvers be asked (on Windows it refused every
    // one, and this test skipped). Only a network that does not reach them skips.
    let asked: Vec<_> = doh
        .servers()
        .iter()
        .map(|s| (s.addr, policy.admit(s.addr.ip())))
        .collect();
    assert!(
        asked.iter().any(|(_, r)| matches!(
            r,
            Ok(()) | Err(Denied::DnsServer(_)) | Err(Denied::PublicAddressUnknown { .. })
        )),
        "the network guard refuses every DNS-over-HTTPS resolver on this host: {asked:?}"
    );
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
        // Where the near-hop check cannot find anything far (Windows), every vet refuses.
        if let Err(why) = zkminer_netguard::nearhop::supported() {
            skipped(format!("the near-hop check refuses every destination here: {why}"));
            continue;
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
        .await;
    if zkminer_netguard::nearhop::supported().is_err() {
        // Fails closed: the fetch is refused, never made unchecked.
        eprintln!("GET https://github.com/ refused here: {:?}", r.as_ref().err());
        assert!(r.is_err(), "fetched with a near-hop check that finds nothing far");
    } else {
        let r = r.expect("a guarded GET of github.com");
        eprintln!("GET https://github.com/ -> {}", r.status());
        assert!(
            r.status().is_success() || r.status().is_redirection(),
            "{}",
            r.status()
        );
    }
    // And the host itself is still refused, by the same client's checks.
    for own in policy.facts().own_addresses() {
        let url = match own {
            std::net::IpAddr::V4(a) => format!("http://{a}/"),
            std::net::IpAddr::V6(a) => format!("http://[{a}]/"),
        };
        assert!(client.policy().check_url(&url).is_err(), "{url}");
    }
}

/// Review r3 G1/G2: on Linux, macOS and Windows the facts public mode rests on are read: the routing
/// table (a default route makes a family routed, so its public address must be known), the DNS
/// servers, the interfaces with their kinds, and the kernel's route for a public address, which
/// takes the default path. Elsewhere public mode says it cannot work.
#[test]
fn this_hosts_facts_are_read() {
    if let Some(why) = zkminer_netguard::public_mode_unsupported() {
        eprintln!("SKIPPED: {why}");
        return;
    }
    let policy = NetPolicy::new(NetMode::Public, Vec::new()).expect("read this host");
    let facts = policy.facts();
    let routes = facts.routes();
    eprintln!(
        "routes: {}, default interfaces {:?}, uplinks {:?}, DNS servers: {}, unknown paths {:?}, \
         needs internal_ranges: {:?}",
        routes.routes().len(),
        routes.default_interfaces(),
        routes.uplinks(),
        facts.resolvers().len(),
        facts.unknown_paths(),
        facts.needs_internal_ranges()
    );
    assert!(routes.routes_family(false), "no IPv4 default route read");
    assert!(
        !routes.on_link_prefixes().is_empty(),
        "no on-link route read"
    );
    for p in routes.on_link_prefixes() {
        assert!(facts.connected().contains(&p), "{p}");
    }
    #[cfg(windows)]
    assert!(!facts.resolvers().is_empty(), "no DNS server read");
    for r in facts.resolvers() {
        assert!(policy.admit(*r).is_err(), "DNS server {r} admitted");
    }
    let oracle = facts.route_oracle().expect("gathered facts ask the kernel");
    let answer = oracle
        .route_to("1.1.1.1".parse().unwrap(), Some(443))
        .expect("the kernel answers");
    assert_eq!(routes.judge_answer(&answer), Ok(()), "{answer:?}");
}

/// The near-hop decision for real, against public anycast resolvers: probes limited to 2..4 hops
/// run out of hops on the way and a router past the limit says so (far, the evidence naming the
/// router and the probe's own address), and a connection with the usual hop limit connects. A
/// family with no route here is skipped (a probe that fails at once is a local failure, refused,
/// never far).
#[test]
fn public_hosts_are_far_and_reachable() {
    if let Err(why) = zkminer_netguard::nearhop::supported() {
        skipped(format!("the near-hop check refuses every destination here: {why}"));
        return;
    }
    for addr in ["1.1.1.1:443", "[2606:4700:4700::1111]:443"] {
        let addr: SocketAddr = addr.parse().unwrap();
        let reachable = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(3));
        eprintln!("{addr} with the default hop limit: {reachable:?}");
        let decided = decide(&TtlProbe, addr, 2);
        eprintln!("{addr} within 2 hops: {decided:?}");
        if reachable.is_err() {
            let family = if addr.is_ipv6() { "[ipv6] " } else { "" };
            skipped(format!("{family}{addr} is not reachable here: {reachable:?}"));
            continue;
        }
        match decided {
            Verdict::Far(e) => {
                assert!(e.ttl >= 2 && e.from != addr.ip(), "{e:?}");
                assert!(e.local.is_some_and(|l| l.port() != 0), "{e:?}");
            }
            other => panic!("{addr}: {other:?}"),
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
        // The path vetted is pinned to the probes' source address and its interface (Windows:
        // the source address only, no interface pin).
        let v = policy.vet_path(addr, addr).expect("vetted");
        assert!(v.source.is_some(), "{v:?}");
        assert!(cfg!(windows) || v.interface.is_some(), "{v:?}");
        let sock = v.socket().expect("the pinned socket");
        let bound = sock.local_addr().unwrap().as_socket().unwrap();
        assert_eq!(Some(bound.ip()), v.source);
    }
}

/// A near target that is not this host, given by the operator as `ZKMINER_TEST_NEAR_TARGET`
/// (`addr:port`, e.g. the first-hop router's own global address on a closed port): the decision
/// finds it near (it answers within 2 hops), or refuses it for want of evidence when it drops
/// the probes silently; never far.
#[test]
#[ignore = "needs a near target named in ZKMINER_TEST_NEAR_TARGET"]
fn a_near_target_is_near() {
    let target: SocketAddr = std::env::var("ZKMINER_TEST_NEAR_TARGET")
        .expect("ZKMINER_TEST_NEAR_TARGET")
        .parse()
        .expect("addr:port");
    let t = std::time::Instant::now();
    let got = decide(&TtlProbe, target, 2);
    eprintln!("{target} within 2 hops: {got:?} in {:?}", t.elapsed());
    assert!(!matches!(got, Verdict::Far(_)), "{got:?}");
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
