//! Review r2 R2-NG-6 (PoC `pubrace`), inverted: facts gathered while the process's first
//! public-address discovery runs on another thread wait for it, and refuse what it learned. Before
//! the fix the second caller got `[]`, and its facts admitted the host's own NAT address.
//!
//! Needs the real reflectors (public DNS); without them both callers learn nothing and the test
//! says so and passes. This file holds only this test: the discovery cache is process-wide, and
//! the race needs a process in which no discovery has run yet.

use std::time::{Duration, Instant};

use zkminer_netguard::public::{learned, FIRST_DISCOVERY_WAIT};
use zkminer_netguard::{admit, FactsOptions, HostFacts, NetMode};

#[test]
fn facts_gathered_during_the_first_discovery_wait_for_it() {
    let first = std::thread::spawn(learned);
    std::thread::sleep(Duration::from_millis(2));
    let t = Instant::now();
    let facts = HostFacts::gather_with(&FactsOptions::default()).expect("read the host");
    let waited = t.elapsed();
    let first = first.join().unwrap();
    assert!(
        waited < FIRST_DISCOVERY_WAIT + Duration::from_secs(1),
        "{waited:?}"
    );
    if first.addresses.is_empty() {
        skipped("no reflector answered here; nothing to race for");
        return;
    }
    for ip in &first.addresses {
        assert!(
            facts.own_addresses().contains(ip),
            "{ip} learned by the first caller is missing from facts gathered meanwhile ({:?})",
            facts.own_addresses()
        );
        assert!(admit(NetMode::Public, *ip, &facts, &[]).is_err(), "{ip}");
    }
    eprintln!(
        "concurrent facts waited {waited:?} and refuse {:?}",
        first.addresses
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
