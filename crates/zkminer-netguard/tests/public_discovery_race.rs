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
        eprintln!("SKIPPED: no reflector answered here; nothing to race for");
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
