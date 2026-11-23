//! The witness broker reads the host's facts once, then sandboxes itself, and its sandbox refuses
//! a process that already has a second thread. After `nat64::without_listener`, the first facts
//! read on Linux leaves no thread of netguard's behind: no PREF64 listener (which outlives the
//! read by design), and the first NAT64 round and public-address discovery run on the calling
//! thread. Before the fix, the listener started on the first read, so every broker on Linux
//! exited at startup: "restrict_self must run before the process starts threads: 2 threads in
//! /proc/self/task".
//!
//! This file holds only this test: the switch and the listener are process-wide.
#![cfg(target_os = "linux")]

use zkminer_netguard::{FactsOptions, HostFacts};

/// The names of this process's threads that netguard started (`netguard-*`).
fn netguard_threads() -> Vec<String> {
    let mut names = Vec::new();
    for task in std::fs::read_dir("/proc/self/task").expect("read /proc/self/task") {
        let comm = task.expect("a task").path().join("comm");
        if let Ok(name) = std::fs::read_to_string(&comm) {
            let name = name.trim().to_string();
            if name.starts_with("netguard") {
                names.push(name);
            }
        }
    }
    names
}

#[test]
fn a_facts_read_without_the_listener_leaves_no_thread_behind() {
    zkminer_netguard::nat64::without_listener();
    assert!(zkminer_netguard::nat64::listener_refused());
    // The broker's own options (`[egress]` defaults: public-address discovery on).
    let facts = HostFacts::gather_with(&FactsOptions::default()).expect("read the host");
    assert!(!facts.own_addresses().is_empty());
    assert_eq!(netguard_threads(), Vec::<String>::new());
}
