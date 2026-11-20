//! `simulate --adversarial` runs in the (unsandboxed) simulate process, on a `W` the requester's
//! builder wrote, up to `[witness] max_witness_bytes`. Its memory must not grow with the number of
//! mutations: each is made just before it runs and dropped after. This makes every mutation a run
//! would execute, as `run_mutations` makes them (one at a time, its sha256 kept), for a random `W`
//! framed as four u32-prefixed items (so the item mutations apply too) and for a scheme-1 `W` of
//! many one-byte nodes (the scheme mutator's worst case), and bounds the peak RSS above the
//! baseline by a few `|W|`.
//!
//! `ADVERSARIAL_MEMORY_W_MIB` sets `|W|` (default 2). Run alone: the peak is the process's.
//!
//! ```text
//! cargo test -p zkminer-witness-host --test adversarial_memory -- --nocapture
//! ```

use std::borrow::Cow;
use std::collections::HashSet;
use std::time::Instant;

use hemiprove_eth_prelude::scheme1::{scheme_word, AccountProof, ProofKind, TrieProof, Witness};
use sha2::{Digest, Sha256};
use zkminer_witness_host::adversarial::scheme1::Scheme1;
use zkminer_witness_host::adversarial::{generic_mutations, seed_for, Mutation, SchemeContext, SchemeMutator};

fn status(key: &str) -> u64 {
    let s = std::fs::read_to_string("/proc/self/status").unwrap();
    s.lines()
        .find(|l| l.starts_with(key))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap()
        * 1024
}

/// Resets the peak (`VmHWM`) to the current RSS.
fn reset_peak() {
    std::fs::write("/proc/self/clear_refs", "5").unwrap();
}

fn mib(b: u64) -> f64 {
    b as f64 / (1u64 << 20) as f64
}

/// Makes each of `mutations` (at most `max` distinct ones) as `run_mutations` does; how many it made.
fn make_all<'a>(w: &[u8], mutations: impl IntoIterator<Item = Mutation<'a>>, max: usize) -> usize {
    let mut seen: HashSet<[u8; 32]> = HashSet::from([Sha256::digest(w).into()]);
    let mut made = 0;
    for m in mutations {
        if made >= max {
            break;
        }
        let Some(bytes) = m.make() else { continue };
        if seen.insert(Sha256::digest(&bytes).into()) {
            made += 1;
        }
    }
    made
}

#[test]
fn mutations_are_made_one_at_a_time() {
    let n = std::env::var("ADVERSARIAL_MEMORY_W_MIB").ok().and_then(|v| v.parse().ok()).unwrap_or(2usize) << 20;
    let bound = |w_len: usize| 8 * w_len as u64 + (64 << 20);

    // A random W of four u32le-framed items.
    let mut w = vec![0u8; n];
    let mut x = 0x9e37_79b9_7f4a_7c15u64;
    for b in w.iter_mut() {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *b = x as u8;
    }
    let item = n / 4 - 4;
    for i in 0..4 {
        w[i * (item + 4)..i * (item + 4) + 4].copy_from_slice(&(item as u32).to_le_bytes());
    }
    reset_peak();
    let base = status("VmRSS:");
    let t = Instant::now();
    let generic = generic_mutations(&w, seed_for(&w, 0x7a6b_6d69_6e65_7231), 32);
    let listed = generic.len();
    let made = make_all(&w, generic, 256);
    let peak = status("VmHWM:").saturating_sub(base);
    println!(
        "generic: W {:.0} MiB, {made} of {listed} mutations made in {:?}; peak RSS above baseline {:.0} MiB ({:.1} x |W|)",
        mib(n as u64),
        t.elapsed(),
        mib(peak),
        peak as f64 / n as f64
    );
    assert!(made >= 40, "{made}");
    assert!(peak <= bound(n), "{:.0} MiB for a {:.0} MiB W", mib(peak), mib(n as u64));
    drop(w);

    // Scheme 1, twice: trie nodes of a real proof's size (532 bytes, as a branch node), and one-byte
    // nodes, the mutator's worst case: the decoded witness it keeps holds a slice per node (24
    // bytes), and each mutation clones that list while it makes its W.
    for node_bytes in [532usize, 1] {
        let nodes = (n - 64) / (node_bytes + 4);
        let w = Witness {
            header_words: vec![scheme_word()],
            headers: vec![Cow::Owned(vec![0xc0])],
            accounts: vec![AccountProof {
                proof: TrieProof {
                    kind: ProofKind::Inclusion,
                    nodes: (0..nodes).map(|i| Cow::Owned(vec![(i % 251) as u8; node_bytes])).collect(),
                },
                storage: vec![],
            }],
            receipts: vec![],
            transactions: vec![],
        }
        .encode()
        .unwrap();
        reset_peak();
        let base = status("VmRSS:");
        let t = Instant::now();
        let s = Scheme1::default();
        let ms = s.mutations(&w, &SchemeContext { statement: &[0u8; 32], seed: 1, answers: &[] }).unwrap();
        let made = make_all(&w, ms, 160);
        let peak = status("VmHWM:").saturating_sub(base);
        println!(
            "scheme 1: W {:.0} MiB ({nodes} nodes of {node_bytes} bytes), {made} mutations made in {:?}; peak RSS above \
             baseline {:.0} MiB ({:.1} x |W|)",
            mib(w.len() as u64),
            t.elapsed(),
            mib(peak),
            peak as f64 / w.len() as f64
        );
        assert_eq!(made, 160);
        let limit = bound(w.len()) + 128 * nodes as u64;
        assert!(
            peak <= limit,
            "{:.0} MiB for a {:.0} MiB W (limit {:.0} MiB)",
            mib(peak),
            mib(w.len() as u64),
            mib(limit)
        );
    }
}
