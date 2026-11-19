//! The reference guest on the risc0 executor (CPU), on real Ethereum, Base and Hemi proxies: it
//! commits exactly the journal the statement computes natively, under any `sys_rand` seed and
//! segment size, and refuses mutated witnesses.

mod common;

use common::*;
use hemiprove_eth_prelude::scheme1::{judge, Mutation, ProofRef, Verdict};
use hemiprove_proxy_slots::{decode_journal, run, HEADER_BYTES, PREFIX_BYTES};

#[test]
fn the_guest_commits_what_the_statement_computes_on_real_chains() {
    for (name, k) in [("ethereum", 3), ("base", 6), ("hemi", 6)] {
        let f = fixture(name);
        let (s, w) = real_witness(&f, k);
        let input = input(&prefix(0x11, 0x22), &w.encode().unwrap());
        let native = run(&input).unwrap();
        let executed = execute(&input, [0; 32], 20).unwrap();
        assert_eq!(executed.journal, native, "{name}");
        let j = decode_journal(&executed.journal).unwrap();
        assert_eq!(j.statement, s);
        assert_eq!(&executed.journal[PREFIX_BYTES..PREFIX_BYTES + HEADER_BYTES], &s.header());
        eprintln!(
            "{name}: W {} bytes, {} cycles in {} segments at po2 20, implementation 0x{}",
            input.len() - 64,
            executed.cycles,
            executed.segments,
            hex::encode(j.outputs.implementation)
        );
    }
}

#[test]
fn the_journal_does_not_depend_on_the_seed_or_the_segment_size() {
    let (_, w) = real_witness(&fixture("base"), 6);
    let input = input(&prefix(0x33, 0x44), &w.encode().unwrap());
    let a = execute(&input, [0; 32], 16).unwrap();
    let b = execute(&input, [0xff; 32], 21).unwrap();
    assert_eq!(a.journal, b.journal);
    assert!(a.segments > b.segments, "{} vs {} segments", a.segments, b.segments);
}

#[test]
fn the_guest_refuses_mutated_witnesses() {
    let f = fixture("hemi");
    let (_, w) = real_witness(&f, 6);
    let p = prefix(1, 2);
    let honest = execute(&input(&p, &w.encode().unwrap()), [0; 32], 20).unwrap().journal;
    let parent = header_from_json(&f["parent"]).encode().unwrap();
    let mutations = [
        Mutation::ReplaceHeader { header: 0, rlp: parent },
        Mutation::HeaderByte { header: 0, byte: 100, mask: 1 },
        Mutation::FlipKind { proof: ProofRef::Storage { account: 0, slot: 1 } },
        Mutation::DropNode { proof: ProofRef::Account(1), node: 0 },
        Mutation::NodeByte { proof: ProofRef::Storage { account: 0, slot: 0 }, node: 0, byte: 40, mask: 1 },
        Mutation::SwapProofs { a: ProofRef::Storage { account: 0, slot: 1 }, b: ProofRef::Storage { account: 0, slot: 2 } },
        Mutation::DropProof { proof: ProofRef::Storage { account: 0, slot: 6 } },
        Mutation::AppendBytes { bytes: vec![0] },
        Mutation::WordByte { word: 2, byte: 31, mask: 1 },
    ];
    for m in &mutations {
        let mutated = w.mutate(m).unwrap();
        let out = execute(&input(&p, &mutated), [0; 32], 20);
        let verdict = judge(&honest, out.as_ref().ok().map(|e| e.journal.as_slice()), PREFIX_BYTES + HEADER_BYTES);
        assert_eq!(verdict, Verdict::Rejected, "{m:?}: {:?}", out.err());
        // The native statement agrees.
        assert!(run(&input(&p, &mutated)).is_err(), "{m:?}");
    }
}
