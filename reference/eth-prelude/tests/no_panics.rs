//! Fuzzing every decoder: arbitrary bytes and mutated real encodings never panic, and whatever a
//! decoder accepts re-encodes to exactly the bytes it read (one encoding per value, so a prover
//! cannot re-encode a header, an account, a receipt or a witness and keep what it means).

use proptest::prelude::*;

use hemiprove_eth_prelude::header::Header;
use hemiprove_eth_prelude::receipt::Receipt;
use hemiprove_eth_prelude::rlp;
use hemiprove_eth_prelude::scheme1::{scheme_word, Reader, Witness};
use hemiprove_eth_prelude::state::Account;
use hemiprove_eth_prelude::tx::Transaction;

fn fixture(name: &str) -> serde_json::Value {
    let path = format!("{}/tests/fixtures/{name}.json", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn hex(v: &serde_json::Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap().strip_prefix("0x").unwrap()).unwrap()
}

/// Real encodings to mutate: raw transactions, and account leaves and nodes from proofs.
fn corpus() -> &'static [Vec<u8>] {
    static CORPUS: std::sync::OnceLock<Vec<Vec<u8>>> = std::sync::OnceLock::new();
    CORPUS.get_or_init(|| {
        let mut out = Vec::new();
        for name in ["ethereum", "base", "hemi"] {
            let f = fixture(name);
            out.extend(f["rawTransactions"].as_array().unwrap().iter().take(8).map(hex));
            for p in f["proofs"].as_array().unwrap() {
                out.extend(p["proof"]["accountProof"].as_array().unwrap().iter().map(hex));
            }
        }
        out
    })
}

/// Every decoder on `b`, checking canonicity where an encoder exists.
fn decode_everything(b: &[u8]) {
    if let Ok(item) = rlp::decode_exact(b) {
        assert_eq!(item.raw(), b);
    }
    if let Ok(h) = Header::decode(b) {
        assert_eq!(h.encode().unwrap(), b, "a header decoded from bytes it does not encode to");
    }
    if let Ok(a) = Account::decode(b) {
        assert_eq!(a.encode(), b);
    }
    if let Ok(r) = Receipt::decode(b) {
        assert_eq!(r.encode().unwrap(), b);
    }
    let _ = Transaction::decode(b);
    if let Ok(w) = Witness::decode(b) {
        assert_eq!(w.encode().unwrap(), b);
    }
    if let Ok(mut r) = Reader::new(b) {
        let mut j = r.journal(None);
        if let Ok(p) = r.pin_scheme_id() {
            let _ = j.commit_pinned(&p);
        }
        while let Ok(p) = r.pin_word() {
            let _ = j.commit_pinned(&p);
        }
        let _ = r.finish(j);
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    #[test]
    fn arbitrary_bytes(b in proptest::collection::vec(any::<u8>(), 0..700)) {
        decode_everything(&b);
    }

    #[test]
    fn arbitrary_rlp_lists(items in proptest::collection::vec(proptest::collection::vec(any::<u8>(), 0..40), 0..24)) {
        // Lists of byte strings: the shapes headers, accounts, receipts and transactions have.
        let mut payload = Vec::new();
        for i in &items {
            rlp::encode_bytes(&mut payload, i);
        }
        let mut b = Vec::new();
        rlp::encode_list(&mut b, &payload);
        decode_everything(&b);
        let mut typed = vec![items.len() as u8 % 5];
        typed.extend_from_slice(&b);
        decode_everything(&typed);
    }

    #[test]
    fn arbitrary_witness_bodies(body in proptest::collection::vec(any::<u8>(), 0..400), words in 1u16..4) {
        let mut b = b"HPW\x01\x01".to_vec();
        b.extend(words.to_be_bytes());
        b.extend(scheme_word());
        b.extend(vec![0u8; 32 * usize::from(words - 1)]);
        b.extend(&body);
        decode_everything(&b);
    }

    #[test]
    fn mutated_real_encodings(pick in any::<prop::sample::Index>(), at in any::<prop::sample::Index>(), op in 0u8..4, byte in any::<u8>()) {
        let corpus = corpus();
        let mut b = corpus[pick.index(corpus.len())].clone();
        let i = at.index(b.len());
        match op {
            0 => b[i] ^= byte | 1,
            1 => { b.remove(i); }
            2 => b.insert(i, byte),
            _ => b.truncate(i),
        }
        decode_everything(&b);
    }
}

#[test]
fn real_encodings_decode_canonically() {
    for b in corpus() {
        decode_everything(b);
    }
    for name in ["ethereum", "base", "hemi"] {
        for raw in fixture(name)["rawTransactions"].as_array().unwrap() {
            Transaction::decode(&hex(raw)).unwrap();
        }
    }
}
