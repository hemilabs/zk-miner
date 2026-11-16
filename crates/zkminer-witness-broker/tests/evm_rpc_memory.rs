//! `parse_answers` streams: a ~1 MB `eth_getProof` answer costs about its canonical output in heap,
//! not a value tree. Measured with a counting global allocator, so this file holds a single test (the
//! counters are process-wide).

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};

use zkminer_witness::envelope::MethodSet;
use zkminer_witness_broker::evm_rpc::{parse_answers, parse_request, render, ParsedRequest};

struct Counting;

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

fn grew(by: usize) {
    let now = LIVE.fetch_add(by, Relaxed) + by;
    PEAK.fetch_max(now, Relaxed);
}

// SAFETY: forwards to the system allocator unchanged; only counts.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        let p = System.alloc(l);
        if !p.is_null() {
            grew(l.size());
        }
        p
    }

    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        System.dealloc(p, l);
        LIVE.fetch_sub(l.size(), Relaxed);
    }

    unsafe fn realloc(&self, p: *mut u8, l: Layout, new: usize) -> *mut u8 {
        let q = System.realloc(p, l, new);
        if !q.is_null() {
            // A moving realloc briefly holds both blocks: count the new one before the old goes.
            grew(new);
            LIVE.fetch_sub(l.size(), Relaxed);
        }
        q
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

/// Peak heap growth while `f` runs, over what was live when it started.
fn peak_during<T>(f: impl FnOnce() -> T) -> (T, usize) {
    let base = LIVE.load(Relaxed);
    PEAK.store(base, Relaxed);
    let out = f();
    (out, PEAK.load(Relaxed) - base)
}

const KEYS: usize = 64;

fn proof_request() -> ParsedRequest {
    let keys: Vec<String> = (0..KEYS).map(|i| format!("\"0x{:x}\"", i + 1)).collect();
    let body = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"eth_getProof","params":["0x{}",[{}],{{"blockHash":"0x{}"}}]}}"#,
        "ab".repeat(20),
        keys.join(","),
        "cd".repeat(32)
    );
    parse_request(body.as_bytes(), MethodSet::StateRead).unwrap()
}

/// A pretty-printed `eth_getProof` answer whose proofs hold `nodes_per_proof` 532-byte trie nodes.
fn proof_answer(id: u64, nodes_per_proof: usize) -> String {
    let node = format!("\"0x{}\"", "f9".repeat(532));
    let nodes = |n: usize| {
        format!(
            "[\n      {}\n    ]",
            vec![node.as_str(); n].join(",\n      ")
        )
    };
    let storage: Vec<String> = (0..KEYS)
        .map(|i| {
            format!(
                "{{\n    \"key\": \"0x{:064x}\",\n    \"value\": \"0x{:x}\",\n    \"proof\": {}\n  }}",
                i + 1,
                i * 7,
                nodes(nodes_per_proof)
            )
        })
        .collect();
    format!(
        "{{\n  \"jsonrpc\": \"2.0\",\n  \"id\": {id},\n  \"result\": {{\n  \"address\": \"0x{}\",\n  \"accountProof\": {},\n  \
         \"balance\": \"0x0\",\n  \"codeHash\": \"0x{}\",\n  \"nonce\": \"0x0\",\n  \"storageHash\": \"0x{}\",\n  \
         \"storageProof\": [\n  {}\n  ]\n  }}\n}}\n",
        "ab".repeat(20),
        nodes(nodes_per_proof),
        "c5".repeat(32),
        "56".repeat(32),
        storage.join(",\n  ")
    )
}

#[test]
fn a_one_megabyte_proof_streams_within_a_linear_memory_budget() {
    let req = proof_request();
    let one = proof_answer(9, 14);
    let two = proof_answer(9, 28);
    assert!((900_000..1_400_000).contains(&one.len()), "{}", one.len());

    let (answers, peak1) = peak_during(|| parse_answers(&req, one.as_bytes(), 9, 8 << 20).unwrap());
    let out1 = answers[0].canonical.len();
    assert!(!answers[0].is_error);
    assert!(
        out1 < one.len(),
        "whitespace is gone: {out1} < {}",
        one.len()
    );
    // The output buffer (sized once from the body) plus small scratch: no tree of nodes.
    assert!(
        peak1 <= one.len() + 64 * 1024,
        "peak {peak1} for a {} byte body",
        one.len()
    );
    assert!(peak1 >= out1, "the output itself is counted");

    let (answers2, peak2) =
        peak_during(|| parse_answers(&req, two.as_bytes(), 9, 8 << 20).unwrap());
    // Linear: twice the body, about twice the peak.
    assert!(peak2 <= 2 * peak1 + 64 * 1024, "peak {peak2} vs {peak1}");
    assert!(peak2 >= peak1, "peak {peak2} vs {peak1}");
    drop(answers2);

    // The cap is enforced while streaming: refusing early allocates no more than the cap allows.
    let cap = 256 * 1024;
    let (refused, peak3) = peak_during(|| parse_answers(&req, one.as_bytes(), 9, cap));
    assert!(refused.is_err());
    assert!(
        peak3 <= cap + 64 * 1024,
        "peak {peak3} with a {cap} byte cap"
    );

    // A batch has no single body to size from: the buffer grows by doubling, still linear.
    let batch_req = parse_request(
        format!("[{}]", String::from_utf8(req.outgoing(&|_| 0, 1)).unwrap()).as_bytes(),
        MethodSet::StateRead,
    )
    .unwrap();
    let batch_body = format!("[{}]", proof_answer(5, 14));
    let (batch, peak4) =
        peak_during(|| parse_answers(&batch_req, batch_body.as_bytes(), 5, 8 << 20).unwrap());
    assert_eq!(batch[0].canonical, answers[0].canonical);
    assert!(
        peak4 <= 3 * out1 + 64 * 1024,
        "batch peak {peak4} for {out1} bytes out"
    );

    // What a value tree costs on the same body, for the record.
    let (tree, tree_peak) =
        peak_during(|| serde_json::from_str::<serde_json::Value>(&one).unwrap());
    drop(tree);
    eprintln!(
        "body {} B, canonical {out1} B: streaming peak {peak1} B (2x body: {peak2} B, batch {peak4} B), \
         serde_json::Value peak {tree_peak} B",
        one.len()
    );
    assert_eq!(
        render(&req, &answers).len(),
        out1 + r#"{"jsonrpc":"2.0","id":1,"result":}"#.len()
    );

    // Many small values are where a tree blows up (tens of bytes per node); streaming stays at the
    // size of the body.
    let small_req = parse_request(
        br#"{"jsonrpc":"2.0","id":1,"method":"eth_getBlockByNumber","params":["0x1",false]}"#,
        MethodSet::StateRead,
    )
    .unwrap();
    let small = format!(
        r#"{{"jsonrpc":"2.0","id":3,"result":[{}]}}"#,
        vec!["0"; 500_000].join(",")
    );
    let (_, peak5) =
        peak_during(|| parse_answers(&small_req, small.as_bytes(), 3, 8 << 20).unwrap());
    let (tree, tree_peak5) =
        peak_during(|| serde_json::from_str::<serde_json::Value>(&small).unwrap());
    drop(tree);
    eprintln!(
        "1 MB of small integers: streaming peak {peak5} B, serde_json::Value peak {tree_peak5} B"
    );
    assert!(
        peak5 <= small.len() + 64 * 1024,
        "peak {peak5} for a {} byte body",
        small.len()
    );
    assert!(
        tree_peak5 > 4 * peak5,
        "the comparison is meaningful: {tree_peak5} vs {peak5}"
    );
}
