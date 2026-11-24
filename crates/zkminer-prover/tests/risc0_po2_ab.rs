//! Steady-state A/B of risc0 segment sizes on one card: the calibration proof (`calibrate_slot_po2`,
//! the same Groth16 pipeline a job runs) at each size in turn, on ONE warm worker, in ABBA order so
//! drift and the cards' occasional slow spells fall on every size alike.
//!
//! A sweep that proves each size once (`calibrate_po2_for_suite`) can neither show steady-state speed
//! nor steady-state memory: its first proof starts on an empty card, and a card that slows for a
//! minute decides the argmax. This prints every proof's wall-clock window (to line up with an outside
//! VRAM or clock sampler) and each size's median.
//!
//! `#[ignore]`d — real GPU proofs. Run with:
//!   ZKMINER_TEST_RISC0_SLOT=risc0:cuda:0 ZKMINER_TEST_PO2S=20,21 ZKMINER_TEST_ROUNDS=3 \
//!     cargo test --release -p zkminer-prover --test risc0_po2_ab -- --ignored --nocapture
//! A size the card has no room for comes back as a sample at a smaller size (`calibrate_slot_po2`
//! sizes to what is free) and is reported as such.

use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use zkminer_prover::dispatcher::WorkerPool;

fn now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

#[test]
#[ignore = "real GPU proofs"]
fn alternate_segment_sizes_on_one_warm_worker() {
    let slot =
        std::env::var("ZKMINER_TEST_RISC0_SLOT").unwrap_or_else(|_| "risc0:cuda:0".to_string());
    let sizes: Vec<u8> = std::env::var("ZKMINER_TEST_PO2S")
        .unwrap_or_else(|_| "20,21".to_string())
        .split(',')
        .map(|s| {
            s.trim()
                .parse()
                .expect("ZKMINER_TEST_PO2S: comma-separated sizes")
        })
        .collect();
    let rounds: usize = std::env::var("ZKMINER_TEST_ROUNDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(3);
    assert!(!sizes.is_empty());

    let mut pool = WorkerPool::new(HashMap::new(), Vec::new(), Some(Duration::from_secs(1800)));
    let connected = pool.discover_and_spawn();
    assert!(
        connected.contains(&slot),
        "{slot} is not among the connected workers: {connected:?}"
    );

    // One proof to warm the worker (kernels, the Groth16 component, the first wrap's SRS upload):
    // not counted.
    let warm = pool
        .calibrate_slot_po2(&slot, sizes[0])
        .expect("warm-up proof");
    eprintln!(
        "AB {slot} warm-up po2={} {:.2}s (not counted)",
        warm.po2, warm.duration_secs
    );

    // ABBA: each round runs the sizes forward, then backward.
    let mut order: Vec<u8> = Vec::new();
    for r in 0..rounds {
        if r % 2 == 0 {
            order.extend(sizes.iter().copied());
        } else {
            order.extend(sizes.iter().rev().copied());
        }
    }
    let mut times: HashMap<u8, Vec<f64>> = HashMap::new();
    for (i, asked) in order.iter().copied().enumerate() {
        let start = now();
        match pool.calibrate_slot_po2(&slot, asked) {
            Ok(s) => {
                let mib = |b: Option<u64>| b.map_or("?".to_string(), |b| (b >> 20).to_string());
                eprintln!(
                    "AB {slot} #{i} asked={asked} po2={} window={start:.1}-{:.1} secs={:.2} \
                     cycles={} segments={} cps={:.0} vram_peak_mib={} free_at_start_mib={}",
                    s.po2,
                    now(),
                    s.duration_secs,
                    s.total_cycles,
                    s.segment_count,
                    s.throughput,
                    mib(s.vram_peak_bytes),
                    mib(s.vram_available_bytes),
                );
                times.entry(s.po2).or_default().push(s.duration_secs);
            }
            Err(e) => eprintln!(
                "AB {slot} #{i} asked={asked} window={start:.1}-{:.1} FAILED: {e:#}",
                now()
            ),
        }
    }
    let mut keys: Vec<u8> = times.keys().copied().collect();
    keys.sort_unstable();
    for p in keys {
        let mut v = times[&p].clone();
        v.sort_by(f64::total_cmp);
        let median = v[v.len() / 2];
        eprintln!(
            "AB {slot} po2={p} n={} median={median:.2}s all={v:.2?}",
            v.len()
        );
    }
    pool.shutdown_all();
}
