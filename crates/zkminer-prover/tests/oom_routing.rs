//! A VRAM OOM on a smaller card must route the retry to a strictly BIGGER one.
//!
//! Measured on this box: bigint-mul's groth16 wrap OOMs on the 16,303 MiB RTX 5080
//! (`cudaMallocAsync ... "out of memory"`, ErrorKind::ResourceExhausted) and proves on
//! the 24,564 MiB RTX 4090 in 16s. The miner's OOM arm used to respond by setting
//! `min_vram = LARGE_JOB_MIN_VRAM_BYTES` (30 GiB), which exceeds EVERY card here, so the
//! filter matched nothing, `prove_min_vram` restored the full key set, and the retry
//! could land straight back on the card that had just failed.
//!
//! Run with (needs both cards):
//!   cargo test --release -p zkminer-prover --test oom_routing -- --ignored --nocapture --test-threads=1

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;
use zkminer_prover::dispatcher::WorkerPool;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn find_risc0_elf(guest: &str) -> Option<Vec<u8>> {
    let p = workspace_root().join(format!(
        "target/riscv-guest/zkminer-prover/{guest}/riscv32im-risc0-zkvm-elf/release/{guest}.bin"
    ));
    if p.exists() {
        return std::fs::read(&p).ok();
    }
    let alt = p.with_extension("");
    if alt.exists() {
        std::fs::read(&alt).ok()
    } else {
        None
    }
}

fn input(vals: &[u32]) -> Vec<u8> {
    vals.iter().flat_map(|v| v.to_le_bytes()).collect()
}

/// The accessor the relative floor depends on must report real per-card VRAM, and the
/// two cards must differ — otherwise "a strictly bigger card" is not expressible and
/// this box cannot exercise the routing at all.
#[test]
#[ignore = "needs real CUDA workers; run explicitly"]
fn per_slot_vram_is_known_and_cards_differ() {
    let mut pool = WorkerPool::new(HashMap::new(), Vec::new(), Some(Duration::from_secs(600)));
    let connected = pool.discover_and_spawn();
    let mut sizes: Vec<(String, u64)> = connected
        .iter()
        .filter(|k| k.starts_with("risc0:cuda"))
        .filter_map(|k| pool.vram_bytes_for_slot(k).map(|v| (k.clone(), v)))
        .collect();
    sizes.sort_by_key(|(_, v)| *v);
    for (k, v) in &sizes {
        eprintln!("  {k}: {} MiB", v / 1024 / 1024);
    }
    assert!(sizes.len() >= 2, "need >= 2 cuda slots, got {sizes:?}");
    assert!(
        sizes[0].1 < sizes[sizes.len() - 1].1,
        "the cards must differ in VRAM for a relative floor to steer anywhere: {sizes:?}"
    );
    pool.shutdown_all();
}

/// THE ROUTING. Ask for strictly more VRAM than the smallest card has, and assert the
/// proof lands on a bigger one — i.e. the floor the OOM arm now computes actually
/// excludes the card that failed, which a 30 GiB floor could not do.
#[test]
#[ignore = "needs real CUDA workers; run explicitly"]
fn a_relative_vram_floor_routes_off_the_smallest_card() {
    let elf = find_risc0_elf("fibonacci")
        .filter(|e| !e.is_empty())
        .expect("fibonacci ELF");

    let mut pool = WorkerPool::new(HashMap::new(), Vec::new(), Some(Duration::from_secs(600)));
    let connected = pool.discover_and_spawn();
    let mut sizes: Vec<(String, u64)> = connected
        .iter()
        .filter(|k| k.starts_with("risc0:cuda"))
        .filter_map(|k| pool.vram_bytes_for_slot(k).map(|v| (k.clone(), v)))
        .collect();
    sizes.sort_by_key(|(_, v)| *v);
    assert!(sizes.len() >= 2, "need >= 2 cuda slots");
    let (small_key, small_vram) = sizes[0].clone();
    eprintln!(
        "smallest card: {small_key} @ {} MiB",
        small_vram / 1024 / 1024
    );

    // Exactly what the OOM arm now computes: one byte more than the failed card.
    let floor = small_vram.saturating_add(1);
    let mut used = None;
    let r = pool.prove_min_vram(
        "risc0",
        &elf,
        &input(&[1000]),
        None,
        Some(Duration::from_secs(300)),
        None,
        Some(floor),
        &[],
        &[],
        &mut used,
        None,
        None,
    );
    assert!(
        r.is_ok(),
        "proof should succeed on a bigger card: {:?}",
        r.err().map(|e| format!("{e:#}"))
    );
    let landed = used.expect("used_slot must be recorded");
    eprintln!("floor {} MiB -> landed on {landed}", floor / 1024 / 1024);
    assert_ne!(
        landed, small_key,
        "a floor of smallest+1 must NOT route back to the smallest card — that is the \
         exact failure the 30 GiB constant produced, since it matched no card and the \
         full key set was restored"
    );
    assert!(
        pool.vram_bytes_for_slot(&landed).unwrap_or(0) > small_vram,
        "the chosen card must be strictly bigger"
    );
    pool.shutdown_all();
}
