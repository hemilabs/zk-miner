//! Our own VRAM must be credited to us, not counted as another process's.
//!
//! The VRAM gate refuses an SP1 proof on a card where too little is free to it. The hazard it
//! introduces is the mirror image: counting OUR OWN device memory as foreign and refusing a card that
//! is perfectly healthy. That cannot be caught in a unit test, because it depends on what the real
//! `sp1-gpu-server` does with the real driver.
//!
//! Measured on this box on 2026-10-05, sampling the 5080 every 3s through a `fibonacci` proof:
//! `sp1-gpu-server` holds 15,076 MiB of the card's 16,303 for the duration. That run read it as
//! released within ~3s of finishing, but on 2026-10-07 the idle server still held 15,124 MiB 30 s
//! after its proof (15,302 MiB on the 4090), so do not rely on it letting go — see
//! `cross_backend_vram.rs`. The moment this test samples is DURING a proof, which is when the card is
//! fullest and the credit matters most: it reads the gate's own evidence from another thread while a
//! proof runs, and requires that the card reads as almost entirely in use while essentially none of it
//! is attributed to anything but this slot.
//!
//! The same shape of bug has already been made twice in this codebase's memory accounting: the
//! host-memory ledger credited resident workers with MIN instead of MAX and made SP1 unclaimable
//! after one proof.
//!
//! Assumes nothing else is on the card — no display, no other backend's worker — since it bounds
//! what may be charged against the slot to driver bookkeeping.
//!
//! `#[ignore]`d — it is a real GPU proof. Run with:
//!   cargo test -p zkminer-prover --test sp1_warm_slot_vram -- --ignored --test-threads=1 --nocapture

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use zkminer_prover::dispatcher::WorkerPool;

fn find_sp1_fibonacci_elf() -> Option<Vec<u8>> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let elf_path = manifest_dir.join(
        "../zkminer-prover/guests/sp1/fibonacci/target/elf-compilation/\
         riscv64im-succinct-zkvm-elf/release/fibonacci-sp1-guest",
    );
    elf_path.exists().then(|| std::fs::read(&elf_path).ok())?
}

#[test]
#[ignore = "real GPU proof"]
fn our_own_device_memory_is_never_counted_as_foreign() {
    let _ = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()),
        )
        .try_init();

    let Some(elf) = find_sp1_fibonacci_elf().filter(|e| !e.is_empty()) else {
        eprintln!("SKIP: SP1 fibonacci ELF not found");
        return;
    };

    let mut pool = WorkerPool::new(HashMap::new(), vec![], Some(Duration::from_secs(900)));
    let connected = pool.discover_and_spawn();
    let want = std::env::var("ZKMINER_TEST_SP1_SLOT").ok();
    let key = match &want {
        Some(w) => connected.iter().find(|k| *k == w).cloned(),
        None => connected.iter().find(|k| k.starts_with("sp1:")).cloned(),
    };
    let Some(key) = key else {
        eprintln!("SKIP: no SP1 worker (connected: {connected:?})");
        pool.shutdown_all();
        return;
    };

    // The rule is now "the backend's floor must be FREE", so what this test must show is that our
    // own server's VRAM does not count against that floor. See `min_available_vram_bytes_for_backend`.
    let needed = zkminer_prover::discovery::min_available_vram_bytes_for_backend("sp1")
        .expect("sp1 must require free VRAM for this test to mean anything");

    // Sample the gate's own evidence while the proof runs.
    let pool = Arc::new(pool);
    let stop = Arc::new(AtomicBool::new(false));
    let peak_used = Arc::new(AtomicU64::new(0));
    let peak_elsewhere = Arc::new(AtomicU64::new(0));
    let min_available = Arc::new(AtomicU64::new(u64::MAX));
    let sampler = {
        let (pool, stop, peak_used, peak_elsewhere, min_available) = (
            pool.clone(),
            stop.clone(),
            peak_used.clone(),
            peak_elsewhere.clone(),
            min_available.clone(),
        );
        let key = key.clone();
        std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                // `held_elsewhere` is everything NOT held by this slot's own worker tree, which is
                // exactly what must stay small while our own server holds the card.
                // Only while our server is actually holding the card (≥ 4 GiB of its own): before
                // admission and after the proof, `held_elsewhere` legitimately includes whatever else
                // of ours is on the card, which is not what this test is about.
                if let Some(budget) = pool.vram_budget_for_slot(&key) {
                    peak_used.fetch_max(budget.used, Ordering::Relaxed);
                    if budget.used.saturating_sub(budget.held_elsewhere) >= 4 << 30 {
                        peak_elsewhere.fetch_max(budget.held_elsewhere, Ordering::Relaxed);
                        min_available.fetch_min(budget.available, Ordering::Relaxed);
                    }
                }
                std::thread::sleep(Duration::from_millis(500));
            }
        })
    };

    let input = 100u32.to_le_bytes();
    let result = pool.prove(
        &key,
        &elf,
        &input,
        None,
        Some(Duration::from_secs(900)),
        None,
    );
    stop.store(true, Ordering::Relaxed);
    let _ = sampler.join();

    let (used, elsewhere, available) = (
        peak_used.load(Ordering::Relaxed),
        peak_elsewhere.load(Ordering::Relaxed),
        min_available.load(Ordering::Relaxed),
    );
    let total = pool
        .vram_budget_for_slot(&key)
        .map(|b| b.total)
        .unwrap_or(0);
    const MIB: f64 = 1024.0 * 1024.0;
    eprintln!(
        "{key}: peak VRAM in use {:.0} MiB, of which {:.0} MiB was counted against this slot, \
         leaving at least {:.0} MiB available; the card is {:.0} MiB and sp1 needs {:.0} MiB free",
        used as f64 / MIB,
        elsewhere as f64 / MIB,
        available as f64 / MIB,
        total as f64 / MIB,
        needed as f64 / MIB,
    );

    if let Err(e) = &result {
        let own_vram = e
            .downcast_ref::<zkminer_prover_protocol::types::GpuMemoryShortage>()
            .is_some();
        assert!(
            !own_vram,
            "{key} refused its own proof for VRAM, with nothing else on the card: {e:#}"
        );
    }

    // Non-vacuity first. If the card never filled up, nothing was credited and the assertion below
    // would pass for the wrong reason — which is exactly how the first version of this test passed:
    // it read the card AFTER the proof, and that day the server read as having released everything.
    assert!(
        used > 4 * 1024 * 1024 * 1024,
        "the card never exceeded {:.0} MiB in use, so this test never observed our server holding \
         it and proves nothing about crediting. Did the proof actually run? result: {:?}",
        used as f64 / MIB,
        result
            .as_ref()
            .map(|p| p.seal.len())
            .map_err(|e| format!("{e:#}")),
    );
    assert!(
        available != u64::MAX,
        "no sample caught our server holding the card, so nothing below is evidence of crediting"
    );
    // Essentially none of the card may be charged against the slot while its own server holds it:
    // driver bookkeeping, nothing more. Bounded on its own because the floor check below is loose on a
    // big card — on the 4090 it would let 8 GiB of misattribution through.
    assert!(
        elsewhere < 512 * 1024 * 1024,
        "{:.0} MiB of the card was charged against {key} while only our own server held it",
        elsewhere as f64 / MIB,
    );
    // The substantive assertion: with ~15 GiB of this card held by our OWN server, the amount the
    // gate considers available — at the fullest moment sampled — must still clear the floor. If the
    // credit regressed, `available` would collapse to near zero and every proof after the first on
    // this slot would be refused on a card that is perfectly healthy.
    assert!(
        available >= needed,
        "while our own sp1-gpu-server held {} MiB of this card, only {} MiB was considered \
         available against a {} MiB floor. The gate must credit our process tree \
         (`attribute_pid`, `CardOccupancy::available_to`) rather than count our own server as \
         somebody else's.",
        used / (1024 * 1024),
        available / (1024 * 1024),
        needed / (1024 * 1024),
    );

    let proof = result.expect("the proof itself must succeed on an otherwise idle card");
    assert!(!proof.seal.is_empty());
}
