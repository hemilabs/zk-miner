//! Our own VRAM must be credited to us, not counted as another process's.
//!
//! The foreign-VRAM gate refuses an SP1 proof on a card that something else is using. The hazard it
//! introduces is the mirror image: counting OUR OWN device memory as foreign and refusing a card that
//! is perfectly healthy. That cannot be caught in a unit test, because it depends on what the real
//! `sp1-gpu-server` does with the real driver.
//!
//! Measured on this box on 2026-10-05, sampling the 5080 every 3s through a `fibonacci` proof:
//! `sp1-gpu-server` holds 15,076 MiB of the card's 16,303 for the duration and releases it within
//! ~3s of finishing. So the interesting moment is DURING a proof, not after one — this test samples
//! the gate's own evidence from another thread while a proof runs, and requires that the card reads
//! as almost entirely in use while essentially none of it is attributed to a foreign process.
//!
//! The same shape of bug has already been made twice in this codebase's memory accounting: the
//! host-memory ledger credited resident workers with MIN instead of MAX and made SP1 unclaimable
//! after one proof.
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
    let peak_foreign = Arc::new(AtomicU64::new(0));
    let sampler = {
        let (pool, stop, peak_used, peak_foreign) = (
            pool.clone(),
            stop.clone(),
            peak_used.clone(),
            peak_foreign.clone(),
        );
        let key = key.clone();
        std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                if let Some((foreign, used, _total)) = pool.foreign_vram_for_slot(&key) {
                    peak_used.fetch_max(used, Ordering::Relaxed);
                    peak_foreign.fetch_max(foreign, Ordering::Relaxed);
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

    let (used, foreign) = (
        peak_used.load(Ordering::Relaxed),
        peak_foreign.load(Ordering::Relaxed),
    );
    let total = pool
        .foreign_vram_for_slot(&key)
        .map(|(_, _, t)| t)
        .unwrap_or(0);
    const MIB: f64 = 1024.0 * 1024.0;
    eprintln!(
        "{key}: peak VRAM in use {:.0} MiB, of which {:.0} MiB was counted as FOREIGN; the card is \
         {:.0} MiB and sp1 needs {:.0} MiB free",
        used as f64 / MIB,
        foreign as f64 / MIB,
        total as f64 / MIB,
        needed as f64 / MIB,
    );

    if let Err(e) = &result {
        let own_vram = e
            .downcast_ref::<zkminer_prover_protocol::types::GpuMemoryShortage>()
            .is_some();
        assert!(
            !own_vram,
            "{key} refused its own proof for foreign VRAM, with nothing else on the card: {e:#}"
        );
    }

    // Non-vacuity first. If the card never filled up, nothing was credited and the assertion below
    // would pass for the wrong reason — which is exactly how the first version of this test passed:
    // it read the card AFTER the proof, by which point the server had already released everything.
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
    // The substantive assertion: with ~15 GiB of this card held by our OWN server, the amount we
    // consider available must still clear the floor. If the credit regressed, `available` would
    // collapse to near zero and every proof after the first on this slot would be refused on a card
    // that is perfectly healthy.
    let available = total.saturating_sub(foreign);
    assert!(
        available >= needed,
        "while our own sp1-gpu-server held {} MiB of this card, only {} MiB was considered \
         available against a {} MiB floor. The gate must credit our process tree \
         (`pid_is_in_our_tree`) rather than count our own server as somebody else's.",
        used / (1024 * 1024),
        available / (1024 * 1024),
        needed / (1024 * 1024),
    );

    let proof = result.expect("the proof itself must succeed on an otherwise idle card");
    assert!(!proof.seal.is_empty());
}
