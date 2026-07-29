//! Regression test for the ROCm/gfx1100 SHA-256 precompile bug.
//!
//! Original symptom: sha256-chain@100_000 produced a proof whose local
//! verification failed ("verification indicates proof is invalid") on AMD
//! gfx1100. The bug appeared only at scale (many 2^20 segments), not at
//! the per-benchmark default of sha256-chain@10_000. This test reproduces
//! at the larger scale and relies on the worker's internal `receipt.verify()`
//! in `run_proof` — any invalid seal would surface as a worker error.
//!
//! Also runs on gfx1201 (RX 9070 XT) so we catch any RDNA4-specific regression.
//!
//! Skipped if the fibonacci sha256-chain ELF or ROCm worker binary aren't
//! present. Pins the CUDA binary out of the discovery path via `zkminer-prove-risc0-cuda.hidden`
//! renaming in the surrounding test-runner pass (this test itself doesn't
//! touch NVIDIA).

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

use zkminer_prover::dispatcher::WorkerPool;

fn find_sha256_chain_elf() -> Option<Vec<u8>> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir.parent()?.parent()?;
    let elf_path = workspace_root.join(
        "target/riscv-guest/zkminer-prove-risc0/sha256-chain/riscv32im-risc0-zkvm-elf/release/sha256-chain.bin",
    );
    if elf_path.exists() {
        std::fs::read(&elf_path).ok()
    } else {
        eprintln!("sha256-chain ELF not found at: {}", elf_path.display());
        None
    }
}

#[test]
fn test_rocm_sha256_chain_at_scale() {
    let elf = match find_sha256_chain_elf() {
        Some(e) if !e.is_empty() => {
            eprintln!("sha256-chain ELF: {} bytes", e.len());
            e
        }
        _ => {
            eprintln!("SKIP: sha256-chain ELF not built");
            return;
        }
    };

    let mut pool = WorkerPool::new(HashMap::new(), vec![], Some(Duration::from_secs(1800)));
    let connected = pool.discover_and_spawn();
    eprintln!("Connected workers: {:?}", connected);

    let rocm_workers: Vec<_> = connected.iter().filter(|k| k.contains("rocm")).collect();
    if rocm_workers.is_empty() {
        eprintln!("SKIP: no ROCm workers discovered");
        pool.shutdown_all();
        return;
    }

    // 100_000 iterations — the scale at which the gfx1100 bug originally
    // manifested. ~460M cycles, ~440 × 2^20 segments.
    let input = 100_000u32.to_le_bytes();

    // Collect all results instead of bailing on first failure — we want to
    // know the status of every AMD GPU independently.
    let mut failures = Vec::new();
    for key in &rocm_workers {
        eprintln!("\n============================================================");
        eprintln!("Testing: {}", key);
        eprintln!("============================================================");
        let start = std::time::Instant::now();

        match pool.prove(
            key,
            &elf,
            &input,
            None,
            Some(Duration::from_secs(1800)),
            None,
        ) {
            Ok(proof) => {
                let elapsed = start.elapsed();
                eprintln!(
                    "PASS: {} cycles, {}-byte seal, {:.1}s",
                    proof.cycles,
                    proof.seal.len(),
                    elapsed.as_secs_f64(),
                );
                assert!(!proof.seal.is_empty(), "seal must be non-empty");
                assert!(proof.seal.len() <= 512, "Groth16 seal should be ~256 bytes");
                assert!(
                    proof.cycles > 100_000_000,
                    "sha256-chain@100K must exceed 100M cycles, got {}",
                    proof.cycles
                );
            }
            Err(e) => {
                eprintln!("FAIL: {key}: {e:#}");
                failures.push(format!("{key}: {e:#}"));
            }
        }
    }
    pool.shutdown_all();
    if !failures.is_empty() {
        panic!(
            "{} of {} ROCm GPUs failed sha256-chain@100K:\n  {}",
            failures.len(),
            rocm_workers.len(),
            failures.join("\n  "),
        );
    }
}
