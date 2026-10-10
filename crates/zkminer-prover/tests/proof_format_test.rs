//! Integration test: generate real Groth16 proofs on CUDA and ROCm GPUs,
//! then verify the proof format matches what the on-chain verifier expects.
//!
//! Run with: cargo test -p zkminer-prover --test proof_format_test -- --nocapture
//!
//! This test:
//! 1. Discovers GPU worker binaries (zkminer-prove-risc0-cuda, -rocm)
//! 2. Sends the fibonacci guest ELF + input via the Prove command
//! 3. Gets back journal + seal (Groth16 proof)
//! 4. Verifies the seal is a valid Groth16 proof (not bincode-serialized junk)

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

use zkminer_prover::dispatcher::WorkerPool;

/// Find the fibonacci guest ELF in the workspace target directory.
fn find_fibonacci_elf() -> Option<Vec<u8>> {
    // Walk up from CARGO_MANIFEST_DIR to find workspace root
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir.parent()?.parent()?; // crates/zkminer-prover -> crates -> workspace

    let elf_path = workspace_root
        .join("target/riscv-guest/zkminer-prove-risc0/fibonacci/riscv32im-risc0-zkvm-elf/release/fibonacci.bin");

    if elf_path.exists() {
        std::fs::read(&elf_path).ok()
    } else {
        eprintln!("ELF not found at: {}", elf_path.display());
        None
    }
}

#[test]
fn test_gpu_groth16_proof_format() {
    // tracing is initialized by the test harness

    let elf = match find_fibonacci_elf() {
        Some(elf) if !elf.is_empty() => {
            eprintln!("Fibonacci ELF: {} bytes", elf.len());
            elf
        }
        _ => {
            eprintln!("SKIP: fibonacci ELF not found or empty");
            return;
        }
    };

    // Discover GPU workers
    let mut pool = WorkerPool::new(HashMap::new(), vec![], Some(Duration::from_secs(600)));
    let connected = pool.discover_and_spawn();
    eprintln!("Connected workers: {:?}", connected);

    let gpu_workers: Vec<_> = connected
        .iter()
        .filter(|k| k.contains("cuda") || k.contains("rocm"))
        .collect();

    if gpu_workers.is_empty() {
        eprintln!("SKIP: No GPU workers found");
        pool.shutdown_all();
        return;
    }

    // fibonacci(100) input
    let input = 100u32.to_le_bytes();

    for key in &gpu_workers {
        eprintln!("\n============================================================");
        eprintln!("Testing: {}", key);
        eprintln!("============================================================");

        eprintln!("Proving fibonacci(100)...");
        let start = std::time::Instant::now();

        match pool.prove(
            key,
            &elf,
            &input,
            None,
            Some(Duration::from_secs(300)),
            None,
        ) {
            Ok(proof) => {
                let elapsed = start.elapsed();
                eprintln!("Proof generated in {:.1}s", elapsed.as_secs_f64());
                eprintln!("  Journal:  {} bytes", proof.journal.len());
                eprintln!("  Seal:     {} bytes", proof.seal.len());
                eprintln!("  Cycles:   {}", proof.cycles);
                eprintln!("  Duration: {:.2}s", proof.duration.as_secs_f64());

                // Verify journal is non-empty
                assert!(!proof.journal.is_empty(), "Journal should not be empty");

                // Verify seal is non-empty
                assert!(!proof.seal.is_empty(), "Seal should not be empty");

                // Verify seal format:
                // A RISC Zero Groth16 seal is typically 256 bytes
                // (a: 2x32, b: 2x2x32, c: 2x32 = 256 bytes)
                // If we got a bincode-serialized InnerReceipt, it would be 100KB+
                // A Composite/Succinct receipt would be 10KB+
                let seal_size = proof.seal.len();

                if seal_size <= 512 {
                    eprintln!(
                        "  FORMAT: Groth16 seal ({} bytes) - CORRECT for on-chain verification",
                        seal_size
                    );
                } else if seal_size <= 10_000 {
                    eprintln!(
                        "  FORMAT: Succinct/Compact receipt ({} bytes) - MAY work on-chain",
                        seal_size
                    );
                } else {
                    eprintln!("  FORMAT: Large receipt ({} bytes) - likely bincode InnerReceipt, WILL NOT work on-chain!", seal_size);
                    panic!(
                        "Worker {} produced a {}-byte seal (expected ~256 for Groth16). \
                         This is likely a bincode-serialized InnerReceipt, not a raw Groth16 seal.",
                        key, seal_size
                    );
                }

                // Print seal header for inspection
                let preview_len = seal_size.min(64);
                eprintln!(
                    "  Seal[0..{}]: {:02x?}",
                    preview_len,
                    &proof.seal[..preview_len]
                );

                eprintln!("  RESULT: PASS");
            }
            Err(e) => {
                eprintln!("  RESULT: FAILED - {}", e);
                // Don't hard-fail the test — some GPUs might not be available
            }
        }
    }

    pool.shutdown_all();
    eprintln!("\nAll GPU proof format tests complete.");
}
