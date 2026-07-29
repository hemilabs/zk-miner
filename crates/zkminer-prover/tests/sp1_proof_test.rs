//! Test SP1 Groth16 proof generation via the worker subprocess.
//!
//! Run with: cargo test -p zkminer-prover --test sp1_proof_test -- --nocapture

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

use zkminer_prover::dispatcher::WorkerPool;

fn find_sp1_fibonacci_elf() -> Option<Vec<u8>> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let elf_path = manifest_dir
        .join("../zkminer-prover/guests/sp1/fibonacci/target/elf-compilation/riscv64im-succinct-zkvm-elf/release/fibonacci-sp1-guest");
    if elf_path.exists() {
        std::fs::read(&elf_path).ok()
    } else {
        eprintln!("SP1 fibonacci ELF not found at: {}", elf_path.display());
        None
    }
}

#[test]
fn test_sp1_groth16_proof() {
    let elf = match find_sp1_fibonacci_elf() {
        Some(elf) if !elf.is_empty() => {
            eprintln!("SP1 fibonacci ELF: {} bytes", elf.len());
            elf
        }
        _ => {
            eprintln!("SKIP: SP1 fibonacci ELF not found");
            return;
        }
    };

    let mut pool = WorkerPool::new(HashMap::new(), vec![], Some(Duration::from_secs(600)));
    let connected = pool.discover_and_spawn();
    eprintln!("Connected workers: {:?}", connected);

    let sp1_key = connected.iter().find(|k| k.starts_with("sp1:"));
    let Some(sp1_key) = sp1_key else {
        eprintln!("SKIP: No SP1 worker found");
        pool.shutdown_all();
        return;
    };

    eprintln!("Testing SP1 worker: {}", sp1_key);
    eprintln!("Proving fibonacci(100) with Groth16...");

    let input = 100u32.to_le_bytes();
    let start = std::time::Instant::now();

    match pool.prove(
        sp1_key,
        &elf,
        &input,
        None,
        Some(Duration::from_secs(600)),
        None,
    ) {
        Ok(proof) => {
            let elapsed = start.elapsed();
            eprintln!("SP1 Proof generated in {:.1}s", elapsed.as_secs_f64());
            eprintln!("  Journal:  {} bytes", proof.journal.len());
            eprintln!("  Seal:     {} bytes", proof.seal.len());
            eprintln!("  Cycles:   {}", proof.cycles);

            assert!(!proof.journal.is_empty(), "Journal should not be empty");
            assert!(!proof.seal.is_empty(), "Seal should not be empty");

            // SP1 Groth16 on-chain proof format:
            // 4 bytes vkey_hash prefix + encoded Groth16 proof
            // Total is typically ~260-300 bytes
            let seal_size = proof.seal.len();
            eprintln!("  Seal[0..4]: {:02x?}", &proof.seal[..proof.seal.len().min(4)]);

            if seal_size < 500 {
                eprintln!("  FORMAT: Compact Groth16 ({} bytes) - CORRECT for on-chain", seal_size);
            } else {
                eprintln!("  FORMAT: Large ({} bytes) - may be bincode, NOT on-chain compatible!", seal_size);
                panic!("SP1 seal too large: {} bytes", seal_size);
            }

            eprintln!("  RESULT: PASS");
        }
        Err(e) => {
            eprintln!("  RESULT: FAILED - {}", e);
            panic!("SP1 proof generation failed: {}", e);
        }
    }

    pool.shutdown_all();
}
