//! Bisect the ROCm SHA-256 scale threshold.
//!
//! Reads the iteration count N from ZKMINER_BISECT_N env var, runs
//! sha256-chain@N on the ROCm worker, reports PASS/FAIL with a clear
//! banner. Ignored by default — run explicitly via:
//!
//!   ZKMINER_BISECT_N=50000 cargo test --release -p zkminer-prover \
//!       --test sha_bisect -- --ignored --nocapture

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
#[ignore]
fn rocm_sha256_bisect() {
    let n: u32 = std::env::var("ZKMINER_BISECT_N")
        .ok()
        .and_then(|v| v.parse().ok())
        .expect("set ZKMINER_BISECT_N");

    let elf = find_sha256_chain_elf().expect("sha256-chain ELF must be built");
    eprintln!("=== BISECT N={} ELF={}B ===", n, elf.len());

    let mut pool = WorkerPool::new(HashMap::new(), vec![], Some(Duration::from_secs(1800)));
    let connected = pool.discover_and_spawn();
    eprintln!("Connected workers: {:?}", connected);

    let rocm_key = connected
        .iter()
        .find(|k| k.contains("rocm"))
        .cloned()
        .expect("no ROCm worker discovered");

    let input = n.to_le_bytes();
    let start = std::time::Instant::now();
    let res = pool.prove(
        &rocm_key,
        &elf,
        &input,
        None,
        Some(Duration::from_secs(1800)),
        None,
    );
    let elapsed = start.elapsed();
    match res {
        Ok(p) => {
            eprintln!(
                "BISECT_RESULT N={} PASS cycles={} seal={}B elapsed={:.1}s",
                n,
                p.cycles,
                p.seal.len(),
                elapsed.as_secs_f64()
            );
        }
        Err(e) => {
            eprintln!(
                "BISECT_RESULT N={} FAIL elapsed={:.1}s err={:#}",
                n,
                elapsed.as_secs_f64(),
                e
            );
            pool.shutdown_all();
            panic!("N={} failed", n);
        }
    }
    pool.shutdown_all();
}
