//! OpenVM prover backend.

use crate::benchmark::BenchmarkResult;
use crate::engine::{ProofOutput, ProvingEngine};
use anyhow::Result;
use std::time::Instant;

/// Default RSS ceiling for an OpenVM prove (8 GiB, matching the risc0 execute self-guard and the
/// `openvm` ledger charge). Override with `ZKMINER_OPENVM_PROVE_MAX_RSS_BYTES` (0 = unlimited).
fn openvm_prove_max_rss_bytes() -> Option<u64> {
    const DEFAULT: u64 = 8 * 1024 * 1024 * 1024;
    match std::env::var("ZKMINER_OPENVM_PROVE_MAX_RSS_BYTES") {
        Ok(s) => match s.trim().parse::<u64>() {
            Ok(0) => None,
            Ok(n) => Some(n),
            Err(_) => Some(DEFAULT),
        },
        Err(_) => Some(DEFAULT),
    }
}

/// This process's current resident set (VmRSS) in bytes, from `/proc/self/status`. `None`
/// off-Linux or on a read error (→ the self-guard simply does not fire).
#[cfg(target_os = "linux")]
fn self_vmrss_bytes() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            return rest
                .split_whitespace()
                .next()
                .and_then(|v| v.parse::<u64>().ok())
                .map(|kb| kb.saturating_mul(1024));
        }
    }
    None
}

#[cfg(not(target_os = "linux"))]
fn self_vmrss_bytes() -> Option<u64> {
    None
}

/// Run `f` while a background thread watches this process's resident set; if it crosses
/// `limit_bytes`, abort the worker to contain the in-process prove balloon before it OOMs the host
/// (mirrors the risc0 execute self-guard). `limit_bytes == None` → no guard. The guard thread is
/// torn down via `Drop`, so a panic out of `f` cannot leak it.
fn with_rss_self_guard<T>(limit_bytes: Option<u64>, f: impl FnOnce() -> T) -> T {
    let Some(limit) = limit_bytes else {
        return f();
    };
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    let stop = Arc::new(AtomicBool::new(false));
    let handle = {
        let stop = stop.clone();
        std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                if let Some(rss) = self_vmrss_bytes() {
                    if rss > limit {
                        tracing::error!(
                            "openvm prove resident set {} MiB exceeded the {} MiB self-guard — \
                             aborting the worker to contain the in-process balloon before it OOMs \
                             the host (ZKMINER_OPENVM_PROVE_MAX_RSS_BYTES)",
                            rss / (1024 * 1024),
                            limit / (1024 * 1024)
                        );
                        std::process::exit(101);
                    }
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
        })
    };
    struct Guard {
        stop: Arc<AtomicBool>,
        handle: Option<std::thread::JoinHandle<()>>,
    }
    impl Drop for Guard {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Relaxed);
            if let Some(h) = self.handle.take() {
                let _ = h.join();
            }
        }
    }
    let mut guard = Guard {
        stop,
        handle: Some(handle),
    };
    let out = f();
    guard.stop.store(true, Ordering::Relaxed);
    if let Some(h) = guard.handle.take() {
        let _ = h.join();
    }
    out
}

/// OpenVM proving engine.
pub struct OpenVmProver;

impl ProvingEngine for OpenVmProver {
    fn prove(&self, elf: &[u8], input_data: &[u8], _po2: Option<u8>) -> Result<ProofOutput> {
        let start = Instant::now();

        let sdk = openvm_sdk::Sdk::new();
        let elf_data = openvm_sdk::fs::ElfData::from_bytes(elf.to_vec());
        let stdin = openvm_sdk::StdIn::from_bytes(input_data);

        // In-process RSS self-guard: contain a ballooning submitter-controlled guest before it
        // OOMs the host (and any co-hosted warm SP1/risc0 server). OpenVM proves the ELF+input
        // in THIS process, so without a bound a crafted job could exhaust host memory.
        let proof = with_rss_self_guard(openvm_prove_max_rss_bytes(), || sdk.prove(&elf_data, stdin))
            .map_err(|e| anyhow::anyhow!("OpenVM proving failed: {e}"))?;

        let duration = start.elapsed();

        Ok(ProofOutput {
            journal: proof.public_values().to_vec(),
            seal: bincode::serialize(&proof)
                .map_err(|e| anyhow::anyhow!("Failed to serialize proof: {e}"))?,
            duration,
            cycles: proof.cycles(),
        })
    }
}

/// Run a fibonacci benchmark using the real OpenVM prover.
///
/// Note: OpenVM guest compilation is handled externally. The ELF must be
/// pre-compiled and provided. For benchmarks, we compile it on the fly
/// using the SDK.
pub fn benchmark_fibonacci(n: u32) -> BenchmarkResult {
    tracing::info!("OpenVM benchmark: fibonacci({n})");
    let start = Instant::now();

    let sdk = openvm_sdk::Sdk::new();

    // Build the guest program from source
    let guest_dir =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("guests/openvm/fibonacci");

    let elf = sdk
        .build(openvm_sdk::fs::BuildArgs::new(guest_dir))
        .expect("OpenVM guest build failed");

    let stdin = openvm_sdk::StdIn::from_bytes(&n.to_le_bytes());
    let proof = sdk
        .prove(&elf, stdin)
        .expect("OpenVM fibonacci proving failed");

    let duration = start.elapsed();
    let cycles = proof.cycles();
    let throughput = cycles as f64 / duration.as_secs_f64();

    tracing::info!(
        "  openvm fibonacci({n}): {cycles} cycles in {duration:?} ({throughput:.0} c/s)"
    );

    BenchmarkResult {
        program_name: format!("fibonacci({n})"),
        prover_backend: "openvm".to_string(),
        cycles,
        duration,
        throughput,
        weight: 0.0,
        precompile: false,
    }
}
