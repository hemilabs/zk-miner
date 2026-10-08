//! Comprehensive zkVM stability and troubleshooting test suite.
//!
//! IMPORTANT: Use `--test-threads=1` to avoid GPU contention:
//!   cargo test -p zkminer-prover --test comprehensive_zkvm_test --release \
//!     -- --nocapture --test-threads=1
//!
//! Fail-closed by default: a missing worker/ELF (or a 0-byte ELF) FAILS the test.
//! Set ZKVM_ALLOW_SKIP=1 to skip (instead of fail) when a worker/ELF is absent
//! (for local dev without GPUs).
//!
//! Selective: cargo test ... -- rv32im_torture / precompile_interleave /
//!           memory_stress / edge_case_arith / segment_boundary / babybear / minimal

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use zkminer_prover::dispatcher::WorkerPool;
use zkminer_prover::engine::ProofOutput;

// ===================================================================
// ELF discovery + pool helpers
// ===================================================================

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
        eprintln!("ELF not found: {}", p.display());
        None
    }
}

fn find_sp1_elf(guest: &str) -> Option<Vec<u8>> {
    let p = workspace_root().join(format!(
        "crates/zkminer-prover/guests/sp1/{guest}/target/elf-compilation/\
         riscv64im-succinct-zkvm-elf/release/{guest}-sp1-guest"
    ));
    if p.exists() {
        std::fs::read(&p).ok()
    } else {
        eprintln!("SP1 ELF not found: {}", p.display());
        None
    }
}

fn create_pool() -> WorkerPool {
    WorkerPool::new(HashMap::new(), vec![], Some(Duration::from_secs(1800)))
}

fn make_input(vals: &[u32]) -> Vec<u8> {
    vals.iter().flat_map(|v| v.to_le_bytes()).collect()
}

/// Whether a missing ELF/worker must FAIL the test (fail-closed) rather than skip.
///
/// Defaults to TRUE so a plain `cargo test` (or a broken/empty guest build) can never
/// pass while verifying nothing. Skipping is opt-in for local dev without GPUs via
/// ZKVM_ALLOW_SKIP=1|true|yes.
fn require_workers() -> bool {
    let allow_skip = std::env::var("ZKVM_ALLOW_SKIP")
        .map(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
        .unwrap_or(false);
    !allow_skip
}

// ===================================================================
// Expected-value helpers (mirrors guest logic without black_box)
// ===================================================================

fn mix(acc: u64, val: u32) -> u64 {
    acc.wrapping_mul(6364136223846793005)
        .wrapping_add(val as u64)
}

fn riscv_div(a: u32, b: u32) -> u32 {
    let (a, b) = (a as i32, b as i32);
    if b == 0 {
        0xFFFFFFFF
    } else if a == i32::MIN && b == -1 {
        a as u32
    } else {
        (a / b) as u32
    }
}
fn riscv_divu(a: u32, b: u32) -> u32 {
    if b == 0 {
        0xFFFFFFFF
    } else {
        a / b
    }
}
fn riscv_rem(a: u32, b: u32) -> u32 {
    let (a, b) = (a as i32, b as i32);
    if b == 0 {
        a as u32
    } else if a == i32::MIN && b == -1 {
        0
    } else {
        (a % b) as u32
    }
}
fn riscv_remu(a: u32, b: u32) -> u32 {
    if b == 0 {
        a
    } else {
        a % b
    }
}
fn mulh(a: u32, b: u32) -> u32 {
    ((a as i32 as i64).wrapping_mul(b as i32 as i64) >> 32) as u32
}
fn mulhsu(a: u32, b: u32) -> u32 {
    ((a as i32 as i64).wrapping_mul(b as u64 as i64) >> 32) as u32
}
fn mulhu(a: u32, b: u32) -> u32 {
    ((a as u64).wrapping_mul(b as u64) >> 32) as u32
}
fn recursive_sum(n: u32) -> u32 {
    if n == 0 {
        0
    } else {
        n.wrapping_add(recursive_sum(n - 1))
    }
}

fn lcg(state: &mut u32) -> u32 {
    *state = state.wrapping_mul(1664525).wrapping_add(1013904223);
    *state
}

// ===================================================================
// Expected-value: rv32im-torture (RISC0)
// ===================================================================

fn expected_rv32im_torture_risc0(seed: u32, iterations: u32) -> Vec<u8> {
    let mut acc: u64 = seed as u64;
    let pairs: Vec<(u32, u32)> = vec![
        (0, 0),
        (1, 0),
        (0, 1),
        (1, 1),
        (0xFFFFFFFF, 1),
        (1, 0xFFFFFFFF),
        (0x80000000, 0x7FFFFFFF),
        (0x7FFFFFFF, 0x80000000),
        (0x80000000, 0x80000000),
        (0x80000000, 0xFFFFFFFF),
        (0xFFFFFFFF, 0x80000000),
        (0xFFFFFFFF, 0xFFFFFFFF),
        (0xDEADBEEF, 0xCAFEBABE),
        (seed, seed.wrapping_add(1)),
        (seed.wrapping_mul(7), seed.wrapping_mul(13)),
    ];
    for _ in 0..iterations {
        for &(a, b) in &pairs {
            acc = mix(acc, a.wrapping_add(b));
            acc = mix(acc, a.wrapping_sub(b));
            acc = mix(acc, a & b);
            acc = mix(acc, a | b);
            acc = mix(acc, a ^ b);
            acc = mix(acc, a.wrapping_shl(b & 31));
            acc = mix(acc, a.wrapping_shr(b & 31));
            acc = mix(acc, ((a as i32).wrapping_shr(b & 31)) as u32);
            acc = mix(acc, if (a as i32) < (b as i32) { 1 } else { 0 });
            acc = mix(acc, if a < b { 1 } else { 0 });
        }
        for &a in &[0u32, 1, 0x80000000, 0x7FFFFFFF, 0xFFFFFFFF, seed] {
            for &imm in &[0u32, 1, 0x7FF, 0xFFF, 0x800] {
                acc = mix(acc, a.wrapping_add(imm));
                acc = mix(acc, a & imm);
                acc = mix(acc, a | imm);
                acc = mix(acc, a ^ imm);
                let simm = ((imm as i32) << 20) >> 20;
                acc = mix(acc, if (a as i32) < simm { 1 } else { 0 });
                acc = mix(acc, if a < (simm as u32) { 1 } else { 0 });
            }
            for &sh in &[0u32, 1, 7, 15, 16, 31] {
                acc = mix(acc, a.wrapping_shl(sh));
                acc = mix(acc, a.wrapping_shr(sh));
                acc = mix(acc, ((a as i32).wrapping_shr(sh)) as u32);
            }
        }
        for &(a, b) in &pairs {
            acc = mix(acc, a.wrapping_mul(b));
            acc = mix(acc, mulh(a, b));
            acc = mix(acc, mulhsu(a, b));
            acc = mix(acc, mulhu(a, b));
            acc = mix(acc, riscv_div(a, b));
            acc = mix(acc, riscv_divu(a, b));
            acc = mix(acc, riscv_rem(a, b));
            acc = mix(acc, riscv_remu(a, b));
        }
        let mut buf = [0u8; 256];
        for i in 0..256u32 {
            buf[i as usize] = (acc.wrapping_add(i as u64) & 0xFF) as u8;
        }
        for i in 0..256 {
            acc = mix(acc, buf[i] as i8 as i32 as u32);
            acc = mix(acc, buf[i] as u32);
        }
        for i in (0..256).step_by(2) {
            let v = u16::from_le_bytes([buf[i], buf[i + 1]]);
            acc = mix(acc, v as i16 as i32 as u32);
            acc = mix(acc, v as u32);
        }
        for i in (0..256).step_by(4) {
            acc = mix(
                acc,
                u32::from_le_bytes([buf[i], buf[i + 1], buf[i + 2], buf[i + 3]]),
            );
        }
        let ab: [u32; 4] = [0xDEADBEEF, 0xCAFEBABE, 0x12345678, 0x9ABCDEF0];
        let bytes: Vec<u8> = ab.iter().flat_map(|w| w.to_le_bytes()).collect();
        for off in 1..4usize {
            acc = mix(
                acc,
                u32::from_le_bytes([bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]]),
            );
        }
        let a = 0xDEADBEEFu32;
        acc = mix(acc, a.wrapping_shl(37));
        acc = mix(acc, a.wrapping_shr(37));
        acc = mix(acc, ((a as i32).wrapping_shr(37)) as u32);
        acc = mix(acc, a.wrapping_shl(32));
        acc = mix(acc, a.wrapping_shl(0));
        let bp: &[(u32, u32)] = &[
            (0, 0),
            (1, 1),
            (0, 1),
            (1, 0),
            (0x7FFFFFFF, 0x80000000),
            (0x80000000, 0x7FFFFFFF),
            (0xFFFFFFFF, 0),
            (0, 0xFFFFFFFF),
            (seed, seed),
            (seed, seed.wrapping_add(1)),
        ];
        for &(a, b) in bp {
            if a == b {
                acc = mix(acc, 1);
            } else {
                acc = mix(acc, 0);
            }
            if a != b {
                acc = mix(acc, 1);
            } else {
                acc = mix(acc, 0);
            }
            if (a as i32) < (b as i32) {
                acc = mix(acc, 1);
            } else {
                acc = mix(acc, 0);
            }
            if (a as i32) >= (b as i32) {
                acc = mix(acc, 1);
            } else {
                acc = mix(acc, 0);
            }
            if a < b {
                acc = mix(acc, 1);
            } else {
                acc = mix(acc, 0);
            }
            if a >= b {
                acc = mix(acc, 1);
            } else {
                acc = mix(acc, 0);
            }
        }
        let mut cd = 50u32;
        while cd > 0 {
            acc = mix(acc, cd);
            cd -= 1;
        }
        acc = mix(acc, 0xDEAD_B000u32.wrapping_add(0xEEF));
        let ops: &[fn(u32, u32) -> u32] = &[
            |a, b| a.wrapping_add(b),
            |a, b| a.wrapping_sub(b),
            |a, b| a.wrapping_mul(b),
            |a, b| a ^ b,
        ];
        for (i, op) in ops.iter().enumerate() {
            acc = mix(acc, op(seed, i as u32));
        }
        acc = mix(acc, recursive_sum(20));
    }
    acc.to_le_bytes().to_vec()
}

// ===================================================================
// Expected-value: rv32im-torture (SP1) — includes rv64im + W-suffix
// ===================================================================

fn expected_rv32im_torture_sp1(seed: u32, iterations: u32) -> Vec<u8> {
    // rv32im section is identical to RISC0
    let mut acc: u64 = seed as u64;
    let pairs: Vec<(u32, u32)> = vec![
        (0, 0),
        (1, 0),
        (0, 1),
        (1, 1),
        (0xFFFFFFFF, 1),
        (1, 0xFFFFFFFF),
        (0x80000000, 0x7FFFFFFF),
        (0x7FFFFFFF, 0x80000000),
        (0x80000000, 0x80000000),
        (0x80000000, 0xFFFFFFFF),
        (0xFFFFFFFF, 0x80000000),
        (0xFFFFFFFF, 0xFFFFFFFF),
        (0xDEADBEEF, 0xCAFEBABE),
        (seed, seed.wrapping_add(1)),
        (seed.wrapping_mul(7), seed.wrapping_mul(13)),
    ];
    for _ in 0..iterations {
        for &(a, b) in &pairs {
            acc = mix(acc, a.wrapping_add(b));
            acc = mix(acc, a.wrapping_sub(b));
            acc = mix(acc, a & b);
            acc = mix(acc, a | b);
            acc = mix(acc, a ^ b);
            acc = mix(acc, a.wrapping_shl(b & 31));
            acc = mix(acc, a.wrapping_shr(b & 31));
            acc = mix(acc, ((a as i32).wrapping_shr(b & 31)) as u32);
            acc = mix(acc, if (a as i32) < (b as i32) { 1 } else { 0 });
            acc = mix(acc, if a < b { 1 } else { 0 });
        }
        for &a in &[0u32, 1, 0x80000000, 0x7FFFFFFF, 0xFFFFFFFF, seed] {
            for &imm in &[0u32, 1, 0x7FF, 0xFFF, 0x800] {
                acc = mix(acc, a.wrapping_add(imm));
                acc = mix(acc, a & imm);
                acc = mix(acc, a | imm);
                acc = mix(acc, a ^ imm);
                let simm = ((imm as i32) << 20) >> 20;
                acc = mix(acc, if (a as i32) < simm { 1 } else { 0 });
                acc = mix(acc, if a < (simm as u32) { 1 } else { 0 });
            }
            for &sh in &[0u32, 1, 7, 15, 16, 31] {
                acc = mix(acc, a.wrapping_shl(sh));
                acc = mix(acc, a.wrapping_shr(sh));
                acc = mix(acc, ((a as i32).wrapping_shr(sh)) as u32);
            }
        }
        for &(a, b) in &pairs {
            acc = mix(acc, a.wrapping_mul(b));
            acc = mix(acc, mulh(a, b));
            acc = mix(acc, mulhsu(a, b));
            acc = mix(acc, mulhu(a, b));
            acc = mix(acc, riscv_div(a, b));
            acc = mix(acc, riscv_divu(a, b));
            acc = mix(acc, riscv_rem(a, b));
            acc = mix(acc, riscv_remu(a, b));
        }
        let mut buf = [0u8; 256];
        for i in 0..256u32 {
            buf[i as usize] = (acc.wrapping_add(i as u64) & 0xFF) as u8;
        }
        for i in 0..256 {
            acc = mix(acc, buf[i] as i8 as i32 as u32);
            acc = mix(acc, buf[i] as u32);
        }
        for i in (0..256).step_by(2) {
            let v = u16::from_le_bytes([buf[i], buf[i + 1]]);
            acc = mix(acc, v as i16 as i32 as u32);
            acc = mix(acc, v as u32);
        }
        for i in (0..256).step_by(4) {
            acc = mix(
                acc,
                u32::from_le_bytes([buf[i], buf[i + 1], buf[i + 2], buf[i + 3]]),
            );
        }
        let ab: [u32; 4] = [0xDEADBEEF, 0xCAFEBABE, 0x12345678, 0x9ABCDEF0];
        let bytes: Vec<u8> = ab.iter().flat_map(|w| w.to_le_bytes()).collect();
        for off in 1..4usize {
            acc = mix(
                acc,
                u32::from_le_bytes([bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]]),
            );
        }
        let a = 0xDEADBEEFu32;
        acc = mix(acc, a.wrapping_shl(37));
        acc = mix(acc, a.wrapping_shr(37));
        acc = mix(acc, ((a as i32).wrapping_shr(37)) as u32);
        acc = mix(acc, a.wrapping_shl(32));
        acc = mix(acc, a.wrapping_shl(0));
        let bp: &[(u32, u32)] = &[
            (0, 0),
            (1, 1),
            (0, 1),
            (1, 0),
            (0x7FFFFFFF, 0x80000000),
            (0x80000000, 0x7FFFFFFF),
            (0xFFFFFFFF, 0),
            (0, 0xFFFFFFFF),
            (seed, seed),
            (seed, seed.wrapping_add(1)),
        ];
        for &(a, b) in bp {
            if a == b {
                acc = mix(acc, 1);
            } else {
                acc = mix(acc, 0);
            }
            if a != b {
                acc = mix(acc, 1);
            } else {
                acc = mix(acc, 0);
            }
            if (a as i32) < (b as i32) {
                acc = mix(acc, 1);
            } else {
                acc = mix(acc, 0);
            }
            if (a as i32) >= (b as i32) {
                acc = mix(acc, 1);
            } else {
                acc = mix(acc, 0);
            }
            if a < b {
                acc = mix(acc, 1);
            } else {
                acc = mix(acc, 0);
            }
            if a >= b {
                acc = mix(acc, 1);
            } else {
                acc = mix(acc, 0);
            }
        }
        let mut cd = 50u32;
        while cd > 0 {
            acc = mix(acc, cd);
            cd -= 1;
        }
        acc = mix(acc, 0xDEAD_B000u32.wrapping_add(0xEEF));
        let ops: &[fn(u32, u32) -> u32] = &[
            |a, b| a.wrapping_add(b),
            |a, b| a.wrapping_sub(b),
            |a, b| a.wrapping_mul(b),
            |a, b| a ^ b,
        ];
        for (i, op) in ops.iter().enumerate() {
            acc = mix(acc, op(seed, i as u32));
        }
        acc = mix(acc, recursive_sum(20));
    }

    // === rv64im-specific section (runs once after the loop) ===
    let mut acc64: u64 = seed as u64;
    let pairs64: &[(u64, u64)] = &[
        (0, 0),
        (u64::MAX, 1),
        (i64::MIN as u64, i64::MAX as u64),
        (0xFFFFFFFF_00000000, 0x00000001_FFFFFFFF),
        (1, u64::MAX),
        (0x80000000_00000000, 0x80000000_00000000),
        (seed as u64, (seed as u64).wrapping_mul(0x100000001)),
    ];
    for &(a, b) in pairs64 {
        acc64 = acc64.wrapping_add(a.wrapping_add(b));
        acc64 = acc64.wrapping_add(a.wrapping_sub(b));
        acc64 = acc64.wrapping_add(a.wrapping_mul(b));
        acc64 = acc64.wrapping_add(a & b);
        acc64 = acc64.wrapping_add(a | b);
        acc64 = acc64.wrapping_add(a ^ b);
        acc64 = acc64.wrapping_add(a.wrapping_shl((b & 63) as u32));
        acc64 = acc64.wrapping_add(a.wrapping_shr((b & 63) as u32));
        acc64 = acc64.wrapping_add(((a as i64).wrapping_shr((b & 63) as u32)) as u64);
        let div_r = if b == 0 { u64::MAX } else { a / b };
        let rem_r = if b == 0 { a } else { a % b };
        acc64 = acc64.wrapping_add(div_r);
        acc64 = acc64.wrapping_add(rem_r);
        // Signed 64-bit div/rem
        let sdiv_r = if b == 0 {
            u64::MAX
        } else if a as i64 == i64::MIN && b as i64 == -1 {
            a
        } else {
            ((a as i64) / (b as i64)) as u64
        };
        let srem_r = if b == 0 {
            a
        } else if a as i64 == i64::MIN && b as i64 == -1 {
            0
        } else {
            ((a as i64) % (b as i64)) as u64
        };
        acc64 = acc64.wrapping_add(sdiv_r);
        acc64 = acc64.wrapping_add(srem_r);
        acc64 = acc64.wrapping_add(if (a as i64) < (b as i64) { 1 } else { 0 });
        acc64 = acc64.wrapping_add(if a < b { 1 } else { 0 });
    }

    // W-suffix instructions
    let pairs32: &[(u32, u32)] = &[
        (0, 0),
        (1, 0),
        (0, 1),
        (1, 1),
        (0xFFFFFFFF, 1),
        (1, 0xFFFFFFFF),
        (0x80000000, 0x7FFFFFFF),
        (0x7FFFFFFF, 0x80000000),
        (0x80000000, 0xFFFFFFFF),
        (0xFFFFFFFF, 0xFFFFFFFF),
        (seed, seed.wrapping_add(1)),
    ];
    for &(a, b) in pairs32 {
        acc64 = acc64.wrapping_add(((a.wrapping_add(b)) as i32) as i64 as u64);
        acc64 = acc64.wrapping_add(((a.wrapping_sub(b)) as i32) as i64 as u64);
        acc64 = acc64.wrapping_add(((a.wrapping_shl(b & 31)) as i32) as i64 as u64);
        acc64 = acc64.wrapping_add(((a.wrapping_shr(b & 31)) as i32) as i64 as u64);
        acc64 = acc64.wrapping_add((((a as i32).wrapping_shr(b & 31)) as i64) as u64);
    }
    // W-suffix immediates: ADDIW, SLLIW, SRLIW, SRAIW
    for &a in &[0u32, 1, 0x80000000, 0x7FFFFFFF, 0xFFFFFFFF, seed] {
        for &imm in &[0u32, 1, 0x7FF, 0xFFF, 0x800] {
            acc64 = acc64.wrapping_add(((a.wrapping_add(imm)) as i32) as i64 as u64);
        }
        for &sh in &[0u32, 1, 7, 15, 16, 31] {
            acc64 = acc64.wrapping_add(((a.wrapping_shl(sh)) as i32) as i64 as u64);
            acc64 = acc64.wrapping_add(((a.wrapping_shr(sh)) as i32) as i64 as u64);
            acc64 = acc64.wrapping_add((((a as i32).wrapping_shr(sh)) as i64) as u64);
        }
    }
    // RV64M W-suffix: MULW, DIVW, DIVUW, REMW, REMUW
    for &(a, b) in pairs32 {
        acc64 = acc64.wrapping_add(((a.wrapping_mul(b)) as i32) as i64 as u64);
        let divw = if b == 0 {
            u64::MAX
        } else if a as i32 == i32::MIN && b as i32 == -1 {
            (a as i32 as i64) as u64
        } else {
            (((a as i32) / (b as i32)) as i64) as u64
        };
        acc64 = acc64.wrapping_add(divw);
        let divuw = if b == 0 {
            u64::MAX
        } else {
            ((a / b) as i32 as i64) as u64
        };
        acc64 = acc64.wrapping_add(divuw);
        let remw = if b == 0 {
            (a as i32 as i64) as u64
        } else if a as i32 == i32::MIN && b as i32 == -1 {
            0u64
        } else {
            (((a as i32) % (b as i32)) as i64) as u64
        };
        acc64 = acc64.wrapping_add(remw);
        let remuw = if b == 0 {
            (a as i32 as i64) as u64
        } else {
            ((a % b) as i32 as i64) as u64
        };
        acc64 = acc64.wrapping_add(remuw);
    }
    // LD/SD test
    for i in 0..8usize {
        acc64 = acc64.wrapping_add(
            (seed as u64)
                .wrapping_mul(i as u64 + 1)
                .wrapping_add(0xCAFE),
        );
    }

    acc = mix(acc, (acc64 & 0xFFFFFFFF) as u32);
    acc = mix(acc, (acc64 >> 32) as u32);
    acc.to_le_bytes().to_vec()
}

// ===================================================================
// Expected-value: edge-case-arith (updated with DIVU/REMU/MULH/MULHSU/MULHU)
// ===================================================================

fn expected_edge_case_arith(n: u32) -> Vec<u8> {
    let mut acc: u64 = 0xCAFE_BABE_DEAD_BEEFu64;
    for i in 0..n {
        let vals: [u32; 6] = [
            0,
            1,
            0x7FFFFFFF,
            0x80000000,
            0xFFFFFFFF,
            i.wrapping_mul(2654435761),
        ];
        for &a in &vals {
            for &b in &vals {
                let (sum, diff, prod) = (a.wrapping_add(b), a.wrapping_sub(b), a.wrapping_mul(b));
                acc = acc
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(sum as u64)
                    .wrapping_add(diff as u64)
                    .wrapping_add(prod as u64);
                acc = acc.wrapping_add(if (a as i32) < (b as i32) { 1 } else { 0 } as u64);
                acc = acc.wrapping_add(if a < b { 1 } else { 0 } as u64);
                let div_r = if b == 0 {
                    0xFFFFFFFF
                } else if a == 0x80000000 && b == 0xFFFFFFFF {
                    0x80000000
                } else {
                    ((a as i32) / (b as i32)) as u32
                };
                acc = acc.wrapping_add(div_r as u64);
                let rem_r = if b == 0 {
                    a
                } else if a == 0x80000000 && b == 0xFFFFFFFF {
                    0
                } else {
                    ((a as i32).wrapping_rem(b as i32)) as u32
                };
                acc = acc.wrapping_add(rem_r as u64);
                // DIVU
                let divu_r = if b == 0 { 0xFFFFFFFFu32 } else { a / b };
                acc = acc.wrapping_add(divu_r as u64);
                // REMU
                let remu_r = if b == 0 { a } else { a % b };
                acc = acc.wrapping_add(remu_r as u64);
                // MULH
                acc = acc.wrapping_add(
                    ((a as i32 as i64).wrapping_mul(b as i32 as i64) >> 32) as u32 as u64,
                );
                // MULHSU
                acc = acc.wrapping_add(
                    ((a as i32 as i64).wrapping_mul(b as u64 as i64) >> 32) as u32 as u64,
                );
                // MULHU
                acc = acc.wrapping_add(((a as u64).wrapping_mul(b as u64) >> 32) as u32 as u64);
            }
        }
        acc = acc.wrapping_add(vals[4].wrapping_sub(vals[4]) as u64);
        acc = acc.wrapping_add(0x7FFFFFFFu32.wrapping_add(1) as u64);
        let mut shifted = i.wrapping_add(1);
        for _ in 1..32u32 {
            shifted = shifted.wrapping_shl(1);
            acc = acc.wrapping_add(shifted as u64);
        }
        for _ in 1..32u32 {
            shifted = ((shifted as i32).wrapping_shr(1)) as u32;
            acc = acc.wrapping_add(shifted as u64);
        }
    }
    // Raw div/rem edge instructions folded once (see guest div_rem_edges): RISC-V
    // spec — div/0=0xFFFFFFFF, divu/0=0xFFFFFFFF, rem/0=1, remu/0=1,
    // INT_MIN/-1: div=0x80000000, rem=0.
    acc = acc.wrapping_add(0xFFFFFFFFu64 + 0xFFFFFFFFu64 + 1 + 1 + 0x80000000u64);
    acc.to_le_bytes().to_vec()
}

// ===================================================================
// Expected-value: memory-stress (all 6 modes)
// ===================================================================

fn expected_memory_stress_seq(size: u32) -> Vec<u8> {
    let len = (size as usize) * 256;
    let mut buf = vec![0u8; len];
    for i in 0..len {
        buf[i] = ((i as u64).wrapping_mul(7) & 0xFF) as u8;
    }
    let mut acc: u64 = 0;
    for i in 0..len {
        acc = acc.wrapping_mul(31).wrapping_add(buf[i] as u64);
    }
    acc.to_le_bytes().to_vec()
}

fn expected_memory_stress_random(size: u32) -> Vec<u8> {
    let len = (size as usize) * 256;
    let mut buf = vec![0u32; len / 4];
    let mut rng = 0x12345678u32;
    for _ in 0..len {
        let idx = (lcg(&mut rng) as usize) % (len / 4);
        let add_val = lcg(&mut rng);
        buf[idx] = buf[idx].wrapping_add(add_val);
    }
    let mut acc: u64 = 0;
    for _ in 0..len {
        let idx = (lcg(&mut rng) as usize) % (len / 4);
        acc = acc.wrapping_add(buf[idx] as u64);
    }
    acc.to_le_bytes().to_vec()
}

fn expected_memory_stress_recurse(size: u32) -> Vec<u8> {
    fn dr(depth: usize, seed: u32) -> u32 {
        if depth == 0 {
            return seed;
        }
        let mut l = [0u32; 16];
        for i in 0..16 {
            l[i] = seed.wrapping_add(i as u32).wrapping_mul(depth as u32);
        }
        dr(depth - 1, l[depth % 16]).wrapping_add(l[(depth + 7) % 16])
    }
    (dr(size.min(2000) as usize, 0x42) as u64)
        .to_le_bytes()
        .to_vec()
}

fn expected_memory_stress_mixed(size: u32) -> Vec<u8> {
    let len = (size as usize) * 128;
    let mut buf: Vec<u32> = (0..len).map(|i| i as u32).collect();
    let mut rng = 0xDEADBEEFu32;
    for _ in 0..len {
        let a = (lcg(&mut rng) as usize) % len;
        let b = (lcg(&mut rng) as usize) % len;
        buf.swap(a, b);
    }
    let mut acc: u64 = 0;
    for i in 0..len {
        acc = acc.wrapping_mul(17).wrapping_add(buf[i] as u64);
    }
    acc.to_le_bytes().to_vec()
}

fn expected_memory_stress_unaligned(size: u32) -> Vec<u8> {
    let len = (size as usize).max(16) * 64;
    let mut buf = vec![0u8; len + 8];
    for i in 0..buf.len() {
        buf[i] = ((i as u64).wrapping_mul(13).wrapping_add(7) & 0xFF) as u8;
    }
    let mut acc: u64 = 0;
    for off in 0..4u32 {
        let count = (len / 4).min(1024);
        for i in 0..count {
            let start = off as usize + i * 4;
            let val =
                u32::from_le_bytes([buf[start], buf[start + 1], buf[start + 2], buf[start + 3]]);
            acc = acc.wrapping_mul(31).wrapping_add(val as u64);
        }
    }
    for off in 1..4u32 {
        let write_val = 0xDEADBEEF_u32.wrapping_add(off);
        let start = off as usize;
        let bytes = write_val.to_le_bytes();
        buf[start] = bytes[0];
        buf[start + 1] = bytes[1];
        buf[start + 2] = bytes[2];
        buf[start + 3] = bytes[3];
        let read_back =
            u32::from_le_bytes([buf[start], buf[start + 1], buf[start + 2], buf[start + 3]]);
        acc = acc.wrapping_mul(31).wrapping_add(read_back as u64);
    }
    acc.to_le_bytes().to_vec()
}

fn expected_memory_stress_heap_churn(size: u32) -> Vec<u8> {
    let rounds = (size as usize).max(1);
    let mut acc: u64 = 0;
    for r in 0..rounds {
        let cap = 64 + (r % 128) * 16;
        let mut v: Vec<u32> = Vec::with_capacity(cap);
        for j in 0..cap {
            v.push((r as u32).wrapping_mul(31).wrapping_add(j as u32));
        }
        for &val in v.iter() {
            acc = acc.wrapping_mul(17).wrapping_add(val as u64);
        }
        let extra = cap / 2;
        for j in 0..extra {
            v.push(j as u32);
        }
        acc = acc.wrapping_add(v.len() as u64);
    }
    acc.to_le_bytes().to_vec()
}

// ===================================================================
// Expected-value: host-side 256-bit modular multiply (mirrors bigint precompile)
// ===================================================================

fn host_modmul_256(a: &[u32; 8], b: &[u32; 8], m: &[u32; 8]) -> [u32; 8] {
    // Standard 256-bit modular multiply: result = (a * b) mod m, computed with
    // num-bigint so the reference is trivially correct (little-endian u32 limbs).
    use num_bigint::BigUint;
    let from_limbs = |limbs: &[u32; 8]| BigUint::from_slice(limbs);
    let prod = from_limbs(a) * from_limbs(b);
    let rem = prod % from_limbs(m);
    // Serialize back to exactly 8 little-endian u32 limbs (zero-padded).
    let mut out = [0u32; 8];
    for (i, limb) in rem.to_u32_digits().into_iter().take(8).enumerate() {
        out[i] = limb;
    }
    out
}

// ===================================================================
// Expected-value: precompile-interleave
// ===================================================================

fn expected_precompile_interleave(n: u32) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    use tiny_keccak::{Hasher, Keccak};

    fn sha256_hash(data: &[u8; 32]) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(data);
        let r = h.finalize();
        let mut o = [0u8; 32];
        o.copy_from_slice(&r);
        o
    }
    fn keccak256_hash(data: &[u8; 32]) -> [u8; 32] {
        let mut h = Keccak::v256();
        h.update(data);
        let mut o = [0u8; 32];
        h.finalize(&mut o);
        o
    }
    fn bigint_mix(data: &[u8; 32]) -> [u8; 32] {
        let mut a = [0u32; 8];
        for i in 0..8 {
            a[i] = u32::from_le_bytes([
                data[i * 4],
                data[i * 4 + 1],
                data[i * 4 + 2],
                data[i * 4 + 3],
            ]);
        }
        let modulus: [u32; 8] = [
            0xFFFFFF43, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
            0xFFFFFFFF,
        ];
        a[0] |= 1;
        let mut b = [0u32; 8];
        for i in 0..8 {
            b[i] = a[(i + 3) % 8].wrapping_add(0x9E3779B9);
        }
        b[0] |= 1;
        let result = host_modmul_256(&a, &b, &modulus);
        let mut o = [0u8; 32];
        for i in 0..8 {
            o[i * 4..i * 4 + 4].copy_from_slice(&result[i].to_le_bytes());
        }
        o
    }

    let mut acc = [0u8; 32];
    acc[0] = 0x42;
    acc[1] = 0xDE;
    acc[2] = 0xAD;
    acc[31] = 0xFF;
    let perms: &[[usize; 3]] = &[
        [0, 1, 2],
        [0, 2, 1],
        [1, 0, 2],
        [1, 2, 0],
        [2, 0, 1],
        [2, 1, 0],
    ];
    for i in 0..n {
        for &op in &perms[(i as usize) % perms.len()] {
            acc = match op {
                0 => sha256_hash(&acc),
                1 => keccak256_hash(&acc),
                _ => bigint_mix(&acc),
            };
        }
    }
    acc.to_vec()
}

// ===================================================================
// Expected-value: segment-boundary
// ===================================================================

fn expected_segment_boundary_multi_commit(param: u32) -> Vec<u8> {
    let commits = param.max(1);
    let mut acc: u64 = 0xDEADBEEF_CAFEBABE;
    let mut journal = Vec::new();
    for c in 0..commits {
        for i in 0..2048u32 {
            let v = i.wrapping_mul(c).wrapping_add(0x9E3779B9);
            acc = acc.wrapping_mul(6364136223846793005).wrapping_add(v as u64);
            for j in 0..8u32 {
                acc = acc.wrapping_add(v.wrapping_shl(j & 31) as u64);
            }
        }
        journal.extend_from_slice(&acc.to_le_bytes());
    }
    journal
}

fn expected_segment_boundary_nop_sled(param: u32) -> Vec<u8> {
    let iters = param as u64 * 1024;
    0x12345678_9ABCDEF0u64
        .wrapping_add(iters)
        .to_le_bytes()
        .to_vec()
}

fn expected_segment_boundary_rapid_fire(param: u32) -> Vec<u8> {
    let count = param.max(1).min(10000);
    let mut acc: u64 = 0;
    let mut journal = Vec::new();
    for i in 0..count {
        acc = acc.wrapping_mul(31).wrapping_add(i as u64);
        journal.extend_from_slice(&acc.to_le_bytes());
    }
    journal
}

// ===================================================================
// Expected-value: babybear-stress
// ===================================================================

fn expected_babybear_stress(iterations: u32) -> Vec<u8> {
    const P: u32 = 2013265921;
    let field_vals: [u32; 12] = [
        0,
        1,
        P - 1,
        P,
        P + 1,
        P.wrapping_mul(2),
        P.wrapping_mul(2).wrapping_sub(1),
        P >> 1,
        (P >> 1) + 1,
        0x7FFFFFFF,
        0x80000000,
        0xFFFFFFFF,
    ];
    let mut acc: u64 = 0;
    for iter in 0..iterations {
        for &a in &field_vals {
            for &b in &field_vals {
                acc = acc.wrapping_add(a.wrapping_add(b) as u64);
                acc = acc.wrapping_add(a.wrapping_sub(b) as u64);
                acc = acc.wrapping_add(a.wrapping_mul(b) as u64);
                acc = acc.wrapping_add((a & b) as u64);
                acc = acc.wrapping_add((a | b) as u64);
                acc = acc.wrapping_add((a ^ b) as u64);
                if b != 0 {
                    acc = acc.wrapping_add((a / b) as u64);
                    acc = acc.wrapping_add((a % b) as u64);
                } else {
                    acc = acc.wrapping_add(0xFFFFFFFF_u64);
                    acc = acc.wrapping_add(a as u64);
                }
                let wide = (a as u64).wrapping_mul(b as u64);
                acc = acc.wrapping_add(wide);
                acc = acc.wrapping_add(a.wrapping_shl(b & 31) as u64);
                acc = acc.wrapping_add(a.wrapping_shr(b & 31) as u64);
            }
        }
        for k in 0..8u32 {
            let val = P.wrapping_mul(k);
            acc = acc.wrapping_add(val as u64);
            acc = acc.wrapping_add(val.wrapping_add(1) as u64);
            acc = acc.wrapping_add(val.wrapping_sub(1) as u64);
        }
        let scatter = P.wrapping_add(iter).wrapping_mul(2654435761);
        acc = acc.wrapping_add(scatter as u64);
    }
    acc.to_le_bytes().to_vec()
}

// ===================================================================
// Test runners
// ===================================================================

fn run_on_all_risc0(guest: &str, input: &[u8], timeout: Duration) -> Vec<(String, ProofOutput)> {
    let elf = match find_risc0_elf(guest) {
        Some(e) if !e.is_empty() => {
            eprintln!("{guest} RISC0 ELF: {} bytes", e.len());
            e
        }
        // File exists but is 0 bytes: a broken/skip build (e.g. RISC0_SKIP_BUILD=1).
        // NEVER skip this — it masquerades as coverage while proving nothing.
        Some(_) => panic!(
            "{guest} RISC0 ELF is 0 bytes (broken build / skip-build stub) — refusing to pass"
        ),
        None => {
            if require_workers() {
                panic!("REQUIRED: {guest} RISC0 ELF not found");
            }
            eprintln!("SKIP: {guest} RISC0 ELF not found");
            return vec![];
        }
    };
    let mut pool = create_pool();
    let connected = pool.discover_and_spawn();
    let workers: Vec<_> = connected
        .iter()
        .filter(|k| k.starts_with("risc0:"))
        .cloned()
        .collect();
    if workers.is_empty() {
        if require_workers() {
            pool.shutdown_all();
            panic!("REQUIRED: no RISC0 workers found");
        }
        eprintln!("SKIP: no RISC0 workers");
        pool.shutdown_all();
        return vec![];
    }
    let mut fails = Vec::new();
    let mut results = Vec::new();
    let mut vram_skips: Vec<String> = Vec::new();
    // Largest card among the risc0 workers: a VRAM failure there has nowhere to retry.
    let max_vram = workers
        .iter()
        .filter_map(|k| pool.vram_bytes_for_slot(k))
        .max()
        .unwrap_or(0);
    for key in &workers {
        eprintln!("\n--- {guest} on {key} ---");
        let start = Instant::now();
        match pool.prove(key, &elf, input, None, Some(timeout), None) {
            Ok(proof) => {
                eprintln!(
                    "  PASS: {} cycles, {}-byte seal, {:.1}s",
                    proof.cycles,
                    proof.seal.len(),
                    start.elapsed().as_secs_f64()
                );
                assert!(!proof.seal.is_empty(), "seal must be non-empty");
                assert!(!proof.journal.is_empty(), "journal must be non-empty");
                results.push((key.clone(), proof));
            }
            Err(e) => {
                let msg = format!("{e:#}");
                // A VRAM exhaustion on a card that is NOT the largest is a HARDWARE
                // LIMIT, not a prover defect, and must not fail the suite.
                //
                // Measured on this box: bigint-mul's groth16 wrap OOMs on the 16,303 MiB
                // RTX 5080 (`cudaMallocAsync ... "out of memory"`) and proves on the
                // 24,564 MiB RTX 4090 in 16s. Demanding that EVERY card prove EVERY
                // guest makes a heterogeneous box permanently red and hides real
                // regressions in the noise. The miner's own answer to this is to retry on
                // a strictly bigger card (see `oom_routing.rs`), so a smaller card
                // declining a heavy guest is expected behaviour.
                //
                // Still fatal: any NON-VRAM failure, a VRAM failure on the largest card
                // (nothing bigger to retry on), and every card failing.
                let is_vram = zkminer_prover_protocol::types::is_gpu_oom(&msg);
                let this_vram = pool.vram_bytes_for_slot(key).unwrap_or(0);
                let is_largest = this_vram >= max_vram;
                if is_vram && !is_largest {
                    eprintln!(
                        "  SKIP (hardware limit): {} MiB card cannot fit this guest; \
                         largest here is {} MiB. {msg}",
                        this_vram / 1024 / 1024,
                        max_vram / 1024 / 1024
                    );
                    vram_skips.push(format!("{key} ({} MiB)", this_vram / 1024 / 1024));
                } else {
                    eprintln!("  FAIL: {msg}");
                    fails.push(format!("{key}: {msg}"));
                }
            }
        }
    }
    pool.shutdown_all();
    if !fails.is_empty() {
        panic!(
            "{guest}: {}/{} workers failed:\n  {}",
            fails.len(),
            workers.len(),
            fails.join("\n  ")
        );
    }
    if results.is_empty() {
        panic!(
            "{guest}: NO worker produced a proof ({} skipped for VRAM: {}). A guest that \
             fits on no card at all is a real failure, not a hardware limit.",
            vram_skips.len(),
            vram_skips.join(", ")
        );
    }
    if !vram_skips.is_empty() {
        eprintln!(
            "  ({} of {} risc0 workers skipped as too small: {})",
            vram_skips.len(),
            workers.len(),
            vram_skips.join(", ")
        );
    }
    results
}

fn run_on_sp1(guest: &str, input: &[u8], timeout: Duration) -> Option<ProofOutput> {
    let elf = match find_sp1_elf(guest) {
        Some(e) if !e.is_empty() => {
            eprintln!("{guest} SP1 ELF: {} bytes", e.len());
            e
        }
        Some(_) => panic!("{guest} SP1 ELF is 0 bytes (broken build) — refusing to pass"),
        None => {
            if require_workers() {
                panic!("REQUIRED: {guest} SP1 ELF not found");
            }
            eprintln!("SKIP: {guest} SP1 ELF not found");
            return None;
        }
    };
    let mut pool = create_pool();
    let connected = pool.discover_and_spawn();
    // Prove on ALL sp1 slots (e.g. sp1:cpu vs sp1:cuda) and assert they agree —
    // the SP1 analog of assert_cross_worker, so a per-slot divergence is caught.
    let sp1_keys: Vec<_> = connected
        .iter()
        .filter(|k| k.starts_with("sp1:"))
        .cloned()
        .collect();
    if sp1_keys.is_empty() {
        if require_workers() {
            pool.shutdown_all();
            panic!("REQUIRED: no SP1 worker found");
        }
        eprintln!("SKIP: no SP1 worker");
        pool.shutdown_all();
        return None;
    }
    let mut first: Option<ProofOutput> = None;
    for (i, key) in sp1_keys.iter().enumerate() {
        // RELEASE the previous slot's worker before starting the next.
        //
        // SP1 now has one slot per CUDA card, so this loop proves on every card in turn — and each
        // proof leaves an `sp1-gpu-server` resident, by design — measured on 2026-10-07 at 23.3 GB of
        // host RSS and 15,124 MiB of VRAM. Walking two cards without a teardown leaves both alive, far
        // more than this 28 GiB box holds: it has already been hard-frozen that way and needed a power
        // cycle.
        // When `sp1_keys` had one element the loop could not do this; now it can.
        if i > 0 {
            pool.recycle_slot(&sp1_keys[i - 1]);
        }
        eprintln!("\n--- {guest} on {key} ---");
        let start = Instant::now();
        match pool.prove(key, &elf, input, None, Some(timeout), None) {
            Ok(proof) => {
                eprintln!(
                    "  PASS: {} cycles, {}-byte seal, {:.1}s",
                    proof.cycles,
                    proof.seal.len(),
                    start.elapsed().as_secs_f64()
                );
                assert!(!proof.seal.is_empty());
                assert!(!proof.journal.is_empty());
                match &first {
                    Some(f) => assert_eq!(
                        proof.journal, f.journal,
                        "{guest} SP1 cross-worker mismatch on {key}"
                    ),
                    None => first = Some(proof),
                }
            }
            Err(e) => {
                pool.shutdown_all();
                panic!("{guest} SP1 on {key}: {e:#}");
            }
        }
    }
    pool.shutdown_all();
    first
}

/// Assert that proving actually happened, and (with >1 worker) that all workers
/// committed identical journals.
///
/// The non-empty guard matters: without it, a `results` vec that came back empty
/// (fail-open skip path) would make the caller's per-worker assert loop iterate
/// zero times and the test pass having verified nothing. Callers in skip mode
/// (ZKVM_ALLOW_SKIP=1) return before reaching here.
fn assert_cross_worker(results: &[(String, ProofOutput)], guest: &str) {
    if results.is_empty() {
        // Empty results are only produced on run_on_all_risc0's skip path (it PANICS
        // on a missing worker/ELF in the default fail-closed mode). So this is a skip
        // when skipping is allowed; keep a fail-open tripwire if enforcement was
        // expected. This lets ZKVM_ALLOW_SKIP=1 actually skip rather than hard-fail.
        assert!(
            !require_workers(),
            "{guest}: no RISC0 worker proved — nothing verified (fail-open?)"
        );
        return;
    }
    let first = &results[0].1.journal;
    for (key, proof) in &results[1..] {
        assert_eq!(
            &proof.journal, first,
            "{guest} cross-worker mismatch: {} vs {}",
            results[0].0, key
        );
    }
}

// ===================================================================
// RISC0 tests — original 4 guests
// ===================================================================

#[test]
fn test_rv32im_torture_risc0() {
    let (seed, iters) = (42u32, 1u32);
    let r = run_on_all_risc0(
        "rv32im-torture",
        &make_input(&[seed, iters]),
        Duration::from_secs(600),
    );
    let exp = expected_rv32im_torture_risc0(seed, iters);
    for (k, p) in &r {
        assert_eq!(p.journal, exp, "rv32im-torture journal mismatch on {k}");
    }
    assert_cross_worker(&r, "rv32im-torture");
}

#[test]
fn test_rv32im_torture_multiseg_risc0() {
    // iterations=50 to force multi-segment execution (~1M+ cycles)
    let (seed, iters) = (42u32, 50u32);
    let r = run_on_all_risc0(
        "rv32im-torture",
        &make_input(&[seed, iters]),
        Duration::from_secs(1800),
    );
    let exp = expected_rv32im_torture_risc0(seed, iters);
    for (k, p) in &r {
        assert_eq!(p.journal, exp, "rv32im-torture multiseg mismatch on {k}");
    }
    assert_cross_worker(&r, "rv32im-torture-multiseg");
}

#[test]
fn test_precompile_interleave_risc0() {
    let n = 100u32;
    let r = run_on_all_risc0(
        "precompile-interleave",
        &make_input(&[n]),
        Duration::from_secs(1200),
    );
    let exp = expected_precompile_interleave(n);
    for (k, p) in &r {
        assert_eq!(p.journal, exp, "precompile-interleave mismatch on {k}");
    }
    assert_cross_worker(&r, "precompile-interleave");
}

#[test]
fn test_precompile_interleave_multiseg_risc0() {
    // n=2000 to force multi-segment with precompile calls spanning boundaries
    let n = 2000u32;
    let r = run_on_all_risc0(
        "precompile-interleave",
        &make_input(&[n]),
        Duration::from_secs(1800),
    );
    let exp = expected_precompile_interleave(n);
    for (k, p) in &r {
        assert_eq!(
            p.journal, exp,
            "precompile-interleave multiseg mismatch on {k}"
        );
    }
}

#[test]
fn test_memory_stress_sequential_risc0() {
    let size = 64u32; // Increased from 4 for more cycles
    let r = run_on_all_risc0(
        "memory-stress",
        &make_input(&[0, size]),
        Duration::from_secs(600),
    );
    let exp = expected_memory_stress_seq(size);
    for (k, p) in &r {
        assert_eq!(p.journal, exp, "mem-stress seq mismatch on {k}");
    }
}

#[test]
fn test_memory_stress_random_risc0() {
    let size = 64u32;
    let r = run_on_all_risc0(
        "memory-stress",
        &make_input(&[1, size]),
        Duration::from_secs(600),
    );
    let exp = expected_memory_stress_random(size);
    for (k, p) in &r {
        assert_eq!(p.journal, exp, "mem-stress random mismatch on {k}");
    }
    assert_cross_worker(&r, "memory-stress-random");
}

#[test]
fn test_memory_stress_recursion_risc0() {
    let size = 1000u32; // Increased from 500
    let r = run_on_all_risc0(
        "memory-stress",
        &make_input(&[2, size]),
        Duration::from_secs(600),
    );
    let exp = expected_memory_stress_recurse(size);
    for (k, p) in &r {
        assert_eq!(p.journal, exp, "mem-stress recursion mismatch on {k}");
    }
}

#[test]
fn test_memory_stress_mixed_risc0() {
    let size = 64u32;
    let r = run_on_all_risc0(
        "memory-stress",
        &make_input(&[3, size]),
        Duration::from_secs(600),
    );
    let exp = expected_memory_stress_mixed(size);
    for (k, p) in &r {
        assert_eq!(p.journal, exp, "mem-stress mixed mismatch on {k}");
    }
    assert_cross_worker(&r, "memory-stress-mixed");
}

#[test]
fn test_memory_stress_unaligned_risc0() {
    let size = 64u32;
    let r = run_on_all_risc0(
        "memory-stress",
        &make_input(&[4, size]),
        Duration::from_secs(600),
    );
    let exp = expected_memory_stress_unaligned(size);
    for (k, p) in &r {
        assert_eq!(p.journal, exp, "mem-stress unaligned mismatch on {k}");
    }
}

#[test]
fn test_memory_stress_heap_churn_risc0() {
    let size = 200u32; // Increased from 50
    let r = run_on_all_risc0(
        "memory-stress",
        &make_input(&[5, size]),
        Duration::from_secs(600),
    );
    let exp = expected_memory_stress_heap_churn(size);
    for (k, p) in &r {
        assert_eq!(p.journal, exp, "mem-stress heap churn mismatch on {k}");
    }
}

#[test]
fn test_edge_case_arith_risc0() {
    let n = 50u32;
    let r = run_on_all_risc0(
        "edge-case-arith",
        &make_input(&[n]),
        Duration::from_secs(600),
    );
    let exp = expected_edge_case_arith(n);
    for (k, p) in &r {
        assert_eq!(p.journal, exp, "edge-case-arith mismatch on {k}");
    }
}

#[test]
fn test_edge_case_arith_scale_risc0() {
    let n = 5000u32;
    let r = run_on_all_risc0(
        "edge-case-arith",
        &make_input(&[n]),
        Duration::from_secs(1800),
    );
    let exp = expected_edge_case_arith(n);
    for (k, p) in &r {
        assert_eq!(p.journal, exp, "edge-case-arith scale mismatch on {k}");
    }
}

// ===================================================================
// RISC0 tests — new guests
// ===================================================================

#[test]
fn test_segment_boundary_multi_commit_risc0() {
    let param = 20u32;
    let r = run_on_all_risc0(
        "segment-boundary",
        &make_input(&[0, param]),
        Duration::from_secs(1200),
    );
    let exp = expected_segment_boundary_multi_commit(param);
    for (k, p) in &r {
        assert_eq!(
            p.journal, exp,
            "segment-boundary multi-commit mismatch on {k}"
        );
    }
    assert_cross_worker(&r, "segment-boundary-multi-commit");
}

#[test]
fn test_segment_boundary_nop_sled_risc0() {
    // Target ~1M cycles: param=1024 → 1024*1024 = ~1M iterations
    let param = 1024u32;
    let r = run_on_all_risc0(
        "segment-boundary",
        &make_input(&[1, param]),
        Duration::from_secs(600),
    );
    let exp = expected_segment_boundary_nop_sled(param);
    for (k, p) in &r {
        assert_eq!(p.journal, exp, "segment-boundary nop-sled mismatch on {k}");
    }
    assert_cross_worker(&r, "segment-boundary-nop-sled");
}

#[test]
fn test_segment_boundary_rapid_fire_risc0() {
    let param = 500u32;
    let r = run_on_all_risc0(
        "segment-boundary",
        &make_input(&[2, param]),
        Duration::from_secs(600),
    );
    let exp = expected_segment_boundary_rapid_fire(param);
    for (k, p) in &r {
        assert_eq!(
            p.journal, exp,
            "segment-boundary rapid-fire mismatch on {k}"
        );
    }
    assert_cross_worker(&r, "segment-boundary-rapid-fire");
}

#[test]
fn test_babybear_stress_risc0() {
    let iters = 100u32;
    let r = run_on_all_risc0(
        "babybear-stress",
        &make_input(&[iters]),
        Duration::from_secs(600),
    );
    let exp = expected_babybear_stress(iters);
    for (k, p) in &r {
        assert_eq!(p.journal, exp, "babybear-stress mismatch on {k}");
    }
}

#[test]
fn test_babybear_stress_scale_risc0() {
    let iters = 5000u32;
    let r = run_on_all_risc0(
        "babybear-stress",
        &make_input(&[iters]),
        Duration::from_secs(1800),
    );
    let exp = expected_babybear_stress(iters);
    for (k, p) in &r {
        assert_eq!(p.journal, exp, "babybear-stress scale mismatch on {k}");
    }
}

/// Exhaustive per-GPU correctness/OOM sampling for the intermittent multi-segment
/// invalid-proof (see docs/multiseg-invalid-proof.md). Proves a complex multi-segment
/// guest N times on EVERY discovered risc0 GPU worker, classifying each outcome as
/// VALID / INVALID_PROOF / OOM_OR_DIED / OTHER — never aborting, so one bad proof
/// doesn't stop the sample. A fresh pool is spawned per run so a worker that dies
/// (OOM) is respawned for the next run instead of poisoning the rest.
///
/// #[ignore]d (long-running). Run explicitly, e.g.:
///   SAMPLE_RUNS=100 SAMPLE_ITERS=5000 timeout --signal=KILL 21600 \
///     env ZKVM_REQUIRE_WORKERS=1 RUST_LOG=warn cargo test -p zkminer-prover \
///     --features risc0 --test comprehensive_zkvm_test sampling_multiseg -- \
///     --ignored --nocapture > sample.log 2>&1
#[test]
#[ignore]
fn sampling_multiseg_per_gpu() {
    // Guest + size are configurable so we can push segment count up to reproduce the
    // rarer high-segment CUDA/Blackwell residual (docs/multiseg-invalid-proof.md).
    let guest = std::env::var("SAMPLE_GUEST").unwrap_or_else(|_| "babybear-stress".to_string());
    let iters: u32 = std::env::var("SAMPLE_ITERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(5000);
    let runs: u32 = std::env::var("SAMPLE_RUNS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(100);
    let input = make_input(&[iters]);
    // Only the babybear guest has an expected-journal oracle here; for others we just
    // require a non-empty journal + a valid proof.
    let expected: Option<Vec<u8>> = if guest == "babybear-stress" {
        Some(expected_babybear_stress(iters))
    } else {
        None
    };
    let per_proof_timeout = Duration::from_secs(
        std::env::var("SAMPLE_TIMEOUT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(1800),
    );

    let elf = match find_risc0_elf(&guest) {
        Some(e) if !e.is_empty() => e,
        _ => panic!("REQUIRED: {guest} RISC0 ELF not found/empty"),
    };

    fn gpu_name(key: &str) -> &'static str {
        match key {
            "risc0:cuda:0" => "RTX 5090",
            "risc0:cuda:1" => "RTX 4090",
            "risc0:rocm:0" => "RX 7900 XTX",
            _ => "unknown",
        }
    }
    // [valid, invalid, oom/died, other]
    let mut tally: std::collections::BTreeMap<String, [u32; 4]> = Default::default();

    eprintln!(
        "\n=== multiseg sampling (PARALLEL per-GPU): {guest} iters={iters}, {runs} runs/GPU, timeout={per_proof_timeout:?} ===\n"
    );

    for i in 0..runs {
        // Fresh pool per round so a worker that OOMs/dies is cleanly respawned next
        // round (and each proof is independent — no cross-run VRAM accumulation).
        let mut pool = create_pool();
        let connected = pool.discover_and_spawn();
        let workers: Vec<String> = connected
            .iter()
            .filter(|k| k.starts_with("risc0:"))
            .cloned()
            .collect();
        if workers.is_empty() {
            pool.shutdown_all();
            panic!("REQUIRED: no RISC0 workers discovered");
        }

        // Prove on EVERY GPU concurrently this round — different physical devices +
        // per-worker slot mutexes, so there's no contention (same model the miner uses).
        let round: Vec<(String, u8, f64)> = std::thread::scope(|s| {
            let handles: Vec<_> = workers
                .iter()
                .map(|key| {
                    let (pool_ref, elf_ref, input_ref, exp_ref) = (&pool, &elf, &input, &expected);
                    s.spawn(move || {
                        let start = Instant::now();
                        let idx = match pool_ref.prove(key, elf_ref, input_ref, None, Some(per_proof_timeout), None) {
                            Ok(proof) => {
                                // BENCHMARK: worker-reported exact prove_with_opts duration
                                // (STARK + recursion + Groth16; excludes the local receipt.verify)
                                // and total_cycles, so cycles/sec is authoritative.
                                let pd = proof.duration.as_secs_f64();
                                eprintln!(
                                    "[BENCHNUM] {key} cycles={} prove_duration_secs={:.3} prove_cps={:.0}",
                                    proof.cycles, pd, proof.cycles as f64 / pd.max(1e-9)
                                );
                                match exp_ref {
                                    Some(exp) if &proof.journal != exp => {
                                        eprintln!("  [{key}] WRONG JOURNAL (proof verified but output differs!)");
                                        3
                                    }
                                    _ if proof.journal.is_empty() => 3,
                                    _ => 0, // VALID
                                }
                            }
                            Err(e) => {
                                let raw = format!("{e:#}");
                                let m = raw.to_lowercase();
                                let idx: u8 = if m.contains("verification indicates") || m.contains("invalid") {
                                    1 // INVALID_PROOF
                                } else if m.contains("out of memory")
                                    || m.contains("oom")
                                    || m.contains("worker_died")
                                    || m.contains("worker died")
                                    || m.contains("out of resource")
                                    || m.contains("outofmemory")
                                    || m.contains("cudaerrormemoryallocation")
                                {
                                    2 // OOM / DIED
                                } else {
                                    3 // OTHER
                                };
                                // Log the raw error so failure modes can be characterized
                                // (CUDA error code vs assert vs signal vs true OOM).
                                eprintln!("  [{key}] {} raw: {raw}", ["", "INVALID", "OOM/DIED", "OTHER"][idx as usize]);
                                idx
                            }
                        };
                        (key.clone(), idx, start.elapsed().as_secs_f64())
                    })
                })
                .collect();
            handles.into_iter().map(|h| h.join().unwrap()).collect()
        });
        pool.shutdown_all();

        for (key, idx, secs) in round {
            tally.entry(key.clone()).or_insert([0; 4])[idx as usize] += 1;
            let label = ["VALID", "INVALID_PROOF", "OOM/DIED", "OTHER"][idx as usize];
            eprintln!(
                "run {:>3}/{runs} [{key} {}] {label} ({secs:.1}s)",
                i + 1,
                gpu_name(&key)
            );
        }

        if (i + 1) % 10 == 0 {
            eprintln!("--- progress after {} runs ---", i + 1);
            for (k, t) in &tally {
                eprintln!(
                    "    {k} {}: valid={} invalid={} oom={} other={}",
                    gpu_name(k),
                    t[0],
                    t[1],
                    t[2],
                    t[3]
                );
            }
        }
    }

    eprintln!("\n=== FINAL: {guest} iters={iters}, {runs} runs/GPU ===");
    for (k, t) in &tally {
        let total = t.iter().sum::<u32>();
        eprintln!(
            "  {k} ({}): valid={}/{total}  invalid_proof={}  oom_died={}  other={}",
            gpu_name(k),
            t[0],
            t[1],
            t[2],
            t[3]
        );
    }
}

#[test]
fn test_minimal_proof_risc0() {
    let r = run_on_all_risc0("minimal-proof", &[], Duration::from_secs(300));
    for (k, p) in &r {
        assert_eq!(p.journal, vec![0x42u8], "minimal-proof mismatch on {k}");
    }
}

// ===================================================================
// Nondeterminism + consistency checks (RISC0)
// ===================================================================

#[test]
fn test_rv32im_torture_nondeterminism_risc0() {
    let input = make_input(&[42, 1]);
    let elf = match find_risc0_elf("rv32im-torture") {
        Some(e) if !e.is_empty() => e,
        // 0-byte ELF = broken/skip build: fail closed regardless of ZKVM_ALLOW_SKIP
        // (mirrors run_on_all_risc0), so it can't masquerade as passing coverage.
        Some(_) => panic!("rv32im-torture RISC0 ELF is 0 bytes (broken build / skip-build stub) — refusing to pass"),
        None => {
            if require_workers() { panic!("REQUIRED: rv32im-torture ELF not found"); }
            eprintln!("SKIP: rv32im-torture RISC0 ELF not found"); return;
        }
    };
    let mut pool = create_pool();
    let connected = pool.discover_and_spawn();
    let key = match connected.iter().find(|k| k.starts_with("risc0:")).cloned() {
        Some(k) => k,
        None => {
            if require_workers() {
                pool.shutdown_all();
                panic!("REQUIRED: no RISC0 workers");
            }
            eprintln!("SKIP: no RISC0 workers");
            pool.shutdown_all();
            return;
        }
    };
    let mut journals = Vec::new();
    for run in 0..5 {
        eprintln!("--- nondeterminism run {run} on {key} ---");
        match pool.prove(
            &key,
            &elf,
            &input,
            None,
            Some(Duration::from_secs(600)),
            None,
        ) {
            Ok(p) => {
                eprintln!("  run {run}: {} cycles", p.cycles);
                journals.push(p.journal);
            }
            Err(e) => {
                pool.shutdown_all();
                panic!("run {run} failed: {e:#}");
            }
        }
    }
    pool.shutdown_all();
    assert!(
        !journals.is_empty(),
        "nondeterminism: no runs completed — nothing verified"
    );
    for i in 1..journals.len() {
        assert_eq!(journals[0], journals[i], "journal mismatch: run 0 vs {i}");
    }
    // Run-to-run equality alone would pass a DETERMINISTICALLY-wrong backend; also
    // pin against the golden value so a systematic (but stable) miscompute is caught.
    assert_eq!(
        journals[0],
        expected_rv32im_torture_risc0(42, 1),
        "nondeterminism-run golden mismatch"
    );
}

// ===================================================================
// SP1 tests
// ===================================================================

#[test]
fn test_rv32im_torture_sp1() {
    let (seed, iters) = (42u32, 1u32);
    if let Some(p) = run_on_sp1(
        "rv32im-torture",
        &make_input(&[seed, iters]),
        Duration::from_secs(600),
    ) {
        let exp = expected_rv32im_torture_sp1(seed, iters);
        assert_eq!(p.journal, exp, "rv32im-torture SP1 journal mismatch");
    }
}

#[test]
fn test_precompile_interleave_sp1() {
    let n = 50u32;
    if let Some(p) = run_on_sp1(
        "precompile-interleave",
        &make_input(&[n]),
        Duration::from_secs(1200),
    ) {
        let exp = expected_precompile_interleave(n);
        assert_eq!(p.journal, exp, "precompile-interleave SP1 mismatch");
    }
}

#[test]
fn test_memory_stress_sequential_sp1() {
    let size = 64u32;
    if let Some(p) = run_on_sp1(
        "memory-stress",
        &make_input(&[0, size]),
        Duration::from_secs(600),
    ) {
        assert_eq!(
            p.journal,
            expected_memory_stress_seq(size),
            "mem-stress seq SP1 mismatch"
        );
    }
}

#[test]
fn test_memory_stress_random_sp1() {
    let size = 64u32;
    if let Some(p) = run_on_sp1(
        "memory-stress",
        &make_input(&[1, size]),
        Duration::from_secs(600),
    ) {
        assert_eq!(
            p.journal,
            expected_memory_stress_random(size),
            "mem-stress random SP1 mismatch"
        );
    }
}

#[test]
fn test_memory_stress_recursion_sp1() {
    let size = 1000u32;
    if let Some(p) = run_on_sp1(
        "memory-stress",
        &make_input(&[2, size]),
        Duration::from_secs(600),
    ) {
        assert_eq!(
            p.journal,
            expected_memory_stress_recurse(size),
            "mem-stress recursion SP1 mismatch"
        );
    }
}

#[test]
fn test_memory_stress_mixed_sp1() {
    let size = 64u32;
    if let Some(p) = run_on_sp1(
        "memory-stress",
        &make_input(&[3, size]),
        Duration::from_secs(600),
    ) {
        assert_eq!(
            p.journal,
            expected_memory_stress_mixed(size),
            "mem-stress mixed SP1 mismatch"
        );
    }
}

#[test]
fn test_memory_stress_unaligned_sp1() {
    let size = 64u32;
    if let Some(p) = run_on_sp1(
        "memory-stress",
        &make_input(&[4, size]),
        Duration::from_secs(600),
    ) {
        assert_eq!(
            p.journal,
            expected_memory_stress_unaligned(size),
            "mem-stress unaligned SP1 mismatch"
        );
    }
}

#[test]
fn test_memory_stress_heap_churn_sp1() {
    let size = 200u32;
    if let Some(p) = run_on_sp1(
        "memory-stress",
        &make_input(&[5, size]),
        Duration::from_secs(600),
    ) {
        assert_eq!(
            p.journal,
            expected_memory_stress_heap_churn(size),
            "mem-stress heap SP1 mismatch"
        );
    }
}

#[test]
fn test_edge_case_arith_sp1() {
    let n = 50u32;
    if let Some(p) = run_on_sp1(
        "edge-case-arith",
        &make_input(&[n]),
        Duration::from_secs(600),
    ) {
        assert_eq!(
            p.journal,
            expected_edge_case_arith(n),
            "edge-case-arith SP1 mismatch"
        );
    }
}

#[test]
fn test_edge_case_arith_scale_sp1() {
    let n = 5000u32;
    if let Some(p) = run_on_sp1(
        "edge-case-arith",
        &make_input(&[n]),
        Duration::from_secs(1800),
    ) {
        assert_eq!(
            p.journal,
            expected_edge_case_arith(n),
            "edge-case-arith scale SP1 mismatch"
        );
    }
}

#[test]
fn test_segment_boundary_multi_commit_sp1() {
    let param = 20u32;
    if let Some(p) = run_on_sp1(
        "segment-boundary",
        &make_input(&[0, param]),
        Duration::from_secs(1200),
    ) {
        assert_eq!(
            p.journal,
            expected_segment_boundary_multi_commit(param),
            "segment-boundary SP1 mismatch"
        );
    }
}

#[test]
fn test_segment_boundary_rapid_fire_sp1() {
    let param = 500u32;
    if let Some(p) = run_on_sp1(
        "segment-boundary",
        &make_input(&[2, param]),
        Duration::from_secs(600),
    ) {
        assert_eq!(
            p.journal,
            expected_segment_boundary_rapid_fire(param),
            "segment-boundary rapid SP1 mismatch"
        );
    }
}

#[test]
fn test_minimal_proof_sp1() {
    if let Some(p) = run_on_sp1("minimal-proof", &[], Duration::from_secs(300)) {
        assert_eq!(p.journal, vec![0x42u8], "minimal-proof SP1 mismatch");
    }
}

// ===================================================================
// Additional coverage from the review: missing SP1 mode + default-mode sentinels.
// ===================================================================

#[test]
fn test_segment_boundary_nop_sled_sp1() {
    let param = 1024u32;
    if let Some(p) = run_on_sp1(
        "segment-boundary",
        &make_input(&[1, param]),
        Duration::from_secs(600),
    ) {
        assert_eq!(
            p.journal,
            expected_segment_boundary_nop_sled(param),
            "segment-boundary nop-sled SP1 mismatch"
        );
    }
}

/// Out-of-range mode must land in the guest's default arm and commit the
/// 0xBADC0DE sentinel — so a malformed mode word can't masquerade as a valid
/// proof while producing a degenerate-but-non-empty journal.
#[test]
fn test_memory_stress_default_mode_risc0() {
    let r = run_on_all_risc0(
        "memory-stress",
        &make_input(&[99, 1]),
        Duration::from_secs(300),
    );
    let exp = 0xBADC0DEu64.to_le_bytes().to_vec();
    for (k, p) in &r {
        assert_eq!(
            p.journal, exp,
            "memory-stress default-mode sentinel mismatch on {k}"
        );
    }
    assert_cross_worker(&r, "memory-stress-default");
}

#[test]
fn test_segment_boundary_default_mode_risc0() {
    let r = run_on_all_risc0(
        "segment-boundary",
        &make_input(&[99, 1]),
        Duration::from_secs(300),
    );
    let exp = 0xBADC0DEu64.to_le_bytes().to_vec();
    for (k, p) in &r {
        assert_eq!(
            p.journal, exp,
            "segment-boundary default-mode sentinel mismatch on {k}"
        );
    }
    assert_cross_worker(&r, "segment-boundary-default");
}

// ===================================================================
// Cross-backend tests: RISC0 journal == SP1 journal == golden expected.
// Asserting BOTH backends against the golden (not just RISC0==SP1) is essential:
// two copy-paste-identical guests can agree on the SAME wrong value (exactly how
// the modmul under-reduction bug hid), which a bare RISC0==SP1 check passes green.
// ===================================================================

/// Prove `guest` on both backends and assert each journal equals `exp` AND each
/// other. Returns early only in explicit skip mode (ZKVM_ALLOW_SKIP=1); otherwise
/// the runners panic on a missing ELF/worker, so both results are always present.
fn cross_backend_check(guest: &str, input: &[u8], timeout: Duration, exp: &[u8]) {
    let risc0 = run_on_all_risc0(guest, input, timeout);
    let sp1 = run_on_sp1(guest, input, timeout);
    // RISC0 side: pin EVERY worker to the golden and to each other (skip-aware —
    // empty means skip). Runs even if SP1 is absent under ZKVM_ALLOW_SKIP=1, so a
    // wrong RISC0 journal is still caught in that asymmetric config.
    for (k, p) in &risc0 {
        assert_eq!(
            &p.journal[..],
            exp,
            "{guest}: RISC0 journal != golden expected on {k}"
        );
    }
    assert_cross_worker(&risc0, guest);
    // SP1 side (may be absent under ZKVM_ALLOW_SKIP=1).
    if let Some(s1) = sp1.as_ref() {
        assert_eq!(
            &s1.journal[..],
            exp,
            "{guest}: SP1 journal != golden expected"
        );
        if let Some(r0) = risc0.first() {
            assert_eq!(
                &r0.1.journal, &s1.journal,
                "{guest}: cross-backend RISC0 vs SP1 mismatch"
            );
        }
    }
}

#[test]
fn test_cross_backend_edge_case_arith() {
    let n = 50u32;
    cross_backend_check(
        "edge-case-arith",
        &make_input(&[n]),
        Duration::from_secs(600),
        &expected_edge_case_arith(n),
    );
}

#[test]
fn test_cross_backend_memory_stress_seq() {
    let size = 64u32;
    cross_backend_check(
        "memory-stress",
        &make_input(&[0, size]),
        Duration::from_secs(600),
        &expected_memory_stress_seq(size),
    );
}

#[test]
fn test_cross_backend_memory_stress_recurse() {
    let size = 500u32;
    cross_backend_check(
        "memory-stress",
        &make_input(&[2, size]),
        Duration::from_secs(600),
        &expected_memory_stress_recurse(size),
    );
}

#[test]
fn test_cross_backend_precompile_interleave() {
    let n = 50u32;
    cross_backend_check(
        "precompile-interleave",
        &make_input(&[n]),
        Duration::from_secs(1200),
        &expected_precompile_interleave(n),
    );
}

#[test]
fn test_cross_backend_minimal_proof() {
    cross_backend_check("minimal-proof", &[], Duration::from_secs(300), &[0x42u8]);
}

// ===================================================================
// Coverage for the 6 previously-untested dual-backend guests
// (fibonacci, sha256-chain, chacha-mix, bigint-mul, ecdsa-verify, memory-merkle).
// Each: host oracle + per-backend journal assert + cross-backend golden check.
// ===================================================================

/// Mirrors fibonacci guest: a=0,b=1; n wrapping_add iterations; commit u64 as 8 LE bytes.
fn expected_fibonacci(n: u32) -> Vec<u8> {
    let (mut a, mut b): (u64, u64) = (0, 1);
    for _ in 0..n {
        let c = a.wrapping_add(b);
        a = b;
        b = c;
    }
    a.to_le_bytes().to_vec()
}

/// Mirrors sha256-chain guest: hash=[0;32]; for i in 0..n hash=SHA256(hash||i_le); commit 32 bytes.
fn expected_sha256_chain(n: u32) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut hash = [0u8; 32];
    for i in 0..n {
        let mut h = Sha256::new();
        h.update(hash);
        h.update(i.to_le_bytes());
        hash = h.finalize().into();
    }
    hash.to_vec()
}

/// Mirrors chacha-mix guest: ChaCha20 ARX; per i set state[12]=i, run block; commit first 8 words LE.
fn expected_chacha_mix(n: u32) -> Vec<u8> {
    fn qr(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
        s[a] = s[a].wrapping_add(s[b]);
        s[d] ^= s[a];
        s[d] = s[d].rotate_left(16);
        s[c] = s[c].wrapping_add(s[d]);
        s[b] ^= s[c];
        s[b] = s[b].rotate_left(12);
        s[a] = s[a].wrapping_add(s[b]);
        s[d] ^= s[a];
        s[d] = s[d].rotate_left(8);
        s[c] = s[c].wrapping_add(s[d]);
        s[b] ^= s[c];
        s[b] = s[b].rotate_left(7);
    }
    fn block(s: &mut [u32; 16]) {
        for _ in 0..10 {
            qr(s, 0, 4, 8, 12);
            qr(s, 1, 5, 9, 13);
            qr(s, 2, 6, 10, 14);
            qr(s, 3, 7, 11, 15);
            qr(s, 0, 5, 10, 15);
            qr(s, 1, 6, 11, 12);
            qr(s, 2, 7, 8, 13);
            qr(s, 3, 4, 9, 14);
        }
    }
    let mut state: [u32; 16] = [
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
    for i in 0..n {
        state[12] = i;
        block(&mut state);
    }
    let mut out = [0u8; 32];
    for i in 0..8 {
        out[i * 4..i * 4 + 4].copy_from_slice(&state[i].to_le_bytes());
    }
    out.to_vec()
}

/// Mirrors bigint-mul guest: LCG-seeded 128-limb a,b; n schoolbook muls chaining lo->a hi->b; commit low 8 limbs of a.
fn expected_bigint_mul(n: u32) -> Vec<u8> {
    fn mul(a: &[u32; 128], b: &[u32; 128]) -> [u32; 256] {
        let mut r = [0u32; 256];
        for i in 0..128 {
            let mut carry: u64 = 0;
            for j in 0..128 {
                let p = (a[i] as u64) * (b[j] as u64) + (r[i + j] as u64) + carry;
                r[i + j] = p as u32;
                carry = p >> 32;
            }
            r[i + 128] = carry as u32;
        }
        r
    }
    fn seed(s: u32) -> [u32; 128] {
        let mut v = [0u32; 128];
        let mut st = s.wrapping_add(1);
        for limb in v.iter_mut() {
            st = st.wrapping_mul(1664525).wrapping_add(1013904223);
            *limb = st;
        }
        v
    }
    let (mut a, mut b) = (seed(0), seed(1));
    for _ in 0..n {
        let p = mul(&a, &b);
        a.copy_from_slice(&p[..128]);
        b.copy_from_slice(&p[128..]);
    }
    let mut out = [0u8; 32];
    for (i, limb) in a[..8].iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&limb.to_le_bytes());
    }
    out.to_vec()
}

/// Mirrors ecdsa-verify guest: verifies a self-produced (always-valid) signature n times,
/// commits count == n as 4 LE bytes. No k256 math needed host-side (outcome is unconditional).
fn expected_ecdsa_verify(n: u32) -> Vec<u8> {
    n.to_le_bytes().to_vec()
}

/// Mirrors memory-merkle guest: leaf[i]=SHA256(i_le); pad to next_pow2 by repeating the LAST
/// ORIGINAL leaf; fold bottom-up SHA256(l||r); commit 32-byte root ([0;32] if empty, leaf if 1).
fn expected_memory_merkle(num_leaves: u32) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    fn sha(parts: &[&[u8]]) -> [u8; 32] {
        let mut h = Sha256::new();
        for p in parts {
            h.update(p);
        }
        h.finalize().into()
    }
    let mut leaves: Vec<[u8; 32]> = (0..num_leaves).map(|i| sha(&[&i.to_le_bytes()])).collect();
    let root: [u8; 32] = if leaves.is_empty() {
        [0u8; 32]
    } else if leaves.len() == 1 {
        leaves[0]
    } else {
        let last = *leaves.last().unwrap();
        let n = leaves.len().next_power_of_two();
        while leaves.len() < n {
            leaves.push(last);
        }
        while leaves.len() > 1 {
            leaves = leaves.chunks(2).map(|c| sha(&[&c[0], &c[1]])).collect();
        }
        leaves[0]
    };
    root.to_vec()
}

#[test]
fn test_fibonacci_risc0() {
    let n = 1000u32;
    let r = run_on_all_risc0("fibonacci", &make_input(&[n]), Duration::from_secs(600));
    let exp = expected_fibonacci(n);
    for (k, p) in &r {
        assert_eq!(p.journal, exp, "fibonacci mismatch on {k}");
    }
    assert_cross_worker(&r, "fibonacci");
}
#[test]
fn test_fibonacci_sp1() {
    let n = 1000u32;
    if let Some(p) = run_on_sp1("fibonacci", &make_input(&[n]), Duration::from_secs(600)) {
        assert_eq!(p.journal, expected_fibonacci(n), "fibonacci SP1 mismatch");
    }
}
#[test]
fn test_cross_backend_fibonacci() {
    let n = 1000u32;
    cross_backend_check(
        "fibonacci",
        &make_input(&[n]),
        Duration::from_secs(600),
        &expected_fibonacci(n),
    );
}

#[test]
fn test_sha256_chain_risc0() {
    let n = 1000u32;
    let r = run_on_all_risc0("sha256-chain", &make_input(&[n]), Duration::from_secs(600));
    let exp = expected_sha256_chain(n);
    for (k, p) in &r {
        assert_eq!(p.journal, exp, "sha256-chain mismatch on {k}");
    }
    assert_cross_worker(&r, "sha256-chain");
}
#[test]
fn test_sha256_chain_sp1() {
    let n = 1000u32;
    if let Some(p) = run_on_sp1("sha256-chain", &make_input(&[n]), Duration::from_secs(600)) {
        assert_eq!(
            p.journal,
            expected_sha256_chain(n),
            "sha256-chain SP1 mismatch"
        );
    }
}
#[test]
fn test_cross_backend_sha256_chain() {
    let n = 1000u32;
    cross_backend_check(
        "sha256-chain",
        &make_input(&[n]),
        Duration::from_secs(600),
        &expected_sha256_chain(n),
    );
}

#[test]
fn test_chacha_mix_risc0() {
    let n = 1000u32;
    let r = run_on_all_risc0("chacha-mix", &make_input(&[n]), Duration::from_secs(600));
    let exp = expected_chacha_mix(n);
    for (k, p) in &r {
        assert_eq!(p.journal, exp, "chacha-mix mismatch on {k}");
    }
    assert_cross_worker(&r, "chacha-mix");
}
#[test]
fn test_chacha_mix_sp1() {
    let n = 1000u32;
    if let Some(p) = run_on_sp1("chacha-mix", &make_input(&[n]), Duration::from_secs(600)) {
        assert_eq!(p.journal, expected_chacha_mix(n), "chacha-mix SP1 mismatch");
    }
}
#[test]
fn test_cross_backend_chacha_mix() {
    let n = 1000u32;
    cross_backend_check(
        "chacha-mix",
        &make_input(&[n]),
        Duration::from_secs(600),
        &expected_chacha_mix(n),
    );
}

#[test]
fn test_bigint_mul_risc0() {
    let n = 64u32;
    let r = run_on_all_risc0("bigint-mul", &make_input(&[n]), Duration::from_secs(600));
    let exp = expected_bigint_mul(n);
    for (k, p) in &r {
        assert_eq!(p.journal, exp, "bigint-mul mismatch on {k}");
    }
    assert_cross_worker(&r, "bigint-mul");
}
#[test]
fn test_bigint_mul_sp1() {
    let n = 64u32;
    if let Some(p) = run_on_sp1("bigint-mul", &make_input(&[n]), Duration::from_secs(600)) {
        assert_eq!(p.journal, expected_bigint_mul(n), "bigint-mul SP1 mismatch");
    }
}
#[test]
fn test_cross_backend_bigint_mul() {
    let n = 64u32;
    cross_backend_check(
        "bigint-mul",
        &make_input(&[n]),
        Duration::from_secs(600),
        &expected_bigint_mul(n),
    );
}

#[test]
fn test_ecdsa_verify_risc0() {
    let n = 8u32;
    let r = run_on_all_risc0("ecdsa-verify", &make_input(&[n]), Duration::from_secs(600));
    let exp = expected_ecdsa_verify(n);
    for (k, p) in &r {
        assert_eq!(p.journal, exp, "ecdsa-verify mismatch on {k}");
    }
    assert_cross_worker(&r, "ecdsa-verify");
}
#[test]
fn test_ecdsa_verify_sp1() {
    let n = 8u32;
    if let Some(p) = run_on_sp1("ecdsa-verify", &make_input(&[n]), Duration::from_secs(600)) {
        assert_eq!(
            p.journal,
            expected_ecdsa_verify(n),
            "ecdsa-verify SP1 mismatch"
        );
    }
}
#[test]
fn test_cross_backend_ecdsa_verify() {
    let n = 8u32;
    cross_backend_check(
        "ecdsa-verify",
        &make_input(&[n]),
        Duration::from_secs(600),
        &expected_ecdsa_verify(n),
    );
}

#[test]
fn test_memory_merkle_risc0() {
    let num_leaves = 1000u32;
    let r = run_on_all_risc0(
        "memory-merkle",
        &make_input(&[num_leaves]),
        Duration::from_secs(600),
    );
    let exp = expected_memory_merkle(num_leaves);
    for (k, p) in &r {
        assert_eq!(p.journal, exp, "memory-merkle mismatch on {k}");
    }
    assert_cross_worker(&r, "memory-merkle");
}
#[test]
fn test_memory_merkle_sp1() {
    let num_leaves = 1000u32;
    if let Some(p) = run_on_sp1(
        "memory-merkle",
        &make_input(&[num_leaves]),
        Duration::from_secs(600),
    ) {
        assert_eq!(
            p.journal,
            expected_memory_merkle(num_leaves),
            "memory-merkle SP1 mismatch"
        );
    }
}
#[test]
fn test_cross_backend_memory_merkle() {
    let num_leaves = 1000u32;
    cross_backend_check(
        "memory-merkle",
        &make_input(&[num_leaves]),
        Duration::from_secs(600),
        &expected_memory_merkle(num_leaves),
    );
}

// ===================================================================
// Mega scale tests (ignored — too slow for CI)
// ===================================================================

#[test]
#[ignore]
fn test_precompile_interleave_mega_risc0() {
    let n = 20000u32;
    let r = run_on_all_risc0(
        "precompile-interleave",
        &make_input(&[n]),
        Duration::from_secs(7200),
    );
    let exp = expected_precompile_interleave(n);
    for (k, p) in &r {
        assert_eq!(p.journal, exp, "precompile-interleave mega mismatch on {k}");
    }
}

#[test]
#[ignore]
fn test_edge_case_arith_mega_risc0() {
    let n = 250000u32;
    let r = run_on_all_risc0(
        "edge-case-arith",
        &make_input(&[n]),
        Duration::from_secs(7200),
    );
    let exp = expected_edge_case_arith(n);
    for (k, p) in &r {
        assert_eq!(p.journal, exp, "edge-case-arith mega mismatch on {k}");
    }
}

#[test]
#[ignore]
fn test_memory_stress_mega_risc0() {
    let size = 50000u32;
    let r = run_on_all_risc0(
        "memory-stress",
        &make_input(&[0, size]),
        Duration::from_secs(7200),
    );
    let exp = expected_memory_stress_seq(size);
    for (k, p) in &r {
        assert_eq!(p.journal, exp, "memory-stress mega mismatch on {k}");
    }
}

#[test]
#[ignore]
fn test_babybear_stress_mega_risc0() {
    let iters = 100000u32;
    let r = run_on_all_risc0(
        "babybear-stress",
        &make_input(&[iters]),
        Duration::from_secs(7200),
    );
    let exp = expected_babybear_stress(iters);
    for (k, p) in &r {
        assert_eq!(p.journal, exp, "babybear-stress mega mismatch on {k}");
    }
}

#[test]
#[ignore]
fn test_segment_boundary_mega_risc0() {
    // Many commits to force multi-segment with syscalls at boundaries
    let r = run_on_all_risc0(
        "segment-boundary",
        &make_input(&[0, 200]),
        Duration::from_secs(7200),
    );
    let exp = expected_segment_boundary_multi_commit(200);
    for (k, p) in &r {
        assert_eq!(p.journal, exp, "segment-boundary mega mismatch on {k}");
    }
}
