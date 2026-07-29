//! Scaled arithmetic edge-case test.
//!
//! Runs many iterations of operations at the signed/unsigned boundary,
//! overflow/underflow edges, and shift extremes. Designed to generate
//! enough segments to surface bugs in cross-segment state stitching
//! (like the ROCm SHA-256 buffer reordering bug).

#![no_main]
#![no_std]

risc0_zkvm::entry!(main);

use core::hint::black_box;

/// Emit the RAW RISC-V div/rem instructions at the exact operands the main loop
/// short-circuits in software (div-by-0 and INT_MIN/-1), via inline asm, so the
/// zkVM circuit actually PROVES the edge behavior instead of the guest bypassing
/// it. RISC-V 32-bit spec: div/0 = -1, divu/0 = all-ones, rem/0 = dividend,
/// INT_MIN/-1: div = INT_MIN, rem = 0. (rv32 uses div/divu/rem/remu; rv64/SP1
/// uses the W-suffix forms for 32-bit semantics.) The committed fold equals the
/// same constants in the host oracle; a backend that mishandled these edges — or
/// trapped on div-by-0 — would fail the test.
macro_rules! raw_op {
    ($m:literal, $a:expr, $b:expr) => {{
        let (x, y): (u32, u32) = ($a, $b);
        let out: u32;
        unsafe {
            core::arch::asm!(concat!($m, " {o}, {x}, {y}"),
                o = out(reg) out, x = in(reg) x, y = in(reg) y,
                options(pure, nomem, nostack));
        }
        out
    }};
}

#[cfg(target_arch = "riscv32")]
fn div_rem_edges() -> u64 {
    let mut a: u64 = 0;
    a = a.wrapping_add(raw_op!("div",  1, 0) as u64);
    a = a.wrapping_add(raw_op!("divu", 1, 0) as u64);
    a = a.wrapping_add(raw_op!("rem",  1, 0) as u64);
    a = a.wrapping_add(raw_op!("remu", 1, 0) as u64);
    a = a.wrapping_add(raw_op!("div",  0x80000000, 0xFFFFFFFF) as u64);
    a = a.wrapping_add(raw_op!("rem",  0x80000000, 0xFFFFFFFF) as u64);
    a
}

#[cfg(target_arch = "riscv64")]
fn div_rem_edges() -> u64 {
    let mut a: u64 = 0;
    a = a.wrapping_add(raw_op!("divw",  1, 0) as u64);
    a = a.wrapping_add(raw_op!("divuw", 1, 0) as u64);
    a = a.wrapping_add(raw_op!("remw",  1, 0) as u64);
    a = a.wrapping_add(raw_op!("remuw", 1, 0) as u64);
    a = a.wrapping_add(raw_op!("divw",  0x80000000, 0xFFFFFFFF) as u64);
    a = a.wrapping_add(raw_op!("remw",  0x80000000, 0xFFFFFFFF) as u64);
    a
}

#[cfg(not(any(target_arch = "riscv32", target_arch = "riscv64")))]
fn div_rem_edges() -> u64 {
    0xFFFFFFFFu64 + 0xFFFFFFFFu64 + 1 + 1 + 0x80000000u64 + 0
}

fn main() {
    let n: u32 = risc0_zkvm::guest::env::read();
    let mut acc: u64 = 0xCAFE_BABE_DEAD_BEEFu64;

    for i in 0..n {
        let i = black_box(i);

        // Signed/unsigned boundary values
        let vals: [u32; 6] = [
            0,
            1,
            0x7FFFFFFF,
            0x80000000,
            0xFFFFFFFF,
            i.wrapping_mul(2654435761), // Knuth multiplicative hash scatter
        ];

        for &a in &vals {
            for &b in &vals {
                let a = black_box(a);
                let b = black_box(b);

                // Wrapping arithmetic chains
                let sum = a.wrapping_add(b);
                let diff = a.wrapping_sub(b);
                let prod = a.wrapping_mul(b);
                acc = acc.wrapping_mul(6364136223846793005)
                    .wrapping_add(sum as u64)
                    .wrapping_add(diff as u64)
                    .wrapping_add(prod as u64);

                // Signed vs unsigned comparison
                let scmp = if (a as i32) < (b as i32) { 1u32 } else { 0 };
                let ucmp = if a < b { 1u32 } else { 0 };
                acc = acc.wrapping_add(scmp as u64).wrapping_add(ucmp as u64);

                // Division edge cases (safe div)
                let div_result = if b == 0 {
                    0xFFFFFFFFu32
                } else if a == 0x80000000 && b == 0xFFFFFFFF {
                    0x80000000u32
                } else {
                    ((a as i32) / (b as i32)) as u32
                };
                acc = acc.wrapping_add(div_result as u64);

                // Remainder edge cases (safe rem)
                let rem_result = if b == 0 {
                    a // RISC-V REM: div-by-zero returns dividend
                } else if a == 0x80000000 && b == 0xFFFFFFFF {
                    0 // RISC-V REM: overflow returns 0
                } else {
                    ((a as i32).wrapping_rem(b as i32)) as u32
                };
                acc = acc.wrapping_add(rem_result as u64);

                // Unsigned division (DIVU)
                let divu_result = if b == 0 { 0xFFFFFFFFu32 } else { a / b };
                acc = acc.wrapping_add(divu_result as u64);

                // Unsigned remainder (REMU)
                let remu_result = if b == 0 { a } else { a % b };
                acc = acc.wrapping_add(remu_result as u64);

                // Widening multiply: MULH (signed x signed, upper 32)
                let mulh = ((a as i32 as i64).wrapping_mul(b as i32 as i64) >> 32) as u32;
                acc = acc.wrapping_add(mulh as u64);

                // MULHSU (signed x unsigned, upper 32)
                let mulhsu = ((a as i32 as i64).wrapping_mul(b as u64 as i64) >> 32) as u32;
                acc = acc.wrapping_add(mulhsu as u64);

                // MULHU (unsigned x unsigned, upper 32)
                let mulhu = ((a as u64).wrapping_mul(b as u64) >> 32) as u32;
                acc = acc.wrapping_add(mulhu as u64);
            }
        }

        // Explicit identity/overflow checks
        {
            let a = black_box(vals[4]); // 0xFFFFFFFF
            acc = acc.wrapping_add(a.wrapping_sub(a) as u64); // should be 0
            acc = acc.wrapping_add(0x7FFFFFFFu32.wrapping_add(black_box(1)) as u64); // overflow to 0x80000000
        }

        // Shift chains: left 1..31, then arithmetic right back
        let mut shifted = i.wrapping_add(1);
        for _shamt in 1..32u32 {
            shifted = black_box(shifted).wrapping_shl(1);
            acc = acc.wrapping_add(shifted as u64);
        }
        for _shamt in 1..32u32 {
            shifted = black_box((shifted as i32).wrapping_shr(1)) as u32;
            acc = acc.wrapping_add(shifted as u64);
        }
    }

    // Prove the raw div/rem edge-instruction behavior (see div_rem_edges).
    acc = acc.wrapping_add(div_rem_edges());

    risc0_zkvm::guest::env::commit_slice(&acc.to_le_bytes());
}
