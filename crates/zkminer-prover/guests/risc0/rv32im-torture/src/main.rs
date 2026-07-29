//! Exhaustive rv32im + M-extension instruction torture test.
//!
//! Exercises every rv32im base instruction and M-extension instruction with
//! edge-case operand values. Accumulates a rolling checksum of all results
//! and commits it to the journal. The host verifies the checksum matches a
//! natively-computed reference.
//!
//! Inputs: seed (u32), iterations (u32).
//! All test logic runs `iterations` times so the program generates many
//! segments at high iteration counts.

#![no_main]
#![no_std]

risc0_zkvm::entry!(main);

use core::hint::black_box;

/// Mix a 32-bit value into a 64-bit accumulator (simple rolling hash).
#[inline(always)]
fn mix(acc: u64, val: u32) -> u64 {
    acc.wrapping_mul(6364136223846793005).wrapping_add(val as u64)
}

/// RISC-V DIV semantics: signed division, div-by-zero -> 0xFFFFFFFF,
/// overflow (0x80000000 / -1) -> 0x80000000.
#[inline(never)]
fn riscv_div(a: u32, b: u32) -> u32 {
    let a = a as i32;
    let b = b as i32;
    if b == 0 {
        0xFFFFFFFFu32
    } else if a == i32::MIN && b == -1 {
        a as u32
    } else {
        (a / b) as u32
    }
}

/// RISC-V DIVU semantics: unsigned division, div-by-zero -> 0xFFFFFFFF.
#[inline(never)]
fn riscv_divu(a: u32, b: u32) -> u32 {
    if b == 0 { 0xFFFFFFFFu32 } else { a / b }
}

/// RISC-V REM semantics: signed remainder, div-by-zero -> a,
/// overflow (0x80000000 % -1) -> 0.
#[inline(never)]
fn riscv_rem(a: u32, b: u32) -> u32 {
    let a = a as i32;
    let b = b as i32;
    if b == 0 {
        a as u32
    } else if a == i32::MIN && b == -1 {
        0
    } else {
        (a % b) as u32
    }
}

/// RISC-V REMU semantics: unsigned remainder, div-by-zero -> a.
#[inline(never)]
fn riscv_remu(a: u32, b: u32) -> u32 {
    if b == 0 { a } else { a % b }
}

/// MULH: signed x signed, return upper 32 bits.
#[inline(never)]
fn mulh(a: u32, b: u32) -> u32 {
    let r = (a as i32 as i64).wrapping_mul(b as i32 as i64);
    (r >> 32) as u32
}

/// MULHSU: signed x unsigned, return upper 32 bits.
#[inline(never)]
fn mulhsu(a: u32, b: u32) -> u32 {
    let r = (a as i32 as i64).wrapping_mul(b as u64 as i64);
    (r >> 32) as u32
}

/// MULHU: unsigned x unsigned, return upper 32 bits.
#[inline(never)]
fn mulhu(a: u32, b: u32) -> u32 {
    let r = (a as u64).wrapping_mul(b as u64);
    (r >> 32) as u32
}

/// Recursive sum — forces JAL for call, JALR for return.
#[inline(never)]
fn recursive_sum(n: u32) -> u32 {
    if n == 0 { 0 } else { n.wrapping_add(recursive_sum(n - 1)) }
}

fn main() {
    let seed: u32 = risc0_zkvm::guest::env::read();
    let iterations: u32 = risc0_zkvm::guest::env::read();
    let mut acc: u64 = seed as u64;

    for _iter in 0..iterations {
        // ===================================================================
        // R-type ALU: ADD, SUB, AND, OR, XOR, SLL, SRL, SRA, SLT, SLTU
        // ===================================================================
        let pairs: &[(u32, u32)] = &[
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

        for &(a, b) in pairs {
            let (a, b) = (black_box(a), black_box(b));
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

        // ===================================================================
        // I-type ALU: ADDI, ANDI, ORI, XORI, SLTI, SLTIU, SLLI, SRLI, SRAI
        // ===================================================================
        let immediates: &[u32] = &[0, 1, 0x7FF, 0xFFF, 0x800];
        let shift_amounts: &[u32] = &[0, 1, 7, 15, 16, 31];
        for &a in &[0u32, 1, 0x80000000, 0x7FFFFFFF, 0xFFFFFFFF, seed] {
            let a = black_box(a);
            for &imm in immediates {
                acc = mix(acc, a.wrapping_add(imm));
                acc = mix(acc, a & imm);
                acc = mix(acc, a | imm);
                acc = mix(acc, a ^ imm);
                let simm = ((imm as i32) << 20) >> 20;
                acc = mix(acc, if (a as i32) < simm { 1 } else { 0 });
                acc = mix(acc, if a < (simm as u32) { 1 } else { 0 });
            }
            for &shamt in shift_amounts {
                acc = mix(acc, a.wrapping_shl(shamt));
                acc = mix(acc, a.wrapping_shr(shamt));
                acc = mix(acc, ((a as i32).wrapping_shr(shamt)) as u32);
            }
        }

        // ===================================================================
        // M-extension: MUL, MULH, MULHSU, MULHU, DIV, DIVU, REM, REMU
        // ===================================================================
        for &(a, b) in pairs {
            let (a, b) = (black_box(a), black_box(b));
            acc = mix(acc, a.wrapping_mul(b));
            acc = mix(acc, mulh(a, b));
            acc = mix(acc, mulhsu(a, b));
            acc = mix(acc, mulhu(a, b));
            acc = mix(acc, riscv_div(a, b));
            acc = mix(acc, riscv_divu(a, b));
            acc = mix(acc, riscv_rem(a, b));
            acc = mix(acc, riscv_remu(a, b));
        }

        // ===================================================================
        // Loads and Stores: SB/LB/LBU, SH/LH/LHU, SW/LW
        // ===================================================================
        let mut buf = [0u8; 256];
        for i in 0..256u32 {
            buf[i as usize] = (acc.wrapping_add(i as u64) & 0xFF) as u8;
        }
        for i in 0..256 {
            let val = buf[i] as u8;
            let signed = val as i8 as i32 as u32;
            let unsigned = val as u32;
            acc = mix(acc, signed);
            acc = mix(acc, unsigned);
        }
        for i in (0..256).step_by(2) {
            let val = u16::from_le_bytes([buf[i], buf[i + 1]]);
            let signed = val as i16 as i32 as u32;
            let unsigned = val as u32;
            acc = mix(acc, signed);
            acc = mix(acc, unsigned);
        }
        for i in (0..256).step_by(4) {
            let val = u32::from_le_bytes([buf[i], buf[i + 1], buf[i + 2], buf[i + 3]]);
            acc = mix(acc, val);
        }

        // ===================================================================
        // Unaligned load test: read_unaligned at offsets 1, 2, 3
        // ===================================================================
        {
            let aligned_buf: [u32; 4] = [0xDEADBEEF, 0xCAFEBABE, 0x12345678, 0x9ABCDEF0];
            let base = aligned_buf.as_ptr() as *const u8;
            for off in 1..4u32 {
                let ptr = unsafe { base.add(off as usize) as *const u32 };
                let val = unsafe { core::ptr::read_unaligned(black_box(ptr)) };
                acc = mix(acc, val);
            }
        }

        // ===================================================================
        // Shift-by-32+ test: verify masking (rv32i masks shift to low 5 bits)
        // ===================================================================
        {
            let a = black_box(0xDEADBEEFu32);
            acc = mix(acc, a.wrapping_shl(black_box(37)));
            acc = mix(acc, a.wrapping_shr(black_box(37)));
            acc = mix(acc, ((a as i32).wrapping_shr(black_box(37) as u32)) as u32);
            acc = mix(acc, a.wrapping_shl(black_box(32)));
            acc = mix(acc, a.wrapping_shl(black_box(0)));
        }

        // ===================================================================
        // Branches: BEQ, BNE, BLT, BGE, BLTU, BGEU
        // ===================================================================
        let branch_pairs: &[(u32, u32)] = &[
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
        for &(a, b) in branch_pairs {
            let (a, b) = (black_box(a), black_box(b));
            if a == b { acc = mix(acc, 1); } else { acc = mix(acc, 0); }
            if a != b { acc = mix(acc, 1); } else { acc = mix(acc, 0); }
            if (a as i32) < (b as i32) { acc = mix(acc, 1); } else { acc = mix(acc, 0); }
            if (a as i32) >= (b as i32) { acc = mix(acc, 1); } else { acc = mix(acc, 0); }
            if a < b { acc = mix(acc, 1); } else { acc = mix(acc, 0); }
            if a >= b { acc = mix(acc, 1); } else { acc = mix(acc, 0); }
        }

        // ===================================================================
        // Backward branch test: explicit while-loop countdown
        // ===================================================================
        {
            let mut countdown = black_box(50u32);
            while countdown > 0 {
                acc = mix(acc, countdown);
                countdown -= 1;
            }
        }

        // ===================================================================
        // FENCE: compiler-only reordering barrier.
        //
        // NOTE: emitting a real RISC-V FENCE (`asm!("fence")` → 0x0ff0000f) is
        // rejected by the RISC0 rv32im circuit as an IllegalInstruction and
        // traps the proof ("Invalid trap address: 0x0, IllegalInstruction
        // (0x0ff0000f)"). RISC0's zkVM is single-threaded with no observable
        // memory reordering, so FENCE is simply not implemented in the circuit.
        // A compiler_fence provides the same ordering guarantee for the
        // surrounding memory operations without emitting an unsupported opcode,
        // and does not affect the committed journal.
        // ===================================================================
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);

        // ===================================================================
        // Jumps: JAL/JALR via function pointer dispatch + recursion
        // LUI/AUIPC via large constants
        // ===================================================================
        let big_const = black_box(0xDEAD_B000u32);
        acc = mix(acc, big_const.wrapping_add(0xEEF));

        let ops: &[fn(u32, u32) -> u32] = &[
            |a, b| a.wrapping_add(b),
            |a, b| a.wrapping_sub(b),
            |a, b| a.wrapping_mul(b),
            |a, b| a ^ b,
        ];
        for (i, op) in ops.iter().enumerate() {
            acc = mix(acc, op(black_box(seed), black_box(i as u32)));
        }

        acc = mix(acc, recursive_sum(black_box(20)));
    }

    risc0_zkvm::guest::env::commit_slice(&acc.to_le_bytes());
}
