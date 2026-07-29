//! SP1 version of the rv32im instruction torture test.
//! Same logic as the RISC Zero version but uses sp1_zkvm::io for I/O.
//! Also includes rv64im-specific tests since SP1 compiles to riscv64im.
//!
//! Inputs: seed (u32), iterations (u32).

use core::hint::black_box;

fn mix(acc: u64, val: u32) -> u64 {
    acc.wrapping_mul(6364136223846793005).wrapping_add(val as u64)
}

#[inline(never)]
fn riscv_div(a: u32, b: u32) -> u32 {
    let a = a as i32; let b = b as i32;
    if b == 0 { 0xFFFFFFFF } else if a == i32::MIN && b == -1 { a as u32 } else { (a / b) as u32 }
}
#[inline(never)]
fn riscv_divu(a: u32, b: u32) -> u32 { if b == 0 { 0xFFFFFFFF } else { a / b } }
#[inline(never)]
fn riscv_rem(a: u32, b: u32) -> u32 {
    let a = a as i32; let b = b as i32;
    if b == 0 { a as u32 } else if a == i32::MIN && b == -1 { 0 } else { (a % b) as u32 }
}
#[inline(never)]
fn riscv_remu(a: u32, b: u32) -> u32 { if b == 0 { a } else { a % b } }
#[inline(never)]
fn mulh(a: u32, b: u32) -> u32 { ((a as i32 as i64).wrapping_mul(b as i32 as i64) >> 32) as u32 }
#[inline(never)]
fn mulhsu(a: u32, b: u32) -> u32 { ((a as i32 as i64).wrapping_mul(b as u64 as i64) >> 32) as u32 }
#[inline(never)]
fn mulhu(a: u32, b: u32) -> u32 { ((a as u64).wrapping_mul(b as u64) >> 32) as u32 }
#[inline(never)]
fn recursive_sum(n: u32) -> u32 { if n == 0 { 0 } else { n.wrapping_add(recursive_sum(n - 1)) } }

fn main() {
    // SP1 worker feeds all input as ONE element; read once and parse (a 2nd
    // io::read::<u32>() would halt the guest before commit). See zkminer-prove-sp1.
    let input = sp1_zkvm::io::read_vec();
    let seed = u32::from_le_bytes([input[0], input[1], input[2], input[3]]);
    let iterations = u32::from_le_bytes([input[4], input[5], input[6], input[7]]);
    let mut acc: u64 = seed as u64;

    for _iter in 0..iterations {
        let pairs: &[(u32, u32)] = &[
            (0, 0), (1, 0), (0, 1), (1, 1),
            (0xFFFFFFFF, 1), (1, 0xFFFFFFFF),
            (0x80000000, 0x7FFFFFFF), (0x7FFFFFFF, 0x80000000),
            (0x80000000, 0x80000000),
            (0x80000000, 0xFFFFFFFF), (0xFFFFFFFF, 0x80000000),
            (0xFFFFFFFF, 0xFFFFFFFF),
            (0xDEADBEEF, 0xCAFEBABE),
            (seed, seed.wrapping_add(1)),
            (seed.wrapping_mul(7), seed.wrapping_mul(13)),
        ];
        // R-type ALU
        for &(a, b) in pairs {
            let (a, b) = (black_box(a), black_box(b));
            acc = mix(acc, a.wrapping_add(b)); acc = mix(acc, a.wrapping_sub(b));
            acc = mix(acc, a & b); acc = mix(acc, a | b); acc = mix(acc, a ^ b);
            acc = mix(acc, a.wrapping_shl(b & 31)); acc = mix(acc, a.wrapping_shr(b & 31));
            acc = mix(acc, ((a as i32).wrapping_shr(b & 31)) as u32);
            acc = mix(acc, if (a as i32) < (b as i32) { 1 } else { 0 });
            acc = mix(acc, if a < b { 1 } else { 0 });
        }
        // I-type ALU
        let immediates: &[u32] = &[0, 1, 0x7FF, 0xFFF, 0x800];
        let shift_amounts: &[u32] = &[0, 1, 7, 15, 16, 31];
        for &a in &[0u32, 1, 0x80000000, 0x7FFFFFFF, 0xFFFFFFFF, seed] {
            let a = black_box(a);
            for &imm in immediates {
                acc = mix(acc, a.wrapping_add(imm)); acc = mix(acc, a & imm);
                acc = mix(acc, a | imm); acc = mix(acc, a ^ imm);
                let simm = ((imm as i32) << 20) >> 20;
                acc = mix(acc, if (a as i32) < simm { 1 } else { 0 });
                acc = mix(acc, if a < (simm as u32) { 1 } else { 0 });
            }
            for &shamt in shift_amounts {
                acc = mix(acc, a.wrapping_shl(shamt)); acc = mix(acc, a.wrapping_shr(shamt));
                acc = mix(acc, ((a as i32).wrapping_shr(shamt)) as u32);
            }
        }
        // M-extension
        for &(a, b) in pairs {
            let (a, b) = (black_box(a), black_box(b));
            acc = mix(acc, a.wrapping_mul(b)); acc = mix(acc, mulh(a, b));
            acc = mix(acc, mulhsu(a, b)); acc = mix(acc, mulhu(a, b));
            acc = mix(acc, riscv_div(a, b)); acc = mix(acc, riscv_divu(a, b));
            acc = mix(acc, riscv_rem(a, b)); acc = mix(acc, riscv_remu(a, b));
        }
        // Loads/Stores
        let mut buf = [0u8; 256];
        for i in 0..256u32 { buf[i as usize] = (acc.wrapping_add(i as u64) & 0xFF) as u8; }
        for i in 0..256 {
            acc = mix(acc, buf[i] as i8 as i32 as u32); acc = mix(acc, buf[i] as u32);
        }
        for i in (0..256).step_by(2) {
            let val = u16::from_le_bytes([buf[i], buf[i + 1]]);
            acc = mix(acc, val as i16 as i32 as u32); acc = mix(acc, val as u32);
        }
        for i in (0..256).step_by(4) {
            acc = mix(acc, u32::from_le_bytes([buf[i], buf[i+1], buf[i+2], buf[i+3]]));
        }
        // Unaligned load test
        {
            let aligned_buf: [u32; 4] = [0xDEADBEEF, 0xCAFEBABE, 0x12345678, 0x9ABCDEF0];
            let base = aligned_buf.as_ptr() as *const u8;
            for off in 1..4u32 {
                let ptr = unsafe { base.add(off as usize) as *const u32 };
                let val = unsafe { core::ptr::read_unaligned(black_box(ptr)) };
                acc = mix(acc, val);
            }
        }
        // Shift-by-32+ test
        {
            let a = black_box(0xDEADBEEFu32);
            acc = mix(acc, a.wrapping_shl(black_box(37)));
            acc = mix(acc, a.wrapping_shr(black_box(37)));
            acc = mix(acc, ((a as i32).wrapping_shr(black_box(37) as u32)) as u32);
            acc = mix(acc, a.wrapping_shl(black_box(32)));
            acc = mix(acc, a.wrapping_shl(black_box(0)));
        }
        // Branches
        let branch_pairs: &[(u32, u32)] = &[
            (0, 0), (1, 1), (0, 1), (1, 0), (0x7FFFFFFF, 0x80000000),
            (0x80000000, 0x7FFFFFFF), (0xFFFFFFFF, 0), (0, 0xFFFFFFFF),
            (seed, seed), (seed, seed.wrapping_add(1)),
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
        // Backward branch test
        {
            let mut countdown = black_box(50u32);
            while countdown > 0 {
                acc = mix(acc, countdown);
                countdown -= 1;
            }
        }
        // FENCE: compiler-only reordering barrier (journal-neutral), kept
        // consistent with the RISC0 twin which cannot emit a real FENCE
        // (RISC0 rv32im rejects 0x0ff0000f as IllegalInstruction).
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        // Jumps
        let big_const = black_box(0xDEAD_B000u32);
        acc = mix(acc, big_const.wrapping_add(0xEEF));
        let ops: &[fn(u32, u32) -> u32] = &[
            |a, b| a.wrapping_add(b), |a, b| a.wrapping_sub(b),
            |a, b| a.wrapping_mul(b), |a, b| a ^ b,
        ];
        for (i, op) in ops.iter().enumerate() {
            acc = mix(acc, op(black_box(seed), black_box(i as u32)));
        }
        acc = mix(acc, recursive_sum(black_box(20)));
    }

    // === rv64im-specific (SP1 compiles to riscv64im) ===
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
        let (a, b) = (black_box(a), black_box(b));
        // 64-bit ALU (ADD, SUB, MUL, AND, OR, XOR, SLL, SRL, SRA)
        acc64 = acc64.wrapping_add(a.wrapping_add(b));
        acc64 = acc64.wrapping_add(a.wrapping_sub(b));
        acc64 = acc64.wrapping_add(a.wrapping_mul(b));
        acc64 = acc64.wrapping_add(a & b);
        acc64 = acc64.wrapping_add(a | b);
        acc64 = acc64.wrapping_add(a ^ b);
        acc64 = acc64.wrapping_add(a.wrapping_shl((b & 63) as u32));
        acc64 = acc64.wrapping_add(a.wrapping_shr((b & 63) as u32));
        acc64 = acc64.wrapping_add(((a as i64).wrapping_shr((b & 63) as u32)) as u64);
        // 64-bit unsigned division/remainder
        let div_r = if b == 0 { u64::MAX } else { a / b };
        let rem_r = if b == 0 { a } else { a % b };
        acc64 = acc64.wrapping_add(div_r);
        acc64 = acc64.wrapping_add(rem_r);
        // 64-bit signed division/remainder (DIVW/REMW semantics at 64-bit width)
        let sdiv_r = if b == 0 {
            u64::MAX
        } else if a as i64 == i64::MIN && b as i64 == -1 {
            a // overflow: return dividend
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
        // Signed 64-bit comparison
        acc64 = acc64.wrapping_add(if (a as i64) < (b as i64) { 1 } else { 0 });
        acc64 = acc64.wrapping_add(if a < b { 1 } else { 0 });
    }

    // === W-suffix instructions (RV64I: ADDW, SUBW, SLLW, SRLW, SRAW) ===
    // These operate on the lower 32 bits and sign-extend the result to 64 bits.
    let pairs32: &[(u32, u32)] = &[
        (0, 0), (1, 0), (0, 1), (1, 1),
        (0xFFFFFFFF, 1), (1, 0xFFFFFFFF),
        (0x80000000, 0x7FFFFFFF), (0x7FFFFFFF, 0x80000000),
        (0x80000000, 0xFFFFFFFF), (0xFFFFFFFF, 0xFFFFFFFF),
        (seed, seed.wrapping_add(1)),
    ];
    for &(a, b) in pairs32 {
        let (a, b) = (black_box(a), black_box(b));
        // ADDW: add lower 32, sign-extend
        let addw = ((a.wrapping_add(b)) as i32) as i64 as u64;
        acc64 = acc64.wrapping_add(addw);
        // SUBW: subtract lower 32, sign-extend
        let subw = ((a.wrapping_sub(b)) as i32) as i64 as u64;
        acc64 = acc64.wrapping_add(subw);
        // SLLW: shift left lower 32, sign-extend (shift amount from low 5 bits of b)
        let sllw = ((a.wrapping_shl(b & 31)) as i32) as i64 as u64;
        acc64 = acc64.wrapping_add(sllw);
        // SRLW: logical right shift lower 32, sign-extend
        let srlw = ((a.wrapping_shr(b & 31)) as i32) as i64 as u64;
        acc64 = acc64.wrapping_add(srlw);
        // SRAW: arithmetic right shift lower 32, sign-extend
        let sraw = (((a as i32).wrapping_shr(b & 31)) as i64) as u64;
        acc64 = acc64.wrapping_add(sraw);
    }

    // RV64I immediate W-suffix: ADDIW, SLLIW, SRLIW, SRAIW
    for &a in &[0u32, 1, 0x80000000, 0x7FFFFFFF, 0xFFFFFFFF, seed] {
        let a = black_box(a);
        for &imm in &[0u32, 1, 0x7FF, 0xFFF, 0x800] {
            let addiw = ((a.wrapping_add(imm)) as i32) as i64 as u64;
            acc64 = acc64.wrapping_add(addiw);
        }
        for &sh in &[0u32, 1, 7, 15, 16, 31] {
            let slliw = ((a.wrapping_shl(sh)) as i32) as i64 as u64;
            acc64 = acc64.wrapping_add(slliw);
            let srliw = ((a.wrapping_shr(sh)) as i32) as i64 as u64;
            acc64 = acc64.wrapping_add(srliw);
            let sraiw = (((a as i32).wrapping_shr(sh)) as i64) as u64;
            acc64 = acc64.wrapping_add(sraiw);
        }
    }

    // RV64M W-suffix: MULW, DIVW, DIVUW, REMW, REMUW
    for &(a, b) in pairs32 {
        let (a, b) = (black_box(a), black_box(b));
        // MULW: multiply lower 32, sign-extend
        let mulw = ((a.wrapping_mul(b)) as i32) as i64 as u64;
        acc64 = acc64.wrapping_add(mulw);
        // DIVW: signed div on lower 32, sign-extend
        let divw = if b == 0 {
            u64::MAX
        } else if a as i32 == i32::MIN && b as i32 == -1 {
            (a as i32 as i64) as u64
        } else {
            (((a as i32) / (b as i32)) as i64) as u64
        };
        acc64 = acc64.wrapping_add(divw);
        // DIVUW: unsigned div on lower 32, sign-extend
        let divuw = if b == 0 {
            u64::MAX
        } else {
            ((a / b) as i32 as i64) as u64
        };
        acc64 = acc64.wrapping_add(divuw);
        // REMW: signed rem on lower 32, sign-extend
        let remw = if b == 0 {
            (a as i32 as i64) as u64
        } else if a as i32 == i32::MIN && b as i32 == -1 {
            0u64
        } else {
            (((a as i32) % (b as i32)) as i64) as u64
        };
        acc64 = acc64.wrapping_add(remw);
        // REMUW: unsigned rem on lower 32, sign-extend
        let remuw = if b == 0 {
            (a as i32 as i64) as u64
        } else {
            ((a % b) as i32 as i64) as u64
        };
        acc64 = acc64.wrapping_add(remuw);
    }

    // LD/SD test: store and load 64-bit values at various alignments
    {
        let mut buf64 = [0u64; 8];
        for i in 0..8usize {
            buf64[i] = black_box((seed as u64).wrapping_mul(i as u64 + 1).wrapping_add(0xCAFE));
        }
        for i in 0..8usize {
            acc64 = acc64.wrapping_add(buf64[i]);
        }
    }

    // Mix acc64 into the main acc
    acc = mix(acc, (acc64 & 0xFFFFFFFF) as u32);
    acc = mix(acc, (acc64 >> 32) as u32);

    sp1_zkvm::io::commit_slice(&acc.to_le_bytes());
}
