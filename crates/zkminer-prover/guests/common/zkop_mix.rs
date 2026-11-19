// The zkOP/s workload. Both zkVMs' guests `include!` this one file, so a proof on either one does
// exactly the same work: that is what lets their timings share a unit, since their cycle counts
// cannot be compared (SP1 guests are 64-bit, RISC Zero's 32-bit).
//
// Deliberately free of hashing and big-number libraries, which the zkVMs accelerate with precompiles,
// and of the allocator, whose behaviour differs between them. Everything is explicitly 32-bit so the
// result is the same on both targets.

const MEM_WORDS: usize = 1 << 14;
const LIMBS: usize = 16;
const ARX_DOUBLE_ROUNDS: u32 = 40;
const BRANCH_STEPS: u32 = 256;
const MEMORY_STEPS: u32 = 256;

fn next(x: &mut u32) -> u32 {
    *x ^= *x << 13;
    *x ^= *x >> 17;
    *x ^= *x << 5;
    *x
}

fn quarter_round(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(16);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(12);
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(8);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(7);
}

/// Bit mixing: add, rotate, xor.
fn arx(state: &mut [u32; 16]) {
    for _ in 0..ARX_DOUBLE_ROUNDS {
        quarter_round(state, 0, 4, 8, 12);
        quarter_round(state, 1, 5, 9, 13);
        quarter_round(state, 2, 6, 10, 14);
        quarter_round(state, 3, 7, 11, 15);
        quarter_round(state, 0, 5, 10, 15);
        quarter_round(state, 1, 6, 11, 12);
        quarter_round(state, 2, 7, 8, 13);
        quarter_round(state, 3, 4, 9, 14);
    }
}

/// Integer multiplication: schoolbook product of two numbers drawn from memory.
fn multiply(mem: &[u32; MEM_WORDS], seed: u32) -> u32 {
    let mut product = [0u32; LIMBS * 2];
    let start = seed as usize & (MEM_WORDS - 1);
    for i in 0..LIMBS {
        let a = mem[(start + i) & (MEM_WORDS - 1)] as u64;
        let mut carry = 0u64;
        for j in 0..LIMBS {
            let b = mem[(start + LIMBS + j) & (MEM_WORDS - 1)] as u64;
            let wide = a * b + product[i + j] as u64 + carry;
            product[i + j] = wide as u32;
            carry = wide >> 32;
        }
        product[i + LIMBS] = carry as u32;
    }
    product.iter().fold(0, |acc, limb| acc.rotate_left(1) ^ limb)
}

/// Control flow: a branch per step that depends on the data, so it cannot be folded away.
fn branch(mut value: u32) -> u32 {
    let mut taken = 0u32;
    for _ in 0..BRANCH_STEPS {
        value = if value & 1 == 0 {
            value >> 1
        } else {
            taken = taken.wrapping_add(1);
            value.wrapping_mul(3).wrapping_add(1)
        };
        if value < 2 {
            value = taken.wrapping_add(0x9E37_79B9);
        }
    }
    value ^ taken
}

/// Memory: read-modify-write at pseudo-random addresses across the whole array.
fn touch_memory(mem: &mut [u32; MEM_WORDS], rng: &mut u32) -> u32 {
    let mut sum = 0u32;
    for _ in 0..MEMORY_STEPS {
        let r = next(rng);
        let slot = &mut mem[r as usize & (MEM_WORDS - 1)];
        sum = sum.wrapping_add(*slot);
        *slot = slot.rotate_left(r & 31) ^ sum;
    }
    sum
}

/// Runs the workload for `iterations` rounds. The result depends on every step, so none of the work
/// can be optimized out.
fn zkop_mix(iterations: u32) -> [u8; 32] {
    let mut rng = 0x9E37_79B9u32;
    let mut mem = [0u32; MEM_WORDS];
    for slot in mem.iter_mut() {
        *slot = next(&mut rng);
    }
    let mut state = [0u32; 16];
    for (i, word) in state.iter_mut().enumerate() {
        *word = mem[i];
    }

    let mut digest = [0u32; 8];
    for i in 0..iterations {
        arx(&mut state);
        let product = multiply(&mem, state[0]);
        let branched = branch(state[1] ^ product);
        let touched = touch_memory(&mut mem, &mut rng);

        let lane = i as usize & 7;
        digest[lane] = digest[lane].rotate_left(5) ^ product ^ branched ^ touched;
        state[2] ^= touched;
        state[3] ^= branched;
    }

    let mut bytes = [0u8; 32];
    for (i, word) in digest.iter().enumerate() {
        bytes[i * 4..(i + 1) * 4].copy_from_slice(&word.to_le_bytes());
    }
    bytes
}
