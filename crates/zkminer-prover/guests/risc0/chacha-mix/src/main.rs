#![no_main]
#![no_std]

risc0_zkvm::entry!(main);

/// ChaCha20 quarter-round: pure ARX (Add, Rotate, XOR) computation.
/// No precompiles, no external dependencies — measures raw CPU throughput.
#[inline(always)]
fn quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(16);

    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(12);

    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(8);

    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(7);
}

/// One full ChaCha20 block: 20 rounds (10 column rounds + 10 diagonal rounds).
#[inline(always)]
fn chacha20_block(state: &mut [u32; 16]) {
    for _ in 0..10 {
        // Column rounds
        quarter_round(state, 0, 4, 8, 12);
        quarter_round(state, 1, 5, 9, 13);
        quarter_round(state, 2, 6, 10, 14);
        quarter_round(state, 3, 7, 11, 15);
        // Diagonal rounds
        quarter_round(state, 0, 5, 10, 15);
        quarter_round(state, 1, 6, 11, 12);
        quarter_round(state, 2, 7, 8, 13);
        quarter_round(state, 3, 4, 9, 14);
    }
}

fn main() {
    let n: u32 = risc0_zkvm::guest::env::read();

    // Standard ChaCha20 initial constant "expand 32-byte k"
    let mut state: [u32; 16] = [
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
        0, 0, 0, 0,  // key words (start zeroed, evolve each iteration)
        0, 0, 0, 0,  // key words
        0, 0, 0, 0,  // counter + nonce
    ];

    for i in 0..n {
        // Feed iteration counter into the block counter position
        state[12] = i;
        chacha20_block(&mut state);
    }

    // Commit first 8 words as the digest (256 bits)
    let out: [u32; 8] = [
        state[0], state[1], state[2], state[3],
        state[4], state[5], state[6], state[7],
    ];
    risc0_zkvm::guest::env::commit_slice(&out);
}
