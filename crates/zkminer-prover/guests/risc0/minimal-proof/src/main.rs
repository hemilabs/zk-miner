//! Minimal proof guest.
//!
//! The absolute minimum program: reads nothing, commits one byte.
//! Tests the edge case of a single segment with almost all padding rows.
//! If the STARK prover has bugs for very short programs, or the Groth16
//! wrapping assumes a minimum segment count, this catches it.

#![no_main]
#![no_std]

risc0_zkvm::entry!(main);

fn main() {
    risc0_zkvm::guest::env::commit_slice(&[0x42u8]);
}
