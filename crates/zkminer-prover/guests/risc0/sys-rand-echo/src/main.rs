//! `sys_rand` echo guest.
//!
//! Commits the first 32 bytes it draws from `sys_rand`. Its journal is the seed rule made visible: a
//! test can predict it from public data, and a measurement and a proof of it must agree byte for byte.

#![no_main]
#![no_std]

risc0_zkvm::entry!(main);

fn main() {
    let mut words = [0u32; 8];
    unsafe { risc0_zkvm_platform::syscall::sys_rand(words.as_mut_ptr(), words.len()) };
    risc0_zkvm::guest::env::commit_slice(&words);
}
