#![no_main]
#![no_std]

risc0_zkvm::entry!(main);

/// RISC Zero guest program: compute fibonacci(n) and commit the result.
fn main() {
    let n: u32 = risc0_zkvm::guest::env::read();
    let result = fibonacci(n);
    risc0_zkvm::guest::env::commit(&result);
}

fn fibonacci(n: u32) -> u64 {
    let mut a: u64 = 0;
    let mut b: u64 = 1;
    for _ in 0..n {
        let c = a.wrapping_add(b);
        a = b;
        b = c;
    }
    a
}
