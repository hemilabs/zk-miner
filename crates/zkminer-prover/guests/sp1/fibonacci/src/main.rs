/// SP1 guest program: compute fibonacci(n) and commit the result.
fn main() {
    let n = sp1_zkvm::io::read::<u32>();
    let result = fibonacci(n);
    sp1_zkvm::io::commit(&result);
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
