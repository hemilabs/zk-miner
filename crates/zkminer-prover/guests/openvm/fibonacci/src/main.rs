#![no_main]
#![no_std]

openvm::entry!(main);

fn main() {
    let n: u32 = openvm::io::read();
    let result = fibonacci(n);
    openvm::io::reveal_u32(result as u32, 0);
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
