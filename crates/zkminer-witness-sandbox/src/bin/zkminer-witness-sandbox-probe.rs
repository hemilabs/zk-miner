//! The sandbox self-test probe (plan §10.3): see `zkminer_witness_sandbox::probe`.

fn main() {
    std::process::exit(zkminer_witness_sandbox::probe::main());
}
