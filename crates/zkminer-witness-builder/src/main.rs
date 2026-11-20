//! `zkminer-witness-builder`: runs one WASM witness builder inside the witness sandbox. See
//! [`zkminer_witness_builder::cli`] for the argv and fd contract.

use std::fs::File;
use std::io::Write;
use std::mem::ManuallyDrop;
use std::os::fd::FromRawFd;
use std::time::Instant;

use zkminer_witness::abi;
use zkminer_witness::ipc::{exit, BuilderSummary};
use zkminer_witness_builder::{main_with_fds, RunnerFds};
use zkminer_witness_sandbox::{restrict_self, Profile};

fn main() {
    // The wall clock starts here: compilation counts against it.
    let process_start = Instant::now();
    // First, while the process still has one thread and has read nothing untrusted. There is no way
    // to skip this.
    if let Err(e) = restrict_self(&Profile::BuilderRunner) {
        // SAFETY: fds 2 and 4 were placed by the miner; ManuallyDrop leaves them open for exit.
        let (mut log, mut summary) = unsafe {
            (ManuallyDrop::new(File::from_raw_fd(abi::fd::LOG)), ManuallyDrop::new(File::from_raw_fd(abi::fd::SUMMARY)))
        };
        let _ = writeln!(log, "[runner] sandbox: {e}");
        let _ = summary.write_all(&BuilderSummary { exit_code: exit::INTERNAL, ..Default::default() }.encode());
        std::process::exit(exit::INTERNAL);
    }
    let args: Vec<String> = std::env::args_os().skip(1).map(|a| a.to_string_lossy().into_owned()).collect();
    // SAFETY: the miner placed fds 2–7 and nothing else in this process owns them.
    let fds = unsafe { RunnerFds::from_standard_fds() };
    std::process::exit(main_with_fds(&args, fds, process_start));
}
