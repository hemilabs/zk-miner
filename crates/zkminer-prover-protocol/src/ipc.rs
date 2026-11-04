//! The worker's end of the IPC stream on Windows.

use std::io;
use std::os::windows::io::{AsHandle, AsRawHandle};

/// The real stdout, kept for IPC alone, with the process's stdout pointed at stderr.
///
/// Anything else printing to stdout would corrupt the bincode stream, and the dispatcher kills a
/// worker whose stream it cannot parse: circom-witnesscalc prints during risc0's Groth16 witness,
/// gnark's Go code may print, and `sp1-gpu-server`, a child, announces itself on the stdout it
/// inherits. Two stdouts are redirected: the OS standard handle, which Rust's `println!` writes
/// through and children inherit, and the C runtime's descriptor 1, which C and C++ `printf` use.
/// The handle returned is not inheritable, so no child holds the stream open either.
pub fn take_ipc_stdout() -> std::fs::File {
    #[link(name = "kernel32")]
    extern "system" {
        fn SetStdHandle(std_handle: u32, handle: *mut std::ffi::c_void) -> i32;
    }
    extern "C" {
        fn _dup2(from: i32, to: i32) -> i32;
    }
    const STD_OUTPUT_HANDLE: u32 = -11i32 as u32;

    // A duplicate, because `_dup2` below closes descriptor 1 and with it the original handle.
    let ipc = io::stdout()
        .as_handle()
        .try_clone_to_owned()
        .expect("failed to duplicate stdout for IPC");
    unsafe {
        SetStdHandle(STD_OUTPUT_HANDLE, io::stderr().as_raw_handle());
        _dup2(2, 1);
    }
    std::fs::File::from(ipc)
}
