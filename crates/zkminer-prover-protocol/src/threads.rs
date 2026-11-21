//! Windows: a worker's threads, closed to the other processes of its user.
//!
//! A thread's object takes its DACL from its process's token, which grants the token's user every
//! right, so any other process of the user's could open a worker's thread and change its context,
//! and so run code in the worker. The miner gives a worker's process and first thread descriptors
//! of their own before it runs (`windows_sandbox::spawn_worker` in `zkminer-prover`); the threads
//! the worker starts later are this module's: [`lock_threads`] narrows every thread running, and a
//! loader hook every thread started after, to what a process manager needs (see it, wait for it)
//! for whoever owns it, which is the worker's user. Another worker, at Low integrity or not, gets
//! no more; the worker itself works on its own threads through their handles and pseudo-handles,
//! which the DACL does not restrict.
//!
//! A token's default DACL cannot do this instead: whatever it grants the user on a thread it grants
//! on a process too, and `CreateProcess` fails unless its caller gets every right on the process it
//! creates, so a worker could no longer start one (its console host, SP1's `sp1-gpu-server`).
//!
//! A thread started between its creation and its first instruction (when the loader runs the
//! hook) still has the token's DACL; a process that opened it in that window keeps its handle. The
//! processes a worker starts, and their threads, keep the token's DACL.

use std::ffi::c_void;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::sync::atomic::{AtomicPtr, Ordering};

type Handle = *mut c_void;

const DACL_SECURITY_INFORMATION: u32 = 0x0000_0004;
const WRITE_DAC: u32 = 0x0004_0000;
const SDDL_REVISION_1: u32 = 1;

/// A worker's thread: everything for SYSTEM; for its owner, the worker's user, only
/// `SYNCHRONIZE | THREAD_QUERY_LIMITED_INFORMATION` (the `OWNER RIGHTS` entry also takes away the
/// owner's implicit `WRITE_DAC`). Protected, so nothing is inherited.
const THREAD_DACL: &str = "D:P(A;;GA;;;SY)(A;;0x100800;;;OW)";

#[repr(C)]
struct ThreadEntry32 {
    size: u32,
    usage: u32,
    thread_id: u32,
    owner_process_id: u32,
    base_priority: i32,
    delta_priority: i32,
    flags: u32,
}

#[link(name = "kernel32")]
extern "system" {
    fn GetCurrentProcessId() -> u32;
    fn GetCurrentThread() -> Handle;
    fn CreateToolhelp32Snapshot(flags: u32, pid: u32) -> Handle;
    fn Thread32First(snapshot: Handle, entry: *mut ThreadEntry32) -> i32;
    fn Thread32Next(snapshot: Handle, entry: *mut ThreadEntry32) -> i32;
    fn OpenThread(access: u32, inherit: i32, thread_id: u32) -> Handle;
}

#[link(name = "advapi32")]
extern "system" {
    fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
        sddl: *const u16,
        revision: u32,
        descriptor: *mut *mut c_void,
        size: *mut u32,
    ) -> i32;
    fn SetKernelObjectSecurity(handle: Handle, information: u32, descriptor: *mut c_void) -> i32;
}

/// The descriptor every thread of this process gets once [`lock_threads`] ran. Never freed: the
/// hook below reads it from any thread.
static DESCRIPTOR: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());

/// Run by the loader on every thread this process starts, on that thread, before its own code.
/// Only `SetKernelObjectSecurity`, which loads nothing: it runs under the loader lock.
unsafe extern "system" fn on_thread_attach(_module: *mut c_void, reason: u32, _: *mut c_void) {
    const DLL_THREAD_ATTACH: u32 = 2;
    if reason == DLL_THREAD_ATTACH {
        let descriptor = DESCRIPTOR.load(Ordering::Acquire);
        if !descriptor.is_null() {
            // SAFETY: the pseudo-handle of the calling thread and a descriptor that is never freed.
            unsafe {
                SetKernelObjectSecurity(GetCurrentThread(), DACL_SECURITY_INFORMATION, descriptor)
            };
        }
    }
}

/// The TLS callback table entry for [`on_thread_attach`] (`.CRT$XL*`, between the CRT's own `XLA`
/// and `XLZ`, as std's is).
#[used]
#[link_section = ".CRT$XLC"]
static ON_THREAD_ATTACH: unsafe extern "system" fn(*mut c_void, u32, *mut c_void) =
    on_thread_attach;

/// Close this process's threads, those running and those it starts from now on, as the module
/// docs say. For a worker's `main`, first thing.
pub fn lock_threads() -> io::Result<()> {
    if !DESCRIPTOR.load(Ordering::Acquire).is_null() {
        return Ok(());
    }
    let text: Vec<u16> = std::ffi::OsStr::new(THREAD_DACL)
        .encode_wide()
        .chain([0])
        .collect();
    let mut descriptor = std::ptr::null_mut();
    // SAFETY: a NUL-terminated string and an out-pointer; the descriptor is kept for the life of
    // the process.
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            text.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            std::ptr::null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    // The threads started from now on lock themselves, then the ones running now are locked.
    DESCRIPTOR.store(descriptor, Ordering::Release);
    // Referenced, so the linker keeps the TLS callback (as std does for its own).
    // SAFETY: a plain read of a static.
    let _ = unsafe { std::ptr::from_ref(&ON_THREAD_ATTACH).read_volatile() };
    lock_running_threads(descriptor)
}

/// Locks every thread of this process running now. A thread that ended in the meantime is skipped.
fn lock_running_threads(descriptor: *mut c_void) -> io::Result<()> {
    const TH32CS_SNAPTHREAD: u32 = 0x0000_0004;
    // SAFETY: plain kernel32 calls on a snapshot this function owns; `entry` outlives each call.
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if snapshot as isize == -1 {
            return Err(io::Error::last_os_error());
        }
        let snapshot = OwnedHandle::from_raw_handle(snapshot);
        let me = GetCurrentProcessId();
        let mut entry: ThreadEntry32 = std::mem::zeroed();
        entry.size = std::mem::size_of::<ThreadEntry32>() as u32;
        let mut more = Thread32First(snapshot.as_raw_handle(), &mut entry) != 0;
        let mut failed = None;
        while more {
            if entry.owner_process_id == me {
                let thread = OpenThread(WRITE_DAC, 0, entry.thread_id);
                if !thread.is_null() {
                    let thread = OwnedHandle::from_raw_handle(thread);
                    if SetKernelObjectSecurity(
                        thread.as_raw_handle(),
                        DACL_SECURITY_INFORMATION,
                        descriptor,
                    ) == 0
                    {
                        failed = Some(io::Error::last_os_error());
                    }
                }
            }
            more = Thread32Next(snapshot.as_raw_handle(), &mut entry) != 0;
        }
        failed.map_or(Ok(()), Err)
    }
}
