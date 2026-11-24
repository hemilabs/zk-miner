//! What happens when the miner crashes on Windows.
//!
//! The miner's process is locked down (`windows_sandbox::lock_down_this_process`): no other process
//! of its user may open it to read its memory. Windows Error Reporting is such a process, so a
//! crash (an access violation on any thread) did not end the miner: WER could not open it, the
//! faulting thread stayed stuck in the fault forever, and the rest of the miner ran on, perhaps
//! deadlocked on what that thread held. A service manager saw a live process and restarted nothing,
//! the job object kept the workers alive, held locks ran to their deadlines, and nothing was
//! recorded anywhere.
//!
//! So [`install`], first thing in `main`:
//! - sets an unhandled-exception filter that writes one line to `~/.zkminer/crashes/crash.log` (and
//!   stderr): the exception code, the faulting address, the module it is in with its offset (or
//!   `<unloaded>`, the signature of a library unloaded under its own callbacks), the thread, and for
//!   an access violation the address accessed. It then ends the process with the exception code as
//!   its exit code, which a service manager sees and restarts on. Nothing on that path allocates or
//!   takes a lock of the miner's: the file is opened and everything else prepared at start-up;
//! - stops Windows from showing an error dialog for this process and its children;
//! - joins the miner's job, which ends a process on an unhandled exception if a library replaced the
//!   filter (`windows_job::join_early`);
//! - starts a thread that ends the process a while after a crash began if the filter itself got
//!   stuck (in the loader's lock, say, which looking up the module takes).
//!
//! No dump is written unless `ZKMINER_CRASH_DUMP=1`: the miner holds the decrypted signing key, and
//! even a minimal dump holds the threads' stacks, where key bytes may be during signing. When asked
//! for, it is minimal (`MiniDumpNormal`: stacks, threads, modules, unloaded modules; no heap, no data
//! sections), written through `MiniDumpWriteDump` from System32's `dbghelp.dll`, loaded at start-up.
//! The directory is labelled so Low-integrity processes (the workers) cannot read what is written in
//! it. WER is never given access: its report would read the whole address space, key included.
//!
//! The next `run` reports what was recorded since the last one ([`take_previous_crashes`]).

use std::ffi::c_void;
use std::os::windows::io::{AsRawHandle, IntoRawHandle};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicIsize, AtomicU32, AtomicUsize, Ordering};
use std::sync::OnceLock;

/// The environment variable that asks for a minidump of a crash, beside its line.
pub const CRASH_DUMP_ENV: &str = "ZKMINER_CRASH_DUMP";

const SEM_FAILCRITICALERRORS: u32 = 0x0001;
const SEM_NOGPFAULTERRORBOX: u32 = 0x0002;
const EXCEPTION_ACCESS_VIOLATION: u32 = 0xC000_0005;
const EXCEPTION_CONTINUE_SEARCH: i32 = 0;
const INFINITE: u32 = 0xFFFF_FFFF;
const STD_ERROR_HANDLE: u32 = -12i32 as u32;
const LOAD_LIBRARY_SEARCH_SYSTEM32: u32 = 0x0000_0800;
const GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT: u32 = 0x2;
const GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS: u32 = 0x4;
/// `FileDispositionInfo`, for `SetFileInformationByHandle`.
const FILE_DISPOSITION_INFO_CLASS: i32 = 4;
const DELETE: u32 = 0x0001_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
/// `MiniDumpNormal` (0) `| MiniDumpWithUnloadedModules | MiniDumpWithThreadInfo`.
const DUMP_TYPE: u32 = 0x0000_0020 | 0x0000_1000;
/// How long after a crash began the watchdog ends the process, if the filter has not: without a
/// dump, and with one.
const STUCK_MS: u32 = 10_000;
const STUCK_DUMP_MS: u32 = 120_000;

#[repr(C)]
struct ExceptionRecord {
    code: u32,
    flags: u32,
    record: *mut ExceptionRecord,
    address: *mut c_void,
    number_parameters: u32,
    information: [usize; 15],
}

#[repr(C)]
struct ExceptionPointers {
    record: *const ExceptionRecord,
    context: *mut c_void,
}

/// `MINIDUMP_EXCEPTION_INFORMATION`, which `minidumpapiset.h` packs to 4.
#[repr(C, packed(4))]
struct MinidumpExceptionInformation {
    thread_id: u32,
    exception_pointers: *const ExceptionPointers,
    client_pointers: i32,
}

type Filter = unsafe extern "system" fn(*const ExceptionPointers) -> i32;
type MiniDumpWriteDump = unsafe extern "system" fn(
    process: *mut c_void,
    pid: u32,
    file: isize,
    dump_type: u32,
    exception: *const MinidumpExceptionInformation,
    user_streams: *const c_void,
    callback: *const c_void,
) -> i32;

#[link(name = "kernel32")]
extern "system" {
    fn SetUnhandledExceptionFilter(filter: Option<Filter>) -> Option<Filter>;
    fn GetErrorMode() -> u32;
    fn SetErrorMode(mode: u32) -> u32;
    fn GetCurrentProcess() -> *mut c_void;
    fn GetCurrentProcessId() -> u32;
    fn GetCurrentThreadId() -> u32;
    fn TerminateProcess(process: *mut c_void, code: u32) -> i32;
    fn WriteFile(
        file: isize,
        buffer: *const u8,
        length: u32,
        written: *mut u32,
        overlapped: *mut c_void,
    ) -> i32;
    fn GetStdHandle(which: u32) -> isize;
    fn GetModuleHandleExW(flags: u32, name: *const u16, module: *mut isize) -> i32;
    fn GetModuleFileNameW(module: isize, name: *mut u16, size: u32) -> u32;
    fn GetSystemTimeAsFileTime(time: *mut u64);
    fn CreateEventW(attributes: *mut c_void, manual: i32, initial: i32, name: *const u16) -> isize;
    fn SetEvent(event: isize) -> i32;
    fn WaitForSingleObject(handle: *mut c_void, ms: u32) -> u32;
    fn Sleep(ms: u32);
    fn LoadLibraryExW(name: *const u16, file: isize, flags: u32) -> isize;
    fn GetProcAddress(module: isize, name: *const u8) -> *mut c_void;
    fn SetFileInformationByHandle(file: isize, class: i32, info: *const c_void, size: u32) -> i32;
}

/// `crash.log`, opened for appending at start-up; 0 if it could not be.
static LOG: AtomicIsize = AtomicIsize::new(0);
/// The dump file prepared at start-up (deleted when the process ends unless a crash keeps it); 0
/// if no dump was asked for or it could not be prepared.
static DUMP_FILE: AtomicIsize = AtomicIsize::new(0);
/// `MiniDumpWriteDump`, resolved at start-up when a dump was asked for; 0 otherwise.
static DUMP_WRITER: AtomicUsize = AtomicUsize::new(0);
/// The event the watchdog waits on; 0 without a watchdog.
static CRASHING: AtomicIsize = AtomicIsize::new(0);
/// The code of the exception being handled, which the watchdog exits with.
static CODE: AtomicU32 = AtomicU32::new(0);
/// The directory `crash.log` is in, once it was opened.
static DIR: OnceLock<PathBuf> = OnceLock::new();

/// `~/.zkminer/crashes`.
pub fn crash_dir() -> Option<PathBuf> {
    dirs::home_dir().map(|h| h.join(".zkminer").join("crashes"))
}

/// Set up crash handling for this process (see the module docs). For the miner's `main`, once and
/// first thing; every command, so a crash anywhere is recorded and ends the process. Reports what
/// it could not do on stderr (logging is not up yet) and carries on.
pub fn install() {
    install_in(crash_dir().as_deref());
}

fn install_in(dir: Option<&Path>) {
    // SAFETY: plain kernel32 calls on this process.
    unsafe { SetErrorMode(GetErrorMode() | SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS) };
    if let Some(dir) = dir {
        match open_log(dir) {
            Ok(log) => LOG.store(log, Ordering::Release),
            Err(e) => eprintln!(
                "warning: crashes will not be recorded in {} ({e})",
                dir.display()
            ),
        }
        if dump_asked() {
            if let Err(e) = prepare_dump(dir) {
                eprintln!("warning: {CRASH_DUMP_ENV} is set, but no dump can be written ({e})");
            }
        }
    }
    start_watchdog();
    // SAFETY: `on_crash` has the filter's signature and lives for the whole process.
    unsafe { SetUnhandledExceptionFilter(Some(on_crash)) };
    if let Err(e) = crate::windows_job::join_early() {
        eprintln!(
            "warning: the miner could not join its job ({e}): its workers will not end with it, \
             and a crash in a library that replaces the miner's crash handler may leave it hanging"
        );
    }
}

/// The lines recorded in `crash.log` since the last call that took them (in any run): one per
/// crash, for `run` to page. Taken, so each crash is reported once; other commands leave them for
/// `run`. `None` if there are none.
pub fn take_previous_crashes() -> Option<String> {
    let dir = DIR.get()?;
    unreported(&dir.join("crash.log"), &dir.join("crash.log.seen"))
}

fn dump_asked() -> bool {
    std::env::var(CRASH_DUMP_ENV).is_ok_and(|v| v.trim() == "1")
}

/// Labels `dir` and opens `crash.log` in it for appending: its raw handle.
fn open_log(dir: &Path) -> std::io::Result<isize> {
    crate::windows_sandbox::make_no_read_up_dir(dir)?;
    let file = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(dir.join("crash.log"))?;
    let _ = DIR.set(dir.to_path_buf());
    Ok(file.into_raw_handle() as isize)
}

/// What `log` holds past the length recorded in `seen` (its last 4 KiB at most), and records the
/// new length. `None` when nothing was added.
fn unreported(log: &Path, seen: &Path) -> Option<String> {
    const MAX: u64 = 4096;
    let len = std::fs::metadata(log).ok()?.len();
    let before = std::fs::read_to_string(seen)
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .filter(|&n| n <= len)
        .unwrap_or(0);
    if len == before {
        return None;
    }
    let _ = std::fs::write(seen, len.to_string());
    let bytes = std::fs::read(log).ok()?;
    let from = (before.max(len.saturating_sub(MAX)) as usize).min(bytes.len());
    let news = String::from_utf8_lossy(&bytes[from..]).trim().to_string();
    (!news.is_empty()).then_some(news)
}

/// Loads `dbghelp.dll` from System32, resolves `MiniDumpWriteDump`, and creates this process's dump
/// file in `dir`, marked to be deleted when it closes: a crash clears the mark before writing it.
fn prepare_dump(dir: &Path) -> std::io::Result<()> {
    use std::os::windows::fs::OpenOptionsExt;
    let name: Vec<u16> = "dbghelp.dll".encode_utf16().chain([0]).collect();
    // SAFETY: a NUL-terminated name; System32's own library.
    let dbghelp = unsafe { LoadLibraryExW(name.as_ptr(), 0, LOAD_LIBRARY_SEARCH_SYSTEM32) };
    if dbghelp == 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: a loaded module and a NUL-terminated export name.
    let writer = unsafe { GetProcAddress(dbghelp, b"MiniDumpWriteDump\0".as_ptr()) };
    if writer.is_null() {
        return Err(std::io::Error::last_os_error());
    }
    let mut stamp = 0u64;
    // SAFETY: a valid out pointer.
    unsafe { GetSystemTimeAsFileTime(&mut stamp) };
    let path = dir.join(format!(
        "miner-{}-{}.dmp",
        unix_secs(stamp),
        std::process::id()
    ));
    let file = std::fs::OpenOptions::new()
        .write(true)
        .access_mode(GENERIC_WRITE | DELETE)
        .share_mode(0)
        .create_new(true)
        .open(&path)?;
    if !set_delete_on_close(file.as_raw_handle() as isize, true) {
        let e = std::io::Error::last_os_error();
        drop(file);
        let _ = std::fs::remove_file(&path);
        return Err(e);
    }
    DUMP_FILE.store(file.into_raw_handle() as isize, Ordering::Release);
    DUMP_WRITER.store(writer as usize, Ordering::Release);
    Ok(())
}

fn set_delete_on_close(file: isize, delete: bool) -> bool {
    let info = u8::from(delete);
    // SAFETY: an open handle with DELETE access and a one-byte FILE_DISPOSITION_INFO.
    unsafe {
        SetFileInformationByHandle(
            file,
            FILE_DISPOSITION_INFO_CLASS,
            (&info as *const u8).cast(),
            1,
        ) != 0
    }
}

/// A thread that waits for a crash and, if the process has not ended [`STUCK_MS`] after it began
/// ([`STUCK_DUMP_MS`] with a dump), ends it with the exception's code.
fn start_watchdog() {
    // SAFETY: an unnamed manual-reset event, owned for the life of the process.
    let event = unsafe { CreateEventW(std::ptr::null_mut(), 1, 0, std::ptr::null()) };
    if event == 0 {
        return;
    }
    let spawned = std::thread::Builder::new()
        .name("crash-watchdog".into())
        .stack_size(64 * 1024)
        .spawn(move || {
            // SAFETY: a valid event handle, then plain kernel32 calls on this process.
            unsafe {
                WaitForSingleObject(event as *mut c_void, INFINITE);
                let dumping = DUMP_WRITER.load(Ordering::Acquire) != 0;
                Sleep(if dumping { STUCK_DUMP_MS } else { STUCK_MS });
                TerminateProcess(GetCurrentProcess(), CODE.load(Ordering::Acquire));
            }
        });
    if spawned.is_ok() {
        CRASHING.store(event, Ordering::Release);
    }
}

/// A line under construction on the stack: nothing on the crash path allocates.
struct Line {
    bytes: [u8; 1024],
    len: usize,
}

impl Line {
    fn push(&mut self, s: &[u8]) {
        let n = s.len().min(self.bytes.len() - self.len);
        self.bytes[self.len..self.len + n].copy_from_slice(&s[..n]);
        self.len += n;
    }

    fn hex(&mut self, mut n: u64) {
        let mut digits = [0u8; 16];
        let mut i = digits.len();
        loop {
            i -= 1;
            digits[i] = b"0123456789abcdef"[(n & 0xf) as usize];
            n >>= 4;
            if n == 0 {
                break;
            }
        }
        self.push(b"0x");
        self.push(&digits[i..]);
    }

    fn dec(&mut self, mut n: u64) {
        let mut digits = [0u8; 20];
        let mut i = digits.len();
        loop {
            i -= 1;
            digits[i] = b'0' + (n % 10) as u8;
            n /= 10;
            if n == 0 {
                break;
            }
        }
        self.push(&digits[i..]);
    }

    /// A UTF-16 path, as ASCII: anything else is written `?`.
    fn wide(&mut self, s: &[u16]) {
        for &c in s {
            let b = if (0x20..0x7f).contains(&c) {
                c as u8
            } else {
                b'?'
            };
            self.push(&[b]);
        }
    }

    fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

/// Seconds since 1970 of a FILETIME (100 ns since 1601).
fn unix_secs(filetime: u64) -> u64 {
    (filetime / 10_000_000).saturating_sub(11_644_473_600)
}

/// The line recorded for exception `code` at `address` on thread `tid` at `now` (a FILETIME), with
/// the module `module` (its path, with the offset of `address` in it; `None` when no loaded module
/// holds the address) and, for an access violation, `access` (`(0 read | 1 write | 8 execute,
/// address accessed)`).
fn format_line(
    line: &mut Line,
    now: u64,
    code: u32,
    address: usize,
    module: Option<(&[u16], usize)>,
    access: Option<(usize, usize)>,
    tid: u32,
    pid: u32,
) {
    line.dec(unix_secs(now));
    line.push(b" crash code=");
    line.hex(code.into());
    line.push(b" addr=");
    line.hex(address as u64);
    line.push(b" module=");
    match module {
        Some((path, offset)) => {
            line.wide(path);
            line.push(b"+");
            line.hex(offset as u64);
        }
        None => line.push(b"<unloaded>"),
    }
    if let Some((kind, target)) = access {
        line.push(match kind {
            0 => b" reading " as &[u8],
            1 => b" writing ",
            8 => b" executing ",
            _ => b" accessing ",
        });
        line.hex(target as u64);
    }
    line.push(b" tid=");
    line.dec(tid.into());
    line.push(b" pid=");
    line.dec(pid.into());
    line.push(b"\r\n");
}

fn write_all(file: isize, bytes: &[u8]) {
    if file == 0 || file == -1 {
        return;
    }
    let mut written = 0u32;
    // SAFETY: an open file handle and a buffer of `bytes.len()` bytes.
    unsafe {
        WriteFile(
            file,
            bytes.as_ptr(),
            bytes.len() as u32,
            &mut written,
            std::ptr::null_mut(),
        )
    };
}

/// The unhandled-exception filter: records the crash and ends the process with its code.
unsafe extern "system" fn on_crash(info: *const ExceptionPointers) -> i32 {
    // SAFETY (whole body): the system passes valid exception pointers; everything else is plain
    // kernel32 calls on handles prepared at start-up, and stack buffers.
    let record = match info.as_ref().and_then(|i| i.record.as_ref()) {
        Some(record) => record,
        None => return EXCEPTION_CONTINUE_SEARCH,
    };
    let code = record.code;
    CODE.store(code, Ordering::Release);
    let event = CRASHING.load(Ordering::Acquire);
    if event != 0 {
        SetEvent(event);
    }
    let address = record.address as usize;
    let access = (code == EXCEPTION_ACCESS_VIOLATION && record.number_parameters >= 2)
        .then(|| (record.information[0], record.information[1]));
    let mut now = 0u64;
    GetSystemTimeAsFileTime(&mut now);

    let mut path = [0u16; 512];
    let mut module = 0isize;
    let named = if GetModuleHandleExW(
        GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        address as *const u16,
        &mut module,
    ) != 0
    {
        let n = GetModuleFileNameW(module, path.as_mut_ptr(), path.len() as u32) as usize;
        Some((
            &path[..n.min(path.len())],
            address.wrapping_sub(module as usize),
        ))
    } else {
        None
    };
    let mut line = Line {
        bytes: [0; 1024],
        len: 0,
    };
    format_line(
        &mut line,
        now,
        code,
        address,
        named,
        access,
        GetCurrentThreadId(),
        GetCurrentProcessId(),
    );
    write_all(LOG.load(Ordering::Acquire), line.as_bytes());
    write_all(GetStdHandle(STD_ERROR_HANDLE), line.as_bytes());

    let writer = DUMP_WRITER.load(Ordering::Acquire);
    let file = DUMP_FILE.load(Ordering::Acquire);
    if writer != 0 && file != 0 && set_delete_on_close(file, false) {
        let write: MiniDumpWriteDump = std::mem::transmute::<usize, MiniDumpWriteDump>(writer);
        let exception = MinidumpExceptionInformation {
            thread_id: GetCurrentThreadId(),
            exception_pointers: info,
            client_pointers: 0,
        };
        write(
            GetCurrentProcess(),
            GetCurrentProcessId(),
            file,
            DUMP_TYPE,
            &exception,
            std::ptr::null(),
            std::ptr::null(),
        );
    }
    TerminateProcess(GetCurrentProcess(), code);
    EXCEPTION_CONTINUE_SEARCH
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    #[test]
    fn a_crash_line_names_the_code_address_module_and_access() {
        let path: Vec<u16> = "C:\\zk\\zkminer.exe".encode_utf16().collect();
        let mut line = Line {
            bytes: [0; 1024],
            len: 0,
        };
        // 2026-11-21 00:00:00 UTC as a FILETIME.
        let now = (1_795_219_200 + 11_644_473_600) * 10_000_000;
        format_line(
            &mut line,
            now,
            0xC000_0005,
            0x7ff6_1234_5678,
            Some((&path, 0x5678)),
            Some((0, 0x10)),
            42,
            7,
        );
        assert_eq!(
            std::str::from_utf8(line.as_bytes()).unwrap(),
            "1795219200 crash code=0xc0000005 addr=0x7ff612345678 module=C:\\zk\\zkminer.exe+0x5678 \
             reading 0x10 tid=42 pid=7\r\n"
        );
        let mut line = Line {
            bytes: [0; 1024],
            len: 0,
        };
        format_line(&mut line, now, 0xC000_001D, 0x1c40, None, None, 1, 2);
        assert!(std::str::from_utf8(line.as_bytes())
            .unwrap()
            .contains("code=0xc000001d addr=0x1c40 module=<unloaded> tid=1"));
        // A line never overruns its buffer.
        let long = vec![b'a' as u16; 4000];
        let mut line = Line {
            bytes: [0; 1024],
            len: 0,
        };
        format_line(&mut line, now, 1, 1, Some((&long, 1)), None, 1, 1);
        assert_eq!(line.len, 1024);
    }

    #[test]
    fn crashes_are_reported_once_at_the_next_start() {
        let dir = tempfile::tempdir().unwrap();
        let (log, seen) = (dir.path().join("crash.log"), dir.path().join("seen"));
        assert_eq!(unreported(&log, &seen), None);
        std::fs::write(&log, "1 crash code=0xc0000005\r\n").unwrap();
        assert_eq!(
            unreported(&log, &seen).as_deref(),
            Some("1 crash code=0xc0000005")
        );
        assert_eq!(unreported(&log, &seen), None, "reported twice");
        let mut both = std::fs::read(&log).unwrap();
        both.extend_from_slice(b"2 crash code=0xc000001d\r\n");
        std::fs::write(&log, both).unwrap();
        assert_eq!(
            unreported(&log, &seen).as_deref(),
            Some("2 crash code=0xc000001d")
        );
    }

    /// Run in a child test process, locked down as the miner is: it faults on a side thread (as a
    /// vendor library's thread-pool work did) and must exit at once with the exception's code, not
    /// hang. `mode` picks what the child sets up.
    fn crash_child(mode: &str, dir: &Path) -> (Option<i32>, std::time::Duration, String) {
        let dump = if mode.starts_with("dump") { "1" } else { "" };
        let start = std::time::Instant::now();
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "windows_crash::tests::a_locked_down_process_that_faults_exits_with_the_code",
                "--nocapture",
            ])
            .env("ZKMINER_CRASH_TEST_CHILD", mode)
            .env("ZKMINER_CRASH_TEST_DIR", dir)
            .env(CRASH_DUMP_ENV, dump)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = start + std::time::Duration::from_secs(20);
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break Some(status);
            }
            if std::time::Instant::now() > deadline {
                let _ = child.kill();
                break None;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        };
        let mut stderr = String::new();
        if let Some(mut e) = child.stderr.take() {
            use std::io::Read;
            let _ = e.read_to_string(&mut stderr);
        }
        (status.and_then(|s| s.code()), start.elapsed(), stderr)
    }

    #[test]
    fn a_locked_down_process_that_faults_exits_with_the_code() {
        if let Ok(mode) = std::env::var("ZKMINER_CRASH_TEST_CHILD") {
            // As a shell that does not pass SEM_NOGPFAULTERRORBOX on (PowerShell, a service
            // manager) would start it: Git Bash and some test runners do pass it, which hides the
            // hang.
            // SAFETY: a plain kernel32 call.
            unsafe { SetErrorMode(0) };
            crate::windows_sandbox::lock_down_this_process().unwrap();
            match mode.as_str() {
                "install" | "dump" | "dump-clean-exit" => {
                    let dir = PathBuf::from(std::env::var_os("ZKMINER_CRASH_TEST_DIR").unwrap());
                    install_in(Some(&dir));
                    if mode == "dump-clean-exit" {
                        std::process::exit(0);
                    }
                }
                // The job alone, as when a library replaced the filter.
                "job" => crate::windows_job::join_early().unwrap(),
                _ => {}
            }
            std::thread::spawn(|| {
                // SAFETY: none; the point is the access violation.
                unsafe { std::ptr::read_volatile(0x10 as *const u8) }
            })
            .join()
            .ok();
            std::thread::sleep(std::time::Duration::from_secs(60));
            std::process::exit(3);
        }
        let dir = tempfile::tempdir().unwrap();
        let crashes = dir.path().join("crashes");
        let (code, took, stderr) = crash_child("install", &crashes);
        assert_eq!(
            code,
            Some(EXCEPTION_ACCESS_VIOLATION as i32),
            "after {took:?}: {stderr}"
        );
        assert!(took < std::time::Duration::from_secs(15), "{took:?}");
        let log = std::fs::read_to_string(crashes.join("crash.log")).unwrap();
        assert!(log.contains("crash code=0xc0000005"), "{log}");
        assert!(log.contains(" reading 0x10 "), "{log}");
        assert!(log.contains(".exe+0x"), "{log}");
        assert!(stderr.contains("crash code=0xc0000005"), "{stderr}");
        // Low processes cannot read the record.
        assert!(crate::windows_sandbox::has_no_read_up_label(&crashes.join("crash.log")).unwrap());

        let (code, took, stderr) = crash_child("job", &crashes);
        assert_eq!(
            code,
            Some(EXCEPTION_ACCESS_VIOLATION as i32),
            "after {took:?}: {stderr}"
        );
        assert!(took < std::time::Duration::from_secs(15), "{took:?}");

        // A dump only when asked for, and only of a crash: a process that ends normally leaves none.
        let dumps = || {
            std::fs::read_dir(&crashes)
                .unwrap()
                .flatten()
                .filter(|e| e.path().extension().is_some_and(|x| x == "dmp"))
                .map(|e| e.metadata().unwrap().len())
                .collect::<Vec<u64>>()
        };
        assert!(dumps().is_empty(), "{:?}", dumps());
        let (code, _, stderr) = crash_child("dump-clean-exit", &crashes);
        assert_eq!(code, Some(0), "{stderr}");
        assert!(
            dumps().is_empty(),
            "a clean exit left a dump: {:?}",
            dumps()
        );
        let (code, took, stderr) = crash_child("dump", &crashes);
        assert_eq!(
            code,
            Some(EXCEPTION_ACCESS_VIOLATION as i32),
            "after {took:?}: {stderr}"
        );
        let written = dumps();
        assert!(
            written.len() == 1 && written[0] > 0,
            "{written:?}: {stderr}"
        );
    }
}
