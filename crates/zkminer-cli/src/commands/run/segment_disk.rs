//! Disk for risc0 proof segments, reserved for every proof planned or running here.
//!
//! A risc0 proof writes every segment of its execution to disk before it proves them (the worker's
//! `segments.rs`): under `[retention] segment_dir` when it is configured (each witness proof in a
//! directory of its own, inline proofs in `inline/`), else under `~/.zkminer/risc0-segments`. A
//! proof is claimed only while its segments fit beside what every proof planned or running here
//! reserved, keeping 1 GiB free (`SEGMENT_FLOOR_BYTES`): a witness proof reserves its measured segment
//! bytes at its claim gate; an inline risc0 proof reserves [`inline_need`] at its claim. Each is
//! given back when its proof is over (its card is released) or its claim does not land.
//!
//! The same reading tells a failed inline proof attempt that this host's disk could not hold its
//! segments ([`inline_short`]) from a failure of the job's, which no worker text can fake.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use alloy::primitives::B256;

use super::witness::policy::segments_fit;

/// An upper estimate of what an inline proof's segments take on disk, per sized cycle. A segment
/// file holds the pages its execution touched (paging one in costs more cycles than its bytes), the
/// bytes its syscalls returned (input and host entropy: a word per cycle at most) and a fixed part
/// (about 40 KB). The reference guests measure at most 1.3 bytes per cycle at po2 16 (the fixed part
/// over the smallest job segment) and under 0.2 at po2 20. Witness proofs measure theirs instead.
pub(crate) const INLINE_SEGMENT_BYTES_PER_CYCLE: u64 = 4;

/// What an inline proof of `cycles` sized cycles may write to its segment directory.
pub(crate) fn inline_need(cycles: u64) -> u64 {
    cycles.saturating_mul(INLINE_SEGMENT_BYTES_PER_CYCLE)
}

/// Where inline proofs' segment directories are, as the workers choose it.
static INLINE_ROOT: OnceLock<PathBuf> = OnceLock::new();

/// At startup: inline segments go under the retention store's segment directory when it is
/// configured, else under `~/.zkminer/risc0-segments`.
pub(crate) fn set_inline_root(retention_segment_dir: Option<&Path>) {
    let root = match retention_segment_dir {
        Some(dir) => Some(dir.join("inline")),
        None => dirs::home_dir().map(|h| h.join(".zkminer").join("risc0-segments")),
    };
    if let Some(root) = root {
        let _ = INLINE_ROOT.set(root);
    }
}

fn inline_root() -> Option<&'static Path> {
    INLINE_ROOT.get().map(PathBuf::as_path)
}

/// The bytes reserved, by job.
static RESERVED: Mutex<Option<HashMap<B256, u64>>> = Mutex::new(None);

fn with_reserved<T>(f: impl FnOnce(&mut HashMap<B256, u64>) -> T) -> T {
    let mut g = RESERVED.lock().unwrap_or_else(|p| p.into_inner());
    f(g.get_or_insert_with(HashMap::new))
}

/// Reserves `need` bytes for `jid`'s proof under `dir` when they fit beside every other
/// reservation and the floor, in one step with the check.
pub(crate) fn try_reserve(jid: B256, need: u64, dir: &Path) -> Result<(), String> {
    with_reserved(|reserved| {
        let others: u64 = reserved
            .iter()
            .filter(|(j, _)| **j != jid)
            .map(|(_, b)| *b)
            .sum();
        match free_bytes(dir) {
            Ok(free) if segments_fit(need, others, free) => {
                reserved.insert(jid, need);
                Ok(())
            }
            Ok(free) => Err(format!(
                "segments need {need} bytes beside {others} reserved; {free} free under {}",
                dir.display()
            )),
            Err(e) => Err(format!("segment directory {}: {e}", dir.display())),
        }
    })
}

/// Reserves an inline risc0 proof of `cycles` sized cycles ([`inline_need`]) where inline segments
/// go. Where that is not known (no home directory), nothing is checked.
pub(crate) fn try_reserve_inline(jid: B256, cycles: u64) -> Result<(), String> {
    match inline_root() {
        Some(root) => try_reserve(jid, inline_need(cycles), &existing(root)),
        None => Ok(()),
    }
}

/// Reserves `need` bytes for `jid` without a check (a lock held already: its proof runs anyway).
pub(crate) fn reserve(jid: B256, need: u64) {
    with_reserved(|reserved| {
        reserved.insert(jid, need);
    });
}

/// Gives `jid`'s reservation back.
pub(crate) fn release(jid: B256) {
    with_reserved(|reserved| {
        reserved.remove(&jid);
    });
}

/// Whether this host's segment disk, as it reads now, is short of room for an inline proof of
/// `cycles` sized cycles beside the other reservations: a failed attempt then failed for want of
/// this host's disk, whatever its worker said. `false` where it cannot be read.
pub(crate) fn inline_short(jid: B256, cycles: u64) -> bool {
    inline_root().is_some_and(|root| short_in(&existing(root), jid, inline_need(cycles)))
}

/// Whether `need` bytes for `jid` do not fit under `dir` now beside the other reservations.
fn short_in(dir: &Path, jid: B256, need: u64) -> bool {
    let others: u64 =
        with_reserved(|r| r.iter().filter(|(j, _)| **j != jid).map(|(_, b)| *b).sum());
    free_bytes(dir).is_ok_and(|free| !segments_fit(need, others, free))
}

/// `dir`, or its nearest ancestor that exists (a worker makes its directory at its start).
fn existing(dir: &Path) -> PathBuf {
    dir.ancestors()
        .find(|a| a.exists())
        .unwrap_or(dir)
        .to_path_buf()
}

/// Bytes available to this user on the filesystem holding `dir`.
#[cfg(unix)]
pub(crate) fn free_bytes(dir: &Path) -> std::io::Result<u64> {
    let c = std::ffi::CString::new(dir.as_os_str().as_encoded_bytes())
        .map_err(|_| std::io::Error::other("path contains NUL"))?;
    // SAFETY: statvfs fills a plain struct, and `c` is a NUL-terminated path.
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(c.as_ptr(), &mut st) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    #[allow(clippy::unnecessary_cast)]
    Ok((st.f_bavail as u64).saturating_mul(st.f_frsize as u64))
}

/// Bytes available to this user (quotas included) on the volume holding `dir`.
#[cfg(windows)]
pub(crate) fn free_bytes(dir: &Path) -> std::io::Result<u64> {
    use std::os::windows::ffi::OsStrExt;
    extern "system" {
        fn GetDiskFreeSpaceExW(
            dir: *const u16,
            free_to_caller: *mut u64,
            total: *mut u64,
            total_free: *mut u64,
        ) -> i32;
    }
    let wide: Vec<u16> = dir.as_os_str().encode_wide().chain([0]).collect();
    let mut free = 0u64;
    // SAFETY: a NUL-terminated path, one out-pointer to a local; the others may be null.
    let ok = unsafe {
        GetDiskFreeSpaceExW(
            wide.as_ptr(),
            &mut free,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(free)
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn free_bytes(_dir: &Path) -> std::io::Result<u64> {
    Err(std::io::Error::other(
        "free space is not read on this platform",
    ))
}

#[cfg(all(test, unix))]
mod tests {
    use super::super::witness::policy::SEGMENT_FLOOR_BYTES;
    use super::*;

    /// The reservations are process-wide: the tests that fill the disk with them take turns.
    static SERIAL: Mutex<()> = Mutex::new(());

    fn serial() -> std::sync::MutexGuard<'static, ()> {
        SERIAL.lock().unwrap_or_else(|p| p.into_inner())
    }

    #[test]
    fn an_inline_proof_reserves_beside_witness_proofs_and_gives_it_back() {
        let _serial = serial();
        let dir = tempfile::tempdir().unwrap();
        let free = free_bytes(dir.path()).unwrap();
        let room = free.saturating_sub(SEGMENT_FLOOR_BYTES);
        let (a, b) = (B256::repeat_byte(0x5a), B256::repeat_byte(0x5b));
        // A witness proof reserves most of the room; an inline proof that needs the rest and more
        // does not fit beside it, and fits once it is given back.
        try_reserve(a, room / 2, dir.path()).unwrap();
        let e = try_reserve(b, room / 2 + room / 4 + 1, dir.path()).unwrap_err();
        assert!(e.contains("reserved"), "{e}");
        release(a);
        try_reserve(b, room / 2 + room / 4 + 1, dir.path()).unwrap();
        release(b);
        // A reservation's own size is not counted against itself again.
        try_reserve(a, room / 2, dir.path()).unwrap();
        try_reserve(a, room / 2, dir.path()).unwrap();
        release(a);
    }

    /// A failed attempt is judged by this host's own reading: short when the job's segments do not
    /// fit beside the other reservations and the floor now.
    #[test]
    fn a_disk_without_room_for_the_jobs_segments_reads_short() {
        let _serial = serial();
        let dir = tempfile::tempdir().unwrap();
        let free = free_bytes(dir.path()).unwrap();
        let (job, other) = (B256::repeat_byte(0x6a), B256::repeat_byte(0x6b));
        assert!(!short_in(dir.path(), job, 1 << 20));
        assert!(short_in(dir.path(), job, free));
        // Room taken by another proof's reservation counts; the job's own does not.
        reserve(other, free.saturating_sub(SEGMENT_FLOOR_BYTES));
        assert!(short_in(dir.path(), job, 1 << 30));
        release(other);
        reserve(job, free.saturating_sub(SEGMENT_FLOOR_BYTES));
        assert!(!short_in(dir.path(), job, 1 << 20));
        release(job);
    }

    #[test]
    fn an_inline_proof_needs_four_bytes_a_cycle() {
        assert_eq!(inline_need(1 << 20), 4 << 20);
        assert_eq!(inline_need(u64::MAX), u64::MAX);
        let missing = Path::new("/definitely/not/here/inline");
        assert_eq!(existing(missing), Path::new("/"));
    }
}

#[cfg(all(test, windows))]
mod windows_tests {
    use super::*;

    /// The free-space read works here: a failed read refuses every inline risc0 claim.
    #[test]
    fn free_space_is_read() {
        let free = free_bytes(&std::env::temp_dir()).expect("free space read");
        assert!(free > 0);
    }

    /// A path whose volume does not exist reads as an error, not as zero bytes free.
    #[test]
    fn a_missing_volume_is_an_error() {
        assert!(free_bytes(Path::new(
            r"\\?\Volume{00000000-0000-0000-0000-000000000000}\"
        ))
        .is_err());
    }
}
