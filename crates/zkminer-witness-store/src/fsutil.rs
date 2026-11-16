//! Low-level filesystem helpers: `statfs`/`statvfs`, randomness, fsync, capped reads and usage walks.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read};
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use crate::store::Usage;

pub(crate) const TMPFS_MAGIC: u32 = 0x0102_1994;
pub(crate) const RAMFS_MAGIC: u32 = 0x8584_58f6;
pub(crate) const OVERLAYFS_SUPER_MAGIC: u32 = 0x794c_7630;

/// Filesystems the store refuses to live on (plan §15.1: never tmpfs, `/dev/shm` or an overlay).
pub(crate) fn refused_fs_type(f_type: u32) -> bool {
    matches!(f_type, TMPFS_MAGIC | RAMFS_MAGIC | OVERLAYFS_SUPER_MAGIC)
}

/// `fstatfs(2)`'s `f_type`.
pub(crate) fn fs_type(f: &File) -> io::Result<u32> {
    // SAFETY: `statfs` is plain old data; `fstatfs` fills it for a valid fd.
    let mut st: libc::statfs = unsafe { std::mem::zeroed() };
    let r = unsafe { libc::fstatfs(f.as_raw_fd(), &mut st) };
    if r != 0 {
        return Err(io::Error::last_os_error());
    }
    // `f_type` is a signed word whose magic values are 32-bit.
    Ok(st.f_type as u32)
}

/// Bytes available to an unprivileged writer (`f_bavail × f_frsize`).
#[allow(clippy::unnecessary_cast)] // the field types differ across targets
pub(crate) fn fs_avail_bytes(f: &File) -> io::Result<u64> {
    // SAFETY: as above, for `fstatvfs`.
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    let r = unsafe { libc::fstatvfs(f.as_raw_fd(), &mut st) };
    if r != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((st.f_bavail as u64).saturating_mul(st.f_frsize as u64))
}

/// Fills `buf` from `getrandom(2)`, falling back to `/dev/urandom` where the syscall is absent.
pub(crate) fn random_bytes(buf: &mut [u8]) -> io::Result<()> {
    let mut filled = 0;
    while filled < buf.len() {
        let rest = &mut buf[filled..];
        // SAFETY: `rest` is a valid writable buffer of `rest.len()` bytes.
        let r = unsafe { libc::getrandom(rest.as_mut_ptr().cast(), rest.len(), 0) };
        if r >= 0 {
            filled += r as usize;
            continue;
        }
        let e = io::Error::last_os_error();
        match e.raw_os_error() {
            Some(libc::EINTR) => continue,
            Some(libc::ENOSYS) => return File::open("/dev/urandom")?.read_exact(rest),
            _ => return Err(e),
        }
    }
    Ok(())
}

/// A random version-4 UUID, lowercase and hyphenated.
pub(crate) fn uuid_v4() -> io::Result<String> {
    let mut b = [0u8; 16];
    random_bytes(&mut b)?;
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h = hex::encode(b);
    Ok(format!("{}-{}-{}-{}-{}", &h[..8], &h[8..12], &h[12..16], &h[16..20], &h[20..]))
}

/// A lowercase, hyphenated UUID.
pub(crate) fn is_uuid(s: &str) -> bool {
    s.len() == 36
        && s.bytes().enumerate().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => c == b'-',
            _ => c.is_ascii_digit() || (b'a'..=b'f').contains(&c),
        })
}

/// A random name for an entry under `<root>/tmp/`.
pub(crate) fn random_name() -> io::Result<String> {
    let mut b = [0u8; 16];
    random_bytes(&mut b)?;
    Ok(hex::encode(b))
}

/// Opens an existing file read-only without following a final symlink. `O_NONBLOCK` keeps a
/// planted FIFO from blocking the open; callers check the file type with `fstat`.
pub(crate) fn open_ro(p: &Path) -> io::Result<File> {
    OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(p)
}

/// Clears the `O_NONBLOCK` that [`open_ro`] set, once the file is known to be regular, so an fd
/// handed to a worker carries no surprising status flag.
pub(crate) fn clear_nonblock(f: &File) -> io::Result<()> {
    // SAFETY: `fcntl` with F_GETFL/F_SETFL on a valid fd.
    let flags = unsafe { libc::fcntl(f.as_raw_fd(), libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::fcntl(f.as_raw_fd(), libc::F_SETFL, flags & !libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Creates a new file (never an existing one, never through a symlink) for writing.
pub(crate) fn create_new(p: &Path) -> io::Result<File> {
    OpenOptions::new().write(true).create_new(true).mode(0o600).custom_flags(libc::O_NOFOLLOW).open(p)
}

/// `fsync(2)` on a directory, so the entries created, renamed or removed in it are durable.
pub(crate) fn fsync_dir(p: &Path) -> io::Result<()> {
    OpenOptions::new().read(true).custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW).open(p)?.sync_all()
}

pub(crate) enum ReadError {
    Io(io::Error),
    TooLarge,
    NotRegular,
}

/// Reads a whole regular file of at most `cap` bytes.
pub(crate) fn read_capped(p: &Path, cap: u64) -> Result<Vec<u8>, ReadError> {
    let f = open_ro(p).map_err(|e| {
        if e.raw_os_error() == Some(libc::ELOOP) {
            ReadError::NotRegular
        } else {
            ReadError::Io(e)
        }
    })?;
    let m = f.metadata().map_err(ReadError::Io)?;
    if !m.is_file() {
        return Err(ReadError::NotRegular);
    }
    if m.len() > cap {
        return Err(ReadError::TooLarge);
    }
    let mut buf = Vec::with_capacity(m.len() as usize);
    f.take(cap + 1).read_to_end(&mut buf).map_err(ReadError::Io)?;
    if buf.len() as u64 > cap {
        return Err(ReadError::TooLarge);
    }
    Ok(buf)
}

/// The usage of `p` and everything under it: one inode per entry, the bytes of regular files.
/// Symlinks are counted, never followed.
pub(crate) fn tree_usage(p: &Path) -> io::Result<Usage> {
    let m = fs::symlink_metadata(p)?;
    let mut u = Usage { bytes: if m.is_file() { m.len() } else { 0 }, inodes: 1 };
    if m.is_dir() {
        for e in fs::read_dir(p)? {
            u.add(tree_usage(&e?.path())?);
        }
    }
    Ok(u)
}

/// [`tree_usage`], or zero when `p` does not exist.
pub(crate) fn tree_usage_opt(p: &Path) -> io::Result<Usage> {
    match tree_usage(p) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Usage::default()),
        r => r,
    }
}

/// Removes a file or a whole directory tree.
pub(crate) fn remove_any(p: &Path) -> io::Result<()> {
    let m = fs::symlink_metadata(p)?;
    if m.is_dir() {
        fs::remove_dir_all(p)
    } else {
        fs::remove_file(p)
    }
}

/// Decodes hex with an optional `0x` prefix.
pub(crate) fn decode_hex(s: &str) -> Option<Vec<u8>> {
    hex::decode(s.strip_prefix("0x").unwrap_or(s)).ok()
}
