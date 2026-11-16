//! Low-level filesystem access.
//!
//! Every path the store touches is reached from the root's directory fd one component at a time
//! with `openat(O_DIRECTORY | O_NOFOLLOW)`, and every change is an `*at` syscall (`mkdirat`,
//! `renameat2`, `linkat`, `unlinkat`, `fstatat`) on a single name inside such a directory. A symlink
//! is never followed at any level, so nothing outside the root is ever read, changed or deleted
//! through one. Every mutating call (and every open) passes the test-only fault seam
//! ([`crate::faults`]), which compiles to nothing outside `cargo test`.

use std::ffi::{CStr, CString, OsStr, OsString};
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use crate::faults::{self, Op};
use crate::store::Usage;

const EXT4_SUPER_MAGIC: u32 = 0xef53; // also ext2 and ext3
const XFS_SUPER_MAGIC: u32 = 0x5846_5342;
const BTRFS_SUPER_MAGIC: u32 = 0x9123_683e;
const ZFS_SUPER_MAGIC: u32 = 0x2fc1_2fc1;
const F2FS_SUPER_MAGIC: u32 = 0xf2f5_2010;

/// The filesystems the store accepts without `allow_any_filesystem` (plan §15.1): local, journaled
/// or copy-on-write, with the rename and fsync semantics the store's durability argument relies on.
/// Everything else — NFS, CIFS, FUSE, virtiofs, 9p, aufs, tmpfs, ramfs, overlay — is refused.
pub(crate) fn supported_fs_type(f_type: u32) -> bool {
    matches!(f_type, EXT4_SUPER_MAGIC | XFS_SUPER_MAGIC | BTRFS_SUPER_MAGIC | ZFS_SUPER_MAGIC | F2FS_SUPER_MAGIC)
}

fn cvt(r: libc::c_int) -> io::Result<libc::c_int> {
    if r < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(r)
    }
}

/// [`cvt`], retrying `EINTR` (only for calls that are safe to repeat: opens, never `fsync`).
fn cvt_r(mut f: impl FnMut() -> libc::c_int) -> io::Result<libc::c_int> {
    loop {
        match cvt(f()) {
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            r => return r,
        }
    }
}

/// One path component: never empty, `.`, `..`, or containing `/` or NUL.
fn cname(name: &OsStr) -> io::Result<CString> {
    let b = name.as_bytes();
    if b.is_empty() || b == b"." || b == b".." || b.contains(&b'/') {
        return Err(io::Error::from_raw_os_error(libc::EINVAL));
    }
    CString::new(b).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))
}

pub(crate) fn errno(e: &io::Error) -> Option<i32> {
    e.raw_os_error()
}

pub(crate) fn is_enoent(e: &io::Error) -> bool {
    errno(e) == Some(libc::ENOENT)
}

/// `openat(O_DIRECTORY | O_NOFOLLOW)` refused the entry: it is a symlink or not a directory.
pub(crate) fn is_not_a_real_dir(e: &io::Error) -> bool {
    matches!(errno(e), Some(libc::ELOOP) | Some(libc::ENOTDIR))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    Dir,
    File,
    Symlink,
    Other,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct Stat {
    pub kind: Kind,
    pub len: u64,
    pub dev: u64,
    pub ino: u64,
}

impl Stat {
    fn of(st: &libc::stat) -> Stat {
        let kind = match st.st_mode & libc::S_IFMT {
            libc::S_IFDIR => Kind::Dir,
            libc::S_IFREG => Kind::File,
            libc::S_IFLNK => Kind::Symlink,
            _ => Kind::Other,
        };
        Stat { kind, len: st.st_size as u64, dev: st.st_dev, ino: st.st_ino }
    }

    /// The usage of this one entry: an inode, plus its bytes when it is a regular file.
    pub(crate) fn usage(&self) -> Usage {
        Usage::new(if self.kind == Kind::File { self.len } else { 0 }, 1)
    }
}

/// A directory entry: its raw name and its type (never followed).
pub(crate) struct Entry {
    pub name: OsString,
    pub kind: Kind,
}

impl Entry {
    pub(crate) fn utf8(&self) -> Option<&str> {
        self.name.to_str()
    }
}

/// An open directory and its path (the path is for messages and the fault seam only; every
/// operation goes through the fd).
#[derive(Debug)]
pub(crate) struct Dir {
    fd: OwnedFd,
    path: PathBuf,
}

impl Dir {
    /// Opens `path` itself as a directory, refusing a final symlink (the store root).
    pub(crate) fn open_path(path: &Path) -> io::Result<Dir> {
        faults::hit(Op::Open, || path.to_path_buf())?;
        let c = CString::new(path.as_os_str().as_bytes()).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
        // SAFETY: a valid NUL-terminated path; the fd is owned below.
        let fd = cvt_r(|| unsafe {
            libc::open(c.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        })?;
        // SAFETY: `fd` was just returned by `open` and is owned by nothing else.
        Ok(Dir { fd: unsafe { OwnedFd::from_raw_fd(fd) }, path: path.to_path_buf() })
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn child(&self, name: impl AsRef<OsStr>) -> PathBuf {
        self.path.join(name.as_ref())
    }

    fn raw(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    /// Opens the subdirectory `name`, refusing a symlink (`ELOOP`) or a non-directory (`ENOTDIR`).
    pub(crate) fn sub(&self, name: impl AsRef<OsStr>) -> io::Result<Dir> {
        let name = name.as_ref();
        faults::hit(Op::Open, || self.child(name))?;
        let c = cname(name)?;
        // SAFETY: a valid dirfd and component; the fd is owned below.
        let fd = cvt_r(|| unsafe {
            libc::openat(self.raw(), c.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        })?;
        // SAFETY: as in `open_path`.
        Ok(Dir { fd: unsafe { OwnedFd::from_raw_fd(fd) }, path: self.child(name) })
    }

    /// `fstatat(AT_SYMLINK_NOFOLLOW)`.
    pub(crate) fn stat(&self, name: impl AsRef<OsStr>) -> io::Result<Stat> {
        let c = cname(name.as_ref())?;
        self.stat_c(&c)
    }

    fn stat_c(&self, c: &CStr) -> io::Result<Stat> {
        // SAFETY: `stat` is plain old data filled by `fstatat` for a valid dirfd and name.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        cvt(unsafe { libc::fstatat(self.raw(), c.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) })?;
        Ok(Stat::of(&st))
    }

    /// [`Dir::stat`], with an absent entry as `None`.
    pub(crate) fn stat_opt(&self, name: impl AsRef<OsStr>) -> io::Result<Option<Stat>> {
        match self.stat(name) {
            Ok(s) => Ok(Some(s)),
            Err(e) if is_enoent(&e) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// The directory itself.
    pub(crate) fn fstat(&self) -> io::Result<Stat> {
        fstat(self.raw())
    }

    /// The parent directory as the kernel sees it (`..` of the fd, crossing a mount point upward).
    pub(crate) fn parent_stat(&self) -> io::Result<Stat> {
        self.stat_c(c"..")
    }

    /// Opens an existing file read-only without following a final symlink. `O_NONBLOCK` keeps a
    /// planted FIFO from blocking the open; callers check the type with `fstat`.
    pub(crate) fn open_ro(&self, name: impl AsRef<OsStr>) -> io::Result<File> {
        let name = name.as_ref();
        faults::hit(Op::Open, || self.child(name))?;
        let c = cname(name)?;
        // SAFETY: as in `sub`.
        let fd = cvt_r(|| unsafe {
            libc::openat(self.raw(), c.as_ptr(), libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        })?;
        // SAFETY: as in `open_path`.
        Ok(unsafe { File::from_raw_fd(fd) })
    }

    /// Opens (with `create`, creates) the lock file read-write, never through a symlink.
    pub(crate) fn open_lock(&self, name: impl AsRef<OsStr>, create: bool) -> io::Result<File> {
        let name = name.as_ref();
        if create {
            faults::hit(Op::Create, || self.child(name))?;
        }
        let c = cname(name)?;
        let flags = libc::O_RDWR | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC | if create { libc::O_CREAT } else { 0 };
        // SAFETY: as in `sub`.
        let fd = cvt_r(|| unsafe { libc::openat(self.raw(), c.as_ptr(), flags, 0o600 as libc::c_uint) })?;
        // SAFETY: as in `open_path`.
        Ok(unsafe { File::from_raw_fd(fd) })
    }

    /// Creates a new file for writing (never an existing one, never through a symlink).
    pub(crate) fn create_new(&self, name: impl AsRef<OsStr>, mode: u32) -> io::Result<File> {
        let name = name.as_ref();
        faults::hit(Op::Create, || self.child(name))?;
        let c = cname(name)?;
        let flags = libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC;
        // SAFETY: as in `sub`.
        let fd = cvt_r(|| unsafe { libc::openat(self.raw(), c.as_ptr(), flags, mode as libc::c_uint) })?;
        // SAFETY: as in `open_path`.
        Ok(unsafe { File::from_raw_fd(fd) })
    }

    pub(crate) fn mkdir(&self, name: impl AsRef<OsStr>) -> io::Result<()> {
        let name = name.as_ref();
        faults::hit(Op::Mkdir, || self.child(name))?;
        let c = cname(name)?;
        // SAFETY: a valid dirfd and component.
        cvt(unsafe { libc::mkdirat(self.raw(), c.as_ptr(), 0o700) }).map(drop)
    }

    /// `renameat2` from `self/name` to `to/to_name`; with `noreplace`, an existing destination is
    /// `EEXIST` instead of being replaced.
    pub(crate) fn rename_to(
        &self,
        name: impl AsRef<OsStr>,
        to: &Dir,
        to_name: impl AsRef<OsStr>,
        noreplace: bool,
    ) -> io::Result<()> {
        let (name, to_name) = (name.as_ref(), to_name.as_ref());
        faults::hit(Op::Rename, || self.child(name))?;
        let (a, b) = (cname(name)?, cname(to_name)?);
        let flags = if noreplace { libc::RENAME_NOREPLACE } else { 0 };
        // SAFETY: valid dirfds and components; `renameat2` has no glibc wrapper requirement here.
        let r = unsafe { libc::syscall(libc::SYS_renameat2, self.raw(), a.as_ptr(), to.raw(), b.as_ptr(), flags) };
        if r < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// A hard link `to/to_name` of the file `self/name` (`linkat` without `AT_SYMLINK_FOLLOW`: a
    /// symlink would be linked as itself, never followed).
    pub(crate) fn link_to(&self, name: impl AsRef<OsStr>, to: &Dir, to_name: impl AsRef<OsStr>) -> io::Result<()> {
        let (name, to_name) = (name.as_ref(), to_name.as_ref());
        faults::hit(Op::Link, || self.child(name))?;
        let (a, b) = (cname(name)?, cname(to_name)?);
        // SAFETY: valid dirfds and components.
        cvt(unsafe { libc::linkat(self.raw(), a.as_ptr(), to.raw(), b.as_ptr(), 0) }).map(drop)
    }

    pub(crate) fn unlink(&self, name: impl AsRef<OsStr>) -> io::Result<()> {
        let name = name.as_ref();
        faults::hit(Op::Unlink, || self.child(name))?;
        let c = cname(name)?;
        // SAFETY: a valid dirfd and component.
        cvt(unsafe { libc::unlinkat(self.raw(), c.as_ptr(), 0) }).map(drop)
    }

    pub(crate) fn rmdir(&self, name: impl AsRef<OsStr>) -> io::Result<()> {
        let name = name.as_ref();
        faults::hit(Op::Rmdir, || self.child(name))?;
        let c = cname(name)?;
        // SAFETY: a valid dirfd and component.
        cvt(unsafe { libc::unlinkat(self.raw(), c.as_ptr(), libc::AT_REMOVEDIR) }).map(drop)
    }

    /// `fsync(2)` on the directory, so the entries created, renamed or removed in it are durable.
    /// Never retried after a failure (the caller poisons the store instead).
    pub(crate) fn fsync(&self) -> io::Result<()> {
        faults::hit(Op::Fsync, || self.path.clone())?;
        // SAFETY: a valid fd.
        cvt(unsafe { libc::fsync(self.raw()) }).map(drop)
    }

    /// Every entry except `.` and `..`, with its type as `readdir` reports it (`fstatat` when the
    /// filesystem does not say).
    pub(crate) fn entries(&self) -> io::Result<Vec<Entry>> {
        faults::hit(Op::Open, || self.path.clone())?;
        // A fresh open file description, so this listing has its own offset.
        // SAFETY: a valid dirfd; `.` is a valid path.
        let fd = cvt_r(|| unsafe { libc::openat(self.raw(), c".".as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC) })?;
        // SAFETY: `fd` is a valid directory fd; on success `fdopendir` owns it.
        let dirp = unsafe { libc::fdopendir(fd) };
        if dirp.is_null() {
            let e = io::Error::last_os_error();
            // SAFETY: `fd` is still ours when `fdopendir` fails.
            unsafe { libc::close(fd) };
            return Err(e);
        }
        struct Closer(*mut libc::DIR);
        impl Drop for Closer {
            fn drop(&mut self) {
                // SAFETY: a stream from `fdopendir`, closed once.
                unsafe { libc::closedir(self.0) };
            }
        }
        let stream = Closer(dirp);
        let mut out = Vec::new();
        loop {
            // SAFETY: `readdir64` signals errors only through errno, so clear it first.
            unsafe { *libc::__errno_location() = 0 };
            // SAFETY: a valid stream.
            let ent = unsafe { libc::readdir64(stream.0) };
            if ent.is_null() {
                let e = io::Error::last_os_error();
                return match e.raw_os_error() {
                    Some(0) | None => Ok(out),
                    Some(_) => Err(e),
                };
            }
            // SAFETY: a non-null entry from `readdir64`, valid until the next call.
            let ent = unsafe { &*ent };
            // SAFETY: `d_name` is NUL-terminated.
            let raw = unsafe { CStr::from_ptr(ent.d_name.as_ptr()) }.to_bytes();
            if raw == b"." || raw == b".." {
                continue;
            }
            let name = OsStr::from_bytes(raw).to_os_string();
            let kind = match ent.d_type {
                libc::DT_DIR => Kind::Dir,
                libc::DT_REG => Kind::File,
                libc::DT_LNK => Kind::Symlink,
                libc::DT_UNKNOWN => match self.stat_opt(&name)? {
                    Some(s) => s.kind,
                    None => continue,
                },
                _ => Kind::Other,
            };
            out.push(Entry { name, kind });
        }
    }

    /// The usage of `name` and everything under it: one inode per entry, the bytes of regular
    /// files. Symlinks are counted, never followed; entries that vanish during the walk are skipped.
    pub(crate) fn tree_usage(&self, name: impl AsRef<OsStr>) -> io::Result<Usage> {
        let name = name.as_ref();
        let st = self.stat(name)?;
        let mut u = st.usage();
        if st.kind == Kind::Dir {
            let d = self.sub(name)?;
            for e in d.entries()? {
                match d.tree_usage(&e.name) {
                    Ok(x) => u.add(x),
                    Err(err) if is_enoent(&err) => {}
                    Err(err) => return Err(err),
                }
            }
        }
        Ok(u)
    }

    /// [`Dir::tree_usage`], or zero when `name` does not exist.
    pub(crate) fn tree_usage_opt(&self, name: impl AsRef<OsStr>) -> io::Result<Usage> {
        match self.tree_usage(name) {
            Err(e) if is_enoent(&e) => Ok(Usage::default()),
            r => r,
        }
    }

    /// Removes `name` and everything under it, never following a symlink (a symlink is unlinked as
    /// itself).
    pub(crate) fn remove_tree(&self, name: impl AsRef<OsStr>) -> io::Result<()> {
        let name = name.as_ref();
        if self.stat(name)?.kind == Kind::Dir {
            let d = self.sub(name)?;
            for e in d.entries()? {
                match d.remove_tree(&e.name) {
                    Err(err) if is_enoent(&err) => {}
                    r => r?,
                }
            }
            self.rmdir(name)
        } else {
            self.unlink(name)
        }
    }

    /// `fstatfs(2)`'s `f_type`.
    pub(crate) fn fs_type(&self) -> io::Result<u32> {
        // SAFETY: `statfs` is plain old data; `fstatfs` fills it for a valid fd.
        let mut st: libc::statfs = unsafe { std::mem::zeroed() };
        cvt(unsafe { libc::fstatfs(self.raw(), &mut st) })?;
        // `f_type` is a signed word whose magic values are 32-bit.
        Ok(st.f_type as u32)
    }

    /// Bytes available to an unprivileged writer (`f_bavail × f_frsize`).
    #[allow(clippy::unnecessary_cast)] // the field types differ across targets
    pub(crate) fn avail_bytes(&self) -> io::Result<u64> {
        // SAFETY: as above, for `fstatvfs`.
        let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
        cvt(unsafe { libc::fstatvfs(self.raw(), &mut st) })?;
        Ok((st.f_bavail as u64).saturating_mul(st.f_frsize as u64))
    }
}

pub(crate) fn fstat(fd: RawFd) -> io::Result<Stat> {
    // SAFETY: `stat` is plain old data filled by `fstat` for a valid fd.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    cvt(unsafe { libc::fstat(fd, &mut st) })?;
    Ok(Stat::of(&st))
}

/// `write_all` through the fault seam.
pub(crate) fn write_all(f: &mut File, data: &[u8], path: &Path) -> io::Result<()> {
    faults::hit(Op::Write, || path.to_path_buf())?;
    f.write_all(data)
}

/// `fchmod` through the fault seam.
pub(crate) fn fchmod(f: &File, mode: u32, path: &Path) -> io::Result<()> {
    faults::hit(Op::Chmod, || path.to_path_buf())?;
    // SAFETY: a valid fd.
    cvt(unsafe { libc::fchmod(f.as_raw_fd(), mode as libc::mode_t) }).map(drop)
}

/// `fsync` of a file through the fault seam. Never retried after a failure: the fd's error state
/// is consumed by the first report (fsyncgate), so a second `fsync` could falsely succeed.
pub(crate) fn fsync_file(f: &File, path: &Path) -> io::Result<()> {
    faults::hit(Op::Fsync, || path.to_path_buf())?;
    // SAFETY: a valid fd.
    cvt(unsafe { libc::fsync(f.as_raw_fd()) }).map(drop)
}

/// Writes `dir/name` atomically through a fresh file in `tmp`: write, `fchmod`, `fsync`, rename
/// over the destination, `fsync` of `dir`. On failure, says whether the rename had happened (the
/// change was visible) and removes the temporary file if it had not.
pub(crate) fn write_file_atomic(tmp: &Dir, dir: &Dir, name: &str, bytes: &[u8], mode: u32) -> Result<(), Staged> {
    let dest = dir.child(name);
    let part = format!("{}.part", random_name().map_err(|e| Staged::before(e, tmp.path()))?);
    let part_path = tmp.child(&part);
    let staged = (|| -> io::Result<()> {
        let mut f = tmp.create_new(&part, 0o600)?;
        write_all(&mut f, bytes, &part_path)?;
        fchmod(&f, mode, &part_path)?;
        fsync_file(&f, &part_path)
    })();
    if let Err(e) = staged {
        let _ = tmp.unlink(&part);
        return Err(Staged::before(e, &part_path));
    }
    if let Err(e) = tmp.rename_to(&part, dir, name, false) {
        let _ = tmp.unlink(&part);
        return Err(Staged::before(e, &dest));
    }
    dir.fsync().map_err(|e| Staged { err: e, path: dir.path().to_path_buf(), visible: true })
}

/// A failed multi-step change: the error, its path, and whether an earlier step had already made
/// a change visible.
#[derive(Debug)]
pub(crate) struct Staged {
    pub err: io::Error,
    pub path: PathBuf,
    pub visible: bool,
}

impl Staged {
    fn before(err: io::Error, path: &Path) -> Staged {
        Staged { err, path: path.to_path_buf(), visible: false }
    }
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

/// Clears the `O_NONBLOCK` that [`Dir::open_ro`] set, once the file is known to be regular, so an
/// fd handed to a worker carries no surprising status flag.
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

pub(crate) enum ReadError {
    Io(io::Error),
    TooLarge,
    NotRegular,
}

/// Reads the whole regular file `dir/name` of at most `cap` bytes (a symlink is `NotRegular`).
pub(crate) fn read_capped(dir: &Dir, name: impl AsRef<OsStr>, cap: u64) -> Result<Vec<u8>, ReadError> {
    let f = dir.open_ro(name).map_err(|e| {
        if errno(&e) == Some(libc::ELOOP) {
            ReadError::NotRegular
        } else {
            ReadError::Io(e)
        }
    })?;
    let m = fstat(f.as_raw_fd()).map_err(ReadError::Io)?;
    if m.kind != Kind::File {
        return Err(ReadError::NotRegular);
    }
    if m.len > cap {
        return Err(ReadError::TooLarge);
    }
    let mut buf = Vec::with_capacity(m.len as usize);
    f.take(cap + 1).read_to_end(&mut buf).map_err(ReadError::Io)?;
    if buf.len() as u64 > cap {
        return Err(ReadError::TooLarge);
    }
    Ok(buf)
}

/// Decodes hex with an optional `0x` prefix.
pub(crate) fn decode_hex(s: &str) -> Option<Vec<u8>> {
    hex::decode(s.strip_prefix("0x").unwrap_or(s)).ok()
}
