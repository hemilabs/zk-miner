//! Quota'd spool files for large bodies (plan §11.3, §11.4): a body is streamed to an anonymous
//! file in `spool_dir` while it is hashed, so nothing buffers it whole. The quota covers every
//! spooled body at once; a file's bytes are released when it is dropped.

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

#[derive(Debug)]
pub struct Spool {
    dir: PathBuf,
    quota: u64,
    used: AtomicU64,
    seq: AtomicU64,
}

/// One spooled body.
#[derive(Debug)]
pub struct SpoolFile {
    file: File,
    spool: Arc<Spool>,
    len: u64,
}

impl Spool {
    /// Creates `dir` (mode 0700) if it is missing.
    pub fn new(dir: &Path, quota: u64) -> io::Result<Arc<Self>> {
        if !dir.exists() {
            std::fs::DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
        }
        Ok(Arc::new(Self { dir: dir.to_path_buf(), quota, used: AtomicU64::new(0), seq: AtomicU64::new(0) }))
    }

    /// Bytes spooled now, across all files.
    pub fn used(&self) -> u64 {
        self.used.load(Ordering::SeqCst)
    }

    /// An anonymous file in the spool directory (`O_TMPFILE`; where the filesystem lacks it, a
    /// named file unlinked at once).
    pub fn create(self: &Arc<Self>) -> io::Result<SpoolFile> {
        let file = match OpenOptions::new()
            .read(true)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_TMPFILE | libc::O_CLOEXEC)
            .open(&self.dir)
        {
            Ok(f) => f,
            // No O_TMPFILE on this filesystem, or a sandbox that refuses it: a named file instead.
            Err(e)
                if matches!(
                    e.raw_os_error(),
                    Some(libc::EOPNOTSUPP | libc::EISDIR | libc::EINVAL | libc::EACCES | libc::EPERM)
                ) =>
            {
                let name = self.dir.join(format!(
                    ".spool-{}-{}",
                    std::process::id(),
                    self.seq.fetch_add(1, Ordering::Relaxed)
                ));
                let f = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .custom_flags(libc::O_CLOEXEC)
                    .open(&name)?;
                std::fs::remove_file(&name)?;
                f
            }
            Err(e) => return Err(e),
        };
        Ok(SpoolFile { file, spool: self.clone(), len: 0 })
    }

    fn charge(&self, n: u64) -> bool {
        self.used
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |u| u.checked_add(n).filter(|&t| t <= self.quota))
            .is_ok()
    }
}

impl SpoolFile {
    /// Appends `chunk`, refusing (`StorageFull`) past the spool quota.
    pub fn write(&mut self, chunk: &[u8]) -> io::Result<()> {
        if !self.spool.charge(chunk.len() as u64) {
            return Err(io::Error::new(io::ErrorKind::StorageFull, "spool quota reached"));
        }
        self.len += chunk.len() as u64;
        self.file.write_all(chunk)
    }

    pub fn len(&self) -> u64 {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The file, to read back (its offset is at the end).
    pub fn file(&self) -> &File {
        &self.file
    }
}

impl Drop for SpoolFile {
    fn drop(&mut self) {
        self.spool.used.fetch_sub(self.len, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::FileExt;

    #[test]
    fn spooled_bytes_count_against_the_quota_until_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let spool = Spool::new(&dir.path().join("s"), 10).unwrap();
        let mut a = spool.create().unwrap();
        a.write(b"123456").unwrap();
        let mut b = spool.create().unwrap();
        assert_eq!(b.write(b"12345").unwrap_err().kind(), io::ErrorKind::StorageFull);
        b.write(b"1234").unwrap();
        assert_eq!(spool.used(), 10);
        let mut out = [0u8; 6];
        a.file().read_exact_at(&mut out, 0).unwrap();
        assert_eq!(&out, b"123456");
        drop(a);
        assert_eq!(spool.used(), 4);
        drop(b);
        assert_eq!(spool.used(), 0);
        // Anonymous: nothing is left in the directory.
        assert_eq!(std::fs::read_dir(dir.path().join("s")).unwrap().count(), 0);
    }
}
