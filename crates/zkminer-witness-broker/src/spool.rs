//! Quota'd spool files for large bodies (plan §11.3, §11.4): a body is streamed to an anonymous
//! file in `spool_dir` while it is hashed, so nothing buffers it whole. The quota covers every
//! spooled body at once; a file's bytes are released when it is dropped.
//!
//! **Held-lock reserve.** `held_lock_share × quota` of the quota is held-lock work's alone: other
//! work may spool only while `used + n ≤ quota − reserve`, held-lock work up to the whole quota. A
//! flood of simulation bodies parked behind slow-reading builders therefore never leaves a held
//! lock without spool room (the in-flight byte permit, held until a result is written, bounds that
//! flood too).
//!
//! **Off the runtime.** Creating, writing and reading spool files is disk I/O: the async variants
//! run it on the blocking pool (bounded by [`crate::MAX_BLOCKING_THREADS`]), never on a runtime
//! worker.

use std::fs::{File, OpenOptions};
use std::io;
use std::os::unix::fs::{DirBuilderExt, FileExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

#[derive(Debug)]
pub struct Spool {
    dir: PathBuf,
    quota: u64,
    reserve: u64,
    used: AtomicU64,
    seq: AtomicU64,
}

/// One spooled body.
#[derive(Debug)]
pub struct SpoolFile {
    file: Arc<File>,
    spool: Arc<Spool>,
    len: u64,
    held: bool,
}

fn blocking_err(e: tokio::task::JoinError) -> io::Error {
    io::Error::other(format!("blocking task: {e}"))
}

impl Spool {
    /// Creates `dir` (mode 0700) if it is missing. `held_lock_share` of `quota` is reserved for
    /// held-lock work.
    pub fn new(dir: &Path, quota: u64, held_lock_share: f64) -> io::Result<Arc<Self>> {
        if !dir.exists() {
            std::fs::DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
        }
        let reserve = ((quota as f64) * held_lock_share.clamp(0.0, 1.0)) as u64;
        Ok(Arc::new(Self {
            dir: dir.to_path_buf(),
            quota,
            reserve: reserve.min(quota),
            used: AtomicU64::new(0),
            seq: AtomicU64::new(0),
        }))
    }

    /// Bytes spooled now, across all files.
    pub fn used(&self) -> u64 {
        self.used.load(Ordering::SeqCst)
    }

    /// An anonymous file in the spool directory (`O_TMPFILE`; where the filesystem lacks it, a
    /// named file unlinked at once). Blocking.
    pub fn create(self: &Arc<Self>, held: bool) -> io::Result<SpoolFile> {
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
        Ok(SpoolFile { file: Arc::new(file), spool: self.clone(), len: 0, held })
    }

    /// [`Spool::create`] on the blocking pool.
    pub async fn create_async(self: &Arc<Self>, held: bool) -> io::Result<SpoolFile> {
        let me = self.clone();
        tokio::task::spawn_blocking(move || me.create(held)).await.map_err(blocking_err)?
    }

    fn charge(&self, n: u64, held: bool) -> bool {
        let limit = if held { self.quota } else { self.quota - self.reserve };
        self.used.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |u| u.checked_add(n).filter(|&t| t <= limit)).is_ok()
    }
}

fn full() -> io::Error {
    io::Error::new(io::ErrorKind::StorageFull, "spool quota reached")
}

impl SpoolFile {
    /// Appends `chunk`, refusing (`StorageFull`) past the spool quota (its non-reserved part for
    /// work that holds no lock). Blocking.
    pub fn write(&mut self, chunk: &[u8]) -> io::Result<()> {
        if !self.spool.charge(chunk.len() as u64, self.held) {
            return Err(full());
        }
        let off = self.len;
        self.len += chunk.len() as u64;
        self.file.write_all_at(chunk, off)
    }

    /// [`SpoolFile::write`] of `buf` on the blocking pool (charged before it is written).
    pub async fn append(&mut self, buf: Vec<u8>) -> io::Result<()> {
        if buf.is_empty() {
            return Ok(());
        }
        if !self.spool.charge(buf.len() as u64, self.held) {
            return Err(full());
        }
        let off = self.len;
        self.len += buf.len() as u64;
        let file = self.file.clone();
        tokio::task::spawn_blocking(move || file.write_all_at(&buf, off)).await.map_err(blocking_err)?
    }

    /// Up to `max` bytes at `off`, read on the blocking pool (`pread`: the offset is explicit).
    pub async fn read_at(&self, off: u64, max: usize) -> io::Result<Vec<u8>> {
        let file = self.file.clone();
        let want = max.min(self.len.saturating_sub(off) as usize);
        tokio::task::spawn_blocking(move || {
            let mut buf = vec![0u8; want];
            let n = file.read_at(&mut buf, off)?;
            buf.truncate(n);
            Ok(buf)
        })
        .await
        .map_err(blocking_err)?
    }

    pub fn len(&self) -> u64 {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The file, to read back with `pread`.
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

    #[test]
    fn spooled_bytes_count_against_the_quota_until_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let spool = Spool::new(&dir.path().join("s"), 10, 0.0).unwrap();
        let mut a = spool.create(false).unwrap();
        a.write(b"123456").unwrap();
        let mut b = spool.create(false).unwrap();
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

    /// Review F4: a share of the quota is held-lock work's alone.
    #[tokio::test]
    async fn the_held_lock_reserve_and_async_io() {
        let dir = tempfile::tempdir().unwrap();
        let spool = Spool::new(&dir.path().join("s"), 100, 0.25).unwrap();
        let mut sim = spool.create_async(false).await.unwrap();
        sim.append(vec![1; 75]).await.unwrap();
        assert_eq!(sim.append(vec![1; 1]).await.unwrap_err().kind(), io::ErrorKind::StorageFull, "the last 25 are reserved");
        let mut held = spool.create_async(true).await.unwrap();
        held.append(vec![2; 25]).await.unwrap();
        assert_eq!(held.append(vec![2; 1]).await.unwrap_err().kind(), io::ErrorKind::StorageFull, "the quota itself");
        assert_eq!(sim.read_at(70, 100).await.unwrap(), vec![1; 5]);
        assert_eq!(held.read_at(0, 10).await.unwrap(), vec![2; 10]);
        drop(held);
        assert_eq!(spool.used(), 75);
    }
}
