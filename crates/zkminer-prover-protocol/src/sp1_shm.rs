//! Which `/dev/shm` files are the SP1 native executor's, for the worker that sweeps up after a dead one
//! and the dispatcher that kills one.

/// True for a `/dev/shm` basename the SP1 native executor creates: the memory image
/// (`sp1_<uuid>_m`), the trace ring (`sp1_<uuid>_t`) and the ring's POSIX semaphores
/// (`sem.sp1_<uuid>_t_filled` / `_empty`). Both prefixes are matched on purpose — glibc backs a
/// named semaphore with a `sem.`-prefixed file in the same tmpfs (see sp1-jit `shm.rs`). The name
/// carries a random uuid, not a pid, so it cannot be the discriminator; liveness is (see reaper).
pub fn is_sp1_shm_basename(name: &str) -> bool {
    name.starts_with("sp1_") || name.starts_with("sem.sp1_")
}

/// Record into `out` every SP1 `/dev/shm` basename a `/proc/<pid>/maps` blob currently maps. For the
/// sweep, a segment ANY live process maps is in use, whichever worker owns it, and is spared; for a
/// kill, it is what the killed group staged. Reads `maps` not `fd` deliberately: SP1 `mmap`s a segment
/// then CLOSES the fd, so the fd is usually gone while the mapping — and the segment's use — persists;
/// keying on fds would unlink a live prover's ring.
pub fn sp1_shm_mapped_in(maps: &str, out: &mut std::collections::HashSet<String>) {
    for line in maps.lines() {
        let Some(idx) = line.find("/dev/shm/") else {
            continue;
        };
        // SP1's names are `sp1_` + base64url(uuid) + suffix; the base64url alphabet has no spaces,
        // so the basename is the first whitespace-delimited token after the prefix. Taking that
        // token also drops a trailing " (deleted)" annotation on an already-unlinked mapping.
        let Some(name) = line[idx + "/dev/shm/".len()..].split_whitespace().next() else {
            continue;
        };
        // Never a path: a caller joins this to `/dev/shm` to unlink it.
        if is_sp1_shm_basename(name) && !name.contains('/') {
            out.insert(name.to_string());
        }
    }
}
