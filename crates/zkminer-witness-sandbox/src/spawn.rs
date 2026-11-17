//! Parent side: [`prepare_command`].

use std::ffi::OsString;
use std::io;
use std::mem::MaybeUninit;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::process::CommandExt;
use std::process::Command;

use crate::{Cgroup, SandboxError};

/// Highest fd number a mapping may target.
pub(crate) const MAX_TARGET_FD: RawFd = 1023;
/// `statfs.f_type` of the cgroup v2 filesystem.
pub(crate) const CGROUP2_SUPER_MAGIC: u64 = 0x6367_7270;

/// How the child rearranges its fds: computed in the parent, executed in the child without
/// allocating.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FdPlan {
    /// `(source, target)` pairs, in the caller's order.
    pub moves: Vec<(RawFd, RawFd)>,
    /// Temporaries are duplicated at or above this number, which is above every target, so a
    /// temporary never lands on a target and every source survives until all are duplicated.
    pub temp_base: RawFd,
    /// Inclusive ranges of fds >= 3 that are not targets; marked close-on-exec.
    pub close_ranges: Vec<(u32, u32)>,
}

impl FdPlan {
    pub fn new(pairs: &[(RawFd, RawFd)]) -> Result<Self, SandboxError> {
        let mut targets = Vec::with_capacity(pairs.len());
        for &(src, dst) in pairs {
            if src < 0 {
                return Err(SandboxError::InvalidArgument(format!(
                    "source fd {src} is negative"
                )));
            }
            if !(3..=MAX_TARGET_FD).contains(&dst) {
                return Err(SandboxError::InvalidArgument(format!(
                    "target fd {dst} not in 3..={MAX_TARGET_FD} (set stdio with Command::stdin/stdout/stderr)"
                )));
            }
            if targets.contains(&dst) {
                return Err(SandboxError::InvalidArgument(format!(
                    "target fd {dst} mapped twice"
                )));
            }
            targets.push(dst);
        }
        targets.sort_unstable();
        let temp_base = targets.last().map_or(3, |t| t + 1);
        let mut close_ranges = Vec::with_capacity(targets.len() + 1);
        let mut next = 3u32;
        for &t in &targets {
            let t = t as u32;
            if t > next {
                close_ranges.push((next, t - 1));
            }
            next = t + 1;
        }
        close_ranges.push((next, u32::MAX));
        Ok(FdPlan {
            moves: pairs.to_vec(),
            temp_base,
            close_ranges,
        })
    }
}

/// The fd operations [`apply_plan`] needs; real in the child, modelled in tests.
pub(crate) trait FdOps {
    /// `fcntl(fd, F_DUPFD_CLOEXEC, min)`: the lowest free fd >= `min`, close-on-exec.
    fn dup_at_least(&mut self, fd: RawFd, min: RawFd) -> io::Result<RawFd>;
    /// `dup2(src, dst)`: replaces `dst`, which is *not* close-on-exec afterwards.
    fn dup2(&mut self, src: RawFd, dst: RawFd) -> io::Result<()>;
    fn close(&mut self, fd: RawFd);
    /// `close_range(first, last, CLOSE_RANGE_CLOEXEC)`.
    fn cloexec_range(&mut self, first: u32, last: u32) -> io::Result<()>;
}

/// Places every source at its target and marks every other fd >= 3 close-on-exec.
/// Allocation-free; `scratch` must hold one slot per move.
pub(crate) fn apply_plan<O: FdOps>(
    ops: &mut O,
    plan: &FdPlan,
    scratch: &mut [RawFd],
) -> io::Result<()> {
    if scratch.len() != plan.moves.len() {
        return Err(io::Error::from_raw_os_error(libc::EINVAL));
    }
    // 1. Copy every source above the targets first: a later dup2 may overwrite an fd that is
    //    still the source of another move (swaps, chains).
    for (slot, &(src, _)) in scratch.iter_mut().zip(&plan.moves) {
        *slot = ops.dup_at_least(src, plan.temp_base)?;
    }
    // 2. Place each copy at its target.
    for (&tmp, &(_, dst)) in scratch.iter().zip(&plan.moves) {
        ops.dup2(tmp, dst)?;
    }
    // 3. Drop the temporaries and everything else.
    for &tmp in scratch.iter() {
        ops.close(tmp);
    }
    for &(first, last) in &plan.close_ranges {
        ops.cloexec_range(first, last)?;
    }
    Ok(())
}

struct LibcFds;

impl FdOps for LibcFds {
    fn dup_at_least(&mut self, fd: RawFd, min: RawFd) -> io::Result<RawFd> {
        // SAFETY: fcntl on an int fd; async-signal-safe.
        let r = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, min) };
        if r < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(r)
        }
    }

    fn dup2(&mut self, src: RawFd, dst: RawFd) -> io::Result<()> {
        loop {
            // SAFETY: dup2 on int fds; async-signal-safe.
            if unsafe { libc::dup2(src, dst) } >= 0 {
                return Ok(());
            }
            let e = io::Error::last_os_error();
            if e.raw_os_error() != Some(libc::EINTR) {
                return Err(e);
            }
        }
    }

    fn close(&mut self, fd: RawFd) {
        // SAFETY: closes a temporary this plan created.
        unsafe { libc::close(fd) };
    }

    fn cloexec_range(&mut self, first: u32, last: u32) -> io::Result<()> {
        // SAFETY: close_range takes integers only; async-signal-safe.
        let r = unsafe {
            libc::syscall(
                libc::SYS_close_range,
                first,
                last,
                libc::CLOSE_RANGE_CLOEXEC,
            )
        };
        if r != 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}

/// `(st_dev, st_ino)` of an fd, to detect a source closed (and its number reused) before spawn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FdIdentity {
    dev: u64,
    ino: u64,
}

fn fd_identity(fd: RawFd) -> io::Result<FdIdentity> {
    let mut st = MaybeUninit::<libc::stat>::uninit();
    // SAFETY: fstat writes a stat into `st`; async-signal-safe.
    if unsafe { libc::fstat(fd, st.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fstat succeeded, so `st` is initialised.
    let st = unsafe { st.assume_init() };
    Ok(FdIdentity {
        dev: st.st_dev,
        ino: st.st_ino,
    })
}

/// Whether `fd` is a file on the cgroup v2 filesystem (`fstatfs`; async-signal-safe).
pub(crate) fn on_cgroup2(fd: RawFd) -> io::Result<bool> {
    let mut st = MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: fstatfs writes a statfs into `st`.
    if unsafe { libc::fstatfs(fd, st.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fstatfs succeeded, so `st` is initialised.
    let st = unsafe { st.assume_init() };
    Ok(st.f_type as u64 == CGROUP2_SUPER_MAGIC)
}

/// `fd` moved to the lowest free number >= 3, close-on-exec (the original is closed).
fn above_stdio(fd: OwnedFd) -> io::Result<OwnedFd> {
    if fd.as_raw_fd() >= 3 {
        return Ok(fd);
    }
    // SAFETY: fcntl on an fd we own; the result, when valid, is a new fd owned by nothing else.
    let r = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `r` was just created and is owned here alone.
    Ok(unsafe { OwnedFd::from_raw_fd(r) })
}

/// The hook body, run in the child between `fork` and `exec`: async-signal-safe and
/// allocation-free (only syscalls, and `io::Error`s built from errno).
fn child_setup(
    procs: RawFd,
    parent: libc::pid_t,
    plan: &FdPlan,
    identities: &[FdIdentity],
    scratch: &mut [RawFd],
) -> io::Result<()> {
    // 0, 1. Join the job cgroup before anything else (failing closed if `procs` is no longer its
    //    `cgroup.procs`: the write would leave the child in the miner's cgroup, uncapped).
    join_cgroup_in_child(procs)?;
    // SAFETY (whole block): plain syscalls on integers and stack memory.
    unsafe {
        // 2. No core dumps, no privilege gain through exec.
        let core = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::setrlimit(libc::RLIMIT_CORE, &core) != 0 {
            return Err(io::Error::last_os_error());
        }
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            return Err(io::Error::last_os_error());
        }
        // 3. Die with the parent; if it already died (we were reparented before the signal was
        //    armed), never run the sandboxed program.
        if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) != 0 {
            return Err(io::Error::last_os_error());
        }
        if libc::getppid() != parent {
            libc::_exit(127);
        }
        // 4. Start in `/`: the miner's working directory (a home or project path) is nothing a
        //    sandboxed process needs to see, and an escaped one could read it back with `getcwd`.
        if libc::chdir(c"/".as_ptr()) != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    // 5. Each source is still the object the caller handed us.
    for (&(src, _), want) in plan.moves.iter().zip(identities) {
        if fd_identity(src)? != *want {
            return Err(io::Error::from_raw_os_error(libc::EBADF));
        }
    }
    // 6. Fixed fd numbers; nothing else survives the exec.
    apply_plan(&mut LibcFds, plan, scratch)
}

/// Parent side: configures `cmd` so that its environment is only what the caller set on it, and
/// so that, between `fork` and `exec`, the child
/// 1. joins `cgroup` by writing `0` to its `cgroup.procs`, through an fd opened now, by the parent,
///    at a number >= 3 (std places the child's stdin, stdout and stderr on 0-2 before the hook runs),
///    after checking with `fstatfs` that the fd is still on cgroup2 (else the spawn fails);
/// 2. sets `RLIMIT_CORE=0` and `NO_NEW_PRIVS`;
/// 3. sets `PR_SET_PDEATHSIG(SIGKILL)`, then compares `getppid()` with this process's pid
///    (captured now) and `_exit(127)`s if they differ (the parent died before the signal was armed);
/// 4. changes its working directory to `/`, so nothing of the miner's (its home, its project
///    path) is visible through `getcwd`; this overrides `Command::current_dir`;
/// 5. checks that every source fd still refers to the file it referred to now (device and inode);
/// 6. places each `(source, target)` of `fds` at `target`: every source is first duplicated to a
///    temporary above the highest target, then `dup2`ed onto its target, so swaps and chains
///    (one pair's source is another's target) work;
/// 7. marks every other fd >= 3 close-on-exec with `close_range(.., CLOSE_RANGE_CLOEXEC)`, so the
///    new program starts with exactly fds 0–2 and the targets.
///
/// The hook is async-signal-safe and does not allocate (the plan and scratch space are built
/// here, in the parent).
///
/// # The environment
/// The child does **not** inherit the miner's environment, which may hold secrets (provider keys,
/// RPC URLs with credentials, `ZKMINER_*` settings) that a sandboxed process can read from its own
/// memory even though nothing else can (it is not dumpable). `prepare_command` calls
/// `Command::env_clear` and re-adds only the variables already set on `cmd` with `Command::env` or
/// `envs`; variables set after it are passed too. Set what the program needs (e.g. `RUST_LOG`)
/// explicitly, and give the program, and any path among its arguments, as an absolute path: there
/// is no `PATH`, and the child starts in `/`.
///
/// # Why this is equivalent to `clone3(CLONE_INTO_CGROUP)` here
/// The point of `CLONE_INTO_CGROUP` (plan §10.2) is that the caps apply before the sandboxed
/// program runs its first instruction. The hook achieves the same: the child migrates itself into
/// the job cgroup before `execve`, and until then it runs only this hook — trusted code from the
/// miner's image that allocates nothing. Every page the new program maps, every task it creates
/// and every CPU cycle it uses after `execve` is charged to the job cgroup (`memory.max`,
/// `pids.max`, `cpu.max` already apply). What differs is only the brief pre-exec window: the
/// forked child (copy-on-write pages shared with the miner, already charged to the miner) is
/// counted in the miner's cgroup until the write, which costs a migration and nothing in
/// isolation. std's `Command` cannot pass `CLONE_INTO_CGROUP`.
///
/// # Caller rules
/// - Sources must stay open until `spawn` returns (the hook duplicates them in the child); a
///   source closed or replaced in between fails the spawn with `EBADF`. Close the parent's copies
///   of child-side pipe ends after `spawn`, or the reader never sees EOF.
/// - Targets are distinct and in `3..=1023`, and the temporaries (just above the highest target)
///   must fit under the soft `RLIMIT_NOFILE`. Set fds 0–2 with `Command::stdin`/`stdout`/`stderr`,
///   to `/dev/null` or pipes, never the miner's terminal.
/// - `PR_SET_PDEATHSIG` fires when the *thread* that spawned the child exits, not the process:
///   spawn from a long-lived thread (a tokio `spawn_blocking` thread exits after 10 s idle and
///   would kill the child).
/// - Call it once per `Command`; the `Command` holds an fd to `cgroup.procs` until dropped.
/// - Every non-target fd is marked close-on-exec rather than closed, because std reports a failed
///   `exec` back to `spawn` through a close-on-exec socket that must stay open until then. If a
///   target happens to have that socket's number, an `exec` failure shows up as the child exiting
///   with status 1 instead of an error from `spawn`.
/// For a command with a launch hook of its own: an fd to `cgroup`'s `cgroup.procs`, opened now, by
/// the parent, above the standard descriptors and checked to be on cgroup2, for
/// [`join_cgroup_in_child`]. Keep it open until the command has been spawned.
pub fn cgroup_procs_fd(cgroup: &Cgroup) -> Result<OwnedFd, SandboxError> {
    let procs_path = cgroup.path().join("cgroup.procs");
    let cg_err = |e: io::Error| SandboxError::Cgroup(format!("{}: {e}", procs_path.display()));
    let procs: OwnedFd = std::fs::OpenOptions::new()
        .write(true)
        .open(&procs_path)
        .map_err(cg_err)?
        .into();
    // A parent with fd 0, 1 or 2 closed gets one of them here; in the child std would replace it
    // with a stdio fd before the hook writes to it.
    let procs = above_stdio(procs).map_err(cg_err)?;
    if !on_cgroup2(procs.as_raw_fd()).map_err(cg_err)? {
        return Err(SandboxError::Cgroup(format!(
            "{} is not on the cgroup2 filesystem",
            procs_path.display()
        )));
    }
    Ok(procs)
}

/// In a launch hook, between `fork` and `exec`: the child joins the cgroup whose `cgroup.procs` is
/// `procs` ([`cgroup_procs_fd`]) by writing "0" (the writing process). Async-signal-safe and
/// allocation-free. Fails closed if `procs` is no longer on cgroup2: std sets up fds 0-2 before
/// launch hooks run, and a write that lands in a pipe or /dev/null would leave the child where it
/// was.
pub fn join_cgroup_in_child(procs: RawFd) -> io::Result<()> {
    if !on_cgroup2(procs)? {
        return Err(io::Error::from_raw_os_error(libc::EBADF));
    }
    // SAFETY: a write of a static byte to an fd.
    match unsafe { libc::write(procs, b"0".as_ptr().cast(), 1) } {
        1 => Ok(()),
        0 => Err(io::Error::from_raw_os_error(libc::EIO)),
        _ => Err(io::Error::last_os_error()),
    }
}

pub fn prepare_command(
    cmd: &mut Command,
    cgroup: &Cgroup,
    fds: &[(BorrowedFd<'_>, RawFd)],
) -> Result<(), SandboxError> {
    let pairs: Vec<(RawFd, RawFd)> = fds
        .iter()
        .map(|(src, dst)| (src.as_raw_fd(), *dst))
        .collect();
    let plan = FdPlan::new(&pairs)?;
    let identities = pairs
        .iter()
        .map(|&(src, _)| fd_identity(src))
        .collect::<io::Result<Vec<_>>>()?;
    let procs = cgroup_procs_fd(cgroup)?;
    // Only what the caller set explicitly reaches the child (see "The environment").
    let explicit: Vec<(OsString, OsString)> = cmd
        .get_envs()
        .filter_map(|(k, v)| Some((k.to_owned(), v?.to_owned())))
        .collect();
    cmd.env_clear();
    cmd.envs(explicit);
    // Review r2 B1: the child's argv[0] is the program's file name, not its install path (the
    // kernel's AT_EXECFN still holds the path `execve` was given).
    let name = std::path::Path::new(cmd.get_program()).file_name().map(|n| n.to_owned());
    if let Some(name) = name {
        cmd.arg0(name);
    }
    let parent = std::process::id() as libc::pid_t;
    let mut scratch = vec![-1 as RawFd; plan.moves.len()];
    // SAFETY: the closure only makes async-signal-safe syscalls and does not allocate.
    unsafe {
        cmd.pre_exec(move || {
            child_setup(procs.as_raw_fd(), parent, &plan, &identities, &mut scratch)
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    /// A model fd table: number -> (object, close-on-exec).
    #[derive(Debug, Default, Clone)]
    struct Table(BTreeMap<RawFd, (u32, bool)>);

    impl Table {
        fn with(open: &[(RawFd, u32, bool)]) -> Self {
            Table(
                open.iter()
                    .map(|&(fd, obj, cloexec)| (fd, (obj, cloexec)))
                    .collect(),
            )
        }

        /// What survives `execve`.
        fn after_exec(&self) -> BTreeMap<RawFd, u32> {
            self.0
                .iter()
                .filter(|(_, (_, cloexec))| !cloexec)
                .map(|(&fd, &(obj, _))| (fd, obj))
                .collect()
        }
    }

    impl FdOps for Table {
        fn dup_at_least(&mut self, fd: RawFd, min: RawFd) -> io::Result<RawFd> {
            let (obj, _) = *self
                .0
                .get(&fd)
                .ok_or_else(|| io::Error::from_raw_os_error(libc::EBADF))?;
            let new = (min..).find(|n| !self.0.contains_key(n)).unwrap();
            self.0.insert(new, (obj, true));
            Ok(new)
        }

        fn dup2(&mut self, src: RawFd, dst: RawFd) -> io::Result<()> {
            let (obj, _) = *self
                .0
                .get(&src)
                .ok_or_else(|| io::Error::from_raw_os_error(libc::EBADF))?;
            self.0.insert(dst, (obj, false));
            Ok(())
        }

        fn close(&mut self, fd: RawFd) {
            self.0.remove(&fd);
        }

        fn cloexec_range(&mut self, first: u32, last: u32) -> io::Result<()> {
            for (fd, (_, cloexec)) in self.0.iter_mut() {
                if (first..=last).contains(&(*fd as u32)) {
                    *cloexec = true;
                }
            }
            Ok(())
        }
    }

    /// Runs `pairs` against `table` and returns what the new program sees.
    fn run(table: &mut Table, pairs: &[(RawFd, RawFd)]) -> BTreeMap<RawFd, u32> {
        let plan = FdPlan::new(pairs).unwrap();
        let mut scratch = vec![-1; pairs.len()];
        apply_plan(table, &plan, &mut scratch).unwrap();
        table.after_exec()
    }

    fn stdio() -> Vec<(RawFd, u32, bool)> {
        vec![(0, 100, false), (1, 101, false), (2, 102, false)]
    }

    #[test]
    fn plan_ranges() {
        let p = FdPlan::new(&[(10, 3), (11, 4), (12, 5), (13, 6), (14, 7)]).unwrap();
        assert_eq!(p.temp_base, 8);
        assert_eq!(p.close_ranges, vec![(8, u32::MAX)]);
        let p = FdPlan::new(&[(10, 5), (11, 9)]).unwrap();
        assert_eq!(p.temp_base, 10);
        assert_eq!(p.close_ranges, vec![(3, 4), (6, 8), (10, u32::MAX)]);
        let p = FdPlan::new(&[]).unwrap();
        assert_eq!(p.close_ranges, vec![(3, u32::MAX)]);
    }

    #[test]
    fn plan_rejects_bad_mappings() {
        assert!(FdPlan::new(&[(5, 2)]).is_err());
        assert!(FdPlan::new(&[(5, 0)]).is_err());
        assert!(FdPlan::new(&[(5, MAX_TARGET_FD + 1)]).is_err());
        assert!(FdPlan::new(&[(-1, 3)]).is_err());
        assert!(FdPlan::new(&[(5, 3), (6, 3)]).is_err());
        // One source at two targets is fine.
        assert!(FdPlan::new(&[(5, 3), (5, 4)]).is_ok());
    }

    #[test]
    fn swap() {
        let mut open = stdio();
        open.extend([(3, 1, false), (4, 2, false)]);
        let seen = run(&mut Table::with(&open), &[(3, 4), (4, 3)]);
        assert_eq!(
            seen,
            BTreeMap::from([(0, 100), (1, 101), (2, 102), (3, 2), (4, 1)])
        );
    }

    #[test]
    fn chain_and_identity() {
        // 3->4, 4->5, 5->6 (each target is the next pair's source), and 7 stays at 7.
        let mut open = stdio();
        open.extend([(3, 1, true), (4, 2, true), (5, 3, true), (7, 4, true)]);
        let seen = run(&mut Table::with(&open), &[(3, 4), (4, 5), (5, 6), (7, 7)]);
        assert_eq!(
            seen,
            BTreeMap::from([(0, 100), (1, 101), (2, 102), (4, 1), (5, 2), (6, 3), (7, 4)])
        );
    }

    #[test]
    fn runner_layout_from_scattered_sources() {
        // The runner's fixed layout (3 W pipe, 4 summary, 5 broker socket, 6 module, 7 context),
        // from parent fds that collide with it, plus leaks that must not survive: an inherited
        // fd without CLOEXEC (40), one inside the target range not mapped (3 is a source, but 8
        // is an unrelated leak), and a high one.
        let mut open = stdio();
        open.extend([
            (7, 11, false),
            (6, 12, false),
            (3, 13, false),
            (12, 14, false),
            (5, 15, false),
            (8, 66, false),
            (40, 77, false),
            (100_000, 88, false),
        ]);
        let seen = run(
            &mut Table::with(&open),
            &[(7, 3), (6, 4), (3, 5), (12, 6), (5, 7)],
        );
        assert_eq!(
            seen,
            BTreeMap::from([
                (0, 100),
                (1, 101),
                (2, 102),
                (3, 11),
                (4, 12),
                (5, 13),
                (6, 14),
                (7, 15)
            ])
        );
    }

    #[test]
    fn same_source_twice() {
        let mut open = stdio();
        open.push((9, 5, false));
        let seen = run(&mut Table::with(&open), &[(9, 3), (9, 4)]);
        assert_eq!(
            seen,
            BTreeMap::from([(0, 100), (1, 101), (2, 102), (3, 5), (4, 5)])
        );
    }

    #[test]
    fn closed_source_fails() {
        let plan = FdPlan::new(&[(9, 3)]).unwrap();
        let mut scratch = vec![-1];
        assert!(apply_plan(&mut Table::with(&stdio()), &plan, &mut scratch).is_err());
    }

    #[test]
    fn the_hook_refuses_a_procs_fd_that_is_not_on_cgroup2() {
        // What the child would hold if std had replaced the fd with /dev/null: the hook must fail
        // before writing anything (or setting any process attribute).
        let null = std::fs::OpenOptions::new()
            .write(true)
            .open("/dev/null")
            .unwrap();
        assert!(!on_cgroup2(null.as_raw_fd()).unwrap());
        let plan = FdPlan::new(&[]).unwrap();
        let parent = std::process::id() as libc::pid_t;
        let e = child_setup(null.as_raw_fd(), parent, &plan, &[], &mut []).unwrap_err();
        assert_eq!(e.raw_os_error(), Some(libc::EBADF));
        // A closed fd: fstatfs fails, so does the hook.
        assert!(child_setup(-1, parent, &plan, &[], &mut []).is_err());
    }

    #[test]
    fn cgroup2_files_are_recognised() {
        let Ok(mount) = crate::cgroup::cgroup2_mount() else {
            return;
        };
        let f = std::fs::File::open(mount.join("cgroup.controllers")).unwrap();
        assert!(on_cgroup2(f.as_raw_fd()).unwrap());
    }

    #[test]
    fn above_stdio_keeps_high_fds_and_moves_low_ones() {
        let f: OwnedFd = std::fs::File::open("/dev/null").unwrap().into();
        let n = f.as_raw_fd();
        assert!(n >= 3);
        assert_eq!(above_stdio(f).unwrap().as_raw_fd(), n);
        // A low fd cannot be produced here without closing the harness's stdio; the integration
        // test `prepare_command_survives_closed_stdio` covers that path.
    }

    #[test]
    fn scratch_mismatch_is_an_error_not_a_panic() {
        let plan = FdPlan::new(&[(9, 3)]).unwrap();
        assert!(apply_plan(&mut Table::default(), &plan, &mut []).is_err());
    }
}
