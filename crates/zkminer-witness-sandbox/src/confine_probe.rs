//! Live checks of [`crate::confine`] and [`crate::supervise`], run by the probe binary
//! (`zkminer-witness-sandbox-probe confined ...` / `supervised ...`) for `tests/confine.rs`: a
//! confinement can only be observed in a process of its own, and the supervisor forks, which needs a
//! single-threaded process (a test harness is not one).
//!
//! Every check prints one line, `CHECK <name> ok <detail>` or `CHECK <name> FAIL <detail>`; what
//! is only observed prints `NOTE <name> <detail>`.

use std::ffi::{CString, OsString};
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use crate::confine::{confine_all_threads, Confinement, Rights, Sockets};

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn check(name: &str, ok: bool, detail: impl std::fmt::Display) {
    println!("CHECK {name} {} {detail}", if ok { "ok" } else { "FAIL" });
    let _ = std::io::stdout().flush();
}

fn note(name: &str, detail: impl std::fmt::Display) {
    println!("NOTE {name} {detail}");
    let _ = std::io::stdout().flush();
}

fn cpath(p: &Path) -> CString {
    CString::new(p.as_os_str().as_bytes()).expect("no NUL in a test path")
}

/// The host's Unix sockets a guest that escaped its executor would pivot through: the session bus
/// (systemd --user's StartTransientUnit), the Docker daemon (root-equivalent, host networking),
/// systemd-resolved (the host's resolvers), the system bus, the user's systemd manager.
pub fn pivot_sockets() -> Vec<(&'static str, PathBuf)> {
    // SAFETY: getuid has no arguments.
    let uid = unsafe { libc::getuid() };
    vec![
        ("session_bus", PathBuf::from(format!("/run/user/{uid}/bus"))),
        ("docker", PathBuf::from("/run/docker.sock")),
        ("docker_var", PathBuf::from("/var/run/docker.sock")),
        (
            "resolved_varlink",
            PathBuf::from("/run/systemd/resolve/io.systemd.Resolve"),
        ),
        ("system_bus", PathBuf::from("/run/dbus/system_bus_socket")),
        (
            "systemd_user_private",
            PathBuf::from(format!("/run/user/{uid}/systemd/private")),
        ),
    ]
}

/// `connect` to the Unix stream socket at `path`: Ok, or the errno of the step that failed.
fn unix_connect(path: &Path) -> Result<libc::c_int, (&'static str, i32)> {
    // SAFETY: plain socket call.
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(("socket", errno()));
    }
    let rc = connect_fd(fd, path);
    if rc != 0 {
        // SAFETY: closing the fd just opened.
        unsafe { libc::close(fd) };
        return Err(("connect", rc));
    }
    Ok(fd)
}

/// `connect(fd, path)`: 0 or the errno.
fn connect_fd(fd: libc::c_int, path: &Path) -> i32 {
    // SAFETY: a zeroed sockaddr_un filled with a path shorter than sun_path.
    unsafe {
        let mut addr: libc::sockaddr_un = std::mem::zeroed();
        addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
        let bytes = path.as_os_str().as_bytes();
        if bytes.len() >= addr.sun_path.len() {
            return libc::ENAMETOOLONG;
        }
        for (i, b) in bytes.iter().enumerate() {
            addr.sun_path[i] = *b as libc::c_char;
        }
        let len = std::mem::size_of::<libc::sa_family_t>() + bytes.len() + 1;
        if libc::connect(fd, (&addr as *const libc::sockaddr_un).cast(), len as u32) == 0 {
            0
        } else {
            errno()
        }
    }
}

/// `open(path, flags)`: Ok(()) or the errno.
fn try_open(path: &Path, flags: libc::c_int) -> Result<(), i32> {
    let c = cpath(path);
    // SAFETY: a NUL-terminated path; the fd is closed.
    let fd = unsafe { libc::open(c.as_ptr(), flags | libc::O_CLOEXEC, 0o600) };
    if fd < 0 {
        return Err(errno());
    }
    // SAFETY: closing the fd just opened.
    unsafe { libc::close(fd) };
    Ok(())
}

/// Runs `path` (no arguments) and waits: its exit status, or the errno `execve` failed with in the
/// child (reported as exit code 100 + errno), or the fork's errno.
fn run(path: &Path) -> Result<(i32, String), i32> {
    let c = cpath(path);
    let argv = [c.as_ptr(), std::ptr::null()];
    let envp: [*const libc::c_char; 1] = [std::ptr::null()];
    // SAFETY: fork; the child only calls async-signal-safe functions.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(errno());
    }
    if pid == 0 {
        unsafe {
            libc::execve(c.as_ptr(), argv.as_ptr(), envp.as_ptr());
            libc::_exit(100 + *libc::__errno_location());
        }
    }
    let mut st = 0;
    // SAFETY: waiting for the child just forked.
    unsafe { libc::waitpid(pid, &mut st, 0) };
    let code = if libc::WIFEXITED(st) {
        libc::WEXITSTATUS(st)
    } else {
        -libc::WTERMSIG(st)
    };
    Ok((code, String::new()))
}

/// A raw syscall: its return value and errno.
fn sys(f: impl FnOnce() -> libc::c_long) -> (libc::c_long, i32) {
    let r = f();
    (r, if r < 0 { errno() } else { 0 })
}

/// Whether a call failed with exactly `want`, and how it went.
fn refused_with(r: libc::c_long, e: i32, want: i32) -> (bool, String) {
    (
        r < 0 && e == want,
        if r < 0 {
            format!("errno {e}")
        } else {
            format!("SUCCEEDED ({r})")
        },
    )
}

/// Namespaces, mounts and the rest of the kernel surface the filters take away: each call's
/// arguments would make it fail with another errno, or succeed harmlessly, without the filter
/// (`fsopen`, `fsmount`, `fspick` and `move_mount` check the capability first, so for them the
/// kernel's own answer is `EPERM` too). Then that threads and `posix_spawn` still work, through
/// libc's fallback from `clone3` to `clone`.
fn kernel_surface_checks(exec: Option<&Path>, mut report: impl FnMut(&str, bool, String)) {
    let m1 = -1 as libc::c_long;
    let null = std::ptr::null::<libc::c_char>();
    // SAFETY (every call below): arguments that make the call fail without side effects, or (for
    // the ones that would succeed unfiltered) a no-op unshare, an fd that is closed, a child that
    // exits at once.
    let calls: Vec<(&str, libc::c_long, i32)> = vec![
        {
            let (r, e) = sys(|| unsafe { libc::unshare(0) } as libc::c_long);
            ("unshare_none", r, e)
        },
        {
            let (r, e) = sys(|| unsafe { libc::unshare(libc::CLONE_NEWUSER) } as libc::c_long);
            ("unshare_newuser", r, e)
        },
        {
            let (r, e) = sys(|| {
                (unsafe { libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNET) }) as libc::c_long
            });
            ("unshare_newnet", r, e)
        },
        {
            let (r, e) = sys(|| unsafe { libc::setns(-1, 0) } as libc::c_long);
            ("setns", r, e)
        },
        {
            let (r, e) =
                sys(|| unsafe { libc::syscall(libc::SYS_mount, null, null, null, 0usize, null) });
            ("mount", r, e)
        },
        {
            let (r, e) = sys(|| unsafe { libc::umount2(c"/".as_ptr(), -1) } as libc::c_long);
            ("umount2", r, e)
        },
        {
            let (r, e) = sys(|| unsafe { libc::syscall(libc::SYS_pivot_root, null, null) });
            ("pivot_root", r, e)
        },
        {
            let (r, e) = sys(
                || unsafe { libc::chroot(c"/nonexistent-zkminer-probe".as_ptr()) } as libc::c_long,
            );
            ("chroot", r, e)
        },
        {
            let (r, e) = sys(|| unsafe { libc::syscall(libc::SYS_fsopen, null, m1) });
            ("fsopen", r, e)
        },
        {
            let (r, e) = sys(|| unsafe { libc::syscall(libc::SYS_fsconfig, m1, 0, null, null, 0) });
            ("fsconfig", r, e)
        },
        {
            let (r, e) = sys(|| unsafe { libc::syscall(libc::SYS_fsmount, m1, 0, 0) });
            ("fsmount", r, e)
        },
        {
            let (r, e) = sys(|| unsafe { libc::syscall(libc::SYS_fspick, m1, null, 0) });
            ("fspick", r, e)
        },
        {
            let (r, e) =
                sys(|| unsafe { libc::syscall(libc::SYS_move_mount, m1, null, m1, null, m1) });
            ("move_mount", r, e)
        },
        {
            let (r, e) = sys(|| unsafe { libc::syscall(libc::SYS_open_tree, m1, null, m1) });
            ("open_tree", r, e)
        },
        {
            let (r, e) = sys(|| unsafe {
                libc::syscall(crate::restrict::SYS_OPEN_TREE_ATTR, m1, null, m1, null, 0)
            });
            ("open_tree_attr", r, e)
        },
        {
            let (r, e) =
                sys(|| unsafe { libc::syscall(libc::SYS_mount_setattr, m1, null, m1, null, 0) });
            ("mount_setattr", r, e)
        },
        {
            // UFFD_USER_MODE_ONLY: what an unprivileged process may create.
            let (r, e) =
                sys(|| unsafe { libc::syscall(libc::SYS_userfaultfd, libc::O_CLOEXEC | 1) });
            if r >= 0 {
                unsafe { libc::close(r as libc::c_int) };
            }
            ("userfaultfd", r, e)
        },
        {
            let (r, e) =
                sys(|| unsafe { libc::syscall(libc::SYS_perf_event_open, null, 0, m1, m1, 0) });
            ("perf_event_open", r, e)
        },
        {
            let (r, e) = sys(|| unsafe {
                libc::syscall(libc::SYS_name_to_handle_at, m1, null, null, null, 0)
            });
            ("name_to_handle_at", r, e)
        },
        {
            let (r, e) = sys(|| unsafe { libc::syscall(libc::SYS_open_by_handle_at, m1, null, 0) });
            ("open_by_handle_at", r, e)
        },
    ];
    for (name, r, e) in calls {
        let (ok, detail) = refused_with(r, e, libc::EPERM);
        report(name, ok, detail);
    }
    for (name, flag) in crate::netdeny::CLONE_NEW_FLAGS {
        let flags = (flag | libc::SIGCHLD) as libc::c_ulong;
        // SAFETY: a fork-like clone (no CLONE_VM, no new stack); a child, if the filter let one
        // through, exits at once.
        let (r, e) = sys(|| unsafe { libc::syscall(libc::SYS_clone, flags, 0usize, 0, 0, 0) });
        if r == 0 {
            unsafe { libc::_exit(0) };
        }
        if r > 0 {
            let mut st = 0;
            unsafe { libc::waitpid(r as libc::pid_t, &mut st, 0) };
        }
        let (ok, detail) = refused_with(r, e, libc::EPERM);
        report(
            &format!(
                "clone_{}",
                name.trim_start_matches("CLONE_").to_ascii_lowercase()
            ),
            ok,
            detail,
        );
    }
    // SAFETY: clone3 with no arguments (EINVAL without the filter).
    let (r, e) = sys(|| unsafe { libc::syscall(libc::SYS_clone3, null, 0usize) });
    let (ok, detail) = refused_with(r, e, libc::ENOSYS);
    report("clone3_enosys", ok, detail);
    // What the GPU stack does keep: threads and posix_spawn, through libc's fallback to clone.
    let t = std::thread::spawn(|| 7).join();
    report(
        "thread_after_confinement",
        t.as_ref().is_ok_and(|v| *v == 7),
        format!("{t:?}"),
    );
    if let Some(exec) = exec {
        let r = std::process::Command::new(exec)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .status();
        report(
            "spawn_after_confinement",
            r.as_ref().is_ok_and(|s| s.success()),
            format!("{r:?}"),
        );
    }
}

/// Every way to signal `pid` besides `kill` (which the callers check): a thread of it
/// (`tgkill`), a queued signal (`rt_sigqueueinfo`, `rt_tgsigqueueinfo`), and through a pidfd
/// (`pidfd_send_signal`). Signal 0 throughout: nothing is sent even if one were allowed.
fn signal_checks(pid: libc::pid_t, who: &str, mut report: impl FnMut(&str, bool, String)) {
    // SAFETY: a zeroed siginfo with si_code SI_QUEUE, as sigqueue makes it.
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    info.si_code = -1; // SI_QUEUE
    let info_ptr = &info as *const libc::siginfo_t;
    // SAFETY: signal 0 to `pid`, with a valid siginfo.
    let calls = [
        (
            "tgkill",
            sys(|| unsafe { libc::syscall(libc::SYS_tgkill, pid, pid, 0) }),
        ),
        (
            "rt_sigqueueinfo",
            sys(|| unsafe { libc::syscall(libc::SYS_rt_sigqueueinfo, pid, 0, info_ptr) }),
        ),
        (
            "rt_tgsigqueueinfo",
            sys(|| unsafe { libc::syscall(libc::SYS_rt_tgsigqueueinfo, pid, pid, 0, info_ptr) }),
        ),
    ];
    for (name, (r, e)) in calls {
        let (ok, detail) = refused_with(r, e, libc::EPERM);
        report(&format!("{name}_{who}"), ok, detail);
    }
    // A pidfd of the process is not refused (it is inert); a signal through it is.
    // SAFETY: pidfd_open takes no pointers; the fd is closed.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    let (ok, detail) = if fd < 0 {
        (false, format!("pidfd_open errno {}", errno()))
    } else {
        // SAFETY: signal 0 through the pidfd just opened, no siginfo.
        let (r, e) = sys(|| unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                fd,
                0,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            )
        });
        unsafe { libc::close(fd as libc::c_int) };
        refused_with(r, e, libc::EPERM)
    };
    report(&format!("pidfd_send_signal_{who}"), ok, detail);
}

/// The name an SP1 executor gives the runner it unpacks, for a pid.
fn runner_temp_name(pid: u32) -> String {
    format!("sp1-native-runner-bin-{}.tmp.{pid}", "ab".repeat(32))
}

/// Before the confinement: a scratch file in `dir` (which the test owns and the confinement makes
/// writable), mode 0644, with a `user.zkminer` attribute where the filesystem keeps one, so that
/// every metadata write [`metadata_checks`] tries would succeed unconfined.
fn prepare_scratch(dir: &Path) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let scratch = dir.join("scratch");
    let _ = std::fs::write(&scratch, b"scratch\n");
    let _ = std::fs::set_permissions(&scratch, std::fs::Permissions::from_mode(0o644));
    let c = cpath(&scratch);
    // SAFETY: a NUL-terminated path, name and a one-byte value.
    let rc = unsafe {
        libc::setxattr(
            c.as_ptr(),
            c"user.zkminer".as_ptr(),
            b"1".as_ptr().cast(),
            1,
            0,
        )
    };
    note(
        "scratch_xattr",
        if rc == 0 {
            "set".to_string()
        } else {
            format!("errno {}", errno())
        },
    );
    scratch
}

/// What a scratch file's metadata is: mode, owner, mtime and its `user.zkminer` attribute.
fn metadata_of(p: &Path) -> (u32, u32, i64, i64, isize) {
    use std::os::unix::fs::MetadataExt;
    let m = std::fs::symlink_metadata(p).expect("the scratch file");
    let c = cpath(p);
    let mut buf = [0u8; 8];
    // SAFETY: a NUL-terminated path and name; `buf` has room for the value.
    let x = unsafe {
        libc::getxattr(
            c.as_ptr(),
            c"user.zkminer".as_ptr(),
            buf.as_mut_ptr().cast(),
            buf.len(),
        )
    };
    (m.mode() & 0o7777, m.uid(), m.mtime(), m.mtime_nsec(), x)
}

/// Metadata writes (mode, owner, extended attributes, times) on `scratch`, by path and through an
/// fd: arguments with which each would succeed unconfined. Each must fail with `EPERM`, and the
/// file must be as it was. Then the same on `key` (a file outside every writable path).
fn metadata_checks(scratch: &Path, key: &Path, mut report: impl FnMut(&str, bool, String)) {
    let before = metadata_of(scratch);
    let p = cpath(scratch);
    let pp = p.as_ptr();
    let name = c"user.zkminer".as_ptr();
    let value = b"2".as_ptr();
    let null = std::ptr::null::<libc::c_void>();
    let m1 = -1 as libc::c_long;
    let at = libc::AT_FDCWD as libc::c_long;
    // struct xattr_args { u64 value; u32 size; u32 flags; } for setxattrat.
    let xargs: [u64; 2] = [value as u64, 1];
    // SAFETY (every call): NUL-terminated paths and names, a one-byte value, NULL times (now).
    let mut calls: Vec<(&str, libc::c_long, i32)> = vec![];
    let mut add = |name: &'static str, f: &dyn Fn() -> libc::c_long| {
        let (r, e) = sys(f);
        calls.push((name, r, e));
    };
    add("fchmodat", &|| unsafe {
        libc::syscall(libc::SYS_fchmodat, at, pp, 0o600)
    });
    add("fchmodat2", &|| unsafe {
        libc::syscall(libc::SYS_fchmodat2, at, pp, 0o600, 0)
    });
    add("fchownat", &|| unsafe {
        libc::syscall(libc::SYS_fchownat, at, pp, m1, m1, 0)
    });
    add("setxattr", &|| unsafe {
        libc::syscall(libc::SYS_setxattr, pp, name, value, 1, 0)
    });
    add("lsetxattr", &|| unsafe {
        libc::syscall(libc::SYS_lsetxattr, pp, name, value, 1, 0)
    });
    add("setxattrat", &|| unsafe {
        libc::syscall(
            crate::restrict::SYS_SETXATTRAT,
            at,
            pp,
            0,
            name,
            xargs.as_ptr(),
            16,
        )
    });
    add("removexattr", &|| unsafe {
        libc::syscall(libc::SYS_removexattr, pp, name)
    });
    add("lremovexattr", &|| unsafe {
        libc::syscall(libc::SYS_lremovexattr, pp, name)
    });
    add("removexattrat", &|| unsafe {
        libc::syscall(crate::restrict::SYS_REMOVEXATTRAT, at, pp, 0, name)
    });
    add("utimensat_path", &|| unsafe {
        libc::syscall(libc::SYS_utimensat, at, pp, null, 0)
    });
    #[cfg(target_arch = "x86_64")]
    {
        add("chmod", &|| unsafe {
            libc::syscall(libc::SYS_chmod, pp, 0o600)
        });
        add("chown", &|| unsafe {
            libc::syscall(libc::SYS_chown, pp, m1, m1)
        });
        add("lchown", &|| unsafe {
            libc::syscall(libc::SYS_lchown, pp, m1, m1)
        });
        add("utime", &|| unsafe {
            libc::syscall(libc::SYS_utime, pp, null)
        });
        add("utimes", &|| unsafe {
            libc::syscall(libc::SYS_utimes, pp, null)
        });
        add("futimesat", &|| unsafe {
            libc::syscall(libc::SYS_futimesat, at, pp, null)
        });
    }
    // Through an fd of the file, opened for writing (which the confinement allows here).
    // SAFETY: opening the scratch file; the fd is closed below.
    let fd = unsafe { libc::open(pp, libc::O_RDWR | libc::O_CLOEXEC) } as libc::c_long;
    if fd < 0 {
        report("metadata_fd_open", false, format!("errno {}", errno()));
    } else {
        add("fchmod", &|| unsafe {
            libc::syscall(libc::SYS_fchmod, fd, 0o600)
        });
        add("fchown", &|| unsafe {
            libc::syscall(libc::SYS_fchown, fd, m1, m1)
        });
        add("fsetxattr", &|| unsafe {
            libc::syscall(libc::SYS_fsetxattr, fd, name, value, 1, 0)
        });
        add("fremovexattr", &|| unsafe {
            libc::syscall(libc::SYS_fremovexattr, fd, name)
        });
        add("futimens", &|| unsafe {
            libc::syscall(libc::SYS_utimensat, fd, null, null, 0)
        });
        // The ioctl forms: the file's current inode flags written back, its current extended
        // attributes written back (each a no-op unconfined), fs-verity.
        let mut flags: libc::c_long = 0;
        let flags_ptr = &mut flags as *mut libc::c_long;
        // SAFETY: FS_IOC_GETFLAGS into a long; allowed.
        unsafe { libc::ioctl(fd as libc::c_int, 0x8008_6601u64 as _, flags_ptr) };
        let mut fsx = [0u8; 28];
        let fsx_ptr = fsx.as_mut_ptr();
        // SAFETY: FS_IOC_FSGETXATTR into a struct fsxattr; allowed.
        unsafe { libc::ioctl(fd as libc::c_int, 0x801c_581fu64 as _, fsx_ptr) };
        add("ioctl_setflags", &|| unsafe {
            libc::syscall(
                libc::SYS_ioctl,
                fd,
                crate::restrict::FS_IOC_SETFLAGS,
                flags_ptr,
            )
        });
        add("ioctl_fssetxattr", &|| unsafe {
            libc::syscall(
                libc::SYS_ioctl,
                fd,
                crate::restrict::FS_IOC_FSSETXATTR,
                fsx_ptr,
            )
        });
        add("ioctl_enable_verity", &|| unsafe {
            libc::syscall(
                libc::SYS_ioctl,
                fd,
                crate::restrict::FS_IOC_ENABLE_VERITY,
                null,
            )
        });
        // SAFETY: closing the fd opened above.
        unsafe { libc::close(fd as libc::c_int) };
    }
    for (name, r, e) in calls {
        let (ok, detail) = refused_with(r, e, libc::EPERM);
        report(&format!("meta_{name}"), ok, detail);
    }
    let after = metadata_of(scratch);
    report(
        "metadata_unchanged",
        after == before,
        format!("before {before:?} after {after:?}"),
    );
    // A key file outside every writable path: its mode stays.
    let k = cpath(key);
    // A home without the key (the FUSE test's) only checks the refusal.
    let key_mode = || {
        std::fs::symlink_metadata(key).map(|m| {
            use std::os::unix::fs::MetadataExt;
            m.mode() & 0o7777
        })
    };
    let key_before = key_mode().ok();
    // SAFETY: a NUL-terminated path.
    let (r, e) = sys(|| unsafe { libc::syscall(libc::SYS_fchmodat, at, k.as_ptr(), 0o644) });
    let key_after = key_mode().ok();
    let (ok, detail) = refused_with(r, e, libc::EPERM);
    report(
        "meta_chmod_key",
        ok && key_before == key_after,
        format!("{detail}, mode {key_before:?} -> {key_after:?}"),
    );
}

/// Links, renames, removals, new directories and symlinks, and truncation outside the writable
/// path `write`, into `home` or out of it: Landlock's to refuse (`EACCES`, or `EXDEV` for a link or
/// rename that would cross into other rights). Each would succeed unconfined on these files.
fn namespace_checks(write: &Path, home: &Path, mut report: impl FnMut(&str, bool, String)) {
    let c = |p: PathBuf| cpath(&p);
    let _ = std::fs::write(write.join("to-move"), b"x");
    let bashrc = c(home.join(".bashrc"));
    let refused = |r: libc::c_long, e: i32| r < 0 && (e == libc::EACCES || e == libc::EXDEV);
    let detail = |r: libc::c_long, e: i32| {
        if r < 0 {
            format!("errno {e}")
        } else {
            "SUCCEEDED".to_string()
        }
    };
    let (src_w, dst_h) = (c(write.join("to-move")), c(home.join(".config/moved")));
    let (dst_w, sym_h) = (
        c(write.join("from-home")),
        c(home.join(".config/autostart/zk.desktop")),
    );
    let (dir_h, empty_h) = (
        c(home.join(".config/new-dir")),
        c(home.join(".config/systemd/user")),
    );
    // SAFETY (every call): NUL-terminated paths.
    let calls: Vec<(&str, (libc::c_long, i32))> = vec![
        (
            "link_into_home",
            sys(|| unsafe { libc::link(src_w.as_ptr(), dst_h.as_ptr()) } as libc::c_long),
        ),
        (
            "link_out_of_home",
            sys(|| unsafe { libc::link(bashrc.as_ptr(), dst_w.as_ptr()) } as libc::c_long),
        ),
        (
            "symlink_into_home",
            sys(|| unsafe { libc::symlink(c"/bin/sh".as_ptr(), sym_h.as_ptr()) } as libc::c_long),
        ),
        (
            "rename_into_home",
            sys(|| unsafe { libc::rename(src_w.as_ptr(), dst_h.as_ptr()) } as libc::c_long),
        ),
        (
            "rename_out_of_home",
            sys(|| unsafe { libc::rename(bashrc.as_ptr(), dst_w.as_ptr()) } as libc::c_long),
        ),
        (
            "unlink_home",
            sys(|| unsafe { libc::unlink(bashrc.as_ptr()) } as libc::c_long),
        ),
        (
            "rmdir_home",
            sys(|| unsafe { libc::rmdir(empty_h.as_ptr()) } as libc::c_long),
        ),
        (
            "mkdir_home",
            sys(|| unsafe { libc::mkdir(dir_h.as_ptr(), 0o700) } as libc::c_long),
        ),
        (
            "truncate_home",
            sys(|| unsafe { libc::truncate(bashrc.as_ptr(), 0) } as libc::c_long),
        ),
    ];
    for (name, (r, e)) in calls {
        report(&format!("ns_{name}"), refused(r, e), detail(r, e));
    }
}

/// A child that runs `f` and exits with its errno (0 for success): for calls that would change this
/// process itself unconfined (`setsid`, `setpgid`).
fn in_child(f: impl FnOnce() -> libc::c_long) -> (libc::c_long, i32) {
    // SAFETY: fork; the child makes one syscall and exits.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return (-1, errno());
    }
    if pid == 0 {
        let r = f();
        let e = if r < 0 { errno() } else { 0 };
        unsafe { libc::_exit(e) };
    }
    let mut st = 0;
    // SAFETY: waiting for the child just forked.
    unsafe { libc::waitpid(pid, &mut st, 0) };
    let e = if libc::WIFEXITED(st) {
        libc::WEXITSTATUS(st)
    } else {
        -1
    };
    (if e == 0 { 0 } else { -1 }, e)
}

/// Leaving the session or process group, and changing `pid`'s (another process's) limits,
/// priority, I/O priority and scheduling, each with the value it already has (a no-op unconfined):
/// all refused. The same for the caller itself (pid 0) stays allowed.
fn process_control_checks(pid: libc::pid_t, who: &str, mut report: impl FnMut(&str, bool, String)) {
    let p = pid as libc::c_long;
    let (r, e) = in_child(|| unsafe { libc::setsid() } as libc::c_long);
    let (ok, d) = refused_with(r, e, libc::EPERM);
    report("setsid", ok, d);
    let (r, e) = in_child(|| unsafe { libc::setpgid(0, 0) } as libc::c_long);
    let (ok, d) = refused_with(r, e, libc::EPERM);
    report("setpgid", ok, d);
    // SAFETY (every call): reading `pid`'s current values into local buffers, then writing them back.
    let mut lim = [0u64; 2];
    unsafe {
        libc::syscall(
            libc::SYS_prlimit64,
            p,
            libc::RLIMIT_NOFILE,
            std::ptr::null::<u64>(),
            lim.as_mut_ptr(),
        )
    };
    let lim_ptr = lim.as_ptr();
    let nice = unsafe { libc::getpriority(libc::PRIO_PROCESS, pid as libc::id_t) } as libc::c_long;
    let ioprio = unsafe { libc::syscall(libc::SYS_ioprio_get, 1, p) };
    let mut mask = [0u64; 16];
    unsafe {
        libc::syscall(
            libc::SYS_sched_getaffinity,
            p,
            std::mem::size_of_val(&mask),
            mask.as_mut_ptr(),
        )
    };
    let mask_ptr = mask.as_ptr();
    let param = [0i32; 1];
    let param_ptr = param.as_ptr();
    // struct sched_attr { u32 size; u32 policy; u64 flags; i32 nice; u32 priority; ... }, 48 bytes.
    let mut attr = [0u32; 12];
    attr[0] = 48;
    attr[4] = nice as u32;
    let attr_ptr = attr.as_ptr();
    let calls: Vec<(&str, (libc::c_long, i32))> = vec![
        (
            "prlimit64",
            sys(|| unsafe {
                libc::syscall(
                    libc::SYS_prlimit64,
                    p,
                    libc::RLIMIT_NOFILE,
                    lim_ptr,
                    std::ptr::null::<u64>(),
                )
            }),
        ),
        (
            "setpriority",
            sys(|| unsafe { libc::syscall(libc::SYS_setpriority, libc::PRIO_PROCESS, p, nice) }),
        ),
        (
            "ioprio_set",
            sys(|| unsafe { libc::syscall(libc::SYS_ioprio_set, 1, p, ioprio) }),
        ),
        (
            "sched_setaffinity",
            sys(|| unsafe { libc::syscall(libc::SYS_sched_setaffinity, p, 128usize, mask_ptr) }),
        ),
        (
            "sched_setscheduler",
            sys(|| unsafe { libc::syscall(libc::SYS_sched_setscheduler, p, 0, param_ptr) }),
        ),
        (
            "sched_setparam",
            sys(|| unsafe { libc::syscall(libc::SYS_sched_setparam, p, param_ptr) }),
        ),
        (
            "sched_setattr",
            sys(|| unsafe { libc::syscall(libc::SYS_sched_setattr, p, attr_ptr, 0) }),
        ),
    ];
    for (name, (r, e)) in calls {
        let (ok, d) = refused_with(r, e, libc::EPERM);
        report(&format!("{name}_{who}"), ok, d);
    }
    // One's own: allowed.
    let own_nice = unsafe { libc::getpriority(libc::PRIO_PROCESS, 0) } as libc::c_long;
    let (r, e) =
        sys(|| unsafe { libc::syscall(libc::SYS_setpriority, libc::PRIO_PROCESS, 0, own_nice) });
    report("setpriority_self", r == 0, format!("rc {r} errno {e}"));
}

static GOT_SIGUSR1: AtomicBool = AtomicBool::new(false);

extern "C" fn on_sigusr1(_: libc::c_int) {
    GOT_SIGUSR1.store(true, Ordering::SeqCst);
}

struct ConfinedArgs {
    home: PathBuf,
    write: PathBuf,
    exec: Option<PathBuf>,
    sockets: Sockets,
    /// A Unix listener of the test's, connected to before the confinement (`keep`) and after.
    listener: Option<PathBuf>,
    /// A socket to leave open before the confinement (`inet`, `unix-dgram`), which must fail it.
    leak: Option<String>,
    /// Keep a connection to a server this process starts itself, as an SP1 worker does.
    own_server: bool,
    /// A datagram socket of the test's: what a datagram pair could reach with `sendto`, and a
    /// seqpacket pair (allowed where pairs are kept) cannot.
    dgram: Option<PathBuf>,
}

fn parse_confined(args: &[OsString]) -> Result<ConfinedArgs, String> {
    let mut a = ConfinedArgs {
        home: PathBuf::new(),
        write: PathBuf::new(),
        exec: None,
        sockets: Sockets::None,
        listener: None,
        leak: None,
        own_server: false,
        dgram: None,
    };
    let mut it = args.iter();
    while let Some(flag) = it.next() {
        let mut value = || {
            it.next()
                .cloned()
                .ok_or_else(|| format!("{} needs a value", flag.to_string_lossy()))
        };
        match flag.to_str() {
            Some("--home") => a.home = value()?.into(),
            Some("--write") => a.write = value()?.into(),
            Some("--exec") => a.exec = Some(value()?.into()),
            Some("--listener") => a.listener = Some(value()?.into()),
            Some("--leak") => a.leak = Some(value()?.to_string_lossy().into_owned()),
            Some("--own-server") => a.own_server = true,
            Some("--dgram") => a.dgram = Some(value()?.into()),
            Some("--sockets") => {
                a.sockets = match value()?.to_str() {
                    Some("none") => Sockets::None,
                    Some("keep") => Sockets::KeepConnected,
                    other => return Err(format!("unknown sockets policy {other:?}")),
                }
            }
            other => return Err(format!("unknown flag {other:?}")),
        }
    }
    if a.home.as_os_str().is_empty() || a.write.as_os_str().is_empty() {
        return Err("--home and --write are required".into());
    }
    Ok(a)
}

/// `confined`: confine this process as an inline worker, then try every way out.
pub fn run_confined(args: &[OsString]) -> i32 {
    let a = match parse_confined(args) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("confined: {e}");
            return 64;
        }
    };
    // SAFETY: installing a handler that only stores to an atomic.
    unsafe { libc::signal(libc::SIGUSR1, on_sigusr1 as *const () as usize) };

    // A thread from before the confinement, which tries its way out when told to.
    let (go_tx, go_rx) = std::sync::mpsc::channel::<PathBuf>();
    let (res_tx, res_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let Ok(home) = go_rx.recv() else {
            return;
        };
        // SAFETY: plain socket call.
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
        let inet = if fd < 0 { errno() } else { 0 };
        let write = try_open(
            &home.join(".config/thread-was-here"),
            libc::O_WRONLY | libc::O_CREAT,
        );
        res_tx.send((inet, write)).unwrap();
    });

    // Before: which pivots are there to be refused.
    let pivots = pivot_sockets();
    for (name, path) in &pivots {
        match unix_connect(path) {
            Ok(fd) => {
                // SAFETY: closing the fd just opened.
                unsafe { libc::close(fd) };
                note(&format!("before_{name}"), "connect ok");
            }
            Err((step, e)) => note(&format!("before_{name}"), format!("{step} errno {e}")),
        }
    }
    let own_server = a.write.join("own.sock");
    if a.own_server {
        let listener = std::os::unix::net::UnixListener::bind(&own_server).unwrap();
        // SAFETY: fork; the child serves one connection and exits.
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            use std::io::Read;
            let code = match listener.accept() {
                Ok((mut conn, _)) => {
                    let mut buf = [0u8; 5];
                    if conn.read_exact(&mut buf).is_ok() && &buf == b"kept\n" {
                        println!("OWN SERVER GOT kept");
                        0
                    } else {
                        1
                    }
                }
                Err(_) => 1,
            };
            let _ = std::io::stdout().flush();
            // SAFETY: leaving the child.
            unsafe { libc::_exit(code) };
        }
        drop(listener);
    }
    let kept_target = if a.own_server {
        Some(own_server.clone())
    } else {
        a.listener.clone()
    };
    let kept = match (&kept_target, a.sockets) {
        (Some(l), Sockets::KeepConnected) => match unix_connect(l) {
            Ok(fd) => Some(fd),
            Err((step, e)) => {
                check("keep_connect_before", false, format!("{step} errno {e}"));
                return 1;
            }
        },
        _ => None,
    };

    if let Some(leak) = &a.leak {
        let (domain, kind) = match leak.as_str() {
            "inet" => (libc::AF_INET, libc::SOCK_DGRAM),
            _ => (libc::AF_UNIX, libc::SOCK_DGRAM),
        };
        // SAFETY: plain socket call; the fd is left open on purpose.
        let fd = unsafe { libc::socket(domain, kind, 0) };
        note("leaked", format!("{leak} fd {fd}"));
    }
    let scratch = prepare_scratch(&a.write);
    let runner = a.write.join(runner_temp_name(std::process::id()));
    let _ = std::fs::write(&runner, b"runner\n");
    let mut c = Confinement::with_system(a.sockets);
    if a.sockets == Sockets::KeepConnected {
        // As an SP1 worker: all of `/proc` (its executor reads its runner child's entries).
        c.allow("/proc", Rights::READ);
    }
    c.allow(&a.write, Rights::WRITE);
    if let Some(exec) = &a.exec {
        c.allow(exec, Rights::EXEC);
    }
    match confine_all_threads(&c) {
        Ok(report) => check("confine", true, report),
        Err(e) => {
            check("confine", false, e);
            return 1;
        }
    }

    for (name, path) in &pivots {
        let r = unix_connect(path);
        check(
            &format!("pivot_{name}"),
            matches!(r, Err((_, libc::EPERM))),
            match r {
                Ok(fd) => {
                    // SAFETY: closing the fd just opened.
                    unsafe { libc::close(fd) };
                    "CONNECTED".to_string()
                }
                Err((step, e)) => format!("{step} errno {e}"),
            },
        );
    }
    if let Some(l) = &a.listener {
        let r = unix_connect(l);
        check(
            "new_connection_to_listener",
            matches!(r, Err((_, libc::EPERM))),
            format!("{r:?}"),
        );
    }
    if let (Sockets::KeepConnected, Some(dgram)) = (a.sockets, &a.dgram) {
        seqpacket_pair_reaches_nothing(dgram);
    }
    if let Some(fd) = kept {
        // SAFETY: writing to the connection kept from before.
        let n = unsafe { libc::write(fd, b"kept\n".as_ptr().cast(), 5) };
        check("kept_connection_usable", n == 5, format!("write -> {n}"));
        if a.own_server {
            let mut st = 0;
            // SAFETY: waiting for the own server child.
            unsafe { libc::wait(&mut st) };
            check(
                "own_server_got_it",
                libc::WIFEXITED(st) && libc::WEXITSTATUS(st) == 0,
                format!("status {st:#x}"),
            );
        }
        // connect on an existing (unconnected) socket is refused too: nothing to make one with.
    }
    for (name, domain, kind) in [
        ("unix_stream", libc::AF_UNIX, libc::SOCK_STREAM),
        ("unix_dgram", libc::AF_UNIX, libc::SOCK_DGRAM),
        ("unix_seqpacket", libc::AF_UNIX, libc::SOCK_SEQPACKET),
        ("inet", libc::AF_INET, libc::SOCK_STREAM),
        ("inet6_udp", libc::AF_INET6, libc::SOCK_DGRAM),
        ("netlink", libc::AF_NETLINK, libc::SOCK_RAW),
    ] {
        // SAFETY: plain socket call.
        let fd = unsafe { libc::socket(domain, kind, 0) };
        let e = errno();
        check(
            &format!("socket_{name}"),
            fd < 0 && e == libc::EPERM,
            format!("fd {fd} errno {e}"),
        );
    }

    // The home directory: nothing to read or write but what is named.
    let home = &a.home;
    for (name, path, flags) in [
        (
            "write_config_autostart",
            home.join(".config/autostart/zk.desktop"),
            libc::O_WRONLY | libc::O_CREAT,
        ),
        (
            "write_config_systemd_unit",
            home.join(".config/systemd/user/zk.service"),
            libc::O_WRONLY | libc::O_CREAT,
        ),
        (
            "write_environment_d",
            home.join(".config/environment.d/zk.conf"),
            libc::O_WRONLY | libc::O_CREAT,
        ),
        (
            "append_bashrc",
            home.join(".bashrc"),
            libc::O_WRONLY | libc::O_APPEND,
        ),
        (
            "overwrite_prover",
            home.join(".zkminer/provers/zkminer-prove-risc0-cuda"),
            libc::O_WRONLY | libc::O_TRUNC,
        ),
        (
            "write_miner_config",
            home.join(".zkminer/config.toml"),
            libc::O_WRONLY | libc::O_TRUNC,
        ),
        (
            "read_key",
            home.join(".zkminer/keystore.json"),
            libc::O_RDONLY,
        ),
        ("read_ssh_key", home.join(".ssh/id_ed25519"), libc::O_RDONLY),
        (
            "write_tmp",
            PathBuf::from("/tmp/zkminer-confine-probe-must-not-exist"),
            libc::O_WRONLY | libc::O_CREAT,
        ),
        (
            "write_dev_shm",
            PathBuf::from("/dev/shm/zkminer-confine-probe-must-not-exist"),
            libc::O_WRONLY | libc::O_CREAT,
        ),
    ] {
        let r = try_open(&path, flags);
        check(
            name,
            r == Err(libc::EACCES),
            format!("{} -> {r:?}", path.display()),
        );
    }
    let own = a.write.join("allowed");
    let r = try_open(&own, libc::O_WRONLY | libc::O_CREAT);
    check("write_own_dir", r.is_ok(), format!("{r:?}"));
    let fifo = cpath(&a.write.join("fifo"));
    // SAFETY: a NUL-terminated path.
    let rc = unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) };
    let e = errno();
    check(
        "mkfifo_refused",
        rc != 0 && (e == libc::EPERM || e == libc::EACCES),
        format!("errno {e}"),
    );
    let r = try_open(Path::new("/etc/hostname"), libc::O_RDONLY);
    check(
        "read_system_file",
        r.is_ok() || r == Err(libc::ENOENT),
        format!("{r:?}"),
    );

    // Other processes: the parent (the test, standing in for the miner).
    // SAFETY: getppid; kill with signal 0 and SIGTERM send nothing that is not refused.
    let parent = unsafe { libc::getppid() };
    let rc = unsafe { libc::kill(parent, 0) };
    let e = errno();
    check(
        "signal_parent_0",
        rc != 0 && e == libc::EPERM,
        format!("rc {rc} errno {e}"),
    );
    let rc = unsafe { libc::kill(parent, libc::SIGTERM) };
    let e = errno();
    check(
        "signal_parent_term",
        rc != 0 && e == libc::EPERM,
        format!("rc {rc} errno {e}"),
    );
    for f in ["environ", "mem", "maps"] {
        let r = try_open(Path::new(&format!("/proc/{parent}/{f}")), libc::O_RDONLY);
        check(
            &format!("proc_parent_{f}"),
            r == Err(libc::EACCES),
            format!("{r:?}"),
        );
    }
    // Without all of `/proc` (the inline workers but SP1's), another process's command line and
    // status are out of reach too; this process's own entries are not.
    if a.sockets == Sockets::None {
        for f in ["cmdline", "status", "stat"] {
            let r = try_open(Path::new(&format!("/proc/{parent}/{f}")), libc::O_RDONLY);
            check(
                &format!("proc_parent_{f}"),
                r == Err(libc::EACCES),
                format!("{r:?}"),
            );
        }
        let r = try_open(Path::new("/proc/1/cmdline"), libc::O_RDONLY);
        check(
            "proc_init_cmdline",
            r == Err(libc::EACCES),
            format!("{r:?}"),
        );
    }
    for f in [
        "/proc/self/status",
        "/proc/thread-self/stat",
        "/proc/cpuinfo",
    ] {
        let r = try_open(Path::new(f), libc::O_RDONLY);
        check(
            &format!("read_{}", f.trim_start_matches('/').replace('/', "_")),
            r.is_ok(),
            format!("{r:?}"),
        );
    }
    // SAFETY: an invalid ptrace request; refused by the filter before the kernel looks.
    let rc = unsafe { libc::ptrace(libc::PTRACE_ATTACH, parent, 0, 0) };
    let e = errno();
    check(
        "ptrace_parent",
        rc != 0 && e == libc::EPERM,
        format!("errno {e}"),
    );
    signal_checks(parent, "parent", |n, ok, d| check(n, ok, d));
    process_control_checks(parent, "parent", |n, ok, d| check(n, ok, d));
    // SAFETY: an io_uring setup with no params; refused by the filter.
    let rc = unsafe { libc::syscall(libc::SYS_io_uring_setup, 1, std::ptr::null_mut::<u8>()) };
    let e = errno();
    check("io_uring", rc < 0 && e == libc::EPERM, format!("errno {e}"));
    kernel_surface_checks(a.exec.as_deref(), |n, ok, d| check(n, ok, d));
    metadata_checks(&scratch, &a.home.join(".ssh/id_ed25519"), |n, ok, d| {
        check(n, ok, d)
    });
    // No supervisor here: even the executor's runner may not be made executable.
    let rc = cpath(&runner);
    // SAFETY: a NUL-terminated path.
    let (r, e) =
        sys(|| unsafe { libc::syscall(libc::SYS_fchmodat, libc::AT_FDCWD, rc.as_ptr(), 0o755) });
    let (ok, detail) = refused_with(r, e, libc::EPERM);
    check("runner_chmod_refused", ok, detail);
    namespace_checks(&a.write, &a.home, |n, ok, d| check(n, ok, d));

    // The thread from before.
    go_tx.send(home.clone()).unwrap();
    let (inet, write) = res_rx.recv().unwrap();
    check(
        "old_thread_socket",
        inet == libc::EPERM,
        format!("errno {inet}"),
    );
    check(
        "old_thread_home_write",
        write == Err(libc::EACCES),
        format!("{write:?}"),
    );

    // Programs: only what was named runs, and it inherits all of it.
    let r = run(Path::new("/usr/bin/true"));
    check(
        "exec_unnamed",
        r == Ok((100 + libc::EACCES, String::new())),
        format!("{r:?}"),
    );
    if let Some(exec) = &a.exec {
        let r = run(exec);
        check(
            "exec_named",
            r.as_ref().is_ok_and(|(c, _)| *c == 0),
            format!("{r:?}"),
        );
    }

    println!("CONFINED CHECKS DONE");
    let _ = std::io::stdout().flush();
    // The test signals this process now: the miner can still reach its workers.
    for _ in 0..300 {
        if GOT_SIGUSR1.load(Ordering::SeqCst) {
            println!("GOT SIGUSR1");
            return 0;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    println!("NO SIGUSR1");
    2
}

/// `supervised <socket> <home> <write>`: run this binary's `supervised-child` under the supervisor,
/// as an SP1 worker runs `sp1-gpu-server`.
pub fn run_supervised_parent(args: &[OsString]) -> i32 {
    let [socket, home, write] = args else {
        eprintln!("supervised: <socket> <home> <write>");
        return 64;
    };
    let socket = PathBuf::from(socket);
    let Some(dir) = socket.parent() else {
        return 64;
    };
    let exe = match std::env::current_exe() {
        Ok(e) => e,
        Err(e) => {
            eprintln!("supervised: {e}");
            return 1;
        }
    };
    // What the server's checks work on, made while nothing is confined: a scratch file, a runner
    // file as SP1's executor unpacks one, and a file that is not one.
    let write_dir = Path::new(write);
    prepare_scratch(write_dir);
    for f in [runner_temp_name(1), "not-a-runner".to_string()] {
        use std::os::unix::fs::PermissionsExt;
        let f = write_dir.join(f);
        let _ = std::fs::write(&f, b"x");
        let _ = std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o644));
    }
    let mut c = Confinement::with_system(Sockets::Supervised);
    // As sp1-gpu-server: all of `/proc`.
    c.allow("/proc", Rights::READ);
    c.allow(dir, Rights::MAKE_SOCK);
    c.allow(write, Rights::WRITE);
    c.allow(&exe, Rights::EXEC);
    println!("SUPERVISOR {}", std::process::id());
    let _ = std::io::stdout().flush();
    match crate::supervise::run_supervised(
        &exe,
        &[
            "supervised-child".into(),
            socket.into_os_string(),
            home.clone(),
            write.clone(),
        ],
        &c,
        Some(Path::new(write)),
    ) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("supervised: {e}");
            1
        }
    }
}

/// `supervised-child <socket> <home> <write>`: the server's part. Listens at `<socket>`, accepts
/// one connection, then tries its way out and reports each check on stdout and on the connection.
/// `<write>` is its writable directory, where its supervisor makes runner files executable.
pub fn run_supervised_child(args: &[OsString]) -> i32 {
    let [socket, home, write] = args else {
        return 64;
    };
    let socket = PathBuf::from(socket);
    let home = PathBuf::from(home);
    let write = PathBuf::from(write);
    // SAFETY: getpid has no arguments.
    println!("SERVER {}", unsafe { libc::getpid() });
    // Before the first connection: a CUDA-style seqpacket listener, then its own.
    // SAFETY: plain socket calls.
    let pre = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC, 0) };
    check(
        "pre_accept_seqpacket_socket",
        pre >= 0,
        format!("fd {pre} errno {}", errno()),
    );
    let inet = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
    let e = errno();
    check(
        "pre_accept_inet_refused",
        inet < 0 && e == libc::EPERM,
        format!("errno {e}"),
    );
    let dgram = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_DGRAM, 0) };
    let e = errno();
    check(
        "pre_accept_dgram_refused",
        dgram < 0 && e == libc::EPERM,
        format!("errno {e}"),
    );
    for (name, path) in pivot_sockets() {
        if !path.exists() {
            continue;
        }
        let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
        let rc = connect_fd(fd, &path);
        check(
            &format!("pre_accept_connect_{name}"),
            rc == libc::EPERM,
            format!("errno {rc}"),
        );
        unsafe { libc::close(fd) };
    }
    let lfd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if lfd < 0 {
        check("listen", false, format!("socket errno {}", errno()));
        return 1;
    }
    // SAFETY: a sockaddr_un filled with a short path.
    let bound = unsafe {
        let mut addr: libc::sockaddr_un = std::mem::zeroed();
        addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
        for (i, b) in socket.as_os_str().as_bytes().iter().enumerate() {
            addr.sun_path[i] = *b as libc::c_char;
        }
        libc::bind(
            lfd,
            (&addr as *const libc::sockaddr_un).cast(),
            std::mem::size_of::<libc::sockaddr_un>() as u32,
        ) == 0
            && libc::listen(lfd, 4) == 0
    };
    check("listen", bound, format!("errno {}", errno()));
    if !bound {
        return 1;
    }
    println!("LISTENING");
    let _ = std::io::stdout().flush();
    // SAFETY: accepting on our listener.
    let conn = unsafe {
        libc::accept4(
            lfd,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            libc::SOCK_CLOEXEC,
        )
    };
    if conn < 0 {
        check("accept", false, format!("errno {}", errno()));
        return 1;
    }
    let mut lines: Vec<String> = Vec::new();
    let mut report = |name: &str, ok: bool, detail: String| {
        check(name, ok, &detail);
        lines.push(format!(
            "CHECK {name} {} {detail}\n",
            if ok { "ok" } else { "FAIL" }
        ));
    };
    // After the first connection: no new socket, bind or listen.
    for (name, domain, kind) in [
        ("unix_stream", libc::AF_UNIX, libc::SOCK_STREAM),
        ("unix_seqpacket", libc::AF_UNIX, libc::SOCK_SEQPACKET),
        ("inet", libc::AF_INET, libc::SOCK_STREAM),
    ] {
        let fd = unsafe { libc::socket(domain, kind, 0) };
        let e = errno();
        report(
            &format!("post_accept_socket_{name}"),
            fd < 0 && e == libc::EPERM,
            format!("fd {fd} errno {e}"),
        );
    }
    // The seqpacket socket from before cannot be bound or made to listen now.
    let rc = unsafe { libc::listen(pre, 4) };
    let e = errno();
    report(
        "post_accept_listen",
        rc != 0 && e == libc::EPERM,
        format!("errno {e}"),
    );
    let abstract_bound = unsafe {
        let mut addr: libc::sockaddr_un = std::mem::zeroed();
        addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
        let name = b"\0zkminer-probe-abstract";
        for (i, b) in name.iter().enumerate() {
            addr.sun_path[i] = *b as libc::c_char;
        }
        libc::bind(
            pre,
            (&addr as *const libc::sockaddr_un).cast(),
            (2 + name.len()) as u32,
        )
    };
    let e = errno();
    report(
        "post_accept_bind_abstract",
        abstract_bound != 0 && e == libc::EPERM,
        format!("errno {e}"),
    );
    let rc = connect_fd(pre, &socket);
    report(
        "post_accept_connect",
        rc == libc::EPERM,
        format!("errno {rc}"),
    );
    let mut pair = [-1; 2];
    let rc = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, pair.as_mut_ptr()) };
    report(
        "stream_pair_allowed",
        rc == 0,
        format!("rc {rc} errno {}", errno()),
    );
    let rc = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM, 0, pair.as_mut_ptr()) };
    let e = errno();
    report(
        "dgram_pair_refused",
        rc != 0 && e == libc::EPERM,
        format!("errno {e}"),
    );
    // No notifying filter of its own, to answer in the supervisor's place.
    let prog = crate::netdeny::notify_filter();
    let fprog = libc::sock_fprog {
        len: prog.len() as u16,
        filter: prog.as_ptr() as *mut libc::sock_filter,
    };
    let rc = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            1,
            crate::netdeny::SECCOMP_FILTER_FLAG_NEW_LISTENER,
            &fprog,
        )
    };
    let e = errno();
    report(
        "own_listener_refused",
        rc < 0 && (e == libc::EPERM || e == libc::EBUSY),
        format!("errno {e}"),
    );
    // The supervisor and the home directory are out of reach.
    let sup = unsafe { libc::getppid() };
    let rc = unsafe { libc::kill(sup, 0) };
    let e = errno();
    report(
        "signal_supervisor",
        rc != 0 && e == libc::EPERM,
        format!("errno {e}"),
    );
    signal_checks(sup, "supervisor", &mut report);
    process_control_checks(sup, "supervisor", &mut report);
    let r = try_open(Path::new(&format!("/proc/{sup}/environ")), libc::O_RDONLY);
    report(
        "proc_supervisor_environ",
        r == Err(libc::EACCES),
        format!("{r:?}"),
    );
    kernel_surface_checks(None, &mut report);
    // Mode changes go to the supervisor: a runner file the executor unpacked becomes executable,
    // nothing else does, and no other mode is given.
    {
        use std::os::unix::fs::MetadataExt;
        let mode = |p: &Path| {
            std::fs::symlink_metadata(p)
                .map(|m| m.mode() & 0o7777)
                .unwrap_or(0)
        };
        let runner = write.join(runner_temp_name(1));
        let other = write.join("not-a-runner");
        let (rp, op) = (cpath(&runner), cpath(&other));
        // SAFETY: NUL-terminated paths.
        let (r, e) = sys(|| unsafe {
            libc::syscall(libc::SYS_fchmodat, libc::AT_FDCWD, rp.as_ptr(), 0o755)
        });
        report(
            "runner_made_executable_by_supervisor",
            r == 0 && mode(&runner) == 0o755,
            format!("rc {r} errno {e} mode {:o}", mode(&runner)),
        );
        let (r, e) = sys(|| unsafe {
            libc::syscall(libc::SYS_fchmodat, libc::AT_FDCWD, op.as_ptr(), 0o755)
        });
        report(
            "other_file_not_made_executable",
            mode(&other) == 0o644,
            format!("rc {r} errno {e} mode {:o}", mode(&other)),
        );
        let (r, e) = sys(|| unsafe {
            libc::syscall(libc::SYS_fchmodat, libc::AT_FDCWD, rp.as_ptr(), 0o666)
        });
        let (ok, detail) = refused_with(r, e, libc::EPERM);
        report(
            "runner_other_mode_refused",
            ok && mode(&runner) == 0o755,
            detail,
        );
    }
    metadata_checks(
        &write.join("scratch"),
        &home.join(".ssh/id_ed25519"),
        &mut report,
    );
    namespace_checks(&write, &home, &mut report);
    let r = try_open(
        &home.join(".config/autostart/zk.desktop"),
        libc::O_WRONLY | libc::O_CREAT,
    );
    report(
        "write_config_autostart",
        r == Err(libc::EACCES),
        format!("{r:?}"),
    );
    let r = try_open(
        Path::new("/tmp/zkminer-confine-probe-must-not-exist"),
        libc::O_WRONLY | libc::O_CREAT,
    );
    report("write_tmp", r == Err(libc::EACCES), format!("{r:?}"));
    // Starting a helper the way Rust's `Command` does when code runs before `exec` (fork, a
    // seqpacket pair to report a failed exec, the parent-death signal): as sp1-gpu-server starts
    // its Groth16 CPU helper, which is itself.
    {
        use std::os::unix::process::CommandExt;
        let mut cmd = std::process::Command::new("/proc/self/exe");
        cmd.arg("noop").stdin(std::process::Stdio::null());
        // SAFETY: prctl is async-signal-safe.
        unsafe {
            cmd.pre_exec(|| {
                if libc::prctl(
                    libc::PR_SET_PDEATHSIG,
                    libc::SIGKILL as libc::c_ulong,
                    0,
                    0,
                    0,
                ) != 0
                {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let r = cmd.status();
        report(
            "spawn_own_helper",
            r.as_ref().is_ok_and(|s| s.success()),
            format!("{r:?}"),
        );
    }
    let stdin_null = std::fs::read_link("/proc/self/fd/0")
        .map(|p| p == Path::new("/dev/null"))
        .unwrap_or(false);
    report("stdin_is_dev_null", stdin_null, String::new());
    lines.push("DONE\n".into());
    for l in &lines {
        // SAFETY: writing to the accepted connection.
        unsafe { libc::write(conn, l.as_ptr().cast(), l.len()) };
    }
    unsafe { libc::close(conn) };
    println!("SERVER DONE");
    let _ = std::io::stdout().flush();
    // Stay up until killed, if asked to (`ZKMINER_PROBE_LINGER`), for the parent-death test.
    if std::env::var_os("ZKMINER_PROBE_LINGER").is_some() {
        loop {
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
    }
    0
}

/// A seqpacket pair (allowed where pairs are kept): `sendto` with the address of the test's datagram
/// socket delivers to the pair's other end; the test checks its socket got nothing.
fn seqpacket_pair_reaches_nothing(dgram_path: &Path) {
    let mut pair = [-1; 2];
    // SAFETY: `pair` has room for the two fds.
    let rc = unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
            0,
            pair.as_mut_ptr(),
        )
    };
    if rc != 0 {
        check(
            "seqpacket_pair_reaches_only_its_peer",
            false,
            format!("socketpair errno {}", errno()),
        );
        return;
    }
    // SAFETY: a sockaddr_un with the datagram socket's path, and a short message.
    let sent = unsafe {
        let mut addr: libc::sockaddr_un = std::mem::zeroed();
        addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
        for (i, b) in dgram_path.as_os_str().as_bytes().iter().enumerate() {
            addr.sun_path[i] = *b as libc::c_char;
        }
        libc::sendto(
            pair[0],
            b"leak".as_ptr().cast(),
            4,
            0,
            (&addr as *const libc::sockaddr_un).cast(),
            std::mem::size_of::<libc::sockaddr_un>() as u32,
        )
    };
    let mut buf = [0u8; 16];
    // SAFETY: a non-blocking read of the pair's other end.
    let n = unsafe {
        libc::recv(
            pair[1],
            buf.as_mut_ptr().cast(),
            buf.len(),
            libc::MSG_DONTWAIT,
        )
    };
    check(
        "seqpacket_pair_reaches_only_its_peer",
        n == 4,
        format!("sendto -> {sent}, the pair's other end got {n}"),
    );
    // SAFETY: the two fds just opened.
    unsafe {
        libc::close(pair[0]);
        libc::close(pair[1]);
    }
}
