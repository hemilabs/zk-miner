//! The fault seam: every mutating syscall the store makes (and every open, for read-side faults
//! and hooks) calls [`hit`] first. Outside `cargo test` it is an empty inline function and the
//! path closure is never called. Under test, a [`Faults`] installed on the current thread can fail
//! a matching call with an errno, crash the "process" at its k-th mutating call (that call and
//! every later one fail without touching the disk), record a trace, or run a one-shot hook just
//! before a matching call (to interleave another store call deterministically).

use std::io;
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Op {
    /// Opening a directory or a file read-only, or listing a directory (not a mutation).
    Open,
    Create,
    Write,
    Chmod,
    Fsync,
    Rename,
    Link,
    Mkdir,
    Unlink,
    Rmdir,
}

#[cfg(not(test))]
#[inline(always)]
pub(crate) fn hit(_op: Op, _path: impl FnOnce() -> PathBuf) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
pub(crate) fn hit(op: Op, path: impl FnOnce() -> PathBuf) -> io::Result<()> {
    match imp::current() {
        Some(f) => f.hit(op, &path().to_string_lossy()),
        None => Ok(()),
    }
}

#[cfg(test)]
pub(crate) use imp::{install, Faults};

#[cfg(test)]
mod imp {
    use std::cell::RefCell;
    use std::io;
    use std::rc::Rc;
    use std::sync::Mutex;

    use super::Op;

    struct Rule {
        op: Op,
        sub: String,
        errno: i32,
        skip: u32,
        count: u32,
    }

    type HookFn = Box<dyn FnOnce()>;

    struct Hook {
        op: Op,
        sub: String,
        f: HookFn,
    }

    #[derive(Default)]
    struct S {
        rules: Vec<Rule>,
        hooks: Vec<Hook>,
        crash_at: Option<u64>,
        steps: u64,
        crashed: bool,
        tracing: bool,
        trace: Vec<String>,
    }

    /// One test's fault plan. It lives on the installing thread (hooks are not `Send`).
    #[derive(Default)]
    pub(crate) struct Faults(Mutex<S>);

    thread_local! {
        static CURRENT: RefCell<Option<Rc<Faults>>> = const { RefCell::new(None) };
    }

    pub(super) fn current() -> Option<Rc<Faults>> {
        CURRENT.with(|c| c.borrow().clone())
    }

    /// Installs a fresh plan on this thread until the guard is dropped.
    pub(crate) fn install() -> Installed {
        let f = Rc::new(Faults::default());
        CURRENT.with(|c| *c.borrow_mut() = Some(Rc::clone(&f)));
        Installed(f)
    }

    pub(crate) struct Installed(Rc<Faults>);

    impl std::ops::Deref for Installed {
        type Target = Faults;
        fn deref(&self) -> &Faults {
            &self.0
        }
    }

    impl Drop for Installed {
        fn drop(&mut self) {
            CURRENT.with(|c| *c.borrow_mut() = None);
        }
    }

    impl Faults {
        fn s(&self) -> std::sync::MutexGuard<'_, S> {
            self.0.lock().unwrap_or_else(|e| e.into_inner())
        }

        /// The `count` calls of `op` whose path contains `sub`, after skipping `skip` of them,
        /// fail with `errno` without being made.
        pub(crate) fn fail(&self, op: Op, sub: &str, errno: i32, skip: u32, count: u32) {
            self.s().rules.push(Rule { op, sub: sub.into(), errno, skip, count });
        }

        /// The `k`-th mutating call (1-based) and every later one fail with EIO without being
        /// made: a process crash just before step `k`.
        pub(crate) fn crash_at(&self, k: u64) {
            let mut s = self.s();
            s.crash_at = Some(k);
            s.steps = 0;
            s.crashed = false;
        }

        pub(crate) fn crashed(&self) -> bool {
            self.s().crashed
        }

        /// Runs `f` once, just before the first call of `op` whose path contains `sub`.
        pub(crate) fn hook(&self, op: Op, sub: &str, f: impl FnOnce() + 'static) {
            self.s().hooks.push(Hook { op, sub: sub.into(), f: Box::new(f) });
        }

        pub(crate) fn trace(&self, on: bool) {
            self.s().tracing = on;
        }

        /// The recorded calls since the last take, as `"<op> <path>[ => errno]"`.
        pub(crate) fn take_trace(&self) -> Vec<String> {
            std::mem::take(&mut self.s().trace)
        }

        /// The mutating calls in the trace.
        pub(crate) fn take_mutations(&self) -> Vec<String> {
            self.take_trace().into_iter().filter(|l| !l.starts_with("Open ")).collect()
        }

        pub(super) fn hit(&self, op: Op, path: &str) -> io::Result<()> {
            let hook = {
                let mut s = self.s();
                let i = s.hooks.iter().position(|h| h.op == op && path.contains(&h.sub));
                i.map(|i| s.hooks.remove(i).f)
            };
            if let Some(f) = hook {
                // Without the plan's lock: the hook calls back into the store.
                f();
            }
            let mut s = self.s();
            let mut fail = None;
            if op != Op::Open {
                if s.crashed {
                    fail = Some(libc::EIO);
                } else if s.crash_at.is_some() {
                    s.steps += 1;
                    if Some(s.steps) == s.crash_at {
                        s.crashed = true;
                        fail = Some(libc::EIO);
                    }
                }
            }
            if fail.is_none() {
                for r in s.rules.iter_mut().filter(|r| r.op == op && r.count > 0 && path.contains(&r.sub)) {
                    if r.skip > 0 {
                        r.skip -= 1;
                        continue;
                    }
                    r.count -= 1;
                    fail = Some(r.errno);
                    break;
                }
            }
            if s.tracing {
                let line = match fail {
                    Some(e) => format!("{op:?} {path} => errno {e}"),
                    None => format!("{op:?} {path}"),
                };
                s.trace.push(line);
            }
            match fail {
                Some(e) => Err(io::Error::from_raw_os_error(e)),
                None => Ok(()),
            }
        }
    }
}
