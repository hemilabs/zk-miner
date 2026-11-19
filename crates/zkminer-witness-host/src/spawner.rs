//! Every sandboxed child is spawned from one long-lived thread.
//!
//! `prepare_command` sets `PR_SET_PDEATHSIG(SIGKILL)`, which the kernel ties to the *thread* that
//! forked the child, not the process: a child spawned from a tokio blocking-pool thread is killed
//! when that thread idles out (after ten seconds). The spawner thread lives as long as the miner.

use std::io;
use std::process::Child;
use std::sync::mpsc;
use std::thread;

type Job = Box<dyn FnOnce() + Send>;

/// A handle to the spawner thread. Cloning shares the thread.
#[derive(Clone)]
pub struct Spawner {
    tx: mpsc::Sender<Job>,
}

impl Spawner {
    /// Starts the spawner thread.
    pub fn new() -> io::Result<Self> {
        let (tx, rx) = mpsc::channel::<Job>();
        thread::Builder::new().name("witness-spawner".into()).spawn(move || {
            for job in rx {
                job();
            }
        })?;
        Ok(Self { tx })
    }

    /// Runs `f` on the spawner thread and returns what it returns. Everything that forks a sandboxed
    /// child goes through here.
    pub fn run<T, F>(&self, f: F) -> io::Result<T>
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static,
    {
        let (rtx, rrx) = mpsc::channel();
        self.tx
            .send(Box::new(move || {
                let _ = rtx.send(f());
            }))
            .map_err(|_| io::Error::other("the spawner thread is gone"))?;
        rrx.recv().map_err(|_| io::Error::other("the spawner thread is gone"))
    }

    /// Runs `f` (which builds and spawns a `Command`) on the spawner thread.
    pub fn spawn<F>(&self, f: F) -> io::Result<Child>
    where
        F: FnOnce() -> io::Result<Child> + Send + 'static,
    {
        self.run(f)?
    }

    /// [`Spawner::run`] without blocking an async runtime thread.
    pub async fn run_async<T, F>(&self, f: F) -> io::Result<T>
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static,
    {
        let (rtx, rrx) = tokio::sync::oneshot::channel();
        self.tx
            .send(Box::new(move || {
                let _ = rtx.send(f());
            }))
            .map_err(|_| io::Error::other("the spawner thread is gone"))?;
        rrx.await.map_err(|_| io::Error::other("the spawner thread is gone"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{Command, Stdio};

    #[test]
    fn spawns_on_its_own_thread() {
        let s = Spawner::new().unwrap();
        let caller = thread::current().id();
        let (tx, rx) = mpsc::channel();
        let mut child = s
            .spawn(move || {
                tx.send(thread::current().id()).unwrap();
                Command::new("true").stdin(Stdio::null()).spawn()
            })
            .unwrap();
        assert_ne!(rx.recv().unwrap(), caller);
        assert!(child.wait().unwrap().success());
        assert!(s.spawn(|| Command::new("/nonexistent/binary").spawn()).is_err());
    }
}
