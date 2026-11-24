//! Which workers hold network sockets: the symptom the chain watch's outage recycle keys on
//! (`commands/run/chain_watch.rs` in the CLI).
//!
//! On Windows a Low-integrity worker keeps the network, so one whose guest broke out of its
//! executor could cut the miner off its RPC without ending it: the host's ephemeral ports held
//! open, or the uplink flooded. Stopping every worker after an outage killed every honest proof
//! with it, and an outage anyone can cause (a flooded link, a dead provider) did so on demand. So
//! the watch stops only the workers that hold sockets. An honest worker holds none while it proves:
//! the only sockets a worker opens are its one-time setup's downloads (the risc0 Groth16 component,
//! `zkminer-prove-risc0/src/groth16_component.rs`, one connection; SP1's circuit artifacts and the
//! size probe beside it, `zkminer-prove-sp1/src/warmup.rs`, one or two), and SP1's worker reaches
//! its GPU server through a named pipe, which is not a socket. DNS goes through the system's DNS
//! client service. The limits ([`Limits::DEFAULT`]) leave several times that room, and a worker in
//! its first [`Limits::DEFAULT`]`.grace` is never flagged, which covers a setup's start.
//!
//! A worker's processes are every process in its job (`windows_job::new_worker_job`), so a child a
//! guest started is counted with it even after its parent is gone. The socket tables are the
//! system's (`GetExtendedTcpTable`, `GetExtendedUdpTable`, with each socket's owning pid), which
//! need no administrator.

use std::collections::HashMap;
use std::time::Duration;

/// The sockets a process (or a worker's processes together) holds.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Sockets {
    /// TCP connections established.
    pub tcp_established: u32,
    /// TCP sockets in any other state (connecting, listening, closing).
    pub tcp_other: u32,
    /// UDP sockets (IPv4 and IPv6).
    pub udp: u32,
}

impl Sockets {
    /// TCP sockets in every state.
    pub fn tcp(&self) -> u32 {
        self.tcp_established.saturating_add(self.tcp_other)
    }

    fn add(&mut self, other: Sockets) {
        self.tcp_established = self.tcp_established.saturating_add(other.tcp_established);
        self.tcp_other = self.tcp_other.saturating_add(other.tcp_other);
        self.udp = self.udp.saturating_add(other.udp);
    }

    /// The sum over `pids` in `table`.
    pub fn of(pids: &[u32], table: &HashMap<u32, Sockets>) -> Sockets {
        let mut s = Sockets::default();
        for pid in pids {
            if let Some(t) = table.get(pid) {
                s.add(*t);
            }
        }
        s
    }
}

impl std::fmt::Display for Sockets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} TCP ({} established), {} UDP",
            self.tcp(),
            self.tcp_established,
            self.udp
        )
    }
}

/// How many sockets a worker may hold before it is suspected of holding the network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// The most TCP sockets (every state) an honest worker is taken to hold.
    pub tcp: u32,
    /// The most UDP sockets an honest worker is taken to hold.
    pub udp: u32,
    /// A worker younger than this is never suspected: its setup may be downloading.
    pub grace: Duration,
}

/// Overrides [`Limits::tcp`], for tuning in the field.
pub const TCP_MAX_ENV: &str = "ZKMINER_RECYCLE_TCP_MAX";
/// Overrides [`Limits::udp`].
pub const UDP_MAX_ENV: &str = "ZKMINER_RECYCLE_UDP_MAX";
/// Overrides [`Limits::grace`], in seconds.
pub const GRACE_SECS_ENV: &str = "ZKMINER_RECYCLE_GRACE_SECS";

impl Limits {
    /// More than 8 TCP or 4 UDP sockets, after a worker's first 2 minutes. An honest worker holds
    /// none while proving and one to three during its setup's download (see the module docs).
    pub const DEFAULT: Limits = Limits {
        tcp: 8,
        udp: 4,
        grace: Duration::from_secs(120),
    };

    /// [`Limits::DEFAULT`], each figure overridden by its variable when that holds a number.
    pub fn from_env() -> Limits {
        Self::from_lookup(|name| std::env::var(name).ok())
    }

    fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Limits {
        let num = |name: &str| get(name).and_then(|v| v.trim().parse::<u32>().ok());
        let d = Self::DEFAULT;
        Limits {
            tcp: num(TCP_MAX_ENV).unwrap_or(d.tcp),
            udp: num(UDP_MAX_ENV).unwrap_or(d.udp),
            grace: num(GRACE_SECS_ENV).map_or(d.grace, |s| Duration::from_secs(s.into())),
        }
    }
}

/// One worker slot as the recycle sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotSockets {
    /// The slot's key (`risc0:cuda:0`, `sp1:measure:0`).
    pub slot: String,
    /// Its worker's processes: the worker and whatever is in its job.
    pub pids: Vec<u32>,
    /// How long its worker has run, when known.
    pub age: Option<Duration>,
    /// What they hold together.
    pub sockets: Sockets,
    /// Whether the slot is busy (proving or measuring).
    pub busy: bool,
}

/// Whether `s` holds more sockets than an honest worker would. A worker in its grace period is
/// not; one whose age is unknown is judged on its sockets.
pub fn is_suspect(s: &SlotSockets, limits: &Limits) -> bool {
    if s.age.is_some_and(|a| a < limits.grace) {
        return false;
    }
    s.sockets.tcp() > limits.tcp || s.sockets.udp > limits.udp
}

/// The slots of `slots` that [`is_suspect`].
pub fn suspects<'a>(slots: &'a [SlotSockets], limits: &Limits) -> Vec<&'a SlotSockets> {
    slots.iter().filter(|s| is_suspect(s, limits)).collect()
}

/// What a socket table's rows add to `out`, by owning pid. `table` is the table as the system
/// writes it, in 32-bit words: the row count, then `width` words per row, the owner at `pid_at` and,
/// for TCP, the state at `state_at` (established is 5). A row past the buffer's end is not read.
#[cfg_attr(not(windows), allow(dead_code))]
fn count_rows(
    table: &[u32],
    width: usize,
    pid_at: usize,
    state_at: Option<usize>,
    out: &mut HashMap<u32, Sockets>,
) {
    const ESTABLISHED: u32 = 5;
    let Some((&n, rows)) = table.split_first() else {
        return;
    };
    for row in rows.chunks_exact(width).take(n as usize) {
        let pid = row[pid_at];
        if pid == 0 {
            continue;
        }
        let s = out.entry(pid).or_default();
        match state_at {
            None => s.udp = s.udp.saturating_add(1),
            Some(i) if row[i] == ESTABLISHED => {
                s.tcp_established = s.tcp_established.saturating_add(1)
            }
            Some(_) => s.tcp_other = s.tcp_other.saturating_add(1),
        }
    }
}

#[cfg(windows)]
pub(crate) use sys::{filetime_now, register_job, sockets_of_worker, terminate_job_of};
#[cfg(windows)]
pub use sys::{job_pids, socket_table};

#[cfg(windows)]
mod sys {
    use super::{count_rows, Sockets};
    use std::collections::HashMap;
    use std::ffi::c_void;
    use std::io;
    use std::os::windows::io::{AsRawHandle, OwnedHandle};
    use std::sync::{Arc, Mutex, Weak};

    const AF_INET: u32 = 2;
    const AF_INET6: u32 = 23;
    const TCP_TABLE_OWNER_PID_ALL: i32 = 5;
    const UDP_TABLE_OWNER_PID: i32 = 1;
    const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
    const ERROR_MORE_DATA: u32 = 234;
    const JOB_OBJECT_BASIC_PROCESS_ID_LIST: i32 = 3;

    #[link(name = "iphlpapi")]
    extern "system" {
        fn GetExtendedTcpTable(
            table: *mut c_void,
            size: *mut u32,
            order: i32,
            family: u32,
            class: i32,
            reserved: u32,
        ) -> u32;
        fn GetExtendedUdpTable(
            table: *mut c_void,
            size: *mut u32,
            order: i32,
            family: u32,
            class: i32,
            reserved: u32,
        ) -> u32;
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn QueryInformationJobObject(
            job: *mut c_void,
            class: i32,
            info: *mut c_void,
            length: u32,
            returned: *mut u32,
        ) -> i32;
        fn TerminateJobObject(job: *mut c_void, code: u32) -> i32;
        fn GetLastError() -> u32;
        fn GetSystemTimeAsFileTime(time: *mut u64);
    }

    /// One of the system's tables, in 32-bit words, by `get(buffer, size)`.
    fn table(get: impl Fn(*mut c_void, *mut u32) -> u32) -> io::Result<Vec<u32>> {
        let mut buf: Vec<u32> = Vec::new();
        let mut size = 0u32;
        // The table can grow between the size query and the read: ask again, a few times.
        for _ in 0..8 {
            let ptr = if buf.is_empty() {
                std::ptr::null_mut()
            } else {
                buf.as_mut_ptr().cast()
            };
            match get(ptr, &mut size) {
                0 => return Ok(buf),
                ERROR_INSUFFICIENT_BUFFER => {
                    // Room for some rows more than asked, in case it grows meanwhile.
                    buf = vec![0u32; (size as usize).div_ceil(4) + 256];
                    size = (buf.len() * 4) as u32;
                }
                e => return Err(io::Error::from_raw_os_error(e as i32)),
            }
        }
        Err(io::Error::other("the socket table kept growing"))
    }

    /// Every TCP (all states) and UDP socket on the host, IPv4 and IPv6, by owning pid.
    pub fn socket_table() -> io::Result<HashMap<u32, Sockets>> {
        let mut out = HashMap::new();
        for (family, width, pid_at, state_at) in [(AF_INET, 6, 5, 0), (AF_INET6, 14, 13, 12)] {
            // SAFETY: the buffer and size are this call's own; `table` sizes the buffer as asked.
            let t = table(|p, s| unsafe {
                GetExtendedTcpTable(p, s, 0, family, TCP_TABLE_OWNER_PID_ALL, 0)
            })?;
            count_rows(&t, width, pid_at, Some(state_at), &mut out);
        }
        for (family, width, pid_at) in [(AF_INET, 3, 2), (AF_INET6, 7, 6)] {
            // SAFETY: as above.
            let t = table(|p, s| unsafe {
                GetExtendedUdpTable(p, s, 0, family, UDP_TABLE_OWNER_PID, 0)
            })?;
            count_rows(&t, width, pid_at, None, &mut out);
        }
        Ok(out)
    }

    /// The pids of every process in `job`, its nested jobs' included.
    pub fn job_pids(job: &OwnedHandle) -> io::Result<Vec<u32>> {
        // JOBOBJECT_BASIC_PROCESS_ID_LIST: two u32 counts (one word), then the pids as words.
        let mut buf: Vec<usize> = vec![0; 64];
        for _ in 0..8 {
            let mut returned = 0u32;
            // SAFETY: a valid job handle; the buffer and its length are this call's own.
            let ok = unsafe {
                QueryInformationJobObject(
                    job.as_raw_handle(),
                    JOB_OBJECT_BASIC_PROCESS_ID_LIST,
                    buf.as_mut_ptr().cast(),
                    (buf.len() * std::mem::size_of::<usize>()) as u32,
                    &mut returned,
                )
            };
            // SAFETY: plain call.
            let more = ok == 0 && unsafe { GetLastError() } == ERROR_MORE_DATA;
            if ok == 0 && !more {
                return Err(io::Error::last_os_error());
            }
            let head = buf[0] as u64;
            let assigned = (head & 0xffff_ffff) as usize;
            let listed = (head >> 32) as usize;
            if !more && listed >= assigned {
                return Ok(buf[1..=listed.min(buf.len() - 1)]
                    .iter()
                    .map(|&p| p as u32)
                    .collect());
            }
            buf = vec![0; assigned.max(listed) * 2 + 64];
        }
        Err(io::Error::other("the job's process list kept growing"))
    }

    /// Each live worker's job, by the worker's pid. Weak: the worker's handle (`WorkerChild`) owns
    /// its job, whose closing ends what is in it, and this must not keep it open. A pid is not
    /// reused while the worker's process handle, held beside the job, is open.
    static JOBS: Mutex<Vec<(u32, Weak<OwnedHandle>)>> = Mutex::new(Vec::new());

    /// Record `job` as worker `pid`'s.
    pub(crate) fn register_job(pid: u32, job: &Arc<OwnedHandle>) {
        let mut jobs = JOBS.lock().unwrap_or_else(|p| p.into_inner());
        jobs.retain(|(p, j)| *p != pid && j.strong_count() > 0);
        jobs.push((pid, Arc::downgrade(job)));
    }

    fn job_of(pid: u32) -> Option<Arc<OwnedHandle>> {
        let jobs = JOBS.lock().unwrap_or_else(|p| p.into_inner());
        jobs.iter()
            .find(|(p, _)| *p == pid)
            .and_then(|(_, j)| j.upgrade())
    }

    /// Worker `pid`'s processes (its job's; just `pid` if it has none) and what they hold in `table`.
    pub(crate) fn sockets_of_worker(
        pid: u32,
        table: &HashMap<u32, Sockets>,
    ) -> (Vec<u32>, Sockets) {
        let mut pids = job_of(pid)
            .and_then(|job| job_pids(&job).ok())
            .unwrap_or_default();
        if !pids.contains(&pid) {
            pids.insert(0, pid);
        }
        let s = Sockets::of(&pids, table);
        (pids, s)
    }

    /// The time now as a FILETIME (100 ns since 1601), as `memory::pid_starttime` reads a start.
    pub(crate) fn filetime_now() -> u64 {
        let mut t = 0u64;
        // SAFETY: writes a FILETIME, two little-endian words, low first: the u64 it is.
        unsafe { GetSystemTimeAsFileTime(&mut t) };
        t
    }

    /// End everything in worker `pid`'s job. False if it has none (or it could not be ended).
    pub(crate) fn terminate_job_of(pid: u32) -> bool {
        // SAFETY: a valid job handle, kept open by the upgrade for the call.
        job_of(pid).is_some_and(|job| unsafe { TerminateJobObject(job.as_raw_handle(), 1) } != 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn slot(age: Option<u64>, tcp: u32, udp: u32) -> SlotSockets {
        SlotSockets {
            slot: "risc0:cuda:0".to_string(),
            pids: vec![10, 11],
            age: age.map(Duration::from_secs),
            sockets: Sockets {
                tcp_established: tcp / 2,
                tcp_other: tcp - tcp / 2,
                udp,
            },
            busy: true,
        }
    }

    #[test]
    fn a_worker_is_suspect_only_past_the_limits_and_its_grace() {
        let l = Limits::DEFAULT;
        // An honest prover holds nothing; a downloading setup a few.
        assert!(!is_suspect(&slot(Some(600), 0, 0), &l));
        assert!(!is_suspect(&slot(Some(600), 3, 1), &l));
        // The edges: at the limit is honest, one past it is not.
        assert!(!is_suspect(&slot(Some(600), 8, 4), &l));
        assert!(is_suspect(&slot(Some(600), 9, 0), &l));
        assert!(is_suspect(&slot(Some(600), 0, 5), &l));
        // Port exhaustion is thousands.
        assert!(is_suspect(&slot(Some(600), 5_000, 0), &l));
        // Inside the grace period never; at its end and with an unknown age, on its sockets.
        assert!(!is_suspect(&slot(Some(119), 5_000, 50), &l));
        assert!(is_suspect(&slot(Some(120), 5_000, 50), &l));
        assert!(is_suspect(&slot(None, 9, 0), &l));
        assert!(!is_suspect(&slot(None, 8, 4), &l));
        let all = [slot(Some(600), 0, 0), slot(Some(600), 20, 0)];
        let s = suspects(&all, &l);
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].sockets.tcp(), 20);
    }

    #[test]
    fn the_limits_can_be_tuned_by_environment() {
        let env = |pairs: &'static [(&'static str, &'static str)]| {
            move |name: &str| {
                pairs
                    .iter()
                    .find(|(k, _)| *k == name)
                    .map(|(_, v)| v.to_string())
            }
        };
        assert_eq!(Limits::from_lookup(env(&[])), Limits::DEFAULT);
        let l = Limits::from_lookup(env(&[
            (TCP_MAX_ENV, "32"),
            (UDP_MAX_ENV, " 10 "),
            (GRACE_SECS_ENV, "300"),
        ]));
        assert_eq!(
            l,
            Limits {
                tcp: 32,
                udp: 10,
                grace: Duration::from_secs(300)
            }
        );
        // Not a number: the default stands.
        let l = Limits::from_lookup(env(&[(TCP_MAX_ENV, "lots"), (UDP_MAX_ENV, "-1")]));
        assert_eq!(l, Limits::DEFAULT);
    }

    #[test]
    fn socket_tables_are_counted_by_owner_and_state() {
        let mut out = HashMap::new();
        // Two IPv4 TCP rows (state, laddr, lport, raddr, rport, pid): one established, one listening;
        // one owned by pid 0 (a closing socket nobody owns) is skipped.
        let tcp = [3, 5, 0, 0, 0, 0, 7, 2, 0, 0, 0, 0, 7, 5, 0, 0, 0, 0, 0];
        count_rows(&tcp, 6, 5, Some(0), &mut out);
        // IPv6 UDP rows (addr x4, scope, port, pid), the count claiming more rows than are there.
        let udp = [9, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 8];
        count_rows(&udp, 7, 6, None, &mut out);
        count_rows(&[], 7, 6, None, &mut out);
        assert_eq!(
            out.get(&7),
            Some(&Sockets {
                tcp_established: 1,
                tcp_other: 1,
                udp: 1
            })
        );
        assert_eq!(out.get(&8).map(|s| s.udp), Some(1));
        assert!(!out.contains_key(&0));
        assert_eq!(Sockets::of(&[7, 8, 9], &out).udp, 2);
        assert_eq!(
            Sockets::of(&[7], &out).to_string(),
            "2 TCP (1 established), 1 UDP"
        );
    }

    /// A child in a worker's job that opens UDP sockets is found by its job, counted, and flagged.
    #[cfg(windows)]
    #[test]
    fn a_job_child_holding_udp_sockets_is_flagged() {
        use std::io::{BufRead, BufReader};
        use std::os::windows::io::AsRawHandle;
        use std::process::{Command, Stdio};
        use std::sync::Arc;

        // Bound to loopback: no firewall prompt, and nothing leaves the host.
        let script = "$s = @(); for ($i = 0; $i -lt 20; $i++) { \
             $s += New-Object System.Net.Sockets.UdpClient (New-Object System.Net.IPEndPoint \
             ([System.Net.IPAddress]::Loopback, 0)) }; \
             [Console]::Out.WriteLine('READY'); [Console]::Out.Flush(); Start-Sleep -Seconds 60";
        let mut child = Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-Command", script])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let job = Arc::new(crate::windows_job::new_worker_job().unwrap());
        // Assigned after it started (a worker is assigned suspended): fine for a test, the sockets
        // are opened only after PowerShell has loaded.
        crate::windows_job::assign(&job, child.as_raw_handle()).unwrap();
        // Registered as a worker's job is at its spawn, and found through that registration.
        let worker_pid = child.id();
        register_job(worker_pid, &job);
        let mut line = String::new();
        let mut out = BufReader::new(child.stdout.take().unwrap());
        let ready = out.read_line(&mut line).is_ok() && line.trim() == "READY";
        let result = (|| {
            if !ready {
                return Err(format!("the child did not get ready: {line:?}"));
            }
            let table = socket_table().map_err(|e| e.to_string())?;
            let (pids, sockets) = sockets_of_worker(worker_pid, &table);
            if !pids.contains(&worker_pid) {
                return Err(format!(
                    "the job's pids {pids:?} miss the child {worker_pid}"
                ));
            }
            let s = SlotSockets {
                slot: "test:0".into(),
                pids,
                age: Some(Duration::from_secs(600)),
                sockets,
                busy: true,
            };
            if sockets.udp < 20 || !is_suspect(&s, &Limits::DEFAULT) {
                return Err(format!("not flagged: {sockets}"));
            }
            Ok(())
        })();
        assert!(terminate_job_of(worker_pid), "the job could not be ended");
        let _ = child.wait();
        drop(job);
        result.unwrap();
    }
}
