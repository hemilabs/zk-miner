//! Where `zkminer run`'s log lines and `PAGE:` lines go besides the terminal (review 6 D1/OJ-3).
//!
//! Headless, the miner logged only to stderr, and the documented Windows service (NSSM) kept no
//! stderr: every line, every `PAGE:` included, was lost. Now a headless run also writes the daily
//! rolling file the dashboard mode writes (`~/.zkminer/logs/zkminer.log`, 14 days), and every run
//! sends each `PAGE:` line to [`PageSink`]:
//! - `~/.zkminer/logs/pages.log`, one timestamped line per page, capped at [`PAGES_CAP`] with one
//!   `.1` generation, which `zkminer status` reads (and exits 2 on while one is unacknowledged);
//! - on Windows, the Application event log (source `zkminer`, an event id per page code, at most
//!   once per code every [`EVENT_EVERY`]), where Event Viewer, a Task Scheduler trigger or a
//!   monitoring agent sees it.
//!
//! Worker output (target `worker`: a guest's own output reaches it) goes to neither file, so a
//! guest cannot fill the disk through them, and every line written to a file (or headless stderr,
//! which a service wrapper may keep) has its URLs cut to scheme and host
//! (`commands::simulate::redact_urls`): an RPC client's error quotes the request URL, and an
//! operator's RPC URL carries its API key.

use std::io::Write;
use std::path::{Path, PathBuf};

/// The most `pages.log` holds before it is moved to `pages.log.1` (and the old `.1` dropped).
pub const PAGES_CAP: u64 = 1024 * 1024;

/// How often one page code reaches the event log at most.
#[cfg_attr(not(windows), allow(dead_code))]
const EVENT_EVERY: std::time::Duration = std::time::Duration::from_secs(300);

/// The longest page line kept.
const PAGE_MAX_CHARS: usize = 4096;

/// `~/.zkminer/logs`.
pub fn logs_dir() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".zkminer")
        .join("logs")
}

/// `pages.log` in `dir`.
pub fn pages_path(dir: &Path) -> PathBuf {
    dir.join("pages.log")
}

/// One line of text as a log file keeps it: control and line-separator characters as spaces (no
/// forged lines), at most [`PAGE_MAX_CHARS`], and every URL cut to its scheme and host.
pub fn clean_line(text: &str) -> String {
    let flat: String = text
        .chars()
        .map(|c| {
            if c.is_control() || matches!(c, '\u{2028}' | '\u{2029}') {
                ' '
            } else {
                c
            }
        })
        .take(PAGE_MAX_CHARS)
        .collect();
    crate::commands::simulate::redact_urls(&flat)
}

/// The code of a page (`PAGE: LOCK-LATE — …` → `LOCK-LATE`), or `PAGE` for one without.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn page_code(message: &str) -> &str {
    let rest = message
        .strip_prefix("PAGE")
        .unwrap_or(message)
        .trim_start_matches(':')
        .trim_start();
    let end = rest
        .find(|c: char| !(c.is_ascii_uppercase() || c.is_ascii_digit() || c == '-'))
        .unwrap_or(rest.len());
    match &rest[..end] {
        "" => "PAGE",
        code => code,
    }
}

/// The event id a page code is reported under (fixed, so a trigger or a monitoring rule can name
/// it); 199 for one not listed.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn event_id(code: &str) -> u32 {
    match code {
        // Locks and funds.
        "SLASHED" => 100,
        "LOCK-LATE" => 101,
        "CHAIN-UNREACHABLE" => 102,
        "PENDING-UNMINED" => 103,
        "FUNDS-SHORT" => 104,
        "CLOCK-SKEW" => 105,
        "JOB-CRASH-LOOP" => 106,
        "ESTIMATE-OVERRUN" => 107,
        "ESTIMATE-REFUSAL" => 108,
        "RATE-EXPIRED" => 109,
        // The account, its secrets and the workers' containment.
        "SECRETS-UNLABELLED" => 110,
        "PRIVILEGED-ACCOUNT" => 111,
        "ELEVATED" => 112,
        "MEDIUM-WORKERS" => 113,
        "WORKER-PRIVILEGES" => 114,
        "PRIVILEGES" => 115,
        "KEY-IN-MACHINE-ENVIRONMENT" => 116,
        "PASSWORD-EXPIRES" => 117,
        "LOW-IL-WORKER-FAILED" => 118,
        "LOW-IL-WARMUP-FAILED" => 119,
        "RUNNING-AS-ROOT" => 120,
        "WORKERS-UNCAPPED" => 121,
        // The job journal.
        "JOURNAL-CORRUPT" => 130,
        "JOURNAL-UNUSABLE" => 131,
        "JOURNAL-DIVERGED" => 132,
        "JOURNAL-ENTRY-UNREADABLE" => 133,
        _ => 199,
    }
}

/// Append `line` to `pages.log` in `dir` (made if missing), first moving a file that `line` would
/// take past `cap` bytes to `pages.log.1`.
pub fn append_page(dir: &Path, line: &str, cap: u64) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    let path = pages_path(dir);
    let len = std::fs::metadata(&path).map_or(0, |m| m.len());
    if len > 0 && len + line.len() as u64 + 1 > cap {
        let mut old = path.as_os_str().to_owned();
        old.push(".1");
        // A rename over an existing file is atomic on both platforms (MoveFileEx with replace).
        std::fs::rename(&path, PathBuf::from(old))?;
    }
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)?;
    file.write_all(format!("{line}\n").as_bytes())
}

/// The pages in `dir` (`pages.log.1`, then `pages.log`), oldest first, as (unix seconds, line).
/// A line whose timestamp does not parse counts as time 0.
pub fn read_pages(dir: &Path) -> Vec<(i64, String)> {
    let mut old = pages_path(dir).into_os_string();
    old.push(".1");
    [PathBuf::from(old), pages_path(dir)]
        .iter()
        .filter_map(|p| std::fs::read_to_string(p).ok())
        .flat_map(|text| {
            text.lines()
                .filter(|l| !l.trim().is_empty())
                .map(|l| {
                    let at = l
                        .split_once(' ')
                        .and_then(|(t, _)| chrono::DateTime::parse_from_rfc3339(t).ok())
                        .map_or(0, |t| t.timestamp());
                    (at, l.to_string())
                })
                .collect::<Vec<_>>()
        })
        .collect()
}

/// `pages.ack` in `dir`: the unix time up to which pages were acknowledged (`zkminer status
/// --ack`).
pub fn ack_path(dir: &Path) -> PathBuf {
    dir.join("pages.ack")
}

/// The acknowledged-up-to time in `dir`, 0 when none.
pub fn read_ack(dir: &Path) -> i64 {
    std::fs::read_to_string(ack_path(dir))
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0)
}

/// Acknowledge every page up to `now` (unix seconds).
pub fn write_ack(dir: &Path, now: i64) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    std::fs::write(ack_path(dir), now.to_string())
}

/// A `tracing` layer that sends each WARN or ERROR event whose message starts with `PAGE` (and
/// that is not worker output) to `pages.log` and, on Windows, the event log.
pub struct PageSink {
    dir: PathBuf,
    /// Whether pages also go to the event log (not from tests).
    #[cfg_attr(not(windows), allow(dead_code))]
    event_log: bool,
    #[cfg(windows)]
    last_event: std::sync::Mutex<std::collections::HashMap<String, std::time::Instant>>,
}

impl PageSink {
    pub fn new(dir: PathBuf) -> Self {
        Self {
            dir,
            event_log: true,
            #[cfg(windows)]
            last_event: Default::default(),
        }
    }

    /// A sink that writes `pages.log` only.
    #[cfg(test)]
    fn files_only(dir: PathBuf) -> Self {
        Self {
            event_log: false,
            ..Self::new(dir)
        }
    }

    /// Record one page (already cleaned).
    fn page(&self, text: &str) {
        let stamp = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ");
        // Nowhere to say it: the log line itself has gone to the other layers.
        let _ = append_page(&self.dir, &format!("{stamp} {text}"), PAGES_CAP);
        #[cfg(windows)]
        if self.event_log {
            let code = page_code(text).to_string();
            let mut last = self.last_event.lock().unwrap_or_else(|p| p.into_inner());
            let due = last.get(&code).is_none_or(|t| t.elapsed() >= EVENT_EVERY);
            if due {
                last.insert(code.clone(), std::time::Instant::now());
                drop(last);
                event_log::report(event_id(&code), text);
            }
        }
    }
}

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for PageSink {
    fn on_event(&self, event: &tracing::Event<'_>, _: tracing_subscriber::layer::Context<'_, S>) {
        if *event.metadata().level() > tracing::Level::WARN || event.metadata().target() == "worker"
        {
            return;
        }
        struct Message(Option<String>);
        impl tracing::field::Visit for Message {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                if field.name() == "message" {
                    self.0 = Some(format!("{value:?}"));
                }
            }
        }
        let mut m = Message(None);
        event.record(&mut m);
        if let Some(msg) = m.0.filter(|s| s.starts_with("PAGE")) {
            self.page(&clean_line(&msg));
        }
    }
}

/// The Windows Application event log, through `ReportEventW` (source `zkminer`; registered by the
/// README's `New-EventLog`, else Event Viewer shows the text under "description not found").
#[cfg(windows)]
mod event_log {
    use std::ffi::c_void;
    use std::os::windows::ffi::OsStrExt;

    #[link(name = "advapi32")]
    extern "system" {
        fn RegisterEventSourceW(server: *const u16, source: *const u16) -> *mut c_void;
        fn ReportEventW(
            log: *mut c_void,
            kind: u16,
            category: u16,
            event_id: u32,
            user_sid: *const c_void,
            num_strings: u16,
            data_size: u32,
            strings: *const *const u16,
            data: *const c_void,
        ) -> i32;
    }

    const EVENTLOG_ERROR_TYPE: u16 = 0x1;

    /// Report `text` as an error event `id`. The source handle is opened once and kept.
    pub(super) fn report(id: u32, text: &str) {
        static SOURCE: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
        let source = *SOURCE.get_or_init(|| {
            let name: Vec<u16> = std::ffi::OsStr::new("zkminer")
                .encode_wide()
                .chain([0])
                .collect();
            // SAFETY: the local computer (NULL) and a NUL-terminated name.
            unsafe { RegisterEventSourceW(std::ptr::null(), name.as_ptr()) as usize }
        });
        if source == 0 {
            return;
        }
        let text: Vec<u16> = std::ffi::OsStr::new(text)
            .encode_wide()
            .filter(|c| *c != 0)
            .chain([0])
            .collect();
        let strings = [text.as_ptr()];
        // SAFETY: an open source handle, one NUL-terminated string that outlives the call, no SID
        // and no data.
        unsafe {
            ReportEventW(
                source as *mut c_void,
                EVENTLOG_ERROR_TYPE,
                0,
                id,
                std::ptr::null(),
                1,
                0,
                strings.as_ptr(),
                std::ptr::null(),
            )
        };
    }
}

/// A writer that cuts every URL in what it is given to its scheme and host ([`clean_line`] without
/// the flattening: a formatted event keeps its newline).
pub struct Redacting<W>(pub W);

impl<W: Write> Write for Redacting<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let text = String::from_utf8_lossy(buf);
        self.0
            .write_all(crate::commands::simulate::redact_urls(&text).as_bytes())?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}

/// [`Redacting`] for a `MakeWriter`.
pub struct RedactingMake<M>(pub M);

impl<'a, M: tracing_subscriber::fmt::MakeWriter<'a>> tracing_subscriber::fmt::MakeWriter<'a>
    for RedactingMake<M>
{
    type Writer = Redacting<M::Writer>;

    fn make_writer(&'a self) -> Self::Writer {
        Redacting(self.0.make_writer())
    }
}

/// The daily rolling `zkminer.log` in `dir`, two weeks of it (the dashboard's and a headless run's).
pub fn rolling_file(dir: &Path) -> tracing_appender::rolling::RollingFileAppender {
    tracing_appender::rolling::Builder::new()
        .rotation(tracing_appender::rolling::Rotation::DAILY)
        .filename_prefix("zkminer.log")
        .max_log_files(14)
        .build(dir)
        .unwrap_or_else(|_| tracing_appender::rolling::daily(dir, "zkminer.log"))
}

/// The subscriber of a headless `zkminer run`: `stderr` as before (colour when `ansi`), the
/// rolling `file`, and [`PageSink`] in `dir`, everything at `filter`; URLs cut to their host in both
/// writers, and worker output kept out of the file.
fn headless_subscriber<E, F>(
    filter: &str,
    stderr: E,
    ansi: bool,
    file: F,
    sink: PageSink,
) -> impl tracing::Subscriber + Send + Sync + 'static
where
    E: for<'w> tracing_subscriber::fmt::MakeWriter<'w> + Send + Sync + 'static,
    F: for<'w> tracing_subscriber::fmt::MakeWriter<'w> + Send + Sync + 'static,
{
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::Layer;
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(filter))
        .with(
            tracing_subscriber::fmt::layer()
                .with_writer(RedactingMake(stderr))
                .with_target(false)
                .with_ansi(ansi),
        )
        .with(
            tracing_subscriber::fmt::layer()
                .with_writer(RedactingMake(file))
                .with_target(false)
                .with_ansi(false)
                .with_filter(tracing_subscriber::filter::filter_fn(|m| {
                    m.target() != "worker"
                })),
        )
        .with(sink)
}

/// Logging for a headless `zkminer run` ([`headless_subscriber`] on stderr and the daily rolling
/// file in `dir`). Returns the file writer's guard, to hold until exit.
pub fn init_headless_run(filter: &str, dir: &Path) -> tracing_appender::non_blocking::WorkerGuard {
    use tracing_subscriber::util::SubscriberInitExt;
    let (file, guard) = tracing_appender::non_blocking(rolling_file(dir));
    let ansi = std::io::IsTerminal::is_terminal(&std::io::stderr());
    headless_subscriber(
        filter,
        std::io::stderr,
        ansi,
        file,
        PageSink::new(dir.to_path_buf()),
    )
    .init();
    guard
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("zkminer-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn page_codes_and_event_ids() {
        assert_eq!(page_code("PAGE: LOCK-LATE — job 0x12"), "LOCK-LATE");
        assert_eq!(
            page_code("PAGE: PRIVILEGED-ACCOUNT refused; holding"),
            "PRIVILEGED-ACCOUNT"
        );
        assert_eq!(
            page_code("PAGE: JOURNAL-CORRUPT: the job journal"),
            "JOURNAL-CORRUPT"
        );
        assert_eq!(page_code("PAGE something else"), "PAGE");
        assert_eq!(event_id("SLASHED"), 100);
        assert_eq!(event_id("LOCK-LATE"), 101);
        assert_eq!(event_id("SECRETS-UNLABELLED"), 110);
        assert_eq!(event_id("PASSWORD-EXPIRES"), 117);
        assert_eq!(event_id("PAGE"), 199);
        assert_eq!(event_id("SOMETHING-NEW"), 199);
    }

    /// A page line keeps no line break, no control character and no URL path or query (where RPC
    /// providers put API keys).
    #[test]
    fn a_page_line_is_flat_and_keeps_no_key() {
        let line = clean_line(
            "PAGE: CHAIN-UNREACHABLE — https://rpc.example.org/v2/SECRETKEY?x=1 failed\n\
             forged line\u{1b}[31m",
        );
        assert!(!line.contains("SECRETKEY") && !line.contains('\n') && !line.contains('\u{1b}'));
        assert!(line.contains("https://rpc.example.org"), "{line}");
        let mut out = Redacting(Vec::new());
        out.write_all(b"error sending request for url (https://u:p@rpc.example.org/key/abc)\n")
            .unwrap();
        let text = String::from_utf8(out.0).unwrap();
        assert!(
            !text.contains("abc") && !text.contains("u:p") && text.ends_with('\n'),
            "{text}"
        );
    }

    /// `pages.log` takes each page on its own line and moves to `pages.log.1` before it would pass
    /// its cap; reading gives back both, oldest first, with their times.
    #[test]
    fn pages_are_written_and_rotated() {
        let dir = temp_dir("pages");
        let line = |n: u32| {
            format!(
                "2026-11-21T10:00:{n:02}Z PAGE: LOCK-LATE — {}",
                "x".repeat(40)
            )
        };
        for n in 0..3 {
            append_page(&dir, &line(n), 200).unwrap();
        }
        // 3 lines of ~70 bytes in a 200-byte cap: the third rotated the first two out.
        let current = std::fs::read_to_string(pages_path(&dir)).unwrap();
        assert_eq!(current.lines().count(), 1);
        let old = std::fs::read_to_string(dir.join("pages.log.1")).unwrap();
        assert_eq!(old.lines().count(), 2);
        let pages = read_pages(&dir);
        assert_eq!(pages.len(), 3);
        assert!(pages[0].1.contains(":00Z") && pages[2].1.contains(":02Z"));
        assert!(pages.windows(2).all(|w| w[0].0 < w[1].0));
        // Another rotation drops the oldest generation.
        for n in 3..6 {
            append_page(&dir, &line(n), 200).unwrap();
        }
        assert!(read_pages(&dir).iter().all(|(_, l)| !l.contains(":00Z")));
        assert_eq!(read_ack(&dir), 0);
        write_ack(&dir, 42).unwrap();
        assert_eq!(read_ack(&dir), 42);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The sink as a layer: a PAGE event lands in `pages.log`, an ordinary one and worker output do
    /// not.
    #[test]
    fn the_page_sink_takes_pages_only() {
        use tracing_subscriber::layer::SubscriberExt;
        let dir = temp_dir("sink");
        let subscriber = tracing_subscriber::registry().with(PageSink::files_only(dir.clone()));
        tracing::subscriber::with_default(subscriber, || {
            tracing::error!("PAGE: JOB-CRASH-LOOP — job 0x01 https://rpc.example.org/key");
            tracing::warn!("an ordinary warning");
            tracing::warn!(target: "worker", "PAGE: FORGED by a guest");
            tracing::info!("PAGE: at info, not a page");
        });
        let pages = read_pages(&dir);
        assert_eq!(pages.len(), 1, "{pages:?}");
        assert!(pages[0].0 > 0);
        assert!(pages[0].1.contains("PAGE: JOB-CRASH-LOOP") && !pages[0].1.contains("/key"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A writer into a shared buffer, for a subscriber under test.
    #[derive(Clone, Default)]
    struct Shared(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

    impl Write for Shared {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Shared {
        type Writer = Shared;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    impl Shared {
        fn text(&self) -> String {
            String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
        }
    }

    /// The headless subscriber: a PAGE reaches stderr, the file and `pages.log`; worker output
    /// reaches stderr only; a URL's path reaches none of them.
    #[test]
    fn a_headless_run_keeps_pages_and_logs_but_not_worker_output() {
        let dir = temp_dir("headless");
        let (stderr, file) = (Shared::default(), Shared::default());
        let subscriber = headless_subscriber(
            "warn,zkminer=info",
            stderr.clone(),
            false,
            file.clone(),
            PageSink::files_only(dir.clone()),
        );
        tracing::subscriber::with_default(subscriber, || {
            tracing::error!(target: "zkminer::run", "PAGE: LOCK-LATE — https://rpc.example.org/KEY");
            tracing::warn!(target: "worker", "[worker:risc0] a guest's line");
        });
        let (stderr, file) = (stderr.text(), file.text());
        assert!(
            stderr.contains("PAGE: LOCK-LATE") && stderr.contains("a guest's line"),
            "{stderr}"
        );
        assert!(
            file.contains("PAGE: LOCK-LATE") && !file.contains("a guest's line"),
            "{file}"
        );
        assert!(!stderr.contains("KEY") && !file.contains("KEY"));
        let pages = read_pages(&dir);
        assert_eq!(pages.len(), 1, "{pages:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
