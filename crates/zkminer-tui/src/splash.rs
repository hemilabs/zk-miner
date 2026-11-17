//! The banner on screen while the miner starts, until the TUI draws its first frame.

use std::io::{self, IsTerminal, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crossterm::{
    cursor, queue,
    style::{Color, Print, ResetColor, SetForegroundColor},
    terminal::{self, Clear, ClearType},
};

const ART: [&str; 5] = [
    r" _                       _  ____",
    r"| |__    ___  _ __ ___  (_)|  _ \  _ __   ___  __   __  ___",
    r"| '_ \  / _ \| '_ ` _ \ | || |_) || '__| / _ \ \ \ / / / _ \",
    r"| | | ||  __/| | | | | || ||  __/ | |   | (_) | \ V / |  __/",
    r"|_| |_| \___||_| |_| |_||_||_|    |_|    \___/   \_/   \___|",
];
const ART_WIDTH: usize = 60;
/// The column where "Prove" begins; "hemi" is everything before it.
const PROVE_COLUMN: usize = 27;
const HEMI_ORANGE: Color = Color::Rgb {
    r: 255,
    g: 108,
    b: 21,
};
const INDENT: &str = "  ";
const FRAME: Duration = Duration::from_millis(100);
const SPINNER: [char; 4] = ['|', '/', '-', '\\'];
const FALLBACK_COLS: usize = 80;

/// Where startup is now; cheap to clone into a thread that does part of the work.
#[derive(Clone)]
pub struct StatusLine(Arc<Mutex<String>>);

impl StatusLine {
    pub fn set(&self, text: impl Into<String>) {
        *self.0.lock().unwrap_or_else(|e| e.into_inner()) = text.into();
    }

    fn get(&self) -> String {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
}

/// The running banner. Dropping it stops the status updates and erases the banner, so an error
/// returned during startup prints on a clean line.
pub struct Splash {
    stop: Arc<AtomicBool>,
    status: StatusLine,
    painter: Option<JoinHandle<()>>,
}

impl Splash {
    /// Starts the banner. It shows nothing when `enabled` is false or stdout is not a terminal, and
    /// a terminal too small for the art gets the status line alone.
    pub fn start(enabled: bool) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let status = StatusLine(Arc::new(Mutex::new("Starting up".to_string())));
        if !enabled || !io::stdout().is_terminal() {
            return Self {
                stop,
                status,
                painter: None,
            };
        }
        let (cols, rows) = terminal::size().unwrap_or((0, 0));
        let (cols, rows) = (cols as usize, rows as usize);
        let fits = cols > ART_WIDTH + INDENT.len() && rows > ART.len() + 3;
        let art: &'static [&'static str] = if fits { &ART } else { &[] };
        let max_status =
            if cols == 0 { FALLBACK_COLS } else { cols }.saturating_sub(INDENT.len() + 1);

        let painter = {
            let stop = stop.clone();
            let status = status.clone();
            thread::spawn(move || {
                // Blank line, art, blank line, then the status line the cursor rests on.
                let lines_above = if art.is_empty() {
                    0
                } else {
                    art.len() as u16 + 2
                };
                let started = Instant::now();
                let _ = paint_art(art);
                let mut painted = 0u16;
                while !stop.load(Ordering::Relaxed) {
                    let lines = status_lines(&status.get(), started.elapsed(), max_status);
                    let _ = paint_status(&lines, &mut painted);
                    thread::sleep(FRAME);
                }
                let _ = erase(lines_above + painted.saturating_sub(1));
            })
        };
        Self {
            stop,
            status,
            painter: Some(painter),
        }
    }

    pub fn status(&self, text: impl Into<String>) {
        self.status.set(text);
    }

    /// A handle for reporting status from another thread.
    pub fn status_line(&self) -> StatusLine {
        self.status.clone()
    }
}

impl Drop for Splash {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(painter) = self.painter.take() {
            let _ = painter.join();
        }
    }
}

/// Runs the one-time setup of each of `backends` (`WorkerPool::warm_up`) before the TUI opens, on
/// `status`: a first run downloads several GB, better watched here, step by step, than behind a
/// dashboard that cannot prove yet. They run at once. Every later start finds everything in place
/// in milliseconds. Returns a problem line for each whose setup failed; the caller retries those
/// in the background as before.
pub fn run_setup(status: &StatusLine, backends: &[&str]) -> Vec<String> {
    use zkminer_prover::dispatcher::WARMUP_TIMEOUT;
    let Some(pool) = zkminer_prover::engine::worker_pool() else {
        return Vec::new();
    };
    let backends: Vec<&str> = backends
        .iter()
        .copied()
        .filter(|b| pool.has_slots(b) && !pool.backend_warmed(b))
        .collect();
    std::thread::scope(|scope| {
        let running: Vec<_> = backends
            .iter()
            .map(|&backend| {
                (
                    backend,
                    scope.spawn(move || pool.warm_up(backend, WARMUP_TIMEOUT)),
                )
            })
            .collect();
        while running.iter().any(|(_, setup)| !setup.is_finished()) {
            let mut lines = vec!["Setting up the provers".to_string()];
            for (backend, setup) in &running {
                let finished = setup.is_finished();
                let step = (!finished).then(|| pool.setup_status(backend)).flatten();
                let zkvm = crate::state::zkvm_label(backend);
                lines.push(setup_line(zkvm, step.as_ref(), finished));
            }
            status.set(lines.join("\n"));
            thread::sleep(FRAME);
        }
        running
            .into_iter()
            .filter_map(|(backend, setup)| {
                let zkvm = crate::state::zkvm_label(backend);
                match setup.join() {
                    Ok(Ok(summary)) => {
                        tracing::info!("{zkvm} is ready: {summary}");
                        None
                    }
                    Ok(Err(e)) => Some(format!(
                        "{zkvm} setup failed, retrying in the background: {e:#}"
                    )),
                    Err(_) => Some(format!("{zkvm} setup panicked")),
                }
            })
            .collect()
    })
}

const BAR_WIDTH: usize = 20;

/// A prover's line under "Setting up the provers": its zkVM, then a bar, percentage and bytes for a
/// step that counts them, then the step.
fn setup_line(
    zkvm: &str,
    step: Option<&zkminer_prover_protocol::SetupStep>,
    finished: bool,
) -> String {
    let what = match step {
        _ if finished => "done".to_string(),
        None => "checking".to_string(),
        Some(step) => match (step.fraction(), step.amount()) {
            (Some(f), Some(amount)) => format!(
                "{} {:>3.0}%  {amount}  {}",
                progress_bar(f),
                f * 100.0,
                step.status
            ),
            (None, Some(amount)) => format!("{amount}  {}", step.status),
            _ => step.status.clone(),
        },
    };
    format!("{zkvm:<10} {what}")
}

fn progress_bar(fraction: f64) -> String {
    let filled = ((fraction.clamp(0.0, 1.0) * BAR_WIDTH as f64).round() as usize).min(BAR_WIDTH);
    format!(
        "[{}{}]",
        "\u{2588}".repeat(filled),
        "\u{2591}".repeat(BAR_WIDTH - filled)
    )
}

/// What startup found, for the status line: each card and the zkVMs running on it, from
/// `WorkerPool::started_provers`.
pub fn found_summary(provers: &[(String, Option<String>)]) -> String {
    let mut cards: Vec<(String, Vec<&str>)> = Vec::new();
    for (backend, gpu) in provers {
        let card = gpu
            .as_deref()
            .map_or("CPU".to_string(), crate::state::short_gpu_name);
        let zkvm = crate::state::zkvm_label(backend);
        match cards.iter_mut().find(|(name, _)| *name == card) {
            Some((_, zkvms)) => zkvms.push(zkvm),
            None => cards.push((card, vec![zkvm])),
        }
    }
    if cards.is_empty() {
        return "no GPU provers".to_string();
    }
    cards
        .iter()
        .map(|(card, zkvms)| format!("{card}: {}", zkvms.join(", ")))
        .collect::<Vec<_>>()
        .join("; ")
}

/// The status line's text, cut to `max` characters: a wrapped line would break the erase.
fn status_text(status: &str, elapsed: Duration, max: usize) -> String {
    let spinner = SPINNER[(elapsed.as_millis() / FRAME.as_millis()) as usize % SPINNER.len()];
    format!("{spinner} {status}... {}s", elapsed.as_secs())
        .chars()
        .take(max)
        .collect()
}

fn paint_art(art: &[&str]) -> io::Result<()> {
    if art.is_empty() {
        return Ok(());
    }
    let mut out = io::stdout().lock();
    queue!(out, Print("\r\n"))?;
    for line in art {
        let (hemi, prove) = line.split_at(PROVE_COLUMN);
        queue!(
            out,
            Print(INDENT),
            SetForegroundColor(HEMI_ORANGE),
            Print(hemi),
            SetForegroundColor(Color::White),
            Print(prove),
            ResetColor,
            Print("\r\n"),
        )?;
    }
    queue!(out, Print("\r\n"))?;
    out.flush()
}

/// The status as the lines to paint: the first with the spinner and elapsed time, and any further
/// ones (a line per prover being set up) indented under it, each cut to `max` characters.
fn status_lines(status: &str, elapsed: Duration, max: usize) -> Vec<String> {
    let mut parts = status.split('\n');
    let first = status_text(parts.next().unwrap_or_default(), elapsed, max);
    std::iter::once(first)
        .chain(parts.map(|part| format!("  {part}").chars().take(max).collect()))
        .collect()
}

/// Paints `lines` over the `painted` lines the last call left, the cursor on the first of them's
/// row's last line, and clears what a taller status leaves below.
fn paint_status(lines: &[String], painted: &mut u16) -> io::Result<()> {
    let mut out = io::stdout().lock();
    queue!(out, cursor::MoveToColumn(0))?;
    if *painted > 1 {
        queue!(out, cursor::MoveUp(*painted - 1))?;
    }
    for (i, line) in lines.iter().enumerate() {
        if i > 0 {
            queue!(out, Print("\r\n"))?;
        }
        queue!(
            out,
            Print(INDENT),
            SetForegroundColor(Color::Grey),
            Print(line),
            ResetColor,
            Clear(ClearType::UntilNewLine),
        )?;
    }
    if (lines.len() as u16) < *painted {
        queue!(out, Clear(ClearType::FromCursorDown))?;
    }
    *painted = lines.len() as u16;
    out.flush()
}

fn erase(lines_above: u16) -> io::Result<()> {
    let mut out = io::stdout().lock();
    queue!(out, cursor::MoveToColumn(0))?;
    if lines_above > 0 {
        queue!(out, cursor::MoveUp(lines_above))?;
    }
    queue!(out, Clear(ClearType::FromCursorDown))?;
    out.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_summary_lists_each_card_and_its_zkvms() {
        let prover = |backend: &str, gpu: &str| (backend.to_string(), Some(gpu.to_string()));
        let rtx = "NVIDIA GeForce RTX 5090";
        let arc = "Intel(R) Arc(TM) Pro B70 Graphics";
        assert_eq!(
            found_summary(&[prover("risc0", rtx), prover("sp1", rtx)]),
            "RTX 5090: RISC Zero, SP1"
        );
        assert_eq!(
            found_summary(&[prover("risc0", rtx), prover("sp1", arc)]),
            "RTX 5090: RISC Zero; Arc Pro B70: SP1"
        );
        assert_eq!(found_summary(&[]), "no GPU provers");
    }

    #[test]
    fn art_fits_its_declared_width() {
        let widest = ART.iter().map(|line| line.chars().count()).max();
        assert_eq!(widest, Some(ART_WIDTH));
    }

    #[test]
    fn the_color_change_falls_between_hemi_and_prove() {
        assert!(ART
            .iter()
            .all(|line| line.is_ascii() && line.len() > PROVE_COLUMN));
        assert!(ART[1][..PROVE_COLUMN].ends_with("(_)"));
        assert!(ART[1][PROVE_COLUMN..].starts_with("|  _ \\"));
        assert!(ART[4][PROVE_COLUMN..].starts_with("|_|"));
    }

    #[test]
    fn status_text_reports_progress_and_never_wraps() {
        let elapsed = Duration::from_secs(12);
        assert_eq!(
            status_text("Starting workers", elapsed, 80),
            "| Starting workers... 12s"
        );
        assert_eq!(
            status_text("Starting workers", elapsed, 8).chars().count(),
            8
        );
    }

    #[test]
    fn each_prover_being_set_up_gets_its_own_line() {
        let lines = status_lines(
            "Setting up the provers\nSP1        a\nRISC Zero  b",
            Duration::from_secs(12),
            80,
        );
        assert_eq!(
            lines,
            [
                "| Setting up the provers... 12s",
                "  SP1        a",
                "  RISC Zero  b"
            ]
        );
        assert!(status_lines(&"x\n".repeat(3), Duration::ZERO, 5)
            .iter()
            .all(|l| l.chars().count() <= 5));
    }

    #[test]
    fn a_setup_line_has_a_bar_where_the_total_is_known() {
        let step = |done, total| zkminer_prover_protocol::SetupStep {
            status: "Downloading the Groth16 circuit (first run)".to_string(),
            done_bytes: done,
            total_bytes: total,
        };
        let half = step(Some(3_100_000_000), Some(6_200_000_000));
        assert_eq!(
            setup_line("SP1", Some(&half), false),
            format!(
                "SP1        [{}{}]  50%  3.1 of 6.2 GB  Downloading the Groth16 circuit (first run)",
                "\u{2588}".repeat(10),
                "\u{2591}".repeat(10)
            )
        );
        assert_eq!(
            setup_line("SP1", Some(&step(Some(3_100_000_000), None)), false),
            "SP1        3.1 GB so far  Downloading the Groth16 circuit (first run)"
        );
        assert_eq!(setup_line("RISC Zero", None, false), "RISC Zero  checking");
        assert_eq!(
            setup_line("RISC Zero", Some(&half), true),
            "RISC Zero  done"
        );
    }

    #[test]
    fn a_disabled_splash_still_accepts_status() {
        let splash = Splash::start(false);
        splash.status_line().set("Connecting");
        assert_eq!(splash.status.get(), "Connecting");
        assert!(splash.painter.is_none());
    }
}
