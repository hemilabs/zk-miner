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
                while !stop.load(Ordering::Relaxed) {
                    let line = status_text(&status.get(), started.elapsed(), max_status);
                    let _ = paint_status(&line);
                    thread::sleep(FRAME);
                }
                let _ = erase(lines_above);
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

fn paint_status(status: &str) -> io::Result<()> {
    let mut out = io::stdout().lock();
    queue!(
        out,
        cursor::MoveToColumn(0),
        Print(INDENT),
        SetForegroundColor(Color::Grey),
        Print(status),
        ResetColor,
        Clear(ClearType::UntilNewLine),
    )?;
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
    fn a_disabled_splash_still_accepts_status() {
        let splash = Splash::start(false);
        splash.status_line().set("Connecting");
        assert_eq!(splash.status.get(), "Connecting");
        assert!(splash.painter.is_none());
    }
}
