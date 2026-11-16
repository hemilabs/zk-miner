//! Stopping the miner from the dashboard: the quit prompt, and the shutdown panel that stays on
//! screen while the miner drains, abandons or hands its locks to the next start.
//!
//! Quitting used to close the dashboard at once and leave a drain of up to 50 minutes running
//! behind a blank terminal, where a reflexive second Ctrl+C abandoned every lock (a release
//! penalty of 5-30% of each lock's collateral). Now quit asks first when jobs are held, a second
//! Ctrl+C at the prompt does nothing, and the dashboard stays open until the miner exits.

use crate::state::{
    LogLevel, MinerJobStatus, MinerState, ShutdownStage, ShutdownView, StopMode, StopPrompt,
};
use crate::theme;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{
    layout::Rect,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph, Wrap},
    Frame,
};

/// The jobs a stop has to deal with, from what the dashboard knows.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct HeldJobs {
    /// Claimed and not yet proved: queued or proving.
    pub proving: usize,
    /// Proved, with the proof being submitted (an abandon leaves these to finish).
    pub submitting: usize,
    /// What releasing the `proving` jobs now would cost, over the ones whose collateral is known.
    pub release_penalty: u128,
    /// `proving` jobs whose collateral is not known here (so not in `release_penalty`).
    pub penalty_unknown: usize,
    /// The earliest working cutoff among them (unix seconds: the last moment a proof is
    /// accepted or a release is possible), if any is known.
    pub earliest_deadline: Option<u64>,
    /// Queued or proving jobs whose cutoff is too close for a restart to save them: a keep-locks
    /// stop releases these first.
    pub too_close_to_keep: usize,
}

impl HeldJobs {
    pub fn total(&self) -> usize {
        self.proving + self.submitting
    }
}

/// The held jobs as of `now` (unix seconds).
pub fn held_jobs(state: &MinerState, now: u64) -> HeldJobs {
    let mut held = HeldJobs::default();
    for job in &state.active_jobs {
        match job.status {
            MinerJobStatus::Queued | MinerJobStatus::Proving { .. } => {
                held.proving += 1;
                // Both known, or the 5% floor would understate it (the penalty scales up to 30%
                // with the time left in the fulfilment window).
                if job.info.locked_collateral > 0 && job.info.fulfillment_timeout > 0 {
                    // `lock_deadline` here is the miner's working cutoff, the contract's
                    // `lockDeadline` plus PROVER_GRACE; the penalty scales with the time left to
                    // the contract's own deadline.
                    held.release_penalty += zkminer_chain::auction::compute_release_penalty(
                        job.info.locked_collateral,
                        job.info.fulfillment_timeout,
                        job.info
                            .lock_deadline
                            .saturating_sub(zkminer_chain::auction::PROVER_GRACE_SECS),
                        now,
                    );
                } else {
                    held.penalty_unknown += 1;
                }
            }
            MinerJobStatus::Submitting => held.submitting += 1,
            _ => continue,
        }
        if matches!(
            job.status,
            MinerJobStatus::Queued | MinerJobStatus::Proving { .. }
        ) && job.info.lock_deadline > 0
            && state.release_margin_secs > 0
            && job.info.lock_deadline <= now.saturating_add(state.release_margin_secs + 120)
        {
            held.too_close_to_keep += 1;
        }
        if job.info.lock_deadline > 0 {
            held.earliest_deadline = Some(
                held.earliest_deadline
                    .map_or(job.info.lock_deadline, |d| d.min(job.info.lock_deadline)),
            );
        }
    }
    held
}

fn now_secs() -> u64 {
    chrono::Utc::now().timestamp().max(0) as u64
}

fn fmt_time(unix: u64) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp(unix as i64, 0)
        .map(|t| t.format("%H:%M UTC").to_string())
        .unwrap_or_else(|| "?".into())
}

fn fmt_penalty(held: &HeldJobs) -> String {
    let known = zkminer_chain::staking::fmt_hemi_ceil(held.release_penalty);
    match held.penalty_unknown {
        0 => format!("≈ {known} HEMI"),
        n if n == held.proving => "5-30% of each lock's collateral".to_string(),
        n => format!("≈ {known} HEMI + 5-30% of {n} more lock(s)"),
    }
}

fn choose(state: &mut MinerState, mode: StopMode) {
    state.stop_prompt = None;
    state.stop_request = Some(mode);
}

/// Handle a key while the miner owns the shutdown (`stop_handled_by_miner`). Returns true when
/// the key was used here and must not reach the screen it was pressed on.
pub fn handle_key(state: &mut MinerState, key: KeyEvent) -> bool {
    let ctrl_c = key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL);
    let quit = ctrl_c || matches!(key.code, KeyCode::Char('q') | KeyCode::Char('Q'));
    if state.shutdown.is_some() && state.stop_prompt == Some(StopPrompt::Quit) {
        // A stop began elsewhere (`zkminer stop`, a signal) while the question was open: it no
        // longer applies, and its keys would skip the confirmations the panel asks for.
        state.stop_prompt = None;
    }
    if let Some(prompt) = state.stop_prompt {
        match prompt {
            StopPrompt::Quit => match key.code {
                KeyCode::Char('d') | KeyCode::Char('D') | KeyCode::Enter => {
                    choose(state, StopMode::Drain)
                }
                KeyCode::Char('k') | KeyCode::Char('K') => choose(state, StopMode::KeepLocks),
                KeyCode::Char('a') | KeyCode::Char('A') => choose(state, StopMode::Abandon),
                KeyCode::Esc | KeyCode::Char('n') | KeyCode::Char('N') => state.stop_prompt = None,
                // Anything else, a second q or Ctrl+C included, leaves the question open: a
                // reflexive double press must not choose for the operator.
                _ => {}
            },
            StopPrompt::Confirm(mode) => match key.code {
                KeyCode::Char('y') | KeyCode::Char('Y') => choose(state, mode),
                _ => state.stop_prompt = None,
            },
        }
        return true;
    }
    if let Some(stage) = state.shutdown.as_ref().map(|v| v.stage) {
        let ask =
            |state: &mut MinerState, mode| state.stop_prompt = Some(StopPrompt::Confirm(mode));
        match key.code {
            KeyCode::Char('a') | KeyCode::Char('A')
                if matches!(stage, ShutdownStage::Draining | ShutdownStage::KeepingLocks) =>
            {
                ask(state, StopMode::Abandon)
            }
            KeyCode::Char('k') | KeyCode::Char('K') if stage == ShutdownStage::Draining => {
                ask(state, StopMode::KeepLocks)
            }
            KeyCode::Char('x') | KeyCode::Char('X') => ask(state, StopMode::Force),
            KeyCode::Char('a') | KeyCode::Char('A') => state.add_log(
                LogLevel::Warn,
                "Too late to abandon: the miner is already releasing, or exiting.",
            ),
            _ if quit => state.add_log(
                LogLevel::Warn,
                match stage {
                    ShutdownStage::Draining => {
                        "Already stopping — the dashboard closes when the miner exits. [a] \
                         abandon, [k] keep locks, [x] force exit."
                    }
                    ShutdownStage::KeepingLocks => {
                        "Already stopping, keeping the locks. [a] abandon instead, [x] force exit."
                    }
                    _ => {
                        "Already stopping — the dashboard closes when the miner exits. [x] force \
                          exit."
                    }
                },
            ),
            // Moving around still works. Everything else is swallowed: `p` must not resume
            // claiming, and the screens' actions (a benchmark, GPU tuning, the setup wizard's
            // mint and stake) would compete with the stop for the workers and the signer.
            _ if navigation(state, key.code) => return false,
            _ => {}
        }
        return true;
    }
    if quit {
        if state.stop_request.is_some() {
            // Asked already; the miner has not picked it up yet.
            return true;
        }
        if held_jobs(state, now_secs()).total() > 0 {
            state.stop_prompt = Some(StopPrompt::Quit);
        } else {
            choose(state, StopMode::Drain);
        }
        return true;
    }
    false
}

/// Keys that only move around the dashboard.
fn navigation(state: &MinerState, code: KeyCode) -> bool {
    use crate::state::Screen;
    match code {
        KeyCode::Char('1'..='7')
        | KeyCode::Up
        | KeyCode::Down
        | KeyCode::Char('j')
        | KeyCode::PageUp
        | KeyCode::PageDown
        | KeyCode::Char('T') => true,
        // Settings uses Tab between sections; Enter on Jobs opens a job's detail.
        KeyCode::Tab | KeyCode::BackTab => state.current_screen == Screen::Settings,
        KeyCode::Enter => state.current_screen == Screen::Jobs,
        _ => false,
    }
}

/// A box of `w` x `h` centred in `area`, clipped to it.
fn centred(area: Rect, w: u16, h: u16) -> Rect {
    let w = w.min(area.width);
    let h = h.min(area.height);
    Rect {
        x: area.x + (area.width - w) / 2,
        y: area.y + (area.height - h) / 2,
        width: w,
        height: h,
    }
}

fn key_line<'a>(key: &'a str, text: String) -> Line<'a> {
    Line::from(vec![
        Span::styled(
            format!(" [{key}] "),
            theme::accent().add_modifier(Modifier::BOLD),
        ),
        Span::styled(text, Style::default().fg(theme::text())),
    ])
}

/// The quit prompt and its confirmations, drawn over the screen.
pub fn render_prompt(f: &mut Frame, area: Rect, state: &MinerState) {
    let Some(prompt) = state.stop_prompt else {
        return;
    };
    let held = held_jobs(state, now_secs());
    // The last moment the next start can still release the earliest lock in time: its cutoff
    // less the margin a release and a restart need (the miner publishes it). Finishing it needs
    // earlier still.
    let restart_by = held
        .earliest_deadline
        .filter(|_| state.release_margin_secs > 0)
        .map(|d| {
            format!(
                " (start it again by {})",
                fmt_time(d.saturating_sub(state.release_margin_secs))
            )
        })
        .unwrap_or_default();
    let too_close = match held.too_close_to_keep {
        0 => String::new(),
        n => format!("; {n} too close to their deadline to keep are released first"),
    };
    let (title, mut lines) = match prompt {
        StopPrompt::Quit => {
            let mut lines = vec![
                Line::from(Span::styled(
                    format!(
                        " {} job(s) hold collateral: {} queued or proving, {} submitting a proof.",
                        held.total(),
                        held.proving,
                        held.submitting
                    ),
                    Style::default().fg(theme::text()),
                )),
                Line::from(""),
                key_line(
                    "d",
                    "Drain: finish them, get paid, then exit (as long as the proofs take; after \
                     ~50 min whatever is left is released, at a penalty)"
                        .into(),
                ),
                key_line(
                    "k",
                    format!(
                        "Keep locks: exit within minutes; the next start finishes them\
                         {restart_by}{too_close}"
                    ),
                ),
            ];
            if held.proving > 0 {
                lines.push(key_line(
                    "a",
                    format!("Abandon: release them now, penalty {}", fmt_penalty(&held)),
                ));
            }
            lines.push(key_line("Esc", "Keep mining".into()));
            (" Stop the miner? ", lines)
        }
        StopPrompt::Confirm(StopMode::Abandon) => (
            " Abandon? ",
            vec![Line::from(format!(
                " Release {} job(s) now, penalty {}? Proofs being submitted are left to finish.",
                held.proving,
                fmt_penalty(&held)
            ))],
        ),
        StopPrompt::Confirm(StopMode::KeepLocks) => (
            " Keep locks? ",
            vec![Line::from(format!(
                " Stop the proofs and exit now, leaving {} lock(s) for the next start{restart_by}? \
                 A lock nobody finishes or releases before its deadline is slashed.",
                held.proving
            ))],
        ),
        StopPrompt::Confirm(StopMode::Force) => (
            " Force exit? ",
            vec![Line::from(
                " Exit at once, without waiting for releases or receipts? Whatever is still held \
                 stays locked until the next start.",
            )],
        ),
        StopPrompt::Confirm(StopMode::Drain) => (" Drain? ", vec![Line::from(" Drain?")]),
    };
    if matches!(prompt, StopPrompt::Confirm(_)) {
        lines.push(Line::from(""));
        lines.push(key_line("y", "Yes".into()));
        lines.push(key_line("any other key", "No".into()));
    }
    let width = area.width.saturating_sub(4).min(92);
    let inner = width.saturating_sub(2).max(1) as usize;
    let height = lines
        .iter()
        .map(|l| l.width().div_ceil(inner).max(1) as u16)
        .sum::<u16>()
        + 2;
    let rect = centred(area, width, height);
    f.render_widget(Clear, rect);
    f.render_widget(
        Paragraph::new(lines).wrap(Wrap { trim: false }).block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(theme::border_type())
                .border_style(theme::warning())
                .title(Span::styled(
                    title,
                    theme::warning().add_modifier(Modifier::BOLD),
                ))
                .style(theme::canvas()),
        ),
        rect,
    );
}

/// The shutdown panel's title and lines: what the stop is doing, the keys that change it (before
/// the history, so a short panel never cuts them off), then the last few things it reported.
fn panel_content(view: &ShutdownView) -> (&'static str, Vec<Line<'static>>) {
    let (title, hints): (&str, &str) = match view.stage {
        ShutdownStage::Draining => (
            " STOPPING — DRAINING ",
            "[a] abandon (release now)  [k] keep locks and exit  [x] force exit  — or wait: it \
             exits by itself when the proofs are done",
        ),
        ShutdownStage::KeepingLocks => (
            " STOPPING — KEEPING LOCKS ",
            "[a] abandon instead  [x] force exit",
        ),
        ShutdownStage::Abandoning => (" STOPPING — RELEASING ", "[x] force exit"),
        ShutdownStage::Finishing => (" STOPPING ", "[x] force exit"),
    };
    let mut lines = Vec::new();
    if !view.status.is_empty() {
        lines.push(Line::from(Span::styled(
            view.status.clone(),
            Style::default()
                .fg(theme::text())
                .add_modifier(Modifier::BOLD),
        )));
    }
    lines.push(Line::from(Span::styled(hints, theme::accent())));
    let skip = view.lines.len().saturating_sub(4);
    lines.extend(
        view.lines
            .iter()
            .skip(skip)
            .map(|l| Line::from(Span::styled(l.clone(), theme::dim()))),
    );
    (title, lines)
}

/// How many rows the shutdown panel needs at `width` columns, borders and wrapping included.
pub fn panel_height(view: &ShutdownView, width: u16) -> u16 {
    let inner = width.saturating_sub(2).max(1) as usize;
    let (_, lines) = panel_content(view);
    2 + lines
        .iter()
        .map(|l| l.width().div_ceil(inner).max(1) as u16)
        .sum::<u16>()
}

/// The shutdown panel: what the stop is doing and the keys that change it.
pub fn render_panel(f: &mut Frame, area: Rect, view: &ShutdownView) {
    let (title, lines) = panel_content(view);
    f.render_widget(Clear, area);
    f.render_widget(
        Paragraph::new(lines).wrap(Wrap { trim: true }).block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(theme::border_type())
                .border_style(theme::warning())
                .title(Span::styled(
                    title,
                    theme::warning().add_modifier(Modifier::BOLD),
                ))
                .style(theme::canvas()),
        ),
        area,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::TrackedJob;
    use crossterm::event::{KeyEventKind, KeyEventState};

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent {
            code,
            modifiers: KeyModifiers::NONE,
            kind: KeyEventKind::Press,
            state: KeyEventState::NONE,
        }
    }

    fn ctrl_c() -> KeyEvent {
        KeyEvent {
            modifiers: KeyModifiers::CONTROL,
            ..key(KeyCode::Char('c'))
        }
    }

    fn job(status: MinerJobStatus, collateral: u128, deadline: u64) -> TrackedJob {
        let info = zkminer_chain::jobs::JobInfo {
            locked_collateral: collateral,
            lock_deadline: deadline,
            fulfillment_timeout: 3600,
            ..Default::default()
        };
        TrackedJob {
            info,
            status,
            current_price: 0,
            gpu_bus_id: None,
            prover_backend: String::new(),
            estimated_cycles: 0,
        }
    }

    fn miner() -> MinerState {
        MinerState {
            stop_handled_by_miner: true,
            ..MinerState::default()
        }
    }

    /// Nothing held: quit stops at once (a drain with nothing to wait for).
    #[test]
    fn quit_with_nothing_held_stops_without_asking() {
        let mut s = miner();
        assert!(handle_key(&mut s, key(KeyCode::Char('q'))));
        assert_eq!(s.stop_request, Some(StopMode::Drain));
        assert_eq!(s.stop_prompt, None);
    }

    /// Jobs held: quit asks, a second Ctrl+C leaves the question open, and each key picks its mode.
    #[test]
    fn quit_with_jobs_held_asks_and_a_double_ctrl_c_chooses_nothing() {
        for (k, want) in [
            ('d', Some(StopMode::Drain)),
            ('k', Some(StopMode::KeepLocks)),
            ('a', Some(StopMode::Abandon)),
        ] {
            let mut s = miner();
            s.active_jobs.push(job(
                MinerJobStatus::Proving {
                    progress: 0.5,
                    elapsed_secs: 9,
                },
                0,
                0,
            ));
            assert!(handle_key(&mut s, ctrl_c()));
            assert_eq!(s.stop_prompt, Some(StopPrompt::Quit));
            assert!(handle_key(&mut s, ctrl_c()));
            assert!(handle_key(&mut s, key(KeyCode::Char('q'))));
            assert_eq!(s.stop_request, None, "a repeated quit key must not choose");
            assert!(handle_key(&mut s, key(KeyCode::Char(k))));
            assert_eq!(s.stop_request, want);
            assert_eq!(s.stop_prompt, None);
        }
        let mut s = miner();
        s.active_jobs.push(job(MinerJobStatus::Queued, 0, 0));
        handle_key(&mut s, key(KeyCode::Char('q')));
        assert!(handle_key(&mut s, key(KeyCode::Esc)));
        assert_eq!((s.stop_prompt, s.stop_request), (None, None));
    }

    /// During a drain: `a`/`k`/`x` ask before acting, `p` cannot resume claiming, quit keys only
    /// say what to press, and other keys still navigate.
    #[test]
    fn keys_during_a_drain() {
        let mut s = miner();
        s.paused = true;
        s.shutdown = Some(ShutdownView::new(ShutdownStage::Draining));
        assert!(handle_key(&mut s, key(KeyCode::Char('p'))));
        assert!(s.paused);
        assert!(handle_key(&mut s, ctrl_c()));
        assert_eq!((s.stop_prompt, s.stop_request), (None, None));
        assert!(
            !handle_key(&mut s, key(KeyCode::Char('3'))),
            "navigation still works"
        );
        assert!(handle_key(&mut s, key(KeyCode::Char('a'))));
        assert_eq!(s.stop_prompt, Some(StopPrompt::Confirm(StopMode::Abandon)));
        assert!(handle_key(&mut s, key(KeyCode::Char('n'))));
        assert_eq!((s.stop_prompt, s.stop_request), (None, None));
        handle_key(&mut s, key(KeyCode::Char('k')));
        handle_key(&mut s, key(KeyCode::Char('y')));
        assert_eq!(s.stop_request, Some(StopMode::KeepLocks));
        // Once releasing, keeping the locks is no longer on offer (and `k` does nothing).
        let mut s = miner();
        s.shutdown = Some(ShutdownView::new(ShutdownStage::Abandoning));
        assert!(handle_key(&mut s, key(KeyCode::Char('k'))));
        assert_eq!(s.stop_prompt, None);
    }

    /// The penalty quoted is the contract's: 5% at the deadline, up to 30% with the whole
    /// fulfilment window left; a job being submitted is not released, so not counted.
    #[test]
    fn the_quoted_penalty_follows_the_contract() {
        let now = 1_000_000;
        let hemi = 1_000_000_000_000_000_000u128;
        let mut s = miner();
        s.active_jobs.push(job(
            MinerJobStatus::Queued,
            100 * hemi,
            now + 3600 + zkminer_chain::auction::PROVER_GRACE_SECS,
        ));
        s.active_jobs.push(job(
            MinerJobStatus::Queued,
            100 * hemi,
            now + 10 + zkminer_chain::auction::PROVER_GRACE_SECS,
        ));
        s.active_jobs
            .push(job(MinerJobStatus::Submitting, 100 * hemi, now + 5));
        let held = held_jobs(&s, now);
        assert_eq!((held.proving, held.submitting), (2, 1));
        assert_eq!(held.release_penalty, 30 * hemi + 5 * hemi);
        assert_eq!(held.earliest_deadline, Some(now + 5));
        assert_eq!(fmt_penalty(&held), "≈ 35.00 HEMI");
    }

    fn rendered(state: &MinerState) -> String {
        use ratatui::{backend::TestBackend, Terminal};
        let mut t = Terminal::new(TestBackend::new(100, 30)).unwrap();
        t.draw(|f| render_prompt(f, f.area(), state)).unwrap();
        let buf = t.backend().buffer().clone();
        let mut out = String::new();
        for y in 0..buf.area.height {
            for x in 0..buf.area.width {
                out.push_str(buf[(x, y)].symbol());
            }
            out.push('\n');
        }
        out
    }

    #[test]
    fn the_quit_prompt_shows_every_choice() {
        let mut s = miner();
        s.active_jobs.push(job(MinerJobStatus::Queued, 0, 0));
        s.stop_prompt = Some(StopPrompt::Quit);
        let out = rendered(&s);
        for want in [
            "[d]",
            "Drain",
            "[k]",
            "Keep locks",
            "[a]",
            "Abandon",
            "[Esc]",
        ] {
            assert!(out.contains(want), "{want} missing:\n{out}");
        }
    }
}
