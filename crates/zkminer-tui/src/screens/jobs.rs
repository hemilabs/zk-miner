use ratatui::{
    layout::Constraint,
    widgets::{Block, Borders, Cell, Row, Table},
    Frame,
};

use super::dashboard::{format_duration, format_token_amount};
use crate::state::{MinerJobStatus, MinerState, TrackedJob};
use crate::theme;
use ratatui::text::Span;

pub fn render(f: &mut Frame, area: ratatui::layout::Rect, state: &MinerState) {
    let header_cells = [
        "ID",
        "Program",
        "Price",
        "Max Price",
        "Timeout",
        "Bonus",
        "Status / why not claimed",
    ]
    .iter()
    .map(|h| Cell::from(*h).style(theme::table_header()));
    let header = Row::new(header_cells).height(1);

    let now = now_unix();
    let jobs = state.jobs_page_rows();
    let claimed = state.active_jobs.len();
    let kind = |job: &TrackedJob| row_kind(job, state);
    let held = jobs.iter().filter(|j| kind(j) == RowKind::Held).count();
    let recent = jobs.iter().filter(|j| kind(j) == RowKind::Finished).count();
    let rows: Vec<Row> = jobs
        .iter()
        .enumerate()
        .map(|(i, job)| {
            let row = kind(job);
            let ours = row != RowKind::Open;
            let id_short = format!("{}...", &format!("{}", job.info.job_id)[..8]);
            let program_short = format!("{}...", &format!("{}", job.info.descriptor_hash)[..8]);

            // What the claim locked, once known: the auction price moves on after the claim.
            let locked = if job.info.settled_price > 0 {
                job.info.settled_price
            } else {
                job.current_price
            };
            let (price, status) = match row {
                RowKind::Claimed => (locked, claimed_status_text(job, state, now)),
                RowKind::Held => (locked, held_status_text(job, state, now)),
                RowKind::Finished => (locked, finished_status_text(job, state, now)),
                RowKind::Open => (job.current_price, job_status_text(job, state)),
            };

            let mut style = theme::striped(i);
            if i == state.selected_job_index {
                style = style.bg(theme::overlay());
            }
            let status_cell = match row {
                RowKind::Finished => Cell::from(status).style(theme::dim()),
                _ if ours => Cell::from(status).style(claimed_status_style(job, now)),
                _ => Cell::from(status),
            };

            Row::new(vec![
                Cell::from(id_short).style(theme::identifier()),
                Cell::from(program_short).style(theme::dim()),
                Cell::from(format_token_amount(price)),
                Cell::from(format_token_amount(job.info.max_price)),
                Cell::from(format!("{}s", job.info.fulfillment_timeout)),
                Cell::from(format_token_amount(job.info.bonus_amount)),
                status_cell,
            ])
            .style(style)
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(12),
            Constraint::Length(12),
            Constraint::Length(12),
            Constraint::Length(12),
            Constraint::Length(10),
            Constraint::Length(12),
            Constraint::Min(24),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .title(Span::styled(
                format!(
                    " Jobs: {claimed} claimed{}, {} open{} — [↑↓] select  [Enter] detail ",
                    if held > 0 {
                        format!(", {held} held but not being proven")
                    } else {
                        String::new()
                    },
                    jobs.len() - claimed - held - recent,
                    if recent > 0 {
                        format!(", last {recent} finished")
                    } else {
                        String::new()
                    },
                ),
                theme::title(),
            ))
            .borders(Borders::ALL)
            .border_style(theme::border())
            .border_type(theme::border_type()),
    );

    f.render_widget(table, area);
}

/// Which part of the Jobs page a row is in (`MinerState::jobs_page_rows`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RowKind {
    /// Claimed, and being proven or settled.
    Claimed,
    /// A lock held on-chain that nothing works on now (`MinerState::kept_locks`).
    Held,
    /// On the market.
    Open,
    /// Fulfilled or released (`MinerState::recent_finished`).
    Finished,
}

pub(crate) fn row_kind(job: &TrackedJob, state: &MinerState) -> RowKind {
    let id = job.info.job_id;
    if state.active_jobs.iter().any(|j| j.info.job_id == id) {
        RowKind::Claimed
    } else if state.kept_reason(id).is_some() {
        RowKind::Held
    } else if matches!(
        job.status,
        MinerJobStatus::Fulfilled { .. } | MinerJobStatus::Released { .. }
    ) {
        RowKind::Finished
    } else {
        RowKind::Open
    }
}

/// A held lock's status: why nothing works on it, and its deadline.
pub(crate) fn held_status_text(job: &TrackedJob, state: &MinerState, now: u64) -> String {
    let why = state.kept_reason(job.info.job_id).unwrap_or("held");
    let deadline = match job.info.lock_deadline {
        0 => String::new(),
        d if d > now => format!(", deadline in {}", format_duration(d - now)),
        _ => ", past its deadline".to_string(),
    };
    format!("Held, not being proven: {why}{deadline}")
}

/// A finished job's status: how it ended, and how long ago.
pub(crate) fn finished_status_text(job: &TrackedJob, state: &MinerState, now: u64) -> String {
    let how = match job.status {
        MinerJobStatus::Released { .. } => "Released",
        _ => "Fulfilled",
    };
    match state.finished_at.get(&job.info.job_id) {
        Some(at) => format!("{how} {} ago", format_duration(now.saturating_sub(*at))),
        None => how.to_string(),
    }
}

pub(crate) fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// The colour of a claimed job's status: green while it is proving or being submitted, blue while it
/// waits for a card, red only once it is past its deadline, the one claimed state that needs the
/// operator. (It was the theme's accent, a red-pink, for every claimed job.)
pub(crate) fn claimed_status_style(job: &TrackedJob, now: u64) -> ratatui::style::Style {
    if job.info.lock_deadline != 0 && job.info.lock_deadline <= now {
        return ratatui::style::Style::default().fg(theme::red());
    }
    match job.status {
        MinerJobStatus::Queued => theme::identifier(),
        _ => theme::positive(),
    }
}

/// The Status column of a job this miner has claimed: where it is (waiting for a card, proving on
/// which one and how far, or submitting) and how long is left before its deadline.
pub(crate) fn claimed_status_text(job: &TrackedJob, state: &MinerState, now: u64) -> String {
    let card = job.gpu_bus_id.as_deref().and_then(|bus| {
        state
            .hardware
            .gpus
            .iter()
            .find(|g| g.pci_bus_id == bus)
            .map(|g| {
                let name = g
                    .name
                    .trim_start_matches("NVIDIA ")
                    .trim_start_matches("GeForce ");
                format!("GPU{} {name}", g.index)
            })
    });
    let stage = match &job.status {
        // What it is waiting on now, where the status would say something older (`JobNote`).
        _ if state.job_note_text(job).is_some() => state.job_note_text(job).unwrap_or_default(),
        MinerJobStatus::Queued => "queued, waiting for a GPU".to_string(),
        MinerJobStatus::Proving { .. } => {
            let on = card.map(|c| format!(" on {c}")).unwrap_or_default();
            let secs = format_duration(state.proving_secs(job));
            let stage = state
                .proving_stage_label(job)
                .map(|l| format!(" ({l})"))
                .unwrap_or_default();
            // With nothing to weigh the stages by (no measurement, no benchmark row), only how long
            // it has run, not a made-up percentage.
            match state.proving_fraction(job) {
                Some(f) => format!("proving{on}, {:.0}% after {secs}{stage}", f * 100.0),
                None => format!("proving{on} for {secs}{stage}"),
            }
        }
        MinerJobStatus::Submitting => "proved, submitting".to_string(),
        other => job_status_text(
            &TrackedJob {
                status: other.clone(),
                ..job.clone()
            },
            state,
        )
        .to_lowercase(),
    };
    let deadline = match job.info.lock_deadline {
        0 => String::new(),
        d if d > now => format!(", deadline in {}", format_duration(d - now)),
        _ => ", PAST its deadline".to_string(),
    };
    format!("Claimed: {stage}{deadline}")
}

/// The Status column: for an open job, why the miner did not claim it when it last looked (or that it
/// has not looked yet); otherwise the job's state, with a skip's reason.
pub(crate) fn job_status_text(job: &TrackedJob, state: &MinerState) -> String {
    // Being claimed: the claim transaction's stage (`JobNote`), not why it was passed over before.
    if let Some(note) = state.job_note_text(job) {
        return note;
    }
    match &job.status {
        MinerJobStatus::Open => match (
            &state.claim_outlook.held,
            state.job_why.get(&job.info.job_id),
        ) {
            // A hold stops every claim before any job is looked at: that is the reason now.
            (Some(held), _) => format!("held: {held}"),
            (None, Some(why)) => why.clone(),
            (None, None) => "Open (not evaluated yet)".to_string(),
        },
        MinerJobStatus::Queued => "Queued".to_string(),
        MinerJobStatus::Proving { .. } => "Proving".to_string(),
        MinerJobStatus::Submitting => "Submitting".to_string(),
        MinerJobStatus::Fulfilled { .. } => "Fulfilled".to_string(),
        MinerJobStatus::Released { .. } => "Released".to_string(),
        MinerJobStatus::Skipped { reason } => format!("Skipped: {reason}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::B256;

    fn job(id: u8, status: MinerJobStatus) -> TrackedJob {
        TrackedJob {
            info: zkminer_chain::jobs::JobInfo {
                job_id: B256::repeat_byte(id),
                ..Default::default()
            },
            status,
            current_price: 20,
            gpu_bus_id: None,
            prover_backend: String::new(),
            estimated_cycles: 0,
        }
    }

    /// The page lists claimed jobs, then locks held but not worked on (with why), then the market,
    /// then the latest finished jobs (with how they ended and when); each job once.
    #[test]
    fn held_locks_and_finished_jobs_are_listed() {
        let mut state = MinerState {
            open_jobs: vec![job(3, MinerJobStatus::Open), job(1, MinerJobStatus::Open)],
            active_jobs: vec![
                job(1, MinerJobStatus::Queued),
                job(5, MinerJobStatus::Queued),
            ],
            kept_locks: vec![job(2, MinerJobStatus::Queued)],
            ..Default::default()
        };
        state.kept_reasons.insert(
            B256::repeat_byte(2),
            "past its deadline, so it cannot be released".into(),
        );
        state.record_finished(
            B256::repeat_byte(5),
            MinerJobStatus::Fulfilled { payout: 0 },
        );
        let ids: Vec<u8> = state
            .jobs_page_rows()
            .iter()
            .map(|j| j.info.job_id.0[0])
            .collect();
        assert_eq!(ids, vec![1, 2, 3, 5]);
        let rows = state.jobs_page_rows();
        let kinds: Vec<RowKind> = rows.iter().map(|j| row_kind(j, &state)).collect();
        assert_eq!(
            kinds,
            vec![
                RowKind::Claimed,
                RowKind::Held,
                RowKind::Open,
                RowKind::Finished
            ]
        );
        let now = now_unix();
        assert!(held_status_text(rows[1], &state, now)
            .starts_with("Held, not being proven: past its deadline"));
        assert!(finished_status_text(rows[3], &state, now).starts_with("Fulfilled "));
        // A held lock taken up again is a claimed job, not a held one.
        state.active_jobs.push(job(2, MinerJobStatus::Queued));
        assert_eq!(state.kept_reason(B256::repeat_byte(2)), None);
    }

    /// While a job waits on something its status would not say (a claim or fulfil transaction the
    /// chain has not confirmed, memory, a retry), its status line says that, with how long; the
    /// transaction's own events rewrite it, and one arriving after its stage ended changes nothing.
    #[test]
    fn a_job_says_what_it_is_waiting_on() {
        use crate::state::JobNoteKind;
        use zkminer_chain::tx_events::{TxEvent, TxKind};
        let mut state = MinerState {
            open_jobs: vec![job(1, MinerJobStatus::Open)],
            active_jobs: vec![
                job(2, MinerJobStatus::Queued),
                job(3, MinerJobStatus::Submitting),
            ],
            ..Default::default()
        };
        let (claiming, queued, submitting) = (
            B256::repeat_byte(1),
            B256::repeat_byte(2),
            B256::repeat_byte(3),
        );
        // Being claimed: the claim's stage, not why it was passed over before.
        state.set_job_note(
            claiming,
            JobNoteKind::Claim,
            "claiming: sending the claim transaction",
        );
        state.on_tx_event(claiming, TxKind::Claim, TxEvent::Sent { attempt: 1, of: 5 });
        assert!(job_status_text(&state.open_jobs[0], &state)
            .starts_with("claiming: waiting for the chain to confirm (try 1 of 5), "));
        state.on_tx_event(
            claiming,
            TxKind::Claim,
            TxEvent::Unconfirmed { attempt: 1, of: 5 },
        );
        assert!(job_status_text(&state.open_jobs[0], &state)
            .starts_with("claiming: not confirmed yet, checking the chain before sending again"));
        // A fulfil event does not touch a claim's note.
        state.on_tx_event(
            claiming,
            TxKind::Fulfil,
            TxEvent::Sent { attempt: 1, of: 5 },
        );
        assert!(job_status_text(&state.open_jobs[0], &state).starts_with("claiming: not confirmed"));
        // Once the claim is over, a late event of it changes nothing.
        state.clear_job_note(claiming, JobNoteKind::Claim);
        state.on_tx_event(claiming, TxKind::Claim, TxEvent::Sent { attempt: 2, of: 5 });
        assert!(!state.job_notes.contains_key(&claiming));
        assert_eq!(
            job_status_text(&state.open_jobs[0], &state),
            "Open (not evaluated yet)"
        );

        // Waiting for memory, not "waiting for a GPU".
        let now = 0;
        assert!(
            claimed_status_text(&state.active_jobs[0], &state, now).contains("waiting for a GPU")
        );
        state.set_job_note(queued, JobNoteKind::Wait, "waiting for host memory");
        assert!(claimed_status_text(&state.active_jobs[0], &state, now)
            .starts_with("Claimed: waiting for host memory, "));
        // Submitting: the fulfil's stage, rate limiting included.
        state.set_job_note(
            submitting,
            JobNoteKind::Submit,
            "submitting the proof: sending",
        );
        state.on_tx_event(
            submitting,
            TxKind::Fulfil,
            TxEvent::SendFailed {
                attempt: 2,
                of: 5,
                rate_limited: true,
            },
        );
        assert!(claimed_status_text(&state.active_jobs[1], &state, now).starts_with(
            "Claimed: submitting the proof: the RPC is rate-limiting, sending again shortly (try 2 of 5)"
        ));
        // Proving speaks for itself: a stale note is not shown over it.
        state.active_jobs[0].status = MinerJobStatus::Proving {
            progress: 0.0,
            elapsed_secs: 0,
        };
        assert!(state.job_note_text(&state.active_jobs[0]).is_none());
        // Notes of jobs no longer listed go when another is set.
        state.active_jobs.retain(|j| j.info.job_id != submitting);
        state.set_job_note(queued, JobNoteKind::Wait, "trying again");
        assert!(!state.job_notes.contains_key(&submitting));
    }

    /// Claimed jobs come first, and a job both claimed and still in the market list (the list has
    /// not caught up with the claim) is listed once, as claimed.
    #[test]
    fn claimed_jobs_lead_the_page_once() {
        let state = MinerState {
            open_jobs: vec![job(1, MinerJobStatus::Open), job(2, MinerJobStatus::Open)],
            active_jobs: vec![
                job(2, MinerJobStatus::Queued),
                job(3, MinerJobStatus::Queued),
            ],
            ..Default::default()
        };
        let ids: Vec<u8> = state
            .jobs_page_rows()
            .iter()
            .map(|j| j.info.job_id[0])
            .collect();
        assert_eq!(ids, vec![2, 3, 1]);
    }

    /// Claimed jobs read green while proving, blue while queued, and red only past their deadline.
    #[test]
    fn claimed_status_colours_follow_the_stage() {
        let mut queued = job(1, MinerJobStatus::Queued);
        queued.info.lock_deadline = 2_000;
        let mut proving = job(
            2,
            MinerJobStatus::Proving {
                progress: 0.5,
                elapsed_secs: 10,
            },
        );
        proving.info.lock_deadline = 2_000;
        assert_eq!(claimed_status_style(&queued, 1_000), theme::identifier());
        assert_eq!(claimed_status_style(&proving, 1_000), theme::positive());
        assert_eq!(claimed_status_style(&proving, 2_000).fg, Some(theme::red()));
    }

    /// The status of a claimed job names its stage and its deadline.
    #[test]
    fn a_claimed_jobs_status_names_its_stage_and_deadline() {
        let state = MinerState::default();
        let mut queued = job(1, MinerJobStatus::Queued);
        queued.info.lock_deadline = 1_000 + 3_700;
        assert_eq!(
            claimed_status_text(&queued, &state, 1_000),
            "Claimed: queued, waiting for a GPU, deadline in 1h 1m"
        );
        let proving = job(
            2,
            MinerJobStatus::Proving {
                progress: 0.42,
                elapsed_secs: 75,
            },
        );
        // A worker that reports no progress: how long it has run, not a stuck 0%.
        let silent = job(
            4,
            MinerJobStatus::Proving {
                progress: 0.0,
                elapsed_secs: 75,
            },
        );
        assert_eq!(
            claimed_status_text(&silent, &state, 1_000),
            "Claimed: proving for 1m 15s"
        );
        // The status's own fraction is not shown: with no measurement and no benchmark to weigh the
        // worker's stages by, there is no honest percentage.
        assert_eq!(
            claimed_status_text(&proving, &state, 1_000),
            "Claimed: proving for 1m 15s"
        );
        let mut late = job(3, MinerJobStatus::Submitting);
        late.info.lock_deadline = 900;
        assert_eq!(
            claimed_status_text(&late, &state, 1_000),
            "Claimed: proved, submitting, PAST its deadline"
        );
    }
}
