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
    let rows: Vec<Row> = jobs
        .iter()
        .enumerate()
        .map(|(i, job)| {
            let ours = i < claimed;
            let id_short = format!("{}...", &format!("{}", job.info.job_id)[..8]);
            let program_short = format!("{}...", &format!("{}", job.info.descriptor_hash)[..8]);

            let (price, status) = if ours {
                // What the claim locked, once known: the auction price moves on after the claim.
                let price = if job.info.settled_price > 0 {
                    job.info.settled_price
                } else {
                    job.current_price
                };
                (price, claimed_status_text(job, state, now))
            } else {
                (job.current_price, job_status_text(job, state))
            };

            let mut style = theme::striped(i);
            if i == state.selected_job_index {
                style = style.bg(theme::overlay());
            }
            let status_cell = if ours {
                Cell::from(status).style(theme::accent())
            } else {
                Cell::from(status)
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
                    " Jobs: {} claimed, {} open — [↑↓] select  [Enter] detail ",
                    claimed,
                    jobs.len() - claimed
                ),
                theme::title(),
            ))
            .borders(Borders::ALL)
            .border_style(theme::border())
            .border_type(theme::border_type()),
    );

    f.render_widget(table, area);
}

pub(crate) fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
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
        MinerJobStatus::Queued => "queued, waiting for a GPU".to_string(),
        MinerJobStatus::Proving {
            progress,
            elapsed_secs,
        } => {
            let on = card.map(|c| format!(" on {c}")).unwrap_or_default();
            format!(
                "proving{on}, {:.0}% after {}",
                progress * 100.0,
                format_duration(*elapsed_secs)
            )
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
        assert_eq!(
            claimed_status_text(&proving, &state, 1_000),
            "Claimed: proving, 42% after 1m 15s"
        );
        let mut late = job(3, MinerJobStatus::Submitting);
        late.info.lock_deadline = 900;
        assert_eq!(
            claimed_status_text(&late, &state, 1_000),
            "Claimed: proved, submitting, PAST its deadline"
        );
    }
}
