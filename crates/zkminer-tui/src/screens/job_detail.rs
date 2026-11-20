use ratatui::{
    layout::{Constraint, Direction, Layout},
    style::Style,
    text::{Line, Span},
    widgets::{Block, Borders, Gauge, Paragraph},
    Frame,
};

use super::dashboard::{format_duration, format_token_amount};
use super::jobs::now_unix;
use crate::state::{MinerJobStatus, MinerState, TrackedJob};
use crate::theme;

pub fn render(f: &mut Frame, area: ratatui::layout::Rect, state: &MinerState) {
    // The job Enter picked, by id: the open list reorders by price every pass, so its index alone
    // would show a different job a moment later.
    // Any row the Jobs page lists: claimed, held, open, or recently finished.
    let by_id = |id| {
        state
            .jobs_page_rows()
            .into_iter()
            .find(|j| j.info.job_id == id)
    };
    // A job picked by id that is no longer listed (fulfilled, released, claimed by another prover)
    // is reported as such: falling back to the index would show a different job as if it were it.
    let selected = match state.selected_job_id {
        Some(id) => by_id(id),
        None => state
            .jobs_page_rows()
            .get(state.selected_job_index)
            .copied(),
    };
    if selected.is_none() && state.selected_job_id.is_some() {
        let paragraph = Paragraph::new(Span::styled(
            "That job is no longer listed (fulfilled, released, or claimed by another prover). \
             Press 2 to browse jobs.",
            theme::placeholder(),
        ))
        .block(
            Block::default()
                .title(Span::styled(" Job Detail ", theme::title()))
                .borders(Borders::ALL)
                .border_style(theme::border())
                .border_type(theme::border_type()),
        );
        f.render_widget(paragraph, area);
        return;
    }

    let block = Block::default()
        .title(Span::styled(" Job Detail ", theme::title()))
        .borders(Borders::ALL)
        .border_style(theme::border())
        .border_type(theme::border_type());

    let Some(job) = selected else {
        let paragraph = Paragraph::new(Span::styled(
            "No job selected. Press 2 to browse jobs.",
            theme::placeholder(),
        ))
        .block(block);
        f.render_widget(paragraph, area);
        return;
    };

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(12), // Job info
            Constraint::Length(4),  // Cycles
            Constraint::Length(8),  // Economics
            Constraint::Length(5),  // Risk
            Constraint::Min(3),     // Progress
        ])
        .margin(1)
        .split(area);

    // Render outer border
    f.render_widget(block, area);

    let claimed = state
        .active_jobs
        .iter()
        .any(|j| j.info.job_id == job.info.job_id);

    // Job info
    let info_text = vec![
        Line::from(vec![
            Span::styled("Job ID:        ", theme::dim()),
            Span::styled(format!("{}", job.info.job_id), theme::identifier()),
        ]),
        Line::from(vec![
            Span::styled("Caller:        ", theme::dim()),
            Span::styled(format!("{}", job.info.caller), theme::identifier()),
        ]),
        Line::from(vec![
            Span::styled("Status:        ", theme::dim()),
            Span::raw(if claimed {
                super::jobs::claimed_status_text(job, state, now_unix())
            } else {
                super::jobs::job_status_text(job, state)
            }),
        ]),
        Line::from(vec![
            Span::styled("Descriptor:    ", theme::dim()),
            Span::raw(format!("{}", job.info.descriptor_hash)),
        ]),
        Line::from(vec![
            Span::styled("Current Price: ", theme::dim()),
            Span::styled(format_token_amount(job.current_price), theme::positive()),
        ]),
        Line::from(vec![
            Span::styled("Min Price:     ", theme::dim()),
            Span::raw(format_token_amount(job.info.min_price)),
        ]),
        Line::from(vec![
            Span::styled("Max Price:     ", theme::dim()),
            Span::raw(format_token_amount(job.info.max_price)),
        ]),
        Line::from(vec![
            Span::styled("Timeout:       ", theme::dim()),
            Span::raw(format_duration(job.info.fulfillment_timeout)),
        ]),
        Line::from(vec![
            Span::styled("Curve:         ", theme::dim()),
            Span::raw(if job.info.curve_type == 0 {
                "Linear"
            } else {
                "Quadratic"
            }),
        ]),
    ];

    let info = Paragraph::new(info_text).block(
        Block::default()
            .title(Span::styled(" Info ", theme::title()))
            .borders(Borders::ALL)
            .border_style(theme::border())
            .border_type(theme::border_type()),
    );
    f.render_widget(info, chunks[0]);

    // Cycles: what the miner measured, or why it has not.
    let cycles_text = vec![
        Line::from(vec![
            Span::styled("Measured:      ", theme::dim()),
            Span::raw(measured_text(job, state, claimed)),
        ]),
        Line::from(vec![
            Span::styled("Declared:      ", theme::dim()),
            Span::raw(declared_text(job.estimated_cycles)),
        ]),
    ];
    let cycles = Paragraph::new(cycles_text).block(
        Block::default()
            .title(Span::styled(" Cycles ", theme::title()))
            .borders(Borders::ALL)
            .border_style(theme::border())
            .border_type(theme::border_type()),
    );
    f.render_widget(cycles, chunks[1]);

    // Economics
    let econ_text = vec![
        Line::from(vec![
            Span::styled("Deposited:    ", theme::dim()),
            Span::raw(format_token_amount(job.info.deposited_amount)),
        ]),
        Line::from(vec![
            Span::styled("Bonus:        ", theme::dim()),
            Span::styled(format_token_amount(job.info.bonus_amount), theme::warning()),
        ]),
        Line::from(vec![
            Span::styled("Speed Premium:", theme::dim()),
            Span::raw(format_token_amount(job.info.speed_premium)),
        ]),
        Line::from(vec![
            Span::styled("Collateral:   ", theme::dim()),
            Span::raw(format!("{}bps", job.info.lock_collateral_bps)),
        ]),
    ];

    let econ = Paragraph::new(econ_text).block(
        Block::default()
            .title(Span::styled(" Economics ", theme::title()))
            .borders(Borders::ALL)
            .border_style(theme::border())
            .border_type(theme::border_type()),
    );
    f.render_widget(econ, chunks[2]);

    // Progress (if proving)
    if let MinerJobStatus::Proving { .. } = &job.status {
        let secs = format_duration(state.proving_secs(job));
        let stage = state.proving_stage_label(job).unwrap_or_default();
        let fraction = state.proving_fraction(job);
        let label = match fraction {
            Some(f) => format!("{:.1}% ({secs}, {stage})", f * 100.0),
            None => {
                format!("proving for {secs} ({stage}); no measurement or benchmark to estimate by")
            }
        };
        let progress = fraction.unwrap_or(0.0);
        let gauge = Gauge::default()
            .block(
                Block::default()
                    .title(Span::styled(" Proving Progress ", theme::title()))
                    .borders(Borders::ALL)
                    .border_style(theme::border())
                    .border_type(theme::border_type()),
            )
            .gauge_style(Style::default().fg(theme::green()))
            .percent((progress * 100.0).clamp(0.0, 100.0) as u16)
            .label(label);
        f.render_widget(gauge, chunks[4]);
    }
}

/// The Cycles box's "Measured" line: the count the miner sized the job on, or that it could not be
/// measured, or why it has not been yet (the same reason the Jobs page gives).
pub(crate) fn measured_text(job: &TrackedJob, state: &MinerState, claimed: bool) -> String {
    match state.job_measurements.get(&job.info.job_id) {
        Some(m) => match m.cycles {
            Some(cycles) => {
                let at = if m.po2s.is_empty() {
                    m.backend.clone()
                } else {
                    let sizes: Vec<String> = m.po2s.iter().map(|p| p.to_string()).collect();
                    format!("{} at po2 {}", m.backend, sizes.join(" and "))
                };
                format!(
                    "{} cycles ({at}; executing it took {})",
                    group_thousands(cycles),
                    format_duration(m.execute_secs.round() as u64)
                )
            }
            None => "could not be measured (over the execute cycle cap, out of time, or a \
                     different journal at each size): never claimed"
                .to_string(),
        },
        None if claimed => "not recorded in this run (claimed before it started)".to_string(),
        None => match state.job_why.get(&job.info.job_id) {
            Some(why) => format!("not yet: {why}"),
            None => "not yet: the miner has not looked at this job".to_string(),
        },
    }
}

/// The Cycles box's "Declared" line: what the submitter claimed, which sizes nothing on its own.
pub(crate) fn declared_text(declared: u64) -> String {
    if declared == 0 {
        "none by the submitter".to_string()
    } else {
        format!(
            "{} by the submitter (not used for sizing; the measurement is)",
            group_thousands(declared)
        )
    }
}

fn group_thousands(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(c);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{JobMeasurement, MinerJobStatus};
    use alloy_primitives::B256;

    fn job(id: u8) -> TrackedJob {
        TrackedJob {
            info: zkminer_chain::jobs::JobInfo {
                job_id: B256::repeat_byte(id),
                ..Default::default()
            },
            status: MinerJobStatus::Open,
            current_price: 0,
            gpu_bus_id: None,
            prover_backend: String::new(),
            estimated_cycles: 0,
        }
    }

    /// Measured, unmeasurable, waiting with its reason, and claimed without a record each read as
    /// what they are.
    #[test]
    fn the_measured_line_says_what_the_miner_knows() {
        let mut state = MinerState::default();
        let (r0, sp1, bad, waiting, fresh, ours) = (job(1), job(2), job(3), job(4), job(5), job(6));
        state.job_measurements.insert(
            r0.info.job_id,
            JobMeasurement {
                cycles: Some(821_035_008),
                backend: "risc0".into(),
                po2s: vec![19, 20],
                execute_secs: 5.2,
            },
        );
        state.job_measurements.insert(
            sp1.info.job_id,
            JobMeasurement {
                cycles: Some(384_551_125),
                backend: "sp1".into(),
                po2s: Vec::new(),
                execute_secs: 7.0,
            },
        );
        state.job_measurements.insert(
            bad.info.job_id,
            JobMeasurement {
                cycles: None,
                backend: "sp1".into(),
                po2s: Vec::new(),
                execute_secs: 120.0,
            },
        );
        state
            .job_why
            .insert(waiting.info.job_id, "waiting to be measured".into());
        assert_eq!(
            measured_text(&r0, &state, false),
            "821,035,008 cycles (risc0 at po2 19 and 20; executing it took 5s)"
        );
        assert_eq!(
            measured_text(&sp1, &state, false),
            "384,551,125 cycles (sp1; executing it took 7s)"
        );
        assert!(measured_text(&bad, &state, false).starts_with("could not be measured"));
        assert_eq!(
            measured_text(&waiting, &state, false),
            "not yet: waiting to be measured"
        );
        assert_eq!(
            measured_text(&fresh, &state, false),
            "not yet: the miner has not looked at this job"
        );
        assert!(measured_text(&ours, &state, true).starts_with("not recorded in this run"));
    }

    #[test]
    fn declared_counts_are_grouped_and_marked_unused() {
        assert_eq!(declared_text(0), "none by the submitter");
        assert_eq!(
            declared_text(1_234_567),
            "1,234,567 by the submitter (not used for sizing; the measurement is)"
        );
        assert_eq!(group_thousands(999), "999");
        assert_eq!(group_thousands(1_000), "1,000");
    }
}
