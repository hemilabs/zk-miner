use ratatui::{
    layout::Constraint,
    widgets::{Block, Borders, Cell, Row, Table},
    Frame,
};

use super::dashboard::format_token_amount;
use crate::state::{MinerJobStatus, MinerState};
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
        "Status",
    ]
    .iter()
    .map(|h| Cell::from(*h).style(theme::table_header()));
    let header = Row::new(header_cells).height(1);

    let rows: Vec<Row> = state
        .open_jobs
        .iter()
        .enumerate()
        .map(|(i, job)| {
            let id_short = format!("{}...", &format!("{}", job.info.job_id)[..8]);
            let program_short = format!("{}...", &format!("{}", job.info.descriptor_hash)[..8]);

            let status = match &job.status {
                MinerJobStatus::Open => "Open",
                MinerJobStatus::Queued => "Queued",
                MinerJobStatus::Proving { .. } => "Proving",
                MinerJobStatus::Submitting => "Submitting",
                MinerJobStatus::Fulfilled { .. } => "Fulfilled",
                MinerJobStatus::Released { .. } => "Released",
                MinerJobStatus::Skipped { .. } => "Skipped",
            };

            let mut style = theme::striped(i);
            if i == state.selected_job_index {
                style = style.bg(theme::overlay());
            }

            Row::new(vec![
                Cell::from(id_short).style(theme::identifier()),
                Cell::from(program_short).style(theme::dim()),
                Cell::from(format_token_amount(job.current_price)),
                Cell::from(format_token_amount(job.info.max_price)),
                Cell::from(format!("{}s", job.info.fulfillment_timeout)),
                Cell::from(format_token_amount(job.info.bonus_amount)),
                Cell::from(status),
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
            Constraint::Length(12),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .title(Span::styled(
                format!(
                    " Open Jobs ({}) — [c]laim [f]ast-path [r]elease [Enter]detail ",
                    state.open_jobs.len()
                ),
                theme::title(),
            ))
            .borders(Borders::ALL)
            .border_style(theme::border())
            .border_type(theme::border_type()),
    );

    f.render_widget(table, area);
}
