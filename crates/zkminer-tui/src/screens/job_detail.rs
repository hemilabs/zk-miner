use ratatui::{
    layout::{Constraint, Direction, Layout},
    style::Style,
    text::{Line, Span},
    widgets::{Block, Borders, Gauge, Paragraph},
    Frame,
};

use super::dashboard::{format_duration, format_token_amount};
use crate::state::{MinerJobStatus, MinerState};
use crate::theme;

pub fn render(f: &mut Frame, area: ratatui::layout::Rect, state: &MinerState) {
    let selected = state
        .open_jobs
        .get(state.selected_job_index)
        .or_else(|| state.active_jobs.first());

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
            Constraint::Length(8),  // Economics
            Constraint::Length(5),  // Risk
            Constraint::Min(3),     // Progress
        ])
        .margin(1)
        .split(area);

    // Render outer border
    f.render_widget(block, area);

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
            Span::raw(
                format!("{:?}", job.status)
                    .chars()
                    .take(30)
                    .collect::<String>(),
            ),
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
    f.render_widget(econ, chunks[1]);

    // Progress (if proving)
    if let MinerJobStatus::Proving {
        progress,
        elapsed_secs,
    } = &job.status
    {
        let gauge = Gauge::default()
            .block(
                Block::default()
                    .title(Span::styled(" Proving Progress ", theme::title()))
                    .borders(Borders::ALL)
                    .border_style(theme::border())
                    .border_type(theme::border_type()),
            )
            .gauge_style(Style::default().fg(theme::green()))
            .percent((*progress * 100.0).clamp(0.0, 100.0) as u16)
            .label(format!(
                "{:.1}% ({})",
                progress * 100.0,
                format_duration(*elapsed_secs)
            ));
        f.render_widget(gauge, chunks[3]);
    }
}
