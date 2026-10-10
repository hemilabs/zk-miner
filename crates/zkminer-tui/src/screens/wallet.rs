use ratatui::{
    layout::{Constraint, Direction, Layout},
    style::Style,
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
    Frame,
};

use super::dashboard::{
    compute_daily_earning_rate, compute_success_rate, format_duration, format_token_amount,
};
use crate::state::MinerState;
use crate::theme;

pub fn render(f: &mut Frame, area: ratatui::layout::Rect, state: &MinerState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(8), // Balances
            Constraint::Min(12),   // $HEMI Staking (merged)
        ])
        .split(area);

    // Balances
    let balance_text = vec![
        Line::from(vec![
            Span::styled("Address:      ", theme::dim()),
            Span::styled(&state.address, theme::identifier()),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("ETH Balance:  ", theme::dim()),
            Span::styled(format_token_amount(state.eth_balance), theme::positive()),
        ]),
        Line::from(vec![
            Span::styled("HEMI Balance: ", theme::dim()),
            Span::styled(format_token_amount(state.hemi_balance), theme::positive()),
        ]),
    ];

    let balances = Paragraph::new(balance_text).block(
        Block::default()
            .title(Span::styled(" Wallet ", theme::title()))
            .borders(Borders::ALL)
            .border_style(theme::border())
            .border_type(theme::border_type()),
    );
    f.render_widget(balances, chunks[0]);

    // $HEMI Staking (merged staking + prover stats)
    let staking_text = if let Some(stake) = &state.stake_info {
        let now = chrono::Utc::now().timestamp() as u64;

        // Deposit block (contract stores block.number, not a timestamp).
        let age_str = if stake.deposit_block > 0 {
            format!("block {}", stake.deposit_block)
        } else {
            "N/A".to_string()
        };

        // Collateral utilization
        let stake_pct = if stake.total_staked > 0 {
            (stake.locked_collateral as f64 / stake.total_staked as f64 * 100.0) as u32
        } else {
            0
        };
        let bar_ratio = stake_pct as f64 / 100.0;
        let (bar_filled, bar_empty) = theme::progress_bar(bar_ratio, 24);
        let bar_color = theme::usage_color(stake_pct);

        // Unstake info
        let unstake_str = if stake.unstake_amount > 0 {
            let cooldown_left = if stake.unstake_request_time > 0 {
                let elapsed = now.saturating_sub(stake.unstake_request_time);
                let cooldown = 7 * 86400_u64; // 7 day cooldown
                if elapsed < cooldown {
                    format!(" ({})", format_duration(cooldown - elapsed))
                } else {
                    " (ready)".to_string()
                }
            } else {
                String::new()
            };
            format!(
                "{} $HEMI{}",
                format_token_amount(stake.unstake_amount),
                cooldown_left
            )
        } else {
            "None".to_string()
        };

        // Performance stats
        let (success_lines, earned_line, rate_line) = if let Some(stats) = &state.prover_stats {
            let (rate, _total) = compute_success_rate(stats);
            let rate_pct = rate * 100.0;
            let rate_style = if rate >= 0.95 {
                theme::positive()
            } else if rate >= 0.80 {
                theme::warning()
            } else {
                theme::error()
            };

            let daily_wei = compute_daily_earning_rate(stats);

            let since_str = if stats.first_fulfillment_at > 0 {
                let dt = chrono::DateTime::from_timestamp(stats.first_fulfillment_at as i64, 0)
                    .map(|d| d.format("%Y-%m-%d").to_string())
                    .unwrap_or_else(|| "N/A".to_string());
                format!("Since: {}", dt)
            } else {
                String::new()
            };

            (
                Line::from(vec![
                    Span::styled("Success Rate:     ", theme::dim()),
                    Span::styled(format!("{:.1}%", rate_pct), rate_style),
                    Span::styled(format!("  F:{}", stats.jobs_fulfilled), theme::positive()),
                    Span::styled(format!("  S:{}", stats.jobs_slashed), theme::error()),
                    Span::styled(format!("  R:{}", stats.jobs_released), theme::warning()),
                ]),
                Line::from(vec![
                    Span::styled("Total Earned:     ", theme::dim()),
                    Span::styled(
                        format!("{} $HEMI", format_token_amount(stats.total_earned)),
                        theme::metric(),
                    ),
                ]),
                Line::from(vec![
                    Span::styled("Earning Rate:     ", theme::dim()),
                    Span::styled(
                        format!("~{} $HEMI/day", format_token_amount(daily_wei)),
                        theme::identifier(),
                    ),
                    Span::styled(format!("         {}", since_str), theme::dim()),
                ]),
            )
        } else {
            (
                Line::from(Span::styled("Loading performance...", theme::placeholder())),
                Line::from(""),
                Line::from(""),
            )
        };

        vec![
            Line::from(vec![
                Span::styled("Staked:           ", theme::dim()),
                Span::styled(
                    format!("{} $HEMI", format_token_amount(stake.total_staked)),
                    theme::metric(),
                ),
                Span::styled(format!("     Deposit: {}", age_str), theme::dim()),
            ]),
            Line::from(vec![
                Span::styled("Collateral:       ", theme::dim()),
                Span::styled(bar_filled, Style::default().fg(bar_color)),
                Span::styled(bar_empty, theme::dim()),
                Span::styled(
                    format!(" {}% utilized", stake_pct),
                    Style::default().fg(bar_color),
                ),
            ]),
            Line::from(vec![
                Span::styled("  Locked:         ", theme::dim()),
                Span::styled(
                    format!("{} $HEMI", format_token_amount(stake.locked_collateral)),
                    theme::accent(),
                ),
                Span::styled(
                    format!("  (backing {} active jobs)", state.active_jobs.len()),
                    theme::dim(),
                ),
            ]),
            Line::from(vec![
                Span::styled("  Liquid:         ", theme::dim()),
                Span::styled(
                    format!("{} $HEMI", format_token_amount(stake.available_collateral)),
                    theme::positive(),
                ),
            ]),
            Line::from(vec![
                Span::styled("Unstake Pending:  ", theme::dim()),
                Span::raw(unstake_str),
            ]),
            Line::from(vec![
                Span::styled("─── ", theme::separator()),
                Span::styled("Performance", theme::dim()),
                Span::styled(" ───", theme::separator()),
            ]),
            success_lines,
            earned_line,
            rate_line,
        ]
    } else {
        vec![Line::from(Span::styled(
            "Loading staking info...",
            theme::placeholder(),
        ))]
    };

    let staking = Paragraph::new(staking_text).block(
        Block::default()
            .title(Span::styled(" $HEMI Staking ", theme::title()))
            .borders(Borders::ALL)
            .border_style(theme::border())
            .border_type(theme::border_type()),
    );
    f.render_widget(staking, chunks[1]);
}
