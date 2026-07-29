use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::Style,
    text::{Line, Span},
    widgets::{Block, Borders, Cell, List, ListItem, Paragraph, Row, Table},
    Frame,
};

use zkminer_chain::staking::ProverStatistics;
use zkminer_prover::engine::{backend_sources, BackendSource};

use crate::hardware::{fmt_bytes, GpuInfo, GpuVendor};
use crate::state::{LogLevel, MinerJobStatus, MinerState};
use crate::theme;

pub fn render(f: &mut Frame, area: Rect, state: &MinerState) {
    let gpu_count = state.hardware.gpus.len();
    let gpu_ideal = if gpu_count > 0 { gpu_count as u16 + 3 } else { 3 };

    // Show a readiness banner if setup is incomplete (but only after checks are done
    // and the user has dismissed the setup wizard or it wasn't shown).
    let show_banner = state.setup_status.checked && !state.setup_status.is_ready();
    let banner_height = if show_banner { 1 } else { 0 };

    // GPUs get priority: use Min so they're never clipped before other panels.
    // Lower panels shrink first when the terminal is short.
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(banner_height), // Readiness banner (0 if ready)
            Constraint::Length(3),           // CPU + ZK Engines (compact, never shrink)
            Constraint::Min(gpu_ideal),      // GPUs (protected — shrinks last)
            Constraint::Max(8),              // Wallet & Staking + Performance (shrinks first)
            Constraint::Length(0),           // Active jobs (hidden when tight)
            Constraint::Max(6),              // Recent activity (shrinks early)
        ])
        .split(area);

    // --- Readiness banner ---
    if show_banner {
        render_readiness_banner(f, chunks[0], state);
    }

    let top_cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Min(40), Constraint::Length(32)])
        .split(chunks[1]);
    render_hardware(f, top_cols[0], state);
    render_zk_engines(f, top_cols[1], state);
    render_gpu(f, chunks[2], state);

    let staking_cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(chunks[3]);
    render_wallet_staking(f, staking_cols[0], state);
    render_performance(f, staking_cols[1], state);

    render_active_jobs(f, chunks[4], state);
    render_activity(f, chunks[5], state);
}

// ---------------------------------------------------------------------------
// Readiness banner
// ---------------------------------------------------------------------------

fn render_readiness_banner(f: &mut Frame, area: Rect, state: &MinerState) {
    let reason = state
        .setup_status
        .blocking_reason()
        .unwrap_or_else(|| "Not ready".to_string());

    let line = Line::from(vec![
        Span::styled(
            " NOT READY ",
            Style::default()
                .fg(theme::base())
                .bg(theme::yellow())
                .add_modifier(ratatui::style::Modifier::BOLD),
        ),
        Span::styled(format!(" {reason} ", ), theme::warning()),
        Span::styled("  Press ", theme::dim()),
        Span::styled("4", theme::accent()),
        Span::styled(":wallet for actions", theme::dim()),
    ]);

    let paragraph = Paragraph::new(line).style(Style::default().bg(theme::base()));
    f.render_widget(paragraph, area);
}

// ---------------------------------------------------------------------------
// Hardware panel
// ---------------------------------------------------------------------------

fn render_hardware(f: &mut Frame, area: Rect, state: &MinerState) {
    let hw = &state.hardware;
    let cpu = &hw.cpu;
    let mem = &hw.memory;

    let mut lines: Vec<Line> = Vec::new();

    let cpu_usage_color = theme::usage_color(cpu.usage_percent as u32);
    let zkops_spans: Vec<Span> = if let Some(ref bench) = state.benchmark_results {
        vec![
            Span::styled(" | ", theme::separator()),
            Span::styled(
                format!("{} zkOP/s", format_compact(bench.zkops)),
                theme::metric(),
            ),
        ]
    } else {
        vec![
            Span::styled(" | ", theme::separator()),
            Span::styled("-- zkOP/s", theme::dim()),
        ]
    };

    let mem_pct = if mem.total_bytes > 0 {
        (mem.used_bytes as f64 / mem.total_bytes as f64 * 100.0) as u32
    } else {
        0
    };

    let is_amd = cpu.model.starts_with("R5 ") || cpu.model.starts_with("R7 ")
        || cpu.model.starts_with("R9 ") || cpu.model.starts_with("TR ")
        || cpu.model.starts_with("EPYC ") || cpu.model.contains("AMD");
    let is_intel = cpu.model.starts_with("Xeon ") || cpu.model.starts_with("i3-")
        || cpu.model.starts_with("i5-") || cpu.model.starts_with("i7-")
        || cpu.model.starts_with("i9-") || cpu.model.contains("Intel");

    let mut cpu_spans: Vec<Span> = Vec::new();
    if is_amd {
        cpu_spans.push(Span::styled("  AMD ", Style::default().fg(theme::base()).bg(theme::amd_red()).add_modifier(ratatui::style::Modifier::BOLD)));
        cpu_spans.push(Span::raw(" "));
    } else if is_intel {
        cpu_spans.push(Span::styled(" INTC ", Style::default().fg(theme::base()).bg(theme::intel_blue()).add_modifier(ratatui::style::Modifier::BOLD)));
        cpu_spans.push(Span::raw(" "));
    }
    cpu_spans.extend(vec![
        Span::styled(&cpu.model, theme::bold()),
        if cpu.freq_mhz > 0 {
            Span::styled(format!(" {}MHz", cpu.freq_mhz), theme::dim())
        } else {
            Span::raw("")
        },
        Span::styled(" | ", theme::separator()),
        Span::styled(
            format!("{:4.1}%", cpu.usage_percent),
            Style::default().fg(cpu_usage_color),
        ),
        Span::styled(" | ", theme::separator()),
        Span::styled(
            format!("{}/{}", fmt_bytes(mem.used_bytes), fmt_bytes(mem.total_bytes)),
            Style::default().fg(theme::usage_color(mem_pct)),
        ),
    ]);
    cpu_spans.extend(zkops_spans);
    lines.push(Line::from(cpu_spans));

    let block = Block::default()
        .title(Span::styled(" CPU ", theme::title()))
        .borders(Borders::ALL)
        .border_style(theme::border())
        .border_type(theme::border_type());

    let paragraph = Paragraph::new(lines).block(block);
    f.render_widget(paragraph, area);
}

fn render_zk_engines(f: &mut Frame, area: Rect, state: &MinerState) {
    let sources = backend_sources();
    let all_engines: &[(&str, &str, ratatui::style::Color)] = &[
        ("risc0", " RISC0 ", theme::risc0_purple()),
        ("sp1", "  SP1  ", theme::sp1_orange()),
        ("openvm", " OpenVM ", theme::openvm_cyan()),
    ];

    let mut spans: Vec<Span> = Vec::new();
    for (i, (key, label, color)) in all_engines.iter().enumerate() {
        if i > 0 {
            spans.push(Span::raw(" "));
        }
        let source = sources.iter().find(|(name, _)| name == key);
        let runtime_disabled = state.runtime_settings.disabled_backends.contains(*key);

        match source {
            None => {
                // Not available — greyed out + strikethrough
                spans.push(Span::styled(
                    *label,
                    Style::default()
                        .fg(theme::overlay())
                        .add_modifier(ratatui::style::Modifier::CROSSED_OUT),
                ));
            }
            Some((_, BackendSource::Simulated)) => {
                // Simulated only — dim badge with (sim) suffix
                spans.push(Span::styled(
                    *label,
                    Style::default().fg(theme::overlay()),
                ));
                spans.push(Span::styled(
                    "(sim)",
                    Style::default().fg(theme::overlay()),
                ));
            }
            Some((_, _source)) if runtime_disabled => {
                // Available but user-disabled — brand color text, strikethrough
                spans.push(Span::styled(
                    *label,
                    Style::default()
                        .fg(*color)
                        .add_modifier(ratatui::style::Modifier::CROSSED_OUT),
                ));
            }
            Some((_, _source)) => {
                // Check health from worker_status
                let worker_healthy = state
                    .worker_status
                    .iter()
                    .find(|w| w.backend == *key)
                    .map(|w| w.healthy)
                    .unwrap_or(true); // Assume healthy if no worker_status entry

                if worker_healthy {
                    // Active + healthy — solid brand-colored badge
                    spans.push(Span::styled(
                        *label,
                        Style::default()
                            .fg(theme::base())
                            .bg(*color)
                            .add_modifier(ratatui::style::Modifier::BOLD),
                    ));
                } else {
                    // Available but degraded — brand color badge + warning
                    spans.push(Span::styled(
                        *label,
                        Style::default()
                            .fg(*color)
                            .bg(theme::base()),
                    ));
                    spans.push(Span::styled(
                        "!",
                        Style::default().fg(theme::yellow()),
                    ));
                }
            }
        }
    }

    let block = Block::default()
        .title(Span::styled(" ZK Engines ", theme::title()))
        .borders(Borders::ALL)
        .border_style(theme::border())
        .border_type(theme::border_type());

    let paragraph = Paragraph::new(Line::from(spans)).block(block);
    f.render_widget(paragraph, area);
}

fn render_gpu(f: &mut Frame, area: Rect, state: &MinerState) {
    let hw = &state.hardware;
    let gpu_count = hw.gpus.len();

    // Inner height = area minus 2 border rows minus 1 header row
    let inner_data_rows = area.height.saturating_sub(3) as usize;
    let hidden = gpu_count.saturating_sub(inner_data_rows);

    let title = if hidden > 0 {
        format!(" GPUs ({}) +{} more \u{2193} ", gpu_count, hidden)
    } else if gpu_count > 1 {
        format!(" GPUs ({}) ", gpu_count)
    } else {
        " GPUs ".to_string()
    };

    let block = Block::default()
        .title(Span::styled(&title, theme::title()))
        .borders(Borders::ALL)
        .border_style(theme::border())
        .border_type(theme::border_type());

    if hw.gpus.is_empty() {
        let paragraph = Paragraph::new(Span::styled("No GPUs detected", theme::placeholder()))
            .block(block);
        f.render_widget(paragraph, area);
        return;
    }

    let header = Row::new(vec![
        Cell::from("Name").style(theme::table_header()),
        Cell::from("zkOP/s").style(theme::table_header()),
        Cell::from("Core").style(theme::table_header()),
        Cell::from("GClk").style(theme::table_header()),
        Cell::from("MClk").style(theme::table_header()),
        Cell::from("VRAM").style(theme::table_header()),
        Cell::from("Temp").style(theme::table_header()),
        Cell::from("Power").style(theme::table_header()),
        Cell::from("Job").style(theme::table_header()),
        Cell::from("Progress").style(theme::table_header()),
    ]);

    let rows: Vec<Row> = hw
        .gpus
        .iter()
        .enumerate()
        .map(|(i, gpu)| gpu_row(gpu, state).style(theme::striped(i)))
        .collect();

    let widths = [
        Constraint::Min(16),
        Constraint::Length(9),
        Constraint::Length(5),
        Constraint::Length(8),
        Constraint::Length(8),
        Constraint::Length(12),
        Constraint::Length(6),
        Constraint::Length(10),
        Constraint::Length(12),
        Constraint::Min(18),
    ];

    let table = Table::new(rows, widths).header(header).block(block);

    f.render_widget(table, area);
}

fn gpu_row<'a>(gpu: &'a GpuInfo, state: &'a MinerState) -> Row<'a> {
    let gpu_color = theme::usage_color(gpu.gpu_usage_percent);
    let temp = gpu.temp_junction_c.or(gpu.temp_edge_c).unwrap_or(0.0);
    let temp_color = if temp >= 90.0 {
        theme::red()
    } else if temp >= 75.0 {
        theme::yellow()
    } else {
        theme::green()
    };

    let temp_str = match gpu.temp_junction_c.or(gpu.temp_edge_c) {
        Some(t) => format!("{:.0}°C", t),
        None => "N/A".to_string(),
    };

    let pwr_pct = if gpu.power_cap_watts > 0.0 {
        (gpu.power_watts / gpu.power_cap_watts * 100.0) as u32
    } else {
        0
    };
    let pwr_color = theme::usage_color(pwr_pct);

    let (vendor_tag, vendor_bg) = match gpu.vendor {
        GpuVendor::Amd => ("  AMD ", theme::amd_red()),
        GpuVendor::Nvidia => (" NVDA ", theme::nvidia_green()),
        GpuVendor::Intel => (" INTC ", theme::intel_blue()),
        GpuVendor::Unknown => (" GPU ", theme::overlay()),
    };

    // Per-GPU zkOP/s: scale from best GPU throughput relative to best CPU throughput
    let zkops_str = if let Some(suite) = &state.benchmark_results {
        let device_id = format!("gpu{}", gpu.index);
        let best_gpu_tp = suite
            .device_benchmarks
            .iter()
            .filter(|d| d.device_id == device_id)
            .map(|d| d.throughput)
            .fold(0.0_f64, f64::max);
        let best_cpu_tp = suite
            .device_benchmarks
            .iter()
            .filter(|d| d.device_id == "cpu")
            .map(|d| d.throughput)
            .fold(0.0_f64, f64::max);
        if best_gpu_tp > 0.0 && best_cpu_tp > 0.0 && suite.zkops > 0.0 {
            let gpu_zkops = best_gpu_tp / best_cpu_tp * suite.zkops;
            format_compact(gpu_zkops)
        } else {
            "--".to_string()
        }
    } else {
        "--".to_string()
    };

    // Find active job assigned to this GPU
    let gpu_job = state
        .active_jobs
        .iter()
        .find(|j| j.gpu_index == Some(gpu.index));

    let (job_str, progress_str, progress_style) = if let Some(job) = gpu_job {
        let id = format!("{}", job.info.job_id);
        let id_short = if id.len() > 10 {
            format!("{}…", &id[..10])
        } else {
            id
        };
        match &job.status {
            MinerJobStatus::Proving { progress, .. } => {
                let (filled, empty) = theme::progress_bar(*progress, 12);
                (
                    id_short,
                    format!("{}{} {:.0}%", filled, empty, progress * 100.0),
                    Style::default().fg(theme::green()),
                )
            }
            MinerJobStatus::Submitting => (
                id_short,
                "Submitting…".to_string(),
                theme::warning(),
            ),
            MinerJobStatus::Fulfilled { .. } => (
                id_short,
                "Done".to_string(),
                theme::positive(),
            ),
            _ => (
                id_short,
                "Pending".to_string(),
                theme::dim(),
            ),
        }
    } else {
        (
            "—".to_string(),
            "Idle".to_string(),
            theme::dim(),
        )
    };

    Row::new(vec![
        Cell::from(Line::from(vec![
            Span::styled(vendor_tag, Style::default().fg(theme::base()).bg(vendor_bg).add_modifier(ratatui::style::Modifier::BOLD)),
            Span::styled(format!(" {}", gpu.name), theme::bold()),
        ])),
        Cell::from(zkops_str).style(theme::metric()),
        Cell::from(format!("{:3}%", gpu.gpu_usage_percent)).style(Style::default().fg(gpu_color)),
        Cell::from(format!("{}MHz", gpu.gpu_clock_mhz)),
        Cell::from(format!("{}MHz", gpu.mem_clock_mhz)),
        Cell::from(format!("{}/{}", fmt_bytes(gpu.vram_used_bytes), fmt_bytes(gpu.vram_total_bytes))),
        Cell::from(temp_str).style(Style::default().fg(temp_color)),
        Cell::from(format!("{:.0}/{:.0}W", gpu.power_watts, gpu.power_cap_watts)).style(Style::default().fg(pwr_color)),
        Cell::from(job_str).style(theme::identifier()),
        Cell::from(progress_str).style(progress_style),
    ])
}

// ---------------------------------------------------------------------------
// Wallet & Staking panel (left)
// ---------------------------------------------------------------------------

fn render_wallet_staking(f: &mut Frame, area: Rect, state: &MinerState) {
    let addr_display = if state.address.len() > 10 {
        format!(
            "{}...{}",
            &state.address[..6],
            &state.address[state.address.len() - 4..]
        )
    } else if state.address.is_empty() {
        "N/A".to_string()
    } else {
        state.address.clone()
    };

    let (status_tag, status_bg) = if state.paused {
        (" PAUSED ", theme::yellow())
    } else if state.connected {
        ("  UP  ", theme::green())
    } else {
        (" DOWN ", theme::red())
    };

    let mut lines: Vec<Line> = vec![
        // Line 1: address + status badge + block
        Line::from(vec![
            Span::styled(&addr_display, theme::identifier()),
            Span::raw(" "),
            Span::styled(
                status_tag,
                Style::default()
                    .fg(theme::base())
                    .bg(status_bg)
                    .add_modifier(ratatui::style::Modifier::BOLD),
            ),
            Span::styled("  Block ", theme::dim()),
            Span::styled(format!("{}", state.block_number), Style::default().fg(theme::text())),
            Span::styled("  RPC ", theme::dim()),
            Span::styled(
                format!("{} ({}/min)", state.rpc_total, state.rpc_last_minute),
                Style::default().fg(theme::text()),
            ),
        ]),
        // Line 2: balances
        Line::from(vec![
            Span::styled("ETH ", theme::dim()),
            Span::styled(format_token_amount(state.eth_balance), Style::default().fg(theme::text())),
            Span::styled("     HEMI ", theme::dim()),
            Span::styled(format_token_amount(state.hemi_balance), Style::default().fg(theme::text())),
        ]),
    ];

    if let Some(stake) = &state.stake_info {
        let stake_pct = if stake.total_staked > 0 {
            (stake.locked_collateral as f64 / stake.total_staked as f64 * 100.0) as u32
        } else {
            0
        };
        let bar_ratio = stake_pct as f64 / 100.0;
        let (bar_filled, bar_empty) = theme::progress_bar(bar_ratio, 20);
        let bar_color = theme::usage_color(stake_pct);

        let mut staking_spans = vec![
            Span::styled("Staked ", theme::dim()),
            Span::styled(format_token_amount(stake.total_staked), Style::default().fg(theme::text())),
            Span::styled("  Locked ", theme::dim()),
            Span::styled(format_token_amount(stake.locked_collateral), Style::default().fg(theme::text())),
            Span::styled("  Liquid ", theme::dim()),
            Span::styled(format_token_amount(stake.available_collateral), theme::positive()),
        ];

        if stake.unstake_amount > 0 {
            staking_spans.push(Span::styled(
                format!("  Unstaking {}", format_token_amount(stake.unstake_amount)),
                theme::warning(),
            ));
        }

        // Line 3: staked / locked / liquid
        lines.push(Line::from(staking_spans));

        // Line 4: utilization bar
        lines.push(Line::from(vec![
            Span::styled(bar_filled, Style::default().fg(bar_color)),
            Span::styled(bar_empty, theme::dim()),
            Span::styled(
                format!(" {}% utilized", stake_pct),
                Style::default().fg(bar_color),
            ),
        ]));
    } else {
        lines.push(Line::from(Span::styled(
            "Loading staking info...",
            theme::placeholder(),
        )));
    }

    let block = Block::default()
        .title(Span::styled(" Wallet & Staking ", theme::title()))
        .borders(Borders::ALL)
        .border_style(theme::border())
        .border_type(theme::border_type());

    f.render_widget(Paragraph::new(lines).block(block), area);
}

// ---------------------------------------------------------------------------
// Performance panel (right)
// ---------------------------------------------------------------------------

fn render_performance(f: &mut Frame, area: Rect, state: &MinerState) {
    let mut lines: Vec<Line> = Vec::new();

    if let Some(stats) = &state.prover_stats {
        let (rate, total) = compute_success_rate(stats);
        let rate_pct = rate * 100.0;
        let rate_style = if rate >= 0.95 {
            theme::positive()
        } else if rate >= 0.80 {
            theme::warning()
        } else {
            theme::error()
        };
        let daily_wei = compute_daily_earning_rate(stats);

        // Line 1: success rate
        lines.push(Line::from(vec![
            Span::styled("Success  ", theme::dim()),
            Span::styled(format!("{:.1}%", rate_pct), rate_style),
            Span::styled(format!("  ({}/{})", stats.jobs_fulfilled, total), theme::dim()),
        ]));

        // Line 2: total earned
        lines.push(Line::from(vec![
            Span::styled("Earned   ", theme::dim()),
            Span::styled(
                format!("{} $HEMI", format_token_amount(stats.total_earned)),
                theme::metric(),
            ),
        ]));

        // Line 3: daily rate
        lines.push(Line::from(vec![
            Span::styled("Rate     ", theme::dim()),
            Span::styled(
                format!("~{} $HEMI/day", format_token_amount(daily_wei)),
                Style::default().fg(theme::text()),
            ),
        ]));

        // Line 4: fulfilled / slashed / released (spelled out)
        let slashed_style = if stats.jobs_slashed > 0 {
            theme::error()
        } else {
            theme::dim()
        };

        lines.push(Line::from(vec![
            Span::styled("Fulfilled ", theme::dim()),
            Span::styled(format!("{}", stats.jobs_fulfilled), theme::positive()),
            Span::styled("  Slashed ", theme::dim()),
            Span::styled(format!("{}", stats.jobs_slashed), slashed_style),
            Span::styled("  Released ", theme::dim()),
            Span::styled(format!("{}", stats.jobs_released), Style::default().fg(theme::text())),
        ]));
    } else {
        lines.push(Line::from(Span::styled(
            "Loading stats...",
            theme::placeholder(),
        )));
    }

    let block = Block::default()
        .title(Span::styled(" Performance ", theme::title()))
        .borders(Borders::ALL)
        .border_style(theme::border())
        .border_type(theme::border_type());

    f.render_widget(Paragraph::new(lines).block(block), area);
}

// ---------------------------------------------------------------------------
// Active jobs
// ---------------------------------------------------------------------------

fn render_active_jobs(f: &mut Frame, area: Rect, state: &MinerState) {
    let block = Block::default()
        .title(Span::styled(
            format!(" Active Jobs ({}) ", state.active_jobs.len()),
            theme::title(),
        ))
        .borders(Borders::ALL)
        .border_style(theme::border())
        .border_type(theme::border_type());

    if state.active_jobs.is_empty() {
        let paragraph = Paragraph::new(Span::styled("No active jobs", theme::placeholder()))
            .block(block);
        f.render_widget(paragraph, area);
        return;
    }

    let header = Row::new(vec![
        Cell::from("Job ID").style(theme::table_header()),
        Cell::from("GPU").style(theme::table_header()),
        Cell::from("Prover").style(theme::table_header()),
        Cell::from("Cycles").style(theme::table_header()),
        Cell::from("Price").style(theme::table_header()),
        Cell::from("Progress").style(theme::table_header()),
    ]);

    let rows: Vec<Row> = state
        .active_jobs
        .iter()
        .enumerate()
        .map(|(i, job)| {
            let id_short = format!("{}...", &format!("{}", job.info.job_id)[..10]);

            let gpu_str = match job.gpu_index {
                Some(idx) => format!("GPU{}", idx),
                None => "CPU".to_string(),
            };

            let cycles_str = format_compact(job.estimated_cycles as f64);

            let status_str = match &job.status {
                MinerJobStatus::Proving { progress, .. } => {
                    let (filled, empty) = theme::progress_bar(*progress, 15);
                    format!("{}{} {:.0}%", filled, empty, progress * 100.0)
                }
                MinerJobStatus::Submitting => "Submitting...".to_string(),
                MinerJobStatus::Fulfilled { payout } => {
                    format!("Fulfilled ({})", format_token_amount(*payout))
                }
                _ => "Unknown".to_string(),
            };

            let price_str = format!("{} HEMI", format_token_amount(job.current_price));

            Row::new(vec![
                Cell::from(id_short).style(theme::identifier()),
                Cell::from(gpu_str),
                Cell::from(job.prover_backend.as_str()).style(theme::accent()),
                Cell::from(cycles_str),
                Cell::from(price_str),
                Cell::from(status_str),
            ])
            .style(theme::striped(i))
        })
        .collect();

    let widths = [
        Constraint::Length(14),
        Constraint::Length(5),
        Constraint::Length(10),
        Constraint::Length(8),
        Constraint::Length(14),
        Constraint::Min(20),
    ];

    let table = Table::new(rows, widths).header(header).block(block);

    f.render_widget(table, area);
}

// ---------------------------------------------------------------------------
// Recent activity
// ---------------------------------------------------------------------------

fn render_activity(f: &mut Frame, area: Rect, state: &MinerState) {
    let items: Vec<ListItem> = state
        .activity_log
        .iter()
        .rev()
        .take(10)
        .map(|entry| {
            let color = match entry.level {
                LogLevel::Info => theme::text(),
                LogLevel::Warn => theme::yellow(),
                LogLevel::Error => theme::red(),
                LogLevel::Success => theme::green(),
            };

            let time = entry.timestamp.format("%H:%M:%S").to_string();
            ListItem::new(Line::from(vec![
                Span::styled(format!("[{}] ", time), theme::dim()),
                Span::styled(&entry.message, Style::default().fg(color)),
            ]))
        })
        .collect();

    let block = Block::default()
        .title(Span::styled(" Recent Activity ", theme::title()))
        .borders(Borders::ALL)
        .border_style(theme::border())
        .border_type(theme::border_type());

    let list = List::new(items).block(block);
    f.render_widget(list, area);
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Format a token amount from raw wei (u128) to human-readable string.
pub fn format_token_amount(amount: u128) -> String {
    let whole = amount / 1_000_000_000_000_000_000;
    let frac = (amount % 1_000_000_000_000_000_000) / 1_000_000_000_000_000; // 3 decimal places
    if frac > 0 {
        format!("{}.{:03}", whole, frac)
    } else {
        format!("{}.0", whole)
    }
}

/// Format a large number with K/M suffix (e.g. 98432 → "98.4K", 1200000 → "1.20M").
fn format_compact(n: f64) -> String {
    if n >= 1_000_000.0 {
        format!("{:.2}M", n / 1_000_000.0)
    } else if n >= 1_000.0 {
        format!("{:.1}K", n / 1_000.0)
    } else {
        format!("{:.0}", n)
    }
}

/// Compute success rate from prover statistics.
/// Returns (rate 0.0–1.0, total_jobs). Returns (1.0, 0) if no jobs yet.
pub fn compute_success_rate(stats: &ProverStatistics) -> (f64, u64) {
    let total = stats.jobs_fulfilled + stats.jobs_slashed + stats.jobs_released;
    if total == 0 {
        return (1.0, 0);
    }
    (stats.jobs_fulfilled as f64 / total as f64, total)
}

/// Compute daily earning rate in wei.
/// Uses first_fulfillment_at → now elapsed time.
pub fn compute_daily_earning_rate(stats: &ProverStatistics) -> u128 {
    if stats.first_fulfillment_at == 0 || stats.total_earned == 0 {
        return 0;
    }
    let now = chrono::Utc::now().timestamp() as u64;
    let elapsed_secs = now.saturating_sub(stats.first_fulfillment_at);
    if elapsed_secs < 86400 {
        // Less than a day — extrapolate from what we have
        if elapsed_secs == 0 {
            return stats.total_earned;
        }
        return stats.total_earned * 86400 / elapsed_secs as u128;
    }
    let days = elapsed_secs as u128 / 86400;
    if days == 0 {
        return stats.total_earned;
    }
    stats.total_earned / days
}

/// Format seconds into a human-readable duration.
pub fn format_duration(secs: u64) -> String {
    if secs < 60 {
        format!("{}s", secs)
    } else if secs < 3600 {
        format!("{}m {}s", secs / 60, secs % 60)
    } else if secs < 86400 {
        format!("{}h {}m", secs / 3600, (secs % 3600) / 60)
    } else {
        format!("{}d {}h", secs / 86400, (secs % 86400) / 3600)
    }
}
