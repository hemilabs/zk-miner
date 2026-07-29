use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table},
    Frame,
};

use crate::hardware::GpuVendor;
use crate::state::{BenchmarkTracker, MinerState, ProgramPhase};
use crate::theme;
use zkminer_prover::benchmark::BENCHMARK_PROGRAMS;

/// Build the ordered list of unique device IDs from benchmark data + hardware.
/// CPU is always first, then gpu0, gpu1, etc.
fn device_ids(state: &MinerState) -> Vec<String> {
    let mut ids = vec!["cpu".to_string()];
    for gpu in &state.hardware.gpus {
        ids.push(format!("gpu{}", gpu.index));
    }
    ids
}

/// Number of selectable devices.
pub fn device_count(state: &MinerState) -> usize {
    device_ids(state).len()
}

/// Navigate up in the device list.
pub fn benchmark_navigate_up(state: &mut MinerState) {
    state.benchmark_selected_device = state.benchmark_selected_device.saturating_sub(1);
}

/// Navigate down in the device list.
pub fn benchmark_navigate_down(state: &mut MinerState) {
    let max = device_count(state).saturating_sub(1);
    state.benchmark_selected_device = (state.benchmark_selected_device + 1).min(max);
}

/// Get the device_id of the currently selected device.
pub fn selected_device_id(state: &MinerState) -> Option<String> {
    let ids = device_ids(state);
    ids.get(state.benchmark_selected_device).cloned()
}

pub fn render(f: &mut Frame, area: Rect, state: &MinerState) {
    // If benchmark tracker is active and not complete, show progress view
    if let Some(tracker) = &state.benchmark_tracker {
        if !tracker.all_complete {
            render_progress_view(f, area, state, tracker);
            return;
        }
    }

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(8),  // CPU info + zkOP/s + power
            Constraint::Min(6),    // Results table
            Constraint::Min(5),    // Device benchmarks (selectable)
            Constraint::Length(3), // Controls
        ])
        .split(area);

    // CPU info + zkOP/s
    let cpu_info = if let Some(bench) = &state.benchmark_results {
        let (zkops_color, zkops_label) = if bench.zkops >= 100_000.0 {
            (theme::green(), "Excellent")
        } else if bench.zkops >= 50_000.0 {
            (theme::yellow(), "Good")
        } else if bench.zkops > 0.0 {
            (theme::red(), "Low")
        } else {
            (theme::subtext(), "N/A")
        };

        vec![
            Line::from(vec![
                Span::styled(
                    format!(" zkOP/s: {:.0} ", bench.zkops),
                    theme::metric(),
                ),
                Span::styled(
                    format!("  ({})", zkops_label),
                    Style::default().fg(zkops_color),
                ),
                if bench.precompile_score > 0.0 || bench.compute_score > 0.0 {
                    Span::styled(
                        format!("   Precompile: {:.1}x  Compute: {:.1}x",
                            bench.precompile_score, bench.compute_score),
                        theme::dim(),
                    )
                } else {
                    Span::raw("")
                },
            ]),
            Line::from(""),
            Line::from(vec![
                Span::styled("CPU: ", theme::dim()),
                Span::styled(&bench.cpu_info, theme::identifier()),
            ]),
            Line::from(vec![
                Span::styled("Last Run: ", theme::dim()),
                Span::raw(&bench.timestamp),
            ]),
            Line::from(vec![
                Span::styled("Avg Throughput: ", theme::dim()),
                Span::styled(
                    format!("{:.0} cycles/sec", bench.average_throughput()),
                    theme::dim(),
                ),
            ]),
            Line::from({
                let mut spans = vec![Span::styled("Power: ", theme::dim())];
                match bench.cpu_power_watts {
                    Some(w) => spans.push(Span::styled(
                        format!("CPU {w:.0}W"),
                        theme::warning(),
                    )),
                    None => spans.push(Span::styled("CPU N/A", theme::dim())),
                }
                spans.push(Span::styled("  ", theme::dim()));
                match bench.gpu_power_watts {
                    Some(w) => spans.push(Span::styled(
                        format!("GPU {w:.0}W"),
                        theme::warning(),
                    )),
                    None => spans.push(Span::styled("GPU N/A", theme::dim())),
                }
                if let (Some(cpu_w), Some(gpu_w)) = (bench.cpu_power_watts, bench.gpu_power_watts) {
                    let total_w = cpu_w + gpu_w;
                    spans.push(Span::styled("  |  ", theme::separator()));
                    spans.push(Span::styled(
                        format!("Total {:.0}W", total_w),
                        theme::bold(),
                    ));
                    if total_w > 0.0 && bench.zkops > 0.0 {
                        let efficiency = bench.zkops / total_w;
                        spans.push(Span::styled("  |  ", theme::separator()));
                        spans.push(Span::styled(
                            format!("{:.0} zkOP/W", efficiency),
                            theme::dim(),
                        ));
                    }
                }
                spans
            }),
        ]
    } else {
        vec![
            Line::from(Span::styled("No benchmark results yet.", theme::placeholder())),
            Line::from(Span::styled("Press 'b' to run benchmarks.", theme::placeholder())),
        ]
    };

    let cpu = Paragraph::new(cpu_info)
        .block(
            Block::default()
                .title(Span::styled(" Benchmark ", theme::title()))
                .borders(Borders::ALL)
                .border_style(theme::border())
                .border_type(theme::border_type()),
        );
    f.render_widget(cpu, chunks[0]);

    // Results table
    if let Some(bench) = &state.benchmark_results {
        let header = Row::new([
            "Program", "Backend", "Precompile", "Weight", "Cycles", "Time", "Throughput",
        ])
        .style(theme::table_header());

        let rows: Vec<Row> = bench
            .results
            .iter()
            .enumerate()
            .map(|(i, r)| {
                let precompile_str = if r.precompile { "\u{2713}" } else { "-" };
                let weight_str = if r.weight > 0.0 {
                    format!("{:.0}%", r.weight * 100.0)
                } else {
                    "-".to_string()
                };
                Row::new(vec![
                    Cell::from(r.program_name.clone()),
                    Cell::from(r.prover_backend.clone()).style(theme::accent()),
                    Cell::from(precompile_str),
                    Cell::from(weight_str),
                    Cell::from(format!("{}", r.cycles)),
                    Cell::from(format!("{:.2}s", r.duration.as_secs_f64())),
                    Cell::from(format!("{:.0} c/s", r.throughput)),
                ])
                .style(theme::striped(i))
            })
            .collect();

        let table = Table::new(
            rows,
            [
                Constraint::Length(18),
                Constraint::Length(12),
                Constraint::Length(11),
                Constraint::Length(8),
                Constraint::Length(12),
                Constraint::Length(10),
                Constraint::Length(15),
            ],
        )
        .header(header)
        .block(
            Block::default()
                .title(Span::styled(" Results ", theme::title()))
                .borders(Borders::ALL)
                .border_style(theme::border())
                .border_type(theme::border_type()),
        );

        f.render_widget(table, chunks[1]);
    } else {
        let placeholder = Paragraph::new(Span::styled(
            if state.benchmark_running {
                "Benchmark running..."
            } else {
                "No results"
            },
            theme::placeholder(),
        ))
        .block(
            Block::default()
                .title(Span::styled(" Results ", theme::title()))
                .borders(Borders::ALL)
                .border_style(theme::border())
                .border_type(theme::border_type()),
        );
        f.render_widget(placeholder, chunks[1]);
    }

    // Device Benchmarks — selectable, grouped by device with per-backend breakdown
    render_device_benchmarks(f, chunks[2], state);

    // Controls
    let mut ctrl_spans: Vec<Span> = Vec::new();
    ctrl_spans.extend(theme::keybind("[b]", " Run All  "));
    ctrl_spans.extend(theme::keybind("[r]", " Re-benchmark Device  "));
    ctrl_spans.extend(theme::keybind("[j/k]", " Select Device"));
    let controls = Paragraph::new(Line::from(ctrl_spans))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(theme::border())
                .border_type(theme::border_type()),
        );
    f.render_widget(controls, chunks[3]);
}

fn render_device_benchmarks(f: &mut Frame, area: Rect, state: &MinerState) {
    let ids = device_ids(state);
    let dev_count = ids.len();

    if let Some(bench) = &state.benchmark_results {
        let dev_header = Row::new([
            "", "Backend", "po2", "Segment", "Memory", "Throughput",
        ])
        .style(theme::table_header());

        let mut dev_rows: Vec<Row> = Vec::new();

        for (dev_idx, device_id) in ids.iter().enumerate() {
            let is_selected = dev_idx == state.benchmark_selected_device;
            let is_running = state
                .benchmark_device_in_progress
                .as_deref()
                == Some(device_id.as_str());

            let dev_entries: Vec<_> = bench
                .device_benchmarks
                .iter()
                .filter(|d| &d.device_id == device_id)
                .collect();

            let label = if device_id == "cpu" {
                bench.cpu_info.clone()
            } else {
                dev_entries
                    .first()
                    .map(|d| d.device_label.clone())
                    .unwrap_or_else(|| {
                        state
                            .hardware
                            .gpus
                            .iter()
                            .find(|g| format!("gpu{}", g.index) == *device_id)
                            .map(|g| format!("GPU{} {}", g.index, g.name))
                            .unwrap_or_else(|| device_id.clone())
                    })
            };

            let total_tp: f64 = dev_entries.iter().map(|d| d.throughput).sum();
            let cursor = if is_selected { "> " } else { "  " };
            let status = if is_running { " [benchmarking...]" } else { "" };
            let device_label = format!("{cursor}{label}{status}");

            let device_style = if is_selected {
                Style::default()
                    .fg(theme::peach())
                    .add_modifier(Modifier::BOLD)
            } else {
                theme::bold()
            };

            dev_rows.push(Row::new(vec![
                Cell::from(device_label).style(device_style),
                Cell::from(""),
                Cell::from(""),
                Cell::from(""),
                Cell::from(""),
                Cell::from(format_throughput(total_tp)).style(theme::metric()),
            ]));

            for d in dev_entries {
                let rows_count = 1u64 << d.optimal_po2;
                let segment_str = if rows_count >= 1_000_000 {
                    format!("{}M rows", rows_count / 1_000_000)
                } else {
                    format!("{}K rows", rows_count / 1_000)
                };
                let mem_gb = d.memory_usage_bytes as f64 / (1024.0 * 1024.0 * 1024.0);
                let mem_str = if mem_gb >= 1.0 {
                    format!("{:.1} GB", mem_gb)
                } else {
                    format!("{:.0} MB", mem_gb * 1024.0)
                };
                dev_rows.push(
                    Row::new(vec![
                        Cell::from(format!("  {}", d.prover_backend)).style(theme::accent()),
                        Cell::from("po2"),
                        Cell::from(format!("{}", d.optimal_po2)),
                        Cell::from(segment_str),
                        Cell::from(mem_str),
                        Cell::from(format_throughput(d.throughput)),
                    ])
                    .style(theme::bold()),
                );

                // Per-program breakdown for this device (real measured throughputs),
                // grouped under the device so results read per-device rather than flat.
                for program in BENCHMARK_PROGRAMS {
                    if let Some(tp) = d.program_throughputs.get(program.name) {
                        let kind = if program.precompile { "precompile" } else { "compute" };
                        dev_rows.push(
                            Row::new(vec![
                                Cell::from(format!("      {}", program.name)),
                                Cell::from(kind),
                                Cell::from(""),
                                Cell::from(""),
                                Cell::from(""),
                                Cell::from(format_throughput(*tp)),
                            ])
                            .style(theme::dim()),
                        );
                    }
                }
            }
        }

        let dev_table = Table::new(
            dev_rows,
            [
                Constraint::Length(30),
                Constraint::Length(10),
                Constraint::Length(5),
                Constraint::Length(10),
                Constraint::Length(10),
                Constraint::Length(14),
            ],
        )
        .header(dev_header)
        .block(
            Block::default()
                .title(Span::styled(
                    format!(" Device Benchmarks ({}) ", dev_count),
                    theme::title(),
                ))
                .borders(Borders::ALL)
                .border_style(theme::border())
                .border_type(theme::border_type()),
        );

        f.render_widget(dev_table, area);
    } else {
        let placeholder = Paragraph::new(Span::styled(
            "No benchmarks — press [b] to run",
            theme::placeholder(),
        ))
        .block(
            Block::default()
                .title(Span::styled(" Device Benchmarks ", theme::title()))
                .borders(Borders::ALL)
                .border_style(theme::border())
                .border_type(theme::border_type()),
        );
        f.render_widget(placeholder, area);
    }
}

// ---------------------------------------------------------------------------
// Progress view — redesigned with per-device focus, live telemetry, and scores
// ---------------------------------------------------------------------------

fn render_progress_view(
    f: &mut Frame,
    area: Rect,
    state: &MinerState,
    tracker: &BenchmarkTracker,
) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),  // Header with progress bar
            Constraint::Length(3),  // Device tabs
            Constraint::Min(10),   // Program table (main content)
            Constraint::Length(5), // GPU telemetry
            Constraint::Length(5), // Score + controls
        ])
        .split(area);

    render_progress_header(f, chunks[0], state, tracker);
    render_device_tabs(f, chunks[1], tracker);
    render_program_table(f, chunks[2], state, tracker);
    render_gpu_telemetry(f, chunks[3], state, tracker);
    render_score_and_controls(f, chunks[4], state, tracker);
}

fn render_progress_header(
    f: &mut Frame,
    area: Rect,
    state: &MinerState,
    tracker: &BenchmarkTracker,
) {
    let elapsed = tracker
        .started_at
        .map(|t| chrono::Utc::now().signed_duration_since(t).num_seconds())
        .unwrap_or(0);
    let done = tracker.completed_count();
    let total = tracker.total_count().max(1);
    let completed_gpus = tracker.devices.iter().filter(|d| d.complete).count();
    let total_gpus = tracker.devices.len();

    let spinners = ['|', '/', '-', '\\'];
    let spinner = spinners[state.tick_count as usize % spinners.len()];

    // Progress bar
    let ratio = done as f64 / total as f64;
    let bar_width = 24usize;
    let filled = (ratio * bar_width as f64).round() as usize;
    let bar_filled: String = "\u{2588}".repeat(filled);
    let bar_empty: String = "\u{2591}".repeat(bar_width.saturating_sub(filled));
    let pct = (ratio * 100.0) as u32;

    // ETA: estimate from elapsed time and progress ratio
    let eta_str = if done > 0 && ratio < 1.0 {
        let eta_secs = (elapsed as f64 / ratio * (1.0 - ratio)) as i64;
        format!("ETA ~{}:{:02}", eta_secs / 60, eta_secs % 60)
    } else if ratio >= 1.0 {
        "Done".to_string()
    } else {
        "ETA --:--".to_string()
    };

    let elapsed_str = format!("{}:{:02}", elapsed / 60, elapsed % 60);

    let line = Line::from(vec![
        Span::styled(
            format!(" {spinner} Benchmarking "),
            Style::default()
                .fg(theme::yellow())
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(format!("{done}/{total} programs"), theme::metric()),
        Span::styled(
            format!("  GPU {}/{total_gpus}", completed_gpus + 1),
            theme::dim(),
        ),
        Span::styled("  ", theme::dim()),
        Span::styled(bar_filled, Style::default().fg(theme::green())),
        Span::styled(bar_empty, Style::default().fg(theme::overlay())),
        Span::styled(format!(" {pct}%"), theme::bold()),
        Span::styled(format!("  {elapsed_str}"), theme::dim()),
        Span::styled(format!("  {eta_str}"), theme::dim()),
    ]);

    let header = Paragraph::new(vec![line]).block(
        Block::default()
            .title(Span::styled(" Benchmark ", theme::title()))
            .borders(Borders::ALL)
            .border_style(theme::border_focused())
            .border_type(theme::border_type()),
    );
    f.render_widget(header, area);
}

fn render_device_tabs(f: &mut Frame, area: Rect, tracker: &BenchmarkTracker) {
    let mut spans: Vec<Span> = vec![Span::raw("  ")];

    for (i, dev) in tracker.devices.iter().enumerate() {
        let is_active = i == tracker.active_device_index;
        let done_count = dev
            .programs
            .iter()
            .filter(|p| p.phase == ProgramPhase::Done)
            .count();

        if dev.complete {
            let score_str = dev
                .partial_zkops
                .map(|s| format!("{:.0} zkOP/s", s))
                .unwrap_or_else(|| "done".to_string());
            spans.push(Span::styled(
                format!("\u{2713} {} [{}]", dev.device_label, score_str),
                Style::default().fg(theme::green()),
            ));
        } else if is_active {
            spans.push(Span::styled(
                format!("\u{25B6} {} [{}/6]", dev.device_label, done_count),
                Style::default()
                    .fg(theme::yellow())
                    .add_modifier(Modifier::BOLD),
            ));
        } else {
            spans.push(Span::styled(
                format!("  {} [\u{00B7}\u{00B7}\u{00B7}\u{00B7}\u{00B7}\u{00B7}]", dev.device_label),
                theme::dim(),
            ));
        }

        if i < tracker.devices.len() - 1 {
            spans.push(Span::styled("    ", theme::dim()));
        }
    }

    let tabs = Paragraph::new(vec![Line::from(spans)]).block(
        Block::default()
            .title(Span::styled(" Devices ", theme::title()))
            .borders(Borders::ALL)
            .border_style(theme::border())
            .border_type(theme::border_type()),
    );
    f.render_widget(tabs, area);
}

fn render_program_table(
    f: &mut Frame,
    area: Rect,
    state: &MinerState,
    tracker: &BenchmarkTracker,
) {
    let active_dev = tracker.devices.get(tracker.active_device_index);

    let title = active_dev
        .map(|d| format!(" Programs \u{2014} {} ", d.device_label))
        .unwrap_or_else(|| " Programs ".to_string());

    let header = Row::new(vec![
        Cell::from("").style(theme::table_header()),
        Cell::from("Program").style(theme::table_header()),
        Cell::from("Weight").style(theme::table_header()),
        Cell::from("Cycles").style(theme::table_header()),
        Cell::from("Duration").style(theme::table_header()),
        Cell::from("Throughput").style(theme::table_header()),
        Cell::from("Reference").style(theme::table_header()),
        Cell::from("Delta").style(theme::table_header()),
    ]);

    let rows: Vec<Row> = if let Some(dev) = active_dev {
        dev.programs
            .iter()
            .enumerate()
            .map(|(i, prog)| {
                let ref_tp = BENCHMARK_PROGRAMS
                    .iter()
                    .find(|p| p.name == prog.name)
                    .map(|p| p.reference_throughput)
                    .unwrap_or(0.0);

                match &prog.phase {
                    ProgramPhase::Pending => Row::new(vec![
                        Cell::from(Span::styled(" \u{00B7}", theme::dim())),
                        Cell::from(Span::styled(&prog.name, theme::dim())),
                        Cell::from(Span::styled(
                            prog.weight
                                .map(|w| format!("{:.0}%", w * 100.0))
                                .unwrap_or_else(|| format!(
                                    "{:.0}%",
                                    BENCHMARK_PROGRAMS
                                        .iter()
                                        .find(|p| p.name == prog.name)
                                        .map(|p| p.weight * 100.0)
                                        .unwrap_or(0.0)
                                )),
                            theme::dim(),
                        )),
                        Cell::from(Span::styled("\u{2014}", theme::dim())),
                        Cell::from(Span::styled("\u{2014}", theme::dim())),
                        Cell::from(Span::styled("\u{2014}", theme::dim())),
                        Cell::from(Span::styled(
                            format_throughput(ref_tp),
                            Style::default().fg(theme::subtext()),
                        )),
                        Cell::from(Span::styled("\u{2014}", theme::dim())),
                    ])
                    .style(theme::striped(i)),

                    ProgramPhase::Running => {
                        let dots =
                            ".".repeat((state.tick_count as usize % 3) + 1);
                        let indicator_style = if state.tick_count % 2 == 0 {
                            Style::default()
                                .fg(theme::yellow())
                                .add_modifier(Modifier::BOLD)
                        } else {
                            Style::default().fg(theme::yellow())
                        };
                        Row::new(vec![
                            Cell::from(Span::styled(" \u{25B6}", indicator_style)),
                            Cell::from(Span::styled(
                                &prog.name,
                                Style::default().add_modifier(Modifier::BOLD),
                            )),
                            Cell::from(Span::styled(
                                format!(
                                    "{:.0}%",
                                    BENCHMARK_PROGRAMS
                                        .iter()
                                        .find(|p| p.name == prog.name)
                                        .map(|p| p.weight * 100.0)
                                        .unwrap_or(0.0)
                                ),
                                Style::default().fg(theme::text()),
                            )),
                            Cell::from(Span::styled("\u{2014}", theme::dim())),
                            Cell::from(Span::styled(
                                format!("proving{dots}"),
                                Style::default().fg(theme::yellow()),
                            )),
                            Cell::from(Span::styled("\u{2014}", theme::dim())),
                            Cell::from(Span::styled(
                                format_throughput(ref_tp),
                                Style::default().fg(theme::subtext()),
                            )),
                            Cell::from(Span::styled("\u{2014}", theme::dim())),
                        ])
                        .style(theme::striped(i))
                    }

                    ProgramPhase::Done => {
                        let tp = prog.throughput.unwrap_or(0.0);
                        let dur = prog.duration_secs.unwrap_or(0.0);
                        let cycles = prog.cycles.unwrap_or(0);

                        let delta = if ref_tp > 0.0 && tp > 0.0 {
                            let pct = ((tp / ref_tp) - 1.0) * 100.0;
                            let color = if pct > 2.0 {
                                theme::green()
                            } else if pct < -2.0 {
                                theme::red()
                            } else {
                                theme::subtext()
                            };
                            Cell::from(Span::styled(
                                format!("{:+.1}%", pct),
                                Style::default().fg(color),
                            ))
                        } else {
                            Cell::from(Span::styled("\u{2014}", theme::dim()))
                        };

                        Row::new(vec![
                            Cell::from(Span::styled(
                                " \u{2713}",
                                Style::default().fg(theme::green()),
                            )),
                            Cell::from(prog.name.clone()),
                            Cell::from(
                                prog.weight
                                    .map(|w| format!("{:.0}%", w * 100.0))
                                    .unwrap_or_default(),
                            ),
                            Cell::from(format_cycles(cycles)),
                            Cell::from(format!("{dur:.1}s")),
                            Cell::from(Span::styled(
                                format_throughput(tp),
                                theme::metric(),
                            )),
                            Cell::from(Span::styled(
                                format_throughput(ref_tp),
                                Style::default().fg(theme::subtext()),
                            )),
                            delta,
                        ])
                        .style(theme::striped(i))
                    }

                    ProgramPhase::Failed => Row::new(vec![
                        Cell::from(Span::styled(
                            " \u{2717}",
                            Style::default().fg(theme::red()),
                        )),
                        Cell::from(Span::styled(&prog.name, theme::error())),
                        Cell::from(""),
                        Cell::from(""),
                        Cell::from(""),
                        Cell::from(Span::styled("FAILED", theme::error())),
                        Cell::from(""),
                        Cell::from(""),
                    ])
                    .style(theme::striped(i)),
                }
            })
            .collect()
    } else {
        vec![]
    };

    let widths = [
        Constraint::Length(3),  // status icon
        Constraint::Length(16), // program name
        Constraint::Length(7),  // weight
        Constraint::Length(10), // cycles
        Constraint::Length(10), // duration
        Constraint::Length(14), // throughput
        Constraint::Length(14), // reference
        Constraint::Length(10), // delta
    ];

    let table = Table::new(rows, widths).header(header).block(
        Block::default()
            .title(Span::styled(title, theme::title()))
            .borders(Borders::ALL)
            .border_style(theme::border_focused())
            .border_type(theme::border_type()),
    );
    f.render_widget(table, area);
}

fn render_gpu_telemetry(
    f: &mut Frame,
    area: Rect,
    state: &MinerState,
    tracker: &BenchmarkTracker,
) {
    let active_dev = tracker.devices.get(tracker.active_device_index);

    // Find the matching GPU in hardware state
    let gpu = active_dev.and_then(|dev| {
        dev.device_index().and_then(|idx| {
            state.hardware.gpus.iter().find(|g| g.index == idx)
        })
    });

    let lines: Vec<Line<'_>> = if let Some(gpu) = gpu {
        let temp = gpu.temp_junction_c.or(gpu.temp_edge_c).unwrap_or(0.0);
        let temp_pct = ((temp / 100.0).clamp(0.0, 1.0) * 100.0) as u32;

        let pwr_pct = if gpu.power_cap_watts > 0.0 {
            ((gpu.power_watts / gpu.power_cap_watts).clamp(0.0, 1.0) * 100.0) as u32
        } else {
            0
        };

        let vram_pct = if gpu.vram_total_bytes > 0 {
            ((gpu.vram_used_bytes as f64 / gpu.vram_total_bytes as f64).clamp(0.0, 1.0) * 100.0) as u32
        } else {
            0
        };

        let vram_used = crate::hardware::fmt_bytes(gpu.vram_used_bytes);
        let vram_total = crate::hardware::fmt_bytes(gpu.vram_total_bytes);

        let vendor_str = match gpu.vendor {
            GpuVendor::Nvidia => "NVDA",
            GpuVendor::Amd => "AMD",
            GpuVendor::Intel => "INTC",
            GpuVendor::Unknown => "GPU",
        };

        let bar = |pct: u32, w: usize| -> String {
            let filled = (pct as f64 / 100.0 * w as f64).round() as usize;
            let empty = w.saturating_sub(filled);
            format!(
                "{}{}",
                "\u{2588}".repeat(filled),
                "\u{2591}".repeat(empty)
            )
        };

        vec![
            Line::from(format!(
                "  Temp {temp:.0}\u{00B0}C  {:<16}    VRAM {vram_used}/{vram_total}  {:<16}",
                bar(temp_pct, 16),
                bar(vram_pct, 16),
            )),
            Line::from(format!(
                "  Power {:.0}W  {:<16}    Clock {}MHz  {vendor_str}  PCIe {} x{}",
                gpu.power_watts,
                bar(pwr_pct, 16),
                gpu.gpu_clock_mhz,
                crate::hardware::pcie_gen_label(&gpu.pcie_speed),
                gpu.pcie_width,
            )),
            Line::from(format!(
                "  Fan {}%  Core {}%",
                if gpu.fan_max_rpm > 0 { gpu.fan_rpm * 100 / gpu.fan_max_rpm } else { 0 },
                gpu.gpu_usage_percent,
            )),
        ]
    } else {
        vec![Line::from(Span::styled(
            "  No GPU telemetry available",
            theme::placeholder(),
        ))]
    };

    let telemetry = Paragraph::new(lines).block(
        Block::default()
            .title(Span::styled(" GPU Telemetry ", theme::title()))
            .borders(Borders::ALL)
            .border_style(theme::border())
            .border_type(theme::border_type()),
    );
    f.render_widget(telemetry, area);
}

fn render_score_and_controls(
    f: &mut Frame,
    area: Rect,
    state: &MinerState,
    tracker: &BenchmarkTracker,
) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
        .split(area);

    // Score panel
    let active_dev = tracker.devices.get(tracker.active_device_index);
    let mut score_lines: Vec<Line> = Vec::new();

    // Per-device scores
    let mut score_spans: Vec<Span> = vec![Span::styled("  ", theme::dim())];
    for dev in &tracker.devices {
        if dev.complete {
            let score = dev.partial_zkops.unwrap_or(0.0);
            score_spans.push(Span::styled(
                format!("{}: {:.0} zkOP/s \u{2713}  ", dev.device_label, score),
                Style::default().fg(theme::green()),
            ));
        } else if let Some(score) = dev.partial_zkops {
            score_spans.push(Span::styled(
                format!("{}: ~{:.0} zkOP/s  ", dev.device_label, score),
                theme::metric(),
            ));
        } else {
            score_spans.push(Span::styled(
                format!("{}: \u{2014}  ", dev.device_label),
                theme::dim(),
            ));
        }
    }
    score_lines.push(Line::from(score_spans));

    // Active device partial score detail
    if let Some(dev) = active_dev {
        let done = dev
            .programs
            .iter()
            .filter(|p| p.phase == ProgramPhase::Done)
            .count();
        if let Some(score) = dev.partial_zkops {
            score_lines.push(Line::from(vec![
                Span::styled("  Partial: ", theme::dim()),
                Span::styled(format!("{score:.0} zkOP/s"), theme::metric()),
                Span::styled(format!(" ({done}/6 programs)"), theme::dim()),
            ]));
        } else {
            score_lines.push(Line::from(Span::styled(
                "  Waiting for first result...",
                theme::placeholder(),
            )));
        }
    }

    let score = Paragraph::new(score_lines).block(
        Block::default()
            .title(Span::styled(" Score ", theme::title()))
            .borders(Borders::ALL)
            .border_style(theme::border())
            .border_type(theme::border_type()),
    );
    f.render_widget(score, cols[0]);

    // Controls
    let dots = ".".repeat((state.tick_count as usize % 3) + 1);
    let mut ctrl_spans: Vec<Span> = Vec::new();
    ctrl_spans.extend(theme::keybind("[Esc]", " Cancel  "));
    ctrl_spans.push(Span::styled(
        format!("Benchmarking{dots}"),
        Style::default().fg(theme::yellow()),
    ));
    let controls = Paragraph::new(vec![Line::from(ctrl_spans)]).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(theme::border())
            .border_type(theme::border_type()),
    );
    f.render_widget(controls, cols[1]);
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn format_throughput(tp: f64) -> String {
    if tp >= 1_000_000_000.0 {
        format!("{:.1}B c/s", tp / 1_000_000_000.0)
    } else if tp >= 1_000_000.0 {
        format!("{:.1}M c/s", tp / 1_000_000.0)
    } else if tp >= 1_000.0 {
        format!("{:.1}K c/s", tp / 1_000.0)
    } else {
        format!("{:.0} c/s", tp)
    }
}

fn format_cycles(cycles: u64) -> String {
    if cycles >= 1_000_000 {
        format!("{:.1}M", cycles as f64 / 1_000_000.0)
    } else if cycles >= 1_000 {
        format!("{:.1}K", cycles as f64 / 1_000.0)
    } else {
        format!("{}", cycles)
    }
}
