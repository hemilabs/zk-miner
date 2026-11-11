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
use zkminer_prover_protocol::{zkops_from_stark_secs, BENCH_ZKOP_MIX};

/// Build the ordered list of unique device IDs from benchmark data + hardware: gpu0, gpu1, etc.
/// The CPU has no row: the benchmark measures only the cards.
fn device_ids(state: &MinerState) -> Vec<String> {
    let mut ids = Vec::new();
    // Resolve each physical card to the benchmark id that actually belongs to it.
    // Building these from `gpu.index` produced ids for cards that have no
    // benchmark row at all (a non-proving AMD card) while omitting the id of a
    // card that does -- so one row rendered another card's label and score, and
    // the last card fell off the list.
    if let Some(suite) = &state.benchmark_results {
        for gpu in &state.hardware.gpus {
            if let Some(id) = gpu.benchmark_device_id(suite) {
                if !ids.contains(&id) {
                    ids.push(id);
                }
            }
        }
    }
    // Include any benchmark row we could not tie to a detected card (e.g. the
    // TUI cannot see the card, or a legacy cache with an ambiguous name), so its
    // data is still reachable rather than silently dropped.
    if let Some(suite) = &state.benchmark_results {
        for d in &suite.device_benchmarks {
            if d.device_id.starts_with("gpu") && !ids.contains(&d.device_id) {
                ids.push(d.device_id.clone());
            }
        }
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
            Constraint::Length(8), // CPU info + zkOP/s + power
            Constraint::Min(6),    // Results table
            Constraint::Min(5),    // Device benchmarks (selectable)
            Constraint::Length(3), // Controls
        ])
        .split(area);

    // CPU info + zkOP/s
    let cpu_info = if let Some(bench) = &state.benchmark_results {
        vec![
            Line::from(vec![
                Span::styled(
                    format!(" zkOP/s: {} ", format_zkops(bench.zkops)),
                    theme::metric(),
                ),
                Span::styled(
                    "  SP1 cycles per second on a 50M-cycle program, all GPUs",
                    theme::dim(),
                ),
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
                    Some(w) => spans.push(Span::styled(format!("CPU {w:.0}W"), theme::warning())),
                    None => spans.push(Span::styled("CPU N/A", theme::dim())),
                }
                spans.push(Span::styled("  ", theme::dim()));
                match bench.gpu_power_watts {
                    Some(w) => spans.push(Span::styled(format!("GPU {w:.0}W"), theme::warning())),
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
            Line::from(Span::styled(
                "No benchmark results yet.",
                theme::placeholder(),
            )),
            Line::from(Span::styled(
                "Press 'b' to run benchmarks.",
                theme::placeholder(),
            )),
        ]
    };

    let title = if state.return_to_setup_after_benchmark && !state.startup_benchmark_pending {
        " Benchmark - press any key to continue to setup "
    } else {
        " Benchmark "
    };
    let cpu = Paragraph::new(cpu_info).block(
        Block::default()
            .title(Span::styled(title, theme::title()))
            .borders(Borders::ALL)
            .border_style(theme::border())
            .border_type(theme::border_type()),
    );
    f.render_widget(cpu, chunks[0]);

    // Results table
    if let Some(bench) = &state.benchmark_results {
        let header = Row::new([
            "Program",
            "Backend",
            "Precompile",
            "Weight",
            "Cycles",
            "Time",
            "Throughput",
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
    let controls = Paragraph::new(Line::from(ctrl_spans)).block(
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
            "",
            "Backend",
            "po2",
            "Segment",
            "Memory",
            "Throughput",
            "zkOP/s",
        ])
            .style(theme::table_header());

        let mut dev_rows: Vec<Row> = Vec::new();

        for (dev_idx, device_id) in ids.iter().enumerate() {
            let is_selected = dev_idx == state.benchmark_selected_device;
            let is_running =
                state.benchmark_device_in_progress.as_deref() == Some(device_id.as_str());

            let dev_entries: Vec<_> = bench
                .device_benchmarks
                .iter()
                .filter(|d| &d.device_id == device_id)
                .collect();

            let label = dev_entries
                .first()
                .map(|d| d.device_label.clone())
                .unwrap_or_else(|| {
                    state
                        .benchmark_results
                        .as_ref()
                        .and_then(|suite| {
                            state.hardware.gpus.iter().find(|g| {
                                g.benchmark_device_id(suite).as_deref() == Some(device_id.as_str())
                            })
                        })
                        .map(|g| format!("GPU{} {}", g.index, g.name))
                        .unwrap_or_else(|| device_id.clone())
                });

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
                        Cell::from(format_zkops(d.zkops())).style(theme::metric()),
                    ])
                    .style(theme::bold()),
                );

                // Per-program breakdown for this device (real measured throughputs),
                // grouped under the device so results read per-device rather than flat.
                for program in BENCHMARK_PROGRAMS {
                    if let Some(tp) = d.program_throughputs.get(program.name) {
                        let kind = if program.precompile {
                            "precompile"
                        } else {
                            "compute"
                        };
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
                Constraint::Length(10),
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

/// Lay `items` out left to right, starting a new line rather than splitting an item.
fn wrap_items(items: Vec<Span<'static>>, width: usize) -> Vec<Line<'static>> {
    const GAP: &str = "   ";
    let mut lines = Vec::new();
    let mut current: Vec<Span<'static>> = vec![Span::raw(" ")];
    let mut used = 1;
    for item in items {
        let len = item.content.chars().count();
        if current.len() > 1 && used + GAP.len() + len > width {
            lines.push(Line::from(std::mem::replace(
                &mut current,
                vec![Span::raw(" ")],
            )));
            used = 1;
        }
        if current.len() > 1 {
            current.push(Span::raw(GAP));
            used += GAP.len();
        }
        used += len;
        current.push(item);
    }
    lines.push(Line::from(current));
    lines
}

fn render_progress_view(f: &mut Frame, area: Rect, state: &MinerState, tracker: &BenchmarkTracker) {
    let tabs = device_tab_lines(tracker, area.width.saturating_sub(2) as usize);
    let problems = &state.startup_problems;
    let problems_height = if problems.is_empty() {
        0
    } else {
        problems.len() as u16 + 2
    };
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),                     // Header with progress bar
            Constraint::Length(tabs.len() as u16 + 2), // Device tabs
            Constraint::Length(problems_height),       // Workers that did not start (0 if none)
            Constraint::Min(10),                       // Program table (main content)
            Constraint::Length(5),                     // GPU telemetry
            Constraint::Length(5),                     // Score + controls
        ])
        .split(area);

    render_progress_header(f, chunks[0], state, tracker);
    render_device_tabs(f, chunks[1], tabs);
    if !problems.is_empty() {
        render_startup_problems(f, chunks[2], problems);
    }
    render_program_table(f, chunks[3], state, tracker);
    render_gpu_telemetry(f, chunks[4], state, tracker);
    render_score_and_controls(f, chunks[5], state, tracker);
}

/// Why a card may be missing a zkVM below: the workers that did not start.
fn render_startup_problems(f: &mut Frame, area: Rect, problems: &[String]) {
    let lines: Vec<Line<'_>> = problems
        .iter()
        .map(|p| Line::from(Span::styled(format!(" {p}"), theme::error())))
        .collect();
    let panel = Paragraph::new(lines).block(
        Block::default()
            .title(Span::styled(" Did not start ", theme::title()))
            .borders(Borders::ALL)
            .border_style(theme::border())
            .border_type(theme::border_type()),
    );
    f.render_widget(panel, area);
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
    // Between two cards the finished worker is shut down and its memory reclaimed.
    let current = tracker
        .active_device()
        .map(|d| tracker.display_name(d))
        .unwrap_or_else(|| "next GPU".to_string());
    let verb = match tracker.active_device() {
        Some(d) if d.warming_up => "Warming up",
        Some(_) => "Benchmarking",
        None => "Preparing",
    };

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
            format!(" {spinner} {verb} {current}  "),
            Style::default()
                .fg(theme::yellow())
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(format!("{done}/{total} programs"), theme::metric()),
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

/// One tab per queued card and zkVM, wrapped to `width`.
fn device_tab_lines(tracker: &BenchmarkTracker, width: usize) -> Vec<Line<'static>> {
    let items = tracker
        .devices
        .iter()
        .enumerate()
        .map(|(i, dev)| {
            let name = tracker.display_name(dev);
            if dev.failed {
                Span::styled(format!("\u{2717} {name}"), theme::error())
            } else if dev.complete {
                Span::styled(
                    format!("\u{2713} {name}"),
                    Style::default().fg(theme::green()),
                )
            } else if i == tracker.active_device_index {
                let done = dev
                    .programs
                    .iter()
                    .filter(|p| p.phase == ProgramPhase::Done)
                    .count();
                Span::styled(
                    format!("\u{25B6} {name} [{done}/{}]", dev.programs.len()),
                    Style::default()
                        .fg(theme::yellow())
                        .add_modifier(Modifier::BOLD),
                )
            } else {
                Span::styled(format!("\u{00B7} {name}"), theme::dim())
            }
        })
        .collect();
    wrap_items(items, width)
}

fn render_device_tabs(f: &mut Frame, area: Rect, lines: Vec<Line<'static>>) {
    let tabs = Paragraph::new(lines).block(
        Block::default()
            .title(Span::styled(" Devices ", theme::title()))
            .borders(Borders::ALL)
            .border_style(theme::border())
            .border_type(theme::border_type()),
    );
    f.render_widget(tabs, area);
}

fn render_program_table(f: &mut Frame, area: Rect, state: &MinerState, tracker: &BenchmarkTracker) {
    let active_dev = tracker.devices.get(tracker.active_device_index);

    let title = active_dev
        .map(|d| {
            format!(
                " Programs \u{2014} {} / {} ",
                d.device_label,
                d.backend_label()
            )
        })
        .unwrap_or_else(|| " Programs ".to_string());

    let header = Row::new(
        [
            "", "Program", "Weight", "Cycles", "STARK", "Groth16", "Result",
        ]
        .map(|title| Cell::from(title).style(theme::table_header())),
    );

    let dash = || Cell::from(Span::styled("\u{2014}", theme::dim()));
    let rows: Vec<Row> = active_dev
        .map(|dev| {
            dev.programs
                .iter()
                .enumerate()
                .map(|(i, prog)| {
                    let row = match &prog.phase {
                        ProgramPhase::Pending => Row::new(vec![
                            Cell::from(Span::styled(" \u{00B7}", theme::dim())),
                            Cell::from(Span::styled(&prog.name, theme::dim())),
                            Cell::from(Span::styled(weight_label(&prog.name), theme::dim())),
                            dash(),
                            dash(),
                            dash(),
                            dash(),
                        ]),
                        ProgramPhase::Running => {
                            let dots = ".".repeat((state.tick_count as usize % 3) + 1);
                            let indicator_style = if state.tick_count.is_multiple_of(2) {
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
                                    weight_label(&prog.name),
                                    Style::default().fg(theme::text()),
                                )),
                                dash(),
                                Cell::from(Span::styled(
                                    format!("proving{dots}"),
                                    Style::default().fg(theme::yellow()),
                                )),
                                dash(),
                                dash(),
                            ])
                        }
                        ProgramPhase::Done => {
                            let duration = prog.duration_secs.unwrap_or(0.0);
                            let result = if prog.name == BENCH_ZKOP_MIX {
                                format!(
                                    "{} zkOP/s",
                                    format_zkops(zkops_from_stark_secs(duration))
                                )
                            } else {
                                format_throughput(prog.throughput.unwrap_or(0.0))
                            };
                            Row::new(vec![
                                Cell::from(Span::styled(
                                    " \u{2713}",
                                    Style::default().fg(theme::green()),
                                )),
                                Cell::from(prog.name.clone()),
                                Cell::from(weight_label(&prog.name)),
                                Cell::from(format_cycles(prog.cycles.unwrap_or(0))),
                                Cell::from(format!("{duration:.1}s")),
                                // SP1 measures the wrap on one program per card, so a dash here means
                                // "not measured for this program", not "no wrap".
                                Cell::from(
                                    prog.wrap_secs
                                        .map(|w| format!("{w:.1}s"))
                                        .unwrap_or_else(|| "\u{2014}".to_string()),
                                ),
                                Cell::from(Span::styled(result, theme::metric())),
                            ])
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
                            Cell::from(""),
                            Cell::from(Span::styled("FAILED", theme::error())),
                        ]),
                    };
                    row.style(theme::striped(i))
                })
                .collect()
        })
        .unwrap_or_default();

    let widths = [
        Constraint::Length(3),  // status icon
        Constraint::Length(16), // program name
        Constraint::Length(7),  // weight
        Constraint::Length(10), // cycles
        Constraint::Length(10), // STARK time
        Constraint::Length(9),  // Groth16 wrap
        Constraint::Length(18), // throughput, or the score
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

fn render_gpu_telemetry(f: &mut Frame, area: Rect, state: &MinerState, tracker: &BenchmarkTracker) {
    let active_dev = tracker.devices.get(tracker.active_device_index);

    // Find the matching GPU in hardware state
    // Join on PCI bus id, not on the prover's device index. `dev.device_index()`
    // is the prover's per-vendor ordinal; `g.index` is a display ordinal over all
    // DRM cards. Matching them meant that while the RTX 5090 benchmarked at ~520W
    // under a tab labelled "GPU0 NVIDIA GeForce RTX 5090", this panel rendered
    // hardware.gpus[0] -- the idle AMD 7900 XTX at 9W, tagged "AMD" -- and the
    // 4090's telemetry was unreachable from this screen entirely.
    let gpu = active_dev.and_then(|dev| dev.resolve_gpu(&state.hardware.gpus));

    let lines: Vec<Line<'_>> = if let Some(gpu) = gpu {
        let temp = gpu.temp_junction_c.or(gpu.temp_edge_c).unwrap_or(0.0);
        let temp_pct = ((temp / 100.0).clamp(0.0, 1.0) * 100.0) as u32;

        let pwr_pct = if gpu.power_cap_watts > 0.0 {
            ((gpu.power_watts / gpu.power_cap_watts).clamp(0.0, 1.0) * 100.0) as u32
        } else {
            0
        };

        let vram_pct = if gpu.vram_total_bytes > 0 {
            ((gpu.vram_used_bytes as f64 / gpu.vram_total_bytes as f64).clamp(0.0, 1.0) * 100.0)
                as u32
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
            format!("{}{}", "\u{2588}".repeat(filled), "\u{2591}".repeat(empty))
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
                if gpu.fan_max_rpm > 0 {
                    gpu.fan_rpm * 100 / gpu.fan_max_rpm
                } else {
                    0
                },
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

    // Score panel: each row's score appears when its scoring program, the last one, finishes.
    let scores: Vec<Span> = tracker
        .devices
        .iter()
        .filter_map(|dev| {
            let name = tracker.display_name(dev);
            if dev.failed {
                Some(Span::styled(format!("{name} failed"), theme::error()))
            } else {
                dev.zkops.map(|score| {
                    Span::styled(
                        format!("{name} {} \u{2713}", format_zkops(score)),
                        Style::default().fg(theme::green()),
                    )
                })
            }
        })
        .collect();
    let score_lines: Vec<Line> = if scores.is_empty() {
        vec![Line::from(Span::styled(
            " Scored by the last program on each zkVM",
            theme::placeholder(),
        ))]
    } else {
        wrap_items(scores, cols[0].width.saturating_sub(2) as usize)
    };

    let score = Paragraph::new(score_lines).block(
        Block::default()
            .title(Span::styled(" Score (zkOP/s) ", theme::title()))
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

/// A zkOP/s figure, or "N/A" when there is no score.
fn format_zkops(zkops: f64) -> String {
    if zkops >= 1_000_000.0 {
        format!("{:.2}M", zkops / 1_000_000.0)
    } else if zkops >= 1_000.0 {
        format!("{:.0}K", zkops / 1_000.0)
    } else if zkops > 0.0 {
        format!("{zkops:.0}")
    } else {
        "N/A".to_string()
    }
}

/// The Weight column: a program's share, or what the scoring program is for.
fn weight_label(name: &str) -> String {
    if name == BENCH_ZKOP_MIX {
        return "score".to_string();
    }
    BENCHMARK_PROGRAMS
        .iter()
        .find(|p| p.name == name)
        .map(|p| format!("{:.0}%", p.weight * 100.0))
        .unwrap_or_default()
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

#[cfg(test)]
mod tests {
    use super::*;

    fn text(line: &Line) -> String {
        line.spans.iter().map(|s| s.content.as_ref()).collect()
    }

    #[test]
    fn items_wrap_between_tabs_and_never_inside_one() {
        let items = ["RTX 4090 RISC Zero", "RTX 4090 SP1", "Arc A770 RISC Zero"]
            .map(|s| Span::raw(s.to_string()))
            .to_vec();

        let lines = wrap_items(items, 36);

        assert_eq!(lines.len(), 2);
        assert_eq!(text(&lines[0]), " RTX 4090 RISC Zero   RTX 4090 SP1");
        assert_eq!(text(&lines[1]), " Arc A770 RISC Zero");
    }

    #[test]
    fn workers_that_did_not_start_are_named_on_the_progress_screen() {
        use ratatui::{backend::TestBackend, Terminal};
        use zkminer_prover::dispatcher::{BenchmarkProgressEvent, BenchmarkProgressKind};
        let mut tracker = BenchmarkTracker::default();
        tracker.apply(&BenchmarkProgressEvent {
            slot_key: "sp1:cuda:0".to_string(),
            gpu_name: Some("NVIDIA GeForce RTX 5090".to_string()),
            device_index: Some(0),
            pci_bus_id: None,
            gpu_tag: "cuda".to_string(),
            kind: BenchmarkProgressKind::Started,
        });
        let mut state = MinerState::default();
        let problem = "RISC Zero could not start on RX 9060 XT: version mismatch".to_string();
        state.note_startup_problems(std::slice::from_ref(&problem));

        let mut term = Terminal::new(TestBackend::new(120, 34)).unwrap();
        term.draw(|f| render_progress_view(f, f.area(), &state, &tracker))
            .unwrap();
        let buffer = term.backend().buffer();
        let screen: String = buffer.content.iter().map(|cell| cell.symbol()).collect();

        assert!(screen.contains("Did not start"), "{screen}");
        assert!(screen.contains(&problem), "{screen}");
        assert_eq!(state.activity_log.back().unwrap().message, problem);
    }

    #[test]
    fn an_item_wider_than_the_panel_still_gets_its_own_line() {
        let lines = wrap_items(vec![Span::raw("a very long card name".to_string())], 5);

        assert_eq!(lines.len(), 1);
        assert_eq!(text(&lines[0]), " a very long card name");
    }

    #[test]
    fn the_progress_screen_names_the_card_and_zkvm_being_benchmarked() {
        use ratatui::{backend::TestBackend, Terminal};
        use zkminer_prover::dispatcher::{BenchmarkProgressEvent, BenchmarkProgressKind as Kind};

        const RTX: &str = "NVIDIA GeForce RTX 4090";
        const ARC: &str = "Intel(R) Arc(TM) A770 Graphics";
        let event = |slot_key: &str, name: &str, kind| BenchmarkProgressEvent {
            slot_key: slot_key.to_string(),
            gpu_name: Some(name.to_string()),
            device_index: Some(0),
            pci_bus_id: None,
            gpu_tag: slot_key.split(':').nth(1).unwrap().to_string(),
            kind,
        };

        let mut tracker = BenchmarkTracker::default();
        let queue = [
            ("risc0:cuda:0", RTX),
            ("sp1:cuda:0", RTX),
            ("risc0:intel:0", ARC),
            ("sp1:intel:0", ARC),
        ];
        for (key, name) in queue {
            tracker.apply(&event(key, name, Kind::Queued));
        }
        tracker.apply(&event("risc0:cuda:0", RTX, Kind::Started));
        tracker.apply(&event(
            "risc0:cuda:0",
            RTX,
            Kind::Finished { succeeded: true },
        ));
        tracker.apply(&event("sp1:cuda:0", RTX, Kind::Started));

        let state = MinerState::default();
        let draw = |tracker: &BenchmarkTracker| -> Vec<String> {
            let mut term = Terminal::new(TestBackend::new(120, 32)).unwrap();
            term.draw(|f| render_progress_view(f, f.area(), &state, tracker))
                .unwrap();
            let buffer = term.backend().buffer();
            buffer
                .content
                .chunks(buffer.area.width as usize)
                .map(|row| row.iter().map(|cell| cell.symbol()).collect())
                .collect()
        };

        let warming = draw(&tracker);
        assert!(
            warming[1].contains("Warming up RTX 4090 SP1"),
            "{}",
            warming[1]
        );
        assert!(!warming.join("\n").contains("fibonacci"));

        tracker.apply(&event("sp1:cuda:0", RTX, Kind::WarmedUp));
        let rows = draw(&tracker);
        println!("{}", rows.join("\n"));

        let screen = rows.join("\n");
        assert!(!screen.contains("Reference") && !screen.contains("Delta"));
        assert!(screen.contains("zkop-mix"), "the scoring program is listed");
        assert!(
            rows[1].contains("Benchmarking RTX 4090 SP1"),
            "{}",
            rows[1]
        );
        let tabs = &rows[4];
        for tab in [
            "RTX 4090 RISC Zero",
            "RTX 4090 SP1 [0/6]",
            "Arc A770 RISC Zero",
            "Arc A770 SP1",
        ] {
            assert!(tabs.contains(tab), "missing {tab}: {tabs}");
        }
    }
}
