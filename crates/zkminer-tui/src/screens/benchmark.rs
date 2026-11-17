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
use zkminer_prover::benchmark::{format_mzkops, gpu_zkops};
use zkminer_prover_protocol::BENCH_ZKOP_MIX;

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

    let Some(bench) = &state.benchmark_results else {
        let placeholder = Paragraph::new(vec![
            Line::from(Span::styled(
                if state.benchmark_running {
                    "Benchmark running..."
                } else {
                    "No benchmark results yet."
                },
                theme::placeholder(),
            )),
            Line::from(Span::styled(
                "Press 'b' to run benchmarks.",
                theme::placeholder(),
            )),
        ])
        .block(summary_block(state));
        f.render_widget(placeholder, area);
        return;
    };

    // One row per GPU, and the selected GPU's programs below: eight GPUs fit a 30-line terminal.
    // The programs panel gives up its lines first when the window is shorter.
    let ids = device_ids(state);
    let gpus = gpu_summaries(bench, &ids);
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),                     // Machine score and power
            Constraint::Length(gpus.len() as u16 + 3), // One row per GPU
            Constraint::Min(0),                        // The selected GPU's programs
        ])
        .split(area);

    render_summary(f, chunks[0], state, bench);
    render_gpu_table(f, chunks[1], state, bench, &gpus);
    render_gpu_programs(f, chunks[2], state, &gpus);
}

fn summary_block(state: &MinerState) -> Block<'static> {
    let title = if state.return_to_setup_after_benchmark && !state.startup_benchmark_pending {
        " Benchmark - press any key to continue to setup "
    } else {
        " Benchmark "
    };
    Block::default()
        .title(Span::styled(title, theme::title()))
        .borders(Borders::ALL)
        .border_style(theme::border())
        .border_type(theme::border_type())
}

/// The machine's score, the last run's power, and when it ran, on one line.
fn render_summary(
    f: &mut Frame,
    area: Rect,
    state: &MinerState,
    bench: &zkminer_prover::benchmark::BenchmarkSuite,
) {
    let mut spans = vec![Span::styled(
        format!(" Machine {} ", format_mzkops(bench.zkops)),
        theme::metric(),
    )];
    // Figures from the last benchmark run, not live: the CPU's average, and the sum of each card's
    // peak (the cards run one after another, so an average would count their idle time). Live
    // draw is on the dashboard.
    spans.push(Span::styled("  Draw while benchmarking: ", theme::dim()));
    if let Some(w) = bench.cpu_power_watts {
        spans.push(Span::styled(
            format!("CPU {w:.0}W average  "),
            theme::warning(),
        ));
    }
    match bench.gpu_power_watts {
        Some(w) => {
            spans.push(Span::styled(format!("GPU {w:.0}W peak"), theme::warning()));
            let total = w + bench.cpu_power_watts.unwrap_or(0.0);
            if total > 0.0 && bench.zkops > 0.0 {
                spans.push(Span::styled(
                    format!("  {:.1}K zkOP/W", bench.zkops / total / 1e3),
                    theme::dim(),
                ));
            }
        }
        None => spans.push(Span::styled("GPU not measured", theme::dim())),
    }
    spans.push(Span::styled(
        format!("   Last run {}", local_time(&bench.timestamp)),
        theme::dim(),
    ));
    f.render_widget(
        Paragraph::new(Line::from(spans)).block(summary_block(state)),
        area,
    );
}

/// An RFC 3339 timestamp as local "2026-11-12 12:41", or as it came if it does not parse.
fn local_time(timestamp: &str) -> String {
    chrono::DateTime::parse_from_rfc3339(timestamp)
        .map(|t| {
            t.with_timezone(&chrono::Local)
                .format("%Y-%m-%d %H:%M")
                .to_string()
        })
        .unwrap_or_else(|_| timestamp.to_string())
}

/// One GPU of the results: its rows for each zkVM.
struct GpuSummary<'a> {
    device_id: &'a str,
    name: String,
    sp1: Option<&'a zkminer_prover::benchmark::DeviceBenchmark>,
    risc0: Option<&'a zkminer_prover::benchmark::DeviceBenchmark>,
    rows: Vec<&'a zkminer_prover::benchmark::DeviceBenchmark>,
}

/// The GPUs in `ids`' order, each named by its model, numbered where two are the same model.
fn gpu_summaries<'a>(
    bench: &'a zkminer_prover::benchmark::BenchmarkSuite,
    ids: &'a [String],
) -> Vec<GpuSummary<'a>> {
    let model = |rows: &[&zkminer_prover::benchmark::DeviceBenchmark], id: &str| {
        rows.first().map_or(id.to_string(), |d| {
            // "GPU0 NVIDIA GeForce RTX 5090" -> "RTX 5090"
            let name = d
                .device_label
                .split_once(' ')
                .filter(|(first, _)| first.starts_with("GPU"))
                .map_or(d.device_label.as_str(), |(_, rest)| rest);
            crate::state::short_gpu_name(name)
        })
    };
    let mut gpus: Vec<GpuSummary> = ids
        .iter()
        .map(|id| {
            let rows: Vec<_> = bench
                .device_benchmarks
                .iter()
                .filter(|d| &d.device_id == id)
                .collect();
            let backend = |b: &str| rows.iter().copied().find(|d| d.prover_backend == b);
            GpuSummary {
                device_id: id,
                name: model(&rows, id),
                sp1: backend("sp1"),
                risc0: backend("risc0"),
                rows,
            }
        })
        .collect();
    let names: Vec<String> = gpus.iter().map(|g| g.name.clone()).collect();
    for gpu in &mut gpus {
        if names.iter().filter(|n| **n == gpu.name).count() > 1 {
            let ordinal: String = gpu
                .device_id
                .chars()
                .rev()
                .take_while(char::is_ascii_digit)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect();
            gpu.name = format!("{} #{ordinal}", gpu.name);
        }
    }
    gpus
}

/// One row per GPU: its score, each zkVM's score and job rate, its wraps and its peak power.
fn render_gpu_table(
    f: &mut Frame,
    area: Rect,
    state: &MinerState,
    bench: &zkminer_prover::benchmark::BenchmarkSuite,
    gpus: &[GpuSummary],
) {
    let dash = || "\u{2014}".to_string();
    let rate =
        |d: Option<&zkminer_prover::benchmark::DeviceBenchmark>,
         pick: fn(&zkminer_prover::benchmark::DeviceBenchmark) -> Option<f64>| {
            d.and_then(pick).map_or_else(dash, format_throughput)
        };
    let wrap = |d: Option<&zkminer_prover::benchmark::DeviceBenchmark>| {
        d.and_then(|d| d.wrap_secs())
            .map_or_else(dash, |s| format!("{s:.1}s"))
    };
    let header = Row::new([
        "GPU",
        "MzkOP/s",
        "SP1 score",
        "RISC Zero score",
        "SP1 job rate",
        "RISC Zero job rate",
        "Groth16 SP1/R0",
        "Peak W",
    ])
    .style(theme::table_header());
    let rows: Vec<Row> = gpus
        .iter()
        .enumerate()
        .map(|(i, gpu)| {
            let selected = i == state.benchmark_selected_device;
            let running = state.benchmark_device_in_progress.as_deref() == Some(gpu.device_id);
            let cursor = if selected { "> " } else { "  " };
            let running = if running { " [benchmarking...]" } else { "" };
            let name_style = if selected {
                Style::default()
                    .fg(theme::peach())
                    .add_modifier(Modifier::BOLD)
            } else {
                theme::bold()
            };
            // A row without a measurement holds the fallback, which is no reading.
            let peak = gpu
                .rows
                .iter()
                .map(|d| d.power_watts)
                .filter(|&w| w > 0.0 && w != zkminer_prover::benchmark::FALLBACK_GPU_WATTS)
                .fold(None, |max: Option<f64>, w| {
                    Some(max.map_or(w, |m| m.max(w)))
                });
            Row::new(vec![
                Cell::from(format!("{cursor}{}{running}", gpu.name)).style(name_style),
                Cell::from(
                    gpu_zkops(&bench.device_benchmarks, gpu.device_id)
                        .map_or_else(dash, |z| format!("{:.2}", z / 1e6)),
                )
                .style(theme::metric()),
                Cell::from(rate(gpu.sp1, |d| d.scoring_cycles_per_sec())),
                Cell::from(rate(gpu.risc0, |d| d.scoring_cycles_per_sec())),
                Cell::from(rate(gpu.sp1, |d| d.stark_rate())),
                Cell::from(rate(gpu.risc0, |d| d.stark_rate())),
                Cell::from(format!("{} / {}", wrap(gpu.sp1), wrap(gpu.risc0))),
                Cell::from(peak.map_or_else(dash, |w| format!("{w:.0}"))),
            ])
        })
        .collect();
    let table = Table::new(
        rows,
        [
            Constraint::Length(22),
            Constraint::Length(8),
            Constraint::Length(11),
            Constraint::Length(15),
            Constraint::Length(12),
            Constraint::Length(18),
            Constraint::Length(15),
            Constraint::Length(7),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .title(Span::styled(
                format!(" GPUs ({}) ", gpus.len()),
                theme::title(),
            ))
            .borders(Borders::ALL)
            .border_style(theme::border())
            .border_type(theme::border_type()),
    );
    f.render_widget(table, area);
}

/// The selected GPU's programs, SP1 and RISC Zero side by side, with the keys in the border.
fn render_gpu_programs(f: &mut Frame, area: Rect, state: &MinerState, gpus: &[GpuSummary]) {
    let selected = gpus.get(state.benchmark_selected_device);
    let mut title = vec![Span::styled(
        format!(
            " {}: programs   ",
            selected.map_or("No GPU", |g| g.name.as_str())
        ),
        theme::title(),
    )];
    title.extend(theme::keybind("[j/k]", " select GPU  "));
    title.extend(theme::keybind("[r]", " re-benchmark  "));
    title.extend(theme::keybind("[b]", " run all "));
    let block = Block::default()
        .title(Line::from(title))
        .borders(Borders::ALL)
        .border_style(theme::border())
        .border_type(theme::border_type());

    let Some(gpu) = selected else {
        f.render_widget(Paragraph::new("").block(block), area);
        return;
    };
    let stage = |d: Option<&'_ zkminer_prover::benchmark::DeviceBenchmark>, name: &str| {
        d.and_then(|d| {
            d.program_stages
                .iter()
                .find(|p| p.program_name == name && p.stark_secs > 0.0)
                .map(|p| (p.cycles, p.cycles as f64 / p.stark_secs))
        })
    };
    let cells = |s: Option<(u64, f64)>| match s {
        Some((cycles, rate)) => (format_cycles(cycles), format_throughput(rate)),
        None => ("\u{2014}".to_string(), "\u{2014}".to_string()),
    };
    let names = BENCHMARK_PROGRAMS
        .iter()
        .map(|p| p.name)
        .chain([BENCH_ZKOP_MIX]);
    let rows: Vec<Row> = names
        .enumerate()
        .map(|(i, name)| {
            let (sp1_cycles, sp1_rate) = cells(stage(gpu.sp1, name));
            let (r0_cycles, r0_rate) = cells(stage(gpu.risc0, name));
            Row::new(vec![
                Cell::from(name),
                Cell::from(weight_label(name)),
                Cell::from(sp1_cycles),
                Cell::from(sp1_rate),
                Cell::from(r0_cycles),
                Cell::from(r0_rate),
            ])
            .style(theme::striped(i))
        })
        .collect();
    let header = Row::new([
        "Program",
        "Weight",
        "SP1 cycles",
        "SP1 rate",
        "RISC Zero cycles",
        "RISC Zero rate",
    ])
    .style(theme::table_header());
    let table = Table::new(
        rows,
        [
            Constraint::Length(16),
            Constraint::Length(8),
            Constraint::Length(12),
            Constraint::Length(12),
            Constraint::Length(17),
            Constraint::Length(15),
        ],
    )
    .header(header)
    .block(block);
    f.render_widget(table, area);
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
        .map_or(0, |t| t.elapsed().as_secs() as i64);
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

    // A first run's setup can take many minutes: say what it is doing, in place of the bar.
    let setup = tracker
        .active_device()
        .and_then(|d| d.setup_status.as_deref());
    if let Some(status) = setup {
        let line = Line::from(vec![
            Span::styled(
                format!(" {spinner} {verb} {current}: "),
                Style::default()
                    .fg(theme::yellow())
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(status.to_string(), theme::metric()),
            Span::styled(format!("  {elapsed_str}"), theme::dim()),
        ]);
        let header = Paragraph::new(vec![line]).block(
            Block::default()
                .title(Span::styled(" Benchmark ", theme::title()))
                .borders(Borders::ALL)
                .border_style(theme::border_focused())
                .border_type(theme::border_type()),
        );
        f.render_widget(header, area);
        return;
    }

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

/// One entry per GPU, wrapped to `width`, with a marker per zkVM: \u{2713} done, \u{2717} failed,
/// \u{25B6} running (with its programs done so far), \u{00B7} waiting. Sixteen card-and-zkVM tabs
/// took several lines for eight GPUs; four GPUs fit a line.
fn device_tab_lines(tracker: &BenchmarkTracker, width: usize) -> Vec<Line<'static>> {
    let items = tracker
        .card_scores()
        .into_iter()
        .map(|card| {
            let mut text = card.name.clone();
            let mut running = false;
            for (i, dev) in tracker.devices.iter().enumerate() {
                if dev.gpu_tag != card.gpu_tag || dev.ordinal != card.ordinal {
                    continue;
                }
                let zkvm = match dev.slot_key.split(':').next() {
                    Some("risc0") => "R0",
                    Some("sp1") => "SP1",
                    _ => dev.backend_label(),
                };
                let marker = if dev.failed {
                    "\u{2717}".to_string()
                } else if dev.complete {
                    "\u{2713}".to_string()
                } else if i == tracker.active_device_index {
                    running = true;
                    if dev.warming_up {
                        "\u{25B6}warm-up".to_string()
                    } else {
                        let done = dev
                            .programs
                            .iter()
                            .filter(|p| p.phase == ProgramPhase::Done)
                            .count();
                        format!("\u{25B6}{done}/{}", dev.programs.len())
                    }
                } else {
                    "\u{00B7}".to_string()
                };
                text.push_str(&format!("  {zkvm} {marker}"));
            }
            let style = if running {
                Style::default()
                    .fg(theme::yellow())
                    .add_modifier(Modifier::BOLD)
            } else if card.failed {
                theme::error()
            } else if card.complete {
                Style::default().fg(theme::green())
            } else {
                theme::dim()
            };
            Span::styled(text, style)
        })
        .collect();
    wrap_items(items, width)
}

fn render_device_tabs(f: &mut Frame, area: Rect, lines: Vec<Line<'static>>) {
    let tabs = Paragraph::new(lines).block(
        Block::default()
            .title(Span::styled(" GPUs ", theme::title()))
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
                            let result = format_throughput(prog.throughput.unwrap_or(0.0));
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

    // Score panel: each GPU's blended score, once a zkVM on it has scored; ticked when every
    // zkVM on it has finished.
    let scores: Vec<Span> = tracker
        .card_scores()
        .into_iter()
        .filter_map(|card| match card.zkops {
            Some(score) => Some(Span::styled(
                format!(
                    "{} {}{}",
                    card.name,
                    format_mzkops(score),
                    if card.complete { " \u{2713}" } else { "" }
                ),
                Style::default().fg(theme::green()),
            )),
            None if card.failed => Some(Span::styled(
                format!("{} failed", card.name),
                theme::error(),
            )),
            None => None,
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
            .title(Span::styled(" Score per GPU ", theme::title()))
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

        // A first run's setup says what it is doing.
        let download = "Downloading SP1's Groth16 circuit (first run, about 8 GB)";
        tracker.refresh_setup_status(|_| Some(download.to_string()));
        let setup = draw(&tracker);
        assert!(setup[1].contains(download), "{}", setup[1]);
        assert!(setup[1].contains("Warming up RTX 4090 SP1"), "{}", setup[1]);

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
            "RTX 4090  R0 \u{2713}  SP1 \u{25B6}0/6",
            "Arc A770  R0 \u{00B7}  SP1 \u{00B7}",
        ] {
            assert!(tabs.contains(tab), "missing {tab}: {tabs}");
        }
    }

    /// Eight GPUs' results in a standard 120 x 30 terminal (28 lines below the tab and status
    /// bars): every GPU's row, and the selected one's programs.
    #[test]
    #[allow(clippy::field_reassign_with_default)] // two of MinerState's many fields
    fn eight_gpus_fit_a_standard_terminal() {
        use ratatui::{backend::TestBackend, Terminal};
        use zkminer_prover::benchmark::{BenchmarkSuite, DeviceBenchmark, ProgramStage};
        let row = |i: usize, backend: &str| DeviceBenchmark {
            program_stages: BENCHMARK_PROGRAMS
                .iter()
                .map(|p| p.name)
                .chain([BENCH_ZKOP_MIX])
                .map(|name| ProgramStage {
                    program_name: name.to_string(),
                    cycles: 50_000_000,
                    stark_secs: 5.0 + i as f64,
                    wrap_secs: Some(1.0),
                })
                .collect(),
            device_id: format!("gpu{i}"),
            device_label: format!("GPU{i} NVIDIA GeForce RTX 5090"),
            prover_backend: backend.to_string(),
            throughput: 1e7,
            power_watts: 600.0,
            optimal_po2: 24,
            memory_usage_bytes: 0,
            max_feasible_po2: 24,
            program_throughputs: Default::default(),
            pci_bus_id: format!("0000:0{i}:00.0"),
            po2_samples: Vec::new(),
            host_peak_bytes: None,
        };
        let mut state = MinerState::default();
        state.benchmark_selected_device = 7;
        state.benchmark_results = Some(BenchmarkSuite {
            device_benchmarks: (0..8)
                .flat_map(|i| [row(i, "sp1"), row(i, "risc0")])
                .collect(),
            zkops: 1e8,
            ..Default::default()
        });

        let mut term = Terminal::new(TestBackend::new(120, 28)).unwrap();
        term.draw(|f| render(f, f.area(), &state)).unwrap();
        let buffer = term.backend().buffer();
        let screen: String = buffer
            .content
            .chunks(buffer.area.width as usize)
            .map(|row| row.iter().map(|cell| cell.symbol()).collect::<String>() + "\n")
            .collect();
        println!("{screen}");
        for i in 0..8 {
            assert!(
                screen.contains(&format!("RTX 5090 #{i}")),
                "GPU {i} missing:\n{screen}"
            );
        }
        assert!(screen.contains("> RTX 5090 #7"), "{screen}");
        assert!(screen.contains("RTX 5090 #7: programs"), "{screen}");
        assert!(
            screen.contains("zkop-mix"),
            "the last program row fits:\n{screen}"
        );
        assert!(screen.contains("100.00 MzkOP/s"), "{screen}");
    }
}
