//! Settings screen — device toggles, backend toggles, 2D device×backend grid,
//! parameters, and advanced po2 overrides.

use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::Style,
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
    Frame,
};

use crate::gpu_tuning::{ClockCaps, ClockSetting, FanSetting, GpuTuningState, PerfLevel};
use crate::hardware::{fmt_bytes, GpuVendor};
use crate::state::{MinerState, SettingsSection};
use crate::theme;

// ---------------------------------------------------------------------------
// Public action type returned by settings handlers
// ---------------------------------------------------------------------------

/// Action returned from settings key handlers that requires async processing.
pub enum SettingsAction {
    None,
    /// Apply all pending tuning changes for a GPU.
    GpuTuningApply {
        device_id: String,
        tuning: GpuTuningState,
    },
    /// Reset a GPU's tuning to hardware defaults.
    GpuTuningReset { device_id: String },
    /// Re-run zkVM benchmarks on a GPU to measure tuning impact.
    GpuTuningBenchmark { device_id: String },
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const BACKENDS: &[(&str, &str)] = &[
    ("risc0", "RISC Zero"),
    ("sp1", "SP1"),
    ("openvm", "OpenVM"),
];

const STRATEGIES: &[&str] = &["conservative", "auto", "aggressive"];

/// Width allocated for each backend column in the grid.
const COL_WIDTH: usize = 14;

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

pub fn render(f: &mut Frame, area: Rect, state: &MinerState) {
    let ui = &state.settings_ui;

    let device_count = 1 + state.hardware.gpus.len();
    let backend_count = BACKENDS.len();
    let grid_device_count = enabled_device_count(state);
    let grid_backend_count = enabled_backend_count(state);
    let param_count = 8;
    let advanced_count = advanced_row_count(state);

    let dev_h = (device_count as u16 + 2).max(3);
    let bk_h = (backend_count as u16 + 2).max(3);
    // Grid: header row + enabled device rows + 2 border. Hide if nothing enabled.
    let grid_h = if grid_device_count > 0 && grid_backend_count > 0 {
        (grid_device_count as u16 + 3).max(4)
    } else {
        3 // just border + "no combos" message
    };
    let pm_h = (param_count as u16 + 2).max(3);
    let adv_h = (advanced_count as u16 + 2).max(3);
    let tuning_h = gpu_tuning_height(state);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(dev_h),
            Constraint::Length(bk_h),
            Constraint::Length(grid_h),
            Constraint::Length(pm_h),
            Constraint::Length(adv_h),
            Constraint::Length(tuning_h),
            Constraint::Length(1), // hint bar
            Constraint::Min(0),   // spacer
        ])
        .split(area);

    render_devices(f, chunks[0], state, ui.active_section == SettingsSection::Devices);
    render_backends(f, chunks[1], state, ui.active_section == SettingsSection::Backends);
    render_device_grid(f, chunks[2], state, ui.active_section == SettingsSection::DeviceGrid);
    render_parameters(f, chunks[3], state, ui.active_section == SettingsSection::Parameters);
    render_advanced(f, chunks[4], state, ui.active_section == SettingsSection::Advanced);
    render_gpu_tuning(f, chunks[5], state, ui.active_section == SettingsSection::GpuTuning);

    // Hint bar
    let hints = Line::from(vec![
        Span::styled("  [", theme::dim()),
        Span::styled("Tab", Style::default().fg(theme::peach())),
        Span::styled("] Section   [", theme::dim()),
        Span::styled("j/k", Style::default().fg(theme::peach())),
        Span::styled("] Row   [", theme::dim()),
        Span::styled("h/l", Style::default().fg(theme::peach())),
        Span::styled("] Column/Adjust   [", theme::dim()),
        Span::styled("Space", Style::default().fg(theme::peach())),
        Span::styled("] Toggle", theme::dim()),
    ]);
    f.render_widget(Paragraph::new(hints), chunks[6]);
}

// ---------------------------------------------------------------------------
// Section 1: Devices (whole-device enable/disable)
// ---------------------------------------------------------------------------

fn render_devices(f: &mut Frame, area: Rect, state: &MinerState, focused: bool) {
    let ui = &state.settings_ui;
    let rs = &state.runtime_settings;
    let mut lines: Vec<Line> = Vec::new();

    // CPU row
    let cpu_enabled = !rs.disabled_devices.contains("cpu");
    let sel = focused && ui.active_section == SettingsSection::Devices && ui.row_index == 0;
    lines.push(toggle_line(
        sel,
        cpu_enabled,
        &format!("CPU    {}", state.hardware.cpu.model),
        cpu_vendor_color(&state.hardware.cpu.model),
    ));

    // GPU rows
    for (i, gpu) in state.hardware.gpus.iter().enumerate() {
        let device_id = format!("gpu{}", gpu.index);
        let enabled = !rs.disabled_devices.contains(&device_id);
        let sel = focused
            && ui.active_section == SettingsSection::Devices
            && ui.row_index == i + 1;
        let vram = fmt_bytes(gpu.vram_total_bytes);
        let label = format!("GPU{}   {:<24} {}", gpu.index, gpu.name, vram);
        let color = match gpu.vendor {
            GpuVendor::Amd => theme::amd_red(),
            GpuVendor::Nvidia => theme::nvidia_green(),
            GpuVendor::Intel => theme::intel_blue(),
            GpuVendor::Unknown => theme::text(),
        };
        lines.push(toggle_line(sel, enabled, &label, color));
    }

    let border = if focused { theme::border_focused() } else { theme::border() };
    let block = Block::default()
        .title(Span::styled(" Devices ", theme::title()))
        .borders(Borders::ALL)
        .border_style(border)
        .border_type(theme::border_type());

    f.render_widget(Paragraph::new(lines).block(block), area);
}

// ---------------------------------------------------------------------------
// Section 2: Proof Systems (whole-backend enable/disable)
// ---------------------------------------------------------------------------

fn render_backends(f: &mut Frame, area: Rect, state: &MinerState, focused: bool) {
    let ui = &state.settings_ui;
    let rs = &state.runtime_settings;
    let mut lines: Vec<Line> = Vec::new();

    for (i, (key, display)) in BACKENDS.iter().enumerate() {
        let enabled = !rs.disabled_backends.contains(*key);
        let sel = focused && ui.active_section == SettingsSection::Backends && ui.row_index == i;
        lines.push(toggle_line(sel, enabled, display, backend_color(key)));
    }

    let border = if focused { theme::border_focused() } else { theme::border() };
    let block = Block::default()
        .title(Span::styled(" Proof Systems ", theme::title()))
        .borders(Borders::ALL)
        .border_style(border)
        .border_type(theme::border_type());

    f.render_widget(Paragraph::new(lines).block(block), area);
}

// ---------------------------------------------------------------------------
// Section 3: Device × Backend grid (per-combo overrides)
// ---------------------------------------------------------------------------

fn render_device_grid(f: &mut Frame, area: Rect, state: &MinerState, focused: bool) {
    let ui = &state.settings_ui;
    let rs = &state.runtime_settings;

    let enabled_devs = enabled_devices(state);
    let enabled_bks = enabled_backends(state);

    let border = if focused { theme::border_focused() } else { theme::border() };
    let block = Block::default()
        .title(Span::styled(" Per-Device Proof Systems ", theme::title()))
        .borders(Borders::ALL)
        .border_style(border)
        .border_type(theme::border_type());

    if enabled_devs.is_empty() || enabled_bks.is_empty() {
        let msg = if enabled_devs.is_empty() {
            "No devices enabled"
        } else {
            "No proof systems enabled"
        };
        let paragraph = Paragraph::new(Span::styled(msg, theme::placeholder())).block(block);
        f.render_widget(paragraph, area);
        return;
    }

    let mut lines: Vec<Line> = Vec::new();

    // Header row
    let device_col_w = 30;
    let mut header_spans: Vec<Span> = vec![
        Span::styled(
            format!("{:<width$}", "", width = device_col_w + 2),
            Style::default(),
        ),
    ];
    for bk in &enabled_bks {
        let color = backend_color(bk.0);
        header_spans.push(Span::styled(
            format!("{:<width$}", bk.1, width = COL_WIDTH),
            Style::default()
                .fg(color)
                .add_modifier(ratatui::style::Modifier::BOLD),
        ));
    }
    lines.push(Line::from(header_spans));

    // Device rows
    for (row, dev) in enabled_devs.iter().enumerate() {
        let sel_row = focused
            && ui.active_section == SettingsSection::DeviceGrid
            && ui.row_index == row;

        let cursor = if sel_row { "> " } else { "  " };
        let mut spans: Vec<Span> = vec![
            Span::styled(
                cursor.to_string(),
                if sel_row {
                    Style::default().fg(theme::peach())
                } else {
                    Style::default()
                },
            ),
            Span::styled(
                format!("{:<width$}", dev.label, width = device_col_w),
                Style::default().fg(dev.color),
            ),
        ];

        // Backend columns
        for (col, bk) in enabled_bks.iter().enumerate() {
            let pair = (dev.id.clone(), bk.0.to_string());
            let enabled = !rs.disabled_device_backends.contains(&pair);
            let sel_cell = sel_row && ui.col_index == col;

            let check = if enabled { "[✓]" } else { "[ ]" };
            let check_style = if sel_cell {
                if enabled {
                    Style::default()
                        .fg(theme::green())
                        .bg(theme::overlay())
                        .add_modifier(ratatui::style::Modifier::BOLD)
                } else {
                    theme::dim().bg(theme::overlay())
                }
            } else if enabled {
                Style::default().fg(theme::green())
            } else {
                theme::dim()
            };

            spans.push(Span::styled(
                format!("{:<width$}", check, width = COL_WIDTH),
                check_style,
            ));
        }

        if sel_row {
            for span in spans.iter_mut().take(2) {
                span.style = span.style.bg(theme::overlay());
            }
        }

        lines.push(Line::from(spans));
    }

    f.render_widget(Paragraph::new(lines).block(block), area);
}

// ---------------------------------------------------------------------------
// Section 4: Parameters
// ---------------------------------------------------------------------------

fn render_parameters(f: &mut Frame, area: Rect, state: &MinerState, focused: bool) {
    let ui = &state.settings_ui;
    let rs = &state.runtime_settings;

    let params: Vec<(&str, String)> = vec![
        (
            "Max Concurrent Proofs",
            format!("{}", rs.max_concurrent_proofs),
        ),
        (
            "Min Profit Rate",
            format!("{:.1} HEMI/day", rs.min_profit_threshold),
        ),
        ("Strategy", rs.strategy.clone()),
        (
            "Electricity Cost",
            format!("${:.2}/kWh", rs.electricity_cost_kwh),
        ),
        ("System Overhead", format!("{:.0}W", rs.system_power_watts)),
        (
            "Deadline Safety",
            format!("{:.1}\u{00d7}", rs.deadline_safety_margin),
        ),
        (
            "Token Price",
            format!("${:.2}", rs.token_price_usd),
        ),
        (
            "Gas Cost",
            format!("${:.3}", rs.gas_cost_usd),
        ),
    ];

    let mut lines: Vec<Line> = Vec::new();
    for (i, (label, value)) in params.iter().enumerate() {
        let sel =
            focused && ui.active_section == SettingsSection::Parameters && ui.row_index == i;
        lines.push(spinner_line(sel, label, value));
    }

    let border = if focused {
        theme::border_focused()
    } else {
        theme::border()
    };
    let block = Block::default()
        .title(Span::styled(" Parameters ", theme::title()))
        .borders(Borders::ALL)
        .border_style(border)
        .border_type(theme::border_type());

    f.render_widget(Paragraph::new(lines).block(block), area);
}

// ---------------------------------------------------------------------------
// Section 5: Advanced (po2 overrides)
// ---------------------------------------------------------------------------

fn render_advanced(f: &mut Frame, area: Rect, state: &MinerState, focused: bool) {
    let ui = &state.settings_ui;
    let rs = &state.runtime_settings;
    let mut lines: Vec<Line> = Vec::new();

    // Row 0: Advanced Mode toggle
    {
        let sel =
            focused && ui.active_section == SettingsSection::Advanced && ui.row_index == 0;
        let check = if rs.advanced_mode { "[✓] " } else { "[ ] " };
        let cursor = if sel { "> " } else { "  " };

        let mut spans = vec![
            Span::styled(
                cursor.to_string(),
                if sel {
                    Style::default().fg(theme::peach())
                } else {
                    Style::default()
                },
            ),
            Span::styled(
                check.to_string(),
                if rs.advanced_mode {
                    Style::default().fg(theme::green())
                } else {
                    theme::dim()
                },
            ),
            Span::styled("Advanced Mode".to_string(), theme::bold()),
        ];

        if sel {
            for span in &mut spans {
                span.style = span.style.bg(theme::overlay());
            }
        }
        lines.push(Line::from(spans));
    }

    if !rs.advanced_mode {
        lines.push(Line::from(Span::styled(
            "  Enable to configure continuation sizes (po2) per device/backend",
            theme::dim(),
        )));
    } else {
        let pairs = fully_enabled_pairs(state);
        for (i, (dev, bk)) in pairs.iter().enumerate() {
            let row_idx = i + 1;
            let sel = focused
                && ui.active_section == SettingsSection::Advanced
                && ui.row_index == row_idx;

            let current_po2 = rs
                .po2_overrides
                .get(&(dev.clone(), bk.clone()))
                .copied()
                .unwrap_or_else(|| optimal_po2_for(state, dev, bk));

            let optimal = optimal_po2_for(state, dev, bk);

            let dev_label = format!("{:<5}", dev.to_uppercase());
            let bk_label = format!("{:<10}", bk);
            let cursor = if sel { "> " } else { "  " };

            let mut spans = vec![
                Span::styled(
                    cursor.to_string(),
                    if sel {
                        Style::default().fg(theme::peach())
                    } else {
                        Style::default()
                    },
                ),
                Span::styled(dev_label, theme::bold()),
                Span::styled("/ ".to_string(), theme::dim()),
                Span::styled(bk_label, theme::accent()),
                Span::styled("po2: ".to_string(), theme::dim()),
                Span::styled(
                    "\u{25c2} ".to_string(),
                    Style::default().fg(theme::peach()),
                ),
                Span::styled(format!("{}", current_po2), theme::metric()),
                Span::styled(
                    " \u{25b8}".to_string(),
                    Style::default().fg(theme::peach()),
                ),
                Span::styled(format!("   (optimal: {})", optimal), theme::dim()),
            ];

            if sel {
                for span in &mut spans {
                    span.style = span.style.bg(theme::overlay());
                }
            }

            lines.push(Line::from(spans));
        }
    }

    let border = if focused {
        theme::border_focused()
    } else {
        theme::border()
    };
    let block = Block::default()
        .title(Span::styled(" Advanced ", theme::title()))
        .borders(Borders::ALL)
        .border_style(border)
        .border_type(theme::border_type());

    f.render_widget(Paragraph::new(lines).block(block), area);
}

// ---------------------------------------------------------------------------
// Section 6: GPU Tuning
// ---------------------------------------------------------------------------

/// Calculate the height needed for the GPU Tuning section.
fn gpu_tuning_height(state: &MinerState) -> u16 {
    if state.gpu_tuning.is_empty() {
        return 3; // border + "No GPUs" message
    }
    let ui = &state.settings_ui;
    let idx = ui.tuning_gpu_index.min(state.gpu_tuning.len().saturating_sub(1));
    let controls = state
        .gpu_tuning
        .get(idx)
        .map(tuning_control_count)
        .unwrap_or(0);

    // 2 (border) + 1 (GPU selector) + controls + 1 (button row, if controls > 0)
    let button_row = if controls > 0 { 1 } else { 0 };
    (3 + controls as u16 + button_row as u16).max(3)
}

/// How many control rows exist for a given GPU's tuning state.
fn tuning_control_count(ts: &GpuTuningState) -> usize {
    let mut count = 0;
    if ts.caps.power.is_some() {
        count += 1;
    }
    if ts.caps.perf_profile.is_some() {
        count += 1;
    }
    if ts.caps.core_clock.is_some() {
        count += 1;
    }
    if ts.caps.mem_clock.is_some() {
        count += 1;
    }
    if ts.caps.fan.is_some() {
        count += 1;
    }
    count
}

/// Whether the selected GPU has a button row (only when controls exist).
fn has_tuning_buttons(state: &MinerState) -> bool {
    let idx = state
        .settings_ui
        .tuning_gpu_index
        .min(state.gpu_tuning.len().saturating_sub(1));
    state
        .gpu_tuning
        .get(idx)
        .map(|ts| tuning_control_count(ts) > 0)
        .unwrap_or(false)
}

/// The row index of the button row for the selected GPU.
fn tuning_button_row(state: &MinerState) -> usize {
    let idx = state
        .settings_ui
        .tuning_gpu_index
        .min(state.gpu_tuning.len().saturating_sub(1));
    let controls = state
        .gpu_tuning
        .get(idx)
        .map(tuning_control_count)
        .unwrap_or(0);
    // GPU selector (row 0) + controls + button row
    1 + controls
}

fn render_gpu_tuning(f: &mut Frame, area: Rect, state: &MinerState, focused: bool) {
    let ui = &state.settings_ui;

    if state.gpu_tuning.is_empty() {
        let border = if focused {
            theme::border_focused()
        } else {
            theme::border()
        };
        let block = Block::default()
            .title(Span::styled(" GPU Tuning ", theme::title()))
            .borders(Borders::ALL)
            .border_style(border)
            .border_type(theme::border_type());
        let msg = if state.hardware.gpus.is_empty() {
            "No GPUs detected"
        } else {
            "GPU tuning not available"
        };
        let paragraph = Paragraph::new(Span::styled(msg, theme::placeholder())).block(block);
        f.render_widget(paragraph, area);
        return;
    }

    let gpu_idx = ui.tuning_gpu_index.min(state.gpu_tuning.len() - 1);

    // Build section title with selected GPU name
    let title = if let Some(ts) = state.gpu_tuning.get(gpu_idx) {
        let gpu = state
            .hardware
            .gpus
            .iter()
            .find(|g| format!("gpu{}", g.index) == ts.caps.device_id);
        let name = gpu
            .map(|g| g.name.as_str())
            .unwrap_or(&ts.caps.device_id);
        let dirty_mark = if ts.dirty { " *" } else { "" };
        format!(" GPU Tuning \u{2014} GPU{}: {}{} ", gpu_idx, name, dirty_mark)
    } else {
        " GPU Tuning ".to_string()
    };

    let border = if focused {
        theme::border_focused()
    } else {
        theme::border()
    };
    let block = Block::default()
        .title(Span::styled(title, theme::title()))
        .borders(Borders::ALL)
        .border_style(border)
        .border_type(theme::border_type());

    let mut lines: Vec<Line> = Vec::new();

    // Row 0: GPU selector tabs
    {
        let on_selector = focused && ui.tuning_row_index == 0;
        let mut spans: Vec<Span> = Vec::new();
        let cursor = if on_selector { "> " } else { "  " };
        spans.push(Span::styled(
            cursor.to_string(),
            if on_selector {
                Style::default().fg(theme::peach())
            } else {
                Style::default()
            },
        ));

        for (i, ts) in state.gpu_tuning.iter().enumerate() {
            let gpu = state
                .hardware
                .gpus
                .iter()
                .find(|g| format!("gpu{}", g.index) == ts.caps.device_id);
            let name = gpu
                .map(|g| g.name.clone())
                .unwrap_or_else(|| ts.caps.device_id.clone());
            let dirty_mark = if ts.dirty { "*" } else { "" };
            let is_selected = i == gpu_idx;
            let color = match ts.caps.vendor {
                GpuVendor::Amd => theme::amd_red(),
                GpuVendor::Nvidia => theme::nvidia_green(),
                GpuVendor::Intel => theme::intel_blue(),
                GpuVendor::Unknown => theme::text(),
            };

            if is_selected {
                // Selected GPU: [ GPU0: Name ]  with color+bold
                spans.push(Span::styled(
                    "[".to_string(),
                    Style::default().fg(color),
                ));
                spans.push(Span::styled(
                    format!("GPU{}: {}{}", i, name, dirty_mark),
                    Style::default()
                        .fg(color)
                        .add_modifier(ratatui::style::Modifier::BOLD),
                ));
                spans.push(Span::styled(
                    "]".to_string(),
                    Style::default().fg(color),
                ));
            } else {
                // Non-selected GPU: dim
                spans.push(Span::styled(
                    format!(" GPU{}: {}{} ", i, name, dirty_mark),
                    theme::dim(),
                ));
            }

            if i < state.gpu_tuning.len() - 1 {
                spans.push(Span::styled("  ", Style::default()));
            }
        }

        // Show h/l hint when on selector with multiple GPUs
        if on_selector && state.gpu_tuning.len() > 1 {
            spans.push(Span::styled("    ", Style::default()));
            spans.push(Span::styled(
                "\u{25c2} h/l \u{25b8}",
                Style::default().fg(theme::peach()),
            ));
        }

        if on_selector {
            for span in &mut spans {
                span.style = span.style.bg(theme::overlay());
            }
        }
        lines.push(Line::from(spans));
    }

    // Control rows for selected GPU
    if let Some(ts) = state.gpu_tuning.get(gpu_idx) {
        let mut control_row = 1usize;

        // Power limit
        if let Some(ref power) = ts.caps.power {
            let sel = focused && ui.tuning_row_index == control_row;
            let current = ts.power_limit_watts.unwrap_or(power.default_watts);
            let value = format!("{:.0}W", current);
            let hint = format!(
                "   ({:.0}\u{2013}{:.0}W, default: {:.0}W)",
                power.min_watts, power.max_watts, power.default_watts
            );
            lines.push(tuning_spinner_line(sel, "Power Limit", &value, &hint));
            control_row += 1;
        }

        // Performance level (AMD only)
        if ts.caps.perf_profile.is_some() {
            let sel = focused && ui.tuning_row_index == control_row;
            let current = ts.perf_level.unwrap_or(PerfLevel::Auto);
            let value = current.to_string();
            let hint = "   (auto/low/high/manual)";
            lines.push(tuning_spinner_line(sel, "Performance Level", &value, hint));
            control_row += 1;
        }

        // Core clock
        if let Some(ref clock) = ts.caps.core_clock {
            let sel = focused && ui.tuning_row_index == control_row;
            let (value, hint) = format_clock_value("Core Clock", clock, &ts.core_clock);
            lines.push(tuning_spinner_line(sel, &value.0, &value.1, &hint));
            control_row += 1;
        }

        // Memory clock
        if let Some(ref clock) = ts.caps.mem_clock {
            let sel = focused && ui.tuning_row_index == control_row;
            let (value, hint) = format_clock_value("Mem Clock", clock, &ts.mem_clock);
            lines.push(tuning_spinner_line(sel, &value.0, &value.1, &hint));
            control_row += 1;
        }

        // Fan speed
        if let Some(ref fan) = ts.caps.fan {
            let sel = focused && ui.tuning_row_index == control_row;
            let (value, hint) = match &ts.fan_speed {
                FanSetting::Auto => (
                    "Auto".to_string(),
                    format!("   ({}–{}%, auto)", fan.min_percent, fan.max_percent),
                ),
                FanSetting::Fixed(pct) => (
                    format!("{}%", pct),
                    format!("   ({}–{}%)", fan.min_percent, fan.max_percent),
                ),
            };
            lines.push(tuning_spinner_line(sel, "Fan Speed", &value, &hint));
            control_row += 1;
        }

        // Button row (Apply / Reset / Benchmark)
        if tuning_control_count(ts) > 0 {
            let on_buttons = focused && ui.tuning_row_index == control_row;
            let btn_idx = ui.tuning_button_idx;
            let dirty = ts.dirty;
            let benchmarking = state
                .benchmark_device_in_progress
                .as_deref()
                == Some(&ts.caps.device_id);

            let mut spans: Vec<Span> = Vec::new();
            let cursor = if on_buttons { "> " } else { "  " };
            spans.push(Span::styled(
                cursor.to_string(),
                if on_buttons {
                    Style::default().fg(theme::peach())
                } else {
                    Style::default()
                },
            ));

            spans.push(Span::styled("    ", Style::default()));

            // Apply button
            let apply_focused = on_buttons && btn_idx == 0;
            let apply_style = if apply_focused {
                if dirty {
                    Style::default()
                        .fg(theme::green())
                        .bg(theme::overlay())
                        .add_modifier(ratatui::style::Modifier::BOLD)
                } else {
                    theme::dim().bg(theme::overlay())
                }
            } else if dirty {
                Style::default().fg(theme::green())
            } else {
                theme::dim()
            };
            spans.push(Span::styled("[ Apply ]", apply_style));

            spans.push(Span::styled("  ", Style::default()));

            // Reset button
            let reset_focused = on_buttons && btn_idx == 1;
            let reset_style = if reset_focused {
                Style::default()
                    .fg(theme::peach())
                    .bg(theme::overlay())
                    .add_modifier(ratatui::style::Modifier::BOLD)
            } else {
                theme::dim()
            };
            spans.push(Span::styled("[ Reset ]", reset_style));

            spans.push(Span::styled("  ", Style::default()));

            // Benchmark button
            let bench_focused = on_buttons && btn_idx == 2;
            let bench_style = if benchmarking {
                Style::default()
                    .fg(theme::yellow())
                    .add_modifier(ratatui::style::Modifier::BOLD)
            } else if bench_focused {
                Style::default()
                    .fg(theme::lavender())
                    .bg(theme::overlay())
                    .add_modifier(ratatui::style::Modifier::BOLD)
            } else {
                theme::dim()
            };
            let bench_label = if benchmarking {
                "[ Benchmarking... ]"
            } else {
                "[ Benchmark ]"
            };
            spans.push(Span::styled(bench_label, bench_style));

            // Dirty indicator
            if dirty {
                spans.push(Span::styled(
                    "  * modified",
                    Style::default().fg(theme::yellow()),
                ));
            }

            lines.push(Line::from(spans));
            let _ = control_row;
        }

        // Benchmark result line (throughput delta after tuning re-benchmark)
        if let Some((ref dev, before, after)) = state.gpu_tuning_bench_result {
            if *dev == ts.caps.device_id {
                let pct = if before > 0.0 {
                    (after - before) / before * 100.0
                } else {
                    0.0
                };
                let delta_str = if pct >= 0.0 {
                    format!("+{pct:.1}%")
                } else {
                    format!("{pct:.1}%")
                };
                let delta_color = if pct > 1.0 {
                    theme::green()
                } else if pct < -1.0 {
                    theme::red()
                } else {
                    theme::subtext()
                };

                let format_tp = |v: f64| -> String {
                    if v >= 1_000_000.0 {
                        format!("{:.1}M c/s", v / 1_000_000.0)
                    } else if v >= 1_000.0 {
                        format!("{:.1}K c/s", v / 1_000.0)
                    } else {
                        format!("{v:.0} c/s")
                    }
                };

                lines.push(Line::from(vec![
                    Span::styled("      Throughput: ", theme::dim()),
                    Span::styled(
                        format_tp(after),
                        Style::default()
                            .fg(theme::peach())
                            .add_modifier(ratatui::style::Modifier::BOLD),
                    ),
                    Span::styled("  (was ", theme::dim()),
                    Span::styled(format_tp(before), theme::dim()),
                    Span::styled(", ", theme::dim()),
                    Span::styled(delta_str, Style::default().fg(delta_color).add_modifier(ratatui::style::Modifier::BOLD)),
                    Span::styled(")", theme::dim()),
                ]));
            }
        }
    }

    f.render_widget(Paragraph::new(lines).block(block), area);
}

/// Format a clock value for display.
/// Returns ((label, value_string), hint_string).
fn format_clock_value(
    base_label: &str,
    caps: &ClockCaps,
    setting: &ClockSetting,
) -> ((String, String), String) {
    match caps {
        ClockCaps::DpmLevels(levels) => {
            let label = format!("{} (DPM)", base_label);
            let (value, hint) = match setting {
                ClockSetting::Default => {
                    let active = levels.iter().find(|l| l.active);
                    let val = active
                        .map(|l| format!("Level {}: {}MHz", l.index, l.freq_mhz))
                        .unwrap_or_else(|| "auto".to_string());
                    let max_idx = levels.last().map(|l| l.index).unwrap_or(0);
                    let hint = format!("   (0\u{2013}{}, auto)", max_idx);
                    (val, hint)
                }
                ClockSetting::DpmLevel(idx) => {
                    let level = levels.iter().find(|l| l.index == *idx);
                    let freq = level.map(|l| l.freq_mhz).unwrap_or(0);
                    let val = format!("Level {}: {}MHz", idx, freq);
                    let max_idx = levels.last().map(|l| l.index).unwrap_or(0);
                    let hint = format!("   (0\u{2013}{})", max_idx);
                    (val, hint)
                }
                _ => ("N/A".to_string(), String::new()),
            };
            ((label, value), hint)
        }
        ClockCaps::Range {
            min_mhz,
            max_mhz,
            default_mhz,
        } => {
            let label = base_label.to_string();
            let (value, hint) = match setting {
                ClockSetting::Default => {
                    let val = format!("{} MHz", default_mhz);
                    let hint = format!(
                        "   ({}\u{2013}{} MHz, default: {})",
                        min_mhz, max_mhz, default_mhz
                    );
                    (val, hint)
                }
                ClockSetting::Fixed(mhz) => {
                    let val = format!("{} MHz", mhz);
                    let hint = format!("   ({}\u{2013}{} MHz)", min_mhz, max_mhz);
                    (val, hint)
                }
                _ => ("N/A".to_string(), String::new()),
            };
            ((label, value), hint)
        }
        ClockCaps::Offset {
            min_offset_mhz,
            max_offset_mhz,
        } => {
            let is_mem = base_label.starts_with("Mem");
            let label = format!("{} Offset", base_label);
            let (value, hint) = match setting {
                ClockSetting::Offset(off) if *off != 0 => {
                    let (disp_off, disp_min, disp_max) = if is_mem {
                        (off / 2, min_offset_mhz / 2, max_offset_mhz / 2)
                    } else {
                        (*off, *min_offset_mhz, *max_offset_mhz)
                    };
                    let val = format!("{:+} MHz", disp_off);
                    let hint = format!("   ({:+}\u{2013}{:+} MHz)", disp_min, disp_max);
                    (val, hint)
                }
                _ => {
                    // Default or Offset(0)
                    let (disp_min, disp_max) = if is_mem {
                        (min_offset_mhz / 2, max_offset_mhz / 2)
                    } else {
                        (*min_offset_mhz, *max_offset_mhz)
                    };
                    let val = "+0 MHz".to_string();
                    let hint = format!("   ({:+}\u{2013}{:+} MHz)", disp_min, disp_max);
                    (val, hint)
                }
            };
            ((label, value), hint)
        }
    }
}

fn tuning_spinner_line<'a>(
    selected: bool,
    label: &str,
    value: &str,
    hint: &str,
) -> Line<'a> {
    let cursor = if selected { "> " } else { "  " };

    let mut spans = vec![
        Span::styled(
            cursor.to_string(),
            if selected {
                Style::default().fg(theme::peach())
            } else {
                Style::default()
            },
        ),
        Span::styled(format!("{:<24}", label), theme::dim()),
        Span::styled(
            "\u{25c2} ".to_string(),
            Style::default().fg(theme::peach()),
        ),
        Span::styled(value.to_string(), theme::metric()),
        Span::styled(
            " \u{25b8}".to_string(),
            Style::default().fg(theme::peach()),
        ),
        Span::styled(hint.to_string(), theme::dim()),
    ];

    if selected {
        for span in &mut spans {
            span.style = span.style.bg(theme::overlay());
        }
    }

    Line::from(spans)
}

// ---------------------------------------------------------------------------
// Shared rendering helpers
// ---------------------------------------------------------------------------

fn toggle_line<'a>(
    selected: bool,
    enabled: bool,
    label: &str,
    color: ratatui::style::Color,
) -> Line<'a> {
    let cursor = if selected { "> " } else { "  " };
    let check = if enabled { "[✓] " } else { "[ ] " };
    let label_style = if enabled {
        Style::default().fg(color)
    } else {
        theme::dim()
    };

    let mut spans = vec![
        Span::styled(
            cursor.to_string(),
            if selected {
                Style::default().fg(theme::peach())
            } else {
                Style::default()
            },
        ),
        Span::styled(
            check.to_string(),
            if enabled {
                Style::default().fg(theme::green())
            } else {
                theme::dim()
            },
        ),
        Span::styled(label.to_string(), label_style),
    ];

    if selected {
        for span in &mut spans {
            span.style = span.style.bg(theme::overlay());
        }
    }

    Line::from(spans)
}

fn spinner_line<'a>(selected: bool, label: &str, value: &str) -> Line<'a> {
    let cursor = if selected { "> " } else { "  " };

    let mut spans = vec![
        Span::styled(
            cursor.to_string(),
            if selected {
                Style::default().fg(theme::peach())
            } else {
                Style::default()
            },
        ),
        Span::styled(format!("{:<28}", label), theme::dim()),
        Span::styled(
            "\u{25c2} ".to_string(),
            Style::default().fg(theme::peach()),
        ),
        Span::styled(value.to_string(), theme::metric()),
        Span::styled(
            " \u{25b8}".to_string(),
            Style::default().fg(theme::peach()),
        ),
    ];

    if selected {
        for span in &mut spans {
            span.style = span.style.bg(theme::overlay());
        }
    }

    Line::from(spans)
}

// ---------------------------------------------------------------------------
// Data helpers
// ---------------------------------------------------------------------------

struct DeviceEntry {
    id: String,
    label: String,
    color: ratatui::style::Color,
}

/// All devices (used for the grid and advanced sections — short labels without VRAM).
fn all_devices(state: &MinerState) -> Vec<DeviceEntry> {
    let mut devices = Vec::new();
    devices.push(DeviceEntry {
        id: "cpu".to_string(),
        label: format!("CPU  {}", state.hardware.cpu.model),
        color: cpu_vendor_color(&state.hardware.cpu.model),
    });
    for gpu in &state.hardware.gpus {
        let color = match gpu.vendor {
            GpuVendor::Amd => theme::amd_red(),
            GpuVendor::Nvidia => theme::nvidia_green(),
            GpuVendor::Intel => theme::intel_blue(),
            GpuVendor::Unknown => theme::text(),
        };
        devices.push(DeviceEntry {
            id: format!("gpu{}", gpu.index),
            label: format!("GPU{}  {}", gpu.index, gpu.name),
            color,
        });
    }
    devices
}

/// Devices not globally disabled (for the grid rows).
fn enabled_devices(state: &MinerState) -> Vec<DeviceEntry> {
    let rs = &state.runtime_settings;
    all_devices(state)
        .into_iter()
        .filter(|d| !rs.disabled_devices.contains(&d.id))
        .collect()
}

fn enabled_device_count(state: &MinerState) -> usize {
    let rs = &state.runtime_settings;
    let total = 1 + state.hardware.gpus.len();
    let disabled = rs.disabled_devices.len();
    total.saturating_sub(disabled)
}

/// Backend keys+display names not globally disabled (for the grid columns).
fn enabled_backends(state: &MinerState) -> Vec<(&'static str, &'static str)> {
    let rs = &state.runtime_settings;
    BACKENDS
        .iter()
        .filter(|(key, _)| !rs.disabled_backends.contains(*key))
        .copied()
        .collect()
}

fn enabled_backend_count(state: &MinerState) -> usize {
    let rs = &state.runtime_settings;
    BACKENDS
        .iter()
        .filter(|(key, _)| !rs.disabled_backends.contains(*key))
        .count()
}

/// All device IDs.
fn device_ids(state: &MinerState) -> Vec<String> {
    let mut ids = vec!["cpu".to_string()];
    for gpu in &state.hardware.gpus {
        ids.push(format!("gpu{}", gpu.index));
    }
    ids
}

/// (device, backend) pairs that are fully enabled at all three levels:
/// device enabled, backend enabled, and per-combo not disabled.
/// Used for the Advanced po2 section.
fn fully_enabled_pairs(state: &MinerState) -> Vec<(String, String)> {
    let rs = &state.runtime_settings;
    let mut pairs = Vec::new();

    for dev in &device_ids(state) {
        if rs.disabled_devices.contains(dev) {
            continue;
        }
        for (bk, _) in BACKENDS {
            if rs.disabled_backends.contains(*bk) {
                continue;
            }
            let pair = (dev.clone(), bk.to_string());
            if !rs.disabled_device_backends.contains(&pair) {
                pairs.push(pair);
            }
        }
    }
    pairs
}

fn optimal_po2_for(state: &MinerState, device: &str, backend: &str) -> u8 {
    if let Some(suite) = &state.benchmark_results {
        for db in &suite.device_benchmarks {
            if db.device_id == device && db.prover_backend == backend {
                return db.optimal_po2;
            }
        }
    }
    18
}

fn cpu_vendor_color(model: &str) -> ratatui::style::Color {
    if model.starts_with("R5 ")
        || model.starts_with("R7 ")
        || model.starts_with("R9 ")
        || model.starts_with("TR ")
        || model.starts_with("EPYC ")
        || model.contains("AMD")
    {
        theme::amd_red()
    } else if model.starts_with("Xeon ")
        || model.starts_with("i3-")
        || model.starts_with("i5-")
        || model.starts_with("i7-")
        || model.starts_with("i9-")
        || model.contains("Intel")
    {
        theme::intel_blue()
    } else {
        theme::text()
    }
}

fn backend_color(key: &str) -> ratatui::style::Color {
    match key {
        "risc0" => theme::risc0_purple(),
        "sp1" => theme::sp1_orange(),
        "openvm" => theme::openvm_cyan(),
        _ => theme::text(),
    }
}

// ---------------------------------------------------------------------------
// Section item counts
// ---------------------------------------------------------------------------

fn section_row_count(state: &MinerState, section: SettingsSection) -> usize {
    match section {
        SettingsSection::Devices => 1 + state.hardware.gpus.len(),
        SettingsSection::Backends => BACKENDS.len(),
        SettingsSection::DeviceGrid => enabled_device_count(state),
        SettingsSection::Parameters => 8,
        SettingsSection::Advanced => advanced_row_count(state),
        SettingsSection::GpuTuning => gpu_tuning_row_count(state),
    }
}

fn gpu_tuning_row_count(state: &MinerState) -> usize {
    if state.gpu_tuning.is_empty() {
        return 0;
    }
    let idx = state
        .settings_ui
        .tuning_gpu_index
        .min(state.gpu_tuning.len().saturating_sub(1));
    let controls = state
        .gpu_tuning
        .get(idx)
        .map(tuning_control_count)
        .unwrap_or(0);
    // Row 0 = GPU selector, then control rows, then button row (if controls > 0)
    let button_row = if controls > 0 { 1 } else { 0 };
    1 + controls + button_row
}

fn advanced_row_count(state: &MinerState) -> usize {
    if !state.runtime_settings.advanced_mode {
        return 2; // toggle + description
    }
    1 + fully_enabled_pairs(state).len()
}

// ---------------------------------------------------------------------------
// Navigation handlers (called from app.rs)
// ---------------------------------------------------------------------------

pub fn settings_navigate_up(state: &mut MinerState) {
    if state.settings_ui.active_section == SettingsSection::GpuTuning {
        if state.settings_ui.tuning_row_index > 0 {
            state.settings_ui.tuning_row_index -= 1;
        } else {
            let prev = state.settings_ui.active_section.prev();
            state.settings_ui.active_section = prev;
            state.settings_ui.col_index = 0;
            let max = section_row_count(state, prev).saturating_sub(1);
            state.settings_ui.row_index = max;
        }
        return;
    }
    if state.settings_ui.row_index > 0 {
        state.settings_ui.row_index -= 1;
    } else {
        // At the top of this section — move to previous section, last row
        let prev = state.settings_ui.active_section.prev();
        if prev != state.settings_ui.active_section {
            state.settings_ui.active_section = prev;
            state.settings_ui.col_index = 0;
            if prev == SettingsSection::GpuTuning {
                let max = gpu_tuning_row_count(state).saturating_sub(1);
                state.settings_ui.tuning_row_index = max;
            } else {
                let max = section_row_count(state, prev).saturating_sub(1);
                state.settings_ui.row_index = max;
            }
        }
    }
}

pub fn settings_navigate_down(state: &mut MinerState) {
    if state.settings_ui.active_section == SettingsSection::GpuTuning {
        let max = gpu_tuning_row_count(state).saturating_sub(1);
        if state.settings_ui.tuning_row_index < max {
            state.settings_ui.tuning_row_index += 1;
        } else {
            let next = state.settings_ui.active_section.next();
            if next != state.settings_ui.active_section {
                state.settings_ui.active_section = next;
                state.settings_ui.row_index = 0;
                state.settings_ui.col_index = 0;
                state.settings_ui.tuning_row_index = 0;
            }
        }
        return;
    }
    let max = section_row_count(state, state.settings_ui.active_section).saturating_sub(1);
    if state.settings_ui.row_index < max {
        state.settings_ui.row_index += 1;
    } else {
        // At the bottom of this section — move to next section, first row
        let next = state.settings_ui.active_section.next();
        if next != state.settings_ui.active_section {
            state.settings_ui.active_section = next;
            state.settings_ui.row_index = 0;
            state.settings_ui.col_index = 0;
            state.settings_ui.tuning_row_index = 0;
        }
    }
}

pub fn settings_next_section(state: &mut MinerState) {
    state.settings_ui.active_section = state.settings_ui.active_section.next();
    state.settings_ui.row_index = 0;
    state.settings_ui.col_index = 0;
    state.settings_ui.tuning_row_index = 0;
}

pub fn settings_prev_section(state: &mut MinerState) {
    state.settings_ui.active_section = state.settings_ui.active_section.prev();
    state.settings_ui.row_index = 0;
    state.settings_ui.col_index = 0;
    state.settings_ui.tuning_row_index = 0;
}

/// Handle Enter/Space — toggle checkboxes, toggle grid cells, cycle spinners.
pub fn settings_activate(state: &mut MinerState) -> SettingsAction {
    match state.settings_ui.active_section {
        SettingsSection::Devices => { toggle_device(state); SettingsAction::None }
        SettingsSection::Backends => { toggle_backend(state); SettingsAction::None }
        SettingsSection::DeviceGrid => { toggle_grid_cell(state); SettingsAction::None }
        SettingsSection::Parameters => { settings_adjust_right(state) }
        SettingsSection::Advanced => {
            if state.settings_ui.row_index == 0 {
                state.runtime_settings.advanced_mode = !state.runtime_settings.advanced_mode;
                SettingsAction::None
            } else {
                settings_adjust_right(state)
            }
        }
        SettingsSection::GpuTuning => activate_tuning_button(state),
    }
}

pub fn settings_adjust_left(state: &mut MinerState) -> SettingsAction {
    match state.settings_ui.active_section {
        SettingsSection::Devices | SettingsSection::Backends => {
            settings_activate(state)
        }
        SettingsSection::DeviceGrid => {
            if state.settings_ui.col_index > 0 {
                state.settings_ui.col_index -= 1;
            }
            SettingsAction::None
        }
        SettingsSection::Parameters => { adjust_param(state, -1); SettingsAction::None }
        SettingsSection::Advanced => {
            if state.settings_ui.row_index == 0 {
                state.runtime_settings.advanced_mode = !state.runtime_settings.advanced_mode;
                SettingsAction::None
            } else {
                adjust_po2(state, -1);
                SettingsAction::None
            }
        }
        SettingsSection::GpuTuning => { adjust_tuning(state, -1); SettingsAction::None }
    }
}

pub fn settings_adjust_right(state: &mut MinerState) -> SettingsAction {
    match state.settings_ui.active_section {
        SettingsSection::Devices | SettingsSection::Backends => {
            settings_activate(state)
        }
        SettingsSection::DeviceGrid => {
            let max_col = enabled_backend_count(state).saturating_sub(1);
            if state.settings_ui.col_index < max_col {
                state.settings_ui.col_index += 1;
            }
            SettingsAction::None
        }
        SettingsSection::Parameters => { adjust_param(state, 1); SettingsAction::None }
        SettingsSection::Advanced => {
            if state.settings_ui.row_index == 0 {
                state.runtime_settings.advanced_mode = !state.runtime_settings.advanced_mode;
                SettingsAction::None
            } else {
                adjust_po2(state, 1);
                SettingsAction::None
            }
        }
        SettingsSection::GpuTuning => { adjust_tuning(state, 1); SettingsAction::None }
    }
}

// ---------------------------------------------------------------------------
// GPU tuning adjustment
// ---------------------------------------------------------------------------

/// Adjust a tuning control value. Only updates local state (sets dirty).
fn adjust_tuning(state: &mut MinerState, dir: i32) {
    if state.gpu_tuning.is_empty() {
        return;
    }

    let row = state.settings_ui.tuning_row_index;
    let gpu_idx = state
        .settings_ui
        .tuning_gpu_index
        .min(state.gpu_tuning.len() - 1);

    // Row 0 = GPU selector: cycle between GPUs
    if row == 0 {
        let count = state.gpu_tuning.len();
        if dir > 0 {
            state.settings_ui.tuning_gpu_index = (gpu_idx + 1) % count;
        } else {
            state.settings_ui.tuning_gpu_index = (gpu_idx + count - 1) % count;
        }
        // Reset control row when switching GPUs
        state.settings_ui.tuning_row_index = 0;
        return;
    }

    // Button row: cycle Apply (0), Reset (1), Benchmark (2)
    if has_tuning_buttons(state) && row == tuning_button_row(state) {
        let idx = state.settings_ui.tuning_button_idx;
        state.settings_ui.tuning_button_idx = if dir > 0 {
            (idx + 1).min(2)
        } else {
            idx.saturating_sub(1)
        };
        return;
    }

    // Control rows: adjust value, mark dirty
    let ts = &mut state.gpu_tuning[gpu_idx];
    let Some(control) = tuning_row_to_control(&ts.caps, row) else {
        return;
    };

    match control {
        // 0 = power
        0 => {
            if let Some(ref power) = ts.caps.power.clone() {
                let current = ts.power_limit_watts.unwrap_or(power.default_watts);
                let step = ((power.max_watts - power.min_watts) / 20.0).max(1.0);
                let new_val = (current + dir as f64 * step).clamp(power.min_watts, power.max_watts);
                let new_val = (new_val * 10.0).round() / 10.0;
                ts.power_limit_watts = Some(new_val);
                ts.dirty = true;
            }
        }
        // 1 = perf profile
        1 => {
            if let Some(ref profile) = ts.caps.perf_profile.clone() {
                let levels = &profile.levels;
                if levels.is_empty() {
                    return;
                }
                let current = ts.perf_level.unwrap_or(PerfLevel::Auto);
                let current_idx = levels.iter().position(|l| *l == current).unwrap_or(0);
                let new_idx = if dir > 0 {
                    (current_idx + 1) % levels.len()
                } else {
                    (current_idx + levels.len() - 1) % levels.len()
                };
                ts.perf_level = Some(levels[new_idx]);
                ts.dirty = true;
            }
        }
        // 2 = core clock
        2 => {
            if adjust_clock(ts, dir, true) {
                ts.dirty = true;
            }
        }
        // 3 = mem clock
        3 => {
            if adjust_clock(ts, dir, false) {
                ts.dirty = true;
            }
        }
        // 4 = fan speed
        4 => {
            if let Some(ref fan) = ts.caps.fan.clone() {
                let current = match &ts.fan_speed {
                    FanSetting::Auto => 50i32,
                    FanSetting::Fixed(pct) => *pct as i32,
                };
                let step = 5i32;
                let new_pct = (current + dir * step).clamp(fan.min_percent as i32, fan.max_percent as i32);
                if dir < 0 && new_pct <= fan.min_percent as i32 {
                    ts.fan_speed = FanSetting::Auto;
                } else {
                    ts.fan_speed = FanSetting::Fixed(new_pct as u32);
                }
                ts.dirty = true;
            }
        }
        _ => {}
    }
}

/// Handle Enter/Space on the GPU Tuning button row.
fn activate_tuning_button(state: &mut MinerState) -> SettingsAction {
    if state.gpu_tuning.is_empty() {
        return SettingsAction::None;
    }

    let row = state.settings_ui.tuning_row_index;
    let gpu_idx = state
        .settings_ui
        .tuning_gpu_index
        .min(state.gpu_tuning.len() - 1);

    // Only button row triggers actions
    if !has_tuning_buttons(state) || row != tuning_button_row(state) {
        return SettingsAction::None;
    }

    let ts = &mut state.gpu_tuning[gpu_idx];
    let device_id = ts.caps.device_id.clone();

    match state.settings_ui.tuning_button_idx {
        0 => {
            // Apply
            if !ts.dirty {
                return SettingsAction::None;
            }
            let tuning = ts.clone();
            ts.dirty = false;
            SettingsAction::GpuTuningApply {
                device_id,
                tuning,
            }
        }
        1 => {
            // Reset
            ts.reset();
            SettingsAction::GpuTuningReset { device_id }
        }
        2 => {
            // Benchmark — skip if already in progress
            if state.benchmark_device_in_progress.is_some() {
                return SettingsAction::None;
            }
            SettingsAction::GpuTuningBenchmark { device_id }
        }
        _ => SettingsAction::None,
    }
}

/// Helper to map a control index within a GpuTuningCaps (skipping None caps).
fn tuning_row_to_control(caps: &crate::gpu_tuning::GpuTuningCaps, row: usize) -> Option<usize> {
    let mut controls = Vec::new();
    if caps.power.is_some() {
        controls.push(0);
    }
    if caps.perf_profile.is_some() {
        controls.push(1);
    }
    if caps.core_clock.is_some() {
        controls.push(2);
    }
    if caps.mem_clock.is_some() {
        controls.push(3);
    }
    if caps.fan.is_some() {
        controls.push(4);
    }
    let control_idx = row.checked_sub(1)?;
    controls.get(control_idx).copied()
}

/// Adjust a clock setting in-place. Returns true if a change was made.
fn adjust_clock(
    ts: &mut GpuTuningState,
    dir: i32,
    is_core: bool,
) -> bool {
    let caps = if is_core {
        match ts.caps.core_clock.clone() {
            Some(c) => c,
            None => return false,
        }
    } else {
        match ts.caps.mem_clock.clone() {
            Some(c) => c,
            None => return false,
        }
    };
    let setting = if is_core {
        &mut ts.core_clock
    } else {
        &mut ts.mem_clock
    };

    match caps {
        ClockCaps::DpmLevels(ref levels) => {
            if levels.is_empty() {
                return false;
            }
            let max_idx = levels.last().map(|l| l.index).unwrap_or(0);
            let current_idx = match setting {
                ClockSetting::DpmLevel(idx) => *idx,
                _ => levels.iter().find(|l| l.active).map(|l| l.index).unwrap_or(0),
            };
            let new_idx = if dir > 0 {
                (current_idx + 1).min(max_idx)
            } else {
                current_idx.saturating_sub(1)
            };
            *setting = ClockSetting::DpmLevel(new_idx);
            true
        }
        ClockCaps::Range {
            min_mhz,
            max_mhz,
            default_mhz,
        } => {
            let step = ((max_mhz - min_mhz) / 20).max(15);
            let current = match setting {
                ClockSetting::Fixed(mhz) => *mhz,
                _ => default_mhz,
            };
            let new_mhz = if dir > 0 {
                (current + step).min(max_mhz)
            } else {
                current.saturating_sub(step).max(min_mhz)
            };
            *setting = ClockSetting::Fixed(new_mhz);
            true
        }
        ClockCaps::Offset {
            min_offset_mhz,
            max_offset_mhz,
        } => {
            // 15 MHz steps for core clock, 50 raw (= 25 effective) for memory
            let step = if is_core { 15 } else { 50 };
            let current = match setting {
                ClockSetting::Offset(off) => *off,
                _ => 0,
            };
            let new_off = (current + dir * step).clamp(min_offset_mhz, max_offset_mhz);
            *setting = ClockSetting::Offset(new_off);
            true
        }
    }
}

// ---------------------------------------------------------------------------
// Toggle helpers
// ---------------------------------------------------------------------------

fn toggle_device(state: &mut MinerState) {
    let idx = state.settings_ui.row_index;
    let device_id = if idx == 0 {
        "cpu".to_string()
    } else {
        let gpu_idx = idx - 1;
        if gpu_idx < state.hardware.gpus.len() {
            format!("gpu{}", state.hardware.gpus[gpu_idx].index)
        } else {
            return;
        }
    };

    if state.runtime_settings.disabled_devices.contains(&device_id) {
        state.runtime_settings.disabled_devices.remove(&device_id);
    } else {
        state.runtime_settings.disabled_devices.insert(device_id);
    }
}

fn toggle_backend(state: &mut MinerState) {
    let idx = state.settings_ui.row_index;
    if idx >= BACKENDS.len() {
        return;
    }
    let key = BACKENDS[idx].0.to_string();

    if state.runtime_settings.disabled_backends.contains(&key) {
        state.runtime_settings.disabled_backends.remove(&key);
    } else {
        state.runtime_settings.disabled_backends.insert(key);
    }
}

fn toggle_grid_cell(state: &mut MinerState) {
    let row = state.settings_ui.row_index;
    let col = state.settings_ui.col_index;

    let devs = enabled_devices(state);
    let bks = enabled_backends(state);

    if row >= devs.len() || col >= bks.len() {
        return;
    }

    let device_id = devs[row].id.clone();
    let backend_key = bks[col].0.to_string();
    let pair = (device_id, backend_key);

    if state.runtime_settings.disabled_device_backends.contains(&pair) {
        state.runtime_settings.disabled_device_backends.remove(&pair);
    } else {
        state.runtime_settings.disabled_device_backends.insert(pair);
    }
}

// ---------------------------------------------------------------------------
// Parameter adjustment
// ---------------------------------------------------------------------------

fn adjust_param(state: &mut MinerState, dir: i32) {
    let rs = &mut state.runtime_settings;
    match state.settings_ui.row_index {
        0 => {
            let v = rs.max_concurrent_proofs as i32 + dir;
            rs.max_concurrent_proofs = v.clamp(1, 16) as usize;
        }
        1 => {
            rs.min_profit_threshold = (rs.min_profit_threshold + dir as f64).clamp(0.0, 1000.0);
        }
        2 => {
            let current_idx = STRATEGIES
                .iter()
                .position(|s| *s == rs.strategy)
                .unwrap_or(1);
            let new_idx = if dir > 0 {
                (current_idx + 1) % STRATEGIES.len()
            } else {
                (current_idx + STRATEGIES.len() - 1) % STRATEGIES.len()
            };
            rs.strategy = STRATEGIES[new_idx].to_string();
        }
        3 => {
            rs.electricity_cost_kwh =
                ((rs.electricity_cost_kwh + dir as f64 * 0.01) * 100.0).round() / 100.0;
            rs.electricity_cost_kwh = rs.electricity_cost_kwh.clamp(0.0, 1.0);
        }
        4 => {
            let v = rs.system_power_watts + dir as f64 * 50.0;
            rs.system_power_watts = v.clamp(50.0, 5000.0);
        }
        5 => {
            rs.deadline_safety_margin =
                ((rs.deadline_safety_margin + dir as f64 * 0.1) * 10.0).round() / 10.0;
            rs.deadline_safety_margin = rs.deadline_safety_margin.clamp(1.0, 5.0);
        }
        6 => {
            rs.token_price_usd =
                ((rs.token_price_usd + dir as f64 * 0.05) * 100.0).round() / 100.0;
            rs.token_price_usd = rs.token_price_usd.clamp(0.01, 100.0);
        }
        7 => {
            rs.gas_cost_usd =
                ((rs.gas_cost_usd + dir as f64 * 0.005) * 1000.0).round() / 1000.0;
            rs.gas_cost_usd = rs.gas_cost_usd.clamp(0.0, 10.0);
        }
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// Po2 adjustment
// ---------------------------------------------------------------------------

fn adjust_po2(state: &mut MinerState, dir: i32) {
    let pairs = fully_enabled_pairs(state);
    let pair_idx = state.settings_ui.row_index.saturating_sub(1);
    if pair_idx >= pairs.len() {
        return;
    }
    let (dev, bk) = &pairs[pair_idx];
    let key = (dev.clone(), bk.clone());

    let current = state
        .runtime_settings
        .po2_overrides
        .get(&key)
        .copied()
        .unwrap_or_else(|| optimal_po2_for(state, dev, bk));

    let new_val = (current as i32 + dir).clamp(14, 24) as u8;
    state.runtime_settings.po2_overrides.insert(key, new_val);
}
