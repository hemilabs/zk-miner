//! Main TUI application.

use anyhow::Result;
use crossterm::{
    event::{DisableMouseCapture, EnableMouseCapture, KeyCode, KeyModifiers},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::Style,
    text::{Line, Span},
    widgets::{Paragraph, Tabs},
    Frame, Terminal,
};
use std::io;
use std::time::Duration;

use crate::event::{AppEvent, spawn_event_reader};
use crate::gpu_tuning::GpuTuningState;
use crate::screens;
use crate::screens::settings::SettingsAction;
use crate::state::{LogLevel, MinerState, Screen, SharedState, TESTNET_MINT_AMOUNT, MIN_STAKE_WEI};
use crate::theme;
use zkminer_chain::client::ChainClient;

/// Action to take after releasing the state lock.
enum PostKeyAction {
    None,
    Quit,
    /// Re-benchmark a single device by device_id.
    RebenchmarkDevice(String),
    /// Run full benchmark suite.
    RebenchmarkAll,
    /// Apply all pending GPU tuning changes for a device.
    ApplyGpuTuningAll {
        device_id: String,
        tuning: GpuTuningState,
    },
    /// Reset a GPU's tuning to hardware defaults.
    ResetGpuTuning {
        device_id: String,
    },
    /// Setup wizard: mint testnet tokens.
    SetupMint,
    /// Setup wizard: approve + stake HEMI.
    SetupStake,
}

/// Run the full interactive TUI.
///
/// If `chain_client` is provided, the setup wizard can perform on-chain actions
/// (mint testnet tokens, approve + stake). Without it, setup is display-only.
pub async fn run_tui(state: SharedState, chain_client: Option<ChainClient>) -> Result<()> {
    let chain_client = std::sync::Arc::new(chain_client);
    // Setup terminal — reset attributes first in case prior tracing output
    // left ANSI escape state (colors, bold, etc.) that would bleed into the TUI.
    let mut stdout = io::stdout();
    execute!(
        stdout,
        crossterm::style::ResetColor,
        crossterm::style::SetAttribute(crossterm::style::Attribute::Reset),
        EnterAlternateScreen,
        EnableMouseCapture,
    )?;
    enable_raw_mode()?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut events = spawn_event_reader(Duration::from_secs(1));

    loop {
        // Draw
        {
            let state = state.read().await;
            terminal.draw(|f| draw(f, &state))?;
        }

        // Handle events
        if let Some(event) = events.recv().await {
            let action = match event {
                AppEvent::Key(key) => {
                    let mut s = state.write().await;
                    handle_key(&mut s, key)
                }
                AppEvent::Tick => {
                    let mut s = state.write().await;
                    s.tick_count = s.tick_count.wrapping_add(1);
                    s.block_just_updated = false;
                    PostKeyAction::None
                }
                AppEvent::Resize(_, _) => PostKeyAction::None,
            };

            // Process actions that need the lock released
            match action {
                PostKeyAction::Quit => break,
                PostKeyAction::RebenchmarkDevice(device_id) => {
                    let st = state.clone();
                    tokio::spawn(async move {
                        run_device_benchmark(st, &device_id).await;
                    });
                }
                PostKeyAction::RebenchmarkAll => {
                    let st = state.clone();
                    tokio::spawn(async move {
                        run_full_benchmark(st).await;
                    });
                }
                PostKeyAction::ApplyGpuTuningAll { device_id, tuning } => {
                    let st = state.clone();
                    tokio::spawn(async move {
                        apply_gpu_tuning_all_async(st, device_id, tuning).await;
                    });
                }
                PostKeyAction::ResetGpuTuning { device_id } => {
                    let st = state.clone();
                    tokio::spawn(async move {
                        reset_gpu_tuning_async(st, device_id).await;
                    });
                }
                PostKeyAction::SetupMint => {
                    let st = state.clone();
                    let cc = chain_client.clone();
                    tokio::spawn(async move {
                        setup_mint_async(st, cc).await;
                    });
                }
                PostKeyAction::SetupStake => {
                    let st = state.clone();
                    let cc = chain_client.clone();
                    tokio::spawn(async move {
                        setup_stake_async(st, cc).await;
                    });
                }
                PostKeyAction::None => {}
            }
        }
    }

    // Cleanup terminal
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    Ok(())
}

fn handle_key(state: &mut MinerState, key: crossterm::event::KeyEvent) -> PostKeyAction {
    // Setup screen has its own key handling — intercept before global keys
    if state.current_screen == Screen::Setup {
        // Allow quit from setup
        match key.code {
            KeyCode::Char('q') | KeyCode::Char('Q') => return PostKeyAction::Quit,
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                return PostKeyAction::Quit;
            }
            // Allow switching to other screens via number keys
            KeyCode::Char(c @ '1'..='7') => {
                if let Some(screen) = Screen::from_key(c) {
                    state.setup_status.dismissed = true;
                    state.current_screen = screen;
                    return PostKeyAction::None;
                }
            }
            _ => {}
        }

        let action = screens::setup::handle_setup_key(state, key.code);
        return match action {
            screens::setup::SetupAction::Dismiss => {
                state.current_screen = Screen::Dashboard;
                PostKeyAction::None
            }
            screens::setup::SetupAction::MintTokens => PostKeyAction::SetupMint,
            screens::setup::SetupAction::ApproveAndStake => PostKeyAction::SetupStake,
            screens::setup::SetupAction::NavigateUp
            | screens::setup::SetupAction::NavigateDown
            | screens::setup::SetupAction::None => PostKeyAction::None,
        };
    }

    match key.code {
        KeyCode::Char('q') | KeyCode::Char('Q') => return PostKeyAction::Quit,
        KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            return PostKeyAction::Quit;
        }

        // Pause toggle
        KeyCode::Char('p') | KeyCode::Char('P') => {
            state.paused = !state.paused;
            let msg = if state.paused {
                "Miner PAUSED — no new jobs will be claimed"
            } else {
                "Miner RESUMED — job claiming active"
            };
            let level = if state.paused {
                LogLevel::Warn
            } else {
                LogLevel::Info
            };
            state.add_log(level, msg);
        }

        // Theme cycle
        KeyCode::Char('T') => {
            let t = theme::cycle_theme();
            state.add_log(LogLevel::Info, format!("Theme: {}", t.name()));
        }

        // Screen navigation
        KeyCode::Char(c @ '1'..='7') => {
            if let Some(screen) = Screen::from_key(c) {
                state.current_screen = screen;
            }
        }

        // Screen-specific keys
        KeyCode::Up | KeyCode::Char('k') => match state.current_screen {
            Screen::Jobs => {
                state.selected_job_index = state.selected_job_index.saturating_sub(1);
            }
            Screen::Logs => {
                state.log_scroll = state.log_scroll.saturating_add(1);
            }
            Screen::Benchmark => {
                screens::benchmark::benchmark_navigate_up(state);
            }
            Screen::Settings => {
                screens::settings::settings_navigate_up(state);
            }
            _ => {}
        },
        KeyCode::Down | KeyCode::Char('j') => match state.current_screen {
            Screen::Jobs => {
                let max = state.open_jobs.len().saturating_sub(1);
                state.selected_job_index = (state.selected_job_index + 1).min(max);
            }
            Screen::Logs => {
                state.log_scroll = state.log_scroll.saturating_sub(1);
            }
            Screen::Benchmark => {
                screens::benchmark::benchmark_navigate_down(state);
            }
            Screen::Settings => {
                screens::settings::settings_navigate_down(state);
            }
            _ => {}
        },
        KeyCode::Enter | KeyCode::Char(' ') => match state.current_screen {
            Screen::Jobs => {
                if key.code == KeyCode::Enter {
                    if let Some(job) = state.open_jobs.get(state.selected_job_index) {
                        state.selected_job_id = Some(job.info.job_id);
                        state.current_screen = Screen::JobDetail;
                    }
                }
            }
            Screen::Settings => {
                let action = screens::settings::settings_activate(state);
                return settings_action_to_post_key(action, state);
            }
            _ => {}
        },
        KeyCode::Left | KeyCode::Char('h') => {
            if state.current_screen == Screen::Settings {
                let action = screens::settings::settings_adjust_left(state);
                return settings_action_to_post_key(action, state);
            }
        }
        KeyCode::Right | KeyCode::Char('l') => {
            if state.current_screen == Screen::Settings {
                let action = screens::settings::settings_adjust_right(state);
                return settings_action_to_post_key(action, state);
            }
        }
        KeyCode::Tab => {
            if state.current_screen == Screen::Settings {
                screens::settings::settings_next_section(state);
            }
        }
        KeyCode::BackTab => {
            if state.current_screen == Screen::Settings {
                screens::settings::settings_prev_section(state);
            }
        }

        // Benchmark: re-benchmark selected device
        KeyCode::Char('r') => {
            if state.current_screen == Screen::Benchmark
                && !state.benchmark_running
                && state.benchmark_device_in_progress.is_none()
            {
                if let Some(device_id) = screens::benchmark::selected_device_id(state) {
                    state.benchmark_device_in_progress = Some(device_id.clone());
                    state.add_log(
                        LogLevel::Info,
                        format!("Re-benchmarking device: {device_id}..."),
                    );
                    return PostKeyAction::RebenchmarkDevice(device_id);
                }
            }
        }

        // Benchmark: run full suite
        KeyCode::Char('b') => {
            if state.current_screen == Screen::Benchmark
                && !state.benchmark_running
                && state.benchmark_device_in_progress.is_none()
            {
                state.benchmark_running = true;
                state.add_log(LogLevel::Info, "Running full benchmark suite...");
                return PostKeyAction::RebenchmarkAll;
            }
        }

        _ => {}
    }

    PostKeyAction::None
}

/// Re-benchmark a single device asynchronously.
async fn run_device_benchmark(state: SharedState, device_id: &str) {
    use zkminer_prover::benchmark;

    if device_id == "cpu" {
        // CPU re-benchmark: re-run the full benchmark suite, replace CPU entries
        let suite = tokio::task::spawn_blocking(benchmark::run_benchmark)
            .await
            .unwrap_or_default();

        let mut s = state.write().await;

        if let Some(existing) = s.benchmark_results.as_mut() {
            // Update CPU-specific data; leave the real (worker-measured) GPU
            // benchmarks intact — GPU throughput is measured, not derived from CPU.
            existing.results = suite.results;
            existing.cpu_info = suite.cpu_info;
            existing.timestamp = suite.timestamp;
            existing.zkops = suite.zkops;
            existing.cpu_power_watts = suite.cpu_power_watts;

            // Replace CPU device benchmarks
            existing
                .device_benchmarks
                .retain(|d| d.device_id != "cpu");
            existing.device_benchmarks.extend(
                suite
                    .device_benchmarks
                    .into_iter()
                    .filter(|d| d.device_id == "cpu"),
            );

            let zkops = existing.zkops;
            benchmark::save_benchmark(existing);
            s.add_log(
                LogLevel::Success,
                format!("CPU benchmark complete (zkOP/s: {zkops:.0})"),
            );
        }
        s.benchmark_device_in_progress = None;
    } else {
        // GPU: run the real streaming benchmark (actual proving). The worker pool
        // can't isolate a single GPU, so all GPUs are re-measured — but identity
        // and throughput come from real measurement, matching how the miner records
        // them, so the selected GPU's name/order stays stable (the old path used a
        // CPU-extrapolation model that was instant and used a different id/name
        // scheme, which flipped names and never actually proved).
        run_streaming_gpu_benchmark(state).await;
    }
}

/// Run the REAL GPU streaming benchmark (actual proving on each GPU worker) and
/// merge the fresh per-GPU results into `benchmark_results`, preserving CPU data.
/// Mirrors the miner's own startup benchmark so device identity (worker index +
/// name, one row per GPU) stays consistent. Reports a GPU-tuning before/after delta
/// if one was requested.
async fn run_streaming_gpu_benchmark(state: SharedState) {
    use zkminer_prover::benchmark;

    {
        let mut s = state.write().await;
        s.benchmark_running = true;
        s.benchmark_tracker = Some(crate::state::BenchmarkTracker {
            devices: Vec::new(),
            all_complete: false,
            started_at: Some(chrono::Utc::now()),
            active_device_index: 0,
        });
        s.add_log(LogLevel::Info, "Running GPU benchmarks (real proving)...");
    }

    let state_for_progress = state.clone();
    let suite = tokio::task::spawn_blocking(move || {
        let (sync_tx, sync_rx) =
            std::sync::mpsc::channel::<zkminer_prover::dispatcher::BenchmarkProgressEvent>();
        let (bridge_tx, mut bridge_rx) =
            tokio::sync::mpsc::channel::<zkminer_prover::dispatcher::BenchmarkProgressEvent>(32);
        let bridge_state = state_for_progress.clone();

        tokio::spawn(async move {
            while let Some(event) = bridge_rx.recv().await {
                let mut s = bridge_state.write().await;
                if let Some(tracker) = s.benchmark_tracker.as_mut() {
                    tracker.on_progress(
                        &event.slot_key,
                        event.gpu_name.as_deref(),
                        event.device_index,
                        &event.gpu_tag,
                        &event.entry,
                        event.program_index,
                        event.total_programs,
                    );
                }
            }
        });

        let bridge = std::thread::spawn(move || {
            while let Ok(event) = sync_rx.recv() {
                if bridge_tx.blocking_send(event).is_err() {
                    break;
                }
            }
        });

        let on_progress = move |event: zkminer_prover::dispatcher::BenchmarkProgressEvent| {
            let _ = sync_tx.send(event);
        };
        let suite = benchmark::run_benchmark_gpu_only_streaming(&on_progress);
        drop(on_progress);
        let _ = bridge.join();
        suite
    })
    .await
    .unwrap_or_default();

    let mut s = state.write().await;
    let gpu_count = suite.device_benchmarks.len();

    // Merge freshly-measured GPU benchmarks into the existing suite (keep CPU data).
    if let Some(existing) = s.benchmark_results.as_mut() {
        existing
            .device_benchmarks
            .retain(|d| !d.device_id.starts_with("gpu"));
        existing.device_benchmarks.extend(suite.device_benchmarks);
        existing.gpu_power_watts = suite.gpu_power_watts;
        existing.timestamp = suite.timestamp;
        benchmark::save_benchmark(existing);
    } else {
        benchmark::save_benchmark(&suite);
        s.benchmark_results = Some(suite);
    }

    // Report a GPU-tuning before/after delta if one was requested for a device.
    if let Some((before_dev, before_tp)) = s.gpu_tuning_bench_before.take() {
        let after_tp: f64 = s
            .benchmark_results
            .as_ref()
            .map(|b| {
                b.device_benchmarks
                    .iter()
                    .filter(|d| d.device_id == before_dev)
                    .map(|d| d.throughput)
                    .sum()
            })
            .unwrap_or(0.0);
        let pct = if before_tp > 0.0 {
            (after_tp - before_tp) / before_tp * 100.0
        } else {
            0.0
        };
        let delta_str = if pct >= 0.0 {
            format!("+{pct:.1}%")
        } else {
            format!("{pct:.1}%")
        };
        s.add_log(
            LogLevel::Success,
            format!("Benchmark complete for {before_dev} ({delta_str})"),
        );
        s.gpu_tuning_bench_result = Some((before_dev, before_tp, after_tp));
    } else {
        s.add_log(
            LogLevel::Success,
            format!("GPU benchmarks complete ({gpu_count} device entries)"),
        );
    }

    s.benchmark_running = false;
    s.benchmark_tracker = None;
    s.benchmark_device_in_progress = None;
}

/// Run a full benchmark suite asynchronously: CPU (measured) then GPUs (measured
/// via the real streaming worker benchmark).
async fn run_full_benchmark(state: SharedState) {
    use zkminer_prover::benchmark;

    let suite = tokio::task::spawn_blocking(benchmark::run_benchmark)
        .await
        .unwrap_or_default();

    {
        let mut s = state.write().await;
        benchmark::save_benchmark(&suite);
        s.add_log(
            LogLevel::Success,
            format!("CPU benchmark complete (zkOP/s: {:.0})", suite.zkops),
        );
        s.benchmark_results = Some(suite);
    }

    // Measure the GPUs for real and merge them in (keeps benchmark_running set).
    run_streaming_gpu_benchmark(state).await;
}

/// Convert a SettingsAction into a PostKeyAction.
fn settings_action_to_post_key(action: SettingsAction, state: &mut MinerState) -> PostKeyAction {
    match action {
        SettingsAction::None => PostKeyAction::None,
        SettingsAction::GpuTuningApply { device_id, tuning } => {
            PostKeyAction::ApplyGpuTuningAll { device_id, tuning }
        }
        SettingsAction::GpuTuningReset { device_id } => {
            PostKeyAction::ResetGpuTuning { device_id }
        }
        SettingsAction::GpuTuningBenchmark { device_id } => {
            // Capture current throughput as the "before" baseline
            let before = state
                .benchmark_results
                .as_ref()
                .map(|suite| {
                    suite
                        .device_benchmarks
                        .iter()
                        .filter(|d| d.device_id == device_id)
                        .map(|d| d.throughput)
                        .sum::<f64>()
                })
                .unwrap_or(0.0);

            state.gpu_tuning_bench_before = Some((device_id.clone(), before));
            state.gpu_tuning_bench_result = None;
            state.benchmark_device_in_progress = Some(device_id.clone());
            state.add_log(
                LogLevel::Info,
                format!("Re-benchmarking {device_id} after tuning changes..."),
            );
            PostKeyAction::RebenchmarkDevice(device_id)
        }
    }
}

/// Apply all pending GPU tuning changes asynchronously.
async fn apply_gpu_tuning_all_async(
    state: SharedState,
    device_id: String,
    tuning: GpuTuningState,
) {
    let hardware = { state.read().await.hardware.clone() };
    let dev_id = device_id.clone();

    let results = tokio::task::spawn_blocking(move || {
        crate::gpu_tuning::apply_full_state(&dev_id, &tuning, &hardware)
    })
    .await
    .unwrap_or_else(|e| vec![Err(anyhow::anyhow!("{e}"))]);

    let mut s = state.write().await;
    let mut any_error = false;
    for result in results {
        match result {
            Ok(msg) => s.add_log(LogLevel::Success, msg),
            Err(e) => {
                s.add_log(LogLevel::Error, format!("Tuning failed: {e}"));
                any_error = true;
            }
        }
    }

    // Re-mark dirty if any write failed so user can retry
    if any_error {
        if let Some(ts) = s.gpu_tuning.iter_mut().find(|t| t.caps.device_id == device_id) {
            ts.dirty = true;
        }
    }
}

/// Reset a GPU's tuning to hardware defaults asynchronously.
async fn reset_gpu_tuning_async(state: SharedState, device_id: String) {
    let hardware = { state.read().await.hardware.clone() };
    let dev_id = device_id.clone();

    let result = tokio::task::spawn_blocking(move || {
        crate::gpu_tuning::apply_tuning(
            &dev_id,
            &crate::gpu_tuning::TuningChange::ResetAll,
            &hardware,
        )
    })
    .await
    .unwrap_or_else(|e| Err(anyhow::anyhow!("{e}")));

    let mut s = state.write().await;
    match result {
        Ok(msg) => s.add_log(LogLevel::Success, msg),
        Err(e) => s.add_log(LogLevel::Error, format!("Tuning reset failed: {e}")),
    }
}

/// Mint testnet HEMI tokens asynchronously (setup wizard action).
async fn setup_mint_async(state: SharedState, chain_client: std::sync::Arc<Option<ChainClient>>) {
    let client = match chain_client.as_ref() {
        Some(c) => c,
        None => {
            let mut s = state.write().await;
            s.setup_status.pending_action = None;
            s.setup_status.last_error = Some("No chain client available".to_string());
            return;
        }
    };

    match client.mint_testnet_tokens(TESTNET_MINT_AMOUNT).await {
        Ok(()) => {
            // Refresh balance after mint
            let new_balance = client.get_hemi_balance(client.address).await.ok();
            let mut s = state.write().await;
            if let Some(balance) = new_balance {
                s.hemi_balance = balance.to::<u128>();
            }
            let (eth, hemi, stake) = (s.eth_balance, s.hemi_balance, s.stake_info.clone());
            s.setup_status.pending_action = None;
            s.setup_status.last_error = None;
            s.setup_status.refresh_from_balances(eth, hemi, stake.as_ref());
            s.add_log(LogLevel::Success, "Minted 1000 tHEMI tokens");
        }
        Err(e) => {
            let mut s = state.write().await;
            s.setup_status.pending_action = None;
            s.setup_status.last_error = Some(format!("{e:#}"));
            s.add_log(LogLevel::Error, format!("Mint failed: {e:#}"));
        }
    }
}

/// Approve + stake HEMI tokens asynchronously (setup wizard action).
async fn setup_stake_async(state: SharedState, chain_client: std::sync::Arc<Option<ChainClient>>) {
    let client = match chain_client.as_ref() {
        Some(c) => c,
        None => {
            let mut s = state.write().await;
            s.setup_status.pending_action = None;
            s.setup_status.last_error = Some("No chain client available".to_string());
            return;
        }
    };

    // Stake the minimum amount (100 HEMI)
    let stake_amount = MIN_STAKE_WEI;
    match client.approve_and_stake(stake_amount).await {
        Ok(()) => {
            // Refresh stake info and balance after staking
            let new_stake = client.get_stake_info(client.address).await.ok();
            let new_balance = client.get_hemi_balance(client.address).await.ok();
            let mut s = state.write().await;
            if let Some(stake) = new_stake {
                s.stake_info = Some(stake);
            }
            if let Some(balance) = new_balance {
                s.hemi_balance = balance.to::<u128>();
            }
            let (eth, hemi, stake) = (s.eth_balance, s.hemi_balance, s.stake_info.clone());
            s.setup_status.pending_action = None;
            s.setup_status.last_error = None;
            s.setup_status.refresh_from_balances(eth, hemi, stake.as_ref());
            s.add_log(LogLevel::Success, "Staked 100 HEMI");
        }
        Err(e) => {
            let mut s = state.write().await;
            s.setup_status.pending_action = None;
            s.setup_status.last_error = Some(format!("{e:#}"));
            s.add_log(LogLevel::Error, format!("Stake failed: {e:#}"));
        }
    }
}

fn draw(f: &mut Frame, state: &MinerState) {
    use ratatui::widgets::Block;

    // Paint the entire terminal background with the theme's base color.
    f.render_widget(Block::default().style(theme::canvas()), f.area());

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1), // Tab bar (compact)
            Constraint::Min(0),   // Content
            Constraint::Length(1), // Status bar
        ])
        .split(f.area());

    // --- Tab bar (1 line, borderless) ---
    let titles: Vec<Line> = Screen::all()
        .iter()
        .enumerate()
        .map(|(i, s)| {
            if *s == state.current_screen {
                Line::from(Span::styled(
                    format!(" {} {} ", i + 1, s.title()),
                    theme::tab_active(),
                ))
            } else {
                Line::from(vec![
                    Span::styled(format!(" {}", i + 1), theme::tab_inactive_num()),
                    Span::styled(format!(" {} ", s.title()), theme::tab_inactive()),
                ])
            }
        })
        .collect();

    let selected_idx = Screen::all()
        .iter()
        .position(|s| *s == state.current_screen)
        .unwrap_or(0);

    let tabs = Tabs::new(titles)
        .select(selected_idx)
        .divider("")
        .style(theme::tab_bar_bg());

    f.render_widget(tabs, chunks[0]);

    // --- Content ---
    let content_area = chunks[1];
    match state.current_screen {
        Screen::Setup => screens::setup::render(f, content_area, state),
        Screen::Dashboard => screens::dashboard::render(f, content_area, state),
        Screen::Jobs => screens::jobs::render(f, content_area, state),
        Screen::JobDetail => screens::job_detail::render(f, content_area, state),
        Screen::Wallet => screens::wallet::render(f, content_area, state),
        Screen::Benchmark => screens::benchmark::render(f, content_area, state),
        Screen::Logs => screens::logs::render(f, content_area, state),
        Screen::Settings => screens::settings::render(f, content_area, state),
    }

    // --- Status bar ---
    let mut left_spans: Vec<Span> = Vec::new();

    // Connection badge
    if state.connected {
        left_spans.push(Span::styled(" CONNECTED ", theme::badge_ok()));
    } else {
        let badge = if state.tick_count.is_multiple_of(2) {
            theme::badge_error()
        } else {
            theme::error()
        };
        left_spans.push(Span::styled(" DISCONNECTED ", badge));
    }

    // Paused badge
    if state.paused {
        left_spans.push(Span::raw(" "));
        left_spans.push(Span::styled(" PAUSED ", theme::badge_warn()));
    }

    // Block number with heartbeat
    let spinner = ["|", "/", "-", "\\"];
    let spin_char = spinner[(state.tick_count % 4) as usize];
    let block_style = if state.block_just_updated {
        theme::metric()
    } else {
        Style::default().fg(theme::text())
    };
    left_spans.push(Span::styled(
        format!("  Block: {} {} ", state.block_number, spin_char),
        block_style,
    ));

    // Job counts
    left_spans.push(Span::styled(
        format!("Locked: {}  Available: {}  ", state.active_jobs.len(), state.open_jobs.len()),
        Style::default().fg(theme::text()),
    ));

    // Right-aligned keybind hints
    let mut right_spans: Vec<Span> = Vec::new();
    right_spans.extend(theme::status_keybind("q", ":quit  "));
    right_spans.extend(theme::status_keybind("p", ":pause  "));
    right_spans.push(Span::styled("T", Style::default().fg(theme::peach())));
    right_spans.push(Span::styled(
        format!(":{name}  ", name = theme::active_theme().name()),
        Style::default().fg(theme::text()),
    ));
    right_spans.extend(theme::status_keybind("1-7", ":screens"));

    // Combine left + spacer + right
    left_spans.extend(right_spans);
    let status = Paragraph::new(Line::from(left_spans)).style(theme::status_bar());

    f.render_widget(status, chunks[2]);
}
