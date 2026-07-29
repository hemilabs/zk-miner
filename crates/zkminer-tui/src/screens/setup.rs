//! First-run setup wizard screen.
//!
//! Guides new users through: wallet check -> mint tokens (testnet) -> stake -> wait for maturity.
//! Shown automatically when the miner detects it is not ready to prove.
//! Can be dismissed with Esc (experienced users) or skipped entirely if already set up.

use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::Style,
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Wrap},
    Frame,
};

use crate::state::{
    MinerState, SetupStatus, MIN_STAKE_WEI, TESTNET_MINT_AMOUNT,
};
use crate::theme;
use super::dashboard::format_token_amount;

/// Step indices in the setup wizard.
const STEP_WALLET: usize = 0;
const STEP_TOKENS: usize = 1;
const STEP_STAKE: usize = 2;
const STEP_MATURITY: usize = 3;
const STEP_READY: usize = 4;
const TOTAL_STEPS: usize = 5;

/// Render the setup wizard screen.
pub fn render(f: &mut Frame, area: Rect, state: &MinerState) {
    let setup = &state.setup_status;

    let outer_block = Block::default()
        .title(Span::styled(" Setup Wizard ", theme::title()))
        .borders(Borders::ALL)
        .border_style(theme::border())
        .border_type(theme::border_type());

    let inner = outer_block.inner(area);
    f.render_widget(outer_block, area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),  // Header
            Constraint::Length(1),  // Spacer
            Constraint::Min(16),   // Steps
            Constraint::Length(1),  // Spacer
            Constraint::Length(3),  // Action bar / status
        ])
        .split(inner);

    // --- Header ---
    render_header(f, chunks[0], state);

    // --- Steps ---
    render_steps(f, chunks[2], state);

    // --- Action bar ---
    render_action_bar(f, chunks[4], state);
}

fn render_header(f: &mut Frame, area: Rect, state: &MinerState) {
    let network = if state.setup_status.is_testnet {
        "Hemi Testnet"
    } else {
        "Hemi Mainnet"
    };

    let lines = vec![
        Line::from(vec![
            Span::styled("Welcome to ", theme::dim()),
            Span::styled("zkminer", theme::bold()),
            Span::styled(format!(" | {network}"), theme::identifier()),
        ]),
        Line::from(Span::styled(
            "Complete the steps below to start proving. Press Esc to skip.",
            theme::dim(),
        )),
    ];

    f.render_widget(Paragraph::new(lines), area);
}

fn render_steps(f: &mut Frame, area: Rect, state: &MinerState) {
    let setup = &state.setup_status;

    let step_height = 3_u16;
    let constraints: Vec<Constraint> = (0..TOTAL_STEPS)
        .map(|_| Constraint::Length(step_height))
        .collect();
    let step_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(constraints)
        .split(area);

    // Step 1: Wallet check
    render_step(
        f,
        step_chunks[STEP_WALLET],
        STEP_WALLET,
        setup,
        "Check Wallet",
        &wallet_description(state),
        setup.checked,
    );

    // Step 2: HEMI tokens
    render_step(
        f,
        step_chunks[STEP_TOKENS],
        STEP_TOKENS,
        setup,
        "HEMI Tokens",
        &tokens_description(state),
        setup.has_hemi,
    );

    // Step 3: Stake
    render_step(
        f,
        step_chunks[STEP_STAKE],
        STEP_STAKE,
        setup,
        "Stake HEMI",
        &stake_description(state),
        setup.has_stake,
    );

    // Step 4: Staking maturity
    render_step(
        f,
        step_chunks[STEP_MATURITY],
        STEP_MATURITY,
        setup,
        "Staking Age",
        &maturity_description(state),
        setup.stake_mature,
    );

    // Step 5: Ready
    render_step(
        f,
        step_chunks[STEP_READY],
        STEP_READY,
        setup,
        "Ready!",
        &ready_description(state),
        setup.is_ready(),
    );
}

fn render_step(
    f: &mut Frame,
    area: Rect,
    step_index: usize,
    setup: &SetupStatus,
    title: &str,
    description: &[Line],
    complete: bool,
) {
    let is_selected = setup.selected_step == step_index;

    let icon = if complete {
        Span::styled(" [x] ", theme::positive())
    } else if is_selected {
        Span::styled(" [>] ", theme::accent())
    } else {
        Span::styled(" [ ] ", theme::dim())
    };

    let title_style = if complete {
        theme::positive()
    } else if is_selected {
        theme::bold()
    } else {
        theme::dim()
    };

    let block = Block::default()
        .borders(Borders::LEFT)
        .border_style(if is_selected {
            theme::accent()
        } else {
            theme::border()
        });

    let mut lines = vec![Line::from(vec![
        icon,
        Span::styled(title, title_style),
    ])];
    lines.extend(description.iter().cloned());

    let paragraph = Paragraph::new(lines).block(block);
    f.render_widget(paragraph, area);
}

fn wallet_description(state: &MinerState) -> Vec<Line<'static>> {
    let setup = &state.setup_status;
    if !setup.checked {
        return vec![Line::from(Span::styled(
            "      Connecting to chain...",
            theme::placeholder(),
        ))];
    }

    let addr_display = if state.address.len() > 10 {
        format!("{}...{}", &state.address[..6], &state.address[state.address.len() - 4..])
    } else if state.address.is_empty() {
        "N/A".to_string()
    } else {
        state.address.clone()
    };

    let eth_str = format_token_amount(state.eth_balance);
    let eth_style = if setup.has_gas { theme::positive() } else { theme::error() };
    let gas_note = if setup.has_gas {
        String::new()
    } else {
        " (need ETH for gas fees)".to_string()
    };

    vec![Line::from(vec![
        Span::styled("      ", theme::dim()),
        Span::styled(addr_display, theme::identifier()),
        Span::styled("  ETH: ", theme::dim()),
        Span::styled(eth_str, eth_style),
        Span::styled(gas_note, theme::error()),
    ])]
}

fn tokens_description(state: &MinerState) -> Vec<Line<'static>> {
    let setup = &state.setup_status;
    if !setup.checked {
        return vec![Line::from(Span::styled(
            "      Waiting...",
            theme::placeholder(),
        ))];
    }

    let balance_str = format_token_amount(state.hemi_balance);
    let balance_style = if setup.has_hemi { theme::positive() } else { theme::warning() };

    let mut spans = vec![
        Span::styled("      Balance: ", theme::dim()),
        Span::styled(format!("{balance_str} $HEMI"), balance_style),
    ];

    if !setup.has_hemi && setup.is_testnet {
        spans.push(Span::styled("  |  Press ", theme::dim()));
        spans.push(Span::styled("[m]", theme::accent()));
        spans.push(Span::styled(" to mint 1000 tHEMI", theme::dim()));
    } else if !setup.has_hemi {
        spans.push(Span::styled("  |  Transfer HEMI tokens to your wallet", theme::dim()));
    }

    vec![Line::from(spans)]
}

fn stake_description(state: &MinerState) -> Vec<Line<'static>> {
    let setup = &state.setup_status;
    if !setup.checked {
        return vec![Line::from(Span::styled(
            "      Waiting...",
            theme::placeholder(),
        ))];
    }

    let staked = state
        .stake_info
        .as_ref()
        .map(|s| s.total_staked)
        .unwrap_or(0);
    let staked_str = format_token_amount(staked);
    let staked_style = if setup.has_stake { theme::positive() } else { theme::warning() };
    let min_str = format_token_amount(MIN_STAKE_WEI);

    let mut spans = vec![
        Span::styled("      Staked: ", theme::dim()),
        Span::styled(format!("{staked_str} $HEMI"), staked_style),
        Span::styled(format!(" (min: {min_str})"), theme::dim()),
    ];

    if !setup.has_stake && setup.has_hemi {
        spans.push(Span::styled("  |  Press ", theme::dim()));
        spans.push(Span::styled("[s]", theme::accent()));
        spans.push(Span::styled(" to approve + stake", theme::dim()));
    }

    vec![Line::from(spans)]
}

fn maturity_description(state: &MinerState) -> Vec<Line<'static>> {
    let setup = &state.setup_status;
    if !setup.has_stake {
        return vec![Line::from(Span::styled(
            "      Stake first",
            theme::placeholder(),
        ))];
    }

    if setup.stake_mature {
        vec![Line::from(vec![
            Span::styled("      ", theme::dim()),
            Span::styled("Stake is mature", theme::positive()),
        ])]
    } else {
        vec![Line::from(vec![
            Span::styled("      Waiting... ", theme::dim()),
            Span::styled(
                format!("{}s remaining", setup.staking_age_remaining),
                theme::warning(),
            ),
            Span::styled(" (auto-refreshing)", theme::dim()),
        ])]
    }
}

fn ready_description(state: &MinerState) -> Vec<Line<'static>> {
    let setup = &state.setup_status;
    if setup.is_ready() {
        vec![Line::from(vec![
            Span::styled("      ", theme::dim()),
            Span::styled("Press ", theme::dim()),
            Span::styled("[Enter]", theme::accent()),
            Span::styled(" to start proving!", theme::dim()),
        ])]
    } else {
        vec![Line::from(Span::styled(
            "      Complete the steps above",
            theme::placeholder(),
        ))]
    }
}

fn render_action_bar(f: &mut Frame, area: Rect, state: &MinerState) {
    let setup = &state.setup_status;

    let mut spans: Vec<Span> = Vec::new();

    // Show pending action or error
    if let Some(action) = &setup.pending_action {
        spans.push(Span::styled(format!(" {action} "), theme::warning()));
    } else if let Some(err) = &setup.last_error {
        spans.push(Span::styled(format!(" Error: {err} "), theme::error()));
    } else {
        // Keybind hints
        if setup.is_testnet && !setup.has_hemi {
            spans.extend(theme::status_keybind("m", ":mint  "));
        }
        if setup.has_hemi && !setup.has_stake {
            spans.extend(theme::status_keybind("s", ":stake  "));
        }
        if setup.is_ready() {
            spans.extend(theme::status_keybind("Enter", ":start  "));
        }
        spans.extend(theme::status_keybind("Esc", ":skip  "));
        spans.extend(theme::status_keybind("4", ":wallet  "));
    }

    let paragraph = Paragraph::new(Line::from(spans));
    f.render_widget(paragraph, area);
}

/// Returns the setup action (if any) for a key press on the Setup screen.
/// This is called from `handle_key` in app.rs.
pub enum SetupAction {
    None,
    /// Dismiss the wizard and go to Dashboard.
    Dismiss,
    /// Mint testnet tokens.
    MintTokens,
    /// Approve + stake HEMI.
    ApproveAndStake,
    /// Navigate up in steps.
    NavigateUp,
    /// Navigate down in steps.
    NavigateDown,
}

/// Handle a key press on the setup screen.
pub fn handle_setup_key(
    state: &mut MinerState,
    key: crossterm::event::KeyCode,
) -> SetupAction {
    match key {
        crossterm::event::KeyCode::Esc => {
            state.setup_status.dismissed = true;
            SetupAction::Dismiss
        }
        crossterm::event::KeyCode::Enter => {
            if state.setup_status.is_ready() {
                state.setup_status.dismissed = true;
                SetupAction::Dismiss
            } else {
                SetupAction::None
            }
        }
        crossterm::event::KeyCode::Char('m') | crossterm::event::KeyCode::Char('M') => {
            if state.setup_status.is_testnet
                && !state.setup_status.has_hemi
                && state.setup_status.pending_action.is_none()
            {
                state.setup_status.pending_action =
                    Some("Minting tHEMI tokens...".to_string());
                state.setup_status.last_error = None;
                SetupAction::MintTokens
            } else {
                SetupAction::None
            }
        }
        crossterm::event::KeyCode::Char('s') | crossterm::event::KeyCode::Char('S') => {
            if state.setup_status.has_hemi
                && !state.setup_status.has_stake
                && state.setup_status.pending_action.is_none()
            {
                state.setup_status.pending_action =
                    Some("Approving + staking HEMI...".to_string());
                state.setup_status.last_error = None;
                SetupAction::ApproveAndStake
            } else {
                SetupAction::None
            }
        }
        crossterm::event::KeyCode::Up | crossterm::event::KeyCode::Char('k') => {
            state.setup_status.selected_step =
                state.setup_status.selected_step.saturating_sub(1);
            SetupAction::NavigateUp
        }
        crossterm::event::KeyCode::Down | crossterm::event::KeyCode::Char('j') => {
            state.setup_status.selected_step =
                (state.setup_status.selected_step + 1).min(TOTAL_STEPS - 1);
            SetupAction::NavigateDown
        }
        _ => SetupAction::None,
    }
}
