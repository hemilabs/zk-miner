//! Centralized color palette and semantic styles for the zkminer TUI.
//!
//! Supports 8 switchable themes with automatic 16-color fallback
//! for terminals that do not support 24-bit RGB.
//!
//! Press `T` in the TUI to cycle themes.

use ratatui::style::{Color, Modifier, Style};
use ratatui::text::Span;
use ratatui::widgets::BorderType;
use std::sync::atomic::{AtomicUsize, Ordering};


// ---------------------------------------------------------------------------
// Theme identification
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThemeId {
    TokyoNight,
    Mocha,
    Phosphor,
    Cyberpunk,
    Kanagawa,
    HighContrast,
}

impl ThemeId {
    pub fn name(&self) -> &'static str {
        match self {
            Self::TokyoNight => "Tokyo Night",
            Self::Mocha => "Catppuccin Mocha",
            Self::Phosphor => "Phosphor",
            Self::Cyberpunk => "Cyberpunk",
            Self::Kanagawa => "Kanagawa",
            Self::HighContrast => "High Contrast",
        }
    }
}

const THEME_ORDER: &[ThemeId] = &[
    ThemeId::TokyoNight,
    ThemeId::Mocha,
    ThemeId::Phosphor,
    ThemeId::Cyberpunk,
    ThemeId::Kanagawa,
    ThemeId::HighContrast,
];

static ACTIVE_THEME_IDX: AtomicUsize = AtomicUsize::new(0);

pub fn active_theme() -> ThemeId {
    THEME_ORDER[ACTIVE_THEME_IDX.load(Ordering::Relaxed) % THEME_ORDER.len()]
}

pub fn cycle_theme() -> ThemeId {
    let next = (ACTIVE_THEME_IDX.load(Ordering::Relaxed) + 1) % THEME_ORDER.len();
    ACTIVE_THEME_IDX.store(next, Ordering::Relaxed);
    THEME_ORDER[next]
}

pub fn set_theme(theme: ThemeId) {
    let idx = THEME_ORDER.iter().position(|t| *t == theme).unwrap_or(0);
    ACTIVE_THEME_IDX.store(idx, Ordering::Relaxed);
}

// ---------------------------------------------------------------------------
// Progress bar style
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProgressStyle {
    /// Unicode block elements with sub-character precision.
    Block,
    /// ASCII `====>------` retro terminal style.
    Ascii,
    /// Filled/empty circles: `●●●●●○○○○○`.
    Dot,
}

// ---------------------------------------------------------------------------
// Palette definition
// ---------------------------------------------------------------------------

struct Palette {
    // Background tones
    base: (u8, u8, u8),
    surface: (u8, u8, u8),
    overlay: (u8, u8, u8),
    subtext: (u8, u8, u8),
    text: (u8, u8, u8),

    // Status bar background
    status_bar: (u8, u8, u8),

    // Default border color — visible, theme-tinted
    border_dim: (u8, u8, u8),

    // Badge/tab foreground (always contrasts colored backgrounds)
    badge_fg: (u8, u8, u8),

    // Accent colors
    primary: (u8, u8, u8),     // focused borders, interactive elements
    secondary: (u8, u8, u8),   // identifiers (addresses, IDs)
    tertiary: (u8, u8, u8),    // secondary accents (GPU labels, backends)
    title_color: (u8, u8, u8), // panel titles
    highlight: (u8, u8, u8),   // tertiary highlight

    // Semantic
    green: (u8, u8, u8),
    yellow: (u8, u8, u8),
    red: (u8, u8, u8),
    metric_color: (u8, u8, u8), // key numbers (zkOP/s, throughput)

    // Row stripe
    stripe: (u8, u8, u8),

    // Visual style
    border: BorderType,
    progress: ProgressStyle,
}

// ---------------------------------------------------------------------------
// Theme palettes
// ---------------------------------------------------------------------------

/// Catppuccin Mocha — warm pastels on deep purple-blue base.
/// The cozy default. Rounded lavender borders, warm peach metrics.
const MOCHA: Palette = Palette {
    base:         (30, 30, 46),
    surface:      (49, 50, 68),
    overlay:      (69, 71, 90),
    subtext:      (127, 132, 156),
    text:         (205, 214, 244),
    status_bar:   (24, 24, 37),
    border_dim:   (88, 91, 112),    // visible muted lavender-gray
    badge_fg:     (30, 30, 46),
    primary:      (180, 190, 254),  // lavender
    secondary:    (137, 180, 250),  // blue
    tertiary:     (203, 166, 247),  // mauve
    title_color:  (137, 220, 235),  // sky
    highlight:    (148, 226, 213),  // teal
    green:        (166, 227, 161),
    yellow:       (249, 226, 175),
    red:          (243, 139, 168),
    metric_color: (250, 179, 135),  // peach
    stripe:       (35, 35, 52),
    border:       BorderType::Rounded,
    progress:     ProgressStyle::Block,
};

/// Phosphor — green-on-black CRT terminal. Maximum retro.
/// Monochrome green with amber warnings. ASCII progress bars.
const PHOSPHOR: Palette = Palette {
    base:         (0, 0, 0),
    surface:      (0, 24, 0),
    overlay:      (0, 45, 0),
    subtext:      (0, 120, 0),
    text:         (0, 255, 0),
    status_bar:   (0, 15, 0),
    border_dim:   (0, 160, 0),      // bright green borders
    badge_fg:     (0, 0, 0),
    primary:      (50, 255, 50),    // bright green
    secondary:    (0, 200, 100),    // green-teal
    tertiary:     (0, 220, 0),      // green
    title_color:  (100, 255, 100),  // bright green
    highlight:    (150, 255, 150),
    green:        (0, 255, 0),
    yellow:       (255, 180, 0),    // amber
    red:          (255, 0, 0),
    metric_color: (255, 200, 0),    // amber/gold
    stripe:       (0, 10, 0),
    border:       BorderType::Plain,
    progress:     ProgressStyle::Ascii,
};

/// Cyberpunk — neon hot pink and electric cyan on jet black.
/// Maximum saturation. Bladerunner vibes.
const CYBERPUNK: Palette = Palette {
    base:         (8, 8, 16),       // near-black with blue tint
    surface:      (18, 18, 32),
    overlay:      (35, 35, 55),
    subtext:      (120, 110, 140),  // muted purple-gray
    text:         (230, 225, 240),  // cool white
    status_bar:   (12, 0, 20),      // deep purple-black
    border_dim:   (255, 0, 128),    // HOT PINK borders
    badge_fg:     (8, 8, 16),
    primary:      (0, 255, 255),    // electric cyan
    secondary:    (255, 0, 128),    // hot pink
    tertiary:     (180, 0, 255),    // electric purple
    title_color:  (0, 255, 255),    // cyan
    highlight:    (0, 255, 180),    // neon mint
    green:        (0, 255, 65),     // neon green
    yellow:       (255, 255, 0),    // neon yellow
    red:          (255, 0, 60),     // neon red
    metric_color: (255, 0, 200),    // neon magenta
    stripe:       (14, 14, 28),
    border:       BorderType::Rounded,
    progress:     ProgressStyle::Dot,
};

/// Tokyo Night — deep blue-black with neon blue and purple accents.
/// Modern IDE aesthetic. Blue-tinted everything.
const TOKYO_NIGHT: Palette = Palette {
    base:         (26, 27, 38),     // bg
    surface:      (36, 40, 59),     // bg_highlight
    overlay:      (55, 59, 78),
    subtext:      (86, 95, 137),    // muted blue
    text:         (192, 202, 245),  // light blue-white
    status_bar:   (22, 22, 30),     // bg_dark
    border_dim:   (61, 89, 161),    // visible blue borders
    badge_fg:     (26, 27, 38),
    primary:      (122, 162, 247),  // bright blue
    secondary:    (187, 154, 247),  // purple
    tertiary:     (255, 117, 127),  // pink-red
    title_color:  (125, 207, 255),  // sky blue
    highlight:    (115, 218, 202),  // teal
    green:        (158, 206, 106),
    yellow:       (224, 175, 104),
    red:          (247, 118, 142),
    metric_color: (255, 158, 100),  // orange
    stripe:       (33, 35, 50),
    border:       BorderType::Rounded,
    progress:     ProgressStyle::Block,
};

/// Kanagawa — inspired by Japanese ink painting and the Great Wave.
/// Deep indigo base, old gold titles, sakura pink accents, warm whites.
const KANAGAWA: Palette = Palette {
    base:         (22, 22, 29),     // sumiInk0
    surface:      (30, 30, 41),     // sumiInk1
    overlay:      (54, 54, 70),     // sumiInk3
    subtext:      (114, 113, 105),  // fujiGray
    text:         (220, 215, 186),  // fujiWhite — warm ivory
    status_bar:   (18, 18, 23),     // sumiInk0 darker
    border_dim:   (84, 84, 109),    // slate-purple borders
    badge_fg:     (22, 22, 29),
    primary:      (126, 156, 216),  // crystalBlue
    secondary:    (149, 127, 184),  // oniViolet
    tertiary:     (210, 126, 153),  // sakuraPink
    title_color:  (192, 163, 110),  // carpYellow — old gold titles
    highlight:    (106, 149, 137),  // waveAqua
    green:        (152, 187, 108),  // springGreen
    yellow:       (192, 163, 110),  // carpYellow
    red:          (195, 64, 67),    // autumnRed
    metric_color: (255, 160, 102),  // surimiOrange
    stripe:       (27, 27, 36),
    border:       BorderType::Plain,
    progress:     ProgressStyle::Dot,
};

/// High Contrast — maximum readability. Pure black, bright white, vivid primaries.
/// Accessibility-first. Cyan borders for structural visibility.
const HIGH_CONTRAST: Palette = Palette {
    base:         (0, 0, 0),        // pure black
    surface:      (25, 25, 25),
    overlay:      (60, 60, 60),
    subtext:      (180, 180, 180),  // bright gray
    text:         (255, 255, 255),  // pure white
    status_bar:   (0, 40, 50),      // dark teal bar
    border_dim:   (0, 190, 210),    // bright cyan borders
    badge_fg:     (0, 0, 0),
    primary:      (100, 160, 255),  // bright blue
    secondary:    (200, 120, 255),  // bright purple
    tertiary:     (255, 120, 200),  // bright pink
    title_color:  (0, 220, 240),    // bright cyan
    highlight:    (100, 255, 220),  // bright mint
    green:        (0, 230, 0),      // vivid green
    yellow:       (255, 230, 0),    // vivid yellow
    red:          (255, 60, 60),    // vivid red
    metric_color: (255, 190, 0),    // vivid orange
    stripe:       (18, 18, 18),
    border:       BorderType::Double,
    progress:     ProgressStyle::Block,
};

const PALETTES: &[Palette] = &[
    TOKYO_NIGHT, MOCHA,
    PHOSPHOR, CYBERPUNK,
    KANAGAWA, HIGH_CONTRAST,
];

fn pal() -> &'static Palette {
    &PALETTES[ACTIVE_THEME_IDX.load(Ordering::Relaxed) % PALETTES.len()]
}

// ---------------------------------------------------------------------------
// Color helpers
// ---------------------------------------------------------------------------

/// Terminal color capability level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ColorMode {
    /// 24-bit RGB (COLORTERM=truecolor/24bit)
    TrueColor,
    /// xterm-256color palette (most terminals including screen-256color)
    Color256,
    /// Basic 16 ANSI colors
    Basic,
}

fn detect_color_mode() -> ColorMode {
    use std::sync::OnceLock;
    static MODE: OnceLock<ColorMode> = OnceLock::new();
    *MODE.get_or_init(|| {
        // Explicit truecolor/non-truecolor override
        if let Ok(ct) = std::env::var("COLORTERM") {
            if matches!(ct.as_str(), "truecolor" | "24bit") {
                return ColorMode::TrueColor;
            }
        }

        let term = std::env::var("TERM").unwrap_or_default();

        // GNU screen and tmux don't reliably pass through 24-bit RGB sequences.
        // Use 256-color approximation instead.
        if term.starts_with("screen") || term.starts_with("tmux") {
            return ColorMode::Color256;
        }

        // Most modern terminals (xterm-256color, alacritty, kitty, wezterm,
        // gnome-terminal, etc.) support 24-bit RGB even without COLORTERM.
        // Default to truecolor.
        ColorMode::TrueColor
    })
}

/// Convert RGB to the nearest xterm-256 color index.
///
/// Compares the input against both the 6×6×6 color cube (indices 16-231)
/// and the 24-step grayscale ramp (232-255), returning whichever is closest
/// by squared Euclidean distance. This avoids the dark-blue artifacts that
/// occur when Catppuccin's slightly-tinted dark grays land in the blue
/// column of the coarse color cube.
fn rgb_to_256(r: u8, g: u8, b: u8) -> u8 {
    // The 6 cube axis values: 0, 95, 135, 175, 215, 255
    const CUBE: [u8; 6] = [0, 95, 135, 175, 215, 255];

    fn nearest_cube_idx(v: u8) -> usize {
        let mut best = 0;
        let mut best_d = 255i32;
        for (i, &c) in CUBE.iter().enumerate() {
            let d = (v as i32 - c as i32).abs();
            if d < best_d {
                best_d = d;
                best = i;
            }
        }
        best
    }

    fn sq_dist(r1: u8, g1: u8, b1: u8, r2: u8, g2: u8, b2: u8) -> u32 {
        let dr = r1 as i32 - r2 as i32;
        let dg = g1 as i32 - g2 as i32;
        let db = b1 as i32 - b2 as i32;
        (dr * dr + dg * dg + db * db) as u32
    }

    // Best match in the 6×6×6 cube
    let ri = nearest_cube_idx(r);
    let gi = nearest_cube_idx(g);
    let bi = nearest_cube_idx(b);
    let cube_idx = 16 + 36 * ri + 6 * gi + bi;
    let cube_dist = sq_dist(r, g, b, CUBE[ri], CUBE[gi], CUBE[bi]);

    // Best match in the grayscale ramp (232-255): values 8, 18, 28, ..., 238
    let gray_avg = (r as u16 + g as u16 + b as u16) / 3;
    let gray_step = if gray_avg <= 3 {
        0
    } else if gray_avg >= 243 {
        23
    } else {
        ((gray_avg - 8 + 5) / 10) as usize // round to nearest step
    };
    let gray_val = (8 + 10 * gray_step) as u8;
    let gray_idx = 232 + gray_step;
    let gray_dist = sq_dist(r, g, b, gray_val, gray_val, gray_val);

    if gray_dist < cube_dist {
        gray_idx as u8
    } else {
        cube_idx as u8
    }
}

fn rgb(color: (u8, u8, u8), fallback: Color) -> Color {
    match detect_color_mode() {
        ColorMode::TrueColor => Color::Rgb(color.0, color.1, color.2),
        ColorMode::Color256 => Color::Indexed(rgb_to_256(color.0, color.1, color.2)),
        ColorMode::Basic => fallback,
    }
}

// ---------------------------------------------------------------------------
// Base palette colors
// ---------------------------------------------------------------------------

pub fn base() -> Color {
    rgb(pal().base, Color::Black)
}

pub fn surface() -> Color {
    rgb(pal().surface, Color::DarkGray)
}

pub fn overlay() -> Color {
    rgb(pal().overlay, Color::DarkGray)
}

pub fn subtext() -> Color {
    rgb(pal().subtext, Color::DarkGray)
}

pub fn text() -> Color {
    rgb(pal().text, Color::White)
}

pub fn lavender() -> Color {
    rgb(pal().primary, Color::Blue)
}

pub fn blue() -> Color {
    rgb(pal().secondary, Color::Cyan)
}

pub fn green() -> Color {
    rgb(pal().green, Color::Green)
}

pub fn yellow() -> Color {
    rgb(pal().yellow, Color::Yellow)
}

pub fn red() -> Color {
    rgb(pal().red, Color::Red)
}

pub fn peach() -> Color {
    rgb(pal().metric_color, Color::Yellow)
}

pub fn mauve() -> Color {
    rgb(pal().tertiary, Color::Magenta)
}

pub fn sky() -> Color {
    rgb(pal().title_color, Color::LightCyan)
}

pub fn teal() -> Color {
    rgb(pal().highlight, Color::Cyan)
}

fn status_bar_bg() -> Color {
    rgb(pal().status_bar, Color::Black)
}

fn border_dim() -> Color {
    rgb(pal().border_dim, Color::Gray)
}

fn badge_fg() -> Color {
    rgb(pal().badge_fg, Color::Black)
}

// ---------------------------------------------------------------------------
// Full-screen canvas & semantic styles
// ---------------------------------------------------------------------------

/// Style to paint the entire terminal background. Render a Block with this
/// style over `f.area()` at the very start of `draw()`.
pub fn canvas() -> Style {
    Style::default().bg(base()).fg(text())
}

/// Style for the tab bar background.
pub fn tab_bar_bg() -> Style {
    Style::default().bg(base()).fg(text())
}

/// Style for the status bar background.
pub fn status_bar() -> Style {
    Style::default().bg(status_bar_bg()).fg(text())
}

/// Panel/section title.
pub fn title() -> Style {
    Style::default().fg(sky()).add_modifier(Modifier::BOLD)
}

/// Default (muted) border — theme-tinted, visible.
pub fn border() -> Style {
    Style::default().fg(border_dim())
}

/// Focused / highlighted border.
pub fn border_focused() -> Style {
    Style::default().fg(lavender())
}

/// Border type for the active theme (Plain, Rounded, Double).
pub fn border_type() -> BorderType {
    pal().border
}

/// Table header row.
pub fn table_header() -> Style {
    Style::default().fg(subtext()).add_modifier(Modifier::BOLD)
}

/// Dim / secondary text (separators, labels, timestamps).
pub fn dim() -> Style {
    Style::default().fg(subtext())
}

/// Identifiers: addresses, job IDs, descriptor hashes.
pub fn identifier() -> Style {
    Style::default().fg(blue())
}

/// Positive values: balances, available collateral, fulfilled counts.
pub fn positive() -> Style {
    Style::default().fg(green())
}

/// Highlighted metrics: zkOP/s, throughput, prices. Used sparingly.
pub fn metric() -> Style {
    Style::default().fg(peach()).add_modifier(Modifier::BOLD)
}

/// Warning text/values.
pub fn warning() -> Style {
    Style::default().fg(yellow())
}

/// Error text/values.
pub fn error() -> Style {
    Style::default().fg(red())
}

/// Secondary accent: GPU labels, locked amounts, backend names.
pub fn accent() -> Style {
    Style::default().fg(mauve())
}

/// Loading / placeholder text.
pub fn placeholder() -> Style {
    Style::default().fg(subtext()).add_modifier(Modifier::ITALIC)
}

/// Separator string (" | ").
pub fn separator() -> Style {
    Style::default().fg(overlay())
}

/// Bold text for emphasis within content.
pub fn bold() -> Style {
    Style::default().fg(text()).add_modifier(Modifier::BOLD)
}

// ---------------------------------------------------------------------------
// Status badges
// ---------------------------------------------------------------------------

pub fn badge_ok() -> Style {
    Style::default()
        .fg(badge_fg())
        .bg(green())
        .add_modifier(Modifier::BOLD)
}

pub fn badge_error() -> Style {
    Style::default()
        .fg(badge_fg())
        .bg(red())
        .add_modifier(Modifier::BOLD)
}

pub fn badge_warn() -> Style {
    Style::default()
        .fg(badge_fg())
        .bg(yellow())
        .add_modifier(Modifier::BOLD)
}

// ---------------------------------------------------------------------------
// Tab bar
// ---------------------------------------------------------------------------

pub fn tab_active() -> Style {
    Style::default()
        .fg(badge_fg())
        .bg(sky())
        .add_modifier(Modifier::BOLD)
}

pub fn tab_inactive() -> Style {
    Style::default().fg(text())
}

pub fn tab_inactive_num() -> Style {
    Style::default().fg(subtext())
}

// ---------------------------------------------------------------------------
// Row striping
// ---------------------------------------------------------------------------

/// Background color for odd table rows (subtle stripe).
pub fn stripe_bg() -> Color {
    rgb(pal().stripe, Color::Reset)
}

/// Apply striped background to a style based on row index.
pub fn striped(row_index: usize) -> Style {
    if row_index % 2 == 1 {
        Style::default().bg(stripe_bg())
    } else {
        Style::default()
    }
}

// ---------------------------------------------------------------------------
// Usage-based coloring (temps, utilization, stake %)
// ---------------------------------------------------------------------------

pub fn usage_color(pct: u32) -> Color {
    if pct >= 90 {
        red()
    } else if pct >= 70 {
        yellow()
    } else {
        green()
    }
}

// ---------------------------------------------------------------------------
// Unicode progress bar
// ---------------------------------------------------------------------------

/// Render a progress bar. Returns (filled_span_text, empty_span_text).
/// Style varies per theme: block elements, ASCII, or dot circles.
pub fn progress_bar(ratio: f64, width: usize) -> (String, String) {
    match pal().progress {
        ProgressStyle::Block => progress_bar_block(ratio, width),
        ProgressStyle::Ascii => progress_bar_ascii(ratio, width),
        ProgressStyle::Dot => progress_bar_dot(ratio, width),
    }
}

fn progress_bar_block(ratio: f64, width: usize) -> (String, String) {
    let total_eighths = (ratio.clamp(0.0, 1.0) * width as f64 * 8.0).round() as usize;
    let full_blocks = total_eighths / 8;
    let remainder = total_eighths % 8;

    let fractional = match remainder {
        7 => "\u{2589}",
        6 => "\u{258a}",
        5 => "\u{258b}",
        4 => "\u{258c}",
        3 => "\u{258d}",
        2 => "\u{258e}",
        1 => "\u{258f}",
        _ => "",
    };

    let frac_width = if remainder > 0 { 1 } else { 0 };
    let empty = width.saturating_sub(full_blocks).saturating_sub(frac_width);

    let filled = format!("{}{}", "\u{2588}".repeat(full_blocks), fractional);
    let blank = " ".repeat(empty);
    (filled, blank)
}

fn progress_bar_ascii(ratio: f64, width: usize) -> (String, String) {
    let filled_count = (ratio.clamp(0.0, 1.0) * width as f64).round() as usize;
    let empty_count = width.saturating_sub(filled_count);
    let filled = if filled_count == 0 {
        String::new()
    } else if filled_count >= width {
        "=".repeat(width)
    } else {
        format!("{}>", "=".repeat(filled_count - 1))
    };
    let blank = "-".repeat(empty_count);
    (filled, blank)
}

fn progress_bar_dot(ratio: f64, width: usize) -> (String, String) {
    let filled_count = (ratio.clamp(0.0, 1.0) * width as f64).round() as usize;
    let empty_count = width.saturating_sub(filled_count);
    let filled = "\u{25cf}".repeat(filled_count); // ●
    let blank = "\u{25cb}".repeat(empty_count);    // ○
    (filled, blank)
}

// ---------------------------------------------------------------------------
// Brand colors (constant across themes)
// ---------------------------------------------------------------------------

/// AMD brand color (Catppuccin Flamingo — warm pink, avoids error-red).
pub fn amd_red() -> Color {
    rgb((242, 205, 205), Color::LightMagenta)
}

/// NVIDIA brand green.
pub fn nvidia_green() -> Color {
    rgb((118, 185, 0), Color::Green)
}

/// Intel brand blue.
pub fn intel_blue() -> Color {
    rgb((0, 104, 181), Color::Blue)
}

/// RISC Zero brand purple.
pub fn risc0_purple() -> Color {
    rgb((147, 112, 219), Color::Magenta)
}

/// SP1 / Succinct brand orange.
pub fn sp1_orange() -> Color {
    rgb((255, 165, 0), Color::Yellow)
}

/// OpenVM brand cyan.
pub fn openvm_cyan() -> Color {
    rgb((0, 210, 211), Color::Cyan)
}

// ---------------------------------------------------------------------------
// Keybind hint formatting
// ---------------------------------------------------------------------------

/// Format a keybind hint like "[b] Run" with the key in peach and label dim.
pub fn keybind<'a>(key: &'a str, label: &'a str) -> Vec<Span<'a>> {
    vec![
        Span::styled(key, Style::default().fg(peach())),
        Span::styled(label, dim()),
    ]
}

/// Format a status-bar keybind like "q:quit" with key highlighted.
pub fn status_keybind<'a>(key: &'a str, label: &'a str) -> Vec<Span<'a>> {
    vec![
        Span::styled(key, Style::default().fg(peach())),
        Span::styled(label, Style::default().fg(text())),
    ]
}
