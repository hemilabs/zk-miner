use ratatui::{
    style::Style,
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem},
    Frame,
};

use crate::state::{LogLevel, MinerState};
use crate::theme;

pub fn render(f: &mut Frame, area: ratatui::layout::Rect, state: &MinerState) {
    let filtered: Vec<&crate::state::ActivityEntry> = state.activity_log
        .iter()
        .filter(|entry| {
            if let Some(filter) = &state.log_filter {
                entry.message.to_lowercase().contains(&filter.to_lowercase())
            } else {
                true
            }
        })
        .collect();

    let visible_height = area.height.saturating_sub(3) as usize;
    let start = if filtered.len() > visible_height + state.log_scroll {
        filtered.len() - visible_height - state.log_scroll
    } else {
        0
    };
    let end = (start + visible_height).min(filtered.len());

    let items: Vec<ListItem> = filtered[start..end]
        .iter()
        .map(|entry| {
            let color = match entry.level {
                LogLevel::Info => theme::text(),
                LogLevel::Warn => theme::yellow(),
                LogLevel::Error => theme::red(),
                LogLevel::Success => theme::green(),
            };

            let level_str = match entry.level {
                LogLevel::Info => "INFO ",
                LogLevel::Warn => "WARN ",
                LogLevel::Error => "ERROR",
                LogLevel::Success => " OK  ",
            };

            let time = entry.timestamp.format("%H:%M:%S%.3f").to_string();
            ListItem::new(Line::from(vec![
                Span::styled(
                    format!("{} ", time),
                    theme::dim(),
                ),
                Span::styled(
                    format!("[{}] ", level_str),
                    Style::default().fg(color),
                ),
                Span::raw(&entry.message),
            ]))
        })
        .collect();

    let title = if let Some(filter) = &state.log_filter {
        format!(" Logs (filter: '{}') — {}/{} ", filter, items.len(), state.activity_log.len())
    } else {
        format!(" Logs — {} entries ", state.activity_log.len())
    };

    let block = Block::default()
        .title(Span::styled(title, theme::title()))
        .borders(Borders::ALL)
        .border_style(theme::border())
        .border_type(theme::border_type());

    let list = List::new(items).block(block);
    f.render_widget(list, area);
}
