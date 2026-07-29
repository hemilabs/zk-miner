//! Terminal event handling.

use crossterm::event::{self, Event, KeyEvent};
use std::time::Duration;
use tokio::sync::mpsc;

/// Application-level events.
#[derive(Debug)]
pub enum AppEvent {
    /// A key was pressed.
    Key(KeyEvent),
    /// Periodic tick for refreshing data.
    Tick,
    /// Resize event.
    Resize(u16, u16),
}

/// Spawn a background task that reads terminal events and sends them to a channel.
///
/// Uses `spawn_blocking` so the synchronous `crossterm::event::poll()` call
/// runs on a dedicated OS thread and never blocks tokio worker threads.
pub fn spawn_event_reader(tick_rate: Duration) -> mpsc::Receiver<AppEvent> {
    let (tx, rx) = mpsc::channel(100);

    tokio::task::spawn_blocking(move || {
        loop {
            // Check if there's a crossterm event within the tick interval
            if event::poll(tick_rate).unwrap_or(false) {
                match event::read() {
                    Ok(Event::Key(key)) => {
                        if tx.blocking_send(AppEvent::Key(key)).is_err() {
                            return;
                        }
                    }
                    Ok(Event::Resize(w, h)) => {
                        if tx.blocking_send(AppEvent::Resize(w, h)).is_err() {
                            return;
                        }
                    }
                    _ => {}
                }
            } else {
                // No event within tick_rate → send a tick
                if tx.blocking_send(AppEvent::Tick).is_err() {
                    return;
                }
            }
        }
    });

    rx
}
