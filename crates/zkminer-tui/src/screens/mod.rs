pub mod benchmark;
pub mod dashboard;
pub mod job_detail;
pub mod jobs;
pub mod logs;
pub mod settings;
pub mod setup;
pub mod wallet;

use crate::state::MinerState;
use ratatui::Frame;

/// Trait for renderable screens.
pub trait ScreenRenderer {
    fn render(&self, f: &mut Frame, state: &MinerState);
}
