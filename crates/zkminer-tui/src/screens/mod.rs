pub mod dashboard;
pub mod jobs;
pub mod job_detail;
pub mod wallet;
pub mod benchmark;
pub mod logs;
pub mod settings;
pub mod setup;

use ratatui::Frame;
use crate::state::MinerState;

/// Trait for renderable screens.
pub trait ScreenRenderer {
    fn render(&self, f: &mut Frame, state: &MinerState);
}
