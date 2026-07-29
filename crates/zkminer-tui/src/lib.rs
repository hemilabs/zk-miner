pub mod app;
pub mod gpu_tuning;
pub mod hardware;
pub mod nvml;
pub mod screens;
pub mod state;
pub mod event;
pub mod theme;

pub use app::run_tui;
pub use state::{MinerState, SharedState, TuiContext, new_shared_state};
