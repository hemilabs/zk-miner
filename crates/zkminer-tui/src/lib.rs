pub mod app;
pub mod event;
pub mod gpu_tuning;
pub mod hardware;
pub mod nvml;
pub mod screens;
pub mod state;
pub mod theme;

pub use app::run_tui;
pub use state::{new_shared_state, MinerState, SharedState, TuiContext};
