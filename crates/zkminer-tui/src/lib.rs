pub mod app;
pub mod event;
pub mod gpu_tuning;
pub mod hardware;
pub mod nvml;
pub mod progress;
pub mod screens;
pub mod splash;
pub mod state;
pub mod theme;
#[cfg(windows)]
mod windows_gpus;

pub use app::{restore_terminal, run_tui, start_benchmark_if_incomplete};
pub use state::{new_shared_state, MinerState, SharedState, TuiContext};
