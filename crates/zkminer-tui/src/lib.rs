pub mod app;
pub mod event;
pub mod gpu_tuning;
pub mod hardware;
pub mod nvml;
pub mod screens;
pub mod splash;
pub mod state;
pub mod theme;
#[cfg(windows)]
mod windows_gpus;
#[cfg(windows)]
mod windows_telemetry;

pub use app::{run_tui, start_benchmark_if_incomplete};
pub use state::{new_shared_state, MinerState, SharedState, TuiContext};
