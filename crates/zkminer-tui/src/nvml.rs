//! Shared NVML singleton for GPU monitoring and tuning.
//!
//! A single `Nvml` instance is initialized lazily on first use and shared
//! across the entire process. This avoids the overhead and potential issues
//! of multiple `nvmlInit_v2()` calls.

use std::sync::OnceLock;

static NVML: OnceLock<Option<nvml_wrapper::Nvml>> = OnceLock::new();

/// Get a reference to the global NVML instance, or None if unavailable.
///
/// Set `ZKMINER_NO_NVML=1` to disable NVML entirely (uses sysfs-only
/// monitoring for NVIDIA GPUs). Useful in VMs where NVML ioctls cause
/// kernel stalls.
pub fn nvml() -> Option<&'static nvml_wrapper::Nvml> {
    NVML.get_or_init(|| {
        if std::env::var("ZKMINER_NO_NVML").is_ok() {
            tracing::info!("NVML disabled via ZKMINER_NO_NVML");
            return None;
        }
        match nvml_wrapper::Nvml::init() {
            Ok(nvml) => Some(nvml),
            Err(e) => {
                tracing::warn!("NVML init failed (no NVIDIA driver?): {e}");
                None
            }
        }
    })
    .as_ref()
}
