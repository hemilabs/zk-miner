//! The reference guest of plan §12 (`PROXY_SLOTS_ELF`, `PROXY_SLOTS_ID`), the lint control guest
//! (`LINT_CONTROL_ELF`) and a guest whose journal depends on host inputs (`HOSTDEP_ELF`, for
//! `simulate --adversarial`'s tests), built by risc0-build. The tests run the guest on the risc0 executor
//! (`tests/executor.rs`), end to end behind the real builder runner and broker
//! (`tests/anvil_e2e.rs`), and check the guest lints (`tests/guest_lints.rs`).
//!
//! The image id depends on the build: a local build embeds this checkout's paths. A requester
//! publishes the id of a reproducible (Docker) build; see ../README.md.

include!(concat!(env!("OUT_DIR"), "/methods.rs"));
