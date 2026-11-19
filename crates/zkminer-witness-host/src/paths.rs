//! Where the sandboxed binaries live: configured paths, or next to the running `zkminer` binary.

use std::path::{Path, PathBuf};

pub const BUILDER_BINARY: &str = "zkminer-witness-builder";
pub const BROKER_BINARY: &str = "zkminer-witness-broker";
pub const EXECUTE_BINARY: &str = "zkminer-prove-risc0-cpu";

/// `configured`, or `name` in the directory of the current executable.
pub fn binary(configured: Option<&Path>, name: &str) -> std::io::Result<PathBuf> {
    if let Some(p) = configured {
        return Ok(p.to_path_buf());
    }
    let exe = std::env::current_exe()?;
    let dir = exe.parent().ok_or_else(|| std::io::Error::other("the executable has no directory"))?;
    Ok(dir.join(name))
}
