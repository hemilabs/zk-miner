use alloy::signers::local::PrivateKeySigner;
use anyhow::{bail, Context, Result};
use zeroize::Zeroizing;

use crate::config::WalletConfig;

/// Load a private key signer based on the wallet configuration.
pub fn load_signer(config: &WalletConfig) -> Result<PrivateKeySigner> {
    match config.key_source.as_str() {
        "env" => load_from_env(&config.key_env_var),
        "file" => load_from_file(config.key_file_path.as_deref()),
        "keystore" => {
            bail!(
                "Keystore loading not yet supported. Use key_source = \"env\" or \"file\" instead."
            );
        }
        other => bail!(
            "Unknown key_source: '{}'. Use 'env', 'file', or 'keystore'",
            other
        ),
    }
}

fn load_from_env(env_var: &str) -> Result<PrivateKeySigner> {
    let key_hex = Zeroizing::new(
        std::env::var(env_var)
            .with_context(|| format!("Environment variable '{}' not set", env_var))?,
    );

    parse_private_key(&key_hex)
}

fn load_from_file(path: Option<&str>) -> Result<PrivateKeySigner> {
    let path = path.context("key_file_path not set in config")?;

    // Check file permissions on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata = std::fs::metadata(path)
            .with_context(|| format!("Failed to read metadata for key file: {}", path))?;
        let mode = metadata.permissions().mode() & 0o777;
        if mode != 0o600 {
            tracing::warn!(
                "Key file {} has permissions {:04o} — should be 0600. \
                 Fix with: chmod 600 {}",
                path,
                mode,
                path,
            );
        }
    }

    let content = Zeroizing::new(
        std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read key file: {}", path))?,
    );

    parse_private_key(content.trim())
}

fn parse_private_key(key_hex: &str) -> Result<PrivateKeySigner> {
    let key_hex = key_hex.trim().strip_prefix("0x").unwrap_or(key_hex.trim());

    let signer: PrivateKeySigner = key_hex.parse().context("Failed to parse private key hex")?;

    Ok(signer)
}
