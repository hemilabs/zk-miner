//! `sdk/build-reproducible.sh` rebuilds the example builder and the reference builder of plan §12 to
//! exactly the sha256 the SDK README publishes, refuses a toolchain other than the pinned one, and
//! passes the target features of `.cargo/config.toml` (which its flags replace) unchanged.

mod common;

use std::path::Path;
use std::process::Command;

use common::sdk_dir;
use sha2::{Digest, Sha256};

const CHECK: &str = env!("CARGO_BIN_EXE_zkminer-builder-check");

/// The script building `package`, with the variables a caller might have set that it must ignore.
fn script(package: &str, target: &Path) -> Command {
    let mut cmd = Command::new("sh");
    cmd.arg(sdk_dir().join("build-reproducible.sh"))
        .args(["-p", package, "--target-dir"])
        .arg(target)
        .env("ZKMINER_BUILDER_CHECK", CHECK)
        .env("RUSTUP_TOOLCHAIN", "1.93.0")
        .env("RUSTC", "/bin/false")
        .env("RUSTC_WRAPPER", "/bin/false")
        .env("RUSTFLAGS", "-C opt-level=0")
        .env("CARGO_PROFILE_RELEASE_OPT_LEVEL", "0")
        .env("CARGO_ENCODED_RUSTFLAGS", "-Copt-level=1")
        .env("CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUSTFLAGS", "-Ctarget-feature=+simd128")
        .env_remove("CARGO_TARGET_DIR");
    cmd
}

/// The hash and size the README records for the script's build of `package`'s `file`.
fn published(package: &str, file: &str) -> (String, usize) {
    let readme = std::fs::read_to_string(sdk_dir().join("README.md")).unwrap();
    let size = readme
        .split(&format!("sha256 of `{file}` ("))
        .nth(1)
        .and_then(|s| s.split(" bytes)").next())
        .map(|s| s.replace(',', "").parse().unwrap())
        .expect("the README's size column");
    let line = readme.lines().find(|l| l.starts_with(&format!("| `./build-reproducible.sh -p {package}`"))).unwrap();
    let hash = line.split('`').nth(3).expect("the hash in backticks").to_string();
    assert_eq!(hash.len(), 64, "{line}");
    (hash, size)
}

/// Builds `package` with the script in a fresh target dir and checks its module against the README.
fn rebuilds_the_published(package: &str, file: &str) {
    let target = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("sdk-target-reproducible-{package}"));
    let _ = std::fs::remove_dir_all(&target);
    let out = script(package, &target).output().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}");
    // The pre-pass ran on the module.
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains(&format!("{file}: ok:")), "{stdout}");
    let wasm = std::fs::read(target.join("wasm32-unknown-unknown/release").join(file)).unwrap();
    let (hash, size) = published(package, file);
    assert_eq!((hex::encode(Sha256::digest(&wasm)), wasm.len()), (hash, size), "update sdk/README.md");
    let _ = std::fs::remove_dir_all(&target);
}

#[test]
fn the_script_rebuilds_the_published_example() {
    rebuilds_the_published("latest-block", "latest_block.wasm");
}

/// The reference builder links the eth prelude and its statement through the `reference` symlink:
/// its bytes must not depend on where the checkout is.
#[test]
fn the_script_rebuilds_the_published_reference_builder() {
    rebuilds_the_published("proxy-slots-builder", "proxy_slots_builder.wasm");
}

#[test]
fn the_script_refuses_another_toolchain() {
    // A rust-toolchain.toml naming another (installed) release, in a copy of the SDK: its rustc is not
    // the commit the script pins, so the script stops before building anything.
    let copy = Path::new(env!("CARGO_TARGET_TMPDIR")).join("sdk-other-toolchain");
    let _ = std::fs::remove_dir_all(&copy);
    std::fs::create_dir_all(&copy).unwrap();
    std::fs::copy(sdk_dir().join("build-reproducible.sh"), copy.join("build-reproducible.sh")).unwrap();
    std::fs::write(copy.join("rust-toolchain.toml"), "[toolchain]\nchannel = \"1.93.0\"\n").unwrap();
    let out = Command::new("sh")
        .arg(copy.join("build-reproducible.sh"))
        .env("RUSTUP_AUTO_INSTALL", "0")
        .env("ZKMINER_BUILDER_CHECK", CHECK)
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("the pinned toolchain is 1.93.0 (8bab26f4f"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn the_scripts_flags_are_the_configs() {
    let config = std::fs::read_to_string(sdk_dir().join(".cargo/config.toml")).unwrap();
    let script = std::fs::read_to_string(sdk_dir().join("build-reproducible.sh")).unwrap();
    // The config's `"-C", "…"` pairs, and the -C values of the script's first CARGO_ENCODED_RUSTFLAGS.
    let from_config: Vec<&str> = config
        .lines()
        .filter_map(|l| l.trim_start().strip_prefix(r#""-C", ""#))
        .map(|v| v.trim_end_matches(',').trim_end_matches('"'))
        .collect();
    let line = script.lines().find_map(|l| l.strip_prefix("CARGO_ENCODED_RUSTFLAGS=\"")).unwrap();
    let from_script: Vec<&str> =
        line.trim_end_matches('"').split("${sep}").collect::<Vec<_>>().chunks(2).map(|p| p[1]).collect();
    assert_eq!(from_config.len(), 2);
    assert_eq!(from_script, from_config);
}
