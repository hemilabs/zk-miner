use anyhow::{ensure, Result};
use std::{fs, path::Path, time::Instant};
fn main() -> Result<()> {
    for name in [
        "RISC0_DEV_MODE",
        "RISC0_SKIP_VERIFY",
        "RISC0_PROVER",
        "RISC0_EXECUTOR",
        "BONSAI_API_URL",
        "BONSAI_API_KEY",
    ] {
        ensure!(
            std::env::var_os(name).is_none(),
            "unset {name} for native acceptance"
        );
    }
    let args: Vec<_> = std::env::args().collect();
    let start = Instant::now();
    if args.len() == 2 && args[1] == "preflight" {
        risc0_groth16::prove::native::preflight()?;
    } else {
        ensure!(
            args.len() == 4,
            "usage: hemi-native-wrap preflight | witness|wrap SEAL NEW_OUTPUT"
        );
        let seal = fs::read(&args[2])?;
        ensure!(!Path::new(&args[3]).exists(), "output already exists");
        match args[1].as_str() {
            "witness" => risc0_groth16::prove::native::write_witness(&seal, Path::new(&args[3]))?,
            "wrap" => fs::write(
                &args[3],
                risc0_groth16::prove::native::shrink_wrap(&seal)?.to_vec(),
            )?,
            _ => anyhow::bail!("unknown command"),
        }
    }
    println!(
        "{}",
        serde_json::json!({"status":"passed", "seconds": start.elapsed().as_secs_f64()})
    );
    Ok(())
}
