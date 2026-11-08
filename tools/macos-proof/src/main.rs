//! Local acceptance harness. The verifier build has no proving or remote features.
use std::{fs, path::Path, time::Instant};

use anyhow::{bail, ensure, Context, Result};
use risc0_zkvm::{compute_image_id, sha::Digest, InnerReceipt, Receipt};
use serde_json::json;
use sha2::{Digest as _, Sha256};

fn reject_overrides() -> Result<()> {
    for name in [
        "RISC0_DEV_MODE",
        "RISC0_SKIP_BUILD",
        "RISC0_SKIP_BUILD_KERNELS",
        "RISC0_SKIP_VERIFY",
        "DOCS_RS",
        "RISC0_PROVER",
        "RISC0_EXECUTOR",
        "RISC0_SERVER_PATH",
        "RISC0_API_URL",
        "BONSAI_API_URL",
        "BONSAI_API_KEY",
        "RISC0_TEST_INJECT_INVALID",
    ] {
        ensure!(
            std::env::var_os(name).is_none(),
            "unset {name} for acceptance testing"
        );
    }
    Ok(())
}

fn hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn check(receipt: &Receipt, image: Digest, expected: &[u8]) -> Result<()> {
    ensure!(
        matches!(receipt.inner, InnerReceipt::Groth16(_)),
        "not a complete Groth16 receipt"
    );
    ensure!(
        receipt.journal.bytes == expected,
        "journal differs from independently expected bytes"
    );
    receipt
        .verify(image)
        .context("Groth16 verification failed")?;
    ensure!(
        receipt.inner.groth16()?.seal.len() == 256,
        "unexpected raw Groth16 seal length"
    );
    Ok(())
}

fn verify(dir: &Path, elf: &[u8], expected: &[u8]) -> Result<()> {
    let receipt: Receipt = bincode::deserialize(&fs::read(dir.join("receipt.bin"))?)?;
    let image = compute_image_id(elf)?;
    check(&receipt, image, expected)?;

    let mut wrong_image = image.as_bytes().to_vec();
    wrong_image[0] ^= 1;
    let wrong_image = Digest::try_from(wrong_image.as_slice())?;
    ensure!(
        receipt.verify(wrong_image).is_err(),
        "wrong image was accepted"
    );
    let mut changed_output = receipt.clone();
    changed_output.journal.bytes.push(1);
    ensure!(
        changed_output.verify(image).is_err(),
        "modified journal was accepted"
    );
    let mut corrupt = receipt.clone();
    if let InnerReceipt::Groth16(inner) = &mut corrupt.inner {
        inner.seal[0] ^= 1;
    }
    ensure!(
        corrupt.verify(image).is_err(),
        "corrupted proof was accepted"
    );
    let report = json!({"verification": "passed", "negative_tests": ["wrong_image", "modified_journal", "corrupt_seal"],
        "image_id": image.to_string(), "elf_sha256": hash(elf), "journal_hex": hex::encode(expected)});
    fs::write(
        dir.join("verification.json"),
        serde_json::to_vec_pretty(&report)?,
    )?;
    println!("{report}");
    Ok(())
}

fn verify_seal(dir: &Path, elf: &[u8], expected: &[u8]) -> Result<()> {
    use risc0_zkvm::{
        sha::Digestible, Groth16Receipt, Groth16ReceiptVerifierParameters, ReceiptClaim,
    };
    let image = compute_image_id(elf)?;
    let journal = fs::read(dir.join("journal.bin"))?;
    ensure!(
        journal == expected,
        "worker journal differs from expected output"
    );
    let inner = Groth16Receipt::new(
        fs::read(dir.join("seal.bin"))?,
        ReceiptClaim::ok(image, journal.clone()).into(),
        Groth16ReceiptVerifierParameters::default().digest(),
    );
    let receipt = Receipt::new(InnerReceipt::Groth16(inner), journal);
    check(&receipt, image, expected)?;
    fs::write(dir.join("receipt.bin"), bincode::serialize(&receipt)?)?;
    verify(dir, elf, expected)
}

#[cfg(feature = "prove")]
fn prove(dir: &Path, elf: &[u8], input: &[u8], expected: &[u8], po2: u32) -> Result<()> {
    use risc0_zkvm::{ExecutorEnv, LocalProver, Prover, ProverOpts};
    ensure!(
        (13..=20).contains(&po2),
        "bounded smoke po2 must be in 13..=20"
    );
    fs::create_dir(dir).context("output directory must be new; never reuse old proof evidence")?;
    let total = Instant::now();
    let image = compute_image_id(elf)?;
    let env = ExecutorEnv::builder()
        .write_slice(input)
        .segment_limit_po2(po2)
        .session_limit(Some(4 * 1024 * 1024))
        .build()?;
    // Deliberately bypass default_prover: no environment/remote/server selection.
    #[cfg(not(feature = "hybrid"))]
    let prover = LocalProver::new("hemi-cpu-acceptance");
    #[cfg(feature = "hybrid")]
    let prover = LocalProver::new_metal("hemi-metal-fold-acceptance", 512 * 1024);
    let requested_mode = if cfg!(feature = "hybrid") { "metal" } else { "cpu" };
    let t = Instant::now();
    let info = prover.prove_with_opts(env, elf, &ProverOpts::composite())?;
    let segment_ms = t.elapsed().as_secs_f64() * 1000.0;
    #[cfg(not(feature = "hybrid"))]
    let observed_stages = json!({"segment": "cpu", "recursion": "cpu", "identity": "cpu",
        "groth16": "local_linux_amd64_helper"});
    #[cfg(feature = "hybrid")]
    let observed_stages = {
        let stages = prover.metal_stage_reports();
        ensure!(stages.len() == info.stats.segments, "missing Metal evidence for a segment");
        for (index, stage) in stages.iter().enumerate() {
            ensure!(stage.segment_index as usize == index && stage.completed_dispatches > 0
                && stage.fold_calls > 0 && stage.output_digests > 0
                && stage.input_digests == 2 * stage.output_digests
                && stage.peak_staging_bytes <= stage.staging_limit_bytes,
                "invalid or empty Metal stage evidence");
        }
        let dispatches: u64 = stages.iter().map(|s| s.completed_dispatches).sum();
        json!({"metal_stage": {"name": "segment_poseidon2_merkle_fold",
            "segments": stages, "completed_dispatches": dispatches,
            "kernel_source_sha256": hash(risc0_zkp::hal::metal::runtime_kernel_source().as_bytes())},
            "other_segment_operations": "cpu", "recursion": "cpu", "identity": "cpu",
            "groth16": "local_linux_amd64_helper"})
    };
    fs::write(dir.join("segment-stages.json"), serde_json::to_vec_pretty(&observed_stages)?)?;
    info.receipt.verify(image)?;
    ensure!(
        info.receipt.journal.bytes == expected,
        "unexpected composite journal"
    );
    fs::write(
        dir.join("partial-composite.bin"),
        bincode::serialize(&info.receipt)?,
    )?;
    eprintln!(
        "PARTIAL: verified composite ({} segments), compressing",
        info.stats.segments
    );
    let t = Instant::now();
    let succinct = prover.compress(&ProverOpts::succinct(), &info.receipt)?;
    let recursion_ms = t.elapsed().as_secs_f64() * 1000.0;
    succinct.verify(image)?;
    fs::write(
        dir.join("partial-succinct.bin"),
        bincode::serialize(&succinct)?,
    )?;
    eprintln!("PARTIAL: verified succinct; identity_p254 and Groth16 wrapping next");
    let t = Instant::now();
    let receipt = prover.compress(&ProverOpts::groth16(), &succinct)?;
    let wrapping_ms = t.elapsed().as_secs_f64() * 1000.0;
    let t = Instant::now();
    check(&receipt, image, expected)?;
    let verify_ms = t.elapsed().as_secs_f64() * 1000.0;
    fs::write(dir.join("receipt.bin"), bincode::serialize(&receipt)?)?;
    fs::write(dir.join("journal.bin"), &receipt.journal.bytes)?;
    fs::write(dir.join("seal.bin"), &receipt.inner.groth16()?.seal)?;
    let report = json!({"proof_kind": "groth16", "requested_mode": requested_mode, "observed_stages": observed_stages, "image_id": image.to_string(),
        "elf_sha256": hash(elf), "input_sha256": hash(input), "journal_hex": hex::encode(expected), "po2": po2,
        "stats": info.stats, "stage_ms": {"execution_and_segment": segment_ms, "recursion": recursion_ms,
        "identity_and_wrap": wrapping_ms, "verification": verify_ms}, "total_ms": total.elapsed().as_secs_f64() * 1000.0,
        "verification": "in_process_passed_independent_pending", "failures": 0});
    fs::write(dir.join("proof.json"), serde_json::to_vec_pretty(&report)?)?;
    println!("{report}");
    Ok(())
}

fn main() -> Result<()> {
    reject_overrides()?;
    let args: Vec<_> = std::env::args().collect();
    if args.len() == 4 && args[1] == "pack" {
        let user = fs::read(&args[2])?;
        ensure!(user.starts_with(b"\x7fELF"), "invalid user ELF");
        // Exactly the default GuestOptions kernel and ProgramBinary encoding in
        // pinned risc0-build. Raw user ELFs are not complete v3 program binaries.
        let kernel = risc0_zkos_v1compat::V1COMPAT_ELF;
        let program = risc0_binfmt::ProgramBinary::new(&user, kernel).encode();
        let image = compute_image_id(&program)?;
        fs::write(&args[3], &program)?;
        println!(
            "{}",
            json!({"image_id": image.to_string(), "program_sha256": hash(&program),
            "user_elf_sha256": hash(&user), "kernel_elf_sha256": hash(kernel)})
        );
        return Ok(());
    }
    ensure!(
        args.len() == 7,
        "usage: hemi-macos-proof prove|verify ELF INPUT EXPECTED_JOURNAL_HEX NEW_OUTPUT_DIR PO2"
    );
    let elf = fs::read(&args[2])?;
    risc0_binfmt::ProgramBinary::decode(&elf)
        .context("expected packed v3 ProgramBinary, use pack USER_ELF OUTPUT first")?;
    let input = fs::read(&args[3])?;
    let expected = hex::decode(&args[4])?;
    let dir = Path::new(&args[5]);
    let po2: u32 = args[6].parse()?;
    match args[1].as_str() {
        "verify" => verify(dir, &elf, &expected),
        "verify-seal" => verify_seal(dir, &elf, &expected),
        #[cfg(feature = "prove")]
        "prove" => prove(dir, &elf, &input, &expected, po2),
        _ => {
            let _ = (input, po2, Instant::now());
            bail!("unsupported operation or prover feature absent")
        }
    }
}
