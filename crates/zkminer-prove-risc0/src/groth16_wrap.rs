//! The Groth16 wrap, where it needs Docker: in the CPU build (`zkminer-prove-risc0-cpu`, for hosts
//! that only size jobs and for tests), and in the Intel build with
//! `RISC0_GROTH16_INTEL_PROVER=docker`. The CUDA, ROCm and default Intel builds wrap in-process with
//! the `risc0-groth16` component and never come here.
//!
//! A confined worker has no sockets ([`crate::confinement`]), so it cannot reach the Docker daemon,
//! and it must not: the daemon's socket is root-equivalent, with the host's network. So the wrap
//! runs in a helper process the worker starts before it confines itself (`--groth16-docker-helper`,
//! this binary), which never runs a guest. The worker proves to a succinct receipt, makes the
//! `identity_p254` receipt of it, and hands the helper only that receipt's seal; the helper turns it
//! into the prover's JSON input, runs the prover image with no network (`--network none`) and
//! answers with the Groth16 seal, which the worker checks as it checks every receipt
//! (`groth16_proof_output`).

use std::io::{Read, Write};
use std::path::Path;
#[cfg(not(target_os = "linux"))]
use std::path::PathBuf;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::Mutex;

use anyhow::{anyhow, bail, Context, Result};
use risc0_zkvm::sha::Digestible;

/// The argument that makes this binary the helper.
pub const HELPER_ARG: &str = "--groth16-docker-helper";

/// The prover image the pinned `risc0-groth16` runs (`prove/docker.rs`, `IMAGE`): the same proving
/// key as the in-process prover, so its seals verify against the same parameters.
const IMAGE: &str = "risczero/risc0-groth16-prover:v2026-10-20.1";

/// The largest seal the helper accepts. An `identity_p254` seal is a fixed-size recursion proof of
/// about 220 KB.
const MAX_SEAL_BYTES: usize = 4 << 20;

/// Whether this build's Groth16 wrap needs Docker.
pub fn needed() -> bool {
    cfg!(feature = "cpu")
        || (cfg!(feature = "intel")
            && std::env::var("RISC0_GROTH16_INTEL_PROVER").as_deref() == Ok("docker"))
}

struct Helper {
    child: Child,
    stdin: ChildStdin,
    stdout: ChildStdout,
}

static HELPER: Mutex<Option<Helper>> = Mutex::new(None);

fn start() -> Result<Helper> {
    let exe =
        std::env::current_exe().context("cannot locate this binary for the Groth16 helper")?;
    let mut child = Command::new(exe)
        .arg(HELPER_ARG)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .context("cannot start the Groth16 helper")?;
    let stdin = child.stdin.take().expect("piped");
    let stdout = child.stdout.take().expect("piped");
    Ok(Helper {
        child,
        stdin,
        stdout,
    })
}

/// Starts the helper if this build needs it and it is not running. Before the confinement: once
/// confined, the worker can start nothing that reaches the daemon.
pub fn start_helper_if_needed() -> Result<(), String> {
    if !needed() {
        return Ok(());
    }
    let mut helper = HELPER.lock().unwrap_or_else(|e| e.into_inner());
    if helper.is_none() {
        *helper = Some(start().map_err(|e| format!("{e:#}"))?);
    }
    Ok(())
}

/// The Groth16 seal of an `identity_p254` seal, from the helper.
fn wrap(identity_p254_seal: &[u8]) -> Result<Vec<u8>> {
    let mut guard = HELPER.lock().unwrap_or_else(|e| e.into_inner());
    if guard.is_none() {
        if crate::confinement::is_confined() {
            bail!(
                "this build's Groth16 wrap needs Docker, through a helper that was not started \
                 before the worker was confined"
            );
        }
        *guard = Some(start()?);
    }
    let helper = guard.as_mut().expect("just started");
    let result = (|| -> Result<Vec<u8>> {
        helper
            .stdin
            .write_all(&(identity_p254_seal.len() as u32).to_le_bytes())?;
        helper.stdin.write_all(identity_p254_seal)?;
        helper.stdin.flush()?;
        let mut status = [0u8; 1];
        helper.stdout.read_exact(&mut status)?;
        let mut len = [0u8; 4];
        helper.stdout.read_exact(&mut len)?;
        let len = u32::from_le_bytes(len) as usize;
        if len > MAX_SEAL_BYTES {
            bail!("the Groth16 helper answered with {len} bytes");
        }
        let mut body = vec![0u8; len];
        helper.stdout.read_exact(&mut body)?;
        if status[0] != 0 {
            bail!("Groth16 wrap failed: {}", String::from_utf8_lossy(&body));
        }
        Ok(body)
    })();
    if result.is_err() {
        // A helper out of step with its answers is not used again.
        if let Some(mut h) = guard.take() {
            let _ = h.child.kill();
            let _ = h.child.wait();
        }
    }
    result
}

/// `receipt` (succinct) as a Groth16 receipt, through the helper: what
/// `ProverServer::succinct_to_groth16` does, with the wrap in another process.
pub fn to_groth16(receipt: &risc0_zkvm::Receipt) -> Result<risc0_zkvm::Receipt> {
    let succinct = receipt
        .inner
        .succinct()
        .map_err(|e| anyhow!("expected a succinct receipt to wrap: {e}"))?;
    let server =
        risc0_zkvm::get_prover_server(&risc0_zkvm::ProverOpts::succinct().with_dev_mode(false))?;
    let ident = server.identity_p254(succinct)?;
    let seal = wrap(&ident.get_seal_bytes())?;
    let groth16 = risc0_zkvm::Groth16Receipt::new(
        seal,
        succinct.claim.clone(),
        risc0_zkvm::Groth16ReceiptVerifierParameters::default().digest(),
    );
    Ok(risc0_zkvm::Receipt::new(
        risc0_zkvm::InnerReceipt::Groth16(groth16),
        receipt.journal.bytes.clone(),
    ))
}

/// A Groth16 proof of `elf` on `env`: in-process, or to a succinct receipt wrapped by the helper.
pub fn prove(
    prover: &risc0_zkvm::LocalProver,
    env: risc0_zkvm::ExecutorEnv<'_>,
    elf: &[u8],
) -> Result<risc0_zkvm::ProveInfo> {
    use risc0_zkvm::Prover as _;
    if !needed() {
        return prover.prove_with_opts(
            env,
            elf,
            &risc0_zkvm::ProverOpts::groth16().with_dev_mode(false),
        );
    }
    let mut info = prover.prove_with_opts(
        env,
        elf,
        &risc0_zkvm::ProverOpts::succinct().with_dev_mode(false),
    )?;
    info.receipt = to_groth16(&info.receipt)?;
    Ok(info)
}

/// A Groth16 proof of an executed `session`, as [`prove`].
pub fn prove_session(session: &risc0_zkvm::Session) -> Result<risc0_zkvm::ProveInfo> {
    let kind = if needed() {
        risc0_zkvm::ProverOpts::succinct()
    } else {
        risc0_zkvm::ProverOpts::groth16()
    };
    let opts = kind.with_dev_mode(false);
    let ctx = risc0_zkvm::VerifierContext::default().with_dev_mode(opts.dev_mode());
    let mut info = risc0_zkvm::get_prover_server(&opts)?.prove_session(&ctx, session)?;
    if needed() {
        info.receipt = to_groth16(&info.receipt)?;
    }
    Ok(info)
}

/// `succinct` compressed to Groth16, as [`prove`].
pub fn compress(
    prover: &risc0_zkvm::LocalProver,
    succinct: &risc0_zkvm::Receipt,
) -> Result<risc0_zkvm::Receipt> {
    use risc0_zkvm::Prover as _;
    if needed() {
        to_groth16(succinct)
    } else {
        prover.compress(
            &risc0_zkvm::ProverOpts::groth16().with_dev_mode(false),
            succinct,
        )
    }
}

/// The helper process (`--groth16-docker-helper`): answers wrap requests on stdin until it closes.
/// Request: a little-endian `u32` length, then an `identity_p254` seal. Answer: a status byte (0
/// for a seal), a `u32` length, then the Groth16 seal or the error's text.
pub fn helper_main() -> ! {
    #[cfg(target_os = "linux")]
    // SAFETY: plain prctls. It ends with the worker that started it.
    unsafe {
        libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);
        libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    }
    #[cfg(target_os = "linux")]
    let work = zkminer_witness_sandbox::confine::private_tmpdir("risc0-g16").ok();
    #[cfg(not(target_os = "linux"))]
    let work: Option<PathBuf> = None;
    let Some(work) = work.or_else(|| Some(std::env::temp_dir())) else {
        std::process::exit(1);
    };
    let mut stdin = std::io::stdin().lock();
    let mut stdout = std::io::stdout().lock();
    let mut n = 0u64;
    loop {
        let mut len = [0u8; 4];
        if stdin.read_exact(&mut len).is_err() {
            let _ = std::fs::remove_dir_all(&work);
            std::process::exit(0);
        }
        let len = u32::from_le_bytes(len) as usize;
        let answer = if len > MAX_SEAL_BYTES {
            Err(anyhow!("a {len}-byte seal is not an identity_p254 seal"))
        } else {
            let mut seal = vec![0u8; len];
            if stdin.read_exact(&mut seal).is_err() {
                std::process::exit(0);
            }
            n += 1;
            let dir = work.join(format!("wrap-{n}"));
            let r = docker_wrap(&dir, &seal);
            let _ = std::fs::remove_dir_all(&dir);
            r
        };
        let (status, body) = match answer {
            Ok(seal) => (0u8, seal),
            Err(e) => (1u8, format!("{e:#}").into_bytes()),
        };
        let ok = stdout.write_all(&[status]).is_ok()
            && stdout.write_all(&(body.len() as u32).to_le_bytes()).is_ok()
            && stdout.write_all(&body).is_ok()
            && stdout.flush().is_ok();
        if !ok {
            std::process::exit(0);
        }
    }
}

/// One wrap in `dir`: risc0-groth16's Docker path (`prove/docker.rs`), with no network for the
/// container.
fn docker_wrap(dir: &Path, identity_p254_seal: &[u8]) -> Result<Vec<u8>> {
    std::fs::create_dir_all(dir)?;
    let json = risc0_groth16::prove::to_json(identity_p254_seal)
        .context("the seal is not an identity_p254 seal")?;
    std::fs::write(dir.join("input.json"), json)?;
    let output = Command::new("docker")
        .args(["run", "--rm", "--network", "none", "-v"])
        .arg(format!("{}:/mnt", dir.display()))
        .arg(IMAGE)
        .stdin(Stdio::null())
        .output()
        .context("cannot run docker")?;
    if !output.status.success() {
        bail!(
            "the Groth16 prover image failed ({}): {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
                .lines()
                .last()
                .unwrap_or("")
        );
    }
    let proof = std::fs::read_to_string(dir.join("proof.json"))?;
    let proof: risc0_groth16::ProofJson = serde_json::from_str(&proof)?;
    let seal: risc0_groth16::Seal = proof.try_into()?;
    Ok(seal.to_vec())
}
