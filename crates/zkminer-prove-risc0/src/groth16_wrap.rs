//! The Groth16 wrap, where it needs Docker: in the CPU build (`zkminer-prove-risc0-cpu`, for hosts
//! that only size jobs and for tests), and in the Intel build with
//! `RISC0_GROTH16_INTEL_PROVER=docker`. The CUDA, ROCm and default Intel builds wrap in-process with
//! the `risc0-groth16` component and never come here.
//!
//! A confined worker has no sockets ([`crate::confinement`]), so it cannot reach the Docker daemon,
//! and it must not: the daemon's socket is root-equivalent, with the host's network. So the wrap
//! runs in a helper process the worker starts before it confines itself (`--groth16-docker-helper`,
//! this binary), which never runs a guest. The helper is not confined (it talks to the daemon), so
//! it reads as little as possible of what the worker sends, and trusts none of it: a guest that
//! escaped its executor in the worker can send the helper anything.
//!
//! - The worker proves to a succinct receipt, makes its `identity_p254` receipt, and turns that
//!   receipt's seal into the prover's input itself (`risc0-groth16`'s `to_json`, in the confined
//!   worker): the helper never parses a seal.
//! - The helper accepts only an input of that exact shape ([`validated_input`]): the JSON text
//!   `to_json` writes, with exactly one number per element of an `identity_p254` seal, each a
//!   canonical decimal below its field's modulus (BabyBear's for a field element, BN254's scalar
//!   field's for a digest, at the positions the seal format puts them). Anything else is refused
//!   before Docker runs. The prover's input file is written from the numbers it validated.
//! - A request that makes the helper panic is answered as an error, and the helper serves the next
//!   one ([`serve`]); an answer the worker cannot read only ends that helper.
//! - The prover image is pinned by digest ([`IMAGE`]) and runs with no network (`--network none`).
//!
//! The worker checks the Groth16 seal it gets back as it checks every receipt
//! (`groth16_proof_output`).

use std::io::{Read, Write};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::{Mutex, OnceLock};

use anyhow::{anyhow, bail, Context, Result};
use risc0_zkvm::sha::Digestible;

/// The argument that makes this binary the helper.
pub const HELPER_ARG: &str = "--groth16-docker-helper";

/// The prover image, pinned by digest: [`IMAGE_TAG`] as the registry resolves it (its
/// multi-platform index), so a tag pushed again cannot change what runs. The same proving key as
/// the in-process prover, so its seals verify against the same parameters.
const IMAGE: &str = "risczero/risc0-groth16-prover@sha256:\
                     e8c2068fb34bbc41447255aa980a89cbb7d6e5a80c0d66041264431f2a955e47";

/// The tag [`IMAGE`]'s digest was read from: the image the pinned `risc0-groth16` runs
/// (`prove/docker.rs`, `IMAGE`; a test checks they agree).
const IMAGE_TAG: &str = "risczero/risc0-groth16-prover:v2026-10-20.1";

/// The words of an `identity_p254` seal (`risc0-groth16`'s `K_SEAL_WORDS`; a test checks it against
/// `to_json`, which takes nothing else).
const SEAL_WORDS: usize = 55_667;

/// The largest request the helper reads: the prover's input for an `identity_p254` seal is under
/// 800 KB.
const MAX_INPUT_BYTES: usize = 1 << 20;

/// The largest answer the worker reads: a 256-byte Groth16 seal, or an error's text.
const MAX_ANSWER_BYTES: usize = 64 << 10;

/// The longest error text the helper sends.
const MAX_ERROR_BYTES: usize = 4 << 10;

/// The largest `proof.json` the helper reads back from the prover image.
const MAX_PROOF_BYTES: u64 = 1 << 20;

/// BabyBear's modulus, `15 * 2^27 + 1`: a seal's field elements are below it.
const BABY_BEAR_P: u64 = 15 * (1 << 27) + 1;

/// BN254's scalar field modulus, in decimal: a seal's digests (`digest_to_fr`) are below it.
const BN254_R: &str =
    "21888242871839275222246405745257275088548364400416034343698204186575808495617";

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
        // The helper works below the temporary directory this worker was started with, never
        // below the worker's own, which the confined worker (and a guest that escaped in it) may
        // write.
        .env("TMPDIR", crate::confinement::original_tmpdir())
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

/// One answer from the helper: the Groth16 seal, or the helper's reason for refusing (`Ok(Err)`,
/// the helper stays usable). `Err` when the exchange itself failed.
fn exchange(helper: &mut Helper, input: &str) -> Result<Result<Vec<u8>, String>> {
    helper
        .stdin
        .write_all(&(input.len() as u32).to_le_bytes())?;
    helper.stdin.write_all(input.as_bytes())?;
    helper.stdin.flush()?;
    let mut status = [0u8; 1];
    helper.stdout.read_exact(&mut status)?;
    let mut len = [0u8; 4];
    helper.stdout.read_exact(&mut len)?;
    let len = u32::from_le_bytes(len) as usize;
    if len > MAX_ANSWER_BYTES {
        bail!("the Groth16 helper answered with {len} bytes");
    }
    let mut body = vec![0u8; len];
    helper.stdout.read_exact(&mut body)?;
    Ok(match status[0] {
        0 => Ok(body),
        _ => Err(String::from_utf8_lossy(&body).into_owned()),
    })
}

/// The Groth16 seal for the prover's input `input` (see [`prover_input`]), from the helper.
fn wrap(input: &str) -> Result<Vec<u8>> {
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
    match exchange(helper, input) {
        Ok(Ok(seal)) => Ok(seal),
        // The helper refused or failed this one wrap, and is ready for the next.
        Ok(Err(reason)) => bail!("Groth16 wrap failed: {reason}"),
        Err(e) => {
            // A helper out of step with its answers is not used again.
            if let Some(mut h) = guard.take() {
                let _ = h.child.kill();
                let _ = h.child.wait();
            }
            Err(e.context("the Groth16 helper is gone"))
        }
    }
}

/// `risc0-groth16`'s `to_json` of an `identity_p254` seal (exactly [`SEAL_WORDS`] words), with a
/// panic (it has some for a malformed seal) turned into an error.
fn seal_to_json(seal: &[u8]) -> Result<String> {
    if seal.len() != SEAL_WORDS * 4 {
        bail!(
            "a {}-byte seal is not an identity_p254 seal ({} bytes)",
            seal.len(),
            SEAL_WORDS * 4
        );
    }
    // `to_json` reads the seal as `u32` words in place, which needs a 4-byte-aligned buffer.
    let words: Vec<u32> = seal
        .chunks_exact(4)
        .map(|w| u32::from_ne_bytes(w.try_into().expect("4 bytes")))
        .collect();
    // SAFETY: the bytes of a live `u32` slice (alignment 1, the same length in bytes).
    let bytes = unsafe { std::slice::from_raw_parts(words.as_ptr().cast::<u8>(), seal.len()) };
    catch_unwind(|| risc0_groth16::prove::to_json(bytes))
        .map_err(|_| anyhow!("the identity_p254 seal is malformed"))?
}

/// The prover's input for an `identity_p254` seal, as `risc0-groth16`'s Docker path writes it. Made
/// in the worker, which is confined, so the helper, which is not, never parses a seal.
fn prover_input(identity_p254_seal: &[u8]) -> Result<String> {
    seal_to_json(identity_p254_seal)
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
    let input = prover_input(&ident.get_seal_bytes())?;
    let seal = wrap(&input)?;
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

/// What one element of the prover's input holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Element {
    /// A BabyBear field element (one seal word).
    Fp,
    /// A digest as a BN254 scalar (eight seal words).
    Digest,
}

/// The kind of every element of the prover's input, in order, read off `to_json` itself: on a
/// seal this process makes (every word 1), a field element and a digest come out as two different
/// numbers, the field element's below BabyBear's modulus and the digest's far above it. Worked out
/// once; an error if `to_json` no longer behaves so.
fn input_shape() -> Result<&'static [Element]> {
    static SHAPE: OnceLock<Result<Vec<Element>, String>> = OnceLock::new();
    SHAPE
        .get_or_init(|| shape_of_to_json().map_err(|e| format!("{e:#}")))
        .as_deref()
        .map_err(|e| anyhow!("cannot work out the prover's input shape: {e}"))
}

fn shape_of_to_json() -> Result<Vec<Element>> {
    let ones: Vec<u8> = std::iter::repeat_n(1u32.to_le_bytes(), SEAL_WORDS)
        .flatten()
        .collect();
    let json = seal_to_json(&ones)?;
    let values = parse_input(json.as_bytes())?;
    let fp = values
        .iter()
        .find(|v| v.len() <= 10 && v.parse::<u64>().is_ok_and(|n| n < BABY_BEAR_P))
        .copied()
        .ok_or_else(|| anyhow!("no field element"))?;
    let digest = values
        .iter()
        .find(|v| v.len() > 10)
        .copied()
        .ok_or_else(|| anyhow!("no digest"))?;
    let shape = values
        .iter()
        .map(|v| match *v {
            v if v == fp => Ok(Element::Fp),
            v if v == digest => Ok(Element::Digest),
            other => Err(anyhow!("an element that is neither: {other}")),
        })
        .collect::<Result<Vec<_>>>()?;
    let words: usize = shape
        .iter()
        .map(|e| match e {
            Element::Fp => 1,
            Element::Digest => 8,
        })
        .sum();
    if words != SEAL_WORDS {
        bail!("the elements cover {words} seal words, not {SEAL_WORDS}");
    }
    Ok(shape)
}

const INPUT_HEAD: &[u8] = b"{\n  \"iop\" : [\n";
const INPUT_TAIL: &[u8] = b"  ]\n}";
const ELEMENT_HEAD: &[u8] = b"    \"";
const ELEMENT_TAIL: &[u8] = b"\"\n";
const ELEMENT_SEPARATOR: &[u8] = b",\n";

/// The numbers of an input in exactly the form `to_json` writes (see [`render_input`]): each a
/// canonical decimal (digits only, no leading zero, at most 78 digits). Nothing else is accepted:
/// no other whitespace, key, sign, exponent or escape.
fn parse_input(bytes: &[u8]) -> Result<Vec<&str>> {
    let mut rest = bytes
        .strip_prefix(INPUT_HEAD)
        .ok_or_else(|| anyhow!("not the prover's input"))?;
    let mut values = Vec::new();
    loop {
        if !values.is_empty() {
            if let Some(tail) = rest.strip_prefix(INPUT_TAIL) {
                if tail.is_empty() {
                    return Ok(values);
                }
                bail!("bytes after the prover's input");
            }
            rest = rest.strip_prefix(ELEMENT_SEPARATOR).ok_or_else(|| {
                anyhow!("element {} is not followed by a separator", values.len())
            })?;
        }
        rest = rest
            .strip_prefix(ELEMENT_HEAD)
            .ok_or_else(|| anyhow!("element {} is malformed", values.len()))?;
        let digits = rest.iter().take_while(|b| b.is_ascii_digit()).count();
        let number = &rest[..digits];
        if digits == 0 || digits > 78 || (digits > 1 && number[0] == b'0') {
            bail!("element {} is not a canonical decimal", values.len());
        }
        values.push(std::str::from_utf8(number).expect("ASCII digits"));
        rest = rest[digits..]
            .strip_prefix(ELEMENT_TAIL)
            .ok_or_else(|| anyhow!("element {} is malformed", values.len() - 1))?;
    }
}

/// `values` as the prover's input, in `to_json`'s exact form.
fn render_input(values: &[&str]) -> String {
    let mut out = Vec::with_capacity(values.iter().map(|v| v.len() + 8).sum::<usize>() + 32);
    out.extend_from_slice(INPUT_HEAD);
    for (i, v) in values.iter().enumerate() {
        if i > 0 {
            out.extend_from_slice(ELEMENT_SEPARATOR);
        }
        out.extend_from_slice(ELEMENT_HEAD);
        out.extend_from_slice(v.as_bytes());
        out.extend_from_slice(ELEMENT_TAIL);
    }
    out.extend_from_slice(INPUT_TAIL);
    String::from_utf8(out).expect("ASCII")
}

/// Whether the canonical decimal `v` is below the canonical decimal `modulus`.
fn below(v: &str, modulus: &str) -> bool {
    v.len() < modulus.len() || (v.len() == modulus.len() && v < modulus)
}

/// The prover's input in `request`, if it has exactly the shape of an `identity_p254` seal's (see
/// the module docs), rendered afresh from the numbers it holds; else why not.
fn validated_input(request: &[u8]) -> Result<String> {
    let shape = input_shape()?;
    let values = parse_input(request)?;
    if values.len() != shape.len() {
        bail!(
            "{} elements, not the {} of an identity_p254 seal",
            values.len(),
            shape.len()
        );
    }
    for (i, (v, kind)) in values.iter().zip(shape).enumerate() {
        let in_field = match kind {
            Element::Fp => v.len() <= 10 && v.parse::<u64>().is_ok_and(|n| n < BABY_BEAR_P),
            Element::Digest => below(v, BN254_R),
        };
        if !in_field {
            bail!("element {i} is not a {kind:?} of the seal");
        }
    }
    Ok(render_input(&values))
}

/// The helper process (`--groth16-docker-helper`): answers wrap requests on stdin until it closes
/// ([`serve`]).
pub fn helper_main() -> ! {
    #[cfg(target_os = "linux")]
    // SAFETY: plain prctls. It ends with the worker that started it.
    unsafe {
        libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);
        libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    }
    // Only a directory of its own, which it removes when it ends: never the shared temporary
    // directory itself, whose other entries (other workers' directories, the wraps other helpers
    // have mounted into their containers) its removal would take with it (review r6 LR-2).
    let work = match private_workdir() {
        Ok(work) => work,
        Err(e) => {
            eprintln!(
                "zkminer: the Groth16 helper cannot make a working directory of its own under {} \
                 ({e}); it serves no wrap",
                std::env::temp_dir().display()
            );
            std::process::exit(1);
        }
    };
    let code = serve(
        std::io::stdin().lock(),
        std::io::stdout().lock(),
        &work,
        docker_wrap,
    );
    let _ = std::fs::remove_dir_all(&work);
    std::process::exit(code);
}

/// A new directory for the helper's wraps, readable by this user only, below the temporary
/// directory: one it made itself, so the helper may remove it, and all below it, when it ends.
fn private_workdir() -> std::io::Result<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        zkminer_witness_sandbox::confine::private_tmpdir("risc0-g16")
    }
    #[cfg(not(target_os = "linux"))]
    {
        use std::sync::atomic::{AtomicU32, Ordering};
        use std::time::{SystemTime, UNIX_EPOCH};
        static N: AtomicU32 = AtomicU32::new(0);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.subsec_nanos());
        let dir = std::env::temp_dir().join(format!(
            "zkminer-risc0-g16-{}-{nanos:09}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        // Not `recursive`: one already there is not ours.
        let mut builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
        builder.create(&dir)?;
        Ok(dir)
    }
}

/// Answers the requests on `input` on `output`, until `input` ends (0) or `output` fails (1).
/// Request: a little-endian `u32` length, then the prover's input. Answer: a status byte (0 for a
/// seal), a `u32` length, then the Groth16 seal or the error's text. A request is checked
/// ([`validated_input`]) before `wrap` sees it, and a panic while answering it is an error answer.
fn serve(
    mut input: impl Read,
    mut output: impl Write,
    work: &Path,
    mut wrap: impl FnMut(&Path, &str) -> Result<Vec<u8>>,
) -> i32 {
    let mut n = 0u64;
    loop {
        let mut len = [0u8; 4];
        if input.read_exact(&mut len).is_err() {
            return 0;
        }
        let len = u32::from_le_bytes(len) as usize;
        let answer = if len > MAX_INPUT_BYTES {
            // Skipped unread, so the next request starts in step.
            match std::io::copy(&mut (&mut input).take(len as u64), &mut std::io::sink()) {
                Ok(skipped) if skipped == len as u64 => {}
                _ => return 0,
            }
            Err(anyhow!(
                "a {len}-byte request is larger than any identity_p254 seal's input"
            ))
        } else {
            let mut request = vec![0u8; len];
            if input.read_exact(&mut request).is_err() {
                return 0;
            }
            n += 1;
            let dir = work.join(format!("wrap-{n}"));
            let answer = catch_unwind(AssertUnwindSafe(|| {
                let prover_input = validated_input(&request)?;
                wrap(&dir, &prover_input)
            }))
            .unwrap_or_else(|_| Err(anyhow!("the Groth16 helper failed on this request")));
            let _ = std::fs::remove_dir_all(&dir);
            answer
        };
        let (status, body) = match answer {
            Ok(seal) => (0u8, seal),
            Err(e) => {
                let mut text = format!("{e:#}").into_bytes();
                text.truncate(MAX_ERROR_BYTES);
                (1u8, text)
            }
        };
        let ok = output.write_all(&[status]).is_ok()
            && output.write_all(&(body.len() as u32).to_le_bytes()).is_ok()
            && output.write_all(&body).is_ok()
            && output.flush().is_ok();
        if !ok {
            return 1;
        }
    }
}

/// One wrap in `dir` (the helper's, below the temporary directory the worker was started with, which
/// no confined process may write) of a validated prover input: risc0-groth16's Docker path
/// (`prove/docker.rs`), with the image pinned by digest and no network for the container. The
/// container sees its input read-only (`dir/in` at `/mnt`) and may write only the proof
/// (`dir/out/proof.json` bound over `/mnt/proof.json`), which is read back without following a
/// link and only as a regular file.
fn docker_wrap(dir: &Path, prover_input: &str) -> Result<Vec<u8>> {
    let input = dir.join("in");
    let output = dir.join("out");
    for d in [dir, &input, &output] {
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
        builder.create(d)?;
    }
    std::fs::write(input.join("input.json"), prover_input)?;
    // The proof's mount point inside `/mnt`, and the file the container writes.
    std::fs::write(input.join("proof.json"), b"")?;
    std::fs::write(output.join("proof.json"), b"")?;
    let mount = |src: &Path, dst: &str, readonly: bool| {
        format!(
            "type=bind,src={},dst={dst}{}",
            src.display(),
            if readonly { ",readonly" } else { "" }
        )
    };
    let result = Command::new("docker")
        .args(["run", "--rm", "--network", "none", "--mount"])
        .arg(mount(&input, "/mnt", true))
        .arg("--mount")
        .arg(mount(&output.join("proof.json"), "/mnt/proof.json", false))
        .arg(IMAGE)
        .stdin(Stdio::null())
        .output()
        .context("cannot run docker")?;
    if !result.status.success() {
        bail!(
            "the Groth16 prover image ({IMAGE_TAG}, pinned by digest) failed ({}): {}",
            result.status,
            String::from_utf8_lossy(&result.stderr)
                .lines()
                .last()
                .unwrap_or("")
        );
    }
    let proof = read_proof(&output)?;
    let proof: risc0_groth16::ProofJson = serde_json::from_str(&proof)?;
    let seal: risc0_groth16::Seal = proof.try_into()?;
    Ok(seal.to_vec())
}

/// `dir/proof.json`, opened without following a link, a regular file of at most
/// [`MAX_PROOF_BYTES`].
fn read_proof(dir: &Path) -> Result<String> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::custom_flags(
        &mut options,
        libc::O_NOFOLLOW | libc::O_NONBLOCK,
    );
    let f = options
        .open(dir.join("proof.json"))
        .context("the prover image left no proof")?;
    if !f.metadata()?.is_file() {
        bail!("the prover image's proof is not a regular file");
    }
    let mut proof = String::new();
    f.take(MAX_PROOF_BYTES).read_to_string(&mut proof)?;
    Ok(proof)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Review r6 LR-2: the helper works, and removes, only a directory it made itself, never the
    /// shared temporary directory.
    #[test]
    fn the_helper_works_in_a_directory_of_its_own() {
        let shared = std::env::temp_dir();
        let a = private_workdir().unwrap();
        let b = private_workdir().unwrap();
        for dir in [&a, &b] {
            assert_ne!(dir, &shared);
            assert_eq!(dir.parent(), Some(shared.as_path()), "{}", dir.display());
            assert!(std::fs::read_dir(dir).unwrap().next().is_none());
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = std::fs::metadata(dir).unwrap().permissions().mode();
                assert_eq!(mode & 0o077, 0, "{mode:o}");
            }
        }
        assert_ne!(a, b);
        for dir in [a, b] {
            std::fs::remove_dir(dir).unwrap();
        }
    }

    /// A seal `to_json` takes: field elements anything, digests below BN254's modulus.
    fn a_seal(seed: u32) -> Vec<u8> {
        let shape = input_shape().unwrap();
        let mut words = Vec::with_capacity(SEAL_WORDS);
        let mut x = seed.wrapping_mul(2_654_435_761).wrapping_add(1);
        let mut next = || {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            x
        };
        for kind in shape {
            match kind {
                Element::Fp => words.push(next()),
                Element::Digest => {
                    for i in 0..8 {
                        // The top word below r's (0x30644e72): the digest is a BN254 scalar.
                        words.push(if i == 7 { next() % 0x3064_4e72 } else { next() });
                    }
                }
            }
        }
        words.iter().flat_map(|w| w.to_le_bytes()).collect()
    }

    #[test]
    fn the_seal_size_is_risc0_groth16s() {
        assert!(seal_to_json(&vec![0u8; SEAL_WORDS * 4]).is_ok());
        // `to_json` itself takes no other size (it panics, contained here), and the worker refuses
        // one before calling it.
        let one_word_more = vec![0u32; SEAL_WORDS + 1];
        // SAFETY: the bytes of a live u32 slice.
        let bytes = unsafe {
            std::slice::from_raw_parts(one_word_more.as_ptr().cast::<u8>(), one_word_more.len() * 4)
        };
        assert!(catch_unwind(|| risc0_groth16::prove::to_json(bytes)).is_err());
        assert!(seal_to_json(&bytes[..(SEAL_WORDS - 1) * 4]).is_err());
        assert!(seal_to_json(bytes).is_err());
    }

    #[test]
    fn the_input_shape_is_the_seal_formats() {
        let shape = input_shape().unwrap();
        let fp = shape.iter().filter(|e| **e == Element::Fp).count();
        let digests = shape.iter().filter(|e| **e == Element::Digest).count();
        // risc0-groth16's seal_format.rs: K_SEAL_ELEMS = 25749, of which these are digests.
        assert_eq!((shape.len(), fp, digests), (25_749, 21_475, 4_274));
        assert_eq!(&shape[..34], {
            let mut v = vec![Element::Fp; 33];
            v.push(Element::Digest);
            v
        });
    }

    #[test]
    fn a_real_input_is_accepted_as_it_is() {
        for seed in [1, 2, 3] {
            let json = prover_input(&a_seal(seed)).unwrap();
            assert_eq!(validated_input(json.as_bytes()).unwrap(), json);
        }
        // The largest numbers each element may hold.
        let shape = input_shape().unwrap();
        let p_minus_1 = (BABY_BEAR_P - 1).to_string();
        let r_minus_1 =
            "21888242871839275222246405745257275088548364400416034343698204186575808495616";
        let values: Vec<&str> = shape
            .iter()
            .map(|k| match k {
                Element::Fp => p_minus_1.as_str(),
                Element::Digest => r_minus_1,
            })
            .collect();
        let json = render_input(&values);
        assert_eq!(validated_input(json.as_bytes()).unwrap(), json);
        assert!(json.len() < MAX_INPUT_BYTES);
    }

    #[test]
    fn the_helper_accepts_nothing_else() {
        let json = prover_input(&a_seal(7)).unwrap();
        let shape = input_shape().unwrap();
        let fp_at = 0;
        let digest_at = shape.iter().position(|k| *k == Element::Digest).unwrap();
        let values = parse_input(json.as_bytes()).unwrap();
        let with = |i: usize, v: &str| {
            let mut vs = values.clone();
            vs[i] = v;
            render_input(&vs)
        };
        let p = BABY_BEAR_P.to_string();
        let mut bad: Vec<(&str, String)> = vec![
            ("empty", String::new()),
            (
                "a seal's bytes",
                String::from_utf8_lossy(&a_seal(7)).into_owned(),
            ),
            ("one element fewer", render_input(&values[1..])),
            ("one element more", {
                let mut vs = values.clone();
                vs.push("1");
                render_input(&vs)
            }),
            ("a byte after", format!("{json}\n")),
            ("a byte before", format!(" {json}")),
            ("another key", json.replacen("\"iop\"", "\"iOp\"", 1)),
            ("compact JSON", json.replace("\n", "").replace("  ", "")),
            ("a field element at p", with(fp_at, &p)),
            ("a field element past u32", with(fp_at, "99999999999")),
            ("a digest at r", with(digest_at, BN254_R)),
            ("a digest past r", with(digest_at, &"9".repeat(77))),
            ("79 digits", with(digest_at, &"1".repeat(79))),
            ("a leading zero", with(fp_at, "01")),
            ("a sign", with(fp_at, "-1")),
            ("a plus sign", with(fp_at, "+1")),
            ("an exponent", with(fp_at, "1e3")),
            ("a fraction", with(fp_at, "1.0")),
            ("hex", with(fp_at, "0x1")),
            ("no digits", with(fp_at, "")),
            ("an escape", with(fp_at, "\\u0031")),
            ("a non-ASCII digit", with(fp_at, "١")),
            (
                "a number, not a string",
                json.replacen(&format!("\"{}\"", values[0]), values[0], 1),
            ),
        ];
        bad.push(("a NUL", with(fp_at, "1\0")));
        for (what, input) in &bad {
            assert!(
                validated_input(input.as_bytes()).is_err(),
                "{what} accepted"
            );
        }
    }

    /// Requests and answers through [`serve`], with `wrap` standing in for Docker.
    fn requests(
        reqs: &[&[u8]],
        wrap: impl FnMut(&Path, &str) -> Result<Vec<u8>>,
    ) -> Vec<(u8, Vec<u8>)> {
        let work = tempfile::tempdir().unwrap();
        let mut input = Vec::new();
        for r in reqs {
            input.extend_from_slice(&(r.len() as u32).to_le_bytes());
            input.extend_from_slice(r);
        }
        let mut output = Vec::new();
        assert_eq!(serve(&input[..], &mut output, work.path(), wrap), 0);
        let mut answers = Vec::new();
        let mut rest = &output[..];
        while !rest.is_empty() {
            let len = u32::from_le_bytes(rest[1..5].try_into().unwrap()) as usize;
            answers.push((rest[0], rest[5..5 + len].to_vec()));
            rest = &rest[5 + len..];
        }
        answers
    }

    #[test]
    fn the_helper_wraps_only_validated_input_and_outlives_a_panic() {
        let json = prover_input(&a_seal(11)).unwrap();
        let mut seen = Vec::new();
        let mut calls = 0;
        let answers = requests(
            &[
                b"{\"iop\":[]}",
                json.as_bytes(),
                json.as_bytes(),
                json.as_bytes(),
            ],
            |_, input| {
                calls += 1;
                seen.push(input.to_string());
                match calls {
                    1 => Ok(vec![0xaa; 256]),
                    2 => panic!("a bug in the wrap"),
                    _ => Ok(vec![0xbb; 256]),
                }
            },
        );
        assert_eq!(answers.len(), 4);
        assert_eq!(answers[0].0, 1, "malformed: refused");
        assert_eq!(answers[1], (0, vec![0xaa; 256]));
        assert_eq!(answers[2].0, 1, "the panic is an error answer");
        assert!(String::from_utf8_lossy(&answers[2].1).contains("failed on this request"));
        assert_eq!(answers[3], (0, vec![0xbb; 256]), "and the helper serves on");
        assert_eq!(seen, vec![json.clone(), json.clone(), json]);
    }

    #[test]
    fn an_oversized_request_is_skipped_in_step() {
        let json = prover_input(&a_seal(12)).unwrap();
        let big = vec![b'1'; MAX_INPUT_BYTES + 1];
        let answers = requests(&[&big, json.as_bytes()], |_, _| Ok(vec![1; 256]));
        assert_eq!(answers.len(), 2);
        assert_eq!(answers[0].0, 1);
        assert_eq!(answers[1], (0, vec![1; 256]));
    }

    /// The image is the one the pinned `risc0-groth16` runs, by digest.
    #[test]
    fn the_image_is_risc0_groth16s_pinned_by_digest() {
        // The source cargo built it from (this host's platform only: others' dependencies are not
        // downloaded).
        let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
        let platform = format!("{}-unknown-linux-gnu", std::env::consts::ARCH);
        let out = Command::new(cargo)
            .args(["metadata", "--format-version", "1", "--offline"])
            .args(["--filter-platform", &platform, "--manifest-path"])
            .arg(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"))
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let meta: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        let manifest = meta["packages"]
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["name"] == "risc0-groth16")
            .and_then(|p| p["manifest_path"].as_str())
            .unwrap()
            .to_string();
        let docker_rs = Path::new(&manifest)
            .parent()
            .unwrap()
            .join("src/prove/docker.rs");
        let source = std::fs::read_to_string(&docker_rs).unwrap();
        let theirs = source
            .lines()
            .find_map(|l| {
                l.trim()
                    .strip_prefix("pub(crate) const IMAGE: &str = \"")?
                    .strip_suffix("\";")
            })
            .unwrap_or_else(|| panic!("no IMAGE in {}", docker_rs.display()));
        assert_eq!(theirs, IMAGE_TAG, "risc0-groth16 runs another image now");
        let (repo, digest) = IMAGE.split_once("@sha256:").unwrap();
        assert_eq!(Some(repo), IMAGE_TAG.split_once(':').map(|(r, _)| r));
        assert!(
            digest.len() == 64
                && digest
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "{digest}"
        );
    }

    /// Where Docker holds the tagged image, its registry digest is the pinned one.
    #[test]
    fn the_pinned_digest_is_the_tags() {
        let Ok(out) = Command::new("docker")
            .args([
                "image",
                "inspect",
                "--format",
                "{{json .RepoDigests}}",
                IMAGE_TAG,
            ])
            .output()
        else {
            eprintln!("SKIPPED: no docker");
            return;
        };
        if !out.status.success() {
            eprintln!("SKIPPED: docker has no {IMAGE_TAG}");
            return;
        }
        let digests: Vec<String> = serde_json::from_slice(&out.stdout).unwrap();
        assert!(digests.iter().any(|d| d == IMAGE), "{digests:?}");
    }
}
