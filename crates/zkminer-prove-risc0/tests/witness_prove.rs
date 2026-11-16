//! The CPU worker's witness prove path over its IPC protocol (protocol v13): a `Prove` whose input is
//! a bundle's `prefix ‖ W` file, executed once into the slot's segment directory, compared with the
//! bundle's journal hash, and proven only on a match.
//!
//! `cargo test -p zkminer-prove-risc0 --features cpu --test witness_prove`; the full CPU Groth16 proof
//! is `#[ignore]`d (minutes; needs docker and the `risc0-groth16-prover` image).
#![cfg(feature = "cpu")]

use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
use zkminer_prover_protocol::{
    read_message, sys_rand, write_message, ErrorKind, WitnessProve, WorkerCommand, WorkerResponse,
    GUEST_EXIT_HALTED, PROTOCOL_VERSION,
};

const WORKER: &str = env!("CARGO_BIN_EXE_zkminer-prove-risc0-cpu");

fn sha256(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}

/// A worker over its pipes, with its stderr collected.
struct Worker {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    log: Arc<Mutex<String>>,
    _home: tempfile::TempDir,
}

impl Worker {
    fn start(extra_env: &[(&str, &str)]) -> Worker {
        let home = tempfile::tempdir().unwrap();
        let mut cmd = Command::new(WORKER);
        cmd.env_clear()
            // A key of the test's own, so nothing reads or creates ~/.zkminer.
            .env(
                sys_rand::SYS_RAND_KEY_ENV,
                sys_rand::encode_key(&[0x5a; 32]),
            )
            .env("HOME", home.path())
            .env("RUST_LOG", "info")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(path) = std::env::var_os("PATH") {
            cmd.env("PATH", path);
        }
        for (k, v) in extra_env {
            cmd.env(k, v);
        }
        let mut child = cmd.spawn().unwrap();
        let stdin = child.stdin.take().unwrap();
        let stdout = BufReader::new(child.stdout.take().unwrap());
        let mut stderr = child.stderr.take().unwrap();
        let log = Arc::new(Mutex::new(String::new()));
        let sink = log.clone();
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while let Ok(n) = stderr.read(&mut buf) {
                if n == 0 {
                    break;
                }
                sink.lock()
                    .unwrap()
                    .push_str(&String::from_utf8_lossy(&buf[..n]));
            }
        });
        let mut w = Worker {
            child,
            stdin,
            stdout,
            log,
            _home: home,
        };
        w.send(&WorkerCommand::Hello {
            protocol_version: PROTOCOL_VERSION,
        });
        match w.recv() {
            WorkerResponse::HelloAck {
                protocol_version, ..
            } => assert_eq!(protocol_version, 13),
            other => panic!("{other:?}"),
        }
        w
    }

    fn send(&mut self, cmd: &WorkerCommand) {
        write_message(&mut self.stdin, cmd).unwrap();
    }

    fn recv(&mut self) -> WorkerResponse {
        read_message(&mut self.stdout).unwrap_or_else(|e| panic!("{e}; log:\n{}", self.log()))
    }

    /// The answer to a Prove, past its progress messages.
    fn prove(
        &mut self,
        request_id: u64,
        elf: &[u8],
        input: &[u8],
        witness: Option<WitnessProve>,
        po2: u8,
    ) -> WorkerResponse {
        self.send(&WorkerCommand::Prove {
            request_id,
            elf: elf.to_vec(),
            input_data: input.to_vec(),
            po2: Some(po2),
            program_id: Some(fibonacci().1),
            witness,
        });
        loop {
            match self.recv() {
                WorkerResponse::Progress { .. } => continue,
                other => return other,
            }
        }
    }

    fn log(&self) -> String {
        self.log.lock().unwrap().clone()
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn fibonacci() -> &'static (Vec<u8>, [u8; 32]) {
    static GUEST: std::sync::OnceLock<(Vec<u8>, [u8; 32])> = std::sync::OnceLock::new();
    GUEST.get_or_init(|| {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fibonacci.elf");
        let out = Command::new(WORKER)
            .args(["--export-guest", "fibonacci"])
            .arg(&path)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let printed = String::from_utf8(out.stdout).unwrap();
        let hex = printed.trim().trim_start_matches("0x");
        let id: Vec<u8> = (0..64)
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect();
        (std::fs::read(&path).unwrap(), id.try_into().unwrap())
    })
}

/// A bundle's W on disk and the witness naming it, expecting `journal`.
fn bundle(dir: &Path, w: &[u8], prefix: &[u8], journal: &[u8]) -> WitnessProve {
    let path = dir.join("w.bin");
    std::fs::write(&path, w).unwrap();
    WitnessProve {
        input_path: path.to_str().unwrap().to_string(),
        prefix: prefix.to_vec(),
        input_sha256: sha256(&[prefix, w].concat()),
        w_len: w.len() as u64,
        expect_journal_sha256: sha256(journal),
        segment_dir: segments(dir).to_str().unwrap().to_string(),
    }
}

fn segments(dir: &Path) -> PathBuf {
    dir.join("segments").join("risc0-cpu-0")
}

/// A journal other than the bundle's is `JournalDiverged` with what the run committed, and no proof
/// starts: with every proving attempt rigged to fail (`RISC0_TEST_INJECT_INVALID`), an attempt would
/// have answered an error instead. A stale segment from an earlier proof is wiped, and the directory
/// is left empty.
#[test]
fn a_wrong_journal_hash_is_journal_diverged_and_nothing_is_proven() {
    let dir = tempfile::tempdir().unwrap();
    let witness = bundle(
        dir.path(),
        &10u32.to_le_bytes(),
        &[],
        b"the bundle's journal",
    );
    std::fs::create_dir_all(segments(dir.path())).unwrap();
    let stale = segments(dir.path()).join("7.bincode");
    std::fs::write(&stale, b"left by a crashed worker").unwrap();

    let mut worker = Worker::start(&[("RISC0_TEST_INJECT_INVALID", "100")]);
    let started = Instant::now();
    match worker.prove(1, &fibonacci().0, &[], Some(witness), 20) {
        WorkerResponse::JournalDiverged {
            request_id,
            journal,
            journal_len,
            journal_sha256,
            exit_kind,
            exit_code,
            cycles,
        } => {
            assert_eq!(request_id, 1);
            assert_eq!(journal, 55u64.to_le_bytes(), "fibonacci(10)");
            assert_eq!(
                (journal_len, journal_sha256),
                (8, sha256(&55u64.to_le_bytes()))
            );
            assert_eq!((exit_kind, exit_code), (GUEST_EXIT_HALTED, 0));
            assert!(cycles.is_power_of_two() && cycles <= 1 << 20, "{cycles}");
        }
        other => panic!("{other:?}\n{}", worker.log()),
    }
    assert!(started.elapsed() < Duration::from_secs(60));
    let log = worker.log();
    assert!(
        !log.contains("TEST INJECTED") && !log.contains("re-proving"),
        "a proof started:\n{log}"
    );
    assert!(!stale.exists(), "the stale segment was wiped");
    assert_eq!(
        std::fs::read_dir(segments(dir.path())).unwrap().count(),
        0,
        "emptied after"
    );
}

/// A W that is not the bundle's is refused with `InputMismatch`, before any execution; a missing one
/// is an internal error (the store may be unavailable), not corruption. The worker stays up.
#[test]
fn a_tampered_w_is_input_mismatch() {
    let dir = tempfile::tempdir().unwrap();
    let witness = bundle(dir.path(), &10u32.to_le_bytes(), &[], &55u64.to_le_bytes());
    let mut worker = Worker::start(&[]);

    std::fs::write(&witness.input_path, 11u32.to_le_bytes()).unwrap();
    let kind = |r: WorkerResponse| match r {
        WorkerResponse::Error { kind, .. } => kind,
        other => panic!("{other:?}"),
    };
    assert!(matches!(
        kind(worker.prove(2, &fibonacci().0, &[], Some(witness.clone()), 20)),
        ErrorKind::InputMismatch
    ));
    // The right bytes under a prefix the hash does not cover.
    std::fs::write(&witness.input_path, 10u32.to_le_bytes()).unwrap();
    let prefixed = WitnessProve {
        prefix: vec![0; 64],
        ..witness.clone()
    };
    assert!(matches!(
        kind(worker.prove(3, &fibonacci().0, &[], Some(prefixed), 20)),
        ErrorKind::InputMismatch
    ));
    // A longer file than the bundle's.
    std::fs::write(&witness.input_path, [10u8, 0, 0, 0, 0]).unwrap();
    assert!(matches!(
        kind(worker.prove(4, &fibonacci().0, &[], Some(witness.clone()), 20)),
        ErrorKind::InputMismatch
    ));
    assert!(!segments(dir.path()).exists(), "nothing was executed");
    // Gone: unreadable, not corrupt.
    std::fs::remove_file(&witness.input_path).unwrap();
    assert!(matches!(
        kind(worker.prove(5, &fibonacci().0, &[], Some(witness.clone()), 20)),
        ErrorKind::Internal
    ));
    // Inline input beside a witness is the host's protocol error.
    assert!(matches!(
        kind(worker.prove(6, &fibonacci().0, &[1], Some(witness), 20)),
        ErrorKind::ProtocolError
    ));
    // And an inline proof is answered as before (here refused for its size, before any work).
    assert!(matches!(
        kind(worker.prove(7, &fibonacci().0, &10u32.to_le_bytes(), None, 15)),
        ErrorKind::InvalidInput
    ));
}

/// On a match the worker proves, and every invalid-proof retry re-proves the SAME session: here every
/// attempt is rigged to fail as an invalid proof, so the answer is a proof failure after four
/// attempts, and the guest was executed exactly once.
#[test]
fn a_matching_journal_is_proven_from_the_one_execution_across_retries() {
    let dir = tempfile::tempdir().unwrap();
    let mut prefix = [0u8; 64];
    prefix[..4].copy_from_slice(&12u32.to_le_bytes());
    let witness = bundle(dir.path(), b"W", &prefix, &144u64.to_le_bytes());
    let mut worker = Worker::start(&[("RISC0_TEST_INJECT_INVALID", "100")]);
    match worker.prove(8, &fibonacci().0, &[], Some(witness), 18) {
        WorkerResponse::Error { kind, message, .. } => {
            assert!(
                matches!(kind, ErrorKind::ProofFailed),
                "{kind:?}: {message}"
            );
            assert!(message.contains("TEST INJECTED"), "{message}");
        }
        other => panic!("{other:?}\n{}", worker.log()),
    }
    let log = worker.log();
    assert_eq!(
        log.matches("Executed the witness session").count(),
        1,
        "{log}"
    );
    assert_eq!(log.matches("re-proving").count(), 3, "{log}");
    assert_eq!(
        std::fs::read_dir(segments(dir.path())).unwrap().count(),
        0,
        "emptied after"
    );
}

/// A full Groth16 proof on the CPU (the STARK, the recursion, and the wrap in the
/// `risc0-groth16-prover` docker image) of a witness job with the journal prefix.
#[test]
#[ignore = "a real CPU Groth16 proof: minutes, docker and the risc0-groth16-prover image"]
fn a_matching_journal_is_proven_on_the_cpu() {
    let dir = tempfile::tempdir().unwrap();
    let mut prefix = [0u8; 64];
    prefix[..4].copy_from_slice(&10u32.to_le_bytes());
    let witness = bundle(
        dir.path(),
        b"the witness bytes",
        &prefix,
        &55u64.to_le_bytes(),
    );
    let mut worker = Worker::start(&[]);
    let started = Instant::now();
    match worker.prove(9, &fibonacci().0, &[], Some(witness), 16) {
        WorkerResponse::ProofResult {
            journal,
            seal,
            cycles,
            duration_secs,
            ..
        } => {
            assert_eq!(journal, 55u64.to_le_bytes());
            assert_eq!(seal.len(), 256, "a Groth16 seal");
            eprintln!(
                "proved {cycles} cycles in {duration_secs:.1}s ({:.1}s with the execution)",
                started.elapsed().as_secs_f64()
            );
        }
        other => panic!("{other:?}\n{}", worker.log()),
    }
    assert_eq!(
        std::fs::read_dir(segments(dir.path())).unwrap().count(),
        0,
        "emptied after"
    );
}
